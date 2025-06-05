const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const encode_std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const encode_hex = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
const crockford_alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const std_padding = '=';
pub const no_padding = null;

pub const std_encoding = Encoding.init(encode_std);
pub const hex_encoding = Encoding.init(encode_hex);
pub const raw_std_encoding = std_encoding.withPadding(no_padding);
pub const raw_hex_encoding = hex_encoding.withPadding(no_padding);
pub const crockford_encoding = Encoding.init(crockford_alphabet).withPadding(no_padding);

pub const Error = error{
    NotEnoughSpace,
    MissingPadding,
    NotEnoughPadding,
    IncorrectPadding,
    CorruptInput,
};

pub const Encoding = struct {
    buf: [32]u8,
    decode_map: [256]u8,
    pad_char: ?u8 = null,

    const Self = @This();

    pub fn init(encoder: []const u8) Encoding {
        if (encoder.len != 32) {
            @panic("encoding alphabet is not 32-bytes long");
        }

        return Encoding{
            .buf = blk: {
                var a: [32]u8 = undefined;
                std.mem.copyForwards(u8, a[0..], encoder);
                break :blk a;
            },
            .decode_map = blk: {
                var a = [_]u8{0xFF} ** 256;
                for (encoder, 0..) |c, i| {
                    a[@intCast(c)] = @intCast(i);
                }
                break :blk a;
            },
            .pad_char = std_padding,
        };
    }

    pub fn withPadding(self: Self, padding: ?u8) Encoding {
        if (padding) |pad| {
            if (pad == '\r' or pad == '\n' or pad > 0xff) {
                @panic("invalid padding");
            }

            for (self.buf) |val| {
                if (val == pad) {
                    @panic("padding contained in alphabet");
                }
            }
        }

        var enc = self;
        enc.pad_char = padding;

        return enc;
    }

    pub fn encode(
        self: Self,
        destination: []u8,
        source: []const u8,
    ) []const u8 {
        var dst = destination;
        var src = source;
        var n: usize = 0;
        while (src.len > 0) {
            var b = [_]u8{0} ** 8;
            switch (src.len) {
                1 => {
                    case1(b[0..], src);
                },
                2 => {
                    case2(b[0..], src);
                    case1(b[0..], src);
                },
                3 => {
                    case3(b[0..], src);
                    case2(b[0..], src);
                    case1(b[0..], src);
                },
                4 => {
                    case4(b[0..], src);
                    case3(b[0..], src);
                    case2(b[0..], src);
                    case1(b[0..], src);
                },
                else => {
                    b[7] = src[4] & 0x1F;
                    b[6] = src[4] >> 5;
                    case4(b[0..], src);
                    case3(b[0..], src);
                    case2(b[0..], src);
                    case1(b[0..], src);
                },
            }

            const size = dst.len;
            if (size >= 8) {
                dst[0] = self.buf[b[0] & 31];
                dst[1] = self.buf[b[1] & 31];
                dst[2] = self.buf[b[2] & 31];
                dst[3] = self.buf[b[3] & 31];
                dst[4] = self.buf[b[4] & 31];
                dst[5] = self.buf[b[5] & 31];
                dst[6] = self.buf[b[6] & 31];
                dst[7] = self.buf[b[7] & 31];
                n += 8;
            } else {
                var i: usize = 0;
                while (i < size) : (i += 1) {
                    dst[i] = self.buf[b[i] & 31];
                }
                n += i;
            }

            if (src.len < 5) {
                if (self.pad_char == null) break;
                dst[7] = self.pad_char.?;
                if (src.len < 4) {
                    dst[6] = self.pad_char.?;
                    dst[5] = self.pad_char.?;
                    if (src.len < 3) {
                        dst[4] = self.pad_char.?;
                        if (src.len < 2) {
                            dst[3] = self.pad_char.?;
                            dst[2] = self.pad_char.?;
                        }
                    }
                }
                break;
            }

            src = src[5..];
            dst = dst[8..];
        }

        return destination[0..n];
    }

    pub fn encodeToString(self: Self, alloc: Allocator, src: []const u8) ![]const u8 {
        var output = try alloc.alloc(u8, self.encodeLen(src.len));
        defer alloc.free(output);

        const result = self.encode(output[0..], src[0..]);
        return alloc.dupe(u8, result);
    }

    pub fn encodeLen(self: Self, n: usize) usize {
        if (self.pad_char == null) {
            return (n * 8 + 4) / 5;
        }

        return (n + 4) / 5 * 8;
    }

    pub fn decode(
        self: Self,
        dest: []u8,
        source: []const u8,
    ) ![]const u8 {
        if (dest.len < self.decodeLen(source.len)) {
            return Error.NotEnoughSpace;
        }

        const dst = dest;
        var src = source;
        var end: bool = false;
        var n: usize = 0;
        var dsti: usize = 0;

        while (src.len > 0 and !end) {
            var dbuf = [_]u8{0} ** 8;
            var dlen: usize = 8;
            var j: usize = 0;
            while (j < 8) {
                if (src.len == 0) {
                    if (self.pad_char != null) {
                        // We have reached the end and are missing padding
                        return Error.MissingPadding;
                    }
                    dlen = j;
                    end = true;
                    break;
                }

                const in = src[0];
                src = src[1..];
                if (self.pad_char != null and in == self.pad_char.? and j >= 2 and src.len < 8) {
                    // We've reached the end and there's padding
                    if (src.len + j < 8 - 1) {
                        // not enough padding
                        return Error.NotEnoughPadding;
                    }

                    var k: usize = 0;
                    while (k < 8 - 1 - j) : (k += 1) {
                        if (src.len > k and self.pad_char != null and src[k] != self.pad_char.?) {
                            return Error.IncorrectPadding;
                        }
                    }

                    dlen = j;
                    end = true;

                    // 7, 5 and 2 are not valid padding lengths, and so 1, 3 and 6 are not
                    // valid dlen values. See RFC 4648 Section 6 "Base 32 Encoding" listing
                    // the five valid padding lengths, and Section 9 "Illustrations and
                    // Examples" for an illustration for how the 1st, 3rd and 6th base32
                    // src bytes do not yield enough information to decode a dst byte.
                    if (dlen == 1 or dlen == 3 or dlen == 6) {
                        return Error.IncorrectPadding;
                    }

                    break;
                }

                dbuf[j] = self.decode_map[in];
                if (dbuf[j] == 0xFF) {
                    return Error.CorruptInput;
                }

                j += 1;
            }

            // Pack 8x 5-bit source blocks into 5 byte destination
            // quantum
            switch (dlen) {
                8 => {
                    dec8(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec7(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec5(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec4(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec2(dst, dsti, dbuf[0..]);
                    n += 1;
                },
                7 => {
                    dec7(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec5(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec4(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec2(dst, dsti, dbuf[0..]);
                    n += 1;
                },
                5 => {
                    dec5(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec4(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec2(dst, dsti, dbuf[0..]);
                    n += 1;
                },
                4 => {
                    dec4(dst, dsti, dbuf[0..]);
                    n += 1;
                    dec2(dst, dsti, dbuf[0..]);
                    n += 1;
                },
                2 => {
                    dec2(dst, dsti, dbuf[0..]);
                    n += 1;
                },
                else => {},
            }
            dsti += 5;
        }

        return dest[0..n];
    }

    pub fn decodeString(self: Self, alloc: Allocator, src: []const u8) ![]const u8 {
        var output = try alloc.alloc(u8, self.decodeLen(src.len));
        defer alloc.free(output);

        const result = try self.decode(output[0..], src);
        return alloc.dupe(u8, result);
    }

    pub fn decodeLen(self: Self, n: usize) usize {
        if (self.pad_char == null) {
            return n * 5 / 8;
        }

        return n / 8 * 5;
    }
};

fn dec2(dst: []u8, dsti: usize, dbuf: []u8) void {
    dst[dsti + 0] = dbuf[0] << 3 | dbuf[1] >> 2;
}

fn dec4(dst: []u8, dsti: usize, dbuf: []u8) void {
    dst[dsti + 1] = dbuf[1] << 6 | dbuf[2] << 1 | dbuf[3] >> 4;
}

fn dec5(dst: []u8, dsti: usize, dbuf: []u8) void {
    dst[dsti + 2] = dbuf[3] << 4 | dbuf[4] >> 1;
}

fn dec7(dst: []u8, dsti: usize, dbuf: []u8) void {
    dst[dsti + 3] = dbuf[4] << 7 | dbuf[5] << 2 | dbuf[6] >> 3;
}

fn dec8(dst: []u8, dsti: usize, dbuf: []u8) void {
    dst[dsti + 4] = dbuf[6] << 5 | dbuf[7];
}

fn case1(b: []u8, src: []const u8) void {
    b[1] |= (src[0] << 2) & 0x1F;
    b[0] = src[0] >> 3;
}

fn case2(b: []u8, src: []const u8) void {
    b[3] |= (src[1] << 4) & 0x1F;
    b[2] = (src[1] >> 1) & 0x1F;
    b[1] = (src[1] >> 6) & 0x1F;
}

fn case3(b: []u8, src: []const u8) void {
    b[4] |= (src[2] << 1) & 0x1F;
    b[3] = (src[2] >> 4) & 0x1F;
}

fn case4(b: []u8, src: []const u8) void {
    b[6] |= (src[3] << 3) & 0x1F;
    b[5] = (src[3] >> 2) & 0x1F;
    b[4] = src[3] >> 7;
}

pub fn encode(alloc: Allocator, input: []const u8, padding: bool) ![]const u8 {
    if (padding) {
        const result = try std_encoding.encodeToString(alloc, input[0..]);
        return result;
    } else {
        const result = try raw_std_encoding.encodeToString(alloc, input[0..]);
        return result;
    }
}

pub fn decode(alloc: Allocator, input: []const u8) ![]const u8 {
    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();

    try buf.appendSlice(input[0..]);

    const n = input.len % 8;
    if (n != 0) {
        for (0..8 - n) |_| {
            try buf.append('=');
        }
    }

    const encoded = try buf.toOwnedSlice();
    defer alloc.free(encoded);

    const result = try std_encoding.decodeString(alloc, encoded);
    return result;
}

const TestPair = struct {
    decoded: []const u8,
    encoded: []const u8,
};

const pairs = [_]TestPair{
    TestPair{ .decoded = "", .encoded = "" },
    TestPair{ .decoded = "f", .encoded = "MY======" },
    TestPair{ .decoded = "fo", .encoded = "MZXQ====" },
    TestPair{ .decoded = "foo", .encoded = "MZXW6===" },
    TestPair{ .decoded = "foob", .encoded = "MZXW6YQ=" },
    TestPair{ .decoded = "fooba", .encoded = "MZXW6YTB" },
    // Wikipedia examples, converted to base32
    TestPair{ .decoded = "sure.", .encoded = "ON2XEZJO" },
    TestPair{ .decoded = "sure", .encoded = "ON2XEZI=" },
    TestPair{ .decoded = "sur", .encoded = "ON2XE===" },
    TestPair{ .decoded = "su", .encoded = "ON2Q====" },
    TestPair{ .decoded = "leasure.", .encoded = "NRSWC43VOJSS4===" },
    TestPair{ .decoded = "easure.", .encoded = "MVQXG5LSMUXA====" },
    TestPair{ .decoded = "easure.", .encoded = "MVQXG5LSMUXA====" },
    TestPair{ .decoded = "asure.", .encoded = "MFZXK4TFFY======" },
    TestPair{ .decoded = "sure.", .encoded = "ON2XEZJO" },
};

test "Encoding" {
    var buf: [1024]u8 = undefined;
    for (pairs) |ts| {
        const size = std_encoding.encodeLen(ts.decoded.len);
        const result = std_encoding.encode(buf[0..size], ts.decoded);
        try testing.expectEqualSlices(u8, ts.encoded, result);
    }
}

test "Decoding" {
    var buf: [1024]u8 = undefined;
    for (pairs) |ts| {
        const size = std_encoding.decodeLen(ts.encoded.len);
        const result = try std_encoding.decode(buf[0..size], ts.encoded);
        try testing.expectEqualSlices(u8, ts.decoded, result);
    }
}

test "Encoding no padding" {
    var buf: [1024]u8 = undefined;
    for (pairs) |ts| {
        const size = raw_std_encoding.encodeLen(ts.decoded.len);
        const result = raw_std_encoding.encode(buf[0..size], ts.decoded);
        const expected_end = std.mem.indexOf(u8, ts.encoded, "=") orelse ts.encoded.len;
        const expected = ts.encoded[0..expected_end];
        try testing.expectEqualSlices(u8, expected, result);
    }
}

test "Decoding no padding" {
    var buf: [1024]u8 = undefined;
    for (pairs) |ts| {
        const size = raw_std_encoding.decodeLen(ts.encoded.len);
        const end_without_padding = std.mem.indexOf(u8, ts.encoded, "=") orelse ts.encoded.len;
        const encoded_no_pad = ts.encoded[0..end_without_padding];
        const result = try raw_std_encoding.decode(buf[0..size], encoded_no_pad);
        try testing.expectEqualSlices(u8, ts.decoded, result);
    }
}

test "base32 encode test" {
    const alloc = testing.allocator;

    const output = try encode(alloc, "Hello world", true);
    defer alloc.free(output);

    try testing.expectEqualSlices(u8, "JBSWY3DPEB3W64TMMQ======", output);

    const output2 = try encode(alloc, "Hello world", false);
    defer alloc.free(output2);

    try testing.expectEqualSlices(u8, "JBSWY3DPEB3W64TMMQ", output2);
}

test "base32 decode test" {
    const alloc = testing.allocator;

    const output = try decode(alloc, "JBSWY3DPEB3W64TMMQ======");
    defer alloc.free(output);

    try testing.expectEqualSlices(u8, "Hello world", output);

    const output2 = try decode(alloc, "JBSWY3DPEB3W64TMMQ");
    defer alloc.free(output2);

    try testing.expectEqualSlices(u8, "Hello world", output2);
}
