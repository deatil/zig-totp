const std = @import("std");
const fmt = std.fmt;
const ascii = std.ascii;
const testing = std.testing;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const url = @import("./url.zig");
const bytes = @import("./bytes.zig");

pub const Key = struct {
    orig: []const u8,
    url: url.Uri,
    query: url.Values,

    arena: ArenaAllocator,

    pub fn init(a: Allocator, orig: []const u8) !Key {
        const u = try url.Uri.parse(orig);

        var query: []const u8 = "";
        if (u.query) |val| {
            query = val.percent_encoded;
        } else {
            query = "";
        }

        const q = try url.parseQuery(a, query);

        return Key{
            .orig = orig,
            .url = u,
            .query = q,
            .arena = ArenaAllocator.init(a),
        };
    }

    pub fn deinit(self: *Key) void {
        self.arena.deinit();
    }

    pub fn string(self: *Key) []const u8 {
        return self.orig;
    }

    pub fn typ(self: *Key) []const u8 {
        if (self.url.host == null) {
            return "";
        }

        return self.url.host.?.percent_encoded;
    }

    pub fn issuer(self: *Key) []const u8 {
        const iss = self.query.get("issuer");
        if (iss != null) {
            return iss.?;
        }

        const p = bytes.trimLeft(self.url.path.percent_encoded, "/");
        const i = bytes.index(p, ":").?;

        if (i < 0) {
            return "";
        }

        return p[0..i];
    }

    pub fn accountName(self: *Key) []const u8 {
        const p = bytes.trimLeft(self.url.path.percent_encoded, "/");
        const i = bytes.index(p, ":").?;

        if (i < 0) {
            return p;
        }

        return p[i+1..];
    }

    pub fn secret(self: *Key) []const u8 {
        const s = self.query.get("secret");
        if (s == null) {
            return "";
        }

        return s.?;
    }

    pub fn period(self: *Key) u32 {
        const per = self.query.get("period");
        if (per == null) {
            return 30;
        }

        return strToInt(per.?);
    }

    pub fn digits(self: *Key) Digits {
        const dig = self.query.get("digits");
        if (dig) |v| {
            return Digits.init(strToInt(v));
        }

        return Digits.Six;
    }

    pub fn algorithm(self: *Key) Algorithm {
        const a = self.arena.allocator();

        const algo = self.query.get("algorithm");
        if (algo) |val| {
            const alg = ascii.allocLowerString(a, val) catch {
                return .sha1;
            };
            defer a.free(alg);

            if (bytes.eq(alg, "md5")) {
                return .md5;
            } else if (bytes.eq(alg, "sha256")) {
                return .sha256;
            } else if (bytes.eq(alg, "sha512")) {
                return .sha512;
            }
        }

        return .sha1;
    }

    // Encoder returns the encoder used or the default ("")
    pub fn encoder(self: *Key) Encoder {
        const a = self.arena.allocator();

        const enc = self.query.get("encoder");
        if (enc) |val| {
            const encoder_name = ascii.allocLowerString(a, val) catch {
                return .default;
            };
            defer a.free(encoder_name);

            if (bytes.eq(encoder_name, "steam")) {
                return .steam;
            }
        }

        return .default;
    }

    pub fn urlString(self: *Key) []const u8 {
        const a = self.arena.allocator();

        var buf = std.ArrayList(u8).init(a);
        defer buf.deinit();

        self.url.format(";@+/?#", .{}, buf.writer()) catch {
            return "";
        };

        const urlStr = buf.toOwnedSlice() catch {
            return "";
        };
        return urlStr;
    }
};

pub const Algorithm = enum {
    sha1,
    sha256,
    sha512,
    md5,

    pub fn string(self: Algorithm) []const u8 {
        return switch (self) {
            .sha1 => "SHA1",
            .sha256 => "SHA256",
            .sha512 => "SHA512",
            else => "MD5",
        };
    }

    pub fn hashType(self: Algorithm) type {
        return switch (self) {
            .sha1 => crypto.auth.hmac.HmacSha1,
            .sha256 => crypto.auth.hmac.sha2.HmacSha256,
            .sha512 => crypto.auth.hmac.sha2.HmacSha512,
            else => crypto.auth.hmac.HmacMd5,
        };
    }

    pub fn hash(self: Algorithm, msg: []const u8, key: []const u8) []u8 {
        var hashed: []u8 = undefined;

        switch (self) {
            .sha1 => {
                var h = crypto.auth.hmac.HmacSha1.init(key);
                var hmac: [crypto.auth.hmac.HmacSha1.mac_length]u8 = undefined;
                h.update(msg);
                h.final(hmac[0..]);

                hashed = hmac[0..];
            },
            .sha256 => {
                var h = crypto.auth.hmac.sha2.HmacSha256.init(key);
                var hmac: [crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
                h.update(msg);
                h.final(hmac[0..]);

                hashed = hmac[0..];
            },
            .sha512 => {
                var h = crypto.auth.hmac.sha2.HmacSha512.init(key);
                var hmac: [crypto.auth.hmac.sha2.HmacSha512.mac_length]u8 = undefined;
                h.update(msg);
                h.final(hmac[0..]);

                hashed = hmac[0..];
            },
            else => {
                var h = crypto.auth.hmac.HmacMd5.init(key);
                var hmac: [crypto.auth.hmac.HmacMd5.mac_length]u8 = undefined;
                h.update(msg);
                h.final(hmac[0..]);

                hashed = hmac[0..];
            },
        }

        return hashed;
    }
};

pub const Encoder = enum {
    steam,
    default,
};

pub const Digits = struct {
    value: u32,

    const Self = @This();

    pub const Six = init(6);
    pub const Eight = init(8);

    pub fn init(v: u32) Digits {
        return .{ 
            .value = v,
        };
    }

    pub fn string(self: Self) ![]const u8 {
        const allocator = std.heap.page_allocator;

        const len = self.length();
        return try fmt.allocPrint(allocator, "{d}", .{len});
    }

    // Length returns the number of characters for this Digits.
    pub fn length(self: Self) u32 {
        return @as(u32, self.value);
    }

    // Format converts an integer into the zero-filled size for this Digits.
    pub fn format(self: Self, in: u32) ![]const u8 {
        const alloc = std.heap.page_allocator;

        var data = std.ArrayList(u8).init(alloc);
        defer data.deinit();

        const len = self.length();
        const inlen = formatLen(in);

        if (len >= inlen) {
            for (0..len-inlen) |_| {
                try data.append('0');
            }
        }

        try data.writer().print("{}", .{in});

        const res = try data.toOwnedSlice();

        if (len < inlen) {
            return res[inlen-len..];
        }

        return res;
    }

    pub fn equal(self: Self, in: Self) bool {
        if (self.value == in.value) {
            return true;
        }

        return false;
    }
};

fn formatLen(in: u32) u32 {
    var len: u32 = 0;
    var data = in;

    while (data > 0) {
        data /= 10;
        len += 1;
    }

    return len;
}

fn toInt(c: u8) u32 {
    switch (c) {
        '0' => return 0,
        '1' => return 1,
        '2' => return 2,
        '3' => return 3,
        '4' => return 4,
        '5' => return 5,
        '6' => return 6,
        '7' => return 7,
        '8' => return 8,
        '9' => return 9,
        else => return 0,
    }
}

fn strToInt(in: []const u8) u32 {
    var res: u32 = 0;

    for (0..in.len) |i| {
        res += @as(u32, toInt(in[i])) * std.math.pow(u32, 10, @as(u32, @intCast(in.len-i-1)));
    }
    
    return res;
}

fn assertEqual(comptime expected_hex: [:0]const u8, input: []const u8) !void {
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    for (&expected_bytes, 0..) |*r, i| {
        r.* = fmt.parseInt(u8, expected_hex[2 * i .. 2 * i + 2], 16) catch unreachable;
    }

    try testing.expectEqualSlices(u8, &expected_bytes, input);
}

test "test strToInt" {
    try testing.expectEqual(1, std.math.pow(u32, 10, 0));
    try testing.expectEqual(100, std.math.pow(u32, 10, 2));

    try testing.expectEqual(321, strToInt("321"));
    try testing.expectEqual(32155, strToInt("32155"));
    try testing.expectEqual(7, strToInt("7"));
}

test "test Encoder" {
    const steam = Encoder.steam;
    const default = Encoder.default;

    try testing.expectEqual(steam, Encoder.steam);
    try testing.expectEqual(default, Encoder.default);
}

test "test Digits" {
    const eight = Digits.Eight;

    const str = try eight.string();
    const len = eight.length();
    const str2 = try eight.format(11222);
    const str21 = try eight.format(11222333);
    const str22 = try eight.format(112223333);

    try testing.expectEqualStrings("8", str);
    try testing.expectEqual(8, len);
    try testing.expectEqualStrings("00011222", str2);
    try testing.expectEqualStrings("11222333", str21);
    try testing.expectEqualStrings("12223333", str22);

    const len2 = formatLen(222);
    try testing.expectEqual(3, len2);

    try testing.expectEqual(eight, Digits.init(8));

    try testing.expectEqual(true, eight.equal(Digits.init(8)));
    try testing.expectEqual(false, eight.equal(Digits.init(7)));
}

test "test Key" {
    const alloc = std.heap.page_allocator;
    const urlStr = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8";
    
    var pu = try Key.init(alloc, urlStr);

    try testing.expectEqualStrings(urlStr, pu.string());
    try testing.expectEqualStrings("totp", pu.typ());
    try testing.expectEqualStrings("Example", pu.issuer());
    try testing.expectEqualStrings("alice@google.com", pu.accountName());
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", pu.secret());
    try testing.expectEqual(30, pu.period());
    try testing.expectEqual(Digits.Eight, pu.digits());
    try testing.expectEqual(Algorithm.sha256, pu.algorithm());
    try testing.expectEqual(Encoder.default, pu.encoder());
    try testing.expectEqualStrings(urlStr, pu.urlString());

    pu.deinit();

    const urlStr2 = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&encoder=steam";
    
    var pu2 = try Key.init(alloc, urlStr2);
    try testing.expectEqual(Encoder.steam, pu2.encoder());
    try testing.expectEqual(Algorithm.sha1, pu2.algorithm());
}

test "test Algorithm" {
    try testing.expectEqualStrings("MD5", Algorithm.md5.string());
    try testing.expectEqualStrings("SHA1", Algorithm.sha1.string());
    try testing.expectEqualStrings("SHA256", Algorithm.sha256.string());
    try testing.expectEqualStrings("SHA512", Algorithm.sha512.string());

    try testing.expectEqual(crypto.auth.hmac.HmacMd5, Algorithm.md5.hashType());
    try testing.expectEqual(crypto.auth.hmac.HmacSha1, Algorithm.sha1.hashType());
    try testing.expectEqual(crypto.auth.hmac.sha2.HmacSha256, Algorithm.sha256.hashType());
    try testing.expectEqual(crypto.auth.hmac.sha2.HmacSha512, Algorithm.sha512.hashType());

    const msg = "test data";
    const key = "test key";

    // try assertEqual("0194d256ddb7b73fde24b0d3aa407b5e", Algorithm.md5.hash(msg, key));
    try assertEqual("910cc7a8f8b718e409c9a8b0ff3af561c8e68262", Algorithm.sha1.hash(msg, key));
    try assertEqual("4695788ca94015a246422be13bbd966ade571842efc3a39296bdb6f2377597ff", Algorithm.sha256.hash(msg, key));
    // try assertEqual("868000a7fdc71b2778d9c820b2058ebce87093ea1bcd9df772faf200b71484efaae15a461a0b509c034ace950a64c4330fac3932677fd509a02d588e74c01ff3", Algorithm.sha512.hash(msg, key));

}

