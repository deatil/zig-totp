const std = @import("std");
const fmt = std.fmt;
const ascii = std.ascii;
const testing = std.testing;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const auth_hmac = crypto.auth.hmac;

const url = @import("url.zig");
const bytes = @import("bytes.zig");

pub const OtpError = error{
    ValidateSecretInvalidBase32,
    ValidateInputInvalidLength,

    GenerateMissingIssuer,
    GenerateMissingAccountName,
};

pub const Key = struct {
    orig: []const u8,
    url: url.Uri,
    query: url.Values,
    query_raw: []const u8,
    alloc: Allocator,

    const Self = @This();

    pub fn init(alloc: Allocator, orig: []const u8) !Key {
        const new_orig = try alloc.dupe(u8, orig);

        const u = try url.Uri.parse(new_orig);

        var query: []const u8 = "";
        if (u.query) |val| {
            query = try Self.toComponentRawMaybeAlloc(alloc, val);
        } else {
            query = "";
        }

        const q = try url.parseQuery(alloc, query);

        return .{
            .orig = new_orig,
            .url = u,
            .query = q,
            .query_raw = query,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.query.deinit();
        self.alloc.free(self.orig);
        self.alloc.free(self.query_raw);
    }

    pub fn string(self: *Self) []const u8 {
        return self.orig;
    }

    pub fn typ(self: *Self) []const u8 {
        if (self.url.host) |val| {
            return val.percent_encoded;
        }

        return "";
    }

    pub fn issuer(self: *Self) []const u8 {
        const iss = self.query.get("issuer");
        if (iss) |val| {
            return val;
        }

        const p = bytes.trimLeft(self.url.path.percent_encoded, "/");
        const i = bytes.index(p, ":");

        if (i) |val| {
            return p[0..val];
        }

        return "";
    }

    pub fn accountName(self: *Self) []const u8 {
        const p = bytes.trimLeft(self.url.path.percent_encoded, "/");
        const i = bytes.index(p, ":");

        if (i) |val| {
            return p[val + 1 ..];
        }

        return p;
    }

    pub fn secret(self: *Self) []const u8 {
        const s = self.query.get("secret");
        if (s) |val| {
            return val;
        }

        return "";
    }

    pub fn period(self: *Self) u32 {
        const per = self.query.get("period");
        if (per) |val| {
            const vv = fmt.parseInt(u32, val, 10) catch {
                return 30;
            };

            return vv;
        }

        return 30;
    }

    pub fn digits(self: *Self) Digits {
        const dig = self.query.get("digits");
        if (dig) |v| {
            const vv = fmt.parseInt(u32, v, 10) catch {
                return .Six;
            };
            return Digits.init(vv);
        }

        return .Six;
    }

    pub fn algorithm(self: *Self) Algorithm {
        const alloc = self.alloc;

        const algo = self.query.get("algorithm");
        if (algo) |val| {
            const alg = ascii.allocLowerString(alloc, val) catch {
                return .SHA1;
            };
            defer alloc.free(alg);

            if (bytes.eq(alg, "md5")) {
                return .MD5;
            } else if (bytes.eq(alg, "sha256")) {
                return .SHA256;
            } else if (bytes.eq(alg, "sha512")) {
                return .SHA512;
            }
        }

        return .SHA1;
    }

    /// Encoder returns the encoder used or the default ("")
    pub fn encoder(self: *Self) Encoder {
        const alloc = self.alloc;

        const enc = self.query.get("encoder");
        if (enc) |val| {
            const encoder_name = ascii.allocLowerString(alloc, val) catch {
                return .Default;
            };
            defer alloc.free(encoder_name);

            if (bytes.eq(encoder_name, "steam")) {
                return .Steam;
            }
        }

        return .Default;
    }

    /// return url string
    pub fn urlString(self: *Self) []const u8 {
        const url_str = fmt.allocPrint(self.alloc, "{f}", .{
            self.url.fmt(.all),
        }) catch "";
        return url_str;
    }

    fn toComponentRawMaybeAlloc(
        alloc: Allocator,
        component: std.Uri.Component,
    ) ![]const u8 {
        return switch (component) {
            .raw => |raw| try alloc.dupe(u8, raw),
            .percent_encoded => |percent_encoded| if (std.mem.indexOfScalar(u8, percent_encoded, '%')) |_|
                try std.fmt.allocPrint(alloc, "{f}", .{std.fmt.alt(component, .formatRaw)})
            else
                try alloc.dupe(u8, percent_encoded),
        };
    }
};

pub const Algorithm = enum {
    SHA1,
    SHA256,
    SHA512,
    MD5,

    const Self = @This();

    pub fn string(self: Self) []const u8 {
        return switch (self) {
            .SHA1 => "SHA1",
            .SHA256 => "SHA256",
            .SHA512 => "SHA512",
            else => "MD5",
        };
    }

    pub fn hashType(self: Self) type {
        return switch (self) {
            .SHA1 => auth_hmac.HmacSha1,
            .SHA256 => auth_hmac.sha2.HmacSha256,
            .SHA512 => auth_hmac.sha2.HmacSha512,
            else => auth_hmac.HmacMd5,
        };
    }

    pub fn hash(self: Self, alloc: Allocator, msg: []const u8, key: []const u8) ![]u8 {
        switch (self) {
            .SHA1 => {
                var hmac: [auth_hmac.HmacSha1.mac_length]u8 = undefined;

                var h = auth_hmac.HmacSha1.init(key);
                h.update(msg);
                h.final(hmac[0..]);

                return alloc.dupe(u8, hmac[0..]);
            },
            .SHA256 => {
                var hmac: [auth_hmac.sha2.HmacSha256.mac_length]u8 = undefined;

                var h = auth_hmac.sha2.HmacSha256.init(key);
                h.update(msg);
                h.final(hmac[0..]);

                return alloc.dupe(u8, hmac[0..]);
            },
            .SHA512 => {
                var hmac: [auth_hmac.sha2.HmacSha512.mac_length]u8 = undefined;

                var h = auth_hmac.sha2.HmacSha512.init(key);
                h.update(msg);
                h.final(hmac[0..]);

                return alloc.dupe(u8, hmac[0..]);
            },
            else => {
                var hmac: [auth_hmac.HmacMd5.mac_length]u8 = undefined;

                var h = auth_hmac.HmacMd5.init(key);
                h.update(msg);
                h.final(hmac[0..]);

                return alloc.dupe(u8, hmac[0..]);
            },
        }
    }
};

pub const Encoder = enum {
    Steam,
    Default,
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

    pub fn string(self: Self, alloc: Allocator) ![]const u8 {
        const len = self.length();
        return fmt.allocPrint(alloc, "{d}", .{len});
    }

    // Length returns the number of characters for this Digits.
    pub fn length(self: Self) u32 {
        return self.value;
    }

    // Format converts an integer into the zero-filled size for this Digits.
    pub fn format(self: Self, alloc: Allocator, in: u32) ![]const u8 {
        var data = try std.ArrayList(u8).initCapacity(alloc, 0);
        defer data.deinit(alloc);

        const len = self.length();
        const inlen = formatLen(in);

        if (len >= inlen) {
            for (0..len - inlen) |_| {
                try data.append(alloc, '0');
            }
        }

        try data.writer(alloc).print("{}", .{in});

        const res = try data.toOwnedSlice(alloc);
        defer alloc.free(res);

        const new_res = try alloc.dupe(u8, res);

        if (len < inlen) {
            defer alloc.free(new_res);
            return alloc.dupe(u8, new_res[inlen - len ..]);
        }

        return new_res;
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

fn assertEqual(comptime expected_hex: [:0]const u8, input: []const u8) !void {
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    for (&expected_bytes, 0..) |*r, i| {
        r.* = fmt.parseInt(u8, expected_hex[2 * i .. 2 * i + 2], 16) catch unreachable;
    }

    try testing.expectEqualSlices(u8, &expected_bytes, input);
}

test "Encoder" {
    const steam = Encoder.Steam;
    const default = Encoder.Default;

    try testing.expectEqual(steam, Encoder.Steam);
    try testing.expectEqual(default, Encoder.Default);
}

test "Digits" {
    const alloc = testing.allocator;

    const eight = Digits.Eight;

    const str = try eight.string(alloc);
    const len = eight.length();
    const str2 = try eight.format(alloc, 11222);
    const str21 = try eight.format(alloc, 11222333);
    const str22 = try eight.format(alloc, 112223333);

    defer alloc.free(str);
    defer alloc.free(str2);
    defer alloc.free(str21);
    defer alloc.free(str22);

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

test "Key" {
    const alloc = testing.allocator;

    const urlStr = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8";

    var pu = try Key.init(alloc, urlStr);
    defer pu.deinit();

    try testing.expectEqualStrings(urlStr, pu.string());
    try testing.expectEqualStrings("totp", pu.typ());

    const issuer = pu.issuer();
    try testing.expectEqualStrings("Example", issuer);

    try testing.expectEqualStrings("alice@google.com", pu.accountName());
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", pu.secret());
    try testing.expectEqual(30, pu.period());
    try testing.expectEqual(Digits.Eight, pu.digits());
    try testing.expectEqual(Algorithm.SHA256, pu.algorithm());
    try testing.expectEqual(Encoder.Default, pu.encoder());

    const us = pu.urlString();
    defer alloc.free(us);

    try testing.expectEqualStrings(urlStr, us);

    const urlStr2 = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&encoder=steam";

    var pu2 = try Key.init(alloc, urlStr2);
    defer pu2.deinit();

    try testing.expectEqual(Encoder.Steam, pu2.encoder());
    try testing.expectEqual(Algorithm.SHA1, pu2.algorithm());

    // ==================

    var url_str: []const u8 = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha1&digits=8";
    var parse_url = try Key.init(alloc, url_str);
    defer parse_url.deinit();
    try testing.expectEqual(Algorithm.SHA1, parse_url.algorithm());

    url_str = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8";
    var parse_url2 = try Key.init(alloc, url_str);
    defer parse_url2.deinit();
    try testing.expectEqual(Algorithm.SHA256, parse_url2.algorithm());

    url_str = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha512&digits=8";
    var parse_url3 = try Key.init(alloc, url_str);
    defer parse_url3.deinit();
    try testing.expectEqual(Algorithm.SHA512, parse_url3.algorithm());

    url_str = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=md5&digits=8";
    var parse_url4 = try Key.init(alloc, url_str);
    defer parse_url4.deinit();
    try testing.expectEqual(Algorithm.MD5, parse_url4.algorithm());

    url_str = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=8";
    var parse_url5 = try Key.init(alloc, url_str);
    defer parse_url5.deinit();
    try testing.expectEqual(Algorithm.SHA1, parse_url5.algorithm());
}

test "Key 2" {
    const alloc = testing.allocator;

    const urlStr = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8";

    var pu = try Key.init(alloc, urlStr);
    defer pu.deinit();

    try testing.expectEqualStrings(urlStr, pu.string());
    try testing.expectEqualStrings("totp", pu.typ());

    const issuer = pu.issuer();
    try testing.expectEqualStrings("Example", issuer);

    try testing.expectEqualStrings("alice@google.com", pu.accountName());
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", pu.secret());

    // ==================

    const urlStr2 = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8";

    var pu2 = try Key.init(alloc, urlStr2);
    defer pu2.deinit();

    try testing.expectEqualStrings(urlStr2, pu2.string());
    try testing.expectEqualStrings("totp", pu2.typ());
    try testing.expectEqualStrings("", pu2.issuer());
    try testing.expectEqualStrings("", pu2.accountName());
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", pu2.secret());

    // ==================

    const urlStr3 = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8";

    var pu3 = try Key.init(alloc, urlStr3);
    defer pu3.deinit();

    try testing.expectEqualStrings(urlStr3, pu3.string());
    try testing.expectEqualStrings("totp", pu3.typ());
    try testing.expectEqualStrings("", pu3.issuer());
    try testing.expectEqualStrings("test", pu3.accountName());
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", pu3.secret());

    // ==================

    const urlStr33 = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8";

    var pu33 = try Key.init(alloc, urlStr33);
    defer pu33.deinit();

    try testing.expectEqualStrings(urlStr33, pu33.string());
    try testing.expectEqualStrings("totp", pu33.typ());

    const issuer33 = pu33.issuer();
    try testing.expectEqualStrings("Example", issuer33);

    try testing.expectEqualStrings("test", pu33.accountName());
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", pu33.secret());

    // ==================

    const urlStr5 = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=9&period=20";

    var pu5 = try Key.init(alloc, urlStr5);
    defer pu5.deinit();

    try testing.expectEqualStrings(urlStr5, pu5.string());
    try testing.expectEqualStrings("totp", pu5.typ());
    try testing.expectEqual(Digits.init(9), pu5.digits());
    try testing.expectEqual(20, pu5.period());

    // ==================

    const urlStr6 = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&period=20";

    var pu6 = try Key.init(alloc, urlStr6);
    defer pu6.deinit();

    try testing.expectEqual(Digits.Six, pu6.digits());

    // ==================

    const urlStr7 = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=a9&period=20";

    var pu7 = try Key.init(alloc, urlStr7);
    defer pu7.deinit();

    try testing.expectEqual(Digits.Six, pu7.digits());

    // ==================

    const urlStr8 = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=9&period=b20";

    var pu8 = try Key.init(alloc, urlStr8);
    defer pu8.deinit();

    try testing.expectEqual(30, pu8.period());
}

test "Algorithm" {
    try testing.expectEqualStrings("MD5", Algorithm.MD5.string());
    try testing.expectEqualStrings("SHA1", Algorithm.SHA1.string());
    try testing.expectEqualStrings("SHA256", Algorithm.SHA256.string());
    try testing.expectEqualStrings("SHA512", Algorithm.SHA512.string());

    try testing.expectEqual(auth_hmac.HmacMd5, Algorithm.MD5.hashType());
    try testing.expectEqual(auth_hmac.HmacSha1, Algorithm.SHA1.hashType());
    try testing.expectEqual(auth_hmac.sha2.HmacSha256, Algorithm.SHA256.hashType());
    try testing.expectEqual(auth_hmac.sha2.HmacSha512, Algorithm.SHA512.hashType());

    const msg = "test data";
    const key = "test key";

    const alloc = testing.allocator;

    const hd1 = try Algorithm.MD5.hash(alloc, msg, key);
    defer alloc.free(hd1);
    try assertEqual("0194d256ddb7b73fde24b0d3aa407b5e", hd1);

    const hd2 = try Algorithm.SHA1.hash(alloc, msg, key);
    defer alloc.free(hd2);

    try assertEqual("910cc7a8f8b718e409c9a8b0ff3af561c8e68262", hd2);

    const hd3 = try Algorithm.SHA256.hash(alloc, msg, key);
    defer alloc.free(hd3);
    try assertEqual("4695788ca94015a246422be13bbd966ade571842efc3a39296bdb6f2377597ff", hd3);

    const hd4 = try Algorithm.SHA512.hash(alloc, msg, key);
    defer alloc.free(hd4);
    try assertEqual("868000a7fdc71b2778d9c820b2058ebce87093ea1bcd9df772faf200b71484efaae15a461a0b509c034ace950a64c4330fac3932677fd509a02d588e74c01ff3", hd4);

    var hh = Algorithm.MD5.hashType().init(key);
    var hmacs: [Algorithm.MD5.hashType().mac_length]u8 = undefined;
    hh.update(msg);
    hh.final(hmacs[0..]);

    try assertEqual("0194d256ddb7b73fde24b0d3aa407b5e", hmacs[0..]);
}
