const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const base32 = @import("./base32.zig");

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

pub fn hotp(key: []const u8, counter: u64, digit: u32, alg: Algorithm) u32 {
    const counter_bytes = [8]u8{
        @as(u8, @truncate(counter >> 56)),
        @as(u8, @truncate(counter >> 48)),
        @as(u8, @truncate(counter >> 40)),
        @as(u8, @truncate(counter >> 32)),
        @as(u8, @truncate(counter >> 24)),
        @as(u8, @truncate(counter >> 16)),
        @as(u8, @truncate(counter >> 8)),
        @as(u8, @truncate(counter)),
    };

    var hmac: []u8 = alg.hash(counter_bytes[0..], key);

    const offset = hmac[hmac.len - 1] & 0xf;
    const bin_code = hmac[offset .. offset + 4];
    const int_code = @as(u32, bin_code[3]) |
        @as(u32, bin_code[2]) << 8 |
        @as(u32, bin_code[1]) << 16 |
        @as(u32, bin_code[0]) << 24 & 0x7FFFFFFF;

    const code = int_code % (std.math.pow(u32, 10, digit));
    return code;
}

test "hotp test" {
    const key: []const u8 = "GM4VC2CQN5UGS33ZJJVWYUSFMQ4HOQJW";
    const counter: u64 = 1662681600;
    const digits: u32 = 6;
    const code: u32 = 886679;

    try testing.expectEqual(code, hotp(key, counter, digits, .sha1));
}

pub fn totp(secret: []const u8, t: i64, digit: u32, period: u32, alg: Algorithm) !u32 {
    const alloc = std.heap.page_allocator;

    const counter = @divFloor(t, period);

    const data = try base32.decode(alloc, secret);
    defer alloc.free(data);

    const code = hotp(data, @as(u64, @bitCast(counter)), digit, alg);
    return code;
}

test "totp test" {
    const secret: []const u8 = "GM4VC2CQN5UGS33ZJJVWYUSFMQ4HOQJW";
    const t: i64 = 1662681600;
    const digits: u32 = 6;
    const period: u32 = 30;
    const code: u32 = 473526;

    try testing.expectEqual(code, try totp(secret, t, digits, period, .sha1));
}

const STEAM_CHARS: *const [26:0]u8 = "23456789BCDFGHJKMNPQRTVWXY";

pub fn steam_guard(secret: []const u8, t: i64, alg: Algorithm) ![5]u8 {
    const alloc = std.heap.page_allocator;
    const counter = @as(u64, @intCast(@divFloor(t, 30)));

    const key = try base32.decode(alloc, secret);
    defer alloc.free(key);

    const counter_bytes = [8]u8{
        @as(u8, @truncate(counter >> 56)),
        @as(u8, @truncate(counter >> 48)),
        @as(u8, @truncate(counter >> 40)),
        @as(u8, @truncate(counter >> 32)),
        @as(u8, @truncate(counter >> 24)),
        @as(u8, @truncate(counter >> 16)),
        @as(u8, @truncate(counter >> 8)),
        @as(u8, @truncate(counter)),
    };

    var hmac: []u8 = alg.hash(counter_bytes[0..], key);

    const offset = hmac[hmac.len - 1] & 0xf;
    const bytes = hmac[offset .. offset + 4];
    const result = @as(u32, bytes[3]) |
        @as(u32, bytes[2]) << 8 |
        @as(u32, bytes[1]) << 16 |
        @as(u32, bytes[0]) << 24 & 0x7FFFFFFF;

    var fc = result;
    var bin_code = [_]u8{0} ** 5;

    for (0..5) |i| {
        bin_code[i] = STEAM_CHARS[(fc % STEAM_CHARS.len)];
        fc /= @as(u32, @intCast(STEAM_CHARS.len));
    }
    return bin_code;
}

test "Steam Guard test" {
    const secret: []const u8 = "GM4VC2CQN5UGS33ZJJVWYUSFMQ4HOQJW";
    const t: i64 = 1662681600;
    const code = "4PRPM";

    try testing.expectEqualSlices(u8, code[0..], (try steam_guard(secret, t, .sha1))[0..]);
}
