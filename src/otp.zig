const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Hmac = std.crypto.auth.hmac.Hmac;

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

    pub fn hash(self: Algorithm) type {
        return switch (self) {
            .sha1 => crypto.hash.Sha1,
            .sha256 => crypto.hash.sha2.Sha256,
            .sha512 => crypto.hash.sha2.Sha512,
            else => crypto.hash.Md5,
        };
    }
};

pub fn hotp(key: []const u8, counter: u64, digit: u32, alg: Algorithm) u32 {
    const h = Hmac(alg.hash());

    var hmac: [h.mac_length]u8 = undefined;
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

    h.create(hmac[0..], counter_bytes[0..], key);

    var offset = hmac[hmac.len - 1] & 0xf;
    var bin_code = hmac[offset .. offset + 4];
    var int_code = @as(u32, bin_code[3]) |
        @as(u32, bin_code[2]) << 8 |
        @as(u32, bin_code[1]) << 16 |
        @as(u32, bin_code[0]) << 24 & 0x7FFFFFFF;

    var code = int_code % (std.math.pow(u32, 10, digit));
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

    var counter = @divFloor(t, period);

    var data = try base32.decode(alloc, secret);
    defer alloc.free(data);

    var code = hotp(data, @as(u64, @bitCast(counter)), digit, alg);
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
    var counter = @as(u64, @intCast(@divFloor(t, 30)));

    var key = try base32.decode(alloc, secret);
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

    const h = Hmac(alg.hash());

    var hmac: [h.mac_length]u8 = undefined;

    h.create(hmac[0..], counter_bytes[0..], key);

    var offset = hmac[hmac.len - 1] & 0xf;
    var bytes = hmac[offset .. offset + 4];
    var result = @as(u32, bytes[3]) |
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
