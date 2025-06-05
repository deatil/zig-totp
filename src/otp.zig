const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const base32 = @import("base32.zig");
const otps = @import("otps.zig");
const Algorithm = otps.Algorithm;

pub fn hotp(alloc: Allocator, key: []const u8, counter: u64, digit: u32, alg: Algorithm) !u32 {
    var counter_bytes: [8]u8 = undefined;
    mem.writeInt(u64, counter_bytes[0..8], counter, .big);

    var hmac: []u8 = try alg.hash(alloc, counter_bytes[0..], key);
    defer alloc.free(hmac);

    // "Dynamic truncation" in RFC 4226
    // http://tools.ietf.org/html/rfc4226#section-5.4
    const offset = hmac[hmac.len - 1] & 0xf;
    const bin_code = hmac[offset .. offset + 4];
    const int_code = @as(u32, bin_code[3]) |
        @as(u32, bin_code[2]) << 8 |
        @as(u32, bin_code[1]) << 16 |
        @as(u32, bin_code[0]) << 24 & 0x7FFFFFFF;

    const code = int_code % (std.math.pow(u32, 10, digit));
    return code;
}

const STEAM_CHARS: *const [26:0]u8 = "23456789BCDFGHJKMNPQRTVWXY";

pub fn steam_guard(alloc: Allocator, key: []const u8, counter: u64, digit: u32, alg: Algorithm) ![]u8 {
    var counter_bytes: [8]u8 = undefined;
    mem.writeInt(u64, counter_bytes[0..8], counter, .big);

    var hmac: []u8 = try alg.hash(alloc, counter_bytes[0..], key);
    defer alloc.free(hmac);

    const offset = hmac[hmac.len - 1] & 0xf;
    const hmac_bytes = hmac[offset .. offset + 4];
    const result = (@as(u32, hmac_bytes[3]) & 0xff) |
        @as(u32, hmac_bytes[2] & 0xff) << 8 |
        @as(u32, hmac_bytes[1] & 0xff) << 16 |
        @as(u32, hmac_bytes[0] & 0x7f) << 24;

    var fc = result;

    var bin_code = std.ArrayList(u8).init(alloc);
    defer bin_code.deinit();

    for (0..digit) |_| {
        try bin_code.append(STEAM_CHARS[(fc % STEAM_CHARS.len)]);
        fc /= @as(u32, @intCast(STEAM_CHARS.len));
    }

    return bin_code.toOwnedSlice();
}

pub fn totp(alloc: Allocator, key: []const u8, t: i64, digit: u32, period: u32, alg: Algorithm) !u32 {
    const counter = @divFloor(t, period);

    const code = try hotp(alloc, key, @as(u64, @bitCast(counter)), digit, alg);
    return code;
}

pub fn totp_steam_guard(alloc: Allocator, key: []const u8, t: i64, digit: u32, period: u32, alg: Algorithm) ![]u8 {
    const counter = @as(u64, @intCast(@divFloor(t, period)));

    const code = try steam_guard(alloc, key, counter, digit, alg);
    return code;
}

test "hotp test" {
    const secret: []const u8 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const counter: u64 = 3;
    const digits: u32 = 6;
    const code: u32 = 969429;

    const alloc = testing.allocator;

    const key = try base32.decode(alloc, secret);
    defer alloc.free(key);

    const passcode = try hotp(alloc, key, counter, digits, .SHA1);

    try testing.expectEqual(code, passcode);
}

test "Steam Guard test" {
    const secret: []const u8 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const counter: u64 = 5;
    const digits: u32 = 6;
    const code = "MD224T";

    const alloc = testing.allocator;

    const key = try base32.decode(alloc, secret);
    defer alloc.free(key);

    const key2 = try steam_guard(alloc, key, counter, digits, .SHA1);
    defer alloc.free(key2);

    try testing.expectEqualSlices(u8, code[0..], key2[0..]);
}

test "totp test" {
    const secret: []const u8 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const t: i64 = 1234567890;
    const digits: u32 = 8;
    const period: u32 = 30;
    const code: u32 = 89005924;

    const alloc = testing.allocator;

    const key = try base32.decode(alloc, secret);
    defer alloc.free(key);

    const passcode = try totp(alloc, key, t, digits, period, .SHA1);

    try testing.expectEqual(code, passcode);
}

test "Totp Steam Guard test" {
    const secret: []const u8 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const t: i64 = 1234567890;
    const digits: u32 = 8;
    const period: u32 = 30;
    const code = "VHHQY742";

    const alloc = testing.allocator;

    const key = try base32.decode(alloc, secret);
    defer alloc.free(key);

    const passcode = try totp_steam_guard(alloc, key, t, digits, period, .SHA1);
    defer alloc.free(passcode);

    try testing.expectEqualSlices(u8, code[0..], passcode[0..]);
}
