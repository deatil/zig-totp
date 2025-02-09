const std = @import("std");
const fmt = std.fmt;
const sort = std.sort;
const math = std.math;
const ascii = std.ascii;
const testing = std.testing;
const Buffer = std.Buffer;
const random = std.crypto.random;
const Allocator = std.mem.Allocator;

pub const hotp = @import("./hotp.zig");
pub const time = @import("./time.zig");

pub const otp = hotp.otp;
pub const url = hotp.url;
pub const bytes = hotp.bytes;
pub const base32 = hotp.base32;
pub const otps = hotp.otps;
pub const otpError = hotp.otpError;

pub fn validate(alloc: Allocator, passcode: []const u8, secret: []const u8) bool {
    return validateCustom(alloc, passcode, secret, time.now().utc(), .{
        .period = 30,
        .skew = 1,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    }) catch false;
}

pub fn generateCode(alloc: Allocator, secret: []const u8, t: time.Time) ![]const u8 {
    return generateCodeCustom(alloc, secret, t, .{
        .period = 30,
        .skew = 1,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    });
}

pub const validateOpts = struct {
    // Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
    period: u32,
    // Periods before or after the current time to allow.  Value of 1 allows up to Period
    // of either side of the specified time.  Defaults to 0 allowed skews.  Values greater
    // than 1 are likely sketchy.
    skew: u32,
    // Digits as part of the input. Defaults to 6.
    digits: otps.Digits,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: otps.Algorithm,
    // Encoder to use for output code.
    encoder: otps.Encoder,
};

// generate Code Custom
pub fn generateCodeCustom(alloc: Allocator, secret: []const u8, t: time.Time, opts: validateOpts) ![]const u8 {
    var period = opts.period;
    if (period == 0) {
        period = 30;
    }

    const counter = @as(u64, @intCast(@divFloor(t.unix(), period)));

    const passcode = try hotp.generateCodeCustom(alloc, secret, counter, .{
        .digits = opts.digits,
        .algorithm = opts.algorithm,
        .encoder = opts.encoder,
    });

    return passcode;
}

// validate Custom
pub fn validateCustom(alloc: Allocator, passcode: []const u8, secret: []const u8, t: time.Time, opts: validateOpts) !bool {
    var period = opts.period;
    if (period == 0) {
        period = 30;
    }

    var counters = std.ArrayList(u64).init(alloc);
    defer counters.deinit();

    const counter = @as(i64, @intCast(@divFloor(t.unix(), period)));

    try counters.append(@as(u64, @intCast(counter)));
    if (opts.skew > 0) {
        for (1..opts.skew+1) |i| {
            try counters.append(@as(u64, @intCast(counter + @as(i64, @intCast(i)))));

            // fixed u64(i64) type
            const tmp = counter - @as(i64, @intCast(i));
            if (tmp >= 0) {
                try counters.append(@as(u64, @intCast(tmp)));
            } else {
                try counters.append(@as(u64, math.maxInt(u64)) - @as(u64, @intCast(@abs(tmp))) + 1);
            }
        }
    }

    const newCounters = try counters.toOwnedSlice();

    for (newCounters) |newCounter| {
        const res = try hotp.validateCustom(alloc, passcode, newCounter, secret, .{
            .digits = opts.digits,
            .algorithm = opts.algorithm,
            .encoder = opts.encoder,
        });
        if (res) {
            return true;
        }
    }

    return false;
}

pub const generateOpts = struct {
    // Name of the issuing Organization/Company.
    issuer: []const u8,
    // Name of the User's Account (eg, email address)
    accountName: []const u8,
    // Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
    period: u32,
    // Size in size of the generated Secret. Defaults to 20 bytes.
    secretSize: u32,
    // Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
    secret: ?[]const u8,
    // Digits to request. Defaults to 6.
    digits: ?otps.Digits,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: ?otps.Algorithm,
};

pub fn generate(allocator: Allocator, opts: generateOpts) !otps.Key {
    // url encode the Issuer/AccountName
    if (opts.issuer.len == 0) {
        return otpError.GenerateMissingIssuer;
    }

    if (opts.accountName.len == 0) {
        return otpError.GenerateMissingAccountName;
    }

    var newOpts = generateOpts{
        .issuer = opts.issuer,
        .accountName = opts.accountName,
        .period = opts.period,
        .secretSize = opts.secretSize,
        .secret = opts.secret,
        .digits = opts.digits,
        .algorithm = opts.algorithm,
    };

    if (newOpts.period == 0) {
        newOpts.period = 30;
    }

    if (newOpts.secretSize == 0) {
        newOpts.secretSize = 20;
    }

    if (newOpts.digits == null) {
        newOpts.digits = otps.Digits.Six;
    }

    if (newOpts.algorithm == null) {
        newOpts.algorithm = otps.Algorithm.sha1;
    }

    // otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

    var v = url.Values.init(allocator);

    var secret: []const u8 = undefined;
    if (newOpts.secret) |val| {
        secret = try base32.encode(allocator, val, false);
    } else {
        var s: []u8 = try allocator.alloc(u8, newOpts.secretSize);
        random.bytes(s[0..]);

        defer allocator.free(s);

        secret = try base32.encode(allocator, s, false);
    }

    try v.set("secret", secret);
    try v.set("issuer", newOpts.issuer);

    const periodStr = try fmt.allocPrint(allocator, "{d}", .{newOpts.period});

    try v.set("period", periodStr);
    try v.set("algorithm", newOpts.algorithm.?.string());
    try v.set("digits", try newOpts.digits.?.string());

    const rawQuery = try url.encodeQuery(v);

    var pathBuf = std.ArrayList(u8).init(allocator);
    defer pathBuf.deinit();

    try pathBuf.appendSlice("/");
    try pathBuf.appendSlice(newOpts.issuer);
    try pathBuf.appendSlice(":");
    try pathBuf.appendSlice(newOpts.accountName);

    const path = try pathBuf.toOwnedSlice();

    var u: url.Uri = .{
        .scheme = "otpauth",
        .user = null,
        .password = null,
        .host = .{ .percent_encoded = "totp" },
        .port = null,
        .path = .{ .percent_encoded = path },
        .query = .{ .percent_encoded = rawQuery },
        .fragment = null,
    };

    var bufUrl = std.ArrayList(u8).init(allocator);
    defer bufUrl.deinit();

    try u.format(";@+/?#", .{}, bufUrl.writer());

    const urlStr = try bufUrl.toOwnedSlice();

    return try otps.Key.init(allocator, urlStr);
}

test "test generate" {
    const alloc = std.heap.page_allocator;

    const secret = "test-data";

    var key = try generate(alloc, .{
        .issuer = "Example",
        .accountName = "accountName",
        .period = 30,
        .secretSize = 8,
        .secret = secret,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    const keyurl = key.urlString();
    const check = "otpauth://totp/Example:accountName?issuer=Example&period=30&digits=6&secret=ORSXG5BNMRQXIYI&algorithm=SHA1";

    try testing.expectFmt(check, "{s}", .{keyurl});
}

test "test generate no secret" {
    const alloc = std.heap.page_allocator;

    var key = try generate(alloc, .{
        .issuer = "Example",
        .accountName = "accountName",
        .period = 30,
        .secretSize = 8,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    const keyurl = key.urlString();

    try testing.expectEqual(104, keyurl.len);
}

// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
test "test ValidateRFCMatrix" {
    const alloc = std.heap.page_allocator;
    
    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);
    const secSha256 = try base32.encode(alloc, "12345678901234567890123456789012", true);
    const secSha512 = try base32.encode(alloc, "1234567890123456789012345678901234567890123456789012345678901234", true);
    
    const optsSha1 = validateOpts{
        .period = 0,
        .skew = 0,
        .digits = otps.Digits.Eight,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    };
    const optsSha256 = validateOpts{
        .period = 0,
        .skew = 0,
        .digits = otps.Digits.Eight,
        .algorithm = otps.Algorithm.sha256,
        .encoder = otps.Encoder.default,
    };
    const optsSha512 = validateOpts{
        .period = 0,
        .skew = 0,
        .digits = otps.Digits.Eight,
        .algorithm = otps.Algorithm.sha512,
        .encoder = otps.Encoder.default,
    };

    var t = time.Time.fromTimestamp(59).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "46119246", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "90693936", secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1111111109).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "07081804", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "68084774", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "25091201", secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1111111111).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "14050471", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "67062674", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "99943326", secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1234567890).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "89005924", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "91819424", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "93441116", secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(2000000000).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "69279037", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "90698825", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "38618901", secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(20000000000).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "65353130", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "77737706", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "47863826", secSha512, t, optsSha512));
}

test "test GenerateRFCMatrix" {
    const alloc = std.heap.page_allocator;
    
    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);
    const secSha256 = try base32.encode(alloc, "12345678901234567890123456789012", true);
    const secSha512 = try base32.encode(alloc, "1234567890123456789012345678901234567890123456789012345678901234", true);

    const optsSha1 = validateOpts{
        .period = 0,
        .skew = 0,
        .digits = otps.Digits.Eight,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    };
    const optsSha256 = validateOpts{
        .period = 0,
        .skew = 0,
        .digits = otps.Digits.Eight,
        .algorithm = otps.Algorithm.sha256,
        .encoder = otps.Encoder.default,
    };
    const optsSha512 = validateOpts{
        .period = 0,
        .skew = 0,
        .digits = otps.Digits.Eight,
        .algorithm = otps.Algorithm.sha512,
        .encoder = otps.Encoder.default,
    };

    var t = time.Time.fromTimestamp(59).utc();
    try testing.expectEqualStrings("94287082", try generateCodeCustom(alloc, secSha1, t, optsSha1));
    try testing.expectEqualStrings("46119246", try generateCodeCustom(alloc, secSha256, t, optsSha256));
    try testing.expectEqualStrings("90693936", try generateCodeCustom(alloc, secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1111111109).utc();
    try testing.expectEqualStrings("07081804", try generateCodeCustom(alloc, secSha1, t, optsSha1));
    try testing.expectEqualStrings("68084774", try generateCodeCustom(alloc, secSha256, t, optsSha256));
    try testing.expectEqualStrings("25091201", try generateCodeCustom(alloc, secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1111111111).utc();
    try testing.expectEqualStrings("14050471", try generateCodeCustom(alloc, secSha1, t, optsSha1));
    try testing.expectEqualStrings("67062674", try generateCodeCustom(alloc, secSha256, t, optsSha256));
    try testing.expectEqualStrings("99943326", try generateCodeCustom(alloc, secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1234567890).utc();
    try testing.expectEqualStrings("89005924", try generateCodeCustom(alloc, secSha1, t, optsSha1));
    try testing.expectEqualStrings("91819424", try generateCodeCustom(alloc, secSha256, t, optsSha256));
    try testing.expectEqualStrings("93441116", try generateCodeCustom(alloc, secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(2000000000).utc();
    try testing.expectEqualStrings("69279037", try generateCodeCustom(alloc, secSha1, t, optsSha1));
    try testing.expectEqualStrings("90698825", try generateCodeCustom(alloc, secSha256, t, optsSha256));
    try testing.expectEqualStrings("38618901", try generateCodeCustom(alloc, secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(20000000000).utc();
    try testing.expectEqualStrings("65353130", try generateCodeCustom(alloc, secSha1, t, optsSha1));
    try testing.expectEqualStrings("77737706", try generateCodeCustom(alloc, secSha256, t, optsSha256));
    try testing.expectEqualStrings("47863826", try generateCodeCustom(alloc, secSha512, t, optsSha512));

}

test "test ValidateSkew" {
    const alloc = std.heap.page_allocator;

    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);

    const optsSha1 = validateOpts{
        .period = 0,
        .skew = 1,
        .digits = otps.Digits.Eight,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    };
    
    var t = time.Time.fromTimestamp(29).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));
    
    t = time.Time.fromTimestamp(59).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));
    
    t = time.Time.fromTimestamp(61).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));
}

test "test generate 2" {
    const alloc = std.heap.page_allocator;

    var key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
        .period = 0,
        .secretSize = 0,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    try testing.expectEqualStrings("SnakeOil", key.issuer());
    try testing.expectEqualStrings("alice@example.com", key.accountName());
    try testing.expectEqual(32, key.secret().len);

    key = try generate(alloc, generateOpts{
        .issuer = "Snake Oil",
        .accountName = "alice@example.com",
        .period = 0,
        .secretSize = 20,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    try testing.expectEqual(true, bytes.contains(key.urlString(), "issuer=Snake%20Oil"));

    key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
        .period = 0,
        .secretSize = 20,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    try testing.expectEqual(32, key.secret().len);

    key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
        .period = 0,
        .secretSize = 13, // anything that is not divisible by 5, really
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    try testing.expectEqual(false, bytes.contains(key.secret(), "="));

    key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
        .period = 0,
        .secretSize = 0,
        .secret = "helloworld",
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    const sec = try base32.decode(alloc, key.secret());
    defer alloc.free(sec);

    try testing.expectEqualStrings("helloworld", sec);

    // ===================

    var errTrue: bool = false;
    _ = generate(alloc, generateOpts{
        .issuer = "",
        .accountName = "alice@example.com",
        .period = 0,
        .secretSize = 0,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    }) catch |err| {
        errTrue = true;
        try testing.expectEqual(otpError.GenerateMissingIssuer, err);
    };
    try testing.expectEqual(true, errTrue);

    errTrue = false;
    try testing.expectEqual(false, errTrue);
    _ = generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "",
        .period = 0,
        .secretSize = 0,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    }) catch |err| {
        errTrue = true;
        try testing.expectEqual(otpError.GenerateMissingAccountName, err);
    };
    try testing.expectEqual(true, errTrue);

    // ===================

    key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
        .period = 0,
        .secretSize = 20,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = null,
    });

    try testing.expectEqual(32, key.secret().len);

}

test "test GoogleLowerCaseSecret" {
    const alloc = std.heap.page_allocator;

    const urlStr = "otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google";

    var key = try otps.Key.init(alloc, urlStr);

    const sec = key.secret();
    const check = "qlt6vmy6svfx4bt4rpmisaiyol6hihca";

    try testing.expectFmt(check, "{s}", .{sec});

    const n = time.now().utc();
    const passcode = try generateCode(alloc, key.secret(), n);

    const res = validate(alloc, passcode, key.secret());

    try testing.expectEqual(true, res);
}

test "test SteamSecret" {
    const alloc = std.heap.page_allocator;

    const urlStr = "otpauth://totp/username%20steam:username?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&period=30&digits=5&issuer=username%20steam&encoder=steam";

    var key = try otps.Key.init(alloc, urlStr);

    const sec = key.secret();
    const check = "qlt6vmy6svfx4bt4rpmisaiyol6hihca";

    try testing.expectFmt(check, "{s}", .{sec});
    try testing.expectEqual(otps.Encoder.steam, key.encoder());
    try testing.expectEqual(5, key.digits().length());

    const n = time.now().utc();
    const opts = validateOpts{
        .period = key.period(),
        .skew = 0,
        .digits = key.digits(),
        .algorithm = otps.Algorithm.sha1,
        .encoder = key.encoder(),
    };
    const passcode = try generateCodeCustom(alloc, key.secret(), n, opts);

    try testing.expectEqual(passcode.len, key.digits().length());

    const valid = validateCustom(alloc, passcode, key.secret(), n, opts);

    try testing.expectEqual(true, valid);
}
