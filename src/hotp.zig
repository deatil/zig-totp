const std = @import("std");
const fmt = std.fmt;
const sort = std.sort;
const ascii = std.ascii;
const testing = std.testing;
const Buffer = std.Buffer;
const random = std.crypto.random;
const Allocator = std.mem.Allocator;

pub const otp = @import("./otp.zig");
pub const otps = otp.otps;
pub const url = otp.url;
pub const Uri = otp.Uri;
pub const bytes = otp.bytes;
pub const base32 = otp.base32;
pub const otpError = otps.otpError;

pub fn validate(alloc: Allocator, passcode: []const u8, counter: u64, secret: []const u8) bool {
    return validateCustom(alloc, passcode, counter, secret, .{
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    }) catch false;
}

pub fn generateCode(alloc: Allocator, secret: []const u8, counter: u64) ![]const u8 {
    return generateCodeCustom(alloc, secret, counter, .{
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    });
}

pub const validateOpts = struct {
    // Digits as part of the input. Defaults to 6.
    digits: otps.Digits,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: otps.Algorithm,
    // Encoder to use for output code.
    encoder: otps.Encoder,
};

// generate Code Custom
pub fn generateCodeCustom(alloc: Allocator, secret: []const u8, counter: u64, opts: validateOpts) ![]const u8 {
    const newSecret = try ascii.allocUpperString(alloc, secret);
    defer alloc.free(newSecret);
    
    const key = base32.decode(alloc, newSecret) catch {
        return otpError.ValidateSecretInvalidBase32;
    };
    defer alloc.free(key);

    switch (opts.encoder) {
        .steam => {
            const code = try otp.steam_guard(alloc, key, counter, opts.digits.length(), opts.algorithm);
            return @as([]const u8, code);
        },
        else => {
            const code = try otp.hotp(alloc, key, counter, opts.digits.length(), opts.algorithm);
            return @as([]const u8, try opts.digits.format(alloc, code));
        }
    }
}

// validate Custom
pub fn validateCustom(alloc: Allocator, passcode: []const u8, counter: u64, secret: []const u8, opts: validateOpts) !bool {
    if (passcode.len != opts.digits.length()) {
        return otpError.ValidateInputInvalidLength;
    }

    const otpstr = try generateCodeCustom(alloc, secret, counter, opts);

    return bytes.eq(passcode, otpstr);
}

pub const generateOpts = struct {
    // Name of the issuing Organization/Company.
    issuer: []const u8,
    // Name of the User's Account (eg, email address)
    accountName: []const u8,
    // Size in size of the generated Secret. Defaults to 20 bytes.
    secretSize: u32,
    // Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
    secret: ?[]const u8,
    // Digits to request. Defaults to 6.
    digits: otps.Digits,
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
        .secretSize = opts.secretSize,
        .secret = opts.secret,
        .digits = opts.digits,
        .algorithm = opts.algorithm,
    };

    if (newOpts.secretSize == 0) {
        newOpts.secretSize = 10;
    }

    if (newOpts.algorithm == null) {
        newOpts.algorithm = otp.Algorithm.sha1;
    }

    // otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

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
    try v.set("algorithm", newOpts.algorithm.?.string());
    try v.set("digits", try newOpts.digits.string(allocator));

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
        .host = .{ .percent_encoded = "hotp" },
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

test "test generateCode" {
    const alloc = std.heap.page_allocator;

    const secret = "test-data";
    const counter: u64 = 6;

    const passcode = try generateCode(alloc, secret, counter);

    const res = validate(alloc, passcode, counter, secret);

    try testing.expectEqual(true, res);
}

test "test generate" {
    const alloc = std.heap.page_allocator;

    const secret = "test-data";

    var key = try generate(alloc, generateOpts{
        .issuer = "Example",
        .accountName = "accountName",
        .secretSize = 8,
        .secret = secret,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    const keyurl = key.urlString();
    const check = "otpauth://hotp/Example:accountName?issuer=Example&digits=6&secret=ORSXG5BNMRQXIYI&algorithm=SHA1";

    try testing.expectFmt(check, "{s}", .{keyurl});
}

test "test generate no secret" {
    const alloc = std.heap.page_allocator;

    var key = try generate(alloc, generateOpts{
        .issuer = "Example",
        .accountName = "accountName",
        .secretSize = 8,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    const keyurl = key.urlString();

    try testing.expectEqual(94, keyurl.len);
}

// Test values from http://tools.ietf.org/html/rfc4226#appendix-D
test "test ValidateRFCMatrix" {
    const alloc = std.heap.page_allocator;
    
    const secret = try base32.encode(alloc, "12345678901234567890", true);
    const opts = validateOpts{
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    };

    try testing.expectEqual(true, validateCustom(alloc, "755224", 0, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "287082", 1, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "359152", 2, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "969429", 3, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "338314", 4, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "254676", 5, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "287922", 6, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "162583", 7, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "399871", 8, secret, opts));
    try testing.expectEqual(true, validateCustom(alloc, "520489", 9, secret, opts));
}

test "test GenerateRFCMatrix" {
    const alloc = std.heap.page_allocator;
    
    const secret = try base32.encode(alloc, "12345678901234567890", true);
    const opts = validateOpts{
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    };

    try testing.expectEqualStrings("755224", try generateCodeCustom(alloc, secret, 0, opts));
    try testing.expectEqualStrings("287082", try generateCodeCustom(alloc, secret, 1, opts));
    try testing.expectEqualStrings("359152", try generateCodeCustom(alloc, secret, 2, opts));
    try testing.expectEqualStrings("969429", try generateCodeCustom(alloc, secret, 3, opts));
    try testing.expectEqualStrings("338314", try generateCodeCustom(alloc, secret, 4, opts));
    try testing.expectEqualStrings("254676", try generateCodeCustom(alloc, secret, 5, opts));
    try testing.expectEqualStrings("287922", try generateCodeCustom(alloc, secret, 6, opts));
    try testing.expectEqualStrings("162583", try generateCodeCustom(alloc, secret, 7, opts));
    try testing.expectEqualStrings("399871", try generateCodeCustom(alloc, secret, 8, opts));
    try testing.expectEqualStrings("520489", try generateCodeCustom(alloc, secret, 9, opts));
}

test "test ValidatePadding" {
    const alloc = std.heap.page_allocator;
    
    const opts = validateOpts{
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
        .encoder = otps.Encoder.default,
    };

    // TestValidatePadding
    try testing.expectEqual(true, validateCustom(alloc, "831097", 0, "JBSWY3DPEHPK3PX", opts));

    // TestValidateLowerCaseSecret
    try testing.expectEqual(true, validateCustom(alloc, "831097", 0, "jbswy3dpehpk3px", opts));
}

test "test generate 2" {
    const alloc = std.heap.page_allocator;

    var key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
        .secretSize = 0,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    try testing.expectEqualStrings("SnakeOil", key.issuer());
    try testing.expectEqualStrings("alice@example.com", key.accountName());
    try testing.expectEqual(16, key.secret().len);

    key = try generate(alloc, generateOpts{
        .issuer = "Snake Oil",
        .accountName = "alice@example.com",
        .secretSize = 20,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    try testing.expectEqual(true, bytes.contains(key.urlString(), "issuer=Snake%20Oil"));

    key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
        .secretSize = 20,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    try testing.expectEqual(32, key.secret().len);

    key = try generate(alloc, generateOpts{
        .issuer = "SnakeOil",
        .accountName = "alice@example.com",
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
        .secretSize = 20,
        .secret = null,
        .digits = otps.Digits.Six,
        .algorithm = null,
    });

    try testing.expectEqual(32, key.secret().len);

}
