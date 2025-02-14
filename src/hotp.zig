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
pub const OtpError = otps.OtpError;

pub fn validate(alloc: Allocator, passcode: []const u8, counter: u64, secret: []const u8) bool {
    return validateCustom(alloc, passcode, counter, secret, .{
        .digits = .Six,
        .algorithm = .SHA1,
        .encoder = .Default,
    }) catch false;
}

pub fn generateCode(alloc: Allocator, secret: []const u8, counter: u64) ![]const u8 {
    return generateCodeCustom(alloc, secret, counter, .{
        .digits = .Six,
        .algorithm = .SHA1,
        .encoder = .Default,
    });
}

pub const ValidateOpts = struct {
    // Digits as part of the input. Defaults to 6.
    digits: otps.Digits = .Six,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: otps.Algorithm = .SHA1,
    // Encoder to use for output code.
    encoder: otps.Encoder = .Default,
};

// generate Code Custom
pub fn generateCodeCustom(alloc: Allocator, secret: []const u8, counter: u64, opts: ValidateOpts) ![]const u8 {
    const newSecret = try ascii.allocUpperString(alloc, secret);
    defer alloc.free(newSecret);
    
    const key = base32.decode(alloc, newSecret) catch {
        return OtpError.ValidateSecretInvalidBase32;
    };
    defer alloc.free(key);

    switch (opts.encoder) {
        .Steam => {
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
pub fn validateCustom(alloc: Allocator, passcode: []const u8, counter: u64, secret: []const u8, opts: ValidateOpts) !bool {
    if (passcode.len != opts.digits.length()) {
        return OtpError.ValidateInputInvalidLength;
    }

    const otp_str = try generateCodeCustom(alloc, secret, counter, opts);

    return bytes.eq(passcode, otp_str);
}

pub const GenerateOpts = struct {
    // Name of the issuing Organization/Company.
    issuer: []const u8,
    // Name of the User's Account (eg, email address)
    account_name: []const u8,
    // Size in size of the generated Secret. Defaults to 20 bytes.
    secret_size: u32 = 10,
    // Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
    secret: []const u8 = "",
    // Digits to request. Defaults to 6.
    digits: otps.Digits = .Six,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: otps.Algorithm = .SHA1,
};

pub fn generate(allocator: Allocator, opts: GenerateOpts) !otps.Key {
    // url encode the Issuer/AccountName
    if (opts.issuer.len == 0) {
        return OtpError.GenerateMissingIssuer;
    }

    if (opts.account_name.len == 0) {
        return OtpError.GenerateMissingAccountName;
    }

    // otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

    var v = url.Values.init(allocator);

    var secret: []const u8 = undefined;
    if (opts.secret.len > 0) {
        secret = try base32.encode(allocator, opts.secret, false);
    } else {
        var s: []u8 = try allocator.alloc(u8, opts.secret_size);
        random.bytes(s[0..]);

        defer allocator.free(s);

        secret = try base32.encode(allocator, s, false);
    }

    defer allocator.free(secret);

    try v.set("secret", secret);
    try v.set("issuer", opts.issuer);
    try v.set("algorithm", opts.algorithm.string());
    try v.set("digits", try opts.digits.string(allocator));

    const raw_query = try url.encodeQuery(v);
    defer allocator.free(raw_query);

    var path_buf = std.ArrayList(u8).init(allocator);
    defer path_buf.deinit();

    try path_buf.appendSlice("/");
    try path_buf.appendSlice(opts.issuer);
    try path_buf.appendSlice(":");
    try path_buf.appendSlice(opts.account_name);

    const path = try path_buf.toOwnedSlice();
    defer allocator.free(path);

    var u = url.Uri{
        .scheme = "otpauth",
        .user = null,
        .password = null,
        .host = .{ .percent_encoded = "hotp" },
        .port = null,
        .path = .{ .percent_encoded = path },
        .query = .{ .percent_encoded = raw_query },
        .fragment = null,
    };

    var buf_url = std.ArrayList(u8).init(allocator);
    defer buf_url.deinit();

    try u.format(";@+/?#", .{}, buf_url.writer());

    const url_str = try buf_url.toOwnedSlice();

    return try otps.Key.init(allocator, url_str);
}

test "test generateCode" {
    const alloc = std.heap.page_allocator;

    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const counter: u64 = 6;

    const passcode = try generateCode(alloc, secret, counter);

    const res = validate(alloc, passcode, counter, secret);

    try testing.expectEqual(true, res);
}

test "test generate" {
    const alloc = std.heap.page_allocator;

    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    var key = try generate(alloc, GenerateOpts{
        .issuer = "Example",
        .account_name = "account_name",
        .secret_size = 8,
        .secret = secret,
        .digits = .Six,
        .algorithm = .SHA1,
    });

    const keyurl = key.urlString();
    const check = "otpauth://hotp/Example:account_name?issuer=Example&digits=6&secret=I5CVURCHJZBFMR2ZGNKFCT2KKFDUKWSEI5HEEVSHLEZVIUKPJJIQ&algorithm=SHA1";

    try testing.expectFmt(check, "{s}", .{keyurl});
}

test "test generate no secret" {
    const alloc = std.heap.page_allocator;

    var key = try generate(alloc, GenerateOpts{
        .issuer = "Example",
        .account_name = "account_name",
        .secret_size = 8,
        .digits = .Six,
        .algorithm = .SHA1,
    });

    const keyurl = key.urlString();

    try testing.expectEqual(95, keyurl.len);
}

// Test values from http://tools.ietf.org/html/rfc4226#appendix-D
test "test ValidateRFCMatrix" {
    const alloc = std.heap.page_allocator;
    
    const secret = try base32.encode(alloc, "12345678901234567890", true);
    const opts = ValidateOpts{
        .digits = .Six,
        .algorithm = .SHA1,
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
    const opts = ValidateOpts{
        .digits = .Six,
        .algorithm = .SHA1,
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

test "test GenerateCodeCustom" {
    const alloc = std.heap.page_allocator;
    
    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);

    var err_true: bool = false;
    if (generateCodeCustom(alloc, "foo", 1, ValidateOpts{})) |_| {
        // no action
    } else |err| {
        err_true = true;
        try testing.expectEqual(OtpError.ValidateSecretInvalidBase32, err);
    }
    try testing.expectEqual(true, err_true);

    err_true = false;
    if (generateCodeCustom(alloc, secSha1, 1, ValidateOpts{})) |code| {
        try testing.expectEqual(6, code.len);
    } else |err| {
        err_true = true;
        try testing.expectEqual(OtpError.ValidateSecretInvalidBase32, err);
    }
    try testing.expectEqual(false, err_true);
}

test "test ValidateInvalid" {
    const alloc = std.heap.page_allocator;
    
    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);

    var err_true: bool = false;
    if (validateCustom(alloc, "foo", 11, secSha1, .{
        .digits = .Six,
        .algorithm = .SHA1,
    })) |_| {
        // 
    } else |err| {
        err_true = true;
        try testing.expectEqual(OtpError.ValidateInputInvalidLength, err);
    }
    try testing.expectEqual(true, err_true);

    err_true = false;
    if (validateCustom(alloc, "000000", 11, secSha1, .{
        .digits = .Six,
        .algorithm = .SHA1,
    })) |val| {
        try testing.expectEqual(false, val);
    } else |err| {
        err_true = true;
        try testing.expectEqual(OtpError.ValidateSecretInvalidBase32, err);
    }
    try testing.expectEqual(false, err_true);

    try testing.expectEqual(false, validate(alloc, "000000", 11, secSha1));
}

test "test ValidatePadding" {
    const alloc = std.heap.page_allocator;
    
    const opts = ValidateOpts{
        .digits = .Six,
        .algorithm = .SHA1,
    };

    // TestValidatePadding
    try testing.expectEqual(true, validateCustom(alloc, "831097", 0, "JBSWY3DPEHPK3PX", opts));

    // TestValidateLowerCaseSecret
    try testing.expectEqual(true, validateCustom(alloc, "831097", 0, "jbswy3dpehpk3px", opts));
}

test "test generate 2" {
    const alloc = std.heap.page_allocator;

    var key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret_size = 10,
    });

    try testing.expectEqualStrings("SnakeOil", key.issuer());
    try testing.expectEqualStrings("alice@example.com", key.accountName());
    try testing.expectEqual(16, key.secret().len);

    key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
    });

    try testing.expectEqualStrings("SnakeOil", key.issuer());
    try testing.expectEqualStrings("alice@example.com", key.accountName());
    try testing.expectEqual(otps.Digits.Six, key.digits());
    try testing.expectEqual(otps.Algorithm.SHA1, key.algorithm());
    try testing.expectEqual(16, key.secret().len);

    key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .algorithm = .SHA256,
    });
    try testing.expectEqual(otps.Algorithm.SHA256, key.algorithm());

    key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .algorithm = .SHA512,
    });
    try testing.expectEqual(otps.Algorithm.SHA512, key.algorithm());

    key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .algorithm = .MD5,
    });
    try testing.expectEqual(otps.Algorithm.MD5, key.algorithm());

    key = try generate(alloc, GenerateOpts{
        .issuer = "Snake Oil",
        .account_name = "alice@example.com",
        .secret_size = 20,
        .digits = .Six,
        .algorithm = .SHA1,
    });

    try testing.expectEqual(true, bytes.contains(key.urlString(), "issuer=Snake%20Oil"));

    key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret_size = 20,
    });

    try testing.expectEqual(32, key.secret().len);

    key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret = "helloworld",
    });

    const sec = try base32.decode(alloc, key.secret());
    defer alloc.free(sec);

    try testing.expectEqualStrings("helloworld", sec);

    // ===================

    var errTrue: bool = false;
    _ = generate(alloc, GenerateOpts{
        .issuer = "",
        .account_name = "alice@example.com",
    }) catch |err| {
        errTrue = true;
        try testing.expectEqual(OtpError.GenerateMissingIssuer, err);
    };
    try testing.expectEqual(true, errTrue);

    errTrue = false;
    try testing.expectEqual(false, errTrue);
    _ = generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "",
    }) catch |err| {
        errTrue = true;
        try testing.expectEqual(OtpError.GenerateMissingAccountName, err);
    };
    try testing.expectEqual(true, errTrue);

    // ===================

    key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret_size = 20,
    });

    try testing.expectEqual(32, key.secret().len);

}
