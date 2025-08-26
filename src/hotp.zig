const std = @import("std");
const fmt = std.fmt;
const ascii = std.ascii;
const testing = std.testing;
const random = std.crypto.random;
const Allocator = std.mem.Allocator;

pub const url = @import("url.zig");
pub const otp = @import("otp.zig");
pub const otps = @import("otps.zig");
pub const bytes = @import("bytes.zig");
pub const base32 = @import("base32.zig");

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
        },
    }
}

// validate Custom
pub fn validateCustom(alloc: Allocator, passcode: []const u8, counter: u64, secret: []const u8, opts: ValidateOpts) !bool {
    if (passcode.len != opts.digits.length()) {
        return OtpError.ValidateInputInvalidLength;
    }

    const otp_str = try generateCodeCustom(alloc, secret, counter, opts);
    defer alloc.free(otp_str);

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

pub fn generate(alloc: Allocator, opts: GenerateOpts) !otps.Key {
    // url encode the Issuer/AccountName
    if (opts.issuer.len == 0) {
        return OtpError.GenerateMissingIssuer;
    }

    if (opts.account_name.len == 0) {
        return OtpError.GenerateMissingAccountName;
    }

    // otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

    var v = url.Values.init(alloc);
    defer v.deinit();

    var secret: []const u8 = undefined;
    if (opts.secret.len > 0) {
        secret = try base32.encode(alloc, opts.secret, false);
    } else {
        var s: []u8 = try alloc.alloc(u8, opts.secret_size);
        random.bytes(s[0..]);

        defer alloc.free(s);

        secret = try base32.encode(alloc, s, false);
    }

    defer alloc.free(secret);

    try v.set("secret", secret);
    try v.set("issuer", opts.issuer);
    try v.set("algorithm", opts.algorithm.string());

    const digits_str = try opts.digits.string(alloc);
    defer alloc.free(digits_str);
    try v.set("digits", digits_str);

    const raw_query = try url.encodeQuery(v);
    defer alloc.free(raw_query);

    var path_buf = try std.ArrayList(u8).initCapacity(alloc, 0);
    defer path_buf.deinit(alloc);

    try path_buf.appendSlice(alloc, "/");
    try path_buf.appendSlice(alloc, opts.issuer);
    try path_buf.appendSlice(alloc, ":");
    try path_buf.appendSlice(alloc, opts.account_name);

    const path = try path_buf.toOwnedSlice(alloc);
    defer alloc.free(path);

    const uri: url.Uri = .{
        .scheme = "otpauth",
        .user = null,
        .password = null,
        .host = .{ .percent_encoded = "hotp" },
        .port = null,
        .path = .{ .percent_encoded = path },
        .query = .{ .percent_encoded = raw_query },
        .fragment = null,
    };

    const url_str = fmt.allocPrint(alloc, "{f}", .{
        uri.fmt(.all),
    }) catch "";
    defer alloc.free(url_str);

    return otps.Key.init(alloc, url_str);
}

test "generateCode" {
    const alloc = testing.allocator;

    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const counter: u64 = 6;

    const passcode = try generateCode(alloc, secret, counter);
    defer alloc.free(passcode);

    const res = validate(alloc, passcode, counter, secret);

    try testing.expectEqual(true, res);
}

test "generate" {
    const alloc = testing.allocator;

    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    var key = try generate(alloc, .{
        .issuer = "Example",
        .account_name = "account_name",
        .secret_size = 8,
        .secret = secret,
        .digits = .Six,
        .algorithm = .SHA1,
    });
    defer key.deinit();

    const keyurl = key.urlString();
    defer alloc.free(keyurl);

    const check = "otpauth://hotp/Example:account_name?issuer=Example&digits=6&secret=I5CVURCHJZBFMR2ZGNKFCT2KKFDUKWSEI5HEEVSHLEZVIUKPJJIQ&algorithm=SHA1";

    try testing.expectFmt(check, "{s}", .{keyurl});
}

test "generate no secret" {
    const alloc = testing.allocator;

    var key = try generate(alloc, GenerateOpts{
        .issuer = "Example",
        .account_name = "account_name",
        .secret_size = 8,
        .digits = .Six,
        .algorithm = .SHA1,
    });
    defer key.deinit();

    const keyurl = key.urlString();
    defer alloc.free(keyurl);

    try testing.expectEqual(95, keyurl.len);
}

// Test values from http://tools.ietf.org/html/rfc4226#appendix-D
test "ValidateRFCMatrix" {
    const alloc = testing.allocator;

    const secret = try base32.encode(alloc, "12345678901234567890", true);
    defer alloc.free(secret);

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

fn testGenerateCodeCustom(check: []const u8, alloc: Allocator, secret: []const u8, counter: u64, opts: ValidateOpts) !void {
    const res = try generateCodeCustom(alloc, secret, counter, opts);
    defer alloc.free(res);

    try testing.expectEqualStrings(check, res);
}

test "GenerateRFCMatrix" {
    const alloc = testing.allocator;

    const secret = try base32.encode(alloc, "12345678901234567890", true);
    defer alloc.free(secret);

    const opts = ValidateOpts{
        .digits = .Six,
        .algorithm = .SHA1,
    };

    try testGenerateCodeCustom("755224", alloc, secret, 0, opts);
    try testGenerateCodeCustom("287082", alloc, secret, 1, opts);
    try testGenerateCodeCustom("359152", alloc, secret, 2, opts);
    try testGenerateCodeCustom("969429", alloc, secret, 3, opts);
    try testGenerateCodeCustom("338314", alloc, secret, 4, opts);
    try testGenerateCodeCustom("254676", alloc, secret, 5, opts);
    try testGenerateCodeCustom("287922", alloc, secret, 6, opts);
    try testGenerateCodeCustom("162583", alloc, secret, 7, opts);
    try testGenerateCodeCustom("399871", alloc, secret, 8, opts);
    try testGenerateCodeCustom("520489", alloc, secret, 9, opts);
}

test "GenerateCodeCustom" {
    const alloc = testing.allocator;

    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);
    defer alloc.free(secSha1);

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
        defer alloc.free(code);

        try testing.expectEqual(6, code.len);
    } else |err| {
        err_true = true;
        try testing.expectEqual(OtpError.ValidateSecretInvalidBase32, err);
    }
    try testing.expectEqual(false, err_true);
}

test "ValidateInvalid" {
    const alloc = testing.allocator;

    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);
    defer alloc.free(secSha1);

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

test "ValidatePadding" {
    const alloc = testing.allocator;

    const opts = ValidateOpts{
        .digits = .Six,
        .algorithm = .SHA1,
    };

    // TestValidatePadding
    try testing.expectEqual(true, validateCustom(alloc, "831097", 0, "JBSWY3DPEHPK3PX", opts));

    // TestValidateLowerCaseSecret
    try testing.expectEqual(true, validateCustom(alloc, "831097", 0, "jbswy3dpehpk3px", opts));
}

test "generate 2" {
    const alloc = testing.allocator;

    var key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret_size = 10,
    });
    defer key.deinit();

    const issuer = key.issuer();
    try testing.expectEqualStrings("SnakeOil", issuer);
    try testing.expectEqualStrings("alice@example.com", key.accountName());
    try testing.expectEqual(16, key.secret().len);

    var key2 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
    });
    defer key2.deinit();

    const issuer2 = key2.issuer();
    try testing.expectEqualStrings("SnakeOil", issuer2);
    try testing.expectEqualStrings("alice@example.com", key2.accountName());
    try testing.expectEqual(otps.Digits.Six, key2.digits());
    try testing.expectEqual(otps.Algorithm.SHA1, key2.algorithm());
    try testing.expectEqual(16, key2.secret().len);

    var key3 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .algorithm = .SHA256,
    });
    defer key3.deinit();
    try testing.expectEqual(otps.Algorithm.SHA256, key3.algorithm());

    var key4 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .algorithm = .SHA512,
    });
    defer key4.deinit();
    try testing.expectEqual(otps.Algorithm.SHA512, key4.algorithm());

    var key5 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .algorithm = .MD5,
    });
    defer key5.deinit();
    try testing.expectEqual(otps.Algorithm.MD5, key5.algorithm());

    var key6 = try generate(alloc, GenerateOpts{
        .issuer = "Snake Oil",
        .account_name = "alice@example.com",
        .secret_size = 20,
        .digits = .Six,
        .algorithm = .SHA1,
    });
    defer key6.deinit();

    const keyurl6 = key6.urlString();
    defer alloc.free(keyurl6);

    try testing.expectEqual(true, bytes.contains(keyurl6, "issuer=Snake%20Oil"));

    var key7 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret_size = 20,
    });
    defer key7.deinit();

    try testing.expectEqual(32, key7.secret().len);

    var key8 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret = "helloworld",
    });
    defer key8.deinit();

    const sec = try base32.decode(alloc, key8.secret());
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

    var key9 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret_size = 20,
    });
    defer key9.deinit();

    try testing.expectEqual(32, key9.secret().len);
}
