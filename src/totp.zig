const std = @import("std");
const fmt = std.fmt;
const sort = std.sort;
const math = std.math;
const ascii = std.ascii;
const testing = std.testing;
const Buffer = std.Buffer;
const random = std.crypto.random;
const Allocator = std.mem.Allocator;

pub const url = @import("url.zig");
pub const otp = @import("otp.zig");
pub const otps = @import("otps.zig");
pub const hotp = @import("hotp.zig");
pub const time = @import("time.zig");
pub const bytes = @import("bytes.zig");
pub const base32 = @import("base32.zig");

pub const OtpError = otps.OtpError;

pub fn validate(alloc: Allocator, passcode: []const u8, secret: []const u8) bool {
    return validateCustom(alloc, passcode, secret, time.now().utc(), .{
        .period = 30,
        .skew = 1,
        .digits = .Six,
        .algorithm = .SHA1,
        .encoder = .Default,
    }) catch false;
}

pub fn generateCode(alloc: Allocator, secret: []const u8, t: time.Time) ![]const u8 {
    return generateCodeCustom(alloc, secret, t, .{
        .period = 30,
        .skew = 1,
        .digits = .Six,
        .algorithm = .SHA1,
        .encoder = .Default,
    });
}

pub const ValidateOpts = struct {
    // Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
    period: u32 = 30,
    // Periods before or after the current time to allow.  Value of 1 allows up to Period
    // of either side of the specified time.  Defaults to 0 allowed skews.  Values greater
    // than 1 are likely sketchy.
    skew: u32 = 0,
    // Digits as part of the input. Defaults to 6.
    digits: otps.Digits = .Six,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: otps.Algorithm = .SHA1,
    // Encoder to use for output code.
    encoder: otps.Encoder = .Default,
};

// generate Code Custom
pub fn generateCodeCustom(alloc: Allocator, secret: []const u8, t: time.Time, opts: ValidateOpts) ![]const u8 {
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
pub fn validateCustom(alloc: Allocator, passcode: []const u8, secret: []const u8, t: time.Time, opts: ValidateOpts) !bool {
    var period = opts.period;
    if (period == 0) {
        period = 30;
    }

    var counters = std.ArrayList(u64).init(alloc);
    defer counters.deinit();

    const counter = @as(i64, @intCast(@divFloor(t.unix(), period)));

    try counters.append(@as(u64, @intCast(counter)));
    if (opts.skew > 0) {
        for (1..opts.skew + 1) |i| {
            try counters.append(@as(u64, @intCast(counter + @as(i64, @intCast(i)))));

            // fix u64(i64)
            const tmp = counter - @as(i64, @intCast(i));
            if (tmp >= 0) {
                try counters.append(@as(u64, @intCast(tmp)));
            } else {
                try counters.append(@as(u64, math.maxInt(u64)) - @as(u64, @intCast(@abs(tmp))) + 1);
            }
        }
    }

    const new_counters = try counters.toOwnedSlice();
    defer alloc.free(new_counters);

    for (new_counters) |new_counter| {
        const res = try hotp.validateCustom(alloc, passcode, new_counter, secret, .{
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

pub const GenerateOpts = struct {
    // Name of the issuing Organization/Company.
    issuer: []const u8,
    // Name of the User's Account (eg, email address)
    account_name: []const u8,
    // Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
    period: u32 = 30,
    // Size in size of the generated Secret. Defaults to 20 bytes.
    secret_size: u32 = 20,
    // Secret to store. Defaults to a randomly generated secret of SecretSize.
    // You should generally leave this empty.
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

    // otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

    var v = url.Values.init(allocator);
    defer v.deinit();

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

    const period_str = try fmt.allocPrint(allocator, "{d}", .{opts.period});
    defer allocator.free(period_str);

    try v.set("period", period_str);
    try v.set("algorithm", opts.algorithm.string());

    const digits_str = try opts.digits.string(allocator);
    defer allocator.free(digits_str);
    try v.set("digits", digits_str);

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
        .host = .{ .percent_encoded = "totp" },
        .port = null,
        .path = .{ .percent_encoded = path },
        .query = .{ .percent_encoded = raw_query },
        .fragment = null,
    };

    var buf_url = std.ArrayList(u8).init(allocator);
    defer buf_url.deinit();

    try u.format(";@+/?#", .{}, buf_url.writer());

    const url_str = try buf_url.toOwnedSlice();
    defer allocator.free(url_str);

    return otps.Key.init(allocator, url_str);
}

test "test generate" {
    const alloc = testing.allocator;

    const secret = "test-data";

    var key = try generate(alloc, .{
        .issuer = "Example",
        .account_name = "account_name",
        .period = 30,
        .secret_size = 8,
        .secret = secret,
        .digits = .Six,
        .algorithm = .SHA1,
    });
    defer key.deinit();

    const keyurl = key.urlString();
    defer alloc.free(keyurl);

    const check = "otpauth://totp/Example:account_name?issuer=Example&period=30&digits=6&secret=ORSXG5BNMRQXIYI&algorithm=SHA1";

    try testing.expectFmt(check, "{s}", .{keyurl});
}

test "test generate no secret" {
    const alloc = testing.allocator;

    var key = try generate(alloc, .{
        .issuer = "Example",
        .account_name = "account_name",
        .period = 30,
        .secret_size = 8,
        .digits = .Six,
        .algorithm = .SHA1,
    });
    defer key.deinit();

    const keyurl = key.urlString();
    defer alloc.free(keyurl);

    try testing.expectEqual(105, keyurl.len);
}

// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
test "test ValidateRFCMatrix" {
    const alloc = testing.allocator;

    const secMd5 = try base32.encode(alloc, "1234567890123456", true);
    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);
    const secSha256 = try base32.encode(alloc, "12345678901234567890123456789012", true);
    const secSha512 = try base32.encode(alloc, "1234567890123456789012345678901234567890123456789012345678901234", true);

    defer alloc.free(secMd5);
    defer alloc.free(secSha1);
    defer alloc.free(secSha256);
    defer alloc.free(secSha512);

    const optsMd5 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .MD5,
    };
    const optsSha1 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .SHA1,
    };
    const optsSha256 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .SHA256,
    };
    const optsSha512 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .SHA512,
    };

    var t = time.Time.fromTimestamp(59).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "85931907", secMd5, t, optsMd5));
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "46119246", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "90693936", secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1111111109).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "48407180", secMd5, t, optsMd5));
    try testing.expectEqual(true, try validateCustom(alloc, "07081804", secSha1, t, optsSha1));
    try testing.expectEqual(true, try validateCustom(alloc, "68084774", secSha256, t, optsSha256));
    try testing.expectEqual(true, try validateCustom(alloc, "25091201", secSha512, t, optsSha512));

    t = time.Time.fromTimestamp(1111111111).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "24643869", secMd5, t, optsMd5));
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

fn testGenerateCodeCustom(check: []const u8, alloc: Allocator, secret: []const u8, t: time.Time, opts: ValidateOpts) !void {
    const res = try generateCodeCustom(alloc, secret, t, opts);
    defer alloc.free(res);

    try testing.expectEqualStrings(check, res);
}

test "test GenerateRFCMatrix" {
    const alloc = testing.allocator;

    const secMd5 = try base32.encode(alloc, "1234567890123456", true);
    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);
    const secSha256 = try base32.encode(alloc, "12345678901234567890123456789012", true);
    const secSha512 = try base32.encode(alloc, "1234567890123456789012345678901234567890123456789012345678901234", true);

    defer alloc.free(secMd5);
    defer alloc.free(secSha1);
    defer alloc.free(secSha256);
    defer alloc.free(secSha512);

    const optsMd5 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .MD5,
    };
    const optsSha1 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .SHA1,
    };
    const optsSha256 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .SHA256,
    };
    const optsSha512 = ValidateOpts{
        .digits = .Eight,
        .algorithm = .SHA512,
    };

    var t = time.Time.fromTimestamp(59).utc();
    try testGenerateCodeCustom("85931907", alloc, secMd5, t, optsMd5);
    try testGenerateCodeCustom("94287082", alloc, secSha1, t, optsSha1);
    try testGenerateCodeCustom("46119246", alloc, secSha256, t, optsSha256);
    try testGenerateCodeCustom("90693936", alloc, secSha512, t, optsSha512);

    t = time.Time.fromTimestamp(1111111109).utc();
    try testGenerateCodeCustom("48407180", alloc, secMd5, t, optsMd5);
    try testGenerateCodeCustom("07081804", alloc, secSha1, t, optsSha1);
    try testGenerateCodeCustom("68084774", alloc, secSha256, t, optsSha256);
    try testGenerateCodeCustom("25091201", alloc, secSha512, t, optsSha512);

    t = time.Time.fromTimestamp(1111111111).utc();
    try testGenerateCodeCustom("24643869", alloc, secMd5, t, optsMd5);
    try testGenerateCodeCustom("14050471", alloc, secSha1, t, optsSha1);
    try testGenerateCodeCustom("67062674", alloc, secSha256, t, optsSha256);
    try testGenerateCodeCustom("99943326", alloc, secSha512, t, optsSha512);

    t = time.Time.fromTimestamp(1234567890).utc();
    try testGenerateCodeCustom("89005924", alloc, secSha1, t, optsSha1);
    try testGenerateCodeCustom("91819424", alloc, secSha256, t, optsSha256);
    try testGenerateCodeCustom("93441116", alloc, secSha512, t, optsSha512);

    t = time.Time.fromTimestamp(2000000000).utc();
    try testGenerateCodeCustom("69279037", alloc, secSha1, t, optsSha1);
    try testGenerateCodeCustom("90698825", alloc, secSha256, t, optsSha256);
    try testGenerateCodeCustom("38618901", alloc, secSha512, t, optsSha512);

    t = time.Time.fromTimestamp(20000000000).utc();
    try testGenerateCodeCustom("65353130", alloc, secSha1, t, optsSha1);
    try testGenerateCodeCustom("77737706", alloc, secSha256, t, optsSha256);
    try testGenerateCodeCustom("47863826", alloc, secSha512, t, optsSha512);
}

test "test ValidateSkew" {
    const alloc = testing.allocator;

    const secSha1 = try base32.encode(alloc, "12345678901234567890", true);
    defer alloc.free(secSha1);

    const optsSha1 = ValidateOpts{
        .skew = 1,
        .digits = .Eight,
        .algorithm = .SHA1,
    };

    var t = time.Time.fromTimestamp(29).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));

    t = time.Time.fromTimestamp(59).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));

    t = time.Time.fromTimestamp(61).utc();
    try testing.expectEqual(true, try validateCustom(alloc, "94287082", secSha1, t, optsSha1));
}

test "test generate 2" {
    const alloc = testing.allocator;

    var key = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
    });
    defer key.deinit();

    try testing.expectEqualStrings("SnakeOil", key.issuer());
    try testing.expectEqualStrings("alice@example.com", key.accountName());
    try testing.expectEqual(32, key.secret().len);

    var key2 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
    });
    defer key2.deinit();

    try testing.expectEqualStrings("SnakeOil", key2.issuer());
    try testing.expectEqualStrings("alice@example.com", key2.accountName());
    try testing.expectEqual(30, key2.period());
    try testing.expectEqual(otps.Digits.Six, key2.digits());
    try testing.expectEqual(otps.Algorithm.SHA1, key2.algorithm());
    try testing.expectEqual(32, key2.secret().len);

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
    });
    defer key6.deinit();

    const keyurl6 = key6.urlString();
    defer alloc.free(keyurl6);

    try testing.expectEqual(true, bytes.contains(keyurl6, "issuer=Snake%20Oil"));

    var key7 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .period = 0,
        .secret_size = 20,
    });
    defer key7.deinit();

    try testing.expectEqual(32, key7.secret().len);

    var key8 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret_size = 13, // anything that is not divisible by 5, really
    });
    defer key8.deinit();

    try testing.expectEqual(false, bytes.contains(key8.secret(), "="));

    var key9 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .secret = "helloworld",
    });
    defer key9.deinit();

    const sec = try base32.decode(alloc, key9.secret());
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

    var key10 = try generate(alloc, GenerateOpts{
        .issuer = "SnakeOil",
        .account_name = "alice@example.com",
        .period = 0,
        .secret_size = 20,
        .digits = .Six,
    });
    defer key10.deinit();

    try testing.expectEqual(32, key10.secret().len);
}

test "test GoogleLowerCaseSecret" {
    const alloc = testing.allocator;

    const urlStr = "otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google";

    var key = try otps.Key.init(alloc, urlStr);
    defer key.deinit();

    const sec = key.secret();
    const check = "qlt6vmy6svfx4bt4rpmisaiyol6hihca";

    try testing.expectFmt(check, "{s}", .{sec});
    try testing.expectEqualStrings("Google", key.issuer());

    const n = time.now().utc();
    const passcode = try generateCode(alloc, key.secret(), n);
    defer alloc.free(passcode);

    const res = validate(alloc, passcode, key.secret());

    try testing.expectEqual(true, res);
}

test "test SteamSecret" {
    const alloc = testing.allocator;

    const urlStr = "otpauth://totp/username%20steam:username?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&period=30&digits=5&issuer=username%20steam&encoder=steam";

    var key = try otps.Key.init(alloc, urlStr);
    defer key.deinit();

    const sec = key.secret();
    const check = "qlt6vmy6svfx4bt4rpmisaiyol6hihca";

    try testing.expectFmt(check, "{s}", .{sec});
    try testing.expectEqual(otps.Encoder.Steam, key.encoder());
    try testing.expectEqual(5, key.digits().length());
    try testing.expectEqualStrings("username%20steam", key.issuer());
    try testing.expectEqualStrings("username", key.accountName());

    const issuer2 = try url.unescapeQuery(alloc, key.issuer());
    defer alloc.free(issuer2);

    try testing.expectEqualStrings("username steam", issuer2);

    const n = time.now().utc();
    const opts = ValidateOpts{
        .period = key.period(),
        .skew = 0,
        .digits = key.digits(),
        .algorithm = .SHA1,
        .encoder = key.encoder(),
    };
    const passcode = try generateCodeCustom(alloc, key.secret(), n, opts);
    defer alloc.free(passcode);

    try testing.expectEqual(passcode.len, key.digits().length());

    const valid = validateCustom(alloc, passcode, key.secret(), n, opts);

    try testing.expectEqual(true, valid);
}
