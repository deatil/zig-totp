const std = @import("std");
const fmt = std.fmt;
const sort = std.sort;
const ascii = std.ascii;
const testing = std.testing;
const Buffer = std.Buffer;
const random = std.crypto.random;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const otp = @import("./otp.zig");
const otp s= @import("./otps.zig");
const url = @import("./url.zig");
const time = @import("./time.zig");
const bytes = @import("./bytes.zig");
const base32 = @import("./base32.zig");

pub fn validate(passcode: []const u8, secret: []const u8) bool {
    const t = time.now();

    return validateCustom(passcode, secret, t, validateOpts{
        .period = 30,
        .skew = 1,
        .digits = Digits.six,
        .algorithm = otp.Algorithm.sha1,
    }) catch false;
}

pub fn generateCode(secret: []const u8, t: time.Time) ![]const u8 {
    return generateCodeCustom(secret, t.unix(), validateOpts{
        .period = 30,
        .skew = 1,
        .digits = Digits.six,
        .algorithm = otp.Algorithm.sha1,
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
    digits: Digits,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: otp.Algorithm,
};

// generate Code Custom
pub fn generateCodeCustom(secret: []const u8, t: i64, opts: validateOpts) ![]const u8 {
    var period = opts.period;
    
    if (period == 0) {
        period = 30;
    }

    const id = try otp.totp(secret, t, opts.digits.length(), period, opts.algorithm);

    var value: [10]u8 = undefined;
    const size = fmtInt(value[0..], @as(u64, @intCast(id)));

    const code = value[size..];
    return @as([]const u8, code);
}

pub fn totpValidateCustom(passcode: []const u8, secret: []const u8, t: i64, opts: validateOpts) !bool {
    const newPasscode = try generateCodeCustom(secret, t, opts);

    return bytes.eq(passcode, newPasscode);
}

// validate Custom
pub fn validateCustom(passcode: []const u8, secret: []const u8, t: time.Time, opts: validateOpts) !bool {
    var skew = opts.skew;

    var counter = @divFloor(t.unix(), opts.period);
    var counter2 = @divFloor(t.unix(), opts.period);

    while (skew > 0) {
        counter += skew;

        const res = totpValidateCustom(passcode, secret, counter * opts.period, opts) catch false;
        if (res) {
            return true;
        }

        counter2 -= skew;
        const res2 = totpValidateCustom(passcode, secret, counter2 * opts.period, opts) catch false;
        if (res2) {
            return true;
        }

        skew -= 1;
    }

    return false;
}

pub const generateError = error{
    ErrGenerateMissingIssuer,
    ErrGenerateMissingAccountName,
};

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
    digits: Digits,
    // Algorithm to use for HMAC. Defaults to SHA1.
    algorithm: ?otp.Algorithm,
};

pub fn generate(opts: generateOpts) !Key {
    // url encode the Issuer/AccountName
    if (opts.issuer.len == 0) {
        return generateError.ErrGenerateMissingIssuer;
    }

    if (opts.accountName.len == 0) {
        return generateError.ErrGenerateMissingAccountName;
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

    if (newOpts.algorithm == null) {
        newOpts.algorithm = otp.Algorithm.sha1;
    }

    // otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

    const allocator = std.heap.page_allocator;
    var alloc: std.heap.ArenaAllocator = std.heap.ArenaAllocator.init(allocator);

    var v: url.Values = url.Values.init(allocator);

    if (newOpts.secret == null) {
        var s: []u8 = try alloc.allocator().alloc(u8, newOpts.secretSize);
        random.bytes(s[0..]);

        newOpts.secret.? = s;
    }

    const secret = try base32.encode(allocator, newOpts.secret.?, false);

    try v.set("secret", secret);
    try v.set("issuer", newOpts.issuer);

    const periodStr = try fmt.allocPrint(allocator, "{s}", .{newOpts.period});

    try v.set("period", periodStr);
    try v.set("algorithm", newOpts.algorithm.?.string());
    try v.set("digits", newOpts.digits.string());

    const rawQuery = try encodeQuery(v);

    var u = url.URL{
        .scheme = "otpauth",
        .host = "totp",
        .path = "/" + newOpts.issuer + ":" + newOpts.accountName,
        .raw_query = rawQuery,
    };

    return try Key.init(alloc, u.string());
}

fn fmtInt(buf: []u8, value: u64) usize {
    var w = buf.len;
    var v = value;
    if (v == 0) {
        w -= 1;
        buf[w] = '0';
    } else {
        while (v > 0) {
            w -= 1;
            buf[w] = @as(u8, @intCast(@mod(v, 10))) + '0';
            v /= 10;
        }
    }
    
    return w;
}

test "test generateCode" {
    const secret = "test-data";
    const t = time.now();

    const code = try generateCode(secret, t);

    const res = validate(code, secret);

    try testing.expectEqual(true, res);
}

test "test generate" {
    const secret = "test-data";

    const key = try generate(generateOpts{
        .issuer = "issuer",
        .accountName = "accountName",
        .period = 30,
        .secretSize = 8,
        .secret = secret,
        .digits = Digits.six,
        .algorithm = otp.Algorithm.sha1,
    });

    const keyurl = try key.urlString();

    try testing.expectFmt("123erty", "{s}", .{keyurl});
}
