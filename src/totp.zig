const std = @import("std");
const fmt = std.fmt;
const sort = std.sort;
const ascii = std.ascii;
const Buffer = std.Buffer;
const random = std.crypto.random;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const otp = @import("./otp.zig");
const url = @import("./url.zig");
const time = @import("./time.zig");
const bytes = @import("./bytes.zig");
const base32 = @import("./base32.zig");

pub const Key = struct {
    orig: []const u8,
    url: url.URL,

    arena: ArenaAllocator,

    pub fn init(a: *Allocator, orig: []const u8) !Key {
        var u = try url.parse(a, orig);

        return Key{
            .orig = orig,
            .url = u,
            .arena = ArenaAllocator.init(a),
        };
    }

    pub fn deinit(self: *Key) void {
        self.arena.deinit();
    }

    pub fn string(self: *Key) []const u8 {
        return self.orig;
    }

    pub fn typ(self: *Key) []const u8 {
        return self.url.host.?;
    }

    pub fn issuer(self: *Key) []const u8 {
        var a = &self.arena.allocator;
        var q = try self.url.query(a);

        const iss = q.get("issuer");
        
        if (iss.len != 0) {
            return iss;
        }

        const p = bytes.trimLeft(self.url.path.?, "/");
        const i = bytes.index(p, ":").?;

        if (i < 0) {
            return "";
        }

        return p[0..i];
    }

    pub fn accountName(self: *Key) []const u8 {
        const p = bytes.trimLeft(self.url.path.?, "/");
        const i = bytes.index(p, ":").?;

        if (i < 0) {
            return "";
        }

        return p[0..i];
    }

    pub fn secret(self: *Key) ![]const u8 {
        var a = &self.arena.allocator;
        var q = try self.url.query(a);

        return q.get("secret");
    }

    pub fn period(self: *Key) !u32 {
        var a = &self.arena.allocator;
        var q = try self.url.query(a);

        const per = q.get("period");

        return @as(u32, per);
    }

    pub fn digit(self: *Key) !Digits {
        var a = &self.arena.allocator;
        var q = try self.url.query(a);

        const dig = q.get("digits");

        if (dig.len == 0) {
            return Digits.six;
        } 

        return Digits.eight;
    }

    pub fn algorithm(self: *Key) !otp.Algorithm {
        var a = &self.arena.allocator;
        var q = try self.url.query(a);

        const alg = try ascii.allocLowerString(a, q.get("algorithm"));

        if (bytes.eq(alg, "md5")) {
            return otp.Algorithm.md5;
        } else if (bytes.eq(alg, "sha256")) {
            return otp.Algorithm.sha256;
        } else if (bytes.eq(alg, "sha512")) {
            return otp.Algorithm.sha512;
        }

        return otp.Algorithm.sha1;
    }

    pub fn urlString(self: *Key) ![]const u8 {
        var a = &self.arena.allocator;
        var buf = &try Buffer.init(a, "");
        defer buf.deinit();

        try self.url.encode(buf);

        return buf.toSlice();
    }
};

// =============

pub const Digits = enum {
    six,
    eight,

    pub fn string(self: Digits) []const u8 {
        if (self == .six) {
            return "6";
        }

        return "8";
    }

    // Length returns the number of characters for this Digits.
    pub fn length(self: Digits) u32 {
        if (self == .six) {
            return 6;
        }

        return 8;
    }

    // Format converts an integer into the zero-filled size for this Digits.
    pub fn format(self: Digits, in: u32) ![]const u8 {
        const allocator = std.heap.page_allocator;
        defer allocator.deinit();

        const len = self.length();

        const f = try fmt.allocPrint(allocator, "{d:0>{d}}", .{len});

        return try fmt.allocPrint(allocator, f, .{in});
    }
};

// =============

pub fn encodeQuery(v: url.Values) ![:0]u8 {
    var buf = std.ArrayList(u8).init(v.allocator);
    defer buf.deinit();

    var alloc = std.heap.ArenaAllocator.init(v.allocator);
    defer alloc.deinit();

    var keys = try alloc.allocator().alloc([]const u8, v.data.count());
    var key_i: usize = 0;

    var data = (try v.data.clone()).iterator();
    while (data.next()) |kv| {
        keys[key_i] = kv.key_ptr.*;
        key_i += 1;
    }

    sort.block([]const u8, keys, {}, url.stringSort([]const u8));

    var buffer = try std.Buffer.init(v.allocator, "");
    var bufEscape = &buffer;
    defer bufEscape.deinit();

    for (keys) |k| {
        const vs = v.data.get(k).?;

        try url.pathEscape(bufEscape, k);
        const keyEscaped = bufEscape.toSlice();
        try bufEscape.resize(0);

        for (vs) |vv| {
            if (buf.len > 0) {
                try buf.appendSlice("&");
            }

            try url.pathEscape(bufEscape, vv);
            const vvEscaped = bufEscape.toSlice();
            try bufEscape.resize(0);

            try buf.appendSlice(keyEscaped);
            try buf.appendSlice("=");
            try buf.appendSlice(vvEscaped);
        }
    }

    return buf.toOwnedSliceSentinel(0);
}

// =============

pub fn validate(passcode: []const u8, secret: []const u8) bool {
    const t = time.now();

    return validateCustom(passcode, secret, t, validateOpts{
        .period = 30,
        .skew = 1,
        .digits = Digits.six,
        .algorithm = otp.Algorithm.sha1,
    }) catch false;
}

pub fn generateCode(secret: []const u8, t: time.Time) !u32 {
    return generateCodeCustom(secret, t, validateOpts{
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
pub fn generateCodeCustom(secret: []const u8, t: time.Time, opts: validateOpts) !u32 {
    if (opts.period == 0) {
        opts.period = 30;
    }

    return try otp.totp(secret, t.unix(), opts.digits.length(), opts.period, opts.algorithm);
}

pub fn totpValidateCustom(passcode: []const u8, secret: []const u8, t: i64, opts: validateOpts) !bool {
    const newPasscode = try generateCodeCustom(secret, t, opts);

    return bytes.eq(passcode, newPasscode);
}

// validate Custom
pub fn validateCustom(passcode: []const u8, secret: []const u8, t: time.Time, opts: validateOpts) !bool {
    const skew = opts.skew;

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

    var secret = try base32.encode(allocator, newOpts.secret.?, false);

    try v.set("secret", secret);
    try v.set("issuer", newOpts.issuer);

    var periodStr = try fmt.allocPrint(allocator, "{s}", .{newOpts.period});

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
