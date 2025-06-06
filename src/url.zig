const std = @import("std");
const mem = std.mem;
const sort = std.sort;
const Allocator = mem.Allocator;

const ArrayList = std.ArrayList(u8);
const StringMap = std.hash_map.StringHashMap([]const u8);

const bytes = @import("bytes.zig");

pub const Uri = std.Uri;

const encoding = enum {
    Path,
    PathSegment,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
};

pub const Error = error{
    EscapeError,
    InvalidHostError,
    QuerySemicolonSeparatorError,
};

fn shouldEscape(c: u8, mode: encoding) bool {
    if ('A' <= c and c <= 'Z' or 'a' <= c and c <= 'z' or '0' <= c and c <= '9') {
        return false;
    }
    if (mode == encoding.Host or mode == encoding.Zone) {
        switch (c) {
            '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '[', ']', '<', '>', '"' => return false,
            else => {},
        }
    }
    switch (c) {
        '-', '_', '.', '~' => return false,
        '$', '&', '+', ',', '/', ':', ';', '=', '?', '@' => {
            switch (mode) {
                encoding.Path => return c == '?',
                encoding.PathSegment => return c == '/' or c == ';' or c == ',' or c == '?',
                encoding.UserPassword => return c == '@' or c == '/' or c == '?' or c == ':',
                encoding.QueryComponent => return true,
                encoding.Fragment => return false,
                else => {},
            }
        },
        else => {},
    }
    if (mode == encoding.Fragment) {
        switch (c) {
            '!', '(', ')', '*' => return false,
            else => {},
        }
    }
    return true;
}

fn ishex(c: u8) bool {
    if ('0' <= c and c <= '9') {
        return true;
    }
    if ('a' <= c and c <= 'f') {
        return true;
    }
    if ('A' <= c and c <= 'F') {
        return true;
    }
    return false;
}

fn unhex(c: u8) u8 {
    if ('0' <= c and c <= '9') {
        return c - '0';
    }
    if ('a' <= c and c <= 'f') {
        return c - 'a' + 10;
    }
    if ('A' <= c and c <= 'F') {
        return c - 'A' + 10;
    }
    return 0;
}

fn is25(s: []const u8) bool {
    return mem.eql(u8, s, "%25");
}

fn unescape(t: []u8, ctx: UnescapeContext, s: []const u8, mode: encoding) void {
    if (ctx.canUnEscape()) {
        var j: usize = 0;
        var i: usize = 0;
        while (i < s.len) {
            switch (s[i]) {
                '%' => {
                    t[j] = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    j = j + 1;
                    i = i + 3;
                },
                '+' => {
                    if (mode == encoding.QueryComponent) {
                        t[j] = ' ';
                    } else {
                        t[j] = '+';
                    }
                    j = j + 1;
                    i = i + 1;
                },
                else => {
                    t[j] = s[i];
                    j = j + 1;
                    i = i + 1;
                },
            }
        }
    } else {
        @memcpy(t, s);
    }
}

const UnescapeContext = struct {
    buffer_size: usize,
    has_plus: bool,
    length: usize,

    // returns true if we can unescape the string with the current unescape context.
    fn canUnEscape(self: UnescapeContext) bool {
        return !(self.buffer_size == self.length and !self.has_plus);
    }

    fn len(self: UnescapeContext) usize {
        return self.buffer_size;
    }
};

// countEscape calcutates and reurns the size of the buffer necessary for
// storing unescaped s.
fn countUneEscape(s: []const u8, mode: encoding) !UnescapeContext {
    var n: usize = 0;
    var has_plus: bool = true;
    var i: usize = 0;
    while (i < s.len) {
        switch (s[i]) {
            '%' => {
                n = n + 1;
                if (i + 2 >= s.len or !ishex(s[i + 1]) or !ishex(s[i + 2])) {
                    return Error.EscapeError;
                }
                if (mode == encoding.Host and unhex(s[i + 1]) < 9 and !is25(s[i .. i + 3])) {
                    return Error.EscapeError;
                }
                if (mode == encoding.Zone) {
                    const v = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    if (!is25(s[i .. i + 3]) and v != ' ' and shouldEscape(v, encoding.Host)) {
                        return Error.EscapeError;
                    }
                }
                i = i + 3;
            },
            '+' => {
                has_plus = mode == encoding.QueryComponent;
                i = i + 1;
            },
            else => {
                if ((mode == encoding.Host or mode == encoding.Zone) and s[i] < 0x80 and shouldEscape(s[i], mode)) {
                    return Error.InvalidHostError;
                }
                i = i + 1;
            },
        }
    }

    return .{
        .buffer_size = s.len - 2 * n,
        .has_plus = has_plus,
        .length = s.len,
    };
}

pub fn queryEscape(a: *ArrayList, s: []const u8) !void {
    const ctx = countEscape(s, encoding.QueryComponent);
    try a.resize(ctx.len());

    const buf = try a.toOwnedSlice();
    defer a.allocator.free(buf);

    escape(buf, ctx, s, encoding.QueryComponent);

    try a.resize(0);
    try a.appendSlice(buf);
}

pub fn queryUnescape(a: *ArrayList, s: []const u8) !void {
    const ctx = try countUneEscape(s, encoding.QueryComponent);
    try a.resize(ctx.buffer_size);

    const buf = try a.toOwnedSlice();
    defer a.allocator.free(buf);

    unescape(buf, ctx, s, encoding.QueryComponent);

    try a.resize(0);
    try a.appendSlice(buf);
}

pub fn queryUnescapeBuf(buf: []u8, s: []const u8) ![]const u8 {
    const ctx = try countUneEscape(s, encoding.QueryComponent);

    unescape(buf, ctx, s, encoding.QueryComponent);

    return buf[0..ctx.buffer_size];
}

pub fn pathEscape(a: *ArrayList, s: []const u8) !void {
    const ctx = countEscape(s, encoding.PathSegment);
    try a.resize(ctx.len());

    const buf = try a.toOwnedSlice();
    defer a.allocator.free(buf);

    escape(buf, ctx, s, encoding.PathSegment);

    try a.resize(0);
    try a.appendSlice(buf);
}

pub fn pathUnescape(a: *ArrayList, s: []const u8) !void {
    const ctx = try countUneEscape(s, encoding.PathSegment);
    try a.resize(ctx.buffer_size);

    const buf = try a.toOwnedSlice();
    defer a.allocator.free(buf);

    unescape(buf, ctx, s, encoding.PathSegment);

    try a.resize(0);
    try a.appendSlice(buf);
}

pub fn pathUnescapeBuf(buf: []u8, s: []const u8) ![]const u8 {
    const ctx = try countUneEscape(s, encoding.PathSegment);

    unescape(buf, ctx, s, encoding.PathSegment);

    return buf[0..ctx.buffer_size];
}

const EscapeContext = struct {
    space_count: usize,
    hex_count: usize,
    length: usize,

    fn canEscape(self: EscapeContext) bool {
        return !(self.space_count == 0 and self.hex_count == 0);
    }

    fn len(self: EscapeContext) usize {
        return self.length + 2 * self.hex_count;
    }
};

fn escape(t: []u8, ctx: EscapeContext, s: []const u8, mode: encoding) void {
    if (ctx.canEscape()) {
        var i: usize = 0;
        if (ctx.hex_count == 0) {
            while (i < s.len) {
                if (s[i] == ' ') {
                    t[i] = '+';
                } else {
                    t[i] = s[i];
                }
                i = i + 1;
            }
        } else {
            i = 0;
            var j: usize = 0;
            const alpha: []const u8 = "0123456789ABCDEF";
            while (i < s.len) {
                const c = s[i];
                if (c == ' ' and mode == encoding.QueryComponent) {
                    t[j] = '+';
                    j = j + 1;
                } else if (shouldEscape(c, mode)) {
                    t[j] = '%';
                    t[j + 1] = alpha[c >> 4];
                    t[j + 2] = alpha[c & 15];
                    j = j + 3;
                } else {
                    t[j] = s[i];
                    j = j + 1;
                }
                i = i + 1;
            }
        }
    } else {
        @memcpy(t[0..], s[0..]);
    }
}

fn countEscape(s: []const u8, mode: encoding) EscapeContext {
    var space_count: usize = 0;
    var hex_count: usize = 0;
    for (s) |c| {
        if (shouldEscape(c, mode)) {
            if (c == ' ' and mode == encoding.QueryComponent) {
                space_count = space_count + 1;
            } else {
                hex_count = hex_count + 1;
            }
        }
    }

    return EscapeContext{
        .space_count = space_count,
        .hex_count = hex_count,
        .length = s.len,
    };
}

pub fn stringSort(comptime T: type) fn (void, T, T) bool {
    return struct {
        pub fn inner(_: void, a: T, b: T) bool {
            if (a.len < b.len) {
                for (a, 0..) |aa, i| {
                    if (aa > b[i]) {
                        return false;
                    }
                }
            } else {
                for (b, 0..) |bb, j| {
                    if (bb < a[j]) {
                        return false;
                    }
                }
            }

            return true;
        }
    }.inner;
}

/// Values maps a string key to a list of values.
/// It is typically used for query parameters and form values.
/// Unlike in the http.Header map, the keys in a Values map
/// are case-sensitive.
pub const Values = struct {
    data: StringMap,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Values {
        return .{
            .data = StringMap.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.data.deinit();
    }

    /// Get gets the first value associated with the given key.
    pub fn get(self: *Self, key: []const u8) ?[]const u8 {
        return self.data.get(key);
    }

    /// Set sets the key to value. It replaces any existing
    /// values.
    pub fn set(self: *Self, key: []const u8, val: []const u8) !void {
        _ = try self.data.getOrPut(key);

        try self.add(key, val);
    }

    /// Add adds the value to key. It appends to any existing
    /// values associated with key.
    pub fn add(self: *Self, key: []const u8, val: []const u8) !void {
        try self.data.put(key, val);
    }

    pub fn del(self: *Self, key: []const u8) bool {
        return self.data.remove(key);
    }

    pub fn has(self: *Self, key: []const u8) bool {
        return self.data.contains(key);
    }

    /// Encode encodes the values into `URL encoded` form
    /// ("bar=baz&foo=quux") sorted by key.
    pub fn encode(self: *Self) ![:0]u8 {
        const alloc = self.allocator;

        var buf = std.ArrayList(u8).init(alloc);
        defer buf.deinit();

        var keys = try alloc.alloc([]const u8, self.data.count());
        var key_i: usize = 0;

        defer alloc.free(keys);

        var data_clone = try self.data.clone();
        defer data_clone.deinit();

        var data = data_clone.iterator();
        while (data.next()) |kv| {
            keys[key_i] = kv.key_ptr.*;
            key_i += 1;
        }

        sort.block([]const u8, keys, {}, stringSort([]const u8));

        var buf_escape = std.ArrayList(u8).init(alloc);
        defer buf_escape.deinit();

        for (keys) |k| {
            const vs = self.data.get(k).?;

            try queryEscape(&buf_escape, k);

            const key_escaped = try buf_escape.toOwnedSlice();
            defer alloc.free(key_escaped);
            try buf_escape.resize(0);

            if (buf.items.len > 0) {
                try buf.appendSlice("&");
            }

            try queryEscape(&buf_escape, vs);
            const vv_escaped = try buf_escape.toOwnedSlice();
            defer alloc.free(vv_escaped);
            try buf_escape.resize(0);

            try buf.appendSlice(key_escaped);
            try buf.appendSlice("=");
            try buf.appendSlice(vv_escaped);
        }

        return buf.toOwnedSliceSentinel(0);
    }
};

// ParseQuery parses the URL-encoded query string and returns
// a map listing the values specified for each key.
// ParseQuery always returns a non-nil map containing all the
// valid query parameters found; err describes the first decoding error
// encountered, if any.
//
// Query is expected to be a list of key=value settings separated by ampersands.
// A setting without an equals sign is interpreted as a key set to an empty
// value.
// Settings containing a non-URL-encoded semicolon are considered invalid.
pub fn parseQuery(allocator: Allocator, query: []const u8) !Values {
    var v = Values.init(allocator);

    var query_data: []const u8 = query;

    while (query_data.len > 0) {
        const cut_data = bytes.cut(query_data, "&");

        query_data = cut_data.after;

        if (bytes.contains(cut_data.before, ";")) {
            continue;
        }

        if (cut_data.before.len == 0) {
            continue;
        }

        const cut_data2 = bytes.cut(cut_data.before, "=");

        try v.add(cut_data2.before, cut_data2.after);
    }

    return v;
}

pub fn encodeQuery(v: Values) ![:0]u8 {
    const alloc = v.allocator;

    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();

    var keys = try alloc.alloc([]const u8, v.data.count());
    var key_i: usize = 0;

    defer alloc.free(keys);

    var data_clone = try v.data.clone();
    defer data_clone.deinit();

    var data = data_clone.iterator();
    while (data.next()) |kv| {
        keys[key_i] = kv.key_ptr.*;
        key_i += 1;
    }

    sort.block([]const u8, keys, {}, stringSort([]const u8));

    var buf_escape = std.ArrayList(u8).init(alloc);
    defer buf_escape.deinit();

    for (keys) |k| {
        const vs = v.data.get(k).?;

        try pathEscape(&buf_escape, k);

        const key_escaped = try buf_escape.toOwnedSlice();
        defer alloc.free(key_escaped);
        try buf_escape.resize(0);

        if (buf.items.len > 0) {
            try buf.appendSlice("&");
        }

        try pathEscape(&buf_escape, vs);
        const vv_escaped = try buf_escape.toOwnedSlice();
        defer alloc.free(vv_escaped);
        try buf_escape.resize(0);

        try buf.appendSlice(key_escaped);
        try buf.appendSlice("=");
        try buf.appendSlice(vv_escaped);
    }

    return buf.toOwnedSliceSentinel(0);
}

pub fn unescapeQuery(alloc: Allocator, query: []const u8) ![]const u8 {
    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();

    try queryUnescape(&buf, query);
    const res = try buf.toOwnedSlice();

    return res;
}

const testing = std.testing;

test "test Values" {
    const alloc = testing.allocator;

    var v = Values.init(alloc);
    defer v.deinit();

    try v.set("secret", "secret_val");
    try v.set("issuer", "issuer_val");

    const url_str = try v.encode();
    defer alloc.free(url_str);
    const check = "issuer=issuer_val&secret=secret_val";

    try testing.expectEqualSlices(u8, url_str[0..], check[0..]);

    try testing.expectEqual(v.has("issuer"), true);
    try testing.expectEqual(v.has("issuer2"), false);

    try v.set("issuer2", "issuer_val2");

    try testing.expectEqual(v.has("issuer2"), true);

    _ = v.del("issuer2");

    try testing.expectEqual(v.has("issuer2"), false);
}

test "test Values 2" {
    const alloc = testing.allocator;

    var v = Values.init(alloc);
    defer v.deinit();

    try v.set("secret", "secret_val data");
    try v.set("issuer", "issuer_val");

    const url_str = try v.encode();
    defer alloc.free(url_str);
    const check = "issuer=issuer_val&secret=secret_val+data";

    try testing.expectEqualSlices(u8, url_str[0..], check[0..]);

    try testing.expectEqual(v.has("issuer"), true);
    try testing.expectEqual(v.has("issuer2"), false);

    try v.set("issuer2", "issuer_val2");

    try testing.expectEqual(v.has("issuer2"), true);

    _ = v.del("issuer2");

    try testing.expectEqual(v.has("issuer2"), false);

    // =======================

    const url_str2 = try encodeQuery(v);
    defer alloc.free(url_str2);
    const check2 = "issuer=issuer_val&secret=secret_val%20data";

    try testing.expectEqualSlices(u8, url_str2[0..], check2[0..]);

    // =======================

    var uu = try parseQuery(alloc, check);
    defer uu.deinit();

    try testing.expectEqual(uu.has("secret"), true);
    try testing.expectEqual(uu.has("issuer"), true);
    try testing.expectEqual(uu.has("issuer2"), false);

    const got_secret = uu.get("secret").?;
    const check_secret = "secret_val+data";

    try testing.expectEqualSlices(u8, got_secret[0..], check_secret[0..]);

    const old_secret2 = "secret_val+data";
    const check_secret2 = "secret_val data";
    const got_secret2 = try unescapeQuery(testing.allocator, old_secret2);
    defer alloc.free(got_secret2);

    try testing.expectEqualSlices(u8, got_secret2[0..], check_secret2[0..]);

    const got_issuer = uu.get("issuer").?;
    const check_issuer = "issuer_val";

    try testing.expectEqualSlices(u8, got_issuer[0..], check_issuer[0..]);

    const got_issuer2 = uu.get("issuer2");

    try testing.expect(got_issuer2 == null);

    // =====================

    var v2 = Values.init(alloc);
    defer v2.deinit();

    try v2.add("secret", "secret_val data");
    try v2.add("issuer", "issuer_val2");

    const url_str22 = try v2.encode();
    defer alloc.free(url_str22);
    const check22 = "issuer=issuer_val2&secret=secret_val+data";

    try testing.expectEqualSlices(u8, url_str22[0..], check22[0..]);
}

test "test parseQuery" {
    const alloc = testing.allocator;

    const check = "issuer=issuer_val&secret=secret_val";

    var uu = try parseQuery(alloc, check);
    defer uu.deinit();

    try testing.expectEqual(uu.has("secret"), true);
    try testing.expectEqual(uu.has("issuer"), true);
    try testing.expectEqual(uu.has("issuer2"), false);

    const got_secret = uu.get("secret").?;
    const check_secret = "secret_val";

    try testing.expectEqualSlices(u8, got_secret[0..], check_secret[0..]);

    const got_issuer = uu.get("issuer").?;
    const check_issuer = "issuer_val";

    try testing.expectEqualSlices(u8, got_issuer[0..], check_issuer[0..]);

    const got_issuer2 = uu.get("issuer2");

    try testing.expect(got_issuer2 == null);
}

test "URI RFC example 1" {
    const uri = "foo://example.com:8042/over/there?name=ferret#nose";
    try std.testing.expectEqual(Uri{
        .scheme = uri[0..3],
        .user = null,
        .password = null,
        .host = .{ .percent_encoded = uri[6..17] },
        .port = 8042,
        .path = .{ .percent_encoded = uri[22..33] },
        .query = .{ .percent_encoded = uri[34..45] },
        .fragment = .{ .percent_encoded = uri[46..50] },
    }, try Uri.parse(uri));
}

test "URI format" {
    const uri: Uri = .{
        .scheme = "file",
        .user = null,
        .password = null,
        .host = null,
        .port = null,
        .path = .{ .raw = "/foo/bar/baz" },
        .query = null,
        .fragment = null,
    };
    try std.testing.expectFmt("file:/foo/bar/baz", "{;/?#}", .{uri});
}

test "URI format 2" {
    const uri = "foo://example.com:8042/over/there?name=ferret#nose";

    const uri1: Uri = .{
        .scheme = uri[0..3],
        .user = null,
        .password = null,
        .host = .{ .percent_encoded = uri[6..17] },
        .port = 8042,
        .path = .{ .percent_encoded = uri[22..33] },
        .query = .{ .percent_encoded = uri[34..45] },
        .fragment = .{ .percent_encoded = uri[46..50] },
    };
    try std.testing.expectFmt(uri, "{;@+/?#}", .{uri1});
}

test "URI query encoding" {
    const address = "https://objects.githubusercontent.com/?response-content-type=application%2Foctet-stream";
    const parsed = try Uri.parse(address);

    // format the URI to percent encode it
    try std.testing.expectFmt("/?response-content-type=application%2Foctet-stream", "{/?}", .{parsed});
}
