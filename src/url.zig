const std = @import("std");
const Buffer = std.Buffer;
const warn = std.debug.warn;
const assert = std.debug.assert;
const mem = std.mem;
const sort = std.sort;
const StringHashMap = std.hash_map.StringHashMap;
const Allocator = mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const bytes = @import("./bytes.zig");

const encoding = enum {
    path,
    pathSegment,
    host,
    zone,
    userPassword,
    queryComponent,
    fragment,
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
    if (mode == encoding.host or mode == encoding.zone) {
        switch (c) {
            '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '[', ']', '<', '>', '"' => return false,
            else => {},
        }
    }
    switch (c) {
        '-', '_', '.', '~' => return false,
        '$', '&', '+', ',', '/', ':', ';', '=', '?', '@' => {
            switch (mode) {
                encoding.path => return c == '?',
                encoding.pathSegment => return c == '/' or c == ';' or c == ',' or c == '?',
                encoding.userPassword => return c == '@' or c == '/' or c == '?' or c == ':',
                encoding.queryComponent => return true,
                encoding.fragment => return false,
                else => {},
            }
        },
        else => {},
    }
    if (mode == encoding.fragment) {
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
                    if (mode == encoding.queryComponent) {
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
        mem.copy(u8, t, s);
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
                if (mode == encoding.host and unhex(s[i + 1]) < 9 and !is25(s[i .. i + 3])) {
                    return Error.EscapeError;
                }
                if (mode == encoding.zone) {
                    const v = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    if (!is25(s[i .. i + 3]) and v != ' ' and shouldEscape(v, encoding.host)) {
                        return Error.EscapeError;
                    }
                }
                i = i + 3;
            },
            '+' => {
                has_plus = mode == encoding.queryComponent;
                i = i + 1;
            },
            else => {
                if ((mode == encoding.host or mode == encoding.zone) and s[i] < 0x80 and shouldEscape(s[i], mode)) {
                    return Error.InvalidHostError;
                }
                i = i + 1;
            },
        }
    }
    return UnescapeContext{
        .buffer_size = s.len - 2 * n,
        .has_plus = has_plus,
        .length = s.len,
    };
}

pub fn queryEscape(a: *std.Buffer, s: []const u8) !void {
    const ctx = countEscape(s, encoding.queryComponent);
    try a.resize(ctx.len());
    return escape(a.toSlice(), ctx, s, encoding.queryComponent);
}

pub fn queryUnescape(a: *std.Buffer, s: []const u8) !void {
    const ctx = try countUneEscape(s, encoding.queryComponent);
    try a.resize(ctx.buffer_size);
    unescape(a.toSlice(), ctx, s, encoding.queryComponent);
}

pub fn pathEscape(a: *std.Buffer, s: []const u8) !void {
    const ctx = countEscape(s, encoding.pathSegment);
    try a.resize(ctx.len());
    escape(a.toSlice(), ctx, s, encoding.pathSegment);
}

pub fn pathUnescape(a: *std.Buffer, s: []const u8) !void {
    const ctx = try countUneEscape(s, encoding.pathSegment);
    try a.resize(ctx.buffer_size);
    unescape(a.toSlice(), ctx, s, encoding.pathSegment);
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
                if (c == ' ' and mode == encoding.queryComponent) {
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
        mem.copy(u8, t, s);
    }
}

fn shouldEscapeString(s: []const u8) bool {
    return countEscape(s).canEscape();
}

fn shouldUnEscapeString(s: []const u8) !bool {
    const ctx = try countUneEscape(s);
    return ctx.canUnEscape();
}

fn countEscape(s: []const u8, mode: encoding) EscapeContext {
    var spaceCount: usize = 0;
    var hexCount: usize = 0;
    for (s) |c| {
        if (shouldEscape(c, mode)) {
            if (c == ' ' and mode == encoding.queryComponent) {
                spaceCount = spaceCount + 1;
            } else {
                hexCount = hexCount + 1;
            }
        }
    }
    return EscapeContext{
        .space_count = spaceCount,
        .hex_count = hexCount,
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

// Values maps a string key to a list of values.
// It is typically used for query parameters and form values.
// Unlike in the http.Header map, the keys in a Values map
// are case-sensitive.
pub const Values = struct {
    data: StringHashMap([][]const u8),
    allocator: Allocator,

    // init
    pub fn init(allocator: Allocator) Values {
        var data = StringHashMap([][]const u8).init(allocator);

        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    // deinit
    pub fn deinit(self: *Values) void {
        self.data.deinit();
    }

    // Get gets the first value associated with the given key.
    // If there are no values associated with the key, Get returns
    // the empty string. To access multiple values, use the map
    // directly.
    pub fn get(self: *Values, key: []const u8) []const u8 {
        const vs = self.data.get(key).?;
        if (vs.len > 0) {
            return vs[0];
        }

        return "";
    }

    // Set sets the key to value. It replaces any existing
    // values.
    pub fn set(self: *Values, key: []const u8, val: []const u8) !void {
        _ = try self.data.getOrPut(key);

        try self.add(key, val);
    }

    // Add adds the value to key. It appends to any existing
    // values associated with key.
    pub fn add(self: *Values, key: []const u8, val: []const u8) !void {
        const vs = self.data.get(key).?;
        vs[vs.len + 1] = val;

        try self.data.put(key, vs);
    }

    pub fn del(self: *Values, key: []const u8) bool {
        return self.data.remove(key);
    }

    pub fn has(self: *Values, key: []const u8) bool {
        if (self.data.get(key) != null) {
            return true;
        }

        return false;
    }

    /// Encode encodes the values into �URL encoded� form
    /// ("bar=baz&foo=quux") sorted by key.
    pub fn encode(self: *Values) ![:0]u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();

        var alloc = std.heap.ArenaAllocator.init(self.allocator);
        defer alloc.deinit();

        var keys = try alloc.allocator().alloc([]const u8, self.data.count());
        var key_i: usize = 0;

        var data = (try self.data.clone()).iterator();
        while (data.next()) |kv| {
            keys[key_i] = kv.key_ptr.*;
            key_i += 1;
        }

        sort.block([]const u8, keys, {}, stringSort([]const u8));

        var buffer = try std.Buffer.init(self.allocator, "");
        var bufEscape = &buffer;
        defer bufEscape.deinit();

        for (keys) |k| {
            const vs = self.data.get(k).?;

            try pathEscape(bufEscape, k);
            const keyEscaped = bufEscape.toSlice();
            try bufEscape.resize(0);

            for (vs) |vv| {
                if (buf.len > 0) {
                    try buf.appendSlice("&");
                }

                try pathEscape(bufEscape, vv);
                const vvEscaped = bufEscape.toSlice();
                try bufEscape.resize(0);

                try buf.appendSlice(keyEscaped);
                try buf.appendSlice("=");
                try buf.appendSlice(vvEscaped);
            }
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
    var m = Values.init(allocator);

    try parseQuerys(m, query);

    return m;
}

fn parseQuerys(m: Values, query: []const u8) !void {
    while (query.len > 0) {
        const cut_data = bytes.cut(query, "&");

        query = cut_data.after;

        if (bytes.Contains(cut_data.before, ";")) {
            continue;
        }

        if (cut_data.before.len == 0) {
            continue;
        }

        const cut_data2 = bytes.cut(cut_data.before, "=");

        const key = queryUnescape(cut_data2.before) catch {
            continue;
        };
        const value = queryUnescape(cut_data2.after) catch {
            continue;
        };

        try m.add(key, value);
    }
}

// A URL represents a parsed URL (technically, a URI reference).
//
// The general form represented is:
//
//[scheme:][//[userinfo@]host][/]path[?query][#fragment]
//
// URLs that do not start with a slash after the scheme are interpreted as:
//
//scheme:opaque[?query][#fragment]
//
// Note that the Path field is stored in decoded form: /%47%6f%2f becomes /Go/.
// A consequence is that it is impossible to tell which slashes in the Path were
// slashes in the raw URL and which were %2f. This distinction is rarely important,
// but when it is, code must not use Path directly.
// The Parse function sets both Path and RawPath in the URL it returns,
// and URL's String method uses RawPath if it is a valid encoding of Path,
// by calling the EscapedPath method.
pub const URL = struct {
    scheme: ?[]const u8 = null,
    opaques: ?[]const u8 = null,
    user: ?UserInfo = null,
    host: ?[]const u8 = null,
    path: ?[]const u8 = null,
    raw_path: ?[]const u8 = null,
    force_query: bool = false,
    raw_query: ?[]const u8 = null,
    fragment: ?[]const u8 = null,

    const Scheme = struct {
        scheme: ?[]const u8,
        path: []const u8,
    };

    pub fn getScheme(raw: []const u8) !Scheme {
        var i: usize = 0;
        var u: Scheme = undefined;
        while (i < raw.len) {
            const c = raw[i];
            if ('a' <= c and c <= 'z' or 'A' <= c and c <= 'Z') {
                // do nothing
            } else if ('0' <= c and c <= '9' and c == '+' and c == '-' and c == '.') {
                if (i == 0) {
                    u.path = raw;
                    return u;
                }
            } else if (c == ':') {
                if (i == 0) {
                    return error.MissingProtocolScheme;
                }
                u.scheme = raw[0..i];
                u.path = raw[i + 1 ..];
                return u;
            } else {
                //  we have encountered an invalid character,
                //  so there is no valid scheme
                u.path = raw;
                return u;
            }
            i = i + 1;
        }
        u.path = raw;
        return u;
    }

    const SplitResult = struct {
        x: []const u8,
        y: ?[]const u8,
    };

    fn split(s: []const u8, c: []const u8, cutc: bool) SplitResult {
        if (mem.indexOf(u8, s, c)) |i| {
            if (cutc) {
                return SplitResult{
                    .x = s[0..i],
                    .y = s[i + c.len ..],
                };
            }
            return SplitResult{
                .x = s[0..i],
                .y = s[i..],
            };
        }
        return SplitResult{ .x = s, .y = null };
    }

    pub fn parse(uri: *URL, a: *Allocator, raw_url: []const u8) !void {
        const frag = split(raw_url, "#", true);
        try parseInternal(uri, a, frag.x, false);
        if (frag.y == null) {
            return;
        }
        const ctx = try countUneEscape(frag.y.?, encoding.path);
        var f = try a.alloc(u8, ctx.buffer_size);
        unescape(f, ctx, frag.y.?, encoding.path);
        uri.fragment = f;
    }

    pub fn encode(u: *URL, buf: *Buffer) !void {
        try buf.resize(0);
        if (u.scheme) |scheme| {
            try buf.append(scheme);
            try buf.appendByte(':');
        }
        if (u.opaques) |opaques| {
            try buf.append(opaques);
        } else {
            if (u.scheme != null or u.host != null or u.user != null) {
                if (u.host != null or u.path != null or u.user != null) {
                    try buf.append("//");
                }
                if (u.user != null) {
                    try u.user.?.encode(buf);
                    try buf.appendByte('@');
                }
                if (u.host) |h| {
                    const x = buf.len();
                    const ctx = countEscape(h, encoding.host);
                    try buf.resize(x + ctx.len());
                    escape(buf.toSlice()[x..], ctx, h, encoding.host);
                }
            }
            var pathBuf = &try Buffer.init(buf.list.allocator, "");
            defer pathBuf.deinit();
            try escapedPath(u, pathBuf);
            const p = pathBuf.toSlice();
            if (p.len > 0 and p[0] != '/' and u.host != null) {
                try buf.appendByte('/');
            }
            if (buf.len() == 0) {
                // RFC 3986 §4.2
                // A path segment that contains a colon character (e.g., "this:that")
                // cannot be used as the first segment of a relative-path reference, as
                // it would be mistaken for a scheme name. Such a segment must be
                // preceded by a dot-segment (e.g., "./this:that") to make a relative-
                // path reference.
                if (mem.indexOfScalar(u8, p, ':')) |idx| {
                    const nx = mem.indexOfScalar(u8, p[0..idx], '/');
                    if (nx == null) {
                        try buf.append("./");
                    }
                }
            }
            if (p.len > 0) {
                try buf.append(p);
            }
        }
        if (u.force_query or u.raw_query != null) {
            try buf.appendByte('?');
            if (u.raw_query) |rq| {
                try buf.append(rq);
            }
        }
        if (u.fragment) |f| {
            try buf.appendByte('#');
            const ctx = countEscape(f, encoding.fragment);
            const current = buf.len();
            try buf.resize(current + ctx.len());
            escape(buf.toSlice()[current..], ctx, f, encoding.fragment);
        }
    }

    // Query parses RawQuery and returns the corresponding values.
    // It silently discards malformed value pairs.
    // To check errors use parseQuery.
    pub fn query(uri: *URL, a: Allocator) !Values {
        var v = try parseQuery(a, uri.raw_query);

        return v;
    }

    pub fn string(uri: *URL) ![]const u8 {
        const alloc = std.heap.page_allocator;

        var buf = &try Buffer.init(alloc, "");
        defer buf.deinit();

        try uri.encode(buf);

        return buf.toSlice();
    }

    fn parseInternal(u: *URL, a: *Allocator, raw_url: []const u8, via_request: bool) !void {
        if (raw_url.len == 0 and via_request) {
            return error.EmptyURL;
        }
        if (mem.eql(u8, raw_url, "*")) {
            u.path = "*";
            return;
        }
        const scheme = try getScheme(raw_url);
        var rest: []const u8 = undefined;
        if (scheme.scheme) |s| {
            // TODO: lowercase scheme
            // I'm afraid to pull unicode package dependency here for now, but
            // shcme must be lowercased.
            u.scheme = s;
        }
        rest = scheme.path;
        if (hasSuffix(rest, "?") and count(rest, "?") == 1) {
            u.force_query = true;
            rest = rest[0 .. rest.len - 1];
        } else {
            const s = split(rest, "?", true);
            rest = s.x;
            u.raw_query = s.y;
        }
        if (!hasPrefix(rest, "/")) {
            if (u.scheme != null) {
                u.opaques = rest;
                return;
            }
            if (via_request) {
                return error.InvalidURL;
            }
            // Avoid confusion with malformed schemes, like cache_object:foo/bar.
            // See golang.org/issue/16822.
            //
            // RFC 3986, §3.3:
            // In addition, a URI reference (Section 4.1) may be a relative-path reference,
            // in which case the first path segment cannot contain a colon (":") character.
            const colon = mem.indexOf(u8, rest, ":");
            const slash = mem.indexOf(u8, rest, "/");
            if (colon != null and colon.? >= 0 and (slash == null or colon.? < slash.?)) {
                return error.BadURL;
            }
        }
        if ((u.scheme != null or !via_request and !hasPrefix(rest, "///")) and hasPrefix(rest, "//")) {
            const x = split(rest[2..], "/", false);
            if (x.y) |y| {
                rest = y;
            } else {
                rest = "";
            }
            const au = try parseAuthority(a, x.x);
            u.user = au.user;
            u.host = au.host;
        }
        if (rest.len > 0) {
            try setPath(u, a, rest);
        }
        return;
    }

    const Authority = struct {
        user: ?UserInfo,
        host: []const u8,
    };

    const hostList = struct {
        host_1: []const u8,
        host_2: []const u8,
        host_3: []const u8,
    };

    fn parseAuthority(allocator: *Allocator, authority: []const u8) !Authority {
        const idx = lastIndex(authority, "@");
        var res: Authority = undefined;
        if (idx == null) {
            res.host = try parseHost(allocator, authority);
        } else {
            res.host = try parseHost(allocator, authority[idx.? + 1 ..]);
        }
        if (idx == null) {
            res.user = null;
            return res;
        }

        const user_info = authority[0..idx.?];
        if (!validUserinfo(user_info)) {
            return error.InvalidUserInfo;
        }
        const s = split(user_info, ":", true);
        var ctx = try countUneEscape(s.x, encoding.userPassword);
        var username = try allocator.alloc(u8, ctx.buffer_size);
        unescape(username, ctx, s.x, encoding.userPassword);
        if (s.y) |y| {
            ctx = try countUneEscape(y, encoding.userPassword);
            var password = try allocator.alloc(u8, ctx.buffer_size);
            unescape(password, ctx, y, encoding.userPassword);
            res.user = UserInfo.initWithPassword(username, password);
        } else {
            res.user = UserInfo.init(username);
        }
        return res;
    }

    fn parseHost(a: *Allocator, host: []const u8) ![]const u8 {
        if (hasPrefix(host, "[")) {
            // Parse an IP-Literal in RFC 3986 and RFC 6874.
            // E.g., "[fe80::1]", "[fe80::1%25en0]", "[fe80::1]:80".
            const idx = lastIndex(host, "]");
            if (idx == null) {
                // TODO: use result to improve error message
                return error.BadURL;
            }
            const i = idx.?;
            const colon_port = host[i + 1 ..];
            if (!validOptionalPort(colon_port)) {
                return error.BadURL;
            }
            // RFC 6874 defines that %25 (%-encoded percent) introduces
            // the zone identifier, and the zone identifier can use basically
            // any %-encoding it likes. That's different from the host, which
            // can only %-encode non-ASCII bytes.
            // We do impose some restrictions on the zone, to avoid stupidity
            // like newlines.
            if (index(host[0..i], "%25")) |zone| {
                const ctx_1 = try countUneEscape(host[0..zone], encoding.host);
                const ctx_2 = try countUneEscape(host[zone..i], encoding.zone);
                const ctx_3 = try countUneEscape(host[i..], encoding.host);
                const required = ctx_1.buffer_size + ctx_2.buffer_size + ctx_3.buffer_size;
                var out_buf = try a.alloc(u8, required);
                unescape(out_buf[0..ctx_1.buffer_size], ctx_1, host[0..zone], encoding.host);
                unescape(out_buf[ctx_1.buffer_size .. ctx_1.buffer_size + ctx_2.buffer_size], ctx_2, host[zone..i], encoding.zone);
                unescape(out_buf[ctx_1.buffer_size + ctx_2.buffer_size .. ctx_1.buffer_size + ctx_2.buffer_size + ctx_3.buffer_size], ctx_3, host[i..], encoding.host);
                return out_buf;
            }
        }
        const ctx = try countUneEscape(host, encoding.host);
        var out = try a.alloc(u8, ctx.buffer_size);
        unescape(out, ctx, host, encoding.host);
        return out;
    }

    fn validOptionalPort(port: []const u8) bool {
        if (port.len == 0) {
            return true;
        }
        if (port[0] != ':') {
            return false;
        }
        for (port[1..]) |value| {
            if (value < '0' or value > '9') {
                return false;
            }
        }
        return true;
    }

    // validUserinfo reports whether s is a valid userinfo string per RFC 3986
    // Section 3.2.1:
    //     userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
    //     unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
    //     sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
    //                   / "*" / "+" / "," / ";" / "="
    //
    // It doesn't validate pct-encoded. The caller does that via func unescape.
    fn validUserinfo(s: []const u8) bool {
        for (s) |r| {
            if ('A' <= r and r <= 'Z') {
                continue;
            }
            if ('a' <= r and r <= 'z') {
                continue;
            }
            if ('0' <= r and r <= '9') {
                continue;
            }
            switch (r) {
                '-', '.', '_', ':', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '%', '@' => {},
                else => {
                    return false;
                },
            }
        }
        return true;
    }

    // escapedPath writes ton buf  the escaped form of u.Path.
    // In general there are multiple possible escaped forms of any path.
    // EscapedPath returns u.RawPath when it is a valid escaping of u.Path.
    // Otherwise EscapedPath ignores u.RawPath and computes an escaped
    // form on its own.
    // The String and RequestURI methods use EscapedPath to construct
    // their results.
    // In general, code should call EscapedPath instead of
    // reading u.RawPath directly.
    fn escapedPath(u: *URL, buf: *Buffer) !void {
        if (u.raw_path) |raw| {
            if (validEncodedPath(raw)) {
                if (countUneEscape(raw, encoding.path)) |ctx| {
                    try buf.resize(ctx.len());
                    unescape(buf.toSlice(), ctx, raw, encoding.path);
                    if (u.path) |p| {
                        if (buf.eql(p)) {
                            try buf.resize(0);
                            try buf.append(raw);
                            return;
                        }
                    }
                } else |_| {}
            }
        }

        if (u.path) |p| {
            if (mem.eql(u8, p, "*")) {
                return buf.append("*");
            }

            const ctx = countEscape(p, encoding.path);
            try buf.resize(ctx.len());
            escape(buf.toSlice(), ctx, p, encoding.path);
        }
    }

    // validEncodedPath reports whether s is a valid encoded path.
    // It must not contain any bytes that require escaping during path encoding.
    fn validEncodedPath(s: []const u8) bool {
        for (s) |c| {
            // RFC 3986, Appendix A.
            // pchar = unreserved / pct-encoded / sub-delims / ":" / "@".
            // shouldEscape is not quite compliant with the RFC,
            // so we check the sub-delims ourselves and let
            // shouldEscape handle the others.
            switch (c) {
                '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@' => {},
                '[', ']' => {
                    // ok - not specified in RFC 3986 but left alone by modern browsers
                },
                '%' => {
                    // ok - percent encoded, will decode
                },
                else => {
                    if (shouldEscape(c, encoding.path)) {
                        return false;
                    }
                },
            }
        }
        return true;
    }
};

fn setPath(u: *URL, a: *Allocator, path: []const u8) !void {
    const uctx = try countUneEscape(path, encoding.path);
    var raw_path = try a.alloc(u8, uctx.buffer_size);
    unescape(raw_path, uctx, path, encoding.path);
    u.path = raw_path;
    const ectx = countEscape(path, encoding.path);
    var escaped_path = try a.alloc(u8, ectx.len());
    escape(escaped_path, ectx, u.path.?, encoding.path);
    if (!mem.eql(u8, raw_path, escaped_path)) {
        var e = try a.alloc(u8, path.len);
        mem.copy(u8, e, path);
        u.raw_path = e;
    }
}

/// hasPrefix returns true if slice s begins with prefix.
pub fn hasPrefix(s: []const u8, prefix: []const u8) bool {
    return s.len >= prefix.len and
        mem.eql(u8, s[0..prefix.len], prefix);
}

pub fn hasSuffix(s: []const u8, suffix: []const u8) bool {
    return s.len >= suffix.len and
        mem.eql(u8, s[(s.len - suffix.len)..], suffix);
}

// naive count
pub fn count(s: []const u8, sub: []const u8) usize {
    var x: usize = 0;
    var idx: usize = 0;
    while (idx < s.len) {
        if (mem.indexOf(u8, s[idx..], sub)) |i| {
            x += 1;
            idx += i + sub.len;
        } else {
            return x;
        }
    }
    return x;
}

fn lastIndex(s: []const u8, sub: []const u8) ?usize {
    return mem.lastIndexOf(u8, s, sub);
}

fn index(s: []const u8, sub: []const u8) ?usize {
    return mem.indexOf(u8, s, sub);
}

pub const UserInfo = struct {
    username: ?[]const u8,
    password: ?[]const u8,

    pub fn init(name: []const u8) UserInfo {
        return UserInfo{
            .username = name,
            .password = null,
        };
    }

    pub fn initWithPassword(name: []const u8, password: []const u8) UserInfo {
        return UserInfo{
            .username = name,
            .password = password,
        };
    }

    pub fn encode(u: *UserInfo, buf: *std.Buffer) !void {
        if (u.username) |usr| {
            const ctx = countEscape(usr, encoding.userPassword);
            const x = buf.len();
            try buf.resize(x + ctx.len());
            escape(buf.toSlice()[x..], ctx, usr, encoding.userPassword);
        }
        if (u.password) |pass| {
            try buf.appendByte(':');
            const ctx = countEscape(pass, encoding.userPassword);
            const x = buf.len();
            try buf.resize(x + ctx.len());
            escape(buf.toSlice()[x..], ctx, pass, encoding.userPassword);
        }
    }
};

// result returns a wrapper struct that helps improve error handling. Panicking
// in production is bad, and adding more context to errors improves the
// experience especially with parsing.
fn result(comptime Value: type, ResultError: type) type {
    return struct {
        const Self = @This();
        value: Result,
        message: ?[]const u8,
        pub const Err = ResultError;

        pub fn withErr(e: Err, msg: ?[]const u8) Self {
            return Self{
                .value = Result{ .err = e },
                .message = msg,
            };
        }

        pub fn withValue(v: Value) Self {
            return Self{
                .value = Result{ .value = v },
                .message = null,
            };
        }

        pub const Result = union(enum) {
            err: Error,
            value: Value,
        };

        pub fn unwrap(self: Self) Error!Value {
            return switch (self.value) {
                Error => |err| err,
                Value => |v| v,
                else => unreachable,
            };
        }
    };
}

// U exposes api for parsing url. The current implementation for parsing
// involves memory allocation. This ensures that all memory allocated for url
// parsing is freed properly.
pub const U = struct {
    // The parsed url object. This will have all fields set to null by default
    // which will mean that we haven't parsed any url witht he current U
    // instance.
    url: URL,
    // we don't free memory while parsing, instead we free all of it at once
    // after we are done using the url object.
    arena: ArenaAllocator,

    fn init(a: *Allocator) U {
        return U{
            .url = URL{},
            .arena = ArenaAllocator.init(a),
        };
    }

    fn parse(self: *U, raw_url: []const u8) !void {
        var a = &self.arena.allocator;
        self.url = URL{};
        try self.url.parse(a, raw_url);
    }

    fn deinit(self: *U) void {
        self.arena.deinit();
    }
};

/// parse parses raw_url using rfc 3986 standard, returning U with the parsed url
/// object acceible in U.url.
///
/// Call u.deinit() when you no longer use the url to free memory.
pub fn parse(a: *Allocator, raw_url: []const u8) !U {
    var u = U.init(a);
    try u.parse(raw_url);
    return u;
}
