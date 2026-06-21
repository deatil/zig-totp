const std = @import("std");
const mem = std.mem;
const testing = std.testing;

pub fn eq(rest: []const u8, needle: []const u8) bool {
    return mem.eql(u8, rest, needle);
}

pub fn contains(data: []const u8, sep: []const u8) bool {
    const i = mem.indexOf(u8, data, sep);
    if (i != null) {
        return true;
    }

    return false;
}

pub fn index(data: []const u8, sep: []const u8) ?usize {
    return mem.indexOf(u8, data, sep);
}

pub fn trimLeft(data: []const u8, sep: []const u8) []const u8 {
    return mem.trimStart(u8, data, sep);
}

pub fn trimRight(data: []const u8, sep: []const u8) []const u8 {
    return mem.trimEnd(u8, data, sep);
}

pub fn hasPrefix(rest: []const u8, needle: []const u8) bool {
    return rest.len > needle.len and mem.eql(u8, rest[0..needle.len], needle);
}

pub fn hasSuffix(rest: []const u8, needle: []const u8) bool {
    return rest.len > needle.len and mem.eql(u8, rest[rest.len - needle.len ..], needle);
}

pub const CutData = struct {
    before: []const u8,
    after: []const u8,
    found: bool,
};

pub fn cut(s: []const u8, sep: []const u8) CutData {
    const i = mem.indexOf(u8, s, sep);
    if (i != null) {
        const j: usize = mem.indexOf(u8, s, sep).?;
        return .{
            .before = s[0..j],
            .after = s[j + sep.len ..],
            .found = true,
        };
    }

    return .{
        .before = s,
        .after = "",
        .found = false,
    };
}

test "bytes all" {
    try testing.expectEqual(true, contains("123erttt", "er"));
    try testing.expectEqual(false, contains("123erttt", "er2"));

    try testing.expectEqual(3, index("123erttt", "er"));

    try testing.expectFmt("rttt", "{s}", .{trimLeft("yerttt", "ye")});
    try testing.expectFmt("123erty", "{s}", .{trimRight("123ertytt", "tt")});

    try testing.expectEqual(true, hasPrefix("123erttt", "123"));
    try testing.expectEqual(true, hasSuffix("123erttt", "tt"));

    try testing.expectEqual(true, eq("123erttt", "123erttt"));
    try testing.expectEqual(false, eq("123erttt", "tt"));
}

test "cut" {
    const buf = "abcdft)098k";

    const res = cut(buf, ")");
    try testing.expectFmt("abcdft", "{s}", .{res.before});
    try testing.expectFmt("098k", "{s}", .{res.after});
    try testing.expectEqual(true, res.found);

    const res2 = cut(buf, "+");
    try testing.expectFmt("abcdft)098k", "{s}", .{res2.before});
    try testing.expectFmt("", "{s}", .{res2.after});
    try testing.expectEqual(false, res2.found);
}
