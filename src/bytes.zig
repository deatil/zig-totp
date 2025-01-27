const std = @import("std");

const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

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
    return mem.trimLeft(u8, data, sep);
}

pub fn trimRight(data: []const u8, sep: []const u8) []const u8 {
    return mem.trimRight(u8, data, sep);
}

pub const getLineData = struct {
    line: []const u8,
    rest: []const u8,
};

pub fn getLine(data: []const u8) getLineData {
    var i = mem.indexOf(u8, data, "\n").?;
    var j: usize = 0;

    if (i < 0) {
        i = data.len;
        j = i;
    } else {
        j = i + 1;
        if (i > 0 and data[i - 1] == '\r') {
            i -= 1;
        }
    }

    return .{
        .line = mem.trimRight(u8, data[0..i], " \t"),
        .rest = data[j..],
    };
}

pub fn removeSpacesAndTabs(allocator: Allocator, data: []const u8) ![:0]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    var n: usize = 0;

    for (data) |b| {
        if (b == ' ' or b == '\t' or b == '\n') {
            continue;
        }

        try buf.append(b);
        n += 1;
    }

    return buf.toOwnedSliceSentinel(0);
}

pub fn hasPrefix(rest: []const u8, needle: []const u8) bool {
    return rest.len > needle.len and mem.eql(u8, rest[0..needle.len], needle);
}

pub fn hasSuffix(rest: []const u8, needle: []const u8) bool {
    return rest.len > needle.len and mem.eql(u8, rest[rest.len - needle.len ..], needle);
}

pub fn eq(rest: []const u8, needle: []const u8) bool {
    return mem.eql(u8, rest, needle);
}

pub const cutData = struct {
    before: []const u8,
    after: []const u8,
    found: bool,
};

pub fn cut(s: []const u8, sep: []const u8) cutData {
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

pub fn isSpace(r: u8) bool {
    return switch (r) {
        '\t', '\n', '\r', ' ', 0x85, 0xA0 => true,
        else => false,
    };
}

pub fn trimSpace(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len) : (start += 1) {
        if (!isSpace(s[start])) {
            break;
        }
    }

    var stop = s.len - 1;
    while (stop > start) : (stop -= 1) {
        if (!isSpace(s[stop])) {
            break;
        }
    }

    if (start == stop) {
        return "";
    }

    return s[start..(stop + 1)];
}

test "contains all" {
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
