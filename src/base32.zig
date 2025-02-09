const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const ALPHABET: *const [32:0]u8 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode(alloc: Allocator, input: []const u8, padding: bool) ![]u8 {
    var output = try std.ArrayList(u8).initCapacity(alloc, (input.len + 3) / 4 * 5);
    defer output.deinit();

    const chunks = try slice_chunks(u8, alloc, input, 5);
    defer alloc.free(chunks);

    for (chunks) |chunk| {
        var buf = [_]u8{0} ** 5;
        for (chunk, 0..) |b, i| buf[i] = b;

        try output.append(ALPHABET[(buf[0] & 0xF8) >> 3]);
        try output.append(ALPHABET[((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)]);
        try output.append(ALPHABET[(buf[1] & 0x3E) >> 1]);
        try output.append(ALPHABET[((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)]);
        try output.append(ALPHABET[(buf[2] & 0x0F) << 1 | (buf[3] >> 7)]);
        try output.append(ALPHABET[(buf[3] & 0x7C) >> 2]);
        try output.append(ALPHABET[((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)]);
        try output.append(ALPHABET[buf[4] & 0x1F]);
    }

    if (input.len % 5 != 0) {
        const len = output.items.len;
        const num_extra = 8 - (input.len % 5 * 8 + 4) / 5;
        if (padding) {
            for (1..num_extra + 1) |i| output.items[len - i] = '=';
        } else {
            try output.resize(len - num_extra);
        }
    }

    return output.toOwnedSlice();
}

pub fn decode(alloc: Allocator, input: []const u8) ![]u8 {
    var unpad = input.len;
    for (1..@min(6, input.len) + 1) |i| {
        if (input[input.len - i] != '=') break;
        unpad -= 1;
    }

    const output_len = unpad * 5 / 8;

    var output = try std.ArrayList(u8).initCapacity(alloc, (output_len + 4) / 5 * 5);
    defer output.deinit();

    const chunks = try slice_chunks(u8, alloc, input, 8);
    defer alloc.free(chunks);

    for (chunks) |chunk| {
        var buf = [_]u8{0} ** 8;
        for (chunk, 0..) |b, ci| {
            if (std.mem.indexOf(u8, ALPHABET, &[1]u8{b})) |v| {
                buf[ci] = @intCast(v);
            }
        }

        try output.append((buf[0] << 3) | (buf[1] >> 2));
        try output.append((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4));
        try output.append((buf[3] << 4) | (buf[4] >> 1));
        try output.append((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3));
        try output.append((buf[6] << 5) | (buf[7]));
    }
    
    try output.resize(output_len);
    return output.toOwnedSlice();
}

test "base32 encode test" {
    const alloc = std.heap.page_allocator;

    const output = try encode(alloc, "Hello world", true);
    defer alloc.free(output);

    try testing.expectEqualSlices(u8, "JBSWY3DPEB3W64TMMQ======", output);
}

test "base32 decode test" {
    const alloc = std.heap.page_allocator;

    const output = try decode(alloc, "JBSWY3DPEB3W64TMMQ======");
    defer alloc.free(output);

    try testing.expectEqualSlices(u8, "Hello world", output);
}

fn slice_chunks(comptime T: type, alloc: Allocator, input: []const T, size: usize) ![][]const T {
    const input_len = input.len;
    const chunk_count = (input_len + size - 1) / size;

    var chunk_list = try std.ArrayList([]const T).initCapacity(alloc, chunk_count);
    defer chunk_list.deinit();

    for (0..chunk_count) |i| {
        const start = i * size;
        const end = start + size;
        if (start > input_len) break;
        try chunk_list.append(if (end < input_len) input[start..end] else input[start..]);
    }
    return chunk_list.toOwnedSlice();
}

test "slice_chunks test" {
    const alloc = std.heap.page_allocator;

    const output = try slice_chunks(u8, alloc, "Hello", 3);
    defer alloc.free(output);

    try testing.expectEqualSlices(u8, "Hel", output[0]);
    try testing.expectEqualSlices(u8, "lo", output[1]);
}
