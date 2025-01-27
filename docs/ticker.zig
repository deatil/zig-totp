const std = @import("std");

pub const Ticker = struct {
    ticks: u32 = 0,

    const Self = @This();

    pub fn init() Self {
        return .{ .ticks = 0 };
    }

    pub fn inc(self: *Self) void {
        _ = @addWithOverflow(u32, self.ticks, 1, &self.ticks);
    }

    pub fn interval(self: *Self, delay: u32) TickerInterval {
        var tc = TickerInterval{
            .ticks = &self.ticks,
        };
        tc.set(self.ticks, delay);
        return tc;
    }
};

pub const TickerInterval = struct {
    ticks: *u32 = undefined,
    next: u32 = 0,
    overflow: bool = false,

    const Self = @This();

    pub fn ready(self: *Self, delay: u32) bool {
        var current = self.ticks.*;
        if (self.overflow and current > 0x7FFFFFFF) {
            return false;
        }
        if (current >= self.next) {
            self.set(current, delay);
            return true;
        }
        return false;
    }

    fn set(self: *Self, current: u32, delay: u32) void {
        self.overflow = @addWithOverflow(u32, current, delay, &self.next);
    }
};

test "ticker overflow" {
    var t = Ticker.init();
    t.ticks = 0xFFFFFFFF;
    t.inc();
    try std.testing.expectEqual(t.ticks, 0);
}

test "counter with overflow" {
    var t = Ticker.init();
    t.ticks = 0xFFFFFFFF;

    var counter = t.interval(2);
    try std.testing.expect(!counter.ready(2));
    t.inc();
    try std.testing.expect(!counter.ready(2));
    try std.testing.expectEqual(t.ticks, 0);
    try std.testing.expectEqual(counter.next, 1);
    try std.testing.expectEqual(counter.overflow, true);
    t.inc();
    try std.testing.expect(counter.ready(2));
    try std.testing.expectEqual(counter.next, 3);
    try std.testing.expectEqual(counter.overflow, false);
}
