const micro = @import("microzig");
const regs = micro.chip.eregs;

// Provide chip frequencies to customize init and checkConfig for that chip.
pub fn Chip(comptime chip_frequencies: type) type {
    return struct {
        pub const Config = struct {
            source: ClockSource,
            pll: Pll,
            latency: u3, // chapter 3.4
            prescaler: Prescaler,
            frequencies: Frequencies,
        };

        pub const ClockSource = enum {
            hsi, // High-speed internal (in chipn)
            hse, // High-speed external (on board)
        };

        pub const Pll = struct {
            m: u16,
            n: u16,
            p: u16,
            q: u16,
        };

        pub const Prescaler = struct { // chapter 6.3.3
            ahb: u16 = 1,
            apb1: u8 = 2,
            apb2: u8 = 1,
        };

        pub const Frequencies = struct {
            source: u32,
            cpu: u32,
            ahb: u32,
            apb1: u32,
            apb2: u32,
            usb: u32,
        };

        pub fn init(comptime cfg: Config) void {
            checkConfig(cfg);

            regs.rcc.apb1enr.modify(.{ .pwren = .enabled }); // enable power interface clock
            regs.pwr.cr.modify(.{ .vos = voltageScalingOutput(cfg.frequencies.cpu) }); // voltage scaling output

            if (cfg.source == .hsi) {
                regs.rcc.cr.modify(.{ .hsion = .on }); // Enable HSI
                while (regs.rcc.cr.read().hsirdy != .ready) {} // Wait for HSI ready
            } else {
                regs.rcc.cr.modify(.{ .hseon = .on }); // Enable external high-speed oscillator (HSE)
                while (regs.rcc.cr.read().hserdy != .ready) {} // Wait for HSE ready
            }

            initPLL(cfg);

            // Set flash latency wait states
            regs.flash.acr.modify(.{ .latency = enumField(regs.flash.Acr.Latency, "ws", cfg.latency) });

            regs.rcc.cfgr.modify(.{
                .sw = .pll, // clock source to pll
                // set prescalers
                // converting number values to the enum 2 => .div2
                .hpre = enumField(regs.rcc.Cfgr.Hpre, "div", cfg.prescaler.ahb), // ahb prescaler
                .ppre1 = enumField(regs.rcc.Cfgr.Ppre1, "div", cfg.prescaler.apb1), // apb low speed prescaler apb1
                .ppre2 = enumField(regs.rcc.Cfgr.Ppre1, "div", cfg.prescaler.apb2), // apb high-speed prescaler apb2
            });
            while (regs.rcc.cfgr.read().sws != .pll) {} // wait for pll ready
        }

        fn initPLL(comptime cfg: Config) void {
            const pll = cfg.pll;

            regs.rcc.cr.modify(.{ .pllon = .off }); // Disable PLL before changing its configuration

            regs.rcc.pllcfgr.modify(.{
                .pllsrc = @field(regs.rcc.Pllcfgr.Pllsrc, @tagName(cfg.source)),
                .pllm = pll.m,
                .plln = pll.n,
                .pllp = enumField(regs.rcc.Pllcfgr.Pllp, "div", pll.p),
                .pllq = pll.q,
            });

            regs.rcc.cr.modify(.{ .pllon = .on }); // Enable PLL
            while (regs.rcc.cr.read().pllrdy != .ready) {} // Wait for PLL ready
        }

        fn voltageScalingOutput(cpu_freq: u32) u2 {
            return switch (cpu_freq) {
                0...64 => 0b01, // 01: Scale 3 mode <= 64 MHz
                65...84 => 0b10, // 10: Scale 2 mode (reset value) <= 84 MHz
                else => 0b11, // 11: Scale 1 mode <= 100 MHz
            };
        }

        pub fn checkConfig(comptime cfg: Config) void {
            const pll = cfg.pll;

            // check ranges for pll parameters
            if (!((pll.m >= 2 and pll.m <= 63) and
                (pll.n >= 50 and pll.n <= 432) and
                (pll.p == 2 or pll.p == 4 or pll.p == 6 or pll.p == 8) and
                (pll.q >= 2 and pll.q <= 15)))
            {
                @compileError("wrong RCC PLL configuration values");
            }
            // check range for latency
            if (!(cfg.latency >= 0 and cfg.latency <= 6)) {
                @compileError("wrong latency value");
            }

            // check frequencies calculations and max values
            const fv = cfg.frequencies.source / pll.m * pll.n;
            const cpu = fv / pll.p;
            if (cfg.frequencies.cpu != cpu) {
                @compileError("wrong cpu frequency");
            }
            if (cpu > chip_frequencies.max_cpu) {
                @compileError("max cpu frequency exceeded");
            }

            if (cfg.frequencies.ahb != cpu / cfg.prescaler.ahb) {
                @compileError("wrong ahb frequency");
            }
            if (cfg.frequencies.apb1 != cpu / cfg.prescaler.apb1) {
                @compileError("wrong apb1 frequency");
            }
            if (cfg.frequencies.apb1 > chip_frequencies.max_apb1) {
                @compileError("max apb1 frequency exceeded");
            }
            if (cfg.frequencies.apb2 != cpu / cfg.prescaler.apb2) {
                @compileError("wrong apb2 frequency");
            }

            const usb = fv / pll.q;
            if (cfg.frequencies.usb != usb) {
                @compileError("wrong usb frequency");
            }

            // depends on clock and voltage range, chapter 3.4 page 45 in RM0383
            const min_latency = switch (cpu / 1_000_000) {
                0...30 => 0,
                31...64 => 1,
                65...90 => 2,
                else => 3,
            };
            if (cfg.latency < min_latency) {
                @compileError("flash memory min latency not satisfied");
            }
        }

        // init SysTick interrupt every ms milliseconds
        pub fn initSysTick(comptime ahb_freq: u32, comptime ms: u16) void {
            const reload: u24 = @as(u24, @intCast(ahb_freq / 8)) / 1000 * ms - 1;
            //const reload: u24 = @intCast(u24, ahb_freq / 1000) * ms - 1;  // for clocksource = 1
            regs.stk.load.modify(.{ .reload = reload }); // set counter
            regs.scb.shpr3.modify(.{ .pri_15 = 0xf0 }); // systick irq priority
            regs.stk.val.modify(.{ .current = 0 }); // start from 0
            regs.stk.ctrl.modify(.{
                .enable = 1,
                .clksource = 0, // 0: AHB/8, 1: AHB (processor clock)
                .tickint = 1, // 1: Counting down to zero to asserts the SysTick exception request
            });
        }
    };
}

fn enumField(comptime T: type, comptime prefix: []const u8, comptime value: anytype) T {
    return comptime @field(T, prefix ++ std.fmt.comptimePrint("{d}", .{value}));
}

const std = @import("std");

// use this terminal command to view possible pll config
// source env var is frequency of input oscilator
// usb frequency is required to be 48 MHz, but then is unable to reach max
//
// SOURCE=8 USB=48 zig test --test-filter pll clock.zig 2>&1 | grep "^fs" | sort -k12 -n | uniq -f 11
// SOURCE=8 USB=50 zig test --test-filter pll clock.zig 2>&1 | grep "^fs" | sort -k12 -n | uniq -f 11
// SOURCE=8 USB=48 MAX=184 zig test --test-filter pll clock.zig 2>&1 | grep "^fs" | sort -k12 -n | uniq -f 11
test "show available pll parameters" {
    var pa = [_]u64{ 2, 4, 6, 8 };

    const source_arg = std.os.getenv("SOURCE"); // no default must be provided
    const usb_arg = std.os.getenv("USB"); // 48MHz default
    const max_arg = std.os.getenv("MAX"); // 100MHz default

    if (source_arg == null) {
        return error.SkipZigTest;
    }
    const source = (try std.fmt.parseInt(u64, source_arg.?, 10)) * 1_000_000;
    const fs_max: u64 = if (max_arg != null) (try std.fmt.parseInt(u64, max_arg.?, 10)) * 1_000_000 else 100_000_000;
    const fusb: u64 = if (usb_arg != null) (try std.fmt.parseInt(u64, usb_arg.?, 10)) * 1_000_000 else 48_000_000;

    var m: u64 = 2;
    while (m <= 63) : (m += 1) {
        var n: u64 = 50;
        while (n <= 432) : (n += 1) {
            var q: u64 = 2;
            while (q <= 15) : (q += 1) {
                for (pa) |p| {
                    var fv = source * n / m;
                    var fs = fv / p;
                    var fu = fv / q;
                    if (fs <= fs_max and (fusb == 0 or fu == fusb)) {
                        std.debug.print("fs: {d:3} MHz", .{fs / 1_000_000});
                        std.debug.print(" m: {d:2}, n: {d:3}, p: {d:2}, q: {d:2}", .{ m, n, p, q });
                        std.debug.print("{d:10} Hz\r\n", .{fs});
                    }
                }
            }
        }
    }
}
