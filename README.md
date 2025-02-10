## Zig-totp 

A totp and hotp library for zig.


### Env

 - Zig >= 0.14


### Adding zig-totp as a dependency

Add the dependency to your project:

```sh
zig fetch --save=zig-totp git+https://github.com/deatil/zig-totp#main
```

And the following to your `build.zig` file:

```zig
    const zig_totp = b.dependency("zig-totp", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("zig-totp", zig_totp.module("zig-totp"));
    exe.linkLibrary(zig_totp.artifact("zig-totp"));
```

The `zig-totp` structure can be imported in your application with:

```zig
const zig_totp = @import("zig-totp");
```


### Get Starting

~~~zig
const std = @import("std");
const totp = @import("zig-totp");

pub fn main() !void {
    const alloc = std.heap.page_allocator;

    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const n = totp.time.now().utc();
    const passcode = try totp.generateCode(alloc, secret, n);
    
    // output: 
    // generateCode: 906939
    std.debug.print("generateCode: {s} \n", .{passcode});

    const valid = totp.validate(alloc, passcode, secret);
    
    // output: 
    // validate: true
    std.debug.print("validate: {} \n", .{valid});
}
~~~


### Generate keyurl

~~~zig
const std = @import("std");
const totp = @import("zig-totp");

pub fn main() !void {
    const alloc = std.heap.page_allocator;

    const secret = "test-data";

    var key = try totp.generate(alloc, .{
        .issuer = "Example",
        .accountName = "accountName",
        .period = 30,
        .secretSize = 0,
        .secret = secret,
        .digits = otps.Digits.Six,
        .algorithm = otps.Algorithm.sha1,
    });

    const keyurl = key.urlString();
    
    // output: 
    // keyurl: otpauth://totp/Example:accountName?issuer=Example&period=30&digits=6&secret=ORSXG5BNMRQXIYI&algorithm=SHA1
    std.debug.print("keyurl: {} \n", .{keyurl});
}
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
