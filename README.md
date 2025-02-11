## Zig-totp 

A totp library for zig.


### Env

 - Zig >= 0.14.0-dev.2851+b074fb7dd


### Adding zig-totp as a dependency

Add the dependency to your project:

```sh
zig fetch --save=zig-totp git+https://github.com/deatil/zig-totp#main
```

or use local path to add dependency at `build.zig.zon` file

```zig
.{
    .dependencies = .{
        .@"zig-totp" = .{
            .path = "./lib/zig-totp",
        },
        ...
    }
}
```

And the following to your `build.zig` file:

```zig
    const zig_totp_dep = b.dependency("zig-totp", .{});
    exe.root_module.addImport("zig-totp", zig_totp_dep.module("zig-totp"));
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
        .digits = .Six,
        .algorithm = .sha1,
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
