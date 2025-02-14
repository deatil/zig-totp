## Zig-totp 

A totp and hotp library for zig.


### Why One Time Passwords?

One Time Passwords (OTPs) are an mechanism to  improve security over passwords alone. When a Time-based OTP (TOTP) is stored on a user's phone, and combined with something the user knows (Password), you have an easy on-ramp to [Multi-factor authentication](http://en.wikipedia.org/wiki/Multi-factor_authentication) without adding a dependency on a SMS provider.  This Password and TOTP combination is used by many popular websites including Google, GitHub, Facebook, Salesforce and many others.

The `otp` library enables you to easily add TOTPs to your own application, increasing your user's security against mass-password breaches and malware.

Because TOTP is standardized and widely deployed, there are many [mobile clients and software implementations](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm#Client_implementations).


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
        .account_name = "accountName",
        .period = 30,
        // .secret_size = 20,
        // use secret if secret not empty, or use secret_size to generate secret
        .secret = secret,
        .digits = .Six,
        .algorithm = .SHA1,
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
