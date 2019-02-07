---
layout: post
title: Taint with Frida
categories: projects
tags: tools binary
comments: true
description: A taint analysis experiment with Frida
---

> Frida is slow, you can't do taint analysis
> 
> cit. chqmatteo

I never used [Frida](https://www.frida.re/) before, so I decided some days ago to start learning it.

But how to start?
Obviously testing the real capabilities of the tool writing a taint analysis module.

[https://github.com/andreafioraldi/taint-with-frida](https://github.com/andreafioraldi/taint-with-frida)

In the following example each buffer readed using the `read` syscall is tainted.

```javascript
var taint = require("./taint");

taint.syscallPreHook = function(ctx) {
    var sn = ctx.rax.toInt32();
    taint.log("foo", "syscall index = " + sn);
    if(sn == 0) { //read
        taint.memory.taint(ctx.rsi, ctx.rdx);
        taint.report();
    }
    else if(sn == 60 || sn == 231) { //exit || exit_group
        taint.log("foo", "exiting");
        taint.stopTracing();
        taint.report();
    }
}

taint.syscallPostHook = function(ctx) {
    taint.log("foo", "syscall ret = " + ctx.rax);
}

Interceptor.attach(ptr("0x400643"), //main
    function() {
        taint.log("foo", "enter main()");
        taint.startTracing(true); //true -> hook syscalls
    }
);
```


