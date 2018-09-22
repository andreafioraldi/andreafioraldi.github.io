---
layout: post
title: Building an AngrDBG frontend for your debugger
categories: articles
tags: tools binary
comments: true
description: How to create a AngrDBG frontend
---

[AngrDBG](https://github.com/andreafioraldi/angrdbg) is the library that I developed to synchronize a concrete process state with an angr state.

The library is debugger agnostic. An frontend library that integrated AngrDBG with a specific debugger must implements a subclass of `angrdbg.Debugger` and register an istance of that class as source of data using `angrdbg.register_debugger`.

The methods that must be implemented are the following:

+ `before_stateshot(self)`

An event handler triggered before the synchronization setup in StateShot, just after the empty state creation
+ `after_stateshot(self, state)`

An event handler triggered before the StateShot return
+ `is_active(self)`

Return True if the debugger is running the target process
+ `input_file(self)`

Return a python file-like object of the target executable
+ `image_base(self)`

Return the process base address
+ `get_<byte|word|dword|qword>(self, addr)`

Read an `byte|word|dword|qword` from the memory as a python int (4 distinct methods)
+ `get_bytes(self, addr, size)`

Read a string from the memory
+ `put_<byte|word|dword|qword>(self, addr, value)`

Write a python in as a `byte|word|dword|qword` to the memory (4 distinct methods)
+ `put_bytes(self, addr, value)`

Write a string to the memory
+ `get_reg(self, name)`

Get a register value
+ `set_reg(self, name, value)`

Set a register value
+ `step_into(self)`

Call the debugger step into command
+ `run(self)`

Run the process inside the debugger
+ `wait_ready(self)`

Wait until the debugged process is ready to be inspected
+ `refresh_memory(self)`

Refresh the memory API of the debugger
+ `seg_by_name(self, name)`

Get a Segment object by the name
+ `seg_by_addr(self, name)`

Get a Segment object by the address
+ `get_got(self)`

Get a tuple (start address, end address) related to the GOT section
+ `get_plt(self)`

Get a tuple (start address, end address) related to the PLT section
+ `resolve_name(self, name)`

Resolve a symbol to its address using the name

You can find [here](https://github.com/andreafioraldi/angrgdb/blob/master/angrgdb/debugger.py) the GDBDebugger class used in the GDB frontend.


