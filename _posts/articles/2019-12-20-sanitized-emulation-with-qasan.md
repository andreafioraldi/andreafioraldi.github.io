---
layout: post
title: Sanitized Emulation with QASan
categories: articles
tags: tools fuzzing sanitization asan
comments: true
hidden: true
description: AddressSanitizer for binaries via DBT
---

Fuzzing techniques evolved and tools are nowadays able to reach a good coverage of target programs with techniques that allow fuzzers to bypass roadblocks [1] [2] [3] [4].

But without good bug detection capabilities, a fuzzer that reaches a high coverage is less effective.

Fuzzing with additional instrumentation for bug detection is one of the most important fields of research in this matter.

Source-level fuzzers such as AFL [5], AFLplusplus [6], libFuzzer [7] and honggfuzz [8] can make use of sanitization frameworks provided by compilers (GCC and LLVM) such as ASAN, MSAN, UBSAN [9] to detect bugs that don't necessary crash the programs such as uninitialized reads, heap negative OOBs, and many others.

Binary-level fuzzers can make use of special hardened allocators such as AFL's libdislocator to detect common misuse of the heap. However, these tools are far from complete (e.g. libdislocator's memalign is not guaranteed to be at the end of a page and so OOBs are not always detected) and don't scale with programs that frequently allocate small chunks.

Static rewriting of binaries is a possible way to address this problem [10] but at the moment only x86_64 PIC ELFs binaries can be rewritten with ASAN support.

As always, there is a gap between source-level and binary-level fuzzing. And, as always, I'll try to share knowledge to fill a bit this gap using the binary instrumentation tool that I love: QEMU.

I created QASan (QEMU-AddressSanitizer), a fork of user-mode QEMU that introduce AddressSanitizer for heap objects into QEMU.

QASan not only enables AddressSanitizer on COTS x86/x86_64/ARM/ARM64 binaries on Linux/*BSD but allows also the instrumentation of code generated at runtime (e.g. JIT) that is, of course, not supported by source-level ASAN. Note also that at the time of writing AddressSanitizer doesn't support ARM/ARM64 on Linux and QASan enables that for this class of binaries.

It is OSS and available on [GitHub](https://github.com/andreafioraldi/qasan).

## AddressSanitizer

AddressSanitizer [11] is one of the most popular memory error detectors nowadays, mainly for its ease of use and speed (~2x slowdown respect to native) that makes it well suited for fuzzing.

It can catch different classes of bugs [12] and in a sound way thanks to the information provided by source-code analysis before instrumentation that enables the detection of bugs like OOB access of stack objects.

ASan uses a shadow memory to keep track of invalid areas of memory. Every memory access (or almost, some may be optimized out if proven to be safe) is instrumented in this way:

```c
ShadowAddr = (Addr >> 3) + Offset;
if (ShadowIsPoisoned(ShadowAddr))
  ReportAndCrash(Addr);
ActualMemoryAccess(Addr);
```

Offset is architecture and OS-dependent, in general, it is an uncommon not used address in the program address space in a way that every 8 bytes of regular memory can be hashed to a single byte of shadow memory and each byte of the shadow memory hashed to unmapped memory (so that the program crashes if trying to do `MemoryAccess(ShadowAddr)`).

<img src="/assets/qasan_img1.png" alt="BBs" style="max-width: 100%; height: auto;">

(picture from [11])

To do this shadow memory mapping, ASan maps a lot of virtual memory that remains unused and so not associated with physical frames by the kernel.

ASan hooks the allocator's routines like malloc, free, memalign & al. with a custom allocator that poisons the memory around chunks (redzones) to detect OOB, invalidates freed memory and keeps track of it in a quarantine queue.

To avoid the need to have an instrumented libc, the ASan runtime provides hooks for common libc routines that involve memory access like memcpy, strcpy and many others.

ASan, as well, adds redzones also around global and stack objects and has also the possibility to add allocated stack frames to detect Use-After-Return, refer to the documentation for more information.

## QEMUing AddressSanitizer

It is known that QEMU user does not like programs compiled with ASan and hangs with these programs.

QEMU user has to know every mapped page of the target program and, I guess, here come the dragons with the ASan shadow memory.

So, if we cannot even run a compiled program with ASan in QEMU, how we can instrument binaries with ASan with it?

The solution is a simple, weird, and effective hack: break the boundary between QEMU and the target and expose ASan as an operating system feature exposed by QEMU.

So now, Linus Torvalds may feel a bit disappointed with this solution and may want to punch me.

In Linux, the kernel should NEVER allocate memory for userspace (except for the early loading stage of a process).

In QEMU user-mode, the syscalls instructions are recompiled into calls to the `do_syscall` QEMU routine that is a syscall dispatcher in userspace that forwards many syscalls to the kernel and handle many others (like brk) in userspace.

We can easily add a syscall in QEMU that is handled in QEMU itself.

So, the workflow is the following:

+ Expose a new syscall that is a dispatcher of routines like malloc/free/memcpy and other routines that ASan hooks.
+ Instrument memory accesses in TCG [13] (the IR).
+ Link QEMU with ASan.

In particular, when allocating memory from this new syscall for malloc/calloc/realloc/valloc/..., we have also to make it reachable from the guest marking its pages as readable and writeable in the target context.

Looking at the code, the QASan fake syscall dispatcher is similar to the following snippet:

```c
static abi_long qasan_fake_syscall(abi_long action, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7) {

    switch(action) {

      ...

      case QASAN_ACTION_MALLOC: {
          abi_long r = h2g(__interceptor_malloc(arg1));
          if (r) page_set_flags(r, r + arg1, PROT_READ | PROT_WRITE | PAGE_VALID);
          return r;
      }

      ...

    }
    
    return 0;

}
```

The memory accesses in TCG are hooked using TCG helpers [13]. For example, qasan_gen_load4 is called before the code that emits the TCG operations associated with a 32-bit memory load and it emits a call to a helper (qasan_load4) that checks the validity of the address using __asan_load4.

```c
static inline void tcg_gen_ld_i32(TCGv_i32 ret, TCGv_ptr arg2,
                                  tcg_target_long offset)
{

    qasan_gen_load4(arg2, offset);
    tcg_gen_ldst_op_i32(INDEX_op_ld_i32, ret, arg2, offset);
}
```

At the time of writing, all memory accesses are instrumented. This is not optmial and in the future I want to exclude memory operations know to not work on heap at translation time (e.g. push/pop).

To hook the functions that ASan needs to be hooked I created a small library, libqasan.so, that has to be loaded using LD_PRELOAD into the target.

A hooked action looks like the following:

```c
void * malloc(size_t size) {

  return (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MALLOC, size);

}
```

Of course, the library can be run only into the patched QEMU. This is not the only possible solution but I opted for this one based on LD_PRELOAD to simplify the things.

It won't work with static binaries, but patching the static routines in the binary with these syscall invocations it's easy and I'll release an automated script using lief [14] one day.

Regarding the error reports, they will not be so meaningful for debugging purposes. The ASan DSO, under the hood, collects stack traces from QEMU and not from the target and so an error report will be something similar to the following screenshot (an OOB negative read):

<img src="/assets/qasan_img2.png" alt="BBs" style="max-width: 100%; height: auto;"> 

I suggest using the `malloc_context_size=0` ASAN_OPTION to avoid to collect these useless stack traces and speedup a bit QASan.

This can be solved with a bit of patching of the ASan codebase but I choose to use the precompiled ASAN DSO for compatibility and to avoid to force the user to recompile a custom compiler-rt (I care about usability and simplicity). The build process will simply take an ASAN DSO and patch the ELF to avoid to hook routines in QEMU (we don't want to use the ASAn allocator in QEMU but only in the target to avoid an useless slowdown).

QASan seems pretty stable, it can run without problems binaries such as GCC, clang, vim, nodejs. To be fair, I have to say that it fails to execute python due to a detected UAF at startup (who knows, maybe python is really bugged).

Just for fun, I recompiled QASan using clang running under QASan. It worked.

There are also problems with some libc code (that is not instrumented by default) that I have to investigate in deep.

## Fuzzing with AFL++

QASan, alongside the patches for ASan, includes also all the patches of AFL++ QEMU, so also CompareCoverage and persistent mode.

Fuzzing the Ubuntu 18.04 objdump binary with QASan vs. plain QEMU mode I experienced a 2x slowdown respect unsanitized QEMU mode that is reasonable and coherent with the ASan slowdown respect to native executables.

The graph represents the exec/sec (Y-axis) over 10 minutes of fuzzing with QEMU and QASan.

<img src="/assets/qasan_img3.png" alt="BBs" style="max-width: 100%; height: auto;"> 

I triggered also a bug (a NULL ptr deref), probably a known bug because the objdump version is quite old (2.30).

```sh
andrea@malweisse:~/Desktop/QASAN$ ./qasan --verbose /usr/bin/objdump -g -x crash1
==20993== QEMU-AddressSanitizer (v0.1)
==20993== Copyright (C) 2019 Andrea Fioraldi <andreafioraldi@gmail.com>
==20993== 
==20993== 0x7f3452e67ece: memcpy(0x7f3453a94c10, 0, 4096)
==20993==          = 0x7f3453a94c10
==20993== 0x7f3452e67f03: strlen(0x7f3453a94c10)
==20993==          = 3596
...
...
...
OFFSET   TYPE              VALUE 
00000000 IGNORE            *ABS*
00000000 IGNORE            *ABS*
00000000 IGNORE            *ABS*
==20993== 
==20993== Caught SIGSEGV: pc=0x7ff1224a18c0 addr=0x7900000
==20993== 
```

Yeah, this crash would be detected also without QASAN, but I want to show you the output of verbose QASan.

More evaluation (and bugs hopefully) will come in the future.

## Conclusion

One step further to fill the gap between source and binary-only fuzzing is done.

QASan is not "definitive"(tm), a lot of work has to be done like MIPS support (x86 ASan addresses are incompatible with the MIPS address space) and contribution from the OSS community are welcome.

The current implementation of QASan cannot be used to fuzz system-wide but there are actions to check and poison memory that are exposed in the dispatcher.

Those actions can be used to build a KASAN implementation using hypercalls (e.g. a Windows kernel module that hooks the kernel allocator with a wrapper that inserts redzones and invalidates memory using hypercalls).

More work has to be done in this direction to enable the fuzzing of closed source kernels/firmwares with QASan and not only user-space applications.

## References

[1] "Circumventing Fuzzing Roadblocks with Compiler Transformations" https://lafintel.wordpress.com/2016/08/15/circumventing-fuzzing-roadblocks-with-compiler-transformations/

[2] C. Aschermann, S. Schumilo, T. Blazytko, R. Gawlik, and T. Holz, "REDQUEEN: fuzzing with input-to-state correspondence" https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/

[3] "Compare coverage for AFL++ QEMU", https://andreafioraldi.github.io/articles/2019/07/20/aflpp-qemu-compcov.html

[4] H. Peng, Y. Shoshitaishvili, M. Payer, "T-Fuzz: fuzzing by program transformation", https://nebelwelt.net/publications/files/18Oakland.pdf

[5] "American Fuzzy Lop", http://lcamtuf.coredump.cx/afl/

[6] "American Fuzzy Lop plus plus", https://github.com/vanhauser-thc/AFLplusplus

[7] "libFuzzer – a library for coverage-guided fuzz testing", https://llvm.org/docs/LibFuzzer.html

[8] "honggfuzz", https://github.com/google/honggfuzz

[9] "sanitizers", https://github.com/google/sanitizers

[10] S. Dinesh, N. Burow, D. Xu, M. Payer, "RetroWrite: Statically Instrumenting COTS Binaries for Fuzzing and Sanitization", https://hexhive.epfl.ch/publications/files/20Oakland.pdf

[11] K. Serebryany, D. Bruening, A. Potapenko, D. Vyukov, "AddressSanitizer: A Fast Address Sanity Checker", https://research.google/pubs/pub37752/

[12] "AddressSanitizer · google/sanitizers Wiki", https://github.com/google/sanitizers/wiki/AddressSanitizer

[13] "Tiny Code Generator - Fabrice Bellard.", https://git.qemu.org/?p=qemu.git;a=blob_plain;f=tcg/README;hb=HEAD

[14] "Library to Instrument Executable Formats", https://lief.quarkslab.com/
