# The build contract

This page tells what the builder gives a build, what a project's `Dockerfile` and `build.sh` must do, and how the driver runs a fuzz target. It is for the person who ports a project's build to OSS Verify, and for people who run our binaries.

The `Dockerfile` and `build.sh` follow the conventions of OSS-Fuzz, on our builder in place of OSS-Fuzz's base image. `tools/check` builds a project exactly as we do.

An OSS-Fuzz `Dockerfile` and `build.sh` do not run here without changes. They expect an x86-64 base image, apt packages, a native clang and often shared libraries. Our builder is a cross-compiler for static riscv64 Linux programs. Thus you must port each build. The port is usually short: the `cmake` or `configure` command, the compile and link commands of the fuzz targets, and the sources of the dependencies.

## The steps

`tools/check`, and our own builds, do these steps:

1. Make the builder image from [infra/base-builder/](../infra/base-builder/), from a toolchain image ([below](#toolchains)).
2. Build the project image from the project's `Dockerfile`, on the builder. `tools/check` gives the build arguments `COMMIT` (the full commit that `repo#ref` names), `REPO` and `BASE_BUILDER`. Only this step has network access.
3. Run `compile` in a new container of the project image, with no network (`docker run --network=none`). Do this once for each build that `project.yaml` asks for: `plain`, `ubsan`, `asan` and `asan-ubsan`. `compile` sets the compilers and flags of the build and runs `$SRC/build.sh`.
4. Find the fuzz targets in the `$OUT` of each build. Copy each binary to `out/<target>/<target>.<build>`. Write the manifest, with the SHA-256 of each binary. `tools/check` lists each binary with its size, the size of its `.text` section, `static` or `dynamic`, and its SHA-256. With `--summary <file>`, it also writes this list as a Markdown table; the Build check of a pull request shows that table. A binary with a `PT_INTERP` or `PT_DYNAMIC` program header is dynamically linked. `tools/check` refuses a dynamically linked binary, and one whose program headers it cannot read, with exit status 2, the status for a project that breaks the enrollment rules. Size is not a rule: a binary of any size passes. Because of our capacity, we are most likely to respond quickly to a project in C whose plain binaries have less than 1 MB of code: the larger of their `.text` section and their executable segments, which can hold read-only data too ([README](../README.md#who-can-enroll)).

## The builder

The toolchain image for C and C++ is the one that the oss-fuzz-theorems 2026.10 release built its binaries in, the row `oss-fuzz-theorems-2026.10` of [infra/toolchains.tsv](../infra/toolchains.tsv). It contains these items:

* clang 20.1.8 for `riscv64-linux-musl`, and lld;
* the musl sysroot at `/opt/musl-sysroot`, with static builds of common libraries that a project can link;
* a sealed static AddressSanitizer runtime;
* Alpine Linux with CMake, Meson, Ninja, the autotools and git.

The builder adds the interface of OSS-Fuzz. Its driver, compiler wrappers and flags come from the build recipe of that release. With them, the builder makes the release's binaries again, byte for byte.

Each binary is a static riscv64 Linux program for RV64G (`-march=rv64g -mabi=lp64d`), linked with lld against musl.

## Static riscv64 programs

The statements use [Linux Process Semantics (LPS)](https://github.com/theorem-labs/rocq-linux-process-semantics), a formal model of a riscv64 Linux process ([what-gets-proven.md](what-gets-proven.md#the-statements)). A statement is about each byte of the program. A static program holds all of its code: the library, the fuzz target, the driver and the C library. Thus no code from outside the binary runs.

## Toolchains

A new toolchain image changes the bytes of each binary that it builds, and a proof is about specified bytes. Thus each project is built with one toolchain image, its vintage.

* [infra/toolchains.tsv](../infra/toolchains.tsv) lists the published toolchain images, oldest first, and the languages that each one builds ([project-yaml.md](project-yaml.md#language)). Today it lists four images: the C and C++ image above, and the Rust, Python and Go toolchains of the same release. We add a new image only after its publication. Outside `projects/`, no other file names the digest of a toolchain image.
* The builder gets the toolchain image as a build argument (`--build-arg TOOLCHAIN=<image>`). Its `Dockerfile` has no default, so a build without the argument fails.
* `tools/check --lock` builds with the toolchain that the lock names. For a manifest, this is `builder.toolchain`. For a `harness.yaml` of oss-fuzz-theorems, it is the `build.builder` field of the `project.yaml` two directories above.
* If you give more than one lock, the locks must name the same toolchain.
* Without a lock, `tools/check` builds with the newest toolchain for the project's language: the last row that lists it. `--toolchain <image>` overrides the lock and the newest toolchain.
* The lock of a project pins its vintage. A project with published proofs stays on the toolchain that its lock names, so its binaries keep their bytes. A project with no lock, for example a seeded project in `tools/seeds/`, uses the newest toolchain.

We check builds ported from oss-fuzz-theorems against the release's binaries, on the release's toolchain. Their `harness.yaml` locks name it.

## What build.sh gets

| variable | value |
|---|---|
| `$SRC`, `$WORK`, `$OUT` | `/src` (the sources and `build.sh`), `/work` (temporary files) and `/out` (the fuzz targets), as in OSS-Fuzz |
| `$CC`, `$CXX` | clang and clang++ for this build: cross-compilers for `riscv64-linux-musl`, with the sanitizer runtime of this build |
| `$CFLAGS` | the common flags, the sanitizer flags of this build, `-Wno-unused-command-line-argument` and `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` |
| `$CXXFLAGS` | `$CFLAGS -stdlib=libc++` |
| `$LIB_FUZZING_ENGINE` | the driver, which takes the place of libFuzzer in each fuzz target ([below](#the-driver)) |
| `$LIB_ALLOCATION_FAILURE_ENGINE` | the driver of an allocation-failure fuzz target ([below](#allocation-failure-fuzz-targets)) |
| `$LIB_ALLOCATION_COUNTING_ENGINE` | the same, with counting mode on, for sweep and test builds that we never publish |
| `$SANITIZER` | `none`, `undefined`, `address` or `address-undefined` |
| `$ARCHITECTURE`, `$FUZZING_ENGINE` | `riscv64`; `none`, the OSS-Fuzz name for a driver that runs inputs from files |
| `$CMAKE_TOOLCHAIN_FILE` | a CMake toolchain file for this build. CMake 3.21 and later find it without help. |
| `$AR`, `$NM`, `$RANLIB`, `$STRIP`, `$OBJCOPY` | the LLVM tools, as `riscv64-linux-musl-ar` and the other names, which are also on `PATH` |
| `<fuzzer/FuzzedDataProvider.h>` | on the include path of `$CC` and `$CXX`, as in OSS-Fuzz |
| `$SOURCE_DATE_EPOCH` | `1756684800`, for each tool that writes a date |

`compile` runs `build.sh` with `bash -eux`, from the `WORKDIR` of the `Dockerfile`. The `build.sh` of a Go project gets the environment that OSS-Fuzz gives a Go project instead ([go/compile-go](../infra/base-builder/go/compile-go)).

## The builds

These are the common compile flags:

    -march=rv64g -mabi=lp64d -Os -g -ffunction-sections -fdata-sections -fno-stack-protector -Wdate-time
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-reallocarray -fno-builtin-free
    -fno-builtin-aligned_alloc -fno-builtin-posix_memalign -fno-builtin-memalign -fno-builtin-valloc
    -fno-builtin-strdup -fno-builtin-strndup

The `-fno-builtin-*` flags keep each allocation an ordinary call in all four builds. Thus the optimizer cannot remove or merge an allocation in one build and keep it in a different build.

`compile` builds the driver with these flags and `-fno-plt`. clang does not use `-fno-plt` for this target. Thus each C, C++, Rust and Python build writes `warning: argument unused during compilation: '-fno-plt'` seven times, before `build.sh` starts. You can ignore this warning. `$CFLAGS` does not have `-fno-plt`.

| build | `$SANITIZER` | sanitizer flags | a detected error |
|---|---|---|---|
| `plain` | `none` | none | none |
| `ubsan` | `undefined` | `-fsanitize=undefined -fno-sanitize-recover=all -fsanitize-trap=all -fno-sanitize=function` | `SIGILL` (status 132), with no output |
| `asan` | `address` | `-fsanitize=address`, with the sealed static runtime | `abort()` (status 134), with no output |
| `asan-ubsan` | `address-undefined` | both | either |

The UBSan builds trap, with no runtime. oss-fuzz-theorems measured the checks that clang 20 makes with these flags:

    alignment, array-bounds, bool, builtin, enum, float-cast-overflow, integer-divide-by-zero, nonnull-attribute,
    null, object-size, pointer-overflow, return, returns-nonnull-attribute, shift-base, shift-exponent,
    signed-integer-overflow, unreachable, vla-bound

The UBSan builds do not make these checks:

* `function`, which is off;
* `vptr`, which needs a runtime. With the next toolchain version, the `ubsan` build of a `c++` project makes it, through the toolchain image's trap-only handler ([project-yaml.md](project-yaml.md#ubsan_checks));
* the checks that clang leaves out of `undefined` by default: unsigned overflow, implicit conversions, `local-bounds`, float division by zero and nullability.

With today's toolchain vintage, these flags are fixed, so that the ported builds make the release's binaries again. With the next toolchain version, a list replaces them: the checks that OSS-Fuzz makes fatal for the project's language, changed by the project's `ubsan_checks` ([project-yaml.md](project-yaml.md#ubsan_checks)). `tools/check` then gives `compile` the checks, and `compile` builds the library and the fuzz targets with `-fsanitize=<checks> -fsanitize-trap=<checks>`. As in OSS-Fuzz, the C files of a `c++` project are compiled without `function`. In the `ubsan` build, `vptr` is compiled with `-fsanitize=vptr -fno-sanitize-link-runtime`, the links get the toolchain image's trap-only handler, and a compile with `-fno-rtti` gets `-fno-sanitize=vptr`; the `asan-ubsan` build leaves `vptr` out. `libcxx-hardening` compiles and links the `ubsan` build's C++ with `/opt/asan-static/musl-hardened.cfg`. The driver never gets these flags. The `ubsan` column of `infra/toolchains.tsv` tells which way each toolchain image works: `fixed` or `checks`.

The sealed AddressSanitizer runtime has these properties, as the documentation of that release describes:

* It reads no environment variable, so `ASAN_OPTIONS` has no effect.
* The driver sets `allocator_may_return_null=1`. Thus `malloc` returns NULL when the runtime refuses memory, as in the plain build.
* A detection aborts and writes no report.
* Leak detection is off.
* The runtime installs no signal handlers.
* At start, it reserves more than 100 GiB of address space. Under a limit such as `ulimit -v`, the reservation fails and the program waits forever.

The driver is compiled with no sanitizer flags in each build. The library and the fuzz targets get the flags of the build. In each build, `getenv()` returns NULL, `getpid()` and `getppid()` return 1, and `mkstemp()` and the related functions use a fixed name in the current directory. Thus a program depends only on its input file.

### Functions that the AddressSanitizer runtime wraps

The sealed AddressSanitizer runtime intercepts functions through the linker's `--wrap` option. Each `asan` and `asan-ubsan` link gets `-Wl,--wrap=<function>` for each function on the runtime's list, and the runtime defines `__wrap_<function>` for them (for example `__wrap_fopen`). The list in the toolchain image has 380 functions. The builder removes `iconv` from it, so the links wrap 379 functions. `fopen`, `time`, `clock_gettime` and `dlopen` are on the list.

Thus do not link with `-Wl,--wrap=<function>` for a function on the list, and do not define `__wrap_<function>` for it. If you define `__wrap_<function>`, two objects define it, and the link of the AddressSanitizer builds fails. To replace a function on the list, rename the call when you compile. This method works in all four builds:

* Compile the file that calls the function with `-D<function>=<name>`, for example `-Dfopen=my_fopen`. `-D` changes each use of the name in that file and in the headers that it includes. Thus use it only in a C file, and only for a name that has no other meaning there.
* Define `my_fopen` in your fuzz target. In a C++ fuzz target, define it with `extern "C"`.
* If the library's archive also has that file, compile a second copy of it for this fuzz target only. Use the flags and include paths of the library's own compile of that file, and add `-D`. Link the copy before the archive. Then the other fuzz targets do not need `my_fopen`.

The list is a file in the toolchain image: `/opt/asan-static-rt/lib/clang/20/lib/riscv64-unknown-linux-musl/libclang_rt.asan.a.wrap`. Each `--wrap=<function>` line names one function. To read it, run `docker run --rm --entrypoint cat <image> <path>`, with the image from [infra/toolchains.tsv](../infra/toolchains.tsv). [infra/base-builder/toolchain.sh](../infra/base-builder/toolchain.sh) removes the `--wrap=iconv` line.

The driver's seals also use `--wrap`, in all four builds: `getenv`, `getpid`, `getppid`, `mkstemp`, `mkostemp`, `mkstemps` and `mkostemps`. `link-fuzz-target` adds them to each link. In a `build.sh` that you write by hand, do not wrap these functions, and do not define `__wrap_<function>` for them. If a link wraps `getenv`, `getpid` or `mkstemp` itself, `link-fuzz-target` adds none of the seals, and the program can then depend on its environment, its process id and the names of its temporary files. A build ported from oss-fuzz-theorems adds the same seals with the `oft_seal_*` helpers of `recipes.sh`. Keep those calls.

## What the Dockerfile must do

Start from [templates/Dockerfile](../templates/Dockerfile). Two builds written by hand are small examples. [projects/cjson/](../projects/cjson/) builds cJSON's own fuzz target with CMake; its `build.sh` also copies the checkout to the path where the oss-fuzz-theorems release built it, which only a build that must match the release's bytes needs. [tools/tests/fixtures/example/](../tools/tests/fixtures/example/) is a test project, whose `Dockerfile` takes the source from the build context, as a `Dockerfile` in your repository does, and whose `fuzz/` subdirectory a project directory cannot have. Obey these rules:

1. Start with `FROM ${BASE_BUILDER}`, after `ARG BASE_BUILDER=oss-verify-base-builder`. `tools/check` gives the builder that it made.
2. Declare `ARG REPO` and `ARG COMMIT`.
3. Get the source at exactly that commit: `RUN fetch-commit $SRC/<name>`. Add `--submodules` if the repository has submodules.
4. Do not write a commit id in the `Dockerfile`. `tools/check` gives the commit, and the lock records it.
5. Get each dependency at a fixed version.
6. Copy `build.sh`, your fuzz target sources and your build patches to `$SRC`. Apply the build patches in the order that `series` gives.

`build.sh` builds the dependencies that a sanitizer build must instrument, with the flags of each build. The libraries of the sysroot are linked as they are, with no instrumentation. `tools/check` records the commit of each git checkout under `$SRC` in its manifest.

If the `Dockerfile` is in the project's repository (`dockerfile` in `project.yaml`), the build context is that repository at the commit that we build. Use `COPY . $SRC/<name>` to get the source.

## What build.sh must do

Start from [templates/build.sh](../templates/build.sh). Obey these rules:

1. Build the library as a static library, with `$CC`, `$CXX`, `$CFLAGS` and `$CXXFLAGS`. CMake finds `$CMAKE_TOOLCHAIN_FILE` without help. Give each other build system the cross-compilers, the sysroot and static linking in its own way. A header-only library has no library to build: compile each fuzz target against its headers, and link it with `$LIB_FUZZING_ENGINE` only:

        $CXX $CXXFLAGS -std=c++17 -Iinclude -c "$SRC/example_fuzzer.cpp" -o "$WORK/example_fuzzer.o"
        $CXX $CXXFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE

2. Compile each fuzz target.
3. Link each fuzz target into `$OUT` through `$CC` or `$CXX`, with `$LIB_FUZZING_ENGINE`:

        $CC $CFLAGS -c fuzz/example_fuzzer.c -o "$WORK/example_fuzzer.o"
        $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE libexample.a

4. Do not run a program that the build compiled. The programs are for riscv64. A build that runs one works only on a machine that runs riscv64 programs, for example through binfmt_misc and qemu. Its result then depends on the machine.
5. Do not change a fuzz target after the link: no `strip` and no `objcopy`. The link makes the published bytes.
6. Make the build deterministic. Do not write dates: `$SOURCE_DATE_EPOCH` is set, and `-Wdate-time` warns about `__DATE__` and `__TIME__`. Do not make version strings from the git history, which is different in a full clone and a shallow clone.

A `build.sh` written by hand has had tests with CMake only. The builds that we ported from oss-fuzz-theorems ([below](#builds-ported-from-oss-fuzz-theorems)) also include Meson, autotools, Makefile and header-only builds.

## How a fuzz target is linked

A link through `$CC` or `$CXX` that names `$LIB_FUZZING_ENGINE` goes to [link-fuzz-target](../infra/base-builder/link-fuzz-target). It makes the link as the release's build recipe does:

    <compiler> -static -no-pie -Wl,--gc-sections <driver> [<silent reports>] <the link's own arguments> <seals>

* The driver's objects come first, in the position where the link named `$LIB_FUZZING_ENGINE`.
* The seals for getenv, getpid and mkstemp come last.
* In the AddressSanitizer builds, `-Wl,--defsym=__sanitizer_silent_reports=1` makes a detection abort without a report.

`link-fuzz-target` links two times. The first link makes the file that `build.sh` asked for, with its symbols, so that we can find the fuzz target by its symbol table. The second link adds `-Wl,--strip-all`, and its output is the published binary. `compile` keeps it as `$OUT/.stripped/<sha256 of the first>`.

## The driver

The driver takes the place of libFuzzer. Each fuzz target is linked with it through `$LIB_FUZZING_ENGINE` ([infra/base-builder/driver/](../infra/base-builder/driver/)). Its files are under MIT OR Apache-2.0, so that a program under version 2 of the GNU GPL can be linked with it ([NOTICE](../NOTICE)). A binary takes one argument, the input file:

    <binary> <input file>

The driver reads the whole input file. It divides the file into four parts:

    [u16 config word][config bytes][u32 allocation mask][payload]

The two integers are little-endian.

* The low 15 bits of the config word give the length of the config bytes. The top bit, bit 15, asks for counting mode ([below](#counting-mode)).
* The driver calls `LLVMFuzzerTestOneInput` on the payload `(config[0] & 3) + 1` times. With no config bytes, it calls it once.
* The driver writes each return value on standard output.
* A fuzz target linked with `$LIB_FUZZING_ENGINE` ignores the allocation mask. An allocation-failure fuzz target uses it ([below](#allocation-failure-fuzz-targets)).

Thus an OSS-Fuzz testcase needs six zero bytes in front of it: `00 00 00 00 00 00`. A seed corpus holds inputs as libFuzzer takes them, without these six bytes ([project-yaml.md](project-yaml.md#seed-corpora)).

### Exit statuses

| status | meaning |
|---:|---|
| 0 | each call of the fuzz target returned 0 or -1 |
| 2 | the driver refused the input and did not call the fuzz target, or the system refused memory to the Go runtime ([below](#go-fuzz-targets)) |
| 77 | the fuzz target called `exit()` during a call, and no exit handler registered after the driver's guard ended the process first ([below](#what-the-driver-does-not-intercept)); in a Python fuzz target, an uncaught `SystemExit` in `TestOneInput`; in a Go fuzz target, `os.Exit` during a call ([below](#go-fuzz-targets)) |
| 78 | a call of the fuzz target returned a value that is not 0 or -1 |
| 79 | a Rust fuzz target panicked; a Python fuzz target raised an exception that nothing caught (not `MemoryError`, which gives 2, or `SystemExit`); a Go fuzz target panicked: a `panic`, a runtime error, or `t.Fatal`, `t.Error` or `t.Fail` in a fuzz test ([below](#go-fuzz-targets)) |
| 80 | the Go runtime stopped with a fatal error that is not out of memory, for example a deadlock or a stack overflow ([below](#go-fuzz-targets)); in a Python fuzz target, the interpreter or the frozen harness failed before the first input, a defect of the build |
| 132 | `SIGILL`: an UndefinedBehaviorSanitizer check failed (the check traps in these builds) |
| 134 | `abort()`: a failed `assert()`, an AddressSanitizer detection, or an uncaught C++ exception |
| 139 | `SIGSEGV`: a crash |

Today's driver counts a return value of -1 as 0. It also writes each return value on standard output, so a -1 stays observable.

> **Next toolchain version.** The driver of the next toolchain version maps the return values to the exit status in a different way:
>
> | status | meaning in the next toolchain version |
> |---:|---|
> | 0 | each call of the fuzz target returned 0 |
> | 3 | one or more calls returned -1, and no call returned another value |
> | 78 | a call of the fuzz target returned a value that is not 0 or -1 |
>
> The statuses 2 and 77, and the statuses of the signals, do not change. A call of `exit()` during `LLVMFuzzerInitialize` with a status other than 0 or 2 becomes status 77. For a fuzz target in C, C++ or Rust, and for a DSL fuzz target, a halts statement then accepts the statuses 0, 2 and 3. The drivers for Python, JavaScript, Go and JVM fuzz targets do not give status 3, so a halts statement for them accepts only 0 and 2 (our tools do not write theorem statements for Go yet). A project with proofs keeps today's driver, through the vintage that its lock pins ([Toolchains](#toolchains)).

> **WARNING:** Do not return -1 for a failed property. The driver counts -1 as a pass: status 0 today, and status 3 in the next toolchain version. A halts statement accepts both. For a failed property, call `abort()`. Return -1 only for a failed expectation that the input chooses, or for an input outside a property's domain. Step 3.7 of [the add-project skill](../.claude/skills/add-project/SKILL.md) tells why.

With today's driver, a statement accepts only the statuses 0 and 2 ([what-gets-proven.md](what-gets-proven.md#what-a-statement-accepts)). The driver refuses the input with status 2 for these causes:

* the number of arguments is not one;
* it cannot open or read the input file;
* the file is shorter than its six-byte header;
* the file is 64 MiB or larger;
* it gets no memory to read the file into.

A sanitizer detection writes nothing. AddressSanitizer aborts silently. UndefinedBehaviorSanitizer has no runtime and traps ([above](#the-builds)).

`tools/tests/test_builder.py` checks each status in all four builds, on a C fuzz target and a C++ fuzz target. It also shows a special case: UndefinedBehaviorSanitizer does not check a `volatile` access for a null pointer. Thus a load through a `volatile` null pointer crashes with 139 in each build. A load through a pointer that is not `volatile` traps with 132 in the UBSan builds.

### What the driver does not intercept

The driver changes a call of `exit()`, during a call of the fuzz target, into status 77. An `atexit` handler does this. The driver does not intercept `_exit`, `_Exit` or `quick_exit`, which do not run `atexit` handlers. A fuzz target that calls one of them ends the process with the status that it gave. `test_builder.py` shows this.

Today's driver registers that handler once, before it calls `LLVMFuzzerInitialize`, and the handler gives 77 only while a call of the fuzz target runs. So an `exit()` in `LLVMFuzzerInitialize` is not 77: unless a handler ends the process first, it ends with the low 8 bits of its argument. Exit handlers run last-registered-first. Thus a handler that the fuzz target or the library registers later, in `LLVMFuzzerInitialize` or during a call, runs first. This includes the destructor of a C++ object that was first made then: a function-local `static`, or a `thread_local` object where the build registers its destructor with `__cxa_atexit`. If that handler does not return (it calls `_exit`, `_Exit`, `quick_exit` or `abort`, makes the `exit_group` system call, or jumps out of the handler), the `exit()` never reaches the guard. The status is then the one that the handler, or the code that it jumps to, gives, and it can be 0. `test_builder.py` shows both cases: a later handler that calls `_Exit(0)` gives status 0, and one that returns leaves the guard to give 77.

The C, C++, Rust and Python adapters all register this guard. Two exits do not reach it: in a Python fuzz target, the interpreter host ends an uncaught `SystemExit` with `_exit(77)` itself; and a Go fuzz target has no C driver, and the patched Go runtime gives 77 for `os.Exit` itself. Native code that a Python fuzz target calls (an extension module, `ctypes` or `cffi`) obeys the rules above.

> **WARNING:** Do not register an exit handler that does not return. It can hide a failed check: the process can then end with a status that a statement allows, for example 0.

> **WARNING:** Do not install a handler for `SIGABRT`, `SIGSEGV` or another signal in a fuzz target. A handler hides a sanitizer detection.

> **WARNING:** Do not call `std::set_terminate` in a C++ fuzz target. An uncaught exception then ends with the status that the terminate handler gives, not 134. Do not replace the panic hook in a Rust fuzz target (`std::panic::set_hook`, `take_hook` or `update_hook`). The driver installs a panic hook before `main` that gives 79, and these calls replace it.

The driver itself never intercepts a signal or `abort()`.

## Allocation-failure fuzz targets

An allocation-failure fuzz target shows that the library survives refused allocations. In it, the allocations fail as the allocation mask of the input tells them to. In the other fuzz targets, the driver makes no allocation fail ([what-gets-proven.md](what-gets-proven.md#allocation-failure)).

The fuzz target must change an out-of-memory stop into a normal exit, and only that stop. To do this, catch `std::bad_alloc`, or use the library's own hooks for allocation failure.

> **WARNING:** Do not catch all exceptions. Do not call `std::set_terminate`. Do not install a `SIGABRT` handler. Such code hides failures that the statements must show.

To make an allocation-failure fuzz target, link the object files of a fuzz target again, into a different binary, with `$LIB_ALLOCATION_FAILURE_ENGINE`:

    $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer_allocation_failure" $LIB_ALLOCATION_FAILURE_ENGINE libexample.a

The fuzz target that you link with `$LIB_FUZZING_ENGINE` does not change. The allocation-failure link is different in two ways ([link-fuzz-target](../infra/base-builder/link-fuzz-target)):

* The driver uses [allocation_failure.c](../infra/base-builder/driver/allocation_failure.c) in place of `adapter.c`.
* The link uses copies of its object files and archives. In these copies, each call of an allocation function goes to the driver. These are the allocation functions:

      malloc calloc realloc reallocarray aligned_alloc posix_memalign memalign strdup strndup
      operator new, operator new[] (C++), with their nothrow and aligned forms

Compile the sources of the fuzz target before the link. Then name the object files and static archives directly, as in the example above. Allocation-failure and counting links refuse source files, response files, linker scripts, `-l` library selectors, and linker forwarding (`-Wl,...`, `-Xlinker` or `--for-linker`), and clang configuration files (`--config`): those forms can hide inputs whose allocation calls would not be rewritten. A normal `$LIB_FUZZING_ENGINE` link keeps its existing behaviour.

While `LLVMFuzzerTestOneInput` runs, the driver counts these calls from 0, over all calls of the fuzz target in a run. Call n fails if bit n of the allocation mask is set:

* `malloc` and the other functions return `NULL` and set `errno` to `ENOMEM`;
* `posix_memalign` returns `ENOMEM`;
* `operator new` throws `std::bad_alloc`, and its nothrow form returns `NULL`.

Calls after the 32nd never fail. The driver counts no other allocations. It does not count its own allocations, or those of `LLVMFuzzerInitialize`. It does not count the allocations that the C or C++ library makes inside a function that the project called. Thus an input makes the same calls fail in all four builds. The builds compile with `-fno-builtin-malloc` and the related flags, so the compiler keeps each call.

### Counting mode

In counting mode, the driver exits with a count in place of the status of the fuzz target. A statement accepts only 0 and 2. Thus a published allocation-failure fuzz target ignores counting mode: with `$LIB_ALLOCATION_FAILURE_ENGINE`, it exits as it does without counting mode.

A fuzz target linked with `$LIB_FUZZING_ENGINE` counts nothing. In counting mode it exits with 0, whatever it returned.

To find which allocations an input makes, link a sweep or test build with `$LIB_ALLOCATION_COUNTING_ENGINE`. We never publish such a build. It is the same as `$LIB_ALLOCATION_FAILURE_ENGINE`, with one difference. In counting mode, it exits with the number of calls that it counted, or 251 if there were more.

`tools/tests/test_builder.py` checks the mask, counting mode and `std::bad_alloc` in all four builds, with each engine. It also builds cJSON's fuzz target with both engines ([tools/tests/fixtures/cjson](../tools/tests/fixtures/cjson/build.sh)). The test shows three results. The fuzz target keeps the release's bytes. An input that makes 21 allocations gets the same count in each build. If any one allocation fails, or all fail, the fuzz target still exits with 0.

## The fuzz targets

A fuzz target is an executable in the `$OUT` of a build whose ELF symbol table defines `LLVMFuzzerTestOneInput`. This is the OSS-Fuzz rule, but we read the symbol table in place of the bytes of the file. A fuzz target must be in each build. A Go program has no `LLVMFuzzerTestOneInput`. Thus `compile` lists the Go fuzz targets in `$OUT/.go-fuzz-targets`, and `tools/check` reads that list ([below](#go-fuzz-targets)).

`fuzz_targets` in `project.yaml` names the fuzz targets to verify. Without it, we verify each fuzz target that we find. `tools/check` copies the published binary of each fuzz target to `out/<target>/<target>.<build>`. It ignores each other file in `$OUT`.

A DSL driver is a fuzz target too: an `LLVMFuzzerTestOneInput` that runs a small program from its payload, and takes its configuration from the payload. It prints the observables of each operation. A failure of the library is one of these observables, not an exit status. The allocation mask works as for each other fuzz target.

A proof is only as strong as its fuzz target. Thus each fuzz target must obey the rules in step 3 of [the add-project skill](../.claude/skills/add-project/SKILL.md):

* Each property is a check that calls `abort()`, not an `assert()`, which `NDEBUG` removes.
* A seed corpus runs each API call and each property check at least once ([project-yaml.md](project-yaml.md#seed-corpora)).
* For each property, a one-line change to the code makes the fuzz target abort on an input of the seed corpus. The change is a `mutant:` record in the check's comment, or a patch in the directory that `mutants` names ([below](#the-checks-of-a-fuzz-target), [project-yaml.md](project-yaml.md#mutants)).
* Each count, size and loop that comes from the input has a bound.
* A run depends only on its input: no threads, clock, random numbers, network, environment or other files.
* `LLVMFuzzerTestOneInput` returns -1 only for a failed expectation that the input chooses, or for an input outside the domain of a property. In all other cases, it returns 0. It never returns -1 for a failed property, and it never calls `exit()` or `_exit()`. It registers no exit handler that does not return, installs no signal handler, calls no `std::set_terminate` and replaces no Rust panic hook ([above](#what-the-driver-does-not-intercept)).

## The checks of a fuzz target

`tools/check --checks <file>` measures the second and third rules above for a C or C++ project, on the inputs of its seed corpora, and writes a report in Markdown. The Build check of each enrollment pull request runs it and shows the report in its step summary and in its comment on the pull request. What it finds changes no exit status. It does these steps:

1. **A coverage build.** It builds the `plain` build again, with `-O0 -fprofile-instr-generate -fcoverage-mapping`, with LLVM's profile runtime, and with `abort()` wrapped so that the profile is written before the program aborts. The toolchain image has no profile runtime, so `tools/check` downloads compiler-rt's source for the toolchain's LLVM version once, checks its SHA-256, and compiles the runtime in the build's container ([tools/checks/compile-check](../tools/checks/compile-check)).
2. **The runs.** It runs each fuzz target on each input of its seed corpus, with the six-byte header in front ([above](#the-driver)), with `qemu-riscv64-static` in a container of the project image with no network ([tools/checks/run-seeds](../tools/checks/run-seeds)). A run that does not end in 120 seconds counts as a failure. The inputs also run on the project's most checking sanitizer build: `asan-ubsan`, else `asan`, else `ubsan`.
3. **The checks.** A check is a call of `abort()` in a file that defines `LLVMFuzzerTestOneInput`, or in another file of its directory. Its guard is what decides whether it runs: the condition of the `if`, `while` or `for` of which it is the body (also through `else`, and also after other statements of the block), or the `switch` of a `case` or `default` label. A check is reached when a run evaluates its guard. The report lists each check that no input reaches. It lists apart, and does not measure, an `abort()` that nothing guards, one inside an expression, and one in a macro definition.
4. **The breakages.** A breakage is a change to the code that must make a check fire. There are two kinds, and a project can use both:
   - **A record in the check's comment** (step 3.4 of the add-project skill), one or more pairs of lines:

         mutant: <path>:<line> `<old>` -> `<new>`
         input: <file name in the seed corpus>

     `<path>` starts at the `WORKDIR` of the `Dockerfile`, and `<line>` is its line at the built commit, after the `Dockerfile` copies the project's files in. `<old>` occurs once on that line, and the change replaces it with `<new>`, which can be empty. The record is met when its input fails with the change, and passes without it.
   - **A patch in the `mutants` directory** ([project-yaml.md](project-yaml.md#mutants)). A patch is caught when any seed input that passes without it fails with it.

   For each breakage, it makes the coverage build with the change and runs the inputs: a record's own input, or every input for a patch. If no run failed, it also makes the sanitizer build with the change and runs the inputs on it. A run fails when it exits with a status other than 0 and 2. A run that does not end within 120 seconds counts as neither a pass nor a failure. The coverage build also shows which checks fired. The breakages build in parallel, for at most `--checks-budget` minutes (60 by default). The report lists each record that is not met, each patch that no input catches, each breakage that does not apply or build, each one that the budget left unchecked, and each check that no breakage makes fire. A patch is applied with `git apply` in the `WORKDIR`, and can change only files under it.
5. **Not a property.** A stop that is not a property, for example `if (!buf) abort();` after a failed allocation, has one line `not a property: <reason>` in its comment, in place of the records. It needs no input and no breakage. The report lists it with its reason, for the review.

It needs `qemu-riscv64-static` on `PATH`, and compiler-rt's source from GitHub on the first run. The check of system calls reads the runs of qemu 10.0.11 only ([below](#the-checks-of-the-binaries)). Take qemu out of Debian 13's package, and do not install it, because the package registers qemu with the kernel for riscv64 programs: download `qemu-user` 1:10.0.11+ds-0+deb13u1 (the Build check takes it from `https://snapshot.debian.org/file/a0eaa62f815efb2361d43b1e3f8011c17ad9123a`, SHA-256 `6b6fea55551fbcc1eb30e146ad5abdfbb49f8fa8c5998016242126de4d7f80df`), run `dpkg-deb -x <the .deb> <directory>` and `ln -s qemu-riscv64 <directory>/usr/bin/qemu-riscv64-static`, then add `<directory>/usr/bin` to `PATH`.

## The checks of the binaries

`tools/check --checks <file>` also does four checks on each build of each fuzz target ([tools/check_binaries.py](../tools/check_binaries.py)). It writes their results into the manifest ([below](#the-manifest)) and adds a table to the report, with one row for each binary. What they find changes no exit status.

The checks hold each binary against LPS as the published proofs use it: the proofs repository's `release.yaml` names the model's repository and commit (`semantics:`), and `tools/check` reads that file from the proofs repository on GitHub and fetches the model at that commit ([tools/model_release.py](../tools/model_release.py)). Checks 1 and 2 read the model through rules that we wrote against one commit of it. If the release names a model whose code is different in a file that a rule reads, the result is `stale` and not a verdict. A change to a comment changes no result.

1. **ELF and instructions** ([tools/binary_isa.py](../tools/binary_isa.py)). The binary is a 64-bit RISC-V executable at fixed addresses (`ET_EXEC`, `EM_RISCV`). Each byte of its executable code is a 32-bit instruction that the model's decoder accepts and executes: no compressed (16-bit) instruction, no vector or other instruction that the model does not have, and no read of a control register that the model does not have. The check reads the instructions, not the ELF header's flags, and every byte that a segment marked executable maps, whatever a section header says about it. The one exception is a section of build-id notes (the Go and GNU build ids that Go's linker puts in front of `.text`), when its bytes are exactly such notes, each of the two at most once.
2. **System calls** ([tools/syscall_shapes.py](../tools/syscall_shapes.py)). The binary runs on the empty input (the six-byte header and no payload) and on the first 8 inputs of the fuzz target's seed corpus, with `qemu-riscv64-static -strace` of qemu 10.0.11, the one release whose log formats and host calls the check reads; a run of any other release decides nothing (qemu 8.2, for one, hands the host 0 for the offset of every anonymous `mmap`, so its runs cannot show the offset the program asked for). Each run is in a container of the toolchain image with no network, in an empty working directory that holds the input as `input.bin`, with empty `/tmp`, `/var/tmp` and `/dev/shm`, with an `/etc` that holds only `hosts`, `nsswitch.conf`, `resolv.conf` and an empty `hostname`, with no environment, as an unprivileged user, and with the fuzz target's name as `argv[0]` ([tools/checks/run-binaries](../tools/checks/run-binaries)). qemu's log prints some arguments as 32-bit numbers (the length of `mmap`, for one) and does not print the address that `connect` gets, so each run runs under a small tracer that logs the host calls with their full arguments, and the address family of each `connect` ([tools/checks/host-calls.c](../tools/checks/host-calls.c)). qemu rounds the length of `mmap`, `munmap`, `mprotect` and `madvise` up to a whole page before it calls the host, so the check takes the length's low 32 bits from qemu's log and its page from the host's. The check reads each trace against the model, under the statements' default for an abort (`abort: error`: an abort is not a modeled end): each call must be in the model's system call table, and its arguments and its result must be ones that the call's specification allows: an errno that the call's arm can answer, or a success that it can give. Otherwise the model says that the call is unmodeled, and no statement about the run is true in the model. The check knows the bytes of `input.bin`, so each `read`, `pread64` and `lseek` of it has the one answer that the model gives, and a `readv` gets no more bytes than remain. Each socket call is answered from the socket's state, as the model keeps it. A call whose answer turns on a value that neither log shows decides nothing. A fork that the model answers ends what the trace decides: the child writes into the same log, and qemu's writes of the two processes interleave inside a line, so the run is not decided from the fork on. The result lists each call and argument shape that the model does not cover, with the inputs that made it. A trace decides something only when it is a whole run: it ends with the run's exit, holds at least 8 calls, and opens and reads `input.bin`. A run that does not end within 60 seconds decides nothing, and all runs together stop after 30 minutes.
3. **Quiet and loud**. With `--checks`, each link of a fuzz target also makes a quiet twin: the same link with each of the driver's objects compiled with `-DHARNESS_QUIET`, which then writes nothing ([link-fuzz-target](../infra/base-builder/link-fuzz-target)). The twin runs on the same inputs, in the same way. It must write nothing to standard output or standard error, and exit with the same status as the binary. Thus what the binary writes does not change which code runs or how it ends; and code of the project that writes (a warning on standard error, for one) shows here. A Rust or Python fuzz target's twin also gets the quiet build of its adapter; a Go fuzz target's twin is the quiet program that OSS-Fuzz's Go helpers make.
4. **Uninstrumented code** ([tools/check_links.py](../tools/check_links.py)). With `--checks`, each link of a fuzz target also writes the linker's map, which names each object and archive member that the link took, and keeps a copy of each file it took. The check lists the files that the link took from the toolchain image (the bytes that the toolchain image has at that path): the C library, compiler-rt, the sanitizer runtime, the C++ runtime, the Fortran runtime and the libraries of the sysroot. No sanitizer instruments them, in any build, as in OSS-Fuzz's sanitizer builds. An allocation-failure fuzz target's link takes renamed copies of its archives, and each copy counts as the file it was made from. In the sanitizer builds, the check also checks that the project's own code is instrumented: in `asan` and `asan-ubsan`, each object with code refers to `__asan_init`, as the constructor that AddressSanitizer adds to each object it instruments does (rustc's allocator shim, which makes no memory access, is the one exception); in `ubsan` and `asan-ubsan`, each archive of the project's code holds more UBSan traps (and rustc UB checks) than the same archive in the `plain` build, and so does the project's code as a whole. An uninstrumented object with no mark of a compiler is listed, with its source file, as OSS-Fuzz allows, when its DWARF says it is assembly or Fortran, or, for an object assembled without DWARF, when a source of the project carries its name and names every global it defines. A list that would leave a file out is not written, and the result is `error`, in the `plain` build too; so is a build with no link record; so is the UndefinedBehaviorSanitizer comparison when there is no `plain` build. The driver is compiled without a sanitizer in every build, and is not listed. A Go program has no link record, because Go's linker writes no map. The check reads the program's own build information instead (its `.go.buildinfo` section, which `go version -m` reads): when it says that Go's own compiler and linker built the program from Go code only (`CGO_ENABLED=0`, `-compiler=gc` and `-buildmode=exe`, for `linux` and `riscv64`, with no race detector, no `-msan` or `-asan`, and no `-linkmode` or `-extld` in `-ldflags`), and Go's function table (`.gopclntab`) spans `.text` and gives every function the line table that Go's compiler and assembler write (only the linker's own trampolines and FIPS markers have none, and the check knows their bytes), the program links no C library and no other file of a C toolchain, and the result is `plain`, with no list. The function table is read because the build information does not show a `.syso` file, which Go's linker takes with no cgo; the C code it brings in has no line table. Otherwise the result is `error`.

The records and the quiet twins change no byte of a binary. With `--twice`, the second build makes neither, and its binaries must be the same as the first build's. A record that cannot be written leaves the link as it is, with a warning, and that fuzz target's checks say that it has no record.

These checks find a build that did not do what it meant to, for example a library whose own build dropped the sanitizer flags. The records are written in the build's own container, so they do not stand against a `build.sh` written to deceive them; the review of the pull request does. The same holds for the runs: qemu writes the trace as the program's own user, so a binary written to deceive the checks can rewrite its trace. `tools/check` reads the records and the runs' results without following a symbolic link, and checks each kept file against its SHA-256.

## Rust fuzz targets

A Rust fuzz target is a cargo-fuzz `[[bin]]` of the project's repository. The Rust toolchain image adds Rust nightly-2025-07-16 (rustc 1.90.0, LLVM 20.1.8) and its sealed standard library to the C and C++ toolchain. Its row in infra/toolchains.tsv names it. The oss-fuzz-theorems 2026.10 release built its Rust binaries in this image. Code that needs a newer Rust than this one takes a build patch: [projects/sqlpage/rust-duration-compat.patch](../projects/sqlpage/rust-duration-compat.patch) replaces `Duration::from_mins` and `Duration::from_hours`, which this rustc does not have ([below](#build-patches)).

rustc makes no static library from a `[[bin]]`. Thus the build makes one package for each fuzz target: [rust/gen-shim.py](../infra/base-builder/rust/gen-shim.py) writes a package named `oft-rust-shim`, whose library root is a copy of the bin's source without its `#![no_main]` lines, with the line `extern crate oft_rust_rt as _;` added at its end. The package depends on the adapter `oft-rust-rt`, on the dependencies of the fuzz package, and on the fuzz package itself when it has a `[lib]`. `build.sh` then builds this package and links it with the driver ([rust/recipes.sh](../infra/base-builder/rust/recipes.sh)).

A Rust project has all four builds. Each one compiles the standard library with its own flags (`-Zbuild-std`). The table gives the flags that make the four builds different. In each build, `recipes.sh` also adds two `--remap-path-prefix` flags, `-Cdebug-assertions=on` when the target sets `CARGO_DEBUG_ASSERTIONS=1`, and the `--cfg` of the stdio seal when the target sets `OFT_RUST_QUIET_STDIO=1`:

| build | what the compiler gets |
|---|---|
| `plain` | `--cfg fuzzing -Zub-checks=no` |
| `ubsan` | `--cfg fuzzing -Zub-checks=yes` |
| `asan` | `--cfg fuzzing -Zub-checks=no -Zsanitizer=address` |
| `asan-ubsan` | `--cfg fuzzing -Zub-checks=yes -Zsanitizer=address` |

The `ubsan` build is rustc's UB checks, which panic; it is not clang's UndefinedBehaviorSanitizer. Thus a Rust project may not set `ubsan_checks` ([project-yaml.md](project-yaml.md#ubsan_checks)).

### The lock of a Rust fuzz target

The lock in the project directory is the lock of the generated `oft-rust-shim` package, not of the fuzz package. The `crates` line of `sources` makes the shim package, copies this lock to `shim/Cargo.lock`, and vendors the crates with `cargo vendor --locked` ([lay-out-sources](../infra/base-builder/lay-out-sources)). The line gives the vendor directory, the lock, the source tree, the fuzz directory and the name of the bin. A `tree` line lays out the source tree before it, and the `patch` lines of that tree, if any, come between them ([projects/sqlpage/sources](../projects/sqlpage/sources)):

    tree	ext/<target>/src	upstream/<repository>
    copy	targets/<target>/Cargo.lock	Cargo.lock
    crates	ext/<target>/vendor	targets/<target>/Cargo.lock	ext/<target>/src	fuzz	<bin>

A lock of the fuzz package names neither `oft-rust-shim` nor `oft-rust-rt`. `cargo vendor --locked` refuses to update a lock and exits with status 101, so `lay-out-sources` stops the build, and the build log shows cargo's reason after the `lay-out-sources` line: `the lock file .../shim/Cargo.lock needs to be updated but --locked was passed to prevent this` (a newer cargo than the toolchain's words it `cannot update the lock file ... because --locked was passed to prevent this`). `lay-out-sources` also stops when `cargo vendor` changed the lock, so the lock must stay as it is.

Make the lock in a checkout of this repository, from a checkout of the project with its build patches applied, with the steps that the `crates` line uses. Run the toolchain's cargo, nightly-2025-07-16, so that the cargo that makes the lock is the cargo that vendors it (with rustup, `cargo +nightly-2025-07-16`):

    tmp=$(mktemp -d) && cp -a <project checkout> "$tmp/src" && touch "$tmp/src/.oft-scratch-copy"
    python3 infra/base-builder/rust/gen-shim.py --src "$tmp/src" --fuzz-dir fuzz --bin <bin> \
      --out "$tmp/pkg" --rt "$PWD/infra/base-builder/rust/oft-rust-rt"
    cargo +nightly-2025-07-16 generate-lockfile --manifest-path "$tmp/pkg/Cargo.toml"
    cp "$tmp/pkg/Cargo.lock" projects/<name>/Cargo.lock

Two fuzz targets with the same dependencies can share one lock and one vendor directory: `tools/seeds/bincode/sources` lays out the second target's vendor directory as a `link` to the first.

## Go fuzz targets

A Go fuzz target is an OSS-Fuzz Go fuzz target, as it is. OSS-Fuzz's Go helpers build it: `compile_go_fuzzer` for a go-fuzz `Fuzz(data []byte) int` function, and `compile_native_go_fuzzer` or `compile_native_go_fuzzer_v2` for a `testing.F` fuzz test. The Go toolchain image adds Go 1.27.1 and these helpers to the C and C++ toolchain. Its row in infra/toolchains.tsv names it. The oss-fuzz-theorems 2026.10 release built its Go binaries in this image, but did not publish them. Our builds make them again, byte for byte.

`build.sh` is the project's OSS-Fuzz `build.sh`, as it is. `compile` runs it with the environment that OSS-Fuzz gives the `build.sh` of a Go project: `SANITIZER=address`, `FUZZING_ENGINE=libfuzzer`, `ARCHITECTURE=x86_64` and `FUZZING_LANGUAGE=go` ([go/compile-go](../infra/base-builder/go/compile-go)). The helpers do OSS-Fuzz's steps until the build. Then they build a static riscv64 program from the fuzz target and a driver in Go, with no cgo. A Go project has the plain build only.

A `go.lock` in the project directory pins the modules. It has one row for each `.mod`, `.zip` and `.info` file of the module proxy, with the SHA-256 of each `.mod` and `.zip` file. The `gomodules` line of the `sources` file gets these files from proxy.golang.org while the `Dockerfile` builds, and checks them. `compile` then builds with `GOPROXY` set to these files, with no network.

Our tools do not write theorem statements for Go fuzz targets yet. These items are different from a Go fuzz target in OSS-Fuzz:

* The build uses a patched Go runtime. The patches are an overlay of the standard library (the `-overlay` flag of `go build`), and a rebuilt compiler. The Go toolchain itself does not change. The patches remove what LPS does not have: signal handlers, the second thread of the scheduler, reads of the environment, of `/proc` and of `/sys`, and the vector instructions of riscv64. They also give the exit statuses below.
* A load through a nil pointer is a segmentation fault (status 139), not a panic, because the runtime installs no signal handler. A statement for a Go fuzz target will count 139 as a failure, as it counts a panic.
* A panic, a runtime error, and `t.Fatal`, `t.Error` or `t.Fail` in a fuzz test exit with status 79. In OSS-Fuzz, they crash the fuzz target.
* `os.Exit` during a call of the fuzz target exits with status 77.
* A fatal error of the runtime that is not out of memory exits with status 80. Examples are a deadlock, a stack overflow and a write to a map from two goroutines. Stock Go exits with status 2.
* The runtime exits with status 2 only after the system refused it memory: an `mmap` for the heap, a stack or the runtime's own data failed. The premise of a statement for a Go fuzz target will exclude this. A request larger than the runtime's limit for one allocation (2^48 bytes), for example a `make()` that is too large, panics without asking the system (status 79).
* `os.Getenv` returns `""` for each variable, and `GOGC`, `GODEBUG`, `GOMAXPROCS` and `GOMEMLIMIT` have no effect.
* The program runs on one CPU.
* The return value of a `Fuzz` function does not change the exit status. OSS-Fuzz also ignores it. The driver writes it on standard output.
* All builds use Go 1.27.1. The `Dockerfile` of some OSS-Fuzz projects installs an older Go, which we do not install.
* The target is riscv64 without the C extension (RV64G), and libFuzzer is not linked: the driver calls the fuzz target.

## Run a binary

Each binary is a static Linux program for riscv64. Run it on a riscv64 machine, or with `qemu-riscv64` on another Linux machine:

    qemu-riscv64 out/<target>/<target>.<build> <input file>

To give it an OSS-Fuzz testcase, put six zero bytes in front of the testcase:

    { printf '\0\0\0\0\0\0'; cat testcase; } > input

> **WARNING:** Do not limit the address space of an `asan` or `asan-ubsan` binary, for example with `ulimit -v`. At start, the AddressSanitizer runtime reserves more than 100 GiB of address space. If it cannot, it waits forever.

The exit status tells the result ([above](#exit-statuses)).

## The manifest

`tools/check` writes `manifest.yaml` next to `out/`, with a mark that a tool made it. It contains these items:

* `repo`, `ref` and `commit`: the repository, the ref in `project.yaml`, and the full commit that the ref named;
* `oss_verifier`: the commit of this repository, and whether `tools/`, `infra/` or the project directory had changes;
* `builder`: the toolchain image of the builder ([Toolchains](#toolchains)), and the local ids of the builder and project images;
* `sources`: each git checkout under `$SRC` in the project image, with its commit;
* `builds` and `fuzz_targets`: what we built, with "each fuzz target" written as a list;
* `targets.<target>.builds.<build>`: the `file`, `bytes` and `sha256` of each binary, in the format of the `builds:` section of an oss-fuzz-theorems `harness.yaml`;
* `layout.<target>.<build>`: the `text_bytes` of each binary (the size of its `.text` section), and `static`, true for a binary with no `PT_INTERP` or `PT_DYNAMIC` program header; a value that `tools/check` cannot read is `null`;
* `rebuild`, only with `--twice`: the second build ([below](#reproducibility));
* only with `--checks`: `targets.<target>.builds.<build>.uninstrumented`, the code that the link took from the toolchain image, in the format of the `uninstrumented` list of a `harness.yaml` build (`name`, `kind`, and `sha256` for a file or `source` for an assembly or Fortran member; `kind` is `libc`, `compiler-rt`, `sanitizer-runtime`, `cxx-runtime`, `fortran-runtime`, `image-library`, `assembly` or `fortran`), and `binary_checks`: the model (`model`: release, repository and commit), the version of qemu (`qemu`), the inputs that each fuzz target ran on, and for each target and build the results of the four checks ([above](#the-checks-of-the-binaries)): `elf`, `system_calls` (with the calls the model does not cover, the exit status on each input, and the abort stance), `quiet_loud` and `instrumented`. Each has a `result` (`pass`, `fail`, `error`, `stale`, `not-run` or `plain`) and a `detail` that a person reads.

We will write the lock in the proofs repository from the manifest. The lock is the only place that records the commit. `tools/check --lock <file>` builds the commit that a lock names, and compares each binary with the lock ([below](#check-a-binary-against-a-lock)). The lock can be a manifest or an oss-fuzz-theorems `harness.yaml`.

Repeat `--lock` to compare with several locks. They must agree on the source commit and toolchain, and on the SHA-256 of any target and build that more than one lock pins. Conflicting pins stop the command before building. Identical pins and locks for different targets or builds can be combined.

If you run `tools/check` before you commit the project directory, the manifest says `modified: true` under `oss_verifier`. Commit first if you want a manifest that names exactly the commit you built. It does not change what we pin: we write the lock from our own build of the merged directory.

## Reproducibility

A statement is about the exact bytes of a binary, which the lock pins by their SHA-256. You can rebuild a binary and compare it with the lock only if each build gives the same bytes.

`tools/check --twice` builds everything a second time from the start, with `docker build --no-cache`, a new fetch and a new compile of each build. It fails if a byte is different. The Build check of a pull request runs `tools/check --twice` too.

After the comparison, `tools/check --twice` adds the `rebuild` block to the manifest. It also adds the block when the builds differ. The block contains these items:

* `kind: same-host`, the `host` and the time (`at`, in UTC) of the second build;
* `builder`, `builds` and `targets` of the second build, in the same format as at the top level of the manifest;
* `result`: `identical` if each binary has the bytes of the first build, or `differs`.

We pin only binaries that two clean builds reproduce. Thus we pin a binary only from a manifest whose `rebuild` block says `result: identical`. The second build uses the same toolchain. Its local image ids can differ from those of the first build, because Docker records the time of each build.

We found that these items decide the bytes:

* **The source paths.** An AddressSanitizer build records the path of each source file that it instruments. A file compiled at `/src/a/x.c` and at `/src/b/x.c` makes different binaries. The plain and UBSan builds do not depend on the path.
* **The order of the link.** The driver comes first and the seals come last. `$LIB_FUZZING_ENGINE` arranges this.
* **The layout of the archives.** OSS-Fuzz links the object of the fuzz target before the archives of the library. The release linked one archive that holds the library and the fuzz target. The two layouts can make different programs. A port that must match the release's bytes links as the release did.
* **Stripping at the link.** A strip after the link gives bytes that are different from `-Wl,--strip-all`.

## Check a binary against a lock

These steps rebuild a binary and compare it with its lock in the proofs repository.

> **WARNING:** `tools/check` builds the project's `Dockerfile` with network access, as `docker build` does. Use it only on a project that you trust ([SECURITY.md](../SECURITY.md)).

1. Get the project's lock from the proofs repository.
2. Check out this repository: at the commit that the lock gives in `oss_verifier.commit`, if it has that field; else at `main`. A `manifest.yaml` that `tools/check` wrote has the field. A `harness.yaml` of the oss-fuzz-theorems 2026.10 release, which each published lock is today, does not have it ([below](#check-a-binary-against-a-harnessyaml-lock)).
3. Run `tools/check --no-shell --lock <lock> <name>`. `<name>` is a project in `projects/`. For a project in `tools/seeds/`, give its directory: `tools/check --no-shell --lock <lock> tools/seeds/<name>`.
4. Read the last line of the output.

`tools/check` builds the commit that the lock names, with the toolchain that the lock names. It then compares the SHA-256 of each binary with the lock. It compares only the builds that `project.yaml` asks for ([sanitizers](project-yaml.md#sanitizers)), and a lock can pin more builds. For example, the lock of `avahi/fuzz-ini-file-parser` pins `plain`, `ubsan`, `asan` and `asan-ubsan`, and `tools/seeds/avahi` makes only `plain` and `ubsan`. `tools/check` does not compare a binary of a build that the project does not make.

* `matches the lock` tells you that each binary that the lock pins for these builds has the same bytes. The line gives their number.
* `DIFFERENT FROM THE LOCK` lists each binary of these builds that has different bytes, or that the build did not make.
* `THE LOCK PINS NONE OF THESE BUILDS` tells you that `tools/check` compared no binary.
* `BUILD FAILED` tells you that the build stopped before `tools/check` compared a binary.

### Check a binary against a harness.yaml lock

`tools/check` also accepts a `harness.yaml` of the oss-fuzz-theorems 2026.10 release as a lock. Use this to check a binary of that release. The locks published today are these files, and none of them has an `oss_verifier` field. Thus step 2 above uses a checkout of `main` with them:

    tools/check --no-shell --lock <proofs>/projects/cjson/cjson_read_fuzzer/harness.yaml cjson

`tools/check` can check the lock of a project that has a directory in this repository, in `projects/` or `tools/seeds/`. The release also has locks of projects that have no directory here. This repository has no build files for them.

If `tools/check` at `main` does not print `matches the lock` for a binary of the release, open an issue in this repository. Include the output of `tools/check`.

## Builds ported from oss-fuzz-theorems

We ported the build of each project that we seeded from the oss-fuzz-theorems 2026.10 release from the release's build recipe. Each port is three files next to `project.yaml`:

* `Dockerfile`: gets the project at `COMMIT` into `$SRC/upstream/<name>`, then runs `lay-out-sources` on `sources`.
* `sources`: tells where each source tree goes, as the release's source manifest tells. It names a copy of the checkout for each release target, and each other tree or file, pinned by commit or SHA-256. It also names the release's own files for a target, and its build patches. It is the only place that records the pin of a dependency. A `Dockerfile` never holds one.
* `build.sh`: for each fuzz target, the release's pin for it (its `build_lib`, `LIB_ARCHIVE` and helpers). [release-target.sh](../infra/base-builder/release-target.sh) runs each pin with the release's recipes ([recipes.sh](../infra/base-builder/recipes.sh)), under `sh -e`, as the release ran it.

`release-target.sh` gives each target the layout that the release built in:

* the tree of the target in `/work/ext/<target>/src`;
* its build directory in `/work/build/lib/<build>/<target>`;
* the release's files for it in `/work/targets/<target>`;
* compiler wrappers that give the compiler the neutral `/src/...` paths that a binary records.

The internal paths matter too. The source locations of the UBSan checks keep the internal path. In an `asan-ubsan` build, a header that uses `__FILE__` and holds a UBSan check thus makes one more string literal, which AddressSanitizer instruments. With the release's layout, a ported build makes the release's binaries again.

We checked each port with `tools/check --lock`, against each `harness.yaml` of the release for its fuzz targets. [tools/seeds/builds.tsv](../tools/seeds/builds.tsv) holds the result for each project, and [seeded-projects.tsv](seeded-projects.tsv) repeats it. A seeded project gets the port in `tools/seeds/<name>/` only if each binary is the release's.

## Build patches

`series` lists each patch that the build applies, one time each, in order. In a ported build, `lay-out-sources` applies each `patch` line of `sources`, and stops when those lines are not the patches that `series` lists, in the same order.

A patch of an enrolled project can only change how the project builds: static linking, cross-compilation, a version stamp or a generated file. A change that fixes a bug never goes in the directory of an enrolled project. We send it to the project as a patch, with its finding ([what-gets-proven.md](what-gets-proven.md#findings)). If a proof needed that patch, we publish the patch with the proof ([what-gets-proven.md](what-gets-proven.md#publishing)). The directory of a seeded project whose proofs we publish can also hold a patch that fixes a bug, once the finding of that bug is public. A proof can then be about the build with the fix. The facts list each such patch ([what-gets-proven.md](what-gets-proven.md#publishing)).
