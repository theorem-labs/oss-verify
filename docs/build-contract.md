# The build contract

This page tells what the builder gives a build, what a project's `Dockerfile` and `build.sh` must do, and how the driver runs a fuzz target. It is for the person who ports a project's build to OSS Verify, and for people who run our binaries.

The `Dockerfile` and `build.sh` follow the conventions of OSS-Fuzz, on our builder in place of OSS-Fuzz's base image. `oss-verify check` builds a project exactly as we do.

An OSS-Fuzz `Dockerfile` and `build.sh` do not run here without changes. They expect an x86-64 base image, apt packages, a native clang and often shared libraries. Our builder is a cross-compiler for static riscv64 Linux programs. Thus you must port each build. The port is usually short: the `cmake` or `configure` command, the compile and link commands of the fuzz targets, and the sources of the dependencies.

## The steps

`oss-verify check`, and our own builds, do these steps:

1. Make the builder image from [infra/base-builder/](../infra/base-builder/), from a toolchain image ([below](#toolchains)).
2. Build the project image from the project's `Dockerfile`, on the builder. `oss-verify check` gives the build arguments `COMMIT` (the full commit that `repo#ref` names), `REPO` and `BASE_BUILDER`. Only this step has network access.
3. Run `compile` in a new container of the project image, with no network (`docker run --network=none`). Do this once for each build that `project.yaml` asks for: `plain`, `ubsan`, `asan` and `asan-ubsan`. `compile` sets the compilers and flags of the build and runs `$SRC/build.sh`. A project with `programs` has the `plain` build alone, and `compile` runs its `build.sh` in the toolchain image's own environment ([below](#whole-programs)).
4. Find the fuzz targets in the `$OUT` of each build. Copy each binary to `out/<target>/<target>.<build>`. For a project with `programs`, take each program that `project.yaml` lists from `$OUT`, as the build wrote it, and copy it to `out/<name>/<name>` ([below](#whole-programs)). Write the manifest, with the SHA-256 of each binary. `oss-verify check` lists each binary with its size, the size of its `.text` section, `static` or `dynamic`, and its SHA-256. With `--summary <file>`, it also writes this list as a Markdown table; the Build check of a pull request shows that table. A binary with a `PT_INTERP` or `PT_DYNAMIC` program header is dynamically linked. `oss-verify check` refuses a dynamically linked binary, and one whose program headers it cannot read, with exit status 2, the status for a project that breaks the enrollment rules. Then it compares each program with the SHA-256 that `project.yaml` pins: a program with other bytes makes the exit status 3. Size is not a rule: a binary of any size passes. Because of our capacity, we are most likely to respond quickly to a project in C whose plain binaries have less than 1 MB of code: the larger of their `.text` section and their executable segments, which can hold read-only data too ([README](../README.md#who-can-enroll)).

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

* [infra/toolchains.tsv](../infra/toolchains.tsv) lists the published toolchain images, oldest first, and the languages that each one builds ([project-yaml.md](project-yaml.md#language)). Today it lists five images: the C and C++ image above, the Rust, Python and Go toolchains of the same release, and the Python toolchain with the prebuilt CPython runtime ([below](#the-prebuilt-cpython-runtime)), which is the newest row for `python` and so the image that a Python project is built with. We add a new image only after its publication. Outside `projects/`, no other file names the digest of a toolchain image.
* The builder gets the toolchain image as a build argument (`--build-arg TOOLCHAIN=<image>`). Its `Dockerfile` has no default, so a build without the argument fails.
* `uv run oss-verify check --lock` builds with the toolchain that the lock names. For a manifest, this is `builder.toolchain`. For a `harness.yaml` of oss-fuzz-theorems, it is the `build.builder` field of the `project.yaml` two directories above.
* If you give more than one lock, the locks must name the same toolchain.
* Without a lock, `oss-verify check` builds with the newest toolchain for the project's language: the last row that lists it. `--toolchain <image>` overrides the lock and the newest toolchain.
* The lock of a project pins its vintage. A project with published proofs stays on the toolchain that its lock names, so its binaries keep their bytes. A project with no lock, for example a seeded project in `seeds/`, uses the newest toolchain.

We check builds ported from oss-fuzz-theorems against the release's binaries, on the release's toolchain. Their `harness.yaml` locks name it.

### Frame pointers

The release's toolchain images build without frame pointers, so many functions use the register `s0` for data. AddressSanitizer's fast unwinder follows the frame records in `s0` when it stores the stack of an allocation. In such a function, it can read data as a frame record. Thus a stored trace is not always a call chain.

A toolchain image with frame pointers is a toolchain image whose configuration sets the environment variable `OFT_FRAME_POINTERS=1`. On such an image, the builder adds these flags:

* For C and C++, [toolchain.sh](../infra/base-builder/toolchain.sh) adds `-fno-omit-frame-pointer` to the common flags ([below](#the-builds)). Thus the library, the fuzz target, the driver and the C code of a Rust or Python build get this flag.
* For Rust, [rust/recipes.sh](../infra/base-builder/rust/recipes.sh) gives rustc `-Cforce-frame-pointers=yes` ([below](#rust-fuzz-targets)). The build compiles the standard library from source with the same flags (`-Zbuild-std`), so the standard library gets this flag too.

With an empty or unset value, the builder adds neither flag, so a build keeps the release's flags. With any other value, `toolchain.sh` stops the build. The rule is that only the toolchain image gives this setting. Thus `oss-verify validate` refuses a `Dockerfile` or `build.sh` beside `project.yaml` that names `OFT_FRAME_POINTERS` ([project-yaml.md](project-yaml.md#rules-for-each-file)).

[.github/workflows/toolchain-images.yaml](../.github/workflows/toolchain-images.yaml) makes each toolchain image with frame pointers from a base row of [infra/toolchains.tsv](../infra/toolchains.tsv): the C and C++, the Rust or the Python row. It takes the image of that row, the base image, and adds only `OFT_FRAME_POINTERS=1` to its configuration (`crane mutate`). Thus the new image has the layers of the base image, and each file of it has the same bytes. The workflow checks this. It also builds probe programs on a builder made from each of the two images, and checks their frame records ([probe](../.github/scripts/frame-pointers/probe)). After a push to main whose run of that workflow passed, [.github/workflows/toolchain-images-publish.yaml](../.github/workflows/toolchain-images-publish.yaml) puts the three images on ghcr.io, all in one package: `ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain`, the package of the C and C++ base image. The tag of each image names the language of its base row: `frame-pointers-<commit>` for the C and C++ row, `frame-pointers-rust-<commit>` for the Rust row and `frame-pointers-python-<commit>` for the Python row. `<commit>` is the commit that the run of that workflow built.

In infra/toolchains.tsv, the row of a toolchain image with frame pointers has the name `<base row>-frame-pointers`. Its image is in that one package for each base row, the Rust and the Python row too, and has the tag of the language of its base row. The row names the image in that package by its digest, as each row of the file names its image.

On a toolchain image with frame pointers, the code that the link takes from the toolchain image has the same bytes as in the base image. This code is the C library, compiler-rt, the C++ library, the AddressSanitizer runtime and the other libraries of the sysroot. Thus it keeps the frame records that it has in the base image, and it gets no new ones.

A calling function has a `jal` or a `jalr` that writes `ra`. A calling function keeps a frame record when an `addi s0, sp, N` comes before its first call. In the base image of the row `oss-fuzz-theorems-2026.10`, the probes of the workflow counted these functions:

* the C library, `/opt/musl-sysroot/usr/lib/libc.a`: 9 of 1,153 calling functions keep a frame record;
* the C++ library, `/opt/musl-sysroot/usr/lib/libc++.a`: 5 of 1,853 calling functions keep a frame record;
* the AddressSanitizer runtime, `libclang_rt.asan.a`: 542 of 1,653 calling functions keep a frame record in `/opt/asan-static-rt`, and 542 of 1,654 in the archive of the same name in `/opt/asan-rt`.

To count them, do these steps in the root of this repository:

1. Build the builder from the base image: `docker build --build-arg TOOLCHAIN=<image> -t <tag> infra/base-builder`. `<image>` is the image of the row `oss-fuzz-theorems-2026.10` in [infra/toolchains.tsv](../infra/toolchains.tsv).
2. Run `docker run --rm --network=none --entrypoint python3 -v "$PWD/.github/scripts/frame-pointers:/fp:ro" <tag> /fp/frames.py count <archive>…`. Each `<archive>` is a path in the builder, for example `/opt/musl-sysroot/usr/lib/libc.a`.

The builder does not hold `frames.py`, so step 2 mounts it from this repository. The `make` job does these steps after it makes the image, and prints the count of each archive again on each run.

### The prebuilt CPython runtime

Each build of a Python project compiles CPython with the compiler and flags of that build, as a library: the runtime ([python/runtime.sh](../infra/base-builder/python/runtime.sh)). On one toolchain image, the runtime of a build has the same bytes in each Python project, and its compilation is most of the time of the four builds. Thus a toolchain image that is derived from a Python toolchain image can hold the runtime of each of the four builds, compiled one time.

The runtime is addressed by its inputs, and its build reads no other input. The build compiles the runtime in an environment of its own (`oft_py_hermetic`), the same where the derived image is made and in a build of a project:

* no environment variable but six of the build's (`CC`, `CXX`, `CFLAGS`, `PKG_CONFIG_LIBDIR`, `PKG_CONFIG_PATH` and `SOURCE_DATE_EPOCH`) and these: `PATH` (the compiler shims in `/tmp/shim`, then `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`), `HOME` and `TMPDIR` in the new build directory of the runtime, `CONFIG_SITE` empty, `PYTHONNOUSERSITE=1` and `PYTHONDONTWRITEBYTECODE=1`;
* the build directory of the runtime as the working directory, and a shell that reads `runtime.sh` again;
* in a build that runs as root, the user `nobody`, who owns the build directory and, while it builds, the records directory of `compile`, and can write no other file of the image. The patched source tree is read-only to it, and the build fails if that tree changed;
* a read boundary (`oft_py_boundary`): while the runtime builds, each path that the key leaves out (below) goes to root with no access for its group and others, but what the build needs there (the patched source tree, through `/src/repo`, its build directory, the records directory, `runtime.sh` and `record-compile`) and the paths that it leaves open: the kernel's (`/proc`, `/sys`, `/dev`), which the build reads as every program does, and what the host mounts (`/out`, `/ov-base-layout`, Docker's init), whose mode the container must not change. Those are what Nix's sandbox, too, gives a build. So the build cannot read a closed file even when a value that it gets, such as `CFLAGS`, names it; and it takes no input from the open paths, since the key holds every name that it gets, and none of the shipped build's names is under them. Before it gives the paths back, the boundary stops each process of `nobody` in the build's container, where nothing else runs as that user. It reaches each path from `/` one directory at a time, follows no link, enters no mount point under a grant and refuses a grant that is one; it gives back each path that it can, and the build fails, naming each path that is not as it was. A mount namespace, as Nix's sandbox uses, would hide those paths instead, but a build's container may not make one (`unshare -m` fails there with "Operation not permitted");
* `-I` on each run of the native Python, but where CPython's `make` runs it for the cross build, with `PYTHONPATH`, which `-I` would ignore.

Before a build compiles the runtime, it computes the inputs, one on each line (`oft_py_runtime_inputs`):

* the build, the arguments of `configure` (`CC` and `CFLAGS` too), and the targets of `make`;
* that environment, and the user;
* the SHA-256 of the CPython tarball, the patches, `Setup.local`, the native Python, and the scripts that the build of the runtime runs, or that write what it reads: `runtime.sh`, `patches/apply.py`, `release-target.sh`, `toolchain.sh`, `compile` and `record-compile`;
* the SHA-256 of the package database;
* the mode and owner of each file of those lines, of each directory above them, above the patched source tree and `/src/repo`, and of `/` and the directories that the tree lines split; and of each compiler shim, the read and run bits of the file that the build runs and of the file that holds its text (`oft_py_runtime_inputs`'s `meta` lines): what `nobody` may read, run and reach;
* each path that the key leaves out, one `excluded` line each: the paths that the read boundary leaves open (`/proc`, `/sys`, `/dev`, `/out`, `/ov-base-layout`, `/sbin/docker-init`); what Docker writes in each container (`/run`, `/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`, `/.dockerenv`); the scratch of `compile` in `/tmp/ov`, the project's sources in `/src`, the build's own `/work`, caches (`/root/.cache`, `/var/tmp`, `/var/cache`), the shipped runtimes, the builder's scripts in `/usr/local/lib/oss-verify`, the Java keystore (each build of the builder writes it anew, with random salts), and the install prefix of each target in `/opt/oft`. `runtime.sh` gives the reason for each (`oft_py_fs_left_out`). The read boundary closes them all to the build but the open ones;
* what the build does read under those paths, each on its own line: the four compiler shims that `release-target.sh` writes in `/tmp/shim`, as `shim <name> as release-target.sh writes it, for no target <SHA-256>` when each is the text that `release-target.sh` writes for the layout of the build's own targets in `build/lib/<flav>`, all with plain names (letters, digits and `. _ + -`), behind the front of `record-compile` with `--checks`, with the SHA-256 of the text that it writes for a layout of no target: all that the shim's text depends on but the targets' names, whose path pairs the build of the runtime never meets (`OV_PATH_REWRITE=off`, set unexported in a target's block, changes it); a shim of any other text, or of a target whose name is not plain, by its own SHA-256; and the link `/src/repo`, through which the build reads its source tree;
* the SHA-256 of the content of the patched CPython source tree, of each entry of `/`, and of `/usr`, `/opt`, `/var` and `/tmp` (the rest of `/tmp/shim`, the sealed AddressSanitizer configuration and its wrap list among them), but those paths: the path, the type, the bytes of each file or the target of each link, and the mode and owner of each entry but a link, which decide what `nobody` may read and run, not its time; then of what each link of those leads to under a path left out (a link of `/usr/bin` to a tool under `/work`, say), but into the container's own paths and the Java keystore, which only Java reads, through its link too. A project whose `Dockerfile` changes any other file compiles its own runtime. The native Python hashes the files in a process pool, with one process for each processor that the build may run on.

The key is the SHA-256 of these lines. Each build of a Python project computes its key, on each toolchain image, and writes it with the time that it took:

    oft-py: runtime <flav>: key <the first 12 hex digits of the key> in <seconds> s

The key reads `runtime.sh`, `release-target.sh` and the other scripts by their bytes, and assumes that the build runs their functions as those files define them where the key runs them (`oft_py_configure`, and the layout's functions of `release-target.sh`): a `build.sh` that defines one of them again, after it sources them, is not seen. The build of the runtime itself runs in a shell that reads `runtime.sh` again.

The derived image holds the runtime of each build in `/opt/oft-py/prebuilt/<flav>-<key>/`: the files of the runtime, the compile records of its build, and its manifest. The manifest has the lines, the key, and the digest of the toolchain image that the runtime was made from. A build takes the runtime only when the directory of its own key is there and the lines of its manifest are the lines of the build. Then the build writes:

    oft-py: runtime <flav>: took the shipped runtime (/opt/oft-py/prebuilt/<flav>-<key>); ran no CPython configure or make

With `--checks`, the build also takes the compile records of the runtime. Thus the checks of the binaries get the same records as when the build compiles the runtime ([below](#the-checks-of-the-binaries)). In all other cases, the build compiles its runtime in the same environment, with the same commands. Before it does, it writes one line: the inputs cannot be read, the toolchain image ships no runtime, or the first input where the shipped runtime and the build differ. For example, a project whose `Dockerfile` installs a package, or sets `PKG_CONFIG_PATH`, compiles its own runtime; one that sets another environment variable takes the shipped runtime, since the build of the runtime does not see that variable.

[.github/scripts/python-runtime/make](../.github/scripts/python-runtime/make) makes the derived image. It compiles the four runtimes in the builder of the toolchain image, and adds them to the toolchain image in one layer. [.github/workflows/toolchain-images.yaml](../.github/workflows/toolchain-images.yaml) makes the derived image of the Python row and of its frame-pointer image, and [.github/workflows/toolchain-images-publish.yaml](../.github/workflows/toolchain-images-publish.yaml) publishes them after a push to main. The row `oss-fuzz-theorems-2026.10-python-prebuilt` names the derived image of the Python row, so a Python project is built with it, and each build takes the runtime that it ships for the build's own key. The derived image of the frame-pointer image is published too, and no row names it, as no row names a frame-pointer image yet.

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
| `$LIB_DSL_ENGINE` | the driver of a DSL fuzz target, whose program is a script that the payload holds ([below](#dsl-fuzz-targets)) |
| `$SANITIZER` | `none`, `undefined`, `address` or `address-undefined` |
| `$ARCHITECTURE`, `$FUZZING_ENGINE` | `riscv64`; `none`, the OSS-Fuzz name for a driver that runs inputs from files |
| `$CMAKE_TOOLCHAIN_FILE` | a CMake toolchain file for this build. CMake 3.21 and later find it without help. |
| `$AR`, `$NM`, `$RANLIB`, `$STRIP`, `$OBJCOPY` | the LLVM tools, as `riscv64-linux-musl-ar` and the other names, which are also on `PATH` |
| `<fuzzer/FuzzedDataProvider.h>` | on the include path of `$CC` and `$CXX`, as in OSS-Fuzz |
| `$SOURCE_DATE_EPOCH` | `1756684800`, for each tool that writes a date |

`compile` runs `build.sh` with `bash -eux`, from the `WORKDIR` of the `Dockerfile`. The `build.sh` of a Go project gets the environment that OSS-Fuzz gives a Go project instead ([go/compile-go](../infra/base-builder/go/compile-go)). The `build.sh` of a project with `programs` gets the toolchain image's own environment instead ([below](#the-environment-of-a-programs-build)).

## The builds

These are the common compile flags:

    -march=rv64g -mabi=lp64d -Os -g -ffunction-sections -fdata-sections -fno-stack-protector -Wdate-time
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-reallocarray -fno-builtin-free
    -fno-builtin-aligned_alloc -fno-builtin-posix_memalign -fno-builtin-memalign -fno-builtin-valloc
    -fno-builtin-strdup -fno-builtin-strndup

The `-fno-builtin-*` flags keep each allocation an ordinary call in all four builds. Thus the optimizer cannot remove or merge an allocation in one build and keep it in a different build.

On a toolchain image with frame pointers, the common flags also have `-fno-omit-frame-pointer` ([Frame pointers](#frame-pointers)).

`compile` builds the driver with these flags and `-fno-plt`. clang does not use `-fno-plt` for this target. Thus each C, C++, Rust and Python build writes `warning: argument unused during compilation: '-fno-plt'` 12 times, before `build.sh` starts. You can ignore this warning. `$CFLAGS` does not have `-fno-plt`.

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

With today's toolchain vintage, these flags are fixed, so that the ported builds make the release's binaries again. With the next toolchain version, a list replaces them: the checks that OSS-Fuzz makes fatal for the project's language, with `strict-flex-arrays`, changed by the project's `ubsan_checks` ([project-yaml.md](project-yaml.md#ubsan_checks)). `oss-verify check` then gives `compile` the checks, and `compile` builds the library and the fuzz targets with `-fsanitize=<checks> -fsanitize-trap=<checks>`. As in OSS-Fuzz, the C files of a `c++` project are compiled without `function`. In the `ubsan` build, `vptr` is compiled with `-fsanitize=vptr -fno-sanitize-link-runtime`, the links get the toolchain image's trap-only handler, and a compile with `-fno-rtti` gets `-fno-sanitize=vptr`; the `asan-ubsan` build leaves `vptr` out. `libcxx-hardening` compiles and links the `ubsan` build's C++ with `/opt/asan-static/musl-hardened.cfg`. `strict-flex-arrays` adds `-fstrict-flex-arrays=1` to both UBSan builds, so that `array-bounds` checks an index into a struct's trailing array whose declared size is 2 or more; a trailing `[1]`, `[0]` or `[]` stays unchecked. The driver never gets these flags. The `ubsan` column of `infra/toolchains.tsv` tells which way each toolchain image works: `fixed` or `checks`.

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

Start from [templates/Dockerfile](../templates/Dockerfile). Two builds written by hand are small examples. [projects/cjson/](../projects/cjson/) builds cJSON's own fuzz target with CMake; its `Dockerfile` also copies the checkout to the path where the oss-fuzz-theorems release built it and makes that copy the `WORKDIR`, and its `build.sh` builds that copy, which only a build that must match the release's bytes needs. Make such a copy in the `Dockerfile`, not in `build.sh`: a file that `build.sh` makes exists only in the container of that build, so a compile command that names it cannot run again in a new container of the project image. Make it the `WORKDIR` too, because a breakage patch of `uv run oss-verify check --checks` changes the files under the `WORKDIR` ([below](#the-checks-of-a-fuzz-target)). [tests/fixtures/example/](../tests/fixtures/example/) is a test project, whose `Dockerfile` takes the source from the build context, as a `Dockerfile` in your repository does, and whose `fuzz/` subdirectory a project directory cannot have. Obey these rules:

1. Start with `FROM ${BASE_BUILDER}`, after `ARG BASE_BUILDER=oss-verify-base-builder`. `oss-verify check` gives the builder that it made.
2. Declare `ARG REPO` and `ARG COMMIT`.
3. Get the source at exactly that commit: `RUN fetch-commit $SRC/<name>`. Add `--submodules` if the repository has submodules.
4. Do not write a commit id in the `Dockerfile`. `oss-verify check` gives the commit, and the lock records it.
5. Get each dependency at a fixed version.
6. Copy `build.sh`, your fuzz target sources and your build patches to `$SRC`. Apply the build patches in the order that `series` gives.

`build.sh` builds the dependencies that a sanitizer build must instrument, with the flags of each build. The libraries of the sysroot are linked as they are, with no instrumentation. `oss-verify check` records the commit of each git checkout under `$SRC` in its manifest.

If the `Dockerfile` is in the project's repository (`dockerfile` in `project.yaml`), the build context is that repository at the commit that we build. Use `COPY . $SRC/<name>` to get the source.

## A private library

A library of ours whose repository is private is fetched with a credential; every other library is fetched with none. The list of such libraries is [infra/private-libraries.tsv](../infra/private-libraries.tsv), one repository a row, and a row there is the only thing that makes a build ask for a token. There is no rule about an account: authenticating everything under one owner would make every public build depend on a token service being up, for the sake of the few repositories in that file.

For a listed library, `oss-verify check` mints one token for that build: read-only (`contents` and `metadata`), narrowed to that one repository, and short-lived. It comes from [infra/github-read-token](../infra/github-read-token), or from the command in `OSS_VERIFY_GIT_TOKEN_COMMAND`, which is run with `<owner> <repo>` and must print the token on standard output. A build host with neither mints nothing, and the build fails saying so. The enrollment workflow has no token command and must never be given one: it builds code from anyone.

The project's `Dockerfile` mounts the token on its fetch step, in place of rule 3 above:

    ARG REPO
    ARG COMMIT
    RUN --mount=type=secret,id=oss-verify-git-token fetch-commit $SRC/<name>

`oss-verify check` refuses a build whose `Dockerfile` and whose library disagree: a listed library whose fetch step does not mount the secret (it would fetch with no credential and fail as an unauthorised one), and a library that is not listed whose `Dockerfile` mounts it (a project asking a build for a credential it is not meant to have). BuildKit gives such a `RUN` an empty mount and says nothing, so neither mistake shows itself. The `Dockerfile` is parsed rather than searched: a mention in a comment is not a mount, a mount on another step is not a mount on the fetch, an id that merely begins with ours is another secret, and a mount whose fields are reordered or whose line is continued is still a mount.

Where the token is while the build runs, and nowhere else:

* It goes to `docker build` as `--secret id=oss-verify-git-token,env=…`, read out of the environment of `oss-verify check` itself. A **build argument** would be in `docker history`; a secret is not, and `docker build` writes nothing of it into the image.
* Inside the build it is a **tmpfs file** that exists only while the `RUN` step that mounts it runs. It is in no layer.
* `git` reads it through the credential helper [git-credential-oss-verify](../infra/base-builder/git-credential-oss-verify), which answers for **that one repository**: `git` asks a helper for every server it reaches, and `git submodule update --recursive` reaches whatever servers the tree names, so a helper that answered all of them would hand the token to a third party. A token in the URL would be written into `.git/config`, which is a layer, and printed by `git remote -v`; a token in `-c http.extraHeader` would be in a command line, which every other process on the host can read. A helper's answer goes down a pipe to `git`.
* The remote in the checkout is `REPO` as `project.yaml` gives it. Nothing about the fetch reaches `manifest.yaml`: `commit` is the commit that was fetched, as for every other library.
* Everything `git` writes, on both of its streams, goes through a filter that replaces the token, in the container ([fetch-commit](../infra/base-builder/fetch-commit)) and on the host ([src/oss_verify/check_build.py](../src/oss_verify/check_build.py)). What `git` writes when a fetch fails is the one message this repository does not author.
* `git`'s own tracing is turned off for the fetch and `GIT_TRACE_REDACT` is forced on, whatever the caller set: `GIT_TRACE_CURL` with `GIT_TRACE_REDACT=0` writes the `Authorization` header into a file that outlives the build.

**What this does not close**, stated rather than claimed away:

* The token is in the **environment** of the `git` and `docker build` processes `oss-verify check` starts, so `/proc/<pid>/environ` holds it for as long as they run, for the account that owns them and for root. An environment is the narrowest place that is not a file; a file in the build's own filesystem would be a layer.
* A **core dump** of one of those processes, or of `git` inside the build, can hold it. Nothing here disables core dumps.
* The mount is a file in the `RUN` step that asks for it, so **other code in that same `RUN`** can copy it. BuildKit does not prevent that, and for a private library of ours the `Dockerfile` is ours.
* `gh-app-token`, which [infra/github-read-token](../infra/github-read-token) asks, writes the token it mints into its own mode-0600 cache file on the build host. Every build mints its own (that file says how, and names the one assumption: the host's clock), and the entry dies with the token in an hour.
* `OSS_VERIFY_GIT_TOKEN_COMMAND` replaces that command, and **nothing checks what a replacement prints**: freshness, repository scope and read-only are obligations of whoever sets it, not properties `oss-verify check` can establish from one line of output.
* **A redirect on the same origin keeps the credential.** The helper answers for one repository, and a request for another path is refused — but once a request has been authenticated, libcurl sends its `Authorization` header on to a redirect of the same origin without asking a helper again. A review drove that with a real server. What limits the damage is the token itself: it may read one repository and nothing else.
* **The guard reads the ordinary spellings, not every one.** The exec form with unusual spacing, and a mount whose id comes from a source other than an `ARG` or `ENV` of the same `Dockerfile`, are read as no mount. Where the guard is wrong it is mostly wrong by refusing — a build that does not start — but not always: a spelling it cannot read can also leave a fetch step unnoticed, and that fetch then goes out with no credential and fails saying so. Neither puts the token anywhere. What it does read is in the tests, scored against real BuildKit builds.
* **The fetch must be its own step.** The guard reads the command of each `RUN`, and refuses a private library whose fetch it cannot read: inside a heredoc body, behind `sh -c "…"` or another command that runs a command, or in an instruction with an unmatched quote. Those are valid `Dockerfile`s, and BuildKit may well mount the secret on them — but whether it mounts it on *that* fetch cannot be read from the instruction, and a review measured five files of those shapes whose real fetch ran with no credential while the guard said they were fine. This is a restriction on how a private library writes its fetch, not a claim about what BuildKit does.
* A server that **lists a repository's refs** has said the build may read it. It has not said that `upload-pack` works or that the objects will arrive, so a fetch that fails after a successful listing is reported as exactly that, and not as a missing commit.

A fetch that fails says which of **three** things went wrong, where before the first two were one message:

* **Not authorised.** The server answered, and would not list the repository's refs, so the commit was never looked up. GitHub answers a private repository you may not read exactly as it answers one that is not there, so the message names both and does not guess.
* **No such commit.** The server listed the refs **and sent the whole repository**, so the build may read it and the transfer worked; the commit is not in it. In the container that conclusion is drawn only after a clone that succeeded. On the host there is no second attempt to draw it from, so the host says the two possibilities it really has — the commit is absent, or the objects did not come — and leaves git's own message for the fetch above it.
* **Could not be reached.** The server did not answer either way: no route, a refused connection, a rate limit, a server fault. This is neither of the other two, and saying it was one of them would be the same bug in a new place. What `git` said comes with each message.

Which of the three it was is decided by **the HTTP status first, and the words of the message only when there is no status**: 401, 403 and 404 are a refusal and every other status is the server failing. The status taken is the **last** one in the message, which is git's own: a body can say `upstream connection permission denied`, `repository not found`, or even quote the status of an earlier request, and all three were measured. A body does not outrank a status. The same rule is written twice, in [src/oss_verify/check_build.py](../src/oss_verify/check_build.py) for the host and in [fetch-commit](../infra/base-builder/fetch-commit) for the container, and a test gives both the same messages and fails if they disagree — the two were once corrected one at a time, which is how the container kept a defect the host had lost.

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

With `OV_BASE_LAYOUT`, `link-fuzz-target` can make the link of a development build, which keeps the address of each function whose code did not change ([below](#a-development-build-that-keeps-addresses)). With no `OV_BASE_LAYOUT`, or with no entry in it for the link, the link is the one above, with the same commands and the same arguments in the same order.

## The settings of one fuzz target

A build can give one fuzz target three settings. Each setting is an environment variable:

| variable | value | what it changes |
|---|---|---|
| `OV_MAX_INPUT_LOG2` | `27` to `31` | the input limit of the driver |
| `OV_LIBC` | the absolute path of a `libc.a` | the C library that the link takes |
| `OV_PATH_REWRITE` | `off` | the source paths that the compiler gets in a ported build |

A build that sets none of them makes the links, the compiler wrappers and the binaries that the rest of this page describes, byte for byte.

A ported build ([below](#builds-ported-from-oss-fuzz-theorems)) builds each fuzz target in a subshell of its own: the block of that fuzz target. Give a setting in the block, so that it applies to that fuzz target only:

    (
    OV_PATH_REWRITE=off                            # before ov_target_begin
    ov_target_begin <target> [<dependency> ...]
    <the release's pin for the target: build_lib, LIB_ARCHIVE and its other variables>
    export OV_MAX_INPUT_LOG2=29                    # before ov_target_build
    export OV_LIBC="$LIBROOT/$T.libc/lib/libc.a"   # before ov_target_build
    ov_target_build <fuzz target>
    )

The path rewrite has one exception ([below](#the-path-rewrite)).

`link-fuzz-target` reads `OV_MAX_INPUT_LOG2` and `OV_LIBC` from its environment, so export them. `ov_target_begin` reads `OV_PATH_REWRITE` in the shell of the block, so an assignment is sufficient. The tools read the environment. Thus an `ENV` line of the `Dockerfile` sets a variable for each block and each link. In the build files of the project's source, an `export` in a shell script sets it for each link after it, and an `export` line in a `Makefile` sets it for each recipe of that `make` run, wherever the line is. The report of the checks names each C library that a build declares, whatever sets it ([below](#the-c-library)).

For a link that `build.sh` makes itself, you can give `OV_MAX_INPUT_LOG2` or `OV_LIBC` on that one command:

    OV_MAX_INPUT_LOG2=29 $CC $CFLAGS "$WORK/example_fuzzer.o" -o "$OUT/example_fuzzer" $LIB_FUZZING_ENGINE libexample.a

Outside the blocks, a setting applies to each later block, and an `export` reaches each later link. Thus in a `build.sh` with no blocks, as an OSS-Fuzz `build.sh` is, an `export` at the top level applies to each fuzz target that `build.sh` links after it.

Only a link that goes to `link-fuzz-target` reads `OV_MAX_INPUT_LOG2` and `OV_LIBC` ([above](#how-a-fuzz-target-is-linked)). A link that names none of `$LIB_FUZZING_ENGINE`, `$LIB_ALLOCATION_FAILURE_ENGINE`, `$LIB_ALLOCATION_COUNTING_ENGINE` and `$LIB_DSL_ENGINE` ignores them.

### The input limit

With `OV_MAX_INPUT_LOG2=<k>`, the driver refuses an input of 2^k bytes or more, with status 2 ([below](#exit-statuses)). Without the variable, the limit is 64 MiB, which is 2^26 bytes. The values 27, 28, 29, 30 and 31 give the limits 128 MiB, 256 MiB, 512 MiB, 1 GiB and 2 GiB. Any other value, the empty one too, stops the link.

The limit applies to each form of the driver: with `adapter.c`, with a recipe's own adapter, the allocation-failure and counting forms, and the quiet form of the quiet twin ([below](#the-checks-of-the-binaries)). Before `build.sh` runs, `compile` compiles `cli.c` again for each value, with the flags of `cli.o` and `-DOV_MAX_INPUT_LOG2=<k>`. This gives `/tmp/ov/cli-limit<k>.o`. When `compile` records the links (`--checks`, `--layout-out`), it also gives `/tmp/ov/cli-limit<k>-quiet.o`, for the quiet twin. `link-fuzz-target` then links `cli-limit<k>.o` in place of `cli.o`, in each link of the fuzz target and in its record.

The limit is a power of two because of how the driver reads. The driver reads the input into a buffer that starts at 64 KiB and doubles. It compares the size of the buffer with the limit only when the buffer is full. Thus a limit between two powers of two would act as the next power of two above it. The largest value is 31, because the driver keeps the limit in a 32-bit unsigned number.

### The C library

With `OV_LIBC=<path>`, the link of the fuzz target takes a C library that the build makes, in place of the toolchain image's musl. `<path>` is the absolute path of a file named `libc.a`, which must be an `ar` archive. The start files `crt1.o`, `crti.o` and `crtn.o` must be beside it, each an ELF file. musl's `make install` installs the four files in this way. Any other value, the empty one too, stops the link. A control character, such as a tab or a newline, in the real path of one of the four files would split the rows of the record's `libc` file (below), so it stops the link. A control character in the value stops the link too.

`link-fuzz-target` makes a directory in `/tmp/ov`, with a symbolic link to each of the four files. Before the driver, it gives the compiler `-B<directory>/` and `-L<directory>`. clang then takes the start files from that directory. It also finds `libc.a` there before its own library directories, at the place in the link where it found the image's `libc.a`. Each link of the fuzz target gets these two options: the output, the stripped twin, the quiet twin and the links of the append mode ([below](#what-the-append-mode-does)).

When `compile` records the links, the record of the link holds one more file, `libc`: the name, the real path and the SHA-256 of each of the four files. Check 4 of [the checks of the binaries](#the-checks-of-the-binaries) reads it:

* The list `uninstrumented` names each file of the declared C library whose code is in the binary, with the kind `libc` and its SHA-256, as it names the files of the toolchain image. `libc.a` and `crt1.o` always have code in the binary. `crti.o` or `crtn.o` has code in the binary only when its source has code: musl's `crti.o` and `crtn.o` for riscv64 are built from empty sources, so with musl the list names neither.
* The list is in path order. Thus a C library under `/work` comes after the files of the toolchain image.
* No build examines a file of the declared C library as the project's code. A file at the declared path with other bytes is the project's code.
* The detail of each build names the declared C library and the SHA-256 of each of its files.
* The report of the checks ([below](#the-checks-of-the-binaries)) names each binary whose build declares a C library, whatever its results are, when the checks could read the record of its link. Its cell in the column "uninstrumented code" ends with "a declared C library". A list at the end of the report gives the path and the SHA-256 of each file of the C library, from the record's `libc` file. The enrollment review reads this report.
* In each build, the result is `error`, with no list, when the link did not take the declared `libc.a`. It is also `error`, with no list, when the link took a file of the toolchain image's C library: its `libc.a`, `crt1.o`, `crti.o` or `crtn.o`.

Build the C library outside `$BUILDDIR`, for example in `$LIBROOT/$T.libc/lib/`. In a block, `$LIBROOT` is `/work/build/lib/<build>`, where `<build>` is `plain`, `ubsan`, `asan`, or `asanubsan` for the `asan-ubsan` build. `$T` is the release target that `ov_target_begin` names, and `$BUILDDIR` is `$LIBROOT/$T` (`release-target.sh`). `oft_build_cmake`, `oft_build_autotools` and `oft_build_meson` end with `oft_merge_archives`, which merges the archives under `$BUILDDIR` into the archive of the target. The link would then take a `libc.a` under `$BUILDDIR` as the project's code.

The tools check the declaration and the files that the link took. They do not check where the C library comes from, or what code its four files hold. The enrollment review judges this rule in its check C5 ([review.md](../review.md)):

**The four files, `libc.a`, `crt1.o`, `crti.o` and `crtn.o`, hold only the C library's own code.** The block builds them with the C library's own build, from a release or a commit of the C library's own upstream project, not a fork and not a prebuilt file. Each patch of the C library changes only the C library's own code and adds none of the project's. No file, flag or object of the project goes into the C library's source tree, its build or its four files. These patches are not in `series` ([below](#build-patches)): each one is a file of the project directory whose name does not end in `.patch`, which a `copy` line of `sources` lays out and `build.sh` applies.

The rule holds, for example, when the block copies the laid-out source unchanged into a work directory, applies the patches, and runs the C library's own build and install (for musl, its `configure`, `make` and `make install`) with no file, flag or object of the project. The rule is broken when anything puts a file, a flag or code of the project into the C library's source tree, its build or its four files, whether by a patch, a copied file, a flag or a changed object, or when the four files come from somewhere other than the C library's own build of its upstream source, such as a fork or a prebuilt file.

### The path rewrite

In a ported build, the compiler wrappers that `release-target.sh` writes give the compiler neutral paths under `/src` ([below](#builds-ported-from-oss-fuzz-theorems)). `OV_PATH_REWRITE=off` disables this path rewrite. The compiler then gets each source path as the build gives it. A binary can record that path, for example through `__FILE__` or in an AddressSanitizer build ([below](#reproducibility)). With `off`, the wrappers:

* rewrite no source path under `/work` to its neutral name under `/src`
* do not make a relative source path that names `oft-vendor` absolute
* add no `-fmacro-prefix-map` option
* add no `-fdebug-prefix-map` option

They keep `-DOFT_RELEASE_BUILD=1`, their other words, and the `-march` pin, which changes each `-march=rv*` to `-march=rv64g`. `ov_target_begin` still makes the neutral names under `/src`, as symbolic links. When `compile` records the build, each compile still writes its record.

Set `OV_PATH_REWRITE=off` in the block, before `ov_target_begin`, which writes the wrappers. The dependencies that the block builds with `ov_target_dependency` use the same wrappers, so the setting applies to them too. With any other value, the empty one too, `ov_target_begin` stops the build. Only `release-target.sh` reads `OV_PATH_REWRITE`. A `build.sh` that does not source that file has no path rewrite to disable.

The wrappers are files in `/tmp/shim`, and they stay after the block ends. The `$CC` and `$CXX` of `compile` run these files in the `plain`, `asan` and `asan-ubsan` builds. They also run them in the `ubsan` build, unless the checks of that build name `vptr` or `libcxx-hardening`. Then `toolchain.sh` writes other wrappers for it ([toolchain.sh](../infra/base-builder/toolchain.sh)).

In those builds, a compile through `$CC` or `$CXX` that `build.sh` makes outside the blocks runs the wrappers of the last block that called `ov_target_begin`. After a block with `OV_PATH_REWRITE=off`, the compile gets no path rewrite. After a block without the setting, the compile gets the path rewrite of that block. Before the first block, it runs the wrappers of `toolchain.sh`, which rewrite no path. If such a compile must get a path rewrite, put it after a block that does not set `OV_PATH_REWRITE`.

In a `ubsan` build whose checks name `vptr` or `libcxx-hardening`, a compile outside the blocks never gets a path rewrite. `release-target.sh` does not write the other wrappers of that build.

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
* the file is at or above the input limit: 64 MiB, unless the fuzz target's build raises the limit ([above](#the-settings-of-one-fuzz-target));
* it gets no memory to read the file into.

A sanitizer detection writes nothing. AddressSanitizer aborts silently. UndefinedBehaviorSanitizer has no runtime and traps ([above](#the-builds)).

`tests/test_builder.py` checks each status in all four builds, on a C fuzz target and a C++ fuzz target. It also shows a special case: UndefinedBehaviorSanitizer does not check a `volatile` access for a null pointer. Thus a load through a `volatile` null pointer crashes with 139 in each build. A load through a pointer that is not `volatile` traps with 132 in the UBSan builds.

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

`tests/test_builder.py` checks the mask, counting mode and `std::bad_alloc` in all four builds, with each engine. It also builds cJSON's fuzz target with both engines ([tests/fixtures/cjson](../tests/fixtures/cjson/build.sh)). The test shows three results. The fuzz target keeps the release's bytes. An input that makes 21 allocations gets the same count in each build. If any one allocation fails, or all fail, the fuzz target still exits with 0.

## DSL fuzz targets

A DSL fuzz target is a driver of our own whose program is a script in the payload: a list of calls of the library's API, which the driver runs on live objects and whose results it prints. It defines no `LLVMFuzzerTestOneInput`. Its own C or C++ code, the driver objects, defines the four functions that `cli.c` calls (`target_name`, `target_alloc_init`, `target_alloc_count` and `target_run`, [target.h](../infra/base-builder/driver/target.h)), in place of `adapter.c`. The input has the format of [the driver](#the-driver), and the exit statuses are the driver's own: the status that `target_run` returns.

The driver makes the library's calls of chosen functions fail, as the input tells it to, through renames. A map is a file of pairs `<old> <new>`, one a line; `#` starts a comment. The link renames each call of `<old>` to `<new>` in copies of the library's archives, and the target's trampolines, objects compiled with no sanitizer as the driver is, define `<new>`. Two kinds of map:

* `OV_DSL_REDEFS`: renamed in the library and in the driver objects, for example the allocators, so that one schedule counts the allocations of both.
* `OV_DSL_LIBRARY_REDEFS`: renamed in the library alone, for example the system calls of its file functions, which the trampolines answer from a file in memory. A driver object that names either side of such a pair stops the link: the driver reaches what the map renames only through the trampolines' own functions.

A block declares the target in its environment, before `ov_target_build_dsl`:

| variable | value |
|---|---|
| `OV_DSL_DRIVER` | the driver objects (`ov_dsl_driver` adds one) |
| `OV_DSL_TRAMPOLINES` | the trampoline objects (`ov_dsl_trampoline` adds one) |
| `OV_DSL_REDEFS`, `OV_DSL_LIBRARY_REDEFS` | the maps: at least one, in either variable |
| `OV_DSL_ALLOW` | with a library map: the allow list of the census (below) |

Each is a list of absolute paths, separated by spaces.

    (
    ov_target_begin zlib-api-driver
    build_lib() {
      oft_build_cmake
      ov_dsl_driver dsl.c            # /work/targets/$T/dsl.c, with $CC, $CFLAGS and the library's include paths
      ov_dsl_trampoline alloc_tramp.c  # with $DRVCC $BASE_CFLAGS: no sanitizer, as cli.o
      oft_seal_getenv
      oft_seal_mkstemp
      oft_seal_getpid
    }
    LIB_ARCHIVE="lib/liboft.a"
    export OV_DSL_REDEFS="/work/targets/$T/alloc_tramp.redefs"
    ov_target_build_dsl api-driver
    )

`ov_dsl_driver` also compiles each driver object with `-DHARNESS_QUIET`, as `<name>-quiet.o`, for the quiet twin. `ov_target_build_dsl` links `$LIB_DSL_ENGINE`, the library's archive and `LIB_EXTRA`, through `link-fuzz-target`:

    <compiler> -static -no-pie -Wl,--gc-sections cli.o <driver objects' copies> [<silent reports>] <the link's own arguments, the library's archives as copies> <trampolines> <seals>

The link takes the library's archives and object files by name: it refuses `-l`, every `-Wl,` option but the seals' `-Wl,--wrap=<name>` (getenv, getpid, getppid, mkstemp, mkostemp, mkstemps and mkostemps, none of which a map may name), `-Xlinker`, response files, configuration files, source files and LLVM bitcode, which could hide a call from the renames ([dsl.py](../infra/base-builder/dsl.py)). A wrap of any other name could send the library's calls past the trampolines, and the trace below would not show it: the linker writes its `-y` trace before it applies `--wrap`. The library is each archive that the link names outside the toolchain image's `/opt`. Before it links, `dsl.py` stops the link when:

* a map has a malformed line or no pair, or the maps rename one name twice, give two names one new name, or name one name as old and new;
* the library defines an old name itself, or the library or a driver object names a new name already;
* a pair does not move every reference from the old name to the new one in a copy, or a copy has another number of undefined symbols (conservation);
* a map renames no reference at all: a schedule over nothing;
* with a library map, a name that the library's copies leave undefined is not defined by the library, is no new name, is no sanitizer's name (`__asan_`, `__ubsan_`, `__sanitizer_`, `__start_`, `__stop_`) and is no line of `OV_DSL_ALLOW` (the census). So each call of the library that no map answers is a line of a file that the review reads, and a call that can reach the kernel belongs in a map, not on that list.

The first link traces each new name (`-Wl,-y`). The link stops, and its output is removed, unless each new name is defined by one trampoline and no other file; each reference comes from a library copy, a driver object's copy or a trampoline, and a library map's new names only from the library; and the link takes a reference from the library to at least one new name of each library map.

`compile` lists each DSL fuzz target in `$OUT/.dsl-fuzz-targets`, and `oss-verify check` finds it there, as it finds a Go fuzz target. The record of the link ([below](#the-checks-of-the-binaries)) names the trampolines as driver objects, compiled with no sanitizer, and each copy as the file that it stands for, in `renamed`; the driver objects are the project's code, compiled with the build's flags. The quiet twin takes the copies of the driver objects' quiet builds.

## The fuzz targets

A fuzz target is an executable in the `$OUT` of a build whose ELF symbol table defines `LLVMFuzzerTestOneInput`. This is the OSS-Fuzz rule, but we read the symbol table in place of the bytes of the file. A fuzz target must be in each build. A Go program has no `LLVMFuzzerTestOneInput`, and nor has a DSL fuzz target. Thus `compile` lists the Go fuzz targets in `$OUT/.go-fuzz-targets` and the DSL fuzz targets in `$OUT/.dsl-fuzz-targets`, and `oss-verify check` reads those lists ([below](#go-fuzz-targets), [above](#dsl-fuzz-targets)).

`fuzz_targets` in `project.yaml` names the fuzz targets to verify. Without it, we verify each fuzz target that we find. `oss-verify check` copies the published binary of each fuzz target to `out/<target>/<target>.<build>`. It ignores each other file in `$OUT`.

A DSL driver is a fuzz target too: either an `LLVMFuzzerTestOneInput`, or a DSL fuzz target ([above](#dsl-fuzz-targets)), that runs a small program from its payload, and takes its configuration from the payload. It prints the observables of each operation. A failure of the library is one of these observables, not an exit status. The allocation mask works as for each other fuzz target.

A proof is only as strong as its fuzz target. Thus each fuzz target must obey the rules in step 3 of [the add-project skill](../.claude/skills/add-project/SKILL.md):

* Each property is a check that calls `abort()`, not an `assert()`, which `NDEBUG` removes.
* A seed corpus runs each API call and each property check at least once ([project-yaml.md](project-yaml.md#seed-corpora)).
* For each property, a one-line change to the code makes the fuzz target abort on an input of the seed corpus. The change is a `mutant:` record in the check's comment, or a patch in the directory that `mutants` names ([below](#the-checks-of-a-fuzz-target), [project-yaml.md](project-yaml.md#mutants)).
* Each count, size and loop that comes from the input has a bound.
* A run depends only on its input: no threads, clock, random numbers, network, environment or other files.
* `LLVMFuzzerTestOneInput` returns -1 only for a failed expectation that the input chooses, or for an input outside the domain of a property. In all other cases, it returns 0. It never returns -1 for a failed property, and it never calls `exit()` or `_exit()`. It registers no exit handler that does not return, installs no signal handler, calls no `std::set_terminate` and replaces no Rust panic hook ([above](#what-the-driver-does-not-intercept)).

## The checks of a fuzz target

`uv run oss-verify check --checks <file>` measures the second and third rules above for a C or C++ project, on the inputs of its seed corpora, and writes a report in Markdown. The Build check of each enrollment pull request runs it and shows the report in its step summary and in its comment on the pull request. What it finds changes no exit status. It does these steps:

1. **A coverage build.** It builds the `plain` build again, with `-O0 -fprofile-instr-generate -fcoverage-mapping`, with LLVM's profile runtime, and with `abort()` wrapped so that the profile is written before the program aborts. The toolchain image has no profile runtime, so `oss-verify check` downloads compiler-rt's source for the toolchain's LLVM version once, checks its SHA-256, and compiles the runtime in the build's container ([infra/checks/compile-check](../infra/checks/compile-check)).
2. **The runs.** It runs each fuzz target on each input of its seed corpus, with the six-byte header in front ([above](#the-driver)), with `qemu-riscv64-static` in a container of the project image with no network ([infra/checks/run-seeds](../infra/checks/run-seeds)). A run that does not end in 120 seconds counts as a failure. Each run's core dump holds no memory (`/proc/self/coredump_filter` is 0): otherwise, on a host whose `core_pattern` is a pipe, the dump of a run of an ASan build would hold its address space of more than 100 GiB ([above](#the-builds)) and would not end within that time, and an abort would read as a run that did not end. The inputs also run on the project's most checking sanitizer build: `asan-ubsan`, else `asan`, else `ubsan`.
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

`uv run oss-verify check --checks <file>` also does four checks on each build of each fuzz target ([src/oss_verify/check_binaries.py](../src/oss_verify/check_binaries.py)). It writes their results into the manifest ([below](#the-manifest)) and adds a table to the report, with one row for each binary. What they find changes no exit status. For a whole program, only check 1 runs ([below](#the-checks-of-a-program)).

The checks hold each binary against LPS as the published proofs use it: the proofs repository's [`release.yaml`](https://github.com/theorem-labs/oss-verify-proofs/blob/main/release.yaml) names the repository and the commit of LPS in its `semantics:` block, and `oss-verify check` reads that file from the proofs repository on GitHub and fetches LPS at that commit ([src/oss_verify/model_release.py](../src/oss_verify/model_release.py)). Checks 1 and 2 read LPS through rules that we wrote against [one commit of it](https://github.com/theorem-labs/rocq-linux-process-semantics/commit/c0dd863a0f8f307beca7f2ee5cb4d7686a875779) (`MODEL_COMMIT` in each check's file). If a file that a rule reads has different code at the commit that the release names, or is not there, or if `oss-verify check` cannot read `release.yaml` or LPS, the result is `stale` and not a verdict. A change to a comment changes no result.

1. **ELF and instructions** ([src/oss_verify/binary_isa.py](../src/oss_verify/binary_isa.py)). The binary is a 64-bit RISC-V executable at fixed addresses (`ET_EXEC`, `EM_RISCV`). Each byte of its executable code is part of a 32-bit instruction that the decoder of LPS accepts and executes, or zero padding: no compressed (16-bit) instruction (the builds target rv64g, although LPS decodes compressed instructions too), no vector or other instruction that LPS does not have, and no read of a control register that LPS does not have. The check reads the instructions, not the ELF header's flags, and every byte that a segment marked executable maps, whatever a section header says about it. The one exception is a section of build-id notes (the Go and GNU build ids that Go's linker puts in front of `.text`), when its bytes are exactly such notes, each of the two at most once.
2. **System calls** ([src/oss_verify/syscall_shapes.py](../src/oss_verify/syscall_shapes.py)). The binary runs on the empty input (the six-byte header and no payload) and on the first 8 inputs of the fuzz target's seed corpus, with `qemu-riscv64-static -strace` of qemu 10.0.11, the one release whose log formats and host calls the check reads; a run of any other release decides nothing (qemu 8.2, for one, hands the host 0 for the offset of every anonymous `mmap`, so its runs cannot show the offset the program asked for). Each run is in a container of the toolchain image with no network, in an empty working directory that holds the input as `input.bin`, with empty `/tmp`, `/var/tmp` and `/dev/shm`, with an `/etc` that holds only `hosts`, `nsswitch.conf`, `resolv.conf` and an empty `hostname`, with no environment, as an unprivileged user, with a core dump that holds no memory (step 2 of [the checks of a fuzz target](#the-checks-of-a-fuzz-target) says why), and with the fuzz target's name as `argv[0]` ([infra/checks/run-binaries](../infra/checks/run-binaries)). qemu's log prints some arguments as 32-bit numbers (the length of `mmap`, for one) and does not print the address that `connect` gets, so each run runs under a small tracer that logs the host calls with their full arguments, and the address family of each `connect` ([infra/checks/host-calls.c](../infra/checks/host-calls.c)). qemu rounds the length of `mmap`, `munmap`, `mprotect` and `madvise` up to a whole page before it calls the host, so the check takes the length's low 32 bits from qemu's log and its page from the host's. The check reads each trace against LPS, under the statements' default for an abort (`abort: error`: an abort is not a modeled end): each call must be in the system call table of LPS, and its arguments and its result must be ones that the call's specification allows: an errno that the call's arm can answer, or a success that it can give. Otherwise LPS says that the call is unmodeled, and no statement about the run is true in LPS. The check knows the bytes of `input.bin`, so each `read`, `pread64` and `lseek` of it has the one answer that LPS gives, and a `readv` gets no more bytes than remain. Each socket call is answered from the socket's state, as LPS keeps it. A call whose answer turns on a value that neither log shows decides nothing. A fork that LPS answers ends what the trace decides: the child writes into the same log, and qemu's writes of the two processes interleave inside a line, so the run is not decided from the fork on. The result lists each call and argument shape that LPS does not cover, with the inputs that made it. A trace decides something only when it is a whole run: it ends with the run's exit, holds at least 8 calls, and opens and reads `input.bin`. A run that does not end within 60 seconds decides nothing, and all runs together stop after 30 minutes.
3. **Quiet and loud**. With `--checks`, each link of a fuzz target also makes a quiet twin: the same link with each of the driver's objects compiled with `-DHARNESS_QUIET`, which then writes nothing ([link-fuzz-target](../infra/base-builder/link-fuzz-target)). The twin runs on the same inputs, in the same way. It must write nothing to standard output or standard error, and exit with the same status as the binary. Thus what the binary writes does not change which code runs or how it ends; and code of the project that writes (a warning on standard error, for one) shows here. A Rust or Python fuzz target's twin also gets the quiet build of its adapter; a Go fuzz target's twin is the quiet program that OSS-Fuzz's Go helpers make.
4. **Uninstrumented code** ([src/oss_verify/check_links.py](../src/oss_verify/check_links.py)). With `--checks`, each link of a fuzz target also writes the linker's map, which names each object and archive member that the link took, and keeps a copy of each file it took. Each compile also writes a record ([record-compile](../infra/base-builder/record-compile)): the SHA-256 of each object it writes, its source, the SHA-256 of the source's bytes, the source's language, the `no_sanitize` attributes of the source (read from the source preprocessed again with the compile's arguments, so an attribute that a macro or a header gives counts; each source of a compile of several is read on its own), the object compiled with those attributes taken out (`$OUT/.records/nosan/<sha256>`), and each argument that the build gave the compiler. The build also records its own sanitizer flags for C and for C++ ([compile](../infra/base-builder/compile)). The check lists the files of the toolchain image (the bytes that the toolchain image has at that path) whose code is in the binary: those with at least one input section that the linker's map puts in a loaded section, so not an archive whose members `--gc-sections` emptied. With no map, the link has no list. These are the C library, compiler-rt, the sanitizer runtime, the C++ runtime, the Fortran runtime and the libraries of the sysroot. No sanitizer instruments them, in any build, as in OSS-Fuzz's sanitizer builds. The check lists each file of a C library that the build declares ([above](#the-settings-of-one-fuzz-target)) in the same way, with kind `libc`, in path order with the image's files. Its `libc.a` and `crt1.o` always have code in the binary. Its `crti.o` or `crtn.o` has code only when its source has code: musl's for riscv64 are built from empty sources, so with musl the list names neither. Two more problems give the result `error` and no list: the link did not take the declared `libc.a`, or it also took a file of the toolchain image's C library (its `libc.a`, `crt1.o`, `crti.o` or `crtn.o`). When the map has non-blank lines and the check kept no input section of it, the link has no list either: the result is `error`, with the check's own problem, which gives the number of the map's non-blank lines, the number read as input sections, 0 kept, and the first line. That problem is the build's whole detail (in `plain`, after "the plain build instruments nothing, by design"), because the check examined nothing of the project's code. An allocation-failure fuzz target's link takes renamed copies of its archives, and each copy counts as the file it was made from. In the sanitizer builds, the check also checks that the project's own code is instrumented: in `asan` and `asan-ubsan`, each object with code refers to `__asan_init`, as the constructor that AddressSanitizer adds to each object it instruments does (rustc's allocator shim, which makes no memory access, is the one exception). In `ubsan` and `asan-ubsan`, the check first finds the compiles whose records have the SHA-256 of each object or archive member. If one of these compiles had the build's UBSan flags for its language, the object is instrumented, also when it has no UBSan trap: code that has nothing to check compiles to the same bytes with or without the flags. Code whose source turns UBSan checks off has no trap either. So when the source has a `no_sanitize` attribute of any kind, the record also holds the object compiled from the preprocessed source with every `no_sanitize` attribute taken out. An object with no trap whose source has an attribute that turns a UBSan check off (`no_sanitize_undefined`, or `no_sanitize(...)` that names any sanitizer but AddressSanitizer, MemorySanitizer, ThreadSanitizer and the other non-UBSan ones) is instrumented by such a compile only when that object has no trap either (the attributes took nothing out of it); when it has traps, the object is not instrumented, and the result is `fail`. When the record cannot say (a compile of standard input, or of a language other than C and C++ and their preprocessed forms, such as a header or Objective-C; a compile whose arguments are in a response file, or that takes a precompiled header or clang modules; a source that could not be preprocessed or compiled again), that compile does not decide an object with no trap, which is then judged by its traps. "Had the flags" means three things. Each of the build's UBSan flags is an argument of the compile (the `-fno-sanitize=` flags are not necessary). Each `-fno-sanitize=` argument of the compile turns off only checks that the build's own flags turn off. And the compile has no argument that takes checks away or makes a check call a handler in place of its trap, unless the build's own flags have the same argument: an ignorelist (`-fsanitize-ignorelist=`, `-fsanitize-system-ignorelist=`, or their older names with `blacklist`), `-fno-sanitize-trap`, `-fsanitize-recover` (each with or without `=<checks>`), `-fno-sanitize-undefined-trap-on-error`, or `-ftrap-function=<function>`, which makes each check call that function in place of its trap; and, when the build's UBSan flags give `-fstrict-flex-arrays=<level>` (`strict-flex-arrays`, [project.yaml](project-yaml.md)), the last `-fstrict-flex-arrays=` that the driver reads gives no lower level than theirs, since clang keeps only the last one it is given, and no `-fstrict-flex-arrays=` that the driver hands on to the front end gives a lower one, wherever it stands. A level that is not decimal digits counts against the compile, and so does every compile when the build's own level is not. A word that the driver hands on to the compiler's front end (through `-Xclang`, `-Xclang=`, `-Xpreprocessor` or `-Wp,`) counts as the same word given alone; a `-fstrict-flex-arrays=` so handed on counts only against the compile. If none of these compiles had the flags, the object is not instrumented, and the result is `fail`. These compiles do not decide: a compile of assembly, a compile that read its arguments from a response file (`@file`), and a compile with an option whose effect the record does not show, unless the build's own flags have the same option and value: an `-mllvm` option, and the options that make clang read flags or an ignorelist from a file (`--config`, `--config-user-dir`, `--config-system-dir` and `-resource-dir`, each with `=` or a separate value). The toolchain's compiler shims give their own `--config`, which is not in the record: the record holds the arguments that the build gave the shim. A compile that runs with `CCC_OVERRIDE_OPTIONS` set has no record, because clang changes its arguments after the record sees them. If the build's own UBSan flags for a language turn on no check (they have no `-fsanitize=` word, so every compile has them), no compile of that language decides, and the result says so; it says so too for a build with no compile records. For the code that no record decides (a compiler that the build runs by its own name and not through the toolchain's shims, an object that a step changed after its compile, a prebuilt object, a build with no records), the check counts UBSan traps (and rustc UB checks): each archive that holds such code holds more of them than the same archive in the `plain` build, and so does the project's code as a whole. An uninstrumented object with no mark of a compiler is listed, with its source file, as OSS-Fuzz allows, when its DWARF says it is assembly or Fortran and names a file in a checkout of the project image, or, for an object assembled without DWARF, when a source of the project carries its name and names every global it defines. A ported build copies the checkout into a build directory and assembles the copy, so the DWARF names the copy. Such an object is listed with the checkout's file when a compile record shows it: a recorded compile wrote the object's bytes, had each of the build's own sanitizer flags (but the `-fno-sanitize=` flags), and read a source whose path, less some of its leading directories, is a file of a checkout with the same SHA-256. If the recorded compiles of an assembly object did not have the build's sanitizer flags (but the `-fno-sanitize=` flags), the result is `fail`, and the detail names the object and the flags, wherever the object's source is. An assembly object with no compile record is judged as before. A list that would leave a file out is not written, and the result is `error`, in the `plain` build too; so is a build with no link record; so is the UndefinedBehaviorSanitizer comparison when there is no `plain` build, or the check kept no input section of the `plain` build's map, and some code has no record to decide it. The driver is compiled without a sanitizer in every build, and is not listed. A Go program has no link record, because Go's linker writes no map. The check reads the program's own build information instead (its `.go.buildinfo` section, which `go version -m` reads): when it says that Go's own compiler and linker built the program from Go code only (`CGO_ENABLED=0`, `-compiler=gc` and `-buildmode=exe`, for `linux` and `riscv64`, with no race detector, no `-msan` or `-asan`, and no `-linkmode` or `-extld` in `-ldflags`), and Go's function table (`.gopclntab`) spans `.text` and gives every function the line table that Go's compiler and assembler write (only the linker's own trampolines and FIPS markers have none, and the check knows their bytes), the program links no C library and no other file of a C toolchain, and the result is `plain`, with no list. The function table is read because the build information does not show a `.syso` file, which Go's linker takes with no cgo; the C code it brings in has no line table. Otherwise the result is `error`.

The one exception that check 4 makes in the AddressSanitizer builds, rustc's allocator shim, is read from the object rather than taken on its name. An object is that shim when it defines at least one global function, when every function it defines, of any binding, is one of `__rust_alloc`, `__rust_dealloc`, `__rust_realloc`, `__rust_alloc_zeroed`, `__rust_alloc_error_handler`, `__rust_no_alloc_shim_is_unstable`, `__rust_no_alloc_shim_is_unstable_v2` and `__rust_alloc_error_handler_should_panic_v2`, each with this name or with its v0 spelling in rustc's `__rustc` crate (`_RNvC`, an optional `s<disambiguator>_`, `7___rustc`, then `<length>_<name>`, where `<length>` is the length of the name, as in `_RNvC7___rustc12___rust_alloc`), and when its code holds no instruction that reads or writes memory: no load, store, floating-point load or store, or atomic, in 32 bits or compressed, and no bytes that the check cannot read as instructions. That last condition is the reason for the exemption, so the check makes it rather than assuming it: an object that carries these names and makes an access is a finding like any other, and so is one that hides a function of another name by making it local. At most one such member is exempt; a second is a finding. The exempt member is the project's own code that no sanitizer instruments, so the `uninstrumented` list names it, with `kind` `rust-allocator-shim` and the SHA-256 of its bytes, and the verdict's detail counts it out of the objects it calls instrumented.

The records and the quiet twins change no byte of a binary. With `--twice`, the second build makes neither, unless `--layout-out` is given ([below](#a-development-build-that-keeps-addresses)), and its binaries must be the same as the first build's. A record that cannot be written leaves the link as it is, with a warning, and that fuzz target's checks say that it has no record. A compile record that cannot be written is not there, and the check counts the traps of that object.

With `OV_LAYOUT=1` (`oss-verify check --layout-out` and `--base-layout` set it), the record of a link also holds `wraps`, the functions that the link wraps (`--wrap=<f>`), and the record of an append link holds `placement.tsv`, where the append mode put each `.text` input section. `layout.py collect` reads the records into a layout tree ([below](#the-layout-tree)).

These checks find a build that did not do what it meant to, for example a library whose own build dropped the sanitizer flags. The records are written in the build's own container, so they do not stand against a `build.sh` written to deceive them; the review of the pull request does. The same holds for the runs: qemu writes the trace as the program's own user, so a binary written to deceive the checks can rewrite its trace. `oss-verify check` reads the records and the runs' results without following a symbolic link, and checks each kept file against its SHA-256.

## Rust fuzz targets

A Rust fuzz target is a cargo-fuzz `[[bin]]` of the project's repository. The Rust toolchain image adds Rust nightly-2025-07-16 (rustc 1.90.0, LLVM 20.1.8) and its sealed standard library to the C and C++ toolchain. Its row in infra/toolchains.tsv names it. The oss-fuzz-theorems 2026.10 release built its Rust binaries in this image. Code that needs a newer Rust than this one takes a build patch: [projects/sqlpage/rust-duration-compat.patch](../projects/sqlpage/rust-duration-compat.patch) replaces `Duration::from_mins` and `Duration::from_hours`, which this rustc does not have ([below](#build-patches)).

rustc makes no static library from a `[[bin]]`. Thus the build makes one package for each fuzz target: [rust/gen-shim.py](../infra/base-builder/rust/gen-shim.py) writes a package named `oft-rust-shim`, whose library root is a copy of the bin's source without its `#![no_main]` lines, with the line `extern crate oft_rust_rt as _;` added at its end. The package depends on the adapter `oft-rust-rt`, on the dependencies of the fuzz package, and on the fuzz package itself when it has a `[lib]`. `build.sh` then builds this package and links it with the driver ([rust/recipes.sh](../infra/base-builder/rust/recipes.sh)).

A Rust project has all four builds. Each one compiles the standard library with its own flags (`-Zbuild-std`). The table gives the flags that make the four builds different. In each build, `recipes.sh` also adds two `--remap-path-prefix` flags, `-Cdebug-assertions=on` when the target sets `CARGO_DEBUG_ASSERTIONS=1`, `-Cforce-frame-pointers=yes` on a toolchain image that sets `OFT_FRAME_POINTERS=1` ([Frame pointers](#frame-pointers)), and the `--cfg` of the stdio seal when the target sets `OFT_RUST_QUIET_STDIO=1`:

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

Two fuzz targets with the same dependencies can share one lock and one vendor directory: `seeds/bincode/sources` lays out the second target's vendor directory as a `link` to the first.

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

## Whole programs

A whole program has its own `main` and no fuzz entry. It defines no `LLVMFuzzerTestOneInput`, and no driver is linked into it. `oss-verify check` finds a fuzz target by its symbol table ([above](#the-fuzz-targets)), but it does not look for a program. A project names each program in the `programs` field of `project.yaml`, with the SHA-256 of its file, the pin ([project-yaml.md](project-yaml.md#programs)). Such a project has the plain build alone, and lists no fuzz target.

### What build.sh does for a program

`build.sh` runs the program's own build, for example its `make`. Then it writes the program's file in `$OUT`, with its execute bit, under the name that the entry's `file` gives. If the entry names a `link_map`, `build.sh` also writes that link map in `$OUT`. [tests/fixtures/program/](../tests/fixtures/program/) is a test port of one program, `hello`. Its `build.sh` runs `make`, then `cp hello hello.map "$OUT/"`.

Keep the checkout under `$SRC`. If the program's own build files name a fixed path, copy the checkout to that path in the `Dockerfile`, and make that path the `WORKDIR` ([above](#what-the-dockerfile-must-do)). The `Dockerfile` of the fixture copies `$SRC/hello` to `/opt/hello`, and its `WORKDIR` is `/opt/hello`.

A program must be statically linked, as each binary must ([below](#the-refusals-of-a-program)). Check 1 of [the checks of the binaries](#the-checks-of-the-binaries) also asks for an `ET_EXEC` file with no compressed instruction. The `Makefile` of the fixture builds `hello` static and not PIE, with `-march=rv64g -mabi=lp64d`.

### The environment of a program's build

The `build.sh` of a program runs in the environment of the toolchain image itself. This is the environment that `docker run --network none <toolchain image>` gives, so it is the environment of the program's own build in that image. Thus the check gives the bytes that the program's own build gives in the toolchain image.

In the container, the image's own variables cannot be told from those that the builder and the project's `Dockerfile` add. Thus `oss-verify check` reads them on the host. These are the steps:

1. `oss-verify check` reads the image's own `ENV`, its `Config.Env`, with `docker image inspect --format '{{json .Config.Env}}' <toolchain image>`. If the image is not on the host, it runs `docker pull --quiet <toolchain image>` and reads the list again. If it still cannot read the list, the build fails with exit status 1. The build also fails for an entry that is not `NAME=value`, or whose name starts with `-`.
2. If the image sets no `PATH`, `oss-verify check` puts Docker's default in front of the list, as `docker run` gives it: `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.
3. It writes the list to `program-env` in its work directory, each entry ended by a NUL byte. It mounts this file read-only in the container of the build, and names it in `OV_PROGRAM_ENV`.
4. `compile` runs `build.sh` with `env -i`, with the list and with `SRC`, `WORK`, `OUT` and `HOME=/tmp`. It does this before it sets up a fuzz build, so nothing that `compile` sets gets to `build.sh`.

For the newest C and C++ toolchain on 2026-11-27, the row `oss-fuzz-theorems-2026.10` of [infra/toolchains.tsv](../infra/toolchains.tsv), `build.sh` gets these variables:

* from the toolchain image: `PATH`, `MUSL_SYSROOT`, `ASAN_RESOURCE_DIR`, `PKG_CONFIG_LIBDIR`, an empty `PKG_CONFIG_PATH`, `OFT_DEP_CC`, `OFT_DEP_CFLAGS` and `OFT_DEP_CXX`;
* from `compile`: `SRC`, `WORK` and `OUT`, which are `/src`, `/work` and `/out` as in each build, and `HOME=/tmp`;
* from bash itself: `PWD`, `SHLVL` and `_`, and `OLDPWD` after a `cd`.

`build.sh` gets no other variable:

* No `HOSTNAME`. Docker gives each container its own value, and both builds of `--twice` must get the same environment.
* None of the settings of the fuzz builds. Of the variables of [What build.sh gets](#what-buildsh-gets), it gets only `$SRC`, `$WORK` and `$OUT`. Thus it gets no `$CC`, `$CFLAGS`, `$LIB_FUZZING_ENGINE` or `$SANITIZER`, and no `$SOURCE_DATE_EPOCH` unless the toolchain image sets it. `PATH` does not name `/tmp/shim`, and the build makes no compiler shims. The variables that `oss-verify check` gives `compile`, such as `OV_OWNER` and `OFT_MAKE_JOBS`, do not get to `build.sh`.
* No `ENV` of the builder image, such as `SANITIZER=none`, and no `ENV` of the project's `Dockerfile`.

Both builds of `--twice` get the same environment. `build.sh` runs as root, from the `WORKDIR` of the `Dockerfile`, with `bash -eux`, as in each build. `$CC` and `$CFLAGS` are not set, so a `build.sh` that names them stops under `-u`.

### What the check takes from $OUT

`oss-verify check` takes each program that `programs` lists, and the link map that its entry names, from the `$OUT` of the plain build. It takes them as the build wrote them. It links no driver into a program and strips nothing, and it makes or reads no stripped twin. Thus the recorded file keeps its symbol table.

It copies the program to `out/<name>/<name>`, with mode 0755, and the link map to `out/<name>/<link map>`, with mode 0644. It ignores each other file in `$OUT`, as for a fuzz target. The `$OUT` of the build stays in `raw/plain/` of the work directory of `oss-verify check`, as for each build. Thus `raw/plain/<name>` has the same bytes as `out/<name>/<name>`.

### The build log of a program

`compile` writes these lines for the build of a program:

    compile: the plain build (SANITIZER=none)
    compile: a program: build.sh runs in the toolchain image's own environment, with SRC, WORK, OUT and HOME=/tmp
    compile: env <NAME>=<value>

The first line is the line of each plain build, at the start of its line. Then comes one line `compile: env NAME=value` for each variable of the toolchain image, in the order of the image. Then comes the trace that `bash -x` writes: a line that starts with `+ ` for each command of `build.sh`. The trace holds the program's own build command, for example `+ make`, and not each compile. The build writes no compile records and no `$OUT/.records/`.

### The refusals of a program

After the first build, `oss-verify check` does these steps, in this order:

1. It takes the programs and the link maps from `$OUT` ([above](#what-the-check-takes-from-out)). It stops with exit status 1 if one of these problems occurs. It then prints `BUILD FAILED: the programs are not right:` and one line for each problem, and it writes no manifest.
   * A program that `project.yaml` lists is not in `$OUT`: `program <name>, which project.yaml lists, is not in $OUT: build.sh did not write it`.
   * A listed file is not an executable ELF file: `program <name> is not an executable ELF file (a regular file, not a link, with the execute bit, of type ET_EXEC or ET_DYN)`.
   * A link map that an entry names is not in `$OUT`, or is a link: `the link map <link map> of program <name>, which project.yaml names, is not in $OUT`.
2. It writes the manifest, and lists each program as it lists a fuzz target ([The steps](#the-steps), step 4). With `--summary <file>`, the table has a row for each program.
3. It refuses a program that is not statically linked, with exit status 2: `<project>: out/<name>/<name> is dynamically linked: a program must be statically linked (no PT_INTERP or PT_DYNAMIC program header)`. A program whose program headers it cannot read gets the same status. The check then compares no pin.
4. It compares the SHA-256 of each program with the pin of its entry ([project-yaml.md](project-yaml.md#programs)). For each program with other bytes, it prints `NOT THE PINNED PROGRAM` on standard output, and this line on standard error: `<project>: program <name>: the build wrote sha256 <built> (<bytes> bytes) FROM the toolchain <image>, and project.yaml pins <pinned>`. The exit status becomes 3, and the manifest keeps the built SHA-256. The check goes on.
5. With `--twice`, it builds again and compares the two builds ([below](#the-second-build-of-a-program)). A difference makes the exit status 3. A second build that fails stops the check with exit status 1, after the message of step 4.
6. With `--lock`, it compares each program with the lock, as it compares a fuzz target ([below](#check-a-binary-against-a-lock)). A difference makes the exit status 3.
7. With `--checks`, it runs the checks of a program ([below](#the-checks-of-a-program)). They change no exit status.

Thus a program that is not statically linked exits with status 2, whatever its SHA-256. A wrong pin is named in each run that gets to step 4, also in a run whose second build fails.

Before it builds, `oss-verify check` refuses `--layout-out` and `--base-layout` for a project with programs, with exit status 2 and this message: `--layout-out and --base-layout record the links of each fuzz target (infra/base-builder/link-fuzz-target), and the build of a program makes none: this project lists programs`. A layout tree needs the record of each link ([below](#a-development-build-that-keeps-addresses)).

### The second build of a program

With `--twice`, the second build of a program does the same steps as the first, from the start, in the same environment ([below](#reproducibility)). The comparison takes each program and its link map. A link map with other bytes is a difference, as a program with other bytes is. Then the `rebuild` block says `result: differs`, and the exit status is 3. `rebuild.targets.<name>` has the `kind`, `builds` and `link_map` of the second build.

After the comparison, the log has one line for each program of the second build:

    second build: out/<name>/<name> sha256 <value>

The list of the binaries after the first build gives the SHA-256 of each program of the first build. Thus the log holds the SHA-256 of both builds.

### The manifest entry of a program

The manifest records a program under its own name: the `file` of its entry, for example `hello`. That name is the key of `targets` and of `layout`. These are the parts of the fixture's manifest that tell about its program:

    builds:
    - plain
    fuzz_targets: []
    targets:
      hello:
        kind: program
        builds:
          plain:
            file: hello
            bytes: <the size of out/hello/hello>
            sha256: <the SHA-256 of out/hello/hello>
        link_map:
          file: hello.map
          bytes: <the size of out/hello/hello.map>
          sha256: <the SHA-256 of out/hello/hello.map>
    layout:
      hello:
        plain:
          text_bytes: <the size of the .text section of out/hello/hello>
          static: true

* `targets.<name>.kind: program` marks a program. The entry of a fuzz target has no `kind` key.
* The one build is `plain`: `builds` is `[plain]`, and `targets.<name>.builds` has `plain` alone.
* `targets.<name>.builds.plain.file` is the program's own name, not `<name>.plain`. Its `bytes` and `sha256` are those of `out/<name>/<name>`: the file as the build wrote it, with its symbol table.
* `fuzz_targets` is `[]`. It lists only the fuzz targets, and the program is in `targets` alone.
* `targets.<name>.link_map` gives the `file`, `bytes` and `sha256` of the link map, which is the file `out/<name>/<link map>`. A program whose entry names no link map has no `link_map` key.
* `layout.<name>.plain` gives `text_bytes` and `static`, as for a fuzz target ([below](#the-manifest)).

### The checks of a program

With `--checks`, only check 1 of [the checks of the binaries](#the-checks-of-the-binaries) runs for a program: the check of the ELF file and its instructions, against LPS as the release names it, on `out/<name>/<name>`. No fuzz driver runs a program, and its build makes no record of its link. Thus checks 2, 3 and 4 do not run. The step reads LPS as for a fuzz target, but it reads no link record, starts no container and does not look for qemu. In the `binary_checks` block of the manifest, `qemu` is empty, and the list of the inputs of each program is empty.

This table tells where each result of a program appears:

| check | in the manifest | in the report of `--checks` |
|---|---|---|
| the static-link rule ([above](#the-refusals-of-a-program)) | `layout.<name>.plain.static` | none: a program that is not static stops the check with exit status 2 |
| 1, ELF and instructions | `binary_checks.targets.<name>.plain.elf`: `pass`, `fail`, `error` or `stale`, as for a fuzz target | its result, as for a fuzz target, with a line under "What each failure is" for each result but `pass` |
| 2, system calls | `binary_checks.targets.<name>.plain.system_calls`: `not-run` | `not run (a program)` |
| 3, quiet and loud | `binary_checks.targets.<name>.plain.quiet_loud`: `not-run` | `not run (a program)` |
| 4, uninstrumented code | `binary_checks.targets.<name>.plain.instrumented`: `plain`. `targets.<name>.builds.plain` has no `uninstrumented` list | `not instrumented (plain)`, and `no list (a program)` in the column "uninstrumented code" |
| the checks of a fuzz target ([above](#the-checks-of-a-fuzz-target)): the coverage build, the seed runs, the `abort()` checks and the breakages | none: they do not run | the section "The checks of the fuzz targets" names each program, and says that these checks do not run for it |

The detail of each `not-run` and `plain` result of a program starts with `a program:`. The report writes no line under "What each failure is" for `not run (a program)`. The line of the report that counts the inputs of each fuzz target names no program.

## Run a binary

Each binary is a static Linux program for riscv64. Run it on a riscv64 machine, or with `qemu-riscv64` on another Linux machine:

    qemu-riscv64 out/<target>/<target>.<build> <input file>

To give it an OSS-Fuzz testcase, put six zero bytes in front of the testcase:

    { printf '\0\0\0\0\0\0'; cat testcase; } > input

> **WARNING:** Do not limit the address space of an `asan` or `asan-ubsan` binary, for example with `ulimit -v`. At start, the AddressSanitizer runtime reserves more than 100 GiB of address space. If it cannot, it waits forever.

The exit status tells the result ([above](#exit-statuses)).

## The manifest

`oss-verify check` writes `manifest.yaml` next to `out/`, with a mark that a tool made it. It contains these items:

* `repo`, `ref` and `commit`: the repository, the ref in `project.yaml`, and the full commit that the ref named;
* `oss_verifier`: the commit of this repository, and whether `src/`, `infra/`, `seeds/` or the project directory had changes;
* `builder`: the toolchain image of the builder ([Toolchains](#toolchains)), and the local ids of the builder and project images;
* `sources`: each git checkout under `$SRC` in the project image, with its commit;
* `builds` and `fuzz_targets`: what we built, with "each fuzz target" written as a list. For a project with `programs`, `builds` is `[plain]` and `fuzz_targets` is `[]` ([above](#the-manifest-entry-of-a-program));
* `targets.<target>.builds.<build>`: the `file`, `bytes` and `sha256` of each binary, in the format of the `builds:` section of an oss-fuzz-theorems `harness.yaml`;
* `targets.<target>.kind`: `program` for a whole program, and no key for a fuzz target;
* `targets.<target>.link_map`: the `file`, `bytes` and `sha256` of the link map of a program, when its entry in `project.yaml` names one;
* `layout.<target>.<build>`: the `text_bytes` of each binary (the size of its `.text` section), and `static`, true for a binary with no `PT_INTERP` or `PT_DYNAMIC` program header; a value that `oss-verify check` cannot read is `null`;
* `rebuild`, only with `--twice`: the second build ([below](#reproducibility));
* only with `--checks`: `targets.<target>.builds.<build>.uninstrumented`, the files of the toolchain image, and each file of a C library that the build declares ([above](#the-settings-of-one-fuzz-target)), whose code is in the binary (an archive is listed when the linker's map puts at least one input section of its members in a loaded section, so one whose code `--gc-sections` removed is not; a link with no map has no list), in the format of the `uninstrumented` list of a `harness.yaml` build (`name`, `kind`, and `sha256` for a file or `source` for an assembly or Fortran member; `kind` is `libc`, `compiler-rt`, `sanitizer-runtime`, `cxx-runtime`, `fortran-runtime`, `image-library`, `rust-allocator-shim`, `assembly` or `fortran`), and `binary_checks`: LPS as the release names it (`model`: release, repository and commit), the version of qemu (`qemu`), the inputs that each fuzz target ran on, and for each target and build the results of the four checks ([above](#the-checks-of-the-binaries)): `elf`, `system_calls` (with the calls LPS does not cover, the exit status on each input, and the abort stance), `quiet_loud` and `instrumented`. Each has a `result` (`pass`, `fail`, `error`, `stale`, `not-run` or `plain`) and a `detail` that a person reads.

We will write the lock in the proofs repository from the manifest. The lock is the only place that records the commit. `uv run oss-verify check --lock <file>` builds the commit that a lock names, and compares each binary with the lock ([below](#check-a-binary-against-a-lock)). The lock can be a manifest or an oss-fuzz-theorems `harness.yaml`.

Repeat `--lock` to compare with several locks. They must agree on the source commit and toolchain, and on the SHA-256 of any target and build that more than one lock pins. Conflicting pins stop the command before building. Identical pins and locks for different targets or builds can be combined.

If you run `oss-verify check` before you commit the project directory, the manifest says `modified: true` under `oss_verifier`. Commit first if you want a manifest that names exactly the commit you built. It does not change what we pin: we write the lock from our own build of the merged directory.

## Reproducibility

A statement is about the exact bytes of a binary, which the lock pins by their SHA-256. You can rebuild a binary and compare it with the lock only if each build gives the same bytes.

`uv run oss-verify check --twice` builds everything a second time from the start, with `docker build --no-cache`, a new fetch and a new compile of each build. It fails if a byte is different. The Build check of a pull request runs `uv run oss-verify check --twice` too.

After the comparison, `uv run oss-verify check --twice` adds the `rebuild` block to the manifest. It also adds the block when the builds differ. The block contains these items:

* `kind: same-host`, the `host` and the time (`at`, in UTC) of the second build;
* `builder`, `builds` and `targets` of the second build, in the same format as at the top level of the manifest;
* `result`: `identical` if each binary, and each link map of a program, has the bytes of the first build, or `differs` ([above](#the-second-build-of-a-program)).

We pin only binaries that two clean builds reproduce. Thus we pin a binary only from a manifest whose `rebuild` block says `result: identical`. The second build uses the same toolchain. Its local image ids can differ from those of the first build, because Docker records the time of each build.

We found that these items decide the bytes:

* **The source paths.** An AddressSanitizer build records the path of each source file that it instruments. A file compiled at `/src/a/x.c` and at `/src/b/x.c` makes different binaries. The plain and UBSan builds do not depend on the path. A ported build gives the compiler neutral paths under `/src`, unless the block of the fuzz target disables the path rewrite ([above](#the-settings-of-one-fuzz-target)).
* **The order of the link.** The driver comes first and the seals come last. `$LIB_FUZZING_ENGINE` arranges this.
* **The layout of the archives.** OSS-Fuzz links the object of the fuzz target before the archives of the library. The release linked one archive that holds the library and the fuzz target. The two layouts can make different programs. A port that must match the release's bytes links as the release did.
* **Stripping at the link.** A strip after the link gives bytes that are different from `-Wl,--strip-all`.

## Check a binary against a lock

These steps rebuild a binary and compare it with its lock in the proofs repository.

> **WARNING:** `oss-verify check` builds the project's `Dockerfile` with network access, as `docker build` does. Use it only on a project that you trust ([SECURITY.md](../SECURITY.md)).

1. Get the project's lock from the proofs repository.
2. Check out this repository: at the commit that the lock gives in `oss_verifier.commit`, if it has that field; else at `main`. A `manifest.yaml` that `oss-verify check` wrote has the field. A `harness.yaml` of the oss-fuzz-theorems 2026.10 release, which each published lock is today, does not have it ([below](#check-a-binary-against-a-harnessyaml-lock)).
3. Run `uv run oss-verify check --no-shell --lock <lock> <name>`. `<name>` is a project in `projects/`. For a project in `seeds/`, give its directory: `uv run oss-verify check --no-shell --lock <lock> seeds/<name>`.
4. Read the last line of the output.

`oss-verify check` builds the commit that the lock names, with the toolchain that the lock names. It then compares the SHA-256 of each binary with the lock. It compares only the builds that `project.yaml` asks for ([sanitizers](project-yaml.md#sanitizers)), and a lock can pin more builds. For example, the lock of `avahi/fuzz-ini-file-parser` pins `plain`, `ubsan`, `asan` and `asan-ubsan`, and `seeds/avahi` makes only `plain` and `ubsan`. `oss-verify check` does not compare a binary of a build that the project does not make.

* `matches the lock` tells you that each binary that the lock pins for these builds has the same bytes. The line gives their number.
* `DIFFERENT FROM THE LOCK` lists each binary of these builds that has different bytes, or that the build did not make.
* `THE LOCK PINS NONE OF THESE BUILDS` tells you that `oss-verify check` compared no binary.
* `BUILD FAILED` tells you that the build stopped before `oss-verify check` compared a binary.

### Check a binary against a harness.yaml lock

`oss-verify check` also accepts a `harness.yaml` of the oss-fuzz-theorems 2026.10 release as a lock. Use this to check a binary of that release. The locks published today are these files, and none of them has an `oss_verifier` field. Thus step 2 above uses a checkout of `main` with them:

    uv run oss-verify check --no-shell --lock <proofs>/projects/cjson/cjson_read_fuzzer/harness.yaml cjson

`oss-verify check` can check the lock of a project that has a directory in this repository, in `projects/` or `seeds/`. The release also has locks of projects that have no directory here. This repository has no build files for them.

If `oss-verify check` at `main` does not print `matches the lock` for a binary of the release, open an issue in this repository. Include the output of `oss-verify check`. [seeded-projects.tsv](seeded-projects.tsv) names each patch that the port of a seeded project applies since the check of its seed port, or no longer applies. Its build notes tell which binaries differ from the release's, or may differ. Do not open an issue for these binaries. When the build notes of a project say that some binaries may differ and do not name them, do not open an issue for any binary of that project.

## A development build that keeps addresses

In a normal link, a change that makes one function larger moves every function after it. Each fact about the address of such a function then changes, and almost every proof file of the fuzz target must build again. A development build in the append mode keeps each function whose code did not change at the address that the base build gave it. The base build is the build of the merge base. The other functions go into free space.

A development build is never evidence. Its binaries are never a pin and never a lock: they go only into a draft release, and no `project.yaml` or `harness.yaml` names them.

Build the merge base and keep its layout tree, then build the change against that tree, then compare the two trees:

    uv run oss-verify check --no-shell --layout-out base-layout <name>       # at the merge base
    uv run oss-verify check --no-shell --layout-out new-layout --base-layout base-layout <name>
    python3 infra/base-builder/layout.py check base-layout new-layout

* `--layout-out DIR` turns on the records of each link, also without `--checks`, and sets `OV_LAYOUT=1`. After the build, it writes the layout tree of the build to `DIR` (`layout.py collect`). `DIR` must be new or an empty directory, because `layout.py check` compares each entry that two trees hold.
* `--base-layout DIR` gives each `compile` container the layout tree `DIR`, read-only, as `OV_BASE_LAYOUT`. It needs `--layout-out`, which then gets the layout tree of the append build. With `--twice`, the second build is an append build too, so `--twice` also shows that two append builds of the same inputs make the same bytes.

A base layout must come from a build with `OV_LAYOUT=1`. A record of `--checks` alone has no `wraps`, and `layout.py collect` refuses it.

### The layout tree

The layout tree has a directory `<build>/<target>/` for each fuzz target that has a record. [layout.py](../infra/base-builder/layout.py) writes these files from the record (`$OUT/.records/<sha256>/`), the files that the link took (`$OUT/.records/store/`) and the binary:

* `map`: the map of the record, as it is: the input sections of the linker's map, in the map's order.
* `sections.tsv`: one line for each line of `map` that names a file. It gives the file, the file that the key uses (for a copy of an allocation-failure link, its original), the archive member, the section, the SHA-256 of the section's bytes before relocation, the size of the input section and its alignment.
* `calls.tsv`: each call relocation (`R_RISCV_CALL`, `R_RISCV_CALL_PLT`) and each thread-local access (`R_RISCV_TPREL_HI20`) of each `.text` input section, in offset order, and its target. `layout.py` finds the target of a global symbol in the objects of the link. Thus a function of hidden visibility has a target too, although the symbol table of the binary lists it as local. A call to a function that the link wraps (`--wrap=<f>`) is a call to `__wrap_<f>`, and a call to `__real_<f>` is a call to `<f>`. A target can also be an undefined weak symbol that no object defines (`weak`: lld gives it the address 0, unless the binary names it), or an `ifunc` (`STT_GNU_IFUNC`: the call goes through an lld PLT entry, whose address no tree holds). Each line also gives `relax`, 1 when the next relocation is `R_RISCV_RELAX` (lld relaxes no other line), and `delta`, the number of bytes that lld's relaxation removed in front of the relocation in its section. The relocation is at the address of the section plus its offset, less `delta`. `layout.py` computes `delta` as lld 20 does in a static link without `--relax-gp`: an `R_RISCV_ALIGN` removes the nops past its boundary, a relaxable call removes 4 bytes when its target is in the reach of `jal`, and a relaxable `R_RISCV_TPREL_HI20` or `R_RISCV_TPREL_ADD` removes 4 bytes when its variable lies within 2 KiB of the start of the TLS segment. From the first relocation whose relaxation it cannot compute (a call to an `ifunc`, a target with no address, a relaxable `R_RISCV_TLSDESC_*` relocation, or a call in an object with compressed instructions), `delta` is `-`. The last field, the target delta, is the number of bytes that lld's relaxation removed in front of the target's symbol in the target's section: lld moves a symbol by the bytes that it removed in front of it, so the target is at the address of its section plus its offset there, less the target delta. `layout.py` reads it from the relaxation of the target's section, which depends on the targets of that section's own calls, so it computes the relaxation of every section of code again until the target deltas no longer change. The target delta is 0 for a target at the start of its section, for a call through a section symbol, for a section that holds no code, and for a target that only the symbol of the binary places. It is `-` when it is not known. With `-ffunction-sections`, which the builder passes, almost every target is at the start of its section.
* `output.tsv`: the output sections, the `PT_LOAD` segments and the global symbols of the binary.
* `binary.sha256`: the SHA-256 of the binary and of its stripped twin.
* `wraps`: each function that the link wraps.
* `placement.tsv`, of an append build only: where the append mode put each `.text` input section, and why a function whose bytes did not change moved. For a build that fell back to its normal link, each line gives the cause `normal_layout` and the reason ([below](#when-the-build-falls-back-to-its-normal-link)).

### What the append mode does

`link-fuzz-target` uses the append mode when `$OV_BASE_LAYOUT/<build>/<target>/` exists. When `OV_BASE_LAYOUT` is set and that directory is not there, it writes one line on standard error and makes a normal link. An allocation-failure link uses the append mode too, and keys each copy of a file by its original.

`layout.py append` does these steps:

1. It links one time normally (the probe link). This gives the input sections that the link takes, their sizes, their calls and thread-local accesses as `calls.tsv` gives them (with `delta`), and the end of the read-only segment.
2. It pairs each `.text` input section of the probe link with one of the base: by its key (the file, the member and the section) when the key occurs one time on each side; else by its section name, SHA-256 and size, when one section on each side has all three (a C++ COMDAT section that now comes from another object); else, for a key that occurs more than one time, member by member in the order of the map. A function has the same bytes when its input section has the same SHA-256 and size as at the base. The test reads the bytes before relocation, so a function whose calls now go to other addresses has the same bytes.
3. Each function with the same bytes stays at its base address. Each other function goes into a hole before or between kept functions, the largest first, where it fits at its alignment. A function that fits no hole goes to the end of `.text`. A changed function never goes to its own base address. `.text` ends at the first address after the last function whose distance from the end of `.text` in the probe link is a multiple of the largest alignment of the sections that lld puts after `.text` in the same `PT_LOAD` segment (libc++'s `__lcxx_override`, which holds `operator new`, for one, and lld's own sections, such as `.iplt`). Thus lld puts each of those sections the same number of bytes after the address that the probe link gave it.
4. It tests each call of each kept function at its base call site against the planned address of its target. When lld would relax the call where it did not at the base, or the other way round (`jal_reach`, below), the function moves too, and the mode plans again. When the target lies inside a section that moves, after relocations that lld may relax, lld's relaxation there can move the target down by up to the bytes that it can remove in front of the target. A hole is then used only when the call is relaxed as at the base for each of those addresses. The base range of a function that moved in this way, and of the other members of its key, stays free in each later plan. When the plan is done, such a function goes back to its base address, with the other members of its key, when none of their calls would change any more. Nothing else moves. Thus each `jal_reach` that the plan records names a call that would change in the final plan. When a function that the plan keeps has a call or a thread-local access that lld may relax and that the mode cannot test, a line in `calls.tsv` that only the base or only the probe link has, or a call whose target the plan puts where lld's relaxation may leave it in the reach of `jal` or out of it, the build falls back to its normal link ([below](#when-the-build-falls-back-to-its-normal-link)).
5. When the code, with the sections after `.text` in its segment, ends at or below the start of the page that holds the start of the base's next `PT_LOAD` segment, that segment starts where it did at the base, so the data after `.text` keeps its addresses. Else lld places the data, and `layout.py check` lists the data that moved.
6. It writes an lld linker script that puts `.text` and each function at its address, and ends `.text` at the address of step 3. The output and its stripped twin are linked with that script, after the seals. The quiet twin of the record is a normal link.
7. It links with the script, and it checks that each kept function has its base address and its base size, that the check link relaxes each call and thread-local access of a kept function there as at the base, that the `PT_LOAD` segments have the count and the flags of the probe link, and that no two `PT_LOAD` segments share a page. A kept function that the check link changes, and whose call or thread-local access it relaxes where the base did not, or the other way round, moves (`jal_reach` or `tls_reach`), and the mode plans and links again. Such a function never goes back to its base address, so the links end. Last, the mode makes the decision of `layout.py check` on the layout that it would keep. It makes the files of the layout tree's entry of the final link as `layout.py collect` makes them, with the map that the record of the link will hold (the input-section lines of the linker's map, as `link-fuzz-target` keeps them) and the `placement.tsv` that it would write, and it compares them with the base's entry as `layout.py check` does. The final link is the last check link (the same command, with the same script), or, for `readonly_growth` (below), a normal link of the same command, which the probe link is. When the check link fails, or shows a difference that no cause below explains, or when `layout.py check` would fail the layout, the build falls back to its normal link ([below](#when-the-build-falls-back-to-its-normal-link)). So an append build that keeps its layout passes `layout.py check`.

### Why a function whose bytes did not change can move

The mode never stops a link for a change of the code. When it cannot test or decide a call of a kept function, or when a check link is not what the plan asks, the build falls back to its normal link ([below](#when-the-build-falls-back-to-its-normal-link)). When the linker cannot keep a function at its base address, the mode moves that function too and records one of these five causes in `placement.tsv`:

* `jal_reach`: lld changes a call into one 4-byte `jal` instruction only when the target is less than 1 MiB away from the call site. The call site is the address of the function plus the offset of the call, less the bytes that relaxation removed in front of the call in the function (`delta` in `calls.tsv`). The target is at the address of its section plus its offset there, less the target delta in `calls.tsv`. When a call in the function would change in this way at its base call site, because its target moved, the function moves too. A target in a section that lld puts after `.text` moves by as many bytes as the end of `.text` moves. This can occur only when `.text` is larger than 1 MiB. lld never changes a call that has no `R_RISCV_RELAX` (`relax` 0), so such a call is never a cause.
* `tls_reach`: lld removes the `lui` and the `add` of a thread-local access only when the variable lies within 2 KiB of the start of the TLS segment, and only when the access has `R_RISCV_RELAX`. When a change moves the variable across that bound, the function changes size wherever it goes, so it moves.
* `repeated_key`: one pattern of a linker script places all the sections of one key together, in their input order. The members of a key that occurs more than one time stay only when they were side by side at the base, in the same order, each has the same bytes as at the base, and no two of them have the same bytes, since the map does not tell such sections apart and lld may take their archive members in another order. Else they all move, as one block. Two sections of one name with the same bytes in one object move too, although lld keeps their order, because the tree does not record which object holds a section: that costs a move, and never makes a function read as kept. `layout.py check` fails for a function of a key with two sections of the same bytes that stays at its base address.
* `alignment`: the alignment of the section grew, and its base address is not a multiple of the new alignment. This occurs only for code compiled without relaxation, or written in assembly: with relaxation, clang puts the padding of an alignment inside the section, so the bytes change.
* `readonly_growth`: the read-only segment before `.text` grew past the start of the page that holds the base's first `.text` byte, so `.text` cannot start where it did. The mode then makes a normal link, writes one line that gives the growth and the room, and records each function with the same bytes with this cause. It makes the decision of `layout.py check` on that layout too (step 7). The room is less than 4 KiB. For `libreac/fuzz_pcap` it is 2,680 bytes (plain), 2,608 (ubsan), 144 (asan) and 64 (asan-ubsan).

A function whose map line's bytes `layout.py` cannot tell has no SHA-256 in `sections.tsv`, so it moves as a changed function. `layout.py` pairs the map lines of one name of one file or archive member with the sections of that name only as far as lld's guarantees go: lld gives a section a linked size from its input size less the most bytes that its relaxation can remove there (the section's removable bytes: an alignment's nops, and the bytes of each call and thread-local access that lld may relax) up to its input size, and which one changes from one link to the next (the base, the probe link and the final link); it takes each section at most once; and it keeps the sections of one name of one object in their order in that object, but it lists the archive members of one name in the order in which it took them, which the tree does not show. So the size of a line tells two sections apart only when no linked size of one can be a linked size of the other: sections whose ranges of linked sizes overlap, directly or through other sections, are one cluster, and a line can be a section of the one cluster whose ranges hold its size. A line gets the section that every assignment of the lines to the sections under these guarantees gives it, which is the same section in the base, the probe link and the final link, whatever linked sizes lld gave them there. When the sizes leave a line two or more sections (lld took only some of them, through `--gc-sections` or the archive members that it did not extract, or they lie in two archive members of one name), the line gets their bytes when they all have the same bytes, calls and alignment and define no global symbol, as `asan.module_ctor` does in two archive members `ov_rk.o` of one name; else it has no SHA-256. Two lines of one key with the same bytes, as those two, always move, with `repeated_key` (above). A line has no SHA-256 either when no assignment fits (a line whose size no section of its name can have, for one), and when the search for the assignments of the lines of one name takes more steps than its bound (`ASSIGNMENT_STEPS`). `libc.a` of musl holds two members `clone.lo`, whose `.text` sections hold 0 and 68 bytes, and its one line of 68 bytes is the second. Two members `util.c.o` of one archive, as CMake makes for `a/util.c` and `b/util.c`, whose sections of one static function hold 8 and 26 bytes and nothing that lld's relaxation removes, give the line of 26 bytes the second member's section and the other line the first member's, in either order of the lines. Were the first member's section 0x20 bytes with one call that lld may shorten by 4 bytes (a linked size of 0x1c to 0x20 bytes) and the second member's 0x1c bytes, the sizes would tell neither line, whatever their sizes in one link.

### When the build falls back to its normal link

The mode cannot test some calls and thread-local accesses that lld may relax: a call to an `ifunc`; a call or an access whose target is a local symbol of a section that has no row of its own in `sections.tsv` (a twin line or a line with no SHA-256, above, or a section that the map did not take), so that the tree cannot place it; a call whose target has no address in a tree; a call or an access whose `delta` is not known (`-`) at the base or in the probe link, such as an access after a relaxable `R_RISCV_TLSDESC_*` relocation, or a call whose target lies after a call to an `ifunc` in its section; an access whose variable has no offset in a TLS segment; a line that only one of the two links marks `R_RISCV_RELAX`; and a line with the offset, the type and the target of another line of the function at the base, since a `jal_reach` or `tls_reach` cause names its line by the offset and the target at the base, and `layout.py check` fails a cause that names two lines. Nor can it test a line, with `relax` 1 or 0, that only one of the two links has, since `layout.py check` fails a kept function with such a line ([below](#the-layout-check)). Nor can it decide a call whose target lies inside its section after relocations that lld may relax, when the plan or the check link puts the target where lld's relaxation there may leave it in the reach of `jal` or out of it. A kept function with such a call, access or line is never linked at its base address: lld may relax it otherwise than at the base, two such calls that lld relaxed the other way round would keep the function's size but not its bytes, and `layout.py check` cannot verify it. The build then falls back to its normal link.

The build also falls back to its normal link when the check link fails, as when lld cannot move the location counter backward to an address of the script because the functions in front of that address took more room than the plan gave them; when the check link changes a kept function and relaxes no call or thread-local access of it otherwise; when the check link puts a kept function at its base address with its base size, but relaxes a call or a thread-local access of it otherwise than at the base, or puts the target of such a call where the mode cannot tell whether lld relaxes it otherwise (the plan predicted that call wrongly, and the size does not show it: lld removes 4 fewer bytes of the nops of an `R_RISCV_ALIGN` after a call that it relaxes, and two calls that it relaxes the other way round keep the size too); when the last check link does not show the cause of a function that moved with `jal_reach` or `tls_reach` (a function that a check link moved never goes back to its base address, so that the links end, and its cause can rest on a call whose target the last check link puts where lld relaxes the call as at the base); when the `PT_LOAD` segments are not those of the probe link, or two of them share a page; when the check link takes a `.text` input section that the probe link does not, or lacks one; when `layout.py check` would fail the layout that the mode would keep (step 7 above), and the reason then names the cause of the first failure of the check: the function, the file that it comes from, and what fails; when the mode cannot make the files of that decision from the final link or read them back, a defect of the mode, and the reason then names the error; and when a file or section name holds a double quote or a line break, which the script cannot quote. So an append build that keeps its layout passes `layout.py check`. An error of the machine while the mode writes the files of that decision, such as a full disk, is not a fallback: `layout.py append` names the error and exits with status 2, and the link stops.

In a fallback, `layout.py append` writes no script, so that the output and its stripped twin are normal links, and it exits with status 0. It writes one line on standard error, `layout.py append: <target> (<build>): normal link: <reason>`. The reason names the function and its call, or the line of the script, the functions in front of that line and the function that lld could not put at its address, or the cause for which `layout.py check` would fail the layout, or the error with which the mode could not make the files of that decision or read them back. `placement.tsv` gives each `.text` input section the place `normal`, its address in the probe link, the cause `normal_layout` and the reason. `layout.py check` verifies that the build's `.text` is laid out as lld's normal link lays it out, and then lists the build as `normal layout: <reason>` (below). The build is correct, and only that build loses the base's addresses. The append mode stops a link only when the probe link fails, as the normal link of the same command would (status 1), and when it cannot read an input or an error of the machine stops it while it writes a file, such as a full disk (status 2, naming the error).

### The layout check

`python3 infra/base-builder/layout.py check BASE NEW` compares each build and fuzz target that the two layout trees both hold. It pairs the `.text` input sections as the append mode does, and reads each address and size from the two maps. Each function with the same bytes must have its base address and its base size in `NEW`, or move for a cause in `NEW`'s `placement.tsv` that the two trees show. The check reads each cause again from the trees, and it does not believe `placement.tsv`. It lists the functions that moved with a cause apart. It also prints the number of kept functions, each changed function with its two addresses, the change of the start and the size of `.text`, and each other section with the same bytes that moved.

A function at its base address with its base size counts as kept only when the trees show that lld relaxed it as at the base, which the size alone does not show: lld removes 4 fewer bytes of the nops of an `R_RISCV_ALIGN` after a call that it relaxes, and two calls that it relaxes the other way round keep the size too. The function must have the same lines in `calls.tsv` in `NEW` as at the base (offsets and types), and the two lines of each pair must agree. The lines of one offset and type pair in their order in `calls.tsv`: the first with the first, the second with the second. The append mode pairs them the same way. A line with `relax` 0 on both sides is never relaxed. Else both lines must have `relax` 1 and the same `delta`, and the delta must be known: a delta that is not known cannot be verified. The append mode keeps no function with a line of `relax` 1 whose delta is not known at the base or in the probe link, or with a line that it cannot test ([above](#when-the-build-falls-back-to-its-normal-link)). The call site, the address of the function plus the offset of the call less the delta, must be in the reach of `jal` of the call's target at the base exactly when it is in reach of its target in `NEW`. The variable of a thread-local access must lie within 2 KiB of the start of the TLS segment at the base exactly when it does in `NEW`. A target with no address, or a variable with no offset in the TLS segment, cannot be verified either. Else the function fails, and the check names the call or the access.

A build whose `placement.tsv` gives `normal_layout` fell back to its normal link. A normal link keeps no base address, so the build claims none. The check verifies the mark from `NEW`'s map and its `output.tsv`. lld's normal link puts the first input section of `.text` at the start of `.text`, and each other one at the end of the one before it (its address plus its linked size), rounded up to its alignment. `.text` ends at the end of the last one. The lines of `.text` in the map must obey this rule, with the address, the linked size and the alignment that the map gives, and the address and the size of `.text` that `output.tsv` gives. These lines are the `.text` input sections, and each line of the linker's own between two of them, such as the padding that lld's `--randomize-section-padding` adds. Thus a mark over the layout of an append build fails: a kept function with a hole in front of it breaks the rule. When the rule holds, the check lists the build as `<build>/<target>: normal layout: <reason>`, with the change of `.text`, and fails nothing else of it. The check does not verify the reason. Its last line counts such builds among those that pass, as `layout check: <p> of <n> (build, target) pass, <m> with a normal layout`.

It exits with status 1 when a function with the same bytes moved with no cause, or with a cause that the trees do not show, or stayed at its base address with its base size but the trees do not show that lld relaxed it as at the base, and names the function. It also exits with status 1 when the `.text` of a build that `placement.tsv` marks with `normal_layout` breaks the rule above, and names the build and the first line that breaks it. It exits with status 2 when it cannot read a tree, or when the two trees have no build and fuzz target in common. A `placement.tsv` in which some lines give `normal_layout` and others do not, or which gives two reasons, cannot be read.

## Builds ported from oss-fuzz-theorems

We ported the build of each project that we seeded from the oss-fuzz-theorems 2026.10 release from the release's build recipe. Each port is three files next to `project.yaml`:

* `Dockerfile`: gets the project at `COMMIT` into `$SRC/upstream/<name>`, then runs `lay-out-sources` on `sources`.
* `sources`: tells where each source tree goes, as the release's source manifest tells. It names a copy of the checkout for each release target, and each other tree or file, pinned by commit or SHA-256. It also names the release's own files for a target, and its build patches. It is the only place that records the pin of a dependency. A `Dockerfile` never holds one.
* `build.sh`: for each fuzz target, the release's pin for it (its `build_lib`, `LIB_ARCHIVE` and helpers). [release-target.sh](../infra/base-builder/release-target.sh) runs each pin with the release's recipes ([recipes.sh](../infra/base-builder/recipes.sh)), under `sh -e`, as the release ran it.

`release-target.sh` gives each target the layout that the release built in:

* the tree of the target in `/work/ext/<target>/src`;
* its build directory in `/work/build/lib/<build>/<target>`;
* the release's files for it in `/work/targets/<target>`;
* compiler wrappers that give the compiler the neutral `/src/...` paths that a binary records, unless the block of the fuzz target disables this rewrite ([above](#the-settings-of-one-fuzz-target)).

The internal paths matter too. The source locations of the UBSan checks keep the internal path. In an `asan-ubsan` build, a header that uses `__FILE__` and holds a UBSan check thus makes one more string literal, which AddressSanitizer instruments. With the release's layout, a ported build makes the release's binaries again.

We checked each port with `uv run oss-verify check --lock`, against each `harness.yaml` of the release for its fuzz targets. [seeds/builds.tsv](../seeds/builds.tsv) holds the result for each project, and [src/oss_verify/seeded_projects.py](../src/oss_verify/seeded_projects.py) writes it into [seeded-projects.tsv](seeded-projects.tsv). A seeded project gets the port in `seeds/<name>/` only if each binary is the release's. [seeds/checked-patches.tsv](../seeds/checked-patches.tsv) holds the patches that each check applied, with their SHA-256. In the build notes, `seeded_projects.py` also names each patch that a port applies since the check of its seed port, or no longer applies.

## Build patches

`series` lists each patch that the build applies, one time each, in order, but not the patches of a C library that the build declares. In a ported build, `lay-out-sources` applies each `patch` line of `sources`, and stops when those lines are not the patches that `series` lists, in the same order.

`lay-out-sources` applies each patch with `git apply` under `core.symlinks=false`, so a patch cannot make a symbolic link: a link in a patch becomes a regular file holding the text of its target. The setting is passed on that one command, never put in a clone's config, where it would break a working tree's own links.

A patch in the `series` of an enrolled project can only change how the project builds: static linking, cross-compilation, a version stamp or a generated file. A change that fixes a bug of the project never goes in the directory of an enrolled project. We send it to the project as a patch, with its finding ([what-gets-proven.md](what-gets-proven.md#findings)). If a proof needed that patch, we publish the patch with the proof ([what-gets-proven.md](what-gets-proven.md#publishing)). The directory of a seeded project whose proofs we publish can also hold a patch that fixes a bug, once the finding of that bug is public. A proof can then be about the build with the fix. The facts list each such patch ([what-gets-proven.md](what-gets-proven.md#publishing)).

A patch of a C library that the build declares is a file of the project directory. Its name does not end in `.patch`, because `oss-verify validate` asks `series` to list each file with that ending. The rest of its rule is in [The C library](#the-c-library).
