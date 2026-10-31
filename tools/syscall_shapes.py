# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The system-call check of a fuzz target's binary: does one run's `qemu-riscv64 -strace` trace stay inside what the
process model answers?

The model (theories/LinuxProcessSem in the published model repository) answers each system call through one arm of
spec_table (Sys/SyscallTable.v). A call whose number has no arm is unmodeled. So is a call whose arm falls through to
`unmodeled` for its arguments, because most arms answer only part of their argument space. A run that makes one
unmodeled call is not a run the published proofs speak about. check_trace() reads a trace and lists each call that is
unmodeled by its name, by the shape of its arguments, or by an answer the arm does not give, as far as the trace shows
them:

- the name, the scalar and flag arguments, the quoted path strings, and the return value;
- a replay of the model's address-space ledgers (State.v VmMaps: vm_maps, vm_noaccess, vm_brk) beside the image
  (vm_reserved: the binary's LOAD segments), which decides the mmap, munmap, mprotect, madvise, mremap and brk arms;
- a replay of the model's descriptor table (State.v init_model: the three channels, then what each open, socket, dup
  and close does), which decides every arm that reads a descriptor's kind;
- the /tmp keys the run created and removed, the tid the model has pinned, and whether a prlimit64 read, a sigaltstack
  install, a pipe2 or a clone has happened.

qemu -strace prints some arguments through a 32-bit format, so a larger value reaches the trace as its low 32 bits
(read signed for `%d`, unsigned for `%#x` and `%u`): the length of mmap, munmap, mprotect and madvise, the offset of
mmap, the count of read and write, the count of pread64 and pwrite64, the size of getrandom and getcwd.
The same run's host-call log (`lengths`, written by tools/checks/host-calls.c) gives those arguments back in full,
because qemu hands them to the host unchanged, or rounded up to a page (see HostLog). Where it does not, the checker
takes the printed value as the low 32 bits of an unknown register and does not decide an answer that a larger value
would change: the call goes into the result's `undecided` list, not its `unmodeled` one. The formats and host calls
read are qemu 10.0.11's (tools/check_binaries.py QEMU_VERSIONS: one release records the runs).

One assumption the trace cannot check (Arg.sext): an argument that the guest passes as a 32-bit int arrives in its
register sign-extended, by the RISC-V calling convention (riscv-elf-psabi-doc, the RVG calling convention: a scalar
narrower than XLEN is widened by the sign of its type to 32 bits and then sign-extended to XLEN; an unsigned 32-bit
value too). qemu prints such an argument in full in its low 32 bits, and neither qemu nor the host call can show the
top half, because qemu reads it as an int as well. The arms this decides are futex's operation and getrandom's flags,
which the model compares as whole registers. A guest written in assembly could put anything in the top half; the
model would then answer unmodeled where this reading answers the arm.

What the trace does not show is not checked: a struct behind a pointer, the bytes of an iovec array (so readv and
writev are held to their count, not to their iovecs), the bytes of a socket address that qemu prints as a pointer
(connect's is always one: strace.list prints connect as `%s(%d,%#x,%d)`; the host-call log gives its family back),
which pages the run has touched (Sys/Mm/Mremap.v mremap_backing_uniform_b), the budget conjuncts of the memory arms
(mmap_noreserve_backed_ok, mmap_fixed_rw_budget_ok, mprotect_budget_ok, brk_budget_ok), the run's RLIMIT_NOFILE
(Sys/Fs/File.v dup3_newfd_under_limit), and the number the model would give a new descriptor (Sys/Fs/File.v
lowest_fd: the trace does not show qemu's own descriptors, so the run's numbers are shifted from the model's). A call
whose only gate is one of those passes on its name. The handler word of an rt_sigaction of SIGABRT does not pass on its
name: it is SIG_DFL for the one install the model answers there (Sys/Kernel/Signal.v sigabrt_dfl_install). A pass on
its name would admit the handler and the SIG_IGN that the model declines, so such an install is undecided.

Facts about the run that the trace does not carry, and what the checker takes for them:

- The declared private /tmp (State.v in_tmp) is empty, as State.v mkProcInput declares it. So a /tmp key exists from
  the run's own create of it until the run's own removal, and no key lives under one.
- The contents of the files the caller names in `inputs` (input.bin, which tools/checks/run-binaries writes in the
  run's working directory). A read-only descriptor of such a file has an offset the replay follows, so read, pread64
  and lseek on it have one answer each (Sys/Fs/ReadWrite.v read_spec: Fs.v file_read), and readv is held to the bytes
  that remain. The file exists: openat, faccessat and newfstatat find it (never -ENOENT) until the run's unlinkat of
  it succeeds. A descriptor that can write it, or its unlinkat, makes its contents unknown from then on.
- The abort stance: whether a SIGABRT the run sends itself is a modeled end of the run (State.v in_abort_terminal).
  The caller names it. The published statements leave it `error`, which is stance "off": every tkill and tgkill is
  then unmodeled (Sys/Kernel/Signal.v tkill_spec answers unmodeled when m_abort_terminal is false).
- The image. Pass `binary`, the fuzz target the trace is of, to give the checker its LOAD segments. Without it, an
  image test on a range that is not wholly above the run's first break declines (the model's initial break is at or
  above the image: Run.v valid_brk).

A socket's state is replayed as Sys/Net/Socket.v keeps it (SockState: fresh, bound, listening, connected, and reset
once a connection has reported its peer's ECONNRESET or ETIMEDOUT), and each socket call is answered from it.

API:
  Model.load(root) -> Model: the arms of a model checkout (root holds theories/). model.names: the modeled call
    names; model.numbers: their numbers, in spec_table's order; model.arms: number -> name.
  check_trace(model, text, *, stance, require_exit=True, binary=None, lengths=None, inputs=None) -> {"verdict": "pass"
    | "fail" | "undecided", "calls": records read, "names": sorted distinct call names, "unmodeled": [{"call", "why"}]
    in trace order, one per distinct pair, "undecided": the same for the calls the trace does not decide, "exited":
    the trace holds the run's end, "host_log": "present" | "missing", "image", "image_error"}. A host log that does
    not hold the tracer's `exec` line, and a `lengths` of None, are "missing": the run did not start, or its host
    calls were not recorded. `inputs` is {path: bytes} (above).
  STANCES.
  MODEL_COMMIT, MODEL_FILES: the model commit the rules were checked against, and the code_sha256 of every model
    file the rules rest on (tools/model_release.py).

Left out, on purpose. This module reads the published model, the trace, the binary and the run's host-call log, and
nothing else:
- A list of arms asserted ahead of the model's text, and the call names such a list would add: an arm counts only
  when the model's text has it.
- A separate number-to-name table from the build repository: the numbers are spec_table's, and SYSCALL_NUMBERS below
  is the Linux riscv64 ABI (the names qemu -strace prints), checked against the arms at load.
- Recorded transcripts of earlier runs, any export of results, and the summary lines a command-line gate prints.
- Deriving the abort stance from the binary's bytes: the stance is the published statement's, and the caller passes
  it.
"""
import pathlib
import re
import struct

import model_release
from check_build import Failed

# The model commit the rules below were read against, and the code (comments removed: model_release.code_sha256) of
# every model file they rest on, by its path in the model repository. model_release.stale() says when a release names
# a model whose code differs in one of them. Comments are not hashed, so no rule may rest on one: the arm numbers are
# read from spec_table's code and named through SYSCALL_NUMBERS.
MODEL_COMMIT = "505d161e1a2e89273739c0c44675892ed4c671a0"
MODEL_DIR = "theories/LinuxProcessSem"
MODEL_FILES = {f"{MODEL_DIR}/{rel}": digest for rel, digest in {
    "Fs.v": "9da1fca6410440131f0e55fc41cd43c15696ddc32832180597a8961ba73f4dba",
    "Monad.v": "0b0a86b9dfaa52cdfa23c0b0dcfed1b213cb569782c8a92ee384d0d6348028d1",
    "Run.v": "2176c5d4371090bf8cc663ecfad5110f49edaf225f516dd9be7700bc46e02035",
    "Specs.v": "4f010576fd8682820b6662789a97a5c9aad5cd1b2a4a83aa92df9aef7979edfc",
    "State.v": "e17836190a5fa5b66cf01ed983965face4c2d14194c7dcf93994adb0bf683a15",
    "Sys/Dispatch.v": "f5d6349b3a4a9e13922ac468207e9b8686cd3b364dc07cada11a66cd015eb0ab",
    "Sys/Drivers/Char/Random.v": "9cd3448e35d04079c8ddb3d59b7ab14c058d145b60c124b2293383aa8fec8dde",
    "Sys/Fs/DPath.v": "3e664edae9c69aa33c5ab602c1eb2923b52c0198dd1d8d4b48f93f2da41ef42b",
    "Sys/Fs/EventFd.v": "05b453d2f3ee4035527316663b1848f5be2644505eaa7aefac65e19b43b31d6e",
    "Sys/Fs/EventPoll.v": "eaab2aa1692e6190c1b85fb47374591685bb7d61db0de8122f1bf88694760563",
    "Sys/Fs/Fcntl.v": "a18e7edd08821ec6ad110fcac14db4c09a09129c0b8647df30c211e5eea5092d",
    "Sys/Fs/File.v": "bffe8531748df2b1f70237037af9000ce52897f1163aecfcbe9bbc7fe5dfee5f",
    "Sys/Fs/Ioctl.v": "d1cb316d90e11c14b866b18a6be0d29d19611886192121463444d4558045362d",
    "Sys/Fs/Locks.v": "0d68d6cb124b7fc47079ab6089f11c772850ce62a634de116efff3c1d6cf1986",
    "Sys/Fs/Namei.v": "f934277cfe58dc1283f1824ad7208b958ff8e913955ca1c2d3f084315ff6790f",
    "Sys/Fs/Open.v": "2391cfd1de518913913f36fe0e0fbdf48e2cc91825215ae42e23c27d8630db1a",
    "Sys/Fs/Pipe.v": "4cd83863f0978493018c947b805bd127e742d2d07bc067373cb6ba6ba441c794",
    "Sys/Fs/ReadWrite.v": "5b6f07d448d44d54fb03754d5dd1b846d512ea47430014122bf3f66d244145f6",
    "Sys/Fs/Readdir.v": "06beb09c7353fa0737d39ff4178dd9a7e6714d1431c8d080bfc1f4127188f35c",
    "Sys/Fs/Select.v": "2bc8e2c3ecbe35aefbfaf078b18cdbd00669974c866246393960d50bfdb5360c",
    "Sys/Fs/Stat.v": "353d58c8144726f5ac053f430f3b91275a7e244c1380129c521999523241e63b",
    "Sys/Fs/Sync.v": "f84f73b33b4f10f898abbccc7110e3c15a5dae71de3c8a07c328ebb53ab5b4a9",
    "Sys/Fs/Timerfd.v": "83d2c14645d209a7dff924eef99e48870a302bff27ab52ecee590a47fb71f1c2",
    "Sys/Kernel/Exit.v": "4e1fa49d7551887c16821b0823a0f1cbbd4c9a802fc20ac9cfe9d27e53c58f0f",
    "Sys/Kernel/Fork.v": "97476b06915bd12c42204512ef73a299b1eeb3208b87db1705dc0f2ed661fb0b",
    "Sys/Kernel/Futex/Syscalls.v": "6ee3af7d7166186ad9e4fb57fcd93f96fe1d8339752eabbe0d5057d3760dbbc4",
    "Sys/Kernel/Groups.v": "033ae29b686941c651848a02a1fc174b74135007f123e3bf0fe39e5fd19479d4",
    "Sys/Kernel/Sched/Syscalls.v": "0a87a2a1b2f77373a71f300cf7277136d2246443f2ad061c7e9a96e7f0ab3622",
    "Sys/Kernel/Signal.v": "37721a59c831003a35e3bcb2fd8f63a42216b1faa2a14585b5b1445140bcd626",
    "Sys/Kernel/Sys.v": "55f4c69db7559d1b5b876f110e361f166fa7999a4b8f6d5123908c880531081f",
    "Sys/Kernel/Time/Hrtimer.v": "5cec6e4973aea425672d0fc7a056a299c06382631caf6f64ad4ffcb2023aa75e",
    "Sys/Kernel/Time/PosixTimers.v": "fffb5d0122a401aaaf7cef55a402621426cc0cf59eec40c2623995f6a202f5d5",
    "Sys/Kernel/Time/Time.v": "add7f06013a2b3c4042904a4b22cfd388256032209432c6a32e1355bf75f56c1",
    "Sys/Mm/Madvise.v": "a158a03ed3226b75b3922fb3792b422221fff7325ca41509cf42b116577de5ef",
    "Sys/Mm/Mmap.v": "16968786f08de4b968295f722ad9d15d54df67805f21e9078054d723e07b9566",
    "Sys/Mm/Mprotect.v": "19b0cc69b9675b09fa4b5459523f77669804d20fa5a53caed58cea4e7cf0afa6",
    "Sys/Mm/Mremap.v": "1376bf68dcb8212d9f183360a2f9f5e72d26c22f4e99705b6c84a828fee4f3c4",
    "Sys/Net/Socket.v": "2adc5d93ee757a4fb0039b72add4b5beb07aeef1397524fe53c5a0492102763d",
    "Sys/Syscall.v": "a16c43acbea4480c7fd440d1edebebdfff11ac7e9c6cb22c131a00681469d3cd",
    "Sys/SyscallTable.v": "633e2c981de5d6d0a4aa6f5e0f88dcb99eb156f2ce0b29e9c48a677d1a366bf1",
    "Sys/Uaccess.v": "f71d78c20b19867ed126e50236988df07c5186b29c16e0bab65dbcd48518f276",
    "Sys/Uapi.v": "4772a5443b7edb1a041cd1cba54c6c9bb70dcc0b3685aa657233fc8f42f53928",
}.items()}
STANCES = ("off", "abort", "either")

# ---------------------------------------------------------------------------------------------------------------------
# Constants of the model. Each one is the model's definition of the same name, at MODEL_COMMIT.
# ---------------------------------------------------------------------------------------------------------------------
PAGE_SIZE = 4096                              # State.v page_size
SP_WINDOW_LO = 0x7FFF80000000                 # State.v sp_window_lo
STACK_MAX_SIZE = 8 * 1024 * 1024              # State.v stack_max_size
# State.v alloc_top is vm_init_sp - stack_max_size, and so is per run: Run.v valid_sp puts vm_init_sp anywhere in
# [sp_window_lo, sp_window_hi]. This is its smallest value. A range that ends at or below it is below every run's
# alloc_top; one that ends above it depends on the run, which the trace does not show, and declines.
ALLOC_TOP_MIN = SP_WINDOW_LO - STACK_MAX_SIZE
TASK_SIZE = 0x800000000000                    # State.v TASK_SIZE: the access_okb bound
TWO_POW_64 = 1 << 64                          # State.v two_pow_64
TWO_POW_32 = 1 << 32
RW_BYTES_MAX = 131072                         # Sys/Uaccess.v rw_bytes_max
MAX_RW_COUNT = 0x7FFFF000                     # State.v MAX_RW_COUNT: State.v rw_count_clamp caps a count at it
IOV_MAX = 1024                                # State.v IOV_MAX
UIO_FASTIOV = 8                               # Sys/Fs/ReadWrite.v UIO_FASTIOV
NAME_MAX = 255                                # Sys/Uapi.v NAME_MAX
NR_OPEN_DEFAULT = 64                          # Sys/Uapi.v NR_OPEN_DEFAULT
NSIG_BYTES = 8                                # Sys/Uapi.v NSIG_BYTES
TMP_PREFIX = "/tmp/"                          # State.v tmp_prefix
LOCALTIME_PATH = "/etc/localtime"             # Sys/Fs/Open.v localtime_path
DEVNULL_PATH = "/dev/null"                    # Sys/Uapi.v devnull_path
URANDOM_PATH = "/dev/urandom"                 # Sys/Uapi.v urandom_path
AT_REMOVEDIR = 0x200                          # Sys/Uapi.v AT_REMOVEDIR
MAP_FIXED_NOREPLACE = 0x100000                # Sys/Uapi.v MAP_FIXED_NOREPLACE: the bit qemu spells by that name
MADV_DONTNEED = 4                             # Sys/Uapi.v MADV_DONTNEED: the value qemu spells by that name
MADVISE_SYSNO = 233
GETRANDOM_SMALL_MAX = 256                     # Sys/Drivers/Char/Random.v getrandom_small_max
DIRENT64_MIN_RECLEN = 24                      # Sys/Fs/Readdir.v dirent64_min_reclen
SOCKADDR_STORAGE_SIZE = 128                   # Sys/Net/Socket.v SOCKADDR_STORAGE_SIZE
SA_FAMILY_SIZE, SOCKADDR_IN_SIZE = 2, 16      # Sys/Net/Socket.v: the family field, and a sockaddr_in
AF_UNSPEC, AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET = 0, 1, 2, 10, 16, 17
SOCK_LEVELS = {0, 1, 6}                       # Sys/Net/Socket.v sock_level_known: IPPROTO_IP, SOL_SOCKET, IPPROTO_TCP
MSG_CMSG_COMPAT = 0x80000000                  # Sys/Net/Socket.v recvmsg_spec
RLIMIT64_SIZE = 16                            # Sys/Kernel/Sys.v prlimit64_spec: the 16-byte limit pair
SIGABRT = 6
PID_MAX = 1 << 31                             # Sys/Kernel/Signal.v pid_positive: 1 <= pid < 2^31
NGROUPS_MAX = 65536                           # Sys/Uapi.v NGROUPS_MAX
PID_MAX_ENVELOPE = 1 << 22                    # Sys/Kernel/Fork.v PID_MAX_ENVELOPE: a task id is in (0, 2^22)

# Errno values, as the kernel numbers them. ERRNO_NAMES spells the ones an arm answers, for the reasons.
EPERM, ENOENT, ESRCH, EINTR, EBADF, ECHILD, EAGAIN, ENOMEM, EACCES, EFAULT = 1, 2, 3, 4, 9, 10, 11, 12, 13, 14
EEXIST, ENOTDIR, EISDIR, EINVAL, ENFILE, EMFILE, ENOTTY = 17, 20, 21, 22, 23, 24, 25
ESPIPE, ECONNRESET, EISCONN, ENOTCONN, ETIMEDOUT = 29, 104, 106, 107, 110
ERANGE, ENAMETOOLONG, ENOTSOCK, EMSGSIZE, ENOPROTOOPT, EOPNOTSUPP, EAFNOSUPPORT = 34, 36, 88, 90, 92, 95, 97
EBUSY, EROFS, EPIPE, ENOTEMPTY, EPROTONOSUPPORT, ESOCKTNOSUPPORT, EADDRINUSE = 16, 30, 32, 39, 93, 94, 98
ERRNO_NAMES = {1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 9: "EBADF", 10: "ECHILD", 11: "EAGAIN", 12: "ENOMEM",
               13: "EACCES", 14: "EFAULT", 16: "EBUSY", 17: "EEXIST", 20: "ENOTDIR", 21: "EISDIR", 22: "EINVAL",
               23: "ENFILE", 24: "EMFILE", 25: "ENOTTY", 29: "ESPIPE", 30: "EROFS", 32: "EPIPE", 34: "ERANGE",
               36: "ENAMETOOLONG", 39: "ENOTEMPTY", 88: "ENOTSOCK", 90: "EMSGSIZE", 92: "ENOPROTOOPT",
               93: "EPROTONOSUPPORT", 94: "ESOCKTNOSUPPORT", 95: "EOPNOTSUPP", 97: "EAFNOSUPPORT", 98: "EADDRINUSE",
               104: "ECONNRESET", 106: "EISCONN", 107: "ENOTCONN", 110: "ETIMEDOUT"}
# The errno sets the model's arms draw an environment's refusal from, each the model's list of the same name.
OPENAT_ERRNOS = {ENOMEM, EACCES, EMFILE, ENFILE}          # Sys/Fs/Open.v openat_errnos
MMAP_ERRNOS = {ENOMEM}                                    # Sys/Mm/Mmap.v mmap_errnos
MPROTECT_ERRNOS = {ENOMEM}                                # Sys/Mm/Mprotect.v mprotect_errnos
MREMAP_ERRNOS = {ENOMEM}                                  # Sys/Mm/Mremap.v mremap_errnos
DUP_ERRNOS = {ENOMEM, EMFILE}                             # Sys/Fs/File.v dup_errnos
CLONE_ERRNOS = {EAGAIN, ENOMEM, EMFILE, EACCES}           # Sys/Kernel/Fork.v clone_errnos
PIPE2_ERRNOS = {EMFILE, ENFILE, ENOMEM}                   # Sys/Fs/Pipe.v pipe2_errnos
GETRANDOM_ERRNOS = {EINTR}                                # Sys/Drivers/Char/Random.v getrandom_errnos
GETCWD_ERRNOS = {ENOMEM, ENOENT, ENAMETOOLONG}            # Sys/Fs/DPath.v getcwd_errnos
GETDENTS64_ERRNOS = {ENOENT}                              # Sys/Fs/Readdir.v getdents64_errnos
UNLINKAT_ERRNOS = {ENOMEM, EACCES, EPERM, EROFS, EBUSY}   # Sys/Fs/Namei.v unlinkat_errnos
SOCKET_ERRNOS = {ENOMEM, EMFILE, ENFILE}                  # Sys/Net/Socket.v socket_errnos, accept_errnos
BIND_ERRNOS = {EADDRINUSE}                                # Sys/Net/Socket.v bind_errnos, listen_errnos

# The Linux riscv64 system-call numbers of the names qemu -strace prints (asm-generic/unistd.h). The model's arms are
# numbers; this table names them. Model.load checks that every arm number is here, so an arm the table cannot name is
# an error rather than a call the checker would pass on its name.
SYSCALL_NUMBERS = {
    "getcwd": 17, "eventfd2": 19, "epoll_create1": 20, "epoll_ctl": 21, "epoll_pwait": 22, "dup": 23, "dup3": 24,
    "fcntl": 25, "ioctl": 29, "flock": 32, "unlinkat": 35, "ftruncate": 46, "faccessat": 48, "openat": 56,
    "close": 57, "pipe2": 59, "getdents64": 61, "lseek": 62, "read": 63, "write": 64, "readv": 65, "writev": 66,
    "pread64": 67, "pwrite64": 68, "pselect6": 72, "ppoll": 73, "readlinkat": 78, "newfstatat": 79, "fstat": 80,
    "fsync": 82, "fdatasync": 83, "timerfd_create": 85, "exit": 93, "exit_group": 94, "set_tid_address": 96,
    "futex": 98, "nanosleep": 101, "clock_gettime": 113, "sched_setscheduler": 119, "sched_getaffinity": 123,
    "sched_yield": 124, "tkill": 130, "tgkill": 131, "sigaltstack": 132, "rt_sigaction": 134, "rt_sigprocmask": 135,
    "setgid": 144, "setuid": 146, "setresuid": 147, "setresgid": 149, "setsid": 157, "getgroups": 158,
    "setgroups": 159, "uname": 160, "prctl": 167, "gettimeofday": 169, "getpid": 172, "getuid": 174, "geteuid": 175,
    "getgid": 176, "getegid": 177, "gettid": 178, "socket": 198, "socketpair": 199, "bind": 200, "listen": 201,
    "accept": 202, "connect": 203, "getsockname": 204, "getpeername": 205, "sendto": 206, "recvfrom": 207,
    "setsockopt": 208, "getsockopt": 209, "shutdown": 210, "sendmsg": 211, "recvmsg": 212, "brk": 214, "munmap": 215,
    "mremap": 216, "clone": 220, "mmap": 222, "mprotect": 226, "madvise": 233, "accept4": 242, "wait4": 260,
    "prlimit64": 261, "getrandom": 278, "clone3": 435, "faccessat2": 439,
}

# ---------------------------------------------------------------------------------------------------------------------
# The model, read from a checkout
# ---------------------------------------------------------------------------------------------------------------------
SPEC_TABLE_CODE = re.compile(r"^Definition spec_table : list SpecArm :=(.*?)^\s*nil\s*\.", re.S | re.M)
ARM = re.compile(r"mkSpecArm\s+(\S+?)\s*%Z")
SYSNOS_DERIVED = re.compile(r"^Definition modeled_sysnos : list Z := arm_numbers spec_table\s*\.", re.M)
NOREPLACE_DEFS = ("mmap_noreplace_flags_b", "mmap_noreplace_rw_b", "mmap_noreplace_noaccess_b")
NOREPLACE_ARMS = ("mmap_noreplace_noaccess_b", "mmap_noreplace_rw_b")
MADVISE_DEFS = ("madvise_dontneed_b", "madvise_dontneed_ok", "madvise_dontneed_next", "madvise_spec")
MADVISE_ARM = "madvise_dontneed_ok"


def _model_file(root, rel):
    """(text, code) of one file of the model: its text, and its code with the comments removed
    (model_release.rocq_code) as one string."""
    path = pathlib.Path(root) / MODEL_DIR / rel
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise Failed(f"the model checkout {root} has no readable {MODEL_DIR}/{rel}: {e}") from None
    return text, "\n".join(model_release.rocq_code(text))


def _spec_table(root):
    """{number: name} of spec_table's arms, in the table's order, read from the table's CODE (the names are
    SYSCALL_NUMBERS'). Anything that would make the result other than the numbers the dispatcher answers is an error:
    no table, no arm, an arm whose number this parser cannot read, a number listed twice (Sys/Dispatch.v lookup_arm
    takes the first match, so a second arm would never answer), or a number SYSCALL_NUMBERS cannot name."""
    rel = "Sys/SyscallTable.v"
    _, code = _model_file(root, rel)
    m = SPEC_TABLE_CODE.search(code)
    if not m:
        raise Failed(f"{rel} has no `Definition spec_table : list SpecArm := ... nil.`")
    body = m.group(1)
    spelled = ARM.findall(body)
    if not spelled:
        raise Failed(f"spec_table in {rel} has no arm")
    if body.count("::") != len(spelled) or not all(n.isdigit() for n in spelled):
        raise Failed(f"spec_table in {rel} has an arm whose number this parser cannot read")
    numbers = [int(n) for n in spelled]
    twice = sorted({n for n in numbers if numbers.count(n) > 1})
    if twice:
        raise Failed(f"spec_table in {rel} lists the number {twice} more than once")
    by_number = {n: name for name, n in SYSCALL_NUMBERS.items()}
    unknown = [n for n in numbers if n not in by_number]
    if unknown:
        raise Failed(f"spec_table in {rel} has arm(s) {unknown}, which SYSCALL_NUMBERS does not name")
    return {n: by_number[n] for n in numbers}


def _definition(code, name):
    return re.search(rf"^(?:Local )?Definition {name}\b", code, re.M) is not None


def _check_arms_present(root, arms):
    """Raise unless the model has the two arms this checker transcribes whole: MAP_FIXED_NOREPLACE in
    Sys/Mm/Mmap.v mmap_spec, and madvise (Sys/Mm/Madvise.v madvise_spec, arm 233), with the constants qemu -strace
    spells by name at the values qemu means."""
    missing = []
    _, mmap = _model_file(root, "Sys/Mm/Mmap.v")
    missing += [f"Sys/Mm/Mmap.v {d}" for d in NOREPLACE_DEFS if not _definition(mmap, d)]
    missing += [f"the mmap_spec arm `if {a} ... then`" for a in NOREPLACE_ARMS
                if not re.search(rf"\bif {a}\b[^\n]*\bthen\b", mmap)]
    _, madvise = _model_file(root, "Sys/Mm/Madvise.v")
    missing += [f"Sys/Mm/Madvise.v {d}" for d in MADVISE_DEFS if not _definition(madvise, d)]
    if not re.search(rf"\bif {MADVISE_ARM}\b[^\n]*\bthen\b", madvise):
        missing.append(f"the madvise_spec arm `if {MADVISE_ARM} ... then`")
    if arms.get(MADVISE_SYSNO) != "madvise":
        missing.append(f"spec_table arm {MADVISE_SYSNO} (madvise)")
    _, uapi = _model_file(root, "Sys/Uapi.v")
    for name, want in (("MAP_FIXED_NOREPLACE", MAP_FIXED_NOREPLACE), ("MADV_DONTNEED", MADV_DONTNEED)):
        m = re.search(rf"^Definition {name} : Z := (\d+)%Z\s*\.", uapi, re.M)
        if not m:
            missing.append(f"Sys/Uapi.v {name}")
        elif int(m.group(1)) != want:
            raise Failed(f"Sys/Uapi.v defines {name} as {int(m.group(1)):#x}, not {want:#x}, the value qemu -strace "
                         "spells by that name")
    if missing:
        raise Failed("the model lacks what these rules transcribe: " + "; ".join(missing))


def _brk_aslr_max(root):
    """State.v brk_aslr_max, in bytes: how far above the image top the initial break may be (Run.v valid_brk)."""
    _, code = _model_file(root, "State.v")
    m = re.search(r"^Definition brk_aslr_max : Z := \(?\s*([0-9][0-9 *]*?)\s*\)?%Z\s*\.", code, re.M)
    if not m:
        raise Failed("State.v has no `Definition brk_aslr_max : Z := <number or product>%Z.`")
    value = 1
    for factor in m.group(1).split("*"):
        value *= int(factor)
    return value


class Model:
    """The arms of one checkout of the model. Model.load(root) reads it; root is the checkout (it holds theories/)."""

    def __init__(self, root, arms, brk_aslr_max):
        self.root = pathlib.Path(root)
        self.arms = dict(arms)
        self.names = frozenset(self.arms.values())
        self.numbers = tuple(self.arms)
        self.brk_aslr_max = brk_aslr_max

    @classmethod
    def load(cls, root):
        """The Model of the checkout `root`. Specs.v must define modeled_sysnos as the arms of spec_table, so that the
        table is what the dispatcher answers (Specs.v syscall_spec)."""
        arms = _spec_table(root)
        _, specs = _model_file(root, "Specs.v")
        if not SYSNOS_DERIVED.search(specs):
            raise Failed("Specs.v does not define `modeled_sysnos := arm_numbers spec_table`")
        _check_arms_present(root, arms)
        return cls(root, arms, _brk_aslr_max(root))


# ---------------------------------------------------------------------------------------------------------------------
# Reading a qemu -strace trace
# ---------------------------------------------------------------------------------------------------------------------
# A record: qemu's task id, the name, the open parenthesis. A record starts a line, and a second record can follow on
# the same line (split_records). The look-behind starts a search only at the head of a run of digits: the earliest
# match is there anyway, and without it a long run of digits costs time quadratic in its length.
RECORD = re.compile(r"(?<![0-9])(\d+)\s+([a-z_0-9]+)\(")
# qemu's line for a syscall number it has no name for (linux-user/strace.c print_syscall). It can follow an open
# record on the same line, so it is searched for anywhere.
UNKNOWN_RECORD = re.compile(r"(?:^|(?<=[\s)]))(\d+) Unknown syscall (\d+)")
# The return value and the errno, read from the text after the call's own `)`, never from the whole line.
RET_TAIL = re.compile(r"\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
ERRNO_TAIL = re.compile(r"\s*=\s*-1\s+errno=(\d+)")
# qemu's line for the SIGABRT death after a self-kill: `--- SIGIOT {si_signo=SIGIOT, si_code=SI_TKILL, ...} ---`.
# It too can land after an open record. kill_line reads the braces itself.
KILL_HEAD = re.compile(r"---\s+SIG(?:IOT|ABRT)\s+\{")
EXIT_NAMES = {"exit", "exit_group"}


def kill_line(line):
    """True when the line holds qemu's SIGABRT line for a self-kill: a `--- SIGIOT {` (or SIGABRT) whose braces hold
    si_code=SI_TKILL. Each head is read up to its first `}`; a head inside text already read is skipped, so a line of
    many heads costs time linear in its length."""
    read_to = 0
    for head in KILL_HEAD.finditer(line):
        if head.start() < read_to:
            continue
        close = line.find("}", head.end())
        if close < 0:
            return False
        if "si_code=SI_TKILL" in line[head.end():close]:
            return True
        read_to = close
    return False


def scan_call(text, start=0):
    """(arguments, index just past the call's closing parenthesis, closed) of the argument list that starts at
    `start` in `text`. Quoted strings, structs and bracketed signal sets are kept whole. `closed` is False when the
    list has no closing parenthesis in the text (the record is cut, or a quoted string swallowed the rest)."""
    args, depth, cur, quoted = [], 0, [], False
    for i in range(start, len(text)):
        ch = text[i]
        if quoted:
            cur.append(ch)
            if ch == '"':
                quoted = False
            continue
        if ch == '"':
            quoted = True
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            if depth == 0:
                arg = "".join(cur).strip()
                if arg:
                    args.append(arg)
                return args, i + 1, True
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    arg = "".join(cur).strip()
    if arg:
        args.append(arg)
    return args, len(text), False


def split_records(line):
    """Yield (tid, name, args, tail, closed) for every record on one line. qemu writes a record's arguments when the
    call is made and its result when it returns, so a thread that blocks leaves its line open, and another task's
    record lands on the same line. Each argument list is walked with scan_call, so a quoted path that looks like a
    record does not start one. A blocked call's result arrives later on a line of its own, which starts no record:
    that call has no return here."""
    line = line.rstrip("\n")
    m = RECORD.match(line)
    while m:
        args, off, closed = scan_call(line, m.end())
        nxt = RECORD.search(line, off)
        yield int(m.group(1)), m.group(2), args, line[off:nxt.start() if nxt else len(line)], closed
        m = nxt


def bits(arg):
    return {b.strip() for b in arg.split("|") if b.strip()}


def num(arg):
    """A scalar argument as qemu prints it (decimal, 0x hex, NULL, or `(nil)`), or None."""
    a = arg.strip()
    if a in ("NULL", "0", "(nil)"):
        return 0
    try:
        return int(a, 16) if a.lower().startswith(("0x", "-0x")) else int(a, 10)
    except ValueError:
        return None


def is_null(arg):
    """True when qemu printed a NULL pointer, False when it printed something else. A struct qemu printed in place of
    a pointer (`{tv_sec = ...}`, `{sin_family=...}`) is NOT NULL: qemu prints the struct only when it could read the
    memory behind the pointer."""
    return arg.strip() in ("NULL", "(nil)", "0", "0x0")


def sym(arg, table):
    """A scalar qemu may print by name: the table's value for a known name, else the number, else None."""
    a = arg.strip()
    return table[a] if a in table else num(a)


def flagword(arg, table):
    """A flag word qemu prints as `A|B|0x40`: the OR of the known names and the numbers, or None."""
    total = 0
    for part in bits(arg):
        if part in table:
            total |= table[part]
            continue
        v = num(part)
        if v is None:
            return None
        total |= v
    return total


def quoted(arg):
    """(text, truncated) of a quoted string argument, or None. qemu ends a string it cut short with `...`."""
    a = arg.strip()
    if not a.startswith('"'):
        return None
    end = a.rfind('"')
    if end <= 0:
        return None
    return a[1:end], a.endswith("...")


def low32(v):
    """The low 32 bits of a register, as Sys/Syscall.v int32, flag32 and fd32 read it."""
    return None if v is None else v & 0xFFFFFFFF


def sint32(v):
    """The low 32 bits read as a signed number (Sys/Syscall.v sint32)."""
    if v is None:
        return None
    x = v & 0xFFFFFFFF
    return x - TWO_POW_32 if x >= (1 << 31) else x


def page_round_up(n):
    return ((n + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE


def parse_ret(tail):
    """The return value in the text after a call's `)`, or None (the call blocked, or the text is cut)."""
    r = RET_TAIL.match(tail)
    if not r:
        return None
    v = r.group(1)
    try:
        return int(v, 16) if "x" in v else int(v)
    except ValueError:
        return None


def ret_text(ret, errno):
    """A return as the trace spells it, for a reason."""
    if ret is None:
        return "no return in the trace"
    if ret < 0 and errno is not None:
        return f"-1 errno={errno}"
    return f"{ret:#x}" if ret > 0xFFFF else str(ret)


def errno_only(ret, errno, allowed, what, cite):
    """The reason a call is outside an arm that answers only an errno in `allowed` (the refusing half of a call), or
    None. A call with no return (it blocked) is judged on its arguments."""
    if ret is None or (ret < 0 and errno in allowed):
        return None
    names = "/".join("-" + ERRNO_NAMES.get(e, f"errno {e}") for e in sorted(allowed))
    return f"{what} returned {ret_text(ret, errno)}: the model answers only {names} there ({cite})"


def errno_in(ret, errno, allowed, what, cite):
    """The reason a call that FAILED carries an errno its arm does not answer, or None. The arm's success is not
    judged here: use errno_only for an arm that only refuses."""
    if ret is None or ret >= 0:
        return None
    return errno_only(ret, errno, allowed, what, cite)


def refused(ret, errno, errnos, what, cite):
    """The reason a FAILED call carries an errno outside `errnos`, or None (also for a success or no return)."""
    if ret is None or ret >= 0 or errno in errnos:
        return None
    if not errnos:
        return f"{what} returned {ret_text(ret, errno)}: the model answers no errno there ({cite})"
    return errno_only(ret, errno, errnos, what, cite)


def answered(ret, errno, values, errnos, what, cite):
    """The reason a call answered neither an errno of `errnos` nor a success in `values`, or None. A call with no
    return (it blocked) is judged on its arguments."""
    if ret is None or (ret >= 0 and ret in values):
        return None
    if ret < 0:
        return refused(ret, errno, errnos, what, cite)
    shown = "/".join(str(v) for v in sorted(values)) or "no success"
    return f"{what} returned {ret_text(ret, errno)}: the model's success there is {shown} ({cite})"


def counted(ret, errno, count, errnos, what, cite, shape="upto"):
    """The reason a read- or write-like call answered neither an errno of `errnos` nor a byte count its arm gives, or
    None. `count` is the call's count (an Arg); the arm's success is, by `shape`: "upto", any of 0..rw_count_clamp
    count; "positive", the same but at least 1 when the count is not 0; "exact", exactly rw_count_clamp count (State.v
    rw_count_clamp caps at MAX_RW_COUNT). `count` None is a total the trace does not show (an iovec array), which the
    model caps at MAX_RW_COUNT (State.v cap_iovecs). A count qemu printed in 32 bits is some v + k * 2**32, so an
    answer that only some of those counts give is undecided."""
    if ret is None:
        return None
    if ret < 0:
        return refused(ret, errno, errnos, what, cite)
    if count is None:
        if ret <= MAX_RW_COUNT:
            return None
        return f"{what} returned {ret}, more than MAX_RW_COUNT ({MAX_RW_COUNT}), which caps it ({cite})"
    least = min(count.v, MAX_RW_COUNT)
    pinned = count.exact or count.v >= MAX_RW_COUNT
    if shape == "exact":
        if ret == least and pinned:
            return None
        if not pinned and ret in (least, MAX_RW_COUNT):
            return undecided(f"the count of {what}")
        want = least if pinned else f"{least} or {MAX_RW_COUNT}"
        return f"{what} returned {ret}: the model answers exactly the clamped count, {want} ({cite})"
    if ret > MAX_RW_COUNT or (pinned and ret > least):
        return f"{what} returned {ret}, more than the {least} bytes it asked for ({cite}: State.v rw_count_clamp)"
    if ret > least:
        return undecided(f"the count of {what}")
    if shape == "positive" and ret == 0:
        zero = count.is_zero()
        if zero is False:
            return f"{what} of {count.v} bytes returned 0: the model moves at least one byte or fails ({cite})"
        if zero is None:
            return undecided(f"the count of {what}")
    return None


class Undecided(str):
    """A reason that is not a verdict against the run: the trace does not show something the model's answer turns on,
    so this call decides nothing either way. check_trace reports these apart from the unmodeled calls."""


def undecided(what):
    """The reason a call decides nothing because the trace does not pin a register the model's answer turns on."""
    return Undecided(f"{what} is not pinned by the trace or by the run's host-call log, and a larger register would "
                     "change the model's answer")


def und(text):
    """A reason of a call the trace does not decide (Undecided)."""
    return Undecided(text)


# ---------------------------------------------------------------------------------------------------------------------
# Arguments qemu prints through a 32-bit format
# ---------------------------------------------------------------------------------------------------------------------
class Arg:
    """One argument of a guest call as the trace pins it. `v` is the value; `exact` says the trace (or the run's
    host-call log) pins the whole 64-bit register. When it does not, the register is some `v + k * 2**32` with k >= 0,
    because qemu printed only its low 32 bits, and every test below answers None when the candidates disagree."""

    __slots__ = ("v", "exact")

    def __init__(self, v, exact):
        self.v = v
        self.exact = exact

    def __repr__(self):
        return f"Arg({self.v}, exact={self.exact})"

    @classmethod
    def full(cls, v):
        """An argument qemu printed in full (a pointer, or the generic 64-bit decimal format), as an unsigned
        register."""
        return None if v is None else cls(v & (TWO_POW_64 - 1), True)

    @classmethod
    def cut(cls, v):
        """An argument qemu printed through a 32-bit format: its low 32 bits, signed or unsigned as printed."""
        return None if v is None else cls(v & 0xFFFFFFFF, False)

    @classmethod
    def sext(cls, v):
        """An argument the guest passes as a 32-bit int, sign-extended to the whole register. The RISC-V calling
        convention (riscv-elf-psabi-doc, the RVG calling convention: a scalar narrower than XLEN is widened by the
        sign of its type to 32 bits and then SIGN-extended to XLEN) makes the register the sign extension of the
        32 bits qemu printed, for an unsigned 32-bit type as well. The trace cannot check it: a guest written in
        assembly could put anything in the top half, and the model, which reads the whole register, would answer
        unmodeled where this reading answers the arm."""
        if v is None:
            return None
        low = v & 0xFFFFFFFF
        return cls(low - TWO_POW_32 + TWO_POW_64 if low >= (1 << 31) else low, True)

    def known(self, what):
        """The reason this argument's register is not pinned, or None when it is."""
        if self.exact:
            return None
        return undecided(f"{what} ({self.v} as qemu printed it)")

    def le(self, bound):
        """True, False or None (not decided): is the register at most `bound`?"""
        if self.v > bound:
            return False
        return True if self.exact else None

    def ge(self, bound):
        r = self.le(bound - 1)
        return None if r is None else not r

    def eq(self, value):
        """True, False or None: is the register exactly `value`?"""
        if self.exact:
            return self.v == value
        if value < self.v or (value - self.v) % TWO_POW_32:
            return False
        return None

    def is_zero(self):
        if self.v != 0:
            return False
        return True if self.exact else None

    def aligned(self, n):
        """True or False: is the register a multiple of `n`? A cut print still pins this for any n dividing 2**32."""
        if TWO_POW_32 % n == 0 or self.exact:
            return self.v % n == 0
        return None

    def paged(self):
        """The length as qemu hands it to the host: rounded up to a whole page (TARGET_PAGE_ALIGN, which target_mmap,
        target_munmap, target_mprotect and target_madvise apply before their host call, linux-user/mmap.c at
        v10.0.11), pinned as this one is. A cut print pins the rounded value's low 32 bits too, since 2**32 is a
        multiple of the page. None for a whole register within a page of 2**64: its rounding wraps to 0, and qemu
        answers the call itself, with no host call."""
        rounded = page_round_up(self.v)
        if self.exact:
            return Arg(rounded, True) if rounded < TWO_POW_64 else None
        return Arg(rounded % TWO_POW_32, False)

    def unpaged(self, host):
        """The whole register whose page rounding is the host call's length `host`, or None when no register this
        print allows rounds to it. Exactly one value in (host - PAGE_SIZE, host] has this print's low 32 bits."""
        if self.exact:
            return self if page_round_up(self.v) == host else None
        v = host - (host - self.v) % TWO_POW_32
        return Arg(v, True) if 0 <= v and host - PAGE_SIZE < v and page_round_up(v) == host else None


# ---------------------------------------------------------------------------------------------------------------------
# The run's host-call log (tools/checks/host-calls.c)
# ---------------------------------------------------------------------------------------------------------------------
# One line per host system call of the names below, whether it succeeded or failed:
#     <name> <result, signed decimal> <argument 0> ... <argument 5>     the arguments in hex
# a connect line ends with one more field, the first two bytes of the address it names (its family, as a little-endian
# hex number), or `-` when its addrlen is below 2 or the tracer could not read them; and the single line `exec` when the
# traced program started. qemu hands most of the guest's arguments to the host unchanged (with no -R, a guest address
# is the host address), so a host line gives back what qemu's 32-bit -strace format cut. Two cases differ:
#   - the length of mmap, munmap, mprotect and madvise, which qemu rounds up to a whole page first (TARGET_PAGE_ALIGN in
#     target_mmap, target_munmap, target_mprotect and target_madvise, linux-user/mmap.c at v10.0.11). The guest's
#     length is keyed by its rounding, and recovered from the host's (Arg.paged, Arg.unpaged): the Go runtime maps
#     lengths that are not whole pages;
#   - connect's address, which qemu copies into its own buffer (target_to_host_sockaddr), so its line is keyed by the
#     descriptor, the addrlen and the result, and gives the family that the guest's address names.
# (qemu 8.2 also hands the host 0 and -1 for the offset and descriptor of every anonymous mmap, so its log cannot show
# an offset's top half: no 8.2 run is read.)
# A guest call takes the first unused line of the same name that agrees with every printed argument it can be keyed on
# (in the low 32 bits for a cut print, in full for the rest) and with the guest's result (HostLog.take): qemu answers
# some calls itself, with no host call (an address it cannot lock is -EFAULT; MAP_FIXED at an unaligned address is
# -EINVAL; most madvise advice is 0), and its own calls (its loading of the program, its start-up mappings, its log)
# are in the log too. A call of qemu's own, or a later guest call, can still agree with a guest call's print and
# result, so lines are not dropped; instead, a guest call takes a value only when EVERY unused line that agrees gives
# the same value. Where they disagree, the argument stays unpinned, and the rules decline what it would decide.
HOST_NAMES = ("mmap", "munmap", "mprotect", "madvise", "mremap", "read", "write", "pread64", "pwrite64", "getrandom",
              "getcwd", "sendto", "connect")
HOST_LINE = re.compile(r"(" + "|".join(HOST_NAMES) + r") (-?\d+)((?: [0-9a-fA-F]+){6})(?: ([0-9a-fA-F]{1,4}|-))?\s*$")
HOST_RESULT, HOST_FAMILY = 6, 7     # the indexes of a host line's result and connect family, after its six arguments
EXEC_LINE = "exec"


class _Bucket:
    """The lines of one host-call name that agree with one projection of the keys, in the log's order: `rows` their
    indexes, `head` the first that may be unused, `answers` the wanted values of the unused ones, counted."""

    __slots__ = ("rows", "head", "answers")

    def __init__(self):
        self.rows, self.head, self.answers = [], 0, {}


class HostLog:
    """The host calls of one run, in the log's order, with the lines a guest call has already taken removed.

    A guest call's keys are each pinned in full (exact) or in their low 32 bits, so the lines that agree with them are
    exactly the lines whose projection (each keyed argument in full or in its low 32 bits, as the key is) equals the
    keys'. take builds one index per (name, which keys and how pinned, wanted), once, and keeps in each bucket the
    count of every wanted value among its unused lines, so a run's matching costs time linear in its two logs."""

    def __init__(self, text):
        self.started = False
        self.lines = []            # [(name, result, (a0..a5, result mod 2**64, family or None), taken)]
        for raw in (text or "").splitlines():
            line = raw.strip()
            if line == EXEC_LINE:
                self.started = True
                continue
            m = HOST_LINE.fullmatch(line)
            # Only a connect line carries the family field.
            if m and (m.group(4) is None or m.group(1) == "connect"):
                result = int(m.group(2))
                family = int(m.group(4), 16) if m.group(4) not in (None, "-") else None
                values = tuple(int(a, 16) for a in m.group(3).split()) + (result % TWO_POW_64, family)
                self.lines.append([m.group(1), result, values, False])
        self.given = text is not None
        self._by_name = {}         # name -> [line index]
        for n, row in enumerate(self.lines):
            self._by_name.setdefault(row[0], []).append(n)
        self._indexes = {}         # (name, shape, wanted) -> {projection: _Bucket}

    @staticmethod
    def _project(values, shape):
        return tuple(values[i] if exact else values[i] % TWO_POW_32 for i, exact in shape)

    def _index(self, name, shape, wanted):
        key = (name, shape, wanted)
        index = self._indexes.get(key)
        if index is None:
            index = {}
            for n in self._by_name.get(name, ()):
                row = self.lines[n]
                if row[3]:
                    continue
                bucket = index.setdefault(self._project(row[2], shape), _Bucket())
                bucket.rows.append(n)
                answer = tuple(row[2][i] for i in wanted)
                bucket.answers[answer] = bucket.answers.get(answer, 0) + 1
            self._indexes[key] = index
        return index

    def _use(self, n):
        """Mark line n taken, and drop it from every index built for its name."""
        row = self.lines[n]
        row[3] = True
        for (name, shape, wanted), index in self._indexes.items():
            if name != row[0]:
                continue
            answers = index[self._project(row[2], shape)].answers
            answer = tuple(row[2][i] for i in wanted)
            answers[answer] -= 1
            if not answers[answer]:
                del answers[answer]

    def take(self, name, keys, wanted, ret, errno):
        """The full values of the arguments `wanted` (indexes) of one host call of `name`, or None. `keys` is
        {index: Arg} that the host line must agree with, and the line's result must be the guest's (`ret`, and
        `errno` for a failure): qemu gives the guest the host's result unchanged when it makes the host call, so a
        call that qemu answered itself, with no host call, cannot take a line of another call that agrees with its
        print (qemu's own start-up calls succeed, and a later guest call has its own result). With `ret` None (the
        trace shows no return) the result is not keyed. The first unused agreeing line is taken, and None comes back
        when the agreeing lines disagree on a wanted value."""
        if ret is not None:
            keys = {**keys, HOST_RESULT: Arg.full((ret if ret >= 0 else -(errno or 0)) % TWO_POW_64)}
        shape = tuple(sorted((i, a.exact) for i, a in keys.items()))
        wanted = tuple(wanted)
        probe = tuple(keys[i].v if exact else keys[i].v % TWO_POW_32 for i, exact in shape)
        bucket = self._index(name, shape, wanted).get(probe)
        if bucket is None or len(bucket.answers) != 1:
            return None
        while self.lines[bucket.rows[bucket.head]][3]:
            bucket.head += 1
        n = bucket.rows[bucket.head]
        answer = tuple(self.lines[n][2][i] for i in wanted)
        self._use(n)
        return dict(zip(wanted, answer))


# ---------------------------------------------------------------------------------------------------------------------
# The image
# ---------------------------------------------------------------------------------------------------------------------
PT_LOAD = 1
EM_RISCV = 243


def image_spans(path):
    """[(address, length)] of a riscv64 ELF binary's reservations: each LOAD segment with bytes in memory, rounded out
    to whole pages as Run.v segment_reservation rounds it. Raises Failed on a file that is not such a binary."""
    try:
        data = pathlib.Path(path).read_bytes()
    except OSError as e:
        raise Failed(f"cannot read the binary {path}: {e}") from None
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise Failed(f"{path} is not a 64-bit little-endian ELF file")
    if struct.unpack_from("<H", data, 18)[0] != EM_RISCV:
        raise Failed(f"{path} is not a RISC-V binary")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or phnum == 0xFFFF or phoff + phnum * 56 > len(data):
        raise Failed(f"{path} has a program header table this reader cannot read")
    spans = []
    for i in range(phnum):
        p = phoff + i * 56
        if struct.unpack_from("<I", data, p)[0] != PT_LOAD:
            continue
        vaddr, memsz = struct.unpack_from("<Q", data, p + 16)[0], struct.unpack_from("<Q", data, p + 40)[0]
        if memsz:
            lo = vaddr // PAGE_SIZE * PAGE_SIZE
            spans.append((lo, page_round_up(vaddr + memsz) - lo))
    if not spans:
        raise Failed(f"{path} has no LOAD segment, so its image cannot be placed")
    return spans


IMAGE_UNKNOWN = ("the image's place is not known (no binary was given) and the range is not wholly above the run's "
                 "first break, under which the image lies (Run.v valid_brk)")


# ---------------------------------------------------------------------------------------------------------------------
# The replay of the model's state
# ---------------------------------------------------------------------------------------------------------------------
# The model's address-space ledgers are lists of (base, length) entries (State.v VmMaps): vm_reserved, the image's
# reservations; vm_maps, the live anonymous mappings and brk grants; vm_noaccess, the PROT_NONE ranges. A run starts
# with vm_maps and vm_noaccess empty and the three channels open (State.v init_model). These are the model's own
# operations on the lists (State.v), in integers.
def iv_subtract(a, sz, lo, hi):
    """State.v iv_subtract: what is left of the entry (a, sz) outside [lo, hi): no, one or two entries."""
    out = []
    if a < lo:
        out.append((a, min(sz, lo - a)))
    if hi < a + sz:
        start = max(a, hi)
        out.append((start, a + sz - start))
    return out


def maps_subtract(entries, lo, hi):
    """State.v maps_subtract: every entry with [lo, hi) cut out of it."""
    return [piece for a, sz in entries for piece in iv_subtract(a, sz, lo, hi)]


def region_free(entries, lo, n):
    """State.v region_free: True when [lo, lo + n) meets no entry (State.v iv_overlap)."""
    return not any(lo < a + sz and a < lo + n for a, sz in entries)


def map_contains(entries, lo, n):
    """State.v map_contains: True when [lo, lo + n) lies inside ONE entry. The model never merges entries, so a range
    that two adjacent entries cover is not contained."""
    return any(a <= lo and lo + n <= a + sz for a, sz in entries)


def map_remove(entries, lo):
    """State.v map_remove: the entries with every one based at lo dropped."""
    return [(a, sz) for a, sz in entries if a != lo]


UNCERTAIN = ("an earlier MAP_FIXED that failed over live memory may have unmapped this range or left it in place "
             "(Sys/Mm/Mmap.v mmap_spec answers -ENOMEM both ways, the second through mmap_fixed_destroyed_next), and "
             "the trace does not say which")
# A descriptor's kind, as State.v FdEntry names it. The replay stores a tuple: ("channel", n), ("file", path) for
# FdFile, ("filew", path), ("filea", path), ("filerw", path), ("dir",), ("devnull", readable, writable),
# ("urandom",), ("socket", True) for a fresh socket (State.v SkFresh), ("socket", False, state) once a bind, listen or
# accept has made it SkBound ("bound"), SkListening ("listening") or SkConnected ("connected"), or a connection's
# reported peer error has made it SkReset ("reset"), and ("pipe", writable).
FILE_KINDS = ("file", "filew", "filea", "filerw")
KIND_NAMES = {"channel": "channel", "file": "read-only file", "filew": "write-only file",
              "filea": "append file", "filerw": "read-write file", "dir": "directory", "devnull": "/dev/null",
              "urandom": "/dev/urandom", "socket": "socket", "pipe": "pipe end"}
ABSENT = ("absent",)


def kind_name(kind):
    """The model's name for a descriptor's entry (State.v FdEntry)."""
    return KIND_NAMES[kind[0]]


def sock_state(kind):
    """A socket kind's SockState: "fresh", "bound", "listening", "connected" or "reset"."""
    return "fresh" if kind[1] else kind[2]


def sock_connected(kind):
    return kind[0] == "socket" and sock_state(kind) == "connected"


# The errnos with which a connection reports its peer's reset or timeout once, moving the socket to SkReset
# (Sys/Net/Socket.v send_on_socket, Sys/Fs/ReadWrite.v socket_pending_error and readv_spec).
PEER_ERRNOS = {ECONNRESET, ETIMEDOUT}


def peer_error(run, fd, ret, errno):
    """After a read, readv, sendto or sendmsg on a connected socket that the model allows: a peer error it reported
    moves the socket to SkReset."""
    if ret is not None and ret < 0 and errno in PEER_ERRNOS:
        run.led.fds[fd] = ("socket", False, "reset")


def forget_contents(run, path):
    """Stop treating `path`'s contents as known: a descriptor that can write it, or its removal, changes what later
    reads of the name see. The name stays in run.present until a removal succeeds."""
    run.inputs.pop(path, None)
    for fd, kind in run.led.fds.items():
        if kind[0] in FILE_KINDS and kind[1] == path:
            run.led.offsets.pop(fd, None)


class Ledger:
    """A replay, from one run's trace, of the model's state that the trace shows: the address-space ledgers (State.v
    VmMaps: vm_reserved, vm_maps, vm_noaccess, vm_brk), the descriptor table (m_fds), the /tmp keys the run holds, the
    pinned tid (m_tid), and the one-way flags m_rlimit_core and m_sigaltstack_installed."""

    def __init__(self, reserved):
        self.reserved = None if reserved is None else list(reserved)   # vm_reserved, or None when not known
        self.maps = []          # vm_maps
        self.noaccess = []      # vm_noaccess
        self.brk = None         # vm_brk
        self.min_brk = None     # vm_start_brk: the run's initial break, from its first brk call when that is a query
        self.brk_calls = 0
        self.brk_unknown = False
        # Ranges whose state the trace does not decide: a MAP_FIXED over live memory that failed (it may have unmapped
        # its range or not), or one with no return in the trace. A later call that needs to know what is there declines.
        self.uncertain = []
        # The /tmp keys the run holds: created by the run, not yet removed by it (the declared /tmp is empty).
        self.tmp_held = set()
        # m_fds. State.v init_model opens the three channels and nothing else.
        self.fds = {0: ("channel", 0), 1: ("channel", 1), 2: ("channel", 2)}
        # A successful pipe2 installs two descriptors at numbers the trace does not show (they are written to memory,
        # and the model's own numbering is shifted from the run's by qemu's descriptors). While this is set, a
        # descriptor the replay does not hold may be a pipe end.
        self.pipe_fds_unknown = False
        self.tid = None                     # m_tid
        self.rlimit_core_read = False       # m_rlimit_core is no longer None
        self.rlimit_core_hard = None        # rlim64_hard of the successful read print, or None when qemu omitted it
        self.sigaltstack_installed = False  # m_sigaltstack_installed
        self.setsid_done = False            # m_setsid_succeeded
        self.ngroups = None                 # the run's number of groups (cr_groups), once an answer has shown it
        self.rlimit_core = None             # (rlim_cur, rlim_max) of m_rlimit_core, once the trace has shown it
        self.ids = {}                       # the first answer of each uid and gid read since the last set*id
        # The offset of each read-only descriptor on a file whose contents the run's environment fixes (FdFile path
        # off), while the trace pins it; a descriptor that is not here has an offset the replay does not know.
        self.offsets = {}

    # -- the address space ------------------------------------------------------------------------------------------
    def image_clear(self, addr, n):
        """True when [addr, addr + n) is clear of the image, False when it meets it, None when that is not known."""
        if self.reserved is not None:
            return region_free(self.reserved, addr, n)
        if self.min_brk is not None and addr >= self.min_brk:
            return True
        return None

    def unknown(self, addr, n):
        """Why the replay cannot say what the model holds over [addr, addr + n), or None when it can."""
        if not region_free(self.uncertain, addr, n):
            return UNCERTAIN
        if self.image_clear(addr, n) is None:
            return IMAGE_UNKNOWN
        return None

    def brk_shrink(self, lo, hi):
        """Sys/Mm/Mmap.v brk_maps_next and brk_unmaps for a shrink from hi to lo."""
        self.maps = maps_subtract(self.maps, lo, hi)
        plo, phi = page_round_up(lo), page_round_up(hi)
        if plo < phi:
            self.noaccess = maps_subtract(self.noaccess, plo, phi)

    # -- the descriptor table ---------------------------------------------------------------------------------------
    def kind(self, fd):
        """The descriptor's entry: a kind tuple, ABSENT when the model's table surely has no such descriptor, or None
        when the trace does not say (a pipe end this run made)."""
        if fd is None:
            return None
        if fd in self.fds:
            return self.fds[fd]
        return None if self.pipe_fds_unknown else ABSENT

    def path_openers(self, path):
        """Sys/Fs/Locks.v path_openers: how many descriptors name this file."""
        return sum(1 for k in self.fds.values() if k[0] in FILE_KINDS and k[1] == path)

    def names_key(self, path):
        return self.path_openers(path) > 0


# ---------------------------------------------------------------------------------------------------------------------
# mmap, munmap, mprotect, madvise, mremap, brk
# ---------------------------------------------------------------------------------------------------------------------
PROT_BITS = {"PROT_NONE": 0, "PROT_READ": 1, "PROT_WRITE": 2, "PROT_EXEC": 4, "PROT_SEM": 8,
             "PROT_GROWSDOWN": 0x01000000, "PROT_GROWSUP": 0x02000000}
# The four plain anonymous shapes of Sys/Mm/Mmap.v mmap_spec, matched after mmap_flags_core has removed MAP_NORESERVE
# (and only that bit): mmap_modeled_b, mmap_noaccess_b, mmap_fixed_noaccess_b, mmap_fixed_rw_b. Each pins offset 0;
# none reads fd (MAP_ANONYMOUS is set).
MMAP_MASK = {"MAP_NORESERVE"}
MMAP_SHAPES = [
    ("rw-anon", {"PROT_READ", "PROT_WRITE"}, {"MAP_PRIVATE", "MAP_ANONYMOUS"}),
    ("noaccess-anon", {"PROT_NONE"}, {"MAP_PRIVATE", "MAP_ANONYMOUS"}),
    ("fixed-noaccess", {"PROT_NONE"}, {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED"}),
    ("fixed-rw", {"PROT_READ", "PROT_WRITE"}, {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED"}),
]
# Sys/Mm/Mmap.v mmap_noreplace_flags_b: the bit alone, or beside MAP_FIXED; mmap_noreplace_rw_b and
# mmap_noreplace_noaccess_b give the two prots.
NOREPLACE_FLAG_WORDS = [
    {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED_NOREPLACE"},
    {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED", "MAP_FIXED_NOREPLACE"},
]
NOREPLACE_PROTS = [{"PROT_READ", "PROT_WRITE"}, {"PROT_NONE"}]


def host_length(run, name, addr, length, ret, errno, extra=None):
    """The length of a munmap, mprotect or madvise at `addr`, recovered from its host call, which has the guest's
    address and the guest's length rounded up to a page (Arg.paged); `extra` are more {index: Arg} keys (madvise's
    advice). `length` as printed when no host line pins it."""
    paged = length.paged()
    keys = {0: Arg.full(addr), 1: paged, **(extra or {})}
    full = run.host.take(name, keys, (1,), ret, errno) if paged is not None else None
    return (length.unpaged(full[1]) or length) if full else length


def _mmap(run, args, ret, errno, tid):
    """Sys/Mm/Mmap.v mmap_spec, in its order: the offset (mmap_off_aligned_b), MAP_ANONYMOUS, a zero length
    (mmap_plain_anon_b), then the shapes. Each answered shape either changes the ledgers as the model does or answers
    an errno of mmap_errnos (-ENOMEM)."""
    if len(args) < 6:
        return und("unparseable argument list")
    led = run.led
    addr = Arg.full(num(args[0]))
    prot, flags = args[2], args[3]
    length, off = Arg.cut(num(args[1])), Arg.cut(num(args[5]))
    if addr is None or length is None or off is None:
        return und("unparseable argument list")
    fd = num(args[4])
    fbits = bits(flags)
    # The host call's length is the guest's rounded up to a page; its offset and descriptor are the guest's.
    keys = {1: length.paged(), 5: off, **({4: Arg.cut(fd)} if fd is not None else {})}
    full = run.host.take("mmap", keys, (1, 5), ret, errno)
    if full:
        length, off = length.unpaged(full[1]) or length, Arg.full(full[5])
    aligned = off.aligned(PAGE_SIZE)
    if not aligned:
        # mmap_off_aligned_b: -EINVAL, unless the page-rounded length wraps 2^64, which declines (mmap_pglen_ok_b).
        if length.ge(TWO_POW_64 - PAGE_SIZE + 1):
            return "the offset is not page-aligned and the page-rounded length wraps 2^64 (Sys/Mm/Mmap.v mmap_spec)"
        return errno_only(ret, errno, {EINVAL}, f"mmap with the unaligned offset {args[5]}",
                          "Sys/Mm/Mmap.v mmap_off_aligned_b")
    if "MAP_ANONYMOUS" not in fbits:
        return f"flags {flags} without MAP_ANONYMOUS: a file mapping is unmodeled (Sys/Mm/Mmap.v mmap_spec)"
    zero = length.is_zero()
    if zero is None:
        return length.known("the mmap length")
    if zero:
        # mmap_plain_anon_b: -EINVAL for a zero length, before any shape.
        if "MAP_HUGETLB" in fbits:
            return "length 0 with MAP_HUGETLB is outside Sys/Mm/Mmap.v mmap_plain_anon_b"
        return errno_only(ret, errno, {EINVAL}, "an mmap of length 0", "Sys/Mm/Mmap.v mmap_plain_anon_b")
    why = length.known("the mmap length")
    if why:
        return why
    if fbits - MMAP_MASK in NOREPLACE_FLAG_WORDS:
        return _mmap_noreplace(run, addr.v, length.v, prot, flags, off, ret, errno)
    shape = next((name for name, p, f in MMAP_SHAPES if bits(prot) == p and fbits - MMAP_MASK == f), None)
    if shape is None:
        return (f"prot {prot} + flags {flags} matches none of the four modeled shapes (Sys/Mm/Mmap.v mmap_modeled_b, "
                "mmap_noaccess_b, mmap_fixed_noaccess_b, mmap_fixed_rw_b)")
    # The offset is pinned whole here: only a host line pins the length, and that line gives the offset too.
    if off.v != 0:
        return f"offset {args[5]}: every anonymous shape needs offset 0 (Sys/Mm/Mmap.v mmap_modeled_b)"
    nz = page_round_up(length.v)
    noaccess = "PROT_NONE" in bits(prot)
    if not shape.startswith("fixed-"):
        # The model picks the address: page-aligned, above 0, ending at or below alloc_top, clear of the image and of
        # every live mapping (the choose of mmap_spec's mmap_modeled_b and mmap_noaccess_b arms). The grant joins
        # vm_maps, and a PROT_NONE one vm_noaccess too. The budget conjunct (mmap_noreserve_backed_ok) is not checked.
        if ret is None:
            return None
        if ret < 0:
            return errno_only(ret, errno, MMAP_ERRNOS, "an anonymous mmap", "Sys/Mm/Mmap.v mmap_errnos")
        a = ret
        if a % PAGE_SIZE or a == 0:
            return (f"mmap returned {a:#x}: the model places a grant at a page-aligned address above 0 "
                    "(Sys/Mm/Mmap.v mmap_spec)")
        if a + nz > ALLOC_TOP_MIN:
            return (f"mmap grant [{a:#x},{a + nz:#x}) ends above the smallest alloc_top {ALLOC_TOP_MIN:#x} "
                    "(Sys/Mm/Mmap.v mmap_spec; State.v alloc_top is per run)")
        why = led.unknown(a, nz)
        if why:
            return und(f"mmap grant [{a:#x},{a + nz:#x}): {why}")
        if not led.image_clear(a, nz) or not region_free(led.maps, a, nz):
            return (f"mmap returned [{a:#x},{a + nz:#x}), which meets the binary's image or a mapping the replay holds "
                    "live: the model places a grant clear of both (Sys/Mm/Mmap.v mmap_spec)")
        led.maps.append((a, nz))
        if noaccess:
            led.noaccess.append((a, nz))
        return None
    # The MAP_FIXED tests, in the kernel's order: a range that wraps 2^64 is -ENOMEM; one that ends above alloc_top is
    # unmodeled (per run: see ALLOC_TOP_MIN); an address not page-aligned is -EINVAL; address 0 is unmodeled (the
    # -EPERM of cap_mmap_addr is not modeled). Then three ways on the ledgers, each answered at the address or with
    # -ENOMEM: inside one entry of vm_maps (vm_maps unchanged: mmap_fixed_rw_next cuts the range out of vm_noaccess,
    # and the PROT_NONE twin puts it back as one entry); clear of every entry (a fresh grant); meeting entries without
    # lying inside one (mmap_fixed_rw_span_next, mmap_fixed_noaccess_span_next). A failure of the first or the third
    # may have destroyed the range (mmap_fixed_destroyed_next) or not. A range that meets the image is unmodeled.
    addr = addr.v
    if addr + nz >= TWO_POW_64:
        return errno_only(ret, errno, {ENOMEM}, "MAP_FIXED whose range wraps 2^64", "Sys/Mm/Mmap.v mmap_spec")
    if addr + nz > ALLOC_TOP_MIN:
        return (f"MAP_FIXED range [{addr:#x},{addr + nz:#x}) ends above the smallest alloc_top {ALLOC_TOP_MIN:#x} "
                "(Sys/Mm/Mmap.v mmap_spec; State.v alloc_top is per run)")
    if addr % PAGE_SIZE:
        return errno_only(ret, errno, {EINVAL}, "MAP_FIXED at an unaligned address", "Sys/Mm/Mmap.v mmap_spec")
    if addr == 0:
        return "MAP_FIXED at address 0 is unmodeled (Sys/Mm/Mmap.v mmap_spec: the -EPERM there is not modeled)"
    why = led.unknown(addr, nz)
    if why:
        return und(f"MAP_FIXED range [{addr:#x},{addr + nz:#x}): {why}")
    if not led.image_clear(addr, nz):
        return f"MAP_FIXED range [{addr:#x},{addr + nz:#x}) meets the binary's image (Sys/Mm/Mmap.v mmap_spec)"
    failed = ret is not None and ret < 0
    if ret is not None and not failed and ret != addr:
        return f"MAP_FIXED returned {ret:#x}, not the requested {addr:#x} (Sys/Mm/Mmap.v mmap_spec)"
    if failed and errno not in MMAP_ERRNOS:
        return errno_only(ret, errno, MMAP_ERRNOS, "a MAP_FIXED mmap", "Sys/Mm/Mmap.v mmap_errnos")
    if map_contains(led.maps, addr, nz):
        if ret is None or failed:
            led.uncertain.append((addr, nz))
        else:
            led.noaccess = maps_subtract(led.noaccess, addr, addr + nz) + ([(addr, nz)] if noaccess else [])
    elif region_free(led.maps, addr, nz):
        if ret is None:
            led.uncertain.append((addr, nz))
        elif not failed:
            led.maps.append((addr, nz))
            if noaccess:
                led.noaccess.append((addr, nz))
    elif ret is None or failed:
        led.uncertain.append((addr, nz))
    else:
        led.maps = [(addr, nz)] + maps_subtract(led.maps, addr, addr + nz)
        led.noaccess = maps_subtract(led.noaccess, addr, addr + nz) + ([(addr, nz)] if noaccess else [])
    return None


def _mmap_noreplace(run, addr, length, prot, flags, off, ret, errno):
    """The two MAP_FIXED_NOREPLACE arms of Sys/Mm/Mmap.v mmap_spec (mmap_noreplace_noaccess_b, mmap_noreplace_rw_b).
    They meet the MAP_FIXED tests, then split once on region_free (vm_reserved ++ vm_maps): a free range is a grant at
    exactly the address (in vm_maps, and in vm_noaccess for PROT_NONE), or -ENOMEM; an occupied one is -EEXIST with
    nothing changed, or -ENOMEM."""
    led = run.led
    if bits(prot) not in NOREPLACE_PROTS:
        return (f"prot {prot} + flags {flags}: MAP_FIXED_NOREPLACE is modeled under PROT_NONE and PROT_READ|PROT_WRITE "
                "only (Sys/Mm/Mmap.v mmap_noreplace_noaccess_b, mmap_noreplace_rw_b)")
    if off.v != 0:
        return "the offset is not 0: both MAP_FIXED_NOREPLACE shapes need offset 0 (Sys/Mm/Mmap.v mmap_noreplace_rw_b)"
    nz = page_round_up(length)
    if addr + nz >= TWO_POW_64:
        return errno_only(ret, errno, {ENOMEM}, "MAP_FIXED_NOREPLACE whose range wraps 2^64",
                          "Sys/Mm/Mmap.v mmap_spec")
    if addr + nz > ALLOC_TOP_MIN:
        return (f"MAP_FIXED_NOREPLACE range [{addr:#x},{addr + nz:#x}) ends above the smallest alloc_top "
                f"{ALLOC_TOP_MIN:#x} (Sys/Mm/Mmap.v mmap_spec; State.v alloc_top is per run)")
    if addr % PAGE_SIZE:
        return errno_only(ret, errno, {EINVAL}, "MAP_FIXED_NOREPLACE at an unaligned address",
                          "Sys/Mm/Mmap.v mmap_spec")
    if addr == 0:
        return ("MAP_FIXED_NOREPLACE at address 0 is unmodeled (Sys/Mm/Mmap.v mmap_spec: the -EPERM there is not "
                "modeled)")
    if ret is None:
        return und(f"MAP_FIXED_NOREPLACE range [{addr:#x},{addr + nz:#x}) has no return in the trace, so the "
                   "grant and the refusal cannot be told apart")
    why = led.unknown(addr, nz)
    if why:
        return und(f"MAP_FIXED_NOREPLACE range [{addr:#x},{addr + nz:#x}): {why}")
    failed = ret < 0
    clear = led.image_clear(addr, nz)
    if clear and region_free(led.maps, addr, nz):
        if not failed:
            if ret != addr:
                return (f"MAP_FIXED_NOREPLACE returned {ret:#x}, not the requested {addr:#x}: the model grants at the "
                        "address exactly (Sys/Mm/Mmap.v mmap_spec)")
            led.maps.append((addr, nz))
            if bits(prot) == {"PROT_NONE"}:
                led.noaccess.append((addr, nz))
            return None
        if errno == ENOMEM:
            return None
        return (f"MAP_FIXED_NOREPLACE range [{addr:#x},{addr + nz:#x}) failed with errno {errno} on a range the replay "
                "calls free: the model answers a grant or -ENOMEM there, never -EEXIST (the kernel saw a mapping the "
                "replay does not track, such as the vdso)")
    what = "the binary's image" if not clear else "a tracked mapping"
    if not failed:
        return (f"MAP_FIXED_NOREPLACE range [{addr:#x},{addr + nz:#x}) returned {ret:#x} but meets {what}: the model "
                "answers -EEXIST or -ENOMEM there and never grants")
    if errno in (EEXIST, ENOMEM):
        return None
    return (f"MAP_FIXED_NOREPLACE range [{addr:#x},{addr + nz:#x}) failed with errno {errno} on a range that meets "
            f"{what}: the model answers -EEXIST or -ENOMEM there and nothing else")


def _munmap(run, args, ret, errno, tid):
    """Sys/Mm/Mmap.v munmap_spec: an address not page-aligned or a zero length is -EINVAL; a range past TASK_SIZE is
    -EINVAL; exactly one recorded mapping (map_has) is removed from vm_maps (map_remove) and cut out of vm_noaccess,
    answering 0; a range clear of the image and of every entry that ends at or below alloc_top is a no-op 0
    (munmap_free_ok); anything else (a partial, interior or spanning unmap, the image, a free range above the smallest
    alloc_top) is unmodeled."""
    if len(args) < 2:
        return und("unparseable argument list")
    addr, length = num(args[0]), Arg.cut(num(args[1]))
    if addr is None or length is None:
        return und("unparseable argument list")
    length = host_length(run, "munmap", addr, length, ret, errno)
    cite = "Sys/Mm/Mmap.v munmap_spec"
    zero = length.is_zero()
    if zero is None:
        return length.known("the munmap length")
    if addr % PAGE_SIZE or zero:
        return errno_only(ret, errno, {EINVAL}, "munmap at an unaligned address or of length 0", cite)
    why = length.known("the munmap length")
    if why:
        return why
    led = run.led
    n = page_round_up(length.v)
    if addr + n > TASK_SIZE:
        return errno_only(ret, errno, {EINVAL}, "munmap past TASK_SIZE", cite)
    if not region_free(led.uncertain, addr, n):
        return und(f"munmap of [{addr:#x},{addr + n:#x}): {UNCERTAIN}")
    answer_0 = (f"munmap of [{addr:#x},{addr + n:#x}) returned {ret_text(ret, errno)}: the model answers 0 there and "
                f"nothing else ({cite})")
    if (addr, n) in led.maps:
        if ret not in (None, 0):
            return answer_0
        led.maps = map_remove(led.maps, addr)
        led.noaccess = maps_subtract(led.noaccess, addr, addr + n)
        return None
    overlaps = [e for e in led.maps if not region_free([e], addr, n)]
    if overlaps:
        return f"partial, interior or spanning unmap of {len(overlaps)} tracked mapping(s): unmodeled ({cite})"
    clear = led.image_clear(addr, n)
    if clear is None:
        return und(f"munmap of [{addr:#x},{addr + n:#x}): {IMAGE_UNKNOWN}")
    if not clear:
        return f"munmap of [{addr:#x},{addr + n:#x}) meets the binary's image ({cite})"
    if addr + n > ALLOC_TOP_MIN:
        return (f"free range [{addr:#x},{addr + n:#x}) ends above the smallest alloc_top {ALLOC_TOP_MIN:#x} "
                "(Sys/Mm/Mmap.v munmap_free_ok; State.v alloc_top is per run)")
    return answer_0 if ret not in (None, 0) else None


def _mprotect(run, args, ret, errno, tid):
    """Sys/Mm/Mprotect.v mprotect_spec, in its order: PROT_GROWSDOWN with PROT_GROWSUP is -EINVAL
    (mprotect_grows_conflict_b); an address not page-aligned is -EINVAL; a zero length is 0; a range whose
    page-rounded end reaches 2^64 is -ENOMEM; a prot other than PROT_READ|PROT_WRITE is unmodeled
    (mprotect_modeled_b). Then the ledgers: a range inside one entry of vm_noaccess and one entry of vm_maps answers 0
    and leaves vm_noaccess (mprotect_model_next), or an errno of mprotect_errnos; a range inside one entry of vm_maps
    and clear of vm_noaccess is already read-write and answers 0 and nothing else; anything else is unmodeled. The
    budget conjunct (mprotect_budget_ok) is not checked."""
    if len(args) < 3:
        return und("unparseable argument list")
    addr, length, prot = num(args[0]), Arg.cut(num(args[1])), flagword(args[2], PROT_BITS)
    if addr is None or length is None or prot is None:
        return und("unparseable argument list")
    length = host_length(run, "mprotect", addr, length, ret, errno)
    cite = "Sys/Mm/Mprotect.v mprotect_spec"
    if prot & PROT_BITS["PROT_GROWSDOWN"] and prot & PROT_BITS["PROT_GROWSUP"]:
        return errno_only(ret, errno, {EINVAL}, "mprotect with PROT_GROWSDOWN and PROT_GROWSUP",
                          "Sys/Mm/Mprotect.v mprotect_grows_conflict_b")
    if addr % PAGE_SIZE:
        return errno_only(ret, errno, {EINVAL}, "mprotect at an unaligned address", cite)
    zero = length.is_zero()
    if zero is None:
        return length.known("the mprotect length")
    if zero:
        return None if ret in (None, 0) else (f"an mprotect of length 0 returned {ret_text(ret, errno)}: the model "
                                              f"answers 0 there ({cite})")
    why = length.known("the mprotect length")
    if why:
        return why
    nz = page_round_up(length.v)
    if addr + nz >= TWO_POW_64:
        return errno_only(ret, errno, {ENOMEM}, "mprotect whose range reaches 2^64", cite)
    if prot != PROT_BITS["PROT_READ"] | PROT_BITS["PROT_WRITE"]:
        return f"prot {args[2]}: the model answers PROT_READ|PROT_WRITE only (Sys/Mm/Mprotect.v mprotect_modeled_b)"
    led = run.led
    span = f"[{addr:#x},{addr + nz:#x})"
    if not region_free(led.uncertain, addr, nz):
        return und(f"mprotect of {span}: {UNCERTAIN}")
    if map_contains(led.noaccess, addr, nz) and map_contains(led.maps, addr, nz):
        if ret is None:
            led.uncertain.append((addr, nz))
            return None
        if ret == 0:
            led.noaccess = maps_subtract(led.noaccess, addr, addr + nz)
            return None
        return errno_only(ret, errno, MPROTECT_ERRNOS, f"mprotect of the PROT_NONE range {span}",
                          "Sys/Mm/Mprotect.v mprotect_errnos")
    if map_contains(led.maps, addr, nz) and region_free(led.noaccess, addr, nz):
        if ret not in (None, 0):
            return (f"mprotect of the read-write range {span} returned {ret_text(ret, errno)}: the model answers 0 "
                    f"there and nothing else ({cite})")
        return None
    where = ("is not inside one tracked mapping" if not map_contains(led.maps, addr, nz)
             else "meets a PROT_NONE range without lying inside one")
    return (f"mprotect(PROT_READ|PROT_WRITE) of {span} {where}: unmodeled ({cite}: the range must lie inside one entry "
            "of vm_maps, and inside one entry of vm_noaccess or clear of all of them)")


MADVISE_ADVICE = {"MADV_NORMAL": 0, "MADV_RANDOM": 1, "MADV_SEQUENTIAL": 2, "MADV_WILLNEED": 3, "MADV_DONTNEED": 4,
                  "MADV_FREE": 8, "MADV_REMOVE": 9, "MADV_DONTFORK": 10, "MADV_DOFORK": 11, "MADV_MERGEABLE": 12,
                  "MADV_UNMERGEABLE": 13, "MADV_HUGEPAGE": 14, "MADV_NOHUGEPAGE": 15, "MADV_DONTDUMP": 16,
                  "MADV_DODUMP": 17, "MADV_WIPEONFORK": 18, "MADV_KEEPONFORK": 19, "MADV_COLD": 20,
                  "MADV_PAGEOUT": 21, "MADV_POPULATE_READ": 22, "MADV_POPULATE_WRITE": 23}


def _madvise(run, args, ret, errno, tid):
    """Sys/Mm/Madvise.v madvise_spec: an address not page-aligned is -EINVAL for every advice; any advice but
    MADV_DONTNEED (read through int32) is unmodeled; a zero length is 0; a range whose page-rounded end reaches 2^64
    is -EINVAL; then madvise_dontneed_ok, all three conjuncts: clear of the image (vm_reserved), inside one entry of
    vm_maps, clear of vm_noaccess; answered 0 with vm_maps unchanged."""
    if len(args) < 3:
        return und("unparseable argument list")
    addr, length, advice = num(args[0]), Arg.cut(num(args[1])), sym(args[2], MADVISE_ADVICE)
    if addr is None:
        return und(f"unparseable address {args[0]}")
    if advice is None:
        return und(f"unparseable advice {args[2]}")
    if length is None:
        return und(f"unparseable length {args[1]}")
    # The host's advice is the guest's, an int (riscv64 and x86-64 share the MADV_* numbers that qemu passes through),
    # so its low 32 bits are keyed.
    length = host_length(run, "madvise", addr, length, ret, errno, {2: Arg.cut(advice)})
    einval = ret is None or (ret < 0 and errno == EINVAL)
    if addr % PAGE_SIZE:
        if einval:
            return None
        return (f"madvise at unaligned {addr:#x} returned {ret_text(ret, errno)}: the model answers -EINVAL there and "
                "nothing else (Sys/Mm/Madvise.v madvise_spec)")
    if low32(advice) != MADV_DONTNEED:
        return (f"advice {args[2]}: only MADV_DONTNEED is modeled; every other advice, MADV_NORMAL and MADV_FREE "
                "included, is unmodeled (Sys/Mm/Madvise.v madvise_dontneed_b)")
    zero = length.is_zero()
    if zero is None:
        return length.known("the madvise length")
    if zero:
        return None if ret in (None, 0) else (f"a zero-length madvise returned {ret_text(ret, errno)}: the model "
                                              "answers 0 there (Sys/Mm/Madvise.v madvise_spec)")
    why = length.known("the madvise length")
    if why:
        return why
    nz = page_round_up(length.v)
    if addr + nz >= TWO_POW_64:
        if einval:
            return None
        return (f"madvise range [{addr:#x},+{nz}) reaches 2^64 and returned {ret_text(ret, errno)}: the model answers "
                "-EINVAL there and nothing else (Sys/Mm/Madvise.v madvise_spec)")
    led = run.led
    why = led.unknown(addr, nz)
    if why:
        return und(f"madvise range [{addr:#x},{addr + nz:#x}): {why}")
    if not led.image_clear(addr, nz):
        return (f"madvise range [{addr:#x},{addr + nz:#x}) meets the binary's image (Sys/Mm/Madvise.v "
                "madvise_dontneed_ok: region_free vm_reserved)")
    if not map_contains(led.maps, addr, nz):
        what = ("meets a tracked mapping without lying inside one" if not region_free(led.maps, addr, nz)
                else "lies in no tracked mapping")
        return (f"madvise range [{addr:#x},{addr + nz:#x}) {what}: it must lie inside one recorded grant or brk grow, "
                "and the model never merges entries (Sys/Mm/Madvise.v madvise_dontneed_ok: map_contains vm_maps)")
    if not region_free(led.noaccess, addr, nz):
        return (f"madvise range [{addr:#x},{addr + nz:#x}) meets a PROT_NONE range: the model declines a DONTNEED "
                "there (Sys/Mm/Madvise.v madvise_dontneed_ok: region_free vm_noaccess)")
    if ret is not None and ret != 0:
        return (f"madvise range [{addr:#x},{addr + nz:#x}) inside a tracked mapping returned {ret_text(ret, errno)}: "
                "the model answers 0 there and no errno (Sys/Mm/Madvise.v madvise_spec)")
    return None


def _brk(run, args, ret, errno, tid):
    """Sys/Mm/Mmap.v brk_spec: the answer is one brk_r_ok allows. A query (req 0), and a req below vm_start_brk,
    answer the current break; a shrink answers req or the break; a grow answers req or the break, and when it answers
    req brk_grow_ok must hold: the new pages and one page more are clear of the image and of vm_maps, and the end is
    at most alloc_top. The run's first break must lie in Run.v valid_brk's band: page-aligned, from the page-rounded
    image top (State.v reserved_top) up to State.v brk_aslr_max above it."""
    led = run.led
    req = num(args[0]) if args else 0
    if req is None:
        return und(f"unparseable break {args[0]}")
    led.brk_calls += 1
    if ret is None:
        return None
    if led.brk is None:
        # The first call. A query answers the initial break, which the run's state needs; anything else leaves the
        # break unknown, because the answer may be req or the break the model started with.
        if req != 0:
            led.brk_unknown = True
            return und("the run's first brk call is not a query, so the trace does not show the initial break "
                       "and the grant this call records cannot be replayed (Sys/Mm/Mmap.v brk_r_ok, brk_maps_next)")
        led.brk = led.min_brk = ret
        if ret % PAGE_SIZE:
            return f"the run's initial break {ret:#x} is not page-aligned (Run.v valid_brk)"
        if led.reserved is not None:
            top = max(a + sz for a, sz in led.reserved)
            if not top <= ret <= top + run.model.brk_aslr_max:
                return (f"the run's initial break {ret:#x} is outside [{top:#x}, {top:#x} + "
                        f"{run.model.brk_aslr_max:#x}], the band from the image top up to brk_aslr_max above it "
                        "(Run.v valid_brk, State.v brk_aslr_max)")
        return None
    if led.brk_unknown:
        return und("the run's break is not known, because its first brk call was not a query "
                   "(Sys/Mm/Mmap.v brk_r_ok)")
    b = led.brk
    if req == 0 or req < led.min_brk:
        if ret != b:
            return (f"brk({args[0]}) answered {ret:#x}, not the current break {b:#x}: the model answers the break "
                    "there (Sys/Mm/Mmap.v brk_r_ok)")
        return None
    if ret not in (req, b):
        return (f"brk({args[0]}) answered {ret:#x}, which is neither the request nor the current break {b:#x} "
                "(Sys/Mm/Mmap.v brk_r_ok)")
    if ret == b:
        return None
    if req < b:
        led.brk_shrink(req, b)
        led.brk = req
        return None
    lo, hi = page_round_up(b), page_round_up(ret)
    if lo < hi:
        if hi > ALLOC_TOP_MIN:
            return (f"the brk grow to {ret:#x} ends above the smallest alloc_top {ALLOC_TOP_MIN:#x} "
                    "(Sys/Mm/Mmap.v brk_grow_ok; State.v alloc_top is per run)")
        n = hi + PAGE_SIZE - lo
        why = led.unknown(lo, n)
        if why:
            return und(f"the brk grow to {ret:#x}: {why}")
        if not led.image_clear(lo, n) or not region_free(led.maps, lo, n):
            return (f"the brk grow to {ret:#x} needs [{lo:#x},{lo + n:#x}), its new pages and one page more, clear of "
                    "the image and of every mapping, and the replay holds something there (Sys/Mm/Mmap.v "
                    "brk_grow_ok)")
    led.maps.append((b, ret - b))       # Sys/Mm/Mmap.v brk_grants
    led.brk = ret
    return None


def _mremap(run, args, ret, errno, tid):
    """Sys/Mm/Mremap.v mremap_spec, in its order: flags must be exactly MREMAP_MAYMOVE; an old address not
    page-aligned and a new size that rounds to 0 are -EINVAL; an old size that rounds to 0 is unmodeled
    (page_align_is0_b); then mremap_source_b. Equal rounded sizes answer the old address. A shrink answers the old
    address (mremap_inplace_effect) or an errno of mremap_errnos. A grow answers the old address only when
    mremap_inplace_grow_b holds, and another address only when mremap_fresh_b holds. mremap_backing_uniform_b reads
    which pages the run has touched, which the trace does not show, and is not checked. qemu prints mremap through
    its generic format, so its sizes are not cut."""
    if len(args) < 4:
        return und("unparseable argument list")
    cite = "Sys/Mm/Mremap.v mremap_spec"
    fl = flagword(args[3], {"MREMAP_MAYMOVE": 1, "MREMAP_FIXED": 2, "MREMAP_DONTUNMAP": 4})
    if fl is None:
        return und(f"unparseable flags {args[3]}")
    if fl != 1:
        return f"flags {args[3]}: only exactly MREMAP_MAYMOVE is modeled ({cite})"
    old, old_size, new_size = num(args[0]), num(args[1]), num(args[2])
    if old is None or old_size is None or new_size is None:
        return und("unparseable argument list")
    old, old_size, new_size = old % TWO_POW_64, old_size % TWO_POW_64, new_size % TWO_POW_64
    if old % PAGE_SIZE or new_size == 0 or page_round_up(new_size) >= TWO_POW_64:
        return errno_only(ret, errno, {EINVAL}, "mremap of an unaligned address or to a size that rounds to 0", cite)
    if old_size == 0 or page_round_up(old_size) >= TWO_POW_64:
        return f"an old size that rounds to 0 is unmodeled ({cite}: page_align_is0_b)"
    old_n, new_n = page_round_up(old_size), page_round_up(new_size)
    led = run.led
    span = f"[{old:#x},{old + old_n:#x})"
    if old + old_n > ALLOC_TOP_MIN:
        return (f"mremap source {span} ends above the smallest alloc_top {ALLOC_TOP_MIN:#x} (Sys/Mm/Mremap.v "
                "mremap_source_b; State.v alloc_top is per run)")
    why = led.unknown(old, old_n)
    if why:
        return und(f"mremap source {span}: {why}")
    if not led.image_clear(old, old_n):
        return f"mremap source {span} meets the binary's image (Sys/Mm/Mremap.v mremap_source_b)"
    if (old, old_n) not in led.maps:
        return (f"mremap source {span} is not exactly one recorded mapping: unmodeled (Sys/Mm/Mremap.v "
                "mremap_source_b: map_has vm_maps)")
    if not region_free(led.noaccess, old, old_n):
        return f"mremap source {span} meets a PROT_NONE range: unmodeled (Sys/Mm/Mremap.v mremap_source_b)"
    if old_n == new_n:
        if ret not in (None, old):
            return (f"mremap to the same rounded size returned {ret_text(ret, errno)}: the model answers {old:#x} "
                    f"({cite})")
        return None
    if ret is None:
        led.uncertain.append((old, old_n))
        return None
    if ret < 0:
        return errno_only(ret, errno, MREMAP_ERRNOS, "mremap", "Sys/Mm/Mremap.v mremap_errnos")
    if new_n < old_n:
        if ret != old:
            return (f"the mremap shrink of {span} returned {ret:#x}: the model shrinks in place and answers "
                    f"{old:#x} ({cite})")
        led.maps = [(old, new_n)] + map_remove(led.maps, old)
        led.noaccess = maps_subtract(led.noaccess, old + new_n, old + old_n)
        return None
    if ret == old:
        # mremap_inplace_grow_b: the grown range must end at or below alloc_top and be clear of the image and of every
        # OTHER mapping.
        if old + new_n > ALLOC_TOP_MIN:
            return (f"the mremap grow in place to [{old:#x},{old + new_n:#x}) ends above the smallest alloc_top "
                    f"{ALLOC_TOP_MIN:#x} (Sys/Mm/Mremap.v mremap_inplace_grow_b)")
        why = led.unknown(old, new_n)
        if why:
            return und(f"the mremap grow in place to [{old:#x},{old + new_n:#x}): {why}")
        if not led.image_clear(old, new_n) or not region_free(map_remove(led.maps, old), old, new_n):
            return (f"the mremap grow in place to [{old:#x},{old + new_n:#x}) meets the image or another mapping: the "
                    "model moves the mapping instead (Sys/Mm/Mremap.v mremap_inplace_grow_b)")
        led.maps = [(old, new_n)] + map_remove(led.maps, old)
        return None
    # mremap_fresh_b: the destination is page-aligned, above 0, ends at or below alloc_top, and is clear of the image
    # and of every mapping, the source included.
    dst = ret
    if dst % PAGE_SIZE or dst == 0:
        return f"the mremap destination {dst:#x} is 0 or not page-aligned (Sys/Mm/Mremap.v mremap_fresh_b)"
    if dst + new_n > ALLOC_TOP_MIN:
        return (f"the mremap destination [{dst:#x},{dst + new_n:#x}) ends above the smallest alloc_top "
                f"{ALLOC_TOP_MIN:#x} (Sys/Mm/Mremap.v mremap_fresh_b)")
    why = led.unknown(dst, new_n)
    if why:
        return und(f"the mremap destination [{dst:#x},{dst + new_n:#x}): {why}")
    if not led.image_clear(dst, new_n) or not region_free(led.maps, dst, new_n):
        return (f"the mremap destination [{dst:#x},{dst + new_n:#x}) meets the image or a mapping, the source "
                "included: the model moves only to a free range (Sys/Mm/Mremap.v mremap_fresh_b)")
    led.maps = [(dst, new_n)] + map_remove(led.maps, old)
    led.noaccess = maps_subtract(led.noaccess, old, old + old_n)
    return None


# ---------------------------------------------------------------------------------------------------------------------
# The descriptor table
# ---------------------------------------------------------------------------------------------------------------------
def kind_reason(fd, ret, errno, what, cite):
    """The reason a rule cannot read a descriptor's kind, or None. After a successful pipe2 a descriptor the replay
    does not hold may be one of the two ends, whose numbers the trace does not show. A call that answered -EBADF is
    still accepted: the model's table may have no such descriptor either, and -EBADF is then its answer."""
    if ret is not None and ret < 0 and errno == EBADF:
        return None
    return und(f"{what} on descriptor {fd}, which this run's pipe2 may have made: the trace does not show the two "
               f"numbers pipe2 wrote, and the model answers a pipe end differently ({cite})")


def bad_fd_only(run, fd, ret, errno, what, cite):
    """The reason a call on a descriptor the model's table does not hold is outside the model, or None. Every arm
    starts with fd_lookup, and None is -EBADF, the arm's whole answer: a caller stops when the descriptor is ABSENT."""
    kind = run.led.kind(fd)
    if kind is not ABSENT:
        return None
    return errno_only(ret, errno, {EBADF}, f"{what} on descriptor {fd}, which this run never opened",
                      f"{cite}: fd_lookup answers -EBADF")


# ---------------------------------------------------------------------------------------------------------------------
# openat, close, unlinkat
# ---------------------------------------------------------------------------------------------------------------------
# Sys/Fs/Open.v modeled_open_flags. The flag word without the bits of open_ignored_flags (O_CLOEXEC, O_LARGEFILE,
# O_NONBLOCK) must be one of: O_RDONLY, wr_create_flags (O_WRONLY|O_CREAT|O_TRUNC), is_excl_create,
# O_RDONLY|O_DIRECTORY, append_create_flags, rdwr_open_word, is_rdwr_excl_create. O_RDONLY is 0, so it is dropped:
# qemu prints a zero word as O_RDONLY.
OPENAT_IGNORED = {"O_CLOEXEC", "O_LARGEFILE", "O_NONBLOCK", "O_RDONLY"}
OPEN_RD = frozenset()
OPEN_WR_CREATE = frozenset({"O_WRONLY", "O_CREAT", "O_TRUNC"})
OPEN_EXCL = (frozenset({"O_WRONLY", "O_CREAT", "O_EXCL"}), frozenset({"O_WRONLY", "O_CREAT", "O_EXCL", "O_TRUNC"}))
OPEN_DIR = frozenset({"O_DIRECTORY"})
OPEN_APPEND = frozenset({"O_WRONLY", "O_CREAT", "O_APPEND"})
OPEN_RDWR = (frozenset({"O_RDWR"}), frozenset({"O_RDWR", "O_TRUNC"}), frozenset({"O_RDWR", "O_CREAT"}),
             frozenset({"O_RDWR", "O_CREAT", "O_TRUNC"}))
OPEN_RDWR_EXCL = (frozenset({"O_RDWR", "O_CREAT", "O_EXCL"}), frozenset({"O_RDWR", "O_CREAT", "O_EXCL", "O_TRUNC"}))
OPENAT_MODELED = [OPEN_RD, OPEN_WR_CREATE, *OPEN_EXCL, OPEN_DIR, OPEN_APPEND, *OPEN_RDWR, *OPEN_RDWR_EXCL]
# qemu's print_openat prints the path with print_string, which escapes nothing, so a path may hold `",`. The flag word
# is the text after the LAST `",` of the record, and the path is everything before it: a path cannot then hide flags.
PATH_END = '",'


def openat_path(args_text):
    """(path, flags_text, mode_text) of an openat or unlinkat record's text after the dirfd, or None. The path is
    read up to its last `",`."""
    cut = args_text.rfind(PATH_END)
    if not args_text.startswith('"') or cut < 0:
        return None
    rest = args_text[cut + len(PATH_END):].split(",")
    return args_text[1:cut], rest[0].strip(), (rest[1].strip() if len(rest) > 1 else "")


def tmp_name(path):
    """Sys/Fs/Namei.v tmp_name: the one component under State.v tmp_prefix, or None (no prefix, an empty rest, a rest
    with a separator, "." or "..")."""
    if not path.startswith(TMP_PREFIX):
        return None
    n = path[len(TMP_PREFIX):]
    return None if n == "" or "/" in n or n in (".", "..") else n


def create_answer(path, ret, errno):
    """The reason the answer to a write-create open (O_WRONLY|O_CREAT|O_TRUNC) of `path` is outside the model, or
    None. Sys/Fs/Open.v openat_create_spec answers -EISDIR for "." and ".." (path_is_dirref) and for a name some key
    of the file system lives under (Sys/Fs/Namei.v fs_under), and create_wronly otherwise: a new descriptor or an
    errno of openat_errnos. Under /tmp no key can live under the name (the declared /tmp is taken to be empty, and
    the image's keys are relative: Fs.v key_is_relative, Run.v valid_input). In the working directory only the image
    could hold a key under the name, and the trace does not show the image, so an -EISDIR there declines."""
    if path in (".", ".."):
        return errno_only(ret, errno, {EISDIR}, f"a create of {path!r}",
                          "Sys/Fs/Open.v openat_create_spec: path_is_dirref")
    if ret is None or ret >= 0 or errno in OPENAT_ERRNOS:
        return None
    if errno == EISDIR:
        if path.startswith(TMP_PREFIX):
            return (f"the create of {path!r} answered -EISDIR: the model answers that only for a name some key lives "
                    "under, and with the declared /tmp empty no key lives under a /tmp key (Sys/Fs/Open.v "
                    "openat_create_spec, State.v in_tmp)")
        return (f"the create of {path!r} answered -EISDIR: the model answers that for a name only when a key of the "
                "image lives under it, which the trace does not show (Sys/Fs/Open.v openat_create_spec, "
                "Sys/Fs/Namei.v fs_under)")
    return errno_only(ret, errno, OPENAT_ERRNOS, f"the create of {path!r}",
                      "Sys/Fs/Open.v create_wronly: a new descriptor or an errno of openat_errnos")


def open_kind(fl, path):
    """The FdEntry an open of `path` with the modeled flag word `fl` installs (Sys/Fs/Open.v openat_read_spec,
    openat_create_spec, openat_dir_spec, openat_devnull_spec, openat_urandom_spec)."""
    if path == DEVNULL_PATH:
        rd = fl in (OPEN_RD,) or fl in OPEN_RDWR or fl in OPEN_RDWR_EXCL
        wr = fl != OPEN_RD
        return ("devnull", rd, wr)
    if path == URANDOM_PATH:
        return ("urandom",)
    if fl == OPEN_DIR or (fl == OPEN_RD and path in (".", "..")):
        return ("dir",)
    if fl == OPEN_RD:
        return ("file", path)
    if fl == OPEN_WR_CREATE or fl in OPEN_EXCL:
        return ("filew", path)
    if fl == OPEN_APPEND:
        return ("filea", path)
    return ("filerw", path)


def _openat(run, args, ret, errno, tid):
    """Sys/Fs/Open.v openat_core_spec and openat_body_spec (the flag word, the empty path, AT_FDCWD), then
    openat_resolved_spec: a slash-free name is a key of the flat file system and every modeled word answers it; a path
    with a separator goes to openat_sep_spec, which answers four spellings and declines every other one."""
    if len(args) < 2:
        return und("unparseable argument list")
    led = run.led
    parts = openat_path(",".join(args[1:]))
    if parts is None:
        return und(f"unparseable path {args[1]}")
    path, flags_text, _ = parts
    if path.endswith("..."):
        return und(f"the path {path!r} was cut short by qemu -strace, so the path tests cannot be decided")
    fl = frozenset(bits(flags_text) - OPENAT_IGNORED)
    if fl not in OPENAT_MODELED:
        return f"flag word {flags_text} is none of the modeled open words (Sys/Fs/Open.v modeled_open_flags)"
    if path == "":
        return errno_only(ret, errno, {ENOENT, ENAMETOOLONG, EFAULT}, "openat of the empty path",
                          "Sys/Fs/Open.v openat_body_spec")
    if args[0].strip() != "AT_FDCWD":
        return f"dirfd {args[0]} is not AT_FDCWD (Sys/Fs/Open.v openat_body_spec)"
    fd = ret if ret is not None and ret >= 0 else None

    def install():
        if fd is not None:
            led.fds[fd] = open_kind(fl, path)
            if path in run.inputs:
                if led.fds[fd][0] == "file":
                    led.offsets[fd] = 0         # FdFile path 0: a read-only open starts at the file's head
                else:
                    forget_contents(run, path)  # a descriptor that can write may change what later reads see

    def any_open_answer(what, cite, errnos=frozenset()):
        """An open arm's answer: a new descriptor (one the table does not hold: lowest_fd), an errno of openat_errnos,
        or one of `errnos`, the path errnos of that arm; read_cstr adds -ENAMETOOLONG and -EFAULT."""
        if fd is not None and fd in led.fds:
            return (f"{what} returned {fd}, a descriptor the run already holds: the model answers a free one "
                    f"({cite}: lowest_fd)")
        return refused(ret, errno, OPENAT_ERRNOS | {ENAMETOOLONG, EFAULT} | set(errnos), what, cite)

    if "/" not in path:
        # Sys/Fs/Open.v openat_dir_spec declines a name over NAME_MAX and never answers a successful directory open of
        # a name other than "." and ".." (only -ENOENT and -ENOTDIR).
        if fl == OPEN_DIR and path not in (".", ".."):
            if len(path) > NAME_MAX:
                return "a directory open of a name over NAME_MAX (Sys/Fs/Open.v openat_dir_spec)"
            # fs_lookup finds a file the run's environment holds (input.bin): a key is never a directory.
            dir_errnos = {ENOTDIR} if path in run.present else {ENOENT, ENOTDIR}
            return errno_only(ret, errno, dir_errnos | {ENAMETOOLONG, EFAULT}, f"openat(O_DIRECTORY) of {path!r}",
                              "Sys/Fs/Open.v openat_dir_spec: a name, not a directory the file system only implies")
        if fl == OPEN_WR_CREATE:
            why = create_answer(path, ret, errno)
            if why:
                return why
        # The path errnos of each word's arm (Sys/Fs/Open.v openat_resolved_spec): openat_read_spec answers -ENOENT
        # for a name the file system lacks; the create and append words -EISDIR; the exclusive words -EEXIST; the
        # read-write words -EISDIR and, without O_CREAT, -ENOENT.
        dirref = path in (".", "..")
        if fl == OPEN_RD or fl == OPEN_DIR:
            path_errnos = set() if dirref else {ENOENT}
        elif fl in (OPEN_WR_CREATE, OPEN_APPEND):
            path_errnos = {EISDIR}
        elif fl in OPEN_EXCL or fl in OPEN_RDWR_EXCL:
            path_errnos = {EEXIST}
        else:
            path_errnos = {EISDIR} if "O_CREAT" in fl else {EISDIR, ENOENT}
        if path in run.present:
            path_errnos = path_errnos - {ENOENT}    # the run's environment holds this file (fs_lookup finds it)
        why = any_open_answer(f"openat of {path!r}", "Sys/Fs/Open.v openat_resolved_spec", path_errnos)
        if why:
            return why
        install()
        return None
    if path == LOCALTIME_PATH:
        # Sys/Fs/Open.v openat_localtime_spec: -ENOENT for every word without O_CREAT; O_CREAT is unmodeled.
        if "O_CREAT" in fl:
            return "openat of /etc/localtime with O_CREAT is unmodeled (Sys/Fs/Open.v openat_localtime_spec)"
        return errno_only(ret, errno, {ENOENT}, "openat of /etc/localtime", "Sys/Fs/Open.v openat_localtime_spec")
    if path == DEVNULL_PATH:
        # Sys/Fs/Open.v openat_devnull_spec: the exclusive words are -EEXIST and O_DIRECTORY -ENOTDIR; every other
        # modeled word opens a /dev/null descriptor or answers openat_errnos.
        if fl in OPEN_EXCL or fl in OPEN_RDWR_EXCL:
            return errno_only(ret, errno, {EEXIST, ENAMETOOLONG, EFAULT}, "an exclusive create of /dev/null",
                              "Sys/Fs/Open.v openat_devnull_spec")
        if fl == OPEN_DIR:
            return errno_only(ret, errno, {ENOTDIR, ENAMETOOLONG, EFAULT}, "openat(O_DIRECTORY) of /dev/null",
                              "Sys/Fs/Open.v openat_devnull_spec")
        why = any_open_answer("openat of /dev/null", "Sys/Fs/Open.v openat_devnull_spec")
        if why:
            return why
        install()
        return None
    if path == URANDOM_PATH:
        # Sys/Fs/Open.v openat_urandom_spec: O_RDONLY opens it; the exclusive words are -EEXIST; O_DIRECTORY is
        # -ENOTDIR; every other word is unmodeled.
        if fl == OPEN_RD:
            why = any_open_answer("openat of /dev/urandom", "Sys/Fs/Open.v openat_urandom_spec")
            if why:
                return why
            install()
            return None
        if fl in OPEN_EXCL or fl in OPEN_RDWR_EXCL:
            return errno_only(ret, errno, {EEXIST}, "an exclusive create of /dev/urandom",
                              "Sys/Fs/Open.v openat_urandom_spec")
        if fl == OPEN_DIR:
            return errno_only(ret, errno, {ENOTDIR}, "openat(O_DIRECTORY) of /dev/urandom",
                              "Sys/Fs/Open.v openat_urandom_spec")
        return (f"openat of /dev/urandom with {flags_text} is unmodeled: only O_RDONLY, the exclusive words and "
                "O_DIRECTORY are answered (Sys/Fs/Open.v openat_urandom_spec)")
    n = tmp_name(path)
    if n is None:
        return (f"the path {path!r} has a separator: only /etc/localtime, /dev/null, /dev/urandom and /tmp/<one "
                "component> are answered, and every other such path is unmodeled (Sys/Fs/Open.v openat_sep_spec)")
    # Sys/Fs/Open.v openat_tmp_spec. A component over NAME_MAX is unmodeled. O_RDONLY opens a key the run holds and
    # declines every other one. The create word is openat_create_spec (create_answer). Every other word is unmodeled.
    if len(n) > NAME_MAX:
        return "a /tmp component over NAME_MAX (Sys/Fs/Open.v openat_tmp_spec)"
    if fl == OPEN_WR_CREATE:
        why = create_answer(path, ret, errno)
        if why:
            return why
        why = any_open_answer(f"openat of {path!r}", "Sys/Fs/Open.v openat_create_spec")
        if why:
            return why
        if fd is not None:
            led.tmp_held.add(path)
        install()
        return None
    if fl == OPEN_RD:
        if path not in led.tmp_held:
            return (f"a read of {path!r}, a /tmp key this run does not hold: no create of that name comes before it, "
                    "the declared /tmp is taken to be empty, and the model declines a key the run does not hold "
                    "(Sys/Fs/Open.v openat_tmp_spec, State.v in_tmp)")
        why = any_open_answer(f"openat of {path!r}", "Sys/Fs/Open.v openat_tmp_spec")
        if why:
            return why
        install()
        return None
    return (f"openat of {path!r} with {flags_text} is unmodeled: the /tmp arm answers O_WRONLY|O_CREAT|O_TRUNC, and "
            "O_RDONLY of a key the run holds (Sys/Fs/Open.v openat_tmp_spec)")


def _close(run, args, ret, errno, tid):
    """Sys/Fs/Open.v close_spec: -EBADF for a descriptor the table does not hold, else 0 and the descriptor goes."""
    if not args:
        return und("unparseable argument list")
    fd = num(args[0])
    why = bad_fd_only(run, fd, ret, errno, "close", "Sys/Fs/Open.v close_spec")
    if why:
        return why
    maybe_absent = run.led.kind(fd) in (None, ABSENT)
    why = answered(ret, errno, {0}, {EBADF} if maybe_absent else set(), "close of an open descriptor",
                   "Sys/Fs/Open.v close_spec")
    if why is None and ret in (None, 0):
        run.led.fds.pop(fd, None)
        run.led.offsets.pop(fd, None)
    return why


def _unlinkat(run, args, ret, errno, tid):
    """Sys/Fs/Namei.v unlinkat_spec and unlinkat_body_spec. A flag word other than 0 and AT_REMOVEDIR is -EINVAL
    (modeled_unlink_flags); the empty path is -ENOENT; a dirfd other than AT_FDCWD is unmodeled. Trailing separators
    are stripped first (path_strip_trailing_slashes): nothing left is -EBUSY or -EISDIR; "." and ".." are errnos; a
    name over NAME_MAX is unmodeled; a separator inside goes to the /tmp arm or is unmodeled. A name with a descriptor
    still open on it declines (unlink_found_spec, fd_names_path)."""
    if len(args) < 2:
        return und("unparseable argument list")
    led = run.led
    parts = openat_path(",".join(args[1:]))
    if parts is None:
        return und(f"unparseable path {args[1]}")
    path, flags_text, _ = parts
    if path.endswith("..."):
        return und(f"the path {path!r} was cut short by qemu -strace, so the path tests cannot be decided")
    fl = flagword(flags_text, {"AT_REMOVEDIR": AT_REMOVEDIR})
    if fl is None:
        return und(f"unparseable flags {flags_text}")
    if low32(fl) not in (0, AT_REMOVEDIR):
        return errno_only(ret, errno, {EINVAL}, f"unlinkat with flags {flags_text}",
                          "Sys/Fs/Namei.v modeled_unlink_flags")
    if path == "":
        return errno_only(ret, errno, {ENOENT}, "unlinkat of the empty path", "Sys/Fs/Namei.v unlinkat_body_spec")
    if args[0].strip() != "AT_FDCWD":
        return f"dirfd {args[0]} is not AT_FDCWD (Sys/Fs/Namei.v unlinkat_body_spec)"
    c = path.rstrip("/")
    found = UNLINKAT_ERRNOS | {ENOTDIR}     # Sys/Fs/Namei.v unlink_found_spec: a name that exists
    if c == "":
        return errno_only(ret, errno, {EBUSY, EISDIR}, f"unlinkat of {path!r}", "Sys/Fs/Namei.v unlinkat_body_spec")
    if "/" in c:
        # Sys/Fs/Namei.v unlinkat_tmp_spec: AT_REMOVEDIR and a component over NAME_MAX are unmodeled; a name some key
        # lives under (fs_under) is -EISDIR; a key the run does not hold is -ENOENT; a key it holds is removed
        # (unlink_found_spec). With the declared /tmp empty no key lives under a /tmp key, so a key the run does not
        # hold is absent and -ENOENT is the one answer for it.
        n = tmp_name(c)
        if n is None:
            return (f"the path {path!r} has a separator not at its end: unmodeled except /tmp/<one component> "
                    "(Sys/Fs/Namei.v unlinkat_body_spec)")
        if low32(fl) == AT_REMOVEDIR:
            return "unlinkat(AT_REMOVEDIR) of a /tmp key is unmodeled (Sys/Fs/Namei.v unlinkat_tmp_spec)"
        if len(n) > NAME_MAX:
            return "a /tmp component over NAME_MAX (Sys/Fs/Namei.v unlinkat_tmp_spec)"
        if c not in led.tmp_held:
            if ret is not None and ret < 0 and errno == EISDIR:
                return (f"unlinkat of {path!r} answered -EISDIR: the model answers that only for a name some key "
                        "lives under, and with the declared /tmp empty no key lives under a /tmp key; a key the run "
                        "does not hold is -ENOENT (Sys/Fs/Namei.v unlinkat_tmp_spec, fs_under; State.v in_tmp)")
            return errno_only(ret, errno, {ENOENT},
                              f"unlinkat of {path!r}, a /tmp key this run does not hold (no create of that name "
                              "comes before it; the declared /tmp is taken to be empty)",
                              "Sys/Fs/Namei.v unlinkat_tmp_spec")
        if led.names_key(c):
            return (f"an unlink of {path!r} while a descriptor on it is open: the model declines "
                    "(Sys/Fs/Namei.v unlink_found_spec, fd_names_path)")
        why = answered(ret, errno, {0}, found, f"unlinkat of {path!r}", "Sys/Fs/Namei.v unlink_found_spec")
        if why:
            return why
        if ret is None or ret == 0:
            led.tmp_held.discard(c)
        return None
    if c in (".", ".."):
        return errno_only(ret, errno, {EINVAL, EISDIR, ENOTEMPTY}, f"unlinkat of {path!r}",
                          "Sys/Fs/Namei.v unlinkat_body_spec")
    if len(c) > NAME_MAX:
        return "a path longer than NAME_MAX (Sys/Fs/Namei.v unlinkat_body_spec)"
    if led.names_key(c):
        return (f"an unlink of {path!r} while a descriptor on it is open: the model declines "
                "(Sys/Fs/Namei.v unlink_found_spec, fd_names_path)")
    if c in run.present:
        # The run's environment holds this file, so it is found (unlink_found_spec); once removed, it is gone, and its
        # contents are no longer known to later opens of the name.
        why = answered(ret, errno, {0}, found | {ENAMETOOLONG, EFAULT}, f"unlinkat of {path!r}",
                       "Sys/Fs/Namei.v unlink_found_spec")
        if why is None and ret in (None, 0):
            forget_contents(run, c)
            run.present.discard(c)
        return why
    return answered(ret, errno, {0}, found | {ENOENT, ENAMETOOLONG, EFAULT}, f"unlinkat of {path!r}",
                    "Sys/Fs/Namei.v unlinkat_body_spec, unlink_found_spec")


# ---------------------------------------------------------------------------------------------------------------------
# read, write and their relatives
# ---------------------------------------------------------------------------------------------------------------------
def access_ok(buf, count):
    """State.v access_okb as a tri-state over the trace's two arguments: count <= TASK_SIZE and buf <= TASK_SIZE -
    count."""
    r = count.le(TASK_SIZE)
    if r is not True:
        return r
    if not buf.exact or not count.exact:
        return None if buf.v <= TASK_SIZE - count.v else False
    return buf.v <= TASK_SIZE - count.v


def modeled_rw_range(buf, count):
    """Sys/Uaccess.v modeled_rw_range as a tri-state: count <= rw_bytes_max, or access_okb buf count."""
    small = count.le(RW_BYTES_MAX)
    if small is True:
        return True
    ok = access_ok(buf, count)
    if ok is True:
        return True
    return False if (small is False and ok is False) else None


def rw_args(run, name, args, ret, errno, fd_index=0, buf_index=1, count_index=2):
    """(fd, buf, count) of a read-like record, with the host-call log's full values where it has them. qemu 10.0.11
    prints the buffer of read and write through `%p` and their count through `%d` (strace.list), and the buffer of
    pread64 and pwrite64 through print_pointer (strace.c print_pread64): the buffer is whole, the count is cut."""
    fd = num(args[fd_index])
    buf = Arg.full(num(args[buf_index]))
    count = Arg.cut(num(args[count_index]))
    if fd is None or buf is None or count is None:
        return None, None, None
    keys = {0: Arg.full(fd), 1: buf, 2: count}
    full = run.host.take(name, keys, (1, 2), ret, errno)
    if full:
        buf, count = Arg.full(full[1]), Arg.full(full[2])
    return fd, buf, count


def urandom_read(count, ret, errno, extra=()):
    """Sys/Fs/ReadWrite.v read_urandom, behind the read and pread64 arms on a /dev/urandom descriptor. The device
    delivers the run's declared byte stream (State.v in_urandom), and Run.v valid_urandom makes that stream endless
    (State.v default_urandom is zero bytes forever), so a read delivers exactly the count, capped at MAX_RW_COUNT
    (State.v rw_count_clamp): a destination none of whose bytes can be written is -EFAULT, and every other answer (a
    short read, another errno) is outside the model. `extra` adds errnos the caller's arm answers first."""
    if ret is None or (ret < 0 and errno in (EFAULT, *extra)):
        return None
    want = min(count.v, MAX_RW_COUNT) if count.exact else None
    if want is None:
        return count.known("the /dev/urandom read's count")
    if ret == want:
        return None
    return (f"a read of {count.v} bytes from /dev/urandom returned {ret_text(ret, errno)}: the model's device delivers "
            f"the whole count, {want} bytes, from an endless stream (Sys/Fs/ReadWrite.v read_urandom; Run.v "
            "valid_urandom; State.v default_urandom)")


def _read(run, args, ret, errno, tid):
    """Sys/Fs/ReadWrite.v read_spec. Every arm starts with the descriptor: a write-only file, a write pipe end and a
    channel other than standard input are -EBADF; a directory is -EISDIR after access_okb; a socket or pipe end is
    gated by modeled_rw_range; the rest by access_okb, which answers -EFAULT when it fails. A success is a byte count
    up to rw_count_clamp count; /dev/null delivers 0, and a socket no connect has reached answers -ENOTCONN."""
    if len(args) < 3:
        return und("unparseable argument list")
    fd, buf, count = rw_args(run, "read", args, ret, errno)
    if fd is None:
        return und("unparseable argument list")
    cite = "Sys/Fs/ReadWrite.v read_spec"
    why = bad_fd_only(run, fd, ret, errno, "read", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "read", cite)
    if kind[0] == "urandom":
        return urandom_read(count, ret, errno)
    if kind[0] in ("filew", "filea"):
        return errno_only(ret, errno, {EBADF}, f"a read on a {kind_name(kind)} descriptor", cite)
    if kind[0] == "channel" and kind[1] != 0:
        return errno_only(ret, errno, {EBADF}, f"a read on channel {kind[1]}",
                          f"{cite}: only standard input is readable")
    if kind[0] == "devnull" and not kind[1]:
        return errno_only(ret, errno, {EBADF}, "a read on a write-only /dev/null descriptor", cite)
    if kind[0] == "pipe" and kind[1]:
        return errno_only(ret, errno, {EBADF}, "a read on the write end of a pipe", cite)
    what = f"a read on a {kind_name(kind)}"
    if kind[0] in ("socket", "pipe"):
        gate = modeled_rw_range(buf, count)
        if gate is False:
            return (f"a read on a {kind_name(kind)}: Sys/Uaccess.v modeled_rw_range does not hold, so the model "
                    f"declines ({cite})")
        if gate is None:
            return undecided(f"the read's count on a {kind_name(kind)}")
        if kind[0] == "pipe":
            return counted(ret, errno, count, {EFAULT}, what, cite)
        state = sock_state(kind)
        if state != "connected":
            # access_ok_zero: -EFAULT exactly when the range runs past TASK_SIZE, ahead of the state's answer.
            ok = access_ok(buf, count)
            if ok is False:
                return errno_only(ret, errno, {EFAULT}, f"{what} whose range runs past TASK_SIZE",
                                  f"{cite}: access_ok_zero")
            if ok is None:
                return undecided(f"the read's count on a {kind_name(kind)}")
        if state == "reset":
            # SkReset: the peer's error was reported once; every later read is end-of-stream (0).
            return answered(ret, errno, {0}, set(), "a read on a socket whose peer error was reported",
                            f"{cite}: SkReset")
        if state != "connected":
            # A socket no accept connected (SkFresh, SkBound, SkListening) answers -ENOTCONN to any count but 0, which
            # reads 0.
            if ret is not None and ret >= 0:
                zero = count.is_zero()
                if ret == 0 and zero is True:
                    return None
                if ret == 0 and zero is None:
                    return undecided("the count of a read on a fresh socket")
                return (f"a read on a socket no connect has reached returned {ret}: the model answers -ENOTCONN, and 0 "
                        f"only for a count of 0 ({cite})")
            return refused(ret, errno, {ENOTCONN}, what, cite)
        # SkConnected: the peer's bytes (1..the clamped count), its FIN (0), or its reset or timeout reported once.
        why = counted(ret, errno, count, {EFAULT} | PEER_ERRNOS, what, cite)
        if why is None:
            peer_error(run, fd, ret, errno)
        return why
    ok = access_ok(buf, count)
    if ok is False:
        return errno_only(ret, errno, {EFAULT}, "a read whose range runs past TASK_SIZE",
                          f"{cite}: State.v access_okb")
    if ok is None and not (ret is not None and ret < 0 and errno == EFAULT):
        return undecided("the read's count")
    if kind[0] == "dir":
        return errno_only(ret, errno, {EISDIR, EFAULT}, "a read on a directory descriptor", cite)
    if kind[0] == "devnull":
        return answered(ret, errno, {0}, {EFAULT}, "a read on /dev/null", cite)
    if kind[0] == "file" and fd in run.led.offsets and kind[1] in run.inputs:
        return known_read(run, fd, kind[1], count, ret, errno, what, cite)
    return counted(ret, errno, count, {EFAULT}, what, cite)


def known_read(run, fd, path, count, ret, errno, what, cite, pos=None):
    """A read of a file whose contents the run's environment fixes (input.bin), at the descriptor's offset, or at
    `pos` for pread64. Sys/Fs/ReadWrite.v read_spec on FdFile is deterministic: exactly the file's bytes from the
    offset, cut at its end and at rw_count_clamp count (Fs.v file_read), or -EFAULT when the first of them cannot land
    (a zero-length delivery always lands). A read moves the descriptor's offset by what it delivered; pread64 does
    not."""
    data, off = run.inputs[path], run.led.offsets[fd] if pos is None else pos
    rest = max(0, len(data) - off)
    least = min(count.v, MAX_RW_COUNT)
    n = min(least, rest) if (count.exact or count.v >= MAX_RW_COUNT or rest <= least) else None
    if n is None or ret is None:
        if pos is None:
            run.led.offsets.pop(fd, None)     # what it delivered, and so the offset, is not known
        return undecided(f"the count of {what}") if n is None else None
    if ret < 0:
        if errno == EFAULT and n > 0:
            return None
        return (f"{what} returned {ret_text(ret, errno)}: {path} holds {rest} bytes past offset {off}, and the model "
                f"delivers exactly {n}{' or answers -EFAULT' if n else ''} ({cite}: Fs.v file_read)")
    if ret != n:
        return (f"{what} returned {ret}: {path} holds {rest} bytes past offset {off}, so the model delivers exactly "
                f"{n} ({cite}: Fs.v file_read, State.v rw_count_clamp)")
    if pos is None:
        run.led.offsets[fd] = off + n
    return None


def _write(run, args, ret, errno, tid):
    """Sys/Fs/ReadWrite.v write_spec. A read-only file, /dev/urandom, a directory, a read pipe end and channel 0 are
    -EBADF; a socket is unmodeled (sendto is its arm); every writable kind is gated by write_range_gate, which is
    Sys/Uaccess.v modeled_rw_range. /dev/null takes the whole clamped count; a pipe takes the whole count or is
    unmodeled; a channel or file takes 1..rw_count_clamp count (0 for a count of 0), and an append file may answer
    -EINVAL (rw_pos_einvalb)."""
    if len(args) < 3:
        return und("unparseable argument list")
    fd, buf, count = rw_args(run, "write", args, ret, errno)
    if fd is None:
        return und("unparseable argument list")
    cite = "Sys/Fs/ReadWrite.v write_spec"
    why = bad_fd_only(run, fd, ret, errno, "write", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "write", cite)
    if kind[0] == "socket":
        return f"a write on a socket is unmodeled ({cite}); sendto is the arm"
    if kind[0] in ("file", "dir", "urandom"):
        return errno_only(ret, errno, {EBADF}, f"a write on a {kind_name(kind)} descriptor", cite)
    if kind[0] == "channel" and kind[1] == 0:
        return errno_only(ret, errno, {EBADF}, "a write on channel 0", f"{cite}: standard input is not writable")
    if kind[0] == "devnull" and not kind[2]:
        return errno_only(ret, errno, {EBADF}, "a write on a read-only /dev/null descriptor", cite)
    if kind[0] == "pipe" and not kind[1]:
        return errno_only(ret, errno, {EBADF}, "a write on the read end of a pipe", cite)
    gate = modeled_rw_range(buf, count)
    if gate is False:
        return (f"a write of {count.v} bytes from {buf.v:#x}: Sys/Uaccess.v modeled_rw_range does not hold, so the "
                f"model declines ({cite}: write_range_gate)")
    if gate is None:
        return undecided("the write's count")
    what = f"a write on a {kind_name(kind)}"
    if kind[0] == "devnull":
        return counted(ret, errno, count, {EFAULT}, what, cite, shape="exact")
    if kind[0] == "pipe":
        # A count of 0 reads 0 or -EFAULT (access_ok_zero); any other count is written whole (pipe_write_room
        # keeps it far below MAX_RW_COUNT), or the model declines.
        zero = count.is_zero()
        return counted(ret, errno, count, {EFAULT} if zero is not False else set(), what, cite, shape="exact")
    errnos = {EFAULT, EINVAL} if kind[0] == "filea" else {EFAULT}
    return counted(ret, errno, count, errnos, what, cite, shape="positive")


def _readv(run, args, ret, errno, tid):
    """Sys/Fs/ReadWrite.v readv_spec: a descriptor readable_fd rejects (a write-only or append file, a write pipe end,
    a channel other than 0, a write-only /dev/null) is -EBADF; an iovcnt in (UIO_FASTIOV, IOV_MAX] takes the heap
    path, which is unmodeled (readv_heap_iovecb, readv_heap_gap); the import answers -EFAULT or -EINVAL (above
    IOV_MAX). A total of 0 reads 0 on every kind. Then readv_imported: a pipe end or /dev/urandom that would deliver is
    unmodeled (readv_buf_gap), /dev/null delivers 0, a directory is -EISDIR, and a channel, socket or file delivers up
    to the total, which cap_iovecs keeps at MAX_RW_COUNT. The array's contents are not in the trace. qemu prints readv
    through its generic format, so its iovcnt is not cut, and the model reads only its low 32 bits (iovcnt32)."""
    if len(args) < 3:
        return und("unparseable argument list")
    fd, cnt = num(args[0]), low32(num(args[2]))
    if cnt is None:
        return und(f"unparseable iovcnt {args[2]}")
    cite = "Sys/Fs/ReadWrite.v readv_spec"
    why = bad_fd_only(run, fd, ret, errno, "readv", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is not None and (kind[0] in ("filew", "filea") or (kind[0] == "channel" and kind[1] != 0)
                             or (kind[0] == "pipe" and kind[1]) or (kind[0] == "devnull" and not kind[1])):
        return errno_only(ret, errno, {EBADF}, f"readv on a {kind_name(kind)} descriptor",
                          f"{cite}: readable_fd")
    # A descriptor the replay cannot name (a pipe end this run may have made) is -EBADF or a readable pipe end.
    maybe_bad = {EBADF} if kind is None else set()
    if UIO_FASTIOV < cnt <= IOV_MAX:
        if maybe_bad and ret is not None and ret < 0 and errno == EBADF:
            return None
        return (f"iovcnt {cnt} is above UIO_FASTIOV ({UIO_FASTIOV}): the heap path is unmodeled "
                "(Sys/Fs/ReadWrite.v readv_heap_iovecb, readv_heap_gap)")
    if cnt > IOV_MAX:
        return errno_only(ret, errno, {EINVAL} | maybe_bad, "readv with iovcnt above IOV_MAX",
                          f"{cite}: import_iovecs")
    if kind is None:
        return kind_reason(fd, ret, errno, "readv", cite)
    what = f"readv on a {kind_name(kind)}"
    if kind[0] == "socket" and sock_state(kind) == "reset":
        return answered(ret, errno, {0}, {EFAULT, EINVAL}, what, f"{cite}: readv_imported, SkReset reads as EOF")
    if kind[0] == "socket" and not sock_connected(kind):
        return answered(ret, errno, {0}, {EFAULT, EINVAL, ENOTCONN}, what, f"{cite}: readv_imported")
    if kind[0] in ("pipe", "urandom", "devnull"):
        if kind[0] != "devnull" and ret is not None and ret > 0:
            return (f"readv of a {kind_name(kind)} returned {ret}: a vectored read that delivers bytes there is "
                    f"unmodeled ({cite}, readv_buf_gap)")
        return answered(ret, errno, {0}, {EFAULT, EINVAL}, what, cite)
    if kind[0] == "dir":
        return answered(ret, errno, {0}, {EFAULT, EINVAL, EISDIR}, what, cite)
    if kind[0] == "socket":
        # SkConnected: never -ENOTCONN; a peer error is reported once and moves the socket to SkReset.
        why = counted(ret, errno, None, {EFAULT, EINVAL} | PEER_ERRNOS, what, cite)
        if why is None:
            peer_error(run, fd, ret, errno)
        return why
    if kind[0] == "file" and fd in run.led.offsets and kind[1] in run.inputs:
        # The file's bytes past the offset bound what it delivers; the iovec total, which picks the exact count, is
        # behind the pointer. The offset moves by what it delivered.
        rest = max(0, len(run.inputs[kind[1]]) - run.led.offsets[fd])
        if ret is not None and ret > rest:
            return (f"{what} returned {ret}: {kind[1]} holds {rest} bytes past offset {run.led.offsets[fd]} "
                    f"({cite}: Fs.v file_read)")
        why = counted(ret, errno, None, {EFAULT, EINVAL}, what, cite)
        if why is None and ret is None:
            run.led.offsets.pop(fd, None)
        elif why is None and ret >= 0:
            run.led.offsets[fd] += ret
        return why
    return counted(ret, errno, None, {EFAULT, EINVAL}, what, cite)


def _writev(run, args, ret, errno, tid):
    """Sys/Fs/ReadWrite.v writev_spec: a read-only file, a directory, /dev/urandom, a read pipe end, channel 0 and a
    read-only /dev/null are -EBADF; a socket is unmodeled (writev_buf_gap); the import answers -EFAULT or -EINVAL (an
    iovcnt above IOV_MAX). A total of 0 writes 0. /dev/null takes the capped total; a pipe end that would take bytes
    is unmodeled; a channel or file takes at least one byte, and a file may answer -EINVAL (rw_pos_einvalb). qemu
    prints the iovcnt through `%#x`, and the model reads only its low 32 bits (iovcnt32)."""
    if len(args) < 3:
        return und("unparseable argument list")
    fd, cnt = num(args[0]), low32(num(args[2]))
    cite = "Sys/Fs/ReadWrite.v writev_spec"
    why = bad_fd_only(run, fd, ret, errno, "writev", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "writev", cite)
    if kind[0] == "socket":
        return f"writev on a socket is unmodeled ({cite}: writev_buf_gap)"
    if (kind[0] in ("file", "dir", "urandom") or (kind[0] == "channel" and kind[1] == 0)
            or (kind[0] == "pipe" and not kind[1]) or (kind[0] == "devnull" and not kind[2])):
        return errno_only(ret, errno, {EBADF}, f"writev on a {kind_name(kind)} descriptor", cite)
    if cnt is not None and cnt > IOV_MAX:
        return errno_only(ret, errno, {EINVAL}, "writev with iovcnt above IOV_MAX", f"{cite}: import_iovecs")
    what = f"writev on a {kind_name(kind)}"
    if kind[0] == "pipe":
        if ret is not None and ret > 0:
            return f"writev on a pipe end returned {ret}: a vectored write that moves bytes is unmodeled ({cite})"
        return answered(ret, errno, {0}, {EFAULT, EINVAL}, what, cite)
    if kind[0] == "channel":
        # The channel arm's count is bounded only by the gathered bytes (below 2**64 and not an error address).
        return refused(ret, errno, {EFAULT, EINVAL}, what, cite)
    if kind[0] == "devnull":
        return counted(ret, errno, None, {EFAULT, EINVAL}, what, cite)
    return counted(ret, errno, None, {EFAULT, EINVAL}, what, f"{cite}: writev_file_arm")


def negative_position(arg):
    """True when a position qemu printed in full is negative as the model reads it (ppos_einvalb: bv_signed < 0),
    False when it is not, None when it does not parse."""
    pos = num(arg)
    if pos is None:
        return None
    return pos < 0 or pos >= TWO_POW_64 >> 1


def _pread64(run, args, ret, errno, tid):
    """Sys/Fs/ReadWrite.v pread64_spec: a negative position is -EINVAL (ppos_einvalb) before the descriptor; a
    channel, pipe end or socket is -ESPIPE; a write-only or append file and a write-only /dev/null are -EBADF; every
    other kind is -EFAULT past access_okb, then -EINVAL past rw_pos_einvalb; /dev/null delivers 0, a directory is
    -EISDIR, /dev/urandom is urandom_read's, and a file delivers up to rw_count_clamp count. qemu prints pread64's
    buffer and position in full and its count through `%d`."""
    if len(args) < 4:
        return und("unparseable argument list")
    cite = "Sys/Fs/ReadWrite.v pread64_spec"
    neg = negative_position(args[3])
    if neg is None:
        return und(f"unparseable position {args[3]}")
    if neg:
        return errno_only(ret, errno, {EINVAL}, "pread64 at a negative position", "Sys/Fs/ReadWrite.v ppos_einvalb")
    fd, buf, count = rw_args(run, "pread64", args, ret, errno)
    if fd is None:
        return und("unparseable argument list")
    why = bad_fd_only(run, fd, ret, errno, "pread64", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "pread64", cite)
    if kind[0] in ("channel", "pipe", "socket"):
        return errno_only(ret, errno, {ESPIPE}, f"pread64 on a {kind_name(kind)}", cite)
    if kind[0] in ("filew", "filea") or (kind[0] == "devnull" and not kind[1]):
        return errno_only(ret, errno, {EBADF}, f"pread64 on a {kind_name(kind)} descriptor", cite)
    if kind[0] == "urandom":
        return urandom_read(count, ret, errno, extra=(EINVAL,))
    what = f"pread64 on a {kind_name(kind)}"
    if kind[0] == "devnull":
        return answered(ret, errno, {0}, {EFAULT, EINVAL}, what, cite)
    if kind[0] == "dir":
        return errno_only(ret, errno, {EFAULT, EINVAL, EISDIR}, what, cite)
    if kind[0] == "file" and kind[1] in run.inputs and access_ok(buf, count) is True:
        pos = num(args[3])
        # rw_pos_einvalb (pos + count past 2^63 - 1 is -EINVAL) is decided only for a whole count.
        if count.exact and pos + count.v <= (TWO_POW_64 >> 1) - 1:
            return known_read(run, fd, kind[1], count, ret, errno, what, cite, pos=pos)
    return counted(ret, errno, count, {EFAULT, EINVAL}, what, cite)


def _pwrite64(run, args, ret, errno, tid):
    """Sys/Fs/ReadWrite.v pwrite64_spec: a negative position is -EINVAL (ppos_einvalb) before the descriptor; a
    channel, pipe end or socket is -ESPIPE; a read-only file, /dev/urandom, a directory and a read-only /dev/null are
    -EBADF; a file created with O_APPEND is unmodeled. The rest are -EFAULT past access_okb and -EINVAL past
    rw_pos_einvalb; /dev/null takes the whole clamped count, and a file up to rw_count_clamp count (the bytes it could
    read). qemu prints the count through `%d`."""
    if len(args) < 4:
        return und("unparseable argument list")
    cite = "Sys/Fs/ReadWrite.v pwrite64_spec"
    neg = negative_position(args[3])
    if neg is None:
        return und(f"unparseable position {args[3]}")
    if neg:
        return errno_only(ret, errno, {EINVAL}, "pwrite64 at a negative position",
                          "Sys/Fs/ReadWrite.v ppos_einvalb")
    fd, _, count = rw_args(run, "pwrite64", args, ret, errno)
    if fd is None:
        return und("unparseable argument list")
    why = bad_fd_only(run, fd, ret, errno, "pwrite64", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "pwrite64", cite)
    if kind[0] in ("channel", "pipe", "socket"):
        return errno_only(ret, errno, {ESPIPE}, f"pwrite64 on a {kind_name(kind)}", cite)
    if kind[0] in ("file", "urandom", "dir") or (kind[0] == "devnull" and not kind[2]):
        return errno_only(ret, errno, {EBADF}, f"pwrite64 on a {kind_name(kind)} descriptor", cite)
    if kind[0] == "filea":
        return f"pwrite64 on a file created with O_APPEND is unmodeled ({cite})"
    what = f"pwrite64 on a {kind_name(kind)}"
    if kind[0] == "devnull":
        return counted(ret, errno, count, {EFAULT, EINVAL}, what, cite, shape="exact")
    return counted(ret, errno, count, {EFAULT, EINVAL}, what, cite, shape="positive")


def _lseek(run, args, ret, errno, tid):
    """Sys/Fs/ReadWrite.v lseek_spec: a descriptor the table does not hold is -EBADF; a whence above SEEK_MAX (4) is
    -EINVAL; a channel, socket or pipe end is -ESPIPE; /dev/null and /dev/urandom answer 0; a directory is unmodeled;
    on a file SEEK_DATA and SEEK_HOLE reach lseek_base = None, unmodeled, and otherwise the answer is the new position
    (lseek_dest: base + the signed offset, in [0, 2^63)) or -EINVAL. SEEK_SET's base is 0, so its answer is pinned;
    SEEK_CUR's and SEEK_END's are the descriptor's offset and the file's length, which the replay knows for a
    read-only descriptor on a file whose contents the run's environment fixes, and not otherwise. qemu prints the
    offset in full."""
    if len(args) < 3:
        return und("unparseable argument list")
    cite = "Sys/Fs/ReadWrite.v lseek_spec"
    fd = num(args[0])
    why = bad_fd_only(run, fd, ret, errno, "lseek", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    names = {"SEEK_SET": 0, "SEEK_CUR": 1, "SEEK_END": 2, "SEEK_DATA": 3, "SEEK_HOLE": 4}
    w = args[2].strip()
    whence = sym(w, names)
    if whence is None:
        return und(f"unparseable whence {w}")
    whence = low32(whence)
    if whence > 4:
        return errno_only(ret, errno, {EINVAL}, f"lseek with whence {w}", f"{cite}: SEEK_MAX")
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "lseek", cite)
    what = f"lseek on a {kind_name(kind)}"
    if kind[0] in ("channel", "socket", "pipe"):
        return errno_only(ret, errno, {ESPIPE}, what, cite)
    if kind[0] in ("devnull", "urandom"):
        return answered(ret, errno, {0}, set(), what, cite)
    if kind[0] == "dir":
        return f"lseek on a directory descriptor is unmodeled ({cite})"
    if whence in (3, 4):
        return f"whence {w} is unmodeled (Sys/Fs/ReadWrite.v lseek_base)"
    off = num(args[1])
    if off is None:
        return und(f"unparseable offset {args[1]}")
    off = off - TWO_POW_64 if off >= TWO_POW_64 >> 1 else off
    # lseek_base: SEEK_SET's base is 0; SEEK_CUR's the descriptor's offset and SEEK_END's the file's length, which the
    # replay knows for a read-only descriptor on a file whose contents the run's environment fixes (input.bin).
    known = kind[0] == "file" and kind[1] in run.inputs
    base = {0: 0, 1: run.led.offsets.get(fd) if known else None,
            2: len(run.inputs[kind[1]]) if known else None}[whence]
    if base is None:
        if known:
            run.led.offsets.pop(fd, None)
        return refused(ret, errno, {EINVAL}, what, "Sys/Fs/ReadWrite.v lseek_dest")
    dest = base + off
    if not 0 <= dest < TWO_POW_64 >> 1:
        return errno_only(ret, errno, {EINVAL}, f"lseek({w}) to {dest}", "Sys/Fs/ReadWrite.v lseek_dest")
    why = answered(ret, errno, {dest}, set(), f"lseek({w}) to {dest}", "Sys/Fs/ReadWrite.v lseek_dest")
    if known:
        if why is None and ret is not None:
            run.led.offsets[fd] = dest
        else:
            run.led.offsets.pop(fd, None)
    return why


# ---------------------------------------------------------------------------------------------------------------------
# The other arms, one function per call name: (run, args, ret, errno, tid) -> the reason the call is unmodeled, or
# None. Each cites the model file and definitions it transcribes.
# ---------------------------------------------------------------------------------------------------------------------
def _getrandom(run, args, ret, errno, tid):
    """Sys/Drivers/Char/Random.v getrandom_spec: flags other than 0 and GRND_NONBLOCK are unmodeled; a buflen above
    rw_bytes_max is unmodeled (Sys/Uaccess.v modeled_rw_count); a buffer the model cannot write is unmodeled. A buflen
    in (0, getrandom_small_max] delivers exactly that many bytes, and nothing else; a larger one delivers 1..buflen or
    -EINTR; a zero buflen answers 0, -EFAULT or -EINTR."""
    if len(args) < 3:
        return und("unparseable argument list")
    buf, buflen, flags = Arg.full(num(args[0])), Arg.cut(num(args[1])), Arg.sext(num(args[2]))
    if buf is None or buflen is None or flags is None:
        return und("unparseable argument list")
    full = run.host.take("getrandom", {0: buf, 1: buflen, 2: flags}, (1,), ret, errno)
    if full:
        buflen = Arg.full(full[1])
    cite = "Sys/Drivers/Char/Random.v getrandom_spec"
    if flags.v not in (0, 1):
        return (f"flags {args[2]}: only 0 and GRND_NONBLOCK are modeled ({cite}; the flags are a 32-bit unsigned "
                "int, so the register is their sign extension)")
    small = buflen.le(RW_BYTES_MAX)
    if small is False:
        return f"a buflen above rw_bytes_max {RW_BYTES_MAX} is unmodeled (Sys/Uaccess.v modeled_rw_count)"
    if small is None:
        return buflen.known("the getrandom buflen")
    if buflen.v == 0:
        return errno_in(ret, errno, {EFAULT, EINTR}, "getrandom of 0 bytes", cite)
    if buflen.v <= GETRANDOM_SMALL_MAX:
        if ret is None or ret == buflen.v:
            return None
        return (f"getrandom of {buflen.v} bytes returned {ret_text(ret, errno)}: at most getrandom_small_max "
                f"({GETRANDOM_SMALL_MAX}) bytes the model delivers the whole count and answers no errno ({cite})")
    if ret is None or ret < 0:
        return errno_only(ret, errno, GETRANDOM_ERRNOS, f"getrandom of {buflen.v} bytes",
                          "Sys/Drivers/Char/Random.v getrandom_errnos")
    if not 1 <= ret <= buflen.v:
        return f"getrandom returned {ret} for a buflen of {buflen.v} ({cite})"
    return None


def _getcwd(run, args, ret, errno, tid):
    """Sys/Fs/DPath.v getcwd_spec: a size above 1 is unmodeled (the model has no name for the working directory); a
    size of 0 or 1 answers -ERANGE or an errno of getcwd_errnos. qemu prints the size through `%d`."""
    if len(args) < 2:
        return und("unparseable argument list")
    size = Arg.cut(num(args[1]))
    if size is None:
        return und(f"unparseable size {args[1]}")
    full = run.host.take("getcwd", {0: Arg.full(num(args[0])), 1: size}, (1,), ret, errno)
    if full:
        size = Arg.full(full[1])
    small = size.le(1)
    if small is False:
        return "a getcwd size above 1 is unmodeled (Sys/Fs/DPath.v getcwd_spec)"
    if small is None:
        return size.known("the getcwd size")
    return errno_only(ret, errno, GETCWD_ERRNOS | {ERANGE}, f"getcwd with size {size.v}",
                      "Sys/Fs/DPath.v getcwd_spec, getcwd_errnos")


CLOCK_IDS = {"CLOCK_REALTIME": 0, "CLOCK_MONOTONIC": 1, "CLOCK_PROCESS_CPUTIME_ID": 2, "CLOCK_THREAD_CPUTIME_ID": 3,
             "CLOCK_MONOTONIC_RAW": 4, "CLOCK_REALTIME_COARSE": 5, "CLOCK_MONOTONIC_COARSE": 6, "CLOCK_BOOTTIME": 7,
             "CLOCK_REALTIME_ALARM": 8, "CLOCK_BOOTTIME_ALARM": 9, "CLOCK_TAI": 11}
# Sys/Kernel/Time/PosixTimers.v clock_gettime_spec: the ids of clockid_percall_b, CLOCK_PROCESS_CPUTIME_ID and
# CLOCK_MONOTONIC.
CLOCK_MODELED = {0, 1, 2, 4, 5, 6, 7}


def _clock_gettime(run, args, ret, errno, tid):
    """Sys/Kernel/Time/PosixTimers.v clock_gettime_spec: every modeled id writes the timespec and answers 0. A buffer
    the model cannot write is unmodeled, not -EFAULT, so an error return is outside the arm."""
    if len(args) < 2:
        return und("unparseable argument list")
    cid = sym(args[0], CLOCK_IDS)
    if cid is None:
        return und(f"unparseable clockid {args[0]}")
    if low32(cid) not in CLOCK_MODELED:
        return (f"clockid {args[0]} is none of the modeled ids (Sys/Kernel/Time/PosixTimers.v clock_gettime_spec, "
                "clockid_percall_b)")
    if ret not in (None, 0):
        return (f"clock_gettime returned {ret_text(ret, errno)}: the model answers 0 and writes the timespec, and an "
                "unwritable buffer is unmodeled, not -EFAULT (Sys/Kernel/Time/PosixTimers.v clock_gettime_spec)")
    return None


def _nanosleep(run, args, ret, errno, tid):
    """Sys/Kernel/Time/Hrtimer.v nanosleep_spec: a request the model cannot read is unmodeled, not -EFAULT; an invalid
    timespec is -EINVAL; the sleep answers 0, or -EINTR with the rest written."""
    return answered(ret, errno, {0}, {EINVAL, EINTR}, "nanosleep",
                    "Sys/Kernel/Time/Hrtimer.v nanosleep_spec: an unreadable request is unmodeled, not -EFAULT")


def _fstat(run, args, ret, errno, tid):
    """Sys/Fs/Stat.v fstat_spec: a channel, a directory, a socket and a pipe end are unmodeled; a file and the two
    devices are answered."""
    if len(args) < 2:
        return und("unparseable argument list")
    fd = num(args[0])
    cite = "Sys/Fs/Stat.v fstat_spec"
    why = bad_fd_only(run, fd, ret, errno, "fstat", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "fstat", cite)
    if kind[0] in ("channel", "dir", "socket", "pipe"):
        return f"fstat of a {kind_name(kind)} descriptor is unmodeled ({cite})"
    return answered(ret, errno, {0}, {EFAULT}, f"fstat of a {kind_name(kind)} descriptor",
                    f"{cite}: fstat_file_spec, fstat_chrdev_spec")


STATAT_FLAGS = {"AT_SYMLINK_NOFOLLOW": 0x100, "AT_EMPTY_PATH": 0x1000, "AT_NO_AUTOMOUNT": 0x800}


def _newfstatat(run, args, ret, errno, tid):
    """Sys/Fs/Stat.v newfstatat_core_spec: the flag word is 0 or AT_SYMLINK_NOFOLLOW (modeled_statat_flags), else
    unmodeled; the empty path is -ENOENT; the dirfd must be AT_FDCWD; "." is unmodeled; and the one answer is -ENOENT,
    because every path that resolves is unmodeled."""
    if len(args) < 4:
        return und("unparseable argument list")
    fl = flagword(args[3], STATAT_FLAGS)
    if fl is None:
        return und(f"unparseable flags {args[3]}")
    if low32(fl) not in (0, 0x100):
        return f"flags {args[3]}: only 0 and AT_SYMLINK_NOFOLLOW are modeled (Sys/Fs/Stat.v modeled_statat_flags)"
    q = quoted(args[1])
    if q is None:
        return und(f"unparseable path {args[1]}")
    if q[0] == "":
        return None
    if args[0].strip() != "AT_FDCWD":
        return f"dirfd {args[0]} is not AT_FDCWD (Sys/Fs/Stat.v newfstatat_core_spec)"
    if q[0] == ".":
        return 'newfstatat of "." is unmodeled (Sys/Fs/Stat.v newfstatat_core_spec)'
    if q[0] in run.present and not q[1]:
        # The run's environment holds this file, so fs_lookup finds it, and a path that resolves is unmodeled.
        return f"newfstatat of {args[1]}, a file the run's environment holds, is unmodeled (Sys/Fs/Stat.v " \
               "newfstatat_core_spec: a path that resolves)"
    return errno_only(ret, errno, {ENOENT}, f"newfstatat of {args[1]}",
                      "Sys/Fs/Stat.v newfstatat_core_spec: every path that resolves is unmodeled")


def _readlinkat(run, args, ret, errno, tid):
    """Sys/Fs/Stat.v readlinkat_spec: a dirfd other than AT_FDCWD is unmodeled; AT_FDCWD is -EINVAL and nothing
    else."""
    if args and args[0].strip() != "AT_FDCWD":
        return f"dirfd {args[0]} is not AT_FDCWD (Sys/Fs/Stat.v readlinkat_spec)"
    return errno_only(ret, errno, {EINVAL}, "readlinkat", "Sys/Fs/Stat.v readlinkat_spec")


# Sys/Fs/Ioctl.v tty_only_request: the terminal requests, each -ENOTTY on any open descriptor but /dev/urandom.
IOCTL_MODELED = {"TCGETS", "TCSETS", "TIOCSCTTY", "TIOCGWINSZ", "TIOCSWINSZ", "TIOCNOTTY", "TIOCGPTN", "TIOCSPTLCK"}
IOCTL_NUMBERS = {0x5401: "TCGETS", 0x5402: "TCSETS", 0x540E: "TIOCSCTTY", 0x5413: "TIOCGWINSZ", 0x5414: "TIOCSWINSZ",
                 0x5422: "TIOCNOTTY", 0x80045430: "TIOCGPTN", 0x40045431: "TIOCSPTLCK"}


def _ioctl(run, args, ret, errno, tid):
    """Sys/Fs/Ioctl.v ioctl_spec: a descriptor the table does not hold is -EBADF; /dev/urandom is unmodeled; on every
    other kind a terminal request is -ENOTTY and nothing else, and any other request is unmodeled."""
    if len(args) < 2:
        return und("unparseable argument list")
    cite = "Sys/Fs/Ioctl.v ioctl_spec"
    fd, req = num(args[0]), args[1].strip()
    why = bad_fd_only(run, fd, ret, errno, "ioctl", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "ioctl", cite)
    if kind[0] == "urandom":
        return f"ioctl on a /dev/urandom descriptor is unmodeled ({cite})"
    n = num(req)
    if req not in IOCTL_MODELED and (n is None or low32(n) not in IOCTL_NUMBERS):
        return (f"request {req}: the model answers only {'/'.join(sorted(IOCTL_MODELED))} "
                "(Sys/Fs/Ioctl.v tty_only_request)")
    return errno_only(ret, errno, {ENOTTY}, f"ioctl({req})", f"{cite}: a terminal request")


# Sys/Fs/Fcntl.v setfl_acted_on: the F_SETFL bits that change something.
SETFL_ACTED_ON = {"O_APPEND", "O_NONBLOCK", "FASYNC", "O_ASYNC", "O_DIRECT", "O_NOATIME"}
SETFL_ACTED_ON_BITS = 0o2000 | 0o4000 | 0o20000 | 0o40000 | 0o1000000
SETFL_NOOP_KINDS = ("file", "filew", "filerw", "dir", "socket")      # Sys/Fs/Fcntl.v setfl_noop_on


def _fcntl(run, args, ret, errno, tid):
    """Sys/Fs/Fcntl.v fcntl_spec: a descriptor the table does not hold is -EBADF; F_SETFD is 0; F_SETFL is 0 only when
    setfl_noop_on holds (false for a channel, an append file, the devices and a pipe end, and for any bit of
    setfl_acted_on); F_GETFL is answered only on a socket, with O_RDWR (getfl_f_flags, socket_f_flags); every other
    command is unmodeled."""
    if len(args) < 2:
        return und("unparseable argument list")
    cite = "Sys/Fs/Fcntl.v fcntl_spec"
    fd, cmd = num(args[0]), args[1].strip()
    why = bad_fd_only(run, fd, ret, errno, "fcntl", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if cmd in ("F_SETFD", "2"):
        return answered(ret, errno, {0}, {EBADF} if kind in (None, ABSENT) else set(), "fcntl(F_SETFD)", cite)
    if kind is None:
        return kind_reason(fd, ret, errno, f"fcntl({cmd})", cite)
    if cmd in ("F_SETFL", "4"):
        if kind[0] not in SETFL_NOOP_KINDS:
            return (f"F_SETFL on a {kind_name(kind)} descriptor: setfl_noop_on is false there "
                    "(Sys/Fs/Fcntl.v setfl_noop_on)")
        if len(args) < 3:
            return und("unparseable argument list")
        arg = args[2].strip()
        acted = bits(arg) & SETFL_ACTED_ON
        if not acted:
            v = num(arg)
            if v is None:
                v = flagword(arg, {"O_RDONLY": 0, "O_WRONLY": 1, "O_RDWR": 2, "O_LARGEFILE": 0o100000,
                                   "O_CLOEXEC": 0o2000000})
            if v is None:
                return und(f"unparseable F_SETFL argument {arg}")
            if v & SETFL_ACTED_ON_BITS:
                acted = {f"{v & SETFL_ACTED_ON_BITS:#x}"}
        if acted:
            return (f"F_SETFL {arg} would change {'|'.join(sorted(acted))}: only an F_SETFL that changes nothing is "
                    "modeled (Sys/Fs/Fcntl.v setfl_noop_on, setfl_acted_on)")
        return answered(ret, errno, {0}, set(), f"fcntl(F_SETFL, {arg})", "Sys/Fs/Fcntl.v setfl_noop_on")
    if cmd in ("F_GETFL", "3"):
        if kind[0] != "socket":
            return "F_GETFL on a descriptor that is not a socket is unmodeled (Sys/Fs/Fcntl.v getfl_f_flags)"
        if ret is not None and ret != 2:
            return (f"F_GETFL returned {ret_text(ret, errno)}: the one answer is O_RDWR (2), on a socket "
                    "(Sys/Fs/Fcntl.v socket_f_flags)")
        return None
    return (f"cmd {cmd}: the model answers F_SETFD, an F_SETFL that changes nothing and a socket's F_GETFL only "
            f"({cite})")


FLOCK_OPS = {"LOCK_SH": 1, "LOCK_EX": 2, "LOCK_NB": 4, "LOCK_UN": 8, "LOCK_MAND": 32}


def _flock(run, args, ret, errno, tid):
    """Sys/Fs/Locks.v flock_spec: LOCK_MAND is 0 before the descriptor; an operation outside LOCK_SH, LOCK_EX and
    LOCK_UN (LOCK_NB aside) is -EINVAL; a descriptor the table does not hold is -EBADF; LOCK_UN is 0 on any open
    descriptor; LOCK_SH and LOCK_EX are answered on a file only while exactly one descriptor names it
    (flock_sole_opener), and are unmodeled on a channel, directory, socket, pipe end or device."""
    if len(args) < 2:
        return und("unparseable argument list")
    cite = "Sys/Fs/Locks.v flock_spec"
    cmd = flagword(args[1], FLOCK_OPS)
    if cmd is None:
        return und(f"unparseable operation {args[1]}")
    cmd = low32(cmd)
    if cmd & 32:
        return answered(ret, errno, {0}, set(), f"flock({args[1]})", "Sys/Fs/Locks.v flock_mand_b")
    base = cmd & ~4
    if base not in (1, 2, 8):
        return errno_only(ret, errno, {EINVAL}, f"flock({args[1]})", "Sys/Fs/Locks.v flock_cmd_ok_b")
    fd = num(args[0])
    why = bad_fd_only(run, fd, ret, errno, "flock", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    if base == 8:
        maybe_absent = run.led.kind(fd) in (None, ABSENT)
        return answered(ret, errno, {0}, {EBADF} if maybe_absent else set(), "flock(LOCK_UN)",
                        f"{cite}: flock_unlock_b")
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "flock", cite)
    if kind[0] not in FILE_KINDS:
        return f"flock(LOCK_SH or LOCK_EX) on a {kind_name(kind)} descriptor is unmodeled ({cite})"
    openers = run.led.path_openers(kind[1])
    if openers != 1:
        return (f"flock(LOCK_SH or LOCK_EX) while {openers} descriptors name the file: answered for the one opener "
                "only (Sys/Fs/Locks.v flock_sole_opener)")
    return answered(ret, errno, {0}, set(), "flock(LOCK_SH or LOCK_EX) of the file's one opener",
                    f"{cite}: flock_sole_opener")


def _getdents64(run, args, ret, errno, tid):
    """Sys/Fs/Readdir.v getdents64_spec: a descriptor the table does not hold is -EBADF; every kind but a directory is
    -ENOTDIR; a directory with room for an entry is unmodeled, and one without is -EINVAL or an errno of
    getdents64_errnos. qemu prints the count through `%u`, and the model reads only its low 32 bits, signed
    (getdents64_ctx_count)."""
    if len(args) < 3:
        return und("unparseable argument list")
    cite = "Sys/Fs/Readdir.v getdents64_spec"
    fd, count = num(args[0]), num(args[2])
    why = bad_fd_only(run, fd, ret, errno, "getdents64", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "getdents64", cite)
    if kind[0] != "dir":
        return errno_only(ret, errno, {ENOTDIR}, f"getdents64 on a {kind_name(kind)} descriptor", cite)
    if count is None:
        return und(f"unparseable count {args[2]}")
    if sint32(count) >= DIRENT64_MIN_RECLEN:
        return (f"getdents64 of a directory with room for an entry (count {sint32(count)}) is unmodeled "
                f"({cite}: getdents64_no_room)")
    return errno_only(ret, errno, GETDENTS64_ERRNOS | {EINVAL}, "getdents64 without room for an entry", cite)


SIGNALS = {"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5, "SIGABRT": 6, "SIGIOT": 6, "SIGBUS": 7,
           "SIGFPE": 8, "SIGKILL": 9, "SIGUSR1": 10, "SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13, "SIGALRM": 14,
           "SIGTERM": 15, "SIGSTKFLT": 16, "SIGCHLD": 17, "SIGCONT": 18, "SIGSTOP": 19, "SIGTSTP": 20, "SIGTTIN": 21,
           "SIGTTOU": 22, "SIGURG": 23, "SIGXCPU": 24, "SIGXFSZ": 25, "SIGVTALRM": 26, "SIGPROF": 27, "SIGWINCH": 28,
           "SIGIO": 29, "SIGPOLL": 29, "SIGPWR": 30, "SIGSYS": 31}


def _rt_sigaction(run, args, ret, errno, tid):
    """Sys/Kernel/Signal.v rt_sigaction_spec: a sigsetsize other than 8 is -EINVAL, before everything else, and qemu
    does not print it (print_rt_sigaction prints three arguments), so -EINVAL is always an answer the model can give.
    Then: a non-NULL old action is unmodeled; with act NULL every valid signal answers 0; with act non-NULL SIGKILL,
    SIGSTOP and signals out of range are -EINVAL, SIGINT and SIGTERM are answered (sigaction_accepted), SIGABRT is
    answered when its handler word is SIG_DFL (sigabrt_dfl_install), and every other signal is unmodeled. The sa_flags
    test reads the struct and is not checked.

    SIGABRT's handler word does not pass on its name: SIG_DFL answers 0, and SIG_IGN or a handler address is
    unmodeled. Neither the trace nor the host-call log shows the word. qemu prints act as a pointer
    (linux-user/strace.c print_rt_sigaction), and the log has no rt_sigaction line; qemu's own host call could not
    tell the two apart either, since for SIGABRT, a signal that dumps core, qemu installs its host handler for SIG_DFL
    and for a guest handler alike (linux-user/signal.c do_sigaction). So a SIGABRT install that answered 0 is
    undecided. -EFAULT (act's 24 bytes are not readable, which the model tests first) and -EINVAL are answers whatever
    the word, and any other answer is none of the model's."""
    if len(args) < 3:
        return und("unparseable argument list")
    if ret is not None and ret < 0 and errno == EINVAL:
        return None
    if not is_null(args[2]):
        return "a non-NULL old action is unmodeled (Sys/Kernel/Signal.v rt_sigaction_spec)"
    sig = low32(sym(args[0], SIGNALS))
    if sig is None:
        return und(f"unparseable signal {args[0]}")
    if not is_null(args[1]):
        if not 1 <= sig <= 64 or sig in (9, 19):
            return errno_only(ret, errno, {EINVAL}, f"rt_sigaction of signal {args[0]}",
                              "Sys/Kernel/Signal.v sig_valid, sig_kernel_only")
        if sig == SIGABRT:
            why = answered(ret, errno, {0}, {EFAULT}, f"rt_sigaction of signal {args[0]}",
                           "Sys/Kernel/Signal.v rt_sigaction_spec, sigabrt_dfl_install")
            if why or (ret is not None and ret < 0):
                return why
            return und("the handler word of a SIGABRT install decides its answer: SIG_DFL is answered 0, and any other "
                       "word is unmodeled (Sys/Kernel/Signal.v sigabrt_dfl_install); qemu prints act as a pointer, so "
                       "neither the trace nor the host-call log shows the word")
        if sig not in (2, 15):
            return (f"a handler for signal {args[0]} is unmodeled: only SIGINT and SIGTERM are accepted, and SIGABRT "
                    "with SIG_DFL (Sys/Kernel/Signal.v sigaction_accepted, sigabrt_dfl_install)")
    elif not 1 <= sig <= 64:
        return errno_only(ret, errno, {EINVAL}, f"rt_sigaction of signal {args[0]}", "Sys/Kernel/Signal.v sig_valid")
    # -EINVAL is accepted above (the sigsetsize qemu does not print); else 0, and -EFAULT for an unreadable act.
    return answered(ret, errno, {0}, set() if is_null(args[1]) else {EFAULT}, f"rt_sigaction of signal {args[0]}",
                    "Sys/Kernel/Signal.v rt_sigaction_spec")


def _rt_sigprocmask(run, args, ret, errno, tid):
    """Sys/Kernel/Signal.v rt_sigprocmask_spec: a sigsetsize other than NSIG_BYTES is -EINVAL; an unreadable new set
    is -EFAULT; an invalid `how` is -EINVAL; every other shape answers 0. qemu prints the sigsetsize through `%u`,
    and a larger register would be -EINVAL, which the model also answers, so the printed value decides nothing the
    checker needs."""
    if len(args) >= 4:
        size = low32(num(args[3]))
        if size is not None and size != NSIG_BYTES:
            return errno_only(ret, errno, {EINVAL}, f"rt_sigprocmask with sigsetsize {size}",
                              "Sys/Kernel/Signal.v rt_sigprocmask_spec")
    return answered(ret, errno, {0}, {EINVAL, EFAULT}, "rt_sigprocmask", "Sys/Kernel/Signal.v rt_sigprocmask_spec")


def _sigaltstack(run, args, ret, errno, tid):
    """Sys/Kernel/Signal.v sigaltstack_spec: once a stack is installed every later call is unmodeled
    (m_sigaltstack_installed); a non-NULL old-stack pointer is unmodeled; a NULL new stack answers 0; the rest reads
    the struct, so only its answers are checked. A call that installs a stack is one with a non-NULL new stack that
    answered 0, which the trace cannot tell from an SS_DISABLE; the checker takes it as an install, which is the
    fail-closed reading."""
    if len(args) < 2:
        return und("unparseable argument list")
    led = run.led
    if led.sigaltstack_installed:
        return ("sigaltstack after a stack was installed is unmodeled (Sys/Kernel/Signal.v sigaltstack_spec: "
                "m_sigaltstack_installed)")
    if not is_null(args[1]):
        return "a non-NULL old-stack pointer is unmodeled (Sys/Kernel/Signal.v sigaltstack_spec)"
    if is_null(args[0]):
        return None if ret in (None, 0) else (f"sigaltstack with a NULL new stack returned {ret_text(ret, errno)}: "
                                              "the model answers 0 (Sys/Kernel/Signal.v sigaltstack_spec)")
    why = answered(ret, errno, {0}, {EFAULT, EINVAL, ENOMEM}, "sigaltstack", "Sys/Kernel/Signal.v sigaltstack_spec")
    if why:
        return why
    if ret == 0:
        led.sigaltstack_installed = True
    return None


STANCE_OFF_REASON = "unmodeled under abort stance off"


def _kill(run, name, args, ret, errno, tid):
    """Sys/Kernel/Signal.v tkill_spec, tgkill_spec and tkill_self, in their order: m_abort_terminal first (false under
    stance off, so every tkill and tgkill is then unmodeled); then pid_positive, -EINVAL; then m_tid, which is None
    until a set_tid_address, getpid, gettid or setsid has pinned it, and unmodeled while it is; then a pid that is not
    the tid (unmodeled), a tgid that is not the tid (-ESRCH), a signal above 64 (-EINVAL), SIGABRT (send_sigabrt), and
    every other signal (unmodeled)."""
    need = 2 if name == "tkill" else 3
    if len(args) < need:
        return und("unparseable argument list")
    led = run.led
    sigarg = args[1] if name == "tkill" else args[2]
    sig32 = low32(sym(sigarg, SIGNALS))
    if sig32 == SIGABRT and ret in (None, 0):
        # A fact about the trace, not about the model: the run sent itself SIGABRT, and qemu's death line that
        # follows is the end of the run. Whether the model answers it is the stance's business, below.
        run.self_kill = True
    if run.stance == "off":
        return (f"{name} is {STANCE_OFF_REASON}: the run does not declare abort() terminal, and the model answers "
                "unmodeled for every tkill and tgkill then (Run.v valid_input; Sys/Kernel/Signal.v tkill_spec)")
    if name == "tkill":
        tgid, pid = None, low32(num(args[0]))
    else:
        tgid, pid = low32(num(args[0])), low32(num(args[1]))
    if pid is None or (name == "tgkill" and tgid is None):
        return und("unparseable pid")
    positive = 1 <= pid < PID_MAX and (name == "tkill" or 1 <= tgid < PID_MAX)
    if not positive:
        return errno_only(ret, errno, {EINVAL}, f"{name} of a pid that is not positive",
                          "Sys/Kernel/Signal.v pid_positive")
    if led.tid is None:
        return (f"{name} before the model has pinned the task's id: m_tid is None until a set_tid_address, getpid, "
                "gettid or setsid answers it, and the model is unmodeled there (Sys/Kernel/Signal.v tkill_self)")
    if pid != led.tid:
        return (f"{name} of pid {pid} while the model's task is {led.tid}: only the caller's own task is modeled "
                "(Sys/Kernel/Signal.v tkill_self)")
    if name == "tgkill" and tgid != led.tid:
        return errno_only(ret, errno, {ESRCH}, "tgkill with a tgid that is not the tid",
                          "Sys/Kernel/Signal.v tgkill_spec")
    sig = sig32
    if sig is None:
        return und(f"unparseable signal {sigarg}")
    if sig > 64:
        return errno_only(ret, errno, {EINVAL}, f"{name} with a signal above 64",
                          "Sys/Kernel/Signal.v tkill_sig_valid")
    if sig != SIGABRT:
        return f"{name}({sigarg}) is unmodeled: SIGABRT is the one answered signal (Sys/Kernel/Signal.v tkill_self)"
    if ret not in (None, 0):
        return (f"{name}(SIGABRT) of the caller's own task returned {ret_text(ret, errno)}: send_sigabrt answers 0 "
                "(Sys/Kernel/Signal.v send_sigabrt)")
    return None


def _tkill(run, args, ret, errno, tid):
    return _kill(run, "tkill", args, ret, errno, tid)


def _tgkill(run, args, ret, errno, tid):
    return _kill(run, "tgkill", args, ret, errno, tid)


def _set_tid_address(run, args, ret, errno, tid):
    """Sys/Kernel/Fork.v set_tid_address_spec: the answer is the task's id, pinned at the first of these calls
    (State.v m_tid). getpid and gettid are the same arm."""
    led = run.led
    if ret is None:
        return None
    if ret <= 0 or ret >= PID_MAX_ENVELOPE:
        return (f"the task's id {ret} is outside (0, 2^22) (Sys/Kernel/Fork.v set_tid_address_spec, "
                "PID_MAX_ENVELOPE)")
    if led.tid is None:
        led.tid = ret
    elif ret != led.tid:
        return (f"the task's id came back as {ret} after {led.tid}: the model pins it once "
                "(Sys/Kernel/Fork.v set_tid_address_spec)")
    return None


def _setsid(run, args, ret, errno, tid):
    """Sys/Kernel/Sys.v setsid_spec: -EPERM, or the task's id, which it pins (set_tid). A second success is
    -EPERM."""
    led = run.led
    if ret is None or ret < 0:
        return errno_only(ret, errno, {EPERM}, "setsid", "Sys/Kernel/Sys.v setsid_spec")
    if led.setsid_done:
        return (f"setsid returned {ret} after an earlier setsid succeeded: the model answers -EPERM "
                "(Sys/Kernel/Sys.v setsid_spec, m_setsid_succeeded)")
    why = _set_tid_address(run, args, ret, errno, tid)
    if why is None:
        led.setsid_done = True
    return why


def _sched_yield(run, args, ret, errno, tid):
    """Sys/Kernel/Sched/Syscalls.v sched_yield_spec: 0, and nothing else."""
    return answered(ret, errno, {0}, set(), "sched_yield", "Sys/Kernel/Sched/Syscalls.v sched_yield_spec")


def _uname(run, args, ret, errno, tid):
    """Sys/Kernel/Sys.v uname_spec: -EFAULT past access_okb, else 0 with the structure written (a buffer the model
    cannot write is unmodeled)."""
    name = num(args[0]) if args else None
    if name is None:
        return und("unparseable argument list")
    if name % TWO_POW_64 > TASK_SIZE - 390:
        return errno_only(ret, errno, {EFAULT}, "uname with a buffer past TASK_SIZE",
                          "Sys/Kernel/Sys.v uname_spec: access_okb name NEW_UTSNAME_SIZE")
    # A buffer in range that cannot be written is unmodeled, not -EFAULT.
    return answered(ret, errno, {0}, set(), "uname", "Sys/Kernel/Sys.v uname_spec")


def _setid(run, args, ret, errno, tid, name):
    """Sys/Kernel/Sys.v setid_spec, which SyscallTable.v reads through uid32: an id of ID_MINUS_ONE (the low 32 bits
    all set) is -EINVAL; otherwise 0, -EPERM, or an errno of setid_errnos (ENOMEM, and EAGAIN for setuid)."""
    v = num(args[0]) if args else None
    if v is None:
        return und("unparseable argument list")
    cite = "Sys/Kernel/Sys.v setid_spec"
    if low32(v) == 0xFFFFFFFF:
        return errno_only(ret, errno, {EINVAL}, f"{name}(-1)", f"{cite}: ID_MINUS_ONE")
    errnos = {EPERM, ENOMEM, EAGAIN} if name == "setuid" else {EPERM, ENOMEM}
    why = answered(ret, errno, {0}, errnos, name, f"{cite}, setid_errnos")
    if why is None and ret == 0:
        run.led.ids.clear()
    return why


def _setresid(run, args, ret, errno, tid, name):
    """Sys/Kernel/Sys.v setresid_spec: 0, -EPERM, or an errno of setid_errnos (ENOMEM, and EAGAIN for setresuid)."""
    errnos = {EPERM, ENOMEM, EAGAIN} if name == "setresuid" else {EPERM, ENOMEM}
    why = answered(ret, errno, {0}, errnos, name, "Sys/Kernel/Sys.v setresid_spec, setid_errnos")
    if why is None and ret == 0:
        run.led.ids.clear()
    return why


def _getid(run, args, ret, errno, tid, name):
    """Sys/Kernel/Sys.v getid_spec: the credential (m_creds), which only a successful set*id call changes. The run
    starts with any credentials, so the first answer is taken, and every later one must repeat it."""
    if ret is None:
        return None
    if ret < 0 and errno is not None:
        return (f"{name} returned {ret_text(ret, errno)}: the model answers the credential, never an errno "
                "(Sys/Kernel/Sys.v getid_spec)")
    seen = run.led.ids.setdefault(name, ret)
    if seen != ret:
        return (f"{name} returned {ret} after {seen}, with no successful set*id call between: the credential does not "
                "change (Sys/Kernel/Sys.v getid_spec)")
    return None


def _prctl(run, args, ret, errno, tid):
    """Sys/Kernel/Sys.v prctl_spec: PR_CAPBSET_READ (23) is the one option answered (prctl_modeled_options). qemu
    prints prctl through its generic format, and the model reads the option through int32."""
    if not args:
        return und("unparseable argument list")
    opt = sym(args[0], {"PR_CAPBSET_READ": 23})
    if opt is None:
        return und(f"unparseable option {args[0]}")
    if low32(opt) != 23:
        return (f"prctl option {args[0]} is unmodeled: PR_CAPBSET_READ (23) is the one answered "
                "(Sys/Kernel/Sys.v prctl_modeled_options)")
    cap = num(args[1]) if len(args) > 1 else None
    if cap is None:
        return und("unparseable capability argument")
    cite = "Sys/Kernel/Sys.v prctl_spec"
    if cap % TWO_POW_64 > 40:
        return errno_only(ret, errno, {EINVAL}, f"prctl(PR_CAPBSET_READ, {args[1]})", f"{cite}: CAP_LAST_CAP")
    return answered(ret, errno, {1}, set(), f"prctl(PR_CAPBSET_READ, {args[1]})", cite)


FUTEX_OPS = {"FUTEX_WAIT": 0, "FUTEX_WAKE": 1, "FUTEX_FD": 2, "FUTEX_REQUEUE": 3, "FUTEX_CMP_REQUEUE": 4,
             "FUTEX_WAKE_OP": 5, "FUTEX_LOCK_PI": 6, "FUTEX_UNLOCK_PI": 7, "FUTEX_TRYLOCK_PI": 8,
             "FUTEX_WAIT_BITSET": 9, "FUTEX_WAKE_BITSET": 10, "FUTEX_WAIT_REQUEUE_PI": 11,
             "FUTEX_CMP_REQUEUE_PI": 12, "FUTEX_LOCK_PI2": 13, "FUTEX_PRIVATE_FLAG": 128,
             "FUTEX_CLOCK_REALTIME": 256, "FUTEX_WAKE_PRIVATE": 129, "FUTEX_WAIT_PRIVATE": 128}


def _futex(run, args, ret, errno, tid):
    """Sys/Kernel/Futex/Syscalls.v futex_spec: two op words are answered, each compared on the whole 64-bit register.
    FUTEX_WAKE|FUTEX_PRIVATE_FLAG (futex_wake_private_spec) answers 0, -EINVAL or -EFAULT on the key.
    FUTEX_WAIT|FUTEX_PRIVATE_FLAG with a NULL timeout answers -EINVAL, -EFAULT or -EAGAIN, and is unmodeled when it
    would block. Every other op word is unmodeled. qemu prints the low 32 bits of the operation (strace.c
    print_futex_op takes an int, as do the kernel's futex and qemu's own do_futex), and the register is their sign
    extension (Arg.sext)."""
    if len(args) < 4:
        return und("unparseable argument list")
    word = flagword(args[1], FUTEX_OPS)
    if word is None:
        return und(f"unparseable futex op {args[1]}")
    op = Arg.sext(word).v
    if op not in (128, 129):
        return (f"futex op {args[1]} is unmodeled: only FUTEX_WAKE|FUTEX_PRIVATE_FLAG and FUTEX_WAIT|"
                "FUTEX_PRIVATE_FLAG are answered (Sys/Kernel/Futex/Syscalls.v futex_spec)")
    if op == 129:
        if ret is not None and ret > 0:
            return (f"FUTEX_WAKE|FUTEX_PRIVATE_FLAG returned {ret}: the model answers 0, it sees no waiter "
                    "(Sys/Kernel/Futex/Syscalls.v futex_wake_private_spec)")
        return errno_in(ret, errno, {EINVAL, EFAULT}, "FUTEX_WAKE|FUTEX_PRIVATE_FLAG",
                        "Sys/Kernel/Futex/Syscalls.v futex_wake_private_spec")
    if not is_null(args[3]):
        return "FUTEX_WAIT|FUTEX_PRIVATE_FLAG with a timeout is unmodeled (Sys/Kernel/Futex/Syscalls.v futex_spec)"
    return errno_only(ret, errno, {EAGAIN, EINVAL, EFAULT}, "FUTEX_WAIT|FUTEX_PRIVATE_FLAG",
                      "Sys/Kernel/Futex/Syscalls.v futex_spec: a wait that would block is unmodeled")


def _pipe2(run, args, ret, errno, tid):
    """Sys/Fs/Pipe.v pipe2_spec: a bit outside pipe2_flags_mask is -EINVAL; any other nonzero word is unmodeled; the
    two ends go to the two lowest free descriptors, whose numbers the trace does not show (qemu writes them to the
    array, and the run's numbering is shifted from the model's by qemu's own descriptors)."""
    if len(args) < 2:
        return und("unparseable argument list")
    fl = flagword(args[1], {"O_CLOEXEC": 0o2000000, "O_NONBLOCK": 0o4000, "O_DIRECT": 0o40000, "O_EXCL": 0o200})
    if fl is None:
        return und(f"unparseable flags {args[1]}")
    if low32(fl) & ~(0o2000000 | 0o4000 | 0o40000 | 0o200):
        return errno_only(ret, errno, {EINVAL}, f"pipe2 with flags {args[1]}", "Sys/Fs/Pipe.v pipe2_flags_mask")
    if low32(fl):
        return f"flags {args[1]}: only pipe2(.., 0) is modeled (Sys/Fs/Pipe.v pipe2_spec)"
    why = answered(ret, errno, {0}, PIPE2_ERRNOS | {EFAULT}, "pipe2", "Sys/Fs/Pipe.v pipe2_spec, pipe2_errnos")
    if why:
        return why
    if ret == 0:
        run.led.pipe_fds_unknown = True
    return None


def _dup(run, args, ret, errno, tid):
    """Sys/Fs/File.v dup_spec: a descriptor the table does not hold is -EBADF; dup_modeled_entry is false for a file,
    a socket and a pipe end, so duplicating one is unmodeled; the copy is the same entry at the lowest free
    descriptor, or an errno of dup_errnos."""
    if not args:
        return und("unparseable argument list")
    cite = "Sys/Fs/File.v dup_spec"
    fd = num(args[0])
    why = bad_fd_only(run, fd, ret, errno, "dup", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    led = run.led
    kind = led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "dup", cite)
    if kind[0] in FILE_KINDS or kind[0] in ("socket", "pipe"):
        return f"dup of a {kind_name(kind)} descriptor is unmodeled (Sys/Fs/File.v dup_modeled_entry)"
    if ret is None:
        return None
    if ret < 0:
        return errno_only(ret, errno, DUP_ERRNOS, "dup", "Sys/Fs/File.v dup_errnos")
    if ret in led.fds:
        return f"dup returned {ret}, a descriptor the run already holds: the model answers a free one ({cite})"
    led.fds[ret] = kind
    return None


def _dup3(run, args, ret, errno, tid):
    """Sys/Fs/File.v dup3_spec, in its order: a flag word outside O_CLOEXEC is -EINVAL (dup3_flags_ok); oldfd equal to
    newfd is -EINVAL; a newfd at or above the run's RLIMIT_NOFILE is -EBADF, and the trace does not show that limit,
    so -EBADF stays an answer the model can give; a descriptor the table does not hold is -EBADF; a file, socket or
    pipe end is unmodeled (dup_modeled_entry); a newfd at or above NR_OPEN_DEFAULT that is not already open is
    unmodeled, and every other newfd takes the entry."""
    if len(args) < 3:
        return und("unparseable argument list")
    cite = "Sys/Fs/File.v dup3_spec"
    oldfd, newfd, flags = num(args[0]), num(args[1]), num(args[2])
    if oldfd is None or newfd is None or flags is None:
        return und("unparseable argument list")
    oldfd, newfd = low32(oldfd), low32(newfd)
    if low32(flags) & ~0o2000000:
        return errno_only(ret, errno, {EINVAL}, f"dup3 with flags {args[2]}", "Sys/Fs/File.v dup3_flags_ok")
    if oldfd == newfd:
        return errno_only(ret, errno, {EINVAL}, "dup3 with oldfd equal to newfd", cite)
    if ret is not None and ret < 0 and errno == EBADF:
        return None
    led = run.led
    kind = led.kind(oldfd)
    if kind is ABSENT:
        return errno_only(ret, errno, {EBADF}, f"dup3 of descriptor {oldfd}, which this run never opened", cite)
    if kind is None:
        return kind_reason(oldfd, ret, errno, "dup3", cite)
    if kind[0] in FILE_KINDS or kind[0] in ("socket", "pipe"):
        return f"dup3 of a {kind_name(kind)} descriptor is unmodeled (Sys/Fs/File.v dup_modeled_entry)"
    if newfd >= NR_OPEN_DEFAULT and led.kind(newfd) is ABSENT:
        return (f"dup3 to the free descriptor {newfd}, at or above NR_OPEN_DEFAULT ({NR_OPEN_DEFAULT}): unmodeled "
                f"({cite})")
    if ret is None:
        return None
    if ret != newfd:
        return f"dup3 returned {ret_text(ret, errno)}: the model answers {newfd} ({cite})"
    led.fds[newfd] = kind
    led.offsets.pop(newfd, None)
    return None


def _sched_getaffinity(run, args, ret, errno, tid):
    """Sys/Kernel/Sched/Syscalls.v sched_getaffinity_spec reads only the length, through abi_low32: one the kernel
    refuses is -EINVAL (affinity_len_einval_b), and every other call is unmodeled."""
    if len(args) < 3:
        return und("unparseable argument list")
    n = low32(num(args[1]))
    if n is None:
        return und(f"unparseable cpusetsize {args[1]}")
    if (n * 8) % TWO_POW_32 == 0 or n % 8:
        return errno_only(ret, errno, {EINVAL}, f"sched_getaffinity with cpusetsize {n}",
                          "Sys/Kernel/Sched/Syscalls.v affinity_len_einval_b")
    return (f"sched_getaffinity with cpusetsize {n}: only a length the kernel refuses is answered "
            "(Sys/Kernel/Sched/Syscalls.v sched_getaffinity_spec)")


def _sched_setscheduler(run, args, ret, errno, tid):
    """Sys/Kernel/Sched/Syscalls.v sched_setscheduler_spec: a negative policy or pid, or a NULL param, is -EINVAL; a
    pid other than 0 or the caller's is unmodeled (sched_targets_self_b); SCHED_RESET_ON_FORK and SCHED_EXT are
    unmodeled; a policy outside sched_valid_policy_b, and SCHED_DEADLINE, is -EINVAL; SCHED_IDLE is the one policy
    whose success is answered."""
    if len(args) < 3:
        return und("unparseable argument list")
    pid, policy, param = sint32(num(args[0])), sint32(num(args[1])), num(args[2])
    if pid is None or policy is None or param is None:
        return und("unparseable argument list")
    cite = "Sys/Kernel/Sched/Syscalls.v sched_setscheduler_spec"
    if policy < 0 or param == 0 or pid < 0:
        return errno_only(ret, errno, {EINVAL}, "sched_setscheduler", cite)
    # The param is read before the target is checked: past access_okb it is -EFAULT, and nothing else.
    if param % TWO_POW_64 > TASK_SIZE - 4:
        return errno_only(ret, errno, {EFAULT}, "sched_setscheduler with a param past TASK_SIZE",
                          f"{cite}: access_okb")
    if pid != 0 and pid != run.led.tid:
        return f"sched_setscheduler of pid {pid}: only the caller's own task is modeled ({cite})"
    if policy & 0x40000000 or policy == 7:
        return f"sched_setscheduler policy {args[1]} is unmodeled ({cite})"
    if policy not in (0, 1, 2, 3, 5):
        return errno_only(ret, errno, {EINVAL}, f"sched_setscheduler policy {policy}", cite)
    if policy != 5:
        return errno_only(ret, errno, {EINVAL}, f"sched_setscheduler policy {policy}",
                          f"{cite}: a success is answered for SCHED_IDLE only")
    return answered(ret, errno, {0}, {EINVAL}, "sched_setscheduler(SCHED_IDLE)", f"{cite}: sched_setscheduler_answer")


RLIM = re.compile(r"\{rlim_cur=(-?\d+),\s*rlim_max=(-?\d+)\}")


def _prlimit64(run, args, ret, errno, tid):
    """Sys/Kernel/Sys.v prlimit64_spec: pid 0, RLIMIT_CORE (4), and exactly one of new and old non-NULL. A successful
    read answers the limit and records it (m_rlimit_core); qemu's print_syscall_ret_prlimit64 prints that old limit
    after the 0 return as `{rlim_cur=..,rlim_max=..}`, so the replay records rlim_max too. A write is unmodeled until
    a read has recorded one; then a soft limit above the hard limit is -EINVAL, a hard limit other than the recorded
    one is unmodeled, and anything else answers 0. If qemu did not print the successful read's old limit, the hard
    limit is not known and a later write is undecided rather than accepted."""
    if len(args) < 4:
        return und("unparseable argument list")
    cite = "Sys/Kernel/Sys.v prlimit64_spec"
    led = run.led
    if num(args[0]) != 0:
        return f"pid {args[0]}: only pid 0 is modeled ({cite})"
    if sym(args[1], {"RLIMIT_CORE": 4}) != 4:
        return f"resource {args[1]}: only RLIMIT_CORE is modeled ({cite})"
    new_null, old_null = is_null(args[2]), is_null(args[3])
    if new_null == old_null:
        return f"exactly one of new_rlim and old_rlim must be non-NULL ({cite})"
    if new_null:
        old_ptr = num(args[3])
        if old_ptr is None:
            return und(f"unparseable old_rlim {args[3]}")
        # read_bytes_map fails: -EFAULT only past access_okb old_rlim 16; an unwritable buffer in range is unmodeled.
        if old_ptr % TWO_POW_64 > TASK_SIZE - RLIMIT64_SIZE:
            return errno_only(ret, errno, {EFAULT}, "a prlimit64 read into a buffer past TASK_SIZE",
                              f"{cite}: access_okb old_rlim 16")
        why = answered(ret, errno, {0}, set(), "a prlimit64 read into a buffer in range",
                       f"{cite}: -EFAULT only past access_okb; an unwritable buffer in range is unmodeled")
        if why:
            return why
        if ret == 0:
            old = RLIM.search(run.tail)
            if not old:
                led.rlimit_core_read = True
                return und("a successful prlimit64 read whose old limit qemu did not print, so rlim_max is not known")
            limit = (int(old.group(1)) % TWO_POW_64, int(old.group(2)) % TWO_POW_64)
            if limit[0] > limit[1]:
                return (f"a prlimit64 read answered rlim_cur {limit[0]} above rlim_max {limit[1]}: the model's limit "
                        f"keeps soft <= hard ({cite}: rlim64_wf)")
            if led.rlimit_core is not None and limit != led.rlimit_core:
                return (f"a prlimit64 read answered {limit} after the model recorded {led.rlimit_core}: a read "
                        f"returns the recorded limit (m_rlimit_core) ({cite})")
            led.rlimit_core_read = True
            led.rlimit_core, led.rlimit_core_hard = limit, limit[1]
        return None
    if not led.rlimit_core_read:
        return (f"a prlimit64 write before any read: the model's m_rlimit_core is None until a read records one, and "
                f"the write arm is unmodeled there ({cite})")
    m = RLIM.search(args[2])
    if not m:
        new_ptr = num(args[2])
        if new_ptr is None or not args[2].strip().startswith("0x"):
            return und(f"unparseable new limit {args[2]}")
        # qemu prints a pointer when it cannot read the new limit (print_rlimit64): read_bytes_map fails, which is
        # -EFAULT past access_okb and unmodeled in range.
        if new_ptr % TWO_POW_64 > TASK_SIZE - RLIMIT64_SIZE:
            return errno_only(ret, errno, {EFAULT}, "a prlimit64 write from a buffer past TASK_SIZE",
                              f"{cite}: access_okb new_rlim 16")
        return f"a prlimit64 write from an unreadable buffer in range is unmodeled ({cite})"
    soft, hard = int(m.group(1)) % TWO_POW_64, int(m.group(2)) % TWO_POW_64
    if hard < soft:
        return errno_only(ret, errno, {EINVAL}, "a prlimit64 write whose hard limit is below its soft limit",
                          f"{cite}: rlim64_hard < rlim64_soft")
    if led.rlimit_core_hard is None:
        return und("the prlimit64 read did not show rlim_max, so the write's hard limit cannot be compared")
    if hard != led.rlimit_core_hard:
        return (f"a prlimit64 write changed rlim_max from {led.rlimit_core_hard} to {hard}: the model answers "
                f"unmodeled when rlim64_hard differs from the recorded limit ({cite})")
    if ret not in (None, 0):
        return (f"a prlimit64 write returned {ret_text(ret, errno)}: the model answers 0 or -EINVAL, and a hard limit "
                f"other than the recorded one is unmodeled ({cite})")
    led.rlimit_core = (soft, hard)
    return None


ACCESS_MODES = {"F_OK": 0, "R_OK": 4, "W_OK": 2, "X_OK": 1}
ACCESS_FLAGS = {"AT_EACCESS": 0x200, "AT_SYMLINK_NOFOLLOW": 0x100, "AT_EMPTY_PATH": 0x1000}


def _faccessat(run, args, ret, errno, tid, name="faccessat"):
    """Sys/Fs/Open.v faccessat_spec and faccessat2_spec: a mode with a bit outside S_IRWXO is -EINVAL
    (modeled_access_mode, read through the low 32 bits); only F_OK is answered (access_mode_f_ok); faccessat2's flag
    bits outside valid_access_flags are -EINVAL and AT_EMPTY_PATH is unmodeled (modeled_access_flags); the dirfd must
    be AT_FDCWD; "." and ".." are answered; a path with a separator or over NAME_MAX is unmodeled."""
    if len(args) < (3 if name == "faccessat" else 4):
        return und("unparseable argument list")
    cite = f"Sys/Fs/Open.v {name}_spec"
    mode = low32(flagword(args[2], ACCESS_MODES))
    if mode is None:
        return und(f"unparseable mode {args[2]}")
    if mode > 7:
        return errno_only(ret, errno, {EINVAL}, f"{name} with mode {args[2]}", "Sys/Fs/Open.v modeled_access_mode")
    if name == "faccessat2":
        fl = low32(flagword(args[3], ACCESS_FLAGS))
        if fl is None:
            return und(f"unparseable flags {args[3]}")
        if fl & ~(0x200 | 0x100 | 0x1000):
            return errno_only(ret, errno, {EINVAL}, f"faccessat2 with flags {args[3]}",
                              "Sys/Fs/Open.v valid_access_flags")
        if fl & 0x1000:
            return "faccessat2 with AT_EMPTY_PATH is unmodeled (Sys/Fs/Open.v modeled_access_flags)"
    if mode != 0:
        return f"mode {args[2]}: only F_OK is answered (Sys/Fs/Open.v access_mode_f_ok)"
    q = quoted(args[1])
    if q is None:
        return und(f"unparseable path {args[1]}")
    path, truncated = q
    # faccessat_body_spec: read_cstr first (-ENAMETOOLONG, -EFAULT), then the empty path is -ENOENT; a name that
    # exists answers access_exists_spec (0 or faccessat_errnos), and one that does not, -ENOENT.
    exists = {0}, {ENOMEM, EACCES, ENAMETOOLONG, EFAULT}
    if path == "":
        return errno_only(ret, errno, {ENOENT, ENAMETOOLONG, EFAULT}, f"{name} of the empty path", cite)
    if args[0].strip() != "AT_FDCWD":
        return f"dirfd {args[0]} is not AT_FDCWD ({cite})"
    if path in (".", ".."):
        return answered(ret, errno, *exists, f"{name} of {path!r}", "Sys/Fs/Open.v access_exists_spec")
    if truncated:
        return und(f"the path {args[1]} was cut short by qemu -strace, so the path tests cannot be decided")
    if "/" in path:
        return f"the path {path!r} has a separator: unmodeled ({cite})"
    if len(path) > NAME_MAX:
        return f"a path longer than NAME_MAX ({cite})"
    # A file the run's environment holds (input.bin) is found by fs_lookup: never -ENOENT.
    absent = set() if path in run.present else {ENOENT}
    return answered(ret, errno, exists[0], exists[1] | absent, f"{name} of {path!r}",
                    "Sys/Fs/Open.v faccessat_body_spec, access_exists_spec")


def _faccessat2(run, args, ret, errno, tid):
    return _faccessat(run, args, ret, errno, tid, name="faccessat2")


CLONE_FLAGS = dict(SIGNALS, **{
    "CLONE_VM": 0x100, "CLONE_FS": 0x200, "CLONE_FILES": 0x400, "CLONE_SIGHAND": 0x800, "CLONE_PIDFD": 0x1000,
    "CLONE_PTRACE": 0x2000, "CLONE_VFORK": 0x4000, "CLONE_PARENT": 0x8000, "CLONE_THREAD": 0x10000,
    "CLONE_NEWNS": 0x20000, "CLONE_SYSVSEM": 0x40000, "CLONE_SETTLS": 0x80000, "CLONE_PARENT_SETTID": 0x100000,
    "CLONE_CHILD_CLEARTID": 0x200000, "CLONE_DETACHED": 0x400000, "CLONE_UNTRACED": 0x800000,
    "CLONE_CHILD_SETTID": 0x1000000, "CLONE_NEWCGROUP": 0x2000000, "CLONE_NEWUTS": 0x4000000,
    "CLONE_NEWIPC": 0x8000000, "CLONE_NEWUSER": 0x10000000, "CLONE_NEWPID": 0x20000000, "CLONE_NEWNET": 0x40000000,
    "CLONE_IO": 0x80000000})
SHARED_FILE_KINDS = FILE_KINDS + ("socket", "pipe")       # Sys/Kernel/Fork.v clone_no_shared_file_b


def clone_shared(run):
    """The reason Sys/Kernel/Fork.v clone_resolve declines, or None: clone_no_shared_file_b is false while a file,
    socket or pipe descriptor is open."""
    led = run.led
    open_kinds = sorted({kind_name(k) for k in led.fds.values() if k[0] in SHARED_FILE_KINDS})
    if open_kinds:
        return (f"a clone while {', '.join(open_kinds)} descriptor(s) are open is unmodeled "
                "(Sys/Kernel/Fork.v clone_resolve: clone_no_shared_file_b)")
    if led.pipe_fds_unknown:
        return ("a clone after this run's pipe2 is unmodeled: the pipe ends are open descriptors and "
                "clone_no_shared_file_b is false for them (Sys/Kernel/Fork.v clone_resolve)")
    return None


def _clone(run, args, ret, errno, tid):
    """Sys/Kernel/Fork.v clone_spec: exactly the flag word SIGCHLD (clone_fork_flags_b, the whole register), then
    clone_resolve: unmodeled while a shared-file descriptor is open, else a child's pid or an errno of clone_errnos.
    check_trace reads a successful fork's arguments only: after it the trace is not the run's alone."""
    if not args:
        return und("unparseable argument list")
    fl = flagword(args[0], CLONE_FLAGS)
    if fl is None:
        return und(f"unparseable flags {args[0]}")
    if fl != 17:
        return f"flags {args[0]}: only the fork word SIGCHLD is modeled (Sys/Kernel/Fork.v clone_fork_flags_b)"
    why = clone_shared(run)
    if why:
        return why
    return errno_in(ret, errno, CLONE_ERRNOS, "clone", "Sys/Kernel/Fork.v clone_errnos")


def _clone3(run, args, ret, errno, tid):
    """Sys/Kernel/Fork.v clone3_spec: the size must be CLONE_ARGS_SIZE (88) and the struct must be a plain fork
    (clone3_fork_args_b), then clone3_resolve, which declines for the same shared descriptors as clone."""
    if len(args) < 2:
        return und("unparseable argument list")
    if num(args[1]) != 88:
        return f"size {args[1]} is not CLONE_ARGS_SIZE 88 (Sys/Kernel/Fork.v clone3_spec)"
    why = clone_shared(run)
    if why:
        return why
    return errno_in(ret, errno, CLONE_ERRNOS, "clone3", "Sys/Kernel/Fork.v clone_errnos")


def _wait4(run, args, ret, errno, tid):
    """Sys/Kernel/Exit.v wait4_spec: wait4(-1, status, WNOHANG, NULL) with no child is -ECHILD, and nothing else
    (check_trace reads nothing after a fork, so the run has no child here)."""
    if len(args) < 4:
        return und("unparseable argument list")
    cite = "Sys/Kernel/Exit.v wait4_spec"
    if low32(num(args[0])) != 0xFFFFFFFF:
        return f"wait4 for pid {args[0]} is unmodeled: only -1 is answered ({cite})"
    if low32(num(args[2])) != 1:
        return f"wait4 options {args[2]}: only WNOHANG (1) is answered ({cite})"
    if not is_null(args[3]):
        return f"wait4 with a non-NULL rusage is unmodeled ({cite})"
    if ret is None:
        return und(f"wait4 with no return in the trace: the model answers only -ECHILD ({cite})")
    return errno_only(ret, errno, {ECHILD}, "wait4(-1, ..., WNOHANG, NULL)", f"{cite}: the run has no child")


def _gettimeofday(run, args, ret, errno, tid):
    """Sys/Kernel/Time/Time.v gettimeofday_spec: a non-NULL tz and a NULL tv are unmodeled; then -EFAULT, or 0 with
    the time written."""
    if len(args) < 2:
        return und("unparseable argument list")
    cite = "Sys/Kernel/Time/Time.v gettimeofday_spec"
    if not is_null(args[1]):
        return f"a non-NULL tz is unmodeled ({cite})"
    if is_null(args[0]):
        return f"a NULL tv is unmodeled ({cite})"
    tv = num(args[0])
    if tv is not None and tv % TWO_POW_64 > TASK_SIZE - 8:
        return errno_only(ret, errno, {EFAULT}, "gettimeofday with a tv past TASK_SIZE", f"{cite}: access_okb")
    # A tv in range that cannot be written is unmodeled, not -EFAULT. qemu prints the pointer in full.
    return answered(ret, errno, {0}, set(), "gettimeofday", cite)


def _getgroups(run, args, ret, errno, tid):
    """Sys/Kernel/Groups.v getgroups_spec: a negative size (sint32) is -EINVAL; a size of 0 answers the number of
    groups (at most NGROUPS_MAX); a size below it is -EINVAL; with no group, 0; delivering a non-empty list is
    unmodeled. The number of groups is the run's, fixed, so every answer must agree with it."""
    if len(args) < 2:
        return und("unparseable argument list")
    cite = "Sys/Kernel/Groups.v getgroups_spec"
    size = sint32(num(args[0]))
    if size is None:
        return und(f"unparseable size {args[0]}")
    led = run.led
    if size < 0:
        return errno_only(ret, errno, {EINVAL}, f"getgroups({size})", cite)
    if ret is None:
        return None
    if size == 0:
        why = answered(ret, errno, range(NGROUPS_MAX + 1), set(), "getgroups(0)", cite)
        if why:
            return why
        if led.ngroups is not None and ret != led.ngroups:
            return f"getgroups(0) returned {ret} after {led.ngroups}: the run's groups do not change ({cite})"
        led.ngroups = ret
        return None
    if ret > 0:
        return f"getgroups({size}) returned {ret}: delivering a non-empty group list is unmodeled ({cite})"
    if ret == 0:
        if led.ngroups not in (None, 0):
            return f"getgroups({size}) returned 0, but the run has {led.ngroups} groups ({cite})"
        led.ngroups = 0
        return None
    why = errno_only(ret, errno, {EINVAL}, f"getgroups({size})", cite)
    if why is None and led.ngroups is not None and size >= led.ngroups:
        return f"getgroups({size}) answered -EINVAL, but the run has {led.ngroups} groups ({cite})"
    return why


def _setgroups(run, args, ret, errno, tid):
    """Sys/Kernel/Groups.v setgroups_spec: -EPERM, or unmodeled for a privileged run."""
    return errno_only(ret, errno, {EPERM}, "setgroups", "Sys/Kernel/Groups.v setgroups_spec")


EFD_FLAGS = {"EFD_CLOEXEC": 0o2000000, "EFD_NONBLOCK": 0o4000, "EFD_SEMAPHORE": 1, "O_CLOEXEC": 0o2000000,
             "O_NONBLOCK": 0o4000}
EFD_FLAGS_SET = 0o2000000 | 0o4000 | 1                 # Sys/Uapi.v EFD_FLAGS_SET
EPOLL_CLOEXEC = 0o2000000                              # Sys/Fs/EventPoll.v EPOLL_CLOEXEC
TFD_FLAGS = {"TFD_CLOEXEC": 0o2000000, "TFD_NONBLOCK": 0o4000, "O_CLOEXEC": 0o2000000, "O_NONBLOCK": 0o4000}
TFD_CREATE_FLAGS = 0o2000000 | 0o4000                  # Sys/Uapi.v TFD_CREATE_FLAGS
TIMERFD_CLOCKS = {0, 1, 7, 8, 9}                       # Sys/Fs/Timerfd.v timerfd_create_einval_b


def _eventfd2(run, args, ret, errno, tid):
    """Sys/Fs/EventFd.v eventfd2_spec answers the refusing half only: a bit outside EFD_FLAGS_SET is -EINVAL
    (eventfd2_einval_b), and every word the kernel accepts is unmodeled."""
    if len(args) < 2:
        return und("unparseable argument list")
    fl = flagword(args[1], EFD_FLAGS)
    if fl is None:
        return und(f"unparseable flags {args[1]}")
    if low32(fl) & ~EFD_FLAGS_SET:
        return errno_only(ret, errno, {EINVAL}, f"eventfd2 with flags {args[1]}", "Sys/Fs/EventFd.v eventfd2_einval_b")
    return (f"eventfd2 with an accepted flag word ({args[1]}) is unmodeled: only the refusing half is modeled "
            "(Sys/Fs/EventFd.v eventfd2_spec)")


def _epoll_create1(run, args, ret, errno, tid):
    """Sys/Fs/EventPoll.v epoll_create1_spec: a bit other than EPOLL_CLOEXEC is -EINVAL; every accepted word is
    unmodeled."""
    if not args:
        return und("unparseable argument list")
    fl = flagword(args[0], {"EPOLL_CLOEXEC": EPOLL_CLOEXEC, "O_CLOEXEC": EPOLL_CLOEXEC})
    if fl is None:
        return und(f"unparseable flags {args[0]}")
    if low32(fl) & ~EPOLL_CLOEXEC:
        return errno_only(ret, errno, {EINVAL}, f"epoll_create1 with flags {args[0]}",
                          "Sys/Fs/EventPoll.v epoll_create1_spec")
    return (f"epoll_create1({args[0]}) is unmodeled: only the refusing half is modeled "
            "(Sys/Fs/EventPoll.v epoll_create1_spec)")


def _epoll_ctl(run, args, ret, errno, tid):
    """Sys/Fs/EventPoll.v epoll_ctl_outcome: -EFAULT, -EBADF, and -EPERM or -EINVAL on a file, directory, socket or
    pipe target; a channel or device target, and every success, is unmodeled."""
    if len(args) < 4:
        return und("unparseable argument list")
    allowed = {EFAULT, EBADF} if low32(num(args[2])) in (0, 1, 2) else {EFAULT, EBADF, EPERM, EINVAL}
    return errno_only(ret, errno, allowed, "epoll_ctl", "Sys/Fs/EventPoll.v epoll_ctl_outcome")


def _epoll_pwait(run, args, ret, errno, tid):
    """Sys/Fs/EventPoll.v epoll_pwait_outcome: the sigmask first (NULL: none; a size other than 8: -EINVAL; readable:
    unmodeled; else -EFAULT), then -EBADF, -EINVAL, -EFAULT; every success is unmodeled."""
    if len(args) < 6:
        return und("unparseable argument list")
    size = num(args[5])
    allowed = ({EBADF, EINVAL, EFAULT} if is_null(args[4])
               else {EINVAL} if size != NSIG_BYTES else {EFAULT})
    return errno_only(ret, errno, allowed, "epoll_pwait", "Sys/Fs/EventPoll.v epoll_pwait_outcome")


def _timerfd_create(run, args, ret, errno, tid):
    """Sys/Fs/Timerfd.v timerfd_create_spec: a clock or a flag word the kernel refuses is -EINVAL
    (timerfd_create_einval_b); every accepted pair is unmodeled."""
    if len(args) < 2:
        return und("unparseable argument list")
    clk, fl = sym(args[0], CLOCK_IDS), flagword(args[1], TFD_FLAGS)
    if clk is None or fl is None:
        return und("unparseable clockid or flags")
    if low32(fl) & ~TFD_CREATE_FLAGS or low32(clk) not in TIMERFD_CLOCKS:
        return errno_only(ret, errno, {EINVAL}, "timerfd_create", "Sys/Fs/Timerfd.v timerfd_create_einval_b")
    return (f"timerfd_create({args[0]},{args[1]}) is unmodeled: only the refusing half is modeled "
            "(Sys/Fs/Timerfd.v timerfd_create_spec)")


def _pselect6(run, args, ret, errno, tid):
    """Sys/Fs/Select.v pselect6_spec: a negative nfds is -EINVAL; above pselect_nfds_max (64) it is unmodeled; a call
    without a timeout that returns 0 (nothing ready, no deadline) is unmodeled."""
    if len(args) < 5:
        return und("unparseable argument list")
    n = sint32(num(args[0]))
    if n is None:
        return und(f"unparseable nfds {args[0]}")
    if n < 0:
        return errno_only(ret, errno, {EINVAL}, "pselect6 with a negative nfds", "Sys/Fs/Select.v pselect6_spec")
    if n > 64:
        return f"pselect6 nfds {n} is above pselect_nfds_max (64): unmodeled (Sys/Fs/Select.v pselect_nfds_max)"
    if is_null(args[4]) and ret == 0:
        return "pselect6 without a timeout returned 0: unmodeled (Sys/Fs/Select.v pselect6_spec)"
    return None


def _ppoll(run, args, ret, errno, tid):
    """Sys/Fs/Select.v ppoll_spec: an nfds above ppoll_nfds_max (30) is unmodeled (the model reads it through
    unfds32); a readable sigmask is unmodeled, so a non-NULL one is answered only with -EINVAL or -EFAULT; a call
    without a timeout that returns 0 is unmodeled."""
    if len(args) < 4:
        return und("unparseable argument list")
    nfds = low32(num(args[1]))
    if nfds is None:
        return und(f"unparseable nfds {args[1]}")
    if nfds > 30:
        return f"ppoll nfds {nfds} is above ppoll_nfds_max (30): unmodeled (Sys/Fs/Select.v ppoll_nfds_max)"
    if not is_null(args[3]):
        return errno_only(ret, errno, {EINVAL, EFAULT}, "ppoll with a sigmask",
                          "Sys/Fs/Select.v ppoll_spec: a readable mask is unmodeled")
    if is_null(args[2]) and ret == 0:
        return "ppoll without a timeout returned 0: unmodeled (Sys/Fs/Select.v ppoll_spec)"
    return answered(ret, errno, range(nfds + 1), {EINVAL, EFAULT}, f"ppoll of {nfds} descriptors",
                    "Sys/Fs/Select.v ppoll_outcome, pselect_finish")


SOCK_FAMILIES = {"PF_UNSPEC": 0, "PF_UNIX": 1, "PF_LOCAL": 1, "PF_INET": 2, "PF_AX25": 3, "PF_IPX": 4,
                 "PF_APPLETALK": 5, "PF_NETROM": 6, "PF_BRIDGE": 7, "PF_ATMPVC": 8, "PF_X25": 9, "PF_INET6": 10,
                 "PF_ROSE": 11, "PF_DECnet": 12, "PF_NETBEUI": 13, "PF_SECURITY": 14, "PF_KEY": 15, "PF_NETLINK": 16,
                 "PF_ROUTE": 16, "PF_PACKET": 17, "PF_ASH": 18, "PF_ECONET": 19, "PF_ATMSVC": 20, "PF_RDS": 21,
                 "PF_SNA": 22, "PF_IRDA": 23, "PF_PPPOX": 24, "PF_WANPIPE": 25, "PF_LLC": 26, "PF_IB": 27,
                 "PF_MPLS": 28, "PF_CAN": 29, "PF_TIPC": 30, "PF_BLUETOOTH": 31, "PF_IUCV": 32, "PF_RXRPC": 33,
                 "PF_ISDN": 34, "PF_PHONET": 35, "PF_IEEE802154": 36, "PF_CAIF": 37, "PF_ALG": 38, "PF_NFC": 39,
                 "PF_VSOCK": 40, "PF_KCM": 41, "PF_QIPCRTR": 42, "PF_SMC": 43, "PF_XDP": 44, "PF_MCTP": 45}
SOCK_FAMILIES.update({k.replace("PF_", "AF_"): v for k, v in list(SOCK_FAMILIES.items())})
SOCK_TYPES = {"SOCK_STREAM": 1, "SOCK_DGRAM": 2, "SOCK_RAW": 3, "SOCK_RDM": 4, "SOCK_SEQPACKET": 5, "SOCK_DCCP": 6,
              "SOCK_PACKET": 10, "SOCK_CLOEXEC": 0o2000000, "SOCK_NONBLOCK": 0o4000}
SOCK_TYPE_MASK, SOCK_CLOEXEC, SOCK_NONBLOCK = 0xF, 0o2000000, 0o4000
IPPROTO = {"IPPROTO_IP": 0, "IPPROTO_ICMP": 1, "IPPROTO_IGMP": 2, "IPPROTO_TCP": 6, "IPPROTO_UDP": 17,
           "IPPROTO_IPV6": 41, "IPPROTO_RAW": 255, "IPPROTO_SCTP": 132, "IPPROTO_MPTCP": 262}
MSG_FLAGS = {"MSG_OOB": 1, "MSG_PEEK": 2, "MSG_DONTROUTE": 4, "MSG_CTRUNC": 8, "MSG_TRUNC": 0x20, "MSG_DONTWAIT": 0x40,
             "MSG_EOR": 0x80, "MSG_WAITALL": 0x100, "MSG_NOSIGNAL": 0x4000, "MSG_MORE": 0x8000,
             "MSG_CMSG_CLOEXEC": 0x40000000}
MSG_NOSIGNAL = 0x4000


def _socket(run, args, ret, errno, tid):
    """Sys/Net/Socket.v socket_spec: a type bit outside the mask and SOCK_CLOEXEC|SOCK_NONBLOCK is -EINVAL;
    SOCK_NONBLOCK is unmodeled; a family outside [0, 46) is -EAFNOSUPPORT; a base type of 11 or more is -EINVAL; a
    family other than AF_INET is unmodeled; SOCK_PACKET is unmodeled; a protocol outside [0, 263) is -EINVAL;
    SOCK_STREAM with protocol 132 or 262 is unmodeled, with another protocol than 0 or 6 -EPROTONOSUPPORT, else the
    one answered success; SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET and SOCK_DCCP are unmodeled."""
    if len(args) < 3:
        return und("unparseable argument list")
    fam, ty, proto = sym(args[0], SOCK_FAMILIES), flagword(args[1], SOCK_TYPES), sym(args[2], IPPROTO)
    if fam is None or ty is None or proto is None:
        return und("unparseable socket arguments")
    fam, ty, proto = sint32(fam), low32(ty), sint32(proto)
    cite = "Sys/Net/Socket.v socket_spec"
    if ty & ~(SOCK_TYPE_MASK | SOCK_CLOEXEC | SOCK_NONBLOCK):
        return errno_only(ret, errno, {EINVAL}, f"socket with type {args[1]}", cite)
    if ty & SOCK_NONBLOCK:
        return f"socket(SOCK_NONBLOCK) is unmodeled ({cite})"
    base = ty & SOCK_TYPE_MASK
    if not 0 <= fam < 46:
        return errno_only(ret, errno, {EAFNOSUPPORT}, f"socket of family {args[0]}", cite)
    if base >= 11:
        return errno_only(ret, errno, {EINVAL}, f"socket with type {args[1]}", cite)
    if fam != 2:
        return f"socket family {args[0]} is unmodeled: only AF_INET is answered ({cite})"
    if base == 10:
        return f"socket(SOCK_PACKET) is unmodeled ({cite})"
    if not 0 <= proto < 263:
        return errno_only(ret, errno, {EINVAL}, f"socket with protocol {args[2]}", cite)
    if base == 1:
        if proto in (132, 262):
            return f"socket(AF_INET, SOCK_STREAM, {args[2]}) is unmodeled ({cite})"
        if proto not in (0, 6):
            return errno_only(ret, errno, {EPROTONOSUPPORT}, f"socket(AF_INET, SOCK_STREAM, {args[2]})", cite)
        if ret is not None and ret >= 0 and ret in run.led.fds:
            return f"socket returned {ret}, a descriptor the run already holds ({cite}: lowest_fd)"
        why = refused(ret, errno, SOCKET_ERRNOS, "socket(AF_INET, SOCK_STREAM)", f"{cite}, socket_errnos")
        if why is None and ret is not None and ret >= 0:
            run.led.fds[ret] = ("socket", True)
        return why
    if base in (2, 3, 5, 6):
        return f"socket(AF_INET, {args[1]}) is unmodeled: only SOCK_STREAM is answered ({cite})"
    return errno_only(ret, errno, {ESOCKTNOSUPPORT}, f"socket with type {args[1]}", cite)


def _socketpair(run, args, ret, errno, tid):
    """Sys/Net/Socket.v socketpair_spec: a bad flag bit is -EINVAL; anything but AF_INET with SOCK_STREAM or SOCK_DGRAM
    and protocol 0 is unmodeled; the answered words never succeed."""
    if len(args) < 4:
        return und("unparseable argument list")
    fam, ty, proto = sym(args[0], SOCK_FAMILIES), flagword(args[1], SOCK_TYPES), sym(args[2], IPPROTO)
    if fam is None or ty is None or proto is None:
        return und("unparseable socketpair arguments")
    ty = low32(ty)
    cite = "Sys/Net/Socket.v socketpair_spec"
    if ty & ~(SOCK_TYPE_MASK | SOCK_CLOEXEC | SOCK_NONBLOCK):
        return errno_only(ret, errno, {EINVAL}, f"socketpair with type {args[1]}", cite)
    if not (sint32(fam) == 2 and (ty & SOCK_TYPE_MASK) in (1, 2) and sint32(proto) == 0):
        return (f"socketpair({args[0]}, {args[1]}, {args[2]}) is unmodeled: only AF_INET stream or datagram with "
                f"protocol 0 is answered ({cite})")
    return errno_only(ret, errno, {EOPNOTSUPP, EFAULT}, "socketpair", f"{cite}: the answered words never succeed")


def _accept(run, args, ret, errno, tid, name="accept"):
    """Sys/Net/Socket.v accept4_spec (accept is flags 0): a descriptor the table does not hold is -EBADF; a bad flag
    is -EINVAL; SOCK_NONBLOCK is unmodeled; a non-NULL address is unmodeled."""
    if len(args) < (3 if name == "accept" else 4):
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v accept4_spec"
    why = bad_fd_only(run, num(args[0]), ret, errno, name, cite)
    if why or run.led.kind(num(args[0])) is ABSENT:
        return why
    fl = 0 if name == "accept" else flagword(args[3], SOCK_TYPES)
    if fl is None:
        return und(f"unparseable flags {args[3]}")
    if low32(fl) & ~(SOCK_CLOEXEC | SOCK_NONBLOCK):
        return errno_only(ret, errno, {EINVAL}, f"{name} with flags {args[3]}", cite)
    if low32(fl) & SOCK_NONBLOCK:
        return f"accept4(SOCK_NONBLOCK) is unmodeled ({cite})"
    if not is_null(args[1]):
        return f"{name} with a non-NULL address is unmodeled ({cite})"
    kind = run.led.kind(num(args[0]))
    if kind is not None and kind is not ABSENT and kind[0] != "socket":
        return errno_only(ret, errno, {ENOTSOCK}, f"{name} on a {kind_name(kind)} descriptor", cite)
    if kind is None:
        return kind_reason(num(args[0]), ret, errno, name, cite)
    if sock_state(kind) != "listening":
        return errno_only(ret, errno, {EINVAL}, f"{name} on a socket that is not listening", cite)
    if ret is not None and ret >= 0 and ret in run.led.fds:
        return f"{name} returned {ret}, a descriptor the run already holds ({cite}: lowest_fd)"
    why = refused(ret, errno, SOCKET_ERRNOS, name, f"{cite}, accept_errnos")
    if why is None and ret is not None and ret >= 0:
        run.led.fds[ret] = ("socket", False, "connected")
    return why


def _accept4(run, args, ret, errno, tid):
    return _accept(run, args, ret, errno, tid, name="accept4")


def _connect(run, args, ret, errno, tid):
    """Sys/Net/Socket.v connect_spec, in its order: a descriptor the table does not hold is -EBADF; an addrlen (read
    through sint32) outside [0, SOCKADDR_STORAGE_SIZE] is -EINVAL; an unreadable address -EFAULT; a descriptor that is
    not a socket -ENOTSOCK; on a socket an addrlen below SA_FAMILY_SIZE is -EINVAL; an AF_UNSPEC address answers 0 on
    a fresh socket and is unmodeled on any other; any other family is -EISCONN on a listening, connected or reset
    socket, and on a fresh or bound one -EINVAL below SOCKADDR_IN_SIZE, -EAFNOSUPPORT for a family other than AF_INET,
    and unmodeled for AF_INET (the attempt itself is the environment's).

    qemu prints connect's address as a 32-bit pointer (strace.list `%s(%d,%#x,%d)` at v10.0.11), so the
    trace never shows the family. qemu copies the address into its own buffer and makes the host call with it
    (do_connect, target_to_host_sockaddr), and the host-call log gives that buffer's family. When qemu cannot read the
    address it answers -EFAULT itself, with no host call: that is the model's -EFAULT."""
    if len(args) < 3:
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v connect_spec"
    fd = num(args[0])
    why = bad_fd_only(run, fd, ret, errno, "connect", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    alen = sint32(num(args[2]))
    if alen is None:
        return und(f"unparseable addrlen {args[2]}")
    if alen < 0 or alen > SOCKADDR_STORAGE_SIZE:
        return errno_only(ret, errno, {EINVAL}, f"connect with addrlen {alen}", cite)
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "connect", cite)
    if kind[0] != "socket":
        return errno_only(ret, errno, {ENOTSOCK, EFAULT}, f"connect on a {kind_name(kind)} descriptor", cite)
    keys = {0: Arg.cut(fd), 2: Arg.cut(num(args[2]))}
    if ret is not None and ret < 0 and errno == EFAULT:
        # The model's -EFAULT is an address it cannot read (read_bytes_map fails), before anything else is looked at.
        # qemu answers it itself, with no host call; a host line of this call means qemu did read the address.
        if run.host.take("connect", keys, (), ret, errno) is None:
            return None
        return (f"connect returned -EFAULT, but the host-call log holds its host call, so qemu read the address, and "
                f"{cite} answers -EFAULT only for an address it cannot read (read_bytes_map)")
    if alen < SA_FAMILY_SIZE:
        return errno_only(ret, errno, {EINVAL}, f"connect with addrlen {alen}, shorter than a family", cite)
    host = run.host.take("connect", keys, (HOST_FAMILY,), ret, errno)
    family = host[HOST_FAMILY] if host else None
    if family is None:
        return und(f"connect returned {ret_text(ret, errno)}, and no line of the host-call log gives the family of "
                   f"its address, which qemu prints as a pointer and {cite} answers by")
    state = sock_state(kind)
    if family == AF_UNSPEC:
        if state != "fresh":
            return (f"connect with an AF_UNSPEC address on a {state} socket is unmodeled ({cite}: a real disconnect, "
                    "which the model does not have)")
        # AF_UNSPEC on SkFresh answers 0 and changes nothing: the socket stays fresh.
        return answered(ret, errno, {0}, set(), "connect(AF_UNSPEC) on a fresh socket", cite)
    if state in ("listening", "connected", "reset"):
        return errno_only(ret, errno, {EISCONN}, f"connect on a {state} socket", cite)
    if alen < SOCKADDR_IN_SIZE:
        return errno_only(ret, errno, {EINVAL}, f"connect with addrlen {alen}, shorter than a sockaddr_in", cite)
    if family != AF_INET:
        return errno_only(ret, errno, {EAFNOSUPPORT}, f"connect with an address of family {family}", cite)
    return (f"connect with an AF_INET address on a {state} socket returned {ret_text(ret, errno)}: the attempt itself "
            f"is unmodeled ({cite})")


def sock_fd_kind(run, fd, ret, errno, name, cite, errnos=frozenset()):
    """Sys/Net/Socket.v sock_fd for the calls that read only the descriptor before the socket: (kind, None) for a
    socket, or (None, the reason or None) when the call is decided here: a descriptor the table does not hold answers
    -EBADF, any other kind -ENOTSOCK. `errnos` are answers that come before the descriptor's."""
    if run.led.kind(fd) is ABSENT:
        return None, errno_only(ret, errno, {EBADF} | errnos, f"{name} on descriptor {fd}, which this run never opened",
                                cite)
    kind = run.led.kind(fd)
    if kind is None:
        return None, kind_reason(fd, ret, errno, name, cite)
    if kind[0] != "socket":
        return None, errno_only(ret, errno, {ENOTSOCK} | errnos, f"{name} on a {kind_name(kind)} descriptor", cite)
    return kind, None


def _getsockname(run, args, ret, errno, tid):
    """Sys/Net/Socket.v getsockname_spec: on a socket every answer is unmodeled (an address write, and a port the model
    cannot know)."""
    cite = "Sys/Net/Socket.v getsockname_spec"
    kind, why = sock_fd_kind(run, num(args[0]) if args else None, ret, errno, "getsockname", cite)
    if kind is None:
        return why
    return f"getsockname on a socket returned {ret_text(ret, errno)}: every answer there is unmodeled ({cite})"


def _getpeername(run, args, ret, errno, tid):
    """Sys/Net/Socket.v getpeername_spec: -ENOTCONN on a fresh, bound, listening or reset socket; unmodeled on a
    connected one."""
    cite = "Sys/Net/Socket.v getpeername_spec"
    kind, why = sock_fd_kind(run, num(args[0]) if args else None, ret, errno, "getpeername", cite)
    if kind is None:
        return why
    state = sock_state(kind)
    if state == "connected":
        return f"getpeername on a connected socket returned {ret_text(ret, errno)}: unmodeled ({cite})"
    return errno_only(ret, errno, {ENOTCONN}, f"getpeername on a {state} socket", cite)


def _setsockopt(run, args, ret, errno, tid):
    """Sys/Net/Socket.v setsockopt_spec: on a socket a negative optlen (int32_neg) is -EINVAL, a level outside
    SOL_SOCKET, IPPROTO_IP and IPPROTO_TCP -ENOPROTOOPT, and every option of those levels unmodeled. qemu prints
    setsockopt through `%s(%d,%d,%d,%p,%p)`: the level as an int, optlen in full."""
    if len(args) < 5:
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v setsockopt_spec"
    kind, why = sock_fd_kind(run, num(args[0]), ret, errno, "setsockopt", cite)
    if kind is None:
        return why
    level, optlen = num(args[1]), num(args[4])
    if level is None or optlen is None:
        return und("unparseable argument list")
    if sint32(optlen) < 0:
        return errno_only(ret, errno, {EINVAL}, f"setsockopt with optlen {args[4]}", f"{cite}: int32_neg optlen")
    if level % TWO_POW_64 not in SOCK_LEVELS:
        return errno_only(ret, errno, {ENOPROTOOPT}, f"setsockopt at level {args[1]}", f"{cite}: sock_level_known")
    return f"setsockopt at level {args[1]} returned {ret_text(ret, errno)}: the option table is unmodeled ({cite})"


def _getsockopt(run, args, ret, errno, tid):
    """Sys/Net/Socket.v getsockopt_spec: a level outside {0, 1, 6} is -EOPNOTSUPP; the levels it reads are
    unmodeled."""
    if len(args) < 2:
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v getsockopt_spec"
    kind, why = sock_fd_kind(run, num(args[0]), ret, errno, "getsockopt", cite)
    if kind is None:
        return why
    if sint32(num(args[1])) in SOCK_LEVELS:
        return f"getsockopt at level {args[1]} is unmodeled ({cite})"
    return errno_only(ret, errno, {EOPNOTSUPP}, f"getsockopt at level {args[1]}", f"{cite}: sock_level_known")


def _shutdown(run, args, ret, errno, tid):
    """Sys/Net/Socket.v shutdown_spec: a how outside {0, 1, 2} is -EINVAL; a success is answered for SHUT_WR only."""
    if len(args) < 2:
        return und("unparseable argument list")
    why = bad_fd_only(run, num(args[0]), ret, errno, "shutdown", "Sys/Net/Socket.v shutdown_spec")
    if why or run.led.kind(num(args[0])) is ABSENT:
        return why
    how = sym(args[1], {"SHUT_RD": 0, "SHUT_WR": 1, "SHUT_RDWR": 2})
    if how is None:
        return und(f"unparseable how {args[1]}")
    how = how % TWO_POW_64              # shut_how_ok reads the whole register, and qemu prints it in full
    cite = "Sys/Net/Socket.v shutdown_spec"
    kind = run.led.kind(num(args[0]))
    if kind is None:
        return kind_reason(num(args[0]), ret, errno, "shutdown", cite)
    if kind[0] != "socket":
        return errno_only(ret, errno, {ENOTSOCK}, f"shutdown of a {kind_name(kind)}", cite)
    if how not in (0, 1, 2):
        return errno_only(ret, errno, {EINVAL}, f"shutdown({args[1]})", f"{cite}: shut_how_ok")
    if how != 1 or sock_state(kind) != "listening":
        return (f"shutdown({args[1]}) of a {sock_state(kind)} socket is unmodeled: only SHUT_WR on a listening socket "
                f"is answered ({cite})")
    return answered(ret, errno, {0}, set(), "shutdown(SHUT_WR) of a listening socket", cite)


def _sendto(run, args, ret, errno, tid):
    """Sys/Net/Socket.v sendto_spec: flags exactly MSG_NOSIGNAL (send_flags_modeled, through sendflags32); a non-NULL
    destination address is unmodeled; a count above rw_bytes_max is unmodeled (modeled_rw_count, which reads the count
    unsigned); then the descriptor, where anything but a socket is -ENOTSOCK. qemu prints the count in full, signed,
    so a negative print is a count at or above 2^63."""
    if len(args) < 6:
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v sendto_spec"
    fl = flagword(args[3], MSG_FLAGS)
    if fl is None:
        return und(f"unparseable flags {args[3]}")
    if low32(fl) != MSG_NOSIGNAL:
        return f"sendto flags {args[3]}: exactly MSG_NOSIGNAL is modeled ({cite}: send_flags_modeled)"
    if not is_null(args[4]):
        return f"sendto with a destination address is unmodeled ({cite})"
    count = num(args[2])
    if count is None:
        return und(f"unparseable count {args[2]}")
    if count % TWO_POW_64 > RW_BYTES_MAX:
        return (f"sendto count {count % TWO_POW_64} is above rw_bytes_max {RW_BYTES_MAX}: unmodeled "
                f"({cite}: Sys/Uaccess.v modeled_rw_count reads the count unsigned)")
    # qemu prints the buffer as a quoted string only when it could read all `count` bytes of it (strace.c print_buf:
    # lock_user VERIFY_READ), so the buffer lies below TASK_SIZE and access_ok_zero cannot answer -EFAULT.
    efault = set() if args[1].startswith('"') else {EFAULT}
    if run.led.kind(num(args[0])) is ABSENT:
        # access_ok_zero wraps the descriptor's lookup, so an unreadable buffer is -EFAULT before -EBADF.
        return errno_only(ret, errno, {EBADF} | efault, f"sendto on descriptor {args[0]}, which this run never opened",
                          f"{cite}: access_ok_zero, fd_lookup")
    kind = run.led.kind(num(args[0]))
    if kind is None:
        return kind_reason(num(args[0]), ret, errno, "sendto", cite)
    if kind[0] != "socket":
        return errno_only(ret, errno, {ENOTSOCK} | efault, f"sendto on a {kind_name(kind)} descriptor", cite)
    # Sys/Net/Socket.v send_on_socket, behind access_ok_zero (-EFAULT): a socket no connect has reached, or one whose
    # peer error was reported, is SendDead (-EPIPE); a connected one gives -ECONNRESET or -ETIMEDOUT once (and is then
    # SkReset), or 1..count bytes (0 for a count of 0), never -EPIPE.
    if not sock_connected(kind):
        return errno_only(ret, errno, {EPIPE} | efault, f"sendto on a {sock_state(kind)} socket",
                          f"{cite}: send_state SendDead")
    why = counted(ret, errno, Arg.full(count), efault | PEER_ERRNOS, "sendto on a connected socket",
                  f"{cite}: send_on_socket", shape="positive")
    if why is None:
        peer_error(run, num(args[0]), ret, errno)
    return why


def _sendmsg(run, args, ret, errno, tid):
    """Sys/Net/Socket.v sendmsg_spec: flags exactly MSG_NOSIGNAL; then the descriptor (-EBADF, -ENOTSOCK); then the
    header and its iovecs, which the trace does not show (-EFAULT, -EMSGSIZE, -EINVAL, or unmodeled shapes); then
    send_on_socket, as sendto: -EPIPE on a socket no connect has reached or whose peer error was reported, and on a
    connected one -ECONNRESET or -ETIMEDOUT once, or a byte count up to the iovec total, which is at most
    rw_bytes_max (a larger total is unmodeled)."""
    if len(args) < 3:
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v sendmsg_spec"
    fl = flagword(args[2], MSG_FLAGS)
    if fl is None:
        return und(f"unparseable flags {args[2]}")
    if low32(fl) != MSG_NOSIGNAL:
        return f"sendmsg flags {args[2]}: exactly MSG_NOSIGNAL is modeled ({cite})"
    kind, why = sock_fd_kind(run, num(args[0]), ret, errno, "sendmsg", cite)
    if kind is None:
        return why
    imported = {EFAULT, EMSGSIZE, EINVAL}
    if not sock_connected(kind):
        return errno_only(ret, errno, imported | {EPIPE}, f"sendmsg on a {sock_state(kind)} socket",
                          f"{cite}: send_state SendDead")
    if ret is not None and ret > RW_BYTES_MAX:
        return (f"sendmsg returned {ret}: the model sends at most the iovec total, and a total above rw_bytes_max "
                f"{RW_BYTES_MAX} is unmodeled ({cite}: iovs_total, Sys/Uaccess.v rw_bytes_max)")
    why = counted(ret, errno, None, imported | PEER_ERRNOS, "sendmsg on a connected socket",
                  f"{cite}: send_on_socket")
    if why is None:
        peer_error(run, num(args[0]), ret, errno)
    return why


def _recvfrom(run, args, ret, errno, tid):
    """Sys/Net/Socket.v recvfrom_spec: a size above rw_bytes_max is unmodeled (modeled_rw_count); an unreadable range
    is -EFAULT (access_ok_zero), before the descriptor: -EBADF, -ENOTSOCK, and on a socket unmodeled. qemu prints the
    size in full (print_recvfrom: TARGET_ABI_FMT_ld at v10.0.11)."""
    if len(args) < 3:
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v recvfrom_spec"
    buf, size = Arg.full(num(args[1])), Arg.full(num(args[2]))
    if buf is None or size is None:
        return und("unparseable argument list")
    if size.v > RW_BYTES_MAX:
        return f"recvfrom size {size.v} is above rw_bytes_max {RW_BYTES_MAX}: unmodeled ({cite})"
    if not access_ok(buf, size):
        return errno_only(ret, errno, {EFAULT}, "recvfrom whose range runs past TASK_SIZE",
                          f"{cite}: access_ok_zero")
    kind, why = sock_fd_kind(run, num(args[0]), ret, errno, "recvfrom", cite)
    if kind is None:
        return why
    return f"recvfrom on a socket returned {ret_text(ret, errno)}: a receive on a socket is unmodeled ({cite})"


def _recvmsg(run, args, ret, errno, tid):
    """Sys/Net/Socket.v recvmsg_spec: MSG_CMSG_COMPAT in the flags' low 32 bits is unmodeled; then the descriptor
    (-EBADF, -ENOTSOCK), and on a socket unmodeled."""
    if len(args) < 3:
        return und("unparseable argument list")
    cite = "Sys/Net/Socket.v recvmsg_spec"
    fl = flagword(args[2], MSG_FLAGS)
    if fl is None:
        return und(f"unparseable flags {args[2]}")
    if low32(fl) & MSG_CMSG_COMPAT:
        return f"recvmsg flags {args[2]}: MSG_CMSG_COMPAT is unmodeled ({cite})"
    kind, why = sock_fd_kind(run, num(args[0]), ret, errno, "recvmsg", cite)
    if kind is None:
        return why
    return f"recvmsg on a socket returned {ret_text(ret, errno)}: a receive on a socket is unmodeled ({cite})"


def _fsync(run, args, ret, errno, tid):
    """Sys/Fs/Sync.v fsync_spec: -EBADF for a descriptor the table does not hold; -EINVAL on a channel, socket, pipe
    end, /dev/null or /dev/urandom; 0 on a file or a directory."""
    cite = "Sys/Fs/Sync.v fsync_spec"
    fd = num(args[0]) if args else None
    why = bad_fd_only(run, fd, ret, errno, "fsync", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "fsync", cite)
    if kind[0] in FILE_KINDS or kind[0] == "dir":
        return answered(ret, errno, {0}, set(), f"fsync of a {kind_name(kind)}", cite)
    return errno_only(ret, errno, {EINVAL}, f"fsync of a {kind_name(kind)}", cite)


def _ftruncate(run, args, ret, errno, tid):
    """Sys/Fs/Open.v ftruncate_spec: a negative length is -EINVAL first; -EBADF for a descriptor the table does not
    hold; -EINVAL on every kind but a writable file; on a writable file 0, or unmodeled past modeled_truncate_gap
    (the file's length, which the trace does not show)."""
    if len(args) < 2:
        return und("unparseable argument list")
    cite = "Sys/Fs/Open.v ftruncate_spec"
    fd, length = num(args[0]), num(args[1])
    if length is None:
        return und(f"unparseable length {args[1]}")
    if length < 0 or length >= TWO_POW_64 >> 1:
        return errno_only(ret, errno, {EINVAL}, "ftruncate to a negative length", cite)
    why = bad_fd_only(run, fd, ret, errno, "ftruncate", cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, "ftruncate", cite)
    if kind[0] in ("filew", "filea", "filerw"):
        if length > RW_BYTES_MAX:
            # modeled_truncate_gap: a length more than rw_bytes_max past the file's is unmodeled, and the trace does
            # not show the file's length.
            return und(f"ftruncate to {length} bytes: past rw_bytes_max the answer turns on the file's length, which "
                       f"the trace does not show ({cite}: modeled_truncate_gap)")
        return answered(ret, errno, {0}, set(), f"ftruncate of a {kind_name(kind)}", cite)
    return errno_only(ret, errno, {EINVAL}, f"ftruncate of a {kind_name(kind)}", cite)


# The address structs qemu's print_sockaddr writes (linux-user/strace.c at v10.0.11), one per family it
# names; any other family prints as `{sa_family=N, sa_data={14 bytes}}`. Each is matched whole from the struct's first
# byte: an AF_UNIX path is guest text and can hold anything, so nothing is searched for inside a struct.
SOCKADDR_NAMED = re.compile(r"\{(?:sin|sun|sll|nl)_family=(AF_INET|AF_UNIX|AF_PACKET|AF_NETLINK)[,}]")
SOCKADDR_IN = re.compile(r'\{sin_family=AF_INET,sin_port=htons\((\d+)\),'
                         r'sin_addr=inet_addr\("(\d+)\.(\d+)\.(\d+)\.(\d+)"\)\}')
SOCKADDR_OTHER = re.compile(r"\{sa_family=(\d+), sa_data=\{((?:[0-9a-f]{2}, ){13}[0-9a-f]{2})\}\}")
SOCKADDR_FAMILIES = {"AF_INET": AF_INET, "AF_UNIX": AF_UNIX, "AF_PACKET": AF_PACKET, "AF_NETLINK": AF_NETLINK}


def sockaddr(arg):
    """(family, port, address) of an address qemu printed as a struct (strace.c print_sockaddr): the family always,
    the port and IPv4 address where the print shows them (AF_INET, and the sa_data bytes of an unnamed family), else
    None. None for a print that is not one of those structs: qemu prints a pointer when it could not read the
    address."""
    a = arg.strip()
    m = SOCKADDR_IN.fullmatch(a)
    if m:
        return AF_INET, int(m.group(1)), sum(int(b) << (8 * (3 - i)) for i, b in enumerate(m.group(2, 3, 4, 5)))
    m = SOCKADDR_OTHER.fullmatch(a)
    if m:
        raw = [int(b, 16) for b in m.group(2).split(", ")]
        # sa_data is the sockaddr from byte 2: a sockaddr_in's port, then its IPv4 address (Socket.v sin_addr_of)
        return int(m.group(1)), (raw[0] << 8) | raw[1], int.from_bytes(bytes(raw[2:6]), "big")
    m = SOCKADDR_NAMED.match(a)
    if m:
        return SOCKADDR_FAMILIES[m.group(1)], None, None
    return None


def _bind_listen(run, args, ret, errno, name):
    """Sys/Net/Socket.v bind_spec and listen_spec. Both start with the descriptor: -EBADF for one the table does not
    hold, -ENOTSOCK for one that is not a socket. bind then reads the address: an addrlen (sint32) outside
    (0, SOCKADDR_STORAGE_SIZE] is -EINVAL; an unreadable address -EFAULT; one shorter than a sockaddr_in -EINVAL; a
    family other than AF_INET (or AF_UNSPEC with INADDR_ANY) -EAFNOSUPPORT; an address other than INADDR_ANY, or a
    port other than 0, is unmodeled; then a fresh socket answers bind_errnos or 0 (SkBound), and any other -EINVAL.
    listen answers listen_errnos or 0 on a fresh socket, 0 on a bound or listening one (SkListening), and -EINVAL on
    a connected or reset one."""
    fd = num(args[0]) if args else None
    cite = f"Sys/Net/Socket.v {name}_spec"
    why = bad_fd_only(run, fd, ret, errno, name, cite)
    if why or run.led.kind(fd) is ABSENT:
        return why
    kind = run.led.kind(fd)
    if kind is None:
        return kind_reason(fd, ret, errno, name, cite)
    if kind[0] != "socket":
        return errno_only(ret, errno, {ENOTSOCK}, f"{name} on a {kind_name(kind)} descriptor", cite)
    state = sock_state(kind)
    if name == "listen":
        if state in ("connected", "reset"):
            return errno_only(ret, errno, {EINVAL}, f"listen on a {state} socket", cite)
        why = answered(ret, errno, {0}, BIND_ERRNOS if state == "fresh" else set(), f"listen on a {state} socket",
                       f"{cite}, listen_errnos")
        if why is None and ret == 0:
            run.led.fds[fd] = ("socket", False, "listening")
        return why
    if len(args) < 3:
        return und("unparseable argument list")
    al = sint32(num(args[2]))
    if al is None:
        return und(f"unparseable addrlen {args[2]}")
    if al <= 0 or al > SOCKADDR_STORAGE_SIZE:
        return errno_only(ret, errno, {EINVAL}, f"bind with addrlen {al}", cite)
    addr = sockaddr(args[1])
    if addr is None:
        # qemu prints a pointer when lock_user(addr, addrlen) fails, and do_bind's target_to_host_sockaddr locks the
        # same range and answers -EFAULT with no host call: the model's -EFAULT (read_bytes_map fails). The two agree
        # only when the printed addrlen, which print_sockaddr reads as a whole register, is the 32-bit one bind uses.
        if not args[1].strip().startswith("0x") or num(args[2]) != al:
            return und(f"bind of {args[1]} with addrlen {args[2]}: the trace does not show the address {cite} reads")
        return errno_only(ret, errno, {EFAULT}, "bind of an address qemu could not read", f"{cite}: read_bytes_map")
    if al < SOCKADDR_IN_SIZE:
        return errno_only(ret, errno, {EINVAL}, f"bind with addrlen {al}, shorter than a sockaddr_in", cite)
    family, port, ip = addr
    if not (family == AF_INET or (family == AF_UNSPEC and ip == 0)):
        return errno_only(ret, errno, {EAFNOSUPPORT}, f"bind of an address of family {family}", cite)
    if ip != 0 or port != 0:
        return f"bind to an address other than INADDR_ANY port 0 is unmodeled ({cite})"
    if state == "reset":
        return (f"bind on a socket whose peer reset it is unmodeled ({cite}: Linux autobinds it again, and SockState "
                "cannot hold a bound socket that reads as end-of-stream)")
    if state != "fresh":
        return errno_only(ret, errno, {EINVAL}, f"bind on a {state} socket", cite)
    why = answered(ret, errno, {0}, BIND_ERRNOS, "bind on a fresh socket", f"{cite}, bind_errnos")
    if why is None and ret == 0:
        run.led.fds[fd] = ("socket", False, "bound")
    return why


def _bind(run, args, ret, errno, tid):
    return _bind_listen(run, args, ret, errno, "bind")


def _listen(run, args, ret, errno, tid):
    return _bind_listen(run, args, ret, errno, "listen")


GATES = {
    "mmap": _mmap, "munmap": _munmap, "madvise": _madvise, "brk": _brk, "mremap": _mremap, "mprotect": _mprotect,
    "openat": _openat, "close": _close, "unlinkat": _unlinkat, "faccessat": _faccessat, "faccessat2": _faccessat2,
    "newfstatat": _newfstatat, "fstat": _fstat, "readlinkat": _readlinkat, "getcwd": _getcwd,
    "getdents64": _getdents64, "ftruncate": _ftruncate, "fsync": _fsync, "fdatasync": _fsync,
    "read": _read, "write": _write, "readv": _readv, "writev": _writev, "pread64": _pread64, "pwrite64": _pwrite64,
    "lseek": _lseek, "ioctl": _ioctl, "fcntl": _fcntl, "flock": _flock, "dup": _dup, "dup3": _dup3, "pipe2": _pipe2,
    "pselect6": _pselect6, "ppoll": _ppoll, "eventfd2": _eventfd2, "epoll_create1": _epoll_create1,
    "epoll_ctl": _epoll_ctl, "epoll_pwait": _epoll_pwait, "timerfd_create": _timerfd_create,
    "getrandom": _getrandom, "clock_gettime": _clock_gettime, "gettimeofday": _gettimeofday, "nanosleep": _nanosleep,
    "rt_sigaction": _rt_sigaction, "rt_sigprocmask": _rt_sigprocmask, "sigaltstack": _sigaltstack,
    "tkill": _tkill, "tgkill": _tgkill, "futex": _futex, "clone": _clone, "clone3": _clone3, "wait4": _wait4,
    "prctl": _prctl, "prlimit64": _prlimit64, "set_tid_address": _set_tid_address, "getpid": _set_tid_address,
    "gettid": _set_tid_address, "setsid": _setsid, "sched_yield": _sched_yield, "uname": _uname,
    **{n: (lambda run, args, ret, errno, tid, n=n: _setid(run, args, ret, errno, tid, n))
       for n in ("setuid", "setgid")},
    **{n: (lambda run, args, ret, errno, tid, n=n: _setresid(run, args, ret, errno, tid, n))
       for n in ("setresuid", "setresgid")},
    **{n: (lambda run, args, ret, errno, tid, n=n: _getid(run, args, ret, errno, tid, n))
       for n in ("getuid", "geteuid", "getgid", "getegid")},
    "sched_getaffinity": _sched_getaffinity, "sched_setscheduler": _sched_setscheduler,
    "getgroups": _getgroups, "setgroups": _setgroups,
    "socket": _socket, "socketpair": _socketpair, "accept": _accept, "accept4": _accept4, "connect": _connect,
    "getsockname": _getsockname, "getpeername": _getpeername, "setsockopt": _setsockopt, "getsockopt": _getsockopt,
    "shutdown": _shutdown, "sendto": _sendto, "sendmsg": _sendmsg, "recvfrom": _recvfrom, "recvmsg": _recvmsg,
    "bind": _bind, "listen": _listen,
}
# The modeled names whose arms read nothing the trace shows and answer any value, and so pass on the name: exit and
# exit_group (Sys/Kernel/Exit.v exit_spec, which ends the run).
NAME_ONLY = frozenset("exit exit_group".split())


# ---------------------------------------------------------------------------------------------------------------------
# One trace
# ---------------------------------------------------------------------------------------------------------------------
class _Run:
    """The state of one check_trace call."""

    def __init__(self, model, stance, reserved, lengths, inputs):
        self.model = model
        self.stance = stance
        self.led = Ledger(reserved)
        self.host = HostLog(lengths)
        self.inputs = dict(inputs or {})    # path -> bytes: the files whose contents the run's environment fixes
        self.present = set(self.inputs)     # the names of those files that exist: a write leaves the name, an unlink
                                            # removes it
        self.self_kill = False      # a tkill or tgkill of SIGABRT to the caller's own task was decided
        self.tail = ""              # text after the current record's `)`: qemu prints prlimit64's old limit here


def check_trace(model, text, *, stance, require_exit=True, binary=None, lengths=None, inputs=None):
    """Check one run's `qemu-riscv64 -strace` trace (`text`, the -D log) against `model` (a Model). `stance` is the
    run's abort stance, one of STANCES. With require_exit, a trace that does not hold the run's end fails: a capture
    that saw nothing has no unmodeled call in it either. `binary` is the fuzz target the trace is of, for its image.
    `lengths` is the text of the same run's host-call log (tools/checks/host-calls.c). `inputs` is {path: bytes} of
    the files the run's model environment holds with known contents (input.bin), whose reads and seeks then have one
    answer each.

    Returns {"verdict": "pass", "fail" or "undecided", "calls": the run's records read, "names": the sorted distinct
    call names, "unmodeled": [{"call": name, "why": one line}] in trace order, one per distinct (call, why),
    "undecided": the same shape for the calls the trace does not decide, "exited": whether the trace holds the run's
    end, "host_log": "present" or "missing", "image": "present" or "missing", "image_error": a one-line cause or
    null}.
    A call is undecided when only a value the trace cannot show would change the model's answer: a register qemu
    printed in 32 bits that no host line recovers, a range an earlier failed MAP_FIXED may or may not have destroyed,
    a descriptor this run's pipe2 may have made, a path qemu cut short, a record whose arguments do not parse. A host
    log with no `exec` line is of a run that never started, and no log at all leaves every cut argument unrecoverable:
    both are "missing". If the binary is not a readable 64-bit RISC-V ELF with a LOAD segment, its image is "missing",
    and the run is undecided: the initial break cannot be checked against the image.

    The run is the task of the trace's first record. The model has one task (State.v m_tid), so another task's record
    is unmodeled. A fork the model answers (clone_spec, clone3_spec) makes a child that "is not executed by this
    model" (Sys/Kernel/Fork.v), and after it the child's text interleaves with the run's in the log, so the run is
    undecided from the fork on, and nothing after it is read. The run's end is an exit or exit_group record of that
    task, or qemu's SIGABRT death line after a self-kill this check decided: accepted under stance abort or either
    (Sys/Kernel/Signal.v send_sigabrt ends the run with State.v KillEv), or refused under stance off (the trace then
    covers the whole run, and the refusal is its one cause)."""
    if stance not in STANCES:
        raise ValueError(f"abort stance {stance!r} is not one of {', '.join(STANCES)}")
    reserved, image, image_error = None, "missing", None
    if binary is not None:
        try:
            reserved = image_spans(binary)
            image = "present"
        except Exception as e:
            image_error = f"could not read the binary image {binary}: {e}".replace("\n", " ")
    run = _Run(model, stance, reserved, lengths, inputs)
    unmodeled, unsure, seen = [], [], set()
    names = set()
    calls = 0
    saw_exit = saw_death = False
    owner = None

    def report(call, why):
        if (call, why) not in seen:
            seen.add((call, why))
            (unsure if isinstance(why, Undecided) else unmodeled).append({"call": call, "why": str(why)})

    if image_error is not None:
        # The image places the initial break (Run.v valid_brk) and every range clear of it: without it a run's
        # address-space calls decide nothing, so the run is never a pass.
        report("the binary's image", und(f"{image_error}: the initial break and the ranges the image holds cannot be "
                                         "checked (Run.v valid_brk)"))

    def judge(tid, name, args, tail):
        ret = parse_ret(tail)
        e = ERRNO_TAIL.match(tail)
        errno = int(e.group(1)) if e else None
        run.tail = tail
        gate = GATES.get(name)
        if gate is not None:
            why = gate(run, args, ret, errno, tid)
        elif name in NAME_ONLY:
            why = None
        else:
            why = "an arm of spec_table that this checker has no rule for, so it cannot say the call is modeled"
        if why is not None:
            report(name, why)

    # A record of the run's task whose return is not on its line. qemu flushes each print, and a single task cannot
    # start a call before the last one returned, so its return follows its record on the same line, unless a signal
    # line took the line meanwhile; then it comes on the next line of its own (` = N`). At most one record waits for
    # its return (`pending`); one whose return never comes, or whose task's next record comes first, is undecided.
    #
    # A fork ends what the trace can decide. After it the child writes to the same log, and qemu writes each argument,
    # the ` = ` and the value with writes of their own, so the two processes' text interleaves inside a line and no
    # byte says whose it is. The fork's arguments are judged (a fork the model refuses fails); a fork they allow makes
    # the run undecided, and nothing after it is read.
    pending = None
    unjudged = und("its return is not where qemu writes it (not on its line, nor on the next line of its own), so "
                   "the answer cannot be read")
    forked = und("a fork the model answers: after it qemu writes the child's text into the same log, interleaved "
                 "inside lines, so the trace does not say which calls and returns are the run's (Sys/Kernel/Fork.v: "
                 "the child is not executed by this model)")
    for line in text.splitlines():
        if kill_line(line):
            saw_death = True
        if not RECORD.match(line) and parse_ret(line) is not None:
            if pending is not None:
                judge(*pending, line)
                pending = None
            continue                        # a return with no record waiting carries no call
        for unknown in UNKNOWN_RECORD.finditer(line):
            calls += 1
            number = int(unknown.group(2))
            name = model.arms.get(number)
            call = name or f"syscall {number}"
            names.add(call)
            if name is None:
                report(call, f"syscall number {number} has no arm in spec_table (Sys/SyscallTable.v), and the model "
                             "answers every other number unmodeled (Specs.v syscall_spec)")
            else:
                report(call, f"qemu has no name for syscall {number} and printed none of its arguments, so the "
                             f"{name} arm cannot be decided (the call reached the guest as -ENOSYS, which that arm "
                             "does not answer)")
        stop = False
        for tid, name, args, tail, closed in split_records(line):
            if owner is None:
                owner = tid
            calls += 1
            names.add(name)
            if tid != owner:
                report(name, f"a record of task {tid}, which is not the run's task {owner}, and no fork came before "
                             "it: the model has one task (State.v m_tid)")
                continue
            if pending is not None:
                report(pending[1], unjudged)
                pending = None
            if not closed:
                report(name, und("the record has no closing parenthesis, so its arguments cannot be read (a guest "
                                 "string can hold any byte: qemu's print_string escapes nothing)"))
                continue
            if name in EXIT_NAMES:
                saw_exit = True
            if name not in model.names:
                report(name, "not an arm of spec_table (Sys/SyscallTable.v): the model answers every other number "
                             "unmodeled (Specs.v syscall_spec)")
                continue
            ret = parse_ret(tail)
            if name in ("clone", "clone3") and (ret is None or ret >= 0):
                # A fork that may have made a child: its arguments are judged, and then nothing after it is read.
                why = GATES[name](run, args, None, None, tid)
                report(name, why if why is not None else forked)
                stop = True
                break
            if ret is None and name not in EXIT_NAMES:
                pending = (tid, name, args)
                continue
            judge(tid, name, args, tail)
        if stop:
            break
    if pending is not None:
        report(pending[1], unjudged)
    exited = saw_exit or (saw_death and run.self_kill)
    host_log = "present" if (run.host.given and run.host.started) else "missing"
    if unmodeled:
        verdict = "fail"
    elif host_log == "missing" or unsure:
        verdict = "undecided"
    else:
        verdict = "fail" if (require_exit and not exited) else "pass"
    return {"verdict": verdict, "calls": calls, "names": sorted(names), "unmodeled": unmodeled, "undecided": unsure,
            "exited": exited, "host_log": host_log, "image": image, "image_error": image_error}
