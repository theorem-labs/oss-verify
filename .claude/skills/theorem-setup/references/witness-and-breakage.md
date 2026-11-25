# Measure the coverage witness and the breakages yourself (steps 4.3 and 4.4)

These steps need a native clang with libFuzzer, `llvm-profdata`, `llvm-cov` and `unzip` (on Ubuntu, `apt install clang llvm unzip`).

The coverage witness:

1. Compile the fuzz target for your machine with `-g -O0 -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping`, linked with the library. If your clang has no libFuzzer, link a small `main` that calls `LLVMFuzzerTestOneInput` on each file.
2. Unzip the seed corpus into a folder, and run the fuzz target on each input: `LLVM_PROFILE_FILE=witness.profraw ./<target> <folder>/*`.
3. Show the counts: `llvm-profdata merge -o witness.profdata witness.profraw`, then `llvm-cov show ./<target> -instr-profile=witness.profdata`.
4. The count of each API call and each property check must be more than 0. Add an input for each 0.

A breakage of one property:

1. Make a one-line change that breaks the property, for example flip a comparison or remove an update, and rebuild the fuzz target above.
2. Find an input that makes the fuzz target abort. Run it as a fuzzer for a few minutes (`./<target> -max_total_time=120 <folder>`), or write the input by hand. Add the input to the seed corpus.
3. Undo the change, and record it in the property's comment, as step 4.4 shows.
