# Fuzzcheck Usage Guide

This guide explains how to run the fuzz test `fuzz_test_1()` located in `salt/src/lib.rs`.

## Where to Run the Command

You have two options:

### Option 1: From the Workspace Root (Recommended)

Stay in `/home/yilongl/work/salt` (the workspace root) and add the `-p salt` flag:

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt
```

The `-p salt` flag tells cargo to run the command on the `salt` package specifically.

### Option 2: From the Package Directory

Navigate to the package directory first:

```bash
cd salt
cargo-fuzzcheck tests::fuzz_test_1
```

## Basic Command

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt
```

This will:
- Run the `fuzz_test_1()` function in the `tests` module of `salt/src/lib.rs`
- Use default options (unlimited duration, complexity up to 4096)
- Generate test inputs and try to find the "bug" in `process_string()`

## Useful Command Variations

### 1. Run for a Limited Time

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt --stop-after-duration 60
```

Runs for 60 seconds then stops.

### 2. Stop After Finding First Failure

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt --stop-after-first-failure
```

Stops immediately when it finds a panic (like when it discovers "bug").

### 3. Save Artifacts and Corpus

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt \
  --out-corpus fuzz_corpus/ \
  --artifacts fuzz_artifacts/
```

Saves:
- Interesting test cases to `fuzz_corpus/`
- Crash-causing inputs to `fuzz_artifacts/`

### 4. Limited Complexity and Duration

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt \
  --max-cplx 1000 \
  --stop-after-duration 30 \
  --stop-after-first-failure
```

Useful for quick testing sessions with simpler inputs.

### 5. Reproduce/Minify a Crash

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt \
  --command minify \
  --input-file fuzz_artifacts/crash.json
```

Minimizes a crash artifact to find the smallest failing input. The minified inputs will be saved in `fuzz_artifacts/crash.minified/`.

## Common Options

- `--stop-after-duration N` - Maximum duration in seconds
- `--stop-after-iterations N` - Maximum number of iterations
- `--detect-infinite-loop` - Fail on tests running for more than one second
- `--stop-after-first-failure` - Stop after the first test failure
- `--in-corpus PATH` - Folder for the input corpus
- `--out-corpus PATH` - Folder for the output corpus
- `--artifacts PATH` - Folder where artifacts will be written
- `--max-cplx N` - Maximum allowed complexity of inputs (default: 4096)
- `--no-instrument-coverage` - Turn off coverage instrumentation
- `--address-sanitizer` - Use AddressSanitizer

## Quick Start Example

For a quick test run that stops after finding the first bug and saves the results:

```bash
cargo-fuzzcheck tests::fuzz_test_1 -p salt \
  --stop-after-first-failure \
  --stop-after-duration 60 \
  --artifacts fuzz_artifacts/
```

This command will:
- Run for maximum 60 seconds
- Stop immediately when it finds the "bug"
- Save the crash-causing input to `fuzz_artifacts/`
