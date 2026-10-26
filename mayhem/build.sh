#!/usr/bin/env bash
#
# mayhem/build.sh — build trezor-crypto's libFuzzer harness (crypto/fuzzer/fuzzer.c) + its check-based test suite.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Everything lives in the trezor-crypto Makefile (crypto/), which builds in-tree: build the oracle
# (test_check) first with the project's normal flags, stash it outside the Makefile's reach, `make clean`,
# then build the sanitized fuzzer, `make clean`, then the sanitized standalone reproducer.
# vendor/secp256k1-zkp is a git submodule; the CI checkout (mayhem.yml `submodules: true`) bakes it in.
[ -f vendor/secp256k1-zkp/src/secp256k1.c ] || { echo "vendor/secp256k1-zkp submodule missing" >&2; exit 1; }
cd "$SRC/crypto"
MK=(make -j"$MAYHEM_JOBS" CC="$CC" VALGRIND=0)

# 3) Oracle build first (normal flags, no sanitizer, no -gdwarf-3).
env -u SANFLAGS -u OPTFLAGS -u CFLAGS "${MK[@]}" clean
env -u SANFLAGS -u OPTFLAGS CFLAGS="$COVERAGE_FLAGS" "${MK[@]}" tests/test_check
cp tests/test_check /mayhem/trezor_crypto_test_check

# Objects of the library as the Makefile defines them (OBJS), for the manual links below.
printf 'print-objs:\n\t@echo $(OBJS)\n' > /tmp/print-objs.mk
objs() { make -s -f Makefile -f /tmp/print-objs.mk print-objs; }

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o /tmp/lsan_off.o

# 1+2) Sanitized fuzzer: project objects built with ASan+UBSan+SanCov (FUZZER=1 adds -fsanitize=fuzzer
# and upstream's sanitizer ignorelist), linked with the harness and the LSan-off hook.
"${MK[@]}" clean
SANFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" OPTFLAGS="-O1" FUZZER=1 "${MK[@]}" fuzzer/fuzzer.o $(objs)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer fuzzer/fuzzer.o $(objs) /tmp/lsan_off.o -o /mayhem/fuzzer

# Standalone (non-fuzzer) reproducer: same code, no coverage instrumentation, run-once driver.
"${MK[@]}" clean
SANFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" OPTFLAGS="-O1" "${MK[@]}" fuzzer/fuzzer.o $(objs)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" fuzzer/fuzzer.o $(objs) /tmp/lsan_off.o -lm -o /mayhem/fuzzer-standalone
"${MK[@]}" clean
