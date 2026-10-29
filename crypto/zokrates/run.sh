#!/usr/bin/env bash
# Run the ZoKrates pipeline for one circuit inside the official Docker image.
#
#   ./run.sh <circuit> [args...]   compile, setup, compute-witness, generate-proof,
#                                  verify, export-verifier -> build/<circuit>/
#   ./run.sh demo                  run every example, including failing cases
#
# Artifacts per circuit (build/<circuit>/):
#   out, abi.json          compiled circuit
#   proving.key            used by the prover
#   verification.key       used by the verifier
#   witness                private + public assignment
#   proof.json             the zkSNARK proof (Groth16 by default) + public inputs
#   verifier.sol           Solidity contract with verifyTx(proof, inputs)
set -euo pipefail

IMAGE=zokrates/zokrates:0.8.8
ROOT="$(cd "$(dirname "$0")" && pwd)"

zok() {
    # $1 = circuit name, rest = shell commands to run in build/<circuit>
    local name=$1; shift
    mkdir -p "$ROOT/build/$name"
    docker run --rm --platform linux/amd64 \
        -v "$ROOT:/home/zokrates/work" \
        -w "/home/zokrates/work/build/$name" \
        "$IMAGE" sh -c "$*"
}

pipeline() {
    local name=$1; shift
    local args="$*"
    echo "=== $name ($args) ==="
    zok "$name" "
        set -e
        zokrates compile -i ../../circuits/$name.zok -o out > /dev/null
        zokrates setup -i out > /dev/null
        zokrates compute-witness -i out -a $args --verbose | grep -i 'witness\|output' || true
        zokrates generate-proof -i out > /dev/null
        zokrates verify
        zokrates export-verifier > /dev/null
        echo \"public inputs: \$(tr -d '\n ' < proof.json | sed 's/.*\"inputs\":\(\[[^]]*\]\).*/\1/')\"
    "
}

# Expect compute-witness to fail: an honest-but-wrong prover can't produce a proof.
expect_fail() {
    local name=$1; shift
    echo "=== $name ($*) [expect failure] ==="
    if zok "$name" "zokrates compile -i ../../circuits/$name.zok -o out > /dev/null && zokrates compute-witness -i out -a $*" > /dev/null 2>&1; then
        echo "UNEXPECTED: witness computed"; exit 1
    else
        echo "OK: no witness, so no proof can be generated"
    fi
}

demo() {
    # 1. Page example: y = 3x^2 + x + 4, x = 1 -> y = 8. Output true (1).
    pipeline quadratic 3 1 4 1 8
    # Wrong y still yields a *valid proof*, but its public output is false (0).
    pipeline quadratic 3 1 4 1 9

    # 2. Assert version: correct answer proves, wrong answer can't.
    pipeline quadratic_assert 3 1 4 1 8
    expect_fail quadratic_assert 3 1 4 1 9

    # 3. Square root knowledge: x = 7, y = 49.
    pipeline square 7 49
    expect_fail square 6 49

    # 4. Hash preimage: compute sha256 of [0,0,0,5], then prove we know it.
    local hash
    hash=$(zok hash "zokrates compile -i ../../circuits/hash.zok -o out > /dev/null && zokrates compute-witness -i out -a 0 0 0 5 --verbose" \
        | tr -d '\n ' | sed 's/.*\[\(.*\)\].*/\1/' | tr -d '"' | tr ',' ' ')
    echo "sha256([0,0,0,5]) packed = $hash"
    pipeline preimage 0 0 0 5 $hash
    expect_fail preimage 0 0 0 6 $hash

    # 5. Range proof: private age 25 >= 18.
    pipeline age 25 18
    expect_fail age 16 18
}

if [[ $# -eq 0 ]]; then
    sed -n '2,7p' "$0"; exit 1
elif [[ $1 == demo ]]; then
    demo
else
    pipeline "$@"
fi
