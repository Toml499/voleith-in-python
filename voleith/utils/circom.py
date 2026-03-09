"""
Automation helpers for the circom / snarkjs toolchain.

Wraps the three manual steps into Python calls:

    1. compile_circuit()  — runs `circom <file>.circom --r1cs --wasm --sym`
    2. generate_witness() — runs `node generate_witness.js` + snarkjs JSON export
    3. compile_and_witness() — one-shot convenience wrapper for both

Typical usage
-------------
    from voleith.utils.circom import compile_and_witness
    from voleith.relations.r1cs import R1CSRelation
    import galois

    r1cs_file, witness = compile_and_witness(
        circom_file="poseidon_preimage.circom",
        input_data={"preimage": "42"},
    )
    F        = galois.GF(r1cs_file.prime)
    relation = R1CSRelation.from_r1cs_file(r1cs_file)
    # -> pass to R1CSProver / R1CSVerifier as usual

Requirements
------------
    circom   — https://docs.circom.io/getting-started/installation/
    node     — https://nodejs.org/
    snarkjs  — npm install -g snarkjs
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .r1cs_parser import R1CSFile, parse_r1cs


# ── internal helpers ──────────────────────────────────────────────────────────

def _require(tool: str) -> str:
    """Return the full path to *tool* or raise a clear error."""
    path = shutil.which(tool)
    if path is None:
        raise FileNotFoundError(
            f"'{tool}' not found on PATH. "
            f"See the module docstring for installation instructions."
        )
    return path


def _run(cmd: list[str], cwd: Path, label: str) -> None:
    """Run *cmd* in *cwd*, raising RuntimeError on non-zero exit."""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{label} failed (exit {result.returncode}).\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )


# ── public API ────────────────────────────────────────────────────────────────

def compile_circuit(
    circom_file: str | Path,
    build_dir: str | Path | None = None,
) -> tuple[Path, Path]:
    """
    Compile a circom circuit to .r1cs and .wasm.

    Parameters
    ----------
    circom_file : path to the .circom source file
    build_dir   : directory for build artefacts; a temporary directory is
                  created and returned if not given

    Returns
    -------
    (r1cs_path, wasm_path) — absolute paths to the compiled outputs

    The wasm file lives inside `<circuit_name>_js/` as circom convention.
    """
    circom_file = Path(circom_file).resolve()
    if not circom_file.exists():
        raise FileNotFoundError(f"circom source not found: {circom_file}")

    circuit_name = circom_file.stem  # e.g. "poseidon_preimage"

    if build_dir is None:
        build_dir = Path(tempfile.mkdtemp(prefix="voleith_circom_"))
    build_dir = Path(build_dir).resolve()
    build_dir.mkdir(parents=True, exist_ok=True)

    circom_bin = _require("circom")

    _run(
        [circom_bin, str(circom_file), "--r1cs", "--wasm", "--sym",
         "--output", str(build_dir)],
        cwd=build_dir,
        label="circom compile",
    )

    r1cs_path = build_dir / f"{circuit_name}.r1cs"
    wasm_path = build_dir / f"{circuit_name}_js" / f"{circuit_name}.wasm"

    if not r1cs_path.exists():
        raise RuntimeError(f"Expected .r1cs output not found: {r1cs_path}")
    if not wasm_path.exists():
        raise RuntimeError(f"Expected .wasm output not found: {wasm_path}")

    return r1cs_path, wasm_path


def generate_witness(
    wasm_path: str | Path,
    input_data: dict,
    build_dir: str | Path | None = None,
) -> list[int]:
    """
    Generate a full witness vector from a compiled circuit WASM and an input dict.

    Parameters
    ----------
    wasm_path  : path to the <circuit>_js/<circuit>.wasm file
    input_data : dict mapping circom signal names to their values
                 (values should be integers or strings of integers)
    build_dir  : directory for intermediate files (witness.wtns, witness.json);
                 defaults to the same directory as wasm_path

    Returns
    -------
    list[int] — full witness vector (wire 0 is always 1)
    """
    wasm_path = Path(wasm_path).resolve()
    if not wasm_path.exists():
        raise FileNotFoundError(f"WASM file not found: {wasm_path}")

    # generate_witness.js lives next to the wasm
    js_dir = wasm_path.parent
    generate_witness_js = js_dir / "generate_witness.js"
    if not generate_witness_js.exists():
        raise FileNotFoundError(
            f"generate_witness.js not found next to wasm: {generate_witness_js}"
        )

    if build_dir is None:
        build_dir = js_dir
    build_dir = Path(build_dir).resolve()
    build_dir.mkdir(parents=True, exist_ok=True)

    node_bin   = _require("node")
    snarkjs_bin = _require("snarkjs")

    # Write input JSON
    input_json_path   = build_dir / "input.json"
    witness_wtns_path = build_dir / "witness.wtns"
    witness_json_path = build_dir / "witness.json"

    input_json_path.write_text(json.dumps(input_data))

    # Step 1: node generate_witness.js <circuit>.wasm input.json witness.wtns
    _run(
        [node_bin, str(generate_witness_js),
         str(wasm_path), str(input_json_path), str(witness_wtns_path)],
        cwd=build_dir,
        label="witness generation (node)",
    )

    if not witness_wtns_path.exists():
        raise RuntimeError(f"Expected witness file not produced: {witness_wtns_path}")

    # Step 2: snarkjs wtns export json witness.wtns witness.json
    _run(
        [snarkjs_bin, "wtns", "export", "json",
         str(witness_wtns_path), str(witness_json_path)],
        cwd=build_dir,
        label="snarkjs wtns export json",
    )

    raw = json.loads(witness_json_path.read_text())
    # snarkjs exports a list of decimal strings
    return [int(x) for x in raw]


def compile_and_witness(
    circom_file: str | Path,
    input_data: dict,
    build_dir: str | Path | None = None,
) -> tuple[R1CSFile, list[int]]:
    """
    One-shot helper: compile a circom circuit and generate a witness.

    Parameters
    ----------
    circom_file : path to the .circom source file
    input_data  : dict mapping circom signal names to their values
    build_dir   : directory for all build artefacts; a temporary directory
                  is used if not given (printed to stdout so you can inspect it)

    Returns
    -------
    (r1cs_file, witness)
      r1cs_file : R1CSFile — parsed circuit (pass to R1CSRelation.from_r1cs_file)
      witness   : list[int] — full wire vector (wire[0] == 1)

    Example
    -------
        r1cs_file, witness = compile_and_witness(
            "poseidon_preimage.circom",
            {"preimage": "42"},
        )
        F        = galois.GF(r1cs_file.prime)
        relation = R1CSRelation.from_r1cs_file(r1cs_file)
        proof    = R1CSProver(relation, F).prove(witness)
        result   = R1CSVerifier(relation, F).verify(proof)
    """
    if build_dir is None:
        build_dir = Path(tempfile.mkdtemp(prefix="voleith_circom_"))
        print(f"[circom] build directory: {build_dir}")

    build_dir = Path(build_dir).resolve()

    r1cs_path, wasm_path = compile_circuit(circom_file, build_dir)
    witness = generate_witness(wasm_path, input_data, build_dir)
    r1cs_file = parse_r1cs(str(r1cs_path))

    return r1cs_file, witness
