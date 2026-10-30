#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Pre-registered real-file check of paddle_program_scan (PREREG_PADDLE_REALFILE.md).

Writes Paddle programs with paddle itself inside the sandbox, scans them, and
grades P1-P7. Nothing written here is ever executed as a model: the programs
are only serialized and scanned. Made with AI agents working in the name of
MV2 of Munim, Inc.

Run with no --mode: it runs "pir" and "legacy" in two child processes (the
FLAGS_enable_pir_api switch must be set before paddle is imported) and merges
their rows into OUT/realfile_summary.json.
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))                    # repo layout
sys.path.insert(0, os.path.join(HERE, "..", "..", "ship", "paddle"))  # job layout

import paddle_program_scan as pp  # noqa: E402


def _rules(findings):
    return [f["rule"] for f in findings]


def _evidence(findings):
    return " | ".join(f["evidence"] for f in findings)


def _exactly(findings, rule, needles):
    ev = _evidence(findings)
    return {"rules": _rules(findings), "evidence": ev,
            "held": _rules(findings) == [rule] and all(n in ev for n in needles)}


def _export(tmp):
    import paddle

    class Net(paddle.nn.Layer):
        def __init__(self):
            super().__init__()
            self.fc = paddle.nn.Linear(4, 2)

        def forward(self, x):
            return paddle.nn.functional.relu(self.fc(x))

    prefix = os.path.join(tmp, "inference")
    paddle.jit.save(Net(), prefix, input_spec=[
        paddle.static.InputSpec(shape=[None, 4], dtype="float32")])
    written = sorted(os.path.basename(p) for p in glob.glob(prefix + "*"))
    model = [p for p in glob.glob(prefix + "*")
             if p.endswith(".json") or p.endswith(".pdmodel")]
    return written, (model[0] if model else None)


def _json_ops(node):
    found = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if key == "ops" and isinstance(value, list):
                    found.extend(op for op in value if isinstance(op, dict))
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return found


def _edit_json(path, new_path):
    with open(path, "rb") as handle:
        doc = json.loads(handle.read().decode("utf-8"))
    target = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "ops" and isinstance(value, list):
                    for op in value:
                        if (not target and isinstance(op, dict)
                                and isinstance(op.get("#"), str)
                                and "." in op["#"]):
                            target.append(op)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    if not target:
        raise RuntimeError("no op with a dotted name found in the PIR json")
    op = target[0]
    original = op["#"]
    op["#"] = original.rsplit(".", 1)[0] + ".save_combine"
    attr_id = "0.a_str"
    for attr in op.get("A") or []:
        at = attr.get("AT") if isinstance(attr, dict) else None
        if isinstance(at, dict) and isinstance(at.get("D"), str):
            attr_id = at.get("#", attr_id)
            break
    op.setdefault("A", []).append({"N": "file_path",
                                   "AT": {"#": attr_id, "D": new_path}})
    return json.dumps(doc).encode("utf-8"), original


def _edit_pdmodel(path, new_path):
    from paddle.base.proto import framework_pb2
    prog = framework_pb2.ProgramDesc()
    with open(path, "rb") as handle:
        prog.ParseFromString(handle.read())
    op = prog.blocks[0].ops[0]
    original = op.type
    op.type = "save_combine"
    attr = op.attrs.add()
    attr.name = "file_path"
    attr.type = framework_pb2.STRING
    attr.s = new_path
    return prog.SerializeToString(), original


def _static_program(kind):
    import paddle
    paddle.enable_static()
    main = paddle.static.Program()
    with paddle.static.program_guard(main, paddle.static.Program()):
        x = paddle.static.data("x", shape=[2], dtype="float32")
        block = main.global_block()
        if kind == "save_combine":
            block.append_op(type="save_combine", inputs={"X": [x]},
                            outputs={}, attrs={"file_path": "/tmp/p5",
                                               "overwrite": True,
                                               "save_as_fp16": False,
                                               "save_to_memory": False})
        elif kind == "load_combine":
            out = block.create_var(name="w", dtype="float32", shape=[2],
                                   persistable=True)
            block.append_op(type="load_combine", inputs={},
                            outputs={"Out": [out]},
                            attrs={"file_path": "/tmp/p6",
                                   "load_as_fp16": False,
                                   "model_from_memory": False})
        else:
            out = block.create_var(name="o", dtype="float32", shape=[2])
            paddle.static.py_func(func=lambda a: a, x=x, out=out)
    return main.desc.serialize_to_string()


def run_mode(mode, tmp):
    import paddle
    rows = []

    def case(pid, func):
        row = {"id": pid, "mode": mode, "paddle": paddle.__version__}
        try:
            row.update(func())
        except Exception as exc:
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
            row["traceback"] = traceback.format_exc()[-2000:]
            row["held"] = False
        rows.append(row)
        print(json.dumps({k: v for k, v in row.items() if k != "traceback"}))

    exported = {}

    def export_clean():
        written, model = _export(tmp)
        exported["model"] = model
        if model is None:
            return {"written": written, "held": False,
                    "error": "no .json or .pdmodel written"}
        f = pp.scan_file(model)
        names = []
        if model.endswith(".json"):
            with open(model, "rb") as handle:
                text = handle.read().decode("utf-8", "replace")
            names = sorted(set(op["#"] for op in _json_ops(json.loads(text))
                               if isinstance(op.get("#"), str)))[:40]
        return {"written": written, "model": os.path.basename(model),
                "op_names": names, "rules": _rules(f),
                "evidence": _evidence(f), "held": f == []}

    def edited():
        model = exported.get("model")
        if model is None:
            raise RuntimeError("export case did not produce a model")
        if model.endswith(".json"):
            raw, original = _edit_json(model, "/tmp/p_edit")
        else:
            raw, original = _edit_pdmodel(model, "/tmp/p_edit")
        result = _exactly(pp.scan_bytes(raw, os.path.basename(model)),
                          "PDL001", ["/tmp/p_edit"])
        result["renamed_op"] = original
        return result

    if mode == "pir":
        case("P1", export_clean)
        case("P2", edited)
    else:
        case("P3", export_clean)
        case("P4", edited)
        case("P5", lambda: _exactly(pp.scan_bytes(
            _static_program("save_combine")), "PDL001", ["/tmp/p5"]))
        case("P6", lambda: _exactly(pp.scan_bytes(
            _static_program("load_combine")), "PDL002", ["/tmp/p6"]))
        case("P7", lambda: _exactly(pp.scan_bytes(
            _static_program("py_func")), "PDL003", ["forward_callable_id"]))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/out")
    parser.add_argument("--mode", default="")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    if args.mode:
        tmp = os.path.join(args.out, "files-" + args.mode)
        os.makedirs(tmp, exist_ok=True)
        rows = run_mode(args.mode, tmp)
        with open(os.path.join(args.out, "rows-%s.json" % args.mode),
                  "w") as handle:
            json.dump(rows, handle, indent=1)
        return 0
    rows = []
    children = {}
    for mode, flag in (("pir", "1"), ("legacy", "0")):
        env = dict(os.environ, FLAGS_enable_pir_api=flag)
        proc = subprocess.run([sys.executable, os.path.abspath(__file__),
                               "--mode", mode, "--out", args.out], env=env)
        children[mode] = proc.returncode
        path = os.path.join(args.out, "rows-%s.json" % mode)
        if os.path.isfile(path):
            with open(path) as handle:
                rows.extend(json.load(handle))
    summary = {"scanner": pp.__version__, "children": children,
               "held": sum(1 for r in rows if r.get("held")),
               "total": len(rows), "rows": rows}
    with open(os.path.join(args.out, "realfile_summary.json"), "w") as handle:
        json.dump(summary, handle, indent=1)
    print("held %d of %d" % (summary["held"], summary["total"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
