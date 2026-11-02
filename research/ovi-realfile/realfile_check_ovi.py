#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check for openvino_ir_scan (research/PREREG_OVI_REALFILE.md).

Builds small models with OpenVINO's Python API, writes them with
openvino.save_model, and scans them (H1). Edits copies of one honest .xml as
the pre-registration says (E1-E6) and scans those. Runs the one-command
model-file-scan over an honest pair, an edited pair (M1, M2) and a directory
of 50 honest pairs (S1, S2). Asks the OpenVINO runtime itself, in a child
process, to read the honest files and the two edited copies whose rejection
the scanner's documentation states (R0-R2). No network is used.

v2 (amendment of 2 November 2026): v1 ended on a segmentation fault after
writing three honest models, before any result was recorded. Every model is
now built and saved in a child process (--build / --sweep), so a crash in
OpenVINO's writer makes the cases that need that model NOT RUN instead of
ending the job. The predictions are unchanged.

v3 (second amendment, 2 November 2026, before ovi-realfile-v3 ran): v2 left
two cases not run. (a) The string-const model: openvino 2026.4.1 crashes when
a Constant is made directly from a numpy str array. That is the known,
already-fixed OpenVINO issue #23611 (fix merged 30 October 2026 for 2026.5).
v3 builds the same string constant through openvino.Tensor and the
op.Constant(tensor) constructor instead. (b) E4: OpenVINO's IR writer spells
the ReLU layer type "ReLU", so the anchor type="Relu" was never found. v3
accepts either spelling. The predictions are unchanged. v3 also reports
(not predicts) the string Const's attributes and leading .bin bytes, and the
first bytes of any sweep .bin that the pickle scanner reports nothing on.

Writes OUT/realfile_summary.json and the small honest/edited files under
OUT/files/. Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.
"""

import argparse
import importlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KMS = os.path.join(HERE, "kms")
sys.path.insert(0, KMS)

import numpy as np  # noqa: E402
import openvino as ov  # noqa: E402
import openvino_ir_scan as oi  # noqa: E402

MFS = os.path.join(KMS, "model_file_scan.py")
SELF = os.path.abspath(__file__)
HIGH_SEVERITIES = ("MEDIUM", "HIGH", "CRITICAL")
RELU_RE = re.compile(r'\btype="(?:Relu|ReLU)"')

CHILD = (
    "import sys\n"
    "import openvino as ov\n"
    "try:\n"
    "    ov.Core().read_model(sys.argv[1])\n"
    "except Exception as exc:\n"
    "    print(type(exc).__name__, str(exc)[:300])\n"
    "    sys.exit(3)\n"
    "print('loaded')\n"
    "sys.exit(0)\n"
)


def _stage(text):
    print("stage: " + text, flush=True)


def _ops():
    errors = []
    for name in ("openvino.opset13", "openvino.runtime.opset13",
                 "openvino.opset8", "openvino.runtime.opset8"):
        try:
            return importlib.import_module(name), name
        except ImportError as exc:
            errors.append("%s: %s" % (name, exc))
    raise ImportError("; ".join(errors))


def _constant_class():
    errors = []
    for name in ("openvino.op", "openvino.runtime.op"):
        try:
            return importlib.import_module(name).Constant
        except (ImportError, AttributeError) as exc:
            errors.append("%s: %s" % (name, exc))
    raise ImportError("; ".join(errors))


def _dense(ops, seed, n_in, n_out):
    rng = np.random.default_rng(seed)
    x = ops.parameter([1, n_in], np.float32, name="x")
    w = ops.constant(rng.standard_normal((n_in, n_out)).astype(np.float32),
                     name="w_main")
    b = ops.constant(rng.standard_normal((1, n_out)).astype(np.float32),
                     name="b_main")
    y = ops.relu(ops.add(ops.matmul(x, w, False, False), b), name="act")
    return x, y


def build_plain(ops, seed=0, n_in=16, n_out=16):
    x, y = _dense(ops, seed, n_in, n_out)
    return ov.Model([y], [x], "tiny_%d" % seed)


def build_i64(ops):
    x, y = _dense(ops, 0, 16, 16)
    shape = ops.constant(np.array([16], dtype=np.int64), name="shape_i64")
    z = ops.reshape(y, shape, False, name="flat")
    return ov.Model([z], [x], "tiny_i64")


def build_string(ops):
    # Not ops.constant(numpy str array): that call crashes in openvino
    # 2026.4.1 (OpenVINO issue #23611, fixed for 2026.5). The Tensor
    # constructor converts numpy str arrays itself.
    x, y = _dense(ops, 0, 16, 16)
    labels = np.array(["alpha", "beta", "gamma"])
    _stage("openvino.Tensor from a numpy %s array" % labels.dtype)
    tensor = ov.Tensor(labels)
    _stage("op.Constant from the string Tensor")
    s = _constant_class()(tensor)
    s.set_friendly_name("labels")
    _stage("model with a string output")
    return ov.Model([y, s], [x], "tiny_string")


def _save(model, folder, stem, fp16=False):
    os.makedirs(folder, exist_ok=True)
    xml = os.path.join(folder, stem + ".xml")
    ov.save_model(model, xml, compress_to_fp16=fp16)
    return xml


BUILDERS = {
    "plain-f32": (lambda ops: build_plain(ops), False),
    "plain-fp16": (lambda ops: build_plain(ops), True),
    "reshape-i64": (build_i64, False),
    "string-const": (build_string, False),
}


def child_build(label, dest):
    """Child-process mode: build one honest model and save it."""
    try:
        ops, _ = _ops()
        make, fp16 = BUILDERS[label]
        _stage("build")
        model = make(ops)
        _stage("save_model")
        _save(model, dest, "model", fp16=fp16)
        _stage("saved")
    except Exception as exc:
        print("error %s: %s" % (type(exc).__name__, str(exc)[:300]),
              flush=True)
        return 3
    return 0


def child_sweep(dest):
    """Child-process mode: write the 50 honest sweep pairs."""
    try:
        ops, _ = _ops()
    except ImportError as exc:
        print("error ImportError: %s" % exc, flush=True)
        return 3
    for seed in range(1, 51):
        try:
            _save(build_plain(ops, seed, 4 + seed % 13, 2 + seed % 7),
                  dest, "m%02d" % seed)
            print("wrote %d" % seed, flush=True)
        except Exception as exc:
            print("error %d %s: %s" % (seed, type(exc).__name__,
                                       str(exc)[:200]), flush=True)
    return 0


def _child(args, timeout=600):
    """Run this script in child mode; never raises on a crash."""
    try:
        proc = subprocess.run([sys.executable, SELF] + args,
                              capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"returncode": None, "lines": [], "stage": "timeout",
                "stderr_tail": ""}
    lines = proc.stdout.splitlines()
    stages = [ln[len("stage: "):] for ln in lines if ln.startswith("stage: ")]
    errors = [ln for ln in lines if ln.startswith("error ")]
    return {"returncode": proc.returncode, "lines": lines,
            "stage": stages[-1] if stages else "",
            "errors": errors[:5],
            "stderr_tail": proc.stderr.strip()[-300:]}


def _child_problem(result):
    """A one-line reason when a child build did not finish cleanly."""
    rc = result["returncode"]
    if rc is None:
        return "the writer process timed out"
    if rc < 0:
        return ("the writer process ended on signal %d during stage '%s'"
                % (-rc, result["stage"]))
    if rc != 0:
        return "OpenVINO API error: %s" % (
            "; ".join(result.get("errors") or []) or "exit %d" % rc)
    return None


def _rules(findings):
    return sorted(set(f["rule"] for f in findings))


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def _head_hex(path, n=8):
    try:
        with open(path, "rb") as handle:
            return handle.read(n).hex()
    except OSError as exc:
        return "unreadable: %s" % exc


def _string_const_report(xml):
    """Attributes of each string Const and the .bin bytes they point at."""
    text = _read(xml).decode("utf-8", "replace")
    try:
        blob = _read(xml[:-4] + ".bin")
    except OSError:
        blob = b""
    out = []
    for m in CONST_RE.finditer(text):
        attrs = m.group(1)
        if 'element_type="string"' not in attrs:
            continue
        item = {"attrs": attrs.strip(), "bin_bytes": len(blob)}
        om = re.search(r'\boffset="(\d+)"', attrs)
        sm = re.search(r'\bsize="(\d+)"', attrs)
        if om and sm:
            off, size = int(om.group(1)), int(sm.group(1))
            item["data_hex"] = blob[off:off + min(size, 96)].hex()
        out.append(item)
    return out


def _runtime_read(xml):
    try:
        proc = subprocess.run([sys.executable, "-c", CHILD, xml],
                              capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout"}
    tail = (proc.stdout.strip().splitlines() or [""])[-1][:300]
    if proc.returncode == 0:
        outcome = "loaded"
    elif proc.returncode == 3:
        outcome = "rejected"
    elif proc.returncode < 0:
        outcome = "signal %d" % -proc.returncode
    else:
        outcome = "exit %d" % proc.returncode
    return {"outcome": outcome, "returncode": proc.returncode, "tail": tail,
            "stderr_tail": proc.stderr.strip()[-300:]}


def _mfs(target):
    proc = subprocess.run([sys.executable, MFS, target, "--json"],
                          capture_output=True, text=True, timeout=600)
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        return proc.returncode, None, proc.stdout[-500:] + proc.stderr[-500:]
    return proc.returncode, doc, ""


def _entry_rules(entry):
    out = []
    for f in entry.get("findings", []):
        rule = f.get("rule") or f.get("id") or f.get("rule_id") or "?"
        out.append((rule, str(f.get("severity", "")).upper()))
    return out


# Const layers: the opening <layer ... type="Const" ...> tag followed by its
# <data .../> child. Group 1 is the data element's attribute text.
CONST_RE = re.compile(
    r'<layer\b[^>]*\btype="Const"[^>]*>\s*<data\b([^>]*?)/?>')


def _biggest_const(text):
    best = None
    for m in CONST_RE.finditer(text):
        attrs = m.group(1)
        sm = re.search(r'\bsize="(\d+)"', attrs)
        if not sm or 'element_type="f32"' not in attrs:
            continue
        size = int(sm.group(1))
        if best is None or size > best[0]:
            best = (size, m.start(1), m.end(1), attrs)
    return best


def _splice(text, best, new_attrs):
    return text[:best[1]] + new_attrs + text[best[2]:]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    ap.add_argument("--work", default="/tmp/ovi")
    ap.add_argument("--build", choices=sorted(BUILDERS))
    ap.add_argument("--sweep")
    ap.add_argument("--dest")
    args = ap.parse_args(argv)
    if args.build:
        return child_build(args.build, args.dest)
    if args.sweep:
        return child_sweep(args.sweep)

    files = os.path.join(args.out, "files")
    shutil.rmtree(args.work, ignore_errors=True)
    os.makedirs(files, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)
    rows = []
    reported = {"writer_crashes": [], "writer_errors": []}

    def row(case_id, case, expected, func):
        r = {"id": case_id, "case": case, "expected": expected}
        try:
            got = func()
        except Exception as exc:  # pre-registered: an API error is "not run"
            r.update({"result": "NOT RUN",
                      "reason": "%s: %s" % (type(exc).__name__, exc)})
            rows.append(r)
            return r
        if isinstance(got, str):
            r.update({"result": "NOT RUN", "reason": got})
        else:
            ok, detail = got
            r.update({"got": detail, "result": "PASS" if ok else "FAIL"})
        rows.append(r)
        return r

    try:
        _ops_mod, ops_name = _ops()
        have_ops = True
    except ImportError as exc:
        ops_name, have_ops = "none (%s)" % exc, False
    reported["opset_module"] = ops_name

    # ---- H1: honest files written by openvino.save_model ----------------
    honest = {}
    h1 = []
    for label in ("plain-f32", "plain-fp16", "reshape-i64", "string-const"):
        sub = {"model": label}
        folder = os.path.join(files, "honest", label)
        xml = os.path.join(folder, "model.xml")
        if not have_ops:
            sub.update({"result": "NOT RUN", "reason": "no opset module"})
            h1.append(sub)
            continue
        built = _child(["--build", label, "--dest", folder])
        problem = _child_problem(built)
        if problem is None and not (os.path.isfile(xml) and
                                    os.path.isfile(xml[:-4] + ".bin")):
            problem = "save_model finished but model.xml/.bin is missing"
        if problem:
            if built["returncode"] is not None and built["returncode"] < 0:
                reported["writer_crashes"].append({
                    "model": label, "signal": -built["returncode"],
                    "stage": built["stage"],
                    "stderr_tail": built["stderr_tail"]})
            else:
                reported["writer_errors"].append({
                    "model": label, "stage": built["stage"],
                    "problem": problem})
            sub.update({"result": "NOT RUN", "reason": problem})
            h1.append(sub)
            continue
        text = _read(xml).decode("utf-8", "replace")
        if label == "string-const":
            reported["string_consts"] = _string_const_report(xml)
            if 'element_type="string"' not in text:
                sub.update({"result": "NOT RUN",
                            "reason": "no element_type=\"string\" Const "
                                      "written"})
                h1.append(sub)
                continue
        honest[label] = xml
        findings = oi.scan_file(xml)
        sub.update({"xml_bytes": len(text),
                    "bin_bytes": os.path.getsize(xml[:-4] + ".bin"),
                    "rules": _rules(findings),
                    "evidence": [f["evidence"] for f in findings],
                    "result": "PASS" if not findings else "FAIL"})
        h1.append(sub)
    ran = [s for s in h1 if s["result"] != "NOT RUN"]
    rows.append({"id": "H1", "case": "honest files from openvino.save_model",
                 "expected": [], "files": h1,
                 "result": ("NOT RUN" if not ran else
                            "FAIL" if any(s["result"] == "FAIL" for s in ran)
                            else "PASS")})

    # ---- E1-E6: edited copies of plain-f32 ------------------------------
    base_xml = honest.get("plain-f32")
    base_text = _read(base_xml).decode("utf-8") if base_xml else None
    base_bin = _read(base_xml[:-4] + ".bin") if base_xml else None
    best = _biggest_const(base_text) if base_text else None
    reported["edited_const_attrs"] = best[3].strip() if best else None
    edited_paths = {}

    def write_pair(name, text, with_bin=True):
        folder = os.path.join(files, "edited", name)
        shutil.rmtree(folder, ignore_errors=True)
        xml = os.path.join(folder, "model.xml")
        _write(xml, text.encode("utf-8"))
        if with_bin:
            _write(os.path.join(folder, "model.bin"), base_bin)
        edited_paths[name] = xml
        return xml

    def scan_edit(name, text, expected, with_bin=True):
        xml = write_pair(name, text, with_bin)
        findings = oi.scan_file(xml)
        rules = _rules(findings)
        return rules == expected, {"rules": rules,
                                   "evidence": [f["evidence"]
                                                for f in findings]}

    def need_const():
        if base_text is None:
            return "plain-f32 was not written"
        if best is None:
            return "no f32 Const with a size attribute found in the XML"
        return None

    def e1():
        problem = need_const()
        if problem:
            return problem
        attrs = best[3]
        if not re.search(r'\boffset="\d+"', attrs):
            return "Const has no offset attribute"
        new = re.sub(r'\boffset="\d+"', 'offset="%d"' % len(base_bin), attrs,
                     count=1)
        return scan_edit("e1-offset-past-end", _splice(base_text, best, new),
                         ["OVI003"])

    def e2():
        problem = need_const()
        if problem:
            return problem
        new = re.sub(r'\bsize="\d+"', 'size="%d"' % (best[0] - 4), best[3],
                     count=1)
        return scan_edit("e2-size-short", _splice(base_text, best, new),
                         ["OVI005"])

    def e3():
        problem = need_const()
        if problem:
            return problem
        if not re.search(r'\bshape="[^"]*"', best[3]):
            return "Const has no shape attribute"
        new = re.sub(r'\bshape="[^"]*"', 'shape="4294967296, 4294967296"',
                     best[3], count=1)
        return scan_edit("e3-shape-overflow", _splice(base_text, best, new),
                         ["OVI004"])

    def e4():
        if base_text is None:
            return "plain-f32 was not written"
        m = RELU_RE.search(base_text)
        if not m:
            return "no type=\"Relu\" or type=\"ReLU\" layer in the XML"
        reported["e4_anchor"] = m.group(0)
        text = base_text[:m.start()] + 'type="Custom"' + base_text[m.end():]
        return scan_edit("e4-custom-op", text, ["OVI002"])

    def e5():
        if base_text is None:
            return "plain-f32 was not written"
        doctype = '<!DOCTYPE net [<!ENTITY e "x">]>\n'
        if base_text.startswith("<?xml"):
            end = base_text.index("?>") + 2
            text = base_text[:end] + "\n" + doctype + base_text[end:].lstrip()
        else:
            text = doctype + base_text
        return scan_edit("e5-doctype", text, ["OVI001"])

    def e6():
        if base_text is None:
            return "plain-f32 was not written"
        return scan_edit("e6-no-bin", base_text, ["OVI005"], with_bin=False)

    row("E1", "largest f32 Const offset set to the .bin length", ["OVI003"],
        e1)
    row("E2", "largest f32 Const size set to 4 bytes short", ["OVI005"], e2)
    row("E3", "largest f32 Const shape set to 2^32 x 2^32", ["OVI004"], e3)
    row("E4", "first ReLU layer type changed to Custom", ["OVI002"], e4)
    row("E5", "DOCTYPE with an internal ENTITY inserted", ["OVI001"], e5)
    row("E6", "the .xml alone, no .bin beside it", ["OVI005"], e6)

    # ---- M1, M2: the one-command model-file-scan ------------------------
    def m1():
        if base_xml is None:
            return "plain-f32 was not written"
        code, doc, err = _mfs(os.path.dirname(base_xml))
        if doc is None:
            return "model-file-scan output was not JSON: %s" % err
        detail = {"exit": code, "files": {}}
        ok = code == 0
        xml_seen = False
        for entry in doc.get("files", []):
            name = os.path.basename(entry.get("path", ""))
            found = _entry_rules(entry)
            detail["files"][name] = found
            if name.endswith(".xml"):
                xml_seen = True
                ok = ok and not found
            elif name.endswith(".bin"):
                ok = ok and all(sev not in HIGH_SEVERITIES
                                for _, sev in found)
        return ok and xml_seen, detail

    def m2():
        xml = edited_paths.get("e1-offset-past-end")
        if xml is None:
            return "E1 file was not written"
        code, doc, err = _mfs(os.path.dirname(xml))
        if doc is None:
            return "model-file-scan output was not JSON: %s" % err
        detail = {"exit": code, "files": {}}
        hit = False
        for entry in doc.get("files", []):
            name = os.path.basename(entry.get("path", ""))
            detail["files"][name] = _entry_rules(entry)
            if name.endswith(".xml") and "OVI003" in json.dumps(entry):
                hit = True
        return code == 1 and hit, detail

    row("M1", "model-file-scan on the honest plain-f32 folder",
        "exit 0; .xml no findings; .bin nothing at MEDIUM or above", m1)
    row("M2", "model-file-scan on the E1 folder",
        "exit 1; .xml carries OVI003", m2)

    # ---- S1, S2: 50 honest pairs in one folder --------------------------
    sweep = os.path.join(args.work, "sweep")
    sweep_written = []
    sweep_errors = []
    if have_ops:
        swept = _child(["--sweep", sweep], timeout=1200)
        for ln in swept["lines"]:
            if ln.startswith("wrote "):
                sweep_written.append(int(ln.split()[1]))
            elif ln.startswith("error "):
                sweep_errors.append(ln[6:])
        crash = _child_problem(swept)
        if crash:
            sweep_errors.append(crash)
            if swept["returncode"] is not None and swept["returncode"] < 0:
                reported["writer_crashes"].append({
                    "model": "sweep", "signal": -swept["returncode"],
                    "after_written": len(sweep_written),
                    "stderr_tail": swept["stderr_tail"]})
    reported["sweep_written"] = len(sweep_written)
    reported["sweep_errors"] = sweep_errors[:5]
    sweep_doc = {}

    def run_sweep():
        if len(sweep_written) != 50:
            return "only %d of 50 sweep models were written" % len(
                sweep_written)
        code, doc, err = _mfs(sweep)
        if doc is None:
            return "model-file-scan output was not JSON: %s" % err
        sweep_doc["exit"] = code
        sweep_doc["doc"] = doc
        return None

    sweep_problem = run_sweep() if have_ops else "no opset module"

    def s1():
        if sweep_problem:
            return sweep_problem
        xmls = [e for e in sweep_doc["doc"].get("files", [])
                if e.get("path", "").endswith(".xml")]
        dirty = [os.path.basename(e["path"]) for e in xmls
                 if e.get("findings")]
        return len(xmls) == 50 and not dirty, {
            "xml_entries": len(xmls), "xml_with_findings": dirty[:10]}

    def s2():
        if sweep_problem:
            return sweep_problem
        bins = [e for e in sweep_doc["doc"].get("files", [])
                if e.get("path", "").endswith(".bin")]
        histogram = {}
        loud = []
        quiet = []
        for e in bins:
            found = _entry_rules(e)
            for rule, sev in found:
                key = "%s %s" % (rule, sev)
                histogram[key] = histogram.get(key, 0) + 1
            if any(sev in HIGH_SEVERITIES for _, sev in found):
                loud.append(os.path.basename(e["path"]))
            if not found:
                path = e["path"]
                if not os.path.isabs(path):
                    path = os.path.join(sweep, os.path.basename(path))
                quiet.append({"file": os.path.basename(e["path"]),
                              "first_bytes_hex": _head_hex(path)})
        reported["sweep_bin_rule_histogram"] = histogram
        reported["sweep_bins_without_findings"] = quiet[:10]
        reported["sweep_exit"] = sweep_doc["exit"]
        return len(bins) == 50 and not loud, {
            "bin_entries": len(bins), "bins_at_medium_or_above": loud,
            "histogram": histogram}

    row("S1", "50 honest pairs: every .xml routed and clean", [], s1)
    row("S2", "50 honest pairs: no .bin finding at MEDIUM or above", [], s2)

    # ---- R0-R2: what the OpenVINO runtime itself does -------------------
    def r0():
        if not honest:
            return "no honest file was written"
        got = {label: _runtime_read(xml)["outcome"]
               for label, xml in sorted(honest.items())}
        return all(v == "loaded" for v in got.values()), got

    def r_edit(name):
        def run():
            xml = edited_paths.get(name)
            if xml is None:
                return "%s was not written" % name
            got = _runtime_read(xml)
            return got["outcome"] == "rejected", got
        return run

    row("R0", "runtime read_model on every honest file", "loaded", r0)
    row("R1", "runtime read_model on E1", "rejected", r_edit(
        "e1-offset-past-end"))
    row("R2", "runtime read_model on E2", "rejected", r_edit(
        "e2-size-short"))

    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    summary = {
        "check_version": 3,
        "openvino": getattr(ov, "__version__", "") or ov.get_version(),
        "openvino_build": ov.get_version(),
        "numpy": np.__version__,
        "scanner": oi.__version__,
        "held": sum(1 for r in graded if r["result"] == "PASS"),
        "graded": len(graded),
        "not_run": [r["id"] for r in rows if r["result"] == "NOT RUN"],
        "reported": reported,
        "rows": rows,
    }
    with open(os.path.join(args.out, "realfile_summary.json"), "w",
              encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"], json.dumps(r.get("got", ""),
                                               default=str)[:400],
              r.get("reason", ""))
    print("reported:", json.dumps(reported, default=str)[:2500])
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
