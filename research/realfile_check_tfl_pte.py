"""Real-file check for tflite_model_scan.py and executorch_pte_scan.py.

Writes model files with the real converters inside the sandbox and scans
them. Expectations are pre-registered in PREREG-tfl-pte-realfile.md. Every
file is written and read locally; nothing is fetched or sent.

Usage: python realfile_check_tfl_pte.py <tfl|pte|summary> --out DIR

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import glob
import json
import os
import struct
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "ship"))


def rules(findings):
    return sorted(f["rule"] for f in findings)


class Checks(object):
    def __init__(self, section, out):
        self.section = section
        self.out = out
        self.files = os.path.join(out, "files")
        os.makedirs(self.files, exist_ok=True)
        self.results = []

    def write(self, name, data):
        with open(os.path.join(self.files, name), "wb") as fh:
            fh.write(data)

    def expect(self, label, got, want, findings=None):
        ok = got == want
        self.results.append({
            "check": label, "status": "PASS" if ok else "FAIL",
            "got": repr(got), "want": repr(want),
            "evidence": [f["rule"] + " " + f["message"] + " [" + f["evidence"]
                         + "]" for f in (findings or [])][:8],
        })
        print("%s %s: got %r want %r" % ("PASS" if ok else "FAIL", label,
                                         got, want))

    def info(self, label, got):
        self.results.append({"check": label, "status": "INFO",
                             "got": repr(got), "want": "", "evidence": []})
        print("INFO %s: %r" % (label, got))

    def error(self, label):
        tb = traceback.format_exc()
        self.results.append({"check": label, "status": "FAIL",
                             "got": "exception", "want": "", "evidence": [tb]})
        print("FAIL %s: exception\n%s" % (label, tb))

    def save(self):
        with open(os.path.join(self.out, self.section + ".json"), "w") as fh:
            json.dump(self.results, fh, indent=1)


def _custom_codes(tms, data):
    buf = tms._Buf(data)
    root = buf.deref(0)
    return [tms._string(buf, t, 1) for t in tms._tables(buf, root, 1)]


def section_tfl(c):
    import tensorflow as tf

    import tflite_model_scan as tms

    c.info("versions", "tensorflow %s, tflite_model_scan %s"
           % (tf.__version__, tms.__version__))

    class Small(tf.Module):
        def __init__(self):
            super().__init__()
            self.w = tf.Variable(tf.ones([4, 3]))

        @tf.function(input_signature=[tf.TensorSpec([1, 4], tf.float32)])
        def __call__(self, x):
            return tf.nn.relu(tf.matmul(x, self.w) + 1.0)

    module = Small()

    def converter():
        fn = module.__call__.get_concrete_function()
        return tf.lite.TFLiteConverter.from_concrete_functions([fn], module)

    try:
        data = converter().convert()
        c.write("builtins.tflite", data)
        f = tms.scan_bytes(data)
        c.expect("T1 builtins-only conversion clean", rules(f), [], f)
    except Exception:
        c.error("T1 builtins-only conversion clean")
    try:
        conv = converter()
        conv.target_spec.supported_ops = [tf.lite.OpsSet.SELECT_TF_OPS]
        data = conv.convert()
    except Exception:
        c.info("T2/T3 NOT TESTED: converter refused SELECT_TF_OPS only",
               traceback.format_exc()[-800:])
        return
    try:
        c.write("select_tf_ops.tflite", data)
        f = tms.scan_bytes(data)
        got = sorted(set(rules(f)))
        c.expect("T2 select-TF-ops conversion gives only TFL003", got,
                 ["TFL003"], f)
        codes = [x for x in _custom_codes(tms, data) if x]
        c.info("T2 custom codes", [x.decode("ascii", "replace") for x in codes])
        names = set(x[4:].decode("ascii", "replace") for x in codes
                    if x.startswith(b"Flex"))
        named = [any((" op %s " % n) in x["message"] for n in names)
                 for x in f if x["rule"] == "TFL003"]
        c.expect("T3 each TFL003 names an op from the custom codes",
                 bool(named) and all(named), True, f)
    except Exception:
        c.error("T2/T3 select-TF-ops conversion")


def section_pte(c):
    import torch
    from torch.export import export
    from executorch.exir import to_edge, to_edge_transform_and_lower

    import executorch_pte_scan as pts

    c.info("versions", "torch %s, executorch_pte_scan %s"
           % (torch.__version__, pts.__version__))
    model = torch.nn.Linear(4, 3).eval()
    example = (torch.randn(1, 4),)
    portable = None
    try:
        portable = bytes(to_edge(export(model, example)).to_executorch().buffer)
        c.write("linear_portable.pte", portable)
        f = pts.scan_bytes(portable)
        c.expect("P1 portable Linear clean", rules(f), [], f)
    except Exception:
        c.error("P1 portable Linear clean")
    try:
        from executorch.backends.xnnpack.partition.xnnpack_partitioner import (
            XnnpackPartitioner)
        lowered = to_edge_transform_and_lower(
            export(model, example), partitioner=[XnnpackPartitioner()])
        xnn = bytes(lowered.to_executorch().buffer)
        c.write("linear_xnnpack.pte", xnn)
        f = pts.scan_bytes(xnn)
        c.expect("P2 XNNPACK-lowered Linear -> PTE003 only", rules(f),
                 ["PTE003"], f)
        c.expect("P2b PTE003 names XnnpackBackend",
                 any("XnnpackBackend" in x["message"] for x in f), True)
    except Exception:
        c.error("P2 XNNPACK-lowered Linear")
    if portable is None:
        return
    try:
        header = pts._header(pts._Buf(portable))
        c.info("P3 header (program_size, base, data_size), file size",
               (header, len(portable)))
        c.expect("P3 eh00 header with a segment base offset",
                 header is not None and header[1] > 0, True)
    except Exception:
        c.error("P3 eh00 header")
        header = None
    try:
        f = pts.scan_bytes(portable[:-16])
        c.expect("P4 last 16 bytes cut -> PTE005 only", rules(f), ["PTE005"], f)
    except Exception:
        c.error("P4 truncated")
    try:
        if header is None:
            c.expect("P5 base inside program -> PTE002 only", "no header",
                     ["PTE002"])
        else:
            patched = bytearray(portable)
            struct.pack_into("<Q", patched, 24, header[0] - 8)
            c.write("linear_base_inside.pte", bytes(patched))
            f = pts.scan_bytes(bytes(patched))
            c.expect("P5 base inside program -> PTE002 only", rules(f),
                     ["PTE002"], f)
    except Exception:
        c.error("P5 base inside program")


def summary(out):
    rows = []
    for path in sorted(glob.glob(os.path.join(out, "*.json"))):
        if os.path.basename(path).endswith("summary.json"):
            continue
        with open(path) as fh:
            rows.extend(json.load(fh))
    failed = [r for r in rows if r["status"] == "FAIL"]
    passed = [r for r in rows if r["status"] == "PASS"]
    with open(os.path.join(out, "realfile_summary.json"), "w") as fh:
        json.dump({"passed": len(passed), "failed": len(failed),
                   "failures": failed}, fh, indent=1)
    print("PASSED %d FAILED %d" % (len(passed), len(failed)))
    for r in failed:
        print("FAIL", r["check"], r["got"], r["want"])
    return 0


SECTIONS = {"tfl": section_tfl, "pte": section_pte}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("section", choices=sorted(SECTIONS) + ["summary"])
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    if args.section == "summary":
        return summary(args.out)
    c = Checks(args.section, args.out)
    try:
        SECTIONS[args.section](c)
    except Exception:
        c.error(args.section + " import/setup")
    c.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
