"""Real-file check for msgpack_weights_scan.py and archive_payload_scan.py.

Writes model files with the real libraries inside the sandbox and scans them.
Expectations are pre-registered in PREREG-mpk-arc-realfile.md. Every file is
written and read locally; nothing is fetched or sent.

Usage: python realfile_check.py <msgpack|flax|torch|keras|bundle|summary> --out DIR

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import glob
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def rules(findings):
    return sorted(f["rule"] for f in findings)


class Checks(object):
    def __init__(self, section, out):
        self.section = section
        self.out = out
        self.files = os.path.join(out, "files")
        os.makedirs(self.files, exist_ok=True)
        self.results = []

    def path(self, name):
        return os.path.join(self.files, name)

    def expect(self, label, got, want, findings=None):
        ok = got == want
        self.results.append({
            "check": label, "status": "PASS" if ok else "FAIL",
            "got": repr(got), "want": repr(want),
            "evidence": [f["evidence"] for f in (findings or [])][:5],
        })
        print("%s %s: got %r want %r" % ("PASS" if ok else "FAIL", label,
                                         got, want))

    def error(self, label):
        tb = traceback.format_exc()
        self.results.append({"check": label, "status": "FAIL",
                             "got": "exception", "want": "", "evidence": [tb]})
        print("FAIL %s: exception\n%s" % (label, tb))

    def save(self):
        with open(os.path.join(self.out, self.section + ".json"), "w") as fh:
            json.dump(self.results, fh, indent=1)


def section_msgpack(c):
    import fractions

    import msgpack
    import msgpack_numpy
    import numpy as np

    import msgpack_weights_scan as mws

    def write(name, obj):
        p = c.path(name)
        with open(p, "wb") as fh:
            fh.write(msgpack.packb(obj, default=msgpack_numpy.encode,
                                   use_bin_type=True))
        return p

    try:
        p = write("mn_plain.msgpack", {"w": np.zeros((2, 3), np.float32),
                                       "s": np.float64(1.5)})
        f = mws.scan_file(p)
        c.expect("1 msgpack-numpy plain arrays clean", rules(f), [], f)
    except Exception:
        c.error("1 msgpack-numpy plain arrays clean")
    try:
        p = write("mn_obj_builtin.msgpack",
                  {"o": np.array([1, "a", None], dtype=object)})
        f = mws.scan_file(p)
        c.expect("2 object array of builtins -> MPK002", rules(f),
                 ["MPK002"], f)
    except Exception:
        c.error("2 object array of builtins -> MPK002")
    try:
        p = write("mn_obj_fraction.msgpack",
                  {"o": np.array([fractions.Fraction(1, 3)], dtype=object)})
        f = mws.scan_file(p)
        c.expect("3 object array with Fraction -> MPK001", rules(f),
                 ["MPK001"], f)
        c.expect("3b evidence names fractions.Fraction",
                 any("fractions.Fraction" in x["evidence"] for x in f), True)
        with open(p, "rb") as fh:
            back = msgpack.unpackb(fh.read(), object_hook=msgpack_numpy.decode,
                                   raw=False)
        c.expect("4 msgpack_numpy.decode unpickles the element",
                 type(back["o"][0]).__name__, "Fraction")
    except Exception:
        c.error("3/4 object array with Fraction")
    try:
        c.results.append({"check": "versions", "status": "INFO",
                          "got": "msgpack %s, msgpack-numpy %s, numpy %s" % (
                              ".".join(map(str, msgpack.version)),
                              getattr(msgpack_numpy, "__version__", "?"),
                              np.__version__),
                          "want": "", "evidence": []})
    except Exception:
        pass


def section_flax(c):
    import msgpack
    import numpy as np
    import jax.numpy as jnp
    from flax import serialization

    import msgpack_weights_scan as mws

    try:
        state = {
            "params": {"Dense_0": {"kernel": jnp.ones((4, 3), jnp.float32),
                                   "bias": jnp.zeros((3,), jnp.float32)}},
            "bf": jnp.ones((5,), jnp.bfloat16),
            "i8": np.arange(6, dtype=np.int8).reshape(2, 3),
            "step": np.int64(7),
            "f8": np.float64(2.5),
            "c": 1 + 2j,
        }
        data = serialization.msgpack_serialize(state)
        p = c.path("flax_state.msgpack")
        with open(p, "wb") as fh:
            fh.write(data)
        f = mws.scan_file(p)
        c.expect("5 Flax state dict clean", rules(f), [], f)
        back = serialization.msgpack_restore(data)
        c.expect("5b Flax round-trip kernel shape",
                 tuple(back["params"]["Dense_0"]["kernel"].shape), (4, 3))
    except Exception:
        c.error("5 Flax state dict clean")
    try:
        payload = msgpack.packb(((2, 3), "float32", b"\x00" * 20),
                                use_bin_type=True)
        data = msgpack.packb({"k": msgpack.ExtType(1, payload)},
                             use_bin_type=True)
        p = c.path("flax_mismatch.msgpack")
        with open(p, "wb") as fh:
            fh.write(data)
        f = mws.scan_file(p)
        c.expect("6 size mismatch -> MPK003", rules(f), ["MPK003"], f)
        try:
            serialization.msgpack_restore(data)
            raised = "no"
        except Exception as exc:
            raised = type(exc).__name__
        c.expect("6b msgpack_restore raises on it", raised != "no", True)
    except Exception:
        c.error("6 size mismatch -> MPK003")


def section_torch(c):
    import numpy as np
    import torch

    import archive_payload_scan as aps

    try:
        p = c.path("model.pt")
        torch.save(torch.nn.Linear(4, 3).state_dict(), p)
        f = aps.scan_file(p)
        c.expect("7 torch.save state_dict clean", rules(f), [], f)
    except Exception:
        c.error("7 torch.save state_dict clean")
    try:
        p = c.path("model_ts.pt")
        torch.jit.script(torch.nn.Linear(4, 3)).save(p)
        f = aps.scan_file(p)
        c.expect("8 TorchScript export clean", rules(f), [], f)
    except Exception:
        c.error("8 TorchScript export clean")
    try:
        p = c.path("arrays.npz")
        np.savez(p, a=np.zeros(3), b=np.ones((2, 2)))
        f = aps.scan_file(p)
        c.expect("9 np.savez clean", rules(f), [], f)
    except Exception:
        c.error("9 np.savez clean")


def section_keras(c):
    os.environ.setdefault("KERAS_BACKEND", "jax")
    import keras

    import archive_payload_scan as aps

    try:
        model = keras.Sequential([keras.Input((4,)), keras.layers.Dense(3)])
        p = c.path("model.keras")
        model.save(p)
        f = aps.scan_file(p)
        c.expect("10 Keras v3 .keras clean", rules(f), [], f)
    except Exception:
        c.error("10 Keras v3 .keras clean")


def section_bundle(c):
    import tarfile
    import zipfile

    import archive_payload_scan as aps

    try:
        p = c.path("bundle.tar.gz")
        with tarfile.open(p, "w:gz") as tf:
            for name in ("model.pt", "model_ts.pt", "arrays.npz",
                         "model.keras"):
                if os.path.exists(c.path(name)):
                    tf.add(c.path(name), arcname="bundle/" + name)
        f = aps.scan_file(p)
        c.expect("11 tar.gz of real model files clean", rules(f), [], f)
    except Exception:
        c.error("11 tar.gz of real model files clean")
    try:
        p = c.path("with_binary.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.write("/bin/ls", "weights/model.bin")
            if os.path.exists(c.path("arrays.npz")):
                zf.write(c.path("arrays.npz"), "weights/arrays.npz")
        f = aps.scan_file(p)
        c.expect("12 real ELF named model.bin -> ARC001", rules(f),
                 ["ARC001"], f)
        c.expect("12b evidence says the name hides it",
                 any("the file name does not say so" in x["evidence"]
                     for x in f), True)
    except Exception:
        c.error("12 real ELF named model.bin -> ARC001")
    try:
        p = c.path("with_script.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("run.sh", "#!/bin/sh\necho hello\n")
        f = aps.scan_file(p)
        c.expect("13 shebang script -> ARC002", rules(f), ["ARC002"], f)
    except Exception:
        c.error("13 shebang script -> ARC002")


def summary(out):
    rows = []
    for path in sorted(glob.glob(os.path.join(out, "*.json"))):
        if os.path.basename(path) in ("summary.json",
                                      "realfile_summary.json"):
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
    return 1 if failed else 0


SECTIONS = {
    "msgpack": section_msgpack,
    "flax": section_flax,
    "torch": section_torch,
    "keras": section_keras,
    "bundle": section_bundle,
}


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
