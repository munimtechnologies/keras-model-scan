# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# Smoke test v2 for skills/model-file-scan/SKILL.md (pinned to v0.54.0): follows the skill's
# own commands on small HONEST files written here by the real libraries (pickle, joblib.dump;
# no crafted or attack-shaped content) and checks that what the skill tells agents (install
# line, version string, exit codes, JSON shape, rule table) is true for the installed release.
# Always exits 0; the verdict is in <out>/skill_smoke.json ("all_pass", 12 rows).
import importlib.util
import json
import os
import pickle
import re
import struct
import subprocess
import sys
import traceback
from collections import Counter, OrderedDict

SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
TAG = "v0.54.0"
VERSION = "0.12.1"
INSTALL_PIP = 'python -m pip install "git+https://github.com/munimtechnologies/keras-model-scan@%s"' % TAG
INSTALL_PIPX = 'pipx install "git+https://github.com/munimtechnologies/keras-model-scan@%s"' % TAG
N_ROWS = 12


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    fm = {}
    for line in m.group(1).split("\n"):
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip()
    return fm


def code_blocks(text):
    return re.findall(r"```(\w*)\n(.*?)```", text, re.S)


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
    return p.returncode, p.stdout, p.stderr


def scan_json(target):
    code, out, err = run(["model-file-scan", target, "--json"])
    try:
        data = json.loads(out)
    except Exception:
        data = None
    return code, data, err[-2000:]


def schema_ok(data):
    if not isinstance(data, dict):
        return False, "not a dict"
    if set(["tool", "version", "files"]) - set(data):
        return False, "missing top-level key"
    if data["tool"] != "model-file-scan":
        return False, "tool name"
    for f in data["files"]:
        if "path" not in f or "findings" not in f:
            return False, "file entry keys"
        for x in f["findings"]:
            if "rule" not in x or "severity" not in x:
                return False, "finding keys"
            if x["severity"] not in SEV:
                return False, "severity " + str(x["severity"])
    return True, ""


def findings(data):
    out = []
    for f in (data or {}).get("files", []):
        for x in f.get("findings", []):
            out.append({"path": os.path.basename(str(f.get("path"))), "rule": x.get("rule"),
                        "severity": x.get("severity"), "title": str(x.get("title", ""))[:200]})
    return out


def worst(data):
    w = -1
    for x in findings(data):
        w = max(w, SEV.get(x["severity"], 0))
    return w


def write_safetensors(path):
    body = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)
    header = {"__metadata__": {"format": "pt"},
              "w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, len(body)]}}
    h = json.dumps(header, separators=(",", ":")).encode("utf-8")
    h += b" " * ((8 - len(h) % 8) % 8)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<Q", len(h)) + h + body)


def table_rules(text):
    """Rule ids named in the skill's 'How to read the findings' table."""
    m = re.search(r"## How to read the findings.*?\n(\|.*?)\n\n", text, re.S)
    if not m:
        return []
    return sorted(set(re.findall(r"`(PKL\d{3})`", m.group(1))))


def main():
    skill_path = sys.argv[sys.argv.index("--skill") + 1]
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    os.makedirs(out_dir, exist_ok=True)
    rows = {}
    obs = {}
    try:
        text = open(skill_path, encoding="utf-8").read().replace("\r\n", "\n")
        fm = frontmatter(text) or {}
        name = fm.get("name", "")
        desc = fm.get("description", "")
        rows["A1_frontmatter"] = bool(
            re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) and len(name) <= 64
            and name == os.path.basename(os.path.dirname(os.path.abspath(skill_path)))
            and 0 < len(desc) <= 1024 and "<" not in desc and ">" not in desc
            and fm.get("license") == "Apache-2.0")
        obs["name"] = name
        obs["description_chars"] = len(desc)
        rows["A2_install_lines_in_skill"] = INSTALL_PIP in text and INSTALL_PIPX in text \
            and "v0.53.1" not in text

        code, out, err = run(["model-file-scan", "--version"])
        obs["version_output"] = (out + err).strip()
        rows["A3_version"] = code == 0 and ("model-file-scan " + VERSION) in (out + err) \
            and ("`model-file-scan %s`" % VERSION) in text

        d = "/tmp/smoke"
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "plain_p2.pkl"), "wb") as fh:
            pickle.dump({"w": [1.0, 2.0], "b": [0.5], "name": "tiny"}, fh, protocol=2)
        write_safetensors(os.path.join(d, "tiny.safetensors"))
        coll = os.path.join("/tmp", "coll_p4.pkl")
        with open(coll, "wb") as fh:
            pickle.dump({"a": OrderedDict(x=1), "c": Counter("abca")}, fh, protocol=4)

        # Honest joblib.dump files (joblib's default, uncompressed): numeric arrays only,
        # and (observation only) one object-dtype array of strings.
        jl_num = os.path.join("/tmp", "num.joblib")
        jl_obj = os.path.join("/tmp", "obj.joblib")
        jl_err = None
        try:
            import joblib
            import numpy as np
            joblib.dump({"w": np.arange(12, dtype=np.float32).reshape(3, 4),
                         "b": np.zeros(4, dtype=np.float64),
                         "idx": np.arange(5, dtype=np.int64)}, jl_num)
            joblib.dump({"names": np.array(["a", "bb", "ccc"], dtype=object),
                         "w": np.ones(3)}, jl_obj)
            obs["joblib_version"] = joblib.__version__
            obs["numpy_version"] = np.__version__
        except Exception:
            jl_err = traceback.format_exc()[-1500:]
            obs["joblib_write_error"] = jl_err

        per = {}
        all_schema = True
        targets = [("plain_p2", os.path.join(d, "plain_p2.pkl")),
                   ("safetensors", os.path.join(d, "tiny.safetensors")),
                   ("folder", d),
                   ("coll_p4", coll)]
        if jl_err is None:
            targets += [("joblib_num", jl_num), ("joblib_obj", jl_obj)]
        for label, target in targets:
            c, data, err = scan_json(target)
            ok, why = schema_ok(data)
            all_schema = all_schema and ok
            per[label] = {"exit": c, "schema_ok": ok, "schema_why": why,
                          "worst": worst(data), "findings": findings(data), "stderr_tail": err}
        obs["scans"] = per
        rows["A4_plain_pickle_clean"] = per["plain_p2"]["exit"] == 0 and per["plain_p2"]["worst"] < 2
        rows["A5_safetensors_clean"] = per["safetensors"]["exit"] == 0 and per["safetensors"]["worst"] < 2
        rows["A6_folder_walk"] = per["folder"]["exit"] == 0 and per["folder"]["schema_ok"]
        rows["A7_json_schema"] = all_schema

        c, data, err = scan_json("/tmp/does-not-exist.pkl")
        obs["missing_exit"] = c
        rows["A8_missing_exit_2"] = c == 2

        # Step 2 of the skill, run literally with only the placeholder path replaced.
        block = [b for lang, b in code_blocks(text) if "--json > scan.json" in b]
        lit = {"found": bool(block)}
        if block:
            cmd = block[0].strip().replace("path/to/model_or_folder", d)
            lit["cmd"] = cmd
            c, out, err = run(["bash", "-c", cmd], cwd="/tmp")
            lit["stdout"] = out.strip()[-300:]
            m = re.search(r"exit=(\d+)", out)
            try:
                sj = json.load(open("/tmp/scan.json"))
                sj_ok = schema_ok(sj)[0]
            except Exception as exc:
                sj_ok = False
                lit["scan_json_error"] = str(exc)
            rows["A9_step2_literal"] = bool(m) and m.group(1) == "0" and sj_ok
        else:
            rows["A9_step2_literal"] = False
        obs["step2_literal"] = lit

        # A10 (new in v2): the PKL007 false alarm on an honest protocol-4 pickle of two
        # collections classes (memoized module name) is gone in the pinned release.
        coll_rules = sorted(set(x["rule"] for x in per["coll_p4"]["findings"]))
        obs["coll_p4_rules"] = coll_rules
        obs["coll_p4_exit"] = per["coll_p4"]["exit"]
        rows["A10_coll_p4_no_pkl007"] = per["coll_p4"]["schema_ok"] and "PKL007" not in coll_rules

        # A11 (new in v2): an honest numeric-only joblib.dump file scans clean at the skill's
        # default threshold, with no PKL007 or PKL008.
        if jl_err is None:
            jn = per["joblib_num"]
            jr = set(x["rule"] for x in jn["findings"])
            rows["A11_joblib_numeric_clean"] = jn["exit"] == 0 and jn["worst"] < 2 \
                and not (jr & {"PKL007", "PKL008"})
            obs["joblib_obj_rules"] = sorted(set(x["rule"] for x in per["joblib_obj"]["findings"]))
            obs["joblib_obj_exit"] = per["joblib_obj"]["exit"]
        else:
            rows["A11_joblib_numeric_clean"] = False

        # A12 (new in v2): every PKL rule id in the skill's table exists in the installed
        # pickle scanner's source (read as text, never imported), so the skill names no
        # rule the release does not have.
        spec = importlib.util.find_spec("pickle_model_scan")
        src = open(spec.origin, encoding="utf-8").read() if spec and spec.origin else ""
        named = table_rules(text)
        missing = [r for r in named if ('"%s"' % r) not in src and ("'%s'" % r) not in src]
        obs["table_rules"] = named
        obs["table_rules_missing_in_source"] = missing
        rows["A12_table_rules_exist"] = len(named) >= 8 and not missing
    except Exception:
        obs["error"] = traceback.format_exc()[-3000:]

    result = {"rows": rows, "all_pass": bool(rows) and all(rows.values()) and len(rows) == N_ROWS,
              "observations": obs}
    with open(os.path.join(out_dir, "skill_smoke.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps({"rows": rows, "all_pass": result["all_pass"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
