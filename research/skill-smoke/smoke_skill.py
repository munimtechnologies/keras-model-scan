# Apache-2.0. MV2 of Munim, Inc. (made with AI agents).
# Smoke test for skills/model-file-scan/SKILL.md: follows the skill's own commands on
# small HONEST files written here (no crafted or attack-shaped content) and checks that
# what the skill tells agents (install line, version string, exit codes, JSON shape) is true.
# Always exits 0; the verdict is in <out>/skill_smoke.json ("all_pass").
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
INSTALL_PIP = 'python -m pip install "git+https://github.com/munimtechnologies/keras-model-scan@v0.53.1"'
INSTALL_PIPX = 'pipx install "git+https://github.com/munimtechnologies/keras-model-scan@v0.53.1"'


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


def run(cmd, cwd=None, shell=False):
    p = subprocess.run(cmd, cwd=cwd, shell=shell, capture_output=True, text=True, timeout=300)
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


def main():
    skill_path = sys.argv[sys.argv.index("--skill") + 1]
    out_dir = sys.argv[sys.argv.index("--out") + 1]
    os.makedirs(out_dir, exist_ok=True)
    rows = {}
    obs = {}
    try:
        text = open(skill_path, encoding="utf-8").read().replace("\r\n", "\n")
        obs["skill_has_crlf"] = "\r\n" in open(skill_path, encoding="utf-8", newline="").read()
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
        rows["A2_install_lines_in_skill"] = INSTALL_PIP in text and INSTALL_PIPX in text

        code, out, err = run(["model-file-scan", "--version"])
        obs["version_output"] = (out + err).strip()
        rows["A3_version"] = code == 0 and "model-file-scan 0.12.0" in (out + err) \
            and "`model-file-scan 0.12.0`" in text

        d = "/tmp/smoke"
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "plain_p2.pkl"), "wb") as fh:
            pickle.dump({"w": [1.0, 2.0], "b": [0.5], "name": "tiny"}, fh, protocol=2)
        write_safetensors(os.path.join(d, "tiny.safetensors"))
        coll = os.path.join("/tmp", "coll_p4.pkl")
        with open(coll, "wb") as fh:
            pickle.dump({"a": OrderedDict(x=1), "c": Counter("abca")}, fh, protocol=4)

        per = {}
        all_schema = True
        for label, target in (("plain_p2", os.path.join(d, "plain_p2.pkl")),
                              ("safetensors", os.path.join(d, "tiny.safetensors")),
                              ("folder", d),
                              ("coll_p4", coll)):
            c, data, err = scan_json(target)
            ok, why = schema_ok(data)
            all_schema = all_schema and ok
            per[label] = {"exit": c, "schema_ok": ok, "schema_why": why,
                          "worst": worst(data), "findings": findings(data), "stderr_tail": err}
        obs["scans"] = per
        rows["A4_plain_pickle_clean"] = per["plain_p2"]["exit"] == 0 and per["plain_p2"]["worst"] < 2
        rows["A5_safetensors_clean"] = per["safetensors"]["exit"] == 0 and per["safetensors"]["worst"] < 2
        rows["A6_folder_walk"] = per["folder"]["exit"] == 0 and len(
            set(x["path"] for x in per["folder"]["findings"])) >= 0 and per["folder"]["schema_ok"]
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

        # Observation only (not a gate): does the skill's PKL007 caveat show on an honest
        # protocol-4 pickle of two collections classes (the module name is memoized)?
        obs["coll_p4_rules"] = sorted(set(x["rule"] for x in per["coll_p4"]["findings"]))
        obs["coll_p4_shows_pkl007"] = "PKL007" in obs["coll_p4_rules"]
    except Exception:
        obs["error"] = traceback.format_exc()[-3000:]

    result = {"rows": rows, "all_pass": bool(rows) and all(rows.values()) and len(rows) == 9,
              "observations": obs}
    with open(os.path.join(out_dir, "skill_smoke.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps({"rows": rows, "all_pass": result["all_pass"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
