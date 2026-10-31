#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""xgboost_model_scan - static validity checks for XGBoost model files.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

XGBoost saves a model as JSON (``.json``) or UBJSON (``.ubj``, and the default
for ``.bst``/``.model`` since 2.0). Each tree is a set of parallel arrays:
``left_children``, ``right_children``, ``parents``, ``split_indices``,
``split_conditions`` and others, plus optional categorical-split arrays.

XGBoost's loader (src/tree/tree_model.cc, read 31 October 2026) checks that
every array has ``num_nodes`` entries, and takes the values in them as
written. Its documentation says to load only JSON models produced by XGBoost.
A CI gate can check the rest before a model reaches a loader:

- XGB001 high   CWE-125  An index points outside its tree or array: a child,
                         the right branch the predictor takes at left child + 1
                         (src/predictor/predict_fn.h), a parent, or a
                         categorical split's category range.
- XGB002 high   CWE-125  A split reads a feature index the model does not have
                         (negative, or not below num_feature).
- XGB003 high   CWE-835  A tree loops: a node leads back to one of its own
                         ancestors, so walking it from the root never ends.
- XGB004 high   CWE-20   An object repeats a key. XGBoost's writer never does.
- XGB005 high   CWE-125  A UBJSON string length or array count runs past the
                         end of the file.
- XGB006 medium CWE-20   Tree data XGBoost's writer does not produce: a stored
                         right child other than left child + 1 (the predictor
                         goes to left child + 1; dmlc/xgboost#7903), a leaf with
                         a right child, a parent entry that does not point back,
                         an output group the model does not have, or
                         categorical data out of order or negative.
- XGB007 medium CWE-693  Not checked: not an XGBoost JSON/UBJSON model, a
                         legacy binary or pickle file, arrays XGBoost would
                         refuse, multi-target trees, nesting too deep, or
                         findings capped.

Static review only: nothing is loaded or executed, and xgboost is not needed.
"""

import json
import os
import struct
import sys

__version__ = "0.1.0"

MAX_FINDINGS = 1000
MAX_DEPTH = 64

_RULES = {
    "XGB001": ("high", "CWE-125"),
    "XGB002": ("high", "CWE-125"),
    "XGB003": ("high", "CWE-835"),
    "XGB004": ("high", "CWE-20"),
    "XGB005": ("high", "CWE-125"),
    "XGB006": ("medium", "CWE-20"),
    "XGB007": ("medium", "CWE-693"),
}

# Arrays the loader requires to have exactly num_nodes entries.
_TREE_ARRAYS = ("loss_changes", "sum_hessian", "base_weights", "left_children",
                "right_children", "parents", "split_indices",
                "split_conditions", "default_left")

# Node ids and split indices keep a flag in bit 31; the value is the rest.
_MASK31 = 0x7FFFFFFF

# UBJSON scalar markers -> struct format (big-endian, as XGBoost writes).
_UBJ_FIXED = {"i": ">b", "U": ">B", "I": ">h", "l": ">i", "L": ">q",
              "d": ">f", "D": ">d", "C": ">b"}
_UBJ_TYPED = ("d", "D", "i", "U", "I", "l", "L")


class _Bad(Exception):
    pass


class _Overrun(Exception):
    pass


def _ascii(value, limit=300):
    text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit] + "..."


class _Findings(object):
    def __init__(self):
        self.items = []
        self._seen = {}
        self.capped = False

    def add(self, rule, message, evidence, key=None):
        if key is not None and key in self._seen:
            self._seen[key][1] += 1
            return
        if len(self.items) >= MAX_FINDINGS:
            self.capped = True
            return
        severity, cwe = _RULES[rule]
        item = {"rule": rule, "severity": severity, "cve": "", "cwe": cwe,
                "message": _ascii(message), "evidence": _ascii(evidence)}
        self.items.append(item)
        if key is not None:
            self._seen[key] = [item, 1]

    def result(self):
        for item, count in self._seen.values():
            if count > 1:
                item["evidence"] += "; %d in total" % count
        if self.capped:
            severity, cwe = _RULES["XGB007"]
            self.items.append({
                "rule": "XGB007", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


# -- UBJSON (the subset XGBoost writes and reads) -----------------------------

class _UBJ(object):
    """Decode XGBoost's UBJSON: keys and strings carry an 'L' int64 length,
    containers carry '#' 'L' counts, and a repeated key keeps its first value
    (UBJReader::ParseObject in src/common/json.cc)."""

    def __init__(self, data, dups):
        self.buf = bytes(data)
        self.pos = 0
        self.dups = dups

    def _left(self):
        return len(self.buf) - self.pos

    def _take(self, n):
        if n > self._left():
            raise _Bad("truncated UBJSON at offset %d" % self.pos)
        start = self.pos
        self.pos += n
        return self.buf[start:self.pos]

    def _marker(self):
        return self._take(1).decode("latin-1")

    def _peek(self):
        if not self._left():
            raise _Bad("truncated UBJSON at offset %d" % self.pos)
        return self.buf[self.pos:self.pos + 1].decode("latin-1")

    def _prim(self, code):
        fmt = _UBJ_FIXED[code]
        return struct.unpack(fmt, self._take(struct.calcsize(fmt)))[0]

    def _count(self, what):
        start = self.pos
        marker = self._marker()
        if marker != "L":
            raise _Bad("%s length at offset %d uses marker %r; XGBoost "
                       "expects 'L'" % (what, start, marker))
        n = self._prim("L")
        if n < 0:
            raise _Bad("%s at offset %d declares a negative length" % (what, start))
        return n, start

    def _string(self, what):
        n, start = self._count(what)
        if n > self._left():
            raise _Overrun("%s at offset %d declares %d bytes; %d remain"
                           % (what, start, n, self._left()))
        return self._take(n).decode("utf-8", "replace")

    def value(self, depth=0):
        if depth > MAX_DEPTH:
            raise _Bad("nesting is deeper than %d levels" % MAX_DEPTH)
        marker = self._marker()
        if marker == "{":
            return self._object(depth)
        if marker == "[":
            return self._array(depth)
        if marker == "Z":
            return None
        if marker == "T":
            return True
        if marker == "F":
            return False
        if marker == "S":
            return self._string("string")
        if marker in _UBJ_FIXED:
            return self._prim(marker)
        raise _Bad("unknown UBJSON marker %r at offset %d"
                   % (marker, self.pos - 1))

    def _object(self, depth):
        out = {}
        while self._peek() != "}":
            key = self._string("key")
            item = self.value(depth + 1)
            if key in out:
                self.dups.append(key)
            else:
                out[key] = item
        self.pos += 1
        return out

    def _array(self, depth):
        marker = self._peek()
        if marker == "$":
            self.pos += 1
            kind = self._marker()
            if kind not in _UBJ_TYPED:
                raise _Bad("typed array of unsupported type %r" % kind)
            if self._marker() != "#":
                raise _Bad("typed array without a count at offset %d"
                           % (self.pos - 1))
            n, start = self._count("typed array")
            size = struct.calcsize(_UBJ_FIXED[kind])
            if n > self._left() // size:
                raise _Overrun("typed array at offset %d declares %d items of "
                               "%d bytes; %d bytes remain"
                               % (start, n, size, self._left()))
            raw = self._take(n * size)
            return list(struct.unpack(">%d%s" % (n, _UBJ_FIXED[kind][1]), raw))
        if marker == "#":
            self.pos += 1
            n, start = self._count("array")
            if n > self._left():
                raise _Overrun("array at offset %d declares %d items; %d bytes "
                               "remain" % (start, n, self._left()))
            return [self.value(depth + 1) for _ in range(n)]
        items = []
        while self._peek() != "]":
            items.append(self.value(depth + 1))
        self.pos += 1
        return items


# -- model checks -------------------------------------------------------------

def _int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            try:
                number = float(value)
            except ValueError:
                return None
            return int(number) if number.is_integer() else None
    return None


def _ints(values):
    if not isinstance(values, list):
        return None
    out = []
    for value in values:
        number = _int(value)
        if number is None:
            return None
        out.append(number)
    return out


def _find_loop(children, n):
    """Return (node, ancestor) for the first edge back to an ancestor of the
    root walk, or None. Iterative, so deep trees cannot exhaust the stack."""
    state = [0] * n
    state[0] = 1
    stack = [(0, 0)]
    while stack:
        node, k = stack[-1]
        kids = children[node]
        if k < len(kids):
            stack[-1] = (node, k + 1)
            kid = kids[k]
            if state[kid] == 1:
                return node, kid
            if state[kid] == 0:
                state[kid] = 1
                stack.append((kid, 0))
        else:
            state[node] = 2
            stack.pop()
    return None


def _check_categories(tree, n, here, out):
    nodes = _ints(tree.get("categories_nodes") or [])
    segments = _ints(tree.get("categories_segments") or [])
    sizes = _ints(tree.get("categories_sizes") or [])
    cats = _ints(tree.get("categories") or [])
    if nodes is None or segments is None or sizes is None or cats is None:
        out.add("XGB007", "categorical split arrays hold values that are not "
                "integers; they were not checked", here,
                key=("XGB007", "cat-type"))
        return
    if not nodes:
        return
    if len(segments) < len(nodes) or len(sizes) < len(nodes):
        out.add("XGB001", "categories_nodes lists more nodes than "
                "categories_segments or categories_sizes has entries; XGBoost "
                "reads one of each per listed node",
                "%s: %d nodes, %d segments, %d sizes"
                % (here, len(nodes), len(segments), len(sizes)),
                key=("XGB001", "cat-count"))
    previous = -1
    for k, node in enumerate(nodes):
        if not previous < node < n:
            out.add("XGB006", "categories_nodes is not a rising list of node "
                    "ids inside the tree",
                    "%s: entry %d is node %d" % (here, k, node),
                    key=("XGB006", "cat-nodes"))
        previous = max(previous, node)
        if k < len(segments) and k < len(sizes):
            begin, size = segments[k], sizes[k]
            if begin < 0 or size < 0 or begin + size > len(cats):
                out.add("XGB001", "a categorical split's category range runs "
                        "outside the categories array",
                        "%s: node %d uses categories[%d:%d] of %d"
                        % (here, node, begin, begin + size, len(cats)),
                        key=("XGB001", "cat-range"))
    if any(cat < 0 for cat in cats):
        out.add("XGB006", "a category value is negative; XGBoost's writer "
                "stores categories as non-negative integers", here,
                key=("XGB006", "cat-negative"))


def _check_tree(tree, t, num_feature, where, out):
    here = "%s tree %d" % (where, t)
    if not isinstance(tree, dict):
        out.add("XGB007", "a tree is not an object", here,
                key=("XGB007", "tree-type"))
        return
    param = tree.get("tree_param")
    param = param if isinstance(param, dict) else {}
    n = _int(param.get("num_nodes"))
    leaf_vector = _int(param.get("size_leaf_vector"))
    if leaf_vector is not None and leaf_vector > 1:
        out.add("XGB007", "multi-target trees (size_leaf_vector > 1) are not "
                "checked", here, key=("XGB007", "multi-target"))
        return
    if n is None or n < 1:
        out.add("XGB007", "tree_param.num_nodes is missing or not positive; "
                "XGBoost refuses such a tree", here,
                key=("XGB007", "num-nodes"))
        return
    bad = [name for name in _TREE_ARRAYS
           if not isinstance(tree.get(name), list) or len(tree[name]) != n]
    split_type = tree.get("split_type")
    if isinstance(split_type, list) and len(split_type) != n:
        bad.append("split_type")
    if bad:
        out.add("XGB007", "tree arrays do not have num_nodes (%d) entries; "
                "XGBoost refuses to load this tree" % n,
                "%s: %s" % (here, ", ".join(bad)), key=("XGB007", "lengths"))
        return
    lefts = _ints(tree["left_children"])
    rights = _ints(tree["right_children"])
    parents = _ints(tree["parents"])
    splits = _ints(tree["split_indices"])
    if any(values is None for values in (lefts, rights, parents, splits)):
        out.add("XGB007", "tree index arrays hold values that are not "
                "integers; the tree was not checked", here,
                key=("XGB007", "index-type"))
        return

    children = [[] for _ in range(n)]
    for i in range(n):
        left, right = lefts[i], rights[i]
        if left == -1:
            if right != -1:
                out.add("XGB006", "a leaf (left child -1) stores a right child",
                        "%s node %d: right child %d" % (here, i, right),
                        key=("XGB006", "leaf-right"))
            continue
        if not 0 <= left < n:
            out.add("XGB001", "a split node's left child is outside the tree",
                    "%s node %d: left child %d, tree has %d nodes"
                    % (here, i, left, n), key=("XGB001", "left"))
            continue
        if not 0 <= right < n:
            out.add("XGB001", "a split node's right child is outside the tree",
                    "%s node %d: right child %d, tree has %d nodes"
                    % (here, i, right, n), key=("XGB001", "right"))
        if left + 1 >= n:
            out.add("XGB001", "XGBoost's predictor takes the right branch at "
                    "left child + 1, which is past the end of the tree",
                    "%s node %d: left child %d, so the right branch is node "
                    "%d of %d" % (here, i, left, left + 1, n),
                    key=("XGB001", "left-plus-one"))
        elif right != left + 1:
            out.add("XGB006", "the stored right child is not left child + 1; "
                    "XGBoost's predictor goes to left child + 1 "
                    "(dmlc/xgboost#7903), so the model does not predict what "
                    "the file says",
                    "%s node %d: left child %d, right child %d"
                    % (here, i, left, right), key=("XGB006", "right"))
        for child in (left, right):
            if 0 <= child < n and parents[child] & _MASK31 != i:
                out.add("XGB006", "a child's parent entry names a different "
                        "node", "%s node %d: child %d has parent %d"
                        % (here, i, child, parents[child]),
                        key=("XGB006", "parent-back"))
        if splits[i] < 0 or (num_feature is not None
                             and splits[i] >= num_feature):
            out.add("XGB002", "a split reads a feature index the model does "
                    "not have",
                    "%s node %d: feature %d, model has %s features"
                    % (here, i, splits[i], num_feature),
                    key=("XGB002", "feature"))
        children[i] = sorted(set(c for c in (left, left + 1, right)
                                 if 0 <= c < n))

    for i in range(1, n):
        if parents[i] & _MASK31 >= n:
            out.add("XGB001", "a node's parent is outside the tree; XGBoost's "
                    "loader reads that parent while setting up the tree",
                    "%s node %d: parent %d, tree has %d nodes"
                    % (here, i, parents[i], n), key=("XGB001", "parent"))

    loop = _find_loop(children, n)
    if loop is not None:
        out.add("XGB003", "the tree loops: a node leads back to one of its "
                "own ancestors, so walking it from the root never ends",
                "%s: node %d leads back to node %d" % (here, loop[0], loop[1]),
                key=("XGB003", "loop"))

    _check_categories(tree, n, here, out)


def _check_model(doc, where, out):
    learner = doc.get("learner") if isinstance(doc, dict) else None
    if not isinstance(learner, dict):
        out.add("XGB007", "no learner object; not an XGBoost model", where)
        return
    lmp = learner.get("learner_model_param")
    lmp = lmp if isinstance(lmp, dict) else {}
    num_feature = _int(lmp.get("num_feature"))
    num_class = _int(lmp.get("num_class")) or 0
    num_target = _int(lmp.get("num_target")) or 1
    booster = learner.get("gradient_booster")
    if not isinstance(booster, dict):
        out.add("XGB007", "no gradient_booster object; not an XGBoost model",
                where)
        return
    name = booster.get("name")
    if name == "gblinear":
        return
    model = booster.get("model")
    if name == "dart" and isinstance(booster.get("gbtree"), dict):
        model = booster["gbtree"].get("model")
    trees = model.get("trees") if isinstance(model, dict) else None
    if not isinstance(trees, list):
        out.add("XGB007", "no gradient_booster model trees list; not a tree "
                "model this scanner can check",
                "%s: booster %s" % (where, _ascii(name, 40)))
        return
    if num_feature is None:
        out.add("XGB007", "learner_model_param.num_feature is missing; split "
                "feature indices are checked per tree only", where)
    param = model.get("gbtree_model_param")
    param = param if isinstance(param, dict) else {}
    num_trees = _int(param.get("num_trees"))
    if num_trees is not None and num_trees != len(trees):
        out.add("XGB007", "num_trees does not match the trees list; XGBoost "
                "refuses to load this model",
                "%s: num_trees %d, %d trees" % (where, num_trees, len(trees)))
    info = model.get("tree_info")
    if isinstance(info, list):
        groups = max(num_class, num_target, 1)
        if len(info) != len(trees):
            out.add("XGB007", "tree_info does not have one entry per tree; "
                    "XGBoost refuses to load this model",
                    "%s: %d entries, %d trees" % (where, len(info), len(trees)))
        for t, group in enumerate(info):
            number = _int(group)
            if number is None or not 0 <= number < groups:
                out.add("XGB006", "tree_info names an output group the model "
                        "does not have",
                        "%s: tree %d, group %s of %d"
                        % (where, t, _ascii(group, 40), groups),
                        key=("XGB006", "tree-info"))
    for t, tree in enumerate(trees):
        per_tree = num_feature
        if per_tree is None and isinstance(tree, dict):
            tree_param = tree.get("tree_param")
            if isinstance(tree_param, dict):
                per_tree = _int(tree_param.get("num_feature"))
        _check_tree(tree, t, per_tree, where, out)


def _report_dups(dups, out):
    for key in dups:
        out.add("XGB004", "an object repeats a key; XGBoost's writer never "
                "does, so the file was edited after XGBoost saved it",
                "key %s" % _ascii(key, 80), key=("XGB004", key))


# -- entry points -------------------------------------------------------------

def _scan_ubj(data, where, out):
    dups = []
    try:
        doc = _UBJ(data, dups).value()
    except _Overrun as exc:
        out.add("XGB005", "a UBJSON string length or array count runs past "
                "the end of the file", "%s: %s" % (where, _ascii(exc)))
        return
    except _Bad as exc:
        out.add("XGB007", "not decodable as XGBoost UBJSON",
                "%s: %s" % (where, _ascii(exc)))
        return
    _report_dups(dups, out)
    _check_model(doc, where + " (UBJSON)", out)


def _scan_json(data, where, out):
    dups = []

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                dups.append(key)
            obj[key] = value
        return obj

    try:
        doc = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        out.add("XGB007", "not valid JSON", "%s: %s"
                % (where, _ascii(type(exc).__name__ + ": " + str(exc), 200)))
        return
    _report_dups(dups, out)
    _check_model(doc, where + " (JSON)", out)


def _scan_blob(data, where, out):
    head = bytes(data[:2])
    if head[:1] == b"{" and head[1:2] in (b"L", b"}"):
        _scan_ubj(data, where, out)
    elif bytes(data[:64]).lstrip()[:1] == b"{":
        _scan_json(data, where, out)
    elif head[:1] == b"\x80":
        out.add("XGB007", "a pickle, not an XGBoost JSON or UBJSON model; "
                "scan it with a pickle scanner", where)
    elif bytes(data[:4]) == b"binf":
        out.add("XGB007", "legacy binary XGBoost model; its trees are not "
                "checked (re-save the model as .json or .ubj)", where)
    else:
        out.add("XGB007", "not an XGBoost JSON or UBJSON model", where)


def _guard(out, func, *args):
    """Run func(*args, out), turning a checker crash into an XGB007 finding."""
    try:
        func(*args, out)
    except OSError:
        raise
    except Exception as exc:  # hostile input must never crash the scan
        out.add("XGB007", "the model could not be checked; findings before "
                "this point are kept",
                "%s: %s" % (type(exc).__name__, _ascii(exc)))


def scan_bytes(data, name=""):
    """Scan an in-memory XGBoost JSON or UBJSON model. Returns findings."""
    out = _Findings()
    _guard(out, _scan_blob, data, name or "model")
    return out.result()


def scan_file(path):
    """Scan an XGBoost .json, .ubj, .bst or .model file."""
    with open(path, "rb") as handle:
        data = handle.read()
    out = _Findings()
    _guard(out, _scan_blob, data, os.path.basename(path))
    return out.result()


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python xgboost_model_scan.py MODEL.json|MODEL.ubj [...]",
              file=sys.stderr)
        return 2
    failed = high = False
    for path in args:
        try:
            findings = scan_file(path)
        except OSError as exc:
            print("%s: cannot read: %s" % (path, exc), file=sys.stderr)
            failed = True
            continue
        if not findings:
            print("%s: no findings" % path)
        for item in findings:
            print("%s: %s %s: %s [%s]" % (path, item["rule"], item["severity"],
                                          item["message"], item["evidence"]))
            high = high or item["severity"] == "high"
    if failed:
        return 2
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
