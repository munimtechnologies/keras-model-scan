#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""lightgbm_model_scan - static validity checks for LightGBM text models.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

LightGBM saves a model as text (``Booster.save_model``, ``model.txt``): a
header (``max_feature_idx``, ``feature_names``, ``tree_sizes`` ...), then one
``Tree=`` block per tree with ``num_leaves``, ``split_feature``,
``left_child``, ``right_child``, ``decision_type``, ``threshold`` and, for
categorical splits, ``cat_boundaries`` and ``cat_threshold``.

LightGBM's loader (src/io/tree.cpp and src/boosting/gbdt_model_text.cpp, read
31 October 2026, release 4.7.0) checks that required keys are present and
the length of some arrays. It uses the index values as written: a child, a
split's feature, a categorical split's category set and the tree_sizes
offsets are not range-checked (lightgbm-org/LightGBM#7357, #7438; fix PR #7366
open). A CI gate can check them before a model reaches a loader:

- LGB001 high   CWE-125  An index points outside its tree or array: a child
                         node or leaf, a categorical split's category set, or
                         a cat_boundaries entry outside cat_threshold.
- LGB002 high   CWE-125  A split or a linear leaf reads a feature index the
                         model does not have (negative or > max_feature_idx).
- LGB003 high   CWE-835  A tree loops: a node leads back to one of its own
                         ancestors (the root included), so prediction never
                         reaches a leaf.
- LGB004 high   CWE-125  The loader would read past the end of the file:
                         a tree_sizes offset outside the file, or a tree whose
                         text ends without the blank line that closes it.
- LGB005 high   CWE-20   The header or a tree repeats a key. LightGBM's writer
                         never does.
- LGB006 medium CWE-20   Model data LightGBM's writer does not produce: an
                         index array with the wrong number of values (the
                         loader pads with 0 or drops the rest), a tree that is
                         not a binary tree, unknown decision_type bits, a
                         categorical split with num_cat 0, cat_boundaries out
                         of order, tree_sizes that do not match the trees, a
                         tree count that is not whole iterations, and others.
- LGB007 medium CWE-693  Not checked: not a LightGBM text model (pickle, JSON
                         dump, other), data LightGBM itself refuses, values
                         that are not numbers, or findings capped.

Static review only: nothing is loaded or executed, and lightgbm is not needed.
"""

import os
import re
import sys

__version__ = "0.1.0"

MAX_FINDINGS = 1000
MAX_LEAVES = 131072      # LightGBM's own upper limit for num_leaves
MAX_TREE_LINES = 22      # Tree::Tree(const char*, size_t*) reads at most 22
MAX_PAD = 1 << 22        # largest array rebuilt the way the loader pads it

_RULES = {
    "LGB001": ("high", "CWE-125"),
    "LGB002": ("high", "CWE-125"),
    "LGB003": ("high", "CWE-835"),
    "LGB004": ("high", "CWE-125"),
    "LGB005": ("high", "CWE-20"),
    "LGB006": ("medium", "CWE-20"),
    "LGB007": ("medium", "CWE-693"),
}

_HEADER_REQUIRED = ("num_class", "label_index", "max_feature_idx",
                    "feature_names", "feature_infos")

_EOL = re.compile(r"[\r\n]")
_INT = re.compile(r"[+-]?[0-9]+\Z")


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
            severity, cwe = _RULES["LGB007"]
            self.items.append({
                "rule": "LGB007", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


# -- reading the text the way LightGBM's loader does --------------------------

def _line(text, pos):
    """Return (line, next_pos, ended): the line at pos without its line break,
    where the next line starts, and whether a line break ended it."""
    match = _EOL.search(text, pos)
    if match is None:
        return text[pos:], len(text), False
    end = match.start()
    nxt = end + 1
    if text[end] == "\r" and text[nxt:nxt + 1] == "\n":
        nxt += 1
    return text[pos:end], nxt, True


def _read_header(text):
    """Header key=value lines up to the first 'Tree=' line. Returns
    (values, repeated keys, position of the first 'Tree=' line or None)."""
    values = {}
    dups = []
    pos = 0
    while pos < len(text):
        start = pos
        line, pos, _ = _line(text, pos)
        if line.startswith("Tree="):
            return values, dups, start
        if line == "end of trees":
            break
        if not line:
            continue
        key, _, value = line.partition("=")
        if key in values:
            dups.append(key)
        values[key] = value
    return values, dups, None


def _read_tree(text, pos):
    """Read the tree whose 'Tree=' line starts at pos, as
    Tree::Tree(const char*, size_t*) does: at most 22 key=value lines, up to
    the first blank line. Returns (tree, position after it)."""
    label, pos, ended = _line(text, pos)
    tree = {"label": label[5:], "values": {}, "dups": [], "no_eq": 0,
            "runs_off": not ended, "extra": False}
    read = 0
    while read < MAX_TREE_LINES and not tree["runs_off"]:
        if pos >= len(text):
            tree["runs_off"] = True
            break
        if text[pos] in "\r\n":
            break
        line, pos, ended = _line(text, pos)
        read += 1
        if not ended:
            tree["runs_off"] = True
        if "=" not in line:
            tree["no_eq"] += 1
            continue
        key, value = line.split("=", 1)
        if key in tree["values"]:
            tree["dups"].append(key)
        tree["values"][key] = value
    if (read == MAX_TREE_LINES and pos < len(text)
            and text[pos] not in "\r\n"):
        tree["extra"] = True
    return tree, pos


def _sequential(text, first):
    """The trees a reader finds by walking 'Tree=' blocks from the first one
    (the loader's path when there is no tree_sizes line)."""
    found = []
    pos = first
    while pos < len(text):
        start = pos
        line, nxt, _ = _line(text, pos)
        if not line:
            pos = nxt
            continue
        if not line.startswith("Tree="):
            break
        tree, pos = _read_tree(text, start)
        found.append((start, tree))
    return found


def _int(value):
    if value is None:
        return None
    value = value.strip()
    return int(value) if _INT.match(value) else None


def _ints(tokens):
    out = []
    for token in tokens:
        if not _INT.match(token):
            return None
        out.append(int(token))
    return out


def _floats(tokens):
    try:
        return [float(token) for token in tokens]
    except ValueError:
        return None


def _fast(text, n, name, here, out):
    """Read n integers the way StringToArrayFast does: missing values become
    0 and extra ones are ignored. None if a value is not an integer."""
    values = _ints(text.split())
    if values is None:
        out.add("LGB007", "an index array holds values that are not integers; "
                "the tree was not checked", "%s: %s" % (here, name),
                key=("LGB007", "not-int"))
        return None
    if len(values) != n:
        out.add("LGB006", "an index array does not have the number of values "
                "LightGBM reads; the loader reads exactly that many, using 0 "
                "for missing values and ignoring extra ones",
                "%s: %s has %d values, LightGBM reads %d"
                % (here, name, len(values), n), key=("LGB006", "count"))
    return (values + [0] * n)[:n]


# -- checks -------------------------------------------------------------------

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


def _check_nodes(lefts, rights, leaves, here, out):
    nodes = leaves - 1
    if nodes < 1:
        return
    node_refs = [0] * nodes
    leaf_refs = [0] * leaves
    children = [[] for _ in range(nodes)]
    bad = False
    for i in range(nodes):
        for side, child in (("left", lefts[i]), ("right", rights[i])):
            if child < 0:
                leaf = ~child
                if leaf >= leaves:
                    bad = True
                    out.add("LGB001", "a child names a leaf the tree does not "
                            "have",
                            "%s node %d: %s child %d is leaf %d, tree has %d "
                            "leaves" % (here, i, side, child, leaf, leaves),
                            key=("LGB001", "leaf"))
                else:
                    leaf_refs[leaf] += 1
            elif child >= nodes:
                bad = True
                out.add("LGB001", "a child names a split node outside the "
                        "tree",
                        "%s node %d: %s child %d, tree has %d split nodes"
                        % (here, i, side, child, nodes),
                        key=("LGB001", "node"))
            else:
                node_refs[child] += 1
                children[i].append(child)
    loop = _find_loop(children, nodes)
    if loop is not None:
        bad = True
        out.add("LGB003", "the tree loops: a node leads back to one of its own "
                "ancestors, so prediction never reaches a leaf",
                "%s: node %d leads back to node %d" % (here, loop[0], loop[1]),
                key=("LGB003", "loop"))
    if bad:
        return
    odd = [("node", k, c) for k, c in enumerate(node_refs)
           if c != (0 if k == 0 else 1)]
    odd += [("leaf", k, c) for k, c in enumerate(leaf_refs) if c != 1]
    if odd:
        kind, k, count = odd[0]
        out.add("LGB006", "the tree is not the binary tree LightGBM's writer "
                "produces, where every split node but the root and every leaf "
                "is the child of exactly one node",
                "%s: %s %d is a child %d times" % (here, kind, k, count),
                key=("LGB006", "shape"))


def _check_decisions(kinds, tokens, cats, here, out):
    thresholds = None
    for i, kind in enumerate(kinds):
        if not 0 <= kind <= 15 or (kind >> 2) & 3 == 3:
            out.add("LGB006", "decision_type has bits LightGBM's writer does "
                    "not set", "%s node %d: decision_type %d" % (here, i, kind),
                    key=("LGB006", "decision-bits"))
        if not kind & 1:
            continue
        if cats <= 0:
            out.add("LGB006", "a split is marked categorical but num_cat is "
                    "not positive; LightGBM's predictor then reads its "
                    "category set number as a numeric threshold",
                    "%s node %d: num_cat %d" % (here, i, cats),
                    key=("LGB006", "cat-flag"))
            continue
        if thresholds is None:
            thresholds = _floats(tokens)
            if thresholds is None:
                out.add("LGB007", "threshold holds values that are not "
                        "numbers; categorical splits were not checked", here,
                        key=("LGB007", "threshold-type"))
                return
        value = thresholds[i]
        if (value != value or abs(value) >= 2 ** 31
                or not 0 <= int(value) < cats):
            out.add("LGB001", "a categorical split names a category set the "
                    "tree does not have",
                    "%s node %d: set %s, num_cat is %d"
                    % (here, i, _ascii(tokens[i], 40), cats),
                    key=("LGB001", "cat-set"))


def _check_cat_arrays(values, cats, nodes, here, out):
    if cats < 0 or cats > nodes:
        out.add("LGB006", "num_cat is negative or larger than the number of "
                "splits; LightGBM's writer adds one category set per "
                "categorical split",
                "%s: num_cat %d, %d splits" % (here, cats, nodes),
                key=("LGB006", "num-cat"))
        return
    if cats == 0:
        return
    if "cat_boundaries" not in values or "cat_threshold" not in values:
        out.add("LGB007", "a tree with num_cat > 0 lacks cat_boundaries or "
                "cat_threshold; LightGBM refuses it", here,
                key=("LGB007", "cat-missing"))
        return
    bounds = _fast(values["cat_boundaries"], cats + 1, "cat_boundaries",
                   here, out)
    if bounds is None:
        return
    last = bounds[-1]
    bad = [b for b in bounds if b < 0] or [b for b in bounds if b > last]
    if bad:
        out.add("LGB001", "cat_boundaries points outside cat_threshold, which "
                "LightGBM sizes from its last entry",
                "%s: cat_boundaries entry %d, cat_threshold has %d words"
                % (here, bad[0], max(last, 0)), key=("LGB001", "cat-bounds"))
        return
    if bounds[0] != 0 or any(b < a for a, b in zip(bounds, bounds[1:])):
        out.add("LGB006", "cat_boundaries does not start at 0 and rise; "
                "LightGBM's writer always writes it that way",
                "%s: cat_boundaries %s" % (here, _ascii(values["cat_boundaries"],
                                                        80)),
                key=("LGB006", "cat-order"))
    if last > MAX_PAD:
        out.add("LGB007", "cat_threshold is too large to check",
                "%s: %d words" % (here, last), key=("LGB007", "cat-size"))
        return
    words = _fast(values["cat_threshold"], last, "cat_threshold", here, out)
    if words is not None and any(not 0 <= w < 2 ** 32 for w in words):
        out.add("LGB006", "a cat_threshold word is not a 32-bit unsigned "
                "value", here, key=("LGB006", "cat-word"))


def _check_linear(values, leaves, max_feature, here, out):
    if "num_features" not in values:
        return
    counts = _fast(values["num_features"], leaves, "num_features", here, out)
    if counts is None:
        return
    if any(c < 0 for c in counts):
        out.add("LGB006", "a linear leaf has a negative feature count", here,
                key=("LGB006", "linear-count"))
        return
    total = sum(counts)
    if total > MAX_PAD:
        out.add("LGB007", "the linear leaves name too many features to check",
                "%s: %d" % (here, total), key=("LGB007", "linear-size"))
        return
    features = _fast(values.get("leaf_features", ""), total, "leaf_features",
                     here, out)
    if features is None:
        return
    bad = [f for f in features
           if f < 0 or (max_feature is not None and f > max_feature)]
    if bad:
        out.add("LGB002", "a linear leaf reads a feature index the model does "
                "not have",
                "%s: leaf feature %d, max_feature_idx is %s"
                % (here, bad[0], max_feature), key=("LGB002", "linear"))


def _check_tree(tree, max_feature, where, out):
    here = "%s tree %s" % (where, _ascii(tree["label"], 20))
    values = tree["values"]
    for key in tree["dups"]:
        out.add("LGB005", "a tree repeats a key; LightGBM's writer never does, "
                "so the file was edited after it was saved",
                "%s: key %s" % (here, _ascii(key, 80)),
                key=("LGB005", "tree", key))
    if tree["runs_off"]:
        out.add("LGB004", "a tree's text ends without the blank line that "
                "closes it; LightGBM's tree reader looks for '=' and line "
                "breaks without checking for the end of the text",
                here, key=("LGB004", "runs-off"))
    if tree["no_eq"]:
        out.add("LGB006", "a tree line has no '='; LightGBM's writer never "
                "writes one", here, key=("LGB006", "no-eq"))
    if tree["extra"]:
        out.add("LGB006", "a tree has more than 22 lines before its blank "
                "line; LightGBM reads only the first 22", here,
                key=("LGB006", "extra-lines"))
    leaves = _int(values.get("num_leaves"))
    cats = _int(values.get("num_cat"))
    if leaves is None or cats is None or "leaf_value" not in values:
        out.add("LGB007", "a tree lacks an integer num_leaves or num_cat, or "
                "leaf_value; LightGBM refuses it or the tree was not checked",
                here, key=("LGB007", "tree-keys"))
        return
    linear = bool(_int(values.get("is_linear", "0")))
    if not 1 <= leaves <= MAX_LEAVES:
        out.add("LGB006", "num_leaves is outside 1..%d, the range LightGBM "
                "itself allows; the tree was not checked further" % MAX_LEAVES,
                "%s: num_leaves %d" % (here, leaves),
                key=("LGB006", "num-leaves"))
        return
    if len(values["leaf_value"].split()) != leaves:
        out.add("LGB007", "leaf_value does not have num_leaves values; "
                "LightGBM refuses this tree", here,
                key=("LGB007", "leaf-count"))
        return
    if leaves == 1 and not linear:
        return
    nodes = leaves - 1
    missing = [k for k in ("left_child", "right_child", "split_feature",
                           "threshold") if k not in values]
    tokens = values.get("threshold", "").split()
    if (missing or (nodes and len(tokens) != nodes)
            or ("leaf_weight" in values
                and len(values["leaf_weight"].split()) != leaves)):
        out.add("LGB007", "a tree lacks a required array, or threshold or "
                "leaf_weight has the wrong number of values; LightGBM refuses "
                "this tree", "%s: %s" % (here, ", ".join(missing) or "counts"),
                key=("LGB007", "tree-arrays"))
        return
    lefts = _fast(values["left_child"], nodes, "left_child", here, out)
    rights = _fast(values["right_child"], nodes, "right_child", here, out)
    features = _fast(values["split_feature"], nodes, "split_feature", here,
                     out)
    kinds = ([0] * nodes if "decision_type" not in values else
             _fast(values["decision_type"], nodes, "decision_type", here, out))
    if lefts is None or rights is None or features is None or kinds is None:
        return
    _check_nodes(lefts, rights, leaves, here, out)
    for i, feature in enumerate(features):
        if feature < 0 or (max_feature is not None and feature > max_feature):
            out.add("LGB002", "a split reads a feature index the model does "
                    "not have",
                    "%s node %d: feature %d, max_feature_idx is %s"
                    % (here, i, feature, max_feature),
                    key=("LGB002", "split"))
    _check_decisions(kinds, tokens, cats, here, out)
    if cats != 0:
        _check_cat_arrays(values, cats, nodes, here, out)
    if linear:
        _check_linear(values, leaves, max_feature, here, out)


def _check_header(header, where, out):
    missing = [k for k in _HEADER_REQUIRED if k not in header]
    for key in missing:
        out.add("LGB007", "the header lacks a key LightGBM requires; it "
                "refuses this model", "%s: %s" % (where, key),
                key=("LGB007", "header-missing"))
    max_feature = _int(header.get("max_feature_idx"))
    if "max_feature_idx" in header and max_feature is None:
        out.add("LGB007", "max_feature_idx is not an integer; feature indices "
                "were not checked against it", where)
    if max_feature is not None:
        if max_feature < 0:
            out.add("LGB006", "max_feature_idx is negative",
                    "%s: %d" % (where, max_feature))
        for key in ("feature_names", "feature_infos"):
            if key in header and len(header[key].split()) != max_feature + 1:
                out.add("LGB007", "%s does not have max_feature_idx + 1 "
                        "entries; LightGBM refuses this model" % key,
                        "%s: %d entries, max_feature_idx %d"
                        % (where, len(header[key].split()), max_feature))
    per_iteration = _int(header.get("num_tree_per_iteration",
                                    header.get("num_class")))
    return max_feature, per_iteration


def _check_tree_sizes(text, first, sizes_text, trees, where, out):
    """Check where tree_sizes makes the loader look for each tree. Trees found
    there that the sequential walk missed are added to trees. Returns how
    many trees the loader reads, or None."""
    sizes = _ints(sizes_text.split())
    if sizes is None:
        out.add("LGB007", "tree_sizes holds values that are not integers; it "
                "was not checked", where)
        return None
    walked = len(trees)
    base = len(text) if first is None else first
    offset = 0
    for i, size in enumerate(sizes):
        pos = base + offset
        offset += size
        if not 0 <= pos < len(text):
            out.add("LGB004", "tree_sizes places a tree outside the file; "
                    "LightGBM's loader reads there without checking the file "
                    "length",
                    "%s: tree %d at byte %d of %d" % (where, i, pos, len(text)),
                    key=("LGB004", "tree-sizes"))
        elif pos in trees:
            continue
        elif text.startswith("Tree=", pos):
            out.add("LGB006", "tree_sizes places a tree where the file's own "
                    "sequence of trees has none; LightGBM's writer always "
                    "writes tree_sizes to match, and the loader uses "
                    "tree_sizes",
                    "%s: tree %d at byte %d" % (where, i, pos),
                    key=("LGB006", "tree-sizes"))
            trees[pos] = _read_tree(text, pos)[0]
        else:
            out.add("LGB007", "tree_sizes does not land on a 'Tree=' line; "
                    "LightGBM refuses this model",
                    "%s: tree %d at byte %d" % (where, i, pos),
                    key=("LGB007", "tree-sizes"))
    if len(sizes) != walked:
        out.add("LGB006", "tree_sizes lists a different number of trees than "
                "the file has", "%s: %d sizes, %d trees"
                % (where, len(sizes), walked))
    return len(sizes)


def _scan_text(data, where, out):
    text = bytes(data).decode("latin-1")
    header, dups, first = _read_header(text)
    for key in dups:
        out.add("LGB005", "the header repeats a key; LightGBM's writer never "
                "does, so the file was edited after it was saved",
                "%s: key %s" % (where, _ascii(key, 80)),
                key=("LGB005", "header", key))
    max_feature, per_iteration = _check_header(header, where, out)
    trees = {}
    if first is not None:
        for start, tree in _sequential(text, first):
            trees[start] = tree
    loaded = len(trees)
    if "tree_sizes" in header:
        loaded = _check_tree_sizes(text, first, header["tree_sizes"], trees,
                                   where, out)
    for start in sorted(trees):
        _check_tree(trees[start], max_feature, where, out)
    if per_iteration is not None and per_iteration < 1:
        out.add("LGB006", "num_tree_per_iteration is not positive; LightGBM's "
                "loader divides by it", "%s: %d" % (where, per_iteration))
    elif (per_iteration is not None and loaded is not None
          and loaded % per_iteration):
        out.add("LGB006", "the number of trees is not a whole number of "
                "iterations; LightGBM's writer saves whole iterations",
                "%s: %d trees, %d per iteration"
                % (where, loaded, per_iteration))


def _scan_blob(data, where, out):
    head = bytes(data[:64])
    if head.split(b"\n", 1)[0].rstrip(b"\r") == b"tree":
        _scan_text(data, where, out)
    elif head[:1] == b"\x80":
        out.add("LGB007", "a pickle, not a LightGBM text model; scan it with a "
                "pickle scanner", where)
    elif head.lstrip()[:1] in (b"{", b"["):
        out.add("LGB007", "JSON, not a LightGBM text model; LightGBM cannot "
                "load its JSON dump (dump_model) as a model, so it is not "
                "checked", where)
    else:
        out.add("LGB007", "not a LightGBM text model (it does not start with "
                "a 'tree' line)", where)


def _guard(out, func, *args):
    """Run func(*args, out), turning a checker crash into an LGB007 finding."""
    try:
        func(*args, out)
    except OSError:
        raise
    except Exception as exc:  # hostile input must never crash the scan
        out.add("LGB007", "the model could not be checked; findings before "
                "this point are kept",
                "%s: %s" % (type(exc).__name__, _ascii(exc)))


def scan_bytes(data, name=""):
    """Scan an in-memory LightGBM text model. Returns findings."""
    out = _Findings()
    _guard(out, _scan_blob, data, name or "model")
    return out.result()


def scan_file(path):
    """Scan a LightGBM text model file (model.txt and similar)."""
    with open(path, "rb") as handle:
        data = handle.read()
    out = _Findings()
    _guard(out, _scan_blob, data, os.path.basename(path))
    return out.result()


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python lightgbm_model_scan.py MODEL.txt [...]",
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
