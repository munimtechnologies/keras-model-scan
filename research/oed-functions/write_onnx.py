#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Write the ONNX files for the pre-registered check (run in a child process).

Honest files come from onnx's own writer (onnx.save_model). Planted copies are
made by editing one external_data entry of a proto that was read with
load_external_data=False and writing SerializeToString() bytes directly, so
no planted location is ever opened, written or loaded by onnx. Only the
honest function model is loaded with external data (row L1).

Usage: write_onnx.py WORKDIR   (writes WORKDIR/*/model.onnx and
WORKDIR/writer_report.json; always exits 0)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import copy
import json
import os
import sys
import traceback

BIG_N = 272_000_000          # > 256 MiB (268,435,456) and far below 2 GiB
OLD_CAP = 256 * 1024 * 1024


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _ext(tensor):
    return {e.key: e.value for e in tensor.external_data}


def _set_loc(tensor, value):
    for e in tensor.external_data:
        if e.key == "location":
            e.value = value
            return True
    return False


def build(work, rep):
    import numpy as np
    import onnx
    from onnx import AttributeProto, TensorProto, helper, numpy_helper

    rep["onnx"] = onnx.__version__
    os.chdir(work)  # convert_model_to_external_data checks paths vs. cwd

    values = np.arange(1024, dtype=np.float32)          # 4096 bytes
    const = numpy_helper.from_array(values, name="fconst")
    f_const = helper.make_node("Constant", [], ["c"], value=const)
    f_add = helper.make_node("Add", ["x", "c"], ["y"])
    func = helper.make_function(
        "local.mv2", "AddConst", ["x"], ["y"], [f_const, f_add],
        opset_imports=[helper.make_opsetid("", 18)])
    w = numpy_helper.from_array(np.ones(1024, dtype=np.float32), name="W")
    call = helper.make_node("AddConst", ["X"], ["Y"], domain="local.mv2")
    add2 = helper.make_node("Add", ["Y", "W"], ["Z"])
    graph = helper.make_graph(
        [call, add2], "g",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1024])],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1024])],
        initializer=[w])
    model = helper.make_model(
        graph, functions=[func],
        opset_imports=[helper.make_opsetid("", 18),
                       helper.make_opsetid("local.mv2", 1)])
    onnx.checker.check_model(model)
    rep["checker_ok"] = True

    plain_graph = helper.make_graph(
        [helper.make_node("Add", ["X", "W"], ["Z"])], "g",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1024])],
        [helper.make_tensor_value_info("Z", TensorProto.FLOAT, [1024])],
        initializer=[numpy_helper.from_array(np.ones(1024, np.float32),
                                             name="W")])
    plain = helper.make_model(plain_graph,
                              opset_imports=[helper.make_opsetid("", 18)])

    # honest files, written by onnx's own writer
    hf = os.path.join(work, "honest_func", "model.onnx")
    os.makedirs(os.path.dirname(hf), exist_ok=True)
    onnx.save_model(model, hf, save_as_external_data=True,
                    all_tensors_to_one_file=True, location="weights.bin",
                    size_threshold=1024, convert_attribute=True)
    hp = os.path.join(work, "honest_plain", "model.onnx")
    os.makedirs(os.path.dirname(hp), exist_ok=True)
    onnx.save_model(plain, hp, save_as_external_data=True,
                    all_tensors_to_one_file=True, location="weights.bin",
                    size_threshold=1024)

    # W1: what the writer stored for the function tensor
    m = onnx.load(hf, load_external_data=False)
    ft = m.functions[0].node[0].attribute[0].t
    wt = m.graph.initializer[0]
    rep["W1"] = {"func_tensor_name": ft.name,
                 "func_data_location": int(ft.data_location),
                 "func_external": _ext(ft),
                 "func_has_raw_data": ft.HasField("raw_data"),
                 "init_external": _ext(wt),
                 "weights_bin_bytes": os.path.getsize(
                     os.path.join(os.path.dirname(hf), "weights.bin"))}

    # L1: onnx's loader fills the function tensor from weights.bin (honest)
    loaded = onnx.load(hf)
    lt = loaded.functions[0].node[0].attribute[0].t
    arr = numpy_helper.to_array(lt)
    rep["L1"] = {"raw_data_bytes": len(lt.raw_data),
                 "equal_to_written": bool(arr.shape == values.shape
                                          and (arr == values).all()),
                 "data_location_after_load": int(lt.data_location)}

    # honest training_info (inline initializer only)
    ht = copy.deepcopy(m)
    ti = ht.training_info.add()
    ti.initialization.CopyFrom(helper.make_graph(
        [], "init", [], [],
        initializer=[numpy_helper.from_array(np.zeros(4, np.float32),
                                             name="T0")]))
    _write(os.path.join(work, "honest_train", "model.onnx"),
           ht.SerializeToString())

    # planted copies (bytes only; never loaded)
    e1 = copy.deepcopy(m)
    ok1 = _set_loc(e1.functions[0].node[0].attribute[0].t, "../outside.bin")
    _write(os.path.join(work, "e1_func_parent", "model.onnx"),
           e1.SerializeToString())

    k1 = copy.deepcopy(m)
    entry = k1.functions[0].node[0].attribute[0].t.external_data.add()
    entry.key, entry.value = "owner", "x"
    _write(os.path.join(work, "k1_func_key", "model.onnx"),
           k1.SerializeToString())

    e2 = copy.deepcopy(m)
    attr = AttributeProto()
    attr.name = "bias"
    attr.type = AttributeProto.TENSOR
    attr.t.name = "d"
    attr.t.data_type = TensorProto.FLOAT
    attr.t.dims.append(4)
    attr.t.data_location = TensorProto.EXTERNAL
    loc = attr.t.external_data.add()
    loc.key, loc.value = "location", "/abs/w.bin"
    e2.functions[0].attribute_proto.append(attr)
    _write(os.path.join(work, "e2_func_attrproto_abs", "model.onnx"),
           e2.SerializeToString())

    p = onnx.load(hp, load_external_data=False)
    e3 = copy.deepcopy(p)
    ti3 = e3.training_info.add()
    t3 = ti3.initialization.initializer.add()
    t3.name = "T1"
    t3.data_type = TensorProto.FLOAT
    t3.dims.append(4)
    t3.data_location = TensorProto.EXTERNAL
    l3 = t3.external_data.add()
    l3.key, l3.value = "location", "..\\t.bin"
    _write(os.path.join(work, "e3_train_backslash", "model.onnx"),
           e3.SerializeToString())

    c1 = copy.deepcopy(p)
    okc = _set_loc(c1.graph.initializer[0], "../g.bin")
    _write(os.path.join(work, "c1_graph_parent", "model.onnx"),
           c1.SerializeToString())
    rep["planted_set"] = {"e1": ok1, "c1": okc}

    # E4 / H4: one big inline initializer, then a small external tensor
    big = onnx.ModelProto()
    big.ir_version = 10
    big.producer_name = "mv2-oed-check"
    op = big.opset_import.add()
    op.domain, op.version = "", 18
    big.graph.name = "big"
    t0 = big.graph.initializer.add()
    t0.name = "big"
    t0.data_type = TensorProto.UINT8
    t0.dims.append(BIG_N)
    t0.raw_data = b"\x00" * BIG_N
    t1 = big.graph.initializer.add()
    t1.name = "tail"
    t1.data_type = TensorProto.FLOAT
    t1.dims.append(4)
    t1.data_location = TensorProto.EXTERNAL
    l4 = t1.external_data.add()
    l4.key, l4.value = "location", "../after.bin"
    data = big.SerializeToString()
    rep["E4_pre"] = {"file_bytes": len(data),
                     "location_offset": data.rfind(b"../after.bin"),
                     "old_cap": OLD_CAP}
    _write(os.path.join(work, "e4_big_after_cap", "model.onnx"), data)
    del data
    l4.value = "after.bin"
    data = big.SerializeToString()
    rep["H4_pre"] = {"file_bytes": len(data),
                     "location_offset": data.rfind(b"after.bin")}
    _write(os.path.join(work, "h4_big_honest", "model.onnx"), data)
    del data, big, t0


def main():
    work = os.path.abspath(sys.argv[1])
    os.makedirs(work, exist_ok=True)
    rep = {"ok": False}
    try:
        build(work, rep)
        rep["ok"] = True
    except Exception as exc:
        rep["error"] = "%s: %s" % (type(exc).__name__, exc)
        rep["traceback"] = traceback.format_exc()[-3000:]
    with open(os.path.join(work, "writer_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({k: v for k, v in rep.items() if k != "traceback"},
                     indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
