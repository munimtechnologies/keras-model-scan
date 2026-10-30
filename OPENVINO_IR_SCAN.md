# openvino_ir_scan

Static scanner for **OpenVINO IR** model files (`.xml` graph + `.bin`
weights). Part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan)
toolkit. Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.

```bash
python openvino_ir_scan.py model.xml
```

It exits `1` on any high finding (so it can gate CI), `2` on a usage error or
an unreadable file, and `0` when clean or only medium findings remain. It uses
**only the Python standard library** — no `openvino`, no `defusedxml`.

## Why

An OpenVINO IR model is a pair of files. The `.xml` describes the graph; each
`Const` layer has a `<data offset="..." size="..." element_type="..."
shape="...">` child that names a byte range inside the sibling `.bin`, which the
runtime maps as that constant's tensor. The runtime reads the IR with
`XmlDeserializer`
(`src/core/xml_util/src/xml_deserialize_util.cpp`). Two details of its
`Const` path are worth a static gate:

1. **The string-tensor branch skips the bounds check.** For a normal `Const`,
   `set_constant_num_buffer` validates the range with
   `is_valid_weights_range(weights_size, offset, size)` before
   `make_region(offset, size)`. But the `element::string` branch calls
   `make_region(offset, size)` **without** that check, so a string `Const`
   whose range runs past the end of the `.bin` is read unchecked.
2. **The size/shape check multiplies in 64-bit arithmetic.** The consistency
   check is `size < ((shape_size(shape) * bitwidth + 7) >> 3)`. When the element
   count times the bitwidth overflows a 64-bit `size_t`, the required byte count
   wraps small and a far-too-small `size` passes — the overflow class addressed
   in openvino PR #39082.

This scanner recomputes both the way the runtime does and reports them from the
`.xml` alone, using the `.bin` only by its length.

## Rules

| rule | severity | CWE | what it means |
|------|----------|-----|---------------|
| OVI001 | high | CWE-611 | The IR XML declares a DOCTYPE or ENTITY. A valid IR has neither; a declared entity is an XML external-entity / expansion surface. The scanner refuses to parse such a document. |
| OVI002 | high | CWE-829 | A layer brings external or application code: op type `python` or `custom`, or a `library` / `implementation` attribute that names a native library (`.so`/`.dll`/`.dylib`/`.lib`) or a filesystem path. |
| OVI003 | high | CWE-125 | A `Const`'s weights range `(offset, size)` falls outside the `.bin`, or a string `Const` whose range the runtime's string path does not bounds-check at all. |
| OVI004 | high | CWE-190 | A `Const` whose element count times element bitwidth overflows 64-bit size arithmetic, or a shape with a negative dimension. |
| OVI005 | medium | CWE-693 | A `Const` declaring fewer bytes than its shape and `element_type` need (the runtime rejects it at load), the weights `.bin` missing so ranges cannot be checked, the file not being well-formed OpenVINO IR, or findings capped. |

The range check is overflow-safe: like the runtime, it tests
`offset <= weights_size and size <= weights_size - offset`, never `offset +
size`.

## Prior art and honest limits

promptfoo's ModelAudit has an OpenVINO scanner that flags `python`/`custom`
layer types and `library`/`implementation` references, but it records the
`.bin` size only and does not read `Const` `offset`/`size` against it, nor
check `shape` against `size`. The Go project `defilantech/socair` reads the IR
and fails a `shape * element_size` mismatch but marks the `offset`/`size`-vs-
`.bin` range and string constants as "not tested". The checks OVI003 (including
the string-tensor gap) and OVI004 (the overflow class) are, as far as we can
tell, not gated by an existing model scanner.

This is static review only — nothing is loaded or executed, and a DOCTYPE /
entity document is never handed to the XML parser. A finding means a file asks
the runtime to do something out of bounds or to run external code; whether a
given runtime version is still vulnerable depends on the fixes it carries. The
scanner needs the `.bin` to be present (by name) to check ranges; without it,
those constants are reported as unchecked. Element types outside the known
bit-width table are not size-checked. If you spot a mistake, the repo is the
place to raise it.
