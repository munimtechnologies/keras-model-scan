# The `.keras` non-config load path: asset store + zip extraction (honest negative)

*Part of the keras-model-scan research notes. Made with AI agents working in the name
of MV2, Munim, Inc. Apache-2.0. Verified against `keras-team/keras` `master` on
2026-10-24; latest release at the time was v3.12.4 (2026-07-29).*

## Why this note exists

Earlier notes in this repo mapped the **config-time** file-I/O surface of a `.keras`
model — every place where parsing `config.json` can cause a read of an attacker-named
path during `from_config`/`__init__` (see `KERAS_NAMESPACE_IO_SURFACE.md`,
`KERAS_NONLAYER_SERIALIZABLE_IO_SURFACE.md`, `KERAS_NESTED_FN_RECURSION_IO_SURFACE.md`).
Those reduced the whole config-time surface to two guarded vocabulary/tokenizer families.

This note maps the one load-path frontier those left open: the **non-config** path —
what happens to the bytes inside the `.keras` ZIP *before and around* config parsing.
A `.keras` file is a ZIP; loading it extracts members to disk and then hands each
sublayer an asset directory. If a member name or an asset filename were taken from
attacker-controlled data, `keras.models.load_model()` could write or read outside its
sandbox **even under `safe_mode=True`**, because extraction happens before any config
trust decision. Mapping result: **it cannot — this path is guarded.** This is an honest
negative; there is no payable bug here. The value is closing the last load-path question
and recording exactly which upstream guards do the work, so later runs do not re-walk it.

## The three questions and their answers

Source: `keras/src/saving/saving_lib.py` and `keras/src/utils/file_utils.py` on `master`.

### 1. Is the per-layer asset directory path taken from `config.json`? — No.

In `saving_lib.py`, `_load_state` hands each saveable its assets with:

```
saveable.load_assets(assets_store.get(inner_path))
```

`inner_path` is built by the object-tree traversal, not read from the config:

```
inner_path=file_utils.join(inner_path, child_attr).replace("\\", "/")
```

For items inside list/tuple/dict containers the name comes from a class-name counter
(`_get_unique_name(naming.to_snake_case(saveable.__class__.__name__), used_names)`), again
not from the config. The config decides *which objects* are instantiated; the asset
lookup path is computed by the traversal itself. So an attacker cannot point a sublayer
at an arbitrary asset path via the config.

### 2. Does a layer's `load_assets` open a config-named file? — No.

The one layer family that reads an asset at load time is the index-lookup family
(`StringLookup`/`IntegerLookup`/`TextVectorization` via `IndexLookup`, in
`keras/src/layers/preprocessing/index_lookup.py`). Its `load_assets(dir_path)` opens a
**hardcoded** filename:

```
with open(vocabulary_filepath, "r") as f:
```

where `vocabulary_filepath` is `"vocabulary.txt"` joined to `dir_path`. The only
config-derived branch is an early return when `self.input_vocabulary is not None` (the
vocabulary lives inline in the config instead — the guarded string-vocabulary surface the
earlier notes already cover). The filename is never pulled from the config.

### 3. Is the ZIP extracted using attacker-controlled member names unsafely? — No.

`DiskIOStore.__init__` extracts the archive to a fresh temp dir on load:

```
file_utils.extract_open_archive(self.archive, self.tmp_dir)
```

`extract_open_archive` does **not** extract first and check later. It filters members
*before* writing, passing a validated member list into `extractall`:

```
archive.extractall(path, members=filter_safe_zipinfos(archive.infolist(), path))
```

`filter_safe_zipinfos` yields a member only when `resolve_sub_path(base_dir,
finfo.filename) is not None`; rejected entries log `"Skipping invalid path during archive
extraction"` and are dropped. `resolve_sub_path` is:

```
path = resolve_path(os.path.join(base_dir, relative_path))
if os.path.commonpath([path, base_dir]) == base_dir:
    return path
return None   # also on ValueError (mixed absolute/relative, different drives)
```

and `resolve_path(path)` is `os.path.realpath(path)` — it resolves symlinks before the
containment test.

This is correct against the usual zip-slip failure modes:

- **`..` traversal** — `realpath` normalises, `commonpath` rejects anything whose common
  ancestor with the temp dir is not the temp dir itself.
- **Absolute member names** (`/etc/...`, `C:\...`) — `os.path.join(base_dir, "/x")`
  collapses to the absolute path, whose `commonpath` with `base_dir` is not `base_dir`.
- **Sibling-prefix trick** (`base_dir` = `/tmp/abc`, member resolving to `/tmp/abc_evil`)
  — `commonpath` compares whole path components, so `/tmp` ≠ `/tmp/abc`: rejected. This is
  why `commonpath` is used rather than `str.startswith`, which that trick defeats.
- **Cross-drive on Windows** — `commonpath` raises `ValueError`, caught → `None` → dropped.
- **Symlinks** — `resolve_path` is `realpath`, so a symlinked component is resolved before
  the test; and Python's `zipfile.extractall` writes a stored symlink's target as ordinary
  file *content*, it does not create a link. (Tar archives, which can carry real links,
  get a separate `is_link_in_dir` check in `filter_safe_tarinfos` that validates both the
  link location and its target against `base_dir`.)

## Conclusion

The `.keras` non-config load path adds **no** unguarded file-write or file-read gadget.
Asset directory paths come from object-tree traversal, not config; the lookup layers open
a hardcoded `vocabulary.txt`; and ZIP/tar extraction validates every member against the
destination root with a realpath + `commonpath` containment test before writing. Combined
with the config-time map in the sibling notes, the **entire** `.keras` load path —
config-time file I/O *and* non-config asset/archive handling — is now mapped. Both halves
reduce to upstream guards that hold on `master`; there is no in-scope, source-review-
verifiable vulnerability here.

## Honest limits

- Source review only, against `master` on 2026-10-24. No live system was touched and no
  model file was loaded; claims are from reading the cited functions.
- Not checked: *when* `filter_safe_zipinfos` was introduced, or whether old Keras releases
  extracted with a plain `extractall` (note that CPython's own `zipfile.extractall` has
  blocked `..` and leading-`/` member names since 3.6.2, so the filter is defence-in-depth
  on top of that, chiefly for absolute and cross-drive names). A per-release regression
  pass on this function is future work.
- Scope: this maps keras-core only. The keras_hub tokenizer asset handling is a separate
  surface; its config-time string-path reads are already covered in
  `KERAS_DESERIALIZATION_IO_BLINDSPOT.md`.
