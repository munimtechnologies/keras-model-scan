# Hydra `_target_` blacklist-bypass recall audit: the two CVE-2026-106442 bypass wrappers (`timeit.timeit`, `pickle.loads`) land at MEDIUM, not HIGH, and the root hydra-core CVEs are uncited

*Source-review audit, 2026-10-28. Made with AI agents working in the name of MV2 of
Munim, Inc. No code was executed against any system; this is a static reading of our own
scanner (`hydra_target_scan.py`) against published advisories.*

## Summary

`hydra_target_scan.py` flags Hydra-style `_target_` instantiation configs. It uses two
tiers: **HYD001 (HIGH)** for a `_target_` naming a callable in an explicit
code-execution denylist (`_DANGEROUS_TARGETS`), and **HYD002 (MEDIUM, LOW for benign
prefixes)** for *any other* `_target_`, on the stated grounds that "the Hydra blocklist
can be bypassed." That flag-everything backstop is the right design and means nothing is
missed outright.

Reading the denylist against the Hydra project's **own** incomplete-fix advisory,
**CVE-2026-106442 / GHSA-rqx7-p7vv-w7hr**, surfaces two refinements:

- **Finding A (severity recall).** CVE-2026-106442's advisory text names specific
  blacklist-bypass vectors: *"execution wrappers such as `timeit.timeit`, executable
  deserialization through `pickle.loads`, and generic dispatch or wrapper targets."*
  `_DANGEROUS_TARGETS` already lists one such indirection wrapper (`functools.partial`)
  but **omits both `timeit.timeit` and `pickle.loads`**. A config with
  `_target_: timeit.timeit` (with a `stmt`/`setup` argument) or `_target_: pickle.loads`
  (with a `bytes` payload) is therefore reported at **HYD002 MEDIUM**, not **HYD001 HIGH**
  — even though these are documented RCE vectors as dangerous as `os.system`.
- **Finding B (CVE-map completeness).** The module cites only *downstream* consumers of
  the flaw — NVIDIA NeMo (**CVE-2025-23304**) and Salesforce Uni2TS (**CVE-2026-22584**)
  — but neither of the *root* hydra-core CVEs: **CVE-2026-68508** (the
  `hydra.utils.instantiate` untrusted-config RCE, CWE-470/CWE-94, fixed 1.3.4) nor
  **CVE-2026-106442** (the incomplete-blacklist bypass, CWE-184, fixed 1.3.6 / 1.4.0.dev9).
  CVE-2026-68508 is the CVE for exactly what HYD001/HYD002 detect, and CVE-2026-106442 is
  the formal justification for HYD002's "the blocklist can be bypassed" MEDIUM design.

Neither is a clean false-negative (HYD002 still fires), so this is a **triage/severity
refinement plus a provenance fix**, not a new library vulnerability. The upstream flaws
are patched (hydra-core >= 1.3.6).

## What the scanner does today (verified by reading `hydra_target_scan.py`, 2026-10-28)

`_DANGEROUS_TARGETS` (the HYD001 HIGH set), verbatim:

- builtins: `builtins.exec`, `builtins.eval`, `builtins.__import__`, `builtins.compile`,
  `builtins.getattr`, `builtins.setattr`
- os: `os.system`, `os.popen`, `os.exec`, `os.execv`, `os.execve`, `os.execvp`,
  `os.spawnl`, `os.spawnv`, `os.posix_spawn`
- subprocess: `subprocess.Popen`, `subprocess.run`, `subprocess.call`,
  `subprocess.check_call`, `subprocess.check_output`, `subprocess.getoutput`
- other: `pty.spawn`, `platform.popen`, `importlib.import_module`,
  `pkgutil.resolve_name`, `ctypes.CDLL`, `ctypes.cdll`, `ctypes.WinDLL`,
  `ctypes.windll`, `runpy.run_path`, `runpy.run_module`, `code.interact`, `pdb.run`,
  **`functools.partial`**

Plus a module-prefix escalation: a `_target_` whose head module is in
`{subprocess, ctypes, pty}` is escalated to HIGH.

Everything else with a `_target_` is **HYD002 MEDIUM** (LOW for `torch.optim.`,
`torch.nn.`, `transformers.`, etc.). Cited identifiers in the docstring: CVE-2026-22584,
CVE-2025-23304, CVE-2026-68770, CVE-2026-100840, GHSA-mwj6-rfh8-7qf4,
GHSA-jhr6-gm9c-rqjv, PYSEC-2026-4164, GHSA-873f-pvrv-4x83, PYSEC-2026-4015.

## Finding A in detail: the two named bypass wrappers are only MEDIUM

The reason `functools.partial` is in the HIGH set is that it is an **indirection wrapper**
— a benign-looking callable that, given the right arguments, invokes an arbitrary other
callable, hiding the real target from a name-based check. That is precisely the class
CVE-2026-106442 is about. The advisory enumerates the same class and names two concrete
members the scanner misses:

| Bypass vector (CVE-2026-106442) | In `_DANGEROUS_TARGETS`? | Tier today |
|---|---|---|
| `functools.partial` | yes | HYD001 HIGH |
| **`timeit.timeit`** | **no** | HYD002 MEDIUM |
| **`pickle.loads`** | **no** | HYD002 MEDIUM |
| aliases / callable-returning helpers / deferred dispatch | n/a (undecidable by name) | HYD002 MEDIUM |

- `timeit.timeit(stmt=..., setup=...)` compiles and runs its `stmt`/`setup` strings as
  Python — a direct `exec` equivalent reachable purely from config scalars.
- `pickle.loads(<bytes>)` is arbitrary-code deserialization; a `_target_: pickle.loads`
  with a `bytes` argument is an RCE primitive.

Both deserve HYD001 HIGH for parity with `functools.partial` and the existing
`builtins.exec` / `builtins.eval` entries. The last row is correctly left at MEDIUM:
arbitrary aliases cannot be resolved by a static name denylist, which is exactly why
HYD002's flag-all backstop exists and must stay.

## Finding B in detail: cite the root hydra-core CVEs

The current citations are downstream products that *embed* vulnerable `instantiate`
usage. The upstream root-cause CVEs are missing:

- **CVE-2026-68508** (GHSA-2cp2-2r3c-7p7r, PYSEC-2026-3850): `hydra.utils.instantiate`
  with untrusted config -> code execution via `_resolve_target`. Affected `< 1.3.4`;
  fixed 1.3.4 (adds target blocking + allowlist escape hatch). CWE-470 / CWE-94.
- **CVE-2026-106442** (GHSA-rqx7-p7vv-w7hr): the 1.3.4 blacklist was incomplete; bypassable
  by execution wrappers. Affected `>= 1.3.4, < 1.3.6` and `>= 1.4.0.dev0, < 1.4.0.dev9`;
  fixed 1.3.6 / 1.4.0.dev9. CWE-184. The upstream fix of record moves the primary boundary
  from a blacklist to an **execution whitelist** (1.4.0.dev9) — direct vindication of
  HYD002's "flag every `_target_`" approach over trusting any denylist.

## Why this is new

Prior public material on these CVEs describes the Hydra flaw itself and the NeMo/Uni2TS
consumers (Unit 42, the GHSA pages, vendor advisories). No prior work maps
CVE-2026-106442's *named* bypass wrappers against a static, pre-load model-config scanner,
and none notes that a denylist which already contains one indirection wrapper
(`functools.partial`) omits the two the advisory calls out by name. Verified by reading
the exact `_DANGEROUS_TARGETS` membership on 2026-10-28 and tracing `timeit.timeit` /
`pickle.loads` through the HYD001 -> HYD002 tiering. This is a recall/provenance
refinement in our own tool, not a new hydra-core vulnerability (the upstream flaws are
public and patched).

## The fix (specced; pending a sealed compute slot)

Editing the live scanner + its test needs a sealed compute slot (a byte-exact repro of an
existing module cannot be reconstructed via WebFetch). Four queued jobs are ahead, so this
is specced, not filed, consistent with the congestion rule.

1. In `hydra_target_scan.py`, add to `_DANGEROUS_TARGETS`:
   `timeit.timeit`, `timeit.repeat`, `pickle.loads`, `pickle.load`, and (for parity with
   `cPickle` style imports) `_pickle.loads`, `_pickle.load`. Leave the MEDIUM backstop
   unchanged for aliases/dispatch.
2. Add `CVE-2026-68508` and `CVE-2026-106442` to the module docstring and to
   `model_file_cve_map.json` (HYD001/HYD002 rows) and `MODEL_FILE_CVE_MAP.md`; keep the
   existing downstream CVEs. Re-run `cve_map_lint.py` so the map stays consistent.
3. Update `HYDRA_TARGET_SCAN.md` HYD001 row to list the added callables.
4. Test (`test_hydra_target_scan.py`, importing only the scanner): a `config.yaml` with
   `_target_: timeit.timeit` asserts a HYD001 HIGH finding (was MEDIUM); same for
   `_target_: pickle.loads`; and a benign `_target_: torch.optim.Adam` still asserts LOW.
5. Bump the `hydra_target_scan` version and ship keras-model-scan **v0.48.0** in the same
   release as whichever queued fix lands first.

### Sealed PoC spec (poc, no network)

Build two tiny config files in `/work`: `cfg_timeit.yaml` with
`_target_: timeit.timeit` + `stmt: "__import__('os').system('id')"`, and
`cfg_pickle.yaml` with `_target_: pickle.loads` + a `bytes` arg. Run the current scanner
(MEDIUM for both) and the patched scanner (HIGH for both) and diff the severities. No
`instantiate()` is ever called; the configs are never loaded by Hydra — static read only.

## Honest limits

- **Not a clean miss.** HYD002 already reports both wrappers at MEDIUM, so this raises
  severity/triage fidelity; it does not rescue a finding from silence (unlike the r188
  pickle BENIGN_TOP false-negative, where gadget paths cleared benign).
- **Upstream is patched** (hydra-core >= 1.3.6; whitelist in 1.4.0.dev9). The value is
  defense-in-depth for pipelines still on vulnerable Hydra or on third-party
  reimplementations of `instantiate`, and accurate provenance in our CVE map.
- **A name denylist can never be complete** against aliasing/dispatch — the whole point of
  CVE-2026-106442. Adding `timeit.timeit`/`pickle.loads` closes the two *named* gaps; the
  MEDIUM backstop remains the real guarantee and must stay.
- Finding B is documentation-only and changes no detection behavior on its own.

## References

- CVE-2026-68508 — GHSA-2cp2-2r3c-7p7r, PYSEC-2026-3850 (hydra.utils.instantiate RCE)
- CVE-2026-106442 — GHSA-rqx7-p7vv-w7hr (incomplete-blacklist bypass; names
  `timeit.timeit`, `pickle.loads`)
- hydra-core changelog: target blocking 1.3.4; blacklist fix 1.3.6; execution whitelist
  1.4.0.dev9

*Apache-2.0. Work made with AI agents in the name of MV2 of Munim, Inc.*
