"""Load exactly one GGUF file with the Python gguf-py reader, under a hard address-space
cap so that a pathological allocation surfaces as MemoryError instead of an OOM kill.

Run as a child process by probe.py: `python load_one.py <path>`. Prints one line of
JSON describing the outcome. A wall-clock timeout is enforced by the PARENT (a hang
shows up there as a TimeoutExpired), so this process only needs the memory cap.

Made with AI by MV2 of Munim, Inc. (Apache-2.0).
"""

import json
import sys


def _cap_memory(limit_bytes: int) -> bool:
    try:
        import resource
    except Exception:
        return False  # non-POSIX; parent timeout still applies
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_hard = limit_bytes if hard == resource.RLIM_INFINITY else min(limit_bytes, hard)
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, new_hard))
        return True
    except Exception:
        return False


def main() -> None:
    path = sys.argv[1]
    capped = _cap_memory(1536 * 1024 * 1024)  # 1.5 GiB
    result = {"path": path, "mem_capped": capped}
    try:
        from gguf import GGUFReader
    except Exception as exc:  # gguf not installed (setup had no network, etc.)
        result["outcome"] = "gguf_unavailable"
        result["exc_type"] = type(exc).__name__
        result["exc_msg"] = str(exc)[:200]
        print(json.dumps(result))
        return
    try:
        reader = GGUFReader(path, "r")
        # Force materialization of every tensor (triggers the memmap slice + reshape).
        n = len(reader.tensors)
        shapes = []
        for tensor in reader.tensors:
            _ = tensor.data  # access the (lazily sized) numpy view
            shapes.append([int(d) for d in tensor.shape])
        result["outcome"] = "loaded"
        result["n_tensors"] = n
        result["n_kv"] = len(reader.fields)
        result["shapes"] = shapes
    except MemoryError:
        result["outcome"] = "memory_error"
    except RecursionError:
        result["outcome"] = "recursion_error"
    except Exception as exc:
        # The predicted safe path: a clean, fast rejection.
        result["outcome"] = "rejected"
        result["exc_type"] = type(exc).__name__
        result["exc_msg"] = str(exc)[:200]
    print(json.dumps(result))


if __name__ == "__main__":
    main()
