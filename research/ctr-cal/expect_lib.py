# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Expected CTR rules for job ctr-cal-v1, written from the pre-registered
calibration spec (research/PREREG_CTR_CALIBRATION.md), independently of the
module under test. Pure functions, standard library only.

Spec: one finding per serialized trust_remote_code key at any depth.
If any string model_type in the file contains "lightglue" (case-insensitive):
truthy value -> CTR001, other value -> CTR002 (both carry CVE-2026-5241).
Otherwise -> CTR003 (LOW, no CVE).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import census_lib as c

TRUTHY_STRINGS = ("true", "1", "yes", "on")


def truthy(value):
    if value is True or value is False:
        return value
    if isinstance(value, str):
        return value.strip().lower() in TRUTHY_STRINGS
    if isinstance(value, (int, float)):
        return value != 0
    return False


def names_lightglue(doc):
    return any("lightglue" in t for t in c.model_types(doc))


def expected_rules(doc):
    """Sorted list of expected rule ids for a parsed config document."""
    lg = names_lightglue(doc)
    out = []
    for v in c.values_of(doc, c.TRC):
        if not lg:
            out.append("CTR003")
        elif truthy(v):
            out.append("CTR001")
        else:
            out.append("CTR002")
    return sorted(out)


EXPECTED_LEVEL = {"CTR001": "CRITICAL", "CTR002": "HIGH", "CTR003": "LOW"}
EXPECTED_CVE = {"CTR001": "CVE-2026-5241", "CTR002": "CVE-2026-5241",
                "CTR003": ""}
