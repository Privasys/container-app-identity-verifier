# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""DG1 MRZ parsing (ICAO 9303 TD3, the passport format).

DG1 is a BER-TLV (tag 0x61) wrapping the MRZ (tag 0x5F1F). For TD3 the MRZ is
two 44-character lines. We extract the certified fields; the DG1 bytes have
already been hash-checked against the SOD by Passive Authentication, so the MRZ
is trusted at this point.
"""

from __future__ import annotations

from datetime import datetime, timezone


class MRZError(Exception):
    """DG1 / MRZ could not be parsed."""


def _read_tlv(data: bytes) -> tuple[int, bytes, bytes]:
    """Read one BER-TLV; return (tag, value, rest)."""
    if not data:
        raise MRZError("empty TLV")
    i = 0
    tag = data[i]
    i += 1
    if tag & 0x1F == 0x1F:  # multi-byte tag
        tag = (tag << 8) | data[i]
        i += 1
        while data[i - 1] & 0x80:  # continuation
            tag = (tag << 8) | data[i]
            i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, data[i:i + length], data[i + length:]


def _mrz_string(dg1: bytes) -> str:
    tag, value, _ = _read_tlv(dg1)
    if tag == 0x61:           # DG1 template → unwrap the inner 5F1F
        tag, value, _ = _read_tlv(value)
    if tag != 0x5F1F:
        raise MRZError("DG1 does not contain an MRZ (5F1F)")
    return value.decode("ascii", "replace")


def parse_dg11(dg11: bytes) -> dict:
    """Parse DG11 (additional personal details). DG11 is tag 0x6B wrapping data
    elements; we extract place of birth (0x5F11) and personal number (0x5F10).
    Returns only the fields present. Already hash-checked against the SOD before
    we get here, so the contents are trusted."""
    try:
        tag, value, _ = _read_tlv(dg11)
    except MRZError:
        return {}
    body = value if tag == 0x6B else dg11  # some encoders omit the template
    out: dict = {}
    rest = body
    while rest:
        try:
            t, v, rest = _read_tlv(rest)
        except MRZError:
            break
        text = v.decode("utf-8", "replace").strip()
        if t == 0x5F11 and text:        # place of birth (components split by '<')
            out["place_of_birth"] = ", ".join(p for p in text.split("<") if p).strip()
        elif t == 0x5F10 and text:      # personal (national) number
            out["personal_number"] = text.replace("<", "").strip()
    return out


def canonical_mrz(dg1: bytes) -> str:
    """The chip's MRZ (from DG1) normalised for comparison: upper-case, no
    whitespace/newlines."""
    return "".join(_mrz_string(dg1).split()).upper()


# OCR-B look-alikes the camera genuinely can't disambiguate. We fold these to a
# single form on BOTH sides before comparing, so OCR noise (e.g. the document
# number's 'I' read as '1') is not mistaken for tampering. Safe because the
# document number, birth date and expiry are already check-digit + BAC verified,
# and a real tamper changes actual values, not just a 1↔I look-alike.
_OCR_FOLD = str.maketrans({"O": "0", "I": "1", "S": "5", "B": "8", "Z": "2"})


def _fold(s: str) -> str:
    return s.upper().translate(_OCR_FOLD)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) + len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _too_different(a: str, b: str) -> bool:
    """Tolerate OCR noise, flag a genuinely different value: allow an edit
    distance up to ~20% of the field (min 2 chars)."""
    return _levenshtein(_fold(a), _fold(b)) > max(2, round(0.2 * max(len(a), len(b))))


def _raw_mrz_fields(mrz88: str) -> dict:
    """Critical fields as raw MRZ substrings (filler stripped) — no date parsing,
    so OCR noise can't raise; for the box-3 consistency comparison only."""
    l1, l2 = mrz88[0:44], mrz88[44:88]
    surname, _, given = l1[5:44].partition("<<")
    return {
        "family_name": surname.replace("<", " ").strip(),
        "given_name": given.replace("<", " ").strip(),
        "document_number": l2[0:9].replace("<", ""),
        "nationality": l2[10:13].replace("<", ""),
        "birthdate": l2[13:19],
        "sex": l2[20],
        "doc_expiry": l2[21:27],
    }


def cross_reference(ocr_mrz: str, dg1: bytes) -> dict:
    """GPG45 box 3 at Medium confidence (M1C): check the OCR'd visual MRZ is
    *consistent* with the chip's DG1 — not a byte-exact match. The chip is
    authoritative and document number / birth date / expiry are already proven by
    the successful BAC/PACE unlock, so we tolerate OCR noise (confusable-folded +
    small edit distance) and flag only a genuine contradiction (likely tampering).

    Returns {"consistent": True|False|None, "mismatches": [field,…]}: None when the
    MRZ could not be OCR'd — M1C does not fail on an unreadable VIZ when the chip
    and biometric verify."""
    visual = "".join((ocr_mrz or "").split()).upper()
    chip = canonical_mrz(dg1)
    if len(visual) < 88 or len(chip) != 88:
        return {"consistent": None, "mismatches": [], "reason": "MRZ not readable"}
    vf, cf = _raw_mrz_fields(visual[:88]), _raw_mrz_fields(chip)
    mismatches = [
        key for key in ("family_name", "given_name", "nationality",
                        "document_number", "birthdate", "doc_expiry", "sex")
        if vf[key] and cf[key] and _too_different(vf[key], cf[key])
    ]
    return {"consistent": len(mismatches) == 0, "mismatches": mismatches}


def _date(yymmdd: str, *, birth: bool) -> str:
    if len(yymmdd) != 6 or not yymmdd.isdigit():
        raise MRZError(f"bad MRZ date {yymmdd!r}")
    yy, mm, dd = int(yymmdd[0:2]), yymmdd[2:4], yymmdd[4:6]
    pivot = datetime.now(timezone.utc).year % 100
    if birth:
        century = 1900 if yy > pivot else 2000
    else:  # expiry dates are in the 2000s
        century = 2000
    return f"{century + yy:04d}-{mm}-{dd}"


def parse_dg1(dg1: bytes) -> dict:
    """Parse DG1 (TD3) into the certified fields."""
    mrz = "".join(_mrz_string(dg1).split())  # drop any whitespace/newlines
    if len(mrz) != 88:
        raise MRZError(f"unsupported MRZ length {len(mrz)} (expected TD3 / 88)")
    l1, l2 = mrz[0:44], mrz[44:88]

    surname, _, given = l1[5:44].partition("<<")
    fields = {
        "document_type": l1[0:2].replace("<", "").strip(),
        "issuing_state": l1[2:5].replace("<", ""),
        "family_name": surname.replace("<", " ").strip(),
        "given_name": given.replace("<", " ").strip(),
        "document_number": l2[0:9].replace("<", ""),
        "nationality": l2[10:13].replace("<", ""),
        "birthdate": _date(l2[13:19], birth=True),
        "sex": l2[20] if l2[20] in ("M", "F") else "",
        "doc_expiry": _date(l2[21:27], birth=False),
    }
    return {k: v for k, v in fields.items() if v}
