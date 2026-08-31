#!/usr/bin/env python3
"""Check snapshot identity and that gas figures in documentation appear in snapshots.

    check_measured.py [root]

Live re-execution is `python3 harness/bench.py all --check`.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import derive_sizes  # noqa: E402

MEASURED = Path("harness/announcement/measured.json")
INTRINSIC = 21_000
SCHEMA_VERSION = 1
ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564"
ANNOUNCER_SHA256 = "97b1a2b6e83d4d2d1184c28bfafe24df2463fcaec94e655b2b56ba5fc52a1b17"
REGISTRY = "0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538"
REGISTRY_SHA256 = "aacd1016938b107361de63f20c358350de9f78fa6033b7727853f0229c94b82f"

# Files this tool reads for quoted gas numbers.
# `docs/*.md` and `AUDIT.md` are unused in this tree; keep the globs so they
# are covered if those paths come back.
GAS_DOCS = ("docs/*.md", "AUDIT.md", "spec/ERC-*.md", "README.md",
            "harness/*/README.md")
GAS_DOCS_ALL = GAS_DOCS

# `--all` prints unmatched numbers instead of failing. Same file list either way.
KNOWN_UNTRACED = 0

# A number in those files is treated as gas when it has at least five digits
# (spaces allowed, e.g. 69 360) and either sits near the word "gas" or is in a
# table column whose header contains "gas". That number must equal a `gas_used`
# in harness/*/measured.json (or a sum of those values).
#
# To quote a number this repo did not measure, put a marker in the same
# paragraph, with a source after the colon:
#     <!-- gas-external: EIP-2929 -->
#     <!-- gas-superseded: pre-Prague figure -->
#     <!-- gas-withdrawn: dropped claim -->
MARKER = re.compile(r"<!--\s*gas-(external|superseded|withdrawn):\s*\S")


def _pipe_split(s: str) -> list[str]:
    """Split on UNESCAPED pipes only: GFM permits `\\|` inside a cell, and a parser
    that counts every raw pipe shifts every cell after the escape — which moves a
    gas figure out of its column and out of the sweep entirely."""
    out: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            cur.append(s[i:i + 2])
            i += 2
            continue
        if s[i] == "|":
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(s[i])
        i += 1
    out.append("".join(cur))
    return out


def _pipes_before(raw: str, upto: int) -> int:
    """How many UNESCAPED pipes precede offset `upto` — the figure's column index
    walks the same tokenization the cells do."""
    n, i = 0, 0
    while i < min(upto, len(raw)):
        if raw[i] == "\\":
            i += 2
            continue
        if raw[i] == "|":
            n += 1
        i += 1
    return n


def _row_cells(raw: str) -> list[str] | None:
    """The cells of a Markdown table row — tolerant of GFM's optional leading and
    trailing pipes, escaped pipes inside cells, and blockquote containers, because
    a table means the same thing spelled any of those ways. None for a line with
    no `|` at all."""
    s = re.sub(r"^[\s>]*", "", raw).strip()
    if "|" not in s:
        return None
    cells = _pipe_split(s)
    if len(cells) > 1 and not cells[0].strip():
        cells = cells[1:]
    if len(cells) > 1 and not cells[-1].strip():
        cells = cells[:-1]
    return [c.replace("\\|", "|").strip() for c in cells]


def _cell_schemes(cell: str) -> set[int]:
    """The schemeIds a table row's FIRST cell claims: lone digits, possibly several
    ("4, 5 (memo)"), with bold markers and parenthetical asides ignored. A cell whose
    remainder is anything else — a byte column, a header label, a dash — claims
    nothing."""
    s = re.sub(r"\([^)]*\)", "", cell).replace("*", "").strip()
    parts = [p for p in re.split(r"\s*(?:,|and|/|or)\s*|\s+", s) if p]
    if parts and all(re.fullmatch(r"\d", p) for p in parts):
        return {int(p) for p in parts}
    return set()

# Numbers that are not gas and would otherwise have to be exempted one at a time: byte counts,
# years, section sizes, hardfork-independent constants. Read from the size model rather than
# listed, so adding a scheme does not mean editing a denylist here.
def _not_gas() -> set[int]:
    """Byte-size constants from `derive_sizes`, plus announcement totals and combiner IKM."""
    out = {INTRINSIC}

    def absorb(v) -> None:
        if isinstance(v, bool):
            return
        if isinstance(v, int):
            out.add(v)
        elif isinstance(v, (tuple, list, set)):
            for x in v:
                absorb(x)
        elif isinstance(v, dict):
            for x in v.values():
                absorb(x)

    for name in dir(derive_sizes):
        if name.isupper():
            absorb(getattr(derive_sizes, name))
    for shape in derive_sizes.SHAPES.values():
        if len(shape) >= 2 and all(isinstance(x, int) for x in shape[:2]):
            out.add(sum(shape[:2]))
    # §1.1's combiner IKM: ss_ec + ss_pq + epk + ct + viewing_pk_ec + ek.
    out.add(
        2 * derive_sizes.SCALAR
        + 2 * derive_sizes.SEC1_COMPRESSED
        + derive_sizes.CT_MLKEM768
        + derive_sizes.EK
    )
    return out


def _tokens(measurement: dict) -> int:
    calldata = measurement["calldata_bytes"]
    zero = measurement["zero_bytes"]
    return zero + 4 * (calldata - zero)


def _gas_used_values(value: object) -> set[int]:
    """Collect raw `gas_used` leaves from a result object."""
    found: set[int] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "gas_used" and isinstance(child, int):
                found.add(child)
            else:
                found.update(_gas_used_values(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_gas_used_values(child))
    return found


def _byte_values(value: object) -> set[int]:
    """Collect wire-size leaves that are not gas claims."""
    keys = {"calldata_bytes", "epk_bytes", "metadata_bytes", "meta_address_bytes"}
    found: set[int] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in keys and isinstance(child, int):
                found.add(child)
            else:
                found.update(_byte_values(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_byte_values(child))
    return found


def _load_artifact(root: Path, relative: str, bad: list[str]) -> dict:
    path = root / relative
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(body, dict):
            bad.append(f"{relative}: top level is not an object")
            return {}
        return body
    except (OSError, ValueError) as exc:
        bad.append(f"{relative}: not readable as JSON ({exc})")
        return {}


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--all"]
    unknown = [a for a in args if a.startswith("-")]
    if unknown or len(args) > 1:
        print(f"usage error: unexpected argument(s) {' '.join(unknown or args[1:])}",
              file=sys.stderr)
        print("usage: check_measured.py [root] [--all]", file=sys.stderr)
        print(__doc__)
        return 2
    root = Path(args[0] if args else ".").resolve()
    path = root / MEASURED
    if not path.is_file():
        print(f"usage error: no measurements at {path}", file=sys.stderr)
        return 2

    bad: list[str] = []
    expected_artifacts = {
        "announcement": (
            "harness/announcement/measured.json",
            {
                "hardfork": "prague",
                "contract_address": ANNOUNCER,
                "contract_code_sha256": ANNOUNCER_SHA256,
            },
        ),
        "registration": (
            "harness/registration/measured.json",
            {
                "hardfork": "prague",
                "contract_address": REGISTRY,
                "contract_code_sha256": REGISTRY_SHA256,
            },
        ),
        "payment": (
            "harness/payment/measured.json",
            {
                "hardfork": "prague",
                "announcer_address": ANNOUNCER,
                "announcer_code_sha256": ANNOUNCER_SHA256,
            },
        ),
    }
    artifacts: dict[str, dict] = {}
    fixture_hashes: set[str] = set()
    for benchmark, (relative, environment) in expected_artifacts.items():
        body = _load_artifact(root, relative, bad)
        artifacts[benchmark] = body
        if body.get("schema_version") != SCHEMA_VERSION:
            bad.append(f"{relative}: schema_version is not {SCHEMA_VERSION}")
        if body.get("benchmark") != benchmark:
            bad.append(f"{relative}: wrong benchmark identity")
        if body.get("environment") != environment:
            bad.append(f"{relative}: wrong benchmark environment")
        if not isinstance(body.get("results"), list) or not body["results"]:
            bad.append(f"{relative}: results is empty or invalid")
        fixture = body.get("fixture")
        if isinstance(fixture, dict) and re.fullmatch(
            r"[0-9a-f]{64}", str(fixture.get("sha256", ""))
        ):
            fixture_hashes.add(fixture["sha256"])
        else:
            bad.append(f"{relative}: missing real fixture identity")
    if len(fixture_hashes) != 1:
        bad.append("benchmark artifacts do not share one real fixture")
    print(f"{len(artifacts)} committed benchmark artifact(s) loaded")

    allowed: set[int] = set()
    # Per-scheme sets so a registration total cannot vouch for an announcement claim.
    by_scheme: dict[int, set[int]] = {}
    for receipts in sorted(root.glob("harness/*/measured.json")):
        try:
            body = json.loads(receipts.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            bad.append(f"{receipts.relative_to(root)}: not readable as JSON")
            continue
        diagnostics = {
            diagnostic.get("for_case"): diagnostic.get("transaction")
            for diagnostic in body.get("diagnostics", [])
            if isinstance(diagnostic, dict)
        }
        for c in body.get("results", []):
            if not isinstance(c, dict):
                continue
            sid = c.get("scheme_id")
            sids = {sid} if isinstance(sid, int) else set()
            # A receipt's NAME may declare coverage beyond its schemeId field:
            # "memo (schemeIds 4, 5)" is ONE measurement of a wire identical on
            # both schemes, and it vouches for both — the declaration is part of
            # the committed measurement artifact, not this tool's inference.
            for nm in re.finditer(r"schemeIds?\s+(\d)(?:\s*(?:,|and|/|or)\s*(\d))*",
                                  str(c.get("name", ""))):
                sids |= {int(g) for g in nm.groups() if g}
            values = _gas_used_values(c)
            transactions = c.get("transactions")
            if isinstance(transactions, dict):
                components = [
                    observation.get("gas_used")
                    for observation in transactions.values()
                    if isinstance(observation, dict)
                    and isinstance(observation.get("gas_used"), int)
                ]
                if len(components) == len(transactions):
                    values.add(sum(components))
            if body.get("benchmark") == "announcement":
                probe = diagnostics.get(c.get("name"))
                if isinstance(probe, dict) and all(
                    isinstance(probe.get(key), int)
                    for key in ("calldata_bytes", "zero_bytes", "gas_used")
                ):
                    values.add(probe["gas_used"])
                    values.add(probe["gas_used"] - INTRINSIC - 4 * _tokens(probe))
            allowed.update(values)
            for scheme in sids:
                by_scheme.setdefault(scheme, set()).update(values)
    # A DIFFERENCE between two receipts is as re-derivable as either receipt, and prose that
    # compares two schemes quotes one -- "1 600 more gas" is 69 060 - 67 460. Allowed, and computed
    # here rather than exempted by hand, so it stays true when a measurement moves.
    allowed |= {a - b for a in allowed for b in allowed if a > b}

    def scheme_context(lines: list[str], line_no: int, doc: Path,
                       col: int) -> tuple[set[int], set[int]]:
        """The schemeIds a quoted figure is claimed FOR, as two sets: BOUND — the
        schemes whose own receipts must vouch for the figure — and NAMED — the
        schemes whose receipts' pairwise differences may vouch for a derived
        figure. A figure binds to the NEAREST scheme mention BEFORE it, not to
        every scheme its scope names: under a scope-wide union, two swapped totals
        in one paragraph each stay vouched by the other's receipt. A markdown
        table row binds to its first cell's schemeId (an em-dash first cell with
        "classical" in the row is the baseline row). A per-scheme document's
        subject is additive on both sets — a comparison "against schemeId 1"
        inside scheme-3.md quotes scheme 3's figure on a line naming scheme 1.
        "classical" is the schemeId 1 baseline's name, additive only. Empty bound
        = unbound; an unbound figure faces only the membership test. Residual,
        stated: inside a per-scheme document a figure misassigned between a row's
        scheme and the document's own subject still passes — the binding narrows
        to the claim's schemes, not to one receipt field."""
        pat = re.compile(r"schemeIds?\s+(\d)(?:\s*(?:,|and|/|or|to)\s*(\d))?"
                         r"|scheme-(\d)\.md|(classical)")

        def match_ids(mm: re.Match) -> set[int]:
            if mm.group(4):
                return {1}
            if mm.group(3):
                return {int(mm.group(3))}
            a = int(mm.group(1))
            got = {a}
            if mm.group(2):
                b = int(mm.group(2))
                # "schemeIds 2 to 5" names the whole range; the other joiners
                # name exactly two.
                got |= set(range(a, b + 1)) if "to" in mm.group(0) else {b}
            return got

        def ids(s: str) -> set[int]:
            got: set[int] = set()
            for mm in pat.finditer(s):
                got |= match_ids(mm)
            return got

        dm = re.search(r"^scheme-(\d)\.md$", doc.name)
        subject = {int(dm.group(1))} if dm else set()
        line = lines[line_no]

        # A table row's first cell IS its scheme claim: `| **3** | ... | 69 360 |`
        # assigns the row's figures to schemeId 3 whatever the prose around the
        # table says, and `| 4, 5 (memo) | ... |` assigns them to BOTH named
        # schemes. The cell must be lone digits (bold markers and a parenthetical
        # aside ignored) so a byte column like `| 1 096 B |` binds nothing.
        cells = _row_cells(line)
        if cells:
            row = _cell_schemes(cells[0])
            if row:
                return row | subject, row | subject | ids(line)
            if (cells[0].strip("* ") in ("—", "–", "-") and "classical" in line):
                return {1} | subject, {1} | subject | ids(line)

        found = ids(line)
        scope, upto = line, col
        if not (found - {1} or "classical" in scope):
            lo = line_no
            while lo > 0 and lines[lo - 1].strip():
                lo -= 1
            hi = line_no
            while hi + 1 < len(lines) and lines[hi + 1].strip():
                hi += 1
            scope = "\n".join(lines[lo:hi + 1])
            upto = sum(len(lines[k]) + 1 for k in range(lo, line_no)) + col
            found = ids(scope)
        # "classical" is ADDITIVE only: a prose comparison against the classical
        # baseline names schemeId 1 beside its subject, but never establishes the
        # subject by itself — a document whose figures belong to an unnamed scheme
        # (the channel ERC) stays unbound rather than bound to the baseline.
        if not (found - {1} or dm):
            return set(), set()
        last = None
        for mm in pat.finditer(scope):
            if mm.start() >= upto:
                break
            last = mm
        # A mention BEFORE the figure is the claim the figure belongs to; with no
        # preceding mention ("costs 69 360 gas under schemeId 3") the whole named
        # set vouches.
        bound = (match_ids(last) if last else found) | subject
        return bound, found | subject
    exempt = _not_gas()
    # Byte counts a RECEIPT attests are not gas either: "1 316 bytes of calldata" sits one
    # line from a gas figure it explains, and a proximity sweep that cannot tell a receipt's
    # byte field from its gas field would demand gas provenance for a length. Only the byte
    # keys — token counts feed gas arithmetic and stay in scope.
    for receipts in sorted(root.glob("harness/*/measured.json")):
        try:
            body = json.loads(receipts.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        exempt.update(_byte_values(body.get("results", [])))
        exempt.update(_byte_values(body.get("diagnostics", [])))
    quoted = 0
    sweep_all = "--all" in argv
    untraced = 0
    for pattern in (GAS_DOCS_ALL if sweep_all else GAS_DOCS):
        for doc in sorted(root.glob(pattern)):
            text = doc.read_text(encoding="utf-8")
            lines = text.split("\n")
            # `(?<![\d ])` before the group: without it the pattern matches the SUFFIX of a
            # space-grouped number -- "671 731" inside "3 671 731" -- and reports a figure that
            # does not appear in the document. Three of the first fourteen findings were that.
            in_docs = "/docs/" in str(doc).replace("\\", "/")
            pattern_re = r"(?<![\d])(?<!\d )\b(\d{1,3}(?: \d{3})+|\d{5,})\b"
            # The elision exemption below applies ONLY inside the GENERATED SPANS of the
            # transcript files — the fenced bodies that follow an `<!-- output-of: ... -->`
            # marker, which are exactly the bytes an example-checker re-runs and compares.
            # The filename alone is too wide a scope: a transcript file's
            # headings and explanations are hand-written, so a figure there must face the
            # sweep like any other prose. The token walk-back inside the span is the belt
            # on top of the scope.
            generated_spans: list[tuple[int, int]] = []
            if doc.name.startswith("transcripts-"):
                # The marker grammar is full-line and anchored, matching the example-checker
                # that authenticates a span's content exactly, because:
                # a marker form it does not recognise is a span it never re-runs, and an
                # exemption there would be an exemption on hand-written bytes.
                for gm in re.finditer(
                    r"^<!--\s*output-of:\s*[a-z0-9_-]+\s*-->$", text, re.M
                ):
                    fence = text.find("```", gm.end())
                    if fence < 0:
                        continue
                    body_start = text.find("\n", fence) + 1
                    close = text.find("\n```", body_start)
                    if close < 0:
                        continue
                    generated_spans.append((body_start, close))
            for m in re.finditer(pattern_re, text):
                token = m.group(1)
                # A digit run behind an ellipsis is bytes, not a figure -- the demo prints
                # long values as head…tail and a hex tail can be all digits. Exempt only
                # inside a generated span, and only when the head is a whole delimited
                # token, all hex, 8+ characters, containing a digit: `preface…99999` is
                # prose wearing an approximation mark. Spaced groups are never exempt --
                # they are this repository's FIGURE formatting, and no hex tail has a space.
                if (
                    any(a <= m.start() < b for a, b in generated_spans)
                    and " " not in token
                    and m.start() > 0
                    and text[m.start() - 1] == "…"
                ):
                    head_end = m.start() - 1
                    head_start = head_end
                    while head_start > 0 and text[head_start - 1] not in " \t\n`|([{":
                        head_start -= 1
                    head = text[head_start:head_end]
                    if (
                        len(head) >= 8
                        and all(c in "0123456789abcdef" for c in head)
                        and any(c.isdigit() for c in head)
                    ):
                        continue
                n = int(token.replace(" ", ""))
                if n in exempt:
                    continue
                # Outside docs/, only figures near the word `gas` are in scope — and the
                # window is SYMMETRIC on the match's own line, because a lookahead-only
                # window is blind to "gas" BEFORE the number, and a live, arithmetically
                # false figure sat unexamined behind exactly that: the word came first in
                # its sentence, so the sweep never read the number.
                if not in_docs:
                    ls = text.rfind("\n", 0, m.start()) + 1
                    le = text.find("\n", m.end())
                    le = len(text) if le < 0 else le
                    rel = m.start() - ls
                    window = text[ls:le][max(0, rel - 40) : rel + (m.end() - m.start()) + 40]
                    # ...and the AUTHOR'S LINE WRAP is part of the window: a wrapped
                    # sentence puts its unit word one line from its figure ("forward
                    # 177 810, inverse 189 874, pointwise ⏎ ... gas per polynomial"),
                    # and a same-line window reads the number and never the unit. The
                    # two NEIGHBOURING lines only — the figure's own line is the ±40
                    # window's job, and folding it in here would let that window's
                    # symmetry guarantee rot unnoticed behind this one.
                    fig_line = text[: m.start()].count("\n")
                    wrapped = "\n".join(
                        lines[max(0, fig_line - 1) : fig_line]
                        + lines[fig_line + 1 : fig_line + 2]
                    )
                    if "gas" not in window and "gas" not in wrapped:
                        # A table cell's unit lives in its column HEADER, however far
                        # that is from the row: a figure under a `gas` column is a
                        # gas claim, and two swapped totals in a README table are
                        # invisible to the ±40 window exactly because the word sits
                        # in the header. Other columns (bytes, ratios) stay out of
                        # scope. The row parse tolerates GFM's optional pipes and
                        # blockquote containers, the same as the binding does.
                        row_no = text[: m.start()].count("\n")
                        row = lines[row_no]
                        if _row_cells(row) is None:
                            continue
                        top = row_no
                        while (top > 0 and lines[top - 1].strip()
                               and _row_cells(lines[top - 1]) is not None):
                            top -= 1
                        body_at = re.match(r"^[\s>]*", row).end()
                        lead = row[body_at:].startswith("|")
                        col_i = _pipes_before(row, rel) - (1 if lead else 0)
                        headers = [h.lower() for h in (_row_cells(lines[top]) or [])]
                        if not (top != row_no and 0 <= col_i < len(headers)
                                and "gas" in headers[col_i]):
                            continue
                line_no = text[: m.start()].count("\n")
                # A MARKER SCOPES THE PARAGRAPH IT INTRODUCES -- from the marker to the next
                # blank line, which is the scope a reader assumes from where it sits. A fixed
                # three-line window missed a figure five lines under a correctly placed marker;
                # an unbounded one would let one classification cover a whole section.
                start_of_para = line_no
                while start_of_para > 0 and lines[start_of_para - 1].strip():
                    start_of_para -= 1
                window = "\n".join(lines[max(0, start_of_para - 1) : line_no + 1])
                if MARKER.search(window):
                    continue
                quoted += 1
                # A figure whose context names a scheme must be that scheme's receipt
                # (or a difference among the named schemes).
                col = m.start() - (text.rfind("\n", 0, m.start()) + 1)
                bound, named = scheme_context(lines, line_no, doc, col)
                if bound and bound <= set(by_scheme):
                    cand = set().union(*(by_scheme[s] for s in bound))
                    pool = set().union(*(by_scheme[s]
                                         for s in named & set(by_scheme)))
                    cand |= {a - b for a in pool for b in pool if a > b}
                    if n in allowed and n not in cand:
                        line = text[: m.start()].count("\n") + 1
                        bad.append(
                            f"{doc.relative_to(root)}:{line}: {m.group(1)} is quoted for "
                            f"schemeId {'/'.join(str(s) for s in sorted(bound))} and is not "
                            f"one of that scheme's receipt figures (assigned to the wrong claim).")
                        continue
                if n not in allowed:
                    line = text[: m.start()].count("\n") + 1
                    # No `docs/` tier here, so this downgrades every miss. It is what
                    # separates `--all`'s report from the bare run's gate, and nothing else
                    # does now that both tuples name the same files.
                    if sweep_all:
                        untraced += 1
                        print(f"  UNTRACED {doc.relative_to(root)}:{line}: {m.group(1)}")
                        continue
                    bad.append(
                        f"{doc.relative_to(root)}:{line}: {m.group(1)} is quoted as gas and is "
                        f"not in measured.json. Re-run `harness/bench.py all --update` "
                        f"or fix the prose.")

    if sweep_all:
        print(f"\n{untraced} untraced gas figure(s) outside the docs directory "
              f"(expected {KNOWN_UNTRACED}).")
        if untraced != KNOWN_UNTRACED:
            bad.append(f"the untraced-figure count moved: {untraced}, expected "
                       f"{KNOWN_UNTRACED}. If figures were traced or marked, lower the "
                       f"constant in the same commit; if new ones appeared, they are the "
                       f"finding.")

    if bad:
        print(f"\nFAIL: {len(bad)} finding(s):")
        for b in bad:
            print(f"  {b}")
        return 1
    print(
        f"\nOK: snapshots name the expected environments and share one fixture; "
        f"all {quoted} unmarked gas figures quoted in prose appear in a snapshot. "
        f"Live re-execution: python3 harness/bench.py all --check."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
