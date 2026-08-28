#!/usr/bin/env python3
"""Re-derive every committed gas receipt from the protocol rule. No node required.

    check_measured.py [root]

Exit 0 if every receipt re-derives and every payload matches §6, 1 otherwise, 2 on usage error.

WHY THIS IS SEPARATE FROM THE HARNESS
-------------------------------------

`harness/announcement/measure.py` sends real transactions to a real node. That is the evidence,
and it is a deliberate local act: running it on every push would make the numbers a side effect
of a build.

This checks the committed result instead, arithmetically, from EIP-7623 and from §6's field
lengths -- so a figure that stopped matching its payload FAILS THIS CHECK, wherever it is
run. Without that, a wire
change moves every payload and nothing
detects that the committed receipts describe shapes the document no longer specifies.

**The arithmetic re-derivation covers the ANNOUNCEMENT receipts only, and the success line says
so because the distinction is invisible from the outside.** EIP-7623 prices calldata, and
an announcement is calldata-dominated, so its total is predictable from the payload. A
registration is dominated by STORAGE and a payment by two transfers; neither is predictable
from field lengths, so for those two the checks are provenance and binding -- the figure must
be a committed receipt, of the right scheme, from the right harness -- and not arithmetic. A
tampered registration receipt with matching prose passes, and saying so is worth more than a
success line that reads stronger than the code.

WHAT IT CANNOT SEE
------------------

It cannot tell whether the node was right. It re-derives the receipt from the rule the node was
supposed to be applying, so a client bug that affected both would pass here -- which is why the
harness's own self-check ALSO validates its execution probe against a second recovery path, and
why this file is a staleness gate rather than a correctness one.
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

# Documents that quote gas. A five-digit-or-more figure in one of these MUST be a figure the
# receipts contain, in either the `1 234` or the `1234` form.
#
# Exists because a deliberately wrong quoted measurement, planted as a probe, went
# unnoticed: the checks above verify
# that measured.json is internally consistent with §6, and the propagation checker guards
# retired figures it has been told about, so a figure typed by hand into prose was outside both.
# That is the same gap in a different place -- rule #54 requires a committed harness for every
# quoted number, and a number nothing compares against the harness is only nominally covered.
# THE DEFAULT SWEEP IS THE DOCUMENTS THAT SHIP, and it did not used to be. It was
# `docs/*.md` and `AUDIT.md`, from a tree that had both; this one has neither, so the bare
# invocation -- the one the README tells a reader to run -- swept nothing and reported "all 0
# unmarked gas figures quoted in prose are receipts". A gate whose scope has emptied still
# says OK, which is the failure this file exists to prevent, occurring inside it.
#
# `AUDIT.md` stays in the tuple. It does not ship here, and a glob that matches nothing costs
# nothing; what it buys is that a tree which reintroduces it does not have to remember to
# widen the gate. `--all` no longer widens the scope -- both tuples are the same set now --
# and what it still changes is the verdict: it REPORTS untraced figures against an expected
# count, where the bare run FAILS on them.
#
# EACH HARNESS'S README IS IN SCOPE, and was not. Those files quote the receipts their own
# harness produced, which is the shortest possible path from a measurement to a reader, and
# nothing checked them: `harness/payment/README.md` quoted an announcement at 69 510 and a
# payment at 111 510 for as long as it took nobody to notice, both superseded by 210 gas when
# the view tag narrowed to one byte, and both sitting beside the receipt that disagreed.
#
# THE SWEEP ONLY SEES A FIGURE THE WORD "gas" IS NEAR, which is the second half of how those
# two survived: the sentence quoting them never used the word, so widening the file scope
# alone would not have caught them. That is a real limit and it is stated rather than
# discovered -- prose that quotes a receipt should say `gas` next to it, and prose that does
# not is outside this gate whatever directory it lives in.
GAS_DOCS = ("docs/*.md", "AUDIT.md", "spec/ERC-*.md", "README.md",
            "harness/*/README.md")
GAS_DOCS_ALL = GAS_DOCS

# What `--all` finds today, asserted so that the gap is a number rather than a memory. A DROP
# is as much a finding as a rise: it means a figure was removed or marked, and either wants
# saying in a commit message.
# ZERO, and in this tree trivially so: every document the sweep covers is a gate, so a figure
# that is neither a receipt nor marked fails the bare run before it can be reported here. The
# audit that first drove this count to zero was done in the multi-scheme tree and classified
# thirteen figures one by one -- external, withdrawn, superseded. None of those figures came to
# this export, so the inventory did not travel with the constant; the rule did.
#
# A RISE IS A FINDING. A drop is too: it means a figure was removed or classified, and either is
# worth a sentence in the commit that did it.
KNOWN_UNTRACED = 0

# A figure this project did not measure is exempt WHEN IT SAYS SO, in a marker that names the
# source. An HTML comment, so it renders as nothing and greps as something:
#
#     <!-- gas-external: <where the number comes from> -->
#     <!-- gas-superseded: <why it is quoted anyway> -->
#
# On the figure's own line or within the three lines above it. The marker is required to carry
# text after the colon, because "exempt" without a source is the claim this check exists to stop.
#
# This is deliberately NOT a keyword sweep over the prose. "measured at", "roughly", "published"
# and "UNVERIFIED" all appear beside both kinds of figure in this repository, so a vocabulary
# list would exempt our own unbacked numbers along with other people's real ones.
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
    """Every number the SIZE model already accounts for, so it needs no gas provenance.

    Read from `derive_sizes` wholesale rather than listed, because the alternative is a denylist
    that excludes whatever is added next -- the failure mode this repository has now watched
    nine times. Every upper-case int and every int inside a tuple or dict value counts, plus the
    sums a document legitimately quotes: a shape's two fields added, and the hybrid combiner's
    2 402-byte IKM.
    """
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


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--all"]
    # ANY unknown flag and ANY extra positional, not just a leading one — the same
    # fail-closed rule the transcript checker states: `. --al` is a typo for the scope AUDIT
    # requires, and a verifier that silently narrows its sweep on a typo reports a pass it
    # never earned.
    unknown = [a for a in args if a.startswith("-")]
    if unknown or len(args) > 1:
        print(f"usage error: unexpected argument(s) {' '.join(unknown or args[1:])}",
              file=sys.stderr)
        print("usage: check_measured.py [root] [--all]   # both sweep the same documents "
              "-- the ERC, the root README and each harness's; --all REPORTS an untraced "
              "figure where the bare form FAILS on it",
              file=sys.stderr)
        print(__doc__)
        return 2
    root = Path(args[0] if args else ".").resolve()
    path = root / MEASURED
    if not path.is_file():
        print(f"usage error: no measurements at {path}", file=sys.stderr)
        return 2

    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("intrinsic_gas") != INTRINSIC:
        print(f"FAIL: the file states an intrinsic of {data.get('intrinsic_gas')}, not "
              f"{INTRINSIC}", file=sys.stderr)
        return 1
    if data.get("self_check") != "pass":
        print(f"FAIL: the harness's own self-check did not pass when this was written: "
              f"{data.get('self_check')}", file=sys.stderr)
        return 1

    cases = data.get("cases", [])
    bad: list[str] = []
    print(f"{len(cases)} committed receipt(s) from {MEASURED}")
    print(f"  {'scheme':<38}{'payload':>9}{'TOTAL':>10}{'re-derived':>12}  rule")
    for c in cases:
        name = c["name"]
        nz, z = c["nonzero"], c["zero"]
        execution = z.get("execution_gas")
        if execution is None:
            bad.append(f"{name}: the zero probe has no execution figure, so nothing can be "
                       f"re-derived from it")
            continue
        standard = INTRINSIC + 4 * nz["tokens"] + execution
        floor = INTRINSIC + 10 * nz["tokens"]
        predicted = max(standard, floor)
        which = "floor" if floor > standard else "standard"
        mark = "ok" if predicted == nz["total_gas"] else "MISMATCH"
        print(f"  {name:<38}{c['payload_bytes']:>9}{nz['total_gas']:>10}{predicted:>12}  "
              f"{which:<9}{mark}")
        if predicted != nz["total_gas"]:
            bad.append(f"{name}: EIP-7623 predicts {predicted}, the receipt says "
                       f"{nz['total_gas']}")
        if nz["floor_gas"] != floor:
            bad.append(f"{name}: the recorded floor {nz['floor_gas']} is not "
                       f"{INTRINSIC} + 10*{nz['tokens']} = {floor}")
        if nz["floor_binds"] != (floor > standard):
            bad.append(f"{name}: `floor_binds` is {nz['floor_binds']} and the rule says "
                       f"{floor > standard}")

        # THE STALENESS CHECK, and the reason this file exists. A receipt whose payload is not
        # the payload §6 specifies is measuring a shape the document withdrew.
        if c["schemeId"] == 1:
            continue
        want = derive_sizes.ANNOUNCE_ERC.get(name)
        if want is None:
            bad.append(f"{name}: not a row of §6's wire table, so its payload is unchecked")
        elif want[1] != c["payload_bytes"]:
            bad.append(f"{name}: measured {c['payload_bytes']} B where §6 specifies {want[1]} B "
                       f"-- the wire changed and this receipt did not. Re-run "
                       f"`harness/announcement/measure.py --json`.")
        shape = derive_sizes.SHAPES.get(name)
        if shape and (shape[0], shape[1]) != (c["epk_bytes"], c["metadata_bytes"]):
            bad.append(f"{name}: measured fields ({c['epk_bytes']}, {c['metadata_bytes']}) "
                       f"where §6 gives {shape}")

    # Every row of §6's table must HAVE a measurement, or §7 has a silent gap.
    measured_names = {c["name"] for c in cases}
    for name in derive_sizes.SHAPES:
        if name not in measured_names:
            bad.append(f"{name}: §6 has this row and nothing measured it")

    # --- every gas figure quoted in prose is one of the receipts ---------------------------
    # EVERY committed harness's receipts, not one file --
    # `announcement` prices one transaction and `payment` prices all three of a payment, and a
    # gate keyed on only one would report the other's figures as unfalsifiable. Read by glob,
    # because the alternative is a list of harnesses that a third one gets left out of.
    allowed: set[int] = set()
    # Membership alone is not a claim check: with every receipt number in ONE set,
    # the registration total vouches for a sentence about an announcement — both numbers are
    # receipts, both resulting claims false. So numbers are ALSO collected per scheme,
    # and a figure whose surrounding prose names a scheme must come from that scheme's
    # own receipts.
    by_scheme: dict[int, set[int]] = {}
    for receipts in sorted(root.glob("harness/*/measured.json")):
        try:
            body = json.loads(receipts.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            bad.append(f"{receipts.relative_to(root)}: not readable as JSON")
            continue
        for c in body.get("cases", []):
            sid = c.get("schemeId", c.get("scheme_id"))
            sids = {sid} if isinstance(sid, int) else set()
            # A receipt's NAME may declare coverage beyond its schemeId field:
            # "memo (schemeIds 4, 5)" is ONE measurement of a wire identical on
            # both schemes, and it vouches for both — the declaration is part of
            # the committed measurement artifact, not this tool's inference.
            for nm in re.finditer(r"schemeIds?\s+(\d)(?:\s*(?:,|and|/|or)\s*(\d))*",
                                  str(c.get("name", ""))):
                sids |= {int(g) for g in nm.groups() if g}
            for v in (c, c.get("nonzero") or {}, c.get("zero") or {}):
                if not isinstance(v, dict):
                    continue
                # `marginal_gas` is the per-call primitive cost the ntt harness reads as
                # gas(n+k)-gas(n) over repetitions -- not a transaction total, so it gets
                # its own key rather than borrowing one that claims to be a receipt of a
                # sent transaction.
                for k in ("total_gas", "floor_gas", "execution_gas",
                          "announce_gas", "fund_gas", "spend_gas", "marginal_gas"):
                    if isinstance(v.get(k), int):
                        allowed.add(v[k])
                        for s in sids:
                            by_scheme.setdefault(s, set()).add(v[k])
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
        for c in body.get("cases", []):
            for v in (c, c.get("nonzero") or {}, c.get("zero") or {}):
                if not isinstance(v, dict):
                    continue
                for k in ("calldata_bytes", "payload_bytes", "epk_bytes",
                          "metadata_bytes", "meta_address_bytes"):
                    if isinstance(v.get(k), int):
                        exempt.add(v[k])
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
                # A CONTIGUOUS digit run directly behind an ellipsis is exempt ONLY in a
                # transcript file, and only when the ellipsis truncates a real hex token:
                # the demo prints long values as head…tail, and a tail that happens to be
                # all digits — a small counter in big-endian hex ends in one, every time —
                # is bytes, not a figure. "Real hex token" is checked by walking back to the
                # token boundary, NOT by peeking at four characters: `preface…99999` has
                # four hex letters before the ellipsis and is still prose wearing an
                # approximation mark, and `deadbee7…99999` in ORDINARY prose is caught by
                # the file scope even though its head passes the token test. The head must
                # be a whole delimited token, all hex, at least 8 characters, containing a
                # decimal digit. Spaced groups are never exempt — they are this repository's
                # FIGURE formatting, and no hex tail contains a space.
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
                # A MARKER SCOPES THE PARAGRAPH IT INTRODUCES, not the three lines after it.
                #
                # Three lines was arbitrary and it showed: a marker placed correctly at the head
                # of a paragraph failed to reach a figure five lines down, so a figure that HAD
                # been classified still reported as untraced. Widened to the paragraph -- from
                # the marker to the next blank line -- which is the scope a reader would assume
                # from where the marker sits.
                #
                # Bounded by the blank line rather than unbounded, because a marker that reached
                # to the end of a section would let one classification quietly cover figures
                # nobody looked at.
                start_of_para = line_no
                while start_of_para > 0 and lines[start_of_para - 1].strip():
                    start_of_para -= 1
                window = "\n".join(lines[max(0, start_of_para - 1) : line_no + 1])
                if MARKER.search(window):
                    continue
                quoted += 1
                # THE BINDING CHECK: a figure whose context names a scheme must come
                # from that scheme's own receipts (or be a difference among the named
                # schemes' figures). A receipt number assigned to the wrong claim is
                # falser than an unsourced one — the membership test alone certified
                # exactly that. Contexts naming schemes with no receipts stay unbound
                # rather than failing: the membership test still applies to them.
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
                            f"one of that scheme's receipt figures — a receipt number "
                            f"assigned to the wrong claim is falser than an unsourced one.")
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
                        f"not in measured.json. Either re-run "
                        f"`harness/announcement/measure.py --json` or fix the prose -- a figure "
                        f"nothing re-derives is unfalsifiable.")

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
    print(f"\nOK: every ANNOUNCEMENT receipt re-derives from EIP-7623, every payload matches "
          f"§6's wire table, every row of that table has a measurement, and all {quoted} unmarked "
          f"gas figures quoted in prose are receipts. **The registration and payment receipts are "
          f"NOT re-derived** -- they are storage- and transfer-dominated rather than calldata-"
          f"dominated, so EIP-7623 does not predict them; a figure quoting one is checked to BE a "
          f"committed receipt of the right scheme, not to be arithmetically right. Marked paragraphs (gas-external, "
          f"gas-superseded, gas-withdrawn) are classified, not receipted — the marker names "
          f"why each is not a receipt, and this gate checks the marker exists, not the claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
