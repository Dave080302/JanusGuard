# AI / LLM Usage Disclosure

The assignment explicitly asks teams to document how they used AI / LLMs.
This page is that disclosure.

## What we used

- **Claude (Anthropic)** as a paired coding and research assistant during
  implementation.
- No code-generation IDE plugins, no autocomplete copilots, no fine-tuned
  models. Plain chat with the assistant in a sandboxed environment.

## What we did *not* delegate to AI

- **Project idea and scope.** Janus / CVE-2017-13156 was our choice, picked
  because it is a real, well-documented Android CVE that can be studied
  safely without exploiting any real app. The one-pager
  (`David_Anghel_Omar_Mahmoud_JanusGuard_SAS_SMD_assignment3_project_idea.pdf`)
  and design document
  (`David_Anghel_Omar_Mahmoud_JanusGuard_SAS_SMD_assignment3_project_design.pdf`)
  were authored by us before any code was written, in line with the
  instruction *"For project description, design, planning, we encourage to
  do them yourselves and resort to AI / LLMs for polishing and review /
  feedback."*

- **Architectural decisions.** The five-module pipeline (Reader → Signature
  Analyzer → Structure Analyzer → Risk Engine → Report Generator), the
  decision to use only the Python standard library, and the choice to keep
  the tool defensive-only with no exploitation surface, were all decided in
  the design phase before implementation.

- **The cryptographic / structural claims.** We did not accept the AI's
  word on the APK Signing Block layout, scheme block IDs, or DEX magic
  values. Every byte-level fact in the implementation was cross-checked
  against:
  - The AOSP source documentation for APK Signature Scheme v2 and v3,
  - Guardsquare's public technical write-up of CVE-2017-13156,
  - The NVD entry for CVE-2017-13156,
  - The official Android Security Bulletin (December 2017).

  When the assistant initially produced plausible-looking but
  unverified values, we required it to web-search and cite primary
  sources before merging the change.

## What we did delegate to AI

- **Boilerplate scaffolding.** `pyproject.toml`, `.gitignore`, `LICENSE`
  (MIT), the `tests/conftest.py` fixtures, and the repetitive parts of the
  test suite were drafted by the assistant and then reviewed.

- **Implementation of well-specified modules.** Once we agreed on the API
  for a module (e.g. *"`analyze_signatures` takes an `ApkReadResult` and
  returns a `SignatureFindings` dataclass with these fields"*), the
  assistant produced a first draft of the Python code. We reviewed each
  draft for:
  - correctness against the verified spec,
  - adherence to "standard library only" and "read-only" constraints,
  - clear failure modes (a corrupt ZIP must not crash the analyzer),
  - test coverage of the edge cases we cared about.

- **Documentation polish.** This document, `safety.md`, `design.md`,
  `limitations.md`, and the README were drafted by the assistant from our
  notes, then edited by us for accuracy and tone. The PDFs (one-pager and
  design plan) were authored by us; the AI did not write them.

- **Synthetic sample generation.** The `samples/generate_samples.py`
  script — which builds five small, non-installable APK-shaped test
  fixtures — was implemented by the assistant. We specified the five
  shapes (modern v2-only, v1+v2+v3, v1-only, unsigned, janus-style) and
  validated that each fixture produced the expected verdict end-to-end.

- **Test brainstorming.** Asking *"what edge cases could break the
  signing-block locator?"* and getting back a list (no EOCD, EOCD past end
  of file, signing-block magic in a comment, zero-length value, etc.) is a
  good use of a paired LLM. Each suggestion was evaluated individually
  before being turned into a test.

- **Code review and bug finding.** In a subsequent session we asked the
  assistant to audit the completed codebase and identify real defects. It
  found — and we verified against the AOSP spec — an off-by-8 error in the
  signing-block pair bounds check inside `_parse_signing_block_ids`
  ([`signature_analyzer.py`](../src/janusguard/signature_analyzer.py),
  line 300): the condition `cursor + 8 + pair_length > pairs_end + 8`
  allowed a parsed pair to read 8 bytes into the trailing size field.
  Corrected to `> pairs_end`.

  A second cosmetic defect was also found: `head[:4]` was applied to a
  variable `head` that was already `data[:4]` — redundant but harmless,
  cleaned up in `structure_analyzer.py`.

  A pre-existing test failure on Windows — `test_html_escapes_filename`
  tried to create a file named `<weird&name>.apk`, which Windows forbids —
  was fixed by injecting the special-character path via `dataclasses.replace`
  instead of touching the filesystem.

- **Feature extensions.** Three improvements were implemented with the
  assistant in the same session:
  - **JSON output** (`--format json` / `--format all`): a new
    `render_json` function in `report_generator.py` produces a
    machine-readable, pretty-printed JSON report suitable for CI pipelines
    and `jq` queries.
  - **Batch mode**: the CLI now accepts multiple APK paths in one
    invocation; the exit code reflects the worst finding across all files.
  - **`--patch-level` format validation**: previously a garbage string
    was silently treated as "predates the fix", escalating risk without
    warning the user. The CLI now validates the format and exits with a
    usage error.

## How we kept the AI honest

Two practices we held to throughout:

1. **No file path or library claim is trusted without a `view` / `ls` /
   `pip show` check.** Early on the assistant tried to reference paths and
   community-repo contents that did not exist; once flagged, the
   expectation was made explicit: *no verification, no merge*.

2. **All claims about the Janus CVE, the APK Signing Block format, and
   the DEX header layout are anchored to a primary source.** Where a
   value would have been easy to hallucinate (e.g. the v3.1 block ID,
   `0x1b93ad61`, or the verity padding ID, `0x42726577`), we web-searched
   the AOSP source and Guardsquare's write-up and only then committed the
   constant.

## Net assessment

The AI accelerated implementation substantially — probably by a factor of
three or four on the mechanical parts (test scaffolding, dataclass
boilerplate, HTML report templating). It did **not** make the security
decisions, design the architecture, or author the design PDFs. Every
non-trivial technical claim in the codebase was verified against primary
sources before being committed.

— David-Tudor Anghel & Omar Hossam Abdelmonem Mahmoud
