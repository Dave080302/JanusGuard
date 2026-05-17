# Design

This document expands on the architecture from the design PDF and describes
the modules, the data shapes that pass between them, and the rules the Risk
Engine applies.

## High-level pipeline

```
                    +-------------------+
                    |   CLI (cli.py)    |
                    | argparse, exit codes
                    +---------+---------+
                              |
                              v
+----------------+   +-------------------+   +---------------------+
|  APK on disk   |-->|  APK Reader       |-->|  Signature Analyzer |
|  (any path)    |   |  bytes + ZIP open |   |  v1 META-INF + APK  |
+----------------+   +---------+---------+   |  Signing Block scan |
                               |             +----------+----------+
                               v                        |
                     +-------------------+              |
                     | Structure Analyzer|              |
                     | magic@0, ZIP EOCD |              |
                     | DEX header sniff  |              |
                     +---------+---------+              |
                               |                        |
                               +------------+-----------+
                                            v
                                  +-------------------+
                                  |   Risk Engine     |
                                  | Finding[] + level |
                                  +---------+---------+
                                            |
                                            v
                                  +-------------------+
                                  | Report Generator  |
                                  | Markdown / HTML   |
                                  |     / JSON        |
                                  +-------------------+
```

The arrows are one-way. No module mutates the APK file, the ZIP archive
object, or the byte buffer it receives from upstream.

## Module responsibilities

### `apk_reader` — `read_apk(path) -> ApkReadResult`

- Validates that the path exists, is a regular file, and is not absurdly
  large (the read is capped at 512 MiB; real APKs are typically well under
  100 MiB).
- Reads the **whole file into memory** so that downstream analyzers can
  index by absolute offset without re-opening the file. This keeps the
  signing-block locator simple (look back from the End-of-Central-Directory
  record).
- Opens the same bytes as a `zipfile.ZipFile`. If the bytes are not a valid
  ZIP, this is recorded as a non-fatal fact (`is_valid_zip = False`) and
  downstream modules degrade gracefully — important because a Janus-shaped
  file may *also* be a valid ZIP, but a totally corrupt file is something we
  still want to report on.
- Computes a SHA-256 of the file contents for inclusion in the report
  (provenance, easy comparison across runs).

Output: an `ApkReadResult` dataclass with `path`, `file_size`, `sha256`,
`raw_data` (bytes), `first_bytes` (first 16 bytes), `is_valid_zip`,
`zip_comment`, `entry_names` (list of ZIP entry filenames), `entries`
(list of `ZipEntryInfo`), and `read_errors` (list of str).

### `signature_analyzer` — `analyze_signatures(apk) -> SignatureFindings`

Detects which APK Signature Scheme markers are present.

- **v1 (JAR signing).** Scans `entry_names` for the case-insensitive
  pattern: a `META-INF/MANIFEST.MF`, **at least one** `META-INF/*.SF`,
  and **at least one** `META-INF/*.RSA|DSA|EC`. All three must be present
  to count as v1.
- **v2 / v3 / v3.1.** Located by parsing the APK Signing Block, which sits
  immediately before the ZIP Central Directory. The locator:
  1. Finds the End-of-Central-Directory (EOCD) record by scanning back
     from end-of-file for the magic `PK\x05\x06` (searches up to
     64 KiB from end to handle ZIP comments).
  2. Reads the central-directory offset from EOCD.
  3. Looks at the 24 bytes immediately before that offset for the magic
     string `"APK Sig Block 42"` (16 bytes) and the preceding 8-byte
     block size field.
  4. Validates that the leading and trailing size fields match (malformed
     block → no signing-block detected).
  5. Walks the id–value pairs inside the block. Block IDs of interest:
     - `0x7109871a` — v2 scheme
     - `0xf05368c0` — v3 scheme
     - `0x1b93ad61` — v3.1 scheme
     - `0x42726577` — verity padding (recorded as informational)
     - `0x2146444e` — Google Play frosting (recorded as informational)
  6. Iteration is capped at 4 096 pairs to guard against malformed input.

This is **structural detection only**. We do not verify the contained
signatures; that is `apksigner`'s job. The point is to know which schemes
the APK *claims* to support — Janus is fundamentally a question of which
verification path Android will take.

Output: a `SignatureFindings` dataclass with booleans for each scheme
(`has_v1`, `has_v2`, `has_v3`, `has_v3_1`, `has_signing_block`), a
`scheme_summary()` method returning e.g. `"v1+v2"`, convenience properties
`v1_only` and `is_unsigned`, plus `v1_files`, `signing_block_ids`,
`signing_block_offset`, and `notes`.

### `structure_analyzer` — `analyze_structure(apk) -> StructureFindings`

Looks at the first few bytes and the ZIP layout for shapes associated with
the Janus pattern.

- Reads the first 8 bytes and classifies file magic:
  - `dex\n` prefix → DEX (version extracted from bytes 4-7)
  - `cdex` prefix → compact DEX (CDEX, ART optimization format)
  - `PK\x03\x04` → ZIP local file header (normal APK shape)
  - anything else → flagged as non-ZIP magic
- If DEX magic appears at offset 0 **and** the file is also a valid ZIP,
  this is the Janus pattern. `janus_pattern_detected` is set.
- Reads the DEX header `file_size` field at offset 32 (little-endian
  uint32). On a real Janus-style file this is the size of the prepended
  DEX, smaller than the actual file. Recorded in `dex_declared_file_size`.

Output: a `StructureFindings` dataclass with `starts_with_dex_magic`,
`dex_version`, `starts_with_cdex_magic`, `starts_with_zip_magic`,
`janus_pattern_detected`, `dex_declared_file_size`, and `notes`.

### `risk_engine` — `assess_risk(signatures, structure, target) -> RiskAssessment`

Converts the two findings dataclasses into a list of `Finding` records and
an overall `RiskLevel`.

Each `Finding` has `code`, `level`, `title`, and `detail`.
The complete rule set (evaluated in priority order):

| Code                     | Trigger                                              | Level                             |
| ------------------------ | ---------------------------------------------------- | --------------------------------- |
| `STRUCT-JANUS-PATTERN`   | DEX magic at offset 0 *and* file is a valid ZIP      | CRITICAL                          |
| `STRUCT-DEX-PREFIX`      | DEX magic at offset 0 but file is not a valid ZIP    | HIGH                              |
| `STRUCT-CDEX-PREFIX`     | `cdex` magic at offset 0                             | HIGH                              |
| `STRUCT-NO-ZIP-MAGIC`    | First 4 bytes are not `PK\x03\x04`                  | MEDIUM                            |
| `SIG-NONE`               | No v1 metadata and no APK Signing Block              | MEDIUM                            |
| `SIG-V1-ONLY`            | v1 present, v2/v3/v3.1 all absent                   | MEDIUM (HIGH with vulnerable ctx) |
| `SIG-V1-PLUS-MODERN`     | v1 + at least one of v2/v3/v3.1                      | LOW                               |
| `SIG-V1-FALLBACK-TARGET` | v1+v2/v3 *and* target is Android 5.x or 6.x         | HIGH                              |
| `SIG-MODERN-ONLY`        | v2 or v3 present, no v1                              | OK                                |
| `SIG-NOTE`               | Informational note from signing-block parser         | INFO                              |
| `STRUCT-NOTE`            | Informational note from structure parser             | INFO                              |

The overall `RiskLevel` is the maximum severity across all findings. Levels
in ascending order: `OK < INFO < LOW < MEDIUM < HIGH < CRITICAL`.

`SIG-V1-ONLY` escalates to `HIGH` when `--android-version` falls in 5–8
*and* `--patch-level` (if given) predates 2017-12-01.

`SIG-V1-FALLBACK-TARGET` is added on top of `SIG-V1-PLUS-MODERN` when
`--android-version` is 5.x or 6.x with a pre-2017-12 patch, because those
devices only verify v1, making the v2/v3 block ineffective.

### `report_generator` — `render_markdown` / `render_html` / `render_json`

Pure formatting. Each function takes `(apk, signatures, structure, risk)`
and emits a single string. None of the renderers write to disk — that is
the CLI's job.

- **Markdown** — human-readable, GitHub-flavoured tables and headers.
- **HTML** — standalone document with embedded CSS. No external assets,
  no JavaScript; safe to email or open from disk.
- **JSON** — machine-readable, pretty-printed. Suitable for CI pipelines,
  `jq` queries, or a future SARIF exporter. Top-level keys: `janusguard_version`,
  `generated_at`, `apk`, `signatures`, `structure`, `risk`.

## Data flow in a single run

1. CLI parses arguments; validates `--patch-level` format if given; builds
   a `TargetContext` (Android version, patch level, both optional).
2. For each APK path supplied (batch mode accepts multiple positional args):
   a. `read_apk(path)` → `ApkReadResult`
   b. `analyze_signatures(result)` → `SignatureFindings`
   c. `analyze_structure(result)` → `StructureFindings`
   d. `assess_risk(...)` → `RiskAssessment` (overall level + ordered findings)
   e. `render_markdown` / `render_html` / `render_json` writes files to
      `--output-dir`; optionally also prints to stdout.
3. CLI exits with a code mapped from the **worst** severity across all
   analyzed files:
   `OK/INFO/LOW→0`, `MEDIUM→10`, `HIGH→20`, `CRITICAL→30`,
   plus `2` for usage errors and `3` for read errors (only when no
   successful analysis was completed).

## Why this shape

- **Read once, analyze many times.** The reader produces a single immutable
  result; analyzers do not re-read the disk. This keeps the modules
  independent and test-friendly.
- **Findings are data, not strings.** Every conclusion is a `Finding` with
  a stable code, so reports are reproducible and downstream tools (CI, a
  future SARIF exporter) can consume them predictably.
- **Target context is optional.** The tool is useful on its own, but giving
  it an Android version turns "this APK is v1-only" from a `MEDIUM` advisory
  into a `HIGH` finding tied to a real device fleet.
- **Standard library only.** No runtime dependencies means no supply-chain
  surface for a security tool. Tests use `pytest`, which is dev-only.
- **Batch mode.** Multiple APK paths can be passed in one invocation; the
  exit code reflects the worst finding across all files, making it easy to
  use in shell glob patterns or CI matrix jobs.
