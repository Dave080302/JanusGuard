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
                                  +-------------------+
```

The arrows are one-way. No module mutates the APK file, the ZIP archive
object, or the byte buffer it receives from upstream.

## Module responsibilities

### `apk_reader` — `ApkReader.read(path)`

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

Output: an `ApkReadResult` dataclass with `path`, `size`, `sha256`, `data`
(bytes), `is_valid_zip`, `zip_names` (list of entry names), and
`zip_error` (str or `None`).

### `signature_analyzer` — `SignatureAnalyzer.analyze(read_result)`

Detects which APK Signature Scheme markers are present.

- **v1 (JAR signing).** Looked up by scanning `zip_names` for the
  case-insensitive pattern: a `META-INF/MANIFEST.MF`, **at least one**
  `META-INF/*.SF`, and **at least one** `META-INF/*.RSA|DSA|EC`. All three
  must be present to count as v1.
- **v2 / v3 / v3.1.** Located by parsing the APK Signing Block, which sits
  immediately before the ZIP Central Directory. The locator:
  1. Finds the End-of-Central-Directory (EOCD) record by searching back
     from end-of-file for the signature `0x06054b50` (we look in the last
     64 KiB, which is the max EOCD size).
  2. Reads the central-directory offset from EOCD.
  3. Looks at the 24 bytes immediately before that offset for the magic
     string `"APK Sig Block 42"` (16 bytes) and the preceding 8-byte block
     size.
  4. Walks the id–value pairs inside the block. Block IDs of interest:
     - `0x7109871a` — v2 scheme
     - `0xf05368c0` — v3 scheme
     - `0x1b93ad61` — v3.1 scheme
     - `0x42726577` — verity padding (ignored, recorded as informational)

This is **structural detection only**. We do not verify the contained
signatures; that is `apksigner`'s job. The point is to know which schemes
the APK *claims* to support — Janus is fundamentally a question of which
verification path Android will take.

Output: a `SignatureFindings` dataclass with booleans for each scheme, a
`scheme_summary()` like `"v1+v2"`, and convenience properties `v1_only`
and `is_unsigned`.

### `structure_analyzer` — `StructureAnalyzer.analyze(read_result)`

Looks at the first few bytes and the ZIP layout for shapes associated with
the Janus pattern.

- Reads the first 8 bytes and classifies file magic:
  - `dex\n035\0` .. `dex\n041\0` → DEX (versions 035 through 041)
  - `cdex001\0` → compact DEX (CDEX, ART optimization format)
  - `PK\x03\x04` → ZIP local file header (normal APK shape)
  - anything else → `unknown`
- If DEX magic appears at offset 0 **and** the file is also a valid ZIP,
  this is the Janus pattern (a file Android's v1 verifier would accept as a
  ZIP while DEX-aware code would treat as DEX). `janus_pattern_detected`
  is set.
- Reads the DEX header `file_size` field at offset 32 (little-endian
  uint32). On a real Janus-style file, this is the size of the prepended
  DEX, **smaller** than the actual file. We record `dex_declared_size` and
  the actual file size so the report can show the mismatch.

Output: a `StructureFindings` dataclass with `magic_bytes`, `magic_kind`,
`dex_at_offset_zero`, `is_valid_zip` (mirrored from the reader),
`janus_pattern_detected`, and optional `dex_declared_size`.

### `risk_engine` — `RiskEngine.assess(signature_findings, structure_findings, target_context)`

Converts the two findings dataclasses into a list of `Finding` records and
an overall `RiskLevel`.

Each `Finding` has a code, severity, title, description, and mitigation.
The current rule set:

| Code                          | Trigger                                             | Severity                          |
| ----------------------------- | --------------------------------------------------- | --------------------------------- |
| `STRUCT-JANUS-PATTERN`        | DEX magic at offset 0 *and* file is a valid ZIP     | CRITICAL                          |
| `STRUCT-MAGIC-UNKNOWN`        | First bytes are neither ZIP nor DEX/CDEX            | LOW                               |
| `STRUCT-ZIP-INVALID`          | ZIP could not be parsed                             | MEDIUM                            |
| `SIG-UNSIGNED`                | No v1 metadata and no APK Signing Block             | MEDIUM                            |
| `SIG-V1-ONLY`                 | v1 present, v2/v3/v3.1 all absent                   | MEDIUM (HIGH with vulnerable ctx) |
| `SIG-V1-FALLBACK-TARGET`      | v1 + v2/v3 *and* target Android ≤ 6.x               | HIGH                              |
| `SIG-MODERN`                  | v2 or v3 present, v1 absent                         | OK                                |
| `SIG-COMPAT`                  | v1 + v2/v3 on modern target (or no target given)    | LOW                               |
| `CTX-VULN-ANDROID`            | Android ≤ 7.x or patch level < 2017-12-01           | INFO (raises ceiling)             |

The overall `RiskLevel` is the maximum severity across all findings.

### `report_generator` — `render_markdown(report)` / `render_html(report)`

Pure formatting. Takes the assembled `Report` (which wraps the original
findings, the rule findings, and metadata like SHA-256 and timestamp) and
emits a single Markdown or HTML string. The HTML is standalone — embedded
CSS, no external assets, no JavaScript — so reports are safe to open from
disk and email around.

## Data flow in a single run

1. CLI parses arguments and builds a `TargetContext` (Android version,
   patch level, both optional).
2. `ApkReader.read(path)` → `ApkReadResult`.
3. `SignatureAnalyzer.analyze(read_result)` → `SignatureFindings`.
4. `StructureAnalyzer.analyze(read_result)` → `StructureFindings`.
5. `RiskEngine.assess(...)` → `Report` (overall level + ordered findings).
6. `render_markdown` / `render_html` writes to `reports/<apk>.md` or
   `reports/<apk>.html`, or both, or stdout.
7. CLI exits with a code mapped from severity:
   `OK→0`, `INFO/LOW→0`, `MEDIUM→10`, `HIGH→20`, `CRITICAL→30`,
   plus `2` for usage errors and `3` for read errors.

## Why this shape

- **Read once, analyze many times.** The reader produces a single immutable
  result; analyzers do not re-read the disk. This keeps the modules
  independent and test-friendly.
- **Findings are data, not strings.** Every conclusion is a `Finding` with
  a stable code, so reports are reproducible and downstream tools (CI, a
  future SARIF exporter) can consume them.
- **Target context is optional.** The tool is useful on its own, but giving
  it an Android version turns "this APK is v1-only" from a `MEDIUM` advisory
  into a `HIGH` finding tied to a real device fleet — exactly the
  information a defender needs.
- **Standard library only.** No runtime dependencies means no supply-chain
  surface for a security tool. Tests use `pytest`, which is dev-only.
