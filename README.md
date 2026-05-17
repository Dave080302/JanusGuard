# JanusGuard

**A static, non-executing analyzer for Android APK files that flags risk indicators consistent with the Janus vulnerability (CVE-2017-13156).**

JanusGuard reads an APK from disk, inspects its signing schemes and ZIP/DEX layout, and produces a human-readable Markdown, HTML, or machine-readable JSON report. It never installs, executes, modifies, or uploads the APK.

The tool is built for the *Security of Mobile Devices* (SMD) course at UPB and is intended as an educational defensive scanner. It is **not** an offensive tool, malware sample, or installer.

---

## What is the Janus vulnerability?

CVE-2017-13156, named "Janus" by Guardsquare, is an Android signature bypass that affects devices running Android 5.0 through 8.0 with a pre-2017-12-01 security patch. An attacker can prepend a malicious DEX file to a legitimately signed APK; on a vulnerable device the runtime sees the DEX magic at offset 0 and executes the prepended DEX, while the package installer still considers the original v1 (JAR) signature valid because v1 only signs ZIP entries and ignores extra bytes.

The vulnerability is closed in two ways:

1. **APK Signature Scheme v2** (Android 7.0+) signs the entire APK byte stream from offset 0 to the start of the APK Signing Block, so prepended bytes invalidate the signature.
2. **The 2017-12-01 Android security patch** fixes the runtime side of the bug on devices that only verify v1.

Apps signed with both v1 and v2 are still exposed on Android 5.x/6.x devices, because those devices only verify v1 and fall back to the affected code path.

---

## What JanusGuard detects

For every APK it analyzes, JanusGuard reports:

- **Signing schemes present**: v1 (JAR), v2, v3, v3.1, and any other IDs found inside the APK Signing Block.
- **v1 META-INF artefacts**: the concrete `MANIFEST.MF`, `*.SF`, and `*.RSA`/`*.DSA`/`*.EC` files that triggered v1 detection.
- **Structural anomalies**: whether the file starts with DEX magic, whether it is also a valid ZIP, and whether the embedded DEX header is well-formed.
- **The signature Janus pattern**: starts-with-DEX-magic **and** parses-as-valid-ZIP simultaneously. This is the decisive structural indicator.
- **An overall risk level**: `OK`, `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- **Targeted mitigations**: re-signing instructions for v1-only APKs, isolation advice for Janus-style files.

The risk level is sharpened when the user supplies a target Android version and security patch level on the command line.

---

## What JanusGuard does **not** do

- It does not verify cryptographic signatures. Surface-level scheme detection is enough to make the Janus call.
- It does not parse `AndroidManifest.xml` (the binary AXML format is out of scope for this educational tool).
- It does not install, repackage, or modify APKs.
- It does not connect to the internet or upload anything.
- It cannot determine whether an APK is actually malicious - only that it has indicators that warrant manual review.

See [`docs/limitations.md`](docs/limitations.md) for the full list.

---

## Installation

JanusGuard targets Python 3.9 or newer and has **no runtime dependencies** beyond the standard library.

### Option A - editable install (recommended for development)

```bash
git clone https://github.com/<your-org>/janusguard.git
cd janusguard
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e .[dev]
```

This puts a `janusguard` command on your `PATH` and installs `pytest`, `black`, and `ruff` for development.

### Option B - run without installing

```bash
git clone https://github.com/<your-org>/janusguard.git
cd janusguard
PYTHONPATH=src python -m janusguard --help
```

---

## Usage

The general form is:

```bash
janusguard <path/to/file.apk> [<path/to/another.apk> ...] \
           [--android-version X.Y] [--patch-level YYYY-MM-DD] \
           [--format markdown|html|json|all] \
           [--output-dir reports/] [--stdout] [--quiet]
```

### Quick examples

```bash
# Generate the bundled test fixtures first.
python samples/generate_samples.py

# A clean, modern APK - expected verdict: OK.
janusguard samples/sample_modern.apk

# A Janus-style file - expected verdict: CRITICAL (all three report formats).
janusguard samples/sample_janus_style.apk --format all

# A legacy v1-only APK targeted at an unpatched Android 6.0 device - HIGH.
janusguard samples/sample_v1_only.apk \
    --android-version 6.0 --patch-level 2017-09-01 \
    --format all --stdout

# Batch mode - analyze every APK in a directory, worst exit code wins.
janusguard samples/*.apk --format json --output-dir reports/

# Machine-readable output piped to jq.
janusguard samples/sample_janus_style.apk --format json --stdout | jq '.risk.overall'
```

The Markdown report goes to `reports/<name>.report.md`, the HTML version to
`reports/<name>.report.html`, and the JSON version to `reports/<name>.report.json`.
The terminal summary on stderr looks like:

```text
[janusguard] sample_janus_style.apk: risk=CRITICAL schemes=v1
```

### CLI options

| Option | Purpose |
|---|---|
| `apk_path` (positional, repeatable) | Path(s) to APK file(s) to analyze. Multiple paths are accepted. |
| `--android-version` | Target Android marketing version, e.g. `6.0` or `8.0`. Used to sharpen the v1-only verdict. |
| `--patch-level` | Target security patch level in `YYYY-MM-DD` form, e.g. `2017-11-05`. Must be a valid date; an invalid format is a usage error. |
| `--format {markdown,html,json,all}` | Report format(s) to write. `all` writes Markdown, HTML, and JSON. Default: `markdown`. |
| `-o`, `--output-dir` | Directory to write reports into. Default: `./reports`. |
| `--stdout` | Also print the Markdown report (or JSON when `--format json`) to stdout. |
| `--quiet` | Suppress the human summary on stderr. |
| `--version` | Print the JanusGuard version. |

### Exit codes (useful in CI)

| Code | Meaning |
|---|---|
| `0` | Overall risk is `OK`, `INFO`, or `LOW`. |
| `10` | Overall risk is `MEDIUM`. |
| `20` | Overall risk is `HIGH`. |
| `30` | Overall risk is `CRITICAL`. |
| `2` | Usage error (handled by `argparse`). |
| `3` | The APK could not be read at all. |

---

## Test APKs

Because real APKs cannot always be redistributed, JanusGuard ships a generator (`samples/generate_samples.py`) that builds **five synthetic test fixtures** covering every code path in the analyzer. These files are real ZIP archives but they carry no valid cryptographic signatures, so they are not installable on a real device - they are intended only as input to the analyzer.

| Sample file | Description | Expected verdict |
|---|---|---|
| `samples/sample_modern.apk` | v2-only signing block, no v1 META-INF | `OK` |
| `samples/sample_v1_v2.apk` | v1 META-INF + signing block with v2 and v3 IDs | `LOW` |
| `samples/sample_v1_only.apk` | v1 META-INF only, no signing block | `MEDIUM` |
| `samples/sample_unsigned.apk` | Plain APK ZIP, no signing artefacts | `MEDIUM` |
| `samples/sample_janus_style.apk` | DEX header prepended to a v1-signed APK | `CRITICAL` |

Build them once:

```bash
python samples/generate_samples.py
```

The generator is fully deterministic; running it again overwrites the fixtures with byte-for-byte identical files.

### Testing on real APKs

The synthetic fixtures exercise the analyzer end-to-end, but you may also want to confirm verdicts on real, openly redistributable APKs:

- **F-Droid** (https://f-droid.org/) publishes thousands of open-source APKs. Modern releases (2020+) are typically signed with v1+v2 or v2-only and should produce `LOW` or `OK` verdicts. The F-Droid client itself is a good first test target.
- **Open-source app releases on GitHub** are often distributed as APK files attached to a release. Termux, K-9 Mail, NewPipe, and many others publish APKs this way.

Download an APK, place it anywhere on disk, and run `janusguard /path/to/that.apk`. To simulate the Janus exploit conditions, supply `--android-version 6.0 --patch-level 2017-09-01`.

> ⚠️ Do not download APKs from untrusted mirrors. JanusGuard only inspects bytes; it cannot tell you whether an APK is malicious. Always cross-check the publisher's signing-certificate hash before installing any APK on a real device.

---

## Project layout

```text
janusguard/
├── README.md                  # this file
├── LICENSE                    # MIT
├── pyproject.toml             # packaging + dev dependencies
├── .gitignore
├── src/janusguard/
│   ├── __init__.py            # package version and re-exports
│   ├── __main__.py            # python -m janusguard entry
│   ├── cli.py                 # argparse + main(); batch mode
│   ├── apk_reader.py          # safe file I/O and ZIP parsing
│   ├── signature_analyzer.py  # v1 META-INF + APK Signing Block parsing
│   ├── structure_analyzer.py  # DEX/ZIP magic + Janus pattern detection
│   ├── risk_engine.py         # rule-based classifier
│   └── report_generator.py    # Markdown + HTML + JSON rendering
├── tests/                     # pytest suite (47 tests, passing on Windows)
│   ├── conftest.py
│   ├── test_apk_reader.py
│   ├── test_signature_analyzer.py
│   ├── test_structure_analyzer.py
│   ├── test_risk_engine.py
│   ├── test_report_generator.py
│   └── test_cli.py
├── samples/                   # synthetic test fixtures + generator
│   ├── README.md
│   └── generate_samples.py
├── docs/
│   ├── design.md              # detailed architecture notes
│   ├── safety.md              # safety and scope statement
│   ├── limitations.md         # what JanusGuard does not do
│   └── ai_usage.md            # required AI-usage disclosure
└── reports/                   # generated reports (.md / .html / .json)
```

---

## Development

The project follows a small, predictable workflow.

### Run the test suite

```bash
python -m pytest -v
```

47 tests should pass in well under a second:

```text
============================= test session starts =============================
...
============================== 47 passed in 0.24s =============================
```

### Lint and format

```bash
python -m ruff check src tests samples
python -m black src tests samples
```

### Architecture in one paragraph

`cli.py` parses arguments (including optional multiple APK paths for batch mode), validates `--patch-level` format, then calls `read_apk` for each file. Each result is passed to `analyze_signatures` and `analyze_structure`. Their outputs plus an optional `TargetContext` go to `assess_risk`, which produces a `RiskAssessment`. Finally, `render_markdown`, `render_html`, and/or `render_json` produce the report(s). Each module is independently testable; see [`docs/design.md`](docs/design.md) for the full data-flow diagram.

### Code-review workflow

The repository uses GitHub pull requests. Every change goes through a PR, and the other team member reviews before merge. PRs that touch user-visible output include a sample report (paste from `reports/`) in the description.

---

## Safety statement

JanusGuard is a defensive, educational tool. It:

- never installs, runs, or repackages APKs,
- never attacks a device or modifies a real app,
- never carries or distributes malware,
- and only performs local, offline static analysis.

The synthetic samples produced by `samples/generate_samples.py` are deliberately non-installable: they contain placeholder signature files, no valid certificates, and a zero-content DEX stub. They are useful as analyzer input and nothing else.

See [`docs/safety.md`](docs/safety.md) for the complete scope statement.

---

## Authors

- **David-Tudor Anghel** (UPB, MSc SAS)
- **Omar Hossam Abdelmonem Mahmoud** (UPB, MSc SAS)

This project is the team's *Assignment 3* deliverable for the **Security of Mobile Devices (SMD)** course, 2026 cohort.

## AI usage disclosure

In keeping with the assignment requirements, our use of AI assistants during the project is documented in [`docs/ai_usage.md`](docs/ai_usage.md).

## License

MIT - see [`LICENSE`](LICENSE).

## References

- Guardsquare, *Janus Vulnerability: Threats and Mitigation*: https://www.guardsquare.com/blog/new-android-vulnerability-allows-attackers-to-modify-apps-without-affecting-their-signatures-guardsquare
- Android Open Source Project, *APK Signature Scheme v2*: https://source.android.com/docs/security/features/apksigning/v2
- Android Open Source Project, *APK Signature Scheme v3*: https://source.android.com/docs/security/features/apksigning/v3
- NIST National Vulnerability Database, *CVE-2017-13156*: https://nvd.nist.gov/vuln/detail/CVE-2017-13156
- Trend Micro, *Janus Android App Signature Bypass*: https://www.trendmicro.com/en_us/research/17/l/janus-android-app-signature-bypass-allows-attackers-modify-legitimate-apps.html
