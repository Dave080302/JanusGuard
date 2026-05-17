# Sample APKs

This directory contains five synthetic APK-shaped files used as test
fixtures for JanusGuard. They are **not real applications** and **not
installable on Android** — they exist only to exercise specific code paths
in the analyzer.

## Files

| File                     | Shape                                              | Expected verdict |
| ------------------------ | -------------------------------------------------- | ---------------- |
| `sample_modern.apk`      | Valid ZIP, v2 signing-block ID present, no v1.     | `OK`             |
| `sample_v1_v2.apk`       | Valid ZIP, META-INF v1 metadata + v2 + v3 blocks.  | `LOW`            |
| `sample_v1_only.apk`     | Valid ZIP, META-INF v1 metadata, no signing block. | `MEDIUM`         |
| `sample_unsigned.apk`    | Valid ZIP, no v1 metadata, no signing block.       | `MEDIUM`         |
| `sample_janus_style.apk` | DEX magic prepended to a valid ZIP.                | `CRITICAL`       |

## Why they exist

A defensive analyzer needs reproducible inputs that span its rule set.
Real-world APKs vary along too many axes to make good unit-test fixtures,
and redistributing third-party APKs would raise licensing and provenance
questions.

These five fixtures cover every branch of the Risk Engine:

- `STRUCT-JANUS-PATTERN` — `sample_janus_style.apk`
- `SIG-V1-ONLY`          — `sample_v1_only.apk`
- `SIG-UNSIGNED`         — `sample_unsigned.apk`
- `SIG-COMPAT`           — `sample_v1_v2.apk`
- `SIG-MODERN`           — `sample_modern.apk`

The target-context escalation rules (`SIG-V1-FALLBACK-TARGET`,
`CTX-VULN-ANDROID`) are tested by passing `--android-version` and
`--patch-level` on top of the same files.

## Why they are not installable

Each fixture is byte-shaped to satisfy JanusGuard's detection rules:

- The ZIP archives contain placeholder entries (`AndroidManifest.xml`,
  `classes.dex`, `META-INF/...`) whose **contents are not valid**. The
  AndroidManifest is not a binary AXML resource; the DEX is a 40-byte
  header stub, not real bytecode.
- The "APK Signing Block" we inject for v2/v3 cases contains the correct
  magic and id–value framing, but the signing-block values are zeros.
  Real cryptographic verification would fail immediately.
- `sample_janus_style.apk` literally has `dex\n035\0` at offset 0, which
  Android's `PackageParser` would reject before installation.

In other words: these files trip the detector without containing anything
that could ever be packaged and shipped.

## Regenerating

The fixtures are checked into the repository so that the test suite is
deterministic and runnable from a clean clone. If you want to regenerate
them — for example, after editing `generate_samples.py` — run:

```bash
python samples/generate_samples.py
```

This deletes and rewrites the five `.apk` files in this directory.

## Testing against real APKs

We strongly recommend testing JanusGuard on real APKs in addition to these
fixtures. Open-source releases from **F-Droid** (https://f-droid.org) are
ideal: they are openly published, signed with traceable keys, and intended
to be inspected. See the *Testing with real APKs* section of the top-level
`README.md` for a one-liner.
