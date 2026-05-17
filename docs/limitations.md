# Limitations

JanusGuard is deliberately small. This page lists what it does **not** do, so
that anyone reading a report understands its limits and does not over-trust
its verdicts.

## Not a cryptographic verifier

JanusGuard detects the **presence** of signing-scheme markers — v1 metadata
files in `META-INF/`, v2 / v3 / v3.1 block IDs in the APK Signing Block. It
does not:

- compute or verify any digest,
- parse the certificate chain,
- check that the signature actually validates against the contents,
- detect signature stripping where the bytes are present but malformed.

For real signature verification, use Android's `apksigner verify --verbose
--print-certs <apk>`.

## Not an AndroidManifest parser

We do not parse the binary AndroidManifest.xml inside the APK. That means
JanusGuard does **not** know:

- the package name,
- the `minSdkVersion`, `targetSdkVersion`, or `compileSdkVersion`,
- declared permissions or components,
- whether `android:debuggable` is set.

The target Android version comes from the user via `--android-version`, not
from the APK itself. This is intentional: a defender usually wants to ask
*"is this APK risky for the Android fleet I have?"*, not *"what does this APK
declare?"*.

## Not a DEX disassembler

We read the DEX header magic and the declared `file_size` field. We do not:

- parse the DEX string/type/method/class tables,
- list methods or classes,
- detect injected code,
- compute opcode coverage or any kind of similarity score.

If an APK is flagged with `STRUCT-JANUS-PATTERN`, the next step is a manual
review with a real DEX inspector (e.g. `androguard`, `jadx`, or `apktool`).

## No native code analysis

`lib/<abi>/*.so` files are listed as ZIP entries but not opened or inspected.
Native-code vulnerabilities are out of scope.

## No ZIP64

The signing-block locator and EOCD scan assume the ZIP-2.0 (non-ZIP64) End-of-
Central-Directory layout. Real APKs are virtually always ZIP-2.0 because
Android's `PackageParser` does not accept ZIP64, but JanusGuard would not
correctly locate the signing block in a ZIP64 archive. APKs > 4 GiB are not a
realistic case in practice.

## No streaming

The APK is read fully into memory (capped at 512 MiB). For typical APKs
(< 100 MiB), this is fine and dramatically simplifies absolute-offset math
into the byte buffer. Very large APKs will be refused with a read error.

## No network, no telemetry

JanusGuard never makes outbound connections. There is no rules-update
mechanism, no analytics, no submission to a cloud service. The rule set is
the Python code in `risk_engine.py`.

## Windows compatibility

The code is plain Python 3.9+ standard library and runs on Windows.
The full test suite (47 tests) passes on Windows 11 with Python 3.13.
One test (`test_html_escapes_filename`) was fixed to avoid creating a file
with `<>&` in its name, which Windows forbids; the test now injects the
special-character path via `dataclasses.replace` without touching the
filesystem.

## Detection completeness

The Janus pattern (`STRUCT-JANUS-PATTERN`) fires on the specific shape used
by the public PoC: a DEX header at offset 0 of a file that is also a valid
ZIP. There are other ways to construct a Janus-style file (for example,
non-zero offset where Android's parser tolerates it, or DEX magic with an
unusual `file_size` field). We do not claim to catch every variant — only
the canonical one that the original advisory and Guardsquare's write-up
describe.

Similarly, the `SIG-V1-FALLBACK-TARGET` rule uses a coarse cutoff
(Android ≤ 6.x). In reality the v1-only fallback is more nuanced (Android 7
introduced v2; some 7.x devices and ROMs differ in how strictly they enforce
v2). The cutoff is conservative on the alerting side and intentionally
overestimates risk rather than underestimating it.

## Not a replacement for real tooling

For production use, combine JanusGuard's output with:

- `apksigner verify --verbose --print-certs` for actual signature validation,
- Google's [App Bundle / Play Integrity API](https://developer.android.com/google/play/integrity)
  for runtime app integrity,
- a dedicated mobile-app SCA tool (MobSF, etc.) for broader static analysis,
- and an actual Android security update — the real fix for Janus is running a
  device patched on or after 2017-12-01.
