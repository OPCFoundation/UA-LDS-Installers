# Opc.Ua.CertificateGenerator — OpenSSL 3.x port

A C re-implementation of the OPC UA certificate generator, built against **the
same OpenSSL distribution the LDS uses** (`LDS/stack/openssl-<arch>`, currently
3.5.7) instead of the end-of-life OpenSSL 1.1.1w the legacy tool pinned.

This directory used to be a git submodule pointing at
[OPCFoundation/Misc-Tools](https://github.com/OPCFoundation/Misc-Tools). The
submodule has been removed and replaced by this in-tree C project of the same
name. The original source remains in Misc-Tools for reference while the last
commands are ported.

**The command line is the contract.** Flags, long/short forms, defaults, usage
text, output parameter names and output ordering are all preserved. Every
intentional difference is listed under [Deviations](#deviations).

## Layout

| File | Contents |
|---|---|
| `CMakeLists.txt` | Build, OpenSSL discovery, hardening flags |
| `src/main.c` | Entry point and command dispatch (mirrors legacy `Main.cpp`) |
| `src/cmdline.c` | Argument parsing, usage text, output — the compatibility layer |
| `src/certops.c` | Certificate operations on the OpenSSL 3.x EVP interfaces |
| `src/util.c` | Strings, maps, UTF-8/UTF-16, files, hex — replaces the std:: and OpcUa_ helpers |
| `src/version.h` | Product identity and version — the single source for the resource |
| `src/Resource.rc`, `src/resource.h` | Win32 `VERSIONINFO` resource |

## Version

**2.1.342.10.**

The legacy tool shipped `1.1.342.10`; the major is bumped to 2 to mark the
OpenSSL 3.x rewrite, and the remaining components carry the lineage forward.
The identity strings — `CompanyName`, `ProductName`, `FileDescription`,
`InternalName`, `OriginalFilename`, `LegalCopyright`, `LegalTrademarks` — are
carried over from the original so the binary keeps its identity in Explorer's
Details tab and in Authenticode dialogs.

The legacy project split version data across three files that disagreed:
`Version.h` declared `1.01.333.0`, `BuildVersion.h` declared build `123`, and
`Resource.rc` hard-coded `1,1,342,10` — which, being the one the resource
compiler read, is what actually shipped. Here `src/version.h` is the only
place the numbers appear, and `Resource.rc` includes it.

To release a new version, edit `src/version.h`. Note this version is
independent of the LDS's `version.txt`; the tool is versioned as its own
product, as it was before.

## Building

`build.ps1` builds this automatically as phase 5b, after OpenSSL. Standalone:

```powershell
cmake -S CertificateGenerator -B CertificateGenerator/.build -A x64 -T v143 `
      -DCERTGEN_OPENSSL_ROOT=LDS/stack/openssl-x64
cmake --build CertificateGenerator/.build --config Release
```

Output: `Opc.Ua.CertificateGenerator.exe`. Both x64 and Win32 build clean at
`/W4` with no warnings.

## What this removes

The legacy build cloned and compiled **an entire second OpenSSL tree** (1.1.1w,
~15 minutes) solely for this one binary, then aliased `libcrypto.lib` to
`libeay32.lib` because the `.vcxproj` still referenced OpenSSL 1.0 library
names. All of that is gone. It also no longer links the OPC UA ANSI C stack:
the legacy code pulled in a vendored copy of the whole stack for status-code
constants, UTF-8/UTF-16 conversion and heap wrappers, which are a few dozen
lines of plain C in `src/util.c`.

## ECC support

All seven `-keyType` values work, covering every curve the OPC UA ECC
SecurityPolicies require:

| `-keyType` | Curve | OPC UA SecurityPolicy | Certificate signature |
|---|---|---|---|
| `rsa` | RSA (`-keySize`, default 2048) | `Basic256Sha256`, `Aes128_Sha256_RsaOaep`, `Aes256_Sha256_RsaPss` | RSA + SHA-256 |
| `nistP256` | `prime256v1` (secp256r1) | `ECC_nistP256`, `ECC-nistP256-ChaChaPoly` | ECDSA-SHA2-256 |
| `nistP384` | `secp384r1` | `ECC_nistP384`, `ECC-nistP384-ChaChaPoly` | ECDSA-SHA2-384 |
| `brainpoolP256r1` | `brainpoolP256r1` | `ECC_brainpoolP256r1` | ECDSA-SHA2-256 |
| `brainpoolP384r1` | `brainpoolP384r1` | `ECC_brainpoolP384r1` | ECDSA-SHA2-384 |
| `curve25519` | Ed25519 | `ECC_curve25519` | PureEdDSA-25519 |
| `curve448` | Ed448 | `ECC_curve448` | PureEdDSA-448 |

This required dropping `no-ec` from the OpenSSL build in `build.ps1` phase 2.
That configuration disabled `EC`, `ECDH`, `ECDSA`, `ECX` and `EC2M`, so no
elliptic curve work was possible against it at all. The flag is now gone and the
comment there says not to re-add it.

Each policy needs its own certificate and key matching the curve — one
certificate cannot serve several curves, though RSA and ECC certificates can
coexist in the same store. Issue one per policy you intend to offer.

### Certificate differences for ECC keys

ECC certificates are not RSA certificates with a different key in them. Per
**OPC UA Part 6 §6.2.2**:

> For RSA keys, the keyUsage shall include digitalSignature, nonRepudiation,
> keyEncipherment and dataEncipherment. For ECC keys, the keyUsage shall
> include digitalSignature. […] Self-signed Certificates shall also include
> keyCertSign.

So the two paths differ:

| | RSA | ECC |
|---|---|---|
| `keyUsage` | `digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyCertSign` (critical) | `digitalSignature` (critical), plus `keyCertSign` when self-signed |
| `basicConstraints` | `CA:TRUE, pathlen:0` (critical) — legacy, preserved | `CA:TRUE, pathlen:0` self-signed; `CA:FALSE` when CA-issued (critical) |
| `extendedKeyUsage` | `serverAuth, clientAuth` (critical) | `serverAuth, clientAuth` (not critical — optional for ECC profiles) |

An ECC key cannot encipher, so `keyEncipherment` and `dataEncipherment` are
meaningless on one: the ECC handshake agrees keys with ephemeral pairs, not with
the certificate key. The spec also notes other `keyUsage` bits are "allowed but
not recommended", so the ECC set is held to the required minimum rather than
copying the RSA list.

Two deliberate choices worth knowing about:

- **`basicConstraints` follows the spec for ECC, not the legacy RSA behaviour.**
  Part 6 says the CA flag must be `FALSE` for an application instance
  certificate, tolerating `TRUE` only as backward compatibility for self-signed
  ones. The RSA path keeps `CA:TRUE` because changing it would alter the trust
  semantics of certificates already deployed in the field; ECC support is new,
  with no installed base, so it starts correct.
- **`extendedKeyUsage` is not marked critical for ECC**, because the spec makes
  it optional there, and marking an optional extension critical invites
  rejection by a conformant validator that declines to parse it.

Note that some stacks still apply RSA-era `keyUsage` checks and expect
`keyAgreement` on an ECC certificate. The spec does not require it and
discourages extra bits, so it is not emitted. If you hit an interop problem
traceable to that, it is a two-line change in `cg_add_extensions`
(`src/certops.c`) — but raise it with the stack vendor too.

### Hash selection

`-hashSize` still wins when given explicitly. When it is not:

- An **ECC** key gets the hash its policy specifies — SHA-256 for the 256-bit
  curves, SHA-384 for the 384-bit ones — rather than inheriting the RSA default
  of 256. A P-384 certificate signed with SHA-256 is legal X.509 but is not what
  `ECC_nistP384` specifies.
- **Ed25519 / Ed448** ignore `-hashSize` entirely. PureEdDSA hashes internally
  and OpenSSL requires a `NULL` digest; there is nothing to select.
- The digest is chosen from the key that actually **signs**, which for a
  CA-issued certificate is the issuer's key, not the one just generated. Picking
  it from `-keyType` would pair an RSA CA's signature with an ECC default.

### Scope note

This makes the generator issue ECC certificates for every OPC UA ECC policy. It
does **not** mean the LDS can negotiate those policies — `opcualds.exe` uses the
vendored OPC UA ANSI C stack 1.04.342, which predates the ECC policies. Enabling
EC in OpenSSL is a prerequisite for that work, not the whole of it.

## Porting status

| Command | Status |
|---|---|
| `issue` (and the no-command default) | **Done** — self-signed, CA certificates, CA-issued certificates, `-reuseKey` |
| `revoke` / `unrevoke` | Not yet ported — CRL handling |
| `convert` / `install` / `password` | Not yet ported — key format and password changes |
| `replace` | Not yet ported — PFX certificate replacement |
| `request` | Not yet ported — CSR creation |
| `process` | Not yet ported — CSR signing |

Unported commands return `BadNotSupported` with a message pointing at the
legacy binary, rather than failing obscurely or appearing to succeed. Suggested
order for the remainder: `convert`/`password` (most used), then
`request`/`process`, then `revoke`/`unrevoke`, then `replace`.

Also not yet ported: the `LocalMachine` / `CurrentUser` Windows certificate
store paths. File-based stores — what the LDS PKI layout uses — are complete.
The legacy Windows-store code is pure CryptoAPI and ports largely unchanged.

## Verified behaviour

Checked against the legacy specification, with certificates inspected using the
LDS's own `openssl.exe`:

- Store layout and naming: `<store>\certs\<CN> [<THUMBPRINT>].der` and
  `<store>\private\<CN> [<THUMBPRINT>].pfx`, with `<>:"/\|?*` in the CN
  replaced by `+`, and intervening directories created
- Subject DN field order is reversed, as the legacy tool built it, so
  `-an MyApp -o MyCompany -dn MyHost` yields `DC=MyHost, O=MyCompany, CN=MyApp`
- Default subject name `CN`/`O`/`DC`, with `DC` omitted for CA certificates
- Default application URI `urn:<firstDomain>:<applicationName>`
- Extension set, exactly as below
- 30-day months: `-lm 12` gives 360 days
- Output parameters sorted by key, `\r\n` line endings, exit code always 0
- `-?` prints usage and then the legacy unprocessed-argument error
- A CA-issued certificate verifies against its CA with `openssl verify`

### Extension set

Application (non-CA) certificates:

```
subjectKeyIdentifier        hash
basicConstraints            critical, CA:TRUE, pathlen:0
keyUsage                    critical, nonRepudiation, digitalSignature,
                            keyEncipherment, dataEncipherment, keyCertSign
extendedKeyUsage            critical, serverAuth, clientAuth
subjectAltName              URI:<applicationUri>[,DNS:<domain>|,IP:<address>]...
authorityKeyIdentifier      keyid
```

CA certificates:

```
subjectKeyIdentifier        hash
basicConstraints            critical, CA:TRUE
keyUsage                    critical, digitalSignature, keyCertSign, cRLSign
authorityKeyIdentifier      keyid
```

**`CA:TRUE` on application certificates is wrong by modern PKI standards** — an
end-entity certificate should not be a CA, and `keyCertSign` on it is worse.
It is reproduced deliberately: it is what the legacy tool emitted, and OPC UA
deployments have been validating against these certificates for years.
Changing it would alter the trust semantics of every certificate this tool
issues, so it should be a deliberate, announced break rather than a side effect
of an OpenSSL port.

## Deviations

Behaviour was preserved wherever it was observable, including several oddities.
The line drawn: **observable behaviour is reproduced; memory-safety bugs and
silently-wrong cryptography are fixed.** Each fix is marked in the source.

### Fixed — memory safety

| Legacy | Fix |
|---|---|
| `IsArgSpecified` ran a `size_t` index down with an `ii >= 0` condition, always true; an all-whitespace argument value underflowed the index and read out of bounds | `cg_str_trim` handles the all-whitespace case |
| `ReadArgumentsFromFile` passed `sizeof(buffer)` to `fgetws` where a character count was required, permitting a write of twice the buffer size | Passes the element count |

### Fixed — silently wrong output

| Legacy | Fix |
|---|---|
| `OutputParameters["-code"] = e.GetCode()` assigned an `int` to a `std::string`, selecting the `char` overload — `-code` carried a single stray byte, the low octet of the status code | `-code` is the status code as `0x%08X` |
| `-hashSize 512` fell through a `switch` that only accepted 224/256/384 and silently produced a **SHA-1** signature, despite the usage text advertising 512 | 512 means SHA-512; 160 means SHA-1 explicitly |
| The URI escape format string was `"%%%2X"`, which space-pads rather than zero-pads, so byte `0x0A` became `"% A"` — a malformed escape | `%02X` |
| `inet_addr` recognises IPv4 only, so an IPv6 literal in `-domainNames` was emitted as `DNS:<literal>`, which is not a valid DNS SAN | `inet_pton` is tried for both families; IPv4 behaviour is unchanged |
| `authorityKeyIdentifier` resolved through OpenSSL's cached extension table, which is only populated for *decoded* certificates — self-signed certificates got an empty `AUTHORITY_KEYID` (printed `0.`), which some validators reject | Built explicitly from the issuer's subjectKeyIdentifier, or derived from its public key |

### Changed — serial numbers

Serial numbers are now 20 random bytes from the CSPRNG, forced positive. The
legacy tool derived them from a GUID on some paths and a counter on others. A
CSPRNG serial of at least 64 bits is required by the CA/Browser Forum baseline
requirements and expected by modern validators. This changes no interface, only
the values.

### Preserved — legacy quirks

Reproduced on purpose, because scripts may depend on them:

- **`-?` prints usage *and then* an error.** `-?` is never consumed as a
  recognised argument, so it remains in the argument map and is reported as
  `-error Unprocessed arguments exist possible syntax error.` after the usage
  text.
- **`-inlineOutput` / `-io` is documented but not implemented.** The usage text
  advertises it; the legacy parser never consumed it, so passing it produces
  the unprocessed-argument error. Reproduced rather than implemented, because
  implementing it would change output format for anyone currently passing it.
- **The usage text contradicts the real defaults.** It claims `-keySize`
  defaults to 1024 and `-lifetimeInMonths` to 60; the constructor used 2048 and
  12. The constructor wins, and the usage text is reproduced verbatim, so the
  contradiction survives intact.
- **`-startTime` is a raw `FILETIME`** — 100ns ticks since 1601-01-01 — not
  "nanoseconds from 1600-01-01" as the usage text says.
- **A trailing flag with no value is silently dropped**, as is a pending
  argument at end-of-file in a `-file` parameter file with no terminating
  newline.
- **`-command password` routes to the convert path**, not to the legacy
  `ChangePassword` method, which was never called.
- **The exit code is always 0.** Success and failure are reported through the
  output parameters; callers parse `-error` rather than checking `%ERRORLEVEL%`.
- **An empty `-password` still produces a password-marked PFX**, because the
  legacy code always passed the string to `PKCS12_create` rather than `NULL`.

## Testing

No automated tests yet. A differential harness that runs both binaries over a
matrix of argument combinations and compares stdout plus the generated
certificate structure would be the right way to prove parity for the remaining
commands as they land.
