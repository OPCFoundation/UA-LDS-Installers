# UA-LDS-Installers

Build and packaging repository for the **OPC UA Local Discovery Server (LDS)** Windows installer.

This repository contains no product source of its own. It pulls the source trees in as git
submodules, compiles them, signs the binaries, and packages everything into a Windows Installer
package. If you are looking for the LDS source code itself, see
[OPCFoundation/UA-LDS](https://github.com/OPCFoundation/UA-LDS).

## What gets built

A single run of `build.ps1` produces, for both x86 and x64:

| Artifact | Location | Contents |
| --- | --- | --- |
| `opc-ua-lds-<version>-<arch>.msi` | `out\wix\` | The end-user installer |
| `opc-ua-lds-mergemodule-<version>-<arch>.msm` | `out\wix\` | Merge module, for vendors embedding the LDS in their own installer |
| `OPC-UA-Local-Discovery-Server-<version>.zip` | `dist\` | Redistributable bundle: both MSIs, both MSMs, and the changelog |

`<version>` is the full four-part version — `MAJOR.MINOR.REVISION` from `version.txt` plus the
build number from `build.txt`, which the script increments on every run (e.g. `1.4.420.36`).

The MSI installs two Windows services and opens the firewall ports they need:

- **opcualds.exe** — the Local Discovery Server itself, on TCP 4840.
- **OPCF Bonjour Service** (mDNSResponder) — multicast discovery, on UDP 5353.

It also lays down `dnssd.dll`, a default `ualds.ini`, and the PKI directory tree. A separately
selectable feature installs `Opc.Ua.CertificateGenerator.exe`, a CLI companion for managing the
LDS certificate store.

## Repository layout

| Path | What it is |
| --- | --- |
| `build.ps1` | The whole build pipeline (see below) |
| `version.txt` / `build.txt` | Version components; `build.txt` is auto-incremented per build |
| `LDS/` | *Submodule* — [UA-LDS](https://github.com/OPCFoundation/UA-LDS): `opcualds.exe`, `dnssd.dll` |
| `mDNSResponder/` | *Submodule* — [UA-LDS-mDNSResponder](https://github.com/OPCFoundation/UA-LDS-mDNSResponder): the Bonjour service |
| `CertificateGenerator/` | *Submodule* — [Misc-Tools](https://github.com/OPCFoundation/Misc-Tools): the legacy certificate generator |
| `CustomActions/` | Source for `ldsca.dll`, the MSI custom actions |
| `WiX/` | WiX v4 authoring: `Installer.wxs`, `MergeModule.wxs`, license text, branding |
| `cmake/` | `Hardening.cmake` — shared compiler/linker hardening flags |
| `build/`, `out/`, `dist/` | Intermediate build trees, staged binaries, final redistributable |

## Prerequisites

- Visual Studio 2022 or newer, C++ desktop workload, **MSVC v143** toolset
- CMake 3.20+
- WiX v4+ — `dotnet tool install --global wix`
- Strawberry Perl (required by OpenSSL's `Configure`)
- AzureSignTool, only if you are code signing — `dotnet tool install --global AzureSignTool`

## Building

```powershell
git clone --recurse-submodules https://github.com/OPCFoundation/UA-LDS-Installers.git
cd UA-LDS-Installers
.\build.ps1
```

Useful switches:

| Switch | Effect |
| --- | --- |
| `-Platform x86\|x64\|both` | Which architectures to build (default `both`) |
| `-Clean` | Delete the CMake build trees first (does *not* rebuild OpenSSL) |
| `-CleanOpenSSL` | Force a re-fetch and rebuild of OpenSSL |
| `-Spectre` | Add `/Qspectre` (needs the Spectre-mitigated libs from the VS Installer) |
| `-SkipWix` | Compile the binaries but don't package anything |

The first build takes considerably longer than later ones because it clones and compiles OpenSSL
from source for each architecture; the result is cached and reused.

### Pipeline

`build.ps1` runs these phases:

1. Bump `build.txt`, generate `LDS\buildversion.h`, and patch the version defines in `LDS\config.h`.
2. Per arch — build **OpenSSL 3.5.7** from upstream source (static, cached).
3. Per arch — build UA-LDS (`opcualds.exe`, `dnssd.dll`) via CMake.
4. Per arch — build `mDNSResponder.exe` via msbuild against its legacy solution.
5. Per arch — build `ldsca.dll` (the MSI custom actions).
6. Once — build `Opc.Ua.CertificateGenerator.exe`.
7. Per arch — stage the binaries into `out\<arch>\bin\` and sign them.
8. Per arch — build the merge module and the MSI with WiX, and sign them.
9. Bundle the redistributable ZIP.

### Code signing

Signing is enabled automatically when `$env:SigningClientSecret` is set, and skipped otherwise —
so an unsigned local build needs no configuration. To sign, set all of:

```
SigningVaultURL  SigningClientId  SigningClientSecret
SigningTenantId  SigningCertName  SigningURL
```

## Notes

- **`CertificateGenerator` is pinned to OpenSSL 1.1.1w** and is built with its own bundled copy,
  separately from the 3.5.7 build used by everything else. This is a stopgap: the tool cannot be
  moved to a current OpenSSL without a rewrite that preserves its command-line interface, and the
  binary is still shipped under the CertGenerator MSI feature.
- **Do not regenerate the `UpgradeCode` GUID** in `build.ps1`. It is carried over from the original
  InstallShield project, and field installs depend on it to upgrade cleanly rather than installing
  side-by-side.
- Help is no longer bundled in the installer. Documentation is served online at
  <https://opcfoundation.github.io/UA-LDS/>.

## License

MIT — see [LICENSE.md](LICENSE.md).
