# Software Bill of Materials

CRA Annex I Part II(1) requires us to "identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products."

## SBOM per Project

The installed product is assembled from three repositories, and each is a public GitHub project that has to be able to publish an SBOM for itself. So each one owns a manifest describing only what it produces and links:

| Manifest | Owning repository | Declares |
|---|---|---|
| `LDS/sbom/components.json` | [OPCFoundation/UA-LDS](https://github.com/OPCFoundation/UA-LDS) | `opcualds.exe`, `dnssd.dll`, the vendored UA ANSI C stack, OpenSSL, the static CRT |
| `mDNSResponder/sbom/components.json` | [OPCFoundation/UA-LDS-mDNSResponder](https://github.com/OPCFoundation/UA-LDS-mDNSResponder) | `mDNSResponder.exe`, the static CRT |
| `sbom/components.json` | this repository | `ldsca.dll`, `Opc.Ua.CertificateGenerator.exe`, OpenSSL, the static CRT |

Nothing is declared twice across repositories. The installer manifest used to restate the submodules' components, which meant two places to update and an eventual disagreement; now it lists them as `subprojects` and composes.

`build.ps1` therefore produces **three SBOMs per architecture**:

```
out/<arch>/ua-lds-<version>-<arch>.cdx.json           # UA-LDS publishes this
out/<arch>/mdnsresponder-<version>-<arch>.cdx.json    # UA-LDS-mDNSResponder publishes this
out/<arch>/OPC-UA-LDS-<version>-<arch>.cdx.json       # the installed product
```

All three ship in the release ZIP.

## Files

| File | Purpose |
|---|---|
| `components.json` | This repository's inventory, plus the `subprojects` list |
| `New-Sbom.ps1` | Renders a manifest, and composes the product SBOM |

```powershell
# What a submodule publishes for itself
.\sbom\New-Sbom.ps1 -ManifestPath .\LDS\sbom\components.json -ProjectOnly `
                    -OutputPath .\out\ua-lds.cdx.json -Architecture x64

# The composed product SBOM
.\sbom\New-Sbom.ps1 -OutputPath .\out\lds-x64.cdx.json `
                    -Version 1.4.420.34 -Architecture x64 `
                    -SubprojectBomDir .\out -BinDir .\out\x64\bin
```

Each manifest is self-contained: `versionFrom.path` and `shaFrom` resolve relative to the project root of the manifest that declares them (the parent of its `sbom/` directory). A submodule manifest therefore renders identically whether driven from here or from its own repository.

## This repository is upstream for the generator

Each subproject carries a copy of `New-Sbom.ps1` beside its own manifest, so it can publish its SBOM without depending on this repository:

```
LDS/sbom/New-Sbom.ps1              <- copy
mDNSResponder/sbom/New-Sbom.ps1    <- copy
sbom/New-Sbom.ps1                  <- canonical; edit here
```

Run inside a submodule with no arguments beyond the output path:

```powershell
cd LDS
.\sbom\New-Sbom.ps1 -OutputPath .\ua-lds.cdx.json -Architecture x64
```
## Merge SBOMs

CycloneDX can express composition either by linking (BOM-Link) or by merging. This merges, because a market surveillance authority asking for "the SBOM" should get one self-contained document, and most tooling does not follow BOM-Links. The composed document still records an `externalReferences` entry of type `bom`, with a SHA-256, against each subproject's primary component, so the authoritative source stays identifiable and tamper-evident.

Two properties make ownership legible after the merge:

- `cra:ownerProject` — the repository that declared the component
- `cra:alsoDeclaredBy` — other repositories that declared the same component

A `compositions` block declares `aggregate: complete` for the product assembly, which is defensible because every manifest is curated under the process rule below and composition pulls in each subproject's own declaration.

### Deduplication

OpenSSL and the static MSVC runtime are linked by several projects, so each declares them, but they must not appear several times in the composed one. Identity is the **purl plus the component name**, not the purl alone: several artifacts can legitimately build from one source package at one commit (`opcualds.exe` and `dnssd.dll` both come from UA-LDS), and collapsing on purl alone silently dropped a shipped binary from the inventory during development. Dependency edges from every duplicate are redirected onto the surviving component, so the graph stays connected across the merge.

## What the generator resolves at build time

Hard-coding versions in a manifest invites drift. These are derived from the actual build instead:

- **Submodule commits** — `git describe`/`rev-parse` in each submodule, stamped into the component `purl` and a `cra:sourceCommit` property. This is what makes a released SBOM map back to exact source state, which is what makes "which versions are affected?" answerable within the Article 14 72-hour deadline.
- **Product version** — from `version.txt` + `build.txt` via `build.ps1`.
- **Component versions defined in source** — read straight out of the header that declares them (`versionFrom.kind: header`). The certificate generator is versioned independently of the LDS in `CertificateGenerator/src/version.h`, and that same header feeds its `VERSIONINFO` resource, so the SBOM and the binary's file properties cannot disagree. Restating the number in this manifest would have reintroduced exactly the three-way drift that header was written to end.
- **MSVC runtime version** — read from the toolset's `Microsoft.VCToolsVersion.v143.default.txt`.
- **SHA-256 digests** — computed over the staged, signed binaries, so the digests describe what actually ships. The certificate generator is staged separately from the per-arch `bin` directory, so `build.ps1` passes its location as `-ExtraBinDir`.

If git provenance is unavailable (uninitialised submodules, or `safe.directory` refusing a repository owned by another user), the generator warns and **omits** the affected identifiers rather than emitting a placeholder. An SBOM with a missing field is recoverable; one with a confidently wrong commit SHA is worse than none. If you see those warnings in a release build, fix the environment and rebuild — do not publish.
