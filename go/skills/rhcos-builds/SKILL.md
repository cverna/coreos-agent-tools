---
name: rhcos-builds
description: RHCOS build system - repositories, packages, version mappings, artifacts, and coreos-assembler
---

# RHCOS Builds

Comprehensive knowledge about the RHEL CoreOS build system, GitHub repositories, packages, and tooling.

## Build Process Overview

RHCOS is built in two stages:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RHCOS Build Pipeline                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────┐     ┌──────────────────────┐                      │
│  │ fedora-coreos-config │     │ coreos-assembler     │                      │
│  │ (upstream manifests) │     │ (cosa build tool)    │                      │
│  └──────────┬───────────┘     └──────────┬───────────┘                      │
│             │ submodule                   │                                  │
│             ▼                             │                                  │
│  ┌──────────────────────┐                 │                                  │
│  │ rhel-coreos-config   │─────────────────┤                                  │
│  │ (RHCOS packages)     │                 │                                  │
│  └──────────┬───────────┘                 │                                  │
│             │                             │                                  │
│             ▼                             ▼                                  │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │              Jenkins: build job (x86_64)            │                    │
│  │         (builds RHCOS base container image)         │                    │
│  └───────────────────┬─────────────────────────────────┘                    │
│                      │                                                       │
│         ┌────────────┼────────────┐                                          │
│         ▼            ▼            ▼                                          │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐                                  │
│  │build-arch │ │build-arch │ │build-arch │  (triggered by build job)        │
│  │ aarch64   │ │ ppc64le   │ │  s390x    │                                  │
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘                                  │
│        │             │             │                                         │
│        └─────────────┴─────────────┘                                         │
│                      │ all must succeed                                      │
│                      ▼                                                       │
│  ┌──────────────────────┐  ┌─────────────────────────────────────────────┐  │
│  │ openshift/os         │──│           Jenkins: build-node-image         │  │
│  │ (OCP packages)       │  │  (adds kubelet, cri-o, oc to base image)    │  │
│  └──────────────────────┘  └─────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Stage 1: Base Image** (`build` + `build-arch` jobs)
- Uses `rhel-coreos-config` (which includes `fedora-coreos-config` as submodule)
- `build` job runs for x86_64 and triggers `build-arch` for other architectures
- `build-arch` runs in parallel for aarch64, ppc64le, s390x
- If any `build-arch` job fails, the parent `build` job fails
- Produces a bootable container with RHEL/CentOS Stream content only
- No OpenShift components

**Stage 2: Node Image** (`build-node-image` job)
- Uses `openshift/os` Containerfile
- Builds FROM the base image
- Adds OpenShift packages: `kubelet`, `cri-o`, `oc`, etc.
- Produces `rhel-coreos` or `stream-coreos` image in OCP release payload

## GitHub Repositories

| Repository | Purpose | Key Files/Directories |
|------------|---------|----------------------|
| [coreos/fedora-coreos-config](https://github.com/coreos/fedora-coreos-config) | Upstream FCOS manifests (inherited by RHCOS) | `manifest.yaml`, `manifests/`, `tests/`, `kola-denylist.yaml` |
| [coreos/rhel-coreos-config](https://github.com/coreos/rhel-coreos-config) | RHCOS/SCOS config (RHEL-specific packages) | `manifest-*.yaml`, `packages-rhcos.yaml`, `tests/kola/`, `kola-denylist.yaml` |
| [coreos/coreos-assembler](https://github.com/coreos/coreos-assembler) | Build tool (cosa) and kola test framework | `mantle/kola/` (tests), `src/`, `docs/` |
| [coreos/fedora-coreos-pipeline](https://github.com/coreos/fedora-coreos-pipeline) | Jenkins pipeline definitions | `jobs/`, `config.yaml` |
| [openshift/os](https://github.com/openshift/os) | Node image layer (adds OCP packages) | `packages-openshift.yaml`, `Containerfile`, `tests/kola/`, `extensions/` |

### Repository Relationships

- `fedora-coreos-config` is a **submodule** inside `rhel-coreos-config`
- `rhel-coreos-config` produces the **base image**
- `openshift/os` **builds FROM** the base image to create the node image

## Package Definitions

### Base OS Packages (Stage 1)

Defined in `rhel-coreos-config`:

| File | Purpose |
|------|---------|
| `packages-rhcos.yaml` | RHCOS-specific packages |
| `manifest-*.yaml` | Stream-specific manifests (repos, versions) |
| `packages-overrides.yaml` | Package version overrides |

Inherited from `fedora-coreos-config`:

| File | Purpose |
|------|---------|
| `manifests/*.yaml` | Modular package groups |
| `manifest-lock.*.json` | Per-architecture package locks |

### OpenShift Packages (Stage 2)

Defined in `openshift/os`:

| File | Purpose |
|------|---------|
| `packages-openshift.yaml` | OCP node packages (kubelet, cri-o, oc, etc.) |
| `extensions/` | Optional extensions (usbguard, etc.) |

## Test Locations

Kola tests are distributed across repositories:

| Repository | Test Path | Test Type |
|------------|-----------|-----------|
| `fedora-coreos-config` | `tests/kola/` | FCOS-specific tests |
| `rhel-coreos-config` | `tests/kola/` | RHCOS-specific tests |
| `openshift/os` | `tests/kola/` | Node image tests |
| `coreos-assembler` | `mantle/kola/tests/` | Core kola tests |

### Test Denylists

Each config repo has a `kola-denylist.yaml` to skip known-failing tests:
- `fedora-coreos-config/kola-denylist.yaml`
- `rhel-coreos-config/kola-denylist.yaml`
- `openshift/os/kola-denylist.yaml`

## Build Variants

Defined in `rhel-coreos-config`:

| Variant | Description | Config File |
|---------|-------------|-------------|
| `rhel-9.8` | RHEL 9.8 based (default) | `manifest-rhel-9.8.yaml` |
| `rhel-10.2` | RHEL 10.2 based | `manifest-rhel-10.2.yaml` |
| `c9s` | CentOS Stream 9 | `manifest-c9s.yaml` |
| `c10s` | CentOS Stream 10 | `manifest-c10s.yaml` |

## Build Streams

| Stream | Description |
|--------|-------------|
| `c9s` | CentOS Stream 9 (upstream development) |
| `c10s` | CentOS Stream 10 (upstream development) |
| `rhel-9.2` | RHEL 9.2 based builds |
| `rhel-9.4` | RHEL 9.4 based builds |
| `rhel-9.6` | RHEL 9.6 based builds |
| `rhel-9.8` | RHEL 9.8 based builds |
| `rhel-10.2` | RHEL 10.2 based builds |

## OCP to RHEL Version Mapping

| OCP Version | RHEL Version |
|-------------|--------------|
| 4.12 | 8.6 |
| 4.13 | 9.2 |
| 4.14 | 9.2 |
| 4.15 | 9.2 |
| 4.16 | 9.4 |
| 4.17 | 9.4 |
| 4.18 | 9.4 |
| 4.19 | 9.6 |
| 4.20 | 9.6 |
| 4.21 | 9.6 |
| 4.22 | 9.8 |

## Jenkins Jobs

| Job | Architecture | Purpose | Output |
|-----|--------------|---------|--------|
| `build` | x86_64 | Main RHCOS base image build, triggers build-arch | Bootable container (RHEL content only) |
| `build-arch` | aarch64, ppc64le, s390x | Architecture-specific base builds (triggered by `build`) | Multi-arch base images |
| `build-node-image` | all | Node image build (adds OCP packages) | `rhel-coreos` / `stream-coreos` |
| `release` | all | Release builds | Production releases |

### Build and Build-Arch Relationship

The `build` job orchestrates multi-architecture builds:

1. `build` job starts for x86_64
2. `build` triggers `build-arch` jobs for aarch64, ppc64le, s390x in parallel
3. `build` waits for all `build-arch` jobs to complete
4. If **any** `build-arch` job fails, the parent `build` job **fails**
5. Only when all architectures succeed does `build-node-image` proceed

This means when investigating a `build` failure, check if the root cause is in `build-arch`:

```bash
# Check if build-arch jobs failed
coreos-tools jenkins builds list build-arch --status FAILURE -n 5

# Get the triggering build job number from build-arch parameters
coreos-tools jenkins builds info build-arch <build-number>
```

### Job Commands

```bash
# List all jobs
coreos-tools jenkins jobs list

# Get job info (health, last builds)
coreos-tools jenkins jobs info <job-name>

# Trigger a build
coreos-tools jenkins jobs build <job-name> -p STREAM=<stream> -p FORCE=true

# View build queue
coreos-tools jenkins queue list

# List nodes
coreos-tools jenkins nodes list
```

## Architectures

| Architecture | Description | Build Job |
|--------------|-------------|-----------|
| `x86_64` | AMD64/Intel 64-bit | `build` |
| `aarch64` | ARM 64-bit | `build-arch` |
| `ppc64le` | IBM POWER little-endian | `build-arch` |
| `s390x` | IBM Z mainframe | `build-arch` |

## Build Artifacts

Common artifacts available from builds:

| Artifact | Description |
|----------|-------------|
| `coreos-assembler-git.json` | cosa version info |
| `manifest-lock.*.json` | Package manifest locks |
| `builds.json` | Build metadata |
| `meta.json` | Build metadata |

### Artifact Commands

```bash
# List build artifacts
coreos-tools jenkins builds artifacts <job-name> <build-number>

# Download a specific artifact
coreos-tools jenkins builds artifacts <job-name> <build-number> --download <artifact-name>

# Download to specific path
coreos-tools jenkins builds artifacts <job-name> <build-number> --download <artifact-name> -o /tmp/output.json
```

## Package Comparison

### Single Build Diff

Shows what packages changed/upgraded in this build:

```bash
coreos-tools jenkins builds diff <job-name> <build-number>
```

### Two Build Comparison

Compare packages between two builds:

```bash
coreos-tools jenkins builds diff <job-name> <build1> <build2>
```

Output format:
```json
{
  "build1": 3399,
  "build2": 3463,
  "stream": "rhel-9.6",
  "added": ["new-package-1.0.0.x86_64 (rhel-9.6-baseos)"],
  "removed": ["old-package-2.0.0.x86_64 (rhel-9.4-appstream)"],
  "changed": [
    {
      "name": "kernel",
      "build1": "kernel-5.14.0-427.112.1.el9_4.x86_64 (rhel-9.4-server-ose-4.17)",
      "build2": "kernel-5.14.0-570.94.1.el9_6.x86_64 (rhel-9.6-early-kernel)"
    }
  ]
}
```

### Analyzing Diffs

```bash
# List all changed package names
coreos-tools jenkins builds diff <job-name> <b1> <b2> | jq -r '.changed[].name'

# Show kernel changes specifically
coreos-tools jenkins builds diff <job-name> <b1> <b2> | jq '.changed[] | select(.name == "kernel")'

# Count changes
coreos-tools jenkins builds diff <job-name> <b1> <b2> | jq '{added: (.added | length), removed: (.removed | length), changed: (.changed | length)}'
```

## Brew Web (Internal)

Brew (Red Hat's internal Koji instance) tracks package builds.

**Base URL**: https://brewweb.engineering.redhat.com/brew/

### Package Search

```
# Search by package name
https://brewweb.engineering.redhat.com/brew/search?match=glob&type=package&terms=<package-name>

# Example
https://brewweb.engineering.redhat.com/brew/search?match=glob&type=package&terms=conmon-rs
```

### Build Search

```
# Search builds by NVR pattern
https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=<pattern>

# Example: Find all conmon-rs builds for RHEL 10
https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=conmon-rs*el10*
```

### NVR Naming Convention

NVR = Name-Version-Release

#### OpenShift-Specific Packages (Plashet/RHAOS)

Packages with `rhaos` in the release are **OpenShift-specific** and come from the plashet (RHAOS repo):

```
conmon-rs-0.6.6-0.rhaos4.18.el10.1
└──────┘ └───┘ └─────────────────┘
  name   ver        release
               └────┘ └──┘
              ocp4.18 rhel10
```

The `rhaos` prefix indicates this package is built specifically for OpenShift, not from RHEL repos.

#### RHEL Packages

Packages from RHEL repos have a different release format:

```
kernel-5.14.0-570.94.1.el9_6.x86_64
└────┘ └───────────────┘ └───┘
 name       version       rhel9.6
```

#### Fast-Tracking RHEL Packages

Sometimes RHEL packages are **tagged into plashets** to fast-track a fix into OpenShift before it lands in the regular RHEL repos. In this case, a RHEL package appears in the `rhaos-4.XX-rhel-Y` tag but retains its original RHEL NVR format.

### Package Sources

| Release Pattern | Source | Example |
|-----------------|--------|---------|
| `*.rhaos4.XX.*` | Plashet (OpenShift-specific) | `cri-o-1.30.0-1.rhaos4.18.el9` |
| `*.el9_6` | RHEL 9.6 repos | `kernel-5.14.0-570.94.1.el9_6` |
| `*.el10` | RHEL 10 repos | `systemd-256-1.el10` |

### Common Tag Patterns

| Tag Pattern | Meaning |
|-------------|---------|
| `rhaos-4.XX-rhel-Y` | OCP 4.XX plashet for RHEL Y (OpenShift packages + fast-tracked RHEL packages) |
| `rhel-Y.Z-baseos` | RHEL Y.Z base OS |
| `rhel-Y.Z-appstream` | RHEL Y.Z AppStream |
| `rhel-Y-server-ose-4.XX` | RHEL Y for OCP 4.XX |

## coreos-assembler (cosa)

coreos-assembler is the build tool for CoreOS images.

- **GitHub**: https://github.com/coreos/coreos-assembler
- **Docs**: https://coreos.github.io/coreos-assembler/
- **Container**: `quay.io/coreos-assembler/coreos-assembler`

### Key cosa Commands

| Command | Purpose |
|---------|---------|
| `cosa init` | Initialize a build directory |
| `cosa fetch` | Fetch packages |
| `cosa build` | Build the OS image |
| `cosa kola` | Run kola tests |

### Comparing cosa Versions

```bash
# Download cosa git info
coreos-tools jenkins builds artifacts <job-name> <build-number> --download coreos-assembler-git.json -o /tmp/cosa.json

# Compare using GitHub API
gh api repos/coreos/coreos-assembler/compare/<old-commit>...<new-commit> \
  --jq '.commits[] | {sha: .sha[0:7], message: .commit.message | split("\n")[0]}'
```
