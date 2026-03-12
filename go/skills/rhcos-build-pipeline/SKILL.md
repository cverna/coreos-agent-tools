---
name: rhcos-build-pipeline
description: RHCOS build pipeline - two-stage process, Jenkins jobs, and multi-architecture builds
---

# RHCOS Build Pipeline

Knowledge about the RHEL CoreOS build pipeline, Jenkins jobs, and multi-architecture builds.

> Related: `rhcos-repositories`, `rhcos-artifacts`, `rhcos-versions`

## Build Process Overview

RHCOS is built in two stages:

**Stage 1: Base Image** (`build` + `build-arch` jobs)
- Input: `rhel-coreos-config` repository (contains `fedora-coreos-config` as submodule)
- The `build` job runs for x86_64 and triggers `build-arch` for other architectures
- `build-arch` runs in parallel for aarch64, ppc64le, s390x
- All `build-arch` jobs must succeed for the pipeline to continue
- Output: Bootable container with RHEL/CentOS Stream content only (no OpenShift components)

**Stage 2: Node Image** (`build-node-image` job)
- Input: Base image from Stage 1 + `openshift/os` Containerfile
- Adds OpenShift packages: kubelet, cri-o, oc, etc.
- Output: `rhel-coreos` or `stream-coreos` image in OCP release payload

## Jenkins Jobs

| Job | Architecture | Purpose | Output |
|-----|--------------|---------|--------|
| `build` | x86_64 | Main RHCOS base image build, triggers build-arch | Bootable container (RHEL content only) |
| `build-arch` | aarch64, ppc64le, s390x | Architecture-specific base builds (triggered by `build`) | Multi-arch base images |
| `build-node-image` | all | Node image build (adds OCP packages) | `rhel-coreos` / `stream-coreos` |
| `release` | all | Release builds | Production releases |

## Build and Build-Arch Relationship

The `build` job orchestrates multi-architecture builds:

1. `build` job starts for x86_64
2. `build` triggers `build-arch` jobs for aarch64, ppc64le, s390x in parallel
3. `build` waits for all `build-arch` jobs to complete
4. If any `build-arch` job fails, the parent `build` job fails
5. Only when all architectures succeed does `build-node-image` proceed

When investigating a `build` failure, check if the root cause is in `build-arch`:

```bash
# Check if build-arch jobs failed
coreos-tools jenkins builds list build-arch --status FAILURE -n 5

# Get the triggering build job number from build-arch parameters
coreos-tools jenkins builds info build-arch <build-number>
```

## Architectures

| Architecture | Description | Build Job |
|--------------|-------------|-----------|
| `x86_64` | AMD64/Intel 64-bit | `build` |
| `aarch64` | ARM 64-bit | `build-arch` |
| `ppc64le` | IBM POWER little-endian | `build-arch` |
| `s390x` | IBM Z mainframe | `build-arch` |

## Job Commands

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
