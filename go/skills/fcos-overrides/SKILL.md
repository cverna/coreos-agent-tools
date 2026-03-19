---
name: fcos-overrides
description: Fedora CoreOS package overrides - fast-tracking, pinning, and graduation status
---

# FCOS Package Overrides

Knowledge for inspecting Fedora CoreOS package overrides (fast-tracks and pins) and checking graduation status.

> Related: `rhcos-brew` (Koji patterns)

## Overview

FCOS uses `manifest-lock.overrides.yaml` to:
- **Fast-track**: Pull in Bodhi updates before they reach stable (auto-removed when graduated)
- **Pin**: Hold back packages at specific versions (manual removal required)

## Key Repositories

| Repository | Purpose |
|------------|---------|
| [coreos/fedora-coreos-config](https://github.com/coreos/fedora-coreos-config) | Override files, `ci/overrides.py` tool |
| [coreos/fedora-coreos-releng-automation](https://github.com/coreos/fedora-coreos-releng-automation) | `coreos-koji-tagger` (auto-tags to coreos-pool) |

## Determining Fedora Version

```bash
# From build-args.conf (VERSION field)
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/build-args.conf?ref=testing-devel | \
  grep "^VERSION="

# From bodhi (current stable Fedora releases)
bodhi releases list
```

## Viewing Current Overrides

```bash
# Fetch current overrides from testing-devel
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/manifest-lock.overrides.yaml?ref=testing-devel

# For other branches (next-devel, branched, rawhide)
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/manifest-lock.overrides.yaml?ref=<branch>
```

## Override Format

### Fast-track

```yaml
packages:
  ignition:
    evr: 2.26.0-1.fc<fedora-version>
    metadata:
      type: fast-track
      bodhi: https://bodhi.fedoraproject.org/updates/FEDORA-XXXX-XXXXXXXXXX
      reason: https://github.com/coreos/fedora-coreos-tracker/issues/XXX  # optional for trivial packages
```

### Pin

```yaml
packages:
  dracut:
    evr: 053-5.fc<fedora-version>
    metadata:
      type: pin
      reason: https://github.com/coreos/fedora-coreos-tracker/issues/XXX  # required
```

## Checking Bodhi Update Status

```bash
# Query by update ID
bodhi updates query --updateid <FEDORA-XXXX-XXXXXXXXXX>

# Check if package has stable updates
bodhi updates query --packages <package> --releases f<fedora-version> --status stable

# Check testing updates
bodhi updates query --packages <package> --releases f<fedora-version> --status testing
```

### Key Status Values

| Status | Meaning |
|--------|---------|
| `stable` | In stable repos - fast-track can graduate |
| `testing` | In updates-testing - not yet graduated |
| `pending` | Submitted but not pushed |
| `obsolete` | Superseded by newer update |
| `unpushed` | Withdrawn from testing |

## Checking Koji Tags

```bash
# Check if package is in stable Fedora repos
koji list-tagged --latest f<fedora-version>-updates <package>
koji list-tagged --latest f<fedora-version> <package>  # GA release

# Check updates-testing
koji list-tagged --latest f<fedora-version>-updates-testing <package>

# Check coreos-pool (where overridden packages are tagged)
koji list-tagged coreos-pool | grep <package>

# Get build details
koji buildinfo <nvr>

# See all tags for a build
koji list-tags <nvr>

# Search for builds
koji search build '<package>*fc<fedora-version>*'
```

## Graduation Check Workflow

To check if a fast-tracked package can graduate:

```bash
# 1. Get the overridden EVR from manifest-lock.overrides.yaml
#    Example: ignition evr: 2.26.0-1.fc43

# 2. Check what version is in stable Fedora repos
koji list-tagged --latest f<fedora-version>-updates <package>

# 3. If stable version >= overridden version, it can graduate
#    The remove-graduated-overrides action runs every 6 hours automatically
```

## Trivial Fast-tracks

These packages don't require a `reason` URL when fast-tracking (core FCOS packages):

- `console-login-helper-messages`
- `ignition`
- `ostree`
- `rpm-ostree`
- `rust-afterburn`
- `rust-bootupd`
- `rust-coreos-installer`
- `rust-ignition-config`
- `rust-zincati`

## Common Queries

### List all package names in overrides

```bash
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/manifest-lock.overrides.yaml?ref=testing-devel | \
  yq '.packages | keys | .[]'
```

### List fast-tracked packages

```bash
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/manifest-lock.overrides.yaml?ref=testing-devel | \
  yq '.packages | to_entries[] | select(.value.metadata.type == "fast-track") | .key'
```

### List pinned packages

```bash
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/manifest-lock.overrides.yaml?ref=testing-devel | \
  yq '.packages | to_entries[] | select(.value.metadata.type == "pin") | .key'
```

### Get override details for a specific package

```bash
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/manifest-lock.overrides.yaml?ref=testing-devel | \
  yq '.packages.<package-name>'
```

### Summary of all overrides with type and EVR

```bash
gh api -H "Accept: application/vnd.github.raw" \
  /repos/coreos/fedora-coreos-config/contents/manifest-lock.overrides.yaml?ref=testing-devel | \
  yq '.packages | to_entries[] | {"name": .key, "evr": (.value.evr // .value.evra), "type": .value.metadata.type}'
```
