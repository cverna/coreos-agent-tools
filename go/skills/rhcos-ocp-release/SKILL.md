---
name: rhcos-ocp-release
description: OCP release queries - latest versions, RHCOS images, and RPM package lists
---

# RHCOS OCP Release

Query OCP release versions, RHCOS container images, and RPM package lists.

> Related: `rhcos-versions`, `rhcos-artifacts`, `rhcos-brew`, `rhcos-build-pipeline`

## CLI Commands Reference

| Command | Purpose |
|---------|---------|
| `oc adm release info --rpmdb <image>` | List all RPMs in node image |
| `oc adm release info --rpmdb-diff <from> <to>` | Get RPM differences between releases |
| `oc adm release info --image-for rhel-coreos <image>` | Get RHEL 9 RHCOS image reference |
| `oc adm release info --image-for rhel-coreos-10 <image>` | Get RHEL 10 RHCOS image reference |
| `oc adm release info --image-for rhel-coreos-extensions <image>` | Get RHEL 9 extensions image reference |
| `oc adm release info --image-for rhel-coreos-10-extensions <image>` | Get RHEL 10 extensions image reference |
| `oc image extract <image> --file=<path>` | Extract specific file from image |

> **Note:** `--rpmdb` and `--rpmdb-diff` require `--rpmdb-cache <dir>` to specify a cache directory.

## Release Controller API

Base URL: `https://amd64.ocp.releases.ci.openshift.org`

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/v1/releasestreams/accepted` | All accepted releases grouped by stream |
| `/api/v1/releasestream/<stream>/latest` | Latest release in a stream |
| `/api/v1/releasestream/<stream>/tags` | All tags in a stream with metadata |

### Available Streams

| Stream | Description |
|--------|-------------|
| `4-stable` | All stable 4.x releases |
| `4-dev-preview` | Developer preview releases |
| `4.21.0-0.nightly` | 4.21 nightly builds |
| `4.21.0-0.ci` | 4.21 CI builds |

## Querying Latest Versions

### Latest Stable Release (any minor)

```bash
curl -s "https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestream/4-stable/latest" | jq .
```

### Latest Z-Stream for Specific Minor Version

```bash
# Get latest 4.21.x GA release (excluding RCs)
curl -s "https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestreams/accepted" | \
  jq -r '."4-stable"[] | select(startswith("4.21.") and (contains("-rc") | not))' | head -1
```

### Latest Nightly for Specific Minor Version

```bash
curl -s "https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestream/4.21.0-0.nightly/latest" | jq .
```

### List All Accepted Versions for a Minor Release

```bash
curl -s "https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestreams/accepted" | \
  jq -r '."4-stable"[] | select(startswith("4.21."))'
```

## RHCOS Image Information

### Get RHCOS Image Reference from Release

OCP 4.22+ includes both RHEL 9 and RHEL 10 based RHCOS images:

```bash
# RHEL 9 based RHCOS image
oc adm release info quay.io/openshift-release-dev/ocp-release:<version>-x86_64 --image-for rhel-coreos

# RHEL 10 based RHCOS image (OCP 4.22+)
oc adm release info quay.io/openshift-release-dev/ocp-release:<version>-x86_64 --image-for rhel-coreos-10
```

### Get Full Release Info

```bash
oc adm release info quay.io/openshift-release-dev/ocp-release:<version>-x86_64
```

## RPM Package Lists

### List RPMs Using oc (Recommended)

Use `oc adm release info --rpmdb` to list RPMs without pulling the full container image:

```bash
# List all RPMs in RHEL 9 RHCOS node image
oc adm release info --rpmdb --rpmdb-cache /tmp/rpmdb-cache \
  --rpmdb-image rhel-coreos \
  quay.io/openshift-release-dev/ocp-release:<version>-x86_64

# List all RPMs in RHEL 10 RHCOS node image (OCP 4.22+)
oc adm release info --rpmdb --rpmdb-cache /tmp/rpmdb-cache \
  --rpmdb-image rhel-coreos-10 \
  quay.io/openshift-release-dev/ocp-release:<version>-x86_64
```

> **Note:** The `--rpmdb-cache` flag is required. For recent machine-os images, this operation is fast and efficient. The `--rpmdb-image` flag may be needed for some releases (e.g., EC builds).

### Compare RPMs Between Releases

```bash
oc adm release info --rpmdb-diff --rpmdb-cache /tmp/rpmdb-cache \
  quay.io/openshift-release-dev/ocp-release:<from-version>-x86_64 \
  quay.io/openshift-release-dev/ocp-release:<to-version>-x86_64
```

### List RPMs Using podman (Alternative)

Use podman when you need to inspect files or run other commands inside the RHCOS image:

```bash
# Get RHCOS image reference
RHCOS_IMAGE=$(oc adm release info quay.io/openshift-release-dev/ocp-release:<version>-x86_64 --image-for rhel-coreos)

# Pull the image
podman pull $RHCOS_IMAGE

# List all RPMs (sorted)
podman run --rm $RHCOS_IMAGE rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort

# List just package names
podman run --rm $RHCOS_IMAGE rpm -qa --qf '%{NAME}\n' | sort -u

# Query specific package
podman run --rm $RHCOS_IMAGE rpm -q kernel

# Inspect files inside the image
podman run --rm -it $RHCOS_IMAGE /bin/bash
```

## Multi-Architecture Support

Replace `amd64` in the URL with other architectures:

| Architecture | Release Controller URL |
|--------------|------------------------|
| x86_64 | `amd64.ocp.releases.ci.openshift.org` |
| aarch64 | `arm64.ocp.releases.ci.openshift.org` |
| ppc64le | `ppc64le.ocp.releases.ci.openshift.org` |
| s390x | `s390x.ocp.releases.ci.openshift.org` |

## Examples

### Full Workflow: Get Latest 4.21 RPMs

```bash
# 1. Find latest version
VERSION=$(curl -s "https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestreams/accepted" | \
  jq -r '."4-stable"[] | select(startswith("4.21.") and (contains("-rc") | not))' | head -1)

# 2. List all RPMs using oc
oc adm release info --rpmdb --rpmdb-cache /tmp/rpmdb-cache \
  --rpmdb-image rhel-coreos \
  quay.io/openshift-release-dev/ocp-release:${VERSION}-x86_64
```

## RHEL Package Flow to RHCOS

RHCOS picks up packages from RHEL composes. Understanding the brew tag flow is essential for tracking when packages will appear in RHCOS.

### Brew Tag Flow

| Tag | Meaning | When RHCOS Picks It Up |
|-----|---------|------------------------|
| `rhel-9.X.0-pending` | Tagged for 9.X GA content | Picked up in pre-GA RHCOS builds |
| `rhel-9.X.0-z-pending` | Tagged for 0-day errata | Picked up after GA (0-day builds) |

**Key insight:** If a package only has the `-z-pending` tag, it won't appear in RHCOS until after RHEL GA unless an exception is granted.

### Checking Brew Tags

```bash
# Check tag history for a build
brew list-history --tag rhel-9.8.0-pending --build <package-nvr>

# Example
brew list-history --tag rhel-9.8.0-pending --build resource-agents-4.10.0-107.el9
```

> See `rhcos-brew` skill for more brew commands and NVR conventions.

## RHEL Compose Structure

RHCOS builds consume packages from RHEL composes. The compose type determines timing.

### Compose Types

| Suffix | Type | Description |
|--------|------|-------------|
| `.d.#` | Development | Development compose (e.g., `RHEL-9.8.0-20260308.d.3`) |
| `.n.#` | Nightly | Nightly compose, picked up by next RHCOS build |

### Compose URL Pattern

```
https://download.eng.brq.redhat.com/rhel-9/composes/RHEL-9/RHEL-9.X.0-YYYYMMDD.<type>.<num>/
```

Example structure:
```
RHEL-9.8.0-20260308.d.3/
└── compose/
    ├── BaseOS/x86_64/os/Packages/
    ├── AppStream/x86_64/os/Packages/
    └── HighAvailability/x86_64/os/Packages/
```

### Timing

1. Package tagged in brew with `rhel-9.X.0-pending`
2. Package appears in nightly RHEL compose
3. Next RHCOS build picks up the compose
4. Package appears in RHCOS nightly (typically next day)

## Extensions Image Inspection

RHCOS extensions (optional packages) are stored in separate images. OCP 4.22+ includes both RHEL 9 and RHEL 10 extensions.

### Get Extensions Image Reference

```bash
# RHEL 9 extensions
oc adm release info --image-for rhel-coreos-extensions \
  quay.io/openshift-release-dev/ocp-release:<version>-x86_64

# RHEL 10 extensions (OCP 4.22+)
oc adm release info --image-for rhel-coreos-10-extensions \
  quay.io/openshift-release-dev/ocp-release:<version>-x86_64
```

### Extract Extensions Metadata Using oc (Recommended)

```bash
# Get the extensions image reference
EXTENSIONS_IMAGE=$(oc adm release info --image-for rhel-coreos-extensions \
  quay.io/openshift-release-dev/ocp-release:<version>-x86_64)

# Extract extensions.json (lists all available extension packages)
oc image extract $EXTENSIONS_IMAGE --file=usr/share/rpm-ostree/extensions.json

# View the extensions
cat extensions.json | jq .

# Search for a specific package
cat extensions.json | jq 'to_entries[] | select(.key | contains("kernel"))'
```

The `extensions.json` file contains a JSON object mapping package names to their versions.

### Inspect Extensions Using podman (Alternative)

Use podman when you need to list actual RPM files or inspect the image contents:

```bash
# List all extension RPMs
podman run --entrypoint /bin/sh $EXTENSIONS_IMAGE \
  -c 'ls /usr/share/rpm-ostree/extensions/*.rpm'

# Check for a specific package
podman run --entrypoint /bin/sh $EXTENSIONS_IMAGE \
  -c 'ls /usr/share/rpm-ostree/extensions/resource*.rpm'
```

### Image Naming Convention

```
quay.io/openshift-release-dev/ocp-v4.0-art-dev:<ocp-version>-<rhel-version>-node-image-extensions
```

Examples:
- `4.22-9.8-node-image-extensions` - OCP 4.22 with RHEL 9.8
- `4.22-10.2-node-image-extensions` - OCP 4.22 with RHEL 10.2
- `4.21-9.6-node-image-extensions` - OCP 4.21 with RHEL 9.6

## Monitoring RHCOS Builds

### Slack Channel

The `#jenkins-rhcos-art` Slack channel shows RHCOS build status. Look for successful `4.X-9.Y` node image builds.

### Build Status

When a package isn't appearing in RHCOS:

1. Check if the RHCOS pipeline is passing (failures block package updates)
2. Look for successful node image builds in the channel
3. Once pipeline succeeds, packages from the latest compose will be included

## Troubleshooting: Package Not in RHCOS

Step-by-step workflow when a package isn't showing up:

### Step 1: Check Brew Tags

```bash
# Does the build have the right tag?
brew list-tags --build=<package-nvr>

# Check tag history
brew list-history --tag rhel-9.X.0-pending --build <package-nvr>
```

**Expected:** Build should have `rhel-9.X.0-pending` tag (not just `-z-pending`).

### Step 2: Check RHEL Compose

Browse the compose directory to verify the package is included:
```
https://download.eng.brq.redhat.com/rhel-9/composes/RHEL-9/
```

Look for nightly composes (`.n.#` suffix) and check the relevant repo (BaseOS, AppStream, HighAvailability).

### Step 3: Check RHCOS Pipeline

- Check `#jenkins-rhcos-art` for recent build status
- Look for successful `4.X-9.Y` node image builds
- Pipeline failures block package updates

### Step 4: Verify in Extensions Image

```bash
# Get extensions image
EXTENSIONS_IMAGE=$(oc adm release info --image-for rhel-coreos-extensions \
  quay.io/openshift-release-dev/ocp-release:<version>-x86_64)

# Extract and search extensions.json for a package
oc image extract $EXTENSIONS_IMAGE --file=usr/share/rpm-ostree/extensions.json
cat extensions.json | jq 'to_entries[] | select(.key | contains("<package>"))'

# Alternative: use podman to list RPM files
podman run --entrypoint /bin/sh $EXTENSIONS_IMAGE \
  -c 'ls /usr/share/rpm-ostree/extensions/<package>*.rpm'
```

### Common Issues

| Symptom | Likely Cause | Resolution |
|---------|--------------|------------|
| Package has `-z-pending` only | Tagged for 0-day, not GA | Ask maintainer to request exception for GA content |
| Package in dev compose only | Not yet in nightly | Wait for nightly compose |
| Pipeline failing | Build blocked | Wait for pipeline fix, check `#jenkins-rhcos-art` |
| Older version appears | Compose not updated yet | Check compose timestamp, wait for next nightly |
