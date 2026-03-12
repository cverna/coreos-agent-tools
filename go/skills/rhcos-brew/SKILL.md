---
name: rhcos-brew
description: Brew (Red Hat build system) - package searches, NVR naming, tags, and package sources
---

# Brew (Red Hat Build System)

Brew is Red Hat's internal Koji instance for tracking package builds.

> Related: `rhcos-artifacts`, `bug-investigation`

**Base URL:** https://brewweb.engineering.redhat.com/brew/

## Package Search

```bash
# Search by package name
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=package&terms=<package-name>" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'

# Example
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=package&terms=conmon-rs" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'
```

## Build Search

```bash
# Search builds by NVR pattern
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=<pattern>" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'

# Example: Find all conmon-rs builds for RHEL 10
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=conmon-rs*el10*" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'

# Example: Find cri-o builds for OCP 4.19
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=cri-o*rhaos4.19*" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'
```

## Getting Build Information

```bash
# Get RPM IDs from a build
curl -sk "https://brewweb.engineering.redhat.com/brew/buildinfo?buildID=<build-id>" | \
  grep -oP 'rpminfo\?rpmID=\d+'

# Check if a specific file exists in an RPM
curl -sk "https://brewweb.engineering.redhat.com/brew/rpminfo?rpmID=<rpm-id>" | \
  grep -i "<filename-pattern>"

# Get build tags
curl -sk "https://brewweb.engineering.redhat.com/brew/buildinfo?buildID=<build-id>" | \
  grep -iE "tag"

# Extract git commit from build info
curl -sk "https://brewweb.engineering.redhat.com/brew/buildinfo?buildID=<build-id>" | \
  grep -iE "git|source|commit"
```

## NVR Naming Convention

NVR = Name-Version-Release

### OpenShift-Specific Packages (Plashet/RHAOS)

Packages with `rhaos` in the release are OpenShift-specific and come from the plashet (RHAOS repo):

```
conmon-rs-0.6.6-0.rhaos4.18.el10.1
└──────┘ └───┘ └─────────────────┘
  name   ver        release
               └────┘ └──┘
              ocp4.18 rhel10
```

### RHEL Packages

Packages from RHEL repos have a different release format:

```
kernel-5.14.0-570.94.1.el9_6.x86_64
└────┘ └───────────────┘ └───┘
 name       version       rhel9.6
```

### Fast-Tracking RHEL Packages

Sometimes RHEL packages are tagged into plashets to fast-track a fix into OpenShift before it lands in the regular RHEL repos. In this case, a RHEL package appears in the `rhaos-4.XX-rhel-Y` tag but retains its original RHEL NVR format.

## Package Sources

| Release Pattern | Source | Example |
|-----------------|--------|---------|
| `*.rhaos4.XX.*` | Plashet (OpenShift-specific) | `cri-o-1.30.0-1.rhaos4.18.el9` |
| `*.el9_6` | RHEL 9.6 repos | `kernel-5.14.0-570.94.1.el9_6` |
| `*.el10` | RHEL 10 repos | `systemd-256-1.el10` |

## Common Tag Patterns

| Tag Pattern | Meaning |
|-------------|---------|
| `rhaos-4.XX-rhel-Y` | OCP 4.XX plashet for RHEL Y (OpenShift packages + fast-tracked RHEL packages) |
| `rhel-Y.Z-baseos` | RHEL Y.Z base OS |
| `rhel-Y.Z-appstream` | RHEL Y.Z AppStream |
| `rhel-Y-server-ose-4.XX` | RHEL Y for OCP 4.XX |

## Finding When a File Was Introduced

To find when a file was first added to a package, compare successive builds:

```bash
# 1. List builds chronologically
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=<package>*rhaos4.18*" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'

# 2. For each build, get RPM IDs
curl -sk "https://brewweb.engineering.redhat.com/brew/buildinfo?buildID=<build-id>" | \
  grep -oP 'rpminfo\?rpmID=\d+' | head -3

# 3. Check if the file exists in that RPM
curl -sk "https://brewweb.engineering.redhat.com/brew/rpminfo?rpmID=<rpm-id>" | \
  grep -i "<filename>"
```
