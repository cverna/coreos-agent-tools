---
name: bug-investigation
description: Investigate OCPBUGS bug issues - tracing package sources, finding when changes were introduced, and analyzing package file changes
---

# OCPBUGS Investigation

Knowledge for investigating package-related issues in RHEL CoreOS, including tracing package origins, finding when changes were introduced, and comparing package versions across builds.

> For general RHCOS build system knowledge, see the `rhcos-builds` skill.


## Brew (Red Hat Build System)

Brew is Red Hat's internal Koji instance for tracking package builds.

**Base URL:** https://brewweb.engineering.redhat.com/brew/

### Searching for Builds

Use `curl` to query Brew (requires VPN):

```bash
# Search for builds by NVR pattern
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=<pattern>" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'

# Example: Find all cri-o builds for OCP 4.19
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=cri-o*rhaos4.19*" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'

# Example: Find all builds for a specific package version
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=<package>-<version>*" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+'
```

### Getting Build Information

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
```

### Finding When a File Was Introduced

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

### Getting Source Commit Information

Build pages include the source commit:

```bash
# Extract git commit from build info
curl -sk "https://brewweb.engineering.redhat.com/brew/buildinfo?buildID=<build-id>" | \
  grep -iE "git|source|commit"
```

## Dist-Git (pkgs.devel.redhat.com)

Red Hat's internal GitLab for RPM specs and sources.

### Viewing Commit History

```bash
# View commit log for a branch
curl -sk "https://pkgs.devel.redhat.com/cgit/rpms/<package>/log/?h=<branch>"

# View a specific commit
curl -sk "https://pkgs.devel.redhat.com/cgit/rpms/<package>/commit/?h=<branch>&id=<commit-hash>"
```

### Branch Naming Convention

| Branch Pattern | Description |
|----------------|-------------|
| `rhaos-4.XX-rhel-Y` | OpenShift 4.XX for RHEL Y |
| `rhel-Y.Z.0` | RHEL Y.Z base |
| `c9s` | CentOS Stream 9 |
| `c10s` | CentOS Stream 10 |

## GitHub Repository Investigation

### Searching Repository Contents

```bash
# List all files in a repository
gh api "repos/<org>/<repo>/git/trees/<branch>?recursive=1" | \
  jq -r '.tree[].path'

# Search for files by name pattern
gh api "repos/<org>/<repo>/git/trees/<branch>?recursive=1" | \
  jq -r '.tree[].path' | grep -i "<pattern>"

# Search code content across repository
gh search code "<search-term>" --repo <org>/<repo>
```

### Fetching Raw Files

```bash
# Fetch raw file from GitHub
curl -s "https://raw.githubusercontent.com/<org>/<repo>/<branch>/<path>"

# Example: Get packages-openshift.yaml from openshift/os
curl -s "https://raw.githubusercontent.com/openshift/os/master/packages-openshift.yaml"
```

### Viewing Issues and Comments

```bash
# Get issue details
gh api repos/<org>/<repo>/issues/<number> | jq -r '.title, .body'

# Get issue comments
gh api repos/<org>/<repo>/issues/<number>/comments | \
  jq -r '.[] | "---\n\(.user.login) (\(.created_at)):\n\(.body)\n"'

# Search for issues
gh search issues "<search-term>" --repo <org>/<repo>
```

### Comparing Commits

```bash
# Compare two commits
gh api repos/<org>/<repo>/compare/<old-commit>...<new-commit> \
  --jq '.commits[] | {sha: .sha[0:7], message: .commit.message | split("\n")[0]}'

# Get details of a specific commit
gh api repos/<org>/<repo>/commits/<commit-sha> \
  --jq '{sha: .sha, author: .commit.author.name, message: .commit.message}'
```

## JIRA Investigation

Use the JIRA CLI for accessing Red Hat JIRA issues:

```bash
# View issue details
jira issue view <issue-key>

# View issue with comments
jira issue view <issue-key> --comments 20

# Search for related issues
jira issue list -q "<search-query>"
```

## Key Repositories

| Repository | Purpose | Key Files |
|------------|---------|-----------|
| [coreos/rhel-coreos-config](https://github.com/coreos/rhel-coreos-config) | RHCOS base config | `group`, `passwd`, `manifest-*.yaml` |
| [coreos/fedora-coreos-config](https://github.com/coreos/fedora-coreos-config) | Upstream FCOS config | `manifest.yaml`, `manifests/`, `overlay.d/` |
| [openshift/os](https://github.com/openshift/os) | OCP node image layer | `packages-openshift.yaml`, `Containerfile` |
| [openshift/machine-config-operator](https://github.com/openshift/machine-config-operator) | MCO | Node configuration |

## Package Version Comparison

### Comparing Packages Between OCP Versions

```bash
# Find package version in 4.18
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=<package>*rhaos4.18*el9" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+' | tail -5

# Find package version in 4.19  
curl -sk "https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=<package>*rhaos4.19*el9" | \
  grep -oP 'buildinfo\?buildID=\d+[^"]*">[^<]+' | tail -5
```

### NVR (Name-Version-Release) Patterns

| Pattern | Source | Example |
|---------|--------|---------|
| `*.rhaos4.XX.*` | OpenShift plashet | `cri-o-1.30.0-1.rhaos4.18.el9` |
| `*.el9_6` | RHEL 9.6 repos | `kernel-5.14.0-570.94.1.el9_6` |
| `*.el9` | RHEL 9 (generic) | `systemd-252-51.el9` |