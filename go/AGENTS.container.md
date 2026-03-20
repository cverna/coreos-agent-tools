# CoreOS Agent Tools

This container provides CLI tools for managing CoreOS/RHCOS infrastructure.

## Available Tools

| Tool | Description |
|------|-------------|
| `coreos-tools` | Jenkins/Jira/OCP management |
| `jira` | Jira CLI |
| `gh` | GitHub CLI |
| `glab` | GitLab CLI |
| `koji` / `brew` | Koji/Brew build system CLI |
| `bodhi` | Fedora updates system CLI |
| `oc` | OpenShift CLI |
| `kubectl` | Kubernetes CLI |
| `podman` | Container management |
| `jq` | JSON processor |
| `yq` | YAML processor |
| `git` | Version control |
| `ripgrep` | Line-oriented search tool |

## When to use

You must use the `gh` cli to interact with GitHub
You must use the `jira` cli to interact with Jira
You must use the `glab` cli to interact with GitLab

You must use rg instead of grep.
