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
| `pandoc` | Markdown to HTML conversion |

## When to use

You must use the `gh` cli to interact with GitHub
You must use the `jira` cli to interact with Jira
You must use the `glab` cli to interact with GitLab

You must use rg instead of grep.

## Web Output Directories

A Caddy web server runs automatically in the background, serving two directories.
Always write HTML output to the appropriate directory so the user can view it in their browser.

| Directory | Port | Use for |
|-----------|------|---------|
| `/var/www` | 9090 | Generic reports, summaries, dashboards, and any output not tied to workspace content |
| `/workspace` | 9091 | HTML files related to the current project or files in `/workspace` |

**Guidelines:**
- Use `/var/www` for pipeline reports, Jira summaries, build status dashboards, and other standalone output.
- Use `/workspace` (or a subdirectory within it) for HTML output that references or documents the current workspace content.
- Prefer self-contained HTML files (inline CSS and JS) so they render correctly without additional assets.
- When creating an HTML report, tell the user which URL to open: `http://localhost:9090/<filename>` or `http://localhost:9091/<filename>`.
- To convert Markdown to a self-contained HTML file, use `pandoc`:
  ```bash
  pandoc report.md -o /var/www/report.html --standalone
  ```
