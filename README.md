# CoreOS Agent Tools

CLI tools for monitoring and analyzing Red Hat CoreOS (RHCOS) infrastructure.

## Tools

| Tool | Description |
|------|-------------|
| `coreos_pipeline_messages.py` | Fetch Slack messages from CoreOS pipeline channels |
| `jenkins.py` | Manage Jenkins jobs, builds, queue, and nodes |
| `process_rhcos_cves.py` | Process RHCOS CVEs from Jira and match with RHEL issues |
| `get_rhcos_image.py` | Retrieve RHCOS container image data for OCP versions |

## Quick Start

```bash
# Build container
podman build -t quay.io/cverna/coreos-agent-tools .

# Run with environment variables
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools <script> [options]
```

See `CLAUDE.md` for detailed usage examples and environment variable configuration.

## Go CLI

A Go implementation is available in the `go/` directory:

```bash
cd go
go build -o bin/coreos-tools ./cmd/coreos-tools
./bin/coreos-tools --help
```

## Claude Code Integration

Copy `coreos_pipeline_status.md` to `~/.claude/commands/` to use the `/coreos_pipeline_status` slash command.