# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CoreOS Agent Tools is a collection of Python CLI tools for monitoring and analyzing Red Hat CoreOS (RHCOS) infrastructure:

- **coreos_pipeline_messages.py** - Fetches Slack messages from CoreOS pipeline channels and posts summaries
- **jenkins.py** - Comprehensive Jenkins CLI for managing jobs, builds, queue, and nodes
- **process_rhcos_cves.py** - Processes RHCOS CVEs from Jira, matches with RHEL issues, and creates issue links
- **get_rhcos_image.py** - Retrieves RHCOS container image data for specific OCP versions\

## Task Tracking

Use `bd` for task tracking

## Commands

All scripts run inside a container. Always rebuild before running.

### Build container
```bash
podman build -t quay.io/cverna/coreos-agent-tools .
```

### Run scripts
```bash
# Pipeline messages
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools coreos_pipeline_messages.py --date 2024-01-15 --pretty

# Jenkins CLI
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools jenkins.py jobs list --pretty
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools jenkins.py jobs info <job-name>
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools jenkins.py builds list <job-name> --last 5
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools jenkins.py builds log <job-name> <build-number>
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools jenkins.py queue list
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools jenkins.py nodes list
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools jenkins.py failures <job-name> --last 5  # backwards compat

# Process RHCOS CVEs
podman run --rm --env-file .env quay.io/cverna/coreos-agent-tools process_rhcos_cves.py --status open --format pretty

# Get RHCOS image data
podman run --rm quay.io/cverna/coreos-agent-tools get_rhcos_image.py --ocp-version 4.16
```

## Environment Variables

Required environment variables (configured via `.env` file):

| Variable | Tool | Description |
|----------|------|-------------|
| `SLACK_XOXC_TOKEN` | coreos_pipeline_messages.py | Slack XOXC authentication token |
| `SLACK_XOXD_TOKEN` | coreos_pipeline_messages.py | Slack XOXD cookie token |
| `SLACK_CHANNEL` | coreos_pipeline_messages.py | Slack channel ID |
| `JENKINS_URL` | jenkins.py | Jenkins server URL |
| `JENKINS_USER` | jenkins.py | Jenkins username |
| `JENKINS_API_TOKEN` | jenkins.py | Jenkins API token |
| `JIRA_API_TOKEN` | process_rhcos_cves.py | Jira API bearer token |
| `REGISTRY_AUTH_FILE` | get_rhcos_image.py | Optional path to registry auth file |

## Architecture

### Output Format
All CLI tools output JSON by default with optional `--pretty` flag for human-readable formatting. This allows tools to be composed together or used with Claude Code slash commands.

### Rate Limiting
Both `jenkins.py` and `process_rhcos_cves.py` implement rate limiting (2 req/sec) with exponential backoff retry logic via a shared `throttled_request()` pattern.

### OCP to RHEL Version Mapping
`process_rhcos_cves.py` contains `OCP_TO_RHEL` mapping dict (e.g., OCP 4.16 → RHEL 9.4) used for matching CVEs between RHCOS and RHEL issues.

### Claude Code Integration
The project includes a slash command at `coreos_pipeline_status.md` for analyzing pipeline builds. Copy to `~/.claude/commands/` to use with `/coreos_pipeline_status`.
