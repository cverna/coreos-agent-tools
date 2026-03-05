# Installation Guide

Quick setup guide for using the CoreOS Agent Tools container with OpenCode.

## Prerequisites

- Podman or Docker installed
- Google Cloud SDK configured (optional, for access to additional AI models)

## Pull the Container

```bash
podman pull ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest
```

## First-Time Setup

Start an interactive session to configure the tools. You'll need:

- A GitHub account
- A Jenkins API token ([how to create one](#jenkins-api-token))
- A Jira personal access token ([how to create one](#jira-personal-access-token))

```bash
podman run -it \
  -v coreos-agent-config:/home/agent/.config \
  -v coreos-agent-data:/home/agent/.local/share \
  -e JIRA_API_TOKEN="your-jira-token" \
  ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest bash
```

**Note:** Don't use `--rm` during setup so configuration is saved even if the session ends unexpectedly.

### Volume Overview

| Volume | Path | Purpose |
|--------|------|---------|
| `coreos-agent-config` | `/home/agent/.config` | Tool configurations (gh, jira, coreos-tools, opencode) |
| `coreos-agent-data` | `/home/agent/.local/share` | Application data (OpenCode sessions, conversation history) |

### Configure GitHub CLI

```bash
gh auth login
```

Follow the prompts to authenticate.

### Configure Jenkins

```bash
coreos-tools jenkins profiles create rhcos \
  --url https://jenkins-rhcos--prod-pipeline.apps.int.prod-stable-spoke1-dc-iad2.itup.redhat.com/ \
  --user your-username \
  --default
```

When prompted, enter your Jenkins API token.

### Configure Jira CLI

```bash
jira init --installation local \
  --server https://issues.redhat.com \
  --login your-email@redhat.com \
  --auth-type bearer \
  --project COS \
  --board "CoreOS Scrum"
```

### Verify Setup

```bash
gh auth status
coreos-tools jenkins jobs list
jira issue list
```

Exit the container when done:

```bash
exit
```

## Usage

### Run OpenCode

```bash
podman run -it --rm \
  -v coreos-agent-config:/home/agent/.config \
  -v coreos-agent-data:/home/agent/.local/share \
  -v ~/.config/gcloud:/home/agent/.config/gcloud:ro \
  -v $(pwd):/workspace \
  -e JIRA_API_TOKEN="your-token" \
  -e GOOGLE_CLOUD_PROJECT="your-gcp-project" \
  -e VERTEX_LOCATION="global" \
  ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest
```

The `/analyze-failures` slash command is pre-installed and can create Jira sub-tasks.

The `coreos-agent-data` volume persists OpenCode sessions, so you can resume previous conversations.

The gcloud mount and environment variables provide access to additional AI models (e.g., Vertex AI) in OpenCode.

### Run Without Jira or gcloud

If you don't need Jira integration or additional models:

```bash
podman run -it --rm \
  -v coreos-agent-config:/home/agent/.config \
  -v coreos-agent-data:/home/agent/.local/share \
  -v $(pwd):/workspace \
  ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest
```

### Run Other Commands

```bash
# Get a bash shell
podman run -it --rm \
  -v coreos-agent-config:/home/agent/.config \
  -v coreos-agent-data:/home/agent/.local/share \
  -v ~/.config/gcloud:/home/agent/.config/gcloud:ro \
  -e JIRA_API_TOKEN="your-token" \
  -e GOOGLE_CLOUD_PROJECT="your-gcp-project" \
  -e VERTEX_LOCATION="global" \
  ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest bash

# Run coreos-tools
podman run --rm \
  -v coreos-agent-config:/home/agent/.config \
  ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest \
  coreos-tools jenkins jobs list

# Run jira
podman run --rm \
  -v coreos-agent-config:/home/agent/.config \
  -e JIRA_API_TOKEN="your-token" \
  ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest \
  jira issue list
```

## Tools Included

| Tool | Description |
|------|-------------|
| `opencode` | AI coding assistant (default) |
| `coreos-tools` | Jenkins/Jira/OCP management |
| `jira` | Jira CLI |
| `gh` | GitHub CLI |
| `jq` | JSON processor |
| `git` | Version control |

## Shell Alias (Optional)

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
export JIRA_API_TOKEN="your-token"
export GOOGLE_CLOUD_PROJECT="your-gcp-project"
export VERTEX_LOCATION="global"

alias coreos-agent='podman run -it --rm \
  -v coreos-agent-config:/home/agent/.config \
  -v coreos-agent-data:/home/agent/.local/share \
  -v ~/.config/gcloud:/home/agent/.config/gcloud:ro \
  -v $(pwd):/workspace \
  -e JIRA_API_TOKEN="$JIRA_API_TOKEN" \
  -e GOOGLE_CLOUD_PROJECT="$GOOGLE_CLOUD_PROJECT" \
  -e VERTEX_LOCATION="$VERTEX_LOCATION" \
  ghcr.io/cverna/coreos-agent-tools/coreos-agent:latest'
```

Then simply run:

```bash
coreos-agent          # OpenCode with Jira support
coreos-agent bash     # Shell with Jira support
```

## Appendix

### Jenkins API Token

1. Log into Jenkins
2. Click your username → Configure
3. Add new API Token

### Jira Personal Access Token

1. Go to https://issues.redhat.com/secure/ViewProfile.jspa?selectedTab=com.atlassian.pats.pats-plugin:jira-user-personal-access-tokens
2. Click "Create token"
