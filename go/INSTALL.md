# Installation Guide (Fedora)

Quick setup guide for using the `analyze-failures` prompt.

## Prerequisites

### 1. Install Required CLI Tools

```bash
sudo dnf install -y jq gh
```

### 2. Install coreos-tools

```bash
go install github.com/coreos/coreos-tools@latest
```

Ensure `~/go/bin` is in your PATH:

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

### 3. Install Jira CLI (Optional - for creating sub-tasks)

```bash
go install github.com/ankitpokhrel/jira-cli/cmd/jira@latest
```

## Configuration

### Jenkins Credentials

Create a `.env` file in your working directory:

```bash
JENKINS_URL=https://your-jenkins-server.example.com
JENKINS_USER=your-username
JENKINS_API_TOKEN=your-api-token
```

To get a Jenkins API token:
1. Log into Jenkins
2. Click your username → Configure
3. Add new API Token

### GitHub CLI Authentication

```bash
gh auth login
```

Follow the prompts to authenticate with GitHub.

### Jira CLI Authentication (Optional)

Configure the Jira CLI with a personal access token:

```bash
jira init --installation local \
  --server https://issues.redhat.com \
  --login your-email@redhat.com \
  --auth-type bearer \
  --project COS \
  --board "CoreOS Scrum"
```

When prompted, paste your personal access token.

To create a token:
1. Go to https://issues.redhat.com/secure/ViewProfile.jspa?selectedTab=com.atlassian.pats.pats-plugin:jira-user-personal-access-tokens
2. Click "Create token"

## Verify Installation

```bash
# Check all tools are available
coreos-tools --version
gh --version
jq --version
jira --version  # optional

# Test Jenkins connection
coreos-tools jenkins jobs list
```

## Usage

```bash
# Analyze failures interactively
/analyze-failures

# Analyze specific job
/analyze-failures build --stream c9s -n 3
```
