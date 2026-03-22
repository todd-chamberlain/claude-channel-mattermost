# Mattermost Channel for Claude Code

Bridge Mattermost messages to your Claude Code session. Self-hosted, private, two-way chat.

DM your Mattermost bot, and the message arrives in your Claude Code terminal. Claude reads it, does the work, and replies back in Mattermost.

## Prerequisites

- [Claude Code](https://code.claude.com) v2.1.80+ with channels support
- [Bun](https://bun.sh) runtime
- A Mattermost instance with a bot account and personal access token

## Setup

### 1. Create a Mattermost bot

1. Go to **System Console > Integrations > Bot Accounts** and enable bot accounts
2. Go to **Integrations > Bot Accounts > Add Bot Account**
3. Give it a username (e.g., `claude-bot`) and role
4. Copy the generated access token

Alternatively, create a personal access token:
1. Go to **Account Settings > Security > Personal Access Tokens**
2. Create a token and copy it

### 2. Install the plugin

```
/plugin install mattermost@claude-plugins-official
```

Or for local development:

```bash
cd ~/claude-channel-mattermost
bun install
```

### 3. Configure credentials

```
/mattermost:configure https://mm.example.com xoxb-your-token-here
```

This saves to `~/.claude/channels/mattermost/.env`.

### 4. Start with channels enabled

```bash
# Published plugin
claude --channels plugin:mattermost@claude-plugins-official

# Local development
claude --dangerously-load-development-channels server:mattermost
```

### 5. Pair your account

1. DM the bot on Mattermost — it replies with a 6-char code
2. In Claude Code: `/mattermost:access pair <code>`
3. Lock down access: `/mattermost:access policy allowlist`

## Tools

| Tool | Description |
|------|-------------|
| `reply` | Post a message (with optional threading and file attachments) |
| `react` | Add an emoji reaction (use names like `thumbsup`, no colons) |
| `edit_message` | Edit a previously sent post |
| `download_attachment` | Download a file attachment to local inbox |
| `fetch_messages` | Retrieve recent channel history |

## Access Control

See [ACCESS.md](ACCESS.md) for full documentation.

- **DM policy**: `pairing` (default), `allowlist`, or `disabled`
- **Group channels**: opt-in per channel with optional mention-gating
- **Sender allowlist**: only approved user IDs can push messages

## State Directory

```
~/.claude/channels/mattermost/
  .env          — MATTERMOST_URL and MATTERMOST_TOKEN
  access.json   — allowlist, groups, pending pairings
  inbox/        — downloaded attachments
  approved/     — pairing approval signal files
```
