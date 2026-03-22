# Mattermost Channel Access Control

The Mattermost channel plugin maintains a sender allowlist. Only approved user
IDs can push messages into your Claude Code session. Everyone else is silently
dropped.

## How access works

All state lives in `~/.claude/channels/mattermost/access.json`. The channel
server re-reads it on every inbound message — changes take effect immediately.

### DM policy

Controls how direct messages from unknown senders are handled:

- **`pairing`** (default) — unknown senders get a 6-char code to approve in
  Claude Code. Temporary setup mode.
- **`allowlist`** — only senders in `allowFrom` can reach you. No pairing codes.
- **`disabled`** — all DMs are dropped.

### Pairing flow

1. Someone DMs your bot on Mattermost
2. The bot replies with a pairing code
3. You run `/mattermost:access pair <code>` in Claude Code
4. Their user ID is added to the allowlist
5. The bot confirms in Mattermost: "Paired! Say hi to Claude."

**Security limits:**
- Max 3 pending pairing codes at once
- Codes expire after 1 hour
- Max 2 replies per pending code (initial + one reminder)

### Group channels

Group/public/private channels are opt-in. Add them with:

```
/mattermost:access group add <channel_id>
/mattermost:access group add <channel_id> --no-mention
/mattermost:access group add <channel_id> --allow user1,user2
```

By default, the bot must be @mentioned to respond in group channels.
`--no-mention` disables this requirement. `--allow` restricts which users
in the channel can trigger the bot.

### Outbound gating

The bot can only send messages to channels it has received approved messages
from. It cannot be used to send unsolicited messages to arbitrary channels.

## Commands

```
/mattermost:access                     — show status
/mattermost:access pair <code>         — approve a pairing
/mattermost:access deny <code>         — reject a pairing
/mattermost:access allow <userId>      — manually add to allowlist
/mattermost:access remove <userId>     — remove from allowlist
/mattermost:access policy <mode>       — set DM policy
/mattermost:access group add <id>      — opt in a channel
/mattermost:access group rm <id>       — opt out a channel
/mattermost:access set <key> <value>   — configure settings
```

### Settings

| Key | Values | Description |
|-----|--------|-------------|
| `ackReaction` | emoji name or `""` | React to inbound messages (e.g. `eyes`) |
| `replyToMode` | `off`, `first`, `all` | Threading behavior for chunked replies |
| `textChunkLimit` | 1–16383 | Max chars per outbound post |
| `chunkMode` | `length`, `newline` | Split on char count or paragraph boundaries |
| `mentionPatterns` | JSON array | Extra regex patterns for mention detection |

## Static mode

Set `MATTERMOST_ACCESS_MODE=static` in `.env` to freeze the access config at
boot. Pairing is downgraded to `allowlist` with a warning. Useful for
production deployments where access shouldn't change at runtime.
