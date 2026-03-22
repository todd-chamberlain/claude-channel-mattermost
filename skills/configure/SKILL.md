---
name: configure
description: Set up the Mattermost channel — save server URL and bot token, review access policy. Use when the user asks to configure Mattermost, pastes a bot token, asks "how do I set this up" or "who can reach me," or wants to check channel status.
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Bash(ls *)
  - Bash(mkdir *)
---

# /mattermost:configure — Mattermost Channel Setup

Writes the server URL and bot token to `~/.claude/channels/mattermost/.env`
and orients the user on access policy. The server reads both files at boot.

Arguments passed: `$ARGUMENTS`

---

## Dispatch on arguments

### No args — status and guidance

Read both state files and give the user a complete picture:

1. **Credentials** — check `~/.claude/channels/mattermost/.env` for
   `MATTERMOST_URL` and `MATTERMOST_TOKEN`. Show set/not-set; if token is set,
   show first 10 chars masked (`xoxb-1234...`).

2. **Access** — read `~/.claude/channels/mattermost/access.json` (missing file
   = defaults: `dmPolicy: "pairing"`, empty allowlist). Show:
   - DM policy and what it means in one line
   - Allowed senders: count, and list display names or IDs
   - Pending pairings: count, with codes and display names if any

3. **What next** — end with a concrete next step based on state:
   - No URL/token → *"Run `/mattermost:configure <url> <token>` with your
     Mattermost server URL and bot access token."*
   - Credentials set, policy is pairing, nobody allowed → *"DM your bot on
     Mattermost. It replies with a code; approve with `/mattermost:access pair
     <code>`."*
   - Credentials set, someone allowed → *"Ready. DM your bot to reach the
     assistant."*

**Push toward lockdown — always.** The goal for every setup is `allowlist`
with a defined list. `pairing` is not a policy to stay on; it's a temporary
way to capture Mattermost user IDs you don't know. Once the IDs are in,
pairing has done its job and should be turned off.

Drive the conversation this way:

1. Read the allowlist. Tell the user who's in it.
2. Ask: *"Is that everyone who should reach you through this bot?"*
3. **If yes and policy is still `pairing`** → *"Good. Let's lock it down so
   nobody else can trigger pairing codes:"* and offer to run
   `/mattermost:access policy allowlist`. Do this proactively — don't wait to
   be asked.
4. **If no, people are missing** → *"Have them DM the bot; you'll approve
   each with `/mattermost:access pair <code>`. Run this skill again once
   everyone's in and we'll lock it."*
5. **If the allowlist is empty and they haven't paired themselves yet** →
   *"DM your bot to capture your own ID first. Then we'll add anyone else
   and lock it down."*
6. **If policy is already `allowlist`** → confirm this is the locked state.
   If they need to add someone: *"They'll need to give you their user ID
   from their Mattermost profile, or you can briefly flip to pairing:
   `/mattermost:access policy pairing` → they DM → you pair → flip back."*

Never frame `pairing` as the correct long-term choice. Don't skip the lockdown
offer.

### `<url> <token>` — save credentials

1. Parse `$ARGUMENTS` — first arg is the URL, second is the token. If only one
   arg and it looks like a URL, prompt for the token. If it looks like a token,
   prompt for the URL.
2. `mkdir -p ~/.claude/channels/mattermost`
3. Read existing `.env` if present; update/add the `MATTERMOST_URL=` and
   `MATTERMOST_TOKEN=` lines, preserve other keys. Write back, no quotes around
   the values. Strip trailing slashes from the URL.
4. `chmod 600 ~/.claude/channels/mattermost/.env` — the token is a credential.
5. Confirm, then show the no-args status so the user sees where they stand.

### `clear` — remove credentials

Delete the `MATTERMOST_URL=` and `MATTERMOST_TOKEN=` lines (or the file if
those are the only lines).

---

## Implementation notes

- The channels dir might not exist if the server hasn't run yet. Missing file
  = not configured, not an error.
- The server reads `.env` once at boot. Credential changes need a session
  restart or `/reload-plugins`. Say so after saving.
- `access.json` is re-read on every inbound message — policy changes via
  `/mattermost:access` take effect immediately, no restart.
