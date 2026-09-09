# Agent integrations

Latchlane's owner and agent identities remain separate. Agents may request a
credential collection by name and destination, but they never submit or receive
credential values through the collection API, CLI output, or MCP. The owner opens
the paired broker locally, unlocks it, and explicitly saves the reviewed batch.

For a local agent, use `latchlane mcp`. It exposes the standard broker tools plus
`latchlane_collect` and `latchlane_collection_status`. A sensitive integration
that only needs to ask the owner for credentials should use:

```sh
latchlane mcp --collections-only
```

That stdio server exposes only the two metadata-only collection tools. Requests
containing values, passwords, usernames, token fields, routes, or unknown fields
are rejected. A collection status returns only its ID, state, expiry, and names.
When `latchlane_collect` returns `unlock_required`, unlock the owner console and
retry the metadata request. It has no collection ID because the locked broker did
not create one.

For Hermes, install the bundled local guidance without changing Hermes settings:

```sh
latchlane install-skill --directory ~/.hermes/skills/latchlane
```

The installer refuses to overwrite a file already there. For the owner-installed
local command, add the MCP server with `hermes mcp add latchlane --command
latchlane --args mcp`, restrict its tools to Latchlane's five named tools, disable
MCP resources and prompts, run `hermes mcp test latchlane`, then use a fresh
session or `/reload-mcp`. Do not bulk-rewrite a Hermes configuration.

The CLI is the simpler path. If you deliberately maintain Hermes YAML, this is the
smallest equivalent fragment to review and add yourself. See the official
[Hermes MCP documentation](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md):

```yaml
mcp_servers:
  latchlane:
    command: latchlane
    args: [mcp]
    tools:
      include:
        - latchlane_keys
        - latchlane_request
        - latchlane_consume
        - latchlane_collect
        - latchlane_collection_status
      resources: false
      prompts: false
    # Optional: adds a Hermes confirmation for each non-read-only tool.
    trust: untrusted
```

Hermes uses `trust: full` by default when this server is added. For an
owner-trusted local command, that leaves Latchlane's Always ask, Auto approve, and
YOLO choices as the approval boundary. The optional `trust: untrusted` shown above
adds a Hermes confirmation for non-read-only tools. Do not change Hermes
configuration automatically.

## Private ChatGPT tunnel

When connecting a personal or workspace ChatGPT MCP tunnel, associate it with the
intended personal or workspace account and use the collection-only command. Follow
OpenAI's [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
to create the tunnel identity and keep its runtime key in the tunnel's protected
runtime setup.

```sh
tunnel-client init --sample sample_mcp_stdio_local --profile latchlane --tunnel-id YOUR_TUNNEL_ID --mcp-command "latchlane mcp --collections-only"
tunnel-client doctor --profile latchlane
tunnel-client run --profile latchlane
```

Keep the tunnel private to that association; it is not a public plugin or relay.
The external OpenAI runtime key belongs in the tunnel provider's protected runtime
configuration. Never put it in command-line arguments, a Latchlane spec, this
file's commands, chat, or a committed configuration file. No public relay is
needed for a local stdio integration.

In ChatGPT, enable Developer Mode, open **Plugins**, select the private tunnel, and
choose this profile. The owner must still pair the requesting agent and explicitly
unlock and save in the Latchlane console. The selected Always ask, Auto approve, or
YOLO policy does not turn on because a collection is requested. These are setup
instructions only: this repository does not connect a tunnel or account for you.
