# Agent Stack private channel

`agent_stack` is a private, durable Hermes gateway adapter for a trusted local
Agent Stack control plane. It implements `agent_stack.channel.v1`; it is not a
public bot connector.

## Configuration

```yaml
platforms:
  agent_stack:
    enabled: true
    extra:
      runtime_dir: /persisted/.hermes/run/agent-stack
      db_path: /persisted/.hermes/state/agent-stack-channel.db
```

Both paths default under `HERMES_HOME`. The runtime directory is mode `0700`.
On each adapter start Hermes creates a new random boot secret and writes it to
`channel.secret` with mode `0600`; it also creates `channel.sock` with mode
`0600`. Hermes removes both endpoints during clean shutdown. Do not copy the
secret into configuration, logs, source control, or an environment variable.

## Transport and authentication

The socket carries a framed stream. Every frame starts with a four-byte,
big-endian unsigned payload length followed by exactly one UTF-8 JSON object.
The maximum frame is 1 MiB. The first frame must be:

```json
{"kind":"authenticate","secret":"<contents of channel.secret>"}
```

Hermes compares the secret in constant time, rejects every command before a
successful handshake, and closes a failed peer. After authentication Hermes
sends the frozen capability document before accepting commands. The Unix
socket permissions and boot secret are independent controls; both are
required. The adapter declares authorization upstream because the private
handshake, not a broad `allow_all_users` setting, establishes the peer.

The parser rejects duplicate object members, byte-order marks, floats,
non-finite values, integers outside the interoperable 53-bit range, unknown
envelope members and kinds, malformed identifiers, forbidden private fields,
and digest mismatches. It never logs command payloads, visible text, attachment
capabilities, or secrets.

## Durable delivery

`conversation.bind`, `turn.submit`, `turn.cancel`, and `event.ack` are committed
to SQLite before Hermes acknowledges them. The database uses WAL mode,
foreign keys, `BEGIN IMMEDIATE` transactions, and mode `0600`.

The uniqueness scope is `(channel_binding_id, ingress_id)`:

- an exact duplicate replays persisted, unacknowledged receipts and events and
  never executes the turn twice;
- a reused ingress ID with a different digest fails with
  `payload_digest_conflict`;
- every turn event has a strictly increasing `gateway_sequence`;
- `event.ack` advances only the highest contiguous sequence and cannot exceed
  the durable outbox;
- a committed cancel request wins a simultaneous completion race;
- after a process restart, accepted but non-terminal work becomes
  `turn.failed` with `execution_interrupted`; Hermes replays it and does not
  execute it again.

Attachment values remain opaque descriptors (`attachment_id`, media type,
size, SHA-256, and `read_capability`). Device paths and server paths never
cross the channel boundary. The descriptor is attached to the internal Hermes
message metadata for a capability-aware resolver; the adapter does not treat it
as a filesystem path.

## Lifecycle and operations

Hermes emits only the capability-advertised event kinds. Visible model output
is delivered as `turn.text.delta` and `turn.text.checkpoint`; activity text is
chosen from the frozen safe allowlist. Terminal outcomes are exactly one of
`turn.completed`, `turn.failed`, or `turn.cancelled`.

`AgentStackAdapter.health()` is payload-free. It reports protocol
version, generation, authenticated peer count, pending outbox count, active
turn count, and whether the adapter is connected. It does not return prompts,
responses, attachment capabilities, or secrets.

A retrying peer should reconnect, authenticate, consume the capability frame,
apply replayed events idempotently by `(gateway_generation,
gateway_turn_id,gateway_sequence)`, and send `event.ack` only after the local
projection commits the full contiguous prefix.
