"""System/user prompts for the Ollama LLM fallback analysis.

Ported from ~/shild/plugins/05_ai.tcl's system_prompt / pattern_prompt /
global_pattern_prompt (lines 11-74), with two changes:
  - "voice" is dropped from the action vocabulary. The classifier can
    only ever represent allow/warn/ban (see shildml.features.ACTIONS),
    and Phase 1 has no command capability to act on any decision anyway,
    so keeping the vocabularies in sync now avoids a silent mismatch later.
  - The old system's biggest parsing fragility was regex-extracting JSON
    out of freeform LLM text (see 05_ai.tcl:263-298 for the seven regexes
    this replaces). Ollama's structured-output support (`format: <json
    schema>`, confirmed working against this server's Ollama 0.32.5 in
    the M0 spike) constrains the response shape directly, so the prompt
    below describes the schema for the model's *understanding*, but the
    actual enforcement is the JSON schema passed alongside it (see
    ollama.py's RESPONSE_SCHEMA) -- ollama.py never regex-parses.

05_ai.tcl's nlp_prompt (natural-language command parsing) and ask_prompt
(!ask command) are Phase 2 (commands) and are deliberately not ported here.

Phase 1.5 adds `evidence_summary` (see shildml/evidence.py's
HostEvidence.summary()) to the join/message prompts -- giving the model
DNSBL/IP-reputation/cloak-trust facts instead of leaving it to guess
entirely from string shape is the single cheapest false-positive
reduction available. This is prompt text only; it is never fed to the
classifier as a feature (see features.py's module docstring for why).
"""

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["allow", "warn", "ban"]},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reason": {"type": "string"},
    },
    "required": ["action", "confidence", "reason"],
}

SYSTEM_PROMPT = """You are SHILD, an AI IRC channel guardian. Analyze events and return protection decisions.

ACTIONS: allow | warn | ban
CONFIDENCE: 0.0-1.0. Only recommend acting if >= 0.7.
BOT SIGNS: random alphanumeric nicks, raw IP hosts, datacenter hosts, fast joins, identical messages.
TRUSTED HOSTS: a host starting with "user/" means NickServ-authenticated on Libera.Chat -- always allow.
SCAN CONTEXT: when given DNSBL/DroneBL findings, weigh the listing type -- IRC drones/proxies warrant ban, but generic spam listings may only warrant warn.
Be strict with bots, fair with humans."""

PATTERN_PROMPT = """You are SHILD, monitoring an IRC channel. Analyze recent events for suspicious patterns:
- Repeated join/part cycles from the same host (flood testing)
- Multiple nicks from similar hosts joining in short succession
- Nicks being kicked or banned by other ops (trust their judgment)
- Coordinated activity (same message from different nicks, wave of joins)

Only flag genuine threats. Confidence must be >= 0.8 to act.
Target must be a nick currently in the channel."""

GLOBAL_PATTERN_PROMPT = """You are SHILD, monitoring multiple IRC channels. Look for cross-channel threats:
- Same host kicked or banned in more than one channel
- Similar hosts joining multiple channels in short succession
- Coordinated abuse across channels

Only flag a host if you are very confident (>= 0.8). Use action=allow if nothing suspicious."""


def build_join_prompt(nick: str, ident: str, host: str, channel: str,
                       channel_context: str = "", host_context: str = "",
                       evidence_summary: str = "") -> str:
    out = f"JOIN: nick={nick} ident={ident} host={host} chan={channel}"
    if evidence_summary:
        out += f"\nHost evidence: {evidence_summary}"
    if channel_context:
        out += f"\nRecent events in {channel}:\n{channel_context}"
    if host_context:
        out += f"\nCross-channel history for {host}:\n{host_context}"
    out += "\nIs this a bot or spammer?"
    return out


def build_message_prompt(nick: str, channel: str, text: str,
                          channel_context: str = "", evidence_summary: str = "") -> str:
    out = f"MESSAGE: nick={nick} chan={channel}\nText: {text}"
    if evidence_summary:
        out += f"\nHost evidence: {evidence_summary}"
    if channel_context:
        out += f"\nRecent channel events:\n{channel_context}"
    out += "\nIs this spam?"
    return out


def build_scan_prompt(nick: str, ident: str, host: str, channel: str,
                       findings: str, host_context: str = "") -> str:
    out = f"SCAN: nick={nick} ident={ident} host={host} chan={channel}"
    out += f"\nScan findings: {findings}"
    if host_context:
        out += f"\nCross-channel history for {host}:\n{host_context}"
    out += "\nBased on these scan results, decide: allow / warn / ban."
    return out
