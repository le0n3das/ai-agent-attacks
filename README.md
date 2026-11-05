# AI Agent Attacks: a five-phase matrix from the ARKX Mothership

Worked attacks against vulnerable LLM-agent levels on the ARKX "Mothership" ( ctf.arkx.ninja ), a public capture-the-flag platform by CyberArk Labs. Each level puts a language-model agent in front of tools that carry a security flaw. The goal is to find the flaw and recover a `flag-xxxx` value.

Six levels are worked end to end here. Each technique below links to the level writeup where it showed up.

The organizing axis is five attack phases. MITRE ATLAS IDs sit in the last column as a searchable tag, verified against current ATLAS. Rows that have no honest ATLAS mapping carry no tag.

## The five phases

1. **Recon.** Enumerate the tools, their parameters, the UI panel.
2. **Fingerprint the backend.** Find the one engine the input is valid in.
3. **Map the defenses.** One primitive per probe. Read every error string as a signal.
4. **Bypass.** Each control on its own. The input filter and the output filter are separate problems.
5. **Exfiltrate.** Move the data out through whatever channel the tool leaves open.

## Levels

| Level | Name | Core vulnerability | Phases | Writeup |
|---|---|---|---|---|
| Advanced 5 | Bad Robot | `eval()` code injection | 1 2 3 4 5 | [advanced-05-bad-robot](advanced-05-bad-robot/) |
| Advanced 7 | Master of Resources | MCP direct access, missing authz | 1 4 5 | [advanced-07-master-of-resources](advanced-07-master-of-resources/) |
| Advanced 9 | Blind Network Ninja | OS command injection, blind oracle | 1 2 3 4 5 | [advanced-09-blind-network-ninja](advanced-09-blind-network-ninja/) |
| Expert 6 | The Shape Shifter | YAML insecure deserialization | 1 2 3 4 5 | [expert-06-the-shape-shifter](expert-06-the-shape-shifter/) |
| Expert 7 | The Octopus | privilege escalation via session-key write | 1 3 4 5 | [expert-07-the-octopus](expert-07-the-octopus/) |
| Expert 8 | The Heist | TOCTOU race, client-supplied price | 1 3 4 5 | [expert-08-the-heist](expert-08-the-heist/) |

## Matrix

### Phase 1. Recon

| Technique | What it is | Signal / trigger | Seen in | ATLAS |
|---|---|---|---|---|
| Tool enumeration via agent self-report | Ask the agent for its tool names, parameters, descriptions. | The agent lists its own capability surface. | [A5](advanced-05-bad-robot/), [A9](advanced-09-blind-network-ninja/), [E6](expert-06-the-shape-shifter/), [E7](expert-07-the-octopus/), [E8](expert-08-the-heist/) | T0084.001 |
| Panel over agent claims | Treat the UI tool panel and scoped track as ground truth; keep the agent-described flow unverified until a real call confirms it, because the agent confabulates a plausible architecture. | Agent flow contradicts the panel or the briefing. | [E7](expert-07-the-octopus/) | T0084.001 |
| Backend endpoint disclosure | An agent that reports its tools as offline still hands over the raw server address. | Agent message contains a URL or path. | [A7](advanced-07-master-of-resources/) | T0084 |

### Phase 2. Fingerprint the backend

| Technique | What it is | Signal / trigger | Seen in | ATLAS |
|---|---|---|---|---|
| Single-engine probe | Send input that is valid in exactly one interpreter. | A non-domain expression evaluates: `len(str(2**100))`=31; a dead host plus newline plus `true` returns Online. | [A5](advanced-05-bad-robot/), [A9](advanced-09-blind-network-ninja/), [E6](expert-06-the-shape-shifter/) | none |
| Error-string library identification | A verbatim library error names the stack. | `could not determine a constructor for the tag` (PyYAML); `Not Acceptable: Client must accept text/event-stream` (MCP Python SDK). | [E6](expert-06-the-shape-shifter/), [A7](advanced-07-master-of-resources/) | none |
| Loader/mode discrimination with harmless callables | Separate the safe mode from the unsafe one before weaponizing. | `!!python/tuple` parses while `!custom_tag` errors; `apply:time.time` runs, so the loader is not `safe_load` and not `FullLoader`. | [E6](expert-06-the-shape-shifter/) | none |
| Output-envelope stack fingerprint | The raw tool envelope reveals the framework (inference). | `lc_...` id plus `structured_content` points to the LangChain MCP adapter. | [A5](advanced-05-bad-robot/), [E6](expert-06-the-shape-shifter/), [E8](expert-08-the-heist/) | none |

### Phase 3. Map the defenses one primitive at a time

| Technique | What it is | Signal / trigger | Seen in | ATLAS |
|---|---|---|---|---|
| One primitive per probe, batched | Change exactly one thing per probe, many probes in a single turn. | Differing outcomes isolate each control. | [A5](advanced-05-bad-robot/), [A9](advanced-09-blind-network-ninja/), [E6](expert-06-the-shape-shifter/), [E7](expert-07-the-octopus/) | none |
| Error strings as a control legend | Each distinct error names a distinct control. | `prohibited values` is an input denylist; `output format not supported` is an output type check; `status must be 'SAFE'` then `cache_task_id not found` are two ordered gates. | [A5](advanced-05-bad-robot/), [E7](expert-07-the-octopus/) | none |
| Input and output filters mapped separately | Treat them as two problems. | A payload clears the input filter and the result is still rejected on type. | [A5](advanced-05-bad-robot/), [E6](expert-06-the-shape-shifter/) | none |

### Phase 4. Bypass each defense separately

| Technique | What it is | Signal / trigger | Seen in | ATLAS |
|---|---|---|---|---|
| Runtime string construction | Build blocked tokens at runtime: `'o'+'s'`, `chr(95)*2`. | The literal is blocked, the concatenation passes. | [A5](advanced-05-bad-robot/) | T0050, T0053 |
| Forgotten separator | Use the command separator the denylist missed. | `;` `&&` `||` `$()` and backticks are blocked; a raw newline survives. | [A9](advanced-09-blind-network-ninja/) | T0050, T0069.000 |
| Output-type bypass by encoding | Emit the data as the only permitted type, one large integer. | Non-numeric output is rejected, an integer is accepted. | [A5](advanced-05-bad-robot/) | none |
| Output-field shaping | Route the data through the only field that gets echoed, dict key names. Reachable only because code execution lets the attacker choose the keys. | The tool prints keys and never values. | [E6](expert-06-the-shape-shifter/) | none |
| Scripted client past a browser guard | The Origin and DNS-rebinding check stops browsers and is not authentication, so a scripted client with a valid session completes the handshake. | Browser POST returns 403 Invalid Origin; curl with the session cookie and no Origin returns 200. | [A7](advanced-07-master-of-resources/) | T0049 |
| UI-hidden tool is still callable | A tool hidden from the agent UI stays in `tools/list` and `tools/call`. | `unlock_flag {}` runs when called directly. | [A7](advanced-07-master-of-resources/) | T0053 |
| Self-declared security flag | The server trusts a field the attacker controls (`status: "SAFE"`). | The SAFE manifest clears the gate legitimately. | [E7](expert-07-the-octopus/) | T0053 |
| Verbose error leaks the required secret | The permission error returns the exact admin key. | `does not match the required administrator key: '...'`. | [E7](expert-07-the-octopus/) | none |
| Ambient-state poisoning when the argument is ignored | The tool reads an ambient session key, not the passed argument, so write the ambient state through another tool. | Passing the key as `session_id` changes nothing; a truncated upload appears verbatim as the key. | [E7](expert-07-the-octopus/) | T0053 |
| Agent as the attacker's scheduler | Instruct the model to drop its own pre-check and issue parallel tool calls. | The agent complies and fires simultaneous executions. | [E8](expert-08-the-heist/) | T0051.000, T0053 |
| Client-supplied immutable parameter | Set a server-assumed value from the client (`price: 0`). | The $0 order executes and still unlocks the goal. | [E8](expert-08-the-heist/) | T0053 |

### Phase 5. Exfiltrate

| Technique | What it is | Signal / trigger | Seen in | ATLAS |
|---|---|---|---|---|
| In-band boolean oracle (blind) | Turn a one-bit Online/Offline reply into yes/no extraction. An anchored-grep literal grows one character at a time, four bracket-class probes carry four bits per hex digit, and the brute runs in the agent's own loop. No attacker infrastructure, and nothing leaves the platform. | A dead host plus an injected test, where the test's exit code sets Online or Offline. | [A9](advanced-09-blind-network-ninja/) | T0050, T0053 |
| Direct privileged read after access | Once privileged or handshaked, read the protected resource. | `read_root_flag` returns the flag; `resources/read resource://flag` returns it after `unlock_flag`. | [A7](advanced-07-master-of-resources/), [E7](expert-07-the-octopus/) | T0053 |
| Goal reached by business-logic abuse | The flag unlocks on a broken invariant, not a data read. | `DUAL FRAGMENTS DETECTED` fires with the balance at or below zero. | [E8](expert-08-the-heist/) | T0053 |

The encoding channel is the Advanced 5 Phase 4 technique seen from the exfiltration side. The dict-key channel is the Expert 6 Phase 4 technique seen the same way.

## ATLAS tags

IDs verified against the current MITRE ATLAS data set. T0049 Exploit Public-Facing Application, T0050 Command and Scripting Interpreter, T0051.000 LLM Prompt Injection: Direct, T0053 AI Agent Tool Invocation, T0069.000 Discover LLM System Information: Special Character Sets, T0084 Discover AI Agent Configuration and T0084.001 Tool Definitions. Only Expert 8 maps direct prompt injection (T0051.000): the prompt dictated the transaction scheduling. The other five map tool invocation and discovery, because no instruction or guardrail was shown to be overridden.
