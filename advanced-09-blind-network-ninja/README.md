# Advanced 9, Blind Network Ninja: reading a flag through one bit

![Attack chain: a connectivity tool returns only Online or Offline; a newline injects a second shell command past a denylist; a dead host plus a test command turns the one-bit reply into a yes/no oracle; the flag is read one hex character at a time with anchored grep and four bracket-class probes per digit, with the brute delegated to the agent's own loop; the right panel contrasts the in-band oracle with the out-of-band exfiltration the platform expected](diagram.png)

> ARKX Mothership, Advanced track, level 9. Public CTF by CyberArk Labs, played as a participant.
> The flag is a CTF value. No third-party data appears here.

---

## Context

The level presents a "Network Discovery Service", a tool that verifies host uptime and returns a simple status for availability checks. The tool `check_connectivity` pings a host and returns "Online" if it is reachable, "Offline" otherwise. The tool returns one bit per call, so the whole channel is Online against Offline. Any extraction has to ride that bit.

## Recon and baselines

Asked the agent for the tool and its parameter. One tool, `check_connectivity`, one host argument. Baselines establish two stable, distinguishable states:

| Host | Result |
|---|---|
| `127.0.0.1` | Online |
| `localhost` | Online |
| `203.0.113.1` | Offline |
| `nonexistent.invalid` | Offline |

## Fingerprint the backend

The host argument is tested for shell behavior, one probe at a time:

```
127.0.0.1 #xyz                         -> Online   (trailing # is a shell comment)
127.0.0.1 -c 1                         -> Online
nonexistent.invalid <newline> true     -> Online    <- decisive
nonexistent.invalid <newline> false    -> Offline
```

A dead host returning Online proves a second command ran. The backend is a shell, the input reaches it, and the Online/Offline bit follows the exit code of the command line. Online is exit code 0, Offline is nonzero.

## Map the defenses

A separator survey, one primitive per probe, shows which separator the shell sees:

```
;   &&   ||   $(...)   backticks   -> Offline or mangled
<newline>                          -> survives as a command separator
```

The denylist blocks the common separators and forgets the newline. The agent layer also normalizes input when instructions are loose: it injected the item label into the host and turned an escaped newline into a literal backslash-n. The method correction is to hand the agent JSON strings to decode and to verify the echoed argument is two real lines before trusting any result.

## Build the oracle

With the newline separator, the host becomes `nonexistent.invalid` plus newline plus a test command, and the test's exit code sets Online or Offline:

```
nonexistent.invalid <newline> test 1 -eq 1   -> Online   (external utilities run, not only builtins)
nonexistent.invalid <newline> test -e flag.txt -> Online  (a file named flag.txt exists)
nonexistent.invalid <newline> test -r flag.txt -> Online  (readable regular file)
nonexistent.invalid <newline> env | grep -qi flag -> Offline (not in the environment)
```

Length math through command substitution was unreliable, because `$(...)` is mangled by the agent layer. The flag is read positionally instead.

## Extract the flag

A pipe through `cut` failed even on known characters, so extraction uses an anchored, whole-file grep that grows a literal pattern one character at a time:

```
grep -q ^flag- flag.txt                       -> Online
grep -q ^flag-<known><candidate> flag.txt      -> Online when the candidate matches
```

Per position, four independent bracket-class probes encode the hex digit as four bits, where Online is 1:

```
[89a-f]     bit 3
[4-7c-f]    bit 2
[2367abef]  bit 1
[13579bdf]  bit 0
```

The per-position brute was delegated to the agent itself as a loop: the host is built from a growing prefix and sixteen candidates. That removed the per-payload character limit and had the agent automate its own exploitation. Read out character by character, the pattern resolves to the flag.

## Beyond the expected path

The platform's intended solution is out-of-band exfiltration: inject a command, suppress output, send the data to an attacker-controlled server over DNS or HTTP. This solve used none of that. The tool's own Online/Offline reply became an in-band boolean oracle, and the flag was read bit by bit. No attacker infrastructure, and nothing leaves the platform. Egress filtering or DNS and HTTP monitoring would not have stopped this, because no outbound connection was ever made. The only control that works is the one both paths land on: prevent the injection at the source.

## Root cause

`check_connectivity` passes the attacker-controlled host into a shell command line without validation, so a hostname field is a command field (CWE-78). The agent is a pass-through and does not classify the host as hostile input.

The only returned signal is a boolean, which the designers likely assumed was safe. It is a complete exfiltration channel when the attacker controls the condition.

The denylist is incomplete (CWE-184): it blocks several separators and forgets the newline.

## Impact

Critical. Remote code execution in the tool runtime through a chat interface, same class as Advanced 5 but blind. An attacker reads any file the process can reach and exfiltrates it through the uptime oracle, and can pivot from the host. The blind channel slows exfiltration without preventing it.

## Remediation

- Never build the command line from user input. Resolve and validate the host against a strict hostname or IP allowlist, then call `ping` through an argument vector with no shell.
- Run the tool with no file-system access to secrets.
- Do not assume a low-bandwidth return channel is harmless. One bit per call still carries a full flag.

---

*ATLAS: T0050 Command and Scripting Interpreter, T0053 AI Agent Tool Invocation, T0069.000 Discover LLM System Information: Special Character Sets. OWASP LLM 2025: LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM02 Sensitive Information Disclosure. CWE-78, CWE-184.*
