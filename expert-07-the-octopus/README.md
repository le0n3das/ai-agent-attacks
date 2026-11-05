# Expert 7, The Octopus: a cache update that writes your session key

![Attack chain: a permission error leaks the exact admin key; the privileged read tool ignores the session_id argument and reads an ambient key; the only state-writing tool is a cache updater gated by a self-declared SAFE flag that writes uploaded file content verbatim as the session key; uploading the leaked key escalates to the privileged session and reads the root flag; the right panel shows the self-asserted SAFE flag and the verbose error as the two gifts to the attacker](diagram.png)

> ARKX Mothership, Expert track, level 7. Public CTF by CyberArk Labs.

---

## Context

The level presents a "Distributed Coordination Node", a multi-agent system where workers handle utilities, files and clearance. The agent intro is identical to a beginner trial banner, so the level is identified by its tool panel and scoped track, not by the banner.

The panel exposes six tools: `summarize_text`, `detect_errors`, `upload_file`, `process_cache_update`, `read_root_flag`, `get_system_status`. The goal is clear from `read_root_flag`, described as reading the root flag if the session is privileged. The task is to reach a privileged session.

## Recon

Asked the agent for the tools, parameters and the clearance flow. The tool names and descriptions matched the panel. The flow was partly confabulated: the agent described a privileged session handed from one worker to another and a clearance token format, none of which a real call confirmed. The flow was treated as unverified until a call proved it.

## Baselines and the leaked key

```
get_system_status                 -> "Benign: All"
read_root_flag (any session_id)   -> permission denied
```

The denial over-discloses:

```
Your session key 'NO_PRIVILEGE' does not match the required administrator key: 'GRANT_ROOT_READ_FOR_SESSION_778'
```

The required admin key is leaked verbatim in the error (CWE-209).

## Argument against ambient state

`read_root_flag` with `session_id` set exactly to the leaked key still reported `Your session key 'NO_PRIVILEGE'`. The tool ignores the `session_id` argument and reads an ambient session key. The key has to be changed in server state, not passed as an argument.

## Map the write path

The only tool that writes state is `process_cache_update`. Its schema was mapped through errors, one layer at a time:

```
manifest with no status field   -> ERROR: Security check failed. Manifest status must be 'SAFE'.
{"status":"SAFE"}               -> ERROR: Logic failed. 'cache_task_id' not found.
```

The status check runs before the parse, and the manifest needs a `cache_task_id`. A source for that id is `upload_file`, which returns `file_id_<n>.txt`:

```
{"status":"SAFE","cache_task_id":"<file_id>"}  -> SUCCESS: Cache updated.
{"status":"SAFE","cache_task_id":"bogus"}      -> ERROR: Could not read file content.
```

So `process_cache_update` reads the uploaded file's content and applies it.

## What it applies the content as

A character-limit truncation gave it away. A manifest upload was cut to `{"st`, and the next `read_root_flag` reported `Your session key '{"st'`. The uploaded file content is written verbatim as the ambient session key. No field parsing, no validation, no clearance from any worker. The file content becomes the session key.

## Solve

Upload a file whose content is exactly the leaked admin key (31 characters, under the truncation limit), run the cache update against that file, then read the flag:

```
upload_file  (content = GRANT_ROOT_READ_FOR_SESSION_778)      -> file_id
process_cache_update {"status":"SAFE","cache_task_id":"<file_id>"} -> SUCCESS
read_root_flag (session_id "NO_PRIVILEGE")                     -> SUCCESS: <flag>
```

## Root cause

Privilege escalation through an unauthenticated session-key write. `process_cache_update` is a privileged, state-changing tool that takes user-uploaded file content and writes it verbatim into the ambient session key, with no authorization (CWE-862). `read_root_flag` then trusts that ambient key. The clearance worker in the design never enforced anything.

The only guard is a self-declared `status: "SAFE"` field inside the attacker-controlled manifest (CWE-807). The client declares its own request safe.

The permission error hands the attacker the exact required admin key (CWE-209). The `session_id` argument is ignored in favor of ambient state, so the attacker needs to poison that state only once.

The platform's intended path is a parser differential: a regex security filter and the JSON parser disagree on duplicate keys, so two `status` keys bypass the check. This solve did not need it. `status: "SAFE"` passed legitimately, and the real defect is downstream: the verbose-error key disclosure and the unauthenticated session-key write. The parser differential is a real third bug, cited and unused.

## Impact

Critical. An unprivileged chat user escalates to the privileged session and reads root-only data, using only public tools: upload a file, run a cache update. No clearance, no credential, one leaked string from an error. In a real agent deployment this is full authorization bypass of the privileged tool tier.

## Remediation

- Authorize privileged tools server-side on caller identity, not on a self-declared manifest flag.
- Never let a cache or file-write primitive set a session's privilege or key.
- Make the privilege check read a value the write path cannot reach.
- Stop echoing the required key in error messages.

---

*ATLAS: T0053 AI Agent Tool Invocation. OWASP LLM 2025: LLM06 Excessive Agency, LLM02 Sensitive Information Disclosure, LLM09 Misinformation (the confabulated clearance flow). OWASP A01 Broken Access Control. CWE-862, CWE-807, CWE-209, CWE-269.*
