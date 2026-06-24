# Security Policy

## Scope and threat model

`llm-guard` is a **defense-in-depth** control that inspects text at the
user ⇄ LLM boundary. It reduces the likelihood of prompt-injection, jailbreak,
and sensitive-data-leakage incidents — it does **not** guarantee prevention
against a determined or novel adversary. Treat it as one layer alongside
least-privilege tool access, output encoding, rate limiting, and human review
for high-stakes actions.

By design, `llm-guard`:

- requires **no network access** and **no API keys** for its own operation;
- never logs or transmits the text it scans;
- **redacts** any secrets it detects before placing them in a result or report.

## Supported versions

The latest released minor version receives security fixes.

| Version | Supported |
|---------|:---------:|
| 0.1.x   | ✅ |

## Reporting a vulnerability

Please report security issues **privately**:

1. Use GitHub's [private vulnerability reporting](https://github.com/BasitS-hash/llm-guard/security/advisories/new)
   ("Report a vulnerability" on the Security tab), **or**
2. Open a minimal issue **without** exploit details and ask for a private channel.

Please include:

- a description of the issue and its impact,
- a minimal reproduction (input text and observed vs. expected verdict),
- the `llm-guard` version and Python version.

Do **not** include live credentials in a report — redact them.

### What to expect

- Acknowledgement within **3 business days**.
- An initial assessment within **7 business days**.
- Coordinated disclosure once a fix is available; credit offered unless you
  prefer to remain anonymous.

## Detection gaps and false negatives

A missed attack (false negative) or an over-eager block (false positive) is a
quality issue, not necessarily a vulnerability — but both matter. Please report
them as regular issues with the offending input so the rule set can be tuned.
Improving precision and recall is a first-class goal of the project.
