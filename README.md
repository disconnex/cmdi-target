# cmdi-target

**Intentionally vulnerable** OS command-injection test fixture (CWE-78) for
adversarial-testing validation — the same class of deliberate-vuln app as
OWASP Juice Shop / VAmPI. `GET /ping?host=` interpolates `host` into a shell
unsanitized. **Do not deploy outside an ephemeral sandbox.**
