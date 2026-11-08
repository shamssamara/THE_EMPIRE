# Security and responsible-use statement

THE_EMPIRE is an experimental network and remote-administration prototype for isolated, authorized lab environments only. Do not install, deploy, or operate it on systems without documented owner consent.

## Known limitations identified during source review

- The application explicitly disables authentication for the agent/session protocol. TLS encryption is **not authentication**.
- The TLS client context disables server certificate verification (`CERT_NONE`) and hostname checks. Clients cannot verify they are speaking with the intended endpoint.
- Agent staging is served over plain HTTP in the current source, despite other connections supporting TLS 1.3. Therefore it is inaccurate to claim that **all** delivery traffic is encrypted.
- The agent contains self-relocation, self-deletion, and process-name-masking behavior. These require especially careful review and transparent authorization before any legitimate use.
- The program permits command execution and file transfer and should not be exposed to public networks in its present form.

**Security status:** Not independently audited. No claims are made that the implementation is secure or production ready.

Security reports: contact the repository owner privately. Do not post credentials, tokens, endpoints or sensitive logs in public issues.
