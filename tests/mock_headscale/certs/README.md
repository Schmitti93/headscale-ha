# Test certificates

These files are deterministic, non-production fixtures used only by the isolated
Docker smoke test. The private key protects no deployed endpoint and must never be
reused outside this test stack. Secret-scanner exceptions are limited to this known
fixture. Production credentials and certificates must not be added to the repository.
