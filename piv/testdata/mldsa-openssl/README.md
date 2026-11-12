# Independent ML-DSA signing fixtures

Generated and verified with OpenSSL 3.6.3 (9 Jun 2026), using its default
provider. These fixtures contain only a public key and signatures. The private
key was generated in a temporary directory and removed after generation.
The Go tests do not require OpenSSL.

The message is the ASCII string `piv-go independent ML-DSA signing options vector`
without a newline. All signatures use deterministic ML-DSA-44 with an empty
context:

- `mldsa44-public.der`: DER SubjectPublicKeyInfo.
- `pure-message.sig`: pure ML-DSA over the message.
- `pure-sha512.sig`: pure ML-DSA over the 64-byte SHA-512 digest, treated as an
  ordinary message.
- `hashmldsa-sha512.sig`: the HashML-DSA/SHA-512 domain, generated through
  OpenSSL's test-only unencoded internal-sign interface. The input is
  `01 00 || DER-OID(SHA-512) || SHA512(message)`, as specified by
  [FIPS 204, Algorithms 4 and 5](https://doi.org/10.6028/NIST.FIPS.204).

This last fixture tests that the domains differ; piv-go does not expose an
internal-sign or HashML-DSA operation. Prefixing an ordinary pure-message input
would add pure ML-DSA's own domain encoding and would not implement HashML-DSA.

From the repository root, equivalent fixtures and the independent verification
checks can be generated with the following script. The generated key is random,
so regenerating produces new public artifacts.

```python
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

openssl = os.environ.get("OPENSSL", "openssl")  # OpenSSL 3.6.3 with ML-DSA support
out = Path("piv/testdata/mldsa-openssl")
message = b"piv-go independent ML-DSA signing options vector"

with tempfile.TemporaryDirectory(prefix="piv-go-mldsa-") as tmp:
    base = Path(tmp)
    key, msg, digest, prehash = [base / name for name in
                                ("key.pem", "message", "digest", "prehash")]
    msg.write_bytes(message)
    digest.write_bytes(hashlib.sha512(message).digest())
    prehash.write_bytes(bytes.fromhex("01000609608648016503040203") +
                        digest.read_bytes())

    def run(*args, expected=0):
        result = subprocess.run([openssl, *map(str, args)], capture_output=True)
        assert result.returncode == expected, result.stderr.decode()

    run("genpkey", "-algorithm", "ML-DSA-44", "-out", key)
    public = out / "mldsa44-public.der"
    run("pkey", "-in", key, "-pubout", "-outform", "DER", "-out", public)
    for source, name, extra in [
        (msg, "pure-message.sig", []),
        (digest, "pure-sha512.sig", []),
        (prehash, "hashmldsa-sha512.sig", ["-pkeyopt", "message-encoding:0"]),
    ]:
        sig = out / name
        run("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", source,
            "-out", sig, "-pkeyopt", "deterministic:1", *extra)
        run("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
            "-in", source, "-sigfile", sig, *extra)

    run("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
        "-in", prehash, "-sigfile", out / "pure-sha512.sig",
        "-pkeyopt", "message-encoding:0", expected=1)
    run("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public,
        "-in", digest, "-sigfile", out / "hashmldsa-sha512.sig", expected=1)
```
