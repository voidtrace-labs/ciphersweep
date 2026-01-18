## CipherSweep

CipherSweep is a fast, scriptable TLS scanner that maps protocol/cipher support, flags common misconfigurations, and outputs results as JSON.

### Quick Start

```bash
# 1) Clone & enter
git https://github.com/voidtrace-labs/ciphersweep.git
cd ciphersweep

# 2) Python env
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

# 3) (Optional) Build OpenSSL toolchains
make -C openssl-builds

# 4) Prepare targets
printf '%s\n' https://mozilla-old.badssl.com/ mozilla-intermediate.badssl.com:443 mozilla-modern.badssl.com > targets.input


# 5) Run scan 
ciphersweep targets.input results.json --openssl-prefix ./openssl-builds/build

```