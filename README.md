# TL;DR

```bash
zokrates compile -i computes/registration_verify.zok -o computes/registration
zokrates compile -i computes/publication_verify.zok -o computes/publication

zokrates setup -i computes/registration -s g16 -p computes/r_proving.key -v computes/r_verification.key
zokrates setup -i computes/publication -s g16 -p computes/p_proving.key -v computes/p_verification.key

zokrates export-verifier -i computes/r_verification.key -o contracts/r_verifier.sol
zokrates export-verifier -i computes/p_verification.key -o contracts/p_verifier.sol
```

---

# References

https://github.com/Zokrates/pycrypto
https://zokrates.github.io/examples/sha256example.html
