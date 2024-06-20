# [Segurança de Sistemas - T2 - RSA, AES, SHA](https://github.com/debemdeboas/pucrs-seguranca-de-sistemas-t2)

This project is a simple implementation of RSA, AES, and SHA.
It can:
- generate a simple key pair,
- verify message signatures given a known public key,
- encrypt and decrypt messages using AES-128

Run `make` to compile the project.
Requires `openssl` and `libssl-dev`.

After compiling, run `./main` to get a small help message.

```shell
$ ./main
Usage: ./main <mode>

Basic modes:
        gen     Generate a key pair and write it to alice.kp
        sign    Generate a symmetric key using AES-128, encipher the key, sign it and write everything to sig.txt

File-related modes:
        verify <file>               Verify <file>'s signature using Bob's key from bob.pk
        decrypt <file>              Decrypt <file> and print to stdout
        encrypt_inv <file>          Decrypt <file> and create a new encrypted and signed message inverting <file>'s contents
        encrypt <file> <message>    Decrypt <file>, verify its signature, and write <message> to <file>.alice
```

## Example usage

```shell
$ ./main gen
$ echo <public key e> > bob.pk
$ echo <public key n> >> bob.pk
$ ./main sign # generates sig
$ ./main encrypt_inv sig.txt
```
