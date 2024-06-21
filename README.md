# [Segurança de Sistemas - T2: RSA, AES, SHA](https://github.com/debemdeboas/pucrs-seguranca-de-sistemas-t2)

This project is a simplified implementation of RSA, AES, and SHA message signing and encryption.
It can:
- generate an RSA key pair,
- generate a symmetric key using AES-128, encipher it, sign it, and save it to a file,
- verify message signatures given a known public key,
- encrypt and decrypt messages using AES-128

## Examples

If you run `./main samples` it will generate the following files:
- `alice.kp` containing Alice's key pair $({sk}_a,{pk}_a)=((d_a, N_a),(e_a,N_a))$
- `bob.pk` containing Bob's public key $pk_b=(e_b, N_b)$
- `sig.txt` containing an AES key $s$, $x=s^{e_b}mod N_b$, its signature $sig=x^{d_a}mod N_a$, and Alice's public key $(e_a, N_a)$
- `message.txt` containing a simple signed message
- `message_inv.txt` containing alice's response to the previous message, which is the inverse of `message.txt` (signed and encrypted)
- `message_2.txt` containing a response to alice's previous message

With these files, you can run the following commands:

```shell
$ ./main verify message.txt
Signature is valid
$ ./main decrypt message.txt
<Decrypted message contents... This is also saved to message.txt.decrypt>
$ ./main encrypt_inv message.txt
<Decrypted message contents...>
<Inverted message... This is also saved to message_inv.txt>
```

## Running

Run `make` to compile the project.
Requires `openssl` and `libssl-dev`.

After compiling, run `./main` to get a small help message.

```shell
$ ./main
Usage: ./main [command]

Basic commands:
        help      Display this help message and exit
        samples   Write sample files to disk and exit
        gen       Generate a key pair and write it to alice.kp
        sign      Generate a symmetric key using AES-128, enciphers the key, signs it and write everything to sig.txt

File-related commands:
        verify <file>               Verify <file>'s signature using Bob's key from bob.pk
        decrypt <file>              Decrypt <file> and print to stdout
        encrypt_inv <file>          Decrypt <file> and create a new encrypted and signed message inverting <file>'s contents
        encrypt <file> <message>    Decrypt <file>, verify its signature, and write <message> to <file>.alice

File structure:
        sig.txt is the signature file, it is structured as follows (one per line):
                AES_key
                AES_key^e_b mod n_b, A.K.A. x
                sig = x^d_a mod n_a
                Alice's public key e_a
                Alice's public key n_a

        alice.kp is Alice's key pair file, it is structured as follows (one per line):
                Alice's secret key d
                Alice's secret key n
                Alice's public key e
                Alice's public key n (same as secret key n)

        bob.pk is Bob's public key file, it is structured as follows (one per line):
                Bob's public key e
                Bob's public key n

        <file> is an encrypted and signed message file, and it is structured as follows:
                Signature
                IV (16 bytes) + Message
```
