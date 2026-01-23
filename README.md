# Cryptography App

A terminal-based Python library room reservation app using various cryptographic algorithms to put into practice the topics covered in class. 

This application allows students to register, authenticate, book rooms and verify reservations while guaranteeing the confidentiality and the integrity of all stored information.

## Main cryptographic features

- `Scrypt` **for password key derivations:** Passwords are never stored directly, instead they are passed with a salt through a KDF.

- `PBKDF2HMAC` **for cryptographic key derivations:** Encryption keys are uniquely derived from a users password and a second salt.

- `ChaCha20Poly1305` **for authenticated encryption:** When any data is encrypted, associated metadata is simultaneously authenticated.

- `RSA-PSS` **for digital signatures:** All reservations are signed to guarantee their authenticity.
  
- `x509` **for public key certificates:** A local root CA issues and verifies user certificates, building a mini-PKI.
  
- `PKCS8` **for key serialisation:** All private keys are stored using this format, encoded as PEM.

- `RSA-SHA256` **for certificate verification:** The certificate's signature is verified to ensure the integrity of the associated public key.

## Getting started

### Requirements
1. Make sure you have `Python 3.10+`
2. Install the Python cryptography library. To do so, run

    ```
    pip install cryptography
    ```

### How to run
1. First, clone the repository and open it as the main folder in your IDE for all paths to work.
2. To run the application, run the `crypto main.py` script. It handles the main user workflow of the app.

## Authors

This project was developed collaboratively by [100551049-ctrl](https://github.com/100551049-ctrl) and [dgarciaCl](https://github.com/dgarciaCl). Check out our profiles to see our other works.

> Developed as part of a Cryptography course
