# Java-Crypto-Utils
## Java Cryptographic, Encoding and Hash Utilities
- **[CryptoUtils.java](https://github.com/tunjos/java-crypto-utils/blob/master/src/main/java/co/tunjos/crypto/crypto/CryptoUtils.java)**
- **[EncodingUtils.java](https://github.com/tunjos/java-crypto-utils/blob/master/src/main/java/co/tunjos/crypto/encoding/EncodingUtils.java)**
- **[HashUtils.java](https://github.com/tunjos/java-crypto-utils/blob/master/src/main/java/co/tunjos/crypto/hash/HashUtils.java)**

[![CircleCI](https://circleci.com/gh/tunjos/java-crypto-utils.svg?style=svg)](https://circleci.com/gh/tunjos/java-crypto-utils)  Build: [Maven](https://maven.apache.org/)

Install Maven

	sudo apt install maven

To run the unit tests:

	mvn test

### Encryption/Decryption Algorithms - Descriptions

Term | Description
---------- | ----------
**AES** | **Advanced Encryption Standard**
**Encryption** | The process of encoding information making in away that makes it unreadable for unauthorized users. `Plaintext` -> `Ciphertext`
**Decryption** | The reverse process of `encryption`. It is the process of decoding the data which has been encrypted making it readable for authorized users. `Ciphertext` -> `Plaintext`
**Cryptographic key/Key** | Is a piece of information (a parameter) that determines the functional output of a cryptographic algorithm.
**RSA** | **Rivest-Shamir-Adleman** (Surnames of the creators)
**Symmetric Cryptography/Symmetric-Key Cryptography** | Makes use of the same cryptographic keys for both `encryption` of `plaintext` and `decryption` of `ciphertext`.
**Asymmetric Cryptography/Public-Key Cryptography** | Makes use of different cryptographic keys(pair of `public` and `private keys`) used for `encryption` of `plaintext` and `decryption` of `ciphertext`.
**Public Key** | A key that is available to the public.
**Private Key** | A key that is private and known only to the owner.
**Cipher/Cypher** | An algorithm for performing `encryption` or `decryption`.
**Plaintext/Cleartext** | An `unencrypted` information pending input into a cryptographic algorithm.
**Ciphertext** | The result of `encryption` performed on `plaintext` using an algorithm - `Cipher`.
**Block Size** |   The length of the fixed length string of bits operated on by a `Block Cipher`. Both the input (`plaintext`) and output (`ciphertext`) are of the same length.
**Key Size/Key Length** | The number of bits in a key used by a cryptographic algorithm.
**Rounds** | In Block Ciphers, the number of times a `cipher transformation` is repeated over a block of `plaintext` to create a block of `ciphertext`. The number of `rounds` is determined by the `key size/ key length`.
**Block Cipher** | A Symmetric-Key `Cipher` which operates on a groups of bits of fixed length, called `blocks`.
**[Block Cipher Mode of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)** | Is an algorithm that uses a `block cipher` to provide information security such as `confidentiality` or `authenticity`. It describes how to repeatedly apply a cipher's single-block operation to securely transform amounts of data larger than a block.
**Common Block Cipher Modes of Operation** | **ECB**(`Electronic Codebook`), **CBC**(`Cipher Block Chaining`), **PCBC**(`Propagating` **CBC**[`Cipher Block Chaining`]), **CFB**(`Cipher Feedback`), **OFB**(`Output Feedback`), **CTR**(`Counter`)
**Broken** | When `brute-force attack` is feasible i.e A key with a given key size can be permutated in feasible time to generate a key that correctly decrypts a `Ciphertext`.
**Brute-force attack** |  When an attacker guesses many keys with the hope of eventually guessing correctly usually using a `supercomputer`.


## Encryption/Decryption Algorithms - Symmetric
- **[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)**
Variants: **AES-128**, **AES-192**, **AES-256**  
Key sizes: _128 bits_, _192 bits_, _256 bits_  
Block Size: _128 bits_  
Rounds: **10, 12 or 14** (depending on key size)

## Encryption/Decryption Algorithms - Asymmetric

- **[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))**  
Key sizes: _1,024 to 4,096 bit typical_   
Rounds: **1**


### Hash Functions - Descriptions

Term | Description
---------- | ----------
**MD5** | Message-Digest Algorithm
**SHA-1** | **Secure Hash Algorithm 1**
**SHA-2** | **Secure Hash Algorithm 2**
**SHA-3** | **Secure Hash Algorithm 3**
**HMAC** | **Keyed-Hash Message Authentication Code** or **Hash-Based Message Authentication Code**
**Cryptographic Hash function** | A mathematical algorithm that maps data of arbitrary size to a bit string of a fixed size (a `digest/hash`) and is designed to be a one-way function - a function which is infeasible to invert.
**Digest/Hash** | The output of a Cryptographic Hash function.
**Digest Size** | The size of the output of a `Cryptographic Hash function`.
**Block Size** | The length of the fixed length string of bits operated on by a `Cryptographic Hash function`.
**Rounds** | In `Cryptographic Hash functions`, the number of times a `digest` transformation stage is repeated over a block of plaintext to create a `digest`.
**Salt** | Random data that is used as an additional input to a one-way function(`Cryptographic Hash functions`) that "hashes" data, a password or passphrase.
**Data Integrity** | Is the maintenance of, and the assurance of the `accuracy` and `consistency` of, data over its entire life-cycle.
**Authentication** | Guarantees that a message has not been modified while in transit (`data integrity`) and that the receiving party can `verify` the source of the message.
**Broken** | When a `collision` is found. i.e two different inputs generate the same hash usually using a `supercomputer`.


## Hash Functions
- **[MD5](https://en.wikipedia.org/wiki/MD5)**  
Digest Size: _128 bit_  
Block Size: _512 bit_  
Rounds: **4/64** (depending of Point of View)  
Broken: Yes

- **[SHA-1](https://en.wikipedia.org/wiki/SHA-1)**  
Digest Size: _160 bit_  
Block Size: _512 bit_  
Rounds: **80**  
Broken: Yes  

- **[SHA-2](https://en.wikipedia.org/wiki/SHA-2)**  
Variants: **SHA224**, **SHA256**, **SHA384**, **SHA512**, **SHA-512/224**, **SHA-512/256**
Digest Size: [SHA-224: _224 bit_], [SHA-256: _256 bit_], [SHA-384: _384 bit_], [SHA-512: _512 bit_], [SHA-512/224: _224 bit_], [SHA-512/256: _224 bit_]  
Block Size: [SHA-224,SHA-256: _512 bit_], [SHA-384,SHA-512,SHA-512/224,SHA-512/256: _1024 bit__]  
Rounds: [SHA-224,SHA-256: **64**], [SHA-384,SHA-512,SHA-512/224,SHA-512/256: **80**]  
Broken: No

- **[SHA-3](https://en.wikipedia.org/wiki/SHA-3)**  
Variants: **SHA3-224**, **SHA3-256**, **SHA3-384**, **SHA3-512**, **SHAKE128**, **SHAKE256**  
Digest Size: [SHA3-224: _224 bit_], [SHA3-256: _256 bit_], [SHA3-384: _384 bit_], [SHA3-512: _512 bit_], [SHAKE128,SHAKE256: _d (arbitrary) bit_]  
Block Size: [SHA3-224: _1152 bit_], [SHA3-256: _1088 bit_], [SHA3-384: _832 bit_], [SHA3-512: _576 bit_], [SHAKE128: _1344 bit_], [SHAKE256: _1088 bit_]  
Rounds: **24**  
Broken: No

## HMAC Functions
- [HMAC_MD5](https://en.wikipedia.org/wiki/HMAC)
- [HMAC_SHA1](https://en.wikipedia.org/wiki/HMAC)
- [HMAC_SHA256](https://en.wikipedia.org/wiki/HMAC)
- [HMAC_SHA512](https://en.wikipedia.org/wiki/HMAC)


### Encoding Algorithms - Descriptions

Term | Description
---------- | ----------
**[Binary-to-text Encoding](https://en.wikipedia.org/wiki/Binary-to-text_encoding)** |  Encoding of data in `plaintext`. More precisely, it is an encoding of binary data(bytes/bits) in a sequence of printable characters.
**Base64** | A  group of similar `binary-to-text encoding` schemes that represent binary data in an ASCII string format by translating it into a radix-64 representation. Each `Base64` digit represents exactly 6 bits of data. Three 8-bit bytes (i.e., a total of 24 bits) can therefore be represented by four 6-bit `Base64` digits.
**URL encoding/Percent-encoding** | A mechanism for encoding information in a `Uniform Resource Identifier` (**URI**) under certain circumstances.

## Encoding Algorithms
- **[Base64](https://en.wikipedia.org/wiki/Base64)**
- **[URL encoding](https://en.wikipedia.org/wiki/Percent-encoding)**



	Note: A hash function is not an encryption/decryption function.

License
----------

  Copyright THIS YEAR tunjos

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
