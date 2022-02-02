# hashtreesig (Java edition)
This is an implementation of parallel signature generation using Merkle hashtree structure and EC-DSA Signatures.
It has a simple, bare-bones GUI built using the OpenJFX Javafx package, 
and utilizes the JSON Web Signature standard format by using the Nimbus JOSE + JWT library as a base.

**Note**: The GUI implementation and its distribution were developed and tested exclusively on a PC running Windows 10. 
No cross-platform compatibility has been attempted.

## About 

Hashtreesig was developed by F. Krause as a semester project as an IT-Security student at the Hochschule Stralsund (HOST). 
They were supervised by Prof. Dr.-Ing. Andreas Noack and in cooperation with the gematik GmbH (contact A. Hallof).

It is distributed under an GNU General Public License. The license text can be found in the program files, named "license.txt" 

## Documentation

Most of the documentation was done using javadoc annotation. 
The resulting Doc can be found [here](https://kellycolt.github.io/hashtreesig-java/hashtreesig.main/module-summary.html).

## Aspect Notes

### Merkle Hashtree Structure

Merkle Hash trees are binary trees in which every parent node contains a cryptographic hash of its children. 
It allows efficient and secure verification of large data structures.

For this implementation, SHA256 was used for all hashes.

### Signature

For our signature, ECDSA was chosen. ECDSA, aka Elliptic Curve DSA, is a variant of classic DSA (Digital Signature Algorithm), 
which increases efficiency by using Elliptic Curves instead of relying upon modular exponentiation. 

After the Hashtree Structure has been built, only its root node is signed. 
Using this single signature and the hashes that are combined into the original hash along the tree's branch, every leaf node can be verified. 
Since Hash Algorithms are much less processing intensive than signing algorithms, this procedure saves resources opposed to signing each node separately.

### JSON Web Signature Format

The JSON Web Signature (RFC7515) Format is a standard proposed by IETF. 
It uses JavaScript Object Notation (JSON) to represent all necessary information about a given Signature.

A JWS is made up of three parts, separated by "." characters. Those parts are:

- JOSE Header
- JWS Payload
- JWS Signature

Each of the  parts is presented in Base64URL encoding. 

#### Header

The header contains algorithm and parameters used for the given signature. 
The "alg"-value that was chosen to represent our algorithm is "HTES256". 
A field titled "x5c" should be included, for passing the certificate chain used. 
Otherwise a certificate must be externally specified. 
This is not implemented into the GUI, but possible using the HTJWSVerifier class.

#### Payload

The Payload represents the signed data. As such, here, it is the SHA256 hash over the signed data which was a leaf in the Hashtree.

#### Signature

For the sake of verification, the sibling nodes along the branch are passed in an Array Object titled "ht_path". 
These are used to then verify the signature passed in "ecdsa_sig". 

#### Example JWS

The actual JWS are Base64URL-encoded and thus not human readable. 
Here is a Decoded example (hash omitted): 
```
{
  "x5c": [
    "MIICPzCCAeWgAwIBAgIUbvojgcSuEMVE70MnfBtCoX+HSH8wCgYIKoZIzj0EAwIwdTELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMRAwDgYDVQQKDAdnZW1hdGlrMRAwDgYDVQQLDAdnZW1hdGlrMSAwHgYDVQQDDBdIYXNodHJlZS1TaWduZXItRXhhbXBsZTAeFw0yMTA0MjAxNTE5MzRaFw0yNjA0MTkxNTE5MzRaMHUxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjEQMA4GA1UECgwHZ2VtYXRpazEQMA4GA1UECwwHZ2VtYXRpazEgMB4GA1UEAwwXSGFzaHRyZWUtU2lnbmVyLUV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQyznSs1COkntQx4mP/x6AuGbaj8Qk5LlN0e98EefU9vKu1pd12xkWWVocpca91Kvg1gVj67zvglpEHM8Gp49V3o1MwUTAdBgNVHQ4EFgQUusy3zmQdvQQDNFZ7WQyg/NNZ1iIwHwYDVR0jBBgwFoAUusy3zmQdvQQDNFZ7WQyg/NNZ1iIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA7a2R1b9XclYCKk2sElHW7LfnrnYcRz/gOw/dcGeNUncCIE452YKIOShdl+FQLjKC4FBpphhTZBHxVF3fdy6/GNpn"
  ] ,
  "alg": "HTES256"
}
.
[hash]
.
{
  "ht_path": [
    "rHm9KyIeN1SP2OUelZ4JGwDdztttjl7eEY8A3oGpfUQ" ,
    "LXXVOwndnXvkQNPoSfwDNanZdSoya1oVfYRK6UMXkRvM" ,
    "qvwaBFyaB0Zw8-rUIro_ePvPNBiFX8mx3O3T7W6runQ"
  ] ,
  "ecdsa_sig": "MEUCIBPQBwtrLM9hpDBXe5e2mS4jC3wBpAdCC_zZPeIfWFbhAiEAxVVQ0OiIOPTuqUt70deL93gARLYYfHjN3LR0TPu-UCc"
}
```
### Java Keystore

A Java Keystore was used to simplify the signing process for GUI-Users. 
It lets the User assign aliases for their Key-Certificate-Pairs and use them easily, while allowing password protection.
This Database is saved to the disk for permanence.