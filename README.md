# Golang Post-Quantum Cryptography Examples
This repository demonstrates the implementation of post-quantum cryptography (PQC) in Go, focusing on the new features introduced in Go 1.23 (August 2024).

## Overview
Go 1.23 introduced support for quantum-resistant cryptography, specifically the X25519Kyber768 hybrid algorithm for TLS key exchange. This repo provides practical examples and explanations on how to leverage these new capabilities in your Go applications.

## Key Features
* TLS Server Configuration: Examples of how to configure a TLS server to support post-quantum cryptography.
* Curve ID Extraction: Demonstrates how to identify the negotiated curve ID in a TLS connection.
* Cipher Suite Information: Shows how to retrieve and display the cipher suite used in a TLS connection.

## Getting Started
* Ensure you have Go 1.23 or later installed.
* Clone this repository:

```bash
git clone https://github.com/GilAddaCyberark/golang-pqc-examples.git
```

* Navigate to the examples and run them to see post-quantum cryptography in action.

## Examples Included
* HTTPS server with PQC support
* TLS configuration for quantum resistance
* Connection information extraction (curve ID, cipher suite)

# Why Post-Quantum Cryptography?
Quantum computers pose a significant threat to current cryptographic standards. Implementing PQC helps future-proof your applications against potential quantum attacks.

# Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

# License
This project is licensed under the MIT License. We hope these examples help you understand and implement post-quantum cryptography in your Go projects.
