# Memory-hardened PoW

This repository contains Rust implementation of two memory-hard PoWs.  
- \scrypt is based on the scrypt key-derivation algorithm, first described by Colin Percival in https://www.tarsnap.com/scrypt/scrypt.pdf.  
- \itsuku is a memory-asymetric PoW scheme based on the MTP-Argon2 of Alex Biryukov and Dmitry Khovratovich. It originates from Coelho et al.'s paper, https://hal-mines-paristech.archives-ouvertes.fr/hal-01653168.  
  
To run one of the programs, just run the .exe (Windows) or executable file (Linux) in target/release/. A string will be prompted to user in order to run the PoW.
