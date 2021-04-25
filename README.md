# Memory-hardened PoW

This repository contains Rust implementation of two memory-hard PoWs.  
- \scrypt is based on the scrypt key-derivation algorithm, first described by Colin Percival in https://www.tarsnap.com/scrypt/scrypt.pdf.  
- \itsuku is a memory-asymetric PoW based on Alex Biryukov and Dmitry Khovratovich's MTP-Argon2 scheme. It was designed by Fabien Coelho, Arnaud Larroche and Baptiste Colin in https://hal-mines-paristech.archives-ouvertes.fr/hal-01653168.  
  
To run the programs, just run the .exe (Windows) or executable file (Linux) in target/release/. A string will be prompted to the user in order to start the PoW.
