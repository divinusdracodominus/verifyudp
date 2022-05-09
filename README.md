# verifyUDP

## Goal
The primary aim of this project is to implement 
an initial TCP handshake in order to verify publickey 
identity, then use aes encryption to encrypt and verify
UDP packets send over the network.

## Implemented
1. TCP handshake
2. UDP aes encryption

## Planned Features
3. Packet Ordering (somewhat)

## Current Focus
This project is a refactor of the networking crate 
(poorly named) that I originally wrote 
as a means of rapidly sending encrypted UDP packets 
over the network, I had also had hopes to sned at layer 
two in the same fashion, this this crate already defragments 
to a decent degree (if I recall correctly), 
though layeer 2 is mostly for the moment a thought experiment, 
though may be important for PSAS (Portland State University Aerospace Society) project.


