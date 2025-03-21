# Project 2: Security

## Design Choices

### Language
I used C instead of C++ because we did not really need the C++ STL containers.

### State Machine Architecture
I implemented a state machine to manage the progress of the TLS-like handshake protocol. The states include INIT, CLIENT_HELLO_SENT/RECEIVED, SERVER_HELLO_SENT/RECEIVED, FINISHED_SENT/RECEIVED, and SECURE.

### TLV Message Encapsulation
All messages are encapsulated using Type-Length-Value encoding as specified, which provides a flexible way to structure and nest message components.

### Security Verification
The client performs three critical verifications:
- Certificate verification
- DNS name verification
- Server signature verification

## Challenges and Solutions

### Sending encrypted data
During development, I encountered errors regarding the differences in encrypted data sending. The majority of the data is correct but there are small error differences (3.2% difference). I fixed this by properly letting encrypt_data generate the IV and calculating MAC over the serialized TLV representations rather than raw values, ensuring consistent encryption and authentication that matched the protocol specification.


### Unrecognized server hello
I faced issues with the server hello message not being recognized correctly by the autograder. After implementing utility functions and debugging, I discovered a critical key management problem in my implementation. The problem was failing to restore the ephemeral key after signing with the server's long-term key. I fixed it by properly saving and restoring keys at the right points in the process.
