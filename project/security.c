#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// State definitions for our security protocol
#define STATE_INIT 0
#define STATE_CLIENT_HELLO_SENT 1
#define STATE_CLIENT_HELLO_RECEIVED 2
#define STATE_SERVER_HELLO_SENT 3
#define STATE_SERVER_HELLO_RECEIVED 4
#define STATE_FINISHED_SENT 5
#define STATE_FINISHED_RECEIVED 6
#define STATE_SECURE 7

// Global variables
static int current_role; // SERVER or CLIENT
static int current_state = STATE_INIT;
static char* target_hostname = NULL;

// Handshake data storage
static uint8_t* client_hello_data = NULL;
static uint16_t client_hello_size = 0;
static uint8_t* server_hello_data = NULL;
static uint16_t server_hello_size = 0;

// Creates a Client Hello message and serializes it to the buffer
static uint16_t create_client_hello(uint8_t* buf) {
    // Create the Client Hello TLV container
    tlv* client_hello = create_tlv(CLIENT_HELLO);
    
    // Generate and add a nonce
    tlv* nonce_tlv = create_tlv(NONCE);
    uint8_t nonce_data[NONCE_SIZE];
    generate_nonce(nonce_data, NONCE_SIZE);
    add_val(nonce_tlv, nonce_data, NONCE_SIZE);
    add_tlv(client_hello, nonce_tlv);
    
    // Generate a key pair and add the public key
    generate_private_key();
    derive_public_key();
    tlv* pubkey_tlv = create_tlv(PUBLIC_KEY);
    add_val(pubkey_tlv, public_key, pub_key_size);
    add_tlv(client_hello, pubkey_tlv);
    
    // Serialize the Client Hello TLV to the buffer
    uint16_t len = serialize_tlv(buf, client_hello);
    
    // Store a copy of the Client Hello for later use in key derivation
    client_hello_data = (uint8_t*)malloc(len);
    if (client_hello_data != NULL) {
        memcpy(client_hello_data, buf, len);
        client_hello_size = len;
    }
    
    // Free the TLV objects
    free_tlv(client_hello);
    
    return len;
}

// Process a received Client Hello message
static int process_client_hello(uint8_t* buf, size_t length) {
    tlv* client_hello = deserialize_tlv(buf, length);
    if (client_hello == NULL || client_hello->type != CLIENT_HELLO) {
        if (client_hello != NULL) {
            free_tlv(client_hello);
        }
        return -1;
    }
    
    // Verify the Client Hello has a nonce
    tlv* nonce_tlv = get_tlv(client_hello, NONCE);
    if (nonce_tlv == NULL || nonce_tlv->length != NONCE_SIZE) {
        free_tlv(client_hello);
        return -1;
    }
    
    // Verify the Client Hello has a public key
    tlv* pubkey_tlv = get_tlv(client_hello, PUBLIC_KEY);
    if (pubkey_tlv == NULL) {
        free_tlv(client_hello);
        return -1;
    }
    
    // Load the client's public key
    load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);
    
    // Store a copy of the Client Hello for later use
    client_hello_data = (uint8_t*)malloc(length);
    if (client_hello_data != NULL) {
        memcpy(client_hello_data, buf, length);
        client_hello_size = length;
    }
    
    free_tlv(client_hello);
    return 0;
}

// Creates a Server Hello message and serializes it to the buffer
static uint16_t create_server_hello(uint8_t* buf) {
    // Save the server's original private key
    EVP_PKEY* original_key = get_private_key();
    
    // Create the Server Hello TLV container
    tlv* server_hello = create_tlv(SERVER_HELLO);
    
    // Generate and add a nonce
    tlv* nonce_tlv = create_tlv(NONCE);
    uint8_t nonce_data[NONCE_SIZE];
    generate_nonce(nonce_data, NONCE_SIZE);
    add_val(nonce_tlv, nonce_data, NONCE_SIZE);
    add_tlv(server_hello, nonce_tlv);
    
    // Add the server's certificate
    // The certificate is already in TLV format, but we need to deserialize and add it
    tlv* cert_tlv = deserialize_tlv(certificate, cert_size);
    if (cert_tlv != NULL) {
        add_tlv(server_hello, cert_tlv);
    } else {
        // Handle error - certificate couldn't be deserialized
        fprintf(stderr, "Failed to deserialize certificate\n");
        free_tlv(server_hello);
        return 0;
    }
    
    // Generate an ephemeral key pair for this session
    generate_private_key();
    derive_public_key();
    
    // Add the ephemeral public key
    tlv* pubkey_tlv = create_tlv(PUBLIC_KEY);
    add_val(pubkey_tlv, public_key, pub_key_size);
    add_tlv(server_hello, pubkey_tlv);
    
    // Create the signature data: client_hello + nonce + certificate + pubkey
    // First serialize the components to find the total length
    uint8_t nonce_buf[100]; // Buffer large enough for nonce TLV
    uint16_t nonce_serialized_len = serialize_tlv(nonce_buf, nonce_tlv);
    
    uint8_t pubkey_buf[200]; // Buffer large enough for pubkey TLV
    uint16_t pubkey_serialized_len = serialize_tlv(pubkey_buf, pubkey_tlv);
    
    uint16_t signature_data_size = client_hello_size + 
                                  nonce_serialized_len +
                                  cert_size + 
                                  pubkey_serialized_len;
    
    uint8_t* signature_data = (uint8_t*)malloc(signature_data_size);
    if (signature_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for signature data\n");
        free_tlv(server_hello);
        return 0;
    }
    
    uint8_t* ptr = signature_data;
    
    // Copy client hello
    memcpy(ptr, client_hello_data, client_hello_size);
    ptr += client_hello_size;
    
    // Copy serialized nonce TLV
    memcpy(ptr, nonce_buf, nonce_serialized_len);
    ptr += nonce_serialized_len;
    
    // Copy certificate
    memcpy(ptr, certificate, cert_size);
    ptr += cert_size;
    
    // Copy serialized pubkey TLV
    memcpy(ptr, pubkey_buf, pubkey_serialized_len);
    ptr += pubkey_serialized_len;
    
    // Switch back to the server's original private key for signature
    set_private_key(original_key);
    
    // Sign the data
    tlv* sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
    uint8_t signature[72]; // Max ECDSA signature size
    size_t sig_size = sign(signature, signature_data, signature_data_size);
    add_val(sig_tlv, signature, sig_size);
    add_tlv(server_hello, sig_tlv);
    
    free(signature_data);
    
    // Serialize the Server Hello TLV to the buffer
    uint16_t len = serialize_tlv(buf, server_hello);
    
    // Store a copy of the Server Hello for later use
    if (server_hello_data != NULL) {
        free(server_hello_data);
    }
    server_hello_data = (uint8_t*)malloc(len);
    if (server_hello_data != NULL) {
        memcpy(server_hello_data, buf, len);
        server_hello_size = len;
    }
    
    // Free the TLV objects
    free_tlv(server_hello);
    
    // Switch back to the ephemeral key for key derivation
    EVP_PKEY* ephemeral_key = get_private_key();
    set_private_key(ephemeral_key);
    
    // Derive the shared secret
    derive_secret();
    
    // Create salt for key derivation: client_hello + server_hello
    uint8_t* salt = (uint8_t*)malloc(client_hello_size + server_hello_size);
    if (salt != NULL) {
        memcpy(salt, client_hello_data, client_hello_size);
        memcpy(salt + client_hello_size, server_hello_data, server_hello_size);
        
        // Derive the encryption and MAC keys
        derive_keys(salt, client_hello_size + server_hello_size);
        free(salt);
    }
    
    return len;
}

// Process a received Server Hello message
static int process_server_hello(uint8_t* buf, size_t length) {
    tlv* server_hello = deserialize_tlv(buf, length);
    if (server_hello == NULL || server_hello->type != SERVER_HELLO) {
        if (server_hello != NULL) {
            free_tlv(server_hello);
        }
        return -1;
    }
    
    // Extract components
    tlv* nonce_tlv = get_tlv(server_hello, NONCE);
    tlv* cert_tlv = get_tlv(server_hello, CERTIFICATE);
    tlv* pubkey_tlv = get_tlv(server_hello, PUBLIC_KEY);
    tlv* sig_tlv = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
    
    if (nonce_tlv == NULL || cert_tlv == NULL || 
        pubkey_tlv == NULL || sig_tlv == NULL) {
        free_tlv(server_hello);
        return -1;
    }
    
    // Verify the certificate
    tlv* dns_tlv = get_tlv(cert_tlv, DNS_NAME);
    tlv* cert_pubkey_tlv = get_tlv(cert_tlv, PUBLIC_KEY);
    tlv* cert_sig_tlv = get_tlv(cert_tlv, SIGNATURE);
    
    if (dns_tlv == NULL || cert_pubkey_tlv == NULL || cert_sig_tlv == NULL) {
        free_tlv(server_hello);
        return -1;
    }
    
    // 1. Verify certificate is signed by CA
    uint8_t* cert_data = (uint8_t*)malloc(dns_tlv->length + 2 + cert_pubkey_tlv->length + 2);
    uint8_t* ptr = cert_data;
    
    // Serialize DNS name and public key
    uint16_t dns_len = serialize_tlv(ptr, dns_tlv);
    ptr += dns_len;
    
    uint16_t cert_pubkey_len = serialize_tlv(ptr, cert_pubkey_tlv);
    ptr += cert_pubkey_len;
    
    // Verify with CA's public key
    if (!verify(cert_sig_tlv->val, cert_sig_tlv->length, 
                cert_data, ptr - cert_data, ec_ca_public_key)) {
        free(cert_data);
        free_tlv(server_hello);
        exit(1); // Bad certificate
    }
    
    free(cert_data);
    
    // 2. Verify DNS name matches expected hostname
    char* cert_hostname = (char*)malloc(dns_tlv->length + 1);
    memcpy(cert_hostname, dns_tlv->val, dns_tlv->length);
    cert_hostname[dns_tlv->length] = '\0';
    
    if (strcmp(cert_hostname, target_hostname) != 0) {
        free(cert_hostname);
        free_tlv(server_hello);
        exit(2); // Bad DNS name
    }
    
    free(cert_hostname);
    
    // 3. Load server's public key from certificate
    load_peer_public_key(cert_pubkey_tlv->val, cert_pubkey_tlv->length);
    
    // 4. Verify server hello signature
    uint16_t sig_data_size = client_hello_size + 
                              nonce_tlv->length + 2 +
                              cert_tlv->length + 2 +
                              pubkey_tlv->length + 2;
    
    uint8_t* sig_data = (uint8_t*)malloc(sig_data_size);
    ptr = sig_data;
    
    // Copy client hello
    memcpy(ptr, client_hello_data, client_hello_size);
    ptr += client_hello_size;
    
    // Serialize nonce, certificate, and public key
    uint16_t nonce_len = serialize_tlv(ptr, nonce_tlv);
    ptr += nonce_len;
    
    uint16_t cert_len = serialize_tlv(ptr, cert_tlv);
    ptr += cert_len;
    
    uint16_t pubkey_len = serialize_tlv(ptr, pubkey_tlv);
    ptr += pubkey_len;
    
    // Verify with server's public key from certificate
    if (!verify(sig_tlv->val, sig_tlv->length, 
                sig_data, ptr - sig_data, ec_peer_public_key)) {
        free(sig_data);
        free_tlv(server_hello);
        exit(3); // Bad signature
    }
    
    free(sig_data);
    
    // 5. Store the Server Hello for later use
    server_hello_data = (uint8_t*)malloc(length);
    if (server_hello_data != NULL) {
        memcpy(server_hello_data, buf, length);
        server_hello_size = length;
    }
    
    // 6. Load the server's ephemeral public key for Diffie-Hellman
    load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);
    
    // 7. Derive the shared secret
    derive_secret();
    
    // 8. Create salt for key derivation: client_hello + server_hello
    uint8_t* salt = (uint8_t*)malloc(client_hello_size + server_hello_size);
    memcpy(salt, client_hello_data, client_hello_size);
    memcpy(salt + client_hello_size, server_hello_data, server_hello_size);
    
    // 9. Derive the encryption and MAC keys
    derive_keys(salt, client_hello_size + server_hello_size);
    
    free(salt);
    free_tlv(server_hello);
    
    return 0;
}

void init_sec(int type, char* host) {
    init_io();
    
    // Store role and hostname
    current_role = type;
    if (host != NULL) {
        target_hostname = strdup(host);
    }
    
    // Initialize state
    current_state = STATE_INIT;
    
    // Initialize security components based on role
    if (current_role == SERVER) {
        // Server needs its private key and certificate
        load_private_key("server_key.bin");
        load_certificate("server_cert.bin");
    } else {
        // Client needs the CA public key for verification
        load_ca_public_key("ca_public_key.bin");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if (current_state == STATE_INIT) {
        if (current_role == CLIENT) {
            // Client initiates handshake with Client Hello
            uint16_t len = create_client_hello(buf);
            current_state = STATE_CLIENT_HELLO_SENT;
            return len;
        }
    } else if (current_state == STATE_CLIENT_HELLO_RECEIVED) {
        if (current_role == SERVER) {
            // Server responds with Server Hello
            uint16_t len = create_server_hello(buf);
            current_state = STATE_SERVER_HELLO_SENT;
            return len;
        }
    }
    
    // For now, just pass through to IO layer for other states
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    tlv* message = deserialize_tlv(buf, length);
    if (message == NULL) {
        // Not a valid TLV message, pass through to IO layer
        output_io(buf, length);
        return;
    }
    
    if (current_state == STATE_INIT && current_role == SERVER) {
        if (message->type == CLIENT_HELLO) {
            // Server receiving Client Hello
            if (process_client_hello(buf, length) == 0) {
                current_state = STATE_CLIENT_HELLO_RECEIVED;
                free_tlv(message);
                return;
            }
        } else {
            // Unexpected message
            free_tlv(message);
            exit(6);
            return;
        }
    } else if (current_state == STATE_CLIENT_HELLO_SENT && current_role == CLIENT) {
        if (message->type == SERVER_HELLO) {
            // Client receiving Server Hello
            if (process_server_hello(buf, length) == 0) {
                current_state = STATE_SERVER_HELLO_RECEIVED;
                free_tlv(message);
                return;
            }
        } else {
            // Unexpected message
            free_tlv(message);
            exit(6);
            return;
        }
    }
    
    free_tlv(message);
    // For now, just pass through to IO layer for other states
    output_io(buf, length);
}