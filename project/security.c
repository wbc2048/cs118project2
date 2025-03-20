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

// Forward declarations
static uint16_t create_client_hello(uint8_t* buf);
static int process_client_hello(uint8_t* buf, size_t length);
static uint16_t create_server_hello(uint8_t* buf);
static int process_server_hello(uint8_t* buf, size_t length);
static uint16_t create_finished(uint8_t* buf);
static int process_finished(uint8_t* buf, size_t length);
static uint16_t create_data_message(uint8_t* buf, const uint8_t* data, size_t data_size);
static int process_data_message(uint8_t* buf, size_t length, uint8_t* output_data, size_t* output_size);

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
    } else if (current_state == STATE_SERVER_HELLO_RECEIVED) {
        if (current_role == CLIENT) {
            // Client sends Finished message
            uint16_t len = create_finished(buf);
            current_state = STATE_FINISHED_SENT;
            return len;
        }
    } else if (current_state == STATE_SECURE) {
        // We're in secure communication mode, encrypt the data
        uint8_t plaintext[1024]; // Buffer for plaintext data
        ssize_t plaintext_len = input_io(plaintext, 943); // Maximum size to prevent block overflow
        
        if (plaintext_len <= 0) {
            return 0; // No data to send
        }
        
        // Encrypt and create data message
        return create_data_message(buf, plaintext, plaintext_len);
    }
    
    // If we reach here, something went wrong
    return 0;
}

void output_sec(uint8_t* buf, size_t length) {
    tlv* message = deserialize_tlv(buf, length);
    if (message == NULL) {
        // Not a valid TLV message, pass through to IO layer
        output_io(buf, length);
        free_tlv(message);
        return;
    }
    
    if (current_state == STATE_INIT && current_role == SERVER) {
        if (message->type == CLIENT_HELLO) {
            // Server receiving Client Hello
            if (process_client_hello(buf, length) == 0) {
                current_state = STATE_CLIENT_HELLO_RECEIVED;
            }
        } else {
            // Unexpected message
            exit(6);
        }
    } else if (current_state == STATE_CLIENT_HELLO_SENT && current_role == CLIENT) {
        if (message->type == SERVER_HELLO) {
            // Client receiving Server Hello
            if (process_server_hello(buf, length) == 0) {
                current_state = STATE_SERVER_HELLO_RECEIVED;
            }
        } else {
            // Unexpected message
            exit(6);
        }
    } else if (current_state == STATE_SERVER_HELLO_SENT && current_role == SERVER) {
        if (message->type == FINISHED) {
            // Server receiving Finished
            if (process_finished(buf, length) == 0) {
                current_state = STATE_FINISHED_RECEIVED;
                current_state = STATE_SECURE; // Ready for secure communication
            }
        } else {
            // Unexpected message
            exit(6);
        }
    } else if (current_state == STATE_FINISHED_SENT && current_role == CLIENT) {
        if (message->type == DATA) {
            // Client already sent Finished, process incoming data
            current_state = STATE_SECURE;
            // Fall through to process the data
        } else {
            // Unexpected message
            exit(6);
        }
    }
    
    // Process data messages in secure state
    if (current_state == STATE_SECURE && message->type == DATA) {
        uint8_t plaintext[1024];
        size_t plaintext_len = 0;
        
        if (process_data_message(buf, length, plaintext, &plaintext_len) == 0) {
            // Output decrypted data
            output_io(plaintext, plaintext_len);
        }
    }
    
    free_tlv(message);
}

// Add this to create_finished message function after process_server_hello
static uint16_t create_finished(uint8_t* buf) {
    // Create the Finished TLV container
    tlv* finished = create_tlv(FINISHED);
    
    // Calculate transcript (HMAC over client_hello + server_hello)
    uint8_t* transcript_data = (uint8_t*)malloc(client_hello_size + server_hello_size);
    if (transcript_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for transcript\n");
        free_tlv(finished);
        return 0;
    }
    
    // Concatenate client_hello and server_hello
    memcpy(transcript_data, client_hello_data, client_hello_size);
    memcpy(transcript_data + client_hello_size, server_hello_data, server_hello_size);
    
    // Create HMAC digest (transcript)
    tlv* transcript_tlv = create_tlv(TRANSCRIPT);
    uint8_t digest[MAC_SIZE];
    hmac(digest, transcript_data, client_hello_size + server_hello_size);
    add_val(transcript_tlv, digest, MAC_SIZE);
    add_tlv(finished, transcript_tlv);
    
    free(transcript_data);
    
    // Serialize the Finished TLV to the buffer
    uint16_t len = serialize_tlv(buf, finished);
    
    // Free the TLV objects
    free_tlv(finished);
    
    return len;
}

// Add this to process the Finished message
static int process_finished(uint8_t* buf, size_t length) {
    tlv* finished = deserialize_tlv(buf, length);
    if (finished == NULL || finished->type != FINISHED) {
        if (finished != NULL) {
            free_tlv(finished);
        }
        return -1;
    }
    
    // Extract transcript
    tlv* transcript_tlv = get_tlv(finished, TRANSCRIPT);
    if (transcript_tlv == NULL || transcript_tlv->length != MAC_SIZE) {
        free_tlv(finished);
        return -1;
    }
    
    // Calculate our own transcript for verification
    uint8_t* transcript_data = (uint8_t*)malloc(client_hello_size + server_hello_size);
    if (transcript_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for transcript verification\n");
        free_tlv(finished);
        return -1;
    }
    
    // Concatenate client_hello and server_hello
    memcpy(transcript_data, client_hello_data, client_hello_size);
    memcpy(transcript_data + client_hello_size, server_hello_data, server_hello_size);
    
    // Calculate HMAC digest
    uint8_t digest[MAC_SIZE];
    hmac(digest, transcript_data, client_hello_size + server_hello_size);
    
    free(transcript_data);
    
    // Compare received transcript with calculated one
    if (memcmp(transcript_tlv->val, digest, MAC_SIZE) != 0) {
        free_tlv(finished);
        exit(4); // Bad transcript
    }
    
    free_tlv(finished);
    return 0;
}

// Add this to encrypt and create data message
static uint16_t create_data_message(uint8_t* buf, const uint8_t* data, size_t data_size) {
    // Create the Data TLV container
    tlv* data_tlv = create_tlv(DATA);
    
    // Generate IV
    uint8_t iv_data[IV_SIZE];
    generate_nonce(iv_data, IV_SIZE);
    tlv* iv_tlv = create_tlv(IV);
    add_val(iv_tlv, iv_data, IV_SIZE);
    add_tlv(data_tlv, iv_tlv);
    
    // Encrypt the data
    // Calculate max ciphertext size (rounded to AES block size)
    size_t max_cipher_size = ((data_size / 16) + 1) * 16;
    uint8_t* cipher_data = (uint8_t*)malloc(max_cipher_size);
    if (cipher_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for ciphertext\n");
        free_tlv(data_tlv);
        return 0;
    }
    
    size_t cipher_size = encrypt_data(iv_data, cipher_data, data, data_size);
    
    // Add ciphertext
    tlv* cipher_tlv = create_tlv(CIPHERTEXT);
    add_val(cipher_tlv, cipher_data, cipher_size);
    add_tlv(data_tlv, cipher_tlv);
    
    free(cipher_data);
    
    // Serialize IV and ciphertext to calculate MAC
    uint8_t iv_buf[20]; // Buffer large enough for IV TLV
    uint16_t iv_serialized_len = serialize_tlv(iv_buf, iv_tlv);
    
    uint8_t cipher_buf[1024]; // Buffer for cipher TLV
    uint16_t cipher_serialized_len = serialize_tlv(cipher_buf, cipher_tlv);
    
    // Concatenate IV and ciphertext for MAC calculation
    uint8_t* mac_data = (uint8_t*)malloc(iv_serialized_len + cipher_serialized_len);
    if (mac_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for MAC data\n");
        free_tlv(data_tlv);
        return 0;
    }
    
    memcpy(mac_data, iv_buf, iv_serialized_len);
    memcpy(mac_data + iv_serialized_len, cipher_buf, cipher_serialized_len);
    
    // Calculate MAC
    uint8_t mac_digest[MAC_SIZE];
    hmac(mac_digest, mac_data, iv_serialized_len + cipher_serialized_len);
    
    free(mac_data);
    
    // Add MAC
    tlv* mac_tlv = create_tlv(MAC);
    add_val(mac_tlv, mac_digest, MAC_SIZE);
    add_tlv(data_tlv, mac_tlv);
    
    // Serialize the Data TLV to the buffer
    uint16_t len = serialize_tlv(buf, data_tlv);
    
    // Free the TLV objects
    free_tlv(data_tlv);
    
    return len;
}

// Add this to process data messages
static int process_data_message(uint8_t* buf, size_t length, uint8_t* output_data, size_t* output_size) {
    tlv* data_tlv = deserialize_tlv(buf, length);
    if (data_tlv == NULL || data_tlv->type != DATA) {
        if (data_tlv != NULL) {
            free_tlv(data_tlv);
        }
        return -1;
    }
    
    // Extract components
    tlv* iv_tlv = get_tlv(data_tlv, IV);
    tlv* cipher_tlv = get_tlv(data_tlv, CIPHERTEXT);
    tlv* mac_tlv = get_tlv(data_tlv, MAC);
    
    if (iv_tlv == NULL || cipher_tlv == NULL || mac_tlv == NULL ||
        iv_tlv->length != IV_SIZE || mac_tlv->length != MAC_SIZE) {
        free_tlv(data_tlv);
        return -1;
    }
    
    // Verify MAC first
    // Serialize IV and ciphertext to calculate MAC
    uint8_t iv_buf[20]; // Buffer large enough for IV TLV
    uint16_t iv_serialized_len = serialize_tlv(iv_buf, iv_tlv);
    
    uint8_t cipher_buf[1024]; // Buffer for cipher TLV
    uint16_t cipher_serialized_len = serialize_tlv(cipher_buf, cipher_tlv);
    
    // Concatenate IV and ciphertext for MAC verification
    uint8_t* mac_data = (uint8_t*)malloc(iv_serialized_len + cipher_serialized_len);
    if (mac_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for MAC verification\n");
        free_tlv(data_tlv);
        return -1;
    }
    
    memcpy(mac_data, iv_buf, iv_serialized_len);
    memcpy(mac_data + iv_serialized_len, cipher_buf, cipher_serialized_len);
    
    // Calculate MAC
    uint8_t mac_digest[MAC_SIZE];
    hmac(mac_digest, mac_data, iv_serialized_len + cipher_serialized_len);
    
    free(mac_data);
    
    // Compare received MAC with calculated one
    if (memcmp(mac_tlv->val, mac_digest, MAC_SIZE) != 0) {
        free_tlv(data_tlv);
        exit(5); // Bad MAC
    }
    
    // Decrypt the data
    *output_size = decrypt_cipher(output_data, cipher_tlv->val, cipher_tlv->length, iv_tlv->val);
    
    free_tlv(data_tlv);
    return 0;
}