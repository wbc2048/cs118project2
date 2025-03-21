#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STATE_INIT 0
#define STATE_CLIENT_HELLO_SENT 1
#define STATE_CLIENT_HELLO_RECEIVED 2
#define STATE_SERVER_HELLO_SENT 3
#define STATE_SERVER_HELLO_RECEIVED 4
#define STATE_FINISHED_SENT 5
#define STATE_FINISHED_RECEIVED 6
#define STATE_SECURE 7

static int current_role;
static int current_state = STATE_INIT;
static char* target_hostname = NULL;

static uint8_t* client_hello_data = NULL;
static uint16_t client_hello_size = 0;
static uint8_t* server_hello_data = NULL;
static uint16_t server_hello_size = 0;

static uint16_t create_client_hello(uint8_t* buf);
static int process_client_hello(uint8_t* buf, size_t length);
static uint16_t create_server_hello(uint8_t* buf);
static int process_server_hello(uint8_t* buf, size_t length);
static uint16_t create_finished(uint8_t* buf);
static int process_finished(uint8_t* buf, size_t length);
static uint16_t create_data_message(uint8_t* buf, const uint8_t* data, size_t data_size);
static int process_data_message(uint8_t* buf, size_t length, uint8_t* output_data, size_t* output_size);

static void store_handshake_data(uint8_t** storage, uint16_t* size, const uint8_t* data, uint16_t length) {
    if (*storage != NULL) {
        free(*storage);
    }
    *storage = (uint8_t*)malloc(length);
    if (*storage != NULL) {
        memcpy(*storage, data, length);
        *size = length;
    }
}

void init_sec(int type, char* host) {
    init_io();
    
    current_role = type;
    if (host != NULL) {
        target_hostname = strdup(host);
    }
    
    current_state = STATE_INIT;
    
    if (current_role == SERVER) {
        load_private_key("server_key.bin");
        load_certificate("server_cert.bin");
    } else {
        load_ca_public_key("ca_public_key.bin");
    }
}

static uint16_t create_client_hello(uint8_t* buf) {
    tlv* client_hello = create_tlv(CLIENT_HELLO);
    
    tlv* nonce_tlv = create_tlv(NONCE);
    uint8_t nonce_data[NONCE_SIZE];
    generate_nonce(nonce_data, NONCE_SIZE);
    add_val(nonce_tlv, nonce_data, NONCE_SIZE);
    add_tlv(client_hello, nonce_tlv);
    
    generate_private_key();
    derive_public_key();
    tlv* pubkey_tlv = create_tlv(PUBLIC_KEY);
    add_val(pubkey_tlv, public_key, pub_key_size);
    add_tlv(client_hello, pubkey_tlv);
    
    uint16_t len = serialize_tlv(buf, client_hello);
    
    store_handshake_data(&client_hello_data, &client_hello_size, buf, len);
    
    free_tlv(client_hello);
    
    return len;
}

static int process_client_hello(uint8_t* buf, size_t length) {
    tlv* client_hello = deserialize_tlv(buf, length);
    if (client_hello == NULL || client_hello->type != CLIENT_HELLO) {
        free_tlv(client_hello);
        return -1;
    }
    
    tlv* nonce_tlv = get_tlv(client_hello, NONCE);
    tlv* pubkey_tlv = get_tlv(client_hello, PUBLIC_KEY);
    
    if (nonce_tlv == NULL || nonce_tlv->length != NONCE_SIZE || pubkey_tlv == NULL) {
        free_tlv(client_hello);
        return -1;
    }
    
    load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);
    
    store_handshake_data(&client_hello_data, &client_hello_size, buf, length);
    
    free_tlv(client_hello);
    return 0;
}

static uint16_t create_server_hello(uint8_t* buf) {
    EVP_PKEY* original_key = get_private_key();
    
    tlv* server_hello = create_tlv(SERVER_HELLO);
    
    tlv* nonce_tlv = create_tlv(NONCE);
    uint8_t nonce_data[NONCE_SIZE];
    generate_nonce(nonce_data, NONCE_SIZE);
    add_val(nonce_tlv, nonce_data, NONCE_SIZE);
    add_tlv(server_hello, nonce_tlv);
    
    tlv* cert_tlv = deserialize_tlv(certificate, cert_size);
    if (cert_tlv == NULL) {
        free_tlv(server_hello);
        return 0;
    }
    add_tlv(server_hello, cert_tlv);
    
    generate_private_key();
    derive_public_key();
    tlv* pubkey_tlv = create_tlv(PUBLIC_KEY);
    add_val(pubkey_tlv, public_key, pub_key_size);
    add_tlv(server_hello, pubkey_tlv);
    
    uint8_t sig_data[2000] = {0};
    uint16_t offset = 0;
    
    memcpy(sig_data + offset, client_hello_data, client_hello_size);
    offset += client_hello_size;
    
    offset += serialize_tlv(sig_data + offset, nonce_tlv);
    offset += serialize_tlv(sig_data + offset, cert_tlv);
    offset += serialize_tlv(sig_data + offset, pubkey_tlv);
    
    load_private_key("server_key.bin");
    
    tlv* sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
    uint8_t signature[72];
    size_t sig_size = sign(signature, sig_data, offset);
    add_val(sig_tlv, signature, sig_size);
    add_tlv(server_hello, sig_tlv);
    
    uint16_t len = serialize_tlv(buf, server_hello);
    
    store_handshake_data(&server_hello_data, &server_hello_size, buf, len);
    
    free_tlv(server_hello);
    
    set_private_key(original_key);
    
    derive_secret();
    
    uint8_t* salt = (uint8_t*)malloc(client_hello_size + server_hello_size);
    if (salt != NULL) {
        memcpy(salt, client_hello_data, client_hello_size);
        memcpy(salt + client_hello_size, server_hello_data, server_hello_size);
        
        derive_keys(salt, client_hello_size + server_hello_size);
        free(salt);
    }

    return len;
}

static int process_server_hello(uint8_t* buf, size_t length) {
    tlv* server_hello = deserialize_tlv(buf, length);
    if (server_hello == NULL || server_hello->type != SERVER_HELLO) {
        free_tlv(server_hello);
        return -1;
    }
    
    tlv* nonce_tlv = get_tlv(server_hello, NONCE);
    tlv* cert_tlv = get_tlv(server_hello, CERTIFICATE);
    tlv* pubkey_tlv = get_tlv(server_hello, PUBLIC_KEY);
    tlv* sig_tlv = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
    
    if (nonce_tlv == NULL || cert_tlv == NULL || 
        pubkey_tlv == NULL || sig_tlv == NULL) {
        free_tlv(server_hello);
        return -1;
    }
    
    tlv* dns_tlv = get_tlv(cert_tlv, DNS_NAME);
    tlv* cert_pubkey_tlv = get_tlv(cert_tlv, PUBLIC_KEY);
    tlv* cert_sig_tlv = get_tlv(cert_tlv, SIGNATURE);
    
    if (dns_tlv == NULL || cert_pubkey_tlv == NULL || cert_sig_tlv == NULL) {
        free_tlv(server_hello);
        return -1;
    }
    
    uint8_t cert_data[2000] = {0};
    uint16_t offset = 0;
    
    offset += serialize_tlv(cert_data + offset, dns_tlv);
    offset += serialize_tlv(cert_data + offset, cert_pubkey_tlv);
    
    if (!verify(cert_sig_tlv->val, cert_sig_tlv->length, 
                cert_data, offset, ec_ca_public_key)) {
        free_tlv(server_hello);
        exit(1);
    }
    
    char* cert_hostname = (char*)malloc(dns_tlv->length + 1);
    if (cert_hostname == NULL) {
        free_tlv(server_hello);
        return -1;
    }
    
    memcpy(cert_hostname, dns_tlv->val, dns_tlv->length);
    cert_hostname[dns_tlv->length] = '\0';
    
    if (strcmp(cert_hostname, target_hostname) != 0) {
        free(cert_hostname);
        free_tlv(server_hello);
        exit(2);
    }
    
    free(cert_hostname);
    
    load_peer_public_key(cert_pubkey_tlv->val, cert_pubkey_tlv->length);
    
    uint8_t sig_data[2000] = {0};
    offset = 0;
    
    memcpy(sig_data + offset, client_hello_data, client_hello_size);
    offset += client_hello_size;
    
    offset += serialize_tlv(sig_data + offset, nonce_tlv);
    offset += serialize_tlv(sig_data + offset, cert_tlv);
    offset += serialize_tlv(sig_data + offset, pubkey_tlv);
    
    if (!verify(sig_tlv->val, sig_tlv->length, 
                sig_data, offset, ec_peer_public_key)) {
        free_tlv(server_hello);
        exit(3);
    }
    
    store_handshake_data(&server_hello_data, &server_hello_size, buf, length);
    
    load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);
    
    derive_secret();
    
    uint8_t* salt = (uint8_t*)malloc(client_hello_size + server_hello_size);
    if (salt == NULL) {
        free_tlv(server_hello);
        return -1;
    }
    
    memcpy(salt, client_hello_data, client_hello_size);
    memcpy(salt + client_hello_size, server_hello_data, server_hello_size);
    
    derive_keys(salt, client_hello_size + server_hello_size);
    
    free(salt);
    free_tlv(server_hello);
    
    return 0;
}

static uint16_t create_finished(uint8_t* buf) {
    tlv* finished = create_tlv(FINISHED);
    
    uint8_t* transcript_data = (uint8_t*)malloc(client_hello_size + server_hello_size);
    if (transcript_data == NULL) {
        free_tlv(finished);
        return 0;
    }
    
    memcpy(transcript_data, client_hello_data, client_hello_size);
    memcpy(transcript_data + client_hello_size, server_hello_data, server_hello_size);
    
    tlv* transcript_tlv = create_tlv(TRANSCRIPT);
    uint8_t digest[MAC_SIZE];
    hmac(digest, transcript_data, client_hello_size + server_hello_size);
    add_val(transcript_tlv, digest, MAC_SIZE);
    add_tlv(finished, transcript_tlv);
    
    free(transcript_data);
    
    uint16_t len = serialize_tlv(buf, finished);
    
    free_tlv(finished);
    
    return len;
}

static int process_finished(uint8_t* buf, size_t length) {
    tlv* finished = deserialize_tlv(buf, length);
    if (finished == NULL || finished->type != FINISHED) {
        free_tlv(finished);
        return -1;
    }
    
    tlv* transcript_tlv = get_tlv(finished, TRANSCRIPT);
    if (transcript_tlv == NULL || transcript_tlv->length != MAC_SIZE) {
        free_tlv(finished);
        return -1;
    }
    
    uint8_t* transcript_data = (uint8_t*)malloc(client_hello_size + server_hello_size);
    if (transcript_data == NULL) {
        free_tlv(finished);
        return -1;
    }
    
    memcpy(transcript_data, client_hello_data, client_hello_size);
    memcpy(transcript_data + client_hello_size, server_hello_data, server_hello_size);
    
    uint8_t digest[MAC_SIZE];
    hmac(digest, transcript_data, client_hello_size + server_hello_size);
    
    free(transcript_data);
    
    if (memcmp(transcript_tlv->val, digest, MAC_SIZE) != 0) {
        free_tlv(finished);
        exit(4);
    }
    
    free_tlv(finished);
    return 0;
}

static uint16_t create_data_message(uint8_t* buf, const uint8_t* data, size_t data_size) {
    tlv* data_tlv = create_tlv(DATA);
    
    tlv* iv_tlv = create_tlv(IV);
    uint8_t iv_data[IV_SIZE];
    
    size_t max_cipher_size = ((data_size / 16) + 1) * 16;
    uint8_t* cipher_data = (uint8_t*)malloc(max_cipher_size);
    if (cipher_data == NULL) {
        free_tlv(data_tlv);
        free_tlv(iv_tlv);
        return 0;
    }
    
    size_t cipher_size = encrypt_data(iv_data, cipher_data, data, data_size);
    
    add_val(iv_tlv, iv_data, IV_SIZE);
    add_tlv(data_tlv, iv_tlv);
    
    tlv* cipher_tlv = create_tlv(CIPHERTEXT);
    add_val(cipher_tlv, cipher_data, cipher_size);
    add_tlv(data_tlv, cipher_tlv);
    
    free(cipher_data);
    
    uint8_t iv_buf[100];
    uint16_t iv_len = serialize_tlv(iv_buf, iv_tlv);
    
    uint8_t cipher_buf[2000];
    uint16_t cipher_len = serialize_tlv(cipher_buf, cipher_tlv);
    
    uint8_t* mac_data = (uint8_t*)malloc(iv_len + cipher_len);
    if (mac_data == NULL) {
        free_tlv(data_tlv);
        return 0;
    }
    
    memcpy(mac_data, iv_buf, iv_len);
    memcpy(mac_data + iv_len, cipher_buf, cipher_len);
    
    uint8_t mac_digest[MAC_SIZE];
    hmac(mac_digest, mac_data, iv_len + cipher_len);
    
    free(mac_data);
    
    tlv* mac_tlv = create_tlv(MAC);
    add_val(mac_tlv, mac_digest, MAC_SIZE);
    add_tlv(data_tlv, mac_tlv);
    
    uint16_t len = serialize_tlv(buf, data_tlv);
    
    free_tlv(data_tlv);
    
    return len;
}

static int process_data_message(uint8_t* buf, size_t length, uint8_t* output_data, size_t* output_size) {
    tlv* data_tlv = deserialize_tlv(buf, length);
    if (data_tlv == NULL || data_tlv->type != DATA) {
        free_tlv(data_tlv);
        return -1;
    }
    
    tlv* iv_tlv = get_tlv(data_tlv, IV);
    tlv* cipher_tlv = get_tlv(data_tlv, CIPHERTEXT);
    tlv* mac_tlv = get_tlv(data_tlv, MAC);
    
    if (iv_tlv == NULL || cipher_tlv == NULL || mac_tlv == NULL ||
        iv_tlv->length != IV_SIZE || mac_tlv->length != MAC_SIZE) {
        free_tlv(data_tlv);
        return -1;
    }
    
    uint8_t iv_buf[100];
    uint16_t iv_len = serialize_tlv(iv_buf, iv_tlv);
    
    uint8_t cipher_buf[2000];
    uint16_t cipher_len = serialize_tlv(cipher_buf, cipher_tlv);
    
    uint8_t* mac_data = (uint8_t*)malloc(iv_len + cipher_len);
    if (mac_data == NULL) {
        free_tlv(data_tlv);
        return -1;
    }
    
    memcpy(mac_data, iv_buf, iv_len);
    memcpy(mac_data + iv_len, cipher_buf, cipher_len);
    
    uint8_t mac_digest[MAC_SIZE];
    hmac(mac_digest, mac_data, iv_len + cipher_len);
    
    free(mac_data);
    
    if (memcmp(mac_tlv->val, mac_digest, MAC_SIZE) != 0) {
        free_tlv(data_tlv);
        exit(5);
    }
    
    *output_size = decrypt_cipher(output_data, cipher_tlv->val, cipher_tlv->length, iv_tlv->val);
    
    free_tlv(data_tlv);
    return 0;
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if (current_state == STATE_INIT) {
        if (current_role == CLIENT) {
            uint16_t len = create_client_hello(buf);
            if (len > 0) {
                current_state = STATE_CLIENT_HELLO_SENT;
                return len;
            }
        }
    } else if (current_state == STATE_CLIENT_HELLO_RECEIVED) {
        if (current_role == SERVER) {
            uint16_t len = create_server_hello(buf);
            if (len > 0) {
                current_state = STATE_SERVER_HELLO_SENT;
                return len;
            }
        }
    } else if (current_state == STATE_SERVER_HELLO_RECEIVED) {
        if (current_role == CLIENT) {
            uint16_t len = create_finished(buf);
            if (len > 0) {
                current_state = STATE_FINISHED_SENT;
                return len;
            }
        }
    } else if (current_state == STATE_SECURE) {
        uint8_t plaintext[943];
        ssize_t plaintext_len = input_io(plaintext, sizeof(plaintext));
        
        if (plaintext_len <= 0) {
            return 0;
        }
        
        return create_data_message(buf, plaintext, plaintext_len);
    }
    
    return 0;
}

void output_sec(uint8_t* buf, size_t length) {
    if (length == 0) {
        return;
    }
    
    tlv* message = deserialize_tlv(buf, length);
    if (message == NULL) {
        return;
    }
    
    if (current_state == STATE_INIT && current_role == SERVER) {
        if (message->type == CLIENT_HELLO) {
            if (process_client_hello(buf, length) == 0) {
                current_state = STATE_CLIENT_HELLO_RECEIVED;
            }
        } else {
            free_tlv(message);
            exit(6);
        }
    } else if (current_state == STATE_CLIENT_HELLO_SENT && current_role == CLIENT) {
        if (message->type == SERVER_HELLO) {
            if (process_server_hello(buf, length) == 0) {
                current_state = STATE_SERVER_HELLO_RECEIVED;
            }
        } else {
            free_tlv(message);
            exit(6);
        }
    } else if (current_state == STATE_SERVER_HELLO_SENT && current_role == SERVER) {
        if (message->type == FINISHED) {
            if (process_finished(buf, length) == 0) {
                current_state = STATE_SECURE;
            }
        } else {
            free_tlv(message);
            exit(6);
        }
    } else if ((current_state == STATE_FINISHED_SENT || current_state == STATE_SECURE) && message->type == DATA) {
        current_state = STATE_SECURE;
        
        uint8_t plaintext[2000];
        size_t plaintext_len = 0;
        
        if (process_data_message(buf, length, plaintext, &plaintext_len) == 0 && plaintext_len > 0) {
            output_io(plaintext, plaintext_len);
        }
    } else if (current_state == STATE_SECURE && message->type != DATA) {
        free_tlv(message);
        exit(6);
    }
    
    free_tlv(message);
}