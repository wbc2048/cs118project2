// debug_utils.h
#pragma once

#include "consts.h"
#include <stdint.h>
#include <stdbool.h>
#include <openssl/sha.h>

// Make assertion, if it's false, exit with given code after sending debug message
void assert(bool assertion, int exit_code, char* debug_message);

// Get printable string with first n bytes of a hash of the contents buf
char* get_hash_str(uint8_t* buf, size_t len, size_t desired_hash_len);

// Print a debug message with prefix followed by hash of a buffer
void print_hash(uint8_t* buf, size_t len, size_t hash_len, char* prefix);

// Check if two buffers are identical
bool compare_bytes(uint8_t* a, size_t size_a, uint8_t* b, size_t size_b);

// Given a tlv, return a string representing its type
char* get_tlv_type_string(tlv* x);

// Print a short hash of a tlv, useful for quickly identifying small differences
void print_tlv_hash(tlv* target, char* prefix);

// Print a formatted summary of a tlv message and all it's children
void print_tlv_summary(tlv* target, char* debug_message);