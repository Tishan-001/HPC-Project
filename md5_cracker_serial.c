#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>

#define MAX_PASSWORD_LENGTH 8
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_SIZE 62

// Function to convert MD5 hash to hex string
void md5_to_hex(unsigned char *hash, char *hex_string) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[32] = '\0';
}

// Function to compute MD5 hash of a string
void compute_md5(const char *input, char *output) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5_ctx;
    
    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, input, strlen(input));
    MD5_Final(hash, &md5_ctx);
    
    md5_to_hex(hash, output);
}

// Function to generate next password in sequence
int generate_next_password(char *password, int length) {
    int i = length - 1;
    
    while (i >= 0) {
        int current_index = strchr(CHARSET, password[i]) - CHARSET;
        
        if (current_index < CHARSET_SIZE - 1) {
            password[i] = CHARSET[current_index + 1];
            return 1; // Successfully generated next password
        } else {
            password[i] = CHARSET[0]; // Reset to first character
            i--;
        }
    }
    
    return 0; // All combinations exhausted for this length
}

// Function to initialize password with first combination
void initialize_password(char *password, int length) {
    for (int i = 0; i < length; i++) {
        password[i] = CHARSET[0];
    }
    password[length] = '\0';
}

// Function to calculate total combinations for given length
long long calculate_combinations(int length) {
    long long total = 1;
    for (int i = 0; i < length; i++) {
        total *= CHARSET_SIZE;
    }
    return total;
}

// Brute force MD5 cracker
int crack_md5_brute_force(const char *target_hash, char *cracked_password) {
    char current_password[MAX_PASSWORD_LENGTH + 1];
    char computed_hash[33];
    long long attempts = 0;
    
    printf("Starting brute-force attack on hash: %s\n", target_hash);
    printf("Character set: %s\n", CHARSET);
    printf("Character set size: %d\n", CHARSET_SIZE);
    
    // Try different password lengths
    for (int length = 1; length <= MAX_PASSWORD_LENGTH; length++) {
        printf("\nTrying passwords of length %d...\n", length);
        
        long long combinations = calculate_combinations(length);
        printf("Total combinations for length %d: %lld\n", length, combinations);
        
        initialize_password(current_password, length);
        
        do {
            attempts++;
            
            // Compute MD5 hash of current password
            compute_md5(current_password, computed_hash);
            
            // Progress indicator (every 100000 attempts)
            if (attempts % 100000 == 0) {
                printf("Attempts: %lld, Current: %s\n", attempts, current_password);
            }
            
            // Check if hash matches
            if (strcmp(computed_hash, target_hash) == 0) {
                strcpy(cracked_password, current_password);
                printf("\n*** PASSWORD FOUND! ***\n");
                printf("Password: %s\n", current_password);
                printf("Total attempts: %lld\n", attempts);
                return 1; // Success
            }
            
        } while (generate_next_password(current_password, length));
    }
    
    printf("\nPassword not found after %lld attempts.\n", attempts);
    printf("Maximum password length (%d) reached.\n", MAX_PASSWORD_LENGTH);
    return 0; // Not found
}

int main(int argc, char *argv[]) {
    char target_hash[33];
    char cracked_password[MAX_PASSWORD_LENGTH + 1];
    clock_t start_time, end_time;
    double execution_time;
    
    // Get target hash from command line or use default
    if (argc > 1) {
        strcpy(target_hash, argv[1]);
    }
    
    // Validate hash length
    if (strlen(target_hash) != 32) {
        printf("Error: Invalid MD5 hash length. Expected 32 characters.\n");
        return 1;
    }
    
    printf("=== Serial MD5 Brute Force Cracker ===\n");
    printf("Target hash: %s\n", target_hash);
    
    // Start timing
    start_time = clock();
    
    // Attempt to crack the hash
    int result = crack_md5_brute_force(target_hash, cracked_password);
    
    // End timing
    end_time = clock();
    execution_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    printf("\n=== Results ===\n");
    if (result) {
        printf("Status: SUCCESS\n");
        printf("Cracked password: %s\n", cracked_password);
    } else {
        printf("Status: FAILED\n");
        printf("Password not found within search space.\n");
    }
    printf("Execution time: %.2f seconds\n", execution_time);
    
    return 0;
}