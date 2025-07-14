#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>

#define MAX_PASSWORD_LENGTH 8
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_SIZE 62

void md5_to_hex(unsigned char *hash, char *hex_string) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[32] = '\0';
}

void compute_md5(const char *input, char *output) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5_ctx;
    
    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, input, strlen(input));
    MD5_Final(hash, &md5_ctx);
    
    md5_to_hex(hash, output);
}

int generate_next_password(char *password, int length) {
    int i = length - 1;
    
    while (i >= 0) {
        int current_index = strchr(CHARSET, password[i]) - CHARSET;
        
        if (current_index < CHARSET_SIZE - 1) {
            password[i] = CHARSET[current_index + 1];
            return 1;
        } else {
            password[i] = CHARSET[0];
            i--;
        }
    }
    
    return 0;
}

void initialize_password(char *password, int length) {
    for (int i = 0; i < length; i++) {
        password[i] = CHARSET[0];
    }
    password[length] = '\0';
}

long long calculate_combinations(int length) {
    long long total = 1;
    for (int i = 0; i < length; i++) {
        total *= CHARSET_SIZE;
    }
    return total;
}

int crack_md5_brute_force(const char *target_hash, char *cracked_password, long long *total_attempts) {
    char current_password[MAX_PASSWORD_LENGTH + 1];
    char computed_hash[33];
    *total_attempts = 0;
    
    printf("Starting brute-force attack on hash: %s\n", target_hash);
    printf("Character set: %s\n", CHARSET);
    printf("Character set size: %d\n", CHARSET_SIZE);
    
    for (int length = 1; length <= MAX_PASSWORD_LENGTH; length++) {
        printf("\nTrying passwords of length %d...\n", length);
        
        long long combinations = calculate_combinations(length);
        printf("Total combinations for length %d: %lld\n", length, combinations);
        
        initialize_password(current_password, length);
        
        do {
            (*total_attempts)++;
            
            compute_md5(current_password, computed_hash);
            
            if (*total_attempts % 100000 == 0) {
                printf("Attempts: %lld, Current: %s\n", *total_attempts, current_password);
            }
            
            // Check if hash matches
            if (strcmp(computed_hash, target_hash) == 0) {
                strcpy(cracked_password, current_password);
                printf("\n*** PASSWORD FOUND! ***\n");
                printf("Password: %s\n", current_password);
                printf("Total attempts: %lld\n", *total_attempts);
                return 1;
            }
            
        } while (generate_next_password(current_password, length));
    }
    
    printf("\nPassword not found after %lld attempts.\n", *total_attempts);
    printf("Maximum password length (%d) reached.\n", MAX_PASSWORD_LENGTH);
    return 0;
}

int main(int argc, char *argv[]) {
    char target_hash[33];
    char cracked_password[MAX_PASSWORD_LENGTH + 1];
    long long total_attempts = 0;
    clock_t start_time, end_time;
    double execution_time;
    
    if (argc > 1) {
        strcpy(target_hash, argv[1]);
    }
    
    if (strlen(target_hash) != 32) {
        printf("Error: Invalid MD5 hash length. Expected 32 characters.\n");
        return 1;
    }
    
    printf("=== Serial MD5 Brute Force Cracker ===\n");
    printf("Target hash: %s\n", target_hash);
    
    start_time = clock();
    
    int result = crack_md5_brute_force(target_hash, cracked_password, &total_attempts);
    
    end_time = clock();
    execution_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    printf("\n=== FINAL RESULTS SERIAL VERSION===\n");
    if (result) {
        printf("Status: SUCCESS\n");
        printf("Cracked password: %s\n", cracked_password);
    } else {
        printf("Status: FAILED\n");
        printf("Password not found within search space.\n");
    }
    printf("Total attempts: %lld\n", total_attempts);
    printf("Execution time: %.2f seconds\n", execution_time);
    if (execution_time > 0) {
        printf("Attempts per second: %.0f\n", total_attempts / execution_time);
    }
    
    return 0;
}

/*
Compilation instructions:
gcc -o md5_cracker_serial md5_cracker_serial.c -lssl -lcrypto

Execution instructions:
./md5_cracker_serial 5d41402abc4b2a76b9719d911017c592

*/