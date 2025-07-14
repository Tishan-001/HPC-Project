#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <omp.h>
#include <openssl/md5.h>

#define MAX_PASSWORD_LENGTH 8
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_SIZE 62

int password_found = 0;
char found_password[MAX_PASSWORD_LENGTH + 1];
long long total_attempts = 0;
double execution_time;

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

void index_to_password(long long index, int length, char *password) {
    for (int i = length - 1; i >= 0; i--) {
        password[i] = CHARSET[index % CHARSET_SIZE];
        index /= CHARSET_SIZE;
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

int crack_md5_openmp(const char *target_hash, char *cracked_password) {
    double start_time, end_time;
    
    printf("Starting OpenMP brute-force attack on hash: %s\n", target_hash);
    printf("Character set: %s\n", CHARSET);
    printf("Character set size: %d\n", CHARSET_SIZE);
    printf("Number of threads: %d\n", omp_get_max_threads());
    
    start_time = omp_get_wtime();
    
    for (int length = 1; length <= MAX_PASSWORD_LENGTH && !password_found; length++) {
        printf("\nTrying passwords of length %d...\n", length);
        
        long long combinations = calculate_combinations(length);
        printf("Total combinations for length %d: %lld\n", length, combinations);
        
        #pragma omp parallel
        {
            char current_password[MAX_PASSWORD_LENGTH + 1];
            char computed_hash[33];
            int thread_id = omp_get_thread_num();
            long long local_attempts = 0;
            
            #pragma omp for schedule(dynamic, 10000) nowait
            for (long long i = 0; i < combinations; i++) {

                if (password_found) continue;
                
                local_attempts++;
                
                index_to_password(i, length, current_password);
                
                compute_md5(current_password, computed_hash);
                
                if (local_attempts % 100000 == 0) {
                    #pragma omp critical
                    {
                        printf("Thread %d: %lld attempts, Current: %s\n", 
                               thread_id, local_attempts, current_password);
                    }
                }
                
                if (strcmp(computed_hash, target_hash) == 0) {
                    #pragma omp critical
                    {
                        if (!password_found) {
                            password_found = 1;
                            strcpy(found_password, current_password);
                            printf("\n*** PASSWORD FOUND BY THREAD %d! ***\n", thread_id);
                            printf("Password: %s\n", current_password);
                        }
                    }
                }
            }
            
            #pragma omp atomic
            total_attempts += local_attempts;
        }
        
        if (password_found) {
            strcpy(cracked_password, found_password);
            break;
        }
    }
    
    end_time = omp_get_wtime();

    execution_time = end_time - start_time;
    
    if (password_found) {
        printf("\nTotal attempts across all threads: %lld\n", total_attempts);
        printf("Execution time: %.2f seconds\n", execution_time);
        return 1;
    } else {
        printf("\nPassword not found after %lld attempts.\n", total_attempts);
        printf("Maximum password length (%d) reached.\n", MAX_PASSWORD_LENGTH);
        printf("Execution time: %.2f seconds\n", execution_time);
        return 0;
    }
}

int main(int argc, char *argv[]) {
    char target_hash[33];
    char cracked_password[MAX_PASSWORD_LENGTH + 1];
    int benchmark_mode = 0;
    int num_threads = omp_get_max_threads();
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[i + 1]);
            i++;
        } else if (strlen(argv[i]) == 32) {
            strcpy(target_hash, argv[i]);
        }
    }
    
    if (strlen(target_hash) != 32) {
        printf("Error: Invalid MD5 hash length. Expected 32 characters.\n");
        return 1;
    }
    
    printf("=== OpenMP Parallel MD5 Brute Force Cracker ===\n");
    printf("Target hash: %s\n", target_hash);
    
    omp_set_num_threads(num_threads);
        
    int result = crack_md5_openmp(target_hash, cracked_password);
        
    printf("\n=== FINAL RESULTS OPENMP VERSION ===\n");
    if (result) {
        printf("Status: SUCCESS\n");
        printf("Cracked password: %s\n", cracked_password);
    } else {
        printf("Status: FAILED\n");
        printf("Password not found within search space.\n");
    }
        
    printf("Total attempts: %lld\n", total_attempts);
    printf("Threads used: %d\n", num_threads);
    printf("Execution time: %.2f seconds\n", execution_time);
    if (execution_time > 0) {
        printf("Attempts per second: %.0f\n", total_attempts / execution_time);
    }
    
    return 0;
}

/*
Compilation instructions:
gcc -fopenmp -o md5_cracker_openmp md5_cracker_openmp.c -lssl -lcrypto

Execution instructions:
./md5_cracker_openmp 5d41402abc4b2a76b9719d911017c592

*/