#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <omp.h>
#include <openssl/md5.h>

#define MAX_PASSWORD_LENGTH 8
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_SIZE 62

// Global variables
int password_found = 0;
char found_password[MAX_PASSWORD_LENGTH + 1];
long long total_attempts = 0;
double execution_time;

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

// Function to convert index to password of given length
void index_to_password(long long index, int length, char *password) {
    for (int i = length - 1; i >= 0; i--) {
        password[i] = CHARSET[index % CHARSET_SIZE];
        index /= CHARSET_SIZE;
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

// OpenMP parallel brute force MD5 cracker
int crack_md5_openmp(const char *target_hash, char *cracked_password) {
    double start_time, end_time;
    
    printf("Starting OpenMP brute-force attack on hash: %s\n", target_hash);
    printf("Character set: %s\n", CHARSET);
    printf("Character set size: %d\n", CHARSET_SIZE);
    printf("Number of threads: %d\n", omp_get_max_threads());
    
    start_time = omp_get_wtime();
    
    // Try different password lengths
    for (int length = 1; length <= MAX_PASSWORD_LENGTH && !password_found; length++) {
        printf("\nTrying passwords of length %d...\n", length);
        
        long long combinations = calculate_combinations(length);
        printf("Total combinations for length %d: %lld\n", length, combinations);
        
        // OpenMP parallel loop
        #pragma omp parallel
        {
            char current_password[MAX_PASSWORD_LENGTH + 1];
            char computed_hash[33];
            int thread_id = omp_get_thread_num();
            long long local_attempts = 0;
            
            // Dynamic scheduling to handle load balancing
            #pragma omp for schedule(dynamic, 10000) nowait
            for (long long i = 0; i < combinations; i++) {
                // Check if password already found by another thread
                if (password_found) continue;
                
                local_attempts++;
                
                // Convert index to password
                index_to_password(i, length, current_password);
                
                // Compute MD5 hash
                compute_md5(current_password, computed_hash);
                
                // Progress indicator (every 100000 attempts per thread)
                if (local_attempts % 100000 == 0) {
                    #pragma omp critical
                    {
                        printf("Thread %d: %lld attempts, Current: %s\n", 
                               thread_id, local_attempts, current_password);
                    }
                }
                
                // Check if hash matches
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
                    // Don't use break - let the continue check handle early exit
                }
            }
            
            // Update total attempts counter
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
        return 1; // Success
    } else {
        printf("\nPassword not found after %lld attempts.\n", total_attempts);
        printf("Maximum password length (%d) reached.\n", MAX_PASSWORD_LENGTH);
        printf("Execution time: %.2f seconds\n", execution_time);
        return 0; // Not found
    }
}

// Function to test different thread counts
void benchmark_thread_performance(const char *target_hash) {
    printf("\n=== Thread Performance Benchmark ===\n");
    
    int thread_counts[] = {1, 2, 4, 8, 16};
    int num_tests = sizeof(thread_counts) / sizeof(thread_counts[0]);
    
    for (int i = 0; i < num_tests; i++) {
        // Reset global variables
        password_found = 0;
        total_attempts = 0;
        memset(found_password, 0, sizeof(found_password));
        
        printf("\n--- Testing with %d threads ---\n", thread_counts[i]);
        omp_set_num_threads(thread_counts[i]);
        
        char cracked_password[MAX_PASSWORD_LENGTH + 1];
        double start_time = omp_get_wtime();
        
        int result = crack_md5_openmp(target_hash, cracked_password);
        
        double end_time = omp_get_wtime();
        double execution_time = end_time - start_time;
        
        printf("Threads: %d, Time: %.2f seconds", thread_counts[i], execution_time);
        if (result) {
            printf(", Password: %s", cracked_password);
        }
        printf("\n");
        
        if (result) break; // Stop if password found
    }
}

int main(int argc, char *argv[]) {
    char target_hash[33];
    char cracked_password[MAX_PASSWORD_LENGTH + 1];
    int benchmark_mode = 0;
    int num_threads = omp_get_max_threads();
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[i + 1]);
            i++; // Skip next argument
        } else if (strcmp(argv[i], "-benchmark") == 0) {
            benchmark_mode = 1;
        } else if (strlen(argv[i]) == 32) {
            strcpy(target_hash, argv[i]);
        }
    }
    
    // Validate hash length
    if (strlen(target_hash) != 32) {
        printf("Error: Invalid MD5 hash length. Expected 32 characters.\n");
        return 1;
    }
    
    printf("=== OpenMP Parallel MD5 Brute Force Cracker ===\n");
    printf("Target hash: %s\n", target_hash);
    
    if (benchmark_mode) {
        benchmark_thread_performance(target_hash);
    } else {
        // Set number of threads
        omp_set_num_threads(num_threads);
        
        // Attempt to crack the hash
        int result = crack_md5_openmp(target_hash, cracked_password);
        
        printf("\n=== Results ===\n");
        if (result) {
            printf("Status: SUCCESS\n");
            printf("Cracked password: %s\n", cracked_password);
        } else {
            printf("Status: FAILED\n");
            printf("Password not found within search space.\n");
        }
        
        printf("Threads used: %d\n", num_threads);
        printf("Execution time: %.2f seconds\n", execution_time);
    }
    
    return 0;
}