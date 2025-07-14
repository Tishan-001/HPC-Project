#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <mpi.h>
#include <omp.h>

#define MAX_PASSWORD_LENGTH 8
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_SIZE 62
#define WORK_CHUNK_SIZE 1000000  // Number of passwords each thread processes before checking for termination

typedef struct {
    int found;
    char password[MAX_PASSWORD_LENGTH + 1];
    long long attempts;
    int finding_process;
    int finding_thread;
} result_t;

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

long long calculate_combinations(int length) {
    long long total = 1;
    for (int i = 0; i < length; i++) {
        total *= CHARSET_SIZE;
    }
    return total;
}

void index_to_password(long long index, char *password, int length) {
    for (int i = length - 1; i >= 0; i--) {
        password[i] = CHARSET[index % CHARSET_SIZE];
        index /= CHARSET_SIZE;
    }
    password[length] = '\0';
}

int crack_md5_hybrid(const char *target_hash, int rank, int size, result_t *result) {
    long long total_attempts = 0;
    int global_found = 0;
    
    for (int length = 1; length <= MAX_PASSWORD_LENGTH && !global_found; length++) {
        long long total_combinations = calculate_combinations(length);
        
        // Calculate work distribution among MPI processes
        long long combinations_per_process = total_combinations / size;
        long long remainder = total_combinations % size;
        
        // Calculate this process's start and end indices
        long long start_index = rank * combinations_per_process;
        if (rank < remainder) {
            start_index += rank;
            combinations_per_process++;
        } else {
            start_index += remainder;
        }
        long long end_index = start_index + combinations_per_process;
        
        if (rank == 0) {
            printf("Length %d: Total combinations: %lld\n", length, total_combinations);
            printf("Process %d handling range: %lld to %lld (%lld combinations)\n", 
                   rank, start_index, end_index - 1, combinations_per_process);
        }
        
        // OpenMP parallel region
        #pragma omp parallel
        {
            char thread_password[MAX_PASSWORD_LENGTH + 1];
            char thread_hash[33];  // Each thread has its own hash buffer
            long long thread_attempts = 0;
            
            #pragma omp for schedule(dynamic, WORK_CHUNK_SIZE) nowait
            for (long long i = start_index; i < end_index; i++) {
                // Check if password already found by any process/thread
                if (global_found) continue;  // Use continue instead of break
                
                // Generate password from index
                index_to_password(i, thread_password, length);
                
                // Compute MD5 hash
                compute_md5(thread_password, thread_hash);
                thread_attempts++;
                
                // Progress reporting every 100,000 attempts
                if (thread_attempts % 100000 == 0) {
                    #pragma omp critical
                    {
                        printf("Process %d, Thread %d: %lld attempts, Current password: %s\n", 
                               rank, omp_get_thread_num(), thread_attempts, thread_password);
                    }
                }
                
                // Check if hash matches
                if (strcmp(thread_hash, target_hash) == 0) {
                    #pragma omp critical
                    {
                        if (!global_found) {
                            global_found = 1;
                            result->found = 1;
                            strcpy(result->password, thread_password);
                            result->attempts = thread_attempts;
                            result->finding_process = rank;
                            result->finding_thread = omp_get_thread_num();
                            printf("*** PASSWORD FOUND! ***\n");
                            printf("Process %d, Thread %d found password: %s\n", 
                                   rank, omp_get_thread_num(), thread_password);
                        }
                    }
                    // Force exit from the loop
                    continue;
                }
            }
            
            // Accumulate thread attempts
            #pragma omp atomic
            total_attempts += thread_attempts;
        }
        
        // Check if any process found the password after the parallel region
        int any_found = 0;
        MPI_Allreduce(&global_found, &any_found, 1, MPI_INT, MPI_LOR, MPI_COMM_WORLD);
        
        if (any_found) {
            global_found = 1;
            if (rank == 0) {
                printf("Password found! Terminating search.\n");
            }
            break;
        }
        
        // Progress reporting
        if (rank == 0) {
            printf("Completed length %d search\n", length);
        }
    }
    
    // Gather results from all processes
    result_t all_results[size];
    MPI_Gather(result, sizeof(result_t), MPI_BYTE, all_results, sizeof(result_t), MPI_BYTE, 0, MPI_COMM_WORLD);
    
    // Find the process that found the password
    if (rank == 0) {
        for (int i = 0; i < size; i++) {
            if (all_results[i].found) {
                strcpy(result->password, all_results[i].password);
                result->found = 1;
                result->finding_process = all_results[i].finding_process;
                result->finding_thread = all_results[i].finding_thread;
                break;
            }
        }
    }
    
    // Broadcast result to all processes
    MPI_Bcast(result, sizeof(result_t), MPI_BYTE, 0, MPI_COMM_WORLD);
    
    // Sum up total attempts from all processes
    long long global_attempts = 0;
    MPI_Reduce(&total_attempts, &global_attempts, 1, MPI_LONG_LONG, MPI_SUM, 0, MPI_COMM_WORLD);
    
    if (rank == 0) {
        result->attempts = global_attempts;
    }
    
    return result->found;
}

int main(int argc, char *argv[]) {
    int rank, size;
    char target_hash[33];
    result_t result = {0, "", 0, -1, -1};
    double start_time, end_time;
    
    // Initialize MPI
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    // Get target hash from command line
    if (argc > 1) {
        strcpy(target_hash, argv[1]);
    } else {
        if (rank == 0) {
            printf("Usage: %s <32-character MD5 hash>\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    }
    
    // Validate hash length
    if (strlen(target_hash) != 32) {
        if (rank == 0) {
            printf("Error: Invalid MD5 hash length. Expected 32 characters.\n");
        }
        MPI_Finalize();
        return 1;
    }
    
    // Print header information
    if (rank == 0) {
        printf("=== Hybrid MPI + OpenMP MD5 Brute Force Cracker ===\n");
        printf("Target hash: %s\n", target_hash);
        printf("MPI processes: %d\n", size);
        printf("OpenMP threads per process: %d\n", omp_get_max_threads());
        printf("Total parallel units: %d\n", size * omp_get_max_threads());
        printf("Character set: %s\n", CHARSET);
        printf("Character set size: %d\n", CHARSET_SIZE);
        printf("Max password length: %d\n", MAX_PASSWORD_LENGTH);
        printf("\nStarting hybrid parallel search...\n");
    }
    
    // Start timing
    start_time = MPI_Wtime();
    
    // Perform the crack attempt
    int success = crack_md5_hybrid(target_hash, rank, size, &result);
    
    // End timing
    end_time = MPI_Wtime();
    
    // Print results (only from rank 0)
    if (rank == 0) {
        printf("\n=== FINAL RESULTS HYBRID VERSION ===\n");
        if (success && result.found) {
            printf("Status: SUCCESS\n");
            printf("Password found: %s\n", result.password);
            printf("Found by: Process %d, Thread %d\n", result.finding_process, result.finding_thread);
            
            // Verify the result
            char verify_hash[33];
            compute_md5(result.password, verify_hash);
            printf("Verification: %s\n", strcmp(verify_hash, target_hash) == 0 ? "PASSED" : "FAILED");
        } else {
            printf("Status: FAILED\n");
            printf("Password not found within search space.\n");
        }
        printf("Total attempts: %lld\n", result.attempts);
        printf("Execution time: %.2f seconds\n", end_time - start_time);
        
        if (success && result.found) {
            printf("Attempts per second: %.0f\n", result.attempts / (end_time - start_time));
        }
    }
    
    // Finalize MPI
    MPI_Finalize();
    return success ? 0 : 1;
}

/*
Compilation instructions:
mpicc -fopenmp -o md5_cracker_hybrid md5_cracker_hybrid.c -lssl -lcrypto

Execution instructions:
mpirun -np 4 ./md5_cracker_hybrid 5d41402abc4b2a76b9719d911017c592

Note: Set the number of OpenMP threads per process using:
export OMP_NUM_THREADS=4
mpirun -np 4 ./md5_cracker_hybrid 5d41402abc4b2a76b9719d911017c592

*/