#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <mpi.h>
#include <unistd.h>

#define MAX_PASSWORD_LENGTH 8
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_SIZE 62
#define PROGRESS_INTERVAL 1000000  // Report progress every N attempts
#define TERMINATION_CHECK_INTERVAL 100000  // Check for termination every N attempts

// MPI message tags
#define TAG_FOUND 1
#define TAG_TERMINATE 2
#define TAG_PROGRESS 3

typedef struct {
    int found;
    char password[MAX_PASSWORD_LENGTH + 1];
    long long attempts;
    int finding_rank;
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

int check_for_termination(int rank) {
    int flag;
    MPI_Status status;
    
    // Non-blocking receive to check for termination message
    MPI_Iprobe(MPI_ANY_SOURCE, TAG_TERMINATE, MPI_COMM_WORLD, &flag, &status);
    
    if (flag) {
        int dummy;
        MPI_Recv(&dummy, 1, MPI_INT, status.MPI_SOURCE, TAG_TERMINATE, MPI_COMM_WORLD, &status);
        return 1;  // Termination signal received
    }
    
    return 0;  // No termination signal
}

void broadcast_termination(int rank, int size) {
    int dummy = 1;
    for (int i = 0; i < size; i++) {
        if (i != rank) {
            MPI_Send(&dummy, 1, MPI_INT, i, TAG_TERMINATE, MPI_COMM_WORLD);
        }
    }
}

void send_result_to_master(int rank, const char *password, long long attempts) {
    result_t result;
    result.found = 1;
    strcpy(result.password, password);
    result.attempts = attempts;
    result.finding_rank = rank;
    
    MPI_Send(&result, sizeof(result_t), MPI_BYTE, 0, TAG_FOUND, MPI_COMM_WORLD);
}

int crack_md5_mpi(const char *target_hash, int rank, int size, result_t *final_result) {
    char current_password[MAX_PASSWORD_LENGTH + 1];
    char computed_hash[33];
    long long local_attempts = 0;
    int password_found = 0;
    
    if (rank == 0) {
        printf("Starting MPI brute-force attack with %d processes\n", size);
        printf("Target hash: %s\n", target_hash);
    }
    
    for (int length = 1; length <= MAX_PASSWORD_LENGTH && !password_found; length++) {
        long long total_combinations = calculate_combinations(length);
        
        // Calculate work distribution among processes
        long long combinations_per_process = total_combinations / size;
        long long remainder = total_combinations % size;
        
        // Calculate this process's range
        long long start_index = rank * combinations_per_process;
        if (rank < remainder) {
            start_index += rank;
            combinations_per_process++;
        } else {
            start_index += remainder;
        }
        long long end_index = start_index + combinations_per_process;
        
        if (rank == 0) {
            printf("\nSearching passwords of length %d...\n", length);
            printf("Total combinations: %lld\n", total_combinations);
        }
        
        MPI_Barrier(MPI_COMM_WORLD);  // Synchronize all processes
        
        // Search through assigned range
        for (long long i = start_index; i < end_index && !password_found; i++) {
            // Check for termination signal periodically
            if (local_attempts % TERMINATION_CHECK_INTERVAL == 0) {
                if (check_for_termination(rank)) {
                    password_found = 1;
                    break;
                }
            }
            
            // Generate password from index
            index_to_password(i, current_password, length);
            
            // Compute MD5 hash
            compute_md5(current_password, computed_hash);
            local_attempts++;
            
            // Progress reporting
            if (rank == 0 && local_attempts % PROGRESS_INTERVAL == 0) {
                printf("Process %d: %lld attempts, current: %s\n", rank, local_attempts, current_password);
            }
            
            // Check if hash matches
            if (strcmp(computed_hash, target_hash) == 0) {
                printf("\n*** PROCESS %d FOUND PASSWORD: %s ***\n", rank, current_password);
                
                // Send result to master
                send_result_to_master(rank, current_password, local_attempts);
                
                // Broadcast termination signal to all other processes
                broadcast_termination(rank, size);
                
                password_found = 1;
                break;
            }
        }
        
        // Master process checks for results from workers
        if (rank == 0) {
            int flag;
            MPI_Status status;
            
            // Non-blocking check for results
            MPI_Iprobe(MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &flag, &status);
            
            if (flag) {
                result_t worker_result;
                MPI_Recv(&worker_result, sizeof(result_t), MPI_BYTE, status.MPI_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &status);
                
                printf("Master received result from process %d\n", worker_result.finding_rank);
                strcpy(final_result->password, worker_result.password);
                final_result->found = 1;
                final_result->finding_rank = worker_result.finding_rank;
                
                // Broadcast termination to all processes
                broadcast_termination(rank, size);
                password_found = 1;
            }
        }
    }
    
    // Gather total attempts from all processes
    long long total_attempts = 0;
    MPI_Reduce(&local_attempts, &total_attempts, 1, MPI_LONG_LONG, MPI_SUM, 0, MPI_COMM_WORLD);
    
    if (rank == 0) {
        final_result->attempts = total_attempts;
    }
    
    return final_result->found;
}

int main(int argc, char *argv[]) {
    int rank, size;
    char target_hash[33];
    result_t result = {0, "", 0, -1};
    double start_time, end_time;
    char hostname[256];
    
    // Initialize MPI
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    // Get hostname for identification
    gethostname(hostname, sizeof(hostname));
    
    // Get target hash from command line
    if (argc > 1) {
        strcpy(target_hash, argv[1]);
    } else {
        if (rank == 0) {
            printf("Usage: %s <32-character MD5 hash>\n", argv[0]);
            printf("Example: %s 5d41402abc4b2a76b9719d911017c592\n", argv[0]);
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
    
    // Print process information
    printf("Process %d of %d running on %s\n", rank, size, hostname);
    
    if (rank == 0) {
        printf("\n=== MPI MD5 Brute Force Cracker ===\n");
        printf("Target hash: %s\n", target_hash);
        printf("Number of MPI processes: %d\n", size);
        printf("Character set: %s\n", CHARSET);
        printf("Character set size: %d\n", CHARSET_SIZE);
        printf("Maximum password length: %d\n", MAX_PASSWORD_LENGTH);
        printf("\nStarting distributed search...\n");
    }
    
    // Synchronize all processes before starting
    MPI_Barrier(MPI_COMM_WORLD);
    
    // Start timing
    start_time = MPI_Wtime();
    
    // Perform the crack attempt
    int success = crack_md5_mpi(target_hash, rank, size, &result);
    
    // End timing
    end_time = MPI_Wtime();
    
    // Final synchronization
    MPI_Barrier(MPI_COMM_WORLD);
    
    // Print results (only from master process)
    if (rank == 0) {
        printf("\n=== FINAL RESULTS MPI VERSION ===\n");
        if (success && result.found) {
            printf("Status: SUCCESS\n");
            printf("Password found: %s\n", result.password);
            printf("Found by process: %d\n", result.finding_rank);
            
            // Verify the result
            char verify_hash[33];
            compute_md5(result.password, verify_hash);
            printf("Verification: %s\n", strcmp(verify_hash, target_hash) == 0 ? "PASSED" : "FAILED");
        } else {
            printf("Status: FAILED\n");
            printf("Password not found within search space.\n");
        }
        
        printf("Total attempts across all processes: %lld\n", result.attempts);
        printf("Total execution time: %.2f seconds\n", end_time - start_time);
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
mpicc -o md5_cracker_mpi md5_cracker_mpi.c -lssl -lcrypto

Execution instructions:
mpirun -np 4 ./md5_cracker_mpi 5d41402abc4b2a76b9719d911017c592

*/