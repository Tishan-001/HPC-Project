# MD5 Cracker Project

This repository contains various implementations of an MD5 hash cracker, demonstrating different approaches to brute-force password cracking, from a basic serial version to parallelized versions using OpenMP, MPI, and a hybrid MPI+OpenMP approach. The project aims to illustrate the performance benefits of parallel computing in computationally intensive tasks like password cracking.




## Features

This project includes four distinct implementations of an MD5 cracker:

*   **`md5_cracker_serial.c`**: A basic, single-threaded implementation that performs a brute-force attack sequentially. It iterates through all possible password combinations within a defined character set and maximum length.

*   **`md5_cracker_openmp.c`**: A parallelized version utilizing OpenMP for shared-memory parallelism. This implementation distributes the workload among multiple threads on a single machine, significantly speeding up the cracking process compared to the serial version.

*   **`md5_cracker_mpi.c`**: A distributed-memory parallel implementation using MPI (Message Passing Interface). This version is designed to run across multiple nodes or machines, with each MPI process handling a portion of the search space. It includes mechanisms for inter-process communication to report found passwords and terminate other processes.

*   **`md5_cracker_hybrid.c`**: A hybrid parallel implementation combining both MPI and OpenMP. This approach leverages the strengths of both paradigms: MPI for distributing tasks across multiple nodes and OpenMP for parallelizing work within each node. This is ideal for high-performance computing environments.




## Compilation

To compile the programs, you will need a C compiler (like GCC) and the OpenSSL development libraries for MD5 hashing. For the parallel versions, you will also need OpenMP support (usually included with GCC) and an MPI implementation (like Open MPI or MPICH).

### General Requirements

*   GCC (GNU Compiler Collection)
*   OpenSSL development libraries (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on Fedora/RHEL)
*   Open MPI or MPICH (for MPI and Hybrid versions)

### `md5_cracker_serial.c`

```bash
gcc -o md5_cracker_serial md5_cracker_serial.c -lssl -lcrypto
```

### `md5_cracker_openmp.c`

```bash
gcc -fopenmp -o md5_cracker_openmp md5_cracker_openmp.c -lssl -lcrypto
```

### `md5_cracker_mpi.c`

```bash
mpicc -o md5_cracker_mpi md5_cracker_mpi.c -lssl -lcrypto
```

### `md5_cracker_hybrid.c`

```bash
mpicc -fopenmp -o md5_cracker_hybrid md5_cracker_hybrid.c -lssl -lcrypto
```





## Usage

All programs require a 32-character MD5 hash as a command-line argument.

### `md5_cracker_serial`

```bash
./md5_cracker_serial <32-character MD5 hash>
# Example:
./md5_cracker_serial 5d41402abc4b2a76b9719d911017c592
```

### `md5_cracker_openmp`

```bash
./md5_cracker_openmp <32-character MD5 hash>
# Example:
./md5_cracker_openmp 5d41402abc4b2a76b9719d911017c592

# To specify the number of OpenMP threads (optional):
export OMP_NUM_THREADS=<number_of_threads>
./md5_cracker_openmp 5d41402abc4b2a76b9719d911017c592
```

### `md5_cracker_mpi`

```bash
mpirun -np <number_of_processes> ./md5_cracker_mpi <32-character MD5 hash>
# Example (run with 4 MPI processes):
mpirun -np 4 ./md5_cracker_mpi 5d41402abc4b2a76b9719d911017c592
```

### `md5_cracker_hybrid`

```bash
# Set the number of OpenMP threads per MPI process:
export OMP_NUM_THREADS=<number_of_threads_per_process>

mpirun -np <number_of_mpi_processes> ./md5_cracker_hybrid <32-character MD5 hash>
# Example (run with 4 MPI processes, each using 2 OpenMP threads):
export OMP_NUM_THREADS=2
mpirun -np 4 ./md5_cracker_hybrid 5d41402abc4b2a76b9719d911017c592
```





## Configuration (Common to all versions)

All cracker versions use a predefined character set and maximum password length. These can be modified by editing the respective `#define` statements in the source code:

*   `MAX_PASSWORD_LENGTH`: Defines the maximum length of passwords to be cracked. Default is 8.
*   `CHARSET`: Defines the set of characters used for generating passwords. Default is `"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"` (alphanumeric, case-sensitive).
*   `CHARSET_SIZE`: Automatically calculated based on `CHARSET`.

**Note**: Increasing `MAX_PASSWORD_LENGTH` or expanding `CHARSET` will significantly increase the search space and, consequently, the time required to crack a password. The search space grows exponentially with password length and character set size.





## Project Structure

```
.
├── md5_cracker_serial.c
├── md5_cracker_openmp.c
├── md5_cracker_mpi.c
├── md5_cracker_hybrid.c
└── README.md
```

*   `md5_cracker_serial.c`: Source code for the serial MD5 cracker.
*   `md5_cracker_openmp.c`: Source code for the OpenMP parallel MD5 cracker.
*   `md5_cracker_mpi.c`: Source code for the MPI distributed MD5 cracker.
*   `md5_cracker_hybrid.c`: Source code for the hybrid MPI+OpenMP MD5 cracker.
*   `README.md`: This documentation file.