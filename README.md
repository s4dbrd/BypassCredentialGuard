# Credential Guard Bypass PoC

This project contains a proof-of-concept (PoC) tool inspired by [itm4n's Credential Guard Bypass](https://itm4n.github.io/credential-guard-bypass/). The tool manipulates the behavior of the `wdigest` authentication mechanism on a Windows system. It locates and modifies specific global variables within the `wdigest` library (`g_fParameter_UseLogonCredential` and `g_IsCredGuardEnabled`) in the context of the `lsass.exe` process to enable or disable `Credential Guard`.

**Disclaimer:** This tool is for educational and research purposes only. Unauthorized use of this tool may violate laws or regulations. Use it responsibly and ensure you have the appropriate permissions.

---

## Features

- **Read** the current state of `Credential Guard` and `Use Logon Credential` variables.
- **Patch** (`enable`) the `Use Logon Credential` variable and disable `Credential Guard`.
- **Clean** (`revert`) the variables to their original state.

---

## How It Works

The program:
1. Locates the `lsass.exe` process.
2. Identifies the `wdigest.dll` library in memory.
3. Finds specific global variables using pattern matching on the `.text` section of `wdigest.dll`.
4. Calculates the virtual addresses of `g_fParameter_UseLogonCredential` and `g_IsCredGuardEnabled`.
5. Patches or cleans these variables in the memory of the `lsass.exe` process.

---

## Usage

Compile the program with a C++ compiler that supports Windows APIs.

### Command Syntax

```bash
CredentialGuardBypass.exe [OPTION]
```

### Parameters

| Parameter  | Description                                                                                  |
|------------|----------------------------------------------------------------------------------------------|
| `--read`   | Reads the current values of `g_fParameter_UseLogonCredential` and `g_IsCredGuardEnabled`.   |
| `--patch`  | Patches (`enables`) `g_fParameter_UseLogonCredential` and disables `g_IsCredGuardEnabled`.  |
| `--clean`  | Cleans (`reverts`) `g_fParameter_UseLogonCredential` and enables `g_IsCredGuardEnabled`.    |

### Example Commands

1. **Read the current state:**
   ```bash
   CredentialGuardBypass.exe --read
   ```

2. **Enable Wdigest (patch):**
   ```bash
   CredentialGuardBypass.exe --patch
   ```

3. **Revert changes (clean):**
   ```bash
   CredentialGuardBypass.exe --clean
   ```

---

## Dependencies

- Windows platform (requires access to `lsass.exe` and `wdigest.dll`).
- Admin privileges (necessary to access and modify the memory of `lsass.exe`).

---

## How It Works Internally

1. **Process Identification:** Uses `Toolhelp32Snapshot` to locate the process ID of `lsass.exe`.
2. **Module Base Address:** Finds the base address of `wdigest.dll` in the process memory.
3. **Pattern Matching:** Searches the `.text` section of `wdigest.dll` for specific instruction patterns to locate offsets.
4. **Virtual Address Calculation:** Computes the addresses of `g_fParameter_UseLogonCredential` and `g_IsCredGuardEnabled`.
5. **Memory Modification:** Reads or writes values to the identified memory locations using `ReadProcessMemory` and `WriteProcessMemory`.

---

## Security Considerations

- Running this tool requires admin privileges and direct access to system processes.
- The tool manipulates sensitive areas of system memory. Improper usage may result in system instability.
- Ensure proper authorization before using this tool.

---

## Legal Disclaimer

This tool is provided "as is" for educational purposes only. The author is not responsible for any misuse or damage caused by this tool. Ensure you have explicit permission to test or audit the targeted system.