<#
.SYNOPSIS
Kerberos Keytab Generator Module

.DESCRIPTION
This module provides functions to convert DSInternals objects to a suitable format and create Kerberos keytab files, including a combined keytab file.

.EXAMPLE
# Import the module
Import-Module .\KeytabGenerator.psm1

# Retrieve DSInternals objects
$dsInternalsObjects = Get-ADReplAccount -All -Server "DC01.contoso.com"

# Convert DSInternals objects to suitable format (as byte arrays)
$accountKeys = ConvertFrom-DSInternals -DSInternalsObjects $dsInternalsObjects -Format ByteArrays

# Create keytabs, including a combined keytab
New-Keytabs -AccountKeys $accountKeys -OutputDirectory "C:\temp\keytabs" -Realm "CONTOSO.COM" -CreateCombined

.NOTES
Ensure you have the necessary permissions to read AD objects and write keytab files.
The DSInternals module is required for retrieving account information.
#>
using namespace System.Collections.Generic
using namespace System.Text

class KeytabEntry {
    [int32]$Size
    [uint16]$NumComponents = 1
    [string]$Realm
    [string]$Principal
    [int32]$NameType = 1
    [uint32]$Timestamp
    [byte]$KeyVersion = 2
    [uint16]$KeyType
    [byte[]]$Key

    [byte[]] ToByteArray() {
        $entry = [List[byte]]::new()
        
        # Placeholder for size (will be filled later)
        $entry.AddRange([byte[]]::new(4))
        
        $entry.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int16]$this.NumComponents)))
        
        $realmBytes = [Encoding]::ASCII.GetBytes($this.Realm)
        $entry.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int16]$realmBytes.Length)))
        $entry.AddRange($realmBytes)
        
        $principalBytes = [Encoding]::ASCII.GetBytes($this.Principal)
        $entry.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int16]$principalBytes.Length)))
        $entry.AddRange($principalBytes)
        
        $entry.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int32]$this.NameType)))
        $entry.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int32]$this.Timestamp)))
        $entry.Add($this.KeyVersion)
        $entry.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int16]$this.KeyType)))
        $entry.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int16]$this.Key.Length)))
        $entry.AddRange($this.Key)
        
        # Calculate and set the size (excluding the size field itself)
        $this.Size = $entry.Count - 4
        $sizeBytes = [BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder($this.Size))
        for ($i = 0; $i -lt 4; $i++) {
            $entry[$i] = $sizeBytes[$i]
        }
        
        return $entry.ToArray()
    }
}

class Keytab {
    [List[KeytabEntry]]$Entries = [List[KeytabEntry]]::new()

    [byte[]] ToByteArray() {
        $keytab = [List[byte]]::new()
        $keytab.AddRange([BitConverter]::GetBytes([IPAddress]::HostToNetworkOrder([int16]0x0502)))
        foreach ($entry in $this.Entries) {
            $keytab.AddRange($entry.ToByteArray())
        }
        return $keytab.ToArray()
    }
}

function ConvertFrom-DSInternals {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSObject[]]$DSInternalsObjects,
        [Parameter(Mandatory=$false)]
        [ValidateSet("ByteArrays", "Strings")]
        [string]$Format = "ByteArrays"
    )

    begin {
        $keyTypeMap = @{
            1 = 'DES_CBC_CRC'
            2 = 'DES_CBC_MD4'
            3 = 'DES_CBC_MD5'
            16 = 'AES128_CTS_HMAC_SHA1_96'
            17 = 'AES256_CTS_HMAC_SHA1_96'
            23 = 'RC4_HMAC'
            24 = 'RC4_HMAC_EXP'
            -133 = 'RC4_HMAC_OLD'
            -135 = 'RC4_HMAC_OLD_EXP'
            -138 = 'RC4_MD4'
            18 = 'AES128_CTS_HMAC_SHA256_128'
            19 = 'AES256_CTS_HMAC_SHA384_192'
        }
        $resultKeys = @{}
    }

    process {
        foreach ($obj in $DSInternalsObjects) {
            $keys = @{}

            # Always process NT hash
            if ($obj.NTHash) {
                if ($Format -eq "Strings") {
                    $keys["RC4_HMAC"] = [System.BitConverter]::ToString($obj.NTHash).Replace('-', '')
                } else {
                    $keys[23] = $obj.NTHash
                }
            }

            # Process Kerberos keys
            if ($obj.SupplementalCredentials.Kerberos) {
                foreach ($kerberosKey in $obj.SupplementalCredentials.Kerberos.Credentials) {
                    $keyType = [int]$kerberosKey.KeyType
                    if ($Format -eq "Strings") {
                        $keys[$keyTypeMap[$keyType]] = [System.BitConverter]::ToString($kerberosKey.Key).Replace('-', '')
                    } else {
                        $keys[$keyType] = $kerberosKey.Key
                    }
                }
            }

            # Process KerberosNew keys
            if ($obj.SupplementalCredentials.KerberosNew) {
                foreach ($kerberosKey in $obj.SupplementalCredentials.KerberosNew.Credentials) {
                    $keyType = [int]$kerberosKey.KeyType
                    if ($Format -eq "Strings") {
                        $keys[$keyTypeMap[$keyType]] = [System.BitConverter]::ToString($kerberosKey.Key).Replace('-', '')
                    } else {
                        $keys[$keyType] = $kerberosKey.Key
                    }
                }
            }

            if ($keys.Count -gt 0) {
                $resultKeys[$obj.SamAccountName] = $keys
            }
        }
    }

    end {
        return $resultKeys
    }
}

function New-Keytabs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$AccountKeys,

        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,

        [Parameter(Mandatory=$true)]
        [string]$Realm,

        [Parameter(Mandatory=$false)]
        [switch]$CreateCombined
    )

    # Ensure output directory exists
    if (-not (Test-Path -Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $combinedKeytab = [Keytab]::new()

    foreach ($account in $AccountKeys.Keys) {
        $keytab = [Keytab]::new()
        $timestamp = 0  # Set timestamp to 0

        # Split the account name into components
        $components = $account.Split('/')
        $principal = $components[-1]  # Last component is the actual account name

        # Sort key types in reverse numerical order
        $sortedKeyTypes = $AccountKeys[$account].Keys | Sort-Object -Descending

        foreach ($keyType in $sortedKeyTypes) {
            $entry = [KeytabEntry]::new()
            $entry.Realm = $Realm
            $entry.Principal = $principal
            $entry.NumComponents = $components.Count
            $entry.Timestamp = $timestamp
            $entry.KeyType = [uint16]$keyType
            $entry.Key = $AccountKeys[$account][$keyType]
            $keytab.Entries.Add($entry)
            $combinedKeytab.Entries.Add($entry)
        }

        $OutputDirectory = $OutputDirectory | Resolve-Path
        $outputFile = Join-Path -Path $OutputDirectory -ChildPath "$account.keytab"
        New-Item -ItemType File -Path $($outputFile) -Force | Out-Null
        [System.IO.File]::WriteAllBytes($outputFile, $keytab.ToByteArray())
    }

    if ($CreateCombined) {
        $combinedOutputFile = Join-Path -Path $OutputDirectory -ChildPath "combined.keytab"
        [System.IO.File]::WriteAllBytes($combinedOutputFile, $combinedKeytab.ToByteArray())
    }
}

function Format-KeysToString {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$AccountKeys
    )

    $formattedOutput = ""
    foreach ($account in $AccountKeys.Keys | Sort-Object) {
        $formattedOutput += "Account: $account`n"
        foreach ($keyType in $AccountKeys[$account].Keys | Sort-Object) {
            $keyValue = $AccountKeys[$account][$keyType]
            $keyString = $keyValue -is [byte[]] ? [System.BitConverter]::ToString($keyValue).Replace('-', '') : $keyValue
            $formattedOutput += "  Key Type $keyType : $keyString`n"
        }
        $formattedOutput += "`n"
    }
    return $formattedOutput
}

# Add a ToString method to the result of ConvertFrom-DSInternals
Update-TypeData -TypeName System.Collections.Hashtable -MemberType ScriptMethod -MemberName ToString -Value {
    return Format-KeysToString -AccountKeys $this
} -Force

function Read-Keytab {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$KeytabPath
    )

    $keyTypeMap = @{
        1 = 'DES-CBC-CRC'
        2 = 'DES-CBC-MD4'
        3 = 'DES-CBC-MD5'
        16 = 'AES128-CTS-HMAC-SHA1-96'
        17 = 'AES256-CTS-HMAC-SHA1-96'
        18 = 'AES128-CTS-HMAC-SHA256-128'
        19 = 'AES256-CTS-HMAC-SHA384-192'
        23 = 'RC4-HMAC'
        24 = 'RC4-HMAC-EXP'
    }

    function ReadInt16 {
        param ([byte[]]$Bytes, [ref]$Offset)
        $value = [BitConverter]::ToInt16($Bytes[$Offset.Value..($Offset.Value+1)], 0)
        $Offset.Value += 2
        return [IPAddress]::NetworkToHostOrder([int16]$value)
    }

    function ReadInt32 {
        param ([byte[]]$Bytes, [ref]$Offset)
        $value = [BitConverter]::ToInt32($Bytes[$Offset.Value..($Offset.Value+3)], 0)
        $Offset.Value += 4
        return [IPAddress]::NetworkToHostOrder([int32]$value)
    }

    function ReadString {
        param ([byte[]]$Bytes, [ref]$Offset)
        $length = ReadInt16 $Bytes $Offset
        $string = [System.Text.Encoding]::ASCII.GetString($Bytes[$Offset.Value..($Offset.Value+$length-1)])
        $Offset.Value += $length
        return $string
    }

    $bytes = [System.IO.File]::ReadAllBytes($KeytabPath)
    $offset = [ref]0

    $version = ReadInt16 $bytes $offset

    Write-Host "Keytab Version: 0x$($version.ToString('X4'))"
    Write-Host "-----------------------------------"

    while ($offset.Value -lt $bytes.Length) {
        $entrySize = ReadInt32 $bytes $offset
        $entryStart = $offset.Value

        $numComponents = ReadInt16 $bytes $offset
        $realm = ReadString $bytes $offset

        $principal = @()
        for ($i = 0; $i -lt $numComponents; $i++) {
            $principal += ReadString $bytes $offset
        }

        $nameType = ReadInt32 $bytes $offset
        $timestamp = ReadInt32 $bytes $offset
        $kvno = $bytes[$offset.Value]; $offset.Value++
        $keyType = ReadInt16 $bytes $offset
        $keyLength = ReadInt16 $bytes $offset
        $key = $bytes[$offset.Value..($offset.Value+$keyLength-1)]
        $offset.Value += $keyLength

        Write-Host "Principal: $($principal -join '/')@$realm"
        Write-Host "  Name Type: $nameType"
        Write-Host "  Timestamp: $([DateTimeOffset]::FromUnixTimeSeconds($timestamp).DateTime)"
        Write-Host "  KVNO: $kvno"
        Write-Host "  Key Type: $($keyTypeMap[$keyType]) ($keyType)"
        Write-Host "  Key: $([BitConverter]::ToString($key).Replace('-',''))"
        Write-Host "-----------------------------------"

        $offset.Value = $entryStart + $entrySize
    }
}

Export-ModuleMember -Function ConvertFrom-DSInternals, New-Keytabs, Format-KeysToString, Read-Keytab
