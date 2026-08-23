<#
.SYNOPSIS
    DNS record lookup script. Uses PowerShell library calls for everything else, uses constructed packet and raw UDP sockets for NSID.

.DESCRIPTION
    Queries DNS for a given hostname and record type, displaying
    Answer, Authority, and Additional sections separately.
    Can use a custom DNS server if specified.
    If -NSID is set, sends an EDNS0 NSID request and displays the result.

.PARAMETER Hostname
    The hostname or domain to query.

.PARAMETER RecordType
    The DNS record type to query (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, ANY).

.PARAMETER DnsServer
    Optional. IP address of the DNS server to query instead of the system default.

.PARAMETER NSID
    Switch. If set, requests the Name Server Identifier via EDNS0.

.EXAMPLE
    .\DnsLookup.ps1 -Hostname "example.com" -RecordType "A" -DnsServer "8.8.8.8" -NSID
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Hostname,

    [ValidateSet("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "ANY")]
    [string]$RecordType = "A",

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^(?:\d{1,3}\.){3}\d{1,3}$')]
    [string]$DnsServer,

    [switch]$NSID
)

function Get-NSID {
    param (
        [string]$Server,
        [string]$QueryName
    )

    try {
        $udpClient = [System.Net.Sockets.UdpClient]::new()
        $udpClient.Client.ReceiveTimeout = 3000
        $udpClient.Connect($Server, 53)

        # Build DNS header
        $transactionId = Get-Random -Minimum 0 -Maximum 65535
        $flags = 0x0100
        $qdCount = 1
        $anCount = 0
        $nsCount = 0
        $arCount = 1

        $header = [byte[]]@(
            [byte](($transactionId -shr 8) -band 0xFF),
            [byte]($transactionId -band 0xFF),
            [byte](($flags -shr 8) -band 0xFF),
            [byte]($flags -band 0xFF),
            [byte](($qdCount -shr 8) -band 0xFF),
            [byte]($qdCount -band 0xFF),
            [byte](($anCount -shr 8) -band 0xFF),
            [byte]($anCount -band 0xFF),
            [byte](($nsCount -shr 8) -band 0xFF),
            [byte]($nsCount -band 0xFF),
            [byte](($arCount -shr 8) -band 0xFF),
            [byte]($arCount -band 0xFF)
        )

        # Encode QNAME
        $qnameBytes = New-Object System.Collections.Generic.List[byte]
        foreach ($label in $QueryName.Split('.')) {
            $qnameBytes.Add([byte]$label.Length)
            $qnameBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
        }
        $qnameBytes.Add(0)

        # QTYPE and QCLASS
        $qtype = 1
        $qclass = 1
        $question = [byte[]]($qnameBytes.ToArray() + @(
            [byte](($qtype -shr 8) -band 0xFF), [byte]($qtype -band 0xFF),
            [byte](($qclass -shr 8) -band 0xFF), [byte]($qclass -band 0xFF)
        ))

        # EDNS0 OPT record with NSID option
        $optName = 0
        $optType = 41
        $udpPayloadSize = 4096
        $extendedRcode = 0
        $ednsVersion = 0
        $zFlags = 0
        $rdLength = 4
        $nsidOptionCode = 3
        $nsidOptionLength = 0

        $optRecord = [byte[]]@(
            [byte]$optName,
            [byte](($optType -shr 8) -band 0xFF), [byte]($optType -band 0xFF),
            [byte](($udpPayloadSize -shr 8) -band 0xFF), [byte]($udpPayloadSize -band 0xFF),
            [byte]$extendedRcode, [byte]$ednsVersion,
            [byte](($zFlags -shr 8) -band 0xFF), [byte]($zFlags -band 0xFF),
            [byte](($rdLength -shr 8) -band 0xFF), [byte]($rdLength -band 0xFF),
            [byte](($nsidOptionCode -shr 8) -band 0xFF), [byte]($nsidOptionCode -band 0xFF),
            [byte](($nsidOptionLength -shr 8) -band 0xFF), [byte]($nsidOptionLength -band 0xFF)
        )

        # Combine packet
        $packet = $header + $question + $optRecord
        $udpClient.Send($packet, $packet.Length) | Out-Null

        $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $response = $udpClient.Receive([ref]$remoteEP)

        # Raw hex and ASCII of entire response
        $hex = ($response | ForEach-Object { $_.ToString("X2") }) -join " "
        $ascii = -join ($response | ForEach-Object {
            if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
        })

        # Variables for OPT record and NSID
        $nsidAscii = $null
        $isValidNsid = $false
        $optRecordHex = $null
        $optRecordAscii = $null

        try {
            $bytes = [System.Collections.Generic.List[byte]]::new()
            $bytes.AddRange($response)

            # Find start of OPT record (type 41)
            for ($i = 0; $i -lt ($bytes.Count - 2); $i++) {
                if ($bytes[$i] -eq 0x00 -and $bytes[$i+1] -eq 0x00 -and $bytes[$i+2] -eq 0x29) {
                    # Found OPT RR, extract until end of packet
                    $optRecordBytes = $bytes.GetRange($i, $bytes.Count - $i).ToArray()
                    $optRecordHex = ($optRecordBytes | ForEach-Object { $_.ToString("X2") }) -join " "
                    $optRecordAscii = -join ($optRecordBytes | ForEach-Object {
                        if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
                    })

                    # Skip fixed fields (11 bytes after type)
                    $optStart = $i + 11
                    while ($optStart -lt $bytes.Count - 4) {
                        $optCode = ($bytes[$optStart] -shl 8) -bor $bytes[$optStart+1]
                        $optLen  = ($bytes[$optStart+2] -shl 8) -bor $bytes[$optStart+3]
                        if ($optCode -eq 3) {
                            # NSID option found
                            $nsidData = $bytes.GetRange($optStart+4, $optLen).ToArray()
                            $nsidAscii = -join ($nsidData | ForEach-Object {
                                if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
                            })
                            $isValidNsid = ($nsidAscii -notmatch '\.')
                            break
                        }
                        $optStart += 4 + $optLen
                    }
                    break
                }
            }
        }
        catch {
            $nsidAscii = $null
        }

        # Build output
        $outputLines = @()
        $outputLines += "Raw NSID Response (hex): $hex"
        $outputLines += "Raw NSID Response (ASCII): $ascii"
        if ($optRecordHex) {
            $outputLines += "OPT Record (hex): $optRecordHex"
            $outputLines += "OPT Record (ASCII): $optRecordAscii"
        }
        if ($nsidAscii) {
            $outputLines += "Decoded NSID (ASCII): $nsidAscii"
            if ($isValidNsid) {
                $outputLines += "NSID appears valid."
            } else {
                $outputLines += "NSID contains non-printable characters."
            }
        } else {
            $outputLines += "No NSID data found in response."
        }

        return $outputLines -join "`n"
    }
    catch {
        return "Failed to retrieve NSID: $($_.Exception.Message)"
    }
}
try {
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        throw "Resolve-DnsName is not available on this system."
    }

    $queryParams = @{
        Name        = $Hostname
        Type        = $RecordType
        ErrorAction = 'Stop'
    }
    if ($DnsServer) {
        $queryParams['Server'] = $DnsServer
        Write-Host "Using custom DNS server: $DnsServer" -ForegroundColor Yellow
    }

    Write-Host "Querying DNS for $Hostname ($RecordType)..." -ForegroundColor Cyan

    # Perform the DNS query
    $results = Resolve-DnsName @queryParams

    # Separate sections
    $answerSection     = $results | Where-Object { $_.Section -eq "Answer" }
    $authoritySection  = $results | Where-Object { $_.Section -eq "Authority" }
    $additionalSection = $results | Where-Object { $_.Section -eq "Additional" }

    # === Answer Section ===
    Write-Host "`n=== Answer Section ===" -ForegroundColor Green
    if ($answerSection) {
        $answerSection | Select-Object Name, Type, TTL, NameHost, IPAddress, Strings | Format-Table -AutoSize
    } else {
        Write-Host "No answer records found." -ForegroundColor Yellow
    }

    # === Authority Section ===
    Write-Host "`n=== Authority Section ===" -ForegroundColor Cyan
    if ($authoritySection) {
        $authoritySection | Select-Object Name, Type, TTL, NameHost | Format-Table -AutoSize
    } else {
        Write-Host "No authority records found." -ForegroundColor Yellow
    }

    # === Additional Section ===
    Write-Host "`n=== Additional Section (Glue Data) ===" -ForegroundColor Magenta
    if ($additionalSection) {
        $additionalSection | Select-Object Name, Type, TTL, IPAddress | Format-Table -AutoSize
    } else {
        Write-Host "No additional/glue records found." -ForegroundColor Yellow
    }

    # === NSID Section (if requested) ===
    if ($NSID) {
        if (-not $DnsServer) {
            Write-Host "`n[!] NSID requires -DnsServer to be specified." -ForegroundColor Red
        } else {
            Write-Host "`n=== NSID Information ===" -ForegroundColor DarkCyan
            $nsidResult = Get-NSID -Server $DnsServer -QueryName $Hostname
            Write-Host $nsidResult -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}





