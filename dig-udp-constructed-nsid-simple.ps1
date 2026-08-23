<#
.SYNOPSIS
    UDP-only DNS NSID diagnostic script (10-second timeout).

.DESCRIPTION
    Sends a UDP DNS query with EDNS0 NSID option to a specified server (IP or hostname)
    and displays the returned NSID (if any). Useful for testing in environments
    where TCP/53 is blocked or intercepted.

.PARAMETER Hostname
    The DNS name to query (e.g., "." for root).

.PARAMETER DnsServer
    The DNS server to query (IP address or hostname).

.EXAMPLE
    .\dig-udp.ps1 -Hostname "." -DnsServer "145.100.185.15"
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Hostname,

    [Parameter(Mandatory = $true)]
    [string]$DnsServer
)

# Resolve hostname to IPv4 if needed
try {
    if ([System.Net.IPAddress]::TryParse($DnsServer, [ref]([System.Net.IPAddress]$null))) {
        $DnsServerIP = $DnsServer
    }
    else {
        $resolved = [System.Net.Dns]::GetHostAddresses($DnsServer) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1
        if (-not $resolved) { throw "Could not resolve $DnsServer to an IPv4 address." }
        $DnsServerIP = $resolved.IPAddressToString
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

function Get-NSID-UDP {
    param (
        [string]$Server,
        [string]$QueryName
    )

    try {
        $transactionId = Get-Random -Minimum 0 -Maximum 65535
        $packet = New-Object System.Collections.Generic.List[byte]
        $packet.AddRange([byte[]]([BitConverter]::GetBytes([UInt16]$transactionId)[1..0]))
        $packet.AddRange([byte[]](0x01,0x00)) # Flags
        $packet.AddRange([byte[]](0x00,0x01)) # QDCOUNT
        $packet.AddRange([byte[]](0x00,0x00)) # ANCOUNT
        $packet.AddRange([byte[]](0x00,0x00)) # NSCOUNT
        $packet.AddRange([byte[]](0x00,0x01)) # ARCOUNT

        foreach ($label in $QueryName.TrimEnd('.').Split('.')) {
            $packet.Add([byte]$label.Length)
            $packet.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
        }
        $packet.Add(0x00) # End of QNAME

        # QTYPE = NS
        $packet.AddRange([byte[]](0x00,0x02))
        # QCLASS = IN
        $packet.AddRange([byte[]](0x00,0x01))

        # OPT record for EDNS0 NSID
        $packet.Add(0x00) # Name root
        $packet.AddRange([byte[]](0x00,0x29)) # TYPE = OPT
        $packet.AddRange([byte[]](0x10,0x00)) # UDP payload size
        $packet.Add(0x00)       # Higher bits of extended RCODE
        $packet.Add(0x00)       # EDNS0 version
        $packet.AddRange([byte[]](0x00,0x00))  # Z flags
        $packet.AddRange([byte[]](0x00,0x06))  # Data length
        $packet.AddRange([byte[]](0x00,0x03))  # Option code = NSID
        $packet.AddRange([byte[]](0x00,0x00))  # Option length = 0

        $bytesToSend = $packet.ToArray()

        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 10000   # 10-second timeout
        $udp.Connect($Server, 53)
        $udp.Send($bytesToSend, $bytesToSend.Length) | Out-Null
        $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref]$remoteEP)
        $udp.Close()

        $respList = [System.Collections.Generic.List[byte]]::new()
        $respList.AddRange($response)
        $respBytes = $respList.ToArray()

        # Parse for NSID
        for ($i = 12; $i -lt $respBytes.Length - 10; $i++) {
            if ($respBytes[$i] -eq 0x00 -and $respBytes[$i+1] -eq 0x00 -and $respBytes[$i+2] -eq 0x29) {
                $rdLen = ($respBytes[$i+8] -shl 8) -bor $respBytes[$i+9]
                $optStart = $i + 10
                while ($optStart -lt $i + 10 + $rdLen) {
                    $optCode = ($respBytes[$optStart] -shl 8) -bor $respBytes[$optStart+1]
                    $optLen  = ($respBytes[$optStart+2] -shl 8) -bor $respBytes[$optStart+3]
                    if ($optCode -eq 3) {
                        return [System.Text.Encoding]::ASCII.GetString($respBytes[($optStart+4)..($optStart+3+$optLen)])
                    }
                    $optStart += 4 + $optLen
                }
            }
        }
        return "<No NSID found>"
    }
    catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

Write-Host "Querying $Hostname for NSID from $DnsServerIP over UDP..." -ForegroundColor Cyan
$udpNsid = Get-NSID-UDP -Server $DnsServerIP -QueryName $Hostname
Write-Host "`n=== UDP Result ===" -ForegroundColor Green
Write-Host ("UDP NSID: {0}" -f $udpNsid) -ForegroundColor Yellow
