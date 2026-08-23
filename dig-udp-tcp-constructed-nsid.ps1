<#
.SYNOPSIS
    DNS NSID Retrieval and Transparent Proxy Detection (Hostname-Aware)

.DESCRIPTION
    Sends DNS queries with EDNS0 NSID option over both UDP and TCP to detect
    if a transparent proxy is intercepting UDP/53 traffic.
    Accepts either an IP address or a hostname for the DNS server.

.PARAMETER Hostname
    The DNS name to query.

.PARAMETER DnsServer
    The DNS server to query (IP address or hostname).

.EXAMPLE
    .\dig.ps1 -Hostname "." -DnsServer "145.100.185.15"
    .\dig.ps1 -Hostname "." -DnsServer "nsidtest.sinodun.com"
#>

param (
[Parameter(Mandatory = $true)]
[string]$Hostname,
[Parameter(Mandatory = $true)]
[string]$RecordType,
[Parameter(Mandatory = $true)]
[string]$DnsServer,
[switch]$NSID
)

function Skip-DnsName {
    param([byte[]]$Data, [int]$Offset)
    while ($Data[$Offset] -ne 0) {
        if (($Data[$Offset] -band 0xC0) -eq 0xC0) { return ($Offset + 2) }
        $Offset += $Data[$Offset] + 1
    }
    return ($Offset + 1)
}

function Build-NsidQueryPacket {
    param ($QueryName)
    $transactionId = Get-Random -Minimum 0 -Maximum 65535
    $flags = 0x0100
    $header = [byte[]]@(
    [byte](($transactionId -shr 8) -band 0xFF),
    [byte]($transactionId -band 0xFF),
    [byte](($flags -shr 8) -band 0xFF),
    [byte]($flags -band 0xFF),
    0,1, 0,0, 0,0, 0,1
    )
    $qnameBytes = New-Object System.Collections.Generic.List[byte]
    foreach ($label in $QueryName.Split('.')) {
        if ($label.Length -gt 0) {
            $qnameBytes.Add([byte]$label.Length)
            $qnameBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
        }
    }
    $qnameBytes.Add(0)
    $question = [byte[]]($qnameBytes.ToArray() + @(0,1, 0,1))
    $optRecord = [byte[]]@(0, 0,41, 16,0, 0,0, 0,0, 0,4, 0,3, 0,0)
    return ,($header + $question + $optRecord)
}

function Parse-NsidFromResponse {
    param ([byte[]]$Response)
    $ancount = ($Response[6] -shl 8) -bor $Response[7]
    $nscount = ($Response[8] -shl 8) -bor $Response[9]
    $arcount = ($Response[10] -shl 8) -bor $Response[11]
    $offset = Skip-DnsName $Response 12
    $offset += 4
    $sections = $ancount + $nscount
    for ($i = 0; $i -lt $sections; $i++) {
        $offset = Skip-DnsName $Response $offset
        $offset += 8
        $rdlen = ($Response[$offset] -shl 8) -bor $Response[$offset+1]
        $offset += 2 + $rdlen
    }
    for ($i = 0; $i -lt $arcount; $i++) {
        $offset = Skip-DnsName $Response $offset
        $type = ($Response[$offset] -shl 8) -bor $Response[$offset+1]
        $offset += 8
        $rdLength = ($Response[$offset] -shl 8) -bor $Response[$offset+1]
        $offset += 2
        if ($type -eq 41) {
            $optOffset = $offset
            while ($optOffset -lt ($offset + $rdLength)) {
                $optCode = ($Response[$optOffset] -shl 8) -bor $Response[$optOffset+1]
                $optOffset += 2
                $optLen = ($Response[$optOffset] -shl 8) -bor $Response[$optOffset+1]
                $optOffset += 2
                if ($optCode -eq 3) {
                    return [System.Text.Encoding]::ASCII.GetString(
                    $Response[$optOffset..($optOffset + $optLen - 1)])
                    }
                $optOffset += $optLen
                }
            }
            $offset += $rdLength
        }
    return $null
}

function Get-NSID-UDP {
    param ($Server, $Packet)
    try {
        $udpClient = [System.Net.Sockets.UdpClient]::new()
        Write-Host "NSID try over UDP..." -ForegroundColor Yellow
        $udpClient.Client.ReceiveTimeout = 3000
        $udpClient.Connect($Server, 53)
        $udpClient.Send($Packet, $Packet.Length) | Out-Null
        $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $response = $udpClient.Receive([ref]$remoteEP)
        $udpClient.Close()
        return Parse-NsidFromResponse -Response $response
    }
catch { return $null }
}

function Get-NSID-TCP {
    param ($Server, $Packet)
    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new($Server, 53)
        Write-Host "NSID try over TCP..." -ForegroundColor Yellow
        $stream = $tcpClient.GetStream()
        $lengthPrefix = [byte[]]@(
        [byte](($Packet.Length -shr 8) -band 0xFF),
        [byte]($Packet.Length -band 0xFF)
        )
        $stream.Write($lengthPrefix, 0, 2)
        $stream.Write($Packet, 0, $Packet.Length)
        $lenBuf = New-Object byte[] 2
        $stream.Read($lenBuf, 0, 2) | Out-Null
        $respLen = ($lenBuf[0] -shl 8) -bor $lenBuf[1]
        $response = New-Object byte[] $respLen
        $stream.Read($response, 0, $respLen) | Out-Null
        $tcpClient.Close()
        return Parse-NsidFromResponse -Response $response
    }
catch { return $null }
}

function Get-NSID {
    param ($Server, $QueryName)
    $packet = Build-NsidQueryPacket -QueryName $QueryName
    $nsid = Get-NSID-UDP -Server $Server -Packet $packet
    if ($nsid) { return "NSID: $nsid" }
    Write-Host "No NSID via UDP  retrying over TCP..." -ForegroundColor Yellow
    $nsid = Get-NSID-TCP -Server $Server -Packet $packet
    if ($nsid) { return "NSID: $nsid" }
    return "No NSID option found (server may have stripped it)."
}

# -------------------------------
# Main execution
# -------------------------------
Write-Host "Using custom DNS server: $DnsServer"
Write-Host "Querying DNS for $Hostname ($RecordType)..."
Write-Host ""

try {
    $result = Resolve-DnsName -Name $Hostname -Type $RecordType -Server $DnsServer -ErrorAction Stop
    if ($result) {
        Write-Host "=== Answer Section ===" -ForegroundColor Cyan
        $result | Format-Table Name, Type, TTL, IPAddress, NameHost -AutoSize
            }
            else {
            Write-Host "No records returned." -ForegroundColor Yellow
            }
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    if ($NSID) {
        Write-Host ""
        Write-Host "=== NSID Information ===" -ForegroundColor Cyan
        $nsidResult = Get-NSID -Server $DnsServer -QueryName $Hostname
        Write-Host $nsidResult
}

Write-Host ""
Write-Host "Query complete." -ForegroundColor Green




