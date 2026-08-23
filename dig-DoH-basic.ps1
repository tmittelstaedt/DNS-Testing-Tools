<#
.SYNOPSIS
    Query root NS records via DNS over HTTPS (DoH) and request NSID.

.DESCRIPTION
    Sends a raw DNS query with EDNS0 NSID option to either Cloudflare or Google
    over HTTPS, parses the binary DNS response, and extracts the NSID if present.

.PARAMETER Provider
    "cloudflare" or "google"

.EXAMPLE
    .\Get-NSID-DoH.ps1 -Provider cloudflare
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("cloudflare", "google")]
    [string]$Provider
)

# Map provider to DoH endpoint
switch ($Provider) {
    "cloudflare" { $dohUrl = "https://cloudflare-dns.com/dns-query" }
    "google"     { $dohUrl = "https://dns.google/dns-query" }
}

# Build DNS query for "." NS with EDNS0 NSID option
function Build-DnsQuery {
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
        [byte](($qdCount -shr 8) -band 0xFF), [byte]($qdCount -band 0xFF),
        [byte](($anCount -shr 8) -band 0xFF), [byte]($anCount -band 0xFF),
        [byte](($nsCount -shr 8) -band 0xFF), [byte]($nsCount -band 0xFF),
        [byte](($arCount -shr 8) -band 0xFF), [byte]($arCount -band 0xFF)
    )

    # QNAME for "."
    $qname = 0
    $qtype = 2  # NS
    $qclass = 1 # IN
    $question = [byte[]]@(
        $qname,
        [byte](($qtype -shr 8) -band 0xFF), [byte]($qtype -band 0xFF),
        [byte](($qclass -shr 8) -band 0xFF), [byte]($qclass -band 0xFF)
    )

    # OPT record with NSID option
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

    return $header + $question + $optRecord
}

# Send DoH request
try {
    $dnsQuery = Build-DnsQuery
    $headers = @{ "Content-Type" = "application/dns-message" }
    $response = Invoke-WebRequest -Uri $dohUrl -Method POST -Headers $headers -Body $dnsQuery -UseBasicParsing
    $bytes = $response.Content

    # Parse NSID from binary DNS message
    $nsidAscii = $null
    for ($i = 0; $i -lt ($bytes.Length - 2); $i++) {
        if ($bytes[$i] -eq 0x00 -and $bytes[$i+1] -eq 0x00 -and $bytes[$i+2] -eq 0x29) {
            $optStart = $i + 11
            while ($optStart -lt $bytes.Length - 4) {
                $optCode = ($bytes[$optStart] -shl 8) -bor $bytes[$optStart+1]
                $optLen  = ($bytes[$optStart+2] -shl 8) -bor $bytes[$optStart+3]
                if ($optCode -eq 3) {
                    $nsidData = $bytes[($optStart+4)..($optStart+3+$optLen)]
                    $nsidAscii = -join ($nsidData | ForEach-Object {
                        if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
                    })
                    break
                }
                $optStart += 4 + $optLen
            }
            break
        }
    }

    Write-Host "=== NSID over DoH ($Provider) ==="
    if ($nsidAscii) {
        Write-Host "NSID: $nsidAscii"
    } else {
        Write-Host "No NSID data found in DoH response."
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}
