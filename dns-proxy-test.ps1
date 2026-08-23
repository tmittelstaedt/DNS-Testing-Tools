<#
DNS Transparent Proxy Detection Script
- Supports running dig locally (if dig.exe in current dir) or via SSH to remote host
- Includes 8 tests:
  1. NSID check
  2. RA bit check
  3. Custom EDNS(0) option echo
  4. Large DNSSEC UDP response TC bit (+ignore fix)
  5. Malformed/unusual query
  6. Long-label + private QTYPE stress test
  7. Glue TTL consistency check
  8. Transparent proxy detection via bogus IP & timeouts
#>

# --- Local dig.exe detection ---
$UseLocalDig = $false
$LocalDigPath = Join-Path (Get-Location) "dig.exe"

if (Test-Path $LocalDigPath) {
    Write-Host "Found dig.exe in current directory."
    $choice = Read-Host "Do you want to run the local dig instead of using SSH? (Y/N)"
    if ($choice -match '^[Yy]') {
        $UseLocalDig = $true
        Write-Host "Using local dig.exe for all tests."
    } else {
        Write-Host "Using SSH to run dig on remote host."
    }
}

# --- Prompt for remote host if needed ---
if (-not $UseLocalDig) {
    $RemoteHost = Read-Host "Enter remote SSH host (user@hostname)"
    if ([string]::IsNullOrWhiteSpace($RemoteHost)) {
        Write-Host "No remote host provided. Exiting."
        exit
    }
}

# --- Root server list ---
$rootServers = @(
    @{ Name = "A-root"; IP = "198.41.0.4" },
    @{ Name = "B-root"; IP = "170.247.170.2" },
    @{ Name = "C-root"; IP = "192.33.4.12" },
    @{ Name = "D-root"; IP = "199.7.91.13" },
    @{ Name = "E-root"; IP = "192.203.230.10" },
    @{ Name = "F-root"; IP = "192.5.5.241" },
    @{ Name = "G-root"; IP = "192.112.36.4" },
    @{ Name = "H-root"; IP = "198.97.190.53" },
    @{ Name = "I-root"; IP = "192.36.148.17" },
    @{ Name = "J-root"; IP = "192.58.128.30" },
    @{ Name = "K-root"; IP = "193.0.14.129" },
    @{ Name = "L-root"; IP = "199.7.83.42" },
    @{ Name = "M-root"; IP = "202.12.27.33" }
)

# --- Select root server ---
Write-Host "Select a root server to query for tests 1-7:"
for ($i = 0; $i -lt $rootServers.Count; $i++) {
    Write-Host "[$($i+1)] $($rootServers[$i].Name) ($($rootServers[$i].IP))"
}

$rootChoiceRaw = Read-Host "Enter number"

# Validate input
if ($rootChoiceRaw -notmatch '^\d+$') {
    Write-Host "Invalid choice: not a number." -ForegroundColor Red
    exit
}

$rootChoice = [int]$rootChoiceRaw

if ($rootChoice -lt 1 -or $rootChoice -gt $rootServers.Count) {
    Write-Host "Invalid choice: out of range." -ForegroundColor Red
    exit
}

# If valid, get the selected server
$selected = $rootServers[$rootChoice - 1]
Write-Host "You selected $($selected.Name) with IP $($selected.IP)"

# --- Test definitions ---
function Get-TestDefinition {
    param($testNum)

    $testNum = [int]$testNum  # <--- force numeric match
    switch ($testNum) {
        1 { return @{
                Cmd = "+norecurse +nsid @$($selected.IP) . NS"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    if ($outputText -match "(?i)NSID:") {
                        "PASS: NSID found -> " + ($outputText -split "(?i)NSID:")[1].Trim()
                    } else {
                        "FAIL: No NSID in response"
                    }
                }
            }
        }
        2 { return @{
                Cmd = "+norecurse @$($selected.IP) . NS"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    if ($outputText -match "(?im)flags:.*\bra\b") {
                        "FAIL: RA bit set (transparent proxy likely, by definition root nameservers never set RA bit)"
                    } else {
                        "PASS: RA bit not set (expected)"
                    }
                }
            }
        }
        3 { return @{
                Cmd = "+norecurse +ednsopt=65001:010203 @$($selected.IP) . NS"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    if ($outputText -match "(?i)65001:") {
                        "PASS: Custom EDNS option echoed back"
                    } else {
                        "FAIL: Custom EDNS option missing"
                    }
                }
            }
        }
        4 { return @{
                Cmd = "+norecurse +dnssec +bufsize=512 +ignore @$($selected.IP) . DNSKEY"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    if ($outputText -match "(?i)\bTC\b") {
                        "PASS: TC bit set for large UDP response"
                    } else {
                        "FAIL: TC bit not set"
                    }
                }
            }
        }
        5 { return @{
                Cmd = "+norecurse @$($selected.IP) longMixedCaseLabel.example. TYPE65"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    if ($outputText -match "(?i)NXDOMAIN") {
                        "PASS: Got NXDOMAIN as expected"
                    } else {
                        "FAIL: Unexpected response code"
                    }
                }
            }
        }
        6 { return @{
                Cmd = "+norecurse @$($selected.IP) $(('a'*60) + '.example.') TYPE65534"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    if ($outputText -match "(?i)NXDOMAIN") {
                        "PASS: Got NXDOMAIN as expected"
                    } else {
                        "FAIL: Unexpected response code"
                    }
                }
            }
        }
        7 { return @{
                Cmd = "+norecurse @$($selected.IP) . NS"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    $inAdditional = $false
                    $ttls = @()
                    foreach ($line in ($outputText -split "`n")) {
                        if ($line -match ";; ADDITIONAL SECTION:") {
                            $inAdditional = $true
                            continue
                        }
                        if ($inAdditional -and $line -match "^\S+\s+(\d+)\s+IN\s+(A|AAAA)\s+") {
                            $ttls += [int]$matches[1]
                        }
                        if ($inAdditional -and $line -match "^\s*$") {
                            break
                        }
                    }
                    if ($ttls.Count -eq 0) {
                        "FAIL: No glue A/AAAA records found"
                    }
                    elseif (($ttls | Select-Object -Unique).Count -eq 1) {
                        "PASS: All glue TTLs match ($($ttls[0]) seconds)"
                    }
                    else {
                        "FAIL: Glue TTLs inconsistent -> " + ($ttls -join ", ")
                    }
                }
            }
        }
        8 { return @{
                Cmd = "+norecurse +time=4 +tries=1 @192.0.2.123 . NS"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }
                    if ($outputText -match "(?i)status:") {
                        "FAIL: Transparent proxy likely (got a DNS response from nonexistent IP)"
                    }
                    elseif ($outputText -match "(?i)timed out") {
                        "PASS: No transparent proxy (query to nonexistent IP timed out)"
                    }
                    else {
                        "FAIL: Unexpected output - no Transparent proxy possible"
                    }
                }
            }
        }
        9 { return @{
                Cmd = "+norecurse +time=5 +tries=1 @8.8.8.8 example.com A +https +nsid"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }

                    if ($outputText -match '(?im)^\s*; NSID:') {
                        "PASS: NSID present"
                    }
                    else {
                        "FAIL: NSID not present (possible interception)"
                    }
                }
            }
        }
        10 { return @{
                Cmd = "+norecurse +time=5 +tries=1 @8.8.8.8 example.com A +nsid"
                Parser = {
                    param($outputText)
                    if (-not $outputText) { return "FAIL: No output from dig" }

                    if ($outputText -match '(?im)^\s*; NSID:') {
                        "PASS: NSID present"
                    }
                    else {
                        "FAIL: NSID not present (possible interception)"
                    }
                }
            }
        }
        11 { return @{
                Cmd = $null  # meta-test, no direct dig call
                Parser = {
                    param($nullOutput)  # not used — we run sub-tests ourselves

                    # Helper to run a sub-test and capture both output and parser result
                    function Invoke-SubTest {
                        param($num)
                        $def = Get-TestDefinition $num
                        if (-not $def) { return @("", "FAIL: Missing test definition") }

                        # Run dig via same logic as Run-Test
                        if ([string]::IsNullOrWhiteSpace($def.Cmd)) {
                            $output = ""
                        }
                        elseif ($UseLocalDig) {
                            $cmdParts = $def.Cmd -split ' '
                            $output = & $LocalDigPath @cmdParts 2>&1
                        }
                        else {
                            $sshCmd = "dig $($def.Cmd)"
                            $output = & ssh $RemoteHost $sshCmd 2>&1
                        }

                        # Join into a single string for safe return
                        $outputStr = ($output -join "`n")

                        # Print like Run-Test
                        if ($outputStr) {
                            Write-Host "=== dig Output (Test $num) ==="
                            $outputStr -split "`n" | ForEach-Object { Write-Host $_ }
                        }

                        # Return as a fixed two-element array
                        return @($outputStr, (& $def.Parser $outputStr))
                    }

                    Write-Host "`n--- Running Test 9 (DoH + NSID) ---" -ForegroundColor Cyan
                    $output9, $result9 = Invoke-SubTest 9

                    Write-Host "`n--- Running Test 10 (UDP + NSID) ---" -ForegroundColor Cyan
                    $output10, $result10 = Invoke-SubTest 10

                    # Summary table
                    Write-Host "`n=== Summary ===" -ForegroundColor Yellow
                    $summary = @(
                        [PSCustomObject]@{ Test = "9 (DoH + NSID)"; Result = $result9 }
                        [PSCustomObject]@{ Test = "10 (UDP + NSID)"; Result = $result10 }
                    )

                    foreach ($row in $summary) {
                        if ($row.Result -match '^PASS') {
                            Write-Host ("{0,-20} {1}" -f $row.Test, $row.Result) -ForegroundColor Green
                        }
                        else {
                            Write-Host ("{0,-20} {1}" -f $row.Test, $row.Result) -ForegroundColor Red
                        }
                    }

                    # Final verdict
                    Write-Host "`n=== Verdict ===" -ForegroundColor Yellow
                    if ($result9 -match '^PASS' -and $result10 -match '^FAIL') {
                        return "FAIL: Likely interception (DoH passed, UDP failed)"
                    }
                    elseif ($result9 -match '^PASS' -and $result10 -match '^PASS') {
                        return "PASS: No interception detected"
                    }
                    elseif ($result9 -match '^FAIL' -and $result10 -match '^FAIL') {
                        return "FAIL: DNS resolution broken or blocked"
                    }
                    else {
                        return "FAIL: Inconsistent results (needs manual review)"
                    }
                }
            }
        }
        12 { return @{
                Cmd    = $null   # No prebuilt dig command; parser handles its own queries
                Parser = {
                    param($outputText) # Ignored for this test

                    $results = @()

                    foreach ($srv in $rootServers) {
                        try {
                            if ($UseLocalDig) {
                                # Run dig, capture ALL output as a single string
                                $out = & $LocalDigPath '+norecurse' '+time=5' '+tries=1' "@$($srv.IP)" 'example.com' 'A' 2>&1 | Out-String
                                Start-Sleep -Milliseconds 200  # Prevent socket reuse issues
                            }
                            else {
                                $sshCmd = "dig +norecurse +time=5 +tries=1 @$($srv.IP) example.com A"
                                $out = & ssh $RemoteHost $sshCmd 2>&1 | Out-String
                                Start-Sleep -Milliseconds 200
                            }

                            # Detect complete failure
                            if ($out -match "no servers could be reached") {
                                $results += [PSCustomObject]@{
                                    Server = $srv.Name
                                    IP     = $srv.IP
                                    TimeMs = 'TIMEOUT'
                                }
                                continue
                            }

                            # Match "Query time: <number> msec" regardless of case/spacing
                            $timeLine = $out | Select-String -Pattern '(?i)query\s*time:\s*(\d+)\s*msec'
                            if ($timeLine) {
                                $ms = [int]$timeLine.Matches[0].Groups[1].Value
                                $results += [PSCustomObject]@{
                                    Server = $srv.Name
                                    IP     = $srv.IP
                                    TimeMs = $ms
                                }
                            }
                            else {
                                $results += [PSCustomObject]@{
                                    Server = $srv.Name
                                    IP     = $srv.IP
                                    TimeMs = 'TIMEOUT'
                                }
                            }
                        }
                        catch {
                            $results += [PSCustomObject]@{
                                Server = $srv.Name
                                IP     = $srv.IP
                                TimeMs = 'TIMEOUT'
                            }
                        }
                    }

                    # Sort by time, TIMEOUTs last
                    $tableText = $results |
                        Sort-Object { if ($_.TimeMs -is [int]) { $_.TimeMs } else { [int]::MaxValue } } |
                        Format-Table -AutoSize | Out-String
                    return $tableText + "`nTest complete: DNS root server response times measured."
                }
            }
        }
    }
}

# --- Run test ---
function Run-Test {
    param($testNum)

    $def = Get-TestDefinition $testNum
    if (-not $def) { Write-Host "Invalid test number." ; return }

    Write-Host "Running Test $testNum..."
    try {
        if ([string]::IsNullOrWhiteSpace($def.Cmd)) {
            # Skip dig execution — parser will handle its own queries
            $output = $null
        }
        elseif ($UseLocalDig) {
            $cmdParts = $def.Cmd -split ' '
            $output = & $LocalDigPath @cmdParts 2>&1
        }
        else {
            $sshCmd = "dig $($def.Cmd)"
            $output = & ssh $RemoteHost $sshCmd 2>&1
        }
    }
    catch {
        Write-Host "ERROR: Failed to execute dig command: $_"
        return
    }
    if (-not $output -and -not [string]::IsNullOrWhiteSpace($def.Cmd)) {
        Write-Host "ERROR: No output received from dig."
        return
    }
    if ($output) {
        # Force proper line breaks for Windows console
        $outputLines = $output -split "`n"
        Write-Host "=== dig Output ==="
        foreach ($line in $outputLines) {
            Write-Host $line
        }
    }
    Write-Host "=== Result ==="
    Write-Host (& ($def.Parser) $output)
}

# --- Menu ---
Write-Host "Select DNS test type:"
Write-Host "[1] NSID check"
Write-Host "[2] RA bit check"
Write-Host "[3] Custom EDNS option echo"
Write-Host "[4] Large DNSSEC UDP response TC bit"
Write-Host "[5] Malformed/unusual query"
Write-Host "[6] Long-label + private QTYPE stress test"
Write-Host "[7] Glue TTL consistency check"
Write-Host "[8] Transparent proxy detection via bogus IP and timeout"
Write-Host "[9] Google NSID check for example.com using DoH"
Write-Host "[10] Google NSID check for example.com using regular UDP"
Write-Host "[11] compare DoH query and regular query for example.com"
Write-Host "[12] Build list of query speed responses"
Write-Host "[13] Run tests 1-8 and compare results"


$testChoice = Read-Host "Enter number"

if ($testChoice -notmatch '^\d+$') {
    Write-Host "Invalid choice numeric entry only."
    exit
}

$testChoice = [int]$testChoice 

if ($testChoice -lt 1 -or $testChoice -gt 13) {
    Write-Host "Invalid choice number between 1 and 13."
    exit
}

if ($testChoice -eq 13) {
    # Run all tests in sequence
    $results = @()
    for ($t = 1; $t -le 8; $t++) {
        $def = Get-TestDefinition $t
        Write-Host "Running Test $t..."
        try {
            if ($UseLocalDig) {
                $cmdParts = $def.Cmd -split ' '
                $output = & $LocalDigPath @cmdParts 2>&1
            } else {
                $sshCmd = "dig $($def.Cmd)"
                $output = & ssh $RemoteHost $sshCmd 2>&1
            }
        }
        catch {
            $results += [PSCustomObject]@{ Test = $t; Result = "ERROR: $_" }
            continue
        }
        if (-not $output) {
            $results += [PSCustomObject]@{ Test = $t; Result = "ERROR: No output" }
            continue
        }
        # Force proper line breaks for Windows console
        $outputLines = $output -split "`n"
        foreach ($line in $outputLines) {
            Write-Host $line
        }
        $result = & $def.Parser $output
        $results += [PSCustomObject]@{ Test = $t; Result = $result }
    }
    Write-Host "=== Summary ==="
    $results | Format-Table -AutoSize
}
else {
    # Run single selected test
    Run-Test $testChoice
}
