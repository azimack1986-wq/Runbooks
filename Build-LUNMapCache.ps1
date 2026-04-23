#Requires -Version 7.0
<#
.SYNOPSIS
    Builds a persistent LUN map cache by scanning every host in every cluster
    across all configured vCenters.

.DESCRIPTION
    Connects to each vCenter, retrieves cluster and host topology, then runs a
    parallel scan (one job per cluster) across all connected hosts. Collects
    CanonicalName (NAA), UUID, LUN ID, and SAN ID for every SAN disk LUN visible
    to every host.

    Deduplicates by CanonicalName — each unique LUN is stored once regardless of
    how many hosts or clusters can see it. Existing cache entries are preserved;
    only LastSeen is updated for entries already present. New entries are appended.

    Cache is written to disk after each cluster merges, so a failure mid-run
    preserves all data collected up to that point.

    Run once initially, then periodically or after storage changes. The main
    inventory script consumes this cache at runtime instead of scanning hosts.

.PARAMETER OutputPath
    UNC or local path where LUNMap_Cache.json will be written.

.EXAMPLE
    .\Build-LUNMapCache.ps1 -OutputPath "\\server\share\VMInventory"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$OutputPath
)

# ══ CONFIGURATION ════════════════════════════════════════════════════════════
$vCenterServers = @(
    'vcenter01.domain.local'
    'vcenter02.domain.local'
    'vcenter03.domain.local'
)
$ThrottleLimit = 10   # Max parallel cluster scan jobs
# ═════════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = 'Stop'

$CachePath = Join-Path $OutputPath 'LUNMap_Cache.json'

# ── Load existing cache ───────────────────────────────────────────────────────
$lunCache = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

if (Test-Path $CachePath) {
    Write-Host "Loading existing LUN cache..."
    try {
        $existing = Get-Content $CachePath -Raw | ConvertFrom-Json
        foreach ($prop in $existing.PSObject.Properties) {
            $lunCache[$prop.Name] = @{
                LunId    = $prop.Value.LunId
                SanId    = $prop.Value.SanId
                Uuid     = $prop.Value.Uuid
                vCenter  = $prop.Value.vCenter
                LastSeen = $prop.Value.LastSeen
            }
        }
        Write-Host "  [$($lunCache.Count)] existing entries loaded"
    } catch {
        Write-Host "  Warning: could not load existing cache — starting fresh: $($_.Exception.Message)"
    }
} else {
    Write-Host "No existing cache found — building from scratch"
}

# ── Credentials ───────────────────────────────────────────────────────────────
$credential = Get-Credential -Message "Enter vCenter credentials"

# ── Per-vCenter loop ──────────────────────────────────────────────────────────
foreach ($vcServer in $vCenterServers) {

    Write-Host "`n$(('═' * 60))"
    Write-Host "  $vcServer"
    Write-Host "$(('═' * 60))"

    # ── Connect and retrieve topology ─────────────────────────────────────────
    $clusterScanList = $null

    try {
        Write-Host "Connecting to retrieve cluster/host topology..."
        $mainConn = Connect-VIServer -Server $vcServer -Credential $credential -ErrorAction Stop

        $clusterHostMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

        # Clusters and their connected hosts
        Write-Host "  Retrieving clusters..."
        Get-View -ViewType ClusterComputeResource -Property @('Name', 'Host') -ErrorAction SilentlyContinue |
            ForEach-Object {
                $clName         = $_.Name
                $connectedHosts = [System.Collections.Generic.List[string]]::new()
                foreach ($hostRef in $_.Host) {
                    $hView = Get-View -Id $hostRef -Property @('Name', 'Runtime') -ErrorAction SilentlyContinue
                    if ($hView -and $hView.Runtime.ConnectionState -eq 'connected') {
                        $connectedHosts.Add($hView.Name)
                    }
                }
                if ($connectedHosts.Count -gt 0) {
                    $clusterHostMap[$clName] = $connectedHosts
                }
            }

        # Standalone hosts (not in a cluster)
        Write-Host "  Retrieving standalone hosts..."
        Get-View -ViewType HostSystem -Property @('Name', 'Runtime', 'Parent') -ErrorAction SilentlyContinue |
            Where-Object { $_.Parent.Type -ne 'ClusterComputeResource' -and $_.Runtime.ConnectionState -eq 'connected' } |
            ForEach-Object {
                $clusterHostMap["__standalone__$($_.Name)"] = [System.Collections.Generic.List[string]]@($_.Name)
            }

        $totalHosts = ($clusterHostMap.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        Write-Host "  [$($clusterHostMap.Count)] clusters/standalone hosts — [$totalHosts] total connected hosts"

        Disconnect-VIServer -Server $mainConn -Confirm:$false -ErrorAction SilentlyContinue

        # Convert to list of PSCustomObjects for safe parallel serialisation
        $clusterScanList = @($clusterHostMap.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                ClusterKey = $_.Key
                Hosts      = @($_.Value)
            }
        })

    } catch {
        Write-Host "  ERROR: $($_.Exception.Message) — skipping $vcServer"
        continue
    }

    # ── Parallel LUN scan ─────────────────────────────────────────────────────
    Write-Host "`nStarting parallel LUN scan (ThrottleLimit=$ThrottleLimit)..."

    $scanResults = $clusterScanList | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {

        Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue

        $clKey     = $_.ClusterKey
        $hostNames = $_.Hosts
        $vcServer  = $using:vcServer
        $cred      = $using:credential

        $lunEntries = [System.Collections.Generic.List[object]]::new()

        # Stagger connections to avoid recentserverlist.xml contention
        Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 2000)

        $localServer = $null
        try {
            Write-Host "  [SCAN] $clKey — connecting..."
            $localServer = Connect-VIServer -Server $vcServer -Credential $cred -NotDefault -ErrorAction Stop

            foreach ($hostName in $hostNames) {

                if (-not (Test-Connection -TargetName $hostName -Count 1 -TimeoutSeconds 2 -Quiet)) {
                    Write-Host "  [SCAN] $clKey — $hostName unreachable (ping), skipping"
                    continue
                }

                Write-Host "  [SCAN] $clKey — scanning $hostName..."
                try {
                    $hostObj = Get-VMHost -Name $hostName -Server $localServer -ErrorAction Stop
                    $allLuns = @(Get-ScsiLun -VMHost $hostObj -LunType disk -Server $localServer -ErrorAction Stop)
                    $sanLuns = @($allLuns | Where-Object { $_.CanonicalName -like 'naa.*' })

                    if ($sanLuns.Count -eq 0) {
                        Write-Host "  [SCAN] $clKey — $hostName : no SAN LUNs found"
                        continue
                    }

                    # SAN ID lookup from LUN paths
                    $sanIdMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
                    $lunPaths = @(Get-ScsiLunPath -ScsiLun $sanLuns -ErrorAction SilentlyContinue)
                    foreach ($path in $lunPaths) {
                        $cn = $path.ScsiLun?.CanonicalName
                        if ($cn -and $path.SanId -and -not $sanIdMap.ContainsKey($cn)) {
                            $sanIdMap[$cn] = $path.SanId
                        }
                    }

                    foreach ($lun in $sanLuns) {
                        $lunId = $null
                        if ($lun.RuntimeName -match ':L(\d+)$') { $lunId = [int]$Matches[1] }

                        $lunEntries.Add([PSCustomObject]@{
                            CanonicalName = $lun.CanonicalName
                            Uuid          = $lun.Uuid
                            LunId         = $lunId
                            SanId         = $sanIdMap[$lun.CanonicalName]
                        })
                    }

                    Write-Host "  [SCAN] $clKey — $hostName : $($sanLuns.Count) SAN LUNs"

                } catch {
                    Write-Host "  [SCAN] $clKey — $hostName error: $($_.Exception.Message)"
                }
            }

        } finally {
            if ($localServer) {
                try { Disconnect-VIServer -Server $localServer -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            }
        }

        [PSCustomObject]@{
            ClusterKey  = $clKey
            LunEntries  = $lunEntries
        }
    }

    # ── Merge results and write incrementally ─────────────────────────────────
    Write-Host "`nMerging results..."

    $today        = Get-Date -Format 'yyyy-MM-dd'
    $vcNewEntries = 0
    $vcUpdated    = 0

    foreach ($result in $scanResults) {
        $added = 0

        foreach ($entry in $result.LunEntries) {
            if (-not $lunCache.ContainsKey($entry.CanonicalName)) {
                $lunCache[$entry.CanonicalName] = @{
                    LunId    = $entry.LunId
                    SanId    = $entry.SanId
                    Uuid     = $entry.Uuid
                    vCenter  = $vcServer
                    LastSeen = $today
                }
                $added++
                $vcNewEntries++
            } else {
                $lunCache[$entry.CanonicalName].LastSeen = $today
                $vcUpdated++
            }
        }

        Write-Host "  [MERGED] $($result.ClusterKey): +$added new ($($result.LunEntries.Count) scanned)"

        # Incremental write after each cluster
        try {
            $lunCache | ConvertTo-Json -Depth 3 | Set-Content $CachePath -Encoding UTF8
        } catch {
            Write-Host "  Warning: cache write failed: $($_.Exception.Message)"
        }
    }

    Write-Host "`n  $vcServer complete — $vcNewEntries new entries, $vcUpdated updated"
}

# ── Final summary ─────────────────────────────────────────────────────────────
Write-Host "`n$(('═' * 60))"
Write-Host "  Cache build complete"
Write-Host "  Total entries : [$($lunCache.Count)]"
Write-Host "  Written to    : $CachePath"
Write-Host "$(('═' * 60))"
