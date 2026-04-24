#Requires -Version 7.0
<#
.SYNOPSIS
    Builds a persistent LUN map cache by scanning representative hosts per cluster.

.DESCRIPTION
    For each cluster across all configured vCenters:

    1. Performs a single batch View call to retrieve the SAN device count for every
       connected host. No individual host connections at this stage.

    2. Groups hosts by device count. Hosts with the same count share identical LUN
       visibility — only one representative per unique count is scanned.

    3. Checks if all NAAs for the representative are already in today's cache.
       If so, the cluster is skipped entirely (resume support).

    4. Scans selected representatives in parallel (ThrottleLimit) using
       Get-ScsiLun and Get-ScsiLunPath to collect LUN ID and SAN ID.

    5. Merges results and writes cache to disk immediately after each cluster.
       If the session is interrupted, all completed clusters are preserved and
       skipped on the next run.

    UUID data is pulled from the View API per host (more reliable than
    Get-ScsiLun.Uuid) and stored in the cache for future bridge use.

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
$ThrottleLimit = 10   # Max parallel representative host scans per cluster
# ═════════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = 'Stop'

$CachePath = Join-Path $OutputPath 'LUNMap_Cache.json'
$today     = Get-Date -Format 'yyyy-MM-dd'

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

    try {
        Write-Host "Connecting..."
        $mainConn = Connect-VIServer -Server $vcServer -Credential $credential -ErrorAction Stop

        # ── Build scan unit list (clusters + standalone hosts) ────────────────
        Write-Host "Retrieving topology..."
        $scanUnits = [System.Collections.Generic.List[object]]::new()

        Get-View -ViewType ClusterComputeResource -Property @('Name', 'Host') -ErrorAction SilentlyContinue |
            ForEach-Object {
                $scanUnits.Add([PSCustomObject]@{
                    Label   = $_.Name
                    HostIds = @($_.Host)
                })
            }

        Get-View -ViewType HostSystem -Property @('Name', 'Runtime.ConnectionState', 'Parent') -ErrorAction SilentlyContinue |
            Where-Object { $_.Parent.Type -ne 'ClusterComputeResource' -and $_.Runtime.ConnectionState -eq 'connected' } |
            ForEach-Object {
                $scanUnits.Add([PSCustomObject]@{
                    Label   = "__standalone__$($_.Name)"
                    HostIds = @($_.MoRef)
                })
            }

        Write-Host "  [$($scanUnits.Count)] clusters/standalone hosts to process"

        # ── Sequential cluster loop ───────────────────────────────────────────
        $unitIndex    = 0
        $vcNewEntries = 0

        foreach ($unit in $scanUnits) {
            $unitIndex++
            $label = $unit.Label
            Write-Host "`n  [$unitIndex/$($scanUnits.Count)] $label"

            # ── Step 1: Batch View call — device count + NAAs + UUID per host ─
            $hostProfiles = [System.Collections.Generic.List[object]]::new()

            foreach ($hostId in $unit.HostIds) {
                $hView = Get-View -Id $hostId `
                    -Property @('Name', 'Runtime.ConnectionState', 'Config.StorageDevice.ScsiLun') `
                    -ErrorAction SilentlyContinue
                if (-not $hView -or $hView.Runtime.ConnectionState -ne 'connected') { continue }

                $sanLunViews = @($hView.Config.StorageDevice.ScsiLun | Where-Object {
                    $_.CanonicalName -like 'naa.*' -and $_.LunType -eq 'disk'
                })

                $hostProfiles.Add([PSCustomObject]@{
                    Name         = $hView.Name
                    DeviceCount  = $sanLunViews.Count
                    LunViewItems = $sanLunViews
                })
            }

            if ($hostProfiles.Count -eq 0) {
                Write-Host "    No connected hosts — skipping"
                continue
            }

            Write-Host "    [$($hostProfiles.Count)] connected hosts"

            # ── Step 2: Group by device count ─────────────────────────────────
            $countGroups = $hostProfiles | Group-Object DeviceCount | Sort-Object { [int]$_.Name }
            $groupSummary = $countGroups | ForEach-Object { "$($_.Name) LUNs x$($_.Count) host(s)" }
            Write-Host "    Groups: $($groupSummary -join ' | ')"

            # ── Step 3: Resume check ──────────────────────────────────────────
            # Use the largest group's representative — if all its NAAs are in today's cache, skip
            $largestGroup   = $countGroups | Sort-Object { $_.Count } -Descending | Select-Object -First 1
            $largestGroupRep = $largestGroup.Group[0]
            $repNaas        = @($largestGroupRep.LunViewItems | Select-Object -ExpandProperty CanonicalName)

            if ($repNaas.Count -gt 0) {
                $uncached = @($repNaas | Where-Object { -not $lunCache.ContainsKey($_) -or $lunCache[$_].LastSeen -ne $today })
                if ($uncached.Count -eq 0) {
                    Write-Host "    All $($repNaas.Count) NAAs in today's cache — skipping"
                    foreach ($profile in $hostProfiles) {
                        foreach ($lv in $profile.LunViewItems) {
                            if ($lunCache.ContainsKey($lv.CanonicalName)) {
                                $lunCache[$lv.CanonicalName].LastSeen = $today
                            }
                        }
                    }
                    continue
                }
            }

            # ── Step 4: One representative per unique device count ─────────────
            $representatives = @($countGroups | ForEach-Object { $_.Group[0].Name })
            Write-Host "    Scanning $($representatives.Count) representative(s): $($representatives -join ', ')"

            # ── Step 5: UUID map from View data (all hosts, first seen wins) ───
            $uuidMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($profile in $hostProfiles) {
                foreach ($lv in $profile.LunViewItems) {
                    if ($lv.CanonicalName -and $lv.Uuid -and -not $uuidMap.ContainsKey($lv.CanonicalName)) {
                        $uuidMap[$lv.CanonicalName] = $lv.Uuid
                    }
                }
            }

            # ── Step 6: Parallel scan of representatives ───────────────────────
            $scanResults = $representatives | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {

                Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue

                $hostName = $_
                $vcServer = $using:vcServer
                $cred     = $using:credential

                $lunEntries = [System.Collections.Generic.List[object]]::new()

                Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 2000)

                $localServer = $null
                try {
                    if (-not (Test-Connection -TargetName $hostName -Count 1 -TimeoutSeconds 2 -Quiet)) {
                        Write-Host "    [SCAN] $hostName — unreachable (ping), skipping"
                        return [PSCustomObject]@{ HostName = $hostName; LunEntries = $lunEntries }
                    }

                    Write-Host "    [SCAN] $hostName — connecting..."
                    $localServer = Connect-VIServer -Server $vcServer -Credential $cred -NotDefault -ErrorAction Stop

                    Write-Host "    [SCAN] $hostName — scanning..."
                    $hostObj = Get-VMHost -Name $hostName -Server $localServer -ErrorAction Stop
                    $allLuns = @(Get-ScsiLun -VMHost $hostObj -LunType disk -Server $localServer -ErrorAction Stop)
                    $sanLuns = @($allLuns | Where-Object { $_.CanonicalName -like 'naa.*' })

                    if ($sanLuns.Count -eq 0) {
                        Write-Host "    [SCAN] $hostName — no SAN LUNs found"
                        return [PSCustomObject]@{ HostName = $hostName; LunEntries = $lunEntries }
                    }

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
                            LunId         = $lunId
                            SanId         = $sanIdMap[$lun.CanonicalName]
                        })
                    }

                    Write-Host "    [SCAN] $hostName — $($sanLuns.Count) SAN LUNs"

                } catch {
                    Write-Host "    [SCAN] $hostName — error: $($_.Exception.Message)"
                } finally {
                    if ($localServer) {
                        try { Disconnect-VIServer -Server $localServer -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                    }
                }

                [PSCustomObject]@{ HostName = $hostName; LunEntries = $lunEntries }
            }

            # ── Step 7: Merge into cache ───────────────────────────────────────
            $added   = 0
            $updated = 0

            foreach ($result in $scanResults) {
                if (-not $result) { continue }
                foreach ($entry in $result.LunEntries) {
                    if (-not $entry.CanonicalName) { continue }
                    if (-not $lunCache.ContainsKey($entry.CanonicalName)) {
                        $lunCache[$entry.CanonicalName] = @{
                            LunId    = $entry.LunId
                            SanId    = $entry.SanId
                            Uuid     = $uuidMap[$entry.CanonicalName]
                            vCenter  = $vcServer
                            LastSeen = $today
                        }
                        $added++
                        $vcNewEntries++
                    } else {
                        $lunCache[$entry.CanonicalName].LastSeen = $today
                        if ($entry.LunId  -and -not $lunCache[$entry.CanonicalName].LunId)  { $lunCache[$entry.CanonicalName].LunId  = $entry.LunId }
                        if ($entry.SanId  -and -not $lunCache[$entry.CanonicalName].SanId)  { $lunCache[$entry.CanonicalName].SanId  = $entry.SanId }
                        if ($uuidMap[$entry.CanonicalName] -and -not $lunCache[$entry.CanonicalName].Uuid) { $lunCache[$entry.CanonicalName].Uuid = $uuidMap[$entry.CanonicalName] }
                        $updated++
                    }
                }
            }

            Write-Host "    +$added new, $updated updated (cache total: $($lunCache.Count))"

            # ── Step 8: Write cache after every cluster ────────────────────────
            try {
                $lunCache | ConvertTo-Json -Depth 3 | Set-Content $CachePath -Encoding UTF8
            } catch {
                Write-Host "    Warning: cache write failed — $($_.Exception.Message)"
            }
        }

        Write-Host "`n  $vcServer complete — $vcNewEntries new entries added"

    } catch {
        Write-Host "  ERROR: $($_.Exception.Message) — skipping $vcServer"
    } finally {
        try { Disconnect-VIServer -Server $vcServer -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        Write-Host "  Disconnected from $vcServer"
    }
}

# ── Final summary ─────────────────────────────────────────────────────────────
Write-Host "`n$(('═' * 60))"
Write-Host "  Cache build complete"
Write-Host "  Total entries : [$($lunCache.Count)]"
Write-Host "  Written to    : $CachePath"
Write-Host "$(('═' * 60))"
