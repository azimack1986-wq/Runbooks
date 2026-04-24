#Requires -Version 7.0
<#
.SYNOPSIS
    Builds a persistent LUN map cache using the vCenter View API only — no
    per-host connections, no Get-ScsiLun, no Get-ScsiLunPath.

.DESCRIPTION
    For each cluster (and each standalone host) across all configured vCenters:

    1. Performs a single batch View call per host pulling
       Config.StorageDevice.ScsiLun and Config.StorageDevice.MultipathInfo.
       No host connections — all data comes from the vCenter API.

    2. Joins ScsiLun.Uuid to MultipathInfo.Lun.Id, then extracts:
         - CanonicalName (NAA)              from ScsiLun
         - LunId                            from MultipathInfo path name (vmhbaX:CY:TZ:LNN)
         - SanId (iSCSI IQN or FC WWN)      from MultipathInfo path Transport
         - Uuid                             from ScsiLun (for future bridge use)

    3. Resume support: if every NAA seen across the cluster is already in
       today's cache, the cluster is skipped (only LastSeen is touched).

    4. Cache is written to disk after every cluster. A session drop preserves
       all completed clusters and they are skipped on the next run.

    Deduplication is by CanonicalName — each unique LUN stored once, regardless
    of how many hosts/clusters can see it. Existing entries are preserved;
    LastSeen is refreshed and missing fields are filled in opportunistically.

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

            # ── Step 1: Batch View call per host — ScsiLun + MultipathInfo ────
            $hostProfiles = [System.Collections.Generic.List[object]]::new()

            foreach ($hostId in $unit.HostIds) {
                $hView = Get-View -Id $hostId `
                    -Property @('Name', 'Runtime.ConnectionState', 'Config.StorageDevice.ScsiLun', 'Config.StorageDevice.MultipathInfo') `
                    -ErrorAction SilentlyContinue
                if (-not $hView -or $hView.Runtime.ConnectionState -ne 'connected') { continue }

                $sanLunViews = @($hView.Config.StorageDevice.ScsiLun | Where-Object {
                    $_.CanonicalName -like 'naa.*' -and $_.LunType -eq 'disk'
                })

                # Uuid → CanonicalName map for joining to MultipathInfo
                $uuidToNaa = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($lv in $sanLunViews) {
                    if ($lv.CanonicalName -and $lv.Uuid) {
                        $uuidToNaa[$lv.Uuid] = $lv.CanonicalName
                    }
                }

                # Extract LunId + SanId from MultipathInfo
                $hostLunData = [System.Collections.Generic.List[object]]::new()
                foreach ($mpLun in $hView.Config.StorageDevice.MultipathInfo.Lun) {
                    $naa = $uuidToNaa[$mpLun.Id]
                    if (-not $naa) { continue }

                    $lunId = $null
                    $sanId = $null

                    if ($mpLun.Path -and $mpLun.Path.Count -gt 0) {
                        if ($mpLun.Path[0].Name -match ':L(\d+)$') { $lunId = [int]$Matches[1] }

                        foreach ($p in $mpLun.Path) {
                            if ($p.Transport.IScsiName)         { $sanId = $p.Transport.IScsiName;         break }
                            if ($p.Transport.PortWorldWideName) { $sanId = $p.Transport.PortWorldWideName; break }
                        }
                    }

                    $hostLunData.Add([PSCustomObject]@{
                        CanonicalName = $naa
                        LunId         = $lunId
                        SanId         = $sanId
                        Uuid          = $mpLun.Id
                    })
                }

                $hostProfiles.Add([PSCustomObject]@{
                    Name        = $hView.Name
                    DeviceCount = $sanLunViews.Count
                    LunData     = $hostLunData
                })
            }

            if ($hostProfiles.Count -eq 0) {
                Write-Host "    No connected hosts — skipping"
                continue
            }

            # ── Step 2: Informational — host count grouping ───────────────────
            $countGroups  = $hostProfiles | Group-Object DeviceCount | Sort-Object { [int]$_.Name }
            $groupSummary = $countGroups | ForEach-Object { "$($_.Name) LUNs x$($_.Count) host(s)" }
            Write-Host "    [$($hostProfiles.Count)] hosts — $($groupSummary -join ' | ')"

            # ── Step 3: Resume check — skip cluster if all NAAs in today's cache
            $allNaas = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($profile in $hostProfiles) {
                foreach ($entry in $profile.LunData) {
                    if ($entry.CanonicalName) { $null = $allNaas.Add($entry.CanonicalName) }
                }
            }

            if ($allNaas.Count -gt 0) {
                $uncached = @($allNaas | Where-Object { -not $lunCache.ContainsKey($_) -or $lunCache[$_].LastSeen -ne $today })
                if ($uncached.Count -eq 0) {
                    Write-Host "    All $($allNaas.Count) NAAs in today's cache — skipping merge"
                    foreach ($naa in $allNaas) {
                        if ($lunCache.ContainsKey($naa)) { $lunCache[$naa].LastSeen = $today }
                    }
                    continue
                }
            }

            # ── Step 4: Merge into cache ──────────────────────────────────────
            $added   = 0
            $updated = 0

            foreach ($profile in $hostProfiles) {
                foreach ($entry in $profile.LunData) {
                    if (-not $entry.CanonicalName) { continue }
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
                        if ($entry.LunId -and -not $lunCache[$entry.CanonicalName].LunId) { $lunCache[$entry.CanonicalName].LunId = $entry.LunId }
                        if ($entry.SanId -and -not $lunCache[$entry.CanonicalName].SanId) { $lunCache[$entry.CanonicalName].SanId = $entry.SanId }
                        if ($entry.Uuid  -and -not $lunCache[$entry.CanonicalName].Uuid)  { $lunCache[$entry.CanonicalName].Uuid  = $entry.Uuid }
                        $updated++
                    }
                }
            }

            Write-Host "    +$added new, $updated updated (cache total: $($lunCache.Count))"

            # ── Step 5: Write cache after every cluster ───────────────────────
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
