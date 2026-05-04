#Requires -Version 7.0
<#
.SYNOPSIS
    Collects VM inventory data from multiple vCenters, maintains a JSON cache,
    and exports a clean JSON file for Copilot consumption.

.DESCRIPTION
    Version 1.7 - DNS moved to a top-level VM field (DNS array) positioned
    after SubnetMask. Removed from NIC records entirely.

    Version 1.6 - DNS servers added to each NIC record (DNSServers field),
    sourced from Guest.IpStack[0].DnsConfig while already processing the
    IP stack for gateway and subnet data.

    Version 1.5 - VML NAA extraction now truncates to the canonical NAA
    length (32 hex for Type 6, 16 hex for Types 2/3/5) so extracted NAAs
    match the cache keys produced by Build-LUNMapCache. Previously the
    regex captured vendor trailing data (e.g. ASCII "LUN C-") which made
    the lookup miss the cache entry and LunId/SanId came back null.

    Version 1.4 - LUN ID and SAN ID lookup now driven by a pre-built
    LUNMap_Cache.json (produced by Build-LUNMapCache.ps1) instead of scanning
    ESX hosts at runtime. Eliminates all in-script host scanning, the parallel
    LUN scan block, and expected-NAA verification logic.
    RDM NAA extraction from VM ExtensionData (VML + NAA format handling with
    Get-HardDisk fallback) is retained as the bridge from VM disk to cache entry.

    Processes all vCenters defined in the CONFIGURATION section.
    Credentials are prompted once and reused for all vCenters.

    VM records are written to cache after each cluster completes. The export
    is regenerated at the same time. This ensures partial data is preserved
    if the script fails partway through a vCenter.

    Cache behaviour: accumulates across all vCenters. Missing-flag logic is
    scoped per vCenter. Cache is saved after each cluster so a failure midway
    does not lose already-collected data.

.PARAMETER OutputPath
    UNC or local path where the JSON cache and export will be written.

.EXAMPLE
    .\Get-RunbookVMInventory_v1.7.ps1 -OutputPath "\\server\share\VMInventory"
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

# ── File paths ────────────────────────────────────────────────────────────────
$JsonCachePath  = Join-Path $OutputPath 'VMInventory_Cache.json'
$JsonExportPath = Join-Path $OutputPath 'VMInventory_Export.json'
$LunCachePath   = Join-Path $OutputPath 'LUNMap_Cache.json'

# ── Helper: Parse Primary Location from hostname ──────────────────────────────
function Get-PrimaryLocation {
    param ([string]$Hostname)
    if ($Hostname.Length -ge 7) { return $Hostname.Substring(4, 3) }
    return $null
}

# ── Helper: Parse SC from datastore name ─────────────────────────────────────
function Get-SCFromDatastore {
    param ([string]$DatastoreName)
    if ($DatastoreName -match '_(?i)(sc[1-5])_') { return $Matches[1].ToUpper() }
    return $null
}

# ── Helper: Convert prefix length to dotted-decimal subnet mask ──────────────
function ConvertTo-SubnetMask {
    param ([int]$PrefixLength)
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { return $null }
    if ($PrefixLength -eq 0) { return '0.0.0.0' }
    $bits   = [string]::new('1', $PrefixLength) + [string]::new('0', 32 - $PrefixLength)
    $octets = for ($i = 0; $i -lt 4; $i++) {
        [Convert]::ToInt32($bits.Substring($i * 8, 8), 2)
    }
    return $octets -join '.'
}

# ── Helper: Build VM inventory record from in-memory data ────────────────────
function Get-VMInventoryRecord {
    param (
        $VM,
        [string]$VCenterName,
        [System.Collections.IDictionary]$Lookups
    )

    $cpuCores = $VM.NumCpu
    $ramGB    = [math]::Round($VM.MemoryGB, 0)
    $os       = $VM.ExtensionData.Config.GuestFullName

    $defaultGateway   = $null
    $ipStackPrefixMap = @{}
    $dnsServers       = @()
    try {
        $ipStack = $VM.ExtensionData.Guest.IpStack
        if ($ipStack) {
            $defaultRoute = $ipStack |
                ForEach-Object { $_.IpRouteConfig.IpRoute } |
                Where-Object { $_.Network -eq '0.0.0.0' -and $_.PrefixLength -eq 0 } |
                Select-Object -First 1
            if ($defaultRoute) { $defaultGateway = $defaultRoute.Gateway.IpAddress }

            $ipStack | ForEach-Object { $_.IpConfig.IpAddress } |
                Where-Object { $_ } |
                ForEach-Object { $ipStackPrefixMap[$_.IpAddress] = $_.PrefixLength }

            $dnsServers = @($ipStack | ForEach-Object { $_.DnsConfig?.IpAddress } |
                Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
                Select-Object -Unique)
        }
    } catch {}

    $guestNetByMac = @{}
    if ($VM.ExtensionData.Guest.Net) {
        foreach ($net in $VM.ExtensionData.Guest.Net) {
            if ($net.MacAddress) { $guestNetByMac[$net.MacAddress.ToLower()] = $net }
        }
    }

    $hostKey    = $VM.ExtensionData.Runtime.Host?.ToString()
    $cluster    = if ($hostKey) { $Lookups.HostClusterMap[$hostKey] } else { $null }
    $datacenter = if ($hostKey) { $Lookups.HostDCMap[$hostKey] }     else { $null }

    $nics = @()
    foreach ($device in $VM.ExtensionData.Config.Hardware.Device) {
        $pgName = switch ($device.Backing?.GetType().Name) {
            'VirtualEthernetCardNetworkBackingInfo' {
                $device.Backing.DeviceName
            }
            'VirtualEthernetCardDistributedVirtualPortBackingInfo' {
                $Lookups.DVPGKeyToName[$device.Backing.Port.PortgroupKey]
            }
            default { $null }
        }
        if ($null -eq $pgName) { continue }

        $nicIP   = $null
        $nicMask = $null
        $netInfo = if ($device.MacAddress) { $guestNetByMac[$device.MacAddress.ToLower()] } else { $null }
        if ($netInfo) {
            if ($netInfo.IpConfig -and $netInfo.IpConfig.IpAddress) {
                $ipEntry = @($netInfo.IpConfig.IpAddress) |
                    Where-Object { $_.IpAddress -match '^\d+\.\d+\.\d+\.\d+$' } |
                    Select-Object -First 1
                if ($ipEntry) {
                    $nicIP   = $ipEntry.IpAddress
                    $nicMask = ConvertTo-SubnetMask -PrefixLength $ipEntry.PrefixLength
                }
            }
            if (-not $nicIP -and $netInfo.IpAddress) {
                $nicIP = @($netInfo.IpAddress) |
                    Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
                    Select-Object -First 1
            }
            if ($nicIP -and -not $nicMask -and $ipStackPrefixMap.ContainsKey($nicIP)) {
                $nicMask = ConvertTo-SubnetMask -PrefixLength $ipStackPrefixMap[$nicIP]
            }
        }

        $nics += [ordered]@{
            PortGroup  = $pgName
            VDS        = $Lookups.PgToVds[$pgName]
            IPAddress  = $nicIP
            SubnetMask = $nicMask
        }
    }

    $ipAddress  = ($nics | Where-Object { $_.IPAddress  } | Select-Object -First 1).IPAddress
    $subnetMask = ($nics | Where-Object { $_.SubnetMask } | Select-Object -First 1).SubnetMask

    $datastoreName    = $null
    $datastoreCluster = $null
    $sc               = $null
    foreach ($dsMoRef in $VM.ExtensionData.Datastore) {
        $dsName = $Lookups.DSNameMap[$dsMoRef.ToString()]
        if ($dsName -and $dsName -notmatch 'vswap') {
            $datastoreName    = $dsName
            $datastoreCluster = $Lookups.DSStoragePodMap[$dsMoRef.ToString()]
            $sc               = Get-SCFromDatastore -DatastoreName $datastoreName
            break
        }
    }

    $disks = @()
    foreach ($device in $VM.ExtensionData.Config.Hardware.Device) {
        if ($device.GetType().Name -ne 'VirtualDisk') { continue }

        $filename = $device.Backing?.FileName
        if (-not $filename -or $filename -match 'vswap') { continue }

        $backingTypeName = $device.Backing.GetType().Name
        $isRDM           = $backingTypeName -like '*RawDiskMapping*'

        $diskTypeName = switch -Wildcard ($backingTypeName) {
            '*FlatVer*'        { 'Flat' }
            '*RawDiskMapping*' {
                if ($device.Backing.CompatibilityMode -eq 'physicalMode') { 'RawPhysical' } else { 'RawVirtual' }
            }
            '*SparseVer*'      { 'Sparse' }
            default            { $backingTypeName }
        }

        $sizeGB      = [math]::Round($device.CapacityInKB / 1048576, 0)
        $scsiMapping = "$($device.ControllerKey):$($device.UnitNumber)"
        $naaNumber   = $null
        $lunId       = $null

        if ($isRDM) {
            $naaNumber = $Lookups.RdmNaaLookup["$($VM.Name)|$scsiMapping"]
            if ($naaNumber) { $lunId = $Lookups.LunCache[$naaNumber]?.LunId }
        }

        $disks += [ordered]@{
            FileName              = $filename
            SizeGB                = $sizeGB
            DiskType              = $diskTypeName
            IsRDM                 = $isRDM
            NAANumber             = $naaNumber
            SCSIControllerMapping = $scsiMapping
            LUN                   = $lunId
            LUN_SVM               = if ($naaNumber) { $Lookups.LunCache[$naaNumber]?.SanId } else { $null }
        }
    }

    return [ordered]@{
        Hostname         = $VM.Name
        OS               = $os
        CPUCores         = $cpuCores
        RAMGB            = $ramGB
        vCenter          = $VCenterName
        ESXCluster       = $cluster
        IPAddress        = $ipAddress
        SubnetMask       = $subnetMask
        DNS              = $dnsServers
        DefaultGateway   = $defaultGateway
        NICs             = $nics
        Datacenter       = $datacenter
        VMwareDatastore  = $datastoreName
        DatastoreCluster = $datastoreCluster
        SC               = $sc
        PrimaryLocation  = Get-PrimaryLocation -Hostname $VM.Name
        PowerState       = $VM.PowerState.ToString()
        IsDecommissioned = $VM.Name -match '(?i)decom'
        Disks            = $disks
        NoLongerPresent  = $false
        LastSeen         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        LastChanged      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

# ── Helper: Compare two records, ignoring audit-only fields ───────────────────
function Compare-VMRecord {
    param ($Existing, $New)
    $skipFields = @('LastSeen', 'LastChanged', 'NoLongerPresent')
    foreach ($field in $New.Keys) {
        if ($field -in $skipFields) { continue }
        $existingVal = $Existing.$field | ConvertTo-Json -Compress -Depth 5
        $newVal      = $New.$field      | ConvertTo-Json -Compress -Depth 5
        if ($existingVal -ne $newVal) { return $true }
    }
    return $false
}

# ── Helper: Convert PSCustomObject to ordered hashtable ──────────────────────
function ConvertTo-OrderedHashtable {
    param ($Object)
    $ht = [ordered]@{}
    foreach ($prop in $Object.PSObject.Properties) { $ht[$prop.Name] = $prop.Value }
    return $ht
}

# ── Helper: Write export JSON from current cache ──────────────────────────────
function Write-VMExport {
    param (
        [System.Collections.IDictionary]$Cache,
        [string]$ExportPath
    )

    $exportList = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $Cache.Values) {
        if ($entry.NoLongerPresent) { continue }

        $diskExport = @(foreach ($disk in @($entry.Disks)) {
            $ds = $null
            if ($disk.FileName -match '^\[(.+?)\]') { $ds = $Matches[1] }
            [ordered]@{
                SizeGB                = $disk.SizeGB
                DiskType              = $disk.DiskType
                Datastore             = $ds
                IsRDM                 = $disk.IsRDM
                NAANumber             = $disk.NAANumber
                SCSIControllerMapping = $disk.SCSIControllerMapping
                LUN                   = $disk.LUN
                LUN_SVM               = $disk.LUN_SVM
            }
        })

        $nicExport = @()
        if ($null -ne $entry.NICs) {
            $nicIndex  = 0
            $nicExport = @($entry.NICs | ForEach-Object {
                $nic = [ordered]@{
                    PortGroup  = $_.PortGroup
                    VDS        = $_.VDS
                    IPAddress  = $_.IPAddress
                    SubnetMask = $_.SubnetMask
                }
                if ($nicIndex -eq 0) { $nic['DefaultGateway'] = $entry.DefaultGateway }
                $nicIndex++
                $nic
            })
        } elseif ($null -ne $entry.PortGroups) {
            $nicIndex  = 0
            $nicExport = @($entry.PortGroups | ForEach-Object {
                $nic = [ordered]@{ PortGroup = $_; VDS = $null; IPAddress = $null; SubnetMask = $null }
                if ($nicIndex -eq 0) { $nic['DefaultGateway'] = $entry.DefaultGateway }
                $nicIndex++
                $nic
            })
        }

        $isDecom = $entry.IsDecommissioned -or ($entry.Hostname -match '(?i)decom')

        $exportList.Add([ordered]@{
            Hostname         = $entry.Hostname
            Status           = if ($isDecom) { 'Decommissioned' } else { 'Active' }
            IsDecommissioned = $isDecom
            OS               = $entry.OS
            CPUCores         = $entry.CPUCores
            RAMGB            = $entry.RAMGB
            vCenter          = $entry.vCenter
            ESXCluster       = $entry.ESXCluster
            IPAddress        = $entry.IPAddress
            SubnetMask       = $entry.SubnetMask
            DNS              = $entry.DNS
            NICs             = $nicExport
            Datacenter       = $entry.Datacenter
            VMwareDatastore  = $entry.VMwareDatastore
            DatastoreCluster = $entry.DatastoreCluster
            SC               = $entry.SC
            PrimaryLocation  = $entry.PrimaryLocation
            PowerState       = $entry.PowerState
            Disks            = $diskExport
        })
    }

    ConvertTo-Json -InputObject @($exportList) -Depth 5 | Set-Content -Path $ExportPath -Encoding UTF8
    return $exportList.Count
}

# ══ Main ══════════════════════════════════════════════════════════════════════

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script requires PowerShell 7 or later. Current version: $($PSVersionTable.PSVersion)"
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: $OutputPath"
}

$cache = [ordered]@{}
if (Test-Path $JsonCachePath) {
    Write-Host "Loading existing cache from: $JsonCachePath"
    $cacheArray = Get-Content $JsonCachePath -Raw | ConvertFrom-Json
    foreach ($entry in $cacheArray) {
        $ht = ConvertTo-OrderedHashtable -Object $entry
        $cache[$ht.Hostname] = $ht
    }
    Write-Host "  $($cache.Count) VMs loaded from cache"
} else {
    Write-Host "No existing cache found — performing full initial pull"
}

Write-Host "`nLoading LUN map cache..."
$lunCache = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path $LunCachePath) {
    try {
        $lunCacheJson = Get-Content $LunCachePath -Raw | ConvertFrom-Json
        foreach ($prop in $lunCacheJson.PSObject.Properties) {
            $lunCache[$prop.Name] = $prop.Value
        }
        Write-Host "  [$($lunCache.Count)] LUN cache entries loaded"
    } catch {
        Write-Host "  Warning: could not load LUN cache — $($_.Exception.Message)"
        Write-Host "  RDM LUN IDs and SAN IDs will be empty. Run Build-LUNMapCache.ps1 to populate."
    }
} else {
    Write-Host "  Warning: LUN cache not found at $LunCachePath"
    Write-Host "  RDM LUN IDs and SAN IDs will be empty. Run Build-LUNMapCache.ps1 to populate."
}

$credential = Get-Credential -Message "Enter vCenter credentials (used for all vCenters)"

$totalNew     = 0
$totalChanged = 0
$totalMissing = 0

foreach ($vcServer in $vCenterServers) {
    Write-Host "`n════════════════════════════════════════"
    Write-Host "Processing vCenter: $vcServer"
    Write-Host "════════════════════════════════════════"

    $connected = $false
    try {
        $null = Connect-VIServer -Server $vcServer -Credential $credential -ErrorAction Stop
        $connected = $true
        Write-Host "Connected successfully"

        Write-Host "`nPre-fetching inventory data..."

        $pgToVds = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            Get-VDPortgroup -ErrorAction SilentlyContinue | ForEach-Object {
                $pgToVds[$_.Name] = $_.VDSwitch.Name
            }
            Write-Host "  [$($pgToVds.Count)] VDS portgroups"
        } catch { Write-Host "  Warning: VDS portgroup data unavailable" }

        $dvpgKeyToName = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            Get-View -ViewType DistributedVirtualPortgroup -Property @('Name', 'Key') -ErrorAction SilentlyContinue |
                ForEach-Object { $dvpgKeyToName[$_.Key] = $_.Name }
            Write-Host "  [$($dvpgKeyToName.Count)] DVPortgroup keys"
        } catch { Write-Host "  Warning: DVPortgroup key data unavailable" }

        $hostClusterMapV = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            Get-View -ViewType ClusterComputeResource -Property @('Name', 'Host') -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $clName = $_.Name
                    foreach ($hostRef in $_.Host) { $hostClusterMapV[$hostRef.ToString()] = $clName }
                }
            Write-Host "  [$($hostClusterMapV.Count)] hosts mapped to clusters"
        } catch { Write-Host "  Warning: cluster data unavailable" }

        $hostDCMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            Get-View -ViewType Datacenter -Property @('Name', 'HostFolder') -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $dcName = $_.Name
                    Get-View -SearchRoot $_.HostFolder -ViewType HostSystem -Property @('Name') -ErrorAction SilentlyContinue |
                        ForEach-Object { $hostDCMap[$_.MoRef.ToString()] = $dcName }
                }
            Write-Host "  [$($hostDCMap.Count)] hosts mapped to datacenters"
        } catch { Write-Host "  Warning: datacenter data unavailable" }

        $dsNameMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            Get-View -ViewType Datastore -Property @('Name') -ErrorAction SilentlyContinue |
                ForEach-Object { $dsNameMap[$_.MoRef.ToString()] = $_.Name }
            Write-Host "  [$($dsNameMap.Count)] datastores"
        } catch { Write-Host "  Warning: datastore data unavailable" }

        $dsStoragePodMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            Get-View -ViewType StoragePod -Property @('Name', 'ChildEntity') -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $podName = $_.Name
                    foreach ($childRef in $_.ChildEntity) { $dsStoragePodMap[$childRef.ToString()] = $podName }
                }
            Write-Host "  [$($dsStoragePodMap.Count)] datastores mapped to datastore clusters"
        } catch { Write-Host "  Warning: datastore cluster data unavailable" }

        Write-Host "`nRetrieving all VMs..."
        $allVMs = @(Get-VM -ErrorAction Stop)
        Write-Host "  $($allVMs.Count) VMs retrieved"

        $filteredVMs = @($allVMs | Where-Object {
            $_.Name -notlike 'vCLS*' -and
            $_.ExtensionData.Config.ManagedBy?.type -ne 'placeholderVm'
        })
        Write-Host "  $($filteredVMs.Count) VMs after filtering vCLS and SRM placeholders"

        Write-Host "`nBuilding RDM NAA lookup from VM ExtensionData..."
        $rdmNaaLookup = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($vm in $filteredVMs) {
            foreach ($device in $vm.ExtensionData.Config.Hardware.Device) {
                if ($device.GetType().Name -ne 'VirtualDisk') { continue }
                if ($device.Backing.GetType().Name -notlike '*RawDiskMapping*') { continue }
                $deviceName = $device.Backing.DeviceName
                if (-not $deviceName) { continue }
                $naa = if ($deviceName -match '^vml\.[0-9a-fA-F]{10}([0-9a-fA-F]+)$') {
                    $hex    = $Matches[1]
                    $naaLen = if ($hex[0] -eq '6') { 32 } else { 16 }
                    if ($hex.Length -ge $naaLen) { "naa.$($hex.Substring(0, $naaLen))" } else { $null }
                } elseif ($deviceName -match '(naa\.[0-9a-fA-F]+)') {
                    $Matches[1]
                } else {
                    $null
                }
                if (-not $naa) { continue }
                $scsiMapping = "$($device.ControllerKey):$($device.UnitNumber)"
                $key = "$($vm.Name)|$scsiMapping"
                if (-not $rdmNaaLookup.ContainsKey($key)) { $rdmNaaLookup[$key] = $naa }
            }
        }
        Write-Host "  [$($rdmNaaLookup.Count)] RDM NAA mappings"

        if ($rdmNaaLookup.Count -eq 0) {
            Write-Host "  ExtensionData extraction returned 0 NAAs. Falling back to Get-HardDisk API..."
            try {
                $allRdmDisks = @(Get-HardDisk -VM $filteredVMs -ErrorAction Stop | Where-Object { $_.DiskType -eq 'RawPhysical' })
                foreach ($disk in $allRdmDisks) {
                    $vmName      = $disk.Parent.Name
                    $naa         = if ($disk.ScsiCanonicalName -match '(naa\.[0-9a-fA-F]+)') { $Matches[1] } else { $null }
                    if (-not $naa) { $naa = $disk.ScsiCanonicalName }
                    if (-not $naa) { continue }
                    $scsiMapping = "$($disk.Slot):-1"
                    $key         = "$vmName|$scsiMapping"
                    if (-not $rdmNaaLookup.ContainsKey($key)) { $rdmNaaLookup[$key] = $naa }
                }
                Write-Host "  [$($rdmNaaLookup.Count)] RDM NAA mappings (from Get-HardDisk fallback)"
            } catch {
                Write-Host "  Warning: Get-HardDisk fallback also failed: $($_.Exception.Message)"
                Write-Host "  Proceeding with 0 RDM mappings."
            }
        }

        Write-Host "`nBuilding cluster host map..."
        $clusterHostMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        $hostMoRefToClusterKey = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            $allHostObjs = @(Get-VMHost -ErrorAction Stop)
            foreach ($h in $allHostObjs) {
                $clKey = if ($hostClusterMapV.ContainsKey($h.Id)) {
                    $hostClusterMapV[$h.Id]
                } else {
                    "__standalone__$($h.Name)"
                }
                if (-not $clusterHostMap.ContainsKey($clKey)) {
                    $clusterHostMap[$clKey] = [System.Collections.Generic.List[object]]::new()
                }
                $clusterHostMap[$clKey].Add($h)
                $hostMoRefToClusterKey[$h.Id] = $clKey
            }
            Write-Host "  [$($clusterHostMap.Count)] clusters/standalone hosts, [$($allHostObjs.Count)] total hosts"
        } catch { Write-Host "  Warning: host list unavailable" }

        $vmClusterKeyMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($vm in $filteredVMs) {
            $hostKey = $vm.ExtensionData.Runtime.Host?.ToString()
            $clKey   = if ($hostKey -and $hostMoRefToClusterKey.ContainsKey($hostKey)) {
                $hostMoRefToClusterKey[$hostKey]
            } elseif ($hostKey) {
                "__standalone__$hostKey"
            } else {
                '__no_host__'
            }
            $vmClusterKeyMap[$vm.Name] = $clKey
        }

        $lookups = @{
            PgToVds         = $pgToVds
            DVPGKeyToName   = $dvpgKeyToName
            HostClusterMap  = $hostClusterMapV
            HostDCMap       = $hostDCMap
            DSNameMap       = $dsNameMap
            DSStoragePodMap = $dsStoragePodMap
            LunCache        = $lunCache
            RdmNaaLookup    = $rdmNaaLookup
        }

        $vmsByCluster = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($vm in $filteredVMs) {
            $clKey = if ($vmClusterKeyMap.ContainsKey($vm.Name)) { $vmClusterKeyMap[$vm.Name] } else { '__no_host__' }
            if (-not $vmsByCluster.ContainsKey($clKey)) {
                $vmsByCluster[$clKey] = [System.Collections.Generic.List[object]]::new()
            }
            $vmsByCluster[$clKey].Add($vm)
        }

        Write-Host "`nProcessing VMs cluster by cluster..."
        $newCount     = 0
        $changedCount = 0
        $currentNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $clusterCount = 0

        foreach ($clKey in $vmsByCluster.Keys) {
            $clusterCount++
            $clVMs = $vmsByCluster[$clKey]
            $clLabel = if ($clKey -like '__standalone__*') { "Standalone:$($clKey.Replace('__standalone__',''))" }
                       elseif ($clKey -eq '__no_host__') { 'No-Host' }
                       else { $clKey }

            Write-Host "  [$clusterCount/$($vmsByCluster.Count)] Cluster: $clLabel ($($clVMs.Count) VMs)"

            $clNew     = 0
            $clChanged = 0

            foreach ($vm in $clVMs) {
                $null = $currentNames.Add($vm.Name)
                $record = Get-VMInventoryRecord -VM $vm -VCenterName $vcServer -Lookups $lookups

                if (-not $cache.Contains($vm.Name)) {
                    $cache[$vm.Name] = $record
                    $clNew++
                    Write-Host "    [NEW]     $($vm.Name)"
                } else {
                    $existing = $cache[$vm.Name]
                    if (Compare-VMRecord -Existing $existing -New $record) {
                        $record.LastChanged = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                        $cache[$vm.Name]    = $record
                        $clChanged++
                        Write-Host "    [UPDATED] $($vm.Name)"
                    } else {
                        $cache[$vm.Name].LastSeen        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                        $cache[$vm.Name].NoLongerPresent = $false
                    }
                }
            }

            $newCount     += $clNew
            $changedCount += $clChanged

            Write-Host "    Saving cache and export..."
            ConvertTo-Json -InputObject @($cache.Values) -Depth 10 | Set-Content -Path $JsonCachePath -Encoding UTF8
            $exportedCount = Write-VMExport -Cache $cache -ExportPath $JsonExportPath
            Write-Host "    Cache: $($cache.Count) total | Export: $exportedCount active"
        }

        $missingCount = 0
        foreach ($cachedName in @($cache.Keys)) {
            if ($cache[$cachedName].vCenter -ne $vcServer) { continue }
            if (-not $currentNames.Contains($cachedName)) {
                if (-not $cache[$cachedName].NoLongerPresent) {
                    $cache[$cachedName].NoLongerPresent = $true
                    $missingCount++
                    Write-Host "  [MISSING] $cachedName"
                }
            }
        }

        if ($missingCount -gt 0) {
            Write-Host "  Saving cache after missing-VM flagging..."
            ConvertTo-Json -InputObject @($cache.Values) -Depth 10 | Set-Content -Path $JsonCachePath -Encoding UTF8
            $exportedCount = Write-VMExport -Cache $cache -ExportPath $JsonExportPath
            Write-Host "  Cache: $($cache.Count) total | Export: $exportedCount active"
        }

        $totalNew     += $newCount
        $totalChanged += $changedCount
        $totalMissing += $missingCount
        Write-Host "`n$vcServer summary: $newCount new | $changedCount updated | $missingCount newly missing"

    } catch {
        Write-Host "ERROR processing $vcServer — $($_.Exception.Message)"
        Write-Host "Continuing to next vCenter..."
    } finally {
        if ($connected) {
            try { Disconnect-VIServer -Server $vcServer -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            Write-Host "Disconnected from $vcServer"
        }
    }
}

Write-Host "`n════════════════════════════════════════"
Write-Host "Overall summary: $totalNew new | $totalChanged updated | $totalMissing newly missing"
Write-Host "`nDone. Upload '$JsonExportPath' to Copilot along with the runbook."
