<#
.SYNOPSIS
  Create (or tear down) an OCI Ampere A1 VM to run the arm64-only 19.19 image (#565).

.DESCRIPTION
  sopuli-dba : an arm64 Docker host for test/compose.yaml's oracle-19c-ru (#565)

  The 19.19.0.0 image is linux/arm64 only and does not start under emulation on
  x86 (see docs/local-testing.md §5). An Always Free Ampere A1 VM is the cheapest
  native arm64 host, so this creates one, and nothing else:

    - a VCN, an internet gateway, a public subnet and a security list that admits
      SSH from ONE address (yours, detected, or -AllowSshFrom). Nothing else is
      open: the database listener is reached through an SSH tunnel, never
      published to the internet;
    - one VM.Standard.A1.Flex instance on the newest Oracle Linux 9 aarch64
      image, 2 OCPU / 12 GB by default.

  THE A1 LIMIT IS THE TENANCY'S, NOT THE DOCUMENTED ONE. Oracle's Always Free
  page says 4 OCPU / 24 GB; the tenancy this was first run in (2026-09-28) had
  standard-a1-core-regional-count 2 and standard-a1-memory-regional-count 12,
  and a 4/24 launch was LimitExceeded. The script reads both limits before it
  plans and refuses a size they do not leave room for. 12 GB is ample for 19c
  EE, whose DBCA sizes SGA + PGA at about 3.1 GB.

  Every resource is found by display name first and reused if it exists, so a
  second run changes nothing but the SSH ingress address. It prints a plan and
  asks before creating anything; -Yes answers in advance.

  -Teardown removes everything this script created, in reverse order.

  COST. 2 OCPU / 12 GB / 100 GB boot is inside the Always Free allowance as
  documented (200 GB block storage), which a single VM running around the clock
  stays under. The script checks the compute limits, not what is billed --
  look at the tenancy's cost analysis after the first day.

  CAPACITY. A1 is often out of host capacity. Each availability domain is tried
  in turn, and "Out of host capacity" on all of them is reported rather than
  retried forever; the network is kept, so a re-run only launches. In
  eu-frankfurt-1 every AD was out on 2026-09-28 and in 31 attempts across
  2026-09-29 (07:41Z-13:19Z), at 2/12 and at 1/6 alike -- on an Always Free
  tenancy there, expect to wait, or upgrade it to Pay As You Go, which is
  served first and still bills nothing inside the free allowance.

  Needs the OCI CLI configured (`oci setup config`) and works in Windows
  PowerShell 5.1 and PowerShell 7. Every JSON argument goes through a file://
  parameter, because 5.1 mangles embedded quotes on a native command line.

.EXAMPLE
  ./new-a1-host.ps1 -CompartmentName my-testing
.EXAMPLE
  ./new-a1-host.ps1 -CompartmentName my-testing -Teardown
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $CompartmentName,

    [string] $Name = 'sopuli-a1',
    [int]    $Ocpus = 2,
    [int]    $MemoryGB = 12,
    [int]    $BootVolumeGB = 100,
    [string] $SshPublicKeyFile = (Join-Path $HOME '.ssh\id_ed25519.pub'),
    # A /32 is normal. Detected from checkip.amazonaws.com when left empty.
    [string] $AllowSshFrom = '',
    # Not $Profile: that is PowerShell's own automatic variable.
    [string] $OciProfile = 'DEFAULT',
    [switch] $Yes,
    [switch] $Teardown
)

$ErrorActionPreference = 'Stop'
$Shape = 'VM.Standard.A1.Flex'
$PurposeTag = 'sopuli-dba-565'
$Tmp = Join-Path ([IO.Path]::GetTempPath()) "sopuli-a1-$PID"
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null

# ---------------------------------------------------------------- helpers ---

function Invoke-Oci {
    # Runs `oci`, returns parsed JSON (or $null for an empty body), and throws
    # with the service's own message on failure -- the capacity loop needs it.
    param([string[]] $Arguments)
    $errFile = Join-Path $Tmp 'stderr.txt'
    # 'Continue' here: under 'Stop', Windows PowerShell 5.1 turns the first line
    # a native command writes to a redirected stderr into a terminating error,
    # and oci writes progress there on success.
    $ErrorActionPreference = 'Continue'
    $out = & oci @Arguments --profile $OciProfile 2> $errFile
    $code = $LASTEXITCODE
    $err = Get-Content -Raw -ErrorAction SilentlyContinue $errFile
    if ($code -ne 0) { throw "oci $($Arguments[0..2] -join ' ') failed (exit $code):`n$err" }
    $text = ($out | Out-String).Trim()
    if ($text) { return $text | ConvertFrom-Json }
    return $null
}

function Write-JsonFile {
    # UTF-8 without a BOM; Out-File in 5.1 writes UTF-16, which the CLI rejects.
    param([string] $Leaf, [string] $Json)
    $path = Join-Path $Tmp $Leaf
    [IO.File]::WriteAllText($path, $Json)
    return 'file://' + ($path -replace '\\', '/')
}

function Get-Items {
    # A list call's items. oci prints NOTHING for an empty list, and
    # @($null.data) is a one-element array, so never count `.data` directly.
    # Wrap every call in @(...) where the result is counted or indexed: a
    # function's returned array is unrolled, so one item arrives bare, and in
    # Windows PowerShell 5.1 a bare [pscustomobject] has no .Count.
    param($Result)
    if (-not $Result) { return @() }
    return @($Result.data | Where-Object { $_ })
}

function Get-Live {
    # A list call's items, minus the ones already on their way out.
    param($Result)
    return @(Get-Items $Result | Where-Object {
        $_.'lifecycle-state' -notin @('TERMINATED', 'TERMINATING', 'DELETED', 'DELETING')
    })
}

function Select-Ours {
    # The one live resource with this display name that this script made, or
    # $null. Display names are not unique in OCI, so a same-named resource
    # somebody else made would otherwise be reused -- and, under -Teardown,
    # deleted. Refuse an untagged or duplicate match rather than pick one.
    param($Result, [string] $What)
    $live = @(Get-Live $Result)
    $ours = @($live | Where-Object { $_.'freeform-tags'.purpose -eq $PurposeTag })
    if ($live.Count -gt $ours.Count) {
        throw ("A $What with this name exists without the purpose=$PurposeTag tag; it is not " +
               "this script's, so it is neither reused nor deleted. Rename it or pass another -Name.")
    }
    if ($ours.Count -gt 1) { throw "$($ours.Count) tagged ${What}s share this name; remove the extra by hand." }
    if ($ours.Count -eq 1) { return $ours[0] }
    return $null
}

function Confirm-Plan {
    param([string] $Question)
    if ($Yes) { return }
    $answer = Read-Host "$Question [y/N]"
    if ($answer -notmatch '^(y|yes)$') { Write-Host 'Nothing done.'; exit 1 }
}

# ------------------------------------------------------------ resolve -----

$configFile = if ($env:OCI_CLI_CONFIG_FILE) { $env:OCI_CLI_CONFIG_FILE } else { Join-Path $HOME '.oci\config' }
if (-not (Test-Path $configFile)) { throw "No OCI CLI config at $configFile -- run 'oci setup config' first." }

# The tenancy OCID is the root compartment, which a compartment search starts from.
$tenancy = $null
$inProfile = $false
foreach ($line in Get-Content $configFile) {
    if ($line -match '^\s*\[(.+)\]\s*$') { $inProfile = ($Matches[1] -eq $OciProfile); continue }
    if ($inProfile -and $line -match '^\s*tenancy\s*=\s*(\S+)') { $tenancy = $Matches[1] }
}
if (-not $tenancy) { throw "No 'tenancy=' under [$OciProfile] in $configFile." }

$found = @(Get-Items (Invoke-Oci @('iam', 'compartment', 'list', '--compartment-id', $tenancy,
            '--compartment-id-in-subtree', 'true', '--all', '--lifecycle-state', 'ACTIVE',
            '--name', $CompartmentName)))
if ($found.Count -ne 1) { throw "Expected one ACTIVE compartment named '$CompartmentName', found $($found.Count)." }
$compartment = $found[0].id

$vcnName = "$Name-vcn"; $igwName = "$Name-igw"; $slName = "$Name-ssh-only"; $subnetName = "$Name-public"

$vcn = Select-Ours (Invoke-Oci @('network', 'vcn', 'list', '--compartment-id', $compartment, '--display-name', $vcnName)) 'VCN'
$instance = Select-Ours (Invoke-Oci @('compute', 'instance', 'list', '--compartment-id', $compartment, '--display-name', $Name)) 'instance'

# ----------------------------------------------------------- teardown -----

if ($Teardown) {
    Write-Host "Teardown in compartment '$CompartmentName':"
    Write-Host "  instance  $Name  $(if ($instance) { $instance.id } else { '(none)' })  -- boot volume deleted with it"
    Write-Host "  network   $vcnName  $(if ($vcn) { $vcn.id } else { '(none)' })  -- subnet, security list, gateway, VCN"
    if (-not $instance -and -not $vcn) { Write-Host 'Nothing to remove.'; exit 0 }
    Confirm-Plan 'Delete all of the above? The database on the VM goes with it.'

    if ($instance) {
        Write-Host "Terminating $Name ..."
        Invoke-Oci @('compute', 'instance', 'terminate', '--instance-id', $instance.id,
                     '--preserve-boot-volume', 'false', '--force', '--wait-for-state', 'TERMINATED') | Out-Null
    }
    if ($vcn) {
        foreach ($s in Get-Live (Invoke-Oci @('network', 'subnet', 'list', '--compartment-id', $compartment, '--vcn-id', $vcn.id))) {
            Write-Host "Deleting subnet $($s.'display-name') ..."
            Invoke-Oci @('network', 'subnet', 'delete', '--subnet-id', $s.id, '--force', '--wait-for-state', 'TERMINATED') | Out-Null
        }
        # The default route table cannot be deleted, only emptied, and a gateway
        # it still points at cannot be deleted either.
        Invoke-Oci @('network', 'route-table', 'update', '--rt-id', $vcn.'default-route-table-id',
                     '--route-rules', (Write-JsonFile 'no-routes.json' '[]'), '--force') | Out-Null
        foreach ($g in Get-Live (Invoke-Oci @('network', 'internet-gateway', 'list', '--compartment-id', $compartment, '--vcn-id', $vcn.id))) {
            Write-Host "Deleting internet gateway $($g.'display-name') ..."
            Invoke-Oci @('network', 'internet-gateway', 'delete', '--ig-id', $g.id, '--force', '--wait-for-state', 'TERMINATED') | Out-Null
        }
        foreach ($l in Get-Live (Invoke-Oci @('network', 'security-list', 'list', '--compartment-id', $compartment, '--vcn-id', $vcn.id))) {
            if ($l.id -eq $vcn.'default-security-list-id') { continue }
            Write-Host "Deleting security list $($l.'display-name') ..."
            Invoke-Oci @('network', 'security-list', 'delete', '--security-list-id', $l.id, '--force', '--wait-for-state', 'TERMINATED') | Out-Null
        }
        Write-Host "Deleting VCN $vcnName ..."
        Invoke-Oci @('network', 'vcn', 'delete', '--vcn-id', $vcn.id, '--force', '--wait-for-state', 'TERMINATED') | Out-Null
    }
    Write-Host 'Removed.'
    exit 0
}

# --------------------------------------------------------------- plan -----

if (-not (Test-Path $SshPublicKeyFile)) {
    throw "No SSH public key at $SshPublicKeyFile -- create one with: ssh-keygen -t ed25519"
}
if (-not $AllowSshFrom) {
    $ip = (Invoke-RestMethod -Uri 'https://checkip.amazonaws.com' -TimeoutSec 15).Trim()
    $AllowSshFrom = "$ip/32"
}

$images = @(Get-Items (Invoke-Oci @('compute', 'image', 'list', '--compartment-id', $compartment,
            '--operating-system', 'Oracle Linux', '--operating-system-version', '9',
            '--shape', $Shape, '--sort-by', 'TIMECREATED', '--sort-order', 'DESC', '--all')))
if ($images.Count -eq 0) { throw "No Oracle Linux 9 image for $Shape in this region." }
$image = $images[0]

if (-not $vcn) {
    # Always Free allows two VCNs per region. Say so now, not after the plan.
    $avail = (Invoke-Oci @('limits', 'resource-availability', 'get', '--service-name', 'vcn',
              '--limit-name', 'vcn-count', '--compartment-id', $tenancy)).data
    if ($avail.available -lt 1) {
        throw ("No VCN left to create: vcn-count is $($avail.used) used, $($avail.available) available. " +
               "Delete an unused VCN first; nothing has been created.")
    }
}

if (-not $instance) {
    # Checked against the tenancy's own A1 limits, which need not be the
    # documented Always Free ones -- see the header.
    foreach ($pair in @(@('standard-a1-core-regional-count', $Ocpus, 'OCPU'),
                        @('standard-a1-memory-regional-count', $MemoryGB, 'GB'))) {
        $avail = (Invoke-Oci @('limits', 'resource-availability', 'get', '--service-name', 'compute',
                  '--limit-name', $pair[0], '--compartment-id', $tenancy)).data
        if ($avail.available -lt $pair[1]) {
            throw ("Asked for $($pair[1]) $($pair[2]) but $($pair[0]) leaves $($avail.available) " +
                   "($($avail.used) used). Pass a smaller -Ocpus / -MemoryGB; nothing has been created.")
        }
    }
}

$ads = @(Get-Items (Invoke-Oci @('iam', 'availability-domain', 'list', '--compartment-id', $tenancy)) | ForEach-Object { $_.name })

Write-Host ''
Write-Host "Plan, compartment '$CompartmentName' ($compartment):"
Write-Host "  network   $vcnName 10.0.0.0/16, $subnetName 10.0.0.0/24, $igwName  $(if ($vcn) { '(exists, reused)' } else { '(create)' })"
Write-Host "  ingress   tcp/22 from $AllowSshFrom only, plus ICMP 3/4 for path MTU"
if ($instance) {
    Write-Host "  instance  $Name  (exists, $($instance.'lifecycle-state'), reused)"
} else {
    Write-Host "  instance  $Name  $Shape  $Ocpus OCPU / $MemoryGB GB / $BootVolumeGB GB boot  (create)"
    Write-Host "  image     $($image.'display-name')"
    Write-Host "  ADs       $($ads -join ', ')  (tried in order)"
    Write-Host "  ssh key   $SshPublicKeyFile"
}
Write-Host ''
Confirm-Plan 'Proceed?'

# ------------------------------------------------------------ network -----

$tags = Write-JsonFile 'tags.json' "{`"purpose`":`"$PurposeTag`"}"

if (-not $vcn) {
    Write-Host "Creating VCN $vcnName ..."
    $vcn = (Invoke-Oci @('network', 'vcn', 'create', '--compartment-id', $compartment,
            '--cidr-blocks', (Write-JsonFile 'cidrs.json' '["10.0.0.0/16"]'),
            '--display-name', $vcnName, '--dns-label', 'sopulia1',
            '--freeform-tags', $tags, '--wait-for-state', 'AVAILABLE')).data
}

$igw = Select-Ours (Invoke-Oci @('network', 'internet-gateway', 'list', '--compartment-id', $compartment,
        '--vcn-id', $vcn.id, '--display-name', $igwName)) 'internet gateway'
if (-not $igw) {
    Write-Host "Creating internet gateway $igwName ..."
    $igw = (Invoke-Oci @('network', 'internet-gateway', 'create', '--compartment-id', $compartment,
            '--vcn-id', $vcn.id, '--is-enabled', 'true', '--display-name', $igwName,
            '--freeform-tags', $tags, '--wait-for-state', 'AVAILABLE')).data
}

$routes = Write-JsonFile 'routes.json' (@"
[{"destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK", "networkEntityId": "$($igw.id)"}]
"@)
Invoke-Oci @('network', 'route-table', 'update', '--rt-id', $vcn.'default-route-table-id',
             '--route-rules', $routes, '--force') | Out-Null

$ingress = Write-JsonFile 'ingress.json' (@"
[
  {"source": "$AllowSshFrom", "protocol": "6", "isStateless": false,
   "tcpOptions": {"destinationPortRange": {"min": 22, "max": 22}}},
  {"source": "0.0.0.0/0", "protocol": "1", "isStateless": false,
   "icmpOptions": {"type": 3, "code": 4}}
]
"@)
$egress = Write-JsonFile 'egress.json' '[{"destination": "0.0.0.0/0", "protocol": "all", "isStateless": false}]'

$sl = Select-Ours (Invoke-Oci @('network', 'security-list', 'list', '--compartment-id', $compartment,
        '--vcn-id', $vcn.id, '--display-name', $slName)) 'security list'
if ($sl) {
    # The one thing a re-run changes: your address may have moved.
    Invoke-Oci @('network', 'security-list', 'update', '--security-list-id', $sl.id,
                 '--ingress-security-rules', $ingress, '--egress-security-rules', $egress, '--force') | Out-Null
} else {
    Write-Host "Creating security list $slName ..."
    $sl = (Invoke-Oci @('network', 'security-list', 'create', '--compartment-id', $compartment,
            '--vcn-id', $vcn.id, '--display-name', $slName,
            '--ingress-security-rules', $ingress, '--egress-security-rules', $egress,
            '--freeform-tags', $tags, '--wait-for-state', 'AVAILABLE')).data
}

$subnet = Select-Ours (Invoke-Oci @('network', 'subnet', 'list', '--compartment-id', $compartment,
        '--vcn-id', $vcn.id, '--display-name', $subnetName)) 'subnet'
if (-not $subnet) {
    Write-Host "Creating subnet $subnetName ..."
    # Only the SSH-only list: the VCN's default list admits SSH from anywhere.
    $subnet = (Invoke-Oci @('network', 'subnet', 'create', '--compartment-id', $compartment,
            '--vcn-id', $vcn.id, '--cidr-block', '10.0.0.0/24', '--display-name', $subnetName,
            '--dns-label', 'pub', '--route-table-id', $vcn.'default-route-table-id',
            '--security-list-ids', (Write-JsonFile 'sl.json' "[`"$($sl.id)`"]"),
            '--prohibit-public-ip-on-vnic', 'false',
            '--freeform-tags', $tags, '--wait-for-state', 'AVAILABLE')).data
}

# ----------------------------------------------------------- instance -----

if (-not $instance) {
    $shapeConfig = Write-JsonFile 'shape.json' "{`"ocpus`": $Ocpus, `"memoryInGBs`": $MemoryGB}"
    foreach ($ad in $ads) {
        Write-Host "Launching $Name in $ad (waits for RUNNING, a few minutes) ..."
        try {
            $instance = (Invoke-Oci @('compute', 'instance', 'launch', '--availability-domain', $ad,
                    '--compartment-id', $compartment, '--shape', $Shape, '--shape-config', $shapeConfig,
                    '--image-id', $image.id, '--subnet-id', $subnet.id, '--assign-public-ip', 'true',
                    '--display-name', $Name, '--ssh-authorized-keys-file', $SshPublicKeyFile,
                    '--boot-volume-size-in-gbs', "$BootVolumeGB",
                    '--freeform-tags', $tags, '--wait-for-state', 'RUNNING')).data
            break
        } catch {
            if ($_.Exception.Message -match 'Out of host capacity') {
                Write-Host "  $ad is out of A1 capacity."
                continue
            }
            throw
        }
    }
    if (-not $instance) {
        throw "Every availability domain was out of A1 capacity. Nothing launched; the network stays for the next try."
    }
}

# A reused instance need not be running, and "Ready" must mean SSH can answer.
# Start a stopped one; wait out one that is on its way up; refuse the rest.
switch ($instance.'lifecycle-state') {
    'RUNNING' { }
    'STOPPED' {
        Write-Host "Starting $Name (was STOPPED) ..."
        $instance = (Invoke-Oci @('compute', 'instance', 'action', '--instance-id', $instance.id,
                     '--action', 'START', '--wait-for-state', 'RUNNING')).data
    }
    { $_ -in @('PROVISIONING', 'STARTING') } {
        Write-Host "Waiting for $Name ($($instance.'lifecycle-state')) to reach RUNNING ..."
        $instance = (Invoke-Oci @('compute', 'instance', 'get', '--instance-id', $instance.id,
                     '--wait-for-state', 'RUNNING')).data
    }
    default {
        throw "$Name is $($instance.'lifecycle-state'); re-run once it has settled. The instance was left alone."
    }
}

$vnics = @(Get-Items (Invoke-Oci @('compute', 'instance', 'list-vnics', '--instance-id', $instance.id)))
if ($vnics.Count -eq 0) { throw "Instance $($instance.id) has no VNIC yet -- re-run in a minute." }
$publicIp = $vnics[0].'public-ip'

Write-Host ''
Write-Host "Ready: $Name  $($instance.id)"
Write-Host "  public IP  $publicIp   (SSH from $AllowSshFrom only; user 'opc')"
Write-Host ''
Write-Host 'Next, from the repository root:'
Write-Host "  ssh opc@$publicIp mkdir -p sopuli"
Write-Host "  scp -r test sql opc@${publicIp}:sopuli/"
Write-Host "  ssh -t opc@$publicIp bash sopuli/test/oci-a1/setup-oracle-19c.sh"
Write-Host '  (a new VM takes a minute or two after RUNNING before sshd answers)'
Write-Host ''
Write-Host 'Then reach the listener through a tunnel, never through the internet:'
Write-Host "  ssh -N -L 1527:127.0.0.1:1527 opc@$publicIp"
Write-Host '  # sopuli: dsn "127.0.0.1:1527/ORCLPDB1", oracle: { scope: pdb, container: ORCLPDB1 }'

Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
