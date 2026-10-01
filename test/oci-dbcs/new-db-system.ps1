<#
.SYNOPSIS
  Create, connect to, stop, start or tear down a minimal OCI Base Database Service 19c DB system (#581).

.DESCRIPTION
  sopuli-dba : a current 19c release update to measure against (#581)

  The release an OCI estate runs is a recent 19c RU, and nothing pullable is one:
  19.3 is the base release, and 19.19 is arm64-only (#565, closed). A Base
  Database Service DB system runs whatever RU Oracle currently ships, so this
  creates one, and nothing else:

    - a VCN, an internet gateway, a public subnet and a security list that admits
      SSH from ONE address (yours, detected, or -AllowSshFrom). The listener is
      NOT open to the internet: it is reached through an OCI Bastion
      port-forwarding session (-Connect);
    - one single-node VM.BaseDB.x86 DB system, 4 ECPU (the shape's minimum), LVM
      storage at its 256 GB minimum, Enterprise Edition, LICENSE_INCLUDED, and
      automatic backups off. CDB ORCLCDB and PDB ORCLPDB1, the names
      test/compose.yaml's 19c services use.

  THE RELEASE IS RESOLVED, NOT ASSUMED. Without -DbVersion the newest explicit
  19.N.0.0 that `oci db version list` offers for the shape is used, and the plan
  prints it. Record measurements with the version the database reports, never as
  "19c".

  THE SYS PASSWORD NEVER REACHES ARGV. It is typed at a prompt (twice), checked
  against OCI's rules, and handed to the CLI inside a --from-json file in a
  private temporary directory that is deleted when the script ends. The same
  value becomes SYSTEM's, the PDB admin's and the TDE wallet's: OCI's default.

  SQLNET.ORA IS LEFT AS PROVISIONED. #575 needs the shipped NNE settings read
  untouched, so nothing here logs in to the node or changes the database.

  Every resource is found by display name AND the purpose tag first, and reused
  if it exists; a same-named resource without the tag is refused, never reused or
  deleted. It prints a plan and asks before creating anything; -Yes answers in
  advance.

    -Connect    opens a Bastion port-forwarding session to the listener and
                prints the `ssh -L` command that uses it. The bastion is created
                on first use and admits only -AllowSshFrom; a session lasts three
                hours. NOT `ssh -L` to the node itself: OCI hardens its sshd with
                AllowTcpForwarding no and DisableForwarding yes, so a tunnel there
                accepts locally and forwards nothing (measured 2026-10-01).
    -Stop       stops the DB node. ECPU billing stops; storage keeps billing.
    -Start      starts it again.
    -Teardown   terminates the DB system, deletes the bastion, and removes the
                network, in reverse order. The database goes with it; there are
                no backups.

  COST. Unlike the A1 route this is not free: the DB system bills per ECPU-hour
  while the node runs and for its block storage until -Teardown. Stop it between
  sessions, terminate it when the measurements are recorded, and read Cost
  Analysis afterwards rather than trusting an estimate.

  Needs the OCI CLI configured (`oci setup config`) on a Pay As You Go tenancy, and
  works in Windows PowerShell 5.1 and PowerShell 7. Every JSON argument goes
  through a file:// parameter, because 5.1 mangles embedded quotes on a native
  command line.

.EXAMPLE
  ./new-db-system.ps1 -CompartmentName my-testing
.EXAMPLE
  ./new-db-system.ps1 -CompartmentName my-testing -Connect
.EXAMPLE
  ./new-db-system.ps1 -CompartmentName my-testing -Stop
.EXAMPLE
  ./new-db-system.ps1 -CompartmentName my-testing -Teardown
#>
[CmdletBinding(DefaultParameterSetName = 'Create')]
param(
    [Parameter(Mandatory = $true)]
    [string] $CompartmentName,

    [string] $Name = 'sopuli-19c',
    # Empty: the newest explicit 19.N.0.0 offered for the shape.
    [Parameter(ParameterSetName = 'Create')]
    [string] $DbVersion = '',
    [Parameter(ParameterSetName = 'Create')]
    [ValidateSet('ENTERPRISE_EDITION', 'STANDARD_EDITION')]
    [string] $DatabaseEdition = 'ENTERPRISE_EDITION',
    [Parameter(ParameterSetName = 'Create')]
    [int]    $Ecpus = 4,
    [Parameter(ParameterSetName = 'Create')]
    [int]    $DataStorageGB = 256,
    # Empty: the first availability domain whose ECPU limit has room.
    [Parameter(ParameterSetName = 'Create')]
    [string] $AvailabilityDomain = '',
    [Parameter(ParameterSetName = 'Create')]
    [Parameter(ParameterSetName = 'Connect')]
    [string] $SshPublicKeyFile = (Join-Path $HOME '.ssh\id_ed25519.pub'),
    # A /32 is normal. Detected from checkip.amazonaws.com when left empty.
    [Parameter(ParameterSetName = 'Create')]
    [Parameter(ParameterSetName = 'Connect')]
    [string] $AllowSshFrom = '',
    # Not $Profile: that is PowerShell's own automatic variable.
    [string] $OciProfile = 'DEFAULT',
    [switch] $Yes,

    [Parameter(ParameterSetName = 'Connect', Mandatory = $true)]
    [switch] $Connect,
    [Parameter(ParameterSetName = 'Stop', Mandatory = $true)]
    [switch] $Stop,
    [Parameter(ParameterSetName = 'Start', Mandatory = $true)]
    [switch] $Start,
    [Parameter(ParameterSetName = 'Teardown', Mandatory = $true)]
    [switch] $Teardown
)

$ErrorActionPreference = 'Stop'
$Shape = 'VM.BaseDB.x86'
$DbName = 'ORCLCDB'
$PdbName = 'ORCLPDB1'
# 1521-1528 are test/compose.yaml's; the tunnel's local end takes the next one.
$TunnelPort = 1529
$PurposeTag = 'sopuli-dba-581'
# Bastion names are alphanumeric only.
$BastionName = ($Name -replace '[^A-Za-z0-9]', '') + 'bastion'
# Hostname: at most 16 characters, alphanumeric and hyphens.
$HostName = ($Name -replace '[^A-Za-z0-9-]', '')
if ($HostName.Length -gt 16) { $HostName = $HostName.Substring(0, 16) }

$Tmp = Join-Path ([IO.Path]::GetTempPath()) "sopuli-dbcs-$PID"
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
# Owner-only, explicitly: launch.json will hold the SYS password, and an
# inherited ACL is only as private as wherever TEMP happens to point. icacls
# rather than Set-Acl, which does not load in every PowerShell this runs in.
# Refused before any prompt if it cannot be enforced.
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $Tmp /inheritance:r /grant:r "*${me}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
    throw "Could not make $Tmp private to the current user (icacls exit $LASTEXITCODE); nothing has been done."
}

# ---------------------------------------------------------------- helpers ---

function Invoke-Oci {
    # Runs `oci`, returns parsed JSON (or $null for an empty body), and throws
    # with the service's own message on failure.
    param([string[]] $Arguments)
    $errFile = Join-Path $Tmp 'stderr.txt'
    # 'Continue' here: under 'Stop', Windows PowerShell 5.1 turns the first line
    # a native command writes to a redirected stderr into a terminating error,
    # and oci writes progress there on success.
    $ErrorActionPreference = 'Continue'
    $out = & oci @Arguments --profile $OciProfile 2> $errFile
    $code = $LASTEXITCODE
    $err = Get-Content -Raw -ErrorAction SilentlyContinue $errFile
    # Both streams on failure: a service error arrives on stderr, but a usage
    # error ("No such option") arrives on stdout, and reporting only one left
    # the message empty.
    if ($code -ne 0) { throw "oci $($Arguments[0..2] -join ' ') failed (exit $code):`n$err$(($out | Out-String).Trim())" }
    $text = ($out | Out-String).Trim()
    # -ErrorAction Stop: under 'Continue' a parse failure would return nothing,
    # and a list call that returns nothing reads as "no such resource" -- which
    # would plan a second, billable one.
    if ($text) { return $text | ConvertFrom-Json -ErrorAction Stop }
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

function Read-AdminPassword {
    # Prompted, never a parameter: a parameter is argv, and argv is `ps`.
    # OCI's rule: 9-30 characters, at least two each of upper, lower, digit and
    # one of _ # -, and nothing else. The double quote that invariant 11 is about
    # is therefore already impossible.
    while ($true) {
        $first = Read-Host 'SYS / SYSTEM / PDB admin password' -AsSecureString
        $second = Read-Host 'Again' -AsSecureString
        $a = ConvertFrom-Secure $first
        $b = ConvertFrom-Secure $second
        if ($a -cne $b) { Write-Host '  They differ; again.'; continue }
        $problems = @()
        if ($a.Length -lt 9 -or $a.Length -gt 30) { $problems += '9 to 30 characters' }
        if ($a -cnotmatch '^[A-Za-z0-9_#-]+$') { $problems += 'only letters, digits and _ # -' }
        foreach ($rule in @(@('[A-Z]', 'two uppercase'), @('[a-z]', 'two lowercase'),
                            @('[0-9]', 'two digits'), @('[_#-]', 'two of _ # -'))) {
            if (([regex]::Matches($a, $rule[0], 'None')).Count -lt 2) { $problems += $rule[1] }
        }
        if ($problems.Count -eq 0) { return $a }
        Write-Host "  OCI will refuse it; it needs: $($problems -join ', ')."
    }
}

function ConvertFrom-Secure {
    param([Security.SecureString] $Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Wait-DbSystem {
    # `oci db system get` has no --wait-for-state, unlike `compute instance get`,
    # so poll. Returns the DB system once it leaves PROVISIONING / UPDATING.
    param([string] $Id, [int] $MaxMinutes = 120)
    $deadline = (Get-Date).AddMinutes($MaxMinutes)
    while ($true) {
        $d = (Invoke-Oci @('db', 'system', 'get', '--db-system-id', $Id)).data
        if ($d.'lifecycle-state' -notin @('PROVISIONING', 'UPDATING')) { return $d }
        if ((Get-Date) -gt $deadline) {
            throw "Still $($d.'lifecycle-state') after $MaxMinutes minutes; re-run later, it is picked up where it is."
        }
        Write-Host ("    {0:HH:mm} {1}" -f (Get-Date), $d.'lifecycle-state')
        Start-Sleep -Seconds 60
    }
}

function Resolve-AllowSshFrom {
    # One address, as the plan and the docs promise: a bare IPv4 becomes a /32,
    # and anything wider -- 0.0.0.0/0 included -- is refused rather than written
    # into a security list or a bastion's allow-list.
    param([string] $Value)
    if (-not $Value) {
        $Value = (Invoke-RestMethod -Uri 'https://checkip.amazonaws.com' -TimeoutSec 15).Trim()
    }
    if ($Value -match '^(\d{1,3}(\.\d{1,3}){3})(/32)?$' -and
        ($Matches[1] -split '\.' | Where-Object { [int]$_ -gt 255 }).Count -eq 0) {
        return "$($Matches[1])/32"
    }
    throw "-AllowSshFrom must be one IPv4 address (optionally with /32), not '$Value'."
}

function Get-DbNode {
    param($DbSystem)
    $nodes = @(Get-Live (Invoke-Oci @('db', 'node', 'list', '--compartment-id', $compartment,
               '--db-system-id', $DbSystem.id)))
    if ($nodes.Count -ne 1) { throw "Expected one DB node on $($DbSystem.'display-name'), found $($nodes.Count)." }
    return $nodes[0]
}

try {

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
$dbSystem = Select-Ours (Invoke-Oci @('db', 'system', 'list', '--compartment-id', $compartment, '--display-name', $Name)) 'DB system'
$bastion = Select-Ours (Invoke-Oci @('bastion', 'bastion', 'list', '--compartment-id', $compartment, '--name', $BastionName, '--all')) 'bastion'

# ------------------------------------------------------------ connect -----

if ($Connect) {
    if (-not $dbSystem) { throw "No DB system named $Name in '$CompartmentName'." }
    $AllowSshFrom = Resolve-AllowSshFrom $AllowSshFrom
    $privateKey = $SshPublicKeyFile -replace '\.pub$', ''
    if (-not (Test-Path $SshPublicKeyFile) -or -not (Test-Path $privateKey)) {
        throw "-Connect needs both halves of the key: $SshPublicKeyFile and $privateKey."
    }
    $node = Get-DbNode $dbSystem
    if ($node.'lifecycle-state' -ne 'AVAILABLE') { throw "$Name's node is $($node.'lifecycle-state'); -Start it first." }
    $privateIp = (Invoke-Oci @('network', 'vnic', 'get', '--vnic-id', $node.'vnic-id')).data.'private-ip'
    $cidrs = Write-JsonFile 'cidrs.json' "[`"$AllowSshFrom`"]"

    if (-not $bastion) {
        Write-Host "Creating bastion $BastionName in $Name's subnet, admitting $AllowSshFrom only ..."
        Invoke-Oci @('bastion', 'bastion', 'create', '--bastion-type', 'STANDARD',
                     '--compartment-id', $compartment, '--target-subnet-id', $dbSystem.'subnet-id',
                     '--name', $BastionName, '--client-cidr-list', $cidrs, '--max-session-ttl', '10800',
                     '--freeform-tags', (Write-JsonFile 'tags.json' "{`"purpose`":`"$PurposeTag`"}"),
                     '--wait-for-state', 'SUCCEEDED', '--wait-for-state', 'FAILED') | Out-Null
        $bastion = Select-Ours (Invoke-Oci @('bastion', 'bastion', 'list', '--compartment-id', $compartment,
                                             '--name', $BastionName, '--all')) 'bastion'
        if (-not $bastion -or $bastion.'lifecycle-state' -ne 'ACTIVE') { throw "Bastion $BastionName did not become ACTIVE." }
    } else {
        # The one thing a re-run changes: your address may have moved.
        Invoke-Oci @('bastion', 'bastion', 'update', '--bastion-id', $bastion.id, '--client-cidr-list', $cidrs,
                     '--force', '--wait-for-state', 'SUCCEEDED', '--wait-for-state', 'FAILED') | Out-Null
    }

    Write-Host "Opening a 3-hour port-forwarding session to ${privateIp}:1521 ..."
    $sessionName = "$Name-$(Get-Date -Format 'yyyyMMddHHmmss')"
    Invoke-Oci @('bastion', 'session', 'create-port-forwarding', '--bastion-id', $bastion.id,
                 '--display-name', $sessionName, '--ssh-public-key-file', $SshPublicKeyFile,
                 '--target-private-ip', $privateIp, '--target-port', '1521', '--session-ttl', '10800',
                 '--wait-for-state', 'SUCCEEDED', '--wait-for-state', 'FAILED') | Out-Null
    $session = @(Get-Items (Invoke-Oci @('bastion', 'session', 'list', '--bastion-id', $bastion.id,
                 '--display-name', $sessionName, '--all')))[0]
    if (-not $session -or $session.'lifecycle-state' -ne 'ACTIVE') { throw "Session $sessionName did not become ACTIVE." }
    $session = (Invoke-Oci @('bastion', 'session', 'get', '--session-id', $session.id)).data
    # OCI hands back the command with <privateKey> and <localPort> placeholders.
    # Literal replacement, and the key path quoted: a Windows profile path can
    # hold spaces, and -replace would read a `$` in it as a group reference.
    $command = $session.'ssh-metadata'.command.Replace('<privateKey>', "`"$privateKey`"").Replace('<localPort>', "$TunnelPort")
    Write-Host ''
    Write-Host "Session $sessionName is ACTIVE for three hours. Leave this running:"
    Write-Host "  $command"
    Write-Host "  # then 127.0.0.1:$TunnelPort is the listener; the service names are in the Ready report"
    exit 0
}

# ------------------------------------------------------- stop / start -----

if ($Stop -or $Start) {
    if (-not $dbSystem) { throw "No DB system named $Name in '$CompartmentName'." }
    $node = Get-DbNode $dbSystem
    $want = if ($Stop) { 'STOPPED' } else { 'AVAILABLE' }
    if ($node.'lifecycle-state' -eq $want) { Write-Host "$Name's node is already $want. Nothing done."; exit 0 }
    $verb = if ($Stop) { 'stop' } else { 'start' }
    Write-Host "Asking $Name's node ($($node.'lifecycle-state')) to $verb; waits for $want, several minutes ..."
    $t0 = Get-Date
    Invoke-Oci @('db', 'node', $verb, '--db-node-id', $node.id, '--wait-for-state', $want,
                 '--max-wait-seconds', '1800') | Out-Null
    Write-Host ("{0} after {1:mm\:ss}." -f $want, ((Get-Date) - $t0))
    if ($Stop) { Write-Host 'ECPU billing has stopped; storage still bills until -Teardown.' }
    exit 0
}

# ----------------------------------------------------------- teardown -----

if ($Teardown) {
    Write-Host "Teardown in compartment '$CompartmentName':"
    Write-Host "  DB system $Name  $(if ($dbSystem) { $dbSystem.id } else { '(none)' })  -- database and storage with it, no backups"
    Write-Host "  bastion   $BastionName  $(if ($bastion) { $bastion.id } else { '(none)' })  -- its sessions with it"
    Write-Host "  network   $vcnName  $(if ($vcn) { $vcn.id } else { '(none)' })  -- subnet, security list, gateway, VCN"
    if (-not $dbSystem -and -not $bastion -and -not $vcn) { Write-Host 'Nothing to remove.'; exit 0 }

    # The VCN is ours by tag, but what is inside it need not be. Everything the
    # loops below delete must be one of the three things this script creates,
    # by name AND tag; anything else -- a subnet, gateway or security list
    # somebody added later -- refuses the whole teardown before anything is
    # deleted, rather than being swept away with the VCN.
    $vcnContents = @()
    if ($vcn) {
        $subnets  = @(Get-Live (Invoke-Oci @('network', 'subnet', 'list', '--compartment-id', $compartment, '--vcn-id', $vcn.id)))
        $gateways = @(Get-Live (Invoke-Oci @('network', 'internet-gateway', 'list', '--compartment-id', $compartment, '--vcn-id', $vcn.id)))
        $lists    = @(Get-Live (Invoke-Oci @('network', 'security-list', 'list', '--compartment-id', $compartment, '--vcn-id', $vcn.id)) |
                      Where-Object { $_.id -ne $vcn.'default-security-list-id' })
        $foreign = @()
        foreach ($pair in @(@($subnets, $subnetName, 'subnet'), @($gateways, $igwName, 'internet gateway'),
                            @($lists, $slName, 'security list'))) {
            foreach ($r in $pair[0]) {
                if ($r.'display-name' -ne $pair[1] -or $r.'freeform-tags'.purpose -ne $PurposeTag) {
                    $foreign += "$($pair[2]) '$($r.'display-name')' ($($r.id))"
                }
            }
        }
        if ($foreign.Count -gt 0) {
            throw ("$vcnName holds resources this script did not create, so nothing has been deleted:`n  " +
                   ($foreign -join "`n  ") + "`nRemove or move them first, then re-run -Teardown.")
        }
        $vcnContents = @($subnets) + @($gateways) + @($lists)
    }
    Confirm-Plan 'Delete all of the above? The database goes with it.'

    if ($dbSystem) {
        Write-Host "Terminating $Name (waits for TERMINATED, can take half an hour) ..."
        $t0 = Get-Date
        Invoke-Oci @('db', 'system', 'terminate', '--db-system-id', $dbSystem.id, '--force',
                     '--wait-for-state', 'TERMINATED', '--max-wait-seconds', '3600') | Out-Null
        Write-Host ("Terminated after {0:hh\:mm\:ss}." -f ((Get-Date) - $t0))
    }
    if ($bastion) {
        # Before the subnet: a bastion holds an endpoint in it.
        Write-Host "Deleting bastion $BastionName ..."
        Invoke-Oci @('bastion', 'bastion', 'delete', '--bastion-id', $bastion.id, '--force',
                     '--wait-for-state', 'SUCCEEDED', '--wait-for-state', 'FAILED') | Out-Null
    }
    if ($vcn) {
        foreach ($s in $subnets) {
            Write-Host "Deleting subnet $($s.'display-name') ..."
            Invoke-Oci @('network', 'subnet', 'delete', '--subnet-id', $s.id, '--force', '--wait-for-state', 'TERMINATED') | Out-Null
        }
        # The default route table cannot be deleted, only emptied, and a gateway
        # it still points at cannot be deleted either.
        Invoke-Oci @('network', 'route-table', 'update', '--rt-id', $vcn.'default-route-table-id',
                     '--route-rules', (Write-JsonFile 'no-routes.json' '[]'), '--force') | Out-Null
        foreach ($g in $gateways) {
            Write-Host "Deleting internet gateway $($g.'display-name') ..."
            Invoke-Oci @('network', 'internet-gateway', 'delete', '--ig-id', $g.id, '--force', '--wait-for-state', 'TERMINATED') | Out-Null
        }
        foreach ($l in $lists) {
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
$AllowSshFrom = Resolve-AllowSshFrom $AllowSshFrom

if (-not $dbSystem -and [Console]::IsInputRedirected) {
    # A new DB system needs the password typed at a prompt, and redirected input
    # cannot answer one -- it would wait forever at the first Read-Host instead.
    throw 'Creating a DB system prompts for the SYS password; run this from an interactive terminal.'
}

if (-not $dbSystem) {
    $versions =@(Get-Items (Invoke-Oci @('db', 'version', 'list', '--compartment-id', $compartment, '--all',
                  '--db-system-shape', $Shape, '--storage-management', 'LVM')) | ForEach-Object { $_.version })
    if (-not $DbVersion) {
        # '19.0.0.0' means "whatever is newest at launch" and records nothing;
        # pick the explicit RU it stands for so the plan can name it.
        $DbVersion = $versions | Where-Object { $_ -match '^19\.(\d+)\.0\.0$' -and $_ -ne '19.0.0.0' } |
            Sort-Object { [int]($_ -split '\.')[1] } -Descending | Select-Object -First 1
        if (-not $DbVersion) { throw "No explicit 19.N.0.0 offered for $Shape with LVM; offered: $($versions -join ', ')." }
    } elseif ($DbVersion -notin $versions) {
        throw "$DbVersion is not offered for $Shape with LVM; offered: $($versions -join ', ')."
    }

    $ads = @(Get-Items (Invoke-Oci @('iam', 'availability-domain', 'list', '--compartment-id', $tenancy)) | ForEach-Object { $_.name })
    if ($AvailabilityDomain) { $ads = @($ads | Where-Object { $_ -eq $AvailabilityDomain }) }
    # The ECPU limit is per AD, not regional, so look for an AD with room.
    $chosenAd = $null
    foreach ($ad in $ads) {
        $avail = (Invoke-Oci @('limits', 'resource-availability', 'get', '--service-name', 'database',
                  '--limit-name', 'vm-basedb-x86-ecpu-count', '--compartment-id', $tenancy,
                  '--availability-domain', $ad)).data
        if ($avail.available -ge $Ecpus) { $chosenAd = $ad; break }
        Write-Host "  $ad has $($avail.available) of vm-basedb-x86-ecpu-count left ($($avail.used) used)."
    }
    if (-not $chosenAd) { throw "No availability domain has $Ecpus ECPU of vm-basedb-x86-ecpu-count left; nothing has been created." }
}

if (-not $vcn) {
    $avail = (Invoke-Oci @('limits', 'resource-availability', 'get', '--service-name', 'vcn',
              '--limit-name', 'vcn-count', '--compartment-id', $tenancy)).data
    if ($avail.available -lt 1) {
        throw ("No VCN left to create: vcn-count is $($avail.used) used, $($avail.available) available. " +
               "Delete an unused VCN first; nothing has been created.")
    }
}

Write-Host ''
Write-Host "Plan, compartment '$CompartmentName' ($compartment):"
Write-Host "  network    $vcnName 10.0.0.0/16, $subnetName 10.0.0.0/24, $igwName  $(if ($vcn) { '(exists, reused)' } else { '(create)' })"
Write-Host "  ingress    tcp/22 from $AllowSshFrom only, tcp/1521 from inside the VCN, ICMP 3/4 for path MTU"
if ($dbSystem) {
    Write-Host "  DB system  $Name  (exists, $($dbSystem.'lifecycle-state'), reused)"
} else {
    Write-Host "  DB system  $Name  $Shape  $Ecpus ECPU  LVM $DataStorageGB GB  single node  (create)"
    Write-Host "  database   $DbVersion  $DatabaseEdition  LICENSE_INCLUDED  CDB $DbName, PDB $PdbName, no automatic backups"
    Write-Host "  AD         $chosenAd"
    Write-Host "  host       $HostName   ssh key $SshPublicKeyFile"
    Write-Host '  cost       bills per ECPU-hour while the node runs, and for storage until -Teardown'
}
Write-Host ''
Confirm-Plan 'Proceed?'

# The password is asked for after the plan is accepted, so a declined plan
# never asks for one.
$adminPassword = if ($dbSystem) { $null } else { Read-AdminPassword }

# ------------------------------------------------------------ network -----

$tags = Write-JsonFile 'tags.json' "{`"purpose`":`"$PurposeTag`"}"

if (-not $vcn) {
    Write-Host "Creating VCN $vcnName ..."
    # A DB system needs DNS labels on the VCN and the subnet: its host name is
    # registered in the VCN resolver, and the database domain is the subnet's.
    $vcn = (Invoke-Oci @('network', 'vcn', 'create', '--compartment-id', $compartment,
            '--cidr-blocks', (Write-JsonFile 'cidrs.json' '["10.0.0.0/16"]'),
            '--display-name', $vcnName, '--dns-label', 'sopulidb',
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

# 1521 from inside the VCN only: the tunnel arrives from the node itself, and
# nothing outside the VCN reaches the listener.
$ingress = Write-JsonFile 'ingress.json' (@"
[
  {"source": "$AllowSshFrom", "protocol": "6", "isStateless": false,
   "tcpOptions": {"destinationPortRange": {"min": 22, "max": 22}}},
  {"source": "10.0.0.0/16", "protocol": "6", "isStateless": false,
   "tcpOptions": {"destinationPortRange": {"min": 1521, "max": 1521}}},
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
} elseif (@($subnet.'security-list-ids').Count -ne 1 -or $subnet.'security-list-ids'[0] -ne $sl.id) {
    # A reused subnet is ours by tag, but its lists may have been changed since.
    # Put it back to the SSH-only list alone, so the restriction the report
    # states is the one in force.
    Write-Host "Subnet $subnetName had other security lists attached; resetting it to $slName only ..."
    $subnet = (Invoke-Oci @('network', 'subnet', 'update', '--subnet-id', $subnet.id,
            '--security-list-ids', (Write-JsonFile 'sl.json' "[`"$($sl.id)`"]"),
            '--force', '--wait-for-state', 'AVAILABLE')).data
}

# ---------------------------------------------------------- DB system -----

if (-not $dbSystem) {
    # Everything goes in one --from-json file, because the password must not be
    # an argument. The file lives in $Tmp, which the finally block deletes.
    $launch = [ordered]@{
        compartmentId              = $compartment
        availabilityDomain         = $chosenAd
        displayName                = $Name
        hostname                   = $HostName
        shape                      = $Shape
        computeModel               = 'ECPU'
        computeCount               = $Ecpus
        nodeCount                  = 1
        storageManagement          = 'LVM'
        initialDataStorageSizeInGb = $DataStorageGB
        subnetId                   = $subnet.id
        sshAuthorizedKeysFile      = $SshPublicKeyFile
        databaseEdition            = $DatabaseEdition
        licenseModel               = 'LICENSE_INCLUDED'
        dbVersion                  = $DbVersion
        dbName                     = $DbName
        pdbName                    = $PdbName
        dbWorkload                 = 'OLTP'
        adminPassword              = $adminPassword
        autoBackupEnabled          = $false
        freeformTags               = @{ purpose = $PurposeTag }
    }
    $launchFile = Write-JsonFile 'launch.json' ($launch | ConvertTo-Json -Depth 4)
    $adminPassword = $null

    # A dry run validates the whole request -- shape, version, subnet, password
    # rules -- before anything that bills exists.
    Write-Host 'Validating the request (opc-dry-run) ...'
    Invoke-Oci @('db', 'system', 'launch', '--from-json', $launchFile, '--opc-dry-run', 'true') | Out-Null

    Write-Host "Launching $Name in $chosenAd ..."
    $t0 = Get-Date
    $dbSystem = (Invoke-Oci @('db', 'system', 'launch', '--from-json', $launchFile)).data
    Remove-Item -Force (Join-Path $Tmp 'launch.json')
    Write-Host "  $($dbSystem.id)"
    Write-Host '  Waiting for AVAILABLE (typically well over half an hour; Ctrl-C is safe, a re-run picks it up) ...'
    $dbSystem = Wait-DbSystem $dbSystem.id
    Write-Host ("  {0} after {1:hh\:mm\:ss}." -f $dbSystem.'lifecycle-state', ((Get-Date) - $t0))
}

switch ($dbSystem.'lifecycle-state') {
    'AVAILABLE' { }
    { $_ -in @('PROVISIONING', 'UPDATING') } {
        Write-Host "Waiting for $Name ($($dbSystem.'lifecycle-state')) to reach AVAILABLE ..."
        $dbSystem = Wait-DbSystem $dbSystem.id
    }
}
if ($dbSystem.'lifecycle-state' -ne 'AVAILABLE') {
    throw ("$Name is $($dbSystem.'lifecycle-state'): $($dbSystem.'lifecycle-details') " +
           "Read the work request in the console; -Teardown removes it.")
}

# ------------------------------------------------------------- report -----

$node = Get-DbNode $dbSystem
if ($node.'lifecycle-state' -eq 'STOPPED') {
    Write-Host "Note: the node is STOPPED. Start it with -Start."
}
$vnic = (Invoke-Oci @('network', 'vnic', 'get', '--vnic-id', $node.'vnic-id')).data

# The DB home is read for its version: the DB system's own `version` is empty.
$dbHome = @(Get-Live (Invoke-Oci @('db', 'db-home', 'list', '--compartment-id', $compartment,
            '--db-system-id', $dbSystem.id)))[0]
$database = @(Get-Live (Invoke-Oci @('db', 'database', 'list', '--compartment-id', $compartment,
              '--db-system-id', $dbSystem.id)))[0]
$pdb = @(Get-Live (Invoke-Oci @('db', 'pluggable-database', 'list', '--database-id', $database.id)))[0]

# The service names carry the subnet's domain; take them from what OCI reports
# rather than assembling them, and put the tunnel's end in place of the host.
$cdbService = ($database.'connection-strings'.'cdb-default' -split '/', 2)[1]
$pdbService = if ($pdb) { ($pdb.'connection-strings'.'pdb-default' -split '/', 2)[1] } else { '(no PDB listed)' }

Write-Host ''
Write-Host "Ready: $Name  $($dbSystem.id)"
Write-Host "  version    $($dbHome.'db-version')  $($dbSystem.'database-edition')"
Write-Host "  node       $($node.hostname)  public $($vnic.'public-ip')  private $($vnic.'private-ip')  ($($node.'lifecycle-state'))"
Write-Host "  SSH        from $AllowSshFrom only; user 'opc'"
Write-Host ''
Write-Host 'Reach the listener through a Bastion session, never through the internet:'
Write-Host "  ./new-db-system.ps1 -CompartmentName $CompartmentName -Connect"
Write-Host "  # PDB  127.0.0.1:${TunnelPort}/$pdbService"
Write-Host "  # CDB  127.0.0.1:${TunnelPort}/$cdbService"
Write-Host "  # sopuli: oracle: { scope: pdb, container: $PdbName }"
Write-Host ''
Write-Host "Stop it between sessions (-Stop) and remove it when done (-Teardown)."

} finally {
    # launch.json holds the SYS password until the launch call returns, and this
    # is its only cleanup when a call fails. Say so if it survives.
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
    if (Test-Path $Tmp) {
        Write-Warning ("Could not remove $Tmp" +
            $(if (Test-Path (Join-Path $Tmp 'launch.json')) { ', and launch.json in it holds the SYS password' } else { '' }) +
            '. Delete it by hand.')
    }
}
