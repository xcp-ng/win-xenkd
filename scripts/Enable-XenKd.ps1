#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detects the xenkd debug device and enables kernel debugging through it.

.DESCRIPTION
    Finds the Xen debug PCI device (5853:c201), installs the matching xenkd DLL (kd_<class>_5853.dll) from the current
    directory into System32 if it's there (otherwise it must already be installed), keeps xencons and xenbus off the
    default console, and configures the boot debug settings to use the device.
    Takes effect after a reboot.

.PARAMETER HostIp
    Debugger host IP for "bcdedit /dbgsettings net". KDNET requires network debug settings to load extension modules.
    bcdedit rejects 0.0.0.0, so the default is a loopback placeholder.

.PARAMETER Port
    Debugger port for "bcdedit /dbgsettings net".

.PARAMETER Key
    Debugger key. If omitted, bcdedit generates one and prints it.

.PARAMETER BootDebug
    Also enable boot debugging (bootmgr/winload) over a serial port, keeping the kernel on xenkd. The shared
    {dbgsettings} become serial and the kernel is pointed at KDNET through winload's kernel-only BCD elements
    (dbgtransport, and 0x2200012D for busparams), which the boot debugger ignores.

.PARAMETER ComPort
    With -BootDebug, the COM port used for boot debugging.

.PARAMETER BaudRate
    With -BootDebug, the baud rate of the boot debugging serial port.

.PARAMETER TargetIp
    The guest's own address on the debug network (TARGET_IP, with NO_DHCP). xenkd-bridge.py is a fake network that
    doesn't answer DHCP, and a fixed address lets a restarted bridge reach the guest before it says anything (pass the
    same one to its --guest-ip).

.PARAMETER Clear
    Instead of enabling anything, turn kernel and boot debugging off and remove every debug setting this script
    makes from the BCD. The xenkd DLL, test signing, the xenbus registry settings and the xencons device are left alone.

.PARAMETER ClearAll
    Like -Clear, and also undo everything else the script does: delete the xenkd DLL from System32, and give xencons
    and xenbus the default console back. xenbus's ConsoleLogLevel can't be restored, since the script deleted it
    without keeping the old value.

.EXAMPLE
    .\Enable-XenKd.ps1 -WhatIf

.EXAMPLE
    .\Enable-XenKd.ps1 -BootDebug -ComPort 1

.EXAMPLE
    .\Enable-XenKd.ps1 -BootDebug -TargetIp 169.254.0.3

.EXAMPLE
    .\Enable-XenKd.ps1 -Clear

.EXAMPLE
    .\Enable-XenKd.ps1 -ClearAll
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Kernel')]
param(
    [string]$HostIp = '169.254.0.1',
    [ValidateRange(1, 65535)]
    [int]$Port = 5364,
    [string]$Key,
    [Parameter(Mandatory, ParameterSetName = 'BootDebug')]
    [switch]$BootDebug,
    [Parameter(ParameterSetName = 'BootDebug')]
    [ValidateRange(1, 4)]
    [int]$ComPort = 1,
    [Parameter(ParameterSetName = 'BootDebug')]
    [int]$BaudRate = 115200,
    [Parameter(ParameterSetName = 'Kernel')]
    [Parameter(ParameterSetName = 'BootDebug')]
    [ValidateNotNullOrEmpty()]
    [string]$TargetIp = '169.254.0.2',
    [Parameter(Mandatory, ParameterSetName = 'Clear')]
    [switch]$Clear,
    [Parameter(Mandatory, ParameterSetName = 'ClearAll')]
    [switch]$ClearAll
)

$ErrorActionPreference = 'Stop'

$VendorId = '5853'
$DeviceId = 'C201'

function Invoke-Bcdedit {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Arguments)

    if ($PSCmdlet.ShouldProcess("bcdedit $($Arguments -join ' ')", 'Run')) {
        & bcdedit.exe @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "bcdedit $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
        }
    }
}

# Delete a BCD element, which is fine if it isn't set.
function Remove-BcdValue {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Id, [string]$Name)

    if ($PSCmdlet.ShouldProcess("bcdedit /deletevalue $Id $Name", 'Run')) {
        & bcdedit.exe /deletevalue $Id $Name 2>&1 | Out-Null
    }
}

# The value of a BCD element as bcdedit /enum prints it, or $null.
function Get-BcdValue {
    param([string]$Id, [string]$Name)

    (& bcdedit.exe /enum $Id | Select-String "^$Name\s+(.*)$" | Select-Object -First 1) |
    ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
}

# Rewrite the loadoptions of the OS loader entry: drop the words matching $Remove, then append $Add. /set replaces the
# whole value, so anything else that's there is kept.
function Update-LoadOptions {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Remove, [string[]]$Add)

    $old = Get-BcdValue '{current}' 'loadoptions'
    $words = @(($old -split '\s+') | Where-Object {
            $word = $_
            $word -and -not ($Remove | Where-Object { $word -match "^$_$" })
        }) + $Add
    $new = $words -join ' '
    if ($new -eq $old) {
        return
    }
    if ($new) {
        Invoke-Bcdedit @('/set', '{current}', 'loadoptions', $new)
    }
    else {
        Remove-BcdValue '{current}' 'loadoptions'
    }
}

# winload's kernel-only debugger elements: they take precedence over {dbgsettings} for the kernel, while the boot
# debugger only reads {dbgsettings}.
$KernelBusParams = 'custom:2200012D'

# With viridian, Xen looks like Hyper-V to winload, which then replaces the net debug device with the Hyper-V synthetic
# one and ignores busparams, unless the load options carry this flag.
$HvFlag = 'FORCEHVTONOTSHAREDEBUGDEVICE'

# KDNET's own settings, which it parses from the load options. winload only generates them when {dbgsettings} is net, so
# with -BootDebug they're added to loadoptions instead. Without ENCRYPTION_KEY, KDNET fails with bugcheck 0x7E.
$KdNetOptions = @('HOST_IP=\S*', 'HOST_PORT=\S*', 'ENCRYPTION_KEY=\S*', 'TARGET_IP=\S*', 'NO_DHCP')

if ($Clear -or $ClearAll) {
    Invoke-Bcdedit @('/debug', 'off')
    Invoke-Bcdedit @('/bootdebug', 'off')
    Remove-BcdValue '{current}' 'dbgtransport'
    Remove-BcdValue '{current}' $KernelBusParams

    # Drop only our options from the load options, keeping anything else that's there.
    Update-LoadOptions -Remove (@($HvFlag) + $KdNetOptions)

    # Back to the default {dbgsettings}: no transport-specific values left over.
    foreach ($name in @('debugtype', 'debugport', 'baudrate', 'busparams', 'hostip', 'port', 'key')) {
        Remove-BcdValue '{dbgsettings}' $name
    }

    if ($ClearAll) {
        # The DLL's name depends on the device's class code, so don't depend on the device still being attached.
        Get-ChildItem -Path (Join-Path $env:SystemRoot 'System32') -Filter "kd_*_$($VendorId.ToLowerInvariant()).dll" |
        ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.FullName, 'Delete')) {
                Remove-Item -LiteralPath $_.FullName -Force
            }
        }

        # Re-enable xencons' default console device.
        Get-PnpDevice | Where-Object { $_.InstanceId -like 'XENCONS\*&DEV_CONSOLE\0' -and $_.Status -eq 'Error' } |
        ForEach-Object {
            Write-Host "Enabling xencons default console $($_.InstanceId)"
            Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false
        }

        # And let xenbus acquire the default console again (it does by default).
        $parametersKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\xenbus\Parameters'
        if ($null -ne (Get-ItemProperty -LiteralPath $parametersKey -Name UseConsole -ErrorAction Ignore)) {
            if ($PSCmdlet.ShouldProcess("$parametersKey\UseConsole", 'Remove')) {
                Remove-ItemProperty -LiteralPath $parametersKey -Name UseConsole
            }
        }
    }

    Write-Host 'Done. Debugging is off after a reboot.'
    return
}

# Find the debug device. Once KDNET owns it, Windows reports it as reserved for the debugger (code 53), but it's
# still present, so don't filter on status.
$device = Get-PnpDevice -PresentOnly | `
    Where-Object { $_.InstanceId -like "PCI\VEN_$VendorId&DEV_$DeviceId*" } | `
    Select-Object -First 1
if ($null -eq $device) {
    throw "No PCI device $VendorId`:$DeviceId found. Is the xenkd device attached to this VM?"
}
Write-Host "Found $($device.FriendlyName) ($($device.InstanceId)), status $($device.Status)"

# KDNET loads kd_<class>_<vendor>.dll, where <class> is the PCI base class from the CC_xxxx hardware ID.
$ids = @($device.HardwareID)
$classMatch = $ids | `
    ForEach-Object { [regex]::Match($_, 'CC_([0-9A-Fa-f]{2})') } | `
    Where-Object Success | `
    Select-Object -First 1
if ($null -eq $classMatch) {
    throw "Cannot determine the PCI class code of $($device.InstanceId)"
}
$dllName = "kd_$($classMatch.Groups[1].Value.ToLowerInvariant())_$($VendorId.ToLowerInvariant()).dll"
$dll = Join-Path $env:SystemRoot "System32\$dllName"
$source = Join-Path (Get-Location) $dllName
if (Test-Path -LiteralPath $source) {
    if ($PSCmdlet.ShouldProcess($dll, "Copy $source")) {
        Copy-Item -LiteralPath $source -Destination $dll -Force
    }
}
elseif (-not (Test-Path -LiteralPath $dll)) {
    throw "$dll is not installed"
}

# busparams wants bus.device.function in decimal. For PCI, DEVPKEY_Device_Address is (device << 16) | function.
$bus = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_BusNumber).Data
$address = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_Address).Data
$busParams = '{0}.{1}.{2}' -f $bus, ($address -shr 16), ($address -band 0xFFFF)
Write-Host "PCI location $busParams, KDNET will load $dll"

# xencons must leave the default console to xenkd: disable its default console device (instance "0").
Get-PnpDevice | Where-Object { $_.InstanceId -like 'XENCONS\*&DEV_CONSOLE\0' } | ForEach-Object {
    Write-Host "Disabling xencons default console $($_.InstanceId)"
    Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false
}

# Stop xenbus from logging to the default console: without ConsoleLogLevel, xenbus uses its default of no logging.
$xenbusParametersKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\xenbus\Parameters'
if ($null -ne (Get-ItemProperty -LiteralPath $xenbusParametersKey -Name ConsoleLogLevel -ErrorAction Ignore)) {
    if ($PSCmdlet.ShouldProcess("$xenbusParametersKey\ConsoleLogLevel", 'Remove')) {
        Remove-ItemProperty -LiteralPath $xenbusParametersKey -Name ConsoleLogLevel
    }
}

# With UseConsole at 0, a patched xenbus doesn't acquire the default console at all: no mapping, no event channel
# binding, and xencons can't get it through xenbus either. Stock xenbus ignores the value.
if (Test-Path -LiteralPath $xenbusParametersKey) {
    if ($PSCmdlet.ShouldProcess("$xenbusParametersKey\UseConsole", 'Set to 0')) {
        Set-ItemProperty -LiteralPath $xenbusParametersKey -Name UseConsole -Type DWord -Value 0
    }
}

# Configure the debugger.
$netArgs = @('/dbgsettings', 'net', "hostip:$HostIp", "port:$Port")
if ($Key) {
    $netArgs += "key:$Key"
}
Invoke-Bcdedit $netArgs
# KDNET parses TARGET_IP and NO_DHCP from the load options itself, so they work whether or not winload generates the
# rest. It keeps a TARGET_IP outside 169.254/16 only with an encryption key, which there always is here.
$loadOptionsToAdd = @($HvFlag, "TARGET_IP=$TargetIp", 'NO_DHCP')
if ($BootDebug) {
    # Read the key back, since bcdedit generates one if -Key wasn't given.
    $netKey = $Key
    if (-not $netKey) {
        $netKey = Get-BcdValue '{dbgsettings}' 'key'
    }
    if (-not $netKey -and -not $WhatIfPreference) {
        throw 'Cannot read the debugger key from {dbgsettings}'
    }
    $loadOptionsToAdd += "HOST_IP=$HostIp", "HOST_PORT=$Port", "ENCRYPTION_KEY=$netKey"

    # Switch only the shared transport to serial with /set: /dbgsettings serial would drop the net settings above,
    # which KDNET still reads once the kernel picks it. busparams moves to the kernel-only element, or the serial boot
    # debugger would take it as the location of its UART.
    Invoke-Bcdedit @('/set', '{dbgsettings}', 'debugtype', 'serial')
    Invoke-Bcdedit @('/set', '{dbgsettings}', 'debugport', "$ComPort")
    Invoke-Bcdedit @('/set', '{dbgsettings}', 'baudrate', "$BaudRate")
    Remove-BcdValue '{dbgsettings}' 'busparams'
    Invoke-Bcdedit @('/set', '{current}', 'dbgtransport', 'kdnet.dll')
    Invoke-Bcdedit @('/set', '{current}', $KernelBusParams, $busParams)
    Invoke-Bcdedit @('/bootdebug', 'on')
}
else {
    # Clear the boot debugger and kernel-only overrides left by a previous -BootDebug run.
    Invoke-Bcdedit @('/bootdebug', 'off')
    Remove-BcdValue '{current}' 'dbgtransport'
    Remove-BcdValue '{current}' $KernelBusParams
    Invoke-Bcdedit @('/set', '{dbgsettings}', 'busparams', $busParams)
}

# Keep winload from swapping in the Hyper-V synthetic debug device ($HvFlag), and with -BootDebug pass KDNET its net
# settings and address. Stale KDNET options from an earlier run are replaced (or dropped when no longer wanted).
Update-LoadOptions -Remove (@($HvFlag) + $KdNetOptions) -Add $loadOptionsToAdd

Invoke-Bcdedit @('/debug', 'on')

Write-Host 'Done. Reboot to start debugging through xenkd.'
