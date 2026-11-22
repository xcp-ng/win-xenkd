<#
.SYNOPSIS
    Enables kernel debugging through the xenkd device.

.DESCRIPTION
    Finds the xenkd PCI device (5853:c201), installs its DLL (kd_<class>_5853.dll) from the current directory into
    System32 if it's there (otherwise it must already be installed), and points the kernel debugger at the device.
    Takes effect after a reboot.

.PARAMETER HostIp
    The debugger's address as the guest sees it, on the private network it shares with the dom0 bridge: the bridge's
    --destination. Where the debugger really runs is given to the bridge.

.PARAMETER Port
    The debugger's port as the guest sees it: the bridge's --destination, not WinDbg's port.

.PARAMETER Key
    KDNET encryption key. If omitted, bcdedit generates one and prints it.

.PARAMETER BootDebug
    Also debug bootmgr and winload, over a serial port. The kernel still goes through xenkd.

.PARAMETER ComPort
    With -BootDebug, the serial port for boot debugging.

.PARAMETER BaudRate
    With -BootDebug, the serial port's baud rate.

.PARAMETER TargetIp
    The guest's address on the private network: the bridge's --guest-ip. Fixed, since the bridge doesn't answer DHCP.

.PARAMETER IoPort
    Rendezvous I/O port: the bridge's --io-port. All four bytes must be reserved in guest ACPI and unused by other
    virtual hardware.

.PARAMETER Clear
    Turn debugging off and remove the BCD settings this script makes. Nothing else is changed.

.PARAMETER ClearAll
    Like -Clear, and also delete the xenkd DLL, and give xencons and xenbus back the default console that older
    versions of this script took (xenbus's ConsoleLogLevel can't be restored).

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
# After the help block: right in front of it, #Requires hides it from Get-Help.
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Kernel')]
param(
    # The default addresses are link-local, since the network is a private link, and in 169.254.0.0/24, which
    # automatic addressing never assigns (RFC 3927): Windows can't give itself either of them.
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
    [Parameter(ParameterSetName = 'Kernel')]
    [Parameter(ParameterSetName = 'BootDebug')]
    [ValidateRange(4, 65532)]
    [ValidateScript({ ($_ -band 3) -eq 0 })]
    [int]$IoPort = 0xEC,
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

# Drop the words matching $Remove from the loader's loadoptions and append $Add, keeping everything else.
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

# winload's kernel-only busparams element, which bcdedit has no name for. Like dbgtransport, the kernel prefers it to
# {dbgsettings}, which is all the boot debugger reads: -BootDebug uses both to keep the kernel on xenkd.
$KernelBusParams = 'custom:2200012D'

# With viridian, Xen looks like Hyper-V to winload, which then replaces the net debug device with the Hyper-V synthetic
# one and ignores busparams, unless the load options carry this flag.
$HvFlag = 'FORCEHVTONOTSHAREDEBUGDEVICE'

# KDNET's settings, which it reads from the load options. winload only adds them when {dbgsettings} is net, so
# -BootDebug adds them itself. Without ENCRYPTION_KEY, KDNET bugchecks (0x7E).
$KdNetOptions = @('HOST_IP=\S*', 'HOST_PORT=\S*', 'ENCRYPTION_KEY=\S*', 'TARGET_IP=\S*', 'NO_DHCP')
$XenKdOptions = @('XENKD_IOPORT=\S*')

if ($Clear -or $ClearAll) {
    Invoke-Bcdedit @('/debug', 'off')
    Invoke-Bcdedit @('/bootdebug', 'off')
    Remove-BcdValue '{current}' 'dbgtransport'
    Remove-BcdValue '{current}' $KernelBusParams

    # Drop only our options from the load options, keeping anything else that's there.
    Update-LoadOptions -Remove (@($HvFlag) + $KdNetOptions + $XenKdOptions)

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

        # Compatibility cleanup for installations that used the old PV-console rendezvous.
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

# Configure the debugger.
$netArgs = @('/dbgsettings', 'net', "hostip:$HostIp", "port:$Port")
if ($Key) {
    $netArgs += "key:$Key"
}
Invoke-Bcdedit $netArgs
# KDNET reads TARGET_IP and NO_DHCP from the load options in both modes. (It only accepts a TARGET_IP outside
# 169.254/16 with an encryption key, which there always is.)
$loadOptionsToAdd = @($HvFlag, "TARGET_IP=$TargetIp", 'NO_DHCP', ('XENKD_IOPORT=0x{0:X}' -f $IoPort))
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

    # Only switch the transport to serial: /dbgsettings serial would drop the net settings, which KDNET still reads.
    # busparams moves to the kernel-only element, or the boot debugger would take it for its UART's location.
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

# Replace whatever load options an earlier run left.
Update-LoadOptions -Remove (@($HvFlag) + $KdNetOptions + $XenKdOptions) -Add $loadOptionsToAdd

Invoke-Bcdedit @('/debug', 'on')

Write-Host 'Done. Reboot to start debugging through xenkd.'
