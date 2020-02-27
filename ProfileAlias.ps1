# Find profile settings
code $profile

# This insipired by code from https://github.com/mikebattista/PowerShell-WSL-Interop
$commands = "Scan-Sslyze", "Scan-pshtt", "Scan-ZapBaseline", "Scan-ZapFull", "Scan-ZapMassScan","Scan-Httpie"

function global:New-AliasCommand() {
    <#
    .SYNOPSIS
    Create Aliases to commands from outside powershell with default parameters

    .DESCRIPTION
    This function creates alias with these steps:
    
    * Creating PowerShell function wrappers for commands
    * Default parameters are supported by $AliasDefaultParameterValues similar to $PSDefaultParameterValues
    * Command completion is enabled by PowerShell's command completion
    The commands can receive both pipeline input as well as their corresponding arguments just as if they were native to Windows.
    Additionally, they will honor any default parameters defined in a hash table called $AliasDefaultParameterValues similar to $PSDefaultParameterValues. For example:
    * $AliasDefaultParameterValues["grep"] = "-E"
    * $AliasDefaultParameterValues["less"] = "-i"
    * $AliasDefaultParameterValues["ls"] = "-AFh --group-directories-first"
    If you use aliases or environment variables within your login profiles to set default parameters for commands, define a hash table called $AliasDefaultParameterValues within
    your PowerShell profile and populate it as above for a similar experience.
    The import of these functions replaces any PowerShell aliases that conflict with the commands.

    .PARAMETER Command
    Specifies the commands to import.

    .EXAMPLE
    Import-WslCommand "awk", "emacs", "grep", "head", "less", "ls", "man", "sed", "seq", "ssh", "tail", "vim"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Command
    )

    # Register an alias for each command.
    $Command | ForEach-Object { Set-Alias $_ Invoke-WslCommand -Scope Global -Force }
}
# Register a function for each command.
$commands | ForEach-Object { Invoke-Expression @"
Remove-Alias $_ -Force -ErrorAction Ignore
function global:$_() {
    for (`$i = 0; `$i -lt `$args.Count; `$i++) {
        # If a path is absolute with a qualifier (e.g. C:), run it through wslpath to map it to the appropriate mount point.
        if (Split-Path `$args[`$i] -IsAbsolute -ErrorAction Ignore) {
            `$args[`$i] = Format-WslArgument (wsl.exe wslpath (`$args[`$i] -replace "\\", "/"))
        # If a path is relative, the current working directory will be translated to an appropriate mount point, so just format it.
        } elseif (Test-Path `$args[`$i] -ErrorAction Ignore) {
            `$args[`$i] = Format-WslArgument (`$args[`$i] -replace "\\", "/")
        }
    }
 
    if (`$input.MoveNext()) {
        `$input.Reset()
        `$input | wsl.exe $_ (`$args -split ' ')
    } else {
        wsl.exe $_ (`$args -split ' ')
    }
}
"@
}
function New-BashStyleAlias([string]$name, [string]$command)
{
    $sb = [scriptblock]::Create($command)
    New-Item "Function:\global:$name" -Value $sb | Out-Null
}

New-BashStyleAlias Scan-Sslyze 'docker run --rm -it nablac0d3/sslyze --regular @args'
New-BashStyleAlias Scan-Pshtt 'pshtt --json @args'
New-BashStyleAlias Scan-ZapBaseline 'docker run --rm -t owasp/zap2docker-weekly zap-baseline.py -t @args'
New-BashStyleAlias Scan-ZapFull 'docker run --rm -t owasp/zap2docker-weekly zap-full-scan.py -t @args'
New-BashStyleAlias Scan-ZapMassScan 'docker run -u zap -it rick.miner/mass-baseline mass-baseline.sh'
New-BashStyleAlias Scan-Httpie 'docker run --rm -it alpine/httpie --follow --all --print=h @args'