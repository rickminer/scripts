param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    [String]$FilePath = $(Read-Host "Enter the input CSV")
)
#Export Detailed list with Plugin,IP Address,Repository,Plugin Text,Last Observed from SC PluginID=10902
$users = @{}
$file = (Get-Item $FilePath).BaseName
Import-Csv $FilePath | % {
    $ip = $_.'IP Address'
    $list = $_.'Plugin Text' -split "  - "
    $system = $_.'Repository' -replace ' CyberScope', ''
    if ( -not $users.ContainsKey($system) ) { $users[$system] = @{} }
    #Remove first element and trim
    $list[1..($list.Length-1)] | .{ process { $_.Trim() } } | % {
        $isLocal = -not ($_ -match '^(NMFS|PIFSC|FPIR)')
        $user = (Get-Culture).TextInfo.ToTitleCase(($_ -replace '^[^\\]+\\(.+) \(.*(User|Group|Unknown|Alias).*\)$','$1'))
        Write-Output $_
        if ( $users[$system].ContainsKey($user) ) {
            $users[$system][$user].Hosts += ";" + $ip
            $users[$system][$user].Count += 1
        } else {
            $isUser = $_ -match '\(User\)$'
            $isGroup = $_ -match '\(Group\)$'
            $users[$system][$user] = [ordered]@{
                System = $system
                User = $user
                Username = $_;
                Hosts = $ip;
                Count = 1;
                UserType = $_ -replace '^.+\(.*(User|Group|Unknown|Alias).*\)$','$1';
                Enabled = 'Local';
                PIVRequired = 'PIV N/A'
            }
            if ( $isGroup ) { $users[$system][$user].Enabled = 'Group' }
            if ( $isLocal ) { $users[$system][$user].Location = 'Local' } else { $users[$system][$user].Location = 'Domain' }
            if ( -not $isLocal -and $isUser ) {
                #Look up the AD info
                Try {
                    $aduser = Get-ADUser $users[$system][$user].User -Properties SmartcardLogonRequired
                    if ( $aduser.Enabled ) { $users[$system][$user].Enabled = "Enabled" } else { $users[$system][$user].Enabled = "Disabled" }
                    if ( $aduser.SmartcardLogonRequired ) { $users[$system][$user].PIVRequired = 'PIV Required' } else { $users[$system][$user].PIVRequired = 'Not Required' }
                } Catch {
                    $users[$system][$user].Enabled = "Not Found"
                    $users[$system][$user].PIVRequired = "Not Found"
                }
            }
        }
        # Domain Admins list gets too long for Excal, just say all.
        if ( $user -eq "Domain Admins" ) { $users[$system][$user].Hosts = "All" }
    }
}
$users.Keys | % { $users.Item($_).GetEnumerator() | % { New-Object PSObject -Property $_.Value } } | Export-Csv "$file Report.csv" -NoTypeInformation
New-Item -Type Directory -Name "$file Reports" -ErrorAction SilentlyContinue | Out-Null
$users.Keys | % { $sys = $_; $users.Item($_).GetEnumerator() | % { New-Object PSObject -Property $_.Value } | Export-Csv "$file Reports\$sys Report.csv" -NoTypeInformation }
