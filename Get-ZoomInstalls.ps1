Write-Output 'Looking at system wide applications...'
$locations = @('Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\')

Write-Output 'Loading all user profiles for inspection...'
# Load all of the other user hives for inspection
$users = Get-ChildItem 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' | Get-ItemProperty -Name ProfileImagePath -ErrorAction SilentlyContinue | Select-Object ProfileImagePath,PSChildName |  Where-Object {Test-Path "$($_.ProfileImagePath)\NTUSER.DAT"} | Where-Object { !(Test-Path "Microsoft.Powershell.Core\Registry::HKEY_USERS\$($_.PSChildName)") }
$users | ForEach-Object { reg load "HKU\$($_.PSChildName)" "$($_.ProfileImagePath)\NTUSER.DAT" 2>&1  | Out-Null }

Write-Output 'Looking in user profiles for applications...'
# Add Local user locations
Get-ChildItem 'Microsoft.PowerShell.Core\Registry::HKEY_USERS\' | ForEach-Object {
    if( Test-Path($_.PSPath + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\')) {
        $locations += ($_.PSPath + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\')
    }
}

Write-Output 'Detecting Zoom installations...'
$zoomInstalls = $locations | Get-ChildItem | Get-ItemProperty -Name DisplayName,DisplayVersion,InstallLocation,InstallDate,InstallSource -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion,InstallLocation,InstallDate,InstallSource,PSPath | Where-Object { $_.DisplayName -like '*oom*' }

# Unload user hives from before
Write-Output 'Unloading unneeded user profiles...'
$users | ForEach-Object { reg unload "HKU\$($_.PSChildName)" 2>&1 | Out-Null }

Write-Host '#------------------------------------------------------------#'
if ($zoomInstalls) {
    Write-Host 'Zoom installations detected:'
    Write-Output $zoomInstalls
} else {
    Write-Host 'No Zoom installations detected.'
}