#HKEY_CURRENT_USER\Software\Locky
#"id" = < Personal Identification ID>
#“pubkey” = <RSA public key received from the CnC Server>
#“paytext” = <Content of “Locky_recover_instructions.txt”>
#“completed” = “0x1” [This value will be added after completion of encryption]

# Get Workstations
#Get-ADComputer -SearchBase "OU=Computers,OU=Infrastructure,OU=HQ,OU=_NMFS,DC=nmfs,DC=local" -Filter * | select Name > computers.txt
$output = @()
Get-Content computers.txt | % {
	$computer = $_
    Write-Host $computer
	# Check to see if workstation is online
	if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
		Write-Host "- Online"
        # Enable Remote Registry
        $svc = Get-WmiObject -computerName $computer -Class Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue
        if ( -not $svc ) {
            Write-Host "- Cannot Connect"
            continue
        }
        if ($svc.State -eq 'Stopped') {
            $wasStopped = $True
            $svc.StartService() | Out-Null
        }
		# Get User registry hives
		$registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::Users,$computer)
		$users = $registry.OpenSubKey("")
		foreach ($user in $users.GetSubKeyNames()) {
			# Get printer list
			$locky = $registry.OpenSubKey("$user\\Software\\Locky")
			if ($locky) {
                $obj = New-Object PSObject
                $obj | Add-Member -MemberType NoteProperty -Name "Workstation" -Value $computer.ToUpper()
				foreach ($val in $locky.GetValueNames()) {
					$obj | Add-Member -MemberType NoteProperty -Name $val -Value $locky.GetValue("$val")
				}
                $output += $obj
                Write-Host "- Found!!!"
			} else {
                Write-Host "- Clean"
            }
		}
        # Stop the Remote Registry
        if ( $wasStopped ) { $svc.StopService() | Out-Null }
	} else {
		Write-Host "- Offline"
	}
}
Write-Output $output