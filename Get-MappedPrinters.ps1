# HKU\*\Printers\Connections\*
# For all keys under HKU list \Printers\Connections\*
# HQCIODT1772020

# Get Workstations
# Get-ADComputer -SearchBase "OU=Computers,OU=Infrastructure,OU=HQ,OU=_NMFS,DC=nmfs,DC=local" -Filter * | select Name > computers.txt
$output = @()
Get-Content computers.txt | % {
	$computer = $_
	# Check to see if workstation is online
	if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
		Write-Host "$computer - Online"
		# Get User registry hives
		$registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::Users,$computer)
		$users = $registry.OpenSubKey("")
		foreach ($user in $users.GetSubKeyNames()) {
			# Get printer list
			$printers = $registry.OpenSubKey("$user\\Printers\\Connections")
			if ($printers) {
				foreach ($printer in $printers.GetSubKeyNames()) {
					$data = $printer.split(",")
					# Output report
					$obj = New-Object PSObject
					$obj | Add-Member -MemberType NoteProperty -Name "Workstation" -Value $computer.ToUpper()
					$obj | Add-Member -MemberType NoteProperty -Name "Print Server" -Value $data[2].ToUpper()
					$obj | Add-Member -MemberType NoteProperty -Name "Printer" -Value $data[3].ToUpper()
					$output += $obj
				}
			}
		}
	} else {
		Write-Host "$computer - Offline"
	}
}
Write-Output $output