#Get the list of repositories
$Login = (ConvertTo-Json -compress @{username="Script";password="Mm246vQs89JXVbW2"})
$ret = Invoke-WebRequest -URI https://snowman.csp.noaa.gov/rest/token -Method POST  -Body $Login -UseBasicParsing -SessionVariable sv
$Token = (ConvertFrom-Json $ret.Content).response.token
$ret = Invoke-WebRequest -URI "https://snowman.csp.noaa.gov/rest/repository"  -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"}  -Websession $sv
$repos = (ConvertFrom-Json ($ret.Content)).response
# Clear sessions
Invoke-WebRequest -URI https://snowman.csp.noaa.gov/rest/token -Method DELETE -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"}  -Websession $sv | Out-Null

# Loop over and only get Cyberscope Repositories
$repos | where { $_.name -like "*CyberScope" } | ForEach-Object {
	$system = (($_.name -split " ")[0] -split "-")[2]
	$properties = @{'Repository'=$_.name; 'System'=$system; 'ID'=$_.id}
	$object = New-Object –TypeName PSObject –Prop $properties
	Write-Output $object
}