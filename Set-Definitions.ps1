Param(
	[Parameter(Mandatory=$True)]
	[ValidateScript({Test-Path $_ -PathType Leaf})]
	[string]$fileName,
	
	# This must match the number of dashboard components and order, and it will replace the report definition
	[Parameter(Mandatory=$True)]
	$update,
	
	[Parameter(Mandatory=$True)]
	[string]$newFile
)

[System.Reflection.Assembly]::LoadFile((Get-ChildItem ".\PHPSerializationLibrary.dll").FullName) | Out-Null
$serializer = New-Object Conversive.PHPSerializationLibrary.Serializer
# Use .Serialize(object) and .Deserialize(string)
[Xml]$xml = Get-Content $fileName

#Check to see which type of XML we are processing
if( Get-Member -InputObject $xml -name "report" -MemberType Properties ) {
	# This is a report
	$definition = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($serializer.Serialize($update.Definition))))
	$xml.report.definition = $definition
} else {
	# This is a dashboard
	for( $i = 0; $i -lt $xml.dashboardTab.dashboardComponents.ChildNodes.Count; $i++ ) {
		$definition = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($serializer.Serialize($update[$i].Definition))))
		$xml.dashboardTab.dashboardComponents.ChildNodes[$i].definition = $definition
	}
}

#Save new dashboard
$xml.Save((Get-Location).Path + "\" + $newFile)
Write-Output ((Get-Location).Path + "\" + $newFile)