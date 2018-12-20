Param(
	[Parameter(Mandatory=$True)]
	[ValidateScript({Test-Path $_ -PathType Leaf})]
	[string]$fileName
)

[System.Reflection.Assembly]::LoadFile((Get-ChildItem ".\PHPSerializationLibrary.dll").FullName) | Out-Null
$serializer = New-Object Conversive.PHPSerializationLibrary.Serializer
# Use .Serialize(object) and .Deserialize(string)
[Xml]$xml = Get-Content $fileName

#Check to see which type of XML we are processing
if( Get-Member -InputObject $xml -name "report" -MemberType Properties ) {
	# This is a report
	$serialized = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xml.report.definition))
	$definition = $serializer.Deserialize($serialized)
	$properties = @{'Report'=$xml.report.name; 'Definition'=$definition; 'Serialized'=$serialized}
	$object = New-Object –TypeName PSObject –Prop $properties
	Write-Output $object
} else {
	# This is a dashboard
	$xml.dashboardTab.dashboardComponents.ChildNodes | ForEach-Object {
		$serialized = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_.definition))
		$definition = $serializer.Deserialize($serialized)
		$properties = @{'Report'=$_.name; 'Definition'=$definition; 'Serialized'=$serialized}
		$object = New-Object –TypeName PSObject –Prop $properties
		Write-Output $object
	}
}