Param(
	[Parameter(Mandatory=$True)]
	[ValidateScript({Test-Path $_ -PathType Leaf})]
	[string]$fileName
)

[System.Reflection.Assembly]::LoadFile((Get-ChildItem ".\PHPSerializationLibrary.dll").FullName) | Out-Null
$serializer = New-Object Conversive.PHPSerializationLibrary.Serializer
$repos = .\Get-Repos.ps1
$dashboard = .\Get-Definitions $fileName

$repos | ForEach-Object {
	$rID = $_.ID
	$dashboard | ForEach-Object {  $_.Definition = $serializer.Deserialize(($_.Serialized -replace "255",$rID)) }
	.\Set-Definitions $fileName $dashboard "Generated\$($_.System) Summary Dashboard.xml"
}