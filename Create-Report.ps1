Param(
	[Parameter(Mandatory=$True)]
	[ValidateScript({Test-Path $_ -PathType Leaf})]
	[string]$template,
	[Parameter(Mandatory=$True)]
	[ValidateScript({Test-Path $_ -PathType Leaf})]
	[string]$summary,
	[Parameter(Mandatory=$True)]
	[ValidateScript({Test-Path $_ -PathType Leaf})]
	[string]$hqtemp
)

[System.Reflection.Assembly]::LoadFile((Get-ChildItem ".\PHPSerializationLibrary.dll").FullName) | Out-Null
$serializer = New-Object Conversive.PHPSerializationLibrary.Serializer

# Start with Exec Summary as first chapter
$report = .\Get-Definitions $summary

# Add HQ as next chapter
$hq = .\Get-Definitions $hqtemp
$hq[0].Definition.chapters | ForEach-Object {$report[0].Definition.chapters.Add($_) }

#Add the rest of the Systems
$repos = .\Get-Repos.ps1 | Where-Object {$_.System -ne "HQ"}
$sys = .\Get-Definitions $template
$chapter = $sys[0].Definition.chapters[0]
$repos | ForEach-Object {
	$newch = $chapter.Clone()
	# Adjust chapter name
	$newch.name = "$($_.System) Summary"
	$rID = $_.ID
	# Serialize the chapter to make the replacement
	$sch = ($serializer.Serialize($newch)) -replace "255",$rID
	# Deserialize again for adding to the report
	$newch = $serializer.Deserialize($sch)
	# Add to the report
	$report[0].Definition.chapters.add($newch)
}

# Save report
.\Set-Definitions $summary $report "Generated\NMFS Summary Report.xml"