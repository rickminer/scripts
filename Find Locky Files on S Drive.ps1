$arr = @()
gci S:\ -filter *Locky*.txt -recurse | ? {$_.PSIsContainer -eq $False} | % {
$obj = New-Object PSObject
$obj | Add-Member NoteProperty Owner ((Get-ACL $_.FullName).Owner)
$obj | Add-Member NoteProperty Name $_.Name
$obj | Add-Member NoteProperty Created $_.CreationTime
$obj | Add-Member NoteProperty LastModified $_.LastWriteTime
$obj | Add-Member NoteProperty Length $_.Length
$obj | Add-Member NoteProperty Directory $_.DirectoryName
$arr += $obj
}
$arr | Export-CSV -notypeinformation "C:\Users\Rick.Miner\Desktop\report_inst.csv"


## Personal ID Calculation
GWMI -namespace root\cimv2 -class win32_Volume | ? {$_.DriveLetter -eq (Get-Item env:SystemDrive).Value } | % { 
    $_.DeviceId -match "^\\\\?\\Volume(?<GUID>{[0-9a-f-]+}\\"
    $matches["GUID"]
}