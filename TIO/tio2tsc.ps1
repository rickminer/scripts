# Convert from TIO to TSC
# TIO setup login headers
$headers=@{}
$headers.Add("accept", "application/json")
#X-Apikeys: accessKey=044365a8a7bb159c5d25230567dd6227cea21f86de4d88dced688f8bd1431918; secretKey=04a19e7db27afe32f039ee19d199fe710c8da88b3b18bddc23bccb7091947ae8;
$headers.Add("x-apikeys", "accessKey=044365a8a7bb159c5d25230567dd6227cea21f86de4d88dced688f8bd1431918; secretKey=04a19e7db27afe32f039ee19d199fe710c8da88b3b18bddc23bccb7091947ae8;")
# Get a list of the scans
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scans' -Method GET -Headers $headers
# If there is an error stop and print what the server said back
if( $response.StatusCode -ne 200 ) { throw $response.Content }
# Extract the scan information from JSON.
$scans = (ConvertFrom-Json ($response.Content)).scans

# Get all of the agent scans (starting with NOAA) and only those that are completed.
$scans | Where-Object { $_.name -match "^NOAA" -and $_.status -eq "completed" } | ForEach-Object {
    # Process each scan for download
    $name = $_.name.substring(0,8)
    Write-Host ("Exporting {0}..." -f $name)
    # Start the export
    $response = Invoke-WebRequest -Uri ('https://cloud.tenable.com/scans/{0}/export' -f $_.id) -Method POST -Headers $headers -ContentType 'application/json' -Body '{"format":"nessus"}'
    if( $response.statusCode -ne 200 ) { throw $response.Content }
    $file = (ConvertFrom-Json ($response.Content)).file
    do {
        Start-Sleep -Seconds 1
        $response = Invoke-WebRequest -Uri ('https://cloud.tenable.com/scans/{0}/export/{1}/status' -f $_.id, $file) -Method GET -Headers $headers
        if( $response.statusCode -ne 200 ) { throw $response.Content }
        $status = (ConvertFrom-Json ($response.Content)).status
    } until ($status -eq "ready")
    Write-Host ("Downloading {0}..." -f $name)
    # Download the Export
    $response = Invoke-WebRequest -Uri ('https://cloud.tenable.com/scans/{0}/export/{1}/download' -f $_.id, $file) -Method GET -Headers $headers -OutFile "$name.nessus" -PassThru
    if( $response.statusCode -ne 200 ) { 
        # There was an error so remove the file and halt script.
        Remove-Item "$name.nessus"
        throw $response.Content
    }
    Write-Host ("{0} Saved." -f $name)
}