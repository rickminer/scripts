# Convert from TIO to TSC
# TIO setup login headers
$tioheaders=@{}
$tioheaders.Add("accept", "application/json")
#X-Apikeys: accessKey=044365a8a7bb159c5d25230567dd6227cea21f86de4d88dced688f8bd1431918; secretKey=04a19e7db27afe32f039ee19d199fe710c8da88b3b18bddc23bccb7091947ae8;
$tioheaders.Add("x-Apikeys", "accessKey=044365a8a7bb159c5d25230567dd6227cea21f86de4d88dced688f8bd1431918; secretKey=04a19e7db27afe32f039ee19d199fe710c8da88b3b18bddc23bccb7091947ae8;")
# Get a list of the scans
$response = Invoke-WebRequest -Uri 'https://cloud.tenable.com/scans' -Method GET -Headers $tioheaders
# If there is an error stop and print what the server said back
if( $response.StatusCode -ne 200 ) { throw $response.Content }
# Extract the scan information from JSON.
$scans = (ConvertFrom-Json ($response.Content)).scans

# TSC setup login headers
$tscheaders = @{}
$tscheaders.Add("accept","application/json")
$Login = (ConvertTo-Json -compress @{username="scriptuser";password='L9ir&wN$TdgZLDH#$$28'})
$ret = Invoke-WebRequest -URI 'https://sccv03.csp.noaa.gov/rest/token' -Method POST  -Body $Login -UseBasicParsing -SessionVariable sv
$tscheaders.Add("X-SecurityCenter",(ConvertFrom-Json $ret.Content).response.token)
$ret = Invoke-WebRequest -URI 'https://sccv03.csp.noaa.gov/rest/repository'  -UseBasicParsing -Headers $tscheaders -Websession $sv
$repos = (ConvertFrom-Json ($ret.Content)).response | Where-Object { $_.name -like "*CyberScope" }


# Get all of the agent scans (starting with NOAA) and only those that are completed.
$scans | Where-Object { $_.name -match "^NOAA" -and $_.status -eq "completed" } | ForEach-Object {
    # Process each scan for download
    $name = $_.name.substring(0,8)
    Write-Output ("Exporting {0}..." -f $name)
    # Start the export
    $response = Invoke-WebRequest -Uri ('https://cloud.tenable.com/scans/{0}/export' -f $_.id) -Method POST -Headers $tioheaders -ContentType 'application/json' -Body '{"format":"nessus"}'
    if( $response.statusCode -ne 200 ) { throw $response.Content }
    $file = (ConvertFrom-Json ($response.Content)).file
    do {
        Start-Sleep -Seconds 1
        $response = Invoke-WebRequest -Uri ('https://cloud.tenable.com/scans/{0}/export/{1}/status' -f $_.id, $file) -Method GET -Headers $tioheaders
        if( $response.statusCode -ne 200 ) { throw $response.Content }
        $status = (ConvertFrom-Json ($response.Content)).status
    } until ($status -eq "ready")
    Write-Output ("Downloading {0}..." -f $name)
    # Download the Export
    $response = Invoke-WebRequest -Uri ('https://cloud.tenable.com/scans/{0}/export/{1}/download' -f $_.id, $file) -Method GET -Headers $tioheaders -OutFile "$name.nessus" -PassThru
    if( $response.statusCode -ne 200 ) { 
        # There was an error so remove the file and halt script.
        Remove-Item "$name.nessus"
        throw $response.Content
    }
    Write-Output ("{0} Saved." -f $name)
    # Upload the file to TSC
    # Build the multipart form post data
    $FileStream = [System.IO.FileStream]::new((Get-ChildItem "$name.nessus" | ForEach-Object { $_.FullName }), [System.IO.FileMode]::Open)
    $FileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new('form-data')
    $FileHeader.Name = 'Filedata'
    $FileHeader.FileName = "$name.nessus"
    $FileContent = [System.Net.Http.StreamContent]::new($FileStream)
    $FileContent.Headers.ContentDisposition = $FileHeader
    $FileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/octet-stream')
    $MultipartContent = [System.Net.Http.MultipartFormDataContent]::new()
    $MultipartContent.Add($FileContent)

    # Actually upload the file
    $response = Invoke-WebRequest -Uri 'https://sccv03.csp.noaa.gov/rest/file/upload' -Headers $tscheaders -Body $MultipartContent -Method POST -WebSession $sv
    if( $response.statusCode -ne 200 ) { throw $response.Content }
    $tempfilename = (ConvertFrom-Json ($response.Content)).response.filename
    Write-Output "$name uploaded."

    # Import the uploaded file
    $repoId = $repos | Where-Object { $_.name.substring(0,8) -eq $name } | ForEach-Object { $_.id }
    $importBody = @{
        "filename" = $tempfilename;
        "repository" = @{
            "id" = $repoId;
        }
    }
    $response = Invoke-WebRequest -Uri 'https://sccv03.csp.noaa.gov/rest/scanResult/import' -Headers $tscheaders -Body ($importBody | ConvertTo-Json) -Method POST -WebSession $sv
    if( $response.statusCode -ne 200 ) { throw $response.Content }
    $status = (ConvertFrom-Json ($response.Content))
    if( $status.error_code -ne 0 ) { throw $status }
    Write-Output ("$name imported.")
}

# Clear sessions
Invoke-WebRequest -URI 'https://sccv03.csp.noaa.gov/rest/token' -Method DELETE -UseBasicParsing -Headers $tscheaders -Websession $sv | Out-Null