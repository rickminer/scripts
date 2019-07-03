Param(
	[Parameter(Mandatory=$True)]
	[ValidateScript({
        If (($_ -as [System.URI]).AbsoluteURI -eq $null) {
            Throw "$_ must be a valid URI to test."
        } Else { $True }
    })]
    [string]$URL,
    [ValidateScript({
        If ( -Not ($_ | Test-Path) ) {
            Throw "$_ does not exist."
        }
        If ( $_ | Test-Path -PathType Leaf ) {
            Throw "$_ must be a folder."
        }
        Return $True
    })]
    [string]$OUTPUT = $env:TEMP,
    [ValidateSet("xml","html","md")]
    [string]$FORMAT = "md",
    [switch]$AJAX = $false
)

# Convert OUTPUT to object
$OUTPUT = Get-Item $OUTPUT
$OUTPUT = "$($OUTPUT.Parent)\$($OUTPUT.Name)"

# Get time for reports
$DATETIME = Get-Date -Format "yyyyMMdd-HHmmss"

# Get domain name
$DOMAIN = ($URI -as [System.URI]).Host

# Start the ZAP daemon
$CONTAINER_ID=docker run --rm -u zap -p 2375:2375 -d owasp/zap2docker-weekly zap.sh -daemon -port 2375 -host 127.0.0.1 -config api.disablekey=true -config scanner.attackOnStart=true -config view.mode=attack -config connection.dnsTtlSuccessfulQueries=-1 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# Check on the status of the ZAP daemon
$STATUS=docker exec $CONTAINER_ID zap-cli -p 2375 status -t 120
if( -Not ($?) ) {
    Throw "ZAP is not running correctly: $STATUS"
}

docker exec $CONTAINER_ID zap-cli -p 2375 open-url $URL
docker exec $CONTAINER_ID zap-cli -p 2375 spider $URL
if ($AJAX -eq $True ) { docker exec $CONTAINER_ID zap-cli -p 2375 ajax-spider $URL }
docker exec $CONTAINER_ID zap-cli -p 2375 active-scan -r $URL
docker exec $CONTAINER_ID zap-cli -p 2375 alerts

# Save the report
docker exec $CONTAINER_ID zap-cli -p 2375 report --output "/tmp/report.$FORMAT" --output-format $FORMAT
docker cp "$CONTAINER_ID`:/tmp/report.$FORMAT" "$OUTPUT\$DATETIME`_$DOMAIN.$FORMAT"
Write-Host "[INFO]            Report saved to $OUTPUT\$DATETIME`_$DOMAIN.$FORMAT"

# Save the logs to an output
docker logs $CONTAINER_ID 2>&1 | Out-File -FilePath "$OUTPUT\$DATETIME`_$DOMAIN.txt"
Write-Host "[INFO]            Logs saved to $OUTPUT\$DATETIME`_$DOMAIN.txt"

# Stop the container
#docker stop $CONTAINER_ID