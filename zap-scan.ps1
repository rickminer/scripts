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
    [ValidateScript({
        If ( -Not ($_ | Test-Path) ) {
            Throw "[ERROR]           $_ does not exist."
        }
        If ( -Not ($_ | Test-Path -PathType Leaf) ) {
            Throw "[ERROR]           $_ must be a file."
        }
        If ( -Not ((Get-Item $_).Extension -eq ".context")) {
            Throw "[ERROR]           $_ must be a ZAP context."
        }
        Return $True
    })]
    [string]$AUTH,
    [ValidateSet("xml","html","md")]
    [string]$FORMAT = "md",
    [switch]$AJAX = $false
)

# Convert OUTPUT to object
Write-Host "[INFO]            Writing output to $OUTPUT"

# Get time for reports
$DATETIME = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Host "[INFO]            $DATETIME"

# Get domain name
$DOMAIN = ($URL -as [System.URI]).Host
Write-Host "[INFO]            $DOMAIN"

# Start the ZAP daemon
$CONTAINER_ID=docker run --rm -u zap -p 2375:2375 -d owasp/zap2docker-weekly zap.sh -daemon -port 2375 -host 127.0.0.1 -config api.disablekey=true -config scanner.attackOnStart=true -config view.mode=attack -config connection.dnsTtlSuccessfulQueries=-1 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# Check on the status of the ZAP daemon
$STATUS=docker exec $CONTAINER_ID zap-cli -p 2375 status -t 120
if( -Not ($?) ) {
    Throw "ZAP is not running correctly: $STATUS"
}
Write-Host "[INFO]            ZAP running.."
# Show the latest created container
docker ps -l

# Setup authentication
If ($AUTH) {
    Write-Host "[INFO]            Authentication enabled."
    $context = [Xml](Get-Content $AUTH)
    #Get User index
    If ( $context.configuration.context.forceduser -eq 0 ) {
        $idx = 0;
    } Else {
        $idx = $context.configuration.context.forceduser - 1;
    }
    $user = [System.Text.Encoding]::UTF8.GetString(
        [System.Convert]::FromBase64String(
            ($context.configuration.context.users.user[$idx] -split ";")[2]
        )
    );
    $name = $context.configuration.context.name
    docker cp $AUTH "$CONTAINER_ID`:/tmp/$DOMAIN.context"
    docker exec $CONTAINER_ID zap-cli -p 2375 context import "/tmp/$DOMAIN.context"
    $AUTH_CMD = "--context-name `"$name`" --user-name $user"
} Else { $AUTH_CMD = '' }

docker exec $CONTAINER_ID zap-cli -p 2375 open-url $URL
docker exec $CONTAINER_ID zap-cli -p 2375 spider $AUTH_CMD $URL
if ($AJAX -eq $True ) { docker exec $CONTAINER_ID zap-cli -p 2375 ajax-spider $AUTH_CMD $URL }
docker exec $CONTAINER_ID zap-cli -p 2375 active-scan --recursive $AUTH_CMD $URL
docker exec $CONTAINER_ID zap-cli -p 2375 alerts

# Save the report
docker exec $CONTAINER_ID zap-cli -p 2375 report --output "/tmp/report.$FORMAT" --output-format $FORMAT
docker cp "$CONTAINER_ID`:/tmp/report.$FORMAT" "$OUTPUT\$DATETIME-$DOMAIN.$FORMAT"
Write-Host "[INFO]            Report saved to $OUTPUT\$DATETIME-$DOMAIN.$FORMAT"

# Save the logs to an output
docker logs $CONTAINER_ID 2>&1 | Out-File -FilePath "$OUTPUT\$DATETIME-$DOMAIN.txt"
Write-Host "[INFO]            Logs saved to $OUTPUT\$DATETIME-$DOMAIN.txt"

# Stop the container
docker stop $CONTAINER_ID