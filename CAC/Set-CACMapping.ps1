$ADSearchBase = "OU=_NMFS,DC=nmfs,DC=local"

function ReverseDN {
    Param(
        [Parameter(Mandatory=$true)]
        [String]
        $DN
    )
    $arDN = $DN -split ", "
    [Array]::Reverse($arDN)
    return $arDN -join ","
}
function Set-CACMapping {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline,Mandatory=$true)]
        [ValidateScript({Test-Path $_ -PathType 'Leaf'})]
        [String]
        $PATH,
        [bool]$APPEND = $true
        )

    # Get CSV Data from Get-FileCerts or Get-SCUserStore
    $csv = Import-Csv -Path $PATH

    $csv | ForEach-Object {
        echo "User: $($_.Username)"
        # Skip users without information
        if( -not $_.UPN ) { return }
        $dn = $_.DistinguishedName
        $aduser = Get-ADUser -SearchBase $ADSearchBase -Filter {DistinguishedName -eq $dn} -SearchScope Subtree -Properties AltSecurityIdentities 
        $certs = $aduser.AltSecurityIdentities
        $issuer = ReverseDN($_.Issuer)
        $subject = ReverseDN($_.Subject)
        $cert = "X509:<I>$issuer<S>$subject"
        # If we want to append
        if( $APPEND ) {
            # Don't add the cert if it is already there.
            $certs | ForEach-Object { 
                if( $cert -eq $_ ) { $FOUND_CERT = $true }
            }
            if( -not $FOUND_CERT ) { $certs += $cert }
        } else {
            # We don't want to append, so overwrite everything and put this certificate
            # If it was already there then it doesn't matter it will still be there after
            $certs = @($cert)
        }
        $aduser.AltSecurityIdentities = $certs
        #Set-ADUser -Instance $ADUser #Add for specifying the DC -Server $DC

    }
}

Set-CACMapping -PATH ".\CAC.csv"