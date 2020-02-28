function Get-FileCerts {
    [CmdletBinding()]

# Local only, no AD
#    $users = Get-WmiObject -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -like '*\Users*' } | select @{LABEL='Username';EXPRESSION={(Get-WmiObject Win32_UserAccount -Filter "SID = '$($_.Sid)'").Caption}},LocalPath,@{LABEL='ComputerName';EXPRESSION={$_.PSComputerName}}

    # Only get AD accounts
    $users = Get-WmiObject -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -like '*\Users*' } | Select-Object @{LABEL='Username';EXPRESSION={(Get-ADObject -Filter "objectSid -eq '$($_.SID)'").Name}},LocalPath,@{LABEL='ComputerName';EXPRESSION={$_.PSComputerName}},@{LABEL='DistinguisehdName';EXPRESSION={(Get-ADObject -Filter "objectSid -eq '$($_.SID)'").DistinguishedName}} | Where-Object { $_.Username }
    $users | ForEach-Object {
#        echo "User: $($_)"
        $path = "$($_.LocalPath)\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates"
#        echo "Path: $($path)"
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($_.FullName)
            $SAN = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"} | ForEach-Object { $_.Format(1)}
#            echo "SAN: $($SAN)"
            # get the PIV cert info
            if( $SAN -and -not $UPN ) {
                $UPN = [regex]::match($SAN, 'Principal Name=([0-9]{15,16}@mil)').Groups[1].Value
                if( $UPN ) {
                    $ISSUER = $cert.Issuer 
                    $SUBJECT = $cert.Subject
                }
            }
#            echo "UPN: $($UPN)"

            # Get the email address
            if( $SAN -and -not $EMAIL ) {
                $EMAIL = [regex]::match($SAN, 'RFC822 Name=([a-zA-Z0-9+.]+@.+$)').Groups[1].Value
            }
#            echo "SAN: $($SAN)"
        }

        $CertInfo = [PSCustomObject]@{
            UPN = $UPN
            Email = $EMAIL
            Username = $_.Username
            DistinguishedName = $_.DistinguishedName
            Computer = $_.ComputerName
            Subject = $SUBJECT
            Issuer = $ISSUER
        }
        Write-Output $CertInfo
        if( $UPN ) { Clear-Variable UPN }
        if( $EMAIL ) { Clear-Variable EMAIL }
        if( $SUBJECT ) { Clear-Variable SUBJECT}
        if( $ISSUER ) { Clear-Variable ISSUER }
    }
}

#$data = 
#Get-FileCerts | Export-Csv -Append -NoTypeInformation -Path CAC.csv
Get-FileCerts