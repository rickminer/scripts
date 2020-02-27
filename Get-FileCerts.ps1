function Get-FileCerts {
    [CmdletBinding()]

    $users = Get-WmiObject -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -like '*\Users*' } | select @{LABEL='Username';EXPRESSION={(Get-WmiObject Win32_UserAccount -Filter "SID = '$($_.Sid)'").Caption}},LocalPath,@{LABEL='ComputerName';EXPRESSION={$_.PSComputerName}}
    $users | ForEach-Object {
        $path = "$($_.LocalPath)\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates"
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($_.FullName)
            $SAN = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"} | ForEach-Object { $_.Format(1)}
            # get the PIV cert info
            if( $SAN -and -not $UPN ) {
                $UPN = [regex]::match($SAN, 'Principal Name=([0-9]{15,16}@mil)').Groups[1].Value
                if( $UPN ) {
                    $ISSUER = $cert.Issuer 
                    $SUBJECT = $cert.Subject
                }
            }

            # Get the email address
            if( $SAN -and -not $EMAIL ) {
                $EMAIL = [regex]::match($SAN, 'RFC822 Name=([a-zA-Z0-9+.]+@.+$)').Groups[1].Value
            }
        }

        $CertInfo = [PSCustomObject]@{
            UPN = $UPN
            Email = $EMAIL
            Username = $_.Username
            Computer = $_.ComputerName
            Subject = $SUBJECT
            Issuer = $ISSUER
        }
        Write-Output $CertInfo
        Clear-Variable UPN
        Clear-Variable EMAIL
        Clear-Variable SUBJECT
        Clear-Variable ISSUER
    }
}

#$data = 
Get-FileCerts | Export-Csv -Append -NoTypeInformation -Path CAC.csv