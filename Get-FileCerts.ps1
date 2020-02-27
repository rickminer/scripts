function Get-FileCerts {
    [CmdletBinding()]
    param(
          [string]$path =$env:APPDATA\Microsoft\SystemCertificates\My\Certificates
        )

    $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    cd $path
    $Cert.Import((Get-Item "FILE").FullName)
    $cert | fl *
}