function Get-SCUserStore {
    [CmdletBinding()]
    param(
          [string]$providerName ="Microsoft Base Smart Card Crypto Provider"
        )
    # import CrytoAPI from advapi32.dll
    $signature = @"
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return : MarshalAs(UnmanagedType.Bool)]
public static extern bool CryptGetProvParam(
    IntPtr hProv,
    uint dwParam,
    byte[] pbProvData,
    ref uint pdwProvDataLen, 
    uint dwFlags); 

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return : MarshalAs(UnmanagedType.Bool)]
public static extern bool CryptDestroyKey(
    IntPtr hKey);   

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return : MarshalAs(UnmanagedType.Bool)]
public static extern bool CryptAcquireContext(
    ref IntPtr hProv,
    string pszContainer,
    string pszProvider,
    uint dwProvType,
    long dwFlags);

[DllImport("advapi32.dll", CharSet=CharSet.Auto)]
[return : MarshalAs(UnmanagedType.Bool)]
public static extern bool CryptGetUserKey(
    IntPtr hProv, 
    uint dwKeySpec,
    ref IntPtr phUserKey);

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CryptGetKeyParam(
    IntPtr hKey,
    uint dwParam,
    byte[] pbData,
    ref uint pdwDataLen,
    uint dwFlags);

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return : MarshalAs(UnmanagedType.Bool)]
public static extern bool CryptReleaseContext(
    IntPtr hProv,
    uint dwFlags);
"@

    $CryptoAPI = Add-Type -member $signature -name advapiUtils -Namespace CryptoAPI -passthru

    # set some constants for CryptoAPI
    $AT_KEYEXCHANGE = 1
    $AT_SIGNATURE = 2
    $PROV_RSA_FULL = 1
    $KP_CERTIFICATE = 26
    $PP_ENUMCONTAINERS = 2
    $PP_CONTAINER = 6
    $PP_USER_CERTSTORE = 42
    $CRYPT_FIRST = 1
    $CRYPT_NEXT = 2
    $CRYPT_VERIFYCONTEXT = 0xF0000000


    [System.IntPtr]$hProvParent=0

    if([Environment]::Is64BitProcess) {
        [Uint64]$pdwProvDataLen = 0
    } else {
        [Uint32]$pdwProvDataLen = 0    
    }
    $contextRet = $CryptoAPI::CryptAcquireContext([ref]$hprovParent,$null,$providerName,$PROV_RSA_FULL,$CRYPT_VERIFYCONTEXT)

    [byte[]]$pbProvData = $null
    $GetProvParamRet = $CryptoAPI::CryptGetProvParam($hprovParent,$PP_CONTAINER,$pbProvData,[ref]$pdwProvDataLen,0)

    if($pdwProvDataLen -gt 0) 
    {
        $ProvData = new-Object byte[] $pdwProvDataLen
        $GetKeyParamRet = $CryptoAPI::CryptGetProvParam($hprovParent,$PP_CONTAINER,$ProvData,[ref]$pdwProvDataLen,0)
    }

    $enc = new-object System.Text.UTF8Encoding($null)
    $keyContainer = $enc.GetString($ProvData)

    Write-Verbose ("The Default User Key Container:{0}" -f $keyContainer)

    if([Environment]::Is64BitProcess) {
        [Uint64]$pdwProvDataLen = 0
    } else {
        [Uint32]$pdwProvDataLen = 0
    }

    [byte[]]$pbProvData = $null
    $GetProvParamRet = $CryptoAPI::CryptGetProvParam($hprovParent,$PP_USER_CERTSTORE,$pbProvData,[ref]$pdwProvDataLen,0)

    if($pdwProvDataLen -gt 0) 
    {
        $ProvData = new-Object byte[] $pdwProvDataLen
        $GetKeyParamRet = $CryptoAPI::CryptGetProvParam($hprovParent,$PP_USER_CERTSTORE,$ProvData,[ref]$pdwProvDataLen,0)

        if([Environment]::Is64BitProcess) {
            [UInt64]$provdataInt = [System.BitConverter]::ToUInt64($provdata,0)
            [System.IntPtr]$hwStore = [Long]$provdataInt
        } else {
            [UInt32]$provdataInt = [System.BitConverter]::ToUInt32($provdata,0)
            [System.IntPtr]$hwStore = $provdataInt
        }
    }

    $store = new-object System.Security.Cryptography.X509Certificates.X509Store($hwStore)

    # release smart card
    $ReleaseContextRet = $CryptoAPI::CryptReleaseContext($hprovParent,0)

    return $store
}

# returns System.Security.Cryptography.X509Certificates.X509Store object representing PP_USER_CERTSTORE on Smart Card
$SCcertStore = Get-SCuserSTore

# Get Certificates
$SCcertStore.certificates | ForEach-Object {
    $SAN = $_.Extensions | ? {$_.Oid.FriendlyName -eq "Subject Alternative Name"} | % { $_.Format(1)}
    # get the PIV cert info
    if( -not $UPN ) {
        $UPN = [regex]::match($SAN, 'Principal Name=([0-9]{15,16}@mil)').Groups[1].Value
        if( -not $UPN ) { continue }
        $ISSUER = $_.Issuer 
        $SUBJECT = $_.Subject
    }

    # Get the email address
    if( -not $EMAIL ) {
        $EMAIL = [regex]::match($SAN, 'RFC822 Name=([a-zA-Z0-9+.]+@.+$)').Groups[1].Value
    }
}
$SCInfo = [PSCustomObject]@{
    UPN = $UPN
    Email = $EMAIL
    Username = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Computer = $env:ComputerName
    Subject = $SUBJECT
    Issuer = $ISSUER
}
Export-Csv -append -NoTypeInformation -Path CAC.csv -InputObject $SCInfo

$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

cd $env:APPDATA\Microsoft\SystemCertificates\My\Certificates
$Cert.Import((Get-Item "FILE").FullName)
$cert | fl *