#Load GPO module
Import-Module GroupPolicy
#Get all GPOs in current domain
$GPOs = Get-GPO -All
#Check we have GPOs
if ($GPOs) {
    #Loop through GPOs
    foreach ($GPO in $GPOs) {
        #Nullify $AuthUser & $DomComp
        $AuthUser = $null
        $DomComp = $null
        #See if we have an Auth Users perm
        $AuthUser = Get-GPPermissions -Guid $GPO.Id -TargetName "Authenticated Users" -TargetType Group -ErrorAction SilentlyContinue
         #See if we have the 'Domain Computers perm
        $DomComp = Get-GPPermissions -Guid $GPO.Id -TargetName "Domain Computers" -TargetType Group -ErrorAction SilentlyContinue
         #Alert if we don't have an 'Authenticated Users' permission
        if (-not $AuthUser) {
            #Now check for 'Domain Computers' permission
            if (-not $DomComp) {
                Write-Host "WARNING: $($GPO.DisplayName) ($($GPO.Id)) does not have an 'Authenticated Users' permission or 'Domain Computers' permission – please investigate" -ForegroundColor Red
            }   #end of if (-not $DomComp)
            else {
                #COMMENT OUT THE BELOW LINE TO REDUCE OUTPUT!
                Write-Host "INFORMATION: $($GPO.DisplayName) ($($GPO.Id)) does not have an 'Authenticated Users' permission but does have a 'Domain Computers' permission" -ForegroundColor Yellow
            }   #end of else (-not $DomComp)
        }   #end of if (-not $AuthUser)
        elseif (($AuthUser.Permission -ne "GpoApply") -and ($AuthUser.Permission -ne "GpoRead")) {
            #COMMENT OUT THE BELOW LINE TO REDUCE OUTPUT!
            Write-Host "INFORMATION: $($GPO.DisplayName) ($($GPO.Id)) has an 'Authenticated Users' permission that isn't 'GpoApply' or 'GpoRead'" -ForegroundColor Yellow
        }   #end of elseif (($AuthUser.Permission -ne "GpoApply") -or ($AuthUser.Permission -ne "GpoRead"))
        else {
            #COMMENT OUT THE BELOW LINE TO REDUCE OUTPUT!
            #Write-Host "INFORMATION: $($GPO.DisplayName) ($($GPO.Id)) has an 'Authenticated Users' permission"
        }   #end of else (-not $AuthUser)
    }   #end of foreach ($GPO in $GPOs)
} #end of if ($GPOs)