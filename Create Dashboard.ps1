#Get the list of repositories
$Login = (ConvertTo-Json -compress @{username="Demo";password="pcjdape43"})
$ret = Invoke-WebRequest -URI https://snowman.csp.noaa.gov/rest/token -Method POST  -Body $Login -UseBasicParsing -SessionVariable sv
$Token = (ConvertFrom-Json $ret.Content).response.token
$ret = Invoke-WebRequest -URI "https://snowman.csp.noaa.gov/rest/repository"  -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"}  -Websession $sv
$repos = (ConvertFrom-Json ($ret.Content)).response

# Get the template dashboard
[Xml]$dashboard = Get-Content ".\dashboardTab.556.10.xml"
$total = $dashboard.dashboardTab.dashboardComponents.component[0]
$old = $dashboard.dashboardTab.dashboardComponents.component[1]
$matrix = $dashboard.dashboardTab.dashboardComponents.component[2]

# Loop over repos
# only do the Cyberscope Repos
$repos | where { $_.name -like "*CyberScope" } | ForEach-Object {
    # clone the template
    $ctotal = $total.Clone()
    $cold = $old.Clone()
    $cmatrix = $matrix.Clone()
    # Get Definition
    $dtotal = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ctotal.definition))
    $dold = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cold.definition))
    $dmatrix = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cmatrix.definition))
    # Get Repo info
    $rID = $_.id
    $rName = (($_.name -split " ")[0] -split "-")[2]
    # Update name and definition
    $ctotal.name = "$($ctotal.name) - $rName"
    $ctotal.definition = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($dtotal -replace "255",$rID)))
    $cold.name = "$($cold.name) - $rName"
    $cold.definition = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($dold -replace "255",$rID)))
    $cmatrix.name = "$($cmatrix.name) - $rName"
    $cmatrix.definition = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($dmatrix -replace "255",$rID)))
    # Append new nodes
    $dashboard.dashboardTab.dashboardComponents.AppendChild($ctotal)
    $dashboard.dashboardTab.dashboardComponents.AppendChild($cold)
    $dashboard.dashboardTab.dashboardComponents.AppendChild($cmatrix)
}

#Save new dashboard
$dashboard.Save((Get-Location).Path + "dashboardSystemTrends.xml")
