:: Chocolatey install script

@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"


:: Install all the packages
:: -y confirm yes for any prompt during the install process

:: Dig
choco install bind-toolsonly -fy
:: Chocolatey GUI
choco install chocolateygui -fy
:: ConEmu
choco install conemu -fy
:: Git (Install)
choco install git.install -fy
:: HashTab
choco install hashtab -fy
:: Hashdeep
::choco install hashdeep -fy
:: PuTTY
::choco install putty.install -fy
:: WinSCP
::choco install winscp.install -fy
:: Lightscreen
choco install lightscreen -fy
:: Nmap
choco install nmap -fy
:: Libressl (openssl replacement)
::choco install libressl -fy
:: PhantomJS
choco install phantomjs -fy
:: Sysinternals
choco install sysinternals -fy
:: Varpanel
choco install varpanel -fy
:: GNU Wget
choco install wget -fy
:: 7zip (Install)
choco install 7zip.install -fy
:: SUMo (lite)
::choco install sumo -fy

:: choco install <package_name> repeats for all the packages you want to install