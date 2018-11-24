##############################################################
##                                                          ##
##              Windows Live Triage Script                  ##
##   Some commands taken from Blue Team Field Manual (BTFM) ##
##           Written by: Alan White & Ben Clark             ##
##                                                          ##
##           Script written by @Security_Badger             ##
##                                                          ##
##############################################################

<#
Imports Modules that may not already exist on the system
#>
Import-Module BitsTransfer
Import-Module DnsClient
Import-Module NetTCPIP
Import-Module NetAdapter
Import-Module PSScheduledJob
Import-Module CimCmcdlets
Import-Module Defender


<#
Moves to the Desktop of the user that is currently logged on
Creates the "WinTriage" folder
Moves into the "WinTriage" folder
#>
cd ~\Desktop
New-Item .\WinTriage -ItemType Directory 
cd .\WinTriage


<#
Download all necessary tools from internet
#>
Start-BitsTransfer https://live.sysinternals.com/psinfo.exe
Start-BitsTransfer https://live.sysinternals.com/autorunsc.exe
Start-BitsTransfer https://live.sysinternals.com/psloglist.exe
Start-BitsTransfer https://live.sysinternals.com/sigcheck.exe
Start-BitsTransfer https://live.sysinternals.com/listdlls.exe
Start-BitsTransfer https://live.sysinternals.com/rootkitrevealer.exe
Update-MpSignature


########################
## Disable Networking ##
########################
Disable-NetAdapter -Name "*" -Confirm:$false

Write-Host "## Networking Disabled ##" -ForegroundColor Red


########################
## System Information ##
########################
Write-Host "Retrieving System information" -ForegroundColor DarkGray

<#
Writes the current system time to SysInfo.txt
#>
Write-Output "-------" > SysInfo.txt
Write-Output "System Time" >> SysInfo.txt
Write-Output "-------" >> SysInfo.txt
Get-Date >> SysInfo.txt

<#
Displays detailed list of system information
Formats it as a table and writes it to SysInfo.txt
#>
Write-Output "-------" >> SysInfo.txt
Write-Output "System Information" >> SysInfo.txt
Write-Output "-------" >> SysInfo.txt
systeminfo | Format-Table >> SysInfo.txt

<#
Displays the Unique Identifier number of the system
Formats it as a table and writes it to SysInfo.txt
#>
Write-Output "-------" >> SysInfo.txt
Write-Output "System Device ID" >> SysInfo.txt
Write-Output "-------" >> SysInfo.txt
wmic csproduct get UUID | Format-Table >> SysInfo.txt

<#
Displays all currently installed programs
Formats it as a table and writes it to SysInfo.txt
#>
Write-Output "-------" >> SysInfo.txt
Write-Output "Installed Programs" >> SysInfo.txt
Write-Output "-------" >> SysInfo.txt
Get-WmiObject win32_product | Format-Table >> SysInfo.txt

<#
Downloads the PSInfo executable from live.sysinternals.com
Executes PS info with the nobanner, h, and d switches
    -nobanner prevents the startup banner and copyright message from displaying
    -h displays installed hotfixes
    -d displays disk volume information
Formats outout as table and writes it to SysInfo.txt
#>
Write-Output "-------" >> SysInfo.txt
Write-Output "PSinfo.exe" >> SysInfo.txt
Write-Output "-------" >> SysInfo.txt
.\psinfo.exe -accepteula -nobanner -h -d | Format-Table >> SysInfo.txt


######################
## User Information ##
######################
Write-Host "Retrieving User information" -ForegroundColor DarkGray

<#
Displays current user
Writes it to UserInfo.txt
#>
Write-Output "-------" > UserInfo.txt
Write-Output "Current User" >> UserInfo.txt
Write-Output "-------" >> UserInfo.txt
whoami >> UserInfo.txt

<#
Displays all local users on system
Writes it to UserInfo.txt
#>
Write-Output "-------" >> UserInfo.txt
Write-Output "Local Users on system" >> UserInfo.txt
Write-Output "-------" >> UserInfo.txt
net user >> UserInfo.txt

<#
Displays all users that are members of the local administrators group on the system
Writes it to UserInfo.txt
#>
Write-Output "-------" >> UserInfo.txt
Write-Output "Local Administrators" >> UserInfo.txt
Write-Output "-------" >> UserInfo.txt
net localgroup administrators >> UserInfo.txt

<#
Check to see if Remote Desktop to the system is allowed
    0 = no
    1 = yes
Writes it to UserInfo.txt
#>
Write-Output "-------" >> UserInfo.txt
Write-Output "Is remote access allowed?" >> UserInfo.txt
Write-Output "-------" >> UserInfo.txt
wmic rdtoggle list >> UserInfo.txt

<#
Get count of bad remote login attempts
#>
Write-Output "-------" >> UserInfo.txt
Write-Output "Network Logons with bad password count" >> UserInfo.txt
Write-Output "-------" >> UserInfo.txt
wmic netlogin get name,lastlogon,badpassword >> UserInfo.txt

<#
Retreiving doskey command history
#>
Write-Output "-------" >> UserInfo.txt
Write-Output "doskey command history" >> UserInfo.txt
Write-Output "-------" >> UserInfo.txt
doskey /history >> UserInfo.txt


#########################
## Network Information ##
#########################
Write-Host "Retrieving Network Information" -ForegroundColor DarkGray

<#
Obtains network interface statistics
#>
Write-Output "-------" > NetInfo.txt
Write-Output "Network interface stats" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
Get-NetAdapterStatistics -IncludeHidden >> NetInfo.txt

<#
Obtains all active network connections
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "Active network connections" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
netstat -noab >> NetInfo.txt

<#
Obtains all local routing tables
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "Routing tables" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
netstat -nr >> NetInfo.txt

<#
Obtains NetBIOS over TCP/IP Sessions table w/ destination IP
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "NBT sessions table" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
nbtstat -S >> NetInfo.txt

<#
Obtains arp tables
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "ARP tables" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
arp -av >> NetInfo.txt

<#
Obtains DNS Cache data
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "DNS Cache" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
Get-DnsClientCache >> NetInfo.txt

<#
Obtains proxy information
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "Proxy settings" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
netsh winhttp show proxy >> NetInfo.txt

<#
Obtains all relevant information from all network interfaces
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "Net Interface Settings" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
Get-NetIPConfiguration -AllCompartments -All -Detailed >> NetInfo.txt

<#
Obtains all information about all network adapters 
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "Net adapter information" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
Get-NetAdapter -Name "*" -IncludeHidden | Select-Object -Property "*" | Format-Table >> NetInfo.txt

<#
Obtains contents of etc\hosts file
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "Net adapter information" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
Get-Content -LiteralPath C:\Windows\System32\drivers\etc\hosts >> NetInfo.txt

<#
Obtains a list of attached network drives and lists type of connection, drive letter/local name, remote name/location of the drive, 
and the username used to connect to the drive
#>
Write-Output "-------" >> NetInfo.txt
Write-Output "Netuse info" >> NetInfo.txt
Write-Output "-------" >> NetInfo.txt
wmic netuse get name,username,connectiontype,localname >> NetInfo.txt


#############################################
## Service and running process Information ##
#############################################
Write-Host "Retrieving Service/Process information" -ForegroundColor DarkGray

<#
Obtains a list of all scheduled tasks
#>
Write-Output "-------" > ServInfo.txt
Write-Output "Scheduled Tasks" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
schtasks >> ServInfo.txt

<#
Obtains a list of all running processes along with user account used to run it
#>
Write-Output "-------" >> ServInfo.txt
Write-Output "Running Processes" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
Get-Process -Verbose -IncludeUserName >> ServInfo.txt

<#
Obtains a list of all running processes and the file version assosiated with it
#>
Write-Output "-------" >> ServInfo.txt
Write-Output "" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
Get-Process -FileVersionInfo >> ServInfo.txt

<#
Obtains a list of all programs that start on system startup
#>
Write-Output "-------" >> ServInfo.txt
Write-Output "Start-Up Programs" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
Get-StartApps >> ServInfo.txt

<#
Obtains a list of all running services
#>
Write-Output "-------" >> ServInfo.txt
Write-Output "Running Services" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
wmic service list brief | findstr 'Running' >> ServInfo.txt

<#
Obtains a list of all service configurations
#>
Write-Output "-------" >> ServInfo.txt
Write-Output "Service configurations" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
wmic service list config >> ServInfo.txt

<#
Obtains a list of all service configurations
#>
Write-Output "-------" >> ServInfo.txt
Write-Output "Memory usage by processes" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
wmic process list memory >> ServInfo.txt

<#
Obtains a list of all files touched by running processes
Commented out due to large output
Uncomment to re-enable
#>
<#
Write-Output "-------" >> ServInfo.txt
Write-Output "Service configurations" >> ServInfo.txt
Write-Output "-------" >> ServInfo.txt
Get-Process | select modules | ForEach-Object { $_.Modules } >> ServInfo.txt
#>


######################################
## Applied Group Policy Information ##
######################################
Write-Host "Applied Group Policy Information" -ForegroundColor DarkGray


<#
Obtains a list of all applied Group Policy settings
#>
gpresult /H GPInfo.html


########################
## Hotfix Information ##
########################
Write-Host "Applied Hotfix Information" -ForegroundColor DarkGray

<#
Retrieves list of applied Hotfixes
#>
Write-Output "-------" > HFInfo.txt
Write-Output "Installed Hotfixes" >> HFInfo.txt
Write-Output "-------" >> HFInfo.txt
wmic qfe >> HFInfo.txt

<#
Lists all software installed via GPO
#>
Write-Output "-------" >> HFInfo.txt
Write-Output "GPO Software" >> HFInfo.txt
Write-Output "-------" >> HFInfo.txt



##################################
## Autorun/Autoload Information ##
##################################
Write-Host "Autoruns and Autoloads Information" -ForegroundColor DarkGray


<#
List all executables and their paths that execute on startup
#>
Write-Output "-------" > AutorunInfo.txt
Write-Output "Startup executables" >> AutorunInfo.txt
Write-Output "-------" >> AutorunInfo.txt
wmic startup list full >> AutorunInfo.txt

<#
List all connected NT domains
#>
Write-Output "-------" >> AutorunInfo.txt
Write-Output "Connected NT domains" >> AutorunInfo.txt
Write-Output "-------" >> AutorunInfo.txt
wmic startup list full >> AutorunInfo.txt

<#
Use SysInternals tool Autorunsc.exe to retrieve remaining autoruns info
    -accepteula: Auto accept EULA to run silently
    -nobanner: remove the banner at the top of the commands output
    -user *: check startup options for all users on system
    -a *: obtain all startup information
    -m: exclude Microsoft executables
    -s: check signatures of all executables
    -h: generate and display hashes for all listed executables
#>
Write-Output "-------" >> AutorunInfo.txt
Write-Output "Autorunsc.exe" >> AutorunInfo.txt
Write-Output "-------" >> AutorunInfo.txt
.\autorunsc.exe -accepteula -nobanner -user * -a * -m -s -h | Format-Table >> AutorunInfo.txt


################
## Event Logs ##
################
Write-Host "Event Log Information" -ForegroundColor DarkGray

<#
Gather the previous 100 Security event logs
    -n 100: display only the previous 100 logs
    -e 5152: exlude event ID 5152 from log results
    -s: Records are listed on one line each with delimited fields, which is convenient for string searches.
    -t \t: delimits fields using tabs rather than commas
    security: specifies to gather security logs
#>
Write-Output "-------" > Logs_Security.csv
Write-Output "Last 100 Security Events" >> Logs_Security.csv
Write-Output "-------" >> Logs_Security.csv
.\psloglist.exe -n 100 -e 5152 -s -t \t security | Format-Table >> Logs_Security.csv

<#
Gather the previous 100 System event logs
    -n 100: display only the previous 100 logs
    -f wec: Only show warning, error, and critical event log results
    -s: Records are listed on one line each with delimited fields
    -t \t: delimits fields using tabs
    system: specifies to gather system logs
#>
Write-Output "-------" > Logs_System.csv
Write-Output "Last 100 System Events" >> Logs_System.csv
Write-Output "-------" >> Logs_System.csv
.\psloglist.exe -n 100 -f wec -s -t \t system | Format-Table >> Logs_System.csv

<#
Gather the previous 100 Application event logs
    -n 100: display only the previous 100 logs
    -f wec: Only show warning, error, and critical event log results
    -s: Records are listed on one line each with delimited fields
    -t \t: delimits fields using tabs
    application: specifies to gather application logs
#>
Write-Output "-------" > Logs_Application.csv
Write-Output "Last 100 Application Events" >> Logs_Application.csv
Write-Output "-------" >> Logs_Application.csv
.\psloglist.exe -n 100 -f wec -s -t \t application | Format-Table >> Logs_Application.csv

########################################
## File, Drive, and Share Information ##
########################################
Write-Host "File, Drive, and Share Information" -ForegroundColor DarkGray

<#
Lists all shares local and external to the machine, including administrative shares
#>
Write-Output "-------" > FDSInfo.txt
Write-Output "Shared files and folders" >>FDSInfo.txt
Write-Output "-------" >> FDSInfo.txt
wmic share list brief >> FDSInfo.txt

<#
List active connections to and from the system
#>
Write-Output "-------" >> FDSInfo.txt
Write-Output "Active connections" >>FDSInfo.txt
Write-Output "-------" >>FDSInfo.txt
net session >> FDSInfo.txt

<#
List all local system volumes
#>
Write-Output "-------" >> FDSInfo.txt
Write-Output "Local System Volumes" >>FDSInfo.txt
Write-Output "-------" >>FDSInfo.txt
wmic volume list brief >> FDSInfo.txt

<#
List all local and network connected drives to the system
#>
Write-Output "-------" >> FDSInfo.txt
Write-Output "Local and Network Connected Drives" >> FDSInfo.txt
Write-Output "-------" >> FDSInfo.txt
wmic logicaldisk get description,filesystem,name,size >> FDSInfo.txt

<#
List all new files with .exe extensions
#>
Write-Output "-------" >> FDSInfo.txt
Write-Output "New Executable Files" >> FDSInfo.txt
Write-Output "-------" >> FDSInfo.txt
$date = Get-Date -Format MM/dd/yyyy
forfiles /p C:\ /M *.exe /S /D $date /C "cmd /c echo @fdate @ftime @path" >> FDSInfo.txt

<#
Uses SysInternals tool Sigcheck.exe to find files with no or potentially bad signatures
    -accepteula: auto accepts the EULA in order to be run silently
    -nobanner: does not display banner when executed
    -e: scan executable images only
    -s: Recurse subdirectories
    -h: Shows file hashes
    -ct: Output is tab delimited
    C:\: Location to begin scan
#>
Write-Output "-------" > Sigcheck.csv
Write-Output "Local and Network Connected Drives" >> Sigcheck.csv
Write-Output "-------" >> Sigcheck.csv
.\sigcheck.exe -accepteula -nobanner -e -s -h -ct C:\ >> Sigcheck.csv

<#
Uses Sysinternals tool ListDLL.exe to list relocated and unsigned DLLs that are currently loaded
    -accepteula: auto accepts the EULA in order to be run silently
    -u: displays unsigned DLLs
    -r: displays DLLs that have been relocated
#>
Write-Output "-------" >> listdll.txt
Write-Output "ListDLL output" >> listdll.txt
Write-Output "-------" >> listdll.txt
.\listdll.exe -accepteula -u -r >> listdll.txt


###########################
## Offline Malware Scans ##
###########################
Write-Host "Offline Malware Scans" -ForegroundColor DarkGray

<#
RootkitRevealer.exe
#>
.\rootkitrevealer.exe -accepteula -a -c C:\

<#
Microsoft Defender
#>
Start-MpScan -ScanType FullScan



##########################
## Re-enable Networking ##
##########################
Enable-NetAdapter -Name "*" -Confirm:$false

Write-Host "Networking Re-Enabled" -ForegroundColor Green


########################
## Virus Total Checks ##
########################
Write-Host "Virus Total Checks" -ForegroundColor DarkGray


.\sigcheck.exe -nobanner -o Sigcheck.csv -u -vr -vt -ct -w Sigcheck_VTScanned.csv