#-----------------------------------------------------------------------------------------------------------------
#
#Installs .NET 4.5 and Powershell 4
#TO-DO: Needs to run in background
#-----------------------------------------------------------------------------------------------------------------
Write-Host("--------------------------------------------------------------------------")
Write-Host("Checking for Powershell 4.0....")
$poop = 0
$netversion = (Get-ItemProperty ‘HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full’  -Name Release).Release
if($netversion -lt 378389){
   Write-Host("Missing .NET 4.5
Script will now update it, DON'T RESTART IF PROMPTED.")
   $ie = New-Object -ComObject InternetExplorer.Application
   $ie.Visible = $true
   $ie.Navigate("https://www.microsoft.com/en-us/download/details.aspx?id=30653")
   while($ie.Busy){Sleep 1}
   $Link=$ie.Document.getElementsByTagName("a") | where-object {$_.innerText -eq 'Download'}
   $Link.click();
   $loopnumber = 0
   $destination = "C:\Users\"+$env:UserName+"\Downloads\dotNetFx45_Full_setup.exe"
   while ($loopnumber -ne 1){
      Write-Host("Press Enter once download is complete")
      Read-Host
      if(Test-Path $destination){
         Set-Location ("C:\Users\"+$env:UserName+"\Downloads")
         .\dotNetFx45_Full_setup.exe /install=agent /silent
         $loopnumber = 1
         Set-Location ("C:\Windows\system32")
         $ie.Quit()
      }else{
         Write-Host("Download is not complete")
      }
   }
}else{
   $poop++
}
$psversion = $PSVersionTable.PSVersion.Major
if($psversion -lt 4){
   Write-Host("Missing PS 4.0
Script will now update it, RESTART IF PROMPTED.")
   $ie = New-Object -ComObject InternetExplorer.Application
   $ie.Visible = $true
   $ie.Navigate("https://www.microsoft.com/en-us/download/details.aspx?id=40855")
   while($ie.Busy){Sleep 1}
   $Link=$ie.Document.getElementsByTagName("a") | where-object {$_.innerText -eq 'Download'}
   $Link.click();
   while($ie.Busy){Sleep 1}
   $Link=$ie.Document.getElementsByTagName("input") | where-object {$_.value -eq '3'}
   $Link.click();
   while($ie.Busy){Sleep 1}
   $Link=$ie.Document.getElementsByTagName("span") | where-object {$_.innerText -eq 'Next'}
   $Link.click();
   $loopnumber = 0
   $destination = "C:\Users\"+$env:UserName+"\Downloads\Windows6.1-KB2819745-x64-MultiPkg.msu"
   while ($loopnumber -ne 1){
      Write-Host("Press Enter once download is complete")
      Read-Host
      if(Test-Path $destination){
         Set-Location ("C:\Users\"+$env:UserName+"\Downloads")
         .\Windows6.1-KB2819745-x64-MultiPkg.msu /install=agent /silent
         $loopnumber = 1
         Set-Location ("C:\Windows\system32")
         $ie.Quit()
      }else{
         Write-Host("Download is not complete")
      }
   }
}else{
   $poop++
}
if($poop -ne 2){
   Write-Host("The powershell update will require you to restart.
Start the script again after you have restarted, and Powershell is on version 4.
Press any key to end.")
}else{
   Write-Host("Powershell 4.0 is installed.")
}
Write-Host("--------------------------------------------------------------------------
Welcome to the script. Press any key to start.")
Read-Host
#-----------------------------------------------------------------------------------------------------------------
#
#Sets security policies (Password stuff, and auditing)
#Verified Operating Systems: Windows 7
#Expected Operating Systems: XP and beyond, Server 2003 and beyond
#TO-DO: I need to make it export secpol.cfg to a more secure file, rather than just exporting it to C:
#-----------------------------------------------------------------------------------------------------------------
#OLD VERSION. It only sets them correctly if the computer is on default security policies
#secedit /export /cfg c:\secpol.cfg /areas SECURITYPOLICY
#(gc C:\secpol.cfg) -replace ("MinimumPasswordLength = 0", "MinimumPasswordLength = 8") -replace ("PasswordComplexity = 0", "PasswordComplexity = 1") -replace ("MinimumPasswordAge = 0", "MinimumPasswordAge = 10") -replace ("MaximumPasswordAge = 42", "MaximumPasswordAge = 30") -replace ("PasswordHistorySize = 0", "PasswordHistorySize = 5") -replace ("ClearTextPassword = 1", "ClearTextPassword = 0") -replace ("LockoutBadCount = 0", "LockoutBadCount = 3") -replace ('NewAdministratorName = "Administrator"', 'NewAdministratorName = "PoopyDumbGuy"') -replace ('NewGuestName = "Guest"', 'NewGuestName = "PoopyFreeloader"') | Out-File C:\secpol.cfg
#secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
#rm -force c:\secpol.cfg

#NEW VERSION. Sets them on any computer regardless of if they have been altered previously
secedit /export /cfg c:\secpol.cfg /areas SECURITYPOLICY
$SecurityPolicyArray = @('MinimumPasswordLength', 'PasswordComplexity', 'MinimumPasswordAge', 'MaximumPasswordAge ', 'PasswordHistorySize', 'LockoutBadCount', 'AuditSystemEvents', 'AuditLogonEvents', 'AuditObjectAccess', 'AuditPrivilegeUse', 'AuditPolicyChange', 'AuditAccountManage', 'AuditProcessTracking', 'AuditDSAccess', 'AuditAccountLogon', 'NewAdministratorName', 'NewGuestName')
$SecurityPolicyValues = @(8, 1, 10, 30, 5, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, "PoopyDumbGuy", "PoopyFreeloader")
$ivalue = 0
for ($i = 0; $i -ne 17; $i++){
   [String]$PolicyLine = Select-String -Path "c:\secpol.cfg" -Pattern $SecurityPolicyArray[$i]
   $PolicyValueChar = $PolicyLine.IndexOf('=')
   [String]$PolicyValue = $PolicyLine.Substring($PolicyValueChar+2)
   #if ($i -eq 3){
   #   [String]$PolicyValue = $PolicyValue.Substring(0, ($PolicyValue.IndexOf('C:\secpol.cfg:83')) - 1)
   #}else{
   #}
   [String]$StringSecurityPolicyArray = $SecurityPolicyArray[$i]
   [String]$StringSecurityPolicyValues = $SecurityPolicyValues[$ivalue]
   [String]$OldPolicy = ($StringSecurityPolicyArray + " = " + $PolicyValue)
   [String]$NewPolicy = ($StringSecurityPolicyArray + " = " + $StringSecurityPolicyValues)
   (gc C:\secpol.cfg) -replace ($OldPolicy), ($NewPolicy)| Out-File C:\secpol.cfg
   $ivalue++
}
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
(gc C:\secpol.cfg)
rm -force c:\secpol.cfg

#-----------------------------------------------------------------------------------------------------------------
#
#Creates secure passwords for all accounts
#Demotes unapproved admins down to standard users
#Promotes approved admins to admins
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
Function generatePasswords([String]$theirname){
   $a = $theirname
   $b = $a.Substring(0,1)
   $b = $b.ToUpper()
   $b = $b.Replace("3", "Thr33")
   $b = $b.Replace("0", "Z3r0")
   $b = $b.Replace("1", "0n3")
   $b = $b.Replace("2", "Tw0")
   $b = $b.Replace("4", "F0ur")
   $b = $b.Replace("5", "Fiv3")
   $b = $b.Replace("6", "Six")
   $b = $b.Replace("7", "S3v3n")
   $b = $b.Replace("8", "Eight")
   $b = $b.Replace("9", "Nin3")
   $c = $a.Substring(1)
   $c = $c.Replace("a", "4")
   $c = $c.Replace("A", "4")
   $c = $c.Replace("e", "3")
   $c = $c.Replace("E", "3")
   $c = $c.Replace("s", "5")
   $c = $c.Replace("S", "5")
   $c = $c.Replace("b", "8")
   $c = $c.Replace("B", "8")
   $c = $c.Replace("l", "1")
   $c = $c.Replace("L", "1")
   $c = $c.Replace("o", "0")
   $c = $c.Replace("O", "0")
   $c = $c.Replace("z", "2")
   $c = $c.Replace("Z", "2")
   $c = $c.replace(" ", "")
   $d = $b + $c + "R0ck5!"
   [String]$theirpassword = $d
   Write-Host($theirpassword)
   return [String]$theirpassword
}

[String]$MainDude = $env:UserName
$userslist = Get-WmiObject win32_useraccount

$loopnumber = 0
while ($loopnumber -ne 1){
   Write-Host("Aside from you, are there other admins? y/n")
   $otheradmins = Read-Host
   if($otheradmins -eq "y"){
      Write-Host("How many other admins are there? Give a number.")
      $admincount = Read-Host
      $arraything = @(0) * $admincount
      For($i=0; $i -ne $admincount; $i++){
         Write-Host("Give me the name")
         $arraything[$i] = Read-Host
      }
      $loopnumber = 1
   }
   if($otheradmins -eq "n"){
      $loopnumber = 1
   }
   if($otheradmins -ne "y" -and $otheradmins -ne "n"){
      Write-Host("That is neither a y or n")
   }
}
$userslist | Foreach-Object {
   if($_.name -Contains $arraything){
      $group = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/administrators,group")
      $group.add("WinNT://"+$_.name+",user")
   }
   if($_.name -NotContains $MainDude -and $_.name -NotContains $arraything){
      $group = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/administrators,group")
      $group.remove("WinNT://"+$_.name+",user")
   }
   if($_.name -NotContains $MainDude){
      Write-Host($_.caption)
      ([adsi](“WinNT://”+$_.caption).replace(“\”,”/”)).SetPassword((generatePasswords($_.name)))
   }
}
#-----------------------------------------------------------------------------------------------------------------
#
#Disables local Guest and Administrator accounts
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
$localguest = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/Guest")
$localguest.userflags.value = $guest.UserFlags.value -BOR 2
$localguest.SetInfo()
$localadministrator = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/Administrator")
$localadministrator.userflags.value = $localadministrator.UserFlags.value -BOR 2
$localadministrator.SetInfo()
#-----------------------------------------------------------------------------------------------------------------
#
#Sets User Account Control to highest settings
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 4
#-----------------------------------------------------------------------------------------------------------------
#
#Removes unwanted users
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
$loopnumber = 0
while ($loopnumber -ne 1){
   Write-Host("")
   Write-Host("Users")
   Write-Host("-------------")
   $userslist = Get-WmiObject win32_useraccount
   $userslist | Foreach-Object {
      $enableduser = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/"+$_.name)
      if([boolean]($enableduser.UserFlags.value  -BAND "2")){
      }else{
         Write-Host($_.name)
      }
   }
   Write-Host("")
   Write-Host("Should any of these users be removed? y/n")
   $badusers = Read-Host
   if($badusers -eq "y"){
      Write-Host("Give me the name")
      $baddude = Read-Host
      $userslist | Foreach-Object {
         if($_.name -Contains $baddude){
            $ADSIComp = [ADSI]("WinNT://"+$env:COMPUTERNAME)
            $ADSIComp.Delete('User',$_.name)
            Write-Host($_.name+" has been removed")
         }else{
         }
      }
   }
   if($badusers -eq "n"){
      $loopnumber = 1
   }
   if($badusers -ne "y" -and $badusers -ne "n"){
      Write-Host("That is neither a y or n")
   }
}
#-----------------------------------------------------------------------------------------------------------------
#
#Removes unwanted groups
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
$loopnumber = 0
while ($loopnumber -ne 1){
   Write-Host("")
   Write-Host("Groups")
   Write-Host("-------------")
   $groupslist = Get-WmiObject win32_group
   $groupslist | Foreach-Object {
      Write-Host($_.name)
   }
   Write-Host("")
   Write-Host("Should any of these groups be removed? y/n")
   $badgroups = Read-Host
   if($badgroups -eq "y"){
      Write-Host("Give me the group name")
      $badgr = Read-Host
      $groupslist | Foreach-Object {
         if($_.name -Contains $badgr){
            $ADSIComp = [ADSI]("WinNT://"+$env:COMPUTERNAME)
            $ADSIComp.Delete('Group',$_.name)
            Write-Host($_.name+" has been removed")
         }else{
         }
      }
   }
   if($badgroups -eq "n"){
      $loopnumber = 1
   }
   if($badgroups -ne "y" -and $badgroups -ne "n"){
      Write-Host("That is neither a y or n")
   }
}
#-----------------------------------------------------------------------------------------------------------------
#
#Sets services on or off
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
#Firewall
Set-Service MpsSvc -StartupType Automatic #-Status Running
Start-Service MpsSvc
#Windows Updates
Set-Service wuauserv -StartupType Automatic #-Status Running
Start-Service wuauserv
#Telnet
Set-Service TlntSvr -StartupType Disabled #-Status Stopped
Stop-Service TlntSvr
#RD Config
Set-Service SessionEnv -StartupType Disabled #-Status Stopped
Stop-Service SessionEnv
#RD Services
Set-Service TermService -StartupType Disabled #-Status Stopped
Stop-Service TermService
#RD Services UserMode Port Redirector
Set-Service UmRdpService -StartupType Disabled #-Status Stopped
Stop-Service UmRdpService
#ICS
Set-Service SharedAccess -StartupType Disabled #-Status Stopped
Stop-Service SharedAccess
#Remote Registry
Set-Service RemoteRegistry -StartupType Disabled #-Status Stopped
Stop-Service RemoteRegistry
#SSDP Discovery
Set-Service SSDPPSRV -StartupType Disabled #-Status Stopped
Stop-Service SSDPPSRV
#UPnP Device Host
Set-Service upnphost -StartupType Disabled #-Status Stopped
Stop-Service upnphost
#WWW Publishing Service
Set-Service W3SVC -StartupType Disabled #-Status Stopped
Stop-Service W3SVC

#For starting services
#Set-Service <servicename> -StartupType Automatic -Status Running
#For stopping services
#Set-Service <servicename> -StartupType Disabled -Status Stopped
#-----------------------------------------------------------------------------------------------------------------
#
#Turns Windows Firewall on, sets firewall inbound/outbound policy to defaults
#Turns off SOME sharing settings
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

#Sets a rule for a port
#netsh advfirewall firewall add rule dir = <in|out> action = <allow | block | bypass > name = "<Name>" protocol = <tcp|udp> localport = <port>
#-----------------------------------------------------------------------------------------------------------------
#
#My attempt at getting rid of shares
#I can't turn off all the share settings
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
netsh advfirewall firewall set rule group="Network Discovery" new enable=no
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=no
if ($share = Get-WmiObject -Class Win32_Share){ #-ComputerName WH0RCUTEACHER -Filter "Name='RobsShare'"){
$share.delete()
}
#Enables system restore
enable-computerrestore -drive "C:\"
#-----------------------------------------------------------------------------------------------------------------
#
#Disables unwanted Windows Features
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
DISM /online /disable-feature /Featurename:TelnetClient /norestart
DISM /online /disable-feature /Featurename:TelnetServer /norestart
DISM /online /disable-feature /Featurename:TFTPClient /norestart
DISM /online /disable-feature /FeatureName:IIS-WebServerRole /norestart
DISM /online /disable-feature /FeatureName:IIS-WebServer /norestart
DISM /online /disable-feature /FeatureName:IIS-CommonHttpFeatures /norestart
DISM /online /disable-feature /FeatureName:IIS-HttpErrors /norestart
DISM /online /disable-feature /FeatureName:IIS-HttpRedirect /norestart
DISM /online /disable-feature /FeatureName:IIS-ApplicationDevelopment /norestart
DISM /online /disable-feature /FeatureName:IIS-NetFxExtensibility /norestart
DISM /online /disable-feature /FeatureName:IIS-NetFxExtensibility45 /norestart
DISM /online /disable-feature /FeatureName:IIS-HealthAndDiagnostics /norestart
DISM /online /disable-feature /FeatureName:IIS-HttpLogging /norestart
DISM /online /disable-feature /FeatureName:IIS-LoggingLibraries /norestart
DISM /online /disable-feature /FeatureName:IIS-RequestMonitor /norestart
DISM /online /disable-feature /FeatureName:IIS-HttpTracing /norestart
DISM /online /disable-feature /FeatureName:IIS-Security /norestart
DISM /online /disable-feature /FeatureName:IIS-URLAuthorization /norestart
DISM /online /disable-feature /FeatureName:IIS-RequestFiltering /norestart
DISM /online /disable-feature /FeatureName:IIS-IPSecurity /norestart
DISM /online /disable-feature /FeatureName:IIS-Performance /norestart
DISM /online /disable-feature /FeatureName:IIS-HttpCompressionDynamic /norestart
DISM /online /disable-feature /FeatureName:IIS-WebServerManagementTools /norestart
DISM /online /disable-feature /FeatureName:IIS-ManagementScriptingTools /norestart
DISM /online /disable-feature /FeatureName:IIS-IIS6ManagementCompatibility /norestart
DISM /online /disable-feature /FeatureName:IIS-Metabase /norestart
DISM /online /disable-feature /FeatureName:IIS-HostableWebCore /norestart
DISM /online /disable-feature /FeatureName:IIS-CertProvider /norestart
DISM /online /disable-feature /FeatureName:IIS-WindowsAuthentication /norestart
DISM /online /disable-feature /FeatureName:IIS-DigestAuthentication /norestart
DISM /online /disable-feature /FeatureName:IIS-ClientCertificateMappingAuthentication /norestart
DISM /online /disable-feature /FeatureName:IIS-IISCertificateMappingAuthentication /norestart
DISM /online /disable-feature /FeatureName:IIS-ODBCLogging /norestart
DISM /online /disable-feature /FeatureName:IIS-StaticContent /norestart
DISM /online /disable-feature /FeatureName:IIS-DefaultDocument /norestart
DISM /online /disable-feature /FeatureName:IIS-DirectoryBrowsing /norestart
DISM /online /disable-feature /FeatureName:IIS-WebDAV /norestart
DISM /online /disable-feature /FeatureName:IIS-WebSockets /norestart
DISM /online /disable-feature /FeatureName:IIS-ApplicationInit /norestart
DISM /online /disable-feature /FeatureName:IIS-ASPNET /norestart
DISM /online /disable-feature /FeatureName:IIS-ASPNET45 /norestart
DISM /online /disable-feature /FeatureName:IIS-ASP /norestart
DISM /online /disable-feature /FeatureName:IIS-CGI /norestart
DISM /online /disable-feature /FeatureName:IIS-ISAPIExtensions /norestart
DISM /online /disable-feature /FeatureName:IIS-ISAPIFilter /norestart
DISM /online /disable-feature /FeatureName:IIS-ServerSideIncludes /norestart
DISM /online /disable-feature /FeatureName:IIS-CustomLogging /norestart
DISM /online /disable-feature /FeatureName:IIS-BasicAuthentication /norestart
DISM /online /disable-feature /FeatureName:IIS-HttpCompressionStatic /norestart
DISM /online /disable-feature /FeatureName:IIS-ManagementConsole /norestart
DISM /online /disable-feature /FeatureName:IIS-ManagementService /norestart
DISM /online /disable-feature /FeatureName:IIS-WMICompatibility /norestart
DISM /online /disable-feature /FeatureName:IIS-LegacyScripts /norestart
DISM /online /disable-feature /FeatureName:IIS-LegacySnapIn /norestart
DISM /online /disable-feature /FeatureName:IIS-FTPServer /norestart
DISM /online /disable-feature /FeatureName:IIS-FTPSvc /norestart
DISM /online /disable-feature /FeatureName:IIS-FTPExtensibility /norestart
DISM /online /disable-feature /FeatureName:MediaPlayback /norestart
DISM /online /disable-feature /FeatureName:WindowsMediaPlayer /norestart
DISM /online /disable-feature /FeatureName:MediaCenter /norestart
DISM /online /disable-feature /FeatureName:WAS-WindowsActivationService /norestart
DISM /online /disable-feature /FeatureName:WAS-ProcessModel /norestart
DISM /online /disable-feature /FeatureName:WAS-NetFxEnvironment /norestart
DISM /online /disable-feature /FeatureName:WAS-ConfigurationAPI /norestart
DISM /online /disable-feature /FeatureName:Solitaire /norestart
DISM /online /disable-feature /FeatureName:Hearts /norestart
DISM /online /disable-feature /FeatureName:SpiderSolitare /norestart
DISM /online /disable-feature /FeatureName:MoreGames /norestart
DISM /online /disable-feature /FeatureName:FreeCell /norestart
DISM /online /disable-feature /FeatureName:MineSweeper /norestart
DISM /online /disable-feature /FeatureName:PurblePlace /norestart
DISM /online /disable-feature /FeatureName:Chess /norestart
DISM /online /disable-feature /FeatureName:Shanghai /norestart
DISM /online /disable-feature /FeatureName:InternetGames /norestart
DISM /online /disable-feature /FeatureName:InternetCheckers /norestart
DISM /online /disable-feature /FeatureName:InternetBackgammon /norestart
DISM /online /disable-feature /FeatureName:Internet Spades /norestart
DISM /online /disable-feature /FeatureName:SimpleTCP /norestart
#-----------------------------------------------------------------------------------------------------------------
#
#Downloads and launches the installer for Windows Security Essentials
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
if(Test-Path "C:\Program Files\Microsoft Security Client\msseces.exe"){
}else{
   $source = "http://mse.dlservice.microsoft.com/download/A/3/8/A38FFBF2-1122-48B4-AF60-E44F6DC28BD8/enus/amd64/mseinstall.exe"
   $destination = ("C:\Users\"+$env:UserName+"\Desktop\mseinstall.exe")
   Invoke-WebRequest $source -OutFile $destination
   $loopnumber = 0
   while ($loopnumber -ne 1){
      Write-Host("Press Enter once download is complete")
      Read-Host
      if(Test-Path ("C:\Users\"+$env:UserName+"\Desktop\mseinstall.exe")){
         Start-Process ("C:\Users\"+$env:UserName+"\Desktop\mseinstall.exe")
         #cmd.exe /c "mseinstall.exe /s /runwgacheck /o" <<<<<<<<<-----------------------------------------------------------------------I NEED TO TEST THIS!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
         $loopnumber = 1
      }else{
         Write-Host("Download is not complete")
      }
   }
}
#-----------------------------------------------------------------------------------------------------------------
#
#Lists all media files in User files and prompts for delete
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
$loopnumber = 0
while ($loopnumber -ne 1){
   $mediacount = (Get-ChildItem C:\Users "*.mp3" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.ac3" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.aac" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.aiff" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.falc" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.m4a" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.m4p" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.midi" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.mp2" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.m3u" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.ogg" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.vqf" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.wav" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.wma" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.mp4" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.avi" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.mpeg4" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.gif" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.png" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.bmp" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.jpg" -r).Count
   $mediacount = $mediacount + (Get-ChildItem C:\Users "*.jpeg" -r).Count
   Write-Host("There are "+$mediacount+" media files")
   Write-Host("Loading media files...")
   $mediacountarray = @(0..$mediacount)
   $i = 1
   Get-ChildItem C:\Users "*.mp3" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.ac3" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.aac" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.aiff" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.falc" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.m4a" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.m4p" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.midi" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.mp2" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.m3u" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.ogg" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.vqf" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.wav" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.wma" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.mp4" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.avi" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.mpeg4" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.gif" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.png" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.bmp" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.jpg" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   Get-ChildItem C:\Users "*.jpeg" -r | Foreach-Object {
      $mediacountarray[$i] = $_.FullName
      $i++
   }
   $u = 1
   $mediacountarray | Foreach-Object{
      Write-Host("Media "+$u+": ") -nonewline
      Write-Host($mediacountarray[$u])
      $u++
   }
   Write-Host("Would you like to delete any of these media files? y/n")
   $deletemedia = Read-Host
   if($deletemedia -eq "y"){
      Write-Host("Enter the media number of the file")
      $badmedia = Read-Host
      rm $mediacountarray[$badmedia]
   }
   if($deletemedia -eq "n"){
      $loopnumber = 1
   }
   if($deletemedia -ne "y" -and $deletemedia -ne "n"){
      Write-Host("That is neither a y or n")
   }
}
#-----------------------------------------------------------------------------------------------------------------
#
#Lists all installed programs and prompts for uninstall
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
$loopnumber = 0
while ($loopnumber -ne 1){
   $programcount = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*).Count
   Write-Host("There are "+$programcount+" installed programs")
   Write-Host("Loading installed programs...")
   Write-Host(" ")
   $programcountarray = @(0..$programcount)
   $programcountarray2 = @(0..$programcount)
   $programcountarray3 = @(0..$programcount)
   $i = 1
   Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Foreach-Object {
      $programcountarray[$i] = $_.DisplayName
      $programcountarray2[$i] = $_.Publisher
      $programcountarray3[$i] = $_.UninstallString
      $i++
   }
   $u = 1
   $programcountarray | Foreach-Object{
      Write-Host("Program "+$u+": ") -nonewline
      Write-Host($programcountarray[$u]) -nonewline
      Write-Host("  |  Publisher: "+$programcountarray2[$u])
      Write-Host(" ")
      $u++
   }
   Write-Host("Would you like to uninstall any of these programs? y/n")
   $deleteprogram = Read-Host
   if($deleteprogram -eq "y"){
      Write-Host("Enter the number of the program")
      $badprogram = Read-Host
      $programcountarray3[$badprogram] = $programcountarray3[$badprogram].Replace("/I", "/X")
      if($programcountarray3[$badprogram].contains(“MsiExec.exe”)){
      $programcountarray3[$badprogram] = ($programcountarray3[$badprogram] + " /qn /norestart")
      Write-Host($a)
      }else{
      }
      Write-Host($programcountarray3[$badprogram])
      cmd.exe /c ($programcountarray3[$badprogram])
   }
   if($deleteprogram -eq "n"){
      $loopnumber = 1
   }
   if($deleteprogram -ne "y" -and $deleteprogram -ne "n"){
      Write-Host("That is neither a y or n")
   }
}
#-----------------------------------------------------------------------------------------------------------------
#
#Sets Windows Update Settings
#Verified Operating Systems: Windows 7
#-----------------------------------------------------------------------------------------------------------------
$MSUpdateSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$MSUpdateSettings.NotificationLevel=4
$MSUpdateSettings.ScheduledInstallationDay=0
$MSUpdateSettings.ScheduledInstallationTime=3
$MSUpdateSettings.IncludeRecommendedUpdates=1
$MSUpdateSettings.NonAdministratorsElevated=1
$MSUpdateSettings.save()
#-----------------------------------------------------------------------------------------------------------------
#
#Updates Mozilla Firefox to version 55.0.3
#Verified Operating Systems: Windows 7                    C:\Program Files (x86)\Mozilla Firefox\
#TODO: Update to newest version
#-----------------------------------------------------------------------------------------------------------------
if(Test-Path "C:\Program Files\Mozilla Firefox"){
New-Item ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR") -type directory | Out-Null
copy-item -path "C:\Program Files\Mozilla Firefox\updater.exe" -destination ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\updater.exe")
$source = "http://archive.mozilla.org/pub/firefox/releases/55.0.3/update/win64/en-US/firefox-55.0.3.complete.mar"
$destination = "C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\update.mar"
Invoke-WebRequest $source -OutFile $destination
$loopnumber = 0
while ($loopnumber -ne 1){
   Write-Host("Press Enter once download is complete")
   Read-Host
   if(Test-Path $destination){
      $loopnumber = 1
   }else{
      Write-Host("Download is not complete")
   }
}
$fileplace = "C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\updater.exe"
$fileplace2 = "C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR"
$fileplace3 = "C:\Program Files\Mozilla Firefox\uninstall\helper.exe"
Set-Location -Path "C:\Program Files\Mozilla Firefox"
cmd.exe /c $fileplace $fileplace2 "C:\Program Files\Mozilla Firefox" "C:\Program Files\Mozilla Firefox"
move-item -force -path ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\update.log") -destination "C:\Program Files\Mozilla Firefox\uninstall\uninstall.update"
cmd.exe /c $fileplace3 /PostUpdate
rm -force ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR") -r
Set-Location -Path "C:\Windows\system32"
}else{
   if(Test-Path "C:\Program Files (x86)\Mozilla Firefox"){
      New-Item ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR") -type directory | Out-Null
      copy-item -path "C:\Program Files (x86)\Mozilla Firefox\updater.exe" -destination ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\updater.exe")
      $source = "http://archive.mozilla.org/pub/firefox/releases/55.0.3/update/win32/en-US/firefox-55.0.3.complete.mar"
      $destination = "C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\update.mar"
      Invoke-WebRequest $source -OutFile $destination
      $loopnumber = 0
      while ($loopnumber -ne 1){
         Write-Host("Press Enter once download is complete")
         Read-Host
         if(Test-Path $destination){
            $loopnumber = 1
         }else{
            Write-Host("Download is not complete")
         }
      }
      $fileplace = "C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\updater.exe"
      $fileplace2 = "C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR"
      $fileplace3 = "C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe"
      Set-Location -Path "C:\Program Files (x86)\Mozilla Firefox"
      cmd.exe /c $fileplace $fileplace2 "C:\Program Files (x86)\Mozilla Firefox" "C:\Program Files (x86)\Mozilla Firefox"
      move-item -force -path ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR\update.log") -destination "C:\Program Files (x86)\Mozilla Firefox\uninstall\uninstall.update"
      cmd.exe /c $fileplace3 /PostUpdate
      rm -force ("C:\Users\"+$env:UserName+"\Desktop\FirefoxMAR") -r
      Set-Location -Path "C:\Windows\system32"
   }else{
      Write-Host("There is no Mozilla Firefox on this machine, stupid.")
   }
}
#-----------------------------------------------------------------------------------------------------------------
#
#Scans for, downloads, and installs updates
#Verified Operating Systems: Windows 7
#It may need some polishing
#-----------------------------------------------------------------------------------------------------------------
Write-Host("Scanning for updates. This will take way too long.")
$criteria="IsInstalled=0 and Type='Software'"
$updateSession = new-object -com "Microsoft.Update.Session"
$updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates
if($Updates.Count -eq 0){
   Write-Host("No updates found")
}else{
   Write-Host($Updates.Count)
   $downloader = $updateSession.CreateUpdateDownloader()
   Write-Host($downloader)
   $downloader.Updates = $Updates
   $Result= $downloader.Download()
   Write-Host($Result)
   if(($Result.Hresult -eq 0) –and (($result.resultCode –eq 2) -or ($result.resultCode –eq 3)) ){
      $updatesToInstall = New-object -com "Microsoft.Update.UpdateColl"
      Write-Host($updatesToInstall)
      $Updates | where {$_.isdownloaded} | foreach-Object{
         $updatesToInstall.Add($_) | out-null
      }
      $installer = $updateSession.CreateUpdateInstaller()
      Write-Host($installer)
      $installer.Updates = $updatesToInstall
      $installationResult = $installer.Install()
      Write-Host($installationResult)
      $Global:counter=-1
      $installer.updates | Format-Table -autosize -property Title,EulaAccepted,@{label='Result';
         expression={$ResultCode[$installationResult.GetUpdateResult($Global:Counter++).resultCode ] }}
      if($installationResult.rebootRequired){
         $loopnumber = 0
         while($loopnumber -ne 1){
            Write-Host("Restart required. Restart now? y/n")
            $restart = Read-Host
            if($restart -eq "y"){
               shutdown.exe /t 0 /r
            }
            if($restart -eq "n"){
               $loopnumber = 1
            }
            if($restart -ne "y" -and $deletemedia -ne "n"){
               Write-Host("That is neither a y or n")
            }
         }
      }
   }
}
