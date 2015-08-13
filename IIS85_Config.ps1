#Define Variables
$SourceInetpub = "C:\inetpub"
$DestInetpub = "W:\inetpub"
$LogDir = "W:\logs"

#Import ServerManager module
Import-Module ServerManager -Verbose

#Install WebServer Components
Write-Verbose "Installing Web Server components"
	Install-WindowsFeature Web-Server -IncludeManagementTools -Verbose
	Install-WindowsFeature Web-Http-Redirect,Web-Log-Libraries,Web-Request-Monitor,Web-Http-Tracing,Web-Dyn-Compression,Web-IP-Security,Web-Url-Auth,Web-Scripting-Tools,Web-App-Dev,Web-Asp-Net,WAS,WAS-Process-Model,Web-Mgmt-Service -IncludeAllSubFeature -Verbose
	Remove-WindowsFeature Web-Dir-Browsing -Verbose

#Import WebAdministration Module
Import-Module WebAdministration

#Backup configuration before moving files
Backup-WebConfiguration beforeRootMove

#Stop IIS Services
Invoke-Expression -command "iisreset /stop" -ErrorAction Stop | Out-Host

#Create Destination Directories
Write-Verbose "Creating new IIS directories"
	"W:\inetpub","$DestInetpub\Sites","W:\logs","$LogDir\IIS","$LogDir\history" | ForEach-Object { New-Item -Path $_ -ItemType Directory -Verbose }

#Copy inetpub folder
Write-Verbose "Copying $SourceInetpub to $DestInetpub"
	xcopy $env:SystemDrive\inetpub\logs $LogDir /E /I /Q
	takeown --% /A /F C:\inetpub\history\* /r /d y
	xcopy $env:SystemDrive\inetpub\history $LogDir\history /E /I /Q
	xcopy $SourceInetpub $DestInetpub /E /I /Q
	remove-item $DestInetpub\logs -force -recurse -Verbose
	remove-item $DestInetpub\history -force -recurse -Verbose
	Set-WebConfigurationProperty "system.applicationHost/configHistory" -Name path -value ([System.IO.Path]::Combine("$LogDir","history"))

#Delete default web site
Write-Verbose "Deleting Default Web Site"
	ForEach ($site in Get-Website) { Remove-Website $site.Name -Verbose }

#Set extended logging properties
Write-Verbose "Setting logging properties"
	Set-WebConfigurationProperty "system.applicationHost/sites/siteDefaults/logFile" -name logExtFileFlags -value "Date,Time,ClientIP,UserName,Method,UriStem,UriQuery,HttpStatus,HttpSubStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,Host,UserAgent,Referer" -Verbose

#Set AppPool Isolation Path and move temporary files
Write-Verbose "Setting Application Pool Isolation Path"
	Set-WebConfigurationProperty "system.webServer/httpCompression" -Name directory -Value "$DestInetpub\temp\IIS Temporary Compressed Files" -Verbose
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WAS\Parameters" -Name "ConfigIsolationPath" -Value "$DestInetpub\temp\appPools" -Verbose

#Set Default Logging Directories
Write-Verbose "Setting default logging directories"
	Set-WebConfigurationProperty "system.applicationHost/sites/siteDefaults/traceFailedRequestsLogging" -Name directory -value ([System.IO.Path]::Combine("$LogDir","FailedReqLogFiles")) -Verbose
	Set-WebConfigurationProperty "system.applicationHost/sites/siteDefaults/logfile" -Name directory -value ([System.IO.Path]::Combine("$LogDir","IIS")) -Verbose
	Set-WebConfigurationProperty "system.applicationHost/log/centralBinaryLogFile" -Name directory -value ([System.IO.Path]::Combine("$LogDir","IIS")) -Verbose
	Set-WebConfigurationProperty "system.applicationHost/log/centralW3CLogFile" -Name directory -value ([System.IO.Path]::Combine("$LogDir","IIS")) -Verbose
	New-ItemProperty -path "HKLM:\System\CurrentControlSet\Services\HTTP\Parameters" -name "EnableErrorLogging" -PropertyType DWord -value "1" -Verbose
	New-ItemProperty -path "HKLM:\System\CurrentControlSet\Services\HTTP\Parameters" -name "ErrorLogFileTruncateSize" -PropertyType DWord -value "1048576" -Verbose
	New-ItemProperty -path "HKLM:\System\CurrentControlSet\Services\HTTP\Parameters" -name "ErrorLoggingDir" -PropertyType String -value $LogDir -Verbose

#System tuning
Write-Verbose "Tuning Compression and Application Pool recycling"
	Set-WebConfigurationProperty "system.webServer/httpCompression" -Name staticCompressionDisableCpuUsage -value 90 -Verbose
	Set-WebConfigurationProperty "system.webServer/httpCompression" -Name dynamicCompressionDisableCpuUsage -value 80 -Verbose
	Set-WebConfigurationProperty "system.applicationHost/applicationPools/applicationPoolDefaults/recycling" -Name logEventOnRecycle -value "Time, Requests, Schedule, Memory, IsapiUnhealthy, OnDemand, ConfigChange, PrivateMemory" -Verbose
	Set-WebConfigurationProperty "system.applicationHost/applicationPools/applicationPoolDefaults" -Name queueLength -value 5000 -Verbose
	Set-WebConfigurationProperty "system.applicationHost/applicationPools/applicationPoolDefaults/processModel" -Name pingResponseTime -value "00:00:10" -Verbose
	Set-WebConfigurationProperty "system.applicationHost/applicationPools/applicationPoolDefaults/processModel" -Name pingInterval -value "00:00:10" -Verbose

#Request Filtering tuning
Write-Verbose "Applying Request Filtering Rules"
	Set-WebConfigurationProperty "system.webServer/security/requestFiltering" -Name allowHighBitCharacters -value false -Verbose
	Set-WebConfigurationProperty "system.webServer/security/requestFiltering" -Name allowDoubleEscaping -value false -Verbose
	Set-WebConfigurationProperty "system.webServer/security/requestFiltering" -Name unescapeQueryString -value true -Verbose
	Set-WebConfigurationProperty "system.webServer/security/requestFiltering/fileExtensions" -Name allowUnlisted -value true -Verbose
	Set-WebConfigurationProperty "system.webServer/security/requestFiltering/fileExtensions" -Name applyToWebDAV -value true -Verbose
	Set-WebConfigurationProperty "system.webServer/security/requestFiltering/verbs" -Name allowUnlisted -value false -Verbose
	Set-WebConfigurationProperty "system.webServer/security/requestFiltering/verbs" -Name applyToWebDAV -value true -Verbose
	Add-WebConfiguration "system.webServer/security/requestFiltering/verbs" -value @{verb="GET";allowed="true"} -Verbose
	Add-WebConfiguration "system.webServer/security/requestFiltering/verbs" -value @{verb="POST";allowed="true"} -Verbose
	cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence='..']"
	cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence='./']"
	cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence='\']"
	cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence=';:']"
	cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence=';^&']"

#Move custom error locations
Write-Verbose "Changing custom error location path"
	Set-WebConfigurationProperty "system.webServer/httpErrors/*" -Name prefixLanguageFilePath -value $DestInetpub\custerr -Verbose

#Make sure Service Pack and Hotfix Installers know where the IIS root directories are
#The registry keys aren't created if they don't exist.
Write-Verbose "Updating paths in registry for hotfix and service pack installers"
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\InetStp" -name "PathWWWRoot" -value $DestInetpub\wwwroot -Verbose
	Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\InetStp" -name "PathWWWRoot" -value $DestInetpub\wwwroot -Verbose


#Create share and modify folder permissions
Write-Verbose "Setting permissions"
	$acl = Get-Acl $DestInetpub -Verbose
	$acl.SetAccessRuleProtection($True, $False)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users","Read", "ContainerInherit, ObjectInherit", "None", "Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("NETWORK SERVICE","Read", "ContainerInherit, ObjectInherit", "None", "Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","Read","ContainerInherit, ObjectInherit","None","Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT Service\WMSvc","Read","ContainerInherit, ObjectInherit","None","Allow") -Verbose
	$acl.AddAccessRule($rule)
	Set-Acl $DestInetpub $acl -Verbose
	$acl = Get-Acl $LogDir -Verbose
	$acl.SetAccessRuleProtection($True, $False)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("NETWORK SERVICE","Read", "ContainerInherit, ObjectInherit", "None", "Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","Modify","ContainerInherit, ObjectInherit","None","Allow") -Verbose
	$acl.AddAccessRule($rule)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT Service\WMSvc","Read","ContainerInherit, ObjectInherit","None","Allow") -Verbose
	$acl.AddAccessRule($rule)
	Set-Acl $LogDir $acl -Verbose

#Enable IIS Remote Management
Write-Verbose "Enabling IIS Remote Management"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -Name EnableRemoteManagement -Value 1 -Verbose
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -Name "LoggingDirectory" -value ([System.IO.Path]::Combine("$LogDir","wmsvc")) -Verbose
	Set-Service -name WMSVC -StartupType Automatic -Verbose
	Start-Service WMSVC -Verbose

#Restart all IIS services
Invoke-Expression -command "iisreset /start" -ErrorAction Stop -Verbose | Out-Host

#Backup configuration after all changes
Backup-WebConfiguration postConfiguration -Verbose
