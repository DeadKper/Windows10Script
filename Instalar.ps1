#Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/DeadKper/Windows10Script/main/Instalar.ps1?token=AINZBETP3VJ6LYLMBQBU2BK73HH26"))

#https://git.io/JLGaJ

# Recive parameter elevated
param([switch]$elevated)

# Check if we have admin, if not, try to elevate
if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -notcontains "S-1-5-32-544") {
	# Check if we have already tried to elevate, if not, try it
	if (-Not $elevated) {
		Start-Process powershell.exe -Verb RunAs -ArgumentList ("-noprofile -command Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(""https://raw.githubusercontent.com/DeadKper/Windows10Script/main/Instalar.ps1?token=AINZBETP3VJ6LYLMBQBU2BK73HH26"")); -elevated" -f ($myinvocation.MyCommand.Definition))
	}
	exit
}
# Running in admin
$ErrorActionPreference = "SilentlyContinue"

# Ask for the job to do and loop until a valid option is entered
$job=""
while($True) {
	# Clear console
	Clear-Host
	# Display menu
	Write-Host "1.- Normal install"
	Write-Host "2.- Full install"
	Write-Host "3.- Configuration only"
	Write-Host "4.- VM setup"
	Write-Host "0.- Exit"
	# Read option
	$job = Read-Host -Prompt " >"
	# If a non alphanumeric value is entered or value typed is invalid then loop
	if($job -notmatch "^[0-4]$") {
		continue
	}
	# If the exit value is entered then close the console
	if($job -eq 0) {
		exit
	}
	if($job -eq 4) {
		$action=4
		$useJdkForJavaHome = $False
	}
	break
}

while($action -notmatch "^[1-4]$") {
	# Clear console
	Clear-Host
	# Display menu
	Write-Host "Dictate action when the program is completed"
	Write-Host "1.- Turn off the computer"
	Write-Host "2.- Reboot"
	Write-Host "3.- Close the program"
	Write-Host "4.- Nothing"
	# Read option
	$action = Read-Host -Prompt ">"
}


$java = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" | Select-Object -ExpandProperty "JAVA_HOME" -ErrorAction SilentlyContinue)
while($job -eq 2 -and -not $java) {
	# Clear console
	Clear-Host
	# Display menu
	Write-Host "Select the JAVA_HOME to set"
	Write-Host "1.- jdk"
	Write-Host "2.- jre"
	# Read option
	$useJdkForJavaHome = Read-Host -Prompt " >"
	# If a non alphanumeric value is entered then loop
	if($useJdkForJavaHome -match "^1$") {
		$useJdkForJavaHome = $True
		break
	} elseif ($useJdkForJavaHome -match "^2$") {
		$useJdkForJavaHome = $False
		break
	}
}

#

$graphics = (Get-WmiObject win32_VideoController).Name
if ($graphics -notlike "radeon*|intel*|nvidia*|amd*" -and $job -ne 3) {
	Clear-Host
	Write-Host "Leave empty or press a different character than the 4 asked to skip this process"
	$graphics = Read-Host -Prompt "Insert graphics to install: [I]ntel, [N]vidia, [A]md/[R]adeon"
	if ($graphics -match "a|r") {
		#
		Write-Host "AMD is not supported by chocolatey, opening web page for manual instalation"
		Start-Process https://www.amd.com/en/support
	}
}


# Last clear to start the config process
Clear-Host

# Add all registry for later use
if (!(Test-Path "HKU:")) {
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
}
if (!(Test-Path "HKCC:")) {
	New-PSDrive -PSProvider Registry -Name HKCC -Root HKEY_CURRENT_CONFIG
}
if (!(Test-Path "HKCR:")) {
	New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT
}

# Install base apps if not installed because they will be needes later
if (-not (Test-Path "$env:ProgramData\chocolatey\choco.exe")) {
	# Force the parameters again, in some cases it's needed don't really know why
	Set-ExecutionPolicy Bypass -Scope Process -Force
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
	Invoke-Expression ((New-Object System.Net.WebClient).DownloadString("https://chocolatey.org/install.ps1"))
}

if (-not (Test-Path "$env:ProgramFiles\7-Zip\7z.exe")) {
	choco install 7zip -y
	$7zipFiles = @(
		[pscustomobject]@{type = "001";icon = "9"}
		[pscustomobject]@{type = "7z";icon = "0"}
		[pscustomobject]@{type = "arj";icon = "4"}
		[pscustomobject]@{type = "bz2";icon = "2"}
		[pscustomobject]@{type = "bzip2";icon = "2"}
		[pscustomobject]@{type = "cab";icon = "7"}
		[pscustomobject]@{type = "cpio";icon = "12"}
		[pscustomobject]@{type = "deb";icon = "11"}
		[pscustomobject]@{type = "dmg";icon = "17"}
		[pscustomobject]@{type = "fat";icon = "21"}
		[pscustomobject]@{type = "gz";icon = "14"}
		[pscustomobject]@{type = "gzip";icon = "14"}
		[pscustomobject]@{type = "hfs";icon = "18"}
		[pscustomobject]@{type = "lha";icon = "6"}
		[pscustomobject]@{type = "lzh";icon = "6"}
		[pscustomobject]@{type = "lzma";icon = "16"}
		[pscustomobject]@{type = "ntfs";icon = "22"}
		[pscustomobject]@{type = "rar";icon = "3"}
		[pscustomobject]@{type = "rpm";icon = "10"}
		[pscustomobject]@{type = "squashfs";icon = "24"}
		[pscustomobject]@{type = "swm";icon = "15"}
		[pscustomobject]@{type = "tar";icon = "13"}
		[pscustomobject]@{type = "taz";icon = "5"}
		[pscustomobject]@{type = "tbz";icon = "2"}
		[pscustomobject]@{type = "tbz2";icon = "2"}
		[pscustomobject]@{type = "tgz";icon = "14"}
		[pscustomobject]@{type = "txz";icon = "23"}
		[pscustomobject]@{type = "wim";icon = "15"}
		[pscustomobject]@{type = "xar";icon = "19"}
		[pscustomobject]@{type = "xz";icon = "23"}
		[pscustomobject]@{type = "z";icon = "5"}
		[pscustomobject]@{type = "zip";icon = "1"}
	)

	foreach ($typeData in $7zipFiles) {
		$type = $typeData.type
		$icon = $typeData.icon
		$command = "assoc .$type=7-Zip.$type"
		cmd /c $command
		$command = "ftype 7-Zip.$type=""$env:ProgramFiles\7-Zip\7zFM.exe"" ""%1"""
		cmd /c $command
		if (-not (Test-Path "HKCR:\7-Zip.$type\DefaultIcon")) {
			New-Item -Path "HKCR:\7-Zip.$type\DefaultIcon"
			New-ItemProperty -Path "HKCR:\7-Zip.$type\DefaultIcon" -Name "(Default)" -Type String -Value "$env:ProgramFiles\7-Zip\7z.dll,$icon"
		} elseif (-not ((Get-ItemProperty -Path "HKCR:\7-Zip.$type\DefaultIcon") | Select-Object -ExpandProperty "(Default)" -ErrorAction SilentlyContinue)){
			New-ItemProperty -Path "HKCR:\7-Zip.$type\DefaultIcon" -Name "(Default)" -Type String -Value "$env:ProgramFiles\7-Zip\7z.dll,$icon"
		}

		# Commented code is being replaced by the assoc and ftype commands, they're there just for reference
		# New-Item -Path "HKCR:\.$type"
		# New-ItemProperty -Path "HKCR:\.$type" -Name "(Default)" -Type String -Value "7-Zip.$type"
		# New-Item -Path "HKCR:\7-Zip.$type"
		# New-ItemProperty -Path "HKCR:\7-Zip.$type" -Name "(Default)" -Type String -Value "$type Archive"
		# New-Item -Path "HKCR:\7-Zip.$type\shell"
		# New-ItemProperty -Path "HKCR:\7-Zip.$type\shell" -Name "(Default)" -Type String -Value ""
		# New-Item -Path "HKCR:\7-Zip.$type\shell\open"
		# New-ItemProperty -Path "HKCR:\7-Zip.$type\shell\open" -Name "(Default)" -Type String -Value ""
		# New-Item -Path "HKCR:\7-Zip.$type\shell\open\command"
		# New-ItemProperty -Path "HKCR:\7-Zip.$type\shell\open\command" -Name "(Default)" -Type String -Value """$env:ProgramFiles\7-Zip\7zFM.exe"" ""%1"""
	}
}

# Install wget if needed and set the alias to webget to avoid alias collision
if (-not (Test-Path "$env:ProgramData\chocolatey\bin\wget.exe")) {
	choco install wget -y
}

if (-not (Test-Path "$env:ProgramData\chocolatey\lib\shutup10\tools\OOSU10.exe")) {
	choco install shutup10 -y
}

# Set the 7z alias to extract files and wget to use it later
Set-Alias 7z "$env:ProgramFiles\7-Zip\7z.exe"
Set-Alias webget "$env:ProgramData\chocolatey\bin\wget.exe"

# Create app instalation string
if ($job -ne 3) {
	[System.Collections.ArrayList]$apps = "adoptopenjdk8openj9jre", "firefox"

	if ($job -eq 2) {
		$apps.add("discord")
		$apps.add("steam")
		$apps.add("origin")
		$apps.add("battle.net --allow-empty-checksums")
		$apps.add("epicgameslauncher")
		$apps.add("vscode")
		$apps.add("paint.net")
		$apps.add("gimp")
		$apps.add("bitwarden")
		$apps.add("goggalaxy")
		$apps.add("cheatengine")
		$apps.add("adoptopenjdkopenj9")
		$apps.add("python3")
		$apps.add("powertoys")
		$apps.add("nodejs")
		$apps.add("gradle")
	}

	if ($job -eq 4) {
		$apps.add("steam")
		$apps.add("origin")
		$apps.add("battle.net --allow-empty-checksums")
		$apps.add("epicgameslauncher")
		$apps.add("goggalaxy")
		$apps.add("cheatengine")
	}

	if ($graphics -match "n") {
		$apps.add("geforce-experience")
	} elseif ($graphics -match "i") {
		$apps.add("intel-graphics-driver")
	}

	# Install choco apps
	foreach ($app in $apps) {
		choco install $app -y
	}

	# Add java to path
	if(-not $java) {
		foreach ($dir in (Get-ChildItem "${env:ProgramFiles}\AdoptOpenJDK").name) {
			if ($dir -match "jre" -and -not $useJdkForJavaHome) {
				$java_home = "${env:ProgramFiles}\AdoptOpenJDK\${dir}"
			}
			if ($dir -match "jdk" -and $useJdkForJavaHome) {
				$java_home = "${env:ProgramFiles}\AdoptOpenJDK\${dir}"
			}
		}
		New-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment" -Name "JAVA_HOME" -Type String -Value "$java_home"
	}
}

# Function to download from google drive
Function GDownload {
	param(
		[string]$googleFileId,
		[string]$fileDestination,
		[bool]$useCookies,
		[string]$arguments
	)
	# Only install sed if needed
	if (-not (Test-Path "$env:ProgramData\chocolatey\bin\sed.exe")) {
		choco install sed -y
	}

	# Use normal webget if cookies are not needed (file is less than 100mb)
	if (-not $useCookies) {
		webget $arguments -O $fileDestination "https://docs.google.com/uc?export=download&id=$googleFileId"
		return
	}
	# Define path for temporal cookies
	$cookies="$env:ProgramData\temp_gdrive_cookies"
	# Save cookies and the confirm string for the download
	$confirm = webget --save-cookies $cookies "https://docs.google.com/uc?export=download&id=$googleFileId" -O- | sed -rn "s/.*confirm=([0-9A-Za-z_]+).*/\1/p"
	# Download file using temporal cookies and the confirm string
	webget $arguments --load-cookies $cookies -O $fileDestination "https://docs.google.com/uc?export=download&id=$googleFileId&confirm=$confirm"
	# Remove cookies
	Remove-Item $cookies
}

# This config is directly copied from the debloat script of ChrisTitusTech
Write-Host "Creating Restore Point incase something bad happens"
Enable-ComputerRestore -Drive "$env:SystemDrive\"
Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

webget --continue --output-document="$env:ProgramData\security-updates-only.reg" "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/security-updates-only.reg"
Get-Command reg
reg import "$env:ProgramData\security-updates-only.reg"
Remove-Item "$env:ProgramData\security-updates-only.reg"

#
Write-Host "Disable bandwith windows limit"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0

#
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

#
Write-Host "Disabling Application suggestions..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

#
Write-Host "Disabling Activity History..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

#
Write-Host "Disabling Location Tracking..."
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

#
Write-Host "Disabling automatic Maps updates..."
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

#
Write-Host "Disabling Feedback..."
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

#
Write-Host "Disabling Tailored Experiences..."
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

#
Write-Host "Disabling Advertising ID..."
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

#
Write-Host "Disabling Error reporting..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

#
Write-Host "Restricting Windows Update P2P only to local network..."
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

#
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack" -WarningAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled

#
Write-Host "Stopping and disabling WAP Push Service..."
Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
Set-Service "dmwappushservice" -StartupType Disabled

#
Write-Host "Enabling F8 boot menu options..."
bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

#
Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
Set-Service "HomeGroupProvider" -StartupType Disabled

#
Write-Host "Disabling Shared Experiences..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0

#
Write-Host "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

#
Write-Host "Disabling Storage Sense..."
Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue

#
Write-Host "Stopping and disabling Superfetch service..."
Stop-Service "SysMain" -WarningAction SilentlyContinue
Set-Service "SysMain" -StartupType Disabled

#
Write-Host "Setting BIOS time to UTC..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

#
Write-Host "Disabling Hibernation..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

#
Write-Host "Showing task manager details..."
$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
Do {
	Start-Sleep -Milliseconds 100
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
} Until ($preferences)
Stop-Process $taskmgr
$preferences.Preferences[28] = 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences

#
Write-Host "Showing file operations details..."
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

#
Write-Host "Hiding Task View button..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

#
Write-Host "Hiding People icon..."
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

#
Write-Host "Changing default Explorer view to This PC..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

#
Write-Host "Hiding 3D Objects icon from This PC..."
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

# Bloatware array
$Bloatware = @(
	#Unnecessary Windows 10 AppX Apps
	"Microsoft.3DBuilder"
	"Microsoft.AppConnector"
	"Microsoft.BingFinance"
	"Microsoft.BingNews"
	"Microsoft.BingSports"
	"Microsoft.BingTranslator"
	"Microsoft.BingWeather"
	"Microsoft.GetHelp"
	"Microsoft.Getstarted"
	"Microsoft.Messaging"
	"Microsoft.Microsoft3DViewer"
	"Microsoft.MicrosoftSolitaireCollection"
	"Microsoft.NetworkSpeedTest"
	"Microsoft.News"
	"Microsoft.Office.Lens"
	"Microsoft.Office.Sway"
	"Microsoft.OneConnect"
	"Microsoft.People"
	"Microsoft.Print3D"
	"Microsoft.SkypeApp"
	"Microsoft.StorePurchaseApp"
	"Microsoft.Wallet"
	"Microsoft.WindowsAlarms"
	"microsoft.windowscommunicationsapps"
	"Microsoft.WindowsFeedbackHub"
	"Microsoft.WindowsMaps"
	"Microsoft.WindowsSoundRecorder"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"

	#Sponsored Windows 10 AppX Apps
	#Add sponsored/featured apps to remove in the "*AppName*" format
	"*EclipseManager*"
	"*ActiproSoftwareLLC*"
	"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
	"*Duolingo-LearnLanguagesforFree*"
	"*PandoraMediaInc*"
	"*CandyCrush*"
	"*BubbleWitch3Saga*"
	"*Wunderlist*"
	"*Flipboard*"
	"*Twitter*"
	"*Facebook*"
	"*Royal Revolt*"
	"*Sway*"
	"*Speed Test*"
	"*Dolby*"
	"*Viber*"
	"*ACGMediaPlayer*"
	"*Netflix*"
	"*OneCalendar*"
	"*LinkedInforWindows*"
	"*HiddenCityMysteryofShadows*"
	"*Hulu*"
	"*HiddenCity*"
	"*AdobePhotoshopExpress*"
)

# Remove bloatware
foreach ($Bloat in $Bloatware) {
	Get-AppxPackage -Name $Bloat| Remove-AppxPackage
	Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
	Write-Host "Trying to remove $Bloat."
}

#
Write-Host "Stopping Edge from taking over as the default .PDF viewer"
$noPDF = "HKCR:\.pdf"
$noProgIds = "HKCR:\.pdf\OpenWithProgids"
$noWithList = "HKCR:\.pdf\OpenWithList"
if (!(Get-ItemProperty "$noPDF" "NoOpenWith")) {
	New-ItemProperty "$noPDF" "NoOpenWidth"
}
if (!(Get-ItemProperty "$noPDF" "NoStaticDefaultVerb")) {
	New-ItemProperty "$noPDF" "NoStaticDefaultVerb"
}
if (!(Get-ItemProperty "$noProgIds" "NoOpenWith")) {
	New-ItemProperty "$noProgIds" "NoOpenWith"
}
if (!(Get-ItemProperty "$noProgIds" "NoStaticDefaultVerb")) {
	New-ItemProperty "$noProgIds" "NoStaticDefaultVerb"
}
if (!(Get-ItemProperty "$noWithList" "NoOpenWith")) {
	New-ItemProperty "$noWithList" "NoOpenWith"
}
if (!(Get-ItemProperty "$noWithList" "NoStaticDefaultVerb")) {
	New-ItemProperty "$noWithList" "NoStaticDefaultVerb"
}

#Appends an underscore "_" to the Registry key for Edge
$Edge = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
if (Test-Path $Edge) {
	Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_
}

#
Write-Host "Enabling Dark Mode"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0

#
Write-Host "Disabling OneDrive..."
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

#
Write-Host "Uninstalling OneDrive..."
Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
Start-Sleep -s 2
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
if (!(Test-Path $onedrive)) {
	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
Start-Sleep -s 2
Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
Start-Sleep -s 2
Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

#
Write-Host "Disabling Windows Update automatic restart..."
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0

#
Write-Host "Disabling Cortana..."
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

#
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

#
Write-Host "Hiding Taskbar Search icon / box..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
# Copied code from ChrisTitusTech ends here

# Check if the config only option is not the one picked by the user
if ($job -ne 3) {
	# Temporary disable windows defender and permanent disable in VM
	Set-MpPreference -DisableRealtimeMonitoring $True
	if ($job -eq 4) {
		Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
		$Drives = @(
			"A:\"
			"B:\"
			"C:\"
			"D:\"
			"E:\"
			"F:\"
			"G:\"
			"H:\"
			"I:\"
			"J:\"
			"K:\"
			"L:\"
			"M:\"
			"N:\"
			"O:\"
			"P:\"
			"Q:\"
			"R:\"
			"S:\"
			"T:\"
			"U:\"
			"V:\"
			"W:\"
			"X:\"
			"Y:\"
			"Z:\"
		)

		foreach ($drive in $Drives) {
			Add-MpPreference -ExclusionPath $path
		}
	} else {
		$KMSPaths = @(
			"$env:ProgramData\KMSAutoS"
			"$env:ProgramData\KMSAutoS\KMSAuto Net.exe"
			"$env:ProgramData\KMSAutoS\bin\KMSSS.exe"
			"$env:ProgramData\KMSAutoS\bin\TunMirror.exe"
			"$env:ProgramData\KMSAutoS\bin\TunMirror2.exe"
			"$env:ProgramData\KMSAutoS\bin\driver\x64TAP1\devcon.exe"
			"$env:ProgramData\KMSAutoS\bin\driver\x64TAP2\devcon.exe"
			"$env:ProgramData\KMSAutoS\bin\driver\x64WDV\FakeClient.exe"
			"$env:ProgramData\KMSAuto"
			"$env:ProgramData\KMSAuto\KMSAuto Net.exe"
			"$env:ProgramData\KMSAuto\bin\KMSSS.exe"
			"$env:ProgramData\KMSAuto\bin\TunMirror.exe"
			"$env:ProgramData\KMSAuto\bin\TunMirror2.exe"
			"$env:ProgramData\KMSAuto\bin\driver\x64TAP1\devcon.exe"
			"$env:ProgramData\KMSAuto\bin\driver\x64TAP2\devcon.exe"
			"$env:ProgramData\KMSAuto\bin\driver\x64WDV\FakeClient.exe"
			"$env:SystemRoot\System32\KMSAuto Net.exe"
			"$env:SystemRoot\System32\Tasks\KMSAutoNet"
			"$env:SystemRoot\System32\SppExtComObjHook.dll"
			"$env:SystemRoot\System32\SppExtComObjPatcher.exe"
			"$env:LocalAppData\Temp\KMSAutoNet.tmp"
			"$env:LocalAppData\Temp\KMSAuto\SppExtComObjPatcher.exe"
			"$env:LocalAppData\Temp\KMSAuto\SppExtComObjHook.dll"
			"$env:LocalAppData\Temp\KMSAutoS\SppExtComObjPatcher.exe"
			"$env:LocalAppData\Temp\KMSAutoS\SppExtComObjHook.dll"
			"$env:LocalAppData\Microsoft\Windows\INetCache\IE\NRI6I6IW\setup_c[1].exe"
			"$env:AppData\build.exe"
			"$env:AppData\KMSAuto Net.exe"
			"$env:AppData\script.vbs"
			"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\KMSAutoNet"
			"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\KMSAutoNet"
		)

		foreach ($path in $KMSPaths) {
			Add-MpPreference -ExclusionPath $path
		}
	}
	#
	if (-not (Test-Path "$env:ProgramFiles\Microsoft Office\Office16") -and $job -ne 4) {
		$fileName="$env:ProgramData\Office\Office.7z"
		Write-Host "Downloading Microsoft Office 2016"
		mkdir -f "$env:ProgramData\Office"
		GDownload "1S0X76A3eCo4Hm9SqeNcqfUoe1nER-OLP" $fileName $True ""
		7z x $fileName -o"$env:ProgramData\Office" -r
		Remove-Item $fileName

		#
		Write-Host "Installing Microsoft Office 2016"
		Set-Alias office "$env:ProgramData\Office\setup.exe"
		office /adminfile $env:ProgramData\Office\auto.msp
	}

	#
	Write-Host "Running KMSAuto to validate windows"

	# Download KMSAuto for windows activation
	mkdir -f "$env:ProgramData\KMSAutoS"
	webget --continue --output-document="$env:ProgramData\KMSAutoS\KMSAuto Net.exe" "https://github.com/DeadKper/Windows10Script/raw/main/Files/KMSAutoS/KMSAuto%20Net.exe"
	Set-Alias kms "$env:ProgramData\KMSAutoS\KMSAuto Net.exe"
	kms /win=act /off=act /task=yes /sound=no
}

#
Write-Host "Running O&O Shutup with Recommended Settings"
webget --continue --output-document="$env:ProgramData\ooshutup10.cfg" "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg"
Set-Alias OOSU "$env:ProgramData\chocolatey\lib\shutup10\tools\OOSU10.exe"
OOSU $env:ProgramData\OOSU\ooshutup10.cfg /quiet

if ($job -ne 3) {
	while(Get-Process setup -ErrorAction SilentlyContinue) {
		Write-Host "Office is being installed, waiting 10 seconds to check again..."
		Start-Sleep -Seconds 10
	}
	Remove-Item -Recurse -Force "$env:ProgramData\Office"

	while(Get-Process "KMSAuto Net" -ErrorAction SilentlyContinue) {
		Write-Host "Windows is being activated, waiting 10 seconds to check again..."
		Start-Sleep -Seconds 10
	}
}

if ($job -ne 4) {
	Set-MpPreference -DisableRealtimeMonitoring $false
}

Write-Host "Program has finished successfully"

switch ($action) {
	1 {Restart-Computer}
	2 {Stop-Computer}
	3 {exit}
	4 {}
}