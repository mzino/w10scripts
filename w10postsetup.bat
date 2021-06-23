rem source: https://gist.githubusercontent.com/matthewjberger/2f4295887d6cb5738fa34e597f457b7f/raw/b23fa065febed8a2d7c2f030fba6da381f640997/Remove-Windows10-Bloat.bat
rem source: https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/win10debloat.ps1
rem source: https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10Debloater.ps1
rem source: https://github.com/W4RH4WK/Debloat-Windows-10/tree/master/scripts
rem source: https://freetimetech.com/windows-10-clean-up-debloat-tool-by-ftt/
rem run this twice: https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/scripts/disable-windows-defender.ps1

echo Disabling services
sc stop diagnosticshub.standardcollector.service
sc stop DiagTrack
sc stop dmwappushservice
sc stop lfsvc
sc stop MapsBroker
sc stop OneSyncSvc
sc stop perceptionsimulation
sc stop RemoteRegistry
rem sc stop TrkWks
sc stop TroubleshootingSvc
sc stop WbioSrvc
sc stop WMPNetworkSvc
sc stop XblAuthManager
sc stop XblGameSave
sc stop XboxNetApiSvc

sc config diagnosticshub.standardcollector.service start= disabled
sc config DiagTrack start= disabled
sc config dmwappushservice start= disabled
sc config lfsvc start= disabled
sc config MapsBroker start= disabled
sc config OneSyncSvc start= disabled
sc config perceptionsimulation start= disabled
sc config RemoteRegistry start= disabled
rem sc config TrkWks start= disabled
sc config TroubleshootingSvc start= disabled
sc config WbioSrvc start= disabled
sc config WMPNetworkSvc start= disabled
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxNetApiSvc start= disabled

echo Disabling scheduled tasks
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Optimization" /Disable
schtasks /Change /TN "Microsoft\Windows\UNP\RunUpdateNotificationMgr" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Maintenance Install" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot_AC" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot_Battery" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
rem schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
rem schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
rem schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
rem schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
rem schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
rem schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
rem schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
rem schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
rem schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
rem The stubborn task Microsoft\Windows\SettingSync\BackgroundUploadTask can be Disabled using a simple bit change. I use a REG file for that (attached to this post).

echo Disabling Telemetry, Data Collection, Application suggestions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Holographic" /v "FirstRunSucceeded" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableMmx" /t REG_DWORD /d 0 /f

echo Disabling Activity History, Smartscreen, Clipboard History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f

echo Disabling Location Tracking
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f

echo Disabling sharing information with unpaired devices
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Type" /t REG_SZ /d "LooselyCoupled" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "InitialAppValue" /t REG_SZ /d "Unspecified" /f

echo Disabling Feedback
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

echo Disabling Advertising ID
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
rem SmartScreen Filter for Store Apps: Disable
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
rem Let websites provide locally...
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f

echo Disabling WiFi Sense
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f
rem WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f

echo Windows Update optimal settings
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d 4 /f
rem Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
rem Disable Windows Update Driver download and automatic reboot
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUPowerManagement" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f

echo Setting Cortana privacy
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f

echo Disabling UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f

echo Disabling Windows Defender Cloud
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f

echo Disabling action center
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f

echo Disabling GameBar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d 0 /f

echo Explorer tweaks
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideDrivesWithNoMedia" /t  REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t  REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t  REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t  REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t  REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "ShowRecent" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "ShowFrequent" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnails" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailsOnNetworkFolders" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f

echo Disabling lockscreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f

echo Removing Bloat apps
PowerShell -Command "Get-AppxPackage -Name Microsoft.3DBuilder | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.AppConnector | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.GamingServices | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.GetHelp | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Getstarted | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Messaging | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Microsoft3DViewer | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.MinecraftUWP | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.MixedReality.Portal | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.NetworkSpeedTest | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.News | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Office.Lens | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Office.Sway | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.OneConnect | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.People | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Print3D | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.SkypeApp | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.StorePurchaseApp | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Wallet | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Whiteboard | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.WindowsAlarms | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.windowscommunicationsapps | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.WindowsFeedbackHub | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.WindowsMaps | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.WindowsReadingList | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.WindowsSoundRecorder | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.Xbox.TCUI | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.XboxApp | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.XboxGameOverlay | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.XboxGamingOverlay | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.XboxIdentityProvider | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.YourPhone | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *zune* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name Microsoft.MicrosoftStickyNotes | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *WindowsCamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *WindowsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *CommsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Facebook* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Twitter* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Drawboard PDF* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *EclipseManager* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *ActiproSoftwareLLC* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Duolingo-LearnLanguagesforFree* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *PandoraMediaInc* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *CandyCrush* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *BubbleWitch3Saga* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Wunderlist* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Flipboard* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Royal Revolt* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Sway* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Speed Test* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Dolby* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Viber* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *ACGMediaPlayer* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *OneCalendar* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *LinkedInforWindows* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *HiddenCityMysteryofShadows* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *Hulu* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *HiddenCity* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -Name *AdobePhotoshopExpress* | Remove-AppxPackage"

echo Uninstalling OneDrive
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /Q /S >NUL 2>&1
rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
echo OneDrive has been removed. Windows Explorer needs to be restarted.
pause
start /wait TASKKILL /F /IM explorer.exe
start explorer.exe
