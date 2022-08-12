rem source: https://gist.githubusercontent.com/matthewjberger/2f4295887d6cb5738fa34e597f457b7f/raw/b23fa065febed8a2d7c2f030fba6da381f640997/Remove-Windows10-Bloat.bat
rem source: https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/win10debloat.ps1
rem source: https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10Debloater.ps1
rem source: https://github.com/W4RH4WK/Debloat-Windows-10/tree/master/scripts
rem source: https://freetimetech.com/windows-10-clean-up-debloat-tool-by-ftt/

echo Disabling services
sc stop diagnosticshub.standardcollector.service
sc stop DiagTrack
sc stop dmwappushservice
sc stop lfsvc
sc stop MapsBroker
sc stop OneSyncSvc
sc stop perceptionsimulation
sc stop RemoteRegistry
sc stop TroubleshootingSvc
sc stop WbioSrvc
sc stop wcncsvc
sc stop WdBoot
sc stop WdFilter
sc stop WdNisDrv
sc stop WdNisSvc
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
sc config TroubleshootingSvc start= disabled
sc config WbioSrvc start= disabled
sc config wcncsvc start= disabled
sc config WdBoot start= disabled
sc config WdFilter start= disabled
sc config WdNisDrv start= disabled
sc config WdNisSvc start= disabled
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
rem For "Bundles" : 		Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *name* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers
rem For other packages : 	Get-AppxProvisionedPackage -Online | where DisplayName -match 'name' | Remove-AppxProvisionedPackage -AllUsers -Online
rem 						Get-AppxPackage -AllUsers *name* | Remove-AppxPackage -AllUsers
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *mixedreality* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Wallet* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.WindowsFeedbackHub* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.GetHelp* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.People* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.WindowsCamera* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *microsoft.windowscommunicationsapps* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Getstarted* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.SkypeApp* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.MicrosoftSolitaireCollection* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.WindowsAlarms* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.MicrosoftOfficeHub* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.MicrosoftStickyNotes* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.WindowsMaps* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.YourPhone* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Microsoft3DViewer* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *zune* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.StorePurchaseApp* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.WindowsSoundRecorder* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"

PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.3DBuilder* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.AppConnector* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *bing* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.GamingServices* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Messaging* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.MinecraftUWP* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.NetworkSpeedTest* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.News* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Office.Lens* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.OneConnect* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Print3D* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Whiteboard* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.WindowsReadingList* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.Xbox.TCUI* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.XboxApp* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.XboxGameOverlay* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.XboxGamingOverlay* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.XboxIdentityProvider* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Microsoft.XboxSpeechToTextOverlay* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *OneNote* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *WindowsPhone* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *CommsPhone* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *ConnectivityStore* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Facebook* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Twitter* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Drawboard* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *EclipseManager* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *ActiproSoftwareLLC* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Duolingo* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *PandoraMediaInc* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *CandyCrush* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *BubbleWitch3Saga* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Wunderlist* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Flipboard* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Royal Revolt* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Sway* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Speed Test* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Dolby* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Viber* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *ACGMediaPlayer* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *OneCalendar* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *LinkedInforWindows* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *HiddenCity* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *Hulu* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle *AdobePhotoshopExpress* | where SignatureKind -ne 'System' | Remove-AppxPackage -AllUsers"

PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'mixedreality' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Wallet' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.WindowsFeedbackHub' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.GetHelp' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.People' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.WindowsCamera' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'microsoft.windowscommunicationsapps' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Getstarted' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.SkypeApp' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.MicrosoftSolitaireCollection' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.WindowsAlarms' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.MicrosoftOfficeHub' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.MicrosoftStickyNotes' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.WindowsMaps' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.YourPhone' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Microsoft3DViewer' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'zune' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.StorePurchaseApp' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.WindowsSoundRecorder' | Remove-AppxProvisionedPackage -AllUsers -Online"

PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.3DBuilder' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.AppConnector' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'bing' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.GamingServices' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Messaging' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.MinecraftUWP' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.NetworkSpeedTest' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.News' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Office.Lens' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.OneConnect' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Print3D' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Whiteboard' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.WindowsReadingList' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.Xbox.TCUI' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.XboxApp' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.XboxGameOverlay' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.XboxGamingOverlay' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.XboxIdentityProvider' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Microsoft.XboxSpeechToTextOverlay' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'OneNote' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'WindowsPhone' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'CommsPhone' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'ConnectivityStore' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Facebook' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Twitter' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Drawboard' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'EclipseManager' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'ActiproSoftwareLLC' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Duolingo' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'PandoraMediaInc' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'CandyCrush' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'BubbleWitch3Saga' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Wunderlist' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Flipboard' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Royal Revolt' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Sway' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Speed Test' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Dolby' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Viber' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'ACGMediaPlayer' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'OneCalendar' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'LinkedInforWindows' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'Hulu' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'HiddenCity' | Remove-AppxProvisionedPackage -AllUsers -Online"
PowerShell -Command "Get-AppxProvisionedPackage -Online | where DisplayName -match 'AdobePhotoshopExpress' | Remove-AppxProvisionedPackage -AllUsers -Online"

PowerShell -Command "Get-AppxPackage -AllUsers *mixedreality* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Wallet* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.GetHelp* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.People* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsCamera* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *microsoft.windowscommunicationsapps* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Getstarted* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.SkypeApp* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsAlarms* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsMaps* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Microsoft3DViewer* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.StorePurchaseApp* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage -AllUsers"

PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.3DBuilder* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.AppConnector* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.GamingServices* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Messaging* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.MinecraftUWP* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.NetworkSpeedTest* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.News* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Office.Lens* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.OneConnect* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Print3D* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Whiteboard* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.WindowsReadingList* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.Xbox.TCUI* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.XboxApp* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.XboxGameOverlay* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.XboxIdentityProvider* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *OneNote* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *WindowsPhone* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *CommsPhone* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *ConnectivityStore* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Facebook* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Twitter* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Drawboard* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *EclipseManager* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *ActiproSoftwareLLC* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Duolingo-LearnLanguagesforFree* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *PandoraMediaInc* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *CandyCrush* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *BubbleWitch3Saga* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Wunderlist* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Flipboard* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Royal Revolt* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Sway* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Speed Test* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Dolby* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Viber* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *ACGMediaPlayer* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *OneCalendar* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *LinkedInforWindows* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *Hulu* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *HiddenCity* | Remove-AppxPackage -AllUsers"
PowerShell -Command "Get-AppxPackage -AllUsers *AdobePhotoshopExpress* | Remove-AppxPackage -AllUsers"
