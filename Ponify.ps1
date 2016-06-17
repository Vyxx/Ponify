﻿clear
<#Todo
 MousePack Change (reg key mods)
 System Sounds    (reg key mods) - Need WAV files
 Fonts
 Web browser settings
#>

#Ƹ̵̡Ӝ̵̨̄Ʒ 
<#Done
Change startbar/quicklaunch shortcut icons (
UserPicture      (Current and Default user)
LockScreen       (folder and reg key)
Wallpaper        (reg key mod)
Startup Sound    (dll inject)
Shortcuts Change  (editing the .lnk properties)

#>

$backuploc = "C:\Temp"
$wallpapers = "C:\Temp"
<# Necessary Files:
wallpaper.jpg
lockscreen.jpg (1440x900)
PwnyStartSound("path\to\soundfile.wav")
$env:SystemRoot\cursors\*.ani
$env:SystemRoot\media\*.wav
$env:WINDIR\pnyres.dll

#>
function PwnBrowser{
    #change homepages
    #IE homepage is easy, registry key
    #Firefox homepage is a javascript @ C:\Users\ [USERNAME]\AppData\Roaming\Mozilla\Firefox\Profiles\ [Subfolder]
    #add or edit the line that looks like: user_pref("browser.startup.homepage", "www.google.com");
    #taskkill /im firefox.exe* /f
    #cd /D "%APPDATA%\Mozilla\Firefox\Profiles"
    #cd *.default
    #set ffile=%cd%
    #echo user_pref("browser.startup.homepage", "https://www.brony.com");>>"%ffile%\prefs.js"

    #chrome is a pain, edge is stupid
}

function PwnyMouse{
    $mouseReg = ("HKCU:\Control Panel\Cursors")
    SP -WhatIf -Path $mouseReg -Name "(Default)" -Value "Pony"
    SP -WhatIf -Path $mouseReg -Name "AppStarting" -Value "$env:SystemRoot\cursors\aero_working.ani"
    SP -WhatIf -Path $mouseReg -Name "Arrow" -Value "$env:SystemRoot\cursors\aero_arrow.cur"
    SP -WhatIf -Path $mouseReg -Name "Crosshair" -Value "$env:SystemRoot\cursors\cross_r.cur"
    SP -WhatIf -Path $mouseReg -Name "Hand" -Value "$env:SystemRoot\cursors\aero_link.cur"
    SP -WhatIf -Path $mouseReg -Name "Help" -Value "$env:SystemRoot\cursors\aero_helpsel.cur"
    SP -WhatIf -Path $mouseReg -Name "IBeam" -Value ""
    SP -WhatIf -Path $mouseReg -Name "No" -Value "$env:SystemRoot\cursors\aero_unavail.cur"
    SP -WhatIf -Path $mouseReg -Name "NWPen" -Value "$env:SystemRoot\cursors\aero_pen.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeAll" -Value "$env:SystemRoot\cursors\aero_move.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeNESW" -Value "$env:SystemRoot\cursors\aero_nesw.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeNS" -Value "$env:SystemRoot\cursors\aero_ns.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeNWSE" -Value "$env:SystemRoot\cursors\aero_nwse.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeWE" -Value "$env:SystemRoot\cursors\aero_ew.cur"
    SP -WhatIf -Path $mouseReg -Name "UpArrow" -Value "$env:SystemRoot\cursors\aero_up.cur"
    SP -WhatIf -Path $mouseReg -Name "Wait" -Value "$env:SystemRoot\cursors\aero_busy.cur"
}

function PwnySound{
    #GP -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Close\.Current" -Name "(Default)"
    GCI -Path "HKCU:\AppEvents\Schemes\Apps\.Default\" | % {
        $key = $_.OpenSubKey(".Current",$true)
        $soundName = Split-path $key.name.Substring(0,$key.Name.Length - (split-path $key.Name -Leaf).Length) -Leaf
        switch ($soundName){
            "AppGPFault"{}
            "CCSelect"{}
            "ChangeTheme"{}
            "Close"{}
            "CriticalBatteryAlarm"{}
            "DeviceConnect"{$key.SetValue("",$key.GetValue(""))}
            "DeviceDisconnect"{}
            "DeviceFail"{}
            "FaxBeep"{}
            "LowBatteryAlarm"{}
            "MailBeep"{}
            "Maximize"{}
            "MenuCommand"{}
            "MenuPopup"{}
            "MessageNudge"{}
            "Minimize"{}
            "Notification.Default"{}
            "Notification.IM"{}
            "Notification.Looping.Alarm"{}
            "Notification.Looping.Alarm10"{}
            "Notification.Looping.Alarm2"{}
            "Notification.Looping.Alarm3"{}
            "Notification.Looping.Alarm4"{}
            "Notification.Looping.Alarm5"{}
            "Notification.Looping.Alarm6"{}
            "Notification.Looping.Alarm7"{}
            "Notification.Looping.Alarm8"{}
            "Notification.Looping.Alarm9"{}
            "Notification.Looping.Call"{}
            "Notification.Looping.Call10"{}
            "Notification.Looping.Call2"{}
            "Notification.Looping.Call3"{}
            "Notification.Looping.Call4"{}
            "Notification.Looping.Call5"{}
            "Notification.Looping.Call6"{}
            "Notification.Looping.Call7"{}
            "Notification.Looping.Call8"{}
            "Notification.Looping.Call9"{}
            "Notification.Mail"{}
            "Notification.Proximity"{}
            "Notification.Reminder"{}
            "Notification.SMS"{}
            "Open"{}
            "PrintComplete"{}
            "ProximityConnection"{}
            "RestoreDown"{}
            "RestoreUp"{}
            "ShowBand"{}
            "SystemAsterisk"{}
            "SystemExclamation"{}
            "SystemExit"{}
            "SystemHand"{}
            "SystemNotification"{}
            "SystemQuestion"{}
            "WindowsLogoff"{}
            "WindowsLogon"{$key.SetValue("","$env:SystemRoot\media\Windows Logon.wav")}
            "WindowsUAC"{}
            "WindowsUnlock"{}
            default{Write-Host -ForegroundColor RED $soundName}
        }
    }
}

function PwnFonts{
    #figure out this one
    <#
    ;Remove Segoe UI
    [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts]
    "Segoe UI (TrueType)"=""
    "Segoe UI Bold (TrueType)"=""
    "Segoe UI Italic (TrueType)"=""
    "Segoe UI Bold Italic (TrueType)"=""
    "Segoe UI Semibold (TrueType)"=""
    "Segoe UI Light (TrueType)"=""
    "Segoe UI Symbol (TrueType)"=""

    ;Font Substitution
    [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes]
    "Segoe UI"="Equestria.ttf"

    #>
    #HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts
}

function PwnQuickLaunch{
    PwnyShortcuts("$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
}

function PwnyUserIcon{
    If  ( -Not ( Test-Path "$env:ProgramData\Microsoft\Default Account Pictures\user.bmp")){
        Copy-Item "$wallpapers\user.bmp" "$env:ProgramData\Microsoft\User Account Pictures\user.bmp" -Force -ErrorAction SilentlyContinue
        Copy-Item "$wallpapers\guest.bmp" "$env:ProgramData\Microsoft\User Account Pictures\guest.bmp" -Force -ErrorAction SilentlyContinue
    }else{
        Copy-Item "$wallpapers\user.bmp" "$env:ProgramData\Microsoft\Default Account Pictures\user.bmp" -Force -ErrorAction SilentlyContinue
        Copy-Item "$wallpapers\guest.bmp" "$env:ProgramData\Microsoft\Default Account Pictures\guest.bmp" -Force -ErrorAction SilentlyContinue
    }
    $Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    If  ( -Not ( Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey -Force}
    Set-ItemProperty -path "Registry::$Key" -Name "UseDefaultTile" -Type "DWORD" -Value "1" -Force
    Write-Host -ForegroundColor Magenta -BackgroundColor White "Ƹ̵̡Ӝ̵̨̄Ʒ Changed the user icons!"
<#
$env:ProgramData\Microsoft\Default Account Pictures\user.bmp
$env:ProgramData\Microsoft\User Account Pictures\user.bmp
$env:ProgramData\Microsoft\User Account Pictures\Default Pictures
user.bmp - size 128x128 pixels
guest.bmp - size 128x128 pixels
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
UseDefaultTile
1
#>
}

function PwnyLockScreen{
    New-Item -Path "$env:windir\System32\oobe\Info\backgrounds" -ItemType directory -ErrorAction SilentlyContinue
    Copy-Item "$wallpapers\lockscreen.jpg" "$env:windir\System32\oobe\Info\backgrounds\backgroundDefault.jpg" -Force
    $Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background"
    If  ( -Not ( Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey -Force}
    Set-ItemProperty -path "Registry::$Key" -Name "OEMBackground" -Type "DWORD" -Value "1" -Force
    Write-Host -ForegroundColor Magenta -BackgroundColor White "Ƹ̵̡Ӝ̵̨̄Ʒ Lockscreen Background Changed!"
}

function PwnyPaper{
<#
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System
Wallpaper = path to location
WallpaperStyle = 2
#>
    #Reg export "HKEY_CURRENT_USER\Control Panel\Desktop" "$backuploc\desktopProps.reg" 
    Set-ItemProperty -path "HKCU:\Control Panel\Desktop\" -name "wallpaper" -value "$wallpapers\wallpaper.jpg"
    rundll32.exe user32.dll, UpdatePerUserSystemParameters
    Write-Host -ForegroundColor Magenta -BackgroundColor White "Ƹ̵̡Ӝ̵̨̄Ʒ Pony wallpaper all set!"
}

function PwnyStartSound([string]$pfile){
#usage PwnyStartSound "C:\temp\newsound.wav"
    $imageresFile = "$($Env:SYSTEMROOT)\System32\imageres.dll"
    
    $check=Test-Path -Path $imageresFile
    if(!$check){Write-Host -ForegroundColor Yellow -BackgroundColor White "Ƹ̵̡Ӝ̵̨̄Ʒ Awww...cant find the imageres.dll at: $imageresFile";return}
    $check=Test-Path -Path $pfile
    if(!$check){Write-Host -ForegroundColor Yellow -BackgroundColor White "Ƹ̵̡Ӝ̵̨̄Ʒ Awww...cant find the startup sound at: $pfile";return}

# kernel32.dll
    $MethodDefinition = @'
[DllImport("kernel32.dll", EntryPoint="BeginUpdateResourceW", CallingConvention=CallingConvention.StdCall, CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
public static extern IntPtr BeginUpdateResource(string pFileName, bool bDeleteExistingResources);

[DllImport("kernel32.dll", EntryPoint="UpdateResourceW", CallingConvention=CallingConvention.StdCall, CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
public static extern bool UpdateResource(IntPtr hUpdate, string lpType, int iResID, ushort wLanguage, byte[] pData, uint cbData);

[DllImport("kernel32.dll", EntryPoint="EndUpdateResourceW", CallingConvention=CallingConvention.StdCall, CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
public static extern bool EndUpdateResource(IntPtr hUpdate, bool bDiscard);

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr LoadLibraryEx(String lpFileName, IntPtr hFile, UInt32 dwFlags);

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)] 
public static extern bool FreeLibrary (IntPtr hModule); 

[DllImport ("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)] 
public static extern IntPtr FindResource(IntPtr hModule, int lpID, string lpType); 
'@
    $Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru

    $reader = New-Object System.IO.BinaryReader([System.IO.File]::OpenRead($pFile))
    $length = $reader.BaseStream.Length
    $pData = $reader.ReadBytes($length)
    $reader.Close()

    #PwrUpPwny SeBackupPrivilege | Out-Null
    #PwrUpPwny SeDebugPrivilege | Out-Null
    $accessControl = Get-ACL $imageresFile
    
    Copy-Item $imageresFile "$imageresFile.orig" -Force
    $accessControl.SetOwner([System.Security.Principal.NTAccount]"$env:userdomain\$env:username")
    Set-Acl -Path $imageresFile -AclObject $accessControl

    #check the DLL
    $hModule = $Kernel32::LoadLibraryEx($imageresFile,[IntPtr]::Zero,0x2)
    $soundCheck = $Kernel32::FindResource($hModule, 5080, "WAVE")
    if ($soundCheck -eq $null){return}
    $Kernel32::FreeLibrary($hModule) | Out-Null

    #mod the DLL
    $hUpdate = $Kernel32::BeginUpdateResource($imageresFile,$false)
        if ($hUpdate -eq $null){return}
    <#
    IntPtr hUpdate    // update resource handle (result of BeginUpdateResource)
    string lpType     // change resource (name of resource)
    int iResID        // resource id (resource id)
    ushort wLanguage  // neutral language
    byte[] pData      // ptr to resource info
    uint cbData       // size of resource info
    #>
    $tUpdate=$Kernel32::UpdateResource($hUpdate, "WAVE", 5080, 0x409, $pData, $length)
    if (!$tUpdate){return}
    $success=$Kernel32::EndUpdateResource($hUpdate,$false)
    if($success){Write-Host -ForegroundColor Magenta -BackgroundColor White "Yay Pony Startup!"}
}

function PwnyShortcuts([string]$sadFolder, [string]$pnyDLL="$env:WINDIR\pnyres.dll"){
    $objShell = New-Object -ComObject WScript.Shell
    #https://forums.adobe.com/thread/1317178
    #C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013
    <# Defaults
    my computer
    (Default) $env:SystemRoot\System32\imageres.dll,-109
    
    my documents
    (Default) $env:SystemRoot\System32\imageres.dll,-123
    
    recycle bin
    (Default) $env:SystemRoot\System32\imageres.dll,-54
    empty $env:SystemRoot\System32\imageres.dll,-55
    full $env:SystemRoot\System32\imageres.dll,-54

    network
    (Default) $env:SystemRoot\System32\imageres.dll,-25
    #>

    #MyComputer
    $icon = "HKCU:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\DefaultIcon"
    SP -Path $icon -Name "(Default)" -Value "$pnyDLL,-138" -WhatIf
    #MyDocuments
    $icon = "HKCU:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\DefaultIcon"
    SP -Path $icon -Name "(Default)" -Value "$pnyDLL,-162" -WhatIf
    #RecycleBin
    $icon = "HKCU:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\DefaultIcon"
    SP -Path $icon -Name "(Default)" -Value "$pnyDLL,-250" -WhatIf
    SP -Path $icon -Name "empty" -Value "$pnyDLL,-256" -WhatIf
    SP -Path $icon -Name "full" -Value "$pnyDLL,-250" -WhatIf
    #Network
    $icon = "HKCU:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\DefaultIcon"
    SP -Path $icon -Name "(Default)" -Value "$pnyDLL,-287" -WhatIf #incorrect icon at the moment Nov24/15
    
    $shortcuts = gci $sadFolder -Recurse -Force -Filter '*.lnk' -ErrorAction SilentlyContinue
    $shortcuts | % { 
        $shortcut = $objShell.Createshortcut($_.FullName)
        $icon = 0
        $do=$true
        switch -Wildcard ($shortcut.TargetPath){
        #use the Icon Group to determine index
            "*WINWORD.EXE*"     { $icon = -222 } #-221 is 2010
            "*EXCEL.EXE*"       { $icon = -207 } #-206 is 2010
            "*ONENOTE.EXE*"     { $icon = -212 } #-211 is 2010
            "*OUTLOOK.EXE*"     { $icon = -214 } #-213 is 2010
            "*POWERPNT.EXE*"    { $icon = -216 } #-215 is 2010
            "*PUBLISHER.EXE*"   { $icon = -219 } #-218 is 2010
            "*INFOPATH.EXE*"    { $icon = -209 } #-208 is 2010
            "*ACCESS.EXE*"      { $icon = -205 } #-204 is 2010
            "*AcroRd*"          { $icon = -242 }
            "*firefox*"         { $icon = -146 }
            "*chrome.exe*"      { $icon = -5 }
            "*notepad.exe"      { $icon = -230 }
            "*wordpad*"         { $icon = -235 }
            "*iexplore.exe*"    { $icon = -188 }
            "*opera*"           { $icon = -237 }
            "*Fireworks*"       { $icon = -110 }
            "*Dreamweaver*"     { $icon = -107 }
            "*Illustrator*"     { $icon = -113 }
            "*Photoshop*"       { $icon = -115 }
            "*AfterFX*"         { $icon = -103 }
            "*Bridge.exe*"      { $icon = -111 }
            "*Flash.exe*"       { $icon = -112 }
            "*Adobe Premiere Pro.exe*"    { $icon = -119 }
            "*Soundbooth*"      { $icon = -121 }
            "*audacity*"        { $icon = -123 }
            "*left4dead2.exe*"  { $icon = -101 }
            "*Acrobat.exe*"     { $icon = -102 }
            "*cmd.exe"          { $icon = -143 }
            "*dropbox*"         { $icon = -152 }
            "*steam.exe*"       { $icon = -164 }
            "*minecraft*"       { $icon = -224 } #-163
            "*gimp*"            { $icon = -165 }
            "*gmail*"           { $icon = -166 } #185
            "*canary*"          { $icon = -170 } #not gonna work..chrome canary is also chrome.exe
            "*calc*"            { $icon = -135 } #198
            "*facebook*"        { $icon = -145 }
            "*picasa*"          { $icon = -182 }
            "*mspaint*"         { $icon = -183 }
            "*itunes*"          { $icon = -192 } #191
            "*join.me.exe*"     { $icon = -193 }
            "*eclipse*"         { $icon = -196 }
            "*thunderbird*"     { $icon = -201 }
            "*safari*"          { $icon = -258 }
            "*skype*"           { $icon = -263 }
            "*spotify*"         { $icon = -265 }
            "*starcraft2*"      { $icon = -266 }
            "*sims3*"           { $icon = -270 }
            "*bittorrent*"      { $icon = -274 } #??
            "*MediaPlayer*"     { $icon = -276 } #??
            "*devenv*"          { $icon = -282 } #281 is 2010 (Visual Studio)
            "*vlc*"             { $icon = -284 } #279
            "*winamp*"          { $icon = -286 } 
            "*avg*"             { $icon = -291 } #??
            "*dragonspeak*"     { $icon = -293 } #??
            "*flash*"           { $icon = -294 } #POSSIBLE REPEAT
            "*putty.exe*"       { $icon = -268 } #incorrect icon, mac console
            "*symantec*"        { $icon = -296 } #??
            "*winrar*"          { $icon = -297 } #??
            "*windowsupdate*"   { $icon = -289 }
            "*GitHub*"          { $icon = 1 }
            "*uTorrent.exe*"    { $icon = -272 }
            "*foxit*"           { $icon = -243 }
            "*wow*"             { $icon = -290 } #?? world of warcraft
            default{
                #Write-Host $shortcut.TargetPath "skipped. :("
                $do=$false
            }
        }
        if($do){
            #Write-Host $shortcut.FullName " ponied. ^_^"
            try{
                $shortcut.IconLocation = ("$pnyDLL, $icon")
                $shortcut.Save()
            }catch{
                Write-Host $shortcut.FullName " has a problem saving. :("
            }
        }
    }
}

function PwrUpPwny {
 param(
  # http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
  [ValidateSet(
   "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
   "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
   "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
   "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
   "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
   "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
   "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
   "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
   "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
   "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
   "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
  $Privilege,
  # The process on which to adjust the privilege. Defaults to the current process.
  $ProcessId = $pid,
  [Switch] $Disable
 )
 $MethodDefinition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool PwrUpPwnyilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

 $processHandle = (Get-Process -id $ProcessId).Handle
 $type = Add-Type $MethodDefinition -PassThru
 $type[0]::PwrUpPwnyilege($processHandle, $Privilege, $Disable)
}

#region ASCII
Write-Host -ForegroundColor Magenta -BackgroundColor Black "__________  __      _________  .___________________.___."
Write-Host -ForegroundColor Magenta -BackgroundColor Black "\______   \/  \    /  \      \ |   \_   _____/\__  |   |"
Write-Host -ForegroundColor Magenta -BackgroundColor Black " |     ___/\   \/\/   /   |   \|   ||    __)   /   |   |"
Write-Host -ForegroundColor Magenta -BackgroundColor Black " |    |     \        /    |    \   ||     \    \____   |"
Write-Host -ForegroundColor Magenta -BackgroundColor Black " |____|      \__/\  /\____|__  /___|\___  /    / ______|"
Write-Host -ForegroundColor Magenta -BackgroundColor Black "                  \/         \/         \/     \/       "
Write-Host -ForegroundColor Magenta -BackgroundColor Black " ___.           ____   _________.___.____  _______  ___ "
Write-Host -ForegroundColor Magenta -BackgroundColor Black " \_ |__ ___.__. \   \ /   /\__  |   |\   \/  /\   \/  / "
Write-Host -ForegroundColor Magenta -BackgroundColor Black "  | __ <   |  |  \   Y   /  /   |   | \     /  \     /  "
Write-Host -ForegroundColor Magenta -BackgroundColor Black "  | \_\ \___  |   \     /   \____   | /     \  /     \  "
Write-Host -ForegroundColor Magenta -BackgroundColor Black "  |___  / ____|    \___/    / ______|/___/\  \/___/\  \ "
Write-Host -ForegroundColor Magenta -BackgroundColor Black "      \/\/                  \/             \_/      \_/ "
Write-Host -ForegroundColor Magenta -BackgroundColor Black "                 WELCOME EVERYPONY!                     "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                          ▓▓▓           "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                          ▓▒▒▒▓▓        "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                     ▄▄▄▄▄▄▄▄▄          ▓▒▒▒▒▒▓         "
Write-Host -ForegroundColor Magenta -BackgroundColor White "    ▓▓▓▓▓   ▄█████▓▓▓▓▓▓░░███████▓▒▒▒▒▓▒▓               "
Write-Host -ForegroundColor Magenta -BackgroundColor White "     ▓▒▓▒▓▓▓██▓█▓▓▓▓▓▓▓░░░▓▓▓▓▓▓▓▓▒▒▒▒▒▓▒▓              "
Write-Host -ForegroundColor Magenta -BackgroundColor White "       ▓▒▒▒▓▒▒▓▓▓▓▓▓▓▓░░░▓▓▓▓▓▓▓▓█▒▒▒▒▒▒▓▒▓             "
Write-Host -ForegroundColor Magenta -BackgroundColor White "       █▓▓▒▒▓▒▒▓▒▒▓▓▓░░░▓▓▓▓▓▓▓▓█▒▒▒▒▒▒▒▓▒▓             "
Write-Host -ForegroundColor Magenta -BackgroundColor White "     ▄█▓▓█▓▓▓▒▒▒▓▒▓▓░░░░▓▓▓▓▓▓▓▓█▒▒▒▒▒▒▓▒▒▓             "
Write-Host -ForegroundColor Magenta -BackgroundColor White "    █▓▓▓█▓▓█▓▓▒▓▒▓▓▓░░░░▓▓▓▓▓▓▓▓▓█▒▒▒▒▓▒▒▒▓             "
Write-Host -ForegroundColor Magenta -BackgroundColor White "   █▓▓▓█▓▓█▓▓▓▓▓▓▓▓▓░░░█████████████▒▒▒▒▒▒▓             "
Write-Host -ForegroundColor Magenta -BackgroundColor White "   █▓▓▓█▓▓█▓▓▓▓▓▓██████▒▌__▓█_____▓▓▒▒▒▒▒▒▒▓            "
Write-Host -ForegroundColor Magenta -BackgroundColor White "  ▐█▓▓█▓▓▓█▓▓████▒▒▒▒▒▒▌__▓▓█▄____▓▓▒▒▒▒▒▒▓             "
Write-Host -ForegroundColor Magenta -BackgroundColor White "  ▐█▓█▓▓▓▓███▒▒▒▒▒▒▒▒▒▒▌__▓▓█████▓▓▒▒▒▒▒▒▓              "
Write-Host -ForegroundColor Magenta -BackgroundColor White "   █▓█▓▓██ ▅▄██▄▒▒▒▒▒▒▒▐___▓▓█▄_██▓▓▄▅▅▒▒▒▓           "
Write-Host -ForegroundColor Magenta -BackgroundColor White "   █▓▓██  ▅▄▄▄▌__▀▄▒▒▒▒▒▐___▓▓▓████▓▅▅▄▒▒▒█           "
Write-Host -ForegroundColor Magenta -BackgroundColor White "   █▓█         ▓▄___▀▒▒▒▒▒▐____▓▓▓▓▓▓▅▅▄▒▒▒██          "
Write-Host -ForegroundColor Magenta -BackgroundColor White "   ██           ▓▓█▀█▄▒▒▒▒▒▌________▒▒▒▒▒▒█▓█▌          "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                  ▓▓███▒▒▒▒▒▐____▒▒▒██▒▒██▓██▌          "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                    ▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒█▓▓██▓▓██▓▌          "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                     ▓▒▒▄▒▒▌▒▒▒▒▒▒▒█▓▓▓▓██▓▓▓█          "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                    ▓▒▒▒▒▒▐▒▒▒▒▒▒▒█▓███▓▓▓█▓▓█▌         "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                      ▓▓▓▄▀▒▒▒▒▓▓▓█▓▓▓▓▓▓█▓▓▓▓██        "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                          ▓▓▓▓▓▓    █▓▓██▀▀█▓▓▓▓░░█     "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                       ▀▀  ▄█▓▓▓▓▓░░▓█  "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                        ▄██▓▓▓▓▓▓░░▓▓█  "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                      ██▓▓▓▓▓▓▓▓░░▓▓█   "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                       █▓▓▓▓▓▓▓░░░▓▓█   "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                        █▓▓▓▓▓░░░▓▓▓█   "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                         █▓▓▓░░░▓▓▓▓█   "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                           ██░░░▓▓▓▓█   "
Write-Host -ForegroundColor Magenta -BackgroundColor White "                                              █░▓▓▓█    "
#endregion

#PwrUpPwny SeBackupPrivilege | Out-Null
#PwrUpPwny SeDebugPrivilege | Out-Null
#PwnyStartSound "C:\Temp\r2d2.wav"
#PwnyShortcuts "$env:USERPROFILE\..\" -pnyDLL "$env:USERPROFILE\Desktop\pnyres.dll"
#PwnySound
#PwnyMouse