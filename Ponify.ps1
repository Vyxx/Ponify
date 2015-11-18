clear
<#Todo
 UserPicture (Current and Default user)
 LockScreen (get win version and adjust accordingly)
 Change startbar/quicklaunch shortcut icons (
 Change system fonts?
 Change web browser settings (include pony theme?)

 Need Custom DLL for icons
 Need Custom Sounds set
 Need Custom Mouse Cursors
 Need startup WAV file
#>

#Ƹ̵̡Ӝ̵̨̄Ʒ 

<#Done
UserPicture      (
Wallpaper        (reg key mod)
Startup Sound    (dll inject)
MousePack Change (reg key mods)
System Sounds    (reg key mods)
Shortcut Change  (editing the .lnk properties)
#>

function PwnBrowser{
    #change homepages
    #find chrome, firefox, and ie, maybe edge
}

function PwnFonts{
    #figure out this one
}

function PwnQuickLaunch{
    PwnyShortcuts("%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
}

function PwnyUserIcon{
<#
C:\ProgramData\Microsoft\Default Account Pictures\user.bmp
C:\ProgramData\Microsoft\User Account Pictures\user.bmp

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
UseDefaultTile
1

#>

}

function PwnyLockScreen{
<#
"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background" 
"OEMBackground"
1

Mkdir C:\Windows\System32\oobe\Info\backgrounds
insert
"backgroundDefault.jpg"
#>
}

function PwnyPaper([string]$pnyPaper){
    GP -Path "HKCU:\Control Panel\Desktop\" -Name "wallpaper"
    Reg export "HKEY_CURRENT_USER\Control Panel\Desktop" "C:\Temp\desktopProps.reg"
    Set-ItemProperty -path "HKCU:\Control Panel\Desktop\" -name wallpaper -value $pnyPaper
    rundll32.exe user32.dll, UpdatePerUserSystemParameters
}

function PwnyStartSound([string]$pfile){
#usage PwnyStartSound "C:\temp\r2d2.wav"
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

function PwnyMouse{
    $mouseReg = ("HKCU:\Control Panel\Cursors")
    SP -WhatIf -Path $mouseReg -Name "(Default)" -Value "Pony"
    SP -WhatIf -Path $mouseReg -Name "AppStarting" -Value "%SystemRoot%\cursors\aero_working.ani"
    SP -WhatIf -Path $mouseReg -Name "Arrow" -Value "%SystemRoot%\cursors\aero_arrow.cur"
    SP -WhatIf -Path $mouseReg -Name "Crosshair" -Value "%SystemRoot%\cursors\cross_r.cur"
    SP -WhatIf -Path $mouseReg -Name "Hand" -Value "%SystemRoot%\cursors\aero_link.cur"
    SP -WhatIf -Path $mouseReg -Name "Help" -Value "%SystemRoot%\cursors\aero_helpsel.cur"
    SP -WhatIf -Path $mouseReg -Name "IBeam" -Value ""
    SP -WhatIf -Path $mouseReg -Name "No" -Value "%SystemRoot%\cursors\aero_unavail.cur"
    SP -WhatIf -Path $mouseReg -Name "NWPen" -Value "%SystemRoot%\cursors\aero_pen.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeAll" -Value "%SystemRoot%\cursors\aero_move.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeNESW" -Value "%SystemRoot%\cursors\aero_nesw.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeNS" -Value "%SystemRoot%\cursors\aero_ns.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeNWSE" -Value "%SystemRoot%\cursors\aero_nwse.cur"
    SP -WhatIf -Path $mouseReg -Name "SizeWE" -Value "%SystemRoot%\cursors\aero_ew.cur"
    SP -WhatIf -Path $mouseReg -Name "UpArrow" -Value "%SystemRoot%\cursors\aero_up.cur"
    SP -WhatIf -Path $mouseReg -Name "Wait" -Value "%SystemRoot%\cursors\aero_busy.cur"
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
            "WindowsLogon"{$key.SetValue("","%SystemRoot%\media\Windows Logon.wav")}
            "WindowsUAC"{}
            "WindowsUnlock"{}
            default{Write-Host -ForegroundColor RED $soundName}
        }
    }
}

function PwnyShortcuts([string]$sadFolder, [string]$pnyDLL="C:\Windows\System32\SHELL32.dll"){
    $objShell = New-Object -ComObject WScript.Shell
    #C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office 2013
    $shortcuts = Get-ChildItem sadFolder -Filter '*.lnk'
    $icon = 0
    $shortcuts | % { 
        $shortcut = $objShell.Createshortcut($_.FullName)
        switch -Wildcard ($shortcut.TargetPath){
            "*accicons*"    { $icon = 1 }
            "*wordi*"       { $icon = 2 }
            "*infi*"        { $icon = 3 }
            "*joti*"        { $icon = 4 }
            "*outi*"        { $icon = 5 }
            "*ppti*"        { $icon = 6 }
            "*xli*"         { $icon = 7 }
            "*firefox*"     { $icon = 11 }
            "*iexp*"        { $icon = 9 }
            "*notepad.exe"  { $icon = 11 }
            #mycomputer, control panel, recycle bin, network, adobe
            default{Write-Host $shortcut.TargetPath "skipped. :("}
        }
        Write-Host $shortcut.FullName "ponied. ^_^"
        $shortcut.IconLocation = ("$pnyDLL, $icon")
        $shortcut.Save()
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
#PwnySound
#PwnyMouse
#PwnyShortcuts

#Find-WinAPIFunction kernel32.dll LoadResource