; LockPing Agent — per-gebruiker installer (geen adminrechten nodig).
; Gebouwd in CI met makensis; verwacht lockping-agent.exe naast dit script.

!define APPNAME "LockPing Agent"
!define COMPANY "RM-Worx"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\LockPing"
!define RUNKEY "Software\Microsoft\Windows\CurrentVersion\Run"

Name "${APPNAME}"
OutFile "lockping-agent-setup.exe"
Unicode true
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\LockPing"
Icon "lockping.ico"
UninstallIcon "lockping.ico"

Page components
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "LockPing Agent (vereist)"
  SectionIn RO
  SetOutPath $INSTDIR
  File "lockping-agent.exe"
  File "lockping.ico"

  CreateDirectory "$SMPROGRAMS\LockPing"
  CreateShortcut "$SMPROGRAMS\LockPing\LockPing Agent.lnk" \
    "$INSTDIR\lockping-agent.exe" "open" "$INSTDIR\lockping.ico"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\lockping.ico"
  WriteRegStr HKCU "${UNINSTKEY}" "Publisher" "${COMPANY}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoRepair" 1
SectionEnd

Section "Automatisch meestarten met Windows"
  WriteRegStr HKCU "${RUNKEY}" "LockPing" '"$INSTDIR\lockping-agent.exe" run'
SectionEnd

Section "Open de companion na installatie"
  Exec '"$INSTDIR\lockping-agent.exe" open'
SectionEnd

Section "Uninstall"
  ; Agent stoppen als hij draait (best effort).
  ExecWait 'taskkill /IM lockping-agent.exe /F' $0
  Delete "$INSTDIR\lockping-agent.exe"
  Delete "$INSTDIR\lockping.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\LockPing\LockPing Agent.lnk"
  RMDir "$SMPROGRAMS\LockPing"
  DeleteRegValue HKCU "${RUNKEY}" "LockPing"
  DeleteRegKey HKCU "${UNINSTKEY}"
  ; Sleutels en pairing-gegevens bewust laten staan (%APPDATA%\lockping):
  ; herinstalleren = zelfde identiteit, koppelingen blijven werken.
SectionEnd
