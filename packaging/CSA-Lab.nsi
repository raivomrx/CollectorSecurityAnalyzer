Unicode True
!include "MUI2.nsh"

!define PRODUCT_NAME "CSA Lab"
!define PRODUCT_VERSION "5.2.2"
!define PRODUCT_PUBLISHER "CollectorSecurityAnalyzer"
!define PRODUCT_EXE "CSA-Lab.exe"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\CSA Lab"

Name "${PRODUCT_NAME}"
OutFile "..\dist\installer\CSA-Lab-Setup.exe"
InstallDir "$LOCALAPPDATA\Programs\CSA Lab"
InstallDirRegKey HKCU "Software\CollectorSecurityAnalyzer\CSA Lab" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "CollectorSecurityAnalyzer"
ShowInstDetails show
ShowUninstDetails show

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PRODUCT_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Open CSA Lab"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "CSA Lab" SEC_MAIN
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  File /r "..\dist\CSA-Lab\*.*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\CSA Lab"
  CreateShortcut "$SMPROGRAMS\CSA Lab\CSA Lab.lnk" "$INSTDIR\${PRODUCT_EXE}"
  CreateShortcut "$SMPROGRAMS\CSA Lab\Uninstall CSA Lab.lnk" "$INSTDIR\Uninstall.exe"

  WriteRegStr HKCU "Software\CollectorSecurityAnalyzer\CSA Lab" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\${PRODUCT_EXE}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  Delete "$SMPROGRAMS\CSA Lab\CSA Lab.lnk"
  Delete "$SMPROGRAMS\CSA Lab\Uninstall CSA Lab.lnk"
  RMDir "$SMPROGRAMS\CSA Lab"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  DeleteRegKey HKCU "Software\CollectorSecurityAnalyzer\CSA Lab"
  MessageBox MB_OK \
    "Assessment data under $LOCALAPPDATA\CSA was retained. Remove it only after export and backup."
SectionEnd
