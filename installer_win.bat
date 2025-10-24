@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ========================== XiaoHackParental — Instalador ==========================
REM - Crea/actualiza venv, pip y requirements
REM - Copia proyecto a %ProgramData%\XiaoHackParental
REM - Crea run_guardian.bat, abrir_panel.bat, uninstall.bat
REM - Crea accesos (sin duplicados): Escritorio Público y Menú Inicio (común)
REM - Crea Notifier en Inicio común
REM - Crea/actualiza tarea programada (SYSTEM) y la lanza
REM - Log en C:\ProgramData\XiaoHackParental\logs\installer_debug.log
REM ================================================================================

REM ------------------------------------------------------------------------------
REM UAC Elevation
REM ------------------------------------------------------------------------------
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if not "%errorlevel%"=="0" (
    echo [!] Elevando permisos como administrador...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

REM ------------------------------------------------------------------------------
REM Rutas
REM ------------------------------------------------------------------------------
set "PROJ=%~dp0"
if "%PROJ:~-1%"=="\" set "PROJ=%PROJ:~0,-1%"

set "INSTALL_DIR=%ProgramData%\XiaoHackParental"
set "LOG_DIR=%INSTALL_DIR%\logs"
set "LOG=%LOG_DIR%\installer_debug.log"

set "VENV=%INSTALL_DIR%\venv"
set "PYEXE=%VENV%\Scripts\python.exe"
set "PYW=%VENV%\Scripts\pythonw.exe"

set "RUN_GUARDIAN=%INSTALL_DIR%\run_guardian.bat"
set "RUN_PANEL=%INSTALL_DIR%\abrir_panel.bat"
set "UNINSTALL=%INSTALL_DIR%\uninstall.bat"

set "STARTUP_COMMON=%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"
set "PROGRAMS_COMMON=%ProgramData%\Microsoft\Windows\Start Menu\Programs"
set "PUB_DESK=%PUBLIC%\Desktop"

set "LNK_NOTIFIER=%STARTUP_COMMON%\XiaoHackParental Notifier.lnk"
set "LNK_PANEL_PUB=%PUB_DESK%\XiaoHack Parental.lnk"
set "LNK_UNINST_PUB=%PUB_DESK%\XiaoHack Uninstall.lnk"
set "LNK_MENU_DIR=%PROGRAMS_COMMON%\XiaoHack Parental"
set "LNK_MENU_PANEL=%LNK_MENU_DIR%\XiaoHack Parental.lnk"
set "LNK_MENU_UNINST=%LNK_MENU_DIR%\Desinstalar XiaoHack Parental.lnk"

set "ICON=%INSTALL_DIR%\assets\app_icon.ico"
set "PY_REQ=%PROJ%\requirements.txt"


REM ------------------------------------------------------------------------------
REM Crear carpetas base
REM ------------------------------------------------------------------------------
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%STARTUP_COMMON%" mkdir "%STARTUP_COMMON%" >nul 2>&1
if not exist "%LNK_MENU_DIR%" mkdir "%LNK_MENU_DIR%" >nul 2>&1

echo ==== INSTALADOR XiaoHackParental ==== %DATE% %TIME% > "%LOG%"
echo [INFO] PROJ = "%PROJ%" >> "%LOG%"
echo [INFO] INSTALL_DIR = "%INSTALL_DIR%" >> "%LOG%"
echo. >> "%LOG%"

REM ------------------------------------------------------------------------------
REM Copia proyecto (excluye carpetas basura)
REM ------------------------------------------------------------------------------
echo [INFO] Copiando proyecto...
echo [INFO] Copiando proyecto... >> "%LOG%"

REM /MIR     : espejo (crea/actualiza y elimina lo que ya no esté)
REM /E       : incluye vacías (lo incluye implícitamente /MIR)
REM /XD      : excluye directorios
REM /XF      : excluye ficheros
REM /R:1 /W:2: reintentos bajos
REM /NFL /NDL /NP: menos ruido
robocopy "%PROJ%" "%INSTALL_DIR%" /MIR /R:1 /W:2 /NFL /NDL /NP ^
  /XD ".git" ".venv" "venv" "build" "dist" "__pycache__" "node_modules" ^
  /XF "Thumbs.db" "desktop.ini" >> "%LOG%" 2>&1

REM Nota: ROBOCOPY devuelve códigos >0 aun con éxito; no fallamos por ERRORLEVEL
REM ------------------------------------------------------------------------------
REM Python + venv
REM ------------------------------------------------------------------------------
set "PY="
for %%V in (3.12 3.11) do (
  py -%%V -c "import sys; print(sys.version)" >> "%LOG%" 2>&1 && (set "PY=py -%%V" & goto :got_py)
)
:got_py
if not defined PY (
  echo [ERROR] Python 3.11+ no encontrado. >> "%LOG%"
  echo Instala Python 3.11+ y reintenta.
  pause
  exit /b 1
)

if not exist "%PYEXE%" (
  echo [INFO] Creando venv...
  echo [INFO] Creando venv... >> "%LOG%"
  %PY% -m venv "%VENV%" >> "%LOG%" 2>&1
)

"%PYEXE%" -m ensurepip --upgrade >> "%LOG%" 2>&1
"%PYEXE%" -m pip install --upgrade pip setuptools wheel >> "%LOG%" 2>&1

if exist "%PY_REQ%" (
  echo [INFO] Instalando requirements...
  echo [INFO] Instalando requirements... >> "%LOG%"
  "%PYEXE%" -m pip install -r "%PY_REQ%" >> "%LOG%" 2>&1
) else (
  echo [WARN] requirements.txt no encontrado en "%PY_REQ%". >> "%LOG%"
)

REM Paquetes útiles (idempotente)
"%PYEXE%" -m pip install --upgrade psutil setproctitle bcrypt >> "%LOG%" 2>&1

REM ------------------------------------------------------------------------------
REM Scripts auxiliares (.bat)
REM ------------------------------------------------------------------------------
echo [INFO] Escribiendo scripts auxiliares...
echo [INFO] Escribiendo scripts auxiliares... >> "%LOG%"

> "%RUN_GUARDIAN%" (
  echo @echo off
  echo setlocal
  echo cd /d "%INSTALL_DIR%"
  echo set "PYTHONUNBUFFERED=1"
  echo set "PYEXE=%VENV%\Scripts\python.exe"
  echo set "PYW=%VENV%\Scripts\pythonw.exe"
  echo set "APPDATA=%INSTALL_DIR%"
  echo set "LOCALAPPDATA=%INSTALL_DIR%"
  echo set "HOME=%INSTALL_DIR%"
  echo if not exist "%INSTALL_DIR%\logs" mkdir "%INSTALL_DIR%\logs"
  echo "%PYEXE%" "%INSTALL_DIR%\guardian.py" --xh-role guardian --no-ui ^>^> "%INSTALL_DIR%\logs\guardian_launcher.log" 2^>^&1
)


> "%RUN_PANEL%" (
  echo @echo off
  echo setlocal
  echo cd /d "%INSTALL_DIR%"
  echo start "" "%PYW%" "%INSTALL_DIR%\run.py" --xh-role panel --no-countdown
)

> "%UNINSTALL%" (
  echo @echo off
  echo setlocal
  echo cd /d "%INSTALL_DIR%"
  echo "%PYEXE%" "%INSTALL_DIR%\uninstall.py"
  echo pause
)

REM ------------------------------------------------------------------------------
REM Tarea programada SYSTEM (Guardian)
REM ------------------------------------------------------------------------------
echo [INFO] Creando/actualizando tarea XiaoHackParental\Guardian...
echo [INFO] Creando/actualizando tarea XiaoHackParental\Guardian... >> "%LOG%"
schtasks /Delete /TN "XiaoHackParental\Guardian" /F >> "%LOG%" 2>&1

schtasks /Create ^
  /TN "XiaoHackParental\Guardian" ^
  /TR "\"%RUN_GUARDIAN%\"" ^
  /SC ONSTART ^
  /RU SYSTEM ^
  /RL HIGHEST ^
  /F >> "%LOG%" 2>&1

if errorlevel 1 (
  echo [WARN] Reintentando creación con cmd /c... >> "%LOG%"
  schtasks /Create ^
    /TN "XiaoHackParental\Guardian" ^
    /TR "cmd /c \"\"%RUN_GUARDIAN%\"\"" ^
    /SC ONSTART ^
    /RU SYSTEM ^
    /RL HIGHEST ^
    /F >> "%LOG%" 2>&1
)


if errorlevel 1 (
  echo [ERROR] No se pudo crear la tarea XiaoHackParental\Guardian. >> "%LOG%"
) else (
  echo [OK] Tarea creada.
  echo [OK] Tarea creada. >> "%LOG%"
)

REM --- Ajustar configuración avanzada de la tarea (PowerShell ScheduledTasks) ---
powershell -NoProfile -ExecutionPolicy Bypass ^
  -Command "$p='\XiaoHackParental\'; $n='Guardian';" ^
           "$t=Get-ScheduledTask -TaskPath $p -TaskName $n;" ^
           "$s=$t.Settings;" ^
           "$s.ExecutionTimeLimit='PT0S';" ^
           "$s.DisallowStartIfOnBatteries=$false;" ^
           "$s.StopIfGoingOnBatteries=$false;" ^
           "$s.RunOnlyIfNetworkAvailable=$false;" ^
           "Set-ScheduledTask -TaskPath $p -TaskName $n -Settings $s | Out-Null;"

schtasks /Query /TN "XiaoHackParental\Guardian" /FO LIST /V >> "%LOG%" 2>&1     
echo [OK] Tarea Actualizada.
echo [OK] Tarea Actualizada. >> "%LOG%"
REM Primer arranque robusto
schtasks /Change /TN "XiaoHackParental\Guardian" /ENABLE >nul 2>&1
schtasks /End   /TN "XiaoHackParental\Guardian" >nul 2>&1
schtasks /Run   /TN "XiaoHackParental\Guardian" >nul 2>&1


REM ------------------------------------------------------------------------------
REM Tarea programada SYSTEM (Notifier)
REM ------------------------------------------------------------------------------
echo [INFO] Creando/actualizando tarea XiaoHackParental\Notificador...
echo [INFO] Creando/actualizando tarea XiaoHackParental\Notificador... >> "%LOG%"

REM --- Wrapper temporal para ejecutar notifier desde SYSTEM ---
set "RUN_NOTIFIER=%INSTALL_DIR%\run_notifier.bat"
> "%RUN_NOTIFIER%" (
  echo @echo off
  echo setlocal
  echo cd /d "%INSTALL_DIR%"
  echo set "PYEXE=%VENV%\Scripts\python.exe"
  echo if not exist "%INSTALL_DIR%\logs" mkdir "%INSTALL_DIR%\logs"
  echo "%PYEXE%" "%INSTALL_DIR%\notifier.py" --xh-role notifier ^>^> "%INSTALL_DIR%\logs\notifier.log" 2^>^&1
)

REM --- Eliminar tarea previa si existía ---
schtasks /Delete /TN "XiaoHackParental\Notificador" /F >> "%LOG%" 2>&1

REM --- Crear tarea programada tipo SYSTEM (ONSTART, prioridad alta) ---
schtasks /Create ^
  /TN "XiaoHackParental\Notificador" ^
  /TR "\"%RUN_NOTIFIER%\"" ^
  /SC ONSTART ^
  /RU SYSTEM ^
  /RL HIGHEST ^
  /F >> "%LOG%" 2>&1

if errorlevel 1 (
  echo [WARN] Reintentando creación con cmd /c... >> "%LOG%"
  schtasks /Create ^
    /TN "XiaoHackParental\Notificador" ^
    /TR "cmd /c \"\"%RUN_NOTIFIER%\"\"" ^
    /SC ONSTART ^
    /RU SYSTEM ^
    /RL HIGHEST ^
    /F >> "%LOG%" 2>&1
)

if errorlevel 1 (
  echo [ERROR] No se pudo crear la tarea XiaoHackParental\Notificador. >> "%LOG%"
) else (
  echo [OK] Tarea XiaoHackParental\Notificador creada. >> "%LOG%"
)

REM --- Ajustar configuración avanzada (sin límite, sin batería, autoreintentos) ---
powershell -NoProfile -ExecutionPolicy Bypass ^
  -Command "$p='\XiaoHackParental\'; $n='Notificador';" ^
           "$t=Get-ScheduledTask -TaskPath $p -TaskName $n;" ^
           "$s=$t.Settings;" ^
           "$s.ExecutionTimeLimit='PT0S';" ^
           "$s.DisallowStartIfOnBatteries=$false; $s.StopIfGoingOnBatteries=$false;" ^
           "$s.RunOnlyIfNetworkAvailable=$false; $s.StartWhenAvailable=$true; $s.AllowStartOnDemand=$true;" ^
           "$s.RestartCount=3; $s.RestartInterval='PT1M'; $s.Hidden=$true;" ^
           "Set-ScheduledTask -TaskPath $p -TaskName $n -Settings $s | Out-Null;" >> "%LOG%" 2>&1

echo [DIAG] Estado tarea Notificador >> "%LOG%"
schtasks /Query /TN "XiaoHackParental\Notificador" /FO LIST /V >> "%LOG%" 2>&1

REM --- Arranque inicial del notifier ---
schtasks /Change /TN "XiaoHackParental\Notificador" /ENABLE >nul 2>&1
schtasks /End    /TN "XiaoHackParental\Notificador" >nul 2>&1
schtasks /Run    /TN "XiaoHackParental\Notificador" >nul 2>&1


REM ------------------------------------------------------------------------------
REM Accesos de Escritorio (solo Público, sin duplicados)
REM ------------------------------------------------------------------------------
echo [INFO] Creando accesos en Escritorio Publico...
echo [INFO] Creando accesos en Escritorio Publico... >> "%LOG%"
del /q "%LNK_PANEL_PUB%"  >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass ^
  -Command "$ws=New-Object -ComObject WScript.Shell;" ^
           "$ico='%ICON%';" ^
           "if (-not (Test-Path $ico)) { $ico = '%INSTALL_DIR%\assets\app_icon.ico' }" ^
           "if (-not (Test-Path $ico)) { $ico = '%PYW%' }" ^
           "$s=$ws.CreateShortcut('%LNK_PANEL_PUB%');" ^
           "$s.TargetPath='%PYW%';" ^
           "$s.Arguments='\"%INSTALL_DIR%\run.py\" --xh-role panel --no-countdown';" ^
           "$s.WorkingDirectory='%INSTALL_DIR%';" ^
           "$s.IconLocation=$ico;" ^
           "$s.Save();" 

REM ------------------------------------------------------------------------------
REM Accesos en Menú Inicio \ Programas (común) — sin duplicados
REM ------------------------------------------------------------------------------
echo [INFO] Creando accesos en Menu Inicio (comun)...
echo [INFO] Creando accesos en Menu Inicio (comun)... >> "%LOG%"
del /q "%LNK_MENU_PANEL%"  >nul 2>&1
del /q "%LNK_MENU_UNINST%" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass ^
  -Command "$ws=New-Object -ComObject WScript.Shell;" ^
           "$ico='%ICON%';" ^
           "if (-not (Test-Path $ico)) { $ico = '%INSTALL_DIR%\assets\app_icon.ico' }" ^
           "if (-not (Test-Path $ico)) { $ico = '%PYW%' }" ^
           "$s=$ws.CreateShortcut('%LNK_MENU_PANEL%');" ^
           "$s.TargetPath='%PYW%';" ^
           "$s.Arguments='\"%INSTALL_DIR%\run.py\" --xh-role panel --no-countdown';" ^
           "$s.WorkingDirectory='%INSTALL_DIR%';" ^
           "$s.IconLocation=$ico;" ^
           "$s.Save();" ^
           "$u=$ws.CreateShortcut('%LNK_MENU_UNINST%');" ^
           "$u.TargetPath='%UNINSTALL%';" ^
           "$u.WorkingDirectory='%INSTALL_DIR%';" ^
           "$u.IconLocation=$ico;" ^
           "$u.Save();"

echo. >> "%LOG%"
echo [OK] Instalacion completa.
echo [OK] Log: "%LOG%"
pause
exit /b 0
