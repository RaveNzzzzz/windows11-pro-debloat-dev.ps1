# windows11-pro-debloat-dev.ps1
Debloat Windows 11 Pro

# Open PowerShell as Admin
Set-ExecutionPolicy Bypass -Scope Process
.\windows11-pro-debloat-dev.ps1

#########################################################
# Windows 11 Pro - Debloat Total (DEV / POWER USER)
# Autor: SeuNome
# Uso: PowerShell como Administrador
#########################################################

Write-Host "=== WINDOWS 11 PRO DEBLOAT TOTAL ===" -ForegroundColor Cyan

# ======================================================
# 0. Ponto de restauração
# ======================================================
Write-Host "Criando ponto de restauracao..." -ForegroundColor Yellow
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "Antes do Debloat Total" -RestorePointType "MODIFY_SETTINGS"

# ======================================================
# 1. Remover Apps UWP inúteis
# ======================================================
Write-Host "Removendo apps UWP desnecessarios..." -ForegroundColor Yellow

$apps = @(
    "*Microsoft.Bing*",
    "*Microsoft.Copilot*",
    "*Microsoft.WindowsWidgets*",
    "*Microsoft.GetHelp*",
    "*Microsoft.Getstarted*",
    "*Microsoft.MicrosoftOfficeHub*",
    "*Microsoft.People*",
    "*Microsoft.MicrosoftSolitaireCollection*",
    "*Microsoft.Xbox*",
    "*Microsoft.ZuneMusic*",
    "*Microsoft.ZuneVideo*",
    "*MicrosoftTeams*",
    "*Microsoft.OneConnect*",
    "*Microsoft.MixedReality*",
    "*Microsoft.YourPhone*"
)

foreach ($app in $apps) {
    Get-AppxPackage -AllUsers $app | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

# ======================================================
# 2. Remover Microsoft Edge (o máximo possível)
# ======================================================
Write-Host "Removendo Microsoft Edge..." -ForegroundColor Yellow

$edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application"
if (Test-Path $edgePath) {
    $version = Get-ChildItem $edgePath | Sort-Object Name -Descending | Select-Object -First 1
    $installer = "$($version.FullName)\Installer\setup.exe"

    if (Test-Path $installer) {
        & $installer --uninstall --system-level --force-uninstall
    }
}

# Bloquear reinstalação
reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v DoNotUpdateToEdgeWithChromium /t REG_DWORD /d 1 /f

# ======================================================
# 3. Desativar SmartScreen
# ======================================================
Write-Host "Desativando SmartScreen..." -ForegroundColor Yellow

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f

# ======================================================
# 4. Microsoft Defender - modo passivo
# ======================================================
Write-Host "Colocando Microsoft Defender em modo passivo..." -ForegroundColor Yellow

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

Stop-Service WinDefend -Force -ErrorAction SilentlyContinue
Set-Service WinDefend -StartupType Disabled -ErrorAction SilentlyContinue

# ======================================================
# 5. Desativar Pesquisa do Windows (Search / Indexação)
# ======================================================
Write-Host "Desativando Windows Search..." -ForegroundColor Yellow

Stop-Service WSearch -Force -ErrorAction SilentlyContinue
Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue

# Remover Bing da pesquisa
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f

# ======================================================
# 6. Telemetria no minimo
# ======================================================
Write-Host "Reduzindo telemetria..." -ForegroundColor Yellow

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

$telemetryServices = @(
    "DiagTrack",
    "dmwappushservice"
)

foreach ($svc in $telemetryServices) {
    Stop-Service $svc -ErrorAction SilentlyContinue
    Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# ======================================================
# 7. Desativar anúncios e sugestões
# ======================================================
Write-Host "Desativando anuncios e sugestoes..." -ForegroundColor Yellow

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f

# ======================================================
# 8. Desativar tarefas agendadas inúteis
# ======================================================
Write-Host "Desativando tarefas agendadas..." -ForegroundColor Yellow

Get-ScheduledTask | Where-Object TaskName -like "*Edge*" | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask | Where-Object TaskName -like "*Telemetry*" | Disable-ScheduledTask -ErrorAction SilentlyContinue

# ======================================================
# 9. Explorer mais limpo
# ======================================================
Write-Host "Ajustando Explorer..." -ForegroundColor Yellow

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Widgets /t REG_DWORD /d 0 /f

# ======================================================
# FINAL
# ======================================================
Write-Host "DEBLOAT FINALIZADO. Reinicie o computador." -ForegroundColor Green
