# Verificar si el usuario actual es administrador
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Verificar si el script está siendo ejecutado como administrador
if ($isAdmin) {
    Write-Host "El usuario tiene privilegios de administrador."

    # Ruta del registro donde se controla la creación de usuarios
    $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    # Comprobar si la clave existe, si no, crearla
    if (!(Test-Path $regKey)) {
        New-Item -Path $regKey -Force
    }

    # Verificar si el bloqueo está activado
    $currentValue = (Get-ItemProperty -Path $regKey -Name "NoAddUser" -ErrorAction SilentlyContinue).NoAddUser

    # Si la clave NoAddUser no existe, significa que la creación de usuarios no está bloqueada
    if ($null -eq $currentValue) {
        # Si NoAddUser no está presente, bloquear la creación de usuarios
        Set-ItemProperty -Path $regKey -Name "NoAddUser" -Value 1
        Write-Host "La creación de nuevos usuarios ha sido bloqueada."
    } elseif ($currentValue -eq 1) {
        # Si NoAddUser es 1, desbloquear la creación de usuarios
        Set-ItemProperty -Path $regKey -Name "NoAddUser" -Value 0
        Write-Host "La creación de nuevos usuarios ha sido desbloqueada."
    } else {
        # Si NoAddUser es 0, bloquear la creación de usuarios
        Set-ItemProperty -Path $regKey -Name "NoAddUser" -Value 1
        Write-Host "La creación de nuevos usuarios ha sido bloqueada."
    }
} else {
    Write-Host "El usuario no tiene privilegios de administrador. No se pueden hacer cambios."
}
