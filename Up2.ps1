# Verificar si el usuario actual es administrador
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "El usuario tiene privilegios de administrador."

    # Ruta del registro donde se controla la creación de usuarios
    $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    # Comprobar si la clave existe
    if (Test-Path $regKey) {
        # Comprobar si la clave NoAddUser existe y restaurar la configuración
        $currentValue = (Get-ItemProperty -Path $regKey -Name "NoAddUser" -ErrorAction SilentlyContinue).NoAddUser
        
        if ($null -ne $currentValue) {
            # Si la clave NoAddUser existe, ponerla en 0 para permitir la creación de usuarios
            Set-ItemProperty -Path $regKey -Name "NoAddUser" -Value 0
            Write-Host "La creación de nuevos usuarios ha sido restablecida (desbloqueada)."
        } else {
            Write-Host "No se encontró la clave NoAddUser. No es necesario hacer cambios."
        }
    } else {
        Write-Host "No se encontró la clave de registro relacionada con la creación de usuarios. No es necesario hacer cambios."
    }
} else {
    Write-Host "El usuario no tiene privilegios de administrador. No se pueden hacer cambios."
}
