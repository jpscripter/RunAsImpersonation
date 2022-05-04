Function Invoke-CommandWithCredential { 
    <#
    .SYNOPSIS
    Uses a PSCredential to start a process 
    
    .DESCRIPTION
    Uses the PSCredential and win32 apis to launch a process
    
    .PARAMETER Credential
    Credential to execute the scriptblock as

    .PARAMETER Binary
    a hash table of the parameters you want to pass into your scriptblock
    
    .PARAMETER Parameters
    Parameters to pass the exe
    
    .PARAMETER ShowUI
    What exe block should be run

    .EXAMPLE
    PS> 
    
    
    .LINK
    http://www.JPScripter.com

    
    #>
        param(  
            [PSCredential]$Credential,
            [System.IO.FileInfo]$Binary = $env:ComSpec,
            [string]$Parameters,
            [Pinvoke.LogonFlags] $logonFlag = [Pinvoke.LogonFlags]::DEFAULT,
            [int]$CreationFlags = ([Pinvoke.CreationFlags]::CREATE_NEW_CONSOLE -bor [Pinvoke.CreationFlags]::CREATE_NEW_PROCESS_GROUP -bor [Pinvoke.CreationFlags]::CREATE_UNICODE_ENVIRONMENT),
            [int]$StartInfoFlags = ([Pinvoke.StartInfoFlags]::STARTF_USESHOWWINDOW),
            [switch] $ShowUI

        )
        Begin{
            $LogonType = [Pinvoke.dwLogonType]::Interactive
            if ($NetOnly.IsPresent){$LogonType = [Pinvoke.dwLogonType]::NewCredentials}

        }
        Process {
            $StartInfo = New-Object Pinvoke.StartupInfo
            $StartInfo.flags = $StartInfoFlags
            $StartInfo.showWindow = 0
            if ($ShowUI.IsPresent){
                $StartInfo.showWindow = 1
            }
            $StartInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartInfo) 

            $ProcessInfo = New-Object Pinvoke.ProcessInformation
            $CurrentDirectory = (Get-Location).Path

            $Success = [Pinvoke.advapi32]::CreateProcessWithLogonW(
                $Credential.GetNetworkCredential().UserName,
                $Credential.GetNetworkCredential().Domain,
                $Credential.GetNetworkCredential().Password,
                $logonFlag,
                $Binary.FullName,
                $Parameters,
                $CreationFlags,
                $Null,
                $CurrentDirectory,
                [ref]$StartInfo,
                [ref]$ProcessInfo
            )
                
            if (-not $Success){
                $Lasterr = ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
                Write-Error -Message "Failed to start process $lasterr"
            }
        }
        End {
            $ProcessInfo.processId
        }
    }