Function Invoke-CommandWithToken { 
    <#
    .SYNOPSIS
    Uses a PSCredential object to build a token 
    
    .DESCRIPTION
    Uses the PSCredential and win32 apis to log the user in and create a local or network only token
    
    .PARAMETER Credential
    Credential to execute the scriptblock as

    .PARAMETER NetOnly
    Credential to execute the scriptblock as

    .PARAMETER Token
    what token should be used to run the script block

    .PARAMETER Binary
    a hash table of the parameters you want to pass into your scriptblock
    
    .PARAMETER CommandLine
    What exe block should be run
    
    .PARAMETER ShowUI
    What exe block should be run

    .EXAMPLE
    PS> 
    
    
    .LINK
    http://www.JPScripter.com
    https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
    
    #>
        param(  
            [Parameter(ParameterSetName = "Token")]
            [Security.Principal.WindowsIdentity]$Token,
            [System.IO.FileInfo]$Binary = $env:ComSpec,
            [string]$Parameters,
            [Pinvoke.LogonFlags] $logonFlag = [Pinvoke.LogonFlags]::DEFAULT,
            [int] $CreationFlags = ([Pinvoke.CreationFlags]::CREATE_NEW_CONSOLE -bor [Pinvoke.CreationFlags]::CREATE_NEW_PROCESS_GROUP -bor [Pinvoke.CreationFlags]::CREATE_UNICODE_ENVIRONMENT),
            [int]$StartInfoFlags = ([Pinvoke.StartInfoFlags]::STARTF_USESHOWWINDOW),
            [string]$Desktop,
            [switch] $ShowUI

        )
        Begin{
            $LogonType = [Pinvoke.dwLogonType]::Interactive
            if ($NetOnly.IsPresent){[Pinvoke.dwLogonType]::NewCredentials}
            if ($null -NE $Credential){
                $token = Get-CredentialToken -Credential $Credential -LogonType $LogonType
            }
            Set-jpsProcessPrivilage -ProcessPrivilege SeAssignPrimaryTokenPrivilege
            Set-jpsProcessPrivilage -ProcessPrivilege SeIncreaseQuotaPrivilege
        }
        Process {
            
            [intptr] $pToken = 0
            $SecurityAttibutes = New-object pinvoke.SECURITY_ATTRIBUTES
            $SecurityAttibutes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttibutes)
            $status = [Pinvoke.advapi32]::DuplicateTokenEx($Token,
                 [System.Security.Principal.TokenAccessLevels]::MaximumAllowed, 
                 [ref] $SecurityAttibutes, 
                 [pinvoke.SECURITY_IMPERSONATION_LEVEL]::SecurityIdentification, 
                 [pinvoke.TOKEN_TYPE]::TokenPrimary, 
                 [ref] $pToken)
            Write-Verbose -Message "Making Primary token - $status"

            $Filename = $Binary.FullName
            if ($Null -eq $Binary) {$Filename = $null}

            $NewProcessPid = [Pinvoke.advapi32]::LaunchProcessAsToken(
                $Binary.FullName,
                $Parameters,
                $ShowUI.IsPresent,
                $logonFlag,
                $CreationFlags,
                $StartInfoFlags,
                $Desktop,
                $pToken,
                [intptr]::Zero
            )
                
            if ($NewProcessPid -eq 0){
               # $Lasterr = ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
                Write-Error -Message "Failed to start process $lasterr"
            }
        }
        End {
            $NewProcessPid
        }
    }