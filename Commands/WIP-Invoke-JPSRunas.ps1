Function Invoke-JPSRunas { 
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
            [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Credential")]
            [PSCredential]$Credential, 
            [Parameter( ParameterSetName = "Credential")]
            [Switch]$NetOnly,
            [Parameter(ParameterSetName = "Token")]
            [intptr]$Token = 0,
            [System.IO.FileInfo]$Binary = $env:ComSpec,
            [string]$Parameters,
            [switch] $ShowUI

        )
        Begin{
            $LogonType = [Pinvoke.dwLogonType]::Interactive
            if ($NetOnly.IsPresent){[Pinvoke.dwLogonType]::NewCredentials}
            if ($null -NE $Credential){
                $token = Get-JPSRunasCredentialToken -Credential $Credential -LogonType $LogonType
            }
        }
        Process {
            
            $ProcessAttributes = New-Object Pinvoke.SECURITY_ATTRIBUTES
            $ProcessAttributes.nLength = [System.Runtime.InteropServices.Marshal]::sizeOf($ProcessAttributes)
            $ThreadAttributes = New-Object Pinvoke.SECURITY_ATTRIBUTES
            $ThreadAttributes.nLength =  [System.Runtime.InteropServices.Marshal]::sizeOf($ProcessAttributes)

            #Start Info
            $StartInfo = New-Object Pinvoke.StartupInfo
            $StartInfo.flags = 0x00000001
            $StartInfo.showWindow = 0x0000
            if ($ShowUI.IsPresent){$StartInfo.showWindow = 0x0001}
            $StartInfo.cb = [System.Runtime.InteropServices.Marshal]::sizeOf($StartInfo)

            $ProcessInfo = New-Object Pinvoke.ProcessInformation

            [intptr] $pToken = 0
            $SecurityAttibutes = New-object pinvoke.SECURITY_ATTRIBUTES
            $SecurityAttibutes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttibutes)
            $status = [Pinvoke.advapi32]::DuplicateTokenEx($mToken,
                 [System.Security.Principal.TokenAccessLevels]::MaximumAllowed, 
                 [ref] $SecurityAttibutes, 
                 [pinvoke.SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, 
                 [pinvoke.TOKEN_TYPE]::TokenPrimary, 
                 [ref] $pToken)

            [intptr]$envptr = 0
            $s = [Pinvoke.userenv]::CreateEnvironmentBlock([ref]$envptr, $pToken, $false)

            7
            [System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()
        }
        End {
    
        }
    }