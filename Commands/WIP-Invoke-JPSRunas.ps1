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
            
            [intptr] $pToken = 0
            $SecurityAttibutes = New-object pinvoke.SECURITY_ATTRIBUTES
            $SecurityAttibutes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttibutes)
            $status = [Pinvoke.advapi32]::DuplicateTokenEx($Token,
                 [System.Security.Principal.TokenAccessLevels]::MaximumAllowed, 
                 [ref] $SecurityAttibutes, 
                 [pinvoke.SECURITY_IMPERSONATION_LEVEL]::SecurityIdentification, 
                 [pinvoke.TOKEN_TYPE]::TokenPrimary, 
                 [ref] $pToken)

            [Pinvoke.advapi32]::LaunchProcessAsToken(
                $Binary,
                $Parameters,
                $ShowUI.IsPresent,
                $pToken,
                [intptr]::Zero
            )
                        
            [System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()
        }
        End {
    
        }
    }