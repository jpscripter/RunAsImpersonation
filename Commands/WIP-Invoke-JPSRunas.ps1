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
    
    .PARAMETER AsConsoleUser
    Should we run this as the currently logged on user

    .PARAMETER Parameters
    a hash table of the parameters you want to pass into your scriptblock
    
    .PARAMETER CMD
    What exe block should be run
    
    .PARAMETER ShowUI
    What exe block should be run

    .EXAMPLE
    PS> 
    
    
    .LINK
    http://www.JPScripter.com
    
    #>
        param(  
            [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Credential")]
            [PSCredential]$Credential, 
            [Parameter( ParameterSetName = "Credential")]
            [Switch]$NetOnly,
            [Parameter(ParameterSetName = "Token")]
            [intptr]$Token = 0,
            [scriptblock]$ScriptBlock,
            [hashtable]$Parameters
        )
        Begin{
            $LogonType = [Pinvoke.dwLogonType]::Interactive
            if ($NetOnly.IsPresent){[Pinvoke.dwLogonType]::NewCredentials}
            if ($null -NE $Credential){
                $token = Get-JPSRunasCredentialToken -Credential $Credential -LogonType $LogonType
            }
        }
        Process {
            $ParamHash = [Hashtable]::Synchronized(@{
                args = $Parameters
            })
            [Func[object]] $Func = {
                [hashtable] $ScriptArgs= $ParamHash['args']
                . $scriptblock @ScriptArgs
            }
            [System.Security.Principal.WindowsIdentity]::RunImpersonated($token,$func)
        }
        End {
    
        }
    }