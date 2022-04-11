Function Invoke-ScriptBlock { 
    <#
    .SYNOPSIS
    Uses a PSCredential object to build a token 
    
    .DESCRIPTION
    Uses the PSCredential and win32 apis to log the user in and create a local or network only token
    
    .PARAMETER Credential
    Credential to execute the scriptblock as
    
    .PARAMETER Token
    what token should be used to run the script block
    
    .PARAMETER Parameters
    a hash table of the parameters you want to pass into your scriptblock
    
    .PARAMETER ScriptBlock
    What code block should be run
    
    .EXAMPLE
    PS> Invoke-ScriptBlock -Credential $credential -ScriptBlock {param($text) Write-output "$text-$([System.Security.Principal.WindowsIdentity]::GetCurrent().name)"} -Parameters @{text='param'}
    
    param-LAPTOP\Administrator
    
    
    .LINK
    http://www.JPScripter.com
    
    #>
        param(  
            [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Credential")]
            [PSCredential]$Credential, 
            [Parameter( ParameterSetName = "Credential")]
            [Switch]$NetOnly,
            [Parameter(ParameterSetName = "Token")]
            [Security.Principal.WindowsIdentity]$Token = [Security.Principal.WindowsIdentity]::GetCurrent(),
            [scriptblock]$ScriptBlock,
            [hashtable]$Parameters
        )
        Begin{
            $LogonType = [Pinvoke.dwLogonType]::Interactive
            if ($NetOnly.IsPresent){[Pinvoke.dwLogonType]::NewCredentials}
            if ($null -NE $Credential){
                $token = Get-CredentialToken -Credential $Credential -LogonType $LogonType
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
            $ImpersonationToken = Get-DuplicateToken -Token $token -returnPointer
            [System.Security.Principal.WindowsIdentity]::RunImpersonated($ImpersonationToken,$func)
        }
        End {
    
        }
    }