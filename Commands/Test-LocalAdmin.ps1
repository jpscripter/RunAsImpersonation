Function Test-LocalAdmin { 
    <#
    .SYNOPSIS
    Tests a token for Local Admin privilages
    
    .DESCRIPTION
    Takes
    
    .PARAMETER Session
    override for other sessions
    
    .EXAMPLE
    PS> 
    
    
    .LINK
    http://www.JPScripter.com
    
    #>
    param(
        [Object]$Token
    )

        #Convert Token
        if ($Null -eq $token){
            $Identity = Get-TokenInfo
        }Else{
            Switch ($Token.GetType().Name) 
            {
                'IntPtr'{ 
                    $Identity = Get-TokenInfo $Token
                    Break
                }
                'WindowsIdentity'{
                    $Identity = $Token
                    Break
                }
                Default {
                    Throw 'Token must be a WidnowsIdentity or intPtr Object'
                }
            }
        }

        #Check for admin
        $Return = $True
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( $Identity  )
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
            $Return = $False
        }
        $Return

    }