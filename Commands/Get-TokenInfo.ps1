Function Get-TokenInfo { 
<#
.SYNOPSIS
returns information on a token or the current thread's token

.DESCRIPTION
returns basic token information

.PARAMETER Token
Credential to log in with

.EXAMPLE
PS> 


.LINK
http://www.JPScripter.com

#>
    param(  
        [intptr] $token 
    )
    Begin{

    }
    Process {
        if ($Null -eq $token ){
            [System.Security.Principal.WindowsIdentity]::GetCurrent()
        }Else{
            [System.Security.Principal.WindowsIdentity]::new($Token)
        }
    }
    End {

    }
}