Function Get-JPSRunAsTokenInfo { 
<#
.SYNOPSIS
returns information on a token 

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
        [System.Security.Principal.WindowsIdentity]::new($Token)
    }
    End {

    }
}