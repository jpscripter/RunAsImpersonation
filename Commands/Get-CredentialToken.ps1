Function Get-CredentialToken { 
<#
.SYNOPSIS
Uses a PSCredential object to build a token 

.DESCRIPTION
Uses the PSCredential and win32 apis to log the user in and create a local or network only token

.PARAMETER Credential
Credential to log in with

.PARAMETER LogonType
How this credential will log in (Default is NetOnly but Interactive is also common)

.EXAMPLE
PS> 


.LINK
http://www.JPScripter.com

#>
    param(  
        [PSCredential]$Credential ,
        [Pinvoke.dwLogonType] $LogonType = [Pinvoke.dwLogonType]::NewCredentials
    )
    Begin{

    }
    Process {
        $Username = $Credential.GetNetworkCredential().username
        $Password = $Credential.GetNetworkCredential().Password
        $Domain   = $Credential.GetNetworkCredential().Domain
        $LogonProvider = 0

        [System.IntPtr]$token = 0
        $status = [Pinvoke.advapi32]::LogonUserEx($Username,$domain, $Password, $LogonType, $LogonProvider, [ref]$token, 0, 0,0,0)

        if (-not $status){
            $ErrorMessage = [System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error $ErrorMessage
            throw "Failed logon with $Username for $LogonType"
        }
        Get-TokenInfo -Token $token
    }
    End {

    }
}