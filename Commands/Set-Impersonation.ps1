Function Set-Impersonation { 
<#
.SYNOPSIS
Uses a PSCredential or token and sets the impersonation for the current thread

.DESCRIPTION
Uses the PSCcredential or provided token to set the current threads impersonation

.PARAMETER Token
Duplicate Token that needs to be impersonated 

.PARAMETER Credential
Credential that needs to be impersonated 

.PARAMETER NetOnly
Should this PSCredential token be made for net only or local system

.EXAMPLE
ps> [System.Security.Principal.WindowsIdentity]::GetCurrent().name
Set-Impersonation -Credential $Credential
[System.Security.Principal.WindowsIdentity]::GetCurrent().name
Set-Impersonation -token 0


.LINK
http://www.JPScripter.com

#>
    param(  
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Credential")]
        [PSCredential]$Credential, 
        [Parameter( ParameterSetName = "Credential")]
        [Switch]$NetOnly,
        [Parameter(ParameterSetName = "Token")]
        [Security.Principle.WindowsIdentity]$Token
    )
    Begin{

    }
    Process {
        $LogonType = [Pinvoke.dwLogonType]::Interactive
        if ($NetOnly.IsPresent){[Pinvoke.dwLogonType]::NewCredentials}
        if ($null -NE $Credential){
            $token = Get-CredentialToken -Credential $Credential -LogonType $LogonType
        }
        
        if ($Null -eq $Token){
            $status = [pinvoke.advapi32]::RevertToSelf()
        }else{
            $status = [pinvoke.advapi32]::ImpersonateLoggedOnUser($Token.token)
        }
        Write-Verbose -message ("Running as {0}" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().name   )
    }
    End {

    }
}