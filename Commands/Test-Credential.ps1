Function Test-Credential { 
<#
.SYNOPSIS
Check to see if the credential is valid

.DESCRIPTION
with check the domain to see if the user name and password is valid.

.PARAMETER Credential
Credential that needs to validate

.EXAMPLE
ps> Test-Credential -credential $Cred
True

.LINK
http://www.JPScripter.com

#>
    param(  
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Credential")]
        [PSCredential]$Credential
    )
    Begin{
        $Null = Add-type -AssemblyName System.DirectoryServices.AccountManagement
    }
    Process {
        $Context = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $PrincipleContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($Context,$Credential.GetNetworkCredential().Domain)
        $PrincipleContext.ValidateCredentials( $Credential.GetNetworkCredential().username, $Credential.GetNetworkCredential().password,'Negotiate')
        $null = $PrincipleContext.Dispose()
    }
    End {

    }
}