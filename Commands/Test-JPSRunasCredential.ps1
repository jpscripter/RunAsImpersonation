Function Test-JPSRunasCredential { 
<#
.SYNOPSIS
Check to see if the credential is valid

.DESCRIPTION
with check the domain to see if the user name and password is valid.

.PARAMETER Credential
Credential that needs to validate

.EXAMPLE
ps> Test-JPSRunasCredential -credential $Cred
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
        $username = $Credential.username
        $password = $Credential.GetNetworkCredential().password
        $Domain = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain')
        $Domain.ValidateCredentials($username, $password)
    }
    End {

    }
}