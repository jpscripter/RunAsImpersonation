Function Get-MachineToken { 
<#
.SYNOPSIS
Opens process for a user and gets token

.DESCRIPTION
Retrieves a duplicate token based on the user we are searching for.

.PARAMETER username
Name of the user account you are trying to access.

.EXAMPLE
PS> 
$token = Get-Token 
[System.Security.Principal.WindowsIdentity]::GetCurrent().name
[System.Security.Principal.WindowsIdentity]::Impersonate($token)
[System.Security.Principal.WindowsIdentity]::GetCurrent().name
[System.Security.Principal.WindowsIdentity]::Impersonate(0)
[System.Security.Principal.WindowsIdentity]::GetCurrent().name

.LINK
http://www.JPScripter.com/extension.html

#>
    param(  
        $Username = 'NT AUTHORITY\SYSTEM'
    )
    Begin{
        #Check for admin
        if(-not (Test-LocalAdmin)) {
            Throw "Run the Command as an Administrator"
        }
    }
    Process {
        # get system Token
        foreach ($process in (Get-process -IncludeUserName)){
            if ($process.UserName -like '*System*'){
                Try {
                    Write-Verbose -Message "Trying for $($process.Name) - $($process.id) - $($Process.UserName)"
                    $ProcessToken = Get-ProcessToken -ID $Process.id 
                    if ($ProcessToken){Break}
                }
                Catch{
                    #$_
                }

            }
        }
        if (-not $ProcessToken){
            Throw "Could not find Process with accessable token for $username"
        }
        Set-Impersonation -Token $ProcessToken
        Get-TokenInfo -Token $ProcessToken
        Set-Impersonation
    }
    End {

    }
}