Function Get-ConsoleUserToken { 
<#
.SYNOPSIS
Opens the console session and copies the user token

.DESCRIPTION
retrieves and impersionation token based on the logon credentials for the console session

.PARAMETER Session
override for other sessions

.EXAMPLE
PS>  Get-ConsoleUserToken 

.LINK
http://www.JPScripter.com/extension.html

#>
param(
    [int]$Session
)
    Begin{
        #Check for admin
        if(-not (Test-LocalAdmin)) {
          Throw "Run the Command as an Administrator"
        }
    }
    Process {
        #get session
        if ($Session -eq 0){
            $Session = [Pinvoke.kernel32]::WTSGetActiveConsoleSessionId()
        }
        if ($null -eq $Session){
            throw "Session Not Found"
        }

        # get console token
        #must be running within the context of the LocalSystem account and have the SeTcbPrivilege privilege
        $SystemToken = Get-MachineToken
        Set-Impersonation -Token $SystemToken
        [intptr]$Token = 0
        $Status = [Pinvoke.wtsapi32]::WTSQueryUserToken($Session,[ref]$Token)
        Set-Impersonation
        
        if (-not $status){
            throw "Could not open up Console Token"
        }

        #impersonate the token
        Get-DuplicateToken -Token $Token 

    }
    End {

    }
}