Function Get-JPSRunAsConsoleUserToken { 
<#
.SYNOPSIS
Opens the console session and copies the user token

.DESCRIPTION
retrieves and impersionation token based on the logon credentials for the console session

.PARAMETER Session
override for other sessions

.EXAMPLE
PS> 
[System.Security.Principal.WindowsIdentity]::GetCurrent().name
$t = Get-JPSRunAsConsoleUserToken
Set-JPSRunAsImpersonation -Token $t
[System.Security.Principal.WindowsIdentity]::GetCurrent().name
Set-JPSRunAsImpersonation

.LINK
http://www.JPScripter.com/extension.html

#>
param(
    [uint]$Session
)
    Begin{
        #Check for admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
          Throw "Run the Command as an Administrator"
        }
    }
    Process {
        #get session
        if ($Session -eq 0){
            $ConsoleSession = [Pinvoke.kernel32]::WTSGetActiveConsoleSessionId()
        }else{
            $ConsoleSession = $Session
        }
        if ($null -eq $ConsoleSession){
            throw "No Logged on Console"
        }

        # get console token
        [intptr]$Token = 0
        $Status = [Pinvoke.wtsapi32]::WTSQueryUserToken(1,[ref]$Token)
        if (-not $status){
            Write-Verbose -Message "Trying as system"
            $SystemToken = Get-JPSRunAsMachineToken
            Set-JPSRunAsImpersonation -Token $SystemToken
            $Status = [Pinvoke.wtsapi32]::WTSQueryUserToken(1,[ref]$Token)
            Set-JPSRunAsImpersonation
        }
        if (-not $status){
            throw "Could not open up Console Token"
        }

        #impersonate the token
        [intptr] $ImpersonationToken = 0
        $SecurityAttibutes = New-object pinvoke.SECURITY_ATTRIBUTES
        $SecurityAttibutes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttibutes)
        $status = [Pinvoke.advapi32]::DuplicateTokenEx($Token, [System.Security.Principal.TokenAccessLevels]::MaximumAllowed, [ref] $SecurityAttibutes, [pinvoke.SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, [pinvoke.TOKEN_TYPE]::TokenImpersonation, [ref] $ImpersonationToken)

        #return
        if ($status){
            Write-Verbose -Message "Found Token for system"
            $ImpersonationToken 
        }else{
            Throw "Failed to duplicate token"
        }
    }
    End {

    }
}