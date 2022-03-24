Function Get-JPSRunAsMachineToken { 
<#
.SYNOPSIS
Opens process for a user and gets token

.DESCRIPTION
Retrieves a duplicate token based on the user we are searching for.

.PARAMETER username
Name of the user account you are trying to access.

.EXAMPLE
PS> 
$token = Get-JPSRunAsToken 
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
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
          Throw "Run the Command as an Administrator"
        }
    }
    Process {
   
        # get system Token
        foreach ($process in (Get-process -IncludeUserName)){
            if ($process.UserName -eq $Username){
            [intptr] $ProcessToken = 0
                Try {
                    $status = [Pinvoke.advapi32]::OpenProcessToken($process.handle, [security.principal.tokenaccesslevels]::Duplicate,[ref]$ProcessToken)
                    Write-Verbose -Message "Found token in $($process.Name) - $($process.id) - $($Process.UserName)"
                    break
                }
                Catch{
                    $status = $false
                }
            }
        }
        if (-not $status){
            Throw "Could not find Process with accessable token for $username"
        }

        # duplicate token
        [intptr] $ImpersonationToken = 0
        $SecurityAttibutes = New-object pinvoke.SECURITY_ATTRIBUTES
        $SecurityAttibutes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttibutes)
        $status = [Pinvoke.advapi32]::DuplicateTokenEx($ProcessToken, [System.Security.Principal.TokenAccessLevels]::MaximumAllowed, [ref] $SecurityAttibutes, [pinvoke.SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, [pinvoke.TOKEN_TYPE]::TokenImpersonation, [ref] $ImpersonationToken)

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