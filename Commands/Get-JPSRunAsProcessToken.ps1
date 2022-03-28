Function Get-JPSRunasProcessToken { 
<#
.SYNOPSIS
Gets a credential token from a process

.DESCRIPTION
Creates an impersonation token based on a target process

.PARAMETER ProcessID
The process id of the process you want to copy the token from. 

.EXAMPLE

PS>    

.LINK
http://www.JPScripter.com

#>
    param(  
        [int]$ProcessID
    )
    Begin{
         #Check for admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
          Throw "Run the Command as an Administrator"
        }

    }
    Process {

        [IntPtr]$Token = 0
        $Process = Get-Process -ID $ProcessID
        $retVal = [Pinvoke.advapi32]::OpenProcessToken($Process.Handle, [Pinvoke.TokenRights]::TOKEN_ALL_ACCESS, [ref]$Token)
  
        if(-not($retVal)) {
            [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
            Throw "Cannot open process - $ProcessID"
        }
			
    }
    End {
        $Token
    }
}