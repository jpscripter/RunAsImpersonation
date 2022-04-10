Function Get-ProcessToken { 
<#
.SYNOPSIS
Gets a credential token from a process

.DESCRIPTION
Creates an impersonation token based on a target process

.PARAMETER ProcessID
The process id of the process you want to copy the token from. 

.EXAMPLE
Get-Process -ID $ProcessID

PS>    

.LINK
http://www.JPScripter.com

#>
    param(  
        [int]$ID,
        [security.principal.tokenaccesslevels]$TokenRights =  [security.principal.tokenaccesslevels]::MaximumAllowed
    )

    $Process = (Get-Process -id $ID -IncludeUserName)
    if ($Null -eq $Process){
        Throw "Cannot open process - $ProcessID"
    }

    [IntPtr]$Token = 0
    $retVal = [Pinvoke.advapi32]::OpenProcessToken($Process.Handle, $TokenRights, [ref]$Token)
    if(-not($retVal)) {
        [System.ComponentModel.Win32Exception][System.Runtime.InteropServices.marshal]::GetLastWin32Error()
        Throw "Cannot open token - $ProcessID"
    }
    Get-DuplicateToken -Token $token -TokenAccess $TokenRights -ImpersionationLevel SecurityImpersonation -TokenType TokenImpersonation -returnPointer
}