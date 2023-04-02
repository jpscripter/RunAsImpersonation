Function Get-TokenElevation { 
<#
.SYNOPSIS
Returns token information using win32API

.DESCRIPTION
Returns selected information from a token api.

.PARAMETER InfoPointer
Pointer or Windows Identity to Duplicate

.EXAMPLE
PS> 
    Import-Module .\RunAsImpersonation\
    $token = [System.Security.Principal.WindowsIdentity]::GetCurrent().Token
    [Pinvoke.TOKEN_INFORMATION_CLASS] $TokenInformationClass = [Pinvoke.TOKEN_INFORMATION_CLASS]::TokenGroups

    Get-TokenInformation -Token $token

.LINK
http://www.JPScripter.com/extension.html

#>
param(
    [object]$Token
)
    if ($Null -eq $token){
        $PtrToken = (Get-TokenInfo).Token
    }Else{
        $PtrToken = Get-DuplicateToken -Token $token -returnPointer
    }
    $InfoPointer = Get-TokenInfoPtr -Token $PtrToken -TokenInformationClass TokenElevation
    [System.Runtime.InteropServices.Marshal]::PtrToStructure($InfoPointer,[type][Pinvoke.TOKEN_ELEVATION])   
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($InfoPointer)
}