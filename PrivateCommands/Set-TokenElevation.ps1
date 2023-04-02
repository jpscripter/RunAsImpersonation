Function Set-TokenElevation { 
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
    $elevation = Get-Token
    $elevation.TokenIsElevated = $true
    $size = [System.Runtime.InteropServices.Marshal]::SizeOf($elevation)
    $pointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($elevation,$pointer,$true)
    $success = [Pinvoke.advapi32]::SetTokenInformation($PtrToken,[Pinvoke.TOKEN_INFORMATION_CLASS]::TokenElevation,$pointer,$size)
    ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
}