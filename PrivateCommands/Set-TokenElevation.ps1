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

.Notes

This approach is blocked by windows and you cant changed the elevation of an existing token. 

#>
param(
    [object]$Token
)
    if ($Null -eq $token){
        $PtrToken = (Get-TokenInfo).Token
    }Else{
        $PtrToken = Get-DuplicateToken -Token $token -returnPointer
    }

    $isElecated = Get-TokenElevation -Token $PtrToken
    $isElecated.TokenIsElevated = $true

    $size = [System.Runtime.InteropServices.Marshal]::SizeOf($isElecated)
    $elevationPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($isElecated,$elevationPointer,$true)

    $success = [Pinvoke.advapi32]::SetTokenInformation($PtrToken,[Pinvoke.TOKEN_INFORMATION_CLASS]::TokenElevation, $elevationPointer, $size)
    if (!$success){
        ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetLastWin32Error()).message
    }
}