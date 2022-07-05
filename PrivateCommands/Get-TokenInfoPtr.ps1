Function Get-TokenInfoPtr { 
<#
.SYNOPSIS
Returns token information pointer using win32API

.DESCRIPTION
Returns selected information from a token api.

.PARAMETER Token
Pointer or Windows Identity to Duplicate

.PARAMETER TokenInformationClass
Token Permissions for Querying, adjusting, creating or impersonating other tokens
https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.tokenaccesslevels?view=net-6.0

.EXAMPLE
PS> 
    Import-Module .\RunAsImpersonation\
    $token = [System.Security.Principal.WindowsIdentity]::GetCurrent().Token
    [Pinvoke.TOKEN_INFORMATION_CLASS] $TokenInformationClass = [Pinvoke.TOKEN_INFORMATION_CLASS]::TokenGroups

    Get-TokenInfoPtr -Token $token -TokenInformationClass $TokenInformationClass

.LINK
http://www.JPScripter.com/extension.html

.NOTES
https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics

#>
param(
    [object]$Token,
    [Pinvoke.TOKEN_INFORMATION_CLASS] $TokenInformationClass = [Pinvoke.TOKEN_INFORMATION_CLASS]::TokenGroups

)
        #Convert Token
        if ($Null -eq $token){
            $PtrToken = (Get-TokenInfo).Token
        }Else{
            $PtrToken = Get-DuplicateToken -Token $token -returnPointer
        }
        #Get buffer length first
        [uint16]$TokenInfoLength = 0
        #always fails the first time but the length gets updated.
        $null = [Pinvoke.advapi32]::GetTokenInformation($PtrToken,$TokenInformationClass,[System.IntPtr]::Zero, $TokenInfoLength, [ref] $TokenInfoLength)
        if ($TokenInfoLength -ne 0){
            $InfoPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenInfoLength)
        }else{
            $Lasterr = ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
            Write-Error -Message "Failed Get token information size $lasterr"
        }
        $Success = [Pinvoke.advapi32]::GetTokenInformation($PtrToken, $TokenInformationClass, $InfoPointer, $TokenInfoLength, [ref] $TokenInfoLength)
        if (-not $Success){
            $Lasterr = ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
            Write-Error -Message "Failed to retrieve information pointer $lasterr"
        }
        $InfoPointer
}