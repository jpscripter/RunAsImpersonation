Function Get-TokenGroups { 
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
    [object]$InfoPointer
)
        $GroupStruc = [System.Runtime.InteropServices.Marshal]::PtrToStructure($InfoPointer,[type][Pinvoke.TOKEN_GROUPS])
        $SidSize = [System.Runtime.InteropServices.Marshal]::sizeof([type][Pinvoke.SID_AND_ATTRIBUTES])
        for ($I = 0; $i -lt $GroupStruc.GroupCount; $I++){
            [System.IntPtr] $NewSidPtr = [IntPtr]::new( $InfoPointer.ToInt64() + $i * $SidSize + [IntPtr]::Size)
            [Pinvoke.SID_AND_ATTRIBUTES] $sidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NewSidPtr, [type][Pinvoke.SID_AND_ATTRIBUTES])
            [IntPtr] $Sid = [IntPtr]::Zero
            $Success = [Pinvoke.advapi32]::ConvertSidToStringSid($sidAndAttributes.Sid,[ref]$Sid)
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Sid)
            $Null = [Pinvoke.kernel32]::LocalFree($Sid)
        }
}