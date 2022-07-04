Function Get-TokenPointerDump { 
<#
.SYNOPSIS
Returns token information using win32API

.DESCRIPTION
Returns selected information from a token api.

.PARAMETER InfoPointer
Pointer or Windows Identity to Duplicate

.EXAMPLE
PS> 

.LINK
http://www.JPScripter.com/extension.html

#>
param(
    [System.IntPtr]$InfoPointer,
    [int] $length = 20,
    [int]$offset = 0
)


    For ($i = $offset; $I -le $Length*2+$offset ; $I+=[System.Text.UnicodeEncoding]::CharSize){
        $b1 =  [System.Runtime.InteropServices.marshal]::ReadByte($InfoPointer,$i) 
        $b2 =  [System.Runtime.InteropServices.marshal]::ReadByte($InfoPointer,$i+1) 
        $currentChar = [System.BitConverter]::ToChar(($b1,$b2),0)
        #if($currentChar -eq [char]::MinValue) { break; }
        Write-Verbose -message "$i = $currentChar - $b1 - $b2"
        $currentChar
    }

    
}