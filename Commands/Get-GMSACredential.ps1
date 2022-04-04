Function Get-GMSACredential{
    <#
    .SYNOPSIS
    Returns the GMSA PSCredential based on the identity name of the account
    
    .DESCRIPTION
    Retrieves the password of the GMSA from AD and uses that to create a PSCredential

    .PARAMETER Identity
    Identity of the GMSA account
    
    .PARAMETER Domain
    Domain logon name of the account

    .EXAMPLE
    Get-GMSACredential -GMSAName 'gmsaUser' 
    
    .NOTES
    .Author: Ryan Ephgrave
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry

    $searcher = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $DirectoryEntry
    
    $searcher.Filter = "(&(name=$($Identity))(ObjectCategory=msDS-GroupManagedServiceAccount))"
    $Null = $searcher.PropertiesToLoad.Add('Name')
    $Null = $searcher.PropertiesToLoad.Add('msDS-ManagedPassword')
    $Null = $searcher.PropertiesToLoad.Add('msDS-ManagedPassword')
   
    $searcher.SearchRoot.AuthenticationType = 'Sealing'
    
    $Accounts = $searcher.FindAll()
    foreach($a in $accounts){
        if($a.Properties.'msds-managedpassword'){
            $pw = $a.Properties.'msds-managedpassword'
            [Byte[]]$byteBlob = $pw.Foreach({$PSItem})
            $MemoryStream = New-Object System.IO.MemoryStream -ArgumentList (,$byteBlob)
            $Reader = New-Object System.IO.BinaryReader -ArgumentList $MemoryStream
            
            # have to move the reader to the pw offset
            $null = $Reader.ReadInt16()
            $null = $Reader.ReadInt16()
            $null = $Reader.ReadInt32()

            $PWOffset = $Reader.ReadInt16()
            $Length = $byteBlob.Length - $PWOffset
            $stringBuilder = New-Object System.Text.StringBuilder -ArgumentList $Length
            for($i = $PWOffset; $i -le $byteBlob.Length; $i += [System.Text.UnicodeEncoding]::CharSize){
                $currentChar = [System.BitConverter]::ToChar($byteBlob, $i)
                if($currentChar -eq [char]::MinValue) { break; }
                [void]$stringBuilder.Append($currentChar)
            }
            return ( New-Object PSCredential -ArgumentList @(
                                    "$($Domain)\$($GMSAName)",
                                    (ConvertTo-SecureString $stringBuilder.ToString() -AsPlainText -Force)
                                    ))
        }
    }
}

