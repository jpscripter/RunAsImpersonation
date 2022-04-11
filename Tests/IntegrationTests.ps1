Import-Module C:\RunasImpersonation -force

$AdminUserName = "$env:Computername\Administrator"
$LocalAdminCred = Get-Credential -UserName $AdminUserName -Message 'Local Admin'


Describe 'Integration Tests for RunasImpersonation'{

    $ProcID = Invoke-CommandWithCredential -Credential $LocalAdminCred -Parameters "/c Whoami >> c:\whoami.txt"
    Start-Sleep -Seconds 1
    $WhoamiContent = Get-Content c:\whoami.txt -Raw
    it 'should launch as Admin'{
        $WhoamiContent.trim() | SHould be $LocalAdminCred.UserName
    }
    it 'Should have processID'{
        $ProcID| should not be 0
    }
    Remove-Item -Path  c:\whoami.txt -Force -ErrorAction SilentlyContinue


    $LAToken = Get-CredentialToken -Credential $LocalAdminCred -LogonType Interactive
    it 'Should get Local Admin Token'{
        $LAToken.name| should be $LocalAdminCred.UserName
    }
         
    $User = Invoke-ScriptBlock -Credential $LocalAdminCred -ScriptBlock { [System.Security.Principal.WindowsIdentity]::GetCurrent().name } 
    it 'Should Run Scriptblock as another user'{
        $User | should be $LocalAdminCred.UserName
    }

    $ProcID = Invoke-CommandWithToken -Token $LAToken -Parameters "/c Whoami >> c:\whoami.txt"
    Start-Sleep -Seconds 1
    $WhoamiContent = Get-Content c:\whoami.txt -Raw
    it 'should launch as Admin'{
        $WhoamiContent.trim() | SHould be $LocalAdminCred.UserName
    }
    it 'Should have processID'{
        $ProcID| should not be 0
    }
    Remove-Item -Path  c:\whoami.txt -Force -ErrorAction SilentlyContinue

    Set-Impersonation -Token $LAToken
    it 'Should Set Impersonation'{
        [System.Security.Principal.WindowsIdentity]::GetCurrent().name | should be $LocalAdminCred.UserName
    }
    Set-Impersonation 

    it 'Impersonation should revert'{
        (Get-TokenInfo).name| should match "$env:Username"
    }

    $PrimaryToken = Get-DuplicateToken -Token $LAToken -TokenType TokenPrimary
    it 'Should get primary duplicate Token'{
        $PrimaryToken.ImpersonationLevel| should be 'none'
    }
    
    if ($env:Computername -eq 'Client1'){
        $GMSA = Get-GMSACredential -Identity MyGMSA
        it 'Should Return a GMSA Cred'{
            Test-Credential -Credential $GMSA | SHould be $true
        }
    }

    if (Test-LocalAdmin){
        $MachineToken = Get-MachineToken 
        it 'Should get Machine Token'{
            $MachineToken.name| should be 'NT AUTHORITY\SYSTEM'
        }

        $MachineCredential = Get-MachineCredential 
        it 'Should get Machine Token'{
            Test-Credential $MachineCredential| should be $True
        }

        it 'Should return session token'{
            $Users = query user
            $Username = $Users[1].split(" ").where({-not [string]::IsNullOrEmpty($_)})[0]
            $Session = $Users[1].split(" ").where({-not [string]::IsNullOrEmpty($_)})[2]
            $ConsoleToken = Get-ConsoleUserToken -Session $Session
            $ConsoleToken.name| should match $Username.replace('>','')
        }

        $LSAProcess = Get-Process lsass
        $SystemLSA = Get-ProcessToken -ID $LSAProcess.id
        $LSAToken = Get-TokenInfo -token $SystemLSA 
        it 'Should get LSA Token'{
            $LSAToken.name| should be 'NT AUTHORITY\SYSTEM'
        }
    }
}