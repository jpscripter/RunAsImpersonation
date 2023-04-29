$ModuleInfo = Import-PowerShellDataFile -Path "$PSScriptRoot\RunAsImpersonation.psd1"

if (Test-Path -Path $PSScriptRoot\Classes\){
    $Class = Get-ChildItem -Path $PSScriptRoot\Classes\*.cs -file -Recurse
    $references = @()
    Foreach($CLS in $Class){
	    Write-Verbose -Message "Class File: $CLS"  
	    $Content = Get-Content -raw -path $CLS
        $LocalFilePath = "$PSScriptRoot\Classes\Pinvoke.$($cls.BaseName)-$($ModuleInfo.ModuleVersion).dll"
        $FilePath = "$env:Tmp\Pinvoke.$($cls.BaseName)-$($ModuleInfo.ModuleVersion).dll"
        Remove-Item -path $FilePath -ErrorAction Ignore
        if (Test-Path -Path $LocalFilePath){
            Add-Type -Path $LocalFilePath
        }elseif(Test-Path -Path $FilePath)
        {
            Add-Type -Path $FilePath
        }else{
            Write-Verbose -Message "Compliling Class File: $CLS -with Unsafe"  
            if ($PSVersionTable.PSVersion.Major -lt 6){
                $cp = New-Object System.CodeDom.Compiler.CompilerParameters
                $cp.CompilerOptions = '/unsafe' 
                $references.ForEach({$cp.ReferencedAssemblies.Add($PSItem)})
                $cp.OutputAssembly = $FilePath 
                $Options = @{CompilerParameters =  $cp}
            }else{
                $Options = @{
                    CompilerOptions =  '/unsafe'
                    OutputAssembly = $FilePath 
                    ReferencedAssemblies = $references
                 }
            }
            $null = Add-Type -TypeDefinition $Content @Options -Passthru
        }
        $references += $FilePath
    }
}

if (Test-Path -Path $PSScriptRoot\Commands\){
    $Commands = Get-ChildItem -Path $PSScriptRoot\Commands\*.ps1 -file -Recurse
    Foreach($CMD in $Commands){
	    Write-Verbose -Message "Cmdlet File: $CMD"  
	    . $CMD
    }
}

if (Test-Path -Path $PSScriptRoot\PrivateCommands\){
    $Commands = Get-ChildItem -Path $PSScriptRoot\PrivateCommands\*.ps1 -file -Recurse
    Foreach($CMD in $Commands){
	    Write-Verbose -Message "Cmdlet File: $CMD"  
	    . $CMD
    }
}