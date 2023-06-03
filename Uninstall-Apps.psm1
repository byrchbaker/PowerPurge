Function Uninstall-Application {
    [CmdletBinding()]
    Param(
        [Alias('Name', 'DisplayName')]
        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$AppName,
        [Parameter(Mandatory=$False)]
        [switch]$Silent,
        [Parameter(Mandatory=$False)]
        [string]$LogLocation
        
    )

    Begin {
       <# Write-Verbose "[BEGIN] Checking if Log directory exists: $LogLocation"

        switch ($LogLocation) {
            $true {
                Write-Verbose "[VERIFY] Log directory exists: $LogLocation"
                break
            }

            $false {
                Write-Verbose "[VERIFY] Log directory does not exist: $LogLocation"
                Write-Verbose "[VERIFY] Creating log directory!"

                New-Item -Path $LogLocation -ItemType Directory -Force -Verbose

            }

        }#>

        Write-Verbose "[BEGIN] Running program"
        Write-Verbose "[INFO] Log Date: $(Get-Date)"


        Function Start-MSIUninstall {

            Param (
                $AppName,
                $LogLocation
            )

            $FoundApps = Get-WmiObject -Class Win32_Product -Verbose | 
            Where-Object {$_.Name -like "*$AppName*"}

            if ($FoundApps) {

                if ($FoundApps.count -gt "1") {
                    Write-Warning "[INFO] More than one Apps were found in WMI objects. Please try more specific app name."
                    Write-Verbose "[INFO] Current defined App name: $AppName"
                    Return $FoundApps
                }

                else {

                    foreach ($FoundApp in $FoundApps) {

                        $FoundApp.Uninstall() | Out-Null
                        
                        Write-Host -ForegroundColor Green ("STATUS: " + $FoundApp.Name + " was uninstalled successfully!")
                        
                    }
               }
            }
            else {
                Write-Warning "[INFO] $AppName is not found in WMI objects. Please try a different app name!"
                return $null
            }


        }

        # Function to find appname in registry uninstall paths and uninstall it if found

        Function Start-RegistryUninstall {

            Param (
                $AppName,
                $LogLocation
            )
            
            

            Write-Verbose "[INFO] Trying to find '$AppName' in registry."
            

            $FoundApps = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | 
            Get-ItemProperty | 
            Where-Object {$_.DisplayName -like "*$AppName*"}

            if ($FoundApps) {
    
                
                if ($FoundApps.count -gt "1") {
                    Write-Warning "[INFO] More than one Apps were found in registry. Please try more specific app name."
                    Write-Verbose "[INFO] Current defined App name: $AppName"
                    Return $FoundApps
                }

                else {

                    foreach ($FoundApp in $FoundApps) {
                        Write-Host -ForegroundColor Green "STATUS: $($FoundApp.DisplayName) was found in registry!"
                        Write-Host -ForegroundColor Green ("STATUS: Starting uninstall of " + $($FoundApp.DisplayName))
                        
                        Write-Verbose "[INFO] Checking to see if there are any MSI entries."
                        
                        if ($($FoundApp.UninstallString) -match '\/X{([^}]+)}' -or $($FoundApp.UninstallString) -match '\/I{([^}]+)}') { 
                            Write-Host -ForegroundColor Green "STATUS: MSI entry found!"
                        
                            Start-MSIUninstall -AppName $AppName -Verbose
                        } else { 
                            Write-Verbose "[INFO] There are no MSI entries. Uninstalling through uninstall string!"

                            switch ($Silent) {
                            $true {

                                Write-Verbose "[VERIFY] Checking if $($FoundApp.DisplayName) has a silent uninstall string"

                                if ($FoundApp.QuietUninstallString) {
                                    Write-Host -ForegroundColor Green "STATUS: Uninstalling $($FoundApp.DisplayName) in silent mode."
                                    $UninstallString = $Foundapp.QuietUninstallString -replace '"',''
                                    $UninstallString = $UninstallString -replace '_\?=.*$'
                                 
                                    $pattern = '^(.+?\.exe)\s*(.*)$'
                                    $matches = [regex]::Match($uninstallstring, $pattern)
                                    if ($matches.Success) {
                                        $executable = $matches.Groups[1].Value
                                        $arguments = $matches.Groups[2].Value
                                        Start-Process -FilePath "$executable" -ArgumentList "$arguments"
                                    } else {
                                        Write-Error "Invalid uninstall string format."
                                    }

                                    
                                    Write-Host -ForegroundColor Green "STATUS: $($FoundApp.DisplayName) uninstalled successfully!"

                                    break
                                }

                                else {
                                    Write-Verbose "[INFO] $($FoundApp.DisplayName) does not have a silent uninstall string"
                                    Write-Verbose "[INFO] Trying to force silent mode on $($FoundApp.DisplayName)"
                                    $UninstallString = $FoundApp.UninstallString -replace '"',''
                                    
                                    $UninstallString = $UninstallString -replace '_\?=.*$'

                                        $pattern = '^(.+?\.exe)\s*(.*)$'
                                        $matches = [regex]::Match($uninstallstring, $pattern)
                                        if ($matches.Success) {
                                            $executable = $matches.Groups[1].Value
                                            $arguments = $matches.Groups[2].Value
                                            if ($arguments) {
                                                if ([string]$arguments -notmatch '--\w+') {
                                                    Start-Process -FilePath "$executable" -ArgumentList "$arguments /SILENT /quiet /S"
                                                } else {
                                                    $pattern = '^(.+?\.exe)\s*(.*)$'
                                                    $matches = [regex]::Match($uninstallstring, $pattern)
                                                    if ($matches.Success) {
                                                        $executable = $matches.Groups[1].Value
                                                        $arguments = $matches.Groups[2].Value
                                                        Start-Process -FilePath "$executable" -ArgumentList "$arguments --verbose-logging --force-uninstall"
                                                    } else {
                                                        Write-Error "Invalid uninstall string format."
                                                    }
                                                }
                                           } else {
                                            Start-Process -FilePath $UninstallString -ArgumentList "/SILENT /quiet /S"
                                            }                                        
                                        } else {
                                            Write-Error "Invalid uninstall string format."
                                        }
                                        
                                   
                                    Write-Host -ForegroundColor Green "STATUS: $($FoundApp.DisplayName) uninstalled successfully!"

                                    break
                                }
                            }

                            $false {
                                Write-Verbose "[INFO] Uninstalling $($FoundApp.DisplayName) in normal mode"
                                $UninstallString = $FoundApp.UninstallString -replace '"',''
                                $UninstallString = $UninstallString -replace '_\?=.*$'

                                $pattern = '^(.+?\.exe)\s*(.*)$'
                                $matches = [regex]::Match($uninstallstring, $pattern)
                                if ($matches.Success) {
                                    $executable = $matches.Groups[1].Value
                                    $arguments = $matches.Groups[2].Value
                                    if ($arguments) {
                                         Start-Process -FilePath "$executable" -ArgumentList "$arguments"
                                    } else {
                                         Start-Process -FilePath $UninstallString
                                    }
                                   
                                } else {
                                    Write-Error "Invalid uninstall string format."
                                }

                               
                                break
                            }
                        }
                        }


                        


                    }
               }
            }
            else {
                Write-Warning "[INFO] $AppName is not found in registry. Please try a different app name!"
                return $null
            }
        }
    }

    Process {
        #Start-MSIUninstall -AppName $AppName -Verbose
        Start-RegistryUninstall -AppName $AppName -Verbose 
    }

    End {
        
    }
}
