Function Invoke-ContainerKitty {

    <#
    .SYNOPSIS

        Invoke-ContainerKitty - Scans Docker container images with Docker Scan Engine

         =^._.^=
        _(      )/  ContainerKitty

        Author:  Michael Schneider, scip AG
        License: MIT
        Required Dependencies: Docker Engine on Windows
        Optional Dependencies: None

    .DESCRIPTION

        This is a script to automate container scanning of container images
        with the Docker Engine. ContainerKitty can build a list of images from
        GitLab or load images from any registry

    .PARAMETER BuildList

        Switch to activate whether a list of container images is to be created.
        During the build process ContainerKitty will ask for a PrivateToken for GitLab. The token will not be stored.

    .PARAMETER BuildListOutput

        Definition of the path and name of the list of container images.      

    .PARAMETER BuildBaseUrl

        The basic URL for the GitLab repository, for example https://gitlab.example.org    

    .PARAMETER BuildId

        The id used in the GitLab repository. The type of the Id should be specified
        in the BuildIdType parameter.

    .PARAMETER BuildIdType

        Definition of the used Id type, this can be a group, user or project id. 

    .PARAMETER Scan

        Switch to run a scan of all images in a list of container images.
        If the image has not yet been imported into Docker, it will be downloaded automatically.

    .PARAMETER ScanInputFile

        Definition of the path and name of the list with container images.        

    .PARAMETER ReportDirectory

        Definition of directory for report files for the scan output.
        A separate JSON file is created for each container image.

    .PARAMETER Report

        Switch to start the report of all scan files in a directory.
        An overview is displayed in the prompt and a summary is created as a CSV.

    .PARAMETER Log

        Switch to create a log file of the output.

    .PARAMETER LogFile

        Define name and path of the log file.       

    .EXAMPLE

        Build a list of containers for user number five:
        Invoke-ContainerKitty -BuildList -BuildBaseUrl https://gitlab.example.org -BuildId 5 -BuildIdType User
        
        Scan all targes in list targets.txt and write a log:
        Invoke-ContainerKitty -Scan -ScanInputFile C:\tmp\targets.txt -ReportDirectory C:\tmp\results -Log

        Parse result files:
        Invoke-ContainerKitty -Report -ReportDirectory C:\tmp\results -Log

        Scan and parse result files:
        Invoke-ContainerKitty -Scan -ScanInputFile C:\tmp\targets.txt -ReportDirectory C:\tmp\results -Report -Log

        All in one:
        Invoke-ContainerKitty -BuildList https://gitlab.example.org -BuildId 5 -BuildIdType User -Scan -Report -ReportDirectory C:\tmp\reports\ -Log
    #>

    [CmdletBinding()]
    Param (

        # Build a list of container images
        [Switch]
        $BuildList = $false,

        # Definition of output file for a build list
        [String]
        $BuildListOutput,

        # Base URL from GitLab
        [String]
        $BuildBaseUrl,     

        # Id on GitLab
        [String]
        $BuildId,

        # Choose the type of the Id
        [ValidateSet("User","Group","Project")]
        [String]
        $BuildIdType = "Project",        

        # Scan a list of container images
        [Switch]
        $Scan = $false,

        # Definition of file with container images
        [ValidateScript({Test-Path $_})]
        [String]
        $ScanInputFile,

        # Definition of directory for report files for the scan output
        [ValidateScript({Test-Path $_})]
        [String]
        $ReportDirectory = "C:\tmp\results",
 
         # Extract information of the scan output file and report vulnerabilites
        [Switch]
        $Report = $false,

        # Definition of for the vulnerability report
        [String]
        $ContainerKittyReportFile,

        # Create a log file
        [Switch]
        $Log = $false,

        # Define name and path of the log file
        [String]
        $LogFile
    )

    Function Write-ProtocolEntry {

        <#
        .SYNOPSIS
    
            Output of an event with timestamp and different formatting
            depending on the level. If the Log parameter is set, the
            output is also stored in a file.
        #>    

        [CmdletBinding()]
        Param (
            
            [String]
            $Text,

            [String]
            $LogLevel
        )

        $Time = Get-Date -Format G

        Switch ($LogLevel) {
            "Info"    { $Message = "[*] $Time - $Text"; Write-Host $Message; Break}
            "Debug"   { $Message = "[-] $Time - $Text"; Write-Host -ForegroundColor Cyan $Message; Break}
            "Warning" { $Message = "[?] $Time - $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
            "Error"   { $Message = "[!] $Time - $Text"; Write-Host -ForegroundColor Red $Message; Break}
            "Success" { $Message = "[$] $Time - $Text"; Write-Host -ForegroundColor Green $Message; Break}
            "Notime"  { $Message = "[*] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
            Default   { $Message = "[*] $Time - $Text"; Write-Host $Message; }
        }
    
        If ($Log) {
            Add-ProtocolEntry -Text $Message
        }       
    }

    Function Add-ProtocolEntry {

        <#
        .SYNOPSIS

            Output of an event with timestamp and different formatting
            depending on the level. If the Log parameter is set, the
            output is also stored in a file.
        #>
    
        [CmdletBinding()]
        Param (
            
            [String]
            $Text
        )     

        try {
            Add-Content -Path $LogFile -Value $Text -ErrorAction Stop
        } catch {
            Write-ProtocolEntry -Text "Error while writing log entries into $LogFile. Aborting..." -LogLevel "Error"
            Break            
        }
    }

    Function Add-ResultEntry {

        <#
        .SYNOPSIS

            The result of the test is saved in a CSV file with the retrieved
            value, the severity level and the recommended value.
        #>
    
        [CmdletBinding()]
        Param (
            
            [String]
            $Text
        )

        try {
            Add-Content -Path $ContainerKittyReportFile -Value $Text -ErrorAction Stop
        } catch {
            Write-ProtocolEntry -Text "Error while writing the result into $ContainerKittyReportFile. Aborting..." -LogLevel "Error"
            Break            
        }
    }

    Function Parse-Report {

        <#
        .SYNOPSIS
    
            The JSON file from Docker is parsed using PowerShell
            and the vulnerabilities are evaluated and written to a CSV.

        #>

        #
        # The JSON file from the Docker Scan Engine cannot be parsed,
        # so the following workaround is necessary.
        #

        $ReportContentRaw = Get-Content -Path $ReportFile
        $ReportContentRaw = Get-Content -Raw -Path $ReportFile
        $TempFileName = [System.IO.Path]::GetTempFileName()

        $Parts = $ReportContentRaw -split "}`r`n{"

        If ($Parts.Count -eq 1) {
            Set-Content -Value ("["+$Parts[0]+","+$Parts[1]+"]") -Path $TempFileName
        }
        ElseIf ($Parts.Count -eq 2) {
            $SubParts = $Parts[1] -split "}`r`n\["

            If ($SubParts.Count -eq 1) {
                Set-Content -Value ("["+$Parts[0]+"},{"+$SubParts[0]+"]") -Path $TempFileName
            }
            ElseIf ($SubParts.Count -eq 2) {
                Set-Content -Value ("["+$Parts[0]+"},{"+$SubParts[0]+"},["+$SubParts[1]+"]") -Path $TempFileName
            }
            Else {
                Write-ProtocolEntry -Text "JSON differs from the expected format in file $ReportFile, please open an issue" -LogLevel "Error"
            }
        }
        ElseIf ($Parts.Count -eq 3) {
            $SubParts = $Parts[2] -split "}`r`n\["
            Set-Content -Value ("["+$Parts[0]+"},{"+$Parts[1]+"},{"+$SubParts[0]+"},["+$SubParts[1]+"]") -Path $TempFileName
        }
        Else {
            Write-ProtocolEntry -Text "JSON differs from the expected format in file $ReportFile, please open an issue" -LogLevel "Error"
            Continue            
        }

        try {
            $ReportContent = Get-Content -Path $TempFileName | ConvertFrom-Json
        } catch {
            Write-ProtocolEntry -Text "Error during JSON parsing of file $ReportFile" -LogLevel "Error"
            Continue
        }

        #
        # Output Summary
        #
        [String] $Message = "$($ReportContent.name) (Tag: $($ReportContent.version)): $($ReportContent.summary) / Unique count: $($ReportContent.uniqueCount)"

        If ($ReportContent.ok -eq $True) {

            Write-ProtocolEntry -Text $Message -LogLevel "Success"
        }
        Else {

            Write-ProtocolEntry -Text $Message -LogLevel "Error"
        }

        #
        # Build Export
        #
        ForEach ($Vulnerability in $ReportContent.vulnerabilities) {
            
            $OutputId = $global:VulnerabilityId
            $OutputIdSnyk = $Vulnerability.id
            $OutputImage = $ReportContent.name
            $OutputImageVersion = $ReportContent.version
            $OutputPackageName = $Vulnerability.packageName
            $OutputPackageVersion = $Vulnerability.version
            $OutputTitle = $Vulnerability.title
            $OutputSeverity = $Vulnerability.severity
            $OutputDescription = $Vulnerability.description -replace "`n|`r"
            $OutputDescription = $OutputDescription -replace '"', '""'
            $OutputCountermeasure = "Fixed Version: $($Vulnerability.nearestFixedInVersion)"
            $OutputUpgradable = $Vulnerability.isUpgradable
            $OutputPatchable = $Vulnerability.isPatchable
            $OutputCvssScore = $Vulnerability.cvssScore
            $OutputCvss3 = $Vulnerability.CVSSv3

            $OutputReference = ""
            ForEach ($Reference in $Vulnerability.references) {
                $OutputReference += "$($Reference.url);"
            }

            $Message = '"'+$OutputId+'","'+$OutputIdSnyk+'","'+$OutputImage+'","'+$OutputImageVersion+'","'+$OutputPackageName+'","'+$OutputPackageVersion+'","'+$OutputTitle+'","'+$OutputSeverity+'","'+$OutputDescription+'","'+$OutputCountermeasure+'","'+$OutputUpgradable+'","'+$OutputPatchable+'","'+$OutputCvssScore+'","'+$OutputCvss3+'","'+$OutputReference+'"'
            Add-ResultEntry -Text $Message
            $global:VulnerabilityId++
        }        

        Remove-Item $TempFileName
    }

    #
    # Start Main
    #
    $ContainerKittyVersion = "0.2.1-1646751589"

    If ($Log -and $LogFile.Length -eq 0) {
        $FileDate = Get-Date -Format yyyyMMdd-HHmm
        $LogFile = "containerkitty_log-$FileDate.log"
    }

    #
    # Header
    #
    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  ContainerKitty $ContainerKittyVersion"
    Write-Output "`n"    
    Write-ProtocolEntry -Text "Starting ContainerKitty" -LogLevel "Info"

    #
    # Build a list of container images
    # This uses the GitLab API to get all projects of a group.
    #
    If ($BuildList) {

        Write-ProtocolEntry -Text "Start API calls" -LogLevel "Info"

        If ($BuildListOutput.Length -eq 0) {
            $FileDate = Get-Date -Format yyyyMMdd-HHmm
            $BuildListOutput = ".\containerkitty_container_list-$FileDate.txt"
        }       

        # Get PrivateToken through built-in function Get-Credential
        Write-ProtocolEntry -Text "ContainerKitty needs a private token to build the container list. This token will not be stored." -LogLevel "Info"
        $PrivateTokenInput = Get-Credential -UserName PrivateToken -Message "Private Token for GitLab"
        $PrivateToken = $PrivateTokenInput.GetNetworkCredential().Password

        # Define variables for API calls
        $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ContainerKitty $ContainerKittyVersion"

        If ($BuildBaseUrl.Length -eq 0) {
            $BuildBaseUrl = "https://gitlab.example.com"
        }

        If ($BuildId.Length -eq 0) {
            $BuildId = "42"
        }

        Switch ($BuildIdType) {
            "User"    { $UriIdProjects = "$BuildBaseUrl/api/v4/users/$BuildId/projects"; Break}
            "Group"   { $UriIdProjects = "$BuildBaseUrl/api/v4/groups/$BuildId/projects"; Break}
        }

        # Get list of projects for the submitted user/group id and request all images from those projects
        If ($BuildIdType -eq "User" -or $BuildIdType -eq "Group" ) {

            $IwrProjects = Invoke-WebRequest -UserAgent $UserAgent -Headers @{"PRIVATE-TOKEN" = $PrivateToken} -Uri $UriIdProjects
            If ($IwrProjects.StatusCode -eq 200) {

                 $Projects = $IwrProjects.Content | ConvertFrom-Json
                 Foreach ($Project in $Projects) {
            
                    $ProjectId = $Project.id
                    $UriContainerRegistryRepositories = "$BuildBaseUrl/api/v4/projects/$ProjectId/registry/repositories?tags=0&tags_count=true"
                    $IwrRepositories = Invoke-WebRequest -UserAgent $UserAgent -Headers @{"PRIVATE-TOKEN" = $PrivateToken} -Uri $UriContainerRegistryRepositories

                    If ($IwrRepositories.StatusCode -eq 200 -and $IwrRepositories.Content -ne "") {

                        $Repositories = $IwrRepositories.Content | ConvertFrom-Json
                
                        Foreach ($Repository in $Repositories) {                                        
                            Add-Content -Value $Repository.location -Path $BuildListOutput
                        }
                    }
                    Else {
                        Write-ProtocolEntry -Text "Error in a API call" -LogLevel "Error"
                        Break
                    }
                 }
            }
            Else {
                Write-ProtocolEntry -Text "Error in a API call" -LogLevel "Error"
                Break
            }
        } 
        ElseIf ($BuildIdType -eq "Project") {

            $ProjectId = $BuildId
            $UriContainerRegistryRepositories = "$BuildBaseUrl/api/v4/projects/$ProjectId/registry/repositories?tags=0&tags_count=true"
            $IwrRepositories = Invoke-WebRequest -UserAgent $UserAgent -Headers @{"PRIVATE-TOKEN" = $PrivateToken} -Uri $UriContainerRegistryRepositories

            If ($IwrRepositories.StatusCode -eq 200 -and $IwrRepositories.Content -ne "") {

                $Repositories = $IwrRepositories.Content | ConvertFrom-Json
        
                Foreach ($Repository in $Repositories) {                                        
                    Add-Content -Value $Repository.location -Path $BuildListOutput
                }
            }
            Else {
                Write-ProtocolEntry -Text "Error in a API call" -LogLevel "Error"
                Break
            }
        }
        Write-ProtocolEntry -Text "List of container images is finished: $BuildListOutput" -LogLevel "Success"
        Write-ProtocolEntry -Text "API calls done" -LogLevel "Info"
    }

    If ($Scan) {
   
        # If a list is to be built and a scan is to be executed at the same time,
        # the new list can be taken if nothing else has been defined
        If ($ScanInputFile.Length -eq 0 -and $BuildList) {
            $ScanInputFile = $BuildListOutput
        }

        $Images = Get-Content -Path $ScanInputFile

        ForEach($Image in $Images) {

            $ImageName = $Image.split(":")
            $ImageName = $ImageName[0]

            $ReportDate = Get-Date -Format yyyyMMdd-HHmm
            $ReportFile = $ImageName -replace "/", "_"
            $ReportFile += "-$ReportDate.json"

            # Load Docker
            Write-ProtocolEntry -Text "Start pulling container image $Image" -LogLevel "Info"
            Try {
                docker pull $Image
            } catch {
                    Write-ProtocolEntry -Text "Error during pulling container image $Image" -LogLevel "Error"
                    Continue
            }
            If ($LastExitCode -eq 0) {
                Write-ProtocolEntry -Text "Pulling container image $Image done" -LogLevel "Success"
            } Else {
                Write-ProtocolEntry -Text "Error during pulling container image $Image" -LogLevel "Error"
                Continue
            }            

            # Scan Docker
            Write-ProtocolEntry -Text "Start scanning container image $Image" -LogLevel "Info"
            Try {
                docker scan --dependency-tree --json $Image > "$ReportDirectory\$ReportFile"
            } catch {
                    Write-ProtocolEntry -Text "Error during scanning container image $Image" -LogLevel "Error"
                    Continue                
            }
            Write-ProtocolEntry -Text "Scanning container image $Image done" -LogLevel "Info"
        }
    }
    
    If ($Report) {        

        If ($ContainerKittyReportFile.Length -eq 0) {
            $FileDate = Get-Date -Format yyyyMMdd-HHmm
            $ContainerKittyReportFile = ".\containerkitty_report-$FileDate.csv"
        }

        Write-ProtocolEntry -Text "Start creating the report $ContainerKittyReportFile" -LogLevel "Info"
					
        # Write Header
        $Message = '"Id","IdSnyk","Image","ImageVersion","PackageName","PackageVersion","Title","Severity","Description","Countermeasure","Upgradable","Patchable","CVSS Score","CVSSv3","Reference"'
        Add-ResultEntry -Text $Message

        #
        # Go trough all reports in a directory
        #
        $Reports = Get-Childitem -Path $ReportDirectory -Filter *.json
        $global:VulnerabilityId = 1

        ForEach ($ReportItem in $Reports) {
        
            $ReportFile = $ReportItem.Fullname
            Parse-Report
        }
        Write-ProtocolEntry -Text "Creating report $ContainerKittyReportFile done" -LogLevel "Info"
    }
    Write-ProtocolEntry -Text "ContainerKitty is done" -LogLevel "Info"
}