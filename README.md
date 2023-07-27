# ContainerKitty

## Introduction

Manual scanning of many container images is repetitive and not efficient. We have developed *ContainerKitty* to automate image scanning and simplify the process. No server infrastructure is required for *ContainerKitty*, the script can be used on any Windows system with *Docker*.

The script builds a list of container images from a *GitLab* repository. It is also possible to use a list from another source. This list should contain one image per line, for example `registry.example.com/dev/example-image:4.2.0`. *ContainerKitty* fetches the images from the *registry* into the local Docker instance and then runs the scan. The results are saved as a *JSON file* per image. The *report* function parses all JSON files and provides a short summary as well as a CSV file for further processing. All steps can be logged if required.

[Docker Desktop for Windows](https://docs.docker.com/docker-for-windows/install/) is necessary for using *Container Kitty*. A [Docker ID](https://hub.docker.com/) must be registered for this purpose. ContainerKitty started with Docker Scan, which was replaced by [Docker Scout](https://docs.docker.com/scout/) in April 2023.

## ContainerKitty in Action

Docker and *ContainerKitty* can be run *without* administrator rights. The requirement for Docker is that the user belongs to the local group `docker-users`. Before *ContainerKitty* is used for the first time, the PowerShell session must be authenticated with Docker. Now, _ContainerKitty_ can be used:

```powershell
PS C:\> docker login
PS C:\> Import-Module -Force .\Invoke-ContainerKitty.ps1
```

The modules of *ContainerKitty* can be combined with each other. In the following example, *ContainerKitty* creates a list of all images of the user with the ID `5` from GitLab and then pulls the images from the registry into the local Docker instance. Afterwards, it scans the images and analyses the results:

```powershell
PS C:\> Invoke-ContainerKitty -BuildList https://gitlab.example.org -BuildId 5 -BuildIdType User -Scan -Report -ReportDirectory .\reports\ -Log


      =^._.^=
     _(      )/  ContainerKitty 0.2.0-1623130424


[*] 6/8/2021 7:32:51 AM - Starting ContainerKitty
[*] 6/8/2021 7:32:51 AM - Start API calls
[*] 6/8/2021 7:32:51 AM - ContainerKitty needs a private token to build the container list. This token will not be stored.
[$] 6/8/2021 7:32:56 AM - List of container images is finished: .\containerkitty_container_list-20210608-0732.txt
[*] 6/8/2021 7:32:56 AM - API calls done
[*] 6/8/2021 7:32:56 AM - Start pulling container image ubuntu:xenial-20210429
...
[$] 6/8/2021 7:32:58 AM - Pulling container image ubuntu:xenial-20210429 done
[*] 6/8/2021 7:32:58 AM - Start scanning container image ubuntu:xenial-20210429
[*] 6/8/2021 7:34:11 AM - Scanning container image ubuntu:xenial-20210429 done
[*] 6/8/2021 7:34:11 AM - Start creating the report .\containerkitty_report-20210608-0734.csv
[*] 6/8/2021 7:34:28 AM - Creating report .\containerkitty_report-20210608-0734.csv done
[*] 6/8/2021 7:34:28 AM - ContainerKitty is done
```

Each module can also be run individually. Thus, a scan can be started directly by providing *ContainerKitty* a manually created list of images. It is also possible to only run an analysis on JSON files created by *Docker Scout*. The report creates a CSV file with the following information:

* Id and Id Snyk
* Image and version (tag)
* Affected package and its version
* Vulnerability title
* Description of the vulnerability
* Countermeasure and statement whether an upgrade/patch is available
* CVSS score and specification according to CVSSv3.1
* References
