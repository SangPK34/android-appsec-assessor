[CmdletBinding()]
param(
    [switch]$Repair,
    [switch]$ForceTools,
    [switch]$SkipDownloads,
    [switch]$SkipBuildTools,
    [switch]$IncludeDev,
    [switch]$AcceptLicenses
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ProjectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path))
$LogDirectory = Join-Path $ProjectRoot "logs"
$SetupLog = Join-Path $LogDirectory "setup.log"
$StateDirectory = Join-Path $ProjectRoot "runtime\state"
$DownloadDirectory = Join-Path $ProjectRoot "runtime\downloads"
$ManifestPath = Join-Path $ProjectRoot "config\tools.lock.json"
$SetupErrors = [Collections.Generic.List[string]]::new()
$OptionalErrors = [Collections.Generic.List[string]]::new()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    [IO.Directory]::CreateDirectory($Path) | Out-Null
}

function Write-SetupLog {
    param(
        [Parameter(Mandatory)][ValidateSet("INFO", "OK", "WARN", "ERROR")][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )

    Ensure-Directory $LogDirectory
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff zzz"), $Level, $Message
    Add-Content -LiteralPath $SetupLog -Value $line -Encoding UTF8
    $color = switch ($Level) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        default { "Cyan" }
    }
    Write-Host $line -ForegroundColor $color
}

function Test-PathUnderProject {
    param([Parameter(Mandatory)][string]$Path)
    $rootPrefix = $ProjectRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $fullPath = [IO.Path]::GetFullPath($Path)
    return $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Remove-ProjectItem {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-PathUnderProject $Path)) {
        throw "Refusing to remove path outside project: $Path"
    }
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    if (-not (Test-PathUnderProject $Path)) {
        throw "Refusing to write JSON outside project: $Path"
    }
    Ensure-Directory (Split-Path -Parent $Path)
    $part = "$Path.part"
    $json = $Value | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($part, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
    [IO.File]::Move($part, $Path)
}

function ConvertTo-WindowsArgument {
    param([AllowEmptyString()][string]$Argument)
    if ($null -eq $Argument -or $Argument.Length -eq 0) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($slashes * 2) + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append(('\' * $slashes))
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) {
        [void]$builder.Append(('\' * ($slashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-LocalProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 120,
        [string]$WorkingDirectory = $ProjectRoot,
        [hashtable]$Environment = @{}
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join " ")
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($name in $Environment.Keys) {
        $startInfo.EnvironmentVariables[$name] = [string]$Environment[$name]
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $startedAt = Get-Date
    if (-not $process.Start()) {
        throw "Could not start process: $FilePath"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $process.Kill() } catch { }
        $process.WaitForExit()
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $exitCode = if ($timedOut) { -1 } else { $process.ExitCode }
    $duration = [int]((Get-Date) - $startedAt).TotalMilliseconds
    $process.Dispose()

    [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout.Trim()
        Stderr = $stderr.Trim()
        TimedOut = $timedOut
        DurationMs = $duration
    }
}

function Test-Executable {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Arguments = @("--version"),
        [int]$TimeoutSeconds = 15
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    try {
        $result = Invoke-LocalProcess -FilePath $Path -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
        return (-not $result.TimedOut -and $result.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-DownloadFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$MinimumBytes,
        [Parameter(Mandatory)][string]$Sha256
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -lt $MinimumBytes) {
        return $false
    }
    return (Get-FileSha256 $Path) -eq $Sha256.ToLowerInvariant()
}

function Get-VerifiedDownload {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][long]$MinimumBytes
    )

    $uri = [Uri]$Url
    if ($uri.Scheme -ne "https") {
        throw "Only HTTPS downloads are allowed: $Url"
    }
    $fileName = [IO.Path]::GetFileName($uri.AbsolutePath)
    $destination = Join-Path $DownloadDirectory $fileName
    Ensure-Directory $DownloadDirectory

    if (Test-DownloadFile -Path $destination -MinimumBytes $MinimumBytes -Sha256 $Sha256) {
        Write-SetupLog "OK" "$Name archive already verified: $destination"
        return $destination
    }
    if ($SkipDownloads) {
        throw "$Name is missing or invalid and -SkipDownloads was supplied."
    }
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Force
    }

    $part = "$destination.part"
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        if (Test-Path -LiteralPath $part) {
            Remove-Item -LiteralPath $part -Force
        }
        try {
            Write-SetupLog "INFO" "Downloading $Name (attempt $attempt/3): $Url"
            $handler = [Net.Http.HttpClientHandler]::new()
            $handler.AllowAutoRedirect = $true
            $client = [Net.Http.HttpClient]::new($handler)
            $client.Timeout = [TimeSpan]::FromMinutes(5)
            try {
                $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                [void]$response.EnsureSuccessStatusCode()
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $outputStream = [IO.File]::Open($part, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
            } finally {
                $client.Dispose()
                $handler.Dispose()
            }

            if (-not (Test-DownloadFile -Path $part -MinimumBytes $MinimumBytes -Sha256 $Sha256)) {
                $actualSize = (Get-Item -LiteralPath $part).Length
                $actualHash = Get-FileSha256 $part
                throw "Verification failed for $Name (size=$actualSize, sha256=$actualHash)."
            }
            [IO.File]::Move($part, $destination)
            Write-SetupLog "OK" "$Name download verified with SHA-256."
            return $destination
        } catch {
            Write-SetupLog "WARN" "$Name download attempt $attempt failed: $($_.Exception.Message)"
            if (Test-Path -LiteralPath $part) {
                Remove-Item -LiteralPath $part -Force
            }
            if ($attempt -lt 3) {
                Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
            }
        }
    }
    throw "Could not download and verify $Name after 3 attempts."
}

function Expand-ZipSafely {
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Ensure-Directory $Destination
    $destinationRoot = [IO.Path]::GetFullPath($Destination).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        foreach ($entry in $zip.Entries) {
            $relative = $entry.FullName.Replace('/', [IO.Path]::DirectorySeparatorChar)
            $outputPath = [IO.Path]::GetFullPath((Join-Path $Destination $relative))
            if (-not $outputPath.StartsWith($destinationRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Unsafe zip entry rejected: $($entry.FullName)"
            }
            if ([string]::IsNullOrEmpty($entry.Name)) {
                Ensure-Directory $outputPath
                continue
            }
            Ensure-Directory (Split-Path -Parent $outputPath)
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $outputPath, $true)
        }
    } finally {
        $zip.Dispose()
    }
}

function Install-ZipAtomically {
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$TargetDirectory,
        [AllowEmptyString()][string]$ArchiveRoot = ""
    )
    if (-not (Test-PathUnderProject $TargetDirectory)) {
        throw "Refusing to install outside project: $TargetDirectory"
    }
    $parent = Split-Path -Parent $TargetDirectory
    Ensure-Directory $parent
    $token = [Guid]::NewGuid().ToString("N")
    $stagingRoot = "$TargetDirectory.installing.$token"
    $candidate = "$TargetDirectory.candidate.$token"
    $backup = "$TargetDirectory.backup.$token"

    try {
        Expand-ZipSafely -Archive $Archive -Destination $stagingRoot
        $source = if ([string]::IsNullOrWhiteSpace($ArchiveRoot)) { $stagingRoot } else { Join-Path $stagingRoot $ArchiveRoot }
        if (-not (Test-Path -LiteralPath $source -PathType Container)) {
            throw "Archive root not found: $ArchiveRoot"
        }
        if ($source -eq $stagingRoot) {
            $candidate = $stagingRoot
        } else {
            Move-Item -LiteralPath $source -Destination $candidate
            Remove-ProjectItem $stagingRoot
        }

        if (Test-Path -LiteralPath $TargetDirectory) {
            Move-Item -LiteralPath $TargetDirectory -Destination $backup
        }
        try {
            Move-Item -LiteralPath $candidate -Destination $TargetDirectory
        } catch {
            if (Test-Path -LiteralPath $backup) {
                Move-Item -LiteralPath $backup -Destination $TargetDirectory
            }
            throw
        }
        if (Test-Path -LiteralPath $backup) {
            Remove-ProjectItem $backup
        }
    } finally {
        foreach ($path in @($stagingRoot, $candidate)) {
            if (Test-Path -LiteralPath $path) {
                Remove-ProjectItem $path
            }
        }
    }
}

function Get-PythonInfo {
    param([Parameter(Mandatory)][string]$PythonPath)
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        return $null
    }
    try {
        $code = "import json,struct,sys; print(json.dumps({'executable':sys.executable,'major':sys.version_info.major,'minor':sys.version_info.minor,'micro':sys.version_info.micro,'bits':struct.calcsize('P')*8}))"
        $result = Invoke-LocalProcess -FilePath $PythonPath -Arguments @("-c", $code) -TimeoutSeconds 15
        if ($result.ExitCode -ne 0 -or $result.TimedOut) {
            return $null
        }
        return $result.Stdout | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Test-CompatiblePython {
    param([Parameter(Mandatory)][string]$PythonPath)
    $info = Get-PythonInfo $PythonPath
    return ($null -ne $info -and $info.major -eq 3 -and $info.minor -eq 12 -and $info.bits -eq 64)
}

function Find-SystemPython312 {
    $candidates = [Collections.Generic.List[string]]::new()
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $launcher) {
        try {
            $probe = Invoke-LocalProcess -FilePath $launcher.Source -Arguments @("-3.12", "-c", "import sys; print(sys.executable)") -TimeoutSeconds 15
            if ($probe.ExitCode -eq 0 -and $probe.Stdout) {
                [void]$candidates.Add($probe.Stdout.Trim())
            }
        } catch { }
    }
    foreach ($commandName in @("python.exe", "python3.exe")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            [void]$candidates.Add($command.Source)
        }
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (Test-CompatiblePython $candidate) {
            return $candidate
        }
    }
    return $null
}

function Configure-EmbeddedPython {
    param(
        [Parameter(Mandatory)][string]$PythonDirectory,
        [Parameter(Mandatory)]$PipManifest
    )
    $pth = Get-ChildItem -LiteralPath $PythonDirectory -Filter "python*._pth" | Select-Object -First 1
    if ($null -eq $pth) {
        throw "Embedded Python _pth file not found."
    }
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($line in (Get-Content -LiteralPath $pth.FullName)) {
        if ($line.Trim() -eq "#import site") {
            continue
        }
        if ($line.Trim() -eq "import site") {
            continue
        }
        if ($line.Trim() -eq "Lib\site-packages") {
            continue
        }
        if ($line.Trim() -eq "..\..") {
            continue
        }
        [void]$lines.Add($line)
    }
    [void]$lines.Add("..\..")
    [void]$lines.Add("Lib\site-packages")
    [void]$lines.Add("import site")
    [IO.File]::WriteAllLines($pth.FullName, $lines, [Text.UTF8Encoding]::new($false))

    $sitePackages = Join-Path $PythonDirectory "Lib\site-packages"
    Ensure-Directory $sitePackages
    $embeddedPython = Join-Path $PythonDirectory "python.exe"
    if (Test-Path -LiteralPath $embeddedPython -PathType Leaf) {
        $pipProbe = Invoke-LocalProcess -FilePath $embeddedPython -Arguments @("-m", "pip", "--version") -TimeoutSeconds 30
        $expectedPrefix = "pip $($PipManifest.version) "
        if (-not $pipProbe.TimedOut -and $pipProbe.ExitCode -eq 0 -and $pipProbe.Stdout.Trim().StartsWith($expectedPrefix)) {
            Write-SetupLog "OK" "Embedded pip $($PipManifest.version) is healthy."
            return
        }
    }
    $pipArchive = Get-VerifiedDownload -Name "pip" -Url $PipManifest.url -Sha256 $PipManifest.sha256 -MinimumBytes $PipManifest.minimum_bytes
    $staging = Join-Path $PythonDirectory ("pip.installing." + [Guid]::NewGuid().ToString("N"))
    try {
        Expand-ZipSafely -Archive $pipArchive -Destination $staging
        Get-ChildItem -LiteralPath $staging -Force | ForEach-Object {
            $destination = Join-Path $sitePackages $_.Name
            if (Test-Path -LiteralPath $destination) {
                Remove-ProjectItem $destination
            }
            Move-Item -LiteralPath $_.FullName -Destination $destination
        }
    } finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-ProjectItem $staging
        }
    }
}

function Get-OrCreateProjectPython {
    param([Parameter(Mandatory)]$Manifest)
    $venvPython = Join-Path $ProjectRoot "runtime\venv\Scripts\python.exe"
    $embeddedDirectory = Join-Path $ProjectRoot "runtime\python"
    $embeddedPython = Join-Path $embeddedDirectory "python.exe"

    if (Test-CompatiblePython $venvPython) {
        Write-SetupLog "OK" "Using existing local venv: $venvPython"
        return $venvPython
    }
    if (Test-CompatiblePython $embeddedPython) {
        Configure-EmbeddedPython -PythonDirectory $embeddedDirectory -PipManifest $Manifest.tools.pip
        Write-SetupLog "OK" "Using existing embedded Python: $embeddedPython"
        return $embeddedPython
    }

    $systemPython = Find-SystemPython312
    if ($null -ne $systemPython) {
        Write-SetupLog "INFO" "Creating project-local venv from: $systemPython"
        $venvDirectory = Join-Path $ProjectRoot "runtime\venv"
        if (Test-Path -LiteralPath $venvDirectory) {
            Remove-ProjectItem $venvDirectory
        }
        $result = Invoke-LocalProcess -FilePath $systemPython -Arguments @("-m", "venv", $venvDirectory) -TimeoutSeconds 180
        if ($result.ExitCode -eq 0 -and (Test-CompatiblePython $venvPython)) {
            Write-SetupLog "OK" "Created local venv."
            return $venvPython
        }
        if (Test-Path -LiteralPath $venvDirectory) {
            Remove-ProjectItem $venvDirectory
        }
        Write-SetupLog "WARN" "Local venv creation failed; falling back to embedded Python. $($result.Stderr)"
    }

    $pythonManifest = $Manifest.tools.python
    $archive = Get-VerifiedDownload -Name "CPython $($pythonManifest.version)" -Url $pythonManifest.url -Sha256 $pythonManifest.sha256 -MinimumBytes $pythonManifest.minimum_bytes
    Install-ZipAtomically -Archive $archive -TargetDirectory $embeddedDirectory -ArchiveRoot $pythonManifest.archive_root
    Configure-EmbeddedPython -PythonDirectory $embeddedDirectory -PipManifest $Manifest.tools.pip
    if (-not (Test-CompatiblePython $embeddedPython)) {
        throw "Embedded Python validation failed after installation."
    }
    Write-SetupLog "OK" "Installed embedded Python: $embeddedPython"
    return $embeddedPython
}

function Test-PythonLockSatisfied {
    param(
        [Parameter(Mandatory)][string]$PythonPath,
        [Parameter(Mandatory)][string]$LockFile
    )
    if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) {
        return $false
    }
    $script = @'
import importlib.metadata
import re
import sys

ok = True
for line in open(sys.argv[1], encoding="utf-8"):
    match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", line.strip())
    if not match:
        continue
    name, expected = match.groups()
    try:
        actual = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        ok = False
        continue
    if actual != expected:
        ok = False
sys.exit(0 if ok else 1)
'@
    try {
        $result = Invoke-LocalProcess -FilePath $PythonPath -Arguments @("-c", $script, $LockFile) -TimeoutSeconds 60
        return (-not $result.TimedOut -and $result.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Install-PythonLock {
    param(
        [Parameter(Mandatory)][string]$PythonPath,
        [Parameter(Mandatory)][string]$LockFile,
        [Parameter(Mandatory)][string]$Name,
        [switch]$Optional,
        [switch]$AllowSource
    )
    if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) {
        if ($Optional) {
            throw "Optional lock file missing: $LockFile"
        }
        throw "Required lock file missing: $LockFile"
    }
    if (Test-PythonLockSatisfied -PythonPath $PythonPath -LockFile $LockFile) {
        Write-SetupLog "OK" "Pinned Python dependencies are healthy: $Name"
        return
    }
    if ($SkipDownloads) {
        Write-SetupLog "WARN" "Skipping package installation for $Name because -SkipDownloads is set."
        return
    }
    Write-SetupLog "INFO" "Installing pinned Python dependencies: $Name"
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($argument in @(
        "-m", "pip", "install",
        "--disable-pip-version-check",
        "--no-input",
        "--require-hashes",
        "-r", $LockFile
    )) {
        [void]$arguments.Add($argument)
    }
    if (-not $AllowSource) {
        [void]$arguments.Insert($arguments.IndexOf("-r"), "--only-binary=:all:")
    } else {
        [void]$arguments.Insert($arguments.IndexOf("-r"), "--no-build-isolation")
    }
    $result = Invoke-LocalProcess -FilePath $PythonPath -Arguments $arguments -TimeoutSeconds 1200 -Environment @{ "PYTHONUTF8" = "1"; "PIP_NO_INPUT" = "1" }
    if ($result.ExitCode -ne 0 -or $result.TimedOut) {
        $detail = if ($result.Stderr) { $result.Stderr } else { $result.Stdout }
        if ($detail.Length -gt 3000) { $detail = $detail.Substring($detail.Length - 3000) }
        throw "pip install failed for ${Name}: $detail"
    }
    if (-not (Test-PythonLockSatisfied -PythonPath $PythonPath -LockFile $LockFile)) {
        throw "Installed dependencies do not match the pinned lock: $Name"
    }
    Write-SetupLog "OK" "Installed and verified $Name."
}

function Install-ArchiveComponent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$ToolManifest,
        [Parameter(Mandatory)][string]$TargetDirectory,
        [Parameter(Mandatory)][string]$ProbePath,
        [string[]]$ProbeArguments = @("--version")
    )
    if (-not $ForceTools -and (Test-Executable -Path $ProbePath -Arguments $ProbeArguments)) {
        Write-SetupLog "OK" "$Name is healthy: $ProbePath"
        return
    }
    $archive = Get-VerifiedDownload -Name $Name -Url $ToolManifest.url -Sha256 $ToolManifest.sha256 -MinimumBytes $ToolManifest.minimum_bytes
    Install-ZipAtomically -Archive $archive -TargetDirectory $TargetDirectory -ArchiveRoot $ToolManifest.archive_root
    if (-not (Test-Executable -Path $ProbePath -Arguments $ProbeArguments)) {
        throw "$Name executable probe failed after installation: $ProbePath"
    }
    Write-SetupLog "OK" "Installed $Name $($ToolManifest.version)."
}

function Install-FileComponent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$ToolManifest,
        [Parameter(Mandatory)][string]$TargetPath
    )
    if (-not $ForceTools -and (Test-DownloadFile -Path $TargetPath -MinimumBytes $ToolManifest.minimum_bytes -Sha256 $ToolManifest.sha256)) {
        Write-SetupLog "OK" "$Name is healthy: $TargetPath"
        return
    }
    $download = Get-VerifiedDownload -Name $Name -Url $ToolManifest.url -Sha256 $ToolManifest.sha256 -MinimumBytes $ToolManifest.minimum_bytes
    Ensure-Directory (Split-Path -Parent $TargetPath)
    $staging = "$TargetPath.installing.$([Guid]::NewGuid().ToString('N'))"
    try {
        Copy-Item -LiteralPath $download -Destination $staging
        if (-not (Test-DownloadFile -Path $staging -MinimumBytes $ToolManifest.minimum_bytes -Sha256 $ToolManifest.sha256)) {
            throw "$Name staging verification failed."
        }
        if (Test-Path -LiteralPath $TargetPath) {
            [IO.File]::Replace($staging, $TargetPath, $null)
        } else {
            [IO.File]::Move($staging, $TargetPath)
        }
    } finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Force
        }
    }
    Write-SetupLog "OK" "Installed $Name $($ToolManifest.version)."
}

function Install-XzFileComponent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$ToolManifest,
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)][string]$PythonPath
    )
    if (-not (Test-PathUnderProject $TargetPath)) {
        throw "Refusing to install outside project: $TargetPath"
    }
    if (-not $ForceTools -and (Test-DownloadFile -Path $TargetPath -MinimumBytes $ToolManifest.output_minimum_bytes -Sha256 $ToolManifest.output_sha256)) {
        Write-SetupLog "OK" "$Name is healthy: $TargetPath"
        return
    }
    $download = Get-VerifiedDownload -Name $Name -Url $ToolManifest.url -Sha256 $ToolManifest.sha256 -MinimumBytes $ToolManifest.minimum_bytes
    Ensure-Directory (Split-Path -Parent $TargetPath)
    $staging = "$TargetPath.installing.$([Guid]::NewGuid().ToString('N'))"
    $decompress = @'
import lzma
import pathlib
import shutil
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
with lzma.open(source, "rb") as input_file, target.open("xb") as output_file:
    shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
'@
    try {
        $result = Invoke-LocalProcess -FilePath $PythonPath -Arguments @("-c", $decompress, $download, $staging) -TimeoutSeconds 300
        if ($result.TimedOut -or $result.ExitCode -ne 0) {
            throw "$Name XZ extraction failed: $($result.Stderr)"
        }
        if (-not (Test-DownloadFile -Path $staging -MinimumBytes $ToolManifest.output_minimum_bytes -Sha256 $ToolManifest.output_sha256)) {
            throw "$Name extracted file verification failed."
        }
        if (Test-Path -LiteralPath $TargetPath) {
            [IO.File]::Replace($staging, $TargetPath, $null)
        } else {
            [IO.File]::Move($staging, $TargetPath)
        }
    } finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Force
        }
    }
    Write-SetupLog "OK" "Installed $Name."
}

function Confirm-AndroidSdkLicense {
    $licenseState = Join-Path $StateDirectory "android-sdk-license.accepted.json"
    if (Test-Path -LiteralPath $licenseState) {
        return
    }
    if ($SkipDownloads) {
        return
    }
    $accepted = $AcceptLicenses
    if (-not $accepted) {
        Write-Host "Android Platform/Build Tools are governed by the Android SDK License:" -ForegroundColor Yellow
        Write-Host "https://developer.android.com/studio/terms"
        $answer = Read-Host "Accept and continue downloading Android SDK components? [y/N]"
        $accepted = $answer -match '^(y|yes)$'
    }
    if (-not $accepted) {
        throw "Android SDK license was not accepted."
    }
    Write-JsonAtomic -Path $licenseState -Value ([ordered]@{
        accepted = $true
        accepted_at = (Get-Date).ToUniversalTime().ToString("o")
        url = "https://developer.android.com/studio/terms"
    })
}

function Initialize-Layout {
    $directories = @(
        "config", "runtime", "runtime\python", "runtime\venv", "runtime\downloads", "runtime\state",
        "tools", "tools\platform-tools", "tools\scrcpy", "tools\build-tools", "tools\java", "tools\frida", "tools\mitmproxy",
        "android_assessor", "web", "web\templates", "web\static", "rules", "hooks", "templates", "tests",
        "logs", "results"
    )
    foreach ($relative in $directories) {
        Ensure-Directory (Join-Path $ProjectRoot $relative)
    }
}

function Test-WindowsHost {
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw "AndroidSecurityLab requires 64-bit Windows."
    }
    $platform = [Environment]::OSVersion.Platform
    if ($platform -ne [PlatformID]::Win32NT) {
        throw "setup.ps1 supports native Windows only."
    }
    $isAdmin = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    Write-SetupLog "INFO" "Windows x64 detected. Running as admin: $isAdmin (not required)."
}

try {
    Initialize-Layout
    Write-SetupLog "INFO" "AndroidSecurityLab bootstrap started. Repair=$Repair ForceTools=$ForceTools SkipDownloads=$SkipDownloads"
    Test-WindowsHost

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Tool manifest missing: $ManifestPath"
    }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    Confirm-AndroidSdkLicense

    $python = Get-OrCreateProjectPython -Manifest $manifest
    $pipProbe = Invoke-LocalProcess -FilePath $python -Arguments @("-m", "pip", "--version") -TimeoutSeconds 30
    if ($pipProbe.ExitCode -ne 0) {
        throw "Local pip is not available: $($pipProbe.Stderr)"
    }
    Write-SetupLog "OK" $pipProbe.Stdout

    Install-PythonLock -PythonPath $python -LockFile (Join-Path $ProjectRoot "requirements.lock") -Name "core + web"
    try {
        Install-PythonLock -PythonPath $python -LockFile (Join-Path $ProjectRoot "requirements-frida.lock") -Name "Frida client tools" -Optional -AllowSource
    } catch {
        [void]$OptionalErrors.Add($_.Exception.Message)
        Write-SetupLog "WARN" $_.Exception.Message
    }
    try {
        Install-PythonLock -PythonPath $python -LockFile (Join-Path $ProjectRoot "requirements-mitmproxy.lock") -Name "mitmproxy" -Optional
    } catch {
        [void]$OptionalErrors.Add($_.Exception.Message)
        Write-SetupLog "WARN" $_.Exception.Message
    }
    if ($IncludeDev) {
        try {
            Install-PythonLock -PythonPath $python -LockFile (Join-Path $ProjectRoot "requirements-dev.lock") -Name "development tools" -Optional
        } catch {
            [void]$OptionalErrors.Add($_.Exception.Message)
            Write-SetupLog "WARN" $_.Exception.Message
        }
    }

    $platformTarget = Join-Path $ProjectRoot "tools\platform-tools"
    try {
        Install-ArchiveComponent -Name "Android Platform Tools" -ToolManifest $manifest.tools.platform_tools -TargetDirectory $platformTarget -ProbePath (Join-Path $platformTarget "adb.exe") -ProbeArguments @("version")
    } catch {
        [void]$SetupErrors.Add($_.Exception.Message)
        Write-SetupLog "ERROR" $_.Exception.Message
    }

    $scrcpyTarget = Join-Path $ProjectRoot "tools\scrcpy"
    try {
        Install-ArchiveComponent -Name "scrcpy" -ToolManifest $manifest.tools.scrcpy -TargetDirectory $scrcpyTarget -ProbePath (Join-Path $scrcpyTarget "scrcpy.exe") -ProbeArguments @("--version")
    } catch {
        [void]$SetupErrors.Add($_.Exception.Message)
        Write-SetupLog "ERROR" $_.Exception.Message
    }

    $javaTarget = Join-Path $ProjectRoot "tools\java"
    try {
        Install-ArchiveComponent -Name "Eclipse Temurin JRE" -ToolManifest $manifest.tools.java_runtime -TargetDirectory $javaTarget -ProbePath (Join-Path $javaTarget "bin\java.exe") -ProbeArguments @("-version")
    } catch {
        [void]$OptionalErrors.Add($_.Exception.Message)
        Write-SetupLog "WARN" $_.Exception.Message
    }

    $fridaServerManifest = $manifest.tools.frida_servers
    foreach ($architecture in @("arm", "arm64", "x86", "x86_64")) {
        $asset = $fridaServerManifest.assets.PSObject.Properties[$architecture].Value
        $target = Join-Path $ProjectRoot "tools\frida\frida-server-$($fridaServerManifest.version)-android-$architecture"
        try {
            Install-XzFileComponent -Name "Frida Server $($fridaServerManifest.version) Android $architecture" -ToolManifest $asset -TargetPath $target -PythonPath $python
        } catch {
            [void]$OptionalErrors.Add($_.Exception.Message)
            Write-SetupLog "WARN" $_.Exception.Message
        }
    }

    if (-not $SkipBuildTools) {
        $buildTarget = Join-Path $ProjectRoot "tools\build-tools"
        try {
            Install-ArchiveComponent -Name "Android Build Tools" -ToolManifest $manifest.tools.build_tools -TargetDirectory $buildTarget -ProbePath (Join-Path $buildTarget "aapt2.exe") -ProbeArguments @("version")
        } catch {
            [void]$OptionalErrors.Add($_.Exception.Message)
            Write-SetupLog "WARN" $_.Exception.Message
        }
    }

    try {
        Install-FileComponent -Name "HTMX" -ToolManifest $manifest.tools.htmx -TargetPath (Join-Path $ProjectRoot "web\static\htmx.min.js")
    } catch {
        [void]$SetupErrors.Add($_.Exception.Message)
        Write-SetupLog "ERROR" $_.Exception.Message
    }

    $environmentReport = Join-Path $ProjectRoot "lab_environment.json"
    $selfTest = Invoke-LocalProcess -FilePath $python -Arguments @("-m", "android_assessor", "self-test", "--json", "--output", $environmentReport) -TimeoutSeconds 120 -Environment @{ "PYTHONPATH" = $ProjectRoot; "PYTHONUTF8" = "1" }
    if ($selfTest.Stdout) { Write-Host $selfTest.Stdout }
    if ($selfTest.ExitCode -ne 0) {
        [void]$SetupErrors.Add("Environment self-test failed. $($selfTest.Stderr)")
    }

    $status = [ordered]@{
        schema_version = 1
        completed_at = (Get-Date).ToUniversalTime().ToString("o")
        python = $python
        repair = [bool]$Repair
        required_errors = @($SetupErrors)
        optional_errors = @($OptionalErrors)
        environment_report = $environmentReport
    }
    Write-JsonAtomic -Path (Join-Path $StateDirectory "setup.status.json") -Value $status

    if ($SetupErrors.Count -gt 0) {
        $completeState = Join-Path $StateDirectory "setup.complete.json"
        if (Test-Path -LiteralPath $completeState) {
            Remove-Item -LiteralPath $completeState -Force
        }
        throw "Setup completed with required component errors. Run repair.cmd after checking setup.log."
    }
    Write-JsonAtomic -Path (Join-Path $StateDirectory "setup.complete.json") -Value $status
    Write-SetupLog "OK" "Setup complete. Daily use does not require Administrator."
    Write-Host "Run start.cmd or run.cmd check" -ForegroundColor Green
    exit 0
} catch {
    Write-SetupLog "ERROR" $_.Exception.Message
    exit 1
}
