param(
    [Parameter(Mandatory=$true)][ValidateSet('race','native')][string]$FixtureProfile,
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$ExpectedArchitecture
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'A disposable GitHub-hosted VM is required.'
}
if (-not $IsWindows -or [IntPtr]::Size -ne 8) { throw 'A native 64-bit Windows process is required.' }
$actualArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$actualArchitecture = @{ x64='amd64'; arm64='arm64' }[$actualArchitecture]
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.RuntimeInformation]::OSArchitecture) { throw 'Emulated processes receive no native qualification.' }
if ($actualArchitecture -ne $ExpectedArchitecture) { throw 'Actual architecture differs from the target.' }
if ($FixtureProfile -eq 'race' -and $actualArchitecture -ne 'amd64') { throw 'This Windows target has no supported race profile.' }
$root = Split-Path -Parent $PSScriptRoot
$token = [Guid]::NewGuid().ToString('N')
$proof = Join-Path $env:RUNNER_TEMP "ca8-store-proof-$token"
if (Test-Path -LiteralPath $proof) { throw 'The proof root already exists.' }
[IO.Directory]::CreateDirectory($proof) | Out-Null
"evidence-path=$proof" | Out-File -LiteralPath $env:GITHUB_OUTPUT -Append -Encoding utf8
$timer = [Diagnostics.Stopwatch]::StartNew()
$stages = [Collections.Generic.List[object]]::new()
$success = $false
$failure = $null
$attached = $false
$attachmentState = 'not-created'
$diskNumber = $null
$driveLetter = $null
$volumeRoot = $null
$image = Join-Path $proof 'fixture.vhdx'
$originalModules = @{}
foreach ($name in @('go.mod','go.sum')) {
    $originalModules[$name] = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash
}
# All native declarations are fixture boundaries. They do not enter the CLI binary.
try {
Add-Type -Path (Join-Path $PSScriptRoot 'identity-qualification-windows.cs')
} catch {
    @{ failure=$_.Exception.ToString(); stage='fixture-native-type-setup'; nativeTestDispatch=$false } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $proof 'setup-failure.json')
    throw
}
function Save-Proof([string]$Name, $Value) {
    $Value | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $proof $Name) -Encoding utf8
}
function Save-FixtureSnapshot([string]$Source) {
    $destination=Join-Path $proof 'failed-fixtures'
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    $pending=[Collections.Generic.Stack[string]]::new(); $pending.Push($Source)
    $manifest=[Collections.Generic.List[object]]::new(); [long]$copied=0; [int]$entries=0
    while ($pending.Count -gt 0) {
        Assert-Phase
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
            $entries++; if ($entries -gt 10000) { throw 'Failure snapshot entry bound reached; volume preserved.' }
            $attributes=[IO.File]::GetAttributes($path)
            $relative=[IO.Path]::GetRelativePath($Source,$path)
            if ($attributes -band [IO.FileAttributes]::ReparsePoint) {
                $manifest.Add(@{ path=$relative; omitted='reparse-point' }); continue
            }
            if ($attributes -band [IO.FileAttributes]::Directory) { $pending.Push($path); continue }
            $target=Join-Path $destination $relative
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            $reader=$null; $writer=$null
            try {
                $reader=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                $writer=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $buffer=[byte[]]::new(65536); [long]$bytes=0
                while (($read=$reader.Read($buffer,0,$buffer.Length)) -gt 0) {
                    Assert-Phase
                    $copied+=$read; $bytes+=$read
                    if ($copied -gt 134217728) { throw 'Failure snapshot byte bound reached; volume preserved.' }
                    $writer.Write($buffer,0,$read)
                }
                $manifest.Add(@{ path=$relative; bytes=$bytes })
            } finally {
                $releaseErrors=[Collections.Generic.List[string]]::new()
                foreach ($stream in @($writer,$reader)) {
                    if ($null -ne $stream) { try { $stream.Dispose() } catch { $releaseErrors.Add($_.ToString()) } }
                }
                if ($releaseErrors.Count -gt 0) { throw ($releaseErrors -join "`n") }
            }
        }
    }
    Save-Proof 'failed-fixtures.json' @{ entries=$manifest; bytes=$copied }
}
function Assert-Phase {
    if ($timer.Elapsed.TotalSeconds -ge 800) { throw 'The outer fixture deadline expired.' }
}
$childEnvironment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($name in @('PATH','SystemRoot','WINDIR','USERPROFILE','APPDATA','LOCALAPPDATA','HOME','LANG','TZ')) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ($null -ne $value) { $childEnvironment[$name] = $value }
}
$childEnvironment['GOTOOLCHAIN']='local'; $childEnvironment['GOENV']='off'; $childEnvironment['GOWORK']='off'
$childEnvironment['GOPRIVATE']=''; $childEnvironment['GONOPROXY']=''; $childEnvironment['GONOSUMDB']=''
$childEnvironment['GOPROXY']='https://proxy.golang.org'; $childEnvironment['GOSUMDB']='sum.golang.org'
$childEnvironment['GIT_TERMINAL_PROMPT']='0'; $childEnvironment['GIT_CONFIG_NOSYSTEM']='1'; $childEnvironment['GIT_CONFIG_GLOBAL']='NUL'
function Resolve-NativeExecutable([string]$Name) {
    $found = Get-Command -Name $Name -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $path = [string]$found.Source
    if (-not [IO.Path]::IsPathFullyQualified($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'The selected native executable is not an absolute file.' }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The selected native executable is a reparse point.' }
    return $item.FullName
}
function Run-Stage([string]$Executable,[string[]]$Arguments,[int]$Seconds=30,[bool]$MonitorVolume=$true) {
    Assert-Phase
    if ($stages.Count -ge 24) { throw 'Owned stage count bound reached.' }
    $limit = [Math]::Min($Seconds*1000,[int]((800-$timer.Elapsed.TotalSeconds)*1000))
    $prefix = Join-Path $proof ('{0:d2}' -f $stages.Count)
    $row = [ordered]@{ executable=$Executable; executableSHA256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash; argv=$Arguments; limitMilliseconds=$limit; monitorVolume=$MonitorVolume }
    $stages.Add($row); Save-Proof 'stages.json' $stages
    $result = [IdentityStoreFixture]::Run($Executable,$Arguments,$root,$childEnvironment,$prefix,$limit,$MonitorVolume)
    $row.result=$result; Save-Proof 'stages.json' $stages
    if ($result.status -ne 0 -or -not $result.jobEmpty -or $result.errors.Count -ne 0) { throw 'A bounded native stage failed. Preserve its raw evidence.' }
    return Get-Content -LiteralPath ($prefix+'.stdout') -Raw
}
try {
    Assert-Phase
    [IdentityStoreFixture]::EnableFixturePrivileges()
    $caller = [IdentityStoreFixture]::Caller()
    Save-Proof 'caller.json' $caller
    [IdentityStoreFixture]::InitializeNewDirectory($proof,$caller.sid)
    Save-Proof 'proof-security.json' ([IdentityStoreFixture]::InspectDirectory($proof,$caller.sid,$true))
    foreach ($command in @('Get-DiskImage','Get-Disk','Get-Partition','Get-Volume')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Missing native storage prerequisite: $command" }
    }
    $used = @((Get-Volume).DriveLetter)
    $driveLetter = @('T','U','V','W','X','Y','Z' | Where-Object { $_ -notin $used -and -not (Test-Path ($_+':\')) })[0]
    if (-not $driveLetter) { throw 'No fresh drive letter is available.' }
    $diskpart = (Resolve-NativeExecutable 'diskpart.exe')
    $recipe = Join-Path $proof 'create-owned-volume.txt'
    @("create vdisk file=`"$image`" maximum=4096 type=expandable", "select vdisk file=`"$image`"", 'attach vdisk',
      'create partition primary', "format fs=ntfs label=CA8-$($token.Substring(0,12)) quick", "assign letter=$driveLetter") |
        Set-Content -LiteralPath $recipe -Encoding ascii
    Run-Stage $diskpart @('/s',$recipe) 60 | Out-Null
    $diskImage = Get-DiskImage -ImagePath $image
    if (-not $diskImage.Attached) { throw 'The owned image is not attached.' }
    $attached=$true; $attachmentState='attached'
    $disks = @($diskImage | Get-Disk)
    if ($disks.Count -ne 1) { throw 'The owned image does not have one exact disk.' }
    $diskNumber = $disks[0].Number
    $partitions = @($disks[0] | Get-Partition | Where-Object DriveLetter -EQ $driveLetter)
    if ($partitions.Count -ne 1) { throw 'The chosen drive does not belong to the owned disk.' }
    $volumeRoot = $driveLetter+':\'
    [IdentityStoreFixture]::InitializeNewDirectory($volumeRoot,$caller.sid)
    $volume = [IdentityStoreFixture]::Volume($volumeRoot)
    $directories = @{}
    foreach ($entry in @{ fixture="ca8-store-fixtures-$token"; evidence="ca8-store-evidence-$token"; temporary='tmp'; cache='cache' }.GetEnumerator()) {
        Assert-Phase
        $path = Join-Path $volumeRoot $entry.Value
        if (Test-Path -LiteralPath $path) { throw 'A new fixture child already exists.' }
        [IO.Directory]::CreateDirectory($path) | Out-Null
        [IdentityStoreFixture]::InitializeNewDirectory($path,$caller.sid)
        $directories[$entry.Key]=$path
    }
    $inspection = [Collections.Generic.List[object]]::new()
    $inspection.Add([IdentityStoreFixture]::InspectDirectory($volumeRoot,$caller.sid,$true))
    foreach ($path in $directories.Values) { $inspection.Add([IdentityStoreFixture]::InspectDirectory($path,$caller.sid,$true)) }
    $go = (Resolve-NativeExecutable 'go.exe')
    Save-Proof 'native.json' @{ caller=$caller; architecture=$actualArchitecture; os=[Environment]::OSVersion.VersionString;
        volume=$volume; diskNumber=$diskNumber; image=$image; directories=$inspection; profile=$FixtureProfile;
        go=$go; goSHA256=(Get-FileHash -LiteralPath $go -Algorithm SHA256).Hash; moduleHashes=$originalModules; volumeMaximumBytes=4294967296 }
    $cache=$directories.cache; $temporary=$directories.temporary
    $ancestor=[IO.DirectoryInfo]::new($temporary)
    while ($null -ne $ancestor) {
        if (Test-Path -LiteralPath (Join-Path $ancestor.FullName 'node_modules')) { throw 'The external temporary chain contains node_modules.' }
        $ancestor=$ancestor.Parent
    }
    $childEnvironment['GOPATH']=Join-Path $cache 'go'; $childEnvironment['GOMODCACHE']=Join-Path $cache 'modules'
    $childEnvironment['GOCACHE']=Join-Path $cache 'build'; $childEnvironment['GOTMPDIR']=$temporary
    $childEnvironment['TMP']=$temporary; $childEnvironment['TEMP']=$temporary
    $childEnvironment['NODE_COMPILE_CACHE']=Join-Path $cache 'node'
    $childEnvironment['OE_IDENTITY_STORE_FIXTURE_ROOT']=$directories.fixture
    $childEnvironment['OE_IDENTITY_STORE_EVIDENCE_ROOT']=$directories.evidence
    $childEnvironment['OE_IDENTITY_STORE_PRIVILEGED_FIXTURES']='1'; $childEnvironment['OE_OPERATION_ID']=''
    $hostInfo = (Run-Stage $go @('env','-json','GOHOSTOS','GOHOSTARCH','GOVERSION')) | ConvertFrom-Json
    if ($hostInfo.GOHOSTOS -ne 'windows' -or $hostInfo.GOHOSTARCH -ne $ExpectedArchitecture -or $hostInfo.GOVERSION -ne 'go1.27.3') { throw 'The Go host differs from the actual target.' }
    Save-Proof 'go-host.json' $hostInfo
    $node=(Resolve-NativeExecutable 'node.exe')
    if ((Run-Stage $node @('--version')).Trim() -ne 'v24.22.1') { throw 'The maintained Node version is required.' }
    $git=(Resolve-NativeExecutable 'git.exe')
    $tracked=(Run-Stage $git @('ls-files','-z')).Split([char]0)
    $sourceInputs=@{}
    foreach ($name in $tracked) {
        if (-not $name) { continue }
        $path=[IO.Path]::GetFullPath((Join-Path $root $name))
        if (-not $path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Uncertain tracked source input.' }
        $sourceInputs[$name]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    Save-Proof 'source-inputs.json' @{ head=(Run-Stage $git @('rev-parse','HEAD')).Trim(); files=$sourceInputs; powershell=$PSVersionTable; sourceSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash }
    Run-Stage $go @('mod','download','-json') 120 | Out-Null
    foreach ($name in $originalModules.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash -ne $originalModules[$name]) { throw 'Module preparation changed a frozen source file.' }
    }
    $childEnvironment['GOPROXY']='off'; $childEnvironment['GOSUMDB']='off'; $childEnvironment['GOFLAGS']='-mod=readonly'
    if ($FixtureProfile -eq 'race') {
        $compiler = (Resolve-NativeExecutable 'gcc.exe')
        $library = (Run-Stage $compiler @('--print-file-name','libsynchronization.a')).Trim()
        if (-not [IO.Path]::IsPathFullyQualified($library) -or -not (Test-Path -LiteralPath $library -PathType Leaf)) { throw 'The installed race compiler runtime prerequisite failed.' }
        Save-Proof 'race-compiler.json' @{ path=$compiler; sha256=(Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash; synchronizationLibrary=$library }
        $childEnvironment['CC']=$compiler; $childEnvironment['CGO_ENABLED']='1'
        Run-Stage $go @('test','-count=1','-json','-race','-timeout=9m','./...') 600 | Out-Null
    } else {
        $childEnvironment['CGO_ENABLED']='0'
        Run-Stage $go @('test','-count=1','-json','-timeout=9m','./internal/identityattempt') 600 | Out-Null
    }
    foreach ($name in $originalModules.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash -ne $originalModules[$name]) { throw 'A frozen module file changed.' }
    }
    $success=$true
} catch { $failure=$_.Exception.ToString() }
finally {
    try { [IdentityStoreFixture]::RestoreFixturePrivileges() } catch { $success=$false; $failure+="`nPrivilege cleanup: $_" }
    try {
        if (Test-Path -LiteralPath $image) {
            $attachmentState='unknown'
            $observedImage=Get-DiskImage -ImagePath $image
            $attached=[bool]$observedImage.Attached
            $attachmentState=if ($attached) { 'attached' } else { 'detached' }
            Save-Proof 'attachment-readback.json' @{ attached=$attached; state=$attachmentState; image=$image; devicePath=$observedImage.DevicePath }
        }
        if ($attached) {
            $allJobsEmpty=@($stages | Where-Object { -not $_.result -or -not $_.result.jobEmpty }).Count -eq 0
            if (-not $allJobsEmpty) { throw 'Owned process cleanup is uncertain; preserve the attached volume without traversal.' }
            if ($directories -and $directories.evidence) { Copy-Item -LiteralPath $directories.evidence -Destination (Join-Path $proof 'native-evidence') -Recurse }
            if (-not $success -and $directories -and $directories.fixture) { Save-FixtureSnapshot $directories.fixture }
            if ($success) {
                $current=Get-DiskImage -ImagePath $image
                if (-not $current.Attached -or @($current | Get-Disk)[0].Number -ne $diskNumber) { throw 'The cleanup disk association changed.' }
                $detach=Join-Path $proof 'detach-owned-volume.txt'
                @("select vdisk file=`"$image`"",'detach vdisk') | Set-Content -LiteralPath $detach -Encoding ascii
                Run-Stage $diskpart @('/s',$detach) 20 -MonitorVolume $false | Out-Null
                if ((Get-DiskImage -ImagePath $image).Attached) { throw 'The owned image remains attached.' }
                $attached=$false; $attachmentState='detached'
                Remove-Item -LiteralPath $image
            }
        }
    } catch { $success=$false; $failure+="`nVolume cleanup: $_" }
    Save-Proof 'result.json' @{ success=$success; failure=$failure; elapsedSeconds=$timer.Elapsed.TotalSeconds;
        ownedVolumePreserved=($attachmentState -in @('attached','unknown')); attachmentState=$attachmentState; image=$image; diskNumber=$diskNumber;
        limits='No ordinary-user/default-root, native ENOSPC, hosted-caller or hard-kernel-deadline qualification.' }
}
if (-not $success) { throw 'Native qualification stopped. Preserve all bounded raw and partial evidence.' }
