param([Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$ExpectedArchitecture)
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'A fresh disposable GitHub-hosted VM is required.' }
if (-not $IsWindows -or [IntPtr]::Size -ne 8) { throw 'A native 64-bit Windows process is required.' }
$architecture=@{X64='amd64';Arm64='arm64'}[[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()]
if ($architecture -ne $ExpectedArchitecture -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.RuntimeInformation]::OSArchitecture) { throw 'The native process differs from the requested target.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $launcherSID=$identity.User.Value
    $launcherIsAdmin=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} finally { $identity.Dispose() }
if ($launcherSID -eq 'S-1-5-18' -or -not $launcherIsAdmin) { throw 'A non-SYSTEM administrator launcher is required.' }
$root=Split-Path -Parent $PSScriptRoot
$nonce=[Guid]::NewGuid().ToString('N')
$proof=Join-Path $env:RUNNER_TEMP "ca8-default-proof-$nonce"
$artifact=Join-Path $proof 'artifact'
$workspace=Join-Path ($env:SystemDrive+'\') "ca8-default-$nonce"
if (-not [IO.Path]::IsPathFullyQualified($workspace)) { throw 'The new fixture workspace requires an actual drive root.' }
$userName='ca8d_'+$nonce.Substring(0,12)
$timer=[Diagnostics.Stopwatch]::StartNew()
$stages=[Collections.Generic.List[object]]::new()
$created=$false; $accountCreationAttempted=$false; $sid=$null; $profileRecord=$null; $runResult=$null
$brokerStarted=$false; $allJobsEmpty=$false; $evidence=$null; $copied=$false; $collectionComplete=$false; $success=$false; $failure=$null
$artifactBytes=0L; $artifactEntries=0; $profileDeleted=$false; $accountDeleted=$false
$module=Join-Path $PSScriptRoot 'identity-qualification-windows.cs'
Add-Type -Path $module
[IdentityStoreFixture]::CreateQualificationDirectory($proof,$launcherSID,'')
[IdentityStoreFixture]::CreateQualificationDirectory($artifact,$launcherSID,'')
"evidence-path=$artifact" | Out-File -LiteralPath $env:GITHUB_OUTPUT -Append -Encoding utf8
function Save-Proof([string]$Name,$Value) {
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $proof $Name) -Encoding utf8
}
function Tool([string]$Name) {
    $paths=@(Get-Command $Name -CommandType Application -All | Select-Object -ExpandProperty Source -Unique)
    if ($paths.Count -lt 1) { throw "Missing native tool: $Name" }
    return [IO.Path]::GetFullPath($paths[0])
}
function Run-Stage([string]$Executable,[string[]]$Arguments,[int]$Seconds=30) {
    if ($timer.Elapsed.TotalSeconds -ge 500 -or $stages.Count -ge 8) { throw 'The default qualification stage bound expired.' }
    $prefix=Join-Path $proof ('stage-{0:d2}' -f $stages.Count)
    $row=@{executable=$Executable;sha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash;argv=$Arguments;result=$null}
    $stages.Add($row)
    Save-Proof 'stages.json' $stages
    $result=[IdentityStoreFixture]::RunBounded($Executable,$Arguments,$root,$buildEnvironment,$prefix,$Seconds*1000,16777216)
    $row.result=$result
    Save-Proof 'stages.json' $stages
    if ($result.status -ne 0 -or -not $result.jobEmpty -or $result.errors.Count -ne 0) { throw 'A bounded preparation stage failed.' }
    return [IO.File]::ReadAllText($prefix+'.stdout')
}
function Read-OwnedJSON([string]$Path) {
    $attributes=[IO.File]::GetAttributes($Path)
    $length=[IO.FileInfo]::new($Path).Length
    if (($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -or $length -gt 1048576) { throw 'The fixed JSON evidence is not a bounded ordinary file.' }
    return [IO.File]::ReadAllText($Path) | ConvertFrom-Json -Depth 32
}
function Test-NativeClosure($Value) {
    return $null -ne $Value -and $Value.pid -gt 0 -and $Value.jobEmpty -eq $true -and $null -ne $Value.errors -and $Value.errors.Count -eq 0
}
function Observe-OwnedClosure {
    if (@($stages | Where-Object {-not (Test-NativeClosure $_.result)}).Count -ne 0) { return $false }
    if (-not $brokerStarted) { return $true }
    if ($null -eq $runResult -or -not (Test-NativeClosure $runResult.process) -or -not $runResult.secretTransferClosed -or $runResult.errors.Count -ne 0) { return $false }
    $gui=Read-OwnedJSON (Join-Path $evidence 'broker-process.json')
    if ($gui.errors.Count -ne 0 -or -not $gui.restored -or -not $gui.stationCreated -or -not $gui.desktopCreated -or
        -not $gui.stationClosed -or -not $gui.desktopClosed -or -not $gui.stationAbsent -or -not $gui.childLaunchAttempted -or
        $gui.station -ne ('ca8_station_'+$nonce) -or $gui.desktop -ne ('ca8_desktop_'+$nonce) -or -not (Test-NativeClosure $gui.child)) { return $false }
    $controller=Read-OwnedJSON (Join-Path $evidence 'controller-process.json')
    return Test-NativeClosure $controller
}
function Read-ExactU64($Value) {
    if ($null -eq $Value -or $Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { throw 'Native integer evidence is absent or inexact.' }
    return [UInt64]::Parse([Convert]::ToString($Value,[Globalization.CultureInfo]::InvariantCulture),[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture)
}
function Assert-CopyStamp($Actual,$Expected,[UInt64]$Bytes,[string]$Owner) {
    if ($Actual.owner -ne $Owner -or (Read-ExactU64 $Actual.device) -ne (Read-ExactU64 $Expected.device) -or
        (Read-ExactU64 $Actual.nativeObject) -ne (Read-ExactU64 $Expected.object) -or (Read-ExactU64 $Actual.fileBytes) -ne $Bytes) { throw 'Copied proof native identity, owner or size differs.' }
    if ($Expected.PSObject.Properties['fileBytes']) {
        if ((Read-ExactU64 $Expected.fileBytes) -ne $Bytes) { throw 'Copied proof declared size differs.' }
    } elseif ($Bytes -ne 0) { throw 'Nonempty copied proof omits its declared size.' }
}
function Copy-StandardHandoff($Manifest) {
    if (-not $allJobsEmpty -or -not $Manifest.leasedWritersClosed -or -not $Manifest.originalPreserved -or -not $Manifest.copyBeforeControllerExit -or
        $Manifest.copyDirectory -ne 'D06-handoff' -or ($Manifest.closedActors.action -join ',') -ne 'busy,retain,read,uncertain') { throw 'Standard-user handoff closure evidence is incomplete.' }
    foreach ($actor in $Manifest.closedActors) {
        $observation=Read-OwnedJSON (Join-Path $evidence ($actor.action+'-process.json'))
        if (-not $observation.exited -or $observation.pid -ne $actor.pid -or $observation.stdoutTruncated -or $observation.stderrTruncated) { throw 'The fixed writer process did not finish before handoff.' }
    }
    $names=@($Manifest.files.PSObject.Properties.Name)
    $locks=@($names | Where-Object {$_ -match '^locks/[a-f0-9]{64}\.lock$'})
    if ($names.Count -ne 4 -or $locks.Count -ne 1) { throw 'The synthetic handoff roster differs.' }
    $stem=$locks[0].Substring(6,64)
    $expected=@('root.lock','store.json.d06-witness',"locks/$stem.lock","v1/$stem.json")
    if (@(Compare-Object ($names | Sort-Object) ($expected | Sort-Object)).Count -ne 0) { throw 'The synthetic handoff contains an unexpected object.' }
    # Reserve the full bounded critical copy before any artifact write, including failure paths.
    $script:artifactBytes=17825792; $script:artifactEntries=8
    $destination=Join-Path $artifact 'D06-handoff'
    [IdentityStoreFixture]::CreateQualificationDirectory($destination,$launcherSID,'')
    foreach ($childName in @('locks','v1')) { [IdentityStoreFixture]::CreateQualificationDirectory((Join-Path $destination $childName),$launcherSID,'') }
    $rows=[Collections.Generic.List[object]]::new(); [UInt64]$total=0
    foreach ($name in $expected) {
        $entry=$Manifest.files.PSObject.Properties[$name].Value
        $bytes=Read-ExactU64 $entry.bytes; $total+=$bytes
        if ($bytes -gt 2097152 -or $total -gt 16777216 -or $entry.source.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $entry.copy.sha256 -cne $entry.source.sha256) { throw 'The synthetic handoff byte/hash bound differs.' }
        if ($entry.source.PSObject.Properties['fileBytes']) {
            if ((Read-ExactU64 $entry.source.fileBytes) -ne $bytes) { throw 'Original source metadata size differs from the copied bytes.' }
        } elseif ($bytes -ne 0) { throw 'Nonempty original source metadata omits its size.' }
        $source=Join-Path (Join-Path $evidence 'D06-handoff') $name
        $target=Join-Path $destination $name
        $before=[IdentityStoreFixture]::InspectQualificationFile($source)
        Assert-CopyStamp $before $entry.copy $bytes $sid
        if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.source.sha256) { throw 'The standard-user handoff hash differs.' }
        [IO.File]::Copy($source,$target,$false)
        $after=[IdentityStoreFixture]::InspectQualificationFile($source)
        Assert-CopyStamp $after $entry.copy $bytes $sid
        $copy=[IdentityStoreFixture]::InspectQualificationFile($target)
        if ($copy.owner -ne $launcherSID -or (Read-ExactU64 $copy.fileBytes) -ne $bytes -or
            (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.source.sha256) { throw 'The preserved artifact handoff differs.' }
        $rows.Add(@{path=$name;original=$entry.source;standardCopy=$entry.copy;artifact=$copy;sha256=$entry.source.sha256})
    }
    if ($total -ne (Read-ExactU64 $Manifest.bytes)) { throw 'The complete synthetic byte total differs.' }
    $sourceManifest=Join-Path $evidence 'D06-handoff.json'; $targetManifest=Join-Path $artifact 'D06-handoff.json'
    $manifestBefore=[IdentityStoreFixture]::InspectQualificationFile($sourceManifest)
    if ($manifestBefore.owner -ne $sid -or $manifestBefore.fileBytes -gt 1048576) { throw 'The handoff manifest owner or size differs.' }
    [IO.File]::Copy($sourceManifest,$targetManifest,$false)
    $manifestAfter=[IdentityStoreFixture]::InspectQualificationFile($sourceManifest)
    if ($manifestBefore.nativeObject -ne $manifestAfter.nativeObject -or $manifestBefore.device -ne $manifestAfter.device -or
        $manifestBefore.fileBytes -ne $manifestAfter.fileBytes -or (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $targetManifest -Algorithm SHA256).Hash) { throw 'The handoff manifest copy differs.' }
    Save-Proof 'D06-copy-verification.json' @{originalPath=$Manifest.originalPath;files=$rows;allJobsEmpty=$true;privilegedOriginalReads=$false}
    $script:artifactBytes=[long]$total+[long]$manifestAfter.fileBytes
    $script:artifactEntries=8
}
function Copy-BoundedTree([string]$Source,[string]$Destination,[long]$MaximumBytes,[int]$MaximumEntries,[string[]]$Exclude=@()) {
    [IdentityStoreFixture]::CreateQualificationDirectory($Destination,$launcherSID,'')
    $pending=[Collections.Generic.Stack[string]]::new(); $pending.Push($Source)
    [long]$bytes=0; [int]$count=0; $manifest=[Collections.Generic.List[object]]::new()
    while ($pending.Count -gt 0) {
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
            $relative=[IO.Path]::GetRelativePath($Source,$path)
            if ($Exclude -contains $relative) { continue }
            if ($timer.Elapsed.TotalSeconds -ge 510 -or ++$count -gt $MaximumEntries) { throw 'Bounded evidence traversal expired.' }
            $attributes=[IO.File]::GetAttributes($path)
            if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Evidence contains a reparse point.' }
            $target=Join-Path $Destination $relative
            if ($attributes -band [IO.FileAttributes]::Directory) {
                [IdentityStoreFixture]::CreateQualificationDirectory($target,$launcherSID,''); $pending.Push($path); continue
            }
            $size=[IO.FileInfo]::new($path).Length; $bytes+=$size
            if ($size -gt 16777216 -or $bytes -gt $MaximumBytes) { throw 'Bounded evidence byte limit reached.' }
            [IO.File]::Copy($path,$target,$false)
            $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            if ($hash -ne (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) { throw 'Evidence copy differs from its source.' }
            $manifest.Add(@{path=$relative;bytes=$size;sha256=$hash})
        }
    }
    return @{files=$manifest;bytes=$bytes;entries=$count}
}
try {
    foreach ($name in @('Get-LocalUser','New-LocalUser','Remove-LocalUser','Get-LocalGroup','Add-LocalGroupMember','Get-LocalGroupMember','Get-CimInstance')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "Missing account/profile prerequisite: $name" }
    }
    if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) { throw 'The new fixture account name already exists.' }
    $random=[Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $passwordPlain='aA1!'+[Convert]::ToBase64String($random)
    [Array]::Clear($random,0,$random.Length)
    $secure=ConvertTo-SecureString $passwordPlain -AsPlainText -Force
    $accountCreationAttempted=$true
    $user=New-LocalUser -Name $userName -Password $secure -AccountNeverExpires -PasswordNeverExpires
    $sid=$user.SID.Value;$created=$true
    Save-Proof 'account-created.json' @{name=$userName;sid=$sid;created=$true;existingAccountReset=$false}
    if (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'") { throw 'The new fixture identity already has a profile.' }
    $users=Get-LocalGroup -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'))
    if (-not @(Get-LocalGroupMember -Group $users | Where-Object {$_.SID.Value -eq $sid}).Count) { Add-LocalGroupMember -Group $users -Member $user }
    $admins=Get-LocalGroup -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    if (@(Get-LocalGroupMember -Group $admins | Where-Object {$_.SID.Value -eq $sid}).Count) { throw 'The fixture account has administrator membership.' }
    [IdentityStoreFixture]::CreateQualificationDirectory($workspace,$launcherSID,$sid)
    $evidence=Join-Path $workspace "ca8-default-proof-$nonce"
    [IdentityStoreFixture]::CreateQualificationDirectory($evidence,$launcherSID,$sid)
    foreach ($name in @('cache','temporary')) { [IdentityStoreFixture]::CreateQualificationDirectory((Join-Path $workspace $name),$launcherSID,$sid) }
    $buildEnvironment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('PATH','SystemRoot','WINDIR','USERPROFILE','APPDATA','LOCALAPPDATA','HOME','LANG','TZ')) {
        $value=[Environment]::GetEnvironmentVariable($name);if ($null -ne $value) {$buildEnvironment[$name]=$value}
    }
    foreach ($entry in @{GOTOOLCHAIN='local';GOENV='off';GOWORK='off';CGO_ENABLED='0';GOPRIVATE='';GONOPROXY='';GONOSUMDB='';GOVCS='off';GOPROXY='https://proxy.golang.org';GOSUMDB='sum.golang.org';OE_OPERATION_ID='';GIT_CONFIG_COUNT='1';GIT_CONFIG_KEY_0='safe.directory';GIT_CONFIG_VALUE_0=$root}.GetEnumerator()) {$buildEnvironment[$entry.Key]=$entry.Value}
    foreach ($entry in @{GOPATH='cache\go';GOMODCACHE='cache\modules';GOCACHE='cache\build';GOTMPDIR='temporary';TMP='temporary';TEMP='temporary'}.GetEnumerator()) {$buildEnvironment[$entry.Key]=Join-Path $workspace $entry.Value}
    $go=Tool 'go.exe';$pwsh=Join-Path $PSHOME 'pwsh.exe';$git=Tool 'git.exe'
    Save-Proof 'native-launcher.json' @{path=$pwsh;sha256=(Get-FileHash -LiteralPath $pwsh -Algorithm SHA256).Hash;architecture=$architecture}
    $goHost=(Run-Stage $go @('env','-json','GOHOSTOS','GOHOSTARCH','GOVERSION')) | ConvertFrom-Json
    if ($goHost.GOHOSTOS -ne 'windows' -or $goHost.GOHOSTARCH -ne $architecture -or $goHost.GOVERSION -ne 'go1.27.3') {throw 'The Go host differs from the native target.'}
    $modules=@{};foreach ($name in @('go.mod','go.sum')) {$modules[$name]=(Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash}
    Run-Stage $go @('mod','download','-json') 120 | Out-Null
    $buildEnvironment['GOPROXY']='off';$buildEnvironment['GOSUMDB']='off';$buildEnvironment['GOFLAGS']='-mod=readonly'
    $binary=Join-Path $workspace 'probe.exe'
    Run-Stage $go @('test','-c','-tags','identity_default_qualification','-o',$binary,'./internal/identityattempt') 120 | Out-Null
    $inputs=@{};$tracked=(Run-Stage $git @('ls-files','-z')).Split([char]0)
    foreach ($name in $tracked) {if ($name) {$inputs[$name]=(Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash}}
    Save-Proof 'source-inputs.json' @{head=(Run-Stage $git @('rev-parse','HEAD')).Trim();files=$inputs;go=$goHost;architecture=$architecture}
    @{nonce=$nonce;identity=$sid;os='windows';architecture=$architecture;binarySHA256=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant();githubHosted=$true} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'disposable.json') -Encoding utf8
    Copy-Item -LiteralPath $module -Destination (Join-Path $workspace 'native.cs')
    $child=Join-Path $workspace 'standard.ps1'
    @'
param([string]$Binary,[string]$Proof,[string]$Nonce)
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'native.cs')
$environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {$environment[$entry.Key]=$entry.Value}
$probeArguments=@('-test.run=^TestIdentityDefaultQualification$','-test.timeout=120s','-test.v',"-identity-default-proof=$Proof","-identity-default-nonce=$Nonce")
$result=[IdentityStoreFixture]::RunBounded($Binary,$probeArguments,$PSScriptRoot,$environment,(Join-Path $Proof 'controller'),125000,16777216)
$result | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $Proof 'controller-process.json') -Encoding utf8
if ($result.status -ne 0 -or -not $result.jobEmpty -or $result.errors.Count -ne 0) {exit 1}
'@ | Set-Content -LiteralPath $child -Encoding utf8
    $broker=Join-Path $workspace 'broker.ps1'
    @'
param([string]$User,[string]$SID,[string]$Pipe,[string]$Pwsh,[string]$Binary,[string]$Proof,[string]$Nonce)
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'native.cs')
$password=[IdentityStoreFixture]::ReadBrokerPassword($Pipe)
try {
    $standardArguments=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'standard.ps1'),$Binary,$Proof,$Nonce)
    $result=[IdentityStoreFixture]::RunInOwnedDesktop($User,$SID,$password,$Pwsh,$standardArguments,$PSScriptRoot,$Nonce)
    $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $Proof 'broker-process.json') -Encoding utf8
    if ($result.errors.Count -ne 0 -or -not $result.restored -or -not $result.stationAbsent -or -not $result.child -or
        $result.child.status -ne 0 -or -not $result.child.jobEmpty -or $result.child.errors.Count -ne 0) {exit 1}
} finally {$password=$null}
'@ | Set-Content -LiteralPath $broker -Encoding utf8
    $pipe='ca8-default-secret-'+$nonce
    $brokerArgs=@('-NoLogo','-NoProfile','-NonInteractive','-File',$broker,$userName,$sid,$pipe,$pwsh,$binary,$evidence,$nonce)
    $brokerStarted=$true
    $runResult=[IdentityStoreFixture]::RunBroker($pwsh,$brokerArgs,$workspace,$buildEnvironment,(Join-Path $proof 'broker'),$pipe,$passwordPlain)
    Save-Proof 'broker-supervision.json' $runResult
    $allJobsEmpty=Observe-OwnedClosure
    if (-not $allJobsEmpty -or $runResult.process.status -ne 0 -or $timer.Elapsed.TotalSeconds -ge 500) { throw 'The isolated process graph did not close within its logical bound.' }
    $profiles=@(Get-CimInstance Win32_UserProfile -Filter "SID='$sid'")
    if ($profiles.Count -ne 1 -or $profiles[0].Special) { throw 'The one newly loaded fixture profile is unavailable.' }
    $profileRecord=$profiles[0]
    Save-Proof 'profile.json' @{sid=$sid;path=$profileRecord.LocalPath;loaded=$profileRecord.Loaded;newlyCreated=$true}
    $completed=Read-OwnedJSON (Join-Path $evidence 'D-result.json')
    if (-not $completed.success -or ($completed.cases -join ',') -ne 'D01,D02,D03,D04,D05,D06' -or $completed.identity.identity -ne $sid) { throw 'All six actual standard-user cases are required.' }
    $handoff=Read-OwnedJSON (Join-Path $evidence 'D06-handoff.json')
    $original=[IO.Path]::GetFullPath($handoff.originalPath)
    if (-not $original.StartsWith($profileRecord.LocalPath+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'The original namespace lies outside the newly created profile.' }
    Copy-StandardHandoff $handoff
    $copied=$true
    foreach ($name in $modules.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash -ne $modules[$name]) { throw 'A frozen module owner changed.' }
    }
    $success=$true
} catch { $failure=$_.Exception.ToString() }
finally {
    $passwordPlain=$null
    try { if ($null -ne $secure) { $secure.Dispose() } }
    catch { $success=$false; $failure+="`nSecret buffer cleanup: $_" }
    $secure=$null
    try { $allJobsEmpty=Observe-OwnedClosure }
    catch { $allJobsEmpty=$false; $success=$false; $failure+="`nClosure: $_" }
    try {
        if (-not $allJobsEmpty) { throw 'Do not traverse source proof while any process or handle closure is uncertain.' }
        if ($evidence -and [IO.Directory]::Exists($evidence)) {
            $exclude=if($copied){@('D06-handoff','D06-handoff.json')}else{@()}
            $copy=Copy-BoundedTree $evidence (Join-Path $artifact 'controller-evidence') (133169152-$artifactBytes) (158-$artifactEntries) $exclude
            $artifactEntries++
            $artifactBytes+=$copy.bytes; $artifactEntries+=$copy.entries
        }
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($proof)) {
            if ($path -eq $artifact) { continue }
            $item=Get-Item -LiteralPath $path
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'The fixed admin proof roster contains an unexpected directory or reparse point.' }
            $artifactBytes+=$item.Length; $artifactEntries++
            if ($item.Length -gt 16777216 -or $artifactBytes -gt 133169152 -or $artifactEntries -gt 159) { throw 'The proof payload exceeds127MiB or160entries.' }
            $target=Join-Path $artifact $item.Name
            [IO.File]::Copy($path,$target,$false)
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) { throw 'Admin proof copy differs.' }
        }
        $collectionComplete=$true
    } catch { $success=$false; $failure+="`nCollection: $_" }
    try {
        if ($accountCreationAttempted -and -not $created) { throw 'The account creation outcome is uncertain. Preserve the disposable VM.' }
        if ($created) {
            if (-not $allJobsEmpty -or -not $collectionComplete) { throw 'Closure or bounded artifact preservation is uncertain. Preserve the new profile/account.' }
            $current=Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
            if (-not $current -or $current.SID.Value -ne $sid) { throw 'Fixture account association changed. Preserve the VM.' }
            $observed=@(Get-CimInstance Win32_UserProfile -Filter "SID='$sid'")
            if ($observed.Count -gt 1) { throw 'The new SID has ambiguous profile metadata.' }
            if ($observed.Count -eq 1) {
                $currentProfile=$observed[0]
                if (-not $copied -or -not $profileRecord -or $currentProfile.LocalPath -cne $profileRecord.LocalPath -or $currentProfile.Special) { throw 'Exact synthetic evidence or new-profile association is uncertain.' }
                $until=[Diagnostics.Stopwatch]::StartNew()
                while ($currentProfile.Loaded -and $until.Elapsed.TotalSeconds -lt 5) {
                    Start-Sleep -Milliseconds 50
                    $observed=@(Get-CimInstance Win32_UserProfile -Filter "SID='$sid'")
                    if ($observed.Count -ne 1 -or $observed[0].LocalPath -cne $profileRecord.LocalPath) { throw 'Profile association changed while waiting for unload.' }
                    $currentProfile=$observed[0]
                }
                if ($currentProfile.Loaded) { throw 'The new fixture profile is still loaded.' }
                $cleanup=[Diagnostics.Stopwatch]::StartNew()
                [IdentityStoreFixture]::DeleteOwnedProfile($sid,$currentProfile.LocalPath)
                if ($cleanup.Elapsed.TotalSeconds -gt 60 -or @(Get-CimInstance Win32_UserProfile -Filter "SID='$sid'").Count -ne 0) { throw 'Fixture profile deletion was not verified.' }
                $profileDeleted=$true
            } elseif ($brokerStarted) { throw 'The launched profile outcome is not authoritative. Preserve the new account.' }
            $current=Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
            if (-not $current -or $current.SID.Value -ne $sid) { throw 'New account association changed before deletion.' }
            Remove-LocalUser -Name $userName
            if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) { throw 'The new fixture account remains.' }
            $accountDeleted=$true
        }
    } catch { $success=$false; $failure+="`nCleanup: $_" }
    $terminal=@{success=$success;failure=$failure;elapsedSeconds=$timer.Elapsed.TotalSeconds;allJobsEmpty=$allJobsEmpty;
        syntheticArtifactPreserved=$copied;collectionComplete=$collectionComplete;artifactUsageExact=$collectionComplete;artifactBytes=$artifactBytes;artifactEntries=$artifactEntries;
        newAccount=$userName;newSID=$sid;originalProfilePath=if($profileRecord){$profileRecord.LocalPath}else{$null};
        profileDeleted=$profileDeleted;accountDeleted=$accountDeleted;
        scope='D01-D06 only. No provider, hosted Relay, public CLI or historical-client acceptance.'}
    $terminalText=$terminal | ConvertTo-Json -Depth 12
    if ([Text.Encoding]::UTF8.GetByteCount($terminalText) -gt 1048576) { throw 'The reserved terminal evidence bound was reached.' }
    [IO.File]::WriteAllText((Join-Path $artifact 'result.json'),$terminalText,[Text.UTF8Encoding]::new($false))
}
if (-not $success) { throw 'Default-location qualification failed. Preserve the bounded artifact and any retained new profile/account.' }
