# Identity attempt store native qualification

These entry points require disposable GitHub-hosted virtual machines.
They provision fresh fixture volumes for the identity attempt store tests.
Their source does not establish a passing native qualification.
Each result requires its actual source hashes, raw test events and cleanup evidence.

## Required environment

The workflow requires Go 1.27.3 and Node.js 24.22.1.
The minimum Go job requires Go 1.26.10 instead.
The manual cleanup diagnostic requires neither Go nor Node.

The scripts require `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`.
They refuse a target that differs from the actual operating system or architecture.
They give emulated processes no native qualification.
Missing privileges, tools, native APIs or storage prerequisites fail the job.
The scripts do not install missing system tools.

Unix requires an ordinary runner account with passwordless `sudo`.
The elevated fixture process requires UID 0 and the original different, existing UID.
Linux requires Python 3, ext4 tooling, loop devices, mount and findmnt.
Darwin requires Python 3, hdiutil, diskutil and the native Apple security APIs.
The race profile requires an installed native C compiler.

Windows requires native 64-bit PowerShell and an enabled administrator token.
It requires DiskPart and the Storage module disk-image commands.
The fixture checks its actual SID, groups and enabled privileges.

It enables `SeRestorePrivilege` and `SeCreateSymbolicLinkPrivilege` for its owned fixtures.
It restores their original attributes during cleanup.
The race profile requires an installed amd64 GCC runtime with `libsynchronization.a`.
Windows arm64 has no race profile.

## Job profiles

The full race jobs retain `go test -count=1 -json -race -timeout=9m ./...`.
They call the wrapper before the existing vet, build and native npm gates.
The minimum Go job retains the full suite and adds six CGO0 cross-builds.
The native job runs the complete `./internal/identityattempt` package with CGO disabled.
Complete execution retains every declared case.

Unix race preparation uses `-run=^$` before the unchanged full execution command.
It runs package initialization and `TestMain`, but no named tests or fuzz seeds.
The app hook changes only its child environment and browser function.
Preparation gives no test coverage or native fixture qualification.

Intel native execution uses three fixed partitions of the maintained complete roster.
The other package, configuration, formatting and Homebrew gates remain present.

| Profile            | Entry point arguments                                           | Scope                                      |
| ------------------ | --------------------------------------------------------------- | ------------------------------------------ |
| Unix race          | `race linux amd64` or `race darwin arm64`                       | Full race suite                            |
| Windows race       | `-FixtureProfile race -ExpectedArchitecture amd64`              | Full race suite                            |
| Minimum Go         | `minimum linux amd64`                                           | Full suite and six CGO0 builds             |
| Unix native        | `native <linux-or-darwin> <amd64-or-arm64>`                     | Native store package                       |
| Windows native     | `-FixtureProfile native -ExpectedArchitecture <amd64-or-arm64>` | Native store package                       |
| Cleanup diagnostic | `cleanup-diagnostic darwin amd64`                               | Owned image cleanup only, `NO_TEST_CREDIT` |

| Runner label       | Native target |
| ------------------ | ------------- |
| `ubuntu-24.04`     | linux/amd64   |
| `ubuntu-24.04-arm` | linux/arm64   |
| `macos-26`         | darwin/arm64  |
| `macos-26-intel`   | darwin/amd64  |
| `windows-2025`     | windows/amd64 |
| `windows-11-arm`   | windows/arm64 |

GitHub lists these labels and architectures in its [hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
A label does not prove an individual job's prerequisites or actual architecture.
Each wrapper checks the actual process and Go host before test dispatch.
Cross-build results do not replace native execution.

The manual `Owned volume cleanup diagnostic` workflow runs only on Darwin Intel.
It reuses the fresh elevated hosted-VM, 4 GiB APFS image and exact device checks.
It records source hashes and index ownership without invoking Go, Node, downloads or test partitions.
Its result explicitly reports `NO_TEST_CREDIT`.
A passing focused episode does not turn a failed native job green.

## Protected fixture namespace

Unix creates one new 4 GiB ext4 or APFS image.
Linux mounts its owned loop device at `/ca8-store-run-<nonce>` with `nodev,nosuid`.
Darwin mounts its owned APFS image at `/Volumes/ca8-store-run-<nonce>` with ownership enabled.
Windows creates one new maximum-4-GiB VHDX and formats only that image as NTFS.
It selects an unused drive letter from T through Z.
It verifies the image, disk, partition, drive and filesystem association.

The scripts create new fixture, evidence, temporary and cache directories on that volume.
The fixture basename starts with `ca8-store-fixtures-`.
The evidence basename starts with `ca8-store-evidence-`.
Tests receive `OE_IDENTITY_STORE_FIXTURE_ROOT` and `OE_IDENTITY_STORE_EVIDENCE_ROOT` with those exact paths.
The scripts set `OE_IDENTITY_STORE_PRIVILEGED_FIXTURES=1`.
Unix also supplies the actual different UID as `OE_IDENTITY_STORE_FOREIGN_UID`.

The tests use internal explicit `Location` values.
They do not initialize the production default state root.

Unix checks actual directory descriptors, UID, mode, ACL bytes and ancestor associations.
It requires root-owned ancestors without group or other mutation modes.
The new final roots require mode 0700.
Darwin reads ACLs through the native Apple APIs.
Linux records the actual POSIX ACL bytes when present.

Windows checks actual directory handles, file identities, owner SID and DACL.
It rejects reparse points and unexpected filesystem types.
New fixture parents have a protected DACL with current-caller and SYSTEM full-access entries.
Their inheritance applies only within the new owned namespace.
Existing runner or user directories receive no ACL repair.
Negative fixtures can alter only their own new objects.

The child environment omits hosted credentials and provider settings.
The wrappers preserve an inherited `HOME` value without replacement.
They select explicit Go caches, module caches, temporary paths and Node compile caches.
Windows preserves its actual profile and known-folder inputs.
No test receives a fabricated profile as the production default-root identity.
The temporary ancestor chain must contain no `node_modules` directory.

## Bounds and evidence

Unix race, minimum, other native targets and Windows keep an 800-second logical outer deadline.
Darwin Intel native keeps its 2,400-second owner deadline and 45-minute workflow job.
Test processes have a 600-second bound and Go's nine-minute test timeout.
Module preparation has a 120-second bound.

Unix race preparation has a 120-second maximum before the full execution command.
Its deadline preserves the existing 630-second execution and cleanup reserve.
The owned fixture and native evidence directories must remain empty afterward.
An insufficient remaining reserve refuses execution without increasing the owner deadline.

Darwin Intel cold preparation keeps its 480-second maximum.
Its three 600-second partitions reserve 70 seconds for cleanup, for a 1,870-second execution reserve.
Each other workflow job keeps its 20-minute bound.
Artifact upload has a two-minute bound and seven-day retention.
Cold-cache sufficiency remains unverified until a run completes.

Each stage records its executable hash, argv, raw stdout, raw stderr and exit status.
Each stream has a 64 MiB limit.
Each stage also has a combined 128 MiB retained-output limit.
Observed byte counts remain separate from retained byte counts after an output refusal.
Each wrapper permits at most 24 child stages.
Raw child output therefore has a 3 GiB total bound.

The owned volume has a 128 MiB free-space floor during child waits.
Public module preparation uses the new owned module cache.
The scripts check both module files after preparation and after tests.
Later Go commands use an offline, read-only module graph.

Unix creates a fresh POSIX session for each child stage.
Native SID observations include owned children that use separate process groups.
Cleanup requires two complete empty session observations and checked observer closure.
The owner uses one five-second settlement deadline for session cleanup, leader wait and remaining pipe drain.

Each receipt records actual leader wait, stdout EOF and stderr EOF separately from session emptiness.

The existing progress callback also records one checkpoint before settlement signals.
That checkpoint stays inside the same five-second settlement deadline.
Intel detach samples record actual mount state.
The pre-signal checkpoint records the leader's current status.
They do not query image metadata or launch another child while the utility is live.

An incomplete drain retains an explicit failure and never substitutes descriptor closure for EOF.
Later cleanup errors do not replace the original stage failure.
Fixture traversal requires session emptiness, actual leader wait and both EOFs.

Windows creates each child suspended and assigns it to a kill-on-close Job Object before resumption.
Cleanup terminates owned descendants and checks for zero remaining processes.
An uncertain process state prevents fixture traversal and successful cleanup claims.
A blocked kernel call can exceed a logical deadline.
The scripts make no hard kernel deadline guarantee.

A failure stops later test stages.
Raw logs, partial measurements and the owned volume remain on the disposable runner.
After zero-process confirmation, failure snapshots copy bounded regular fixture files.
Windows omits reparse points from its bounded snapshot.
Snapshots have a 128 MiB byte limit.
Windows also has a 10,000-entry limit.

The workflow uploads proof files and excludes backing volume images.
An uncertain volume readback remains an explicit failure.

A successful run detaches only its recorded owned volume.
Darwin Intel permits one ordinary detach with a 60-second allowance.
Other targets keep their existing 20-second allowance.

Detach uses an explicit environment and working directory outside the mounted volume.
No force flag or retry follows a refusal.
The 60-second allowance is an operational limit, not a measured latency guarantee or proven cure.
The 70-second cleanup reserve is nominal and does not bound blocked kernel calls.

The wrapper records a fresh mount observation after every detach outcome.
Intel detach requests the utility's documented verbose progress output.
It records backing-image preservation separately from the observed mount state.
Only exit zero, complete process and pipe closure, and an absent mount permit backing deletion.
A failed attempt retains its backing image even if the mount proves absent.

The wrapper deletes only its new backing image and mount directory.
Native evidence and cleanup records remain in the uploaded artifact.
The scripts never detach an unrelated disk or repair a user directory.

The cleanup-only profile can query `hdiutil info -plist` once after complete utility closure.
It requires a free stage slot and 35 seconds remaining in the unchanged absolute owner deadline.
The query uses the existing 30-second metadata limit and reserves five seconds for settlement.
Its execution deadline cannot exceed the owner deadline minus those five seconds.
This optional admission does not increase the 70-second nominal native cleanup reserve.
The existing stage, output and 4 MiB stdout-capture caps still apply.

The receipt binds only the exact new image path and recorded device.
Missing, malformed, unadmitted or ambiguous metadata stays `UNKNOWN`.
A report that the exact image remains attached prevents its backing deletion.
Other image-info outcomes do not replace the ordinary detach exit and closure requirements.
Post-termination metadata cannot prove earlier attachment state or identify an earlier volume user.
No concurrent observer, recursive live-utility execution or volume-user census runs.

If process or pipe closure is uncertain, the wrapper persists its result before refusing proof traversal.
It does not walk the proof tree to transfer ownership in that state.
Root-owned evidence may then remain inaccessible to the unprivileged artifact uploader.
Its later hosted custody remains unverified.

## Evidence limits

All 85 original declarations and their later additive tests remain source requirements.
The 145 policy cases, 295 interruption rows and 99 controlled rows retain their separate mappings.
Join a green package result to matching source and raw events.
It does not prove that every abstract row ran as a separate native event.

These privileged fixtures do not qualify an ordinary user's default-root behavior.
Native ENOSPC, actual public commands and hosted callers remain separate acceptance gates.
The Windows known-folder boundary still requires its own actual-caller evidence.
All-witness loss can remain undetectable.
A valid stale backup does not prove freshness.
A stalled kernel operation does not provide a bounded return.

## Darwin distribution notices

Darwin archives and Darwin npm package `bin` directories contain `THIRD_PARTY_NOTICES.txt`.
Its source is `licenses/purego-v0.11.1.txt`.
The exact 13,211-byte payload includes the purego Apache-2.0 and retained Go BSD licenses.
Its SHA-256 is `293dc5471fc6bf3e3002e6115e3b9fbea1c2817b7878ab8d8e3dffedbd7bfd04`.
The release test compares both Darwin archives and both Darwin npm packages with those exact bytes.

Linux and Windows archive contents retain only their native executable.
The test inspects foreign archives without executing their binaries.
