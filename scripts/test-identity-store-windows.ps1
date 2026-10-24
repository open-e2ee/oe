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
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
public static class IdentityStoreFixture {
    [StructLayout(LayoutKind.Sequential)] struct SA { public int length; public IntPtr descriptor; public int inherit; }
    [StructLayout(LayoutKind.Sequential)] struct FILEINFO {
        public uint attributes; public System.Runtime.InteropServices.ComTypes.FILETIME created,accessed,written;
        public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [StructLayout(LayoutKind.Sequential)] struct SI {
        public int cb; public IntPtr reserved,desktop,title;
        public uint x,y,xSize,ySize,xChars,yChars,fill,flags;
        public ushort show,reservedBytes; public IntPtr reservedData,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct SIX { public SI startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr process,thread; public uint pid,tid; }
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint low; public int high; }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr value);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out LUID luid);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,IntPtr state,int size,IntPtr previous,out int returned);
    [DllImport("advapi32.dll")] static extern bool IsValidSid(IntPtr sid);
    [DllImport("advapi32.dll")] static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int size,out int returned);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out FILEINFO info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr file);
    [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(IntPtr file,int kind,uint requested,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll",SetLastError=true)] static extern uint SetSecurityInfo(IntPtr file,int kind,uint requested,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorOwner(IntPtr descriptor,out IntPtr owner,out bool defaulted);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeInformationW(string root,StringBuilder label,uint labelSize,out uint serial,out uint maximum,out uint flags,StringBuilder filesystem,uint filesystemSize);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SA security,int size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string cwd,ref SIX startup,out PI process);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr security,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,IntPtr information,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr information,uint size,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint status);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint status);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(IntPtr file,byte[] buffer,uint length,out uint read,IntPtr overlapped);
    static readonly Dictionary<string,uint> originalPrivileges = new Dictionary<string,uint>();
    static Exception Error(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(),operation); }
    static void Close(IntPtr handle) { if(handle!=IntPtr.Zero && handle!=new IntPtr(-1) && !CloseHandle(handle)) throw Error("checked CloseHandle"); }
    static void Free(IntPtr pointer) { if(pointer!=IntPtr.Zero && LocalFree(pointer)!=IntPtr.Zero) throw Error("checked LocalFree"); }
    static void ReleaseNativeResources(Exception primary,params Action[] releases) {
        var errors=new List<Exception>();
        foreach(Action release in releases)try{release();}catch(Exception error){errors.Add(error);}
        if(errors.Count!=0) {
            if(primary!=null)errors.Insert(0,primary);
            throw new AggregateException(errors);
        }
    }
    static byte[] TokenData(IntPtr token,int kind) {
        int length; GetTokenInformation(token,kind,IntPtr.Zero,0,out length);
        if(length<=0 || length>1048576) throw Error("token length");
        IntPtr memory=Marshal.AllocHGlobal(length);
        try {
            if(!GetTokenInformation(token,kind,memory,length,out length)) throw Error("token read");
            byte[] bytes=new byte[length]; Marshal.Copy(memory,bytes,0,length); return bytes;
        } finally { Marshal.FreeHGlobal(memory); }
    }
    static uint PrivilegeAttributes(IntPtr token,LUID id) {
        byte[] bytes=TokenData(token,3);
        if(bytes.Length<4) throw new Exception("invalid privilege response");
        uint count=BitConverter.ToUInt32(bytes,0);
        if(count>1024 || 4L+12L*count!=bytes.Length) throw new Exception("invalid privilege span");
        for(int i=0;i<count;i++) {
            int offset=4+12*i;
            if(BitConverter.ToUInt32(bytes,offset)==id.low && BitConverter.ToInt32(bytes,offset+4)==id.high)
                return BitConverter.ToUInt32(bytes,offset+8);
        }
        throw new Exception("required privilege is absent");
    }
    static void SetPrivilege(IntPtr token,LUID id,uint attributes) {
        IntPtr memory=Marshal.AllocHGlobal(16);
        try {
            Marshal.WriteInt32(memory,1); Marshal.WriteInt32(memory,4,unchecked((int)id.low));
            Marshal.WriteInt32(memory,8,id.high); Marshal.WriteInt32(memory,12,unchecked((int)attributes));
            int returned;
            if(!AdjustTokenPrivileges(token,false,memory,0,IntPtr.Zero,out returned)) throw Error("AdjustTokenPrivileges");
            if(Marshal.GetLastWin32Error()!=0) throw Error("privilege assignment");
            if((PrivilegeAttributes(token,id)&2)!=(attributes&2)) throw new Exception("privilege enabled-state readback mismatch");
        } finally { Marshal.FreeHGlobal(memory); }
    }
    public static void EnableFixturePrivileges() {
        IntPtr token; if(!OpenProcessToken(GetCurrentProcess(),0x28,out token)) throw Error("OpenProcessToken");
        Exception failure=null;
        try {
            foreach(string name in new[]{"SeRestorePrivilege","SeCreateSymbolicLinkPrivilege"}) {
                LUID id; if(!LookupPrivilegeValue(null,name,out id)) throw Error("LookupPrivilegeValue");
                uint before=PrivilegeAttributes(token,id); originalPrivileges.Add(name,before);
                SetPrivilege(token,id,before|2);
            }
        } catch(Exception error){failure=error;throw;}
        finally { ReleaseNativeResources(failure,()=>Close(token)); }
    }
    public static void RestoreFixturePrivileges() {
        if(originalPrivileges.Count==0) return;
        IntPtr token; if(!OpenProcessToken(GetCurrentProcess(),0x28,out token)) throw Error("restore token");
        var errors=new List<Exception>();
        try {
            foreach(var entry in originalPrivileges) try {
                LUID id; if(!LookupPrivilegeValue(null,entry.Key,out id)) throw Error("restore privilege lookup");
                SetPrivilege(token,id,entry.Value);
            } catch(Exception error) { errors.Add(error); }
            originalPrivileges.Clear();
        } finally { try{Close(token);}catch(Exception error){errors.Add(error);} }
        if(errors.Count!=0) throw new AggregateException(errors);
    }
    public static object Caller() {
        IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),8,out token))throw Error("caller token");
        Exception failure=null;
        try {
            var groups=new List<object>();int size;
            GetTokenInformation(token,2,IntPtr.Zero,0,out size);
            if(size<8||size>1048576)throw new Exception("invalid native group length");
            IntPtr data=Marshal.AllocHGlobal(size);
            try {
                if(!GetTokenInformation(token,2,data,size,out size))throw Error("native groups");
                int count=Marshal.ReadInt32(data);
                if(count<0||8L+16L*count>size)throw new Exception("invalid native group span");
                for(int index=0;index<count;index++) {
                    IntPtr sidPointer=Marshal.ReadIntPtr(data,8+16*index);
                    long offset=sidPointer.ToInt64()-data.ToInt64();
                    if(offset<0||offset>size-8||!IsValidSid(sidPointer))throw new Exception("invalid native group SID");
                    uint length=GetLengthSid(sidPointer);
                    if(length<8||length>size-offset)throw new Exception("invalid native group SID span");
                    groups.Add(new { sid=new SecurityIdentifier(sidPointer).Value, attributes=unchecked((uint)Marshal.ReadInt32(data,16+16*index)) });
                }
            } finally { Marshal.FreeHGlobal(data); }
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                string sid=identity.User.Value;
                bool administrator=new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                if(sid=="S-1-5-18"||!administrator)throw new Exception("a non-SYSTEM administrator token is required");
                var privileges=new List<object>();
                foreach(string name in new[]{"SeRestorePrivilege","SeCreateSymbolicLinkPrivilege"}) {
                    LUID id;if(!LookupPrivilegeValue(null,name,out id))throw Error("privilege metadata lookup");
                    uint flags=PrivilegeAttributes(token,id);
                    if((flags&2)==0)throw new Exception("required native privilege is not enabled");
                    privileges.Add(new { name=name,attributes=flags });
                }
                return new { sid=sid,groups=groups.ToArray(),privileges=privileges.ToArray(),administrator=administrator,
                             impersonation=identity.ImpersonationLevel.ToString(),authentication=identity.AuthenticationType };
            }
        } catch(Exception error){failure=error;throw;}
        finally { ReleaseNativeResources(failure,()=>Close(token)); }
    }
    public static void InitializeNewDirectory(string path,string sid) {
        IntPtr descriptor=IntPtr.Zero,handle=new IntPtr(-1);
        Exception failure=null;
        try {
            uint size;
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:"+sid+"D:P(A;OICI;FA;;;"+sid+")(A;OICI;FA;;;SY)",1,out descriptor,out size)) throw Error("fixture descriptor");
            bool ignored,present; IntPtr owner,dacl;
            if(!GetSecurityDescriptorOwner(descriptor,out owner,out ignored) || !GetSecurityDescriptorDacl(descriptor,out present,out dacl,out ignored) || !present) throw Error("fixture descriptor fields");
            handle=CreateFileW(path,0x000e0000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(handle==new IntPtr(-1)) throw Error("new fixture directory handle");
            uint status=SetSecurityInfo(handle,1,0x80000005,owner,IntPtr.Zero,dacl,IntPtr.Zero);
            if(status!=0) throw new Win32Exception((int)status,"initial new-object security");
        } catch(Exception error){failure=error;throw;}
        finally { ReleaseNativeResources(failure,()=>Close(handle),()=>Free(descriptor)); }
    }
    public static object InspectDirectory(string path,string sid,bool protectedParent) {
        IntPtr handle=CreateFileW(path,0x00020000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(handle==new IntPtr(-1)) throw Error("fixture directory inspection");
        IntPtr descriptor=IntPtr.Zero;
        Exception failure=null;
        try {
            FILEINFO before,after;
            if(GetFileType(handle)!=1 || !GetFileInformationByHandle(handle,out before)) throw Error("native directory identity");
            if((before.attributes&0x410)!=0x10) throw new Exception("non-directory or reparse ancestor");
            IntPtr owner,group,dacl,sacl;
            uint status=GetSecurityInfo(handle,1,5,out owner,out group,out dacl,out sacl,out descriptor);
            if(status!=0) throw new Win32Exception((int)status,"native directory security");
            uint length=GetSecurityDescriptorLength(descriptor);
            if(length<20 || length>1048576) throw new Exception("invalid security descriptor length");
            byte[] bytes=new byte[length]; Marshal.Copy(descriptor,bytes,0,(int)length);
            var security=new RawSecurityDescriptor(bytes,0);
            var trusted=new[]{sid,"S-1-5-18","S-1-5-32-544"};
            if(!trusted.Contains(security.Owner.Value) || security.DiscretionaryAcl==null || !security.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent) || security.ControlFlags.HasFlag(ControlFlags.OwnerDefaulted) || security.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclDefaulted)) throw new Exception("unsafe owner or null DACL");
            if(protectedParent && (security.Owner.Value!=sid || !security.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) || security.DiscretionaryAcl.Count!=2)) throw new Exception("invalid protected fixture parent");
            var seen=new HashSet<string>();
            foreach(GenericAce generic in security.DiscretionaryAcl) {
                var ace=generic as CommonAce;
                if(ace==null || ace.IsCallback || ((int)ace.AceFlags&~0x1f)!=0) throw new Exception("unsupported native ACE");
                string principal=ace.SecurityIdentifier.Value;
                if(protectedParent && (ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AccessMask!=0x001f01ff || !new[]{sid,"S-1-5-18"}.Contains(principal) || !seen.Add(principal))) throw new Exception("invalid protected parent grant");
                if(ace.AceQualifier==AceQualifier.AccessAllowed && (ace.AccessMask&~0x001200a9)!=0 && !trusted.Contains(principal)) throw new Exception("untrusted ancestor mutation grant");
                if(ace.AceQualifier!=AceQualifier.AccessAllowed && ace.AceQualifier!=AceQualifier.AccessDenied) throw new Exception("unknown ACE kind");
            }
            if(!GetFileInformationByHandle(handle,out after) || before.volume!=after.volume || before.indexHigh!=after.indexHigh || before.indexLow!=after.indexLow || before.attributes!=after.attributes) throw new Exception("directory changed during native inspection");
            return new { path=path, owner=security.Owner.Value, descriptor=Convert.ToBase64String(bytes),
                         volume=before.volume, indexHigh=before.indexHigh,indexLow=before.indexLow,attributes=before.attributes };
        } catch(Exception error){failure=error;throw;}
        finally { ReleaseNativeResources(failure,()=>Free(descriptor),()=>Close(handle)); }
    }
    public static object Volume(string root) {
        var label=new StringBuilder(256);var filesystem=new StringBuilder(256);uint serial,maximum,flags;
        if(GetDriveTypeW(root)!=3 || !GetVolumeInformationW(root,label,256,out serial,out maximum,out flags,filesystem,256)) throw Error("native local volume");
        if(filesystem.ToString()!="NTFS") throw new Exception("the owned volume is not NTFS");
        return new { root=root,label=label.ToString(),filesystem=filesystem.ToString(),serial=serial,flags=flags };
    }
    static string Quote(string value) {
        if(value.IndexOf('\0')>=0) throw new Exception("NUL in process argument");
        var output=new StringBuilder("\"");int slashes=0;
        foreach(char character in value) {
            if(character=='\\'){slashes++;continue;}
            if(character=='\"') output.Append('\\',slashes*2+1);else output.Append('\\',slashes);
            slashes=0;output.Append(character);
        }
        output.Append('\\',slashes*2);output.Append('"');return output.ToString();
    }
    static long Pump(IntPtr handle,string path) {
        long total=0;byte[] buffer=new byte[65536];
        using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) {
            while(true) {
                uint count;
                if(!ReadFile(handle,buffer,(uint)buffer.Length,out count,IntPtr.Zero)) {
                    int code=Marshal.GetLastWin32Error();if(code==109)break;throw new Win32Exception(code,"native pipe read");
                }
                if(count==0)break;
                int retained=(int)Math.Min((long)count,Math.Max(0,67108864-total));
                if(retained>0)output.Write(buffer,0,retained);
                total+=count;
                if(total>67108864)throw new Exception("bounded native output exceeded");
            }
        }
        return total;
    }
    public static object Run(string executable,string[] argv,string cwd,IDictionary<string,string> environment,string prefix,int milliseconds) {
        if(milliseconds<=0) throw new Exception("outer fixture deadline expired");
        IntPtr job=IntPtr.Zero,outRead=IntPtr.Zero,outWrite=IntPtr.Zero,errRead=IntPtr.Zero,errWrite=IntPtr.Zero;
        IntPtr input=new IntPtr(-1),attributes=IntPtr.Zero,handles=IntPtr.Zero,block=IntPtr.Zero,limits=IntPtr.Zero;
        PI child=new PI();bool assigned=false,empty=false,attributesInitialized=false;uint status=0xffffffff;
        Task<long> stdout=null,stderr=null;var errors=new List<string>();
        try {
            job=CreateJobObjectW(IntPtr.Zero,null);if(job==IntPtr.Zero)throw Error("CreateJobObject");
            limits=Marshal.AllocHGlobal(144);Marshal.Copy(new byte[144],0,limits,144);Marshal.WriteInt32(limits,16,0x2000);
            if(!SetInformationJobObject(job,9,limits,144))throw Error("kill-on-close job limit");
            SA sa=new SA{length=Marshal.SizeOf<SA>(),inherit=1};
            if(!CreatePipe(out outRead,out outWrite,ref sa,0)||!CreatePipe(out errRead,out errWrite,ref sa,0))throw Error("owned process pipes");
            if(!SetHandleInformation(outRead,1,0)||!SetHandleInformation(errRead,1,0))throw Error("noninherited pipe readers");
            input=CreateFileW("NUL",0x80000000,3,IntPtr.Zero,3,0,IntPtr.Zero);
            if(input==new IntPtr(-1)||!SetHandleInformation(input,1,1))throw Error("owned null input");
            IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
            if(size.ToInt64()<=0||size.ToInt64()>65536)throw Error("process attribute length");
            attributes=Marshal.AllocHGlobal(size);if(!InitializeProcThreadAttributeList(attributes,1,0,ref size))throw Error("process attributes");
            attributesInitialized=true;
            handles=Marshal.AllocHGlobal(IntPtr.Size*3);Marshal.WriteIntPtr(handles,input);Marshal.WriteIntPtr(handles,IntPtr.Size,outWrite);Marshal.WriteIntPtr(handles,2*IntPtr.Size,errWrite);
            if(!UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20002),handles,new IntPtr(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero))throw Error("restricted inherited handles");
            var startup=new SIX{startup=new SI{cb=Marshal.SizeOf<SIX>(),flags=0x100,input=input,output=outWrite,error=errWrite},attributes=attributes};
            string values=String.Join("\0",environment.OrderBy(pair=>pair.Key,StringComparer.OrdinalIgnoreCase).Select(pair=>pair.Key+"="+pair.Value))+"\0\0";
            block=Marshal.StringToHGlobalUni(values);
            var command=new StringBuilder(String.Join(" ",new[]{executable}.Concat(argv).Select(Quote)));
            if(!CreateProcessW(executable,command,IntPtr.Zero,IntPtr.Zero,true,0x00080404,block,cwd,ref startup,out child))throw Error("suspended owned process");
            if(!AssignProcessToJobObject(job,child.process))throw Error("assign suspended process to job");assigned=true;
            Close(outWrite);outWrite=IntPtr.Zero;Close(errWrite);errWrite=IntPtr.Zero;Close(input);input=IntPtr.Zero;
            stdout=Task.Run(()=>Pump(outRead,prefix+".stdout"));stderr=Task.Run(()=>Pump(errRead,prefix+".stderr"));
            if(ResumeThread(child.thread)==0xffffffff)throw Error("ResumeThread");
            var watch=System.Diagnostics.Stopwatch.StartNew();
            while(true) {
                uint wait=WaitForSingleObject(child.process,50);
                if(wait==0)break;
                if(wait!=258)throw Error("process wait");
                if(watch.ElapsedMilliseconds>=milliseconds)throw new Exception("bounded process deadline");
                string cache;
                if(environment.TryGetValue("GOCACHE",out cache) && new DriveInfo(Path.GetPathRoot(cache)).AvailableFreeSpace<134217728)
                    throw new Exception("owned fixture volume space floor");
                if(stdout.IsFaulted||stderr.IsFaulted)throw new Exception("bounded output pump failed");
            }
            if(!GetExitCodeProcess(child.process,out status))throw Error("process exit status");
        } catch(Exception error){errors.Add(error.ToString());}
        finally {
            if(assigned) {
                if(!TerminateJobObject(job,137))errors.Add(Error("TerminateJobObject").ToString());
                IntPtr accounting=Marshal.AllocHGlobal(48);
                try {
                    var deadline=System.Diagnostics.Stopwatch.StartNew();
                    do {
                        uint returned;
                        if(!QueryInformationJobObject(job,1,accounting,48,out returned)||returned!=48){errors.Add(Error("job accounting").ToString());break;}
                        if(Marshal.ReadInt32(accounting,40)==0){empty=true;break;}
                        Thread.Sleep(10);
                    } while(deadline.ElapsedMilliseconds<1000);
                } finally{Marshal.FreeHGlobal(accounting);}
                if(!empty)errors.Add("owned job did not reach zero active processes");
            } else if(child.process!=IntPtr.Zero) {
                if(!TerminateProcess(child.process,137))errors.Add(Error("terminate suspended unassigned process").ToString());
                empty=WaitForSingleObject(child.process,1000)==0;
                if(!empty)errors.Add("suspended process cleanup was not observed");
            } else empty=true;
            try {
                var tasks=new Task[]{stdout,stderr}.Where(task=>task!=null).ToArray();
                if(tasks.Length>0&&!Task.WaitAll(tasks,1000))errors.Add("bounded output drain failed");
            } catch(Exception error){errors.Add(error.ToString());}
            foreach(IntPtr handle in new[]{outWrite,errWrite,input,outRead,errRead,child.thread,child.process,job})
                try{Close(handle);}catch(Exception error){errors.Add(error.ToString());}
            if(attributes!=IntPtr.Zero) {
                try { if(attributesInitialized)DeleteProcThreadAttributeList(attributes); }
                finally { Marshal.FreeHGlobal(attributes); }
            }
            foreach(IntPtr pointer in new[]{handles,block,limits})if(pointer!=IntPtr.Zero)Marshal.FreeHGlobal(pointer);
        }
        return new { status=status, pid=child.pid, jobEmpty=empty, errors=errors.ToArray(),
                     stdoutBytes=stdout!=null&&stdout.Status==TaskStatus.RanToCompletion?stdout.Result:-1,
                     stderrBytes=stderr!=null&&stderr.Status==TaskStatus.RanToCompletion?stderr.Result:-1 };
    }
}
'@
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
function Run-Stage([string]$Executable,[string[]]$Arguments,[int]$Seconds=30) {
    Assert-Phase
    if ($stages.Count -ge 24) { throw 'Owned stage count bound reached.' }
    $limit = [Math]::Min($Seconds*1000,[int]((800-$timer.Elapsed.TotalSeconds)*1000))
    $prefix = Join-Path $proof ('{0:d2}' -f $stages.Count)
    $row = [ordered]@{ executable=$Executable; executableSHA256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash; argv=$Arguments; limitMilliseconds=$limit }
    $stages.Add($row); Save-Proof 'stages.json' $stages
    $result = [IdentityStoreFixture]::Run($Executable,$Arguments,$root,$childEnvironment,$prefix,$limit)
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
    $diskpart = (Get-Command diskpart.exe -CommandType Application).Source
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
    $go = (Get-Command go.exe -CommandType Application).Source
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
    $node=(Get-Command node.exe -CommandType Application).Source
    if ((Run-Stage $node @('--version')).Trim() -ne 'v24.22.1') { throw 'The maintained Node version is required.' }
    $git=(Get-Command git.exe -CommandType Application).Source
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
        $compiler = (Get-Command gcc.exe -CommandType Application -ErrorAction Stop).Source
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
                Run-Stage $diskpart @('/s',$detach) 20 | Out-Null
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
