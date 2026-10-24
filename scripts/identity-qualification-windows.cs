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
    [DllImport("kernel32.dll")] static extern uint GetErrorMode();
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessId(IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint process,out uint session);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,
        out System.Runtime.InteropServices.ComTypes.FILETIME created,out System.Runtime.InteropServices.ComTypes.FILETIME exited,
        out System.Runtime.InteropServices.ComTypes.FILETIME kernel,out System.Runtime.InteropServices.ComTypes.FILETIME user);
    [DllImport("wevtapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr EvtOpenChannelConfig(IntPtr session,string path,uint flags);
    [DllImport("wevtapi.dll",SetLastError=true)] static extern bool EvtGetChannelConfigProperty(IntPtr channel,uint property,uint flags,uint size,IntPtr value,out uint used);
    [DllImport("wevtapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr EvtCreateRenderContext(uint count,
        [In,MarshalAs(UnmanagedType.LPArray,ArraySubType=UnmanagedType.LPWStr,SizeParamIndex=0)] string[] paths,uint flags);
    [DllImport("wevtapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr EvtQuery(IntPtr session,string path,string query,uint flags);
    [DllImport("wevtapi.dll",SetLastError=true)] static extern bool EvtNext(IntPtr query,uint size,
        [Out,MarshalAs(UnmanagedType.LPArray,SizeParamIndex=1)] IntPtr[] events,uint timeout,uint flags,out uint returned);
    [DllImport("wevtapi.dll",SetLastError=true)] static extern bool EvtRender(IntPtr context,IntPtr fragment,uint flags,uint size,IntPtr buffer,out uint used,out uint count);
    [DllImport("wevtapi.dll",SetLastError=true)] static extern bool EvtClose(IntPtr handle);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateEventW(ref SA security,bool manualReset,bool initialState,string name);
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
    static long Pump(IntPtr handle,string path,int outputLimit) {
        long total=0;byte[] buffer=new byte[65536];
        using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) {
            while(true) {
                uint count;
                if(!ReadFile(handle,buffer,(uint)buffer.Length,out count,IntPtr.Zero)) {
                    int code=Marshal.GetLastWin32Error();if(code==109)break;throw new Win32Exception(code,"native pipe read");
                }
                if(count==0)break;
                int retained=(int)Math.Min((long)count,Math.Max(0,(long)outputLimit-total));
                if(retained>0)output.Write(buffer,0,retained);
                total+=count;
                if(total>outputLimit)throw new Exception("bounded native output exceeded");
            }
        }
        return total;
    }
    public static object Run(string executable,string[] argv,string cwd,IDictionary<string,string> environment,string prefix,int milliseconds,bool monitorVolume=true) {
        return RunBounded(executable,argv,cwd,environment,prefix,milliseconds,67108864,monitorVolume);
    }
    public static object RunBounded(string executable,string[] argv,string cwd,IDictionary<string,string> environment,string prefix,int milliseconds,int outputLimit,bool monitorVolume=true) {
        if(outputLimit<=0||outputLimit>67108864)throw new Exception("invalid native output bound");
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
            stdout=Task.Run(()=>Pump(outRead,prefix+".stdout",outputLimit));stderr=Task.Run(()=>Pump(errRead,prefix+".stderr",outputLimit));
            if(ResumeThread(child.thread)==0xffffffff)throw Error("ResumeThread");
            var watch=System.Diagnostics.Stopwatch.StartNew();
            while(true) {
                uint wait=WaitForSingleObject(child.process,50);
                if(wait==0)break;
                if(wait!=258)throw Error("process wait");
                if(watch.ElapsedMilliseconds>=milliseconds)throw new Exception("bounded process deadline");
                string cache;
                if(monitorVolume && environment.TryGetValue("GOCACHE",out cache) && new DriveInfo(Path.GetPathRoot(cache)).AvailableFreeSpace<134217728)
                    throw new Exception("owned fixture volume space floor");
                if(stdout.IsFaulted||stderr.IsFaulted)throw new Exception("bounded output pump failed");
            }
            if(!GetExitCodeProcess(child.process,out status))throw Error("process exit status");
        } catch(Exception error){errors.Add(error.ToString());}
        finally {
            empty=CloseOwnedProcessJob(job,child,assigned,errors);
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
    static bool CloseOwnedProcessJob(IntPtr job,PI child,bool assigned,List<string> errors) {
        bool empty=false;
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
        return empty;
    }

    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool CreateProcessWithLogonW(string user,string domain,string password,uint logonFlags,
        string application,StringBuilder command,uint creationFlags,IntPtr environment,string cwd,ref SI startup,out PI process);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool DeleteProfileW(string sid,string path,string computer);

    public sealed class MandatoryLabelMetadata {
        public bool available { get; private set; }
        public string code { get; private set; }
        public uint win32Code { get; private set; }
        public string sid { get; private set; }
        public uint? mask { get; private set; }
        internal MandatoryLabelMetadata(bool available,string code,uint win32Code,string sid,uint? mask) {
            this.available=available;this.code=code;this.win32Code=win32Code;this.sid=sid;this.mask=mask;
        }
    }
    static MandatoryLabelMetadata UnavailableMandatoryLabel(string code,uint win32Code=0) {
        return new MandatoryLabelMetadata(false,code,win32Code,null,null);
    }
    static MandatoryLabelMetadata DecodeMandatoryLabel(byte[] bytes) {
        var security=new RawSecurityDescriptor(bytes,0);
        if(!security.ControlFlags.HasFlag(ControlFlags.SelfRelative))
            return UnavailableMandatoryLabel("LABEL_NOT_SELF_RELATIVE");
        if(!security.ControlFlags.HasFlag(ControlFlags.SystemAclPresent)||security.SystemAcl==null)
            return UnavailableMandatoryLabel("LABEL_ABSENT");
        if(security.SystemAcl.Count!=1)return UnavailableMandatoryLabel("LABEL_ACE_COUNT");
        GenericAce ace=security.SystemAcl[0];
        if((byte)ace.AceType!=0x11||ace.AceFlags!=AceFlags.None||ace.BinaryLength!=20)
            return UnavailableMandatoryLabel("LABEL_ACE_UNSUPPORTED");
        byte[] label=new byte[20];ace.GetBinaryForm(label,0);
        if(label[8]!=1||label[9]!=1||label[10]!=0||label[11]!=0||label[12]!=0||
            label[13]!=0||label[14]!=0||label[15]!=16)
            return UnavailableMandatoryLabel("LABEL_SID_UNSUPPORTED");
        uint mask=BitConverter.ToUInt32(label,4);
        if((mask&~7u)!=0)return UnavailableMandatoryLabel("LABEL_MASK_UNSUPPORTED");
        var sid=new SecurityIdentifier(label,8);
        if(sid.BinaryLength!=12)return UnavailableMandatoryLabel("LABEL_SID_UNSUPPORTED");
        return new MandatoryLabelMetadata(true,"AVAILABLE",0,sid.Value,mask);
    }
    static MandatoryLabelMetadata ReadMandatoryLabel(IntPtr handle,int objectType) {
        if(handle==IntPtr.Zero||(objectType!=6&&objectType!=7))
            return UnavailableMandatoryLabel("LABEL_OBJECT_UNAVAILABLE");
        IntPtr owner,group,dacl,sacl,descriptor=IntPtr.Zero;
        var result=UnavailableMandatoryLabel("LABEL_NOT_QUERIED");
        try {
            // LABEL_SECURITY_INFORMATION requires READ_CONTROL, not full SACL access.
            uint code=GetSecurityInfo(handle,objectType,0x10,out owner,out group,out dacl,out sacl,out descriptor);
            if(code!=0)result=UnavailableMandatoryLabel("LABEL_QUERY_FAILED",code);
            else if(descriptor==IntPtr.Zero)result=UnavailableMandatoryLabel("LABEL_DESCRIPTOR_ABSENT");
            else {
                uint length=GetSecurityDescriptorLength(descriptor);
                if(length<20||length>65536)result=UnavailableMandatoryLabel("LABEL_DESCRIPTOR_SIZE");
                else {
                    byte[] bytes=new byte[(int)length];Marshal.Copy(descriptor,bytes,0,(int)length);
                    result=DecodeMandatoryLabel(bytes);
                }
            }
        } catch(Exception) { result=UnavailableMandatoryLabel("LABEL_READ_UNAVAILABLE"); }
        finally {
            try {
                if(descriptor!=IntPtr.Zero&&LocalFree(descriptor)!=IntPtr.Zero)
                    result=UnavailableMandatoryLabel("LABEL_RELEASE_FAILED",unchecked((uint)Marshal.GetLastWin32Error()));
            } catch(Exception) { result=UnavailableMandatoryLabel("LABEL_RELEASE_UNAVAILABLE"); }
        }
        return result;
    }
    // The ordinary logon receives its actual profile environment from Windows.
    // Its launcher starts suspended and enters the owned Job before any script runs.
    static readonly string[] StandardStartupPhases={"entered","helper-loaded","probe-returned","controller-recorded"};
    static void CreateStandardStartupEvents(IntPtr[] events,MandatoryLabelMetadata[] labels,string user,string nonce) {
        if(events.Length!=StandardStartupPhases.Length||labels.Length!=events.Length||events.Any(value=>value!=IntPtr.Zero)||
            nonce.Length!=32||nonce.Any(character=>!"0123456789abcdef".Contains(character)))
            throw new Exception("invalid standard startup event scope");
        string owner;
        using(var identity=WindowsIdentity.GetCurrent()) {
            owner=identity.User.Value;
            if(owner==user||owner=="S-1-5-18"||!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new Exception("standard startup events require the isolated admin broker");
        }
        const uint trustedMask=0x001f0003,userMask=0x00100002;
        IntPtr descriptor=NewOwnedObjectDescriptor(owner,user,trustedMask,userMask,true);
        try {
            var security=new SA{length=Marshal.SizeOf<SA>(),descriptor=descriptor,inherit=0};
            for(int index=0;index<events.Length;index++) {
                events[index]=CreateEventW(ref security,true,false,"Global\\ca8_standard_"+nonce+"_"+StandardStartupPhases[index]);
                int error=Marshal.GetLastWin32Error();
                if(events[index]==IntPtr.Zero)throw new Win32Exception(error,"create owned standard startup event");
                if(error==183)throw new Exception("standard startup event already exists");
                CheckOwnedObjectSecurity(events[index],6,owner,user,trustedMask,userMask);
                labels[index]=ReadMandatoryLabel(events[index],6);
                if(!labels[index].available||labels[index].sid!="S-1-16-8192"||labels[index].mask!=1u)
                    throw new Exception("owned standard startup event mandatory label differs");
            }
        } finally { Free(descriptor); }
    }
    static void ObserveStandardStartup(IntPtr[] events,long[] observed,System.Diagnostics.Stopwatch watch) {
        if(watch==null)return;
        for(int index=0;index<events.Length;index++) {
            if(events[index]==IntPtr.Zero||observed[index]>=0)continue;
            uint state=WaitForSingleObject(events[index],0);
            if(state==0)observed[index]=watch.ElapsedMilliseconds;
            else if(state!=258)throw Error("observe standard startup event");
        }
    }
    public sealed class StandardChildTokenMetadata {
        public bool available { get; internal set; }
        public string code { get; internal set; }
        public int win32Code { get; internal set; }
        public string sid { get; internal set; }
        public bool? elevated { get; internal set; }
        public uint? elevationType { get; internal set; }
        public bool tokenClosed { get; internal set; }
        internal StandardChildTokenMetadata() { code="TOKEN_NOT_QUERIED";tokenClosed=true; }
    }
    static StandardChildTokenMetadata ReadStandardChildToken(IntPtr process,List<string> errors) {
        var result=new StandardChildTokenMetadata();IntPtr token=IntPtr.Zero,memory=IntPtr.Zero;
        try {
            if(!OpenProcessToken(process,0x0008,out token)) {
                result.code="TOKEN_OPEN_FAILED";result.win32Code=Marshal.GetLastWin32Error();return result;
            }
            result.tokenClosed=false;
            using(var identity=new WindowsIdentity(token)) {
                var user=identity.User;
                if(user==null||user.BinaryLength>68) {result.code="TOKEN_SID_UNAVAILABLE";return result;}
                string sid=user.Value;
                if(sid.Length>184) {result.code="TOKEN_SID_UNAVAILABLE";return result;}
                result.sid=sid;
            }
            // These two native records contain one DWORD each, with no pointers.
            memory=Marshal.AllocHGlobal(4);int returned;
            if(!GetTokenInformation(token,20,memory,4,out returned)) {
                result.code="TOKEN_ELEVATION_FAILED";result.win32Code=Marshal.GetLastWin32Error();return result;
            }
            if(returned!=4) {result.code="TOKEN_ELEVATION_LENGTH";return result;}
            result.elevated=Marshal.ReadInt32(memory)!=0;
            if(!GetTokenInformation(token,18,memory,4,out returned)) {
                result.code="TOKEN_ELEVATION_TYPE_FAILED";result.win32Code=Marshal.GetLastWin32Error();return result;
            }
            if(returned!=4) {result.code="TOKEN_ELEVATION_TYPE_LENGTH";return result;}
            uint type=unchecked((uint)Marshal.ReadInt32(memory));
            if(type<1||type>3) {result.code="TOKEN_ELEVATION_TYPE_UNKNOWN";return result;}
            result.elevationType=type;result.available=true;result.code="AVAILABLE";
        } catch {result.available=false;result.code="TOKEN_READ_UNAVAILABLE";}
        finally {
            try {if(memory!=IntPtr.Zero)Marshal.FreeHGlobal(memory);}
            finally {
                if(token!=IntPtr.Zero) {
                    try {
                        if(CloseHandle(token))result.tokenClosed=true;
                        else {
                            result.available=false;result.code="TOKEN_CLOSE_FAILED";result.win32Code=Marshal.GetLastWin32Error();
                            errors.Add("standard child diagnostic token close failed");
                        }
                    } catch {
                        result.available=false;result.code="TOKEN_CLOSE_UNAVAILABLE";
                        errors.Add("standard child diagnostic token close unavailable");
                    }
                }
            }
        }
        return result;
    }
    public sealed class StandardProcessStateMetadata {
        public bool available { get; internal set; }
        public string code { get; internal set; }
        public int win32Code { get; internal set; }
        public uint? waitState { get; internal set; }
        public uint? exitCode { get; internal set; }
        internal StandardProcessStateMetadata() {code="PROCESS_NOT_CREATED";}
    }
    static StandardProcessStateMetadata ReadStandardProcessState(IntPtr process) {
        var result=new StandardProcessStateMetadata();
        if(process==IntPtr.Zero)return result;
        try {
            uint wait=WaitForSingleObject(process,0);
            if(wait==0||wait==258)result.waitState=wait;
            else {
                result.code="PROCESS_WAIT_UNAVAILABLE";
                if(wait==0xffffffff)result.win32Code=Marshal.GetLastWin32Error();
            }
            uint exit;
            if(GetExitCodeProcess(process,out exit))result.exitCode=exit;
            else {result.code="PROCESS_EXIT_UNAVAILABLE";result.win32Code=Marshal.GetLastWin32Error();}
            result.available=result.waitState.HasValue&&result.exitCode.HasValue;
            if(result.available)result.code="AVAILABLE";
        } catch {result.available=false;result.code="PROCESS_STATE_READ_UNAVAILABLE";}
        return result;
    }
    public sealed class StandardChildContextMetadata {
        public string lifetimeCode { get; internal set; } = "PROCESS_NOT_CREATED";
        public int lifetimeWin32Code { get; internal set; }
        public uint? pid { get; internal set; }
        public ulong? createdFileTime { get; internal set; }
        public ulong? observedFileTime { get; internal set; }
        public string sessionCode { get; internal set; } = "SESSION_NOT_QUERIED";
        public int sessionWin32Code { get; internal set; }
        public uint? brokerSession { get; internal set; }
        public uint? childSession { get; internal set; }
        public string desktopCode { get; internal set; } = "DESKTOP_NOT_QUERIED";
        public int desktopWin32Code { get; internal set; }
        public uint? initialThreadID { get; internal set; }
        public string initialThreadDesktop { get; internal set; }
    }
    static StandardChildContextMetadata ReadStandardChildContext(PI child) {
        var result=new StandardChildContextMetadata();
        if(child.process==IntPtr.Zero)return result;
        try {
            uint actualPID=GetProcessId(child.process);
            if(actualPID==0)throw Error("standard child process ID");
            if(actualPID!=child.pid) {result.lifetimeCode="PROCESS_ID_MISMATCH";return result;}
            result.pid=actualPID;
            System.Runtime.InteropServices.ComTypes.FILETIME created,exited,kernel,user;
            if(!GetProcessTimes(child.process,out created,out exited,out kernel,out user))throw Error("standard child creation time");
            ulong creation=((ulong)(uint)created.dwHighDateTime<<32)|(uint)created.dwLowDateTime;
            ulong observed=(ulong)DateTime.UtcNow.ToFileTimeUtc();
            if(creation==0||creation>observed) {result.lifetimeCode="PROCESS_TIME_RANGE_INVALID";}
            else {result.createdFileTime=creation;result.observedFileTime=observed;result.lifetimeCode="AVAILABLE";}
        } catch(Win32Exception error) {result.lifetimeCode="PROCESS_LIFETIME_QUERY_FAILED";result.lifetimeWin32Code=error.NativeErrorCode;}
        catch {result.lifetimeCode="PROCESS_LIFETIME_UNAVAILABLE";}
        if(!result.pid.HasValue)return result;
        try {
            uint brokerPID=GetProcessId(GetCurrentProcess()),session;
            if(brokerPID==0)throw Error("broker process ID");
            if(!ProcessIdToSessionId(brokerPID,out session))throw Error("broker session");
            result.brokerSession=session;
            if(!ProcessIdToSessionId(result.pid.Value,out session))throw Error("standard child session");
            result.childSession=session;result.sessionCode="AVAILABLE";
        } catch(Win32Exception error) {result.sessionCode="SESSION_QUERY_FAILED";result.sessionWin32Code=error.NativeErrorCode;}
        catch {result.sessionCode="SESSION_UNAVAILABLE";}
        try {
            if(child.thread==IntPtr.Zero||child.tid==0) {result.desktopCode="INITIAL_THREAD_UNAVAILABLE";}
            else {
                result.initialThreadID=child.tid;
                // GetThreadDesktop returns a borrowed handle. Do not close it.
                IntPtr desktop=GetThreadDesktop(child.tid);
                if(desktop==IntPtr.Zero)throw Error("standard child initial-thread desktop");
                result.initialThreadDesktop=GuiObjectName(desktop);result.desktopCode="AVAILABLE";
            }
        } catch(Win32Exception error) {result.desktopCode="DESKTOP_QUERY_FAILED";result.desktopWin32Code=error.NativeErrorCode;}
        catch {result.desktopCode="DESKTOP_UNAVAILABLE";}
        return result;
    }
    public sealed class PowerShellStartupEventMetadata {
        public ushort eventID { get; internal set; }
        public ulong createdFileTime { get; internal set; }
        public ulong recordID { get; internal set; }
        public uint processID { get; internal set; }
    }
    public sealed class PowerShellStartupLogMetadata {
        public bool available { get; internal set; }
        public string code { get; internal set; } = "EVENTS_NOT_QUERIED";
        public int win32Code { get; internal set; }
        public bool? channelEnabled { get; internal set; }
        public bool complete { get; internal set; }
        public bool handlesClosed { get; internal set; } = true;
        public bool bufferReleased { get; internal set; } = true;
        public int closeWin32Code { get; internal set; }
        public long elapsedMilliseconds { get; internal set; }
        public PowerShellStartupEventMetadata[] events { get; internal set; } = new PowerShellStartupEventMetadata[0];
    }
    static uint StartupLogWaitBudget(System.Diagnostics.Stopwatch watch) {
        long remaining=5000-watch.ElapsedMilliseconds;
        if(remaining<=0)throw new TimeoutException();
        return (uint)Math.Min(250,remaining);
    }
    static void CloseStartupLogHandle(IntPtr handle,PowerShellStartupLogMetadata result,List<string> errors) {
        if(handle==IntPtr.Zero)return;
        try {
            if(EvtClose(handle))return;
            result.closeWin32Code=Marshal.GetLastWin32Error();
        } catch { }
        result.handlesClosed=false;
        errors.Add("standard startup event-log handle close failed");
    }
    static PowerShellStartupLogMetadata ReadPowerShellStartupLog(StandardChildContextMetadata child,List<string> errors) {
        var result=new PowerShellStartupLogMetadata();
        if(child.lifetimeCode!="AVAILABLE"||!child.pid.HasValue||!child.createdFileTime.HasValue||!child.observedFileTime.HasValue) {
            result.code="PROCESS_LIFETIME_UNAVAILABLE";return result;
        }
        IntPtr channel=IntPtr.Zero,context=IntPtr.Zero,query=IntPtr.Zero,buffer=IntPtr.Zero;
        var eventHandles=new IntPtr[1];var rows=new List<PowerShellStartupEventMetadata>();
        var watch=System.Diagnostics.Stopwatch.StartNew();
        try {
            const string channelName="PowerShellCore/Operational";
            buffer=Marshal.AllocHGlobal(64);result.bufferReleased=false;
            Marshal.Copy(new byte[64],0,buffer,64);
            StartupLogWaitBudget(watch);
            channel=EvtOpenChannelConfig(IntPtr.Zero,channelName,0);
            if(channel==IntPtr.Zero) {
                result.win32Code=Marshal.GetLastWin32Error();
                result.code=result.win32Code==15007?"CHANNEL_MISSING":"CHANNEL_QUERY_FAILED";return result;
            }
            StartupLogWaitBudget(watch);
            uint used;
            if(!EvtGetChannelConfigProperty(channel,0,0,16,buffer,out used)) {
                result.code="CHANNEL_ENABLED_QUERY_FAILED";result.win32Code=Marshal.GetLastWin32Error();return result;
            }
            StartupLogWaitBudget(watch);
            if(used!=16||Marshal.ReadInt32(buffer,12)!=13) {result.code="CHANNEL_ENABLED_SHAPE_UNSUPPORTED";return result;}
            result.channelEnabled=Marshal.ReadInt32(buffer)!=0;
            if(!result.channelEnabled.Value) {result.code="CHANNEL_DISABLED";return result;}
            string[] valuePaths={"Event/System/EventID","Event/System/TimeCreated/@SystemTime","Event/System/EventRecordID","Event/System/Execution/@ProcessID"};
            context=EvtCreateRenderContext(4,valuePaths,0);
            if(context==IntPtr.Zero) {result.code="EVENT_CONTEXT_FAILED";result.win32Code=Marshal.GetLastWin32Error();return result;}
            StartupLogWaitBudget(watch);
            var culture=System.Globalization.CultureInfo.InvariantCulture;
            string from=DateTime.FromFileTimeUtc((long)child.createdFileTime.Value).ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ",culture);
            string through=DateTime.FromFileTimeUtc((long)child.observedFileTime.Value).ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ",culture);
            string filter="*[System[Provider[@Name='PowerShellCore'] and (EventID=40961 or EventID=40962) and Execution[@ProcessID="+
                child.pid.Value.ToString(culture)+"] and TimeCreated[@SystemTime>='"+from+"' and @SystemTime<='"+through+"']]]";
            query=EvtQuery(IntPtr.Zero,channelName,filter,0x101);
            if(query==IntPtr.Zero) {
                result.win32Code=Marshal.GetLastWin32Error();
                result.code=result.win32Code==15007?"CHANNEL_MISSING":"EVENT_QUERY_FAILED";return result;
            }
            StartupLogWaitBudget(watch);
            for(int index=0;index<8;index++) {
                uint returned;
                bool next=EvtNext(query,1,eventHandles,StartupLogWaitBudget(watch),0,out returned);
                int nextError=next?0:Marshal.GetLastWin32Error();
                try {
                    StartupLogWaitBudget(watch);
                    if(!next) {
                        if(nextError==259&&returned==0&&eventHandles[0]==IntPtr.Zero) {
                            result.complete=true;result.code=rows.Count==0?"NO_MATCH":"MATCHES";
                        } else {result.code="EVENT_NEXT_FAILED";result.win32Code=nextError;}
                        return result;
                    }
                    if(returned!=1||eventHandles[0]==IntPtr.Zero) {result.code="EVENT_HANDLE_COUNT_INVALID";return result;}
                    Marshal.Copy(new byte[64],0,buffer,64);uint count;
                    if(!EvtRender(context,eventHandles[0],0,64,buffer,out used,out count)) {
                        result.code="EVENT_RENDER_FAILED";result.win32Code=Marshal.GetLastWin32Error();return result;
                    }
                    StartupLogWaitBudget(watch);
                    // Four 16-byte EVT_VARIANT records. Exact types reject arrays and pointers.
                    if(used!=64||count!=4||Marshal.ReadInt32(buffer,12)!=6||Marshal.ReadInt32(buffer,28)!=17||
                        Marshal.ReadInt32(buffer,44)!=10||Marshal.ReadInt32(buffer,60)!=8) {
                        result.code="EVENT_SCALAR_SHAPE_UNSUPPORTED";return result;
                    }
                    var row=new PowerShellStartupEventMetadata {
                        eventID=unchecked((ushort)Marshal.ReadInt16(buffer)),createdFileTime=unchecked((ulong)Marshal.ReadInt64(buffer,16)),
                        recordID=unchecked((ulong)Marshal.ReadInt64(buffer,32)),processID=unchecked((uint)Marshal.ReadInt32(buffer,48))
                    };
                    if((row.eventID!=40961&&row.eventID!=40962)||row.processID!=child.pid.Value||
                        row.createdFileTime<child.createdFileTime.Value||row.createdFileTime>child.observedFileTime.Value) {
                        result.code="EVENT_IDENTITY_OR_TIME_MISMATCH";return result;
                    }
                    rows.Add(row);
                } finally {
                    CloseStartupLogHandle(eventHandles[0],result,errors);eventHandles[0]=IntPtr.Zero;
                }
                if(!result.handlesClosed) {result.code="EVENT_CLOSE_FAILED";return result;}
            }
            result.code="EVENT_LIMIT_REACHED";
        } catch(TimeoutException) {result.code="EVENT_QUERY_BUDGET_EXCEEDED";}
        catch {result.code="EVENT_QUERY_UNAVAILABLE";}
        finally {
            CloseStartupLogHandle(eventHandles[0],result,errors);
            CloseStartupLogHandle(query,result,errors);
            CloseStartupLogHandle(context,result,errors);
            CloseStartupLogHandle(channel,result,errors);
            if(buffer!=IntPtr.Zero) {
                try {Marshal.FreeHGlobal(buffer);result.bufferReleased=true;}
                catch {errors.Add("standard startup event-log buffer release failed");}
            }
            result.events=rows.ToArray();result.elapsedMilliseconds=watch.ElapsedMilliseconds;
            if(result.elapsedMilliseconds>=5000) {result.complete=false;result.code="EVENT_QUERY_BUDGET_EXCEEDED";}
            result.available=result.complete&&result.handlesClosed&&result.bufferReleased;
        }
        return result;
    }
    public static object RunAsStandard(string user,string password,string executable,string[] argv,string cwd,int milliseconds,string desktopName,string startupSID=null,string startupNonce=null) {
        IntPtr job=IntPtr.Zero,limits=IntPtr.Zero;
        PI child=new PI(); bool assigned=false,empty=false; uint status=0xffffffff;
        long profileMilliseconds=-1; var errors=new List<string>();
        uint? resumePreviousSuspendCount=null,brokerErrorModeAtCreate=null;
        var childToken=new StandardChildTokenMetadata();var processBeforeCleanup=new StandardProcessStateMetadata();
        var contextBeforeCleanup=new StandardChildContextMetadata();var powerShellStartupLog=new PowerShellStartupLogMetadata();
        var startupEvents=new IntPtr[4]; var startupObserved=Enumerable.Repeat(-1L,4).ToArray();
        var startupLabels=Enumerable.Range(0,4).Select(index=>UnavailableMandatoryLabel("LABEL_NOT_QUERIED")).ToArray();
        System.Diagnostics.Stopwatch startupWatch=null; bool startupEventsClosed=true;
        try {
            if(milliseconds<=0||milliseconds>130000)throw new Exception("invalid standard-process bound");
            if((startupSID==null)!=(startupNonce==null))throw new Exception("incomplete standard startup event scope");
            if(startupNonce!=null)CreateStandardStartupEvents(startupEvents,startupLabels,startupSID,startupNonce);
            job=CreateJobObjectW(IntPtr.Zero,null);
            if(job==IntPtr.Zero)throw Error("standard process job");
            limits=Marshal.AllocHGlobal(144); Marshal.Copy(new byte[144],0,limits,144); Marshal.WriteInt32(limits,16,0x2000);
            if(!SetInformationJobObject(job,9,limits,144))throw Error("standard kill-on-close job limit");
            var command=new StringBuilder(String.Join(" ",new[]{executable}.Concat(argv).Select(Quote)));
            if(command.Length>=1024)throw new Exception("standard logon command exceeds its native bound");
            if(String.IsNullOrEmpty(desktopName)||!desktopName.StartsWith("ca8_station_",StringComparison.Ordinal))throw new Exception("owned desktop locator unavailable");
            IntPtr desktopText=Marshal.StringToHGlobalUni(desktopName);
            var startup=new SI{cb=Marshal.SizeOf<SI>(),desktop=desktopText};
            try {brokerErrorModeAtCreate=GetErrorMode();}catch {brokerErrorModeAtCreate=null;}
            var profileWatch=System.Diagnostics.Stopwatch.StartNew();
            try {
                if(!CreateProcessWithLogonW(user,".",password,1,executable,command,0x08000004,IntPtr.Zero,cwd,ref startup,out child))
                    throw Error("standard suspended profile logon");
            } finally { Marshal.FreeHGlobal(desktopText); }
            profileMilliseconds=profileWatch.ElapsedMilliseconds;
            if(profileMilliseconds>60000)throw new Exception("standard profile stage exceeded its logical bound");
            if(!AssignProcessToJobObject(job,child.process))throw Error("assign suspended standard process to owned job");
            assigned=true;
            childToken=ReadStandardChildToken(child.process,errors);
            if(!childToken.tokenClosed)throw new Exception("standard child diagnostic token did not close");
            uint previousSuspendCount=ResumeThread(child.thread);resumePreviousSuspendCount=previousSuspendCount;
            if(previousSuspendCount==0xffffffff)throw Error("resume standard process");
            var watch=System.Diagnostics.Stopwatch.StartNew(); startupWatch=watch;
            while(true) {
                uint wait=WaitForSingleObject(child.process,50);
                ObserveStandardStartup(startupEvents,startupObserved,startupWatch);
                if(wait==0)break;
                if(wait!=258)throw Error("standard process wait");
                if(watch.ElapsedMilliseconds>=milliseconds)throw new Exception("standard controller logical bound exceeded");
            }
            if(!GetExitCodeProcess(child.process,out status))throw Error("standard process exit status");
        } catch(Exception error){errors.Add(error.ToString());}
        finally {
            processBeforeCleanup=ReadStandardProcessState(child.process);
            contextBeforeCleanup=ReadStandardChildContext(child);
            empty=CloseOwnedProcessJob(job,child,assigned,errors);
            if(empty)powerShellStartupLog=ReadPowerShellStartupLog(contextBeforeCleanup,errors);
            else powerShellStartupLog.code="CHILD_JOB_NOT_EMPTY";
            try { ObserveStandardStartup(startupEvents,startupObserved,startupWatch); }
            catch(Exception error){errors.Add(error.ToString());}
            foreach(IntPtr handle in startupEvents)
                try{Close(handle);}catch(Exception error){startupEventsClosed=false;errors.Add(error.ToString());}
            foreach(IntPtr handle in new[]{child.thread,child.process,job})
                try{Close(handle);}catch(Exception error){errors.Add(error.ToString());}
            if(limits!=IntPtr.Zero)Marshal.FreeHGlobal(limits);
        }
        return new {status=status,pid=child.pid,jobEmpty=empty,profileMilliseconds=profileMilliseconds,errors=errors.ToArray(),
                    launchDiagnostics=new {resumePreviousSuspendCount=resumePreviousSuspendCount,brokerErrorModeAtCreate=brokerErrorModeAtCreate,
                        childToken=childToken,processBeforeCleanup=processBeforeCleanup,
                        contextBeforeCleanup=contextBeforeCleanup,powerShellStartupLog=powerShellStartupLog},
                    startupEventsClosed=startupEventsClosed,
                    startupPhases=StandardStartupPhases.Select((phase,index)=>new {phase=phase,observedMilliseconds=startupObserved[index],mandatoryLabel=startupLabels[index]}).ToArray()};
    }

    public static void DeleteOwnedProfile(string sid,string path) {
        if(String.IsNullOrEmpty(sid)||String.IsNullOrEmpty(path)||!Path.IsPathFullyQualified(path))
            throw new Exception("owned profile locator is invalid");
        if(!DeleteProfileW(sid,path,null))throw Error("delete owned fixture profile");
    }

    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateWindowStationW(string name,uint flags,uint access,ref SA security);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenWindowStationW(string name,bool inherit,uint access);
    [DllImport("user32.dll",SetLastError=true)] static extern bool CloseWindowStation(IntPtr station);
    [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll",SetLastError=true)] static extern bool SetProcessWindowStation(IntPtr station);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("user32.dll",SetLastError=true)] static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateDesktopW(string name,IntPtr device,IntPtr mode,uint flags,uint access,ref SA security);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenDesktopW(string name,uint flags,bool inherit,uint access);
    [DllImport("user32.dll",SetLastError=true)] static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformationW(IntPtr handle,int index,[Out] byte[] information,uint length,out uint needed);

    static string GuiObjectName(IntPtr handle) {
        if(handle==IntPtr.Zero)throw Error("GUI name handle unavailable");
        byte[] bytes=new byte[512];
        try {
            uint needed;
            if(!GetUserObjectInformationW(handle,2,bytes,(uint)bytes.Length,out needed))throw Error("bounded GUI object name readback");
            if(needed<4||needed>bytes.Length||(needed&1)!=0)throw new Exception("GUI object name byte count is invalid");
            int length=(int)needed;
            if(bytes[length-2]!=0||bytes[length-1]!=0)throw new Exception("GUI object name terminator is absent");
            string name=new UnicodeEncoding(false,false,true).GetString(bytes,0,length-2);
            if(name.Length==0||name.IndexOf('\0')>=0)throw new Exception("GUI object name is empty or contains a terminator");
            return name;
        } finally { Array.Clear(bytes,0,bytes.Length); }
    }

    static IntPtr NewOwnedObjectDescriptor(string owner,string user,uint trustedMask,uint userMask,bool mediumStartupEvents=false) {
        new SecurityIdentifier(owner); new SecurityIdentifier(user);
        if(mediumStartupEvents&&(trustedMask!=0x001f0003||userMask!=0x00100002))
            throw new Exception("mandatory event label requires the fixed event grants");
        string text="O:"+owner+"D:P(A;;0x"+trustedMask.ToString("x8")+";;;"+owner+")(A;;0x"+trustedMask.ToString("x8")+";;;SY)(A;;0x"+userMask.ToString("x8")+";;;"+user+")";
        if(mediumStartupEvents)text+="S:(ML;;NW;;;ME)";
        IntPtr descriptor;uint size;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor(text,1,out descriptor,out size))throw Error("owned object security descriptor");
        return descriptor;
    }
    static void CheckGuiSecurity(IntPtr handle,string owner,string user,uint trustedMask,uint userMask) {
        CheckOwnedObjectSecurity(handle,7,owner,user,trustedMask,userMask);
    }
    static void CheckOwnedObjectSecurity(IntPtr handle,int objectType,string owner,string user,uint trustedMask,uint userMask) {
        if(objectType!=6&&objectType!=7)throw new Exception("unsupported owned object type");
        IntPtr actualOwner,group,dacl,sacl,descriptor;
        uint code=GetSecurityInfo(handle,objectType,5,out actualOwner,out group,out dacl,out sacl,out descriptor);
        if(code!=0)throw new Win32Exception((int)code,"owned object security readback");
        try {
            uint length=GetSecurityDescriptorLength(descriptor);
            if(length<20||length>65536)throw new Exception("owned object descriptor size");
            byte[] bytes=new byte[length];Marshal.Copy(descriptor,bytes,0,(int)length);
            var security=new RawSecurityDescriptor(bytes,0);
            if(security.Owner.Value!=owner||(objectType==7&&!security.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected))||security.DiscretionaryAcl==null||security.DiscretionaryAcl.Count!=3)
                throw new Exception("owned object security mismatch");
            var expected=new Dictionary<string,uint>{{owner,trustedMask},{"S-1-5-18",trustedMask},{user,userMask}};
            foreach(GenericAce generic in security.DiscretionaryAcl) {
                var ace=generic as CommonAce;uint mask;
                if(ace==null||ace.IsCallback||ace.AceQualifier!=AceQualifier.AccessAllowed||ace.AceFlags!=0||
                    !expected.TryGetValue(ace.SecurityIdentifier.Value,out mask)||unchecked((uint)ace.AccessMask)!=mask)
                    throw new Exception("owned object ACE mismatch");
                expected.Remove(ace.SecurityIdentifier.Value);
            }
            if(expected.Count!=0)throw new Exception("owned object trustee mismatch");
        } finally { Free(descriptor); }
    }

    // Only the isolated broker script calls this entry. The long-lived parent
    // never changes its process window station or its thread desktop.
    public static object RunInOwnedDesktop(string user,string sid,string password,string executable,string[] argv,string cwd,string nonce) {
        if(nonce.Length!=32||nonce.Any(character=>!"0123456789abcdef".Contains(character)))throw new Exception("owned GUI nonce unavailable");
        string owner;
        using(var identity=WindowsIdentity.GetCurrent()) {
            owner=identity.User.Value;
            if(owner==sid||owner=="S-1-5-18"||!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new Exception("isolated non-SYSTEM admin broker is required");
        }
        string stationName="ca8_station_"+nonce,desktopName="ca8_desktop_"+nonce;
        IntPtr previousStation=GetProcessWindowStation(),previousDesktop=GetThreadDesktop(GetCurrentThreadId());
        if(previousStation==IntPtr.Zero||previousDesktop==IntPtr.Zero)throw Error("broker GUI provenance");
        IntPtr station=IntPtr.Zero,desktop=IntPtr.Zero,stationSD=IntPtr.Zero,desktopSD=IntPtr.Zero;
        bool restored=false,stationClosed=false,desktopClosed=false,stationAbsent=false,childLaunchAttempted=false;
        bool desktopCreatorStarted=false,desktopCreatorExited=true,stationNameBound=false,desktopNameBound=false;
        string originalStationName=null,originalDesktopName=null,restoredStationName=null,restoredDesktopName=null;
        string stationNameReadback=null,desktopNameReadback=null,creationStationName=null,creatorCurrentDesktopName=null;
        object child=null;var errors=new List<string>();
        var stationMandatoryLabel=UnavailableMandatoryLabel("LABEL_NOT_QUERIED");
        var desktopMandatoryLabel=UnavailableMandatoryLabel("LABEL_NOT_QUERIED");
        try {
            originalStationName=GuiObjectName(previousStation);
            originalDesktopName=GuiObjectName(previousDesktop);
            stationSD=NewOwnedObjectDescriptor(owner,sid,0x000f037f,0x00020123);
            var stationSecurity=new SA{length=Marshal.SizeOf<SA>(),descriptor=stationSD,inherit=0};
            station=CreateWindowStationW(stationName,1,0x000f037f,ref stationSecurity);
            if(station==IntPtr.Zero)throw Error("create-only owned noninteractive station");
            stationNameReadback=GuiObjectName(station);
            stationNameBound=String.Equals(stationNameReadback,stationName,StringComparison.Ordinal);
            if(!stationNameBound)throw new Exception("created station name differs");
            CheckGuiSecurity(station,owner,sid,0x000f037f,0x00020123);
            stationMandatoryLabel=ReadMandatoryLabel(station,7);
            if(!SetProcessWindowStation(station))throw Error("isolated broker station association");
            creationStationName=GuiObjectName(GetProcessWindowStation());
            if(!String.Equals(creationStationName,stationName,StringComparison.Ordinal))throw new Exception("desktop creation station name differs");
            IntPtr collision=OpenDesktopW(desktopName,0,false,0x00020081);
            if(collision!=IntPtr.Zero) {
                if(!CloseDesktop(collision))throw Error("colliding desktop close");
                throw new Exception("owned desktop name already exists");
            }
            if(Marshal.GetLastWin32Error()!=2)throw Error("owned desktop absence prerequisite");
            desktopSD=NewOwnedObjectDescriptor(owner,sid,0x000f01ff,0x000200c3);
            Exception creatorError=null;
            // CreateDesktop assigns its desktop to the calling thread. Keep
            // that association on a new thread that exits before restoration.
            var creator=new Thread(()=>{
                try {
                    var desktopSecurity=new SA{length=Marshal.SizeOf<SA>(),descriptor=desktopSD,inherit=0};
                    desktop=CreateDesktopW(desktopName,IntPtr.Zero,IntPtr.Zero,0,0x000f01ff,ref desktopSecurity);
                    if(desktop==IntPtr.Zero)throw Error("owned noninteractive desktop");
                    desktopNameReadback=GuiObjectName(desktop);
                    creatorCurrentDesktopName=GuiObjectName(GetThreadDesktop(GetCurrentThreadId()));
                } catch(Exception error){creatorError=error;}
            });
            creator.IsBackground=true;
            creator.Start();desktopCreatorStarted=true;desktopCreatorExited=false;
            desktopCreatorExited=creator.Join(10000);
            if(!desktopCreatorExited)throw new Exception("owned desktop creator did not exit within its bound");
            if(creatorError!=null)throw creatorError;
            desktopNameBound=String.Equals(desktopNameReadback,desktopName,StringComparison.Ordinal);
            if(!desktopNameBound)throw new Exception("created desktop name differs");
            CheckGuiSecurity(desktop,owner,sid,0x000f01ff,0x000200c3);
            desktopMandatoryLabel=ReadMandatoryLabel(desktop,7);
            if(!SetProcessWindowStation(previousStation))throw Error("restore isolated broker station before child launch");
            restoredStationName=GuiObjectName(GetProcessWindowStation());
            restoredDesktopName=GuiObjectName(GetThreadDesktop(GetCurrentThreadId()));
            if(!String.Equals(restoredStationName,originalStationName,StringComparison.Ordinal)||
                !String.Equals(restoredDesktopName,originalDesktopName,StringComparison.Ordinal))
                throw new Exception("restored broker GUI names differ before child launch");
            restored=true;
            childLaunchAttempted=true;
            child=RunAsStandard(user,password,executable,argv,cwd,130000,stationName+"\\"+desktopName,sid,nonce);
        } catch(Exception error){errors.Add(error.ToString());}
        finally {
            if(desktopCreatorExited) {
                if(!restored) {
                    try {
                        if(!SetProcessWindowStation(previousStation))throw Error("broker station restoration");
                        restoredStationName=GuiObjectName(GetProcessWindowStation());
                        restoredDesktopName=GuiObjectName(GetThreadDesktop(GetCurrentThreadId()));
                        restored=originalStationName!=null&&originalDesktopName!=null&&
                            String.Equals(restoredStationName,originalStationName,StringComparison.Ordinal)&&
                            String.Equals(restoredDesktopName,originalDesktopName,StringComparison.Ordinal);
                        if(!restored)errors.Add("broker GUI restoration names differ");
                    } catch(Exception error){errors.Add(error.ToString());}
                }
                if(desktop!=IntPtr.Zero){desktopClosed=CloseDesktop(desktop);if(!desktopClosed)errors.Add(Error("owned desktop close").ToString());}
                if(station!=IntPtr.Zero){stationClosed=CloseWindowStation(station);if(!stationClosed)errors.Add(Error("owned station close").ToString());}
                if(stationClosed) {
                    IntPtr observed=OpenWindowStationW(stationName,false,0x00020000);
                    if(observed==IntPtr.Zero)stationAbsent=Marshal.GetLastWin32Error()==2;
                    else if(!CloseWindowStation(observed))errors.Add(Error("owned station observation close").ToString());
                    if(!stationAbsent)errors.Add("owned station absence was not established");
                }
                foreach(IntPtr descriptor in new[]{stationSD,desktopSD})try{Free(descriptor);}catch(Exception error){errors.Add(error.ToString());}
            } else errors.Add("preserve creator-owned GUI handles and descriptors until isolated broker exit");
        }
        return new {child=child,childLaunchAttempted=childLaunchAttempted,stationCreated=station!=IntPtr.Zero,desktopCreated=desktop!=IntPtr.Zero,
            desktopCreatorStarted=desktopCreatorStarted,desktopCreatorExited=desktopCreatorExited,
            stationNameBound=stationNameBound,desktopNameBound=desktopNameBound,
            stationNameReadback=stationNameReadback,desktopNameReadback=desktopNameReadback,creationStationName=creationStationName,
            creatorCurrentDesktopName=creatorCurrentDesktopName,originalStationName=originalStationName,originalDesktopName=originalDesktopName,
            restoredStationName=restoredStationName,restoredDesktopName=restoredDesktopName,
            errors=errors.ToArray(),restored=restored,stationClosed=stationClosed,desktopClosed=desktopClosed,
            stationAbsent=stationAbsent,station=stationName,desktop=desktopName,stationUserMask=0x00020123,desktopUserMask=0x000200c3,stationMandatoryLabel=stationMandatoryLabel,desktopMandatoryLabel=desktopMandatoryLabel};
    }

    public static string ReadBrokerPassword(string pipeName) {
        using(var pipe=new System.IO.Pipes.NamedPipeClientStream(".",pipeName,System.IO.Pipes.PipeDirection.In,System.IO.Pipes.PipeOptions.Asynchronous)) {
            pipe.Connect(20000);
            using(var reader=new BinaryReader(pipe,Encoding.UTF8,false)) {
                int count=reader.ReadInt32();
                if(count<16||count>256)throw new Exception("broker secret length");
                byte[] bytes=reader.ReadBytes(count);
                try{if(bytes.Length!=count)throw new Exception("broker secret frame incomplete");return Encoding.UTF8.GetString(bytes);}
                finally{Array.Clear(bytes,0,bytes.Length);}
            }
        }
    }
    public static object RunBroker(string executable,string[] argv,string cwd,IDictionary<string,string> environment,string prefix,string pipeName,string password) {
        using(var pipe=new System.IO.Pipes.NamedPipeServerStream(pipeName,System.IO.Pipes.PipeDirection.Out,1,
            System.IO.Pipes.PipeTransmissionMode.Byte,System.IO.Pipes.PipeOptions.Asynchronous|System.IO.Pipes.PipeOptions.CurrentUserOnly))
        using(var cancellation=new CancellationTokenSource(20000)) {
            byte[] secret=Encoding.UTF8.GetBytes(password);
            var transfer=Task.Run(async()=>{
                await pipe.WaitForConnectionAsync(cancellation.Token);
                using(var writer=new BinaryWriter(pipe,Encoding.UTF8,true)){writer.Write(secret.Length);writer.Write(secret);writer.Flush();}
            });
            object result=null;bool transferClosed=false;var errors=new List<string>();
            try {result=RunBounded(executable,argv,cwd,environment,prefix,210000,16777216);}
            catch(Exception error){errors.Add(error.ToString());}
            finally {
                cancellation.Cancel();
                try {pipe.Dispose();} catch(Exception error){errors.Add(error.ToString());}
                try {transferClosed=transfer.Wait(1000);}
                catch(Exception error){transferClosed=transfer.IsCompleted;errors.Add(error.ToString());}
                if(!transferClosed)errors.Add("broker secret task did not close");
                Array.Clear(secret,0,secret.Length);
            }
            return new {process=result,secretTransferClosed=transferClosed,errors=errors.ToArray()};
        }
    }

    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string path,ref SA security);
    public static void CreateQualificationDirectory(string path,string owner,string standard) {
        new SecurityIdentifier(owner);
        if(!String.IsNullOrEmpty(standard))new SecurityIdentifier(standard);
        IntPtr descriptor=IntPtr.Zero;
        try {
            string text="O:"+owner+"D:P(A;OICI;FA;;;"+owner+")(A;OICI;FA;;;SY)";
            if(!String.IsNullOrEmpty(standard))text+="(A;OICI;FA;;;"+standard+")";
            uint size;
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor(text,1,out descriptor,out size))throw Error("new qualification directory descriptor");
            var security=new SA{length=Marshal.SizeOf<SA>(),descriptor=descriptor,inherit=0};
            if(!CreateDirectoryW(path,ref security))throw Error("exclusive new qualification directory");
        } finally {Free(descriptor);}
    }

    public static object InspectQualificationFile(string path) {
        IntPtr handle=CreateFileW(path,0x80020000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        if(handle==new IntPtr(-1))throw Error("owned proof file open");
        try {
            FILEINFO info;
            if(GetFileType(handle)!=1||!GetFileInformationByHandle(handle,out info)||(info.attributes&0x410)!=0||info.links!=1)
                throw new Exception("owned proof file is not one regular unreparsed object");
            ulong bytes=((ulong)info.sizeHigh<<32)|info.sizeLow;
            if(bytes>16777216)throw new Exception("owned proof file size bound");
            IntPtr owner,group,dacl,sacl,descriptor;
            uint code=GetSecurityInfo(handle,1,1,out owner,out group,out dacl,out sacl,out descriptor);
            if(code!=0)throw new Win32Exception((int)code,"owned proof file owner readback");
            try {
                return new {device=(ulong)info.volume,nativeObject=((ulong)info.indexHigh<<32)|info.indexLow,
                    fileBytes=bytes,owner=new SecurityIdentifier(owner).Value};
            } finally {Free(descriptor);}
        } finally {Close(handle);}
    }
}
