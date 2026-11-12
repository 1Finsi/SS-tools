<#
Check-Javaw.ps1 - one-shot check of running Java (Minecraft) processes for cheats.
Run on the player's PC while the game is running. The one-line command in
Check-Javaw-command.txt is generated from this file by build-command.ps1.

Checks:
  1. Java agents (command line, instrument.dll / attach.dll)
  2. Unsigned modules + verification that Java/LWJGL-named DLLs really are those libraries
  3. Threads starting outside every module
  4. Hidden PE images and non-JIT executable memory
  5. Code of key modules compared with the files on disk (hooks anywhere in a function)
  6. Other processes holding a handle to the game with write / thread rights (needs admin)
  7. Kernel drivers: unsigned, known abused, test-signing mode

Style note: every line must end at a statement boundary; no comments below this block
(build-command.ps1 joins lines into one).
#>
$adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators');
if(!$adm -and $PSCommandPath){Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`"";return};
if(!$adm){Write-Host "Not admin - handle check skipped, other results may be incomplete. Run PowerShell as administrator." -F Yellow};
if(![Environment]::Is64BitProcess){Write-Host "Use 64-bit PowerShell" -F Red}else{
if(!('JC2.N' -as [type])){Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.IO;using System.Runtime.InteropServices;
namespace JC2{
public class PA{public long B;public long S;public long X;public long J;public string T;public bool Pe;}
public class EX{public string N;public int R;}
public class PT{public long A;public int L;public long T;public string K;public string M;public string D;}
public class HO{public int P;public uint A;}
public static class N{
[StructLayout(LayoutKind.Sequential)]struct MBI{public IntPtr Ba;public IntPtr Ab;public uint Ap;public ushort Pi;public IntPtr Rs;public uint St;public uint Pr;public uint Ty;}
[StructLayout(LayoutKind.Sequential)]struct TP{public uint C;public uint Lo;public int Hi;public uint At;}
[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,int p);
[DllImport("kernel32.dll")]static extern IntPtr OpenThread(uint a,bool i,int t);
[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll")]static extern int GetCurrentProcessId();
[DllImport("kernel32.dll")]static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr a,out MBI m,UIntPtr l);
[DllImport("kernel32.dll")]static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr r);
[DllImport("ntdll.dll")]static extern int NtQueryInformationThread(IntPtr h,int c,out IntPtr i,int l,IntPtr r);
[DllImport("ntdll.dll")]static extern int NtQuerySystemInformation(int c,IntPtr b,int l,out int r);
[DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
[DllImport("advapi32.dll",SetLastError=true)]static extern bool LookupPrivilegeValue(string s,string n,out long l);
[DllImport("advapi32.dll",SetLastError=true)]static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref TP n,int l,IntPtr p,IntPtr r);
public static bool EnableDebug(){IntPtr t;if(!OpenProcessToken(GetCurrentProcess(),0x28,out t))return false;try{long l;if(!LookupPrivilegeValue(null,"SeDebugPrivilege",out l))return false;var tp=new TP{C=1,Lo=(uint)(l&0xFFFFFFFF),Hi=(int)(l>>32),At=2};return AdjustTokenPrivileges(t,false,ref tp,0,IntPtr.Zero,IntPtr.Zero)&&Marshal.GetLastWin32Error()==0;}finally{CloseHandle(t);}}
public static long TS(int t){IntPtr h=OpenThread(0x40,false,t);if(h==IntPtr.Zero)return 0;try{IntPtr a;return NtQueryInformationThread(h,9,out a,IntPtr.Size,IntPtr.Zero)==0?a.ToInt64():0;}finally{CloseHandle(h);}}
static bool IsPe(byte[] d,int n){if(n<0x40||d[0]!=0x4D||d[1]!=0x5A)return false;int l=BitConverter.ToInt32(d,0x3C);return l>0&&l<n-4&&d[l]==0x50&&d[l+1]==0x45&&d[l+2]==0&&d[l+3]==0;}
public static List<PA> Mem(int p){var all=new Dictionary<long,PA>();IntPtr h=OpenProcess(0x410,false,p);if(h==IntPtr.Zero)throw new Exception("OpenProcess failed");try{long a=0;MBI m;var z=(UIntPtr)Marshal.SizeOf(typeof(MBI));var d=new byte[0x400];while(VirtualQueryEx(h,(IntPtr)a,out m,z)!=UIntPtr.Zero){long s=m.Rs.ToInt64(),ab=m.Ab.ToInt64();if(m.St==0x1000&&m.Ty!=0x1000000){PA q;if(!all.TryGetValue(ab,out q)){IntPtr n;bool pe=ReadProcessMemory(h,(IntPtr)ab,d,(IntPtr)d.Length,out n)&&IsPe(d,(int)n.ToInt64());q=new PA{B=ab,T=m.Ty==0x40000?"Mapped":"Private",Pe=pe};all[ab]=q;}q.S+=s;if((m.Pr&0xF0)!=0){q.X+=s;if((m.Pr&0xFF)!=0x40)q.J+=s;}}long nx=m.Ba.ToInt64()+s;if(nx<=a)break;a=nx;}}finally{CloseHandle(h);}var res=new List<PA>();foreach(var q in all.Values){if(q.Pe||q.J>0)res.Add(q);}return res;}
static byte[] ReadImg(IntPtr h,long b,int sz,bool[] ok){var img=new byte[sz];var pg=new byte[0x1000];IntPtr r;int i=0;for(int o=0;o<sz;o+=0x1000){int n=Math.Min(0x1000,sz-o);if(ReadProcessMemory(h,(IntPtr)(b+o),pg,(IntPtr)n,out r)){Buffer.BlockCopy(pg,0,img,o,n);if(ok!=null)ok[i]=true;}i++;}return img;}
static List<EX> ExportTable(byte[] img,int sz){var res=new List<EX>();int lf=BitConverter.ToInt32(img,0x3C);if(lf<=0||lf+144>sz)return res;int er=BitConverter.ToInt32(img,lf+136);if(er<=0||er+0x28>sz)return res;int nf=BitConverter.ToInt32(img,er+0x14),nn=BitConverter.ToInt32(img,er+0x18),af=BitConverter.ToInt32(img,er+0x1C),an=BitConverter.ToInt32(img,er+0x20),ao=BitConverter.ToInt32(img,er+0x24);if(nf<0||nn<0||af<0||an<0||ao<0||(long)af+nf*4L>sz||(long)an+nn*4L>sz||(long)ao+nn*2L>sz)return res;var nm=new Dictionary<int,string>();for(int i=0;i<nn;i++){int nr=BitConverter.ToInt32(img,an+i*4);int od=BitConverter.ToUInt16(img,ao+i*2);if(nr<=0||nr>=sz)continue;int e=nr;while(e<sz&&img[e]!=0)e++;nm[od]=System.Text.Encoding.ASCII.GetString(img,nr,e-nr);}for(int i=0;i<nf;i++){int v=BitConverter.ToInt32(img,af+i*4);if(v<=0||v>=sz)continue;string s;nm.TryGetValue(i,out s);res.Add(new EX{N=s??("#"+i),R=v});}return res;}
public static EX[] Exports(int p,long b,int sz){IntPtr h=OpenProcess(0x410,false,p);if(h==IntPtr.Zero)return new EX[0];try{return ExportTable(ReadImg(h,b,sz,null),sz).ToArray();}finally{CloseHandle(h);}}
static long Jump(byte[] c,int v,long a,IntPtr h,out string k){k=null;if(v<0||v+13>c.Length)return 0;if(c[v]==0xE9){k="jmp rel32";return a+5+BitConverter.ToInt32(c,v+1);}if(c[v]==0xFF&&c[v+1]==0x25){long pp=a+6+BitConverter.ToInt32(c,v+2);var q=new byte[8];IntPtr r;k="jmp [mem]";return ReadProcessMemory(h,(IntPtr)pp,q,(IntPtr)8,out r)?BitConverter.ToInt64(q,0):0;}if(c[v]==0x48&&c[v+1]==0xB8&&c[v+10]==0xFF&&c[v+11]==0xE0){k="mov rax;jmp rax";return BitConverter.ToInt64(c,v+2);}if(c[v]==0x49&&c[v+1]==0xBB&&c[v+10]==0x41&&c[v+11]==0xFF&&c[v+12]==0xE3){k="mov r11;jmp r11";return BitConverter.ToInt64(c,v+2);}if(c[v]==0x68&&c[v+5]==0xC3){k="push;ret";return (uint)BitConverter.ToInt32(c,v+1);}return 0;}
public static List<PT> TextDiff(int p,long b,int sz,string path){var res=new List<PT>();byte[] f=File.ReadAllBytes(path);int lf=BitConverter.ToInt32(f,0x3C);int ns=BitConverter.ToUInt16(f,lf+6),so=BitConverter.ToUInt16(f,lf+20);int opt=lf+24;if(BitConverter.ToUInt16(f,opt)!=0x20B)return res;long ib=BitConverter.ToInt64(f,opt+24);int rr=BitConverter.ToInt32(f,opt+152),rs=BitConverter.ToInt32(f,opt+156);var disk=new byte[sz];var xs=new List<int[]>();var sva=new int[ns];for(int i=0;i<ns;i++){int e=opt+so+i*40;int vs=BitConverter.ToInt32(f,e+8),va=BitConverter.ToInt32(f,e+12),raw=BitConverter.ToInt32(f,e+16),pr=BitConverter.ToInt32(f,e+20);uint ch=BitConverter.ToUInt32(f,e+36);sva[i]=va;if(va<=0||va>=sz||pr<0||pr>=f.Length)continue;int n=Math.Min(raw,vs==0?raw:vs);n=Math.Min(n,Math.Min(sz-va,f.Length-pr));if(n<=0)continue;Buffer.BlockCopy(f,pr,disk,va,n);if((ch&0x20000000)!=0&&(ch&0x80000000)==0)xs.Add(new int[]{va,n});}
long delta=b-ib;if(delta!=0&&rr>0&&rs>0&&rr<sz){int o=rr,end=Math.Min(rr+rs,sz);while(o+8<=end){int pg=BitConverter.ToInt32(disk,o),bs=BitConverter.ToInt32(disk,o+4);if(bs<8)break;for(int j=o+8;j+2<=o+bs&&j+2<=end;j+=2){int en=BitConverter.ToUInt16(disk,j);int ty=en>>12,rv=pg+(en&0xFFF);if(ty==10&&rv>=0&&rv+8<=sz){Buffer.BlockCopy(BitConverter.GetBytes(BitConverter.ToInt64(disk,rv)+delta),0,disk,rv,8);}else if(ty==3&&rv>=0&&rv+4<=sz){Buffer.BlockCopy(BitConverter.GetBytes(BitConverter.ToInt32(disk,rv)+(int)delta),0,disk,rv,4);}}o+=bs;}}
var skip=new bool[sz];int lcr=BitConverter.ToInt32(f,opt+192);if(lcr>0&&lcr+0xE8<sz&&BitConverter.ToInt32(disk,lcr)>=0xE8){int dvo=BitConverter.ToInt32(disk,lcr+0xE0),dvs=BitConverter.ToUInt16(disk,lcr+0xE4);if(dvs>0&&dvs<=ns){int t=sva[dvs-1]+dvo;if(t>0&&t+8<sz&&BitConverter.ToInt32(disk,t)==1){int end=Math.Min(t+8+BitConverter.ToInt32(disk,t+4),sz);int o=t+8;while(o+12<=end){long sym=BitConverter.ToInt64(disk,o);int bsz=BitConverter.ToInt32(disk,o+8);if(bsz<=0)break;int bb=o+12,be=Math.Min(bb+bsz,end);if(sym==7){if(bb+4<=be){int foe=Math.Min(bb+4+BitConverter.ToInt32(disk,bb),be);int q=bb+4;while(q+16<=foe){int rvasz=BitConverter.ToInt32(disk,q+8),brs=BitConverter.ToInt32(disk,q+12);if(rvasz<0||brs<0)break;int r0=q+16+rvasz;Blocks(disk,r0,Math.Min(r0+brs,foe),skip,4);q=r0+brs;}}}else{Blocks(disk,bb,be,skip,8);}o=be;}}}}
IntPtr h=OpenProcess(0x410,false,p);if(h==IntPtr.Zero)return res;try{var ok=new bool[(sz+0xFFF)/0x1000];var mem=ReadImg(h,b,sz,ok);foreach(var x in xs){int i=x[0],e2=x[0]+x[1];while(i<e2&&res.Count<200){if(!ok[i>>12]){i=((i>>12)+1)<<12;continue;}if(mem[i]==disk[i]||skip[i]){i++;continue;}int s0=i,last=i;while(i<e2&&i-last<8){if(ok[i>>12]&&mem[i]!=disk[i]&&!skip[i])last=i;i++;}int len=last-s0+1;string k=null;long t=0;int ub=0;for(int bk=0;bk<=4&&k==null;bk++){t=Jump(mem,s0-bk,b+s0-bk,h,out k);if(k!=null)ub=bk;}int sh=Math.Min(len,16);res.Add(new PT{A=b+s0-ub,L=len,T=t,K=k,M=BitConverter.ToString(mem,s0,sh),D=BitConverter.ToString(disk,s0,sh)});}}}finally{CloseHandle(h);}return res;}
static void Blocks(byte[] d,int bb,int be,bool[] skip,int w){while(bb+8<=be){int pg=BitConverter.ToInt32(d,bb),bs=BitConverter.ToInt32(d,bb+4);if(bs<8)break;for(int j=bb+8;j+2<=bb+bs&&j+2<=be;j+=2){int en=BitConverter.ToUInt16(d,j);if(en==0)continue;int s=pg+(en&0xFFF);for(int k=0;k<w;k++){if(s+k>=0&&s+k<skip.Length)skip[s+k]=true;}}bb+=bs;}}
public static long Follow(int p,long a){IntPtr h=OpenProcess(0x410,false,p);if(h==IntPtr.Zero)return a;try{var c=new byte[16];IntPtr r;for(int i=0;i<4;i++){if(!ReadProcessMemory(h,(IntPtr)a,c,(IntPtr)16,out r))break;string k;long t=Jump(c,0,a,h,out k);if(k==null||t==0)break;a=t;}}finally{CloseHandle(h);}return a;}
public static long[] Relays(int p,long b,int n){var res=new List<long>();IntPtr h=OpenProcess(0x410,false,p);if(h==IntPtr.Zero)return res.ToArray();try{var c=ReadImg(h,b,n,null);var q=new byte[8];IntPtr r;for(int i=0;i+6<=n&&res.Count<64;i++){if(c[i]!=0xFF||c[i+1]!=0x25)continue;long pp=b+i+6+BitConverter.ToInt32(c,i+2);long t=0;if(pp>=b&&pp+8<=b+n)t=BitConverter.ToInt64(c,(int)(pp-b));else if(ReadProcessMemory(h,(IntPtr)pp,q,(IntPtr)8,out r))t=BitConverter.ToInt64(q,0);if(t!=0&&!res.Contains(t))res.Add(t);}}finally{CloseHandle(h);}return res.ToArray();}
public static long ImgBase(int p,long a){IntPtr h=OpenProcess(0x400,false,p);if(h==IntPtr.Zero)return 0;try{MBI m;if(VirtualQueryEx(h,(IntPtr)a,out m,(UIntPtr)Marshal.SizeOf(typeof(MBI)))==UIntPtr.Zero)return 0;return m.Ty==0x1000000?m.Ab.ToInt64():0;}finally{CloseHandle(h);}}
public static List<HO> Holders(int target,out string err){err=null;var res=new List<HO>();IntPtr mine=OpenProcess(0x1000,false,target);if(mine==IntPtr.Zero){err="cannot open game process";return res;}IntPtr buf=IntPtr.Zero;try{int len=0x400000,ret,st;while(true){buf=Marshal.AllocHGlobal(len);st=NtQuerySystemInformation(64,buf,len,out ret);if(st==unchecked((int)0xC0000004)){Marshal.FreeHGlobal(buf);buf=IntPtr.Zero;len=Math.Max(len*2,ret+0x100000);continue;}break;}if(st!=0){err="NtQuerySystemInformation failed 0x"+st.ToString("X");return res;}long cnt=Marshal.ReadIntPtr(buf).ToInt64();long me=GetCurrentProcessId(),hv=mine.ToInt64(),bp=buf.ToInt64();IntPtr obj=IntPtr.Zero;for(long i=0;i<cnt;i++){var e=new IntPtr(bp+16+i*40);if(Marshal.ReadIntPtr(e,8).ToInt64()==me&&Marshal.ReadIntPtr(e,16).ToInt64()==hv){obj=Marshal.ReadIntPtr(e);break;}}if(obj==IntPtr.Zero){err="kernel object addresses are hidden - run as administrator";return res;}for(long i=0;i<cnt;i++){var e=new IntPtr(bp+16+i*40);if(Marshal.ReadIntPtr(e)!=obj)continue;long pid=Marshal.ReadIntPtr(e,8).ToInt64();if(pid==me||pid==target)continue;res.Add(new HO{P=(int)pid,A=(uint)Marshal.ReadInt32(e,24)});}}finally{if(buf!=IntPtr.Zero)Marshal.FreeHGlobal(buf);CloseHandle(mine);}return res;}
}}
'@};
if($adm){[void][JC2.N]::EnableDebug()};
$ps=if($env:JCHECK_PID){@(Get-Process -Id $env:JCHECK_PID)}else{@(Get-Process javaw,java -EA 0)};
$Out=New-Object Collections.Generic.List[object];$SigC=@{};$HashC=@{};
$getSig={param($x)if(!$SigC.ContainsKey($x)){$SigC[$x]=try{[string](Get-AuthenticodeSignature -LiteralPath $x -EA Stop).Status}catch{'CheckFailed'}};$SigC[$x]};
$getHash={param($x)if(!$HashC.ContainsKey($x)){$HashC[$x]=try{(Get-FileHash -LiteralPath $x -EA Stop).Hash}catch{''}};$HashC[$x]};
$fmod={param($x)try{(Get-Item -LiteralPath $x -Force -EA Stop).LastWriteTime.ToString('dd.MM.yyyy HH:mm:ss')}catch{'N/A'}};
$add={param($rk,$nm,$pa,$md,$why,$hs)$Out.Add([PSCustomObject]@{PID=[string]$cur;Risk=$rk;Name=$nm;Path=$pa;Modified=$md;Reasons=$why;SHA256=$hs})};
$hm='opengl32.dll','gdi32full.dll','gdi32.dll','glfw.dll','lwjgl.dll','lwjgl_opengl.dll','jvm.dll','java.dll','user32.dll','win32u.dll','kernelbase.dll','kernel32.dll','ntdll.dll','ws2_32.dll';
$gd='\\(\.minecraft|natives|\.tlauncher|PrismLauncher|MultiMC|ATLauncher|\.lunarclient|\.feather|CurseForge|Modrinth)';
$tmp=[IO.Path]::GetTempPath();$bd=@($tmp,"$env:USERPROFILE\Downloads\","$env:USERPROFILE\Desktop\","$env:PUBLIC\");
$rx='^(jna-?\d+|libtmp\d+junixsocket-native-[\d.]+|sqlite-[\d.]+-.+|netty_\w+|libzstd-jni.*|liblz4-java.*)\.dll$';
$known='^(lwjgl|glfw|openal|jemalloc|jinput|jvm|java|jli|jimage|jsvml|net|nio|zip|verify|awt|fontmanager|freetype|lcms|mlib_image|javajpeg|management|prefs|sunmscapi|jsound|jaas|j2pkcs11|sunec|extnet|rmi|w2k_lsa_auth|splashscreen|jawt)';
$mk=[ordered]@{'^lwjgl'='Java_org_lwjgl_';'^glfw'='glfw';'^openal'='alc';'^jemalloc'='je_';'^freetype'='FT_';'^jvm\.dll$'='JNI_CreateJavaVM';'^jli\.dll$'='JLI_';'^jna-?\d+\.dll$'='Java_com_sun_jna_';'junixsocket'='Java_org_newsclub_'};
$KnownHash=@{'5A7FF949F6D93D86491EB5B26B1CFC60051168A60622650224B89995AC420023'='JNA';'D3335E589BF1C3E2D2F55F6550E5DE173B776CFAA077B235E4C69523F0071726'='junixsocket-native 2.9.0'};
$sysProc='^(csrss|lsass|svchost|wininit|services|smss|System|MsMpEng|NisSrv|SecurityHealthService|MpDefenderCoreService|WmiPrvSE|audiodg)$';
$vulnDrv='^(iqvw64e|gdrv|rtcore64|dbutil_2_3|asrdrv\d*|kprocesshacker|winring0x?64|mhyprot\d*|capcom|aswarpot|zam64|zamguard64)\.sys$';
if(!$ps){Write-Host "Java not found" -F Red};
foreach($p in $ps){
$cur=$p.Id;$exe=$null;$st=$null;try{$exe=$p.Path}catch{};try{$st=$p.StartTime}catch{};
$jh=if($exe){Split-Path(Split-Path $exe)};
$ci=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)";$cmd=[string]$ci.CommandLine;
$role=if($cmd -match 'net\.minecraft|fabric|forge|quilt|--gameDir'){' (game)'}else{' (launcher)'};
Write-Host "`n$($p.ProcessName) PID $($p.Id) | $exe | started $st$role" -F Cyan;
try{$ms=@($p.Modules)}catch{Write-Host "  Cannot read modules: $($_.Exception.Message)" -F Red;continue};
$whereM={param([long]$a)foreach($x in $ms){$b=$x.BaseAddress.ToInt64();if($a -ge $b -and $a -lt $b+$x.ModuleMemorySize){return $x}};$ib=[JC2.N]::ImgBase($p.Id,$a);if($ib){foreach($x in $ms){if($x.BaseAddress.ToInt64() -eq $ib){return $x}}};$null};
foreach($x in [regex]::Matches($cmd,'-(javaagent|agentpath|agentlib)[:=]\S+')){&$add 'High' 'Java agent' $x.Value $null 'Java agent in command line' $null};
foreach($m in $ms|?{$_.ModuleName -match '^(instrument|attach)\.dll$'}){&$add 'High' $m.ModuleName $m.FileName $null 'Java agent attached (Attach API / -javaagent)' $null};
foreach($m in $ms){
$fp=$m.FileName;if(!$fp -or $m.ModuleName -match '^(instrument|attach)\.dll$'){continue};
$ex=Test-Path -LiteralPath $fp;$sg=if($ex){&$getSig $fp}else{'FileMissing'};if($sg -eq 'Valid'){continue};
$it=if($ex){Get-Item -LiteralPath $fp -Force};$k=$m.ModuleName -match $known;
$ok=($jh -and $fp.StartsWith($jh,'OrdinalIgnoreCase')) -or $fp -match $gd;
$bad=[bool]($bd|?{$fp.StartsWith($_,'OrdinalIgnoreCase')});
$nw=$st -and $it -and ($it.LastWriteTime -gt $st -or $it.CreationTime -gt $st);
$oe=[IO.Path]::GetExtension($fp) -notin '.dll','.exe';
$rt=$m.ModuleName -match $rx -and ($fp -match '\\natives\\|\\jna-\d+\\' -or $fp.StartsWith($tmp,'OrdinalIgnoreCase'));
$hs=if($ex){&$getHash $fp}else{''};$kh=$KnownHash[$hs];
$why=@(if($ex){$sg}else{'file deleted after load'});$fake=$false;$mkr=$null;
foreach($re in $mk.Keys){if($m.ModuleName -match $re){$mkr=$mk[$re];break}};
if($mkr -and !$kh){$exn=@([JC2.N]::Exports($p.Id,$m.BaseAddress.ToInt64(),$m.ModuleMemorySize)|%{$_.N});if(!($exn|?{$_.StartsWith($mkr)})){$fake=$true;$why+="named like a Java/LWJGL library but has no $mkr* exports"}};
if($kh){$why+="known build ($kh)"}elseif($rt){$why+='runtime-extracted Java library'}else{if($bad){$why+='suspicious dir'};if($nw){$why+='modified after process start'};if($oe){$why+='odd extension'};if($k -and !$fake){$why+='known Java/LWJGL native'}};
$rk=if($fake){'High'}elseif($kh -or $rt){'Low'}elseif(!$ex -or $oe -or ($bad -and !$k) -or ($nw -and !$k)){'High'}elseif($k -and ($ok -or $bad)){'Low'}else{'Medium'};
&$add $rk $m.ModuleName $fp $(if($it){$it.LastWriteTime.ToString('dd.MM.yyyy HH:mm:ss')}else{'N/A'}) ($why -join '; ') $(if($rk -ne 'Low'){$hs});
};
foreach($th in $p.Threads){$s=[JC2.N]::TS($th.Id);if($s -and !(&$whereM $s)){&$add 'High' "TID $($th.Id)" ('start 0x{0:X}' -f $s) $null 'thread starts outside any module' $null}};
try{foreach($a in [JC2.N]::Mem($p.Id)){$loc='0x{0:X} ({1}, {2:N0} KB, exec {3:N0} KB)' -f $a.B,$a.T,($a.S/1KB),($a.X/1KB);if($a.Pe -and ($a.T -eq 'Private' -or $a.X)){&$add 'High' 'Hidden PE image' $loc $null 'PE image in memory not in module list (manual map)' $null}elseif(!$a.Pe -and $a.J){$rel=@([JC2.N]::Relays($p.Id,$a.B,[int][math]::Min($a.S,0x10000)));$rm=@($rel|%{&$whereM $_});$uns=@($rm|?{(&$getSig $_.FileName) -ne 'Valid'});if($rel.Count -and $rm.Count -eq $rel.Count -and !$uns.Count){&$add 'Low' 'Executable memory' $loc $null ('hook trampolines leading into signed {0} (overlays like Discord/Steam/OBS do this)' -f (($rm|%{$_.ModuleName}|select -Unique) -join ', ')) $null}else{$tail=if($uns.Count){'; jumps into unsigned '+(($uns|%{$_.ModuleName}|select -Unique) -join ', ')}else{''};&$add 'Medium' 'Executable memory' $loc $null (('{0:N0} KB of RX memory outside modules (JVM JIT uses RWX, injected code is usually RX)' -f ($a.J/1KB))+$tail) $null}}}}catch{Write-Host "  Memory scan failed: $($_.Exception.Message)" -F Yellow};
foreach($m in $ms|?{$hm -contains $_.ModuleName.ToLower()}){
if(!(Test-Path -LiteralPath $m.FileName)){continue};
try{$pts=[JC2.N]::TextDiff($p.Id,$m.BaseAddress.ToInt64(),$m.ModuleMemorySize,$m.FileName)}catch{continue};
if(!$pts.Count){continue};
$exl=@([JC2.N]::Exports($p.Id,$m.BaseAddress.ToInt64(),$m.ModuleMemorySize)|sort R);
foreach($pt in $pts){
$off=$pt.A-$m.BaseAddress.ToInt64();$fn=$exl|?{$_.R -le $off}|select -Last 1;
$nm=if($fn){'{0}!{1}+0x{2:X}' -f $m.ModuleName,$fn.N,($off-$fn.R)}else{'{0}+0x{1:X}' -f $m.ModuleName,$off};
$tm=if($pt.T){&$whereM $pt.T}else{$null};$pd="mem $($pt.M) | disk $($pt.D)";$via='';
if($pt.T -and !$tm){$fin=[JC2.N]::Follow($p.Id,$pt.T);$tm=&$whereM $fin;if($tm){$via=' via trampoline'}};
if($pt.T -and !$tm){&$add 'High' $nm $pd $null ('code patched: {0} -> 0x{1:X} outside any module (hook)' -f $pt.K,$pt.T) $null}elseif($tm){$ts=&$getSig $tm.FileName;if($ts -eq 'Valid'){&$add 'Low' $nm $pd $null "code patched to jump$via into signed $($tm.ModuleName) (overlays like Discord/Steam/OBS do this)" $null}else{&$add 'High' $nm $pd $null "code patched to jump$via into unsigned $($tm.ModuleName) ($($tm.FileName))" $null}}else{&$add 'Medium' $nm $pd $null "$($pt.L) bytes of code differ from the file on disk" $null};
};
};
if($adm){
$herr=$null;$hl=[JC2.N]::Holders($p.Id,[ref]$herr);if($herr){Write-Host "  Handle check: $herr" -F Yellow};
foreach($g in ($hl|Group-Object P)){
$hp=[int]$g.Name;$acc=0L;foreach($e in $g.Group){$acc=$acc -bor $e.A};
if(!($acc -band 0x3A)){continue};
$hpr=Get-Process -Id $hp -EA 0;$hn=if($hpr){$hpr.ProcessName}else{"PID $hp"};if($hn -match $sysProc){continue};
$hpath=$null;try{$hpath=$hpr.Path}catch{};
$fl=@();if($acc -band 0x20){$fl+='VM_WRITE'};if($acc -band 0x8){$fl+='VM_OPERATION'};if($acc -band 0x2){$fl+='CREATE_THREAD'};if($acc -band 0x10){$fl+='VM_READ'};
$hsg=if($hpath){&$getSig $hpath}else{'Unknown'};$dang=$acc -band 0x2A;
$hrk=if($hp -eq $ci.ParentProcessId -or $hn -match '^javaw?$'){'Low'}elseif($hsg -eq 'Valid'){if($dang){'Medium'}else{'Low'}}elseif($dang){'High'}else{'Medium'};
$hwhy="open handle to the game: $($fl -join ', '); signature $hsg";if($hrk -eq 'Low' -and $hp -eq $ci.ParentProcessId){$hwhy+='; parent launcher (normal)'};
&$add $hrk "$hn (PID $hp)" $(if($hpath){$hpath}else{'path unavailable'}) $(if($hpath){&$fmod $hpath}else{$null}) $hwhy $(if($hrk -ne 'Low' -and $hpath){&$getHash $hpath});
};
};
};
$cur='SYS';
$sso=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -EA 0).SystemStartOptions;
if($sso -match 'TESTSIGNING'){&$add 'High' 'Test-signing mode' $sso.Trim() $null 'Windows test-signing is on: unsigned kernel drivers can be loaded' $null};
if($sso -match 'DISABLE_INTEGRITY_CHECKS'){&$add 'High' 'Integrity checks disabled' $sso.Trim() $null 'driver signature enforcement is disabled' $null};
foreach($dv in @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -EA 0)){
$dp=[string]$dv.PathName;if(!$dp){continue};$dp=$dp.Trim('"') -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\',"$env:windir\" -replace '^system32\\',"$env:windir\System32\";
$dn=Split-Path $dp -Leaf;
if(!(Test-Path -LiteralPath $dp)){&$add 'Medium' $dn $dp $null 'running kernel driver, file not found on disk' $null;continue};
$ds=&$getSig $dp;
if($ds -ne 'Valid'){&$add 'High' $dn $dp (&$fmod $dp) "kernel driver not validly signed ($ds)" (&$getHash $dp)}elseif($dn -match $vulnDrv){&$add 'Medium' $dn $dp (&$fmod $dp) 'signed driver often abused to load kernel cheats (also used by some legit tools)' $null};
};
if(!$Out.Count){Write-Host "`nNo suspicious findings" -F Green}else{
$cl=@{High='Red';Medium='Yellow';Low='DarkGray'};$od=@{High=0;Medium=1;Low=2};Write-Host "";
$Out|sort {$od[$_.Risk]},PID,Name|%{$mt=if($_.Modified){"  modified $($_.Modified)"}else{''};Write-Host "[$($_.Risk)] [$($_.PID)] $($_.Name)$mt" -F $cl[$_.Risk];Write-Host "    $($_.Path)";Write-Host "    -> $($_.Reasons)" -F DarkGray;if($_.SHA256){Write-Host "    SHA256 $($_.SHA256)" -F DarkGray}};
Write-Host ("`nHigh {0} | Medium {1} | Low {2}" -f @($Out|?{$_.Risk -eq 'High'}).Count,@($Out|?{$_.Risk -eq 'Medium'}).Count,@($Out|?{$_.Risk -eq 'Low'}).Count) -F Cyan;
};
};
try{$hfile=(Get-PSReadLineOption).HistorySavePath;if($hfile -and (Test-Path -LiteralPath $hfile)){$keep=@(Get-Content -LiteralPath $hfile|?{$_ -notmatch 'githubusercontent|JC2\.N'});Set-Content -LiteralPath $hfile $keep -Encoding UTF8};[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()}catch{}
