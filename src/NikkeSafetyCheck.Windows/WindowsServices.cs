using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using NikkeSafetyCheck.Core;

namespace NikkeSafetyCheck.Windows;

public sealed class WindowsRegistryStore : IRegistryStore
{
    private static string Relative(string path)
    {
        if (!path.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("이 프로그램은 사용자 하이브 밖의 레지스트리를 다루지 않습니다.");
        return path[4..];
    }

    public RegistryKeySnapshot? Read(string path)
    {
        try
        {
            using var k = Registry.Users.OpenSubKey(Relative(path), false);
            if (k is null) return null;
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var n in k.GetValueNames())
                values[n] = k.GetValue(n, "", RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
            return new RegistryKeySnapshot(values, k.GetSubKeyNames());
        }
        catch (SecurityException e) { throw new UnauthorizedAccessException(e.Message, e); }
    }

    public bool IsHiveLoaded(string hiveName)
    {
        try { return Registry.Users.GetSubKeyNames().Contains(hiveName, StringComparer.OrdinalIgnoreCase); }
        catch (SecurityException e) { throw new UnauthorizedAccessException(e.Message, e); }
    }

    public IReadOnlyList<string> ListSubKeys(string path)
    {
        try
        {
            using var k = Registry.Users.OpenSubKey(Relative(path), false);
            return k?.GetSubKeyNames() ?? [];
        }
        catch (SecurityException e) { throw new UnauthorizedAccessException(e.Message, e); }
    }

    public void DeleteEmptyKey(string path)
    {
        var rel = Relative(path);
        var i = rel.LastIndexOf('\\');
        try
        {
            using var parent = Registry.Users.OpenSubKey(rel[..i], true) ?? throw new IOException("상위 키를 찾을 수 없습니다.");
            // DeleteSubKey는 하위 키가 있으면 실패한다. 트리 삭제 API는 쓰지 않는다.
            parent.DeleteSubKey(rel[(i + 1)..], throwOnMissingSubKey: false);
        }
        catch (SecurityException e) { throw new UnauthorizedAccessException(e.Message, e); }
    }
}

public static class TargetUserResolver
{
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);
    private const int WTS_CURRENT_SESSION = -1, WTSUserName = 5, WTSDomainName = 7;

    private static string? SessionString(int cls)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, WTS_CURRENT_SESSION, cls, out var p, out _)) return null;
        try { return Marshal.PtrToStringUni(p); } finally { WTSFreeMemory(p); }
    }

    /// <summary>
    /// 로그인 세션의 소유자를 대상으로 잡는다. UAC에서 다른 관리자 계정을 입력해 실행해도 그 계정의 프로필을 검사하지 않는다.
    /// </summary>
    public static TargetUser Resolve()
    {
        using var me = WindowsIdentity.GetCurrent();
        var mySid = me.User!.Value;
        var myName = me.Name;
        var sid = mySid; var name = myName;
        try
        {
            var u = SessionString(WTSUserName); var d = SessionString(WTSDomainName);
            if (!string.IsNullOrEmpty(u))
            {
                var acct = new NTAccount(string.IsNullOrEmpty(d) ? u : $@"{d}\{u}");
                sid = ((SecurityIdentifier)acct.Translate(typeof(SecurityIdentifier))).Value;
                name = u;
            }
        }
        catch (Exception e) when (e is IdentityNotMappedException or SystemException) { }

        var same = sid.Equals(mySid, StringComparison.OrdinalIgnoreCase);
        var shortName = name.Contains('\\') ? name[(name.LastIndexOf('\\') + 1)..] : name;
        if (same)
        {
            return new TargetUser(sid, shortName, Environment.MachineName,
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Path.TrimEndingDirectorySeparator(Path.GetTempPath()), true, myName);
        }
        using var pl = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        var profile = pl?.GetValue("ProfileImagePath")?.ToString() ?? Path.Combine(@"C:\Users", shortName);
        return new TargetUser(sid, shortName, Environment.MachineName, profile,
            Path.Combine(profile, "AppData", "Local"), Path.Combine(profile, "AppData", "Roaming"),
            Path.Combine(profile, "AppData", "Local", "Temp"), false, myName);
    }
}

public sealed class WindowsSignatureChecker : IFileSignatureChecker
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FileInfoData { public int cbStruct; public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public int cbStruct; public IntPtr pPolicyCallbackData, pSIPClientData; public int dwUIChoice, fdwRevocationChecks, dwUnionChoice;
        public IntPtr pFile; public int dwStateAction; public IntPtr hWVTStateData, pwszURLReference; public int dwProvFlags, dwUIContext; public IntPtr pSignatureSettings;
    }
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref TrustData data);

    /// <summary>파일을 불러오지 않고 서명만 검증한다. 네트워크 조회를 하지 않도록 캐시만 사용한다.</summary>
    public SignatureState Check(string path)
    {
        var info = new FileInfoData { cbStruct = Marshal.SizeOf<FileInfoData>(), pcwszFilePath = path };
        var pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfoData>());
        try
        {
            Marshal.StructureToPtr(info, pInfo, false);
            var d = new TrustData
            {
                cbStruct = Marshal.SizeOf<TrustData>(), dwUIChoice = 2 /*NONE*/, fdwRevocationChecks = 0, dwUnionChoice = 1 /*FILE*/,
                pFile = pInfo, dwStateAction = 1 /*VERIFY*/, dwProvFlags = 0x00001000 /*CACHE_ONLY_URL_RETRIEVAL*/,
            };
            var action = GenericVerifyV2;
            var r = WinVerifyTrust(new IntPtr(-1), ref action, ref d);
            d.dwStateAction = 2; // CLOSE
            WinVerifyTrust(new IntPtr(-1), ref action, ref d);
            return (uint)r switch
            {
                0 => SignatureState.Valid,
                0x800B0100 => SignatureState.Unsigned, // TRUST_E_NOSIGNATURE
                0x800B0003 or 0x800B0001 => SignatureState.Unsigned, // SUBJECT_FORM_UNKNOWN, PROVIDER_UNKNOWN
                _ => SignatureState.Invalid,
            };
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { return SignatureState.Unknown; }
        finally { Marshal.DestroyStructure<FileInfoData>(pInfo); Marshal.FreeHGlobal(pInfo); }
    }
}

public sealed class WindowsFileIdProvider : IFileIdentityProvider
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandle
    {
        public uint Attr; public System.Runtime.InteropServices.ComTypes.FILETIME C, A, W;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetFileInformationByHandle(SafeFileHandle h, out ByHandle info);

    public string? GetFileId(string path)
    {
        try
        {
            using var h = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return GetFileInformationByHandle(h, out var i) ? $"{i.VolumeSerial:x8}-{i.IndexHigh:x8}{i.IndexLow:x8}" : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }
}

public sealed class WindowsFileProtector : IFileProtector
{
    /// <summary>격리 파일은 소유자 읽기·삭제만 허용하고 실행 권한은 주지 않는다.</summary>
    public void ProtectForQuarantine(string path)
    {
        using var me = WindowsIdentity.GetCurrent();
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(true, false);
        sec.AddAccessRule(new FileSystemAccessRule(me.User!, FileSystemRights.Read | FileSystemRights.Delete | FileSystemRights.ChangePermissions, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.Read | FileSystemRights.Delete, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(sec);
    }

    public void RestrictToCurrentUser(string directory)
    {
        using var me = WindowsIdentity.GetCurrent();
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(true, false);
        const InheritanceFlags inh = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(me.User!, FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(sec);
    }
}

public sealed class WindowsProcessInspector : IProcessInspector
{
    public IReadOnlyList<RunningProcess> FindByNames(IEnumerable<string> names)
    {
        var res = new List<RunningProcess>();
        foreach (var n in names)
            foreach (var p in Process.GetProcessesByName(n))
            {
                using (p)
                {
                    string? path = null;
                    try { path = p.MainModule?.FileName; } catch (Exception e) when (e is Win32Exception or InvalidOperationException or NotSupportedException) { }
                    res.Add(new RunningProcess(p.Id, n, path));
                }
            }
        return res;
    }

    public ModuleInspection FindLoadedModule(string moduleFileName, CancellationToken ct)
    {
        var hits = new List<LoadedModuleHit>();
        var denied = 0;
        var session = Process.GetCurrentProcess().SessionId;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (p.Id == Environment.ProcessId || p.SessionId != session) continue;
                    foreach (ProcessModule m in p.Modules)
                        using (m)
                            if (Path.GetFileName(m.FileName).Equals(moduleFileName, StringComparison.OrdinalIgnoreCase))
                                hits.Add(new LoadedModuleHit(p.Id, p.ProcessName, m.FileName));
                }
                catch (Exception e) when (e is Win32Exception or InvalidOperationException or NotSupportedException) { denied++; }
            }
        }
        return new ModuleInspection(hits, denied);
    }
}

internal static class PowerShell
{
    private static string Exe => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    /// <summary>코드에 고정된 명령만 실행한다. 외부 입력을 명령 문자열에 넣지 않는다.</summary>
    public static async Task<(int Exit, string Out)> RunFixedAsync(string fixedScript, TimeSpan? timeout, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(Exe)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        // 사용자 폴더의 모듈이 Defender 명령을 가로채지 못하도록 시스템 모듈 경로만 쓴다.
        psi.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");
        psi.ArgumentList.Add("-NoProfile"); psi.ArgumentList.Add("-NonInteractive"); psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; " + fixedScript);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell을 시작할 수 없습니다.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeout is not null) cts.CancelAfter(timeout.Value);
        var o = p.StandardOutput.ReadToEndAsync(cts.Token);
        var err = p.StandardError.ReadToEndAsync(cts.Token);
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) { try { p.Kill(true); } catch (Exception e) when (e is Win32Exception or InvalidOperationException) { } throw; }
        return (p.ExitCode, await o);
    }
}

public sealed class WindowsNetworkInspector : INetworkInspector
{
    public IReadOnlyList<string> FindConnections(IEnumerable<string> ips)
    {
        var set = ips.Select(IPAddress.Parse).ToHashSet();
        return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
            .Where(c => set.Contains(c.RemoteEndPoint.Address)).Select(c => c.RemoteEndPoint.Address.ToString()).Distinct().ToList();
    }

    public IReadOnlyList<string>? FindDnsCacheEntries(IEnumerable<string> domains)
    {
        try
        {
            var (exit, o) = PowerShell.RunFixedAsync("Get-DnsClientCache | Select-Object -ExpandProperty Entry | ConvertTo-Json -Compress", TimeSpan.FromSeconds(20), default).GetAwaiter().GetResult();
            if (exit != 0) return null;
            var set = domains.ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(o)) return [];
            using var d = JsonDocument.Parse(o);
            var names = d.RootElement.ValueKind == JsonValueKind.Array ? d.RootElement.EnumerateArray().Select(e => e.GetString()) : [d.RootElement.GetString()];
            return names.Where(n => n is not null && set.Contains(n)).Distinct().ToList()!;
        }
        catch (Exception e) when (e is IOException or JsonException or OperationCanceledException or Win32Exception or InvalidOperationException) { return null; }
    }
}

public sealed class WindowsInstallHints(TargetUser target) : IInstallHintSource
{
    public IEnumerable<string> GetFixedDriveRoots()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            bool ok;
            try { ok = d.DriveType == DriveType.Fixed && d.IsReady; } catch (IOException) { ok = false; }
            if (ok) yield return d.RootDirectory.FullName;
        }
    }

    public IEnumerable<InstallHint> GetHints(CancellationToken ct)
    {
        var res = new List<InstallHint>();
        foreach (var p in new WindowsProcessInspector().FindByNames(["nikke_launcher", "nikke", "nikke_launcher_hmt"]))
            if (p.Path is not null) res.Add(new InstallHint(p.Path, "실행 중인 프로세스 경로"));

        void Uninstall(RegistryKey? root, string label)
        {
            if (root is null) return;
            using (root)
                foreach (var name in root.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var k = root.OpenSubKey(name);
                        var display = k?.GetValue("DisplayName")?.ToString() ?? "";
                        var publisher = k?.GetValue("Publisher")?.ToString() ?? "";
                        // 여기서는 경로 후보만 모은다. 실제 검사 대상은 폴더 구조가 일치해야 하므로 설치만으로 판정되지 않는다.
                        var related = display.Contains("nikke", StringComparison.OrdinalIgnoreCase) || display.Contains("니케", StringComparison.Ordinal)
                            || name.Contains("nikke", StringComparison.OrdinalIgnoreCase)
                            || new[] { "Level Infinite", "Proxima", "Tencent" }.Any(x => publisher.Contains(x, StringComparison.OrdinalIgnoreCase));
                        if (!related) continue;
                        foreach (var v in new[] { "GameInstallPath", "InstallLocation", "InstallDir", "UninstallString", "DisplayIcon" })
                            if (k?.GetValue(v)?.ToString() is { Length: > 0 } s) res.Add(new InstallHint(s, label));
                    }
                    catch (Exception e) when (e is SecurityException or IOException or UnauthorizedAccessException) { }
                }
        }
        const string U = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        try
        {
            Uninstall(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(U), "설치 정보(64비트)");
            Uninstall(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32).OpenSubKey(U), "설치 정보(32비트)");
            Uninstall(Registry.Users.OpenSubKey($@"{target.Sid}\{U}"), "사용자 설치 정보");
        }
        catch (Exception e) when (e is SecurityException or IOException or UnauthorizedAccessException) { }

        // 런처가 스스로 기록해 두는 설치 경로. 값은 경로로만 해석하고 실행하지 않는다.
        void Value(RegistryKey? root, string sub, string? name, string label)
        {
            if (root is null) return;
            try
            {
                using (root)
                using (var k = root.OpenSubKey(sub))
                    if (k?.GetValue(name)?.ToString() is { Length: > 0 } s) res.Add(new InstallHint(s, label));
            }
            catch (Exception e) when (e is SecurityException or IOException or UnauthorizedAccessException) { }
        }
        const string AppPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\nikke_launcher.exe";
        Value(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), AppPath, null, "앱 경로 등록");
        Value(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32), AppPath, null, "앱 경로 등록");
        Value(RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default), $@"{target.Sid}\{AppPath}", null, "앱 경로 등록");
        Value(RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default), $@"{target.Sid}_Classes\nikkelauncher\DefaultIcon", null, "런처 주소 등록");
        Value(RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default), $@"{target.Sid}_Classes\nikkelauncher\Shell\Open\Command", null, "런처 주소 등록");
        foreach (var data in PathSafety.NikkeDataNames)
        {
            var reg = Path.Combine(target.RoamingAppData, data, "url_protocol.reg");
            try
            {
                if (File.Exists(reg) && new FileInfo(reg).Length < 1 << 20)
                    foreach (var p in InstallLocator.PathsInRegText(File.ReadAllText(reg))) res.Add(new InstallHint(p, "런처 기록 파일"));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }

        try { res.AddRange(ReadShortcuts(ct)); }
        catch (Exception e) when (e is COMException or IOException or UnauthorizedAccessException or InvalidOperationException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException) { }
        return res;
    }

    private IEnumerable<InstallHint> ReadShortcuts(CancellationToken ct)
    {
        var dirs = new[]
        {
            Path.Combine(target.ProfileDir, "Desktop"),
            Path.Combine(target.ProfileDir, "OneDrive", "Desktop"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Path.Combine(target.RoamingAppData, "Microsoft", "Windows", "Start Menu", "Programs"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
        };
        var res = new List<InstallHint>();
        var type = Type.GetTypeFromProgID("WScript.Shell");
        if (type is null) return res;
        dynamic shell = Activator.CreateInstance(type)!;
        var opts = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 3, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var d in dirs.Where(Directory.Exists))
            foreach (var lnk in Directory.EnumerateFiles(d, "*.lnk", opts).Take(2000))
            {
                ct.ThrowIfCancellationRequested();
                var n = Path.GetFileName(lnk);
                if (!n.Contains("nikke", StringComparison.OrdinalIgnoreCase) && !n.Contains("니케", StringComparison.Ordinal)) continue;
                // CreateShortcut은 .lnk를 읽기만 한다. 대상을 실행하지 않는다.
                dynamic sc = shell.CreateShortcut(lnk);
                string target0 = sc.TargetPath;
                if (!string.IsNullOrWhiteSpace(target0)) res.Add(new InstallHint(target0, "바로가기 대상"));
            }
        return res;
    }
}

public sealed class WindowsDefenderService : IDefenderService
{
    public DefenderStatus Query()
    {
        var others = new List<string>();
        var active = false; var queried = false; var summary = "Microsoft Defender 상태를 확인하지 못했습니다.";
        try
        {
            var (exit, o) = PowerShell.RunFixedAsync("Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress", TimeSpan.FromSeconds(30), default).GetAwaiter().GetResult();
            if (exit == 0 && o.Trim().Length > 0)
            {
                using var d = JsonDocument.Parse(o);
                var mode = d.RootElement.TryGetProperty("AMRunningMode", out var m) ? m.GetString() ?? "" : "";
                var enabled = d.RootElement.TryGetProperty("AntivirusEnabled", out var e) && e.ValueKind == JsonValueKind.True;
                active = enabled && mode.Equals("Normal", StringComparison.OrdinalIgnoreCase);
                queried = true;
                summary = active ? "Microsoft Defender가 기본 백신으로 동작 중입니다." : $"Microsoft Defender가 기본 백신이 아닙니다(상태: {(mode.Length > 0 ? mode : "알 수 없음")}).";
            }
        }
        catch (Exception e) when (e is IOException or JsonException or OperationCanceledException or Win32Exception or InvalidOperationException) { }
        try
        {
            var (exit, o) = PowerShell.RunFixedAsync(@"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName | ConvertTo-Json -Compress", TimeSpan.FromSeconds(20), default).GetAwaiter().GetResult();
            if (exit == 0 && o.Trim().Length > 0)
            {
                using var d = JsonDocument.Parse(o);
                var names = d.RootElement.ValueKind == JsonValueKind.Array ? d.RootElement.EnumerateArray().Select(x => x.GetString()) : [d.RootElement.GetString()];
                others.AddRange(names.Where(n => !string.IsNullOrEmpty(n) && !n!.Contains("Defender", StringComparison.OrdinalIgnoreCase))!);
            }
        }
        catch (Exception e) when (e is IOException or JsonException or OperationCanceledException or Win32Exception or InvalidOperationException) { }
        return new DefenderStatus(active, summary, others, queried);
    }

    public async Task<NetworkActionResult> RunScanAsync(bool full, CancellationToken ct)
    {
        try
        {
            var (exit, _) = await PowerShell.RunFixedAsync(full ? "Start-MpScan -ScanType FullScan" : "Start-MpScan -ScanType QuickScan", null, ct);
            return exit == 0
                ? new NetworkActionResult(true, "검사가 끝났습니다. 발견 여부는 Windows 보안 > 바이러스 및 위협 방지 > 보호 기록에서 확인하세요. 미탐지여도 위 증거가 취소되지는 않습니다.")
                : new NetworkActionResult(false, "검사를 시작하거나 마치지 못했습니다. Windows 보안 화면에서 직접 실행하세요.");
        }
        catch (OperationCanceledException) { return new NetworkActionResult(false, "검사 대기를 취소했습니다. 검사 자체는 계속될 수 있으니 Windows 보안에서 확인하세요."); }
        catch (Exception e) when (e is IOException or Win32Exception or InvalidOperationException) { return new NetworkActionResult(false, "검사를 시작하지 못했습니다. Windows 보안 화면에서 직접 실행하세요."); }
    }

    public static async Task<NetworkActionResult> StartOfflineFromElevatedAsync()
    {
        var (exit, _) = await PowerShell.RunFixedAsync("Start-MpWDOScan", TimeSpan.FromMinutes(2), default);
        return exit == 0 ? new NetworkActionResult(true, "오프라인 검사를 예약했습니다. PC가 곧 다시 시작됩니다.") : new NetworkActionResult(false, "오프라인 검사를 시작하지 못했습니다.");
    }
}

public static class WindowsPlatform
{
    public static PlatformServices Create(TargetUser t) => new(new WindowsRegistryStore(), new WindowsSignatureChecker(), new WindowsFileIdProvider(), new WindowsProcessInspector(), new WindowsNetworkInspector(), new WindowsInstallHints(t));
}
