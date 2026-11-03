using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NikkeSafetyCheck.Core;

namespace NikkeSafetyCheck.Windows;

/// <summary>관리자 권한으로 실행되는 예방 설정. 방화벽 규칙과 hosts의 앱 소유 부분만 다룬다.</summary>
public sealed class NetworkBlockService(string? hostsPathOverride = null)
{
    private const string Group = "NikkeSafetyCheck";
    private const string IpRulePrefix = "NikkeSafetyCheck-KnownIp-";
    private const string LauncherRulePrefix = "NikkeSafetyCheck-Launcher-";
    private const int Outbound = 2, Block = 0, ProfilesAll = 0x7FFFFFFF;

    public string HostsPath => hostsPathOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    private static dynamic Policy() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ?? throw new InvalidOperationException("방화벽 구성 요소를 찾을 수 없습니다."))!;

    private static bool RuleExists(dynamic rules, string name)
    {
        foreach (dynamic r in rules) if ((string)r.Name == name) return true;
        return false;
    }

    /// <summary>이름만 보지 않고 실제 내용까지 맞는지 확인한다.</summary>
    private static bool RuleMatches(dynamic rules, string name, string? remoteIp, string? program)
    {
        foreach (dynamic r in rules)
        {
            if ((string)r.Name != name) continue;
            if ((bool)r.Enabled != true || (int)r.Action != Block || (int)r.Direction != Outbound) return false;
            if (remoteIp is not null && !((string)r.RemoteAddresses).StartsWith(remoteIp, StringComparison.Ordinal)) return false;
            if (program is not null && !string.Equals((string)r.ApplicationName, program, StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }
        return false;
    }

    private static void AddRule(dynamic policy, string name, string description, string? remoteIp, string? program)
    {
        dynamic rules = policy.Rules;
        if (RuleMatches(rules, name, remoteIp, program)) return;
        // 이름은 이 앱 소유다. 누군가 내용을 바꿨거나 꺼 두었으면 다시 만든다.
        if (RuleExists(rules, name)) rules.Remove(name);
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        rule.Name = name; rule.Description = description; rule.Grouping = Group;
        rule.Direction = Outbound; rule.Action = Block; rule.Enabled = true; rule.Profiles = ProfilesAll;
        if (remoteIp is not null) rule.RemoteAddresses = remoteIp;
        if (program is not null) rule.ApplicationName = program;
        rules.Add(rule);
    }

    /// <summary>방화벽이 꺼져 있거나 정책이 로컬 규칙을 무시하면 '적용 실패'로 알린다. 서비스를 강제로 켜지 않는다.</summary>
    private static string? EffectiveProblem(dynamic policy)
    {
        try
        {
            int current = policy.CurrentProfileTypes;
            foreach (var p in new[] { 1, 2, 4 })
                if ((current & p) != 0 && !(bool)policy.FirewallEnabled[p]) return "Windows 방화벽이 꺼져 있어 규칙이 동작하지 않습니다. 다른 방화벽을 쓰고 있다면 그 제품에서 차단하세요.";
            int state = policy.LocalPolicyModifyState;
            if (state != 0) return "조직 정책 때문에 이 PC의 방화벽 규칙이 적용되지 않을 수 있습니다.";
        }
        catch (Exception e) when (e is COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException) { return "방화벽 적용 상태를 확인하지 못했습니다."; }
        return null;
    }

    public NetworkActionResult BlockKnown(IocData ioc)
    {
        var msgs = new List<string>();
        var ok = true;
        try
        {
            var policy = Policy();
            foreach (var ip in ioc.BlockIps) AddRule(policy, IpRulePrefix + ip, "NIKKE PC 안전 점검 도우미(비공식)가 추가한 알려진 지표 IP 차단", ip, null);
            var problem = EffectiveProblem(policy);
            var verified = ioc.BlockIps.All(ip => (bool)RuleMatches(policy.Rules, IpRulePrefix + ip, ip, null));
            if (!verified) { ok = false; msgs.Add("방화벽 규칙을 확인하지 못했습니다."); }
            else if (problem is not null) { ok = false; msgs.Add(problem); }
            else msgs.Add($"방화벽 IP 차단 규칙 {ioc.BlockIps.Length}개가 적용되어 있습니다.");
        }
        catch (Exception e) when (e is COMException or UnauthorizedAccessException or InvalidOperationException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        { ok = false; msgs.Add("방화벽 규칙을 추가하지 못했습니다."); }

        try
        {
            EnsureHostsSafe();
            var original = File.ReadAllBytes(HostsPath);
            var updated = HostsEditor.Apply(original, ioc.BlockDomains);
            if (!updated.SequenceEqual(original)) WriteInPlace(updated);
            var back = File.ReadAllBytes(HostsPath);
            if (back.SequenceEqual(updated)) msgs.Add($"hosts에 도메인 {ioc.BlockDomains.Length}개를 앱 소유 구간으로 추가했습니다(기존 내용 보존).");
            else { ok = false; msgs.Add("hosts 변경을 확인하지 못했습니다. 보안 제품이 막았을 수 있습니다."); }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        { ok = false; msgs.Add("hosts를 수정하지 못했습니다: " + (e is InvalidDataException ? e.Message : "파일이 보호되어 있거나 사용 중입니다.")); }
        msgs.Add("새 서버나 다른 통신 경로까지 막지는 못합니다.");
        return new NetworkActionResult(ok, string.Join(" ", msgs));
    }

    public NetworkActionResult BlockLauncher(string exe)
    {
        if (!PathSafety.IsValidLauncherExecutable(exe, out var why)) return new NetworkActionResult(false, "검증된 런처 파일이 아니어서 중단했습니다: " + why);
        try
        {
            var policy = Policy();
            var id = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(exe.ToLowerInvariant())))[..12];
            AddRule(policy, LauncherRulePrefix + id, "NIKKE PC 안전 점검 도우미(비공식)가 추가한 런처 외부 통신 차단", null, exe);
            if (!(bool)RuleMatches(policy.Rules, LauncherRulePrefix + id, null, exe)) return new NetworkActionResult(false, "방화벽 규칙을 확인하지 못했습니다.");
            var problem = EffectiveProblem(policy);
            return problem is null ? new NetworkActionResult(true, "런처 파일의 외부 통신 차단 규칙이 적용되어 있습니다. 해제하기 전에는 런처가 동작하지 않습니다.") : new NetworkActionResult(false, problem);
        }
        catch (Exception e) when (e is COMException or UnauthorizedAccessException or InvalidOperationException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        { return new NetworkActionResult(false, "방화벽 규칙을 추가하지 못했습니다."); }
    }

    public NetworkActionResult Unblock()
    {
        var msgs = new List<string>();
        var ok = true;
        try
        {
            dynamic policy = Policy();
            dynamic rules = policy.Rules;
            var names = new List<string>();
            foreach (dynamic r in rules)
            {
                string n = r.Name;
                string? g = r.Grouping;
                if (g == Group && (n.StartsWith(IpRulePrefix, StringComparison.Ordinal) || n.StartsWith(LauncherRulePrefix, StringComparison.Ordinal))) names.Add(n);
            }
            foreach (var n in names) rules.Remove(n);
            msgs.Add($"이 프로그램이 추가한 방화벽 규칙 {names.Count}개를 제거했습니다.");
        }
        catch (Exception e) when (e is COMException or UnauthorizedAccessException or InvalidOperationException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        { ok = false; msgs.Add("방화벽 규칙을 제거하지 못했습니다."); }
        try
        {
            EnsureHostsSafe();
            var original = File.ReadAllBytes(HostsPath);
            if (HostsEditor.HasBlock(original))
            {
                WriteInPlace(HostsEditor.Remove(original));
                File.Delete(HostsPath + ".NikkeSafetyCheck.bak");
                msgs.Add("hosts에서 이 프로그램이 추가한 줄만 제거했습니다.");
            }
            else msgs.Add("hosts에 이 프로그램이 추가한 구간이 없습니다.");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        { ok = false; msgs.Add("hosts를 복구하지 못했습니다: " + (e is InvalidDataException ? e.Message : "파일이 보호되어 있거나 사용 중입니다.")); }
        return new NetworkActionResult(ok, string.Join(" ", msgs));
    }

    private void EnsureHostsSafe()
    {
        if (PathSafety.IsReparse(HostsPath)) throw new IOException("hosts가 링크여서 수정하지 않습니다.");
    }

    /// <summary>파일을 교체하지 않고 내용만 다시 써서 ACL을 그대로 유지한다.</summary>
    private void WriteInPlace(byte[] bytes)
    {
        // 쓰는 도중 전원이 꺼져도 사용자 내용을 복구할 수 있도록 변경 전 파일을 옆에 남긴다. 백업이 안 되면 수정하지 않는다.
        File.Copy(HostsPath, HostsPath + ".NikkeSafetyCheck.bak", overwrite: true);
        using var fs = new FileStream(HostsPath, FileMode.Open, FileAccess.Write, FileShare.Read);
        fs.Write(bytes);
        fs.SetLength(bytes.Length);
        fs.Flush(true);
    }

    public int CountOwnedRules()
    {
        dynamic policy = Policy();
        var c = 0;
        foreach (dynamic r in policy.Rules) { string? g = r.Grouping; if (g == Group) c++; }
        return c;
    }
}

/// <summary>
/// 관리자 보조 실행의 진입점. 동작은 고정된 동사로만 고르고, 차단 값은 내장 IOC에서 읽는다.
/// 호출자에게서 임의 경로나 명령을 받지 않는다. 런처 경로 하나만 받아 다시 검증한다.
/// </summary>
public static partial class ElevatedHelper
{
    public const string Flag = "--elevated-helper";
    [GeneratedRegex("^NSC-[0-9a-f]{32}$")] private static partial Regex PipeName();

    public static int Run(string[] args)
    {
        // 형식: --elevated-helper <verb> --pipe <name> [--launcher <path>]
        if (args.Length < 4 || args[0] != Flag || args[2] != "--pipe" || !PipeName().IsMatch(args[3])) return 64;
        if (args.Length is not (4 or 6)) return 64;
        var verb = args[1];
        string? launcher = null;
        if (args.Length == 6) { if (args[4] != "--launcher" || verb != "block-launcher") return 64; launcher = args[5]; }
        if (verb == "block-launcher" && launcher is null) return 64;
        if (verb is not ("block-known" or "block-launcher" or "unblock" or "defender-offline")) return 64;
        if (LoadedUserWritableModule()) return Report(args[3], new NetworkActionResult(false, "관리자 동작 전 안전 확인에 실패해 아무것도 바꾸지 않았습니다. 사용자 임시 폴더에서 불러온 구성 요소가 있습니다."));

        NetworkActionResult r;
        try
        {
            var svc = new NetworkBlockService();
            r = verb switch
            {
                "block-known" => svc.BlockKnown(IocData.LoadEmbedded()),
                "block-launcher" => svc.BlockLauncher(launcher!),
                "unblock" => svc.Unblock(),
                _ => WindowsDefenderService.StartOfflineFromElevatedAsync().GetAwaiter().GetResult(),
            };
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception or OperationCanceledException)
        { r = new NetworkActionResult(false, "관리자 동작을 끝내지 못했습니다."); }
        return Report(args[3], r);
    }

    private static int Report(string pipeName, NetworkActionResult r)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out);
            pipe.Connect(10000);
            pipe.Write(JsonSerializer.SerializeToUtf8Bytes(r));
        }
        catch (Exception e) when (e is IOException or TimeoutException or UnauthorizedAccessException) { return r.Ok ? 3 : 4; }
        return r.Ok ? 0 : 1;
    }

    /// <summary>
    /// 단일 파일 배포는 일부 네이티브 라이브러리를 사용자 임시 폴더에 풉니다. 그 위치의 파일은 다른 사용자 프로세스가 바꿀 수 있으므로,
    /// 관리자 권한으로 도는 동안 하나라도 불러와져 있으면 멈춘다. 이 보조 경로는 WPF를 쓰지 않아 정상이라면 불러오지 않는다.
    /// </summary>
    private static bool LoadedUserWritableModule()
    {
        try
        {
            var temp = Path.GetTempPath();
            using var self = Process.GetCurrentProcess();
            foreach (ProcessModule m in self.Modules)
                using (m)
                    if (m.FileName.StartsWith(temp, StringComparison.OrdinalIgnoreCase) || m.FileName.Contains(@"\.net\", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or NotSupportedException) { return false; }
    }
}

public sealed class ElevatedRunner : IPrivilegedRunner
{
    private static async Task<NetworkActionResult> InvokeAsync(string verb, string? launcher, CancellationToken ct)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("실행 파일 경로를 찾을 수 없습니다.");
        var pipeName = "NSC-" + Guid.NewGuid().ToString("N");
        var ps = new System.IO.Pipes.PipeSecurity();
        using var me = WindowsIdentity.GetCurrent();
        ps.AddAccessRule(new PipeAccessRule(me.User!, PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));
        await using var server = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, ps);
        var args = $"{ElevatedHelper.Flag} {verb} --pipe {pipeName}";
        if (launcher is not null)
        {
            if (launcher.Contains('"')) return new NetworkActionResult(false, "허용되지 않는 경로입니다.");
            args += $" --launcher \"{launcher}\"";
        }
        Process? p;
        try { p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden }); }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223) { return new NetworkActionResult(false, "관리자 승인을 취소하셔서 이 항목은 변경하지 않았습니다. 다른 항목에는 영향이 없습니다."); }
        catch (Win32Exception) { return new NetworkActionResult(false, "관리자 권한으로 실행하지 못했습니다."); }
        if (p is null) return new NetworkActionResult(false, "관리자 권한으로 실행하지 못했습니다.");
        using (p)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMinutes(3));
            try
            {
                await server.WaitForConnectionAsync(cts.Token);
                using var ms = new MemoryStream();
                await server.CopyToAsync(ms, cts.Token);
                return JsonSerializer.Deserialize<NetworkActionResult>(ms.ToArray()) ?? new NetworkActionResult(false, "결과를 읽지 못했습니다.");
            }
            catch (OperationCanceledException) { return new NetworkActionResult(false, "관리자 동작의 결과를 받지 못했습니다. 다시 점검해 적용 여부를 확인하세요."); }
            catch (JsonException) { return new NetworkActionResult(false, "결과를 읽지 못했습니다."); }
        }
    }

    public Task<NetworkActionResult> BlockKnownNetworkAsync(CancellationToken ct) => InvokeAsync("block-known", null, ct);
    public Task<NetworkActionResult> BlockLauncherAsync(string launcherExe, CancellationToken ct) => InvokeAsync("block-launcher", launcherExe, ct);
    public Task<NetworkActionResult> UnblockAllAsync(CancellationToken ct) => InvokeAsync("unblock", null, ct);
    public Task<NetworkActionResult> StartDefenderOfflineAsync(CancellationToken ct) => InvokeAsync("defender-offline", null, ct);
}
