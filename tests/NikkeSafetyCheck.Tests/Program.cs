using System.Text;
using NikkeSafetyCheck.Core;

// 외부 테스트 프레임워크 없이 동작하는 회귀 테스트. 실제 악성코드나 공격 서버를 쓰지 않는다.
var ioc = IocData.LoadEmbedded();
var failures = new List<string>();
var passed = 0;
void T(string name, Action body)
{
    try { body(); passed++; Console.WriteLine($"PASS  {name}"); }
    catch (Exception e) { failures.Add(name); Console.WriteLine($"FAIL  {name}\n      {e.GetType().Name}: {e.Message}"); }
}
void TA(string name, Func<Task> body) => T(name, () => body().GetAwaiter().GetResult());
static void True(bool c, string m = "조건 불일치") { if (!c) throw new Exception(m); }
static void Eq<X>(X a, X b, string m = "") { if (!EqualityComparer<X>.Default.Equals(a, b)) throw new Exception($"{m} 기대={a} 실제={b}"); }

const string Sid = "S-1-5-21-1000-2000-3000-1001";
const string Clsid = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
const string ExecLine = "[1101/012037.043:INFO:CONSOLE(1)] \"k2f_chan registered\", source: (1)";

Env NewEnv(string? nameSuffix = null)
{
    var root = Path.Combine(Path.GetTempPath(), "nsc-test-" + Guid.NewGuid().ToString("N")[..8] + (nameSuffix ?? ""));
    Directory.CreateDirectory(root);
    return new Env(root, ioc);
}
ScanResult Scan(Env e, Func<ScanRequest, ScanRequest>? f = null, CancellationToken ct = default)
{
    var req = new ScanRequest { Target = e.Target, ExtraFolders = e.Installs };
    if (f is not null) req = f(req);
    return new ScanEngine(ioc, e.Services, "test").Run(req, null, ct);
}
Finding[] Of(ScanResult r, string id) => r.Findings.Where(x => x.RuleId == id).ToArray();

// 1
T("01 정상 부모 폴더/정상 EXE만 있으면 고위험·삭제 없음", () =>
{
    using var e = NewEnv();
    var helper = e.ChromeHelper();
    File.WriteAllText(Path.Combine(helper, "platform_experience_helper.exe"), "benign");
    File.WriteAllText(Path.Combine(helper, "LoadFeatures"), "");
    e.Install(); e.DebugLog("ordinary\nFETCH_LIST suc success\n");
    var r = Scan(e);
    Eq(OverallRisk.NoKnownTraces, r.Risk);
    Eq(Completeness.Complete, r.Completeness);
    var plan = PlanBuilder.Build(r, null);
    True(!plan.Items.Any(i => i.Kind is PlanKind.QuarantineDll or PlanKind.RemoveComKey));
    True(File.Exists(Path.Combine(helper, "platform_experience_helper.exe")));
    foreach (var h in new[] { Verdict.Headline(r.Risk, r.Completeness), Verdict.Explanation(r.Risk, r.Completeness) })
        True(!h.Contains("100%") && !h.Contains("정상 보장") && !h.Contains("감염 없음"));
});
// 2
T("02 정상 HKLM CLSID만 있으면 수정 0건", () =>
{
    using var e = NewEnv();
    e.Reg.Add($@"HKLM\SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32", new() { [""] = @"C:\Windows\System32\wpc.dll" });
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    Eq(OverallRisk.NoKnownTraces, r.Risk);
    Eq(0, PlanBuilder.Build(r, null).Items.Count(i => i.Kind == PlanKind.RemoveComKey));
    Eq(0, e.Reg.Deletes.Count);
});
// 3
TA("03 일치하는 사용자 COM/DLL은 올바른 SID만 계획에 포함하고 실제 조치됨", async () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("harmless test bytes A"), matchName: false);
    var key = e.PlantCom(dll);
    e.Reg.Add($@"HKU\S-1-5-21-9-9-9-500_Classes\CLSID\{Clsid}\InprocServer32", new() { [""] = dll });
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    Eq(OverallRisk.High, r.Risk);
    var plan = PlanBuilder.Build(r, null);
    var com = plan.Items.Single(i => i.Kind == PlanKind.RemoveComKey);
    True(com.ExpectedRegistryKey!.StartsWith($@"HKU\{Sid}_Classes\"), "다른 SID 포함");
    var res = await e.Exec().ExecuteAsync(plan, plan.Items.Where(i => i.Kind is PlanKind.RemoveComKey or PlanKind.QuarantineDll).Select(i => i.Id).ToHashSet(), r, false, null, default);
    True(res.Where(x => x.Outcome != ItemOutcome.Skipped).All(x => x.Outcome == ItemOutcome.Succeeded), string.Join("|", res.Select(x => x.Message)));
    True(!File.Exists(dll), "DLL 남음");
    True(Directory.Exists(e.ChromeHelper()), "부모 폴더 삭제됨");
    True(!Directory.Exists(Path.GetDirectoryName(dll)!), "해시 폴더 남음");
    Eq(null, e.Reg.Read(key));
    True(e.Reg.Read($@"HKU\S-1-5-21-9-9-9-500_Classes\CLSID\{Clsid}\InprocServer32") is not null, "다른 사용자 키 변경됨");
    var q = Directory.GetFiles(e.Data.Quarantine).Single();
    True(q.EndsWith(".quarantined"), "실행 가능한 이름");
    True(e.Protector.Protected.Contains(q));
    var after = Scan(e);
    True(Of(after, "NSC-DLL-SCAN").All(f => f.Status == CheckStatus.NotFound));
});
// 4
T("04 해시가 달라도 결합 증거는 고위험, 해시 불일치를 정상 근거로 안 씀", () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("variant bytes"), matchName: false);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var f = Of(Scan(e), "NSC-DLL-SCAN").Single();
    Eq(Severity.High, f.Severity); Eq(RemediationEligibility.Eligible, f.RemediationEligibility);
});
T("04b 단독 DLL(폴더명≠해시, COM 없음)은 의심이며 자동 제거 안 함", () =>
{
    using var e = NewEnv();
    e.PlantDll(Encoding.ASCII.GetBytes("lonely"), matchName: false);
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    var f = Of(r, "NSC-DLL-SCAN").Single();
    Eq(Severity.Suspicious, f.Severity); Eq(RemediationEligibility.ManualOnly, f.RemediationEligibility);
    True(!PlanBuilder.Build(r, null).Items.Any(i => i.Kind == PlanKind.QuarantineDll));
});
T("04c 폴더명=자기 SHA-256 구조는 고위험, 유효 서명이면 자동 제거 제외", () =>
{
    using var e = NewEnv();
    e.PlantDll(Encoding.ASCII.GetBytes("structural"), matchName: true);
    e.Install(); e.DebugLog("x\n");
    Eq(Severity.High, Of(Scan(e), "NSC-DLL-SCAN").Single().Severity);
    e.Sig.State = SignatureState.Valid;
    Eq(Severity.Suspicious, Of(Scan(e), "NSC-DLL-SCAN").Single().Severity);
});
T("04d 단독 COM 키(다른 경로)는 자동 삭제 대상 아님", () =>
{
    using var e = NewEnv();
    e.Reg.Add($@"HKU\{Sid}_Classes\CLSID\{Clsid}\InprocServer32", new() { [""] = Path.Combine(e.Root, "other", "thing.dll") });
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    Eq(RemediationEligibility.ManualOnly, Of(r, "NSC-COM-KNOWN").Single().RemediationEligibility);
    True(!PlanBuilder.Build(r, null).Items.Any(i => i.Kind == PlanKind.RemoveComKey));
});
// 5
T("05 로그만 있으면 과거 고위험, DLL 없음과 함께 유지", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog(ExecLine + "\n[1101/012037.114:INFO:CONSOLE(1)] \"adopted 11111111-2222-3333-4444-555555555555\", source: (1)\n");
    var r = Scan(e);
    var l = Of(r, "NSC-LOG-EXEC").Single();
    Eq(Severity.High, l.Severity); Eq(Temporal.Past, l.Temporal);
    Eq(CheckStatus.NotFound, Of(r, "NSC-DLL-SCAN").Single().Status);
    Eq(OverallRisk.High, r.Risk);
    True(!l.Detail.Contains("11111111"), "UUID 노출");
    True(l.Detail.Contains("11-01 01:20:37"));
});
T("05b 일반 텍스트 인용은 실행 증거로 승격 안 함", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("someone wrote: search for k2f_chan registered in your log\n");
    Eq(Severity.Suspicious, Of(Scan(e), "NSC-LOG-EXEC").Single().Severity);
});
T("05c 수동 제출 자료는 의심 이상으로 올리지 않음", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    var m = Path.Combine(e.Root, "copy.log"); File.WriteAllText(m, ExecLine + "\n");
    var r = Scan(e, q => q with { ManualLogFiles = [m] });
    Eq(Severity.Suspicious, Of(r, "NSC-MANUAL").Single().Severity);
    Eq(OverallRisk.Suspicious, r.Risk);
});
T("05d k2f.agent.state는 고위험, UTF-16 저장도 탐지, k2f.agent 단독은 의심", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    var ls = Path.Combine(PathSafety.LauncherCacheDir(e.Target), "Local Storage", "leveldb"); Directory.CreateDirectory(ls);
    File.WriteAllBytes(Path.Combine(ls, "000001.log"), [.. new byte[100], .. Encoding.Unicode.GetBytes("k2f.agent.state"), .. new byte[100]]);
    Eq(Severity.High, Of(Scan(e), "NSC-LS-STATE").Single().Severity);
    File.WriteAllText(Path.Combine(ls, "000001.log"), "xx k2f.agent yy");
    Eq(Severity.Suspicious, Of(Scan(e), "NSC-LS-STATE").Single().Severity);
});
// 6
T("06 경로 없음은 미검사, '안전' 오판 없음", () =>
{
    using var e = NewEnv();
    var r = Scan(e);
    Eq(Completeness.Partial, r.Completeness); Eq(CheckStatus.Unknown, Of(r, "NSC-LOG-EXEC").Single().Status);
    True(Verdict.Headline(r.Risk, r.Completeness).StartsWith("점검 불완전"));
    var r2 = Scan(e, q => q with { DeclaredNeverInstalled = true });
    Eq(CheckStatus.NotApplicable, Of(r2, "NSC-LOG-EXEC").Single().Status);
});
T("06b 접근 거부는 Unknown, 고위험 증거는 유지", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog(ExecLine + "\n");
    e.Reg.DenyAll = true;
    var r = Scan(e);
    Eq(CheckStatus.Unknown, Of(r, "NSC-COM-KNOWN").Single().Status);
    Eq(OverallRisk.High, r.Risk); Eq(Completeness.Partial, r.Completeness);
    True(Verdict.Headline(r.Risk, r.Completeness).Contains("일부 항목"));
});
T("06c 하이브 미로드는 Unknown", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    e.Reg.HiveLoaded = false;
    Eq(CheckStatus.Unknown, Of(Scan(e), "NSC-COM-KNOWN").Single().Status);
});
T("06d 취소하면 미검사로 표시", () =>
{
    using var e = NewEnv();
    using var c = new CancellationTokenSource(); c.Cancel();
    var r = Scan(e, null, c.Token);
    True(r.Cancelled); Eq(Completeness.Partial, r.Completeness);
    Eq(OverallRisk.NoKnownTraces, r.Risk);
    True(Verdict.Headline(r.Risk, r.Completeness).StartsWith("점검 불완전"));
});
T("06e 잠긴 로그는 Unknown (Windows 잠금)", () =>
{
    using var e = NewEnv();
    e.Install();
    var p = e.DebugLog("x\n");
    if (!OperatingSystem.IsWindows()) return;
    using var hold = new FileStream(p, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    Eq(CheckStatus.Unknown, Of(Scan(e), "NSC-LOG-EXEC").Single().Status);
});
// 7
T("07 다른 관리자 자격으로 실행해도 대상 사용자가 안 바뀌고 사용자 조치 제외", () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    var key = e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var other = e.Target with { ProcessIsTargetUser = false, ProcessUserName = "OtherAdmin" };
    var r = new ScanEngine(ioc, e.Services, "t").Run(new ScanRequest { Target = other, ExtraFolders = e.Installs }, null, default);
    True(r.Findings.All(f => f.UserSid == Sid), "SID 변경");
    True(e.Reg.ReadPaths.All(p => !p.Contains("OtherAdmin")));
    var plan = PlanBuilder.Build(r, null);
    True(!plan.Items.Any(i => i.Kind is PlanKind.RemoveComKey or PlanKind.QuarantineDll or PlanKind.ClearLauncherCache));
    True(plan.ManualNotes.Any(n => n.Contains("OtherAdmin")));
});
// 8
T("08 32/64비트 뷰, 다중 설치, 비영문·공백·긴 경로", () =>
{
    using var e = NewEnv(" 한글 공백");
    var longPart = string.Join(Path.DirectorySeparatorChar, Enumerable.Repeat("긴폴더이름abc", 12));
    var d1 = Path.Combine(e.Root, "게임 폴더", longPart, "NIKKE", "Launcher");
    var d2 = Path.Combine(e.Root, "D드라이브", "NIKKE");
    Directory.CreateDirectory(Path.Combine(d1, "intl_service"));
    Directory.CreateDirectory(Path.Combine(d2, "Launcher", "intl_service"));
    File.WriteAllText(Path.Combine(d1, "intl_service", "debug.log"), "x\n");
    File.WriteAllText(Path.Combine(d2, "Launcher", "intl_service", "debug.log"), ExecLine + "\n");
    e.Hints.Hints.Add(new InstallHint("\"" + Path.Combine(d1, "uninstall.exe") + "\" /S", "설치 정보(64비트)"));
    File.WriteAllText(Path.Combine(d1, "uninstall.exe"), "not run");
    e.Hints.Hints.Add(new InstallHint(d2, "설치 정보(32비트)"));
    e.Hints.Hints.Add(new InstallHint(d2 + Path.DirectorySeparatorChar, "중복"));
    var r = Scan(e);
    Eq(2, r.Installs.Count);
    Eq(2, Of(r, "NSC-LOG-EXEC").Length);
    Eq(1, Of(r, "NSC-LOG-EXEC").Count(f => f.Severity == Severity.High));
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("wow"), matchName: false);
    e.Reg.Add($@"HKU\{Sid}_Classes\WOW6432Node\CLSID\{Clsid}\InprocServer32", new() { [""] = dll });
    var r2 = Scan(e);
    True(Of(r2, "NSC-COM-KNOWN").Any(f => f.RegistryKey!.Contains("WOW6432Node") && f.Severity == Severity.High));
});
T("08b UTF-16/BOM 로그와 줄바꿈 없는 부분 기록, 초장문 줄", () =>
{
    using var e = NewEnv();
    var p = Path.Combine(e.Root, "a.log");
    foreach (var enc in new Encoding[] { Encoding.Unicode, Encoding.BigEndianUnicode, new UTF8Encoding(true) })
    {
        using (var w = new StreamWriter(p, false, enc)) w.Write("first\r\n" + ExecLine);
        Eq(1, new LogScanner(ioc).Scan(p, long.MaxValue, default).ExecutionHits, enc.WebName);
    }
    File.WriteAllBytes(p, Encoding.Unicode.GetBytes("hello\n" + ExecLine + "\n"));
    Eq(1, new LogScanner(ioc).Scan(p, long.MaxValue, default).ExecutionHits, "BOM 없는 UTF-16");
    File.WriteAllText(p, new string('a', 3_000_000) + " k2f_chan registered\n" + ExecLine + "\n");
    var r = new LogScanner(ioc).Scan(p, long.MaxValue, default);
    Eq(1, r.ExecutionHits); Eq(1, r.LiteralOnlyHits);
});
// 9
TA("09 reparse/경로 이탈/교체 시 조치 중단", async () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("orig"), matchName: false);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    var plan = PlanBuilder.Build(r, null);
    var q = plan.Items.Single(i => i.Kind == PlanKind.QuarantineDll);
    var ids = new HashSet<string> { q.Id };
    // 교체
    File.WriteAllText(dll, "swapped");
    var res = await e.Exec().ExecuteAsync(plan, ids, r, false, null, default);
    Eq(ItemOutcome.Aborted, res.Single(x => x.ItemId == q.Id).Outcome);
    True(File.Exists(dll));
    // 경로 이탈
    var evil = q with { ExpectedPath = Path.Combine(e.Root, "AppData", "..", "elsewhere", "x", PathSafety.DllName) };
    var p2 = plan with { Items = [evil] };
    Eq(ItemOutcome.Aborted, (await e.Exec().ExecuteAsync(p2, ids, r, false, null, default)).Single().Outcome);
    // 다른 위치
    var other = Path.Combine(e.Root, "elsewhere", new string('a', 64)); Directory.CreateDirectory(other);
    var evil2 = q with { ExpectedPath = Path.Combine(other, PathSafety.DllName) }; File.WriteAllText(evil2.ExpectedPath!, "x");
    Eq(ItemOutcome.Aborted, (await e.Exec().ExecuteAsync(plan with { Items = [evil2] }, ids, r, false, null, default)).Single().Outcome);
    True(File.Exists(evil2.ExpectedPath!));
    // COM 값 교체
    var c = plan.Items.Single(i => i.Kind == PlanKind.RemoveComKey);
    e.Reg.Add(c.ExpectedRegistryKey!, new() { [""] = "changed" });
    Eq(ItemOutcome.Aborted, (await e.Exec().ExecuteAsync(plan, new HashSet<string> { c.Id }, r, false, null, default)).Single(x => x.ItemId == c.Id).Outcome);
    // HKLM 경로 위조
    var hk = c with { ExpectedRegistryKey = $@"HKLM\SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32" };
    Eq(ItemOutcome.Aborted, (await e.Exec().ExecuteAsync(plan with { Items = [hk] }, new HashSet<string> { c.Id }, r, false, null, default)).Single().Outcome);
    Eq(0, e.Reg.Deletes.Count);
});
TA("09b 심볼릭 링크 경로는 조치 거부", async () =>
{
    using var e = NewEnv();
    var real = Path.Combine(e.Root, "real", new string('b', 64)); Directory.CreateDirectory(real);
    var helper = e.ChromeHelper();
    var link = Path.Combine(helper, new string('b', 64));
    try { Directory.CreateSymbolicLink(link, real); } catch (Exception x) when (x is IOException or UnauthorizedAccessException) { Console.WriteLine("      (링크 생성 권한 없음: 건너뜀)"); return; }
    var dll = Path.Combine(link, PathSafety.DllName); File.WriteAllText(dll, "x");
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    var f = Of(r, "NSC-DLL-SCAN").Single();
    Eq(RemediationEligibility.ManualOnly, f.RemediationEligibility);
    var hash = ScanEngine.Sha256File(dll, default);
    var item = new PlanItem { Id = "x", Kind = PlanKind.QuarantineDll, Title = "t", WhatChanges = "w", ExpectedPath = dll, ExpectedSha256 = hash };
    var plan = new RemediationPlan("p0000000", "s", Sid, DateTimeOffset.Now, [item], []);
    var res = await e.Exec().ExecuteAsync(plan, new HashSet<string> { "x" }, r, false, null, default);
    Eq(ItemOutcome.Aborted, res.Single().Outcome);
    True(File.Exists(Path.Combine(real, PathSafety.DllName)));
});
TA("09c 관계없는 값이 있으면 COM 일괄 삭제 안 함", async () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    var plan = PlanBuilder.Build(r, null);
    var c = plan.Items.Single(i => i.Kind == PlanKind.RemoveComKey);
    e.Reg.Add(c.ExpectedRegistryKey!, new() { [""] = dll, ["Unrelated"] = "1" });
    var res = await e.Exec().ExecuteAsync(plan, new HashSet<string> { c.Id }, r, false, null, default);
    Eq(ItemOutcome.ManualRequired, res.Single(x => x.ItemId == c.Id).Outcome);
    Eq(0, e.Reg.Deletes.Count);
});
TA("09d DryRun은 아무것도 바꾸지 않음", async () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    Directory.CreateDirectory(PathSafety.LauncherCacheDir(e.Target));
    var r = Scan(e);
    var plan = PlanBuilder.Build(r, null);
    var res = await e.Exec().ExecuteAsync(plan, plan.Items.Select(i => i.Id).ToHashSet(), r, true, null, default);
    True(res.All(x => x.Outcome == ItemOutcome.DryRunOk), string.Join("|", res.Select(x => x.Outcome + x.Message)));
    True(File.Exists(dll)); True(Directory.Exists(PathSafety.LauncherCacheDir(e.Target)));
    Eq(0, e.Reg.Deletes.Count); Eq(0, e.Priv.Calls);
    True(!Directory.Exists(e.Data.Journal));
});
// 10
T("10 hosts 반복 실행 중복 없음, 다른 설정·인코딩 보존, 사용자 수정 보존", () =>
{
    var original = Encoding.UTF8.GetBytes("# 사용자 주석\r\n127.0.0.1 my.local\r\n");
    var ansi = new byte[] { 0x23, 0xC7, 0xD1, 0xB1, 0xDB, 0x0D, 0x0A, 0x31, 0x2E, 0x31, 0x2E, 0x31, 0x2E, 0x31, 0x20, 0x61, 0x0D, 0x0A }; // CP949 "#한글"
    foreach (var src in new[] { original, ansi, Array.Empty<byte>(), Encoding.UTF8.GetPreamble().Concat(original).ToArray(), Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("1.1.1.1 a\r\n")).ToArray() })
    {
        var once = HostsEditor.Apply(src, ioc.BlockDomains);
        var twice = HostsEditor.Apply(once, ioc.BlockDomains);
        True(once.SequenceEqual(twice), "중복");
        var back = HostsEditor.Remove(twice);
        True(back.SequenceEqual(src) || (src.Length > 0 && back.Take(src.Length).SequenceEqual(src)), "원문 손상");
    }
    var a = HostsEditor.Apply(original, ioc.BlockDomains);
    var text = Encoding.UTF8.GetString(a) + "10.0.0.1 after.block\r\n";
    var inner = text.Replace(HostsEditor.EndMarker, "9.9.9.9 user-added.example\r\n" + HostsEditor.EndMarker);
    var removed = Encoding.UTF8.GetString(HostsEditor.Remove(Encoding.UTF8.GetBytes(inner)));
    True(removed.Contains("9.9.9.9 user-added.example"), "구간 안 사용자 줄 삭제");
    True(removed.Contains("10.0.0.1 after.block")); True(removed.Contains("127.0.0.1 my.local"));
    True(!removed.Contains("insightjs"));
    var broken = Encoding.UTF8.GetBytes(HostsEditor.BeginMarker + "\r\n0.0.0.0 insightjs.com\r\n");
    var threw = false; try { HostsEditor.Remove(broken); } catch (InvalidDataException) { threw = true; }
    True(threw, "깨진 표식을 수정함");
    foreach (var l in Encoding.UTF8.GetString(a).Split('\n'))
        True(!l.Contains('*'), "와일드카드");
});
// 11
TA("11 중간 실패·잠금: 완료 오표시 없음, 저널로 후속 처리", async () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    var plan = PlanBuilder.Build(r, new DefenderStatus(true, "", [], true));
    e.Priv.Fail = true;
    e.Procs.LoadedHit = true;
    var res = await e.Exec().ExecuteAsync(plan, plan.Items.Where(i => i.Kind is PlanKind.QuarantineDll or PlanKind.BlockKnownNetwork).Select(i => i.Id).ToHashSet(), r, false, null, default);
    Eq(ItemOutcome.PendingReboot, res.Single(x => x.Kind == PlanKind.QuarantineDll).Outcome);
    Eq(ItemOutcome.Failed, res.Single(x => x.Kind == PlanKind.BlockKnownNetwork).Outcome);
    var pend = Journal.FindPending(e.Data);
    Eq(1, pend.PendingReboot); Eq(0, pend.UnfinishedRuns);
    var j = Journal.Create(e.Data, "zzzzzzzz"); Thread.Sleep(1100);
    var j2 = Journal.Create(e.Data, "yyyyyyyy"); j2.Write("plan", new { a = 1 });
    Eq(1, Journal.FindPending(e.Data).UnfinishedRuns, "강제 종료 흔적");
    // 조치 전 증거 유지
    HistoryStore.RecordIfWorse(e.Data, r);
    var clean = new ScanResult { ScanId = "s", RuleVersion = "r", ToolVersion = "t", StartedAt = default, FinishedAt = default, Target = e.Target, Findings = [], Installs = [], Cancelled = false };
    HistoryStore.RecordIfWorse(e.Data, clean);
    Eq(OverallRisk.High, HistoryStore.LoadWorst(e.Data)!.Risk);
    True(HistoryStore.LoadWorst(e.Data)!.CurrentHighRuleIds.Contains("NSC-DLL-SCAN"), "조치 전 현재 증거 소실");
    var logOnly = new ScanResult { ScanId = "s", RuleVersion = "r", ToolVersion = "t", StartedAt = default, FinishedAt = default, Target = e.Target, Installs = [], Cancelled = false,
        Findings = r.Findings.Where(f => f.RuleId == "NSC-DLL-SCAN").Select(f => f with { Temporal = Temporal.Past }).ToList() };
    HistoryStore.RecordIfWorse(e.Data, logOnly);
    True(HistoryStore.LoadWorst(e.Data)!.CurrentHighRuleIds.Contains("NSC-DLL-SCAN"), "같은 등급 재점검으로 증거 소실");
});
TA("11b 증거 보존 실패 시 캐시 삭제 안 함, 런처 실행 중이면 중단", async () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog(ExecLine + "\n");
    var cache = PathSafety.LauncherCacheDir(e.Target);
    var ls = Path.Combine(cache, "Local Storage", "leveldb"); Directory.CreateDirectory(ls);
    File.WriteAllText(Path.Combine(ls, "000001.log"), "state");
    var r = Scan(e);
    var plan = PlanBuilder.Build(r, null);
    var c = plan.Items.Single(i => i.Kind == PlanKind.ClearLauncherCache);
    var ids = new HashSet<string> { c.Id };
    e.Procs.Running = true;
    Eq(ItemOutcome.Aborted, (await e.Exec().ExecuteAsync(plan, ids, r, false, null, default)).Single(x => x.ItemId == c.Id).Outcome);
    True(Directory.Exists(cache));
    e.Procs.Running = false;
    Directory.CreateDirectory(e.Data.Root);
    File.WriteAllText(e.Data.Evidence, "not a directory");
    var res = await e.Exec().ExecuteAsync(plan, ids, r, false, null, default);
    Eq(ItemOutcome.Failed, res.Single(x => x.ItemId == c.Id).Outcome);
    True(Directory.Exists(cache), "증거 없이 삭제됨");
    File.Delete(e.Data.Evidence);
    res = await e.Exec().ExecuteAsync(plan, ids, r, false, null, default);
    Eq(ItemOutcome.Succeeded, res.Single(x => x.ItemId == c.Id).Outcome);
    True(!Directory.Exists(cache));
    True(Directory.GetFiles(e.Data.Evidence, "debug.log", SearchOption.AllDirectories).Length == 1);
    True(Directory.GetFiles(e.Data.Evidence, "000001.log.data", SearchOption.AllDirectories).Length == 1, "실행 불가 이름 아님");
    var after = Scan(e);
    Eq(Severity.High, Of(after, "NSC-LOG-EXEC").Single().Severity);
});
// 12
T("12 공유 보고서: 식별자·비밀·HTML 삽입 노출 없음", () =>
{
    using var e = NewEnv();
    e.Install();
    var t = e.Target with { UserName = "hong<script>", MachineName = "DESKTOP-ABC" };
    var secretHex = new string('c', 64);
    var uuid = "11111111-2222-3333-4444-555555555555";
    var evil = $"<img src=x onerror=alert(1)> {Sid} {uuid} https://a.example/p?token=abc Bearer {secretHex} {t.ProfileDir}{Path.DirectorySeparatorChar}x DESKTOP-ABC hong<script> C:\\Users\\kim\\file password=hunter2";
    var f = new Finding { RuleId = "R", Title = "<b>t</b>", Detail = evil, SourceUrl = "https://x", RuleVersion = "1", ObservedAt = default, UserSid = Sid, EvidenceType = EvidenceType.Coverage, Confidence = Confidence.Low, Status = CheckStatus.Found, RemediationEligibility = RemediationEligibility.None, Path = Path.Combine(e.Installs.First(), "intl_service", "debug.log"), Severity = Severity.High };
    var scan = new ScanResult { ScanId = "s", RuleVersion = "r", ToolVersion = "t", StartedAt = default, FinishedAt = default, Target = t, Findings = [f], Installs = [new(e.Installs.First(), "x", null)], Cancelled = false };
    foreach (var (name, s) in new[] { ("html", ReportBuilder.Html(scan, ioc)), ("txt", ReportBuilder.Text(scan, ioc)), ("json", ReportBuilder.JsonReport(scan, ioc)) })
    {
        foreach (var bad in new[] { Sid, uuid, "token=abc", "abc\"", secretHex, "DESKTOP-ABC", "hong", "kim", "hunter2", e.Installs.First(), t.ProfileDir })
            True(!s.Contains(bad), $"{name}에 {bad} 노출");
    }
    var html = ReportBuilder.Html(scan, ioc);
    True(!html.Contains("<img") && !html.Contains("<b>t") && html.Contains("&lt;img"), "이스케이프 실패");
    True(!html.Contains("<script") && !html.Contains("http://") && !html.Contains("src=\""), "외부 리소스");
    True(html.Contains("default-src 'none'"));
});
// 13
T("13 Defender 미사용/오프라인/권한 거부: 범위와 이유 표시", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog(ExecLine + "\n");
    var r = Scan(e);
    var third = PlanBuilder.Build(r, new DefenderStatus(false, "x", ["Other AV"], true));
    True(!third.Items.Any(i => i.Kind is PlanKind.DefenderQuickScan or PlanKind.DefenderFullScan));
    True(third.ManualNotes.Any(n => n.Contains("Other AV")));
    var mdav = PlanBuilder.Build(r, new DefenderStatus(true, "x", [], true));
    True(!mdav.Items.Single(i => i.Kind == PlanKind.DefenderOfflineScan).SelectedByDefault, "오프라인 기본 선택");
    True(mdav.Items.Single(i => i.Kind == PlanKind.DefenderOfflineScan).Warning!.Contains("재부팅"));
    e.Net.Throw = true; e.Procs.Throw = true;
    var r2 = Scan(e);
    Eq(CheckStatus.Unknown, Of(r2, "NSC-NET-CONN").Single().Status);
    Eq(CheckStatus.Unknown, Of(r2, "NSC-PROC-MOD").Single().Status);
    Eq(OverallRisk.High, r2.Risk);
    Eq(Completeness.Complete, r2.Completeness, "선택 검사 실패는 필수 아님");
});
// 14
T("14 명령/인자 주입: 설치 정보·경로·IOC 입력으로 실행 불가", () =>
{
    Eq(@"C:\G\NIKKE\Launcher\u.exe", InstallLocator.ExtractPath("\"C:\\G\\NIKKE\\Launcher\\u.exe\" & calc.exe /S"));
    Eq(@"C:\G\a.exe", InstallLocator.ExtractPath(@"C:\G\a.exe,0"));
    foreach (var bad in new[] { @"\\evil\share\x.dll", "//evil/x", @"C:\a\..\b", @"C:\a\b.txt:ads", "", "\0", "relative\\p", @"\\?\C:\x" })
        True(!PathSafety.IsPlainLocalPath(bad), bad);
    Eq(null, InstallLocator.ValidateLauncherDir(@"\\evil\share\NIKKE"));
    True(!PathSafety.IsValidLauncherExecutable(@"C:\Windows\System32\cmd.exe", out _));
    True(!PathSafety.IsValidLauncherExecutable(@"\\evil\s\nikke_launcher.exe", out _));
    using var e = NewEnv();
    var fake = Path.Combine(e.Root, "nikke_launcher.exe"); File.WriteAllText(fake, "x");
    True(!PathSafety.IsValidLauncherExecutable(fake, out _), "폴더 구조 없이 통과");
    var ok = e.Install(); var exe = Path.Combine(ok, "nikke_launcher.exe"); File.WriteAllText(exe, "x");
    True(PathSafety.IsValidLauncherExecutable(exe, out _));
    var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "NikkeSafetyCheck.Core", "Data", "iocs.json"));
    foreach (var mutate in new Func<string, string>[]
    {
        s => s.Replace("\"schemaVersion\": 1,", "\"schemaVersion\": 1, \"deletePaths\": [\"C:\\\\Windows\"],"),
        s => s.Replace("\"insightjs.org\"", "\"evil.com; rm -rf\""),
        s => s.Replace("\"89.127.233.127\"", "\"127.0.0.1\""),
        s => s.Replace("\"k2f-bcreds-\"", "\"..\\\\..\\\\x\""),
        s => s.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 2"),
    })
    {
        var threw = false;
        try { IocData.Parse(mutate(json)); } catch (Exception x) when (x is InvalidDataException or System.Text.Json.JsonException) { threw = true; }
        True(threw, "잘못된 IOC 통과");
    }
});
T("22 취소 중 사용자 CLSID 키가 있어도 충돌 없이 불완전 표시", () =>
{
    using var e = NewEnv();
    e.Reg.Add($@"HKU\{Sid}_Classes\CLSID\{{AAAAAAAA-0000-0000-0000-000000000000}}\InprocServer32", new() { [""] = "x" });
    using var c = new CancellationTokenSource(); c.Cancel();
    var r = Scan(e, null, c.Token);
    Eq(Completeness.Partial, r.Completeness);
});
T("23 읽지 못한 저장소 파일은 미발견이 아니라 불완전(Windows 잠금)", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    var ls = Path.Combine(PathSafety.LauncherCacheDir(e.Target), "Local Storage", "leveldb"); Directory.CreateDirectory(ls);
    var f = Path.Combine(ls, "000001.ldb"); File.WriteAllText(f, "k2f.agent.state");
    if (!OperatingSystem.IsWindows()) return;
    using var hold = new FileStream(f, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    var r = Scan(e);
    Eq(CheckStatus.Unknown, Of(r, "NSC-LS-STATE").Single().Status); Eq(Completeness.Partial, r.Completeness);
});
T("24 알려진 해시는 구조가 달라도 고위험, 자동 조치는 제외", () =>
{
    using var e = NewEnv();
    var dir = Path.Combine(e.ChromeHelper(), "not-hex"); Directory.CreateDirectory(dir);
    var dll = Path.Combine(dir, PathSafety.DllName); File.WriteAllBytes(dll, Encoding.ASCII.GetBytes("sample"));
    var hash = ScanEngine.Sha256File(dll, default);
    var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "NikkeSafetyCheck.Core", "Data", "iocs.json")).Replace("f3e93d049851d5c19552c7d9b73c8be4580dc9d549e8f65f9f0c357c1df9d252", hash);
    var ioc2 = IocData.Parse(json);
    e.Install(); e.DebugLog("x\n");
    var f = new ScanEngine(ioc2, e.Services, "t").Run(new ScanRequest { Target = e.Target, ExtraFolders = e.Installs }, null, default).Findings.Single(x => x.RuleId == "NSC-DLL-SCAN");
    Eq(Severity.High, f.Severity); Eq(RemediationEligibility.ManualOnly, f.RemediationEligibility);
});
T("25 wpc.dll 이름만 흉내 낸 경로는 정상으로 보지 않음", () =>
{
    using var e = NewEnv();
    e.Reg.Add($@"HKU\{Sid}_Classes\CLSID\{Clsid}\InprocServer32", new() { [""] = @"C:\Users\x\AppData\Roaming\System32\wpc.dll" });
    e.Install(); e.DebugLog("x\n");
    var f = Of(Scan(e), "NSC-COM-KNOWN").Single();
    Eq(CheckStatus.Found, f.Status); Eq(Severity.Suspicious, f.Severity);
});
T("26 공유 보고서: 공백 사용자명, 알려진 위치 밖 경로, 이전 고위험 기록", () =>
{
    using var e = NewEnv();
    e.Install();
    var f = new Finding { RuleId = "R", Title = "t", Detail = @"C:\Users\John Smith\a.txt 와 D:\개인자료\김철수\debug.log", SourceUrl = "https://x", RuleVersion = "1", ObservedAt = default, UserSid = Sid, EvidenceType = EvidenceType.Coverage, Confidence = Confidence.Low, Status = CheckStatus.NotFound, RemediationEligibility = RemediationEligibility.None, Path = @"D:\개인자료\김철수\debug.log" };
    var scan = new ScanResult { ScanId = "s", RuleVersion = "r", ToolVersion = "t", StartedAt = default, FinishedAt = default, Target = e.Target, Findings = [f], Installs = [], Cancelled = false };
    var worst = new ScanSnapshot(DateTimeOffset.Now, OverallRisk.High, Completeness.Complete, ["NSC-DLL-SCAN"], ["NSC-DLL-SCAN"]);
    foreach (var s in new[] { ReportBuilder.Html(scan, ioc, null, worst), ReportBuilder.Text(scan, ioc, null, worst), ReportBuilder.JsonReport(scan, ioc, null, worst) })
    {
        foreach (var bad in new[] { "John", "Smith", "김철수", "개인자료" }) True(!s.Contains(bad), bad + " 노출");
        True(s.Contains("debug.log"), "파일 이름 유지");
        True(s.Contains("고위험 증거가 있었습니다"), "이전 기록 누락");
    }
});
TA("27 접근 거부 이동은 재부팅이 아니라 실패로 표시", async () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    var plan = PlanBuilder.Build(r, null);
    var q = plan.Items.Single(i => i.Kind == PlanKind.QuarantineDll);
    Directory.CreateDirectory(e.Data.Root);
    File.WriteAllText(e.Data.Quarantine, "file blocks folder");
    var res = await e.Exec().ExecuteAsync(plan, new HashSet<string> { q.Id }, r, false, null, default);
    Eq(ItemOutcome.Failed, res.Single(x => x.ItemId == q.Id).Outcome);
    True(File.Exists(dll));
});
T("28 재부팅 대기는 실제 재부팅 전에는 지워지지 않음", () =>
{
    using var e = NewEnv();
    var j = Journal.Create(e.Data, "aaaaaaaa");
    j.Write("item-result", new ItemResult("x", PlanKind.QuarantineDll, "t", ItemOutcome.PendingReboot, "m", DateTimeOffset.Now));
    j.Write("run-finished", new { Count = 1 });
    Journal.MarkReviewedAfterRescan(e.Data, DateTime.UtcNow.AddHours(-1));
    Eq(1, Journal.FindPending(e.Data).PendingReboot);
    Journal.MarkReviewedAfterRescan(e.Data, DateTime.UtcNow.AddHours(1));
    Eq(0, Journal.FindPending(e.Data).PendingReboot);
});
T("29 악성 URL 요청과 다운로드 성공은 다른 증거 단계", () =>
{
    using var e = NewEnv();
    var l = e.Install(); e.DebugLog("x\n");
    var tg = Path.Combine(l, "log", "tinyget"); Directory.CreateDirectory(tg);
    var f = Path.Combine(tg, "tinyget.1.log");
    File.WriteAllText(f, "AddTask https://analytics.example/comm/assets/insight.bundle\nOnTaskResult insight.bundle result=7\n");
    Eq(EvidenceStage.ExposureOrAttempt, Of(Scan(e), "NSC-LOG-TINYGET").Single().Stage);
    File.WriteAllText(f, "AddTask insight.bundle\nOnTaskResult insight.bundle result=0\n");
    var s = Of(Scan(e), "NSC-LOG-TINYGET").Single();
    Eq(EvidenceStage.DownloadSucceeded, s.Stage); Eq(Severity.Suspicious, s.Severity);
    True(s.Detail.Contains("실행까지 되었는지는"), "실행 미확정 안내 없음");
});
T("30 LevelDB 내부 문자열: 별도 파일 없이 탐지, 상태 값은 보고서에서 제외", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    var ls = Path.Combine(PathSafety.LauncherCacheDir(e.Target), "Local Storage", "leveldb"); Directory.CreateDirectory(ls);
    File.WriteAllText(Path.Combine(ls, "000005.ldb"), "_https://www.nikkelauncher.com k2f.agent.state {\"password\":\"s3cret-agent-pass\",\"token\":\"tok-abc-123\"}");
    var r = Scan(e);
    var f = Of(r, "NSC-LS-STATE").Single();
    Eq(EvidenceStage.AgentExecuted, f.Stage);
    foreach (var s in new[] { ReportBuilder.Html(r, ioc), ReportBuilder.Text(r, ioc), ReportBuilder.JsonReport(r, ioc) })
        True(!s.Contains("s3cret-agent-pass") && !s.Contains("tok-abc-123"), "상태 값 노출");
    True(!System.Text.Json.JsonSerializer.Serialize(f).Contains("s3cret"), "결과에 상태 값 저장");
});
T("31 onominan.tmp와 관련 회사 게임만 있으면 판정·조치 없음", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    File.WriteAllText(Path.Combine(e.Target.TempDir, "onominan.tmp"), "x");
    foreach (var g in new[] { "PUBG MOBILE", "Delta Force", "Honor of Kings", "Arena Breakout Infinite", "Dune Awakening", "Undawn" })
    {
        var d = Path.Combine(e.Root, "Program Files", g); Directory.CreateDirectory(d);
        e.Hints.Hints.Add(new InstallHint(d, "설치 정보"));
    }
    var r = Scan(e);
    Eq(OverallRisk.NoKnownTraces, r.Risk); Eq(1, r.Installs.Count);
    True(!PlanBuilder.Build(r, null).Items.Any(i => i.Kind is PlanKind.QuarantineDll or PlanKind.RemoveComKey));
    True(!ioc.AgentTempFilePrefixes.Any(p => p.Contains("onominan")));
});
T("32 DLL 존재와 로드 상태 구분, 과거 실행 경고 유지, 원인 미확인 표시", () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var r = Scan(e);
    var d = Of(r, "NSC-DLL-SCAN").Single();
    Eq(EvidenceStage.PersistenceInstalled, d.Stage);
    True(d.Detail.Contains("지금 실행 중이라는 뜻은 아닙니다"));
    True(!Verdict.StagesOf(r.Findings).Contains(EvidenceStage.CurrentlyLoaded), "미로드를 로드로 표시");
    True(Verdict.CauseNote(r.Findings)!.StartsWith("감염 원인 미확인"));
    e.Procs.PlantedModule = dll;
    var r2 = Scan(e);
    True(Verdict.StagesOf(r2.Findings).Contains(EvidenceStage.CurrentlyLoaded), "로드 미표시");
    e.DebugLog(ExecLine + "\n");
    var r3 = Scan(e);
    Eq(null, Verdict.CauseNote(r3.Findings));
    e.Procs.PlantedModule = null;
    File.Delete(dll);
    True(Verdict.StagesOf(Scan(e).Findings).Contains(EvidenceStage.AgentExecuted), "과거 실행 경고 해제");
});
TA("33 조치 내역은 다시 열어도 남고, 시험 실행과 선택 안 한 항목은 남지 않음", async () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    var key = e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var cache = PathSafety.LauncherCacheDir(e.Target); Directory.CreateDirectory(cache);
    var r = Scan(e);
    var plan = PlanBuilder.Build(r, null);
    var ids = plan.Items.Where(i => i.Kind is PlanKind.RemoveComKey or PlanKind.QuarantineDll or PlanKind.ClearLauncherCache).Select(i => i.Id).ToHashSet();
    await e.Exec().ExecuteAsync(plan, ids, r, true, null, default);
    Eq(0, HistoryStore.LoadActions(e.Data).Count, "시험 실행 기록");
    await e.Exec().ExecuteAsync(plan, ids, r, false, null, default);
    var acts = HistoryStore.LoadActions(e.Data);
    Eq(3, acts.Count, "조치 기록");
    True(acts.All(a => a.Outcome == ItemOutcome.Succeeded));
    True(!acts.Any(a => a.Kind == PlanKind.BlockKnownNetwork), "선택 안 한 항목 기록");
    foreach (var a in acts) True(Guidance.ManualCheckNote(a.Kind) is not null, "안내 누락");
    HistoryStore.AppendActions(e.Data, [new ItemResult("x", PlanKind.DefenderQuickScan, "t", ItemOutcome.Succeeded, "m", DateTimeOffset.Now)]);
    Eq(4, HistoryStore.LoadActions(e.Data).Count);
    Eq(null, Guidance.ManualCheckNote(PlanKind.DefenderQuickScan));
    File.WriteAllText(Path.Combine(e.Data.History, "actions.json"), "{broken");
    Eq(0, HistoryStore.LoadActions(e.Data).Count, "손상된 기록");
});
T("34 조치 후 수동 확인 안내: 사라지는 항목을 실행 전에 알리고 debug.log는 유지", () =>
{
    using var e = NewEnv();
    var dll = e.PlantDll(Encoding.ASCII.GetBytes("a"), matchName: false);
    e.PlantCom(dll);
    var log = e.DebugLog(ExecLine + "\n");
    Directory.CreateDirectory(PathSafety.LauncherCacheDir(e.Target));
    var plan = PlanBuilder.Build(Scan(e), null);
    foreach (var k in new[] { PlanKind.RemoveComKey, PlanKind.QuarantineDll, PlanKind.ClearLauncherCache })
        True(plan.Items.Single(i => i.Kind == k).WhatChanges.Contains("실행하면"), k + " 안내 누락");
    True(Guidance.ManualCheckIntro.Contains("안전하다는 뜻은 아닙니다"), "안전 오해 문구");
    True(File.Exists(log));
});
T("35 이름에 니케가 없어도 같은 구조의 런처 폴더는 같은 기준으로 검사, 조치 대상은 아님", () =>
{
    using var e = NewEnv();
    var other = Path.Combine(e.Root, "Games", "SomeOtherGame", "Launcher");
    Directory.CreateDirectory(Path.Combine(other, "intl_service"));
    File.WriteAllText(Path.Combine(other, "intl_service", "debug.log"), ExecLine + "\n");
    var exe = Path.Combine(other, "nikke_launcher_fake.exe"); File.WriteAllText(exe, "x");
    e.Hints.Hints.Add(new InstallHint(other, "설치 정보"));
    var r = Scan(e);
    Eq(1, r.Installs.Count); True(!r.Installs[0].IsNikke, "니케로 분류");
    var f = Of(r, "NSC-LOG-EXEC").Single();
    Eq(Severity.High, f.Severity); True(f.OtherLauncher); True(f.Detail.StartsWith("[니케 외 런처 폴더]"));
    True(Verdict.CauseNote(r.Findings)!.Contains("단정할 수는 없지만"));
    var plan = PlanBuilder.Build(r, null);
    True(!plan.Items.Any(i => i.Kind is PlanKind.ClearLauncherCache or PlanKind.BlockLauncherOutbound), "다른 런처 조치");
    True(plan.ManualNotes.Any(n => n.Contains("니케 외 런처")));
});
T("36 드라이브 탐색: 깊은 위치의 같은 구조 폴더를 찾고 구조가 없으면 무시", () =>
{
    using var e = NewEnv();
    var deep = Path.Combine(e.Root, "drive", "Games", "Level Infinite", "Other", "Launcher");
    Directory.CreateDirectory(Path.Combine(deep, "intl_service"));
    Directory.CreateDirectory(Path.Combine(e.Root, "drive", "Games", "NoStructureGame", "Launcher"));
    e.Hints.Roots.Add(Path.Combine(e.Root, "drive"));
    var list = InstallLocator.Locate(e.Hints, [], new ScanLimits(), default, out var limited);
    True(!limited, "제한");
    Eq(1, list.Count); Eq(deep, list[0].LauncherDir);
});
T("37 다른 런처 저장소는 검사만, HMT 저장소는 니케로 검사·정리", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    string Ls(string baseDir) { var d = Path.Combine(baseDir, "tbs_cache", "Local Storage", "leveldb"); Directory.CreateDirectory(d); return d; }
    File.WriteAllText(Path.Combine(Ls(Path.Combine(e.Target.RoamingAppData, "other_launcher")), "1.log"), "k2f.agent.state");
    var r = Scan(e);
    var o = Of(r, "NSC-LS-STATE").Single(x => x.OtherLauncher);
    Eq(Severity.High, o.Severity);
    True(!PlanBuilder.Build(r, null).Items.Any(i => i.ExpectedPath?.Contains("other_launcher") == true), "다른 런처 캐시가 정리 대상");
    File.WriteAllText(Path.Combine(Ls(Path.Combine(e.Target.RoamingAppData, "nikke_launcher_hmt")), "1.log"), "k2f.agent.state");
    var r2 = Scan(e);
    True(Of(r2, "NSC-LS-STATE").Any(x => !x.OtherLauncher && x.Severity == Severity.High && x.Path!.Contains("hmt")), "HMT 미탐지");
    var plan = PlanBuilder.Build(r2, null);
    True(plan.Items.Single(i => i.Kind == PlanKind.ClearLauncherCache).Title.Contains("HMT"));
});
TA("38 다른 런처 캐시 경로를 계획에 위조해도 조치 거부", async () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    var fake = Path.Combine(e.Target.RoamingAppData, "other_launcher", "tbs_cache"); Directory.CreateDirectory(fake);
    var r = Scan(e);
    var item = new PlanItem { Id = "x", Kind = PlanKind.ClearLauncherCache, Title = "t", WhatChanges = "w", ExpectedPath = fake };
    var res = await e.Exec().ExecuteAsync(new RemediationPlan("p0000000", "s", Sid, DateTimeOffset.Now, [item], []), new HashSet<string> { "x" }, r, false, null, default);
    Eq(ItemOutcome.Aborted, res.Single().Outcome);
    True(Directory.Exists(fake));
});
T("39 설치 경로 힌트: .reg 내용에서 경로만 추출, 공격 도메인 로그와 접속 기록은 의심, 빈 해시 폴더도 알림", () =>
{
    var paths = InstallLocator.PathsInRegText("[HKEY_CURRENT_USER\\Software\\Classes\\nikkelauncher\\Shell\\Open\\Command]\r\n@=\"\\\"D:\\\\Games\\\\Level Infinite\\\\NIKKE\\\\Launcher\\\\nikke_launcher.exe\\\" \\\"%1\\\"\"").ToList();
    Eq(1, paths.Count); Eq(@"D:\Games\Level Infinite\NIKKE\Launcher\nikke_launcher.exe", paths[0]);
    using var e = NewEnv();
    e.Install(); e.DebugLog("[1101/1:INFO:CONSOLE(1)] \"load https://insightjs.com/l.js failed\", source: https://x (1)\n");
    Eq(Severity.Suspicious, Of(Scan(e), "NSC-LOG-EXEC").Single().Severity);
    e.DebugLog("x\n");
    var cache = PathSafety.LauncherCacheDir(e.Target); Directory.CreateDirectory(Path.Combine(cache, "Network"));
    File.WriteAllText(Path.Combine(cache, "Network", "Network Persistent State"), "{\"server\":\"https://insightjs.com\"}");
    Eq(Severity.Suspicious, Of(Scan(e), "NSC-CACHE-LOADER").Single().Severity);
    Directory.CreateDirectory(Path.Combine(e.ChromeHelper(), new string('c', 64)));
    var dl = Of(Scan(e), "NSC-DLL-SCAN").Single();
    Eq(Severity.Suspicious, dl.Severity); Eq(RemediationEligibility.ManualOnly, dl.RemediationEligibility);
});
T("15 IOC 데이터 무결성과 출처", () =>
{
    True(ioc.BlockDomains.Contains("analytics.insightjs.com"));
    True(ioc.KnownDllSha256.Any(h => h.Sha256.StartsWith("f3e93d04")));
    True(!ioc.BlockIps.Contains("89.126.250.172"), "미검증 IP는 차단 대상 제외");
    True(DateTime.Parse(ioc.ReviewAfter) > DateTime.Parse(ioc.ObservedAt));
});
T("16 Reparse/UNC COM 값은 자동 조치 불가", () =>
{
    using var e = NewEnv();
    e.Reg.Add($@"HKU\{Sid}_Classes\CLSID\{Clsid}\InprocServer32", new() { [""] = @"\\evil\share\PlatformExperienceHelper\" + new string('a', 64) + @"\platform_experience_helper.dll" });
    e.Install(); e.DebugLog("x\n");
    Eq(RemediationEligibility.ManualOnly, Of(Scan(e), "NSC-COM-KNOWN").Single().RemediationEligibility);
});
T("17 DLL 빠진 COM 잔여물은 과거 고위험+제거 가능(값 구조 완전 일치)", () =>
{
    using var e = NewEnv();
    var dll = Path.Combine(e.ChromeHelper(), new string('d', 64), PathSafety.DllName);
    e.PlantCom(dll);
    e.Install(); e.DebugLog("x\n");
    var f = Of(Scan(e), "NSC-COM-KNOWN").Single();
    Eq(Severity.High, f.Severity); Eq(Temporal.Past, f.Temporal); Eq(RemediationEligibility.Eligible, f.RemediationEligibility);
});
T("18 다른 브라우저 단독 DLL은 의심, COM 연결 시에만 고위험", () =>
{
    using var e = NewEnv();
    var bytes = Encoding.ASCII.GetBytes("edge");
    var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
    var dir = Path.Combine(e.Target.LocalAppData, "Microsoft", "Edge", "User Data", PathSafety.HelperDirName, hash); Directory.CreateDirectory(dir);
    var dll = Path.Combine(dir, PathSafety.DllName); File.WriteAllBytes(dll, bytes);
    e.Install(); e.DebugLog("x\n");
    Eq(Severity.Suspicious, Of(Scan(e), "NSC-DLL-SCAN").Single().Severity);
    e.PlantCom(dll);
    Eq(Severity.High, Of(Scan(e), "NSC-DLL-SCAN").Single().Severity);
});
T("19 런타임 모듈 경로 불일치는 판정 안 함(프로세스 이름만으로 판정 금지)", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    e.Procs.ForeignModule = true;
    Eq(CheckStatus.NotFound, Of(Scan(e), "NSC-PROC-MOD").Single().Status);
});
T("20 tinyget 다운로드·로더 캐시는 의심 등급", () =>
{
    using var e = NewEnv();
    var l = e.Install(); e.DebugLog("x\n");
    var tg = Path.Combine(l, "log", "tinyget"); Directory.CreateDirectory(tg);
    File.WriteAllText(Path.Combine(tg, "tinyget.1.log"), "OnTaskResult insight.bundle result=0");
    var cc = Path.Combine(PathSafety.LauncherCacheDir(e.Target), "Code Cache", "js"); Directory.CreateDirectory(cc);
    File.WriteAllText(Path.Combine(cc, "abc"), "https://insightjs.com/l.js?f=aegis");
    var r = Scan(e);
    Eq(Severity.Suspicious, Of(r, "NSC-LOG-TINYGET").Single().Severity);
    Eq(Severity.Suspicious, Of(r, "NSC-CACHE-LOADER").Single().Severity);
    Eq(OverallRisk.Suspicious, r.Risk);
});
T("21 임시 파일은 이름만 확인하고 자동 삭제하지 않음", () =>
{
    using var e = NewEnv();
    e.Install(); e.DebugLog("x\n");
    var p = Path.Combine(e.Target.TempDir, "k2f-bcreds-1234"); File.WriteAllText(p, "secret");
    var r = Scan(e);
    Eq(Severity.Suspicious, Of(r, "NSC-TEMP").Single().Severity);
    True(!Of(r, "NSC-TEMP").Single().Detail.Contains("secret"));
    True(PlanBuilder.Build(r, null).ManualNotes.Any());
    True(File.Exists(p));
});

Console.WriteLine($"\n통과 {passed}, 실패 {failures.Count}");
foreach (var f in failures) Console.WriteLine("  실패: " + f);
return failures.Count == 0 ? 0 : 1;

sealed class FakeRegistry : IRegistryStore
{
    public readonly Dictionary<string, Dictionary<string, string>> Keys = new(StringComparer.OrdinalIgnoreCase);
    public readonly List<string> Deletes = [];
    public readonly List<string> ReadPaths = [];
    public bool DenyAll, HiveLoaded = true;
    public void Add(string p, Dictionary<string, string> v) => Keys[p] = v;
    public RegistryKeySnapshot? Read(string path)
    {
        if (DenyAll) throw new UnauthorizedAccessException();
        ReadPaths.Add(path);
        var subs = ListSubKeys(path);
        if (!Keys.TryGetValue(path, out var v) && subs.Count == 0) return null;
        return new RegistryKeySnapshot(v ?? [], subs);
    }
    public bool IsHiveLoaded(string h) => HiveLoaded;
    public IReadOnlyList<string> ListSubKeys(string path)
    {
        if (DenyAll) throw new UnauthorizedAccessException();
        return Keys.Keys.Where(k => k.StartsWith(path + "\\", StringComparison.OrdinalIgnoreCase))
            .Select(k => k[(path.Length + 1)..].Split('\\')[0]).Distinct().ToList();
    }
    public void DeleteEmptyKey(string path)
    {
        if (path.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("HKLM 금지");
        Deletes.Add(path); Keys.Remove(path);
    }
}
sealed class FakeSig : IFileSignatureChecker { public SignatureState State = SignatureState.Unsigned; public SignatureState Check(string p) => State; }
sealed class FakeIds : IFileIdentityProvider { public string? GetFileId(string p) => null; }
sealed class FakeProtector : IFileProtector
{
    public readonly List<string> Protected = [];
    public void ProtectForQuarantine(string p) => Protected.Add(p);
    public void RestrictToCurrentUser(string d) { }
}
sealed class FakeProcs : IProcessInspector
{
    public bool Running, LoadedHit, Throw, ForeignModule;
    public string? PlantedModule;
    public IReadOnlyList<RunningProcess> FindByNames(IEnumerable<string> n) => Running ? [new(1, "nikke_launcher", null)] : [];
    public ModuleInspection FindLoadedModule(string m, CancellationToken ct)
    {
        if (Throw) throw new UnauthorizedAccessException();
        if (PlantedModule is not null) return new([new(1, "chrome", PlantedModule)], 0);
        if (LoadedHit) return new([new(1, "chrome", "x")], 0);
        if (ForeignModule) return new([new(1, "nikke_launcher", @"C:\Program Files\x\platform_experience_helper.dll")], 0);
        return new([], 0);
    }
}
sealed class FakeNet : INetworkInspector
{
    public bool Throw;
    public IReadOnlyList<string> FindConnections(IEnumerable<string> i) => Throw ? throw new UnauthorizedAccessException() : [];
    public IReadOnlyList<string>? FindDnsCacheEntries(IEnumerable<string> d) => Throw ? null : [];
}
sealed class FakeHints : IInstallHintSource
{
    public readonly List<InstallHint> Hints = [];
    public readonly List<string> Roots = [];
    public IEnumerable<InstallHint> GetHints(CancellationToken ct) => Hints;
    public IEnumerable<string> GetFixedDriveRoots() => Roots;
}
sealed class FakePriv : IPrivilegedRunner
{
    public bool Fail; public int Calls;
    private Task<NetworkActionResult> R() { Calls++; return Task.FromResult(new NetworkActionResult(!Fail, Fail ? "관리자 승인 취소" : "ok")); }
    public Task<NetworkActionResult> BlockKnownNetworkAsync(CancellationToken c) => R();
    public Task<NetworkActionResult> BlockLauncherAsync(string l, CancellationToken c) => R();
    public Task<NetworkActionResult> UnblockAllAsync(CancellationToken c) => R();
    public Task<NetworkActionResult> StartDefenderOfflineAsync(CancellationToken c) => R();
}
sealed class FakeDefender : IDefenderService
{
    public DefenderStatus Query() => new(true, "", [], true);
    public Task<NetworkActionResult> RunScanAsync(bool full, CancellationToken ct) => Task.FromResult(new NetworkActionResult(true, "ok"));
}

sealed class Env : IDisposable
{
    public readonly string Root;
    public readonly FakeRegistry Reg = new();
    public readonly FakeSig Sig = new();
    public readonly FakeProcs Procs = new();
    public readonly FakeNet Net = new();
    public readonly FakeHints Hints = new();
    public readonly FakeProtector Protector = new();
    public readonly FakePriv Priv = new();
    public readonly List<string> Installs = [];
    public readonly TargetUser Target;
    public readonly DataPaths Data;
    public readonly PlatformServices Services;
    private readonly IocData _ioc;

    public Env(string root, IocData ioc)
    {
        Root = root; _ioc = ioc;
        var profile = Path.Combine(root, "Users", "tester");
        var local = Path.Combine(profile, "AppData", "Local");
        var roaming = Path.Combine(profile, "AppData", "Roaming");
        var temp = Path.Combine(local, "Temp");
        Directory.CreateDirectory(temp); Directory.CreateDirectory(roaming);
        Target = new TargetUser("S-1-5-21-1000-2000-3000-1001", "tester", "TESTPC", profile, local, roaming, temp, true, "tester");
        Data = DataPaths.ForTarget(Target);
        Services = new PlatformServices(Reg, Sig, new FakeIds(), Procs, Net, Hints);
    }
    public string Install()
    {
        var d = Path.Combine(Root, "Games", "NIKKE", "Launcher");
        Directory.CreateDirectory(Path.Combine(d, "intl_service"));
        if (!Installs.Contains(d)) Installs.Add(d);
        return d;
    }
    public string DebugLog(string content)
    {
        var p = Path.Combine(Install(), "intl_service", "debug.log");
        File.WriteAllText(p, content);
        return p;
    }
    public string ChromeHelper()
    {
        var d = Path.Combine(Target.LocalAppData, "Google", "Chrome", "User Data", PathSafety.HelperDirName);
        Directory.CreateDirectory(d);
        return d;
    }
    public string PlantDll(byte[] content, bool matchName)
    {
        var name = matchName ? Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(content)) : new string('e', 64);
        var dir = Path.Combine(ChromeHelper(), name);
        Directory.CreateDirectory(dir);
        var p = Path.Combine(dir, PathSafety.DllName);
        File.WriteAllBytes(p, content);
        return p;
    }
    public string PlantCom(string dll)
    {
        var key = $@"HKU\{Target.Sid}_Classes\CLSID\{{E77CC89B-7401-4C04-8CED-149DB35ADD04}}\InprocServer32";
        Reg.Add(key, new() { [""] = dll, ["ThreadingModel"] = "Both" });
        return key;
    }
    public RemediationExecutor Exec() => new(new ExecutorDeps(_ioc, Reg, new FakeIds(), Protector, Procs, Priv, new FakeDefender()), Target, Data);
    public void Dispose() { try { Directory.Delete(Root, true); } catch { } }
}
