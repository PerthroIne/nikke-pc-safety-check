using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using NikkeSafetyCheck.Core;
using NikkeSafetyCheck.UI;
using NikkeSafetyCheck.Windows;

namespace NikkeSafetyCheck.WinTests;

/// <summary>
/// 일회용 Windows VM에서만 실행하는 통합 테스트. 무해한 가짜 파일과 앱 소유 설정만 만들고 지운다.
/// 인자: --out 폴더 --app 게시된exe [--e2e]
/// </summary>
public static class Program
{
    private const string Clsid = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
    private static readonly List<string> Failures = [];
    private static int _passed;
    private static string _out = ".";

    private static void T(string name, Action body)
    {
        try { body(); _passed++; Console.WriteLine($"PASS  {name}"); }
        catch (Exception e) { Failures.Add(name); Console.WriteLine($"FAIL  {name}\n      {e.GetType().Name}: {e.Message}\n{e.StackTrace}"); }
    }
    private static void True(bool c, string m = "조건 불일치") { if (!c) throw new Exception(m); }

    [STAThread]
    public static int Main(string[] args)
    {
        string? app = null; var e2e = false; var limited = false;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--out") _out = args[++i];
            else if (args[i] == "--app") app = args[++i];
            else if (args[i] == "--e2e") e2e = true;
            else if (args[i] == "--limited") limited = true;
        }
        Directory.CreateDirectory(_out);
        var ioc = IocData.LoadEmbedded();
        var target = TargetUserResolver.Resolve();
        if (limited)
        {
            // 관리자 권한을 뺀 일반 토큰으로 사용자 범위 점검·조치를 실제로 실행한다.
            var result = Path.Combine(_out, "limited-result.txt");
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                var admin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                RealFlow(ioc, target);
                File.WriteAllText(result, $"OK admin={admin}");
            }
            catch (Exception ex) { File.WriteAllText(result, "FAIL " + ex); }
            return 0;
        }
        Console.WriteLine($"OS: {Environment.OSVersion}, 64bit={Environment.Is64BitOperatingSystem}");

        T("W01 대상 사용자 해석", () =>
        {
            using var me = WindowsIdentity.GetCurrent();
            True(target.Sid.StartsWith("S-1-"), "SID");
            True(Directory.Exists(target.LocalAppData), "LocalAppData");
            Console.WriteLine($"      sameUser={target.ProcessIsTargetUser}");
        });

        T("W02 실제 레지스트리와 파일로 점검→조치→재점검", () => RealFlow(ioc, target));
        T("W02b 일반 권한 토큰으로 점검→조치", () =>
        {
            var self = Environment.ProcessPath!;
            var result = Path.Combine(Path.GetFullPath(_out), "limited-result.txt");
            File.Delete(result);
            var dll = Path.ChangeExtension(self, ".exe");
            var inner = $"\\\"{dll}\\\" --limited --out \\\"{Path.GetFullPath(_out)}\\\"";
            var p = Process.Start(new ProcessStartInfo("runas.exe") { Arguments = $"/trustlevel:0x20000 \"{inner}\"", UseShellExecute = false, CreateNoWindow = true })!;
            var sw = Stopwatch.StartNew();
            while (!File.Exists(result) && sw.Elapsed.TotalSeconds < 150) Thread.Sleep(500);
            True(File.Exists(result), "일반 토큰 실행 결과 없음");
            Thread.Sleep(300);
            var text = File.ReadAllText(result);
            Console.WriteLine("      " + text);
            True(text.StartsWith("OK admin=False"), text);
        });
        T("W03 HKLM 항목은 건드리지 않음", () =>
        {
            using var k = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32");
            Console.WriteLine($"      HKLM 존재={k is not null}");
            var threw = false;
            try { new WindowsRegistryStore().DeleteEmptyKey($@"HKLM\SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32"); } catch (InvalidOperationException) { threw = true; }
            True(threw, "HKLM 삭제 요청이 거부되지 않음");
            using var k2 = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32");
            True((k is null) == (k2 is null));
        });
        T("W04 정션(reparse point) 감지", () =>
        {
            var root = Path.Combine(Path.GetTempPath(), "nsc-j-" + Guid.NewGuid().ToString("N")[..6]);
            var real = Path.Combine(root, "real"); var j = Path.Combine(root, "link");
            Directory.CreateDirectory(real);
            var p = Process.Start(new ProcessStartInfo("cmd.exe") { ArgumentList = { "/c", "mklink", "/J", j, real }, UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
            p.WaitForExit();
            True(PathSafety.IsReparse(j), "정션 미감지");
            True(PathSafety.HasReparseInChain(root, Path.Combine(j, "a.dll")), "체인 미감지");
            Directory.Delete(j); Directory.Delete(root, true);
        });
        T("W05 서명 확인(파일을 불러오지 않음)", () =>
        {
            var c = new WindowsSignatureChecker();
            var txt = Path.GetTempFileName();
            File.WriteAllText(txt, "not a pe");
            True(c.Check(txt) is SignatureState.Unsigned or SignatureState.Unknown, "텍스트 파일 서명 판정");
            File.Delete(txt);
            var dotnet = Environment.ProcessPath!;
            Console.WriteLine($"      self={c.Check(dotnet)}");
            var signed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
            if (File.Exists(signed)) { var s = c.Check(signed); Console.WriteLine($"      dotnet.exe={s}"); True(s == SignatureState.Valid, "서명 파일 판정"); }
        });
        T("W06 파일 ID는 교체 시 달라짐", () =>
        {
            var ids = new WindowsFileIdProvider();
            var f = Path.GetTempFileName(); var a = ids.GetFileId(f);
            File.Delete(f); File.WriteAllText(f + ".x", "x"); File.Move(f + ".x", f);
            True(a is not null && a != ids.GetFileId(f), "ID 동일");
            File.Delete(f);
        });
        T("W07 관리자 보조 인자 검증", () =>
        {
            foreach (var bad in new[]
            {
                new[] { ElevatedHelper.Flag }, new[] { ElevatedHelper.Flag, "block-known", "--pipe", "bad-name" },
                new[] { ElevatedHelper.Flag, "cmd /c calc", "--pipe", "NSC-" + new string('a', 32) },
                new[] { ElevatedHelper.Flag, "block-known", "--pipe", "NSC-" + new string('a', 32), "--launcher", "C:\\x" },
                new[] { ElevatedHelper.Flag, "block-launcher", "--pipe", "NSC-" + new string('a', 32) },
            })
                True(ElevatedHelper.Run(bad) == 64, "잘못된 인자 허용: " + string.Join(' ', bad));
        });
        T("W08 런처 차단 입력 검증", () =>
        {
            var r = new NetworkBlockService().BlockLauncher(@"C:\Windows\System32\cmd.exe");
            True(!r.Ok, "임의 프로그램 차단 허용");
        });
        T("W09 방화벽·hosts 실제 적용, 반복 실행, 복구", () =>
        {
            var svc = new NetworkBlockService();
            var original = File.ReadAllBytes(svc.HostsPath);
            var aclBefore = new FileInfo(svc.HostsPath).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            try
            {
                var r1 = svc.BlockKnown(ioc); Console.WriteLine("      1차: " + r1.Message);
                var count1 = svc.CountOwnedRules();
                var after1 = File.ReadAllBytes(svc.HostsPath);
                var r2 = svc.BlockKnown(ioc); Console.WriteLine("      2차: " + r2.Message);
                True(svc.CountOwnedRules() == count1 && count1 == ioc.BlockIps.Length, $"규칙 수 {count1}");
                True(File.ReadAllBytes(svc.HostsPath).SequenceEqual(after1), "hosts 중복");
                True(new FileInfo(svc.HostsPath).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access) == aclBefore, "ACL 변경");
                var u = svc.Unblock(); Console.WriteLine("      복구: " + u.Message);
                True(u.Ok, "복구 실패");
                True(svc.CountOwnedRules() == 0, "규칙 남음");
                True(File.ReadAllBytes(svc.HostsPath).SequenceEqual(original), "hosts 원문 불일치");
            }
            finally { try { svc.Unblock(); } catch (Exception) { } }
        });
        T("W10 Defender·보안 제품 조회가 앱을 멈추지 않음", () =>
        {
            var s = new WindowsDefenderService().Query();
            Console.WriteLine($"      active={s.DefenderActive} queried={s.Queried} {s.Summary}");
        });
        T("W11 화면 렌더링 스크린샷", () => RenderScreens(ioc));

        if (e2e && app is not null) T("W12 게시된 EXE 실제 흐름(UI 자동화)", () => EndToEnd(app, ioc, target));

        Console.WriteLine($"\n통과 {_passed}, 실패 {Failures.Count}");
        foreach (var f in Failures) Console.WriteLine("  실패: " + f);
        return Failures.Count == 0 ? 0 : 1;
    }

    private static string ClassesKey => $@"Software\Classes\CLSID\{Clsid}";

    private static string PlantDll(TargetUser t, string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        var dir = Path.Combine(t.LocalAppData, "Google", "Chrome", "User Data", PathSafety.HelperDirName, new string('a', 64));
        Directory.CreateDirectory(dir);
        var dll = Path.Combine(dir, PathSafety.DllName);
        File.WriteAllBytes(dll, bytes);
        return dll;
    }

    private static void PlantCom(string dll)
    {
        using var k = Registry.CurrentUser.CreateSubKey(ClassesKey + @"\InprocServer32");
        k.SetValue("", dll); k.SetValue("ThreadingModel", "Both");
    }

    private static void CleanFixture(TargetUser t)
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(ClassesKey, false); } catch (Exception) { }
        try { Directory.Delete(Path.Combine(t.LocalAppData, "Google", "Chrome", "User Data", PathSafety.HelperDirName), true); } catch (Exception) { }
        try { Directory.Delete(Path.Combine(t.RoamingAppData, "nikke_launcher"), true); } catch (Exception) { }
        var data = DataPaths.ForTarget(t).Root;
        try { if (Directory.Exists(data)) { new WindowsFileProtector().RestrictToCurrentUser(data); Directory.Delete(data, true); } } catch (Exception) { }
    }

    private static void RealFlow(IocData ioc, TargetUser t)
    {
        CleanFixture(t);
        var fake = Path.Combine(Path.GetTempPath(), "nsc 설치 " + Guid.NewGuid().ToString("N")[..6], "NIKKE", "Launcher");
        Directory.CreateDirectory(Path.Combine(fake, "intl_service"));
        File.WriteAllText(Path.Combine(fake, "intl_service", "debug.log"), "[1101/012037.043:INFO:CONSOLE(1)] \"k2f_chan registered\", source: (1)\n");
        var parent = Path.Combine(t.LocalAppData, "Google", "Chrome", "User Data", PathSafety.HelperDirName);
        var dll = PlantDll(t, "harmless test file, not a real dll");
        var okExe = Path.Combine(parent, "platform_experience_helper.exe");
        File.WriteAllText(okExe, "harmless"); File.WriteAllText(Path.Combine(parent, "LoadFeatures"), "");
        PlantCom(dll);
        var cache = PathSafety.LauncherCacheDir(t);
        Directory.CreateDirectory(Path.Combine(cache, "Local Storage", "leveldb"));
        File.WriteAllText(Path.Combine(cache, "Local Storage", "leveldb", "000001.log"), "k2f.agent.state");
        try
        {
            var svc = WindowsPlatform.Create(t);
            var engine = new ScanEngine(ioc, svc, "wintest");
            var scan = engine.Run(new ScanRequest { Target = t, ExtraFolders = [fake] }, null, default);
            foreach (var f in scan.Findings) Console.WriteLine($"      {f.RuleId} {f.Status} {f.Severity}");
            True(scan.Risk == OverallRisk.High, "고위험 아님");
            True(scan.Findings.Single(f => f.RuleId == "NSC-COM-KNOWN").RegistryKey!.StartsWith($@"HKU\{t.Sid}_Classes\"), "실제 하이브 경로 아님");
            var plan = PlanBuilder.Build(scan, null);
            True(plan.Items.Any(i => i.Kind == PlanKind.RemoveComKey) && plan.Items.Any(i => i.Kind == PlanKind.QuarantineDll), "계획 누락");
            var priv = new NoElevation();
            var exec = new RemediationExecutor(new ExecutorDeps(ioc, svc.Registry, svc.FileIds, new WindowsFileProtector(), svc.Processes, priv, new WindowsDefenderService()), t, DataPaths.ForTarget(t));
            var ids = plan.Items.Where(i => i.Kind is PlanKind.RemoveComKey or PlanKind.QuarantineDll or PlanKind.ClearLauncherCache).Select(i => i.Id).ToHashSet();
            var res = exec.ExecuteAsync(plan, ids, scan, false, null, default).GetAwaiter().GetResult();
            foreach (var r in res) Console.WriteLine($"      {r.Kind} {r.Outcome}: {r.Message}");
            True(res.Where(r => ids.Contains(r.ItemId)).All(r => r.Outcome == ItemOutcome.Succeeded), "조치 실패");
            True(!File.Exists(dll), "DLL 남음");
            True(File.Exists(okExe) && Directory.Exists(parent), "정상 파일 삭제됨");
            using (var k = Registry.CurrentUser.OpenSubKey(ClassesKey)) True(k is null, "COM 키 남음");
            True(!Directory.Exists(cache), "캐시 남음");
            var q = Directory.GetFiles(DataPaths.ForTarget(t).Quarantine).Single();
            var rules = new FileInfo(q).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
            True(rules.All(a => !a.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile)), "격리 파일에 실행 권한");
            var after = engine.Run(new ScanRequest { Target = t, ExtraFolders = [fake] }, null, default);
            True(after.Risk == OverallRisk.High, "로그 증거 유지 안 됨");
            True(after.Findings.Where(f => f.RuleId is "NSC-DLL-SCAN" or "NSC-COM-KNOWN").All(f => f.Status == CheckStatus.NotFound), "재점검 결과");
            // 공유 보고서에 실제 사용자 정보가 없는지
            var html = ReportBuilder.Html(after, ioc);
            True(!html.Contains(t.Sid) && !html.Contains(t.ProfileDir, StringComparison.OrdinalIgnoreCase) && !html.Contains(fake, StringComparison.OrdinalIgnoreCase), "보고서 식별자 노출");
            File.WriteAllText(Path.Combine(_out, "sample-report.html"), html);
        }
        finally
        {
            CleanFixture(t);
            try { Directory.Delete(Path.GetDirectoryName(Path.GetDirectoryName(fake)!)!, true); } catch (Exception) { }
        }
    }

    private sealed class NoElevation : IPrivilegedRunner
    {
        private static Task<NetworkActionResult> R() => Task.FromResult(new NetworkActionResult(false, "테스트"));
        public Task<NetworkActionResult> BlockKnownNetworkAsync(CancellationToken c) => R();
        public Task<NetworkActionResult> BlockLauncherAsync(string l, CancellationToken c) => R();
        public Task<NetworkActionResult> UnblockAllAsync(CancellationToken c) => R();
        public Task<NetworkActionResult> StartDefenderOfflineAsync(CancellationToken c) => R();
    }

    private sealed class StubDefender : IDefenderService
    {
        public DefenderStatus Query() => new(true, "동작 중", [], true);
        public Task<NetworkActionResult> RunScanAsync(bool full, CancellationToken ct) => Task.FromResult(new NetworkActionResult(true, "ok"));
    }

    private static Finding F(IocData ioc, string id, string title, string detail, CheckStatus st, Severity sev = Severity.None, Temporal tmp = Temporal.NotApplicable, RemediationEligibility el = RemediationEligibility.None, EvidenceType ev = EvidenceType.Coverage, bool req = false, string? path = null, string? retry = null, string? key = null, string? sha = null) => new()
    {
        RuleId = id, Title = title, Detail = detail, SourceUrl = ioc.Source("motherSphere"), RuleVersion = ioc.RuleVersion, ObservedAt = DateTimeOffset.Now, UserSid = "S-1-5-21-1-2-3-1001",
        EvidenceType = ev, Confidence = sev == Severity.High ? Confidence.High : Confidence.Medium, Status = st, Severity = sev, Temporal = tmp, RemediationEligibility = el, Required = req, Path = path, RetryHint = retry, RegistryKey = key, Sha256 = sha,
    };

    private static void RenderScreens(IocData ioc)
    {
        var t = new TargetUser("S-1-5-21-1-2-3-1001", "사용자", "PC", @"C:\Users\사용자", @"C:\nsc-preview\Local", @"C:\nsc-preview\Roaming", @"C:\nsc-preview\Temp", true, "사용자");
        var services = new AppServices(ioc, t, new PlatformServices(new WindowsRegistryStore(), new WindowsSignatureChecker(), new WindowsFileIdProvider(), new WindowsProcessInspector(), new WindowsNetworkInspector(), new WindowsInstallHints(t)), new NoElevation(), new StubDefender(), new WindowsFileProtector(), "preview");
        var app = System.Windows.Application.Current ?? new System.Windows.Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };

        ScanResult S(params Finding[] fs) => new() { ScanId = "preview", RuleVersion = ioc.RuleVersion, ToolVersion = "preview", StartedAt = DateTimeOffset.Now, FinishedAt = DateTimeOffset.Now, Target = t, Findings = fs, Installs = [new LauncherInstall(@"C:\NIKKE\Launcher", "일반 설치 경로", null)], Cancelled = false };
        var log = F(ioc, "NSC-LOG-EXEC", "런처 실행 로그(debug.log)", "런처 로그에서 에이전트 실행 기록 3건을 찾았습니다. 첫 기록 11-01 01:20:37, 마지막 기록 11-03 22:10:02(로그 시각, 연도 없음). 과거에 실행되었다는 증거이며, 지금도 실행 중이라는 뜻은 아닙니다.", CheckStatus.Found, Severity.High, Temporal.Past, RemediationEligibility.ManualOnly, EvidenceType.LauncherLogExecution, true, @"C:\NIKKE\Launcher\intl_service\debug.log");
        var dll = F(ioc, "NSC-DLL-SCAN", "의심 DLL", "Chrome 폴더에서 의심 DLL을 찾았습니다. 사용자 COM 항목과 연결되어 있습니다. 서명 없음.", CheckStatus.Found, Severity.High, Temporal.Current, RemediationEligibility.Eligible, EvidenceType.PersistenceDll, true, @"C:\Users\사용자\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\aaaa…\platform_experience_helper.dll", sha: new string('a', 64));
        var com = F(ioc, "NSC-COM-KNOWN", "사용자 COM 등록", "사용자 COM 항목이 브라우저 폴더 안의 의심 DLL을 가리킵니다. 지속 실행 장치가 현재 남아 있다는 결합 증거입니다.", CheckStatus.Found, Severity.High, Temporal.Current, RemediationEligibility.Eligible, EvidenceType.PersistenceCom, true, key: $@"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{Clsid}\InprocServer32");
        var tiny = F(ioc, "NSC-LOG-TINYGET", "다운로드 보조 로그(tinyget)", "페이로드 다운로드 관련 기록 파일 1개를 찾았습니다. 다운로드 흔적만으로 실행을 확정할 수는 없지만 중요한 경고입니다.", CheckStatus.Found, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, EvidenceType.LauncherLogDownload);
        var unk = F(ioc, "NSC-LOG-EXEC", "런처 실행 로그(debug.log)", "설치 위치를 찾지 못해 로그를 확인하지 못했습니다. 게임을 지웠다면 로그도 함께 사라졌을 수 있습니다.", CheckStatus.Unknown, req: true, retry: "설치 폴더를 직접 선택하거나, 설치한 적이 없으면 '설치한 적 없음'을 선택하세요.");
        var nf1 = F(ioc, "NSC-DLL-SCAN", "의심 DLL", "확인한 브라우저 폴더에서 해당 DLL을 찾지 못했습니다.", CheckStatus.NotFound, req: true);
        var nf2 = F(ioc, "NSC-COM-KNOWN", "사용자 COM 등록", "이 사용자 하이브에서 해당 COM 항목을 찾지 못했습니다.", CheckStatus.NotFound, req: true);
        var nf3 = F(ioc, "NSC-LOG-EXEC", "런처 실행 로그(debug.log)", "확인한 로그에서 에이전트 실행 기록을 찾지 못했습니다.", CheckStatus.NotFound, req: true);

        void Snap(string name, Action<MainWindow> act)
        {
            var w = new MainWindow(services) { Width = 960, Height = 900, WindowStyle = WindowStyle.None, ShowInTaskbar = false, Left = -4000, Top = -4000, WindowStartupLocation = WindowStartupLocation.Manual };
            act(w);
            w.Show();
            w.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            w.UpdateLayout();
            var c = (FrameworkElement)w.Content;
            var rtb = new RenderTargetBitmap((int)c.ActualWidth, (int)c.ActualHeight, 96, 96, PixelFormats.Pbgra32);
            rtb.Render(c);
            var enc = new PngBitmapEncoder(); enc.Frames.Add(BitmapFrame.Create(rtb));
            using var fs = File.Create(Path.Combine(_out, name + ".png"));
            enc.Save(fs);
            w.Close();
        }
        var high = S(log, dll, com, tiny);
        Snap("01-welcome", w => { });
        Snap("02-high", w => w.ShowResult(high));
        Snap("03-suspicious", w => w.ShowResult(S(tiny, nf1, nf2)));
        Snap("04-incomplete", w => w.ShowResult(S(unk, nf1, nf2) with { Installs = [] }));
        Snap("05-no-known", w => w.ShowResult(S(nf1, nf2, nf3)));
        var plan = PlanBuilder.Build(high with { Findings = [log, dll with { Sha256 = new string('a', 64), Path = dll.Path }, com with { RegistryValue = "x" }] }, new DefenderStatus(true, "", [], true));
        Snap("06-plan", w => { w.ShowResult(high); w.ShowPlan(plan); });
        Snap("07-guide", w => { w.ShowResult(high); w.ShowGuide(); });
        Snap("08-help", w => w.ShowHelp());
        var h = Path.Combine(t.LocalAppData);
        try { if (Directory.Exists(@"C:\nsc-preview")) Directory.Delete(@"C:\nsc-preview", true); } catch (Exception) { }
    }

    private static AutomationElement Find(AutomationElement root, string name, int seconds = 60)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed.TotalSeconds < seconds)
        {
            var e = root.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, name));
            if (e is not null) return e;
            Thread.Sleep(500);
        }
        throw new TimeoutException("UI 요소를 찾지 못함: " + name);
    }

    private static void Click(AutomationElement root, string name)
    {
        var e = Find(root, name);
        ((InvokePattern)e.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    }

    private static void Screen_(string name)
    {
        var b = System.Windows.Forms.Screen.PrimaryScreen!.Bounds;
        using var bmp = new System.Drawing.Bitmap(b.Width, b.Height);
        using var g = System.Drawing.Graphics.FromImage(bmp);
        g.CopyFromScreen(b.Location, System.Drawing.Point.Empty, b.Size);
        bmp.Save(Path.Combine(_out, name + ".png"), System.Drawing.Imaging.ImageFormat.Png);
    }

    private static void EndToEnd(string exe, IocData ioc, TargetUser t)
    {
        CleanFixture(t);
        var launcher = @"C:\NIKKE\Launcher";
        Directory.CreateDirectory(Path.Combine(launcher, "intl_service"));
        File.WriteAllText(Path.Combine(launcher, "intl_service", "debug.log"), "[1101/012037.043:INFO:CONSOLE(1)] \"k2f_chan registered\", source: (1)\n");
        var dll = PlantDll(t, "harmless test file, not a real dll");
        PlantCom(dll);
        var net = new NetworkBlockService();
        var hostsBefore = File.ReadAllBytes(net.HostsPath);
        Process? p = null;
        try
        {
            p = Process.Start(new ProcessStartInfo(exe) { UseShellExecute = false })!;
            var sw = Stopwatch.StartNew();
            while (p.MainWindowHandle == IntPtr.Zero && sw.Elapsed.TotalSeconds < 90) { Thread.Sleep(500); p.Refresh(); }
            True(p.MainWindowHandle != IntPtr.Zero, "창이 뜨지 않음");
            var win = AutomationElement.FromHandle(p.MainWindowHandle);
            Thread.Sleep(1500);
            Screen_("e2e-1-welcome");
            Click(win, "지금 점검하기");
            Find(win, "권장 조치 실행", 180);
            Thread.Sleep(800);
            Screen_("e2e-2-result");
            Click(win, "권장 조치 실행");
            Find(win, "선택한 조치 실행", 120);
            Thread.Sleep(800);
            Screen_("e2e-3-plan");
            Click(win, "선택한 조치 실행");
            Find(win, "예방 설정 되돌리기", 240);
            Thread.Sleep(1500);
            Screen_("e2e-4-actions");
            True(!File.Exists(dll), "DLL이 남음");
            using (var k = Registry.CurrentUser.OpenSubKey(ClassesKey)) True(k is null, "COM 키가 남음");
            True(net.CountOwnedRules() >= 1, "방화벽 규칙 미적용(관리자 보조 실패)");
            True(HostsEditor.HasBlock(File.ReadAllBytes(net.HostsPath)), "hosts 미적용");
            Click(win, "예방 설정 되돌리기");
            var sw2 = Stopwatch.StartNew();
            while (net.CountOwnedRules() > 0 && sw2.Elapsed.TotalSeconds < 60) Thread.Sleep(500);
            True(net.CountOwnedRules() == 0, "되돌리기 실패");
            True(File.ReadAllBytes(net.HostsPath).SequenceEqual(hostsBefore), "hosts 원문 불일치");
            Thread.Sleep(1000);
            Screen_("e2e-5-undo");
            Click(win, "다시 점검");
            Find(win, "권장 조치 실행", 180);
            Thread.Sleep(800);
            Screen_("e2e-6-rescan");
        }
        catch { Screen_("e2e-failure"); throw; }
        finally
        {
            try { p?.Kill(); } catch (Exception) { }
            try { net.Unblock(); } catch (Exception) { }
            CleanFixture(t);
            try { Directory.Delete(@"C:\NIKKE", true); } catch (Exception) { }
        }
    }
}
