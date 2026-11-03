using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using NikkeSafetyCheck.Core;
using NikkeSafetyCheck.Windows;
using static NikkeSafetyCheck.UI.Ui;

namespace NikkeSafetyCheck.UI;

public sealed record AppServices(IocData Ioc, TargetUser Target, PlatformServices Platform, IPrivilegedRunner Privileged, IDefenderService Defender, IFileProtector Protector, string ToolVersion);

public sealed class MainWindow : Window
{
    private readonly AppServices _s;
    private readonly DataPaths _data;
    private readonly ContentControl _host = new();
    private readonly ScrollViewer _scroll = new() { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private readonly List<string> _extraFolders = [];
    private readonly List<string> _manualLogs = [];
    private bool _neverInstalled, _runtimeChecks = true;
    private ScanResult? _scan;
    private ScanSnapshot? _worst;
    private RemediationPlan? _plan;
    private List<ItemResult> _actions = [];
    private readonly List<ItemResult> _sessionActions = [];
    private CancellationTokenSource? _cts;

    public static AppServices DefaultServices(string version)
    {
        var target = TargetUserResolver.Resolve();
        return new AppServices(IocData.LoadEmbedded(), target, WindowsPlatform.Create(target), new ElevatedRunner(), new WindowsDefenderService(), new WindowsFileProtector(), version);
    }

    public MainWindow(AppServices services)
    {
        _s = services;
        _data = DataPaths.ForTarget(_s.Target);
        Title = "NIKKE PC 안전 점검 도우미 (비공식)";
        Width = 960; Height = 760; MinWidth = 640; MinHeight = 500;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        FontFamily = Font; Background = PageBg; Foreground = Ink;
        AllowDrop = true;
        Drop += OnDrop;

        var root = new DockPanel();
        var header = new Border { Background = White, BorderBrush = Line, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(24, 14, 24, 12) };
        header.Child = Stack(
            Text("NIKKE PC 안전 점검 도우미 (비공식)", 20, true, bottom: 2),
            Text("비공식 대응 보조 도구입니다. SHIFT UP, Level Infinite와 관련이 없습니다.", 13, color: Muted, bottom: 0));
        DockPanel.SetDock(header, Dock.Top);
        root.Children.Add(header);
        _host.Margin = new Thickness(24, 18, 24, 18);
        _host.MaxWidth = 880;
        _scroll.Content = _host;
        root.Children.Add(_scroll);
        Content = root;
        ShowWelcome();
    }

    private void Show(UIElement page) { _host.Content = page; _scroll.ScrollToTop(); }

    public void ShowWelcome()
    {
        var page = new StackPanel();
        if (!_s.Target.ProcessIsTargetUser)
            page.Children.Add(Card(Stack(Text("⚠ 다른 계정으로 실행 중입니다", 15, true, B("#7A4B00")),
                Text($"로그인한 사용자({_s.Target.UserName})를 기준으로 점검하지만 파일과 레지스트리 조치는 진행하지 않습니다. 본인 계정에서 일반 실행으로 다시 열어 주세요. 관리자 권한으로 실행할 필요가 없습니다.")), "#FFF4DB", "#E5C77F"));
        try
        {
            var pending = Journal.FindPending(_data);
            if (pending.PendingReboot > 0 || pending.UnfinishedRuns > 0)
                page.Children.Add(Card(Stack(Text("↻ 이전 조치에 남은 일이 있습니다", 15, true, B("#7A4B00")),
                    Text(pending.PendingReboot > 0 ? $"재부팅 후 처리가 필요한 항목이 {pending.PendingReboot}개 있었습니다. 재부팅했다면 지금 다시 점검하세요." : "이전 조치가 끝까지 진행되지 않았습니다. 다시 점검하면 현재 상태를 기준으로 이어서 처리할 수 있습니다.")), "#FFF4DB", "#E5C77F"));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }

        if (RulesStale() is { } stale) page.Children.Add(stale);
        page.Children.Add(Card(Stack(
            Text("이 PC에서 니케 PC 런처 사고의 알려진 흔적을 찾아 드립니다", 18, true),
            Text("2026년 11월, 니케 PC 런처가 불러오는 공식 CDN 파일이 변조되어 원격 제어 에이전트가 설치될 수 있었다는 공개 분석이 나왔습니다. 이 프로그램은 그 분석에 나온 지표를 이 PC에서 확인합니다."),
            Bullets([
                "런처 로그와 저장소에서 에이전트 실행 기록을 찾습니다.",
                "Chrome 폴더의 의심 DLL과 사용자 레지스트리 등록을 확인합니다.",
                "결과를 쉬운 말로 설명하고, 필요한 조치를 한 화면에서 고를 수 있게 합니다.",
            ]),
            Text("✔ '지금 점검하기'는 PC의 설정이나 파일을 바꾸지 않습니다. 인터넷 접속, 로그인, 런처 실행도 하지 않습니다.", 14, true, B("#1B6E3C")),
            Row(Btn("지금 점검하기", true, (_, _) => StartScan()), Btn("사용 방법 보기", false, (_, _) => ShowHelp())))));

        var runtime = new CheckBox { Content = new TextBlock { Text = "실행 중인 프로그램과 네트워크 연결도 확인하기 (읽기 전용, 권장)", TextWrapping = TextWrapping.Wrap, FontSize = 14 }, IsChecked = _runtimeChecks, Margin = new Thickness(0, 0, 0, 8) };
        runtime.Checked += (_, _) => _runtimeChecks = true;
        runtime.Unchecked += (_, _) => _runtimeChecks = false;
        page.Children.Add(Card(Stack(Text("점검 설정", 15, true), runtime,
            Text("설치 폴더를 다른 곳에 두었다면 폴더를 이 창에 끌어다 놓거나 아래 버튼으로 선택하세요. 찾지 못해도 결과 화면에서 다시 선택할 수 있습니다.", 13, color: Muted),
            Row(Btn("설치 폴더 직접 선택", false, (_, _) => PickFolder(false))))));
        page.Children.Add(UndoCard());

        page.Children.Add(Card(Stack(Text("지금 꼭 기억하세요", 15, true, B("#8E1F17")), Bullets([
            "공식 복구 공지를 확인하기 전까지 니케 PC 런처를 열지 마세요. 공개 분석에 따르면 런처를 열 때 악성 코드가 내려올 수 있었습니다.",
            Guidance.StatusNotice,
        ])), "#FDECEA", "#EDB7B1"));
        Show(page);
    }

    private UIElement? RulesStale() =>
        DateTime.TryParse(_s.Ioc.ReviewAfter, out var due) && DateTime.Now > due
            ? Card(Stack(Text("⚠ 점검 규칙이 오래되었습니다", 15, true, B("#7A4B00")),
                Text($"이 프로그램의 규칙은 {_s.Ioc.ObservedAt} 기준입니다. 그 뒤 새로 알려진 흔적은 찾지 못합니다. 저장소에서 새 버전이 있는지 확인하세요.")), "#FFF4DB", "#E5C77F")
            : null;

    private UIElement UndoCard()
    {
        var status = Text("", 14, true);
        return Card(Stack(Text("이전에 추가한 차단을 해제하려면", 15, true),
            Text("이 프로그램이 추가한 방화벽 규칙과 hosts 줄만 제거합니다. 격리한 파일과 삭제한 악성 항목은 되살리지 않습니다. 관리자 승인이 필요합니다.", 13, color: Muted),
            Row(UndoButton(status)), status));
    }

    private Button UndoButton(TextBlock status) => Btn("예방 설정 되돌리기", false, async (_, _) =>
    {
        status.Text = "되돌리는 중입니다.";
        try
        {
            var r = await _s.Privileged.UnblockAllAsync(default);
            status.Text = (r.Ok ? "✔ " : "✖ ") + r.Message;
        }
        catch (Exception ex) { status.Text = $"✖ 되돌리지 못했습니다({ex.GetType().Name})."; }
    });

    private void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] items || _cts is not null) return;
        foreach (var i in items)
        {
            if (Directory.Exists(i)) _extraFolders.Add(i);
            else if (File.Exists(i)) _manualLogs.Add(i);
        }
        StartScan();
    }

    private void PickFolder(bool rescan)
    {
        var d = new OpenFolderDialog { Title = "니케 설치 폴더 선택 (예: C:\\NIKKE)" };
        if (d.ShowDialog(this) != true) return;
        _extraFolders.Add(d.FolderName);
        _neverInstalled = false;
        if (rescan) StartScan();
    }

    private void PickLog()
    {
        var d = new OpenFileDialog { Title = "로그 파일 선택 (수동 제출 자료)", Filter = "로그 파일|*.log;*.txt|모든 파일|*.*" };
        if (d.ShowDialog(this) != true) return;
        _manualLogs.Add(d.FileName);
        StartScan();
    }

    private async void StartScan()
    {
        if (_cts is not null) return;
        _cts = new CancellationTokenSource();
        var bar = new ProgressBar { Minimum = 0, Maximum = 10, Height = 14, Margin = new Thickness(0, 6, 0, 10) };
        var msg = Text("점검을 시작합니다", 15);
        Show(Card(Stack(Text("점검 중입니다", 18, true),
            Text("PC를 바꾸지 않고 읽기만 합니다. 로그가 크면 몇 분 걸릴 수 있습니다."), bar, msg,
            Row(Btn("점검 취소", false, (_, _) => _cts?.Cancel())))));
        var progress = new Progress<ScanProgress>(p => { bar.Value = p.Done; msg.Text = p.Message; });
        var req = new ScanRequest { Target = _s.Target, ExtraFolders = _extraFolders.ToList(), ManualLogFiles = _manualLogs.ToList(), DeclaredNeverInstalled = _neverInstalled, IncludeRuntimeChecks = _runtimeChecks };
        var ct = _cts.Token;
        var engine = new ScanEngine(_s.Ioc, _s.Platform, _s.ToolVersion);
        ScanResult result;
        try { result = await Task.Run(() => engine.Run(req, progress, ct)); }
        catch (Exception ex)
        {
            _cts.Dispose(); _cts = null;
            Show(Card(Stack(Text("점검을 마치지 못했습니다", 18, true, B("#8E1F17")), Text($"예상하지 못한 오류({ex.GetType().Name})가 났습니다. 이것은 '문제없음'이 아닙니다. 다시 시도해 주세요."), Row(Btn("다시 점검", true, (_, _) => StartScan())))));
            return;
        }
        _cts.Dispose(); _cts = null;
        // 재부팅을 기다리는 기록은 실제 재부팅 뒤에 끝까지 점검했을 때만 정리한다.
        if (result.Completeness == Completeness.Complete)
            try { Journal.MarkReviewedAfterRescan(_data, DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64)); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        ShowResult(result);
    }

    private static (string Bg, string Border, string Fg, string Icon) Palette(OverallRisk r, Completeness c) => (r, c) switch
    {
        (OverallRisk.High, _) => ("#FDECEA", "#D9716A", "#8E1F17", "⛔"),
        (OverallRisk.Suspicious, _) => ("#FFF4DB", "#E0B34E", "#7A4B00", "⚠"),
        (_, Completeness.Partial) => ("#EEF1F5", "#A9B4C2", "#333F4F", "❔"),
        _ => ("#E8F5EC", "#86C29B", "#1B6E3C", "ⓘ"),
    };

    public void ShowResult(ScanResult scan)
    {
        _scan = scan; _actions = []; _plan = null;
        HistoryStore.RecordIfWorse(_data, scan);
        _worst = HistoryStore.LoadWorst(_data);

        var page = new StackPanel();
        var (bg, border, fg, icon) = Palette(scan.Risk, scan.Completeness);
        page.Children.Add(Card(Stack(
            Text($"{icon}  {Verdict.Headline(scan.Risk, scan.Completeness)}", 20, true, B(fg)),
            Text(Verdict.Explanation(scan.Risk, scan.Completeness), 15),
            Text($"점검 시각 {scan.FinishedAt:yyyy-MM-dd HH:mm} · 대상 사용자 {scan.Target.UserName} · 규칙 {scan.RuleVersion}", 12, color: Muted, bottom: 0),
            Text($"적용 출처: {_s.Ioc.SourceRevision}", 12, color: Muted, bottom: 0)), bg, border));
        var stages = Verdict.StagesOf(scan.Findings);
        if (stages.Count > 0)
            page.Children.Add(Card(Stack(Text("확인된 증거 단계", 15, true),
                Bullets(stages.Select(Verdict.StageLabel)),
                Text("단계는 모든 PC에서 순서대로 나타나지 않습니다. 어느 단계든 실제로 어떤 정보가 유출되었는지까지 증명하지는 않습니다.", 13, color: Muted))));
        if (Verdict.CauseNote(scan.Findings) is { } cause)
            page.Children.Add(Card(Text(cause), "#EEF1F5", "#A9B4C2"));

        if (_worst is not null && _worst.Risk == OverallRisk.High && scan.Risk != OverallRisk.High)
            page.Children.Add(Card(Stack(Text("조치 전 증거는 그대로 남아 있습니다", 15, true, B("#8E1F17")),
                Text($"{_worst.At:yyyy-MM-dd HH:mm} 점검에서 고위험 증거가 있었습니다. 지금 보이는 결과는 현재 상태일 뿐, 과거 노출 가능성을 없애지 않습니다. 계정 보호 안내를 꼭 진행하세요.")), "#FDECEA", "#EDB7B1"));
        else if (_worst is not null && _worst.Risk == OverallRisk.High && scan.Risk == OverallRisk.High && _worst.CurrentHighRuleIds.Length > 0 && !scan.Findings.Any(f => f.Status == CheckStatus.Found && f.Severity == Severity.High && f.Temporal == Temporal.Current))
            page.Children.Add(Card(Stack(Text("현재 상태와 과거 흔적을 구분해서 보세요", 15, true),
                Text("지속 실행 장치는 지금 발견되지 않습니다. 고위험 판정은 과거 실행 기록 때문에 유지됩니다. 로그는 일부러 지우지 마세요.")), "#EEF1F5", "#A9B4C2"));
        if (scan.LauncherRunning)
            page.Children.Add(Card(Stack(Text("⚠ 니케 런처가 켜져 있습니다", 15, true, B("#7A4B00")), Text("런처 창을 닫고 다시 점검하세요. 캐시 파일이 잠겨 있으면 일부 항목을 볼 수 없습니다.")), "#FFF4DB", "#E5C77F"));

        if (RulesStale() is { } stale) page.Children.Add(stale);
        try
        {
            if (Journal.FindPending(_data).PendingReboot > 0)
                page.Children.Add(Card(Stack(Text("↻ 재부팅 후 처리할 항목이 남아 있습니다", 15, true, B("#7A4B00")),
                    Text("작업을 저장하고 PC를 직접 다시 시작한 뒤, 런처를 열지 말고 다시 점검하세요.")), "#FFF4DB", "#E5C77F"));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }

        var planBtn = Btn("권장 조치 실행", true, async (_, _) => await GuardUi(OpenPlanAsync));
        page.Children.Add(Row(planBtn, Btn("결과 저장", false, (_, _) => SaveReport()), Btn("계정 보호 안내", false, (_, _) => ShowGuide()), Btn("다시 점검", false, (_, _) => StartScan())));

        page.Children.Add(NextStepsCard(scan));

        var found = scan.Findings.Where(f => f.Status == CheckStatus.Found).OrderByDescending(f => f.Severity).ToList();
        var unknown = scan.Findings.Where(f => f.Status == CheckStatus.Unknown).ToList();
        var rest = scan.Findings.Where(f => f.Status is CheckStatus.NotFound or CheckStatus.NotApplicable && f.RuleId != "NSC-INSTALL").ToList();

        if (found.Count > 0)
        {
            page.Children.Add(Text($"발견된 항목 {found.Count}개", 17, true));
            foreach (var f in found) page.Children.Add(FindingCard(f));
        }
        if (unknown.Count > 0)
        {
            page.Children.Add(Text($"확인하지 못한 항목 {unknown.Count}개", 17, true));
            page.Children.Add(Text("아래 항목은 '문제없음'이 아니라 '보지 못함'입니다.", 14, color: Muted));
            foreach (var f in unknown) page.Children.Add(FindingCard(f));
            if (scan.Installs.Count == 0)
                page.Children.Add(Card(Stack(Text("니케 설치 위치를 찾지 못했습니다", 15, true),
                    Text("다른 드라이브에 설치했다면 폴더를 선택하세요. 게임을 지웠다면 로그는 사라졌을 수 있지만, 다른 항목은 위 결과에 반영되어 있습니다. PC 버전을 설치한 적이 전혀 없다면 '설치한 적 없음'을 눌러 주세요."),
                    Row(Btn("설치 폴더 선택", false, (_, _) => PickFolder(true)), Btn("로그 파일 직접 선택", false, (_, _) => PickLog()), Btn("설치한 적 없음", false, (_, _) => { _neverInstalled = true; StartScan(); })))));
        }
        if (scan.Installs.Count > 0)
            page.Children.Add(Text("찾은 설치 위치: " + string.Join(", ", scan.Installs.Select(i => $"{i.LauncherDir} ({i.DiscoveredBy})")), 12, color: Muted));

        var restPanel = new StackPanel();
        foreach (var f in rest) restPanel.Children.Add(FindingCard(f));
        page.Children.Add(new Expander { Header = new TextBlock { Text = $"일치 항목이 없거나 해당 없는 검사 {rest.Count}개 보기", FontSize = 14 }, Content = restPanel, Margin = new Thickness(0, 6, 0, 10) });
        page.Children.Add(UndoCard());
        Show(page);
    }

    private UIElement NextStepsCard(ScanResult scan)
    {
        IEnumerable<string> steps = scan.Risk switch
        {
            OverallRisk.High =>
            [
                "니케 PC 런처를 열지 마세요.",
                "'권장 조치 실행'으로 남아 있는 알려진 항목을 정리합니다. 변경 목록을 먼저 보여 드립니다.",
                "휴대전화 같은 깨끗한 기기에서 '계정 보호 안내'를 진행합니다. 비밀번호 변경은 이 PC에서 하지 마세요.",
                "작업을 저장한 뒤 PC를 다시 시작하고 이 프로그램으로 다시 점검합니다.",
                "실행 증거가 있으면 Windows 재설치를 검토합니다. 알려진 항목을 지워도 공격자가 실행한 다른 변경까지 되돌렸다고 볼 수 없습니다.",
            ],
            OverallRisk.Suspicious =>
            [
                "니케 PC 런처를 열지 마세요.",
                "아래 항목을 읽어 보세요. 이 등급은 자동으로 지우지 않습니다.",
                "Windows 보안이나 쓰는 백신으로 전체 검사를 실행합니다.",
                "중요한 계정은 깨끗한 기기에서 비밀번호와 2단계 인증을 점검하면 더 안전합니다.",
            ],
            _ when scan.Completeness == Completeness.Partial =>
            [
                "아래 '확인하지 못한 항목'의 안내대로 한 뒤 다시 점검합니다.",
                "그래도 확인이 어렵고 2026년 9월 27일 이후 런처를 실행했다면 계정 보호 안내를 예방 차원에서 진행하세요.",
            ],
            _ =>
            [
                "이 결과는 알려진 지표가 없다는 뜻이지 안전 보장이 아닙니다.",
                "공식 복구 공지를 확인하기 전까지 런처를 열지 않는 것이 좋습니다.",
                "9월 27일 이후 런처를 실행한 적이 있다면 중요한 계정의 2단계 인증을 점검하세요.",
            ],
        };
        return Card(Stack(Text("다음에 할 일", 16, true), Bullets(steps)));
    }

    private static UIElement FindingCard(Finding f)
    {
        var (label, icon, color, bg, border) = (f.Status, f.Severity) switch
        {
            (CheckStatus.Found, Severity.High) => ("고위험", "⛔", "#8E1F17", "#FFFFFF", "#D9716A"),
            (CheckStatus.Found, _) => ("의심", "⚠", "#7A4B00", "#FFFFFF", "#E0B34E"),
            (CheckStatus.Unknown, _) => ("확인 못 함", "❔", "#333F4F", "#FFFFFF", "#A9B4C2"),
            (CheckStatus.NotFound, _) => ("일치 없음", "–", "#1B6E3C", "#FFFFFF", "#D5DBE3"),
            _ => ("해당 없음", "–", "#4F5B6B", "#FFFFFF", "#D5DBE3"),
        };
        var when = f.Stage != EvidenceStage.None ? " · " + Verdict.StageLabel(f.Stage) : f.Temporal switch { Temporal.Past => " · 과거 흔적", Temporal.Current => " · 현재 상태", _ => "" };
        var s = Stack(Text($"{icon} [{label}{when}] {f.Title}", 15, true, B(color), 4), Text(f.Detail));
        if (f.RetryHint is not null) s.Children.Add(Text("해 볼 일: " + f.RetryHint, 14, true));
        if (f.Path is not null) s.Children.Add(Selectable("위치: " + f.Path));
        if (f.RegistryKey is not null) s.Children.Add(Selectable("레지스트리: " + f.RegistryKey + (f.RegistryValue is { Length: > 0 } ? " = " + f.RegistryValue : "")));
        if (f.Sha256 is not null) s.Children.Add(Selectable("SHA-256: " + f.Sha256));
        if (f.Status != CheckStatus.Unknown) s.Children.Add(Selectable($"규칙 {f.RuleId} · 신뢰도 {f.Confidence} · 출처 {f.SourceUrl}"));
        return Card(s, bg, border);
    }

    private async Task OpenPlanAsync()
    {
        if (_scan is null) return;
        Show(Card(Stack(Text("조치 목록을 준비하는 중입니다", 16, true), Text("Windows 보안 상태를 확인하고 있습니다. 아직 아무것도 바꾸지 않았습니다."))));
        var scan = _scan;
        var defender = await Task.Run(() => { try { return _s.Defender.Query(); } catch (Exception e) when (e is IOException or InvalidOperationException) { return new DefenderStatus(false, "", [], false); } });
        ShowPlan(PlanBuilder.Build(scan, defender));
    }

    public void ShowPlan(RemediationPlan plan)
    {
        _plan = plan;
        var page = new StackPanel();
        page.Children.Add(Text("권장 조치: 실제로 바뀌는 내용", 20, true));
        page.Children.Add(Text("아래가 전부입니다. 필요 없는 항목은 체크를 끄세요. 실행 전에 대상이 점검 때와 같은지 다시 확인하고, 다르면 그 항목을 멈춥니다. PC를 자동으로 재부팅하거나 브라우저를 강제로 끄거나 게임을 지우지 않습니다."));
        var boxes = new Dictionary<string, CheckBox>();
        foreach (var i in plan.Items)
        {
            var cb = new CheckBox { IsChecked = i.SelectedByDefault, Content = new TextBlock { Text = i.Title + (i.NeedsAdmin ? "  (관리자 승인 필요)" : ""), FontSize = 15, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap }, Margin = new Thickness(0, 0, 0, 6) };
            boxes[i.Id] = cb;
            var s = Stack(cb, Text(i.WhatChanges));
            if (i.Warning is not null) s.Children.Add(Text("⚠ " + i.Warning, 14, false, B("#7A4B00")));
            if (i.ExpectedPath is not null) s.Children.Add(Selectable("대상: " + i.ExpectedPath));
            if (i.ExpectedRegistryKey is not null) s.Children.Add(Selectable("대상: " + i.ExpectedRegistryKey));
            if (i.LauncherExe is not null) s.Children.Add(Selectable("대상: " + i.LauncherExe));
            page.Children.Add(Card(s));
        }
        if (plan.Items.Count == 0) page.Children.Add(Card(Text("지금 자동으로 실행할 수 있는 항목이 없습니다.")));
        if (plan.ManualNotes.Count > 0) page.Children.Add(Card(Stack(Text("이 프로그램이 대신 하지 않는 일", 15, true), Bullets(plan.ManualNotes)), "#EEF1F5", "#A9B4C2"));
        page.Children.Add(Card(Stack(Text("실행 전에 알아 두세요", 15, true), Bullets([
            "이 조치는 '알려진 항목'만 다룹니다. 완치를 뜻하지 않습니다.",
            "변경 전 값과 해시를 이 PC의 사용자 전용 폴더에 기록합니다. 외부로 보내지 않습니다.",
            "격리한 파일과 삭제한 악성 항목을 원클릭으로 되살리는 기능은 없습니다. 방화벽과 hosts 차단만 되돌릴 수 있습니다.",
            "관리자 승인 창은 관리자 항목을 고른 경우에만 뜹니다. 취소해도 다른 항목은 진행됩니다.",
        ]))));
        HashSet<string> Selected() => boxes.Where(kv => kv.Value.IsChecked == true).Select(kv => kv.Key).ToHashSet();
        page.Children.Add(Row(
            Btn("선택한 조치 실행", true, async (_, _) => await GuardUi(() => ExecuteAsync(Selected(), false))),
            Btn("시험 실행 (변경 없음)", false, async (_, _) => await GuardUi(() => ExecuteAsync(Selected(), true))),
            Btn("돌아가기", false, (_, _) => { if (_scan is not null) ShowResult(_scan); })));
        Show(page);
    }

    private async Task GuardUi(Func<Task> body)
    {
        try { await body(); }
        catch (Exception ex)
        {
            Show(Card(Stack(Text("처리를 마치지 못했습니다", 18, true, B("#8E1F17")),
                Text($"예상하지 못한 오류({ex.GetType().Name})가 났습니다. 일부 항목이 이미 처리되었을 수 있으니 다시 점검해 현재 상태를 확인하세요."),
                Row(Btn("다시 점검", true, (_, _) => StartScan())))));
        }
    }

    private async Task ExecuteAsync(HashSet<string> selected, bool dryRun)
    {
        if (_plan is null || _scan is null) return;
        var plan = _plan; var scan = _scan;
        var msg = Text("준비 중", 15);
        Show(Card(Stack(Text(dryRun ? "시험 실행 중입니다 (변경 없음)" : "선택한 조치를 진행 중입니다", 18, true), new ProgressBar { IsIndeterminate = true, Height = 14, Margin = new Thickness(0, 6, 0, 10) }, msg,
            Text("관리자 승인 창이 뜨면 내용을 확인한 뒤 선택해 주세요.", 14, color: Muted))));
        var defenderItems = plan.Items.Where(i => selected.Contains(i.Id) && i.Kind is PlanKind.DefenderQuickScan or PlanKind.DefenderFullScan).ToList();
        var direct = selected.Except(dryRun ? [] : defenderItems.Select(i => i.Id)).ToHashSet();
        var exec = new RemediationExecutor(new ExecutorDeps(_s.Ioc, _s.Platform.Registry, _s.Platform.FileIds, _s.Protector, _s.Platform.Processes, _s.Privileged, _s.Defender), _s.Target, _data);
        var progress = new Progress<string>(m => msg.Text = m);
        IReadOnlyList<ItemResult> res;
        try { res = await Task.Run(() => exec.ExecuteAsync(plan, direct, scan, dryRun, progress, default)); }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Show(Card(Stack(Text("조치를 시작하지 못했습니다", 18, true, B("#8E1F17")), Text("변경 기록 폴더를 만들 수 없거나 대상 사용자가 달라 시작하지 않았습니다. 아무것도 바꾸지 않았습니다. 다시 점검한 뒤 시도하세요."), Row(Btn("다시 점검", true, (_, _) => StartScan())))));
            return;
        }
        _actions = res.Where(r => r.Outcome != ItemOutcome.Skipped || !defenderItems.Any(d => d.Id == r.ItemId)).ToList();
        if (!dryRun) _sessionActions.AddRange(_actions.Where(a => a.Outcome != ItemOutcome.Skipped));
        var defenderRows = dryRun ? [] : defenderItems;
        ShowActionResults(dryRun, defenderRows);
    }

    public void ShowActionResults(bool dryRun, IReadOnlyList<PlanItem>? defenderToRun = null)
    {
        var page = new StackPanel();
        var acted = _actions.Where(a => a.Outcome != ItemOutcome.Skipped).ToList();
        int done = acted.Count(a => a.Outcome == ItemOutcome.Succeeded), pending = acted.Count(a => a.Outcome == ItemOutcome.PendingReboot),
            failed = acted.Count(a => a.Outcome is ItemOutcome.Failed or ItemOutcome.Aborted), manual = acted.Count(a => a.Outcome == ItemOutcome.ManualRequired);
        page.Children.Add(Card(Stack(
            Text(dryRun ? "시험 실행 결과 (아무것도 바꾸지 않았습니다)" : "선택한 항목 조치 결과", 20, true),
            Text(dryRun ? "실제 실행 시 같은 확인을 다시 거칩니다." : $"완료 {done} · 재부팅 후 처리 {pending} · 실패 또는 중단 {failed} · 수동 조치 {manual}", 15),
            Text("이 결과는 '완치'가 아닙니다. 과거에 에이전트가 실행되었다면 노출 가능성은 그대로이므로 계정 보호 안내를 진행하세요.", 14, true, B("#8E1F17")))));

        foreach (var a in _actions.Where(a => a.Outcome != ItemOutcome.Skipped))
        {
            var (ic, col) = a.Outcome switch
            {
                ItemOutcome.Succeeded or ItemOutcome.DryRunOk or ItemOutcome.Started => ("✔", "#1B6E3C"),
                ItemOutcome.PendingReboot or ItemOutcome.ManualRequired => ("↻", "#7A4B00"),
                _ => ("✖", "#8E1F17"),
            };
            page.Children.Add(Card(Stack(Text($"{ic} [{ReportBuilder.OutcomeLabel(a.Outcome)}] {a.Title}", 15, true, B(col), 4), Text(a.Message))));
        }
        foreach (var d in defenderToRun ?? [])
        {
            var status = Text("검사 시작, 실행 중입니다. 이 창을 열어 둔 채 다른 일을 해도 됩니다.");
            var title = Text($"⏳ [실행 중] {d.Title}", 15, true, null, 4);
            page.Children.Add(Card(Stack(title, status)));
            var item = d;
            _ = Dispatcher.InvokeAsync(async () =>
            {
                NetworkActionResult r;
                try { r = await _s.Defender.RunScanAsync(item.Kind == PlanKind.DefenderFullScan, default); }
                catch (Exception ex) { r = new NetworkActionResult(false, $"검사를 진행하지 못했습니다({ex.GetType().Name}). Windows 보안 화면에서 직접 실행하세요."); }
                title.Text = (r.Ok ? "✔ [완료, 결과 확인 필요] " : "✖ [실패] ") + item.Title;
                status.Text = r.Message;
                var ir = new ItemResult(item.Id, item.Kind, item.Title, r.Ok ? ItemOutcome.Succeeded : ItemOutcome.Failed, r.Message, DateTimeOffset.Now);
                _actions.Add(ir); _sessionActions.Add(ir);
            });
        }

        if (pending > 0)
            page.Children.Add(Card(Stack(Text("재부팅 후 할 일", 16, true), Bullets([
                "저장하지 않은 작업을 저장합니다.", "PC를 직접 다시 시작합니다. 이 프로그램은 자동으로 재부팅하지 않습니다.", "니케 런처를 열지 말고 이 프로그램을 다시 실행해 '다시 점검'을 누릅니다.", "같은 파일이 다시 나오면 권장 조치를 한 번 더 실행합니다.",
            ])), "#FFF4DB", "#E5C77F"));
        var undo = Text("", 14, true);
        var undoBtn = UndoButton(undo);
        page.Children.Add(Row(
            Btn("다시 점검", true, (_, _) => StartScan()), Btn("계정 보호 안내", false, (_, _) => ShowGuide()), Btn("결과 저장", false, (_, _) => SaveReport()),
            undoBtn,
            Btn("기록 폴더 열기", false, (_, _) => OpenDataFolder())));
        page.Children.Add(undo);
        page.Children.Add(Text("'예방 설정 되돌리기'는 이 프로그램이 추가한 방화벽 규칙과 hosts 줄만 제거합니다. 격리한 파일과 삭제한 악성 항목은 되살리지 않습니다.", 13, color: Muted));
        Show(page);
    }

    private void OpenDataFolder()
    {
        try
        {
            Directory.CreateDirectory(_data.Root);
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { _data.Root }, UseShellExecute = false });
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { }
    }

    private void SaveReport()
    {
        if (_scan is null) return;
        var d = new SaveFileDialog { Title = "공유용 결과 저장", FileName = $"NIKKE_점검결과_{DateTime.Now:yyyyMMdd_HHmm}", Filter = "HTML 보고서 (TXT, JSON도 함께 저장)|*.html", AddExtension = true, DefaultExt = ".html", InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) };
        if (d.ShowDialog(this) != true) return;
        try
        {
            var b = Path.ChangeExtension(d.FileName, null);
            File.WriteAllText(b + ".html", ReportBuilder.Html(_scan, _s.Ioc, _sessionActions, _worst));
            File.WriteAllText(b + ".txt", ReportBuilder.Text(_scan, _s.Ioc, _sessionActions, _worst));
            File.WriteAllText(b + ".json", ReportBuilder.JsonReport(_scan, _s.Ioc, _sessionActions, _worst));
            MessageBox.Show(this, "HTML, TXT, JSON 세 파일로 저장했습니다.\n사용자 이름, PC 이름, SID, 경로 일부, 토큰은 가렸습니다. 그래도 공유 전에 한 번 읽어 보세요.", "저장 완료", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, "저장하지 못했습니다. 다른 위치를 선택해 주세요.", "저장 실패", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private Button Back() => Btn(_scan is null ? "처음으로" : "결과로 돌아가기", false, (_, _) => { if (_scan is not null && _actions.Count == 0) ShowResult(_scan); else if (_scan is not null) ShowActionResults(false); else ShowWelcome(); });

    public void ShowGuide()
    {
        var page = new StackPanel();
        page.Children.Add(Row(Back()));
        page.Children.Add(Text("계정 보호 안내", 20, true));
        page.Children.Add(Card(Text(Guidance.Intro, 15, true, B("#8E1F17")), "#FDECEA", "#EDB7B1"));
        page.Children.Add(Text("순서대로 진행하세요. 쓰지 않는 서비스는 건너뛰면 됩니다.", 14));
        foreach (var g in Guidance.Account)
            page.Children.Add(Card(Stack(Text(g.Title, 16, true), Text(g.Why, 14, color: Muted), Bullets(g.Steps))));
        page.Children.Add(Card(Stack(Text(Guidance.Reinstall.Title, 16, true), Text(Guidance.Reinstall.Why), Bullets(Guidance.Reinstall.Steps)), "#FFF4DB", "#E5C77F"));
        page.Children.Add(Row(Back()));
        Show(page);
    }

    public void ShowHelp()
    {
        var page = new StackPanel();
        page.Children.Add(Row(Btn(_scan is null ? "처음으로" : "결과로 돌아가기", false, (_, _) => { if (_scan is not null) ShowResult(_scan); else ShowWelcome(); })));
        page.Children.Add(Text("사용 방법과 결과 읽는 법", 20, true));
        page.Children.Add(Card(Stack(Text("사용 순서", 16, true), Bullets([
            "'지금 점검하기'를 누릅니다. 읽기만 하며 보통 1분 안에 끝납니다.",
            "결과 카드의 등급을 확인합니다.",
            "'권장 조치 실행'을 누르면 바뀌는 내용 전체를 먼저 보여 줍니다. 체크를 확인하고 실행합니다.",
            "깨끗한 다른 기기에서 '계정 보호 안내'를 진행합니다.",
            "PC를 다시 시작한 뒤 '다시 점검'으로 확인합니다.",
        ]))));
        page.Children.Add(Card(Stack(Text("등급의 뜻", 16, true), Bullets([
            "⛔ 고위험: 공식 설치 위치의 실행 로그, 알려진 악성 해시, DLL과 레지스트리 결합처럼 강한 증거가 있습니다. 실제 유출이 끝났다는 증명은 아닙니다.",
            "⚠ 의심: 다운로드 기록, 캐시 주소처럼 단독으로는 부족한 흔적입니다. 자동으로 지우지 않습니다.",
            "ⓘ 알려진 흔적 미발견: 정해진 범위를 끝까지 봤지만 일치 항목이 없습니다. 안전 보장이 아닙니다.",
            "❔ 점검 불완전: 경로를 못 찾았거나 권한, 잠금, 취소로 충분히 못 봤습니다.",
            "과거 흔적과 현재 상태는 다릅니다. 로그는 과거의 실행 기록이고, DLL과 레지스트리 등록은 지금 남아 있는 장치입니다. DLL 파일이 있다고 지금 실행 중인 것은 아니며, 메모리 로드 항목이 따로 알려 줍니다.",
            "다른 게임을 설치했다는 사실만으로 판정하지 않습니다. 공통 흔적을 찾아도 원인 게임을 알 수 없으면 '원인 미확인'으로 표시합니다.",
        ]))));
        page.Children.Add(Card(Stack(Text("하지 않는 일", 16, true), Bullets([
            "인터넷으로 아무것도 보내지 않습니다. 업데이트 확인도, 공격 서버 접속도 하지 않습니다.",
            "브라우저 저장 비밀번호, 쿠키, Claude 인증 파일, SSH 키를 열지 않습니다.",
            "비밀번호나 복구 문구를 입력받지 않습니다.",
            "DLL을 실행하거나 불러오지 않습니다. 파일을 읽어 해시만 계산합니다.",
            "자동 재부팅, 브라우저 강제 종료, 게임 삭제를 하지 않습니다.",
        ]))));
        page.Children.Add(Card(Stack(Text("지원 범위", 16, true), Bullets([
            "Windows x64 대상입니다. ARM64 Windows, Linux, Steam Deck(Proton)은 지원하지 않습니다.",
            "Linux와 Steam Deck에서 런처를 실행했다면 공개 분석상 Proton이 보호막이 되지 않으므로, 홈 폴더의 비밀 값을 노출된 것으로 보고 계정 보호 안내를 따르세요.",
            "다른 Windows 계정은 점검하지 않습니다. 각 계정에서 따로 실행하세요.",
        ]))));
        page.Children.Add(Card(Stack(Text("기록 위치", 16, true),
            Selectable(_data.Root),
            Text("조치 기록, 증거 복사본, 격리 파일이 이 폴더에 있습니다. 런처 저장소 복사본에는 로그인 정보가 들어 있을 수 있으니 다른 사람에게 보내지 마세요. 공유는 '결과 저장'으로 만든 파일만 사용하세요."),
            Row(Btn("기록 폴더 열기", false, (_, _) => OpenDataFolder())))));
        Show(page);
    }
}
