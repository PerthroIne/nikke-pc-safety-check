using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NikkeSafetyCheck.Core;

/// <summary>공유용 보고서에서 사용자 식별 정보, 경로, 토큰을 가린다.</summary>
public sealed partial class Masker(TargetUser t, IEnumerable<string> installDirs, IocData ioc)
{
    private readonly List<(string From, string To)> _roots = BuildRoots(t, installDirs);

    private static List<(string, string)> BuildRoots(TargetUser t, IEnumerable<string> installs)
    {
        var l = new List<(string, string)>();
        foreach (var d in installs) l.Add((d, "<설치 폴더>"));
        l.Add((t.TempDir, "%TEMP%"));
        l.Add((t.LocalAppData, "%LOCALAPPDATA%"));
        l.Add((t.RoamingAppData, "%APPDATA%"));
        l.Add((t.ProfileDir, "%USERPROFILE%"));
        return l.Where(x => !string.IsNullOrEmpty(x.Item1)).OrderByDescending(x => x.Item1.Length).ToList();
    }

    [GeneratedRegex(@"S-1-\d+(-\d+)+")] private static partial Regex Sid();
    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")] private static partial Regex Uuid();
    [GeneratedRegex(@"\b[0-9a-fA-F]{32,128}\b")] private static partial Regex LongHex();
    [GeneratedRegex(@"(?i)(bearer\s+)\S+")] private static partial Regex Bearer();
    [GeneratedRegex(@"(?i)(https?://[^\s?""'<>]+)\?[^\s""'<>]*")] private static partial Regex UrlQuery();
    [GeneratedRegex(@"(?i)\b[A-Z]:\\Users\\[^\\""'\r\n]+")] private static partial Regex AnyProfile();
    [GeneratedRegex(@"(?i)\b[A-Z]:\\(?:[^\\""'<>|\r\n]+\\)*(?<last>[^\\\s""'<>|]*)")] private static partial Regex AnyDrivePath();
    [GeneratedRegex(@"(?i)\b(?:token|password|passwd|pwd|secret|api[_-]?key)=\S+")] private static partial Regex KeyValueSecret();

    public string Mask(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? "";
        foreach (var (from, to) in _roots) s = s.Replace(from, to, StringComparison.OrdinalIgnoreCase);
        s = AnyProfile().Replace(s, "%USERPROFILE%");
        // 알려진 위치 밖의 경로에는 폴더 이름에 실명이 들어 있을 수 있어 파일 이름만 남긴다.
        s = AnyDrivePath().Replace(s, m => @"<다른 위치>\" + m.Groups["last"].Value);
        s = UrlQuery().Replace(s, "$1?<가림>");
        s = Bearer().Replace(s, "$1<가림>");
        s = KeyValueSecret().Replace(s, "<가림>");
        s = Sid().Replace(s, "<SID 가림>");
        s = Uuid().Replace(s, "<ID 가림>");
        s = LongHex().Replace(s, m => ioc.IsKnownDll(m.Value) ? m.Value : m.Value[..8] + "…<가림>");
        if (t.UserName.Length >= 2) s = Regex.Replace(s, Regex.Escape(t.UserName), "<사용자>", RegexOptions.IgnoreCase);
        if (t.MachineName.Length >= 2) s = Regex.Replace(s, Regex.Escape(t.MachineName), "<PC>", RegexOptions.IgnoreCase);
        return s;
    }

    public string MaskRegistry(string? key) => string.IsNullOrEmpty(key) ? "" : Mask(key);
}

public sealed record ShareFinding(string RuleId, string Title, string Detail, string SourceUrl, string RuleVersion, DateTimeOffset ObservedAt, string UserSid, EvidenceStage Stage, EvidenceType EvidenceType, Confidence Confidence, CheckStatus Status, Severity Severity, Temporal Temporal, RemediationEligibility RemediationEligibility, string? Path, string? Sha256, string? RegistryKey);

public static class ReportBuilder
{
    public static IReadOnlyList<ShareFinding> ToShareable(ScanResult scan, IocData ioc)
    {
        var m = new Masker(scan.Target, scan.Installs.Select(i => i.LauncherDir), ioc);
        return scan.Findings.Select(f => new ShareFinding(f.RuleId, f.Title, m.Mask(f.Detail), f.SourceUrl, f.RuleVersion, f.ObservedAt, "<SID 가림>", f.Stage, f.EvidenceType, f.Confidence, f.Status, f.Severity, f.Temporal, f.RemediationEligibility, f.Path is null ? null : m.Mask(f.Path), f.Sha256 is null ? null : m.Mask(f.Sha256), f.RegistryKey is null ? null : m.MaskRegistry(f.RegistryKey))).ToList();
    }

    private static string StatusText(CheckStatus s) => s switch
    {
        CheckStatus.Found => "발견",
        CheckStatus.NotFound => "일치 없음",
        CheckStatus.Unknown => "확인 못 함",
        _ => "해당 없음",
    };

    private static string OutcomeText(ItemOutcome o) => o switch
    {
        ItemOutcome.Succeeded => "완료",
        ItemOutcome.PendingReboot => "재부팅 후 처리 필요",
        ItemOutcome.Skipped => "선택 안 함",
        ItemOutcome.Aborted => "안전을 위해 중단",
        ItemOutcome.Failed => "실패",
        ItemOutcome.Started => "시작함",
        ItemOutcome.ManualRequired => "수동 조치 필요",
        ItemOutcome.DryRunOk => "시험 실행 통과",
        _ => "실행 안 함",
    };
    public static string OutcomeLabel(ItemOutcome o) => OutcomeText(o);
    public static string StatusLabel(CheckStatus s) => StatusText(s);

    private static string? HistoryLine(ScanResult scan, ScanSnapshot? worst) =>
        worst is { Risk: OverallRisk.High } && (scan.Risk != OverallRisk.High || worst.CurrentHighRuleIds.Length > 0)
            ? $"이전 점검 기록: {worst.At:yyyy-MM-dd HH:mm}에 고위험 증거가 있었습니다(규칙 {string.Join(", ", worst.HighRuleIds)}). 현재 결과만으로 과거 노출 가능성이 없어지지 않습니다."
            : null;

    public static string Text(ScanResult scan, IocData ioc, IReadOnlyList<ItemResult>? actions = null, ScanSnapshot? worst = null)
    {
        var m = new Masker(scan.Target, scan.Installs.Select(i => i.LauncherDir), ioc);
        var sb = new StringBuilder();
        sb.AppendLine("NIKKE·관련 PC 런처 안전 점검 도우미 (비공식) — 공유용 결과");
        sb.AppendLine($"도구 {scan.ToolVersion} / 규칙 {scan.RuleVersion} / 점검 {scan.FinishedAt:yyyy-MM-dd HH:mm zzz}");
        sb.AppendLine($"결과: {Verdict.Headline(scan.Risk, scan.Completeness)}");
        sb.AppendLine(Verdict.Explanation(scan.Risk, scan.Completeness));
        sb.AppendLine($"적용 출처: {ioc.SourceRevision}");
        var stages = Verdict.StagesOf(scan.Findings);
        if (stages.Count > 0) sb.AppendLine("확인된 증거 단계: " + string.Join(", ", stages.Select(Verdict.StageLabel)));
        if (Verdict.CauseNote(scan.Findings) is { } cause) sb.AppendLine(cause);
        if (HistoryLine(scan, worst) is { } hl) sb.AppendLine(hl);
        sb.AppendLine("이 프로그램은 운영사와 무관합니다. 결과는 알려진 지표와 비교한 것으로, 안전을 보장하지 않습니다.");
        sb.AppendLine();
        foreach (var f in ToShareable(scan, ioc))
        {
            sb.AppendLine($"[{StatusText(f.Status)}] {f.Title} ({f.RuleId}){(f.Stage == EvidenceStage.None ? "" : " / " + Verdict.StageLabel(f.Stage))}");
            sb.AppendLine($"  {f.Detail}");
            if (f.Path is not null) sb.AppendLine($"  위치: {f.Path}");
            if (f.RegistryKey is not null) sb.AppendLine($"  레지스트리: {f.RegistryKey}");
            if (f.Sha256 is not null) sb.AppendLine($"  SHA-256: {f.Sha256}");
        }
        if (actions is { Count: > 0 })
        {
            sb.AppendLine().AppendLine("선택한 항목 조치 결과");
            foreach (var a in actions) sb.AppendLine($"[{OutcomeText(a.Outcome)}] {a.Title}: {m.Mask(a.Message)}");
            sb.AppendLine("조치 결과는 알려진 항목에 대한 것입니다. 과거 노출 가능성은 없어지지 않습니다.");
        }
        return sb.ToString();
    }

    public static string JsonReport(ScanResult scan, IocData ioc, IReadOnlyList<ItemResult>? actions = null, ScanSnapshot? worst = null)
    {
        var m = new Masker(scan.Target, scan.Installs.Select(i => i.LauncherDir), ioc);
        return JsonSerializer.Serialize(new
        {
            tool = "NIKKE·관련 PC 런처 안전 점검 도우미 (비공식)", toolVersion = scan.ToolVersion, ruleVersion = scan.RuleVersion,
            finishedAt = scan.FinishedAt, risk = scan.Risk, completeness = scan.Completeness,
            headline = Verdict.Headline(scan.Risk, scan.Completeness),
            history = HistoryLine(scan, worst),
            sourceRevision = ioc.SourceRevision,
            evidenceStages = Verdict.StagesOf(scan.Findings),
            causeNote = Verdict.CauseNote(scan.Findings),
            findings = ToShareable(scan, ioc),
            actions = actions?.Select(a => new { a.Title, a.Kind, a.Outcome, Message = m.Mask(a.Message), a.At }),
        }, Json.Options);
    }

    public static string Html(ScanResult scan, IocData ioc, IReadOnlyList<ItemResult>? actions = null, ScanSnapshot? worst = null)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var m = new Masker(scan.Target, scan.Installs.Select(i => i.LauncherDir), ioc);
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>점검 결과</title>");
        sb.Append("<style>body{font-family:'Malgun Gothic',system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#1f2733;line-height:1.6}.card{border:1px solid #d5dbe3;border-radius:10px;padding:14px 18px;margin:12px 0}.tag{font-weight:700}small{color:#5b6673}code{word-break:break-all}</style></head><body>");
        sb.Append($"<h1>NIKKE·관련 PC 런처 안전 점검 도우미 (비공식) 결과</h1><p><small>도구 {E(scan.ToolVersion)} · 규칙 {E(scan.RuleVersion)} · {E(scan.FinishedAt.ToString("yyyy-MM-dd HH:mm zzz"))}<br>적용 출처: {E(ioc.SourceRevision)}</small></p>");
        sb.Append($"<div class=\"card\"><h2>{E(Verdict.Headline(scan.Risk, scan.Completeness))}</h2><p>{E(Verdict.Explanation(scan.Risk, scan.Completeness))}</p><p><small>운영사와 무관한 도구입니다. 알려진 지표와 비교한 결과이며 안전을 보장하지 않습니다.</small></p></div>");
        var stages = Verdict.StagesOf(scan.Findings);
        if (stages.Count > 0) sb.Append($"<div class=\"card\"><p>확인된 증거 단계: {E(string.Join(", ", stages.Select(Verdict.StageLabel)))}</p></div>");
        if (Verdict.CauseNote(scan.Findings) is { } cause) sb.Append($"<div class=\"card\"><p>{E(cause)}</p></div>");
        if (HistoryLine(scan, worst) is { } hl) sb.Append($"<div class=\"card\"><p>{E(hl)}</p></div>");
        foreach (var f in ToShareable(scan, ioc))
        {
            sb.Append($"<div class=\"card\"><div class=\"tag\">[{E(StatusText(f.Status))}] {E(f.Title)}{(f.Stage == EvidenceStage.None ? "" : " / " + E(Verdict.StageLabel(f.Stage)))}</div><p>{E(f.Detail)}</p><small>{E(f.RuleId)}");
            if (f.Path is not null) sb.Append($"<br>위치: <code>{E(f.Path)}</code>");
            if (f.RegistryKey is not null) sb.Append($"<br>레지스트리: <code>{E(f.RegistryKey)}</code>");
            if (f.Sha256 is not null) sb.Append($"<br>SHA-256: <code>{E(f.Sha256)}</code>");
            sb.Append("</small></div>");
        }
        if (actions is { Count: > 0 })
        {
            sb.Append("<h2>선택한 항목 조치 결과</h2>");
            foreach (var a in actions) sb.Append($"<div class=\"card\"><div class=\"tag\">[{E(OutcomeText(a.Outcome))}] {E(a.Title)}</div><p>{E(m.Mask(a.Message))}</p></div>");
            sb.Append("<p>조치 결과는 알려진 항목에 대한 것입니다. 과거 노출 가능성은 없어지지 않습니다.</p>");
        }
        sb.Append("</body></html>");
        return sb.ToString();
    }
}

/// <summary>다시 점검할 때 조치 전 증거와 지금 상태를 구분하기 위한 최소 요약. 경로와 식별자는 저장하지 않는다.</summary>
public sealed record ScanSnapshot(DateTimeOffset At, OverallRisk Risk, Completeness Completeness, string[] HighRuleIds, string[] CurrentHighRuleIds);

public static class HistoryStore
{
    private const int MaxActions = 200;
    private static string File_(DataPaths p) => Path.Combine(p.History, "worst.json");
    private static string ActionsFile(DataPaths p) => Path.Combine(p.History, "actions.json");

    /// <summary>실행한 조치 내역. 프로그램을 다시 켜도 무엇을 언제 처리했는지 보여 주기 위해 남긴다.</summary>
    public static IReadOnlyList<ItemResult> LoadActions(DataPaths p)
    {
        try { return File.Exists(ActionsFile(p)) ? JsonSerializer.Deserialize<List<ItemResult>>(File.ReadAllText(ActionsFile(p)), Json.Options) ?? [] : []; }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return []; }
    }

    public static void AppendActions(DataPaths p, IEnumerable<ItemResult> actions)
    {
        try
        {
            var all = LoadActions(p).Concat(actions).TakeLast(MaxActions).ToList();
            Directory.CreateDirectory(p.History);
            File.WriteAllText(ActionsFile(p), JsonSerializer.Serialize(all, Json.Options));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* 기록 실패가 조치 결과를 바꾸지 않는다 */ }
    }


    public static ScanSnapshot Snapshot(ScanResult s) => new(s.FinishedAt, s.Risk, s.Completeness,
        s.Findings.Where(f => f.Status == CheckStatus.Found && f.Severity == Severity.High).Select(f => f.RuleId).Distinct().ToArray(),
        s.Findings.Where(f => f.Status == CheckStatus.Found && f.Severity == Severity.High && f.Temporal == Temporal.Current).Select(f => f.RuleId).Distinct().ToArray());

    public static ScanSnapshot? LoadWorst(DataPaths p)
    {
        try { return File.Exists(File_(p)) ? JsonSerializer.Deserialize<ScanSnapshot>(File.ReadAllText(File_(p)), Json.Options) : null; }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>가장 위험했던 점검을 남긴다. 조치 후 파일이 사라져도 과거 고위험 사실은 지워지지 않는다.</summary>
    public static void RecordIfWorse(DataPaths p, ScanResult s)
    {
        try
        {
            var prev = LoadWorst(p);
            if (s.Risk == OverallRisk.NoKnownTraces && prev is null) return;
            var cur = Snapshot(s);
            // 다시 점검해도 이전에 본 증거를 지우지 않는다. 등급은 가장 높았던 값, 시각은 그 등급을 처음 본 때로 유지한다.
            if (prev is not null)
                cur = cur with
                {
                    At = prev.Risk >= cur.Risk ? prev.At : cur.At,
                    Risk = prev.Risk > cur.Risk ? prev.Risk : cur.Risk,
                    HighRuleIds = prev.HighRuleIds.Union(cur.HighRuleIds).ToArray(),
                    CurrentHighRuleIds = prev.CurrentHighRuleIds.Union(cur.CurrentHighRuleIds).ToArray(),
                };
            Directory.CreateDirectory(p.History);
            File.WriteAllText(File_(p), JsonSerializer.Serialize(cur, Json.Options));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* 기록 실패가 점검을 막지 않는다 */ }
    }
}
