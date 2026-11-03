using System.Text.Json;
using System.Text.Json.Serialization;

namespace NikkeSafetyCheck.Core;

public enum CheckStatus { Found, NotFound, Unknown, NotApplicable }
public enum Confidence { Low, Medium, High }
public enum Severity { None, Suspicious, High }
public enum Temporal { NotApplicable, Past, Current }
public enum RemediationEligibility { None, ManualOnly, Eligible }
public enum EvidenceType
{
    Coverage, LauncherLogExecution, LauncherLogDownload, LauncherLogLoader, AgentState, LoaderCache,
    PersistenceDll, PersistenceCom, AgentTempFile, ProcessModule, NetworkConnection, DnsCache, ManualSubmission,
}
public enum OverallRisk { NoKnownTraces, Suspicious, High }
public enum Completeness { Complete, Partial }

/// <summary>모든 검사 결과의 공통 기록. 발견하지 못한 항목과 못 본 항목도 같은 형태로 남긴다.</summary>
public sealed record Finding
{
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required string SourceUrl { get; init; }
    public required string RuleVersion { get; init; }
    public required DateTimeOffset ObservedAt { get; init; }
    public required string UserSid { get; init; }
    public required EvidenceType EvidenceType { get; init; }
    public required Confidence Confidence { get; init; }
    public required CheckStatus Status { get; init; }
    public required RemediationEligibility RemediationEligibility { get; init; }
    public Severity Severity { get; init; }
    public Temporal Temporal { get; init; }
    /// <summary>이 검사를 못 하면 '점검 불완전'이 되는 필수 항목인지.</summary>
    public bool Required { get; init; }
    public string? Path { get; init; }
    public string? Sha256 { get; init; }
    public string? RegistryKey { get; init; }
    public string? RegistryValue { get; init; }
    public string? FileId { get; init; }
    public string? RetryHint { get; init; }
}

public sealed record TargetUser(
    string Sid, string UserName, string MachineName, string ProfileDir, string LocalAppData, string RoamingAppData,
    string TempDir, bool ProcessIsTargetUser, string ProcessUserName);

public sealed record LauncherInstall(string LauncherDir, string DiscoveredBy, string? ExecutablePath);

public sealed record ScanRequest
{
    public required TargetUser Target { get; init; }
    public IReadOnlyList<string> ExtraFolders { get; init; } = [];
    public IReadOnlyList<string> ManualLogFiles { get; init; } = [];
    public bool DeclaredNeverInstalled { get; init; }
    public bool IncludeRuntimeChecks { get; init; } = true;
    public ScanLimits Limits { get; init; } = new();
}

public sealed record ScanLimits
{
    public long MaxLogBytes { get; init; } = 8L * 1024 * 1024 * 1024;
    public long MaxBinaryFileBytes { get; init; } = 256L * 1024 * 1024;
    public long MaxCacheTotalBytes { get; init; } = 4L * 1024 * 1024 * 1024;
    public int MaxCacheFiles { get; init; } = 30000;
    public int MaxSearchDirectories { get; init; } = 4000;
    public int MaxTempEntries { get; init; } = 200000;
    public TimeSpan SearchTimeBudget { get; init; } = TimeSpan.FromSeconds(8);
}

public sealed record ScanResult
{
    public required string ScanId { get; init; }
    public required string RuleVersion { get; init; }
    public required string ToolVersion { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset FinishedAt { get; init; }
    public required TargetUser Target { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required IReadOnlyList<LauncherInstall> Installs { get; init; }
    public required bool Cancelled { get; init; }
    public bool LauncherRunning { get; init; }
    public OverallRisk Risk => Verdict.RiskOf(Findings);
    public Completeness Completeness => Verdict.CompletenessOf(Findings);
}

public sealed record ScanProgress(string Message, int Done, int Total);

public static class Verdict
{
    public static OverallRisk RiskOf(IEnumerable<Finding> fs)
    {
        var found = fs.Where(f => f.Status == CheckStatus.Found).ToList();
        if (found.Any(f => f.Severity == Severity.High)) return OverallRisk.High;
        return found.Any(f => f.Severity == Severity.Suspicious) ? OverallRisk.Suspicious : OverallRisk.NoKnownTraces;
    }

    public static Completeness CompletenessOf(IEnumerable<Finding> fs) =>
        fs.Any(f => f.Required && f.Status == CheckStatus.Unknown) ? Completeness.Partial : Completeness.Complete;

    /// <summary>결과 카드의 머리글. '감염 없음', '100% 안전' 같은 표현은 어디에도 쓰지 않는다.</summary>
    public static string Headline(OverallRisk r, Completeness c) => (r, c) switch
    {
        (OverallRisk.High, Completeness.Complete) => "고위험 — 악성 에이전트 관련 증거가 발견되었습니다",
        (OverallRisk.High, _) => "고위험 — 증거가 발견되었고, 일부 항목은 확인하지 못했습니다",
        (OverallRisk.Suspicious, Completeness.Complete) => "의심 — 추가 확인이 필요한 흔적이 있습니다",
        (OverallRisk.Suspicious, _) => "의심 — 추가 확인이 필요하고, 일부 항목은 확인하지 못했습니다",
        (_, Completeness.Partial) => "점검 불완전 — 충분히 확인하지 못한 항목이 있습니다",
        _ => "알려진 흔적 미발견 — 정의된 범위에서 일치하는 항목이 없었습니다",
    };

    public static string Explanation(OverallRisk r, Completeness c)
    {
        var body = r switch
        {
            OverallRisk.High => "이 PC에서 악성 에이전트가 실행되었거나 지속 실행 장치가 설치되었다고 볼 만한 증거입니다. 실제로 어떤 정보가 빠져나갔는지는 이 프로그램으로 알 수 없습니다. 원격 명령 실행 기능이 보고되었으므로 파일을 정리한 뒤에도 과거 노출 가능성은 남습니다. 깨끗한 다른 기기에서 계정 보호 조치를 진행하세요.",
            OverallRisk.Suspicious => "관련 흔적이 있지만 이것만으로 악성 에이전트 실행을 확정할 수는 없습니다. 아래 항목을 확인하고, 중요한 계정은 예방 차원에서 깨끗한 기기로 점검하세요. 이 등급의 항목은 자동 제거 대상이 아닙니다.",
            _ when c == Completeness.Partial => "확인하지 못한 항목이 있어 판단을 내릴 수 없습니다. 아래에서 어떤 항목을 왜 못 봤는지 확인하고 다시 시도하세요.",
            _ => "현재 알려진 지표와 일치하는 항목이 없다는 뜻입니다. 감염되지 않았다는 보장은 아닙니다. 로그가 지워졌거나 새로운 변종이면 찾지 못할 수 있습니다. 2026년 9월 27일 이후 런처를 실행한 적이 있다면 중요한 계정의 2단계 인증 점검을 권장합니다.",
        };
        if (r != OverallRisk.NoKnownTraces && c == Completeness.Partial)
            body += " 또한 일부 항목은 확인하지 못했으니 아래 '확인하지 못한 항목'도 살펴보세요.";
        return body;
    }
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}
