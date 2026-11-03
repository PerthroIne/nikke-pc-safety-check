using System.Text.Json;

namespace NikkeSafetyCheck.Core;

public enum PlanKind { RemoveComKey, QuarantineDll, ClearLauncherCache, BlockKnownNetwork, BlockLauncherOutbound, DefenderQuickScan, DefenderFullScan, DefenderOfflineScan }
public enum ItemOutcome { NotRun, DryRunOk, Succeeded, PendingReboot, Skipped, Aborted, Failed, Started, ManualRequired }

public sealed record PlanItem
{
    public required string Id { get; init; }
    public required PlanKind Kind { get; init; }
    public required string Title { get; init; }
    public required string WhatChanges { get; init; }
    public string? Warning { get; init; }
    public bool SelectedByDefault { get; init; }
    public bool NeedsAdmin { get; init; }
    public string? ExpectedPath { get; init; }
    public string? ExpectedSha256 { get; init; }
    public string? ExpectedFileId { get; init; }
    public string? ExpectedRegistryKey { get; init; }
    public string? ExpectedRegistryValue { get; init; }
    public string? LauncherExe { get; init; }
}

/// <summary>점검 결과로 한 번 만들면 바뀌지 않는 조치 계획. 실행 시 사용자는 항목 선택만 바꿀 수 있다.</summary>
public sealed record RemediationPlan(string PlanId, string ScanId, string UserSid, DateTimeOffset CreatedAt, IReadOnlyList<PlanItem> Items, IReadOnlyList<string> ManualNotes);

public sealed record DefenderStatus(bool DefenderActive, string Summary, IReadOnlyList<string> OtherProducts, bool Queried);

public static class PlanBuilder
{
    public static RemediationPlan Build(ScanResult scan, DefenderStatus? defender)
    {
        var items = new List<PlanItem>();
        var notes = new List<string>();
        var t = scan.Target;
        var hasRisk = scan.Risk != OverallRisk.NoKnownTraces;

        if (!t.ProcessIsTargetUser)
            notes.Add($"지금 프로그램이 다른 계정({t.ProcessUserName})으로 실행 중입니다. 사용자 파일과 레지스트리 조치는 대상 사용자 본인 계정으로 실행했을 때만 진행합니다.");

        if (t.ProcessIsTargetUser)
        {
            foreach (var f in scan.Findings.Where(f => f.Status == CheckStatus.Found && f.RemediationEligibility == RemediationEligibility.Eligible))
            {
                if (f.EvidenceType == EvidenceType.PersistenceCom && f.RegistryKey is not null)
                    items.Add(new PlanItem
                    {
                        Id = "com-" + items.Count, Kind = PlanKind.RemoveComKey, Title = "사용자 COM 등록 제거", SelectedByDefault = true,
                        WhatChanges = "이 계정의 레지스트리에서 악성 DLL을 가리키는 항목 하나만 삭제합니다. 삭제 전 값을 기록합니다. HKLM의 Windows 정상 항목은 건드리지 않습니다. 실행하면 안내글의 레지스트리 확인 명령으로 찾아도 나오지 않습니다.",
                        ExpectedRegistryKey = f.RegistryKey, ExpectedRegistryValue = f.RegistryValue,
                    });
                else if (f.EvidenceType == EvidenceType.PersistenceDll && f.Path is not null && f.Sha256 is not null)
                    items.Add(new PlanItem
                    {
                        Id = "dll-" + items.Count, Kind = PlanKind.QuarantineDll, Title = "의심 DLL 격리", SelectedByDefault = true,
                        WhatChanges = "DLL 파일 하나를 실행되지 않는 격리 폴더로 옮깁니다. 상위 PlatformExperienceHelper 폴더와 Chrome 정상 EXE는 남겨 둡니다. 실행하면 안내글의 경로에서 이 파일과 64자리 폴더가 보이지 않습니다.",
                        Warning = "파일이 사용 중이면 재부팅 후 다시 처리해야 합니다.",
                        ExpectedPath = f.Path, ExpectedSha256 = f.Sha256, ExpectedFileId = f.FileId,
                    });
            }
            // 레지스트리를 먼저 끊어야 잠긴 DLL도 재부팅 후 다시 불러와지지 않는다.
            items = items.OrderBy(i => i.Kind == PlanKind.RemoveComKey ? 0 : 1).ToList();

            if (Directory.Exists(PathSafety.LauncherCacheDir(t)))
                items.Add(new PlanItem
                {
                    Id = "cache", Kind = PlanKind.ClearLauncherCache, Title = "런처 전용 캐시 정리", SelectedByDefault = hasRisk,
                    WhatChanges = "%APPDATA%\\nikke_launcher\\tbs_cache 폴더만 지웁니다. 먼저 로그와 상태 증거를 복사해 둡니다. 브라우저 프로필은 건드리지 않습니다. 실행하면 안내글대로 tbs_cache에서 k2f.agent를 찾아도 나오지 않습니다.",
                    Warning = "감염 치료가 아닙니다. 변조 파일 재사용을 막기 위한 것이며 런처 로그인과 표시 설정이 초기화될 수 있습니다.",
                    ExpectedPath = PathSafety.LauncherCacheDir(t),
                });
        }

        items.Add(new PlanItem
        {
            Id = "net", Kind = PlanKind.BlockKnownNetwork, Title = "알려진 공격 서버 차단", SelectedByDefault = hasRisk, NeedsAdmin = true,
            WhatChanges = "Windows 방화벽에 알려진 IP 차단 규칙을 추가하고 hosts 파일에 알려진 도메인을 앱 소유 구간으로 추가합니다. 나중에 되돌릴 수 있습니다.",
            Warning = "새 서버, 하위 도메인, DoH, 프록시까지 막는 완전 격리가 아닙니다. 이 차단만으로 대응이 끝나지 않습니다. insightjs.org는 공격 당시의 대체 도메인으로, 조사 시점에는 제3자의 경고 페이지였습니다. 현재 상태와 무관하게 예방으로 막으며, 차단하면 그 경고 페이지도 이 PC에서 열리지 않습니다.",
        });
        foreach (var inst in scan.Installs.Where(i => i.ExecutablePath is not null))
            if (PathSafety.IsValidLauncherExecutable(inst.ExecutablePath!, out _))
                items.Add(new PlanItem
                {
                    Id = "launcher-" + items.Count, Kind = PlanKind.BlockLauncherOutbound, Title = "니케 런처 외부 통신 차단", SelectedByDefault = false, NeedsAdmin = true,
                    WhatChanges = "검증된 런처 실행 파일 하나의 외부 통신을 막습니다. 게임 자체를 지우지 않습니다.",
                    Warning = "차단 중에는 런처 업데이트와 게임 실행이 되지 않습니다. 나중에 되돌릴 수 있습니다.",
                    LauncherExe = inst.ExecutablePath,
                });

        if (defender is { DefenderActive: true })
        {
            items.Add(new PlanItem { Id = "mdav-quick", Kind = PlanKind.DefenderQuickScan, Title = "Microsoft Defender 빠른 검사 시작", SelectedByDefault = hasRisk, WhatChanges = "Windows 기본 백신으로 빠른 검사를 시작합니다. 파일을 이 프로그램이 지우지 않습니다." });
            items.Add(new PlanItem { Id = "mdav-full", Kind = PlanKind.DefenderFullScan, Title = "Microsoft Defender 전체 검사 시작", WhatChanges = "전체 디스크를 검사합니다. 오래 걸릴 수 있습니다.", Warning = "미탐지여도 위에서 찾은 증거가 취소되지는 않습니다." });
            items.Add(new PlanItem { Id = "mdav-offline", Kind = PlanKind.DefenderOfflineScan, Title = "Microsoft Defender 오프라인 검사", NeedsAdmin = true, WhatChanges = "PC를 다시 시작해 Windows 밖에서 검사합니다.", Warning = "실행하면 곧바로 재부팅됩니다. 저장하지 않은 작업을 먼저 저장하세요." });
        }
        else if (defender is not null)
        {
            notes.Add(defender.OtherProducts.Count > 0
                ? $"다른 백신({string.Join(", ", defender.OtherProducts)})을 쓰고 있어 설정을 바꾸지 않습니다. 해당 제품에서 전체 검사를 직접 실행하세요."
                : "Microsoft Defender를 사용할 수 없는 상태입니다. 쓰고 있는 보안 제품이나 Windows 보안 화면에서 전체 검사를 직접 실행하세요.");
        }

        foreach (var f in scan.Findings.Where(f => f.Status == CheckStatus.Found && f.RemediationEligibility == RemediationEligibility.ManualOnly && f.Severity != Severity.None && f.EvidenceType is EvidenceType.PersistenceDll or EvidenceType.PersistenceCom or EvidenceType.AgentTempFile))
            notes.Add($"자동 제거하지 않는 항목: {f.Title}. 전문가 확인이나 보안 제품 검사를 권장합니다.");

        return new RemediationPlan(Guid.NewGuid().ToString("N"), scan.ScanId, t.Sid, DateTimeOffset.Now, items, notes);
    }
}

public sealed record ItemResult(string ItemId, PlanKind Kind, string Title, ItemOutcome Outcome, string Message, DateTimeOffset At);

public sealed record NetworkActionResult(bool Ok, string Message);

/// <summary>관리자 권한이 필요한 고정 동작. 경로나 명령을 자유롭게 받지 않는다.</summary>
public interface IPrivilegedRunner
{
    Task<NetworkActionResult> BlockKnownNetworkAsync(CancellationToken ct);
    Task<NetworkActionResult> BlockLauncherAsync(string launcherExe, CancellationToken ct);
    Task<NetworkActionResult> UnblockAllAsync(CancellationToken ct);
    Task<NetworkActionResult> StartDefenderOfflineAsync(CancellationToken ct);
}

public interface IDefenderService
{
    DefenderStatus Query();
    /// <summary>검사를 시작하고 끝나면 완료되는 작업을 돌려준다.</summary>
    Task<NetworkActionResult> RunScanAsync(bool full, CancellationToken ct);
}

public sealed record DataPaths(string Root)
{
    public string Journal => Path.Combine(Root, "journal");
    public string Quarantine => Path.Combine(Root, "quarantine");
    public string Evidence => Path.Combine(Root, "evidence");
    public string History => Path.Combine(Root, "history");
    public static DataPaths ForTarget(TargetUser t) => new(Path.Combine(t.LocalAppData, "NikkeSafetyCheck"));
}

/// <summary>실행 저널. 항목별 변경 전 상태와 결과를 한 줄씩 추가 기록해 앱이 꺼져도 어디까지 했는지 남긴다.</summary>
public sealed class Journal
{
    private readonly string _file;
    private Journal(string file) { _file = file; }

    public static Journal Create(DataPaths p, string planId)
    {
        Directory.CreateDirectory(p.Journal);
        return new Journal(Path.Combine(p.Journal, $"{DateTime.UtcNow:yyyyMMddHHmmss}-{planId}.jsonl"));
    }

    public void Write(string type, object data)
    {
        var line = JsonSerializer.Serialize(new { at = DateTimeOffset.Now, type, data }, new JsonSerializerOptions { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } });
        using var fs = new FileStream(_file, FileMode.Append, FileAccess.Write, FileShare.Read);
        using var w = new StreamWriter(fs);
        w.WriteLine(line);
        w.Flush();
        fs.Flush(true);
    }

    public sealed record PendingWork(int UnfinishedRuns, int PendingReboot);

    /// <summary>이전 실행 중 끝나지 않았거나 재부팅이 필요했던 항목을 찾는다.</summary>
    public static PendingWork FindPending(DataPaths p)
    {
        if (!Directory.Exists(p.Journal)) return new PendingWork(0, 0);
        var latest = Directory.EnumerateFiles(p.Journal, "*.jsonl").OrderDescending().FirstOrDefault();
        if (latest is null) return new PendingWork(0, 0);
        var finished = false; var pending = 0;
        foreach (var line in File.ReadLines(latest))
        {
            try
            {
                using var d = JsonDocument.Parse(line);
                var type = d.RootElement.GetProperty("type").GetString();
                if (type == "run-finished") finished = true;
                if (type == "item-result" && d.RootElement.GetProperty("data").GetProperty("Outcome").GetString() == nameof(ItemOutcome.PendingReboot)) pending++;
            }
            catch (JsonException) { /* 기록 도중 꺼진 마지막 줄 */ }
        }
        return new PendingWork(finished ? 0 : 1, pending);
    }

    /// <summary>
    /// 재점검을 마친 뒤 호출한다. 재부팅 대기 항목은 그 기록 이후 실제로 재부팅한 경우에만 정리한다.
    /// </summary>
    public static void MarkReviewedAfterRescan(DataPaths p, DateTime bootTimeUtc)
    {
        if (!Directory.Exists(p.Journal)) return;
        var latest = Directory.EnumerateFiles(p.Journal, "*.jsonl").OrderDescending().FirstOrDefault();
        if (latest is null) return;
        if (FindPending(p).PendingReboot > 0 && File.GetLastWriteTimeUtc(latest) > bootTimeUtc) return;
        File.Move(latest, latest + ".reviewed", overwrite: true);
    }
}

public sealed class EvidenceTooLargeException(string message) : IOException(message);

public sealed record ExecutorDeps(
    IocData Ioc, IRegistryStore Registry, IFileIdentityProvider FileIds, IFileProtector Protector,
    IProcessInspector Processes, IPrivilegedRunner Privileged, IDefenderService Defender);

/// <summary>
/// Apply 단계. 각 항목을 실행 직전에 다시 확인하고, 다르면 아무것도 바꾸지 않고 중단한다.
/// 사용자 파일·레지스트리 변경은 일반 권한의 본인 프로세스에서만 수행한다.
/// </summary>
public sealed class RemediationExecutor(ExecutorDeps deps, TargetUser target, DataPaths paths)
{
    private const long MaxEvidenceBytes = 2L * 1024 * 1024 * 1024;

    public async Task<IReadOnlyList<ItemResult>> ExecuteAsync(RemediationPlan plan, IReadOnlySet<string> selectedIds, ScanResult scan, bool dryRun, IProgress<string>? progress, CancellationToken ct)
    {
        var results = new List<ItemResult>();
        if (plan.UserSid != target.Sid) throw new InvalidOperationException("계획의 대상 사용자와 현재 대상이 다릅니다.");
        Journal? journal = null;
        if (!dryRun)
        {
            Directory.CreateDirectory(paths.Root);
            journal = Journal.Create(paths, plan.PlanId);
            journal.Write("plan", new { plan.PlanId, plan.ScanId, Selected = selectedIds.ToArray(), Items = plan.Items.Where(i => selectedIds.Contains(i.Id)).ToArray() });
        }
        foreach (var item in plan.Items)
        {
            if (!selectedIds.Contains(item.Id)) { results.Add(R(item, ItemOutcome.Skipped, "선택하지 않았습니다.")); continue; }
            if (ct.IsCancellationRequested) { results.Add(R(item, ItemOutcome.Skipped, "취소되어 실행하지 않았습니다.")); continue; }
            progress?.Report(item.Title);
            ItemResult r;
            try
            {
                journal?.Write("item-start", new { item.Id, item.Kind });
                r = await RunItemAsync(item, scan, plan, dryRun, journal, ct);
            }
            catch (OperationCanceledException) { r = R(item, ItemOutcome.Aborted, "취소되었습니다."); }
            catch (Exception e) { r = R(item, ItemOutcome.Failed, $"처리하지 못했습니다: {FriendlyError(e)}"); }
            // 변경이 이미 끝난 뒤의 기록 실패 때문에 결과를 잃으면 안 된다. 결과는 화면에 그대로 전달한다.
            try { journal?.Write("item-result", r); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { r = r with { Message = r.Message + " (변경 기록을 남기지 못했습니다.)" }; }
            results.Add(r);
        }
        try { journal?.Write("run-finished", new { Count = results.Count }); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        if (!dryRun) HistoryStore.AppendActions(paths, results.Where(r => r.Outcome != ItemOutcome.Skipped));
        return results;
    }

    private static string FriendlyError(Exception e) => e switch
    {
        UnauthorizedAccessException => "권한이 부족합니다.",
        IOException when IsDiskFull(e) => "디스크 공간이 부족합니다.",
        EvidenceTooLargeException => e.Message,
        IOException => "파일이 사용 중이거나 읽을 수 없습니다.",
        System.Security.SecurityException => "권한이 부족합니다.",
        InvalidDataException or InvalidOperationException => e.Message,
        _ => $"예상하지 못한 오류({e.GetType().Name})",
    };
    private static bool IsDiskFull(Exception e) => (e.HResult & 0xFFFF) is 0x70 or 0x27;
    private static bool IsSharingViolation(Exception e) => (e.HResult & 0xFFFF) is 0x20 or 0x21;

    private static ItemResult R(PlanItem i, ItemOutcome o, string m) => new(i.Id, i.Kind, i.Title, o, m, DateTimeOffset.Now);

    private async Task<ItemResult> RunItemAsync(PlanItem item, ScanResult scan, RemediationPlan plan, bool dryRun, Journal? journal, CancellationToken ct)
    {
        switch (item.Kind)
        {
            case PlanKind.RemoveComKey: return RemoveCom(item, dryRun, journal, plan);
            case PlanKind.QuarantineDll: return QuarantineDll(item, dryRun, journal, plan, ct);
            case PlanKind.ClearLauncherCache: return ClearCache(item, scan, dryRun, journal, plan, ct);
            case PlanKind.BlockKnownNetwork:
            {
                if (dryRun) return R(item, ItemOutcome.DryRunOk, "관리자 승인 후 차단 규칙을 추가할 예정입니다.");
                var res = await deps.Privileged.BlockKnownNetworkAsync(ct);
                return R(item, res.Ok ? ItemOutcome.Succeeded : ItemOutcome.Failed, res.Message);
            }
            case PlanKind.BlockLauncherOutbound:
            {
                if (item.LauncherExe is null || !PathSafety.IsValidLauncherExecutable(item.LauncherExe, out var why))
                    return R(item, ItemOutcome.Aborted, "런처 파일을 다시 확인하지 못해 중단했습니다.");
                if (dryRun) return R(item, ItemOutcome.DryRunOk, "관리자 승인 후 차단 규칙을 추가할 예정입니다.");
                var res = await deps.Privileged.BlockLauncherAsync(item.LauncherExe, ct);
                return R(item, res.Ok ? ItemOutcome.Succeeded : ItemOutcome.Failed, res.Message);
            }
            case PlanKind.DefenderQuickScan or PlanKind.DefenderFullScan:
            {
                if (dryRun) return R(item, ItemOutcome.DryRunOk, "Defender 검사를 시작할 예정입니다.");
                var res = await deps.Defender.RunScanAsync(item.Kind == PlanKind.DefenderFullScan, ct);
                return R(item, res.Ok ? ItemOutcome.Succeeded : ItemOutcome.Failed, res.Message);
            }
            case PlanKind.DefenderOfflineScan:
            {
                if (dryRun) return R(item, ItemOutcome.DryRunOk, "관리자 승인 후 재부팅과 함께 검사합니다.");
                var res = await deps.Privileged.StartDefenderOfflineAsync(ct);
                return R(item, res.Ok ? ItemOutcome.Started : ItemOutcome.Failed, res.Message);
            }
            default: return R(item, ItemOutcome.Failed, "알 수 없는 항목입니다.");
        }
    }

    private string ExpectedKeyPrefix() => $@"HKU\{target.Sid}_Classes\";

    private ItemResult RemoveCom(PlanItem item, bool dryRun, Journal? journal, RemediationPlan plan)
    {
        var key = item.ExpectedRegistryKey ?? "";
        var clsidSuffix = $@"CLSID\{deps.Ioc.ComClsid}\InprocServer32";
        if (!key.StartsWith(ExpectedKeyPrefix(), StringComparison.OrdinalIgnoreCase) || !key.EndsWith(clsidSuffix, StringComparison.OrdinalIgnoreCase))
            return R(item, ItemOutcome.Aborted, "대상 사용자의 지정된 COM 항목이 아니어서 중단했습니다.");
        if (!target.ProcessIsTargetUser) return R(item, ItemOutcome.Aborted, "다른 계정으로 실행 중이어서 중단했습니다.");

        var snap = deps.Registry.Read(key);
        if (snap is null) return R(item, ItemOutcome.Succeeded, "이미 없는 항목입니다.");
        snap.Values.TryGetValue("", out var v);
        if (!string.Equals((v ?? "").Trim().Trim('"'), item.ExpectedRegistryValue, StringComparison.OrdinalIgnoreCase))
            return R(item, ItemOutcome.Aborted, "점검 이후 값이 바뀌어 중단했습니다. 다시 점검해 주세요.");
        if (snap.SubKeys.Count > 0 || snap.Values.Keys.Any(k => k.Length > 0 && !k.Equals("ThreadingModel", StringComparison.OrdinalIgnoreCase)))
            return R(item, ItemOutcome.ManualRequired, "관계없는 값이 함께 있어 일괄 삭제하지 않았습니다. 전문가 확인이 필요합니다.");

        var parentPath = key[..key.LastIndexOf('\\')];
        var parent = deps.Registry.Read(parentPath);
        var parentRemovable = parent is not null
            && parent.SubKeys.All(s => s.Equals("InprocServer32", StringComparison.OrdinalIgnoreCase))
            && parent.Values.Keys.All(k => k.Length == 0);
        if (dryRun) return R(item, ItemOutcome.DryRunOk, "조치 조건을 모두 통과했습니다.");

        WriteEvidence(plan.PlanId, $"com-{item.Id}.json", JsonSerializer.Serialize(new { key, values = snap.Values, parent = parent?.Values }, Json.Options));
        journal?.Write("before", new { item.Id, key, values = snap.Values });
        deps.Registry.DeleteEmptyKey(key);
        if (parentRemovable) deps.Registry.DeleteEmptyKey(parentPath);
        if (deps.Registry.Read(key) is not null) return R(item, ItemOutcome.Failed, "삭제를 확인하지 못했습니다.");
        return R(item, ItemOutcome.Succeeded, parentRemovable ? "사용자 COM 항목을 삭제했고, 삭제가 확인되었습니다." : "InprocServer32 항목을 삭제했습니다. 상위 키에 다른 값이 있어 상위 키는 남겼습니다.");
    }

    private ItemResult QuarantineDll(PlanItem item, bool dryRun, Journal? journal, RemediationPlan plan, CancellationToken ct)
    {
        var path = item.ExpectedPath ?? "";
        if (!target.ProcessIsTargetUser) return R(item, ItemOutcome.Aborted, "다른 계정으로 실행 중이어서 중단했습니다.");
        if (!PathSafety.TryMatchDllLayout(target, path, out var root) || root is null) return R(item, ItemOutcome.Aborted, "허용된 위치가 아니어서 중단했습니다.");
        if (PathSafety.HasReparseInChain(target.LocalAppData, path) && PathSafety.HasReparseInChain(target.RoamingAppData, path))
            return R(item, ItemOutcome.Aborted, "경로에 링크가 있어 중단했습니다.");
        if (!File.Exists(path)) return R(item, ItemOutcome.Succeeded, "이미 없는 파일입니다.");
        string hash;
        try { hash = ScanEngine.Sha256File(path, ct); }
        catch (IOException e) when (IsSharingViolation(e)) { return R(item, ItemOutcome.PendingReboot, "파일이 잠겨 있습니다. PC를 다시 시작한 뒤 이 프로그램으로 다시 점검하세요."); }
        if (!hash.Equals(item.ExpectedSha256, StringComparison.OrdinalIgnoreCase)) return R(item, ItemOutcome.Aborted, "점검 이후 파일이 바뀌어 중단했습니다. 다시 점검해 주세요.");
        if (item.ExpectedFileId is not null && deps.FileIds.GetFileId(path) != item.ExpectedFileId) return R(item, ItemOutcome.Aborted, "점검 이후 다른 파일로 교체되어 중단했습니다.");
        if (dryRun) return R(item, ItemOutcome.DryRunOk, "조치 조건을 모두 통과했습니다.");

        Directory.CreateDirectory(paths.Quarantine);
        deps.Protector.RestrictToCurrentUser(paths.Root);
        var dest = Path.Combine(paths.Quarantine, hash + ".quarantined");
        WriteEvidence(plan.PlanId, $"dll-{item.Id}.json", JsonSerializer.Serialize(new { path, sha256 = hash, length = new FileInfo(path).Length, lastWriteUtc = File.GetLastWriteTimeUtc(path) }, Json.Options));
        journal?.Write("before", new { item.Id, path, hash });
        try { File.Move(path, dest, overwrite: true); }
        catch (IOException e) when (IsSharingViolation(e))
        { return R(item, ItemOutcome.PendingReboot, "파일이 사용 중이라 옮기지 못했습니다. PC를 다시 시작한 뒤 런처를 열지 말고 이 프로그램으로 다시 점검하세요."); }
        catch (UnauthorizedAccessException)
        {
            return IsLoaded(path, ct)
                ? R(item, ItemOutcome.PendingReboot, "실행 중인 프로그램이 파일을 쓰고 있어 옮기지 못했습니다. PC를 다시 시작한 뒤 런처를 열지 말고 이 프로그램으로 다시 점검하세요.")
                : R(item, ItemOutcome.Failed, "권한이 없어 파일을 옮기지 못했습니다. 보안 제품이 막았을 수 있습니다. 보호 기록을 확인한 뒤 다시 점검하세요.");
        }

        // 여기부터는 파일이 이미 옮겨졌다. 뒷정리가 실패해도 격리 사실을 실패로 보고하지 않는다.
        var notes = "";
        try { deps.Protector.ProtectForQuarantine(dest); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException) { notes += " 격리 파일 권한은 제한하지 못했습니다. 이름을 바꿔 실행되지 않게 해 두었습니다."; }
        try
        {
            if (!ScanEngine.Sha256File(dest, ct).Equals(hash, StringComparison.OrdinalIgnoreCase))
                return R(item, ItemOutcome.Failed, "파일은 옮겼지만 격리된 파일의 해시가 달라 확인이 필요합니다.");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { notes += " 격리 후 해시는 다시 확인하지 못했습니다."; }
        try
        {
            var hashDir = Path.GetDirectoryName(path)!;
            if (PathSafety.Hex64().IsMatch(Path.GetFileName(hashDir)) && !Directory.EnumerateFileSystemEntries(hashDir).Any())
                Directory.Delete(hashDir, recursive: false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { notes += " 비어 있는 폴더는 남았습니다."; }
        return IsLoaded(PathSafety.DllName, ct)
            ? R(item, ItemOutcome.PendingReboot, "파일은 격리했지만 실행 중인 프로그램이 아직 불러와 있습니다. 작업을 저장한 뒤 PC를 다시 시작하세요." + notes)
            : R(item, ItemOutcome.Succeeded, "DLL을 격리했습니다. 상위 폴더와 정상 파일은 남겨 두었습니다." + notes);
    }

    private bool IsLoaded(string pathOrName, CancellationToken ct)
    {
        try { return deps.Processes.FindLoadedModule(Path.GetFileName(pathOrName), ct).Hits.Count > 0; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException) { return false; }
    }

    private ItemResult ClearCache(PlanItem item, ScanResult scan, bool dryRun, Journal? journal, RemediationPlan plan, CancellationToken ct)
    {
        var dir = PathSafety.LauncherCacheDir(target);
        if (!target.ProcessIsTargetUser) return R(item, ItemOutcome.Aborted, "다른 계정으로 실행 중이어서 중단했습니다.");
        if (!string.Equals(item.ExpectedPath, dir, StringComparison.OrdinalIgnoreCase)) return R(item, ItemOutcome.Aborted, "지정된 캐시 위치가 아니어서 중단했습니다.");
        if (!Directory.Exists(dir)) return R(item, ItemOutcome.Succeeded, "이미 없는 폴더입니다.");
        if (PathSafety.HasReparseInChain(target.RoamingAppData, dir)) return R(item, ItemOutcome.Aborted, "경로에 링크가 있어 중단했습니다.");
        if (Directory.EnumerateFileSystemEntries(dir, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 }).Any(PathSafety.IsReparse))
            return R(item, ItemOutcome.Aborted, "캐시 안에 링크가 있어 중단했습니다.");
        if (deps.Processes.FindByNames(["nikke_launcher", "tbs_browser"]).Count > 0)
            return R(item, ItemOutcome.Aborted, "런처가 실행 중이라 캐시가 잠겨 있을 수 있습니다. 런처를 닫고 다시 시도하세요. 런처를 다시 켜서 풀지 마세요.");
        if (dryRun) return R(item, ItemOutcome.DryRunOk, "조치 조건을 모두 통과했습니다.");

        // 증거 보존이 실패하면 지우지 않는다.
        PreserveLogs(plan.PlanId, scan, dir, ct);
        journal?.Write("before", new { item.Id, dir });
        var moved = dir + ".removing-" + plan.PlanId[..8];
        try { Directory.Move(dir, moved); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { return R(item, ItemOutcome.Failed, "캐시가 사용 중이라 정리하지 못했습니다. 런처를 닫거나 PC를 다시 시작한 뒤 다시 시도하세요."); }
        try { Directory.Delete(moved, recursive: true); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { return R(item, ItemOutcome.PendingReboot, "캐시는 런처가 쓰지 않는 이름으로 옮겼지만 일부 파일을 지우지 못했습니다. 재부팅 후 해당 폴더를 지워 주세요."); }
        return R(item, ItemOutcome.Succeeded, "런처 전용 캐시를 정리했습니다. 감염 치료가 아니라 변조 파일 재사용 방지 조치입니다.");
    }

    private void PreserveLogs(string planId, ScanResult scan, string cacheDir, CancellationToken ct)
    {
        var dest = EvidenceDir(planId);
        long total = 0;
        void Copy(string src, string relName)
        {
            ct.ThrowIfCancellationRequested();
            var len = new FileInfo(src).Length;
            total += len;
            if (total > MaxEvidenceBytes) throw new EvidenceTooLargeException("보존할 로그가 2GB를 넘어 캐시를 지우지 않았습니다. 증거를 잃지 않도록 멈췄습니다. 런처만 열지 않으면 당장 위험하지 않으니 전문가와 상의하거나 로그를 다른 곳에 복사한 뒤 진행하세요.");
            var to = Path.Combine(dest, relName);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            using var i = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var o = new FileStream(to, FileMode.Create, FileAccess.Write);
            i.CopyTo(o);
        }
        var n = 0;
        foreach (var inst in scan.Installs)
        {
            n++;
            var log = Path.Combine(inst.LauncherDir, "intl_service", "debug.log");
            if (File.Exists(log)) Copy(log, Path.Combine($"launcher{n}", "debug.log"));
            var tg = Path.Combine(inst.LauncherDir, "log", "tinyget");
            if (Directory.Exists(tg))
                foreach (var f in Directory.EnumerateFiles(tg, "*.log", new EnumerationOptions { AttributesToSkip = FileAttributes.ReparsePoint }))
                    Copy(f, Path.Combine($"launcher{n}", "tinyget", Path.GetFileName(f) + ".txt"));
        }
        var ls = Path.Combine(cacheDir, "Local Storage", "leveldb");
        if (Directory.Exists(ls))
            foreach (var f in Directory.EnumerateFiles(ls, "*", new EnumerationOptions { AttributesToSkip = FileAttributes.ReparsePoint }))
                Copy(f, Path.Combine("leveldb", Path.GetFileName(f) + ".data"));
    }

    private string EvidenceDir(string planId)
    {
        var d = Path.Combine(paths.Evidence, planId);
        Directory.CreateDirectory(d);
        deps.Protector.RestrictToCurrentUser(paths.Root);
        return d;
    }

    private void WriteEvidence(string planId, string name, string content) =>
        File.WriteAllText(Path.Combine(EvidenceDir(planId), name), content);
}
