using System.Security.Cryptography;

namespace NikkeSafetyCheck.Core;

public sealed class ScanEngine(IocData ioc, PlatformServices svc, string toolVersion)
{
    private const int TotalSteps = 10;

    public ScanResult Run(ScanRequest req, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var started = DateTimeOffset.Now;
        var ctx = new Ctx(ioc, req, ct);
        var step = 0;
        void Step(string msg) => progress?.Report(new ScanProgress(msg, step++, TotalSteps));

        IReadOnlyList<LauncherInstall> installs = [];
        Step("설치 위치를 찾는 중");
        Guard(ctx, "NSC-INSTALL", "니케 런처 설치 위치", true, () =>
        {
            installs = InstallLocator.Locate(svc.InstallHints, req.ExtraFolders, req.Limits, ct, out var searchLimited);
            if (searchLimited)
                ctx.Unknown("NSC-INSTALL", "니케 런처 설치 위치", "폴더 탐색 제한에 걸려 일부 드라이브는 끝까지 찾지 못했습니다. 다른 곳에 또 설치했다면 폴더를 직접 선택하세요.", false);
            if (installs.Count > 0)
                ctx.Add("NSC-INSTALL", "니케 런처 설치 위치", $"니케 {installs.Count(i => i.IsNikke)}곳, 같은 구조의 다른 런처 {installs.Count(i => !i.IsNikke)}곳을 찾았습니다.", CheckStatus.NotApplicable, EvidenceType.Coverage, Confidence.High, source: "motherSphere");
        });

        Step("런처 로그를 확인하는 중");
        Guard(ctx, "NSC-LOG-EXEC", "런처 실행 로그(debug.log)", true, () => ScanExecutionLogs(ctx, installs));
        Step("보조 로그를 확인하는 중");
        Guard(ctx, "NSC-LOG-TINYGET", "다운로드 보조 로그(tinyget)", true, () => ScanTinyget(ctx, installs));
        Step("런처 저장 상태를 확인하는 중");
        Guard(ctx, "NSC-LS-STATE", "런처 Local Storage 상태 문자열", true, () => ScanLocalStorage(ctx));
        Step("런처 캐시를 확인하는 중");
        Guard(ctx, "NSC-CACHE-LOADER", "런처 캐시의 로더 주소", true, () => ScanLoaderCache(ctx));

        Step("사용자 COM 등록을 확인하는 중");
        var coms = new List<ComObservation>();
        Guard(ctx, "NSC-COM-KNOWN", "사용자 COM 등록", true, () => coms = ReadComEntries(ctx));

        Step("의심 DLL을 확인하는 중");
        var dllPaths = new List<DllObservation>();
        Guard(ctx, "NSC-DLL-SCAN", "의심 DLL", true, () => dllPaths = ScanDlls(ctx));
        EvaluatePersistence(ctx, coms, dllPaths);
        Guard(ctx, "NSC-COM-VARIANT", "다른 CLSID의 사용자 COM 등록", false, () => ScanComVariants(ctx));

        Step("임시 폴더 파일 이름을 확인하는 중");
        Guard(ctx, "NSC-TEMP", "에이전트 임시 파일 이름", false, () => ScanTemp(ctx));

        var running = false;
        Step("실행 중인 런처를 확인하는 중");
        try { running = svc.Processes.FindByNames(["nikke_launcher", "tbs_browser"]).Count > 0; }
        catch (Exception e) when (e is not OperationCanceledException) { }

        Step("실행 중 프로그램과 네트워크 연결을 확인하는 중");
        if (req.IncludeRuntimeChecks)
        {
            Guard(ctx, "NSC-PROC-MOD", "실행 중 프로그램의 로드 모듈", false, () => ScanModules(ctx));
            Guard(ctx, "NSC-NET-CONN", "현재 네트워크 연결", false, () => ScanNetwork(ctx));
            Guard(ctx, "NSC-DNS", "DNS 캐시", false, () => ScanDns(ctx));
        }
        else
        {
            foreach (var (id, title) in new[] { ("NSC-PROC-MOD", "실행 중 프로그램의 로드 모듈"), ("NSC-NET-CONN", "현재 네트워크 연결"), ("NSC-DNS", "DNS 캐시") })
                ctx.Add(id, title, "선택 항목을 끄고 점검해서 확인하지 않았습니다.", CheckStatus.NotApplicable, EvidenceType.Coverage, Confidence.Low);
        }

        Guard(ctx, "NSC-MANUAL", "직접 선택한 로그", false, () => ScanManual(ctx));
        Step("결과를 정리하는 중");

        return new ScanResult
        {
            ScanId = Guid.NewGuid().ToString("N"), RuleVersion = ioc.RuleVersion, ToolVersion = toolVersion,
            StartedAt = started, FinishedAt = DateTimeOffset.Now, Target = req.Target,
            Findings = ctx.Findings, Installs = installs, Cancelled = ct.IsCancellationRequested, LauncherRunning = running,
        };
    }

    /// <summary>한 검사의 실패가 이미 찾은 증거나 다른 검사에 영향을 주지 않도록 격리한다.</summary>
    private static void Guard(Ctx c, string id, string title, bool required, Action body)
    {
        if (c.Ct.IsCancellationRequested) { c.Unknown(id, title, "사용자가 점검을 취소해 확인하지 못했습니다.", required, "다시 점검하기를 눌러 주세요."); return; }
        try { body(); }
        catch (OperationCanceledException) { c.Unknown(id, title, "사용자가 점검을 취소해 확인을 마치지 못했습니다.", required, "다시 점검하기를 눌러 주세요."); }
        catch (UnauthorizedAccessException) { c.Unknown(id, title, "접근이 거부되어 확인하지 못했습니다.", required, "이 PC의 본인 계정으로 실행했는지 확인한 뒤 다시 점검하세요."); }
        catch (IOException) { c.Unknown(id, title, "파일이 잠겨 있거나 읽을 수 없어 확인하지 못했습니다.", required, "런처를 닫고 다시 점검하세요."); }
        catch (Exception e) { c.Unknown(id, title, $"예상하지 못한 오류로 확인하지 못했습니다({e.GetType().Name}).", required, "다시 점검하세요."); }
    }

    private void ScanExecutionLogs(Ctx c, IReadOnlyList<LauncherInstall> installs)
    {
        const string id = "NSC-LOG-EXEC"; const string title = "런처 실행 로그(debug.log)";
        if (installs.Count == 0)
        {
            if (c.Req.DeclaredNeverInstalled) c.Add(id, title, "니케 PC 버전을 설치한 적이 없다고 선택하셔서 해당 없음으로 처리했습니다.", CheckStatus.NotApplicable, EvidenceType.Coverage, Confidence.Low);
            else c.Unknown(id, title, "니케나 같은 구조의 런처 설치 위치를 찾지 못해 로그를 확인하지 못했습니다. 게임을 지웠다면 로그도 함께 사라졌을 수 있습니다.", true, "설치 폴더를 직접 선택하거나, 해당 런처를 설치한 적이 없으면 '설치한 적 없음'을 선택하세요.");
            return;
        }
        var scanner = new LogScanner(ioc);
        foreach (var inst in installs)
        {
            using var mark = c.BeginInstall(inst);
            var log = Path.Combine(inst.LauncherDir, "intl_service", "debug.log");
            if (!File.Exists(log))
            {
                c.Unknown(id, title, "설치 폴더는 찾았지만 debug.log가 없습니다. 런처를 실행한 적이 없거나 로그가 지워졌을 수 있습니다.", inst.IsNikke, "기록이 없으므로 이 항목으로는 판단할 수 없습니다.", log);
                continue;
            }
            LogScanResult r;
            try { r = scanner.Scan(log, c.Req.Limits.MaxLogBytes, c.Ct); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                c.Unknown(id, title, "로그를 읽을 수 없어 확인하지 못했습니다.", true, "런처를 닫고 다시 점검하세요.", log);
                continue;
            }
            if (r.ExecutionHits > 0)
            {
                var when = r.FirstStamp is null ? "" : $" 첫 기록 {r.FirstStamp}, 마지막 기록 {r.LastStamp}(로그 시각, 연도 없음).";
                c.Add(id, title, $"런처 로그에서 에이전트 실행 기록 {r.ExecutionHits}건을 찾았습니다.{when} 과거에 실행되었다는 증거이며, 지금도 실행 중이라는 뜻은 아닙니다. 어떤 정보가 유출되었는지까지 증명하지는 않습니다.",
                    CheckStatus.Found, EvidenceType.LauncherLogExecution, Confidence.High, Severity.High, Temporal.Past, RemediationEligibility.ManualOnly, path: log, required: true, source: "motherSphere", stage: EvidenceStage.AgentExecuted);
            }
            else if (r.LiteralOnlyHits > 0 || r.LoaderHits > 0)
            {
                var what = r.LoaderHits > 0 ? $"로더 관련 기록 {r.LoaderHits}건" : $"지표 문자열 {r.LiteralOnlyHits}건(콘솔 실행 기록 형식은 아님)";
                c.Add(id, title, $"{what}을 찾았습니다. 악성 코드가 불러와졌을 수 있으나 에이전트 실행까지 확인된 것은 아닙니다. 추가 확인이 필요합니다.",
                    CheckStatus.Found, EvidenceType.LauncherLogLoader, Confidence.Medium, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, path: log, required: true, source: "motherSphere", stage: EvidenceStage.ExposureOrAttempt);
            }
            else if (r.Truncated)
            {
                c.Unknown(id, title, "로그가 너무 커서 끝까지 읽지 못했습니다.", true, "읽은 부분에서는 일치 항목이 없었습니다.", log);
            }
            else
            {
                c.Add(id, title, "확인한 로그에서 에이전트 실행 기록을 찾지 못했습니다.", CheckStatus.NotFound, EvidenceType.LauncherLogExecution, Confidence.High, path: log, required: true, source: "motherSphere");
            }
        }
    }

    private void ScanTinyget(Ctx c, IReadOnlyList<LauncherInstall> installs)
    {
        const string id = "NSC-LOG-TINYGET"; const string title = "다운로드 보조 로그(tinyget)";
        if (installs.Count == 0)
        {
            c.Add(id, title, c.Req.DeclaredNeverInstalled ? "설치한 적 없음으로 선택되어 해당 없음입니다." : "설치 위치를 찾지 못해 확인하지 못했습니다.",
                c.Req.DeclaredNeverInstalled ? CheckStatus.NotApplicable : CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low);
            return;
        }
        foreach (var inst in installs)
        {
            using var mark = c.BeginInstall(inst);
            var dir = Path.Combine(inst.LauncherDir, "log", "tinyget");
            if (!Directory.Exists(dir)) { c.Add(id, title, "tinyget 로그 폴더가 없어 이 항목은 확인할 수 없습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low, path: dir); continue; }
            int requests = 0, successes = 0, unreadable = 0, luaFiles = 0;
            var scanner = new LogScanner(ioc);
            foreach (var f in Directory.EnumerateFiles(dir, "*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
            {
                c.Ct.ThrowIfCancellationRequested();
                var name = Path.GetFileName(f);
                if (name.StartsWith("k2f", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".lua", StringComparison.OrdinalIgnoreCase)) luaFiles++;
                if (!name.EndsWith(".log", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    if (new FileInfo(f).Length > c.Req.Limits.MaxBinaryFileBytes) { unreadable++; continue; }
                    var t = scanner.ScanTinyget(f, c.Req.Limits.MaxBinaryFileBytes, c.Ct);
                    requests += t.RequestLines; successes += t.SuccessLines;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { unreadable++; }
            }
            if (successes > 0 || luaFiles > 0)
                c.Add(id, title, $"악성 파일 다운로드 성공 기록 {successes}건, 에이전트 스크립트 이름의 파일 {luaFiles}개를 찾았습니다. 내려받은 것이 실행까지 되었는지는 이 기록만으로 알 수 없지만 중요한 경고입니다.",
                    CheckStatus.Found, EvidenceType.LauncherLogDownload, Confidence.Medium, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, path: dir, source: "whykusanagi", stage: EvidenceStage.DownloadSucceeded);
            else if (requests > 0)
                c.Add(id, title, $"악성 파일 주소 요청 기록 {requests}건을 찾았지만 다운로드 성공 기록은 없습니다. 시도가 있었다는 뜻이며 다운로드나 실행을 뜻하지 않습니다.",
                    CheckStatus.Found, EvidenceType.LauncherLogDownload, Confidence.Medium, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, path: dir, source: "whykusanagi", stage: EvidenceStage.ExposureOrAttempt);
            else if (unreadable > 0)
                c.Add(id, title, $"파일 {unreadable}개를 읽지 못했습니다. 읽은 파일에서는 일치 항목이 없었습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low, path: dir, required: true, retry: "런처를 닫고 다시 점검하세요.");
            else
                c.Add(id, title, "페이로드 다운로드 기록을 찾지 못했습니다.", CheckStatus.NotFound, EvidenceType.LauncherLogDownload, Confidence.Medium, path: dir, source: "motherSphere");
        }
    }

    private void ScanLocalStorage(Ctx c)
    {
        const string id = "NSC-LS-STATE"; const string title = "런처 Local Storage 상태 문자열";
        var nikke = PathSafety.NikkeCacheDirs(c.Req.Target).Where(Directory.Exists).ToList();
        if (nikke.Count == 0 || nikke.All(d => !Directory.Exists(Path.Combine(d, "Local Storage", "leveldb"))))
            c.Add(id, title, "니케 런처 저장 폴더가 없어 확인할 수 없습니다. 런처를 쓴 적이 없거나 이미 지워졌을 수 있습니다.",
                c.Req.DeclaredNeverInstalled ? CheckStatus.NotApplicable : CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low);
        foreach (var d in nikke) ScanOneLocalStorage(c, d);
        foreach (var d in PathSafety.DiscoverOtherCacheDirs(c.Req.Target))
        {
            var start = c.Findings.Count;
            ScanOneLocalStorage(c, d);
            c.MarkOther(start, d);
        }
    }

    private void ScanOneLocalStorage(Ctx c, string cacheRoot)
    {
        const string id = "NSC-LS-STATE"; const string title = "런처 Local Storage 상태 문자열";
        var dir = Path.Combine(cacheRoot, "Local Storage", "leveldb");
        if (!Directory.Exists(dir)) return;
        int strong = 0, weak = 0, unreadable = 0;
        foreach (var f in Directory.EnumerateFiles(dir, "*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
        {
            c.Ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(f);
            if (!ext.Equals(".log", StringComparison.OrdinalIgnoreCase) && !ext.Equals(".ldb", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                if (new FileInfo(f).Length > c.Req.Limits.MaxBinaryFileBytes) { unreadable++; continue; }
                if (BinaryScanner.Contains(f, ioc.AgentStateStrong, c.Ct)) strong++;
                else if (BinaryScanner.Contains(f, ioc.AgentStateWeak, c.Ct)) weak++;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { unreadable++; }
        }
        if (strong > 0)
            c.Add(id, title, "런처 저장소에서 에이전트 상태 값의 이름(k2f.agent.state)을 찾았습니다. 이 사용자 계정에서 에이전트가 실행되었다는 증거입니다. 게임 폴더를 지워도 남는 항목입니다. 값의 내용은 읽거나 기록하지 않았습니다.",
                CheckStatus.Found, EvidenceType.AgentState, Confidence.High, Severity.High, Temporal.Past, RemediationEligibility.ManualOnly, path: dir, source: "motherSphere", stage: EvidenceStage.AgentExecuted);
        else if (weak > 0)
            c.Add(id, title, "런처 저장소에서 관련 문자열(k2f.agent)을 찾았습니다. 단독으로는 판단하기 어려워 추가 확인이 필요합니다.",
                CheckStatus.Found, EvidenceType.AgentState, Confidence.Medium, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, path: dir, source: "motherSphere", stage: EvidenceStage.ExposureOrAttempt);
        else if (unreadable > 0)
            c.Add(id, title, $"파일 {unreadable}개를 읽지 못했습니다. 런처가 켜져 있으면 잠겨 있을 수 있습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low, path: dir, required: true, retry: "런처를 닫고 다시 점검하세요.");
        else
            c.Add(id, title, "일치하는 문자열을 찾지 못했습니다. 압축 저장된 내용은 찾지 못할 수 있습니다.", CheckStatus.NotFound, EvidenceType.AgentState, Confidence.Medium, path: dir, source: "motherSphere");
    }

    private void ScanLoaderCache(Ctx c)
    {
        const string id = "NSC-CACHE-LOADER"; const string title = "런처 캐시의 로더 주소";
        var nikke = PathSafety.NikkeCacheDirs(c.Req.Target).Where(Directory.Exists).ToList();
        if (nikke.Count == 0)
            c.Add(id, title, "니케 런처 캐시 폴더가 없어 확인할 수 없습니다.", c.Req.DeclaredNeverInstalled ? CheckStatus.NotApplicable : CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low);
        foreach (var d in nikke) ScanOneCache(c, d);
        foreach (var d in PathSafety.DiscoverOtherCacheDirs(c.Req.Target))
        {
            var start = c.Findings.Count;
            ScanOneCache(c, d);
            c.MarkOther(start, d);
        }
    }

    private void ScanOneCache(Ctx c, string root)
    {
        const string id = "NSC-CACHE-LOADER"; const string title = "런처 캐시의 로더 주소";
        int hits = 0, netHits = 0, skipped = 0, files = 0; long total = 0;
        var dirs = new[] { Path.Combine(root, "Code Cache", "js"), Path.Combine(root, "Cache", "Cache_Data") }.Where(Directory.Exists).ToList();
        foreach (var d in dirs)
        foreach (var f in Directory.EnumerateFiles(d, "*", new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint }))
        {
            c.Ct.ThrowIfCancellationRequested();
            if (++files > c.Req.Limits.MaxCacheFiles) { skipped++; continue; }
            try
            {
                var len = new FileInfo(f).Length;
                total += len;
                if (len > c.Req.Limits.MaxBinaryFileBytes || total > c.Req.Limits.MaxCacheTotalBytes) { skipped++; continue; }
                if (ioc.LoaderCacheMarkers.Any(m => BinaryScanner.Contains(f, m, c.Ct))) hits++;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { skipped++; }
        }
        // 런처가 접속한 호스트를 남기는 파일. 쿠키와 저장 비밀번호 파일은 이름으로 걸러 열지 않는다.
        foreach (var name in new[] { "Network Persistent State", "Reporting and NEL" })
        foreach (var f in Directory.EnumerateFiles(root, name, new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 3, AttributesToSkip = FileAttributes.ReparsePoint }))
        {
            c.Ct.ThrowIfCancellationRequested();
            try { if (new FileInfo(f).Length <= c.Req.Limits.MaxBinaryFileBytes && BinaryScanner.Contains(f, ioc.LogExposureMarker, c.Ct)) netHits++; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { skipped++; }
        }
        if (hits + netHits > 0)
            c.Add(id, title, $"캐시 파일 {hits}개에서 악성 로더 주소를, 접속 기록 파일 {netHits}개에서 공격 도메인을 찾았습니다. 변조 파일을 불러오거나 접속한 흔적이며 에이전트 실행을 뜻하지는 않습니다. 런처를 다시 열기 전에 캐시 정리가 필요합니다.",
                CheckStatus.Found, EvidenceType.LoaderCache, Confidence.Medium, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, path: root, source: "motherSphere", stage: EvidenceStage.ExposureOrAttempt);
        else if (skipped > 0)
            c.Add(id, title, $"파일 {skipped}개를 제한이나 잠금 때문에 확인하지 못했습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low, path: root, required: true, retry: "런처를 닫고 다시 점검하세요.");
        else
            c.Add(id, title, dirs.Count == 0 ? "캐시 폴더가 비어 있어 일치 항목이 없습니다." : "일치하는 주소를 찾지 못했습니다.", CheckStatus.NotFound, EvidenceType.LoaderCache, Confidence.Medium, path: root, source: "motherSphere");
    }

    private sealed record ComObservation(string KeyPath, RegistryKeySnapshot Inproc, string Value, string Expanded);
    private sealed record DllObservation(string Path, BrowserRoot Root, string Sha256, bool Layout, bool NameMatchesHash, SignatureState Signature, bool Reparse, string? FileId);

    private List<ComObservation> ReadComEntries(Ctx c)
    {
        var t = c.Req.Target;
        var classes = t.Sid + "_Classes";
        if (!svc.Registry.IsHiveLoaded(classes))
            throw new UnauthorizedAccessException("사용자 하이브 미로드");
        var list = new List<ComObservation>();
        foreach (var prefix in new[] { $@"HKU\{classes}\CLSID", $@"HKU\{classes}\WOW6432Node\CLSID" })
        {
            var path = $@"{prefix}\{ioc.ComClsid}\InprocServer32";
            var snap = svc.Registry.Read(path);
            if (snap is null) continue;
            snap.Values.TryGetValue("", out var v);
            var value = (v ?? "").Trim().Trim('"');
            list.Add(new ComObservation(path, snap, value, t.ProcessIsTargetUser ? Environment.ExpandEnvironmentVariables(value) : value));
        }
        return list;
    }

    private List<DllObservation> ScanDlls(Ctx c)
    {
        var res = new List<DllObservation>();
        var denied = false;
        foreach (var root in PathSafety.BrowserRoots(c.Req.Target))
        {
            var helper = Path.Combine(root.UserDataDir, PathSafety.HelperDirName);
            try
            {
                if (!Directory.Exists(helper)) continue;
                var opts = new EnumerationOptions { IgnoreInaccessible = false, AttributesToSkip = 0 };
                void TryObserve(string dll, bool layout)
                {
                    // 파일 하나가 잠겨도 나머지 파일과 다른 브라우저 폴더는 계속 확인한다.
                    try { res.Add(Observe(dll, root, layout, c.Ct)); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { denied = true; }
                }
                var direct = Path.Combine(helper, PathSafety.DllName);
                if (File.Exists(direct)) TryObserve(direct, false);
                foreach (var sub in Directory.EnumerateDirectories(helper, "*", opts))
                {
                    c.Ct.ThrowIfCancellationRequested();
                    var dll = Path.Combine(sub, PathSafety.DllName);
                    if (File.Exists(dll)) TryObserve(dll, PathSafety.Hex64().IsMatch(Path.GetFileName(sub)));
                    else if (PathSafety.Hex64().IsMatch(Path.GetFileName(sub)))
                        c.Add("NSC-DLL-SCAN", "의심 DLL", $"{root.Browser} 폴더에 악성 설치 구조와 같은 64자리 이름의 폴더가 있지만 DLL은 없습니다. 백신이나 다른 도구가 DLL만 지웠을 수 있습니다. 자동으로 지우지 않습니다.",
                            CheckStatus.Found, EvidenceType.PersistenceDll, Confidence.Medium, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, path: sub, source: "motherSphere", required: true, stage: EvidenceStage.PersistenceInstalled);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { denied = true; }
        }
        if (denied) c.Unknown("NSC-DLL-SCAN", "의심 DLL", "일부 파일이나 브라우저 폴더를 읽지 못했습니다.", true, "브라우저를 닫고 다시 점검하세요. 그래도 안 되면 PC를 다시 시작한 뒤 점검하세요.");
        return res;
    }

    private DllObservation Observe(string path, BrowserRoot root, bool layoutFolder, CancellationToken ct)
    {
        var hash = Sha256File(path, ct);
        var parent = Path.GetFileName(Path.GetDirectoryName(path)!);
        SignatureState sig;
        try { sig = svc.Signatures.Check(path); } catch (Exception e) when (e is not OperationCanceledException) { sig = SignatureState.Unknown; }
        return new DllObservation(path, root, hash, layoutFolder, layoutFolder && parent.Equals(hash, StringComparison.OrdinalIgnoreCase), sig,
            PathSafety.IsReparse(path) || PathSafety.IsReparse(Path.GetDirectoryName(path)!), svc.FileIds.GetFileId(path));
    }

    public static string Sha256File(string path, CancellationToken ct)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buf = new byte[1 << 16];
        int n;
        while ((n = fs.Read(buf, 0, buf.Length)) > 0) { ct.ThrowIfCancellationRequested(); sha.AppendData(buf, 0, n); }
        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    /// <summary>DLL과 COM은 서로를 근거로 판정한다. 해시 불일치는 어떤 경우에도 정상 근거로 쓰지 않는다.</summary>
    private void EvaluatePersistence(Ctx c, List<ComObservation> coms, List<DllObservation> dlls)
    {
        var alreadyUnknownDll = c.Findings.Any(f => f.RuleId == "NSC-DLL-SCAN" && f.Status == CheckStatus.Unknown);
        var comUnknown = c.Findings.Any(f => f.RuleId == "NSC-COM-KNOWN" && f.Status == CheckStatus.Unknown);
        var linked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var com in coms)
        {
            var layout = PathSafety.TryMatchDllLayout(c.Req.Target, com.Expanded, out _);
            var canonical = Canonical(com.Expanded);
            var linkedDll = dlls.FirstOrDefault(d => Canonical(d.Path).Equals(canonical, StringComparison.OrdinalIgnoreCase));
            var systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var sys32 = systemDir.Length > 0 && canonical.Equals(Path.Combine(systemDir, "wpc.dll"), StringComparison.OrdinalIgnoreCase);
            var fileExists = layout && SafeFileExists(com.Expanded);
            if (linkedDll is not null) linked.Add(linkedDll.Path);

            if (sys32)
                c.Add("NSC-COM-KNOWN", "사용자 COM 등록", "사용자 COM 항목이 Windows 정상 위치를 가리킵니다. 이 값은 지표와 일치하지 않습니다.", CheckStatus.NotFound, EvidenceType.PersistenceCom, Confidence.Medium, regKey: com.KeyPath, regValue: com.Value, required: true, source: "motherSphere");
            else if (linkedDll is not null && !linkedDll.Reparse)
                c.Add("NSC-COM-KNOWN", "사용자 COM 등록", "사용자 COM 항목이 브라우저 폴더 안의 의심 DLL을 가리킵니다. 지속 실행 장치가 설치되어 남아 있다는 결합 증거입니다. 지금 실행 중인지는 '실행 중 프로그램의 로드 모듈' 항목을 보세요.",
                    CheckStatus.Found, EvidenceType.PersistenceCom, Confidence.High, Severity.High, Temporal.Current, RemediationEligibility.Eligible, regKey: com.KeyPath, regValue: com.Value, required: true, source: "motherSphere", stage: EvidenceStage.PersistenceInstalled);
            else if (fileExists)
                c.Add("NSC-COM-KNOWN", "사용자 COM 등록", "사용자 COM 항목이 악성 DLL과 같은 구조의 경로를 가리키고 파일도 있지만, 파일이 잠겨 있거나 링크여서 끝까지 확인하지 못했습니다. 지속 실행 장치가 남아 있을 수 있어 자동으로 처리하지 않습니다. PC를 다시 시작한 뒤 다시 점검하세요.",
                    CheckStatus.Found, EvidenceType.PersistenceCom, Confidence.High, Severity.High, Temporal.Current, RemediationEligibility.ManualOnly, regKey: com.KeyPath, regValue: com.Value, required: true, source: "motherSphere", stage: EvidenceStage.PersistenceInstalled);
            else if (layout)
                c.Add("NSC-COM-KNOWN", "사용자 COM 등록", "사용자 COM 항목이 악성 DLL과 같은 구조의 경로를 가리키지만 DLL 파일은 없습니다. 백신이 DLL만 지운 경우 등에 나타나며, 설치된 적이 있다는 증거입니다.",
                    CheckStatus.Found, EvidenceType.PersistenceCom, Confidence.High, Severity.High, Temporal.Past, RemediationEligibility.Eligible, regKey: com.KeyPath, regValue: com.Value, required: true, source: "motherSphere", stage: EvidenceStage.PersistenceInstalled);
            else
                c.Add("NSC-COM-KNOWN", "사용자 COM 등록", "같은 CLSID의 사용자 항목이 있지만 알려진 악성 경로 구조가 아닙니다. 자동으로 제거하지 않습니다. 추가 확인이 필요합니다.",
                    CheckStatus.Found, EvidenceType.PersistenceCom, Confidence.Low, Severity.Suspicious, Temporal.Current, RemediationEligibility.ManualOnly, regKey: com.KeyPath, regValue: com.Value, required: true, source: "motherSphere");
        }
        if (coms.Count == 0 && !comUnknown)
            c.Add("NSC-COM-KNOWN", "사용자 COM 등록", "이 사용자 하이브에서 해당 COM 항목을 찾지 못했습니다. HKLM의 같은 CLSID는 Windows 정상 항목이므로 판정에 쓰지 않습니다.", CheckStatus.NotFound, EvidenceType.PersistenceCom, Confidence.High, required: true, source: "motherSphere");

        foreach (var d in dlls)
        {
            var known = ioc.IsKnownDll(d.Sha256);
            var comLink = linked.Contains(d.Path);
            var structural = d.Layout && d.NameMatchesHash && d.Signature != SignatureState.Valid;
            var sigText = d.Signature switch { SignatureState.Valid => "유효한 서명 있음(보조 정보)", SignatureState.Unsigned => "서명 없음", SignatureState.Invalid => "서명 검증 실패", _ => "서명 확인 불가" };
            var browser = d.Root.Browser;

            // 알려진 악성 해시는 위치와 무관하게 고위험이다. 위치와 링크 조건은 자동 조치 자격에만 쓴다.
            var eligible = !d.Reparse && d.Layout;
            var high = known || (eligible && (comLink || (structural && d.Root.IsPrimary)));
            if (high)
            {
                var why = known ? "공개된 악성 샘플 해시와 일치합니다. 해시는 샘플을 식별할 뿐이며 파일이 실행되었는지는 별개입니다." : comLink ? "사용자 COM 항목과 연결되어 있습니다(해시는 피해자별로 다를 수 있어 불일치를 정상 근거로 쓰지 않습니다)." : "폴더 이름이 파일 자신의 SHA-256과 같은, 보고된 악성 설치 구조와 일치합니다.";
                c.Add("NSC-DLL-SCAN", "의심 DLL", $"{browser} 폴더에서 의심 DLL을 찾았습니다. 파일이 있다는 것이 지금 실행 중이라는 뜻은 아닙니다. {why} {sigText}.", CheckStatus.Found, EvidenceType.PersistenceDll, Confidence.High, Severity.High, Temporal.Current, eligible ? RemediationEligibility.Eligible : RemediationEligibility.ManualOnly, path: d.Path, sha: d.Sha256, fileId: d.FileId, required: true, source: known && ioc.KnownDllSha256.First(h => h.Sha256 == d.Sha256).Source == "wormW" ? "wormW" : "motherSphere", stage: EvidenceStage.PersistenceInstalled);
            }
            else
            {
                var why = d.Reparse ? "링크가 포함된 경로라 자동 조치에서 제외합니다." : d.Root.IsPrimary ? "폴더 이름이나 서명 조건이 보고된 구조와 다릅니다." : $"{browser}에서의 지속 실행은 공개 보고로 확정되지 않았습니다.";
                c.Add("NSC-DLL-SCAN", "의심 DLL", $"{browser} 폴더에서 같은 이름의 DLL을 찾았습니다. {why} {sigText}. 추가 확인이 필요합니다.", CheckStatus.Found, EvidenceType.PersistenceDll, Confidence.Medium, Severity.Suspicious, Temporal.Current, RemediationEligibility.ManualOnly, path: d.Path, sha: d.Sha256, fileId: d.FileId, required: true, source: "whykusanagi");
            }
        }
        if (dlls.Count == 0 && !alreadyUnknownDll && !c.Findings.Any(f => f.RuleId == "NSC-DLL-SCAN"))
            c.Add("NSC-DLL-SCAN", "의심 DLL", "확인한 브라우저 폴더에서 해당 DLL을 찾지 못했습니다. PlatformExperienceHelper 폴더와 Chrome의 정상 EXE, LoadFeatures 파일은 정상일 수 있어 판정에 쓰지 않습니다.", CheckStatus.NotFound, EvidenceType.PersistenceDll, Confidence.High, required: true, source: "motherSphere");
    }

    private static string Canonical(string p)
    {
        try { return Path.TrimEndingDirectorySeparator(Path.GetFullPath(p)); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException or System.Security.SecurityException) { return p; }
    }

    private static bool SafeFileExists(string p)
    {
        try { return File.Exists(p); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>알려진 CLSID 외에 같은 악성 구조를 가리키는 사용자 COM 변종을 수동 확인 대상으로 알린다.</summary>
    private void ScanComVariants(Ctx c)
    {
            var classes = c.Req.Target.Sid + "_Classes";
            var variants = 0;
            foreach (var sub in svc.Registry.ListSubKeys($@"HKU\{classes}\CLSID").Take(20000))
            {
                c.Ct.ThrowIfCancellationRequested();
                if (sub.Equals(ioc.ComClsid, StringComparison.OrdinalIgnoreCase)) continue;
                var snap = svc.Registry.Read($@"HKU\{classes}\CLSID\{sub}\InprocServer32");
                if (snap is null || !snap.Values.TryGetValue("", out var v) || v is null) continue;
                if (v.Contains(PathSafety.HelperDirName + @"\", StringComparison.OrdinalIgnoreCase) && v.Contains(PathSafety.DllName, StringComparison.OrdinalIgnoreCase)) variants++;
            }
            c.Add("NSC-COM-VARIANT", "다른 CLSID의 사용자 COM 등록", variants > 0 ? $"다른 CLSID {variants}개가 같은 구조의 DLL 경로를 가리킵니다. 자동으로 제거하지 않습니다." : "일치하는 항목을 찾지 못했습니다.",
                variants > 0 ? CheckStatus.Found : CheckStatus.NotFound, EvidenceType.PersistenceCom, Confidence.Medium, variants > 0 ? Severity.Suspicious : Severity.None, variants > 0 ? Temporal.Current : Temporal.NotApplicable, variants > 0 ? RemediationEligibility.ManualOnly : RemediationEligibility.None, source: "whykusanagi");
    }

    private void ScanTemp(Ctx c)
    {
        const string id = "NSC-TEMP"; const string title = "에이전트 임시 파일 이름";
        var temp = c.Req.Target.TempDir;
        if (!Directory.Exists(temp)) { c.Add(id, title, "임시 폴더를 찾지 못했습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low); return; }
        var opts = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 3, AttributesToSkip = FileAttributes.ReparsePoint };
        var hits = 0; var seen = 0; var limited = false;
        foreach (var e in Directory.EnumerateFileSystemEntries(temp, "*", opts))
        {
            c.Ct.ThrowIfCancellationRequested();
            if (++seen > c.Req.Limits.MaxTempEntries) { limited = true; break; }
            var name = Path.GetFileName(e);
            if (ioc.AgentTempFilePrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase))) hits++;
        }
        if (hits > 0)
            c.Add(id, title, $"임시 폴더에서 에이전트 이름 규칙과 같은 항목 {hits}개를 찾았습니다. 수집한 자격 증명이나 화면 사진이 담겼을 수 있어 내용을 열지 않았습니다. 공유하지 말고 Windows 보안 검사 후 직접 삭제하세요.",
                CheckStatus.Found, EvidenceType.AgentTempFile, Confidence.Medium, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, source: "motherSphere");
        else if (limited)
            c.Add(id, title, "임시 파일이 너무 많아 일부만 확인했습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low);
        else
            c.Add(id, title, "일치하는 이름을 찾지 못했습니다. 파일 내용은 열지 않습니다.", CheckStatus.NotFound, EvidenceType.AgentTempFile, Confidence.Low, source: "motherSphere");
    }

    private void ScanModules(Ctx c)
    {
        const string id = "NSC-PROC-MOD"; const string title = "실행 중 프로그램의 로드 모듈";
        var r = svc.Processes.FindLoadedModule(PathSafety.DllName, c.Ct);
        var hits = r.Hits.Where(h => PathSafety.TryMatchDllLayout(c.Req.Target, h.ModulePath, out _)).ToList();
        if (hits.Count > 0)
            c.Add(id, title, $"실행 중인 프로그램 {hits.Count}개가 의심 DLL을 불러와 있습니다. 지금 활성 상태라는 뜻입니다. 조치 후 PC를 다시 시작해야 메모리에서 사라집니다.",
                CheckStatus.Found, EvidenceType.ProcessModule, Confidence.High, Severity.High, Temporal.Current, RemediationEligibility.ManualOnly, path: hits[0].ModulePath, source: "whykusanagi", stage: EvidenceStage.CurrentlyLoaded);
        else if (r.InaccessibleProcesses > 0)
            c.Add(id, title, $"일치 항목은 없었지만 프로그램 {r.InaccessibleProcesses}개는 권한 문제로 들여다보지 못했습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low);
        else
            c.Add(id, title, "일치하는 로드 모듈을 찾지 못했습니다.", CheckStatus.NotFound, EvidenceType.ProcessModule, Confidence.Medium, source: "whykusanagi");
    }

    private void ScanNetwork(Ctx c)
    {
        const string id = "NSC-NET-CONN"; const string title = "현재 네트워크 연결";
        var hits = svc.Network.FindConnections(ioc.BlockIps.Concat(ioc.WatchOnlyIps));
        if (hits.Count > 0)
            c.Add(id, title, $"알려진 지표 IP와 연결된 항목 {hits.Count}개가 있습니다. 보조 지표이며 이것만으로 감염을 확정하지 않습니다.", CheckStatus.Found, EvidenceType.NetworkConnection, Confidence.Medium, Severity.Suspicious, Temporal.Current, RemediationEligibility.ManualOnly, source: "motherSphere");
        else
            c.Add(id, title, "현재 연결 중 일치 항목이 없습니다. 공격 서버가 바뀌었으면 찾지 못합니다.", CheckStatus.NotFound, EvidenceType.NetworkConnection, Confidence.Low, source: "motherSphere");
    }

    private void ScanDns(Ctx c)
    {
        const string id = "NSC-DNS"; const string title = "DNS 캐시";
        var hits = svc.Network.FindDnsCacheEntries(ioc.BlockDomains);
        if (hits is null)
            c.Add(id, title, "DNS 캐시를 읽지 못했습니다.", CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low);
        else if (hits.Count > 0)
            c.Add(id, title, $"지표 도메인 조회 기록 {hits.Count}건이 있습니다. 런처 실행이나 정보 유출을 뜻하지 않으며 보안 뉴스를 보다가 생겼을 수도 있습니다.", CheckStatus.Found, EvidenceType.DnsCache, Confidence.Low, Severity.Suspicious, Temporal.Past, RemediationEligibility.ManualOnly, source: "motherSphere");
        else
            c.Add(id, title, "일치 항목이 없습니다. DNS 캐시는 금방 사라지므로 과거 기록을 뜻하지 않습니다.", CheckStatus.NotFound, EvidenceType.DnsCache, Confidence.Low, source: "motherSphere");
    }

    private void ScanManual(Ctx c)
    {
        var scanner = new LogScanner(ioc);
        foreach (var f in c.Req.ManualLogFiles)
        {
            if (!PathSafety.IsPlainLocalPath(f) || !File.Exists(f)) { c.Add("NSC-MANUAL", "직접 선택한 로그", "선택한 파일을 읽을 수 없습니다.", CheckStatus.Unknown, EvidenceType.ManualSubmission, Confidence.Low, path: f); continue; }
            var r = scanner.Scan(f, c.Req.Limits.MaxLogBytes, c.Ct);
            var any = r.ExecutionHits + r.LiteralOnlyHits + r.LoaderHits;
            // 임의 위치의 파일은 위치를 믿을 수 없으므로 의심 이상으로 올리지 않는다.
            c.Add("NSC-MANUAL", "직접 선택한 로그", any > 0 ? $"수동 제출 자료에서 지표 문자열 {any}건을 찾았습니다. 공식 설치 위치에서 읽은 기록이 아니어서 실행 증거로 올리지 않습니다." : "수동 제출 자료에서 일치 항목을 찾지 못했습니다.",
                any > 0 ? CheckStatus.Found : CheckStatus.NotFound, EvidenceType.ManualSubmission, Confidence.Low, any > 0 ? Severity.Suspicious : Severity.None, any > 0 ? Temporal.Past : Temporal.NotApplicable, any > 0 ? RemediationEligibility.ManualOnly : RemediationEligibility.None, path: f);
        }
    }

    private sealed class Ctx(IocData ioc, ScanRequest req, CancellationToken ct)
    {
        public ScanRequest Req => req;
        public CancellationToken Ct => ct;
        public List<Finding> Findings { get; } = [];

        public void Add(string id, string title, string detail, CheckStatus status, EvidenceType type, Confidence conf,
            Severity sev = Severity.None, Temporal temporal = Temporal.NotApplicable, RemediationEligibility elig = RemediationEligibility.None,
            string? path = null, string? sha = null, string? regKey = null, string? regValue = null, string? fileId = null,
            bool required = false, string source = "motherSphere", string? retry = null, EvidenceStage stage = EvidenceStage.None)
        {
            Findings.Add(new Finding
            {
                RuleId = id, Title = title, Detail = detail, SourceUrl = ioc.Source(source), RuleVersion = ioc.RuleVersion,
                ObservedAt = DateTimeOffset.Now, UserSid = req.Target.Sid, EvidenceType = type, Confidence = conf, Status = status,
                RemediationEligibility = elig, Severity = sev, Temporal = temporal, Required = required, Path = path, Sha256 = sha,
                RegistryKey = regKey, RegistryValue = regValue, FileId = fileId, RetryHint = retry, Stage = stage,
            });
        }

        /// <summary>니케가 아닌 폴더에서 나온 결과임을 표시한다. 등급은 지표로 정해지고 게임 이름으로 바뀌지 않는다.</summary>
        public void MarkOther(int start, string folder)
        {
            for (var i = start; i < Findings.Count; i++)
                Findings[i] = Findings[i] with { OtherLauncher = true, Detail = $"[니케 외 런처 폴더] {Findings[i].Detail}" };
        }

        public IDisposable BeginInstall(LauncherInstall inst) => new InstallScope(this, inst, Findings.Count);

        private sealed class InstallScope(Ctx c, LauncherInstall inst, int start) : IDisposable
        {
            public void Dispose() { if (!inst.IsNikke) c.MarkOther(start, inst.LauncherDir); }
        }

        public void Unknown(string id, string title, string detail, bool required, string? retry = null, string? path = null) =>
            Add(id, title, detail, CheckStatus.Unknown, EvidenceType.Coverage, Confidence.Low, required: required, retry: retry, path: path);
    }
}
