using System.Diagnostics;
using System.Text.RegularExpressions;

namespace NikkeSafetyCheck.Core;

/// <summary>
/// 설치 후보를 모아 폴더 구조로 검증한다. 설치 정보나 바로가기 문자열은 경로로만 해석하며 절대 실행하지 않는다.
/// </summary>
public static partial class InstallLocator
{
    private static readonly string[] CommonRelative =
    [
        @"NIKKE", @"Program Files\NIKKE", @"Program Files (x86)\NIKKE", @"Games\NIKKE", @"Game\NIKKE",
        @"SteamLibrary\NIKKE", @"Level Infinite\NIKKE", @"Program Files\Level Infinite\NIKKE", @"Games\Level Infinite\NIKKE",
    ];

    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase) { "Windows", "AppData", "node_modules", ".git" };

    [GeneratedRegex(@"^\s*""?(?<p>[^""]+?\.exe)""?(\s|,|$)", RegexOptions.IgnoreCase)] private static partial Regex ExeInCommand();

    /// <summary>명령 형식 문자열에서 앞쪽 실행 파일 경로만 잘라 낸다. 나머지 인자는 버린다.</summary>
    public static string ExtractPath(string raw)
    {
        var s = raw.Trim();
        var m = ExeInCommand().Match(s);
        if (m.Success) return m.Groups["p"].Value.Trim();
        return s.Trim('"').Split(',')[0].Trim();
    }

    [GeneratedRegex(@"[A-Za-z]:\\[^""\r\n]*?nikke_launcher(_hmt)?\.exe", RegexOptions.IgnoreCase)] private static partial Regex ExeInReg();

    /// <summary>런처가 남긴 .reg 내용에서 경로만 뽑는다. .reg를 실행하거나 레지스트리에 넣지 않는다.</summary>
    public static IEnumerable<string> PathsInRegText(string text) =>
        ExeInReg().Matches(text.Replace(@"\\", @"\")).Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>실행 파일이나 런처 폴더 이름으로만 판단한다. 사용자 폴더 등 상위 경로의 이름은 근거로 쓰지 않는다.</summary>
    public static bool LooksLikeNikke(string dir)
    {
        if (PathSafety.LauncherExeNames.Any(n => File.Exists(Path.Combine(dir, n)))) return true;
        static bool Named(string? p) => p is not null && (Path.GetFileName(p).Contains("nikke", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(p).Contains("니케", StringComparison.Ordinal));
        return Named(dir) || Named(Path.GetDirectoryName(dir));
    }

    public static string? ValidateLauncherDir(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return null;
        var p = ExtractPath(candidate);
        if (!PathSafety.IsPlainLocalPath(p)) return null;
        try
        {
            if (File.Exists(p)) p = Path.GetDirectoryName(p)!;
            if (!Directory.Exists(p)) return null;
            foreach (var dir in new[] { Path.Combine(p, "Launcher"), p, Path.GetDirectoryName(p) ?? p })
            {
                if (!Directory.Exists(dir)) continue;
                if (Directory.Exists(Path.Combine(dir, "intl_service")) || Directory.Exists(Path.Combine(dir, "log", "tinyget")))
                    return Path.TrimEndingDirectorySeparator(Path.GetFullPath(dir));
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        return null;
    }

    public static IReadOnlyList<LauncherInstall> Locate(IInstallHintSource src, IEnumerable<string> extraFolders, ScanLimits limits, CancellationToken ct, out bool searchLimited)
    {
        searchLimited = false;
        var found = new Dictionary<string, LauncherInstall>(StringComparer.OrdinalIgnoreCase);
        void Add(string? raw, string source)
        {
            var d = ValidateLauncherDir(raw);
            if (d is null || found.ContainsKey(d)) return;
            var exe = PathSafety.LauncherExeNames.Select(n => Path.Combine(d, n)).FirstOrDefault(File.Exists);
            found[d] = new LauncherInstall(d, source, exe, LooksLikeNikke(d));
        }
        foreach (var f in extraFolders) Add(f, "사용자가 선택한 폴더");
        foreach (var h in src.GetHints(ct)) { ct.ThrowIfCancellationRequested(); Add(h.RawPath, h.Source); }

        foreach (var drive in src.GetFixedDriveRoots())
        {
            ct.ThrowIfCancellationRequested();
            foreach (var rel in CommonRelative)
                Add(Path.Combine(drive, rel.Replace('\\', Path.DirectorySeparatorChar)), "일반 설치 경로");
            // 큰 드라이브 하나가 뒤쪽 드라이브의 탐색 시간을 다 쓰지 않도록 드라이브마다 따로 잰다.
            if (!SearchShallow(drive, Add, limits, Stopwatch.StartNew(), ct)) searchLimited = true;
        }
        return found.Values.ToList();
    }

    /// <returns>제한에 걸리지 않고 끝까지 찾았으면 true.</returns>
    private static bool SearchShallow(string root, Action<string?, string> add, ScanLimits limits, Stopwatch sw, CancellationToken ct)
    {
        var opts = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = false, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System };
        var queue = new Queue<(string Dir, int Depth)>();
        queue.Enqueue((root, 0));
        var seen = 0;
        while (queue.TryDequeue(out var cur))
        {
            ct.ThrowIfCancellationRequested();
            if (seen++ > limits.MaxSearchDirectories || sw.Elapsed > limits.SearchTimeBudget) return false;
            IEnumerable<string> subs;
            try { subs = Directory.EnumerateDirectories(cur.Dir, "*", opts).ToList(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            foreach (var s in subs)
            {
                var name = Path.GetFileName(s);
                // 게임 이름 목록이 아니라 폴더 구조로 찾는다. 이름에 니케가 없어도 같은 구조면 같은 지표로 검사한다.
                if (name.Contains("nikke", StringComparison.OrdinalIgnoreCase) || name.Contains("니케", StringComparison.Ordinal)
                    || Directory.Exists(Path.Combine(s, "intl_service")))
                    add(s, "제한된 폴더 탐색");
                if (cur.Depth < 4 && !SkipDirs.Contains(name)) queue.Enqueue((s, cur.Depth + 1));
            }
        }
        return true;
    }
}
