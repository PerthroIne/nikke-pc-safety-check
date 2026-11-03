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
        @"SteamLibrary\NIKKE", @"Level Infinite\NIKKE", @"Program Files\Level Infinite\NIKKE",
    ];

    [GeneratedRegex(@"^\s*""?(?<p>[^""]+?\.exe)""?(\s|,|$)", RegexOptions.IgnoreCase)] private static partial Regex ExeInCommand();

    /// <summary>명령 형식 문자열에서 앞쪽 실행 파일 경로만 잘라 낸다. 나머지 인자는 버린다.</summary>
    public static string ExtractPath(string raw)
    {
        var s = raw.Trim();
        var m = ExeInCommand().Match(s);
        if (m.Success) return m.Groups["p"].Value.Trim();
        return s.Trim('"').Split(',')[0].Trim();
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

    public static IReadOnlyList<LauncherInstall> Locate(IInstallHintSource src, IEnumerable<string> extraFolders, ScanLimits limits, CancellationToken ct)
    {
        var found = new Dictionary<string, LauncherInstall>(StringComparer.OrdinalIgnoreCase);
        void Add(string? raw, string source)
        {
            var d = ValidateLauncherDir(raw);
            if (d is null || found.ContainsKey(d)) return;
            var exe = Path.Combine(d, "nikke_launcher.exe");
            found[d] = new LauncherInstall(d, source, File.Exists(exe) ? exe : null);
        }
        foreach (var f in extraFolders) Add(f, "사용자가 선택한 폴더");
        foreach (var h in src.GetHints(ct)) { ct.ThrowIfCancellationRequested(); Add(h.RawPath, h.Source); }

        var sw = Stopwatch.StartNew();
        foreach (var drive in src.GetFixedDriveRoots())
        {
            ct.ThrowIfCancellationRequested();
            foreach (var rel in CommonRelative)
                Add(Path.Combine(drive, rel.Replace('\\', Path.DirectorySeparatorChar)), "일반 설치 경로");
            SearchShallow(drive, Add, limits, sw, ct);
        }
        return found.Values.ToList();
    }

    private static void SearchShallow(string root, Action<string?, string> add, ScanLimits limits, Stopwatch sw, CancellationToken ct)
    {
        var opts = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = false, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System };
        var queue = new Queue<(string Dir, int Depth)>();
        queue.Enqueue((root, 0));
        var seen = 0;
        while (queue.TryDequeue(out var cur))
        {
            ct.ThrowIfCancellationRequested();
            if (seen++ > limits.MaxSearchDirectories || sw.Elapsed > limits.SearchTimeBudget) return;
            IEnumerable<string> subs;
            try { subs = Directory.EnumerateDirectories(cur.Dir, "*", opts).ToList(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            foreach (var s in subs)
            {
                var name = Path.GetFileName(s);
                if (name.Contains("nikke", StringComparison.OrdinalIgnoreCase) || name.Contains("니케", StringComparison.Ordinal))
                    add(s, "제한된 폴더 탐색");
                if (cur.Depth < 2 && !name.Equals("Windows", StringComparison.OrdinalIgnoreCase)) queue.Enqueue((s, cur.Depth + 1));
            }
        }
    }
}
