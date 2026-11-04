using System.Text.RegularExpressions;

namespace NikkeSafetyCheck.Core;

public sealed record BrowserRoot(string Browser, string UserDataDir, bool IsPrimary);

public static partial class PathSafety
{
    public const string HelperDirName = "PlatformExperienceHelper";
    public const string DllName = "platform_experience_helper.dll";

    [GeneratedRegex(@"^[0-9a-fA-F]{64}$")] public static partial Regex Hex64();

    public static IReadOnlyList<BrowserRoot> BrowserRoots(TargetUser t) =>
    [
        new("Chrome", Path.Combine(t.LocalAppData, "Google", "Chrome", "User Data"), true),
        new("Edge", Path.Combine(t.LocalAppData, "Microsoft", "Edge", "User Data"), false),
        new("Brave", Path.Combine(t.LocalAppData, "BraveSoftware", "Brave-Browser", "User Data"), false),
        new("Vivaldi", Path.Combine(t.LocalAppData, "Vivaldi", "User Data"), false),
        new("Opera", Path.Combine(t.RoamingAppData, "Opera Software", "Opera Stable"), false),
    ];

    public static readonly string[] NikkeDataNames = ["nikke_launcher", "nikke_launcher_hmt"];

    public static string LauncherCacheDir(TargetUser t) => Path.Combine(t.RoamingAppData, "nikke_launcher", "tbs_cache");

    /// <summary>자동 정리가 허용되는 니케 런처 전용 캐시 위치(일반판과 HMT판).</summary>
    public static IReadOnlyList<string> NikkeCacheDirs(TargetUser t) =>
        NikkeDataNames.Select(n => Path.Combine(t.RoamingAppData, n, "tbs_cache")).ToList();

    /// <summary>같은 구조의 다른 런처 저장소를 찾는다. 읽기 전용 검사에만 쓰고 조치 대상으로 삼지 않는다.</summary>
    public static IReadOnlyList<string> DiscoverOtherCacheDirs(TargetUser t)
    {
        var res = new List<string>();
        var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var root in new[] { t.RoamingAppData, t.LocalAppData })
        {
            if (!Directory.Exists(root)) continue;
            foreach (var d in Directory.EnumerateDirectories(root, "*", opts).Take(5000))
            {
                if (NikkeDataNames.Contains(Path.GetFileName(d), StringComparer.OrdinalIgnoreCase)) continue;
                var cache = Path.Combine(d, "tbs_cache");
                if (Directory.Exists(cache) && !IsReparse(cache)) res.Add(cache);
            }
        }
        return res;
    }

    /// <summary>UNC, 장치 경로, 상위 폴더 이동, 대체 데이터 스트림 표기를 거른다.</summary>
    public static bool IsPlainLocalPath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Contains('\0')) return false;
        if (raw.StartsWith(@"\\", StringComparison.Ordinal) || raw.StartsWith("//", StringComparison.Ordinal)) return false;
        var parts = raw.Split('\\', '/');
        if (parts.Any(p => p is ".." or ".")) return false;
        var colon = raw.IndexOf(':');
        if (colon >= 0 && (colon != 1 || raw.IndexOf(':', colon + 1) >= 0)) return false;
        return Path.IsPathFullyQualified(raw);
    }

    public static bool IsUnder(string path, string root)
    {
        var p = Path.TrimEndingDirectorySeparator(path);
        var r = Path.TrimEndingDirectorySeparator(root);
        return p.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>root 아래부터 path까지 모든 구성요소에 reparse point(심볼릭 링크, 정션 등)가 없는지 확인한다.</summary>
    public static bool HasReparseInChain(string root, string path)
    {
        if (!IsUnder(path, root)) return true;
        var rel = Path.GetRelativePath(root, path);
        var cur = Path.TrimEndingDirectorySeparator(root);
        foreach (var seg in rel.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            cur = Path.Combine(cur, seg);
            if (IsReparse(cur)) return true;
        }
        return false;
    }

    public static bool IsReparse(string path)
    {
        FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
        if (!info.Exists) return false;
        return info.Attributes.HasFlag(FileAttributes.ReparsePoint) || info.LinkTarget is not null;
    }

    /// <summary>조치 대상 DLL의 정확한 구조: 브라우저 루트\PlatformExperienceHelper\64자리\platform_experience_helper.dll</summary>
    public static bool TryMatchDllLayout(TargetUser t, string path, out BrowserRoot? root)
    {
        root = null;
        if (!IsPlainLocalPath(path)) return false;
        if (!Path.GetFileName(path).Equals(DllName, StringComparison.OrdinalIgnoreCase)) return false;
        var hashDir = Path.GetDirectoryName(path);
        var helper = hashDir is null ? null : Path.GetDirectoryName(hashDir);
        var userData = helper is null ? null : Path.GetDirectoryName(helper);
        if (hashDir is null || helper is null || userData is null) return false;
        if (!Hex64().IsMatch(Path.GetFileName(hashDir))) return false;
        if (!Path.GetFileName(helper).Equals(HelperDirName, StringComparison.OrdinalIgnoreCase)) return false;
        root = BrowserRoots(t).FirstOrDefault(b => string.Equals(
            Path.TrimEndingDirectorySeparator(b.UserDataDir), Path.TrimEndingDirectorySeparator(userData), StringComparison.OrdinalIgnoreCase));
        return root is not null;
    }

    /// <summary>검증된 런처 실행 파일인지 판단한다. 관리자 보조 프로세스도 이 함수만으로 입력을 받아들인다.</summary>
    public static bool IsValidLauncherExecutable(string path, out string reason)
    {
        reason = "";
        if (!IsPlainLocalPath(path)) { reason = "허용되지 않는 경로 형식"; return false; }
        if (!Path.GetFileName(path).Equals("nikke_launcher.exe", StringComparison.OrdinalIgnoreCase)) { reason = "런처 파일 이름이 아님"; return false; }
        if (!File.Exists(path)) { reason = "파일 없음"; return false; }
        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(Path.Combine(dir, "intl_service")) && !Directory.Exists(Path.Combine(dir, "log", "tinyget")))
        { reason = "런처 폴더 구조가 아님"; return false; }
        var cur = path;
        while (cur is not null && Path.GetPathRoot(cur) != cur)
        {
            if (IsReparse(cur)) { reason = "링크가 포함된 경로"; return false; }
            cur = Path.GetDirectoryName(cur);
        }
        return true;
    }
}
