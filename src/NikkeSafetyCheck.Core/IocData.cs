using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace NikkeSafetyCheck.Core;

public sealed record KnownHash(string Sha256, string Source, string Note);

/// <summary>
/// 선언적 IOC 데이터. 명령, 스크립트, 삭제 경로를 담을 수 없도록 스키마를 고정하고 모르는 필드는 거부한다.
/// </summary>
public sealed partial record IocData(
    int SchemaVersion, string RuleVersion, string ObservedAt, string ReviewAfter,
    Dictionary<string, string> Sources, string ComClsid,
    string[] LogExecutionMarkers, string[] LogCorroboratingMarkers, string[] LogLoaderMarkers,
    string TinygetPayloadMarker, string AgentStateStrong, string AgentStateWeak,
    string[] LoaderCacheMarkers, string[] AgentTempFilePrefixes,
    KnownHash[] KnownDllSha256, string[] BlockDomains, string[] BlockIps, string[] WatchOnlyIps)
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static IocData LoadEmbedded()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("iocs.json")
            ?? throw new InvalidDataException("내장 IOC 데이터를 찾을 수 없습니다.");
        return Parse(s);
    }

    public static IocData Parse(Stream json)
    {
        var d = JsonSerializer.Deserialize<IocData>(json, Options) ?? throw new InvalidDataException("IOC 데이터가 비어 있습니다.");
        d.Validate();
        return d;
    }

    public static IocData Parse(string json)
    {
        using var ms = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(json));
        return Parse(ms);
    }

    private void Validate()
    {
        if (SchemaVersion != 1) throw new InvalidDataException("지원하지 않는 IOC 스키마입니다.");
        if (!ClsidRegex().IsMatch(ComClsid)) throw new InvalidDataException("CLSID 형식 오류");
        foreach (var h in KnownDllSha256)
            if (!Sha256Regex().IsMatch(h.Sha256) || !Sources.ContainsKey(h.Source)) throw new InvalidDataException("해시 항목 오류");
        foreach (var d in BlockDomains)
            if (!DomainRegex().IsMatch(d)) throw new InvalidDataException("도메인 형식 오류");
        foreach (var ip in BlockIps.Concat(WatchOnlyIps))
            if (!IPAddress.TryParse(ip, out var parsed) || IPAddress.IsLoopback(parsed)) throw new InvalidDataException("IP 형식 오류");
        foreach (var p in AgentTempFilePrefixes)
            if (p.IndexOfAny(['\\', '/', ':', '*', '?']) >= 0) throw new InvalidDataException("파일 접두사에는 경로를 넣을 수 없습니다.");
        foreach (var u in Sources.Values)
            if (!u.StartsWith("https://", StringComparison.Ordinal)) throw new InvalidDataException("출처 URL 오류");
    }

    public bool IsKnownDll(string sha256) => KnownDllSha256.Any(h => h.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase));
    public string Source(string key) => Sources.TryGetValue(key, out var u) ? u : "";

    [GeneratedRegex(@"^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$")] private static partial Regex ClsidRegex();
    [GeneratedRegex(@"^[0-9a-f]{64}$")] public static partial Regex Sha256Regex();
    [GeneratedRegex(@"^([a-z0-9-]+\.)+[a-z]{2,}$")] private static partial Regex DomainRegex();
}
