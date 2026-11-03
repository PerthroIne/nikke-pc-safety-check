using System.Text;
using System.Text.RegularExpressions;

namespace NikkeSafetyCheck.Core;

public sealed record LogScanResult
{
    public int ExecutionHits { get; init; }
    public int CorroboratingHits { get; init; }
    public int LoaderHits { get; init; }
    public int LiteralOnlyHits { get; init; }
    public string? FirstStamp { get; init; }
    public string? LastStamp { get; init; }
    public bool Truncated { get; init; }
}

/// <summary>
/// 로그를 스트리밍으로 읽어 지표를 '세기만' 한다. 원문, 컴퓨터 이름, UUID는 결과에 담지 않는다.
/// 실행 문맥은 Chromium 콘솔 로그 줄 형식과 일치할 때만 인정한다.
/// </summary>
public sealed partial class LogScanner(IocData ioc)
{
    private const int MaxLine = 1 << 20;

    [GeneratedRegex(@"^\[(?<stamp>[^\]]*):INFO:CONSOLE\(\d+\)\]\s*""(?<msg>.*?)""\s*(,\s*source:\s*(?<src>.*))?$")]
    private static partial Regex ConsoleLine();
    [GeneratedRegex(@"(?<md>\d{4})/(?<hms>\d{6})")] private static partial Regex Stamp();
    [GeneratedRegex(@"^\(\d+\)\s*$")] private static partial Regex EmptySource();

    public static Encoding DetectEncoding(ReadOnlySpan<byte> head, out int bomLength)
    {
        bomLength = 0;
        if (head.Length >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF) { bomLength = 3; return new UTF8Encoding(false); }
        if (head.Length >= 2 && head[0] == 0xFF && head[1] == 0xFE) { bomLength = 2; return Encoding.Unicode; }
        if (head.Length >= 2 && head[0] == 0xFE && head[1] == 0xFF) { bomLength = 2; return Encoding.BigEndianUnicode; }
        int odd = 0, even = 0, n = Math.Min(head.Length, 4096);
        for (var i = 0; i < n; i++) if (head[i] == 0) { if (i % 2 == 0) even++; else odd++; }
        if (n >= 8 && odd > n / 4 && even == 0) return Encoding.Unicode;
        if (n >= 8 && even > n / 4 && odd == 0) return Encoding.BigEndianUnicode;
        return new UTF8Encoding(false);
    }

    public sealed record TinygetScanResult(int RequestLines, int SuccessLines, bool Truncated);

    /// <summary>요청 기록과 다운로드 성공 기록을 구분한다. 성공은 같은 줄의 OnTaskResult와 result=0으로 판단한다.</summary>
    public TinygetScanResult ScanTinyget(string path, long maxBytes, CancellationToken ct)
    {
        int req = 0, ok = 0;
        var truncated = ReadLines(path, maxBytes, ct, line =>
        {
            if (!line.Contains(ioc.TinygetPayloadMarker, StringComparison.OrdinalIgnoreCase)) return;
            req++;
            if (line.Contains("OnTaskResult", StringComparison.Ordinal) && TinygetOk().IsMatch(line)) ok++;
        });
        return new TinygetScanResult(req, ok, truncated);
    }

    [GeneratedRegex(@"\bresult=0\b")] private static partial Regex TinygetOk();

    public LogScanResult Scan(string path, long maxBytes, CancellationToken ct)
    {
        var state = new Counter();
        var truncated = ReadLines(path, maxBytes, ct, l => Classify(l, state));
        return new LogScanResult
        {
            ExecutionHits = state.Exec, CorroboratingHits = state.Corro, LoaderHits = state.Loader,
            LiteralOnlyHits = state.Literal, FirstStamp = state.First, LastStamp = state.Last, Truncated = truncated,
        };
    }

    private static bool ReadLines(string path, long maxBytes, CancellationToken ct, Action<string> onLine)
    {
        using var fs = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.ReadWrite | FileShare.Delete,
            Options = FileOptions.SequentialScan, BufferSize = 1 << 16,
        });
        var head = new byte[4096];
        var read = fs.Read(head, 0, head.Length);
        var enc = DetectEncoding(head.AsSpan(0, read), out var bom);
        fs.Position = bom;
        using var reader = new StreamReader(fs, enc, detectEncodingFromByteOrderMarks: false, 1 << 16, leaveOpen: true);

        var buf = new char[1 << 16];
        var line = new StringBuilder();
        int n;
        var truncated = false;
        while ((n = reader.Read(buf, 0, buf.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            var start = 0;
            for (var i = 0; i < n; i++)
            {
                if (buf[i] != '\n') continue;
                line.Append(buf, start, i - start);
                onLine(line.ToString().TrimEnd('\r'));
                line.Clear();
                start = i + 1;
            }
            line.Append(buf, start, n - start);
            if (line.Length > MaxLine)
            {
                // 비정상적으로 긴 줄은 실행 문맥으로 볼 수 없다. 뒤쪽 일부만 남겨 경계에 걸린 문자열을 놓치지 않는다.
                onLine(line.ToString());
                line.Remove(0, line.Length - 512);
            }
            if (fs.Position > maxBytes) { truncated = true; break; }
        }
        if (line.Length > 0) onLine(line.ToString());
        return truncated;
    }

    private void Classify(string line, Counter c)
    {
        if (line.Length == 0) return;
        var mayMatch = ioc.LogExecutionMarkers.Concat(ioc.LogCorroboratingMarkers).Concat(ioc.LogLoaderMarkers)
            .Any(m => line.Contains(m, StringComparison.Ordinal));
        if (!mayMatch) return;
        var m = line.Length <= MaxLine ? ConsoleLine().Match(line) : Match.Empty;
        if (m.Success)
        {
            var msg = m.Groups["msg"].Value;
            if (ioc.LogExecutionMarkers.Any(x => msg.StartsWith(x, StringComparison.Ordinal)))
            {
                c.Exec++;
                var s = Stamp().Match(m.Groups["stamp"].Value);
                if (s.Success)
                {
                    var txt = $"{s.Groups["md"].Value[..2]}-{s.Groups["md"].Value[2..]} {s.Groups["hms"].Value[..2]}:{s.Groups["hms"].Value[2..4]}:{s.Groups["hms"].Value[4..]}";
                    c.First ??= txt; c.Last = txt;
                }
                return;
            }
            if (ioc.LogCorroboratingMarkers.Any(x => msg.StartsWith(x, StringComparison.Ordinal))) { c.Corro++; return; }
            if (ioc.LogLoaderMarkers.Any(x => msg.StartsWith(x, StringComparison.Ordinal)))
            {
                // 'startup already in progress'는 소스가 비어 있을 때만 주입 코드의 흔적이다.
                if (EmptySource().IsMatch(m.Groups["src"].Value) || msg.StartsWith("lua downloaded", StringComparison.Ordinal)) c.Loader++;
                return;
            }
        }
        if (ioc.LogExecutionMarkers.Any(x => line.Contains(x, StringComparison.Ordinal))) c.Literal++;
    }

    private sealed class Counter { public int Exec, Corro, Loader, Literal; public string? First, Last; }
}

public static class BinaryScanner
{
    /// <summary>파일에서 문자열을 ASCII와 UTF-16LE로 찾는다. 내용은 돌려주지 않고 일치 여부만 알린다.</summary>
    public static bool Contains(string path, string needle, CancellationToken ct)
    {
        var a = Encoding.ASCII.GetBytes(needle);
        var u = Encoding.Unicode.GetBytes(needle);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        var overlap = Math.Max(a.Length, u.Length) - 1;
        var buf = new byte[(1 << 20) + overlap];
        var keep = 0;
        int n;
        while ((n = fs.Read(buf, keep, buf.Length - keep)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            var span = buf.AsSpan(0, keep + n);
            if (span.IndexOf(a) >= 0 || span.IndexOf(u) >= 0) return true;
            keep = Math.Min(overlap, span.Length);
            span[^keep..].CopyTo(buf);
        }
        return false;
    }
}
