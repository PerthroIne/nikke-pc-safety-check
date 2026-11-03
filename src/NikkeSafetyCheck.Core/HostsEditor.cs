using System.Text;

namespace NikkeSafetyCheck.Core;

/// <summary>
/// hosts 내용 변환만 담당하는 순수 함수. 인코딩과 줄바꿈을 보존하고 앱 소유 구간만 추가·제거한다.
/// </summary>
public static class HostsEditor
{
    public const string BeginMarker = "# >>> NikkeSafetyCheck managed block (added by NIKKE PC safety check helper) >>>";
    public const string EndMarker = "# <<< NikkeSafetyCheck managed block <<<";

    private static (Encoding Enc, byte[] Bom) Detect(byte[] data)
    {
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) return (new UTF8Encoding(false), [0xEF, 0xBB, 0xBF]);
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) return (Encoding.Unicode, [0xFF, 0xFE]);
        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF) return (Encoding.BigEndianUnicode, [0xFE, 0xFF]);
        // BOM이 없으면 ANSI일 수 있다. Latin-1은 바이트가 그대로 왕복되므로 한글 주석도 손상되지 않는다.
        return (Encoding.Latin1, []);
    }

    private static string Decode(byte[] data, Encoding enc, byte[] bom) => enc.GetString(data, bom.Length, data.Length - bom.Length);

    private static byte[] Encode(string text, Encoding enc, byte[] bom)
    {
        var body = enc.GetBytes(text);
        var all = new byte[bom.Length + body.Length];
        bom.CopyTo(all, 0);
        body.CopyTo(all, bom.Length);
        return all;
    }

    public static bool HasBlock(byte[] data)
    {
        var (enc, bom) = Detect(data);
        return Decode(data, enc, bom).Contains(BeginMarker, StringComparison.Ordinal);
    }

    public static byte[] Apply(byte[] original, IEnumerable<string> domains)
    {
        var (enc, bom) = Detect(original);
        var cleaned = RemoveBlock(Decode(original, enc, bom));
        var nl = cleaned.Contains("\r\n", StringComparison.Ordinal) || !cleaned.Contains('\n') ? "\r\n" : "\n";
        var sb = new StringBuilder(cleaned);
        if (sb.Length > 0 && sb[^1] != '\n') sb.Append(nl);
        sb.Append(BeginMarker).Append(nl);
        foreach (var d in domains) sb.Append("0.0.0.0 ").Append(d).Append(nl);
        sb.Append(EndMarker).Append(nl);
        return Encode(sb.ToString(), enc, bom);
    }

    public static byte[] Remove(byte[] original)
    {
        var (enc, bom) = Detect(original);
        return Encode(RemoveBlock(Decode(original, enc, bom)), enc, bom);
    }

    /// <summary>앱이 만든 줄만 지운다. 구간 안에 사용자가 추가한 줄은 구간 밖으로 살려 둔다. 표식이 깨졌으면 건드리지 않는다.</summary>
    private static string RemoveBlock(string text)
    {
        var begin = text.IndexOf(BeginMarker, StringComparison.Ordinal);
        var end = text.IndexOf(EndMarker, StringComparison.Ordinal);
        if (begin < 0 && end < 0) return text;
        if (begin < 0 || end < begin) throw new InvalidDataException("hosts의 관리 구간 표식이 손상되어 자동으로 수정하지 않습니다.");
        if (text.IndexOf(BeginMarker, begin + 1, StringComparison.Ordinal) >= 0) throw new InvalidDataException("hosts에 관리 구간이 여러 개 있어 자동으로 수정하지 않습니다.");
        var afterEnd = end + EndMarker.Length;
        if (afterEnd < text.Length && text[afterEnd] == '\r') afterEnd++;
        if (afterEnd < text.Length && text[afterEnd] == '\n') afterEnd++;
        var inner = text[(begin + BeginMarker.Length)..end];
        var kept = inner.Split('\n').Select(l => l.TrimEnd('\r'))
            .Where(l => l.Trim().Length > 0 && !IsOwnedLine(l)).ToList();
        var nl = text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var keptText = kept.Count == 0 ? "" : string.Join(nl, kept) + nl;
        return text[..begin] + keptText + text[afterEnd..];
    }

    private static bool IsOwnedLine(string line)
    {
        var p = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return p.Length == 2 && p[0] == "0.0.0.0" && p[1].Contains("insightjs.", StringComparison.OrdinalIgnoreCase);
    }
}
