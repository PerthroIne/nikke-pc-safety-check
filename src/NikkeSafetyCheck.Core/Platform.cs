namespace NikkeSafetyCheck.Core;

public sealed record RegistryKeySnapshot(
    IReadOnlyDictionary<string, string> Values, IReadOnlyList<string> SubKeys);

/// <summary>
/// 경로는 항상 실제 하이브 기준(HKU\SID_Classes\...)으로 쓴다. HKCU/HKCR 병합 보기는 사용하지 않는다.
/// 쓰기는 사용자 하이브의 빈 키 삭제 하나뿐이며 구현체는 HKLM 경로를 거부해야 한다.
/// </summary>
public interface IRegistryStore
{
    /// <returns>키가 없으면 null. 접근 거부와 하이브 미로드는 예외.</returns>
    RegistryKeySnapshot? Read(string path);
    bool IsHiveLoaded(string hiveName);
    IReadOnlyList<string> ListSubKeys(string path);
    void DeleteEmptyKey(string path);
}

public enum SignatureState { Unknown, Unsigned, Invalid, Valid }
public interface IFileSignatureChecker { SignatureState Check(string path); }
public interface IFileIdentityProvider { string? GetFileId(string path); }
public interface IFileProtector { void ProtectForQuarantine(string path); void RestrictToCurrentUser(string directory); }

public sealed record LoadedModuleHit(int Pid, string ProcessPath, string ModulePath);
public sealed record RunningProcess(int Pid, string Name, string? Path);
public sealed record ModuleInspection(IReadOnlyList<LoadedModuleHit> Hits, int InaccessibleProcesses);
public interface IProcessInspector
{
    IReadOnlyList<RunningProcess> FindByNames(IEnumerable<string> names);
    ModuleInspection FindLoadedModule(string moduleFileName, CancellationToken ct);
}

public interface INetworkInspector
{
    /// <summary>현재 TCP 연결 중 대상 IP와 일치하는 것을 돌려준다. 외부로 아무것도 보내지 않는다.</summary>
    IReadOnlyList<string> FindConnections(IEnumerable<string> ips);
    /// <summary>로컬 DNS 캐시 조회. 조회할 수 없으면 null.</summary>
    IReadOnlyList<string>? FindDnsCacheEntries(IEnumerable<string> domains);
}

public sealed record InstallHint(string RawPath, string Source);
public interface IInstallHintSource
{
    IEnumerable<InstallHint> GetHints(CancellationToken ct);
    IEnumerable<string> GetFixedDriveRoots();
}

public sealed record PlatformServices(
    IRegistryStore Registry, IFileSignatureChecker Signatures, IFileIdentityProvider FileIds,
    IProcessInspector Processes, INetworkInspector Network, IInstallHintSource InstallHints);
