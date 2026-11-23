using System.Collections.Concurrent;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Facts;

public sealed partial class RuntimeHelpers
{
    private ILookup<ulong, ExceptionFacts.ThrowSite> wrapperThrows = Array.Empty<ExceptionFacts.ThrowSite>().ToLookup(s => s.Entry);
    private readonly ConcurrentDictionary<ulong, bool> wrapperRaises = new();

    private bool WrapperRaiseBody(ulong address) => wrapperRaises.GetOrAdd(address, entry =>
    {
        var result = false;
        if (map.At(entry) is { Region: CodeRegion.Runtime, ExceptionRegions.Length: 0 } function && function.Start == entry
            && wrapperThrows[entry].ToArray() is [var site] && site.Site + 4 == function.End)
        {
            var machine = new Arm64Machine(map);
            var statements = new List<Stmt>();
            for (var pc = function.Start; pc < function.End; pc += 4) machine.Lift(pc, statements);
            result = ForwardsExceptionObject(statements, site.Site);
        }
        return result;
    });

    /// <summary>直线包装体把入口 x0 写入抛出载荷；调用后仅保留 AAPCS64 的非易失寄存器来源。</summary>
    internal static bool ForwardsExceptionObject(IReadOnlyList<Stmt> statements, ulong throwSite)
    {
        var origins = new Dictionary<Storage, int> { [Storage.Gpr(0)] = 1 };
        var next = 1;
        var payload = 0;
        int Origin(Expr value) => Fold.Simplify(value) is Read { Width: 64 } read ? origins.GetValueOrDefault(read.Storage) : 0;
        foreach (var statement in statements)
            switch (statement)
            {
                case Assign assign:
                    origins[assign.Target] = Origin(assign.Value);
                    break;
                case Store store:
                    // 载荷写入之后的任何其他写入都使证明失效，不能猜测别名。
                    payload = store.Value.Width == 64 && Origin(store.Value) == 1 && Origin(store.Target) is > 1 and var target ? target : 0;
                    break;
                case Call call when call.Address == throwSite:
                    return call.Kind is CallKind.Direct or CallKind.Tail && payload > 1 && origins.GetValueOrDefault(Storage.Gpr(0)) == payload;
                case Call { Kind: CallKind.Direct }:
                    payload = 0;
                    foreach (var storage in origins.Keys.Where(s => s.Bank != Bank.Gpr || s.Index is < 19 or > 29).ToArray()) origins.Remove(storage);
                    origins[Storage.Gpr(0)] = ++next;
                    break;
                default:
                    return false;
            }
        return false;
    }
}
