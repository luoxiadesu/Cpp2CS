using Cpp2CS.Facts;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Ir;

namespace Cpp2CS.Idioms;

internal static class GuardsPass
{
    internal static bool Guards(this IdiomState state)
    {
        var changed = false;
        foreach (var head in state.function.Blocks.ToArray())
        {
            if (state.removed.Contains(head) || head.Statements.LastOrDefault() is not Branch branch)
                continue;

            // 连续两道守卫共用同一个跳过块：if (a) { if (b) init(); }。两块合并成一个分支块，条件写成合取。
            if (CombineConjunction(state, head, branch)) { changed = true; continue; }

            var normal = head.NormalSuccessors.ToArray();
            if (normal.Length != 2 || normal[0] == normal[1])
                continue;
            for (var side = 0; side < 2; side++)
            {
                // 两臂都跳到汇合点时，先越过没有活语句的跳过臂，形成标准的元数据或类初始化守卫。
                var skipped = normal[1 - side];
                if (skipped.Predecessors.Count == 1 && !skipped.IsLandingPad && skipped.Statements.All(s => s is Nop or Jump) && skipped.NormalSuccessors.ToArray() is [var merge] && merge != head && ChainPass.Chain(normal[side], merge) is { Count: > 0 } guarded && guarded.SelectMany(b => b.Statements).OfType<Call>().ToArray() is { Length: > 0 } initializers && (initializers.All(c => state.owner.HelperOf(c)?.Kind == HelperKind.InitMetadata) || initializers is [var initializer] && state.owner.HelperOf(initializer)?.Kind is HelperKind.ClassInit or HelperKind.InitializedTypeInfo))
                {
                    var targets = side == 0 ? new List<(Block, Block)>
                    {
                        (normal[0], head),
                        (merge, skipped)
                    }

                    : [(merge, skipped), (normal[1], head)];
                    var rewritten = new Branch(branch.Address, branch.Condition, targets[0].Item1.Start, targets[1].Item1.Start);
                    if (state.Rewire(head, [], rewritten, targets, [skipped]))
                    {
                        state.Remove([skipped]);
                        changed = true;
                        break;
                    }
                }

                if (ChainPass.Chain(normal[side], normal[1 - side]) is not { Count: > 0 } chain)
                    continue;
                if (!state.Guard(head, branch, side, chain, normal[1 - side]))
                    continue;
                changed = true;
                break;
            }
        }

        return changed;
    }

    /// <summary>
    /// head 的一臂直接是另一个守卫块 inner：inner 的分支分别指向跳过块（head 的另一臂）与初始化链。
    /// 把 inner 的条件并进 head，写成 a ∧ b（或按方向取反），跳过块成为唯一的失败汇合点。
    /// 要求 inner 只从 head 进入；跳过块与初始化块在 inner 那一行上的 φ 来源必须取得到（Rewire 会搬运）。
    /// </summary>
    private static bool CombineConjunction(IdiomState state, Block head, Branch branch)
    {
        var normal = head.NormalSuccessors.ToArray();
        if (normal.Length != 2 || normal[0] == normal[1]) return false;
        for (var side = 0; side < 2; side++)
        {
            var inner = normal[side];
            var skipped = normal[1 - side];
            if (inner == skipped || state.removed.Contains(inner) || inner.Predecessors.Count != 1
                || inner.Statements.LastOrDefault() is not Branch innerBranch) continue;
            var innerNormal = inner.NormalSuccessors.ToArray();
            if (innerNormal.Length != 2 || !innerNormal.Contains(skipped)) continue;
            var initialize = innerNormal[0] == skipped ? innerNormal[1] : innerNormal[0];
            if (initialize == skipped || initialize == head) continue;
            if (ChainPass.Chain(initialize, skipped) is not { Count: > 0 } chain) continue;
            var calls = chain.SelectMany(b => b.Statements).OfType<Call>().ToArray();
            if (calls is not [var initializer] || state.owner.HelperOf(initializer)?.Kind is not (HelperKind.ClassInit or HelperKind.InitializedTypeInfo)) continue;
            // 外层条件为真即走向 inner；整条件在「外层真且内层走向初始化」时为真。
            var outer = state.defs.Expand(branch.Condition);
            var nested = state.defs.Expand(innerBranch.Condition);
            var nestedToInitialize = innerNormal.IndexOf(initialize) == 0;
            var innerCondition = nestedToInitialize ? nested : Negate(nested);
            var conjunction = side == 0 ? Conjoin(outer, innerCondition) : Conjoin(Negate(outer), innerCondition);
            var rewritten = new Branch(branch.Address, conjunction, initialize.Start, skipped.Start);
            // 两条新边都从 inner 原来那一行取 φ（head 的旧行由 Rewire 先删边时移除）。
            if (!state.Rewire(head, [], rewritten, [(initialize, inner), (skipped, inner)], [inner])) continue;
            state.Remove([inner]);
            return true;
        }
        return false;
    }

    private static Expr Conjoin(Expr left, Expr right) => Fold.Simplify(new Binary(BinOp.And, left, right, 32));

    /// <summary>条件取反：比较条件翻转比较方向，其余与 0 比较。</summary>
    private static Expr Negate(Expr condition) => Fold.Simplify(condition switch
    {
        Compare compare => compare with { Cond = Flip(compare.Cond) },
        _ => new Compare(Cond.Eq, condition, Expr.C(0, condition.Width)),
    });

    private static Cond Flip(Cond cond) => cond switch
    {
        Cond.Eq => Cond.Ne, Cond.Ne => Cond.Eq,
        Cond.Slt => Cond.Sge, Cond.Sge => Cond.Slt,
        Cond.Sle => Cond.Sgt, Cond.Sgt => Cond.Sle,
        Cond.Ult => Cond.Uge, Cond.Uge => Cond.Ult,
        Cond.Ule => Cond.Ugt, Cond.Ugt => Cond.Ule,
        _ => cond,
    };
}
