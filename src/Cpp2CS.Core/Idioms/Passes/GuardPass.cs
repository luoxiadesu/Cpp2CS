using Cpp2CS.Facts;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Ir;

namespace Cpp2CS.Idioms;

internal static class GuardPass
{
    internal static bool Guard(this IdiomState state, Block head, Branch branch, int side, List<Block> chain, Block merge)
    {
        var statements = chain.SelectMany(b => b.Statements).ToList();
        var calls = statements.OfType<Call>().ToList();
        if (calls.Count == 0)
            return false;
        var helpers = calls.Select(c => state.owner.HelperOf(c)?.Kind).ToList();
        var condition = state.defs.Expand(branch.Condition);
        var loads = TopLoadsPass.TopLoads(condition).Distinct().ToList();
        // 静态构造守卫可由 has_cctor 与 cctor_finished 两个字段合取。
        if (loads.Count is not (1 or 2))
            return false;
        var load = loads[0];
        Expr Assign(ulong[] values) =>
            Fold.Simplify(ExprMap.Map(condition, e => e is Load hit && loads.IndexOf(hit) is var index and >= 0
                ? Expr.C(values[index], hit.Width) : null));
        bool Decides(ulong enter, ulong skip) => loads.Count == 1
            && DirectionPass.Direction(Assign([enter]), e => e) == side
            && DirectionPass.Direction(Assign([skip]), e => e) == 1 - side;
        // s_Il2CppMethodInitialized：读 1 字节守卫，区域内只有 InitMetadata(槽位)、置位写入与纯定义。
        // 纯定义包括跨调用保存恢复的寄存器（如按低位保存的实参），只经合并点的 φ 流出，由 Merge 检查两侧相同。
        if (helpers.All(k => k == HelperKind.InitMetadata))
        {
            if (load is not { Width: 8, Address: Const guard } || !state.owner.guardSections.Any(s => s.Contains(guard.Value)))
                return false;
            var slots = new List<ulong>();
            var sets = 0;
            foreach (var stmt in statements)
            {
                switch (stmt)
                {
                    case Call call when state.MetadataSlots(call.Arguments.FirstOrDefault() ?? Expr.C(0, 64)) is { } group:
                        slots.AddRange(group.Select(s => s.Slot));
                        break;
                    case Store { Target: Const target, Value: Const { Value: 1, Width: 8 } } when target.Value == guard.Value:
                        sets++;
                        break;
                    case Define { Value: Const or Symbol } or Nop or Jump:
                        break;
                    case Define define when !ExprMap.Walk(define.Value).Any(e => e is Load or Intrinsic or Unknown):
                        break;
                    default:
                        return false;
                }
            }

            if (sets == 0 || !Decides(0, 1) || state.Merge(head, chain, merge, null, null) is not { } overrides)
                return false;
            if (state.recording)
                state.Record(Template.MetadataInitGuard, head, state.Start(head), new() { ["merge"] = merge.Start }, new() { ["guard"] = guard.Value, ["slots"] = slots.ToArray(), ["helpers"] = calls.Select(c => ((Const)c.Target).Value).Distinct().ToArray(), });
            CollapsePass.Collapse(head, merge, head, [], overrides, branch.Address);
            state.Remove(chain);
            state.initializedGuards.Add((head, guard.Value));
            state.Result.GuardSlots[guard.Value] = [.. state.Result.GuardSlots.GetValueOrDefault(guard.Value, []).Union(slots).Order()];
            state.Result.MetadataGuardBranches.Add(branch.Address);
            state.Result.InitializedSlots.UnionWith(slots);
            state.Result.Hit(Template.MetadataInitGuard);
            return true;
        }

        if (calls.Count != 1 || calls[0].Arguments.Length == 0)
            return false;
        var helperCall = calls[0];
        var argument = helperCall.Arguments[0];
        var regionDefined = DefinedPass.Defined(chain);
        if (ExprMap.Walk(argument).OfType<Use>().Any(u => regionDefined.Contains(u.Variable)))
            return false;
        var subject = state.defs.Expand(argument);
        Expr Field(int offset) => Fold.Simplify(new Binary(BinOp.Add, subject, Expr.C((ulong)offset, 64), 64));
        var (kind, template, enter, skip, offsets, width, returnsArgument) = helpers[0] switch
        {
            HelperKind.ClassInit => (OpKind.RunClassConstructor, Template.ClassConstructorGuard, 0UL, 1UL,
                (int[])[RuntimeLayout.ClassCctorFinishedOrNoCctor, RuntimeLayout.ClassBitflags2, RuntimeLayout.ClassBitflags1], 32, false),
            HelperKind.InitializedTypeInfo => (OpKind.InitClass, Template.InitClassGuard, 0UL, ulong.MaxValue,
                (int[])[RuntimeLayout.ClassBitflags1], 8, true),
            HelperKind.InitMethodRgctx => (OpKind.InitMethodRgctx, Template.MethodRgctxGuard, 0UL, 0x1000UL, (int[])[RuntimeLayout.MethodRgctxData], 64, true),
            _ => (default, default, 0UL, 0UL, (int[])[], 0, false),
        };
        var offset = offsets.FirstOrDefault(o => load.Address == Field(o), -1);
        if (width == 0 || offset < 0)
            return false;
        if (kind == OpKind.RunClassConstructor && loads.Count == 2)
        {
            var flags = loads.SingleOrDefault(l => l.Width == 8 && l.Address == Field(RuntimeLayout.ClassBitflags2)
                || l.Width == 16 && l.Address == Field(RuntimeLayout.ClassBitflags1));
            var finished = loads.SingleOrDefault(l => l.Width == 32 && l.Address == Field(RuntimeLayout.ClassCctorFinishedOrNoCctor));
            var hasMask = (ulong)RuntimeLayout.ClassHasCctorMask << (flags?.Width == 16 ? 8 : 0);
            if (flags is null || finished is null || !ClassInitializationFlags.UsesOnlyMask(condition, flags, hasMask)) return false;
            foreach (var hasConstructor in new[] { false, true })
                foreach (var done in new[] { false, true })
                {
                    var values = loads.Select(l => l == flags ? (hasConstructor ? hasMask : 0) : (done ? 1UL : 0)).ToArray();
                    if (DirectionPass.Direction(Assign(values), e => e) != (hasConstructor && !done ? side : 1 - side)) return false;
                }
        }
        else if (!Decides(enter, skip) || (kind == OpKind.InitClass
            ? !ClassInitializationFlags.IsBitTest(condition, load)
            : load.Width != width || offset != offsets[0]))
            return false;
        // 区域内除 helper 调用外只允许纯定义：常量、符号、对守卫字段的重新读取（初始化之后的值）
        if (!statements.All(s => s is Nop or Jump || ReferenceEquals(s, helperCall) || s is Define { Value: Const or Symbol } || s is Define d && loads.Any(l => ClassInitializationFlags.IsReload(state.defs.Expand(d.Value), l))))
            return false;
        var result = returnsArgument && helperCall.Defines.Length > 0 ? helperCall.Defines[0] : null;
        if (result is not null && statements.Any(s => ExprMap.Operands(s).SelectMany(ExprMap.Walk).OfType<Use>().Any(u => u.Variable == result)))
            return false;
        var reload = new List<Stmt>();
        var reloaded = new Dictionary<Expr, Variable>();
        Variable Reload(Expr value)
        {
            if (reloaded.TryGetValue(value, out var previous))
                return previous;
            var variable = state.Fresh();
            // 条件里的每个守卫读取都换成初始化之后的重新读取（同一字段、同一宽度）。
            var source = ExprMap.Map(value, e => loads.FirstOrDefault(l => l == e) is { } hit
                ? new Load(Fold.Simplify(new Binary(BinOp.Add, argument, Expr.C((ulong)OffsetOf(hit), 64), 64)), hit.Width)
                : null);
            reload.Add(new Define(helperCall.Address, variable, source));
            reloaded[value] = variable;
            return variable;
        }
        int OffsetOf(Load candidate) => offsets.FirstOrDefault(o => candidate.Address == Field(o), offset);

        if (state.Merge(head, chain, merge, result is null ? null : subject, v => state.defs.Expand(new Use(v, 64)) is var value && loads.Any(l => ClassInitializationFlags.IsReload(value, l)) ? Reload(value) : null) is not { } merged)
            return false;
        var op = new Call(helperCall.Address, CallKind.Direct, helperCall.Target)
        {
            Op = new RuntimeOp(kind, subject is Symbol { Kind: SymbolKind.Class } c ? c.Value : null),
            Arguments = [argument],
        };
        var at = state.recording ? state.Start(head, argument) : default;
        if (state.recording && state.Location(subject, head, at) is { } where)
            state.Record(template, head, at, new() { ["merge"] = merge.Start }, new() { ["subject"] = where, ["helper"] = ((Const)helperCall.Target).Value });
        CollapsePass.Collapse(head, merge, head, [op, .. reload], merged, branch.Address);
        state.Remove(chain);
        state.Result.Hit(template);
        return true;
    }

}
