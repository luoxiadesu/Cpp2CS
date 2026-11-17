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
        // 类布局守卫可以是两个字段的合取：未初始化（size_inited 为 0）且没有静态构造在跑（cctor_finished 为 0）。
        // 其余情况只有一个守卫字段。
        if (loads.Count is not (1 or 2))
            return false;
        var load = loads[0];
        // 守卫字段一起代入：全 0（都不待初始化）时走跳过一侧；待初始化的字段置位时走初始化一侧。
        // 「置位」取该读取宽度内的全 1：位测试只关心对应位非零，与具体掩码等价。
        Expr Assign(ulong[] values) =>
            Fold.Simplify(ExprMap.Map(condition, e => e is Load hit && loads.IndexOf(hit) is var index and >= 0
                ? Expr.C(values[index], hit.Width) : null));
        bool Decides(ulong enter, ulong skip)
        {
            if (enter != 0 || skip == 0) return false;
            // 全 0 走跳过一侧；至少有一个字段的置位组合走初始化一侧（合取条件里它是必需的那个字段）。
            var initial = DirectionPass.Direction(Assign(new ulong[loads.Count]), e => e);
            if (initial is null) return false;
            var triggering = 0;
            for (var i = 0; i < loads.Count; i++)
            {
                var values = new ulong[loads.Count];
                values[i] = ulong.MaxValue;
                if (DirectionPass.Direction(Assign(values), e => e) is not { } direction) return false;
                if (direction != initial) triggering++;
            }
            return triggering == 1;
        }
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
            HelperKind.ClassInit => (OpKind.RunClassConstructor, Template.ClassConstructorGuard, 0UL, 1UL, (int[])[RuntimeLayout.ClassCctorFinishedOrNoCctor], 32, false),
            // 类布局守卫：位测试可以落在 bitflags1 或 bitflags2；两字段合取时另一个字段是 cctor_finished。
            HelperKind.InitializedTypeInfo => (OpKind.InitClass, Template.InitClassGuard, 0UL, 1UL,
                (int[])[RuntimeLayout.ClassBitflags1, RuntimeLayout.ClassBitflags2, RuntimeLayout.ClassCctorFinishedOrNoCctor], 8, true),
            HelperKind.InitMethodRgctx => (OpKind.InitMethodRgctx, Template.MethodRgctxGuard, 0UL, 0x1000UL, (int[])[RuntimeLayout.MethodRgctxData], 64, true),
            _ => (default, default, 0UL, 0UL, (int[])[], 0, false),
        };
        var offset = offsets.FirstOrDefault(o => load.Address == Field(o), -1);
        if (width == 0 || offset < 0 || !Decides(enter, skip))
            return false;
        if (kind == OpKind.InitClass)
        {
            // 每个 load 都必须是对应字段上的位测试或 32 位的 cctor 判断；位测试至少有一个。
            var bits = 0;
            foreach (var candidate in loads)
            {
                if (candidate.Width == 32 && candidate.Address == Field(RuntimeLayout.ClassCctorFinishedOrNoCctor)) continue;
                if (!ClassInitializationFlags.IsBitTest(condition, candidate)) return false;
                bits++;
            }
            if (bits == 0) return false;
        }
        else if (loads.Count != 1 || load.Width != width)
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
