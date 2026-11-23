using Cpp2CS.Ir;

namespace Cpp2CS.Idioms;

/// <summary>类初始化低位检查与零扩展重读；其他位仍属于原生布局。</summary>
internal static class ClassInitializationFlags
{
    /// <summary>
    /// 条件是否为对 load 的单个位测试（and 掩码后与 0 比较）。掩码可以是 2 的任意次幂：
    /// 位域里同一字节上的不同标志位各有一位，测试哪一位由编译器按运行时的位域布局决定。
    /// 条件可以是多个判断的合取，位测试出现在其中一个合取项里。
    /// </summary>
    internal static bool IsBitTest(Expr condition, Load load)
    {
        if (IsDirectBitTest(condition, load)) return true;
        return condition is Binary { Op: BinOp.And } binary
            && (IsBitTest(binary.Left, load) || IsBitTest(binary.Right, load));
    }

    /// <summary>该读取的每处使用都被同一掩码覆盖，其他位不参与条件。</summary>
    internal static bool UsesOnlyMask(Expr condition, Load load, ulong expectedMask)
    {
        var masked = ExprMap.Map(condition, e => MaskedLoad(e, load, out var bits) && bits == expectedMask ? Expr.C(0, e.Width) : null);
        return !ExprMap.Walk(masked).Contains(load);
    }

    private static bool IsDirectBitTest(Expr condition, Load load)
    {
        if (load.Width is not (8 or 16) || condition is not Compare
            {
                Cond: Cond.Eq or Cond.Ne, Right: Const { Value: 0 },
                Left: Binary { Op: BinOp.And } mask
            }) return false;
        return MaskedLoad(mask, load, out var bits) && bits != 0 && (bits & (bits - 1)) == 0;
    }

    private static bool MaskedLoad(Expr value, Load load, out ulong bits)
    {
        bits = 0;
        if (value is not Binary { Op: BinOp.And } mask) return false;
        Expr operand;
        if (mask.Right is Const right) { operand = mask.Left; bits = right.Value; }
        else if (mask.Left is Const left) { operand = mask.Right; bits = left.Value; }
        else return false;
        Expr Low(Expr part) => part switch
        {
            Ir.Convert c => Low(c.Operand),
            Extract { Low: 0 } e => Low(e.Operand),
            _ => part,
        };
        return Low(operand) == load;
    }

    internal static bool IsReload(Expr value, Load load) => value == load
        || value is Ir.Convert { Kind: ConvKind.ZeroExtend } c && IsReload(c.Operand, load);
}
