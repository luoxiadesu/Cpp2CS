using Cpp2CS.Ir;
using Cpp2CS.Recovery.Runtime;
using Cpp2CS.Recovery.Typing;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.Recovery.Effects;

/// <summary>机器语句在托管语义下的效果；地址与类型事实由 TypeOracle 提供。</summary>
internal sealed class MachineEffects(ValueModel values, TypeOracle oracle)
{
    /// <summary>与 nonNull 无关的部分（位置、根、类别）；同一读取在判空吸收里会被反复求值，位置查询不便宜。</summary>
    private readonly Dictionary<ReadSym, (Location? Location, Sym Root, MemoryKind Kind)> readKinds = new(ReferenceEqualityComparer.Instance);

    private (Location? Location, Sym Root, MemoryKind Kind) Classify(ReadSym read)
    {
        if (readKinds.TryGetValue(read, out var known)) return known;
        var location = oracle.Locate(read.Address, read.Width);
        var (root, offset, index, _) = oracle.Decompose(read.Address);
        root = SymTable.Resolve(root);
        var metadata = root is ResultSym { Site: Call { Op.Kind: OpKind.InterfaceInvokeData or OpKind.ResolveGenericVirtual } }
            || oracle.ClassOwner(root) is not null;
        var header = location is null && offset == 0 && index is null && read.Width == 64
            && oracle.TypeOf(root) is { } type && ManagedTypes.IsReferenceType(type);
        // 多维数组的 bounds 指针在对象里，和长度一样只经对象读取。
        var bounds = location is null && offset == Facts.RuntimeLayout.ArrayBounds && index is null && read.Width == 64
            && oracle.TypeOf(root) is ArrayRef { IsVector: false };
        // 维长与下界经 bounds 指针读取，按所属数组判空。
        if (location is { Kind: LocationKind.Dimension or LocationKind.LowerBound, Base: { } boundsOwner }) root = SymTable.Resolve(boundsOwner);
        var kind = metadata ? MemoryKind.Metadata : location?.Kind switch
        {
            LocationKind.Local => MemoryKind.Local,
            LocationKind.Instance or LocationKind.Length or LocationKind.StringLength or LocationKind.Dimension or LocationKind.LowerBound => MemoryKind.Instance,
            LocationKind.Element or LocationKind.MultiElement or LocationKind.StringChar => MemoryKind.Element,
            LocationKind.Static or LocationKind.ThreadStatic => MemoryKind.Static,
            LocationKind.Reference => MemoryKind.Reference,
            _ when header || bounds => MemoryKind.Instance,
            _ => MemoryKind.Unknown,
        };
        return readKinds[read] = (location, root, kind);
    }

    public (EffectSummary Effects, Sym? Root) Read(ReadSym read, IReadOnlySet<Sym> nonNull)
    {
        var (location, root, kind) = Classify(read);
        // beforefieldinit 类型的初始化可以在首次访问之前的任何时刻发生（ECMA-335 II.10.5.3.2），读取不构成时序约束。
        if (location is { Kind: LocationKind.Static, Owner: DefinitionRef owner } && (owner.Definition.Attributes & System.Reflection.TypeAttributes.BeforeFieldInit) != 0)
            return (new(EffectKind.Read), root);
        return (EffectSummary.Access(kind, nonNull: nonNull.Contains(root)), kind is MemoryKind.Local or MemoryKind.Metadata ? null : root);
    }

    public static EffectSummary Operation(Stmt statement) => statement switch
    {
        Define or Phi or Nop or Jump or Branch or Return or IndirectJump => EffectSummary.None,
        Store => new(EffectKind.Write, ExceptionEffect.Any),
        Call { Op: { } op } => RuntimeOps.Of(op.Kind)?.Behavior ?? EffectSummary.Unknown,
        _ => EffectSummary.Unknown,
    };

    public EffectSummary Statement(Stmt statement, IReadOnlySet<Sym> nonNull)
    {
        var effect = Operation(statement);
        foreach (var read in values.ReadsAt(statement)) effect |= Read(read, nonNull).Effects;
        // 共享子节点只展开一次：符号图可以很大，逐操作数独立递归会重复展开同一子树。
        var seen = new HashSet<Sym>();
        foreach (var value in values.Operands(statement)) effect |= Computation(value, seen);
        return effect;
    }

    /// <summary>运算是否可能在计算时抛出其他异常。符号图节点在大方法上可达数千，结果按节点缓存。</summary>
    private EffectSummary Computation(Sym value, HashSet<Sym> seen)
    {
        var (effect, _) = Compute(value, seen);
        return effect;
    }

    /// <summary>返回效果与子树是否含环；含环的结果依赖展开路径，不能缓存。</summary>
    private (EffectSummary Effect, bool Cyclic) Compute(Sym value, HashSet<Sym> seen)
    {
        value = SymTable.Resolve(value);
        if (computations.TryGetValue(value, out var known)) return (known, false);
        if (!seen.Add(value)) return (EffectSummary.None, true);
        (EffectSummary Effect, bool Cyclic) result = value switch
        {
            UnknownSym or UndefSym => (EffectSummary.Unknown, false),
            OpSym op => Combine(op.Args, op.Op.Kind == OperatorKind.Binary && op.Op.Binary is BinOp.SDiv or BinOp.UDiv or BinOp.SRem or BinOp.URem
                ? new EffectSummary(EffectKind.None, ExceptionEffect.Other) : EffectSummary.None, seen),
            SliceSym slice => Compute(slice.Base, seen),
            ConcatSym concat => Combine(concat.Parts, EffectSummary.None, seen),
            _ => (EffectSummary.None, false),
        };
        seen.Remove(value);
        if (!result.Cyclic) computations[value] = result.Effect;
        return result;
    }

    /// <summary>多个子值的效果取并；任一子值含环则整棵子树不缓存。</summary>
    private (EffectSummary Effect, bool Cyclic) Combine(IEnumerable<Sym> args, EffectSummary seed, HashSet<Sym> seen)
    {
        var effect = seed;
        var cyclic = false;
        foreach (var arg in args)
        {
            var (part, cycle) = Compute(arg, seen);
            effect |= part;
            cyclic |= cycle;
        }
        return (effect, cyclic);
    }

    /// <summary>节点效果与语句无关，可在方法的整个下降期间复用。</summary>
    private readonly Dictionary<Sym, EffectSummary> computations = new(ReferenceEqualityComparer.Instance);
}
