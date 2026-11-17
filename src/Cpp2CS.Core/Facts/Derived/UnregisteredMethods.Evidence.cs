using Cpp2CS.Idioms;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Lifting;
using static Cpp2CS.Facts.UnregisteredMethods;

namespace Cpp2CS.Facts.Derived;

public static partial class UnregisteredInference
{
    /// <summary>单个目标的耗时监视：主线程进入目标后，超过阈值仍停留在该目标时由后台线程输出一次。</summary>
    private sealed class Watchdog : IDisposable
    {
        private readonly Action<string>? log;
        private readonly string format;
        private readonly System.Diagnostics.Stopwatch clock = System.Diagnostics.Stopwatch.StartNew();
        private readonly Thread worker;
        private long target;
        private int since;
        private volatile bool stopped;

        public Watchdog(Action<string>? log, string format)
        {
            this.log = log;
            this.format = format;
            worker = new Thread(Loop) { IsBackground = true };
            worker.Start();
        }

        public void Enter(ulong entry, double seconds)
        {
            Interlocked.Exchange(ref target, (long)entry);
            Volatile.Write(ref since, (int)(seconds * 1000));
        }

        private void Loop()
        {
            while (!stopped)
            {
                Thread.Sleep(5000);
                var entry = (ulong)Interlocked.Read(ref target);
                if (entry == 0) continue;
                var elapsed = clock.Elapsed.TotalSeconds - Volatile.Read(ref since) / 1000.0;
                if (elapsed > 20) log?.Invoke(string.Format(format, entry, elapsed));
            }
        }

        public void Dispose() => stopped = true;
    }

    private sealed class Observation(ulong caller, CodeRef reference)
    {
        public ulong Caller { get; } = caller;
        public CodeRef Reference { get; } = reference;
        public bool Failed { get; set; }
        public Dictionary<Storage, MethodRef[]> Symbols { get; } = [];
        public List<MethodRef> Positive { get; } = [];
    }

    public static UnregisteredMethods Build(BaseFacts facts, Action<string>? log = null)
    {
        return new Builder(facts, log).Run();
    }

    private sealed partial class Builder(BaseFacts facts, Action<string>? log)
    {
        private readonly ManagedAbi abi = new(facts.Layouts);
        private readonly Dictionary<MethodRef, AbiSignature?> signatures = [];
        private readonly Dictionary<ulong, HashSet<ulong>> guards = [];
        private readonly Dictionary<ulong, HashSet<ulong>> guardBranches = [];
        private readonly Dictionary<ulong, bool> addressProofs = [];
        private readonly List<string> analysisErrors = [];
        private AbiSignature? Signature(MethodRef method)
        {
            // 开放参数的相等性只包含名称和槽位，不包含调用者的约束；不能跨调用者复用分类。
            if (!IsClosed(method)) return ClassifyInstance(method, abi);
            if (!signatures.TryGetValue(method, out var result)) signatures[method] = result = ClassifyInstance(method, abi);
            return result;
        }

        public UnregisteredMethods Run()
        {
            var result = new UnregisteredMethods();
            var functions = facts.Code.Functions.Where(f => f.Region == CodeRegion.Managed && facts.EntriesAt(f.Start).Length == 0).ToDictionary(f => f.Start);
            log?.Invoke($"未注册推断：无注册入口的托管函数 {functions.Count} 个");
            var sites = facts.Scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall && functions.ContainsKey(r.Target))
                .Select(r => new Observation(facts.Code.At(r.Site)!.Start, r)).ToArray();
            var clock = System.Diagnostics.Stopwatch.StartNew();
            Observe(sites);
            log?.Invoke($"未注册推断：调用者提升与归一 {clock.Elapsed.TotalSeconds:F1}s");
            // 整个注册集合参与歧义否决；不能先按 A 的定义过滤再宣布 B 唯一。
            var shapes = RegisteredShapes();
            log?.Invoke($"未注册推断：注册指纹 {clock.Elapsed.TotalSeconds:F1}s");
            var conflicts = new List<string>();
            var abiProblems = new List<string>();
            var contradictions = new List<string>();
            foreach (var group in sites.GroupBy(s => s.Reference.Target).OrderBy(g => g.Key))
            {
                var observations = group.ToArray();
                var positive = observations.SelectMany(s => s.Positive).Distinct().ToArray();
                var complete = positive.Where(IsComplete).ToArray();
                var definitions = positive.Select(m => m.Method).Distinct().ToArray();
                var definition = definitions.Length == 1 ? definitions[0] : null;
                var reason = "A/无见证";
                AbiSignature? signature = null;
                ulong[] matches = [];
                var adjustors = Adjustors(group.Key, observations);
                // IL2CPP 在调用方的翻译单元生成的 inline 副本：非泛型方法不传 MethodInfo，没有见证。
                // 机器码（含引用的数据）与唯一一个注册的非泛型定义同形时，它就是这个方法的副本。
                // 它的身份只由方法体决定，个别调用方分析不完整不影响结论。
                var copied = definitions.Length == 0 ? UniqueCopy(functions[group.Key], shapes) : null;
                if (copied is not null)
                {
                    definition = copied.Method;
                    complete = [copied];
                }
                if (definitions.Length > 1) reason = "A/不同定义冲突";
                else if (definition is not null && complete.Length == 0) reason = "A/不完整实例";
                else if (definition is not null)
                {
                    signature = Signature(complete[0])!;
                    var register = signature.MethodInfo!.Register;
                    reason = observations.Any(s => s.Symbols.TryGetValue(register, out var symbols) && symbols.Any(m => m.Method != definition)) ? "A/不同定义冲突"
                        : copied is null && observations.Any(s => s.Failed) ? "A/分析不完整"
                        : complete.Any(m => Signature(m) is not { } sig || Shape(sig) != Shape(signature)) ? "ABI/正见证不吻合"
                        : "A/通过";
                    // 非单值符号也不能掩盖 ABI 冲突；它不给正见证，但有否决权。
                    if (reason == "A/通过" && observations.SelectMany(s => s.Symbols.GetValueOrDefault(register) ?? [])
                        .Where(IsComplete).Any(m => Signature(m) is { } sig && Shape(sig) != Shape(signature))) reason = "ABI/候选槽位不吻合";
                    if (reason == "A/通过")
                    {
                        reason = Compare(functions[group.Key], definition, signature, shapes, out matches);
                        // ABI 由本调用的完整实例分类；开放参数不替换成任意封闭见证。
                    }
                }
                if (reason == "A/不同定义冲突") conflicts.Add($"0x{group.Key:x}: {string.Join(';', positive.Select(m => m.ToString()))}");
                if (reason.StartsWith("ABI/", StringComparison.Ordinal)) abiProblems.Add($"0x{group.Key:x}: {reason}");
                if (definition is not null && adjustors.Any(e => e.Method!.Method != definition))
                {
                    reason = "注册调整器/定义矛盾";
                    contradictions.Add($"0x{group.Key:x}: A={definition.Index}, adjustors={string.Join(';', adjustors.Select(e => e.ToString()))}");
                }
                if (reason == "接受")
                    result.accepted.Add(group.Key, new(group.Key, definition!, signature!,
                        observations.SelectMany(s => s.Positive.Where(IsComplete).Select(m => new MethodWitness(s.Caller, s.Reference.Site, m))).ToArray(), matches, adjustors));
                result.decisions.Add(new(group.Key, reason, observations.Length, observations.Count(s => s.Positive.Count > 0), positive.Length, definition?.Index));
            }
            facts.Checks.Add("unregistered.definition-conflict", "Warning", functions.Count, conflicts, "不同定义的 MethodInfo 见证，拒绝身份推断");
            facts.Checks.Add("unregistered.abi", "Warning", functions.Count, abiProblems, "正见证或注册同形体 ABI 不吻合，拒绝身份推断");
            facts.Checks.Add("unregistered.analysis", "Warning", sites.Length, analysisErrors, "调用者提升/L2 不完整，相关目标不接受");
            facts.Checks.Add("unregistered.registration", "Error", functions.Count, contradictions, "A 与注册调整器精确跳转的定义矛盾");
            facts.Checks.Info("unregistered.definitions", result.All.Count, string.Join("；", result.Decisions.GroupBy(d => d.Reason).OrderBy(g => g.Key).Select(g => $"{g.Key}={g.Count()}")));
            log?.Invoke($"未注册定义：{result.All.Count}/{functions.Count}；原始调用点 {sites.Length}");
            return result;
        }

        private MethodRef? UniqueCopy(CodeFunction function, Dictionary<string, List<RegisteredShape>> shapes) =>
            shapes.TryGetValue(Fingerprint(function).Hash, out var bucket) && bucket.Select(m => m.Method).Distinct().ToArray() is [var only]
            && only.TypeArguments.Count + only.MethodArguments.Count == 0 && IsComplete(only) && Signature(only) is { MethodInfo: not null } ? only : null;

        private CodeEntry[] Adjustors(ulong target, Observation[] sites) => sites.Select(s => s.Caller).Distinct()
            .Where(entry => facts.Code.At(entry) is { Size: 8 } && facts.Code.Word(entry) == 0x91004000
                && facts.Code.Word(entry + 4) is { } jump && A64.IsB(jump) && A64.Imm26Target(jump, entry + 4) == target)
            .SelectMany(facts.EntriesAt).Where(e => e.Method is not null && e.Kind is EntryKind.AdjustorThunk or EntryKind.GenericAdjustorThunk).ToArray();

        private void Observe(Observation[] sites)
        {
            var lifter = new FunctionLifter(facts);
            var rewriter = new IdiomRewriter(facts) { RecordFilter = _ => false };
            var groups = sites.GroupBy(s => s.Caller).ToArray();
            log?.Invoke($"未注册推断：提升调用者 {groups.Length} 个（调用点 {sites.Length}）");
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var done = 0;
            // 单个调用者长时间不结束时打印当前目标，避免整段无输出。
            var watching = new Watchdog(log, $"未注册推断：0x{{0:x}} 已用时 {{0:F0}}s");
            foreach (var group in groups)
            {
                watching.Enter(group.Key, clock.Elapsed.TotalSeconds);
                var started = clock.Elapsed.TotalSeconds;
                if (++done % 128 == 0)
                    log?.Invoke($"未注册推断：已提升 {done}/{groups.Length}，{clock.Elapsed.TotalSeconds / done:F2}s/个");
                var lifted = lifter.Lift(group.Key);
                var rewritten = lifted.Succeeded ? rewriter.Run(lifted.Function) : null;
                var spent = clock.Elapsed.TotalSeconds - started;
                if (spent > 1)
                    log?.Invoke($"未注册推断：0x{group.Key:x} {group.Count()} 调用点耗时 {spent:F1}s" +
                        (group.Count() > 0 ? $"（{string.Join(" | ", facts.EntriesAt(group.Key).Select(e => e.Method?.ToString() ?? e.Kind.ToString()).DefaultIfEmpty("无注册入口"))}）" : ""));
                if (!lifted.Succeeded || rewritten!.Errors.Count > 0)
                {
                    foreach (var site in group) site.Failed = true;
                    analysisErrors.Add($"0x{group.Key:x}: {string.Join(';', lifted.Errors.Concat(rewritten?.Errors ?? []))}");
                    continue;
                }
                guards[group.Key] = rewritten.Guards;
                guardBranches[group.Key] = rewritten.MetadataGuardBranches;
                var statements = lifted.Function.Blocks.SelectMany(b => b.Statements).ToArray();
                var definitions = statements.OfType<Define>().Concat(lifted.Function.Dead.Select(d => d.Define))
                    .GroupBy(d => d.Target).ToDictionary(g => g.Key, g => g.First().Value);
                var phis = statements.OfType<Phi>().ToDictionary(p => p.Target);
                var calls = statements.OfType<Call>().ToLookup(c => c.Address);
                foreach (var site in group)
                {
                    var call = calls[site.Reference.Site].SingleOrDefault(c => c.Target is Const target && target.Value == site.Reference.Target);
                    if (call is null) continue;
                    for (var i = 0; i < call.Arguments.Length; i++)
                    {
                        var storage = call.Sources[i];
                        var symbols = Methods(call.Arguments[i], definitions, phis, []);
                        if (symbols.Length == 0) continue;
                        site.Symbols[storage] = symbols;
                        if (Expand(call.Arguments[i], definitions, []) is Symbol { Kind: SymbolKind.Method, Value: MethodRef method }
                            && Signature(method)?.MethodInfo?.Register == storage) site.Positive.Add(method);
                    }
                }
            }
            watching.Dispose();
            log?.Invoke($"未注册定义 A 普查完成：{sites.Select(s => s.Caller).Distinct().Count()} 调用者");
        }

        private static Expr Expand(Expr value, Dictionary<Variable, Expr> definitions, HashSet<Variable> path) =>
            value is Use { Width: 64 } use && definitions.TryGetValue(use.Variable, out var next) && path.Add(use.Variable) ? Expand(next, definitions, path) : value;

        private static MethodRef[] Methods(Expr value, Dictionary<Variable, Expr> definitions, Dictionary<Variable, Phi> phis, HashSet<Variable> path)
        {
            if (value is Symbol { Kind: SymbolKind.Method, Value: MethodRef method }) return [method];
            if (value is Select select) return Methods(select.True, definitions, phis, new(path)).Concat(Methods(select.False, definitions, phis, new(path))).Distinct().ToArray();
            if (value is not Use { Width: 64 } use || !path.Add(use.Variable)) return [];
            if (definitions.TryGetValue(use.Variable, out var next)) return Methods(next, definitions, phis, path);
            return phis.TryGetValue(use.Variable, out var phi) ? phi.Sources.SelectMany(v => Methods(new Use(v, 64), definitions, phis, new(path))).Distinct().ToArray() : [];
        }
    }
}
