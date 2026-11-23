using System.Text.Encodings.Web;
using System.Text.Json;
using Cpp2CS.Facts;
using Cpp2CS.Input;

namespace Cpp2CS.Cli;

internal static class Program
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        return args switch
        {
            ["facts", var binary, var metadata, var output, .. var options] => Facts(binary, metadata, output, options),
            ["refs", var binary, var metadata, var address] => Refs(binary, metadata, Convert.ToUInt64(address, 16)),
            ["layout", var binary, var metadata, var type, .. var options] => Layout(binary, metadata, type, options),
            ["ssa", var binary, var metadata, .. var addresses] when addresses.Length > 0 => Ssa(binary, metadata, Hex(addresses), addresses.Contains("--idioms"), addresses),
            ["idioms", var binary, var metadata, var output, .. var options] => Idioms(binary, metadata, output, options),
            ["recover", var binary, var metadata, var output, .. var options] => RecoverCommand.Run(binary, metadata, output, options),
            ["inspect", var binary, var metadata, .. var options] when options.Length > 0 => Inspect.Run(binary, metadata, options),
            ["source-project", var assembly, var output] => SourceProject(assembly, output),
            ["holes", var run, .. var options] => HoleCensus.Run(run, options),
            ["callers", var binary, var metadata, var range, .. var options] => Callers(binary, metadata, range, options),
            ["eh", var binary, var metadata, .. var entries] when entries.Length > 0 => Eh(binary, metadata, entries),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine("""
            用法: cpp2cs facts  <libil2cpp.so> <global-metadata.dat> <输出目录>   建立基础事实，写出 summary.json 与 *.tsv
                  cpp2cs refs   <libil2cpp.so> <global-metadata.dat> <十六进制地址>  打印所在函数的所有者与引用
                  cpp2cs layout <libil2cpp.so> <global-metadata.dat> <类型全名> [--fact-cache-file 文件]  打印类型（含泛型实例）的字段布局
                  cpp2cs ssa    <libil2cpp.so> <global-metadata.dat> <十六进制入口>... [--idioms] [--fact-cache-file 文件]
                                                                      打印函数的寄存器 SSA（--idioms：L2 归一之后）
                  cpp2cs idioms <libil2cpp.so> <global-metadata.dat> <输出目录> [--owner 前缀] [--limit N]
                                                                      对托管函数做 L2 模板普查，写出 idioms.txt 与 idiom-residuals.tsv
                  cpp2cs recover <libil2cpp.so> <global-metadata.dat> <输出目录> [--all | --assemblies A.dll,B.dll | --namespaces A,B] [--no-source] [--stubs-only] [--keep-going] [--method-timeout 秒] [--limit N] [--jobs N] [--methods 清单 | --types 类型清单] [--source-layout flat|project]
                                                                      恢复范围必须显式指定，写出 CIL 与 C#；
                                                                      --methods：从外部方法清单选择目标；
                                                                      --types：按顶层类型全名清单选择这些类型（含嵌套类型）的全部方法；
                                                                      --source-layout project：按程序集/命名空间/类型导出，含范围内全部类型声明与 csproj。
                                                                      --jobs N：方法恢复的最大并行度，默认 1；程序集写出按顺序执行。
                                                                      --fact-cache-file 文件：显式固定事实快照，输入变化仍会失效；用于重构前后对比。
                  cpp2cs inspect <libil2cpp.so> <global-metadata.dat> <十六进制入口|方法清单>... [--fact-cache-file 文件]
                                                                      逐层打印方法的恢复产物
                  cpp2cs holes <恢复输出目录> [--top N]
                                                                      按归一后的原因汇总未恢复方法，并统计拒绝规则与运行时痕迹
                  cpp2cs source-project <程序集.dll> <输出目录>
                                                                      将已有程序集按项目目录导出 C#，依赖从程序集所在目录解析。
            """);
        return 2;
    }

    private static int SourceProject(string assembly, string output)
    {
        var path = Path.GetFullPath(assembly);
        var count = Output.SourceProject.Write(path, Path.GetDirectoryName(path)!, output, _ => true, null);
        Console.WriteLine($"C#：{count} 个类型文件，{Path.GetFullPath(output)}");
        return 0;
    }

    /// <summary>打印一个函数的边界、所有者与引用普查结果（调试用）。</summary>
    private static int Refs(string binary, string metadata, ulong address)
    {
        var facts = FactsBuilder.Build(binary, metadata);
        var index = facts.Code.IndexOf(address);
        if (index < 0) { Console.Error.WriteLine($"0x{address:x} 不在任何函数内"); return 1; }
        var function = facts.Code.Functions[index];
        Console.WriteLine($"函数 0x{function.Start:x}..0x{function.End:x} {function.Region}/{function.Evidence} {facts.Scan.ShapeOf(index)}");
        foreach (var e in facts.EntriesAt(function.Start)) Console.WriteLine($"  所有者 {e}");
        foreach (var r in facts.Scan.Of(index))
        {
            var note = facts.Usages.At(r.Target)?.Usage.ToString() ?? facts.Helpers.At(r.Target)?.ToString()
                ?? string.Join(" | ", facts.EntriesAt(r.Target).Select(e => e.ToString())) ?? "";
            Console.WriteLine($"  0x{r.Site:x} {r.Kind,-8} 0x{r.Target:x} {(r.Size > 0 ? $"[{r.Size}]" : "")} {facts.Model.Image.SectionAt(r.Target)?.Name} {note} {(facts.Model.UsageAt(r.Target) is { } u ? "token:" + u : "")}");
        }
        return 0;
    }

    /// <summary>打印函数入口的寄存器 SSA（调试用）；idioms 为真时打印 L2 归一之后的形式与残余。</summary>
    /// <summary>--fact-cache-file 复用事实快照，定位问题时不必每次重建。</summary>
    private static Cpp2CS.Options.RecoveryOptions CacheOptions(string[] options) =>
        options.SkipWhile(o => o != "--fact-cache-file").Skip(1).FirstOrDefault() is { } cache
            ? new Cpp2CS.Options.RecoveryOptions { FactCacheFile = Path.GetFullPath(cache) } : new();

    private static ulong[] Hex(string[] options) => options.Where(o => o.StartsWith("0x", StringComparison.Ordinal) || !o.StartsWith("--", StringComparison.Ordinal) && !File.Exists(o))
        .Select(a => System.Convert.ToUInt64(a.StartsWith("0x", StringComparison.Ordinal) ? a[2..] : a, 16)).ToArray();

    private static int Ssa(string binary, string metadata, ulong[] entries, bool idioms, string[] options)
    {
        var facts = FactsBuilder.Build(binary, metadata, options: CacheOptions(options), inferUnregistered: !options.Contains("--no-infer"));
        var lifter = new Cpp2CS.Machine.Lifting.FunctionLifter(facts);
        var rewriter = new Cpp2CS.Idioms.IdiomRewriter(facts);
        foreach (var entry in entries)
        {
            Console.WriteLine($"== 0x{entry:x} {string.Join(" | ", facts.EntriesAt(entry).Select(e => e.ToString()))}");
            var lifted = lifter.Lift(entry);
            foreach (var error in lifted.Errors) Console.WriteLine($"  ! {error}");
            if (idioms && lifted.Succeeded)
            {
                var result = rewriter.Run(lifted.Function);
                Console.WriteLine($"  模板: {string.Join(", ", result.Hits.Select(p => $"{p.Key}×{p.Value}"))}");
                foreach (var error in result.Errors) Console.WriteLine($"  ! {error}");
                foreach (var residual in result.Residuals) Console.WriteLine($"  残余 0x{residual.Address:x} {residual.Category}: {residual.Detail}");
                foreach (var instance in result.Instances)
                    Console.WriteLine($"  实例 {instance.Template} 0x{instance.Head:x} {System.Text.Json.JsonSerializer.Serialize(instance.Inputs)}");
                foreach (var (block, define) in lifted.Function.Dead) Console.WriteLine($"  删去 B{block.Index}@0x{block.Start:x} 0x{define.Address:x}: {define}");
            }
            Console.Write(lifted.Function);
        }
        return 0;
    }

    /// <summary>L2 模板普查。选项：--owner 只取托管所有者全名以该前缀开头的函数；--limit 只取前 N 个。</summary>
    private static int Idioms(string binary, string metadata, string output, string[] options)
    {
        string? prefix = null;
        var limit = int.MaxValue;
        for (var i = 0; i + 1 < options.Length; i += 2)
        {
            if (options[i] == "--owner") prefix = options[i + 1];
            else if (options[i] == "--limit") limit = int.Parse(options[i + 1]);
        }
        var facts = FactsBuilder.Build(binary, metadata, Console.Error.WriteLine);
        var functions = facts.Code.Functions.Where(f => f.Region == CodeRegion.Managed)
            .Where(f => prefix is null || facts.EntriesAt(f.Start).Any(e => e.Method is not null && e.Method.ToString().StartsWith(prefix, StringComparison.Ordinal)))
            .Take(limit).ToArray();
        Console.Error.WriteLine($"普查 {functions.Length} 个托管函数");
        var census = Cpp2CS.Idioms.IdiomCensus.Run(facts, functions, Console.Error.WriteLine);
        Directory.CreateDirectory(output);
        var report = IdiomReport.Write(facts, census, output);
        Console.Write(report);
        return 0;
    }

    /// <summary>
    /// 打印函数（或包含该地址的函数）的 LSDA 区间、action 链与类型槽，用于核对异常事实。
    /// --scan：汇总全部托管 LSDA action 的类别、序号与类型名分布。
    /// </summary>
    private static int Eh(string binary, string metadata, string[] entries)
    {
        var facts = FactsBuilder.Build(binary, metadata, inferUnregistered: false, options: CacheOptions(entries));
        if (entries.Contains("--scan"))
        {
            var groups = new Dictionary<string, int>();
            var names = new Dictionary<string, int>();
            var indices = new Dictionary<(string Kind, long Filter, bool Null), int>();
            var typed = new Dictionary<(long Filter, string Name), int>();
            foreach (var function in facts.Code.Functions.Where(f => f.Region == CodeRegion.Managed))
                foreach (var region in function.ExceptionRegions)
                    foreach (var action in region.Actions)
                    {
                        var slot = action.TypeInfo ?? 0;
                        // 类型槽存的是重定位后的 typeinfo 指针；名字在 typeinfo+8。
                        var typeInfo = slot is > 0 ? facts.Model.Image.RelocatedPointer(slot) : null;
                        var name = typeInfo is { } pointer && pointer != 0 ? ExceptionFacts.TypeName(facts.Model.Image, pointer) ?? "（未解析）" : "（空槽）";
                        var key = (action.Kind, action.Filter, slot == 0);
                        indices[key] = indices.GetValueOrDefault(key) + 1;
                        groups[action.Kind] = groups.GetValueOrDefault(action.Kind) + 1;
                        names[name] = names.GetValueOrDefault(name) + 1;
                        if (slot != 0) typed[(action.Filter, name)] = typed.GetValueOrDefault((action.Filter, name)) + 1;
                    }
            Console.WriteLine("按类别：" + string.Join("，", groups.OrderByDescending(p => p.Value).Select(p => $"{p.Key}={p.Value}")));
            Console.WriteLine("按（类别，序号，槽为空）：");
            foreach (var (key, count) in indices.OrderByDescending(p => p.Value))
                Console.WriteLine($"  {key.Kind} filter={key.Filter} 空槽={key.Null}: {count}");
            Console.WriteLine("非空类型槽按（序号，类型名）：");
            foreach (var (key, count) in typed.OrderByDescending(p => p.Value))
                Console.WriteLine($"  filter={key.Filter} {key.Name}: {count}");
            Console.WriteLine("按类型名：" + string.Join("，", names.OrderByDescending(p => p.Value).Take(20).Select(p => $"{p.Key}={p.Value}")));
            // 抛出点按实参形态的证据：列出抛出点所属函数与调用目标，核对是否集中在少数 helper。
            var throws = ExceptionFacts.Throws(facts.Code, facts.Scan, facts.Helpers);
            var sites = facts.Scan.All.ToDictionary(r => r.Site, r => r.Target);
            var targets = throws.GroupBy(t => sites.GetValueOrDefault(t.Site))
                .OrderByDescending(g => g.Count()).ToArray();
            Console.WriteLine($"抛出点 {throws.Length} 处，按调用目标：");
            foreach (var group in targets.Take(12))
                Console.WriteLine($"  0x{group.Key:x} {group.Count()} 处，函数 {group.Select(t => $"0x{t.Entry:x}").Distinct().Count()} 个" +
                    $"（{(facts.Helpers.At(group.Key)?.ToString() ?? "无 helper 证据")}）");
            // 每个（序号，空槽）组合给出若干函数入口，便于逐点核对类型表。
            var samples = new Dictionary<(long Filter, bool Null), List<ulong>>();
            foreach (var function in facts.Code.Functions.Where(f => f.Region == CodeRegion.Managed))
                foreach (var region in function.ExceptionRegions)
                    foreach (var action in region.Actions.Where(a => a.Filter > 0))
                    {
                        var key = (action.Filter, (action.TypeInfo ?? 0) == 0);
                        if (!samples.TryGetValue(key, out var list)) samples[key] = list = [];
                        if (list.Count < 4 && !list.Contains(function.Start)) list.Add(function.Start);
                    }
            foreach (var (key, list) in samples.OrderByDescending(p => p.Value.Count))
                Console.WriteLine($"样例 filter={key.Filter} 空槽={key.Null}：" + string.Join("，", list.Select(a => $"0x{a:x}")));
            return 0;
        }
        var addresses = entries.Where(e => e.StartsWith("0x", StringComparison.Ordinal)).Select(e => Convert.ToUInt64(e[2..], 16)).ToArray();
        // --helpers：打印给定地址作为 helper 的识别结果与依据（含内部调用）。
        if (entries.Length == 1 || entries.Contains("--helpers"))
        {
            foreach (var address in addresses)
            {
                var helper = facts.Helpers.At(address);
                var internalCall = facts.Helpers.InternalCall(address);
                Console.WriteLine($"0x{address:x} 表内：{helper?.Kind.ToString() ?? "无"} {helper?.Evidence}");
                Console.WriteLine($"0x{address:x} 内部：{internalCall.Kind} {internalCall.Detail} — {internalCall.Evidence}");
                // 判据分解：类初始化本体依赖的几项形态各自是否成立。
                var function = facts.Code.At(address);
                if (function is not null)
                {
                    int Count(Func<uint, bool> predicate)
                    {
                        var n = 0;
                        for (var pc = function.Start; pc < function.End; pc += 4) if (facts.Code.Word(pc) is { } w && predicate(w)) n++;
                        return n;
                    }
                    Console.WriteLine($"  原子 {Count(w => (w & 0x3FE0FC00) is 0x085FFC00 or 0x0809FC00 or 0x081FFC00 or 0x080DFC00)} 条，" +
                        $"add #0xd8 {Count(w => (w & 0xFF800000) == 0x91000000 && ((w >> 10) & 0xFFF) == 0xD8)} 条，" +
                        $"add #0xd4 {Count(w => (w & 0xFF800000) == 0x91000000 && ((w >> 10) & 0xFFF) == 0xD4)} 条");
                    for (var pc = function.Start; pc < function.End; pc += 4)
                        if (facts.Code.Word(pc) is { } w && (w & 0x3B000000) == 0x39000000 && ((w >> 22) & 3) != 0)
                            Console.WriteLine($"  读 [x{(w >> 5) & 31}, #0x{((w >> 10) & 0xFFF) * (1 << (int)(w >> 30)):x}] 宽 {1 << (int)(w >> 30)} @0x{pc:x}");
                }
            }
        }
        // --cxa：打印静态链接 __cxa_throw 的识别结果与函数边界，核对常量链扫描。
        if (entries.Contains("--cxa"))
        {
            var found = new List<(ulong Start, ulong End)>();
            foreach (var function in facts.Code.Functions.Where(f => f.Region is CodeRegion.Runtime or CodeRegion.Managed))
            {
                for (var pc = function.Start; pc + 4 <= function.End; pc += 4)
                    if (facts.Code.Word(pc) is { } w && (w & 0x7F800000) == 0x52800000 && (w & 0x80000000) != 0
                        && ((w >> 5) & 0xFFFF) == 0x2B00 && ((w >> 21) & 3) == 0)
                    { found.Add((function.Start, pc)); break; }
            }
            Console.WriteLine($"MOVZ 低 16 位 0x2b00 的函数 {found.Count} 个");
            foreach (var (start, pc) in found.Take(10))
                Console.WriteLine($"  函数 0x{start:x} 首条 0x{pc:x}");
            if (facts.Code.At(0x142d9bc) is { } owner)
            {
                Console.WriteLine($"0x142d9bc 属于函数 0x{owner.Start:x}..0x{owner.End:x} {owner.Region}/{owner.Evidence}");
                for (var pc = 0x142da10UL; pc <= 0x142da2c; pc += 4)
                {
                    var w = facts.Code.Word(pc);
                    Console.WriteLine($"  0x{pc:x} word={(w is { } x ? x.ToString("x8") : "无")}" +
                        (w is { } y ? $" imm16=0x{(y >> 5) & 0xFFFF:x} shift={(y >> 21) & 3}" : ""));
                }
                var callsInto = facts.Scan.Of(facts.Code.EntryIndex(0x142d9bc)).ToArray()
                    .Where(r => r.Kind is RefKind.Call or RefKind.TailCall).Select(r => r.Target).Distinct().Take(6).ToArray();
                Console.WriteLine("  该函数调用的目标：" + string.Join("，", callsInto.Select(a => $"0x{a:x}")));
                Console.WriteLine($"  以 0xfde220 为目标的调用点 {facts.Scan.All.Count(r => r.Target == 0xfde220)} 处");
            }
        }
        foreach (var address in addresses)
        {
            var function = facts.Code.At(address);
            if (function is null) { Console.WriteLine($"0x{address:x} 不在任何函数内"); continue; }
            Console.WriteLine($"函数 0x{function.Start:x}..0x{function.End:x} {function.Region} LSDA 区间 {function.ExceptionRegions.Length} 个");
            foreach (var region in function.ExceptionRegions)
            {
                Console.WriteLine($"  0x{region.Start:x}..0x{region.End:x} 落地 0x{region.LandingPad:x} actionOffset {region.ActionOffset}");
                foreach (var action in region.Actions)
                {
                    // 类型槽存的是重定位后的 typeinfo 指针；名字在 typeinfo+8。
                    var typeInfo = action.TypeInfo is { } slot && slot != 0 ? facts.Model.Image.RelocatedPointer(slot) : null;
                    var name = typeInfo is { } pointer && pointer != 0 ? ExceptionFacts.TypeName(facts.Model.Image, pointer) ?? "（未解析）" : "（空槽）";
                    Console.WriteLine($"    @0x{action.Address:x} filter={action.Filter} next={action.NextOffset} {action.Kind} " +
                        $"槽=0x{action.TypeInfo:x} 重定位=0x{typeInfo:x} 名={name}");
                }
            }
        }
        return 0;
    }

    /// <summary>按全名查找类型（非泛型定义按 FullName，泛型实例按运行时类型的显示名）并打印布局。
    /// --algorithm：同时打印不采用元数据值的算法重算结果，用于核对 layout.instance-fields。
    /// </summary>
    private static int Layout(string binary, string metadata, string name, string[] options)
    {
        var facts = FactsBuilder.Build(binary, metadata, inferUnregistered: false, options: CacheOptions(options));
        var algorithm = options.Contains("--algorithm");
        var matches = facts.Model.Types.Where(t => t.FullName == name && t.GenericParameters.Count == 0).Select(t => new Model.DefinitionRef(t, []))
            .Concat(facts.Model.RuntimeTypes.OfType<Model.DefinitionRef>().Where(d => d.Arguments.Count > 0 && d.ToString() == name)).Distinct().ToArray();
        if (matches.Length == 0) { Console.Error.WriteLine($"没有名为 {name} 的封闭类型"); return 1; }
        foreach (var type in matches)
        {
            var layout = facts.Layouts.Of(type);
            var computed = algorithm ? facts.Layouts.Compute(type) : null;
            if (layout is null) { Console.WriteLine($"{type}: 没有运行时布局"); continue; }
            Console.WriteLine($"{type}  instance_size=0x{layout.InstanceSize:x} actualSize=0x{layout.ActualSize:x} minimumAlignment={layout.MinimumAlignment} " +
                $"has_references={layout.HasReferences} {(layout.FromMetadata ? "（元数据）" : "（按运行时算法）")} " +
                $"元数据大小={(type.Definition.Size < 0 ? "未知" : $"0x{type.Definition.Size:x}")} packing={type.Definition.PackingSize} classSizeDefault={type.Definition.ClassSizeIsDefault}");
            if (computed is { } c)
                Console.WriteLine($"  算法：instance_size=0x{c.InstanceSize:x} actualSize=0x{c.ActualSize:x} minimumAlignment={c.MinimumAlignment} has_references={c.HasReferences}");
            var algorithmOffsets = computed?.Fields.ToDictionary(f => f.Field, f => f.Offset);
            foreach (var f in layout.Fields)
                Console.WriteLine($"  +0x{f.Offset:x3} {f.Type} {f.Field.Name}" +
                    (algorithmOffsets is { } offsets && offsets.TryGetValue(f.Field, out var a) ? $"（算法 0x{a:x}，原始偏移 {f.Field.Offset}）" : ""));
            foreach (var f in layout.Statics) Console.WriteLine($"  static +0x{f.Offset:x3} {f.Type} {f.Field.Name}");
            foreach (var f in layout.ThreadStatics) Console.WriteLine($"  threadstatic +0x{f.Offset:x3} {f.Type} {f.Field.Name}");
            foreach (var m in type.Definition.Methods) Console.WriteLine($"  method 0x{m.Address:x} {m.Name}({string.Join(", ", m.Parameters.Select(p => p.Type))}) : {m.ReturnType}");
        }
        return 0;
    }

    /// <summary>按未注册推断的调用者顺序（<see cref="CodeScan.All"/> 中首次出现）列出调用者及其调用点数，用于定位长耗时函数。</summary>
    private static int Callers(string binary, string metadata, string range, string[] options)
    {
        var parts = range.Split("..", StringSplitOptions.None);
        var from = int.Parse(parts[0]);
        var to = parts.Length > 1 ? int.Parse(parts[1]) : from;
        var facts = FactsBuilder.Build(binary, metadata, inferUnregistered: false, options: CacheOptions(options));
        if (options.Contains("--checks"))
        {
            foreach (var check in facts.Checks.All)
            {
                var mark = check.Severity == "Info" ? "  " : check.Passed ? "✓ " : check.Severity == "Error" ? "✗ " : "! ";
                Console.WriteLine($"{mark}{check.Name}: {check.Violations}/{check.Total} — {check.Detail}");
                foreach (var sample in check.Samples) Console.WriteLine($"      {sample}");
            }
            return 0;
        }
        var unregistered = facts.Code.Functions.Where(f => f.Region == CodeRegion.Managed && facts.EntriesAt(f.Start).Length == 0).ToDictionary(f => f.Start);
        var groups = facts.Scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall && unregistered.ContainsKey(r.Target))
            .GroupBy(r => facts.Code.At(r.Site)!.Start).ToArray();
        Console.WriteLine($"调用者 {groups.Length}");
        for (var i = Math.Max(1, from); i <= Math.Min(groups.Length, to); i++)
        {
            var group = groups[i - 1];
            var function = facts.Code.At(group.Key)!;
            var size = function.End - function.Start;
            Console.WriteLine($"{i}\t0x{group.Key:x}\t{size} 字节\t{group.Count()} 调用点\t{string.Join(" | ", facts.EntriesAt(group.Key).Select(e => e.Method?.ToString() ?? e.Kind.ToString()).DefaultIfEmpty("无注册入口"))}");
        }
        return 0;
    }

    /// <summary>建立基础事实并写出 summary.json（检查结果、计时）。存在 Error 级违例时返回 1。</summary>
    private static int Facts(string binary, string metadata, string output, string[] options)
    {
        var facts = FactsBuilder.Build(binary, metadata, Console.Error.WriteLine, options: CacheOptions(options));
        Directory.CreateDirectory(output);
        var summary = new
        {
            binarySha256 = facts.Model.Image.Sha256,
            metadataVersion = facts.Model.MetadataVersion,
            timings = facts.Timings,
            checks = facts.Checks.All,
        };
        File.WriteAllText(Path.Combine(output, "summary.json"), JsonSerializer.Serialize(summary, Json));
        FactsWriter.Write(facts, output);
        foreach (var check in facts.Checks.All)
        {
            var mark = check.Severity == "Info" ? "  " : check.Passed ? "✓ " : check.Severity == "Error" ? "✗ " : "! ";
            Console.WriteLine($"{mark}{check.Name}: {check.Violations}/{check.Total} — {check.Detail}");
            foreach (var sample in check.Samples) Console.WriteLine($"      {sample}");
        }
        return facts.Checks.AnyErrors ? 1 : 0;
    }
}
