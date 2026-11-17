#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Model;

namespace Cpp2CS.Input
{
    /// <summary>
    /// 按 Unity 2018.4.19f1 libil2cpp（元数据 v24.1）的运行时布局，
    /// 直接从映像读取 CodeRegistration / MetadataRegistration 中的代码入口表。
    /// 该版本的 CodeRegistration 以全局 methodPointers 表开头，没有 CodeGenModule；RGCTX 来自元数据 rgctxEntries。
    /// 指针一律经 <see cref="ImageDocument.ReadPointer"/> 读取，以应用 RELATIVE 重定位。
    /// </summary>
    public sealed class RegistrationReader
    {
        // Il2CppCodeRegistration：methodPointers, reversePInvoke, genericMethodPointers, invokerPointers,
        // customAttributeGenerators, unresolvedVirtualCallPointers, interopData（均为 count/pointer 对）
        private const int CrMethodCount = 0, CrMethods = 8, CrReversePInvokeCount = 16, CrReversePInvoke = 24,
            CrGenericMethodCount = 32, CrGenericMethods = 40, CrInvokerCount = 48, CrInvokers = 56,
            CrUnresolvedCount = 80, CrUnresolvedVirtual = 88, CrInteropCount = 96, CrInterop = 104;
        // Il2CppMetadataRegistration：genericClasses, genericInsts, genericMethodTable, types, methodSpecs, fieldOffsets, typeDefinitionsSizes, metadataUsages
        private const int MrGenericMethodTableCount = 32, MrGenericMethodTable = 40, MrTypesCount = 48, MrTypes = 56,
            MrUsagesCount = 112, MrUsages = 120;
        private const int InteropSize = 56, GenericMethodTableSize = 12;

        private readonly ImageDocument image;
        private readonly ProgramModel model;
        private readonly List<string> problems = new();

        private RegistrationReader(ImageDocument image, ProgramModel model)
        {
            this.image = image;
            this.model = model;
        }

        public IReadOnlyList<string> Problems => problems;

        public static (Registrations Registrations, IReadOnlyList<string> Problems) Read(ProgramModel model, ulong codeRegistration, ulong metadataRegistration)
        {
            var reader = new RegistrationReader(model.Image, model);
            return (reader.Build(codeRegistration, metadataRegistration), reader.problems);
        }

        private ulong Pointer(ulong address) => image.ReadPointer(address) ?? throw new InvalidDataException($"0x{address:x} 引用外部符号，不是注册表指针");
        private uint U32(ulong address) => image.ReadU32(address);
        private int I32(ulong address) => image.ReadI32(address);
        private ulong[] Pointers(ulong array, long count)
        {
            if (count == 0) return Array.Empty<ulong>();
            if (array == 0) throw new InvalidDataException($"注册表数组为空指针但长度为 {count}");
            var result = new ulong[count];
            for (long i = 0; i < count; i++) result[i] = Pointer(array + (ulong)i * 8);
            return result;
        }

        private Registrations Build(ulong code, ulong meta)
        {
            var entries = new List<CodeEntry>();
            void Add(ulong address, EntryKind kind, MethodRef? method, int index, string? detail)
            {
                if (address == 0) return;
                if (!image.IsExecutable(address)) { problems.Add($"{kind} #{index} 指向非代码地址 0x{address:x}"); return; }
                entries.Add(new CodeEntry(address, kind, method, index, detail));
            }

            var typePointers = Pointers(Pointer(meta + MrTypes), I32(meta + MrTypesCount));
            if (typePointers.Length != model.RuntimeTypes.Count)
                throw new InvalidDataException($"types 数量 {typePointers.Length} 与模型 {model.RuntimeTypes.Count} 不一致");
            var typeIndex = new Dictionary<ulong, int>(typePointers.Length);
            for (var i = 0; i < typePointers.Length; i++) typeIndex.TryAdd(typePointers[i], i);

            // 非泛型方法的全局入口表：方法定义的 methodIndex 给出表内序号。
            var methods = Pointers(Pointer(code + CrMethods), (long)image.ReadU64(code + CrMethodCount));
            var invokerOf = new Dictionary<MethodDef, int>();
            foreach (var method in model.Methods)
            {
                var index = method.MethodIndex;
                if (index < 0) continue;
                if (index >= methods.Length) { problems.Add($"{method} 的 methodIndex {index} 超出全局方法表 {methods.Length}"); continue; }
                Add(methods[index], EntryKind.Method, new MethodRef(method, [], []), index, method.Owner.Assembly);
                if (method.InvokerIndex >= 0) invokerOf[method] = method.InvokerIndex;
                if (method.Address != methods[index]) problems.Add($"{method} 的 Address 0x{method.Address:x} 与 methodPointers 0x{methods[index]:x} 不一致");
            }

            // 反向 P/Invoke 包装：count 后紧跟指针数组。
            var reverseWrappers = Pointers(Pointer(code + CrReversePInvoke), (long)image.ReadU64(code + CrReversePInvokeCount));
            for (var i = 0; i < reverseWrappers.Length; i++) Add(reverseWrappers[i], EntryKind.ReversePInvoke, null, i, null);

            // 泛型方法实例：genericMethodTable[i] = { methodSpec, { methodIndex, invokerIndex } }；该版本没有 adjustorThunk。
            var genericPointers = Pointers(Pointer(code + CrGenericMethods), (long)image.ReadU64(code + CrGenericMethodCount));
            var table = Pointer(meta + MrGenericMethodTable);
            var tableCount = I32(meta + MrGenericMethodTableCount);
            for (var i = 0; i < tableCount; i++)
            {
                var row = table + (ulong)i * GenericMethodTableSize;
                var spec = I32(row);
                var methodIndex = I32(row + 4);
                if (spec < 0 || spec >= model.MethodSpecs.Count || methodIndex < 0 || methodIndex >= genericPointers.Length)
                { problems.Add($"genericMethodTable[{i}] 序号越界：spec {spec}, method {methodIndex}"); continue; }
                Add(genericPointers[methodIndex], EntryKind.GenericMethod, model.MethodSpecs[spec], methodIndex, null);
            }

            var invokers = Pointers(Pointer(code + CrInvokers), (long)image.ReadU64(code + CrInvokerCount));
            for (var i = 0; i < invokers.Length; i++) Add(invokers[i], EntryKind.Invoker, null, i, null);
            var unresolved = (long)image.ReadU64(code + CrUnresolvedCount);
            var unresolvedPointers = Pointers(Pointer(code + CrUnresolvedVirtual), unresolved);
            for (var i = 0; i < unresolvedPointers.Length; i++) Add(unresolvedPointers[i], EntryKind.UnresolvedVirtualCall, null, i, null);

            // 互操作数据：Il2CppInteropData 为 7 个指针
            // { delegatePInvokeWrapper, marshalToNative, marshalFromNative, marshalCleanup, createCCW, guid, type }。
            // 按 56 字节步长读取时，469 项的类型指针全部落在 types 表中。
            var interop = Pointer(code + CrInterop);
            var interopCount = (long)image.ReadU64(code + CrInteropCount);
            var interopKinds = new[]
            {
                EntryKind.DelegatePInvokeWrapper, EntryKind.MarshalToNative, EntryKind.MarshalFromNative,
                EntryKind.MarshalCleanup, EntryKind.CreateCcw,
            };
            for (var i = 0; i < interopCount; i++)
            {
                var row = interop + (ulong)i * InteropSize;
                var type = Pointer(row + 48);
                var detail = typeIndex.TryGetValue(type, out var t) ? model.RuntimeTypes[t].ToString() : $"type@0x{type:x}";
                for (var k = 0; k < interopKinds.Length; k++)
                    Add(Pointer(row + (ulong)k * 8), interopKinds[k], null, (int)i, detail);
            }

            var rgctx = ReadRgctx();
            // v24：槽位表长度以元数据用途表的最大 destinationIndex+1 为准。注册表里的 metadataUsagesCount
            // 可能小于实际长度（该样本为 74485，而序号最大到 76685），按它读取会截断尾部槽位。
            // Il2CppDumper 同样以元数据表算出的数量读取这张表。
            var listed = image.ReadU64(meta + MrUsagesCount);
            var usageCount = listed;
            if (model.MetadataUsagePairs.Count > 0)
                usageCount = Math.Max(listed, model.MetadataUsagePairs.Max(p => (ulong)p.Destination) + 1);
            var usages = usageCount == 0 ? Array.Empty<ulong>() : Pointers(Pointer(meta + MrUsages), (long)usageCount);
            // 槽位在 .bss、初值为 0，不能用 v27+ 的初值解码，这里按地址直接建立映射。
            if (model.MetadataVersion <= 24.1 && model.MetadataUsagePairs.Count > 0)
            {
                var bySlot = new Dictionary<ulong, Usage>();
                foreach (var (destination, kind, index) in model.MetadataUsagePairs)
                {
                    if (destination >= usages.Length) { problems.Add($"元数据用途序号 {destination} 超出槽位表 {usages.Length}"); continue; }
                    if (model.DecodeToken(kind, index) is not { } usage) { problems.Add($"元数据用途 ({kind}, {index}) 无法解码"); continue; }
                    bySlot[usages[destination]] = usage;
                }
                model.MetadataUsages = bySlot;
                model.UsageSlotAddresses = usages;
            }

            return new Registrations
            {
                CodeRegistration = code,
                MetadataRegistration = meta,
                Entries = entries,
                ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()),
                Rgctx = rgctx,
                MetadataUsageSlots = usages,
                TypePointers = typeIndex,
                InvokerOf = invokerOf,
            };
        }

        /// <summary>
        /// v24.1：元数据 rgctxEntries 是 Il2CppRGCTXDefinition { int32 type; int32 data }。
        /// 方法或类型定义用 (rgctxStartIndex, rgctxCount) 指向其中一段；data 为类型表序号（TYPE/CLASS/ARRAY）
        /// 或 methodSpec 序号（METHOD）。按 (映像名, 令牌) 汇总，与后续版本 CodeGenModule 的 RGCTX 同形。
        /// </summary>
        private Dictionary<(string, uint), RgctxEntry[]> ReadRgctx()
        {
            var rgctx = new Dictionary<(string, uint), RgctxEntry[]>();
            var entries = model.MetadataRgctxEntries;
            if (entries.Count == 0) return rgctx;
            void Add((string, uint) key, int start, int count)
            {
                if (count <= 0) return;
                if (start < 0 || (long)start + count > entries.Count) { problems.Add($"RGCTX 区间越界 {key.Item1} 0x{key.Item2:x8}：{start}+{count}"); return; }
                var list = new RgctxEntry[count];
                for (var k = 0; k < count; k++)
                {
                    var (kind, data) = entries[start + k];
                    object? value = null;
                    switch (kind)
                    {
                        case RgctxKind.Type or RgctxKind.Class or RgctxKind.Array:
                            if (data >= 0 && data < model.RuntimeTypes.Count) value = model.RuntimeTypes[data];
                            else problems.Add($"{key.Item1} 0x{key.Item2:x8} RGCTX[{k}] {kind} 类型序号越界 {data}");
                            break;
                        case RgctxKind.Method:
                            if (data >= 0 && data < model.MethodSpecs.Count) value = model.MethodSpecs[data];
                            else problems.Add($"{key.Item1} 0x{key.Item2:x8} RGCTX[{k}] methodSpec 序号越界 {data}");
                            break;
                        default:
                            problems.Add($"{key.Item1} 0x{key.Item2:x8} RGCTX[{k}] 未知种类 {(int)kind}");
                            break;
                    }
                    list[k] = new RgctxEntry(kind, value);
                }
                if (!rgctx.TryAdd(key, list)) problems.Add($"{key.Item1} RGCTX 令牌 0x{key.Item2:x8} 重复");
            }
            foreach (var type in model.Types) Add((type.Assembly, type.Token), type.RgctxStartIndex, type.RgctxCount);
            foreach (var method in model.Methods) Add((method.Owner.Assembly, method.Token), method.RgctxStartIndex, method.RgctxCount);
            return rgctx;
        }

    }
}
