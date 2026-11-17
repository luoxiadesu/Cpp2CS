
namespace Cpp2CS.Facts;

/// <summary>
/// Unity 2018.4.19f1 libil2cpp 运行时结构的字段偏移（LP64，Android ARM64）。
/// 来源：该版本构建的 il2cpp.h（Il2CppDumper 按运行时结构生成）与实机指令频次核对：
/// Il2CppClass 的 bitflags1 在 0x126、vtable 在 0x128，MethodInfo 无 virtualMethodPointer。
/// 代码中的使用情况另由普查核验（见 <see cref="LayoutChecks"/>）。
/// </summary>
public static class RuntimeLayout
{
    public const string UnityVersion = "2018.4.19f1";

    /// <summary>
    /// Il2CppType.bits 的最高位是否为 valuetype。该位自元数据 v27.2 起存在；
    /// 更早的版本用 element type 区分值类型与引用类型，不能按最高位判定。
    /// </summary>
    public static bool HasTypeValuetypeBit => UnityVersion != "2018.4.19f1";

    // Il2CppObject / Il2CppArray / Il2CppString
    public const int ObjectKlass = 0x00, ObjectMonitor = 0x08, ObjectHeaderSize = Cpp2CS.Model.TypeLayout.ObjectHeaderSize;
    public const int ArrayBounds = 0x10, ArrayMaxLength = 0x18, ArrayData = 0x20;
    // Il2CppArrayBounds：多维数组每维一项，长度为 il2cpp_array_size_t，下界为 int32
    public const int ArrayBoundSize = 0x10, ArrayBoundLength = 0x00, ArrayBoundLowerBound = 0x08;
    public const int StringLength = 0x10, StringChars = 0x14;

    // Il2CppClass：_1（0x00–0xB8）、static_fields、rgctx_data、_2（0xC8 起）、vtable
    public const int ClassImage = 0x00, ClassByvalArg = 0x20, ClassElementClass = 0x40, ClassCastClass = 0x48, ClassDeclaringType = 0x50,
        ClassParent = 0x58, ClassGenericClass = 0x60, ClassTypeMetadataHandle = 0x68, ClassKlass = 0x78, ClassFields = 0x80, ClassMethods = 0x98,
        ClassNestedTypes = 0xA0, ClassImplementedInterfaces = 0xA8, ClassInterfaceOffsets = 0xB0, ClassStaticFields = 0xB8, ClassRgctxData = 0xC0,
        ClassTypeHierarchy = 0xC8, ClassInitializationExceptionGCHandle = 0xD0, ClassCctorStarted = 0xD4,
        ClassCctorFinishedOrNoCctor = 0xD8, ClassCctorThread = 0xE0, ClassInstanceSize = 0xEC,
        ClassActualSize = 0xF0, ClassElementSize = 0xF4, ClassNativeSize = 0xF8, ClassStaticFieldsSize = 0xFC,
        ClassThreadStaticFieldsSize = 0x100, ClassThreadStaticFieldsOffset = 0x104, ClassFlags = 0x108, ClassToken = 0x10C, ClassMethodCount = 0x110,
        ClassVtableCount = 0x11A, ClassInterfacesCount = 0x11C, ClassInterfaceOffsetsCount = 0x11E, ClassTypeHierarchyDepth = 0x120,
        ClassGenericRecursionDepth = 0x121, ClassRank = 0x122, ClassMinimumAlignment = 0x123, ClassNaturalAlignment = 0x124, ClassPackingSize = 0x125,
        /// <summary>位域首字节：bit0 initialized_and_no_error，bit1 initialized，bit2 enumtype，bit3 nullabletype，bit4 is_generic，bit5 has_references，bit6 init_pending，bit7 size_init_pending。</summary>
        ClassBitflags1 = 0x126,
        /// <summary>位域次字节：bit0 enumtype，bit1 size_init_pending（置位表示类布局还待初始化），其余位的位序未逐位核对。</summary>
        ClassBitflags2 = 0x127,
        ClassVtable = 0x128;
    /// <summary>VirtualInvokeData { methodPtr; method }。</summary>
    public const int VirtualInvokeDataSize = 0x10, VirtualInvokeDataMethod = 0x08;
    /// <summary>Il2CppRuntimeInterfaceOffsetPair { interfaceType; offset }。</summary>
    public const int InterfaceOffsetPairSize = 0x10;

    // MethodInfo（该版本没有 virtualMethodPointer）
    public const int MethodPointer = 0x00, MethodInvoker = 0x08, MethodName = 0x10, MethodKlass = 0x18,
        MethodReturnType = 0x20, MethodParameters = 0x28, MethodRgctxData = 0x30, MethodGenericMethod = 0x38, MethodToken = 0x40,
        MethodFlags = 0x44, MethodIflags = 0x46, MethodSlot = 0x48, MethodParametersCount = 0x4A, MethodBitflags = 0x4B, MethodInfoSize = 0x50;

    // Il2CppImage { name; nameNoExt; assembly; ... }
    public const int ImageAssembly = 0x10;

    // FieldInfo { name; type; parent; offset; token }
    public const int FieldName = 0x00, FieldType = 0x08, FieldParent = 0x10, FieldOffset = 0x18, FieldToken = 0x1C;
    public const int FieldInfoSize = 0x20;

    // Il2CppDelegate（System.Delegate 的实例布局）：
    // method_ptr 0x10、invoke_impl 0x18、m_target 0x20、method 0x28、delegate_trampoline 0x30、extra_arg 0x38、method_code 0x40。
    public const int DelegateMethodPtr = 0x10, DelegateInvokeImpl = 0x18, DelegateTarget = 0x20, DelegateMethod = 0x28, DelegateMethodCode = 0x40;

    /// <summary>vtable 槽位 slot 的方法指针在 Il2CppClass 中的偏移。</summary>
    public static int VtableMethodPointer(int slot) => ClassVtable + slot * VirtualInvokeDataSize;
    /// <summary>vtable 槽位 slot 的 MethodInfo* 在 Il2CppClass 中的偏移。</summary>
    public static int VtableMethodInfo(int slot) => ClassVtable + slot * VirtualInvokeDataSize + 8;
}
