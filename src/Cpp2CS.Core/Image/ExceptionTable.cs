using System.Buffers.Binary;

namespace Cpp2CS.Image;

/// <summary>LSDA action 链上的一条记录。</summary>
public sealed record ExceptionAction(ulong Address, long Filter, long NextOffset, ulong? TypeInfo, string Kind);

/// <summary>
/// ARM64 .eh_frame 的 LSDA（gcc_except_table）解析。
/// 只有带 LSDA 的函数才有异常区间；没有 LSDA 的函数在托管侧没有 try/catch。
/// </summary>
public static class ExceptionTable
{
    public static ExceptionRegion[] Read(ImageDocument image, ulong address, ulong functionStart, ulong functionEnd)
    {
        var cursor = address;
        byte ReadByte() => image.Read(cursor++, 1)[0];
        ulong ReadUleb()
        {
            ulong value = 0;
            for (var shift = 0; shift < 64; shift += 7)
            {
                var b = ReadByte();
                if (shift == 63 && b > 1) throw new InvalidDataException("LSDA ULEB128 溢出");
                value |= (ulong)(b & 127) << shift;
                if ((b & 128) == 0) return value;
            }
            throw new InvalidDataException("LSDA ULEB128 过长");
        }
        long ReadSleb()
        {
            ulong value = 0;
            for (var shift = 0; shift < 64; shift += 7)
            {
                var b = ReadByte();
                if (shift == 63 && b is not (0 or 127)) throw new InvalidDataException("LSDA SLEB128 溢出");
                value |= (ulong)(b & 127) << shift;
                if ((b & 128) != 0) continue;
                if (shift < 57 && (b & 64) != 0) value |= ulong.MaxValue << (shift + 7);
                return unchecked((long)value);
            }
            throw new InvalidDataException("LSDA SLEB128 过长");
        }

        if (ReadByte() != 0xff) throw new NotSupportedException("尚未支持显式 LPStart");
        var typeEncoding = ReadByte();
        ulong? typeEnd = null;
        if (typeEncoding != 0xff)
        {
            // libc++abi scan_eh_tab：classInfoOffset 相对 ULEB128 读完后的位置。
            // 不能在加法左操作数提前取 cursor，否则类型表倒退一个 ULEB128 的长度。
            var offset = ReadUleb();
            typeEnd = checked(cursor + offset);
        }
        // call-site 编码：clang 对 Android 通常写 0x01（ULEB128），本样本为 0x03（udata4）。
        var callSiteEncoding = ReadByte();
        ulong ReadCallSite()
        {
            if (callSiteEncoding == 1) return ReadUleb();
            if (callSiteEncoding == 3) { var value = image.ReadU32(cursor); cursor += 4; return value; }
            throw new NotSupportedException($"尚未支持 call-site 编码 0x{callSiteEncoding:x}");
        }
        // call-site 表长度始终是 ULEB128；表内 start/length/landing 用 call-site 编码（本样本为 0x03 udata4）。
        var length = ReadUleb();
        if (length > 65536) throw new InvalidDataException("LSDA call-site table 超出限制");
        var end = checked(cursor + length);
        var regions = new List<ExceptionRegion>();
        while (cursor < end)
        {
            var start = checked(functionStart + ReadCallSite());
            var limit = checked(start + ReadCallSite());
            var landing = ReadCallSite();
            // action 是动作表的 ULEB128 偏移，与 call-site 字段编码无关（Itanium C++ ABI 的 LSDA 布局）。
            var action = ReadUleb();
            if (start < functionStart || limit > functionEnd || limit < start ||
                (landing != 0 && checked(functionStart + landing) >= functionEnd) ||
                (regions.Count > 0 && start < regions[^1].End) || (landing == 0 && action != 0))
                throw new InvalidDataException("LSDA 区间重叠或超出函数范围");
            regions.Add(new ExceptionRegion(start, limit, landing == 0 ? 0 : checked(functionStart + landing))
            {
                ActionOffset = action,
            });
        }
        if (cursor != end) throw new InvalidDataException("LSDA call-site table 长度不匹配");
        return regions.Select(region => region with { Actions = Actions(region.ActionOffset, end) }).ToArray();

        ExceptionAction[] Actions(ulong offset, ulong tableEnd)
        {
            if (offset == 0) return [];
            var actions = new List<ExceptionAction>();
            cursor = checked(tableEnd + offset - 1);
            var visited = new HashSet<ulong>();
            while (true)
            {
                if (cursor < tableEnd || cursor - tableEnd > 65536 || (typeEnd is { } limit && cursor >= limit) || !visited.Add(cursor))
                    throw new InvalidDataException("LSDA action 链越界或成环");
                var at = cursor;
                var filter = ReadSleb();
                var nextAt = cursor;
                var next = ReadSleb();
                var type = filter > 0 ? TypeInfo(filter) : null;
                actions.Add(new(at, filter, next, type, filter == 0 ? "cleanup"
                    : filter < 0 ? "exception-specification-unresolved"
                    : type is null or 0 ? "catch-all" : "typed-catch"));
                if (next == 0) return actions.ToArray();
                cursor = checked((ulong)((long)nextAt + next));
            }
        }

        ulong? TypeInfo(long index)
        {
            if (typeEnd is not { } limit) throw new InvalidDataException("LSDA catch 缺少类型表");
            var width = (typeEncoding & 15) switch { 0 or 4 or 12 => 8, 3 or 11 => 4, _ => 0 };
            if (width == 0 || (typeEncoding & 0x70) is not (0 or 0x10))
                throw new NotSupportedException($"不支持 LSDA 类型指针编码 0x{typeEncoding:x}");
            var at = checked(limit - checked((ulong)index * (ulong)width));
            if (at < end) throw new InvalidDataException("LSDA 类型索引越界");
            // 返回类型表槽位（或 pcrel 指向的槽位）地址，不解引用：槽位内容依赖动态重定位，
            // 而 IL2CPP 的托管类型筛选不依赖这里的 C++ typeinfo。
            if (typeEncoding == 0) return at;
            var bytes = image.Read(at, width);
            long raw = width == 8 ? BinaryPrimitives.ReadInt64LittleEndian(bytes)
                : (typeEncoding & 15) == 11 ? BinaryPrimitives.ReadInt32LittleEndian(bytes)
                : BinaryPrimitives.ReadUInt32LittleEndian(bytes);
            if (raw == 0) return 0;
            return (typeEncoding & 0x70) == 0x10 ? checked((ulong)((long)at + raw)) : unchecked((ulong)raw);
        }
    }
}
