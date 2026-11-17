using Cpp2CS.Machine.Ssa;
using static Cpp2CS.Idioms.IdiomRewriter;

namespace Cpp2CS.Idioms;

internal static class CleanupPass
{
    internal static void Cleanup(this IdiomState state)
    {
        var trace = Environment.GetEnvironmentVariable("CPP2CS_PASS_TRACE") == "1";
        var watch = System.Diagnostics.Stopwatch.StartNew();
        state.Result.Errors.AddRange(Lowering.Cleanup(state.function));
        if (trace) { Console.Error.WriteLine($"cleanup lowering {watch.Elapsed.TotalSeconds:F2}s"); watch.Restart(); }
        // 规则看到的表达式不含私有栈槽的搬运：转发后再清理一次。
        var rounds = 0;
        while (Cpp2CS.Machine.Storage.FrameForwarding.Run(state.function, state.owner.CallEffects))
        {
            rounds++;
            state.Result.Errors.AddRange(Lowering.Cleanup(state.function));
        }
        if (trace) Console.Error.WriteLine($"cleanup forwarding {rounds} 轮 {watch.Elapsed.TotalSeconds:F2}s");
        if (rounds > 0 && trace)
            Console.Error.WriteLine($"cleanup forwarding {rounds} 轮");
        state.removed.Clear();
        state.defs = new Defs(state.function);
    }
}
