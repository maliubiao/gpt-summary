Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This is the third part of a larger file, and I need to focus only on the code given.
The code defines several methods within the `Simulator` class related to memory access (read/write of bytes, half-words, words), stack management, calling C runtime functions, handling software interrupts (including breakpoints and calls to V8 runtime), and some floating-point utility functions.

Here's a breakdown of the functionalities present in this part:
1. **Memory Access:** `ReadW`, `WriteW`, `ReadWU`, `WriteWU`, `ReadH`, `WriteH`, `ReadBU`, `ReadB`, `WriteB`. These methods handle reading and writing different sizes of data (word, half-word, byte) to memory. They also include alignment checks and tracing.
2. **Stack Management:** `StackLimit`, `GetCentralStackView`. These methods are related to determining the stack limit and getting a view of the stack.
3. **Calling C Runtime:** `SimulatorRuntimeCall`, `SimulatorRuntimeCompareCall`, `SimulatorRuntimeFPFPCall`, `SimulatorRuntimeFPCall`, `SimulatorRuntimeFPIntCall`, `SimulatorRuntimeFPTaggedCall`, `SimulatorRuntimeDirectApiCall`, `SimulatorRuntimeDirectGetterCall`, `MixedRuntimeCall_N`, `CallAnyCTypeFunction`. These define function pointer types and the `CallAnyCTypeFunction` method is used to call C functions based on a signature.
4. **Software Interrupts:** `SoftwareInterrupt`. This function handles software interrupts, which are used for calling V8 runtime functions and debugging (breakpoints). It deals with different types of runtime calls, including those involving floating-point numbers.
5. **Breakpoint Handling:** `IsWatchpoint`, `PrintWatchpoint`, `HandleStop`, `IsStopInstruction`, `IsEnabledStop`, `EnableStop`, `DisableStop`, `IncreaseStopCounter`, `PrintStopInfo`. These methods are used to manage and interact with breakpoints in the simulated environment.
6. **Exception Handling:** `SignalException`. A basic function to signal an exception.
7. **Floating-Point Utilities:** `FPAbs`, `FPUProcessNaNsAndZeros`, `FPUMin`, `FPUMax`, `FPUMinA`, `FPUMaxA`, `FPUCanonalizeNaNArg`, `FPUCanonalizeNaNArgs`, `FPUCanonalizeOperation`. These functions provide utility operations for floating-point numbers, including handling NaN and zero values, and implementing min/max operations with different behaviors.
8. **Instruction Decoding and Execution (TypeOp6 and TypeOp7):** `DecodeTypeOp6`, `DecodeTypeOp7`. These functions are responsible for decoding and simulating the execution of specific instruction types in the LoongArch64 architecture. They handle various branch, jump, and load/store instructions.
这是v8/src/execution/loong64/simulator-loong64.cc的第三部分代码，主要功能可以归纳为以下几点：

1. **内存读写操作的实现:**  提供了不同大小数据类型（字节、半字、字）的内存读取和写入功能。
    * `ReadW`, `WriteW`, `ReadWU`, `WriteWU`: 读取和写入 32 位字（有符号和无符号）。
    * `ReadH`, `WriteH`: 读取和写入 16 位半字（有符号和无符号）。
    * `ReadBU`, `ReadB`, `WriteB`: 读取和写入 8 位字节（有符号和无符号）。
    * 这些函数都包含了 `local_monitor_` 和 `GlobalMonitor` 的通知机制，用于跟踪内存访问，并可能涉及同步控制。
    * 提供了模板函数 `ReadMem` 和 `WriteMem` 用于处理任意大小类型的内存读写，并带有未对齐访问的检查和处理。

2. **模拟器栈的管理:** 提供了获取栈限制和栈视图的功能。
    * `StackLimit`: 返回当前栈的限制，用于检查栈溢出。考虑了 C 栈和模拟器自身的 JS 栈。
    * `GetCentralStackView`: 返回中心栈区域的视图。

3. **不支持指令的处理:** `Format` 函数用于处理模拟器遇到不支持的指令时打印错误信息并停止执行。

4. **调用 C++ Runtime 的框架:** 定义了一系列函数指针类型 (`SimulatorRuntimeCall`, `SimulatorRuntimeCompareCall` 等) 用于表示不同参数和返回类型的 C++ Runtime 函数。
    * `CallAnyCTypeFunction`:  根据给定的函数地址和签名，使用 C 调用约定来调用 C++ 函数。

5. **软件中断的处理 (`SoftwareInterrupt`):** 这是模拟器与 V8 Runtime 交互的关键部分。
    * 当执行到特定的软件中断指令时，`SoftwareInterrupt` 函数会被调用。
    * 它首先检查是否是 `call_rt_redirected` 指令，这是 V8 用来调用 C++ Runtime 函数的机制。
    * 对于 `call_rt_redirected` 指令，它会提取目标函数地址、参数，并根据函数签名调用相应的 C++ 函数。
    * 支持不同类型的 C++ Runtime 调用，包括普通调用、浮点数调用、直接 API 调用和 Getter 调用。
    * 对于非 `call_rt_redirected` 的软件中断，如果 `code` 小于等于 `kMaxStopCode`，则可能是断点或停止指令。
    * 其他情况则认为是调试相关的中断，会调用 `Loong64Debugger` 进行处理。

6. **断点和停止点的管理:** 提供了一系列函数来管理模拟器中的断点和停止点。
    * `IsWatchpoint`: 判断一个代码是否是观察点。
    * `PrintWatchpoint`: 打印观察点信息。
    * `HandleStop`: 处理停止指令，如果启用了该停止点，则会进入调试器。
    * `IsStopInstruction`: 判断一个指令是否是停止指令。
    * `IsEnabledStop`, `EnableStop`, `DisableStop`: 控制停止点的启用和禁用状态。
    * `IncreaseStopCounter`: 增加停止点的计数器。
    * `PrintStopInfo`: 打印停止点的状态信息。

7. **异常处理:** `SignalException` 函数用于在模拟器中抛出异常。

8. **浮点数辅助函数:** 提供了一系列用于浮点数运算的辅助函数，用于处理 NaN、正负零，以及实现 min/max 等操作。
    * `FPAbs`: 计算浮点数的绝对值。
    * `FPUProcessNaNsAndZeros`: 处理 NaN 和零值的比较。
    * `FPUMin`, `FPUMax`, `FPUMinA`, `FPUMaxA`: 计算最小值和最大值，考虑 NaN 和绝对值。
    * `FPUCanonalizeNaNArg`, `FPUCanonalizeNaNArgs`, `FPUCanonalizeOperation`: 用于规范化 NaN 值的处理。

9. **指令解码和执行 (TypeOp6 和 TypeOp7):** `DecodeTypeOp6` 和 `DecodeTypeOp7` 函数负责解码和执行特定类型的 LoongArch64 指令。
    * 这些函数根据指令的操作码，模拟指令的行为，包括算术运算、比较、跳转等。
    * 例如，`DecodeTypeOp6` 处理 `ADDU16I_D`, `BEQZ`, `BNEZ`, `BCZ`, `JIRL`, `B`, `BL`, `BEQ`, `BNE`, `BLT`, `BGE`, `BLTU`, `BGEU` 等指令。
    * `DecodeTypeOp7` 处理 `LU12I_W`, `LU32I_D`, `PCADDI`, `PCALAU12I`, `PCADDU12I` 等指令。

**关于问题中的其他点:**

* **`.tq` 结尾:**  `v8/src/execution/loong64/simulator-loong64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 Torque 源代码。Torque 源代码通常以 `.tq` 结尾。

* **与 JavaScript 的关系 (如果有):**  这部分代码直接模拟了 LoongArch64 架构上的指令执行，是 V8 引擎在 LoongArch64 平台上运行 JavaScript 代码的基础。JavaScript 代码最终会被编译成这种架构的机器码，然后由这个模拟器（在没有硬件支持的情况下）或者实际的硬件执行。

* **代码逻辑推理:**

假设输入以下指令 (以 `DecodeTypeOp6` 中的 `BEQZ` 为例):

```assembly
BEQZ  r3, offset
```

并且假设在模拟器中，寄存器 `r3` 的值为 0，当前程序计数器 `pc` 的值为 `0x1000`，并且指令中编码的 `offset` 值为 `0x10`.

**假设输入:**
* `instr_.Bits(31, 26)` 对应 `BEQZ` 的操作码。
* `rj_reg()` (对应 `r3`) 返回 3。
* `get_register(3)` 返回 0。
* `instr_.Bits(25, 10)` 对应 `offset` 的低 16 位，假设为 `0x0010`。
* `instr_.Bits(4, 0)` 对应 `offset` 的高 5 位，假设为 `0x00`。

**代码逻辑推理:**
1. 进入 `DecodeTypeOp6` 函数的 `case BEQZ:` 分支。
2. 打印指令信息："BEQZ\t r3: 0000000000000000, ".
3. 调用 `BranchOff21Helper(rj() == 0)`，由于 `rj()` 返回 3，`get_register(3)` 返回 0，所以条件 `rj() == 0` 为真。
4. 在 `BranchOff21Helper` 中：
    * `current_pc` 为 `0x1000`。
    * `offs21_low16` 从指令中提取为 `0x0010`。
    * `offs21_high5` 从指令中提取为 `0x00`。
    * `offs` 计算为 `0x0010 | 0x00 = 0x10`。
    * `offs` 被左移 2 位： `0x10 << 2 = 0x40`。
    * `next_pc` 计算为 `0x1000 + 0x40 = 0x1040`。
    * `set_pc(next_pc)` 将程序计数器设置为 `0x1040`。

**预期输出:**
程序计数器 `pc` 的值变为 `0x1040`。

* **用户常见的编程错误:**

    * **内存访问越界:**  由于模拟器直接操作内存地址，如果 JavaScript 代码中存在数组越界等错误，可能导致 `ReadW`, `WriteW` 等函数访问到无效的内存地址，模拟器可能会崩溃或者产生不可预测的行为。

    ```javascript
    let arr = [1, 2, 3];
    let value = arr[10]; // 数组越界
    ```
    在模拟器执行这段代码时，当尝试读取 `arr[10]` 对应的内存地址时，可能会触发错误。

    * **未对齐的内存访问:**  某些架构（包括 LoongArch64）对内存对齐有要求。如果 JavaScript 代码导致生成未对齐的内存访问指令，模拟器的 `ReadMem` 或 `WriteMem` 函数会检测到并调用 `base::OS::Abort()` 终止程序。

    * **调用不存在的 Runtime 函数:** 如果模拟器尝试调用 V8 Runtime 中不存在的函数，`SoftwareInterrupt` 函数可能会因为找不到对应的处理而出现错误。

**总结:**

这部分代码是 V8 引擎在 LoongArch64 平台模拟执行机器码的核心组件，负责模拟内存访问、控制流、与 V8 Runtime 的交互以及处理调试相关的操作。它为在没有实际 LoongArch64 硬件的情况下运行和测试 V8 引擎提供了基础。

Prompt: 
```
这是目录为v8/src/execution/loong64/simulator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/loong64/simulator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

"""
tr;
}

void Simulator::WriteH(int64_t addr, uint16_t value, Instruction* instr) {
  local_monitor_.NotifyStore();
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
  TraceMemWr(addr, value, HALF);
  uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
  *ptr = value;
  return;
}

void Simulator::WriteH(int64_t addr, int16_t value, Instruction* instr) {
  local_monitor_.NotifyStore();
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
  TraceMemWr(addr, value, HALF);
  int16_t* ptr = reinterpret_cast<int16_t*>(addr);
  *ptr = value;
  return;
}

uint32_t Simulator::ReadBU(int64_t addr) {
  local_monitor_.NotifyLoad();
  uint8_t* ptr = reinterpret_cast<uint8_t*>(addr);
  TraceMemRd(addr, static_cast<int64_t>(*ptr));
  return *ptr & 0xFF;
}

int32_t Simulator::ReadB(int64_t addr) {
  local_monitor_.NotifyLoad();
  int8_t* ptr = reinterpret_cast<int8_t*>(addr);
  TraceMemRd(addr, static_cast<int64_t>(*ptr));
  return *ptr;
}

void Simulator::WriteB(int64_t addr, uint8_t value) {
  local_monitor_.NotifyStore();
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
  TraceMemWr(addr, value, BYTE);
  uint8_t* ptr = reinterpret_cast<uint8_t*>(addr);
  *ptr = value;
}

void Simulator::WriteB(int64_t addr, int8_t value) {
  local_monitor_.NotifyStore();
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
  TraceMemWr(addr, value, BYTE);
  int8_t* ptr = reinterpret_cast<int8_t*>(addr);
  *ptr = value;
}

template <typename T>
T Simulator::ReadMem(int64_t addr, Instruction* instr) {
  int alignment_mask = (1 << sizeof(T)) - 1;
  if ((addr & alignment_mask) == 0) {
    local_monitor_.NotifyLoad();
    T* ptr = reinterpret_cast<T*>(addr);
    TraceMemRd(addr, *ptr);
    return *ptr;
  }
  PrintF("Unaligned read of type sizeof(%ld) at 0x%08lx, pc=0x%08" V8PRIxPTR
         "\n",
         sizeof(T), addr, reinterpret_cast<intptr_t>(instr));
  base::OS::Abort();
  return 0;
}

template <typename T>
void Simulator::WriteMem(int64_t addr, T value, Instruction* instr) {
  int alignment_mask = (1 << sizeof(T)) - 1;
  if ((addr & alignment_mask) == 0) {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    T* ptr = reinterpret_cast<T*>(addr);
    *ptr = value;
    TraceMemWr(addr, value);
    return;
  }
  PrintF("Unaligned write of type sizeof(%ld) at 0x%08lx, pc=0x%08" V8PRIxPTR
         "\n",
         sizeof(T), addr, reinterpret_cast<intptr_t>(instr));
  base::OS::Abort();
}

// Returns the limit of the stack area to enable checking for stack overflows.
uintptr_t Simulator::StackLimit(uintptr_t c_limit) const {
  // The simulator uses a separate JS stack. If we have exhausted the C stack,
  // we also drop down the JS limit to reflect the exhaustion on the JS stack.
  if (base::Stack::GetCurrentStackPosition() < c_limit) {
    return get_sp();
  }

  // Otherwise the limit is the JS stack. Leave a safety margin
  // to prevent overrunning the stack when pushing values.
  return stack_limit_ + kAdditionalStackMargin;
}

base::Vector<uint8_t> Simulator::GetCentralStackView() const {
  // We do not add an additional safety margin as above in
  // Simulator::StackLimit, as users of this method are expected to add their
  // own margin.
  return base::VectorOf(
      reinterpret_cast<uint8_t*>(stack_) + kStackProtectionSize,
      UsableStackSize());
}

// Unsupported instructions use Format to print an error and stop execution.
void Simulator::Format(Instruction* instr, const char* format) {
  PrintF("Simulator found unsupported instruction:\n 0x%08" PRIxPTR " : %s\n",
         reinterpret_cast<intptr_t>(instr), format);
  UNIMPLEMENTED();
}

// Calls into the V8 runtime are based on this very simple interface.
// Note: To be able to return two values from some calls the code in runtime.cc
// uses the ObjectPair which is essentially two 32-bit values stuffed into a
// 64-bit value. With the code below we assume that all runtime calls return
// 64 bits of result. If they don't, the v1 result register contains a bogus
// value, which is fine because it is caller-saved.

using SimulatorRuntimeCall = ObjectPair (*)(
    int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4,
    int64_t arg5, int64_t arg6, int64_t arg7, int64_t arg8, int64_t arg9,
    int64_t arg10, int64_t arg11, int64_t arg12, int64_t arg13, int64_t arg14,
    int64_t arg15, int64_t arg16, int64_t arg17, int64_t arg18, int64_t arg19);

// These prototypes handle the four types of FP calls.
using SimulatorRuntimeCompareCall = int64_t (*)(double darg0, double darg1);
using SimulatorRuntimeFPFPCall = double (*)(double darg0, double darg1);
using SimulatorRuntimeFPCall = double (*)(double darg0);
using SimulatorRuntimeFPIntCall = double (*)(double darg0, int32_t arg0);
// Define four args for future flexibility; at the time of this writing only
// one is ever used.
using SimulatorRuntimeFPTaggedCall = double (*)(int64_t arg0, int64_t arg1,
                                                int64_t arg2, int64_t arg3);

// This signature supports direct call in to API function native callback
// (refer to InvocationCallback in v8.h).
using SimulatorRuntimeDirectApiCall = void (*)(int64_t arg0);

// This signature supports direct call to accessor getter callback.
using SimulatorRuntimeDirectGetterCall = void (*)(int64_t arg0, int64_t arg1);

using MixedRuntimeCall_0 = AnyCType (*)();

#define BRACKETS(ident, N) ident[N]

#define REP_0(expr, FMT)
#define REP_1(expr, FMT) FMT(expr, 0)
#define REP_2(expr, FMT) REP_1(expr, FMT), FMT(expr, 1)
#define REP_3(expr, FMT) REP_2(expr, FMT), FMT(expr, 2)
#define REP_4(expr, FMT) REP_3(expr, FMT), FMT(expr, 3)
#define REP_5(expr, FMT) REP_4(expr, FMT), FMT(expr, 4)
#define REP_6(expr, FMT) REP_5(expr, FMT), FMT(expr, 5)
#define REP_7(expr, FMT) REP_6(expr, FMT), FMT(expr, 6)
#define REP_8(expr, FMT) REP_7(expr, FMT), FMT(expr, 7)
#define REP_9(expr, FMT) REP_8(expr, FMT), FMT(expr, 8)
#define REP_10(expr, FMT) REP_9(expr, FMT), FMT(expr, 9)
#define REP_11(expr, FMT) REP_10(expr, FMT), FMT(expr, 10)
#define REP_12(expr, FMT) REP_11(expr, FMT), FMT(expr, 11)
#define REP_13(expr, FMT) REP_12(expr, FMT), FMT(expr, 12)
#define REP_14(expr, FMT) REP_13(expr, FMT), FMT(expr, 13)
#define REP_15(expr, FMT) REP_14(expr, FMT), FMT(expr, 14)
#define REP_16(expr, FMT) REP_15(expr, FMT), FMT(expr, 15)
#define REP_17(expr, FMT) REP_16(expr, FMT), FMT(expr, 16)
#define REP_18(expr, FMT) REP_17(expr, FMT), FMT(expr, 17)
#define REP_19(expr, FMT) REP_18(expr, FMT), FMT(expr, 18)
#define REP_20(expr, FMT) REP_19(expr, FMT), FMT(expr, 19)

#define GEN_MAX_PARAM_COUNT(V) \
  V(0)                         \
  V(1)                         \
  V(2)                         \
  V(3)                         \
  V(4)                         \
  V(5)                         \
  V(6)                         \
  V(7)                         \
  V(8)                         \
  V(9)                         \
  V(10)                        \
  V(11)                        \
  V(12)                        \
  V(13)                        \
  V(14)                        \
  V(15)                        \
  V(16)                        \
  V(17)                        \
  V(18)                        \
  V(19)                        \
  V(20)

#define MIXED_RUNTIME_CALL(N) \
  using MixedRuntimeCall_##N = AnyCType (*)(REP_##N(AnyCType arg, CONCAT));

GEN_MAX_PARAM_COUNT(MIXED_RUNTIME_CALL)
#undef MIXED_RUNTIME_CALL

#define CALL_ARGS(N) REP_##N(args, BRACKETS)
#define CALL_TARGET_VARARG(N)                                   \
  if (signature.ParameterCount() == N) { /* NOLINT */           \
    MixedRuntimeCall_##N target =                               \
        reinterpret_cast<MixedRuntimeCall_##N>(target_address); \
    result = target(CALL_ARGS(N));                              \
  } else /* NOLINT */

// Configuration for C calling convention (see c-linkage.cc).
#define PARAM_REGISTERS a0, a1, a2, a3, a4, a5, a6, a7
#define RETURN_REGISTER a0
#define FP_PARAM_REGISTERS f0, f1, f2, f3, f4, f5, f6, f7
#define FP_RETURN_REGISTER f0

void Simulator::CallAnyCTypeFunction(Address target_address,
                                     const EncodedCSignature& signature) {
  const int64_t* stack_pointer = reinterpret_cast<int64_t*>(get_register(sp));
  const double* double_stack_pointer =
      reinterpret_cast<double*>(get_register(sp));

  const Register kParamRegisters[] = {PARAM_REGISTERS};
  const FPURegister kFPParamRegisters[] = {FP_PARAM_REGISTERS};

  int num_gp_params = 0, num_fp_params = 0, num_stack_params = 0;

  CHECK_LE(signature.ParameterCount(), kMaxCParameters);
  static_assert(sizeof(AnyCType) == 8, "AnyCType is assumed to be 64-bit.");
  AnyCType args[kMaxCParameters];
  for (int i = 0; i < signature.ParameterCount(); ++i) {
    if (signature.IsFloat(i)) {
      if (num_fp_params < 8) {
        args[i].double_value =
            get_fpu_register_double(kFPParamRegisters[num_fp_params++]);
      } else if (num_gp_params < 8) {
        args[i].int64_value = get_register(kParamRegisters[num_gp_params++]);
      } else {
        args[i].double_value = double_stack_pointer[num_stack_params++];
      }
    } else {
      if (num_gp_params < 8) {
        args[i].int64_value = get_register(kParamRegisters[num_gp_params++]);
      } else {
        args[i].int64_value = stack_pointer[num_stack_params++];
      }
    }
  }
  AnyCType result;
  GEN_MAX_PARAM_COUNT(CALL_TARGET_VARARG)
  /* else */ {
    UNREACHABLE();
  }
  static_assert(20 == kMaxCParameters,
                "If you've changed kMaxCParameters, please change the "
                "GEN_MAX_PARAM_COUNT macro.");

#undef CALL_TARGET_VARARG
#undef CALL_ARGS
#undef GEN_MAX_PARAM_COUNT

  if (signature.IsReturnFloat()) {
    set_fpu_register_double(FP_RETURN_REGISTER, result.double_value);
  } else {
    set_register(RETURN_REGISTER, result.int64_value);
  }
}

#undef PARAM_REGISTERS
#undef RETURN_REGISTER
#undef FP_PARAM_REGISTERS
#undef FP_RETURN_REGISTER

// Software interrupt instructions are used by the simulator to call into the
// C-based V8 runtime. They are also used for debugging with simulator.
void Simulator::SoftwareInterrupt() {
  int32_t opcode_hi15 = instr_.Bits(31, 17);
  CHECK_EQ(opcode_hi15, 0x15);
  uint32_t code = instr_.Bits(14, 0);
  // We first check if we met a call_rt_redirected.
  if (instr_.InstructionBits() == rtCallRedirInstr) {
    Redirection* redirection = Redirection::FromInstruction(instr_.instr());

    // This is dodgy but it works because the C entry stubs are never moved.
    int64_t saved_ra = get_register(ra);
    intptr_t external =
        reinterpret_cast<intptr_t>(redirection->external_function());

    Address func_addr =
        reinterpret_cast<Address>(redirection->external_function());
    SimulatorData* simulator_data = isolate_->simulator_data();
    DCHECK_NOT_NULL(simulator_data);
    const EncodedCSignature& signature =
        simulator_data->GetSignatureForTarget(func_addr);
    if (signature.IsValid()) {
      CHECK_EQ(redirection->type(), ExternalReference::FAST_C_CALL);
      CallAnyCTypeFunction(external, signature);
      set_register(ra, saved_ra);
      set_pc(get_register(ra));
      return;
    }

    int64_t* stack_pointer = reinterpret_cast<int64_t*>(get_register(sp));

    int64_t arg0 = get_register(a0);
    int64_t arg1 = get_register(a1);
    int64_t arg2 = get_register(a2);
    int64_t arg3 = get_register(a3);
    int64_t arg4 = get_register(a4);
    int64_t arg5 = get_register(a5);
    int64_t arg6 = get_register(a6);
    int64_t arg7 = get_register(a7);
    int64_t arg8 = stack_pointer[0];
    int64_t arg9 = stack_pointer[1];
    int64_t arg10 = stack_pointer[2];
    int64_t arg11 = stack_pointer[3];
    int64_t arg12 = stack_pointer[4];
    int64_t arg13 = stack_pointer[5];
    int64_t arg14 = stack_pointer[6];
    int64_t arg15 = stack_pointer[7];
    int64_t arg16 = stack_pointer[8];
    int64_t arg17 = stack_pointer[9];
    int64_t arg18 = stack_pointer[10];
    int64_t arg19 = stack_pointer[11];
    static_assert(kMaxCParameters == 20);

    bool fp_call =
        (redirection->type() == ExternalReference::BUILTIN_FP_FP_CALL) ||
        (redirection->type() == ExternalReference::BUILTIN_COMPARE_CALL) ||
        (redirection->type() == ExternalReference::BUILTIN_FP_CALL) ||
        (redirection->type() == ExternalReference::BUILTIN_FP_INT_CALL);

    {
      // With the hard floating point calling convention, double
      // arguments are passed in FPU registers. Fetch the arguments
      // from there and call the builtin using soft floating point
      // convention.
      switch (redirection->type()) {
        case ExternalReference::BUILTIN_FP_FP_CALL:
        case ExternalReference::BUILTIN_COMPARE_CALL:
          arg0 = get_fpu_register(f0);
          arg1 = get_fpu_register(f1);
          arg2 = get_fpu_register(f2);
          arg3 = get_fpu_register(f3);
          break;
        case ExternalReference::BUILTIN_FP_CALL:
          arg0 = get_fpu_register(f0);
          arg1 = get_fpu_register(f1);
          break;
        case ExternalReference::BUILTIN_FP_INT_CALL:
          arg0 = get_fpu_register(f0);
          arg1 = get_fpu_register(f1);
          arg2 = get_register(a2);
          break;
        default:
          break;
      }
    }

    // Based on CpuFeatures::IsSupported(FPU), Loong64 will use either hardware
    // FPU, or gcc soft-float routines. Hardware FPU is simulated in this
    // simulator. Soft-float has additional abstraction of ExternalReference,
    // to support serialization.
    if (fp_call) {
      double dval0, dval1;  // one or two double parameters
      int32_t ival;         // zero or one integer parameters
      int64_t iresult = 0;  // integer return value
      double dresult = 0;   // double return value
      GetFpArgs(&dval0, &dval1, &ival);
      SimulatorRuntimeCall generic_target =
          reinterpret_cast<SimulatorRuntimeCall>(external);
      if (v8_flags.trace_sim) {
        switch (redirection->type()) {
          case ExternalReference::BUILTIN_FP_FP_CALL:
          case ExternalReference::BUILTIN_COMPARE_CALL:
            PrintF("Call to host function at %p with args %f, %f",
                   reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                   dval0, dval1);
            break;
          case ExternalReference::BUILTIN_FP_CALL:
            PrintF("Call to host function at %p with arg %f",
                   reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                   dval0);
            break;
          case ExternalReference::BUILTIN_FP_INT_CALL:
            PrintF("Call to host function at %p with args %f, %d",
                   reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                   dval0, ival);
            break;
          default:
            UNREACHABLE();
        }
      }
      switch (redirection->type()) {
        case ExternalReference::BUILTIN_COMPARE_CALL: {
          SimulatorRuntimeCompareCall target =
              reinterpret_cast<SimulatorRuntimeCompareCall>(external);
          iresult = target(dval0, dval1);
          set_register(v0, static_cast<int64_t>(iresult));
          //  set_register(v1, static_cast<int64_t>(iresult >> 32));
          break;
        }
        case ExternalReference::BUILTIN_FP_FP_CALL: {
          SimulatorRuntimeFPFPCall target =
              reinterpret_cast<SimulatorRuntimeFPFPCall>(external);
          dresult = target(dval0, dval1);
          SetFpResult(dresult);
          break;
        }
        case ExternalReference::BUILTIN_FP_CALL: {
          SimulatorRuntimeFPCall target =
              reinterpret_cast<SimulatorRuntimeFPCall>(external);
          dresult = target(dval0);
          SetFpResult(dresult);
          break;
        }
        case ExternalReference::BUILTIN_FP_INT_CALL: {
          SimulatorRuntimeFPIntCall target =
              reinterpret_cast<SimulatorRuntimeFPIntCall>(external);
          dresult = target(dval0, ival);
          SetFpResult(dresult);
          break;
        }
        default:
          UNREACHABLE();
      }
      if (v8_flags.trace_sim) {
        switch (redirection->type()) {
          case ExternalReference::BUILTIN_COMPARE_CALL:
            PrintF("Returned %08x\n", static_cast<int32_t>(iresult));
            break;
          case ExternalReference::BUILTIN_FP_FP_CALL:
          case ExternalReference::BUILTIN_FP_CALL:
          case ExternalReference::BUILTIN_FP_INT_CALL:
            PrintF("Returned %f\n", dresult);
            break;
          default:
            UNREACHABLE();
        }
      }
    } else if (redirection->type() ==
               ExternalReference::BUILTIN_FP_POINTER_CALL) {
      if (v8_flags.trace_sim) {
        PrintF("Call to host function at %p args %08" PRIx64 " \n",
               reinterpret_cast<void*>(external), arg0);
      }
      SimulatorRuntimeFPTaggedCall target =
          reinterpret_cast<SimulatorRuntimeFPTaggedCall>(external);
      double dresult = target(arg0, arg1, arg2, arg3);
      SetFpResult(dresult);
      if (v8_flags.trace_sim) {
        PrintF("Returned %f\n", dresult);
      }
    } else if (redirection->type() == ExternalReference::DIRECT_API_CALL) {
      if (v8_flags.trace_sim) {
        PrintF("Call to host function at %p args %08" PRIx64 " \n",
               reinterpret_cast<void*>(external), arg0);
      }
      SimulatorRuntimeDirectApiCall target =
          reinterpret_cast<SimulatorRuntimeDirectApiCall>(external);
      target(arg0);
    } else if (redirection->type() == ExternalReference::DIRECT_GETTER_CALL) {
      if (v8_flags.trace_sim) {
        PrintF("Call to host function at %p args %08" PRIx64 "  %08" PRIx64
               " \n",
               reinterpret_cast<void*>(external), arg0, arg1);
      }
      SimulatorRuntimeDirectGetterCall target =
          reinterpret_cast<SimulatorRuntimeDirectGetterCall>(external);
      target(arg0, arg1);
    } else {
      DCHECK(redirection->type() == ExternalReference::BUILTIN_CALL ||
             redirection->type() == ExternalReference::BUILTIN_CALL_PAIR);
      SimulatorRuntimeCall target =
          reinterpret_cast<SimulatorRuntimeCall>(external);
      if (v8_flags.trace_sim) {
        PrintF(
            "Call to host function at %p "
            "args %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64
            " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64
            " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64
            " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64
            " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64 " , %08" PRIx64
            " \n",
            reinterpret_cast<void*>(FUNCTION_ADDR(target)), arg0, arg1, arg2,
            arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
            arg13, arg14, arg15, arg16, arg17, arg18, arg19);
      }
      ObjectPair result = target(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                                 arg8, arg9, arg10, arg11, arg12, arg13, arg14,
                                 arg15, arg16, arg17, arg18, arg19);
      set_register(v0, (int64_t)(result.x));
      set_register(v1, (int64_t)(result.y));
    }
    if (v8_flags.trace_sim) {
      PrintF("Returned %08" PRIx64 "  : %08" PRIx64 " \n", get_register(v1),
             get_register(v0));
    }
    set_register(ra, saved_ra);
    set_pc(get_register(ra));

  } else if (code <= kMaxStopCode) {
    if (IsWatchpoint(code)) {
      PrintWatchpoint(code);
    } else {
      IncreaseStopCounter(code);
      HandleStop(code, instr_.instr());
    }
  } else {
    // All remaining break_ codes, and all traps are handled here.
    Loong64Debugger dbg(this);
    dbg.Debug();
  }
}

// Stop helper functions.
bool Simulator::IsWatchpoint(uint64_t code) {
  return (code <= kMaxWatchpointCode);
}

void Simulator::PrintWatchpoint(uint64_t code) {
  Loong64Debugger dbg(this);
  ++break_count_;
  PrintF("\n---- break %" PRId64 "  marker: %3d  (instr count: %8" PRId64
         " ) ----------"
         "----------------------------------",
         code, break_count_, icount_);
  dbg.PrintAllRegs();  // Print registers and continue running.
}

void Simulator::HandleStop(uint64_t code, Instruction* instr) {
  // Stop if it is enabled, otherwise go on jumping over the stop
  // and the message address.
  if (IsEnabledStop(code)) {
    Loong64Debugger dbg(this);
    dbg.Stop(instr);
  }
}

bool Simulator::IsStopInstruction(Instruction* instr) {
  int32_t opcode_hi15 = instr->Bits(31, 17);
  uint32_t code = static_cast<uint32_t>(instr->Bits(14, 0));
  return (opcode_hi15 == 0x15) && code > kMaxWatchpointCode &&
         code <= kMaxStopCode;
}

bool Simulator::IsEnabledStop(uint64_t code) {
  DCHECK_LE(code, kMaxStopCode);
  DCHECK_GT(code, kMaxWatchpointCode);
  return !(watched_stops_[code].count & kStopDisabledBit);
}

void Simulator::EnableStop(uint64_t code) {
  if (!IsEnabledStop(code)) {
    watched_stops_[code].count &= ~kStopDisabledBit;
  }
}

void Simulator::DisableStop(uint64_t code) {
  if (IsEnabledStop(code)) {
    watched_stops_[code].count |= kStopDisabledBit;
  }
}

void Simulator::IncreaseStopCounter(uint64_t code) {
  DCHECK_LE(code, kMaxStopCode);
  if ((watched_stops_[code].count & ~(1 << 31)) == 0x7FFFFFFF) {
    PrintF("Stop counter for code %" PRId64
           "  has overflowed.\n"
           "Enabling this code and reseting the counter to 0.\n",
           code);
    watched_stops_[code].count = 0;
    EnableStop(code);
  } else {
    watched_stops_[code].count++;
  }
}

// Print a stop status.
void Simulator::PrintStopInfo(uint64_t code) {
  if (code <= kMaxWatchpointCode) {
    PrintF("That is a watchpoint, not a stop.\n");
    return;
  } else if (code > kMaxStopCode) {
    PrintF("Code too large, only %u stops can be used\n", kMaxStopCode + 1);
    return;
  }
  const char* state = IsEnabledStop(code) ? "Enabled" : "Disabled";
  int32_t count = watched_stops_[code].count & ~kStopDisabledBit;
  // Don't print the state of unused breakpoints.
  if (count != 0) {
    if (watched_stops_[code].desc) {
      PrintF("stop %" PRId64 "  - 0x%" PRIx64 " : \t%s, \tcounter = %i, \t%s\n",
             code, code, state, count, watched_stops_[code].desc);
    } else {
      PrintF("stop %" PRId64 "  - 0x%" PRIx64 " : \t%s, \tcounter = %i\n", code,
             code, state, count);
    }
  }
}

void Simulator::SignalException(Exception e) {
  FATAL("Error: Exception %i raised.", static_cast<int>(e));
}

template <typename T>
static T FPAbs(T a);

template <>
double FPAbs<double>(double a) {
  return fabs(a);
}

template <>
float FPAbs<float>(float a) {
  return fabsf(a);
}

template <typename T>
static bool FPUProcessNaNsAndZeros(T a, T b, MaxMinKind kind, T* result) {
  if (std::isnan(a) && std::isnan(b)) {
    *result = a;
  } else if (std::isnan(a)) {
    *result = b;
  } else if (std::isnan(b)) {
    *result = a;
  } else if (b == a) {
    // Handle -0.0 == 0.0 case.
    // std::signbit() returns int 0 or 1 so subtracting MaxMinKind::kMax
    // negates the result.
    *result = std::signbit(b) - static_cast<int>(kind) ? b : a;
  } else {
    return false;
  }
  return true;
}

template <typename T>
static T FPUMin(T a, T b) {
  T result;
  if (FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMin, &result)) {
    return result;
  } else {
    return b < a ? b : a;
  }
}

template <typename T>
static T FPUMax(T a, T b) {
  T result;
  if (FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMax, &result)) {
    return result;
  } else {
    return b > a ? b : a;
  }
}

template <typename T>
static T FPUMinA(T a, T b) {
  T result;
  if (!FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMin, &result)) {
    if (FPAbs(a) < FPAbs(b)) {
      result = a;
    } else if (FPAbs(b) < FPAbs(a)) {
      result = b;
    } else {
      result = a < b ? a : b;
    }
  }
  return result;
}

template <typename T>
static T FPUMaxA(T a, T b) {
  T result;
  if (!FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMin, &result)) {
    if (FPAbs(a) > FPAbs(b)) {
      result = a;
    } else if (FPAbs(b) > FPAbs(a)) {
      result = b;
    } else {
      result = a > b ? a : b;
    }
  }
  return result;
}

enum class KeepSign : bool { no = false, yes };

template <typename T, typename std::enable_if<std::is_floating_point<T>::value,
                                              int>::type = 0>
T FPUCanonalizeNaNArg(T result, T arg, KeepSign keepSign = KeepSign::no) {
  DCHECK(std::isnan(arg));
  T qNaN = std::numeric_limits<T>::quiet_NaN();
  if (keepSign == KeepSign::yes) {
    return std::copysign(qNaN, result);
  }
  return qNaN;
}

template <typename T>
T FPUCanonalizeNaNArgs(T result, KeepSign keepSign, T first) {
  if (std::isnan(first)) {
    return FPUCanonalizeNaNArg(result, first, keepSign);
  }
  return result;
}

template <typename T, typename... Args>
T FPUCanonalizeNaNArgs(T result, KeepSign keepSign, T first, Args... args) {
  if (std::isnan(first)) {
    return FPUCanonalizeNaNArg(result, first, keepSign);
  }
  return FPUCanonalizeNaNArgs(result, keepSign, args...);
}

template <typename Func, typename T, typename... Args>
T FPUCanonalizeOperation(Func f, T first, Args... args) {
  return FPUCanonalizeOperation(f, KeepSign::no, first, args...);
}

template <typename Func, typename T, typename... Args>
T FPUCanonalizeOperation(Func f, KeepSign keepSign, T first, Args... args) {
  T result = f(first, args...);
  if (std::isnan(result)) {
    result = FPUCanonalizeNaNArgs(result, keepSign, first, args...);
  }
  return result;
}

// Handle execution based on instruction types.
void Simulator::DecodeTypeOp6() {
  int64_t alu_out;
  // Next pc.
  int64_t next_pc = bad_ra;

  // Branch instructions common part.
  auto BranchAndLinkHelper = [this, &next_pc]() {
    int64_t current_pc = get_pc();
    set_register(ra, current_pc + kInstrSize);
    int32_t offs26_low16 =
        static_cast<uint32_t>(instr_.Bits(25, 10) << 16) >> 16;
    int32_t offs26_high10 = static_cast<int32_t>(instr_.Bits(9, 0) << 22) >> 6;
    int32_t offs26 = offs26_low16 | offs26_high10;
    next_pc = current_pc + (offs26 << 2);
    printf_instr("Offs26: %08x\n", offs26);
    set_pc(next_pc);
  };

  auto BranchOff16Helper = [this, &next_pc](bool do_branch) {
    int64_t current_pc = get_pc();
    int32_t offs16 = static_cast<int32_t>(instr_.Bits(25, 10) << 16) >> 16;
    printf_instr("Offs16: %08x\n", offs16);
    int32_t offs = do_branch ? (offs16 << 2) : kInstrSize;
    next_pc = current_pc + offs;
    set_pc(next_pc);
  };

  auto BranchOff21Helper = [this, &next_pc](bool do_branch) {
    int64_t current_pc = get_pc();
    int32_t offs21_low16 =
        static_cast<uint32_t>(instr_.Bits(25, 10) << 16) >> 16;
    int32_t offs21_high5 = static_cast<int32_t>(instr_.Bits(4, 0) << 27) >> 11;
    int32_t offs = offs21_low16 | offs21_high5;
    printf_instr("Offs21: %08x\n", offs);
    offs = do_branch ? (offs << 2) : kInstrSize;
    next_pc = current_pc + offs;
    set_pc(next_pc);
  };

  auto BranchOff26Helper = [this, &next_pc]() {
    int64_t current_pc = get_pc();
    int32_t offs26_low16 =
        static_cast<uint32_t>(instr_.Bits(25, 10) << 16) >> 16;
    int32_t offs26_high10 = static_cast<int32_t>(instr_.Bits(9, 0) << 22) >> 6;
    int32_t offs26 = offs26_low16 | offs26_high10;
    next_pc = current_pc + (offs26 << 2);
    printf_instr("Offs26: %08x\n", offs26);
    set_pc(next_pc);
  };

  auto JumpOff16Helper = [this, &next_pc]() {
    int32_t offs16 = static_cast<int32_t>(instr_.Bits(25, 10) << 16) >> 16;
    printf_instr("JIRL\t %s: %016lx, %s: %016lx, offs16: %x\n",
                 Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                 rj(), offs16);
    set_register(rd_reg(), get_pc() + kInstrSize);
    next_pc = rj() + (offs16 << 2);
    set_pc(next_pc);
  };

  switch (instr_.Bits(31, 26) << 26) {
    case ADDU16I_D: {
      printf_instr("ADDU16I_D\t %s: %016lx, %s: %016lx, si16: %d\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si16());
      int32_t si16_upper = static_cast<int32_t>(si16()) << 16;
      alu_out = static_cast<int64_t>(si16_upper) + rj();
      SetResult(rd_reg(), alu_out);
      break;
    }
    case BEQZ:
      printf_instr("BEQZ\t %s: %016lx, ", Registers::Name(rj_reg()), rj());
      BranchOff21Helper(rj() == 0);
      break;
    case BNEZ:
      printf_instr("BNEZ\t %s: %016lx, ", Registers::Name(rj_reg()), rj());
      BranchOff21Helper(rj() != 0);
      break;
    case BCZ: {
      if (instr_.Bits(9, 8) == 0b00) {
        // BCEQZ
        printf_instr("BCEQZ\t fcc%d: %s, ", cj_reg(), cj() ? "True" : "False");
        BranchOff21Helper(cj() == false);
      } else if (instr_.Bits(9, 8) == 0b01) {
        // BCNEZ
        printf_instr("BCNEZ\t fcc%d: %s, ", cj_reg(), cj() ? "True" : "False");
        BranchOff21Helper(cj() == true);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case JIRL:
      JumpOff16Helper();
      break;
    case B:
      printf_instr("B\t ");
      BranchOff26Helper();
      break;
    case BL:
      printf_instr("BL\t ");
      BranchAndLinkHelper();
      break;
    case BEQ:
      printf_instr("BEQ\t %s: %016lx, %s, %016lx, ", Registers::Name(rj_reg()),
                   rj(), Registers::Name(rd_reg()), rd());
      BranchOff16Helper(rj() == rd());
      break;
    case BNE:
      printf_instr("BNE\t %s: %016lx, %s, %016lx, ", Registers::Name(rj_reg()),
                   rj(), Registers::Name(rd_reg()), rd());
      BranchOff16Helper(rj() != rd());
      break;
    case BLT:
      printf_instr("BLT\t %s: %016lx, %s, %016lx, ", Registers::Name(rj_reg()),
                   rj(), Registers::Name(rd_reg()), rd());
      BranchOff16Helper(rj() < rd());
      break;
    case BGE:
      printf_instr("BGE\t %s: %016lx, %s, %016lx, ", Registers::Name(rj_reg()),
                   rj(), Registers::Name(rd_reg()), rd());
      BranchOff16Helper(rj() >= rd());
      break;
    case BLTU:
      printf_instr("BLTU\t %s: %016lx, %s, %016lx, ", Registers::Name(rj_reg()),
                   rj(), Registers::Name(rd_reg()), rd());
      BranchOff16Helper(rj_u() < rd_u());
      break;
    case BGEU:
      printf_instr("BGEU\t %s: %016lx, %s, %016lx, ", Registers::Name(rj_reg()),
                   rj(), Registers::Name(rd_reg()), rd());
      BranchOff16Helper(rj_u() >= rd_u());
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeOp7() {
  int64_t alu_out;

  switch (instr_.Bits(31, 25) << 25) {
    case LU12I_W: {
      printf_instr("LU12I_W\t %s: %016lx, si20: %d\n",
                   Registers::Name(rd_reg()), rd(), si20());
      int32_t si20_upper = static_cast<int32_t>(si20() << 12);
      SetResult(rd_reg(), static_cast<int64_t>(si20_upper));
      break;
    }
    case LU32I_D: {
      printf_instr("LU32I_D\t %s: %016lx, si20: %d\n",
                   Registers::Name(rd_reg()), rd(), si20());
      int32_t si20_signExtend = static_cast<int32_t>(si20() << 12) >> 12;
      int64_t lower_32bit_mask = 0xFFFFFFFF;
      alu_out = (static_cast<int64_t>(si20_signExtend) << 32) |
                (rd() & lower_32bit_mask);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case PCADDI: {
      printf_instr("PCADDI\t %s: %016lx, si20: %d\n", Registers::Name(rd_reg()),
                   rd(), si20());
      int32_t si20_signExtend = static_cast<int32_t>(si20() << 12) >> 10;
      int64_t current_pc = get_pc();
      alu_out = static_cast<int64_t>(si20_signExtend) + current_pc;
      SetResult(rd_reg(), alu_out);
      break;
    }
    case PCALAU12I: {
      printf_instr("PCALAU12I\t %s: %016lx, si20: %d\n",
                   Registers::Name(rd_reg()), rd(), si20());
      int32_t si20_signExtend = static_cast<int32_t>(si20() << 12);
      int64_t current_pc = get_pc();
      int64_t clear_lower12bit_mask = 0xFFFFFFFFFFFFF000;
      alu_out = static_cast<int64_t>(si20_signExtend) + current_pc;
      SetResult(rd_reg(), alu_out & clear_lower12bit_mask);
      break;
    }
    case PCADDU12I: {
      printf_instr("PCADDU12I\t %s: %016lx, si20: %d\n",
                   Registers::Name(rd_reg()), rd(), si20());
      int32_t si20_signExtend = static_cast<int32_t>(si20
"""


```