Response: The user wants to understand the functionality of the provided C++ code snippet. This is part 2 of a 4-part file, which suggests the entire file implements a simulator for the LoongArch64 architecture within the V8 JavaScript engine.

The code in this part focuses on:

1. **Memory Access:** Functions for reading and writing different sizes of data (bytes, half-words, words, double-words) to memory. It handles both signed and unsigned variants. It also includes checks for unaligned memory access.
2. **Stack Management:** Functions to determine the stack limit and get a view of the central stack.
3. **Runtime Calls:**  Defines structures and functions for calling into the V8 runtime from the simulated environment. This includes handling different calling conventions for regular functions and floating-point functions.
4. **Software Interrupts:** Implements the handling of software interrupts, which are used to trigger calls to the V8 runtime and for debugging purposes (breakpoints, watchpoints).
5. **Stop/Breakpoint Handling:** Functions to manage and handle stops (breakpoints) in the simulated execution.
6. **Floating-Point Utilities:** Helper functions for floating-point operations like absolute value, min, max, and NaN handling.
7. **Instruction Decoding and Execution:**  The code contains a series of `DecodeTypeOpX` functions, which appear to be responsible for decoding and simulating the execution of different instruction types in the LoongArch64 instruction set. This part includes logic for branching, arithmetic, logical, and memory access instructions.

To illustrate the relationship with JavaScript, I can show how the simulator's memory read/write operations are crucial for managing JavaScript objects and data within the simulated environment.
这是目录为v8/src/execution/loong64/simulator-loong64.cc 的一个 c++ 源代码文件的第2部分，主要功能是**模拟LoongArch64架构的CPU执行指令，并提供与V8 JavaScript引擎运行时环境交互的能力**。

具体来说，这部分代码实现了以下关键功能：

1. **内存读写操作:**
   - 提供了 `ReadW`, `ReadH`, `ReadB`, `WriteW`, `WriteH`, `WriteB` 等函数，用于模拟读取和写入不同大小的数据（字、半字、字节）到模拟的内存中。
   - 区分了有符号和无符号的读取操作（例如 `ReadBU` 读取无符号字节）。
   - 实现了模板函数 `ReadMem` 和 `WriteMem`，用于处理任意大小的内存读写，并检查内存对齐。如果发生未对齐的内存访问，会打印错误信息并终止程序。

2. **栈管理:**
   - `StackLimit` 函数用于计算模拟器栈的限制，考虑了C++栈的限制，以防止栈溢出。
   - `GetCentralStackView` 函数用于获取模拟器栈的视图。

3. **不支持指令处理:**
   - `Format` 函数用于处理模拟器遇到不支持的指令时，打印错误信息并终止执行。

4. **与V8运行时环境的交互（Runtime Calls）:**
   - 定义了 `SimulatorRuntimeCall`、`SimulatorRuntimeCompareCall` 等函数指针类型，用于表示不同类型的V8运行时函数的调用签名。
   - `CallAnyCTypeFunction` 函数负责根据C函数签名，从模拟器的寄存器或栈中提取参数，并调用相应的C函数。
   - 定义了宏 `MIXED_RUNTIME_CALL` 和 `CALL_TARGET_VARARG` 等，用于生成和调用具有不同数量参数的运行时函数。

5. **软件中断处理 (Software Interrupt):**
   - `SoftwareInterrupt` 函数用于处理模拟器遇到的软件中断指令。
   - 它可以用来调用V8的运行时函数（通过 `rtCallRedirInstr` 指令进行重定向）。
   - 也用于实现调试功能，例如设置断点和观察点 (`kMaxStopCode`, `kMaxWatchpointCode`)。
   -  在调用运行时函数时，会根据函数类型（例如浮点调用）从模拟器的FPU寄存器或通用寄存器中提取参数。

6. **断点和观察点处理:**
   - `IsWatchpoint`, `PrintWatchpoint`, `HandleStop`, `IsStopInstruction`, `IsEnabledStop`, `EnableStop`, `DisableStop`, `IncreaseStopCounter`, `PrintStopInfo` 等函数用于管理和处理模拟器中的断点和观察点。

7. **浮点数工具函数:**
   - 提供了 `FPAbs`（绝对值）、`FPUMin`（最小值）、`FPUMax`（最大值）、`FPUMinA`（绝对值最小值）、`FPUMaxA`（绝对值最大值）等浮点数操作的辅助函数。
   - 提供了 `FPUCanonalizeNaNArg` 和 `FPUCanonalizeOperation` 等函数，用于处理浮点数中的 NaN (Not a Number) 值。

8. **指令解码和执行 (DecodeTypeOpX):**
   - 定义了一系列的 `DecodeTypeOp6`, `DecodeTypeOp7`, `DecodeTypeOp8`, `DecodeTypeOp10`, `DecodeTypeOp12`, `DecodeTypeOp14`, `DecodeTypeOp17` 等函数，这些函数负责解码不同类型的LoongArch64指令，并模拟其执行过程。
   - 在每个解码函数中，会根据指令的操作码和操作数，模拟指令的行为，例如：
     - **算术运算:**  `ADDU16I_D`, `ADDI_W`, `ADDI_D` 等。
     - **逻辑运算:** `ANDI`, `ORI`, `XORI` 等。
     - **移位和旋转:** `SLLI`, `SRLI`, `SRAI`, `ROTRI` 等。
     - **内存访问:** `LD_B`, `LD_H`, `LD_W`, `LD_D`, `ST_B`, `ST_H`, `ST_W`, `ST_D` 等。
     - **分支跳转:** `BEQZ`, `BNEZ`, `B`, `BL`, `BEQ`, `BNE` 等。
     - **浮点运算:** `FMADD_S`, `FMADD_D`, `FCMP_COND_S`, `FCMP_COND_D` 等。

**与 JavaScript 的关系及示例:**

这个模拟器的主要目的是为了在没有真实 LoongArch64 硬件的情况下，能够运行和测试 V8 JavaScript 引擎。JavaScript 代码的执行最终会被 V8 编译成机器码，而这个模拟器就负责模拟执行这些机器码。

例如，当 JavaScript 代码中访问一个对象属性时，V8 可能会生成一个加载指令（例如 `LD_D`）来从内存中读取属性的值。模拟器中的 `DecodeTypeOp10` 函数中的 `LD_D` 分支就会模拟这个加载操作：

```c++
    case LD_D:
      printf_instr("LD_D\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int64_t))) return;
      set_register(rd_reg(), Read2W(rj() + si12_se, instr_.instr()));
      break;
```

对应的 JavaScript 例子：

```javascript
const obj = { x: 10 };
const value = obj.x; // 访问对象属性
```

在这个 JavaScript 例子中，V8 可能会生成类似于 `LD_D` 的指令，将对象 `obj` 在内存中的地址加上 `x` 属性的偏移量，读取 64 位的值（假设是数字类型）。模拟器的 `Read2W` 函数就会被调用，从模拟的内存中读取这个值并存放到模拟的寄存器中，最终 JavaScript 就能获取到属性 `x` 的值 `10`。

再比如，当 JavaScript 调用一个内置函数（例如 `console.log`）时，V8 可能会生成一个软件中断指令，并将其重定向到 V8 的运行时函数。模拟器中的 `SoftwareInterrupt` 函数会捕获这个中断，并调用相应的 C++ 函数来模拟 `console.log` 的行为。

总而言之，这部分代码是 V8 引擎在 LoongArch64 架构上运行的关键组成部分，它充当了一个桥梁，使得 V8 能够在没有真实硬件的情况下执行 JavaScript 代码，并与 V8 的底层运行时环境进行交互。

### 提示词
```
这是目录为v8/src/execution/loong64/simulator-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
      int32_t si20_signExtend = static_cast<int32_t>(si20() << 12);
      int64_t current_pc = get_pc();
      alu_out = static_cast<int64_t>(si20_signExtend) + current_pc;
      SetResult(rd_reg(), alu_out);
      break;
    }
    case PCADDU18I: {
      printf_instr("PCADDU18I\t %s: %016lx, si20: %d\n",
                   Registers::Name(rd_reg()), rd(), si20());
      int64_t si20_signExtend = (static_cast<int64_t>(si20()) << 44) >> 26;
      int64_t current_pc = get_pc();
      alu_out = si20_signExtend + current_pc;
      SetResult(rd_reg(), alu_out);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeOp8() {
  int64_t addr = 0x0;
  int64_t si14_se = (static_cast<int64_t>(si14()) << 50) >> 48;

  switch (instr_.Bits(31, 24) << 24) {
    case LDPTR_W:
      printf_instr("LDPTR_W\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      if (!ProbeMemory(rj() + si14_se, sizeof(int32_t))) return;
      set_register(rd_reg(), ReadW(rj() + si14_se, instr_.instr()));
      break;
    case STPTR_W:
      printf_instr("STPTR_W\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      if (!ProbeMemory(rj() + si14_se, sizeof(int32_t))) return;
      WriteW(rj() + si14_se, static_cast<int32_t>(rd()), instr_.instr());
      break;
    case LDPTR_D:
      printf_instr("LDPTR_D\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      if (!ProbeMemory(rj() + si14_se, sizeof(int64_t))) return;
      set_register(rd_reg(), Read2W(rj() + si14_se, instr_.instr()));
      break;
    case STPTR_D:
      printf_instr("STPTR_D\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      if (!ProbeMemory(rj() + si14_se, sizeof(int64_t))) return;
      Write2W(rj() + si14_se, rd(), instr_.instr());
      break;
    case LL_W: {
      printf_instr("LL_W\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      addr = si14_se + rj();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      {
        base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
        set_register(rd_reg(), ReadW(addr, instr_.instr()));
        local_monitor_.NotifyLoadLinked(addr, TransactionSize::Word);
        GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                      &global_monitor_thread_);
      }
      break;
    }
    case SC_W: {
      printf_instr("SC_W\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      addr = si14_se + rj();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      int32_t LLbit = 0;
      WriteConditionalW(addr, static_cast<int32_t>(rd()), instr_.instr(),
                        &LLbit);
      set_register(rd_reg(), LLbit);
      break;
    }
    case LL_D: {
      printf_instr("LL_D\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      addr = si14_se + rj();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      {
        base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
        set_register(rd_reg(), Read2W(addr, instr_.instr()));
        local_monitor_.NotifyLoadLinked(addr, TransactionSize::DoubleWord);
        GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                      &global_monitor_thread_);
      }
      break;
    }
    case SC_D: {
      printf_instr("SC_D\t %s: %016lx, %s: %016lx, si14: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si14_se);
      addr = si14_se + rj();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      int32_t LLbit = 0;
      WriteConditional2W(addr, rd(), instr_.instr(), &LLbit);
      set_register(rd_reg(), LLbit);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeOp10() {
  int64_t alu_out = 0x0;
  int64_t si12_se = (static_cast<int64_t>(si12()) << 52) >> 52;
  uint64_t si12_ze = (static_cast<uint64_t>(ui12()) << 52) >> 52;

  switch (instr_.Bits(31, 22) << 22) {
    case BSTR_W: {
      CHECK_EQ(instr_.Bit(21), 1);
      uint8_t lsbw_ = lsbw();
      uint8_t msbw_ = msbw();
      CHECK_LE(lsbw_, msbw_);
      uint8_t size = msbw_ - lsbw_ + 1;
      uint64_t mask = (1ULL << size) - 1;
      if (instr_.Bit(15) == 0) {
        // BSTRINS_W
        printf_instr(
            "BSTRINS_W\t %s: %016lx, %s: %016lx, msbw: %02x, lsbw: %02x\n",
            Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()), rj(),
            msbw_, lsbw_);
        alu_out = static_cast<int32_t>((rd_u() & ~(mask << lsbw_)) |
                                       ((rj_u() & mask) << lsbw_));
      } else {
        // BSTRPICK_W
        printf_instr(
            "BSTRPICK_W\t %s: %016lx, %s: %016lx, msbw: %02x, lsbw: %02x\n",
            Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()), rj(),
            msbw_, lsbw_);
        alu_out = static_cast<int32_t>((rj_u() & (mask << lsbw_)) >> lsbw_);
      }
      SetResult(rd_reg(), alu_out);
      break;
    }
    case BSTRINS_D: {
      uint8_t lsbd_ = lsbd();
      uint8_t msbd_ = msbd();
      CHECK_LE(lsbd_, msbd_);
      printf_instr(
          "BSTRINS_D\t %s: %016lx, %s: %016lx, msbw: %02x, lsbw: %02x\n",
          Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()), rj(),
          msbd_, lsbd_);
      uint8_t size = msbd_ - lsbd_ + 1;
      if (size < 64) {
        uint64_t mask = (1ULL << size) - 1;
        alu_out = (rd_u() & ~(mask << lsbd_)) | ((rj_u() & mask) << lsbd_);
        SetResult(rd_reg(), alu_out);
      } else if (size == 64) {
        SetResult(rd_reg(), rj());
      }
      break;
    }
    case BSTRPICK_D: {
      uint8_t lsbd_ = lsbd();
      uint8_t msbd_ = msbd();
      CHECK_LE(lsbd_, msbd_);
      printf_instr(
          "BSTRPICK_D\t %s: %016lx, %s: %016lx, msbw: %02x, lsbw: %02x\n",
          Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()), rj(),
          msbd_, lsbd_);
      uint8_t size = msbd_ - lsbd_ + 1;
      if (size < 64) {
        uint64_t mask = (1ULL << size) - 1;
        alu_out = (rj_u() & (mask << lsbd_)) >> lsbd_;
        SetResult(rd_reg(), alu_out);
      } else if (size == 64) {
        SetResult(rd_reg(), rj());
      }
      break;
    }
    case SLTI:
      printf_instr("SLTI\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_se);
      SetResult(rd_reg(), rj() < si12_se ? 1 : 0);
      break;
    case SLTUI:
      printf_instr("SLTUI\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_se);
      SetResult(rd_reg(), rj_u() < static_cast<uint64_t>(si12_se) ? 1 : 0);
      break;
    case ADDI_W: {
      printf_instr("ADDI_W\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_se);
      int32_t alu32_out =
          static_cast<int32_t>(rj()) + static_cast<int32_t>(si12_se);
      SetResult(rd_reg(), alu32_out);
      break;
    }
    case ADDI_D:
      printf_instr("ADDI_D\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_se);
      SetResult(rd_reg(), rj() + si12_se);
      break;
    case LU52I_D: {
      printf_instr("LU52I_D\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_se);
      int64_t si12_se = static_cast<int64_t>(si12()) << 52;
      uint64_t mask = (1ULL << 52) - 1;
      alu_out = si12_se + (rj() & mask);
      SetResult(rd_reg(), alu_out);
      break;
    }
    case ANDI:
      printf_instr("ANDI\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      SetResult(rd_reg(), rj() & si12_ze);
      break;
    case ORI:
      printf_instr("ORI\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      SetResult(rd_reg(), rj_u() | si12_ze);
      break;
    case XORI:
      printf_instr("XORI\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      SetResult(rd_reg(), rj_u() ^ si12_ze);
      break;
    case LD_B:
      printf_instr("LD_B\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int8_t))) return;
      set_register(rd_reg(), ReadB(rj() + si12_se));
      break;
    case LD_H:
      printf_instr("LD_H\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int16_t))) return;
      set_register(rd_reg(), ReadH(rj() + si12_se, instr_.instr()));
      break;
    case LD_W:
      printf_instr("LD_W\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int32_t))) return;
      set_register(rd_reg(), ReadW(rj() + si12_se, instr_.instr()));
      break;
    case LD_D:
      printf_instr("LD_D\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int64_t))) return;
      set_register(rd_reg(), Read2W(rj() + si12_se, instr_.instr()));
      break;
    case ST_B:
      printf_instr("ST_B\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int8_t))) return;
      WriteB(rj() + si12_se, static_cast<int8_t>(rd()));
      break;
    case ST_H:
      printf_instr("ST_H\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int16_t))) return;
      WriteH(rj() + si12_se, static_cast<int16_t>(rd()), instr_.instr());
      break;
    case ST_W:
      printf_instr("ST_W\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int32_t))) return;
      WriteW(rj() + si12_se, static_cast<int32_t>(rd()), instr_.instr());
      break;
    case ST_D:
      printf_instr("ST_D\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(int64_t))) return;
      Write2W(rj() + si12_se, rd(), instr_.instr());
      break;
    case LD_BU:
      printf_instr("LD_BU\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(uint8_t))) return;
      set_register(rd_reg(), ReadBU(rj() + si12_se));
      break;
    case LD_HU:
      printf_instr("LD_HU\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(uint16_t))) return;
      set_register(rd_reg(), ReadHU(rj() + si12_se, instr_.instr()));
      break;
    case LD_WU:
      printf_instr("LD_WU\t %s: %016lx, %s: %016lx, si12: %016lx\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(uint32_t))) return;
      set_register(rd_reg(), ReadWU(rj() + si12_se, instr_.instr()));
      break;
    case FLD_S: {
      printf_instr("FLD_S\t %s: %016f, %s: %016lx, si12: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   Registers::Name(rj_reg()), rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(float))) return;
      set_fpu_register(fd_reg(), kFPUInvalidResult);  // Trash upper 32 bits.
      set_fpu_register_word(
          fd_reg(), ReadW(rj() + si12_se, instr_.instr(), FLOAT_DOUBLE));
      break;
    }
    case FST_S: {
      printf_instr("FST_S\t %s: %016f, %s: %016lx, si12: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   Registers::Name(rj_reg()), rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(float))) return;
      int32_t alu_out_32 = static_cast<int32_t>(get_fpu_register(fd_reg()));
      WriteW(rj() + si12_se, alu_out_32, instr_.instr());
      break;
    }
    case FLD_D: {
      printf_instr("FLD_D\t %s: %016f, %s: %016lx, si12: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   Registers::Name(rj_reg()), rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(double))) return;
      set_fpu_register_double(fd_reg(), ReadD(rj() + si12_se, instr_.instr()));
      TraceMemRd(rj() + si12_se, get_fpu_register(fd_reg()), DOUBLE);
      break;
    }
    case FST_D: {
      printf_instr("FST_D\t %s: %016f, %s: %016lx, si12: %016lx\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   Registers::Name(rj_reg()), rj(), si12_ze);
      if (!ProbeMemory(rj() + si12_se, sizeof(double))) return;
      WriteD(rj() + si12_se, get_fpu_register_double(fd_reg()), instr_.instr());
      TraceMemWr(rj() + si12_se, get_fpu_register(fd_reg()), DWORD);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeOp12() {
  switch (instr_.Bits(31, 20) << 20) {
    case FMADD_S:
      printf_instr("FMADD_S\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fk_reg()), fk_float(),
                   FPURegisters::Name(fa_reg()), fa_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUFloatResult(fd_reg(), std::fma(fj_float(), fk_float(), fa_float()));
      break;
    case FMADD_D:
      printf_instr("FMADD_D\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fk_reg()), fk_double(),
                   FPURegisters::Name(fa_reg()), fa_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetFPUDoubleResult(fd_reg(),
                         std::fma(fj_double(), fk_double(), fa_double()));
      break;
    case FMSUB_S:
      printf_instr("FMSUB_S\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fk_reg()), fk_float(),
                   FPURegisters::Name(fa_reg()), fa_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUFloatResult(fd_reg(),
                        std::fma(fj_float(), fk_float(), -fa_float()));
      break;
    case FMSUB_D:
      printf_instr("FMSUB_D\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fk_reg()), fk_double(),
                   FPURegisters::Name(fa_reg()), fa_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetFPUDoubleResult(fd_reg(),
                         std::fma(fj_double(), fk_double(), -fa_double()));
      break;
    case FNMADD_S:
      printf_instr("FNMADD_S\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fk_reg()), fk_float(),
                   FPURegisters::Name(fa_reg()), fa_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUFloatResult(fd_reg(),
                        std::fma(-fj_float(), fk_float(), -fa_float()));
      break;
    case FNMADD_D:
      printf_instr("FNMADD_D\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fk_reg()), fk_double(),
                   FPURegisters::Name(fa_reg()), fa_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetFPUDoubleResult(fd_reg(),
                         std::fma(-fj_double(), fk_double(), -fa_double()));
      break;
    case FNMSUB_S:
      printf_instr("FNMSUB_S\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_float(),
                   FPURegisters::Name(fk_reg()), fk_float(),
                   FPURegisters::Name(fa_reg()), fa_float(),
                   FPURegisters::Name(fj_reg()), fj_float());
      SetFPUFloatResult(fd_reg(),
                        std::fma(-fj_float(), fk_float(), fa_float()));
      break;
    case FNMSUB_D:
      printf_instr("FNMSUB_D\t %s: %016f, %s: %016f, %s: %016f %s: %016f\n",
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fk_reg()), fk_double(),
                   FPURegisters::Name(fa_reg()), fa_double(),
                   FPURegisters::Name(fj_reg()), fj_double());
      SetFPUDoubleResult(fd_reg(),
                         std::fma(-fj_double(), fk_double(), fa_double()));
      break;
    case FCMP_COND_S: {
      CHECK_EQ(instr_.Bits(4, 3), 0);
      float fj = fj_float();
      float fk = fk_float();
      switch (cond()) {
        case CAF: {
          printf_instr("FCMP_CAF_S fcc%d\n", cd_reg());
          set_cf_register(cd_reg(), false);
          break;
        }
        case CUN: {
          printf_instr("FCMP_CUN_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CEQ: {
          printf_instr("FCMP_CEQ_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), fj == fk);
          break;
        }
        case CUEQ: {
          printf_instr("FCMP_CUEQ_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj == fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CLT: {
          printf_instr("FCMP_CLT_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), fj < fk);
          break;
        }
        case CULT: {
          printf_instr("FCMP_CULT_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj < fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CLE: {
          printf_instr("FCMP_CLE_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), fj <= fk);
          break;
        }
        case CULE: {
          printf_instr("FCMP_CULE_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj <= fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CNE: {
          printf_instr("FCMP_CNE_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), (fj < fk) || (fj > fk));
          break;
        }
        case COR: {
          printf_instr("FCMP_COR_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), !std::isnan(fj) && !std::isnan(fk));
          break;
        }
        case CUNE: {
          printf_instr("FCMP_CUNE_S fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj != fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case SAF:
        case SUN:
        case SEQ:
        case SUEQ:
        case SLT:
        case SULT:
        case SLE:
        case SULE:
        case SNE:
        case SOR:
        case SUNE:
          UNIMPLEMENTED();
        default:
          UNREACHABLE();
      }
      break;
    }
    case FCMP_COND_D: {
      CHECK_EQ(instr_.Bits(4, 3), 0);
      double fj = fj_double();
      double fk = fk_double();
      switch (cond()) {
        case CAF: {
          printf_instr("FCMP_CAF_D fcc%d\n", cd_reg());
          set_cf_register(cd_reg(), false);
          break;
        }
        case CUN: {
          printf_instr("FCMP_CUN_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CEQ: {
          printf_instr("FCMP_CEQ_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), fj == fk);
          break;
        }
        case CUEQ: {
          printf_instr("FCMP_CUEQ_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj == fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CLT: {
          printf_instr("FCMP_CLT_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), fj < fk);
          break;
        }
        case CULT: {
          printf_instr("FCMP_CULT_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj < fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CLE: {
          printf_instr("FCMP_CLE_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), fj <= fk);
          break;
        }
        case CULE: {
          printf_instr("FCMP_CULE_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj <= fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case CNE: {
          printf_instr("FCMP_CNE_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), (fj < fk) || (fj > fk));
          break;
        }
        case COR: {
          printf_instr("FCMP_COR_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(), !std::isnan(fj) && !std::isnan(fk));
          break;
        }
        case CUNE: {
          printf_instr("FCMP_CUNE_D fcc%d, %s: %016f, %s: %016f\n", cd_reg(),
                       FPURegisters::Name(fj_reg()), fj,
                       FPURegisters::Name(fk_reg()), fk);
          set_cf_register(cd_reg(),
                          (fj != fk) || std::isnan(fj) || std::isnan(fk));
          break;
        }
        case SAF:
        case SUN:
        case SEQ:
        case SUEQ:
        case SLT:
        case SULT:
        case SLE:
        case SULE:
        case SNE:
        case SOR:
        case SUNE:
          UNIMPLEMENTED();
        default:
          UNREACHABLE();
      }
      break;
    }
    case FSEL: {
      CHECK_EQ(instr_.Bits(19, 18), 0);
      printf_instr("FSEL fcc%d, %s: %016f, %s: %016f, %s: %016f\n", ca_reg(),
                   FPURegisters::Name(fd_reg()), fd_double(),
                   FPURegisters::Name(fj_reg()), fj_double(),
                   FPURegisters::Name(fk_reg()), fk_double());
      if (ca() == 0) {
        SetFPUDoubleResult(fd_reg(), fj_double());
      } else {
        SetFPUDoubleResult(fd_reg(), fk_double());
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeOp14() {
  int64_t alu_out = 0x0;
  int32_t alu32_out = 0x0;

  switch (instr_.Bits(31, 18) << 18) {
    case ALSL: {
      uint8_t sa = sa2() + 1;
      alu32_out =
          (static_cast<int32_t>(rj()) << sa) + static_cast<int32_t>(rk());
      if (instr_.Bit(17) == 0) {
        // ALSL_W
        printf_instr("ALSL_W\t %s: %016lx, %s: %016lx, %s: %016lx, sa2: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), Registers::Name(rk_reg()), rk(), sa2());
        SetResult(rd_reg(), alu32_out);
      } else {
        // ALSL_WU
        printf_instr("ALSL_WU\t %s: %016lx, %s: %016lx, %s: %016lx, sa2: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), Registers::Name(rk_reg()), rk(), sa2());
        SetResult(rd_reg(), static_cast<uint32_t>(alu32_out));
      }
      break;
    }
    case BYTEPICK_W: {
      CHECK_EQ(instr_.Bit(17), 0);
      printf_instr("BYTEPICK_W\t %s: %016lx, %s: %016lx, %s: %016lx, sa2: %d\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk(), sa2());
      uint8_t sa = sa2() * 8;
      if (sa == 0) {
        alu32_out = static_cast<int32_t>(rk());
      } else {
        int32_t mask = (1 << 31) >> (sa - 1);
        int32_t rk_hi = (static_cast<int32_t>(rk()) & (~mask)) << sa;
        int32_t rj_lo = (static_cast<uint32_t>(rj()) & mask) >> (32 - sa);
        alu32_out = rk_hi | rj_lo;
      }
      SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      break;
    }
    case BYTEPICK_D: {
      printf_instr("BYTEPICK_D\t %s: %016lx, %s: %016lx, %s: %016lx, sa3: %d\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk(), sa3());
      uint8_t sa = sa3() * 8;
      if (sa == 0) {
        alu_out = rk();
      } else {
        int64_t mask = (1LL << 63) >> (sa - 1);
        int64_t rk_hi = (rk() & (~mask)) << sa;
        int64_t rj_lo = static_cast<uint64_t>(rj() & mask) >> (64 - sa);
        alu_out = rk_hi | rj_lo;
      }
      SetResult(rd_reg(), alu_out);
      break;
    }
    case ALSL_D: {
      printf_instr("ALSL_D\t %s: %016lx, %s: %016lx, %s: %016lx, sa2: %d\n",
                   Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                   rj(), Registers::Name(rk_reg()), rk(), sa2());
      CHECK_EQ(instr_.Bit(17), 0);
      uint8_t sa = sa2() + 1;
      alu_out = (rj() << sa) + rk();
      SetResult(rd_reg(), alu_out);
      break;
    }
    case SLLI: {
      DCHECK_EQ(instr_.Bit(17), 0);
      if (instr_.Bits(17, 15) == 0b001) {
        // SLLI_W
        printf_instr("SLLI_W\t %s: %016lx, %s: %016lx, ui5: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui5());
        alu32_out = static_cast<int32_t>(rj()) << ui5();
        SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      } else if ((instr_.Bits(17, 16) == 0b01)) {
        // SLLI_D
        printf_instr("SLLI_D\t %s: %016lx, %s: %016lx, ui6: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui6());
        SetResult(rd_reg(), rj() << ui6());
      }
      break;
    }
    case SRLI: {
      DCHECK_EQ(instr_.Bit(17), 0);
      if (instr_.Bits(17, 15) == 0b001) {
        // SRLI_W
        printf_instr("SRLI_W\t %s: %016lx, %s: %016lx, ui5: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui5());
        alu32_out = static_cast<uint32_t>(rj()) >> ui5();
        SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      } else if (instr_.Bits(17, 16) == 0b01) {
        // SRLI_D
        printf_instr("SRLI_D\t %s: %016lx, %s: %016lx, ui6: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui6());
        SetResult(rd_reg(), rj_u() >> ui6());
      }
      break;
    }
    case SRAI: {
      DCHECK_EQ(instr_.Bit(17), 0);
      if (instr_.Bits(17, 15) == 0b001) {
        // SRAI_W
        printf_instr("SRAI_W\t %s: %016lx, %s: %016lx, ui5: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui5());
        alu32_out = static_cast<int32_t>(rj()) >> ui5();
        SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      } else if (instr_.Bits(17, 16) == 0b01) {
        // SRAI_D
        printf_instr("SRAI_D\t %s: %016lx, %s: %016lx, ui6: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui6());
        SetResult(rd_reg(), rj() >> ui6());
      }
      break;
    }
    case ROTRI: {
      DCHECK_EQ(instr_.Bit(17), 0);
      if (instr_.Bits(17, 15) == 0b001) {
        // ROTRI_W
        printf_instr("ROTRI_W\t %s: %016lx, %s: %016lx, ui5: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui5());
        alu32_out = static_cast<int32_t>(
            base::bits::RotateRight32(static_cast<const uint32_t>(rj_u()),
                                      static_cast<const uint32_t>(ui5())));
        SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      } else if (instr_.Bits(17, 16) == 0b01) {
        // ROTRI_D
        printf_instr("ROTRI_D\t %s: %016lx, %s: %016lx, ui6: %d\n",
                     Registers::Name(rd_reg()), rd(), Registers::Name(rj_reg()),
                     rj(), ui6());
        alu_out =
            static_cast<int64_t>(base::bits::RotateRight64(rj_u(), ui6()));
        SetResult(rd_reg(), alu_out);
        printf_instr("ROTRI, %s, %s, %d\n", Registers::Name(rd_reg()),
                     Registers::Name(rj_reg()), ui6());
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeOp17() {
  int64_t alu_out;

  switch (instr_.Bits(31, 15) << 15) {
    case ADD_W: {
      printf_instr("ADD_W\t %s: %016lx, %s, %016lx, %s, %016lx\n",
                   Registers::Nam
```