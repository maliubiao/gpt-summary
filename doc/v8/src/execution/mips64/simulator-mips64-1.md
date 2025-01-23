Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part 2 of a 5-part file.

The code seems to be part of a MIPS64 simulator, specifically dealing with:

1. **Memory Access:** Functions for reading and writing words (32-bit), double words (64-bit), half-words (16-bit), and bytes (8-bit) from/to simulated memory. It also handles aligned and unaligned access, potentially triggering debug or aborting on unaligned access depending on the architecture variant.
2. **Memory Access Tracing:** Functions like `TraceMemRd` and `TraceMemWr` are used to log memory read and write operations.
3. **Synchronization Primitives:** Usage of `local_monitor_` and `GlobalMonitor` suggests support for simulating memory access synchronization.
4. **Runtime Calls:** Mechanisms for calling into the V8 runtime or other external C functions, including handling different calling conventions (e.g., for floating-point arguments). This involves software interrupt handling.
5. **Debugging Support:** Functions and data structures for breakpoints, watchpoints, and stepping through code.
6. **Floating-Point Operations:**  A significant portion of the code deals with simulating MIPS64 floating-point instructions, including arithmetic operations, comparisons, conversions, and handling of NaN and rounding modes.
7. **Instruction Decoding and Execution:** The `DecodeTypeRegisterSRsType`, `DecodeTypeRegisterDRsType`, `DecodeTypeRegisterWRsType`, and `DecodeTypeRegisterLRsType` functions are responsible for simulating the execution of different categories of floating-point instructions.

Considering this is part 2 of the file, it's likely that part 1 handled the basic simulator setup, register initialization, and potentially the main execution loop. Parts 3-5 will likely cover other instruction types and simulator functionalities.

Regarding the relationship with JavaScript: This simulator is part of the V8 JavaScript engine. It's used when V8 needs to execute JavaScript code on an architecture for which a native code generator isn't available or for testing purposes. The runtime calls facilitate communication between the simulated MIPS64 environment and the actual V8 runtime environment.

For the JavaScript example, I can show how a JavaScript operation might trigger a simulated MIPS64 instruction that this code handles. For instance, a floating-point operation in JavaScript would eventually be translated into a corresponding MIPS64 floating-point instruction that is executed by this simulator.
这是 `v8/src/execution/mips64/simulator-mips64.cc` 文件的第二部分，它主要负责模拟 MIPS64 架构的 CPU 指令执行，特别是涉及到内存访问、运行时调用和浮点运算的部分。

**功能归纳：**

1. **内存读写模拟:**  提供了 `ReadW`, `ReadWU`, `WriteW`, `WriteConditionalW`, `Read2W`, `Write2W`, `WriteConditional2W`, `ReadD`, `WriteD`, `ReadHU`, `ReadH`, `WriteH`, `ReadBU`, `ReadB`, `WriteB` 等函数，用于模拟从指定内存地址读取和写入不同大小的数据（字节、半字、字、双字）。这些函数还会检查内存对齐情况，并根据架构变体 (`kArchVariant`) 决定是否允许非对齐访问。对于无效的内存访问（例如空指针解引用），会触发错误或进入调试器。

2. **内存访问跟踪:**  使用了 `TraceMemRd` 和 `TraceMemWr` 函数来记录内存的读取和写入操作，这对于调试模拟器本身或跟踪模拟程序的行为很有用。

3. **同步原语模拟:**  使用了 `local_monitor_` 和 `GlobalMonitor` 对象，以及互斥锁 (`base::MutexGuard`)，来模拟多线程环境下的内存访问同步和条件存储操作。

4. **运行时调用机制:**  定义了 `SimulatorRuntimeCall` 等函数指针类型，以及 `CallAnyCTypeFunction` 函数，用于模拟从模拟器内部调用到 V8 运行时或其他 C 函数。这包括处理参数传递和返回值。特殊的软件中断指令 (`SoftwareInterrupt`) 用于触发这些运行时调用。

5. **浮点运算模拟:**  包含了大量的代码来模拟 MIPS64 的浮点运算指令，例如加法 (`ADD_S`, `ADD_D`)、减法 (`SUB_S`, `SUB_D`)、乘法 (`MUL_S`, `MUL_D`)、除法 (`DIV_S`, `DIV_D`)、绝对值 (`ABS_S`, `ABS_D`)、取反 (`NEG_S`, `NEG_D`)、平方根 (`SQRT_S`, `SQRT_D`) 等。还包括浮点数的比较操作 (`C_F_D`, `C_UN_D`, `C_EQ_D` 等) 和类型转换操作 (`CVT_D_S`, `CVT_W_D` 等)。这些模拟会考虑浮点数的特殊值（如 NaN）和舍入模式。

6. **指令解码和执行 (浮点部分):**  定义了 `DecodeTypeRegisterSRsType`, `DecodeTypeRegisterDRsType`, `DecodeTypeRegisterWRsType`, `DecodeTypeRegisterLRsType` 等函数，用于解码和执行不同类型的浮点寄存器操作指令。

7. **调试支持:**  提供了处理 `BREAK` 指令的功能，可以用于设置断点和观察点 (`IsWatchpoint`, `PrintWatchpoint`, `HandleStop`)。

**与 JavaScript 的关系及示例：**

这个文件是 V8 JavaScript 引擎的一部分，它提供了一个 MIPS64 架构的软件模拟器。当 V8 需要在 MIPS64 平台上运行 JavaScript 代码，但没有本地代码生成器或者出于测试目的时，就会使用这个模拟器。

当 JavaScript 代码执行时，V8 会将其编译成 MIPS64 的机器码。如果使用模拟器，这些 MIPS64 指令将由 `simulator-mips64.cc` 中的代码逐条解释执行。

**JavaScript 示例：**

```javascript
// JavaScript 代码
let a = 1.5;
let b = 2.5;
let sum = a + b;
console.log(sum);
```

**模拟器中的可能执行过程：**

当执行 `let sum = a + b;` 这行 JavaScript 代码时，V8 可能会将其编译成类似的 MIPS64 指令序列（简化示例）：

1. **加载浮点数 `a` 到浮点寄存器 `f1`：**  模拟器中的某个 `ReadD` 或类似的函数会被调用，从内存中读取 `a` 的双精度浮点数表示。
2. **加载浮点数 `b` 到浮点寄存器 `f2`：**  类似地，读取 `b` 的值。
3. **执行浮点加法指令 `add.d f0, f1, f2`：**  模拟器中的 `DecodeTypeRegisterDRsType` 函数会被调用，根据指令的操作码判断是 `ADD_D` 指令，然后执行相应的模拟代码：

   ```c++
   // 在 DecodeTypeRegisterDRsType 函数中
   case ADD_D:
     SetFPUDoubleResult(
         fd_reg(),
         FPUCanonalizeOperation(
             [](double lhs, double rhs) { return lhs + rhs; }, fs, ft));
     break;
   ```

   这里，`fs` 和 `ft` 会对应 `f1` 和 `f2` 寄存器的值（1.5 和 2.5），计算结果 4.0 会被写入 `fd_reg()` 对应的 `f0` 寄存器。

4. **将结果 `sum` 存储回内存：** 模拟器中的 `WriteD` 或类似的函数会被调用，将 `f0` 寄存器中的值写回内存中 `sum` 变量对应的地址。

**运行时调用示例：**

JavaScript 中的 `console.log(sum)` 调用可能会触发一个运行时调用，以便在宿主环境中输出结果。 这会涉及到 `SoftwareInterrupt` 函数的处理，根据特定的代码跳转到 V8 运行时的 C++ 代码中执行输出操作。

总而言之，这部分代码是 MIPS64 模拟器的核心组成部分，负责模拟 CPU 的内存操作、同步机制以及至关重要的浮点运算，使得 V8 可以在没有硬件 MIPS64 支持的环境下运行 JavaScript 代码。

### 提示词
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```
, addr, icount_);
        break;
      case 4:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx32 " --> [%08" PRIx64 "]    (%" PRIu64 ")",
                       static_cast<uint32_t>(value), addr, icount_);
        break;
      case 8:
        base::SNPrintF(trace_buf_,
                       "%16" PRIx64 " --> [%08" PRIx64 "]    (%" PRIu64 ")",
                       static_cast<uint64_t>(value), addr, icount_);
        break;
      default:
        UNREACHABLE();
    }
  }
}

// TODO(plind): sign-extend and zero-extend not implmented properly
// on all the ReadXX functions, I don't think re-interpret cast does it.
int32_t Simulator::ReadW(int64_t addr, Instruction* instr, TraceType t) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
  if ((addr & 0x3) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyLoad();
    int32_t* ptr = reinterpret_cast<int32_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr), t);
    return *ptr;
  }
  PrintF("Unaligned read at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
  return 0;
}

uint32_t Simulator::ReadWU(int64_t addr, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
  if ((addr & 0x3) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyLoad();
    uint32_t* ptr = reinterpret_cast<uint32_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr), WORD);
    return *ptr;
  }
  PrintF("Unaligned read at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
  return 0;
}

void Simulator::WriteW(int64_t addr, int32_t value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
  if ((addr & 0x3) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, WORD);
    int* ptr = reinterpret_cast<int*>(addr);
    *ptr = value;
    return;
  }
  PrintF("Unaligned write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

void Simulator::WriteConditionalW(int64_t addr, int32_t value,
                                  Instruction* instr, int32_t rt_reg) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
  if ((addr & 0x3) == 0 || kArchVariant == kMips64r6) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (local_monitor_.NotifyStoreConditional(addr, TransactionSize::Word) &&
        GlobalMonitor::Get()->NotifyStoreConditional_Locked(
            addr, &global_monitor_thread_)) {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
      TraceMemWr(addr, value, WORD);
      int* ptr = reinterpret_cast<int*>(addr);
      *ptr = value;
      set_register(rt_reg, 1);
    } else {
      set_register(rt_reg, 0);
    }
    return;
  }
  PrintF("Unaligned write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

int64_t Simulator::Read2W(int64_t addr, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
  if ((addr & kPointerAlignmentMask) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyLoad();
    int64_t* ptr = reinterpret_cast<int64_t*>(addr);
    TraceMemRd(addr, *ptr);
    return *ptr;
  }
  PrintF("Unaligned read at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
  return 0;
}

void Simulator::Write2W(int64_t addr, int64_t value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
  if ((addr & kPointerAlignmentMask) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, DWORD);
    int64_t* ptr = reinterpret_cast<int64_t*>(addr);
    *ptr = value;
    return;
  }
  PrintF("Unaligned write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

void Simulator::WriteConditional2W(int64_t addr, int64_t value,
                                   Instruction* instr, int32_t rt_reg) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
  if ((addr & kPointerAlignmentMask) == 0 || kArchVariant == kMips64r6) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (local_monitor_.NotifyStoreConditional(addr,
                                              TransactionSize::DoubleWord) &&
        GlobalMonitor::Get()->NotifyStoreConditional_Locked(
            addr, &global_monitor_thread_)) {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
      TraceMemWr(addr, value, DWORD);
      int64_t* ptr = reinterpret_cast<int64_t*>(addr);
      *ptr = value;
      set_register(rt_reg, 1);
    } else {
      set_register(rt_reg, 0);
    }
    return;
  }
  PrintF("Unaligned write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

double Simulator::ReadD(int64_t addr, Instruction* instr) {
  if ((addr & kDoubleAlignmentMask) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyLoad();
    double* ptr = reinterpret_cast<double*>(addr);
    return *ptr;
  }
  PrintF("Unaligned (double) read at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n",
         addr, reinterpret_cast<intptr_t>(instr));
  base::OS::Abort();
}

void Simulator::WriteD(int64_t addr, double value, Instruction* instr) {
  if ((addr & kDoubleAlignmentMask) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    double* ptr = reinterpret_cast<double*>(addr);
    *ptr = value;
    return;
  }
  PrintF("Unaligned (double) write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR
         "\n",
         addr, reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

uint16_t Simulator::ReadHU(int64_t addr, Instruction* instr) {
  if ((addr & 1) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyLoad();
    uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr));
    return *ptr;
  }
  PrintF("Unaligned unsigned halfword read at 0x%08" PRIx64
         " , pc=0x%08" V8PRIxPTR "\n",
         addr, reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
  return 0;
}

int16_t Simulator::ReadH(int64_t addr, Instruction* instr) {
  if ((addr & 1) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyLoad();
    int16_t* ptr = reinterpret_cast<int16_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr));
    return *ptr;
  }
  PrintF("Unaligned signed halfword read at 0x%08" PRIx64
         " , pc=0x%08" V8PRIxPTR "\n",
         addr, reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
  return 0;
}

void Simulator::WriteH(int64_t addr, uint16_t value, Instruction* instr) {
  if ((addr & 1) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, HALF);
    uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
    *ptr = value;
    return;
  }
  PrintF("Unaligned unsigned halfword write at 0x%08" PRIx64
         " , pc=0x%08" V8PRIxPTR "\n",
         addr, reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

void Simulator::WriteH(int64_t addr, int16_t value, Instruction* instr) {
  if ((addr & 1) == 0 || kArchVariant == kMips64r6) {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, HALF);
    int16_t* ptr = reinterpret_cast<int16_t*>(addr);
    *ptr = value;
    return;
  }
  PrintF("Unaligned halfword write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR
         "\n",
         addr, reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
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
  if ((addr & alignment_mask) == 0 || kArchVariant == kMips64r6) {
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
  if ((addr & alignment_mask) == 0 || kArchVariant == kMips64r6) {
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
  UNIMPLEMENTED_MIPS();
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

#define PARAM_REGISTERS a0, a1, a2, a3, a4, a5, a6, a7
#define RETURN_REGISTER v0
#define FP_PARAM_REGISTERS f12, f13, f14, f15, f16, f17, f18, f19
#define FP_RETURN_REGISTER f0

void Simulator::CallAnyCTypeFunction(Address target_address,
                                     const EncodedCSignature& signature) {
  const int64_t* stack_pointer = reinterpret_cast<int64_t*>(get_register(sp));
  const double* double_stack_pointer =
      reinterpret_cast<double*>(get_register(sp));

  const Register kParamRegisters[] = {PARAM_REGISTERS};
  const FPURegister kFPParamRegisters[] = {FP_PARAM_REGISTERS};

  int num_reg_params = 0, num_stack_params = 0;

  CHECK_LE(signature.ParameterCount(), kMaxCParameters);
  static_assert(sizeof(AnyCType) == 8, "AnyCType is assumed to be 64-bit.");
  AnyCType args[kMaxCParameters];
  for (int i = 0; i < signature.ParameterCount(); ++i) {
    if (num_reg_params < 8) {
      if (signature.IsFloat(i)) {
        args[i].double_value =
            get_fpu_register_double(kFPParamRegisters[num_reg_params++]);
      } else {
        args[i].int64_value = get_register(kParamRegisters[num_reg_params++]);
      }
    } else {
      if (signature.IsFloat(i)) {
        args[i].double_value = double_stack_pointer[num_stack_params++];
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
  printf("CallAnyCTypeFunction end result \n");

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
  // There are several instructions that could get us here,
  // the break_ instruction, or several variants of traps. All
  // Are "SPECIAL" class opcode, and are distinuished by function.
  int32_t func = instr_.FunctionFieldRaw();
  uint32_t code = (func == BREAK) ? instr_.Bits(25, 6) : -1;
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

    if (!IsMipsSoftFloatABI) {
      // With the hard floating point calling convention, double
      // arguments are passed in FPU registers. Fetch the arguments
      // from there and call the builtin using soft floating point
      // convention.
      switch (redirection->type()) {
        case ExternalReference::BUILTIN_FP_FP_CALL:
        case ExternalReference::BUILTIN_COMPARE_CALL:
          arg0 = get_fpu_register(f12);
          arg1 = get_fpu_register(f13);
          arg2 = get_fpu_register(f14);
          arg3 = get_fpu_register(f15);
          break;
        case ExternalReference::BUILTIN_FP_CALL:
          arg0 = get_fpu_register(f12);
          arg1 = get_fpu_register(f13);
          break;
        case ExternalReference::BUILTIN_FP_INT_CALL:
          arg0 = get_fpu_register(f12);
          arg1 = get_fpu_register(f13);
          arg2 = get_register(a2);
          break;
        default:
          break;
      }
    }

    // Based on CpuFeatures::IsSupported(FPU), Mips will use either hardware
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

  } else if (func == BREAK && code <= kMaxStopCode) {
    if (IsWatchpoint(code)) {
      PrintWatchpoint(code);
    } else {
      IncreaseStopCounter(code);
      HandleStop(code, instr_.instr());
    }
  } else {
    // All remaining break_ codes, and all traps are handled here.
    MipsDebugger dbg(this);
    dbg.Debug();
  }
}

// Stop helper functions.
bool Simulator::IsWatchpoint(uint64_t code) {
  return (code <= kMaxWatchpointCode);
}

void Simulator::PrintWatchpoint(uint64_t code) {
  MipsDebugger dbg(this);
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
    MipsDebugger dbg(this);
    dbg.Stop(instr);
  }
}

bool Simulator::IsStopInstruction(Instruction* instr) {
  int32_t func = instr->FunctionFieldRaw();
  uint32_t code = static_cast<uint32_t>(instr->Bits(25, 6));
  return (func == BREAK) && code > kMaxWatchpointCode && code <= kMaxStopCode;
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

// Min/Max template functions for Double and Single arguments.

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

void Simulator::DecodeTypeRegisterSRsType() {
  float fs, ft, fd;
  fs = get_fpu_register_float(fs_reg());
  ft = get_fpu_register_float(ft_reg());
  fd = get_fpu_register_float(fd_reg());
  int32_t ft_int = base::bit_cast<int32_t>(ft);
  int32_t fd_int = base::bit_cast<int32_t>(fd);
  uint32_t cc, fcsr_cc;
  cc = instr_.FCccValue();
  fcsr_cc = get_fcsr_condition_bit(cc);
  switch (instr_.FunctionFieldRaw()) {
    case RINT: {
      DCHECK_EQ(kArchVariant, kMips64r6);
      float result, temp_result;
      double temp;
      float upper = std::ceil(fs);
      float lower = std::floor(fs);
      switch (get_fcsr_rounding_mode()) {
        case kRoundToNearest:
          if (upper - fs < fs - lower) {
            result = upper;
          } else if (upper - fs > fs - lower) {
            result = lower;
          } else {
            temp_result = upper / 2;
            float reminder = modf(temp_result, &temp);
            if (reminder == 0) {
              result = upper;
            } else {
              result = lower;
            }
          }
          break;
        case kRoundToZero:
          result = (fs > 0 ? lower : upper);
          break;
        case kRoundToPlusInf:
          result = upper;
          break;
        case kRoundToMinusInf:
          result = lower;
          break;
      }
      SetFPUFloatResult(fd_reg(), result);
      if (result != fs) {
        set_fcsr_bit(kFCSRInexactFlagBit, true);
      }
      break;
    }
    case ADD_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs + rhs; },
                                 fs, ft));
      break;
    case SUB_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs - rhs; },
                                 fs, ft));
      break;
    case MADDF_S:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), std::fma(fs, ft, fd));
      break;
    case MSUBF_S:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), std::fma(-fs, ft, fd));
      break;
    case MUL_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs * rhs; },
                                 fs, ft));
      break;
    case DIV_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs / rhs; },
                                 fs, ft));
      break;
    case ABS_S:
      SetFPUFloatResult(fd_reg(), FPUCanonalizeOperation(
                                      [](float fs) { return FPAbs(fs); }, fs));
      break;
    case MOV_S:
      SetFPUFloatResult(fd_reg(), fs);
      break;
    case NEG_S:
      SetFPUFloatResult(fd_reg(),
                        FPUCanonalizeOperation([](float src) { return -src; },
                                               KeepSign::yes, fs));
      break;
    case SQRT_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float src) { return std::sqrt(src); }, fs));
      break;
    case RSQRT_S:
      SetFPUFloatResult(
          fd_reg(), FPUCanonalizeOperation(
                        [](float src) { return 1.0 / std::sqrt(src); }, fs));
      break;
    case RECIP_S:
      SetFPUFloatResult(fd_reg(), FPUCanonalizeOperation(
                                      [](float src) { return 1.0 / src; }, fs));
      break;
    case C_F_D:
      set_fcsr_bit(fcsr_cc, false);
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_UN_D:
      set_fcsr_bit(fcsr_cc, std::isnan(fs) || std::isnan(ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_EQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_UEQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case CVT_D_S:
      SetFPUDoubleResult(fd_reg(), static_cast<double>(fs));
      break;
    case CLASS_S: {  // Mips64r6 instruction
      // Convert float input to uint32_t for easier bit manipulation
      uint32_t classed = base::bit_cast<uint32_t>(fs);

      // Extracting sign, exponent and mantissa from the input float
      uint32_t sign = (classed >> 31) & 1;
      uint32_t exponent = (classed >> 23) & 0x000000FF;
      uint32_t mantissa = classed & 0x007FFFFF;
      uint32_t result;
      float fResult;

      // Setting flags if input float is negative infinity,
      // positive infinity, negative zero or positive zero
      bool negInf = (classed == 0xFF800000);
      bool posInf = (classed == 0x7F800000);
      bool negZero = (classed == 0x80000000);
      bool posZero = (classed == 0x00000000);

      bool signalingNan;
      bool quietNan;
      bool negSubnorm;
      bool posSubnorm;
      bool negNorm;
      bool posNorm;

      // Setting flags if float is NaN
      signalingNan = false;
      quietNan = false;
      if (!negInf && !posInf && (exponent == 0xFF)) {
        quietNan = ((mantissa & 0x00200000) == 0) &&
                   ((mantissa & (0x00200000 - 1)) == 0);
        signalingNan = !quietNan;
      }

      // Setting flags if float is subnormal number
      posSubnorm = false;
      negSubnorm = false;
      if ((exponent == 0) && (mantissa != 0)) {
        DCHECK(sign == 0 || sign == 1);
        posSubnorm = (sign == 0);
        negSubnorm = (sign == 1);
      }

      // Setting flags if float is normal number
      posNorm = false;
      negNorm = false;
      if (!posSubnorm && !negSubnorm && !posInf && !negInf && !signalingNan &&
          !quietNan && !negZero && !posZero) {
        DCHECK(sign == 0 || sign == 1);
        posNorm = (sign == 0);
        negNorm = (sign == 1);
      }

      // Calculating result according to description of CLASS.S instruction
      result = (posZero << 9) | (posSubnorm << 8) | (posNorm << 7) |
               (posInf << 6) | (negZero << 5) | (negSubnorm << 4) |
               (negNorm << 3) | (negInf << 2) | (quietNan << 1) | signalingNan;

      DCHECK_NE(result, 0);

      fResult = base::bit_cast<float>(result);
      SetFPUFloatResult(fd_reg(), fResult);
      break;
    }
    case CVT_L_S: {
      float rounded;
      int64_t result;
      round64_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case CVT_W_S: {
      float rounded;
      int32_t result;
      round_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
      break;
    }
    case TRUNC_W_S: {  // Truncate single to word (round towards 0).
      float rounded = trunc(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
    } break;
    case TRUNC_L_S: {  // Mips64r2 instruction.
      float rounded = trunc(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case ROUND_W_S: {
      float rounded = std::floor(fs + 0.5);
      int32_t result = static_cast<int32_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
      break;
    }
    case ROUND_L_S: {  // Mips64r2 instruction.
      float rounded = std::floor(fs + 0.5);
      int64_t result = static_cast<int64_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      int64_t i64 = static_cast<int64_t>(result);
      SetFPUResult(fd_reg(), i64);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case FLOOR_L_S: {  // Mips64r2 instruction.
      float rounded = floor(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case FLOOR_W_S:  // Round double to word towards negative infinity.
    {
      float rounded = std::floor(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
    } break;
    case CEIL_W_S:  // Round double to word towards positive infinity.
    {
      float rounded = std::ceil(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case CEIL_L_S: {  // Mips64r2 instruction.
      float rounded = ceil(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case MINA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMinA(ft, fs));
      break;
    case MAXA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMaxA(ft, fs));
      break;
    case MIN:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMin(ft, fs));
      break;
    case MAX:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMax(ft, fs));
      break;
    case SEL:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), (fd_int & 0x1) == 0 ? fs : ft);
      break;
    case SELEQZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), (ft_int & 0x1) == 0
                                      ? get_fpu_register_float(fs_reg())
                                      : 0.0);
      break;
    case SELNEZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), (ft_int & 0x1) != 0
                                      ? get_fpu_register_float(fs_reg())
                                      : 0.0);
      break;
    case MOVZ_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() == 0) {
        SetFPUFloatResult(fd_reg(), fs);
      }
      break;
    }
    case MOVN_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() != 0) {
        SetFPUFloatResult(fd_reg(), fs);
      }
      break;
    }
    case MOVF: {
      // Same function field for MOVT.D and MOVF.D
      uint32_t ft_cc = (ft_reg() >> 2) & 0x7;
      ft_cc = get_fcsr_condition_bit(ft_cc);

      if (instr_.Bit(16)) {  // Read Tf bit.
        // MOVT.D
        if (test_fcsr_bit(ft_cc)) SetFPUFloatResult(fd_reg(), fs);
      } else {
        // MOVF.D
        if (!test_fcsr_bit(ft_cc)) SetFPUFloatResult(fd_reg(), fs);
      }
      break;
    }
    default:
      // TRUNC_W_S ROUND_W_S ROUND_L_S FLOOR_W_S FLOOR_L_S
      // CEIL_W_S CEIL_L_S CVT_PS_S are unimplemented.
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterDRsType() {
  double ft, fs, fd;
  uint32_t cc, fcsr_cc;
  fs = get_fpu_register_double(fs_reg());
  ft = (instr_.FunctionFieldRaw() != MOVF) ? get_fpu_register_double(ft_reg())
                                           : 0.0;
  fd = get_fpu_register_double(fd_reg());
  cc = instr_.FCccValue();
  fcsr_cc = get_fcsr_condition_bit(cc);
  int64_t ft_int = base::bit_cast<int64_t>(ft);
  int64_t fd_int = base::bit_cast<int64_t>(fd);
  switch (instr_.FunctionFieldRaw()) {
    case RINT: {
      DCHECK_EQ(kArchVariant, kMips64r6);
      double result, temp, temp_result;
      double upper = std::ceil(fs);
      double lower = std::floor(fs);
      switch (get_fcsr_rounding_mode()) {
        case kRoundToNearest:
          if (upper - fs < fs - lower) {
            result = upper;
          } else if (upper - fs > fs - lower) {
            result = lower;
          } else {
            temp_result = upper / 2;
            double reminder = modf(temp_result, &temp);
            if (reminder == 0) {
              result = upper;
            } else {
              result = lower;
            }
          }
          break;
        case kRoundToZero:
          result = (fs > 0 ? lower : upper);
          break;
        case kRoundToPlusInf:
          result = upper;
          break;
        case kRoundToMinusInf:
          result = lower;
          break;
      }
      SetFPUDoubleResult(fd_reg(), result);
      if (result != fs) {
        set_fcsr_bit(kFCSRInexactFlagBit, true);
      }
      break;
    }
    case SEL:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), (fd_int & 0x1) == 0 ? fs : ft);
      break;
    case SELEQZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), (ft_int & 0x1) == 0 ? fs : 0.0);
      break;
    case SELNEZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), (ft_int & 0x1) != 0 ? fs : 0.0);
      break;
    case MOVZ_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() == 0) {
        SetFPUDoubleResult(fd_reg(), fs);
      }
      break;
    }
    case MOVN_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() != 0) {
        SetFPUDoubleResult(fd_reg(), fs);
      }
      break;
    }
    case MOVF: {
      // Same function field for MOVT.D and MOVF.D
      uint32_t ft_cc = (ft_reg() >> 2) & 0x7;
      ft_cc = get_fcsr_condition_bit(ft_cc);
      if (instr_.Bit(16)) {  // Read Tf bit.
        // MOVT.D
        if (test_fcsr_bit(ft_cc)) SetFPUDoubleResult(fd_reg(), fs);
      } else {
        // MOVF.D
        if (!test_fcsr_bit(ft_cc)) SetFPUDoubleResult(fd_reg(), fs);
      }
      break;
    }
    case MINA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMinA(ft, fs));
      break;
    case MAXA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMaxA(ft, fs));
      break;
    case MIN:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMin(ft, fs));
      break;
    case MAX:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMax(ft, fs));
      break;
    case ADD_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs + rhs; }, fs, ft));
      break;
    case SUB_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs - rhs; }, fs, ft));
      break;
    case MADDF_D:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), std::fma(fs, ft, fd));
      break;
    case MSUBF_D:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), std::fma(-fs, ft, fd));
      break;
    case MUL_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs * rhs; }, fs, ft));
      break;
    case DIV_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs / rhs; }, fs, ft));
      break;
    case ABS_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation([](double fs) { return FPAbs(fs); }, fs));
      break;
    case MOV_D:
      SetFPUDoubleResult(fd_reg(), fs);
      break;
    case NEG_D:
      SetFPUDoubleResult(fd_reg(),
                         FPUCanonalizeOperation([](double src) { return -src; },
                                                KeepSign::yes, fs));
      break;
    case SQRT_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation([](double fs) { return std::sqrt(fs); }, fs));
      break;
    case RSQRT_D:
      SetFPUDoubleResult(
          fd_reg(), FPUCanonalizeOperation(
                        [](double fs) { return 1.0 / std::sqrt(fs); }, fs));
      break;
    case RECIP_D:
      SetFPUDoubleResult(fd_reg(), FPUCanonalizeOperation(
                                       [](double fs) { return 1.0 / fs; }, fs));
      break;
    case C_UN_D:
      set_fcsr_bit(fcsr_cc, std::isnan(fs) || std::isnan(ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_EQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_UEQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case CVT_W_D: {  // Convert double to word.
      double rounded;
      int32_t result;
      round_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
      break;
    }
    case ROUND_W_D:  // Round double to word (round half to even).
    {
      double rounded = std::floor(fs + 0.5);
      int32_t result = static_cast<int32_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case TRUNC_W_D:  // Truncate double to word (round towards 0).
    {
      double rounded = trunc(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case FLOOR_W_D:  // Round double to word towards negative infinity.
    {
      double rounded = std::floor(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case CEIL_W_D:  // Round double to word towards positive infinity.
    {
      double rounded = std::ceil(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult2(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case CVT_S_D:  // Convert double to float (single).
      SetFPUFloatResult(fd_reg(), static_cast<float>(fs));
      break;
    case CVT_L_D: {  // Mips64r2: Truncate double to 64-bit long-word.
      double rounded;
      int64_t result;
      round64_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case ROUND_L_D: {  // Mips64r2 instruction.
      double rounded = std::floor(fs + 0.5);
      int64_t result = static_cast<int64_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      int64_t i64 = static_cast<int64_t>(result);
      SetFPUResult(fd_reg(), i64);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case TRUNC_L_D: {  // Mips64r2 instruction.
      double rounded = trunc(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case FLOOR_L_D: {  // Mips64r2 instruction.
      double rounded = floor(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case CEIL_L_D: {  // Mips64r2 instruction.
      double rounded = ceil(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case CLASS_D: {  // Mips64r6 instruction
      // Convert double input to uint64_t for easier bit manipulation
      uint64_t classed = base::bit_cast<uint64_t>(fs);

      // Extracting sign, exponent and mantissa from the input double
      uint32_t sign = (classed >> 63) & 1;
      uint32_t exponent = (classed >> 52) & 0x00000000000007FF;
      uint64_t mantissa = classed & 0x000FFFFFFFFFFFFF;
      uint64_t result;
      double dResult;

      // Setting flags if input double is negative infinity,
      // positive infinity, negative zero or positive zero
      bool negInf = (classed == 0xFFF0000000000000);
      bool posInf = (classed == 0x7FF0000000000000);
      bool negZero = (classed == 0x8000000000000000);
      bool posZero = (classed == 0x0000000000000000);

      bool signalingNan;
      bool quietNan;
      bool negSubnorm;
      bool posSubnorm;
      bool negNorm;
      bool posNorm;

      // Setting flags if double is NaN
      signalingNan = false;
      quietNan = false;
      if (!negInf && !posInf && exponent == 0x7FF) {
        quietNan = ((mantissa & 0x0008000000000000) != 0) &&
                   ((mantissa & (0x0008000000000000 - 1)) == 0);
        signalingNan = !quietNan;
      }

      // Setting flags if double is subnormal number
      posSubnorm = false;
      negSubnorm = false;
      if ((exponent == 0) && (mantissa != 0)) {
        DCHECK(sign == 0 || sign == 1);
        posSubnorm = (sign == 0);
        negSubnorm = (sign == 1);
      }

      // Setting flags if double is normal number
      posNorm = false;
      negNorm = false;
      if (!posSubnorm && !negSubnorm && !posInf && !negInf && !signalingNan &&
          !quietNan && !negZero && !posZero) {
        DCHECK(sign == 0 || sign == 1);
        posNorm = (sign == 0);
        negNorm = (sign == 1);
      }

      // Calculating result according to description of CLASS.D instruction
      result = (posZero << 9) | (posSubnorm << 8) | (posNorm << 7) |
               (posInf << 6) | (negZero << 5) | (negSubnorm << 4) |
               (negNorm << 3) | (negInf << 2) | (quietNan << 1) | signalingNan;

      DCHECK_NE(result, 0);

      dResult = base::bit_cast<double>(result);
      SetFPUDoubleResult(fd_reg(), dResult);
      break;
    }
    case C_F_D: {
      set_fcsr_bit(fcsr_cc, false);
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterWRsType() {
  float fs = get_fpu_register_float(fs_reg());
  float ft = get_fpu_register_float(ft_reg());
  int64_t alu_out = 0x12345678;
  switch (instr_.FunctionFieldRaw()) {
    case CVT_S_W:  // Convert word to float (single).
      alu_out = get_fpu_register_signed_word(fs_reg());
      SetFPUFloatResult(fd_reg(), static_cast<float>(alu_out));
      break;
    case CVT_D_W:  // Convert word to double.
      alu_out = get_fpu_register_signed_word(fs_reg());
      SetFPUDoubleResult(fd_reg(), static_cast<double>(alu_out));
      break;
    case CMP_AF:
      SetFPUWordResult2(fd_reg(), 0);
      break;
    case CMP_UN:
      if (std::isnan(fs) || std::isnan(ft)) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_EQ:
      if (fs == ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_UEQ:
      if ((fs == ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_LT:
      if (fs < ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_ULT:
      if ((fs < ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_LE:
      if (fs <= ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_ULE:
      if ((fs <= ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_OR:
      if (!std::isnan(fs) && !std::isnan(ft)) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_UNE:
      if ((fs != ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_NE:
      if (fs != ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterLRsType() {
  double fs = get_fpu_register_double(fs_reg());
  double ft = get_fpu_register_double(ft_reg());
  int64_t i64;
  switch (instr_.FunctionFieldRaw()) {
    case CVT_D_L:  // Mips32r2 instruction.
      i64 = get_fpu_register(fs_reg());
      SetFPUDoubleResult(fd_reg(), static_cast<double>(i64));
      break;
    case CVT_S_L:
      i64 = get_fpu_register(fs_reg());
      SetFPUFloatResult(fd_reg(), static_cast<float>(i64));
      break;
    case CMP_AF:
      SetFPUResult(fd_reg(), 0);
      break;
    case CMP_UN:
      if (std::isnan(fs) || std::isnan(ft)) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_EQ:
      if (fs == ft) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_UEQ:
      if ((fs == ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_LT:
      if (fs < ft) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_ULT:
      if ((fs < ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_LE:
      if (fs <= ft) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_ULE:
      if ((fs <= ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_OR:
      if (!std::isnan(fs) && !std::isnan(ft)) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_UNE:
      if ((fs != ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_NE:
      if (fs != ft && (!std::isnan(fs) && !std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterCOP1() {
  switch (instr_.RsFieldRaw()) {
    case BC1:  // Branch on coprocessor condition.
    case BC1EQZ:
    case BC1NEZ:
      UNREACHABLE();
    case CFC1:
      // At the moment only FCSR is supported.
      DCHECK_EQ(fs_reg(), kFCSRRegister);
      SetResult(rt_reg(), FCSR_);
      break;
    case MFC1:
      set_register(rt_reg(),
                   static_cast<int64_t>(get_fpu_register_word(fs_reg())));
      TraceRegWr(get_register(rt_reg()), WORD_DWORD);
      break;
    case DMFC1:
      SetResult(rt_reg(), get_fpu_register(fs_reg()));
      break;
    case MFHC1:
      SetResult(rt_reg(), get_fpu_register_hi_word(fs_reg()));
      break;
    case CTC1: {
      // At the moment only FCSR is supported.
      DCHECK_EQ(fs_reg(), kFCSRRegist
```