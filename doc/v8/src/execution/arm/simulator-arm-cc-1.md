Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `simulator-arm.cc` file in the V8 JavaScript engine. Specifically, they're asking for a continuation of a previous analysis.

Here's a breakdown of the code and how to summarize its function:

1. **`TrashCallerSaveRegisters()`**: This function sets specific registers to a "trash" value (`0x50BAD4U`) or NaN. This likely happens before or after calling external functions to ensure that the calling convention is respected and that external functions don't rely on the caller-saved registers to contain specific values.

2. **Memory Access Functions (`ReadW`, `WriteW`, `ReadH`, `WriteH`, `ReadB`, `WriteB`, `ReadDW`, `WriteDW`, and their `Ex` counterparts)**: These functions simulate reading and writing data of different sizes (word, half-word, byte, double-word) from simulated memory. The `Ex` versions likely stand for "Exclusive", and are related to atomic operations. These functions use mutexes (`base::MutexGuard`) and a `GlobalMonitor` and `local_monitor_` to track memory accesses, potentially for debugging or correctness checking in a multithreaded environment. The comment "All supported ARM targets allow unaligned accesses" is important context.

3. **`StackLimit()` and `GetCentralStackView()`**: These functions deal with managing the simulated stack. `StackLimit()` determines the boundary to prevent stack overflows, taking into account both the simulated stack and the real C++ stack. `GetCentralStackView()` provides a view of the simulated stack's contents.

4. **`Format()`**: This function is used to report an error when an unsupported instruction is encountered. It prints the instruction address and a format string before triggering an `UNIMPLEMENTED()` error.

5. **`ConditionallyExecute()`**: This function determines whether an instruction should be executed based on the ARM condition codes (flags like zero, negative, carry, overflow).

6. **Flag Manipulation Functions (`SetNZFlags`, `SetCFlag`, `SetVFlag`)**: These functions set the ARM processor flags based on the results of operations.

7. **Carry and Overflow Calculation Functions (`CarryFrom`, `BorrowFrom`, `OverflowFrom`)**: These functions implement the logic to calculate the Carry and Overflow flags based on arithmetic operations.

8. **VFP (Vector Floating Point) Comparison Functions (`Compute_FPSCR_Flags`) and Flag Transfer (`Copy_FPSCR_to_APSR`)**: These functions handle comparisons for floating-point numbers and copying the VFP status flags to the ARM Application Program Status Register (APSR).

9. **Operand Fetching Functions (`GetShiftRm`, `GetImm`)**: These functions implement the different ways operands are accessed in ARM instructions, including immediate values and register values with optional shifts and rotations.

10. **Load and Store Multiple Support (`ProcessPU`, `HandleRList`, `HandleVList`)**: These functions implement the logic for `LDM` (Load Multiple) and `STM` (Store Multiple) instructions, which can transfer multiple registers to or from memory in a single instruction. They handle different addressing modes.

11. **Runtime Call Support (`SimulatorRuntimeCall`, `SoftwareInterrupt`, `UnsafeGenericFunctionCall`)**:  This is a crucial section. It defines how the simulator interacts with the V8 runtime environment. The `SoftwareInterrupt` function handles calls to C++ functions within V8. It extracts arguments from registers and the stack, performs the call, and then handles the return value. Different function pointer types (`SimulatorRuntimeCompareCall`, `SimulatorRuntimeFPFPCall`, etc.) are used for different types of runtime calls, especially those involving floating-point numbers. The `UnsafeGenericFunctionCall` is a workaround for type safety issues due to the varied signatures of runtime functions.

12. **The remaining part of `SoftwareInterrupt`**: This section within the `SoftwareInterrupt` function handles various types of runtime calls, including:
    * Calls to built-in functions (potentially with floating-point arguments)
    * Direct calls to API functions
    * Direct calls to accessor getters

**Summarizing the Functionality for Part 2:**

Based on the provided code, the primary function of this section of `simulator-arm.cc` is to **simulate the execution of ARM instructions, particularly those related to memory access, stack manipulation, conditional execution, flag handling, and calls to the V8 runtime**. This involves:

* **Simulating memory reads and writes of various sizes,** with support for unaligned accesses and optional atomic operations (exclusive accesses).
* **Managing the simulated stack** and preventing overflows.
* **Evaluating instruction conditions** based on processor flags.
* **Calculating and setting processor flags** based on arithmetic and logical operations, including floating-point comparisons.
* **Fetching operands** for instructions using different addressing modes, including shifts and rotations.
* **Handling load and store multiple instructions**, allowing efficient transfer of register blocks.
* **Providing a mechanism for calling into the V8 runtime environment** from the simulated ARM code, including handling function arguments and return values for different call types (integer, floating-point, API calls). This is a core part of how the simulator allows executing JavaScript code within a simulated ARM environment.

这是`v8/src/execution/arm/simulator-arm.cc`的第2部分代码，主要功能是继续实现ARM架构的模拟器，涵盖了以下几个关键方面：

**功能归纳：**

1. **模拟寄存器状态管理:**  `TrashCallerSaveRegisters` 函数模拟在函数调用前后清理调用者保存的寄存器，防止外部函数依赖这些寄存器的旧值。这对于模拟环境的正确性至关重要。

2. **模拟内存访问:** 提供了一系列函数 (`ReadW`, `WriteW`, `ReadH`, `WriteH`, `ReadB`, `WriteB`, `ReadDW`, `WriteDW` 及其 `Ex` 版本) 来模拟ARM架构下的内存读写操作。这些函数支持非对齐访问，并引入了互斥锁 (`base::MutexGuard`) 和监控机制 (`local_monitor_`, `GlobalMonitor`) 来跟踪内存操作，可能用于调试或同步。`Ex` 版本暗示了对独占访问的支持，用于实现原子操作。

3. **模拟栈操作:** `StackLimit` 函数返回模拟栈的上限，用于检测栈溢出。它会考虑宿主 C++ 栈的状态，以更精确地模拟栈的行为。`GetCentralStackView` 函数则提供了模拟栈的内存视图。

4. **错误处理:** `Format` 函数用于处理模拟器遇到不支持的指令的情况，会打印错误信息并终止执行。

5. **条件执行模拟:** `ConditionallyExecute` 函数根据ARM指令的条件码来判断是否应该执行该指令，这是ARM架构的一个核心特性。

6. **标志位操作:**  `SetNZFlags`, `SetCFlag`, `SetVFlag` 函数用于设置ARM处理器的标志位（N, Z, C, V），这些标志位会影响条件执行的结果。

7. **计算标志位:** `CarryFrom`, `BorrowFrom`, `OverflowFrom` 函数实现了加减运算中进位、借位和溢出标志位的计算逻辑。

8. **VFP (浮点单元) 支持:**  `Compute_FPSCR_Flags` 函数用于模拟浮点比较操作，并设置浮点状态控制寄存器（FPSCR）的标志位。 `Copy_FPSCR_to_APSR` 函数将FPSCR的标志位复制到ARM应用处理器状态寄存器（APSR），使得条件执行可以基于浮点比较的结果。

9. **寻址模式模拟:** `GetShiftRm` 和 `GetImm` 函数模拟了ARM指令中操作数的获取方式，包括寄存器移位和立即数。

10. **Load/Store 多寄存器指令模拟:** `ProcessPU`, `HandleRList`, `HandleVList` 函数用于模拟 `LDM` (Load Multiple) 和 `STM` (Store Multiple) 指令，这些指令可以一次性加载或存储多个寄存器的值。 `HandleVList` 专门处理VFP寄存器的批量加载和存储。

11. **模拟运行时调用:**  `SimulatorRuntimeCall`, `SoftwareInterrupt`, `UnsafeGenericFunctionCall` 定义了模拟器如何调用V8的运行时函数。 `SoftwareInterrupt` 函数处理软件中断指令，这通常用于从模拟代码跳转到V8的C++运行时。它负责从寄存器和栈中提取参数，调用运行时函数，并将结果写回寄存器。针对不同类型的运行时调用（例如，涉及浮点数的调用），使用了不同的函数指针类型。`UnsafeGenericFunctionCall` 提供了一个通用的函数调用方式。

**与 JavaScript 功能的关系:**

这部分代码是 V8 模拟器的核心，它直接关系到 JavaScript 代码的执行。当 V8 在不支持目标架构的平台上运行时，或者为了进行调试和测试，它会使用模拟器来执行生成的机器码。

例如，当 JavaScript 代码执行一个需要调用 V8 内部运行时函数的操作时（比如分配内存、类型转换等），模拟器中的 `SoftwareInterrupt` 函数就会被触发，模拟调用相应的 C++ 运行时函数。

**JavaScript 示例 (假设 `kCallRtRedirected` 对应某个运行时函数):**

```javascript
// 假设以下 JavaScript 代码会导致调用一个运行时函数

function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

在这个例子中，当模拟器执行 `add` 函数的加法操作时，如果 V8 内部使用了一个运行时函数来实现加法（尽管实际情况可能更复杂，通常加法是直接的机器指令），那么就会触发一个软件中断，对应到 `Simulator::SoftwareInterrupt` 函数中的 `kCallRtRedirected` 分支。模拟器会提取 `a` 和 `b` 的值，并调用 V8 的 C++ 运行时函数来执行加法。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `instr` 是一个模拟的 ARM 指令，表示将寄存器 `r1` 的值加到寄存器 `r2`，并将结果存回 `r2`，同时设置标志位。
* `get_register(1)` 返回 `10`。
* `get_register(2)` 返回 `5`。

**输出:**

* 在执行完模拟的指令后，`get_register(2)` 将返回 `15`。
* `n_flag_` (负数标志) 将为 `false`。
* `z_flag_` (零标志) 将为 `false`。
* `c_flag_` (进位标志) 将为 `false` (假设没有溢出)。
* `v_flag_` (溢出标志) 将为 `false` (假设没有溢出)。

**用户常见的编程错误 (在模拟器层面):**

由于这部分代码是模拟器的一部分，用户直接编写 JavaScript 代码不会遇到这些错误。但是，在开发或理解 V8 内部机制时，可能会遇到以下与模拟相关的概念性错误：

1. **错误理解调用约定:**  不清楚哪些寄存器是调用者保存的，哪些是被调用者保存的，可能导致在模拟器中错误地假设寄存器的值。 `TrashCallerSaveRegisters` 的作用就是强调这一点。

2. **忽略内存对齐:** 尽管代码中提到 ARM 允许非对齐访问，但在某些情况下，性能仍然会受到影响。在理解 V8 的内存布局和访问模式时，可能会错误地假设所有访问都是高效的。

3. **对运行时调用的理解偏差:**  不清楚哪些 JavaScript 操作会触发运行时调用，以及这些调用是如何传递参数和返回值的，可能导致对模拟执行流程的误解。

**总结这部分代码的功能:**

这部分 `simulator-arm.cc` 代码的核心功能是 **模拟 ARM 处理器的指令执行，包括寄存器和内存管理、条件执行、标志位操作、浮点运算以及与 V8 运行时的交互**。它是 V8 在非 ARM 平台上运行或进行调试的关键组成部分，使得 JavaScript 代码能够在模拟的 ARM 环境中执行。

### 提示词
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm/simulator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
gisters_, buffer, sizeof(buffer));
  }
}

void Simulator::TrashCallerSaveRegisters() {
  // Return registers.
  registers_[0] = 0x50BAD4U;
  registers_[1] = 0x50BAD4U;
  // Caller-saved registers.
  registers_[2] = 0x50BAD4U;
  registers_[3] = 0x50BAD4U;
  registers_[12] = 0x50BAD4U;
  // This value is a NaN in both 32-bit and 64-bit FP.
  static const uint64_t v = 0x7ff000007f801000UL;
  // d0 - d7 are caller-saved.
  for (int i = 0; i < 8; i++) {
    set_d_register(i, &v);
  }
  if (DoubleRegister::SupportedRegisterCount() > 16) {
    // d16 - d31 (if supported) are caller-saved.
    for (int i = 16; i < 32; i++) {
      set_d_register(i, &v);
    }
  }
}

int Simulator::ReadW(int32_t addr) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoad(addr);
  return base::ReadUnalignedValue<intptr_t>(addr);
}

int Simulator::ReadExW(int32_t addr) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoadExcl(addr, TransactionSize::Word);
  GlobalMonitor::Get()->NotifyLoadExcl_Locked(addr, &global_monitor_processor_);
  return base::ReadUnalignedValue<intptr_t>(addr);
}

void Simulator::WriteW(int32_t addr, int value) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyStore(addr);
  GlobalMonitor::Get()->NotifyStore_Locked(addr, &global_monitor_processor_);
  base::WriteUnalignedValue<intptr_t>(addr, value);
}

int Simulator::WriteExW(int32_t addr, int value) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  if (local_monitor_.NotifyStoreExcl(addr, TransactionSize::Word) &&
      GlobalMonitor::Get()->NotifyStoreExcl_Locked(
          addr, &global_monitor_processor_)) {
    base::WriteUnalignedValue<intptr_t>(addr, value);
    return 0;
  } else {
    return 1;
  }
}

uint16_t Simulator::ReadHU(int32_t addr) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoad(addr);
  return base::ReadUnalignedValue<uint16_t>(addr);
}

int16_t Simulator::ReadH(int32_t addr) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoad(addr);
  return base::ReadUnalignedValue<int16_t>(addr);
}

uint16_t Simulator::ReadExHU(int32_t addr) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoadExcl(addr, TransactionSize::HalfWord);
  GlobalMonitor::Get()->NotifyLoadExcl_Locked(addr, &global_monitor_processor_);
  return base::ReadUnalignedValue<uint16_t>(addr);
}

void Simulator::WriteH(int32_t addr, uint16_t value) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyStore(addr);
  GlobalMonitor::Get()->NotifyStore_Locked(addr, &global_monitor_processor_);
  base::WriteUnalignedValue(addr, value);
}

void Simulator::WriteH(int32_t addr, int16_t value) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyStore(addr);
  GlobalMonitor::Get()->NotifyStore_Locked(addr, &global_monitor_processor_);
  base::WriteUnalignedValue(addr, value);
}

int Simulator::WriteExH(int32_t addr, uint16_t value) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  if (local_monitor_.NotifyStoreExcl(addr, TransactionSize::HalfWord) &&
      GlobalMonitor::Get()->NotifyStoreExcl_Locked(
          addr, &global_monitor_processor_)) {
    base::WriteUnalignedValue(addr, value);
    return 0;
  } else {
    return 1;
  }
}

uint8_t Simulator::ReadBU(int32_t addr) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoad(addr);
  return base::ReadUnalignedValue<uint8_t>(addr);
}

int8_t Simulator::ReadB(int32_t addr) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoad(addr);
  return base::ReadUnalignedValue<int8_t>(addr);
}

uint8_t Simulator::ReadExBU(int32_t addr) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoadExcl(addr, TransactionSize::Byte);
  GlobalMonitor::Get()->NotifyLoadExcl_Locked(addr, &global_monitor_processor_);
  return base::ReadUnalignedValue<uint8_t>(addr);
}

void Simulator::WriteB(int32_t addr, uint8_t value) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyStore(addr);
  GlobalMonitor::Get()->NotifyStore_Locked(addr, &global_monitor_processor_);
  base::WriteUnalignedValue(addr, value);
}

void Simulator::WriteB(int32_t addr, int8_t value) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyStore(addr);
  GlobalMonitor::Get()->NotifyStore_Locked(addr, &global_monitor_processor_);
  base::WriteUnalignedValue(addr, value);
}

int Simulator::WriteExB(int32_t addr, uint8_t value) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  if (local_monitor_.NotifyStoreExcl(addr, TransactionSize::Byte) &&
      GlobalMonitor::Get()->NotifyStoreExcl_Locked(
          addr, &global_monitor_processor_)) {
    base::WriteUnalignedValue(addr, value);
    return 0;
  } else {
    return 1;
  }
}

int32_t* Simulator::ReadDW(int32_t addr) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoad(addr);
  return reinterpret_cast<int32_t*>(addr);
}

int32_t* Simulator::ReadExDW(int32_t addr) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyLoadExcl(addr, TransactionSize::DoubleWord);
  GlobalMonitor::Get()->NotifyLoadExcl_Locked(addr, &global_monitor_processor_);
  return reinterpret_cast<int32_t*>(addr);
}

void Simulator::WriteDW(int32_t addr, int32_t value1, int32_t value2) {
  // All supported ARM targets allow unaligned accesses, so we don't need to
  // check the alignment here.
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  local_monitor_.NotifyStore(addr);
  GlobalMonitor::Get()->NotifyStore_Locked(addr, &global_monitor_processor_);
  base::WriteUnalignedValue(addr, value1);
  base::WriteUnalignedValue(addr + sizeof(value1), value2);
}

int Simulator::WriteExDW(int32_t addr, int32_t value1, int32_t value2) {
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  if (local_monitor_.NotifyStoreExcl(addr, TransactionSize::DoubleWord) &&
      GlobalMonitor::Get()->NotifyStoreExcl_Locked(
          addr, &global_monitor_processor_)) {
    base::WriteUnalignedValue(addr, value1);
    base::WriteUnalignedValue(addr + sizeof(value1), value2);
    return 0;
  } else {
    return 1;
  }
}

// Returns the limit of the stack area to enable checking for stack overflows.
uintptr_t Simulator::StackLimit(uintptr_t c_limit) const {
  // The simulator uses a separate JS stack. If we have exhausted the C stack,
  // we also drop down the JS limit to reflect the exhaustion on the JS stack.
  if (base::Stack::GetCurrentStackPosition() < c_limit) {
    return reinterpret_cast<uintptr_t>(get_sp());
  }

  // Otherwise the limit is the JS stack. Leave a safety margin to prevent
  // overrunning the stack when pushing values.
  return reinterpret_cast<uintptr_t>(stack_) + kAdditionalStackMargin;
}

base::Vector<uint8_t> Simulator::GetCentralStackView() const {
  // We do not add an additional safety margin as above in
  // Simulator::StackLimit, as this is currently only used in wasm::StackMemory,
  // which adds its own margin.
  return base::VectorOf(stack_, kUsableStackSize);
}

// Unsupported instructions use Format to print an error and stop execution.
void Simulator::Format(Instruction* instr, const char* format) {
  PrintF("Simulator found unsupported instruction:\n 0x%08" V8PRIxPTR ": %s\n",
         reinterpret_cast<intptr_t>(instr), format);
  UNIMPLEMENTED();
}

// Checks if the current instruction should be executed based on its
// condition bits.
bool Simulator::ConditionallyExecute(Instruction* instr) {
  switch (instr->ConditionField()) {
    case eq:
      return z_flag_;
    case ne:
      return !z_flag_;
    case cs:
      return c_flag_;
    case cc:
      return !c_flag_;
    case mi:
      return n_flag_;
    case pl:
      return !n_flag_;
    case vs:
      return v_flag_;
    case vc:
      return !v_flag_;
    case hi:
      return c_flag_ && !z_flag_;
    case ls:
      return !c_flag_ || z_flag_;
    case ge:
      return n_flag_ == v_flag_;
    case lt:
      return n_flag_ != v_flag_;
    case gt:
      return !z_flag_ && (n_flag_ == v_flag_);
    case le:
      return z_flag_ || (n_flag_ != v_flag_);
    case al:
      return true;
    default:
      UNREACHABLE();
  }
}

// Calculate and set the Negative and Zero flags.
void Simulator::SetNZFlags(int32_t val) {
  n_flag_ = (val < 0);
  z_flag_ = (val == 0);
}

// Set the Carry flag.
void Simulator::SetCFlag(bool val) { c_flag_ = val; }

// Set the oVerflow flag.
void Simulator::SetVFlag(bool val) { v_flag_ = val; }

// Calculate C flag value for additions.
bool Simulator::CarryFrom(int32_t left, int32_t right, int32_t carry) {
  uint32_t uleft = static_cast<uint32_t>(left);
  uint32_t uright = static_cast<uint32_t>(right);
  uint32_t urest = 0xFFFFFFFFU - uleft;

  return (uright > urest) ||
         (carry && (((uright + 1) > urest) || (uright > (urest - 1))));
}

// Calculate C flag value for subtractions.
bool Simulator::BorrowFrom(int32_t left, int32_t right, int32_t carry) {
  uint32_t uleft = static_cast<uint32_t>(left);
  uint32_t uright = static_cast<uint32_t>(right);

  return (uright > uleft) ||
         (!carry && (((uright + 1) > uleft) || (uright > (uleft - 1))));
}

// Calculate V flag value for additions and subtractions.
bool Simulator::OverflowFrom(int32_t alu_out, int32_t left, int32_t right,
                             bool addition) {
  bool overflow;
  if (addition) {
    // operands have the same sign
    overflow = ((left >= 0 && right >= 0) || (left < 0 && right < 0))
               // and operands and result have different sign
               && ((left < 0 && alu_out >= 0) || (left >= 0 && alu_out < 0));
  } else {
    // operands have different signs
    overflow = ((left < 0 && right >= 0) || (left >= 0 && right < 0))
               // and first operand and result have different signs
               && ((left < 0 && alu_out >= 0) || (left >= 0 && alu_out < 0));
  }
  return overflow;
}

// Support for VFP comparisons.
void Simulator::Compute_FPSCR_Flags(float val1, float val2) {
  if (std::isnan(val1) || std::isnan(val2)) {
    n_flag_FPSCR_ = false;
    z_flag_FPSCR_ = false;
    c_flag_FPSCR_ = true;
    v_flag_FPSCR_ = true;
    // All non-NaN cases.
  } else if (val1 == val2) {
    n_flag_FPSCR_ = false;
    z_flag_FPSCR_ = true;
    c_flag_FPSCR_ = true;
    v_flag_FPSCR_ = false;
  } else if (val1 < val2) {
    n_flag_FPSCR_ = true;
    z_flag_FPSCR_ = false;
    c_flag_FPSCR_ = false;
    v_flag_FPSCR_ = false;
  } else {
    // Case when (val1 > val2).
    n_flag_FPSCR_ = false;
    z_flag_FPSCR_ = false;
    c_flag_FPSCR_ = true;
    v_flag_FPSCR_ = false;
  }
}

void Simulator::Compute_FPSCR_Flags(double val1, double val2) {
  if (std::isnan(val1) || std::isnan(val2)) {
    n_flag_FPSCR_ = false;
    z_flag_FPSCR_ = false;
    c_flag_FPSCR_ = true;
    v_flag_FPSCR_ = true;
    // All non-NaN cases.
  } else if (val1 == val2) {
    n_flag_FPSCR_ = false;
    z_flag_FPSCR_ = true;
    c_flag_FPSCR_ = true;
    v_flag_FPSCR_ = false;
  } else if (val1 < val2) {
    n_flag_FPSCR_ = true;
    z_flag_FPSCR_ = false;
    c_flag_FPSCR_ = false;
    v_flag_FPSCR_ = false;
  } else {
    // Case when (val1 > val2).
    n_flag_FPSCR_ = false;
    z_flag_FPSCR_ = false;
    c_flag_FPSCR_ = true;
    v_flag_FPSCR_ = false;
  }
}

void Simulator::Copy_FPSCR_to_APSR() {
  n_flag_ = n_flag_FPSCR_;
  z_flag_ = z_flag_FPSCR_;
  c_flag_ = c_flag_FPSCR_;
  v_flag_ = v_flag_FPSCR_;
}

// Addressing Mode 1 - Data-processing operands:
// Get the value based on the shifter_operand with register.
int32_t Simulator::GetShiftRm(Instruction* instr, bool* carry_out) {
  ShiftOp shift = instr->ShiftField();
  int shift_amount = instr->ShiftAmountValue();
  int32_t result = get_register(instr->RmValue());
  if (instr->Bit(4) == 0) {
    // by immediate
    if ((shift == ROR) && (shift_amount == 0)) {
      UNIMPLEMENTED();
    } else if (((shift == LSR) || (shift == ASR)) && (shift_amount == 0)) {
      shift_amount = 32;
    }
    switch (shift) {
      case ASR: {
        if (shift_amount == 0) {
          if (result < 0) {
            result = 0xFFFFFFFF;
            *carry_out = true;
          } else {
            result = 0;
            *carry_out = false;
          }
        } else {
          result >>= (shift_amount - 1);
          *carry_out = (result & 1) == 1;
          result >>= 1;
        }
        break;
      }

      case LSL: {
        if (shift_amount == 0) {
          *carry_out = c_flag_;
        } else {
          result = static_cast<uint32_t>(result) << (shift_amount - 1);
          *carry_out = (result < 0);
          result = static_cast<uint32_t>(result) << 1;
        }
        break;
      }

      case LSR: {
        if (shift_amount == 0) {
          result = 0;
          *carry_out = c_flag_;
        } else {
          uint32_t uresult = static_cast<uint32_t>(result);
          uresult >>= (shift_amount - 1);
          *carry_out = (uresult & 1) == 1;
          uresult >>= 1;
          result = static_cast<int32_t>(uresult);
        }
        break;
      }

      case ROR: {
        if (shift_amount == 0) {
          *carry_out = c_flag_;
        } else {
          result = base::bits::RotateRight32(result, shift_amount);
          *carry_out = (static_cast<uint32_t>(result) >> 31) != 0;
        }
        break;
      }

      default: {
        UNREACHABLE();
      }
    }
  } else {
    // by register
    int rs = instr->RsValue();
    shift_amount = get_register(rs) & 0xFF;
    switch (shift) {
      case ASR: {
        if (shift_amount == 0) {
          *carry_out = c_flag_;
        } else if (shift_amount < 32) {
          result >>= (shift_amount - 1);
          *carry_out = (result & 1) == 1;
          result >>= 1;
        } else {
          DCHECK_GE(shift_amount, 32);
          if (result < 0) {
            *carry_out = true;
            result = 0xFFFFFFFF;
          } else {
            *carry_out = false;
            result = 0;
          }
        }
        break;
      }

      case LSL: {
        if (shift_amount == 0) {
          *carry_out = c_flag_;
        } else if (shift_amount < 32) {
          result = static_cast<uint32_t>(result) << (shift_amount - 1);
          *carry_out = (result < 0);
          result = static_cast<uint32_t>(result) << 1;
        } else if (shift_amount == 32) {
          *carry_out = (result & 1) == 1;
          result = 0;
        } else {
          DCHECK_GT(shift_amount, 32);
          *carry_out = false;
          result = 0;
        }
        break;
      }

      case LSR: {
        if (shift_amount == 0) {
          *carry_out = c_flag_;
        } else if (shift_amount < 32) {
          uint32_t uresult = static_cast<uint32_t>(result);
          uresult >>= (shift_amount - 1);
          *carry_out = (uresult & 1) == 1;
          uresult >>= 1;
          result = static_cast<int32_t>(uresult);
        } else if (shift_amount == 32) {
          *carry_out = (result < 0);
          result = 0;
        } else {
          *carry_out = false;
          result = 0;
        }
        break;
      }

      case ROR: {
        if (shift_amount == 0) {
          *carry_out = c_flag_;
        } else {
          // Avoid undefined behavior. Rotating by multiples of 32 is no-op.
          result = base::bits::RotateRight32(result, shift_amount & 31);
          *carry_out = (static_cast<uint32_t>(result) >> 31) != 0;
        }
        break;
      }

      default: {
        UNREACHABLE();
      }
    }
  }
  return result;
}

// Addressing Mode 1 - Data-processing operands:
// Get the value based on the shifter_operand with immediate.
int32_t Simulator::GetImm(Instruction* instr, bool* carry_out) {
  int rotate = instr->RotateValue() * 2;
  int immed8 = instr->Immed8Value();
  int imm = base::bits::RotateRight32(immed8, rotate);
  *carry_out = (rotate == 0) ? c_flag_ : (imm < 0);
  return imm;
}

static int count_bits(int bit_vector) {
  int count = 0;
  while (bit_vector != 0) {
    if ((bit_vector & 1) != 0) {
      count++;
    }
    bit_vector >>= 1;
  }
  return count;
}

int32_t Simulator::ProcessPU(Instruction* instr, int num_regs, int reg_size,
                             intptr_t* start_address, intptr_t* end_address) {
  int rn = instr->RnValue();
  int32_t rn_val = get_register(rn);
  switch (instr->PUField()) {
    case da_x: {
      UNIMPLEMENTED();
    }
    case ia_x: {
      *start_address = rn_val;
      *end_address = rn_val + (num_regs * reg_size) - reg_size;
      rn_val = rn_val + (num_regs * reg_size);
      break;
    }
    case db_x: {
      *start_address = rn_val - (num_regs * reg_size);
      *end_address = rn_val - reg_size;
      rn_val = *start_address;
      break;
    }
    case ib_x: {
      *start_address = rn_val + reg_size;
      *end_address = rn_val + (num_regs * reg_size);
      rn_val = *end_address;
      break;
    }
    default: {
      UNREACHABLE();
    }
  }
  return rn_val;
}

// Addressing Mode 4 - Load and Store Multiple
void Simulator::HandleRList(Instruction* instr, bool load) {
  int rlist = instr->RlistValue();
  int num_regs = count_bits(rlist);

  intptr_t start_address = 0;
  intptr_t end_address = 0;
  int32_t rn_val =
      ProcessPU(instr, num_regs, kPointerSize, &start_address, &end_address);

  intptr_t* address = reinterpret_cast<intptr_t*>(start_address);
  // Catch null pointers a little earlier.
  DCHECK(start_address > 8191 || start_address < 0);
  int reg = 0;
  while (rlist != 0) {
    if ((rlist & 1) != 0) {
      if (load) {
        set_register(reg, *address);
      } else {
        *address = get_register(reg);
      }
      address += 1;
    }
    reg++;
    rlist >>= 1;
  }
  DCHECK(end_address == ((intptr_t)address) - 4);
  if (instr->HasW()) {
    set_register(instr->RnValue(), rn_val);
  }
}

// Addressing Mode 6 - Load and Store Multiple Coprocessor registers.
void Simulator::HandleVList(Instruction* instr) {
  VFPRegPrecision precision =
      (instr->SzValue() == 0) ? kSinglePrecision : kDoublePrecision;
  int operand_size = (precision == kSinglePrecision) ? 4 : 8;

  bool load = (instr->VLValue() == 0x1);

  int vd;
  int num_regs;
  vd = instr->VFPDRegValue(precision);
  if (precision == kSinglePrecision) {
    num_regs = instr->Immed8Value();
  } else {
    num_regs = instr->Immed8Value() / 2;
  }

  intptr_t start_address = 0;
  intptr_t end_address = 0;
  int32_t rn_val =
      ProcessPU(instr, num_regs, operand_size, &start_address, &end_address);

  intptr_t* address = reinterpret_cast<intptr_t*>(start_address);
  for (int reg = vd; reg < vd + num_regs; reg++) {
    if (precision == kSinglePrecision) {
      if (load) {
        set_s_register_from_sinteger(reg,
                                     ReadW(reinterpret_cast<int32_t>(address)));
      } else {
        WriteW(reinterpret_cast<int32_t>(address),
               get_sinteger_from_s_register(reg));
      }
      address += 1;
    } else {
      if (load) {
        int32_t data[] = {ReadW(reinterpret_cast<int32_t>(address)),
                          ReadW(reinterpret_cast<int32_t>(address + 1))};
        set_d_register(reg, reinterpret_cast<uint32_t*>(data));
      } else {
        uint32_t data[2];
        get_d_register(reg, data);
        WriteW(reinterpret_cast<int32_t>(address), data[0]);
        WriteW(reinterpret_cast<int32_t>(address + 1), data[1]);
      }
      address += 2;
    }
  }
  DCHECK(reinterpret_cast<intptr_t>(address) - operand_size == end_address);
  if (instr->HasW()) {
    set_register(instr->RnValue(), rn_val);
  }
}

// Calls into the V8 runtime are based on this very simple interface.
// Note: To be able to return two values from some calls the code in runtime.cc
// uses the ObjectPair which is essentially two 32-bit values stuffed into a
// 64-bit value. With the code below we assume that all runtime calls return
// 64 bits of result. If they don't, the r1 result register contains a bogus
// value, which is fine because it is caller-saved.
using SimulatorRuntimeCall = int64_t (*)(
    int32_t arg0, int32_t arg1, int32_t arg2, int32_t arg3, int32_t arg4,
    int32_t arg5, int32_t arg6, int32_t arg7, int32_t arg8, int32_t arg9,
    int32_t arg10, int32_t arg11, int32_t arg12, int32_t arg13, int32_t arg14,
    int32_t arg15, int32_t arg16, int32_t arg17, int32_t arg18, int32_t arg19);

// These prototypes handle the four types of FP calls.
using SimulatorRuntimeCompareCall = int64_t (*)(double darg0, double darg1);
using SimulatorRuntimeFPFPCall = double (*)(double darg0, double darg1);
using SimulatorRuntimeFPCall = double (*)(double darg0);
using SimulatorRuntimeFPIntCall = double (*)(double darg0, int32_t arg0);
// Define four args for future flexibility; at the time of this writing only
// one is ever used.
using SimulatorRuntimeFPTaggedCall = double (*)(int32_t arg0, int32_t arg1,
                                                int32_t arg2, int32_t arg3);

// This signature supports direct call in to API function native callback
// (refer to InvocationCallback in v8.h).
using SimulatorRuntimeDirectApiCall = void (*)(int32_t arg0);

// This signature supports direct call to accessor getter callback.
using SimulatorRuntimeDirectGetterCall = void (*)(int32_t arg0, int32_t arg1);

// Separate for fine-grained UBSan blocklisting. Casting any given C++
// function to {SimulatorRuntimeCall} is undefined behavior; but since
// the target function can indeed be any function that's exposed via
// the "fast C call" mechanism, we can't reconstruct its signature here.
int64_t UnsafeGenericFunctionCall(intptr_t function, int32_t arg0, int32_t arg1,
                                  int32_t arg2, int32_t arg3, int32_t arg4,
                                  int32_t arg5, int32_t arg6, int32_t arg7,
                                  int32_t arg8, int32_t arg9, int32_t arg10,
                                  int32_t arg11, int32_t arg12, int32_t arg13,
                                  int32_t arg14, int32_t arg15, int32_t arg16,
                                  int32_t arg17, int32_t arg18, int32_t arg19) {
  SimulatorRuntimeCall target =
      reinterpret_cast<SimulatorRuntimeCall>(function);
  return target(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9,
                arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, arg18,
                arg19);
}

// Software interrupt instructions are used by the simulator to call into the
// C-based V8 runtime.
void Simulator::SoftwareInterrupt(Instruction* instr) {
  int svc = instr->SvcValue();
  switch (svc) {
    case kCallRtRedirected: {
      // Check if stack is aligned. Error if not aligned is reported below to
      // include information on the function called.
      bool stack_aligned =
          (get_register(sp) & (v8_flags.sim_stack_alignment - 1)) == 0;
      Redirection* redirection = Redirection::FromInstruction(instr);
      int32_t arg0 = get_register(r0);
      int32_t arg1 = get_register(r1);
      int32_t arg2 = get_register(r2);
      int32_t arg3 = get_register(r3);
      int32_t* stack_pointer = reinterpret_cast<int32_t*>(get_register(sp));
      int32_t arg4 = stack_pointer[0];
      int32_t arg5 = stack_pointer[1];
      int32_t arg6 = stack_pointer[2];
      int32_t arg7 = stack_pointer[3];
      int32_t arg8 = stack_pointer[4];
      int32_t arg9 = stack_pointer[5];
      int32_t arg10 = stack_pointer[6];
      int32_t arg11 = stack_pointer[7];
      int32_t arg12 = stack_pointer[8];
      int32_t arg13 = stack_pointer[9];
      int32_t arg14 = stack_pointer[10];
      int32_t arg15 = stack_pointer[11];
      int32_t arg16 = stack_pointer[12];
      int32_t arg17 = stack_pointer[13];
      int32_t arg18 = stack_pointer[14];
      int32_t arg19 = stack_pointer[15];
      static_assert(kMaxCParameters == 20);

      bool fp_call =
          (redirection->type() == ExternalReference::BUILTIN_FP_FP_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_COMPARE_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_FP_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_FP_INT_CALL);
      // This is dodgy but it works because the C entry stubs are never moved.
      // See comment in codegen-arm.cc and bug 1242173.
      int32_t saved_lr = get_register(lr);
      intptr_t external =
          reinterpret_cast<intptr_t>(redirection->external_function());
      if (fp_call) {
        double dval0, dval1;  // one or two double parameters
        int32_t ival;         // zero or one integer parameters
        int64_t iresult = 0;  // integer return value
        double dresult = 0;   // double return value
        GetFpArgs(&dval0, &dval1, &ival);
        if (InstructionTracingEnabled() || !stack_aligned) {
          SimulatorRuntimeCall generic_target =
              reinterpret_cast<SimulatorRuntimeCall>(external);
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
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08x\n", get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        switch (redirection->type()) {
          case ExternalReference::BUILTIN_COMPARE_CALL: {
            SimulatorRuntimeCompareCall target =
                reinterpret_cast<SimulatorRuntimeCompareCall>(external);
            iresult = target(dval0, dval1);
#ifdef DEBUG
            TrashCallerSaveRegisters();
#endif
            set_register(r0, static_cast<int32_t>(iresult));
            set_register(r1, static_cast<int32_t>(iresult >> 32));
            break;
          }
          case ExternalReference::BUILTIN_FP_FP_CALL: {
            SimulatorRuntimeFPFPCall target =
                reinterpret_cast<SimulatorRuntimeFPFPCall>(external);
            dresult = target(dval0, dval1);
#ifdef DEBUG
            TrashCallerSaveRegisters();
#endif
            SetFpResult(dresult);
            break;
          }
          case ExternalReference::BUILTIN_FP_CALL: {
            SimulatorRuntimeFPCall target =
                reinterpret_cast<SimulatorRuntimeFPCall>(external);
            dresult = target(dval0);
#ifdef DEBUG
            TrashCallerSaveRegisters();
#endif
            SetFpResult(dresult);
            break;
          }
          case ExternalReference::BUILTIN_FP_INT_CALL: {
            SimulatorRuntimeFPIntCall target =
                reinterpret_cast<SimulatorRuntimeFPIntCall>(external);
            dresult = target(dval0, ival);
#ifdef DEBUG
            TrashCallerSaveRegisters();
#endif
            SetFpResult(dresult);
            break;
          }
          default:
            UNREACHABLE();
        }
        if (InstructionTracingEnabled()) {
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
        if (InstructionTracingEnabled() || !stack_aligned) {
          PrintF("Call to host function at %p args %08x",
                 reinterpret_cast<void*>(external), arg0);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08x\n", get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeFPTaggedCall target =
            reinterpret_cast<SimulatorRuntimeFPTaggedCall>(external);
        double dresult = target(arg0, arg1, arg2, arg3);
#ifdef DEBUG
        TrashCallerSaveRegisters();
#endif
        SetFpResult(dresult);
        if (InstructionTracingEnabled()) {
          PrintF("Returned %f\n", dresult);
        }
      } else if (redirection->type() == ExternalReference::DIRECT_API_CALL) {
        // void f(v8::FunctionCallbackInfo&)
        if (InstructionTracingEnabled() || !stack_aligned) {
          PrintF("Call to host function at %p args %08x",
                 reinterpret_cast<void*>(external), arg0);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08x\n", get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeDirectApiCall target =
            reinterpret_cast<SimulatorRuntimeDirectApiCall>(external);
        target(arg0);
#ifdef DEBUG
        TrashCallerSaveRegisters();
#endif
      } else if (redirection->type() == ExternalReference::DIRECT_GETTER_CALL) {
        // void f(v8::Local<String> property, v8::PropertyCallbackInfo& info)
        if (InstructionTracingEnabled() || !stack_aligned) {
          PrintF("Call to host function at %p args %08x %08x",
                 reinterpret_cast<void*>(external), arg0, arg1);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08x\n", get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeDirectGetterCall target =
            reinterpret_cast<SimulatorRuntimeDirectGetterCall>(external);
        target(arg0, arg1);
#ifdef DEBUG
        TrashCallerSaveRegisters();
#endif
      } else {
        // builtin call.
        // FAST_C_CALL is temporarily handled here as well, because we lack
        // proper support for direct C calls with FP params in the simulator.
        // The generic BUILTIN_CALL path assumes all parameters are passed in
        // the GP registers, thus supporting calling the slow callback without
        // crashing. The reason for that is that in the mjsunit tests we check
        // the `fast_c_api.supports_fp_params` (which is false on non-simulator
        // builds for arm/arm64), thus we expect that the slow path will be
        // called. And since the slow path passes the arguments as a `const
        // FunctionCallbackInfo<Value>&` (which is a GP argument), the call is
        // made correctly.
        DCHECK(redirection->type() == ExternalReference::BUILTIN_CALL ||
               redirection->type() == ExternalReference::BUILTIN_CALL_PAIR ||
               redirection->type() == ExternalReference::FAST_C_CALL);
        if (InstructionTracingEnabled() || !stack_aligned) {
          PrintF(
              "Call to host function at %p "
              "args %08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x, "
              "%08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x, "
              "%08x",
              reinterpret_cast<void*>(external), arg0, arg1, arg2, arg3, arg4,
              arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg1
```