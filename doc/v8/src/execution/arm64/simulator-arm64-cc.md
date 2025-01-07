Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a part of the V8 JavaScript engine, specifically the ARM64 simulator.

Here's a breakdown of the thinking process to arrive at the summary:

1. **Identify the core purpose:** The filename `simulator-arm64.cc` and the `#if defined(USE_SIMULATOR)` directive strongly suggest this code is responsible for simulating the execution of ARM64 instructions on a different architecture.

2. **Scan for key functionalities:**  Read through the code looking for important classes, methods, and data structures. Keywords like "Simulator", "registers", "stack", "breakpoints", "runtime call", "decoder", "disassembler" are significant.

3. **Group related functionalities:**  Organize the identified functionalities into logical categories. For example, handling registers (setting, getting, logging), managing the stack (allocation, pushing, popping), debugging features (breakpoints, tracing), and interaction with the V8 runtime.

4. **Elaborate on each category:** Describe the purpose and key mechanisms within each category. For instance, for register handling, mention both general-purpose and floating-point registers, and the possibility of logging their values. For runtime calls, note the mechanism for calling external C++ functions.

5. **Address specific instructions:** The prompt asks about `.tq` files and JavaScript interaction. Since the file doesn't end in `.tq`, conclude it's not Torque code. Recognize the interaction with JavaScript happens indirectly through the V8 runtime calls.

6. **Consider examples:** The request asks for JavaScript examples and code logic reasoning. Since the code is a low-level simulator, the connection to JavaScript is through the *effect* of the simulated instructions. Runtime calls are a prime example of this interaction. Think of a JavaScript function calling a native function – the simulator handles the execution within the native function. For code logic, focus on fundamental simulator operations like pushing to the stack or setting register values.

7. **Identify potential errors:** Look for aspects related to correct program execution, like stack alignment. This can lead to examples of common programming errors.

8. **Structure the summary:** Organize the findings logically, starting with the main purpose and then detailing the individual functionalities. Use clear and concise language.

9. **Refine and review:**  Read through the summary to ensure accuracy and completeness. Check if all parts of the initial request have been addressed. Ensure the language is accessible to someone with a general understanding of software development but perhaps not intimate knowledge of V8's internals.

**Self-Correction during the process:**

* Initially, I might focus too much on the low-level details of instruction decoding. Realize the request is for a functional overview, so prioritize higher-level functionalities.
* I might not immediately connect the runtime calls to the interaction with JavaScript. Remember that JavaScript often relies on native code for certain operations, and the simulator needs to handle these calls.
* The prompt mentions `.tq` files. Double-check the filename to avoid making an incorrect assumption.

By following these steps, including the refinement process, we can construct a comprehensive and accurate summary of the provided V8 simulator code.
这个C++源代码文件 `v8/src/execution/arm64/simulator-arm64.cc` 是V8 JavaScript 引擎中 **ARM64 架构的模拟器实现** 的一部分。 它的主要功能是：

1. **模拟 ARM64 指令的执行:**  它允许在非 ARM64 架构的机器上运行为 ARM64 架构编译的代码。这对于开发、测试和调试 V8 引擎在 ARM64 平台上的行为非常有用，而无需实际的 ARM64 硬件。

2. **提供寄存器和内存的抽象:** 它维护了 ARM64 架构中寄存器（通用寄存器、浮点寄存器、系统寄存器）和内存的软件表示，并提供了操作这些抽象的接口。

3. **支持执行代码片段:**  它可以加载并执行一段 ARM64 指令序列，并跟踪执行过程中的寄存器和内存状态。

4. **提供调试功能:**  它包含了用于调试模拟执行的功能，例如设置断点、单步执行、查看寄存器和内存的值等。

5. **模拟运行时调用:** 它允许模拟执行的代码调用 V8 引擎的运行时函数（用 C++ 实现）。这对于测试 JavaScript 代码的执行和与 V8 引擎的交互至关重要。

6. **处理系统调用和异常:** 它能够模拟某些系统调用和处理器异常的行为。

**关于 .tq 文件和 JavaScript 功能的关系：**

正如代码注释中提到的，如果 `v8/src/execution/arm64/simulator-arm64.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种 V8 内部使用的类型化的汇编语言，用于生成高效的机器码。  然而，这个文件以 `.cc` 结尾，所以它是 C++ 源代码，直接实现了模拟器的逻辑。

尽管 `simulator-arm64.cc` 本身不是 JavaScript 代码，但它与 JavaScript 的功能有着密切的关系。 它模拟了 JavaScript 代码编译后在 ARM64 架构上的执行过程。

**JavaScript 举例说明：**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 引擎执行这段代码时，它会：

1. **解析和编译:** 将 JavaScript 代码解析成抽象语法树 (AST)，然后将其编译成 ARM64 机器码（在实际 ARM64 硬件上）或模拟的 ARM64 机器码（在使用模拟器时）。

2. **在模拟器中执行:** 如果启用了 ARM64 模拟器，编译后的模拟 ARM64 机器码会被加载到模拟器中执行。 `simulator-arm64.cc` 中的代码负责解释和执行这些模拟的机器指令。例如，模拟器会处理加载 `a` 和 `b` 的值到寄存器，执行加法运算，并将结果存储回寄存器，最后返回结果。

3. **调用运行时函数:**  当执行 `console.log(result)` 时，模拟器会遇到一个需要调用 V8 运行时函数的指令。`simulator-arm64.cc` 中 `DoRuntimeCall` 函数负责处理这种调用，它会将参数传递给相应的 C++ 运行时函数，并模拟其执行。

**代码逻辑推理 (假设输入与输出)：**

假设我们模拟执行以下简单的 ARM64 指令：

```assembly
MOV X0, #5   // 将立即数 5 移动到寄存器 X0
MOV X1, #10  // 将立即数 10 移动到寄存器 X1
ADD X2, X0, X1 // 将 X0 和 X1 的值相加，结果存储到 X2
```

**假设输入：**

* 模拟器初始化完成，寄存器和内存处于初始状态 (例如，寄存器值可能为 0 或某个默认值)。
* 程序计数器 (PC) 指向 `MOV X0, #5` 指令的地址。

**执行过程和输出：**

1. **执行 `MOV X0, #5`:**
   - 模拟器解码该指令。
   - 模拟器将立即数 5 写入其内部表示的 X0 寄存器。
   - **模拟器内部状态变化：**  X0 寄存器的值变为 5。
   - PC 更新到下一条指令的地址。

2. **执行 `MOV X1, #10`:**
   - 模拟器解码该指令。
   - 模拟器将立即数 10 写入其内部表示的 X1 寄存器。
   - **模拟器内部状态变化：** X1 寄存器的值变为 10。
   - PC 更新到下一条指令的地址。

3. **执行 `ADD X2, X0, X1`:**
   - 模拟器解码该指令。
   - 模拟器读取其内部表示的 X0 (值为 5) 和 X1 (值为 10) 寄存器的值。
   - 模拟器执行加法运算 5 + 10 = 15。
   - 模拟器将结果 15 写入其内部表示的 X2 寄存器。
   - **模拟器内部状态变化：** X2 寄存器的值变为 15。
   - PC 更新到下一条指令的地址。

**假设输出 (模拟器内部状态)：**

* X0 寄存器的值为 5。
* X1 寄存器的值为 10。
* X2 寄存器的值为 15。
* PC 指向下一条指令的地址 (或者如果这是最后一条指令，则指向某个终止地址)。

**涉及用户常见的编程错误 (在模拟环境中发现)：**

模拟器可以帮助发现一些在真实硬件上可能难以捕捉的编程错误，例如：

1. **未初始化的变量使用:**  如果模拟的代码尝试读取一个未被明确赋值的寄存器或内存位置，模拟器可以检测到这种情况并发出警告或错误。

   **C++ 模拟示例 (假设模拟器有检测未初始化访问的机制):**

   ```c++
   // 模拟指令序列
   Instruction* pc = ...;
   uint64_t x0_value = simulator->GetRegister(0); // 假设 X0 未初始化
   // ... 某些操作使用了 x0_value ...
   ```

   模拟器可能会在这种情况下报告错误，指出 X0 的值是不确定的。

2. **栈溢出:** 模拟器可以维护一个模拟的栈，并检测是否发生了栈溢出。

   **C++ 模拟示例:**

   ```c++
   simulator->SetStackPointer(initial_stack_pointer);
   for (int i = 0; i < large_number; ++i) {
       simulator->PushToStack(i); // 模拟多次压栈操作
   }
   if (simulator->GetStackPointer() < simulator->GetStackLimit()) {
       // 模拟器检测到栈溢出
       std::cerr << "Stack overflow detected!" << std::endl;
   }
   ```

3. **内存访问越界:** 模拟器可以检查代码是否尝试访问超出分配内存范围的地址。

   **C++ 模拟示例:**

   ```c++
   uintptr_t allocated_memory = simulator->AllocateMemory(100); // 分配 100 字节
   uintptr_t access_address = allocated_memory + 200; // 越界访问
   // 模拟尝试读取或写入 access_address
   if (!simulator->ProbeMemory(access_address, access_size)) {
       std::cerr << "Memory access violation!" << std::endl;
   }
   ```

4. **不正确的指令使用:** 模拟器可以验证指令的操作数和格式是否正确。

   **C++ 模拟示例:**

   ```c++
   Instruction invalid_instruction = ...; // 构造一个无效的指令
   if (!simulator->DecodeAndExecute(&invalid_instruction)) {
       std::cerr << "Invalid instruction encountered!" << std::endl;
   }
   ```

**归纳其功能 (第 1 部分)：**

总而言之，`v8/src/execution/arm64/simulator-arm64.cc` 的主要功能是 **为 V8 引擎提供一个软件实现的 ARM64 指令执行环境，用于在非 ARM64 平台上模拟执行 ARM64 代码，并提供调试和分析能力。** 它是 V8 引擎跨平台开发和测试的关键组件。

Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/arm64/simulator-arm64.h"

#include "src/execution/isolate.h"

#if defined(USE_SIMULATOR)

#include <stdlib.h>

#include <cmath>
#include <cstdarg>
#include <type_traits>

#include "src/base/overflowing-math.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/wrappers.h"
#include "src/base/sanitizer/msan.h"
#include "src/codegen/arm64/decoder-arm64-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disasm.h"
#include "src/heap/combined-heap.h"
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/utils/ostreams.h"

#if V8_OS_WIN
#include <windows.h>
#endif

#if V8_ENABLE_WEBASSEMBLY
#include "src/trap-handler/trap-handler-simulator.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent way through
// ::v8::internal::OS in the same way as SNPrintF is that the
// Windows C Run-Time Library does not provide vsscanf.
#define SScanF sscanf

// Helpers for colors.
#define COLOUR(colour_code) "\033[0;" colour_code "m"
#define COLOUR_BOLD(colour_code) "\033[1;" colour_code "m"
#define NORMAL ""
#define GREY "30"
#define RED "31"
#define GREEN "32"
#define YELLOW "33"
#define BLUE "34"
#define MAGENTA "35"
#define CYAN "36"
#define WHITE "37"

using TEXT_COLOUR = char const* const;
TEXT_COLOUR clr_normal = v8_flags.log_colour ? COLOUR(NORMAL) : "";
TEXT_COLOUR clr_flag_name = v8_flags.log_colour ? COLOUR_BOLD(WHITE) : "";
TEXT_COLOUR clr_flag_value = v8_flags.log_colour ? COLOUR(NORMAL) : "";
TEXT_COLOUR clr_reg_name = v8_flags.log_colour ? COLOUR_BOLD(CYAN) : "";
TEXT_COLOUR clr_reg_value = v8_flags.log_colour ? COLOUR(CYAN) : "";
TEXT_COLOUR clr_vreg_name = v8_flags.log_colour ? COLOUR_BOLD(MAGENTA) : "";
TEXT_COLOUR clr_vreg_value = v8_flags.log_colour ? COLOUR(MAGENTA) : "";
TEXT_COLOUR clr_memory_address = v8_flags.log_colour ? COLOUR_BOLD(BLUE) : "";
TEXT_COLOUR clr_debug_number = v8_flags.log_colour ? COLOUR_BOLD(YELLOW) : "";
TEXT_COLOUR clr_debug_message = v8_flags.log_colour ? COLOUR(YELLOW) : "";
TEXT_COLOUR clr_printf = v8_flags.log_colour ? COLOUR(GREEN) : "";

DEFINE_LAZY_LEAKY_OBJECT_GETTER(Simulator::GlobalMonitor,
                                Simulator::GlobalMonitor::Get)

bool Simulator::ProbeMemory(uintptr_t address, uintptr_t access_size) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  uintptr_t last_accessed_byte = address + access_size - 1;
  uintptr_t current_pc = reinterpret_cast<uintptr_t>(pc_);
  uintptr_t landing_pad =
      trap_handler::ProbeMemory(last_accessed_byte, current_pc);
  if (!landing_pad) return true;
  set_pc(landing_pad);
  set_reg(kWasmTrapHandlerFaultAddressRegister.code(), current_pc);
  return false;
#else
  return true;
#endif
}

// This is basically the same as PrintF, with a guard for v8_flags.trace_sim.
void Simulator::TraceSim(const char* format, ...) {
  if (v8_flags.trace_sim) {
    va_list arguments;
    va_start(arguments, format);
    base::OS::VFPrint(stream_, format, arguments);
    va_end(arguments);
  }
}

const Instruction* Simulator::kEndOfSimAddress = nullptr;

void SimSystemRegister::SetBits(int msb, int lsb, uint32_t bits) {
  int width = msb - lsb + 1;
  DCHECK(is_uintn(bits, width) || is_intn(bits, width));

  bits <<= lsb;
  uint32_t mask = ((1 << width) - 1) << lsb;
  DCHECK_EQ(mask & write_ignore_mask_, 0);

  value_ = (value_ & ~mask) | (bits & mask);
}

SimSystemRegister SimSystemRegister::DefaultValueFor(SystemRegister id) {
  switch (id) {
    case NZCV:
      return SimSystemRegister(0x00000000, NZCVWriteIgnoreMask);
    case FPCR:
      return SimSystemRegister(0x00000000, FPCRWriteIgnoreMask);
    default:
      UNREACHABLE();
  }
}

// Get the active Simulator for the current thread.
Simulator* Simulator::current(Isolate* isolate) {
  Isolate::PerIsolateThreadData* isolate_data =
      isolate->FindOrAllocatePerThreadDataForThisThread();
  DCHECK_NOT_NULL(isolate_data);

  Simulator* sim = isolate_data->simulator();
  if (sim == nullptr) {
    if (v8_flags.trace_sim || v8_flags.debug_sim) {
      sim = new Simulator(new Decoder<DispatchingDecoderVisitor>(), isolate);
    } else {
      sim = new Decoder<Simulator>();
      sim->isolate_ = isolate;
    }
    isolate_data->set_simulator(sim);
  }
  return sim;
}

void Simulator::CallImpl(Address entry, CallArgument* args) {
  int index_x = 0;
  int index_d = 0;

  std::vector<int64_t> stack_args(0);
  for (int i = 0; !args[i].IsEnd(); i++) {
    CallArgument arg = args[i];
    if (arg.IsX() && (index_x < 8)) {
      set_xreg(index_x++, arg.bits());
    } else if (arg.IsD() && (index_d < 8)) {
      set_dreg_bits(index_d++, arg.bits());
    } else {
      DCHECK(arg.IsD() || arg.IsX());
      stack_args.push_back(arg.bits());
    }
  }

  // Process stack arguments, and make sure the stack is suitably aligned.
  uintptr_t original_stack = sp();
  uintptr_t entry_stack =
      original_stack - stack_args.size() * sizeof(stack_args[0]);
  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }
  char* stack = reinterpret_cast<char*>(entry_stack);
  std::vector<int64_t>::const_iterator it;
  for (it = stack_args.begin(); it != stack_args.end(); it++) {
    memcpy(stack, &(*it), sizeof(*it));
    stack += sizeof(*it);
  }

  DCHECK(reinterpret_cast<uintptr_t>(stack) <= original_stack);
  set_sp(entry_stack);

  // Call the generated code.
  set_pc(entry);
  set_lr(kEndOfSimAddress);
  CheckPCSComplianceAndRun();

  set_sp(original_stack);
}

#ifdef DEBUG
namespace {
int PopLowestIndexAsCode(CPURegList* list) {
  if (list->IsEmpty()) {
    return -1;
  }
  uint64_t reg_list = list->bits();
  int index = base::bits::CountTrailingZeros(reg_list);
  DCHECK((1LL << index) & reg_list);
  list->Remove(index);

  return index;
}
}  // namespace
#endif

void Simulator::CheckPCSComplianceAndRun() {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

#ifdef DEBUG
  DCHECK_EQ(kNumberOfCalleeSavedRegisters, kCalleeSaved.Count());
  DCHECK_EQ(kNumberOfCalleeSavedVRegisters, kCalleeSavedV.Count());

  int64_t saved_registers[kNumberOfCalleeSavedRegisters];
  uint64_t saved_fpregisters[kNumberOfCalleeSavedVRegisters];

  CPURegList register_list = kCalleeSaved;
  CPURegList fpregister_list = kCalleeSavedV;

  for (int i = 0; i < kNumberOfCalleeSavedRegisters; i++) {
    // x31 is not a caller saved register, so no need to specify if we want
    // the stack or zero.
    saved_registers[i] = xreg(PopLowestIndexAsCode(&register_list));
  }
  for (int i = 0; i < kNumberOfCalleeSavedVRegisters; i++) {
    saved_fpregisters[i] = dreg_bits(PopLowestIndexAsCode(&fpregister_list));
  }
  int64_t original_stack = sp();
  int64_t original_fp = fp();
#endif
  // Start the simulation!
  Run();
#ifdef DEBUG
  DCHECK_EQ(original_stack, sp());
  DCHECK_EQ(original_fp, fp());
  // Check that callee-saved registers have been preserved.
  register_list = kCalleeSaved;
  fpregister_list = kCalleeSavedV;
  for (int i = 0; i < kNumberOfCalleeSavedRegisters; i++) {
    DCHECK_EQ(saved_registers[i], xreg(PopLowestIndexAsCode(&register_list)));
  }
  for (int i = 0; i < kNumberOfCalleeSavedVRegisters; i++) {
    DCHECK(saved_fpregisters[i] ==
           dreg_bits(PopLowestIndexAsCode(&fpregister_list)));
  }

  // Corrupt caller saved register minus the return regiters.

  // In theory x0 to x7 can be used for return values, but V8 only uses x0, x1
  // for now .
  register_list = kCallerSaved;
  register_list.Remove(x0);
  register_list.Remove(x1);

  // In theory d0 to d7 can be used for return values, but V8 only uses d0
  // for now .
  fpregister_list = kCallerSavedV;
  fpregister_list.Remove(d0);

  CorruptRegisters(&register_list, kCallerSavedRegisterCorruptionValue);
  CorruptRegisters(&fpregister_list, kCallerSavedVRegisterCorruptionValue);
#endif
}

#ifdef DEBUG
// The least significant byte of the curruption value holds the corresponding
// register's code.
void Simulator::CorruptRegisters(CPURegList* list, uint64_t value) {
  if (list->type() == CPURegister::kRegister) {
    while (!list->IsEmpty()) {
      unsigned code = PopLowestIndexAsCode(list);
      set_xreg(code, value | code);
    }
  } else {
    DCHECK_EQ(list->type(), CPURegister::kVRegister);
    while (!list->IsEmpty()) {
      unsigned code = PopLowestIndexAsCode(list);
      set_dreg_bits(code, value | code);
    }
  }
}

void Simulator::CorruptAllCallerSavedCPURegisters() {
  // Corrupt alters its parameter so copy them first.
  CPURegList register_list = kCallerSaved;
  CPURegList fpregister_list = kCallerSavedV;

  CorruptRegisters(&register_list, kCallerSavedRegisterCorruptionValue);
  CorruptRegisters(&fpregister_list, kCallerSavedVRegisterCorruptionValue);
}
#endif

// Extending the stack by 2 * 64 bits is required for stack alignment purposes.
uintptr_t Simulator::PushAddress(uintptr_t address) {
  DCHECK(sizeof(uintptr_t) < 2 * kXRegSize);
  intptr_t new_sp = sp() - 2 * kXRegSize;
  uintptr_t* alignment_slot = reinterpret_cast<uintptr_t*>(new_sp + kXRegSize);
  memcpy(alignment_slot, &kSlotsZapValue, kSystemPointerSize);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(new_sp);
  memcpy(stack_slot, &address, kSystemPointerSize);
  set_sp(new_sp);
  return new_sp;
}

uintptr_t Simulator::PopAddress() {
  intptr_t current_sp = sp();
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(current_sp);
  uintptr_t address = *stack_slot;
  DCHECK_LT(sizeof(uintptr_t), 2 * kXRegSize);
  set_sp(current_sp + 2 * kXRegSize);
  return address;
}

// Returns the limit of the stack area to enable checking for stack overflows.
uintptr_t Simulator::StackLimit(uintptr_t c_limit) const {
  // The simulator uses a separate JS stack. If we have exhausted the C stack,
  // we also drop down the JS limit to reflect the exhaustion on the JS stack.
  if (base::Stack::GetCurrentStackPosition() < c_limit) {
    return get_sp();
  }

  // Otherwise the limit is the JS stack. Leave a safety margin to prevent
  // overrunning the stack when pushing values.
  return stack_limit_ + kAdditionalStackMargin;
}

base::Vector<uint8_t> Simulator::GetCentralStackView() const {
  // We do not add an additional safety margin as above in
  // Simulator::StackLimit, as users of this method are expected to add their
  // own margin.
  return base::VectorOf(
      reinterpret_cast<uint8_t*>(stack_ + kStackProtectionSize),
      UsableStackSize());
}

void Simulator::SetRedirectInstruction(Instruction* instruction) {
  instruction->SetInstructionBits(
      HLT | Assembler::ImmException(kImmExceptionIsRedirectedCall));
}

Simulator::Simulator(Decoder<DispatchingDecoderVisitor>* decoder,
                     Isolate* isolate, FILE* stream)
    : decoder_(decoder),
      guard_pages_(ENABLE_CONTROL_FLOW_INTEGRITY_BOOL),
      last_debugger_input_(nullptr),
      log_parameters_(NO_PARAM),
      icount_for_stop_sim_at_(0),
      isolate_(isolate) {
  // Setup the decoder.
  decoder_->AppendVisitor(this);

  Init(stream);

  if (v8_flags.trace_sim) {
    decoder_->InsertVisitorBefore(print_disasm_, this);
    log_parameters_ = LOG_ALL;
  }
}

Simulator::Simulator()
    : decoder_(nullptr),
      guard_pages_(ENABLE_CONTROL_FLOW_INTEGRITY_BOOL),
      last_debugger_input_(nullptr),
      log_parameters_(NO_PARAM),
      isolate_(nullptr) {
  Init(stdout);
  CHECK(!v8_flags.trace_sim);
}

void Simulator::Init(FILE* stream) {
  ResetState();

  // Allocate and setup the simulator stack.
  size_t stack_size = AllocatedStackSize();

  stack_ = reinterpret_cast<uintptr_t>(new uint8_t[stack_size]());
  stack_limit_ = stack_ + kStackProtectionSize;
  uintptr_t tos = stack_ + stack_size - kStackProtectionSize;
  // The stack pointer must be 16-byte aligned.
  set_sp(tos & ~0xFULL);

  stream_ = stream;
  print_disasm_ = new PrintDisassembler(stream_);

  // The debugger needs to disassemble code without the simulator executing an
  // instruction, so we create a dedicated decoder.
  disassembler_decoder_ = new Decoder<DispatchingDecoderVisitor>();
  disassembler_decoder_->AppendVisitor(print_disasm_);
}

void Simulator::ResetState() {
  // Reset the system registers.
  nzcv_ = SimSystemRegister::DefaultValueFor(NZCV);
  fpcr_ = SimSystemRegister::DefaultValueFor(FPCR);

  // Reset registers to 0.
  pc_ = nullptr;
  for (unsigned i = 0; i < kNumberOfRegisters; i++) {
    set_xreg(i, 0xBADBEEF);
  }
  for (unsigned i = 0; i < kNumberOfVRegisters; i++) {
    // Set FP registers to a value that is NaN in both 32-bit and 64-bit FP.
    set_dreg_bits(i, 0x7FF000007F800001UL);
  }
  // Returning to address 0 exits the Simulator.
  set_lr(kEndOfSimAddress);

  // Reset debug helpers.
  breakpoints_.clear();
  break_on_next_ = false;

  btype_ = DefaultBType;
}

Simulator::~Simulator() {
  GlobalMonitor::Get()->RemoveProcessor(&global_monitor_processor_);
  delete[] reinterpret_cast<uint8_t*>(stack_);
  delete disassembler_decoder_;
  delete print_disasm_;
  delete decoder_;
}

void Simulator::Run() {
  // Flush any written registers before executing anything, so that
  // manually-set registers are logged _before_ the first instruction.
  LogAllWrittenRegisters();

  pc_modified_ = false;

  if (v8_flags.stop_sim_at == 0) {
    // Fast version of the dispatch loop without checking whether the simulator
    // should be stopping at a particular executed instruction.
    while (pc_ != kEndOfSimAddress) {
      ExecuteInstruction();
    }
  } else {
    // v8_flags.stop_sim_at is at the non-default value. Stop in the debugger
    // when we reach the particular instruction count.
    while (pc_ != kEndOfSimAddress) {
      icount_for_stop_sim_at_ =
          base::AddWithWraparound(icount_for_stop_sim_at_, 1);
      if (icount_for_stop_sim_at_ == v8_flags.stop_sim_at) {
        Debug();
      }
      ExecuteInstruction();
    }
  }
}

void Simulator::RunFrom(Instruction* start) {
  set_pc(start);
  Run();
}

// Calls into the V8 runtime are based on this very simple interface.
// Note: To be able to return two values from some calls the code in runtime.cc
// uses the ObjectPair structure.
// The simulator assumes all runtime calls return two 64-bits values. If they
// don't, register x1 is clobbered. This is fine because x1 is caller-saved.
#if defined(V8_OS_WIN)
using SimulatorRuntimeCall_ReturnPtr = int64_t (*)(
    int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4,
    int64_t arg5, int64_t arg6, int64_t arg7, int64_t arg8, int64_t arg9,
    int64_t arg10, int64_t arg11, int64_t arg12, int64_t arg13, int64_t arg14,
    int64_t arg15, int64_t arg16, int64_t arg17, int64_t arg18, int64_t arg19);
#endif

using SimulatorRuntimeCall = ObjectPair (*)(
    int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4,
    int64_t arg5, int64_t arg6, int64_t arg7, int64_t arg8, int64_t arg9,
    int64_t arg10, int64_t arg11, int64_t arg12, int64_t arg13, int64_t arg14,
    int64_t arg15, int64_t arg16, int64_t arg17, int64_t arg18, int64_t arg19);

using SimulatorRuntimeCompareCall = int64_t (*)(double arg1, double arg2);
using SimulatorRuntimeFPFPCall = double (*)(double arg1, double arg2);
using SimulatorRuntimeFPCall = double (*)(double arg1);
using SimulatorRuntimeFPIntCall = double (*)(double arg1, int32_t arg2);
// Define four args for future flexibility; at the time of this writing only
// one is ever used.
using SimulatorRuntimeFPTaggedCall = double (*)(int64_t arg0, int64_t arg1,
                                                int64_t arg2, int64_t arg3);

// This signature supports direct call in to API function native callback
// (refer to InvocationCallback in v8.h).
using SimulatorRuntimeDirectApiCall = void (*)(int64_t arg0);

// This signature supports direct call to accessor getter callback.
using SimulatorRuntimeDirectGetterCall = void (*)(int64_t arg0, int64_t arg1);

// Separate for fine-grained UBSan blocklisting. Casting any given C++
// function to {SimulatorRuntimeCall} is undefined behavior; but since
// the target function can indeed be any function that's exposed via
// the "fast C call" mechanism, we can't reconstruct its signature here.
ObjectPair UnsafeGenericFunctionCall(
    int64_t function, int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3,
    int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg7, int64_t arg8,
    int64_t arg9, int64_t arg10, int64_t arg11, int64_t arg12, int64_t arg13,
    int64_t arg14, int64_t arg15, int64_t arg16, int64_t arg17, int64_t arg18,
    int64_t arg19) {
  SimulatorRuntimeCall target =
      reinterpret_cast<SimulatorRuntimeCall>(function);
  return target(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9,
                arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, arg18,
                arg19);
}

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

void Simulator::CallAnyCTypeFunction(Address target_address,
                                     const EncodedCSignature& signature) {
  TraceSim("Type: mixed types BUILTIN_CALL\n");

  const int64_t* stack_pointer = reinterpret_cast<int64_t*>(sp());
  const double* double_stack_pointer = reinterpret_cast<double*>(sp());
  int num_gp_params = 0, num_fp_params = 0, num_stack_params = 0;

  CHECK_LE(signature.ParameterCount(), kMaxCParameters);
  static_assert(sizeof(AnyCType) == 8, "AnyCType is assumed to be 64-bit.");
  AnyCType args[kMaxCParameters];
  // The first 8 parameters of each type (GP or FP) are placed in corresponding
  // registers. The rest are expected to be on the stack, where each parameter
  // type counts on its own. For example a function like:
  // foo(int i1, ..., int i9, float f1, float f2) will use up all 8 GP
  // registers, place i9 on the stack, and place f1 and f2 in FP registers.
  // Source: https://developer.arm.com/documentation/ihi0055/d/, section
  // "Parameter Passing".
  for (int i = 0; i < signature.ParameterCount(); ++i) {
    if (signature.IsFloat(i)) {
      if (num_fp_params < 8) {
        args[i].double_value = dreg(num_fp_params++);
      } else {
        args[i].double_value = double_stack_pointer[num_stack_params++];
      }
    } else {
      if (num_gp_params < 8) {
        args[i].int64_value = xreg(num_gp_params++);
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

#ifdef DEBUG
  CorruptAllCallerSavedCPURegisters();
#endif

  if (signature.IsReturnFloat()) {
    set_dreg(0, result.double_value);
  } else {
    set_xreg(0, result.int64_value);
  }
}

void Simulator::DoRuntimeCall(Instruction* instr) {
  Redirection* redirection = Redirection::FromInstruction(instr);

  // The called C code might itself call simulated code, so any
  // caller-saved registers (including lr) could still be clobbered by a
  // redirected call.
  Instruction* return_address = lr();

  int64_t external =
      reinterpret_cast<int64_t>(redirection->external_function());

  TraceSim("Call to host function at %p\n", redirection->external_function());

  // SP must be 16-byte-aligned at the call interface.
  bool stack_alignment_exception = ((sp() & 0xF) != 0);
  if (stack_alignment_exception) {
    TraceSim("  with unaligned stack 0x%016" PRIx64 ".\n", sp());
    FATAL("ALIGNMENT EXCEPTION");
  }

  Address func_addr =
      reinterpret_cast<Address>(redirection->external_function());
  SimulatorData* simulator_data = isolate_->simulator_data();
  DCHECK_NOT_NULL(simulator_data);
  const EncodedCSignature& signature =
      simulator_data->GetSignatureForTarget(func_addr);
  if (signature.IsValid()) {
    CHECK(redirection->type() == ExternalReference::FAST_C_CALL);
    CallAnyCTypeFunction(external, signature);
    set_lr(return_address);
    set_pc(return_address);
    return;
  }

  int64_t* stack_pointer = reinterpret_cast<int64_t*>(sp());

  const int64_t arg0 = xreg(0);
  const int64_t arg1 = xreg(1);
  const int64_t arg2 = xreg(2);
  const int64_t arg3 = xreg(3);
  const int64_t arg4 = xreg(4);
  const int64_t arg5 = xreg(5);
  const int64_t arg6 = xreg(6);
  const int64_t arg7 = xreg(7);
  const int64_t arg8 = stack_pointer[0];
  const int64_t arg9 = stack_pointer[1];
  const int64_t arg10 = stack_pointer[2];
  const int64_t arg11 = stack_pointer[3];
  const int64_t arg12 = stack_pointer[4];
  const int64_t arg13 = stack_pointer[5];
  const int64_t arg14 = stack_pointer[6];
  const int64_t arg15 = stack_pointer[7];
  const int64_t arg16 = stack_pointer[8];
  const int64_t arg17 = stack_pointer[9];
  const int64_t arg18 = stack_pointer[10];
  const int64_t arg19 = stack_pointer[11];
  static_assert(kMaxCParameters == 20);

#ifdef V8_USE_MEMORY_SANITIZER
  // `UnsafeGenericFunctionCall()` dispatches calls to functions with
  // varying signatures and relies on the fact that the mismatched prototype
  // used by the caller and the prototype used by the callee (defined using
  // the `RUNTIME_FUNCTION*()` macros happen to line up so that things more
  // or less work out [1].
  //
  // Unfortunately, this confuses MSan's uninit tracking with eager checks
  // enabled; it's unclear if these are all false positives or if there are
  // legitimate reports. For now, unconditionally unpoison args to
  // unblock finding and fixing more violations with MSan eager checks.
  //
  // TODO(crbug.com/v8/14712): Fix the MSan violations and migrate to
  // something like crrev.com/c/5422076 instead.
  //
  // [1] Yes, this is undefined behaviour. 🙈🙉🙊
  MSAN_MEMORY_IS_INITIALIZED(&arg0, sizeof(arg0));
  MSAN_MEMORY_IS_INITIALIZED(&arg1, sizeof(arg1));
  MSAN_MEMORY_IS_INITIALIZED(&arg2, sizeof(arg2));
  MSAN_MEMORY_IS_INITIALIZED(&arg3, sizeof(arg3));
  MSAN_MEMORY_IS_INITIALIZED(&arg4, sizeof(arg4));
  MSAN_MEMORY_IS_INITIALIZED(&arg5, sizeof(arg5));
  MSAN_MEMORY_IS_INITIALIZED(&arg6, sizeof(arg6));
  MSAN_MEMORY_IS_INITIALIZED(&arg7, sizeof(arg7));
  MSAN_MEMORY_IS_INITIALIZED(&arg8, sizeof(arg8));
  MSAN_MEMORY_IS_INITIALIZED(&arg9, sizeof(arg9));
  MSAN_MEMORY_IS_INITIALIZED(&arg10, sizeof(arg10));
  MSAN_MEMORY_IS_INITIALIZED(&arg11, sizeof(arg11));
  MSAN_MEMORY_IS_INITIALIZED(&arg12, sizeof(arg12));
  MSAN_MEMORY_IS_INITIALIZED(&arg13, sizeof(arg13));
  MSAN_MEMORY_IS_INITIALIZED(&arg14, sizeof(arg14));
  MSAN_MEMORY_IS_INITIALIZED(&arg15, sizeof(arg15));
  MSAN_MEMORY_IS_INITIALIZED(&arg16, sizeof(arg16));
  MSAN_MEMORY_IS_INITIALIZED(&arg17, sizeof(arg17));
  MSAN_MEMORY_IS_INITIALIZED(&arg18, sizeof(arg18));
  MSAN_MEMORY_IS_INITIALIZED(&arg19, sizeof(arg19));
#endif  // V8_USE_MEMORY_SANITIZER

  switch (redirection->type()) {
    default:
      TraceSim("Type: Unknown.\n");
      UNREACHABLE();

    case ExternalReference::BUILTIN_CALL:
#if defined(V8_OS_WIN)
    {
      // Object f(v8::internal::Arguments).
      TraceSim("Type: BUILTIN_CALL\n");

      // When this simulator runs on Windows x64 host, function with ObjectPair
      // return type accepts an implicit pointer to caller allocated memory for
      // ObjectPair as return value. This diverges the calling convention from
      // function which returns primitive type, so function returns ObjectPair
      // and primitive type cannot share implementation.

      // We don't know how many arguments are being passed, but we can
      // pass 8 without touching the stack. They will be ignored by the
      // host function if they aren't used.
      TraceSim(
          "Arguments: "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64,
          arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10,
          arg11, arg12, arg13, arg14, arg15, arg16, arg17, arg18, arg19);

      SimulatorRuntimeCall_ReturnPtr target =
          reinterpret_cast<SimulatorRuntimeCall_ReturnPtr>(external);

      int64_t result = target(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                              arg8, arg9, arg10, arg11, arg12, arg13, arg14,
                              arg15, arg16, arg17, arg18, arg19);
      TraceSim("Returned: 0x%16\n", result);
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_xreg(0, result);

      break;
    }
#endif
    case ExternalReference::BUILTIN_CALL_PAIR: {
      // Object f(v8::internal::Arguments) or
      // ObjectPair f(v8::internal::Arguments).
      TraceSim("Type: BUILTIN_CALL\n");

      // We don't know how many arguments are being passed, but we can
      // pass 8 without touching the stack. They will be ignored by the
      // host function if they aren't used.
      TraceSim(
          "Arguments: "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64
          ", "
          "0x%016" PRIx64 ", 0x%016" PRIx64,
          arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10,
          arg11, arg12, arg13, arg14, arg15, arg16, arg17, arg18, arg19);

      ObjectPair result = UnsafeGenericFunctionCall(
          external, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9,
          arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, arg18, arg19);
#ifdef V8_USE_MEMORY_SANITIZER
      // `UnsafeGenericFunctionCall()` dispatches calls to functions with
      // varying signatures and relies on the fact that the mismatched prototype
      // used by the caller and the prototype used by the callee (defined using
      // the `RUNTIME_FUNCTION*()` macros happen to line up so that things more
      // or less work out [1].
      //
      // Unfortunately, this confuses MSan's uninit tracking with eager checks
      // enabled; it's unclear if these are all false positives or if there are
      // legitimate reports. For now, unconditionally unpoison `result` to
      // unblock finding and fixing more violations with MSan eager checks.
      //
      // TODO(crbug.com/v8/14712): Fix the MSan violations and migrate to
      // something like crrev.com/c/5422076 instead.
      //
      // [1] Yes, this is undefined behaviour. 🙈🙉🙊
      MSAN_MEMORY_IS_INITIALIZED(&result, sizeof(result));
#endif
      TraceSim("Returned: {%p, %p}\n", reinterpret_cast<void*>(result.x),
               reinterpret_cast<void*>(result.y));
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_xreg(0, static_cast<int64_t>(result.x));
      set_xreg(1, static_cast<int64_t>(result.y));
      break;
    }

    case ExternalReference::BUILTIN_COMPARE_CALL: {
      // int f(double, double)
      TraceSim("Type: BUILTIN_COMPARE_CALL\n");
      SimulatorRuntimeCompareCall target =
          reinterpret_cast<SimulatorRuntimeCompareCall>(external);
      TraceSim("Arguments: %f, %f\n", dreg(0), dreg(1));
      int64_t result = target(dreg(0), dreg(1));
      TraceSim("Returned: %" PRId64 "\n", result);
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_xreg(0, result);
      break;
    }

    case ExternalReference::BUILTIN_FP_CALL: {
      // double f(double)
      TraceSim("Type: BUILTIN_FP_CALL\n");
      SimulatorRuntimeFPCall target =
          reinterpret_cast<SimulatorRuntimeFPCall>(external);
      TraceSim("Argument: %f\n", dreg(0));
      double result = target(dreg(0));
      TraceSim("Returned: %f\n", result);
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_dreg(0, result);
      break;
    }

    case ExternalReference::BUILTIN_FP_FP_CALL: {
      // double f(double, double)
      TraceSim("Type: BUILTIN_FP_FP_CALL\n");
      SimulatorRuntimeFPFPCall target =
          reinterpret_cast<SimulatorRuntimeFPFPCall>(external);
      TraceSim("Arguments: %f, %f\n", dreg(0), dreg(1));
      double result = target(dreg(0), dreg(1));
      TraceSim("Returned: %f\n", result);
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_dreg(0, result);
      break;
    }

    case ExternalReference::BUILTIN_FP_INT_CALL: {
      // double f(double, int)
      TraceSim("Type: BUILTIN_FP_INT_CALL\n");
      SimulatorRuntimeFPIntCall target =
          reinterpret_cast<SimulatorRuntimeFPIntCall>(external);
      TraceSim("Arguments: %f, %d\n", dreg(0), wreg(0));
      double result = target(dreg(0), wreg(0));
      TraceSim("Returned: %f\n", result);
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_dreg(0, result);
      break;
    }

    case ExternalReference::BUILTIN_FP_POINTER_CALL: {
      // double f(Address tagged_ptr)
      TraceSim("Type: BUILTIN_FP_POINTER_CALL\n");
      SimulatorRuntimeFPTaggedCall target =
          reinterpret_cast<SimulatorRuntimeFPTaggedCall>(external);
      TraceSim(
          "Arguments: "
          "0x%016" PRIx64
"""


```