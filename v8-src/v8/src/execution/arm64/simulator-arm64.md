Response: The user wants a summary of the functionality of the provided C++ code, which is the first part of a larger file. I need to understand what this part of the code is responsible for. Keywords like `Simulator`, `arm64`, `execution`, and the various includes suggest this code is part of a CPU simulator for the ARM64 architecture, likely used within the V8 JavaScript engine.

Specifically, I should focus on:
- The overall purpose of the `Simulator` class.
- How it interacts with memory and registers.
- Any functionalities related to executing code, breakpoints, or debugging.
- The interaction with JavaScript, if any, mentioned in this part.

After summarizing the functionality, I need to provide a JavaScript example illustrating the connection, if one exists in this part of the code. Given the focus on low-level simulation, the connection to JavaScript might be indirect, perhaps through the execution of generated machine code.
This C++ code defines the initial part of a `Simulator` class for the ARM64 architecture within the V8 JavaScript engine. Its primary function is to emulate the execution of ARM64 instructions.

Here's a breakdown of its key features and functionalities within this section:

**Core Simulation Infrastructure:**

* **Simulator Class:** Defines the `Simulator` class, which is responsible for managing the simulated CPU state, including registers, program counter (PC), stack pointer (SP), and system registers (like NZCV and FPCR).
* **Memory Management:**  Includes mechanisms for probing memory (`ProbeMemory`) and managing a simulated stack.
* **Instruction Fetch and Execution:**  Sets up the foundation for fetching and executing instructions. While the actual execution logic is in subsequent parts, this section includes helper functions like `Run` and `RunFrom` to start the simulation.
* **Register Management:** Provides methods to get and set the values of general-purpose registers (X and W registers) and floating-point/SIMD registers (V, D, and S registers).
* **System Register Emulation:** Emulates the behavior of key system registers like NZCV (flags) and FPCR (floating-point control).
* **Tracing and Logging:**  Includes functionality for tracing the simulation (`TraceSim`) and logging register values.
* **Breakpoints:** Implements basic breakpoint functionality (`SetBreakpoint`, `ListBreakpoints`, `CheckBreakpoints`) to pause the simulation for debugging.

**Interaction with the V8 Engine:**

* **Isolate Awareness:** The simulator is associated with a V8 `Isolate`, which represents an isolated instance of the JavaScript engine.
* **Runtime Calls:** Handles calls from the simulated code into the V8 runtime environment (`DoRuntimeCall`). This involves setting up arguments in registers and on the stack according to the ARM64 calling convention. It supports various types of runtime calls, including regular built-in calls, comparison calls, floating-point calls, and direct API calls.
* **Stack Management:**  Integrates with V8's stack management, including adjusting the stack limit for the simulator.

**Debugging and Introspection:**

* **Disassembly:** Uses a `Decoder` class to disassemble instructions for debugging purposes.
* **Register Printing:**  Provides functions to print the values of registers in various formats.

**Key Data Structures:**

* **Registers:**  Arrays to store the values of general-purpose and floating-point/SIMD registers.
* **System Registers:**  Objects to represent system registers and their associated write-ignore masks.
* **Stack:** A dynamically allocated memory region to simulate the stack.
* **Breakpoints:** A list to store active breakpoints.

**Relationship to JavaScript (Illustrative Example):**

While this C++ code doesn't directly manipulate JavaScript objects or execute JavaScript code, it provides the environment for *emulating the machine code* that the V8 engine generates when compiling JavaScript.

For instance, when V8 compiles a JavaScript function, it might generate ARM64 instructions that perform an arithmetic operation and then call a built-in runtime function for a more complex task. This `Simulator` would then execute those generated ARM64 instructions.

Here's a conceptual JavaScript example:

```javascript
function add(a, b) {
  return a + b;
}

// When V8 compiles this function, it might generate ARM64 instructions like:
// (Conceptual ARM64, not actual output)
//   ldr x0, [sp, #offset_a]  // Load value of 'a' into register x0
//   ldr x1, [sp, #offset_b]  // Load value of 'b' into register x1
//   add x2, x0, x1          // Add x0 and x1, store result in x2
//   str x2, [sp, #offset_result] // Store the result back to the stack
//   ret                       // Return

// The Simulator would execute these instructions step-by-step,
// updating its simulated registers and memory.

// For more complex operations, the generated code might call a built-in function:
// (Conceptual ARM64)
//   mov x0, <address of 'a'>
//   mov x1, <address of 'b'>
//   bl <address of runtime_add_function> // Call the runtime function

// The Simulator's `DoRuntimeCall` would handle this 'bl' instruction,
// invoking the actual C++ implementation of the 'runtime_add_function'.
```

In essence, the `Simulator` acts as a virtual ARM64 processor, allowing developers to test and debug the generated machine code for V8 without needing physical ARM64 hardware. It's a crucial tool for V8 development and testing on different platforms.

Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
          "0x%016" PRIx64 ", 0x%016" PRIx64 ", 0x%016" PRIx64 ", 0x%016" PRIx64,
          arg0, arg1, arg2, arg3);
      double result = target(arg0, arg1, arg2, arg3);
      TraceSim("Returned: %f\n", result);
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      set_dreg(0, result);
      break;
    }

    case ExternalReference::DIRECT_API_CALL: {
      // void f(v8::FunctionCallbackInfo&)
      TraceSim("Type: DIRECT_API_CALL\n");
      TraceSim("Arguments: 0x%016" PRIx64 "\n", arg0);
      SimulatorRuntimeDirectApiCall target =
          reinterpret_cast<SimulatorRuntimeDirectApiCall>(external);
      target(arg0);
      TraceSim("No return value.");
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      break;
    }

    case ExternalReference::DIRECT_GETTER_CALL: {
      // void f(v8::Local<String> property, v8::PropertyCallbackInfo& info)
      TraceSim("Type: DIRECT_GETTER_CALL\n");
      TraceSim("Arguments: 0x%016" PRIx64 ", 0x%016" PRIx64 "\n", arg0, arg1);
      SimulatorRuntimeDirectGetterCall target =
          reinterpret_cast<SimulatorRuntimeDirectGetterCall>(external);
      target(arg0, arg1);
      TraceSim("No return value.");
#ifdef DEBUG
      CorruptAllCallerSavedCPURegisters();
#endif
      break;
    }
  }

  set_lr(return_address);
  set_pc(return_address);
}

const char* Simulator::xreg_names[] = {
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",  "x10",
    "x11", "x12", "x13", "x14", "x15", "ip0", "ip1", "x18", "x19", "x20", "x21",
    "x22", "x23", "x24", "x25", "x26", "cp",  "x28", "fp",  "lr",  "xzr", "sp"};

const char* Simulator::wreg_names[] = {
    "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",  "w8",
    "w9",  "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17",
    "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26",
    "wcp", "w28", "wfp", "wlr", "wzr", "wsp"};

const char* Simulator::sreg_names[] = {
    "s0",  "s1",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",  "s8",  "s9",  "s10",
    "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21",
    "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31"};

const char* Simulator::dreg_names[] = {
    "d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",  "d8",  "d9",  "d10",
    "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21",
    "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"};

const char* Simulator::vreg_names[] = {
    "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v8",  "v9",  "v10",
    "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21",
    "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"};

const char* Simulator::WRegNameForCode(unsigned code, Reg31Mode mode) {
  static_assert(arraysize(Simulator::wreg_names) == (kNumberOfRegisters + 1),
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
  // The modulo operator has no effect here, but it silences a broken GCC
  // warning about out-of-bounds array accesses.
  code %= kNumberOfRegisters;

  // If the code represents the stack pointer, index the name after zr.
  if ((code == kZeroRegCode) && (mode == Reg31IsStackPointer)) {
    code = kZeroRegCode + 1;
  }
  return wreg_names[code];
}

const char* Simulator::XRegNameForCode(unsigned code, Reg31Mode mode) {
  static_assert(arraysize(Simulator::xreg_names) == (kNumberOfRegisters + 1),
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
  code %= kNumberOfRegisters;

  // If the code represents the stack pointer, index the name after zr.
  if ((code == kZeroRegCode) && (mode == Reg31IsStackPointer)) {
    code = kZeroRegCode + 1;
  }
  return xreg_names[code];
}

const char* Simulator::SRegNameForCode(unsigned code) {
  static_assert(arraysize(Simulator::sreg_names) == kNumberOfVRegisters,
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return sreg_names[code % kNumberOfVRegisters];
}

const char* Simulator::DRegNameForCode(unsigned code) {
  static_assert(arraysize(Simulator::dreg_names) == kNumberOfVRegisters,
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return dreg_names[code % kNumberOfVRegisters];
}

const char* Simulator::VRegNameForCode(unsigned code) {
  static_assert(arraysize(Simulator::vreg_names) == kNumberOfVRegisters,
                "Array must be large enough to hold all register names.");
  DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
  return vreg_names[code % kNumberOfVRegisters];
}

void LogicVRegister::ReadUintFromMem(VectorFormat vform, int index,
                                     uint64_t addr) const {
  switch (LaneSizeInBitsFromFormat(vform)) {
    case 8:
      register_.Insert(index, SimMemory::Read<uint8_t>(addr));
      break;
    case 16:
      register_.Insert(index, SimMemory::Read<uint16_t>(addr));
      break;
    case 32:
      register_.Insert(index, SimMemory::Read<uint32_t>(addr));
      break;
    case 64:
      register_.Insert(index, SimMemory::Read<uint64_t>(addr));
      break;
    default:
      UNREACHABLE();
  }
}

void LogicVRegister::WriteUintToMem(VectorFormat vform, int index,
                                    uint64_t addr) const {
  switch (LaneSizeInBitsFromFormat(vform)) {
    case 8:
      SimMemory::Write<uint8_t>(addr, static_cast<uint8_t>(Uint(vform, index)));
      break;
    case 16:
      SimMemory::Write<uint16_t>(addr,
                                 static_cast<uint16_t>(Uint(vform, index)));
      break;
    case 32:
      SimMemory::Write<uint32_t>(addr,
                                 static_cast<uint32_t>(Uint(vform, index)));
      break;
    case 64:
      SimMemory::Write<uint64_t>(addr, Uint(vform, index));
      break;
    default:
      UNREACHABLE();
  }
}

int Simulator::CodeFromName(const char* name) {
  for (unsigned i = 0; i < kNumberOfRegisters; i++) {
    if ((strcmp(xreg_names[i], name) == 0) ||
        (strcmp(wreg_names[i], name) == 0)) {
      return i;
    }
  }
  for (unsigned i = 0; i < kNumberOfVRegisters; i++) {
    if ((strcmp(vreg_names[i], name) == 0) ||
        (strcmp(dreg_names[i], name) == 0) ||
        (strcmp(sreg_names[i], name) == 0)) {
      return i;
    }
  }
  if ((strcmp("sp", name) == 0) || (strcmp("wsp", name) == 0)) {
    return kSPRegInternalCode;
  }
  if (strcmp("x16", name) == 0) return CodeFromName("ip0");
  if (strcmp("x17", name) == 0) return CodeFromName("ip1");
  if (strcmp("x29", name) == 0) return CodeFromName("fp");
  if (strcmp("x30", name) == 0) return CodeFromName("lr");
  return -1;
}

// Helpers ---------------------------------------------------------------------
template <typename T>
T Simulator::AddWithCarry(bool set_flags, T left, T right, int carry_in) {
  // Use unsigned types to avoid implementation-defined overflow behaviour.
  static_assert(std::is_unsigned<T>::value, "operands must be unsigned");
  static_assert((sizeof(T) == kWRegSize) || (sizeof(T) == kXRegSize),
                "Only W- or X-sized operands are tested");

  DCHECK((carry_in == 0) || (carry_in == 1));
  T result = left + right + carry_in;

  if (set_flags) {
    nzcv().SetN(CalcNFlag(result));
    nzcv().SetZ(CalcZFlag(result));

    // Compute the C flag by comparing the result to the max unsigned integer.
    T max_uint_2op = std::numeric_limits<T>::max() - carry_in;
    nzcv().SetC((left > max_uint_2op) || ((max_uint_2op - left) < right));

    // Overflow iff the sign bit is the same for the two inputs and different
    // for the result.
    T sign_mask = T(1) << (sizeof(T) * 8 - 1);
    T left_sign = left & sign_mask;
    T right_sign = right & sign_mask;
    T result_sign = result & sign_mask;
    nzcv().SetV((left_sign == right_sign) && (left_sign != result_sign));

    LogSystemRegister(NZCV);
  }
  return result;
}

template <typename T>
void Simulator::AddSubWithCarry(Instruction* instr) {
  // Use unsigned types to avoid implementation-defined overflow behaviour.
  static_assert(std::is_unsigned<T>::value, "operands must be unsigned");

  T op2 = reg<T>(instr->Rm());
  T new_val;

  if ((instr->Mask(AddSubOpMask) == SUB) || instr->Mask(AddSubOpMask) == SUBS) {
    op2 = ~op2;
  }

  new_val = AddWithCarry<T>(instr->FlagsUpdate(), reg<T>(instr->Rn()), op2,
                            nzcv().C());

  set_reg<T>(instr->Rd(), new_val);
}

sim_uint128_t Simulator::PolynomialMult128(uint64_t op1, uint64_t op2,
                                           int lane_size_in_bits) const {
  DCHECK_LE(static_cast<unsigned>(lane_size_in_bits), kDRegSizeInBits);
  sim_uint128_t result = std::make_pair(0, 0);
  sim_uint128_t op2q = std::make_pair(0, op2);
  for (int i = 0; i < lane_size_in_bits; i++) {
    if ((op1 >> i) & 1) {
      result = Eor128(result, Lsl128(op2q, i));
    }
  }
  return result;
}

sim_uint128_t Simulator::Lsl128(sim_uint128_t x, unsigned shift) const {
  DCHECK_LE(shift, 64);
  if (shift == 0) return x;
  if (shift == 64) return std::make_pair(x.second, 0);
  uint64_t lo = x.second << shift;
  uint64_t hi = (x.first << shift) | (x.second >> (64 - shift));
  return std::make_pair(hi, lo);
}

sim_uint128_t Simulator::Eor128(sim_uint128_t x, sim_uint128_t y) const {
  return std::make_pair(x.first ^ y.first, x.second ^ y.second);
}

template <typename T>
T Simulator::ShiftOperand(T value, Shift shift_type, unsigned amount) {
  using unsignedT = typename std::make_unsigned<T>::type;

  if (amount == 0) {
    return value;
  }
  // Larger shift {amount}s would be undefined behavior in C++.
  DCHECK(amount < sizeof(value) * kBitsPerByte);

  switch (shift_type) {
    case LSL:
      return static_cast<unsignedT>(value) << amount;
    case LSR:
      return static_cast<unsignedT>(value) >> amount;
    case ASR:
      return value >> amount;
    case ROR: {
      unsignedT mask = (static_cast<unsignedT>(1) << amount) - 1;
      return (static_cast<unsignedT>(value) >> amount) |
             ((value & mask) << (sizeof(mask) * 8 - amount));
    }
    default:
      UNIMPLEMENTED();
      return 0;
  }
}

template <typename T>
T Simulator::ExtendValue(T value, Extend extend_type, unsigned left_shift) {
  const unsigned kSignExtendBShift = (sizeof(T) - 1) * 8;
  const unsigned kSignExtendHShift = (sizeof(T) - 2) * 8;
  const unsigned kSignExtendWShift = (sizeof(T) - 4) * 8;
  using unsignedT = typename std::make_unsigned<T>::type;

  switch (extend_type) {
    case UXTB:
      value &= kByteMask;
      break;
    case UXTH:
      value &= kHalfWordMask;
      break;
    case UXTW:
      value &= kWordMask;
      break;
    case SXTB:
      value =
          static_cast<T>(static_cast<unsignedT>(value) << kSignExtendBShift) >>
          kSignExtendBShift;
      break;
    case SXTH:
      value =
          static_cast<T>(static_cast<unsignedT>(value) << kSignExtendHShift) >>
          kSignExtendHShift;
      break;
    case SXTW:
      value =
          static_cast<T>(static_cast<unsignedT>(value) << kSignExtendWShift) >>
          kSignExtendWShift;
      break;
    case UXTX:
    case SXTX:
      break;
    default:
      UNREACHABLE();
  }
  return static_cast<T>(static_cast<unsignedT>(value) << left_shift);
}

template <typename T>
void Simulator::Extract(Instruction* instr) {
  unsigned lsb = instr->ImmS();
  T op2 = reg<T>(instr->Rm());
  T result = op2;

  if (lsb) {
    T op1 = reg<T>(instr->Rn());
    result = op2 >> lsb | (op1 << ((sizeof(T) * 8) - lsb));
  }
  set_reg<T>(instr->Rd(), result);
}

void Simulator::FPCompare(double val0, double val1) {
  AssertSupportedFPCR();

  // TODO(jbramley): This assumes that the C++ implementation handles
  // comparisons in the way that we expect (as per AssertSupportedFPCR()).
  if ((std::isnan(val0) != 0) || (std::isnan(val1) != 0)) {
    nzcv().SetRawValue(FPUnorderedFlag);
  } else if (val0 < val1) {
    nzcv().SetRawValue(FPLessThanFlag);
  } else if (val0 > val1) {
    nzcv().SetRawValue(FPGreaterThanFlag);
  } else if (val0 == val1) {
    nzcv().SetRawValue(FPEqualFlag);
  } else {
    UNREACHABLE();
  }
  LogSystemRegister(NZCV);
}

Simulator::PrintRegisterFormat Simulator::GetPrintRegisterFormatForSize(
    size_t reg_size, size_t lane_size) {
  DCHECK_GE(reg_size, lane_size);

  uint32_t format = 0;
  if (reg_size != lane_size) {
    switch (reg_size) {
      default:
        UNREACHABLE();
      case kQRegSize:
        format = kPrintRegAsQVector;
        break;
      case kDRegSize:
        format = kPrintRegAsDVector;
        break;
    }
  }

  switch (lane_size) {
    default:
      UNREACHABLE();
    case kQRegSize:
      format |= kPrintReg1Q;
      break;
    case kDRegSize:
      format |= kPrintReg1D;
      break;
    case kSRegSize:
      format |= kPrintReg1S;
      break;
    case kHRegSize:
      format |= kPrintReg1H;
      break;
    case kBRegSize:
      format |= kPrintReg1B;
      break;
  }

  // These sizes would be duplicate case labels.
  static_assert(kXRegSize == kDRegSize, "X and D registers must be same size.");
  static_assert(kWRegSize == kSRegSize, "W and S registers must be same size.");
  static_assert(kPrintXReg == kPrintReg1D,
                "X and D register printing code is shared.");
  static_assert(kPrintWReg == kPrintReg1S,
                "W and S register printing code is shared.");

  return static_cast<PrintRegisterFormat>(format);
}

Simulator::PrintRegisterFormat Simulator::GetPrintRegisterFormat(
    VectorFormat vform) {
  switch (vform) {
    default:
      UNREACHABLE();
    case kFormat16B:
      return kPrintReg16B;
    case kFormat8B:
      return kPrintReg8B;
    case kFormat8H:
      return kPrintReg8H;
    case kFormat4H:
      return kPrintReg4H;
    case kFormat4S:
      return kPrintReg4S;
    case kFormat2S:
      return kPrintReg2S;
    case kFormat2D:
      return kPrintReg2D;
    case kFormat1D:
      return kPrintReg1D;

    case kFormatB:
      return kPrintReg1B;
    case kFormatH:
      return kPrintReg1H;
    case kFormatS:
      return kPrintReg1S;
    case kFormatD:
      return kPrintReg1D;
  }
}

Simulator::PrintRegisterFormat Simulator::GetPrintRegisterFormatFP(
    VectorFormat vform) {
  switch (vform) {
    default:
      UNREACHABLE();
    case kFormat4S:
      return kPrintReg4SFP;
    case kFormat2S:
      return kPrintReg2SFP;
    case kFormat2D:
      return kPrintReg2DFP;
    case kFormat1D:
      return kPrintReg1DFP;

    case kFormatS:
      return kPrintReg1SFP;
    case kFormatD:
      return kPrintReg1DFP;
  }
}

void Simulator::SetBreakpoint(Instruction* location) {
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    if (breakpoints_.at(i).location == location) {
      PrintF(stream_, "Existing breakpoint at %p was %s\n",
             reinterpret_cast<void*>(location),
             breakpoints_.at(i).enabled ? "disabled" : "enabled");
      breakpoints_.at(i).enabled = !breakpoints_.at(i).enabled;
      return;
    }
  }
  Breakpoint new_breakpoint = {location, true};
  breakpoints_.push_back(new_breakpoint);
  PrintF(stream_, "Set a breakpoint at %p\n",
         reinterpret_cast<void*>(location));
}

void Simulator::ListBreakpoints() {
  PrintF(stream_, "Breakpoints:\n");
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    PrintF(stream_, "%p  : %s\n",
           reinterpret_cast<void*>(breakpoints_.at(i).location),
           breakpoints_.at(i).enabled ? "enabled" : "disabled");
  }
}

void Simulator::CheckBreakpoints() {
  bool hit_a_breakpoint = false;
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    if ((breakpoints_.at(i).location == pc_) && breakpoints_.at(i).enabled) {
      hit_a_breakpoint = true;
      // Disable this breakpoint.
      breakpoints_.at(i).enabled = false;
    }
  }
  if (hit_a_breakpoint) {
    PrintF(stream_, "Hit and disabled a breakpoint at %p.\n",
           reinterpret_cast<void*>(pc_));
    Debug();
  }
}

void Simulator::CheckBreakNext() {
  // If the current instruction is a BL, insert a breakpoint just after it.
  if (break_on_next_ && pc_->IsBranchAndLinkToRegister()) {
    SetBreakpoint(pc_->following());
    break_on_next_ = false;
  }
}

void Simulator::PrintInstructionsAt(Instruction* start, uint64_t count) {
  Instruction* end = start->InstructionAtOffset(count * kInstrSize);
  for (Instruction* pc = start; pc < end; pc = pc->following()) {
    disassembler_decoder_->Decode(pc);
  }
}

void Simulator::PrintWrittenRegisters() {
  for (unsigned i = 0; i < kNumberOfRegisters; i++) {
    if (registers_[i].WrittenSinceLastLog()) PrintRegister(i);
  }
}

void Simulator::PrintWrittenVRegisters() {
  for (unsigned i = 0; i < kNumberOfVRegisters; i++) {
    // At this point there is no type information, so print as a raw 1Q.
    if (vregisters_[i].WrittenSinceLastLog()) PrintVRegister(i, kPrintReg1Q);
  }
}

void Simulator::PrintSystemRegisters() {
  PrintSystemRegister(NZCV);
  PrintSystemRegister(FPCR);
}

void Simulator::PrintRegisters() {
  for (unsigned i = 0; i < kNumberOfRegisters; i++) {
    PrintRegister(i);
  }
}

void Simulator::PrintVRegisters() {
  for (unsigned i = 0; i < kNumberOfVRegisters; i++) {
    // At this point there is no type information, so print as a raw 1Q.
    PrintVRegister(i, kPrintReg1Q);
  }
}

void Simulator::PrintRegister(unsigned code, Reg31Mode r31mode) {
  registers_[code].NotifyRegisterLogged();

  // Don't print writes into xzr.
  if ((code == kZeroRegCode) && (r31mode == Reg31IsZeroRegister)) {
    return;
  }

  // The template for all x and w registers:
  //   "# x{code}: 0x{value}"
  //   "# w{code}: 0x{value}"

  PrintRegisterRawHelper(code, r31mode);
  fprintf(stream_, "\n");
}

// Print a register's name and raw value.
//
// The `bytes` and `lsb` arguments can be used to limit the bytes that are
// printed. These arguments are intended for use in cases where register hasn't
// actually been updated (such as in PrintVWrite).
//
// No newline is printed. This allows the caller to print more details (such as
// a floating-point interpretation or a memory access annotation).
void Simulator::PrintVRegisterRawHelper(unsigned code, int bytes, int lsb) {
  // The template for vector types:
  //   "# v{code}: 0xFFEEDDCCBBAA99887766554433221100".
  // An example with bytes=4 and lsb=8:
  //   "# v{code}:         0xBBAA9988                ".
  fprintf(stream_, "# %s%5s: %s", clr_vreg_name, VRegNameForCode(code),
          clr_vreg_value);

  int msb = lsb + bytes - 1;
  int byte = kQRegSize - 1;

  // Print leading padding spaces. (Two spaces per byte.)
  while (byte > msb) {
    fprintf(stream_, "  ");
    byte--;
  }

  // Print the specified part of the value, byte by byte.
  qreg_t rawbits = qreg(code);
  fprintf(stream_, "0x");
  while (byte >= lsb) {
    fprintf(stream_, "%02x", rawbits.val[byte]);
    byte--;
  }

  // Print trailing padding spaces.
  while (byte >= 0) {
    fprintf(stream_, "  ");
    byte--;
  }
  fprintf(stream_, "%s", clr_normal);
}

// Print each of the specified lanes of a register as a float or double value.
//
// The `lane_count` and `lslane` arguments can be used to limit the lanes that
// are printed. These arguments are intended for use in cases where register
// hasn't actually been updated (such as in PrintVWrite).
//
// No newline is printed. This allows the caller to print more details (such as
// a memory access annotation).
void Simulator::PrintVRegisterFPHelper(unsigned code,
                                       unsigned lane_size_in_bytes,
                                       int lane_count, int rightmost_lane) {
  DCHECK((lane_size_in_bytes == kSRegSize) ||
         (lane_size_in_bytes == kDRegSize));

  unsigned msb = (lane_count + rightmost_lane) * lane_size_in_bytes;
  DCHECK_LE(msb, static_cast<unsigned>(kQRegSize));

  // For scalar types ((lane_count == 1) && (rightmost_lane == 0)), a register
  // name is used:
  //   " (s{code}: {value})"
  //   " (d{code}: {value})"
  // For vector types, "..." is used to represent one or more omitted lanes.
  //   " (..., {value}, {value}, ...)"
  if ((lane_count == 1) && (rightmost_lane == 0)) {
    const char* name = (lane_size_in_bytes == kSRegSize)
                           ? SRegNameForCode(code)
                           : DRegNameForCode(code);
    fprintf(stream_, " (%s%s: ", clr_vreg_name, name);
  } else {
    if (msb < (kQRegSize - 1)) {
      fprintf(stream_, " (..., ");
    } else {
      fprintf(stream_, " (");
    }
  }

  // Print the list of values.
  const char* separator = "";
  int leftmost_lane = rightmost_lane + lane_count - 1;
  for (int lane = leftmost_lane; lane >= rightmost_lane; lane--) {
    double value = (lane_size_in_bytes == kSRegSize)
                       ? vreg(code).Get<float>(lane)
                       : vreg(code).Get<double>(lane);
    fprintf(stream_, "%s%s%#g%s", separator, clr_vreg_value, value, clr_normal);
    separator = ", ";
  }

  if (rightmost_lane > 0) {
    fprintf(stream_, ", ...");
  }
  fprintf(stream_, ")");
}

// Print a register's name and raw value.
//
// Only the least-significant `size_in_bytes` bytes of the register are printed,
// but the value is aligned as if the whole register had been printed.
//
// For typical register updates, size_in_bytes should be set to kXRegSize
// -- the default -- so that the whole register is printed. Other values of
// size_in_bytes are intended for use when the register hasn't actually been
// updated (such as in PrintWrite).
//
// No newline is printed. This allows the caller to print more details (such as
// a memory access annotation).
void Simulator::PrintRegisterRawHelper(unsigned code, Reg31Mode r31mode,
                                       int size_in_bytes) {
  // The template for all supported sizes.
  //   "# x{code}: 0xFFEEDDCCBBAA9988"
  //   "# w{code}:         0xBBAA9988"
  //   "# w{code}<15:0>:       0x9988"
  //   "# w{code}<7:0>:          0x88"
  unsigned padding_chars = (kXRegSize - size_in_bytes) * 2;

  const char* name = "";
  const char* suffix = "";
  switch (size_in_bytes) {
    case kXRegSize:
      name = XRegNameForCode(code, r31mode);
      break;
    case kWRegSize:
      name = WRegNameForCode(code, r31mode);
      break;
    case 2:
      name = WRegNameForCode(code, r31mode);
      suffix = "<15:0>";
      padding_chars -= strlen(suffix);
      break;
    case 1:
      name = WRegNameForCode(code, r31mode);
      suffix = "<7:0>";
      padding_chars -= strlen(suffix);
      break;
    default:
      UNREACHABLE();
  }
  fprintf(stream_, "# %s%5s%s: ", clr_reg_name, name, suffix);

  // Print leading padding spaces.
  DCHECK_LT(padding_chars, kXRegSize * 2U);
  for (unsigned i = 0; i < padding_chars; i++) {
    putc(' ', stream_);
  }

  // Print the specified bits in hexadecimal format.
  uint64_t bits = reg<uint64_t>(code, r31mode);
  bits &= kXRegMask >> ((kXRegSize - size_in_bytes) * 8);
  static_assert(sizeof(bits) == kXRegSize,
                "X registers and uint64_t must be the same size.");

  int chars = size_in_bytes * 2;
  fprintf(stream_, "%s0x%0*" PRIx64 "%s", clr_reg_value, chars, bits,
          clr_normal);
}

void Simulator::PrintVRegister(unsigned code, PrintRegisterFormat format) {
  vregisters_[code].NotifyRegisterLogged();

  int lane_size_log2 = format & kPrintRegLaneSizeMask;

  int reg_size_log2;
  if (format & kPrintRegAsQVector) {
    reg_size_log2 = kQRegSizeLog2;
  } else if (format & kPrintRegAsDVector) {
    reg_size_log2 = kDRegSizeLog2;
  } else {
    // Scalar types.
    reg_size_log2 = lane_size_log2;
  }

  int lane_count = 1 << (reg_size_log2 - lane_size_log2);
  int lane_size = 1 << lane_size_log2;

  // The template for vector types:
  //   "# v{code}: 0x{rawbits} (..., {value}, ...)".
  // The template for scalar types:
  //   "# v{code}: 0x{rawbits} ({reg}:{value})".
  // The values in parentheses after the bit representations are floating-point
  // interpretations. They are displayed only if the kPrintVRegAsFP bit is set.

  PrintVRegisterRawHelper(code);
  if (format & kPrintRegAsFP) {
    PrintVRegisterFPHelper(code, lane_size, lane_count);
  }

  fprintf(stream_, "\n");
}

void Simulator::PrintSystemRegister(SystemRegister id) {
  switch (id) {
    case NZCV:
      fprintf(stream_, "# %sNZCV: %sN:%d Z:%d C:%d V:%d%s\n", clr_flag_name,
              clr_flag_value, nzcv().N(), nzcv().Z(), nzcv().C(), nzcv().V(),
              clr_normal);
      break;
    case FPCR: {
      static const char* rmode[] = {
          "0b00 (Round to Nearest)", "0b01 (Round towards Plus Infinity)",
          "0b10 (Round towards Minus Infinity)", "0b11 (Round towards Zero)"};
      DCHECK(fpcr().RMode() < arraysize(rmode));
      fprintf(stream_, "# %sFPCR: %sAHP:%d DN:%d FZ:%d RMode:%s%s\n",
              clr_flag_name, clr_flag_value, fpcr().AHP(), fpcr().DN(),
              fpcr().FZ(), rmode[fpcr().RMode()], clr_normal);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::PrintRead(uintptr_t address, unsigned reg_code,
                          PrintRegisterFormat format) {
  registers_[reg_code].NotifyRegisterLogged();

  USE(format);

  // The template is "# {reg}: 0x{value} <- {address}".
  PrintRegisterRawHelper(reg_code, Reg31IsZeroRegister);
  fprintf(stream_, " <- %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

void Simulator::PrintVRead(uintptr_t address, unsigned reg_code,
                           PrintRegisterFormat format, unsigned lane) {
  vregisters_[reg_code].NotifyRegisterLogged();

  // The template is "# v{code}: 0x{rawbits} <- address".
  PrintVRegisterRawHelper(reg_code);
  if (format & kPrintRegAsFP) {
    PrintVRegisterFPHelper(reg_code, GetPrintRegLaneSizeInBytes(format),
                           GetPrintRegLaneCount(format), lane);
  }
  fprintf(stream_, " <- %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

void Simulator::PrintWrite(uintptr_t address, unsigned reg_code,
                           PrintRegisterFormat format) {
  DCHECK_EQ(GetPrintRegLaneCount(format), 1U);

  // The template is "# v{code}: 0x{value} -> {address}". To keep the trace tidy
  // and readable, the value is aligned with the values in the register trace.
  PrintRegisterRawHelper(reg_code, Reg31IsZeroRegister,
                         GetPrintRegSizeInBytes(format));
  fprintf(stream_, " -> %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

void Simulator::PrintVWrite(uintptr_t address, unsigned reg_code,
                            PrintRegisterFormat format, unsigned lane) {
  // The templates:
  //   "# v{code}: 0x{rawbits} -> {address}"
  //   "# v{code}: 0x{rawbits} (..., {value}, ...) -> {address}".
  //   "# v{code}: 0x{rawbits} ({reg}:{value}) -> {address}"
  // Because this trace doesn't represent a change to the source register's
  // value, only the relevant part of the value is printed. To keep the trace
  // tidy and readable, the raw value is aligned with the other values in the
  // register trace.
  int lane_count = GetPrintRegLaneCount(format);
  int lane_size = GetPrintRegLaneSizeInBytes(format);
  int reg_size = GetPrintRegSizeInBytes(format);
  PrintVRegisterRawHelper(reg_code, reg_size, lane_size * lane);
  if (format & kPrintRegAsFP) {
    PrintVRegisterFPHelper(reg_code, lane_size, lane_count, lane);
  }
  fprintf(stream_, " -> %s0x%016" PRIxPTR "%s\n", clr_memory_address, address,
          clr_normal);
}

// Visitors---------------------------------------------------------------------

void Simulator::VisitUnimplemented(Instruction* instr) {
  fprintf(stream_, "Unimplemented instruction at %p: 0x%08" PRIx32 "\n",
          reinterpret_cast<void*>(instr), instr->InstructionBits());
  UNIMPLEMENTED();
}

void Simulator::VisitUnallocated(Instruction* instr) {
  fprintf(stream_, "Unallocated instruction at %p: 0x%08" PRIx32 "\n",
          reinterpret_cast<void*>(instr), instr->InstructionBits());
  UNIMPLEMENTED();
}

void Simulator::VisitPCRelAddressing(Instruction* instr) {
  switch (instr->Mask(PCRelAddressingMask)) {
    case ADR:
      set_reg(instr->Rd(), instr->ImmPCOffsetTarget());
      break;
    case ADRP:  // Not implemented in the assembler.
      UNIMPLEMENTED();
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitUnconditionalBranch(Instruction* instr) {
  switch (instr->Mask(UnconditionalBranchMask)) {
    case BL:
      set_lr(instr->following());
      [[fallthrough]];
    case B:
      set_pc(instr->ImmPCOffsetTarget());
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitConditionalBranch(Instruction* instr) {
  DCHECK(instr->Mask(ConditionalBranchMask) == B_cond);
  if (ConditionPassed(static_cast<Condition>(instr->ConditionBranch()))) {
    set_pc(instr->ImmPCOffsetTarget());
  }
}

Simulator::BType Simulator::GetBTypeFromInstruction(
    const Instruction* instr) const {
  switch (instr->Mask(UnconditionalBranchToRegisterMask)) {
    case BLR:
      return BranchAndLink;
    case BR:
      if (!PcIsInGuardedPage() || (instr->Rn() == 16) || (instr->Rn() == 17)) {
        return BranchFromUnguardedOrToIP;
      }
      return BranchFromGuardedNotToIP;
  }
  return DefaultBType;
}

void Simulator::VisitUnconditionalBranchToRegister(Instruction* instr) {
  Instruction* target = reg<Instruction*>(instr->Rn());
  switch (instr->Mask(UnconditionalBranchToRegisterMask)) {
    case BLR: {
      set_lr(instr->following());
      if (instr->Rn() == 31) {
        // BLR XZR is used as a guard for the constant pool. We should never hit
        // this, but if we do trap to allow debugging.
        Debug();
      }
      [[fallthrough]];
    }
    case BR:
    case RET:
      set_pc(target);
      break;
    default:
      UNIMPLEMENTED();
  }
  set_btype(GetBTypeFromInstruction(instr));
}

void Simulator::VisitTestBranch(Instruction* instr) {
  unsigned bit_pos =
      (instr->ImmTestBranchBit5() << 5) | instr->ImmTestBranchBit40();
  bool take_branch = ((xreg(instr->Rt()) & (1ULL << bit_pos)) == 0);
  switch (instr->Mask(TestBranchMask)) {
    case TBZ:
      break;
    case TBNZ:
      take_branch = !take_branch;
      break;
    default:
      UNIMPLEMENTED();
  }
  if (take_branch) {
    set_pc(instr->ImmPCOffsetTarget());
  }
}

void Simulator::VisitCompareBranch(Instruction* instr) {
  unsigned rt = instr->Rt();
  bool take_branch = false;
  switch (instr->Mask(CompareBranchMask)) {
    case CBZ_w:
      take_branch = (wreg(rt) == 0);
      break;
    case CBZ_x:
      take_branch = (xreg(rt) == 0);
      break;
    case CBNZ_w:
      take_branch = (wreg(rt) != 0);
      break;
    case CBNZ_x:
      take_branch = (xreg(rt) != 0);
      break;
    default:
      UNIMPLEMENTED();
  }
  if (take_branch) {
    set_pc(instr->ImmPCOffsetTarget());
  }
}

template <typename T>
void Simulator::AddSubHelper(Instruction* instr, T op2) {
  // Use unsigned types to avoid implementation-defined overflow behaviour.
  static_assert(std::is_unsigned<T>::value, "operands must be unsigned");

  bool set_flags = instr->FlagsUpdate();
  T new_val = 0;
  Instr operation = instr->Mask(AddSubOpMask);

  switch (operation) {
    case ADD:
    case ADDS: {
      new_val =
          AddWithCarry<T>(set_flags, reg<T>(instr->Rn(), instr->RnMode()), op2);
      break;
    }
    case SUB:
    case SUBS: {
      new_val = AddWithCarry<T>(set_flags, reg<T>(instr->Rn(), instr->RnMode()),
                                ~op2, 1);
      break;
    }
    default:
      UNREACHABLE();
  }

  set_reg<T>(instr->Rd(), new_val, instr->RdMode());
}

void Simulator::VisitAddSubShifted(Instruction* instr) {
  Shift shift_type = static_cast<Shift>(instr->ShiftDP());
  unsigned shift_amount = instr->ImmDPShift();

  if (instr->SixtyFourBits()) {
    uint64_t op2 = ShiftOperand(xreg(instr->Rm()), shift_type, shift_amount);
    AddSubHelper(instr, op2);
  } else {
    uint32_t op2 = ShiftOperand(wreg(instr->Rm()), shift_type, shift_amount);
    AddSubHelper(instr, op2);
  }
}

void Simulator::VisitAddSubImmediate(Instruction* instr) {
  int64_t op2 = instr->ImmAddSub() << ((instr->ShiftAddSub() == 1) ? 12 : 0);
  if (instr->SixtyFourBits()) {
    AddSubHelper(instr, static_cast<uint64_t>(op2));
  } else {
    AddSubHelper(instr, static_cast<uint32_t>(op2));
  }
}

void Simulator::VisitAddSubExtended(Instruction* instr) {
  Extend ext = static_cast<Extend>(instr->ExtendMode());
  unsigned left_shift = instr->ImmExtendShift();
  if (instr->Six
"""


```