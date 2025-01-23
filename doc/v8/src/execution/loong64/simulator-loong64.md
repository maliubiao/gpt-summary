Response: The user wants me to summarize the functionality of the provided C++ code snippet.
This code seems to implement a simulator for the LOONG64 architecture within the V8 JavaScript engine.

Here's a breakdown of the code's key aspects:

1. **Simulator Core:** It defines the `Simulator` class, which holds the state of the simulated LOONG64 processor (registers, memory, etc.).
2. **Instruction Fetch and Decode:**  Although not explicitly shown in this snippet, the simulator will need to fetch and decode LOONG64 instructions. The `InstructionDecode` methods suggest this.
3. **Register Management:** The code provides methods to get and set both general-purpose and floating-point registers (`get_register`, `set_register`, `get_fpu_register`, `set_fpu_register`).
4. **Memory Access:**  It includes functions for reading and writing to simulated memory (`ReadW`, `WriteW`, `Read2W`, `Write2W`, etc.). It also simulates cache behavior (`FlushICache`, `CheckICache`).
5. **Debugging Support:**  The `Loong64Debugger` class allows for stepping through simulated code, inspecting registers and memory, setting breakpoints, and more.
6. **Floating-Point Unit (FPU) Simulation:**  The code simulates the LOONG64 FPU, including handling floating-point registers, the FCSR control register, and rounding modes.
7. **WebAssembly Integration:** The `#if V8_ENABLE_WEBASSEMBLY` block suggests it can be used to simulate LOONG64 execution for WebAssembly.
8. **Tracing:**  The `TraceRegWr` and `TraceMemWr` functions indicate the simulator can log register writes and memory accesses for debugging.
9. **Stack Management:** The simulator manages a simulated stack.

Now, let's consider the relationship with JavaScript. The V8 engine executes JavaScript code. This simulator is used when V8 needs to run JavaScript code on a LOONG64 architecture *without* having actual LOONG64 hardware. This is common during development, testing, or on platforms where a LOONG64 processor isn't available.

To illustrate with JavaScript, imagine a simple function:

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

When V8 executes this, it compiles the JavaScript into machine code. If V8 is configured to use the LOONG64 simulator (e.g., when running on a non-LOONG64 machine but targeting that architecture), the simulator will execute the LOONG64 machine code generated for this `add` function. The simulator will mimic how a real LOONG64 processor would perform the addition, manipulating its simulated registers and memory according to the LOONG64 instructions.
This C++ code snippet is part of the **LOONG64 architecture simulator** within the V8 JavaScript engine. Its primary function is to **emulate the behavior of a LOONG64 processor**, allowing V8 to run LOONG64 machine code on platforms where a real LOONG64 processor is not present.

Here's a breakdown of its key responsibilities as seen in this portion of the code:

1. **Simulator Class Definition:** It defines the `Simulator` class, which is the core component responsible for holding the simulated state of the processor (registers, memory, program counter, etc.).

2. **Initialization:** The constructor of the `Simulator` class initializes the simulated processor state, including:
    * Setting up the simulated stack.
    * Initializing general-purpose and floating-point registers to zero or known bad values.
    * Setting up the program counter (PC) and return address register (RA).

3. **Register Access:** It provides methods to get and set the values of both general-purpose registers (`get_register`, `set_register`) and floating-point registers (`get_fpu_register`, `set_fpu_register`, etc.).

4. **Debugger Integration:** It includes a `Loong64Debugger` class that allows for interactive debugging of the simulated code. This debugger provides functionalities like:
    * Stepping through instructions.
    * Printing register values (both general-purpose and floating-point).
    * Setting and deleting breakpoints.
    * Disassembling code.
    * Examining memory.

5. **Instruction Handling (Indirectly):**  While this specific snippet doesn't contain the detailed logic for executing each LOONG64 instruction, it lays the groundwork. The `InstructionDecode` calls within the debugger suggest that there's code elsewhere in the simulator responsible for interpreting and executing LOONG64 instructions.

6. **Floating-Point Support:** It includes handling for floating-point registers and the Floating-Point Control and Status Register (FCSR), indicating support for simulating floating-point operations.

7. **ICache Simulation:** It includes basic instruction cache (ICache) simulation logic (`FlushICache`, `CheckICache`) to model how instructions are fetched and cached.

8. **Tracing:**  The `TraceRegWr` and `TraceMemRd` functions suggest the capability to trace register writes and memory accesses for debugging purposes.

**Relationship to JavaScript (with Javascript example):**

This simulator is crucial for V8's ability to run JavaScript on LOONG64 architectures, especially during development or on platforms that don't have native LOONG64 hardware.

When V8 compiles JavaScript code, it can target different architectures, including LOONG64. If V8 is running on a non-LOONG64 machine but needs to execute LOONG64 code (e.g., for testing or in an embedded environment), the simulator steps in.

**Example:**

Consider this simple JavaScript function:

```javascript
function multiply(a, b) {
  return a * b;
}

let result = multiply(5, 10);
console.log(result);
```

When V8 executes this on a system using the LOONG64 simulator, the following happens conceptually:

1. **Compilation to LOONG64 Machine Code:** V8 compiles the `multiply` function into actual LOONG64 assembly instructions. These instructions might look something like (simplified):
   ```assembly
   // Load the value of 'a' into a register (e.g., $r4)
   ld.d $r4, [stack_location_of_a]
   // Load the value of 'b' into another register (e.g., $r5)
   ld.d $r5, [stack_location_of_b]
   // Perform the multiplication and store the result in a register (e.g., $r6)
   mul.d $r6, $r4, $r5
   // Store the result back to memory
   st.d $r6, [stack_location_of_result]
   // ... and so on
   ```

2. **Simulator Execution:** The LOONG64 simulator takes over and executes these generated machine code instructions **step-by-step**.

3. **Register and Memory Emulation:**  The simulator's internal state (registers, memory) is updated to reflect the effects of each instruction. For example:
   * When `ld.d $r4, [stack_location_of_a]` is "executed" by the simulator, it will read the value from the simulated memory location representing `a` and store it in the simulator's representation of register `$r4`.
   * When `mul.d $r6, $r4, $r5` is executed, the simulator will perform the multiplication of the values it holds for `$r4` and `$r5` and store the result in its `$r6` register.

4. **JavaScript Result:**  Eventually, the simulated execution will complete, and the simulator will have effectively calculated the result of the JavaScript function. V8 can then retrieve this simulated result and make it available to the JavaScript environment.

In essence, the `simulator-loong64.cc` file (and the broader simulator framework) acts as a **software-based LOONG64 processor** that V8 can use to run JavaScript code compiled for that architecture, even when the underlying hardware is different. This is crucial for cross-platform compatibility and development workflows.

### 提示词
```
这是目录为v8/src/execution/loong64/simulator-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/loong64/simulator-loong64.h"

// Only build the simulator if not compiling for real LOONG64 hardware.
#if defined(USE_SIMULATOR)

#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>

#include <cmath>

#include "src/base/bits.h"
#include "src/base/platform/memory.h"
#include "src/base/platform/platform.h"
#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/loong64/constants-loong64.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disasm.h"
#include "src/heap/combined-heap.h"
#include "src/runtime/runtime-utils.h"
#include "src/utils/ostreams.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/trap-handler/trap-handler-simulator.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(Simulator::GlobalMonitor,
                                Simulator::GlobalMonitor::Get)

// #define PRINT_SIM_LOG

// Util functions.
inline bool HaveSameSign(int64_t a, int64_t b) { return ((a ^ b) >= 0); }

uint32_t get_fcsr_condition_bit(uint32_t cc) {
  if (cc == 0) {
    return 23;
  } else {
    return 24 + cc;
  }
}

#ifdef PRINT_SIM_LOG
inline void printf_instr(const char* _Format, ...) {
  va_list varList;
  va_start(varList, _Format);
  vprintf(_Format, varList);
  va_end(varList);
}
#else
#define printf_instr(...)
#endif

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent was through
// ::v8::internal::OS in the same way as base::SNPrintF is that the Windows C
// Run-Time Library does not provide vsscanf.
#define SScanF sscanf

// The Loong64Debugger class is used by the simulator while debugging simulated
// code.
class Loong64Debugger {
 public:
  explicit Loong64Debugger(Simulator* sim) : sim_(sim) {}

  void Stop(Instruction* instr);
  void Debug();
  // Print all registers with a nice formatting.
  void PrintAllRegs();
  void PrintAllRegsIncludingFPU();

 private:
  // We set the breakpoint code to 0xFFFF to easily recognize it.
  static const Instr kBreakpointInstr = BREAK | 0xFFFF;
  static const Instr kNopInstr = 0x0;

  Simulator* sim_;

  int64_t GetRegisterValue(int regnum);
  int64_t GetFPURegisterValue(int regnum);
  float GetFPURegisterValueFloat(int regnum);
  double GetFPURegisterValueDouble(int regnum);
  bool GetValue(const char* desc, int64_t* value);

  // Set or delete a breakpoint. Returns true if successful.
  bool SetBreakpoint(Instruction* breakpc);
  bool DeleteBreakpoint(Instruction* breakpc);

  // Undo and redo all breakpoints. This is needed to bracket disassembly and
  // execution to skip past breakpoints when run from the debugger.
  void UndoBreakpoints();
  void RedoBreakpoints();
};

inline void UNSUPPORTED() { printf("Sim: Unsupported instruction.\n"); }

void Loong64Debugger::Stop(Instruction* instr) {
  // Get the stop code.
  uint32_t code = instr->Bits(25, 6);
  PrintF("Simulator hit (%u)\n", code);
  Debug();
}

int64_t Loong64Debugger::GetRegisterValue(int regnum) {
  if (regnum == kNumSimuRegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_register(regnum);
  }
}

int64_t Loong64Debugger::GetFPURegisterValue(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register(regnum);
  }
}

float Loong64Debugger::GetFPURegisterValueFloat(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_float(regnum);
  }
}

double Loong64Debugger::GetFPURegisterValueDouble(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_double(regnum);
  }
}

bool Loong64Debugger::GetValue(const char* desc, int64_t* value) {
  int regnum = Registers::Number(desc);
  int fpuregnum = FPURegisters::Number(desc);

  if (regnum != kInvalidRegister) {
    *value = GetRegisterValue(regnum);
    return true;
  } else if (fpuregnum != kInvalidFPURegister) {
    *value = GetFPURegisterValue(fpuregnum);
    return true;
  } else if (strncmp(desc, "0x", 2) == 0) {
    return SScanF(desc + 2, "%" SCNx64, reinterpret_cast<uint64_t*>(value)) ==
           1;
  } else {
    return SScanF(desc, "%" SCNu64, reinterpret_cast<uint64_t*>(value)) == 1;
  }
}

bool Loong64Debugger::SetBreakpoint(Instruction* breakpc) {
  // Check if a breakpoint can be set. If not return without any side-effects.
  if (sim_->break_pc_ != nullptr) {
    return false;
  }

  // Set the breakpoint.
  sim_->break_pc_ = breakpc;
  sim_->break_instr_ = breakpc->InstructionBits();
  // Not setting the breakpoint instruction in the code itself. It will be set
  // when the debugger shell continues.
  return true;
}

bool Loong64Debugger::DeleteBreakpoint(Instruction* breakpc) {
  if (sim_->break_pc_ != nullptr) {
    sim_->break_pc_->SetInstructionBits(sim_->break_instr_);
  }

  sim_->break_pc_ = nullptr;
  sim_->break_instr_ = 0;
  return true;
}

void Loong64Debugger::UndoBreakpoints() {
  if (sim_->break_pc_ != nullptr) {
    sim_->break_pc_->SetInstructionBits(sim_->break_instr_);
  }
}

void Loong64Debugger::RedoBreakpoints() {
  if (sim_->break_pc_ != nullptr) {
    sim_->break_pc_->SetInstructionBits(kBreakpointInstr);
  }
}

void Loong64Debugger::PrintAllRegs() {
#define REG_INFO(n) Registers::Name(n), GetRegisterValue(n), GetRegisterValue(n)

  PrintF("\n");
  // at, v0, a0.
  PrintF("%3s: 0x%016" PRIx64 " %14" PRId64 "\t%3s: 0x%016" PRIx64 " %14" PRId64
         "\t%3s: 0x%016" PRIx64 " %14" PRId64 "\n",
         REG_INFO(1), REG_INFO(2), REG_INFO(4));
  // v1, a1.
  PrintF("%34s\t%3s: 0x%016" PRIx64 "  %14" PRId64 " \t%3s: 0x%016" PRIx64
         "  %14" PRId64 " \n",
         "", REG_INFO(3), REG_INFO(5));
  // a2.
  PrintF("%34s\t%34s\t%3s: 0x%016" PRIx64 "  %14" PRId64 " \n", "", "",
         REG_INFO(6));
  // a3.
  PrintF("%34s\t%34s\t%3s: 0x%016" PRIx64 "  %14" PRId64 " \n", "", "",
         REG_INFO(7));
  PrintF("\n");
  // a4-t3, s0-s7
  for (int i = 0; i < 8; i++) {
    PrintF("%3s: 0x%016" PRIx64 "  %14" PRId64 " \t%3s: 0x%016" PRIx64
           "  %14" PRId64 " \n",
           REG_INFO(8 + i), REG_INFO(16 + i));
  }
  PrintF("\n");
  // t8, k0, LO.
  PrintF("%3s: 0x%016" PRIx64 "  %14" PRId64 " \t%3s: 0x%016" PRIx64
         "  %14" PRId64 " \t%3s: 0x%016" PRIx64 "  %14" PRId64 " \n",
         REG_INFO(24), REG_INFO(26), REG_INFO(32));
  // t9, k1, HI.
  PrintF("%3s: 0x%016" PRIx64 "  %14" PRId64 " \t%3s: 0x%016" PRIx64
         "  %14" PRId64 " \t%3s: 0x%016" PRIx64 "  %14" PRId64 " \n",
         REG_INFO(25), REG_INFO(27), REG_INFO(33));
  // sp, fp, gp.
  PrintF("%3s: 0x%016" PRIx64 "  %14" PRId64 " \t%3s: 0x%016" PRIx64
         "  %14" PRId64 " \t%3s: 0x%016" PRIx64 "  %14" PRId64 " \n",
         REG_INFO(29), REG_INFO(30), REG_INFO(28));
  // pc.
  PrintF("%3s: 0x%016" PRIx64 "  %14" PRId64 " \t%3s: 0x%016" PRIx64
         "  %14" PRId64 " \n",
         REG_INFO(31), REG_INFO(34));

#undef REG_INFO
}

void Loong64Debugger::PrintAllRegsIncludingFPU() {
#define FPU_REG_INFO(n) \
  FPURegisters::Name(n), GetFPURegisterValue(n), GetFPURegisterValueDouble(n)

  PrintAllRegs();

  PrintF("\n\n");
  // f0, f1, f2, ... f31.
  // TODO(plind): consider printing 2 columns for space efficiency.
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(0));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(1));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(2));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(3));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(4));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(5));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(6));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(7));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(8));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(9));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(10));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(11));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(12));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(13));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(14));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(15));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(16));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(17));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(18));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(19));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(20));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(21));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(22));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(23));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(24));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(25));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(26));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(27));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(28));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(29));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(30));
  PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n", FPU_REG_INFO(31));

#undef FPU_REG_INFO
}

void Loong64Debugger::Debug() {
  if (v8_flags.correctness_fuzzer_suppressions) {
    PrintF("Debugger disabled for differential fuzzing.\n");
    return;
  }
  intptr_t last_pc = -1;
  bool done = false;

#define COMMAND_SIZE 63
#define ARG_SIZE 255

#define STR(a) #a
#define XSTR(a) STR(a)

  char cmd[COMMAND_SIZE + 1];
  char arg1[ARG_SIZE + 1];
  char arg2[ARG_SIZE + 1];
  char* argv[3] = {cmd, arg1, arg2};

  // Make sure to have a proper terminating character if reaching the limit.
  cmd[COMMAND_SIZE] = 0;
  arg1[ARG_SIZE] = 0;
  arg2[ARG_SIZE] = 0;

  // Undo all set breakpoints while running in the debugger shell. This will
  // make them invisible to all commands.
  UndoBreakpoints();

  while (!done && (sim_->get_pc() != Simulator::end_sim_pc)) {
    if (last_pc != sim_->get_pc()) {
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      // Use a reasonably large buffer.
      v8::base::EmbeddedVector<char, 256> buffer;
      dasm.InstructionDecode(buffer,
                             reinterpret_cast<uint8_t*>(sim_->get_pc()));
      PrintF("  0x%016" PRIx64 "   %s\n", sim_->get_pc(), buffer.begin());
      last_pc = sim_->get_pc();
    }
    char* line = ReadLine("sim> ");
    if (line == nullptr) {
      break;
    } else {
      char* last_input = sim_->last_debugger_input();
      if (strcmp(line, "\n") == 0 && last_input != nullptr) {
        line = last_input;
      } else {
        // Ownership is transferred to sim_;
        sim_->set_last_debugger_input(line);
      }
      // Use sscanf to parse the individual parts of the command line. At the
      // moment no command expects more than two parameters.
      int argc = SScanF(line,
                        "%" XSTR(COMMAND_SIZE) "s "
                        "%" XSTR(ARG_SIZE) "s "
                        "%" XSTR(ARG_SIZE) "s",
                        cmd, arg1, arg2);
      if ((strcmp(cmd, "si") == 0) || (strcmp(cmd, "stepi") == 0)) {
        Instruction* instr = reinterpret_cast<Instruction*>(sim_->get_pc());
        if (!(instr->IsTrap()) ||
            instr->InstructionBits() == rtCallRedirInstr) {
          sim_->InstructionDecode(
              reinterpret_cast<Instruction*>(sim_->get_pc()));
        } else {
          // Allow si to jump over generated breakpoints.
          PrintF("/!\\ Jumping over generated breakpoint.\n");
          sim_->set_pc(sim_->get_pc() + kInstrSize);
        }
      } else if ((strcmp(cmd, "c") == 0) || (strcmp(cmd, "cont") == 0)) {
        // Execute the one instruction we broke at with breakpoints disabled.
        sim_->InstructionDecode(reinterpret_cast<Instruction*>(sim_->get_pc()));
        // Leave the debugger shell.
        done = true;
      } else if ((strcmp(cmd, "p") == 0) || (strcmp(cmd, "print") == 0)) {
        if (argc == 2) {
          int64_t value;
          double dvalue;
          if (strcmp(arg1, "all") == 0) {
            PrintAllRegs();
          } else if (strcmp(arg1, "allf") == 0) {
            PrintAllRegsIncludingFPU();
          } else {
            int regnum = Registers::Number(arg1);
            int fpuregnum = FPURegisters::Number(arg1);

            if (regnum != kInvalidRegister) {
              value = GetRegisterValue(regnum);
              PrintF("%s: 0x%08" PRIx64 "  %" PRId64 "  \n", arg1, value,
                     value);
            } else if (fpuregnum != kInvalidFPURegister) {
              value = GetFPURegisterValue(fpuregnum);
              dvalue = GetFPURegisterValueDouble(fpuregnum);
              PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n",
                     FPURegisters::Name(fpuregnum), value, dvalue);
            } else {
              PrintF("%s unrecognized\n", arg1);
            }
          }
        } else {
          if (argc == 3) {
            if (strcmp(arg2, "single") == 0) {
              int64_t value;
              float fvalue;
              int fpuregnum = FPURegisters::Number(arg1);

              if (fpuregnum != kInvalidFPURegister) {
                value = GetFPURegisterValue(fpuregnum);
                value &= 0xFFFFFFFFUL;
                fvalue = GetFPURegisterValueFloat(fpuregnum);
                PrintF("%s: 0x%08" PRIx64 "  %11.4e\n", arg1, value, fvalue);
              } else {
                PrintF("%s unrecognized\n", arg1);
              }
            } else {
              PrintF("print <fpu register> single\n");
            }
          } else {
            PrintF("print <register> or print <fpu register> single\n");
          }
        }
      } else if ((strcmp(cmd, "po") == 0) ||
                 (strcmp(cmd, "printobject") == 0)) {
        if (argc == 2) {
          int64_t value;
          StdoutStream os;
          if (GetValue(arg1, &value)) {
            Tagged<Object> obj(value);
            os << arg1 << ": \n";
#ifdef DEBUG
            Print(obj, os);
            os << "\n";
#else
            os << Brief(obj) << "\n";
#endif
          } else {
            os << arg1 << " unrecognized\n";
          }
        } else {
          PrintF("printobject <value>\n");
        }
      } else if (strcmp(cmd, "stack") == 0 || strcmp(cmd, "mem") == 0 ||
                 strcmp(cmd, "dump") == 0) {
        int64_t* cur = nullptr;
        int64_t* end = nullptr;
        int next_arg = 1;

        if (strcmp(cmd, "stack") == 0) {
          cur = reinterpret_cast<int64_t*>(sim_->get_register(Simulator::sp));
        } else {  // Command "mem".
          int64_t value;
          if (!GetValue(arg1, &value)) {
            PrintF("%s unrecognized\n", arg1);
            continue;
          }
          cur = reinterpret_cast<int64_t*>(value);
          next_arg++;
        }

        int64_t words;
        if (argc == next_arg) {
          words = 10;
        } else {
          if (!GetValue(argv[next_arg], &words)) {
            words = 10;
          }
        }
        end = cur + words;

        bool skip_obj_print = (strcmp(cmd, "dump") == 0);
        while (cur < end) {
          PrintF("  0x%012" PRIxPTR " :  0x%016" PRIx64 "  %14" PRId64 " ",
                 reinterpret_cast<intptr_t>(cur), *cur, *cur);
          Tagged<Object> obj(*cur);
          Heap* current_heap = sim_->isolate_->heap();
          if (!skip_obj_print) {
            if (IsSmi(obj) ||
                IsValidHeapObject(current_heap, Cast<HeapObject>(obj))) {
              PrintF(" (");
              if (IsSmi(obj)) {
                PrintF("smi %d", Smi::ToInt(obj));
              } else {
                ShortPrint(obj);
              }
              PrintF(")");
            }
          }
          PrintF("\n");
          cur++;
        }

      } else if ((strcmp(cmd, "disasm") == 0) || (strcmp(cmd, "dpc") == 0) ||
                 (strcmp(cmd, "di") == 0)) {
        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        // Use a reasonably large buffer.
        v8::base::EmbeddedVector<char, 256> buffer;

        uint8_t* cur = nullptr;
        uint8_t* end = nullptr;

        if (argc == 1) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
          end = cur + (10 * kInstrSize);
        } else if (argc == 2) {
          int regnum = Registers::Number(arg1);
          if (regnum != kInvalidRegister || strncmp(arg1, "0x", 2) == 0) {
            // The argument is an address or a register name.
            int64_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(value);
              // Disassemble 10 instructions at <arg1>.
              end = cur + (10 * kInstrSize);
            }
          } else {
            // The argument is the number of instructions.
            int64_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
              // Disassemble <arg1> instructions.
              end = cur + (value * kInstrSize);
            }
          }
        } else {
          int64_t value1;
          int64_t value2;
          if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
            cur = reinterpret_cast<uint8_t*>(value1);
            end = cur + (value2 * kInstrSize);
          }
        }

        while (cur < end) {
          dasm.InstructionDecode(buffer, cur);
          PrintF("  0x%08" PRIxPTR "   %s\n", reinterpret_cast<intptr_t>(cur),
                 buffer.begin());
          cur += kInstrSize;
        }
      } else if (strcmp(cmd, "gdb") == 0) {
        PrintF("relinquishing control to gdb\n");
        v8::base::OS::DebugBreak();
        PrintF("regaining control from gdb\n");
      } else if (strcmp(cmd, "break") == 0) {
        if (argc == 2) {
          int64_t value;
          if (GetValue(arg1, &value)) {
            if (!SetBreakpoint(reinterpret_cast<Instruction*>(value))) {
              PrintF("setting breakpoint failed\n");
            }
          } else {
            PrintF("%s unrecognized\n", arg1);
          }
        } else {
          PrintF("break <address>\n");
        }
      } else if (strcmp(cmd, "del") == 0) {
        if (!DeleteBreakpoint(nullptr)) {
          PrintF("deleting breakpoint failed\n");
        }
      } else if (strcmp(cmd, "flags") == 0) {
        PrintF("No flags on LOONG64 !\n");
      } else if (strcmp(cmd, "stop") == 0) {
        int64_t value;
        intptr_t stop_pc = sim_->get_pc() - 2 * kInstrSize;
        Instruction* stop_instr = reinterpret_cast<Instruction*>(stop_pc);
        Instruction* msg_address =
            reinterpret_cast<Instruction*>(stop_pc + kInstrSize);
        if ((argc == 2) && (strcmp(arg1, "unstop") == 0)) {
          // Remove the current stop.
          if (sim_->IsStopInstruction(stop_instr)) {
            stop_instr->SetInstructionBits(kNopInstr);
            msg_address->SetInstructionBits(kNopInstr);
          } else {
            PrintF("Not at debugger stop.\n");
          }
        } else if (argc == 3) {
          // Print information about all/the specified breakpoint(s).
          if (strcmp(arg1, "info") == 0) {
            if (strcmp(arg2, "all") == 0) {
              PrintF("Stop information:\n");
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->PrintStopInfo(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->PrintStopInfo(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          } else if (strcmp(arg1, "enable") == 0) {
            // Enable all/the specified breakpoint(s).
            if (strcmp(arg2, "all") == 0) {
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->EnableStop(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->EnableStop(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          } else if (strcmp(arg1, "disable") == 0) {
            // Disable all/the specified breakpoint(s).
            if (strcmp(arg2, "all") == 0) {
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->DisableStop(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->DisableStop(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          }
        } else {
          PrintF("Wrong usage. Use help command for more information.\n");
        }
      } else if ((strcmp(cmd, "stat") == 0) || (strcmp(cmd, "st") == 0)) {
        // Print registers and disassemble.
        PrintAllRegs();
        PrintF("\n");

        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        // Use a reasonably large buffer.
        v8::base::EmbeddedVector<char, 256> buffer;

        uint8_t* cur = nullptr;
        uint8_t* end = nullptr;

        if (argc == 1) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
          end = cur + (10 * kInstrSize);
        } else if (argc == 2) {
          int64_t value;
          if (GetValue(arg1, &value)) {
            cur = reinterpret_cast<uint8_t*>(value);
            // no length parameter passed, assume 10 instructions
            end = cur + (10 * kInstrSize);
          }
        } else {
          int64_t value1;
          int64_t value2;
          if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
            cur = reinterpret_cast<uint8_t*>(value1);
            end = cur + (value2 * kInstrSize);
          }
        }

        while (cur < end) {
          dasm.InstructionDecode(buffer, cur);
          PrintF("  0x%08" PRIxPTR "   %s\n", reinterpret_cast<intptr_t>(cur),
                 buffer.begin());
          cur += kInstrSize;
        }
      } else if ((strcmp(cmd, "h") == 0) || (strcmp(cmd, "help") == 0)) {
        PrintF("cont\n");
        PrintF("  continue execution (alias 'c')\n");
        PrintF("stepi\n");
        PrintF("  step one instruction (alias 'si')\n");
        PrintF("print <register>\n");
        PrintF("  print register content (alias 'p')\n");
        PrintF("  use register name 'all' to print all registers\n");
        PrintF("printobject <register>\n");
        PrintF("  print an object from a register (alias 'po')\n");
        PrintF("stack [<words>]\n");
        PrintF("  dump stack content, default dump 10 words)\n");
        PrintF("mem <address> [<words>]\n");
        PrintF("  dump memory content, default dump 10 words)\n");
        PrintF("dump [<words>]\n");
        PrintF(
            "  dump memory content without pretty printing JS objects, default "
            "dump 10 words)\n");
        PrintF("flags\n");
        PrintF("  print flags\n");
        PrintF("disasm [<instructions>]\n");
        PrintF("disasm [<address/register>]\n");
        PrintF("disasm [[<address/register>] <instructions>]\n");
        PrintF("  disassemble code, default is 10 instructions\n");
        PrintF("  from pc (alias 'di')\n");
        PrintF("gdb\n");
        PrintF("  enter gdb\n");
        PrintF("break <address>\n");
        PrintF("  set a break point on the address\n");
        PrintF("del\n");
        PrintF("  delete the breakpoint\n");
        PrintF("stop feature:\n");
        PrintF("  Description:\n");
        PrintF("    Stops are debug instructions inserted by\n");
        PrintF("    the Assembler::stop() function.\n");
        PrintF("    When hitting a stop, the Simulator will\n");
        PrintF("    stop and give control to the Debugger.\n");
        PrintF("    All stop codes are watched:\n");
        PrintF("    - They can be enabled / disabled: the Simulator\n");
        PrintF("       will / won't stop when hitting them.\n");
        PrintF("    - The Simulator keeps track of how many times they \n");
        PrintF("      are met. (See the info command.) Going over a\n");
        PrintF("      disabled stop still increases its counter. \n");
        PrintF("  Commands:\n");
        PrintF("    stop info all/<code> : print infos about number <code>\n");
        PrintF("      or all stop(s).\n");
        PrintF("    stop enable/disable all/<code> : enables / disables\n");
        PrintF("      all or number <code> stop(s)\n");
        PrintF("    stop unstop\n");
        PrintF("      ignore the stop instruction at the current location\n");
        PrintF("      from now on\n");
      } else {
        PrintF("Unknown command: %s\n", cmd);
      }
    }
  }

  // Add all the breakpoints back to stop execution and enter the debugger
  // shell when hit.
  RedoBreakpoints();

#undef COMMAND_SIZE
#undef ARG_SIZE

#undef STR
#undef XSTR
}

bool Simulator::ICacheMatch(void* one, void* two) {
  DCHECK_EQ(reinterpret_cast<intptr_t>(one) & CachePage::kPageMask, 0);
  DCHECK_EQ(reinterpret_cast<intptr_t>(two) & CachePage::kPageMask, 0);
  return one == two;
}

static uint32_t ICacheHash(void* key) {
  return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(key)) >> 2;
}

static bool AllOnOnePage(uintptr_t start, size_t size) {
  intptr_t start_page = (start & ~CachePage::kPageMask);
  intptr_t end_page = ((start + size) & ~CachePage::kPageMask);
  return start_page == end_page;
}

void Simulator::set_last_debugger_input(char* input) {
  DeleteArray(last_debugger_input_);
  last_debugger_input_ = input;
}

void Simulator::SetRedirectInstruction(Instruction* instruction) {
  instruction->SetInstructionBits(rtCallRedirInstr);
}

void Simulator::FlushICache(base::CustomMatcherHashMap* i_cache,
                            void* start_addr, size_t size) {
  int64_t start = reinterpret_cast<int64_t>(start_addr);
  int64_t intra_line = (start & CachePage::kLineMask);
  start -= intra_line;
  size += intra_line;
  size = ((size - 1) | CachePage::kLineMask) + 1;
  int offset = (start & CachePage::kPageMask);
  while (!AllOnOnePage(start, size - 1)) {
    int bytes_to_flush = CachePage::kPageSize - offset;
    FlushOnePage(i_cache, start, bytes_to_flush);
    start += bytes_to_flush;
    size -= bytes_to_flush;
    DCHECK_EQ((int64_t)0, start & CachePage::kPageMask);
    offset = 0;
  }
  if (size != 0) {
    FlushOnePage(i_cache, start, size);
  }
}

CachePage* Simulator::GetCachePage(base::CustomMatcherHashMap* i_cache,
                                   void* page) {
  base::HashMap::Entry* entry = i_cache->LookupOrInsert(page, ICacheHash(page));
  if (entry->value == nullptr) {
    CachePage* new_page = new CachePage();
    entry->value = new_page;
  }
  return reinterpret_cast<CachePage*>(entry->value);
}

// Flush from start up to and not including start + size.
void Simulator::FlushOnePage(base::CustomMatcherHashMap* i_cache,
                             intptr_t start, size_t size) {
  DCHECK_LE(size, CachePage::kPageSize);
  DCHECK(AllOnOnePage(start, size - 1));
  DCHECK_EQ(start & CachePage::kLineMask, 0);
  DCHECK_EQ(size & CachePage::kLineMask, 0);
  void* page = reinterpret_cast<void*>(start & (~CachePage::kPageMask));
  int offset = (start & CachePage::kPageMask);
  CachePage* cache_page = GetCachePage(i_cache, page);
  char* valid_bytemap = cache_page->ValidityByte(offset);
  memset(valid_bytemap, CachePage::LINE_INVALID, size >> CachePage::kLineShift);
}

void Simulator::CheckICache(base::CustomMatcherHashMap* i_cache,
                            Instruction* instr) {
  int64_t address = reinterpret_cast<int64_t>(instr);
  void* page = reinterpret_cast<void*>(address & (~CachePage::kPageMask));
  void* line = reinterpret_cast<void*>(address & (~CachePage::kLineMask));
  int offset = (address & CachePage::kPageMask);
  CachePage* cache_page = GetCachePage(i_cache, page);
  char* cache_valid_byte = cache_page->ValidityByte(offset);
  bool cache_hit = (*cache_valid_byte == CachePage::LINE_VALID);
  char* cached_line = cache_page->CachedData(offset & ~CachePage::kLineMask);
  if (cache_hit) {
    // Check that the data in memory matches the contents of the I-cache.
    CHECK_EQ(0, memcmp(reinterpret_cast<void*>(instr),
                       cache_page->CachedData(offset), kInstrSize));
  } else {
    // Cache miss.  Load memory into the cache.
    memcpy(cached_line, line, CachePage::kLineLength);
    *cache_valid_byte = CachePage::LINE_VALID;
  }
}

Simulator::Simulator(Isolate* isolate) : isolate_(isolate) {
  // Set up simulator support first. Some of this information is needed to
  // setup the architecture state.
  size_t stack_size = AllocatedStackSize();
  stack_ = reinterpret_cast<uintptr_t>(new uint8_t[stack_size]);
  stack_limit_ = stack_ + kStackProtectionSize;
  pc_modified_ = false;
  icount_ = 0;
  break_count_ = 0;
  break_pc_ = nullptr;
  break_instr_ = 0;

  // Set up architecture state.
  // All registers are initialized to zero to start with.
  for (int i = 0; i < kNumSimuRegisters; i++) {
    registers_[i] = 0;
  }
  for (int i = 0; i < kNumFPURegisters; i++) {
    FPUregisters_[i] = 0;
  }
  for (int i = 0; i < kNumCFRegisters; i++) {
    CFregisters_[i] = 0;
  }

  FCSR_ = 0;

  // The sp is initialized to point to the bottom (high address) of the
  // allocated stack area. To be safe in potential stack underflows we leave
  // some buffer below.
  registers_[sp] = stack_ + stack_size - kStackProtectionSize;
  // The ra and pc are initialized to a known bad value that will cause an
  // access violation if the simulator ever tries to execute it.
  registers_[pc] = bad_ra;
  registers_[ra] = bad_ra;

  last_debugger_input_ = nullptr;
}

Simulator::~Simulator() {
  GlobalMonitor::Get()->RemoveLinkedAddress(&global_monitor_thread_);
  delete[] reinterpret_cast<uint8_t*>(stack_);
}

// Get the active Simulator for the current thread.
Simulator* Simulator::current(Isolate* isolate) {
  v8::internal::Isolate::PerIsolateThreadData* isolate_data =
      isolate->FindOrAllocatePerThreadDataForThisThread();
  DCHECK_NOT_NULL(isolate_data);

  Simulator* sim = isolate_data->simulator();
  if (sim == nullptr) {
    // TODO(146): delete the simulator object when a thread/isolate goes away.
    sim = new Simulator(isolate);
    isolate_data->set_simulator(sim);
  }
  return sim;
}

#define FloatPoint_Covert_F32(func)                  \
  float Simulator::func(float value) {               \
    float result = std::func(value);                 \
    if (std::isnan(result)) {                        \
      uint32_t q_nan, nan;                           \
      nan = *reinterpret_cast<uint32_t*>(&result);   \
      q_nan = nan | 0x400000;                        \
      *reinterpret_cast<uint32_t*>(&result) = q_nan; \
    }                                                \
    return result;                                   \
  }
#define FloatPoint_Covert_F64(func)                  \
  FloatPoint_Covert_F32(func)                        \
  double Simulator::func(double value) {             \
    double result = std::func(value);                \
    if (std::isnan(result)) {                        \
      uint64_t q_nan, nan;                           \
      nan = *reinterpret_cast<uint64_t*>(&value);    \
      q_nan = nan | 0x8000000000000;                 \
      *reinterpret_cast<uint64_t*>(&result) = q_nan; \
    }                                                \
    return result;                                   \
  }

FloatPoint_Covert_F64(ceil)
FloatPoint_Covert_F64(floor)
FloatPoint_Covert_F64(trunc)
#undef FloatPoint_Covert_F32
#undef FloatPoint_Covert_F64

// Sets the register in the architecture state. It will also deal with updating
// Simulator internal state for special registers such as PC.
void Simulator::set_register(int reg, int64_t value) {
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));
  if (reg == pc) {
    pc_modified_ = true;
  }

  // Zero register always holds 0.
  registers_[reg] = (reg == 0) ? 0 : value;
}

void Simulator::set_dw_register(int reg, const int* dbl) {
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));
  registers_[reg] = dbl[1];
  registers_[reg] = registers_[reg] << 32;
  registers_[reg] += dbl[0];
}

void Simulator::set_fpu_register(int fpureg, int64_t value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  FPUregisters_[fpureg] = value;
}

void Simulator::set_fpu_register_word(int fpureg, int32_t value) {
  // Set ONLY lower 32-bits, leaving upper bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* pword;
  pword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg]);

  *pword = value;
}

void Simulator::set_fpu_register_hi_word(int fpureg, int32_t value) {
  // Set ONLY upper 32-bits, leaving lower bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* phiword;
  phiword = (reinterpret_cast<int32_t*>(&FPUregisters_[fpureg])) + 1;

  *phiword = value;
}

void Simulator::set_fpu_register_float(int fpureg, float value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  memcpy(&FPUregisters_[fpureg], &value, sizeof(value));
}

void Simulator::set_fpu_register_double(int fpureg, double value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  memcpy(&FPUregisters_[fpureg], &value, sizeof(value));
}

void Simulator::set_cf_register(int cfreg, bool value) {
  DCHECK((cfreg >= 0) && (cfreg < kNumCFRegisters));
  CFregisters_[cfreg] = value;
}

// Get the register from the architecture state. This function does handle
// the special case of accessing the PC register.
int64_t Simulator::get_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));
  if (reg == 0)
    return 0;
  else
    return registers_[reg];
}

double Simulator::get_double_from_register_pair(int reg) {
  // TODO(plind): bad ABI stuff, refactor or remove.
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));

  double dm_val = 0.0;
  // Read the bits from the unsigned integer register_[] array
  // into the double precision floating point value and return it.
  char buffer[sizeof(registers_[0])];
  memcpy(buffer, &registers_[reg], sizeof(registers_[0]));
  memcpy(&dm_val, buffer, sizeof(registers_[0]));
  return (dm_val);
}

int64_t Simulator::get_fpu_register(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return FPUregisters_[fpureg];
}

int32_t Simulator::get_fpu_register_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>(FPUregisters_[fpureg] & 0xFFFFFFFF);
}

int32_t Simulator::get_fpu_register_signed_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>(FPUregisters_[fpureg] & 0xFFFFFFFF);
}

int32_t Simulator::get_fpu_register_hi_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>((FPUregisters_[fpureg] >> 32) & 0xFFFFFFFF);
}

float Simulator::get_fpu_register_float(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return base::bit_cast<float>(get_fpu_register_word(fpureg));
}

double Simulator::get_fpu_register_double(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return base::bit_cast<double>(FPUregisters_[fpureg]);
}

bool Simulator::get_cf_register(int cfreg) const {
  DCHECK((cfreg >= 0) && (cfreg < kNumCFRegisters));
  return CFregisters_[cfreg];
}

// Runtime FP routines take up to two double arguments and zero
// or one integer arguments. All are constructed here,
// from a0-a3 or fa0 and fa1 (n64).
void Simulator::GetFpArgs(double* x, double* y, int32_t* z) {
  const int fparg2 = f1;
  *x = get_fpu_register_double(f0);
  *y = get_fpu_register_double(fparg2);
  *z = static_cast<int32_t>(get_register(a2));
}

// The return value is either in v0/v1 or f0.
void Simulator::SetFpResult(const double& result) {
  set_fpu_register_double(0, result);
}

// Helper functions for setting and testing the FCSR register's bits.
void Simulator::set_fcsr_bit(uint32_t cc, bool value) {
  if (value) {
    FCSR_ |= (1 << cc);
  } else {
    FCSR_ &= ~(1 << cc);
  }
}

bool Simulator::test_fcsr_bit(uint32_t cc) { return FCSR_ & (1 << cc); }

void Simulator::set_fcsr_rounding_mode(FPURoundingMode mode) {
  FCSR_ |= mode & kFPURoundingModeMask;
}

unsigned int Simulator::get_fcsr_rounding_mode() {
  return FCSR_ & kFPURoundingModeMask;
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round_error(double original, double rounded) {
  bool ret = false;
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < DBL_MIN && rounded > -DBL_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded > max_int32 || rounded < min_int32) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round64_error(double original, double rounded) {
  bool ret = false;
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < DBL_MIN && rounded > -DBL_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded >= max_int64 || rounded < min_int64) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round_error(float original, float rounded) {
  bool ret = false;
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < FLT_MIN && rounded > -FLT_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded > max_int32 || rounded < min_int32) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

void Simulator::set_fpu_register_word_invalid_result(float original,
                                                     float rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register_word(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result(float original, float rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result64(float original,
                                                  float rounded) {
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded >= max_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResult);
  } else if (rounded < min_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_word_invalid_result(double original,
                                                     double rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register_word(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result(double original,
                                                double rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result64(double original,
                                                  double rounded) {
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded >= max_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResult);
  } else if (rounded < min_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round64_error(float original, float rounded) {
  bool ret = false;
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < FLT_MIN && rounded > -FLT_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded >= max_int64 || rounded < min_int64) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

// For ftint instructions only
void Simulator::round_according_to_fcsr(double toRound, double* rounded,
                                        int32_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  // switch ((FCSR_ >> 8) & 3) {
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int32_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
  }
}

void Simulator::round64_according_to_fcsr(double toRound, double* rounded,
                                          int64_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or.
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int64_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
  }
}

void Simulator::round_according_to_fcsr(float toRound, float* rounded,
                                        int32_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int32_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.f;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
  }
}

void Simulator::round64_according_to_fcsr(float toRound, float* rounded,
                                          int64_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or.
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int64_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.f;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
  }
}

// Raw access to the PC register.
void Simulator::set_pc(int64_t value) {
  pc_modified_ = true;
  registers_[pc] = value;
}

bool Simulator::has_bad_pc() const {
  return ((registers_[pc] == bad_ra) || (registers_[pc] == end_sim_pc));
}

// Raw access to the PC register without the special adjustment when reading.
int64_t Simulator::get_pc() const { return registers_[pc]; }

// TODO(plind): refactor this messy debug code when we do unaligned access.
void Simulator::DieOrDebug() {
  if ((1)) {  // Flag for this was removed.
    Loong64Debugger dbg(this);
    dbg.Debug();
  } else {
    base::OS::Abort();
  }
}

void Simulator::TraceRegWr(int64_t value, TraceType t) {
  if (v8_flags.trace_sim) {
    union {
      int64_t fmt_int64;
      int32_t fmt_int32[2];
      float fmt_float[2];
      double fmt_double;
    } v;
    v.fmt_int64 = value;

    switch (t) {
      case WORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    int32:%" PRId32
                       " uint32:%" PRIu32,
                       v.fmt_int64, icount_, v.fmt_int32[0], v.fmt_int32[0]);
        break;
      case DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    int64:%" PRId64
                       " uint64:%" PRIu64,
                       value, icount_, value, value);
        break;
      case FLOAT:
        base::SNPrintF(trace_buf_, "%016" PRIx64 "    (%" PRId64 ")    flt:%e",
                       v.fmt_int64, icount_, v.fmt_float[0]);
        break;
      case DOUBLE:
        base::SNPrintF(trace_buf_, "%016" PRIx64 "    (%" PRId64 ")    dbl:%e",
                       v.fmt_int64, icount_, v.fmt_double);
        break;
      case FLOAT_DOUBLE:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    flt:%e dbl:%e",
                       v.fmt_int64, icount_, v.fmt_float[0], v.fmt_double);
        break;
      case WORD_DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    int32:%" PRId32
                       " uint32:%" PRIu32 " int64:%" PRId64 " uint64:%" PRIu64,
                       v.fmt_int64, icount_, v.fmt_int32[0], v.fmt_int32[0],
                       v.fmt_int64, v.fmt_int64);
        break;
      default:
        UNREACHABLE();
    }
  }
}

// TODO(plind): consider making icount_ printing a flag option.
void Simulator::TraceMemRd(int64_t addr, int64_t value, TraceType t) {
  if (v8_flags.trace_sim) {
    union {
      int64_t fmt_int64;
      int32_t fmt_int32[2];
      float fmt_float[2];
      double fmt_double;
    } v;
    v.fmt_int64 = value;

    switch (t) {
      case WORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    int32:%" PRId32 " uint32:%" PRIu32,
                       v.fmt_int64, addr, icount_, v.fmt_int32[0],
                       v.fmt_int32[0]);
        break;
      case DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    int64:%" PRId64 " uint64:%" PRIu64,
                       value, addr, icount_, value, value);
        break;
      case FLOAT:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    flt:%e",
                       v.fmt_int64, addr, icount_, v.fmt_float[0]);
        break;
      case DOUBLE:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    dbl:%e",
                       v.fmt_int64, addr, icount_, v.fmt_double);
        break;
      case FLOAT_DOUBLE:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    flt:%e dbl:%e",
                       v.fmt_int64, addr, icount_, v.fmt_float[0],
                       v.fmt_double);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void Simulator::TraceMemWr(int64_t addr, int64_t value, TraceType t) {
  if (v8_flags.trace_sim) {
    switch (t) {
      case BYTE:
        base::SNPrintF(trace_buf_,
                       "               %02" PRIx8 " --> [%016" PRIx64
                       "]    (%" PRId64 ")",
                       static_cast<uint8_t>(value), addr, icount_);
        break;
      case HALF:
        base::SNPrintF(trace_buf_,
                       "            %04" PRIx16 " --> [%016" PRIx64
                       "]    (%" PRId64 ")",
                       static_cast<uint16_t>(value), addr, icount_);
        break;
      case WORD:
        base::SNPrintF(trace_buf_,
                       "        %08" PRIx32 " --> [%016" PRIx64 "]    (%" PRId64
                       ")",
                       static_cast<uint32_t>(value), addr, icount_);
        break;
      case DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  --> [%016" PRIx64 "]    (%" PRId64 " )",
                       value, addr, icount_);
        break;
      default:
        UNREACHABLE();
    }
  }
}

template <typename T>
void Simulator::TraceMemRd(int64_t addr, T value) {
  if (v8_flags.trace_sim) {
    switch (sizeof(T)) {
      case 1:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx8 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int8:%" PRId8 " uint8:%" PRIu8,
                       static_cast<uint8_t>(value), addr, icount_,
                       static_cast<int8_t>(value), static_cast<uint8_t>(value));
        break;
      case 2:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx16 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int16:%" PRId16 " uint16:%" PRIu16,
                       static_cast<uint16_t>(value), addr, icount_,
                       static_cast<int16_t>(value),
                       static_cast<uint16_t>(value));
        break;
      case 4:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx32 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int32:%" PRId32 " uint32:%" PRIu32,
                       static_cast<uint32_t>(value), addr, icount_,
                       static_cast<int32_t>(value),
                       static_cast<uint32_t>(value));
        break;
      case 8:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx64 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int64:%" PRId64 " uint64:%" PRIu64,
                       static_cast<uint64_t>(value), addr, icount_,
                       static_cast<int64_t>(value),
                       static_cast<uint64_t>(value));
        break;
      default:
        UNREACHABLE();
    }
  }
}

template <typename T>
void Simulator::TraceMemWr(int64_t addr, T value) {
  if (v8_flags.trace_sim) {
    switch (sizeof(T)) {
      case 1:
        base::SNPrintF(trace_buf_,
                       "      %02" PRIx8 " --> [%08" PRIx64 "]    (%" PRIu64
                       ")",
                       static_cast<uint8_t>(value), addr, icount_);
        break;
      case 2:
        base::SNPrintF(trace_buf_,
                       "    %04" PRIx16 " --> [%08" PRIx64 "]    (%" PRIu64 ")",
                       static_cast<uint16_t>(value), addr, icount_);
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

bool Simulator::ProbeMemory(uintptr_t address, uintptr_t access_size) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  uintptr_t last_accessed_byte = address + access_size - 1;
  uintptr_t current_pc = registers_[pc];
  uintptr_t landing_pad =
      trap_handler::ProbeMemory(last_accessed_byte, current_pc);
  if (!landing_pad) return true;
  set_pc(landing_pad);
  set_register(kWasmTrapHandlerFaultAddressRegister.code(), current_pc);
  return false;
#else
  return true;
#endif
}

int32_t Simulator::ReadW(int64_t addr, Instruction* instr, TraceType t) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyLoad();
    int32_t* ptr = reinterpret_cast<int32_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr), t);
    return *ptr;
  }
}

uint32_t Simulator::ReadWU(int64_t addr, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyLoad();
    uint32_t* ptr = reinterpret_cast<uint32_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr), WORD);
    return *ptr;
  }
}

void Simulator::WriteW(int64_t addr, int32_t value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, WORD);
    int* ptr = reinterpret_cast<int*>(addr);
    *ptr = value;
    return;
  }
}

void Simulator::WriteConditionalW(int64_t addr, int32_t value,
                                  Instruction* instr, int32_t* done) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  if ((addr & 0x3) == 0) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (local_monitor_.NotifyStoreConditional(addr, TransactionSize::Word) &&
        GlobalMonitor::Get()->NotifyStoreConditional_Locked(
            addr, &global_monitor_thread_)) {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
      TraceMemWr(addr, value, WORD);
      int* ptr = reinterpret_cast<int*>(addr);
      *ptr = value;
      *done = 1;
    } else {
      *done = 0;
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

  {
    local_monitor_.NotifyLoad();
    int64_t* ptr = reinterpret_cast<int64_t*>(addr);
    TraceMemRd(addr, *ptr);
    return *ptr;
  }
}

void Simulator::Write2W(int64_t addr, int64_t value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, DWORD);
    int64_t* ptr = reinterpret_cast<int64_t*>(addr);
    *ptr = value;
    return;
  }
}

void Simulator::WriteConditional2W(int64_t addr, int64_t value,
                                   Instruction* instr, int32_t* done) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  if ((addr & kPointerAlignmentMask) == 0) {
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
      *done = 1;
    } else {
      *done = 0;
    }
    return;
  }
  PrintF("Unaligned write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

double Simulator::ReadD(int64_t addr, Instruction* instr) {
  local_monitor_.NotifyLoad();
  double* ptr = reinterpret_cast<double*>(addr);
  return *ptr;
}

void Simulator::WriteD(int64_t addr, double value, Instruction* instr) {
  local_monitor_.NotifyStore();
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
  double* ptr = reinterpret_cast<double*>(addr);
  *ptr = value;
  return;
}

uint16_t Simulator::ReadHU(int64_t addr, Instruction* instr) {
  local_monitor_.NotifyLoad();
  uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
  TraceMemRd(addr, static_cast<int64_t>(*ptr));
  return *ptr;
}

int16_t Simulator::ReadH(int64_t addr, Instruction* instr) {
  local_monitor_.NotifyLoad();
  int16_t* ptr = reinterpret_cast<int16_t*>(addr);
  TraceMemRd(addr, static_cast<int64_t>(*ptr));
  return *p
```