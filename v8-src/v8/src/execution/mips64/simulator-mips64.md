Response: The user wants to understand the functionality of the C++ code provided. The code is part of the V8 JavaScript engine and is specific to the MIPS64 architecture. The file name `simulator-mips64.cc` suggests it's a simulator for this architecture.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Functionality:** The file name `simulator-mips64.cc` strongly indicates that this code implements a simulator for the MIPS64 architecture. This means it aims to mimic the behavior of a real MIPS64 processor.

2. **Look for Key Classes and Structures:**  The code defines a `Simulator` class and a nested `MipsDebugger` class. These are central to the simulation process. The `Simulator` likely manages the simulated processor state (registers, memory, etc.), and the `MipsDebugger` provides debugging capabilities.

3. **Analyze the `Simulator` Class:**  The `Simulator` class has methods for:
    * Setting and getting register values (`set_register`, `get_register`).
    * Handling FPU registers (`set_fpu_register`, `get_fpu_register`).
    * Managing the instruction cache (`FlushICache`, `CheckICache`).
    * Interacting with a debugger (`set_last_debugger_input`).
    * Managing floating-point control and status registers (FCSR).
    * Implementing floating-point rounding logic.
    * Tracing execution (various `Trace` methods).

4. **Analyze the `MipsDebugger` Class:** The `MipsDebugger` class provides debugging features like:
    * Stepping through instructions (`Stop`, `Debug`).
    * Printing register values (`PrintAllRegs`, `PrintAllRegsIncludingFPU`).
    * Setting and deleting breakpoints (`SetBreakpoint`, `DeleteBreakpoint`).
    * Disassembling code.
    * Interacting with the user through a command-line interface.

5. **Connect to JavaScript:**  V8 is a JavaScript engine. The simulator plays a crucial role when the engine needs to execute JavaScript code on an architecture different from the one it's running on. This is often the case during development, testing, or when running on platforms where a native JIT compiler hasn't been fully implemented.

6. **Provide a JavaScript Example:** To illustrate the connection, a simple JavaScript example that would involve architecture-specific operations (like bitwise operations or floating-point calculations) is a good choice. The simulator would be used by V8 to execute this code if the underlying hardware were MIPS64.

7. **Structure the Summary:** Organize the findings into a clear and concise summary. Start with the primary function, then detail the key classes and their roles, and finally, explain the relationship to JavaScript with an example.

8. **Review and Refine:** Ensure the summary is accurate and easy to understand. For instance, initially, I might just say "manages registers," but specifying "both general-purpose and floating-point registers" is more informative. Similarly, explaining *why* a simulator is needed in the context of JavaScript execution adds valuable context. Adding that it's used when a native JIT isn't available makes the purpose clearer.
这个C++源代码文件是V8 JavaScript引擎中针对 **MIPS64架构的指令模拟器 (Simulator)** 的一部分。它的主要功能是：

**模拟 MIPS64 处理器的行为，用于执行为 MIPS64 架构编译的代码。**

更具体地说，这个文件实现了 `Simulator` 类，该类负责：

* **维护模拟的处理器状态：** 包括通用寄存器、浮点寄存器、程序计数器 (PC)、以及浮点控制和状态寄存器 (FCSR) 等。
* **指令解码和执行：**  尽管这部分代码本身没有直接实现所有 MIPS64 指令的解码和执行逻辑（这通常在其他文件中完成），但它提供了执行指令的框架和辅助功能，例如从内存中获取指令，并调用相应的模拟函数。
* **内存访问模拟：**  提供对模拟内存的读写操作。
* **指令缓存模拟：**  模拟指令缓存的行为，用于提高模拟效率。
* **调试支持：**  包含一个 `MipsDebugger` 类，允许在模拟执行过程中进行断点设置、单步执行、查看寄存器和内存等操作。
* **浮点运算支持：**  模拟 MIPS64 的浮点运算，包括处理浮点舍入模式和异常。
* **跟踪和日志记录：** 提供跟踪指令执行和内存访问的功能，用于调试和分析。

**与 JavaScript 的关系：**

V8 JavaScript 引擎使用指令模拟器来执行 JavaScript 代码，特别是当目标平台是 MIPS64 架构，并且没有可用的即时编译器 (JIT) 或在某些调试场景下。

当 V8 需要在 MIPS64 平台上执行 JavaScript 代码时，它会将 JavaScript 代码编译成 MIPS64 的机器码。  如果是在真实的 MIPS64 硬件上运行，这些机器码会被直接执行。  但是，如果在其他架构的机器上运行，或者为了调试目的，V8 会使用这个模拟器来一步一步地执行这些 MIPS64 指令，从而达到执行 JavaScript 代码的目的。

**JavaScript 例子：**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 在 MIPS64 架构上执行这段代码时，`add(5, 10)` 这个操作会被编译成一系列 MIPS64 指令。  如果使用了模拟器，那么 `simulator-mips64.cc` 文件中的代码将会模拟这些 MIPS64 指令的执行过程，例如：

1. **加载常量到寄存器：** 模拟将数字 `5` 和 `10` 加载到 MIPS64 的寄存器中。例如，可能涉及到 `LDI` (Load Immediate) 指令的模拟。
2. **执行加法运算：** 模拟 MIPS64 的加法指令，例如 `ADD` 或 `ADDU`，将两个寄存器中的值相加，并将结果存储到另一个寄存器中。
3. **返回值：** 模拟将结果寄存器中的值移动到用于返回值的寄存器（例如 `v0`）。
4. **函数调用：** 如果 `console.log` 是一个需要模拟的运行时函数，模拟器会处理函数调用和参数传递。

**总结：**

这个 `simulator-mips64.cc` 文件是 V8 引擎中 MIPS64 架构的软件模拟器，它允许 V8 在非 MIPS64 平台上执行为 MIPS64 编译的 JavaScript 代码，并提供调试和分析功能。 它通过模拟 MIPS64 处理器的寄存器、指令执行流程和内存访问来实现这一目标。

Prompt: 
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/mips64/simulator-mips64.h"

// Only build the simulator if not compiling for real MIPS hardware.
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
#include "src/codegen/macro-assembler.h"
#include "src/codegen/mips64/constants-mips64.h"
#include "src/diagnostics/disasm.h"
#include "src/heap/combined-heap.h"
#include "src/runtime/runtime-utils.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(Simulator::GlobalMonitor,
                                Simulator::GlobalMonitor::Get)

// Util functions.
inline bool HaveSameSign(int64_t a, int64_t b) { return ((a ^ b) >= 0); }

uint32_t get_fcsr_condition_bit(uint32_t cc) {
  if (cc == 0) {
    return 23;
  } else {
    return 24 + cc;
  }
}

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent was through
// ::v8::internal::OS in the same way as base::SNPrintF is that the Windows C
// Run-Time Library does not provide vsscanf.
#define SScanF sscanf

// The MipsDebugger class is used by the simulator while debugging simulated
// code.
class MipsDebugger {
 public:
  explicit MipsDebugger(Simulator* sim) : sim_(sim) {}

  void Stop(Instruction* instr);
  void Debug();
  // Print all registers with a nice formatting.
  void PrintAllRegs();
  void PrintAllRegsIncludingFPU();

 private:
  // We set the breakpoint code to 0xFFFFF to easily recognize it.
  static const Instr kBreakpointInstr = SPECIAL | BREAK | 0xFFFFF << 6;
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

void MipsDebugger::Stop(Instruction* instr) {
  // Get the stop code.
  uint32_t code = instr->Bits(25, 6);
  PrintF("Simulator hit (%u)\n", code);
  Debug();
}

int64_t MipsDebugger::GetRegisterValue(int regnum) {
  if (regnum == kNumSimuRegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_register(regnum);
  }
}

int64_t MipsDebugger::GetFPURegisterValue(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register(regnum);
  }
}

float MipsDebugger::GetFPURegisterValueFloat(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_float(regnum);
  }
}

double MipsDebugger::GetFPURegisterValueDouble(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_double(regnum);
  }
}

bool MipsDebugger::GetValue(const char* desc, int64_t* value) {
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

bool MipsDebugger::SetBreakpoint(Instruction* breakpc) {
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

bool MipsDebugger::DeleteBreakpoint(Instruction* breakpc) {
  if (sim_->break_pc_ != nullptr) {
    sim_->break_pc_->SetInstructionBits(sim_->break_instr_);
  }

  sim_->break_pc_ = nullptr;
  sim_->break_instr_ = 0;
  return true;
}

void MipsDebugger::UndoBreakpoints() {
  if (sim_->break_pc_ != nullptr) {
    sim_->break_pc_->SetInstructionBits(sim_->break_instr_);
  }
}

void MipsDebugger::RedoBreakpoints() {
  if (sim_->break_pc_ != nullptr) {
    sim_->break_pc_->SetInstructionBits(kBreakpointInstr);
  }
}

void MipsDebugger::PrintAllRegs() {
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

void MipsDebugger::PrintAllRegsIncludingFPU() {
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

void MipsDebugger::Debug() {
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
        PrintF("No flags on MIPS !\n");
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
    FPUregisters_[2 * i] = 0;
    FPUregisters_[2 * i + 1] = 0;  // upper part for MSA ASE
  }

  if (kArchVariant == kMips64r6) {
    FCSR_ = kFCSRNaN2008FlagMask;
    MSACSR_ = 0;
  } else {
    FCSR_ = 0;
  }

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
  FPUregisters_[fpureg * 2] = value;
}

void Simulator::set_fpu_register_word(int fpureg, int32_t value) {
  // Set ONLY lower 32-bits, leaving upper bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* pword;
  if (kArchEndian == kLittle) {
    pword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg * 2]);
  } else {
    pword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg * 2]) + 1;
  }
  *pword = value;
}

void Simulator::set_fpu_register_hi_word(int fpureg, int32_t value) {
  // Set ONLY upper 32-bits, leaving lower bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* phiword;
  if (kArchEndian == kLittle) {
    phiword = (reinterpret_cast<int32_t*>(&FPUregisters_[fpureg * 2])) + 1;
  } else {
    phiword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg * 2]);
  }
  *phiword = value;
}

void Simulator::set_fpu_register_float(int fpureg, float value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  memcpy(&FPUregisters_[fpureg * 2], &value, sizeof(value));
}

void Simulator::set_fpu_register_double(int fpureg, double value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  memcpy(&FPUregisters_[fpureg * 2], &value, sizeof(value));
}

// Get the register from the architecture state. This function does handle
// the special case of accessing the PC register.
int64_t Simulator::get_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));
  if (reg == 0)
    return 0;
  else
    return registers_[reg] + ((reg == pc) ? Instruction::kPCReadOffset : 0);
}

double Simulator::get_double_from_register_pair(int reg) {
  // TODO(plind): bad ABI stuff, refactor or remove.
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters) && ((reg % 2) == 0));

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
  return FPUregisters_[fpureg * 2];
}

int32_t Simulator::get_fpu_register_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>(FPUregisters_[fpureg * 2] & 0xFFFFFFFF);
}

int32_t Simulator::get_fpu_register_signed_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>(FPUregisters_[fpureg * 2] & 0xFFFFFFFF);
}

int32_t Simulator::get_fpu_register_hi_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>((FPUregisters_[fpureg * 2] >> 32) & 0xFFFFFFFF);
}

float Simulator::get_fpu_register_float(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return base::bit_cast<float>(get_fpu_register_word(fpureg));
}

double Simulator::get_fpu_register_double(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return base::bit_cast<double>(FPUregisters_[fpureg * 2]);
}

template <typename T>
void Simulator::get_msa_register(int wreg, T* value) {
  DCHECK((wreg >= 0) && (wreg < kNumMSARegisters));
  memcpy(value, FPUregisters_ + wreg * 2, kSimd128Size);
}

template <typename T>
void Simulator::set_msa_register(int wreg, const T* value) {
  DCHECK((wreg >= 0) && (wreg < kNumMSARegisters));
  memcpy(FPUregisters_ + wreg * 2, value, kSimd128Size);
}

// Runtime FP routines take up to two double arguments and zero
// or one integer arguments. All are constructed here,
// from a0-a3 or f12 and f13 (n64), or f14 (O32).
void Simulator::GetFpArgs(double* x, double* y, int32_t* z) {
  if (!IsMipsSoftFloatABI) {
    const int fparg2 = 13;
    *x = get_fpu_register_double(12);
    *y = get_fpu_register_double(fparg2);
    *z = static_cast<int32_t>(get_register(a2));
  } else {
    // TODO(plind): bad ABI stuff, refactor or remove.
    // We use a char buffer to get around the strict-aliasing rules which
    // otherwise allow the compiler to optimize away the copy.
    char buffer[sizeof(*x)];
    int32_t* reg_buffer = reinterpret_cast<int32_t*>(buffer);

    // Registers a0 and a1 -> x.
    reg_buffer[0] = get_register(a0);
    reg_buffer[1] = get_register(a1);
    memcpy(x, buffer, sizeof(buffer));
    // Registers a2 and a3 -> y.
    reg_buffer[0] = get_register(a2);
    reg_buffer[1] = get_register(a3);
    memcpy(y, buffer, sizeof(buffer));
    // Register 2 -> z.
    reg_buffer[0] = get_register(a2);
    memcpy(z, buffer, sizeof(*z));
  }
}

// The return value is either in v0/v1 or f0.
void Simulator::SetFpResult(const double& result) {
  if (!IsMipsSoftFloatABI) {
    set_fpu_register_double(0, result);
  } else {
    char buffer[2 * sizeof(registers_[0])];
    int64_t* reg_buffer = reinterpret_cast<int64_t*>(buffer);
    memcpy(buffer, &result, sizeof(buffer));
    // Copy result to v0 and v1.
    set_register(v0, reg_buffer[0]);
    set_register(v1, reg_buffer[1]);
  }
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

void Simulator::clear_fcsr_cause() {
  FCSR_ &= ~kFCSRCauseMask;
}

void Simulator::set_fcsr_rounding_mode(FPURoundingMode mode) {
  FCSR_ |= mode & kFPURoundingModeMask;
}

void Simulator::set_msacsr_rounding_mode(FPURoundingMode mode) {
  MSACSR_ |= mode & kFPURoundingModeMask;
}

unsigned int Simulator::get_fcsr_rounding_mode() {
  return FCSR_ & kFPURoundingModeMask;
}

unsigned int Simulator::get_msacsr_rounding_mode() {
  return MSACSR_ & kFPURoundingModeMask;
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round_error(double original, double rounded) {
  bool ret = false;
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();

  clear_fcsr_cause();

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactFlagBit, true);
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < DBL_MIN && rounded > -DBL_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowFlagBit, true);
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded > max_int32 || rounded < min_int32) {
    set_fcsr_bit(kFCSROverflowFlagBit, true);
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
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

  clear_fcsr_cause();

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactFlagBit, true);
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < DBL_MIN && rounded > -DBL_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowFlagBit, true);
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded >= max_int64 || rounded < min_int64) {
    set_fcsr_bit(kFCSROverflowFlagBit, true);
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
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

  clear_fcsr_cause();

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactFlagBit, true);
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < FLT_MIN && rounded > -FLT_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowFlagBit, true);
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded > max_int32 || rounded < min_int32) {
    set_fcsr_bit(kFCSROverflowFlagBit, true);
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

void Simulator::set_fpu_register_word_invalid_result(float original,
                                                     float rounded) {
  if (FCSR_ & kFCSRNaN2008FlagMask) {
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
  } else {
    set_fpu_register_word(fd_reg(), kFPUInvalidResult);
  }
}

void Simulator::set_fpu_register_invalid_result(float original, float rounded) {
  if (FCSR_ & kFCSRNaN2008FlagMask) {
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
  } else {
    set_fpu_register(fd_reg(), kFPUInvalidResult);
  }
}

void Simulator::set_fpu_register_invalid_result64(float original,
                                                  float rounded) {
  if (FCSR_ & kFCSRNaN2008FlagMask) {
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
  } else {
    set_fpu_register(fd_reg(), kFPU64InvalidResult);
  }
}

void Simulator::set_fpu_register_word_invalid_result(double original,
                                                     double rounded) {
  if (FCSR_ & kFCSRNaN2008FlagMask) {
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
  } else {
    set_fpu_register_word(fd_reg(), kFPUInvalidResult);
  }
}

void Simulator::set_fpu_register_invalid_result(double original,
                                                double rounded) {
  if (FCSR_ & kFCSRNaN2008FlagMask) {
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
  } else {
    set_fpu_register(fd_reg(), kFPUInvalidResult);
  }
}

void Simulator::set_fpu_register_invalid_result64(double original,
                                                  double rounded) {
  if (FCSR_ & kFCSRNaN2008FlagMask) {
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
  } else {
    set_fpu_register(fd_reg(), kFPU64InvalidResult);
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

  clear_fcsr_cause();

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactFlagBit, true);
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < FLT_MIN && rounded > -FLT_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowFlagBit, true);
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded >= max_int64 || rounded < min_int64) {
    set_fcsr_bit(kFCSROverflowFlagBit, true);
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpFlagBit, true);
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

// For cvt instructions only
void Simulator::round_according_to_fcsr(double toRound, double* rounded,
                                        int32_t* rounded_int, double fs) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero. Behave like round_w_d.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or
  // equal to the infinitely accurate result. Behave like trunc_w_d.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up. Behave like ceil_w_d.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down. Behave like floor_w_d.
  switch (FCSR_ & 3) {
    case kRoundToNearest:
      *rounded = std::floor(fs + 0.5);
      *rounded_int = static_cast<int32_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(fs);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = std::ceil(fs);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = std::floor(fs);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
  }
}

void Simulator::round64_according_to_fcsr(double toRound, double* rounded,
                                          int64_t* rounded_int, double fs) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero. Behave like round_w_d.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or.
  // equal to the infinitely accurate result. Behave like trunc_w_d.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up. Behave like ceil_w_d.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down. Behave like floor_w_d.
  switch (FCSR_ & 3) {
    case kRoundToNearest:
      *rounded = std::floor(fs + 0.5);
      *rounded_int = static_cast<int64_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(fs);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = std::ceil(fs);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = std::floor(fs);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
  }
}

// for cvt instructions only
void Simulator::round_according_to_fcsr(float toRound, float* rounded,
                                        int32_t* rounded_int, float fs) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero. Behave like round_w_d.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or
  // equal to the infinitely accurate result. Behave like trunc_w_d.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up. Behave like ceil_w_d.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down. Behave like floor_w_d.
  switch (FCSR_ & 3) {
    case kRoundToNearest:
      *rounded = std::floor(fs + 0.5);
      *rounded_int = static_cast<int32_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.f;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(fs);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = std::ceil(fs);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = std::floor(fs);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
  }
}

void Simulator::round64_according_to_fcsr(float toRound, float* rounded,
                                          int64_t* rounded_int, float fs) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero. Behave like round_w_d.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or.
  // equal to the infinitely accurate result. Behave like trunc_w_d.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up. Behave like ceil_w_d.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down. Behave like floor_w_d.
  switch (FCSR_ & 3) {
    case kRoundToNearest:
      *rounded = std::floor(fs + 0.5);
      *rounded_int = static_cast<int64_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.f;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(fs);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = std::ceil(fs);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = std::floor(fs);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
  }
}

template <typename T_fp, typename T_int>
void Simulator::round_according_to_msacsr(T_fp toRound, T_fp* rounded,
                                          T_int* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero. Behave like round_w_d.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or
  // equal to the infinitely accurate result. Behave like trunc_w_d.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up. Behave like ceil_w_d.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down. Behave like floor_w_d.
  switch (get_msacsr_rounding_mode()) {
    case kRoundToNearest:
      *rounded = std::floor(toRound + 0.5);
      *rounded_int = static_cast<T_int>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<T_int>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = std::ceil(toRound);
      *rounded_int = static_cast<T_int>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = std::floor(toRound);
      *rounded_int = static_cast<T_int>(*rounded);
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

// The MIPS cannot do unaligned reads and writes.  On some MIPS platforms an
// interrupt is caused.  On others it does a funky rotation thing.  For now we
// simply disallow unaligned reads, but at some point we may want to move to
// emulating the rotate behaviour.  Note that simulator runs have the runtime
// system running directly on the host system and only generated code is
// executed in the simulator.  Since the host is typically IA32 we will not
// get the correct MIPS-like behaviour on unaligned accesses.

// TODO(plind): refactor this messy debug code when we do unaligned access.
void Simulator::DieOrDebug() {
  if ((1)) {  // Flag for this was removed.
    MipsDebugger dbg(this);
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

template <typename T>
void Simulator::TraceMSARegWr(T* value, TraceType t) {
  if (v8_flags.trace_sim) {
    union {
      uint8_t b[16];
      uint16_t h[8];
      uint32_t w[4];
      uint64_t d[2];
      float f[4];
      double df[2];
    } v;
    memcpy(v.b, value, kSimd128Size);
    switch (t) {
      case BYTE:
        base::SNPrintF(trace_buf_,
                       "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                       ")",
                       v.d[0], v.d[1], icount_);
        break;
      case HALF:
        base::SNPrintF(trace_buf_,
                       "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                       ")",
                       v.d[0], v.d[1], icount_);
        break;
      case WORD:
        base::SNPrintF(trace_buf_,
                       "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                       ")    int32[0..3]:%" PRId32 "  %" PRId32 "  %" PRId32
                       "  %" PRId32,
                       v.d[0], v.d[1], icount_, v.w[0], v.w[1], v.w[2], v.w[3]);
        break;
      case DWORD:
        base::SNPrintF(trace_buf_,
                       "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                       ")",
                       v.d[0], v.d[1], icount_);
        break;
      case FLOAT:
        base::SNPrintF(trace_buf_,
                       "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                       ")    flt[0..3]:%e  %e  %e  %e",
                       v.d[0], v.d[1], icount_, v.f[0], v.f[1], v.f[2], v.f[3]);
        break;
      case DOUBLE:
        base::SNPrintF(trace_buf_,
                       "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                       ")    dbl[0..1]:%e  %e",
                       v.d[0], v.d[1], icount_, v.df[0], v.df[1]);
        break;
      default:
        UNREACHABLE();
    }
  }
}

template <typename T>
void Simulator::TraceMSARegWr(T* value) {
  if (v8_flags.trace_sim) {
    union {
      uint8_t b[kMSALanesByte];
      uint16_t h[kMSALanesHalf];
      uint32_t w[kMSALanesWord];
      uint64_t d[kMSALanesDword];
      float f[kMSALanesWord];
      double df[kMSALanesDword];
    } v;
    memcpy(v.b, value, kMSALanesByte);

    if (std::is_same<T, int32_t>::value) {
      base::SNPrintF(trace_buf_,
                     "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                     ")    int32[0..3]:%" PRId32 "  %" PRId32 "  %" PRId32
                     "  %" PRId32,
                     v.d[0], v.d[1], icount_, v.w[0], v.w[1], v.w[2], v.w[3]);
    } else if (std::is_same<T, float>::value) {
      base::SNPrintF(trace_buf_,
                     "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                     ")    flt[0..3]:%e  %e  %e  %e",
                     v.d[0], v.d[1], icount_, v.f[0], v.f[1], v.f[2], v.f[3]);
    } else if (std::is_same<T, double>::value) {
      base::SNPrintF(trace_buf_,
                     "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64
                     ")    dbl[0..1]:%e  %e",
                     v.d[0], v.d[1], icount_, v.df[0], v.df[1]);
    } else {
      base::SNPrintF(trace_buf_,
                     "LO: %016" PRIx64 "  HI: %016" PRIx64 "    (%" PRIu64 ")",
                     v.d[0], v.d[1], icount_);
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
                       static_cast<uint16_t>(value)
"""


```