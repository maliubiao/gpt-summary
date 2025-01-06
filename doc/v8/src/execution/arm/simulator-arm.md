Response: The user wants me to summarize the functionality of the C++ code provided in the file `v8/src/execution/arm/simulator-arm.cc`. The code seems to be related to a simulator for the ARM architecture within the V8 JavaScript engine. I need to identify the key components and their roles. Since the user mentioned JavaScript, I should also look for connections between the simulator and JavaScript execution, and if found, provide a simple JavaScript example to illustrate the relationship.

Here's a breakdown of the code's functionality:

1. **Simulator Core:** The code defines the `Simulator` class, which is responsible for emulating the behavior of an ARM processor. This includes managing registers, memory, and executing instructions.

2. **Debugger:**  The `ArmDebugger` class provides debugging capabilities for the simulated ARM code. It allows users to step through instructions, inspect registers and memory, and set breakpoints.

3. **Instruction Execution:**  The simulator includes logic to decode and execute ARM instructions. This involves fetching instruction bits, interpreting the opcode and operands, and updating the simulator's state (registers, flags, memory).

4. **Floating-Point Support:** The simulator provides support for floating-point operations, including managing VFP (Vector Floating-Point) registers and implementing floating-point arithmetic.

5. **Runtime Calls:** The simulator handles calls from the simulated code to the V8 runtime environment. This allows the simulated JavaScript code to interact with the rest of the V8 engine.

6. **ICache Simulation:** The simulator includes a basic instruction cache (ICache) simulation to model how instructions are fetched and cached in a real processor.

7. **Memory Access:** The simulator provides methods for reading and writing data to simulated memory, including handling memory access attributes and exclusive access operations.

8. **Stack Management:** The simulator manages a simulated stack for the emulated ARM code.

**Connection to JavaScript:**

The simulator plays a crucial role in running JavaScript code on platforms where a native ARM execution environment is not available during development or testing. V8 can compile JavaScript code to ARM machine code, and then the simulator executes this generated code instruction by instruction. This allows developers to test and debug V8 on various platforms.

**JavaScript Example:** A simple JavaScript example wouldn't directly interact with the simulator code. The connection is more architectural. When V8 runs JavaScript on a simulated ARM platform, the following happens conceptually:

1. JavaScript code is parsed and compiled into ARM assembly code.
2. Instead of executing directly on the hardware, the `Simulator` class interprets and executes these ARM instructions.
3. If the JavaScript code calls a built-in function or needs to interact with the V8 runtime, the simulator handles these calls through the `SoftwareInterrupt` mechanism.
这个C++代码文件是V8 JavaScript引擎中用于模拟ARM架构处理器行为的模拟器实现的第一部分。

其主要功能可以归纳为：

1. **定义了ARM模拟器的核心结构:**  它定义了 `Simulator` 类，这个类负责模拟ARM处理器的各种状态，例如通用寄存器、程序计数器（PC）、栈指针（SP）、链接寄存器（LR）、状态标志位（N, Z, C, V）以及浮点寄存器等。

2. **实现了调试功能:** 包含了 `ArmDebugger` 类，为模拟执行的ARM代码提供了交互式的调试功能。这包括：
    *   单步执行 (`si`, `stepi`)
    *   继续执行 (`c`, `cont`)
    *   打印寄存器值 (`p`, `print`)，支持打印通用寄存器和浮点寄存器
    *   打印对象信息 (`po`, `printobject`)
    *   查看栈和内存 (`stack`, `mem`, `dump`)
    *   反汇编代码 (`disasm`, `di`)
    *   进入GDB调试 (`gdb`)
    *   设置和删除断点 (`break`, `del`)
    *   查看调用栈 (`backtrace`, `bt`)
    *   查看状态标志位 (`flags`)
    *   控制停止点 (`stop`)
    *   切换指令跟踪 (`t`, `trace`)
    *   显示帮助信息 (`h`, `help`)

3. **提供了与外部环境交互的能力:**  定义了 `SoftwareInterrupt` 函数，用于处理模拟器执行过程中遇到的软件中断指令。这通常用于模拟调用V8的运行时（runtime）函数。

4. **实现了基本的指令缓存模拟:**  包含了 `ICacheMatch`, `ICacheHash`, `FlushICache`, `GetCachePage`, `FlushOnePage`, `CheckICache` 等函数，用于模拟指令缓存的行为，这对于准确模拟处理器性能至关重要。

5. **定义了内存访问方法:**  提供了 `ReadW`, `WriteW`, `ReadHU`, `WriteH`, `ReadBU`, `WriteB`, `ReadDW`, `WriteDW` 等函数，用于模拟从内存中读取和写入不同大小的数据。

6. **实现了条件执行逻辑:** `ConditionallyExecute` 函数根据指令的条件码和当前的状态标志位来判断是否执行当前指令。

7. **包含了辅助函数用于设置和获取状态标志位:**  例如 `SetNZFlags`, `SetCFlag`, `SetVFlag` 以及用于VFP的 `Compute_FPSCR_Flags` 等。

**与JavaScript的功能关系以及JavaScript示例:**

这个文件中的代码是V8引擎的一部分，直接负责在不支持本地ARM执行的环境下运行JavaScript代码。当V8引擎需要在ARM架构上运行但实际硬件并非ARM时（例如在x86机器上进行开发和测试），就会使用这个模拟器。

**概念上**，当JavaScript代码被V8引擎执行时，会经历以下步骤（简化）：

1. **解析 (Parsing):** JavaScript源代码被解析成抽象语法树 (AST)。
2. **编译 (Compilation):** AST被编译成机器码。在模拟器环境下，这会生成ARM机器码。
3. **执行 (Execution):**  生成的ARM机器码不再直接在物理CPU上执行，而是由 `Simulator` 类逐条指令地模拟执行。

**虽然JavaScript代码不能直接“调用”这个C++文件中的函数，但是V8引擎在执行JavaScript代码的过程中会使用这个模拟器。**

举个例子，考虑一段简单的JavaScript代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当V8引擎在模拟ARM环境下执行这段代码时，`add` 函数会被编译成一系列ARM指令。  `Simulator` 类会负责执行这些指令，例如：

*   将参数 `5` 和 `10` 加载到模拟的ARM寄存器中。
*   执行加法指令，更新模拟的寄存器值。
*   将结果存储到另一个模拟的寄存器中。
*   当执行到 `console.log` 时，这会触发一个V8的运行时调用。`Simulator` 的 `SoftwareInterrupt` 机制会被用来模拟这个调用，将控制权转移到V8的C++运行时代码中去执行实际的输出操作。

**总结来说， `simulator-arm.cc` 文件的主要作用是提供一个软件层面的ARM处理器模拟器，使得V8引擎能够在非ARM平台上运行为ARM架构编译的JavaScript代码，这对于开发、测试和调试V8引擎本身至关重要。**

Prompt: 
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/arm/simulator-arm.h"

#include "src/base/logging.h"

#if defined(USE_SIMULATOR)

#include <stdarg.h>
#include <stdlib.h>

#include <cmath>

#include "src/base/bits.h"
#include "src/base/lazy-instance.h"
#include "src/base/memory.h"
#include "src/base/overflowing-math.h"
#include "src/base/platform/memory.h"
#include "src/base/platform/platform.h"
#include "src/base/vector.h"
#include "src/codegen/arm/constants-arm.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disasm.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-inl.h"  // For CodeSpaceMemoryModificationScope.
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/utils/ostreams.h"
#include "src/utils/utils.h"

// Only build the simulator if not compiling for real ARM hardware.
namespace v8 {
namespace internal {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(Simulator::GlobalMonitor,
                                Simulator::GlobalMonitor::Get)

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent way through
// ::v8::internal::OS in the same way as SNPrintF is that the
// Windows C Run-Time Library does not provide vsscanf.
#define SScanF sscanf

// The ArmDebugger class is used by the simulator while debugging simulated ARM
// code.
class ArmDebugger {
 public:
  explicit ArmDebugger(Simulator* sim) : sim_(sim) {}
  void Debug();
  bool ExecDebugCommand(ArrayUniquePtr<char> line_ptr);

 private:
  static const Instr kBreakpointInstr =
      (al | (7 * B25) | (1 * B24) | kBreakpoint);
  static const Instr kNopInstr = (al | (13 * B21));

  Simulator* sim_;

  int32_t GetRegisterValue(int regnum);
  double GetRegisterPairDoubleValue(int regnum);
  double GetVFPDoubleRegisterValue(int regnum);
  bool GetValue(const char* desc, int32_t* value);
  bool GetVFPSingleValue(const char* desc, float* value);
  bool GetVFPDoubleValue(const char* desc, double* value);

  // Set or delete breakpoint (there can be only one).
  bool SetBreakpoint(Instruction* breakpc);
  void DeleteBreakpoint();

  // Undo and redo the breakpoint. This is needed to bracket disassembly and
  // execution to skip past the breakpoint when run from the debugger.
  void UndoBreakpoint();
  void RedoBreakpoint();
};

void Simulator::DebugAtNextPC() {
  PrintF("Starting debugger on the next instruction:\n");
  set_pc(get_pc() + kInstrSize);
  ArmDebugger(this).Debug();
}

void Simulator::AdvancedSIMDElementOrStructureLoadStoreWriteback(int Rn, int Rm,
                                                                 int ebytes) {
  if (Rm != 15) {
    if (Rm == 13) {
      set_register(Rn, get_register(Rn) + ebytes);
    } else {
      set_register(Rn, get_register(Rn) + get_register(Rm));
    }
  }
}

int32_t ArmDebugger::GetRegisterValue(int regnum) {
  if (regnum == kPCRegister) {
    return sim_->get_pc();
  } else {
    return sim_->get_register(regnum);
  }
}

double ArmDebugger::GetRegisterPairDoubleValue(int regnum) {
  return sim_->get_double_from_register_pair(regnum);
}

double ArmDebugger::GetVFPDoubleRegisterValue(int regnum) {
  return sim_->get_double_from_d_register(regnum).get_scalar();
}

bool ArmDebugger::GetValue(const char* desc, int32_t* value) {
  int regnum = Registers::Number(desc);
  if (regnum != kNoRegister) {
    *value = GetRegisterValue(regnum);
    return true;
  }
  if (strncmp(desc, "0x", 2) == 0)
    return SScanF(desc + 2, "%x", reinterpret_cast<uint32_t*>(value)) == 1;
  return SScanF(desc, "%u", reinterpret_cast<uint32_t*>(value)) == 1;
}

bool ArmDebugger::GetVFPSingleValue(const char* desc, float* value) {
  bool is_double;
  int regnum = VFPRegisters::Number(desc, &is_double);
  if (regnum != kNoRegister && !is_double) {
    *value = sim_->get_float_from_s_register(regnum).get_scalar();
    return true;
  }
  return false;
}

bool ArmDebugger::GetVFPDoubleValue(const char* desc, double* value) {
  bool is_double;
  int regnum = VFPRegisters::Number(desc, &is_double);
  if (regnum != kNoRegister && is_double) {
    *value = sim_->get_double_from_d_register(regnum).get_scalar();
    return true;
  }
  return false;
}

bool ArmDebugger::SetBreakpoint(Instruction* breakpc) {
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

namespace {
// This function is dangerous, but it's only available in non-production
// (simulator) builds.
void SetInstructionBitsInCodeSpace(Instruction* instr, Instr value,
                                   Heap* heap) {
  CodePageMemoryModificationScopeForDebugging scope(
      MemoryChunkMetadata::FromAddress(reinterpret_cast<Address>(instr)));
  instr->SetInstructionBits(value);
}
}  // namespace

void ArmDebugger::DeleteBreakpoint() {
  UndoBreakpoint();
  sim_->break_pc_ = nullptr;
  sim_->break_instr_ = 0;
}

void ArmDebugger::UndoBreakpoint() {
  if (sim_->break_pc_ != nullptr) {
    SetInstructionBitsInCodeSpace(sim_->break_pc_, sim_->break_instr_,
                                  sim_->isolate_->heap());
  }
}

void ArmDebugger::RedoBreakpoint() {
  if (sim_->break_pc_ != nullptr) {
    SetInstructionBitsInCodeSpace(sim_->break_pc_, kBreakpointInstr,
                                  sim_->isolate_->heap());
  }
}

void ArmDebugger::Debug() {
  if (v8_flags.correctness_fuzzer_suppressions) {
    PrintF("Debugger disabled for differential fuzzing.\n");
    return;
  }
  intptr_t last_pc = -1;
  bool done = false;

  // Unset breakpoint while running in the debugger shell, making it invisible
  // to all commands.
  UndoBreakpoint();

  while (!done && !sim_->has_bad_pc()) {
    if (last_pc != sim_->get_pc()) {
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      // use a reasonably large buffer
      v8::base::EmbeddedVector<char, 256> buffer;
      dasm.InstructionDecode(buffer,
                             reinterpret_cast<uint8_t*>(sim_->get_pc()));
      PrintF("  0x%08x  %s\n", sim_->get_pc(), buffer.begin());
      last_pc = sim_->get_pc();
    }
    ArrayUniquePtr<char> line(ReadLine("sim> "));

    done = ExecDebugCommand(std::move(line));
  }

  // Reinstall breakpoint to stop execution and enter the debugger shell when
  // hit.
  RedoBreakpoint();
}

bool ArmDebugger::ExecDebugCommand(ArrayUniquePtr<char> line_ptr) {
#define COMMAND_SIZE 63
#define ARG_SIZE 255

#define STR(a) #a
#define XSTR(a) STR(a)

  char cmd[COMMAND_SIZE + 1];
  char arg1[ARG_SIZE + 1];
  char arg2[ARG_SIZE + 1];
  char* argv[3] = {cmd, arg1, arg2};

  // make sure to have a proper terminating character if reaching the limit
  cmd[COMMAND_SIZE] = 0;
  arg1[ARG_SIZE] = 0;
  arg2[ARG_SIZE] = 0;

  if (line_ptr == nullptr) return true;

  // Repeat last command by default.
  const char* line = line_ptr.get();
  const char* last_input = sim_->last_debugger_input();
  if (strcmp(line, "\n") == 0 && (last_input != nullptr)) {
    line_ptr.reset();
    line = last_input;
  } else {
    // Update the latest command ran
    sim_->set_last_debugger_input(std::move(line_ptr));
  }

  // Use sscanf to parse the individual parts of the command line. At the
  // moment no command expects more than two parameters.
  int argc = SScanF(line,
                      "%" XSTR(COMMAND_SIZE) "s "
                      "%" XSTR(ARG_SIZE) "s "
                      "%" XSTR(ARG_SIZE) "s",
                      cmd, arg1, arg2);
  if ((strcmp(cmd, "si") == 0) || (strcmp(cmd, "stepi") == 0)) {
    sim_->InstructionDecode(reinterpret_cast<Instruction*>(sim_->get_pc()));
  } else if ((strcmp(cmd, "c") == 0) || (strcmp(cmd, "cont") == 0)) {
    // Execute the one instruction we broke at with breakpoints disabled.
    sim_->InstructionDecode(reinterpret_cast<Instruction*>(sim_->get_pc()));
    // Leave the debugger shell.
    return true;
  } else if ((strcmp(cmd, "p") == 0) || (strcmp(cmd, "print") == 0)) {
    if (argc == 2 || (argc == 3 && strcmp(arg2, "fp") == 0)) {
      int32_t value;
      float svalue;
      double dvalue;
      if (strcmp(arg1, "all") == 0) {
        for (int i = 0; i < kNumRegisters; i++) {
          value = GetRegisterValue(i);
          PrintF("%3s: 0x%08x %10d", RegisterName(Register::from_code(i)),
                 value, value);
          if ((argc == 3 && strcmp(arg2, "fp") == 0) && i < 8 && (i % 2) == 0) {
            dvalue = GetRegisterPairDoubleValue(i);
            PrintF(" (%f)\n", dvalue);
          } else {
            PrintF("\n");
          }
        }
        for (int i = 0; i < DwVfpRegister::SupportedRegisterCount(); i++) {
          dvalue = GetVFPDoubleRegisterValue(i);
          uint64_t as_words = base::bit_cast<uint64_t>(dvalue);
          PrintF("%3s: %f 0x%08x %08x\n", VFPRegisters::Name(i, true), dvalue,
                 static_cast<uint32_t>(as_words >> 32),
                 static_cast<uint32_t>(as_words & 0xFFFFFFFF));
        }
      } else {
        if (GetValue(arg1, &value)) {
          PrintF("%s: 0x%08x %d \n", arg1, value, value);
        } else if (GetVFPSingleValue(arg1, &svalue)) {
          uint32_t as_word = base::bit_cast<uint32_t>(svalue);
          PrintF("%s: %f 0x%08x\n", arg1, svalue, as_word);
        } else if (GetVFPDoubleValue(arg1, &dvalue)) {
          uint64_t as_words = base::bit_cast<uint64_t>(dvalue);
          PrintF("%s: %f 0x%08x %08x\n", arg1, dvalue,
                 static_cast<uint32_t>(as_words >> 32),
                 static_cast<uint32_t>(as_words & 0xFFFFFFFF));
        } else {
          PrintF("%s unrecognized\n", arg1);
        }
      }
    } else {
      PrintF("print <register>\n");
    }
  } else if ((strcmp(cmd, "po") == 0) || (strcmp(cmd, "printobject") == 0)) {
    if (argc == 2) {
      int32_t value;
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
    int32_t* cur = nullptr;
    int32_t* end = nullptr;
    int next_arg = 1;

    if (strcmp(cmd, "stack") == 0) {
      cur = reinterpret_cast<int32_t*>(sim_->get_register(Simulator::sp));
    } else {  // "mem"
      int32_t value;
      if (!GetValue(arg1, &value)) {
        PrintF("%s unrecognized\n", arg1);
        return false;
      }
      cur = reinterpret_cast<int32_t*>(value);
      next_arg++;
    }

    int32_t words;
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
      PrintF("  0x%08" V8PRIxPTR ":  0x%08x %10d",
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
  } else if (strcmp(cmd, "disasm") == 0 || strcmp(cmd, "di") == 0) {
    disasm::NameConverter converter;
    disasm::Disassembler dasm(converter);
    // use a reasonably large buffer
    v8::base::EmbeddedVector<char, 256> buffer;

    uint8_t* prev = nullptr;
    uint8_t* cur = nullptr;
    uint8_t* end = nullptr;

    if (argc == 1) {
      cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
      end = cur + (10 * kInstrSize);
    } else if (argc == 2) {
      int regnum = Registers::Number(arg1);
      if (regnum != kNoRegister || strncmp(arg1, "0x", 2) == 0) {
        // The argument is an address or a register name.
        int32_t value;
        if (GetValue(arg1, &value)) {
          cur = reinterpret_cast<uint8_t*>(value);
          // Disassemble 10 instructions at <arg1>.
          end = cur + (10 * kInstrSize);
        }
      } else {
        // The argument is the number of instructions.
        int32_t value;
        if (GetValue(arg1, &value)) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
          // Disassemble <arg1> instructions.
          end = cur + (value * kInstrSize);
        }
      }
    } else {
      int32_t value1;
      int32_t value2;
      if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
        cur = reinterpret_cast<uint8_t*>(value1);
        end = cur + (value2 * kInstrSize);
      }
    }

    while (cur < end) {
      prev = cur;
      cur += dasm.InstructionDecode(buffer, cur);
      PrintF("  0x%08" V8PRIxPTR "  %s\n", reinterpret_cast<intptr_t>(prev),
             buffer.begin());
    }
  } else if (strcmp(cmd, "gdb") == 0) {
    PrintF("relinquishing control to gdb\n");
    v8::base::OS::DebugBreak();
    PrintF("regaining control from gdb\n");
  } else if (strcmp(cmd, "break") == 0) {
    if (argc == 2) {
      int32_t value;
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
  } else if (strcmp(cmd, "backtrace") == 0 || strcmp(cmd, "bt") == 0) {
    int32_t pc = sim_->get_pc();
    int32_t lr = sim_->get_register(Simulator::lr);
    int32_t sp = sim_->get_register(Simulator::sp);
    int32_t fp = sim_->get_register(Simulator::fp);

    int i = 0;
    while (true) {
      PrintF("#%d: 0x%08x (sp=0x%08x, fp=0x%08x)\n", i, pc, sp, fp);
      pc = lr;
      sp = fp;
      if (pc == Simulator::end_sim_pc) {
        break;
      }
      lr = *(reinterpret_cast<int32_t*>(fp) + 1);
      fp = *reinterpret_cast<int32_t*>(fp);
      i++;
      if (i > 100) {
        PrintF("Too many frames\n");
        break;
      }
    }
  } else if (strcmp(cmd, "del") == 0) {
    DeleteBreakpoint();
  } else if (strcmp(cmd, "flags") == 0) {
    PrintF("N flag: %d; ", sim_->n_flag_);
    PrintF("Z flag: %d; ", sim_->z_flag_);
    PrintF("C flag: %d; ", sim_->c_flag_);
    PrintF("V flag: %d\n", sim_->v_flag_);
    PrintF("INVALID OP flag: %d; ", sim_->inv_op_vfp_flag_);
    PrintF("DIV BY ZERO flag: %d; ", sim_->div_zero_vfp_flag_);
    PrintF("OVERFLOW flag: %d; ", sim_->overflow_vfp_flag_);
    PrintF("UNDERFLOW flag: %d; ", sim_->underflow_vfp_flag_);
    PrintF("INEXACT flag: %d;\n", sim_->inexact_vfp_flag_);
  } else if (strcmp(cmd, "stop") == 0) {
    int32_t value;
    intptr_t stop_pc = sim_->get_pc() - kInstrSize;
    Instruction* stop_instr = reinterpret_cast<Instruction*>(stop_pc);
    if ((argc == 2) && (strcmp(arg1, "unstop") == 0)) {
      // Remove the current stop.
      if (stop_instr->IsStop()) {
        SetInstructionBitsInCodeSpace(stop_instr, kNopInstr,
                                      sim_->isolate_->heap());
      } else {
        PrintF("Not at debugger stop.\n");
      }
    } else if (argc == 3) {
      // Print information about all/the specified breakpoint(s).
      if (strcmp(arg1, "info") == 0) {
        if (strcmp(arg2, "all") == 0) {
          PrintF("Stop information:\n");
          for (uint32_t i = 0; i < sim_->kNumOfWatchedStops; i++) {
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
          for (uint32_t i = 0; i < sim_->kNumOfWatchedStops; i++) {
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
          for (uint32_t i = 0; i < sim_->kNumOfWatchedStops; i++) {
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
  } else if ((strcmp(cmd, "t") == 0) || strcmp(cmd, "trace") == 0) {
    sim_->ToggleInstructionTracing();
    PrintF("Trace of executed instructions is %s\n",
           sim_->InstructionTracingEnabled() ? "on" : "off");
  } else if ((strcmp(cmd, "h") == 0) || (strcmp(cmd, "help") == 0)) {
    PrintF("cont\n");
    PrintF("  continue execution (alias 'c')\n");
    PrintF("stepi\n");
    PrintF("  step one instruction (alias 'si')\n");
    PrintF("print <register>\n");
    PrintF("  print register content (alias 'p')\n");
    PrintF("  use register name 'all' to print all registers\n");
    PrintF("  add argument 'fp' to print register pair double values\n");
    PrintF("printobject <register>\n");
    PrintF("  print an object from a register (alias 'po')\n");
    PrintF("flags\n");
    PrintF("  print flags\n");
    PrintF("stack [<words>]\n");
    PrintF("  dump stack content, default dump 10 words)\n");
    PrintF("mem <address> [<words>]\n");
    PrintF("  dump memory content, default dump 10 words)\n");
    PrintF("dump [<words>]\n");
    PrintF(
        "  dump memory content without pretty printing JS objects, default "
        "dump 10 words)\n");
    PrintF("disasm [<instructions>]\n");
    PrintF("disasm [<address/register>]\n");
    PrintF("disasm [[<address/register>] <instructions>]\n");
    PrintF("  disassemble code, default is 10 instructions\n");
    PrintF("  from pc (alias 'di')\n");
    PrintF("gdb\n");
    PrintF("  enter gdb\n");
    PrintF("break <address>\n");
    PrintF("  set a break point on the address\n");
    PrintF("backtrace / bt\n");
    PrintF("  Walk the frame pointers, dumping the pc/sp/fp for each frame.\n");
    PrintF("del\n");
    PrintF("  delete the breakpoint\n");
    PrintF("trace (alias 't')\n");
    PrintF("  toogle the tracing of all executed statements\n");
    PrintF("stop feature:\n");
    PrintF("  Description:\n");
    PrintF("    Stops are debug instructions inserted by\n");
    PrintF("    the Assembler::stop() function.\n");
    PrintF("    When hitting a stop, the Simulator will\n");
    PrintF("    stop and give control to the ArmDebugger.\n");
    PrintF("    The first %d stop codes are watched:\n",
           Simulator::kNumOfWatchedStops);
    PrintF("    - They can be enabled / disabled: the Simulator\n");
    PrintF("      will / won't stop when hitting them.\n");
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
  return false;

#undef COMMAND_SIZE
#undef ARG_SIZE

#undef STR
#undef XSTR
}

bool Simulator::InstructionTracingEnabled() { return instruction_tracing_; }

void Simulator::ToggleInstructionTracing() {
  instruction_tracing_ = !instruction_tracing_;
}

bool Simulator::ICacheMatch(void* one, void* two) {
  DCHECK_EQ(reinterpret_cast<intptr_t>(one) & CachePage::kPageMask, 0);
  DCHECK_EQ(reinterpret_cast<intptr_t>(two) & CachePage::kPageMask, 0);
  return one == two;
}

static uint32_t ICacheHash(void* key) {
  return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(key)) >> 2;
}

static bool AllOnOnePage(uintptr_t start, int size) {
  intptr_t start_page = (start & ~CachePage::kPageMask);
  intptr_t end_page = ((start + size) & ~CachePage::kPageMask);
  return start_page == end_page;
}

void Simulator::SetRedirectInstruction(Instruction* instruction) {
  instruction->SetInstructionBits(al | (0xF * B24) | kCallRtRedirected);
}

void Simulator::FlushICache(base::CustomMatcherHashMap* i_cache,
                            void* start_addr, size_t size) {
  intptr_t start = reinterpret_cast<intptr_t>(start_addr);
  int intra_line = (start & CachePage::kLineMask);
  start -= intra_line;
  size += intra_line;
  size = ((size - 1) | CachePage::kLineMask) + 1;
  int offset = (start & CachePage::kPageMask);
  while (!AllOnOnePage(start, size - 1)) {
    int bytes_to_flush = CachePage::kPageSize - offset;
    FlushOnePage(i_cache, start, bytes_to_flush);
    start += bytes_to_flush;
    size -= bytes_to_flush;
    DCHECK_EQ(0, start & CachePage::kPageMask);
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
                             intptr_t start, int size) {
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
  intptr_t address = reinterpret_cast<intptr_t>(instr);
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
  stack_ = reinterpret_cast<uint8_t*>(base::Malloc(kAllocatedStackSize));
  pc_modified_ = false;
  icount_ = 0;
  break_pc_ = nullptr;
  break_instr_ = 0;

  // Set up architecture state.
  // All registers are initialized to zero to start with.
  for (int i = 0; i < num_registers; i++) {
    registers_[i] = 0;
  }
  n_flag_ = false;
  z_flag_ = false;
  c_flag_ = false;
  v_flag_ = false;

  // Initializing VFP registers.
  // All registers are initialized to zero to start with
  // even though s_registers_ & d_registers_ share the same
  // physical registers in the target.
  for (int i = 0; i < num_d_registers * 2; i++) {
    vfp_registers_[i] = 0;
  }
  n_flag_FPSCR_ = false;
  z_flag_FPSCR_ = false;
  c_flag_FPSCR_ = false;
  v_flag_FPSCR_ = false;
  FPSCR_rounding_mode_ = RN;
  FPSCR_default_NaN_mode_ = false;

  inv_op_vfp_flag_ = false;
  div_zero_vfp_flag_ = false;
  overflow_vfp_flag_ = false;
  underflow_vfp_flag_ = false;
  inexact_vfp_flag_ = false;

  // The sp is initialized to point to the bottom (high address) of the
  // usable stack area.
  registers_[sp] = reinterpret_cast<int32_t>(stack_) + kUsableStackSize;
  // The lr and pc are initialized to a known bad value that will cause an
  // access violation if the simulator ever tries to execute it.
  registers_[pc] = bad_lr;
  registers_[lr] = bad_lr;

  last_debugger_input_ = nullptr;
}

Simulator::~Simulator() {
  GlobalMonitor::Get()->RemoveProcessor(&global_monitor_processor_);
  base::Free(stack_);
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
void Simulator::set_register(int reg, int32_t value) {
  DCHECK((reg >= 0) && (reg < num_registers));
  if (reg == pc) {
    pc_modified_ = true;
  }
  registers_[reg] = value;
}

// Get the register from the architecture state. This function does handle
// the special case of accessing the PC register.
int32_t Simulator::get_register(int reg) const {
  DCHECK((reg >= 0) && (reg < num_registers));
  // Stupid code added to avoid bug in GCC.
  // See: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=43949
  if (reg >= num_registers) return 0;
  // End stupid code.
  return registers_[reg] + ((reg == pc) ? Instruction::kPcLoadDelta : 0);
}

double Simulator::get_double_from_register_pair(int reg) {
  DCHECK((reg >= 0) && (reg < num_registers) && ((reg % 2) == 0));

  double dm_val = 0.0;
  // Read the bits from the unsigned integer register_[] array
  // into the double precision floating point value and return it.
  char buffer[2 * sizeof(vfp_registers_[0])];
  memcpy(buffer, &registers_[reg], 2 * sizeof(registers_[0]));
  memcpy(&dm_val, buffer, 2 * sizeof(registers_[0]));
  return (dm_val);
}

void Simulator::set_register_pair_from_double(int reg, double* value) {
  DCHECK((reg >= 0) && (reg < num_registers) && ((reg % 2) == 0));
  memcpy(registers_ + reg, value, sizeof(*value));
}

void Simulator::set_dw_register(int dreg, const int* dbl) {
  DCHECK((dreg >= 0) && (dreg < num_d_registers));
  registers_[dreg] = dbl[0];
  registers_[dreg + 1] = dbl[1];
}

void Simulator::get_d_register(int dreg, uint64_t* value) {
  DCHECK((dreg >= 0) && (dreg < DwVfpRegister::SupportedRegisterCount()));
  memcpy(value, vfp_registers_ + dreg * 2, sizeof(*value));
}

void Simulator::set_d_register(int dreg, const uint64_t* value) {
  DCHECK((dreg >= 0) && (dreg < DwVfpRegister::SupportedRegisterCount()));
  memcpy(vfp_registers_ + dreg * 2, value, sizeof(*value));
}

void Simulator::get_d_register(int dreg, uint32_t* value) {
  DCHECK((dreg >= 0) && (dreg < DwVfpRegister::SupportedRegisterCount()));
  memcpy(value, vfp_registers_ + dreg * 2, sizeof(*value) * 2);
}

void Simulator::set_d_register(int dreg, const uint32_t* value) {
  DCHECK((dreg >= 0) && (dreg < DwVfpRegister::SupportedRegisterCount()));
  memcpy(vfp_registers_ + dreg * 2, value, sizeof(*value) * 2);
}

template <typename T, int SIZE>
void Simulator::get_neon_register(int reg, T (&value)[SIZE / sizeof(T)]) {
  DCHECK(SIZE == kSimd128Size || SIZE == kDoubleSize);
  DCHECK_LE(0, reg);
  DCHECK_GT(SIZE == kSimd128Size ? num_q_registers : num_d_registers, reg);
  memcpy(value, vfp_registers_ + reg * (SIZE / 4), SIZE);
}

template <typename T, int SIZE>
void Simulator::set_neon_register(int reg, const T (&value)[SIZE / sizeof(T)]) {
  DCHECK(SIZE == kSimd128Size || SIZE == kDoubleSize);
  DCHECK_LE(0, reg);
  DCHECK_GT(SIZE == kSimd128Size ? num_q_registers : num_d_registers, reg);
  memcpy(vfp_registers_ + reg * (SIZE / 4), value, SIZE);
}

// Raw access to the PC register.
void Simulator::set_pc(int32_t value) {
  pc_modified_ = true;
  registers_[pc] = value;
}

bool Simulator::has_bad_pc() const {
  return ((registers_[pc] == bad_lr) || (registers_[pc] == end_sim_pc));
}

// Raw access to the PC register without the special adjustment when reading.
int32_t Simulator::get_pc() const { return registers_[pc]; }

// Getting from and setting into VFP registers.
void Simulator::set_s_register(int sreg, unsigned int value) {
  DCHECK((sreg >= 0) && (sreg < num_s_registers));
  vfp_registers_[sreg] = value;
}

unsigned int Simulator::get_s_register(int sreg) const {
  DCHECK((sreg >= 0) && (sreg < num_s_registers));
  return vfp_registers_[sreg];
}

template <class InputType, int register_size>
void Simulator::SetVFPRegister(int reg_index, const InputType& value) {
  unsigned bytes = register_size * sizeof(vfp_registers_[0]);
  DCHECK_EQ(sizeof(InputType), bytes);
  DCHECK_GE(reg_index, 0);
  if (register_size == 1) DCHECK(reg_index < num_s_registers);
  if (register_size == 2)
    DCHECK(reg_index < DwVfpRegister::SupportedRegisterCount());

  memcpy(&vfp_registers_[reg_index * register_size], &value, bytes);
}

template <class ReturnType, int register_size>
ReturnType Simulator::GetFromVFPRegister(int reg_index) {
  unsigned bytes = register_size * sizeof(vfp_registers_[0]);
  DCHECK_EQ(sizeof(ReturnType), bytes);
  DCHECK_GE(reg_index, 0);
  if (register_size == 1) DCHECK(reg_index < num_s_registers);
  if (register_size == 2)
    DCHECK(reg_index < DwVfpRegister::SupportedRegisterCount());

  ReturnType value;
  memcpy(&value, &vfp_registers_[register_size * reg_index], bytes);
  return value;
}

void Simulator::SetSpecialRegister(SRegisterFieldMask reg_and_mask,
                                   uint32_t value) {
  // Only CPSR_f is implemented. Of that, only N, Z, C and V are implemented.
  if ((reg_and_mask == CPSR_f) && ((value & ~kSpecialCondition) == 0)) {
    n_flag_ = ((value & (1 << 31)) != 0);
    z_flag_ = ((value & (1 << 30)) != 0);
    c_flag_ = ((value & (1 << 29)) != 0);
    v_flag_ = ((value & (1 << 28)) != 0);
  } else {
    UNIMPLEMENTED();
  }
}

uint32_t Simulator::GetFromSpecialRegister(SRegister reg) {
  uint32_t result = 0;
  // Only CPSR_f is implemented.
  if (reg == CPSR) {
    if (n_flag_) result |= (1 << 31);
    if (z_flag_) result |= (1 << 30);
    if (c_flag_) result |= (1 << 29);
    if (v_flag_) result |= (1 << 28);
  } else {
    UNIMPLEMENTED();
  }
  return result;
}

// Runtime FP routines take:
// - two double arguments
// - one double argument and zero or one integer arguments.
// All are consructed here from r0-r3 or d0, d1 and r0.
void Simulator::GetFpArgs(double* x, double* y, int32_t* z) {
  if (use_eabi_hardfloat()) {
    *x = get_double_from_d_register(0).get_scalar();
    *y = get_double_from_d_register(1).get_scalar();
    *z = get_register(0);
  } else {
    // Registers 0 and 1 -> x.
    *x = get_double_from_register_pair(0);
    // Register 2 and 3 -> y.
    *y = get_double_from_register_pair(2);
    // Register 2 -> z
    *z = get_register(2);
  }
}

// The return value is either in r0/r1 or d0.
void Simulator::SetFpResult(const double& result) {
  if (use_eabi_hardfloat()) {
    char buffer[2 * sizeof(vfp_registers_[0])];
    memcpy(buffer, &result, sizeof(buffer));
    // Copy result to d0.
    memcpy(vfp_registers_, buffer, sizeof(buffer));
  } else {
    char buffer[2 * sizeof(registers_[0])];
    memcpy(buffer, &result, sizeof(buffer));
    // Copy result to r0 and r1.
    memcpy(registers_, buffer, sizeof(buffer));
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
"""


```