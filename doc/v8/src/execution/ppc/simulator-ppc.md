Response: The user wants a summary of the functionality of the provided C++ code file. The file is part of the V8 JavaScript engine and specifically for the PPC architecture simulator. It's the first part of a larger file.

Therefore, the core functionality is likely related to *simulating* PPC instructions. This will involve:

1. **Debugger:**  The code includes a `PPCDebugger` class, indicating debugging capabilities for the simulated environment.
2. **Register Management:**  The simulator needs to manage the state of PPC registers.
3. **Memory Access:**  Simulating memory reads and writes is crucial.
4. **Instruction Execution:**  The simulator must be able to interpret and execute PPC instructions.
5. **Integration with V8:** Since it's part of V8, there will likely be interactions with other V8 components, particularly for running JavaScript code.

For the JavaScript relationship, I need to consider how a simulator facilitates JavaScript execution. A simulator allows running JavaScript code compiled for an architecture (PPC in this case) even on a different host architecture. I can illustrate this with a simple JavaScript example and how the simulator would be involved.
这个C++代码文件是V8 JavaScript引擎的一部分，专门用于PowerPC (PPC) 架构的**模拟器 (Simulator)**。它的主要功能是：

1. **提供一个在非PPC硬件上执行PPC代码的环境。**  它通过软件模拟PPC的指令集架构，允许开发者在没有实际PPC硬件的情况下运行和调试为PPC编译的代码。
2. **实现PPC处理器的核心功能。**  这包括管理通用寄存器、浮点寄存器、特殊寄存器（如PC、LR、CTR、XER）、条件寄存器等的状态。
3. **提供指令级的调试功能。**  `PPCDebugger` 类允许用户在模拟环境中设置断点、单步执行、查看和修改寄存器和内存的值，以及反汇编代码。
4. **支持调用V8运行时函数。**  通过软件中断机制 (`SoftwareInterrupt`)，模拟器可以调用V8引擎的C++运行时函数，这是JavaScript代码执行的关键。
5. **管理模拟器的内存和栈。** 它分配和管理模拟器的栈空间，并提供读写内存的方法。
6. **实现指令缓存模拟。**  `FlushICache` 和 `CheckICache` 等函数用于模拟指令缓存的行为，确保模拟的准确性。
7. **处理特定的PPC指令。** 代码中可以看到针对不同PPC指令的操作，例如分支指令、加载/存储指令等。

**与JavaScript功能的关联及JavaScript示例：**

模拟器在V8中扮演着让JavaScript代码能够在非PPC架构上运行的关键角色。当V8需要在一个非PPC的平台上执行为PPC架构编译的JavaScript代码时（例如在开发或测试阶段），它会使用这个模拟器。

以下是一个简单的JavaScript例子，并解释模拟器如何参与其执行：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // 输出 15
```

**在模拟器中的执行流程可能如下：**

1. **编译：** V8的编译器（例如TurboFan或Crankshaft）会将这段JavaScript代码编译成针对PPC架构的机器码。
2. **模拟器介入：** 当V8尝试在非PPC平台上执行这段PPC机器码时，模拟器就会被激活。
3. **指令获取与执行：** 模拟器会逐条读取编译后的PPC指令。例如，对于 `a + b` 这个操作，可能会有PPC的加法指令被读取。
4. **寄存器操作：** 模拟器会根据指令操作模拟的PPC寄存器。例如，`a` 和 `b` 的值可能被加载到模拟的通用寄存器中。
5. **算术运算：** 模拟器会执行加法操作，并将结果存储到另一个模拟的寄存器中。
6. **函数调用：** 对于 `console.log(result)`，模拟器会遇到一个调用V8运行时函数的指令。
7. **软件中断：** 模拟器会触发一个软件中断 (`SoftwareInterrupt`)。
8. **运行时调用：** 模拟器的软件中断处理程序会识别这是一个对V8运行时函数的调用，并将控制权转移到相应的C++运行时函数（用于实现 `console.log` 的功能）。
9. **结果返回：** 运行时函数执行完毕后，会将结果返回给模拟器。
10. **继续执行：** 模拟器会继续执行后续的PPC指令。

**总结来说，这个`simulator-ppc.cc`文件是V8引擎在非PPC平台上执行JavaScript代码的关键组成部分，它通过软件模拟PPC硬件的行为，使得为PPC架构编译的JavaScript代码能够正确运行。**

### 提示词
```
这是目录为v8/src/execution/ppc/simulator-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/ppc/simulator-ppc.h"

#if defined(USE_SIMULATOR)

#include <stdarg.h>
#include <stdlib.h>

#include <cmath>

#include "src/base/bits.h"
#include "src/base/lazy-instance.h"
#include "src/base/overflowing-math.h"
#include "src/base/platform/memory.h"
#include "src/base/platform/platform.h"
#include "src/codegen/assembler.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/ppc/constants-ppc.h"
#include "src/codegen/register-configuration.h"
#include "src/diagnostics/disasm.h"
#include "src/execution/ppc/frame-constants-ppc.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-inl.h"  // For CodeSpaceMemoryModificationScope.
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/utils/ostreams.h"

// Only build the simulator if not compiling for real PPC hardware.
namespace v8 {
namespace internal {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(Simulator::GlobalMonitor,
                                Simulator::GlobalMonitor::Get)

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent way through
// ::v8::internal::OS in the same way as SNPrintF is that the
// Windows C Run-Time Library does not provide vsscanf.
#define SScanF sscanf

// The PPCDebugger class is used by the simulator while debugging simulated
// PowerPC code.
class PPCDebugger {
 public:
  explicit PPCDebugger(Simulator* sim) : sim_(sim) {}
  void Debug();

 private:
  static const Instr kBreakpointInstr = (TWI | 0x1F * B21);
  static const Instr kNopInstr = (ORI);  // ori, 0,0,0

  Simulator* sim_;

  intptr_t GetRegisterValue(int regnum);
  double GetRegisterPairDoubleValue(int regnum);
  double GetFPDoubleRegisterValue(int regnum);
  bool GetValue(const char* desc, intptr_t* value);
  bool GetFPDoubleValue(const char* desc, double* value);

  // Set or delete breakpoint (there can be only one).
  bool SetBreakpoint(Instruction* break_pc);
  void DeleteBreakpoint();

  // Undo and redo the breakpoint. This is needed to bracket disassembly and
  // execution to skip past the breakpoint when run from the debugger.
  void UndoBreakpoint();
  void RedoBreakpoint();
};

void Simulator::DebugAtNextPC() {
  PrintF("Starting debugger on the next instruction:\n");
  set_pc(get_pc() + kInstrSize);
  PPCDebugger(this).Debug();
}

intptr_t PPCDebugger::GetRegisterValue(int regnum) {
  return sim_->get_register(regnum);
}

double PPCDebugger::GetRegisterPairDoubleValue(int regnum) {
  return sim_->get_double_from_register_pair(regnum);
}

double PPCDebugger::GetFPDoubleRegisterValue(int regnum) {
  return sim_->get_double_from_d_register(regnum);
}

bool PPCDebugger::GetValue(const char* desc, intptr_t* value) {
  int regnum = Registers::Number(desc);
  if (regnum != kNoRegister) {
    *value = GetRegisterValue(regnum);
    return true;
  }
  if (strncmp(desc, "0x", 2) == 0) {
    return SScanF(desc + 2, "%" V8PRIxPTR,
                  reinterpret_cast<uintptr_t*>(value)) == 1;
  }
  return SScanF(desc, "%" V8PRIuPTR, reinterpret_cast<uintptr_t*>(value)) == 1;
}

bool PPCDebugger::GetFPDoubleValue(const char* desc, double* value) {
  int regnum = DoubleRegisters::Number(desc);
  if (regnum != kNoRegister) {
    *value = sim_->get_double_from_d_register(regnum);
    return true;
  }
  return false;
}

bool PPCDebugger::SetBreakpoint(Instruction* break_pc) {
  // Check if a breakpoint can be set. If not return without any side-effects.
  if (sim_->break_pc_ != nullptr) {
    return false;
  }

  // Set the breakpoint.
  sim_->break_pc_ = break_pc;
  sim_->break_instr_ = break_pc->InstructionBits();
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

void PPCDebugger::DeleteBreakpoint() {
  UndoBreakpoint();
  sim_->break_pc_ = nullptr;
  sim_->break_instr_ = 0;
}

void PPCDebugger::UndoBreakpoint() {
  if (sim_->break_pc_ != nullptr) {
    SetInstructionBitsInCodeSpace(sim_->break_pc_, sim_->break_instr_,
                                  sim_->isolate_->heap());
  }
}

void PPCDebugger::RedoBreakpoint() {
  if (sim_->break_pc_ != nullptr) {
    SetInstructionBitsInCodeSpace(sim_->break_pc_, kBreakpointInstr,
                                  sim_->isolate_->heap());
  }
}

void PPCDebugger::Debug() {
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

  // make sure to have a proper terminating character if reaching the limit
  cmd[COMMAND_SIZE] = 0;
  arg1[ARG_SIZE] = 0;
  arg2[ARG_SIZE] = 0;

  // Unset breakpoint while running in the debugger shell, making it invisible
  // to all commands.
  UndoBreakpoint();
  // Disable tracing while simulating
  bool trace = v8_flags.trace_sim;
  v8_flags.trace_sim = false;

  while (!done && !sim_->has_bad_pc()) {
    if (last_pc != sim_->get_pc()) {
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      // use a reasonably large buffer
      v8::base::EmbeddedVector<char, 256> buffer;
      dasm.InstructionDecode(buffer,
                             reinterpret_cast<uint8_t*>(sim_->get_pc()));
      PrintF("  0x%08" V8PRIxPTR "  %s\n", sim_->get_pc(), buffer.begin());
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
        intptr_t value;

        // If at a breakpoint, proceed past it.
        if ((reinterpret_cast<Instruction*>(sim_->get_pc()))
                ->InstructionBits() == 0x7D821008) {
          sim_->set_pc(sim_->get_pc() + kInstrSize);
        } else {
          sim_->ExecuteInstruction(
              reinterpret_cast<Instruction*>(sim_->get_pc()));
        }

        if (argc == 2 && last_pc != sim_->get_pc() && GetValue(arg1, &value)) {
          for (int i = 1; i < value; i++) {
            disasm::NameConverter converter;
            disasm::Disassembler dasm(converter);
            // use a reasonably large buffer
            v8::base::EmbeddedVector<char, 256> buffer;
            dasm.InstructionDecode(buffer,
                                   reinterpret_cast<uint8_t*>(sim_->get_pc()));
            PrintF("  0x%08" V8PRIxPTR "  %s\n", sim_->get_pc(),
                   buffer.begin());
            sim_->ExecuteInstruction(
                reinterpret_cast<Instruction*>(sim_->get_pc()));
          }
        }
      } else if ((strcmp(cmd, "c") == 0) || (strcmp(cmd, "cont") == 0)) {
        // If at a breakpoint, proceed past it.
        if ((reinterpret_cast<Instruction*>(sim_->get_pc()))
                ->InstructionBits() == 0x7D821008) {
          sim_->set_pc(sim_->get_pc() + kInstrSize);
        } else {
          // Execute the one instruction we broke at with breakpoints disabled.
          sim_->ExecuteInstruction(
              reinterpret_cast<Instruction*>(sim_->get_pc()));
        }
        // Leave the debugger shell.
        done = true;
      } else if ((strcmp(cmd, "p") == 0) || (strcmp(cmd, "print") == 0)) {
        if (argc == 2 || (argc == 3 && strcmp(arg2, "fp") == 0)) {
          intptr_t value;
          double dvalue;
          if (strcmp(arg1, "all") == 0) {
            for (int i = 0; i < kNumRegisters; i++) {
              value = GetRegisterValue(i);
              PrintF("    %3s: %08" V8PRIxPTR,
                     RegisterName(Register::from_code(i)), value);
              if ((argc == 3 && strcmp(arg2, "fp") == 0) && i < 8 &&
                  (i % 2) == 0) {
                dvalue = GetRegisterPairDoubleValue(i);
                PrintF(" (%f)\n", dvalue);
              } else if (i != 0 && !((i + 1) & 3)) {
                PrintF("\n");
              }
            }
            PrintF("  pc: %08" V8PRIxPTR "  lr: %08" V8PRIxPTR
                   "  "
                   "ctr: %08" V8PRIxPTR "  xer: %08x  cr: %08x\n",
                   sim_->special_reg_pc_, sim_->special_reg_lr_,
                   sim_->special_reg_ctr_, sim_->special_reg_xer_,
                   sim_->condition_reg_);
          } else if (strcmp(arg1, "alld") == 0) {
            for (int i = 0; i < kNumRegisters; i++) {
              value = GetRegisterValue(i);
              PrintF("     %3s: %08" V8PRIxPTR " %11" V8PRIdPTR,
                     RegisterName(Register::from_code(i)), value, value);
              if ((argc == 3 && strcmp(arg2, "fp") == 0) && i < 8 &&
                  (i % 2) == 0) {
                dvalue = GetRegisterPairDoubleValue(i);
                PrintF(" (%f)\n", dvalue);
              } else if (!((i + 1) % 2)) {
                PrintF("\n");
              }
            }
            PrintF("   pc: %08" V8PRIxPTR "  lr: %08" V8PRIxPTR
                   "  "
                   "ctr: %08" V8PRIxPTR "  xer: %08x  cr: %08x\n",
                   sim_->special_reg_pc_, sim_->special_reg_lr_,
                   sim_->special_reg_ctr_, sim_->special_reg_xer_,
                   sim_->condition_reg_);
          } else if (strcmp(arg1, "allf") == 0) {
            for (int i = 0; i < DoubleRegister::kNumRegisters; i++) {
              dvalue = GetFPDoubleRegisterValue(i);
              uint64_t as_words = base::bit_cast<uint64_t>(dvalue);
              PrintF("%3s: %f 0x%08x %08x\n",
                     RegisterName(DoubleRegister::from_code(i)), dvalue,
                     static_cast<uint32_t>(as_words >> 32),
                     static_cast<uint32_t>(as_words & 0xFFFFFFFF));
            }
          } else if (arg1[0] == 'r' &&
                     (arg1[1] >= '0' && arg1[1] <= '9' &&
                      (arg1[2] == '\0' || (arg1[2] >= '0' && arg1[2] <= '9' &&
                                           arg1[3] == '\0')))) {
            int regnum = strtoul(&arg1[1], 0, 10);
            if (regnum != kNoRegister) {
              value = GetRegisterValue(regnum);
              PrintF("%s: 0x%08" V8PRIxPTR " %" V8PRIdPTR "\n", arg1, value,
                     value);
            } else {
              PrintF("%s unrecognized\n", arg1);
            }
          } else {
            if (GetValue(arg1, &value)) {
              PrintF("%s: 0x%08" V8PRIxPTR " %" V8PRIdPTR "\n", arg1, value,
                     value);
            } else if (GetFPDoubleValue(arg1, &dvalue)) {
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
      } else if ((strcmp(cmd, "po") == 0) ||
                 (strcmp(cmd, "printobject") == 0)) {
        if (argc == 2) {
          intptr_t value;
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
      } else if (strcmp(cmd, "setpc") == 0) {
        intptr_t value;

        if (!GetValue(arg1, &value)) {
          PrintF("%s unrecognized\n", arg1);
          continue;
        }
        sim_->set_pc(value);
      } else if (strcmp(cmd, "stack") == 0 || strcmp(cmd, "mem") == 0 ||
                 strcmp(cmd, "dump") == 0) {
        intptr_t* cur = nullptr;
        intptr_t* end = nullptr;
        int next_arg = 1;

        if (strcmp(cmd, "stack") == 0) {
          cur = reinterpret_cast<intptr_t*>(sim_->get_register(Simulator::sp));
        } else {  // "mem"
          intptr_t value;
          if (!GetValue(arg1, &value)) {
            PrintF("%s unrecognized\n", arg1);
            continue;
          }
          cur = reinterpret_cast<intptr_t*>(value);
          next_arg++;
        }

        intptr_t words;  // likely inaccurate variable name for 64bit
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
          PrintF("  0x%08" V8PRIxPTR ":  0x%08" V8PRIxPTR " %10" V8PRIdPTR,
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
            intptr_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(value);
              // Disassemble 10 instructions at <arg1>.
              end = cur + (10 * kInstrSize);
            }
          } else {
            // The argument is the number of instructions.
            intptr_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
              // Disassemble <arg1> instructions.
              end = cur + (value * kInstrSize);
            }
          }
        } else {
          intptr_t value1;
          intptr_t value2;
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
          intptr_t value;
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
        DeleteBreakpoint();
      } else if (strcmp(cmd, "cr") == 0) {
        PrintF("Condition reg: %08x\n", sim_->condition_reg_);
      } else if (strcmp(cmd, "lr") == 0) {
        PrintF("Link reg: %08" V8PRIxPTR "\n", sim_->special_reg_lr_);
      } else if (strcmp(cmd, "ctr") == 0) {
        PrintF("Ctr reg: %08" V8PRIxPTR "\n", sim_->special_reg_ctr_);
      } else if (strcmp(cmd, "xer") == 0) {
        PrintF("XER: %08x\n", sim_->special_reg_xer_);
      } else if (strcmp(cmd, "fpscr") == 0) {
        PrintF("FPSCR: %08x\n", sim_->fp_condition_reg_);
      } else if (strcmp(cmd, "stop") == 0) {
        intptr_t value;
        intptr_t stop_pc = sim_->get_pc() - (kInstrSize + kSystemPointerSize);
        Instruction* stop_instr = reinterpret_cast<Instruction*>(stop_pc);
        Instruction* msg_address =
            reinterpret_cast<Instruction*>(stop_pc + kInstrSize);
        if ((argc == 2) && (strcmp(arg1, "unstop") == 0)) {
          // Remove the current stop.
          if (sim_->isStopInstruction(stop_instr)) {
            SetInstructionBitsInCodeSpace(stop_instr, kNopInstr,
                                          sim_->isolate_->heap());
            msg_address->SetInstructionBits(kNopInstr);
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
        v8_flags.trace_sim = !v8_flags.trace_sim;
        PrintF("Trace of executed instructions is %s\n",
               v8_flags.trace_sim ? "on" : "off");
      } else if ((strcmp(cmd, "h") == 0) || (strcmp(cmd, "help") == 0)) {
        PrintF("cont\n");
        PrintF("  continue execution (alias 'c')\n");
        PrintF("stepi [num instructions]\n");
        PrintF("  step one/num instruction(s) (alias 'si')\n");
        PrintF("print <register>\n");
        PrintF("  print register content (alias 'p')\n");
        PrintF("  use register name 'all' to display all integer registers\n");
        PrintF(
            "  use register name 'alld' to display integer registers "
            "with decimal values\n");
        PrintF("  use register name 'rN' to display register number 'N'\n");
        PrintF("  add argument 'fp' to print register pair double values\n");
        PrintF(
            "  use register name 'allf' to display floating-point "
            "registers\n");
        PrintF("printobject <register>\n");
        PrintF("  print an object from a register (alias 'po')\n");
        PrintF("cr\n");
        PrintF("  print condition register\n");
        PrintF("lr\n");
        PrintF("  print link register\n");
        PrintF("ctr\n");
        PrintF("  print ctr register\n");
        PrintF("xer\n");
        PrintF("  print XER\n");
        PrintF("fpscr\n");
        PrintF("  print FPSCR\n");
        PrintF("stack [<num words>]\n");
        PrintF("  dump stack content, default dump 10 words)\n");
        PrintF("mem <address> [<num words>]\n");
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
        PrintF("del\n");
        PrintF("  delete the breakpoint\n");
        PrintF("trace (alias 't')\n");
        PrintF("  toogle the tracing of all executed statements\n");
        PrintF("stop feature:\n");
        PrintF("  Description:\n");
        PrintF("    Stops are debug instructions inserted by\n");
        PrintF("    the Assembler::stop() function.\n");
        PrintF("    When hitting a stop, the Simulator will\n");
        PrintF("    stop and give control to the PPCDebugger.\n");
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
    }
  }

  // Reinstall breakpoint to stop execution and enter the debugger shell when
  // hit.
  RedoBreakpoint();
  // Restore tracing
  v8_flags.trace_sim = trace;

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

static bool AllOnOnePage(uintptr_t start, int size) {
  intptr_t start_page = (start & ~CachePage::kPageMask);
  intptr_t end_page = ((start + size) & ~CachePage::kPageMask);
  return start_page == end_page;
}

static bool is_snan(float input) {
  uint32_t kQuietNanFPBit = 1 << 22;
  uint32_t InputAsUint = base::bit_cast<uint32_t>(input);
  return isnan(input) && ((InputAsUint & kQuietNanFPBit) == 0);
}

static bool is_snan(double input) {
  uint64_t kQuietNanDPBit = 1L << 51;
  uint64_t InputAsUint = base::bit_cast<uint64_t>(input);
  return isnan(input) && ((InputAsUint & kQuietNanDPBit) == 0);
}

void Simulator::set_last_debugger_input(char* input) {
  DeleteArray(last_debugger_input_);
  last_debugger_input_ = input;
}

void Simulator::SetRedirectInstruction(Instruction* instruction) {
  instruction->SetInstructionBits(rtCallRedirInstr | kCallRtRedirected);
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
    DCHECK_EQ(0, static_cast<int>(start & CachePage::kPageMask));
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
  stack_ = reinterpret_cast<uint8_t*>(base::Malloc(AllocatedStackSize()));
  pc_modified_ = false;
  icount_ = 0;
  break_pc_ = nullptr;
  break_instr_ = 0;

  // Set up architecture state.
  // All registers are initialized to zero to start with.
  for (int i = 0; i < kNumGPRs; i++) {
    registers_[i] = 0;
  }
  condition_reg_ = 0;
  fp_condition_reg_ = 0;
  special_reg_pc_ = 0;
  special_reg_lr_ = 0;
  special_reg_ctr_ = 0;

  // Initializing FP registers.
  for (int i = 0; i < kNumFPRs; i++) {
    fp_registers_[i] = 0.0;
  }

  // The sp is initialized to point to the bottom (high address) of the
  // allocated stack area. To be safe in potential stack underflows we leave
  // some buffer below.
  registers_[sp] = reinterpret_cast<intptr_t>(stack_) + UsableStackSize();

  last_debugger_input_ = nullptr;
}

Simulator::~Simulator() { base::Free(stack_); }

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

// Sets the register in the architecture state.
void Simulator::set_register(int reg, intptr_t value) {
  DCHECK((reg >= 0) && (reg < kNumGPRs));
  registers_[reg] = value;
}

// Get the register from the architecture state.
intptr_t Simulator::get_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumGPRs));
  // Stupid code added to avoid bug in GCC.
  // See: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=43949
  if (reg >= kNumGPRs) return 0;
  // End stupid code.
  return registers_[reg];
}

double Simulator::get_double_from_register_pair(int reg) {
  DCHECK((reg >= 0) && (reg < kNumGPRs) && ((reg % 2) == 0));

  double dm_val = 0.0;
  return (dm_val);
}

// Raw access to the PC register.
void Simulator::set_pc(intptr_t value) {
  pc_modified_ = true;
  special_reg_pc_ = value;
}

bool Simulator::has_bad_pc() const {
  return ((special_reg_pc_ == bad_lr) || (special_reg_pc_ == end_sim_pc));
}

// Raw access to the PC register without the special adjustment when reading.
intptr_t Simulator::get_pc() const { return special_reg_pc_; }

// Accessor to the internal Link Register
intptr_t Simulator::get_lr() const { return special_reg_lr_; }

// Runtime FP routines take:
// - two double arguments
// - one double argument and zero or one integer arguments.
// All are consructed here from d1, d2 and r3.
void Simulator::GetFpArgs(double* x, double* y, intptr_t* z) {
  *x = get_double_from_d_register(1);
  *y = get_double_from_d_register(2);
  *z = get_register(3);
}

// The return value is in d1.
void Simulator::SetFpResult(const double& result) {
  set_d_register_from_double(1, result);
}

void Simulator::TrashCallerSaveRegisters() {
// We don't trash the registers with the return value.
#if 0  // A good idea to trash volatile registers, needs to be done
  registers_[2] = 0x50BAD4U;
  registers_[3] = 0x50BAD4U;
  registers_[12] = 0x50BAD4U;
#endif
}

#define GENERATE_RW_FUNC(size, type)                             \
  type Simulator::Read##size(uintptr_t addr) {                   \
    type value;                                                  \
    Read(addr, &value);                                          \
    return value;                                                \
  }                                                              \
  type Simulator::ReadEx##size(uintptr_t addr) {                 \
    type value;                                                  \
    ReadEx(addr, &value);                                        \
    return value;                                                \
  }                                                              \
  void Simulator::Write##size(uintptr_t addr, type value) {      \
    Write(addr, value);                                          \
  }                                                              \
  int32_t Simulator::WriteEx##size(uintptr_t addr, type value) { \
    return WriteEx(addr, value);                                 \
  }

RW_VAR_LIST(GENERATE_RW_FUNC)
#undef GENERATE_RW_FUNC

// Returns the limit of the stack area to enable checking for stack overflows.
uintptr_t Simulator::StackLimit(uintptr_t c_limit) const {
  // The simulator uses a separate JS stack. If we have exhausted the C stack,
  // we also drop down the JS limit to reflect the exhaustion on the JS stack.
  if (base::Stack::GetCurrentStackPosition() < c_limit) {
    return reinterpret_cast<uintptr_t>(get_sp());
  }

  // Otherwise the limit is the JS stack. Leave a safety margin to prevent
  // overrunning the stack when pushing values.
  return reinterpret_cast<uintptr_t>(stack_) + kStackProtectionSize;
}

base::Vector<uint8_t> Simulator::GetCentralStackView() const {
  // We do not add an additional safety margin as above in
  // Simulator::StackLimit, as this is currently only used in wasm::StackMemory,
  // which adds its own margin.
  return base::VectorOf(stack_, UsableStackSize());
}

// Unsupported instructions use Format to print an error and stop execution.
void Simulator::Format(Instruction* instr, const char* format) {
  PrintF("Simulator found unsupported instruction:\n 0x%08" V8PRIxPTR ": %s\n",
         reinterpret_cast<intptr_t>(instr), format);
  UNIMPLEMENTED();
}

// Calculate C flag value for additions.
bool Simulator::CarryFrom(int32_t left, int32_t right, int32_t carry) {
  uint32_t uleft = static_cast<uint32_t>(left);
  uint32_t uright = static_cast<uint32_t>(right);
  uint32_t urest = 0xFFFFFFFFU - uleft;

  return (uright > urest) ||
         (carry && (((uright + 1) > urest) || (uright > (urest - 1))));
}

// Calculate C flag value for subtractions.
bool Simulator::BorrowFrom(int32_t left, int32_t right) {
  uint32_t uleft = static_cast<uint32_t>(left);
  uint32_t uright = static_cast<uint32_t>(right);

  return (uright > uleft);
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

static void decodeObjectPair(ObjectPair* pair, intptr_t* x, intptr_t* y) {
  *x = static_cast<intptr_t>(pair->x);
  *y = static_cast<intptr_t>(pair->y);
}

// Calls into the V8 runtime.
using SimulatorRuntimeCall = intptr_t (*)(
    intptr_t arg0, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4,
    intptr_t arg5, intptr_t arg6, intptr_t arg7, intptr_t arg8, intptr_t arg9,
    intptr_t arg10, intptr_t arg11, intptr_t arg12, intptr_t arg13,
    intptr_t arg14, intptr_t arg15, intptr_t arg16, intptr_t arg17,
    intptr_t arg18, intptr_t arg19);
using SimulatorRuntimePairCall = ObjectPair (*)(
    intptr_t arg0, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4,
    intptr_t arg5, intptr_t arg6, intptr_t arg7, intptr_t arg8, intptr_t arg9,
    intptr_t arg10, intptr_t arg11, intptr_t arg12, intptr_t arg13,
    intptr_t arg14, intptr_t arg15, intptr_t arg16, intptr_t arg17,
    intptr_t arg18, intptr_t arg19);

// These prototypes handle the four types of FP calls.
using SimulatorRuntimeCompareCall = int (*)(double darg0, double darg1);
using SimulatorRuntimeFPFPCall = double (*)(double darg0, double darg1);
using SimulatorRuntimeFPCall = double (*)(double darg0);
using SimulatorRuntimeFPIntCall = double (*)(double darg0, intptr_t arg0);
// Define four args for future flexibility; at the time of this writing only
// one is ever used.
using SimulatorRuntimeFPTaggedCall = double (*)(int32_t arg0, int32_t arg1,
                                                int32_t arg2, int32_t arg3);

// This signature supports direct call in to API function native callback
// (refer to InvocationCallback in v8.h).
using SimulatorRuntimeDirectApiCall = void (*)(intptr_t arg0);

// This signature supports direct call to accessor getter callback.
using SimulatorRuntimeDirectGetterCall = void (*)(intptr_t arg0, intptr_t arg1);

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
      const int kArgCount = 20;
      const int kRegisterArgCount = 8;
      int arg0_regnum = 3;
      intptr_t result_buffer = 0;
      bool uses_result_buffer =
          (redirection->type() == ExternalReference::BUILTIN_CALL_PAIR &&
           !ABI_RETURNS_OBJECT_PAIRS_IN_REGS);
      if (uses_result_buffer) {
        result_buffer = get_register(r3);
        arg0_regnum++;
      }
      intptr_t arg[kArgCount];
      // First eight arguments in registers r3-r10.
      for (int i = 0; i < kRegisterArgCount; i++) {
        arg[i] = get_register(arg0_regnum + i);
      }
      intptr_t* stack_pointer = reinterpret_cast<intptr_t*>(get_register(sp));
      // Remaining argument on stack
      for (int i = kRegisterArgCount, j = 0; i < kArgCount; i++, j++) {
        arg[i] = stack_pointer[kStackFrameExtraParamSlot + j];
      }
      static_assert(kArgCount == kRegisterArgCount + 12);
      static_assert(kMaxCParameters == kArgCount);
      bool fp_call =
          (redirection->type() == ExternalReference::BUILTIN_FP_FP_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_COMPARE_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_FP_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_FP_INT_CALL);
      // This is dodgy but it works because the C entry stubs are never moved.
      // See comment in codegen-arm.cc and bug 1242173.
      intptr_t saved_lr = special_reg_lr_;
      intptr_t external =
          reinterpret_cast<intptr_t>(redirection->external_function());
      if (fp_call) {
        double dval0, dval1;  // one or two double parameters
        intptr_t ival;        // zero or one integer parameters
        int iresult = 0;      // integer return value
        double dresult = 0;   // double return value
        GetFpArgs(&dval0, &dval1, &ival);
        if (v8_flags.trace_sim || !stack_aligned) {
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
              PrintF("Call to host function at %p with args %f, %" V8PRIdPTR,
                     reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                     dval0, ival);
              break;
            default:
              UNREACHABLE();
          }
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        switch (redirection->type()) {
          case ExternalReference::BUILTIN_COMPARE_CALL: {
            SimulatorRuntimeCompareCall target =
                reinterpret_cast<SimulatorRuntimeCompareCall>(external);
            iresult = target(dval0, dval1);
            set_register(r3, iresult);
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
              PrintF("Returned %08x\n", iresult);
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
        if (v8_flags.trace_sim || !stack_aligned) {
          PrintF("Call to host function at %p args %08" V8PRIxPTR,
                 reinterpret_cast<void*>(external), arg[0]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeFPTaggedCall target =
            reinterpret_cast<SimulatorRuntimeFPTaggedCall>(external);
        double dresult = target(arg[0], arg[1], arg[2], arg[3]);
#ifdef DEBUG
        TrashCallerSaveRegisters();
#endif
        SetFpResult(dresult);
        if (v8_flags.trace_sim) {
          PrintF("Returned %f\n", dresult);
        }
      } else if (redirection->type() == ExternalReference::DIRECT_API_CALL) {
        // See callers of MacroAssembler::CallApiFunctionAndReturn for
        // explanation of register usage.
        // void f(v8::FunctionCallbackInfo&)
        if (v8_flags.trace_sim || !stack_aligned) {
          PrintF("Call to host function at %p args %08" V8PRIxPTR,
                 reinterpret_cast<void*>(external), arg[0]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeDirectApiCall target =
            reinterpret_cast<SimulatorRuntimeDirectApiCall>(external);
        target(arg[0]);
      } else if (redirection->type() == ExternalReference::DIRECT_GETTER_CALL) {
        // See callers of MacroAssembler::CallApiFunctionAndReturn for
        // explanation of register usage.
        // void f(v8::Local<String> property, v8::PropertyCallbackInfo& info)
        if (v8_flags.trace_sim || !stack_aligned) {
          PrintF("Call to host function at %p args %08" V8PRIxPTR
                 " %08" V8PRIxPTR,
                 reinterpret_cast<void*>(external), arg[0], arg[1]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeDirectGetterCall target =
            reinterpret_cast<SimulatorRuntimeDirectGetterCall>(external);
        if (!ABI_PASSES_HANDLES_IN_REGS) {
          arg[0] = base::bit_cast<intptr_t>(arg[0]);
        }
        target(arg[0], arg[1]);
      } else {
        // builtin call.
        if (v8_flags.trace_sim || !stack_aligned) {
          SimulatorRuntimeCall target =
              reinterpret_cast<SimulatorRuntimeCall>(external);
          PrintF(
              "Call to host function at %p,\n"
              "\t\t\t\targs %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR,
              reinterpret_cast<void*>(FUNCTION_ADDR(target)), arg[0], arg[1],
              arg[2], arg[3], arg[4], arg[5], arg[6], arg[7], arg[8], arg[9],
              arg[10], arg[11], arg[12], arg[13], arg[14], arg[15], arg[16],
              arg[17], arg[18], arg[19]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        if (redirection->type() == ExternalReference::BUILTIN_CALL_PAIR) {
          SimulatorRuntimePairCall target =
              reinterpret_cast<SimulatorRuntimePairCall>(external);
          ObjectPair result =
              target(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6],
                     arg[7], arg[8], arg[9], arg[10], arg[11], arg[12], arg[13],
                     arg[14], arg[15], arg[16], arg[17], arg[18], arg[19]);
          intptr_t x;
          intptr_t y;
          decodeObjectPair(&result, &x, &y);
          if (v8_flags.trace_sim) {
            PrintF("Returned {%08" V8PRIxPTR ", %08" V8PRIxPTR "}\n", x, y);
          }
          if (ABI_RETURNS_OBJECT_PAIRS_IN_REGS) {
            set_register(r3, x);
            set_register(r4, y);
          } else {
            memcpy(reinterpret_cast<void*>(result_buffer), &result,
                   sizeof(ObjectPair));
            set_register(r3, result_buffer);
          }
        } else {
          // FAST_C_CALL is temporarily handled here as well, because we lack
          // proper support for direct C calls with FP params in the simulator.
          // The generic BUILTIN_CALL path assumes all parameters are passed in
          // the GP registers, thus supporting calling the slow callback without
          // crashing. The reason for that is that in the mjsunit tests we check
          // the `fast_c_api.supports_fp_params` (which is false on
          // non-simulator builds for arm/arm64), thus we expect that the slow
          // path will be called. And since the slow path passes the arguments
          // as a `const FunctionCallbackInfo<Value>&` (which is a GP argument),
          // the call is made correctly.
          DCHECK(redirection->type() == ExternalReference::BUILTIN_CALL ||
                 redirection->type() == ExternalReference::FAST_C_CALL);
          SimulatorRuntimeCall target =
              reinterpret_cast<SimulatorRuntimeCall>(external);
          intptr_t result =
              target(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6],
                     arg[7], arg[8], arg[9], arg[10], arg[11], arg[12], arg[13],
                     arg[14], arg[15], arg[16], arg[17], arg[18], arg[19]);
          if (v8_flags.trace_sim) {
            PrintF("Returned %08" V8PRIxPTR "\n", result);
          }
          set_register(r3, result);
        }
      }
      set_pc(saved_lr);
      break;
    }
    case kBreakpoint:
      PPCDebugger(this).Debug();
      break;
    // stop uses all codes greater than 1 << 23.
    default:
      if (svc >= (1 << 23)) {
        uint32_t code = svc & kStopCodeMask;
        if (isWatchedStop(code)) {
          IncreaseStopCounter(code);
        }
        // Stop if it is enabled, otherwise go on jumping over the stop
        // and the message address.
        if (isEnabledStop(code)) {
          if (code != kMaxStopCode) {
            PrintF("Simulator hit stop %u. ", code);
          } else {
            PrintF("Simulator hit stop. ");
          }
          DebugAtNextPC();
        } else {
          set_pc(get_pc() + kInstrSize + kSystemPointerSize);
        }
      } else {
        // This is not a valid svc code.
        UNREACHABLE();
      }
  }
}

// Stop helper functions.
bool Simulator::isStopInstruction(Instruction* instr) {
  return (instr->Bits(27, 24) == 0xF) && (instr->SvcValue() >= kStopCode);
}

bool Simulator::isWatchedStop(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  return code < kNumOfWatchedStops;
}

bool Simulator::isEnabledStop(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  // Unwatched stops are always enabled.
  return !isWatchedStop(code) ||
         !(watched_stops_[code].count & kStopDisabledBit);
}

void Simulator::EnableStop(uint32_t code) {
  DCHECK(isWatchedStop(code));
  if (!isEnabledStop(code)) {
    watched_stops_[code].count &= ~kStopDisabledBit;
  }
}

void Simulator::DisableStop(uint32_t code) {
  DCHECK(isWatchedStop(code));
  if (isEnabledStop(code)) {
    watched_stops_[code].count |= kStopDisabledBit;
  }
}

void Simulator::IncreaseStopCounter(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  DCHECK(isWatchedStop(code));
  if ((watched_stops_[code].count & ~(1 << 31)) == 0x7FFFFFFF) {
    PrintF(
        "Stop counter for code %i has overflowed.\n"
        "Enabling this code and reseting the counter to 0.\n",
        code);
    watched_stops_[code].count = 0;
    EnableStop(code);
  } else {
    watched_stops_[code].count++;
  }
}

// Print a stop status.
void Simulator::PrintStopInfo(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  if (!isWatchedStop(code)) {
    PrintF("Stop not watched.");
  } else {
    const char* state = isEnabledStop(code) ? "Enabled" : "Disabled";
    int32_t count = watched_stops_[code].count & ~kStopDisabledBit;
    // Don't print the state of unused breakpoints.
    if (count != 0) {
      if (watched_stops_[code].desc) {
        PrintF("stop %i - 0x%x: \t%s, \tcounter = %i, \t%s\n", code, code,
               state, count, watched_stops_[code].desc);
      } else {
        PrintF("stop %i - 0x%x: \t%s, \tcounter = %i\n", code, code, state,
               count);
      }
    }
  }
}

void Simulator::SetCR0(intptr_t result, bool setSO) {
  int bf = 0;
  if (result < 0) {
    bf |= 0x80000000;
  }
  if (result > 0) {
    bf |= 0x40000000;
  }
  if (result == 0) {
    bf |= 0x20000000;
  }
  if (setSO) {
    bf |= 0x10000000;
  }
  condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
}

void Simulator::SetCR6(bool true_for_all) {
  int32_t clear_cr6_mask = 0xFFFFFF0F;
  if (true_for_all) {
    condition_reg_ = (condition_reg_ & clear_cr6_mask) | 0x80;
  } else {
    condition_reg_ = (condition_reg_ & clear_cr6_mask) | 0x20;
  }
}

void Simulator::ExecuteBranchConditional(Instruction* instr, BCType type) {
  int bo = instr->Bits(25, 21) << 21;
  int condition_bit = instr->Bits(20, 16);
  int condition_mask = 0x80000000 >> condition_bit;
  switch (bo) {
    case DCBNZF:  // Decrement CTR; branch if CTR != 0 and condition false
    case DCBEZF:  // Decrement CTR; branch if CTR == 0 and condition false
      UNIMPLEMENTED();
    case BF: {  // Branch if condition false
      if (condition_reg_ & condition_mask) return;
      break;
    }
    case DCBNZT:  // Decrement CTR; branch if CTR != 0 and condition true
    case DCBEZT:  // Decrement CTR; branch if CTR == 0 and condition true
      UNIMPLEMENTED();
    case BT: {  // Branch if condition true
      if (!(condition_reg_ & condition_mask)) return;
      break;
    }
    case DCBNZ:  // Decrement CTR; branch if CTR != 0
    case DCBEZ:  // Decrement CTR; branch if CTR == 0
      special_reg_ctr_ -= 1;
      if ((special_reg_ctr_ == 0) != (bo == DCBEZ)) return;
      break;
    case BA: {  // Branch always
      break;
    }
    default:
      UNIMPLEMENTED();  // Invalid encoding
  }

  intptr_t old_pc = get_pc();

  switch (type) {
    case BC_OFFSET: {
      int offset = (instr->Bits(15, 2) << 18) >> 16;
      set_pc(old_pc + offset);
      break;
    }
    case BC_LINK_REG:
      set_pc(special_reg_lr_);
      break;
    case BC_CTR_REG:
      set_pc(special_reg_ctr_);
      break;
  }

  if (instr->Bit(0) == 1) {  // LK flag set
    special_reg_lr_ = old_pc + 4;
  }
}

// Vector instruction helpers.
#define GET_ADDRESS(a, b, a_val, b_val)          \
  intptr_t a_val = a == 0 ? 0 : get_register(a); \
  intptr_t b_val = get_register(b);
#define DECODE_VX_INSTRUCTION(d, a, b, source_or_target) \
  int d = instr->R##source_or_target##Value();           \
  int a = instr->RAValue();                              \
  int b = instr->RBValue();
#define FOR_EACH_LANE(i, type) \
  for (uint32_t i = 0; i < kSimd128Size / sizeof(type); i++)
template <typename A, typename T, typename Operation>
void VectorCompareOp(Simulator* sim, Instruction* instr, bool is_fp,
                     Operation op) {
  DECODE_VX_INSTRUCTION(t, a, b, T)
  bool true_for_all = true;
  FOR_EACH_LANE(i, A) {
    A a_val = sim->get_simd_register_by_lane<A>(a, i);
    A b_val = sim->get_simd_register_by_lane<A>(b, i);
    T t_val = 0;
    bool is_not_nan = is_fp ? !isnan(a_val) && !isnan(b_val) : true;
    if (is_not_nan && op(a_val, b_val)) {
      t_val = -1;  // Set all bits to 1 indicating true.
    } else {
      true_for_all = false;
    }
    sim->set_simd_register_by_lane<T>(t, i, t_val);
  }
  if (instr->Bit(10)) {  // RC bit set.
    sim->SetCR6(true_for_all);
  }
}

template <typename S, typename T>
void VectorConverFromFPSaturate(Simulator* sim, Instruction* instr, T min_val,
                                T max_val, bool even_lane_result = false) {
  int t = instr->RTValue();
  int b = instr->RBValue();
  FOR_EACH_LANE(i, S) {
    T t_val;
    double b_val = static_cast<double>(sim->get_simd_register_by_lane<S>(b, i));
    if (isnan(b_val)) {
      t_val = min_val;
    } else {
      // Round Towards Zero.
      b_val = std::trunc(b_val);
      if (b_val < min_val) {
        t_val = min_val;
      } else if (b_val > max_val) {
        t_val = max_val;
      } else {
        t_val = static_cast<T>(b_val);
      }
    }
    sim->set_simd_register_by_lane<T>(t, even_lane_result ? 2 * i : i, t_val);
  }
}

template <typename S, typename T>
void VectorPackSaturate(Simulator* sim, Instruction* instr, S min_val,
                        S max_val) {
  DECODE_VX_INSTRUCTION(t, a, b, T)
  int src = a;
  int count = 0;
  S value = 0;
  // Setup a temp array to avoid overwriting dst mid loop.
  T temps[kSimd128Size / sizeof(T)] = {0};
  for (size_t i = 0; i < kSimd128Size / sizeof(T); i++, count++) {
    if (count == kSimd128Size / sizeof(S)) {
      src = b;
      count = 0;
    }
    value = sim->get_simd_register_by_lane<S>(src, count);
    if (value > max_val) {
      value = max_val;
    } else if (value < min_val) {
      value = min_val;
    }
    temps[i] = static_cast<T>(value);
  }
  FOR_EACH_LANE(i, T) { sim->set_simd_register_by_lane<T>(t, i, temps[i]); }
}

template <typename T>
T VSXFPMin(T x, T y) {
  // Handle NaN.
  // TODO(miladfarca): include the payload of src1.
  if (std::isnan(x) && std::isnan(y)) return NAN;
  // Handle +0 and -0.
  if (std::signbit(x) < std::signbit(y)) return y;
  if (std::signbit(y) < std::signbit(x)) return x;
  return std::fmin(x, y);
}

template <typename T>
T VSXFPMax(T x, T y) {
  // Handle NaN.
  // TODO(miladfarca): include the payload of src1.
  if (std::isnan(x) && std::isnan(y)) return NAN;
  // Handle +0 and -0.
  if (std::signbit(x) < std::signbit(y)) return x;
  if (std::signbit(y) < std::signbit(x)) return y;
  return std::fmax(x, y);
}

float VMXFPMin(float x, float y) {
  // Handle NaN.
  if (std::isnan(x) || std::isnan(y)) return NAN;
  // Handle +0 and -0.
  if (std::signbit(x) < std::signbit(y)) return y;
  if (std::signbit(y) < std::signbit(x)) return x;
  return x < y ? x : y;
}

float VMXFPMax(float x, float y) {
  // Handle NaN.
  if (std::isnan(x) || std::isnan(y)) return NAN;
  // Handle +0 and -0.
  if (std::signbit(x) < std::signbit(y)) return x;
  if (std::signbit(y) < std::signbit(x)) return y;
  return x > y ? x : y;
}

void Simulator::ExecuteGeneric(Instruction* instr) {
  uint32_t opcode = instr->OpcodeBase();
  switch (opcode) {
      // Prefixed instructions.
    case PLOAD_STORE_8LS:
    case PLOAD_STORE_MLS: {
      // TODO(miladfarca): Simulate PC-relative capability indicated by the R
      // bit.
      DCHECK_NE(instr->Bit(20), 1);
      // Read prefix value.
      uint64_t prefix_value = instr->Bits(17, 0);
      // Read suffix (next instruction).
      Instruction* next_instr =
          reinterpret_cast<Instruction*>(get_pc() + kInstrSize);
      uint16_t suffix_value = next_instr->Bits(15, 0);
      int64_t im_val = SIGN_EXT_IMM34((prefix_value << 16) | suffix_value);
      switch (next_instr->OpcodeBase()) {
          // Prefixed ADDI.
        case ADDI: {
          int rt = next_instr->RTValue();
          int ra = next_instr->RAValue();
          intptr_t alu_out;
          if (ra == 0) {
            alu_out = im_val;
          } else {
            intptr_t ra_val = get_register(ra);
            alu_out = ra_val + im_val;
          }
          set_register(rt, alu_out);
          break;
        }
          // Prefixed LBZ.
        case LBZ: {
          int ra = next_instr->RAValue();
          int rt = next_instr->RTValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          set_register(rt, ReadB(ra_val + im_val) & 0xFF);
          break;
        }
          // Prefixed LHZ.
        case LHZ: {
          int ra = next_instr->RAValue();
          int rt = next_instr->RTValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          uintptr_t result = ReadHU(ra_val + im_val) & 0xFFFF;
          set_register(rt, result);
          break;
        }
          // Prefixed LHA.
        case LHA: {
          int ra = next_instr->RAValue();
          int rt = next_instr->RTValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          intptr_t result = ReadH(ra_val + im_val);
          set_register(rt, result);
          break;
        }
          // Prefixed LWZ.
        case LWZ: {
          int ra = next_instr->RAValue();
          int rt = next_instr->RTValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          set_register(rt, ReadWU(ra_val + im_val));
          break;
        }
          // Prefixed LWA.
        case PPLWA: {
          int ra = next_instr->RAValue();
          int rt = next_instr->RTValue();
          int64_t ra_val = ra == 0 ? 0 : get_register(ra);
          set_register(rt, ReadW(ra_val + im_val));
          break;
        }
          // Prefixed LD.
        case PPLD: {
          int ra = next_instr->RAValue();
          int rt = next_instr->RTValue();
          int64_t ra_val = ra == 0 ? 0 : get_register(ra);
          set_register(rt, ReadDW(ra_val + im_val));
          break;
        }
          // Prefixed LFS.
        case LFS: {
          int frt = next_instr->RTValue();
          int ra = next_instr->RAValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          int32_t val = ReadW(ra_val + im_val);
          float* fptr = reinterpret_cast<float*>(&val);
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
          // Conversion using double changes sNan to qNan on ia32/x64
          if ((val & 0x7F800000) == 0x7F800000) {
            int64_t dval = static_cast<int64_t>(val);
            dval = ((dval & 0xC0000000) << 32) | ((dval & 0x40000000) << 31) |
                   ((dval & 0x40000000) << 30) | ((dval & 0x7FFFFFFF) << 29) |
                   0x0;
            set_d_register(frt, dval);
          } else {
            set_d_register_from_double(frt, static_cast<double>(*fptr));
          }
#else
          set_d_register_from_double(frt, static_cast<double>(*fptr));
#endif
          break;
        }
          // Prefixed LFD.
        case LFD: {
          int frt = next_instr->RTValue();
          int ra = next_instr->RAValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          int64_t dptr = ReadDW(ra_val + im_val);
          set_d_register(frt, dptr);
          break;
        }
        // Prefixed STB.
        case STB: {
          int ra = next_instr->RAValue();
          int rs = next_instr->RSValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          WriteB(ra_val + im_val, get_register(rs));
          break;
        }
        // Prefixed STH.
        case STH: {
          int ra = next_instr->RAValue();
          int rs = next_instr->RSValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          WriteH(ra_val + im_val, get_register(rs));
          break;
        }
        // Prefixed STW.
        case STW: {
          int ra = next_instr->RAValue();
          int rs = next_instr->RSValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          WriteW(ra_val + im_val, get_register(rs));
          break;
        }
        // Prefixed STD.
        case PPSTD: {
          int ra = next_instr->RAValue();
          int rs = next_instr->RSValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          WriteDW(ra_val + im_val, get_register(rs));
          break;
        }
        // Prefixed STFS.
        case STFS: {
          int frs = next_instr->RSValue();
          int ra = next_instr->RAValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          float frs_val = static_cast<float>(get_double_from_d_register(frs));
          int32_t* p;
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
          // Conversion using double changes sNan to qNan on ia32/x64
          int32_t sval = 0;
          int64_t dval = get_d_register(frs);
          if ((dval & 0x7FF0000000000000) == 0x7FF0000000000000) {
            sval = ((dval & 0xC000000000000000) >> 32) |
                   ((dval & 0x07FFFFFFE0000000) >> 29);
            p = &sval;
          } else {
            p = reinterpret_cast<int32_t*>(&frs_val);
          }
#else
          p = reinterpret_cast<int32_t*>(&frs_val);
#endif
          WriteW(ra_val + im_val, *p);
          break;
        }
        // Prefixed STFD.
        case STFD: {
          int frs = next_instr->RSValue();
          int ra = next_instr->RAValue();
          intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
          int64_t frs_val = get_d_register(frs);
          WriteDW(ra_val + im_val, frs_val);
          break;
        }
        default:
          UNREACHABLE();
      }
      // We have now executed instructions at this as well as next pc.
      set_pc(get_pc() + (2 * kInstrSize));
      break;
    }
    case SUBFIC: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      intptr_t ra_val = get_register(ra);
      int32_t im_val = instr->Bits(15, 0);
      im_val = SIGN_EXT_IMM16(im_val);
      intptr_t alu_out = im_val - ra_val;
      set_register(rt, alu_out);
      // todo - handle RC bit
      break;
    }
    case CMPLI: {
      int ra = instr->RAValue();
      uint32_t im_val = instr->Bits(15, 0);
      int cr = instr->Bits(25, 23);
      uint32_t bf = 0;
      int L = instr->Bit(21);
      if (L) {
        uintptr_t ra_val = get_register(ra);
        if (ra_val < im_val) {
          bf |= 0x80000000;
        }
        if (ra_val > im_val) {
          bf |= 0x40000000;
        }
        if (ra_val == im_val) {
          bf |= 0x20000000;
        }
      } else {
        uint32_t ra_val = get_register(ra);
        if (ra_val < im_val) {
          bf |= 0x80000000;
        }
        if (ra_val > im_val) {
          bf |= 0x40000000;
        }
        if (ra_val == im_val) {
          bf |= 0x20000000;
        }
      }
      uint32_t condition_mask = 0xF0000000U >> (cr * 4);
      uint32_t condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      break;
    }
    case CMPI: {
      int ra = instr->RAValue();
      int32_t im_val = instr->Bits(15, 0);
      im_val = SIGN_EXT_IMM16(im_val);
      int cr = instr->Bits(25, 23);
      uint32_t bf = 0;
      int L = instr->Bit(21);
      if (L) {
        intptr_t ra_val = get_register(ra);
        if (ra_val < im_val) {
          bf |= 0x80000000;
        }
        if (ra_val > im_val) {
          bf |= 0x40000000;
        }
        if (ra_val == im_val) {
          bf |= 0x20000000;
        }
      } else {
        int32_t ra_val = ge
```