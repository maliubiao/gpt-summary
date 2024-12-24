Response: The user wants a summary of the functionality of the C++ code provided.
The code is part of a simulator for the s390 architecture within the V8 JavaScript engine.
I need to identify the key components and their roles within the simulator.

Based on the included headers and the class name `Simulator`, it's clear this file implements the core logic for simulating s390 instructions.

Key functionalities likely include:
- Instruction fetching and decoding.
- Register and memory management.
- Execution of individual s390 instructions.
- Debugging capabilities.
- Interaction with the V8 engine (e.g., for memory management).
- Instruction cache simulation.

Since the user asked for a JavaScript example if there's a connection, I need to think about how this simulator relates to JavaScript execution. The simulator is used when running JavaScript on non-s390 hardware or for testing purposes. It allows V8 to execute s390 assembly code indirectly.

A simple JavaScript example demonstrating this indirect execution could involve a function that eventually gets compiled to s390 assembly and then executed by the simulator.
This C++ code file implements a **simulator for the s390 architecture**. Its primary function is to **mimic the behavior of a real s390 processor**, allowing developers to execute s390 assembly code on different hardware platforms (where a native s390 processor isn't available).

Here's a breakdown of its key functionalities:

*   **Initialization and Setup:** Includes necessary headers, defines constants (like `fp_zero`), and sets up the simulator environment.
*   **Debugging Capabilities:** Implements a `S390Debugger` class that provides interactive debugging features like stepping through instructions, inspecting registers and memory, setting breakpoints, and disassembling code.
*   **Instruction Execution:** The code will contain logic to fetch, decode, and execute individual s390 instructions. This part isn't fully shown in this snippet, but it's the core purpose of the simulator.
*   **Register and Memory Management:** The simulator manages the simulated state of the s390 processor, including its general-purpose registers, floating-point registers, program counter, condition register, and memory.
*   **Instruction Cache Simulation:**  It includes mechanisms to simulate an instruction cache (`ICacheMatch`, `ICacheHash`, `FlushICache`, `CheckICache`), which is important for performance modeling and correctness.
*   **Integration with V8:** The code interacts with other parts of the V8 engine, such as the heap (for memory management related to simulated code) and potentially the code generation pipeline (although that's not directly visible here).

**Relationship to JavaScript and an example:**

This simulator is crucial for V8's ability to run JavaScript code on s390 platforms (or when testing/developing on non-s390 platforms). When JavaScript code is executed, V8 compiles it into machine code for the target architecture. On an s390 system, this would be native s390 instructions. However, when running on a different architecture, or during development/testing, this simulator steps in to execute that generated s390 machine code instruction by instruction.

Here's a conceptual JavaScript example to illustrate the connection (though you wouldn't directly interact with the simulator code from JavaScript like this):

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // Output: 15
```

**How the simulator might be involved internally:**

1. **Compilation:** When V8 compiles the `add` function for an s390 target (either real or simulated), it will generate s390 assembly instructions. For instance, the addition might be translated to an `AR` instruction (Add Register).
2. **Simulation (if not on real s390):** If you are *not* running this JavaScript on actual s390 hardware, the simulator (the code in `simulator-s390.cc`) will be used.
3. **Instruction Execution within the Simulator:**  The simulator will fetch the generated `AR` instruction (represented as a sequence of bytes). The simulator's `Evaluate_AR` function (which is likely defined later in the full file) will be called.
4. **Register Manipulation:** The `Evaluate_AR` function within the simulator will update the simulated s390 registers to reflect the addition operation, based on the operands specified in the instruction.
5. **Result:**  Eventually, the simulated execution will lead to the correct result (15) being available in a simulated register, which the V8 engine can then use to continue the JavaScript execution.

In essence, the simulator acts as a software layer that interprets s390 machine code, allowing JavaScript to run correctly even when the underlying hardware is different. The debugging features in this file are invaluable for understanding and verifying the behavior of the generated s390 code and the simulator itself.

Prompt: 
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/s390/simulator-s390.h"

// Only build the simulator if not compiling for real s390 hardware.
#if defined(USE_SIMULATOR)

#include <stdarg.h>
#include <stdlib.h>

#include <cmath>

#include "src/base/bits.h"
#include "src/base/once.h"
#include "src/base/platform/memory.h"
#include "src/base/platform/platform.h"
#include "src/codegen/assembler.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/s390/constants-s390.h"
#include "src/diagnostics/disasm.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-inl.h"  // For CodeSpaceMemoryModificationScope.
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime-utils.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent way through
// ::v8::internal::OS in the same way as SNPrintF is that the
// Windows C Run-Time Library does not provide vsscanf.
#define SScanF sscanf

const Simulator::fpr_t Simulator::fp_zero;

// The S390Debugger class is used by the simulator while debugging simulated
// z/Architecture code.
class S390Debugger {
 public:
  explicit S390Debugger(Simulator* sim) : sim_(sim) {}
  void Debug();

 private:
#if V8_TARGET_LITTLE_ENDIAN
  static const Instr kBreakpointInstr = (0x0000FFB2);  // TRAP4 0000
  static const Instr kNopInstr = (0x00160016);         // OR r0, r0 x2
#else
  static const Instr kBreakpointInstr = (0xB2FF0000);  // TRAP4 0000
  static const Instr kNopInstr = (0x16001600);         // OR r0, r0 x2
#endif

  Simulator* sim_;

  intptr_t GetRegisterValue(int regnum);
  double GetRegisterPairDoubleValue(int regnum);
  double GetFPDoubleRegisterValue(int regnum);
  float GetFPFloatRegisterValue(int regnum);
  bool GetValue(const char* desc, intptr_t* value);
  bool GetFPDoubleValue(const char* desc, double* value);

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
  set_pc(get_pc() + sizeof(FourByteInstr));
  S390Debugger(this).Debug();
}

intptr_t S390Debugger::GetRegisterValue(int regnum) {
  return sim_->get_register(regnum);
}

double S390Debugger::GetRegisterPairDoubleValue(int regnum) {
  return sim_->get_double_from_register_pair(regnum);
}

double S390Debugger::GetFPDoubleRegisterValue(int regnum) {
  return sim_->get_fpr<double>(regnum);
}

float S390Debugger::GetFPFloatRegisterValue(int regnum) {
  return sim_->get_fpr<float>(regnum);
}

bool S390Debugger::GetValue(const char* desc, intptr_t* value) {
  int regnum = Registers::Number(desc);
  if (regnum != kNoRegister) {
    *value = GetRegisterValue(regnum);
    return true;
  } else {
    if (strncmp(desc, "0x", 2) == 0) {
      return SScanF(desc + 2, "%" V8PRIxPTR,
                    reinterpret_cast<uintptr_t*>(value)) == 1;
    } else {
      return SScanF(desc, "%" V8PRIuPTR, reinterpret_cast<uintptr_t*>(value)) ==
             1;
    }
  }
}

bool S390Debugger::GetFPDoubleValue(const char* desc, double* value) {
  int regnum = DoubleRegisters::Number(desc);
  if (regnum != kNoRegister) {
    *value = sim_->get_fpr<double>(regnum);
    return true;
  }
  return false;
}

bool S390Debugger::SetBreakpoint(Instruction* break_pc) {
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

void S390Debugger::DeleteBreakpoint() {
  UndoBreakpoint();
  sim_->break_pc_ = nullptr;
  sim_->break_instr_ = 0;
}

void S390Debugger::UndoBreakpoint() {
  if (sim_->break_pc_ != nullptr) {
    SetInstructionBitsInCodeSpace(sim_->break_pc_, sim_->break_instr_,
                                  sim_->isolate_->heap());
  }
}

void S390Debugger::RedoBreakpoint() {
  if (sim_->break_pc_ != nullptr) {
    SetInstructionBitsInCodeSpace(sim_->break_pc_, kBreakpointInstr,
                                  sim_->isolate_->heap());
  }
}

void S390Debugger::Debug() {
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
          sim_->set_pc(sim_->get_pc() + sizeof(FourByteInstr));
        } else {
          sim_->ExecuteInstruction(
              reinterpret_cast<Instruction*>(sim_->get_pc()));
        }

        if (argc == 2 && last_pc != sim_->get_pc()) {
          disasm::NameConverter converter;
          disasm::Disassembler dasm(converter);
          // use a reasonably large buffer
          v8::base::EmbeddedVector<char, 256> buffer;

          if (GetValue(arg1, &value)) {
            // Interpret a numeric argument as the number of instructions to
            // step past.
            for (int i = 1; (!sim_->has_bad_pc()) && i < value; i++) {
              dasm.InstructionDecode(
                  buffer, reinterpret_cast<uint8_t*>(sim_->get_pc()));
              PrintF("  0x%08" V8PRIxPTR "  %s\n", sim_->get_pc(),
                     buffer.begin());
              sim_->ExecuteInstruction(
                  reinterpret_cast<Instruction*>(sim_->get_pc()));
            }
          } else {
            // Otherwise treat it as the mnemonic of the opcode to stop at.
            char mnemonic[256];
            while (!sim_->has_bad_pc()) {
              dasm.InstructionDecode(
                  buffer, reinterpret_cast<uint8_t*>(sim_->get_pc()));
              char* mnemonicStart = buffer.begin();
              while (*mnemonicStart != 0 && *mnemonicStart != ' ')
                mnemonicStart++;
              SScanF(mnemonicStart, "%s", mnemonic);
              if (!strcmp(arg1, mnemonic)) break;

              PrintF("  0x%08" V8PRIxPTR "  %s\n", sim_->get_pc(),
                     buffer.begin());
              sim_->ExecuteInstruction(
                  reinterpret_cast<Instruction*>(sim_->get_pc()));
            }
          }
        }
      } else if ((strcmp(cmd, "c") == 0) || (strcmp(cmd, "cont") == 0)) {
        // If at a breakpoint, proceed past it.
        if ((reinterpret_cast<Instruction*>(sim_->get_pc()))
                ->InstructionBits() == 0x7D821008) {
          sim_->set_pc(sim_->get_pc() + sizeof(FourByteInstr));
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
            PrintF("  pc: %08" V8PRIxPTR "  cr: %08x\n", sim_->special_reg_pc_,
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
            PrintF("   pc: %08" V8PRIxPTR "  cr: %08x\n", sim_->special_reg_pc_,
                   sim_->condition_reg_);
          } else if (strcmp(arg1, "allf") == 0) {
            for (int i = 0; i < DoubleRegister::kNumRegisters; i++) {
              float fvalue = GetFPFloatRegisterValue(i);
              uint32_t as_words = base::bit_cast<uint32_t>(fvalue);
              PrintF("%3s: %f 0x%08x\n",
                     RegisterName(DoubleRegister::from_code(i)), fvalue,
                     as_words);
            }
          } else if (strcmp(arg1, "alld") == 0) {
            for (int i = 0; i < DoubleRegister::kNumRegisters; i++) {
              dvalue = GetFPDoubleRegisterValue(i);
              uint64_t as_words = base::bit_cast<uint64_t>(dvalue);
              PrintF("%3s: %f 0x%08x %08x\n",
                     RegisterName(DoubleRegister::from_code(i)), dvalue,
                     static_cast<uint32_t>(as_words >> 32),
                     static_cast<uint32_t>(as_words & 0xFFFFFFFF));
            }
          } else if (arg1[0] == 'r' &&
                     (arg1[1] >= '0' && arg1[1] <= '2' &&
                      (arg1[2] == '\0' || (arg1[2] >= '0' && arg1[2] <= '5' &&
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
            if (IsSmi(obj)) {
              PrintF(" (smi %d)", Smi::ToInt(obj));
            } else if (IsValidHeapObject(current_heap, Cast<HeapObject>(obj))) {
              PrintF(" (");
              ShortPrint(obj);
              PrintF(")");
            }
            PrintF("\n");
          }
          cur++;
        }
      } else if (strcmp(cmd, "disasm") == 0 || strcmp(cmd, "di") == 0) {
        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        // use a reasonably large buffer
        v8::base::EmbeddedVector<char, 256> buffer;

        uint8_t* prev = nullptr;
        uint8_t* cur = nullptr;
        // Default number of instructions to disassemble.
        int32_t numInstructions = 10;

        if (argc == 1) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
        } else if (argc == 2) {
          int regnum = Registers::Number(arg1);
          if (regnum != kNoRegister || strncmp(arg1, "0x", 2) == 0) {
            // The argument is an address or a register name.
            intptr_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(value);
            }
          } else {
            // The argument is the number of instructions.
            intptr_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
              // Disassemble <arg1> instructions.
              numInstructions = static_cast<int32_t>(value);
            }
          }
        } else {
          intptr_t value1;
          intptr_t value2;
          if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
            cur = reinterpret_cast<uint8_t*>(value1);
            // Disassemble <arg2> instructions.
            numInstructions = static_cast<int32_t>(value2);
          }
        }

        while (numInstructions > 0) {
          prev = cur;
          cur += dasm.InstructionDecode(buffer, cur);
          PrintF("  0x%08" V8PRIxPTR "  %s\n", reinterpret_cast<intptr_t>(prev),
                 buffer.begin());
          numInstructions--;
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
      } else if (strcmp(cmd, "stop") == 0) {
        intptr_t value;
        intptr_t stop_pc =
            sim_->get_pc() - (sizeof(FourByteInstr) + kSystemPointerSize);
        Instruction* stop_instr = reinterpret_cast<Instruction*>(stop_pc);
        Instruction* msg_address =
            reinterpret_cast<Instruction*>(stop_pc + sizeof(FourByteInstr));
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
      } else if (strcmp(cmd, "icount") == 0) {
        PrintF("%05" PRId64 "\n", sim_->icount_);
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
        PrintF("    stop and give control to the S390Debugger.\n");
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

void Simulator::set_last_debugger_input(char* input) {
  DeleteArray(last_debugger_input_);
  last_debugger_input_ = input;
}

void Simulator::SetRedirectInstruction(Instruction* instruction) {
// we use TRAP4 here (0xBF22)
#if V8_TARGET_LITTLE_ENDIAN
  instruction->SetInstructionBits(0x1000FFB2);
#else
  instruction->SetInstructionBits(0xB2FF0000 | kCallRtRedirected);
#endif
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
    CHECK_EQ(memcmp(reinterpret_cast<void*>(instr),
                    cache_page->CachedData(offset), sizeof(FourByteInstr)),
             0);
  } else {
    // Cache miss.  Load memory into the cache.
    memcpy(cached_line, line, CachePage::kLineLength);
    *cache_valid_byte = CachePage::LINE_VALID;
  }
}

Simulator::EvaluateFuncType Simulator::EvalTable[] = {nullptr};

void Simulator::EvalTableInit() {
  for (int i = 0; i < MAX_NUM_OPCODES; i++) {
    EvalTable[i] = &Simulator::Evaluate_Unknown;
  }

#define S390_SUPPORTED_VECTOR_OPCODE_LIST(V)                                   \
  V(vst, VST, 0xE70E)     /* type = VRX   VECTOR STORE  */                     \
  V(vl, VL, 0xE706)       /* type = VRX   VECTOR LOAD  */                      \
  V(vlp, VLP, 0xE7DF)     /* type = VRR_A VECTOR LOAD POSITIVE */              \
  V(vlgv, VLGV, 0xE721)   /* type = VRS_C VECTOR LOAD GR FROM VR ELEMENT  */   \
  V(vlvg, VLVG, 0xE722)   /* type = VRS_B VECTOR LOAD VR ELEMENT FROM GR  */   \
  V(vlvgp, VLVGP, 0xE762) /* type = VRR_F VECTOR LOAD VR FROM GRS DISJOINT */  \
  V(vrep, VREP, 0xE74D)   /* type = VRI_C VECTOR REPLICATE  */                 \
  V(vlrep, VLREP, 0xE705) /* type = VRX   VECTOR LOAD AND REPLICATE  */        \
  V(vrepi, VREPI, 0xE745) /* type = VRI_A VECTOR REPLICATE IMMEDIATE  */       \
  V(vlr, VLR, 0xE756)     /* type = VRR_A VECTOR LOAD  */                      \
  V(vsteb, VSTEB, 0xE708) /* type = VRX   VECTOR STORE ELEMENT (8)  */         \
  V(vsteh, VSTEH, 0xE709) /* type = VRX   VECTOR STORE ELEMENT (16)  */        \
  V(vstef, VSTEF, 0xE70B) /* type = VRX   VECTOR STORE ELEMENT (32)  */        \
  V(vsteg, VSTEG, 0xE70A) /* type = VRX   VECTOR STORE ELEMENT (64)  */        \
  V(vleb, VLEB, 0xE701)   /* type = VRX   VECTOR LOAD ELEMENT (8)  */          \
  V(vleh, VLEH, 0xE701)   /* type = VRX   VECTOR LOAD ELEMENT (16)  */         \
  V(vlef, VLEF, 0xE703)   /* type = VRX   VECTOR LOAD ELEMENT (32)  */         \
  V(vleg, VLEG, 0xE702)   /* type = VRX   VECTOR LOAD ELEMENT (64)  */         \
  V(vavgl, VAVGL, 0xE7F0) /* type = VRR_C VECTOR AVERAGE LOGICAL  */           \
  V(va, VA, 0xE7F3)       /* type = VRR_C VECTOR ADD  */                       \
  V(vs, VS, 0xE7F7)       /* type = VRR_C VECTOR SUBTRACT  */                  \
  V(vml, VML, 0xE7A2)     /* type = VRR_C VECTOR MULTIPLY LOW  */              \
  V(vme, VME, 0xE7A6)     /* type = VRR_C VECTOR MULTIPLY EVEN  */             \
  V(vmle, VMLE, 0xE7A4)   /* type = VRR_C VECTOR MULTIPLY EVEN LOGICAL */      \
  V(vmo, VMO, 0xE7A7)     /* type = VRR_C VECTOR MULTIPLY ODD  */              \
  V(vmlo, VMLO, 0xE7A75)  /* type = VRR_C VECTOR MULTIPLY LOGICAL ODD */       \
  V(vnc, VNC, 0xE769)     /* type = VRR_C VECTOR AND WITH COMPLEMENT */        \
  V(vsum, VSUM, 0xE764)   /* type = VRR_C VECTOR SUM ACROSS WORD  */           \
  V(vsumg, VSUMG, 0xE765) /* type = VRR_C VECTOR SUM ACROSS DOUBLEWORD  */     \
  V(vpk, VPK, 0xE794)     /* type = VRR_C VECTOR PACK  */                      \
  V(vmrl, VMRL, 0xE760)   /* type = VRR_C VECTOR MERGE LOW */                  \
  V(vmrh, VMRH, 0xE761)   /* type = VRR_C VECTOR MERGE HIGH */                 \
  V(vpks, VPKS, 0xE797)   /* type = VRR_B VECTOR PACK SATURATE  */             \
  V(vpkls, VPKLS, 0xE795) /* type = VRR_B VECTOR PACK LOGICAL SATURATE  */     \
  V(vupll, VUPLL, 0xE7D4) /* type = VRR_A VECTOR UNPACK LOGICAL LOW  */        \
  V(vuplh, VUPLH, 0xE7D5) /* type = VRR_A VECTOR UNPACK LOGICAL HIGH  */       \
  V(vupl, VUPL, 0xE7D6)   /* type = VRR_A VECTOR UNPACK LOW  */                \
  V(vuph, VUPH, 0xE7D7)   /* type = VRR_A VECTOR UNPACK HIGH  */               \
  V(vpopct, VPOPCT, 0xE750) /* type = VRR_A VECTOR POPULATION COUNT  */        \
  V(vcdg, VCDG, 0xE7C3)     /* VECTOR FP CONVERT FROM FIXED  */                \
  V(vcdlg, VCDLG, 0xE7C1)   /* VECTOR FP CONVERT FROM LOGICAL  */              \
  V(vcgd, VCGD, 0xE7C2)     /* VECTOR FP CONVERT TO FIXED */                   \
  V(vclgd, VCLGD, 0xE7C0)   /* VECTOR FP CONVERT TO LOGICAL */                 \
  V(vmnl, VMNL, 0xE7FC)     /* type = VRR_C VECTOR MINIMUM LOGICAL  */         \
  V(vmxl, VMXL, 0xE7FD)     /* type = VRR_C VECTOR MAXIMUM LOGICAL  */         \
  V(vmn, VMN, 0xE7FE)       /* type = VRR_C VECTOR MINIMUM  */                 \
  V(vmx, VMX, 0xE7FF)       /* type = VRR_C VECTOR MAXIMUM  */                 \
  V(vceq, VCEQ, 0xE7F8)     /* type = VRR_B VECTOR COMPARE EQUAL  */           \
  V(vx, VX, 0xE76D)         /* type = VRR_C VECTOR EXCLUSIVE OR  */            \
  V(vchl, VCHL, 0xE7F9)     /* type = VRR_B VECTOR COMPARE HIGH LOGICAL  */    \
  V(vch, VCH, 0xE7FB)       /* type = VRR_B VECTOR COMPARE HIGH  */            \
  V(vo, VO, 0xE76A)         /* type = VRR_C VECTOR OR  */                      \
  V(vn, VN, 0xE768)         /* type = VRR_C VECTOR AND  */                     \
  V(vno, VNO, 0xE768B)      /* type = VRR_C VECTOR NOR  */                     \
  V(vlc, VLC, 0xE7DE)       /* type = VRR_A VECTOR LOAD COMPLEMENT  */         \
  V(vsel, VSEL, 0xE78D)     /* type = VRR_E VECTOR SELECT  */                  \
  V(vperm, VPERM, 0xE78C)   /* type = VRR_E VECTOR PERMUTE  */                 \
  V(vbperm, VBPERM, 0xE785) /* type = VRR_C VECTOR BIT PERMUTE   */            \
  V(vtm, VTM, 0xE7D8)       /* type = VRR_A VECTOR TEST UNDER MASK  */         \
  V(vesl, VESL, 0xE730)     /* type = VRS_A VECTOR ELEMENT SHIFT LEFT  */      \
  V(veslv, VESLV, 0xE770)   /* type = VRR_C VECTOR ELEMENT SHIFT LEFT  */      \
  V(vesrl, VESRL,                                                              \
    0xE738) /* type = VRS_A VECTOR ELEMENT SHIFT RIGHT LOGICAL  */             \
  V(vesrlv, VESRLV,                                                            \
    0xE778) /* type = VRR_C VECTOR ELEMENT SHIFT RIGHT LOGICAL  */             \
  V(vesra, VESRA,                                                              \
    0xE73A) /* type = VRS_A VECTOR ELEMENT SHIFT RIGHT ARITHMETIC  */          \
  V(vesrav, VESRAV,                                                            \
    0xE77A) /* type = VRR_C VECTOR ELEMENT SHIFT RIGHT ARITHMETIC  */          \
  V(vfsq, VFSQ, 0xE7CE)   /* type = VRR_A VECTOR FP SQUARE ROOT  */            \
  V(vfmax, VFMAX, 0xE7EF) /* type = VRR_C VECTOR FP MAXIMUM */                 \
  V(vfmin, VFMIN, 0xE7EE) /* type = VRR_C VECTOR FP MINIMUM */                 \
  V(vfce, VFCE, 0xE7E8)   /* type = VRR_C VECTOR FP COMPARE EQUAL  */          \
  V(vfpso, VFPSO, 0xE7CC) /* type = VRR_A VECTOR FP PERFORM SIGN OPERATION  */ \
  V(vfche, VFCHE, 0xE7EA) /* type = VRR_C VECTOR FP COMPARE HIGH OR EQUAL  */  \
  V(vfch, VFCH, 0xE7EB)   /* type = VRR_C VECTOR FP COMPARE HIGH  */           \
  V(vfi, VFI, 0xE7C7)     /* type = VRR_A VECTOR LOAD FP INTEGER  */           \
  V(vfs, VFS, 0xE7E2)     /* type = VRR_C VECTOR FP SUBTRACT  */               \
  V(vfa, VFA, 0xE7E3)     /* type = VRR_C VECTOR FP ADD  */                    \
  V(vfd, VFD, 0xE7E5)     /* type = VRR_C VECTOR FP DIVIDE  */                 \
  V(vfm, VFM, 0xE7E7)     /* type = VRR_C VECTOR FP MULTIPLY  */               \
  V(vfma, VFMA, 0xE78F)   /* type = VRR_E VECTOR FP MULTIPLY AND ADD  */       \
  V(vfnms, VFNMS,                                                              \
    0xE79E) /* type = VRR_E VECTOR FP NEGATIVE MULTIPLY AND SUBTRACT   */

#define CREATE_EVALUATE_TABLE(name, op_name, op_value) \
  EvalTable[op_name] = &Simulator::Evaluate_##op_name;
  S390_SUPPORTED_VECTOR_OPCODE_LIST(CREATE_EVALUATE_TABLE);
#undef CREATE_EVALUATE_TABLE

  EvalTable[DUMY] = &Simulator::Evaluate_DUMY;
  EvalTable[BKPT] = &Simulator::Evaluate_BKPT;
  EvalTable[SPM] = &Simulator::Evaluate_SPM;
  EvalTable[BALR] = &Simulator::Evaluate_BALR;
  EvalTable[BCTR] = &Simulator::Evaluate_BCTR;
  EvalTable[BCR] = &Simulator::Evaluate_BCR;
  EvalTable[SVC] = &Simulator::Evaluate_SVC;
  EvalTable[BSM] = &Simulator::Evaluate_BSM;
  EvalTable[BASSM] = &Simulator::Evaluate_BASSM;
  EvalTable[BASR] = &Simulator::Evaluate_BASR;
  EvalTable[MVCL] = &Simulator::Evaluate_MVCL;
  EvalTable[CLCL] = &Simulator::Evaluate_CLCL;
  EvalTable[LPR] = &Simulator::Evaluate_LPR;
  EvalTable[LNR] = &Simulator::Evaluate_LNR;
  EvalTable[LTR] = &Simulator::Evaluate_LTR;
  EvalTable[LCR] = &Simulator::Evaluate_LCR;
  EvalTable[NR] = &Simulator::Evaluate_NR;
  EvalTable[CLR] = &Simulator::Evaluate_CLR;
  EvalTable[OR] = &Simulator::Evaluate_OR;
  EvalTable[XR] = &Simulator::Evaluate_XR;
  EvalTable[LR] = &Simulator::Evaluate_LR;
  EvalTable[CR] = &Simulator::Evaluate_CR;
  EvalTable[AR] = &Simulator::Evaluate_AR;
  EvalTable[SR] = &Simulator::Evaluate_SR;
  EvalTable[MR] = &Simulator::Evaluate_MR;
  EvalTable[DR] = &Simulator::Evaluate_DR;
  EvalTable[ALR] = &Simulator::Evaluate_ALR;
  EvalTable[SLR] = &Simulator::Evaluate_SLR;
  EvalTable[LDR] = &Simulator::Evaluate_LDR;
  EvalTable[CDR] = &Simulator::Evaluate_CDR;
  EvalTable[LER] = &Simulator::Evaluate_LER;
  EvalTable[STH] = &Simulator::Evaluate_STH;
  EvalTable[LA] = &Simulator::Evaluate_LA;
  EvalTable[STC] = &Simulator::Evaluate_STC;
  EvalTable[IC_z] = &Simulator::Evaluate_IC_z;
  EvalTable[EX] = &Simulator::Evaluate_EX;
  EvalTable[BAL] = &Simulator::Evaluate_BAL;
  EvalTable[BCT] = &Simulator::Evaluate_BCT;
  EvalTable[BC] = &Simulator::Evaluate_BC;
  EvalTable[LH] = &Simulator::Evaluate_LH;
  EvalTable[CH] = &Simulator::Evaluate_CH;
  EvalTable[AH] = &Simulator::Evaluate_AH;
  EvalTable[SH] = &Simulator::Evaluate_SH;
  EvalTable[MH] = &Simulator::Evaluate_MH;
  EvalTable[BAS] = &Simulator::Evaluate_BAS;
  EvalTable[CVD] = &Simulator::Evaluate_CVD;
  EvalTable[CVB] = &Simulator::Evaluate_CVB;
  EvalTable[ST] = &Simulator::Evaluate_ST;
  EvalTable[LAE] = &Simulator::Evaluate_LAE;
  EvalTable[N] = &Simulator::Evaluate_N;
  EvalTable[CL] = &Simulator::Evaluate_CL;
  EvalTable[O] = &Simulator::Evaluate_O;
  EvalTable[X] = &Simulator::Evaluate_X;
  EvalTable[L] = &Simulator::Evaluate_L;
  EvalTable[C] = &Simulator::Evaluate_C;
  EvalTable[A] = &Simulator::Evaluate_A;
  EvalTable[S] = &Simulator::Evaluate_S;
  EvalTable[M] = &Simulator::Evaluate_M;
  EvalTable[D] = &Simulator::Evaluate_D;
  EvalTable[AL] = &Simulator::Evaluate_AL;
  EvalTable[SL] = &Simulator::Evaluate_SL;
  EvalTable[STD] = &Simulator::Evaluate_STD;
  EvalTable[LD] = &Simulator::Evaluate_LD;
  EvalTable[CD] = &Simulator::Evaluate_CD;
  EvalTable[STE] = &Simulator::Evaluate_STE;
  EvalTable[MS] = &Simulator::Evaluate_MS;
  EvalTable[LE] = &Simulator::Evaluate_LE;
  EvalTable[BRXH] = &Simulator::Evaluate_BRXH;
  EvalTable[BRXLE] = &Simulator::Evaluate_BRXLE;
  EvalTable[BXH] = &Simulator::Evaluate_BXH;
  EvalTable[BXLE] = &Simulator::Evaluate_BXLE;
  EvalTable[SRL] = &Simulator::Evaluate_SRL;
  EvalTable[SLL] = &Simulator::Evaluate_SLL;
  EvalTable[SRA] = &Simulator::Evaluate_SRA;
  EvalTable[SLA] = &Simulator::Evaluate_SLA;
  EvalTable[SRDL] = &Simulator::Evaluate_SRDL;
  EvalTable[SLDL] = &Simulator::Evaluate_SLDL;
  EvalTable[SRDA] = &Simulator::Evaluate_SRDA;
  EvalTable[SLDA] = &Simulator::Evaluate_SLDA;
  EvalTable[STM] = &Simulator::Evaluate_STM;
  EvalTable[TM] = &Simulator::Evaluate_TM;
  EvalTable[MVI] = &Simulator::Evaluate_MVI;
  EvalTable[TS] = &Simulator::Evaluate_TS;
  EvalTable[NI] = &Simulator::Evaluate_NI;
  EvalTable[CLI] = &Simulator::Evaluate_CLI;
  EvalTable[OI] = &Simulator::Evaluate_OI;
  EvalTable[XI] = &Simulator::Evaluate_XI;
  EvalTable[LM] = &Simulator::Evaluate_LM;
  EvalTable[CS] = &Simulator::Evaluate_CS;
  EvalTable[MVCLE] = &Simulator::Evaluate_MVCLE;
  EvalTable[CLCLE] = &Simulator::Evaluate_CLCLE;
  EvalTable[MC] = &Simulator::Evaluate_MC;
  EvalTable[CDS] = &Simulator::Evaluate_CDS;
  EvalTable[STCM] = &Simulator::Evaluate_STCM;
  EvalTable[ICM] = &Simulator::Evaluate_ICM;
  EvalTable[BPRP] = &Simulator::Evaluate_BPRP;
  EvalTable[BPP] = &Simulator::Evaluate_BPP;
  EvalTable[TRTR] = &Simulator::Evaluate_TRTR;
  EvalTable[MVN] = &Simulator::Evaluate_MVN;
  EvalTable[MVC] = &Simulator::Evaluate_MVC;
  EvalTable[MVZ] = &Simulator::Evaluate_MVZ;
  EvalTable[NC] = &Simulator::Evaluate_NC;
  EvalTable[CLC] = &Simulator::Evaluate_CLC;
  EvalTable[OC] = &Simulator::Evaluate_OC;
  EvalTable[XC] = &Simulator::Evaluate_XC;
  EvalTable[MVCP] = &Simulator::Evaluate_MVCP;
  EvalTable[TR] = &Simulator::Evaluate_TR;
  EvalTable[TRT] = &Simulator::Evaluate_TRT;
  EvalTable[ED] = &Simulator::Evaluate_ED;
  EvalTable[EDMK] = &Simulator::Evaluate_EDMK;
  EvalTable[PKU] = &Simulator::Evaluate_PKU;
  EvalTable[UNPKU] = &Simulator::Evaluate_UNPKU;
  EvalTable[MVCIN] = &Simulator::Evaluate_MVCIN;
  EvalTable[PKA] = &Simulator::Evaluate_PKA;
  EvalTable[UNPKA] = &Simulator::Evaluate_UNPKA;
  EvalTable[PLO] = &Simulator::Evaluate_PLO;
  EvalTable[LMD] = &Simulator::Evaluate_LMD;
  EvalTable[SRP] = &Simulator::Evaluate_SRP;
  EvalTable[MVO] = &Simulator::Evaluate_MVO;
  EvalTable[PACK] = &Simulator::Evaluate_PACK;
  EvalTable[UNPK] = &Simulator::Evaluate_UNPK;
  EvalTable[ZAP] = &Simulator::Evaluate_ZAP;
  EvalTable[AP] = &Simulator::Evaluate_AP;
  EvalTable[SP] = &Simulator::Evaluate_SP;
  EvalTable[MP] = &Simulator::Evaluate_MP;
  EvalTable[DP] = &Simulator::Evaluate_DP;
  EvalTable[UPT] = &Simulator::Evaluate_UPT;
  EvalTable[PFPO] = &Simulator::Evaluate_PFPO;
  EvalTable[IIHH] = &Simulator::Evaluate_IIHH;
  EvalTable[IIHL] = &Simulator::Evaluate_IIHL;
  EvalTable[IILH] = &Simulator::Evaluate_IILH;
  EvalTable[IILL] = &Simulator::Evaluate_IILL;
  EvalTable[NIHH] = &Simulator::Evaluate_NIHH;
  EvalTable[NIHL] = &Simulator::Evaluate_NIHL;
  EvalTable[NILH] = &Simulator::Evaluate_NILH;
  EvalTable[NILL] = &Simulator::Evaluate_NILL;
  EvalTable[OIHH] = &Simulator::Evaluate_OIHH;
  EvalTable[OIHL] = &Simulator::Evaluate_OIHL;
  EvalTable[OILH] = &Simulator::Evaluate_OILH;
  EvalTable[OILL] = &Simulator::Evaluate_OILL;
  EvalTable[LLIHH] = &Simulator::Evaluate_LLIHH;
  EvalTable[LLIHL] = &Simulator::Evaluate_LLIHL;
  EvalTable[LLILH] = &Simulator::Evaluate_LLILH;
  EvalTable[LLILL] = &Simulator::Evaluate_LLILL;
  EvalTable[TMLH] = &Simulator::Evaluate_TMLH;
  EvalTable[TMLL] = &Simulator::Evaluate_TMLL;
  EvalTable[TMHH] = &Simulator::Evaluate_TMHH;
  EvalTable[TMHL] = &Simulator::Evaluate_TMHL;
  EvalTable[BRC] = &Simulator::Evaluate_BRC;
  EvalTable[BRAS] = &Simulator::Evaluate_BRAS;
  EvalTable[BRCT] = &Simulator::Evaluate_BRCT;
  EvalTable[BRCTG] = &Simulator::Evaluate_BRCTG;
  EvalTable[LHI] = &Simulator::Evaluate_LHI;
  EvalTable[LGHI] = &Simulator::Evaluate_LGHI;
  EvalTable[AHI] = &Simulator::Evaluate_AHI;
  EvalTable[AGHI] = &Simulator::Evaluate_AGHI;
  EvalTable[MHI] = &Simulator::Evaluate_MHI;
  EvalTable[MGHI] = &Simulator::Evaluate_MGHI;
  EvalTable[CHI] = &Simulator::Evaluate_CHI;
  EvalTable[CGHI] = &Simulator::Evaluate_CGHI;
  EvalTable[LARL] = &Simulator::Evaluate_LARL;
  EvalTable[LGFI] = &Simulator::Evaluate_LGFI;
  EvalTable[BRCL] = &Simulator::Evaluate_BRCL;
  EvalTable[BRASL] = &Simulator::Evaluate_BRASL;
  EvalTable[XIHF] = &Simulator::Evaluate_XIHF;
  EvalTable[XILF] = &Simulator::Evaluate_XILF;
  EvalTable[IIHF] = &Simulator::Evaluate_IIHF;
  EvalTable[IILF] = &Simulator::Evaluate_IILF;
  EvalTable[NIHF] = &Simulator::Evaluate_NIHF;
  EvalTable[NILF] = &Simulator::Evaluate_NILF;
  EvalTable[OIHF] = &Simulator::Evaluate_OIHF;
  EvalTable[OILF] = &Simulator::Evaluate_OILF;
  EvalTable[LLIHF] = &Simulator::Evaluate_LLIHF;
  EvalTable[LLILF] = &Simulator::Evaluate_LLILF;
  EvalTable[MSGFI] = &Simulator::Evaluate_MSGFI;
  EvalTable[MSFI] = &Simulator::Evaluate_MSFI;
  EvalTable[SLGFI] = &Simulator::Evaluate_SLGFI;
  EvalTable[SLFI] = &Simulator::Evaluate_SLFI;
  EvalTable[AGFI] = &Simulator::Evaluate_AGFI;
  EvalTable[AFI] = &Simulator::Evaluate_AFI;
  EvalTable[ALGFI] = &Simulator::Evaluate_ALGFI;
  EvalTable[ALFI] = &Simulator::Evaluate_ALFI;
  EvalTable[CGFI] = &Simulator::Evaluate_CGFI;
  EvalTable[CFI] = &Simulator::Evaluate_CFI;
  EvalTable[CLGFI] = &Simulator::Evaluate_CLGFI;
  EvalTable[CLFI] = &Simulator::Evaluate_CLFI;
  EvalTable[LLHRL] = &Simulator::Evaluate_LLHRL;
  EvalTable[LGHRL] = &Simulator::Evaluate_LGHRL;
  EvalTable[LHRL] = &Simulator::Evaluate_LHRL;
  EvalTable[LLGHRL] = &Simulator::Evaluate_LLGHRL;
  EvalTable[STHRL] = &Simulator::Evaluate_STHRL;
  EvalTable[LGRL] = &Simulator::Evaluate_LGRL;
  EvalTable[STGRL] = &Simulator::Evaluate_STGRL;
  EvalTable[LGFRL] = &Simulator::Evaluate_LGFRL;
  EvalTable[LRL] = &Simulator::Evaluate_LRL;
  EvalTable[LLGFRL] = &Simulator::Evaluate_LLGFRL;
  EvalTable[STRL] = &Simulator::Evaluate_STRL;
  EvalTable[EXRL] = &Simulator::Evaluate_EXRL;
  EvalTable[PFDRL] = &Simulator::Evaluate_PFDRL;
  EvalTable[CGHRL] = &Simulator::Evaluate_CGHRL;
  EvalTable[CHRL] = &Simulator::Evaluate_CHRL;
  EvalTable[CGRL] = &Simulator::Evaluate_CGRL;
  EvalTable[CGFRL] = &Simulator::Evaluate_CGFRL;
  EvalTable[ECTG] = &Simulator::Evaluate_ECTG;
  EvalTable[CSST] = &Simulator::Evaluate_CSST;
  EvalTable[LPD] = &Simulator::Evaluate_LPD;
  EvalTable[LPDG] = &Simulator::Evaluate_LPDG;
  EvalTable[BRCTH] = &Simulator::Evaluate_BRCTH;
  EvalTable[AIH] = &Simulator::Evaluate_AIH;
  EvalTable[ALSIH] = &Simulator::Evaluate_ALSIH;
  EvalTable[ALSIHN] = &Simulator::Evaluate_ALSIHN;
  EvalTable[CIH] = &Simulator::Evaluate_CIH;
  EvalTable[CLIH] = &Simulator::Evaluate_CLIH;
  EvalTable[STCK] = &Simulator::Evaluate_STCK;
  EvalTable[CFC] = &Simulator::Evaluate_CFC;
  EvalTable[IPM] = &Simulator::Evaluate_IPM;
  EvalTable[HSCH] = &Simulator::Evaluate_HSCH;
  EvalTable[MSCH] = &Simulator::Evaluate_MSCH;
  EvalTable[SSCH] = &Simulator::Evaluate_SSCH;
  EvalTable[STSCH] = &Simulator::Evaluate_STSCH;
  EvalTable[TSCH] = &Simulator::Evaluate_TSCH;
  EvalTable[TPI] = &Simulator::Evaluate_TPI;
  EvalTable[SAL] = &Simulator::Evaluate_SAL;
  EvalTable[RSCH] = &Simulator::Evaluate_RSCH;
  EvalTable[STCRW] = &Simulator::Evaluate_STCRW;
  EvalTable[STCPS] = &Simulator::Evaluate_STCPS;
  EvalTable[RCHP] = &Simulator::Evaluate_RCHP;
  EvalTable[SCHM] = &Simulator::Evaluate_SCHM;
  EvalTable[CKSM] = &Simulator::Evaluate_CKSM;
  EvalTable[SAR] = &Simulator::Evaluate_SAR;
  EvalTable[EAR] = &Simulator::Evaluate_EAR;
  EvalTable[MSR] = &Simulator::Evaluate_MSR;
  EvalTable[MSRKC] = &Simulator::Evaluate_MSRKC;
  EvalTable[MVST] = &Simulator::Evaluate_MVST;
  EvalTable[CUSE] = &Simulator::Evaluate_CUSE;
  EvalTable[SRST] = &Simulator::Evaluate_SRST;
  EvalTable[XSCH] = &Simulator::Evaluate_XSCH;
  EvalTable[STCKE] = &Simulator::Evaluate_STCKE;
  EvalTable[STCKF] = &Simulator::Evaluate_STCKF;
  EvalTable[SRNM] = &Simulator::Evaluate_SRNM;
  EvalTable[STFPC] = &Simulator::Evaluate_STFPC;
  EvalTable[LFPC] = &Simulator::Evaluate_LFPC;
  EvalTable[TRE] = &Simulator::Evaluate_TRE;
  EvalTable[STFLE] = &Simulator::Evaluate_STFLE;
  EvalTable[SRNMB] = &Simulator::Evaluate_SRNMB;
  EvalTable[SRNMT] = &Simulator::Evaluate_SRNMT;
  EvalTable[LFAS] = &Simulator::Evaluate_LFAS;
  EvalTable[PPA] = &Simulator::Evaluate_PPA;
  EvalTable[ETND] = &Simulator::Evaluate_ETND;
  EvalTable[TEND] = &Simulator::Evaluate_TEND;
  EvalTable[NIAI] = &Simulator::Evaluate_NIAI;
  EvalTable[TABORT] = &Simulator::Evaluate_TABORT;
  EvalTable[TRAP4] = &Simulator::Evaluate_TRAP4;
  EvalTable[LPEBR] = &Simulator::Evaluate_LPEBR;
  EvalTable[LNEBR] = &Simulator::Evaluate_LNEBR;
  EvalTable[LTEBR] = &Simulator::Evaluate_LTEBR;
  EvalTable[LCEBR] = &Simulator::Evaluate_LCEBR;
  EvalTable[LDEBR] = &Simulator::Evaluate_LDEBR;
  EvalTable[LXDBR] = &Simulator::Evaluate_LXDBR;
  EvalTable[LXEBR] = &Simulator::Evaluate_LXEBR;
  EvalTable[MXDBR] = &Simulator::Evaluate_MXDBR;
  EvalTable[KEBR] = &Simulator::Evaluate_KEBR;
  EvalTable[CEBR] = &Simulator::Evaluate_CEBR;
  EvalTable[AEBR] = &Simulator::Evaluate_AEBR;
  EvalTable[SEBR] = &Simulator::Evaluate_SEBR;
  EvalTable[MDEBR] = &Simulator::Evaluate_MDEBR;
  EvalTable[DEBR] = &Simulator::Evaluate_DEBR;
  EvalTable[MAEBR] = &Simulator::Evaluate_MAEBR;
  EvalTable[MSEBR] = &Simulator::Evaluate_MSEBR;
  EvalTable[LPDBR] = &Simulator::Evaluate_LPDBR;
  EvalTable[LNDBR] = &Simulator::Evaluate_LNDBR;
  EvalTable[LTDBR] = &Simulator::Evaluate_LTDBR;
  EvalTable[LCDBR] = &Simulator::Evaluate_LCDBR;
  EvalTable[SQEBR] = &Simulator::Evaluate_SQEBR;
  EvalTable[SQDBR] = &Simulator::Evaluate_SQDBR;
  EvalTable[SQXBR] = &Simulator::Evaluate_SQXBR;
  EvalTable[MEEBR] = &Simulator::Evaluate_MEEBR;
  EvalTable[KDBR] = &Simulator::Evaluate_KDBR;
  EvalTable[CDBR] = &Simulator::Evaluate_CDBR;
  EvalTable[ADBR] = &Simulator::Evaluate_ADBR;
  EvalTable[SDBR] = &Simulator::Evaluate_SDBR;
  EvalTable[MDBR] = &Simulator::Evaluate_MDBR;
  EvalTable[DDBR] = &Simulator::Evaluate_DDBR;
  EvalTable[MADBR] = &Simulator::Evaluate_MADBR;
  EvalTable[MSDBR] = &Simulator::Evaluate_MSDBR;
  EvalTable[LPXBR] = &Simulator::Evaluate_LPXBR;
  EvalTable[LNXBR] = &Simulator::Evaluate_LNXBR;
  EvalTable[LTXBR] = &Simulator::Evaluate_LTXBR;
  EvalTable[LCXBR] = &Simulator::Evaluate_LCXBR;
  EvalTable[LEDBRA] = &Simulator::Evaluate_LEDBRA;
  EvalTable[LDXBRA] = &Simulator::Evaluate_LDXBRA;
  EvalTable[LEXBRA] = &Simulator::Evaluate_LEXBRA;
  EvalTable[FIXBRA] = &Simulator::Evaluate_FIXBRA;
  EvalTable[KXBR] = &Simulator::Evaluate_KXBR;
  EvalTable[CXBR] = &Simulator::Evaluate_CXBR;
  EvalTable[AXBR] = &Simulator::Evaluate_AXBR;
  EvalTable[SXBR] = &Simulator::Evaluate_SXBR;
  EvalTable[MXBR] = &Simulator::Evaluate_MXBR;
  EvalTable[DXBR] = &Simulator::Evaluate_DXBR;
  EvalTable[TBEDR] = &Simulator::Evaluate_TBEDR;
  EvalTable[TBDR] = &Simulator::Evaluate_TBDR;
  EvalTable[DIEBR] = &Simulator::Evaluate_DIEBR;
  EvalTable[FIEBRA] = &Simulator::Evaluate_FIEBRA;
  EvalTable[THDER] = &Simulator::Evaluate_THDER;
  EvalTable[THDR] = &Simulator::Evaluate_THDR;
  EvalTable[DIDBR] = &Simulator::Evaluate_DIDBR;
  EvalTable[FIDBRA] = &Simulator::Evaluate_FIDBRA;
  EvalTable[LXR] = &Simulator::Evaluate_LXR;
  EvalTable[LPDFR] = &Simulator::Evaluate_LPDFR;
  EvalTable[LNDFR] = &Simulator::Evaluate_LNDFR;
  EvalTable[LCDFR] = &Simulator::Evaluate_LCDFR;
  EvalTable[LZER] = &Simulator::Evaluate_LZER;
  EvalTable[LZDR] = &Simulator::Evaluate_LZDR;
  EvalTable[LZXR] = &Simulator::Evaluate_LZXR;
  EvalTable[SFPC] = &Simulator::Evaluate_SFPC;
  EvalTable[SFASR] = &Simulator::Evaluate_SFASR;
  EvalTable[EFPC] = &Simulator::Evaluate_EFPC;
  EvalTable[CELFBR] = &Simulator::Evaluate_CELFBR;
  EvalTable[CDLFBR] = &Simulator::Evaluate_CDLFBR;
  EvalTable[CXLFBR] = &Simulator::Evaluate_CXLFBR;
  EvalTable[CEFBRA] = &Simulator::Evaluate_CEFBRA;
  EvalTable[CDFBRA] = &Simulator::Evaluate_CDFBRA;
  EvalTable[CXFBRA] = &Simulator::Evaluate_CXFBRA;
  EvalTable[CFEBRA] = &Simulator::Evaluate_CFEBRA;
  EvalTable[CFDBRA] = &Simulator::Evaluate_CFDBRA;
  EvalTable[CFXBRA] = &Simulator::Evaluate_CFXBRA;
  EvalTable[CLFEBR] = &Simulator::Evaluate_CLFEBR;
  EvalTable[CLFDBR] = &Simulator::Evaluate_CLFDBR;
  EvalTable[CLFXBR] = &Simulator::Evaluate_CLFXBR;
  EvalTable[CELGBR] = &Simulator::Evaluate_CELGBR;
  EvalTable[CDLGBR] = &Simulator::Evaluate_CDLGBR;
  EvalTable[CXLGBR] = &Simulator::Evaluate_CXLGBR;
  EvalTable[CEGBRA] = &Simulator::Evaluate_CEGBRA;
  EvalTable[CDGBRA] = &Simulator::Evaluate_CDGBRA;
  EvalTable[CXGBRA] = &Simulator::Evaluate_CXGBRA;
  EvalTable[CGEBRA] = &Simulator::Evaluate_CGEBRA;
  EvalTable[CGDBRA] = &Simulator::Evaluate_CGDBRA;
  EvalTable[CGXBRA] = &Simulator::Evaluate_CGXBRA;
  EvalTable[CLGEBR] = &Simulator::Evaluate_CLGEBR;
  EvalTable[CLGDBR] = &Simulator::Evaluate_CLGDBR;
  EvalTable[CFER] = &Simulator::Evaluate_CFER;
  EvalTable[CFDR] = &Simulator::Evaluate_CFDR;
  EvalTable[CFXR] = &Simulator::Evaluate_CFXR;
  EvalTable[LDGR] = &Simulator::Evaluate_LDGR;
  EvalTable[CGER] = &Simulator::Evaluate_CGER;
  EvalTable[CGDR] = &Simulator::Evaluate_CGDR;
  EvalTable[CGXR] = &Simulator::Evaluate_CGXR;
  EvalTable[LGDR] = &Simulator::Evaluate_LGDR;
  EvalTable[MDTRA] = &Simulator::Evaluate_MDTRA;
  EvalTable[DDTRA] = &Simulator::Evaluate_DDTRA;
  EvalTable[ADTRA] = &Simulator::Evaluate_ADTRA;
  EvalTable[SDTRA] = &Simulator::Evaluate_SDTRA;
  EvalTable[LDETR] = &Simulator::Evaluate_LDETR;
  EvalTable[LEDTR] = &Simulator::Evaluate_LEDTR;
  EvalTable[LTDTR] = &Simulator::Evaluate_LTDTR;
  EvalTable[FIDTR] = &Simulator::Evaluate_FIDTR;
  EvalTable[MXTRA] = &Simulator::Evaluate_MXTRA;
  EvalTable[DXTRA] = &Simulator::Evaluate_DXTRA;
  EvalTable[AXTRA] = &Simulator::Evaluate_AXTRA;
  EvalTable[SXTRA] = &Simulator::Evaluate_SXTRA;
  EvalTable[LXDTR] = &Simulator::Evaluate_LXDTR;
  EvalTable[LDXTR] = &Simulator::Evaluate_LDXTR;
  EvalTable[LTXTR] = &Simulator::Evaluate_LTXTR;
  EvalTable[FIXTR] = &Simulator::Evaluate_FIXTR;
  EvalTable[KDTR] = &Simulator::Evaluate_KDTR;
  EvalTable[CGDTRA] = &Simulator::Evaluate_CGDTRA;
  EvalTable[CUDTR] = &Simulator::Evaluate_CUDTR;
  EvalTable[CDTR] = &Simulator::Evaluate_CDTR;
  EvalTable[EEDTR] = &Simulator::Evaluate_EEDTR;
  EvalTable[ESDTR] = &Simulator::Evaluate_ESDTR;
  EvalTable[KXTR] = &Simulator::Evaluate_KXTR;
  EvalTable[CGXTRA] = &Simulator::Evaluate_CGXTRA;
  EvalTable[CUXTR] = &Simulator::Evaluate_CUXTR;
  EvalTable[CSXTR] = &Simulator::Evaluate_CSXTR;
  EvalTable[CXTR] = &Simulator::Evaluate_CXTR;
  EvalTable[EEXTR] = &Simulator::Evaluate_EEXTR;
  EvalTable[ESXTR] = &Simulator::Evaluate_ESXTR;
  EvalTable[CDGTRA] = &Simulator::Evaluate_CDGTRA;
  EvalTable[CDUTR] = &Simulator::Evaluate_CDUTR;
  EvalTable[CDSTR] = &Simulator::Evaluate_CDSTR;
  EvalTable[CEDTR] = &Simulator::Evaluate_CEDTR;
  EvalTable[QADTR] = &Simulator::Evaluate_QADTR;
  EvalTable[IEDTR] = &Simulator::Evaluate_IEDTR;
  EvalTable[RRDTR] = &Simulator::Evaluate_RRDTR;
  EvalTable[CXGTRA] = &Simulator::Evaluate_CXGTRA;
  EvalTable[CXUTR] = &Simulator::Evaluate_CXUTR;
  EvalTable[CXSTR] = &Simulator::Evaluate_CXSTR;
  EvalTable[CEXTR] = &Simulator::Evaluate_CEXTR;
  EvalTable[QAXTR] = &Simulator::Evaluate_QAXTR;
  EvalTable[IEXTR] = &Simulator::Evaluate_IEXTR;
  EvalTable[RRXTR] = &Simulator::Evaluate_RRXTR;
  EvalTable[LPGR] = &Simulator::Evaluate_LPGR;
  EvalTable[LNGR] = &Simulator::Evaluate_LNGR;
  EvalTable[LTGR] = &Simulator::Evaluate_LTGR;
  EvalTable[LCGR] = &Simulator::Evaluate_LCGR;
  EvalTable[LGR] = &Simulator::Evaluate_LGR;
  EvalTable[LGBR] = &Simulator::Evaluate_LGBR;
  EvalTable[LGHR] = &Simulator::Evaluate_LGHR;
  EvalTable[AGR] = &Simulator::Evaluate_AGR;
  EvalTable[SGR] = &Simulator::Evaluate_SGR;
  EvalTable[ALGR] = &Simulator::Evaluate_ALGR;
  EvalTable[SLGR] = &Simulator::Evaluate_SLGR;
  EvalTable[MSGR] = &Simulator::Evaluate_MSGR;
  EvalTable[MSGRKC] = &Simulator::Evaluate_MSGRKC;
  EvalTable[DSGR] = &Simulator::Evaluate_DSGR;
  EvalTable[LRVGR] = &Simulator::Evaluate_LRVGR;
  EvalTable[LPGFR] = &Simulator::Evaluate_LPGFR;
  EvalTable[LNGFR] = &Simulator::Evaluate_LNGFR;
  EvalTable[LTGFR] = &Simulator::Evaluate_LTGFR;
  EvalTable[LCGFR] = &Simulator::Evaluate_LCGFR;
  EvalTable[LGFR] = &Simulator::Evaluate_LGFR;
  EvalTable[LLGFR] = &Simulator::Evaluate_LLGFR;
  EvalTable[LLGTR] = &Simulator::Evaluate_LLGTR;
  EvalTable[AGFR] = &Simulator::Evaluate_AGFR;
  EvalTable[SGFR] = &Simulator::Evaluate_SGFR;
  EvalTable[ALGFR] = &Simulator::Evaluate_ALGFR;
  EvalTable[SLGFR] = &Simulator::Evaluate_SLGFR;
  EvalTable[MSGFR] = &Simulator::Evaluate_MSGFR;
  EvalTable[DSGFR] = &Simulator::Evaluate_DSGFR;
  EvalTable[KMAC] = &Simulator::Evaluate_KMAC;
  EvalTable[LRVR] = &Simulator::Evaluate_LRVR;
  EvalTable[CGR] = &Simulator::Evaluate_CGR;
  EvalTable[CLGR] = &Simulator::Evaluate_CLGR;
  EvalTable[LBR] = &Simulator::Evaluate_LBR;
  EvalTable[LHR] = &Simulator::Evaluate_LHR;
  EvalTable[KMF] = &Simulator::Evaluate_KMF;
  EvalTable[KMO] = &Simulator::Evaluate_KMO;
  EvalTable[PCC] = &Simulator::Evaluate_PCC;
  EvalTable[KMCTR] = &Simulator::Evaluate_KMCTR;
  EvalTable[KM] = &Simulator::Evaluate_KM;
  EvalTable[KMC] = &Simulator::Evaluate_KMC;
  EvalTable[CGFR] = &Simulator::Evaluate_CGFR;
  EvalTable[KIMD] = &Simulator::Evaluate_KIMD;
  EvalTable[KLMD] = &Simulator::Evaluate_KLMD;
  EvalTable[CFDTR] = &Simulator::Evaluate_CFDTR;
  EvalTable[CLGDTR] = &Simulator::Evaluate_CLGDTR;
  EvalTable[CLFDTR] = &Simulator::Evaluate_CLFDTR;
  EvalTable[BCTGR] = &Simulator::Evaluate_BCTGR;
  EvalTable[CFXTR] = &Simulator::Evaluate_CFXTR;
  EvalTable[CLFXTR] = &Simulator::Evaluate_CLFXTR;
  EvalTable[CDFTR] = &Simulator::Evaluate_CDFTR;
  EvalTable[CDLGTR] = &Simulator::Evaluate_CDLGTR;
  EvalTable[CDLFTR] = &Simulator::Evaluate_CDLFTR;
  EvalTable[CXFTR] = &Simulator::Evaluate_CXFTR;
  EvalTable[CXLGTR] = &Simulator::Evaluate_CXLGTR;
  EvalTable[CXLFTR] = &Simulator::Evaluate_CXLFTR;
  EvalTable[CGRT] = &Simulator::Evaluate_CGRT;
  EvalTable[NGR] = &Simulator::Evaluate_NGR;
  EvalTable[OGR] = &Simulator::Evaluate_OGR;
  EvalTable[XGR] = &Simulator::Evaluate_XGR;
  EvalTable[FLOGR] = &Simulator::Evaluate_FLOGR;
  EvalTable[LLGCR] = &Simulator::Evaluate_LLGCR;
  EvalTable[LLGHR] = &Simulator::Evaluate_LLGHR;
  EvalTable[MLGR] = &Simulator::Evaluate_MLGR;
  EvalTable[MGRK] = &Simulator::Evaluate_MGRK;
  EvalTable[MG] = &Simulator::Evaluate_MG;
  EvalTable[DLGR] = &Simulator::Evaluate_DLGR;
  EvalTable[ALCGR] = &Simulator::Evaluate_ALCGR;
  EvalTable[SLBGR] = &Simulator::Evaluate_SLBGR;
  EvalTable[EPSW] = &Simulator::Evaluate_EPSW;
  EvalTable[TRTT] = &Simulator::Evaluate_TRTT;
  EvalTable[TRTO] = &Simulator::Evaluate_TRTO;
  EvalTable[TROT] = &Simulator::Evaluate_TROT;
  EvalTable[TROO] = &Simulator::Evaluate_TROO;
  EvalTable[LLCR] = &Simulator::Evaluate_LLCR;
  EvalTable[LLHR] = &Simulator::Evaluate_LLHR;
  EvalTable[MLR] = &Simulator::Evaluate_MLR;
  EvalTable[DLR] = &Simulator::Evaluate_DLR;
  EvalTable[ALCR] = &Simulator::Evaluate_ALCR;
  EvalTable[SLBR] = &Simulator::Evaluate_SLBR;
  EvalTable[CU14] = &Simulator::Evaluate_CU14;
  EvalTable[CU24] = &Simulator::Evaluate_CU24;
  EvalTable[CU41] = &Simulator::Evaluate_CU41;
  EvalTable[CU42] = &Simulator::Evaluate_CU42;
  EvalTable[TRTRE] = &Simulator::Evaluate_TRTRE;
  EvalTable[SRSTU] = &Simulator::Evaluate_SRSTU;
  EvalTable[TRTE] = &Simulator::Evaluate_TRTE;
  EvalTable[AHHHR] = &Simulator::Evaluate_AHHHR;
  EvalTable[SHHHR] = &Simulator::Evaluate_SHHHR;
  EvalTable[ALHHHR] = &Simulator::Evaluate_ALHHHR;
  EvalTable[SLHHHR] = &Simulator::Evaluate_SLHHHR;
  EvalTable[CHHR] = &Simulator::Evaluate_CHHR;
  EvalTable[AHHLR] = &Simulator::Evaluate_AHHLR;
  EvalTable[SHHLR] = &Simulator::Evaluate_SHHLR;
  EvalTable[ALHHLR] = &Simulator::Evaluate_ALHHLR;
  EvalTable[SLHHLR] = &Simulator::Evaluate_SLHHLR;
  EvalTable[CHLR] = &Simulator::Evaluate_CHLR;
  EvalTable[POPCNT_Z] = &Simulator::Evaluate_POPCNT_Z;
  EvalTable[LOCGR] = &Simulator::Evaluate_LOCGR;
  EvalTable[NGRK] = &Simulator::Evaluate_NGRK;
  EvalTable[OGRK] = &Simulator::Evaluate_OGRK;
  EvalTable[XGRK] = &Simulator::Evaluate_XGRK;
  EvalTable[AGRK] = &Simulator::Evaluate_AGRK;
  EvalTable[SGRK] = &Simulator::Evaluate_SGRK;
  EvalTable[ALGRK] = &Simulator::Evaluate_ALGRK;
  EvalTable[SLGRK] = &Simulator::Evaluate_SLGRK;
  EvalTable[LOCR] = &Simulator::Evaluate_LOCR;
  EvalTable[NRK] = &Simulator::Evaluate_NRK;
  EvalTable[ORK] = &Simulator::Evaluate_ORK;
  EvalTable[XRK] = &Simulator::Evaluate_XRK;
  EvalTable[ARK] = &Simulator::Evaluate_ARK;
  EvalTable[SRK] = &Simulator::Evaluate_SRK;
  EvalTable[ALRK] = &Simulator::Evaluate_ALRK;
  EvalTable[SLRK] = &Simulator::Evaluate_SLRK;
  EvalTable[LTG] = &Simulator::Evaluate_LTG;
  EvalTable[LG] = &Simulator::Evaluate_LG;
  EvalTable[CVBY] = &Simulator::Evaluate_CVBY;
  EvalTable[AG] = &Simulator::Evaluate_AG;
  EvalTable[SG] = &Simulator::Evaluate_SG;
  EvalTable[ALG] = &Simulator::Evaluate_ALG;
  EvalTable[SLG] = &Simulator::Evaluate_SLG;
  EvalTable[MSG] = &Simulator::Evaluate_MSG;
  EvalTable[DSG] = &Simulator::Evaluate_DSG;
  EvalTable[CVBG] = &Simulator::Evaluate_CVBG;
  EvalTable[LRVG] = &Simulator::Evaluate_LRVG;
  EvalTable[LT] = &Simulator::Evaluate_LT;
  EvalTable[LGF] = &Simulator::Evaluate_LGF;
  EvalTable[LGH] = &Simulator::Evaluate_LGH;
  EvalTable[LLGF] = &Simulator::Evaluate_LLGF;
  EvalTable[LLGT] = &Simulator::Evaluate_LLGT;
  EvalTable[AGF] = &Simulator::Evaluate_AGF;
  EvalTable[SGF] = &Simulator::Evaluate_SGF;
  EvalTable[ALGF] = &Simulator::Evaluate_ALGF;
  EvalTable[SLGF] = &Simulator::Evaluate_SLGF;
  EvalTable[MSGF] = &Simulator::Evaluate_MSGF;
  EvalTable[DSGF] = &Simulator::Evaluate_DSGF;
  EvalTable[LRV] = &Simulator::Evaluate_LRV;
  EvalTable[LRVH] = &Simulator::Evaluate_LRVH;
  EvalTable[CG] = &Simulator::Evaluate_CG;
  EvalTable[CLG] = &Simulator::Evaluate_CLG;
  EvalTable[STG] = &Simulator::Evaluate_STG;
  EvalTable[NTSTG] = &Simulator::Evaluate_NTSTG;
  EvalTable[CVDY] = &Simulator::Evaluate_CVDY;
  EvalTable[CVDG] = &Simulator::Evaluate_CVDG;
  EvalTable[STRVG] = &Simulator::Evaluate_STRVG;
  EvalTable[CGF] = &Simulator::Evaluate_CGF;
  EvalTable[CLGF] = &Simulator::Evaluate_CLGF;
  EvalTable[LTGF] = &Simulator::Evaluate_LTGF;
  EvalTable[CGH] = &Simulator::Evaluate_CGH;
  EvalTable[PFD] = &Simulator::Evaluate_PFD;
  EvalTable[STRV] = &Simulator::Evaluate_STRV;
  EvalTable[STRVH] = &Simulator::Evaluate_STRVH;
  EvalTable[BCTG] = &Simulator::Evaluate_BCTG;
  EvalTable[STY] = &Simulator::Evaluate_STY;
  EvalTable[MSY] = &Simulator::Evaluate_MSY;
  EvalTable[MSC] = &Simulator::Evaluate_MSC;
  EvalTable[NY] = &Simulator::Evaluate_NY;
  EvalTable[CLY] = &Simulator::Evaluate_CLY;
  EvalTable[OY] = &Simulator::Evaluate_OY;
  EvalTable[XY] = &Simulator::Evaluate_XY;
  EvalTable[LY] = &Simulator::Evaluate_LY;
  EvalTable[CY] = &Simulator::Evaluate_CY;
  EvalTable[AY] = &Simulator::Evaluate_AY;
  EvalTable[SY] = &Simulator::Evaluate_SY;
  EvalTable[MFY] = &Simulator::Evaluate_MFY;
  EvalTable[ALY] = &Simulator::Evaluate_ALY;
  EvalTable[SLY] = &Simulator::Evaluate_SLY;
  EvalTable[STHY] = &Simulator::Evaluate_STHY;
  EvalTable[LAY] = &Simulator::Evaluate_LAY;
  EvalTable[STCY] = &Simulator::Evaluate_STCY;
  EvalTable[ICY] = &Simulator::Evaluate_ICY;
  EvalTable[LAEY] = &Simulator::Evaluate_LAEY;
  EvalTable[LB] = &Simulator::Evaluate_LB;
  EvalTable[LGB] = &Simulator::Evaluate_LGB;
  EvalTable[LHY] = &Simulator::Evaluate_LHY;
  EvalTable[CHY] = &Simulator::Evaluate_CHY;
  EvalTable[AHY] = &Simulator::Evaluate_AHY;
  EvalTable[SHY] = &Simulator::Evaluate_SHY;
  EvalTable[MHY] = &Simulator::Evaluate_MHY;
  EvalTable[NG] = &Simulator::Evaluate_NG;
  EvalTable[OG] = &Simulator::Evaluate_OG;
  EvalTable[XG] = &Simulator::Evaluate_XG;
  EvalTable[LGAT] = &Simulator::Evaluate_LGAT;
  EvalTable[MLG] = &Simulator::Evaluate_MLG;
  EvalTable[DLG] = &Simulator::Evaluate_DLG;
  EvalTable[ALCG] = &Simulator::Evaluate_ALCG;
  EvalTable[SLBG] = &Simulator::Evaluate_SLBG;
  EvalTable[STPQ] = &Simulator::Evaluate_STPQ;
  EvalTable[LPQ] = &Simulator::Evaluate_LPQ;
  EvalTable[LLGC] = &Simulator::Evaluate_LLGC;
  EvalTable[LLGH] = &Simulator::Evaluate_LLGH;
  EvalTable[LLC] = &Simulator::Evaluate_LLC;
  EvalTable[LLH] = &Simulator::Evaluate_LLH;
  EvalTable[ML] = &Simulator::Evaluate_ML;
  EvalTable[DL] = &Simulator::Evaluate_DL;
  EvalTable[ALC] = &Simulator::Evaluate_ALC;
  EvalTable[SLB] = &Simulator::Evaluate_SLB;
  EvalTable[LLGTAT] = &Simulator::Evaluate_LLGTAT;
  EvalTable[LLGFAT] = &Simulator::Evaluate_LLGFAT;
  EvalTable[LAT] = &Simulator::Evaluate_LAT;
  EvalTable[LBH] = &Simulator::Evaluate_LBH;
  EvalTable[LLCH] = &Simulator::Evaluate_LLCH;
  EvalTable[STCH] = &Simulator::Evaluate_STCH;
  EvalTable[LHH] = &Simulator::Evaluate_LHH;
  EvalTable[LLHH] = &Simulator::Evaluate_LLHH;
  EvalTable[STHH] = &Simulator::Evaluate_STHH;
  EvalTable[LFHAT] = &Simulator::Evaluate_LFHAT;
  EvalTable[LFH] = &Simulator::Evaluate_LFH;
  EvalTable[STFH] = &Simulator::Evaluate_STFH;
  EvalTable[CHF] = &Simulator::Evaluate_CHF;
  EvalTable[MVCDK] = &Simulator::Evaluate_MVCDK;
  EvalTable[MVHHI] = &Simulator::Evaluate_MVHHI;
  EvalTable[MVGHI] = &Simulator::Evaluate_MVGHI;
  EvalTable[MVHI] = &Simulator::Evaluate_MVHI;
  EvalTable[CHHSI] = &Simulator::Evaluate_CHHSI;
  EvalTable[CGHSI] = &Simulator::Evaluate_CGHSI;
  EvalTable[CHSI] = &Simulator::Evaluate_CHSI;
  EvalTable[CLFHSI] = &Simulator::Evaluate_CLFHSI;
  EvalTable[TBEGIN] = &Simulator::Evaluate_TBEGIN;
  EvalTable[TBEGINC] = &Simulator::Evaluate_TBEGINC;
  EvalTable[LMG] = &Simulator::Evaluate_LMG;
  EvalTable[SRAG] = &Simulator::Evaluate_SRAG;
  EvalTable[SLAG] = &Simulator::Evaluate_SLAG;
  EvalTable[SRLG] = &Simulator::Evaluate_SRLG;
  EvalTable[SLLG] = &Simulator::Evaluate_SLLG;
  EvalTable[CSY] = &Simulator::Evaluate_CSY;
  EvalTable[CSG] = &Simulator::Evaluate_CSG;
  EvalTable[RLLG] = &Simulator::Evaluate_RLLG;
  EvalTable[RLL] = &Simulator::Evaluate_RLL;
  EvalTable[STMG] = &Simulator::Evaluate_STMG;
  EvalTable[STMH] = &Simulator::Evaluate_STMH;
  EvalTable[STCMH] = &Simulator::Evaluate_STCMH;
  EvalTable[STCMY] = &Simulator::Evaluate_STCMY;
  EvalTable[CDSY] = &Simulator::Evaluate_CDSY;
  EvalTable[CDSG] = &Simulator::Evaluate_CDSG;
  EvalTable[BXHG] = &Simulator::Evaluate_BXHG;
  EvalTable[BXLEG] = &Simulator::Evaluate_BXLEG;
  EvalTable[ECAG] = &Simulator::Evaluate_ECAG;
  EvalTable[TMY] = &Simulator::Evaluate_TMY;
  EvalTable[MVIY] = &Simulator::Evaluate_MVIY;
  EvalTable[NIY] = &Simulator::Evaluate_NIY;
  EvalTable[CLIY] = &Simulator::Evaluate_CLIY;
  EvalTable[OIY] = &Simulator::Evaluate_OIY;
  EvalTable[XIY] = &Simulator::Evaluate_XIY;
  EvalTable[ASI] = &Simulator::Evaluate_ASI;
  EvalTable[ALSI] = &Simulator::Evaluate_ALSI;
  EvalTable[AGSI] = &Simulator::Evaluate_AGSI;
  EvalTable[ALGSI] = &Simulator::Evaluate_ALGSI;
  EvalTable[ICMH] = &Simulator::Evaluate_ICMH;
  EvalTable[ICMY] = &Simulator::Evaluate_ICMY;
  Eva
"""


```