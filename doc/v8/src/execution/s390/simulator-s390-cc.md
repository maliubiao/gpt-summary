Response:
The user wants to understand the functionality of the provided C++ code snippet. I need to:

1. **Identify the main purpose of the code:**  The filename `simulator-s390.cc` strongly suggests it's a simulator for the s390 architecture.
2. **Break down the code into functional units:**  Look for classes, key methods, and data structures. The `Simulator` and `S390Debugger` classes seem central.
3. **Explain the role of each unit:** Describe what each part of the code does.
4. **Address the specific questions:**
    - Check if the filename ends with `.tq`.
    - Determine if the code relates to JavaScript functionality.
    - Provide JavaScript examples if applicable.
    - Give examples of code logic and potential programming errors.
5. **Summarize the overall functionality.**
6. **Remember this is part 1 of 10.**

**Plan:**

1. State the main function: Simulating s390 architecture.
2. Describe the `Simulator` class: Core simulation logic, register management, memory access, instruction execution.
3. Describe the `S390Debugger` class: Interactive debugging capabilities.
4. Check the filename extension (.cc, not .tq).
5. Determine JavaScript relevance: This code is a low-level simulator, likely used for development and testing of the V8 engine on s390. It doesn't directly implement JavaScript features but supports their execution on the simulated architecture.
6. Provide a JavaScript example: Show how JavaScript code execution would eventually rely on the simulated instructions.
7. Provide a code logic example: Focus on the debugging commands and their effects (e.g., `si`, `p`).
8. Provide a common programming error example: Relate it to debugging in the simulated environment (e.g., incorrect address for breakpoint).
9. Summarize the functions covered in this part.
```cpp
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
#
### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  V(vn, VN, 0xE768)         /* type = VRR_C VECTOR AN
```