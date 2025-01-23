Response:

### 提示词
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/mips64/simulator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
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

double Simulato
```