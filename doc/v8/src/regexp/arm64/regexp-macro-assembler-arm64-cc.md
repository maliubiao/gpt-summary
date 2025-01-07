Response:
The user wants a summary of the functionality of the provided C++ code, which is a part of the V8 JavaScript engine responsible for regular expression matching on ARM64 architecture.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The filename `regexp-macro-assembler-arm64.cc` strongly suggests that this code is responsible for generating machine code (assembly) for regular expression operations specifically for the ARM64 architecture. The "macro assembler" part indicates it provides a higher-level abstraction over raw assembly instructions.

2. **Examine Key Includes:** The `#include` statements reveal dependencies:
    * `regexp-macro-assembler-arm64.h`:  Its own header file, suggesting it defines a class interface.
    * `macro-assembler-arm64-inl.h`, `macro-assembler.h`: Core V8 assembler components.
    * `regexp-macro-assembler.h`:  A general regular expression assembler interface.
    * `regexp-stack.h`:  Deals with managing the stack used during regex matching.
    * `objects-inl.h`, `strings/unicode.h`:  V8's object model and Unicode handling.

3. **Analyze Class Definition:** The code defines a class `RegExpMacroAssemblerARM64` inheriting from `NativeRegExpMacroAssembler`. This confirms its role as an architecture-specific implementation.

4. **Register Usage Convention:** The detailed comment on register assignments is crucial. It shows how the code manages state during regex execution, including input position, current character, backtrack stack, and capture registers. This indicates a core function is to manage the execution environment for regex matching.

5. **Stack Layout:**  The description of the stack frame layout is also key. It reveals how parameters, local variables, and capture registers are stored and accessed during execution. This further supports the idea that this code is about controlling the execution flow of the regex matching process.

6. **Method Analysis (Skimming):**  Quickly go through the provided methods. Notice patterns:
    * Methods like `AdvanceCurrentPosition`, `AdvanceRegister` manipulate the state described in the register usage.
    * `Backtrack`, `Bind`, `BindJumpTarget` relate to control flow within the generated assembly code.
    * `CheckCharacter`, `CheckAtStart`, `CheckNotBackReferenceIgnoreCase`, `CheckCharacterInRange`, `CheckBitInTable`, `CheckSpecialClassRanges` are all about comparing the input against patterns – core regex matching logic.
    * `PushCachedRegisters`, `PopCachedRegisters` indicate optimization for frequently used registers.
    * `Fail`, `Success` represent termination conditions of the matching process.
    * Methods involving `CallCFunctionFromIrregexpCode` suggest interaction with lower-level C++ helper functions for complex operations (like Unicode case-insensitive comparisons).

7. **Address Specific Instructions:**
    * The `#if V8_TARGET_ARCH_ARM64` guard confirms its architecture-specific nature.
    * The `ACCESS_MASM(masm_)` macro suggests it's using a macro assembler to generate ARM64 instructions.

8. **Connect to JavaScript (If Applicable):**  The code handles regex matching, a fundamental part of JavaScript. Examples of JavaScript regex usage are relevant.

9. **Code Logic and Assumptions:** Some methods perform comparisons and branching. Hypothesize inputs and outputs for a simple scenario (e.g., `CheckCharacter`).

10. **Common Programming Errors:** Think about what could go wrong in regex implementations (e.g., incorrect capture group handling, off-by-one errors in indexing).

11. **Structure the Summary:**  Organize the findings into logical categories: core functionality, key aspects, relationships to JavaScript, code logic, potential errors, and the final summary.

12. **Address the `.tq` Question:** Directly answer the question about the `.tq` extension and Torque.

13. **Review and Refine:** Read through the summary, ensuring it's clear, concise, and accurately reflects the code's purpose. Ensure all parts of the prompt are addressed. For instance, explicitly state that the code is *not* Torque code.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive summary of its functionalities.
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_ARM64

#include "src/regexp/arm64/regexp-macro-assembler-arm64.h"

#include "src/codegen/arm64/macro-assembler-arm64-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp-stack.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/strings/unicode.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention:
 * - w19     : Used to temporarely store a value before a call to C code.
 *             See CheckNotBackReferenceIgnoreCase.
 * - x20     : Pointer to the current InstructionStream object,
 *             it includes the heap object tag.
 * - w21     : Current position in input, as negative offset from
 *             the end of the string. Please notice that this is
 *             the byte offset, not the character offset!
 * - w22     : Currently loaded character. Must be loaded using
 *             LoadCurrentCharacter before using any of the dispatch methods.
 * - x23     : Points to tip of backtrack stack.
 * - w24     : Position of the first character minus one: non_position_value.
 *             Used to initialize capture registers.
 * - x25     : Address at the end of the input string: input_end.
 *             Points to byte after last character in input.
 * - x26     : Address at the start of the input string: input_start.
 * - w27     : Where to start in the input string.
 * - x28     : Output array pointer.
 * - x29/fp  : Frame pointer. Used to access arguments, local variables and
 *             RegExp registers.
 * - x16/x17 : IP registers, used by assembler. Very volatile.
 * - sp      : Points to tip of C stack.
 *
 * - x0-x7   : Used as a cache to store 32 bit capture registers. These
 *             registers need to be retained every time a call to C code
 *             is done.
 *
 * The remaining registers are free for computations.
 * Each call to a public method should retain this convention.
 *
 * The stack will have the following structure:
 *
 *  Location     Name               Description
 *               (as referred to
 *               in the code)
 *
 *  - fp[104]    Address regexp     Address of the JSRegExp object. Unused in
 *                                  native code, passed to match signature of
 *                                  the interpreter.
 *  - fp[96]     isolate            Address of the current isolate.
 *  ^^^^^^^^^ sp when called ^^^^^^^^^
 *  - fp[16..88] r19-r28            Backup of CalleeSaved registers.
 *  - fp[8]      lr                 Return from the RegExp code.
 *  - fp[0]      fp                 Old frame pointer.
 *  ^^^^^^^^^ fp ^^^^^^^^^
 *  - fp[-8]     frame marker
 *  - fp[-16]    isolate
 *  - fp[-24]    direct_call        1 => Direct call from JavaScript code.
 *                                  0 => Call through the runtime system.
 *  - fp[-32]    output_size        Output may fit multiple sets of matches.
 *  - fp[-40]    input              Handle containing the input string.
 *  - fp[-48]    success_counter
 *  ^^^^^^^^^^^^^ From here and downwards we store 32 bit values ^^^^^^^^^^^^^
 *  - fp[-56]    register N         Capture registers initialized with
 *  - fp[-60]    register N + 1     non_position_value.
 *               ...                The first kNumCachedRegisters (N) registers
 *               ...                are cached in x0 to x7.
 *               ...                Only positions must be stored in the first
 *  -            ...                num_saved_registers_ registers.
 *  -            ...
 *  -            register N + num_registers - 1
 *  ^^^^^^^^^ sp ^^^^^^^^^
 *
 * The first num_saved_registers_ registers are initialized to point to
 * "character -1" in the string (i.e., char_size() bytes before the first
 * character of the string). The remaining registers start out as garbage.
 *
 * The data up to the return address must be placed there by the calling
 * code and the remaining arguments are passed in registers, e.g. by calling the
 * code entry as cast to a function with the signature:
 * int (*match)(String input_string,
 *              int start_index,
 *              Address start,
 *              Address end,
 *              int* capture_output_array,
 *              int num_capture_registers,
 *              bool direct_call = false,
 *              Isolate* isolate,
 *              Address regexp);
 * The call is performed by NativeRegExpMacroAssembler::Execute()
 * (in regexp-macro-assembler.cc) via the GeneratedCode wrapper.
 */

#define __ ACCESS_MASM(masm_)

RegExpMacroAssemblerARM64::RegExpMacroAssemblerARM64(Isolate* isolate,
                                                     Zone* zone, Mode mode,
                                                     int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(std::make_unique<MacroAssembler>(
          isolate, zone, CodeObjectRequired::kYes,
          NewAssemblerBuffer(kInitialBufferSize))),
      no_root_array_scope_(masm_.get()),
      mode_(mode),
      num_registers_(registers_to_save),
      num_saved_registers_(registers_to_save),
      entry_label_(),
      start_label_(),
      success_label_(),
      backtrack_label_(),
      exit_label_() {
  DCHECK_EQ(0, registers_to_save % 2);
  // We can cache at most 16 W registers in x0-x7.
  static_assert(kNumCachedRegisters <= 16);
  static_assert((kNumCachedRegisters % 2) == 0);
  __ CallTarget();

  __ B(&entry_label_);   // We'll write the entry code later.
  __ Bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerARM64::~RegExpMacroAssemblerARM64() = default;

void RegExpMacroAssemblerARM64::AbortedCodeGeneration() {
  masm_->AbortedCodeGeneration();
  entry_label_.Unuse();
  start_label_.Unuse();
  success_label_.Unuse();
  backtrack_label_.Unuse();
  exit_label_.Unuse();
  check_preempt_label_.Unuse();
  stack_overflow_label_.Unuse();
  fallback_label_.Unuse();
}

int RegExpMacroAssemblerARM64::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerARM64::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ Add(current_input_offset(),
           current_input_offset(), by * char_size());
  }
}

void RegExpMacroAssemblerARM64::AdvanceRegister(int reg, int by) {
  DCHECK((reg >= 0) && (reg < num_registers_));
  if (by != 0) {
    RegisterState register_state = GetRegisterState(reg);
    switch (register_state) {
      case STACKED:
        __ Ldr(w10, register_location(reg));
        __ Add(w10, w10, by);
        __ Str(w10, register_location(reg));
        break;
      case CACHED_LSW: {
        Register to_advance = GetCachedRegister(reg);
        __ Add(to_advance, to_advance, by);
        break;
      }
      case CACHED_MSW: {
        Register to_advance = GetCachedRegister(reg);
        // Sign-extend to int64, shift as uint64, cast back to int64.
        __ Add(
            to_advance, to_advance,
            static_cast<int64_t>(static_cast<uint64_t>(static_cast<int64_t>(by))
                                 << kWRegSizeInBits));
        break;
      }
      default:
        UNREACHABLE();
    }
  }
}

void RegExpMacroAssemblerARM64::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    UseScratchRegisterScope temps(masm_.get());
    Register scratch = temps.AcquireW();
    __ Ldr(scratch, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ Add(scratch, scratch, 1);
    __ Str(scratch, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ Cmp(scratch, Operand(backtrack_limit()));
    __ B(ne, &next);

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ B(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  Pop(w10);
  __ Add(x10, code_pointer(), Operand(w10, UXTW));
  __ Br(x10);
}

void RegExpMacroAssemblerARM64::Bind(Label* label) {
  __ Bind(label);
}

void RegExpMacroAssemblerARM64::BindJumpTarget(Label* label) {
  __ BindJumpTarget(label);
}

void RegExpMacroAssemblerARM64::CheckCharacter(uint32_t c, Label* on_equal) {
  CompareAndBranchOrBacktrack(current_character(), c, eq, on_equal);
}

void RegExpMacroAssemblerARM64::CheckCharacterGT(base::uc16 limit,
                                                 Label* on_greater) {
  CompareAndBranchOrBacktrack(current_character(), limit, hi, on_greater);
}

void RegExpMacroAssemblerARM64::CheckAtStart(int cp_offset,
                                             Label* on_at_start) {
  __ Add(w10, current_input_offset(),
         Operand(-char_size() + cp_offset * char_size()));
  __ Cmp(w10, string_start_minus_one());
  BranchOrBacktrack(eq, on_at_start);
}

void RegExpMacroAssemblerARM64::CheckNotAtStart(int cp_offset,
                                                Label* on_not_at_start) {
  __ Add(w10, current_input_offset(),
         Operand(-char_size() + cp_offset * char_size()));
  __ Cmp(w10, string_start_minus_one());
  BranchOrBacktrack(ne, on_not_at_start);
}

void RegExpMacroAssemblerARM64::CheckCharacterLT(base::uc16 limit,
                                                 Label* on_less) {
  CompareAndBranchOrBacktrack(current_character(), limit, lo, on_less);
}

void RegExpMacroAssemblerARM64::CheckCharacters(
    base::Vector<const base::uc16> str, int cp_offset, Label* on_failure,
    bool check_end_of_string) {
  // This method is only ever called from the cctests.

  if (check_end_of_string) {
    // Is last character of required match inside string.
    CheckPosition(cp_offset + str.length() - 1, on_failure);
  }

  Register characters_address = x11;

  __ Add(characters_address,
         input_end(),
         Operand(current_input_offset(), SXTW));
  if (cp_offset != 0) {
    __ Add(characters_address, characters_address, cp_offset * char_size());
  }

  for (int i = 0; i < str.length(); i++) {
    if (mode_ == LATIN1) {
      __ Ldrb(w10, MemOperand(characters_address, 1, PostIndex));
      DCHECK_GE(String::kMaxOneByteCharCode, str[i]);
    } else {
      __ Ldrh(w10, MemOperand(characters_address, 2, PostIndex));
    }
    CompareAndBranchOrBacktrack(w10, str[i], ne, on_failure);
  }
}

void RegExpMacroAssemblerARM64::CheckGreedyLoop(Label* on_equal) {
  __ Ldr(w10, MemOperand(backtrack_stackpointer()));
  __ Cmp(current_input_offset(), w10);
  __ Cset(x11, eq);
  __ Add(backtrack_stackpointer(),
         backtrack_stackpointer(), Operand(x11, LSL, kWRegSizeLog2));
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerARM64::PushCachedRegisters() {
  CPURegList cached_registers(CPURegister::kRegister, kXRegSizeInBits, 0, 7);
  DCHECK_EQ(kNumCachedRegisters, cached_registers.Count() * 2);
  __ PushCPURegList(cached_registers);
}

void RegExpMacroAssemblerARM64::PopCachedRegisters() {
  CPURegList cached_registers(CPURegister::kRegister, kXRegSizeInBits, 0, 7);
  DCHECK_EQ(kNumCachedRegisters, cached_registers.Count() * 2);
  __ PopCPURegList(cached_registers);
}

void RegExpMacroAssemblerARM64::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;

  Register capture_start_offset = w10;
  // Save the capture length in a callee-saved register so it will
  // be preserved if we call a C helper.
  Register capture_length = w19;
  DCHECK(kCalleeSaved.IncludesAliasOf(capture_length));

  // Find length of back-referenced capture.
  DCHECK_EQ(0, start_reg % 2);
  if (start_reg < kNumCachedRegisters) {
    __ Mov(capture_start_offset.X(), GetCachedRegister(start_reg));
    __ Lsr(x11, GetCachedRegister(start_reg), kWRegSizeInBits);
  } else {
    __ Ldp(w11, capture_start_offset, capture_location(start_reg, x10));
  }
  __ Sub(capture_length, w11, capture_start_offset);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ CompareAndBranch(capture_length, Operand(0), eq, &fallthrough);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ Add(w12, string_start_minus_one(), capture_length);
    __ Cmp(current_input_offset(), w12);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ Cmn(capture_length, current_input_offset());
    BranchOrBacktrack(gt, on_no_match);
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_check;

    Register capture_start_address = x12;
    Register capture_end_address = x13;
    Register current_position_address = x14;

    __ Add(capture_start_address,
           input_end(),
           Operand(capture_start_offset, SXTW));
    __ Add(capture_end_address, capture_start_address,
           Operand(capture_length, SXTW));
    __ Add(current_position_address,
           input_end(),
           Operand(current_input_offset(), SXTW));
    if (read_backward) {
      // Offset by length when matching backwards.
      __ Sub(current_position_address, current_position_address,
             Operand(capture_length, SXTW));
    }

    Label loop;
    __ Bind(&loop);
    __ Ldrb(w10, MemOperand(capture_start_address, 1, PostIndex));
    __ Ldrb(w11, MemOperand(current_position_address, 1, PostIndex));
    __ Cmp(w10, w11);
    __ B(eq, &loop_check);

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ Orr(w10, w10, 0x20);  // Convert capture character to lower-case.
    __ Orr(w11, w11, 0x20);  // Also convert input character.
    __ Cmp(w11, w10);
    __ B(ne, &fail);
    __ Sub(w10, w10, 'a');
    __ Cmp(w10, 'z' - 'a');  // Is w10 a lowercase letter?
    __ B(ls, &loop_check);  // In range 'a'-'z'.
    // Latin-1: Check for values in range [224,254] but not 247.
    __ Sub(w10, w10, 224 - 'a');
    __ Cmp(w10, 254 - 224);
    __ Ccmp(w10, 247 - 224, ZFlag, ls);  // Check for 247.
    __ B(eq, &fail);  // Weren't Latin-1 letters.

    __ Bind(&loop_check);
    __ Cmp(capture_start_address, capture_end_address);
    __ B(lt, &loop);
    __ B(&success);

    __ Bind(&fail);
    BranchOrBacktrack(al, on_no_match);

    __ Bind(&success);
    // Compute new value of character position after the matched part.
    __ Sub(current_input_offset().X(), current_position_address, input_end());
    if (read_backward) {
      __ Sub(current_input_offset().X(), current_input_offset().X(),
             Operand(capture_length, SXTW));
    }
    if (v8_flags.debug_code) {
      __ Cmp(current_input_offset().X(), Operand(current_input_offset(), SXTW));
      __ Ccmp(current_input_offset(), 0, NoFlag, eq);
      // The current input offset should be <= 0, and fit in a W register.
      __ Check(le, AbortReason::kOffsetOutOfRange);
    }
  } else {
    DCHECK(mode_ == UC16);
    int argument_count = 4;

    PushCachedRegisters();

    // Put arguments into arguments registers.
    // Parameters are
    //   x0: Address byte_offset1 - Address captured substring's start.
    //   x1: Address byte_offset2 - Address of current character position.
    //   w2: size_t byte_length - length of capture in bytes(!)
    //   x3: Isolate* isolate.

    // Address of start of capture.
    __ Add(x0, input_end(), Operand(capture_start_offset, SXTW));
    // Length of capture.
    __ Mov(w2, capture_length);
    // Address of current input position.
    __ Add(x1, input_end(), Operand(current_input_offset(), SXTW));
    if (read_backward) {
      __ Sub(x1, x1, Operand(capture_length, SXTW));
    }
    // Isolate.
    __ Mov(x3, ExternalReference::isolate_address(isolate()));

    {
      AllowExternalCallThatCantCauseGC scope(masm_.get());
      ExternalReference function =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(function, argument_count);
    }

    // Check if function returned non-zero for success or zero for failure.
    // x0 is one of the registers used as a cache so it must be tested before
    // the cache is restored.
    __ Cmp(x0, 0);
    PopCachedRegisters();
    BranchOrBacktrack(eq, on_no_match);

    // On success, advance position by length of capture.
    if (read_backward) {
      __ Sub(current_input_offset(), current_input_offset(), capture_length);
    } else {
      __ Add(current_input_offset(), current_input_offset(), capture_length);
    }
  }

  __ Bind(&fallthrough);
}

void RegExpMacroAssemblerARM64::CheckNotBackReference(int start_reg,
                                                      bool read_backward,
                                                      Label* on_no_match) {
  Label fallthrough;

  Register capture_start_address = x12;
  Register capture_end_address = x13;
  Register current_position_address = x14;
  Register capture_length = w15;

  // Find length of back-referenced capture.
  DCHECK_EQ(0, start_reg % 2);
  if (start_reg < kNumCachedRegisters) {
    __ Mov(x10, GetCachedRegister(start_reg));
    __ Lsr(x11, GetCachedRegister(start_reg), kWRegSizeInBits);
  } else {
    __ Ldp(w11, w10, capture_location(start_reg, x10));
  }
  __ Sub(capture_length, w11, w10);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ CompareAndBranch(capture_length, Operand(0), eq, &fallthrough);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ Add(w12, string_start_minus_one(), capture_length);
    __ Cmp(current_input_offset(), w12);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ Cmn(capture_length, current_input_offset());
    BranchOrBacktrack(gt, on_no_match);
  }

  // Compute pointers to match string and capture string
  __ Add(capture_start_address, input_end(), Operand(w10, SXTW));
  __ Add(capture_end_address,
         capture_start_address,
         Operand(capture_length, SXTW));
  __ Add(current_position_address,
         input_end(),
         Operand(current_input_offset(), SXTW));
  if (read_backward) {
    // Offset by length when matching backwards.
    __ Sub(current_position_address, current_position_address,
           Operand(capture_length, SXTW));
  }

  Label loop;
  __ Bind(&loop);
  if (mode_ == LATIN1) {
    __ Ldrb(w10, MemOperand(capture_start_address, 1, PostIndex));
    __ Ldrb(w11, MemOperand(current_position_address, 1, PostIndex));
  } else {
    DCHECK(mode_ == UC16);
    __ Ldrh(w10, MemOperand(capture_start_address, 2, PostIndex));
    __ Ldrh(w11, MemOperand(current_position_address, 2, PostIndex));
  }
  __ Cmp(w10, w11);
  BranchOrBacktrack(ne, on_no_match);
  __ Cmp(capture_start_address, capture_end_address);
  __ B(lt, &loop);

  // Move current character position to position after match.
  __ Sub(current_input_offset().X(), current_position_address, input_end());
  if (read_backward) {
    __ Sub(current_input_offset().X(), current_input_offset().X(),
           Operand(capture_length, SXTW));
  }

  if (v8_flags.debug_code) {
    __ Cmp(current_input_offset().X(), Operand(current_input_offset(), SXTW));
    __ Ccmp(current_input_offset(), 0, NoFlag, eq);
    // The current input offset should be <= 0, and fit in a W register.
    __ Check(le, AbortReason::kOffsetOutOfRange);
  }
  __ Bind(&fallthrough);
}

void RegExpMacroAssemblerARM64::CheckNotCharacter(unsigned c,
                                                  Label* on_not_equal) {
  CompareAndBranchOrBacktrack(current_character(), c, ne, on_not_equal);
}

void RegExpMacroAssemblerARM64::CheckCharacterAfterAnd(uint32_t c,
                                                       uint32_t mask,
                                                       Label* on_equal) {
  __ And(w10, current_character(), mask);
  CompareAndBranchOrBacktrack(w10, c, eq, on_equal);
}

void RegExpMacroAssemblerARM64::CheckNotCharacterAfterAnd(unsigned c,
                                                          unsigned mask,
                                                          Label* on_not_equal) {
  __ And(w10, current_character(), mask);
  CompareAndBranchOrBacktrack(w10, c, ne, on_not_equal);
}

void RegExpMacroAssemblerARM64::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ Sub(w10, current_character(), minus);
  __ And(w10, w10, mask);
  CompareAndBranchOrBacktrack(w10, c, ne, on_not_equal);
}

void RegExpMacroAssemblerARM64::CheckCharacterInRange(base::uc16 from,
                                                      base::uc16 to,
                                                      Label* on_in_range) {
  __ Sub(w10, current_character(), from);
  // Unsigned lower-or-same condition.
  CompareAndBranchOrBacktrack(w10, to - from, ls, on_in_range);
}

void RegExpMacroAssemblerARM64::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ Sub(w10, current_character(), from);
  // Unsigned higher condition.
  CompareAndBranchOrBacktrack(w10, to - from, hi, on_not_in_range);
}

void RegExpMacroAssemblerARM64::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  static const int kNumArguments = 2;
  __ Mov(w0, current_character());
  __ Mov(x1, GetOrAddRangeArray(ranges));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  __ Mov(code_pointer(), Operand(masm_->CodeObject()));
}

bool RegExpMacroAssemblerARM64::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  // Note: due to the arm64 oddity of x0 being a 'cached register',
  // pushing/popping registers must happen outside of CallIsCharacterInRange
  // s.t. we can compare the return value to 0 before popping x0.
  PushCachedRegisters();
  CallIsCharacterInRangeArray(ranges);
  __ Cmp(x0, 0);
  PopCachedRegisters();
  BranchOrBacktrack(ne, on_in_range);
  return true;
}

bool RegExpMacroAssemblerARM64::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  // Note: due to the arm64 oddity of x0 being a 'cached register',
  // pushing/popping registers must happen outside of CallIsCharacterInRange
  // s.t. we can compare the return value to 0 before popping x0.
  PushCachedRegisters();
  CallIsCharacterInRangeArray(ranges);
  __ Cmp(x0, 0);
  PopCachedRegisters();
  BranchOrBacktrack(eq, on_not_in_range);
  return true;
}

void RegExpMacroAssemblerARM64::CheckBitInTable(
    Handle<ByteArray> table,
    Label* on_bit_set) {
  __ Mov(x11, Operand(table));
  if ((mode_ != LATIN1) || (kTableMask != String::kMaxOneByteCharCode)) {
    __ And(w10, current_character(), kTableMask);
    __ Add(w10, w10, OFFSET_OF_DATA_START(ByteArray) - kHeapObject
Prompt: 
```
这是目录为v8/src/regexp/arm64/regexp-macro-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/arm64/regexp-macro-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_ARM64

#include "src/regexp/arm64/regexp-macro-assembler-arm64.h"

#include "src/codegen/arm64/macro-assembler-arm64-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp-stack.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/strings/unicode.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention:
 * - w19     : Used to temporarely store a value before a call to C code.
 *             See CheckNotBackReferenceIgnoreCase.
 * - x20     : Pointer to the current InstructionStream object,
 *             it includes the heap object tag.
 * - w21     : Current position in input, as negative offset from
 *             the end of the string. Please notice that this is
 *             the byte offset, not the character offset!
 * - w22     : Currently loaded character. Must be loaded using
 *             LoadCurrentCharacter before using any of the dispatch methods.
 * - x23     : Points to tip of backtrack stack.
 * - w24     : Position of the first character minus one: non_position_value.
 *             Used to initialize capture registers.
 * - x25     : Address at the end of the input string: input_end.
 *             Points to byte after last character in input.
 * - x26     : Address at the start of the input string: input_start.
 * - w27     : Where to start in the input string.
 * - x28     : Output array pointer.
 * - x29/fp  : Frame pointer. Used to access arguments, local variables and
 *             RegExp registers.
 * - x16/x17 : IP registers, used by assembler. Very volatile.
 * - sp      : Points to tip of C stack.
 *
 * - x0-x7   : Used as a cache to store 32 bit capture registers. These
 *             registers need to be retained every time a call to C code
 *             is done.
 *
 * The remaining registers are free for computations.
 * Each call to a public method should retain this convention.
 *
 * The stack will have the following structure:
 *
 *  Location     Name               Description
 *               (as referred to
 *               in the code)
 *
 *  - fp[104]    Address regexp     Address of the JSRegExp object. Unused in
 *                                  native code, passed to match signature of
 *                                  the interpreter.
 *  - fp[96]     isolate            Address of the current isolate.
 *  ^^^^^^^^^ sp when called ^^^^^^^^^
 *  - fp[16..88] r19-r28            Backup of CalleeSaved registers.
 *  - fp[8]      lr                 Return from the RegExp code.
 *  - fp[0]      fp                 Old frame pointer.
 *  ^^^^^^^^^ fp ^^^^^^^^^
 *  - fp[-8]     frame marker
 *  - fp[-16]    isolate
 *  - fp[-24]    direct_call        1 => Direct call from JavaScript code.
 *                                  0 => Call through the runtime system.
 *  - fp[-32]    output_size        Output may fit multiple sets of matches.
 *  - fp[-40]    input              Handle containing the input string.
 *  - fp[-48]    success_counter
 *  ^^^^^^^^^^^^^ From here and downwards we store 32 bit values ^^^^^^^^^^^^^
 *  - fp[-56]    register N         Capture registers initialized with
 *  - fp[-60]    register N + 1     non_position_value.
 *               ...                The first kNumCachedRegisters (N) registers
 *               ...                are cached in x0 to x7.
 *               ...                Only positions must be stored in the first
 *  -            ...                num_saved_registers_ registers.
 *  -            ...
 *  -            register N + num_registers - 1
 *  ^^^^^^^^^ sp ^^^^^^^^^
 *
 * The first num_saved_registers_ registers are initialized to point to
 * "character -1" in the string (i.e., char_size() bytes before the first
 * character of the string). The remaining registers start out as garbage.
 *
 * The data up to the return address must be placed there by the calling
 * code and the remaining arguments are passed in registers, e.g. by calling the
 * code entry as cast to a function with the signature:
 * int (*match)(String input_string,
 *              int start_index,
 *              Address start,
 *              Address end,
 *              int* capture_output_array,
 *              int num_capture_registers,
 *              bool direct_call = false,
 *              Isolate* isolate,
 *              Address regexp);
 * The call is performed by NativeRegExpMacroAssembler::Execute()
 * (in regexp-macro-assembler.cc) via the GeneratedCode wrapper.
 */

#define __ ACCESS_MASM(masm_)

RegExpMacroAssemblerARM64::RegExpMacroAssemblerARM64(Isolate* isolate,
                                                     Zone* zone, Mode mode,
                                                     int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(std::make_unique<MacroAssembler>(
          isolate, zone, CodeObjectRequired::kYes,
          NewAssemblerBuffer(kInitialBufferSize))),
      no_root_array_scope_(masm_.get()),
      mode_(mode),
      num_registers_(registers_to_save),
      num_saved_registers_(registers_to_save),
      entry_label_(),
      start_label_(),
      success_label_(),
      backtrack_label_(),
      exit_label_() {
  DCHECK_EQ(0, registers_to_save % 2);
  // We can cache at most 16 W registers in x0-x7.
  static_assert(kNumCachedRegisters <= 16);
  static_assert((kNumCachedRegisters % 2) == 0);
  __ CallTarget();

  __ B(&entry_label_);   // We'll write the entry code later.
  __ Bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerARM64::~RegExpMacroAssemblerARM64() = default;

void RegExpMacroAssemblerARM64::AbortedCodeGeneration() {
  masm_->AbortedCodeGeneration();
  entry_label_.Unuse();
  start_label_.Unuse();
  success_label_.Unuse();
  backtrack_label_.Unuse();
  exit_label_.Unuse();
  check_preempt_label_.Unuse();
  stack_overflow_label_.Unuse();
  fallback_label_.Unuse();
}

int RegExpMacroAssemblerARM64::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerARM64::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ Add(current_input_offset(),
           current_input_offset(), by * char_size());
  }
}


void RegExpMacroAssemblerARM64::AdvanceRegister(int reg, int by) {
  DCHECK((reg >= 0) && (reg < num_registers_));
  if (by != 0) {
    RegisterState register_state = GetRegisterState(reg);
    switch (register_state) {
      case STACKED:
        __ Ldr(w10, register_location(reg));
        __ Add(w10, w10, by);
        __ Str(w10, register_location(reg));
        break;
      case CACHED_LSW: {
        Register to_advance = GetCachedRegister(reg);
        __ Add(to_advance, to_advance, by);
        break;
      }
      case CACHED_MSW: {
        Register to_advance = GetCachedRegister(reg);
        // Sign-extend to int64, shift as uint64, cast back to int64.
        __ Add(
            to_advance, to_advance,
            static_cast<int64_t>(static_cast<uint64_t>(static_cast<int64_t>(by))
                                 << kWRegSizeInBits));
        break;
      }
      default:
        UNREACHABLE();
    }
  }
}


void RegExpMacroAssemblerARM64::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    UseScratchRegisterScope temps(masm_.get());
    Register scratch = temps.AcquireW();
    __ Ldr(scratch, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ Add(scratch, scratch, 1);
    __ Str(scratch, MemOperand(frame_pointer(), kBacktrackCountOffset));
    __ Cmp(scratch, Operand(backtrack_limit()));
    __ B(ne, &next);

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ B(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  Pop(w10);
  __ Add(x10, code_pointer(), Operand(w10, UXTW));
  __ Br(x10);
}


void RegExpMacroAssemblerARM64::Bind(Label* label) {
  __ Bind(label);
}

void RegExpMacroAssemblerARM64::BindJumpTarget(Label* label) {
  __ BindJumpTarget(label);
}

void RegExpMacroAssemblerARM64::CheckCharacter(uint32_t c, Label* on_equal) {
  CompareAndBranchOrBacktrack(current_character(), c, eq, on_equal);
}

void RegExpMacroAssemblerARM64::CheckCharacterGT(base::uc16 limit,
                                                 Label* on_greater) {
  CompareAndBranchOrBacktrack(current_character(), limit, hi, on_greater);
}

void RegExpMacroAssemblerARM64::CheckAtStart(int cp_offset,
                                             Label* on_at_start) {
  __ Add(w10, current_input_offset(),
         Operand(-char_size() + cp_offset * char_size()));
  __ Cmp(w10, string_start_minus_one());
  BranchOrBacktrack(eq, on_at_start);
}

void RegExpMacroAssemblerARM64::CheckNotAtStart(int cp_offset,
                                                Label* on_not_at_start) {
  __ Add(w10, current_input_offset(),
         Operand(-char_size() + cp_offset * char_size()));
  __ Cmp(w10, string_start_minus_one());
  BranchOrBacktrack(ne, on_not_at_start);
}

void RegExpMacroAssemblerARM64::CheckCharacterLT(base::uc16 limit,
                                                 Label* on_less) {
  CompareAndBranchOrBacktrack(current_character(), limit, lo, on_less);
}

void RegExpMacroAssemblerARM64::CheckCharacters(
    base::Vector<const base::uc16> str, int cp_offset, Label* on_failure,
    bool check_end_of_string) {
  // This method is only ever called from the cctests.

  if (check_end_of_string) {
    // Is last character of required match inside string.
    CheckPosition(cp_offset + str.length() - 1, on_failure);
  }

  Register characters_address = x11;

  __ Add(characters_address,
         input_end(),
         Operand(current_input_offset(), SXTW));
  if (cp_offset != 0) {
    __ Add(characters_address, characters_address, cp_offset * char_size());
  }

  for (int i = 0; i < str.length(); i++) {
    if (mode_ == LATIN1) {
      __ Ldrb(w10, MemOperand(characters_address, 1, PostIndex));
      DCHECK_GE(String::kMaxOneByteCharCode, str[i]);
    } else {
      __ Ldrh(w10, MemOperand(characters_address, 2, PostIndex));
    }
    CompareAndBranchOrBacktrack(w10, str[i], ne, on_failure);
  }
}

void RegExpMacroAssemblerARM64::CheckGreedyLoop(Label* on_equal) {
  __ Ldr(w10, MemOperand(backtrack_stackpointer()));
  __ Cmp(current_input_offset(), w10);
  __ Cset(x11, eq);
  __ Add(backtrack_stackpointer(),
         backtrack_stackpointer(), Operand(x11, LSL, kWRegSizeLog2));
  BranchOrBacktrack(eq, on_equal);
}

void RegExpMacroAssemblerARM64::PushCachedRegisters() {
  CPURegList cached_registers(CPURegister::kRegister, kXRegSizeInBits, 0, 7);
  DCHECK_EQ(kNumCachedRegisters, cached_registers.Count() * 2);
  __ PushCPURegList(cached_registers);
}

void RegExpMacroAssemblerARM64::PopCachedRegisters() {
  CPURegList cached_registers(CPURegister::kRegister, kXRegSizeInBits, 0, 7);
  DCHECK_EQ(kNumCachedRegisters, cached_registers.Count() * 2);
  __ PopCPURegList(cached_registers);
}

void RegExpMacroAssemblerARM64::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;

  Register capture_start_offset = w10;
  // Save the capture length in a callee-saved register so it will
  // be preserved if we call a C helper.
  Register capture_length = w19;
  DCHECK(kCalleeSaved.IncludesAliasOf(capture_length));

  // Find length of back-referenced capture.
  DCHECK_EQ(0, start_reg % 2);
  if (start_reg < kNumCachedRegisters) {
    __ Mov(capture_start_offset.X(), GetCachedRegister(start_reg));
    __ Lsr(x11, GetCachedRegister(start_reg), kWRegSizeInBits);
  } else {
    __ Ldp(w11, capture_start_offset, capture_location(start_reg, x10));
  }
  __ Sub(capture_length, w11, capture_start_offset);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ CompareAndBranch(capture_length, Operand(0), eq, &fallthrough);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ Add(w12, string_start_minus_one(), capture_length);
    __ Cmp(current_input_offset(), w12);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ Cmn(capture_length, current_input_offset());
    BranchOrBacktrack(gt, on_no_match);
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_check;

    Register capture_start_address = x12;
    Register capture_end_address = x13;
    Register current_position_address = x14;

    __ Add(capture_start_address,
           input_end(),
           Operand(capture_start_offset, SXTW));
    __ Add(capture_end_address, capture_start_address,
           Operand(capture_length, SXTW));
    __ Add(current_position_address,
           input_end(),
           Operand(current_input_offset(), SXTW));
    if (read_backward) {
      // Offset by length when matching backwards.
      __ Sub(current_position_address, current_position_address,
             Operand(capture_length, SXTW));
    }

    Label loop;
    __ Bind(&loop);
    __ Ldrb(w10, MemOperand(capture_start_address, 1, PostIndex));
    __ Ldrb(w11, MemOperand(current_position_address, 1, PostIndex));
    __ Cmp(w10, w11);
    __ B(eq, &loop_check);

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ Orr(w10, w10, 0x20);  // Convert capture character to lower-case.
    __ Orr(w11, w11, 0x20);  // Also convert input character.
    __ Cmp(w11, w10);
    __ B(ne, &fail);
    __ Sub(w10, w10, 'a');
    __ Cmp(w10, 'z' - 'a');  // Is w10 a lowercase letter?
    __ B(ls, &loop_check);  // In range 'a'-'z'.
    // Latin-1: Check for values in range [224,254] but not 247.
    __ Sub(w10, w10, 224 - 'a');
    __ Cmp(w10, 254 - 224);
    __ Ccmp(w10, 247 - 224, ZFlag, ls);  // Check for 247.
    __ B(eq, &fail);  // Weren't Latin-1 letters.

    __ Bind(&loop_check);
    __ Cmp(capture_start_address, capture_end_address);
    __ B(lt, &loop);
    __ B(&success);

    __ Bind(&fail);
    BranchOrBacktrack(al, on_no_match);

    __ Bind(&success);
    // Compute new value of character position after the matched part.
    __ Sub(current_input_offset().X(), current_position_address, input_end());
    if (read_backward) {
      __ Sub(current_input_offset().X(), current_input_offset().X(),
             Operand(capture_length, SXTW));
    }
    if (v8_flags.debug_code) {
      __ Cmp(current_input_offset().X(), Operand(current_input_offset(), SXTW));
      __ Ccmp(current_input_offset(), 0, NoFlag, eq);
      // The current input offset should be <= 0, and fit in a W register.
      __ Check(le, AbortReason::kOffsetOutOfRange);
    }
  } else {
    DCHECK(mode_ == UC16);
    int argument_count = 4;

    PushCachedRegisters();

    // Put arguments into arguments registers.
    // Parameters are
    //   x0: Address byte_offset1 - Address captured substring's start.
    //   x1: Address byte_offset2 - Address of current character position.
    //   w2: size_t byte_length - length of capture in bytes(!)
    //   x3: Isolate* isolate.

    // Address of start of capture.
    __ Add(x0, input_end(), Operand(capture_start_offset, SXTW));
    // Length of capture.
    __ Mov(w2, capture_length);
    // Address of current input position.
    __ Add(x1, input_end(), Operand(current_input_offset(), SXTW));
    if (read_backward) {
      __ Sub(x1, x1, Operand(capture_length, SXTW));
    }
    // Isolate.
    __ Mov(x3, ExternalReference::isolate_address(isolate()));

    {
      AllowExternalCallThatCantCauseGC scope(masm_.get());
      ExternalReference function =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(function, argument_count);
    }

    // Check if function returned non-zero for success or zero for failure.
    // x0 is one of the registers used as a cache so it must be tested before
    // the cache is restored.
    __ Cmp(x0, 0);
    PopCachedRegisters();
    BranchOrBacktrack(eq, on_no_match);

    // On success, advance position by length of capture.
    if (read_backward) {
      __ Sub(current_input_offset(), current_input_offset(), capture_length);
    } else {
      __ Add(current_input_offset(), current_input_offset(), capture_length);
    }
  }

  __ Bind(&fallthrough);
}

void RegExpMacroAssemblerARM64::CheckNotBackReference(int start_reg,
                                                      bool read_backward,
                                                      Label* on_no_match) {
  Label fallthrough;

  Register capture_start_address = x12;
  Register capture_end_address = x13;
  Register current_position_address = x14;
  Register capture_length = w15;

  // Find length of back-referenced capture.
  DCHECK_EQ(0, start_reg % 2);
  if (start_reg < kNumCachedRegisters) {
    __ Mov(x10, GetCachedRegister(start_reg));
    __ Lsr(x11, GetCachedRegister(start_reg), kWRegSizeInBits);
  } else {
    __ Ldp(w11, w10, capture_location(start_reg, x10));
  }
  __ Sub(capture_length, w11, w10);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ CompareAndBranch(capture_length, Operand(0), eq, &fallthrough);

  // Check that there are enough characters left in the input.
  if (read_backward) {
    __ Add(w12, string_start_minus_one(), capture_length);
    __ Cmp(current_input_offset(), w12);
    BranchOrBacktrack(le, on_no_match);
  } else {
    __ Cmn(capture_length, current_input_offset());
    BranchOrBacktrack(gt, on_no_match);
  }

  // Compute pointers to match string and capture string
  __ Add(capture_start_address, input_end(), Operand(w10, SXTW));
  __ Add(capture_end_address,
         capture_start_address,
         Operand(capture_length, SXTW));
  __ Add(current_position_address,
         input_end(),
         Operand(current_input_offset(), SXTW));
  if (read_backward) {
    // Offset by length when matching backwards.
    __ Sub(current_position_address, current_position_address,
           Operand(capture_length, SXTW));
  }

  Label loop;
  __ Bind(&loop);
  if (mode_ == LATIN1) {
    __ Ldrb(w10, MemOperand(capture_start_address, 1, PostIndex));
    __ Ldrb(w11, MemOperand(current_position_address, 1, PostIndex));
  } else {
    DCHECK(mode_ == UC16);
    __ Ldrh(w10, MemOperand(capture_start_address, 2, PostIndex));
    __ Ldrh(w11, MemOperand(current_position_address, 2, PostIndex));
  }
  __ Cmp(w10, w11);
  BranchOrBacktrack(ne, on_no_match);
  __ Cmp(capture_start_address, capture_end_address);
  __ B(lt, &loop);

  // Move current character position to position after match.
  __ Sub(current_input_offset().X(), current_position_address, input_end());
  if (read_backward) {
    __ Sub(current_input_offset().X(), current_input_offset().X(),
           Operand(capture_length, SXTW));
  }

  if (v8_flags.debug_code) {
    __ Cmp(current_input_offset().X(), Operand(current_input_offset(), SXTW));
    __ Ccmp(current_input_offset(), 0, NoFlag, eq);
    // The current input offset should be <= 0, and fit in a W register.
    __ Check(le, AbortReason::kOffsetOutOfRange);
  }
  __ Bind(&fallthrough);
}


void RegExpMacroAssemblerARM64::CheckNotCharacter(unsigned c,
                                                  Label* on_not_equal) {
  CompareAndBranchOrBacktrack(current_character(), c, ne, on_not_equal);
}


void RegExpMacroAssemblerARM64::CheckCharacterAfterAnd(uint32_t c,
                                                       uint32_t mask,
                                                       Label* on_equal) {
  __ And(w10, current_character(), mask);
  CompareAndBranchOrBacktrack(w10, c, eq, on_equal);
}


void RegExpMacroAssemblerARM64::CheckNotCharacterAfterAnd(unsigned c,
                                                          unsigned mask,
                                                          Label* on_not_equal) {
  __ And(w10, current_character(), mask);
  CompareAndBranchOrBacktrack(w10, c, ne, on_not_equal);
}

void RegExpMacroAssemblerARM64::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ Sub(w10, current_character(), minus);
  __ And(w10, w10, mask);
  CompareAndBranchOrBacktrack(w10, c, ne, on_not_equal);
}

void RegExpMacroAssemblerARM64::CheckCharacterInRange(base::uc16 from,
                                                      base::uc16 to,
                                                      Label* on_in_range) {
  __ Sub(w10, current_character(), from);
  // Unsigned lower-or-same condition.
  CompareAndBranchOrBacktrack(w10, to - from, ls, on_in_range);
}

void RegExpMacroAssemblerARM64::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ Sub(w10, current_character(), from);
  // Unsigned higher condition.
  CompareAndBranchOrBacktrack(w10, to - from, hi, on_not_in_range);
}

void RegExpMacroAssemblerARM64::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  static const int kNumArguments = 2;
  __ Mov(w0, current_character());
  __ Mov(x1, GetOrAddRangeArray(ranges));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  __ Mov(code_pointer(), Operand(masm_->CodeObject()));
}

bool RegExpMacroAssemblerARM64::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  // Note: due to the arm64 oddity of x0 being a 'cached register',
  // pushing/popping registers must happen outside of CallIsCharacterInRange
  // s.t. we can compare the return value to 0 before popping x0.
  PushCachedRegisters();
  CallIsCharacterInRangeArray(ranges);
  __ Cmp(x0, 0);
  PopCachedRegisters();
  BranchOrBacktrack(ne, on_in_range);
  return true;
}

bool RegExpMacroAssemblerARM64::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  // Note: due to the arm64 oddity of x0 being a 'cached register',
  // pushing/popping registers must happen outside of CallIsCharacterInRange
  // s.t. we can compare the return value to 0 before popping x0.
  PushCachedRegisters();
  CallIsCharacterInRangeArray(ranges);
  __ Cmp(x0, 0);
  PopCachedRegisters();
  BranchOrBacktrack(eq, on_not_in_range);
  return true;
}

void RegExpMacroAssemblerARM64::CheckBitInTable(
    Handle<ByteArray> table,
    Label* on_bit_set) {
  __ Mov(x11, Operand(table));
  if ((mode_ != LATIN1) || (kTableMask != String::kMaxOneByteCharCode)) {
    __ And(w10, current_character(), kTableMask);
    __ Add(w10, w10, OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag);
  } else {
    __ Add(w10, current_character(),
           OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag);
  }
  __ Ldrb(w11, MemOperand(x11, w10, UXTW));
  CompareAndBranchOrBacktrack(w11, 0, ne, on_bit_set);
}

void RegExpMacroAssemblerARM64::SkipUntilBitInTable(
    int cp_offset, Handle<ByteArray> table,
    Handle<ByteArray> nibble_table_array, int advance_by) {
  Label cont, scalar_repeat;

  const bool use_simd = SkipUntilBitInTableUseSimd(advance_by);
  if (use_simd) {
    DCHECK(!nibble_table_array.is_null());
    Label simd_repeat, found, scalar;
    static constexpr int kVectorSize = 16;
    const int kCharsPerVector = kVectorSize / char_size();

    // Fallback to scalar version if there are less than kCharsPerVector chars
    // left in the subject.
    // We subtract 1 because CheckPosition assumes we are reading 1 character
    // plus cp_offset. So the -1 is the the character that is assumed to be
    // read by default.
    CheckPosition(cp_offset + kCharsPerVector - 1, &scalar);

    // Load table and mask constants.
    // For a description of the table layout, check the comment on
    // BoyerMooreLookahead::GetSkipTable in regexp-compiler.cc.
    VRegister nibble_table = v0;
    __ Mov(x8, Operand(nibble_table_array));
    __ Add(x8, x8, OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag);
    __ Ld1(nibble_table.V16B(), MemOperand(x8));
    VRegister nibble_mask = v1;
    const uint64_t nibble_mask_imm = 0x0f0f0f0f'0f0f0f0f;
    __ Movi(nibble_mask.V16B(), nibble_mask_imm, nibble_mask_imm);
    VRegister hi_nibble_lookup_mask = v2;
    const uint64_t hi_nibble_mask_imm = 0x80402010'08040201;
    __ Movi(hi_nibble_lookup_mask.V16B(), hi_nibble_mask_imm,
            hi_nibble_mask_imm);

    Bind(&simd_repeat);
    // Load next characters into vector.
    VRegister input_vec = v3;
    __ Add(x8, input_end(), Operand(current_input_offset(), SXTW));
    __ Add(x8, x8, cp_offset * char_size());
    __ Ld1(input_vec.V16B(), MemOperand(x8));

    // Extract low nibbles.
    // lo_nibbles = input & 0x0f
    VRegister lo_nibbles = v4;
    __ And(lo_nibbles.V16B(), nibble_mask.V16B(), input_vec.V16B());
    // Extract high nibbles.
    // hi_nibbles = (input >> 4) & 0x0f
    VRegister hi_nibbles = v5;
    __ Ushr(hi_nibbles.V16B(), input_vec.V16B(), 4);
    __ And(hi_nibbles.V16B(), hi_nibbles.V16B(), nibble_mask.V16B());

    // Get rows of nibbles table based on low nibbles.
    // row = nibble_table[lo_nibbles]
    VRegister row = v6;
    __ Tbl(row.V16B(), nibble_table.V16B(), lo_nibbles.V16B());

    // Check if high nibble is set in row.
    // bitmask = 1 << (hi_nibbles & 0x7)
    //         = hi_nibbles_lookup_mask[hi_nibbles] & 0x7
    // Note: The hi_nibbles & 0x7 part is implicitly executed, as tbl sets
    // the result byte to zero if the lookup index is out of range.
    VRegister bitmask = v7;
    __ Tbl(bitmask.V16B(), hi_nibble_lookup_mask.V16B(), hi_nibbles.V16B());

    // result = row & bitmask != 0
    VRegister result = ReassignRegister(lo_nibbles);
    __ Cmtst(result.V16B(), row.V16B(), bitmask.V16B());

    // Narrow the result to 64 bit.
    __ Shrn(result.V8B(), result.V8H(), 4);
    __ Umov(x8, result.V1D(), 0);
    __ Cbnz(x8, &found);

    // The maximum lookahead for boyer moore is less than vector size, so we can
    // ignore advance_by in the vectorized version.
    AdvanceCurrentPosition(kCharsPerVector);
    CheckPosition(cp_offset + kCharsPerVector - 1, &scalar);
    __ B(&simd_repeat);

    Bind(&found);
    // Extract position.
    __ Rbit(x8, x8);
    __ Clz(x8, x8);
    __ Lsr(x8, x8, 2);
    if (mode_ == UC16) {
      // Make sure that we skip an even number of bytes in 2-byte subjects.
      // Odd skips can happen if the higher byte produced a match.
      // False positives should be rare and are no problem in general, as the
      // following instructions will check for an exact match.
      __ And(x8, x8, Immediate(0xfffe));
    }
    __ Add(current_input_offset(), current_input_offset(), w8);
    __ B(&cont);
    Bind(&scalar);
  }

  // Scalar version.
  Register table_reg = x9;
  __ Mov(table_reg, Operand(table));

  Bind(&scalar_repeat);
  CheckPosition(cp_offset, &cont);
  LoadCurrentCharacterUnchecked(cp_offset, 1);
  Register index = w10;
  if ((mode_ != LATIN1) || (kTableMask != String::kMaxOneByteCharCode)) {
    __ And(index, current_character(), kTableMask);
    __ Add(index, index, OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag);
  } else {
    __ Add(index, current_character(),
           OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag);
  }
  Register found_in_table = w11;
  __ Ldrb(found_in_table, MemOperand(table_reg, index, UXTW));
  __ Cbnz(found_in_table, &cont);
  AdvanceCurrentPosition(advance_by);
  __ B(&scalar_repeat);

  Bind(&cont);
}

bool RegExpMacroAssemblerARM64::SkipUntilBitInTableUseSimd(int advance_by) {
  // We only use SIMD instead of the scalar version if we advance by 1 byte
  // in each iteration. For higher values the scalar version performs better.
  return v8_flags.regexp_simd && advance_by * char_size() == 1;
}

bool RegExpMacroAssemblerARM64::CheckSpecialClassRanges(
    StandardCharacterSet type, Label* on_no_match) {
  // Range checks (c in min..max) are generally implemented by an unsigned
  // (c - min) <= (max - min) check
  // TODO(jgruber): No custom implementation (yet): s(UC16), S(UC16).
  switch (type) {
    case StandardCharacterSet::kWhitespace:
      // Match space-characters.
      if (mode_ == LATIN1) {
        // One byte space characters are '\t'..'\r', ' ' and \u00a0.
        Label success;
        // Check for ' ' or 0x00A0.
        __ Cmp(current_character(), ' ');
        __ Ccmp(current_character(), 0x00A0, ZFlag, ne);
        __ B(eq, &success);
        // Check range 0x09..0x0D.
        __ Sub(w10, current_character(), '\t');
        CompareAndBranchOrBacktrack(w10, '\r' - '\t', hi, on_no_match);
        __ Bind(&success);
        return true;
      }
      return false;
    case StandardCharacterSet::kNotWhitespace:
      // The emitted code for generic character classes is good enough.
      return false;
    case StandardCharacterSet::kDigit:
      // Match ASCII digits ('0'..'9').
      __ Sub(w10, current_character(), '0');
      CompareAndBranchOrBacktrack(w10, '9' - '0', hi, on_no_match);
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match ASCII non-digits.
      __ Sub(w10, current_character(), '0');
      CompareAndBranchOrBacktrack(w10, '9' - '0', ls, on_no_match);
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029)
      // Here we emit the conditional branch only once at the end to make branch
      // prediction more efficient, even though we could branch out of here
      // as soon as a character matches.
      __ Cmp(current_character(), 0x0A);
      __ Ccmp(current_character(), 0x0D, ZFlag, ne);
      if (mode_ == UC16) {
        __ Sub(w10, current_character(), 0x2028);
        // If the Z flag was set we clear the flags to force a branch.
        __ Ccmp(w10, 0x2029 - 0x2028, NoFlag, ne);
        // ls -> !((C==1) && (Z==0))
        BranchOrBacktrack(ls, on_no_match);
      } else {
        BranchOrBacktrack(eq, on_no_match);
      }
      return true;
    }
    case StandardCharacterSet::kLineTerminator: {
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029)
      // We have to check all 4 newline characters before emitting
      // the conditional branch.
      __ Cmp(current_character(), 0x0A);
      __ Ccmp(current_character(), 0x0D, ZFlag, ne);
      if (mode_ == UC16) {
        __ Sub(w10, current_character(), 0x2028);
        // If the Z flag was set we clear the flags to force a fall-through.
        __ Ccmp(w10, 0x2029 - 0x2028, NoFlag, ne);
        // hi -> (C==1) && (Z==0)
        BranchOrBacktrack(hi, on_no_match);
      } else {
        BranchOrBacktrack(ne, on_no_match);
      }
      return true;
    }
    case StandardCharacterSet::kWord: {
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        CompareAndBranchOrBacktrack(current_character(), 'z', hi, on_no_match);
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ Mov(x10, map);
      __ Ldrb(w10, MemOperand(x10, current_character(), UXTW));
      CompareAndBranchOrBacktrack(w10, 0, eq, on_no_match);
      return true;
    }
    case StandardCharacterSet::kNotWord: {
      Label done;
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ Cmp(current_character(), 'z');
        __ B(hi, &done);
      }
      ExternalReference map = ExternalReference::re_word_character_map();
      __ Mov(x10, map);
      __ Ldrb(w10, MemOperand(x10, current_character(), UXTW));
      CompareAndBranchOrBacktrack(w10, 0, ne, on_no_match);
      __ Bind(&done);
      return true;
    }
    case StandardCharacterSet::kEverything:
      // Match any character.
      return true;
  }
}

void RegExpMacroAssemblerARM64::Fail() {
  __ Mov(w0, FAILURE);
  __ B(&exit_label_);
}

void RegExpMacroAssemblerARM64::LoadRegExpStackPointerFromMemory(Register dst
"""


```