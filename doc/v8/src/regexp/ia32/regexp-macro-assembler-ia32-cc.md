Response:
The user wants a summary of the functionality of the provided C++ code snippet. Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file name `regexp-macro-assembler-ia32.cc` strongly suggests this code is responsible for generating machine code for regular expression matching on IA32 architecture within the V8 engine. This forms the central theme of the summary.

2. **Pinpoint key data structures and registers:** The comments extensively document register usage and stack layout. Extract this information as it reveals fundamental aspects of the code's operation. List the important registers (edx, edi, esi, ebp, esp, ecx, eax, ebx) and their assigned roles. Similarly, note the stack structure, highlighting the stored information (regexp address, isolate, call type, capture array details, input string info, return address, saved registers, etc.).

3. **Recognize architectural specifics:** The "ia32" in the filename and the frequent use of x86 assembly instructions (`mov`, `cmp`, `jmp`, `push`, `pop`, `lea`, `add`, `sub`, `test`, `and_`, `or_`, `xor_`) confirm that this code is architecture-specific. Emphasize this in the summary.

4. **Trace the control flow (high-level):** The code initializes with a jump to `entry_label_`. The `GetCode` function reveals the setup steps within the entry code: stack frame creation, saving registers, allocating space for regexp registers, loading input parameters, and initializing registers. The presence of `success_label_`, `backtrack_label_`, and `exit_label_` points to the core regex matching loop with backtracking capabilities.

5. **Identify key operations:**  Scan the code for method names and common regex operations. Notice functions like `AdvanceCurrentPosition`, `AdvanceRegister`, `Backtrack`, `CheckCharacter`, `CheckAtStart`, `CheckNotBackReference`, `CheckCharacterInRange`, `CheckBitInTable`, `Fail`, etc. These methods reveal the low-level operations involved in regex matching.

6. **Consider interaction with JavaScript:** The comments mention `direct_call` and interaction with `JSRegExp` objects. This links the C++ code to JavaScript's regex functionality. Think about how JavaScript regexes are used (e.g., `string.match()`, `string.replace()`, `RegExp.test()`). Construct simple JavaScript examples demonstrating these functionalities.

7. **Address the ".tq" question:** The prompt specifically asks about ".tq" files. State clearly that this file is ".cc" and therefore C++, not Torque. Explain the purpose of Torque files within V8.

8. **Infer potential programming errors:** Given the low-level nature of the code and the manual stack management, common errors likely involve incorrect register usage, stack overflow, or incorrect handling of capture groups. Provide examples of these.

9. **Address the "code logic inference" request:** Select a straightforward code snippet, like `AdvanceCurrentPosition`, and demonstrate the input/output behavior. Provide a simple, concrete example.

10. **Structure the answer:** Organize the information logically into sections covering the main functionalities, relationship to JavaScript, hypothetical logic, common errors, and a final summary. Use clear and concise language.

11. **Review and refine:** Read through the generated summary and ensure it accurately reflects the code's purpose and functionality. Check for clarity, conciseness, and accuracy. Ensure all parts of the prompt are addressed. For example, initially, I might have focused too much on individual assembly instructions. Refinement would involve pulling back to the higher-level functionalities the methods perform. Also, double-check the register assignments and stack offsets from the comments.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_IA32

#include "src/regexp/ia32/regexp-macro-assembler-ia32.h"

#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp-stack.h"
#include "src/strings/unicode.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention
 * - edx : Current character. Must be loaded using LoadCurrentCharacter
 *         before using any of the dispatch methods. Temporarily stores the
 *         index of capture start after a matching pass for a global regexp.
 * - edi : Current position in input, as negative offset from end of string.
 *         Please notice that this is the byte offset, not the character offset!
 * - esi : end of input (points to byte after last character in input).
 * - ebp : Frame pointer. Used to access arguments, local variables and
 *         RegExp registers.
 * - esp : Points to tip of C stack.
 * - ecx : Points to tip of backtrack stack
 *
 * The registers eax and ebx are free to use for computations.
 *
 * Each call to a public method should retain this convention.
 * The stack will have the following structure:
 *       - Address regexp       (address of the JSRegExp object; unused in
 *                               native code, passed to match signature of
 *                               the interpreter)
 *       - Isolate* isolate     (address of the current isolate)
 *       - direct_call          (if 1, direct call from JavaScript code, if 0
 *                               call through the runtime system)
 *       - capture array size   (may fit multiple sets of matches)
 *       - int* capture_array   (int[num_saved_registers_], for output).
 *       - end of input         (address of end of string)
 *       - start of input       (address of first character in string)
 *       - start index          (character index of start)
 *       - String input_string  (location of a handle containing the string)
 *       --- frame alignment (if applicable) ---
 *       - return address
 * ebp-> - old ebp
 *       - frame marker
 *       - backup of caller esi
 *       - backup of caller edi
 *       - backup of caller ebx
 *       - success counter      (only for global regexps to count matches).
 *       - Offset of location before start of input (effectively character
 *         string start - 1). Used to initialize capture registers to a
 *         non-position.
 *       - register 0  ebp[-4]  (only positions must be stored in the first
 *       - register 1  ebp[-8]   num_saved_registers_ registers)
 *       - ...
 *
 * The first num_saved_registers_ registers are initialized to point to
 * "character -1" in the string (i.e., char_size() bytes before the first
 * character of the string). The remaining registers starts out as garbage.
 *
 * The data up to the return address must be placed there by the calling
 * code, by calling the code entry as cast to a function with the signature:
 * int (*match)(String input_string,
 *              int start_index,
 *              Address start,
 *              Address end,
 *              int* capture_output_array,
 *              int num_capture_registers,
 *              bool direct_call = false,
 *              Isolate* isolate
 *              Address regexp);
 */

#define __ ACCESS_MASM(masm_)

const int RegExpMacroAssemblerIA32::kRegExpCodeSize;

RegExpMacroAssemblerIA32::RegExpMacroAssemblerIA32(Isolate* isolate, Zone* zone,
                                                   Mode mode,
                                                   int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(std::make_unique<MacroAssembler>(
          isolate, CodeObjectRequired::kYes,
          NewAssemblerBuffer(kRegExpCodeSize))),
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
  __ jmp(&entry_label_);   // We'll write the entry code later.
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerIA32::~RegExpMacroAssemblerIA32() {
  // Unuse labels in case we throw away the assembler without calling GetCode.
  entry_label_.Unuse();
  start_label_.Unuse();
  success_label_.Unuse();
  backtrack_label_.Unuse();
  exit_label_.Unuse();
  check_preempt_label_.Unuse();
  stack_overflow_label_.Unuse();
  fallback_label_.Unuse();
}

int RegExpMacroAssemblerIA32::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerIA32::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ add(edi, Immediate(by * char_size()));
  }
}

void RegExpMacroAssemblerIA32::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ add(register_location(reg), Immediate(by));
  }
}

void RegExpMacroAssemblerIA32::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ inc(Operand(ebp, kBacktrackCountOffset));
    __ cmp(Operand(ebp, kBacktrackCountOffset), Immediate(backtrack_limit()));
    __ j(not_equal, &next);

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ jmp(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  // Pop InstructionStream offset from backtrack stack, add InstructionStream
  // and jump to location.
  Pop(ebx);
  __ add(ebx, Immediate(masm_->CodeObject()));
  __ jmp(ebx);
}

void RegExpMacroAssemblerIA32::Bind(Label* label) {
  __ bind(label);
}

void RegExpMacroAssemblerIA32::CheckCharacter(uint32_t c, Label* on_equal) {
  __ cmp(current_character(), c);
  BranchOrBacktrack(equal, on_equal);
}

void RegExpMacroAssemblerIA32::CheckCharacterGT(base::uc16 limit,
                                                Label* on_greater) {
  __ cmp(current_character(), limit);
  BranchOrBacktrack(greater, on_greater);
}

void RegExpMacroAssemblerIA32::CheckAtStart(int cp_offset, Label* on_at_start) {
  __ lea(eax, Operand(edi, -char_size() + cp_offset * char_size()));
  __ cmp(eax, Operand(ebp, kStringStartMinusOneOffset));
  BranchOrBacktrack(equal, on_at_start);
}

void RegExpMacroAssemblerIA32::CheckNotAtStart(int cp_offset,
                                               Label* on_not_at_start) {
  __ lea(eax, Operand(edi, -char_size() + cp_offset * char_size()));
  __ cmp(eax, Operand(ebp, kStringStartMinusOneOffset));
  BranchOrBacktrack(not_equal, on_not_at_start);
}

void RegExpMacroAssemblerIA32::CheckCharacterLT(base::uc16 limit,
                                                Label* on_less) {
  __ cmp(current_character(), limit);
  BranchOrBacktrack(less, on_less);
}

void RegExpMacroAssemblerIA32::CheckGreedyLoop(Label* on_equal) {
  Label fallthrough;
  __ cmp(edi, Operand(backtrack_stackpointer(), 0));
  __ j(not_equal, &fallthrough);
  __ add(backtrack_stackpointer(), Immediate(kSystemPointerSize));  // Pop.
  BranchOrBacktrack(on_equal);
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerIA32::CallCFunctionFromIrregexpCode(
    ExternalReference function, int num_arguments) {
  // Irregexp code must not set fast_c_call_caller_fp and fast_c_call_caller_pc
  // since
  //
  // 1. it may itself have been called using CallCFunction and nested calls are
  //    unsupported, and
  // 2. it may itself have been called directly from C where the frame pointer
  //    might not be set (-fomit-frame-pointer), and thus frame iteration would
  //    fail.
  //
  // See also: crbug.com/v8/12670#c17.
  __ CallCFunction(function, num_arguments, SetIsolateDataSlots::kNo);
}

void RegExpMacroAssemblerIA32::PushCallerSavedRegisters() {
  static_assert(backtrack_stackpointer() == ecx);
  static_assert(current_character() == edx);
  __ push(ecx);
  __ push(edx);
}

void RegExpMacroAssemblerIA32::PopCallerSavedRegisters() {
  __ pop(edx);
  __ pop(ecx);
}

void RegExpMacroAssemblerIA32::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  __ mov(edx, register_location(start_reg));  // Index of start of capture
  __ mov(ebx, register_location(start_reg + 1));  // Index of end of capture
  __ sub(ebx, edx);  // Length of capture.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ j(equal, &fallthrough);

  // Check that there are sufficient characters left in the input.
  if (read_backward) {
    __ mov(eax, Operand(ebp, kStringStartMinusOneOffset));
    __ add(eax, ebx);
    __ cmp(edi, eax);
    BranchOrBacktrack(less_equal, on_no_match);
  } else {
    __ mov(eax, edi);
    __ add(eax, ebx);
    BranchOrBacktrack(greater, on_no_match);
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_increment;
    // Save register contents to make the registers available below.
    __ push(edi);
    __ push(backtrack_stackpointer());
    // After this, the eax, ecx, and edi registers are available.

    __ add(edx, esi);  // Start of capture
    __ add(edi, esi);  // Start of text to match against capture.
    if (read_backward) {
      __ sub(edi, ebx);  // Offset by length when matching backwards.
    }
    __ add(ebx, edi);  // End of text to match against capture.

    Label loop;
    __ bind(&loop);
    __ movzx_b(eax, Operand(edi, 0));
    __ cmpb_al(Operand(edx, 0));
    __ j(equal, &loop_increment);

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ or_(eax, 0x20);  // Convert match character to lower-case.
    __ lea(ecx, Operand(eax, -'a'));
    __ cmp(ecx, static_cast<int32_t>('z' - 'a'));  // Is eax a lowercase letter?
    Label convert_capture;
    __ j(below_equal, &convert_capture);  // In range 'a'-'z'.
    // Latin-1: Check for values in range [224,254] but not 247.
    __ sub(ecx, Immediate(224 - 'a'));
    __ cmp(ecx, Immediate(254 - 224));
    __ j(above, &fail);  // Weren't Latin-1 letters.
    __ cmp(ecx, Immediate(247 - 224));  // Check for 247.
    __ j(equal, &fail);
    __ bind(&convert_capture);
    // Also convert capture character.
    __ movzx_b(ecx, Operand(edx, 0));
    __ or_(ecx, 0x20);

    __ cmp(eax, ecx);
    __ j(not_equal, &fail);

    __ bind(&loop_increment);
    // Increment pointers into match and capture strings.
    __ add(edx, Immediate(1));
    __ add(edi, Immediate(1));
    // Compare to end of match, and loop if not done.
    __ cmp(edi, ebx);
    __ j(below, &loop);
    __ jmp(&success);

    __ bind(&fail);
    // Restore original values before failing.
    __ pop(backtrack_stackpointer());
    __ pop(edi);
    BranchOrBacktrack(on_no_match);

    __ bind(&success);
    // Restore original value before continuing.
    __ pop(backtrack_stackpointer());
    // Drop original value of character position.
    __ add(esp, Immediate(kSystemPointerSize));
    // Compute new value of character position after the matched part.
    __ sub(edi, esi);
    if (read_backward) {
      // Subtract match length if we matched backward.
      __ add(edi, register_location(start_reg));
      __ sub(edi, register_location(start_reg + 1));
    }
  } else {
    DCHECK(mode_ == UC16);
    // Save registers before calling C function.
    __ push(esi);
    __ push(edi);
    __ push(backtrack_stackpointer());
    __ push(ebx);

    static const int argument_count = 4;
    __ PrepareCallCFunction(argument_count, ecx);
    // Put arguments into allocated stack area, last argument highest on stack.
    // Parameters are
    //   Address byte_offset1 - Address captured substring's start.
    //   Address byte_offset2 - Address of current character position.
    //   size_t byte_length - length of capture in bytes(!)
    //   Isolate* isolate.

    // Set isolate.
    __ mov(Operand(esp, 3 * kSystemPointerSize),
           Immediate(ExternalReference::isolate_address(isolate())));
    // Set byte_length.
    __ mov(Operand(esp, 2 * kSystemPointerSize), ebx);
    // Set byte_offset2.
    // Found by adding negative string-end offset of current position (edi)
    // to end of string.
    __ add(edi, esi);
    if (read_backward) {
      __ sub(edi, ebx);  // Offset by length when matching backwards.
    }
    __ mov(Operand(esp, 1 * kSystemPointerSize), edi);
    // Set byte_offset1.
    // Start of capture, where edx already holds string-end negative offset.
    __ add(edx, esi);
    __ mov(Operand(esp, 0 * kSystemPointerSize), edx);

    {
      AllowExternalCallThatCantCauseGC scope(masm_.get());
      ExternalReference compare =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(compare, argument_count);
    }
    // Pop original values before reacting on result value.
    __ pop(ebx);
    __ pop(backtrack_stackpointer());
    __ pop(edi);
    __ pop(esi);

    // Check if function returned non-zero for success or zero for failure.
    __ or_(eax, eax);
    BranchOrBacktrack(zero, on_no_match);
    // On success, advance position by length of capture.
    if (read_backward) {
      __ sub(edi, ebx);
    } else {
      __ add(edi, ebx);
    }
  }
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerIA32::CheckNotBackReference(int start_reg,
                                                     bool read_backward,
                                                     Label* on_no_match) {
  Label fallthrough;
  Label success;
  Label fail;

  // Find length of back-referenced capture.
  __ mov(edx, register_location(start_reg));
  __ mov(eax, register_location(start_reg + 1));
  __ sub(eax, edx);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ j(equal, &fallthrough);

  // Check that there are sufficient characters left in the input.
  if (read_backward) {
    __ mov(ebx, Operand(ebp, kStringStartMinusOneOffset));
    __ add(ebx, eax);
    __ cmp(edi, ebx);
    BranchOrBacktrack(less_equal, on_no_match);
  } else {
    __ mov(ebx, edi);
    __ add(ebx, eax);
    BranchOrBacktrack(greater, on_no_match);
  }

  // Save register to make it available below.
  __ push(backtrack_stackpointer());

  // Compute pointers to match string and capture string
  __ add(edx, esi);  // Start of capture.
  __ lea(ebx, Operand(esi, edi, times_1, 0));  // Start of match.
  if (read_backward) {
    __ sub(ebx, eax);  // Offset by length when matching backwards.
  }
  __ lea(ecx, Operand(eax, ebx, times_1, 0));  // End of match

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ movzx_b(eax, Operand(edx, 0));
    __ cmpb_al(Operand(ebx, 0));
  } else {
    DCHECK(mode_ == UC16);
    __ movzx_w(eax, Operand(edx, 0));
    __ cmpw_ax(Operand(ebx, 0));
  }
  __ j(not_equal, &fail);
  // Increment pointers into capture and match string.
  __ add(edx, Immediate(char_size()));
  __ add(ebx, Immediate(char_size()));
  // Check if we have reached end of match area.
  __ cmp(ebx, ecx);
  __ j(below, &loop);
  __ jmp(&success);

  __ bind(&fail);
  // Restore backtrack stackpointer.
  __ pop(backtrack_stackpointer());
  BranchOrBacktrack(on_no_match);

  __ bind(&success);
  // Move current character position to position after match.
  __ mov(edi, ecx);
  __ sub(edi, esi);
  if (read_backward) {
    // Subtract match length if we matched backward.
    __ add(edi, register_location(start_reg));
    __ sub(edi, register_location(start_reg + 1));
  }
  // Restore backtrack stackpointer.
  __ pop(backtrack_stackpointer());

  __ bind(&fallthrough);
}

void RegExpMacroAssemblerIA32::CheckNotCharacter(uint32_t c,
                                                 Label* on_not_equal) {
  __ cmp(current_character(), c);
  BranchOrBacktrack(not_equal, on_not_equal);
}

void RegExpMacroAssemblerIA32::CheckCharacterAfterAnd(uint32_t c,
                                                      uint32_t mask,
                                                      Label* on_equal) {
  if (c == 0) {
    __ test(current_character(), Immediate(mask));
  } else {
    __ mov(eax, mask);
    __ and_(eax, current_character());
    __ cmp(eax, c);
  }
  BranchOrBacktrack(equal, on_equal);
}

void RegExpMacroAssemblerIA32::CheckNotCharacterAfterAnd(uint32_t c,
                                                         uint32_t mask,
                                                         Label* on_not_equal) {
  if (c == 0) {
    __ test(current_character(), Immediate(mask));
  } else {
    __ mov(eax, mask);
    __ and_(eax, current_character());
    __ cmp(eax, c);
  }
  BranchOrBacktrack(not_equal, on_not_equal);
}

void RegExpMacroAssemblerIA32::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ lea(eax, Operand(current_character(), -minus));
  if (c == 0) {
    __ test(eax, Immediate(mask));
  } else {
    __ and_(eax, mask);
    __ cmp(eax, c);
  }
  BranchOrBacktrack(not_equal, on_not_equal);
}

void RegExpMacroAssemblerIA32::CheckCharacterInRange(base::uc16 from,
                                                     base::uc16 to,
                                                     Label* on_in_range) {
  __ lea(eax, Operand(current_character(), -from));
  __ cmp(eax, to - from);
  BranchOrBacktrack(below_equal, on_in_range);
}

void RegExpMacroAssemblerIA32::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ lea(eax, Operand(current_character(), -from));
  __ cmp(eax, to - from);
  BranchOrBacktrack(above, on_not_in_range);
}

void RegExpMacroAssemblerIA32::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  PushCallerSavedRegisters();

  static const int kNumArguments = 2;
  __ PrepareCallCFunction(kNumArguments, ecx);

  __ mov(Operand(esp, 0 * kSystemPointerSize), current_character());
  __ mov(Operand(esp, 1 * kSystemPointerSize), GetOrAddRangeArray(ranges));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  PopCallerSavedRegisters();
}

bool RegExpMacroAssemblerIA32::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ or_(eax, eax);
  BranchOrBacktrack(not_zero, on_in_range);
  return true;
}

bool RegExpMacroAssemblerIA32::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ or_(eax, eax);
  BranchOrBacktrack(zero, on_not_in_range);
  return true;
}

void RegExpMacroAssemblerIA32::CheckBitInTable(
    Handle<ByteArray> table,
    Label* on_bit_set) {
  __ mov(eax, Immediate(table));
  Register index = current_character();
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ mov(ebx, kTableSize - 1);
    __ and_(ebx, current_character());
    index = ebx;
  }
  __ cmpb(FieldOperand(eax, index, times_1, OFFSET_OF_DATA_START(ByteArray)),
          Immediate(0));
  BranchOrBacktrack(not_equal, on_bit_set);
}

void RegExpMacroAssemblerIA32::SkipUntilBitInTable(
    int cp_offset, Handle<ByteArray> table, Handle<ByteArray> nibble_table,
    int advance_by) {
  // TODO(pthier): Optimize. Table can be loaded outside of the loop.
  Label cont, again;
  Bind(&again);
  LoadCurrentCharacter(cp_offset, &cont, true);
  CheckBitInTable(table, &cont);
  AdvanceCurrentPosition(advance_by);
  GoTo(&again);
  Bind(&cont);
}

bool RegExpMacroAssemblerIA32::CheckSpecialClassRanges(
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
        __ cmp(current_character(), ' ');
        __ j(equal, &success, Label::kNear);
        // Check range 0x09..0x0D.
        __ lea(eax, Operand(current_character(), -'\t'));
        __ cmp(eax, '\r' - '\t');
        __ j(below_equal, &success, Label::kNear);
        // \u00a0 (NBSP).
        __ cmp(eax, 0x00A0 - '\t');
        BranchOrBacktrack(not_equal, on_no_match);
        __ bind(&success);
        return true;
      }
      return false;
    case StandardCharacterSet::kNotWhitespace:
      // The emitted code for generic character classes is good enough.
      return false;
    case StandardCharacterSet::kDigit:
      // Match ASCII digits ('0'..'9').
      __ lea(eax, Operand(current_character(), -'0'));
      __ cmp(eax, '9' - '0');
      BranchOrBacktrack(above, on_no_match);
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non ASCII-digits.
      __ lea(eax, Operand(current_character(), -'0'));
      __ cmp(eax, '9' - '0');
      BranchOrBacktrack(below_equal, on_no_match);
      return true;
    case StandardCharacterSet::kLineTerminator:
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 or 0x2029).
      // The opposite of '.'.
      __ mov(eax, current_character());
      __ xor_(eax, Immediate(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ sub(eax, Immediate(0x0B));
      __ cmp(eax, 0x0C - 0x0B);
      if (mode_ == LATIN1) {
        BranchOrBacktrack(above, on_no_match);
      } else {
        Label done;
        BranchOrBacktrack(below_equal, &done);
        DCHECK_EQ(UC16, mode_);
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ sub(eax, Immediate(0x2028 - 0x0B));
        __ cmp(eax, 1);
        BranchOrBacktrack(above, on_no_match);
        __ bind(&done);
      }
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ mov(eax, current_character());
      __ xor_(eax, Immediate(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ sub(eax, Immediate(0x0B));
      __ cmp(eax, 0x0C - 0x0B);
      BranchOrBacktrack(below_equal, on_no_match);
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or
### 提示词
```
这是目录为v8/src/regexp/ia32/regexp-macro-assembler-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/ia32/regexp-macro-assembler-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_IA32

#include "src/regexp/ia32/regexp-macro-assembler-ia32.h"

#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp-stack.h"
#include "src/strings/unicode.h"

namespace v8 {
namespace internal {

/*
 * This assembler uses the following register assignment convention
 * - edx : Current character.  Must be loaded using LoadCurrentCharacter
 *         before using any of the dispatch methods.  Temporarily stores the
 *         index of capture start after a matching pass for a global regexp.
 * - edi : Current position in input, as negative offset from end of string.
 *         Please notice that this is the byte offset, not the character offset!
 * - esi : end of input (points to byte after last character in input).
 * - ebp : Frame pointer.  Used to access arguments, local variables and
 *         RegExp registers.
 * - esp : Points to tip of C stack.
 * - ecx : Points to tip of backtrack stack
 *
 * The registers eax and ebx are free to use for computations.
 *
 * Each call to a public method should retain this convention.
 * The stack will have the following structure:
 *       - Address regexp       (address of the JSRegExp object; unused in
 *                               native code, passed to match signature of
 *                               the interpreter)
 *       - Isolate* isolate     (address of the current isolate)
 *       - direct_call          (if 1, direct call from JavaScript code, if 0
 *                               call through the runtime system)
 *       - capture array size   (may fit multiple sets of matches)
 *       - int* capture_array   (int[num_saved_registers_], for output).
 *       - end of input         (address of end of string)
 *       - start of input       (address of first character in string)
 *       - start index          (character index of start)
 *       - String input_string  (location of a handle containing the string)
 *       --- frame alignment (if applicable) ---
 *       - return address
 * ebp-> - old ebp
 *       - frame marker
 *       - backup of caller esi
 *       - backup of caller edi
 *       - backup of caller ebx
 *       - success counter      (only for global regexps to count matches).
 *       - Offset of location before start of input (effectively character
 *         string start - 1). Used to initialize capture registers to a
 *         non-position.
 *       - register 0  ebp[-4]  (only positions must be stored in the first
 *       - register 1  ebp[-8]   num_saved_registers_ registers)
 *       - ...
 *
 * The first num_saved_registers_ registers are initialized to point to
 * "character -1" in the string (i.e., char_size() bytes before the first
 * character of the string). The remaining registers starts out as garbage.
 *
 * The data up to the return address must be placed there by the calling
 * code, by calling the code entry as cast to a function with the signature:
 * int (*match)(String input_string,
 *              int start_index,
 *              Address start,
 *              Address end,
 *              int* capture_output_array,
 *              int num_capture_registers,
 *              bool direct_call = false,
 *              Isolate* isolate
 *              Address regexp);
 */

#define __ ACCESS_MASM(masm_)

const int RegExpMacroAssemblerIA32::kRegExpCodeSize;

RegExpMacroAssemblerIA32::RegExpMacroAssemblerIA32(Isolate* isolate, Zone* zone,
                                                   Mode mode,
                                                   int registers_to_save)
    : NativeRegExpMacroAssembler(isolate, zone),
      masm_(std::make_unique<MacroAssembler>(
          isolate, CodeObjectRequired::kYes,
          NewAssemblerBuffer(kRegExpCodeSize))),
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
  __ jmp(&entry_label_);   // We'll write the entry code later.
  __ bind(&start_label_);  // And then continue from here.
}

RegExpMacroAssemblerIA32::~RegExpMacroAssemblerIA32() {
  // Unuse labels in case we throw away the assembler without calling GetCode.
  entry_label_.Unuse();
  start_label_.Unuse();
  success_label_.Unuse();
  backtrack_label_.Unuse();
  exit_label_.Unuse();
  check_preempt_label_.Unuse();
  stack_overflow_label_.Unuse();
  fallback_label_.Unuse();
}

int RegExpMacroAssemblerIA32::stack_limit_slack_slot_count() {
  return RegExpStack::kStackLimitSlackSlotCount;
}

void RegExpMacroAssemblerIA32::AdvanceCurrentPosition(int by) {
  if (by != 0) {
    __ add(edi, Immediate(by * char_size()));
  }
}


void RegExpMacroAssemblerIA32::AdvanceRegister(int reg, int by) {
  DCHECK_LE(0, reg);
  DCHECK_GT(num_registers_, reg);
  if (by != 0) {
    __ add(register_location(reg), Immediate(by));
  }
}


void RegExpMacroAssemblerIA32::Backtrack() {
  CheckPreemption();
  if (has_backtrack_limit()) {
    Label next;
    __ inc(Operand(ebp, kBacktrackCountOffset));
    __ cmp(Operand(ebp, kBacktrackCountOffset), Immediate(backtrack_limit()));
    __ j(not_equal, &next);

    // Backtrack limit exceeded.
    if (can_fallback()) {
      __ jmp(&fallback_label_);
    } else {
      // Can't fallback, so we treat it as a failed match.
      Fail();
    }

    __ bind(&next);
  }
  // Pop InstructionStream offset from backtrack stack, add InstructionStream
  // and jump to location.
  Pop(ebx);
  __ add(ebx, Immediate(masm_->CodeObject()));
  __ jmp(ebx);
}


void RegExpMacroAssemblerIA32::Bind(Label* label) {
  __ bind(label);
}


void RegExpMacroAssemblerIA32::CheckCharacter(uint32_t c, Label* on_equal) {
  __ cmp(current_character(), c);
  BranchOrBacktrack(equal, on_equal);
}

void RegExpMacroAssemblerIA32::CheckCharacterGT(base::uc16 limit,
                                                Label* on_greater) {
  __ cmp(current_character(), limit);
  BranchOrBacktrack(greater, on_greater);
}

void RegExpMacroAssemblerIA32::CheckAtStart(int cp_offset, Label* on_at_start) {
  __ lea(eax, Operand(edi, -char_size() + cp_offset * char_size()));
  __ cmp(eax, Operand(ebp, kStringStartMinusOneOffset));
  BranchOrBacktrack(equal, on_at_start);
}

void RegExpMacroAssemblerIA32::CheckNotAtStart(int cp_offset,
                                               Label* on_not_at_start) {
  __ lea(eax, Operand(edi, -char_size() + cp_offset * char_size()));
  __ cmp(eax, Operand(ebp, kStringStartMinusOneOffset));
  BranchOrBacktrack(not_equal, on_not_at_start);
}

void RegExpMacroAssemblerIA32::CheckCharacterLT(base::uc16 limit,
                                                Label* on_less) {
  __ cmp(current_character(), limit);
  BranchOrBacktrack(less, on_less);
}

void RegExpMacroAssemblerIA32::CheckGreedyLoop(Label* on_equal) {
  Label fallthrough;
  __ cmp(edi, Operand(backtrack_stackpointer(), 0));
  __ j(not_equal, &fallthrough);
  __ add(backtrack_stackpointer(), Immediate(kSystemPointerSize));  // Pop.
  BranchOrBacktrack(on_equal);
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerIA32::CallCFunctionFromIrregexpCode(
    ExternalReference function, int num_arguments) {
  // Irregexp code must not set fast_c_call_caller_fp and fast_c_call_caller_pc
  // since
  //
  // 1. it may itself have been called using CallCFunction and nested calls are
  //    unsupported, and
  // 2. it may itself have been called directly from C where the frame pointer
  //    might not be set (-fomit-frame-pointer), and thus frame iteration would
  //    fail.
  //
  // See also: crbug.com/v8/12670#c17.
  __ CallCFunction(function, num_arguments, SetIsolateDataSlots::kNo);
}

void RegExpMacroAssemblerIA32::PushCallerSavedRegisters() {
  static_assert(backtrack_stackpointer() == ecx);
  static_assert(current_character() == edx);
  __ push(ecx);
  __ push(edx);
}

void RegExpMacroAssemblerIA32::PopCallerSavedRegisters() {
  __ pop(edx);
  __ pop(ecx);
}

void RegExpMacroAssemblerIA32::CheckNotBackReferenceIgnoreCase(
    int start_reg, bool read_backward, bool unicode, Label* on_no_match) {
  Label fallthrough;
  __ mov(edx, register_location(start_reg));  // Index of start of capture
  __ mov(ebx, register_location(start_reg + 1));  // Index of end of capture
  __ sub(ebx, edx);  // Length of capture.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ j(equal, &fallthrough);

  // Check that there are sufficient characters left in the input.
  if (read_backward) {
    __ mov(eax, Operand(ebp, kStringStartMinusOneOffset));
    __ add(eax, ebx);
    __ cmp(edi, eax);
    BranchOrBacktrack(less_equal, on_no_match);
  } else {
    __ mov(eax, edi);
    __ add(eax, ebx);
    BranchOrBacktrack(greater, on_no_match);
  }

  if (mode_ == LATIN1) {
    Label success;
    Label fail;
    Label loop_increment;
    // Save register contents to make the registers available below.
    __ push(edi);
    __ push(backtrack_stackpointer());
    // After this, the eax, ecx, and edi registers are available.

    __ add(edx, esi);  // Start of capture
    __ add(edi, esi);  // Start of text to match against capture.
    if (read_backward) {
      __ sub(edi, ebx);  // Offset by length when matching backwards.
    }
    __ add(ebx, edi);  // End of text to match against capture.

    Label loop;
    __ bind(&loop);
    __ movzx_b(eax, Operand(edi, 0));
    __ cmpb_al(Operand(edx, 0));
    __ j(equal, &loop_increment);

    // Mismatch, try case-insensitive match (converting letters to lower-case).
    __ or_(eax, 0x20);  // Convert match character to lower-case.
    __ lea(ecx, Operand(eax, -'a'));
    __ cmp(ecx, static_cast<int32_t>('z' - 'a'));  // Is eax a lowercase letter?
    Label convert_capture;
    __ j(below_equal, &convert_capture);  // In range 'a'-'z'.
    // Latin-1: Check for values in range [224,254] but not 247.
    __ sub(ecx, Immediate(224 - 'a'));
    __ cmp(ecx, Immediate(254 - 224));
    __ j(above, &fail);  // Weren't Latin-1 letters.
    __ cmp(ecx, Immediate(247 - 224));  // Check for 247.
    __ j(equal, &fail);
    __ bind(&convert_capture);
    // Also convert capture character.
    __ movzx_b(ecx, Operand(edx, 0));
    __ or_(ecx, 0x20);

    __ cmp(eax, ecx);
    __ j(not_equal, &fail);

    __ bind(&loop_increment);
    // Increment pointers into match and capture strings.
    __ add(edx, Immediate(1));
    __ add(edi, Immediate(1));
    // Compare to end of match, and loop if not done.
    __ cmp(edi, ebx);
    __ j(below, &loop);
    __ jmp(&success);

    __ bind(&fail);
    // Restore original values before failing.
    __ pop(backtrack_stackpointer());
    __ pop(edi);
    BranchOrBacktrack(on_no_match);

    __ bind(&success);
    // Restore original value before continuing.
    __ pop(backtrack_stackpointer());
    // Drop original value of character position.
    __ add(esp, Immediate(kSystemPointerSize));
    // Compute new value of character position after the matched part.
    __ sub(edi, esi);
    if (read_backward) {
      // Subtract match length if we matched backward.
      __ add(edi, register_location(start_reg));
      __ sub(edi, register_location(start_reg + 1));
    }
  } else {
    DCHECK(mode_ == UC16);
    // Save registers before calling C function.
    __ push(esi);
    __ push(edi);
    __ push(backtrack_stackpointer());
    __ push(ebx);

    static const int argument_count = 4;
    __ PrepareCallCFunction(argument_count, ecx);
    // Put arguments into allocated stack area, last argument highest on stack.
    // Parameters are
    //   Address byte_offset1 - Address captured substring's start.
    //   Address byte_offset2 - Address of current character position.
    //   size_t byte_length - length of capture in bytes(!)
    //   Isolate* isolate.

    // Set isolate.
    __ mov(Operand(esp, 3 * kSystemPointerSize),
           Immediate(ExternalReference::isolate_address(isolate())));
    // Set byte_length.
    __ mov(Operand(esp, 2 * kSystemPointerSize), ebx);
    // Set byte_offset2.
    // Found by adding negative string-end offset of current position (edi)
    // to end of string.
    __ add(edi, esi);
    if (read_backward) {
      __ sub(edi, ebx);  // Offset by length when matching backwards.
    }
    __ mov(Operand(esp, 1 * kSystemPointerSize), edi);
    // Set byte_offset1.
    // Start of capture, where edx already holds string-end negative offset.
    __ add(edx, esi);
    __ mov(Operand(esp, 0 * kSystemPointerSize), edx);

    {
      AllowExternalCallThatCantCauseGC scope(masm_.get());
      ExternalReference compare =
          unicode
              ? ExternalReference::re_case_insensitive_compare_unicode()
              : ExternalReference::re_case_insensitive_compare_non_unicode();
      CallCFunctionFromIrregexpCode(compare, argument_count);
    }
    // Pop original values before reacting on result value.
    __ pop(ebx);
    __ pop(backtrack_stackpointer());
    __ pop(edi);
    __ pop(esi);

    // Check if function returned non-zero for success or zero for failure.
    __ or_(eax, eax);
    BranchOrBacktrack(zero, on_no_match);
    // On success, advance position by length of capture.
    if (read_backward) {
      __ sub(edi, ebx);
    } else {
      __ add(edi, ebx);
    }
  }
  __ bind(&fallthrough);
}

void RegExpMacroAssemblerIA32::CheckNotBackReference(int start_reg,
                                                     bool read_backward,
                                                     Label* on_no_match) {
  Label fallthrough;
  Label success;
  Label fail;

  // Find length of back-referenced capture.
  __ mov(edx, register_location(start_reg));
  __ mov(eax, register_location(start_reg + 1));
  __ sub(eax, edx);  // Length to check.

  // At this point, the capture registers are either both set or both cleared.
  // If the capture length is zero, then the capture is either empty or cleared.
  // Fall through in both cases.
  __ j(equal, &fallthrough);

  // Check that there are sufficient characters left in the input.
  if (read_backward) {
    __ mov(ebx, Operand(ebp, kStringStartMinusOneOffset));
    __ add(ebx, eax);
    __ cmp(edi, ebx);
    BranchOrBacktrack(less_equal, on_no_match);
  } else {
    __ mov(ebx, edi);
    __ add(ebx, eax);
    BranchOrBacktrack(greater, on_no_match);
  }

  // Save register to make it available below.
  __ push(backtrack_stackpointer());

  // Compute pointers to match string and capture string
  __ add(edx, esi);  // Start of capture.
  __ lea(ebx, Operand(esi, edi, times_1, 0));  // Start of match.
  if (read_backward) {
    __ sub(ebx, eax);  // Offset by length when matching backwards.
  }
  __ lea(ecx, Operand(eax, ebx, times_1, 0));  // End of match

  Label loop;
  __ bind(&loop);
  if (mode_ == LATIN1) {
    __ movzx_b(eax, Operand(edx, 0));
    __ cmpb_al(Operand(ebx, 0));
  } else {
    DCHECK(mode_ == UC16);
    __ movzx_w(eax, Operand(edx, 0));
    __ cmpw_ax(Operand(ebx, 0));
  }
  __ j(not_equal, &fail);
  // Increment pointers into capture and match string.
  __ add(edx, Immediate(char_size()));
  __ add(ebx, Immediate(char_size()));
  // Check if we have reached end of match area.
  __ cmp(ebx, ecx);
  __ j(below, &loop);
  __ jmp(&success);

  __ bind(&fail);
  // Restore backtrack stackpointer.
  __ pop(backtrack_stackpointer());
  BranchOrBacktrack(on_no_match);

  __ bind(&success);
  // Move current character position to position after match.
  __ mov(edi, ecx);
  __ sub(edi, esi);
  if (read_backward) {
    // Subtract match length if we matched backward.
    __ add(edi, register_location(start_reg));
    __ sub(edi, register_location(start_reg + 1));
  }
  // Restore backtrack stackpointer.
  __ pop(backtrack_stackpointer());

  __ bind(&fallthrough);
}


void RegExpMacroAssemblerIA32::CheckNotCharacter(uint32_t c,
                                                 Label* on_not_equal) {
  __ cmp(current_character(), c);
  BranchOrBacktrack(not_equal, on_not_equal);
}


void RegExpMacroAssemblerIA32::CheckCharacterAfterAnd(uint32_t c,
                                                      uint32_t mask,
                                                      Label* on_equal) {
  if (c == 0) {
    __ test(current_character(), Immediate(mask));
  } else {
    __ mov(eax, mask);
    __ and_(eax, current_character());
    __ cmp(eax, c);
  }
  BranchOrBacktrack(equal, on_equal);
}


void RegExpMacroAssemblerIA32::CheckNotCharacterAfterAnd(uint32_t c,
                                                         uint32_t mask,
                                                         Label* on_not_equal) {
  if (c == 0) {
    __ test(current_character(), Immediate(mask));
  } else {
    __ mov(eax, mask);
    __ and_(eax, current_character());
    __ cmp(eax, c);
  }
  BranchOrBacktrack(not_equal, on_not_equal);
}

void RegExpMacroAssemblerIA32::CheckNotCharacterAfterMinusAnd(
    base::uc16 c, base::uc16 minus, base::uc16 mask, Label* on_not_equal) {
  DCHECK_GT(String::kMaxUtf16CodeUnit, minus);
  __ lea(eax, Operand(current_character(), -minus));
  if (c == 0) {
    __ test(eax, Immediate(mask));
  } else {
    __ and_(eax, mask);
    __ cmp(eax, c);
  }
  BranchOrBacktrack(not_equal, on_not_equal);
}

void RegExpMacroAssemblerIA32::CheckCharacterInRange(base::uc16 from,
                                                     base::uc16 to,
                                                     Label* on_in_range) {
  __ lea(eax, Operand(current_character(), -from));
  __ cmp(eax, to - from);
  BranchOrBacktrack(below_equal, on_in_range);
}

void RegExpMacroAssemblerIA32::CheckCharacterNotInRange(
    base::uc16 from, base::uc16 to, Label* on_not_in_range) {
  __ lea(eax, Operand(current_character(), -from));
  __ cmp(eax, to - from);
  BranchOrBacktrack(above, on_not_in_range);
}

void RegExpMacroAssemblerIA32::CallIsCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges) {
  PushCallerSavedRegisters();

  static const int kNumArguments = 2;
  __ PrepareCallCFunction(kNumArguments, ecx);

  __ mov(Operand(esp, 0 * kSystemPointerSize), current_character());
  __ mov(Operand(esp, 1 * kSystemPointerSize), GetOrAddRangeArray(ranges));

  {
    // We have a frame (set up in GetCode), but the assembler doesn't know.
    FrameScope scope(masm_.get(), StackFrame::MANUAL);
    CallCFunctionFromIrregexpCode(
        ExternalReference::re_is_character_in_range_array(), kNumArguments);
  }

  PopCallerSavedRegisters();
}

bool RegExpMacroAssemblerIA32::CheckCharacterInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ or_(eax, eax);
  BranchOrBacktrack(not_zero, on_in_range);
  return true;
}

bool RegExpMacroAssemblerIA32::CheckCharacterNotInRangeArray(
    const ZoneList<CharacterRange>* ranges, Label* on_not_in_range) {
  CallIsCharacterInRangeArray(ranges);
  __ or_(eax, eax);
  BranchOrBacktrack(zero, on_not_in_range);
  return true;
}

void RegExpMacroAssemblerIA32::CheckBitInTable(
    Handle<ByteArray> table,
    Label* on_bit_set) {
  __ mov(eax, Immediate(table));
  Register index = current_character();
  if (mode_ != LATIN1 || kTableMask != String::kMaxOneByteCharCode) {
    __ mov(ebx, kTableSize - 1);
    __ and_(ebx, current_character());
    index = ebx;
  }
  __ cmpb(FieldOperand(eax, index, times_1, OFFSET_OF_DATA_START(ByteArray)),
          Immediate(0));
  BranchOrBacktrack(not_equal, on_bit_set);
}

void RegExpMacroAssemblerIA32::SkipUntilBitInTable(
    int cp_offset, Handle<ByteArray> table, Handle<ByteArray> nibble_table,
    int advance_by) {
  // TODO(pthier): Optimize. Table can be loaded outside of the loop.
  Label cont, again;
  Bind(&again);
  LoadCurrentCharacter(cp_offset, &cont, true);
  CheckBitInTable(table, &cont);
  AdvanceCurrentPosition(advance_by);
  GoTo(&again);
  Bind(&cont);
}

bool RegExpMacroAssemblerIA32::CheckSpecialClassRanges(
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
        __ cmp(current_character(), ' ');
        __ j(equal, &success, Label::kNear);
        // Check range 0x09..0x0D.
        __ lea(eax, Operand(current_character(), -'\t'));
        __ cmp(eax, '\r' - '\t');
        __ j(below_equal, &success, Label::kNear);
        // \u00a0 (NBSP).
        __ cmp(eax, 0x00A0 - '\t');
        BranchOrBacktrack(not_equal, on_no_match);
        __ bind(&success);
        return true;
      }
      return false;
    case StandardCharacterSet::kNotWhitespace:
      // The emitted code for generic character classes is good enough.
      return false;
    case StandardCharacterSet::kDigit:
      // Match ASCII digits ('0'..'9').
      __ lea(eax, Operand(current_character(), -'0'));
      __ cmp(eax, '9' - '0');
      BranchOrBacktrack(above, on_no_match);
      return true;
    case StandardCharacterSet::kNotDigit:
      // Match non ASCII-digits.
      __ lea(eax, Operand(current_character(), -'0'));
      __ cmp(eax, '9' - '0');
      BranchOrBacktrack(below_equal, on_no_match);
      return true;
    case StandardCharacterSet::kLineTerminator:
      // Match newlines (0x0A('\n'), 0x0D('\r'), 0x2028 or 0x2029).
      // The opposite of '.'.
      __ mov(eax, current_character());
      __ xor_(eax, Immediate(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ sub(eax, Immediate(0x0B));
      __ cmp(eax, 0x0C - 0x0B);
      if (mode_ == LATIN1) {
        BranchOrBacktrack(above, on_no_match);
      } else {
        Label done;
        BranchOrBacktrack(below_equal, &done);
        DCHECK_EQ(UC16, mode_);
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ sub(eax, Immediate(0x2028 - 0x0B));
        __ cmp(eax, 1);
        BranchOrBacktrack(above, on_no_match);
        __ bind(&done);
      }
      return true;
    case StandardCharacterSet::kNotLineTerminator: {
      // Match non-newlines (not 0x0A('\n'), 0x0D('\r'), 0x2028 and 0x2029).
      __ mov(eax, current_character());
      __ xor_(eax, Immediate(0x01));
      // See if current character is '\n'^1 or '\r'^1, i.e., 0x0B or 0x0C.
      __ sub(eax, Immediate(0x0B));
      __ cmp(eax, 0x0C - 0x0B);
      BranchOrBacktrack(below_equal, on_no_match);
      if (mode_ == UC16) {
        // Compare original value to 0x2028 and 0x2029, using the already
        // computed (current_char ^ 0x01 - 0x0B). I.e., check for
        // 0x201D (0x2028 - 0x0B) or 0x201E.
        __ sub(eax, Immediate(0x2028 - 0x0B));
        __ cmp(eax, 0x2029 - 0x2028);
        BranchOrBacktrack(below_equal, on_no_match);
      }
      return true;
    }
    case StandardCharacterSet::kWord: {
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ cmp(current_character(), Immediate('z'));
        BranchOrBacktrack(above, on_no_match);
      }
      DCHECK_EQ(0,
                word_character_map[0]);  // Character '\0' is not a word char.
      ExternalReference word_map = ExternalReference::re_word_character_map();
      __ test_b(current_character(),
                Operand(current_character(), times_1, word_map.address(),
                        RelocInfo::EXTERNAL_REFERENCE));
      BranchOrBacktrack(zero, on_no_match);
      return true;
    }
    case StandardCharacterSet::kNotWord: {
      Label done;
      if (mode_ != LATIN1) {
        // Table is 256 entries, so all Latin1 characters can be tested.
        __ cmp(current_character(), Immediate('z'));
        __ j(above, &done);
      }
      DCHECK_EQ(0,
                word_character_map[0]);  // Character '\0' is not a word char.
      ExternalReference word_map = ExternalReference::re_word_character_map();
      __ test_b(current_character(),
                Operand(current_character(), times_1, word_map.address(),
                        RelocInfo::EXTERNAL_REFERENCE));
      BranchOrBacktrack(not_zero, on_no_match);
      if (mode_ != LATIN1) {
        __ bind(&done);
      }
      return true;
    }
  // Non-standard classes (with no syntactic shorthand) used internally.
  case StandardCharacterSet::kEverything:
    // Match any character.
    return true;
  }
}

void RegExpMacroAssemblerIA32::Fail() {
  static_assert(FAILURE == 0);  // Return value for failure is zero.
  if (!global()) {
    __ Move(eax, Immediate(FAILURE));
  }
  __ jmp(&exit_label_);
}

void RegExpMacroAssemblerIA32::LoadRegExpStackPointerFromMemory(Register dst) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ mov(dst, __ ExternalReferenceAsOperand(ref, dst));
}

void RegExpMacroAssemblerIA32::StoreRegExpStackPointerToMemory(
    Register src, Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_stack_pointer(isolate());
  __ mov(__ ExternalReferenceAsOperand(ref, scratch), src);
}

void RegExpMacroAssemblerIA32::PushRegExpBasePointer(Register stack_pointer,
                                                     Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(scratch, __ ExternalReferenceAsOperand(ref, scratch));
  __ sub(scratch, stack_pointer);
  __ mov(Operand(ebp, kRegExpStackBasePointerOffset), scratch);
}

void RegExpMacroAssemblerIA32::PopRegExpBasePointer(Register stack_pointer_out,
                                                    Register scratch) {
  ExternalReference ref =
      ExternalReference::address_of_regexp_stack_memory_top_address(isolate());
  __ mov(scratch, Operand(ebp, kRegExpStackBasePointerOffset));
  __ mov(stack_pointer_out,
         __ ExternalReferenceAsOperand(ref, stack_pointer_out));
  __ sub(stack_pointer_out, scratch);
  StoreRegExpStackPointerToMemory(stack_pointer_out, scratch);
}

Handle<HeapObject> RegExpMacroAssemblerIA32::GetCode(Handle<String> source,
                                                     RegExpFlags flags) {
  Label return_eax;
  // Finalize code - write the entry point code now we know how many
  // registers we need.

  // Entry code:
  __ bind(&entry_label_);

  // Tell the system that we have a stack frame.  Because the type is MANUAL, no
  // code is generated.
  FrameScope scope(masm_.get(), StackFrame::MANUAL);

  // Actually emit code to start a new stack frame. This pushes the frame type
  // marker into the stack slot at kFrameTypeOffset.
  static_assert(kFrameTypeOffset == -1 * kSystemPointerSize);
  __ EnterFrame(StackFrame::IRREGEXP);

  // Save callee-save registers. Order here should correspond to order of
  // kBackupEbxOffset etc.
  __ push(esi);
  __ push(edi);
  __ push(ebx);  // Callee-save on MacOS.
  static_assert(kLastCalleeSaveRegisterOffset == kBackupEbxOffset);

  static_assert(kSuccessfulCapturesOffset ==
                kLastCalleeSaveRegisterOffset - kSystemPointerSize);
  __ push(Immediate(0));  // Number of successful matches in a global regexp.
  static_assert(kStringStartMinusOneOffset ==
                kSuccessfulCapturesOffset - kSystemPointerSize);
  __ push(Immediate(0));  // Make room for "string start - 1" constant.
  static_assert(kBacktrackCountOffset ==
                kStringStartMinusOneOffset - kSystemPointerSize);
  __ push(Immediate(0));  // The backtrack counter.
  static_assert(kRegExpStackBasePointerOffset ==
                kBacktrackCountOffset - kSystemPointerSize);
  __ push(Immediate(0));  // The regexp stack base ptr.

  // Initialize backtrack stack pointer. It must not be clobbered from here on.
  // Note the backtrack_stackpointer is *not* callee-saved.
  static_assert(backtrack_stackpointer() == ecx);
  LoadRegExpStackPointerFromMemory(backtrack_stackpointer());

  // Store the regexp base pointer - we'll later restore it / write it to
  // memory when returning from this irregexp code object.
  PushRegExpBasePointer(backtrack_stackpointer(), eax);

  {
    // Check if we have space on the stack for registers.
    Label stack_limit_hit, stack_ok;

    ExternalReference stack_limit =
        ExternalReference::address_of_jslimit(isolate());
    __ mov(eax, esp);
    __ sub(eax, StaticVariable(stack_limit));
    Immediate extra_space_for_variables(num_registers_ * kSystemPointerSize);

    // Handle it if the stack pointer is already below the stack limit.
    __ j(below_equal, &stack_limit_hit);
    // Check if there is room for the variable number of registers above
    // the stack limit.
    __ cmp(eax, extra_space_for_variables);
    __ j(above_equal, &stack_ok);
    // Exit with OutOfMemory exception. There is not enough space on the stack
    // for our working registers.
    __ mov(eax, EXCEPTION);
    __ jmp(&return_eax);

    __ bind(&stack_limit_hit);
    __ push(backtrack_stackpointer());
    CallCheckStackGuardState(ebx, extra_space_for_variables);
    __ pop(backtrack_stackpointer());
    __ or_(eax, eax);
    // If returned value is non-zero, we exit with the returned value as result.
    __ j(not_zero, &return_eax);

    __ bind(&stack_ok);
  }

  // Load start index for later use.
  __ mov(ebx, Operand(ebp, kStartIndexOffset));

  // Allocate space on stack for registers.
  __ AllocateStackSpace(num_registers_ * kSystemPointerSize);
  // Load string length.
  __ mov(esi, Operand(ebp, kInputEndOffset));
  // Load input position.
  __ mov(edi, Operand(ebp, kInputStartOffset));
  // Set up edi to be negative offset from string end.
  __ sub(edi, esi);

  // Set eax to address of char before start of the string.
  // (effectively string position -1).
  __ neg(ebx);
  if (mode_ == UC16) {
    __ lea(eax, Operand(edi, ebx, times_2, -char_size()));
  } else {
    __ lea(eax, Operand(edi, ebx, times_1, -char_size()));
  }
  // Store this value in a local variable, for use when clearing
  // position registers.
  __ mov(Operand(ebp, kStringStartMinusOneOffset), eax);

  Label load_char_start_regexp;
  {
    Label start_regexp;

    // Load newline if index is at start, previous character otherwise.
    __ cmp(Operand(ebp, kStartIndexOffset), Immediate(0));
    __ j(not_equal, &load_char_start_regexp, Label::kNear);
    __ mov(current_character(), '\n');
    __ jmp(&start_regexp, Label::kNear);

    // Global regexp restarts matching here.
    __ bind(&load_char_start_regexp);
    // Load previous char as initial value of current character register.
    LoadCurrentCharacterUnchecked(-1, 1);
    __ bind(&start_regexp);
  }

  // Initialize on-stack registers.
  if (num_saved_registers_ > 0) {  // Always is, if generated from a regexp.
    // Fill saved registers with initial value = start offset - 1
    // Fill in stack push order, to avoid accessing across an unwritten
    // page (a problem on Windows).
    if (num_saved_registers_ > 8) {
      DCHECK_EQ(ecx, backtrack_stackpointer());
      __ push(ecx);
      __ mov(ecx, kRegisterZeroOffset);
      Label init_loop;
      __ bind(&init_loop);
      __ mov(Operand(ebp, ecx, times_1, 0), eax);
      __ sub(ecx, Immediate(kSystemPointerSize));
      __ cmp(ecx,
             kRegisterZeroOffset - num_saved_registers_ * kSystemPointerSize);
      __ j(greater, &init_loop);
      __ pop(ecx);
    } else {  // Unroll the loop.
      for (int i = 0; i < num_saved_registers_; i++) {
        __ mov(register_location(i), eax);
      }
    }
  }

  __ jmp(&start_label_);

  // Exit code:
  if (success_label_.is_linked()) {
    // Save captures when successful.
    __ bind(&success_label_);
    if (num_saved_registers_ > 0) {
      // copy captures to output
      __ mov(ebx, Operand(ebp, kRegisterOutputOffset));
      __ mov(ecx, Operand(ebp, kInputEndOffset));
      __ mov(edx, Operand(ebp, kStartIndexOffset));
      __ sub(ecx, Operan
```