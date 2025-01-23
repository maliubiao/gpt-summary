Response:
Let's break down the thought process for analyzing the `bytecode-array-writer.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the provided C++ code. It also has specific sub-questions related to Torque, JavaScript relevance, code logic, and common programming errors. The core is about describing what this code *does*.

2. **Identify the Class:** The most prominent element is the `BytecodeArrayWriter` class. This immediately suggests the primary function is about *writing* or *creating* something called a `BytecodeArray`.

3. **Examine the Constructor:** The constructor takes a `Zone`, `ConstantArrayBuilder`, and a `SourcePositionTableBuilder::RecordingMode`. This hints at the class's dependencies and the kinds of data it manages:
    * `Zone`: Memory management.
    * `ConstantArrayBuilder`: Building a pool of constants used in the bytecode.
    * `SourcePositionTableBuilder`:  Associating bytecode with source code locations.

4. **Analyze Public Methods:** These are the primary ways to interact with the class. Look for methods that *produce* something or have visible side effects:
    * `ToBytecodeArray`: This looks like the key method! It returns a `Handle<BytecodeArray>`. This confirms the class's purpose. It takes `register_count`, `parameter_count`, `max_arguments`, and a `handler_table` as arguments, suggesting it's packaging up information about a function's execution.
    * `ToSourcePositionTable`:  Returns a `Handle<TrustedByteArray>`, suggesting it creates the source map.
    * `Write`, `WriteJump`, `WriteJumpLoop`, `WriteSwitch`: These methods indicate how bytecode instructions are added to the `BytecodeArray`. The different `Write` variations suggest different types of instructions (normal, jumps, loops, switches).
    * `BindLabel`, `BindLoopHeader`, `BindJumpTableEntry`, `BindHandlerTarget`, `BindTryRegionStart`, `BindTryRegionEnd`: These methods are about linking different parts of the bytecode together, particularly for control flow and exception handling.
    * `SetFunctionEntrySourcePosition`:  Sets the starting source position.
    * `StartBasicBlock`:  Related to code optimization and control flow analysis.

5. **Analyze Private/Protected Methods and Members:** These often reveal the implementation details:
    * `bytecodes_`: A `std::vector<uint8_t>` strongly suggests this is where the raw bytecode instructions are stored.
    * `constant_array_builder_`: The builder for the constant pool.
    * `source_position_table_builder_`: The builder for the source map.
    * `unbound_jumps_`:  Keeps track of jumps whose targets aren't yet known.
    * `PatchJump` family of methods:  Used to fix up jump targets once they are known.
    * `EmitBytecode`, `EmitJump`, `EmitJumpLoop`, `EmitSwitch`:  These are the low-level methods that actually append bytecode bytes to the `bytecodes_` vector.
    * `UpdateSourcePositionTable`, `UpdateExitSeenInBlock`, `MaybeElideLastBytecode`, `InvalidateLastBytecode`: These are helper methods for managing source information, tracking control flow, and performing minor optimizations.

6. **Infer Functionality from Method Names and Arguments:**  Even without deep knowledge of V8 internals, educated guesses can be made. For example, `WriteJump` and `BindLabel` clearly work together for implementing jumps.

7. **Address Specific Sub-Questions:**
    * **Torque:** The code doesn't end with `.tq`, so it's standard C++.
    * **JavaScript Relationship:**  The core purpose is to *generate the bytecode that executes JavaScript*. This is a crucial link. Think about how a JavaScript function is compiled down to machine-understandable instructions. This class is part of that process.
    * **JavaScript Example:** A simple function with control flow (like an `if` statement) or a loop would demonstrate the need for the jump and label binding functionality.
    * **Code Logic Inference:** Focus on the jump patching mechanism. The writer doesn't know the target of a forward jump immediately. It reserves space and then "patches" the jump instruction later when the target is known. Think about the state transitions and the purpose of `unbound_jumps_`.
    * **Common Programming Errors:** Consider what could go wrong in the process of generating bytecode. Incorrect jump offsets leading to unexpected behavior is a prime example. Also, inefficient or incorrect generation of source maps could cause debugging issues.

8. **Structure the Answer:** Organize the findings logically:
    * Start with a high-level summary of the class's purpose.
    * Detail the key functionalities, grouping related methods.
    * Address the specific sub-questions clearly and concisely.
    * Use examples where appropriate to illustrate the concepts.

9. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check that all parts of the request have been addressed. For instance, initially, I might have just said "writes bytecode," but the prompt encourages deeper detail about *how* it writes it, handling jumps, source maps, etc.

Self-Correction Example During the Process:  Initially, I might not have fully grasped the purpose of `MaybeElideLastBytecode`. Upon closer inspection of the name and the code within, I'd realize it's a micro-optimization related to removing redundant load instructions. This deeper understanding would then be incorporated into the explanation. Similarly, recognizing the connection between `WriteJump` and the eventual `PatchJump` operations becomes clearer upon reviewing the code flow.
Based on the provided C++ source code for `v8/src/interpreter/bytecode-array-writer.cc`, here's a breakdown of its functionality:

**Core Functionality:**

The primary responsibility of `BytecodeArrayWriter` is to **construct a `BytecodeArray`**, which is the fundamental representation of executable code in V8's interpreter (Ignition). It acts as a builder, sequentially writing bytecode instructions and related metadata into a contiguous memory block.

Here are its key functions:

* **Writing Bytecode Instructions:**
    * `Write(BytecodeNode* node)`: Writes a non-jump bytecode instruction.
    * `WriteJump(BytecodeNode* node, BytecodeLabel* label)`: Writes a forward jump instruction, where the target is not yet known.
    * `WriteJumpLoop(BytecodeNode* node, BytecodeLoopHeader* loop_header)`: Writes a backward jump instruction for loops.
    * `WriteSwitch(BytecodeNode* node, BytecodeJumpTable* jump_table)`: Writes a switch statement instruction.
    * These methods take a `BytecodeNode`, which encapsulates the bytecode and its operands, and append the corresponding bytes to an internal buffer (`bytecodes_`).

* **Handling Control Flow:**
    * **Labels (`BytecodeLabel`)**:  Used as targets for jump instructions.
        * `BindLabel(BytecodeLabel* label)`:  Marks the current position as the target of a previously written jump instruction, "patching" the jump with the correct offset.
    * **Loop Headers (`BytecodeLoopHeader`)**: Used to mark the beginning of a loop for `JumpLoop` instructions.
        * `BindLoopHeader(BytecodeLoopHeader* loop_header)`: Records the starting offset of a loop.
    * **Jump Tables (`BytecodeJumpTable`)**: Used for efficient implementation of switch statements.
        * `BindJumpTableEntry(BytecodeJumpTable* jump_table, int case_value)`: Records the offset for a specific case in a switch statement.

* **Managing Constant Pool:**
    * The `BytecodeArrayWriter` uses a `ConstantArrayBuilder` to manage constants used by the bytecode. When a jump target is not yet known, it reserves space in the constant pool. Later, when the label is bound, it updates the jump instruction, potentially using a constant pool entry if the jump offset is too large to fit in the immediate operand.

* **Building Source Position Table:**
    * `UpdateSourcePositionTable(const BytecodeNode* const node)`: Records the mapping between bytecode offsets and corresponding source code positions. This information is crucial for debugging and stack traces.
    * `SetFunctionEntrySourcePosition(int position)`: Sets the source position for the beginning of the function.

* **Creating the Final `BytecodeArray`:**
    * `ToBytecodeArray(IsolateT* isolate, int register_count, uint16_t parameter_count, uint16_t max_arguments, Handle<TrustedByteArray> handler_table)`:  Assembles the collected bytecode instructions, constant pool, and other metadata into a final `BytecodeArray` object.

* **Handling Exception Handlers:**
    * `BindHandlerTarget(HandlerTableBuilder* handler_table_builder, int handler_id)`: Records the starting offset of an exception handler.
    * `BindTryRegionStart(HandlerTableBuilder* handler_table_builder, int handler_id)`: Marks the beginning of a try block.
    * `BindTryRegionEnd(HandlerTableBuilder* handler_table_builder, int handler_id)`: Marks the end of a try block.

* **Optimization (Eliding Noneffectful Bytecodes):**
    * `MaybeElideLastBytecode(Bytecode next_bytecode, bool has_source_info)`:  If the `ignition_elide_noneffectful_bytecodes` flag is enabled, it can remove the previous bytecode if it was a load into the accumulator that is immediately overwritten without being used.

**Relationship to JavaScript:**

`BytecodeArrayWriter` is a core component in the pipeline that transforms JavaScript code into executable instructions for V8's interpreter. Here's how it relates:

1. **Compilation:** When V8 compiles JavaScript code, it goes through several stages. One of these stages involves generating bytecode instructions that represent the semantics of the JavaScript code.
2. **Bytecode Generation:** The compiler uses the `BytecodeArrayWriter` to sequentially add these bytecode instructions. For example:
    * A JavaScript addition operation (`a + b`) might translate into `Ldar a` (load `a` into the accumulator) followed by `Add r1` (add the value in register `r1` to the accumulator).
    * An `if` statement would involve `Test چیزی` bytecode followed by `JumpIfFalse` to skip a block of code.
    * Function calls, variable access, and other JavaScript constructs are all represented by specific bytecode instructions.

**JavaScript Example:**

Consider this simple JavaScript function:

```javascript
function add(x, y) {
  if (x > 10) {
    return x + y;
  } else {
    return x * 2;
  }
}
```

The `BytecodeArrayWriter` would be involved in generating bytecode similar to the following (this is a simplified illustration):

1. **Load arguments:** Load the values of `x` and `y` into registers.
2. **Compare `x` with 10:**  A bytecode instruction to compare `x` with the constant 10.
3. **Conditional Jump:** A `JumpIfFalse` bytecode instruction. If the comparison is false (`x <= 10`), jump to the `else` block. This would involve creating a `BytecodeLabel` for the `else` block and using `WriteJump`.
4. **`then` block:**
   * Load `x`.
   * Add `y`.
   * Return the result (using a `Return` bytecode).
5. **`else` block (binding the label):**  The `BindLabel` method would be called for the label created for the `else` block.
   * Load `x`.
   * Multiply by 2.
   * Return the result.

**Code Logic Inference (Jump Patching):**

**Assumption:** We are writing bytecode for a function containing an `if` statement.

**Input:**
* A `BytecodeNode` representing a `JumpIfFalse` instruction. The target of the jump is the beginning of the `else` block, but the offset is not yet known.
* A `BytecodeLabel` representing the start of the `else` block.

**Steps:**

1. **`WriteJump(jump_node, else_label)` is called:**
   * The `JumpIfFalse` bytecode and a placeholder operand (e.g., 0 or a special value) are written to the `bytecodes_` buffer.
   * The `else_label` records the current offset of the jump instruction (`label->set_referrer(current_offset)`).
   * `unbound_jumps_` is incremented.

2. **Bytecode for the `then` block is written.**

3. **`BindLabel(else_label)` is called:**
   * The current offset in the `bytecodes_` buffer is determined (this is the actual start of the `else` block).
   * `PatchJump(current_offset, else_label->jump_offset())` is called.
   * **`PatchJump` logic:**
     * Calculates the difference (`delta`) between the target offset (`current_offset`) and the jump instruction's offset (`else_label->jump_offset()`).
     * Depending on the size of `delta`, it updates the operand of the `JumpIfFalse` instruction in the `bytecodes_` buffer. It might use an 8-bit, 16-bit, or 32-bit operand, or even a constant pool entry if the offset is very large.
     * `unbound_jumps_` is decremented.

**Output:**
* The `JumpIfFalse` instruction in the `bytecodes_` buffer now has the correct offset to jump to the beginning of the `else` block.

**Common Programming Errors (Related to Bytecode Generation):**

* **Incorrect Jump Targets:** If the `PatchJump` logic is flawed or the `BindLabel` is called at the wrong time, jump instructions might point to incorrect locations in the bytecode. This can lead to unexpected program behavior, crashes, or infinite loops.
    * **Example:**  Forgetting to call `BindLabel` for a label used by a jump instruction. The jump would then have an invalid target.
* **Mismatched Operand Sizes:** If the `BytecodeArrayWriter` writes an operand with an incorrect size for a particular bytecode, the interpreter might misinterpret the bytecode stream, leading to errors.
    * **Example:**  Writing an 8-bit offset for a jump that requires a 16-bit offset because the target is far away.
* **Incorrect Constant Pool Usage:**  Errors in managing the `ConstantArrayBuilder` can lead to incorrect constants being used by the bytecode.
    * **Example:**  Referencing the wrong index in the constant pool for a string literal.
* **Incorrect Source Position Information:** Errors in `UpdateSourcePositionTable` can make debugging difficult, as stack traces and debugger information might point to the wrong lines of code.
    * **Example:**  Forgetting to update the source position table for a particular bytecode instruction.
* **Eliding Necessary Bytecodes:** If the optimization logic in `MaybeElideLastBytecode` is too aggressive or contains errors, it might remove bytecodes that are actually needed, leading to incorrect program execution. This is less likely since the conditions for elision are usually quite strict.

In summary, `v8/src/interpreter/bytecode-array-writer.cc` is a crucial class responsible for building the executable bytecode representation of JavaScript code within V8's interpreter. It handles the sequential writing of instructions, manages control flow through labels and jump instructions, and associates bytecode with source code locations for debugging purposes.

### 提示词
```
这是目录为v8/src/interpreter/bytecode-array-writer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/bytecode-array-writer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/interpreter/bytecode-array-writer.h"

#include "src/api/api-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/interpreter/bytecode-jump-table.h"
#include "src/interpreter/bytecode-label.h"
#include "src/interpreter/bytecode-node.h"
#include "src/interpreter/bytecode-source-info.h"
#include "src/interpreter/constant-array-builder.h"
#include "src/interpreter/handler-table-builder.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {
namespace interpreter {

STATIC_CONST_MEMBER_DEFINITION const size_t
    BytecodeArrayWriter::kMaxSizeOfPackedBytecode;

BytecodeArrayWriter::BytecodeArrayWriter(
    Zone* zone, ConstantArrayBuilder* constant_array_builder,
    SourcePositionTableBuilder::RecordingMode source_position_mode)
    : bytecodes_(zone),
      unbound_jumps_(0),
      source_position_table_builder_(zone, source_position_mode),
      constant_array_builder_(constant_array_builder),
      last_bytecode_(Bytecode::kIllegal),
      last_bytecode_offset_(0),
      last_bytecode_had_source_info_(false),
      elide_noneffectful_bytecodes_(
          v8_flags.ignition_elide_noneffectful_bytecodes),
      exit_seen_in_block_(false) {
  bytecodes_.reserve(512);  // Derived via experimentation.
}

template <typename IsolateT>
Handle<BytecodeArray> BytecodeArrayWriter::ToBytecodeArray(
    IsolateT* isolate, int register_count, uint16_t parameter_count,
    uint16_t max_arguments, Handle<TrustedByteArray> handler_table) {
  DCHECK_EQ(0, unbound_jumps_);

  int bytecode_size = static_cast<int>(bytecodes()->size());
  int frame_size = register_count * kSystemPointerSize;
  Handle<TrustedFixedArray> constant_pool =
      constant_array_builder()->ToFixedArray(isolate);
  Handle<BytecodeArray> bytecode_array = isolate->factory()->NewBytecodeArray(
      bytecode_size, &bytecodes()->front(), frame_size, parameter_count,
      max_arguments, constant_pool, handler_table);
  return bytecode_array;
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<BytecodeArray> BytecodeArrayWriter::ToBytecodeArray(
        Isolate* isolate, int register_count, uint16_t parameter_count,
        uint16_t max_arguments, Handle<TrustedByteArray> handler_table);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<BytecodeArray> BytecodeArrayWriter::ToBytecodeArray(
        LocalIsolate* isolate, int register_count, uint16_t parameter_count,
        uint16_t max_arguments, Handle<TrustedByteArray> handler_table);

template <typename IsolateT>
Handle<TrustedByteArray> BytecodeArrayWriter::ToSourcePositionTable(
    IsolateT* isolate) {
  DCHECK(!source_position_table_builder_.Lazy());
  Handle<TrustedByteArray> source_position_table =
      source_position_table_builder_.Omit()
          ? isolate->factory()->empty_trusted_byte_array()
          : source_position_table_builder_.ToSourcePositionTable(isolate);
  return source_position_table;
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> BytecodeArrayWriter::ToSourcePositionTable(
        Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> BytecodeArrayWriter::ToSourcePositionTable(
        LocalIsolate* isolate);

#ifdef DEBUG
int BytecodeArrayWriter::CheckBytecodeMatches(Tagged<BytecodeArray> bytecode) {
  int mismatches = false;
  int bytecode_size = static_cast<int>(bytecodes()->size());
  const uint8_t* bytecode_ptr = &bytecodes()->front();
  if (bytecode_size != bytecode->length()) mismatches = true;

  // If there's a mismatch only in the length of the bytecode (very unlikely)
  // then the first mismatch will be the first extra bytecode.
  int first_mismatch = std::min(bytecode_size, bytecode->length());
  for (int i = 0; i < first_mismatch; ++i) {
    if (bytecode_ptr[i] != bytecode->get(i)) {
      mismatches = true;
      first_mismatch = i;
      break;
    }
  }

  if (mismatches) {
    return first_mismatch;
  }
  return -1;
}
#endif

void BytecodeArrayWriter::Write(BytecodeNode* node) {
  DCHECK(!Bytecodes::IsJump(node->bytecode()));

  if (exit_seen_in_block_) return;  // Don't emit dead code.
  UpdateExitSeenInBlock(node->bytecode());
  MaybeElideLastBytecode(node->bytecode(), node->source_info().is_valid());

  UpdateSourcePositionTable(node);
  EmitBytecode(node);
}

void BytecodeArrayWriter::WriteJump(BytecodeNode* node, BytecodeLabel* label) {
  DCHECK(Bytecodes::IsForwardJump(node->bytecode()));

  if (exit_seen_in_block_) return;  // Don't emit dead code.
  UpdateExitSeenInBlock(node->bytecode());
  MaybeElideLastBytecode(node->bytecode(), node->source_info().is_valid());

  UpdateSourcePositionTable(node);
  EmitJump(node, label);
}

void BytecodeArrayWriter::WriteJumpLoop(BytecodeNode* node,
                                        BytecodeLoopHeader* loop_header) {
  DCHECK_EQ(node->bytecode(), Bytecode::kJumpLoop);

  if (exit_seen_in_block_) return;  // Don't emit dead code.
  UpdateExitSeenInBlock(node->bytecode());
  MaybeElideLastBytecode(node->bytecode(), node->source_info().is_valid());

  UpdateSourcePositionTable(node);
  EmitJumpLoop(node, loop_header);
}

void BytecodeArrayWriter::WriteSwitch(BytecodeNode* node,
                                      BytecodeJumpTable* jump_table) {
  DCHECK(Bytecodes::IsSwitch(node->bytecode()));

  if (exit_seen_in_block_) return;  // Don't emit dead code.
  UpdateExitSeenInBlock(node->bytecode());
  MaybeElideLastBytecode(node->bytecode(), node->source_info().is_valid());

  UpdateSourcePositionTable(node);
  EmitSwitch(node, jump_table);
}

void BytecodeArrayWriter::BindLabel(BytecodeLabel* label) {
  DCHECK(label->has_referrer_jump());
  size_t current_offset = bytecodes()->size();
  // Update the jump instruction's location.
  PatchJump(current_offset, label->jump_offset());
  label->bind();
  StartBasicBlock();
}

void BytecodeArrayWriter::BindLoopHeader(BytecodeLoopHeader* loop_header) {
  size_t current_offset = bytecodes()->size();
  loop_header->bind_to(current_offset);
  // Don't start a basic block when the entire loop is dead.
  if (exit_seen_in_block_) return;
  StartBasicBlock();
}

void BytecodeArrayWriter::BindJumpTableEntry(BytecodeJumpTable* jump_table,
                                             int case_value) {
  DCHECK(!jump_table->is_bound(case_value));

  size_t current_offset = bytecodes()->size();
  size_t relative_jump = current_offset - jump_table->switch_bytecode_offset();

  constant_array_builder()->SetJumpTableSmi(
      jump_table->ConstantPoolEntryFor(case_value),
      Smi::FromInt(static_cast<int>(relative_jump)));
  jump_table->mark_bound(case_value);

  StartBasicBlock();
}

void BytecodeArrayWriter::BindHandlerTarget(
    HandlerTableBuilder* handler_table_builder, int handler_id) {
  size_t current_offset = bytecodes()->size();
  StartBasicBlock();
  handler_table_builder->SetHandlerTarget(handler_id, current_offset);
}

void BytecodeArrayWriter::BindTryRegionStart(
    HandlerTableBuilder* handler_table_builder, int handler_id) {
  size_t current_offset = bytecodes()->size();
  // Try blocks don't have to be in a separate basic block, but we do have to
  // invalidate the bytecode to avoid eliding it and changing the offset.
  InvalidateLastBytecode();
  handler_table_builder->SetTryRegionStart(handler_id, current_offset);
}

void BytecodeArrayWriter::BindTryRegionEnd(
    HandlerTableBuilder* handler_table_builder, int handler_id) {
  // Try blocks don't have to be in a separate basic block, but we do have to
  // invalidate the bytecode to avoid eliding it and changing the offset.
  InvalidateLastBytecode();
  size_t current_offset = bytecodes()->size();
  handler_table_builder->SetTryRegionEnd(handler_id, current_offset);
}

void BytecodeArrayWriter::SetFunctionEntrySourcePosition(int position) {
  bool is_statement = false;
  source_position_table_builder_.AddPosition(
      kFunctionEntryBytecodeOffset, SourcePosition(position), is_statement);
}

void BytecodeArrayWriter::StartBasicBlock() {
  InvalidateLastBytecode();
  exit_seen_in_block_ = false;
}

void BytecodeArrayWriter::UpdateSourcePositionTable(
    const BytecodeNode* const node) {
  int bytecode_offset = static_cast<int>(bytecodes()->size());
  const BytecodeSourceInfo& source_info = node->source_info();
  if (source_info.is_valid()) {
    source_position_table_builder()->AddPosition(
        bytecode_offset, SourcePosition(source_info.source_position()),
        source_info.is_statement());
  }
}

void BytecodeArrayWriter::UpdateExitSeenInBlock(Bytecode bytecode) {
  switch (bytecode) {
    case Bytecode::kReturn:
    case Bytecode::kThrow:
    case Bytecode::kReThrow:
    case Bytecode::kAbort:
    case Bytecode::kJump:
    case Bytecode::kJumpLoop:
    case Bytecode::kJumpConstant:
    case Bytecode::kSuspendGenerator:
      exit_seen_in_block_ = true;
      break;
    default:
      break;
  }
}

void BytecodeArrayWriter::MaybeElideLastBytecode(Bytecode next_bytecode,
                                                 bool has_source_info) {
  if (!elide_noneffectful_bytecodes_) return;

  // If the last bytecode loaded the accumulator without any external effect,
  // and the next bytecode clobbers this load without reading the accumulator,
  // then the previous bytecode can be elided as it has no effect.
  if (Bytecodes::IsAccumulatorLoadWithoutEffects(last_bytecode_) &&
      Bytecodes::GetImplicitRegisterUse(next_bytecode) ==
          ImplicitRegisterUse::kWriteAccumulator &&
      (!last_bytecode_had_source_info_ || !has_source_info)) {
    DCHECK_GT(bytecodes()->size(), last_bytecode_offset_);
    bytecodes()->resize(last_bytecode_offset_);
    // If the last bytecode had source info we will transfer the source info
    // to this bytecode.
    has_source_info |= last_bytecode_had_source_info_;
  }
  last_bytecode_ = next_bytecode;
  last_bytecode_had_source_info_ = has_source_info;
  last_bytecode_offset_ = bytecodes()->size();
}

void BytecodeArrayWriter::InvalidateLastBytecode() {
  last_bytecode_ = Bytecode::kIllegal;
}

void BytecodeArrayWriter::EmitBytecode(const BytecodeNode* const node) {
  DCHECK_NE(node->bytecode(), Bytecode::kIllegal);

  Bytecode bytecode = node->bytecode();
  OperandScale operand_scale = node->operand_scale();

  if (operand_scale != OperandScale::kSingle) {
    Bytecode prefix = Bytecodes::OperandScaleToPrefixBytecode(operand_scale);
    bytecodes()->push_back(Bytecodes::ToByte(prefix));
  }
  bytecodes()->push_back(Bytecodes::ToByte(bytecode));

  const uint32_t* const operands = node->operands();
  const int operand_count = node->operand_count();
  const OperandSize* operand_sizes =
      Bytecodes::GetOperandSizes(bytecode, operand_scale);
  for (int i = 0; i < operand_count; ++i) {
    switch (operand_sizes[i]) {
      case OperandSize::kNone:
        UNREACHABLE();
      case OperandSize::kByte:
        bytecodes()->push_back(static_cast<uint8_t>(operands[i]));
        break;
      case OperandSize::kShort: {
        uint16_t operand = static_cast<uint16_t>(operands[i]);
        const uint8_t* raw_operand = reinterpret_cast<const uint8_t*>(&operand);
        bytecodes()->push_back(raw_operand[0]);
        bytecodes()->push_back(raw_operand[1]);
        break;
      }
      case OperandSize::kQuad: {
        const uint8_t* raw_operand =
            reinterpret_cast<const uint8_t*>(&operands[i]);
        bytecodes()->push_back(raw_operand[0]);
        bytecodes()->push_back(raw_operand[1]);
        bytecodes()->push_back(raw_operand[2]);
        bytecodes()->push_back(raw_operand[3]);
        break;
      }
    }
  }
}

// static
Bytecode GetJumpWithConstantOperand(Bytecode jump_bytecode) {
  switch (jump_bytecode) {
    case Bytecode::kJump:
      return Bytecode::kJumpConstant;
    case Bytecode::kJumpIfTrue:
      return Bytecode::kJumpIfTrueConstant;
    case Bytecode::kJumpIfFalse:
      return Bytecode::kJumpIfFalseConstant;
    case Bytecode::kJumpIfToBooleanTrue:
      return Bytecode::kJumpIfToBooleanTrueConstant;
    case Bytecode::kJumpIfToBooleanFalse:
      return Bytecode::kJumpIfToBooleanFalseConstant;
    case Bytecode::kJumpIfNull:
      return Bytecode::kJumpIfNullConstant;
    case Bytecode::kJumpIfNotNull:
      return Bytecode::kJumpIfNotNullConstant;
    case Bytecode::kJumpIfUndefined:
      return Bytecode::kJumpIfUndefinedConstant;
    case Bytecode::kJumpIfNotUndefined:
      return Bytecode::kJumpIfNotUndefinedConstant;
    case Bytecode::kJumpIfUndefinedOrNull:
      return Bytecode::kJumpIfUndefinedOrNullConstant;
    case Bytecode::kJumpIfJSReceiver:
      return Bytecode::kJumpIfJSReceiverConstant;
    case Bytecode::kJumpIfForInDone:
      return Bytecode::kJumpIfForInDoneConstant;
    default:
      UNREACHABLE();
  }
}

void BytecodeArrayWriter::PatchJumpWith8BitOperand(size_t jump_location,
                                                   int delta) {
  Bytecode jump_bytecode = Bytecodes::FromByte(bytecodes()->at(jump_location));
  DCHECK(Bytecodes::IsForwardJump(jump_bytecode));
  DCHECK(Bytecodes::IsJumpImmediate(jump_bytecode));
  DCHECK_EQ(Bytecodes::GetOperandType(jump_bytecode, 0), OperandType::kUImm);
  DCHECK_GT(delta, 0);
  size_t operand_location = jump_location + 1;
  DCHECK_EQ(bytecodes()->at(operand_location), k8BitJumpPlaceholder);
  if (Bytecodes::ScaleForUnsignedOperand(delta) == OperandScale::kSingle) {
    // The jump fits within the range of an UImm8 operand, so cancel
    // the reservation and jump directly.
    constant_array_builder()->DiscardReservedEntry(OperandSize::kByte);
    bytecodes()->at(operand_location) = static_cast<uint8_t>(delta);
  } else {
    // The jump does not fit within the range of an UImm8 operand, so
    // commit reservation putting the offset into the constant pool,
    // and update the jump instruction and operand.
    size_t entry = constant_array_builder()->CommitReservedEntry(
        OperandSize::kByte, Smi::FromInt(delta));
    DCHECK_EQ(Bytecodes::SizeForUnsignedOperand(static_cast<uint32_t>(entry)),
              OperandSize::kByte);
    jump_bytecode = GetJumpWithConstantOperand(jump_bytecode);
    bytecodes()->at(jump_location) = Bytecodes::ToByte(jump_bytecode);
    bytecodes()->at(operand_location) = static_cast<uint8_t>(entry);
  }
}

void BytecodeArrayWriter::PatchJumpWith16BitOperand(size_t jump_location,
                                                    int delta) {
  Bytecode jump_bytecode = Bytecodes::FromByte(bytecodes()->at(jump_location));
  DCHECK(Bytecodes::IsForwardJump(jump_bytecode));
  DCHECK(Bytecodes::IsJumpImmediate(jump_bytecode));
  DCHECK_EQ(Bytecodes::GetOperandType(jump_bytecode, 0), OperandType::kUImm);
  DCHECK_GT(delta, 0);
  size_t operand_location = jump_location + 1;
  uint8_t operand_bytes[2];
  if (Bytecodes::ScaleForUnsignedOperand(delta) <= OperandScale::kDouble) {
    // The jump fits within the range of an Imm16 operand, so cancel
    // the reservation and jump directly.
    constant_array_builder()->DiscardReservedEntry(OperandSize::kShort);
    base::WriteUnalignedValue<uint16_t>(
        reinterpret_cast<Address>(operand_bytes), static_cast<uint16_t>(delta));
  } else {
    // The jump does not fit within the range of an Imm16 operand, so
    // commit reservation putting the offset into the constant pool,
    // and update the jump instruction and operand.
    size_t entry = constant_array_builder()->CommitReservedEntry(
        OperandSize::kShort, Smi::FromInt(delta));
    jump_bytecode = GetJumpWithConstantOperand(jump_bytecode);
    bytecodes()->at(jump_location) = Bytecodes::ToByte(jump_bytecode);
    base::WriteUnalignedValue<uint16_t>(
        reinterpret_cast<Address>(operand_bytes), static_cast<uint16_t>(entry));
  }
  DCHECK(bytecodes()->at(operand_location) == k8BitJumpPlaceholder &&
         bytecodes()->at(operand_location + 1) == k8BitJumpPlaceholder);
  bytecodes()->at(operand_location++) = operand_bytes[0];
  bytecodes()->at(operand_location) = operand_bytes[1];
}

void BytecodeArrayWriter::PatchJumpWith32BitOperand(size_t jump_location,
                                                    int delta) {
  DCHECK(Bytecodes::IsJumpImmediate(
      Bytecodes::FromByte(bytecodes()->at(jump_location))));
  constant_array_builder()->DiscardReservedEntry(OperandSize::kQuad);
  uint8_t operand_bytes[4];
  base::WriteUnalignedValue<uint32_t>(reinterpret_cast<Address>(operand_bytes),
                                      static_cast<uint32_t>(delta));
  size_t operand_location = jump_location + 1;
  DCHECK(bytecodes()->at(operand_location) == k8BitJumpPlaceholder &&
         bytecodes()->at(operand_location + 1) == k8BitJumpPlaceholder &&
         bytecodes()->at(operand_location + 2) == k8BitJumpPlaceholder &&
         bytecodes()->at(operand_location + 3) == k8BitJumpPlaceholder);
  bytecodes()->at(operand_location++) = operand_bytes[0];
  bytecodes()->at(operand_location++) = operand_bytes[1];
  bytecodes()->at(operand_location++) = operand_bytes[2];
  bytecodes()->at(operand_location) = operand_bytes[3];
}

void BytecodeArrayWriter::PatchJump(size_t jump_target, size_t jump_location) {
  Bytecode jump_bytecode = Bytecodes::FromByte(bytecodes()->at(jump_location));
  int delta = static_cast<int>(jump_target - jump_location);
  int prefix_offset = 0;
  OperandScale operand_scale = OperandScale::kSingle;
  if (Bytecodes::IsPrefixScalingBytecode(jump_bytecode)) {
    // If a prefix scaling bytecode is emitted the target offset is one
    // less than the case of no prefix scaling bytecode.
    delta -= 1;
    prefix_offset = 1;
    operand_scale = Bytecodes::PrefixBytecodeToOperandScale(jump_bytecode);
    jump_bytecode =
        Bytecodes::FromByte(bytecodes()->at(jump_location + prefix_offset));
  }

  DCHECK(Bytecodes::IsJump(jump_bytecode));
  switch (operand_scale) {
    case OperandScale::kSingle:
      PatchJumpWith8BitOperand(jump_location, delta);
      break;
    case OperandScale::kDouble:
      PatchJumpWith16BitOperand(jump_location + prefix_offset, delta);
      break;
    case OperandScale::kQuadruple:
      PatchJumpWith32BitOperand(jump_location + prefix_offset, delta);
      break;
    default:
      UNREACHABLE();
  }
  unbound_jumps_--;
}

void BytecodeArrayWriter::EmitJumpLoop(BytecodeNode* node,
                                       BytecodeLoopHeader* loop_header) {
  DCHECK_EQ(node->bytecode(), Bytecode::kJumpLoop);
  DCHECK_EQ(0u, node->operand(0));

  size_t current_offset = bytecodes()->size();

  CHECK_GE(current_offset, loop_header->offset());
  CHECK_LE(current_offset, static_cast<size_t>(kMaxUInt32));

  // Update the actual jump offset now that we know the bytecode offset of both
  // the target loop header and this JumpLoop bytecode.
  //
  // The label has been bound already so this is a backwards jump.
  uint32_t delta =
      static_cast<uint32_t>(current_offset - loop_header->offset());
  // This JumpLoop bytecode itself may have a kWide or kExtraWide prefix; if
  // so, bump the delta to account for it.
  const bool emits_prefix_bytecode =
      Bytecodes::OperandScaleRequiresPrefixBytecode(node->operand_scale()) ||
      Bytecodes::OperandScaleRequiresPrefixBytecode(
          Bytecodes::ScaleForUnsignedOperand(delta));
  if (emits_prefix_bytecode) {
    static constexpr int kPrefixBytecodeSize = 1;
    delta += kPrefixBytecodeSize;
    DCHECK_EQ(Bytecodes::Size(Bytecode::kWide, OperandScale::kSingle),
              kPrefixBytecodeSize);
    DCHECK_EQ(Bytecodes::Size(Bytecode::kExtraWide, OperandScale::kSingle),
              kPrefixBytecodeSize);
  }
  node->update_operand0(delta);
  DCHECK_EQ(
      Bytecodes::OperandScaleRequiresPrefixBytecode(node->operand_scale()),
      emits_prefix_bytecode);

  EmitBytecode(node);
}

void BytecodeArrayWriter::EmitJump(BytecodeNode* node, BytecodeLabel* label) {
  DCHECK(Bytecodes::IsForwardJump(node->bytecode()));
  DCHECK_EQ(0u, node->operand(0));

  size_t current_offset = bytecodes()->size();

  // The label has not yet been bound so this is a forward reference
  // that will be patched when the label is bound. We create a
  // reservation in the constant pool so the jump can be patched
  // when the label is bound. The reservation means the maximum size
  // of the operand for the constant is known and the jump can
  // be emitted into the bytecode stream with space for the operand.
  unbound_jumps_++;
  label->set_referrer(current_offset);
  OperandSize reserved_operand_size =
      constant_array_builder()->CreateReservedEntry(
          static_cast<OperandSize>(node->operand_scale()));
  DCHECK_NE(Bytecode::kJumpLoop, node->bytecode());
  switch (reserved_operand_size) {
    case OperandSize::kNone:
      UNREACHABLE();
    case OperandSize::kByte:
      node->update_operand0(k8BitJumpPlaceholder);
      break;
    case OperandSize::kShort:
      node->update_operand0(k16BitJumpPlaceholder);
      break;
    case OperandSize::kQuad:
      node->update_operand0(k32BitJumpPlaceholder);
      break;
  }
  EmitBytecode(node);
}

void BytecodeArrayWriter::EmitSwitch(BytecodeNode* node,
                                     BytecodeJumpTable* jump_table) {
  DCHECK(Bytecodes::IsSwitch(node->bytecode()));

  size_t current_offset = bytecodes()->size();
  if (node->operand_scale() > OperandScale::kSingle) {
    // Adjust for scaling byte prefix.
    current_offset += 1;
  }
  jump_table->set_switch_bytecode_offset(current_offset);

  EmitBytecode(node);
}

}  // namespace interpreter
}  // namespace internal
}  // namespace v8
```