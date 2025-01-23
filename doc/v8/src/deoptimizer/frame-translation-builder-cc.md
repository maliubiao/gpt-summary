Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Goal:** The request asks for a breakdown of the code's functionality, whether it relates to JavaScript, potential user errors, and examples. The key is to identify the *purpose* of this code within the larger V8 context.

2. **Initial Skim and Keyword Identification:**  A quick read-through reveals keywords like "deoptimizer," "frame," "translation," "opcode," "register," "stack slot," "literal," and "feedback." These immediately suggest the code is involved in the process of transitioning from optimized code back to a less optimized state (deoptimization) and involves representing the state of the program's execution (the frame).

3. **Identifying the Core Class:** The central class is `FrameTranslationBuilder`. The name itself is highly informative. It suggests that this class is responsible for *building* something related to *translating* the execution *frame*.

4. **Analyzing Public Methods:** The public methods of `FrameTranslationBuilder` are good indicators of its functionality. Let's examine some key ones:

    * `BeginTranslation`: This seems to initiate the process of creating a translation for a new frame. The arguments `frame_count`, `jsframe_count`, and `update_feedback` provide context.
    * `AddRawToContents`, `AddRawToContentsForCompression`, `AddRawBegin`: These methods appear to add raw data, likely representing opcodes and operands, to internal buffers. The "compression" variant suggests optimization for storage.
    * `Add`: This is the main method for adding translation information. It seems to handle both raw addition and a mechanism for reusing previous translations (`match_previous_allowed_`).
    * `ToFrameTranslation`, `ToFrameTranslationWasm`: These methods finalize the building process and return the constructed translation, potentially in different formats (one specifically for WebAssembly).
    * Methods starting with `Begin...Frame`:  These clearly define different types of frames (e.g., `BeginInterpretedFrame`, `BeginBuiltinContinuationFrame`). This indicates the code needs to handle various execution contexts.
    * Methods starting with `Store...`: These methods deal with storing the values of registers (general, floating-point, SIMD), stack slots, and literals. This points to the need to capture the state of variables and constants.
    * `ArgumentsElements`, `ArgumentsLength`, `RestLength`: These suggest handling function arguments.
    * `AddUpdateFeedback`: This is likely related to performance optimization and collecting information about how code is being used.

5. **Analyzing Private Members and Helper Classes:**

    * `contents_`, `contents_for_compression_`: These are the internal buffers where the translation data is stored.
    * `basis_instructions_`: This seems to store a "basis" translation that can be reused, hinting at optimization strategies to reduce the size of translation data.
    * `OperandBase`, `SmallUnsignedOperand`, `UnsignedOperand`, `SignedOperand`: These classes handle the encoding of operands with different types and sizes, often using Variable-Length Quantity (VLQ) encoding for efficiency.

6. **Connecting to Deoptimization:** The file path `v8/src/deoptimizer/frame-translation-builder.cc` is the strongest clue. Deoptimization happens when the optimized code makes assumptions that turn out to be invalid. The V8 engine needs a way to unwind the stack and restore the program state to a point where it can continue execution using the interpreter or less optimized code. The `FrameTranslationBuilder` plays a crucial role in *describing the layout and contents of the optimized frame* so that the deoptimizer can correctly reconstruct the state.

7. **Identifying JavaScript Relevance:** Deoptimization is directly related to JavaScript execution. When JavaScript code is optimized by TurboFan (V8's optimizing compiler), the generated machine code needs a way to "bail out" back to a less optimized state. The information built by `FrameTranslationBuilder` is essential for this process.

8. **Formulating JavaScript Examples:** Based on the identified functionalities, examples can be constructed. Storing register values relates to storing local variables. Storing stack slots relates to function call context and temporary values. The frame types relate to different kinds of function calls and execution stages. The `UPDATE_FEEDBACK` relates to inline caches and optimization hints.

9. **Inferring Code Logic and Assumptions:** The code uses VLQ encoding, which is a common technique for efficiently storing variable-length integers. The logic around `match_previous_allowed_` and `basis_instructions_` demonstrates an optimization to avoid redundant translation data.

10. **Identifying Potential User Errors (Indirectly):**  While the user doesn't directly interact with this code, understanding its purpose helps identify scenarios where deoptimization *might* occur due to programmer actions:

    * **Changing object shapes dynamically:** This can invalidate assumptions made by the optimizing compiler.
    * **Using `arguments` object:** This can hinder optimization.
    * **Unpredictable control flow:**  Makes it harder for the compiler to make assumptions.

11. **Review and Refine:**  After drafting the initial explanation, review it for clarity, accuracy, and completeness. Ensure the JavaScript examples are relevant and illustrative. Double-check the assumptions about the code's behavior. For example, confirming that VLQ is indeed used helps solidify the explanation.

This systematic approach, moving from general understanding to specific details and then connecting the pieces back to the larger context, allows for a comprehensive analysis of the C++ code.
This C++ source code file, `v8/src/deoptimizer/frame-translation-builder.cc`, is part of the V8 JavaScript engine and is responsible for **building frame translations during the deoptimization process**.

Here's a breakdown of its functionalities:

**Core Functionality: Building Deoptimization Frame Translations**

* **Purpose of Frame Translations:** When V8's optimizing compiler (TurboFan) generates optimized machine code, it makes assumptions about the state of the program. If these assumptions become invalid at runtime (e.g., the type of a variable changes unexpectedly), the engine needs to "deoptimize" back to a less optimized state (usually the interpreter). To do this, it needs to reconstruct the program's state (registers, stack, etc.) at the point of deoptimization. This reconstruction information is stored in a "frame translation".
* **`FrameTranslationBuilder`'s Role:** This class provides methods to incrementally build these frame translations. It acts as a builder pattern, allowing different components of the deoptimization information to be added step by step.
* **Opcodes and Operands:** The translations are essentially sequences of opcodes (instructions) and their operands (data). The `FrameTranslationBuilder` has methods to add these opcodes and operands to an internal buffer. Examples of opcodes include `BEGIN_WITH_FEEDBACK`, `INTERPRETED_FRAME_WITH_RETURN`, `REGISTER`, `STACK_SLOT`, `LITERAL`, etc. These opcodes describe what kind of data is being stored in the translation (e.g., the value of a register, the location of a stack slot, a constant value).
* **Compression:** The code includes logic for optionally compressing the frame translations using zlib (`#ifdef V8_USE_ZLIB`). This is controlled by the `v8_flags.turbo_compress_frame_translations` flag. Compression helps reduce the size of the translation data.
* **Basis Translation Optimization:** The class implements a mechanism to reuse parts of previously built translations. This is an optimization to avoid redundant information and reduce the size of the translations, especially when deoptimizing multiple frames in a stack.

**Relationship to JavaScript Functionality**

This code is **directly related to JavaScript functionality**, specifically the performance optimization and deoptimization aspects of V8. When JavaScript code is executed, V8 may:

1. **Optimize the code:** TurboFan compiles frequently executed JavaScript functions into highly optimized machine code.
2. **Make assumptions:** During optimization, TurboFan makes assumptions about the types of variables and the control flow.
3. **Deoptimize:** If these assumptions are violated, the optimized code needs to "bail out" and the interpreter or a less optimized version of the code takes over.
4. **Use Frame Translations:** The `FrameTranslationBuilder` is crucial in creating the data needed for this deoptimization process. The frame translation describes how to reconstruct the JavaScript execution state at the point where the optimization failed.

**JavaScript Example (Illustrative)**

Imagine the following JavaScript code:

```javascript
function add(a, b) {
  return a + b;
}

let result = 0;
for (let i = 0; i < 10000; i++) {
  result = add(i, 1); // Likely optimized with 'a' and 'b' as numbers
}

result = add("hello", "world"); // Type of 'a' and 'b' changed! Potential deoptimization
```

In this example:

* V8 might optimize the `add` function assuming `a` and `b` are always numbers during the loop.
* When `add("hello", "world")` is called, the assumption about the types of `a` and `b` becomes invalid.
* **Deoptimization happens:** V8 needs to revert to a less optimized version of `add`.
* **`FrameTranslationBuilder` comes into play:**  When the optimized version of `add` was entered, information about the current state (registers holding the values of `a` and `b`, the return address, etc.) was potentially recorded or prepared. If a deoptimization occurs within the optimized `add` function called with strings, the frame translation built by this code would describe how to restore the state of the JavaScript engine right before that call, allowing the interpreter to correctly execute `add("hello", "world")`.

**Code Logic Inference (Hypothetical Example)**

Let's consider the `BeginInterpretedFrame` method:

```c++
void FrameTranslationBuilder::BeginInterpretedFrame(
    BytecodeOffset bytecode_offset, int literal_id, int bytecode_array_id,
    unsigned height, int return_value_offset, int return_value_count) {
  if (return_value_count == 0) {
    auto opcode = TranslationOpcode::INTERPRETED_FRAME_WITHOUT_RETURN;
    Add(opcode, SignedOperand(bytecode_offset.ToInt()),
        SignedOperand(literal_id), SignedOperand(bytecode_array_id),
        UnsignedOperand(height));
  } else {
    auto opcode = TranslationOpcode::INTERPRETED_FRAME_WITH_RETURN;
    Add(opcode, SignedOperand(bytecode_offset.ToInt()),
        SignedOperand(literal_id), SignedOperand(bytecode_array_id),
        UnsignedOperand(height), SignedOperand(return_value_offset),
        SignedOperand(return_value_count));
  }
}
```

**Hypothetical Input:**

* `bytecode_offset`: 10 (The offset within the bytecode of the current instruction)
* `literal_id`: 5 (An ID referencing a literal value in the constant pool)
* `bytecode_array_id`: 2 (An ID referencing the bytecode array of the function)
* `height`: 3 (The stack frame height)
* `return_value_offset`: -1 (The offset for the return value on the stack)
* `return_value_count`: 1 (The number of return values)

**Output (Conceptual - added to the internal `contents_` buffer):**

Since `return_value_count` is 1, the `INTERPRETED_FRAME_WITH_RETURN` opcode will be used, followed by its operands encoded using VLQ (Variable-Length Quantity) encoding:

`[Opcode: INTERPRETED_FRAME_WITH_RETURN, Operand: 10, Operand: 5, Operand: 2, Operand: 3, Operand: -1, Operand: 1]`

The exact byte representation would depend on the VLQ encoding scheme used.

**User-Common Programming Errors Leading to Deoptimization (Indirectly Related)**

While developers don't directly interact with `frame-translation-builder.cc`, certain coding practices can increase the likelihood of deoptimization, making the work of this code more relevant:

1. **Type Instability:**  Continuously changing the type of a variable within a function can prevent effective optimization.

   ```javascript
   function calculate(input) {
     let result = 0;
     if (typeof input === 'number') {
       result = input * 2;
     } else if (typeof input === 'string') {
       result = input.length;
     }
     return result;
   }

   console.log(calculate(5));   // Optimized for number
   console.log(calculate("hello")); // Might trigger deoptimization
   ```

2. **Hidden Classes/Shapes Changes:**  Modifying the structure of objects after they are created can invalidate optimizations.

   ```javascript
   function Point(x, y) {
     this.x = x;
     this.y = y;
   }

   let p1 = new Point(1, 2); // V8 might assume the shape {x, y}
   p1.z = 3; // Changing the shape can lead to deoptimization for code using 'p1'
   ```

3. **Use of `arguments` Object:**  The `arguments` object can hinder certain optimizations. Rest parameters (`...args`) are often a better alternative.

   ```javascript
   function sum() {
     let total = 0;
     for (let i = 0; i < arguments.length; i++) { // Can be less optimizable
       total += arguments[i];
     }
     return total;
   }
   ```

4. **Unpredictable Control Flow:** Excessive use of dynamic conditions or `eval()` can make it difficult for the optimizer to make assumptions.

In summary, `v8/src/deoptimizer/frame-translation-builder.cc` is a crucial piece of V8's internal machinery, responsible for constructing the data needed to smoothly transition from optimized code back to a less optimized state when runtime assumptions are violated. It doesn't directly involve user-written JavaScript code, but its functionality is essential for the overall performance and robustness of the JavaScript engine.

### 提示词
```
这是目录为v8/src/deoptimizer/frame-translation-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/deoptimizer/frame-translation-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/deoptimizer/frame-translation-builder.h"

#include <optional>

#include "src/base/vlq.h"
#include "src/deoptimizer/translated-state.h"
#include "src/objects/fixed-array-inl.h"

#ifdef V8_USE_ZLIB
#include "third_party/zlib/google/compression_utils_portable.h"
#endif  // V8_USE_ZLIB

namespace v8 {
namespace internal {

namespace {

class OperandBase {
 public:
  explicit OperandBase(uint32_t value) : value_(value) {}
  uint32_t value() const { return value_; }

 private:
  uint32_t value_;
};

class SmallUnsignedOperand : public OperandBase {
 public:
  explicit SmallUnsignedOperand(uint32_t value) : OperandBase(value) {
    DCHECK_LE(value, base::kDataMask);
  }
  void WriteVLQ(ZoneVector<uint8_t>* buffer) { buffer->push_back(value()); }
  bool IsSigned() const { return false; }
};

class UnsignedOperand : public OperandBase {
 public:
  explicit UnsignedOperand(int32_t value)
      : UnsignedOperand(static_cast<uint32_t>(value)) {
    DCHECK_GE(value, 0);
  }
  explicit UnsignedOperand(uint32_t value) : OperandBase(value) {}
  void WriteVLQ(ZoneVector<uint8_t>* buffer) {
    base::VLQEncodeUnsigned(
        [buffer](uint8_t value) { buffer->push_back(value); }, value());
  }
  bool IsSigned() const { return false; }
};

class SignedOperand : public OperandBase {
 public:
  explicit SignedOperand(int32_t value) : OperandBase(value) {}
  // Use UnsignedOperand for unsigned values.
  explicit SignedOperand(uint32_t value) = delete;
  void WriteVLQ(ZoneVector<uint8_t>* buffer) {
    base::VLQEncode(
        [buffer](uint8_t value) {
          buffer->push_back(value);
          return &buffer->back();
        },
        value());
  }
  bool IsSigned() const { return true; }
};

template <typename... T>
inline bool OperandsEqual(uint32_t* expected_operands, T... operands) {
  return (... && (*(expected_operands++) == operands.value()));
}

}  // namespace

template <typename... T>
void FrameTranslationBuilder::AddRawToContents(TranslationOpcode opcode,
                                               T... operands) {
  DCHECK_EQ(sizeof...(T), TranslationOpcodeOperandCount(opcode));
  DCHECK(!v8_flags.turbo_compress_frame_translations);
  contents_.push_back(static_cast<uint8_t>(opcode));
  (..., operands.WriteVLQ(&contents_));
}

template <typename... T>
void FrameTranslationBuilder::AddRawToContentsForCompression(
    TranslationOpcode opcode, T... operands) {
  DCHECK_EQ(sizeof...(T), TranslationOpcodeOperandCount(opcode));
  DCHECK(v8_flags.turbo_compress_frame_translations);
  contents_for_compression_.push_back(static_cast<uint8_t>(opcode));
  (..., contents_for_compression_.push_back(operands.value()));
}

template <typename... T>
void FrameTranslationBuilder::AddRawBegin(bool update_feedback, T... operands) {
  auto opcode = update_feedback ? TranslationOpcode::BEGIN_WITH_FEEDBACK
                                : TranslationOpcode::BEGIN_WITHOUT_FEEDBACK;
  if (V8_UNLIKELY(v8_flags.turbo_compress_frame_translations)) {
    AddRawToContentsForCompression(opcode, operands...);
  } else {
    AddRawToContents(opcode, operands...);
#ifdef ENABLE_SLOW_DCHECKS
    if (v8_flags.enable_slow_asserts) {
      all_instructions_.emplace_back(opcode, operands...);
    }
#endif
  }
}

int FrameTranslationBuilder::BeginTranslation(int frame_count,
                                              int jsframe_count,
                                              bool update_feedback) {
  FinishPendingInstructionIfNeeded();
  int start_index = Size();
  int distance_from_last_start = 0;

  // We should reuse an existing basis translation if:
  // - we just finished writing the basis translation
  //   (match_previous_allowed_ is false), or
  // - the translation we just finished was moderately successful at reusing
  //   instructions from the basis translation. We'll define "moderately
  //   successful" as reusing more than 3/4 of the basis instructions.
  // Otherwise we should reset and write a new basis translation. At the
  // beginning, match_previous_allowed_ is initialized to true so that this
  // logic decides to start a new basis translation.
  if (!match_previous_allowed_ ||
      total_matching_instructions_in_current_translation_ >
          instruction_index_within_translation_ / 4 * 3) {
    // Use the existing basis translation.
    distance_from_last_start = start_index - index_of_basis_translation_start_;
    match_previous_allowed_ = true;
  } else {
    // Abandon the existing basis translation and write a new one.
    basis_instructions_.clear();
    index_of_basis_translation_start_ = start_index;
    match_previous_allowed_ = false;
  }

  total_matching_instructions_in_current_translation_ = 0;
  instruction_index_within_translation_ = 0;

  // BEGIN instructions can't be replaced by MATCH_PREVIOUS_TRANSLATION, so
  // use a special helper function rather than calling Add().
  AddRawBegin(update_feedback, UnsignedOperand(distance_from_last_start),
              SignedOperand(frame_count), SignedOperand(jsframe_count));
  return start_index;
}

void FrameTranslationBuilder::FinishPendingInstructionIfNeeded() {
  if (matching_instructions_count_) {
    total_matching_instructions_in_current_translation_ +=
        matching_instructions_count_;

    // There is a short form for the MATCH_PREVIOUS_TRANSLATION instruction
    // because it's the most common opcode: rather than spending a byte on the
    // opcode and a second byte on the operand, we can use only a single byte
    // which doesn't match any valid opcode.
    const int kMaxShortenableOperand =
        std::numeric_limits<uint8_t>::max() - kNumTranslationOpcodes;
    if (matching_instructions_count_ <= kMaxShortenableOperand) {
      contents_.push_back(kNumTranslationOpcodes +
                          matching_instructions_count_);
    } else {
      // The operand didn't fit in the opcode byte, so encode it normally.
      AddRawToContents(
          TranslationOpcode::MATCH_PREVIOUS_TRANSLATION,
          UnsignedOperand(static_cast<uint32_t>(matching_instructions_count_)));
    }
    matching_instructions_count_ = 0;
  }
}

template <typename... T>
void FrameTranslationBuilder::Add(TranslationOpcode opcode, T... operands) {
  DCHECK_EQ(sizeof...(T), TranslationOpcodeOperandCount(opcode));
  if (V8_UNLIKELY(v8_flags.turbo_compress_frame_translations)) {
    AddRawToContentsForCompression(opcode, operands...);
    return;
  }
#ifdef ENABLE_SLOW_DCHECKS
  if (v8_flags.enable_slow_asserts) {
    all_instructions_.emplace_back(opcode, operands...);
  }
#endif
  if (match_previous_allowed_ &&
      instruction_index_within_translation_ < basis_instructions_.size() &&
      opcode ==
          basis_instructions_[instruction_index_within_translation_].opcode &&
      OperandsEqual(
          basis_instructions_[instruction_index_within_translation_].operands,
          operands...)) {
    ++matching_instructions_count_;
  } else {
    FinishPendingInstructionIfNeeded();
    AddRawToContents(opcode, operands...);
    if (!match_previous_allowed_) {
      // Include this instruction in basis_instructions_ so that future
      // translations can check whether they match with it.
      DCHECK_EQ(basis_instructions_.size(),
                instruction_index_within_translation_);
      basis_instructions_.emplace_back(opcode, operands...);
    }
  }
  ++instruction_index_within_translation_;
}

Handle<DeoptimizationFrameTranslation>
FrameTranslationBuilder::ToFrameTranslation(LocalFactory* factory) {
#ifdef V8_USE_ZLIB
  if (V8_UNLIKELY(v8_flags.turbo_compress_frame_translations)) {
    const int input_size = SizeInBytes();
    uLongf compressed_data_size = compressBound(input_size);

    ZoneVector<uint8_t> compressed_data(compressed_data_size, zone());

    CHECK_EQ(
        zlib_internal::CompressHelper(
            zlib_internal::ZRAW, compressed_data.data(), &compressed_data_size,
            reinterpret_cast<const Bytef*>(contents_for_compression_.data()),
            input_size, Z_DEFAULT_COMPRESSION, nullptr, nullptr),
        Z_OK);

    const int translation_array_size =
        static_cast<int>(compressed_data_size) +
        DeoptimizationFrameTranslation::kUncompressedSizeSize;
    Handle<DeoptimizationFrameTranslation> result =
        factory->NewDeoptimizationFrameTranslation(translation_array_size);

    result->set_int(DeoptimizationFrameTranslation::kUncompressedSizeOffset,
                    Size());
    std::memcpy(
        result->begin() + DeoptimizationFrameTranslation::kCompressedDataOffset,
        compressed_data.data(), compressed_data_size);

    return result;
  }
#endif
  DCHECK(!v8_flags.turbo_compress_frame_translations);
  FinishPendingInstructionIfNeeded();
  Handle<DeoptimizationFrameTranslation> result =
      factory->NewDeoptimizationFrameTranslation(SizeInBytes());
  if (SizeInBytes() == 0) return result;
  memcpy(result->begin(), contents_.data(), contents_.size() * sizeof(uint8_t));
#ifdef ENABLE_SLOW_DCHECKS
  DeoptimizationFrameTranslation::Iterator iter(*result, 0);
  ValidateBytes(iter);
#endif
  return result;
}

base::Vector<const uint8_t> FrameTranslationBuilder::ToFrameTranslationWasm() {
  DCHECK(!v8_flags.turbo_compress_frame_translations);
  FinishPendingInstructionIfNeeded();
  base::Vector<const uint8_t> result = base::VectorOf(contents_);
#ifdef ENABLE_SLOW_DCHECKS
  DeoptTranslationIterator iter(result, 0);
  ValidateBytes(iter);
#endif
  return result;
}

void FrameTranslationBuilder::ValidateBytes(
    DeoptTranslationIterator& iter) const {
#ifdef ENABLE_SLOW_DCHECKS
  if (v8_flags.enable_slow_asserts) {
    // Check that we can read back all of the same content we intended to write.
    for (size_t i = 0; i < all_instructions_.size(); ++i) {
      CHECK(iter.HasNextOpcode());
      const Instruction& instruction = all_instructions_[i];
      CHECK_EQ(instruction.opcode, iter.NextOpcode());
      for (int j = 0; j < TranslationOpcodeOperandCount(instruction.opcode);
           ++j) {
        uint32_t operand = instruction.is_operand_signed[j]
                               ? iter.NextOperand()
                               : iter.NextOperandUnsigned();
        CHECK_EQ(instruction.operands[j], operand);
      }
    }
  }
#endif
}

void FrameTranslationBuilder::BeginBuiltinContinuationFrame(
    BytecodeOffset bytecode_offset, int literal_id, unsigned height) {
  auto opcode = TranslationOpcode::BUILTIN_CONTINUATION_FRAME;
  Add(opcode, SignedOperand(bytecode_offset.ToInt()), SignedOperand(literal_id),
      UnsignedOperand(height));
}

#if V8_ENABLE_WEBASSEMBLY
void FrameTranslationBuilder::BeginJSToWasmBuiltinContinuationFrame(
    BytecodeOffset bytecode_offset, int literal_id, unsigned height,
    std::optional<wasm::ValueKind> return_kind) {
  auto opcode = TranslationOpcode::JS_TO_WASM_BUILTIN_CONTINUATION_FRAME;
  Add(opcode, SignedOperand(bytecode_offset.ToInt()), SignedOperand(literal_id),
      UnsignedOperand(height),
      SignedOperand(return_kind ? static_cast<int>(return_kind.value())
                                : kNoWasmReturnKind));
}

void FrameTranslationBuilder::BeginWasmInlinedIntoJSFrame(
    BytecodeOffset bailout_id, int literal_id, unsigned height) {
  auto opcode = TranslationOpcode::WASM_INLINED_INTO_JS_FRAME;
  Add(opcode, SignedOperand(bailout_id.ToInt()), SignedOperand(literal_id),
      UnsignedOperand(height));
}

void FrameTranslationBuilder::BeginLiftoffFrame(BytecodeOffset bailout_id,
                                                unsigned height,
                                                uint32_t wasm_function_index) {
  auto opcode = TranslationOpcode::LIFTOFF_FRAME;
  Add(opcode, SignedOperand(bailout_id.ToInt()), UnsignedOperand(height),
      UnsignedOperand(wasm_function_index));
}
#endif  // V8_ENABLE_WEBASSEMBLY

void FrameTranslationBuilder::BeginJavaScriptBuiltinContinuationFrame(
    BytecodeOffset bytecode_offset, int literal_id, unsigned height) {
  auto opcode = TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_FRAME;
  Add(opcode, SignedOperand(bytecode_offset.ToInt()), SignedOperand(literal_id),
      UnsignedOperand(height));
}

void FrameTranslationBuilder::BeginJavaScriptBuiltinContinuationWithCatchFrame(
    BytecodeOffset bytecode_offset, int literal_id, unsigned height) {
  auto opcode =
      TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH_FRAME;
  Add(opcode, SignedOperand(bytecode_offset.ToInt()), SignedOperand(literal_id),
      UnsignedOperand(height));
}

void FrameTranslationBuilder::BeginConstructCreateStubFrame(int literal_id,
                                                            unsigned height) {
  auto opcode = TranslationOpcode::CONSTRUCT_CREATE_STUB_FRAME;
  Add(opcode, SignedOperand(literal_id), UnsignedOperand(height));
}

void FrameTranslationBuilder::BeginConstructInvokeStubFrame(int literal_id) {
  auto opcode = TranslationOpcode::CONSTRUCT_INVOKE_STUB_FRAME;
  Add(opcode, SignedOperand(literal_id));
}

void FrameTranslationBuilder::BeginInlinedExtraArguments(int literal_id,
                                                         unsigned height) {
  auto opcode = TranslationOpcode::INLINED_EXTRA_ARGUMENTS;
  Add(opcode, SignedOperand(literal_id), UnsignedOperand(height));
}

void FrameTranslationBuilder::BeginInterpretedFrame(
    BytecodeOffset bytecode_offset, int literal_id, int bytecode_array_id,
    unsigned height, int return_value_offset, int return_value_count) {
  if (return_value_count == 0) {
    auto opcode = TranslationOpcode::INTERPRETED_FRAME_WITHOUT_RETURN;
    Add(opcode, SignedOperand(bytecode_offset.ToInt()),
        SignedOperand(literal_id), SignedOperand(bytecode_array_id),
        UnsignedOperand(height));
  } else {
    auto opcode = TranslationOpcode::INTERPRETED_FRAME_WITH_RETURN;
    Add(opcode, SignedOperand(bytecode_offset.ToInt()),
        SignedOperand(literal_id), SignedOperand(bytecode_array_id),
        UnsignedOperand(height), SignedOperand(return_value_offset),
        SignedOperand(return_value_count));
  }
}

void FrameTranslationBuilder::ArgumentsElements(CreateArgumentsType type) {
  auto opcode = TranslationOpcode::ARGUMENTS_ELEMENTS;
  Add(opcode, SignedOperand(static_cast<uint8_t>(type)));
}

void FrameTranslationBuilder::ArgumentsLength() {
  auto opcode = TranslationOpcode::ARGUMENTS_LENGTH;
  Add(opcode);
}

void FrameTranslationBuilder::RestLength() {
  auto opcode = TranslationOpcode::REST_LENGTH;
  Add(opcode);
}

void FrameTranslationBuilder::BeginCapturedObject(int length) {
  auto opcode = TranslationOpcode::CAPTURED_OBJECT;
  Add(opcode, SignedOperand(length));
}

void FrameTranslationBuilder::DuplicateObject(int object_index) {
  auto opcode = TranslationOpcode::DUPLICATED_OBJECT;
  Add(opcode, SignedOperand(object_index));
}

void FrameTranslationBuilder::StringConcat() {
  auto opcode = TranslationOpcode::STRING_CONCAT;
  Add(opcode);
}

void FrameTranslationBuilder::StoreRegister(TranslationOpcode opcode,
                                            Register reg) {
  static_assert(Register::kNumRegisters - 1 <= base::kDataMask);
  Add(opcode, SmallUnsignedOperand(static_cast<uint8_t>(reg.code())));
}

void FrameTranslationBuilder::StoreRegister(Register reg) {
  auto opcode = TranslationOpcode::REGISTER;
  StoreRegister(opcode, reg);
}

void FrameTranslationBuilder::StoreInt32Register(Register reg) {
  auto opcode = TranslationOpcode::INT32_REGISTER;
  StoreRegister(opcode, reg);
}

void FrameTranslationBuilder::StoreInt64Register(Register reg) {
  auto opcode = TranslationOpcode::INT64_REGISTER;
  StoreRegister(opcode, reg);
}

void FrameTranslationBuilder::StoreSignedBigInt64Register(Register reg) {
  auto opcode = TranslationOpcode::SIGNED_BIGINT64_REGISTER;
  StoreRegister(opcode, reg);
}

void FrameTranslationBuilder::StoreUnsignedBigInt64Register(Register reg) {
  auto opcode = TranslationOpcode::UNSIGNED_BIGINT64_REGISTER;
  StoreRegister(opcode, reg);
}

void FrameTranslationBuilder::StoreUint32Register(Register reg) {
  auto opcode = TranslationOpcode::UINT32_REGISTER;
  StoreRegister(opcode, reg);
}

void FrameTranslationBuilder::StoreBoolRegister(Register reg) {
  auto opcode = TranslationOpcode::BOOL_REGISTER;
  StoreRegister(opcode, reg);
}

void FrameTranslationBuilder::StoreFloatRegister(FloatRegister reg) {
  static_assert(FloatRegister::kNumRegisters - 1 <= base::kDataMask);
  auto opcode = TranslationOpcode::FLOAT_REGISTER;
  Add(opcode, SmallUnsignedOperand(static_cast<uint8_t>(reg.code())));
}

void FrameTranslationBuilder::StoreDoubleRegister(DoubleRegister reg) {
  static_assert(DoubleRegister::kNumRegisters - 1 <= base::kDataMask);
  auto opcode = TranslationOpcode::DOUBLE_REGISTER;
  Add(opcode, SmallUnsignedOperand(static_cast<uint8_t>(reg.code())));
}

void FrameTranslationBuilder::StoreHoleyDoubleRegister(DoubleRegister reg) {
  static_assert(DoubleRegister::kNumRegisters - 1 <= base::kDataMask);
  auto opcode = TranslationOpcode::HOLEY_DOUBLE_REGISTER;
  Add(opcode, SmallUnsignedOperand(static_cast<uint8_t>(reg.code())));
}

void FrameTranslationBuilder::StoreSimd128Register(Simd128Register reg) {
  static_assert(DoubleRegister::kNumRegisters - 1 <= base::kDataMask);
  auto opcode = TranslationOpcode::SIMD128_REGISTER;
  Add(opcode, SmallUnsignedOperand(static_cast<uint8_t>(reg.code())));
}

void FrameTranslationBuilder::StoreStackSlot(int index) {
  auto opcode = TranslationOpcode::TAGGED_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreInt32StackSlot(int index) {
  auto opcode = TranslationOpcode::INT32_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreInt64StackSlot(int index) {
  auto opcode = TranslationOpcode::INT64_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreSignedBigInt64StackSlot(int index) {
  auto opcode = TranslationOpcode::SIGNED_BIGINT64_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreUnsignedBigInt64StackSlot(int index) {
  auto opcode = TranslationOpcode::UNSIGNED_BIGINT64_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreUint32StackSlot(int index) {
  auto opcode = TranslationOpcode::UINT32_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreBoolStackSlot(int index) {
  auto opcode = TranslationOpcode::BOOL_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreFloatStackSlot(int index) {
  auto opcode = TranslationOpcode::FLOAT_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreDoubleStackSlot(int index) {
  auto opcode = TranslationOpcode::DOUBLE_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreSimd128StackSlot(int index) {
  auto opcode = TranslationOpcode::SIMD128_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreHoleyDoubleStackSlot(int index) {
  auto opcode = TranslationOpcode::HOLEY_DOUBLE_STACK_SLOT;
  Add(opcode, SignedOperand(index));
}

void FrameTranslationBuilder::StoreLiteral(int literal_id) {
  auto opcode = TranslationOpcode::LITERAL;
  DCHECK_GE(literal_id, 0);
  Add(opcode, SignedOperand(literal_id));
}

void FrameTranslationBuilder::StoreOptimizedOut() {
  auto opcode = TranslationOpcode::OPTIMIZED_OUT;
  Add(opcode);
}

void FrameTranslationBuilder::AddUpdateFeedback(int vector_literal, int slot) {
  auto opcode = TranslationOpcode::UPDATE_FEEDBACK;
  Add(opcode, SignedOperand(vector_literal), SignedOperand(slot));
}

void FrameTranslationBuilder::StoreJSFrameFunction() {
  StoreStackSlot((StandardFrameConstants::kCallerPCOffset -
                  StandardFrameConstants::kFunctionOffset) /
                 kSystemPointerSize);
}

}  // namespace internal
}  // namespace v8
```