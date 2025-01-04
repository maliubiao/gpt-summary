Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

**1. Understanding the Goal:**

The core request is to understand the functionality of `frame-translation-builder.cc` and relate it to JavaScript. This means figuring out *what* it does and *why* it exists within the V8 (JavaScript engine) context.

**2. Initial Code Scan - Identifying Key Areas:**

A quick skim reveals several important elements:

* **Includes:** `#include` statements hint at dependencies and functionalities. `deoptimizer/translated-state.h` and `objects/fixed-array-inl.h` are particularly relevant as they suggest interaction with V8's internal object model and the deoptimization process.
* **Namespaces:** `v8::internal` indicates this code is part of V8's internal implementation, not exposed directly to JavaScript developers.
* **Operand Classes:**  `OperandBase`, `SmallUnsignedOperand`, `UnsignedOperand`, `SignedOperand` suggest a mechanism for encoding and handling different types of data. The `WriteVLQ` methods point to Variable Length Quantity encoding, a common technique for efficient data serialization.
* **`FrameTranslationBuilder` Class:** This is the central class. Its methods like `BeginTranslation`, `Add`, `ToFrameTranslation`, and methods starting with `Begin...Frame` and `Store...` are strong indicators of its purpose.
* **`TranslationOpcode`:** The repeated use of `TranslationOpcode` and functions like `TranslationOpcodeOperandCount` suggests an enumeration or structure defining different translation operations.
* **Compression (`V8_USE_ZLIB`, `turbo_compress_frame_translations`):**  The presence of compression logic indicates a concern for data size and efficiency.
* **`DeoptimizationFrameTranslation`:** This type is returned by `ToFrameTranslation`, directly linking this code to the deoptimization process.
* **`ENABLE_SLOW_DCHECKS`:**  Conditional compilation for debugging and assertions suggests this code is performance-sensitive and requires careful validation.

**3. Deduction - Connecting the Dots:**

Based on the identified elements, I start forming hypotheses:

* **Deoptimization:** The filename and the interaction with `DeoptimizationFrameTranslation` strongly suggest this code is involved in the *reverse* process of optimization. When optimized code needs to fall back to a less optimized version (due to type mismatches or other reasons), V8 needs to reconstruct the state of the program.
* **Frame Translation:** The name "FrameTranslationBuilder" implies it's responsible for creating a representation of the call stack frames at the point of deoptimization.
* **Data Encoding:** The operand classes and VLQ encoding suggest a way to efficiently serialize the information about each frame. This likely includes things like program counters, register values, and stack slot contents.
* **Opcodes:** The `TranslationOpcode` likely defines different instructions for recording the state of various components of a frame (registers, stack slots, literals, etc.).
* **Optimization and Re-Optimization:** The compression and the logic around `match_previous_allowed_` and basis translations hints at an attempt to optimize the storage of frame translation data, potentially by reusing information from previous translations.

**4. Focusing on the `FrameTranslationBuilder` Methods:**

I examine the key methods in more detail:

* **`BeginTranslation`:** This method seems to initiate the process of building a frame translation for a sequence of frames. The logic about reusing basis translations becomes clearer – it's an optimization to avoid redundant data.
* **`Add`:**  This is the workhorse method. It takes an opcode and operands, encoding them into the internal buffer. The logic for checking against `basis_instructions_` reinforces the optimization hypothesis.
* **`ToFrameTranslation`:** This method finalizes the translation process, potentially compressing the data and creating the `DeoptimizationFrameTranslation` object.
* **`Begin...Frame` methods:** These methods correspond to different types of frames (interpreted, built-in continuations, etc.). They use the `Add` method with specific opcodes.
* **`Store...` methods:** These methods handle storing the values of registers and stack slots, each with its corresponding opcode.

**5. Relating to JavaScript:**

Now, the crucial step: how does this internal C++ code relate to the JavaScript developer?

* **Deoptimization as the Key Link:**  Deoptimization is a direct consequence of V8's optimization strategy. JavaScript code is initially interpreted, then potentially compiled and optimized. When assumptions made during optimization are invalidated, deoptimization happens.
* **Reconstructing State:** The `FrameTranslationBuilder` helps V8 reconstruct the JavaScript execution context when deoptimizing. This involves knowing the values of variables, the current position in the code, and the call stack.
* **Illustrative Examples:** To make this connection concrete, I need to provide JavaScript code snippets that *cause* deoptimization. Common scenarios include:
    * **Type Changes:**  Assigning values of different types to the same variable.
    * **Hidden Classes:**  Dynamically adding properties to objects in ways that invalidate optimized object structures.
    * **`arguments` Object:** Using the `arguments` object can sometimes hinder optimization.
    * **Try-Catch Blocks:**  Optimizations around try-catch blocks can sometimes lead to deoptimization.

**6. Structuring the Explanation:**

Finally, I organize the findings into a clear and concise summary:

* **Core Function:**  State the primary purpose of the class.
* **Mechanism:** Explain how it achieves this (opcodes, operands, encoding).
* **Relationship to Deoptimization:** Emphasize the crucial role in the deoptimization process.
* **JavaScript Connection:**  Explain *why* this matters for JavaScript and provide concrete examples of JavaScript code that triggers the underlying mechanisms this C++ code supports.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the low-level details of VLQ encoding. I need to step back and emphasize the higher-level purpose.
* I need to ensure the JavaScript examples are clear and directly illustrate the *causes* of deoptimization. Vague examples are not helpful.
* It's important to highlight that this is internal V8 code and not directly accessible to JavaScript developers. The impact is indirect, affecting performance and debugging.

By following these steps, combining code analysis with an understanding of V8's architecture and the JavaScript execution model, I can arrive at a comprehensive and helpful explanation.
这个C++源代码文件 `frame-translation-builder.cc` 的主要功能是构建**帧转换信息 (Frame Translation)**，用于**反优化 (Deoptimization)** 过程。

**具体来说，它的作用是：**

1. **记录优化代码执行时的状态：** 当V8的TurboFan等优化编译器将JavaScript代码编译成高度优化的机器码时，它会进行各种假设和优化。如果这些假设在运行时失效，就需要进行反优化，即回退到解释执行的状态。为了能够正确地回退，V8需要在优化代码执行的特定点记录下程序的状态，包括：
    * **寄存器的值:**  各个通用寄存器和浮点寄存器中存储的值。
    * **栈上的值:**  局部变量、函数参数等存储在栈上的位置和值。
    * **字面量:**  代码中使用的常量值。
    * **帧信息:**  当前调用栈的结构，例如函数调用关系、字节码偏移量等。
    * **反馈向量信息:** 用于后续优化的类型反馈信息。

2. **生成紧凑的帧转换数据：** `FrameTranslationBuilder` 负责将这些状态信息编码成一种紧凑的格式。它使用了以下技术来减少数据量：
    * **变长编码 (VLQ):**  对于数值类型的操作数，使用变长编码可以有效地压缩较小的数值。
    * **操作码 (Opcodes):**  定义了一系列操作码来表示不同类型的状态信息记录操作，例如存储寄存器、存储栈槽、开始一个新的帧等。
    * **匹配之前的翻译 (Match Previous Translation):**  为了进一步减少冗余，`FrameTranslationBuilder` 可以识别当前帧的翻译与之前某个帧的翻译是否相似。如果相似，它可以只记录与之前翻译的差异，而不是重新记录所有信息。这通过维护一个 `basis_instructions_` 来实现。
    * **可选的压缩 (Zlib):** 在开启特定编译选项后，可以对生成的帧转换数据进行进一步的压缩，以减少内存占用。

3. **为反优化器提供数据：** 生成的帧转换数据被存储在 `DeoptimizationFrameTranslation` 对象中。当需要进行反优化时，V8的反优化器会读取这些数据，并根据其中的指令恢复到解释执行所需的程序状态。

**与 JavaScript 的关系以及 JavaScript 举例说明：**

`FrameTranslationBuilder` 并不直接操作 JavaScript 代码，而是作为 V8 引擎内部的一个组件，服务于 JavaScript 代码的优化和反优化过程。它的存在使得 V8 能够在高性能的优化执行和必要的反优化回退之间平滑切换，从而保证 JavaScript 代码的正确执行。

**JavaScript 示例：**

以下 JavaScript 代码可能会触发优化和反优化，从而间接地使用到 `FrameTranslationBuilder` 生成的帧转换信息：

```javascript
function add(x, y) {
  return x + y;
}

// 初始调用，V8可能会进行优化
add(1, 2);

// 后续调用，传入不同类型的值，可能导致反优化
add("hello", "world");
```

**解释：**

1. 当第一次调用 `add(1, 2)` 时，V8 的优化编译器可能会根据传入的参数类型（数字）将 `add` 函数编译成优化的机器码，并假设 `x` 和 `y` 始终是数字。

2. 当第二次调用 `add("hello", "world")` 时，传入的参数类型变成了字符串，这违反了优化器之前的假设。此时，V8 需要进行反优化，将程序的执行状态回退到 `add` 函数开始执行之前的某个状态，然后以解释执行的方式继续运行。

3. 在反优化过程中，`FrameTranslationBuilder` 在之前优化 `add` 函数时生成的帧转换信息就派上了用场。反优化器会读取这些信息，从中提取出寄存器和栈上的值，以及当时的程序执行点等信息，从而正确地恢复执行环境。

**更复杂的反优化场景可能涉及：**

* **类型突变 (Type Mismatch):**  变量的类型在运行时发生改变。
* **去优化标记 (Deoptimization Bailout):**  优化代码中遇到无法高效处理的情况，主动触发反优化。
* **内联失败 (Inlining Failure):**  优化器尝试将一个函数调用内联到调用者中，但后续执行时条件不满足，需要回退。

**总结：**

`FrameTranslationBuilder` 是 V8 引擎中一个关键的内部组件，它负责记录和编码优化代码执行时的状态信息，以便在需要进行反优化时能够正确地恢复程序的执行环境。虽然 JavaScript 开发者不能直接访问或操作这个类，但它的工作直接影响着 JavaScript 代码的性能和执行的稳定性。理解其功能有助于更好地理解 V8 引擎的内部工作原理。

Prompt: 
```
这是目录为v8/src/deoptimizer/frame-translation-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```