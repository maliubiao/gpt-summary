Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan and Identification of Key Structures:**  The first step is a quick read-through to identify the major classes and enums. I see `TranslatedValue`, `TranslatedFrame`, `DeoptimizationLiteralProvider`, and `TranslatedState`. These seem like the core components. The `#ifndef` and `#define` guard confirms it's a header file meant to prevent multiple inclusions.

2. **Understanding the Purpose from the Comments:** The leading comments are crucial. They explicitly state the purpose: "utility functions to work with the combination of translations (built from a DeoptimizationFrameTranslation) and the actual current CPU state (represented by RegisterValues)."  This tells me it's about converting the optimized representation of the program state back to a more understandable form during deoptimization.

3. **Deconstructing Each Class/Structure:**

   * **`TranslatedValue`:**  The name suggests representing a single value. I look at its members and methods: `Kind` enum (tagged, int32, float, etc.), `MaterializationState` enum (uninitialized, allocated, finished), and various `New...` static methods. This indicates it represents a value that might need to be *materialized* (created as a real object in memory). The union confirms it holds different types of raw values. The `GetRawValue()` and `GetValue()` distinction hints at lazy materialization.

   * **`TranslatedFrame`:** This likely represents a single stack frame. The `Kind` enum lists different types of frames (unoptimized, inlined, builtins, wasm related). It has members like `bytecode_offset`, `shared_info`, `bytecode_array`, and a `values_` deque of `TranslatedValue` objects. This fits the idea of a frame containing metadata and the values held within that frame. The `iterator` suggests a way to access the values.

   * **`DeoptimizationLiteralProvider`:** This seems like a helper to access constant values ("literals") used during deoptimization. It can hold them either on the heap or off-heap.

   * **`TranslatedState`:** This appears to be the top-level structure, representing the *entire* stack state. It contains a `std::vector<TranslatedFrame>` called `frames_`. This confirms it represents a collection of stack frames. The constructors hint at different uses: deoptimization and frame inspection. Methods like `Prepare`, `StoreMaterializedValuesAndDeopt`, and `Init` suggest the main workflow of the class.

4. **Identifying Relationships:** The `friend` declarations clearly show relationships between the classes. `TranslatedValue` is a friend of `TranslatedState` and `TranslatedFrame`, suggesting they work closely together. `TranslatedState` seems to manage a collection of `TranslatedFrame` objects, and each `TranslatedFrame` manages a collection of `TranslatedValue` objects.

5. **Looking for Specific Clues:**

   * **"Deduplicate into one class" TODO:**  This comment in `DeoptimizationFrameTranslationPrintSingleOpcode` suggests potential areas for code improvement and refactoring.
   * **"Allocation-free getter" in `TranslatedValue::GetRawValue`:** This points to performance considerations.
   * **"Materializing it first" in `TranslatedValue::GetValue`:** This confirms the idea of lazy materialization.
   * **`#if V8_ENABLE_WEBASSEMBLY`:**  This indicates that some parts of the code are specific to WebAssembly support.

6. **Connecting to JavaScript Functionality (if applicable):** I consider how deoptimization relates to JavaScript. When optimized code makes assumptions that turn out to be incorrect, the JavaScript engine needs to revert to a slower, unoptimized version. `TranslatedState` is crucial in this process because it reconstructs the JavaScript state from the optimized representation.

7. **Considering Potential Errors:** Deoptimization happens when assumptions are violated. Common JavaScript errors that might lead to deoptimization include type inconsistencies, calling undefined methods, or accessing properties that don't exist.

8. **Formulating Examples (JavaScript and Hypothetical):**  Based on the understanding of the classes and their purpose, I can create JavaScript examples to illustrate scenarios where deoptimization might occur. For the hypothetical input/output, I focus on the data structures and how they might be populated during the deoptimization process.

9. **Structuring the Answer:** I organize the information into clear sections (Functionality, Torque, JavaScript Relation, Logic Reasoning, Common Errors) to make it easy to understand. I use bullet points and code formatting for better readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe `TranslatedState` directly holds the values."
* **Correction:** After seeing `TranslatedFrame` contain `values_`, I realize `TranslatedState` manages frames, which in turn manage values.

* **Initial thought:** "The `Kind` enums are just for internal type tracking."
* **Refinement:**  While true, they also play a role in how the values are materialized and interpreted during deoptimization.

* **Initially unsure:** How does this relate to the actual deoptimization process?
* **Clarification:** The comments and method names like `StoreMaterializedValuesAndDeopt` make it clear this is a key component in reconstructing the unoptimized state.

By following these steps, iteratively analyzing the code and comments, and making connections to the broader context of JavaScript execution and optimization, I can arrive at a comprehensive understanding of the header file's purpose and functionality.
好的，让我们来分析一下 `v8/src/deoptimizer/translated-state.h` 这个 V8 源代码文件。

**功能列表:**

这个头文件定义了一系列类和数据结构，用于在 V8 引擎的**反优化 (Deoptimization)** 过程中，表示和操作程序的状态。其核心功能是：

1. **表示优化代码执行前的状态:**  当一段被优化的代码需要回退到未优化状态时，`TranslatedState` 及其相关的类负责捕捉并表示优化代码执行前的各种信息，例如寄存器的值、栈帧的布局、变量的值等。

2. **翻译优化后的状态到未优化状态:**  它提供了一种机制，将优化后的代码执行状态（例如，存储在寄存器中的值）“翻译”回未优化代码所期望的状态（例如，存储在栈上的局部变量中）。

3. **处理不同类型的变量和值:**  `TranslatedValue` 类可以表示各种不同的 JavaScript 值类型，包括原始类型（数字、布尔值）、对象、字符串等等。它还处理了一些 V8 内部的特殊值，例如逃逸分析捕获的对象。

4. **管理栈帧信息:** `TranslatedFrame` 类表示未优化代码的一个栈帧，包含了该帧的元数据（例如，字节码偏移量、函数信息）以及该帧中变量的值。

5. **支持 WebAssembly:** 文件中包含 `#if V8_ENABLE_WEBASSEMBLY` 块，表明它也处理了 WebAssembly 代码的反优化场景。

6. **延迟物化 (Lazy Materialization):**  `TranslatedValue` 的设计允许延迟创建对象。只有在真正需要访问对象的内容时，才会将其物化到堆上，这有助于提高效率。

7. **提供迭代器:**  `TranslatedFrame` 提供了迭代器，方便遍历帧内的 `TranslatedValue` 对象。

8. **辅助调试和分析:**  这些类提供的结构化信息可以用于调试器和性能分析工具，帮助开发者理解代码在反优化时的状态。

**关于 `.tq` 结尾:**

如果 `v8/src/deoptimizer/translated-state.h` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**文件。Torque 是一种 V8 内部使用的类型化中间语言，用于生成高效的 C++ 代码。目前来看，该文件以 `.h` 结尾，是一个 C++ 头文件。

**与 JavaScript 功能的关系 (及 JavaScript 示例):**

`TranslatedState` 直接关联着 V8 引擎的优化和反优化机制，而这对于 JavaScript 代码的执行至关重要。当 V8 的优化编译器（例如 TurboFan）对 JavaScript 代码进行优化后，会生成更高效的机器码。然而，优化是基于一些假设的，当这些假设在运行时被打破时，就需要进行反优化，退回到解释执行或者更基础的编译代码。

`TranslatedState` 在反优化过程中扮演着核心角色，它确保了程序状态能够平滑地从优化状态过渡到未优化状态，从而保证 JavaScript 代码的正确执行。

**JavaScript 示例（说明可能触发反优化的场景）:**

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，V8 可能会假设 a 和 b 都是数字
add(1, 2); // 输出 3

// 后续调用，如果传入非数字类型，可能触发反优化
add("hello", "world"); // 输出 "helloworld"

add(1, {}); //  加法运算会调用对象的 toString() 方法，也可能触发反优化
```

在这个例子中，`add` 函数最初被调用时，V8 可能会优化它，假设 `a` 和 `b` 总是数字类型。如果后续调用传入了字符串或对象，V8 发现之前的假设不再成立，就会触发反优化。`TranslatedState` 将会记录优化代码执行到反优化点时的状态，并帮助恢复到未优化状态，以便正确执行后续的代码。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的函数被优化了，然后在运行时触发了反优化。

**假设输入:**

* **优化代码执行到的位置:**  函数 `add` 内部，即将执行加法操作。
* **寄存器状态:** 假设寄存器 `R1` 存储了变量 `a` 的值 (数字 `1`)，寄存器 `R2` 存储了变量 `b` 的值 (字符串 `"world"`)。
* **反优化数据:**  包含了如何将优化状态映射回未优化状态的信息。

**TranslatedState 的可能输出 (简化描述):**

`TranslatedState` 对象会包含一个 `TranslatedFrame` 对象，表示 `add` 函数的栈帧。这个 `TranslatedFrame` 对象会包含以下 `TranslatedValue` 对象：

* 一个 `TranslatedValue` 对象表示局部变量 `a`，其值为数字 `1`。
* 一个 `TranslatedValue` 对象表示局部变量 `b`，其值为字符串 `"world"`。
* 其他可能的 `TranslatedValue` 对象，表示中间计算结果或 V8 内部状态。

**用户常见的编程错误 (可能导致反优化):**

1. **类型不一致:**  如上面的例子所示，对变量的类型做出假设，然后在运行时违反这些假设。

   ```javascript
   function process(input) {
     return input.toUpperCase(); // 假设 input 是字符串
   }

   process("hello");
   process(123); // 运行时错误，因为数字没有 toUpperCase 方法，可能导致反优化
   ```

2. **访问未定义的属性:**  访问对象上不存在的属性。

   ```javascript
   const obj = { name: "Alice" };
   console.log(obj.age); // age 属性未定义，可能导致优化后的代码出现问题并触发反优化
   ```

3. **在循环中修改对象的形状 (Hidden Classes):** V8 的对象有隐藏类 (Hidden Classes) 来优化属性访问。在循环中动态添加或删除对象的属性会导致隐藏类频繁变化，可能触发反优化。

   ```javascript
   function modifyObject(obj) {
     for (let i = 0; i < 10; i++) {
       obj['prop' + i] = i; // 动态添加属性
     }
     return obj;
   }

   const myObj = {};
   modifyObject(myObj); // 可能会导致 myObj 的隐藏类发生多次变化
   ```

4. **使用 `arguments` 对象:**  在现代 JavaScript 中，使用剩余参数 (`...args`) 通常比 `arguments` 对象更利于优化。`arguments` 对象的某些特性（例如它可以被修改）使得优化变得困难。

**总结:**

`v8/src/deoptimizer/translated-state.h` 定义的类是 V8 引擎反优化机制的关键组成部分。它们负责捕获、表示和转换程序状态，确保在优化假设失效时，JavaScript 代码能够安全地回退到未优化状态继续执行。理解这些类的功能有助于深入了解 V8 的内部工作原理以及优化和反优化过程。

### 提示词
```
这是目录为v8/src/deoptimizer/translated-state.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/deoptimizer/translated-state.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_DEOPTIMIZER_TRANSLATED_STATE_H_
#define V8_DEOPTIMIZER_TRANSLATED_STATE_H_

#include <optional>
#include <stack>
#include <vector>

#include "src/common/simd128.h"
#include "src/deoptimizer/frame-translation-builder.h"
#include "src/objects/deoptimization-data.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/heap-object.h"
#include "src/objects/shared-function-info.h"
#include "src/utils/boxed-float.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/value-type.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

class DeoptimizationLiteral;
class RegisterValues;
class TranslatedState;

// TODO(jgruber): This duplicates decoding logic already present in
// TranslatedState/TranslatedFrame. Deduplicate into one class, e.g. by basing
// printing off TranslatedFrame.
void DeoptimizationFrameTranslationPrintSingleOpcode(
    std::ostream& os, TranslationOpcode opcode,
    DeoptimizationFrameTranslation::Iterator& iterator,
    Tagged<ProtectedDeoptimizationLiteralArray> protected_literal_array,
    Tagged<DeoptimizationLiteralArray> literal_array);

// The Translated{Value,Frame,State} class hierarchy are a set of utility
// functions to work with the combination of translations (built from a
// DeoptimizationFrameTranslation) and the actual current CPU state (represented
// by RegisterValues).
//
// TranslatedState: describes the entire stack state of the current optimized
// frame, contains:
//
// TranslatedFrame: describes a single unoptimized frame, contains:
//
// TranslatedValue: the actual value of some location.

class TranslatedValue {
 public:
  // Allocation-free getter of the value.
  // Returns ReadOnlyRoots::arguments_marker() if allocation would be necessary
  // to get the value. In the case of numbers, returns a Smi if possible.
  Tagged<Object> GetRawValue() const;

  // Convenience wrapper around GetRawValue (checked).
  int GetSmiValue() const;

  // Returns the value, possibly materializing it first (and the whole subgraph
  // reachable from this value). In the case of numbers, returns a Smi if
  // possible.
  Handle<Object> GetValue();

  bool IsMaterializedObject() const;
  bool IsMaterializableByDebugger() const;

 private:
  friend class TranslatedState;
  friend class TranslatedFrame;
  friend class Deoptimizer;
  friend class DeoptimizationLiteralProvider;

  enum Kind : uint8_t {
    kInvalid,
    kTagged,
    kInt32,
    kInt64,
    kInt64ToBigInt,
    kUint64ToBigInt,
    kUint32,
    kUint64,
    kBoolBit,
    kFloat,
    kDouble,
    kHoleyDouble,
    kSimd128,
    kCapturedObject,    // Object captured by the escape analysis.
                        // The number of nested objects can be obtained
                        // with the DeferredObjectLength() method
                        // (the values of the nested objects follow
                        // this value in the depth-first order.)
    kDuplicatedObject,  // Duplicated object of a deferred object.
    kCapturedStringConcat
  };

  enum MaterializationState : uint8_t {
    kUninitialized,
    kAllocated,  // Storage for the object has been allocated (or
                 // enqueued for allocation).
    kFinished,   // The object has been initialized (or enqueued for
                 // initialization).
  };

  TranslatedValue(TranslatedState* container, Kind kind)
      : kind_(kind), container_(container) {}
  Kind kind() const { return kind_; }
  MaterializationState materialization_state() const {
    return materialization_state_;
  }
  void Handlify();
  int GetChildrenCount() const;

  static TranslatedValue NewDeferredObject(TranslatedState* container,
                                           int length, int object_index);
  static TranslatedValue NewDuplicateObject(TranslatedState* container, int id);
  static TranslatedValue NewStringConcat(TranslatedState* container, int id);
  static TranslatedValue NewFloat(TranslatedState* container, Float32 value);
  static TranslatedValue NewDouble(TranslatedState* container, Float64 value);
  static TranslatedValue NewHoleyDouble(TranslatedState* container,
                                        Float64 value);
  static TranslatedValue NewSimd128(TranslatedState* container, Simd128 value);
  static TranslatedValue NewInt32(TranslatedState* container, int32_t value);
  static TranslatedValue NewInt64(TranslatedState* container, int64_t value);
  static TranslatedValue NewInt64ToBigInt(TranslatedState* container,
                                          int64_t value);
  static TranslatedValue NewUint64ToBigInt(TranslatedState* container,
                                           uint64_t value);
  static TranslatedValue NewUint32(TranslatedState* container, uint32_t value);
  static TranslatedValue NewUint64(TranslatedState* container, uint64_t value);
  static TranslatedValue NewBool(TranslatedState* container, uint32_t value);
  static TranslatedValue NewTagged(TranslatedState* container,
                                   Tagged<Object> literal);
  static TranslatedValue NewInvalid(TranslatedState* container);

  Isolate* isolate() const;

  void set_storage(Handle<HeapObject> storage) { storage_ = storage; }
  void set_initialized_storage(Handle<HeapObject> storage);
  void mark_finished() { materialization_state_ = kFinished; }
  void mark_allocated() { materialization_state_ = kAllocated; }

  Handle<HeapObject> storage() {
    DCHECK_NE(materialization_state(), kUninitialized);
    return storage_;
  }

  void ReplaceElementsArrayWithCopy();

  Kind kind_;
  MaterializationState materialization_state_ = kUninitialized;
  TranslatedState* container_;  // This is only needed for materialization of
                                // objects and constructing handles (to get
                                // to the isolate).

  Handle<HeapObject> storage_;  // Contains the materialized value or the
                                // byte-array that will be later morphed into
                                // the materialized object.

  struct MaterializedObjectInfo {
    int id_;
    int length_;  // Applies only to kCapturedObject kinds.
  };

  union {
    // kind kTagged. After handlification it is always nullptr.
    Tagged<Object> raw_literal_;
    // kind is kUInt32 or kBoolBit.
    uint32_t uint32_value_;
    // kind is kInt32.
    int32_t int32_value_;
    // kind is kUint64ToBigInt.
    uint64_t uint64_value_;
    // kind is kInt64 or kInt64ToBigInt.
    int64_t int64_value_;
    // kind is kFloat
    Float32 float_value_;
    // kind is kDouble or kHoleyDouble
    Float64 double_value_;
    // kind is kDuplicatedObject or kCapturedObject.
    MaterializedObjectInfo materialization_info_;
    // kind is kSimd128.
    Simd128 simd128_value_;
  };

  // Checked accessors for the union members.
  Tagged<Object> raw_literal() const;
  int32_t int32_value() const;
  int64_t int64_value() const;
  uint32_t uint32_value() const;
  uint64_t uint64_value() const;
  Float32 float_value() const;
  Float64 double_value() const;
  Simd128 simd_value() const;
  int object_length() const;
  int object_index() const;
  // TODO(dmercadier): use object_index instead of string_concat_index.
  int string_concat_index() const;
};

class TranslatedFrame {
 public:
  enum Kind {
    kUnoptimizedFunction,
    kInlinedExtraArguments,
    kConstructCreateStub,
    kConstructInvokeStub,
    kBuiltinContinuation,
#if V8_ENABLE_WEBASSEMBLY
    kWasmInlinedIntoJS,
    kJSToWasmBuiltinContinuation,
    kLiftoffFunction,
#endif  // V8_ENABLE_WEBASSEMBLY
    kJavaScriptBuiltinContinuation,
    kJavaScriptBuiltinContinuationWithCatch,
    kInvalid
  };

  int GetValueCount() const;

  Kind kind() const { return kind_; }
  BytecodeOffset bytecode_offset() const { return bytecode_offset_; }
  Handle<SharedFunctionInfo> shared_info() const {
    CHECK_EQ(handle_state_, kHandles);
    return shared_info_;
  }
  Handle<BytecodeArray> bytecode_array() const {
    CHECK_EQ(handle_state_, kHandles);
    return bytecode_array_;
  }

  // TODO(jgruber): Simplify/clarify the semantics of this field. The name
  // `height` is slightly misleading. Yes, this value is related to stack frame
  // height, but must undergo additional mutations to arrive at the real stack
  // frame height (e.g.: addition/subtraction of context, accumulator, fixed
  // frame sizes, padding).
  uint32_t height() const { return height_; }

  int return_value_offset() const { return return_value_offset_; }
  int return_value_count() const { return return_value_count_; }

  Tagged<SharedFunctionInfo> raw_shared_info() const {
    CHECK_EQ(handle_state_, kRawPointers);
    CHECK(!raw_shared_info_.is_null());
    return raw_shared_info_;
  }

  Tagged<BytecodeArray> raw_bytecode_array() const {
    CHECK_EQ(handle_state_, kRawPointers);
    CHECK(!raw_bytecode_array_.is_null());
    return raw_bytecode_array_;
  }

  class iterator {
   public:
    iterator& operator++() {
      ++input_index_;
      AdvanceIterator(&position_);
      return *this;
    }

    iterator operator++(int) {
      iterator original(position_, input_index_);
      ++input_index_;
      AdvanceIterator(&position_);
      return original;
    }

    bool operator==(const iterator& other) const {
      // Ignore {input_index_} for equality.
      return position_ == other.position_;
    }
    bool operator!=(const iterator& other) const { return !(*this == other); }

    TranslatedValue& operator*() { return (*position_); }
    TranslatedValue* operator->() { return &(*position_); }
    const TranslatedValue& operator*() const { return (*position_); }
    const TranslatedValue* operator->() const { return &(*position_); }

    int input_index() const { return input_index_; }

   private:
    friend TranslatedFrame;

    explicit iterator(std::deque<TranslatedValue>::iterator position,
                      int input_index = 0)
        : position_(position), input_index_(input_index) {}

    std::deque<TranslatedValue>::iterator position_;
    int input_index_;
  };

  using reference = TranslatedValue&;
  using const_reference = TranslatedValue const&;

  iterator begin() { return iterator(values_.begin()); }
  iterator end() { return iterator(values_.end()); }

  reference front() { return values_.front(); }
  const_reference front() const { return values_.front(); }

#if V8_ENABLE_WEBASSEMBLY
  // Only for Kind == kJSToWasmBuiltinContinuation
  std::optional<wasm::ValueKind> wasm_call_return_kind() const {
    DCHECK_EQ(kind(), kJSToWasmBuiltinContinuation);
    return return_kind_;
  }

  int wasm_function_index() const {
    DCHECK_EQ(kind(), kLiftoffFunction);
    return wasm_function_index_;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

 private:
  friend class TranslatedState;
  friend class Deoptimizer;

  // Constructor static methods.
  static TranslatedFrame UnoptimizedJSFrame(
      BytecodeOffset bytecode_offset, Tagged<SharedFunctionInfo> shared_info,
      Tagged<BytecodeArray> bytecode_array, uint32_t height,
      int return_value_offset, int return_value_count);
  static TranslatedFrame AccessorFrame(Kind kind,
                                       Tagged<SharedFunctionInfo> shared_info);
  static TranslatedFrame InlinedExtraArguments(
      Tagged<SharedFunctionInfo> shared_info, uint32_t height);
  static TranslatedFrame ConstructCreateStubFrame(
      Tagged<SharedFunctionInfo> shared_info, uint32_t height);
  static TranslatedFrame ConstructInvokeStubFrame(
      Tagged<SharedFunctionInfo> shared_info);
  static TranslatedFrame BuiltinContinuationFrame(
      BytecodeOffset bailout_id, Tagged<SharedFunctionInfo> shared_info,
      uint32_t height);
#if V8_ENABLE_WEBASSEMBLY
  static TranslatedFrame WasmInlinedIntoJSFrame(
      BytecodeOffset bailout_id, Tagged<SharedFunctionInfo> shared_info,
      uint32_t height);
  static TranslatedFrame JSToWasmBuiltinContinuationFrame(
      BytecodeOffset bailout_id, Tagged<SharedFunctionInfo> shared_info,
      uint32_t height, std::optional<wasm::ValueKind> return_type);
  static TranslatedFrame LiftoffFrame(BytecodeOffset bailout_id,
                                      uint32_t height, uint32_t function_index);
#endif  // V8_ENABLE_WEBASSEMBLY
  static TranslatedFrame JavaScriptBuiltinContinuationFrame(
      BytecodeOffset bailout_id, Tagged<SharedFunctionInfo> shared_info,
      uint32_t height);
  static TranslatedFrame JavaScriptBuiltinContinuationWithCatchFrame(
      BytecodeOffset bailout_id, Tagged<SharedFunctionInfo> shared_info,
      uint32_t height);
  static TranslatedFrame InvalidFrame() {
    return TranslatedFrame(kInvalid, {}, {}, 0);
  }

  static void AdvanceIterator(std::deque<TranslatedValue>::iterator* iter);

  explicit TranslatedFrame(Kind kind,
                           Tagged<SharedFunctionInfo> raw_shared_info,
                           Tagged<BytecodeArray> raw_bytecode_array,
                           uint32_t height, int return_value_offset = 0,
                           int return_value_count = 0)
      : kind_(kind),
        bytecode_offset_(BytecodeOffset::None()),
        raw_shared_info_(raw_shared_info),
        raw_bytecode_array_(raw_bytecode_array),
        height_(height),
        return_value_offset_(return_value_offset),
        return_value_count_(return_value_count),
        handle_state_(kRawPointers) {}

  void Add(const TranslatedValue& value) { values_.push_back(value); }
  TranslatedValue* ValueAt(int index) { return &(values_[index]); }
  void Handlify(Isolate* isolate);

  Kind kind_;
  BytecodeOffset bytecode_offset_;

  // Object references are stored as either raw pointers (before Handlify is
  // called) or handles (afterward).
  union {
    Tagged<SharedFunctionInfo> raw_shared_info_;
    IndirectHandle<SharedFunctionInfo> shared_info_;
  };
  union {
    Tagged<BytecodeArray> raw_bytecode_array_;
    IndirectHandle<BytecodeArray> bytecode_array_;
  };

  uint32_t height_;
  int return_value_offset_;
  int return_value_count_;

  enum HandleState { kRawPointers, kHandles } handle_state_;

  using ValuesContainer = std::deque<TranslatedValue>;

  ValuesContainer values_;

#if V8_ENABLE_WEBASSEMBLY
  // Only for Kind == kJSToWasmBuiltinContinuation
  std::optional<wasm::ValueKind> return_kind_;
  // Only for Kind == kLiftOffFunction
  int wasm_function_index_ = -1;
#endif  // V8_ENABLE_WEBASSEMBLY
};

class DeoptimizationLiteralProvider {
 public:
  explicit DeoptimizationLiteralProvider(
      Tagged<DeoptimizationLiteralArray> literal_array);

  explicit DeoptimizationLiteralProvider(
      std::vector<DeoptimizationLiteral> literals);

  ~DeoptimizationLiteralProvider();
  // Prevent expensive copying.
  DeoptimizationLiteralProvider(const DeoptimizationLiteralProvider&) = delete;
  void operator=(const DeoptimizationLiteralProvider&) = delete;

  TranslatedValue Get(TranslatedState* container, int literal_index) const;

  Tagged<DeoptimizationLiteralArray> get_on_heap_literals() const {
    DCHECK(!literals_on_heap_.is_null());
    return literals_on_heap_;
  }

 private:
  Tagged<DeoptimizationLiteralArray> literals_on_heap_;
  std::vector<DeoptimizationLiteral> literals_off_heap_;
};

// Auxiliary class for translating deoptimization values.
// Typical usage sequence:
//
// 1. Construct the instance. This will involve reading out the translations
//    and resolving them to values using the supplied frame pointer and
//    machine state (registers). This phase is guaranteed not to allocate
//    and not to use any HandleScope. Any object pointers will be stored raw.
//
// 2. Handlify pointers. This will convert all the raw pointers to handles.
//
// 3. Reading out the frame values.
//
// Note: After the instance is constructed, it is possible to iterate over
// the values eagerly.

class TranslatedState {
 public:
  // There are two constructors, each for a different purpose:

  // The default constructor is for the purpose of deoptimizing an optimized
  // frame (replacing it with one or several unoptimized frames). It is used by
  // the Deoptimizer.
  TranslatedState() : purpose_(kDeoptimization) {}

  // This constructor is for the purpose of merely inspecting an optimized
  // frame. It is used by stack trace generation and various debugging features.
  explicit TranslatedState(const JavaScriptFrame* frame);

  void Prepare(Address stack_frame_pointer);

  // Store newly materialized values into the isolate.
  void StoreMaterializedValuesAndDeopt(JavaScriptFrame* frame);

  using iterator = std::vector<TranslatedFrame>::iterator;
  iterator begin() { return frames_.begin(); }
  iterator end() { return frames_.end(); }

  using const_iterator = std::vector<TranslatedFrame>::const_iterator;
  const_iterator begin() const { return frames_.begin(); }
  const_iterator end() const { return frames_.end(); }

  std::vector<TranslatedFrame>& frames() { return frames_; }

  TranslatedFrame* GetFrameFromJSFrameIndex(int jsframe_index);
  TranslatedFrame* GetArgumentsInfoFromJSFrameIndex(int jsframe_index,
                                                    int* arguments_count);

  Isolate* isolate() { return isolate_; }

  void Init(Isolate* isolate, Address input_frame_pointer,
            Address stack_frame_pointer, DeoptTranslationIterator* iterator,
            Tagged<ProtectedDeoptimizationLiteralArray> protected_literal_array,
            const DeoptimizationLiteralProvider& literal_array,
            RegisterValues* registers, FILE* trace_file, int parameter_count,
            int actual_argument_count);

  void VerifyMaterializedObjects();
  bool DoUpdateFeedback();

 private:
  friend TranslatedValue;

  // See the description of the constructors for an explanation of the two
  // purposes. The only actual difference is that in the kFrameInspection case
  // extra work is needed to not violate assumptions made by left-trimming.  For
  // details, see the code around ReplaceElementsArrayWithCopy.
  enum Purpose { kDeoptimization, kFrameInspection };

  TranslatedFrame CreateNextTranslatedFrame(
      DeoptTranslationIterator* iterator,
      Tagged<ProtectedDeoptimizationLiteralArray> protected_literal_array,
      const DeoptimizationLiteralProvider& literal_array, Address fp,
      FILE* trace_file);
  int CreateNextTranslatedValue(
      int frame_index, DeoptTranslationIterator* iterator,
      const DeoptimizationLiteralProvider& literal_array, Address fp,
      RegisterValues* registers, FILE* trace_file);
  Address DecompressIfNeeded(intptr_t value);
  void CreateArgumentsElementsTranslatedValues(int frame_index,
                                               Address input_frame_pointer,
                                               CreateArgumentsType type,
                                               FILE* trace_file);

  void UpdateFromPreviouslyMaterializedObjects();
  void MaterializeFixedDoubleArray(TranslatedFrame* frame, int* value_index,
                                   TranslatedValue* slot,
                                   DirectHandle<Map> map);
  void MaterializeHeapNumber(TranslatedFrame* frame, int* value_index,
                             TranslatedValue* slot);

  void EnsureObjectAllocatedAt(TranslatedValue* slot);

  void SkipSlots(int slots_to_skip, TranslatedFrame* frame, int* value_index);

  Handle<ByteArray> AllocateStorageFor(TranslatedValue* slot);
  void EnsureJSObjectAllocated(TranslatedValue* slot, DirectHandle<Map> map);
  void EnsurePropertiesAllocatedAndMarked(TranslatedValue* properties_slot,
                                          DirectHandle<Map> map);
  void EnsureChildrenAllocated(int count, TranslatedFrame* frame,
                               int* value_index, std::stack<int>* worklist);
  void EnsureCapturedObjectAllocatedAt(int object_index,
                                       std::stack<int>* worklist);
  Handle<HeapObject> InitializeObjectAt(TranslatedValue* slot);
  void InitializeCapturedObjectAt(int object_index, std::stack<int>* worklist,
                                  const DisallowGarbageCollection& no_gc);
  void InitializeJSObjectAt(TranslatedFrame* frame, int* value_index,
                            TranslatedValue* slot, DirectHandle<Map> map,
                            const DisallowGarbageCollection& no_gc);
  void InitializeObjectWithTaggedFieldsAt(
      TranslatedFrame* frame, int* value_index, TranslatedValue* slot,
      DirectHandle<Map> map, const DisallowGarbageCollection& no_gc);

  Handle<HeapObject> ResolveStringConcat(TranslatedValue* slot);

  void ReadUpdateFeedback(DeoptTranslationIterator* iterator,
                          Tagged<DeoptimizationLiteralArray> literal_array,
                          FILE* trace_file);

  TranslatedValue* ResolveCapturedObject(TranslatedValue* slot);
  TranslatedValue* GetValueByObjectIndex(int object_index);
  Handle<Object> GetValueAndAdvance(TranslatedFrame* frame, int* value_index);
  TranslatedValue* GetResolvedSlot(TranslatedFrame* frame, int value_index);
  TranslatedValue* GetResolvedSlotAndAdvance(TranslatedFrame* frame,
                                             int* value_index);

  static uint32_t GetUInt32Slot(Address fp, int slot_index);
  static uint64_t GetUInt64Slot(Address fp, int slot_index);
  static Float32 GetFloatSlot(Address fp, int slot_index);
  static Float64 GetDoubleSlot(Address fp, int slot_index);
  static Simd128 getSimd128Slot(Address fp, int slot_index);

  Purpose const purpose_;
  std::vector<TranslatedFrame> frames_;
  Isolate* isolate_ = nullptr;
  Address stack_frame_pointer_ = kNullAddress;
  int formal_parameter_count_;
  int actual_argument_count_;

  struct ObjectPosition {
    int frame_index_;
    int value_index_;
  };
  std::deque<ObjectPosition> object_positions_;
  std::deque<ObjectPosition> string_concat_positions_;
  Handle<FeedbackVector> feedback_vector_handle_;
  Tagged<FeedbackVector> feedback_vector_;
  FeedbackSlot feedback_slot_;
};

// Return kind encoding for a Wasm function returning void.
const int kNoWasmReturnKind = -1;

}  // namespace internal
}  // namespace v8

#endif  // V8_DEOPTIMIZER_TRANSLATED_STATE_H_
```