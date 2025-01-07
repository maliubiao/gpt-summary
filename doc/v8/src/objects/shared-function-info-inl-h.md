Response:
Let's break down the thought process for analyzing this V8 C++ header file.

**1. Initial Scan and High-Level Understanding:**

* **Keywords:** The file name `shared-function-info-inl.h` immediately suggests this code deals with information shared across instances of the same function in V8. The `.inl.h` suffix strongly indicates it's an inline header, containing implementations of methods.
* **Copyright and Includes:**  The copyright notice confirms it's part of the V8 project. The included headers give hints about the functionality:
    * `src/base/macros.h`, `src/base/platform/mutex.h`: Basic utilities, potential for thread safety.
    * `src/builtins/builtins.h`: Interaction with built-in JavaScript functions.
    * `src/codegen/optimized-compilation-info.h`: Information related to code optimization.
    * `src/objects/...`:  Heavy reliance on V8's object model. Specifically `shared-function-info.h` (the non-inline version) will define the basic structure.
    * `torque-generated/...`:  Indicates use of Torque, V8's domain-specific language for generating runtime code.
* **Namespace:**  The code is within the `v8::internal` namespace.

**2. Identifying Key Structures and Concepts:**

* **`PreparseData`:**  Seems related to pre-parsing or initial analysis of function code. The methods like `inner_start_offset`, `get`, `set`, `copy_in`, and `get_child` suggest it's a structured data container.
* **`UncompiledData` variations:**  Clearly related to the state of a function before it's compiled. The different suffixes likely represent different stages or additional information (like `PreparseData` or a job queue).
* **`InterpreterData`:**  Holds information specifically for interpreted functions, including the `BytecodeArray` and interpreter trampoline code.
* **`SharedFunctionInfo`:** The central focus. The accessors (`RELEASE_ACQUIRE_ACCESSORS`, `DEF_GETTER`, `BIT_FIELD_ACCESSORS`) point to various pieces of information stored within it. The numerous methods suggest a complex role.

**3. Analyzing `SharedFunctionInfo` Methods:**

* **Accessors:**  Look for patterns like `Get...`, `Set...`, `Has...`, which reveal the properties being managed. Examples: `name_or_scope_info`, `script`, `trusted_data`, `untrusted_data`, `flags`, `bytecode_array`, `baseline_code`.
* **Methods with Logic:**  Pay attention to methods that perform more than simple getting or setting.
    * `SetTrustedData`/`SetUntrustedData`:  Mutual exclusivity suggests these are alternative ways to store certain kinds of function-related information.
    * `HasSharedName`/`Name`/`SetName`:  Management of the function's name.
    * `is_script`/`needs_script_context`: Properties related to whether the function represents a top-level script.
    * `abstract_code`:  Retrieving the compiled code (bytecode or machine code).
    * `GetInlineability`:  Important for performance; determines if a function can be inlined.
    * `optimization_disabled`/`disabled_optimization_reason`:  Indicates why a function might not be optimized.
    * `language_mode`/`kind`: Properties defining the function's behavior (strict/sloppy, normal function/constructor, etc.).
    * `UpdateFunctionMapIndex`:  Likely related to how V8 internally categorizes functions.
    * `DontAdaptArguments`/`IsDontAdaptArguments`:  Optimization related to function arguments.
    * `GetBytecodeArray`/`SetActiveBytecodeArray`:  Managing the bytecode representation of the function.
    * `HasBaselineCode`/`GetBaselineCode`/`FlushBaselineCode`:  Related to V8's tiered compilation.

**4. Identifying Torque Usage:**

* **`//torque-generated/...` include:**  Direct indication of Torque's involvement.
* **`TQ_OBJECT_CONSTRUCTORS_IMPL(...)`:** Torque macros for generating constructor implementations.
* **`RENAME_TORQUE_ACCESSORS(...)`, `RENAME_PRIMITIVE_TORQUE_ACCESSORS(...)`:**  Torque macros for defining accessors for fields.

**5. Connecting to JavaScript Functionality (Conceptual):**

At this stage, without deeper V8 knowledge, we can make educated guesses about how these C++ concepts map to JavaScript.

* **Function Declaration/Expression:** `SharedFunctionInfo` stores metadata about a JavaScript function defined using `function`, arrow functions, class methods, etc.
* **Scope:** `ScopeInfo` holds information about the variables accessible within a function.
* **Compilation:**  `BytecodeArray` is the result of the initial compilation. `BaselineCode` and more optimized code are results of later optimization stages.
* **Built-in Functions:**  `HasBuiltinId` and related logic handle core JavaScript functions like `Math.sin`, `Array.map`, etc.
* **Strict Mode:**  `language_mode` reflects whether the function is running in strict mode.
* **Function Type (Constructor, etc.):** `kind` distinguishes between regular functions, constructors, generators, etc.
* **Inlining:** The `GetInlineability` method directly impacts whether V8 can optimize function calls by inserting the function's code directly.
* **Debugging:** The `hook_flag` and related bits likely play a role in debugging and profiling.

**6. Formulating the Summary:**

Combine the identified features and their relationships to create a concise summary. Focus on the main purpose of `SharedFunctionInfo` and the types of information it manages.

**7. Addressing Specific Instructions:**

* **`.tq` extension:**  Recognize the Torque implication.
* **JavaScript examples:**  Think of simple JavaScript code snippets that illustrate the concepts (function declarations, built-ins, strict mode).
* **Logic and assumptions:**  For methods with more complex logic (like `GetInlineability`), outline the factors considered and how they might lead to a decision.
* **Common programming errors:**  Relate the V8 concepts to potential errors developers might make (e.g., relying on inlining, issues with strict mode).

**Self-Correction/Refinement During the Process:**

* **Initial Overwhelm:** The file is dense. Focus on the main structures first and then dive into the details of the methods.
* **Guessing vs. Knowing:**  Be clear about what is inferred and what is explicitly stated in the code. Avoid making definitive statements without sufficient evidence.
* **Iterative Understanding:**  Reading the code multiple times, focusing on different aspects each time, helps build a more complete picture.
* **Looking for Connections:**  Notice how different parts of the code relate to each other (e.g., how `SetTrustedData` clears `untrusted_data`).

By following this systematic approach, combining code analysis with conceptual understanding of JavaScript and V8's architecture, we can arrive at a comprehensive and accurate summary of the provided header file.
好的，让我们来分析一下 `v8/src/objects/shared-function-info-inl.h` 这个 V8 源代码文件。

**功能归纳:**

`v8/src/objects/shared-function-info-inl.h` 文件是 V8 引擎中关于 `SharedFunctionInfo` 对象的内联定义（实现）。`SharedFunctionInfo` 是 V8 内部表示 JavaScript 函数元数据的一个核心数据结构。 这个 `.inl.h` 文件提供了访问和操作 `SharedFunctionInfo` 对象及其相关子对象（如 `PreparseData`, `UncompiledData`, `InterpreterData`）的内联方法，目的是提高性能。

**主要功能点包括:**

1. **定义和操作 `PreparseData`:**  `PreparseData` 存储了函数预解析阶段的信息，用于加速后续的编译过程。文件中包含了创建、访问和修改 `PreparseData` 的方法，例如获取内部数据偏移、设置和获取字节、复制数据以及操作子 `PreparseData` 对象。

2. **定义 `UncompiledData` 及其变体:** `UncompiledData` 用于存储函数在未编译时的各种信息，例如源代码、预解析数据等。  文件中定义了不同类型的 `UncompiledData`，以适应不同的场景，例如是否包含预解析数据，是否关联了解析任务等。

3. **定义和操作 `InterpreterData`:** `InterpreterData` 存储了解释执行 JavaScript 函数所需的信息，包括字节码数组和解释器入口点。文件中提供了访问和设置这些信息的方法。

4. **定义和操作核心的 `SharedFunctionInfo`:**  这是文件的核心部分，提供了大量访问和修改 `SharedFunctionInfo` 对象属性的方法，这些属性描述了 JavaScript 函数的各种特征：
    * **名称和作用域信息:**  访问和设置函数的名称和作用域信息 (`name_or_scope_info`)。
    * **脚本信息:** 关联的脚本 (`script`)。
    * **代码数据:**  存储已编译的代码 (`TrustedData`, `UntrustedData`)，可以是字节码数组 (`BytecodeArray`)、解释器数据 (`InterpreterData`) 或优化后的机器码 (`Code`)。
    * **受信任/不受信任数据:**  V8 使用受信任和不受信任数据来区分内部数据和可能受到外部影响的数据。
    * **参数信息:**  获取和设置形参个数 (`formal_parameter_count`)。
    * **标记 (Flags):**  各种布尔标记，用于表示函数的特性，例如是否是严格模式、是否是原生函数、是否禁用了优化等。
    * **内联策略:**  获取函数的内联能力 (`GetInlineability`)。
    * **优化状态:**  检查是否禁用了优化，以及禁用优化的原因。
    * **语言模式 (Language Mode):**  获取和设置函数的语言模式（严格模式或非严格模式）。
    * **函数种类 (Function Kind):**  获取和设置函数的种类（普通函数、构造函数等）。
    * **字节码数组 (BytecodeArray):**  获取和设置函数的字节码数组。
    * **解释器数据 (InterpreterData):** 获取和设置函数的解释器数据。
    * **优化代码 (BaselineCode):** 获取和设置基线编译器生成的代码。
    * **WebAssembly 相关数据:**  如果启用了 WebAssembly，还包含访问和设置 WebAssembly 相关数据的方法。
    * **Hook 标志:** 用于调试和性能分析的 Hook 标志。

5. **使用 Torque 生成代码:**  文件中包含了 `#include "torque-generated/src/objects/shared-function-info-tq-inl.inc"`， 表明 V8 使用 Torque 这种领域特定语言来生成部分 `SharedFunctionInfo` 相关的代码，特别是对象构造函数和一些访问器。`TQ_OBJECT_CONSTRUCTORS_IMPL` 宏就是 Torque 提供的用于实现对象构造函数的。

**如果 `v8/src/objects/shared-function-info-inl.h` 以 `.tq` 结尾:**

如果该文件以 `.tq` 结尾，那么它会是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 内部使用的语言，用于以一种类型安全和可维护的方式生成 C++ 代码，尤其是用于实现 V8 的内置函数和运行时代码。

**与 JavaScript 功能的关系及示例:**

`SharedFunctionInfo` 对象在 V8 引擎内部与 JavaScript 函数有着直接的对应关系。每当 JavaScript 引擎遇到一个函数定义时，V8 就会创建一个 `SharedFunctionInfo` 对象来存储这个函数的元数据。

**示例 (JavaScript):**

```javascript
function myFunction(a, b) {
  'use strict';
  console.log(a + b);
}

const arrowFunction = (x) => x * 2;

class MyClass {
  constructor() {
    this.value = 10;
  }
  method() {
    console.log(this.value);
  }
}
```

对于上述 JavaScript 代码，V8 引擎会创建多个 `SharedFunctionInfo` 对象：

* 一个对应于 `myFunction`。这个 `SharedFunctionInfo` 会记录：
    * 函数名: "myFunction"
    * 形参个数: 2
    * 语言模式: 严格模式 (因为有 `'use strict';`)
    * 关联的脚本信息
    * 函数的字节码 (存储在 `TrustedData` 或 `InterpreterData` 中)
* 一个对应于 `arrowFunction`。
* 一个对应于 `MyClass` 的构造函数。
* 一个对应于 `MyClass` 的 `method`。

**代码逻辑推理 (假设输入与输出):**

考虑 `SharedFunctionInfo::Name()` 方法：

**假设输入:**  一个 `SharedFunctionInfo` 对象，其 `name_or_scope_info` 字段指向一个 `String` 对象，内容为 "myFunction"。

**输出:** 方法 `Name()` 将返回一个 `Tagged<String>` 对象，其内容为 "myFunction"。

**假设输入:** 一个 `SharedFunctionInfo` 对象，其 `name_or_scope_info` 字段指向一个 `ScopeInfo` 对象，并且该 `ScopeInfo` 对象的函数名 (`FunctionName`) 字段指向一个 `String` 对象，内容为 "anotherFunction"。

**输出:** 方法 `Name()` 将返回一个 `Tagged<String>` 对象，其内容为 "anotherFunction"。

**用户常见的编程错误 (与 `SharedFunctionInfo` 相关的概念):**

虽然开发者通常不直接操作 `SharedFunctionInfo` 对象，但理解其背后的概念有助于避免一些性能问题和理解 JavaScript 的行为：

1. **过度依赖内联:**  开发者可能会期望某个函数总是被内联以提高性能，但 V8 的内联策略是动态的，受到多种因素影响（例如函数大小、调用次数等）。如果一个函数由于某些原因（例如包含调试断点、过大）无法内联，性能可能不如预期。`SharedFunctionInfo::GetInlineability()` 描述了 V8 判断是否可以内联的逻辑。

2. **不理解严格模式的影响:**  `SharedFunctionInfo` 存储了函数的语言模式。开发者可能在某些代码中意外地使用了严格模式，导致一些在非严格模式下允许的行为（例如全局变量的隐式创建）报错。

3. **性能分析盲点:** 理解 `SharedFunctionInfo` 中与优化相关的信息（例如是否禁用了优化以及原因）可以帮助开发者更好地进行性能分析。如果一个关键函数由于某种原因被禁用了优化，开发者可以尝试修改代码以消除禁用优化的因素。

**总结 (第 1 部分功能):**

`v8/src/objects/shared-function-info-inl.h` 文件的主要功能是定义了 `SharedFunctionInfo` 对象及其相关子对象的内联访问和操作方法。`SharedFunctionInfo` 作为 V8 内部表示 JavaScript 函数元数据的核心结构，包含了函数的名称、作用域、代码、参数、优化状态等关键信息。该文件还涉及对函数预解析数据、未编译数据和解释器数据的管理。通过这些内联方法，V8 引擎能够高效地访问和操作函数元数据，为 JavaScript 代码的编译、优化和执行提供了基础。文件的存在和内容体现了 V8 引擎在性能和效率上的追求。

Prompt: 
```
这是目录为v8/src/objects/shared-function-info-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/shared-function-info-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_SHARED_FUNCTION_INFO_INL_H_
#define V8_OBJECTS_SHARED_FUNCTION_INFO_INL_H_

#include <optional>

#include "src/base/macros.h"
#include "src/base/platform/mutex.h"
#include "src/builtins/builtins.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/objects/abstract-code-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/feedback-vector-inl.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/scope-info-inl.h"
#include "src/objects/script-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/string.h"
#include "src/objects/templates-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8::internal {

#include "torque-generated/src/objects/shared-function-info-tq-inl.inc"

TQ_OBJECT_CONSTRUCTORS_IMPL(PreparseData)

int PreparseData::inner_start_offset() const {
  return InnerOffset(data_length());
}

ObjectSlot PreparseData::inner_data_start() const {
  return RawField(inner_start_offset());
}

void PreparseData::clear_padding() {
  int data_end_offset = kDataStartOffset + data_length();
  int padding_size = inner_start_offset() - data_end_offset;
  DCHECK_LE(0, padding_size);
  if (padding_size == 0) return;
  memset(reinterpret_cast<void*>(address() + data_end_offset), 0, padding_size);
}

uint8_t PreparseData::get(int index) const {
  DCHECK_LE(0, index);
  DCHECK_LT(index, data_length());
  int offset = kDataStartOffset + index * kByteSize;
  return ReadField<uint8_t>(offset);
}

void PreparseData::set(int index, uint8_t value) {
  DCHECK_LE(0, index);
  DCHECK_LT(index, data_length());
  int offset = kDataStartOffset + index * kByteSize;
  WriteField<uint8_t>(offset, value);
}

void PreparseData::copy_in(int index, const uint8_t* buffer, int length) {
  DCHECK(index >= 0 && length >= 0 && length <= kMaxInt - index &&
         index + length <= this->data_length());
  Address dst_addr = field_address(kDataStartOffset + index * kByteSize);
  memcpy(reinterpret_cast<void*>(dst_addr), buffer, length);
}

Tagged<PreparseData> PreparseData::get_child(int index) const {
  return Cast<PreparseData>(get_child_raw(index));
}

Tagged<Object> PreparseData::get_child_raw(int index) const {
  DCHECK_LE(0, index);
  DCHECK_LT(index, this->children_length());
  int offset = inner_start_offset() + index * kTaggedSize;
  return RELAXED_READ_FIELD(*this, offset);
}

void PreparseData::set_child(int index, Tagged<PreparseData> value,
                             WriteBarrierMode mode) {
  DCHECK_LE(0, index);
  DCHECK_LT(index, this->children_length());
  int offset = inner_start_offset() + index * kTaggedSize;
  RELAXED_WRITE_FIELD(*this, offset, value);
  CONDITIONAL_WRITE_BARRIER(*this, offset, value, mode);
}

TQ_OBJECT_CONSTRUCTORS_IMPL(UncompiledData)
TQ_OBJECT_CONSTRUCTORS_IMPL(UncompiledDataWithoutPreparseData)
TQ_OBJECT_CONSTRUCTORS_IMPL(UncompiledDataWithPreparseData)
TQ_OBJECT_CONSTRUCTORS_IMPL(UncompiledDataWithoutPreparseDataWithJob)
TQ_OBJECT_CONSTRUCTORS_IMPL(UncompiledDataWithPreparseDataAndJob)

TQ_OBJECT_CONSTRUCTORS_IMPL(InterpreterData)
PROTECTED_POINTER_ACCESSORS(InterpreterData, bytecode_array, BytecodeArray,
                            kBytecodeArrayOffset)
PROTECTED_POINTER_ACCESSORS(InterpreterData, interpreter_trampoline, Code,
                            kInterpreterTrampolineOffset)

TQ_OBJECT_CONSTRUCTORS_IMPL(SharedFunctionInfo)

RELEASE_ACQUIRE_ACCESSORS(SharedFunctionInfo, name_or_scope_info,
                          Tagged<NameOrScopeInfoT>, kNameOrScopeInfoOffset)
RELEASE_ACQUIRE_ACCESSORS(SharedFunctionInfo, script, Tagged<HeapObject>,
                          kScriptOffset)
RELEASE_ACQUIRE_ACCESSORS(SharedFunctionInfo, raw_script, Tagged<Object>,
                          kScriptOffset)

void SharedFunctionInfo::SetTrustedData(Tagged<ExposedTrustedObject> value,
                                        WriteBarrierMode mode) {
  WriteTrustedPointerField<kUnknownIndirectPointerTag>(
      kTrustedFunctionDataOffset, value);

  // Only one of trusted_function_data and untrusted_function_data can be in
  // use, so clear the untrusted data field. Using -1 here as cleared data value
  // allows HasBuiltinId to become quite simple, as it can just check if the
  // untrusted data is a Smi containing a valid builtin ID.
  constexpr int kClearedUntrustedFunctionDataValue = -1;
  static_assert(!Builtins::IsBuiltinId(kClearedUntrustedFunctionDataValue));
  TaggedField<Object, kUntrustedFunctionDataOffset>::Release_Store(
      *this, Smi::FromInt(kClearedUntrustedFunctionDataValue));

  CONDITIONAL_TRUSTED_POINTER_WRITE_BARRIER(*this, kTrustedFunctionDataOffset,
                                            kUnknownIndirectPointerTag, value,
                                            mode);
}

void SharedFunctionInfo::SetUntrustedData(Tagged<Object> value,
                                          WriteBarrierMode mode) {
  TaggedField<Object, kUntrustedFunctionDataOffset>::Release_Store(*this,
                                                                   value);

  // Only one of trusted_function_data and untrusted_function_data can be in
  // use, so clear the trusted data field.
  ClearTrustedPointerField(kTrustedFunctionDataOffset, kReleaseStore);

  CONDITIONAL_WRITE_BARRIER(*this, kUntrustedFunctionDataOffset, value, mode);
}

bool SharedFunctionInfo::HasTrustedData() const {
  return !IsTrustedPointerFieldEmpty(kTrustedFunctionDataOffset);
}

bool SharedFunctionInfo::HasUntrustedData() const { return !HasTrustedData(); }

Tagged<Object> SharedFunctionInfo::GetTrustedData(
    IsolateForSandbox isolate) const {
  return ReadMaybeEmptyTrustedPointerField<kUnknownIndirectPointerTag>(
      kTrustedFunctionDataOffset, isolate, kAcquireLoad);
}

template <typename T, IndirectPointerTag tag>
Tagged<T> SharedFunctionInfo::GetTrustedData(IsolateForSandbox isolate) const {
  static_assert(tag != kUnknownIndirectPointerTag);
  return Cast<T>(ReadMaybeEmptyTrustedPointerField<tag>(
      kTrustedFunctionDataOffset, isolate, kAcquireLoad));
}

Tagged<Object> SharedFunctionInfo::GetTrustedData() const {
#ifdef V8_ENABLE_SANDBOX
  auto trusted_data_slot = RawIndirectPointerField(kTrustedFunctionDataOffset,
                                                   kUnknownIndirectPointerTag);
  // This routine is sometimes used for SFI's in read-only space (which never
  // have trusted data). In that case, GetIsolateForSandbox cannot be used, so
  // we need to return early in that case, before trying to obtain an Isolate.
  IndirectPointerHandle handle = trusted_data_slot.Acquire_LoadHandle();
  if (handle == kNullIndirectPointerHandle) return Smi::zero();
  return trusted_data_slot.ResolveHandle(handle, GetIsolateForSandbox(*this));
#else
  return TaggedField<Object, kTrustedFunctionDataOffset>::Acquire_Load(*this);
#endif
}

Tagged<Object> SharedFunctionInfo::GetUntrustedData() const {
  return TaggedField<Object, kUntrustedFunctionDataOffset>::Acquire_Load(*this);
}

DEF_GETTER(SharedFunctionInfo, script, Tagged<HeapObject>) {
  return script(cage_base, kAcquireLoad);
}
bool SharedFunctionInfo::has_script(AcquireLoadTag tag) const {
  return IsScript(script(tag));
}

RENAME_TORQUE_ACCESSORS(SharedFunctionInfo,
                        raw_outer_scope_info_or_feedback_metadata,
                        outer_scope_info_or_feedback_metadata,
                        Tagged<HeapObject>)
DEF_ACQUIRE_GETTER(SharedFunctionInfo,
                   raw_outer_scope_info_or_feedback_metadata,
                   Tagged<HeapObject>) {
  Tagged<HeapObject> value =
      TaggedField<HeapObject, kOuterScopeInfoOrFeedbackMetadataOffset>::
          Acquire_Load(cage_base, *this);
  return value;
}

uint16_t SharedFunctionInfo::internal_formal_parameter_count_with_receiver()
    const {
  const uint16_t param_count = TorqueGeneratedClass::formal_parameter_count();
  return param_count;
}

uint16_t SharedFunctionInfo::internal_formal_parameter_count_without_receiver()
    const {
  const uint16_t param_count = TorqueGeneratedClass::formal_parameter_count();
  if (param_count == kDontAdaptArgumentsSentinel) return param_count;
  return param_count - kJSArgcReceiverSlots;
}

void SharedFunctionInfo::set_internal_formal_parameter_count(int value) {
  DCHECK_EQ(value, static_cast<uint16_t>(value));
  DCHECK_GE(value, kJSArgcReceiverSlots);
  TorqueGeneratedClass::set_formal_parameter_count(value);
}

RENAME_PRIMITIVE_TORQUE_ACCESSORS(SharedFunctionInfo, raw_function_token_offset,
                                  function_token_offset, uint16_t)

RELAXED_INT32_ACCESSORS(SharedFunctionInfo, flags, kFlagsOffset)
int32_t SharedFunctionInfo::relaxed_flags() const {
  return flags(kRelaxedLoad);
}
void SharedFunctionInfo::set_relaxed_flags(int32_t flags) {
  return set_flags(flags, kRelaxedStore);
}

UINT8_ACCESSORS(SharedFunctionInfo, flags2, kFlags2Offset)

bool SharedFunctionInfo::HasSharedName() const {
  Tagged<Object> value = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(value)) {
    return Cast<ScopeInfo>(value)->HasSharedFunctionName();
  }
  return value != kNoSharedNameSentinel;
}

Tagged<String> SharedFunctionInfo::Name() const {
  if (!HasSharedName()) return GetReadOnlyRoots().empty_string();
  Tagged<Object> value = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(value)) {
    if (Cast<ScopeInfo>(value)->HasFunctionName()) {
      return Cast<String>(Cast<ScopeInfo>(value)->FunctionName());
    }
    return GetReadOnlyRoots().empty_string();
  }
  return Cast<String>(value);
}

void SharedFunctionInfo::SetName(Tagged<String> name) {
  Tagged<Object> maybe_scope_info = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(maybe_scope_info)) {
    Cast<ScopeInfo>(maybe_scope_info)->SetFunctionName(name);
  } else {
    DCHECK(IsString(maybe_scope_info) ||
           maybe_scope_info == kNoSharedNameSentinel);
    set_name_or_scope_info(name, kReleaseStore);
  }
  UpdateFunctionMapIndex();
}

bool SharedFunctionInfo::is_script() const {
  return scope_info(kAcquireLoad)->is_script_scope() &&
         Cast<Script>(script())->compilation_type() ==
             Script::CompilationType::kHost;
}

bool SharedFunctionInfo::needs_script_context() const {
  return is_script() && scope_info(kAcquireLoad)->ContextLocalCount() > 0;
}

Tagged<AbstractCode> SharedFunctionInfo::abstract_code(Isolate* isolate) {
  // TODO(v8:11429): Decide if this return bytecode or baseline code, when the
  // latter is present.
  if (HasBytecodeArray(isolate)) {
    return Cast<AbstractCode>(GetBytecodeArray(isolate));
  } else {
    return Cast<AbstractCode>(GetCode(isolate));
  }
}

int SharedFunctionInfo::function_token_position() const {
  int offset = raw_function_token_offset();
  if (offset == kFunctionTokenOutOfRange) {
    return kNoSourcePosition;
  } else {
    return StartPosition() - offset;
  }
}

template <typename IsolateT>
bool SharedFunctionInfo::AreSourcePositionsAvailable(IsolateT* isolate) const {
  if (v8_flags.enable_lazy_source_positions) {
    return !HasBytecodeArray() ||
           GetBytecodeArray(isolate)->HasSourcePositionTable();
  }
  return true;
}

template <typename IsolateT>
SharedFunctionInfo::Inlineability SharedFunctionInfo::GetInlineability(
    IsolateT* isolate) const {
  if (!IsScript(script())) return kHasNoScript;

  if (isolate->is_precise_binary_code_coverage() &&
      !has_reported_binary_coverage()) {
    // We may miss invocations if this function is inlined.
    return kNeedsBinaryCoverage;
  }

  // Built-in functions are handled by the JSCallReducer.
  if (HasBuiltinId()) return kIsBuiltin;

  if (!IsUserJavaScript()) return kIsNotUserCode;

  // If there is no bytecode array, it is either not compiled or it is compiled
  // with WebAssembly for the asm.js pipeline. In either case we don't want to
  // inline.
  if (!HasBytecodeArray()) return kHasNoBytecode;

  if (GetBytecodeArray(isolate)->length() >
      v8_flags.max_inlined_bytecode_size) {
    return kExceedsBytecodeLimit;
  }

  {
    SharedMutexGuardIfOffThread<IsolateT, base::kShared> mutex_guard(
        isolate->shared_function_info_access(), isolate);
    if (HasBreakInfo(isolate->GetMainThreadIsolateUnsafe())) {
      return kMayContainBreakPoints;
    }
  }

  if (optimization_disabled()) return kHasOptimizationDisabled;

  return kIsInlineable;
}

//hook实现
BIT_FIELD_ACCESSORS(SharedFunctionInfo, hook_flag, hooked,
                    SharedFunctionInfo::HookedBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, hook_flag, hook_running,
                    SharedFunctionInfo::HookRunningBit)                   

BIT_FIELD_ACCESSORS(SharedFunctionInfo, flags2, class_scope_has_private_brand,
                    SharedFunctionInfo::ClassScopeHasPrivateBrandBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, flags2,
                    has_static_private_methods_or_accessors,
                    SharedFunctionInfo::HasStaticPrivateMethodsOrAccessorsBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, flags2, is_sparkplug_compiling,
                    SharedFunctionInfo::IsSparkplugCompilingBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, flags2, maglev_compilation_failed,
                    SharedFunctionInfo::MaglevCompilationFailedBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, flags2,
                    function_context_independent_compiled,
                    SharedFunctionInfo::FunctionContextIndependentCompiledBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags, syntax_kind,
                    SharedFunctionInfo::FunctionSyntaxKindBits)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags, allows_lazy_compilation,
                    SharedFunctionInfo::AllowLazyCompilationBit)
BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags, has_duplicate_parameters,
                    SharedFunctionInfo::HasDuplicateParametersBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags, native,
                    SharedFunctionInfo::IsNativeBit)
#if V8_ENABLE_WEBASSEMBLY
BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags, is_asm_wasm_broken,
                    SharedFunctionInfo::IsAsmWasmBrokenBit)
#endif  // V8_ENABLE_WEBASSEMBLY
BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags,
                    requires_instance_members_initializer,
                    SharedFunctionInfo::RequiresInstanceMembersInitializerBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags,
                    name_should_print_as_anonymous,
                    SharedFunctionInfo::NameShouldPrintAsAnonymousBit)
BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags,
                    has_reported_binary_coverage,
                    SharedFunctionInfo::HasReportedBinaryCoverageBit)

BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags, is_toplevel,
                    SharedFunctionInfo::IsTopLevelBit)
BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags, properties_are_final,
                    SharedFunctionInfo::PropertiesAreFinalBit)
BIT_FIELD_ACCESSORS(SharedFunctionInfo, relaxed_flags,
                    private_name_lookup_skips_outer_class,
                    SharedFunctionInfo::PrivateNameLookupSkipsOuterClassBit)

bool SharedFunctionInfo::optimization_disabled() const {
  return disabled_optimization_reason() != BailoutReason::kNoReason;
}

BailoutReason SharedFunctionInfo::disabled_optimization_reason() const {
  return DisabledOptimizationReasonBits::decode(flags(kRelaxedLoad));
}

LanguageMode SharedFunctionInfo::language_mode() const {
  static_assert(LanguageModeSize == 2);
  return construct_language_mode(IsStrictBit::decode(flags(kRelaxedLoad)));
}

void SharedFunctionInfo::set_language_mode(LanguageMode language_mode) {
  static_assert(LanguageModeSize == 2);
  // We only allow language mode transitions that set the same language mode
  // again or go up in the chain:
  DCHECK(is_sloppy(this->language_mode()) || is_strict(language_mode));
  int hints = flags(kRelaxedLoad);
  hints = IsStrictBit::update(hints, is_strict(language_mode));
  set_flags(hints, kRelaxedStore);
  UpdateFunctionMapIndex();
}

FunctionKind SharedFunctionInfo::kind() const {
  static_assert(FunctionKindBits::kSize == kFunctionKindBitSize);
  return FunctionKindBits::decode(flags(kRelaxedLoad));
}

void SharedFunctionInfo::set_kind(FunctionKind kind) {
  int hints = flags(kRelaxedLoad);
  hints = FunctionKindBits::update(hints, kind);
  hints = IsClassConstructorBit::update(hints, IsClassConstructor(kind));
  set_flags(hints, kRelaxedStore);
  UpdateFunctionMapIndex();
}

bool SharedFunctionInfo::is_wrapped() const {
  return syntax_kind() == FunctionSyntaxKind::kWrapped;
}

bool SharedFunctionInfo::construct_as_builtin() const {
  return ConstructAsBuiltinBit::decode(flags(kRelaxedLoad));
}

void SharedFunctionInfo::CalculateConstructAsBuiltin() {
  bool uses_builtins_construct_stub = false;
  if (HasBuiltinId()) {
    Builtin id = builtin_id();
    if (id != Builtin::kCompileLazy && id != Builtin::kEmptyFunction) {
      uses_builtins_construct_stub = true;
    }
  } else if (IsApiFunction()) {
    uses_builtins_construct_stub = true;
  }

  int f = flags(kRelaxedLoad);
  f = ConstructAsBuiltinBit::update(f, uses_builtins_construct_stub);
  set_flags(f, kRelaxedStore);
}

uint16_t SharedFunctionInfo::age() const {
  return RELAXED_READ_UINT16_FIELD(*this, kAgeOffset);
}

void SharedFunctionInfo::set_age(uint16_t value) {
  RELAXED_WRITE_UINT16_FIELD(*this, kAgeOffset, value);
}

uint16_t SharedFunctionInfo::CompareExchangeAge(uint16_t expected_age,
                                                uint16_t new_age) {
  Address age_addr = address() + kAgeOffset;
  return base::AsAtomic16::Relaxed_CompareAndSwap(
      reinterpret_cast<base::Atomic16*>(age_addr), expected_age, new_age);
}

int SharedFunctionInfo::function_map_index() const {
  // Note: Must be kept in sync with the FastNewClosure builtin.
  int index = Context::FIRST_FUNCTION_MAP_INDEX +
              FunctionMapIndexBits::decode(flags(kRelaxedLoad));
  DCHECK_LE(index, Context::LAST_FUNCTION_MAP_INDEX);
  return index;
}

void SharedFunctionInfo::set_function_map_index(int index) {
  static_assert(Context::LAST_FUNCTION_MAP_INDEX <=
                Context::FIRST_FUNCTION_MAP_INDEX + FunctionMapIndexBits::kMax);
  DCHECK_LE(Context::FIRST_FUNCTION_MAP_INDEX, index);
  DCHECK_LE(index, Context::LAST_FUNCTION_MAP_INDEX);
  index -= Context::FIRST_FUNCTION_MAP_INDEX;
  set_flags(FunctionMapIndexBits::update(flags(kRelaxedLoad), index),
            kRelaxedStore);
}

void SharedFunctionInfo::clear_padding() { set_padding(0); }

void SharedFunctionInfo::UpdateFunctionMapIndex() {
  int map_index =
      Context::FunctionMapIndex(language_mode(), kind(), HasSharedName());
  set_function_map_index(map_index);
}

void SharedFunctionInfo::DontAdaptArguments() {
#if V8_ENABLE_WEBASSEMBLY
  // TODO(leszeks): Revise this DCHECK now that the code field is gone.
  DCHECK(!HasWasmExportedFunctionData());
#endif  // V8_ENABLE_WEBASSEMBLY
  if (HasBuiltinId()) {
    Builtin builtin = builtin_id();
    if (Builtins::KindOf(builtin) == Builtins::TFJ) {
      const int formal_parameter_count =
          Builtins::GetStackParameterCount(builtin);
      // If we have `kDontAdaptArgumentsSentinel` or no arguments, then we are
      // good. Otherwise this is a mismatch.
      if (formal_parameter_count != kDontAdaptArgumentsSentinel &&
          formal_parameter_count != JSParameterCount(0)) {
        FATAL(
            "Conflicting argument adaptation configuration (SFI vs call "
            "descriptor) for builtin: %s (%d)",
            Builtins::name(builtin), static_cast<int>(builtin));
      }
    }
  }
  TorqueGeneratedClass::set_formal_parameter_count(kDontAdaptArgumentsSentinel);
}

bool SharedFunctionInfo::IsDontAdaptArguments() const {
  return TorqueGeneratedClass::formal_parameter_count() ==
         kDontAdaptArgumentsSentinel;
}

DEF_ACQUIRE_GETTER(SharedFunctionInfo, scope_info, Tagged<ScopeInfo>) {
  Tagged<Object> maybe_scope_info = name_or_scope_info(cage_base, kAcquireLoad);
  if (IsScopeInfo(maybe_scope_info, cage_base)) {
    return Cast<ScopeInfo>(maybe_scope_info);
  }
  return GetReadOnlyRoots().empty_scope_info();
}

DEF_GETTER(SharedFunctionInfo, scope_info, Tagged<ScopeInfo>) {
  return scope_info(cage_base, kAcquireLoad);
}

Tagged<ScopeInfo> SharedFunctionInfo::EarlyScopeInfo(AcquireLoadTag tag) {
  // Keep in sync with the scope_info getter above.
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  Tagged<Object> maybe_scope_info = name_or_scope_info(cage_base, tag);
  if (IsScopeInfo(maybe_scope_info, cage_base)) {
    return Cast<ScopeInfo>(maybe_scope_info);
  }
  return EarlyGetReadOnlyRoots().empty_scope_info();
}

void SharedFunctionInfo::SetScopeInfo(Tagged<ScopeInfo> scope_info,
                                      WriteBarrierMode mode) {
  // Move the existing name onto the ScopeInfo.
  Tagged<NameOrScopeInfoT> name_or_scope_info =
      this->name_or_scope_info(kAcquireLoad);
  Tagged<UnionOf<Smi, String>> name;
  if (IsScopeInfo(name_or_scope_info)) {
    name = Cast<ScopeInfo>(name_or_scope_info)->FunctionName();
  } else {
    name = Cast<UnionOf<Smi, String>>(name_or_scope_info);
  }
  DCHECK(IsString(name) || name == kNoSharedNameSentinel);
  // ScopeInfo can get promoted to read-only space. Now that we reuse them after
  // flushing bytecode, we'll actually reinstall read-only scopeinfos on
  // SharedFunctionInfos if they required a context. The read-only scopeinfos
  // should already be fully initialized though, and hence will already have the
  // right FunctionName (and InferredName if relevant).
  if (scope_info->FunctionName() != name) {
    scope_info->SetFunctionName(name);
  }
  if (HasInferredName() && inferred_name()->length() != 0 &&
      scope_info->InferredFunctionName() != inferred_name()) {
    scope_info->SetInferredFunctionName(inferred_name());
  }
  set_name_or_scope_info(scope_info, kReleaseStore, mode);
}

void SharedFunctionInfo::set_raw_scope_info(Tagged<ScopeInfo> scope_info,
                                            WriteBarrierMode mode) {
  WRITE_FIELD(*this, kNameOrScopeInfoOffset, scope_info);
  CONDITIONAL_WRITE_BARRIER(*this, kNameOrScopeInfoOffset, scope_info, mode);
}

DEF_GETTER(SharedFunctionInfo, outer_scope_info, Tagged<HeapObject>) {
  DCHECK(!is_compiled());
  DCHECK(!HasFeedbackMetadata());
  return raw_outer_scope_info_or_feedback_metadata(cage_base);
}

bool SharedFunctionInfo::HasOuterScopeInfo() const {
  Tagged<ScopeInfo> outer_info;
  Tagged<ScopeInfo> info = scope_info(kAcquireLoad);
  if (info->IsEmpty()) {
    if (is_compiled()) return false;
    if (!IsScopeInfo(outer_scope_info())) return false;
    outer_info = Cast<ScopeInfo>(outer_scope_info());
  } else {
    if (!info->HasOuterScopeInfo()) return false;
    outer_info = info->OuterScopeInfo();
  }
  return !outer_info->IsEmpty();
}

Tagged<ScopeInfo> SharedFunctionInfo::GetOuterScopeInfo() const {
  DCHECK(HasOuterScopeInfo());
  Tagged<ScopeInfo> info = scope_info(kAcquireLoad);
  if (info->IsEmpty()) return Cast<ScopeInfo>(outer_scope_info());
  return info->OuterScopeInfo();
}

void SharedFunctionInfo::set_outer_scope_info(Tagged<HeapObject> value,
                                              WriteBarrierMode mode) {
  DCHECK(!is_compiled());
  DCHECK(IsTheHole(raw_outer_scope_info_or_feedback_metadata()));
  DCHECK(IsScopeInfo(value) || IsTheHole(value));
  DCHECK(scope_info()->IsEmpty());
  set_raw_outer_scope_info_or_feedback_metadata(value, mode);
}

bool SharedFunctionInfo::HasFeedbackMetadata() const {
  return IsFeedbackMetadata(raw_outer_scope_info_or_feedback_metadata());
}

bool SharedFunctionInfo::HasFeedbackMetadata(AcquireLoadTag tag) const {
  return IsFeedbackMetadata(raw_outer_scope_info_or_feedback_metadata(tag));
}

DEF_GETTER(SharedFunctionInfo, feedback_metadata, Tagged<FeedbackMetadata>) {
  DCHECK(HasFeedbackMetadata());
  return Cast<FeedbackMetadata>(
      raw_outer_scope_info_or_feedback_metadata(cage_base));
}

RELEASE_ACQUIRE_ACCESSORS_CHECKED2(SharedFunctionInfo, feedback_metadata,
                                   Tagged<FeedbackMetadata>,
                                   kOuterScopeInfoOrFeedbackMetadataOffset,
                                   HasFeedbackMetadata(kAcquireLoad),
                                   !HasFeedbackMetadata(kAcquireLoad) &&
                                       IsFeedbackMetadata(value))

bool SharedFunctionInfo::is_compiled() const {
  return GetUntrustedData() != Smi::FromEnum(Builtin::kCompileLazy) &&
         !HasUncompiledData();
}

template <typename IsolateT>
IsCompiledScope SharedFunctionInfo::is_compiled_scope(IsolateT* isolate) const {
  return IsCompiledScope(*this, isolate);
}

IsCompiledScope::IsCompiledScope(const Tagged<SharedFunctionInfo> shared,
                                 Isolate* isolate)
    : is_compiled_(shared->is_compiled()) {
  if (shared->HasBaselineCode()) {
    retain_code_ = handle(shared->baseline_code(kAcquireLoad), isolate);
  } else if (shared->HasBytecodeArray()) {
    retain_code_ = handle(shared->GetBytecodeArray(isolate), isolate);
  } else {
    retain_code_ = MaybeHandle<HeapObject>();
  }

  DCHECK_IMPLIES(!retain_code_.is_null(), is_compiled());
}

IsCompiledScope::IsCompiledScope(const Tagged<SharedFunctionInfo> shared,
                                 LocalIsolate* isolate)
    : is_compiled_(shared->is_compiled()) {
  if (shared->HasBaselineCode()) {
    retain_code_ = isolate->heap()->NewPersistentHandle(
        shared->baseline_code(kAcquireLoad));
  } else if (shared->HasBytecodeArray()) {
    retain_code_ =
        isolate->heap()->NewPersistentHandle(shared->GetBytecodeArray(isolate));
  } else {
    retain_code_ = MaybeHandle<HeapObject>();
  }

  DCHECK_IMPLIES(!retain_code_.is_null(), is_compiled());
}

bool SharedFunctionInfo::has_simple_parameters() {
  return scope_info(kAcquireLoad)->HasSimpleParameters();
}

bool SharedFunctionInfo::CanCollectSourcePosition(Isolate* isolate) {
  return v8_flags.enable_lazy_source_positions && HasBytecodeArray() &&
         !GetBytecodeArray(isolate)->HasSourcePositionTable();
}

bool SharedFunctionInfo::IsApiFunction() const {
  return IsFunctionTemplateInfo(GetUntrustedData());
}

DEF_GETTER(SharedFunctionInfo, api_func_data, Tagged<FunctionTemplateInfo>) {
  DCHECK(IsApiFunction());
  return Cast<FunctionTemplateInfo>(GetUntrustedData());
}

DEF_GETTER(SharedFunctionInfo, HasBytecodeArray, bool) {
  Tagged<Object> data = GetTrustedData();
  // If the SFI has no trusted data, GetTrustedData() will return Smi::zero().
  if (IsSmi(data)) return false;
  InstanceType instance_type =
      Cast<HeapObject>(data)->map(cage_base)->instance_type();
  return InstanceTypeChecker::IsBytecodeArray(instance_type) ||
         InstanceTypeChecker::IsInterpreterData(instance_type) ||
         InstanceTypeChecker::IsCode(instance_type);
}

template <typename IsolateT>
Tagged<BytecodeArray> SharedFunctionInfo::GetBytecodeArray(
    IsolateT* isolate) const {
  SharedMutexGuardIfOffThread<IsolateT, base::kShared> mutex_guard(
      isolate->shared_function_info_access(), isolate);

  DCHECK(HasBytecodeArray());

  Isolate* main_isolate = isolate->GetMainThreadIsolateUnsafe();
  std::optional<Tagged<DebugInfo>> debug_info = TryGetDebugInfo(main_isolate);
  if (debug_info.has_value() &&
      debug_info.value()->HasInstrumentedBytecodeArray()) {
    return debug_info.value()->OriginalBytecodeArray(main_isolate);
  }

  return GetActiveBytecodeArray(main_isolate);
}

Tagged<BytecodeArray> SharedFunctionInfo::GetActiveBytecodeArray(
    IsolateForSandbox isolate) const {
  Tagged<Object> data = GetTrustedData(isolate);
  if (IsCode(data)) {
    Tagged<Code> baseline_code = Cast<Code>(data);
    data = baseline_code->bytecode_or_interpreter_data();
  }
  if (IsBytecodeArray(data)) {
    return Cast<BytecodeArray>(data);
  } else {
    // We need an explicit check here since we use the
    // kUnknownIndirectPointerTag above and so don't have any type guarantees.
    SBXCHECK(IsInterpreterData(data));
    return Cast<InterpreterData>(data)->bytecode_array();
  }
}

void SharedFunctionInfo::SetActiveBytecodeArray(Tagged<BytecodeArray> bytecode,
                                                IsolateForSandbox isolate) {
  // We don't allow setting the active bytecode array on baseline-optimized
  // functions. They should have been flushed earlier.
  DCHECK(!HasBaselineCode());

  if (HasInterpreterData(isolate)) {
    interpreter_data(isolate)->set_bytecode_array(bytecode);
  } else {
    DCHECK(HasBytecodeArray());
    overwrite_bytecode_array(bytecode);
  }
}

void SharedFunctionInfo::set_bytecode_array(Tagged<BytecodeArray> bytecode) {
  DCHECK(GetUntrustedData() == Smi::FromEnum(Builtin::kCompileLazy) ||
         HasUncompiledData());
  SetTrustedData(bytecode);
}

void SharedFunctionInfo::overwrite_bytecode_array(
    Tagged<BytecodeArray> bytecode) {
  DCHECK(HasBytecodeArray());
  SetTrustedData(bytecode);
}

Tagged<Code> SharedFunctionInfo::InterpreterTrampoline(
    IsolateForSandbox isolate) const {
  DCHECK(HasInterpreterData(isolate));
  return interpreter_data(isolate)->interpreter_trampoline();
}

bool SharedFunctionInfo::HasInterpreterData(IsolateForSandbox isolate) const {
  Tagged<Object> data = GetTrustedData(isolate);
  if (IsCode(data)) {
    Tagged<Code> baseline_code = Cast<Code>(data);
    DCHECK_EQ(baseline_code->kind(), CodeKind::BASELINE);
    data = baseline_code->bytecode_or_interpreter_data();
  }
  return IsInterpreterData(data);
}

Tagged<InterpreterData> SharedFunctionInfo::interpreter_data(
    IsolateForSandbox isolate) const {
  DCHECK(HasInterpreterData(isolate));
  Tagged<Object> data = GetTrustedData(isolate);
  if (IsCode(data)) {
    Tagged<Code> baseline_code = Cast<Code>(data);
    DCHECK_EQ(baseline_code->kind(), CodeKind::BASELINE);
    data = baseline_code->bytecode_or_interpreter_data();
  }
  SBXCHECK(IsInterpreterData(data));
  return Cast<InterpreterData>(data);
}

void SharedFunctionInfo::set_interpreter_data(
    Tagged<InterpreterData> interpreter_data, WriteBarrierMode mode) {
  DCHECK(v8_flags.interpreted_frames_native_stack);
  DCHECK(!HasBaselineCode());
  SetTrustedData(interpreter_data, mode);
}

DEF_GETTER(SharedFunctionInfo, HasBaselineCode, bool) {
  Tagged<Object> data = GetTrustedData();
  if (IsCode(data, cage_base)) {
    DCHECK_EQ(Cast<Code>(data)->kind(), CodeKind::BASELINE);
    return true;
  }
  return false;
}

DEF_ACQUIRE_GETTER(SharedFunctionInfo, baseline_code, Tagged<Code>) {
  DCHECK(HasBaselineCode(cage_base));
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  return GetTrustedData<Code, kCodeIndirectPointerTag>(isolate);
}

void SharedFunctionInfo::set_baseline_code(Tagged<Code> baseline_code,
                                           ReleaseStoreTag tag,
                                           WriteBarrierMode mode) {
  DCHECK_EQ(baseline_code->kind(), CodeKind::BASELINE);
  SetTrustedData(baseline_code, mode);
}

void SharedFunctionInfo::FlushBaselineCode() {
  DCHECK(HasBaselineCode());
  Tagged<TrustedObject> new_data =
      baseline_code(kAcquireLoad)->bytecode_or_interpreter_data();
  DCHECK(IsBytecodeArray(new_data) || IsInterpreterData(new_data));
  SetTrustedData(Cast<ExposedTrustedObject>(new_data));
}

#if V8_ENABLE_WEBASSEMBLY
bool SharedFunctionInfo::HasAsmWasmData() const {
  return IsAsmWasmData(GetUntrustedData());
}

bool SharedFunctionInfo::HasWasmFunctionData() const {
  return IsWasmFunctionData(GetTrustedData());
}

bool SharedFunctionInfo::HasWasmExportedFunctionData() const {
  return IsWasmExportedFunctionData(GetTrustedData());
}

bool SharedFunctionInfo::HasWasmJSFunctionData() const {
  return IsWasmJSFunctionData(GetTrustedData());
}

bool SharedFunctionInfo::HasWasmCapiFunctionData() const {
  return IsWasmCapiFunctionData(GetTrustedData());
}

bool SharedFunctionInfo::HasWasmResumeData() const {
  return IsWasmResumeData(GetUntrustedData());
}

DEF_GETTER(SharedFunctionInfo, asm_wasm_data, Tagged<AsmWasmData>) {
  DCHECK(HasAsmWasmData());
  return Cast<AsmWasmData>(GetUntruste
"""


```