Response: Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The primary request is to summarize the functionality of the `factory-base.cc` file within the V8 engine and to illustrate its connection to JavaScript.

2. **Initial Scan for Keywords and Structure:**  Quickly skim the code, looking for recurring patterns, keywords, and included headers. This helps form an initial high-level idea.

    * **Headers:**  The included headers (`src/heap/factory-base.h`, `src/ast/ast.h`, `src/heap/heap-inl.h`, `src/objects/...`, etc.) suggest this code is heavily involved in memory management (heap) and object creation within V8. The `objects/` headers point to the definitions of various V8 internal object types. `ast/` indicates involvement with the Abstract Syntax Tree representation of JavaScript code.
    * **Namespaces:** The code is within `v8::internal`, confirming it's part of V8's internal implementation.
    * **Templates:** The use of `template <typename Impl>` and specializations for `Factory` and `LocalFactory` indicates a pattern where the core logic is shared, but specific implementations might vary. This suggests a design for different allocation contexts.
    * **Function Names:** Names like `NewHeapNumber`, `NewFixedArray`, `NewString`, `NewCode`, `NewScript`, etc., strongly suggest object creation and initialization.
    * **`read_only_roots()`:** This frequently used function points to a read-only area of the heap containing fundamental objects, hinting at bootstrapping and core object types.
    * **Allocation Types:**  Terms like `AllocationType::kYoung`, `kOld`, `kReadOnly`, `kTrusted`, `kSharedOld`  are prominent, reinforcing the idea of memory management and different heap spaces.

3. **Identify the Core Abstraction:** The name `FactoryBase` and the prevalence of "New..." functions strongly indicate this is an *object factory*. Its primary responsibility is creating and initializing V8 internal objects.

4. **Group Related Functions:** Start grouping the functions based on the type of object they create. For example:

    * **Numbers:** `NewHeapNumber`
    * **Arrays:** `NewFixedArray`, `NewWeakFixedArray`, `NewByteArray`
    * **Strings:** `NewString`, `InternalizeString`, `NewConsString`
    * **Code:** `NewCode`, `NewCodeWrapper`
    * **Functions:** `NewSharedFunctionInfo`, `NewSharedFunctionInfoWrapper`
    * **Scripts:** `NewScript`
    * **Other Objects:**  `NewStruct`, `NewAccessorPair`, `NewObjectBoilerplateDescription`, etc.

5. **Analyze Key Functions in Detail:**  Pick a few representative functions to understand *how* they create objects. For example:

    * **`NewHeapNumber`:**  Allocates raw memory, gets the `heap_number_map`, and casts the result. This reveals the basic allocation process and the use of "maps" (which define object structure).
    * **`NewFixedArray`:**  Similar allocation process, sets the length. The variants like `NewFixedArrayWithHoles` and `NewFixedArrayWithFiller` show different initialization strategies.
    * **`NewString` (various forms):** The presence of `InternalizeString` suggests string interning for efficiency. `NewConsString` indicates how string concatenation is handled at a low level. The distinction between one-byte and two-byte strings is also apparent.
    * **`NewCode`:**  More complex, involving setting various code-related attributes (instruction size, metadata size, etc.) and linking to bytecode or deoptimization data. This highlights the creation of executable code objects.
    * **`NewScript`:**  Associates source code with a script object, assigns an ID, etc. This connects the code to the parsed JavaScript.

6. **Focus on the JavaScript Connection:** Now, consider *how* these internal objects relate to JavaScript. Think about fundamental JavaScript concepts:

    * **Numbers:**  `NewHeapNumber` creates the internal representation of JavaScript numbers.
    * **Arrays:** `NewFixedArray` is the underlying structure for JavaScript arrays.
    * **Strings:** The various string creation functions are how JavaScript strings are represented in memory.
    * **Functions:** `NewSharedFunctionInfo` holds metadata about functions, crucial for execution.
    * **Code:**  `NewCode` creates the compiled JavaScript code that the engine executes.
    * **Scripts:** `NewScript` represents the loaded JavaScript source code.

7. **Craft JavaScript Examples:** For each key object type, create a simple JavaScript snippet that would lead to the creation of that object internally. This requires understanding the semantics of JavaScript and how V8 implements them. *Initially, might just think about the high-level action. Then refine to something more specific.*

    *  *Initial Thought:*  Creating a number. *Refined:* `let num = 10;`
    *  *Initial Thought:* Creating an array. *Refined:* `let arr = [1, 2, 3];`
    *  *Initial Thought:* Creating a string. *Refined:* `let str = "hello";` (and think about concatenation for `NewConsString`).
    *  *Initial Thought:* Defining a function. *Refined:* `function foo() {}`

8. **Structure the Summary:** Organize the findings logically:

    * **Purpose:** Clearly state the main function of `factory-base.cc`.
    * **Key Functions:**  List and briefly describe the important object creation functions.
    * **JavaScript Connection:** Explain how these internal objects map to JavaScript concepts.
    * **Examples:** Provide the JavaScript code examples.

9. **Review and Refine:** Read through the summary to ensure clarity, accuracy, and completeness. Check for any technical jargon that might need simplification. Ensure the JavaScript examples are correct and relevant. *For example, initially, might forget to mention string interning or the different string representations (one-byte, two-byte).*

By following these steps, we move from a raw code file to a meaningful explanation of its role within a complex system like the V8 JavaScript engine. The process involves both high-level understanding of the system's architecture and detailed examination of specific code sections.
## 功能归纳

`v8/src/heap/factory-base.cc` 文件是 V8 JavaScript 引擎中 **堆内存管理** 的一个核心组件，它定义了一个 **基础工厂类 (`FactoryBase`)**，用于 **创建和初始化各种 V8 内部使用的堆对象**。

更具体地说，它的主要功能可以归纳为以下几点：

1. **提供创建各种堆对象的接口:**  `FactoryBase` 类定义了许多 `New...` 开头的模板方法，用于创建 V8 引擎内部使用的各种对象，例如：
    * **基本类型:** `HeapNumber` (堆上的数字), `String` (字符串), `BigInt` (大整数)
    * **数据结构:** `FixedArray` (固定大小数组), `ByteArray` (字节数组), `WeakFixedArray` (弱引用数组), `SwissNameDictionary` (高效的字典)
    * **代码相关:** `Code` (已编译的代码), `BytecodeArray` (字节码数组), `SharedFunctionInfo` (共享函数信息), `Script` (脚本对象)
    * **其他内部对象:**  例如 `Map` (对象布局描述), `ScopeInfo` (作用域信息), `ObjectBoilerplateDescription` (对象模板描述) 等。

2. **封装对象分配和初始化的细节:**  `FactoryBase` 的方法隐藏了底层内存分配和对象初始化的复杂性。它负责：
    * **确定对象的大小:**  根据对象的类型和所需的数据量计算所需内存大小。
    * **从堆中分配内存:**  调用底层的堆分配器 (`AllocateRaw`, `AllocateRawWithImmortalMap`) 在合适的堆空间（新生代、老生代、只读堆等）中分配内存。
    * **设置对象的 Map:**  将新分配的对象与描述其结构和类型的 `Map` 对象关联起来。
    * **初始化对象的字段:**  根据对象的类型和需要，初始化对象的各个字段，例如长度、内容、标志位等。
    * **处理内联字符串:** 提供高效的字符串创建和内部化机制 (`InternalizeString`)，避免重复创建相同的字符串。

3. **提供不同分配策略的支持:**  `FactoryBase` 使用模板参数 `AllocationType` 来支持在不同的堆空间中分配对象，例如：
    * `kYoung`: 新生代，用于存放短期存活的对象。
    * `kOld`: 老生代，用于存放长期存活的对象。
    * `kReadOnly`: 只读堆，用于存放不可变的对象。
    * `kTrusted`:  可信任堆，用于存放 V8 内部可信任的对象。
    * `kSharedOld`: 共享老生代，用于存放在多个 Isolate 之间共享的对象。

4. **作为 `Factory` 和 `LocalFactory` 的基类:**  `FactoryBase` 是 `Factory` 和 `LocalFactory` 的基类。这两个类提供了在不同上下文（例如全局 Isolate 和本地 Isolate）中创建对象的具体实现。

## 与 Javascript 功能的关系 (并用 Javascript 举例说明)

`FactoryBase` 中创建的各种对象是 V8 引擎实现 JavaScript 语言特性的基础。当 JavaScript 代码执行时，V8 引擎会在内部创建和操作这些对象。

以下是一些 `FactoryBase` 创建的对象与 JavaScript 功能的对应关系，并用 JavaScript 代码举例说明：

**1. 数字 (`HeapNumber`)**

```javascript
let num = 10.5; // JavaScript 代码创建一个浮点数
```

当执行这行 JavaScript 代码时，V8 引擎内部会调用 `FactoryBase::NewHeapNumber` 来创建一个 `HeapNumber` 对象，用于存储 `10.5` 这个浮点数值。

**2. 字符串 (`String`)**

```javascript
let str = "hello"; // JavaScript 代码创建一个字符串
let str2 = "hello" + " world"; // JavaScript 代码进行字符串拼接
```

*  `let str = "hello";` 会导致 V8 调用 `FactoryBase::InternalizeString` (或其他字符串创建方法) 来创建一个内部字符串对象，并将 "hello" 存储在其中。
*  `let str2 = "hello" + " world";` 会导致 V8 调用 `FactoryBase::NewConsString` 创建一个 `ConsString` 对象，表示字符串的连接。如果结果字符串足够短，可能会直接创建 `SeqOneByteString` 或 `SeqTwoByteString`。

**3. 数组 (`FixedArray`)**

```javascript
let arr = [1, 2, 3]; // JavaScript 代码创建一个数组
```

当创建数组时，V8 会调用 `FactoryBase::NewFixedArray` 来分配一个 `FixedArray` 对象，用于存储数组的元素 (数字在这种情况下会是 `HeapNumber` 或 `Smi`)。

**4. 函数 (`SharedFunctionInfo`, `Code`)**

```javascript
function myFunction(x) {
  return x * 2;
} // JavaScript 代码定义一个函数
```

*  当定义函数 `myFunction` 时，V8 会调用 `FactoryBase::NewSharedFunctionInfoForLiteral` 创建一个 `SharedFunctionInfo` 对象，用于存储函数的元数据，例如函数名、参数个数等。
*  V8 还会将 JavaScript 代码编译成机器码，并调用 `FactoryBase::NewCode` 创建一个 `Code` 对象来存储编译后的代码。

**5. 对象 (隐式使用 `Map` 等)**

```javascript
let obj = { name: "Alice", age: 30 }; // JavaScript 代码创建一个对象
```

虽然 `FactoryBase` 没有直接创建 "JSObject" 这样的对象（通常由更高级的工厂类负责），但对象的创建会涉及到 `FactoryBase` 创建的 `Map` 对象。`Map` 对象描述了 `obj` 的结构（属性和类型），并且通常是在第一次遇到这种结构的对象时由 `FactoryBase` 创建的。

**6. 脚本 (`Script`)**

```javascript
// 当加载一个 JavaScript 文件时
```

当 V8 加载和解析 JavaScript 代码时，它会调用 `FactoryBase::NewScript` 创建一个 `Script` 对象，用于存储脚本的源代码、元数据等信息。

**总结:**

`v8/src/heap/factory-base.cc` 中定义的 `FactoryBase` 类是 V8 引擎中 **对象生命周期的起点**。它提供的对象创建能力是 V8 引擎实现各种 JavaScript 语言特性的基础，直接影响着 JavaScript 代码的执行效率和内存管理。 了解 `FactoryBase` 的功能有助于更深入地理解 V8 引擎的内部工作原理。

Prompt: 
```
这是目录为v8/src/heap/factory-base.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/factory-base.h"

#include "src/ast/ast-source-ranges.h"
#include "src/ast/ast.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/local-isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/heap/large-page-metadata-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/read-only-heap.h"
#include "src/logging/local-logger.h"
#include "src/logging/log.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/source-text-module.h"
#include "src/objects/string-inl.h"
#include "src/objects/string.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/template-objects-inl.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

template <typename Impl>
template <AllocationType allocation>
Handle<HeapNumber> FactoryBase<Impl>::NewHeapNumber() {
  static_assert(sizeof(HeapNumber) <= kMaxRegularHeapObjectSize);
  Tagged<Map> map = read_only_roots().heap_number_map();
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      sizeof(HeapNumber), allocation, map, kDoubleUnaligned);
  return handle(Cast<HeapNumber>(result), isolate());
}

template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kYoung>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kOld>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kReadOnly>();
template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<Factory>::NewHeapNumber<AllocationType::kSharedOld>();

template V8_EXPORT_PRIVATE Handle<HeapNumber>
FactoryBase<LocalFactory>::NewHeapNumber<AllocationType::kOld>();

template <typename Impl>
Handle<Struct> FactoryBase<Impl>::NewStruct(InstanceType type,
                                            AllocationType allocation) {
  ReadOnlyRoots roots = read_only_roots();
  Tagged<Map> map = Map::GetMapFor(roots, type);
  int size = map->instance_size();
  return handle(NewStructInternal(roots, map, size, allocation), isolate());
}

template <typename Impl>
Handle<AccessorPair> FactoryBase<Impl>::NewAccessorPair() {
  auto accessors =
      NewStructInternal<AccessorPair>(ACCESSOR_PAIR_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  accessors->set_getter(read_only_roots().null_value(), SKIP_WRITE_BARRIER);
  accessors->set_setter(read_only_roots().null_value(), SKIP_WRITE_BARRIER);
  return handle(accessors, isolate());
}

template <typename Impl>
Handle<Code> FactoryBase<Impl>::NewCode(const NewCodeOptions& options) {
  DirectHandle<CodeWrapper> wrapper = NewCodeWrapper();
  Tagged<Map> map = read_only_roots().code_map();
  int size = map->instance_size();
  Tagged<Code> code = Cast<Code>(
      AllocateRawWithImmortalMap(size, AllocationType::kTrusted, map));
  DisallowGarbageCollection no_gc;
  code->init_self_indirect_pointer(isolate());
  code->initialize_flags(options.kind, options.is_context_specialized,
                         options.is_turbofanned);
  code->set_builtin_id(options.builtin);
  code->set_instruction_size(options.instruction_size);
  code->set_metadata_size(options.metadata_size);
  code->set_inlined_bytecode_size(options.inlined_bytecode_size);
  code->set_osr_offset(options.osr_offset);
  code->set_handler_table_offset(options.handler_table_offset);
  code->set_constant_pool_offset(options.constant_pool_offset);
  code->set_code_comments_offset(options.code_comments_offset);
  code->set_builtin_jump_table_info_offset(
      options.builtin_jump_table_info_offset);
  code->set_unwinding_info_offset(options.unwinding_info_offset);
  code->set_parameter_count(options.parameter_count);

  // Set bytecode/interpreter data or deoptimization data.
  if (CodeKindUsesBytecodeOrInterpreterData(options.kind)) {
    DCHECK(options.deoptimization_data.is_null());
    Tagged<TrustedObject> data =
        *options.bytecode_or_interpreter_data.ToHandleChecked();
    DCHECK(IsBytecodeArray(data) || IsInterpreterData(data));
    code->set_bytecode_or_interpreter_data(data);
  } else if (CodeKindUsesDeoptimizationData(options.kind)) {
    DCHECK(options.bytecode_or_interpreter_data.is_null());
    code->set_deoptimization_data(
        *options.deoptimization_data.ToHandleChecked());
  } else {
    DCHECK(options.deoptimization_data.is_null());
    DCHECK(options.bytecode_or_interpreter_data.is_null());
    code->clear_deoptimization_data_and_interpreter_data();
  }

  // Set bytecode offset table or source position table.
  if (CodeKindUsesBytecodeOffsetTable(options.kind)) {
    DCHECK(options.source_position_table.is_null());
    code->set_bytecode_offset_table(
        *options.bytecode_offset_table.ToHandleChecked());
  } else if (CodeKindMayLackSourcePositionTable(options.kind)) {
    DCHECK(options.bytecode_offset_table.is_null());
    Handle<TrustedByteArray> table;
    if (options.source_position_table.ToHandle(&table)) {
      code->set_source_position_table(*table);
    } else {
      code->clear_source_position_table_and_bytecode_offset_table();
    }
  } else {
    DCHECK(options.bytecode_offset_table.is_null());
    code->set_source_position_table(
        *options.source_position_table.ToHandleChecked());
  }

  // Set instruction stream and entrypoint.
  Handle<InstructionStream> istream;
  if (options.instruction_stream.ToHandle(&istream)) {
    DCHECK_EQ(options.instruction_start, kNullAddress);
    code->SetInstructionStreamAndInstructionStart(isolate(), *istream);
  } else {
    DCHECK_NE(options.instruction_start, kNullAddress);
    code->set_raw_instruction_stream(Smi::zero(), SKIP_WRITE_BARRIER);
    code->SetInstructionStartForOffHeapBuiltin(isolate(),
                                               options.instruction_start);
  }

  wrapper->set_code(code);
  code->set_wrapper(*wrapper);

  code->clear_padding();
  return handle(code, isolate());
}

template <typename Impl>
Handle<CodeWrapper> FactoryBase<Impl>::NewCodeWrapper() {
  Handle<CodeWrapper> wrapper(
      Cast<CodeWrapper>(NewWithImmortalMap(read_only_roots().code_wrapper_map(),
                                           AllocationType::kOld)),
      isolate());
  // The CodeWrapper is typically created before the Code object it wraps, so
  // the code field cannot yet be set. However, as a heap verifier might see
  // the wrapper before the field can be set, we need to clear the field here.
  wrapper->clear_code();
  return wrapper;
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArray(int length,
                                                    AllocationType allocation) {
  return FixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedFixedArray> FactoryBase<Impl>::NewTrustedFixedArray(
    int length, AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);

  // TODO(saelo): Move this check to TrustedFixedArray::New once we have a RO
  // trusted space.
  if (length == 0) return empty_trusted_fixed_array();
  return TrustedFixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<ProtectedFixedArray> FactoryBase<Impl>::NewProtectedFixedArray(
    int length) {
  if (length == 0) return empty_protected_fixed_array();
  return ProtectedFixedArray::New(isolate(), length);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithMap(
    DirectHandle<Map> map, int length, AllocationType allocation) {
  // Zero-length case must be handled outside, where the knowledge about
  // the map is.
  DCHECK_LT(0, length);
  return NewFixedArrayWithFiller(
      map, length, read_only_roots().undefined_value_handle(), allocation);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithHoles(
    int length, AllocationType allocation) {
  DCHECK_LE(0, length);
  if (length == 0) return impl()->empty_fixed_array();
  return NewFixedArrayWithFiller(
      read_only_roots().fixed_array_map_handle(), length,
      read_only_roots().the_hole_value_handle(), allocation);
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithFiller(
    DirectHandle<Map> map, int length, DirectHandle<HeapObject> filler,
    AllocationType allocation) {
  Tagged<HeapObject> result = AllocateRawFixedArray(length, allocation);
  DisallowGarbageCollection no_gc;
  DCHECK(ReadOnlyHeap::Contains(*map));
  DCHECK(ReadOnlyHeap::Contains(*filler));
  result->set_map_after_allocation(isolate(), *map, SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(result);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(), *filler, length);
  return handle(array, isolate());
}

template <typename Impl>
Handle<FixedArray> FactoryBase<Impl>::NewFixedArrayWithZeroes(
    int length, AllocationType allocation) {
  DCHECK_LE(0, length);
  if (length == 0) return impl()->empty_fixed_array();
  if (length > FixedArray::kMaxLength) {
    FATAL("Invalid FixedArray size %d", length);
  }
  Tagged<HeapObject> result = AllocateRawFixedArray(length, allocation);
  DisallowGarbageCollection no_gc;
  result->set_map_after_allocation(
      isolate(), read_only_roots().fixed_array_map(), SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(result);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(), Smi::zero(), length);
  return handle(array, isolate());
}

template <typename Impl>
Handle<FixedArrayBase> FactoryBase<Impl>::NewFixedDoubleArray(
    int length, AllocationType allocation) {
  return FixedDoubleArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<WeakFixedArray> FactoryBase<Impl>::NewWeakFixedArrayWithMap(
    Tagged<Map> map, int length, AllocationType allocation) {
  // Zero-length case must be handled outside.
  DCHECK_LT(0, length);
  DCHECK(ReadOnlyHeap::Contains(map));

  Tagged<HeapObject> result =
      AllocateRawArray(WeakFixedArray::SizeFor(length), allocation);
  result->set_map_after_allocation(isolate(), map, SKIP_WRITE_BARRIER);
  DisallowGarbageCollection no_gc;
  Tagged<WeakFixedArray> array = Cast<WeakFixedArray>(result);
  array->set_length(length);
  MemsetTagged(ObjectSlot(array->RawFieldOfFirstElement()),
               read_only_roots().undefined_value(), length);

  return handle(array, isolate());
}

template <typename Impl>
Handle<WeakFixedArray> FactoryBase<Impl>::NewWeakFixedArray(
    int length, AllocationType allocation) {
  return WeakFixedArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedWeakFixedArray> FactoryBase<Impl>::NewTrustedWeakFixedArray(
    int length) {
  // TODO(saelo): Move this check to TrustedWeakFixedArray::New once we have a
  // RO trusted space.
  if (length == 0) return empty_trusted_weak_fixed_array();
  return TrustedWeakFixedArray::New(isolate(), length);
}

template <typename Impl>
Handle<ByteArray> FactoryBase<Impl>::NewByteArray(int length,
                                                  AllocationType allocation) {
  return ByteArray::New(isolate(), length, allocation);
}

template <typename Impl>
Handle<TrustedByteArray> FactoryBase<Impl>::NewTrustedByteArray(
    int length, AllocationType allocation_type) {
  if (length == 0) return empty_trusted_byte_array();
  return TrustedByteArray::New(isolate(), length, allocation_type);
}

template <typename Impl>
Handle<DeoptimizationLiteralArray>
FactoryBase<Impl>::NewDeoptimizationLiteralArray(int length) {
  return Cast<DeoptimizationLiteralArray>(NewTrustedWeakFixedArray(length));
}

template <typename Impl>
Handle<DeoptimizationFrameTranslation>
FactoryBase<Impl>::NewDeoptimizationFrameTranslation(int length) {
  return Cast<DeoptimizationFrameTranslation>(NewTrustedByteArray(length));
}

template <typename Impl>
Handle<BytecodeArray> FactoryBase<Impl>::NewBytecodeArray(
    int length, const uint8_t* raw_bytecodes, int frame_size,
    uint16_t parameter_count, uint16_t max_arguments,
    DirectHandle<TrustedFixedArray> constant_pool,
    DirectHandle<TrustedByteArray> handler_table, AllocationType allocation) {
  DCHECK(allocation == AllocationType::kTrusted ||
         allocation == AllocationType::kSharedTrusted);
  if (length < 0 || length > BytecodeArray::kMaxLength) {
    FATAL("Fatal JavaScript invalid size error %d", length);
    UNREACHABLE();
  }
  DirectHandle<BytecodeWrapper> wrapper = NewBytecodeWrapper();
  int size = BytecodeArray::SizeFor(length);
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, allocation, read_only_roots().bytecode_array_map());
  DisallowGarbageCollection no_gc;
  Tagged<BytecodeArray> instance = Cast<BytecodeArray>(result);
  instance->init_self_indirect_pointer(isolate());
  instance->set_length(length);
  instance->set_frame_size(frame_size);
  instance->set_parameter_count(parameter_count);
  instance->set_max_arguments(max_arguments);
  instance->set_incoming_new_target_or_generator_register(
      interpreter::Register::invalid_value());
  instance->set_constant_pool(*constant_pool);
  instance->set_handler_table(*handler_table);
  instance->clear_source_position_table(kReleaseStore);
  instance->set_wrapper(*wrapper);
  CopyBytes(reinterpret_cast<uint8_t*>(instance->GetFirstBytecodeAddress()),
            raw_bytecodes, length);
  instance->clear_padding();
  wrapper->set_bytecode(instance);
  return handle(instance, isolate());
}

template <typename Impl>
Handle<BytecodeWrapper> FactoryBase<Impl>::NewBytecodeWrapper(
    AllocationType allocation) {
  DCHECK(allocation == AllocationType::kOld ||
         allocation == AllocationType::kSharedOld);

  Handle<BytecodeWrapper> wrapper(
      Cast<BytecodeWrapper>(NewWithImmortalMap(
          read_only_roots().bytecode_wrapper_map(), allocation)),
      isolate());
  // The BytecodeWrapper is typically created before the BytecodeArray it
  // wraps, so the bytecode field cannot yet be set. However, as a heap
  // verifier might see the wrapper before the field can be set, we need to
  // clear the field here.
  wrapper->clear_bytecode();
  return wrapper;
}

template <typename Impl>
Handle<Script> FactoryBase<Impl>::NewScript(
    DirectHandle<UnionOf<String, Undefined>> source,
    ScriptEventType script_event_type) {
  return NewScriptWithId(source, isolate()->GetNextScriptId(),
                         script_event_type);
}

template <typename Impl>
Handle<Script> FactoryBase<Impl>::NewScriptWithId(
    DirectHandle<UnionOf<String, Undefined>> source, int script_id,
    ScriptEventType script_event_type) {
  DCHECK(IsString(*source) || IsUndefined(*source));
  // Create and initialize script object.
  ReadOnlyRoots roots = read_only_roots();
  Handle<Script> script = handle(
      NewStructInternal<Script>(SCRIPT_TYPE, AllocationType::kOld), isolate());
  {
    DisallowGarbageCollection no_gc;
    Tagged<Script> raw = *script;
    raw->set_source(*source);
    raw->set_name(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_id(script_id);
    raw->set_line_offset(0);
    raw->set_column_offset(0);
    raw->set_context_data(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_type(Script::Type::kNormal);
    raw->set_line_ends(Smi::zero());
    raw->set_eval_from_shared_or_wrapped_arguments(roots.undefined_value(),
                                                   SKIP_WRITE_BARRIER);
    raw->set_eval_from_position(0);
    raw->set_infos(roots.empty_weak_fixed_array(), SKIP_WRITE_BARRIER);
    raw->set_flags(0);
    raw->set_host_defined_options(roots.empty_fixed_array(),
                                  SKIP_WRITE_BARRIER);
    raw->set_source_hash(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_compiled_lazy_function_positions(roots.undefined_value(),
                                              SKIP_WRITE_BARRIER);
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
    raw->set_script_or_modules(roots.empty_array_list());
#endif
  }
  impl()->ProcessNewScript(script, script_event_type);
  return script;
}

template <typename Impl>
Handle<SloppyArgumentsElements> FactoryBase<Impl>::NewSloppyArgumentsElements(
    int length, DirectHandle<Context> context,
    DirectHandle<FixedArray> arguments, AllocationType allocation) {
  Tagged<SloppyArgumentsElements> result =
      Cast<SloppyArgumentsElements>(AllocateRawWithImmortalMap(
          SloppyArgumentsElements::SizeFor(length), allocation,
          read_only_roots().sloppy_arguments_elements_map()));

  DisallowGarbageCollection no_gc;
  WriteBarrierMode write_barrier_mode = allocation == AllocationType::kYoung
                                            ? SKIP_WRITE_BARRIER
                                            : UPDATE_WRITE_BARRIER;
  result->set_length(length);
  result->set_context(*context, write_barrier_mode);
  result->set_arguments(*arguments, write_barrier_mode);
  return handle(result, isolate());
}

template <typename Impl>
Handle<ArrayList> FactoryBase<Impl>::NewArrayList(int size,
                                                  AllocationType allocation) {
  return ArrayList::New(isolate(), size, allocation);
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfoForLiteral(
    FunctionLiteral* literal, DirectHandle<Script> script, bool is_toplevel) {
  FunctionKind kind = literal->kind();
  Handle<SharedFunctionInfo> shared =
      NewSharedFunctionInfo(literal->GetName(isolate()), {},
                            Builtin::kCompileLazy, 0, kDontAdapt, kind);
  shared->set_function_literal_id(literal->function_literal_id());
  literal->set_shared_function_info(shared);
  SharedFunctionInfo::InitFromFunctionLiteral(isolate(), literal, is_toplevel);
  shared->SetScript(isolate(), read_only_roots(), *script,
                    literal->function_literal_id(), false);
  return shared;
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::CloneSharedFunctionInfo(
    DirectHandle<SharedFunctionInfo> other) {
  Tagged<Map> map = read_only_roots().shared_function_info_map();

  Tagged<SharedFunctionInfo> shared =
      Cast<SharedFunctionInfo>(NewWithImmortalMap(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;

  shared->clear_padding();
  shared->CopyFrom(*other, isolate());

  return handle(shared, isolate());
}

template <typename Impl>
Handle<SharedFunctionInfoWrapper>
FactoryBase<Impl>::NewSharedFunctionInfoWrapper(
    DirectHandle<SharedFunctionInfo> sfi) {
  Tagged<Map> map = read_only_roots().shared_function_info_wrapper_map();
  Tagged<SharedFunctionInfoWrapper> wrapper = Cast<SharedFunctionInfoWrapper>(
      NewWithImmortalMap(map, AllocationType::kTrusted));

  wrapper->set_shared_info(*sfi);

  return handle(wrapper, isolate());
}

template <typename Impl>
Handle<PreparseData> FactoryBase<Impl>::NewPreparseData(int data_length,
                                                        int children_length) {
  int size = PreparseData::SizeFor(data_length, children_length);
  Tagged<PreparseData> result = Cast<PreparseData>(AllocateRawWithImmortalMap(
      size, AllocationType::kOld, read_only_roots().preparse_data_map()));
  DisallowGarbageCollection no_gc;
  result->set_data_length(data_length);
  result->set_children_length(children_length);
  MemsetTagged(result->inner_data_start(), read_only_roots().null_value(),
               children_length);
  result->clear_padding();
  return handle(result, isolate());
}

template <typename Impl>
Handle<UncompiledDataWithoutPreparseData>
FactoryBase<Impl>::NewUncompiledDataWithoutPreparseData(
    Handle<String> inferred_name, int32_t start_position,
    int32_t end_position) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithoutPreparseData(
      inferred_name, start_position, end_position, AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithPreparseData>
FactoryBase<Impl>::NewUncompiledDataWithPreparseData(
    Handle<String> inferred_name, int32_t start_position, int32_t end_position,
    Handle<PreparseData> preparse_data) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithPreparseData(
      inferred_name, start_position, end_position, preparse_data,
      AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithoutPreparseDataWithJob>
FactoryBase<Impl>::NewUncompiledDataWithoutPreparseDataWithJob(
    Handle<String> inferred_name, int32_t start_position,
    int32_t end_position) {
  return TorqueGeneratedFactory<Impl>::
      NewUncompiledDataWithoutPreparseDataWithJob(inferred_name, start_position,
                                                  end_position, kNullAddress,
                                                  AllocationType::kTrusted);
}

template <typename Impl>
Handle<UncompiledDataWithPreparseDataAndJob>
FactoryBase<Impl>::NewUncompiledDataWithPreparseDataAndJob(
    Handle<String> inferred_name, int32_t start_position, int32_t end_position,
    Handle<PreparseData> preparse_data) {
  return TorqueGeneratedFactory<Impl>::NewUncompiledDataWithPreparseDataAndJob(
      inferred_name, start_position, end_position, preparse_data, kNullAddress,
      AllocationType::kTrusted);
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfo(
    MaybeDirectHandle<String> maybe_name,
    MaybeDirectHandle<HeapObject> maybe_function_data, Builtin builtin, int len,
    AdaptArguments adapt, FunctionKind kind) {
  Handle<SharedFunctionInfo> shared =
      NewSharedFunctionInfo(AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> raw = *shared;
  // Function names are assumed to be flat elsewhere.
  DirectHandle<String> shared_name;
  bool has_shared_name = maybe_name.ToHandle(&shared_name);
  if (has_shared_name) {
    DCHECK(shared_name->IsFlat());
    raw->set_name_or_scope_info(*shared_name, kReleaseStore);
  } else {
    DCHECK_EQ(raw->name_or_scope_info(kAcquireLoad),
              SharedFunctionInfo::kNoSharedNameSentinel);
  }

  DirectHandle<HeapObject> function_data;
  if (maybe_function_data.ToHandle(&function_data)) {
    // If we pass function_data then we shouldn't pass a builtin index, and
    // the function_data should not be code with a builtin.
    DCHECK(!Builtins::IsBuiltinId(builtin));
    DCHECK(!IsInstructionStream(*function_data));
    DCHECK(!IsCode(*function_data));
    if (IsExposedTrustedObject(*function_data)) {
      raw->SetTrustedData(Cast<ExposedTrustedObject>(*function_data));
    } else {
      raw->SetUntrustedData(*function_data);
    }
  } else if (Builtins::IsBuiltinId(builtin)) {
    raw->set_builtin_id(builtin);
  } else {
    DCHECK(raw->HasBuiltinId());
    DCHECK_EQ(Builtin::kIllegal, raw->builtin_id());
  }

  raw->CalculateConstructAsBuiltin();
  raw->set_kind(kind);

  switch (adapt) {
    case AdaptArguments::kYes:
      raw->set_formal_parameter_count(JSParameterCount(len));
      break;
    case AdaptArguments::kNo:
      raw->DontAdaptArguments();
      break;
  }
  raw->set_length(len);

  DCHECK_IMPLIES(raw->HasBuiltinId(),
                 Builtins::CheckFormalParameterCount(
                     raw->builtin_id(), raw->length(),
                     raw->internal_formal_parameter_count_with_receiver()));
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) raw->SharedFunctionInfoVerify(isolate());
#endif  // VERIFY_HEAP
  return shared;
}

template <typename Impl>
Handle<ObjectBoilerplateDescription>
FactoryBase<Impl>::NewObjectBoilerplateDescription(int boilerplate,
                                                   int all_properties,
                                                   int index_keys,
                                                   bool has_seen_proto) {
  return ObjectBoilerplateDescription::New(
      isolate(), boilerplate, all_properties, index_keys, has_seen_proto,
      AllocationType::kOld);
}

template <typename Impl>
Handle<ArrayBoilerplateDescription>
FactoryBase<Impl>::NewArrayBoilerplateDescription(
    ElementsKind elements_kind, DirectHandle<FixedArrayBase> constant_values) {
  auto result = NewStructInternal<ArrayBoilerplateDescription>(
      ARRAY_BOILERPLATE_DESCRIPTION_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_elements_kind(elements_kind);
  result->set_constant_elements(*constant_values);
  return handle(result, isolate());
}

template <typename Impl>
Handle<RegExpDataWrapper> FactoryBase<Impl>::NewRegExpDataWrapper() {
  Handle<RegExpDataWrapper> wrapper(
      Cast<RegExpDataWrapper>(NewWithImmortalMap(
          read_only_roots().regexp_data_wrapper_map(), AllocationType::kOld)),
      isolate());
  wrapper->clear_data();
  return wrapper;
}

template <typename Impl>
Handle<RegExpBoilerplateDescription>
FactoryBase<Impl>::NewRegExpBoilerplateDescription(
    DirectHandle<RegExpData> data, DirectHandle<String> source,
    Tagged<Smi> flags) {
  auto result = NewStructInternal<RegExpBoilerplateDescription>(
      REG_EXP_BOILERPLATE_DESCRIPTION_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_data(*data);
  result->set_source(*source);
  result->set_flags(flags.value());
  return handle(result, isolate());
}

template <typename Impl>
Handle<TemplateObjectDescription>
FactoryBase<Impl>::NewTemplateObjectDescription(
    DirectHandle<FixedArray> raw_strings,
    DirectHandle<FixedArray> cooked_strings) {
  DCHECK_EQ(raw_strings->length(), cooked_strings->length());
  DCHECK_LT(0, raw_strings->length());
  auto result = NewStructInternal<TemplateObjectDescription>(
      TEMPLATE_OBJECT_DESCRIPTION_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_raw_strings(*raw_strings);
  result->set_cooked_strings(*cooked_strings);
  return handle(result, isolate());
}

template <typename Impl>
Handle<FeedbackMetadata> FactoryBase<Impl>::NewFeedbackMetadata(
    int slot_count, int create_closure_slot_count, AllocationType allocation) {
  DCHECK_LE(0, slot_count);
  int size = FeedbackMetadata::SizeFor(slot_count, create_closure_slot_count);
  Tagged<FeedbackMetadata> result =
      Cast<FeedbackMetadata>(AllocateRawWithImmortalMap(
          size, allocation, read_only_roots().feedback_metadata_map()));
  result->set_slot_count(slot_count);
  result->set_create_closure_slot_count(create_closure_slot_count);

  // Initialize the data section to 0.
  int data_size = size - FeedbackMetadata::kHeaderSize;
  Address data_start = result->address() + FeedbackMetadata::kHeaderSize;
  memset(reinterpret_cast<uint8_t*>(data_start), 0, data_size);
  // Fields have been zeroed out but not initialized, so this object will not
  // pass object verification at this point.
  return handle(result, isolate());
}

template <typename Impl>
Handle<CoverageInfo> FactoryBase<Impl>::NewCoverageInfo(
    const ZoneVector<SourceRange>& slots) {
  const int slot_count = static_cast<int>(slots.size());

  int size = CoverageInfo::SizeFor(slot_count);
  Tagged<Map> map = read_only_roots().coverage_info_map();
  Tagged<CoverageInfo> info = Cast<CoverageInfo>(
      AllocateRawWithImmortalMap(size, AllocationType::kOld, map));
  info->set_slot_count(slot_count);
  for (int i = 0; i < slot_count; i++) {
    SourceRange range = slots[i];
    info->InitializeSlot(i, range.start, range.end);
  }
  return handle(info, isolate());
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::MakeOrFindTwoCharacterString(uint16_t c1,
                                                               uint16_t c2) {
  if ((c1 | c2) <= unibrow::Latin1::kMaxChar) {
    uint8_t buffer[] = {static_cast<uint8_t>(c1), static_cast<uint8_t>(c2)};
    return InternalizeString(base::Vector<const uint8_t>(buffer, 2));
  }
  uint16_t buffer[] = {c1, c2};
  return InternalizeString(base::Vector<const uint16_t>(buffer, 2));
}

template <typename Impl>
template <class StringTableKey>
Handle<String> FactoryBase<Impl>::InternalizeStringWithKey(
    StringTableKey* key) {
  return indirect_handle(isolate()->string_table()->LookupKey(isolate(), key),
                         isolate());
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        OneByteStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        TwoByteStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        SeqOneByteSubStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<Factory>::InternalizeStringWithKey(
        SeqTwoByteSubStringKey* key);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<LocalFactory>::InternalizeStringWithKey(
        OneByteStringKey* key);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<String> FactoryBase<LocalFactory>::InternalizeStringWithKey(
        TwoByteStringKey* key);

template <typename Impl>
Handle<String> FactoryBase<Impl>::InternalizeString(
    base::Vector<const uint8_t> string, bool convert_encoding) {
  SequentialStringKey<uint8_t> key(string, HashSeed(read_only_roots()),
                                   convert_encoding);
  return InternalizeStringWithKey(&key);
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::InternalizeString(
    base::Vector<const uint16_t> string, bool convert_encoding) {
  SequentialStringKey<uint16_t> key(string, HashSeed(read_only_roots()),
                                    convert_encoding);
  return InternalizeStringWithKey(&key);
}

template <typename Impl>
Handle<SeqOneByteString> FactoryBase<Impl>::NewOneByteInternalizedString(
    base::Vector<const uint8_t> str, uint32_t raw_hash_field) {
  Handle<SeqOneByteString> result =
      AllocateRawOneByteInternalizedString(str.length(), raw_hash_field);
  // No synchronization is needed since the shared string hasn't yet escaped to
  // script.
  DisallowGarbageCollection no_gc;
  MemCopy(result->GetChars(no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
          str.begin(), str.length());
  return result;
}

template <typename Impl>
Handle<SeqTwoByteString> FactoryBase<Impl>::NewTwoByteInternalizedString(
    base::Vector<const base::uc16> str, uint32_t raw_hash_field) {
  Handle<SeqTwoByteString> result =
      AllocateRawTwoByteInternalizedString(str.length(), raw_hash_field);
  // No synchronization is needed since the shared string hasn't yet escaped to
  // script.
  DisallowGarbageCollection no_gc;
  MemCopy(result->GetChars(no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
          str.begin(), str.length() * base::kUC16Size);
  return result;
}

template <typename Impl>
Handle<SeqOneByteString>
FactoryBase<Impl>::NewOneByteInternalizedStringFromTwoByte(
    base::Vector<const base::uc16> str, uint32_t raw_hash_field) {
  Handle<SeqOneByteString> result =
      AllocateRawOneByteInternalizedString(str.length(), raw_hash_field);
  DisallowGarbageCollection no_gc;
  CopyChars(
      result->GetChars(no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
      str.begin(), str.length());
  return result;
}

template <typename Impl>
template <typename SeqStringT>
MaybeHandle<SeqStringT> FactoryBase<Impl>::NewRawStringWithMap(
    int length, Tagged<Map> map, AllocationType allocation) {
  DCHECK(SeqStringT::IsCompatibleMap(map, read_only_roots()));
  DCHECK_IMPLIES(!StringShape(map).IsShared(),
                 RefineAllocationTypeForInPlaceInternalizableString(
                     allocation, map) == allocation);
  if (length < 0 || static_cast<uint32_t>(length) > String::kMaxLength) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }
  DCHECK_GT(length, 0);  // Use Factory::empty_string() instead.
  int size = SeqStringT::SizeFor(length);
  DCHECK_GE(ObjectTraits<SeqStringT>::kMaxSize, size);

  Tagged<SeqStringT> string =
      Cast<SeqStringT>(AllocateRawWithImmortalMap(size, allocation, map));
  DisallowGarbageCollection no_gc;
  string->clear_padding_destructively(length);
  string->set_length(length);
  string->set_raw_hash_field(String::kEmptyHashField);
  DCHECK_EQ(size, string->Size());
  return handle(string, isolate());
}

template <typename Impl>
MaybeHandle<SeqOneByteString> FactoryBase<Impl>::NewRawOneByteString(
    int length, AllocationType allocation) {
  Tagged<Map> map = read_only_roots().seq_one_byte_string_map();
  return NewRawStringWithMap<SeqOneByteString>(
      length, map,
      RefineAllocationTypeForInPlaceInternalizableString(allocation, map));
}

template <typename Impl>
MaybeHandle<SeqTwoByteString> FactoryBase<Impl>::NewRawTwoByteString(
    int length, AllocationType allocation) {
  Tagged<Map> map = read_only_roots().seq_two_byte_string_map();
  return NewRawStringWithMap<SeqTwoByteString>(
      length, map,
      RefineAllocationTypeForInPlaceInternalizableString(allocation, map));
}

template <typename Impl>
MaybeHandle<SeqOneByteString> FactoryBase<Impl>::NewRawSharedOneByteString(
    int length) {
  return NewRawStringWithMap<SeqOneByteString>(
      length, read_only_roots().shared_seq_one_byte_string_map(),
      AllocationType::kSharedOld);
}

template <typename Impl>
MaybeHandle<SeqTwoByteString> FactoryBase<Impl>::NewRawSharedTwoByteString(
    int length) {
  return NewRawStringWithMap<SeqTwoByteString>(
      length, read_only_roots().shared_seq_two_byte_string_map(),
      AllocationType::kSharedOld);
}

template <typename Impl>
MaybeHandle<String> FactoryBase<Impl>::NewConsString(
    Handle<String> left, Handle<String> right, AllocationType allocation) {
  if (IsThinString(*left)) {
    left = handle(Cast<ThinString>(*left)->actual(), isolate());
  }
  if (IsThinString(*right)) {
    right = handle(Cast<ThinString>(*right)->actual(), isolate());
  }
  uint32_t left_length = left->length();
  if (left_length == 0) return right;
  uint32_t right_length = right->length();
  if (right_length == 0) return left;

  uint32_t length = left_length + right_length;

  if (length == 2) {
    uint16_t c1 = left->Get(0, isolate());
    uint16_t c2 = right->Get(0, isolate());
    return MakeOrFindTwoCharacterString(c1, c2);
  }

  // Make sure that an out of memory exception is thrown if the length
  // of the new cons string is too large.
  if (length > String::kMaxLength || length < 0) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }

  bool left_is_one_byte = left->IsOneByteRepresentation();
  bool right_is_one_byte = right->IsOneByteRepresentation();
  bool is_one_byte = left_is_one_byte && right_is_one_byte;

  // If the resulting string is small make a flat string.
  if (length < ConsString::kMinLength) {
    // Note that neither of the two inputs can be a slice because:
    static_assert(ConsString::kMinLength <= SlicedString::kMinLength);
    DCHECK(left->IsFlat());
    DCHECK(right->IsFlat());

    static_assert(ConsString::kMinLength <= String::kMaxLength);
    if (is_one_byte) {
      Handle<SeqOneByteString> result =
          NewRawOneByteString(length, allocation).ToHandleChecked();
      DisallowGarbageCollection no_gc;
      SharedStringAccessGuardIfNeeded access_guard(isolate());
      uint8_t* dest = result->GetChars(no_gc, access_guard);
      // Copy left part.
      {
        const uint8_t* src =
            left->template GetDirectStringChars<uint8_t>(no_gc, access_guard);
        CopyChars(dest, src, left_length);
      }
      // Copy right part.
      {
        const uint8_t* src =
            right->template GetDirectStringChars<uint8_t>(no_gc, access_guard);
        CopyChars(dest + left_length, src, right_length);
      }
      return result;
    }

    Handle<SeqTwoByteString> result =
        NewRawTwoByteString(length, allocation).ToHandleChecked();

    DisallowGarbageCollection no_gc;
    SharedStringAccessGuardIfNeeded access_guard(isolate());
    base::uc16* sink = result->GetChars(no_gc, access_guard);
    String::WriteToFlat(*left, sink, 0, left->length(), access_guard);
    String::WriteToFlat(*right, sink + left->length(), 0, right->length(),
                        access_guard);
    return result;
  }

  return NewConsString(left, right, length, is_one_byte, allocation);
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::NewConsString(DirectHandle<String> left,
                                                DirectHandle<String> right,
                                                int length, bool one_byte,
                                                AllocationType allocation) {
  DCHECK(!IsThinString(*left));
  DCHECK(!IsThinString(*right));
  DCHECK_GE(length, ConsString::kMinLength);
  DCHECK_LE(length, String::kMaxLength);

  Tagged<ConsString> result = Cast<ConsString>(
      one_byte ? NewWithImmortalMap(
                     read_only_roots().cons_one_byte_string_map(), allocation)
               : NewWithImmortalMap(
                     read_only_roots().cons_two_byte_string_map(), allocation));

  DisallowGarbageCollection no_gc;
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  result->set_raw_hash_field(String::kEmptyHashField);
  result->set_length(length);
  result->set_first(*left, mode);
  result->set_second(*right, mode);
  return handle(result, isolate());
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::LookupSingleCharacterStringFromCode(
    uint16_t code) {
  if (code <= unibrow::Latin1::kMaxChar) {
    DisallowGarbageCollection no_gc;
    Tagged<Object> value = single_character_string_table()->get(code);
    DCHECK_NE(value, *undefined_value());
    return handle(Cast<String>(value), isolate());
  }
  uint16_t buffer[] = {code};
  return InternalizeString(base::Vector<const uint16_t>(buffer, 1));
}

template <typename Impl>
MaybeHandle<String> FactoryBase<Impl>::NewStringFromOneByte(
    base::Vector<const uint8_t> string, AllocationType allocation) {
  DCHECK_NE(allocation, AllocationType::kReadOnly);
  int length = string.length();
  if (length == 0) return empty_string();
  if (length == 1) return LookupSingleCharacterStringFromCode(string[0]);
  Handle<SeqOneByteString> result;
  ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                             NewRawOneByteString(string.length(), allocation));

  DisallowGarbageCollection no_gc;
  // Copy the characters into the new object.
  // SharedStringAccessGuardIfNeeded is NotNeeded because {result} is freshly
  // allocated and hasn't escaped the factory yet, so it can't be concurrently
  // accessed.
  CopyChars(Cast<SeqOneByteString>(*result)->GetChars(
                no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
            string.begin(), length);
  return result;
}
namespace {

template <typename Impl>
V8_INLINE Handle<String> CharToString(FactoryBase<Impl>* factory,
                                      const char* string,
                                      NumberCacheMode mode) {
  // We tenure the allocated string since it is referenced from the
  // number-string cache which lives in the old space.
  AllocationType type = mode == NumberCacheMode::kIgnore
                            ? AllocationType::kYoung
                            : AllocationType::kOld;
  return factory->NewStringFromAsciiChecked(string, type);
}

}  // namespace

template <typename Impl>
Handle<String> FactoryBase<Impl>::NumberToString(DirectHandle<Object> number,
                                                 NumberCacheMode mode) {
  SLOW_DCHECK(IsNumber(*number));
  if (IsSmi(*number)) return SmiToString(Cast<Smi>(*number), mode);

  double double_value = Cast<HeapNumber>(number)->value();
  // Try to canonicalize doubles.
  int smi_value;
  if (DoubleToSmiInteger(double_value, &smi_value)) {
    return SmiToString(Smi::FromInt(smi_value), mode);
  }
  return HeapNumberToString(Cast<HeapNumber>(number), double_value, mode);
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::HeapNumberToString(
    DirectHandle<HeapNumber> number, double value, NumberCacheMode mode) {
  int hash = mode == NumberCacheMode::kIgnore
                 ? 0
                 : impl()->NumberToStringCacheHash(value);

  if (mode == NumberCacheMode::kBoth) {
    Handle<Object> cached = impl()->NumberToStringCacheGet(*number, hash);
    if (!IsUndefined(*cached, isolate())) return Cast<String>(cached);
  }

  Handle<String> result;
  if (value == 0) {
    result = zero_string();
  } else if (std::isnan(value)) {
    result = NaN_string();
  } else {
    char arr[kNumberToStringBufferSize];
    base::Vector<char> buffer(arr, arraysize(arr));
    const char* string = DoubleToCString(value, buffer);
    result = CharToString(this, string, mode);
  }
  if (mode != NumberCacheMode::kIgnore) {
    impl()->NumberToStringCacheSet(number, hash, result);
  }
  return result;
}

template <typename Impl>
inline Handle<String> FactoryBase<Impl>::SmiToString(Tagged<Smi> number,
                                                     NumberCacheMode mode) {
  int hash = mode == NumberCacheMode::kIgnore
                 ? 0
                 : impl()->NumberToStringCacheHash(number);

  if (mode == NumberCacheMode::kBoth) {
    Handle<Object> cached = impl()->NumberToStringCacheGet(number, hash);
    if (!IsUndefined(*cached, isolate())) return Cast<String>(cached);
  }

  Handle<String> result;
  if (number == Smi::zero()) {
    result = zero_string();
  } else {
    char arr[kNumberToStringBufferSize];
    base::Vector<char> buffer(arr, arraysize(arr));
    const char* string = IntToCString(number.value(), buffer);
    result = CharToString(this, string, mode);
  }
  if (mode != NumberCacheMode::kIgnore) {
    impl()->NumberToStringCacheSet(handle(number, isolate()), hash, result);
  }

  // Compute the hash here (rather than letting the caller take care of it) so
  // that the "cache hit" case above doesn't have to bother with it.
  static_assert(Smi::kMaxValue <= std::numeric_limits<uint32_t>::max());
  {
    DisallowGarbageCollection no_gc;
    Tagged<String> raw = *result;
    if (raw->raw_hash_field() == String::kEmptyHashField &&
        number.value() >= 0) {
      uint32_t raw_hash_field = StringHasher::MakeArrayIndexHash(
          static_cast<uint32_t>(number.value()), raw->length());
      raw->set_raw_hash_field(raw_hash_field);
    }
  }
  return result;
}

template <typename Impl>
Handle<FreshlyAllocatedBigInt> FactoryBase<Impl>::NewBigInt(
    uint32_t length, AllocationType allocation) {
  if (length > BigInt::kMaxLength) {
    FATAL("Fatal JavaScript invalid size error %d", length);
    UNREACHABLE();
  }
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      BigInt::SizeFor(length), allocation, read_only_roots().bigint_map());
  DisallowGarbageCollection no_gc;
  Tagged<FreshlyAllocatedBigInt> bigint = Cast<FreshlyAllocatedBigInt>(result);
  bigint->clear_padding();
  return handle(bigint, isolate());
}

template <typename Impl>
Handle<ScopeInfo> FactoryBase<Impl>::NewScopeInfo(int length,
                                                  AllocationType type) {
  DCHECK(type == AllocationType::kOld || type == AllocationType::kReadOnly);
  int size = ScopeInfo::SizeFor(length);
  Tagged<HeapObject> obj = AllocateRawWithImmortalMap(
      size, type, read_only_roots().scope_info_map());
  Tagged<ScopeInfo> scope_info = Cast<ScopeInfo>(obj);
  MemsetTagged(scope_info->data_start(), read_only_roots().undefined_value(),
               length);
#if TAGGED_SIZE_8_BYTES
  scope_info->set_optional_padding(0);
#endif
  return handle(scope_info, isolate());
}

template <typename Impl>
Handle<SourceTextModuleInfo> FactoryBase<Impl>::NewSourceTextModuleInfo() {
  return Cast<SourceTextModuleInfo>(NewFixedArrayWithMap(
      read_only_roots().module_info_map_handle(), SourceTextModuleInfo::kLength,
      AllocationType::kOld));
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfo(
    AllocationType allocation) {
  Tagged<Map> map = read_only_roots().shared_function_info_map();
  Tagged<SharedFunctionInfo> shared =
      Cast<SharedFunctionInfo>(NewWithImmortalMap(map, allocation));

  DisallowGarbageCollection no_gc;
  shared->Init(read_only_roots(), isolate()->GetAndIncNextUniqueSfiId());
  return handle(shared, isolate());
}

template <typename Impl>
Handle<DescriptorArray> FactoryBase<Impl>::NewDescriptorArray(
    int number_of_descriptors, int slack, AllocationType allocation) {
  int number_of_all_descriptors = number_of_descriptors + slack;
  // Zero-length case must be handled outside.
  DCHECK_LT(0, number_of_all_descriptors);
  int size = DescriptorArray::SizeFor(number_of_all_descriptors);
  Tagged<HeapObject> obj = AllocateRawWithImmortalMap(
      size, allocation, read_only_roots().descriptor_array_map());
  Tagged<DescriptorArray> array = Cast<DescriptorArray>(obj);

  auto raw_gc_state = DescriptorArrayMarkingState::kInitialGCState;
  if (allocation != AllocationType::kYoung &&
      allocation != AllocationType::kReadOnly) {
    auto* local_heap = allocation == AllocationType::kSharedOld
                           ? isolate()->shared_space_isolate()->heap()
                           : isolate()->heap();
    Heap* heap = local_heap->AsHeap();
    if (heap->incremental_marking()->IsMajorMarking()) {
      // Black allocation: We must create a full marked state.
      raw_gc_state = DescriptorArrayMarkingState::GetFullyMarkedState(
          heap->mark_compact_collector()->epoch(), number_of_descriptors);
    }
  }
  array->Initialize(read_only_roots().empty_enum_cache(),
                    read_only_roots().undefined_value(), number_of_descriptors,
                    slack, raw_gc_state);
  return handle(array, isolate());
}

template <typename Impl>
Handle<ClassPositions> FactoryBase<Impl>::NewClassPositions(int start,
                                                            int end) {
  auto result = NewStructInternal<ClassPositions>(CLASS_POSITIONS_TYPE,
                                                  AllocationType::kOld);
  result->set_start(start);
  result->set_end(end);
  return handle(result, isolate());
}

template <typename Impl>
Handle<SeqOneByteString>
FactoryBase<Impl>::AllocateRawOneByteInternalizedString(
    int length, uint32_t raw_hash_field) {
  CHECK_GE(String::kMaxLength, length);
  // The canonical empty_string is the only zero-length string we allow.
  DCHECK_IMPLIES(length == 0, !impl()->EmptyStringRootIsInitialized());

  Tagged<Map> map = read_only_roots().internalized_one_byte_string_map();
  const int size = SeqOneByteString::SizeFor(length);
  const AllocationType allocation =
      RefineAllocationTypeForInPlaceInternalizableString(
          impl()->CanAllocateInReadOnlySpace() ? AllocationType::kReadOnly
                                               : AllocationType::kOld,
          map);
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(size, allocation, map);
  Tagged<SeqOneByteString> answer = Cast<SeqOneByteString>(result);
  DisallowGarbageCollection no_gc;
  answer->clear_padding_destructively(length);
  answer->set_length(length);
  answer->set_raw_hash_field(raw_hash_field);
  DCHECK_EQ(size, answer->Size());
  return handle(answer, isolate());
}

template <typename Impl>
Handle<SeqTwoByteString>
FactoryBase<Impl>::AllocateRawTwoByteInternalizedString(
    int length, uint32_t raw_hash_field) {
  CHECK_GE(String::kMaxLength, length);
  DCHECK_NE(0, length);  // Use Heap::empty_string() instead.

  Tagged<Map> map = read_only_roots().internalized_two_byte_string_map();
  int size = SeqTwoByteString::SizeFor(length);
  Tagged<SeqTwoByteString> answer =
      Cast<SeqTwoByteString>(AllocateRawWithImmortalMap(
          size,
          RefineAllocationTypeForInPlaceInternalizableString(
              AllocationType::kOld, map),
          map));
  DisallowGarbageCollection no_gc;
  answer->clear_padding_destructively(length);
  answer->set_length(length);
  answer->set_raw_hash_field(raw_hash_field);
  DCHECK_EQ(size, answer->Size());
  return handle(answer, isolate());
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawArray(
    int size, AllocationType allocation) {
  Tagged<HeapObject> result = AllocateRaw(size, allocation);
  if ((size >
       isolate()->heap()->AsHeap()->MaxRegularHeapObjectSize(allocation)) &&
      v8_flags.use_marking_progress_bar) {
    LargePageMetadata::FromHeapObject(result)->MarkingProgressTracker().Enable(
        size);
  }
  return result;
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawFixedArray(
    int length, AllocationType allocation) {
  if (length < 0 || length > FixedArray::kMaxLength) {
    FATAL("Fatal JavaScript invalid size error %d", length);
    UNREACHABLE();
  }
  return AllocateRawArray(FixedArray::SizeFor(length), allocation);
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawWeakArrayList(
    int capacity, AllocationType allocation) {
  if (capacity < 0 || capacity > WeakArrayList::kMaxCapacity) {
    FATAL("Fatal JavaScript invalid size error %d", capacity);
    UNREACHABLE();
  }
  return AllocateRawArray(WeakArrayList::SizeForCapacity(capacity), allocation);
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::NewWithImmortalMap(
    Tagged<Map> map, AllocationType allocation) {
  return AllocateRawWithImmortalMap(map->instance_size(), allocation, map);
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawWithImmortalMap(
    int size, AllocationType allocation, Tagged<Map> map,
    AllocationAlignment alignment) {
  // TODO(delphick): Potentially you could also pass an immortal immovable Map
  // from OLD_SPACE here, like external_map or message_object_map, but currently
  // no one does so this check is sufficient.
  DCHECK(ReadOnlyHeap::Contains(map));
  Tagged<HeapObject> result = AllocateRaw(size, allocation, alignment);
  DisallowGarbageCollection no_gc;
  result->set_map_after_allocation(isolate(), map, SKIP_WRITE_BARRIER);
  return result;
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRaw(
    int size, AllocationType allocation, AllocationAlignment alignment) {
  return impl()->AllocateRaw(size, allocation, alignment);
}

template <typename Impl>
Handle<SwissNameDictionary>
FactoryBase<Impl>::NewSwissNameDictionaryWithCapacity(
    int capacity, AllocationType allocation) {
  DCHECK(SwissNameDictionary::IsValidCapacity(capacity));

  if (capacity == 0) {
    DCHECK_NE(
        read_only_roots().address_at(RootIndex::kEmptySwissPropertyDictionary),
        kNullAddress);

    return read_only_roots().empty_swiss_property_dictionary_handle();
  }

  if (capacity < 0 || capacity > SwissNameDictionary::MaxCapacity()) {
    FATAL("Fatal JavaScript invalid size error %d", capacity);
    UNREACHABLE();
  }

  int meta_table_length = SwissNameDictionary::MetaTableSizeFor(capacity);
  DirectHandle<ByteArray> meta_table =
      impl()->NewByteArray(meta_table_length, allocation);

  Tagged<Map> map = read_only_roots().swiss_name_dictionary_map();
  int size = SwissNameDictionary::SizeFor(capacity);
  Tagged<SwissNameDictionary> table = Cast<SwissNameDictionary>(
      AllocateRawWithImmortalMap(size, allocation, map));
  DisallowGarbageCollection no_gc;
  table->Initialize(isolate(), *meta_table, capacity);
  return handle(table, isolate());
}

template <typename Impl>
Handle<SwissNameDictionary> FactoryBase<Impl>::NewSwissNameDictionary(
    int at_least_space_for, AllocationType allocation) {
  return NewSwissNameDictionaryWithCapacity(
      SwissNameDictionary::CapacityFor(at_least_space_for), allocation);
}

template <typename Impl>
Handle<FunctionTemplateRareData>
FactoryBase<Impl>::NewFunctionTemplateRareData() {
  auto function_template_rare_data =
      NewStructInternal<FunctionTemplateRareData>(
          FUNCTION_TEMPLATE_RARE_DATA_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  function_template_rare_data->set_c_function_overloads(
      *impl()->empty_fixed_array(), SKIP_WRITE_BARRIER);
  return handle(function_template_rare_data, isolate());
}

template <typename Impl>
MaybeDirectHandle<Map> FactoryBase<Impl>::GetInPlaceInternalizedStringMap(
    Tagged<Map> from_string_map) {
  InstanceType instance_type = from_string_map->instance_type();
  MaybeDirectHandle<Map> map;
  switch (instance_type) {
    case SEQ_TWO_BYTE_STRING_TYPE:
    case SHARED_SEQ_TWO_BYTE_STRING_TYPE:
      map = read_only_roots().internalized_two_byte_string_map_handle();
      break;
    case SEQ_ONE_BYTE_STRING_TYPE:
    case SHARED_SEQ_ONE_BYTE_STRING_TYPE:
      map = read_only_roots().internalized_one_byte_string_map_handle();
      break;
    case SHARED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
      map =
          read_only_roots().external_internalized_two_byte_string_map_handle();
      break;
    case SHARED_EXTERNAL_ONE_BYTE_STRING_TYPE:
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
      map =
          read_only_roots().external_internalized_one_byte_string_map_handle();
      break;
    default:
      break;
  }
  DCHECK_EQ(!map.is_null(), String::IsInPlaceInternalizable(instance_type));
  return map;
}

template <typename Impl>
AllocationType
FactoryBase<Impl>::RefineAllocationTypeForInPlaceInternalizableString(
    AllocationType allocation, Tagged<Map> string_map) {
#ifdef DEBUG
  InstanceType instance_type = string_map->instance_type();
  DCHECK(InstanceTypeChecker::IsInternalizedString(instance_type) ||
         String::IsInPlaceInternalizable(instance_type));
#endif
  if (v8_flags.single_generation && allocation == AllocationType::kYoung) {
    allocation = AllocationType::kOld;
  }
  if (allocation != AllocationType::kOld) return allocation;
  return impl()->AllocationTypeForInPlaceInternalizableString();
}

// Instantiate FactoryBase for the two variants we want.
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) FactoryBase<Factory>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    FactoryBase<LocalFactory>;

}  // namespace internal
}  // namespace v8

"""

```