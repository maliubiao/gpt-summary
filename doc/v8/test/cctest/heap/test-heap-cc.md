Response:
The user wants a summary of the functionality of the provided C++ code snippet. Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the Core Purpose:** The filename `test-heap.cc` and the `#include` directives (e.g., `"src/heap/heap.h"`, `"test/cctest/cctest.h"`) strongly suggest this is a unit test file for the V8 heap component.

2. **Scan for Test Macros:**  Look for occurrences of `TEST(...)`. These define individual test cases. Each test function name provides a hint about the specific functionality being tested.

3. **Analyze Individual Tests:**
    * **`HeapMaps`**: Checks the properties (`instance_type`, `instance_size`) of various core `Map` objects within the heap.
    * **`ContextMaps`**: Verifies that critical maps related to built-in prototypes (like `String.prototype`, `RegExp.prototype`) stored in the context remain unchanged after initialization.
    * **`InitialObjects`**:  Compares initial prototype objects in the V8 context with the results of JavaScript evaluations.
    * **`HeapObjects`**: Tests the creation and properties of various heap objects like `HeapNumber`, `Smi`, and `String`. It also includes a test (`CheckGcSafeFindCodeForInnerPointer`) related to finding code objects given an inner pointer, which is important for garbage collection and execution.
    * **`HandleNull`**: Checks the behavior of a "null" handle in the V8 context.
    * **`Tagging`**: Verifies the tagging mechanism used by V8 to distinguish between object types (e.g., `Smi`).
    * **`GarbageCollection`**:  Tests the basic functionality of minor garbage collection by allocating objects, ensuring some survive GC, and others are collected.
    * **`String`**:  Tests the creation and basic properties of string objects.
    * **`LocalHandles`**:  Checks the creation and usage of local handles for managing V8 objects within a scope.
    * **`GlobalHandles`**:  Tests the creation, persistence (across GCs), and destruction of global handles.
    * **`WeakGlobalUnmodifiedApiHandlesScavenge`**: Tests weak global handles and how they are cleared during garbage collection when the referenced object is collected. It specifically mentions "unmodified API handles", suggesting testing scenarios involving external (API) objects.
    * **`WeakGlobalHandlesMark`**: Similar to the previous test but focuses on the marking phase of garbage collection for weak handles.
    * **`DeleteWeakGlobalHandle`**: Tests the deletion of weak global handles and verifies the associated callback is triggered.
    * **`BytecodeArray`**: Tests the allocation, initialization, and survival of `BytecodeArray` objects across garbage collection, including scenarios involving moving objects during compaction.
    * **`StringTable`**: Tests the internalization of strings in the string table, ensuring that identical strings are represented by the same object.
    * **`FunctionAllocation`**: Tests the creation of JavaScript functions and the ability to add properties to them.
    * **`ObjectProperties`**: Tests adding, deleting, and checking the existence of properties on JavaScript objects.
    * **`JSObjectMaps`**:  Tests how the map (structure information) of a JavaScript object changes when properties are added.

4. **Identify Relationships to JavaScript:** Many tests directly relate to JavaScript concepts:
    * Creating functions, objects, arrays.
    * Setting and getting properties.
    * String manipulation.
    * Garbage collection (which directly impacts JavaScript object lifecycles).
    * Prototypes.

5. **Look for Specific Clues:**
    * The `#include` statements indicate the V8 components being tested (heap, handles, objects, etc.).
    * The `CcTest::InitializeVM()` call in many tests signifies the initialization of the V8 virtual machine for testing.

6. **Address Specific Questions:**
    * **`.tq` extension:** The code is `.cc`, not `.tq`, so it's C++, not Torque.
    * **JavaScript examples:**  Provide JavaScript code snippets that demonstrate the functionality being tested in the C++ code.
    * **Code Logic Reasoning:** For tests involving specific values or state changes, describe the expected input and output.
    * **Common Programming Errors:** Think about typical JavaScript errors that relate to the tested areas (e.g., memory leaks with global handles if not managed correctly).

7. **Summarize the Functionality:** Combine the analysis of individual tests into a concise summary statement. Emphasize that it's a test suite for the V8 heap, covering object creation, management, garbage collection, and related mechanisms.

8. **Structure the Answer:** Organize the information logically, addressing each part of the user's request. Use bullet points for clarity when listing test functionalities. Provide clear JavaScript examples and explanations.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This is just about memory management."  **Correction:** While memory management (heap) is central, it also tests related concepts like object properties, string internalization, and handle management, which are crucial for the JavaScript execution model.
* **Realization:**  Some tests are more abstract (like `HeapMaps`) and test internal V8 structures, while others (like `ObjectProperties`) have a more direct JavaScript equivalent. The answer should reflect this spectrum.
* **Emphasis on Testing:**  Repeatedly emphasize that this is *test* code, not the core implementation. This helps the user understand the purpose of the file.
好的，让我们来分析一下 `v8/test/cctest/heap/test-heap.cc` 这个 V8 源代码文件的功能。

**文件功能归纳：**

`v8/test/cctest/heap/test-heap.cc` 是 V8 JavaScript 引擎的一个 C++ 单元测试文件，专门用于测试 V8 堆（Heap）的各种功能。它包含了多个独立的测试用例（以 `TEST(...)` 宏定义），涵盖了堆的各个方面，例如：

* **基本对象分配和类型检查:** 测试各种堆对象的创建（例如数字、字符串、数组、函数、对象等）以及它们的类型和属性。
* **堆数据结构和元信息:** 验证堆内部的关键数据结构，例如 `Map` 对象（描述对象的布局和类型）。
* **垃圾回收机制:** 测试 V8 的垃圾回收器（包括新生代和老生代 GC）的功能，例如对象的生命周期管理、可达性判断、弱引用处理等。
* **句柄管理:** 测试局部句柄（`Handle`）和全局句柄（`GlobalHandle`）的创建、使用和销毁，以及弱全局句柄的行为。
* **字符串处理:** 测试字符串对象的创建、内部化（string interning）以及相关操作。
* **对象属性操作:** 测试在 JavaScript 对象上设置、获取、删除属性的功能。
* **字节码数组:** 测试字节码数组的创建和管理，这是 V8 执行 JavaScript 代码的关键组成部分。
* **上下文（Context）管理:** 测试与 JavaScript 执行上下文相关的堆对象。

**关于文件扩展名和 Torque：**

正如你所说，如果 `v8/test/cctest/heap/test-heap.cc` 的扩展名是 `.tq`，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。由于该文件扩展名是 `.cc`，所以它是纯粹的 C++ 代码。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`v8/test/cctest/heap/test-heap.cc` 中测试的很多功能都直接对应着 JavaScript 的运行时行为。下面是一些例子：

* **对象创建和属性访问:**  C++ 代码中测试 `factory->NewJSObject()` 创建 JavaScript 对象，以及 `Object::SetProperty()` 和 `Object::GetProperty()` 操作，这直接对应于 JavaScript 中的对象字面量创建和属性访问：

   ```javascript
   const obj = {};
   obj.name = "value";
   console.log(obj.name); // 输出 "value"
   delete obj.name;
   ```

* **函数创建:** C++ 代码中测试 `factory->NewFunctionForTesting()` 创建函数对象，对应 JavaScript 中的函数声明和函数表达式：

   ```javascript
   function myFunction() {
       // ...
   }

   const anotherFunction = function() {
       // ...
   };
   ```

* **数组创建:**  虽然这段代码中没有直接展示数组创建，但 V8 堆中也管理着 JavaScript 数组对象，其测试可能在其他相关文件中。JavaScript 中的数组创建如下：

   ```javascript
   const arr = [1, 2, 3];
   ```

* **字符串操作:** C++ 代码中测试 `factory->NewStringFromUtf8()` 创建字符串对象，对应 JavaScript 中的字符串字面量：

   ```javascript
   const str = "hello";
   ```

* **垃圾回收:** 虽然 JavaScript 本身不直接暴露垃圾回收的 API，但 V8 的堆测试确保了当 JavaScript 对象不再被引用时，垃圾回收器能够正确地回收它们占用的内存。

**代码逻辑推理及假设输入输出：**

让我们看一个简单的测试用例 `TEST(HeapMaps)` 中的代码逻辑：

```c++
static void CheckMap(Tagged<Map> map, int type, int instance_size) {
  CHECK(IsHeapObject(map));
  DCHECK(IsValidHeapObject(CcTest::heap(), map));
  CHECK_EQ(ReadOnlyRoots(CcTest::heap()).meta_map(), map->map());
  CHECK_EQ(type, map->instance_type());
  CHECK_EQ(instance_size, map->instance_size());
}

TEST(HeapMaps) {
  CcTest::InitializeVM();
  ReadOnlyRoots roots(CcTest::heap());
  CheckMap(roots.meta_map(), MAP_TYPE, Map::kSize);
  CheckMap(roots.heap_number_map(), HEAP_NUMBER_TYPE, sizeof(HeapNumber));
  CheckMap(roots.fixed_array_map(), FIXED_ARRAY_TYPE, kVariableSizeSentinel);
  CheckMap(roots.hash_table_map(), HASH_TABLE_TYPE, kVariableSizeSentinel);
  CheckMap(roots.seq_two_byte_string_map(), SEQ_TWO_BYTE_STRING_TYPE,
           kVariableSizeSentinel);
}
```

**假设输入：** V8 虚拟机已成功初始化。

**代码逻辑：** `CheckMap` 函数接收一个 `Map` 对象、期望的类型和实例大小。它断言（`CHECK`）传入的 `map` 是一个堆对象，并且其 `map()` 属性（指向自身的 `Map`）等于根对象的 `meta_map`。它还断言 `map` 的 `instance_type()` 和 `instance_size()` 属性与期望值相符。

`TEST(HeapMaps)` 调用 `CheckMap` 函数来验证 V8 启动时创建的一些核心 `Map` 对象：

* `roots.meta_map()`:  元地图，用于描述 `Map` 对象自身。期望类型是 `MAP_TYPE`，大小是 `Map::kSize`。
* `roots.heap_number_map()`: 用于描述堆数字对象。期望类型是 `HEAP_NUMBER_TYPE`，大小是 `sizeof(HeapNumber)`。
* `roots.fixed_array_map()`: 用于描述定长数组对象。期望类型是 `FIXED_ARRAY_TYPE`，大小是 `kVariableSizeSentinel`（表示可变大小）。
* `roots.hash_table_map()`: 用于描述哈希表对象。期望类型是 `HASH_TABLE_TYPE`，大小是 `kVariableSizeSentinel`。
* `roots.seq_two_byte_string_map()`: 用于描述双字节字符串对象。期望类型是 `SEQ_TWO_BYTE_STRING_TYPE`，大小是 `kVariableSizeSentinel`。

**预期输出：** 如果 V8 堆的初始化是正确的，并且这些核心 `Map` 对象的属性符合预期，那么所有的 `CHECK` 断言都会通过，测试成功。

**涉及用户常见的编程错误及示例：**

虽然这是一个 V8 内部的测试文件，但它所测试的功能与用户在使用 JavaScript 时可能遇到的错误间接相关。例如：

* **内存泄漏:** 如果 V8 的垃圾回收器存在缺陷，可能导致本应被回收的对象无法释放，最终导致内存泄漏。`test-heap.cc` 中关于垃圾回收的测试用例旨在发现这类问题。一个用户可能遇到的 JavaScript 内存泄漏的例子是意外地将不再使用的对象存储在全局变量中，阻止其被回收。

   ```javascript
   let leakedObject = null;
   function createLeakedObject() {
       leakedObject = { data: new Array(1000000).fill(0) }; // 创建一个大对象
   }

   setInterval(createLeakedObject, 1000); // 每秒创建一个大对象并赋值给全局变量
   ```
   在这个例子中，`leakedObject` 是一个全局变量，每次 `createLeakedObject` 被调用时，旧的对象会被新的对象覆盖，但旧的对象仍然被全局变量引用，不会被垃圾回收，导致内存消耗不断增加。

* **类型错误:**  `test-heap.cc` 中对对象类型和 `Map` 对象的验证，与 JavaScript 中可能出现的类型错误相关。例如，尝试访问一个 `undefined` 值的属性会抛出 `TypeError`。

   ```javascript
   let myVar;
   console.log(myVar.property); // TypeError: Cannot read properties of undefined (reading 'property')
   ```
   V8 的堆管理需要确保对象的类型信息正确，以便在运行时进行正确的操作。

* **意外的属性访问或修改:**  测试对象属性的添加、删除等操作，与 JavaScript 中对对象属性的错误操作有关。例如，忘记使用 `delete` 操作符移除不再需要的属性可能会导致对象占用不必要的内存。

**总结一下它的功能（第 1 部分）：**

这部分代码（`v8/test/cctest/heap/test-heap.cc` 的开头部分）主要关注 V8 堆的基础结构和基本对象的测试。它验证了核心 `Map` 对象的正确性，测试了基本堆对象的创建和类型，以及一些关键的初始化流程。这些测试是确保 V8 堆功能正常运行的基石，为后续更复杂的堆功能测试奠定了基础。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdlib.h>

#include <utility>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/base/strings.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/script-details.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/execution.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/combined-heap.h"
#include "src/heap/factory.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/heap.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/large-page-metadata-inl.h"
#include "src/heap/large-spaces.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-barrier.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/memory-reducer.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/parked-scope.h"
#include "src/heap/remembered-set-inl.h"
#include "src/heap/safepoint.h"
#include "src/ic/ic.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/elements.h"
#include "src/objects/field-type.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/slots.h"
#include "src/objects/transitions.h"
#include "src/regexp/regexp.h"
#include "src/snapshot/snapshot.h"
#include "src/tracing/tracing-category-observer.h"
#include "src/utils/ostreams.h"
#include "test/cctest/cctest.h"
#include "test/cctest/feedback-vector-helper.h"
#include "test/cctest/heap/heap-tester.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/test-transitions.h"

namespace v8 {
namespace internal {
namespace heap {

// We only start allocation-site tracking with the second instantiation.
static const int kPretenureCreationCount =
    PretenuringHandler::GetMinMementoCountForTesting() + 1;

static void CheckMap(Tagged<Map> map, int type, int instance_size) {
  CHECK(IsHeapObject(map));
  DCHECK(IsValidHeapObject(CcTest::heap(), map));
  CHECK_EQ(ReadOnlyRoots(CcTest::heap()).meta_map(), map->map());
  CHECK_EQ(type, map->instance_type());
  CHECK_EQ(instance_size, map->instance_size());
}

TEST(HeapMaps) {
  CcTest::InitializeVM();
  ReadOnlyRoots roots(CcTest::heap());
  CheckMap(roots.meta_map(), MAP_TYPE, Map::kSize);
  CheckMap(roots.heap_number_map(), HEAP_NUMBER_TYPE, sizeof(HeapNumber));
  CheckMap(roots.fixed_array_map(), FIXED_ARRAY_TYPE, kVariableSizeSentinel);
  CheckMap(roots.hash_table_map(), HASH_TABLE_TYPE, kVariableSizeSentinel);
  CheckMap(roots.seq_two_byte_string_map(), SEQ_TWO_BYTE_STRING_TYPE,
           kVariableSizeSentinel);
}

static void VerifyStoredPrototypeMap(Isolate* isolate,
                                     int stored_map_context_index,
                                     int stored_ctor_context_index) {
  DirectHandle<Context> context = isolate->native_context();

  DirectHandle<Map> this_map(Cast<Map>(context->get(stored_map_context_index)),
                             isolate);

  DirectHandle<JSFunction> fun(
      Cast<JSFunction>(context->get(stored_ctor_context_index)), isolate);
  DirectHandle<JSObject> proto(Cast<JSObject>(fun->initial_map()->prototype()),
                               isolate);
  DirectHandle<Map> that_map(proto->map(), isolate);

  CHECK(proto->HasFastProperties());
  CHECK_EQ(*this_map, *that_map);
}

// Checks that critical maps stored on the context (mostly used for fast-path
// checks) are unchanged after initialization.
TEST(ContextMaps) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handle_scope(isolate);

  VerifyStoredPrototypeMap(isolate,
                           Context::STRING_FUNCTION_PROTOTYPE_MAP_INDEX,
                           Context::STRING_FUNCTION_INDEX);
  VerifyStoredPrototypeMap(isolate, Context::REGEXP_PROTOTYPE_MAP_INDEX,
                           Context::REGEXP_FUNCTION_INDEX);
}

TEST(InitialObjects) {
  LocalContext env;
  HandleScope scope(CcTest::i_isolate());
  DirectHandle<Context> context = v8::Utils::OpenDirectHandle(*env);
  // Initial ArrayIterator prototype.
  CHECK_EQ(context->initial_array_iterator_prototype(),
           *v8::Utils::OpenDirectHandle(
               *CompileRun("[][Symbol.iterator]().__proto__")));
  // Initial Array prototype.
  CHECK_EQ(context->initial_array_prototype(),
           *v8::Utils::OpenDirectHandle(*CompileRun("Array.prototype")));
  // Initial Generator prototype.
  CHECK_EQ(context->initial_generator_prototype(),
           *v8::Utils::OpenDirectHandle(
               *CompileRun("(function*(){}).__proto__.prototype")));
  // Initial Iterator prototype.
  CHECK_EQ(context->initial_iterator_prototype(),
           *v8::Utils::OpenDirectHandle(
               *CompileRun("[][Symbol.iterator]().__proto__.__proto__")));
  // Initial Object prototype.
  CHECK_EQ(context->initial_object_prototype(),
           *v8::Utils::OpenDirectHandle(*CompileRun("Object.prototype")));
}

static void CheckOddball(Isolate* isolate, Tagged<Object> obj,
                         const char* string) {
  CHECK(IsOddball(obj));
  Handle<Object> handle(obj, isolate);
  Tagged<Object> print_string =
      *Object::ToString(isolate, handle).ToHandleChecked();
  CHECK(Cast<String>(print_string)->IsOneByteEqualTo(base::CStrVector(string)));
}

static void CheckSmi(Isolate* isolate, int value, const char* string) {
  Handle<Object> handle(Smi::FromInt(value), isolate);
  Tagged<Object> print_string =
      *Object::ToString(isolate, handle).ToHandleChecked();
  CHECK(Cast<String>(print_string)->IsOneByteEqualTo(base::CStrVector(string)));
}

static void CheckNumber(Isolate* isolate, double value, const char* string) {
  Handle<Object> number = isolate->factory()->NewNumber(value);
  CHECK(IsNumber(*number));
  DirectHandle<Object> print_string =
      Object::ToString(isolate, number).ToHandleChecked();
  CHECK(
      Cast<String>(*print_string)->IsOneByteEqualTo(base::CStrVector(string)));
}

void CheckEmbeddedObjectsAreEqual(Isolate* isolate, DirectHandle<Code> lhs,
                                  DirectHandle<Code> rhs) {
  int mode_mask = RelocInfo::ModeMask(RelocInfo::FULL_EMBEDDED_OBJECT);
  PtrComprCageBase cage_base(isolate);
  RelocIterator lhs_it(*lhs, mode_mask);
  RelocIterator rhs_it(*rhs, mode_mask);
  while (!lhs_it.done() && !rhs_it.done()) {
    CHECK_EQ(lhs_it.rinfo()->target_object(cage_base),
             rhs_it.rinfo()->target_object(cage_base));

    lhs_it.next();
    rhs_it.next();
  }
  CHECK(lhs_it.done() == rhs_it.done());
}

static void CheckGcSafeFindCodeForInnerPointer(Isolate* isolate) {
  // Test GcSafeFindCodeForInnerPointer
#define __ assm.

  Assembler assm(isolate->allocator(), AssemblerOptions{});

  __ nop();  // supported on all architectures

  PtrComprCageBase cage_base(isolate);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  DirectHandle<InstructionStream> code(
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING)
          .Build()
          ->instruction_stream(),
      isolate);
  CHECK(IsInstructionStream(*code, cage_base));

  Tagged<HeapObject> obj = Cast<HeapObject>(*code);
  Address obj_addr = obj.address();

  for (int i = 0; i < obj->Size(cage_base); i += kTaggedSize) {
    Tagged<Code> lookup_result =
        isolate->heap()->FindCodeForInnerPointer(obj_addr + i);
    CHECK_EQ(*code, lookup_result->instruction_stream());
  }

  DirectHandle<InstructionStream> copy(
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING)
          .Build()
          ->instruction_stream(),
      isolate);
  Tagged<HeapObject> obj_copy = Cast<HeapObject>(*copy);
  Tagged<Code> not_right = isolate->heap()->FindCodeForInnerPointer(
      obj_copy.address() + obj_copy->Size(cage_base) / 2);
  CHECK_NE(not_right->instruction_stream(), *code);
  CHECK_EQ(not_right->instruction_stream(), *copy);
}

TEST(HandleNull) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  LocalContext context;
  Handle<Object> n(Tagged<Object>(kNullAddress), isolate);
  CHECK(!n.is_null());
}

TEST(HeapObjects) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope sc(isolate);
  DirectHandle<Object> value = factory->NewNumber(1.000123);
  CHECK(IsHeapNumber(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(1.000123, Object::NumberValue(*value));

  value = factory->NewNumber(1.0);
  CHECK(IsSmi(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(1.0, Object::NumberValue(*value));

  value = factory->NewNumberFromInt(1024);
  CHECK(IsSmi(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(1024.0, Object::NumberValue(*value));

  value = factory->NewNumberFromInt(Smi::kMinValue);
  CHECK(IsSmi(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(Smi::kMinValue, Cast<Smi>(*value).value());

  value = factory->NewNumberFromInt(Smi::kMaxValue);
  CHECK(IsSmi(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(Smi::kMaxValue, Cast<Smi>(*value).value());

#if !defined(V8_TARGET_ARCH_64_BIT)
  // TODO(lrn): We need a NumberFromIntptr function in order to test this.
  value = factory->NewNumberFromInt(Smi::kMinValue - 1);
  CHECK(IsHeapNumber(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(static_cast<double>(Smi::kMinValue - 1),
           Object::NumberValue(*value));
#endif

  value = factory->NewNumberFromUint(static_cast<uint32_t>(Smi::kMaxValue) + 1);
  CHECK(IsHeapNumber(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(static_cast<double>(static_cast<uint32_t>(Smi::kMaxValue) + 1),
           Object::NumberValue(*value));

  value = factory->NewNumberFromUint(static_cast<uint32_t>(1) << 31);
  CHECK(IsHeapNumber(*value));
  CHECK(IsNumber(*value));
  CHECK_EQ(static_cast<double>(static_cast<uint32_t>(1) << 31),
           Object::NumberValue(*value));

  // nan oddball checks
  CHECK(IsNumber(*factory->nan_value()));
  CHECK(std::isnan(Object::NumberValue(*factory->nan_value())));

  DirectHandle<String> s = factory->NewStringFromStaticChars("fisk hest ");
  CHECK(IsString(*s));
  CHECK_EQ(10, s->length());

  Handle<String> object_string = Cast<String>(factory->Object_string());
  Handle<JSGlobalObject> global(CcTest::i_isolate()->context()->global_object(),
                                isolate);
  CHECK(Just(true) ==
        JSReceiver::HasOwnProperty(isolate, global, object_string));

  // Check ToString for oddballs
  ReadOnlyRoots roots(heap);
  CheckOddball(isolate, roots.true_value(), "true");
  CheckOddball(isolate, roots.false_value(), "false");
  CheckOddball(isolate, roots.null_value(), "null");
  CheckOddball(isolate, roots.undefined_value(), "undefined");

  // Check ToString for Smis
  CheckSmi(isolate, 0, "0");
  CheckSmi(isolate, 42, "42");
  CheckSmi(isolate, -42, "-42");

  // Check ToString for Numbers
  CheckNumber(isolate, 1.1, "1.1");

  CheckGcSafeFindCodeForInnerPointer(isolate);
}

TEST(Tagging) {
  CcTest::InitializeVM();
  int request = 24;
  CHECK_EQ(request, static_cast<int>(OBJECT_POINTER_ALIGN(request)));
  CHECK(IsSmi(Smi::FromInt(42)));
  CHECK(IsSmi(Smi::FromInt(Smi::kMinValue)));
  CHECK(IsSmi(Smi::FromInt(Smi::kMaxValue)));
}

TEST(GarbageCollection) {
  if (v8_flags.single_generation) return;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  HandleScope sc(isolate);
  // Check GC.
  heap::InvokeMinorGC(CcTest::heap());

  Handle<JSGlobalObject> global(CcTest::i_isolate()->context()->global_object(),
                                isolate);
  Handle<String> name = factory->InternalizeUtf8String("theFunction");
  Handle<String> prop_name = factory->InternalizeUtf8String("theSlot");
  Handle<String> prop_namex = factory->InternalizeUtf8String("theSlotx");
  Handle<String> obj_name = factory->InternalizeUtf8String("theObject");
  Handle<Smi> twenty_three(Smi::FromInt(23), isolate);
  Handle<Smi> twenty_four(Smi::FromInt(24), isolate);

  {
    HandleScope inner_scope(isolate);
    // Allocate a function and keep it in global object's property.
    Handle<JSFunction> function = factory->NewFunctionForTesting(name);
    Object::SetProperty(isolate, global, name, function).Check();
    // Allocate an object.  Unrooted after leaving the scope.
    Handle<JSObject> obj = factory->NewJSObject(function);
    Object::SetProperty(isolate, obj, prop_name, twenty_three).Check();
    Object::SetProperty(isolate, obj, prop_namex, twenty_four).Check();

    CHECK_EQ(Smi::FromInt(23),
             *Object::GetProperty(isolate, obj, prop_name).ToHandleChecked());
    CHECK_EQ(Smi::FromInt(24),
             *Object::GetProperty(isolate, obj, prop_namex).ToHandleChecked());
  }

  heap::InvokeMinorGC(CcTest::heap());

  // Function should be alive.
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, global, name));
  // Check function is retained.
  Handle<Object> func_value =
      Object::GetProperty(isolate, global, name).ToHandleChecked();
  CHECK(IsJSFunction(*func_value));
  Handle<JSFunction> function = Cast<JSFunction>(func_value);

  {
    HandleScope inner_scope(isolate);
    // Allocate another object, make it reachable from global.
    Handle<JSObject> obj = factory->NewJSObject(function);
    Object::SetProperty(isolate, global, obj_name, obj).Check();
    Object::SetProperty(isolate, obj, prop_name, twenty_three).Check();
  }

  // After gc, it should survive.
  heap::InvokeMinorGC(CcTest::heap());

  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, global, obj_name));
  Handle<Object> obj =
      Object::GetProperty(isolate, global, obj_name).ToHandleChecked();
  CHECK(IsJSObject(*obj));
  CHECK_EQ(Smi::FromInt(23),
           *Object::GetProperty(isolate, Cast<JSObject>(obj), prop_name)
                .ToHandleChecked());
}

static void VerifyStringAllocation(Isolate* isolate, const char* string) {
  HandleScope scope(isolate);
  DirectHandle<String> s = isolate->factory()
                               ->NewStringFromUtf8(base::CStrVector(string))
                               .ToHandleChecked();
  CHECK_EQ(strlen(string), s->length());
  for (uint32_t index = 0; index < s->length(); index++) {
    CHECK_EQ(static_cast<uint16_t>(string[index]), s->Get(index));
  }
}

TEST(String) {
  CcTest::InitializeVM();
  Isolate* isolate = reinterpret_cast<Isolate*>(CcTest::isolate());

  VerifyStringAllocation(isolate, "a");
  VerifyStringAllocation(isolate, "ab");
  VerifyStringAllocation(isolate, "abc");
  VerifyStringAllocation(isolate, "abcd");
  VerifyStringAllocation(isolate, "fiskerdrengen er paa havet");
}

TEST(LocalHandles) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  v8::HandleScope scope(CcTest::isolate());
  const char* name = "Kasper the spunky";
  DirectHandle<String> string = factory->NewStringFromAsciiChecked(name);
  CHECK_EQ(strlen(name), string->length());
}

TEST(GlobalHandles) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  GlobalHandles* global_handles = isolate->global_handles();

  Handle<Object> h1;
  Handle<Object> h2;
  Handle<Object> h3;
  Handle<Object> h4;

  {
    HandleScope scope(isolate);

    DirectHandle<Object> i = factory->NewStringFromStaticChars("fisk");
    DirectHandle<Object> u = factory->NewNumber(1.12344);

    h1 = global_handles->Create(*i);
    h2 = global_handles->Create(*u);
    h3 = global_handles->Create(*i);
    h4 = global_handles->Create(*u);
  }

  // after gc, it should survive
  heap::InvokeMinorGC(CcTest::heap());

  CHECK(IsString(*h1));
  CHECK(IsHeapNumber(*h2));
  CHECK(IsString(*h3));
  CHECK(IsHeapNumber(*h4));

  CHECK_EQ(*h3, *h1);
  GlobalHandles::Destroy(h1.location());
  GlobalHandles::Destroy(h3.location());

  CHECK_EQ(*h4, *h2);
  GlobalHandles::Destroy(h2.location());
  GlobalHandles::Destroy(h4.location());
}

static bool WeakPointerCleared = false;

static void TestWeakGlobalHandleCallback(
    const v8::WeakCallbackInfo<void>& data) {
  std::pair<v8::Persistent<v8::Value>*, int>* p =
      reinterpret_cast<std::pair<v8::Persistent<v8::Value>*, int>*>(
          data.GetParameter());
  if (p->second == 1234) WeakPointerCleared = true;
  p->first->Reset();
}

TEST(WeakGlobalUnmodifiedApiHandlesScavenge) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  LocalContext context;
  Factory* factory = isolate->factory();
  GlobalHandles* global_handles = isolate->global_handles();

  WeakPointerCleared = false;

  IndirectHandle<Object> h1;
  IndirectHandle<Object> h2;

  {
    HandleScope scope(isolate);

    // Create an Api object that is unmodified.
    Local<v8::Function> function = FunctionTemplate::New(context->GetIsolate())
                                       ->GetFunction(context.local())
                                       .ToLocalChecked();
    Local<v8::Object> i =
        function->NewInstance(context.local()).ToLocalChecked();
    DirectHandle<Object> u = factory->NewNumber(1.12344);

    h1 = global_handles->Create(*u);
    h2 = global_handles->Create(internal::ValueHelper::ValueAsAddress(*i));
  }

  std::pair<Handle<Object>*, int> handle_and_id(&h2, 1234);
  GlobalHandles::MakeWeak(
      h2.location(), reinterpret_cast<void*>(&handle_and_id),
      &TestWeakGlobalHandleCallback, v8::WeakCallbackType::kParameter);

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    v8_flags.single_generation ? heap::InvokeMajorGC(heap)
                               : heap::InvokeMinorGC(heap);
  }

  CHECK(IsHeapNumber(*h1));
  CHECK(WeakPointerCleared);
  GlobalHandles::Destroy(h1.location());
}

TEST(WeakGlobalHandlesMark) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = isolate->factory();
  GlobalHandles* global_handles = isolate->global_handles();

  WeakPointerCleared = false;

  IndirectHandle<Object> h1;
  IndirectHandle<Object> h2;

  {
    HandleScope scope(isolate);

    DirectHandle<Object> i = factory->NewStringFromStaticChars("fisk");
    DirectHandle<Object> u = factory->NewNumber(1.12344);

    h1 = global_handles->Create(*i);
    h2 = global_handles->Create(*u);
  }

  // Make sure the objects are promoted.
  heap::EmptyNewSpaceUsingGC(heap);
  CHECK(!HeapLayout::InYoungGeneration(*h1) &&
        !HeapLayout::InYoungGeneration(*h2));

  std::pair<Handle<Object>*, int> handle_and_id(&h2, 1234);
  GlobalHandles::MakeWeak(
      h2.location(), reinterpret_cast<void*>(&handle_and_id),
      &TestWeakGlobalHandleCallback, v8::WeakCallbackType::kParameter);

  // Incremental marking potentially marked handles before they turned weak.
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(IsString(*h1));
  CHECK(WeakPointerCleared);
  GlobalHandles::Destroy(h1.location());
}

TEST(DeleteWeakGlobalHandle) {
  v8_flags.stress_compaction = false;
  v8_flags.stress_incremental_marking = false;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = isolate->factory();
  GlobalHandles* global_handles = isolate->global_handles();

  WeakPointerCleared = false;
  IndirectHandle<Object> h;
  {
    HandleScope scope(isolate);

    DirectHandle<Object> i = factory->NewStringFromStaticChars("fisk");
    h = global_handles->Create(*i);
  }

  std::pair<Handle<Object>*, int> handle_and_id(&h, 1234);
  GlobalHandles::MakeWeak(h.location(), reinterpret_cast<void*>(&handle_and_id),
                          &TestWeakGlobalHandleCallback,
                          v8::WeakCallbackType::kParameter);
  CHECK(!WeakPointerCleared);
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(WeakPointerCleared);
}

TEST(BytecodeArray) {
  if (!v8_flags.compact) return;
  static const uint8_t kRawBytes[] = {0xC3, 0x7E, 0xA5, 0x5A};
  static const int kRawBytesSize = sizeof(kRawBytes);
  static const int32_t kFrameSize = 32;
  static const uint16_t kParameterCount = 2;
  static const uint16_t kMaxArguments = 0;

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  heap::SimulateFullSpace(heap->old_space());
  IndirectHandle<TrustedFixedArray> constant_pool =
      factory->NewTrustedFixedArray(5);
  for (int i = 0; i < 5; i++) {
    IndirectHandle<Object> number = factory->NewHeapNumber(i);
    constant_pool->set(i, *number);
  }

  IndirectHandle<TrustedByteArray> handler_table =
      factory->NewTrustedByteArray(3);

  // Allocate and initialize BytecodeArray
  IndirectHandle<BytecodeArray> array = factory->NewBytecodeArray(
      kRawBytesSize, kRawBytes, kFrameSize, kParameterCount, kMaxArguments,
      constant_pool, handler_table);

  CHECK(IsBytecodeArray(*array));
  CHECK_EQ(array->length(), (int)sizeof(kRawBytes));
  CHECK_EQ(array->frame_size(), kFrameSize);
  CHECK_EQ(array->parameter_count(), kParameterCount);
  CHECK_EQ(array->constant_pool(), *constant_pool);
  CHECK_EQ(array->handler_table(), *handler_table);
  CHECK_LE(array->address(), array->GetFirstBytecodeAddress());
  CHECK_GE(array->address() + array->BytecodeArraySize(),
           array->GetFirstBytecodeAddress() + array->length());
  for (int i = 0; i < kRawBytesSize; i++) {
    CHECK_EQ(Memory<uint8_t>(array->GetFirstBytecodeAddress() + i),
             kRawBytes[i]);
    CHECK_EQ(array->get(i), kRawBytes[i]);
  }

  Tagged<TrustedFixedArray> old_constant_pool_address = *constant_pool;

  // Perform a full garbage collection and force the constant pool to be on an
  // evacuation candidate.
  PageMetadata* evac_page = PageMetadata::FromHeapObject(*constant_pool);
  heap::ForceEvacuationCandidate(evac_page);
  {
    // We need to invoke GC without stack, otherwise no compaction is performed.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  // BytecodeArray should survive.
  CHECK_EQ(array->length(), kRawBytesSize);
  CHECK_EQ(array->frame_size(), kFrameSize);
  for (int i = 0; i < kRawBytesSize; i++) {
    CHECK_EQ(array->get(i), kRawBytes[i]);
    CHECK_EQ(Memory<uint8_t>(array->GetFirstBytecodeAddress() + i),
             kRawBytes[i]);
  }

  // Constant pool should have been migrated.
  CHECK_EQ(array->constant_pool().ptr(), constant_pool->ptr());
  CHECK_NE(array->constant_pool().ptr(), old_constant_pool_address.ptr());
}

static const char* not_so_random_string_table[] = {
    "abstract",   "boolean",      "break",      "byte",    "case",
    "catch",      "char",         "class",      "const",   "continue",
    "debugger",   "default",      "delete",     "do",      "double",
    "else",       "enum",         "export",     "extends", "false",
    "final",      "finally",      "float",      "for",     "function",
    "goto",       "if",           "implements", "import",  "in",
    "instanceof", "int",          "interface",  "long",    "native",
    "new",        "null",         "package",    "private", "protected",
    "public",     "return",       "short",      "static",  "super",
    "switch",     "synchronized", "this",       "throw",   "throws",
    "transient",  "true",         "try",        "typeof",  "var",
    "void",       "volatile",     "while",      "with",    nullptr};

static void CheckInternalizedStrings(const char** strings) {
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  for (const char* string = *strings; *strings != nullptr;
       string = *strings++) {
    HandleScope scope(isolate);
    DirectHandle<String> a =
        isolate->factory()->InternalizeUtf8String(base::CStrVector(string));
    // InternalizeUtf8String may return a failure if a GC is needed.
    CHECK(IsInternalizedString(*a));
    DirectHandle<String> b = factory->InternalizeUtf8String(string);
    CHECK_EQ(*b, *a);
    CHECK(b->IsOneByteEqualTo(base::CStrVector(string)));
    b = isolate->factory()->InternalizeUtf8String(base::CStrVector(string));
    CHECK_EQ(*b, *a);
    CHECK(b->IsOneByteEqualTo(base::CStrVector(string)));
  }
}

TEST(StringTable) {
  CcTest::InitializeVM();

  v8::HandleScope sc(CcTest::isolate());
  CheckInternalizedStrings(not_so_random_string_table);
  CheckInternalizedStrings(not_so_random_string_table);
}

TEST(FunctionAllocation) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  v8::HandleScope sc(CcTest::isolate());
  DirectHandle<String> name = factory->InternalizeUtf8String("theFunction");
  Handle<JSFunction> function = factory->NewFunctionForTesting(name);

  Handle<Smi> twenty_three(Smi::FromInt(23), isolate);
  Handle<Smi> twenty_four(Smi::FromInt(24), isolate);

  Handle<String> prop_name = factory->InternalizeUtf8String("theSlot");
  Handle<JSObject> obj = factory->NewJSObject(function);
  Object::SetProperty(isolate, obj, prop_name, twenty_three).Check();
  CHECK_EQ(Smi::FromInt(23),
           *Object::GetProperty(isolate, obj, prop_name).ToHandleChecked());
  // Check that we can add properties to function objects.
  Object::SetProperty(isolate, function, prop_name, twenty_four).Check();
  CHECK_EQ(
      Smi::FromInt(24),
      *Object::GetProperty(isolate, function, prop_name).ToHandleChecked());
}

TEST(ObjectProperties) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  v8::HandleScope sc(CcTest::isolate());
  Handle<String> object_string(
      Cast<String>(ReadOnlyRoots(CcTest::heap()).Object_string()), isolate);
  Handle<Object> object =
      Object::GetProperty(isolate, CcTest::i_isolate()->global_object(),
                          object_string)
          .ToHandleChecked();
  Handle<JSFunction> constructor = Cast<JSFunction>(object);
  Handle<JSObject> obj = factory->NewJSObject(constructor);
  Handle<String> first = factory->InternalizeUtf8String("first");
  Handle<String> second = factory->InternalizeUtf8String("second");

  Handle<Smi> one(Smi::FromInt(1), isolate);
  Handle<Smi> two(Smi::FromInt(2), isolate);

  // check for empty
  CHECK(Just(false) == JSReceiver::HasOwnProperty(isolate, obj, first));

  // add first
  Object::SetProperty(isolate, obj, first, one).Check();
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, first));

  // delete first
  CHECK(Just(true) ==
        JSReceiver::DeleteProperty(isolate, obj, first, LanguageMode::kSloppy));
  CHECK(Just(false) == JSReceiver::HasOwnProperty(isolate, obj, first));

  // add first and then second
  Object::SetProperty(isolate, obj, first, one).Check();
  Object::SetProperty(isolate, obj, second, two).Check();
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, first));
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, second));

  // delete first and then second
  CHECK(Just(true) ==
        JSReceiver::DeleteProperty(isolate, obj, first, LanguageMode::kSloppy));
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, second));
  CHECK(Just(true) == JSReceiver::DeleteProperty(isolate, obj, second,
                                                 LanguageMode::kSloppy));
  CHECK(Just(false) == JSReceiver::HasOwnProperty(isolate, obj, first));
  CHECK(Just(false) == JSReceiver::HasOwnProperty(isolate, obj, second));

  // add first and then second
  Object::SetProperty(isolate, obj, first, one).Check();
  Object::SetProperty(isolate, obj, second, two).Check();
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, first));
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, second));

  // delete second and then first
  CHECK(Just(true) == JSReceiver::DeleteProperty(isolate, obj, second,
                                                 LanguageMode::kSloppy));
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, first));
  CHECK(Just(true) ==
        JSReceiver::DeleteProperty(isolate, obj, first, LanguageMode::kSloppy));
  CHECK(Just(false) == JSReceiver::HasOwnProperty(isolate, obj, first));
  CHECK(Just(false) == JSReceiver::HasOwnProperty(isolate, obj, second));

  // check string and internalized string match
  const char* string1 = "fisk";
  Handle<String> s1 = factory->NewStringFromAsciiChecked(string1);
  Object::SetProperty(isolate, obj, s1, one).Check();
  Handle<String> s1_string = factory->InternalizeUtf8String(string1);
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, s1_string));

  // check internalized string and string match
  const char* string2 = "fugl";
  Handle<String> s2_string = factory->InternalizeUtf8String(string2);
  Object::SetProperty(isolate, obj, s2_string, one).Check();
  Handle<String> s2 = factory->NewStringFromAsciiChecked(string2);
  CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, obj, s2));
}

TEST(JSObjectMaps) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  v8::HandleScope sc(CcTest::isolate());
  DirectHandle<String> name = factory->InternalizeUtf8String("theFunction");
  Handle<JSFunction> function = factory->NewFunctionForTesting(name);

  Handle<String> prop_name = factory->InternalizeUtf8String("theSlot");
  Handle<JSObject> obj = factory->NewJSObject(function);
  DirectHandle<Map> initial_map(function->initial_map(), isolate);

  // Set a propery
  Handle<Smi> twenty_three(Smi::FromInt(23), isolate);
  Object::SetProperty(isolate, obj, prop_name, twenty_three).Check();
  CHECK_EQ(Smi::FromInt(23),
           *Object::GetProperty(isolate, obj, prop_name).ToHandleChecked());

  // Check the map has changed
  CHECK(*initial_map != obj->map());
}

TEST(JSArray) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  v8::HandleScope sc(CcTest::isolate());
  Handle<String> name = fact
"""


```