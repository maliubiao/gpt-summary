Response: The user wants me to summarize the functionality of the provided C++ code snippet. I should focus on the parts related to heap management and testing within the V8 JavaScript engine. I need to identify the main functionalities being tested and how they relate to JavaScript concepts if possible, illustrating with JavaScript examples.

The code snippet seems to be a part of a larger test suite for the V8 engine's heap. It includes tests for:
- Basic heap object creation and manipulation (numbers, strings, objects, arrays).
- Garbage collection (minor and major GC).
- String internalization and management.
- Global and local handles.
- Weak handles.
- Bytecode array management and flushing.
- Compilation cache behavior.

Let's break down the functionalities and see if there are direct JavaScript equivalents to illustrate the concepts.
This C++ code snippet is part of the V8 JavaScript engine's test suite, specifically testing the functionality of the V8 heap. It focuses on verifying core heap operations and object management mechanisms.

Here's a breakdown of its main functions:

1. **Basic Heap Object Creation and Properties:**
    *   It tests the creation of fundamental V8 heap objects like Maps (object structure descriptors), HeapNumbers (floating-point numbers), FixedArrays (dynamically sized arrays), Strings, and JSObjects (general JavaScript objects).
    *   It verifies the properties of these objects, such as their type, size, and internal structure.
    *   It checks the behavior of oddball values (like `true`, `false`, `null`, `undefined`) and their string representations.

2. **Garbage Collection (GC):**
    *   The code includes tests for both minor (scavenge) and major (mark-compact) garbage collection cycles.
    *   It verifies that objects that are still reachable from global objects survive GC, while unreachable objects are collected.

3. **String Management:**
    *   It tests the creation and manipulation of strings, including both one-byte (ASCII) and two-byte (UTF-16) strings.
    *   It specifically tests string internalization, a process where identical strings share the same memory location to save space and improve performance.

4. **Handles (Local and Global):**
    *   The code demonstrates the usage of local and global handles. Handles are smart pointers used to manage V8 objects and prevent them from being prematurely garbage collected.
    *   Global handles persist across function calls and GC cycles, while local handles are typically scoped to a specific function or block.

5. **Weak Handles:**
    *   It tests weak global handles, which allow holding a reference to an object without preventing its garbage collection. A callback is associated with a weak handle and is invoked when the referenced object is collected.

6. **Bytecode Array Management:**
    *   The code includes tests related to `BytecodeArray`, which stores the bytecode generated from JavaScript code.
    *   It verifies the creation, initialization, and survival of `BytecodeArray` objects across garbage collection cycles.
    *   It also tests "bytecode flushing," a mechanism where bytecode for infrequently used functions can be discarded to save memory and recompiled when needed.

7. **Object Properties and Arrays:**
    *   The tests cover adding, deleting, and checking the existence of properties on JSObjects.
    *   It also tests the creation and manipulation of JSArrays, including setting and getting elements, and changing the array's length.

8. **Object Copying:**
    *   The code tests the functionality of copying JSObjects, ensuring that the cloned object has the same properties and elements as the original.

9. **Heap Iteration:**
    *   It includes a test that iterates through the heap to find specific allocated objects.

10. **Compilation Cache:**
    *   The code tests the behavior of the compilation cache, which stores compiled JavaScript code to avoid redundant compilations. It verifies that cached code survives GC cycles and can be flushed under certain conditions.

**Relationship to JavaScript and Examples:**

Many of the functionalities tested in this C++ code directly relate to how JavaScript code is executed and managed within the V8 engine. Here are some examples:

*   **Heap Objects:** When you create variables in JavaScript, V8 allocates corresponding objects on the heap:

    ```javascript
    let number = 42;  // A HeapNumber or Smi might be allocated
    let text = "hello"; // A String object is allocated
    let obj = {};      // A JSObject is allocated
    let arr = [1, 2, 3]; // A JSArray is allocated
    ```

*   **Garbage Collection:**  JavaScript's automatic memory management relies on the garbage collector. V8's GC reclaims memory occupied by objects that are no longer reachable:

    ```javascript
    function createObject() {
      let localObj = { data: "important" };
      return localObj; // localObj is still reachable
    }

    let myObj = createObject(); // myObj keeps the object alive

    myObj = null; // Now the object created inside createObject is likely garbage collected
    ```

*   **String Interning:**  JavaScript engines often intern strings to optimize memory usage:

    ```javascript
    let str1 = "hello";
    let str2 = "hello";
    console.log(str1 === str2); // true, in many engines, these might point to the same memory location
    ```

*   **Object Properties:**  Adding and deleting properties in JavaScript directly interacts with V8's object property management:

    ```javascript
    let person = { name: "Alice" };
    person.age = 30; // Adds a property
    delete person.age; // Deletes the property
    console.log("age" in person); // false
    ```

*   **Arrays:** JavaScript arrays are fundamental, and their behavior is tested extensively in the C++ code:

    ```javascript
    let numbers = [10, 20, 30];
    console.log(numbers.length); // 3
    numbers.push(40);
    console.log(numbers[0]); // 10
    ```

*   **Function Compilation and Caching:** When a JavaScript function is defined, V8 compiles it into bytecode. The compilation cache stores this bytecode for potential reuse:

    ```javascript
    function add(a, b) {
      return a + b;
    }

    add(5, 3); // Function is compiled (or retrieved from cache)
    add(10, 2); // Might reuse the cached bytecode
    ```

In essence, this `test-heap.cc` file is a low-level verification of the core memory management and object handling mechanisms that underpin JavaScript execution in the V8 engine. The C++ tests directly manipulate the internal structures of the V8 heap to ensure their correctness and robustness, which directly impacts the performance and reliability of JavaScript code.

### 提示词
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```
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
  Handle<String> name = factory->InternalizeUtf8String("Array");
  Handle<Object> fun_obj =
      Object::GetProperty(isolate, CcTest::i_isolate()->global_object(), name)
          .ToHandleChecked();
  Handle<JSFunction> function = Cast<JSFunction>(fun_obj);

  // Allocate the object.
  DirectHandle<Object> element;
  Handle<JSObject> object = factory->NewJSObject(function);
  Handle<JSArray> array = Cast<JSArray>(object);
  // We just initialized the VM, no heap allocation failure yet.
  JSArray::Initialize(array, 0);

  // Set array length to 0.
  JSArray::SetLength(array, 0);
  CHECK_EQ(Smi::zero(), array->length());
  // Must be in fast mode.
  CHECK(array->HasSmiOrObjectElements());

  // array[length] = name.
  Object::SetElement(isolate, array, 0, name, ShouldThrow::kDontThrow).Check();
  CHECK_EQ(Smi::FromInt(1), array->length());
  element = i::Object::GetElement(isolate, array, 0).ToHandleChecked();
  CHECK_EQ(*element, *name);

  // Set array length with larger than smi value.
  JSArray::SetLength(array, static_cast<uint32_t>(Smi::kMaxValue) + 1);

  uint32_t int_length = 0;
  CHECK(Object::ToArrayIndex(array->length(), &int_length));
  CHECK_EQ(static_cast<uint32_t>(Smi::kMaxValue) + 1, int_length);
  CHECK(array->HasDictionaryElements());  // Must be in slow mode.

  // array[length] = name.
  Object::SetElement(isolate, array, int_length, name, ShouldThrow::kDontThrow)
      .Check();
  uint32_t new_int_length = 0;
  CHECK(Object::ToArrayIndex(array->length(), &new_int_length));
  CHECK_EQ(static_cast<double>(int_length), new_int_length - 1);
  element = Object::GetElement(isolate, array, int_length).ToHandleChecked();
  CHECK_EQ(*element, *name);
  element = Object::GetElement(isolate, array, 0).ToHandleChecked();
  CHECK_EQ(*element, *name);
}

TEST(JSObjectCopy) {
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

  Object::SetProperty(isolate, obj, first, one).Check();
  Object::SetProperty(isolate, obj, second, two).Check();

  Object::SetElement(isolate, obj, 0, first, ShouldThrow::kDontThrow).Check();
  Object::SetElement(isolate, obj, 1, second, ShouldThrow::kDontThrow).Check();

  // Make the clone.
  DirectHandle<Object> value1, value2;
  Handle<JSObject> clone = factory->CopyJSObject(obj);
  CHECK(!clone.is_identical_to(obj));

  value1 = Object::GetElement(isolate, obj, 0).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 0).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetElement(isolate, obj, 1).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 1).ToHandleChecked();
  CHECK_EQ(*value1, *value2);

  value1 = Object::GetProperty(isolate, obj, first).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, first).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetProperty(isolate, obj, second).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, second).ToHandleChecked();
  CHECK_EQ(*value1, *value2);

  // Flip the values.
  Object::SetProperty(isolate, clone, first, two).Check();
  Object::SetProperty(isolate, clone, second, one).Check();

  Object::SetElement(isolate, clone, 0, second, ShouldThrow::kDontThrow)
      .Check();
  Object::SetElement(isolate, clone, 1, first, ShouldThrow::kDontThrow).Check();

  value1 = Object::GetElement(isolate, obj, 1).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 0).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetElement(isolate, obj, 0).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 1).ToHandleChecked();
  CHECK_EQ(*value1, *value2);

  value1 = Object::GetProperty(isolate, obj, second).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, first).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetProperty(isolate, obj, first).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, second).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
}

TEST(StringAllocation) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  const unsigned char chars[] = {0xE5, 0xA4, 0xA7};
  for (int length = 0; length < 100; length++) {
    v8::HandleScope scope(CcTest::isolate());
    char* non_one_byte = NewArray<char>(3 * length + 1);
    char* one_byte = NewArray<char>(length + 1);
    non_one_byte[3 * length] = 0;
    one_byte[length] = 0;
    for (int i = 0; i < length; i++) {
      one_byte[i] = 'a';
      non_one_byte[3 * i] = chars[0];
      non_one_byte[3 * i + 1] = chars[1];
      non_one_byte[3 * i + 2] = chars[2];
    }
    DirectHandle<String> non_one_byte_sym = factory->InternalizeUtf8String(
        base::Vector<const char>(non_one_byte, 3 * length));
    CHECK_EQ(length, non_one_byte_sym->length());
    DirectHandle<String> one_byte_sym =
        factory->InternalizeString(base::OneByteVector(one_byte, length));
    CHECK_EQ(length, one_byte_sym->length());
    CHECK(one_byte_sym->HasHashCode());
    DirectHandle<String> non_one_byte_str =
        factory
            ->NewStringFromUtf8(
                base::Vector<const char>(non_one_byte, 3 * length))
            .ToHandleChecked();
    CHECK_EQ(length, non_one_byte_str->length());
    DirectHandle<String> one_byte_str =
        factory->NewStringFromUtf8(base::Vector<const char>(one_byte, length))
            .ToHandleChecked();
    CHECK_EQ(length, one_byte_str->length());
    DeleteArray(non_one_byte);
    DeleteArray(one_byte);
  }
}

static int ObjectsFoundInHeap(Heap* heap, Handle<Object> objs[], int size) {
  // Count the number of objects found in the heap.
  int found_count = 0;
  HeapObjectIterator iterator(heap);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    for (int i = 0; i < size; i++) {
      // V8_EXTERNAL_CODE_SPACE specific: we might be comparing
      // InstructionStream object with non-InstructionStream object here and it
      // might produce false positives because operator== for tagged values
      // compares only lower 32 bits when pointer compression is enabled.
      if ((*objs[i]).ptr() == obj.ptr()) {
        found_count++;
      }
    }
  }
  return found_count;
}

TEST(Iteration) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  v8::HandleScope scope(CcTest::isolate());

  // Array of objects to scan heap for.
  const int objs_count = 6;
  Handle<Object> objs[objs_count];
  int next_objs_index = 0;

  // Allocate a JS array to OLD_SPACE and NEW_SPACE
  objs[next_objs_index++] = factory->NewJSArray(10);
  objs[next_objs_index++] =
      factory->NewJSArray(10, HOLEY_ELEMENTS, AllocationType::kOld);

  // Allocate a small string to OLD_DATA_SPACE and NEW_SPACE
  objs[next_objs_index++] = factory->NewStringFromStaticChars("abcdefghij");
  objs[next_objs_index++] =
      factory->NewStringFromStaticChars("abcdefghij", AllocationType::kOld);

  // Allocate a large string (for large object space).
  int large_size = kMaxRegularHeapObjectSize + 1;
  char* str = new char[large_size];
  for (int i = 0; i < large_size - 1; ++i) str[i] = 'a';
  str[large_size - 1] = '\0';
  objs[next_objs_index++] =
      factory->NewStringFromAsciiChecked(str, AllocationType::kOld);
  delete[] str;

  // Add a Map object to look for.
  objs[next_objs_index++] =
      Handle<Map>(Cast<HeapObject>(*objs[0])->map(), isolate);

  CHECK_EQ(objs_count, next_objs_index);
  CHECK_EQ(objs_count, ObjectsFoundInHeap(CcTest::heap(), objs, objs_count));
}

TEST(TestBytecodeFlushing) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = false;
  v8_flags.always_turbofan = false;
  i::v8_flags.optimize_for_size = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = i_isolate->factory();

  {
    v8::HandleScope scope(isolate);
    v8::Context::New(isolate)->Enter();
    const char* source =
        "function foo() {"
        "  var x = 42;"
        "  var y = 42;"
        "  var z = x + y;"
        "};"
        "foo()";
    IndirectHandle<String> foo_name = factory->InternalizeUtf8String("foo");

    // This compile will add the code to the compilation cache.
    {
      v8::HandleScope new_scope(isolate);
      CompileRun(source);
    }

    // Check function is compiled.
    IndirectHandle<Object> func_value =
        Object::GetProperty(i_isolate, i_isolate->global_object(), foo_name)
            .ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    IndirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
    CHECK(function->shared()->is_compiled());

    // The code will survive at least two GCs.
    {
      // In this test, we need to invoke GC without stack, otherwise some
      // objects may not be reclaimed because of conservative stack scanning.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
      heap::InvokeMajorGC(heap);
    }
    CHECK(function->shared()->is_compiled());

    i::SharedFunctionInfo::EnsureOldForTesting(function->shared());
    {
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // foo should no longer be in the compilation cache
    CHECK(!function->shared()->is_compiled());
    CHECK(!function->is_compiled(i_isolate));
    // Call foo to get it recompiled.
    CompileRun("foo()");
    CHECK(function->shared()->is_compiled());
    CHECK(function->is_compiled(i_isolate));
  }
}

static void TestMultiReferencedBytecodeFlushing(bool sparkplug_compile) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = false;
  v8_flags.always_turbofan = false;
  i::v8_flags.optimize_for_size = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
  v8_flags.flush_baseline_code = true;
#else
  if (sparkplug_compile) return;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = i_isolate->factory();

  {
    v8::HandleScope scope(isolate);
    v8::Context::New(isolate)->Enter();
    const char* source =
        "function foo() {"
        "  var x = 42;"
        "  var y = 42;"
        "  var z = x + y;"
        "};"
        "foo()";
    IndirectHandle<String> foo_name = factory->InternalizeUtf8String("foo");

    // This compile will add the code to the compilation cache.
    {
      v8::HandleScope new_scope(isolate);
      CompileRun(source);
    }

    // Check function is compiled.
    IndirectHandle<Object> func_value =
        Object::GetProperty(i_isolate, i_isolate->global_object(), foo_name)
            .ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    IndirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
    IndirectHandle<SharedFunctionInfo> shared(function->shared(), i_isolate);
    CHECK(shared->is_compiled());

    // Make a copy of the SharedFunctionInfo which points to the same bytecode.
    IndirectHandle<SharedFunctionInfo> copy =
        i_isolate->factory()->CloneSharedFunctionInfo(shared);

    if (sparkplug_compile) {
      v8::HandleScope baseline_compilation_scope(isolate);
      IsCompiledScope is_compiled_scope = copy->is_compiled_scope(i_isolate);
      Compiler::CompileSharedWithBaseline(
          i_isolate, copy, Compiler::CLEAR_EXCEPTION, &is_compiled_scope);
    }

    i::SharedFunctionInfo::EnsureOldForTesting(*shared);
    {
      // We need to invoke GC without stack, otherwise some objects may not be
      // reclaimed because of conservative stack scanning.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // shared SFI is marked old but BytecodeArray is kept alive by copy.
    CHECK(shared->is_compiled());
    CHECK(copy->is_compiled());
    CHECK(function->is_compiled(i_isolate));

    // The feedback metadata for both SharedFunctionInfo instances should have
    // been reset.
    CHECK(shared->HasFeedbackMetadata());
    CHECK(copy->HasFeedbackMetadata());
  }
}

TEST(TestMultiReferencedBytecodeFlushing) {
  TestMultiReferencedBytecodeFlushing(/*sparkplug_compile=*/false);
}

TEST(TestMultiReferencedBytecodeFlushingWithSparkplug) {
  TestMultiReferencedBytecodeFlushing(/*sparkplug_compile=*/true);
}

HEAP_TEST(Regress10560) {
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable flags that allocate a feedback vector eagerly.
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  i::v8_flags.turbofan = false;
  i::v8_flags.always_turbofan = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.lazy_feedback_allocation = true;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  {
    v8::HandleScope scope(isolate);
    const char* source =
        "function foo() {"
        "  var x = 42;"
        "  var y = 42;"
        "  var z = x + y;"
        "};"
        "foo()";
    Handle<String> foo_name = factory->InternalizeUtf8String("foo");
    CompileRun(source);

    // Check function is compiled.
    Handle<Object> func_value =
        Object::GetProperty(i_isolate, i_isolate->global_object(), foo_name)
            .ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    DirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
    CHECK(function->shared()->is_compiled());
    CHECK(!function->has_feedback_vector());

    // Pre-age bytecode so it will be flushed on next run.
    CHECK(function->shared()->HasBytecodeArray());
    SharedFunctionInfo::EnsureOldForTesting(function->shared());

    heap::SimulateFullSpace(heap->old_space());

    // Just check bytecode isn't flushed still
    CHECK(function->shared()->is_compiled());

    heap->set_force_gc_on_next_allocation();

    // Allocate feedback vector.
    IsCompiledScope is_compiled_scope(
        function->shared()->is_compiled_scope(i_isolate));
    JSFunction::EnsureFeedbackVector(i_isolate, function, &is_compiled_scope);

    CHECK(function->has_feedback_vector());
    CHECK(function->shared()->is_compiled());
    CHECK(function->is_compiled(i_isolate));
  }
}

UNINITIALIZED_TEST(Regress10843) {
  v8_flags.max_semi_space_size = 2;
  v8_flags.min_semi_space_size = 2;
  v8_flags.max_old_space_size = 8;
  v8_flags.compact_on_every_full_gc = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  bool callback_was_invoked = false;

  heap->AddNearHeapLimitCallback(
      [](void* data, size_t current_heap_limit,
         size_t initial_heap_limit) -> size_t {
        *reinterpret_cast<bool*>(data) = true;
        return current_heap_limit * 2;
      },
      &callback_was_invoked);

  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    HandleScope scope(i_isolate);
    std::vector<Handle<FixedArray>> arrays;
    for (int i = 0; i < 140; i++) {
      arrays.push_back(factory->NewFixedArray(10000));
    }
    heap::InvokeMajorGC(heap);
    heap::InvokeMajorGC(heap);
    for (int i = 0; i < 40; i++) {
      arrays.push_back(factory->NewFixedArray(10000));
    }
    heap::InvokeMajorGC(heap);
    for (int i = 0; i < 100; i++) {
      arrays.push_back(factory->NewFixedArray(10000));
    }
    heap::InvokeMajorGC(heap);
    CHECK(callback_was_invoked);
  }
  isolate->Dispose();
}

size_t near_heap_limit_invocation_count = 0;
size_t InvokeGCNearHeapLimitCallback(void* data, size_t current_heap_limit,
                                     size_t initial_heap_limit) {
  near_heap_limit_invocation_count++;
  if (near_heap_limit_invocation_count > 1) {
    // We are already in a GC triggered in this callback, raise the limit
    // to avoid an OOM.
    return current_heap_limit * 5;
  }

  DCHECK_EQ(near_heap_limit_invocation_count, 1);
  // Operations that may cause GC (e.g. taking heap snapshots) in the
  // near heap limit callback should not hit the AllowGarbageCollection
  // assertion.
  static_cast<v8::Isolate*>(data)->GetHeapProfiler()->TakeHeapSnapshot();
  return current_heap_limit * 5;
}

UNINITIALIZED_TEST(Regress12777) {
  v8::Isolate::CreateParams create_params;
  create_params.constraints.set_max_old_generation_size_in_bytes(10 * i::MB);
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  isolate->AddNearHeapLimitCallback(InvokeGCNearHeapLimitCallback, isolate);

  {
    v8::Isolate::Scope isolate_scope(isolate);

    Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
    // Allocate data to trigger the NearHeapLimitCallback.
    HandleScope scope(i_isolate);
    int length = 2 * i::MB / i::kTaggedSize;
    std::vector<Handle<FixedArray>> arrays;
    for (int i = 0; i < 5; i++) {
      arrays.push_back(i_isolate->factory()->NewFixedArray(length));
    }
    heap::InvokeMajorGC(i_isolate->heap());
    for (int i = 0; i < 5; i++) {
      arrays.push_back(i_isolate->factory()->NewFixedArray(length));
    }
    heap::InvokeMajorGC(i_isolate->heap());
    for (int i = 0; i < 5; i++) {
      arrays.push_back(i_isolate->factory()->NewFixedArray(length));
    }

    // Normally, taking a heap snapshot in the near heap limit would result in
    // a full GC, then the overhead of the promotions would cause another
    // invocation of the heap limit callback and it can raise the limit in
    // the second call to avoid an OOM, so we test that the callback can
    // indeed raise the limit this way in this case. When there is only one
    // generation, however, there would not be the overhead of promotions so the
    // callback may not be triggered again during the generation of the heap
    // snapshot. In that case we only need to check that the callback is called
    // and it can perform GC-triggering operations jsut fine there.
    size_t minimum_callback_invocation_count =
        v8_flags.single_generation ? 1 : 2;
    CHECK_GE(near_heap_limit_invocation_count,
             minimum_callback_invocation_count);
  }

  isolate->GetHeapProfiler()->DeleteAllHeapSnapshots();
  isolate->Dispose();
}

#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
TEST(TestOptimizeAfterBytecodeFlushingCandidate) {
  if (v8_flags.single_generation) return;
  v8_flags.turbofan = true;
  v8_flags.always_turbofan = false;
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.optimize_for_size = false;
  i::v8_flags.incremental_marking = true;
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;
  ManualGCScope manual_gc_scope;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = isolate->factory();

  v8::HandleScope outer_scope(CcTest::isolate());
  const char* source =
      "function foo() {"
      "  var x = 42;"
      "  var y = 42;"
      "  var z = x + y;"
      "};"
      "foo()";
  IndirectHandle<String> foo_name = factory->InternalizeUtf8String("foo");

  // This compile will add the code to the compilation cache.
  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun(source);
  }

  // Check function is compiled.
  IndirectHandle<Object> func_value =
      Object::GetProperty(isolate, isolate->global_object(), foo_name)
          .ToHandleChecked();
  CHECK(IsJSFunction(*func_value));
  IndirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
  CHECK(function->shared()->is_compiled());

  // The code will survive at least two GCs.
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(function->shared()->is_compiled());

  i::SharedFunctionInfo::EnsureOldForTesting(function->shared());
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  CHECK(!function->shared()->is_compiled());
  CHECK(!function->is_compiled(isolate));

  // This compile will compile the function again.
  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun("foo();");
  }

  SharedFunctionInfo::EnsureOldForTesting(function->shared());
  heap::SimulateIncrementalMarking(CcTest::heap());

  // Force optimization while incremental marking is active and while
  // the function is enqueued as a candidate.
  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun(
        "%PrepareFunctionForOptimization(foo);"
        "%OptimizeFunctionOnNextCall(foo); foo();");
  }

  // Simulate one final GC and make sure the candidate wasn't flushed.
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(function->shared()->is_compiled());
  CHECK(function->is_compiled(isolate));
}
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)

TEST(TestUseOfIncrementalBarrierOnCompileLazy) {
  if (!v8_flags.incremental_marking) return;
  // Turn off always_turbofan because it interferes with running the built-in
  // for the last call to g().
  v8_flags.always_turbofan = false;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  v8::HandleScope scope(CcTest::isolate());

  CompileRun(
      "function make_closure(x) {"
      "  return function() { return x + 3 };"
      "}"
      "var f = make_closure(5);"
      "%PrepareFunctionForOptimization(f); f();"
      "var g = make_closure(5);");

  // Check f is compiled.
  Handle<String> f_name = factory->InternalizeUtf8String("f");
  Handle<Object> f_value =
      Object::GetProperty(isolate, isolate->global_object(), f_name)
          .ToHandleChecked();
  DirectHandle<JSFunction> f_function = Cast<JSFunction>(f_value);
  CHECK(f_function->is_compiled(isolate));

  // Check g is not compiled.
  Handle<String> g_name = factory->InternalizeUtf8String("g");
  Handle<Object> g_value =
      Object::GetProperty(isolate, isolate->global_object(), g_name)
          .ToHandleChecked();
  DirectHandle<JSFunction> g_function = Cast<JSFunction>(g_value);
  CHECK(!g_function->is_compiled(isolate));

  heap::SimulateIncrementalMarking(heap);
  CompileRun("%OptimizeFunctionOnNextCall(f); f();");

  // g should now have available an optimized function, unmarked by gc. The
  // CompileLazy built-in will discover it and install it in the closure, and
  // the incremental write barrier should be used.
  CompileRun("g();");
  CHECK(g_function->is_compiled(isolate));
}

void CompilationCacheCachingBehavior(bool retain_script) {
  // If we do not have the compilation cache turned off, this test is invalid.
  if (!v8_flags.compilation_cache) {
    return;
  }
  if (!v8_flags.flush_bytecode ||
      (v8_flags.always_sparkplug && !v8_flags.flush_baseline_code)) {
    return;
  }
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = isolate->factory();
  CompilationCache* compilation_cache = isolate->compilation_cache();
  LanguageMode language_mode = LanguageMode::kSloppy;

  v8::HandleScope outer_scope(CcTest::isolate());
  const char* raw_source = retain_script ? "function foo() {"
                                           "  var x = 42;"
                                           "  var y = 42;"
                                           "  var z = x + y;"
                                           "};"
                                           "foo();"
                                         : "(function foo() {"
                                           "  var x = 42;"
                                           "  var y = 42;"
                                           "  var z = x + y;"
                                           "})();";
  IndirectHandle<String> source = factory->InternalizeUtf8String(raw_source);

  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun(raw_source);
  }

  // The script should be in the cache now.
  {
    v8::HandleScope scope(CcTest::isolate());
    ScriptDetails script_details(Handle<Object>(),
                                 v8::ScriptOriginOptions(true, false));
    auto lookup_result =
        compilation_cache->LookupScript(source, script_details, language_mode);
    CHECK(!lookup_result.toplevel_sfi().is_null());
  }

  // Check that the code cache entry survives at least one GC.
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  {
    v8::HandleScope scope(CcTest::isolate());
    ScriptDetails script_details(Handle<Object>(),
                                 v8::ScriptOriginOptions(true, false));
    auto lookup_result =
        compilation_cache->LookupScript(source, script_details, language_mode);
    CHECK(!lookup_result.toplevel_sfi().is_null());

    // Progress code age until it's old and ready for GC.
    DirectHandle<SharedFunctionInfo> shared =
        lookup_result.toplevel_sfi().ToHandleChecked();
    CHECK(shared->HasBytecodeArray());
    SharedFunctionInfo::EnsureOldForTesting(*shared);
  }

  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    // The first GC flushes the BytecodeArray from the SFI.
    heap::InvokeMajorGC(heap);
    // The second GC removes the SFI from the compilation cache.
    heap::InvokeMajorGC(heap);
  }

  {
    v8::HandleScope scope(CcTest::isolate());
    // Ensure code aging cleared the entry from the cache.
    ScriptDetails script_details(Handle<Object>(),
                                 v8::ScriptOriginOptions(true, false));
    auto lookup_result =
        compilation_cache->LookupScript(source, script_details, language_mode);
    CHECK(lookup_result.toplevel_sfi().is_null());
    CHECK_EQ(retain_script, !lookup_result.script().is_null());
  }
}

TEST(CompilationCacheCachingBehaviorDiscardScript) {
  CompilationCacheCachingBehavior(false);
}

TEST(CompilationCacheCachingBehaviorRetainScript) {
  CompilationCacheCachingBehavior(true);
}

namespace {

template <typename T>
Handle<SharedFunctionInfo> GetSharedFunctionInfo(
    v8::Local<T> function_or_script) {
  DirectHandle<JSFunction> i_function =
      Cast<JSFunction>(v8::Utils::OpenDirectHandle(*function_or_script));
  return handle(i_function->shared(), CcTest::i_isolate());
}

template <typename T>
void AgeBytecode(v8::Local<T> function_or_script) {
  DirectHandle<SharedFunctionInfo> shared =
      GetSharedFunctionInfo(function_or_script);
  CHECK(shared->HasBytecodeArray());
  SharedFunctionInfo::EnsureOldForTesting(*shared);
}

void CompilationCacheRegeneration(bool retain_root_sfi, bool flush_root_sfi,
                                  bool flush_eager_sfi) {
  // If the compilation cache is turned off, this test is invalid.
  if (!v8_flags.compilation_cache) {
    return;
  }

  // Skip test if code flushing was disabled.
  if (!v8_flags.flush_bytecode ||
      (v8_flags.always_sparkplug && !v8_flags.flush_baseline_code)) {
    return;
  }

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();

  const char* source =
      "({"
      "  lazyFunction: function () {"
      "    var x = 42;"
      "    var y = 42;"
      "    var z = x + y;"
      "  },"
      "  eagerFunction: (function () {"
      "    var x = 43;"
      "    var y = 43;"
      "    var z = x + y;"
      "  })"
      "})";

  v8::Global<v8::Script> outer_function;
  v8::Global<v8::Function> lazy_function;
  v8::Global<v8::Function> eager_function;

  {
    v8::HandleScope scope(CcTest::isolate());
    v8::Local<v8::Context> context =
        v8::Isolate::GetCurrent()->GetCurrentContext();
    v8::Local<v8::Script> script = v8_compile(v8_str(source));
    outer_function.Reset(CcTest::isolate(), script);

    // Even though the script has not executed, it should already be parsed.
    DirectHandle<SharedFunctionInfo> script_sfi = GetSharedFunctionInfo(script);
    CHECK(script_sfi->is_compiled());

    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();

    // Now that the script has run, we can get references to the inner
    // functions, and verify that the eager parsing heuristics are behaving as
    // expected.
    v8::Local<v8::Object> result_obj =
        result->ToObject(context).ToLocalChecked();
    v8::Local<v8::Value> lazy_function_value =
        result_obj->GetRealNamedProperty(context, v8_str("lazyFunction"))
            .ToLocalChecked();
    CHECK(lazy_function_value->IsFunction());
    CHECK(!GetSharedFunctionInfo(lazy_function_value)->is_compiled());
    lazy_function.Reset(CcTest::isolate(),
                        lazy_function_value.As<v8::Function>());
    v8::Local<v8::Value> eager_function_value =
        result_obj->GetRealNamedProperty(context, v8_str("eagerFunction"))
            .ToLocalChecked();
    CHECK(eager_function_value->IsFunction());
    eager_function.Reset(CcTest::isolate(),
                         eager_function_value.As<v8::Function>());
    CHECK(GetSharedFunctionInfo(eager_function_value)->is_compiled());
  }

  {
    v8::HandleScope scope(CcTest::isolate());

    // Progress code age until it's old and ready for GC.
    if (flush_root_sfi) {
      v8::Local<v8::Script> outer_function_value =
          outer_function.Get(CcTest::isolate());
      AgeBytecode(outer_function_value);
    }
    if (flush_eager_sfi) {
      v8::Local<v8::Function> eager_function_value =
          eager_function.Get(CcTest::isolate());
      AgeBytecode(eager_function_value);
    }
    if (!retain_root_sfi) {
      outer_function.Reset();
    }
  }

  {
    // In these tests, we need to invoke GC without stack, otherwise some
    // objects may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

    if (v8_flags.stress_incremental_marking) {
      // This GC finishes incremental marking if it is already running. If
      // incremental marking was already running we would not flush the code
      // right away.
      heap::InvokeMajorGC(heap);
    }

    // The first GC performs code flushing.
    heap::InvokeMajorGC(heap);
    // The second GC clears the entry from the compilation cache.
    heap::InvokeMajorGC(heap);
  }

  // The root SharedFunctionInfo can be retained either by a Global in this
  // function or by the compilation cache.
  bool root_sfi_should_still_exist = retain_root_sfi || !flush_root_sfi;

  {
    v8::HandleScope scope(CcTest::is
```