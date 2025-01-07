Response:
Let's break down the request and formulate a plan to address it effectively.

**1. Understanding the Core Task:**

The primary goal is to analyze the provided C++ code snippet for `v8/test/cctest/heap/test-mark-compact.cc` and describe its functionality. This involves understanding what the code *does* in terms of V8's heap management.

**2. Identifying Key Information to Extract:**

The request specifically asks for:

* **Functionality:** A high-level explanation of the code's purpose.
* **Torque Check:**  Whether the file would be a Torque file if it had a `.tq` extension.
* **JavaScript Relation:**  Connection to JavaScript functionality and an illustrative example.
* **Code Logic Reasoning:**  Explanation of any specific logic, including hypothetical inputs and outputs.
* **Common Programming Errors:** Identification of potential errors related to the tested scenarios.

**3. Initial Code Scan and Keyword Identification:**

Skimming the code reveals important keywords and concepts:

* `TEST(...)`: Indicates this is a C++ testing file.
* `MarkCompactCollector`: Directly relates to V8's mark-compact garbage collection algorithm.
* `Heap`, `Isolate`, `Factory`, `FixedArray`, `JSGlobalObject`, `JSFunction`, `JSObject`, `Map`: These are core V8 object and heap management classes.
* `InvokeMajorGC`, `InvokeMinorGC`:  Explicitly triggers garbage collection.
* `SealCurrentObjects`:  Freezes the current state of objects, often used in testing.
* `AllocationResult`:  Deals with memory allocation outcomes.
* `MemoryChunk`, `Pinned`: Concepts related to memory page management and preventing eviction.
* `#ifdef __linux__`, `/proc/self/maps`:  Linux-specific code for memory usage analysis.
* `incremental_marking`:  A feature of V8's garbage collection.

**4. Deconstructing Each Test Case:**

To understand the functionality, I need to analyze each `TEST(...)` block individually:

* **`Promotion`:**  Seems to test object promotion from new space to old space during garbage collection.
* **`MarkCompactCollector`:** This appears to be a more comprehensive test, covering various aspects of mark-compact, including basic invocation, handling of different object types (arrays, maps, functions, objects), and property access after GC.
* **`DoNotEvacuatePinnedPages`:**  Focuses on testing the behavior of pinned memory pages during compaction, ensuring they are not moved when pinned and are moved when unpinned.
* **`RegressJoinThreadsOnIsolateDeinit` (UNINITIALIZED_TEST):** This test (Linux-specific) seems to measure memory usage related to short-lived isolates, likely checking for memory leaks or improper cleanup.
* **`Regress5829`:**  Tests a specific regression related to incremental marking, potentially involving trimming arrays and ensuring mark bits are handled correctly.

**5. Planning the Response Structure:**

I'll organize the response according to the prompt's requests:

* **Overall Functionality:** Summarize the general purpose of the file (testing mark-compact GC).
* **Torque:**  Address the `.tq` question directly.
* **JavaScript Relation:**  Identify the JavaScript concepts being tested (objects, functions, properties, garbage collection) and create simple JavaScript examples that would trigger similar behaviors.
* **Code Logic Reasoning:** For each test case, provide:
    * A brief description of the test's goal.
    * Hypothetical "input" (the setup of the heap and objects).
    * Expected "output" (the assertions made in the test).
* **Common Programming Errors:**  Relate the test scenarios to common errors, such as memory leaks, dangling pointers (though less direct in managed languages), and unexpected object behavior after GC.

**6. Addressing Specific Challenges:**

* **Linux-Specific Code:** The memory usage tests require careful explanation of their limited scope.
* **Internal V8 Concepts:** I need to explain terms like "new space," "old space," "pinned pages," and "incremental marking" in a way that is understandable even without deep V8 knowledge.

**7. Refinement and Iteration:**

After drafting the initial response, I'll review it to ensure:

* **Accuracy:**  The explanations are correct based on the code.
* **Clarity:** The language is easy to understand.
* **Completeness:** All aspects of the prompt are addressed.
* **Conciseness:**  Avoid unnecessary jargon or overly technical details.

By following this structured approach, I can effectively analyze the provided C++ code and generate a comprehensive and helpful response that addresses all the user's requirements.
这个C++源代码文件 `v8/test/cctest/heap/test-mark-compact.cc` 的主要功能是 **测试 V8 引擎的 Mark-Compact 垃圾回收器**。

更具体地说，它包含了一系列 C++ 单元测试，用于验证 Mark-Compact 垃圾回收器在各种场景下的正确性和性能。这些测试覆盖了 Mark-Compact 垃圾回收器的不同方面，例如：

* **对象晋升 (Promotion):**  测试年轻代（New Space）的对象在经过垃圾回收后是否能够正确晋升到老年代（Old Space）。
* **基本 Mark-Compact 流程:** 测试在各种堆状态下调用 Mark-Compact 垃圾回收器是否能正常工作，包括空堆、包含各种类型对象（例如，数组、Map、函数、普通对象）的堆。
* **Pinned Pages 的处理:** 测试带有 `PINNED` 标记的内存页是否在 Mark-Compact 过程中被正确保留，不会被移动。
* **回归测试 (Regression Tests):** 包含了一些针对特定 bug 的回归测试，例如 `Regress5829`，确保修复后的问题不会再次出现。
* **内存使用情况的测试 (Linux Only):**  在 Linux 环境下，测试 Mark-Compact 垃圾回收器对内存使用的影响。

**关于文件扩展名和 Torque:**

如果 `v8/test/cctest/heap/test-mark-compact.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。`.tq` 文件通常包含类型定义、内置函数的实现等。

**与 JavaScript 的关系以及 JavaScript 示例:**

`v8/test/cctest/heap/test-mark-compact.cc` 测试的垃圾回收机制是 V8 引擎的核心部分，它直接影响着 JavaScript 代码的执行和内存管理。  当 JavaScript 代码创建对象、调用函数时，V8 引擎会在堆上分配内存。当不再需要这些对象时，垃圾回收器会回收它们占用的内存。

以下是一些与 `test-mark-compact.cc` 中测试场景相关的 JavaScript 示例：

1. **对象晋升 (Promotion):**

   ```javascript
   let longLivedObject = {}; // 在新生代分配

   function allocateGarbage() {
     for (let i = 0; i < 10000; i++) {
       let shortLivedObject = { data: i }; // 快速创建和丢弃大量对象
     }
   }

   allocateGarbage();
   allocateGarbage();
   // 多次分配和回收，触发 Minor GC，使得 longLivedObject 更有可能晋升到老年代

   // 之后继续使用 longLivedObject
   longLivedObject.property = "still here";
   ```

   这个 JavaScript 例子中，`longLivedObject` 如果存活足够长，并且经历了多次新生代垃圾回收（Minor GC），则很可能会被晋升到老年代，这正是 `Promotion` 测试所验证的。

2. **基本的 Mark-Compact 流程:**

   ```javascript
   let globalObject = {};
   globalThis.myObject = globalObject; // 使 globalObject 可达

   function createAndForget() {
     let tempObject = { data: "temporary" }; // 创建临时对象
   }

   createAndForget(); // tempObject 变得不可达

   // ... 一段时间后，或者在内存压力下，触发 Major GC (Mark-Compact)

   console.log(globalThis.myObject); // globalObject 应该仍然存在
   // tempObject 应该被回收
   ```

   这个例子模拟了 Mark-Compact 垃圾回收器的基本功能：标记可达对象（`globalObject`），并回收不可达对象（`tempObject`）。

3. **属性访问和垃圾回收:**

   ```javascript
   let myObject = { value: 23 };
   globalThis.theObject = myObject;

   // 模拟垃圾回收发生
   // ...

   console.log(globalThis.theObject.value); // 访问回收后的对象属性
   ```

   `MarkCompactCollector` 测试中的很多用例都关注在垃圾回收之后，对象及其属性是否仍然能够被正确访问，这反映了 JavaScript 代码中对对象属性的常见操作。

**代码逻辑推理和假设输入输出:**

以 `TEST(Promotion)` 为例：

**假设输入:**

* 启动 V8 引擎，未开启 `single_generation` 标志（意味着存在新生代和老年代）。
* 在新生代中分配一个非常大的 `FixedArray`，其大小接近或等于新生代的最大对象大小。

**代码逻辑:**

1. `CcTest::InitializeVM();` 初始化 V8 引擎。
2. `isolate->factory()->NewFixedArray(array_length);` 在新生代分配一个 `FixedArray`。
3. `CHECK(heap->InSpace(*array, NEW_SPACE));` 断言该数组最初位于新生代。
4. `heap::InvokeMajorGC(heap);` 触发一次 Full GC (Mark-Compact)。
5. `heap::InvokeMajorGC(heap);` 再次触发 Full GC。
6. `CHECK(heap->InSpace(*array, OLD_SPACE));` 断言经过两次 Full GC 后，该数组已晋升到老年代。

**预期输出:**

该测试会断言在两次 Major GC 后，最初分配在新生代的 `FixedArray` 现在位于老年代。这是因为大的对象或者存活时间较长的对象会被晋升到老年代，避免在频繁的新生代垃圾回收中被清理。

**用户常见的编程错误:**

1. **内存泄漏:**  在 JavaScript 中，如果创建了对象但没有正确解除引用，导致对象一直可达，那么垃圾回收器无法回收这些对象，最终可能导致内存泄漏。

   ```javascript
   let leakedObjects = [];
   function createLeakedObject() {
     let obj = { data: new Array(1000000) }; // 创建一个占用较大内存的对象
     leakedObjects.push(obj); // 将对象添加到全局数组，使其一直可达
   }

   for (let i = 0; i < 100; i++) {
     createLeakedObject(); // 持续创建并存储对象，导致内存占用增加
   }
   ```

   `test-mark-compact.cc` 中的测试确保了垃圾回收器能够正确识别和回收不可达的对象，从而帮助避免这类内存泄漏问题。

2. **意外的对象被回收:**  如果开发者错误地认为某个对象不再被使用，并移除了对其的引用，但实际上该对象仍然被其他部分的代码引用，那么该对象可能会被垃圾回收器回收，导致程序出现错误（例如尝试访问已回收的对象）。虽然 JavaScript 的垃圾回收是自动的，但理解其机制对于避免这类问题仍然很重要。

   ```javascript
   function processData(data) {
     // ... 对 data 进行处理 ...
   }

   function main() {
     let data = { value: "important data" };
     processData(data);
     data = null; // 错误地认为 data 不再需要

     // ... 稍后某处的代码尝试访问 data ... (这将会出错)
     // console.log(data.value);
   }

   main();
   ```

   `test-mark-compact.cc` 中对对象属性访问的测试，如 `HEAP_TEST(MarkCompactCollector)` 中的例子，验证了在垃圾回收后，可达对象的属性仍然可以被正确访问，这有助于确保 JavaScript 代码的正确性。

总之，`v8/test/cctest/heap/test-mark-compact.cc` 是一个关键的测试文件，它通过各种 C++ 单元测试来确保 V8 引擎的 Mark-Compact 垃圾回收器能够正确有效地管理 JavaScript 程序的内存，从而保证程序的稳定性和性能。这些测试覆盖了对象分配、晋升、回收等核心环节，并有助于发现和修复潜在的内存管理问题。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-mark-compact.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-mark-compact.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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

#include "src/common/globals.h"

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <utility>

#include "include/v8-locker.h"
#include "src/handles/global-handles.h"
#include "src/heap/live-object-range-inl.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-inl.h"
#include "src/init/v8.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-tester.h"
#include "test/cctest/heap/heap-utils.h"

namespace v8 {
namespace internal {
namespace heap {

TEST(Promotion) {
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  {
    v8::HandleScope sc(CcTest::isolate());
    Heap* heap = isolate->heap();

    heap::SealCurrentObjects(heap);

    int array_length = heap::FixedArrayLenFromSize(kMaxRegularHeapObjectSize);
    DirectHandle<FixedArray> array =
        isolate->factory()->NewFixedArray(array_length);

    // Array should be in the new space.
    CHECK(heap->InSpace(*array, NEW_SPACE));
    heap::InvokeMajorGC(heap);
    heap::InvokeMajorGC(heap);
    CHECK(heap->InSpace(*array, OLD_SPACE));
  }
}

// This is the same as Factory::NewContextfulMapForCurrentContext, except it
// doesn't retry on allocation failure.
AllocationResult HeapTester::AllocateMapForTest(Isolate* isolate) {
  Heap* heap = isolate->heap();
  Tagged<HeapObject> obj;
  AllocationResult alloc = heap->AllocateRaw(Map::kSize, AllocationType::kMap);
  if (!alloc.To(&obj)) return alloc;
  ReadOnlyRoots roots(isolate);
  obj->set_map_after_allocation(isolate, *isolate->meta_map());
  return AllocationResult::FromObject(isolate->factory()->InitializeMap(
      Cast<Map>(obj), JS_OBJECT_TYPE, JSObject::kHeaderSize,
      TERMINAL_FAST_ELEMENTS_KIND, 0, roots));
}

// This is the same as Factory::NewFixedArray, except it doesn't retry
// on allocation failure.
AllocationResult HeapTester::AllocateFixedArrayForTest(
    Heap* heap, int length, AllocationType allocation) {
  DCHECK(length >= 0 && length <= FixedArray::kMaxLength);
  int size = FixedArray::SizeFor(length);
  Tagged<HeapObject> obj;
  {
    AllocationResult result = heap->AllocateRaw(size, allocation);
    if (!result.To(&obj)) return result;
  }
  obj->set_map_after_allocation(heap->isolate(),
                                ReadOnlyRoots(heap).fixed_array_map(),
                                SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(obj);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(),
               ReadOnlyRoots(heap).undefined_value(), length);
  return AllocationResult::FromObject(array);
}

HEAP_TEST(MarkCompactCollector) {
  v8_flags.incremental_marking = false;
  v8_flags.retain_maps_for_n_gc = 0;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = isolate->factory();

  v8::HandleScope sc(CcTest::isolate());
  Handle<JSGlobalObject> global(isolate->context()->global_object(), isolate);

  // call mark-compact when heap is empty
  heap::InvokeMajorGC(heap);

  AllocationResult allocation;
  if (!v8_flags.single_generation) {
    // keep allocating garbage in new space until it fails
    const int arraysize = 100;
    do {
      allocation =
          AllocateFixedArrayForTest(heap, arraysize, AllocationType::kYoung);
    } while (!allocation.IsFailure());
    heap::InvokeMinorGC(heap);
    AllocateFixedArrayForTest(heap, arraysize, AllocationType::kYoung)
        .ToObjectChecked();
  }

  // keep allocating maps until it fails
  do {
    allocation = AllocateMapForTest(isolate);
  } while (!allocation.IsFailure());
  heap::InvokeMajorGC(heap);
  AllocateMapForTest(isolate).ToObjectChecked();

  { HandleScope scope(isolate);
    // allocate a garbage
    Handle<String> func_name = factory->InternalizeUtf8String("theFunction");
    Handle<JSFunction> function = factory->NewFunctionForTesting(func_name);
    Object::SetProperty(isolate, global, func_name, function).Check();

    factory->NewJSObject(function);
  }

  heap::InvokeMajorGC(heap);

  { HandleScope scope(isolate);
    Handle<String> func_name = factory->InternalizeUtf8String("theFunction");
    CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, global, func_name));
    Handle<Object> func_value =
        Object::GetProperty(isolate, global, func_name).ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    Handle<JSFunction> function = Cast<JSFunction>(func_value);
    Handle<JSObject> obj = factory->NewJSObject(function);

    Handle<String> obj_name = factory->InternalizeUtf8String("theObject");
    Object::SetProperty(isolate, global, obj_name, obj).Check();
    Handle<String> prop_name = factory->InternalizeUtf8String("theSlot");
    Handle<Smi> twenty_three(Smi::FromInt(23), isolate);
    Object::SetProperty(isolate, obj, prop_name, twenty_three).Check();
  }

  heap::InvokeMajorGC(heap);

  { HandleScope scope(isolate);
    Handle<String> obj_name = factory->InternalizeUtf8String("theObject");
    CHECK(Just(true) == JSReceiver::HasOwnProperty(isolate, global, obj_name));
    Handle<Object> object =
        Object::GetProperty(isolate, global, obj_name).ToHandleChecked();
    CHECK(IsJSObject(*object));
    Handle<String> prop_name = factory->InternalizeUtf8String("theSlot");
    CHECK_EQ(*Object::GetProperty(isolate, Cast<JSObject>(object), prop_name)
                  .ToHandleChecked(),
             Smi::FromInt(23));
  }
}

HEAP_TEST(DoNotEvacuatePinnedPages) {
  if (!v8_flags.compact || !v8_flags.single_generation) return;

  v8_flags.compact_on_every_full_gc = true;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();

  v8::HandleScope sc(CcTest::isolate());
  Heap* heap = isolate->heap();

  heap::SealCurrentObjects(heap);

  DirectHandleVector<FixedArray> handles(isolate);
  heap::CreatePadding(
      heap, static_cast<int>(MemoryChunkLayout::AllocatableMemoryInDataPage()),
      AllocationType::kOld, &handles);

  MemoryChunk* chunk = MemoryChunk::FromHeapObject(*handles.front());

  CHECK(heap->InSpace(*handles.front(), OLD_SPACE));
  chunk->SetFlagNonExecutable(MemoryChunk::PINNED);

  heap::InvokeMajorGC(heap);
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);

  // The pinned flag should prevent the page from moving.
  for (DirectHandle<FixedArray> object : handles) {
    CHECK_EQ(chunk, MemoryChunk::FromHeapObject(*object));
  }

  chunk->ClearFlagNonExecutable(MemoryChunk::PINNED);

  heap::InvokeMajorGC(heap);
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);

  // `compact_on_every_full_gc` ensures that this page is an evacuation
  // candidate, so with the pin flag cleared compaction should now move it.
  for (DirectHandle<FixedArray> object : handles) {
    CHECK_NE(chunk, MemoryChunk::FromHeapObject(*object));
  }
}

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define V8_WITH_ASAN 1
#endif
#endif

// Here is a memory use test that uses /proc, and is therefore Linux-only.  We
// do not care how much memory the simulator uses, since it is only there for
// debugging purposes. Testing with ASAN doesn't make sense, either.
#if defined(__linux__) && !defined(USE_SIMULATOR) && !defined(V8_WITH_ASAN)


static uintptr_t ReadLong(char* buffer, intptr_t* position, int base) {
  char* end_address = buffer + *position;
  uintptr_t result = strtoul(buffer + *position, &end_address, base);
  CHECK(result != ULONG_MAX || errno != ERANGE);
  CHECK(end_address > buffer + *position);
  *position = end_address - buffer;
  return result;
}


// The memory use computed this way is not entirely accurate and depends on
// the way malloc allocates memory.  That's why the memory use may seem to
// increase even though the sum of the allocated object sizes decreases.  It
// also means that the memory use depends on the kernel and stdlib.
static intptr_t MemoryInUse() {
  intptr_t memory_use = 0;

  int fd = open("/proc/self/maps", O_RDONLY);
  if (fd < 0) return -1;

  const int kBufSize = 20000;
  char buffer[kBufSize];
  ssize_t length = read(fd, buffer, kBufSize);
  intptr_t line_start = 0;
  CHECK_LT(length, kBufSize);  // Make the buffer bigger.
  CHECK_GT(length, 0);  // We have to find some data in the file.
  while (line_start < length) {
    if (buffer[line_start] == '\n') {
      line_start++;
      continue;
    }
    intptr_t position = line_start;
    uintptr_t start = ReadLong(buffer, &position, 16);
    CHECK_EQ(buffer[position++], '-');
    uintptr_t end = ReadLong(buffer, &position, 16);
    CHECK_EQ(buffer[position++], ' ');
    CHECK(buffer[position] == '-' || buffer[position] == 'r');
    bool read_permission = (buffer[position++] == 'r');
    CHECK(buffer[position] == '-' || buffer[position] == 'w');
    bool write_permission = (buffer[position++] == 'w');
    CHECK(buffer[position] == '-' || buffer[position] == 'x');
    bool execute_permission = (buffer[position++] == 'x');
    CHECK(buffer[position] == 's' || buffer[position] == 'p');
    bool private_mapping = (buffer[position++] == 'p');
    CHECK_EQ(buffer[position++], ' ');
    uintptr_t offset = ReadLong(buffer, &position, 16);
    USE(offset);
    CHECK_EQ(buffer[position++], ' ');
    uintptr_t major = ReadLong(buffer, &position, 16);
    USE(major);
    CHECK_EQ(buffer[position++], ':');
    uintptr_t minor = ReadLong(buffer, &position, 16);
    USE(minor);
    CHECK_EQ(buffer[position++], ' ');
    uintptr_t inode = ReadLong(buffer, &position, 10);
    while (position < length && buffer[position] != '\n') position++;
    if ((read_permission || write_permission || execute_permission) &&
        private_mapping && inode == 0) {
      memory_use += (end - start);
    }

    line_start = position;
  }
  close(fd);
  return memory_use;
}


intptr_t ShortLivingIsolate() {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  { v8::Isolate::Scope isolate_scope(isolate);
    v8::Locker lock(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
  }
  isolate->Dispose();
  return MemoryInUse();
}

UNINITIALIZED_TEST(RegressJoinThreadsOnIsolateDeinit) {
  // Memory is measured, do not allocate in background thread.
  v8_flags.stress_concurrent_allocation = false;
  intptr_t size_limit = ShortLivingIsolate() * 2;
  for (int i = 0; i < 10; i++) {
    CHECK_GT(size_limit, ShortLivingIsolate());
  }
}

TEST(Regress5829) {
  if (!v8_flags.incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::HandleScope sc(CcTest::isolate());
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  i::IncrementalMarking* marking = heap->incremental_marking();
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK(marking->IsMarking() || marking->IsStopped());
  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMarking());
  CHECK(marking->black_allocation());
  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(10, AllocationType::kOld);
  Address old_end = array->address() + array->Size();
  // Right trim the array without clearing the mark bits.
  array->set_length(9);
  heap->CreateFillerObjectAt(old_end - kTaggedSize, kTaggedSize);
  heap->FreeMainThreadLinearAllocationAreas();
  PageMetadata* page = PageMetadata::FromAddress(array->address());
  for (auto object_and_size : LiveObjectRange(page)) {
    CHECK(!IsFreeSpaceOrFiller(object_and_size.first));
  }
}

#endif  // __linux__ and !USE_SIMULATOR

}  // namespace heap
}  // namespace internal
}  // namespace v8

"""

```