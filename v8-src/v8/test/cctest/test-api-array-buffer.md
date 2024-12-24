Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript examples.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code, paying attention to the included headers, the `TEST` macros, and the general structure. Key observations at this stage:

* **Headers:**  Includes like `src/api/api-inl.h`, `src/objects/js-array-buffer-inl.h`, and the `v8::` namespace strongly suggest this code is testing V8's C++ API for `ArrayBuffer` and related functionalities.
* **`TEST` Macros:** The numerous `THREADED_TEST` and `TEST` macros indicate that this file is a collection of unit tests. Each test focuses on a specific aspect of `ArrayBuffer` or `SharedArrayBuffer`.
* **Function Names:**  Names like `ArrayBuffer_ApiInternalToExternal`, `ArrayBuffer_DetachingApi`, `SharedArrayBuffer_JSInternalToExternal`, `BackingStore_NewBackingStore`, etc., clearly hint at the features being tested.
* **Assertions (`CHECK_EQ`, `CHECK`, `CHECK_NOT_NULL`):**  These are standard C++ testing assertions, confirming expected behavior.

**2. Grouping Tests by Functionality:**

Next, I'd start grouping the tests based on the themes they address. This helps in organizing the information. Looking at the test names and their contents, I can identify these categories:

* **Creation and Basic Properties:** Tests like `ArrayBuffer_ApiInternalToExternal`, `ArrayBuffer_ApiMaybeNew`, `SharedArrayBuffer_ApiInternalToExternal` focus on creating `ArrayBuffer` instances from C++ and verifying their properties (`byteLength`).
* **Interaction with JavaScript:** Tests like `ArrayBuffer_JSInternalToExternal`, `SharedArrayBuffer_JSInternalToExternal` demonstrate how JavaScript code interacts with `ArrayBuffer`s created in C++.
* **Detaching:** Tests like `ArrayBuffer_DisableDetach`, `ArrayBuffer_DetachingApi`, `ArrayBuffer_DetachingScript`, `ArrayBuffer_WasDetached`, `ArrayBuffer_NonDetachableWasDetached` cover the detachment mechanism.
* **Backing Stores:** A significant number of tests (`ArrayBuffer_ExternalizeEmpty`, `SharedArrayBuffer_ApiInternalToExternal`, `SharedArrayBuffer_JSInternalToExternal`, `SkipArrayBufferBackingStoreDuringGC`, `SkipArrayBufferDuringScavenge`, `ArrayBuffer_NewBackingStore`, `SharedArrayBuffer_NewBackingStore`,  and the custom deleter tests) are related to `BackingStore` management (creation, sharing, garbage collection, custom deleters).
* **Resizability:**  Tests like `ArrayBuffer_Resizable` and `ArrayBuffer_FixedLength` focus on resizable ArrayBuffers.
* **Data Access:** Tests like `ArrayBuffer_DataApiWithEmptyExternal` and the `ArrayBufferView_GetContents*` family deal with how to access the underlying data.
* **Memory Management and Allocation:**  Tests like `BackingStore_HoldAllocatorAlive_UntilIsolateShutdown`, `BackingStore_HoldAllocatorAlive_AfterIsolateShutdown`, `BackingStore_ReleaseAllocator_NullptrBackingStore` examine the lifecycle of the `ArrayBuffer::Allocator`.
* **Reallocation (Deprecated):** Tests prefixed with `BackingStore_Reallocate` handle the (deprecated) reallocation API.

**3. Detailed Analysis of Key Tests:**

Once the tests are grouped, I'd dive deeper into representative examples from each category. For instance:

* **`ArrayBuffer_ApiInternalToExternal`:**  This test creates an `ArrayBuffer` in C++, writes to it via a JavaScript `Uint8Array`, and then verifies the data in the C++ backing store. This illustrates how C++ can directly manipulate the memory of a JavaScript `ArrayBuffer`.
* **`ArrayBuffer_DetachingScript`:** This test demonstrates how detaching an `ArrayBuffer` in JavaScript invalidates associated `TypedArray` and `DataView` objects.
* **`ArrayBuffer_NewBackingStore`:** This shows the direct creation of an `ArrayBuffer` using a C++ backing store.
* **`ArrayBufferView_GetContentsSmallUint8`:** This example shows how to retrieve the contents of an `ArrayBufferView` back into C++ memory.

**4. Identifying the Relationship with JavaScript:**

As I analyze the tests, the connection to JavaScript becomes clear. The tests frequently:

* Create `ArrayBuffer` objects in C++ and then access or manipulate them from JavaScript.
* Create `ArrayBuffer` objects in JavaScript and then inspect their underlying data or properties from C++.
* Test JavaScript APIs related to `ArrayBuffer` like detaching and creating views.

**5. Crafting JavaScript Examples:**

With a solid understanding of the C++ tests, I can create corresponding JavaScript examples that demonstrate the same concepts. The goal is to show the JavaScript equivalent of what the C++ code is testing. For example:

* For `ArrayBuffer_ApiInternalToExternal`, the JavaScript example would show creating an `ArrayBuffer`, creating a `Uint8Array` view, and modifying the array to demonstrate the connection.
* For `ArrayBuffer_DetachingScript`, the JavaScript example would show creating an `ArrayBuffer` and a `DataView`, detaching the buffer, and then trying to access the detached `DataView` to trigger an error.
* For resizable ArrayBuffers, the JavaScript example shows the syntax for creating them with `maxByteLength`.

**6. Structuring the Summary:**

Finally, I'd structure the summary to be clear and concise:

* Start with a general overview of the file's purpose (testing `ArrayBuffer` API).
* List the key functionalities tested, using the categories identified earlier.
* Explain the relationship to JavaScript, highlighting the bi-directional interaction.
* Provide the JavaScript examples, ensuring they are well-commented and illustrate the corresponding C++ functionality.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just tests C++ API."
* **Correction:** "Wait, many tests involve running JavaScript code. This is about the *interaction* between the C++ API and JavaScript."
* **Initial thought:**  "Just list all the tests."
* **Refinement:** "Grouping them by functionality will make the summary much easier to understand."
* **Initial thought:**  "The JavaScript examples should just be snippets."
* **Refinement:** "More complete examples that show the setup and verification will be more helpful."

By following these steps, the detailed C++ code can be effectively analyzed, summarized, and linked to its corresponding JavaScript functionality.
这个C++源代码文件 `v8/test/cctest/test-api-array-buffer.cc` 主要是用于测试 V8 JavaScript 引擎中 `ArrayBuffer` 和 `SharedArrayBuffer` 的 C++ API。它包含了一系列的单元测试，用于验证这些 API 的各种功能和行为是否符合预期。

**功能归纳:**

该文件中的测试覆盖了 `ArrayBuffer` 和 `SharedArrayBuffer` 的以下主要功能：

1. **创建和基本属性:**
   - 测试通过 C++ API 创建 `ArrayBuffer` 和 `SharedArrayBuffer` 的不同方法，例如 `New` 和 `MaybeNew`。
   - 验证创建后的 `byteLength` 属性是否正确。
   - 检查内部字段是否初始化为零。

2. **C++ 和 JavaScript 之间的互操作:**
   - 测试从 C++ 创建的 `ArrayBuffer` 能否在 JavaScript 中正常使用和访问。
   - 测试从 JavaScript 创建的 `ArrayBuffer` 能否在 C++ 中获取其 `BackingStore` 并进行操作。
   - 验证通过 JavaScript 修改 `ArrayBuffer` 的数据，C++ 能否感知到，反之亦然。

3. **可分离性 (Detachable):**
   - 测试 `ArrayBuffer` 的可分离特性，包括禁用分离的能力。
   - 验证通过 C++ API (`Detach`) 和 JavaScript API (`transfer`) 分离 `ArrayBuffer` 后的状态。
   - 检查分离后相关的 `TypedArray` 和 `DataView` 对象的状态（例如，`byteLength` 变为 0）。
   - 测试 `WasDetached()` 方法是否能正确反映 `ArrayBuffer` 的分离状态。

4. **BackingStore (后备存储):**
   - 测试获取和管理 `ArrayBuffer` 和 `SharedArrayBuffer` 的 `BackingStore` 的 API。
   - 验证 `BackingStore` 的 `ByteLength()` 是否正确。
   - 测试 `BackingStore` 的 `Data()` 方法能否获取到正确的内存地址。
   - 测试自定义 `BackingStore` 的创建，包括自定义的析构函数。
   - 测试在垃圾回收 (GC) 期间对 `BackingStore` 的处理，确保不会因为错误的指针而崩溃。
   - 测试 `BackingStore` 的共享属性 (`IsShared()`)。
   - 测试使用 `EmptyDeleter` 的 `BackingStore`。
   - 测试 `BackingStore::Reallocate` (已弃用) 的功能。

5. **可调整大小 (Resizable):**
   - 测试创建可调整大小的 `ArrayBuffer` 和 `SharedArrayBuffer`，并通过 `maxByteLength` 设置最大长度。
   - 验证 `IsResizableByUserJavaScript()` 方法是否正确反映其状态。
   - 验证 `MaxByteLength()` 方法是否返回正确的值。

6. **空 ArrayBuffer:**
   - 测试创建 `byteLength` 为 0 的 `ArrayBuffer` 的行为，包括其 `Data()` 方法的返回值。

7. **ArrayBufferView 的内容获取:**
   - 测试 `ArrayBufferView` 的 `GetContents()` 方法，用于将视图的内容复制到 C++ 的内存中。

8. **内存管理和分配器:**
   - 测试 `ArrayBuffer::Allocator` 的生命周期管理，确保在 `Isolate` 关闭后能正确释放内存。
   - 测试使用自定义 `Allocator` 的场景。

**与 JavaScript 的关系和示例:**

该文件测试的 C++ API 直接对应于 JavaScript 中 `ArrayBuffer` 和 `SharedArrayBuffer` 对象的功能。

**JavaScript 示例:**

以下是一些与该 C++ 测试文件中的功能相关的 JavaScript 示例：

**1. 创建和基本属性:**

```javascript
// 对应 ArrayBuffer_ApiInternalToExternal, ArrayBuffer_ApiMaybeNew
const ab = new ArrayBuffer(1024);
console.log(ab.byteLength); // 输出 1024

const sab = new SharedArrayBuffer(512);
console.log(sab.byteLength); // 输出 512
```

**2. C++ 和 JavaScript 之间的互操作:**

```javascript
// 对应 ArrayBuffer_JSInternalToExternal, SharedArrayBuffer_JSInternalToExternal
const ab = new ArrayBuffer(2);
const view = new Uint8Array(ab);
view[0] = 0xAA;
view[1] = 0xFF;

// 在 C++ 代码中，可以获取 ab 的 BackingStore 并检查其内容是否为 0xAA 和 0xFF。
```

**3. 可分离性 (Detachable):**

```javascript
// 对应 ArrayBuffer_DetachingScript
const ab = new ArrayBuffer(1024);
const view = new Uint8Array(ab);
console.log(ab.byteLength); // 输出 1024

ab.transfer(); // 分离 ArrayBuffer

console.log(ab.byteLength); // 输出 0
console.log(view.byteLength); // 输出 0 (TypedArray 也被分离)

try {
  view[0] = 10; // 尝试访问已分离的 TypedArray，会抛出错误
} catch (e) {
  console.error("Error accessing detached TypedArray:", e);
}
```

**4. 可调整大小 (Resizable):**

```javascript
// 对应 ArrayBuffer_Resizable
const rab = new ArrayBuffer(32, { maxByteLength: 1024 });
console.log(rab.byteLength); // 输出 32
console.log(rab.maxByteLength); // 输出 1024

const gsab = new SharedArrayBuffer(32, { maxByteLength: 1024 });
console.log(gsab.byteLength); // 输出 32
console.log(gsab.maxByteLength); // 输出 1024
```

**总结:**

`v8/test/cctest/test-api-array-buffer.cc` 文件是 V8 引擎中用于测试 `ArrayBuffer` 和 `SharedArrayBuffer` C++ API 的重要组成部分，确保了这些核心功能在引擎内部的正确实现和与 JavaScript 的良好交互。通过这些测试，V8 开发者可以验证对 `ArrayBuffer` 和 `SharedArrayBuffer` 的修改或新功能的添加不会引入错误。

Prompt: 
```
这是目录为v8/test/cctest/test-api-array-buffer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-inl.h"
#include "src/base/logging.h"
#include "src/base/strings.h"
#include "src/common/globals.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/sandbox/sandbox.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/test-api.h"
#include "test/common/flag-utils.h"

using ::v8::Array;
using ::v8::Context;
using ::v8::Local;
using ::v8::Maybe;
using ::v8::Value;

namespace {

void CheckDataViewIsDetached(v8::Local<v8::DataView> dv) {
  CHECK_EQ(0, static_cast<int>(dv->ByteLength()));
  CHECK_EQ(0, static_cast<int>(dv->ByteOffset()));
}

void CheckIsDetached(v8::Local<v8::TypedArray> ta) {
  CHECK_EQ(0, static_cast<int>(ta->ByteLength()));
  CHECK_EQ(0, static_cast<int>(ta->Length()));
  CHECK_EQ(0, static_cast<int>(ta->ByteOffset()));
}

void CheckIsTypedArrayVarDetached(const char* name) {
  v8::base::ScopedVector<char> source(1024);
  v8::base::SNPrintF(
      source, "%s.byteLength == 0 && %s.byteOffset == 0 && %s.length == 0",
      name, name, name);
  CHECK(CompileRun(source.begin())->IsTrue());
  v8::Local<v8::TypedArray> ta = CompileRun(name).As<v8::TypedArray>();
  CheckIsDetached(ta);
}

template <typename TypedArray, int kElementSize>
Local<TypedArray> CreateAndCheck(Local<v8::ArrayBuffer> ab, int byteOffset,
                                 int length) {
  v8::Local<TypedArray> ta = TypedArray::New(ab, byteOffset, length);
  CheckInternalFieldsAreZero<v8::ArrayBufferView>(ta);
  CHECK_EQ(byteOffset, static_cast<int>(ta->ByteOffset()));
  CHECK_EQ(length, static_cast<int>(ta->Length()));
  CHECK_EQ(length * kElementSize, static_cast<int>(ta->ByteLength()));
  return ta;
}

std::shared_ptr<v8::BackingStore> Externalize(Local<v8::ArrayBuffer> ab) {
  std::shared_ptr<v8::BackingStore> backing_store = ab->GetBackingStore();
  return backing_store;
}

std::shared_ptr<v8::BackingStore> Externalize(Local<v8::SharedArrayBuffer> ab) {
  std::shared_ptr<v8::BackingStore> backing_store = ab->GetBackingStore();
  return backing_store;
}

}  // namespace

THREADED_TEST(ArrayBuffer_ApiInternalToExternal) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 1024);
  CheckInternalFieldsAreZero(ab);
  CHECK_EQ(1024, ab->ByteLength());
  i::heap::InvokeMajorGC(CcTest::heap());

  std::shared_ptr<v8::BackingStore> backing_store = Externalize(ab);
  CHECK_EQ(1024, backing_store->ByteLength());

  uint8_t* data = static_cast<uint8_t*>(backing_store->Data());
  CHECK_NOT_NULL(data);
  CHECK(env->Global()->Set(env.local(), v8_str("ab"), ab).FromJust());

  v8::Local<v8::Value> result = CompileRun("ab.byteLength");
  CHECK_EQ(1024, result->Int32Value(env.local()).FromJust());

  result = CompileRun(
      "var u8 = new Uint8Array(ab);"
      "u8[0] = 0xFF;"
      "u8[1] = 0xAA;"
      "u8.length");
  CHECK_EQ(1024, result->Int32Value(env.local()).FromJust());
  CHECK_EQ(0xFF, data[0]);
  CHECK_EQ(0xAA, data[1]);
  data[0] = 0xCC;
  data[1] = 0x11;
  result = CompileRun("u8[0] + u8[1]");
  CHECK_EQ(0xDD, result->Int32Value(env.local()).FromJust());
}

THREADED_TEST(ArrayBuffer_ApiMaybeNew) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  // Reasonable-sized ArrayBuffer.
  v8::MaybeLocal<v8::ArrayBuffer> maybe_ab =
      v8::ArrayBuffer::MaybeNew(isolate, 1024);
  CHECK(!maybe_ab.IsEmpty());
  auto ab = v8::Local<v8::ArrayBuffer>::Cast(maybe_ab.ToLocalChecked());
  CheckInternalFieldsAreZero(ab);
  CHECK_EQ(1024, ab->ByteLength());
  i::heap::InvokeMajorGC(CcTest::heap());

  std::shared_ptr<v8::BackingStore> backing_store = Externalize(ab);
  CHECK_EQ(1024, backing_store->ByteLength());

  uint8_t* data = static_cast<uint8_t*>(backing_store->Data());
  CHECK_NOT_NULL(data);
  CHECK(env->Global()->Set(env.local(), v8_str("ab"), ab).FromJust());

  v8::Local<v8::Value> result = CompileRun("ab.byteLength");
  CHECK_EQ(1024, result->Int32Value(env.local()).FromJust());

  // Too large ArrayBuffer.
  size_t unreasonable_size = 1;
#if V8_TARGET_ARCH_64_BIT
  unreasonable_size <<= 53;
#else
  unreasonable_size <<= 31;
#endif
  v8::MaybeLocal<v8::ArrayBuffer> maybe_ab_2 =
      v8::ArrayBuffer::MaybeNew(isolate, unreasonable_size);
  CHECK(maybe_ab_2.IsEmpty());
}

THREADED_TEST(ArrayBuffer_JSInternalToExternal) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> result = CompileRun(
      "var ab1 = new ArrayBuffer(2);"
      "var u8_a = new Uint8Array(ab1);"
      "u8_a[0] = 0xAA;"
      "u8_a[1] = 0xFF; u8_a.buffer");
  Local<v8::ArrayBuffer> ab1 = result.As<v8::ArrayBuffer>();
  CheckInternalFieldsAreZero(ab1);
  CHECK_EQ(2, ab1->ByteLength());
  std::shared_ptr<v8::BackingStore> backing_store = Externalize(ab1);

  result = CompileRun("ab1.byteLength");
  CHECK_EQ(2, result->Int32Value(env.local()).FromJust());
  result = CompileRun("u8_a[0]");
  CHECK_EQ(0xAA, result->Int32Value(env.local()).FromJust());
  result = CompileRun("u8_a[1]");
  CHECK_EQ(0xFF, result->Int32Value(env.local()).FromJust());
  result = CompileRun(
      "var u8_b = new Uint8Array(ab1);"
      "u8_b[0] = 0xBB;"
      "u8_a[0]");
  CHECK_EQ(0xBB, result->Int32Value(env.local()).FromJust());
  result = CompileRun("u8_b[1]");
  CHECK_EQ(0xFF, result->Int32Value(env.local()).FromJust());

  CHECK_EQ(2, backing_store->ByteLength());
  uint8_t* ab1_data = static_cast<uint8_t*>(backing_store->Data());
  CHECK_EQ(0xBB, ab1_data[0]);
  CHECK_EQ(0xFF, ab1_data[1]);
  ab1_data[0] = 0xCC;
  ab1_data[1] = 0x11;
  result = CompileRun("u8_a[0] + u8_a[1]");
  CHECK_EQ(0xDD, result->Int32Value(env.local()).FromJust());
}

THREADED_TEST(ArrayBuffer_DisableDetach) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
  CHECK(ab->IsDetachable());

  i::DirectHandle<i::JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
  buf->set_is_detachable(false);

  CHECK(!ab->IsDetachable());
}

THREADED_TEST(ArrayBuffer_DetachingApi) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::ArrayBuffer> buffer = v8::ArrayBuffer::New(isolate, 1024);

  v8::Local<v8::Uint8Array> u8a =
      CreateAndCheck<v8::Uint8Array, 1>(buffer, 1, 1023);
  v8::Local<v8::Uint8ClampedArray> u8c =
      CreateAndCheck<v8::Uint8ClampedArray, 1>(buffer, 1, 1023);
  v8::Local<v8::Int8Array> i8a =
      CreateAndCheck<v8::Int8Array, 1>(buffer, 1, 1023);

  v8::Local<v8::Uint16Array> u16a =
      CreateAndCheck<v8::Uint16Array, 2>(buffer, 2, 511);
  v8::Local<v8::Int16Array> i16a =
      CreateAndCheck<v8::Int16Array, 2>(buffer, 2, 511);

  v8::Local<v8::Uint32Array> u32a =
      CreateAndCheck<v8::Uint32Array, 4>(buffer, 4, 255);
  v8::Local<v8::Int32Array> i32a =
      CreateAndCheck<v8::Int32Array, 4>(buffer, 4, 255);

  v8::Local<v8::Float32Array> f32a =
      CreateAndCheck<v8::Float32Array, 4>(buffer, 4, 255);
  v8::Local<v8::Float64Array> f64a =
      CreateAndCheck<v8::Float64Array, 8>(buffer, 8, 127);

  v8::Local<v8::DataView> dv = v8::DataView::New(buffer, 1, 1023);
  CheckInternalFieldsAreZero<v8::ArrayBufferView>(dv);
  CHECK_EQ(1, dv->ByteOffset());
  CHECK_EQ(1023, dv->ByteLength());

  Externalize(buffer);
  buffer->Detach(v8::Local<v8::Value>()).Check();
  CHECK_EQ(0, buffer->ByteLength());
  CheckIsDetached(u8a);
  CheckIsDetached(u8c);
  CheckIsDetached(i8a);
  CheckIsDetached(u16a);
  CheckIsDetached(i16a);
  CheckIsDetached(u32a);
  CheckIsDetached(i32a);
  CheckIsDetached(f32a);
  CheckIsDetached(f64a);
  CheckDataViewIsDetached(dv);
}

THREADED_TEST(ArrayBuffer_DetachingScript) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  CompileRun(
      "var ab = new ArrayBuffer(1024);"
      "var u8a = new Uint8Array(ab, 1, 1023);"
      "var u8c = new Uint8ClampedArray(ab, 1, 1023);"
      "var i8a = new Int8Array(ab, 1, 1023);"
      "var u16a = new Uint16Array(ab, 2, 511);"
      "var i16a = new Int16Array(ab, 2, 511);"
      "var u32a = new Uint32Array(ab, 4, 255);"
      "var i32a = new Int32Array(ab, 4, 255);"
      "var f32a = new Float32Array(ab, 4, 255);"
      "var f64a = new Float64Array(ab, 8, 127);"
      "var dv = new DataView(ab, 1, 1023);");

  v8::Local<v8::ArrayBuffer> ab = CompileRun("ab").As<v8::ArrayBuffer>();
  v8::Local<v8::DataView> dv = CompileRun("dv").As<v8::DataView>();

  Externalize(ab);
  ab->Detach(v8::Local<v8::Value>()).Check();
  CHECK_EQ(0, ab->ByteLength());
  CHECK_EQ(0, v8_run_int32value(v8_compile("ab.byteLength")));

  CheckIsTypedArrayVarDetached("u8a");
  CheckIsTypedArrayVarDetached("u8c");
  CheckIsTypedArrayVarDetached("i8a");
  CheckIsTypedArrayVarDetached("u16a");
  CheckIsTypedArrayVarDetached("i16a");
  CheckIsTypedArrayVarDetached("u32a");
  CheckIsTypedArrayVarDetached("i32a");
  CheckIsTypedArrayVarDetached("f32a");
  CheckIsTypedArrayVarDetached("f64a");

  {
    v8::TryCatch try_catch(isolate);
    CompileRun("dv.byteLength == 0 ");
    CHECK(try_catch.HasCaught());
  }

  {
    v8::TryCatch try_catch(isolate);
    CompileRun("dv.byteOffset == 0");
    CHECK(try_catch.HasCaught());
  }

  CheckDataViewIsDetached(dv);
}

THREADED_TEST(ArrayBuffer_WasDetached) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 0);
  CHECK(!ab->WasDetached());

  ab->Detach(v8::Local<v8::Value>()).Check();
  CHECK(ab->WasDetached());
}

THREADED_TEST(ArrayBuffer_NonDetachableWasDetached) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  CompileRun(R"JS(
    var wasmMemory = new WebAssembly.Memory({initial: 1, maximum: 2});
  )JS");

  Local<v8::ArrayBuffer> non_detachable =
      CompileRun("wasmMemory.buffer").As<v8::ArrayBuffer>();
  CHECK(!non_detachable->IsDetachable());
  CHECK(!non_detachable->WasDetached());

  CompileRun("wasmMemory.grow(1)");
  CHECK(!non_detachable->IsDetachable());
  CHECK(non_detachable->WasDetached());
}

THREADED_TEST(ArrayBuffer_ExternalizeEmpty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 2);
  CheckInternalFieldsAreZero(ab);
  CHECK_EQ(2, ab->ByteLength());

  // Externalize the buffer (taking ownership of the backing store memory).
  std::shared_ptr<v8::BackingStore> backing_store = Externalize(ab);

  Local<v8::Uint8Array> u8a = v8::Uint8Array::New(ab, 0, 0);
  // Calling Buffer() will materialize the ArrayBuffer (transitioning it from
  // on-heap to off-heap if need be). This should not affect whether it is
  // marked as is_external or not.
  USE(u8a->Buffer());

  CHECK_EQ(2, backing_store->ByteLength());
}

THREADED_TEST(SharedArrayBuffer_ApiInternalToExternal) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::SharedArrayBuffer> ab = v8::SharedArrayBuffer::New(isolate, 1024);
  CheckInternalFieldsAreZero(ab);
  CHECK_EQ(1024, ab->ByteLength());
  i::heap::InvokeMajorGC(CcTest::heap());

  std::shared_ptr<v8::BackingStore> backing_store = Externalize(ab);

  CHECK_EQ(1024, backing_store->ByteLength());
  uint8_t* data = static_cast<uint8_t*>(backing_store->Data());
  CHECK_NOT_NULL(data);
  CHECK(env->Global()->Set(env.local(), v8_str("ab"), ab).FromJust());

  v8::Local<v8::Value> result = CompileRun("ab.byteLength");
  CHECK_EQ(1024, result->Int32Value(env.local()).FromJust());

  result = CompileRun(
      "var u8 = new Uint8Array(ab);"
      "u8[0] = 0xFF;"
      "u8[1] = 0xAA;"
      "u8.length");
  CHECK_EQ(1024, result->Int32Value(env.local()).FromJust());
  CHECK_EQ(0xFF, data[0]);
  CHECK_EQ(0xAA, data[1]);
  data[0] = 0xCC;
  data[1] = 0x11;
  result = CompileRun("u8[0] + u8[1]");
  CHECK_EQ(0xDD, result->Int32Value(env.local()).FromJust());
}

THREADED_TEST(SharedArrayBuffer_JSInternalToExternal) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> result = CompileRun(
      "var ab1 = new SharedArrayBuffer(2);"
      "var u8_a = new Uint8Array(ab1);"
      "u8_a[0] = 0xAA;"
      "u8_a[1] = 0xFF; u8_a.buffer");
  Local<v8::SharedArrayBuffer> ab1 = result.As<v8::SharedArrayBuffer>();
  CheckInternalFieldsAreZero(ab1);
  CHECK_EQ(2, ab1->ByteLength());
  CHECK(!ab1->IsExternal());
  std::shared_ptr<v8::BackingStore> backing_store = Externalize(ab1);

  result = CompileRun("ab1.byteLength");
  CHECK_EQ(2, result->Int32Value(env.local()).FromJust());
  result = CompileRun("u8_a[0]");
  CHECK_EQ(0xAA, result->Int32Value(env.local()).FromJust());
  result = CompileRun("u8_a[1]");
  CHECK_EQ(0xFF, result->Int32Value(env.local()).FromJust());
  result = CompileRun(
      "var u8_b = new Uint8Array(ab1);"
      "u8_b[0] = 0xBB;"
      "u8_a[0]");
  CHECK_EQ(0xBB, result->Int32Value(env.local()).FromJust());
  result = CompileRun("u8_b[1]");
  CHECK_EQ(0xFF, result->Int32Value(env.local()).FromJust());

  CHECK_EQ(2, backing_store->ByteLength());
  uint8_t* ab1_data = static_cast<uint8_t*>(backing_store->Data());
  CHECK_EQ(0xBB, ab1_data[0]);
  CHECK_EQ(0xFF, ab1_data[1]);
  ab1_data[0] = 0xCC;
  ab1_data[1] = 0x11;
  result = CompileRun("u8_a[0] + u8_a[1]");
  CHECK_EQ(0xDD, result->Int32Value(env.local()).FromJust());
}

THREADED_TEST(SkipArrayBufferBackingStoreDuringGC) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  void* buffer = CcTest::array_buffer_allocator()->Allocate(100);
  // Make sure the pointer looks like a heap object
  uintptr_t address = reinterpret_cast<uintptr_t>(buffer) | i::kHeapObjectTag;
  void* store_ptr = reinterpret_cast<void*>(address);
  auto backing_store = v8::ArrayBuffer::NewBackingStore(
      store_ptr, 8, [](void*, size_t, void*) {}, nullptr);

  // Create ArrayBuffer with pointer-that-cannot-be-visited in the backing store
  Local<v8::ArrayBuffer> ab =
      v8::ArrayBuffer::New(isolate, std::move(backing_store));

  // Should not crash
  i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());

  // Should not move the pointer
  CHECK_EQ(ab->GetBackingStore()->Data(), store_ptr);
  CHECK_EQ(ab->Data(), store_ptr);

  CcTest::array_buffer_allocator()->Free(buffer, 100);
}

THREADED_TEST(SkipArrayBufferDuringScavenge) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  // Make sure the pointer looks like a heap object
  Local<v8::Object> tmp = v8::Object::New(isolate);
  uint8_t* store_ptr =
      reinterpret_cast<uint8_t*>(i::ValueHelper::ValueAsAddress(*tmp));
  auto backing_store = v8::ArrayBuffer::NewBackingStore(
      store_ptr, 8, [](void*, size_t, void*) {}, nullptr);

  i::heap::InvokeMinorGC(CcTest::heap());

  // Create ArrayBuffer with pointer-that-cannot-be-visited in the backing store
  Local<v8::ArrayBuffer> ab =
      v8::ArrayBuffer::New(isolate, std::move(backing_store));

  // Should not crash,
  // i.e. backing store pointer should not be treated as a heap object pointer
  i::heap::EmptyNewSpaceUsingGC(CcTest::heap());

  CHECK_EQ(ab->GetBackingStore()->Data(), store_ptr);
  CHECK_EQ(ab->Data(), store_ptr);
}

THREADED_TEST(Regress1006600) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::Value> ab = CompileRunChecked(isolate, "new ArrayBuffer()");
  for (int i = 0; i < v8::ArrayBuffer::kEmbedderFieldCount; i++) {
    CHECK_NULL(ab.As<v8::Object>()->GetAlignedPointerFromInternalField(i));
  }
}

THREADED_TEST(ArrayBuffer_NewBackingStore) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  std::shared_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewBackingStore(isolate, 100);
  CHECK(!backing_store->IsShared());
  CHECK(!backing_store->IsResizableByUserJavaScript());
  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, backing_store);
  CHECK_EQ(backing_store.get(), ab->GetBackingStore().get());
  CHECK_EQ(backing_store->Data(), ab->Data());
}

THREADED_TEST(ArrayBuffer_NewResizableBackingStore) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  std::shared_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewResizableBackingStore(32, 1024);
  CHECK(!backing_store->IsShared());
  CHECK(backing_store->IsResizableByUserJavaScript());
  CHECK_EQ(1024, backing_store->MaxByteLength());
  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, backing_store);
  CHECK_EQ(backing_store.get(), ab->GetBackingStore().get());
  CHECK_EQ(backing_store->Data(), ab->Data());
  CHECK_EQ(backing_store->MaxByteLength(), ab->MaxByteLength());
}

THREADED_TEST(SharedArrayBuffer_NewBackingStore) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  std::shared_ptr<v8::BackingStore> backing_store =
      v8::SharedArrayBuffer::NewBackingStore(isolate, 100);
  CHECK(backing_store->IsShared());
  CHECK(!backing_store->IsResizableByUserJavaScript());
  Local<v8::SharedArrayBuffer> ab =
      v8::SharedArrayBuffer::New(isolate, backing_store);
  CHECK_EQ(backing_store.get(), ab->GetBackingStore().get());
  CHECK_EQ(backing_store->Data(), ab->Data());
}

static void* backing_store_custom_data = nullptr;
static size_t backing_store_custom_length = 0;
static bool backing_store_custom_called = false;
const intptr_t backing_store_custom_deleter_data = 1234567;

static void BackingStoreCustomDeleter(void* data, size_t length,
                                      void* deleter_data) {
  CHECK(!backing_store_custom_called);
  CHECK_EQ(backing_store_custom_data, data);
  CHECK_EQ(backing_store_custom_length, length);
  CHECK_EQ(backing_store_custom_deleter_data,
           reinterpret_cast<intptr_t>(deleter_data));
  CcTest::array_buffer_allocator()->Free(data, length);
  backing_store_custom_called = true;
}

TEST(ArrayBuffer_NewBackingStore_CustomDeleter) {
  {
    // Create and destroy a backing store.
    backing_store_custom_called = false;
    backing_store_custom_data = CcTest::array_buffer_allocator()->Allocate(100);
    backing_store_custom_length = 100;
    v8::ArrayBuffer::NewBackingStore(
        backing_store_custom_data, backing_store_custom_length,
        BackingStoreCustomDeleter,
        reinterpret_cast<void*>(backing_store_custom_deleter_data));
  }
  CHECK(backing_store_custom_called);
}

TEST(SharedArrayBuffer_NewBackingStore_CustomDeleter) {
  {
    // Create and destroy a backing store.
    backing_store_custom_called = false;
    backing_store_custom_data = CcTest::array_buffer_allocator()->Allocate(100);
    backing_store_custom_length = 100;
    v8::SharedArrayBuffer::NewBackingStore(
        backing_store_custom_data, backing_store_custom_length,
        BackingStoreCustomDeleter,
        reinterpret_cast<void*>(backing_store_custom_deleter_data));
  }
  CHECK(backing_store_custom_called);
}

TEST(ArrayBuffer_NewBackingStore_EmptyDeleter) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  size_t size = 100;
  void* buffer = CcTest::array_buffer_allocator()->Allocate(size);
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewBackingStore(buffer, size,
                                       v8::BackingStore::EmptyDeleter, nullptr);
  uint64_t external_memory_before =
      isolate->AdjustAmountOfExternalAllocatedMemory(0);
  v8::ArrayBuffer::New(isolate, std::move(backing_store));
  uint64_t external_memory_after =
      isolate->AdjustAmountOfExternalAllocatedMemory(0);
  // The ArrayBuffer constructor does not increase the external memory counter.
  // The counter may decrease however if the allocation triggers GC.
  CHECK_GE(external_memory_before, external_memory_after);
  CcTest::array_buffer_allocator()->Free(buffer, size);
}

TEST(SharedArrayBuffer_NewBackingStore_EmptyDeleter) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  size_t size = 100;
  void* buffer = CcTest::array_buffer_allocator()->Allocate(size);
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::SharedArrayBuffer::NewBackingStore(
          buffer, size, v8::BackingStore::EmptyDeleter, nullptr);
  uint64_t external_memory_before =
      isolate->AdjustAmountOfExternalAllocatedMemory(0);
  v8::SharedArrayBuffer::New(isolate, std::move(backing_store));
  uint64_t external_memory_after =
      isolate->AdjustAmountOfExternalAllocatedMemory(0);
  // The SharedArrayBuffer constructor does not increase the external memory
  // counter. The counter may decrease however if the allocation triggers GC.
  CHECK_GE(external_memory_before, external_memory_after);
  CcTest::array_buffer_allocator()->Free(buffer, size);
}

THREADED_TEST(BackingStore_NotShared) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 8);
  CHECK(!ab->GetBackingStore()->IsShared());
  CHECK(!v8::ArrayBuffer::NewBackingStore(isolate, 8)->IsShared());
  backing_store_custom_called = false;
  backing_store_custom_data = CcTest::array_buffer_allocator()->Allocate(100);
  backing_store_custom_length = 100;
  CHECK(!v8::ArrayBuffer::NewBackingStore(
             backing_store_custom_data, backing_store_custom_length,
             BackingStoreCustomDeleter,
             reinterpret_cast<void*>(backing_store_custom_deleter_data))
             ->IsShared());
}

THREADED_TEST(BackingStore_Shared) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  Local<v8::SharedArrayBuffer> ab = v8::SharedArrayBuffer::New(isolate, 8);
  CHECK(ab->GetBackingStore()->IsShared());
  CHECK(v8::SharedArrayBuffer::NewBackingStore(isolate, 8)->IsShared());
  backing_store_custom_called = false;
  backing_store_custom_data = CcTest::array_buffer_allocator()->Allocate(100);
  backing_store_custom_length = 100;
  CHECK(v8::SharedArrayBuffer::NewBackingStore(
            backing_store_custom_data, backing_store_custom_length,
            BackingStoreCustomDeleter,
            reinterpret_cast<void*>(backing_store_custom_deleter_data))
            ->IsShared());
}

THREADED_TEST(ArrayBuffer_NewBackingStore_NullData) {
  // This test creates a BackingStore with nullptr as data. The test then
  // creates an ArrayBuffer and a TypedArray from this BackingStore. Writing
  // into that TypedArray at index 0 is expected to be a no-op, reading from
  // that TypedArray at index 0 should result in the default value '0'.
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewBackingStore(nullptr, 0,
                                       v8::BackingStore::EmptyDeleter, nullptr);
  v8::Local<v8::ArrayBuffer> buffer =
      v8::ArrayBuffer::New(isolate, std::move(backing_store));

  CHECK(env->Global()->Set(env.local(), v8_str("buffer"), buffer).FromJust());

  v8::Local<v8::Value> result =
      CompileRunChecked(isolate,
                        "const view = new Int32Array(buffer);"
                        "view[0] = 14;"
                        "view[0];");
  CHECK_EQ(0, result->Int32Value(env.local()).FromJust());
}

class DummyAllocator final : public v8::ArrayBuffer::Allocator {
 public:
  DummyAllocator() : allocator_(NewDefaultAllocator()) {}

  ~DummyAllocator() override { CHECK_EQ(allocation_count(), 0); }

  void* Allocate(size_t length) override {
    allocation_count_++;
    return allocator_->Allocate(length);
  }
  void* AllocateUninitialized(size_t length) override {
    allocation_count_++;
    return allocator_->AllocateUninitialized(length);
  }
  void Free(void* data, size_t length) override {
    allocation_count_--;
    allocator_->Free(data, length);
  }

  uint64_t allocation_count() const { return allocation_count_; }

 private:
  std::unique_ptr<v8::ArrayBuffer::Allocator> allocator_;
  uint64_t allocation_count_ = 0;
};

TEST(BackingStore_HoldAllocatorAlive_UntilIsolateShutdown) {
  std::shared_ptr<DummyAllocator> allocator =
      std::make_shared<DummyAllocator>();
  std::weak_ptr<DummyAllocator> allocator_weak(allocator);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator_shared = allocator;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();

  allocator.reset();
  create_params.array_buffer_allocator_shared.reset();
  CHECK(!allocator_weak.expired());
  CHECK_EQ(allocator_weak.lock()->allocation_count(), 0);

  {
    // Create an ArrayBuffer and do not garbage collect it. This should make
    // the allocator be released automatically once the Isolate is disposed.
    v8::HandleScope handle_scope(isolate);
    v8::Context::Scope context_scope(Context::New(isolate));
    v8::ArrayBuffer::New(isolate, 8);

    // This should be inside the HandleScope, so that we can be sure that
    // the allocation is not garbage collected yet.
    CHECK(!allocator_weak.expired());
    CHECK_EQ(allocator_weak.lock()->allocation_count(), 1);
  }

  isolate->Exit();
  isolate->Dispose();
  CHECK(allocator_weak.expired());
}

TEST(BackingStore_HoldAllocatorAlive_AfterIsolateShutdown) {
  std::shared_ptr<DummyAllocator> allocator =
      std::make_shared<DummyAllocator>();
  std::weak_ptr<DummyAllocator> allocator_weak(allocator);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator_shared = allocator;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();

  allocator.reset();
  create_params.array_buffer_allocator_shared.reset();
  CHECK(!allocator_weak.expired());
  CHECK_EQ(allocator_weak.lock()->allocation_count(), 0);

  std::shared_ptr<v8::BackingStore> backing_store;
  {
    // Create an ArrayBuffer and do not garbage collect it. This should make
    // the allocator be released automatically once the Isolate is disposed.
    v8::HandleScope handle_scope(isolate);
    v8::Context::Scope context_scope(Context::New(isolate));
    v8::Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 8);
    backing_store = ab->GetBackingStore();
  }

  isolate->Exit();
  isolate->Dispose();
  CHECK(!allocator_weak.expired());
  CHECK_EQ(allocator_weak.lock()->allocation_count(), 1);
  backing_store.reset();
  CHECK(allocator_weak.expired());
}

class NullptrAllocator final : public v8::ArrayBuffer::Allocator {
 public:
  void* Allocate(size_t length) override {
    CHECK_EQ(length, 0);
    return nullptr;
  }
  void* AllocateUninitialized(size_t length) override {
    CHECK_EQ(length, 0);
    return nullptr;
  }
  void Free(void* data, size_t length) override { CHECK_EQ(data, nullptr); }
};

TEST(BackingStore_ReleaseAllocator_NullptrBackingStore) {
  std::shared_ptr<NullptrAllocator> allocator =
      std::make_shared<NullptrAllocator>();
  std::weak_ptr<NullptrAllocator> allocator_weak(allocator);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator_shared = allocator;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();

  allocator.reset();
  create_params.array_buffer_allocator_shared.reset();
  CHECK(!allocator_weak.expired());

  {
    std::shared_ptr<v8::BackingStore> backing_store =
        v8::ArrayBuffer::NewBackingStore(isolate, 0);
    // This should release a reference to the allocator, even though the
    // buffer is empty/nullptr.
    backing_store.reset();
  }

  isolate->Exit();
  isolate->Dispose();
  CHECK(allocator_weak.expired());
}

START_ALLOW_USE_DEPRECATED()

TEST(BackingStore_ReallocateExpand) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewBackingStore(isolate, 10);
  {
    uint8_t* data = reinterpret_cast<uint8_t*>(
        reinterpret_cast<uintptr_t>(backing_store->Data()));
    for (uint8_t i = 0; i < 10; i++) {
      data[i] = i;
    }
  }
  std::unique_ptr<v8::BackingStore> new_backing_store =
      v8::BackingStore::Reallocate(isolate, std::move(backing_store), 20);
  CHECK_EQ(new_backing_store->ByteLength(), 20);
  CHECK(!new_backing_store->IsShared());
  {
    uint8_t* data = reinterpret_cast<uint8_t*>(
        reinterpret_cast<uintptr_t>(new_backing_store->Data()));
    for (uint8_t i = 0; i < 10; i++) {
      CHECK_EQ(data[i], i);
    }
    for (uint8_t i = 10; i < 20; i++) {
      CHECK_EQ(data[i], 0);
    }
  }
}

TEST(BackingStore_ReallocateShrink) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewBackingStore(isolate, 20);
  {
    uint8_t* data = reinterpret_cast<uint8_t*>(backing_store->Data());
    for (uint8_t i = 0; i < 20; i++) {
      data[i] = i;
    }
  }
  std::unique_ptr<v8::BackingStore> new_backing_store =
      v8::BackingStore::Reallocate(isolate, std::move(backing_store), 10);
  CHECK_EQ(new_backing_store->ByteLength(), 10);
  CHECK(!new_backing_store->IsShared());
  {
    uint8_t* data = reinterpret_cast<uint8_t*>(new_backing_store->Data());
    for (uint8_t i = 0; i < 10; i++) {
      CHECK_EQ(data[i], i);
    }
  }
}

TEST(BackingStore_ReallocateNotShared) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewBackingStore(isolate, 20);
  std::unique_ptr<v8::BackingStore> new_backing_store =
      v8::BackingStore::Reallocate(isolate, std::move(backing_store), 10);
  CHECK(!new_backing_store->IsShared());
}

TEST(BackingStore_ReallocateShared) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::SharedArrayBuffer::NewBackingStore(isolate, 20);
  std::unique_ptr<v8::BackingStore> new_backing_store =
      v8::BackingStore::Reallocate(isolate, std::move(backing_store), 10);
  CHECK(new_backing_store->IsShared());
}

END_ALLOW_USE_DEPRECATED()

TEST(ArrayBuffer_Resizable) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  const char rab_source[] = "new ArrayBuffer(32, { maxByteLength: 1024 });";
  v8::Local<v8::ArrayBuffer> rab = CompileRun(rab_source).As<v8::ArrayBuffer>();
  CHECK(rab->GetBackingStore()->IsResizableByUserJavaScript());
  CHECK_EQ(32, rab->ByteLength());
  CHECK_EQ(1024, rab->MaxByteLength());

  const char gsab_source[] =
      "new SharedArrayBuffer(32, { maxByteLength: 1024 });";
  v8::Local<v8::SharedArrayBuffer> gsab =
      CompileRun(gsab_source).As<v8::SharedArrayBuffer>();
  CHECK(gsab->GetBackingStore()->IsResizableByUserJavaScript());
  CHECK_EQ(32, gsab->ByteLength());
  CHECK_EQ(1024, gsab->MaxByteLength());
  CHECK_EQ(gsab->MaxByteLength(), gsab->GetBackingStore()->MaxByteLength());
}

TEST(ArrayBuffer_FixedLength) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  // Fixed-length ArrayBuffers' byte length are equal to their max byte length.
  v8::Local<v8::ArrayBuffer> ab =
      CompileRun("new ArrayBuffer(32);").As<v8::ArrayBuffer>();
  CHECK(!ab->GetBackingStore()->IsResizableByUserJavaScript());
  CHECK_EQ(32, ab->ByteLength());
  CHECK_EQ(32, ab->MaxByteLength());
  CHECK_EQ(ab->MaxByteLength(), ab->GetBackingStore()->MaxByteLength());
  v8::Local<v8::SharedArrayBuffer> sab =
      CompileRun("new SharedArrayBuffer(32);").As<v8::SharedArrayBuffer>();
  CHECK(!sab->GetBackingStore()->IsResizableByUserJavaScript());
  CHECK_EQ(32, sab->ByteLength());
  CHECK_EQ(32, sab->MaxByteLength());
  CHECK_EQ(sab->MaxByteLength(), sab->GetBackingStore()->MaxByteLength());
}

THREADED_TEST(ArrayBuffer_DataApiWithEmptyExternal) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 0);
  void* expected_data_ptr = V8_ENABLE_SANDBOX_BOOL
                                ? v8::internal::EmptyBackingStoreBuffer()
                                : nullptr;
  CHECK_EQ(expected_data_ptr, ab->Data());
  CHECK_EQ(0, ab->ByteLength());
  CHECK_NULL(ab->GetBackingStore()->Data());
  // Repeat test to make sure that accessing the backing store buffer hasn't
  // changed what sandboxed AB's Data method returns.
  CHECK_EQ(expected_data_ptr, ab->Data());
  CHECK_EQ(0, ab->ByteLength());

  void* buffer = CcTest::array_buffer_allocator()->Allocate(1);
  std::unique_ptr<v8::BackingStore> backing_store =
      v8::ArrayBuffer::NewBackingStore(buffer, 0,
                                       v8::BackingStore::EmptyDeleter, nullptr);
  Local<v8::ArrayBuffer> ab2 =
      v8::ArrayBuffer::New(isolate, std::move(backing_store));
  CHECK_EQ(buffer, ab2->Data());
  CHECK_EQ(0, ab->ByteLength());
}

namespace {
void TestArrayBufferViewGetContent(const char* source, void* expected) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  auto view = v8::Local<v8::ArrayBufferView>::Cast(CompileRun(source));
  uint8_t buffer[i::JSTypedArray::kMaxSizeInHeap];
  v8::MemorySpan<uint8_t> storage(buffer);
  storage = view->GetContents(storage);
  CHECK_EQ(view->ByteLength(), storage.size());
  if (expected) {
    CHECK_EQ(0, memcmp(storage.data(), expected, view->ByteLength()));
  } else {
    CHECK_EQ(0, storage.size());
  }
}
}  // namespace

TEST(ArrayBufferView_GetContentsSmallUint8) {
  const char* source = "new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])";
  uint8_t expected[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsLargeUint8) {
  const char* source =
      "let array = new Uint8Array(100);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "array";
  uint8_t expected[100];
  for (uint8_t i = 0; i < 100; ++i) {
    expected[i] = i;
  }
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsUint8View) {
  const char* source =
      "let array = new Uint8Array(100);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "new Uint8Array(array.buffer, 70, 9)";
  uint8_t expected[]{70, 71, 72, 73, 74, 75, 76, 77, 78, 79};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsSmallUint32) {
  const char* source = "new Uint16Array([1, 2, 3, 4, 5, 6, 7, 8, 9])";
  uint16_t expected[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsLargeUint16) {
  const char* source =
      "let array = new Uint16Array(100);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "array";
  uint16_t expected[100];
  for (uint16_t i = 0; i < 100; ++i) {
    expected[i] = i;
  }
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsUint16View) {
  const char* source =
      "let array = new Uint16Array(100);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "new Uint16Array(array.buffer, 140, 9)";
  uint16_t expected[]{70, 71, 72, 73, 74, 75, 76, 77, 78, 79};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsSmallDataView) {
  const char* source =
      "let array = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);"
      "new DataView(array.buffer)";
  uint8_t expected[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsLargeDataView) {
  const char* source =
      "let array = new Uint8Array(100);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "new DataView(array.buffer)";
  uint8_t expected[100];
  for (uint8_t i = 0; i < 100; ++i) {
    expected[i] = i;
  }
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsDataViewWithOffset) {
  const char* source =
      "let array = new Uint8Array(100);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "new DataView(array.buffer, 70, 9)";
  uint8_t expected[]{70, 71, 72, 73, 74, 75, 76, 77, 78, 79};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsSmallResizableDataView) {
  const char* source =
      "let rsab = new ArrayBuffer(10, {maxByteLength: 20});"
      "let array = new Uint8Array(rsab);"
      "for (let i = 0; i < 10; ++i) {"
      "  array[i] = i;"
      "}"
      "new DataView(rsab)";
  uint8_t expected[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsResizableTypedArray) {
  const char* source =
      "let rsab = new ArrayBuffer(8, {maxByteLength: 8});"
      "let array = new Uint8Array(rsab);"
      "for (let i = 0; i < 8; ++i) {"
      "  array[i] = i;"
      "};"
      "array";
  uint8_t expected[]{0, 1, 2, 3, 4, 5, 6, 7};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsLargeResizableDataView) {
  const char* source =
      "let rsab = new ArrayBuffer(100, {maxByteLength: 200});"
      "let array = new Uint8Array(rsab);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "new DataView(rsab)";
  uint8_t expected[100];
  for (uint8_t i = 0; i < 100; ++i) {
    expected[i] = i;
  }
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsResizableDataViewWithOffset) {
  const char* source =
      "let rsab = new ArrayBuffer(100, {maxByteLength: 200});"
      "let array = new Uint8Array(rsab);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "new DataView(rsab, 70, 9)";
  uint8_t expected[]{70, 71, 72, 73, 74, 75, 76, 77, 78, 79};
  TestArrayBufferViewGetContent(source, expected);
}

TEST(ArrayBufferView_GetContentsDetached) {
  const char* source =
      "let array = new Uint8Array(100);"
      "for (let i = 0; i < 100; ++i) {"
      "  array[i] = i;"
      "}"
      "const data_view = new DataView(array.buffer);"
      "let buffer = array.buffer.transfer();"
      "data_view";
  TestArrayBufferViewGetContent(source, nullptr);
}

"""

```