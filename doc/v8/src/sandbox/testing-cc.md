Response:
The user wants to understand the functionality of the provided C++ code snippet `v8/src/sandbox/testing.cc`. The request also has several constraints:

1. **List Functionality:** I need to summarize what the code does.
2. **Torque Check:**  The code ends with `.cc`, not `.tq`, so it's C++, not Torque.
3. **JavaScript Relation:**  I should identify any connection to JavaScript and provide JavaScript examples.
4. **Code Logic Inference:**  If there's logic that can be analyzed, I need to give example inputs and outputs.
5. **Common Programming Errors:**  I need to point out potential mistakes developers might make when using this code.
6. **Part 1 Summary:** This is the first part of the request, so I should provide a summary specifically for this part.

**Plan:**

1. **High-Level Overview:**  Read through the code to get a general understanding of its purpose. It seems to be related to testing the V8 sandbox.
2. **Key Features:** Identify the major functionalities, such as installing the memory corruption API and the crash filter.
3. **Memory Corruption API:**  Analyze the JavaScript functions exposed by this API (e.g., `Sandbox.base`, `Sandbox.MemoryView`, `Sandbox.getAddressOf`). Provide JavaScript examples demonstrating their use.
4. **Crash Filter:** Understand the purpose of the crash filter and how it handles signals.
5. **Code Logic Examples:** For functions like `Sandbox.isValidObjectAt`, try to create simple scenarios with example inputs and expected outputs.
6. **Common Errors:** Think about what mistakes developers might make when using the provided API, such as providing invalid addresses or sizes.
7. **JavaScript Relation:** Clearly link the C++ functions to their JavaScript counterparts.
8. **Part 1 Summary:**  Concisely summarize the functionalities covered in this part of the code.
```
v8/src/sandbox/testing.cc 的功能：

该 C++ 代码文件 `v8/src/sandbox/testing.cc` 的主要功能是为 V8 JavaScript 引擎的沙箱环境提供测试支持。它包含以下几个关键方面的功能：

1. **内存破坏 API (Memory Corruption API):**  在启用了 `V8_ENABLE_MEMORY_CORRUPTION_API` 宏的情况下，它会向 JavaScript 环境注入一个全局对象 `Sandbox`，该对象提供了一系列方法，允许 JavaScript 代码检查和操作沙箱内的内存。这些方法包括：
    * `Sandbox.base`: 获取沙箱的基地址。
    * `Sandbox.byteLength`: 获取沙箱的大小（字节数）。
    * `Sandbox.MemoryView`: 创建一个可以访问沙箱内存特定区域的 `ArrayBuffer` 视图。
    * `Sandbox.getAddressOf(object)`: 获取 JavaScript 对象在沙箱内的地址。
    * `Sandbox.getObjectAt(address)`: 获取沙箱内指定地址处的 JavaScript 对象。
    * `Sandbox.isValidObjectAt(address)`: 检查沙箱内指定地址是否指向一个看起来有效的 JavaScript 对象。
    * `Sandbox.isWritable(object)`: 检查包含给定 JavaScript 对象的内存块是否可写。
    * `Sandbox.isWritableObjectAt(address)`: 检查沙箱内指定地址处的内存块是否可写。
    * `Sandbox.getSizeOf(object)`: 获取给定 JavaScript 对象的大小。
    * `Sandbox.getSizeOfObjectAt(address)`: 获取沙箱内指定地址处的 JavaScript 对象的大小。
    * `Sandbox.getInstanceTypeOf(object)`: 获取给定 JavaScript 对象的类型名称（字符串）。
    * `Sandbox.getInstanceTypeOfObjectAt(address)`: 获取沙箱内指定地址处的 JavaScript 对象的类型名称（字符串）。
    * `Sandbox.getInstanceTypeIdOf(object)`: 获取给定 JavaScript 对象的类型 ID（数字）。
    * `Sandbox.getInstanceTypeIdOfObjectAt(address)`: 获取沙箱内指定地址处的 JavaScript 对象的类型 ID（数字）。
    * `Sandbox.getInstanceTypeIdFor(typeName)`: 根据类型名称获取类型 ID。
    * `Sandbox.getFieldOffset(typeId, fieldName)`: 获取特定类型对象的特定字段的偏移量。

2. **崩溃过滤器 (Crash Filter):** 在 Linux 系统上，当启用了沙箱测试模式时，该代码会安装一个信号处理程序，用于捕获导致程序崩溃的信号（例如 `SIGABRT`, `SIGTRAP`, `SIGBUS`, `SIGSEGV`）。这个过滤器会检查崩溃是否发生在沙箱的内存空间内。如果崩溃发生在沙箱内部，则认为这是一个预期的、无害的崩溃（可能是因为沙箱的安全机制阻止了非法访问），程序会以一种受控的方式退出。如果崩溃发生在沙箱外部，则认为是真正的沙箱逃逸或错误，会将信号传递给原始的处理程序，导致程序以通常的方式崩溃。这有助于区分由沙箱保护引起的崩溃和真正的安全漏洞。

**关于源代码类型：**

`v8/src/sandbox/testing.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 源代码文件以 `.tq` 结尾）。

**与 JavaScript 功能的关系及示例：**

`v8/src/sandbox/testing.cc` 中定义的内存破坏 API 直接与 JavaScript 功能相关。它在 JavaScript 全局对象上注入了一个名为 `Sandbox` 的对象，使得 JavaScript 代码能够调用 C++ 中定义的功能来检查和操作内存。

**JavaScript 示例：**

```javascript
// 假设在 V8 环境中启用了内存破坏 API

// 获取沙箱的基地址和大小
const baseAddress = Sandbox.base;
const sandboxSize = Sandbox.byteLength;
console.log(`Sandbox base address: ${baseAddress}`);
console.log(`Sandbox size: ${sandboxSize}`);

// 创建一个可以读取沙箱内存的视图
const memoryView = new Sandbox.MemoryView(0, 1024);
const firstByte = memoryView[0];
console.log(`First byte in sandbox: ${firstByte}`);

// 获取一个 JavaScript 对象的地址
const obj = { value: 42 };
const objectAddress = Sandbox.getAddressOf(obj);
console.log(`Address of obj: ${objectAddress}`);

// 根据地址获取对象
const retrievedObj = Sandbox.getObjectAt(objectAddress);
console.log(`Object at address ${objectAddress}:`, retrievedObj);

// 检查一个地址是否包含一个有效的对象
const isValid = Sandbox.isValidObjectAt(objectAddress);
console.log(`Is there a valid object at ${objectAddress}: ${isValid}`);

// 获取对象的类型名称和 ID
const typeName = Sandbox.getInstanceTypeOf(obj);
const typeId = Sandbox.getInstanceTypeIdOf(obj);
console.log(`Type name of obj: ${typeName}`);
console.log(`Type ID of obj: ${typeId}`);

// 获取已知类型的 ID
const objectTypeId = Sandbox.getInstanceTypeIdFor("JS_OBJECT_TYPE");
console.log(`Type ID for JS_OBJECT_TYPE: ${objectTypeId}`);

// 获取对象字段的偏移量 (假设 JS_OBJECT_TYPE 有一个名为 "properties" 的字段)
const propertiesOffset = Sandbox.getFieldOffset(objectTypeId, "properties");
console.log(`Offset of 'properties' in JS_OBJECT_TYPE: ${propertiesOffset}`);
```

**代码逻辑推理及假设输入与输出：**

以 `Sandbox.isValidObjectAt(address)` 为例进行代码逻辑推理。该函数会尝试从给定地址读取 Map 指针，并沿着 Map 链最多追踪三次，以检查是否最终找到一个 MetaMap（其 Map 指针指向自身）。

**假设输入与输出：**

* **假设输入 1:** `address` 指向沙箱内一个有效的、未损坏的 JavaScript 对象的起始位置。
    * **预期输出:** `true` (因为可以成功追踪 Map 链并找到 MetaMap)。
* **假设输入 2:** `address` 指向沙箱内一个已损坏的内存区域，该区域看起来不像有效的 JavaScript 对象。
    * **预期输出:** `false` (因为无法正确读取 Map 指针或无法追踪到 MetaMap)。
* **假设输入 3:** `address` 指向沙箱外的内存地址。
    * **预期输出:**  可能会导致程序崩溃（如果未启用崩溃过滤器）或者被崩溃过滤器捕获并判断为沙箱违规。在启用了崩溃过滤器的情况下，如果崩溃发生在沙箱外部，过滤器会放行，由默认的信号处理程序处理。
* **假设输入 4:** `address` 指向沙箱内，但不是一个 JavaScript 对象的起始位置，例如，指向对象的中间某个字段。
    * **预期输出:** `false` (因为该地址的数据很可能无法解释为有效的 Map 指针)。

**涉及用户常见的编程错误：**

1. **传递无效的地址给 `Sandbox.getObjectAt` 或其他 `*ObjectAt` 方法:** 用户可能会传递一个不在沙箱内存范围内的地址，或者一个不指向有效 JavaScript 对象起始位置的地址。这会导致 `Sandbox.getObjectAt` 尝试访问无效内存，可能导致崩溃（在没有崩溃过滤器的情况下）或返回未定义的行为。

    ```javascript
    // 错误示例：传递一个随机的数字作为地址
    const invalidAddress = 12345;
    const objAtInvalidAddress = Sandbox.getObjectAt(invalidAddress);
    // 这可能会导致错误或未定义的行为。
    ```

2. **传递超出沙箱范围的偏移量和大小给 `Sandbox.MemoryView`:** 用户可能尝试创建一个访问沙箱边界之外的 `MemoryView`。

    ```javascript
    // 错误示例：尝试创建一个超出沙箱大小的 MemoryView
    const largeView = new Sandbox.MemoryView(Sandbox.byteLength - 100, 200);
    // 这会导致错误，因为视图超出了沙箱的边界。
    ```

3. **错误地使用 `Sandbox.getAddressOf` 的返回值:**  用户可能会错误地认为 `Sandbox.getAddressOf` 返回的地址是绝对地址，并在没有考虑沙箱基地址的情况下使用它。然而，在某些上下文中，这个地址可能是相对于沙箱基地址的偏移量。

4. **假设所有返回的对象都是有效的:** `Sandbox.getObjectAt` 可能会返回看似有效的 JavaScript 对象，即使给定的地址指向的是被破坏的内存。用户需要小心验证返回的对象。

**第 1 部分功能归纳：**

`v8/src/sandbox/testing.cc` 的第 1 部分主要负责在 V8 引擎中集成用于测试沙箱安全性的基础设施。这主要通过以下两个方面实现：

1. **暴露内存检查和操作 API 到 JavaScript:**  通过 `Sandbox` 全局对象，允许 JavaScript 代码对沙箱内存进行细粒度的检查和操作，这对于编写测试用例来验证沙箱的隔离性和安全性至关重要。
2. **实现用于检测沙箱逃逸的崩溃过滤器 (在 Linux 上):**  通过监控程序崩溃信号，判断崩溃是否发生在沙箱内部，从而区分良性的沙箱内部错误和潜在的沙箱逃逸漏洞。

总而言之，该代码为 V8 引擎提供了一套强大的工具，用于测试和验证其沙箱环境的安全性。

Prompt: 
```
这是目录为v8/src/sandbox/testing.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/sandbox/testing.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/sandbox/testing.h"

#include "src/api/api-inl.h"
#include "src/api/api-natives.h"
#include "src/common/globals.h"
#include "src/execution/isolate-inl.h"
#include "src/heap/factory.h"
#include "src/objects/backing-store.h"
#include "src/objects/js-objects.h"
#include "src/objects/templates.h"
#include "src/sandbox/sandbox.h"

#ifdef V8_OS_LINUX
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#endif  // V8_OS_LINUX

#ifdef V8_USE_ADDRESS_SANITIZER
#include <sanitizer/asan_interface.h>
#endif  // V8_USE_ADDRESS_SANITIZER

namespace v8 {
namespace internal {

#ifdef V8_ENABLE_SANDBOX

SandboxTesting::Mode SandboxTesting::mode_ = SandboxTesting::Mode::kDisabled;

#ifdef V8_ENABLE_MEMORY_CORRUPTION_API

namespace {

// Sandbox.base
void SandboxGetBase(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  double sandbox_base = GetProcessWideSandbox()->base();
  info.GetReturnValue().Set(v8::Number::New(isolate, sandbox_base));
}
// Sandbox.byteLength
void SandboxGetByteLength(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  double sandbox_size = GetProcessWideSandbox()->size();
  info.GetReturnValue().Set(v8::Number::New(isolate, sandbox_size));
}

// new Sandbox.MemoryView(info) -> Sandbox.MemoryView
void SandboxMemoryView(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  Local<v8::Context> context = isolate->GetCurrentContext();

  if (!info.IsConstructCall()) {
    isolate->ThrowError("Sandbox.MemoryView must be invoked with 'new'");
    return;
  }

  Local<v8::Integer> arg1, arg2;
  if (!info[0]->ToInteger(context).ToLocal(&arg1) ||
      !info[1]->ToInteger(context).ToLocal(&arg2)) {
    isolate->ThrowError("Expects two number arguments (start offset and size)");
    return;
  }

  Sandbox* sandbox = GetProcessWideSandbox();
  CHECK_LE(sandbox->size(), kMaxSafeIntegerUint64);

  uint64_t offset = arg1->Value();
  uint64_t size = arg2->Value();
  if (offset > sandbox->size() || size > sandbox->size() ||
      (offset + size) > sandbox->size()) {
    isolate->ThrowError(
        "The MemoryView must be entirely contained within the sandbox");
    return;
  }

  Factory* factory = reinterpret_cast<Isolate*>(isolate)->factory();
  std::unique_ptr<BackingStore> memory = BackingStore::WrapAllocation(
      reinterpret_cast<void*>(sandbox->base() + offset), size,
      v8::BackingStore::EmptyDeleter, nullptr, SharedFlag::kNotShared);
  if (!memory) {
    isolate->ThrowError("Out of memory: MemoryView backing store");
    return;
  }
  Handle<JSArrayBuffer> buffer = factory->NewJSArrayBuffer(std::move(memory));
  info.GetReturnValue().Set(Utils::ToLocal(buffer));
}

// The methods below either take a HeapObject or the address of a HeapObject as
// argument. These helper functions can be used to extract the argument object
// in both cases.
using ArgumentObjectExtractorFunction = std::function<bool(
    const v8::FunctionCallbackInfo<v8::Value>&, Tagged<HeapObject>* out)>;

static bool GetArgumentObjectPassedAsReference(
    const v8::FunctionCallbackInfo<v8::Value>& info, Tagged<HeapObject>* out) {
  v8::Isolate* isolate = info.GetIsolate();

  if (info.Length() == 0) {
    isolate->ThrowError("First argument must be provided");
    return false;
  }

  Handle<Object> arg = Utils::OpenHandle(*info[0]);
  if (!IsHeapObject(*arg)) {
    isolate->ThrowError("First argument must be a HeapObject");
    return false;
  }

  *out = Cast<HeapObject>(*arg);
  return true;
}

static bool GetArgumentObjectPassedAsAddress(
    const v8::FunctionCallbackInfo<v8::Value>& info, Tagged<HeapObject>* out) {
  Sandbox* sandbox = GetProcessWideSandbox();
  v8::Isolate* isolate = info.GetIsolate();
  Local<v8::Context> context = isolate->GetCurrentContext();

  if (info.Length() == 0) {
    isolate->ThrowError("First argument must be provided");
    return false;
  }

  Local<v8::Uint32> arg1;
  if (!info[0]->ToUint32(context).ToLocal(&arg1)) {
    isolate->ThrowError("First argument must be the address of a HeapObject");
    return false;
  }

  uint32_t address = arg1->Value();
  // Allow tagged addresses by removing the kHeapObjectTag and
  // kWeakHeapObjectTag. This allows clients to just read tagged pointers from
  // the heap and use them for these APIs.
  address &= ~kHeapObjectTagMask;
  *out = HeapObject::FromAddress(sandbox->base() + address);
  return true;
}

// Sandbox.getAddressOf(Object) -> Number
void SandboxGetAddressOf(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();

  Tagged<HeapObject> obj;
  if (!GetArgumentObjectPassedAsReference(info, &obj)) {
    return;
  }

  // HeapObjects must be allocated inside the pointer compression cage so their
  // address relative to the start of the sandbox can be obtained simply by
  // taking the lowest 32 bits of the absolute address.
  uint32_t address = static_cast<uint32_t>(obj->address());
  info.GetReturnValue().Set(v8::Integer::NewFromUnsigned(isolate, address));
}

// Sandbox.getObjectAt(Number) -> Object
void SandboxGetObjectAt(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();

  Tagged<HeapObject> obj;
  if (!GetArgumentObjectPassedAsAddress(info, &obj)) {
    return;
  }

  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Handle<Object> handle(obj, i_isolate);
  info.GetReturnValue().Set(ToApiHandle<v8::Value>(handle));
}

// Sandbox.isValidObjectAt(Address) -> Bool
void SandboxIsValidObjectAt(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  Sandbox* sandbox = GetProcessWideSandbox();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  auto IsLocatedInMappedMemory = [&](Address address) {
    // Note that IsOutsideAllocatedSpace is imprecise and may return false for
    // some addresses outside the allocated space. However, it's probably good
    // enough for our purposes.
    return !heap->memory_allocator()->IsOutsideAllocatedSpace(address);
  };

  Tagged<HeapObject> obj;
  if (!GetArgumentObjectPassedAsAddress(info, &obj)) {
    return;
  }

  // Simple heuristic: follow the Map chain three times until we find a MetaMap
  // (where the map pointer points to itself), or give up.
  info.GetReturnValue().Set(false);
  Address current = obj.address();
  for (int i = 0; i < 3; i++) {
    if (!IsLocatedInMappedMemory(current)) {
      return;
    }
    uint32_t map_word = *reinterpret_cast<uint32_t*>(current);
    if ((map_word & kHeapObjectTag) != kHeapObjectTag) {
      return;
    }
    Address map_address = sandbox->base() + map_word - kHeapObjectTag;
    if (map_address == current) {
      info.GetReturnValue().Set(true);
      return;
    }
    current = map_address;
  }
}

static void SandboxIsWritableImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    ArgumentObjectExtractorFunction getArgumentObject) {
  DCHECK(ValidateCallbackInfo(info));

  Tagged<HeapObject> obj;
  if (!getArgumentObject(info, &obj)) {
    return;
  }

  MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(obj);
  bool is_writable = chunk->IsWritable();
  info.GetReturnValue().Set(is_writable);
}

// Sandbox.isWritable(Object) -> Bool
void SandboxIsWritable(const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxIsWritableImpl(info, &GetArgumentObjectPassedAsReference);
}

// Sandbox.isWritableObjectAt(Number) -> Bool
void SandboxIsWritableObjectAt(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxIsWritableImpl(info, &GetArgumentObjectPassedAsAddress);
}

static void SandboxGetSizeOfImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    ArgumentObjectExtractorFunction getArgumentObject) {
  DCHECK(ValidateCallbackInfo(info));

  Tagged<HeapObject> obj;
  if (!getArgumentObject(info, &obj)) {
    return;
  }

  int size = obj->Size();
  info.GetReturnValue().Set(size);
}

// Sandbox.getSizeOf(Object) -> Number
void SandboxGetSizeOf(const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxGetSizeOfImpl(info, &GetArgumentObjectPassedAsReference);
}

// Sandbox.getSizeOfObjectAt(Number) -> Number
void SandboxGetSizeOfObjectAt(const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxGetSizeOfImpl(info, &GetArgumentObjectPassedAsAddress);
}

static void SandboxGetInstanceTypeOfImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    ArgumentObjectExtractorFunction getArgumentObject) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();

  Tagged<HeapObject> obj;
  if (!getArgumentObject(info, &obj)) {
    return;
  }

  InstanceType type = obj->map()->instance_type();
  std::stringstream out;
  out << type;
  MaybeLocal<v8::String> result =
      v8::String::NewFromUtf8(isolate, out.str().c_str());
  info.GetReturnValue().Set(result.ToLocalChecked());
}

// Sandbox.getInstanceTypeOf(Object) -> String
void SandboxGetInstanceTypeOf(const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxGetInstanceTypeOfImpl(info, &GetArgumentObjectPassedAsReference);
}

// Sandbox.getInstanceTypeOfObjectAt(Number) -> String
void SandboxGetInstanceTypeOfObjectAt(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxGetInstanceTypeOfImpl(info, &GetArgumentObjectPassedAsAddress);
}

static void SandboxGetInstanceTypeIdOfImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info,
    ArgumentObjectExtractorFunction getArgumentObject) {
  DCHECK(ValidateCallbackInfo(info));

  Tagged<HeapObject> obj;
  if (!getArgumentObject(info, &obj)) {
    return;
  }

  InstanceType type = obj->map()->instance_type();
  static_assert(std::is_same_v<std::underlying_type_t<InstanceType>, uint16_t>);
  if (type > LAST_TYPE) {
    // This can happen with corrupted objects. Canonicalize to a special
    // "unknown" instance type to indicate that this is an unknown type.
    const uint16_t kUnknownInstanceType = std::numeric_limits<uint16_t>::max();
    type = static_cast<InstanceType>(kUnknownInstanceType);
  }

  info.GetReturnValue().Set(type);
}

// Sandbox.getInstanceTypeIdOf(Object) -> Number
void SandboxGetInstanceTypeIdOf(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxGetInstanceTypeIdOfImpl(info, &GetArgumentObjectPassedAsReference);
}

// Sandbox.getInstanceTypeIdOfObjectAt(Number) -> Number
void SandboxGetInstanceTypeIdOfObjectAt(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  SandboxGetInstanceTypeIdOfImpl(info, &GetArgumentObjectPassedAsAddress);
}

// Sandbox.getInstanceTypeIdFor(String) -> Number
void SandboxGetInstanceTypeIdFor(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();

  v8::String::Utf8Value type_name(isolate, info[0]);
  if (!*type_name) {
    isolate->ThrowError("First argument must be a string");
    return;
  }

  auto& all_types = SandboxTesting::GetInstanceTypeMap();
  if (all_types.find(*type_name) == all_types.end()) {
    isolate->ThrowError(
        "Unknown type name. If needed, add it in "
        "SandboxTesting::GetInstanceTypeMap");
    return;
  }

  InstanceType type_id = all_types[*type_name];
  info.GetReturnValue().Set(type_id);
}

// Obtain the offset of a field in an object.
//
// This can be used to obtain the offsets of internal object fields in order to
// avoid hardcoding offsets into testcases. It basically makes the various
// Foo::kBarOffset constants accessible from JavaScript. The main benefit of
// that is that testcases continue to work if the field offset changes.
// Additionally, if a field is removed, testcases that use it will fail and can
// then be deleted if they are no longer useful.
//
// TODO(saelo): instead of this, consider adding an API like
// `Sandbox.getTypeDescriptor(Number|String) -> Object` which, given an
// instance type id or name, returns an object containing the offset constants
// as properties as well as potentially other information such as the types of
// the object's fields.
//
// Sandbox.getFieldOffset(Number, String) -> Number
void SandboxGetFieldOffset(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  Local<v8::Context> context = isolate->GetCurrentContext();

  if (!info[0]->IsInt32()) {
    isolate->ThrowError("Second argument must be an integer");
    return;
  }

  int raw_type = info[0]->Int32Value(context).FromMaybe(-1);
  if (raw_type < FIRST_TYPE || raw_type > LAST_TYPE) {
    isolate->ThrowError("Invalid instance type");
    return;
  }
  InstanceType instance_type = static_cast<InstanceType>(raw_type);

  v8::String::Utf8Value field_name(isolate, info[1]);
  if (!*field_name) {
    isolate->ThrowError("Second argument must be a string");
    return;
  }

  auto& all_fields = SandboxTesting::GetFieldOffsetMap();
  if (all_fields.find(instance_type) == all_fields.end()) {
    isolate->ThrowError(
        "Unknown object type. If needed, add it in "
        "SandboxTesting::GetFieldOffsetMap");
    return;
  }

  auto& obj_fields = all_fields[instance_type];
  if (obj_fields.find(*field_name) == obj_fields.end()) {
    isolate->ThrowError(
        "Unknown field. If needed, add it in "
        "SandboxTesting::GetFieldOffsetMap");
    return;
  }

  int offset = obj_fields[*field_name];
  info.GetReturnValue().Set(offset);
}

Handle<FunctionTemplateInfo> NewFunctionTemplate(
    Isolate* isolate, FunctionCallback func,
    ConstructorBehavior constructor_behavior) {
  // Use the API functions here as they are more convenient to use.
  v8::Isolate* api_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  Local<FunctionTemplate> function_template =
      FunctionTemplate::New(api_isolate, func, {}, {}, 0, constructor_behavior,
                            SideEffectType::kHasSideEffect);
  return v8::Utils::OpenHandle(*function_template);
}

Handle<JSFunction> CreateFunc(Isolate* isolate, FunctionCallback func,
                              Handle<String> name, bool is_constructor) {
  ConstructorBehavior constructor_behavior = is_constructor
                                                 ? ConstructorBehavior::kAllow
                                                 : ConstructorBehavior::kThrow;
  Handle<FunctionTemplateInfo> function_template =
      NewFunctionTemplate(isolate, func, constructor_behavior);
  return ApiNatives::InstantiateFunction(isolate, function_template, name)
      .ToHandleChecked();
}

void InstallFunc(Isolate* isolate, Handle<JSObject> holder,
                 FunctionCallback func, const char* name, int num_parameters,
                 bool is_constructor) {
  Factory* factory = isolate->factory();
  Handle<String> function_name = factory->NewStringFromAsciiChecked(name);
  Handle<JSFunction> function =
      CreateFunc(isolate, func, function_name, is_constructor);
  function->shared()->set_length(num_parameters);
  JSObject::AddProperty(isolate, holder, function_name, function, NONE);
}

void InstallGetter(Isolate* isolate, Handle<JSObject> object,
                   FunctionCallback func, const char* name) {
  Factory* factory = isolate->factory();
  Handle<String> property_name = factory->NewStringFromAsciiChecked(name);
  Handle<JSFunction> getter = CreateFunc(isolate, func, property_name, false);
  Handle<Object> setter = factory->null_value();
  JSObject::DefineOwnAccessorIgnoreAttributes(object, property_name, getter,
                                              setter, FROZEN);
}

void InstallFunction(Isolate* isolate, Handle<JSObject> holder,
                     FunctionCallback func, const char* name,
                     int num_parameters) {
  InstallFunc(isolate, holder, func, name, num_parameters, false);
}

void InstallConstructor(Isolate* isolate, Handle<JSObject> holder,
                        FunctionCallback func, const char* name,
                        int num_parameters) {
  InstallFunc(isolate, holder, func, name, num_parameters, true);
}
}  // namespace

void SandboxTesting::InstallMemoryCorruptionApi(Isolate* isolate) {
#ifndef V8_ENABLE_MEMORY_CORRUPTION_API
#error "This function should not be available in any shipping build "          \
       "where it could potentially be abused to facilitate exploitation."
#endif

  CHECK(GetProcessWideSandbox()->is_initialized());

  // Create the special Sandbox object that provides read/write access to the
  // sandbox address space alongside other miscellaneous functionality.
  Handle<JSObject> sandbox = isolate->factory()->NewJSObject(
      isolate->object_function(), AllocationType::kOld);

  InstallGetter(isolate, sandbox, SandboxGetBase, "base");
  InstallGetter(isolate, sandbox, SandboxGetByteLength, "byteLength");
  InstallConstructor(isolate, sandbox, SandboxMemoryView, "MemoryView", 2);
  InstallFunction(isolate, sandbox, SandboxGetAddressOf, "getAddressOf", 1);
  InstallFunction(isolate, sandbox, SandboxGetObjectAt, "getObjectAt", 1);
  InstallFunction(isolate, sandbox, SandboxIsValidObjectAt, "isValidObjectAt",
                  1);
  InstallFunction(isolate, sandbox, SandboxIsWritable, "isWritable", 1);
  InstallFunction(isolate, sandbox, SandboxIsWritableObjectAt,
                  "isWritableObjectAt", 1);
  InstallFunction(isolate, sandbox, SandboxGetSizeOf, "getSizeOf", 1);
  InstallFunction(isolate, sandbox, SandboxGetSizeOfObjectAt,
                  "getSizeOfObjectAt", 1);
  InstallFunction(isolate, sandbox, SandboxGetInstanceTypeOf,
                  "getInstanceTypeOf", 1);
  InstallFunction(isolate, sandbox, SandboxGetInstanceTypeOfObjectAt,
                  "getInstanceTypeOfObjectAt", 1);
  InstallFunction(isolate, sandbox, SandboxGetInstanceTypeIdOf,
                  "getInstanceTypeIdOf", 1);
  InstallFunction(isolate, sandbox, SandboxGetInstanceTypeIdOfObjectAt,
                  "getInstanceTypeIdOfObjectAt", 1);
  InstallFunction(isolate, sandbox, SandboxGetInstanceTypeIdFor,
                  "getInstanceTypeIdFor", 1);
  InstallFunction(isolate, sandbox, SandboxGetFieldOffset, "getFieldOffset", 2);

  // Install the Sandbox object as property on the global object.
  Handle<JSGlobalObject> global = isolate->global_object();
  Handle<String> name =
      isolate->factory()->NewStringFromAsciiChecked("Sandbox");
  JSObject::AddProperty(isolate, global, name, sandbox, DONT_ENUM);
}

#endif  // V8_ENABLE_MEMORY_CORRUPTION_API

namespace {
#ifdef V8_OS_LINUX

void PrintToStderr(const char* output) {
  // NOTE: This code MUST be async-signal safe.
  // NO malloc or stdio is allowed here.
  ssize_t return_val = write(STDERR_FILENO, output, strlen(output));
  USE(return_val);
}

[[noreturn]] void FilterCrash(const char* reason) {
  // NOTE: This code MUST be async-signal safe.
  // NO malloc or stdio is allowed here.
  PrintToStderr(reason);
  // In sandbox fuzzing mode, we want to exit with a non-zero status to
  // indicate to the fuzzer that the sample "failed" (ran into an unrecoverable
  // error) and should probably not be mutated further. Otherwise, we exit with
  // zero, which is for example needed for regression tests to make them "pass"
  // when no sandbox violation is detected.
  int status =
      SandboxTesting::mode() == SandboxTesting::Mode::kForFuzzing ? -1 : 0;
  _exit(status);
}

// Signal handler checking whether a memory access violation happened inside or
// outside of the sandbox address space. If inside, the signal is ignored and
// the process terminated normally, in the latter case the original signal
// handler is restored and the signal delivered again.
struct sigaction g_old_sigabrt_handler, g_old_sigtrap_handler,
    g_old_sigbus_handler, g_old_sigsegv_handler;

void UninstallCrashFilter() {
  // NOTE: This code MUST be async-signal safe.
  // NO malloc or stdio is allowed here.

  // It's important that we always restore all signal handlers. For example, if
  // we forward a SIGSEGV to Asan's signal handler, that signal handler may
  // terminate the process with SIGABRT, which we must then *not* ignore.
  //
  // Should any of the sigaction calls below ever fail, the default signal
  // handler will be invoked (due to SA_RESETHAND) and will terminate the
  // process, so there's no need to attempt to handle that condition.
  sigaction(SIGABRT, &g_old_sigabrt_handler, nullptr);
  sigaction(SIGTRAP, &g_old_sigtrap_handler, nullptr);
  sigaction(SIGBUS, &g_old_sigbus_handler, nullptr);
  sigaction(SIGSEGV, &g_old_sigsegv_handler, nullptr);

  // We should also uninstall the sanitizer death callback as our crash filter
  // may hand a crash over to ASan, which should then not enter our crash
  // filtering logic a second time.
#ifdef V8_USE_ADDRESS_SANITIZER
  __sanitizer_set_death_callback(nullptr);
#endif
}

void CrashFilter(int signal, siginfo_t* info, void* void_context) {
  // NOTE: This code MUST be async-signal safe.
  // NO malloc or stdio is allowed here.

  if (signal == SIGABRT) {
    // SIGABRT typically indicates a failed CHECK or similar, which is harmless.
    FilterCrash("Caught harmless signal (SIGABRT). Exiting process...\n");
  }

  if (signal == SIGTRAP) {
    // Similarly, SIGTRAP may for example indicate UNREACHABLE code.
    FilterCrash("Caught harmless signal (SIGTRAP). Exiting process...\n");
  }

  Address faultaddr = reinterpret_cast<Address>(info->si_addr);

  if (GetProcessWideSandbox()->Contains(faultaddr)) {
    FilterCrash(
        "Caught harmless memory access violaton (inside sandbox address "
        "space). Exiting process...\n");
  }

  if (info->si_code == SI_KERNEL && faultaddr == 0) {
    // This combination appears to indicate a crash at a non-canonical address
    // on Linux. Crashes at non-canonical addresses are for example caused by
    // failed external pointer type checks. Memory accesses that _always_ land
    // at a non-canonical address are not exploitable and so these are filtered
    // out here. However, testcases need to be written with this in mind and
    // must cause crashes at valid addresses.
    FilterCrash(
        "Caught harmless memory access violaton (non-canonical address). "
        "Exiting process...\n");
  }

  if (faultaddr >= 0x8000'0000'0000'0000ULL) {
    // On Linux, it appears that the kernel will still report valid (i.e.
    // canonical) kernel space addresses via the si_addr field, so we need to
    // handle these separately. We've already filtered out non-canonical
    // addresses above, so here we can just test if the most-significant bit of
    // the address is set, and if so assume that it's a kernel address.
    FilterCrash(
        "Caught harmless memory access violatation (kernel space address). "
        "Exiting process...\n");
  }

  if (faultaddr < 0x1000) {
    // Nullptr dereferences are harmless as nothing can be mapped there. We use
    // the typical page size (which is also the default value of mmap_min_addr
    // on Linux) to determine what counts as a nullptr dereference here.
    FilterCrash(
        "Caught harmless memory access violaton (nullptr dereference). Exiting "
        "process...\n");
  }

  if (faultaddr < 4ULL * GB) {
    // Currently we also ignore access violations in the first 4GB of the
    // virtual address space. See crbug.com/1470641 for more details.
    FilterCrash(
        "Caught harmless memory access violaton (first 4GB of virtual address "
        "space). Exiting process...\n");
  }

  // Stack overflow detection.
  //
  // On Linux, we generally have two types of stacks:
  //  1. The main thread's stack, allocated by the kernel, and
  //  2. The stacks of any other thread, allocated by the application
  //
  // These stacks differ in some ways, and that affects the way stack overflows
  // (caused e.g. by unbounded recursion) materialize: for (1) the kernel will
  // use a "gap" region below the stack segment, i.e. an unmapped area into
  // which the kernel itself will not place any mappings and into which the
  // stack cannot grow. A stack overflow therefore crashes with a SEGV_MAPERR.
  // On the other hand, for (2) the application is responsible for allocating
  // the stack and therefore also for allocating any guard regions around it.
  // As these guard regions must be regular mappings (with PROT_NONE), a stack
  // overflow will crash with a SEGV_ACCERR.
  //
  // It's relatively hard to reliably and accurately detect stack overflow, so
  // here we use a simple heuristic: did we crash on any kind of access
  // violation on an address just below the current thread's stack region. This
  // may cause both false positives (e.g. an access not through the stack
  // pointer register that happens to also land just below the stack) and false
  // negatives (e.g. a stack overflow on the main thread that "jumps over" the
  // first page of the gap region), but is probably good enough in practice.
  pthread_attr_t attr;
  int pthread_error = pthread_getattr_np(pthread_self(), &attr);
  if (!pthread_error) {
    uintptr_t stack_base;
    size_t stack_size;
    pthread_error = pthread_attr_getstack(
        &attr, reinterpret_cast<void**>(&stack_base), &stack_size);
    // The main thread's stack on Linux typically has a fairly large gap region
    // (1MB by default), but other thread's stacks usually have smaller guard
    // regions so here we're conservative and assume that the guard region
    // consists only of a single page.
    const size_t kMinStackGuardRegionSize = sysconf(_SC_PAGESIZE);
    uintptr_t stack_guard_region_start = stack_base - kMinStackGuardRegionSize;
    uintptr_t stack_guard_region_end = stack_base;
    if (!pthread_error && stack_guard_region_start <= faultaddr &&
        faultaddr < stack_guard_region_end) {
      FilterCrash("Caught harmless stack overflow. Exiting process...\n");
    }
  }

  if (info->si_code == SEGV_ACCERR) {
    // This indicates an access to a valid mapping but with insufficient
    // permissions, for example accessing a region mapped with PROT_NONE, or
    // writing to a read-only mapping.
    //
    // The sandbox relies on such accesses crashing in a safe way in some
    // cases. For example, the accesses into the various pointer tables are not
    // bounds checked, but instead it is guaranteed that an out-of-bounds
    // access will hit a PROT_NONE mapping.
    //
    // Memory accesses that _always_ cause such a permission violation are not
    // exploitable and the crashes are therefore filtered out here. However,
    // testcases need to be written with this behavior in mind and should
    // typically try to access non-existing memory to demonstrate the ability
    // to escape from the sandbox.
    FilterCrash(
        "Caught harmless memory access violaton (memory permission violation). "
        "Exiting process...\n");
  }

  // Otherwise it's a sandbox violation, so restore the original signal
  // handlers, then return from this handler. The faulting instruction will be
  // re-executed and will again trigger the access violation, but now the
  // signal will be handled by the original signal handler.
  UninstallCrashFilter();

  PrintToStderr("\n## V8 sandbox violation detected!\n\n");
}

#ifdef V8_USE_ADDRESS_SANITIZER
void AsanFaultHandler() {
  Address faultaddr = reinterpret_cast<Address>(__asan_get_report_address());

  if (faultaddr == kNullAddress) {
    FilterCrash(
        "Caught ASan fault without a fault address. Ignoring it as we cannot "
        "check if it is a sandbox violation. Exiting process...\n");
  }

  if (GetProcessWideSandbox()->Contains(faultaddr)) {
    FilterCrash(
        "Caught harmless ASan fault (inside sandbox address space). Exiting "
        "process...\n");
  }

  // Asan may report the failure via abort(), so we should also restore the
  // original signal handlers here.
  UninstallCrashFilter();

  PrintToStderr("\n## V8 sandbox violation detected!\n\n");
}
#endif  // V8_USE_ADDRESS_SANITIZER

void InstallCrashFilter() {
  // Register an alternate stack for signal delivery so that signal handlers
  // can run properly even if for example the stack pointer has been corrupted
  // or the stack has overflowed.
  // Note that the alternate stack is currently only registered for the main
  // thread. Stack pointer corruption or stack overflows on background threads
  // may therefore still cause the signal handler to crash.
  VirtualAddressSpace* vas = GetPlatformVirtualAddressSpace();
  Address alternate_stack =
      vas->AllocatePages(VirtualAddressSpace::kNoHint, SIGSTKSZ,
                         vas->page_size(), PagePermissions::kReadWrite);
  CHECK_NE(alternate_stack, kNullAddress);
  stack_t signalstack = {
      .ss_sp = reinterpret_cast<void*>(alternate_stack),
      .ss_flags = 0,
      .ss_size = static_cast<size_t>(SIGSTKSZ),
  };
  CHECK_EQ(sigaltstack(&signalstack, nullptr), 0);

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_flags = SA_SIGINFO | SA_ONSTACK;
  action.sa_sigaction = &CrashFilter;
  sigemptyset(&action.sa_mask);

  bool success = true;
  success &= (sigaction(SIGABRT, &action, &g_old_sigabrt_handler) == 0);
  success &= (sigaction(SIGTRAP, &action, &g_old_sigtrap_handler) == 0);
  success &= (sigaction(SIGBUS, &action, &g_old_sigbus_handler) == 0);
  success &= (sigaction(SIGSEGV, &action, &g_old_sigsegv_handler) == 0);
  CHECK(success);

#if defined(V8_USE_ADDRESS_SANITIZER)
  __sanitizer_set_death_callback(&AsanFaultHandler);
#elif defined(V8_USE_MEMORY_SANITIZER) || \
    defined(V8_USE_UNDEFINED_BEHAVIOR_SANITIZER)
  // TODO(saelo): can we also test for the other sanitizers here somehow?
  FATAL("The sandbox crash filter currently only supports AddressSanitizer");
#endif
}

#endif  // V8_OS_LINUX
}  // namespace

void SandboxTesting::Enable(Mode mode) {
  CHECK_EQ(mode_, Mode::kDisabled);
  CHECK_NE(mode, Mode::kDisabled);
  CHECK(GetProcessWideSandbox()->is_initialized());

  mode_ = mode;

  fprintf(stderr,
          "Sandbox testing mode is enabled. Only sandbox violations will be "
          "reported, all other crashes will be ignored.\n");

#ifdef V8_OS_LINUX
  InstallCrashFilter();
#else
  FATAL("The sandbox crash filter is currently only available on Linux");
#endif  // V8_OS_LINUX
}

SandboxTesting::InstanceTypeMap& SandboxTesting::GetInstanceTypeMap() {
  // This mechanism is currently very crude and needs to be manually maintained
  // and extended (e.g. when adding a js test for the sandbox). In the future,
  // it would be nice to somehow automatically generate this map from the
  // object definitions and also support the class inheritance hierarchy.
  static base::LeakyObject<InstanceTypeMap> g_known_instance_types;
  auto& types = *g_known_instance_types.get();
  bool is_initialized = types.size() != 0;
  if (!is_initialized) {
    types["JS_OBJECT_TYPE"] = JS_OBJECT_TYPE;
    types["JS_FUNCTION_TYPE"] = JS_FUNCTION_TYPE;
    types["JS_ARRAY_TYPE"] = JS_ARRAY_TYPE;
    types["SEQ_ONE_BYTE_STRING_TYPE"] = SEQ_ONE_BYTE_STRING_TYPE;
    types["INTERNALIZED_ONE_BYTE_STRING_TYPE"] =
        INTERNALIZED_ONE_BYTE_STRING_TYPE;
    types["SLICED_ONE_BYTE_STRING_TYPE"] = SLICED_ONE_BYTE_STRING_TYPE;
    types["CONS_ONE_BYTE_STRING_TYPE"] = CONS_ONE_BYTE_STRING_TYPE;
    types["SHARED_FUNCTION_INFO_TYPE"] = SHARED_FUNCTION_INFO_TYPE;
    types["SCRIPT_TYPE"] = SCRIPT_TYPE;
#ifdef V8_ENABLE_WEBASSEMBLY
    types["WASM_MODULE_OBJECT_TYPE"] = WASM_MODULE_OBJECT_TYPE;
    types["WASM_INSTANCE_OBJECT_TYPE"] = WASM_INSTANCE_OBJECT_TYPE;
    types["WASM_FUNC_REF_TYPE"] = WASM_FUNC_REF_TYPE;
    types["WASM_TABLE_OBJECT_TYPE"] = WASM_TABLE_OBJECT_TYPE;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  return types;
}

SandboxTesting::FieldOffsetMap& SandboxTesting::GetFieldOffsetMap() {
  // This mechanism is currently very crude and needs to be manually maintained
  // and extended (e.g. when adding a js test for the sandbox). In the future,
  // it would be nice to somehow automatically generate this map from the
  // object definitions and also support the class inheritance hierarchy.
  static base::LeakyObject<FieldOffsetMap> g_known_fields;
  auto& fields = *g_known_fields.get();
  bool is_initialized = fields.size() != 0;
  if (!is_initialized) {
#ifdef V8_ENABLE_LEAPTIERING
    fields[JS_FUNCTION_TY
"""


```