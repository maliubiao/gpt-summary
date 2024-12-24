Response: The user wants to understand the functionality of the C++ file `v8/src/sandbox/testing.cc`. I need to analyze the code and provide a summary of its purpose. Since the filename includes "sandbox" and "testing", it's likely related to testing the V8 sandbox functionality.

Specifically, I need to:

1. **Identify the main purpose of the code.**  Look for keywords, class names, and function names that reveal the core functionality.
2. **Determine if it interacts with JavaScript.**  Check if the code exposes any APIs or functionality that can be accessed from JavaScript. Callback functions with signatures like `v8::FunctionCallbackInfo` are a strong indicator of this.
3. **If there's a connection to JavaScript, provide a JavaScript example.** This example should demonstrate how the C++ code's functionality can be used from JavaScript.
这个C++文件 `v8/src/sandbox/testing.cc` 的主要功能是**为V8引擎的沙箱环境提供测试和调试支持**。  更具体地说，它在V8中暴露了一些底层的API，允许JavaScript代码与沙箱环境进行交互，用于测试沙箱的隔离性和安全性，以及进行一些底层的内存检查和分析。

以下是该文件功能的详细归纳：

1. **启用/禁用沙箱测试模式:**  该文件定义了一个 `SandboxTesting` 类，可以用来启用或禁用特定的沙箱测试模式 (`SandboxTesting::Enable`). 当启用时，它会安装一个信号处理程序，用于捕获内存访问违规等信号，并判断这些违规是否发生在沙箱地址空间内。  如果是沙箱内的违规，则会被认为是无害的，并被忽略或以特定的方式处理，以便测试可以继续进行。  这使得在测试环境中可以区分由沙箱保护机制引发的预期错误和真正的程序错误。

2. **暴露内存腐败API (仅在非发布版本中):**  当 `V8_ENABLE_MEMORY_CORRUPTION_API` 宏被定义时（通常只在测试或调试构建中），该文件会向JavaScript环境注入一个名为 `Sandbox` 的全局对象。这个对象提供了一系列方法，允许JavaScript代码执行以下操作：
    * **获取沙箱的基地址和大小:**  `Sandbox.base` 和 `Sandbox.byteLength` 可以获取沙箱内存区域的起始地址和总大小。
    * **创建沙箱内存视图:** `Sandbox.MemoryView(offset, size)`  创建一个指向沙箱内部内存的 `ArrayBuffer` 视图，允许JavaScript代码直接读取或修改沙箱内的内存。**这部分功能极其危险，仅用于测试目的。**
    * **获取对象的地址:** `Sandbox.getAddressOf(object)` 获取JavaScript堆对象的在沙箱内的地址。
    * **获取指定地址的对象:** `Sandbox.getObjectAt(address)`  根据沙箱内的地址获取对应的JavaScript堆对象。
    * **验证指定地址是否是有效的对象:** `Sandbox.isValidObjectAt(address)` 检查给定地址是否指向一个看起来像有效V8堆对象的内存区域。
    * **检查对象或地址是否可写:** `Sandbox.isWritable(object)` 和 `Sandbox.isWritableObjectAt(address)` 检查指定的对象或内存地址是否可写。
    * **获取对象的大小:** `Sandbox.getSizeOf(object)` 和 `Sandbox.getSizeOfObjectAt(address)` 获取指定对象或内存地址处对象的大小。
    * **获取对象的实例类型:** `Sandbox.getInstanceTypeOf(object)` 和 `Sandbox.getInstanceTypeOfObjectAt(address)` 获取指定对象或内存地址处对象的实例类型名称（例如 "JS_OBJECT_TYPE"）。
    * **获取对象实例类型的ID:** `Sandbox.getInstanceTypeIdOf(object)` 和 `Sandbox.getInstanceTypeIdOfObjectAt(address)` 获取指定对象或内存地址处对象的实例类型ID（一个数字）。
    * **根据类型名称获取类型ID:** `Sandbox.getInstanceTypeIdFor(typeName)`  根据实例类型的名称获取对应的ID。
    * **获取对象字段的偏移量:** `Sandbox.getFieldOffset(typeId, fieldName)`  获取特定类型对象的指定字段在其内存布局中的偏移量。

3. **安装崩溃过滤器 (仅限Linux):** 在Linux系统上，当启用沙箱测试模式时，该文件会安装一个自定义的信号处理程序，用于捕获诸如 `SIGSEGV` (段错误), `SIGABRT` (中止信号) 等信号。这个处理程序会检查导致信号的内存访问是否发生在沙箱的地址空间内。如果是，则认为这是一个预期的沙箱保护行为，并可能选择忽略该信号或以特定的方式处理，以便测试可以继续进行。如果发生在沙箱外部，则会将信号传递给原始的处理程序。

**与JavaScript的功能关系及示例:**

该文件通过 `InstallMemoryCorruptionApi` 函数在JavaScript中暴露了 `Sandbox` 对象及其方法。这些方法允许JavaScript代码直接与V8的内部结构（特别是沙箱）进行交互。

**JavaScript 示例:**

```javascript
// 假设在启用了内存腐败API的V8环境中运行

// 获取沙箱的基地址和大小
const sandboxBase = Sandbox.base;
const sandboxByteLength = Sandbox.byteLength;
console.log(`Sandbox base address: 0x${sandboxBase.toString(16)}`);
console.log(`Sandbox size: ${sandboxByteLength} bytes`);

// 创建一个简单的对象
const obj = { value: 42 };

// 获取对象的地址
const objAddress = Sandbox.getAddressOf(obj);
console.log(`Object address: 0x${objAddress.toString(16)}`);

// 尝试从沙箱内部读取对象 (需要先知道对象的偏移量和结构)
// 注意：这只是一个概念示例，实际操作需要对V8内部结构有深入了解
// const valueOffset = Sandbox.getFieldOffset(Sandbox.getInstanceTypeIdOf(obj), "value");
// const memoryView = new Sandbox.MemoryView(objAddress + valueOffset, 4); // 假设 value 是一个 4 字节的整数
// const dataView = new DataView(memoryView.buffer);
// const readValue = dataView.getInt32(0, true); // 从内存中读取整数 (假设是小端序)
// console.log(`Read value from memory: ${readValue}`);

// 创建一个指向沙箱内存的 MemoryView
const view = new Sandbox.MemoryView(0, 1024); // 创建一个指向沙箱起始位置的 1024 字节的视图
const buffer = view.buffer;
const uint8Array = new Uint8Array(buffer);

// 修改沙箱内的内存 (非常危险!)
uint8Array[0] = 0x41; // 修改沙箱起始位置的第一个字节

// 获取指定地址的对象（需要知道沙箱内的有效对象地址）
// 注意：直接使用任意地址可能会导致错误或崩溃
// const anotherObj = Sandbox.getObjectAt(someKnownValidAddress);
// console.log(anotherObj);

// 检查对象是否可写
const isObjWritable = Sandbox.isWritable(obj);
console.log(`Is object writable: ${isObjWritable}`);

// 获取对象的大小
const objSize = Sandbox.getSizeOf(obj);
console.log(`Object size: ${objSize}`);

// 获取对象的实例类型名称
const objType = Sandbox.getInstanceTypeOf(obj);
console.log(`Object type: ${objType}`);

// 获取对象的实例类型 ID
const objTypeId = Sandbox.getInstanceTypeIdOf(obj);
console.log(`Object type ID: ${objTypeId}`);

// 根据类型名称获取类型 ID
const functionTypeId = Sandbox.getInstanceTypeIdFor("JS_FUNCTION_TYPE");
console.log(`JS_FUNCTION_TYPE ID: ${functionTypeId}`);

// 获取 JSFunction 对象的 dispatch_handle 字段的偏移量 (假设启用了 LEAPTIERING)
// const dispatchHandleOffset = Sandbox.getFieldOffset(Sandbox.getInstanceTypeIdFor("JS_FUNCTION_TYPE"), "dispatch_handle");
// console.log(`JSFunction.dispatch_handle offset: ${dispatchHandleOffset}`);
```

**重要提示:**  `Sandbox` 对象提供的API 允许直接访问和修改V8引擎的内部状态和内存，这在正常情况下是被严格禁止的。这些API **只能用于测试和调试目的**，并且需要在特殊的V8构建版本中启用。在生产环境中使用这些API可能会导致严重的崩溃、安全漏洞或其他不可预测的行为。

总而言之，`v8/src/sandbox/testing.cc` 是V8沙箱机制的关键测试组件，它通过暴露底层API和提供崩溃过滤功能，帮助开发者验证沙箱的隔离性和安全性，并在测试过程中区分预期行为和真正的错误。

Prompt: 
```
这是目录为v8/src/sandbox/testing.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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
    fields[JS_FUNCTION_TYPE]["dispatch_handle"] =
        JSFunction::kDispatchHandleOffset;
#endif  // V8_ENABLE_LEAPTIERING
    fields[JS_FUNCTION_TYPE]["shared_function_info"] =
        JSFunction::kSharedFunctionInfoOffset;
    fields[JS_ARRAY_TYPE]["length"] = JSArray::kLengthOffset;
    fields[SEQ_ONE_BYTE_STRING_TYPE]["length"] =
        offsetof(SeqOneByteString, length_);
    fields[INTERNALIZED_ONE_BYTE_STRING_TYPE]["length"] =
        offsetof(InternalizedString, length_);
    fields[SLICED_ONE_BYTE_STRING_TYPE]["parent"] =
        offsetof(SlicedString, parent_);
    fields[CONS_ONE_BYTE_STRING_TYPE]["length"] = offsetof(ConsString, length_);
    fields[CONS_ONE_BYTE_STRING_TYPE]["first"] = offsetof(ConsString, first_);
    fields[CONS_ONE_BYTE_STRING_TYPE]["second"] = offsetof(ConsString, second_);
    fields[SHARED_FUNCTION_INFO_TYPE]["trusted_function_data"] =
        SharedFunctionInfo::kTrustedFunctionDataOffset;
    fields[SHARED_FUNCTION_INFO_TYPE]["length"] =
        SharedFunctionInfo::kLengthOffset;
    fields[SHARED_FUNCTION_INFO_TYPE]["formal_parameter_count"] =
        SharedFunctionInfo::kFormalParameterCountOffset;
    fields[SCRIPT_TYPE]["wasm_managed_native_module"] =
        Script::kEvalFromPositionOffset;
#ifdef V8_ENABLE_WEBASSEMBLY
    fields[WASM_MODULE_OBJECT_TYPE]["managed_native_module"] =
        WasmModuleObject::kManagedNativeModuleOffset;
    fields[WASM_MODULE_OBJECT_TYPE]["script"] = WasmModuleObject::kScriptOffset;
    fields[WASM_INSTANCE_OBJECT_TYPE]["module_object"] =
        WasmInstanceObject::kModuleObjectOffset;
    fields[WASM_FUNC_REF_TYPE]["trusted_internal"] =
        WasmFuncRef::kTrustedInternalOffset;
    fields[WASM_TABLE_OBJECT_TYPE]["entries"] = WasmTableObject::kEntriesOffset;
    fields[WASM_TABLE_OBJECT_TYPE]["current_length"] =
        WasmTableObject::kCurrentLengthOffset;
    fields[WASM_TABLE_OBJECT_TYPE]["maximum_length"] =
        WasmTableObject::kMaximumLengthOffset;
    fields[WASM_TABLE_OBJECT_TYPE]["raw_type"] =
        WasmTableObject::kRawTypeOffset;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  return fields;
}

#endif  // V8_ENABLE_SANDBOX

}  // namespace internal
}  // namespace v8

"""

```