Response:
The user is providing a C++ header file (`wasm-objects.h`) from the V8 JavaScript engine source code and asking for a breakdown of its functionality. The prompt also includes specific instructions related to file extensions, JavaScript relevance, code logic, common errors, and a summary of its purpose.

Here's a plan to address the request:

1. **Analyze the Header File Structure:** Identify the key components, such as includes, namespaces, classes, enums, and macros.
2. **Determine Core Functionality:** Based on the class names and their members, deduce the primary responsibilities of `wasm-objects.h`. Focus on concepts like module representation, memory management, tables, globals, instances, and exception handling within the WebAssembly context.
3. **Address Specific Instructions:**
    * **File Extension:** Confirm that `.h` is not `.tq`, so it's not a Torque source file.
    * **JavaScript Relationship:** Identify classes that directly correspond to JavaScript WebAssembly API objects (e.g., `WasmModuleObject`, `WasmMemoryObject`, `WasmTableObject`, `WasmGlobalObject`, `WasmInstanceObject`, `WasmTagObject`). Provide JavaScript examples.
    * **Code Logic Inference:**  Look for methods that suggest specific logic, such as `Grow` for tables and memory, `Set` and `Get` for table elements, and `UpdateDispatchTables`. Create hypothetical input and output scenarios.
    * **Common Programming Errors:** Consider potential mistakes developers might make when interacting with the WebAssembly JavaScript API, which this header helps define.
4. **Summarize Functionality:** Condense the findings into a concise overview of the header's purpose.
这是对V8源代码文件 `v8/src/wasm/wasm-objects.h` 功能的分析。

**功能列举:**

`v8/src/wasm/wasm-objects.h`  定义了 V8 引擎中用于表示 WebAssembly 相关对象的 C++ 类结构。这些类是 V8 内部表示 WebAssembly 模块、实例、内存、表、全局变量、异常等的蓝图。

具体功能包括：

* **定义 WebAssembly 模块的表示 (`WasmModuleObject`)**:  包含对已编译 WebAssembly 模块的引用，以及获取模块名称和函数名称等元数据的方法。
* **定义 WebAssembly 实例的表示 (`WasmInstanceObject`)**: 代表 WebAssembly 模块的一个具体实例，包含了模块的运行时状态。
* **定义 WebAssembly 内存的表示 (`WasmMemoryObject`)**:  封装了 WebAssembly 模块的线性内存，提供了增长内存、获取内存数据等操作。
* **定义 WebAssembly 表的表示 (`WasmTableObject`)**:  表示 WebAssembly 的表结构，用于存储函数引用或其他引用类型，并支持动态增长和元素访问。
* **定义 WebAssembly 全局变量的表示 (`WasmGlobalObject`)**:  表示 WebAssembly 模块中定义的全局变量，可以是可变的或不可变的。
* **定义 WebAssembly 异常标签的表示 (`WasmTagObject`)**:  表示 WebAssembly 的异常标签，用于实现 try/catch 机制。
* **定义受信任的实例数据 (`WasmTrustedInstanceData`)**: 存储 WebAssembly 实例的受保护的运行时信息，例如内存的起始地址、全局变量的存储位置、分发表等。这个对象在信任域中，用户代码无法直接修改。
* **定义导入函数入口 (`ImportedFunctionEntry`)**: 用于管理 WebAssembly 调用导入函数时的信息，区分 Wasm 到 JS 的调用和 Wasm 到 Wasm 的调用。
* **定义函数目标和隐式参数 (`FunctionTargetAndImplicitArg`)**:  用于存储函数调用的目标代码指针和隐式参数，例如 `WasmTrustedInstanceData`。
* **提供与 JavaScript 对象交互的接口**:  虽然这个头文件主要是 C++ 定义，但它定义的对象与 JavaScript 的 `WebAssembly` API 中的对象（如 `WebAssembly.Module`, `WebAssembly.Instance`, `WebAssembly.Memory`, `WebAssembly.Table`, `WebAssembly.Global`, `WebAssembly.Tag`) 有着直接的关联。
* **管理 WebAssembly 的分发表 (`WasmDispatchTable`)**: 用于高效地进行间接函数调用，例如通过表调用函数。
* **支持 WebAssembly 的各种特性**:  例如，共享内存 (`SharedFlag`)，以及区分32位和64位地址空间。

**关于文件扩展名 `.tq`:**

`v8/src/wasm/wasm-objects.h` 以 `.h` 结尾，**不是**以 `.tq` 结尾。因此，它不是一个 V8 Torque 源代码文件。Torque 文件通常用于定义 V8 内部的内置函数和对象，并生成高效的 C++ 代码。

**与 JavaScript 功能的关系和示例:**

`v8/src/wasm/wasm-objects.h` 中定义的 C++ 类直接对应于 JavaScript 中 `WebAssembly` API 的概念。

例如：

* **`WasmModuleObject`**  对应于 JavaScript 的 `WebAssembly.Module` 对象。
   ```javascript
   const wasmCode = new Uint8Array([ /* ... wasm 字节码 ... */ ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   console.log(wasmModule instanceof WebAssembly.Module); // true
   ```

* **`WasmInstanceObject`** 对应于 JavaScript 的 `WebAssembly.Instance` 对象。
   ```javascript
   const wasmInstance = new WebAssembly.Instance(wasmModule);
   console.log(wasmInstance instanceof WebAssembly.Instance); // true
   ```

* **`WasmMemoryObject`** 对应于 JavaScript 的 `WebAssembly.Memory` 对象。
   ```javascript
   const wasmMemory = new WebAssembly.Memory({ initial: 10 });
   console.log(wasmMemory instanceof WebAssembly.Memory); // true
   ```

* **`WasmTableObject`** 对应于 JavaScript 的 `WebAssembly.Table` 对象。
   ```javascript
   const wasmTable = new WebAssembly.Table({ initial: 2, element: 'funcref' });
   console.log(wasmTable instanceof WebAssembly.Table); // true
   ```

* **`WasmGlobalObject`** 对应于 JavaScript 的 `WebAssembly.Global` 对象。
   ```javascript
   const wasmGlobal = new WebAssembly.Global({ value: 'i32', mutable: true }, 42);
   console.log(wasmGlobal.value); // 42
   ```

* **`WasmTagObject`** 对应于 JavaScript 的 `WebAssembly.Tag` 对象 (Exception Handling)。
   ```javascript
   const wasmTag = new WebAssembly.Tag({ parameters: [] });
   ```

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `WasmTableObject` 实例，其内部存储着函数引用。

**假设输入:**

* `table`: 一个 `WasmTableObject` 实例，其大小为 5，已经存储了一些函数引用。
* `index`:  一个整数，表示要获取的表元素的索引，例如 `2`。

**代码逻辑 (基于 `WasmTableObject::Get` 方法):**

`WasmTableObject::Get` 方法会根据提供的索引，从其内部存储中检索对应的元素。

**假设输出:**

* 如果索引 `2` 处存储的是一个有效的函数引用（例如，一个 `WasmJSFunction` 或内部的 WebAssembly 函数表示），则该方法会返回对该函数引用的一个 `Handle<Object>`。
* 如果索引 `2` 处是空的或无效的，则可能会返回一个表示空值的 `Handle<Object>` (例如 `Null`)。

**用户常见的编程错误 (与 JavaScript 层面相关):**

* **尝试访问超出 WebAssembly 内存或表边界的地址或索引:** 这会导致运行时错误。
   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1 });
   const buffer = new Uint8Array(memory.buffer);
   // 内存大小为 65536 字节 (1 页)
   buffer[100000] = 10; // 错误: 访问超出内存边界
   ```

* **尝试在类型不匹配的表条目中设置值:** WebAssembly 表有固定的元素类型（例如 `funcref`），尝试设置不兼容的值会导致错误。
   ```javascript
   const table = new WebAssembly.Table({ initial: 1, element: 'funcref' });
   table.set(0, 123); // 错误: 尝试在 'funcref' 表中设置一个数字
   ```

* **在未初始化的 WebAssembly 实例上调用导出函数:** 在实例成功创建之前调用导出的函数会导致错误。
   ```javascript
   let instance;
   WebAssembly.instantiateStreaming(fetch('module.wasm'))
     .then(results => {
       instance = results.instance;
       instance.exports.exported_function(); // 现在可以调用
     });
   // instance.exports.exported_function(); // 错误: 实例可能尚未准备好
   ```

**功能归纳 (第 1 部分):**

`v8/src/wasm/wasm-objects.h` 是 V8 引擎中至关重要的头文件，它定义了用于表示 WebAssembly 核心概念的 C++ 类。这些类构成了 V8 如何在内部管理和操作 WebAssembly 模块、实例及其相关资源的基础。它为 V8 引擎提供了描述 WebAssembly 结构和行为的数据模型，并为 JavaScript 的 `WebAssembly` API 提供了底层的实现支撑。该文件不是 Torque 源代码，并且它定义的对象直接映射到 JavaScript WebAssembly API 中的对象。

### 提示词
```
这是目录为v8/src/wasm/wasm-objects.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.  Use of
// this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_OBJECTS_H_
#define V8_WASM_WASM_OBJECTS_H_

#include <memory>
#include <optional>

#include "src/base/bit-field.h"
#include "src/debug/interface-types.h"
#include "src/heap/heap.h"
#include "src/objects/backing-store.h"
#include "src/objects/casting.h"
#include "src/objects/foreign.h"
#include "src/objects/js-function.h"
#include "src/objects/js-objects.h"
#include "src/objects/objects-body-descriptors.h"
#include "src/objects/objects.h"
#include "src/objects/struct.h"
#include "src/objects/trusted-object.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/stacks.h"
#include "src/wasm/struct-types.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-module.h"

// Has to be the last include (doesn't have include guards)
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {
namespace wasm {
class NativeModule;
class WasmCode;
struct WasmFunction;
struct WasmGlobal;
struct WasmModule;
struct WasmTag;
using WasmTagSig = FunctionSig;
class WasmValue;
class WireBytesRef;
}  // namespace wasm

class BreakPoint;
class JSArrayBuffer;
class SeqOneByteString;
class StructBodyDescriptor;
class WasmCapiFunction;
class WasmExceptionTag;
class WasmExportedFunction;
class WasmExternalFunction;
class WasmTrustedInstanceData;
class WasmJSFunction;
class WasmModuleObject;

enum class SharedFlag : uint8_t;

enum class IsAWrapper : uint8_t { kYes, kMaybe, kNo };

template <typename CppType>
class Managed;
template <typename CppType>
class TrustedManaged;

#include "torque-generated/src/wasm/wasm-objects-tq.inc"

#define DECL_OPTIONAL_ACCESSORS(name, type) \
  DECL_GETTER(has_##name, bool)             \
  DECL_ACCESSORS(name, type)

class V8_EXPORT_PRIVATE FunctionTargetAndImplicitArg {
 public:
  FunctionTargetAndImplicitArg(
      Isolate* isolate, Handle<WasmTrustedInstanceData> target_instance_data,
      int target_func_index);
  // The "implicit_arg" will be a WasmTrustedInstanceData or a WasmImportData.
  Handle<TrustedObject> implicit_arg() { return implicit_arg_; }
  WasmCodePointer call_target() { return call_target_; }

#if V8_ENABLE_DRUMBRAKE
  int target_func_index() { return target_func_index_; }
#endif  // V8_ENABLE_DRUMBRAKE

 private:
  Handle<TrustedObject> implicit_arg_;
  WasmCodePointer call_target_;

#if V8_ENABLE_DRUMBRAKE
  int target_func_index_;
#endif  // V8_ENABLE_DRUMBRAKE
};

namespace wasm {
enum class OnResume : int { kContinue, kThrow };
}  // namespace wasm

// A helper for an entry for an imported function, indexed statically.
// The underlying storage in the instance is used by generated code to
// call imported functions at runtime.
// Each entry is either:
//   - Wasm to JS, which has fields
//      - object = a WasmImportData
//      - target = entrypoint to import wrapper code
//   - Wasm to Wasm, which has fields
//      - object = target instance data
//      - target = entrypoint for the function
class ImportedFunctionEntry {
 public:
  inline ImportedFunctionEntry(Isolate*, DirectHandle<WasmInstanceObject>,
                               int index);
  inline ImportedFunctionEntry(Handle<WasmTrustedInstanceData>, int index);

  // Initialize this entry as a Wasm to JS call. This accepts the isolate as a
  // parameter since it allocates a WasmImportData.
  void SetGenericWasmToJs(Isolate*, DirectHandle<JSReceiver> callable,
                          wasm::Suspend suspend, const wasm::CanonicalSig* sig);
  V8_EXPORT_PRIVATE void SetCompiledWasmToJs(Isolate*,
                                             DirectHandle<JSReceiver> callable,
                                             wasm::WasmCode* wasm_to_js_wrapper,
                                             wasm::Suspend suspend,
                                             const wasm::CanonicalSig* sig);

  // Initialize this entry as a Wasm to Wasm call.
  void SetWasmToWasm(Tagged<WasmTrustedInstanceData> target_instance_object,
                     WasmCodePointer call_target
#if V8_ENABLE_DRUMBRAKE
                     ,
                     int exported_function_index
#endif  // V8_ENABLE_DRUMBRAKE
  );

  Tagged<JSReceiver> callable();
  Tagged<Object> maybe_callable();
  Tagged<Object> implicit_arg();
  WasmCodePointer target();

#if V8_ENABLE_DRUMBRAKE
  int function_index_in_called_module();
#endif  // V8_ENABLE_DRUMBRAKE

 private:
  Handle<WasmTrustedInstanceData> const instance_data_;
  int const index_;
};

enum InternalizeString : bool { kInternalize = true, kNoInternalize = false };

// Representation of a WebAssembly.Module JavaScript-level object.
class WasmModuleObject
    : public TorqueGeneratedWasmModuleObject<WasmModuleObject, JSObject> {
 public:
  inline wasm::NativeModule* native_module() const;
  inline const std::shared_ptr<wasm::NativeModule>& shared_native_module()
      const;
  inline const wasm::WasmModule* module() const;

  // Dispatched behavior.
  DECL_PRINTER(WasmModuleObject)

  // Creates a new {WasmModuleObject} for an existing {NativeModule} that is
  // reference counted and might be shared between multiple Isolates.
  V8_EXPORT_PRIVATE static Handle<WasmModuleObject> New(
      Isolate* isolate, std::shared_ptr<wasm::NativeModule> native_module,
      DirectHandle<Script> script);

  // Check whether this module was generated from asm.js source.
  inline bool is_asm_js();

  // Get the module name, if set. Returns an empty handle otherwise.
  static MaybeHandle<String> GetModuleNameOrNull(
      Isolate*, DirectHandle<WasmModuleObject>);

  // Get the function name of the function identified by the given index.
  // Returns a null handle if the function is unnamed or the name is not a valid
  // UTF-8 string.
  static MaybeHandle<String> GetFunctionNameOrNull(
      Isolate*, DirectHandle<WasmModuleObject>, uint32_t func_index);

  // Get the raw bytes of the function name of the function identified by the
  // given index.
  // Meant to be used for debugging or frame printing.
  // Does not allocate, hence gc-safe.
  base::Vector<const uint8_t> GetRawFunctionName(int func_index);

  // Extract a portion of the wire bytes as UTF-8 string, optionally
  // internalized. (Prefer to internalize early if the string will be used for a
  // property lookup anyway.)
  static Handle<String> ExtractUtf8StringFromModuleBytes(
      Isolate*, DirectHandle<WasmModuleObject>, wasm::WireBytesRef,
      InternalizeString);
  static Handle<String> ExtractUtf8StringFromModuleBytes(
      Isolate*, base::Vector<const uint8_t> wire_byte, wasm::WireBytesRef,
      InternalizeString);

  TQ_OBJECT_CONSTRUCTORS(WasmModuleObject)
};

#if V8_ENABLE_SANDBOX || DEBUG
// This should be checked before writing an untrusted function reference
// into a dispatch table (e.g. via WasmTableObject::Set).
bool FunctionSigMatchesTable(wasm::CanonicalTypeIndex sig_id,
                             const wasm::WasmModule* module, int table_index);
#endif

// Representation of a WebAssembly.Table JavaScript-level object.
class WasmTableObject
    : public TorqueGeneratedWasmTableObject<WasmTableObject, JSObject> {
 public:
  class BodyDescriptor;

  inline wasm::ValueType type();

  DECL_TRUSTED_POINTER_ACCESSORS(trusted_data, WasmTrustedInstanceData)

  V8_EXPORT_PRIVATE static int Grow(Isolate* isolate,
                                    DirectHandle<WasmTableObject> table,
                                    uint32_t count,
                                    DirectHandle<Object> init_value);

  V8_EXPORT_PRIVATE static Handle<WasmTableObject> New(
      Isolate* isolate, Handle<WasmTrustedInstanceData> trusted_data,
      wasm::ValueType type, uint32_t initial, bool has_maximum,
      uint64_t maximum, DirectHandle<Object> initial_value,
      wasm::AddressType address_type);

  // Store that a specific instance uses this table, in order to update the
  // instance's dispatch table when this table grows (and hence needs to
  // allocate a new dispatch table).
  V8_EXPORT_PRIVATE static void AddUse(
      Isolate* isolate, DirectHandle<WasmTableObject> table,
      Handle<WasmInstanceObject> instance_object, int table_index);

  inline bool is_in_bounds(uint32_t entry_index);

  inline bool is_table64() const;

  // Get the declared maximum as uint64_t or nullopt if no maximum was declared.
  inline std::optional<uint64_t> maximum_length_u64() const;

  // Thin wrapper around {JsToWasmObject}.
  static MaybeHandle<Object> JSToWasmElement(
      Isolate* isolate, DirectHandle<WasmTableObject> table,
      Handle<Object> entry, const char** error_message);

  // This function will not handle JS objects; i.e., {entry} needs to be in wasm
  // representation.
  V8_EXPORT_PRIVATE static void Set(Isolate* isolate,
                                    DirectHandle<WasmTableObject> table,
                                    uint32_t index, DirectHandle<Object> entry);

  V8_EXPORT_PRIVATE static Handle<Object> Get(
      Isolate* isolate, DirectHandle<WasmTableObject> table, uint32_t index);

  V8_EXPORT_PRIVATE static void Fill(Isolate* isolate,
                                     DirectHandle<WasmTableObject> table,
                                     uint32_t start, DirectHandle<Object> entry,
                                     uint32_t count);

  // TODO(wasm): Unify these three methods into one.
  static void UpdateDispatchTables(
      Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
      const wasm::WasmFunction* func,
      DirectHandle<WasmTrustedInstanceData> target_instance
#if V8_ENABLE_DRUMBRAKE
      ,
      int target_func_index
#endif  // V8_ENABLE_DRUMBRAKE
  );
  static void UpdateDispatchTables(Isolate* isolate,
                                   DirectHandle<WasmTableObject> table,
                                   int entry_index,
                                   DirectHandle<WasmJSFunction> function);
  static void UpdateDispatchTables(
      Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
      DirectHandle<WasmCapiFunction> capi_function);

  void ClearDispatchTables(int index);

  V8_EXPORT_PRIVATE static void SetFunctionTablePlaceholder(
      Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int func_index);

  // This function reads the content of a function table entry and returns it
  // through the output parameters.
  static void GetFunctionTableEntry(
      Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
      bool* is_valid, bool* is_null,
      MaybeHandle<WasmTrustedInstanceData>* instance_data, int* function_index,
      MaybeDirectHandle<WasmJSFunction>* maybe_js_function);

 private:
  // {entry} is either {Null} or a {WasmInternalFunction}.
  static void SetFunctionTableEntry(Isolate* isolate,
                                    DirectHandle<WasmTableObject> table,
                                    int entry_index,
                                    DirectHandle<Object> entry);

  TQ_OBJECT_CONSTRUCTORS(WasmTableObject)
};

// Representation of a WebAssembly.Memory JavaScript-level object.
class WasmMemoryObject
    : public TorqueGeneratedWasmMemoryObject<WasmMemoryObject, JSObject> {
 public:
  class BodyDescriptor;

  DECL_ACCESSORS(instances, Tagged<WeakArrayList>)

  // Add a use of this memory object to the given instance. This updates the
  // internal weak list of instances that use this memory and also updates the
  // fields of the instance to reference this memory's buffer.
  // Note that we update both the non-shared and shared (if any) parts of the
  // instance for faster access to shared memory.
  V8_EXPORT_PRIVATE static void UseInInstance(
      Isolate* isolate, DirectHandle<WasmMemoryObject> memory,
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
      int memory_index_in_instance);
  inline bool has_maximum_pages();

  inline bool is_memory64() const;

  V8_EXPORT_PRIVATE static Handle<WasmMemoryObject> New(
      Isolate* isolate, Handle<JSArrayBuffer> buffer, int maximum,
      wasm::AddressType address_type);

  V8_EXPORT_PRIVATE static MaybeHandle<WasmMemoryObject> New(
      Isolate* isolate, int initial, int maximum, SharedFlag shared,
      wasm::AddressType address_type);

  // Assign a new (grown) buffer to this memory, also updating the shortcut
  // fields of all instances that use this memory.
  void SetNewBuffer(Tagged<JSArrayBuffer> new_buffer);

  V8_EXPORT_PRIVATE static int32_t Grow(Isolate*, Handle<WasmMemoryObject>,
                                        uint32_t pages);

  static constexpr int kNoMaximum = -1;

  TQ_OBJECT_CONSTRUCTORS(WasmMemoryObject)
};

// Representation of a WebAssembly.Global JavaScript-level object.
class WasmGlobalObject
    : public TorqueGeneratedWasmGlobalObject<WasmGlobalObject, JSObject> {
 public:
  class BodyDescriptor;

  DECL_ACCESSORS(untagged_buffer, Tagged<JSArrayBuffer>)
  DECL_ACCESSORS(tagged_buffer, Tagged<FixedArray>)
  DECL_PRIMITIVE_ACCESSORS(type, wasm::ValueType)
  DECL_TRUSTED_POINTER_ACCESSORS(trusted_data, WasmTrustedInstanceData)

  // Dispatched behavior.
  DECL_PRINTER(WasmGlobalObject)

  V8_EXPORT_PRIVATE static MaybeHandle<WasmGlobalObject> New(
      Isolate* isolate, Handle<WasmTrustedInstanceData> instance_object,
      MaybeHandle<JSArrayBuffer> maybe_untagged_buffer,
      MaybeHandle<FixedArray> maybe_tagged_buffer, wasm::ValueType type,
      int32_t offset, bool is_mutable);

  inline int type_size() const;

  inline int32_t GetI32();
  inline int64_t GetI64();
  inline float GetF32();
  inline double GetF64();
  inline uint8_t* GetS128RawBytes();
  inline Handle<Object> GetRef();

  inline void SetI32(int32_t value);
  inline void SetI64(int64_t value);
  inline void SetF32(float value);
  inline void SetF64(double value);
  // {value} must be an object in Wasm representation.
  inline void SetRef(DirectHandle<Object> value);

 private:
  // This function returns the address of the global's data in the
  // JSArrayBuffer. This buffer may be allocated on-heap, in which case it may
  // not have a fixed address.
  inline Address address() const;

  TQ_OBJECT_CONSTRUCTORS(WasmGlobalObject)
};

// The trusted part of a WebAssembly instance.
// This object lives in trusted space and is never modified from user space.
class V8_EXPORT_PRIVATE WasmTrustedInstanceData : public ExposedTrustedObject {
 public:
  DECL_OPTIONAL_ACCESSORS(instance_object, Tagged<WasmInstanceObject>)
  DECL_ACCESSORS(native_context, Tagged<Context>)
  DECL_ACCESSORS(memory_objects, Tagged<FixedArray>)
#if V8_ENABLE_DRUMBRAKE
  DECL_OPTIONAL_ACCESSORS(interpreter_object, Tagged<Tuple2>)
#endif  // V8_ENABLE_DRUMBRAKE
  DECL_OPTIONAL_ACCESSORS(untagged_globals_buffer, Tagged<JSArrayBuffer>)
  DECL_OPTIONAL_ACCESSORS(tagged_globals_buffer, Tagged<FixedArray>)
  DECL_OPTIONAL_ACCESSORS(imported_mutable_globals_buffers, Tagged<FixedArray>)
  // tables: FixedArray of WasmTableObject.
  DECL_OPTIONAL_ACCESSORS(tables, Tagged<FixedArray>)
  DECL_PROTECTED_POINTER_ACCESSORS(dispatch_table_for_imports,
                                   WasmDispatchTable)
  DECL_ACCESSORS(imported_mutable_globals, Tagged<FixedAddressArray>)
#if V8_ENABLE_DRUMBRAKE
  // Points to an array that contains the function index for each imported Wasm
  // function. This is required to call imported functions from the Wasm
  // interpreter.
  DECL_ACCESSORS(imported_function_indices, Tagged<FixedInt32Array>)
#endif  // V8_ENABLE_DRUMBRAKE
  DECL_PROTECTED_POINTER_ACCESSORS(shared_part, WasmTrustedInstanceData)
  DECL_PROTECTED_POINTER_ACCESSORS(dispatch_table0, WasmDispatchTable)
  DECL_PROTECTED_POINTER_ACCESSORS(dispatch_tables, ProtectedFixedArray)
  DECL_OPTIONAL_ACCESSORS(tags_table, Tagged<FixedArray>)
  DECL_ACCESSORS(func_refs, Tagged<FixedArray>)
  DECL_ACCESSORS(managed_object_maps, Tagged<FixedArray>)
  DECL_ACCESSORS(feedback_vectors, Tagged<FixedArray>)
  DECL_ACCESSORS(well_known_imports, Tagged<FixedArray>)
  DECL_PRIMITIVE_ACCESSORS(memory0_start, uint8_t*)
  DECL_PRIMITIVE_ACCESSORS(memory0_size, size_t)
  DECL_PROTECTED_POINTER_ACCESSORS(managed_native_module,
                                   TrustedManaged<wasm::NativeModule>)
  DECL_PRIMITIVE_ACCESSORS(new_allocation_limit_address, Address*)
  DECL_PRIMITIVE_ACCESSORS(new_allocation_top_address, Address*)
  DECL_PRIMITIVE_ACCESSORS(old_allocation_limit_address, Address*)
  DECL_PRIMITIVE_ACCESSORS(old_allocation_top_address, Address*)
  DECL_PRIMITIVE_ACCESSORS(globals_start, uint8_t*)
  DECL_PRIMITIVE_ACCESSORS(jump_table_start, Address)
  DECL_PRIMITIVE_ACCESSORS(hook_on_function_call_address, Address)
  DECL_PRIMITIVE_ACCESSORS(tiering_budget_array, std::atomic<uint32_t>*)
  DECL_PROTECTED_POINTER_ACCESSORS(memory_bases_and_sizes,
                                   TrustedFixedAddressArray)
  DECL_ACCESSORS(data_segment_starts, Tagged<FixedAddressArray>)
  DECL_ACCESSORS(data_segment_sizes, Tagged<FixedUInt32Array>)
  DECL_ACCESSORS(element_segments, Tagged<FixedArray>)
  DECL_PRIMITIVE_ACCESSORS(break_on_entry, uint8_t)
  DECL_PRIMITIVE_ACCESSORS(stress_deopt_counter_address, Address)

  // Clear uninitialized padding space. This ensures that the snapshot content
  // is deterministic. Depending on the V8 build mode there could be no padding.
  inline void clear_padding();

  inline Tagged<WasmMemoryObject> memory_object(int memory_index) const;
  inline uint8_t* memory_base(int memory_index) const;
  inline size_t memory_size(int memory_index) const;

  inline wasm::NativeModule* native_module() const;

  inline Tagged<WasmModuleObject> module_object() const;
  inline const wasm::WasmModule* module() const;

  // Dispatched behavior.
  DECL_PRINTER(WasmTrustedInstanceData)
  DECL_VERIFIER(WasmTrustedInstanceData)

// Layout description.
#define FIELD_LIST(V)                                                     \
  /* Often-accessed fields go first to minimize generated code size. */   \
  /* Less than system pointer sized fields come first. */                 \
  V(kProtectedDispatchTable0Offset, kTaggedSize)                          \
  V(kProtectedDispatchTableForImportsOffset, kTaggedSize)                 \
  V(kImportedMutableGlobalsOffset, kTaggedSize)                           \
  IF_WASM_DRUMBRAKE(V, kImportedFunctionIndicesOffset, kTaggedSize)       \
  /* Optional padding to align system pointer size fields */              \
  V(kOptionalPaddingOffset, POINTER_SIZE_PADDING(kOptionalPaddingOffset)) \
  V(kMemory0StartOffset, kSystemPointerSize)                              \
  V(kMemory0SizeOffset, kSizetSize)                                       \
  V(kGlobalsStartOffset, kSystemPointerSize)                              \
  V(kJumpTableStartOffset, kSystemPointerSize)                            \
  /* End of often-accessed fields. */                                     \
  /* Continue with system pointer size fields to maintain alignment. */   \
  V(kNewAllocationLimitAddressOffset, kSystemPointerSize)                 \
  V(kNewAllocationTopAddressOffset, kSystemPointerSize)                   \
  V(kOldAllocationLimitAddressOffset, kSystemPointerSize)                 \
  V(kOldAllocationTopAddressOffset, kSystemPointerSize)                   \
  V(kHookOnFunctionCallAddressOffset, kSystemPointerSize)                 \
  V(kTieringBudgetArrayOffset, kSystemPointerSize)                        \
  V(kStressDeoptCounterOffset, kSystemPointerSize)                        \
  /* Less than system pointer size aligned fields are below. */           \
  V(kProtectedMemoryBasesAndSizesOffset, kTaggedSize)                     \
  V(kDataSegmentStartsOffset, kTaggedSize)                                \
  V(kDataSegmentSizesOffset, kTaggedSize)                                 \
  V(kElementSegmentsOffset, kTaggedSize)                                  \
  V(kInstanceObjectOffset, kTaggedSize)                                   \
  V(kNativeContextOffset, kTaggedSize)                                    \
  V(kProtectedSharedPartOffset, kTaggedSize)                              \
  V(kMemoryObjectsOffset, kTaggedSize)                                    \
  V(kUntaggedGlobalsBufferOffset, kTaggedSize)                            \
  V(kTaggedGlobalsBufferOffset, kTaggedSize)                              \
  V(kImportedMutableGlobalsBuffersOffset, kTaggedSize)                    \
  IF_WASM_DRUMBRAKE(V, kInterpreterObjectOffset, kTaggedSize)             \
  V(kTablesOffset, kTaggedSize)                                           \
  V(kProtectedDispatchTablesOffset, kTaggedSize)                          \
  V(kTagsTableOffset, kTaggedSize)                                        \
  V(kFuncRefsOffset, kTaggedSize)                                         \
  V(kManagedObjectMapsOffset, kTaggedSize)                                \
  V(kFeedbackVectorsOffset, kTaggedSize)                                  \
  V(kWellKnownImportsOffset, kTaggedSize)                                 \
  V(kProtectedManagedNativeModuleOffset, kTaggedSize)                     \
  V(kBreakOnEntryOffset, kUInt8Size)                                      \
  /* More padding to make the header pointer-size aligned */              \
  V(kHeaderPaddingOffset, POINTER_SIZE_PADDING(kHeaderPaddingOffset))     \
  V(kHeaderSize, 0)                                                       \
  V(kSize, 0)

  DEFINE_FIELD_OFFSET_CONSTANTS(ExposedTrustedObject::kHeaderSize, FIELD_LIST)
  static_assert(IsAligned(kHeaderSize, kTaggedSize));
  // TODO(ishell, v8:8875): When pointer compression is enabled 8-byte size
  // fields (external pointers, doubles and BigInt data) are only kTaggedSize
  // aligned so checking for alignments of fields bigger than kTaggedSize
  // doesn't make sense until v8:8875 is fixed.
#define ASSERT_FIELD_ALIGNED(offset, size)                                 \
  static_assert(size == 0 || IsAligned(offset, size) ||                    \
                (COMPRESS_POINTERS_BOOL && (size == kSystemPointerSize) && \
                 IsAligned(offset, kTaggedSize)));
  FIELD_LIST(ASSERT_FIELD_ALIGNED)
#undef ASSERT_FIELD_ALIGNED
#undef FIELD_LIST

  // GC support: List all tagged fields and protected fields.
  // V(offset, name)
#define WASM_TAGGED_INSTANCE_DATA_FIELDS(V)                                   \
  V(kInstanceObjectOffset, "instance_object")                                 \
  V(kNativeContextOffset, "native_context")                                   \
  V(kMemoryObjectsOffset, "memory_objects")                                   \
  V(kUntaggedGlobalsBufferOffset, "untagged_globals_buffer")                  \
  V(kTaggedGlobalsBufferOffset, "tagged_globals_buffer")                      \
  V(kImportedMutableGlobalsBuffersOffset, "imported_mutable_globals_buffers") \
  IF_WASM_DRUMBRAKE(V, kInterpreterObjectOffset, "interpreter_object")        \
  V(kTablesOffset, "tables")                                                  \
  V(kTagsTableOffset, "tags_table")                                           \
  V(kFuncRefsOffset, "func_refs")                                             \
  V(kManagedObjectMapsOffset, "managed_object_maps")                          \
  V(kFeedbackVectorsOffset, "feedback_vectors")                               \
  V(kWellKnownImportsOffset, "well_known_imports")                            \
  V(kImportedMutableGlobalsOffset, "imported_mutable_globals")                \
  IF_WASM_DRUMBRAKE(V, kImportedFunctionIndicesOffset,                        \
                    "imported_function_indices")                              \
  V(kDataSegmentStartsOffset, "data_segment_starts")                          \
  V(kDataSegmentSizesOffset, "data_segment_sizes")                            \
  V(kElementSegmentsOffset, "element_segments")
#define WASM_PROTECTED_INSTANCE_DATA_FIELDS(V)                             \
  V(kProtectedSharedPartOffset, "shared_part")                             \
  V(kProtectedMemoryBasesAndSizesOffset, "memory_bases_and_sizes")         \
  V(kProtectedDispatchTable0Offset, "dispatch_table0")                     \
  V(kProtectedDispatchTablesOffset, "dispatch_tables")                     \
  V(kProtectedDispatchTableForImportsOffset, "dispatch_table_for_imports") \
  V(kProtectedManagedNativeModuleOffset, "managed_native_module")

#define WASM_INSTANCE_FIELD_OFFSET(offset, _) offset,
#define WASM_INSTANCE_FIELD_NAME(_, name) name,

#if V8_ENABLE_DRUMBRAKE
  static constexpr size_t kWasmInterpreterAdditionalFields = 2;
#else
  static constexpr size_t kWasmInterpreterAdditionalFields = 0;
#endif  // V8_ENABLE_DRUMBRAKE
  static constexpr size_t kTaggedFieldsCount =
      16 + kWasmInterpreterAdditionalFields;

  static constexpr std::array<uint16_t, kTaggedFieldsCount>
      kTaggedFieldOffsets = {
          WASM_TAGGED_INSTANCE_DATA_FIELDS(WASM_INSTANCE_FIELD_OFFSET)};
  static constexpr std::array<const char*, kTaggedFieldsCount>
      kTaggedFieldNames = {
          WASM_TAGGED_INSTANCE_DATA_FIELDS(WASM_INSTANCE_FIELD_NAME)};
  static constexpr std::array<uint16_t, 6> kProtectedFieldOffsets = {
      WASM_PROTECTED_INSTANCE_DATA_FIELDS(WASM_INSTANCE_FIELD_OFFSET)};
  static constexpr std::array<const char*, 6> kProtectedFieldNames = {
      WASM_PROTECTED_INSTANCE_DATA_FIELDS(WASM_INSTANCE_FIELD_NAME)};

#undef WASM_INSTANCE_FIELD_OFFSET
#undef WASM_INSTANCE_FIELD_NAME
#undef WASM_TAGGED_INSTANCE_DATA_FIELDS
#undef WASM_PROTECTED_INSTANCE_DATA_FIELDS

  static_assert(kTaggedFieldOffsets.size() == kTaggedFieldNames.size(),
                "every tagged field offset needs a name");
  static_assert(kProtectedFieldOffsets.size() == kProtectedFieldNames.size(),
                "every protected field offset needs a name");

  static void EnsureMinimumDispatchTableSize(
      Isolate* isolate,
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int table_index, int minimum_size);

  void SetRawMemory(int memory_index, uint8_t* mem_start, size_t mem_size);

#if V8_ENABLE_DRUMBRAKE
  // Get the interpreter object associated with the given wasm object.
  // If no interpreter object exists yet, it is created automatically.
  static Handle<Tuple2> GetOrCreateInterpreterObject(
      Handle<WasmInstanceObject>);
  static Handle<Tuple2> GetInterpreterObject(Handle<WasmInstanceObject>);
#endif  // V8_ENABLE_DRUMBRAKE

  static Handle<WasmTrustedInstanceData> New(Isolate*,
                                             DirectHandle<WasmModuleObject>,
                                             bool shared);

  WasmCodePointer GetCallTarget(uint32_t func_index);

  inline Tagged<WasmDispatchTable> dispatch_table(uint32_t table_index);
  inline bool has_dispatch_table(uint32_t table_index);

  // Copies table entries. Returns {false} if the ranges are out-of-bounds.
  static bool CopyTableEntries(
      Isolate* isolate,
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      uint32_t table_dst_index, uint32_t table_src_index, uint32_t dst,
      uint32_t src, uint32_t count) V8_WARN_UNUSED_RESULT;

  // Loads a range of elements from element segment into a table.
  // Returns the empty {Optional} if the operation succeeds, or an {Optional}
  // with the error {MessageTemplate} if it fails.
  static std::optional<MessageTemplate> InitTableEntries(
      Isolate* isolate, Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
      uint32_t table_index, uint32_t segment_index, uint32_t dst, uint32_t src,
      uint32_t count) V8_WARN_UNUSED_RESULT;

  class BodyDescriptor;

  // Read a WasmFuncRef from the func_refs FixedArray. Returns true on success
  // and writes the result in the output parameter. Returns false if no func_ref
  // exists yet for this function. Use GetOrCreateFuncRef to always create one.
  bool try_get_func_ref(int index, Tagged<WasmFuncRef>* result);

  // Acquires the {WasmFuncRef} for a given {function_index} from the cache of
  // the given {trusted_instance_data}, or creates a new {WasmInternalFunction}
  // and {WasmFuncRef} if it does not exist yet. The new objects are added to
  // the cache of the {trusted_instance_data} immediately.
  static Handle<WasmFuncRef> GetOrCreateFuncRef(
      Isolate* isolate,
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int function_index);

  // Imports a constructed {WasmJSFunction} into the indirect function table of
  // this instance. Note that this might trigger wrapper compilation, since a
  // {WasmJSFunction} is instance-independent and just wraps a JS callable.
  static void ImportWasmJSFunctionIntoTable(
      Isolate* isolate,
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int table_index, int entry_index,
      DirectHandle<WasmJSFunction> js_function);

  // Get a raw pointer to the location where the given global is stored.
  // {global} must not be a reference type.
  uint8_t* GetGlobalStorage(const wasm::WasmGlobal&);

  // Get the FixedArray and the index in that FixedArray for the given global,
  // which must be a reference type.
  std::pair<Tagged<FixedArray>, uint32_t> GetGlobalBufferAndIndex(
      const wasm::WasmGlobal&);

  // Get the value of a global.
  wasm::WasmValue GetGlobalValue(Isolate*, const wasm::WasmGlobal&);

  OBJECT_CONSTRUCTORS(WasmTrustedInstanceData, ExposedTrustedObject);

 private:
  void InitDataSegmentArrays(const wasm::NativeModule*);
};

// Representation of a WebAssembly.Instance JavaScript-level object.
// This is mostly a wrapper around the WasmTrustedInstanceData, plus any
// user-set properties.
class WasmInstanceObject
    : public TorqueGeneratedWasmInstanceObject<WasmInstanceObject, JSObject> {
 public:
  DECL_TRUSTED_POINTER_ACCESSORS(trusted_data, WasmTrustedInstanceData)

  inline const wasm::WasmModule* module() const;

  class BodyDescriptor;

  DECL_PRINTER(WasmInstanceObject)
  TQ_OBJECT_CONSTRUCTORS(WasmInstanceObject)
};

// Representation of WebAssembly.Exception JavaScript-level object.
class WasmTagObject
    : public TorqueGeneratedWasmTagObject<WasmTagObject, JSObject> {
 public:
  class BodyDescriptor;

  // Checks whether the given {sig} has the same parameter types as the
  // serialized signature stored within this tag object.
  bool MatchesSignature(wasm::CanonicalTypeIndex expected_index);

  static Handle<WasmTagObject> New(
      Isolate* isolate, const wasm::FunctionSig* sig,
      wasm::CanonicalTypeIndex type_index, DirectHandle<HeapObject> tag,
      DirectHandle<WasmTrustedInstanceData> instance);

  DECL_TRUSTED_POINTER_ACCESSORS(trusted_data, WasmTrustedInstanceData)

  TQ_OBJECT_CONSTRUCTORS(WasmTagObject)
};

// Off-heap data object owned by a WasmDispatchTable. Currently used for
// tracking referenced WasmToJS wrappers (shared per process), so we can
// decrement their refcounts when the WasmDispatchTable is freed.
class WasmDispatchTableData {
 public:
  WasmDispatchTableData() = default;
  ~WasmDispatchTableData();

 private:
  friend class WasmDispatchTable;

  // We need to map {call_target} to a WasmCode* if it is an import wrapper.
  // Doing that via the wrapper cache has overhead, so as a performance
  // optimization, callers can avoid that lookup by providing additional
  // information: a non-nullptr WasmCode* if they have it; and otherwise
  // {contextual_knowledge == kNo} when they know for sure that {call_target}
  // does not belong to a wrapper.
  // Passing {wrapper_if_known == nullptr} and {contextual_knowledge == kMaybe}
  // is always safe, but might be slower.
  void Add(WasmCodePointer call_target, wasm::WasmCode* wrapper_if_known,
           IsAWrapper contextual_knowledge);
  void Remove(WasmCodePointer call_target);

  // The {wrappers_} data structure serves two purposes:
  // 1) It maps call targets to wrappers.
  //    When an entry's value is {nullptr}, that means we know for sure it's not
  //    a wrapper. This duplicates information we could get from
  //    {wasm::GetWasmImportWrapperCache()->FindWrapper}, but doesn't require
  //    any locks, which is important for applications with many worker threads.
  // 2) It keeps track of all wrappers that are currently installed in this
  //    table, and how often they are stored in this table. The first time a
```