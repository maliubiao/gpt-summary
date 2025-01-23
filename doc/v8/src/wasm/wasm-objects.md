Response: Let's break down the thought process for analyzing this Torque file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality and, if related to JavaScript, to provide JavaScript examples. This means identifying the core concepts being defined and how they might be surfaced in JavaScript's WebAssembly API.

2. **Identify the File Type and Location:** The file `v8/src/wasm/wasm-objects.tq` and the `.tq` extension immediately tell us this is a Torque file within the V8 project's WebAssembly implementation. Torque is V8's language for defining object layouts and generating C++ code for interacting with the V8 heap. This gives us a high-level context: this file describes the structure of WebAssembly-related objects within the V8 JavaScript engine.

3. **Scan for Keywords and Structure:**  Look for common Torque keywords and structural elements.
    * `type`:  Defines new types, often aliases or specialized versions of existing types. This is crucial for understanding the basic building blocks.
    * `extern enum`: Defines enums, often mapping to C++ enums.
    * `extern class`: Defines the layout of objects on the V8 heap. These are the most important declarations. The `extends` keyword indicates inheritance.
    * `extern operator '.name' macro`: Defines macros that provide access to fields within objects, sometimes with added logic or type checking.
    * `@if`/`@ifnot`: Conditional compilation based on V8 build flags. Note these, but don't dwell on them initially.
    * Comments (`//`): Provide context and explanations. Pay attention to introductory comments like the copyright and the mention of `wasm::FunctionSig` and `wasm::AddressType`.

4. **Group Related Definitions:** As you scan, group related definitions together conceptually. For example, notice the cluster of definitions related to function calls: `WasmInternalFunction`, `WasmFuncRef`, `WasmFunctionData`, `WasmExportedFunctionData`, `WasmJSFunctionData`, `WasmCapiFunctionData`. This suggests a focus on how WebAssembly functions are represented and called.

5. **Focus on Key Classes:**  The `extern class` definitions are the core of the file. For each class, identify:
    * **Purpose:** What does this class represent in the context of WebAssembly? Look at the class name and the names of its fields.
    * **Key Fields:** What are the most important pieces of data stored in this object? Try to understand the meaning of the field names. For instance, `trusted_data`, `module_object`, `exports_object` in `WasmInstanceObject` clearly relate to a WebAssembly instance.
    * **Relationships:** How does this class relate to other classes defined in the file?  Look for fields that are other custom types defined in the file. For example, `WasmInstanceObject` contains a `WasmModuleObject`.

6. **Infer Functionality from Class Structure:**  Based on the identified classes and their fields, start to infer the overall functionality. For instance:
    * `WasmInstanceObject` likely represents a WebAssembly instance in the JavaScript API.
    * The function-related classes (`WasmInternalFunction`, etc.) describe how WebAssembly functions are managed, including their signatures, call targets, and relationships to JavaScript functions.
    * `WasmTableObject`, `WasmMemoryObject`, and `WasmGlobalObject` clearly correspond to the respective WebAssembly concepts.

7. **Connect to JavaScript API (if applicable):** Now, think about how these internal representations map to the JavaScript WebAssembly API.
    * `WasmInstanceObject` directly corresponds to the `WebAssembly.Instance` object.
    * `WasmModuleObject` corresponds to `WebAssembly.Module`.
    * `WasmTableObject`, `WasmMemoryObject`, and `WasmGlobalObject` map to `WebAssembly.Table`, `WebAssembly.Memory`, and `WebAssembly.Global`, respectively.
    * The function-related classes describe the underlying mechanism for calling WebAssembly functions from JavaScript and vice versa. Think about how `instance.exports.myFunc()` works.

8. **Craft JavaScript Examples:**  Based on the connections made in the previous step, create simple JavaScript examples that demonstrate the concepts. Focus on the user-visible API and how it relates to the internal structures. For instance, accessing an exported function (`instance.exports.myFunc`) relates to the `exports_object` in `WasmInstanceObject` and the underlying function data structures.

9. **Refine and Organize the Summary:**  Organize the findings into a clear and concise summary. Group related classes together and explain their roles. Use clear language and avoid overly technical jargon where possible. Start with a high-level overview and then delve into more specific details.

10. **Review and Iterate:** Review the summary and examples for accuracy and clarity. Are there any ambiguities? Are the examples easy to understand?  Could the explanation be improved?  For instance, initially, I might have just listed the classes without explaining their relationships. A better summary would explicitly state how `WasmInstanceObject` contains `WasmModuleObject` and `exports_object`.

Self-Correction Example during the process:  Initially, I might focus too much on the low-level details of `RawPtr` and the conditional compilation flags. Realizing the goal is a functional summary, I would then shift focus to the higher-level object representations and their JavaScript counterparts. Also, I might initially struggle to articulate the role of `WasmInternalFunction`. By revisiting the comments and field names (`call_target`, `implicit_arg`), I'd realize it's a key internal representation for function references.
这个 Torque 源代码文件 `v8/src/wasm/wasm-objects.tq` 定义了 V8 引擎中用于表示 WebAssembly (Wasm) 相关对象的结构和布局。Torque 是一种 V8 内部使用的语言，用于生成高效的 C++ 代码，它允许以一种类型安全的方式定义 V8 堆上的对象。

**功能归纳:**

这个文件的主要功能是定义了 V8 中用于表示各种 WebAssembly 概念的对象的内存布局和类型信息。这些对象是 V8 执行 WebAssembly 代码和与 JavaScript 交互的基础。它涵盖了以下关键的 Wasm 概念：

1. **模块 (Module):**  `WasmModuleObject` 代表一个已编译的 WebAssembly 模块。
2. **实例 (Instance):** `WasmInstanceObject` 代表一个 WebAssembly 模块的实例化，包含其内存、表和全局变量。
3. **函数 (Function):**
   - `WasmInternalFunction`: 代表 Wasm 内部的函数引用，包含调用目标和隐式参数信息。
   - `WasmFuncRef`:  代表堆上的 Wasm 函数引用。
   - `WasmFunctionData`:  存储关于 Wasm 函数的元数据，例如包装器代码和函数引用。
   - `WasmExportedFunctionData`:  专门用于表示导出的 Wasm 函数。
   - `WasmJSFunctionData`:  表示由 JavaScript 创建的 `WebAssembly.Function` 对象。
   - `WasmCapiFunctionData`: 表示通过 C API 导入的函数。
4. **内存 (Memory):** `WasmMemoryObject` 代表 WebAssembly 的线性内存。
5. **表 (Table):** `WasmTableObject` 代表 WebAssembly 的表，用于存储函数引用或其他引用类型。
6. **全局变量 (Global):** `WasmGlobalObject` 代表 WebAssembly 的全局变量。
7. **异常 (Exception):** `WasmExceptionTag` 和 `WasmExceptionPackage` 用于处理 WebAssembly 的异常。
8. **函数引用 (Function References):**  `WasmFuncRef` 和 `WasmInternalFunction` 以及相关的 `WasmFunctionData` 等类型定义了 Wasm 中函数引用的内部表示方式。
9. **导入 (Import):** `WasmImportData` 存储关于导入的信息，用于在 Wasm 调用非 Wasm 代码时传递必要的数据。
10. **调用约定 (Call Convention):**  涉及到函数签名 (`RawFunctionSigPtr`) 以及快速 API 调用的数据结构 (`WasmFastApiCallData`).
11. **异步操作 (Async Operations):** `WasmResumeData`, `WasmContinuationObject`, `WasmSuspenderObject` 用于支持 WebAssembly 的异步操作，例如挂起和恢复。
12. **类型信息 (Type Information):** `WasmTypeInfo` 用于存储关于 Wasm 结构体和数组类型的信息。
13. **字符串视图 (String View):** `WasmStringViewIter` 用于迭代 WebAssembly 的字符串视图。
14. **空引用 (Null Reference):** `WasmNull` 代表 Wasm 中的空引用。

**与 JavaScript 功能的关系及示例:**

这个文件定义的结构直接支撑了 JavaScript 中 WebAssembly API 的实现。当你使用 JavaScript 的 `WebAssembly` API 时，V8 引擎会在内部创建和操作这里定义的这些对象。

以下是一些 JavaScript 示例，说明了这些对象在幕后是如何工作的：

**1. `WebAssembly.Module` 和 `WasmModuleObject`:**

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
  0x03, 0x02, 0x01, 0x00,
  0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
]);
const wasmModule = new WebAssembly.Module(wasmCode);
// 在 V8 内部，wasmModule 对应于一个 WasmModuleObject 实例。
```

**2. `WebAssembly.Instance` 和 `WasmInstanceObject`:**

```javascript
const wasmInstance = new WebAssembly.Instance(wasmModule);
// wasmInstance 对应于一个 WasmInstanceObject 实例，它关联了 wasmModule。
// WasmInstanceObject 包含了对模块的引用 (module_object) 和导出的对象 (exports_object)。
```

**3. 访问导出的函数和 `WasmExportedFunction` / `WasmFunctionData`:**

```javascript
const addFunction = wasmInstance.exports.add;
// addFunction 是一个 JavaScript 函数，但在 V8 内部，它关联到一个 WasmExportedFunction 对象。
// 这个 WasmExportedFunction 对象又关联到一个 WasmFunctionData 对象，
// 其中包含了调用实际 Wasm 代码所需的 wrapper_code 和其他信息。
const result = addFunction(5, 3); // 调用导出的 Wasm 函数
```

**4. `WebAssembly.Memory` 和 `WasmMemoryObject`:**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const importObject = { env: { memory: memory } };
const wasmInstanceWithMemory = new WebAssembly.Instance(wasmModule, importObject);
// 如果 Wasm 模块导入了内存，那么 importObject.env.memory 对应于一个 WasmMemoryObject。
// WasmMemoryObject 包含了 ArrayBuffer (array_buffer) 和内存的大小等信息。
```

**5. `WebAssembly.Table` 和 `WasmTableObject`:**

```javascript
const table = new WebAssembly.Table({ initial: 2, element: 'funcref' });
const importObjectWithTable = { env: { table: table } };
const wasmInstanceWithTable = new WebAssembly.Instance(wasmModule, importObjectWithTable);
// importObject.env.table 对应于一个 WasmTableObject。
// WasmTableObject 存储函数引用 (WasmFuncRef 或其他类型的引用)。
```

**6. `WebAssembly.Global` 和 `WasmGlobalObject`:**

```javascript
const global = new WebAssembly.Global({ value: "i32", mutable: true }, 10);
const importObjectWithGlobal = { env: { global: global } };
const wasmInstanceWithGlobal = new WebAssembly.Instance(wasmModule, importObjectWithGlobal);
// importObject.env.global 对应于一个 WasmGlobalObject。
// WasmGlobalObject 存储全局变量的值和类型信息。
```

**7. `WebAssembly.Function` 和 `WasmJSFunctionData`:**

```javascript
const jsFunction = new WebAssembly.Function({ parameters: [], results: [] }, function() {
  console.log("Hello from JS!");
});
// jsFunction 对应于一个 WasmJSFunction 对象，其数据存储在 WasmJSFunctionData 中。
```

总而言之，`wasm-objects.tq` 是 V8 引擎中 WebAssembly 功能的核心定义文件，它定义了用于在 JavaScript 中表示和操作 WebAssembly 代码的各种内部数据结构。理解这个文件的内容有助于深入理解 V8 如何实现 WebAssembly。

### 提示词
```
这是目录为v8/src/wasm/wasm-objects.tq的一个v8 torque源代码， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// For wasm::FunctionSig.
#include "src/wasm/value-type.h"
// For wasm::AddressType.
#include "src/wasm/wasm-module.h"

@useParentTypeChecker
type PodArrayOfWasmValueType extends ByteArray
    constexpr 'PodArray<wasm::ValueType>';
@useParentTypeChecker
type ManagedWasmNativeModule extends Foreign
    constexpr 'Managed<wasm::NativeModule>';
@useParentTypeChecker
type TrustedManagedWasmJSFunctionOffheapData extends TrustedForeign
    constexpr 'TrustedManaged<WasmJSFunctionData::OffheapData>';

type RawFunctionSigPtr extends RawPtr constexpr 'const wasm::CanonicalSig*';

extern enum AddressType extends uint8 constexpr 'wasm::AddressType' {
  kI32,
  kI64
}

@if(V8_ENABLE_WASM_CODE_POINTER_TABLE) type WasmCodePointer = uint32;
@ifnot(V8_ENABLE_WASM_CODE_POINTER_TABLE) type WasmCodePointer = RawPtr;

// Trusted instance data, exposed via WasmInstanceObject::trusted_data.
extern class WasmTrustedInstanceData extends ExposedTrustedObject;

extern class WasmInstanceObject extends JSObject {
  trusted_data: TrustedPointer<WasmTrustedInstanceData>;
  module_object: WasmModuleObject;
  exports_object: JSObject;
}

// The WasmImportData is passed to non-wasm imports in place of the
// WasmTrustedInstanceData. It is used in import wrappers (wasm-to-*) to load
// needed information, and is used during wrapper tiering to know which
// call site to patch (see the `call_origin` field).
extern class WasmImportData extends TrustedObject {
  // The instance data is used to load memory start/size for fast API calls, and
  // for tier-up of wasm-to-js wrappers.
  // Use the '.instance_data' macro to read this from torque code.
  protected_instance_data: ProtectedPointer<WasmTrustedInstanceData>;
  native_context: NativeContext;
  callable: JSReceiver|Undefined;
  suspend: Smi;  // Boolean.
  wrapper_budget: Smi;
  // `call_origin` is being used to identify which place to patch on wrapper
  // tier-up.
  // - negative Smi: import index (-index - 1)
  // - positive Smi: table index in same instance (index + 1)
  // - tuple<WasmInstanceObject, Smi>: table index in other instance (index + 1)
  // - WasmFuncRef: a func ref
  call_origin: Smi|WasmFuncRef|Tuple2;
  // The signature is needed for the generic wasm-to-js wrapper.
  sig: RawFunctionSigPtr;
}

extern operator '.instance_data' macro LoadInstanceDataFromWasmImportData(
    WasmImportData): WasmTrustedInstanceData|Smi;

class WasmFastApiCallData extends HeapObject {
  signature: HeapObject;
  callback_data: Object;
  cached_map: Weak<Map>|Null;
}

// This is the representation that is used internally by wasm to represent
// function references. It is "exposed" via the WasmFuncRef.
extern class WasmInternalFunction extends ExposedTrustedObject {
  // This is the implicit first argument that must be passed along in the
  // "instance" register when calling the given function. It is either the
  // target instance data (for wasm functions), or a WasmImportData object (for
  // non-wasm imports). For imported functions, this value equals the respective
  // entry in the module's dispatch_table_for_imports.
  // Torque code should use the '.implicit_arg' macro to access the value.
  protected_implicit_arg:
      ProtectedPointer<WasmTrustedInstanceData|WasmImportData>;
  // The external (JS) representation of this function reference.
  external: JSFunction|Undefined;
  // For exported Wasm functions: the function index in the defining module;
  // {protected_implicit_arg} is the {WasmTrustedInstanceData} corresponding
  // to this module.
  // For imported JS functions: the function index in the importing module;
  // {protected_implicit_arg} is a {WasmImportData} describing this module.
  // For WasmJSFunctions and WasmCapiFunctions: -1.
  function_index: Smi;
  // The call target, stored as raw pointer in this trusted object.
  call_target: WasmCodePointer;
  @if(WASM_CODE_POINTER_NEEDS_PADDING) optional_padding: uint32;
  @ifnot(WASM_CODE_POINTER_NEEDS_PADDING) optional_padding: void;

  // The signature hash. See signature-hashing.h for background.
  // The value stored here must be in sync with {call_target}!
  // Ideally we'd type this as "uint64", but Torque doesn't support that,
  // and we only enable the sandbox when uintptr == uint64 anyway.
  @if(V8_ENABLE_SANDBOX) signature_hash: uintptr;
}

extern operator '.implicit_arg' macro LoadImplicitArgFromWasmInternalFunction(
    WasmInternalFunction): WasmTrustedInstanceData|WasmImportData;

// WasmFuncRef is the type of function references. They are stored on-heap and
// link to a WasmInternalFunction which contains the actual information.
extern class WasmFuncRef extends HeapObject {
  // Note: Torque code uses the '.internal' macro below to access the reference.
  trusted_internal: TrustedPointer<WasmInternalFunction>;
}

extern operator '.internal' macro LoadWasmInternalFunctionFromFuncRef(
    WasmFuncRef): WasmInternalFunction;

// Exposed via SharedFunctionInfo::trusted_function_data.
extern class WasmFunctionData extends ExposedTrustedObject {
  // Used for calling this function from JavaScript.
  wrapper_code: TrustedPointer<Code>;
  // The function reference for this function object. This is used when
  // converting a JS function back to the wasm-side func ref.
  func_ref: WasmFuncRef;
  // Encode the {promising} and {suspending} flags in a single smi.
  js_promise_flags: Smi;
  // Trusted-to-trusted pointer, to ensure that the pair of WasmFunctionData
  // and WasmInternalFunction remains in an overall consistent state.
  protected_internal: ProtectedPointer<WasmInternalFunction>;
}

extern operator '.internal' macro LoadWasmInternalFunctionFromFunctionData(
    WasmFunctionData): WasmInternalFunction;

extern class WasmExportedFunctionData extends WasmFunctionData {
  // This is the instance that exported the function (which in case of
  // imported and re-exported functions is different from the instance
  // where the function is defined).
  protected_instance_data: ProtectedPointer<WasmTrustedInstanceData>;
  function_index: Smi;
  // Contains a Smi; boxed so that generated code can update the value.
  wrapper_budget: Cell;
  canonical_type_index: Smi;

  // {packed_args_size} and {c_wrapper_code} are for fast calling from C++.
  // The contract is that they are lazily populated, and either both will be
  // present or neither.
  packed_args_size: Smi;
  c_wrapper_code: TrustedPointer<Code>;

  sig: RawFunctionSigPtr;
}

extern operator '.instance_data' macro
    LoadWasmTrustedInstanceDataFromWasmExportedFunctionData(
        WasmExportedFunctionData): WasmTrustedInstanceData;

extern class WasmJSFunctionData extends WasmFunctionData {
  canonical_sig_index: Smi;
  protected_offheap_data:
      ProtectedPointer<TrustedManagedWasmJSFunctionOffheapData>;
}

extern class WasmCapiFunctionData extends WasmFunctionData {
  // TODO(jkummerow): Move {canonical_sig_index} into {WasmFunctionData}.
  canonical_sig_index: Smi;
  embedder_data: Foreign;  // Managed<wasm::FuncData>
  sig: RawFunctionSigPtr;
}

extern class WasmResumeData extends HeapObject {
  suspender: WasmSuspenderObject;
  on_resume: Smi;  // See wasm::OnResume enum.
}

extern class WasmContinuationObject extends HeapObject {
  parent: WasmContinuationObject|Undefined;
  stack: ExternalPointer;
  jmpbuf: ExternalPointer;  // Direct access to the stack's jump buffer.
}

extern class WasmSuspenderObject extends HeapObject {
  continuation: WasmContinuationObject|Undefined;
  parent: WasmSuspenderObject|Undefined;
  promise: JSPromise;
  resume: JSObject|Undefined;
  reject: JSObject|Undefined;
  state: Smi;  // 0: Inactive, 1: Active, 2: Suspended.
}

extern class WasmExceptionTag extends Struct {
  // Note that this index is only useful for debugging purposes and it is not
  // unique across modules. The GC however does not allow objects without at
  // least one field, hence this also serves as a padding field for now.
  index: Smi;
}

extern class WasmExceptionPackage extends JSObject;

extern class WasmModuleObject extends JSObject {
  managed_native_module: ManagedWasmNativeModule;
  script: Script;
}

extern class WasmDispatchTable extends TrustedObject;

extern class WasmTableObject extends JSObject {
  // The entries array is at least as big as {current_length()}, but might be
  // bigger to make future growth more efficient.
  // If this is a function table, each element is either
  //   - a WasmFuncRef (Wasm function added from Wasm),
  //   - a WasmExportedFunction (exported Wasm function added from JS),
  //   - a WasmJSFunction (WebAssembly.Function created from JS), or
  //   - a Tuple2 (placeholder for lazy initialization), holding a
  //     WasmInstanceObject and Smi for the function index.
  entries: FixedArray;
  current_length: Smi;
  // The declared maximum. Undefined if no maximum was declared.
  // If {address_type == kI32} this stores a Smi or HeapNumber, otherwise a
  // BigInt. Note that the value can in any case be bigger than
  // {wasm::kV8MaxWasmTableSize}.
  maximum_length: Smi|HeapNumber|BigInt|Undefined;
  // The uses field stores an array of <WasmInstanceObject, index> pairs so we
  // can update the instance's dispatch table when the table grows.
  uses: FixedArray;
  raw_type: Smi;
  // The instance in which this WasmTableObject is defined.
  // This field is undefined if the table is defined outside any Wasm module,
  // i.e., through the JS API (WebAssembly.Table).
  trusted_data: TrustedPointer<WasmTrustedInstanceData>;
  address_type: AddressType;
  // TODO(clemensb): Support fixed-sized arrays in torque.
  padding_for_address_type_0: uint8;
  padding_for_address_type_1: uint16;
  @if(TAGGED_SIZE_8_BYTES) padding_for_address_type_2: uint32;
}

extern class WasmMemoryObject extends JSObject {
  array_buffer: JSArrayBuffer;
  maximum_pages: Smi;
  instances: WeakArrayList;
  address_type: AddressType;
  // TODO(clemensb): Support fixed-sized arrays in torque.
  padding_for_address_type_0: uint8;
  padding_for_address_type_1: uint16;
  @if(TAGGED_SIZE_8_BYTES) padding_for_address_type_2: uint32;
}

extern class WasmGlobalObject extends JSObject {
  // The instance in which this WasmGlobalObject is defined.
  // This field is undefined if the global is defined outside any Wasm module,
  // i.e., through the JS API (WebAssembly.Global).
  trusted_data: TrustedPointer<WasmTrustedInstanceData>;
  untagged_buffer: JSArrayBuffer|Undefined;
  tagged_buffer: FixedArray|Undefined;
  offset: Smi;
  raw_type: Smi;
  // TODO(14034): If we encode mutability in raw_type, turn this into a boolean
  // accessor.
  is_mutable: Smi;
}

extern class WasmTagObject extends JSObject {
  serialized_signature: PodArrayOfWasmValueType;
  tag: HeapObject;
  canonical_type_index: Smi;
  trusted_data: TrustedPointer<WasmTrustedInstanceData>;
}

type WasmExportedFunction extends JSFunction;

extern class AsmWasmData extends Struct {
  managed_native_module: ManagedWasmNativeModule;
  uses_bitset: HeapNumber;
}

extern class WasmTypeInfo extends HeapObject {
  // We must make sure that the StructType/ArrayType, which is allocated in
  // the WasmModule's "signature_zone", stays around as long as there are
  // HeapObjects referring to it. Short term, we simply keep a reference to
  // the trusted instance data, which in turn keeps the entire WasmModule alive.
  // TODO(jkummerow): Possible optimization: manage the "signature_zone"'s
  // lifetime separately by having WasmModule refer to it via std::shared_ptr,
  // and introduce a new link from here to just that zone using a Managed<...>.
  // Details: https://bit.ly/2UxD4hW
  native_type: ExternalPointer;
  module_type_index: uint32;
  @if(TAGGED_SIZE_8_BYTES) optional_padding: uint32;
  @ifnot(TAGGED_SIZE_8_BYTES) optional_padding: void;
  // Is undefined for WasmExternalFunctions referring to WasmJSFunctions.
  trusted_data: TrustedPointer<WasmTrustedInstanceData>;
  const supertypes_length: Smi;
  supertypes[supertypes_length]: Object;
}

extern operator '.native_type_ptr' macro LoadWasmTypeInfoNativeTypePtr(
    WasmTypeInfo): RawPtr;

// WasmObject corresponds to data ref types which are WasmStruct and WasmArray.
@abstract
extern class WasmObject extends JSReceiver {}

@highestInstanceTypeWithinParentClassRange
extern class WasmStruct extends WasmObject {}

@lowestInstanceTypeWithinParentClassRange
extern class WasmArray extends WasmObject {
  length: uint32;

  @if(TAGGED_SIZE_8_BYTES) optional_padding: uint32;
  @ifnot(TAGGED_SIZE_8_BYTES) optional_padding: void;
}

class WasmStringViewIter extends HeapObject {
  string: String;
  offset: uint32;  // Index into string.

  @if(TAGGED_SIZE_8_BYTES) optional_padding: uint32;
  @ifnot(TAGGED_SIZE_8_BYTES) optional_padding: void;
}

extern class WasmNull extends HeapObject {}

extern macro WasmNullConstant(): WasmNull;
const kWasmNull: WasmNull = WasmNullConstant();

extern class WasmSuspendingObject extends JSObject {
  callable: JSReceiver;
}
```