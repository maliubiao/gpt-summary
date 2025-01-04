Response: Let's break down the thought process for analyzing this Torque file.

1. **Identify the Core Purpose:** The filename `wasm-objects.tq` strongly suggests this file defines the data structures representing WebAssembly objects within the V8 JavaScript engine. The `.tq` extension confirms it's a Torque file, used for defining the internal structure and types of V8's objects.

2. **Scan for Key Terms and Patterns:** Look for recurring keywords and structures:
    * `extern class`: This is the most frequent keyword, indicating definitions of classes that represent different Wasm entities.
    * `extends`:  Shows inheritance relationships between classes.
    * `TrustedPointer`, `ProtectedPointer`, `RawPtr`: These indicate low-level memory management and access within V8. "Trusted" and "Protected" likely denote security considerations.
    * `Smi`, `HeapObject`, `JSObject`, `FixedArray`: These are fundamental V8 object types. `Smi` for small integers, `HeapObject` for objects allocated on the heap, `JSObject` for JavaScript objects (Wasm objects often inherit from this), and `FixedArray` for fixed-size arrays.
    * `wasm::...`: This namespace clearly indicates WebAssembly-specific types.
    * `macro`:  Indicates utility functions for accessing members of the defined classes.
    * `@if(...)`: Shows conditional compilation based on V8 build flags.
    * `canonical_sig`, `function_index`, `call_target`: These relate to function representation and execution.
    * `module_object`, `instance_object`, `exports_object`, `imports`: These are high-level concepts in WebAssembly module structure.
    * `table`, `memory`, `global`, `tag`: These are the core Wasm entities that can be instantiated.

3. **Group Classes by Functionality:**  As you scan, start grouping classes based on their apparent purpose. This is an iterative process. Initial groupings might be broad, and you'll refine them as you understand more.

    * **Module & Instance:** `WasmModuleObject`, `WasmInstanceObject`, `WasmTrustedInstanceData`, `WasmImportData`, `AsmWasmData`. These seem related to the overall structure and execution context of a Wasm module.
    * **Functions:** `WasmInternalFunction`, `WasmFuncRef`, `WasmFunctionData`, `WasmExportedFunctionData`, `WasmJSFunctionData`, `WasmCapiFunctionData`. These are clearly about representing Wasm functions and their interactions with JavaScript.
    * **Tables, Memory, Globals, Tags:** `WasmTableObject`, `WasmMemoryObject`, `WasmGlobalObject`, `WasmTagObject`. These are the fundamental data structures within a Wasm module's instance.
    * **Execution & Control Flow:** `WasmResumeData`, `WasmContinuationObject`, `WasmSuspenderObject`, `WasmFastApiCallData`. These appear to be related to managing the execution of Wasm code, potentially including asynchronous operations.
    * **Types:** `WasmTypeInfo`, `WasmNull`, `WasmObject`, `WasmStruct`, `WasmArray`. These define the type system within Wasm in V8.

4. **Analyze Individual Class Members:** Once you have a rough grouping, examine the members (fields) of each class. Try to understand:

    * **What information does this field store?** (e.g., `module_object` stores a reference to the `WasmModuleObject`).
    * **What is the data type of the field?** (e.g., `TrustedPointer<WasmTrustedInstanceData>`). This provides clues about how the data is managed.
    * **How might this field be used?** (e.g., `call_target` likely points to the actual executable code of a Wasm function).
    * **Are there any macros associated with the field?** Macros like `.implicit_arg` suggest a specific way to access the field.

5. **Look for Relationships and Connections:** Pay attention to how classes refer to each other.

    * `WasmInstanceObject` has a `module_object`.
    * `WasmFunctionData` has a `func_ref` of type `WasmFuncRef`.
    * `WasmFuncRef` has a `trusted_internal` of type `WasmInternalFunction`.

    These relationships reveal the underlying structure and how different Wasm entities are linked.

6. **Connect to JavaScript (If Applicable):** The prompt specifically asks about the relationship to JavaScript. Look for:

    * Classes inheriting from `JSObject`.
    * Fields with types like `JSFunction`, `JSArrayBuffer`, `JSPromise`.
    * Classes representing interactions between Wasm and JS, such as `WasmImportData`, `WasmExportedFunctionData`, `WasmJSFunctionData`.
    * Think about how these structures facilitate calling Wasm from JS and vice versa.

7. **Summarize and Synthesize:** Based on the analysis, start formulating a summary of the file's purpose. Organize the information logically, grouping related concepts together.

8. **Provide JavaScript Examples:** For the JavaScript examples, focus on illustrating how the Wasm objects defined in the Torque file manifest in JavaScript. Consider:

    * Creating Wasm modules and instances.
    * Accessing exports (functions, memories, tables, globals).
    * Importing JavaScript functions into Wasm.
    * Creating `WebAssembly.Function` (which corresponds to `WasmJSFunctionData`).
    * Working with `WebAssembly.Table`, `WebAssembly.Memory`, `WebAssembly.Global`.
    * (More advanced) Using function references (`funcref`).

9. **Review and Refine:**  Read through your summary and examples. Ensure they are accurate, clear, and address all aspects of the prompt. Double-check your understanding of the Torque syntax and the meaning of the different data types. For example, initially, I might not fully grasp the difference between `TrustedPointer` and `ProtectedPointer`, but further reading or context clues within the file would help clarify that.

By following these steps, you can systematically analyze a complex Torque file like `wasm-objects.tq` and derive a comprehensive understanding of its functionality and its relationship to JavaScript. The process involves pattern recognition, understanding data structures, identifying relationships, and connecting internal representations to external (JavaScript) behavior.
这个 Torque 源代码文件 `v8/src/wasm/wasm-objects.tq` 的主要功能是**定义了 V8 引擎中用于表示 WebAssembly (Wasm) 各种对象的数据结构和类型**。它详细描述了 Wasm 模块、实例、函数、表、内存、全局变量、标签、异常等在 V8 内部的表示形式。

这些定义使用 Torque 语言，这是一种 V8 内部使用的类型定义语言，用于生成高效的 C++ 代码来操作这些对象。

以下是对文件中定义的主要类型的归纳：

**核心 Wasm 结构：**

* **`WasmInstanceObject`:** 代表一个 Wasm 模块的实例。它包含了指向可信实例数据 (`trusted_data`)、模块对象 (`module_object`) 和导出对象 (`exports_object`) 的指针。
* **`WasmModuleObject`:**  代表已编译的 Wasm 模块。它包含指向本地模块 (`managed_native_module`) 和脚本 (`script`) 的信息。
* **`WasmTrustedInstanceData`:**  存储与特定 Wasm 实例相关的可信数据，例如线性内存的基地址等。这个类是 `ExposedTrustedObject` 的子类，意味着它可以被 V8 的其他可信部分直接访问。
* **`WasmImportData`:**  用于表示 Wasm 导入的信息，在调用非 Wasm 导入时传递。它包含了实例数据、原生上下文、可调用对象、挂起状态、预算、调用来源和签名。

**函数相关：**

* **`WasmInternalFunction`:**  Wasm 内部表示的函数引用，包含隐式参数（通常是实例数据或导入数据）、外部 JS 函数表示、函数索引、调用目标代码指针等。
* **`WasmFuncRef`:**  代表 Wasm 函数引用的堆对象，它包含指向 `WasmInternalFunction` 的可信指针。
* **`WasmFunctionData`:**  表示 Wasm 函数的元数据，与 `SharedFunctionInfo` 关联。它包含包装器代码、函数引用、Promise 相关的标志等。
* **`WasmExportedFunctionData`:**  表示导出的 Wasm 函数的元数据，继承自 `WasmFunctionData`。它额外包含了导出函数的实例数据、函数索引、包装器预算、规范类型索引等。
* **`WasmJSFunctionData`:**  表示由 JavaScript 创建的 `WebAssembly.Function` 实例的元数据。
* **`WasmCapiFunctionData`:**  表示通过 C API 创建的 Wasm 函数的元数据。

**表、内存、全局变量：**

* **`WasmTableObject`:**  代表 Wasm 的表。它包含表条目的数组、当前长度、最大长度、使用情况信息、元素类型等。
* **`WasmMemoryObject`:**  代表 Wasm 的线性内存。它包含 `JSArrayBuffer`、最大页数、关联的实例列表等。
* **`WasmGlobalObject`:**  代表 Wasm 的全局变量。它包含指向实例数据的指针、用于存储值的缓冲区（标记或未标记）、偏移量、类型和可变性信息。

**异常和控制流：**

* **`WasmExceptionTag`:**  代表 Wasm 异常标签。
* **`WasmExceptionPackage`:**  代表 Wasm 异常包。
* **`WasmResumeData`:**  用于 Wasm 异步操作的恢复数据。
* **`WasmContinuationObject`:**  用于表示 Wasm 的 continuation 对象，用于支持异步操作。
* **`WasmSuspenderObject`:**  用于管理 Wasm 的挂起状态。
* **`WasmSuspendingObject`:** 代表一个挂起的 Wasm 对象。

**其他类型：**

* **`PodArrayOfWasmValueType`:** 表示 `wasm::ValueType` 的普通数组。
* **`ManagedWasmNativeModule`:**  表示由 V8 管理的 `wasm::NativeModule`。
* **`TrustedManagedWasmJSFunctionOffheapData`:**  表示 `WasmJSFunctionData` 的可信非堆数据。
* **`RawFunctionSigPtr`:**  表示指向 `wasm::CanonicalSig` 的原始指针。
* **`AddressType`:**  枚举，表示地址的类型 (kI32, kI64)。
* **`WasmCodePointer`:**  表示 Wasm 代码的指针。
* **`WasmFastApiCallData`:** 用于存储快速 API 调用的数据。
* **`WasmTagObject`:** 代表 Wasm 的标签。
* **`AsmWasmData`:**  用于 asm.js 到 Wasm 的数据。
* **`WasmTypeInfo`:**  存储 Wasm 类型信息。
* **`WasmObject`:**  抽象类，作为 `WasmStruct` 和 `WasmArray` 的基类。
* **`WasmStruct`:**  代表 Wasm 的结构体。
* **`WasmArray`:**  代表 Wasm 的数组。
* **`WasmStringViewIter`:**  用于迭代 Wasm 字符串视图。
* **`WasmNull`:**  代表 Wasm 的 null 值。
* **`WasmExportedFunction`:**  类型别名，表示导出的 Wasm 函数。

**与 JavaScript 的关系和示例：**

这些 Torque 定义直接关系到 JavaScript 中 `WebAssembly` API 的实现。当你使用 JavaScript 操作 Wasm 模块和实例时，V8 引擎内部会创建和操作这些在 `wasm-objects.tq` 中定义的 C++ 对象。

以下是一些 JavaScript 示例，说明了这些 Torque 类型在幕后的作用：

1. **`WasmInstanceObject` 和 `WasmModuleObject`：**

   ```javascript
   const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // 省略 Wasm 字节码
   const wasmModule = new WebAssembly.Module(wasmCode); // 创建 WasmModuleObject
   const wasmInstance = new WebAssembly.Instance(wasmModule); // 创建 WasmInstanceObject
   ```

   在 V8 内部，`WebAssembly.Module` 的调用会创建一个 `WasmModuleObject` 来表示编译后的模块，而 `WebAssembly.Instance` 的调用会创建一个 `WasmInstanceObject` 来表示该模块的一个实例。

2. **`WasmTableObject`：**

   ```javascript
   const table = new WebAssembly.Table({ initial: 2, element: 'anyfunc' }); // 创建 WasmTableObject
   ```

   这会在 V8 内部创建一个 `WasmTableObject`，其 `entries` 数组会存储函数引用。

3. **`WasmMemoryObject`：**

   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1 }); // 创建 WasmMemoryObject
   const buffer = memory.buffer; // 对应 WasmMemoryObject 的 array_buffer
   ```

   `WebAssembly.Memory` 会创建一个 `WasmMemoryObject`，其内部包含一个 `JSArrayBuffer` 来表示线性内存。

4. **`WasmGlobalObject`：**

   ```javascript
   const global = new WebAssembly.Global({ value: "i32", mutable: true }, 42); // 创建 WasmGlobalObject
   console.log(global.value); // 访问 WasmGlobalObject 存储的值
   global.value = 100;      // 修改 WasmGlobalObject 存储的值
   ```

   `WebAssembly.Global` 会创建一个 `WasmGlobalObject`，其值会存储在 `untagged_buffer` 或 `tagged_buffer` 中。

5. **`WasmExportedFunction` 和 `WasmFunctionData`：**

   ```javascript
   const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // 省略 Wasm 字节码
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule, {});
   const exportedFunction = wasmInstance.exports.myFunction; // 获取导出的函数

   if (typeof exportedFunction === 'function') {
     exportedFunction(10); // 调用导出的函数
   }
   ```

   当从 Wasm 实例的 `exports` 对象访问导出的函数时，JavaScript 会得到一个 `WasmExportedFunction`，它在 V8 内部关联着 `WasmFunctionData` 等信息。

6. **`WasmFuncRef` 和函数引用 (funcref)：**

   ```javascript
   const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule, {});

   // 假设 Wasm 模块导出了一个表和一个函数
   const table = wasmInstance.exports.myTable;
   const func = wasmInstance.exports.myFunc;

   table.set(0, func); // 将导出的 Wasm 函数放入表中，这里涉及到 WasmFuncRef
   const funcRefFromTable = table.get(0); // 从表中获取函数引用 (WasmFuncRef)
   ```

   当 Wasm 代码使用 `funcref` 类型时，V8 会使用 `WasmFuncRef` 来表示函数引用。

总而言之，`wasm-objects.tq` 文件是理解 V8 如何在内部表示和管理 WebAssembly 对象的关键。它定义了 V8 执行 Wasm 代码和与 JavaScript 互操作所需的基础数据结构。理解这些定义有助于深入了解 V8 的 Wasm 实现细节。

Prompt: 
```
这是目录为v8/src/wasm/wasm-objects.tq的一个v8 torque源代码， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```