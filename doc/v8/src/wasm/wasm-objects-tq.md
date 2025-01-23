Response:
Let's break down the thought process for analyzing the provided Torque file and answering the request.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the `wasm-objects.tq` file within the V8 JavaScript engine's WebAssembly implementation. Key aspects to identify are:

* **Purpose:** What are these objects used for in the WebAssembly context?
* **Torque Nature:** Recognize that `.tq` indicates a Torque file, a V8-specific language for defining object layouts and generating C++ code.
* **JavaScript Relation:** Connect the defined structures to their counterparts or behaviors in JavaScript when interacting with WebAssembly.
* **Code Logic/Data Flow:**  Infer how these objects are used and interact based on their members and relationships.
* **Common Errors:** Identify potential pitfalls for developers using the JavaScript WebAssembly API that might relate to these internal structures.

**2. Analyzing the File Structure (Top-Down):**

* **Headers and Imports:** The initial `#include` lines provide context. They indicate dependencies on `wasm/value-type.h` and `wasm/wasm-module.h`, confirming this file is deeply involved in WebAssembly type representation and module management.
* **Torque Type Definitions (`type ... extends ...`):**  These are the fundamental building blocks. Each `type` declaration defines an alias or a new type, often inheriting from a base type. The `constexpr` keyword suggests compile-time information related to these types. The `@useParentTypeChecker` likely relates to type safety and verification in Torque.
* **Torque Extern Definitions (`extern ...`):**  These are crucial. They declare classes, enums, and operators that are *defined elsewhere* (likely in C++). Torque uses these declarations to generate code that interacts with the C++ implementation. Pay close attention to the members of these external classes. The types of members (e.g., `TrustedPointer`, `ProtectedPointer`, `Smi`, `HeapObject`) provide valuable clues about memory management, security, and data representation.
* **Torque Class Definitions (`class ... extends ...`):** These define the layout and properties of objects managed by the JavaScript heap. They list the fields (members) and their types.
* **Torque Macros and Constants (`extern operator ... macro`, `extern macro ...`, `const ...`):**  These provide shorthand or predefined values for use within the Torque code. They often represent common operations or special values.
* **Abstract and Instance Type Hints (`@abstract`, `@highestInstanceTypeWithinParentClassRange`, `@lowestInstanceTypeWithinParentClassRange`):** These are Torque-specific annotations that help the compiler and potentially the runtime with type information and optimization.

**3. Identifying Key Concepts and Relationships:**

As you go through the declarations, start grouping related concepts:

* **Instances and Modules:**  `WasmInstanceObject`, `WasmModuleObject`, `WasmTrustedInstanceData`. These are fundamental to the lifecycle and execution of a WebAssembly module.
* **Function Calls:** `WasmInternalFunction`, `WasmFuncRef`, `WasmFunctionData`, `WasmExportedFunctionData`, `WasmImportData`. These are central to how functions are represented and called, both within WebAssembly and between JavaScript and WebAssembly.
* **Memory Management:** `WasmMemoryObject`, `JSArrayBuffer`. Essential for understanding how WebAssembly linear memory is represented and accessed.
* **Tables:** `WasmTableObject`. Important for indirect function calls and element segments.
* **Globals:** `WasmGlobalObject`. Represents mutable and immutable global variables.
* **Exceptions:** `WasmExceptionTag`, `WasmExceptionPackage`. Relate to the WebAssembly exception handling proposal.
* **Continuations and Suspension:** `WasmContinuationObject`, `WasmSuspenderObject`, `WasmResumeData`. Related to asynchronous operations and the upcoming continuation proposal.
* **Types:** `WasmTypeInfo`. Represents struct and array types in the type proposal.
* **Null Reference:** `WasmNull`. Represents the null value for reference types.

**4. Connecting to JavaScript:**

For each key concept, think about its corresponding JavaScript API or behavior:

* `WasmInstanceObject` ->  `WebAssembly.Instance`
* `WasmModuleObject` -> `WebAssembly.Module`
* `WasmMemoryObject` -> `WebAssembly.Memory`
* `WasmTableObject` -> `WebAssembly.Table`
* `WasmGlobalObject` -> `WebAssembly.Global`
* `WasmFuncRef` and Function Data -> How JavaScript calls WebAssembly functions and how WebAssembly functions can be passed around.
* `WasmExceptionTag` and `WasmExceptionPackage` -> The `catch` clause of the `try...catch` block when dealing with WebAssembly exceptions.
* Continuations/Suspension -> The ongoing work on asynchronous WebAssembly integration.
* `WasmStruct` and `WasmArray` -> The emerging "reference types" proposal and its interaction with JavaScript.

**5. Inferring Code Logic and Data Flow:**

Based on the member names and types, reason about how the data flows:

* `WasmInstanceObject` holds a reference to `WasmModuleObject` and exports.
* `WasmInternalFunction` is the core representation of a callable, with pointers to code and implicit arguments.
* `WasmFuncRef` is a handle to a `WasmInternalFunction`.
* The various function data objects (`WasmFunctionData`, `WasmExportedFunctionData`, `WasmJSFunctionData`, `WasmCapiFunctionData`) store metadata about functions depending on their origin and type.
* `WasmImportData` acts as a bridge for calling JavaScript functions from WebAssembly.

**6. Identifying Potential Programming Errors:**

Think about common mistakes developers make with the WebAssembly JavaScript API and relate them to the internal structures:

* Incorrectly accessing memory bounds (relates to `WasmMemoryObject` and `JSArrayBuffer`).
* Calling functions with the wrong number or types of arguments (relates to function signatures and the various function data structures).
* Trying to modify immutable globals (relates to `WasmGlobalObject`).
* Issues with table access, especially out-of-bounds access (relates to `WasmTableObject`).
* Misunderstanding the lifecycle of instances and modules.

**7. Structuring the Answer:**

Organize the findings into clear categories as requested:

* **Functionality:** A high-level overview of the file's purpose.
* **Torque Nature:** Explain what `.tq` files are.
* **JavaScript Relationship:** Provide concrete JavaScript examples.
* **Code Logic/Data Flow:** Illustrate with simple scenarios and hypothetical inputs/outputs.
* **Common Errors:** Give practical examples of developer mistakes.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus too much on individual class definitions.
* **Correction:**  Shift focus to the *relationships* between the classes and how they collectively represent WebAssembly concepts.
* **Initial thought:**  Overcomplicate the explanation of Torque.
* **Correction:** Keep the Torque explanation concise and focused on its role in defining object layouts.
* **Initial thought:**  Only provide very technical details.
* **Correction:**  Balance technical details with more accessible explanations and relatable JavaScript examples.

By following this structured approach, you can systematically analyze the Torque file, understand its purpose, and generate a comprehensive and helpful answer.
`v8/src/wasm/wasm-objects.tq` 是一个 V8 源代码文件，它使用 Torque 语言定义了在 V8 的 WebAssembly (Wasm) 实现中使用的各种对象的结构和布局。

**功能列举:**

这个文件的主要功能是定义了 V8 中用于表示 WebAssembly 概念的各种对象的类型和布局。这些对象包括：

* **模块 (Module):** `WasmModuleObject` 表示已编译的 WebAssembly 模块。
* **实例 (Instance):** `WasmInstanceObject` 表示 WebAssembly 模块的一个实例化。它包含了模块的内存、表和全局变量的实例。
* **函数 (Function):**
    * `WasmInternalFunction`:  WebAssembly 函数的内部表示，包含执行代码的指针。
    * `WasmFuncRef`:  用于在 WebAssembly 中传递函数引用的类型。
    * `WasmFunctionData`:  与 JavaScript 可调用 WebAssembly 函数关联的元数据。
    * `WasmExportedFunctionData`:  关于从 WebAssembly 导出的函数的额外信息。
    * `WasmJSFunctionData`:  关于作为 `WebAssembly.Function` 从 JavaScript 创建的函数的元数据。
    * `WasmCapiFunctionData`:  关于通过 C API 导入的函数的元数据。
* **内存 (Memory):** `WasmMemoryObject` 表示 WebAssembly 实例的线性内存。
* **表 (Table):** `WasmTableObject` 表示 WebAssembly 实例的表，用于存储函数引用或其他值。
* **全局变量 (Global):** `WasmGlobalObject` 表示 WebAssembly 实例的全局变量。
* **异常标签 (Exception Tag):** `WasmExceptionTag` 用于表示 WebAssembly 异常处理中的标签。
* **异常包 (Exception Package):** `WasmExceptionPackage` 用于封装抛出的 WebAssembly 异常。
* **函数签名 (Function Signature):** 虽然没有明确的类，但 `RawFunctionSigPtr` 和 `PodArrayOfWasmValueType` 用于表示函数签名。
* **导入数据 (Import Data):** `WasmImportData` 用于向非 WebAssembly 导入提供必要的信息。
* **快速 API 调用数据 (Fast API Call Data):** `WasmFastApiCallData` 用于优化 JavaScript 调用 WebAssembly 函数的场景。
* **延续 (Continuation) 和 暂停 (Suspender):** `WasmContinuationObject`, `WasmSuspenderObject`, `WasmResumeData`, `WasmSuspendingObject` 用于支持 WebAssembly 的异步操作和延续特性。
* **类型信息 (Type Information):** `WasmTypeInfo` 用于表示 WebAssembly 的结构体和数组类型。
* **空引用 (Null Reference):** `WasmNull` 表示 WebAssembly 引用类型的空值。
* **字符串视图迭代器 (String View Iterator):** `WasmStringViewIter` 用于遍历 WebAssembly 的字符串视图。

**Torque 源代码:**

正如你所指出的，以 `.tq` 结尾的文件是 V8 的 Torque 源代码。 Torque 是一种用于描述对象布局和生成高效 C++ 代码的领域特定语言。  它允许 V8 团队以类型安全的方式定义对象，并自动生成用于访问和操作这些对象的 C++ 代码。

**与 JavaScript 的关系及举例:**

这些在 `wasm-objects.tq` 中定义的内部对象直接对应于 JavaScript 中 `WebAssembly` API 中暴露的概念。

* **`WebAssembly.Module`:**  对应于 `WasmModuleObject`。当你使用 `WebAssembly.compile()` 或 `WebAssembly.instantiate()` 编译或实例化 WebAssembly 模块时，V8 内部会创建 `WasmModuleObject` 来表示编译后的代码。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // WebAssembly 字节码
  WebAssembly.compile(source)
    .then(module => {
      // 'module' 在 V8 内部是由 WasmModuleObject 表示的
      console.log(module instanceof WebAssembly.Module); // true
    });
  ```

* **`WebAssembly.Instance`:** 对应于 `WasmInstanceObject`。当你实例化一个 `WebAssembly.Module` 时，V8 会创建一个 `WasmInstanceObject`，其中包含模块的内存、表和导出的实例。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]);
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module))
    .then(instance => {
      // 'instance' 在 V8 内部是由 WasmInstanceObject 表示的
      console.log(instance instanceof WebAssembly.Instance); // true
    });
  ```

* **`WebAssembly.Memory`:** 对应于 `WasmMemoryObject`。如果你的 WebAssembly 模块导入或定义了内存，你可以在 JavaScript 中通过 `instance.exports.memory` 访问它。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // 包含内存定义的 WASM
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module))
    .then(instance => {
      if (instance.exports.memory) {
        // instance.exports.memory 在 V8 内部是由 WasmMemoryObject 表示的
        console.log(instance.exports.memory instanceof WebAssembly.Memory); // true
      }
    });
  ```

* **`WebAssembly.Table`:** 对应于 `WasmTableObject`。类似于内存，你可以通过 `instance.exports` 访问导出的表。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // 包含表定义的 WASM
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module))
    .then(instance => {
      if (instance.exports.myTable) {
        // instance.exports.myTable 在 V8 内部是由 WasmTableObject 表示的
        console.log(instance.exports.myTable instanceof WebAssembly.Table); // true
      }
    });
  ```

* **导出的 WebAssembly 函数:** 对应于 `WasmExportedFunctionData`。当你调用一个导出的 WebAssembly 函数时，V8 会使用 `WasmExportedFunctionData` 中存储的信息来执行该函数。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // 包含导出函数的 WASM
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module))
    .then(instance => {
      if (instance.exports.add) {
        const result = instance.exports.add(5, 3);
        // 调用 instance.exports.add 涉及到使用 WasmExportedFunctionData
        console.log(result); // 输出 WebAssembly 函数的计算结果
      }
    });
  ```

* **`WebAssembly.Global`:** 对应于 `WasmGlobalObject`。JavaScript 可以读取和（如果可变）写入导出的全局变量。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // 包含全局变量定义的 WASM
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module))
    .then(instance => {
      if (instance.exports.myGlobal) {
        // instance.exports.myGlobal 在 V8 内部是由 WasmGlobalObject 表示的
        console.log(instance.exports.myGlobal.value);
        // 如果全局变量是可变的
        // instance.exports.myGlobal.value = 10;
      }
    });
  ```

* **`WebAssembly.Function`:**  对应于 `WasmJSFunctionData`。  允许在 JavaScript 中创建可以传递给 WebAssembly 的函数。

  ```javascript
  const wasmFunc = new WebAssembly.Function({ parameters: ['i32', 'i32'], results: ['i32'] },
    function(x, y) { return x + y; }
  );

  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, /* ... 使用 wasmFunc 的导入 ... */]);
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module, { imports: { js: { add: wasmFunc } } }))
    .then(instance => {
      // wasmFunc 在传递给 WebAssembly 时，V8 内部会创建 WasmJSFunctionData
    });
  ```

**代码逻辑推理及假设输入与输出:**

考虑 `WasmInstanceObject` 和 `WasmMemoryObject` 的交互。

**假设输入:**

1. 一个已编译的 WebAssembly 模块，其中定义了一个线性内存，初始大小为 1 页 (64KB)。
2. 使用 `WebAssembly.instantiate()` 实例化该模块。

**代码逻辑推理:**

当 V8 实例化模块时：

1. 创建一个新的 `WasmInstanceObject` 来表示实例。
2. 根据模块的定义，创建一个 `WasmMemoryObject` 来表示线性内存。
3. `WasmInstanceObject` 的某个成员（例如 `trusted_data` 指向的 `WasmTrustedInstanceData` 中的信息）会关联到新创建的 `WasmMemoryObject`。这允许 WebAssembly 代码通过实例访问其线性内存。
4. JavaScript 可以通过 `instance.exports.memory` 获取到这个 `WasmMemoryObject` 的 JavaScript 包装器 (`WebAssembly.Memory`)。

**假设输出:**

1. 一个 `WebAssembly.Instance` 对象在 JavaScript 中创建。
2. `instance.exports.memory` 存在，并且是一个 `WebAssembly.Memory` 实例。
3. 这个 `WebAssembly.Memory` 实例的 `buffer` 属性是一个 `ArrayBuffer`，其 `byteLength` 为 65536 (64KB)。

**涉及用户常见的编程错误:**

* **访问超出内存边界:**  用户经常在 JavaScript 中通过 `WebAssembly.Memory.buffer` 获取 `ArrayBuffer`，然后使用 `Uint8Array` 等视图进行读写。一个常见的错误是访问超出分配的内存大小的索引。虽然 JavaScript 会抛出错误，但在 WebAssembly 内部，这种错误可能导致更严重的问题，如果 V8 没有正确处理，可能会导致安全漏洞。 `WasmMemoryObject` 内部维护了内存的大小信息，用于边界检查。

  ```javascript
  const memory = new WebAssembly.Memory({ initial: 1 });
  const buffer = new Uint8Array(memory.buffer);
  // 错误：尝试访问超出 64KB 的内存
  // buffer[65536] = 10; // JavaScript 会抛出 RangeError
  ```

* **错误的函数签名:** 当 JavaScript 调用 WebAssembly 函数时，如果提供的参数类型或数量与 WebAssembly 函数的签名不匹配，V8 会抛出 `TypeError`。 `WasmFunctionData` 和相关的结构体存储了函数的签名信息，用于在调用时进行类型检查。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, /* ... 定义一个接受 i32 参数的函数 ... */]);
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module))
    .then(instance => {
      // 假设 instance.exports.myFunc 接受一个 i32 参数
      // 错误：传递了字符串参数
      // instance.exports.myFunc("hello"); // JavaScript 会抛出 TypeError
    });
  ```

* **尝试修改不可变的全局变量:** 如果 WebAssembly 模块导出了一个不可变的全局变量，并且 JavaScript 尝试修改它，V8 会抛出 `TypeError`。 `WasmGlobalObject` 中存储了全局变量的可变性信息。

  ```javascript
  const source = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, /* ... 定义一个不可变的全局变量 ... */]);
  WebAssembly.compile(source)
    .then(module => WebAssembly.instantiate(module))
    .then(instance => {
      if (instance.exports.myImmutableGlobal) {
        // 错误：尝试修改不可变的全局变量
        // instance.exports.myImmutableGlobal.value = 10; // JavaScript 会抛出 TypeError
      }
    });
  ```

总之，`v8/src/wasm/wasm-objects.tq` 定义了 V8 内部如何表示 WebAssembly 的各种概念，这些定义直接影响了 JavaScript 中 `WebAssembly` API 的行为和用户与 WebAssembly 代码的交互方式。理解这些内部结构有助于深入理解 V8 的 WebAssembly 实现和调试相关问题。

### 提示词
```
这是目录为v8/src/wasm/wasm-objects.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-objects.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
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