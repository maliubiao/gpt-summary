Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `v8/src/wasm/module-instantiate.cc`. This immediately tells us it's related to WebAssembly instantiation within the V8 engine. "instantiate" is a key term, indicating the process of creating a running instance of a Wasm module.
* **Copyright and License:** Standard V8 header, confirming the source and licensing.
* **Includes:** A long list of `#include` directives. These are crucial for understanding dependencies and the functionalities being used. I'd quickly scan these, noting important areas like:
    * `src/wasm/*`:  Clearly Wasm-related.
    * `src/objects/*`:  Dealing with V8's object model (maps, arrays, etc.).
    * `src/codegen/*`, `src/compiler/*`: Compilation and code generation.
    * `src/api/*`: Interaction with the V8 API.
* **Namespace:** `v8::internal::wasm`. Confirms it's internal V8 code, specifically for Wasm.

**2. High-Level Functionality Deduction (Skimming for Keywords and Patterns):**

* **`CreateStructMap`, `CreateArrayMap`:**  These strongly suggest the creation of V8 `Map` objects specifically for Wasm structs and arrays. The parameters (`Isolate`, `WasmModule`, `ModuleTypeIndex`, etc.) reinforce this.
* **`CreateMapForType`:**  This looks like a higher-level function that orchestrates the creation of maps for various Wasm types. The recursion and handling of supertypes are interesting.
* **`IsSupportedWasmFastApiFunction`, `ResolveBoundJSFastApiFunction`:** These functions are clearly about optimizing calls between Wasm and JavaScript using a "fast API". Keywords like "API", "signature", and checks on `SharedFunctionInfo` point in this direction.
* **`CheckForWellKnownImport`:**  This suggests the identification of specific, commonly used JavaScript functions that can be optimized when imported into Wasm. The `WellKnownImport` enum (though not shown in the snippet) likely holds the different types of optimized imports. The logic around `Function.prototype.call.bind` is a strong indicator of handling specific binding patterns.
* **`ResolvedWasmImport`:** This class seems to encapsulate the result of resolving a Wasm import, determining the kind of call needed (JS function, Wasm function, C API, etc.).
* **`ComputeKind`:**  A method within `ResolvedWasmImport` that determines the type of import call based on the imported callable and its signature.

**3. Detailed Analysis of Key Sections:**

* **Map Creation:** Focus on the details within `CreateStructMap` and `CreateArrayMap`. Notice things like:
    * Setting `instance_type` to `WASM_STRUCT_TYPE` and `WASM_ARRAY_TYPE`.
    * Using `kVariableSizeSentinel` for instance sizes.
    * Setting up `WasmTypeInfo`.
    * Handling extensibility and descriptors.
* **Fast API Functions:**  Read carefully the checks within `IsSupportedWasmFastApiFunction`. Understand the criteria for a JS function to be considered for the fast API: API function, C function count, receiver handling, signature matching (including argument and return types).
* **Well-Known Imports:** Analyze the logic within `CheckForWellKnownImport`. Pay attention to the patterns being matched (e.g., `Function.prototype.call.bind`), the specific built-in IDs being checked, and the conditions for recognizing specific imports (e.g., `kStringPrototypeToLocaleLowerCase`, `kDataViewPrototypeGetBigInt64`).
* **Import Resolution:** Examine the `ResolvedWasmImport` constructor and the `ComputeKind` method. Note how it handles different types of imported callables (JS functions, Wasm functions, C API functions) and the checks performed (signature matching, suspending objects).

**4. Connecting to JavaScript (Conceptual and Example):**

* **Maps:**  Think about how JavaScript objects work and how V8 represents them internally with `Map` objects. The code is essentially creating specialized `Map`s for Wasm's structured data.
* **Fast API:**  Consider the performance implications of calling JavaScript from Wasm. The fast API aims to bypass some of the overhead. Imagine a simple JavaScript function being called frequently from Wasm – the fast API could optimize this.
* **Well-Known Imports:** Think about common JavaScript operations that Wasm modules might need (string manipulation, data view access). The "well-known" part implies that V8 has optimized paths for these. For instance, Wasm might need to convert a number to a string, and `Number.prototype.toString` is a prime candidate for optimization.

**5. Anticipating User Errors and Code Logic:**

* **User Errors:** Think about common mistakes when importing JavaScript functions into Wasm:
    * **Signature mismatch:**  The most likely error. Wasm expects a certain signature, and the provided JS function doesn't match.
    * **Incorrect receiver:**  For methods, the `this` context is crucial. Errors can occur if the receiver isn't handled correctly.
    * **Type errors:** Passing the wrong type of argument (e.g., a string where a number is expected).
* **Code Logic:** Follow the conditional logic in the `if` statements and `switch` statements. Consider different input scenarios and how the code would behave. For example, what happens if a bound function has bound arguments?

**6. Structuring the Summary:**

* **Start with a concise overview.**
* **Break down the functionality into logical categories (Map creation, Fast API, Well-Known Imports, Import Resolution).**
* **Provide details for each category, explaining the purpose of key functions and concepts.**
* **Illustrate with JavaScript examples where applicable.**
* **Include examples of user errors and potential code logic scenarios.**

**Self-Correction/Refinement During Analysis:**

* **"`.tq` Check":** Realize that the file extension check is a simple conditional statement and doesn't require deep analysis of the code itself.
* **Focus on Functionality:**  Avoid getting bogged down in the very low-level details of every line of code. Focus on the *purpose* of the functions and code blocks.
* **Use the Includes:**  Refer back to the `#include` directives if you're unsure about the meaning of a particular type or function.
* **Iterative Understanding:**  It's okay if your initial understanding is incomplete. As you analyze more of the code, your understanding will become more refined. Go back and revise your initial assumptions if needed.

By following this structured approach, combining high-level skimming with detailed analysis of key areas, and constantly relating the code back to its purpose within the V8 engine and its interaction with JavaScript, a comprehensive understanding of the provided source code can be achieved.
好的，让我们来分析一下 `v8/src/wasm/module-instantiate.cc` 这个文件的功能。

**核心功能归纳：WebAssembly 模块的实例化**

这个 C++ 源代码文件 `v8/src/wasm/module-instantiate.cc` 的主要功能是负责 **WebAssembly 模块的实例化**。  实例化是将编译好的 WebAssembly 模块转换成可以在 V8 引擎中运行的实例的过程。  这个过程涉及到连接模块的导入（imports）、创建模块的内存、表（tables）、全局变量（globals），并初始化实例。

更具体地，根据代码片段，我们可以分解出以下几个关键功能点：

1. **创建 WebAssembly 类型的 Map (Maps for Wasm Types):**
   - 提供了 `CreateStructMap` 和 `CreateArrayMap` 函数，用于为 WebAssembly 的结构体 (struct) 和数组 (array) 创建对应的 V8 `Map` 对象。`Map` 在 V8 中用于描述对象的结构和属性。
   - `CreateMapForType` 函数是一个更通用的函数，它根据 WebAssembly 模块中定义的类型 (可以是结构体、数组或函数引用) 创建相应的 `Map`。它还处理了超类型的关系，确保父类型的 Map 在子类型之前创建。
   - 这里创建的 `Map` 对象是 WebAssembly 对象在 V8 中的表示形式，包含了类型信息和布局信息。

2. **处理 WebAssembly 导入 (Handling Wasm Imports):**
   - `IsSupportedWasmFastApiFunction` 和 `ResolveBoundJSFastApiFunction` 看起来是用于优化从 WebAssembly 调用 JavaScript 函数的场景，特别是针对 V8 的 "Fast API" 功能。这允许更高效地调用特定的 JavaScript API 函数。
   - `CheckForWellKnownImport` 函数识别某些特定的、常见的 JavaScript 函数导入模式（例如，绑定了 `Function.prototype.call` 的函数，或者直接导入的内置函数）。V8 可以对这些已知的导入进行优化。
   - `ResolvedWasmImport` 类用于表示已解析的 WebAssembly 导入。它存储了导入的 JavaScript 可调用对象，并确定了调用该导入的最佳方式 (`ComputeKind`)。可能的调用方式包括直接调用 JavaScript 函数、调用另一个 WebAssembly 函数、调用 C++ API 函数等。

3. **与 JavaScript 的交互 (Interaction with JavaScript):**
   - 代码中大量涉及到与 V8 的 JavaScript 对象模型交互，例如 `JSArrayBuffer`，`Map`，`JSFunction` 等。
   - Fast API 和 Well-Known Imports 的机制都是为了提升 WebAssembly 与 JavaScript 之间互操作的性能。

**关于文件扩展名和 Torque：**

如果 `v8/src/wasm/module-instantiate.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**文件。Torque 是 V8 用于定义其内置函数和对象布局的一种领域特定语言。由于这里是 `.cc`，所以它是标准的 C++ 源代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/wasm/module-instantiate.cc` 的功能与 JavaScript 的 WebAssembly API 密切相关，特别是 `WebAssembly.instantiate()` 方法。  这个 C++ 代码是 `WebAssembly.instantiate()` 在 V8 引擎内部的实现部分。

**JavaScript 示例：**

```javascript
// 假设我们有一个编译好的 WebAssembly 模块的字节码
const wasmBytes = new Uint8Array([
  // ... WebAssembly 模块的字节码 ...
]);

WebAssembly.instantiate(wasmBytes)
  .then(result => {
    const wasmInstance = result.instance;
    // wasmInstance 现在是 WebAssembly 模块的实例，
    // 它的创建过程涉及到 `v8/src/wasm/module-instantiate.cc` 中的代码。
    console.log(wasmInstance.exports.add(5, 3)); // 调用导出的函数
  });

// 或者使用导入对象进行实例化：
const importObject = {
  js: {
    log: function(message) {
      console.log("来自 WebAssembly:", message);
    }
  }
};

WebAssembly.instantiate(wasmBytes, importObject)
  .then(result => {
    const wasmInstance = result.instance;
    // 这里 `importObject` 中的 JavaScript 函数的连接和处理，
    // 部分逻辑也会在 `v8/src/wasm/module-instantiate.cc` 中实现。
  });
```

**代码逻辑推理和假设输入/输出：**

假设输入是一个编译好的 WebAssembly 模块的字节码，并且这个模块声明了一个导入的函数 `log`，签名是接受一个 i32 类型的参数。

**假设输入：**

- `wasmBytes`:  包含一个声明了导入函数 `log` 的 WebAssembly 模块的字节码。
- `importObject`:  一个 JavaScript 对象，包含一个名为 `log` 的函数，它接受一个数字参数。

**代码逻辑推理（`CheckForWellKnownImport` 可能涉及）：**

1. 当 `WebAssembly.instantiate(wasmBytes, importObject)` 被调用时，V8 会解析 `wasmBytes` 并识别出需要导入的函数 `log` 及其签名。
2. V8 会在 `importObject` 中查找名为 `js.log` 的属性，并检查它是否是一个 JavaScript 函数。
3. `CheckForWellKnownImport` 或类似的函数可能会被调用，来分析导入的 JavaScript 函数 `log`，看是否符合某些已知的优化模式。在这个简单的例子中，可能不会匹配到特殊的优化。
4. `ResolvedWasmImport` 会被用来表示这个导入，它会记录 `importObject.js.log` 作为可调用的目标。
5. `ComputeKind` 会确定调用 `log` 的方式，因为它是一个标准的 JavaScript 函数，所以会选择相应的调用机制。

**假设输出（部分）：**

- `ResolvedWasmImport` 对象，其中 `callable_` 成员指向 `importObject.js.log` 函数。
- `ComputeKind` 的结果可能是 `ImportCallKind::kJSFunctionArityMatch` (如果参数数量匹配)。

**用户常见的编程错误：**

1. **导入的 JavaScript 函数签名不匹配 WebAssembly 模块的声明。**
   ```javascript
   // WebAssembly 期望导入一个接受 i32 的 log 函数
   const importObjectWithError = {
     js: {
       log: function(message, level) { // 参数数量不匹配
         console.log("来自 WebAssembly:", message, level);
       }
     }
   };

   WebAssembly.instantiate(wasmBytes, importObjectWithError)
     .catch(error => {
       console.error("实例化错误:", error); // 可能会抛出 LinkError
     });
   ```
   V8 在实例化时会检查导入的函数签名是否与 WebAssembly 模块的期望一致。如果不一致，会抛出 `LinkError`。

2. **导入的 JavaScript 函数返回类型与 WebAssembly 模块的期望不符（虽然 JavaScript 没有显式的返回类型声明，但在某些优化场景下可能会有影响）。**

3. **尝试导入不存在的 JavaScript 函数。**
   ```javascript
   const importObjectMissing = {
     // js.log 缺失
   };

   WebAssembly.instantiate(wasmBytes, importObjectMissing)
     .catch(error => {
       console.error("实例化错误:", error); // 可能会抛出 LinkError
     });
   ```
   如果 `importObject` 中缺少 WebAssembly 模块声明的导入，也会导致 `LinkError`。

**总结 `v8/src/wasm/module-instantiate.cc` 的功能（第 1 部分）：**

在提供的代码片段中，`v8/src/wasm/module-instantiate.cc` 的主要功能集中在 **WebAssembly 模块实例化的早期阶段**，特别是以下几个方面：

- **为 WebAssembly 的结构化类型（结构体和数组）创建 V8 内部表示（`Map` 对象）。**
- **处理 WebAssembly 模块的导入，包括识别和解析导入的 JavaScript 函数。**
- **针对特定的 JavaScript 函数导入模式（Fast API 和 Well-Known Imports）进行优化，以提升性能。**
- **确定调用导入函数的最佳方式，并处理可能的类型错误和链接错误。**

这部分代码是 WebAssembly 与 JavaScript 互操作性的关键组成部分，确保了 WebAssembly 模块能够正确地连接到 JavaScript 环境并高效地执行。

### 提示词
```
这是目录为v8/src/wasm/module-instantiate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-instantiate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/module-instantiate.h"

#include "src/api/api-inl.h"
#include "src/asmjs/asm-js.h"
#include "src/base/atomicops.h"
#include "src/codegen/compiler.h"
#include "src/compiler/wasm-compiler.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/metrics.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/descriptor-array-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/torque-defined-classes.h"
#include "src/tracing/trace-event.h"
#include "src/utils/utils.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/constant-expression-interface.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/pgo.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-external-refs.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
#include "src/execution/simulator-base.h"
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

#define TRACE(...)                                          \
  do {                                                      \
    if (v8_flags.trace_wasm_instances) PrintF(__VA_ARGS__); \
  } while (false)

namespace v8::internal::wasm {

namespace {

uint8_t* raw_buffer_ptr(MaybeHandle<JSArrayBuffer> buffer, int offset) {
  return static_cast<uint8_t*>(buffer.ToHandleChecked()->backing_store()) +
         offset;
}

Handle<Map> CreateStructMap(Isolate* isolate, const WasmModule* module,
                            ModuleTypeIndex struct_index,
                            Handle<Map> opt_rtt_parent,
                            DirectHandle<WasmTrustedInstanceData> trusted_data,
                            Handle<WasmInstanceObject> instance) {
  const wasm::StructType* type = module->struct_type(struct_index);
  const int inobject_properties = 0;
  // We have to use the variable size sentinel because the instance size
  // stored directly in a Map is capped at 255 pointer sizes.
  const int map_instance_size = kVariableSizeSentinel;
  const InstanceType instance_type = WASM_STRUCT_TYPE;
  // TODO(jkummerow): If NO_ELEMENTS were supported, we could use that here.
  const ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
  DirectHandle<WasmTypeInfo> type_info = isolate->factory()->NewWasmTypeInfo(
      reinterpret_cast<Address>(type), opt_rtt_parent, trusted_data,
      struct_index);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      instance, instance_type, map_instance_size, elements_kind,
      inobject_properties);
  map->set_wasm_type_info(*type_info);
  map->SetInstanceDescriptors(isolate,
                              *isolate->factory()->empty_descriptor_array(), 0,
                              SKIP_WRITE_BARRIER);
  map->set_is_extensible(false);
  const int real_instance_size = WasmStruct::Size(type);
  WasmStruct::EncodeInstanceSizeInMap(real_instance_size, *map);
  return map;
}

Handle<Map> CreateArrayMap(Isolate* isolate, const WasmModule* module,
                           ModuleTypeIndex array_index,
                           Handle<Map> opt_rtt_parent,
                           DirectHandle<WasmTrustedInstanceData> trusted_data,
                           Handle<WasmInstanceObject> instance) {
  const wasm::ArrayType* type = module->array_type(array_index);
  const int inobject_properties = 0;
  const int instance_size = kVariableSizeSentinel;
  const InstanceType instance_type = WASM_ARRAY_TYPE;
  const ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
  DirectHandle<WasmTypeInfo> type_info = isolate->factory()->NewWasmTypeInfo(
      reinterpret_cast<Address>(type), opt_rtt_parent, trusted_data,
      array_index);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      instance, instance_type, instance_size, elements_kind,
      inobject_properties);
  map->set_wasm_type_info(*type_info);
  map->SetInstanceDescriptors(isolate,
                              *isolate->factory()->empty_descriptor_array(), 0,
                              SKIP_WRITE_BARRIER);
  map->set_is_extensible(false);
  WasmArray::EncodeElementSizeInMap(type->element_type().value_kind_size(),
                                    *map);
  return map;
}

}  // namespace

void CreateMapForType(Isolate* isolate, const WasmModule* module,
                      ModuleTypeIndex type_index,
                      Handle<WasmTrustedInstanceData> trusted_data,
                      Handle<WasmInstanceObject> instance,
                      Handle<FixedArray> maybe_shared_maps) {
  // Recursive calls for supertypes may already have created this map.
  if (IsMap(maybe_shared_maps->get(type_index.index))) return;

  CanonicalTypeIndex canonical_type_index =
      module->canonical_type_id(type_index);

  // Try to find the canonical map for this type in the isolate store.
  DirectHandle<WeakFixedArray> canonical_rtts =
      direct_handle(isolate->heap()->wasm_canonical_rtts(), isolate);
  DCHECK_GT(static_cast<uint32_t>(canonical_rtts->length()),
            canonical_type_index.index);
  Tagged<MaybeObject> maybe_canonical_map =
      canonical_rtts->get(canonical_type_index.index);
  if (!maybe_canonical_map.IsCleared()) {
    maybe_shared_maps->set(type_index.index,
                           maybe_canonical_map.GetHeapObjectAssumeWeak());
    return;
  }

  Handle<Map> rtt_parent;
  // If the type with {type_index} has an explicit supertype, make sure the
  // map for that supertype is created first, so that the supertypes list
  // that's cached on every RTT can be set up correctly.
  ModuleTypeIndex supertype = module->supertype(type_index);
  if (supertype.valid()) {
    // This recursion is safe, because kV8MaxRttSubtypingDepth limits the
    // number of recursive steps, so we won't overflow the stack.
    CreateMapForType(isolate, module, supertype, trusted_data, instance,
                     maybe_shared_maps);
    // We look up the supertype in {maybe_shared_maps} as a shared type can only
    // inherit from a shared type and vice verca.
    rtt_parent =
        handle(Cast<Map>(maybe_shared_maps->get(supertype.index)), isolate);
  }
  DirectHandle<Map> map;
  switch (module->type(type_index).kind) {
    case TypeDefinition::kStruct:
      map = CreateStructMap(isolate, module, type_index, rtt_parent,
                            trusted_data, instance);
      break;
    case TypeDefinition::kArray:
      map = CreateArrayMap(isolate, module, type_index, rtt_parent,
                           trusted_data, instance);
      break;
    case TypeDefinition::kFunction:
      map = CreateFuncRefMap(isolate, rtt_parent);
      break;
  }
  canonical_rtts->set(canonical_type_index.index, MakeWeak(*map));
  maybe_shared_maps->set(type_index.index, *map);
}

namespace {

bool CompareWithNormalizedCType(const CTypeInfo& info,
                                CanonicalValueType expected,
                                CFunctionInfo::Int64Representation int64_rep) {
  MachineType t = MachineType::TypeForCType(info);
  // Wasm representation of bool is i32 instead of i1.
  if (t.semantic() == MachineSemantic::kBool) {
    return expected == kCanonicalI32;
  }
  if (info.GetType() == CTypeInfo::Type::kSeqOneByteString) {
    // WebAssembly does not support one byte strings in fast API calls as
    // runtime type checks are not supported so far.
    return false;
  }

  if (t.representation() == MachineRepresentation::kWord64) {
    if (int64_rep == CFunctionInfo::Int64Representation::kBigInt) {
      return expected == kCanonicalI64;
    }
    DCHECK_EQ(int64_rep, CFunctionInfo::Int64Representation::kNumber);
    return expected == kCanonicalI32 || expected == kCanonicalF32 ||
           expected == kCanonicalF64;
  }
  return t.representation() == expected.machine_representation();
}

enum class ReceiverKind { kFirstParamIsReceiver, kAnyReceiver };

bool IsSupportedWasmFastApiFunction(Isolate* isolate,
                                    const wasm::CanonicalSig* expected_sig,
                                    Tagged<SharedFunctionInfo> shared,
                                    ReceiverKind receiver_kind,
                                    int* out_index) {
  if (!shared->IsApiFunction()) {
    return false;
  }
  if (shared->api_func_data()->GetCFunctionsCount() == 0) {
    return false;
  }
  if (receiver_kind == ReceiverKind::kAnyReceiver &&
      !shared->api_func_data()->accept_any_receiver()) {
    return false;
  }
  if (receiver_kind == ReceiverKind::kAnyReceiver &&
      !IsUndefined(shared->api_func_data()->signature())) {
    // TODO(wasm): CFunctionInfo* signature check.
    return false;
  }

  const auto log_imported_function_mismatch = [&shared, isolate](
                                                  int func_index,
                                                  const char* reason) {
    if (v8_flags.trace_opt) {
      CodeTracer::Scope scope(isolate->GetCodeTracer());
      PrintF(scope.file(), "[disabled optimization for ");
      ShortPrint(*shared, scope.file());
      PrintF(scope.file(),
             " for C function %d, reason: the signature of the imported "
             "function in the Wasm module doesn't match that of the Fast API "
             "function (%s)]\n",
             func_index, reason);
    }
  };

  // C functions only have one return value.
  if (expected_sig->return_count() > 1) {
    // Here and below, we log when the function we call is declared as an Api
    // function but we cannot optimize the call, which might be unxepected. In
    // that case we use the "slow" path making a normal Wasm->JS call and
    // calling the "slow" callback specified in FunctionTemplate::New().
    log_imported_function_mismatch(0, "too many return values");
    return false;
  }

  for (int c_func_id = 0, end = shared->api_func_data()->GetCFunctionsCount();
       c_func_id < end; ++c_func_id) {
    const CFunctionInfo* info =
        shared->api_func_data()->GetCSignature(isolate, c_func_id);
    if (!compiler::IsFastCallSupportedSignature(info)) {
      log_imported_function_mismatch(c_func_id,
                                     "signature not supported by the fast API");
      continue;
    }

    CTypeInfo return_info = info->ReturnInfo();
    // Unsupported if return type doesn't match.
    if (expected_sig->return_count() == 0 &&
        return_info.GetType() != CTypeInfo::Type::kVoid) {
      log_imported_function_mismatch(c_func_id, "too few return values");
      continue;
    }
    // Unsupported if return type doesn't match.
    if (expected_sig->return_count() == 1) {
      if (return_info.GetType() == CTypeInfo::Type::kVoid) {
        log_imported_function_mismatch(c_func_id, "too many return values");
        continue;
      }
      if (!CompareWithNormalizedCType(return_info, expected_sig->GetReturn(0),
                                      info->GetInt64Representation())) {
        log_imported_function_mismatch(c_func_id, "mismatching return value");
        continue;
      }
    }

    if (receiver_kind == ReceiverKind::kFirstParamIsReceiver) {
      if (expected_sig->parameter_count() < 1) {
        log_imported_function_mismatch(
            c_func_id, "at least one parameter is needed as the receiver");
        continue;
      }
      if (!expected_sig->GetParam(0).is_reference()) {
        log_imported_function_mismatch(c_func_id,
                                       "the receiver has to be a reference");
        continue;
      }
    }

    int param_offset =
        receiver_kind == ReceiverKind::kFirstParamIsReceiver ? 1 : 0;
    // Unsupported if arity doesn't match.
    if (expected_sig->parameter_count() - param_offset !=
        info->ArgumentCount() - 1) {
      log_imported_function_mismatch(c_func_id, "mismatched arity");
      continue;
    }
    // Unsupported if any argument types don't match.
    bool param_mismatch = false;
    for (unsigned int i = 0; i < expected_sig->parameter_count() - param_offset;
         ++i) {
      int sig_index = i + param_offset;
      // Arg 0 is the receiver, skip over it since either the receiver does not
      // matter, or we already checked it above.
      CTypeInfo arg = info->ArgumentInfo(i + 1);
      if (!CompareWithNormalizedCType(arg, expected_sig->GetParam(sig_index),
                                      info->GetInt64Representation())) {
        log_imported_function_mismatch(c_func_id, "parameter type mismatch");
        param_mismatch = true;
        break;
      }
      if (arg.GetSequenceType() == CTypeInfo::SequenceType::kIsSequence) {
        log_imported_function_mismatch(c_func_id,
                                       "sequence types are not allowed");
        param_mismatch = true;
        break;
      }
    }
    if (param_mismatch) {
      continue;
    }
    *out_index = c_func_id;
    return true;
  }
  return false;
}

bool ResolveBoundJSFastApiFunction(const wasm::CanonicalSig* expected_sig,
                                   DirectHandle<JSReceiver> callable) {
  DirectHandle<JSFunction> target;
  if (IsJSBoundFunction(*callable)) {
    auto bound_target = Cast<JSBoundFunction>(callable);
    // Nested bound functions and arguments not supported yet.
    if (bound_target->bound_arguments()->length() > 0) {
      return false;
    }
    if (IsJSBoundFunction(bound_target->bound_target_function())) {
      return false;
    }
    DirectHandle<JSReceiver> bound_target_function(
        bound_target->bound_target_function(), callable->GetIsolate());
    if (!IsJSFunction(*bound_target_function)) {
      return false;
    }
    target = Cast<JSFunction>(bound_target_function);
  } else if (IsJSFunction(*callable)) {
    target = Cast<JSFunction>(callable);
  } else {
    return false;
  }

  Isolate* isolate = target->GetIsolate();
  DirectHandle<SharedFunctionInfo> shared(target->shared(), isolate);
  int api_function_index = -1;
  // The fast API call wrapper currently does not support function overloading.
  // Therefore, if the matching function is not function 0, the fast API cannot
  // be used.
  return IsSupportedWasmFastApiFunction(isolate, expected_sig, *shared,
                                        ReceiverKind::kAnyReceiver,
                                        &api_function_index) &&
         api_function_index == 0;
}

bool IsStringRef(wasm::CanonicalValueType type) {
  return type.is_reference_to(wasm::HeapType::kString);
}

bool IsExternRef(wasm::CanonicalValueType type) {
  return type.is_reference_to(wasm::HeapType::kExtern);
}

bool IsStringOrExternRef(wasm::CanonicalValueType type) {
  return IsStringRef(type) || IsExternRef(type);
}

bool IsDataViewGetterSig(const wasm::CanonicalSig* sig,
                         wasm::CanonicalValueType return_type) {
  return sig->parameter_count() == 3 && sig->return_count() == 1 &&
         sig->GetParam(0) == wasm::kCanonicalExternRef &&
         sig->GetParam(1) == wasm::kCanonicalI32 &&
         sig->GetParam(2) == wasm::kCanonicalI32 &&
         sig->GetReturn(0) == return_type;
}

bool IsDataViewSetterSig(const wasm::CanonicalSig* sig,
                         wasm::CanonicalValueType value_type) {
  return sig->parameter_count() == 4 && sig->return_count() == 0 &&
         sig->GetParam(0) == wasm::kCanonicalExternRef &&
         sig->GetParam(1) == wasm::kCanonicalI32 &&
         sig->GetParam(2) == value_type &&
         sig->GetParam(3) == wasm::kCanonicalI32;
}

const MachineSignature* GetFunctionSigForFastApiImport(
    Zone* zone, const CFunctionInfo* info) {
  uint32_t arg_count = info->ArgumentCount();
  uint32_t ret_count =
      info->ReturnInfo().GetType() == CTypeInfo::Type::kVoid ? 0 : 1;
  constexpr uint32_t param_offset = 1;

  MachineSignature::Builder sig_builder(zone, ret_count,
                                        arg_count - param_offset);
  if (ret_count) {
    sig_builder.AddReturn(MachineType::TypeForCType(info->ReturnInfo()));
  }

  for (uint32_t i = param_offset; i < arg_count; ++i) {
    sig_builder.AddParam(MachineType::TypeForCType(info->ArgumentInfo(i)));
  }
  return sig_builder.Get();
}

// This detects imports of the forms:
// - `Function.prototype.call.bind(foo)`, where `foo` is something that has a
//   Builtin id.
// - JSFunction with Builtin id (e.g. `parseFloat`).
WellKnownImport CheckForWellKnownImport(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data, int func_index,
    DirectHandle<JSReceiver> callable, const wasm::CanonicalSig* sig) {
  WellKnownImport kGeneric = WellKnownImport::kGeneric;  // "using" is C++20.
  if (trusted_instance_data.is_null()) return kGeneric;
  // Check for plain JS functions.
  if (IsJSFunction(*callable)) {
    Tagged<SharedFunctionInfo> sfi = Cast<JSFunction>(*callable)->shared();
    if (!sfi->HasBuiltinId()) return kGeneric;
    // This needs to be a separate switch because it allows other cases than
    // the one below. Merging them would be invalid, because we would then
    // recognize receiver-requiring methods even when they're (erroneously)
    // being imported such that they don't get a receiver.
    switch (sfi->builtin_id()) {
        // =================================================================
        // String-related imports that aren't part of the JS String Builtins
        // proposal.
      case Builtin::kNumberParseFloat:
        if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
            IsStringRef(sig->GetParam(0)) &&
            sig->GetReturn(0) == wasm::kCanonicalF64) {
          return WellKnownImport::kParseFloat;
        }
        break;
      default:
        break;
    }
    return kGeneric;
  }

  // Check for bound JS functions.
  // First part: check that the callable is a bound function whose target
  // is {Function.prototype.call}, and which only binds a receiver.
  if (!IsJSBoundFunction(*callable)) return kGeneric;
  auto bound = Cast<JSBoundFunction>(callable);
  if (bound->bound_arguments()->length() != 0) return kGeneric;
  if (!IsJSFunction(bound->bound_target_function())) return kGeneric;
  Tagged<SharedFunctionInfo> sfi =
      Cast<JSFunction>(bound->bound_target_function())->shared();
  if (!sfi->HasBuiltinId()) return kGeneric;
  if (sfi->builtin_id() != Builtin::kFunctionPrototypeCall) return kGeneric;
  // Second part: check if the bound receiver is one of the builtins for which
  // we have special-cased support.
  Tagged<Object> bound_this = bound->bound_this();
  if (!IsJSFunction(bound_this)) return kGeneric;
  sfi = Cast<JSFunction>(bound_this)->shared();
  Isolate* isolate = Cast<JSFunction>(bound_this)->GetIsolate();
  int out_api_function_index = -1;
  if (v8_flags.wasm_fast_api &&
      IsSupportedWasmFastApiFunction(isolate, sig, sfi,
                                     ReceiverKind::kFirstParamIsReceiver,
                                     &out_api_function_index)) {
    Tagged<FunctionTemplateInfo> func_data = sfi->api_func_data();
    NativeModule* native_module = trusted_instance_data->native_module();
    if (!native_module->TrySetFastApiCallTarget(
            func_index,
            func_data->GetCFunction(isolate, out_api_function_index))) {
      return kGeneric;
    }
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    Address c_functions[] = {func_data->GetCFunction(isolate, 0)};
    const v8::CFunctionInfo* const c_signatures[] = {
        func_data->GetCSignature(isolate, 0)};
    isolate->simulator_data()->RegisterFunctionsAndSignatures(c_functions,
                                                              c_signatures, 1);
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    // Store the signature of the C++ function in the native_module. We check
    // first if the signature already exists in the native_module such that we
    // do not create a copy of the signature unnecessarily. Since
    // `has_fast_api_signature` and `set_fast_api_signature` don't happen
    // atomically, it is still possible that multiple copies of the signature
    // get created. However, the `TrySetFastApiCallTarget` above guarantees that
    // if there are concurrent calls to `set_cast_api_signature`, then all calls
    // would store the same signature to the native module.
    if (!native_module->has_fast_api_signature(func_index)) {
      native_module->set_fast_api_signature(
          func_index,
          GetFunctionSigForFastApiImport(
              &native_module->module()->signature_zone,
              func_data->GetCSignature(isolate, out_api_function_index)));
    }

    DirectHandle<HeapObject> js_signature(sfi->api_func_data()->signature(),
                                          isolate);
    DirectHandle<Object> callback_data(
        sfi->api_func_data()->callback_data(kAcquireLoad), isolate);
    DirectHandle<WasmFastApiCallData> fast_api_call_data =
        isolate->factory()->NewWasmFastApiCallData(js_signature, callback_data);
    trusted_instance_data->well_known_imports()->set(func_index,
                                                     *fast_api_call_data);
    return WellKnownImport::kFastAPICall;
  }
  if (!sfi->HasBuiltinId()) return kGeneric;
  switch (sfi->builtin_id()) {
#if V8_INTL_SUPPORT
    case Builtin::kStringPrototypeToLocaleLowerCase:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          IsStringRef(sig->GetParam(0)) && IsStringRef(sig->GetParam(1)) &&
          IsStringRef(sig->GetReturn(0))) {
        DCHECK_GE(func_index, 0);
        trusted_instance_data->well_known_imports()->set(func_index,
                                                         bound_this);
        return WellKnownImport::kStringToLocaleLowerCaseStringref;
      }
      break;
    case Builtin::kStringPrototypeToLowerCaseIntl:
      if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
          IsStringRef(sig->GetParam(0)) && IsStringRef(sig->GetReturn(0))) {
        return WellKnownImport::kStringToLowerCaseStringref;
      } else if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
                 sig->GetParam(0) == wasm::kCanonicalExternRef &&
                 sig->GetReturn(0) == wasm::kCanonicalExternRef) {
        return WellKnownImport::kStringToLowerCaseImported;
      }
      break;
#endif
    case Builtin::kDataViewPrototypeGetBigInt64:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewGetBigInt64;
      }
      break;
    case Builtin::kDataViewPrototypeGetBigUint64:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewGetBigUint64;
      }
      break;
    case Builtin::kDataViewPrototypeGetFloat32:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalF32)) {
        return WellKnownImport::kDataViewGetFloat32;
      }
      break;
    case Builtin::kDataViewPrototypeGetFloat64:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalF64)) {
        return WellKnownImport::kDataViewGetFloat64;
      }
      break;
    case Builtin::kDataViewPrototypeGetInt8:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewGetInt8;
      }
      break;
    case Builtin::kDataViewPrototypeGetInt16:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetInt16;
      }
      break;
    case Builtin::kDataViewPrototypeGetInt32:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetInt32;
      }
      break;
    case Builtin::kDataViewPrototypeGetUint8:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewGetUint8;
      }
      break;
    case Builtin::kDataViewPrototypeGetUint16:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetUint16;
      }
      break;
    case Builtin::kDataViewPrototypeGetUint32:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetUint32;
      }
      break;

    case Builtin::kDataViewPrototypeSetBigInt64:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewSetBigInt64;
      }
      break;
    case Builtin::kDataViewPrototypeSetBigUint64:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewSetBigUint64;
      }
      break;
    case Builtin::kDataViewPrototypeSetFloat32:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalF32)) {
        return WellKnownImport::kDataViewSetFloat32;
      }
      break;
    case Builtin::kDataViewPrototypeSetFloat64:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalF64)) {
        return WellKnownImport::kDataViewSetFloat64;
      }
      break;
    case Builtin::kDataViewPrototypeSetInt8:
      if (sig->parameter_count() == 3 && sig->return_count() == 0 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetParam(2) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewSetInt8;
      }
      break;
    case Builtin::kDataViewPrototypeSetInt16:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetInt16;
      }
      break;
    case Builtin::kDataViewPrototypeSetInt32:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetInt32;
      }
      break;
    case Builtin::kDataViewPrototypeSetUint8:
      if (sig->parameter_count() == 3 && sig->return_count() == 0 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetParam(2) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewSetUint8;
      }
      break;
    case Builtin::kDataViewPrototypeSetUint16:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetUint16;
      }
      break;
    case Builtin::kDataViewPrototypeSetUint32:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetUint32;
      }
      break;
    case Builtin::kDataViewPrototypeGetByteLength:
      if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetReturn(0) == kCanonicalF64) {
        return WellKnownImport::kDataViewByteLength;
      }
      break;
    case Builtin::kNumberPrototypeToString:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalI32 &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          IsStringOrExternRef(sig->GetReturn(0))) {
        return WellKnownImport::kIntToString;
      }
      if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalF64 &&
          IsStringOrExternRef(sig->GetReturn(0))) {
        return WellKnownImport::kDoubleToString;
      }
      break;
    case Builtin::kStringPrototypeIndexOf:
      // (string, string, i32) -> (i32).
      if (sig->parameter_count() == 3 && sig->return_count() == 1 &&
          IsStringRef(sig->GetParam(0)) && IsStringRef(sig->GetParam(1)) &&
          sig->GetParam(2) == wasm::kCanonicalI32 &&
          sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kStringIndexOf;
      } else if (sig->parameter_count() == 3 && sig->return_count() == 1 &&
                 sig->GetParam(0) == wasm::kCanonicalExternRef &&
                 sig->GetParam(1) == wasm::kCanonicalExternRef &&
                 sig->GetParam(2) == wasm::kCanonicalI32 &&
                 sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kStringIndexOfImported;
      }
      break;
    default:
      break;
  }
  return kGeneric;
}

}  // namespace

ResolvedWasmImport::ResolvedWasmImport(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data, int func_index,
    Handle<JSReceiver> callable, const wasm::CanonicalSig* expected_sig,
    CanonicalTypeIndex expected_sig_id, WellKnownImport preknown_import) {
  DCHECK_EQ(expected_sig, wasm::GetTypeCanonicalizer()->LookupFunctionSignature(
                              expected_sig_id));
  SetCallable(callable->GetIsolate(), callable);
  kind_ = ComputeKind(trusted_instance_data, func_index, expected_sig,
                      expected_sig_id, preknown_import);
}

void ResolvedWasmImport::SetCallable(Isolate* isolate,
                                     Tagged<JSReceiver> callable) {
  SetCallable(isolate, handle(callable, isolate));
}
void ResolvedWasmImport::SetCallable(Isolate* isolate,
                                     Handle<JSReceiver> callable) {
  callable_ = callable;
  trusted_function_data_ = {};
  if (!IsJSFunction(*callable)) return;
  Tagged<SharedFunctionInfo> sfi = Cast<JSFunction>(*callable_)->shared();
  if (sfi->HasWasmFunctionData()) {
    trusted_function_data_ = handle(sfi->wasm_function_data(), isolate);
  }
}

ImportCallKind ResolvedWasmImport::ComputeKind(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data, int func_index,
    const wasm::CanonicalSig* expected_sig, CanonicalTypeIndex expected_sig_id,
    WellKnownImport preknown_import) {
  // If we already have a compile-time import, simply pass that through.
  if (IsCompileTimeImport(preknown_import)) {
    well_known_status_ = preknown_import;
    DCHECK(IsJSFunction(*callable_));
    DCHECK_EQ(Cast<JSFunction>(*callable_)
                  ->shared()
                  ->internal_formal_parameter_count_without_receiver(),
              expected_sig->parameter_count());
    return ImportCallKind::kJSFunctionArityMatch;
  }
  Isolate* isolate = callable_->GetIsolate();
  if (IsWasmSuspendingObject(*callable_)) {
    suspend_ = kSuspend;
    SetCallable(isolate, Cast<WasmSuspendingObject>(*callable_)->callable());
  }
  if (!trusted_function_data_.is_null() &&
      IsWasmExportedFunctionData(*trusted_function_data_)) {
    Tagged<WasmExportedFunctionData> data =
        Cast<WasmExportedFunctionData>(*trusted_function_data_);
    if (!data->MatchesSignature(expected_sig_id)) {
      return ImportCallKind::kLinkError;
    }
    uint32_t func_index = static_cast<uint32_t>(data->function_index());
    if (func_index >= data->instance_data()->module()->num_imported_functions) {
      return ImportCallKind::kWasmToWasm;
    }
    // Resolve the shortcut to the underlying callable and continue.
    ImportedFunctionEntry entry(handle(data->instance_data(), isolate),
                                func_index);
    suspend_ = static_cast<Suspend>(
        Cast<WasmImportData>(entry.implicit_arg())->suspend());
    SetCallable(isolate, entry.callable());
  }
  if (!trusted_function_data_.is_null() &&
      IsWasmJSFunctionData(*trusted_function_data_)) {
    Tagged<WasmJSFunctionData> js_function_data =
        Cast<WasmJSFunctionData>(*trusted_function_data_);
    suspend_ = js_function_data->GetSuspend();
    if (!js_function_data->MatchesSignature(expected_sig_id)) {
      return ImportCallKind::kLinkError;
    }
    // Resolve the short-cut to the underlying callable and continue.
    SetCallable(isolate, js_function_data->GetCallable());
  }
  if (WasmCapiFunction::IsWasmCapiFunction(*callable_)) {
    // TODO(jkummerow): Update this to follow the style of the other kinds of
    // functions.
    auto capi_function = Cast<WasmCapiFunction>(callable_);
    if (!capi_function->MatchesSignature(expected_sig_id)) {
      return ImportCallKind::kLinkError;
    }
    return ImportCallKind::kWasmToCapi;
  }
  // Assuming we are calling to JS, check whether this would be a runtime error.
  if (!wasm::IsJSCompatibleSignature(expected_sig)) {
    return ImportCallKind::kRuntimeTypeError;
  }
  // Check if this can be a JS fast API call.
  if (v8_flags.turbo_fast_api_calls &&
      ResolveBoundJSFastApiFunction(expected_sig, callable_))
```