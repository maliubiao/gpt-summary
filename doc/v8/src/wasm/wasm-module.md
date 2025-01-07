Response: The user wants to understand the functionality of the C++ source code file `v8/src/wasm/wasm-module.cc`. I need to:

1. **Identify the main purpose of the file.** Based on the filename and the included headers, it likely deals with the representation and management of WebAssembly modules within the V8 engine.
2. **Summarize the key functionalities** implemented in the file. This will involve looking at the classes, methods, and static functions defined.
3. **Check for relationships with JavaScript.**  WebAssembly is executed within a JavaScript environment in the browser, so there should be some interaction. I need to pinpoint these connections.
4. **Provide JavaScript examples** to illustrate the interaction, if any.

**Detailed breakdown of the code:**

*   **Includes:** Standard C++ headers and V8 specific headers related to API, compiler, objects, and various WASM components (decoder, code manager, engine, etc.). This confirms the file's role in V8's WASM implementation.
*   **Namespaces:**  The code is within `v8::internal::wasm`, which is the standard namespace for V8's internal WASM components.
*   **`AdaptiveMap`:**  A templated class for a map that can switch between sparse and dense storage depending on usage. This is likely an optimization for storing data associated with modules.
*   **`LazilyGeneratedNames`:**  Manages function names, possibly decoding them on demand. This is relevant for debugging and reflection.
*   **`GetWasmFunctionOffset`, `GetNearestWasmFunction`, `GetContainingWasmFunction`:** Utility functions for locating functions within the module's bytecode. These are crucial for debugging and error reporting.
*   **`GetSubtypingDepth`:**  Retrieves the subtyping depth of a WebAssembly type. This relates to WebAssembly's type system.
*   **`AsmJsOffsetInformation`:**  Handles source map information for asm.js modules. asm.js is a subset of JavaScript that can be optimized like WebAssembly, so this is a connection to JavaScript.
*   **`ModuleWireBytes`:**  A wrapper for the raw byte representation of the WebAssembly module.
*   **`WasmName`:** Represents a name within the WebAssembly module.
*   **`WasmModule`:**  The core class representing a loaded WebAssembly module. It contains various metadata about the module (functions, globals, memory, imports, exports, etc.). This is the central data structure the file revolves around.
*   **`IsWasmCodegenAllowed`, `ErrorStringForCodegen`:** Functions related to checking permissions and generating error messages during code generation. This links to V8's security and error handling.
*   **`GetTypeForFunction`, `GetTypeForGlobal`, `GetTypeForMemory`, `GetTypeForTable`:** Functions that create JavaScript objects representing the types of WebAssembly entities. This is a key interaction point between WASM and JavaScript, enabling reflection.
*   **`GetImports`, `GetExports`, `GetCustomSections`:** Functions that extract information about the module's imports, exports, and custom sections, and represent them as JavaScript objects. This directly exposes WASM module structure to JavaScript.
*   **`GetSourcePosition`:**  Retrieves the original source code position for a given byte offset in a WASM function. This is used for debugging.
*   **`EstimateStoredSize`, `EstimateCurrentMemoryConsumption`:** Functions for estimating the memory usage of the `WasmModule` and related structures. This is important for V8's memory management.
*   **`PrintSignature`:**  Generates a string representation of a function signature.
*   **`JumpTableOffset`:** Calculates the offset of a function's entry in the jump table.
*   **`GetWireBytesHash`:** Calculates a hash of the module's bytecode.
*   **`NumFeedbackSlots`:**  Returns the number of feedback slots for a given function, used for optimization.

**JavaScript Interaction Points:**

The file extensively uses V8's JavaScript object model (`Handle`, `JSObject`, `JSArray`, `String`, etc.) to represent WASM module information. The functions like `GetImports`, `GetExports`, `GetTypeFor*`, and `GetCustomSections` are clearly designed to be called from JavaScript or by code that interacts with JavaScript. The presence of `WasmModuleObject` further reinforces this connection.

**JavaScript Examples:**

I can use the `WebAssembly` API in JavaScript to demonstrate how the information managed by this C++ file is exposed to JavaScript.

**Final Plan:**

1. State that the file is responsible for representing and managing WebAssembly modules in V8.
2. List the key functionalities, grouping them logically (e.g., module representation, function lookup, type reflection, import/export handling, debugging).
3. Explicitly state the relationship with JavaScript, highlighting the use of V8's JavaScript object model.
4. Provide JavaScript examples using the `WebAssembly` API's reflection features (e.g., `WebAssembly.Module.imports()`, `WebAssembly.Module.exports()`) to show how the data managed in this C++ file becomes accessible in JavaScript.
5. Briefly mention the asm.js support as another connection point.
这个C++源代码文件 `v8/src/wasm/wasm-module.cc` 的主要功能是**定义和管理 WebAssembly 模块的内部表示**。它包含了 `WasmModule` 类及其相关的辅助类和函数，用于存储和操作 WebAssembly 模块的元数据和结构信息。

具体来说，这个文件负责以下几个方面的功能：

**1. WebAssembly 模块的表示 (`WasmModule` 类):**

*   `WasmModule` 类是 WebAssembly 模块在 V8 引擎中的核心表示。它存储了模块的各种信息，例如：
    *   **函数 (`functions`)**:  模块中定义的函数列表，包括它们的签名、代码范围等信息。
    *   **全局变量 (`globals`)**:  模块中定义的全局变量的类型和可变性。
    *   **内存 (`memories`)**:  模块的内存定义，包括初始大小和最大大小。
    *   **表 (`tables`)**:  模块的表定义，用于存储函数引用或其他值。
    *   **导入 (`import_table`)**:  模块导入的外部函数、全局变量、内存和表的信息。
    *   **导出 (`export_table`)**:  模块导出的函数、全局变量、内存和表的信息。
    *   **类型 (`types`)**:  模块中定义的类型信息。
    *   **数据段 (`data_segments`)**:  用于初始化内存的数据段。
    *   **元素段 (`elem_segments`)**:  用于初始化表的元素段。
    *   **自定义段 (`custom sections`)**:  模块中的自定义段数据。
    *   **其他元数据**:  例如，模块的来源、类型反馈信息、名称等。

**2. 辅助数据结构和功能:**

*   **`AdaptiveMap`**:  一个自适应的映射表，可以根据条目数量在稀疏和密集存储之间切换，用于优化内存使用。
*   **`LazilyGeneratedNames`**:  用于延迟生成函数名称，可能在需要时才解码。
*   **函数查找**:  提供查找特定函数或给定字节偏移量所属函数的功能 (`GetWasmFunctionOffset`, `GetNearestWasmFunction`, `GetContainingWasmFunction`).
*   **源码位置映射**:  处理 asm.js 模块的源码位置信息 (`AsmJsOffsetInformation`)，用于调试。
*   **类型反射**:  提供将 WebAssembly 类型信息转换为 JavaScript 对象的功能 (`GetTypeForFunction`, `GetTypeForGlobal`, `GetTypeForMemory`, `GetTypeForTable`)，使得 JavaScript 可以检查模块的类型信息。
*   **导入和导出处理**:  提供将模块的导入和导出信息转换为 JavaScript 数组的功能 (`GetImports`, `GetExports`)，方便 JavaScript 理解模块的接口。
*   **自定义段处理**:  提供访问模块自定义段数据的功能 (`GetCustomSections`).
*   **内存估算**:  提供估算 `WasmModule` 对象及其相关数据结构内存使用情况的功能。

**3. 与 JavaScript 的关系:**

这个文件与 JavaScript 的功能有非常密切的关系，因为它负责构建 WebAssembly 模块在 V8 中供 JavaScript 使用的表示。当 JavaScript 代码加载一个 WebAssembly 模块时，V8 会解析模块的二进制代码，并使用 `WasmModule` 类及其相关结构来存储模块的信息。

以下是一些关键的联系点，并用 JavaScript 示例说明：

*   **`WebAssembly.Module` 对象:** 当 JavaScript 使用 `WebAssembly.Module` 加载一个 WebAssembly 模块时，V8 内部会创建一个 `WasmModule` 对象来表示这个模块。

    ```javascript
    const wasmCode = new Uint8Array([
      0, 97, 115, 109, 1, 0, 0, 0,  // 魔数和版本
      1, 4, 1, 96, 0, 1, 127      // 类型段：定义一个函数类型 () => [i32]
    ]);
    const wasmModule = new WebAssembly.Module(wasmCode);
    ```

*   **获取导入和导出:** JavaScript 可以通过 `WebAssembly.Module.imports()` 和 `WebAssembly.Module.exports()` 方法获取模块的导入和导出信息。这些方法内部会访问 `WasmModule` 对象中的 `import_table` 和 `export_table`，并通过 `GetImports` 和 `GetExports` 函数将信息转换为 JavaScript 对象。

    ```javascript
    const imports = WebAssembly.Module.imports(wasmModule);
    console.log(imports); // 输出模块的导入信息，例如 { module: "env", name: "external_func", kind: "function" }

    const exports = WebAssembly.Module.exports(wasmModule);
    console.log(exports); // 输出模块的导出信息，例如 { name: "exported_func", kind: "function" }
    ```

*   **类型反射:**  如果启用了类型反射功能，`GetImports` 和 `GetExports` 函数会使用 `GetTypeFor*` 函数来为导入和导出的实体添加 `type` 属性，该属性是一个 JavaScript 对象，描述了 WebAssembly 的类型信息。

    ```javascript
    // 假设模块导出一个名为 'myGlobal' 的全局变量
    const exportsWithTypes = WebAssembly.Module.exports(wasmModule);
    const myGlobalExport = exportsWithTypes.find(exp => exp.name === 'myGlobal');
    console.log(myGlobalExport.type); // 输出描述 'myGlobal' 全局变量类型的 JavaScript 对象，例如 { mutable: false, value: 'i32' }
    ```

*   **获取自定义段:** JavaScript 可以通过实验性的 `WebAssembly.Module.customSections()` 方法获取模块的自定义段数据。该方法内部会访问 `WasmModule` 对象的自定义段信息，并通过 `GetCustomSections` 函数将数据转换为 JavaScript 的 `ArrayBuffer` 对象。

    ```javascript
    // 假设模块有一个名为 'my_custom_section' 的自定义段
    const customSections = WebAssembly.Module.customSections(wasmModule, 'my_custom_section');
    console.log(customSections); // 输出包含自定义段数据的 ArrayBuffer 数组
    ```

总而言之，`v8/src/wasm/wasm-module.cc` 文件是 V8 引擎中 WebAssembly 模块的核心表示层，它负责存储和管理模块的各种元数据，并提供了将这些信息暴露给 JavaScript 的机制，使得 JavaScript 可以与 WebAssembly 模块进行交互和内省。

Prompt: 
```
这是目录为v8/src/wasm/wasm-module.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-module.h"

#include <functional>
#include <memory>

#include "src/api/api-inl.h"
#include "src/compiler/wasm-compiler.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/objects.h"
#include "src/wasm/jump-table-assembler.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/std-object-sizes.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-init-expr.h"
#include "src/wasm/wasm-js.h"
#include "src/wasm/wasm-module-builder.h"  // For {ZoneBuffer}.
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::wasm {

// Ensure that the max subtyping depth can be stored in the TypeDefinition.
static_assert(
    kV8MaxRttSubtypingDepth <=
    std::numeric_limits<decltype(TypeDefinition().subtyping_depth)>::max());

template <class Value>
void AdaptiveMap<Value>::FinishInitialization() {
  uint32_t count = 0;
  uint32_t max = 0;
  DCHECK_EQ(mode_, kInitializing);
  for (const auto& entry : *map_) {
    count++;
    max = std::max(max, entry.first);
  }
  if (count >= (max + 1) / kLoadFactor) {
    mode_ = kDense;
    vector_.resize(max + 1);
    for (auto& entry : *map_) {
      vector_[entry.first] = std::move(entry.second);
    }
    map_.reset();
  } else {
    mode_ = kSparse;
  }
}
template void NameMap::FinishInitialization();
template void IndirectNameMap::FinishInitialization();

WireBytesRef LazilyGeneratedNames::LookupFunctionName(
    ModuleWireBytes wire_bytes, uint32_t function_index) {
  base::MutexGuard lock(&mutex_);
  if (!has_functions_) {
    has_functions_ = true;
    DecodeFunctionNames(wire_bytes.module_bytes(), function_names_);
  }
  const WireBytesRef* result = function_names_.Get(function_index);
  if (!result) return WireBytesRef();
  return *result;
}

bool LazilyGeneratedNames::Has(uint32_t function_index) {
  DCHECK(has_functions_);
  base::MutexGuard lock(&mutex_);
  return function_names_.Get(function_index) != nullptr;
}

// static
int GetWasmFunctionOffset(const WasmModule* module, uint32_t func_index) {
  const std::vector<WasmFunction>& functions = module->functions;
  if (static_cast<uint32_t>(func_index) >= functions.size()) return -1;
  DCHECK_GE(kMaxInt, functions[func_index].code.offset());
  return static_cast<int>(functions[func_index].code.offset());
}

// static
int GetNearestWasmFunction(const WasmModule* module, uint32_t byte_offset) {
  const std::vector<WasmFunction>& functions = module->functions;

  // Binary search for a function containing the given position.
  int left = 0;                                    // inclusive
  int right = static_cast<int>(functions.size());  // exclusive
  if (right == 0) return -1;
  while (right - left > 1) {
    int mid = left + (right - left) / 2;
    if (functions[mid].code.offset() <= byte_offset) {
      left = mid;
    } else {
      right = mid;
    }
  }

  return left;
}

// static
int GetContainingWasmFunction(const WasmModule* module, uint32_t byte_offset) {
  int func_index = GetNearestWasmFunction(module, byte_offset);

  if (func_index >= 0) {
    // If the found function does not contain the given position, return -1.
    const WasmFunction& func = module->functions[func_index];
    if (byte_offset < func.code.offset() ||
        byte_offset >= func.code.end_offset()) {
      return -1;
    }
  }
  return func_index;
}

int GetSubtypingDepth(const WasmModule* module, ModuleTypeIndex type_index) {
  DCHECK_LT(type_index.index, module->types.size());
  int depth = module->type(type_index).subtyping_depth;
  DCHECK_LE(depth, kV8MaxRttSubtypingDepth);
  return depth;
}

void LazilyGeneratedNames::AddForTesting(int function_index,
                                         WireBytesRef name) {
  base::MutexGuard lock(&mutex_);
  function_names_.Put(function_index, name);
}

AsmJsOffsetInformation::AsmJsOffsetInformation(
    base::Vector<const uint8_t> encoded_offsets)
    : encoded_offsets_(base::OwnedVector<const uint8_t>::Of(encoded_offsets)) {}

AsmJsOffsetInformation::~AsmJsOffsetInformation() = default;

int AsmJsOffsetInformation::GetSourcePosition(int declared_func_index,
                                              int byte_offset,
                                              bool is_at_number_conversion) {
  EnsureDecodedOffsets();

  DCHECK_LE(0, declared_func_index);
  DCHECK_GT(decoded_offsets_->functions.size(), declared_func_index);
  std::vector<AsmJsOffsetEntry>& function_offsets =
      decoded_offsets_->functions[declared_func_index].entries;

  auto byte_offset_less = [](const AsmJsOffsetEntry& a,
                             const AsmJsOffsetEntry& b) {
    return a.byte_offset < b.byte_offset;
  };
  SLOW_DCHECK(std::is_sorted(function_offsets.begin(), function_offsets.end(),
                             byte_offset_less));
  // If there are no positions recorded, map offset 0 (for function entry) to
  // position 0.
  if (function_offsets.empty() && byte_offset == 0) return 0;
  auto it =
      std::lower_bound(function_offsets.begin(), function_offsets.end(),
                       AsmJsOffsetEntry{byte_offset, 0, 0}, byte_offset_less);
  DCHECK_NE(function_offsets.end(), it);
  DCHECK_EQ(byte_offset, it->byte_offset);
  return is_at_number_conversion ? it->source_position_number_conversion
                                 : it->source_position_call;
}

std::pair<int, int> AsmJsOffsetInformation::GetFunctionOffsets(
    int declared_func_index) {
  EnsureDecodedOffsets();

  DCHECK_LE(0, declared_func_index);
  DCHECK_GT(decoded_offsets_->functions.size(), declared_func_index);
  AsmJsOffsetFunctionEntries& function_info =
      decoded_offsets_->functions[declared_func_index];

  return {function_info.start_offset, function_info.end_offset};
}

void AsmJsOffsetInformation::EnsureDecodedOffsets() {
  base::MutexGuard mutex_guard(&mutex_);
  DCHECK_EQ(encoded_offsets_ == nullptr, decoded_offsets_ != nullptr);

  if (decoded_offsets_) return;
  AsmJsOffsetsResult result =
      wasm::DecodeAsmJsOffsets(encoded_offsets_.as_vector());
  decoded_offsets_ = std::make_unique<AsmJsOffsets>(std::move(result).value());
  encoded_offsets_.ReleaseData();
}

// Get a string stored in the module bytes representing a name.
WasmName ModuleWireBytes::GetNameOrNull(WireBytesRef ref) const {
  if (!ref.is_set()) return {nullptr, 0};  // no name.
  DCHECK(BoundsCheck(ref));
  return WasmName::cast(
      module_bytes_.SubVector(ref.offset(), ref.end_offset()));
}

// Get a string stored in the module bytes representing a function name.
WasmName ModuleWireBytes::GetNameOrNull(int func_index,
                                        const WasmModule* module) const {
  return GetNameOrNull(
      module->lazily_generated_names.LookupFunctionName(*this, func_index));
}

std::ostream& operator<<(std::ostream& os, const WasmFunctionName& name) {
  os << "#" << name.func_index_;
  if (!name.name_.empty()) {
    if (name.name_.begin()) {
      os << ":";
      os.write(name.name_.begin(), name.name_.length());
    }
  } else {
    os << "?";
  }
  return os;
}

WasmModule::WasmModule(ModuleOrigin origin)
    : signature_zone(GetWasmEngine()->allocator(), "signature zone"),
      origin(origin) {}

bool IsWasmCodegenAllowed(Isolate* isolate, Handle<NativeContext> context) {
  // TODO(wasm): Once wasm has its own CSP policy, we should introduce a
  // separate callback that includes information about the module about to be
  // compiled. For the time being, pass an empty string as placeholder for the
  // sources.
  if (auto wasm_codegen_callback = isolate->allow_wasm_code_gen_callback()) {
    return wasm_codegen_callback(
        v8::Utils::ToLocal(context),
        v8::Utils::ToLocal(isolate->factory()->empty_string()));
  }
  return true;
}

DirectHandle<String> ErrorStringForCodegen(Isolate* isolate,
                                           DirectHandle<Context> context) {
  DirectHandle<Object> error = context->ErrorMessageForWasmCodeGeneration();
  DCHECK(!error.is_null());
  return Object::NoSideEffectsToString(isolate, error);
}

namespace {

// Converts the given {type} into a string representation that can be used in
// reflective functions. Should be kept in sync with the {GetValueType} helper.
template <typename T>
Handle<String> ToValueTypeString(Isolate* isolate, T type) {
  return isolate->factory()->InternalizeUtf8String(base::VectorOf(type.name()));
}
}  // namespace

template <typename T>
Handle<JSObject> GetTypeForFunction(Isolate* isolate, const Signature<T>* sig,
                                    bool for_exception) {
  Factory* factory = isolate->factory();

  // Extract values for the {ValueType[]} arrays.
  int param_index = 0;
  int param_count = static_cast<int>(sig->parameter_count());
  DirectHandle<FixedArray> param_values = factory->NewFixedArray(param_count);
  for (T type : sig->parameters()) {
    DirectHandle<String> type_value = ToValueTypeString(isolate, type);
    param_values->set(param_index++, *type_value);
  }

  // Create the resulting {FunctionType} object.
  Handle<JSFunction> object_function = isolate->object_function();
  Handle<JSObject> object = factory->NewJSObject(object_function);
  DirectHandle<JSArray> params = factory->NewJSArrayWithElements(param_values);
  Handle<String> params_string = factory->InternalizeUtf8String("parameters");
  Handle<String> results_string = factory->InternalizeUtf8String("results");
  JSObject::AddProperty(isolate, object, params_string, params, NONE);

  // Now add the result types if needed.
  if (for_exception) {
    DCHECK_EQ(sig->returns().size(), 0);
  } else {
    int result_index = 0;
    int result_count = static_cast<int>(sig->return_count());
    DirectHandle<FixedArray> result_values =
        factory->NewFixedArray(result_count);
    for (T type : sig->returns()) {
      DirectHandle<String> type_value = ToValueTypeString(isolate, type);
      result_values->set(result_index++, *type_value);
    }
    DirectHandle<JSArray> results =
        factory->NewJSArrayWithElements(result_values);
    JSObject::AddProperty(isolate, object, results_string, results, NONE);
  }

  return object;
}

template Handle<JSObject> GetTypeForFunction(
    Isolate*, const Signature<CanonicalValueType>*, bool);

Handle<JSObject> GetTypeForGlobal(Isolate* isolate, bool is_mutable,
                                  ValueType type) {
  Factory* factory = isolate->factory();

  Handle<JSFunction> object_function = isolate->object_function();
  Handle<JSObject> object = factory->NewJSObject(object_function);
  Handle<String> mutable_string = factory->InternalizeUtf8String("mutable");
  Handle<String> value_string = factory->value_string();
  JSObject::AddProperty(isolate, object, mutable_string,
                        factory->ToBoolean(is_mutable), NONE);
  JSObject::AddProperty(isolate, object, value_string,
                        ToValueTypeString(isolate, type), NONE);

  return object;
}

Handle<JSObject> GetTypeForMemory(Isolate* isolate, uint32_t min_size,
                                  std::optional<uint64_t> max_size, bool shared,
                                  AddressType address_type) {
  Factory* factory = isolate->factory();

  Handle<JSFunction> object_function = isolate->object_function();
  Handle<JSObject> object = factory->NewJSObject(object_function);
  Handle<String> minimum_string = factory->InternalizeUtf8String("minimum");
  Handle<String> maximum_string = factory->InternalizeUtf8String("maximum");
  Handle<String> shared_string = factory->InternalizeUtf8String("shared");
  Handle<String> address_string = factory->InternalizeUtf8String("address");
  JSObject::AddProperty(isolate, object, minimum_string,
                        factory->NewNumberFromUint(min_size), NONE);
  if (max_size.has_value()) {
    Handle<UnionOf<Smi, HeapNumber, BigInt>> max;
    if (address_type == AddressType::kI32) {
      DCHECK_GE(kMaxUInt32, *max_size);
      max = factory->NewNumberFromUint(static_cast<uint32_t>(*max_size));
    } else {
      max = BigInt::FromUint64(isolate, *max_size);
    }
    JSObject::AddProperty(isolate, object, maximum_string, max, NONE);
  }
  JSObject::AddProperty(isolate, object, shared_string,
                        factory->ToBoolean(shared), NONE);

  JSObject::AddProperty(
      isolate, object, address_string,
      factory->InternalizeUtf8String(AddressTypeToStr(address_type)), NONE);

  return object;
}

Handle<JSObject> GetTypeForTable(Isolate* isolate, ValueType type,
                                 uint32_t min_size,
                                 std::optional<uint64_t> max_size,
                                 AddressType address_type) {
  Factory* factory = isolate->factory();

  DirectHandle<String> element =
      factory->InternalizeUtf8String(base::VectorOf(type.name()));

  Handle<JSFunction> object_function = isolate->object_function();
  Handle<JSObject> object = factory->NewJSObject(object_function);
  Handle<String> element_string = factory->element_string();
  Handle<String> minimum_string = factory->InternalizeUtf8String("minimum");
  Handle<String> maximum_string = factory->InternalizeUtf8String("maximum");
  Handle<String> address_string = factory->InternalizeUtf8String("address");
  JSObject::AddProperty(isolate, object, element_string, element, NONE);
  JSObject::AddProperty(isolate, object, minimum_string,
                        factory->NewNumberFromUint(min_size), NONE);
  if (max_size.has_value()) {
    Handle<UnionOf<Smi, HeapNumber, BigInt>> max;
    if (address_type == AddressType::kI32) {
      DCHECK_GE(kMaxUInt32, *max_size);
      max = factory->NewNumberFromUint(static_cast<uint32_t>(*max_size));
    } else {
      max = BigInt::FromUint64(isolate, *max_size);
    }
    JSObject::AddProperty(isolate, object, maximum_string, max, NONE);
  }
  JSObject::AddProperty(
      isolate, object, address_string,
      factory->InternalizeUtf8String(AddressTypeToStr(address_type)), NONE);

  return object;
}

Handle<JSArray> GetImports(Isolate* isolate,
                           DirectHandle<WasmModuleObject> module_object) {
  auto enabled_features = i::wasm::WasmEnabledFeatures::FromIsolate(isolate);
  Factory* factory = isolate->factory();

  Handle<String> module_string = factory->InternalizeUtf8String("module");
  Handle<String> name_string = factory->name_string();
  Handle<String> kind_string = factory->InternalizeUtf8String("kind");
  Handle<String> type_string = factory->InternalizeUtf8String("type");

  Handle<String> function_string = factory->function_string();
  Handle<String> table_string = factory->InternalizeUtf8String("table");
  Handle<String> memory_string = factory->InternalizeUtf8String("memory");
  Handle<String> global_string = factory->global_string();
  Handle<String> tag_string = factory->InternalizeUtf8String("tag");

  // Create the result array.
  NativeModule* native_module = module_object->native_module();
  const WasmModule* module = native_module->module();
  int num_imports = static_cast<int>(module->import_table.size());
  Handle<JSArray> array_object = factory->NewJSArray(PACKED_ELEMENTS, 0, 0);
  Handle<FixedArray> storage = factory->NewFixedArray(num_imports);
  JSArray::SetContent(array_object, storage);

  Handle<JSFunction> object_function =
      Handle<JSFunction>(isolate->native_context()->object_function(), isolate);

  // Populate the result array.
  const WellKnownImportsList& well_known_imports =
      module->type_feedback.well_known_imports;
  const std::string& magic_string_constants =
      native_module->compile_imports().constants_module();
  const bool has_magic_string_constants =
      native_module->compile_imports().contains(
          CompileTimeImport::kStringConstants);

  int cursor = 0;
  for (int index = 0; index < num_imports; ++index) {
    const WasmImport& import = module->import_table[index];

    Handle<JSObject> entry = factory->NewJSObject(object_function);

    Handle<String> import_kind;
    Handle<JSObject> type_value;
    switch (import.kind) {
      case kExternalFunction:
        if (IsCompileTimeImport(well_known_imports.get(import.index))) {
          continue;
        }
        if (enabled_features.has_type_reflection()) {
          auto& func = module->functions[import.index];
          type_value = GetTypeForFunction(isolate, func.sig);
        }
        import_kind = function_string;
        break;
      case kExternalTable:
        if (enabled_features.has_type_reflection()) {
          auto& table = module->tables[import.index];
          std::optional<uint32_t> maximum_size;
          if (table.has_maximum_size) maximum_size.emplace(table.maximum_size);
          type_value = GetTypeForTable(isolate, table.type, table.initial_size,
                                       maximum_size, table.address_type);
        }
        import_kind = table_string;
        break;
      case kExternalMemory:
        if (enabled_features.has_type_reflection()) {
          auto& memory = module->memories[import.index];
          std::optional<uint32_t> maximum_size;
          if (memory.has_maximum_pages) {
            maximum_size.emplace(memory.maximum_pages);
          }
          type_value =
              GetTypeForMemory(isolate, memory.initial_pages, maximum_size,
                               memory.is_shared, memory.address_type);
        }
        import_kind = memory_string;
        break;
      case kExternalGlobal:
        if (has_magic_string_constants &&
            import.module_name.length() == magic_string_constants.size() &&
            std::equal(magic_string_constants.begin(),
                       magic_string_constants.end(),
                       module_object->native_module()->wire_bytes().begin() +
                           import.module_name.offset())) {
          continue;
        }
        if (enabled_features.has_type_reflection()) {
          auto& global = module->globals[import.index];
          type_value =
              GetTypeForGlobal(isolate, global.mutability, global.type);
        }
        import_kind = global_string;
        break;
      case kExternalTag:
        import_kind = tag_string;
        break;
    }
    DCHECK(!import_kind.is_null());

    DirectHandle<String> import_module =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate, module_object, import.module_name, kInternalize);

    DirectHandle<String> import_name =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate, module_object, import.field_name, kInternalize);

    JSObject::AddProperty(isolate, entry, module_string, import_module, NONE);
    JSObject::AddProperty(isolate, entry, name_string, import_name, NONE);
    JSObject::AddProperty(isolate, entry, kind_string, import_kind, NONE);
    if (!type_value.is_null()) {
      JSObject::AddProperty(isolate, entry, type_string, type_value, NONE);
    }

    storage->set(cursor++, *entry);
  }

  array_object->set_length(Smi::FromInt(cursor));
  return array_object;
}

Handle<JSArray> GetExports(Isolate* isolate,
                           DirectHandle<WasmModuleObject> module_object) {
  auto enabled_features = i::wasm::WasmEnabledFeatures::FromIsolate(isolate);
  Factory* factory = isolate->factory();

  Handle<String> name_string = factory->name_string();
  Handle<String> kind_string = factory->InternalizeUtf8String("kind");
  Handle<String> type_string = factory->InternalizeUtf8String("type");

  DirectHandle<String> function_string = factory->function_string();
  DirectHandle<String> table_string = factory->InternalizeUtf8String("table");
  DirectHandle<String> memory_string = factory->InternalizeUtf8String("memory");
  DirectHandle<String> global_string = factory->global_string();
  DirectHandle<String> tag_string = factory->InternalizeUtf8String("tag");

  // Create the result array.
  const WasmModule* module = module_object->module();
  int num_exports = static_cast<int>(module->export_table.size());
  Handle<JSArray> array_object = factory->NewJSArray(PACKED_ELEMENTS, 0, 0);
  Handle<FixedArray> storage = factory->NewFixedArray(num_exports);
  JSArray::SetContent(array_object, storage);
  array_object->set_length(Smi::FromInt(num_exports));

  Handle<JSFunction> object_function =
      Handle<JSFunction>(isolate->native_context()->object_function(), isolate);

  // Populate the result array.
  for (int index = 0; index < num_exports; ++index) {
    const WasmExport& exp = module->export_table[index];

    DirectHandle<String> export_kind;
    Handle<JSObject> type_value;
    switch (exp.kind) {
      case kExternalFunction:
        if (enabled_features.has_type_reflection()) {
          auto& func = module->functions[exp.index];
          type_value = GetTypeForFunction(isolate, func.sig);
        }
        export_kind = function_string;
        break;
      case kExternalTable:
        if (enabled_features.has_type_reflection()) {
          auto& table = module->tables[exp.index];
          std::optional<uint32_t> maximum_size;
          if (table.has_maximum_size) maximum_size.emplace(table.maximum_size);
          type_value = GetTypeForTable(isolate, table.type, table.initial_size,
                                       maximum_size, table.address_type);
        }
        export_kind = table_string;
        break;
      case kExternalMemory:
        if (enabled_features.has_type_reflection()) {
          auto& memory = module->memories[exp.index];
          std::optional<uint32_t> maximum_size;
          if (memory.has_maximum_pages) {
            maximum_size.emplace(memory.maximum_pages);
          }
          type_value =
              GetTypeForMemory(isolate, memory.initial_pages, maximum_size,
                               memory.is_shared, memory.address_type);
        }
        export_kind = memory_string;
        break;
      case kExternalGlobal:
        if (enabled_features.has_type_reflection()) {
          auto& global = module->globals[exp.index];
          type_value =
              GetTypeForGlobal(isolate, global.mutability, global.type);
        }
        export_kind = global_string;
        break;
      case kExternalTag:
        export_kind = tag_string;
        break;
      default:
        UNREACHABLE();
    }

    Handle<JSObject> entry = factory->NewJSObject(object_function);

    DirectHandle<String> export_name =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate, module_object, exp.name, kNoInternalize);

    JSObject::AddProperty(isolate, entry, name_string, export_name, NONE);
    JSObject::AddProperty(isolate, entry, kind_string, export_kind, NONE);
    if (!type_value.is_null()) {
      JSObject::AddProperty(isolate, entry, type_string, type_value, NONE);
    }

    storage->set(index, *entry);
  }

  return array_object;
}

Handle<JSArray> GetCustomSections(Isolate* isolate,
                                  DirectHandle<WasmModuleObject> module_object,
                                  DirectHandle<String> name,
                                  ErrorThrower* thrower) {
  Factory* factory = isolate->factory();

  base::Vector<const uint8_t> wire_bytes =
      module_object->native_module()->wire_bytes();
  std::vector<CustomSectionOffset> custom_sections =
      DecodeCustomSections(wire_bytes);

  std::vector<Handle<Object>> matching_sections;

  // Gather matching sections.
  for (auto& section : custom_sections) {
    DirectHandle<String> section_name =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate, module_object, section.name, kNoInternalize);

    if (!name->Equals(*section_name)) continue;

    // Make a copy of the payload data in the section.
    size_t size = section.payload.length();
    MaybeHandle<JSArrayBuffer> result =
        isolate->factory()->NewJSArrayBufferAndBackingStore(
            size, InitializedFlag::kUninitialized);
    Handle<JSArrayBuffer> array_buffer;
    if (!result.ToHandle(&array_buffer)) {
      thrower->RangeError("out of memory allocating custom section data");
      return Handle<JSArray>();
    }
    memcpy(array_buffer->backing_store(),
           wire_bytes.begin() + section.payload.offset(),
           section.payload.length());

    matching_sections.push_back(array_buffer);
  }

  int num_custom_sections = static_cast<int>(matching_sections.size());
  Handle<JSArray> array_object = factory->NewJSArray(PACKED_ELEMENTS, 0, 0);
  Handle<FixedArray> storage = factory->NewFixedArray(num_custom_sections);
  JSArray::SetContent(array_object, storage);
  array_object->set_length(Smi::FromInt(num_custom_sections));

  for (int i = 0; i < num_custom_sections; i++) {
    storage->set(i, *matching_sections[i]);
  }

  return array_object;
}

// Get the source position from a given function index and wire bytes offset
// (relative to the function entry), for either asm.js or pure Wasm modules.
int GetSourcePosition(const WasmModule* module, uint32_t func_index,
                      uint32_t byte_offset, bool is_at_number_conversion) {
  DCHECK_EQ(is_asmjs_module(module),
            module->asm_js_offset_information != nullptr);
  if (!is_asmjs_module(module)) {
    // For non-asm.js modules, we just add the function's start offset
    // to make a module-relative position.
    return byte_offset + GetWasmFunctionOffset(module, func_index);
  }

  // asm.js modules have an additional offset table that must be searched.
  return module->asm_js_offset_information->GetSourcePosition(
      declared_function_index(module, func_index), byte_offset,
      is_at_number_conversion);
}

size_t WasmModule::EstimateStoredSize() const {
  UPDATE_WHEN_CLASS_CHANGES(WasmModule,
#if V8_ENABLE_DRUMBRAKE
                            896
#else   // V8_ENABLE_DRUMBRAKE
                            832
#endif  // V8_ENABLE_DRUMBRAKE
  );
  return sizeof(WasmModule) +                            // --
         signature_zone.allocation_size_for_tracing() +  // --
         ContentSize(types) +                            // --
         ContentSize(isorecursive_canonical_type_ids) +  // --
         ContentSize(functions) +                        // --
         ContentSize(globals) +                          // --
         ContentSize(data_segments) +                    // --
         ContentSize(tables) +                           // --
         ContentSize(memories) +                         // --
         ContentSize(import_table) +                     // --
         ContentSize(export_table) +                     // --
         ContentSize(tags) +                             // --
         ContentSize(stringref_literals) +               // --
         ContentSize(elem_segments) +                    // --
         ContentSize(compilation_hints) +                // --
         ContentSize(branch_hints) +                     // --
         ContentSize(inst_traces) +                      // --
         (num_declared_functions + 7) / 8;               // validated_functions
}

template <class Value>
size_t AdaptiveMap<Value>::EstimateCurrentMemoryConsumption() const {
  UNREACHABLE();  // Explicit implementations below.
}

template <>
size_t NameMap::EstimateCurrentMemoryConsumption() const {
  size_t result = ContentSize(vector_);
  if (map_) result += ContentSize(*map_);
  return result;
}

size_t LazilyGeneratedNames::EstimateCurrentMemoryConsumption() const {
  base::MutexGuard lock(&mutex_);
  return function_names_.EstimateCurrentMemoryConsumption();
}

template <>
size_t IndirectNameMap::EstimateCurrentMemoryConsumption() const {
  size_t result = ContentSize(vector_);
  for (const auto& inner_map : vector_) {
    result += inner_map.EstimateCurrentMemoryConsumption();
  }
  if (map_) {
    result += ContentSize(*map_);
    for (const auto& [outer_index, inner_map] : *map_) {
      result += inner_map.EstimateCurrentMemoryConsumption();
    }
  }
  return result;
}

size_t TypeFeedbackStorage::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(TypeFeedbackStorage, 152);
  UPDATE_WHEN_CLASS_CHANGES(FunctionTypeFeedback, 48);
  // Not including sizeof(TFS) because that's contained in sizeof(WasmModule).
  base::SharedMutexGuard<base::kShared> lock(&mutex);
  size_t result = ContentSize(feedback_for_function);
  for (const auto& [func_idx, feedback] : feedback_for_function) {
    result += ContentSize(feedback.feedback_vector);
    result += feedback.call_targets.size() * sizeof(uint32_t);
  }
  result += ContentSize(deopt_count_for_function);
  // The size of {well_known_imports} can only be estimated at the WasmModule
  // level.
  if (v8_flags.trace_wasm_offheap_memory) {
    PrintF("TypeFeedback: %zu\n", result);
  }
  return result;
}

size_t WasmModule::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(WasmModule,
#if V8_ENABLE_DRUMBRAKE
                            896
#else   // V8_ENABLE_DRUMBRAKE
                            832
#endif  // V8_ENABLE_DRUMBRAKE
  );
  size_t result = EstimateStoredSize();

  result += type_feedback.EstimateCurrentMemoryConsumption();
  // For type_feedback.well_known_imports:
  result += num_imported_functions * sizeof(WellKnownImport);

  result += lazily_generated_names.EstimateCurrentMemoryConsumption();

  if (v8_flags.trace_wasm_offheap_memory) {
    PrintF("WasmModule: %zu\n", result);
  }
  return result;
}

size_t PrintSignature(base::Vector<char> buffer, const CanonicalSig* sig,
                      char delimiter) {
  if (buffer.empty()) return 0;
  size_t old_size = buffer.size();
  auto append_char = [&buffer](char c) {
    if (buffer.size() == 1) return;  // Keep last character for '\0'.
    buffer[0] = c;
    buffer += 1;
  };
  for (CanonicalValueType t : sig->parameters()) {
    append_char(t.short_name());
  }
  append_char(delimiter);
  for (CanonicalValueType t : sig->returns()) {
    append_char(t.short_name());
  }
  buffer[0] = '\0';
  return old_size - buffer.size();
}

int JumpTableOffset(const WasmModule* module, int func_index) {
  return JumpTableAssembler::JumpSlotIndexToOffset(
      declared_function_index(module, func_index));
}

size_t GetWireBytesHash(base::Vector<const uint8_t> wire_bytes) {
  return StringHasher::HashSequentialString(
      reinterpret_cast<const char*>(wire_bytes.begin()), wire_bytes.length(),
      kZeroHashSeed);
}

int NumFeedbackSlots(const WasmModule* module, int func_index) {
  base::SharedMutexGuard<base::kShared> type_feedback_guard{
      &module->type_feedback.mutex};
  auto it = module->type_feedback.feedback_for_function.find(func_index);
  if (it == module->type_feedback.feedback_for_function.end()) return 0;
  // The number of call instructions is capped by max function size.
  static_assert(kV8MaxWasmFunctionSize < std::numeric_limits<int>::max() / 2);
  return static_cast<int>(2 * it->second.call_targets.size());
}

}  // namespace v8::internal::wasm

"""

```