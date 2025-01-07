Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Request:** The core request is to analyze the C++ source code of `v8/src/wasm/wasm-module.cc` and provide insights into its functionality, potential JavaScript connections, logical reasoning, and common user errors.

2. **Initial Scan and Keyword Identification:**  The first step is to quickly scan the code, looking for keywords and familiar C++ constructs that give clues about its purpose. Keywords like `wasm`, `module`, `import`, `export`, `function`, `table`, `memory`, `global`, `type`, `JSObject`, `Isolate`, etc., immediately signal that this code is related to WebAssembly within the V8 JavaScript engine. The `#include` directives confirm dependencies on other V8 components like the compiler and object system.

3. **High-Level Purpose Inference:** Based on the keywords, the file seems to be responsible for representing and managing WebAssembly modules within V8. This includes storing information about imports, exports, functions, memory, tables, and types.

4. **Section-by-Section Analysis (Iterative Refinement):** Now, delve into the code section by section, understanding the purpose of each part.

   * **Includes:**  These provide context about the dependencies. Note the inclusion of headers for API, compiler, objects, and other WASM-specific components.

   * **Namespaces:**  The code is within `v8::internal::wasm`, which confirms its internal V8 and WebAssembly context.

   * **Static Assertions:** These are compile-time checks, indicating constraints on the code (like `kV8MaxRttSubtypingDepth`).

   * **Templates (`AdaptiveMap`):**  Recognize this as a data structure likely used for efficient storage and lookup of data related to the module. The `FinishInitialization` method hints at a transition from a sparse map to a dense vector for performance.

   * **`LazilyGeneratedNames`:**  The name suggests that function names are not always decoded upfront but only when needed. The `LookupFunctionName` and `Has` methods confirm this. The mutex suggests thread-safety.

   * **`GetWasmFunctionOffset`, `GetNearestWasmFunction`, `GetContainingWasmFunction`:** These functions clearly deal with locating functions within the module's bytecode based on offsets. This is crucial for debugging and potentially for runtime execution.

   * **`AsmJsOffsetInformation`:** This class is specifically for asm.js, indicating that this module handles both standard WebAssembly and its predecessor. The methods relate to mapping bytecode offsets to source positions, essential for debugging asm.js code.

   * **`ModuleWireBytes`:** This appears to be a wrapper around the raw bytes of the WebAssembly module. The `GetNameOrNull` functions retrieve names from these raw bytes.

   * **`WasmModule` Class:** This is the central data structure for representing a WebAssembly module. Examine its member variables (vectors for functions, globals, tables, memories, imports, exports, etc.) to understand the information it stores. The `EstimateStoredSize` and `EstimateCurrentMemoryConsumption` methods are for memory management and debugging.

   * **`IsWasmCodegenAllowed` and `ErrorStringForCodegen`:** These functions are related to security and error reporting during the compilation process.

   * **`GetTypeForFunction`, `GetTypeForGlobal`, `GetTypeForMemory`, `GetTypeForTable`:** These functions are responsible for creating JavaScript objects that represent the types of WebAssembly entities (functions, globals, etc.). This is crucial for the JavaScript API to interact with WebAssembly modules reflectively.

   * **`GetImports` and `GetExports`:** These functions extract information about the module's imports and exports and create JavaScript arrays of objects to represent them. This is a key part of the WebAssembly JavaScript API.

   * **`GetCustomSections`:** This function allows access to custom sections within the WebAssembly module, which can be used for various metadata or extensions.

   * **`GetSourcePosition`:** This is a generalized function to get source positions, handling both standard WebAssembly and asm.js cases.

   * **`PrintSignature`, `JumpTableOffset`, `GetWireBytesHash`, `NumFeedbackSlots`:** These are utility functions for debugging, code generation, and potentially performance optimization.

5. **Identifying JavaScript Connections:**  Look for places where the C++ code interacts with JavaScript concepts:

   * **`Handle<JSObject>` and related types:**  These clearly indicate the creation and manipulation of JavaScript objects.
   * **Function names like `GetImports` and `GetExports`:** These directly correspond to methods in the WebAssembly JavaScript API.
   * **Creation of JavaScript arrays and objects:**  The code explicitly creates `JSArray` and `JSObject` instances to represent module metadata.
   * **Use of `Isolate` and `Factory`:** These are core V8 components for managing the JavaScript heap and creating objects.

6. **Inferring Logical Reasoning and Providing Examples:** When you see functions like `GetNearestWasmFunction` (using binary search), you can explain the logic behind it and provide hypothetical inputs and outputs to illustrate its behavior. Similarly, for the `AdaptiveMap`, you can explain the transition logic.

7. **Considering Common User Errors:** Think about how users might interact with WebAssembly and what mistakes they could make. For example, trying to access an export that doesn't exist or passing incorrect types to imported functions.

8. **Structuring the Output:** Organize the findings into logical sections as requested: functionality, JavaScript relationship (with examples), logical reasoning (with examples), and common errors (with examples).

9. **Refinement and Review:**  After the initial analysis, review the findings for accuracy and completeness. Ensure that the explanations are clear and concise and that the examples are relevant. Double-check for any missed connections or potential misunderstandings of the code. For instance, initially, I might have missed the nuances of the `AdaptiveMap` and its performance implications. Reviewing would prompt me to add that. Similarly, carefully considering the purpose of `AsmJsOffsetInformation` is crucial to understanding the code's full scope.
This C++ source file, `v8/src/wasm/wasm-module.cc`, plays a crucial role in how the V8 JavaScript engine handles WebAssembly (Wasm) modules. Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Represents and Manages Wasm Module Data:** This file defines the `WasmModule` class, which serves as the central data structure to hold all the information parsed from a Wasm binary. This includes:
    * **Function Definitions:**  Details about each function in the module (signature, code offsets, etc.).
    * **Global Variables:** Information about global variables (type, mutability).
    * **Memory:**  Configuration of linear memory (initial and maximum size, shared status).
    * **Tables:**  Configuration of tables (element type, initial and maximum size).
    * **Imports:**  Details about imported functions, memories, tables, and globals from the host environment (JavaScript).
    * **Exports:**  Details about functions, memories, tables, and globals exported by the Wasm module.
    * **Custom Sections:**  Access to raw data in custom sections of the Wasm binary.
    * **Type Information:**  Information about function signatures and other types defined in the module.
    * **Debugging Information:**  (Potentially) information for source maps and debugging.
    * **Lazy Name Generation:**  Mechanism to delay the decoding of function names until needed.

2. **Provides Utilities for Accessing Module Information:** The file includes various functions to retrieve specific information from a `WasmModule` object, such as:
    * `GetWasmFunctionOffset`:  Gets the byte offset of a function's code within the module.
    * `GetNearestWasmFunction`, `GetContainingWasmFunction`:  Locates the function containing a specific byte offset, useful for debugging and error reporting.
    * `GetImports`, `GetExports`:  Creates JavaScript objects representing the module's imports and exports.
    * `GetCustomSections`: Retrieves the content of custom sections as ArrayBuffers.
    * `GetSourcePosition`: Maps a byte offset within the Wasm code back to a source code position (especially relevant for asm.js).

3. **Handles Asm.js Specifics:** The `AsmJsOffsetInformation` class specifically deals with mapping byte offsets in asm.js modules to their original JavaScript source code positions. This is necessary because asm.js is a strict subset of JavaScript that can be optimized similarly to Wasm.

4. **Supports Type Reflection:**  Functions like `GetTypeForFunction`, `GetTypeForGlobal`, `GetTypeForMemory`, and `GetTypeForTable` are used to create JavaScript objects that represent the types of Wasm entities. This enables JavaScript code to inspect the structure of a Wasm module.

5. **Manages Lazy Decoding of Names:** The `LazilyGeneratedNames` class provides a way to decode function names from the Wasm binary only when they are needed, improving performance during initial module loading.

6. **Estimates Memory Consumption:** Functions like `EstimateStoredSize` and `EstimateCurrentMemoryConsumption` are used for tracking the memory usage of `WasmModule` objects, aiding in memory management within V8.

**Is `v8/src/wasm/wasm-module.cc` a Torque Source File?**

No, `v8/src/wasm/wasm-module.cc` is **not** a Torque source file. Torque files have the `.tq` extension. This file is standard C++ code.

**Relationship with JavaScript and Examples:**

This file has a direct relationship with JavaScript because it provides the underlying data structures and logic that make Wasm modules accessible and usable from JavaScript. The functions that create JavaScript objects to represent Wasm entities are a key part of this interaction.

**Example:** The `GetImports` function directly relates to the `WebAssembly.Module.imports()` method in JavaScript.

```javascript
// Assume 'wasmModule' is a compiled WebAssembly.Module instance

const imports = WebAssembly.Module.imports(wasmModule);

imports.forEach(imp => {
  console.log(`Import: module="${imp.module}", name="${imp.name}", kind="${imp.kind}"`);
  if (imp.kind === 'function') {
    // If type reflection is enabled, 'imp.type' might exist
    if (imp.type) {
      console.log("  Parameters:", imp.type.parameters.map(p => p));
      console.log("  Results:", imp.type.results.map(r => r));
    }
  }
  // ... handle other import kinds (table, memory, global)
});
```

In this JavaScript example, `WebAssembly.Module.imports(wasmModule)` internally calls code that utilizes the information stored in the `WasmModule` object (created from `v8/src/wasm/wasm-module.cc`) and populated by the `GetImports` function in that C++ file. The `imp.kind` and potentially `imp.type` properties of each import object are derived from the data managed by `wasm-module.cc`.

Similarly, `WebAssembly.Module.exports(wasmModule)` relies on the `GetExports` function in `wasm-module.cc`.

```javascript
const exports = WebAssembly.Module.exports(wasmModule);

exports.forEach(exp => {
  console.log(`Export: name="${exp.name}", kind="${exp.kind}"`);
  if (exp.kind === 'function') {
    // If type reflection is enabled, 'exp.type' might exist
    if (exp.type) {
      console.log("  Parameters:", exp.type.parameters.map(p => p));
      console.log("  Results:", exp.type.results.map(r => r));
    }
  }
  // ... handle other export kinds
});
```

**Code Logic Reasoning with Hypothetical Input and Output:**

Let's consider the `GetNearestWasmFunction` function:

**Hypothetical Input:**

* `module`: A `WasmModule` object with the following function offsets:
    * Function 0: offset 0
    * Function 1: offset 100
    * Function 2: offset 250
    * Function 3: offset 400
* `byte_offset`: 150

**Logic:**

The function performs a binary search on the sorted list of function offsets.

1. `left = 0`, `right = 4`
2. `mid = 2`. `functions[2].code.offset()` (250) is greater than `byte_offset` (150). `right` becomes 2.
3. `left = 0`, `right = 2`
4. `mid = 1`. `functions[1].code.offset()` (100) is less than or equal to `byte_offset` (150). `left` becomes 1.
5. `right - left` (2 - 1 = 1), loop terminates.

**Hypothetical Output:**

The function returns `left`, which is `1`. This indicates that the nearest function whose starting offset is less than or equal to the given `byte_offset` is Function 1.

**Common User Programming Errors:**

While this C++ file isn't directly written by users, the logic it implements helps prevent or expose errors in user-written JavaScript and WebAssembly code. Here are examples of user errors that are related to the functionalities in this file:

1. **Incorrectly Assuming Export Names:** If a user tries to access an export by a name that doesn't exist in the module's export table, the JavaScript `instance.exports` object will not have that property. The `GetExports` function plays a role in defining what exports are available.

   **Example:**

   **Wasm Module (hypothetical):** Exports a function named "add".

   **JavaScript Error:**

   ```javascript
   const instance = await WebAssembly.instantiateStreaming(...);
   instance.exports.addition(5, 3); // Error! "addition" is not exported, "add" is.
   ```

2. **Type Mismatches with Imports/Exports:**  If the user attempts to pass arguments of the wrong type to an imported or exported Wasm function, or if the return type doesn't match expectations, the Wasm execution might trap or produce unexpected results. The type information managed in `wasm-module.cc` and exposed through the reflection API can help users understand these type requirements.

   **Example:**

   **Wasm Module (hypothetical):** Imports a JavaScript function that expects an integer and returns an integer.

   **JavaScript Error:**

   ```javascript
   const importObject = {
     env: {
       importedFunc: (val) => {
         console.log("Received:", val);
         return "not an integer"; // Incorrect return type
       },
     },
   };
   const instance = await WebAssembly.instantiateStreaming(response, importObject);
   instance.exports.callImportedFunc(10); // May lead to a Wasm trap or unexpected behavior
   ```

3. **Trying to Access Non-Existent Imports:**  Similar to exports, if JavaScript code tries to provide an import that the Wasm module doesn't declare, the instantiation process will fail. The `GetImports` function helps define the required imports.

   **Example:**

   **Wasm Module (hypothetical):** Imports a function named "log" from the "console" module.

   **JavaScript Error:**

   ```javascript
   const importObject = {
     // Missing the 'console' module
     // env: { log: (msg) => console.log(msg) }
   };
   try {
     await WebAssembly.instantiateStreaming(response, importObject); // Instantiation error
   } catch (e) {
     console.error("Instantiation failed:", e);
   }
   ```

In summary, `v8/src/wasm/wasm-module.cc` is a foundational file for WebAssembly support in V8. It defines the core representation of Wasm modules and provides essential utilities for accessing and understanding their structure, directly impacting how JavaScript interacts with Wasm.

Prompt: 
```
这是目录为v8/src/wasm/wasm-module.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-module.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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