Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for the functionality of `wasm-run-utils.cc`, specifically focusing on its role in testing WebAssembly within the V8 engine. It also asks about potential Torque (.tq) files, JavaScript connections, logic/reasoning, and common programming errors.

2. **Initial Scan and Keyword Recognition:**  Immediately scan the code for recognizable patterns and keywords:
    * `#include`:  Indicates dependencies on other V8 components. Pay attention to what's being included (e.g., `assembler-inl.h`, `pipeline.h`, `wasm/...`). This gives a high-level idea of the areas the code interacts with.
    * `namespace v8::internal::wasm`: Confirms this is within the WebAssembly part of V8.
    * Class names like `TestingModuleBuilder`, `WasmFunctionCompiler`, `WasmRunnerBase`: These are the core building blocks. Focus on what these classes *do*.
    * Function names like `AddMemory`, `AddFunction`, `WrapCode`, `AddIndirectFunctionTable`, `Build`:  These are the actions the utility provides.
    * Data structures related to WebAssembly: `WasmModule`, `WasmInstanceObject`, `WasmCode`, `FunctionSig`, `WasmTableObject`, etc. This reinforces that the file is about manipulating and creating WebAssembly structures.
    * Testing-related terms:  "Test", "TestingModuleBuilder", "fuzzing".

3. **Focus on `TestingModuleBuilder`:** This class appears central. Analyze its constructor and methods:
    * **Constructor:** Takes parameters like `ModuleOrigin`, `ManuallyImportedJSFunction`, `TestExecutionTier`, `Isolate`. This suggests it sets up a testing environment for different types of modules and execution scenarios. The `maybe_import` parameter hints at testing interactions with JavaScript.
    * **`AddMemory`:**  Clearly responsible for setting up the WebAssembly memory. Look at how it interacts with `WasmMemoryObject`.
    * **`AddFunction`:** Adds functions to the module. Note the `kImport` function type, further suggesting JS interaction.
    * **`WrapCode`:** Creates a JavaScript function wrapper around a WebAssembly function. This is a *key* connection to JavaScript.
    * **`AddIndirectFunctionTable`:** Deals with function tables, essential for function calls through indices.
    * **`AddBytes`:**  Manipulates the raw bytecode of the WebAssembly module.
    * **`AddException`:** Adds exception handling capabilities.
    * **`AddGlobal`:** Defines global variables.
    * **`InitInstanceObject`:** Creates the `WasmInstanceObject`, which is crucial for executing WebAssembly. The comments about tiering and native modules are important.

4. **Analyze `WasmFunctionCompiler`:** This class seems focused on constructing the *content* of a WebAssembly function:
    * **`Build`:**  Takes bytecode, prepends local declarations, appends an end opcode. It then involves validation and compilation. Notice the conditional compilation based on `TestExecutionTier` and the mention of Liftoff.
    * **Constructor:** Takes a `FunctionSig`, `TestingModuleBuilder`, and a name, indicating it's associated with a specific function within a test module.

5. **Analyze `WasmRunnerBase`:** This appears to be a utility for creating `FunctionSig` objects, which describe the signature (parameters and return types) of a function.

6. **Address Specific Questions:** Now go back through the request and address each point:
    * **Functionality:** Summarize the roles of the key classes and methods based on the analysis above. Emphasize its use in *testing*.
    * **Torque:** Explicitly state that `.cc` extension means it's C++, not Torque.
    * **JavaScript Relationship:** Highlight `WrapCode` as the primary connection. Provide a simple JavaScript example of calling a wrapped Wasm function.
    * **Logic/Reasoning:** Focus on `IsSameNan`. Explain the input (two NaN values), the logic (ignoring the sign bit, handling signaling vs. quiet NaNs), and provide examples of inputs and expected outputs.
    * **Common Programming Errors:** Think about typical WebAssembly development errors that this utility might help catch. Focus on type mismatches and out-of-bounds access as they are relevant to the structures being manipulated. Provide concrete C++ examples of how these errors might be triggered within the testing context.

7. **Structure and Refine:** Organize the findings logically with clear headings and bullet points. Use precise language. Ensure the examples are concise and illustrate the points effectively. Review for clarity and completeness. For example, initially, I might have just said "manages memory."  Refining this to "Allocating and managing linear memory for the WebAssembly module" is more precise. Similarly, just saying "adds functions" isn't as informative as explaining the different types of functions (imported, declared).

8. **Self-Correction/Refinement During the Process:**
    * **Initial thought:**  Maybe it's heavily involved in the *execution* of Wasm. **Correction:** Closer inspection reveals it's primarily about *setting up* and *compiling* test modules, not the main execution engine.
    * **Missing detail:** Initially overlooked the purpose of `AddBytes`. **Correction:** Realized it's for directly manipulating the module's bytecode, essential for fine-grained testing.
    * **Vague language:**  Initially used terms like "deals with." **Correction:** Switched to more active and descriptive verbs like "allocates," "adds," "creates," "compiles."

By following this structured analysis, focusing on the core components, and systematically addressing each part of the request, a comprehensive and accurate explanation can be generated.
`v8/test/cctest/wasm/wasm-run-utils.cc` 是 V8 引擎中用于 WebAssembly 单元测试的辅助工具代码。它提供了一系列类和函数，用于方便地构建、配置和运行 WebAssembly 模块以进行测试。

以下是该文件的主要功能列表：

**核心类:**

* **`TestingModuleBuilder`:**  这是构建 WebAssembly 测试模块的核心类。它允许你以编程方式构建一个 WebAssembly 模块，而无需手动编写 WebAssembly 二进制代码。其功能包括：
    * **添加内存 (`AddMemory`)**:  定义模块的线性内存，包括初始大小、最大大小和共享属性。
    * **添加函数 (`AddFunction`)**:  声明或导入函数，指定其签名（参数和返回值类型）。
    * **包装代码 (`WrapCode`)**:  将一个 WebAssembly 函数封装成 JavaScript 函数，使其可以在 JavaScript 代码中被调用。
    * **添加间接函数表 (`AddIndirectFunctionTable`)**:  创建和初始化函数表，用于 `call_indirect` 指令。
    * **添加字节 (`AddBytes`)**:  向模块的字节码中添加原始字节，用于更底层的控制。
    * **添加异常标签 (`AddException`)**:  定义异常标签，用于测试 WebAssembly 的异常处理。
    * **添加被动数据段 (`AddPassiveDataSegment`)**:  添加不会立即加载到内存的数据段。
    * **添加全局变量 (`AddGlobal`)**:  声明模块的全局变量。
    * **初始化实例对象 (`InitInstanceObject`)**: 创建 `WasmInstanceObject`，它是 WebAssembly 模块的运行时实例。
    * **初始化包装器缓存 (`InitializeWrapperCache`)**:  为模块的类型创建必要的 JavaScript 对象映射。

* **`WasmFunctionCompiler`:** 用于构建单个 WebAssembly 函数的代码。
    * **`Build`**:  将本地变量声明和函数体字节码组合成完整的函数代码，并进行验证和编译。

* **`WasmRunnerBase`:**  提供创建 `FunctionSig`（函数签名）的静态辅助方法。

**辅助功能:**

* **`IsSameNan` (多个重载版本):**  比较两个浮点数或双精度浮点数是否都是 NaN (Not-a-Number)。由于 NaN 的符号位是不确定的，这个函数会忽略符号位进行比较，并考虑某些实现可能将 signaling NaN 转换为 quiet NaN 的情况。

**关于文件扩展名和 Torque:**

`v8/test/cctest/wasm/wasm-run-utils.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。根据你提供的规则，如果文件以 `.tq` 结尾，它才是 V8 Torque 源代码。因此，`wasm-run-utils.cc` **不是** Torque 代码。

**与 JavaScript 的关系及示例:**

`wasm-run-utils.cc` 的主要目的是为了方便测试 WebAssembly，而 WebAssembly 经常需要与 JavaScript 交互。 该文件通过 `TestingModuleBuilder::WrapCode` 方法建立了与 JavaScript 的直接联系。这个方法可以将一个已编译的 WebAssembly 函数包装成一个普通的 JavaScript 函数对象，这样就可以在 JavaScript 代码中像调用普通函数一样调用 WebAssembly 函数。

**JavaScript 示例:**

假设我们使用 `TestingModuleBuilder` 创建了一个简单的 WebAssembly 模块，其中有一个将两个整数相加的函数：

```c++
// C++ 代码 (使用 wasm-run-utils.cc)
TestingModuleBuilder builder;
WasmFunctionCompiler compiler(nullptr, wasm::WasmRunnerBase::CreateSig(CcTest::isolate()->heap()->zone(), wasm::MachineType::Int32(), {wasm::MachineType::Int32(), wasm::MachineType::Int32()}), &builder, "add");
compiler.Build({wasm::kI32Const, 0, wasm::kLocalGet, 0, wasm::kI32Const, 0, wasm::kLocalGet, 1, wasm::kI32Add, wasm::kReturn});
Handle<JSFunction> add_js_func = builder.WrapCode(0);
```

现在，在 JavaScript 中就可以调用 `add_js_func` 了：

```javascript
// JavaScript 代码
const result = add_js_func(5, 3);
console.log(result); // 输出: 8
```

在这个例子中，`TestingModuleBuilder::WrapCode(0)` 返回的 `add_js_func` 就是一个可以直接在 JavaScript 中调用的函数，它实际上执行的是 WebAssembly 代码。

**代码逻辑推理 (以 `IsSameNan` 为例):**

**假设输入：**

* `expected` (float): `NaN` (例如，通过 `0.0 / 0.0` 得到)
* `actual` (float):  也是 `NaN`，但符号位可能不同，或者可能是 signaling NaN。

**输出：**

* `true`

**逻辑推理:**

`IsSameNan(float expected, float actual)` 函数的逻辑如下：

1. **提取位表示并清除符号位:**
   - `expected_bits = base::bit_cast<uint32_t>(expected) & ~0x80000000;`  将 `expected` 的浮点数表示转换为 32 位整数，并清除最高位（符号位）。
   - `actual_bits = base::bit_cast<uint32_t>(actual) & ~0x80000000;` 对 `actual` 执行相同的操作。

2. **直接比较清除符号位后的位表示:**
   - `(expected_bits == actual_bits)`: 如果清除符号位后的位表示完全相同，则认为是同一个 NaN。

3. **考虑 Signaling NaN 到 Quiet NaN 的转换:**
   - `((expected_bits | 0x00400000) == actual_bits)`: 某些处理器或实现可能会将 signaling NaN 转换为 quiet NaN。Quiet NaN 的特定位模式与 signaling NaN 只有一位不同（通常是 significand 的最高位）。这个条件检查了 `expected` 是 signaling NaN，而 `actual` 是对应的 quiet NaN 的情况。

**示例输入和输出:**

* **输入:** `expected = std::numeric_limits<float>::quiet_NaN(); actual = std::numeric_limits<float>::quiet_NaN();`  **输出:** `true`
* **输入:** `expected = -std::numeric_limits<float>::quiet_NaN(); actual = std::numeric_limits<float>::quiet_NaN();` **输出:** `true` (忽略符号位)
* **输入:** `expected = std::numeric_limits<float>::signaling_NaN(); actual = std::numeric_limits<float>::quiet_NaN();` **输出:** `true` (处理了 signaling 到 quiet 的转换)

**用户常见的编程错误 (与 WebAssembly 测试相关):**

使用像 `wasm-run-utils.cc` 这样的工具进行 WebAssembly 测试时，用户可能会犯以下编程错误：

1. **函数签名不匹配:**
   - **错误示例 (C++):**  在 `TestingModuleBuilder::AddFunction` 中指定的函数签名与实际编译的函数体不匹配。
   - **后果:**  在调用 WebAssembly 函数时，可能会导致栈溢出、类型错误或程序崩溃。

2. **内存访问越界:**
   - **错误示例 (C++):**  在 WebAssembly 函数的实现中，尝试读取或写入超出已分配内存范围的地址。
   - **后果:**  可能导致程序崩溃或产生不可预测的结果。`TestingModuleBuilder::AddMemory` 用于设置内存大小，如果测试中 WebAssembly 代码试图访问超出此范围的内存，可能会暴露这类错误。

3. **类型错误 (例如，在函数调用时传递错误的参数类型):**
   - **错误示例 (JavaScript):**  在调用通过 `WrapCode` 包装的 WebAssembly 函数时，传递的参数类型与函数签名不符。
   - **后果:**  WebAssembly 引擎可能会抛出异常或产生错误的结果。

4. **未正确初始化全局变量:**
   - **错误示例 (C++):**  在测试中依赖于全局变量的初始值，但 WebAssembly 模块的初始化逻辑存在问题，导致全局变量未被正确初始化。
   - **后果:**  程序的行为可能不符合预期。

5. **间接调用时函数表索引越界或类型不匹配:**
   - **错误示例 (C++):**  在使用 `call_indirect` 指令时，提供的索引超出了函数表的大小，或者函数表中存储的函数签名与调用的签名不匹配。
   - **后果:**  可能导致程序崩溃或类型错误。`TestingModuleBuilder::AddIndirectFunctionTable` 用于设置函数表，测试可以验证间接调用的正确性。

**总结:**

`v8/test/cctest/wasm/wasm-run-utils.cc` 是一个关键的测试基础设施组件，它简化了 WebAssembly 模块的创建、配置和执行，使得 V8 团队能够有效地测试 WebAssembly 功能的各个方面，包括与 JavaScript 的互操作。它提供的工具可以帮助发现各种潜在的编程错误，确保 WebAssembly 引擎的正确性和稳定性。

Prompt: 
```
这是目录为v8/test/cctest/wasm/wasm-run-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/wasm-run-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/cctest/wasm/wasm-run-utils.h"

#include <optional>

#include "src/codegen/assembler-inl.h"
#include "src/compiler/pipeline.h"
#include "src/diagnostics/code-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/wasm/baseline/liftoff-compiler.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/graph-builder-interface.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8 {
namespace internal {
namespace wasm {

// Helper Functions.
bool IsSameNan(uint16_t expected, uint16_t actual) {
  // Sign is non-deterministic.
  uint16_t expected_bits = expected & ~0x8000;
  uint16_t actual_bits = actual & ~0x8000;
  return (expected_bits == actual_bits);
}

bool IsSameNan(float expected, float actual) {
  // Sign is non-deterministic.
  uint32_t expected_bits = base::bit_cast<uint32_t>(expected) & ~0x80000000;
  uint32_t actual_bits = base::bit_cast<uint32_t>(actual) & ~0x80000000;
  // Some implementations convert signaling NaNs to quiet NaNs.
  return (expected_bits == actual_bits) ||
         ((expected_bits | 0x00400000) == actual_bits);
}

bool IsSameNan(double expected, double actual) {
  // Sign is non-deterministic.
  uint64_t expected_bits =
      base::bit_cast<uint64_t>(expected) & ~0x8000000000000000;
  uint64_t actual_bits = base::bit_cast<uint64_t>(actual) & ~0x8000000000000000;
  // Some implementations convert signaling NaNs to quiet NaNs.
  return (expected_bits == actual_bits) ||
         ((expected_bits | 0x0008000000000000) == actual_bits);
}

TestingModuleBuilder::TestingModuleBuilder(
    Zone* zone, ModuleOrigin origin, ManuallyImportedJSFunction* maybe_import,
    TestExecutionTier tier, Isolate* isolate)
    : test_module_(std::make_shared<WasmModule>(origin)),
      isolate_(isolate ? isolate : CcTest::InitIsolateOnce()),
      enabled_features_(WasmEnabledFeatures::FromIsolate(isolate_)),
      execution_tier_(tier) {
  WasmJs::Install(isolate_);
  test_module_->untagged_globals_buffer_size = kMaxGlobalsSize;
  // The GlobalsData must be located inside the sandbox, so allocate it from the
  // ArrayBuffer allocator.
  globals_data_ = reinterpret_cast<uint8_t*>(
      CcTest::array_buffer_allocator()->Allocate(kMaxGlobalsSize));

  uint32_t maybe_import_index = 0;
  if (maybe_import) {
    // Manually add an imported function before any other functions.
    // This must happen before the instance object is created, since the
    // instance object allocates import entries.
    maybe_import_index = AddFunction(maybe_import->sig, nullptr, kImport);
    DCHECK_EQ(0, maybe_import_index);
  }

  instance_object_ = InitInstanceObject();
  trusted_instance_data_ =
      handle(instance_object_->trusted_data(isolate_), isolate_);
  DirectHandle<FixedArray> tables(isolate_->factory()->NewFixedArray(0));
  trusted_instance_data_->set_tables(*tables);

  if (maybe_import) {
    WasmCodeRefScope code_ref_scope;
    // Manually compile an import wrapper and insert it into the instance.
    CanonicalTypeIndex sig_index =
        GetTypeCanonicalizer()->AddRecursiveGroup(maybe_import->sig);
    const wasm::CanonicalSig* sig =
        GetTypeCanonicalizer()->LookupFunctionSignature(sig_index);
    ResolvedWasmImport resolved({}, -1, maybe_import->js_function, sig,
                                sig_index, WellKnownImport::kUninstantiated);
    ImportCallKind kind = resolved.kind();
    DirectHandle<JSReceiver> callable = resolved.callable();
    WasmCode* import_wrapper = GetWasmImportWrapperCache()->MaybeGet(
        kind, sig_index, static_cast<int>(sig->parameter_count()), kNoSuspend);
    if (import_wrapper == nullptr) {
      import_wrapper = CompileImportWrapperForTest(
          isolate_, native_module_, kind, sig, sig_index,
          static_cast<int>(sig->parameter_count()), kNoSuspend);
    }

    ImportedFunctionEntry(trusted_instance_data_, maybe_import_index)
        .SetCompiledWasmToJs(isolate_, callable, import_wrapper,
                             resolved.suspend(), sig);
  }
}

TestingModuleBuilder::~TestingModuleBuilder() {
  // When the native module dies and is erased from the cache, it is expected to
  // have either valid bytes or no bytes at all.
  native_module_->SetWireBytes({});
  CcTest::array_buffer_allocator()->Free(globals_data_, kMaxGlobalsSize);
}

uint8_t* TestingModuleBuilder::AddMemory(uint32_t size, SharedFlag shared,
                                         AddressType address_type,
                                         std::optional<size_t> max_size) {
  // The TestingModuleBuilder only supports one memory currently.
  CHECK_EQ(0, test_module_->memories.size());
  CHECK_NULL(mem0_start_);
  CHECK_EQ(0, mem0_size_);
  CHECK_EQ(0, trusted_instance_data_->memory_objects()->length());

  uint32_t initial_pages = RoundUp(size, kWasmPageSize) / kWasmPageSize;
  uint32_t maximum_pages =
      max_size.has_value()
          ? static_cast<uint32_t>(RoundUp(max_size.value(), kWasmPageSize) /
                                  kWasmPageSize)
          : initial_pages;
  test_module_->memories.resize(1);
  WasmMemory* memory = &test_module_->memories[0];
  memory->initial_pages = initial_pages;
  memory->maximum_pages = maximum_pages;
  memory->address_type = address_type;
  UpdateComputedInformation(memory, test_module_->origin);

  // Create the WasmMemoryObject.
  DirectHandle<WasmMemoryObject> memory_object =
      WasmMemoryObject::New(isolate_, initial_pages, maximum_pages, shared,
                            address_type)
          .ToHandleChecked();
  DirectHandle<FixedArray> memory_objects =
      isolate_->factory()->NewFixedArray(1);
  memory_objects->set(0, *memory_object);
  trusted_instance_data_->set_memory_objects(*memory_objects);

  // Create the memory_bases_and_sizes array.
  DirectHandle<TrustedFixedAddressArray> memory_bases_and_sizes =
      TrustedFixedAddressArray::New(isolate_, 2);
  uint8_t* mem_start = reinterpret_cast<uint8_t*>(
      memory_object->array_buffer()->backing_store());
  memory_bases_and_sizes->set_sandboxed_pointer(
      0, reinterpret_cast<Address>(mem_start));
  memory_bases_and_sizes->set(1, size);
  trusted_instance_data_->set_memory_bases_and_sizes(*memory_bases_and_sizes);

  mem0_start_ = mem_start;
  mem0_size_ = size;
  CHECK(size == 0 || mem0_start_);

  // TODO(14616): Add shared_trusted_instance_data_.
  WasmMemoryObject::UseInInstance(isolate_, memory_object,
                                  trusted_instance_data_,
                                  trusted_instance_data_, 0);
  // TODO(wasm): Delete the following line when test-run-wasm will use a
  // multiple of kPageSize as memory size. At the moment, the effect of these
  // two lines is used to shrink the memory for testing purposes.
  trusted_instance_data_->SetRawMemory(0, mem0_start_, mem0_size_);
  return mem0_start_;
}

uint32_t TestingModuleBuilder::AddFunction(const FunctionSig* sig,
                                           const char* name,
                                           FunctionType type) {
  if (test_module_->functions.size() == 0) {
    // TODO(titzer): Reserving space here to avoid the underlying WasmFunction
    // structs from moving.
    test_module_->functions.reserve(kMaxFunctions);
    DCHECK_NULL(test_module_->validated_functions);
    test_module_->validated_functions =
        std::make_unique<std::atomic<uint8_t>[]>((kMaxFunctions + 7) / 8);
    if (is_asmjs_module(test_module_.get())) {
      // All asm.js functions are valid by design.
      std::fill_n(test_module_->validated_functions.get(),
                  (kMaxFunctions + 7) / 8, 0xff);
    }
    test_module_->type_feedback.well_known_imports.Initialize(kMaxFunctions);
  }
  uint32_t index = static_cast<uint32_t>(test_module_->functions.size());
  test_module_->functions.push_back({sig,                 // sig
                                     index,               // func_index
                                     ModuleTypeIndex{0},  // sig_index
                                     {0, 0},              // code
                                     false,               // imported
                                     false,               // exported
                                     false});             // declared
  if (type == kImport) {
    DCHECK_EQ(0, test_module_->num_declared_functions);
    ++test_module_->num_imported_functions;
    test_module_->functions.back().imported = true;
  } else {
    ++test_module_->num_declared_functions;
  }
  DCHECK_EQ(test_module_->functions.size(),
            test_module_->num_imported_functions +
                test_module_->num_declared_functions);
  if (name) {
    base::Vector<const uint8_t> name_vec =
        base::Vector<const uint8_t>::cast(base::CStrVector(name));
    test_module_->lazily_generated_names.AddForTesting(
        index, {AddBytes(name_vec), static_cast<uint32_t>(name_vec.length())});
  }
  DCHECK_LT(index, kMaxFunctions);  // limited for testing.
  if (!trusted_instance_data_.is_null()) {
    DirectHandle<FixedArray> func_refs =
        isolate_->factory()->NewFixedArrayWithZeroes(
            static_cast<int>(test_module_->functions.size()));
    trusted_instance_data_->set_func_refs(*func_refs);
  }
  return index;
}

void TestingModuleBuilder::InitializeWrapperCache() {
  TypeCanonicalizer::PrepareForCanonicalTypeId(
      isolate_, test_module_->MaxCanonicalTypeIndex());
  Handle<FixedArray> maps = isolate_->factory()->NewFixedArray(
      static_cast<int>(test_module_->types.size()));
  for (uint32_t index = 0; index < test_module_->types.size(); index++) {
    // TODO(14616): Support shared types.
    CreateMapForType(
        isolate_, test_module_.get(), ModuleTypeIndex{index},
        handle(instance_object_->trusted_data(isolate()), isolate()),
        instance_object_, maps);
  }
  trusted_instance_data_->set_managed_object_maps(*maps);
}

Handle<JSFunction> TestingModuleBuilder::WrapCode(uint32_t index) {
  InitializeWrapperCache();
  DirectHandle<WasmFuncRef> func_ref =
      WasmTrustedInstanceData::GetOrCreateFuncRef(
          isolate_, trusted_instance_data_, index);
  DirectHandle<WasmInternalFunction> internal{func_ref->internal(isolate_),
                                              isolate_};
  return WasmInternalFunction::GetOrCreateExternal(internal);
}

void TestingModuleBuilder::AddIndirectFunctionTable(
    const uint16_t* function_indexes, uint32_t table_size,
    ValueType table_type) {
  uint32_t table_index = static_cast<uint32_t>(test_module_->tables.size());
  test_module_->tables.emplace_back();
  WasmTable& table = test_module_->tables.back();
  table.initial_size = table_size;
  table.maximum_size = table_size;
  table.has_maximum_size = true;
  table.type = table_type;

  {
    // Allocate the dispatch table.
    DirectHandle<ProtectedFixedArray> old_dispatch_tables{
        trusted_instance_data_->dispatch_tables(), isolate_};
    DCHECK_EQ(table_index, old_dispatch_tables->length());
    DirectHandle<ProtectedFixedArray> new_dispatch_tables =
        isolate_->factory()->NewProtectedFixedArray(table_index + 1);
    DirectHandle<WasmDispatchTable> new_dispatch_table =
        WasmDispatchTable::New(isolate_, table.initial_size);
    for (int i = 0; i < old_dispatch_tables->length(); ++i) {
      new_dispatch_tables->set(i, old_dispatch_tables->get(i));
    }
    new_dispatch_tables->set(table_index, *new_dispatch_table);
    if (table_index == 0) {
      trusted_instance_data_->set_dispatch_table0(*new_dispatch_table);
    }
    trusted_instance_data_->set_dispatch_tables(*new_dispatch_tables);
  }

  WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
      isolate_, trusted_instance_data_, table_index, table_size);
  DirectHandle<WasmTableObject> table_obj = WasmTableObject::New(
      isolate_, handle(instance_object_->trusted_data(isolate_), isolate_),
      table.type, table.initial_size, table.has_maximum_size,
      table.maximum_size,
      IsSubtypeOf(table.type, kWasmExternRef, test_module_.get())
          ? Handle<HeapObject>{isolate_->factory()->null_value()}
          : Handle<HeapObject>{isolate_->factory()->wasm_null()},
      // TODO(clemensb): Make this configurable.
      wasm::AddressType::kI32);

  WasmTableObject::AddUse(isolate_, table_obj, instance_object_, table_index);

  if (function_indexes) {
    for (uint32_t i = 0; i < table_size; ++i) {
      WasmFunction& function = test_module_->functions[function_indexes[i]];
      CanonicalTypeIndex sig_id =
          test_module_->canonical_sig_id(function.sig_index);
      FunctionTargetAndImplicitArg entry(isolate_, trusted_instance_data_,
                                         function.func_index);
      trusted_instance_data_->dispatch_table(table_index)
          ->Set(i, *entry.implicit_arg(), entry.call_target(), sig_id,
#if V8_ENABLE_DRUMBRAKE
                function.func_index,
#endif  // !V8_ENABLE_DRUMBRAKE
                nullptr, IsAWrapper::kMaybe, WasmDispatchTable::kNewEntry);
      WasmTableObject::SetFunctionTablePlaceholder(
          isolate_, table_obj, i, trusted_instance_data_, function_indexes[i]);
    }
  }

  DirectHandle<FixedArray> old_tables(trusted_instance_data_->tables(),
                                      isolate_);
  DirectHandle<FixedArray> new_tables =
      isolate_->factory()->CopyFixedArrayAndGrow(old_tables, 1);
  new_tables->set(old_tables->length(), *table_obj);
  trusted_instance_data_->set_tables(*new_tables);
}

uint32_t TestingModuleBuilder::AddBytes(base::Vector<const uint8_t> bytes) {
  base::Vector<const uint8_t> old_bytes = native_module_->wire_bytes();
  uint32_t old_size = static_cast<uint32_t>(old_bytes.size());
  // Avoid placing strings at offset 0, this might be interpreted as "not
  // set", e.g. for function names.
  uint32_t bytes_offset = old_size ? old_size : 1;
  size_t new_size = bytes_offset + bytes.size();
  base::OwnedVector<uint8_t> new_bytes =
      base::OwnedVector<uint8_t>::New(new_size);
  if (old_size > 0) {
    memcpy(new_bytes.begin(), old_bytes.begin(), old_size);
  } else {
    // Set the unused byte. It is never decoded, but the bytes are used as the
    // key in the native module cache.
    new_bytes[0] = 0;
  }
  memcpy(new_bytes.begin() + bytes_offset, bytes.begin(), bytes.length());
  native_module_->SetWireBytes(std::move(new_bytes));
  return bytes_offset;
}

uint32_t TestingModuleBuilder::AddException(const FunctionSig* sig) {
  DCHECK_EQ(0, sig->return_count());
  uint32_t index = static_cast<uint32_t>(test_module_->tags.size());
  test_module_->tags.emplace_back(sig, AddSignature(sig));
  DirectHandle<WasmExceptionTag> tag = WasmExceptionTag::New(isolate_, index);
  DirectHandle<FixedArray> table(trusted_instance_data_->tags_table(),
                                 isolate_);
  table = isolate_->factory()->CopyFixedArrayAndGrow(table, 1);
  trusted_instance_data_->set_tags_table(*table);
  table->set(index, *tag);
  return index;
}

uint32_t TestingModuleBuilder::AddPassiveDataSegment(
    base::Vector<const uint8_t> bytes) {
  uint32_t index = static_cast<uint32_t>(test_module_->data_segments.size());
  DCHECK_EQ(index, test_module_->data_segments.size());
  DCHECK_EQ(index, data_segment_starts_.size());
  DCHECK_EQ(index, data_segment_sizes_.size());

  // Add a passive data segment. This isn't used by function compilation, but
  // but it keeps the index in sync. The data segment's source will not be
  // correct, since we don't store data in the module wire bytes.
  test_module_->data_segments.push_back(WasmDataSegment::PassiveForTesting());

  // The num_declared_data_segments (from the DataCount section) is used
  // to validate the segment index, during function compilation.
  test_module_->num_declared_data_segments = index + 1;

  Address old_data_address =
      reinterpret_cast<Address>(data_segment_data_.data());
  size_t old_data_size = data_segment_data_.size();
  data_segment_data_.resize(old_data_size + bytes.length());
  Address new_data_address =
      reinterpret_cast<Address>(data_segment_data_.data());

  memcpy(data_segment_data_.data() + old_data_size, bytes.begin(),
         bytes.length());

  // The data_segment_data_ offset may have moved, so update all the starts.
  for (Address& start : data_segment_starts_) {
    start += new_data_address - old_data_address;
  }
  data_segment_starts_.push_back(new_data_address + old_data_size);
  data_segment_sizes_.push_back(bytes.length());

  // The vector pointers may have moved, so update the instance object.
  uint32_t size = static_cast<uint32_t>(data_segment_sizes_.size());
  DirectHandle<FixedAddressArray> data_segment_starts =
      FixedAddressArray::New(isolate_, size);
  MemCopy(data_segment_starts->begin(), data_segment_starts_.data(),
          size * sizeof(Address));
  trusted_instance_data_->set_data_segment_starts(*data_segment_starts);
  DirectHandle<FixedUInt32Array> data_segment_sizes =
      FixedUInt32Array::New(isolate_, size);
  MemCopy(data_segment_sizes->begin(), data_segment_sizes_.data(),
          size * sizeof(uint32_t));
  trusted_instance_data_->set_data_segment_sizes(*data_segment_sizes);
  return index;
}

const WasmGlobal* TestingModuleBuilder::AddGlobal(ValueType type) {
  uint8_t size = type.value_kind_size();
  global_offset = (global_offset + size - 1) & ~(size - 1);  // align
  test_module_->globals.push_back(
      {type, true, {}, {global_offset}, false, false, false});
  global_offset += size;
  // limit number of globals.
  CHECK_LT(global_offset, kMaxGlobalsSize);
  return &test_module_->globals.back();
}

Handle<WasmInstanceObject> TestingModuleBuilder::InitInstanceObject() {
  // In this test setup, the NativeModule gets allocated before functions get
  // added. The tiering budget array, which gets allocated in the NativeModule
  // constructor, therefore does not have slots for functions that get added
  // later. By disabling dynamic tiering, the tiering budget does not get
  // accessed by generated code.
  FlagScope<bool> no_dynamic_tiering(&v8_flags.wasm_dynamic_tiering, false);
  const bool kUsesLiftoff = true;
  // Compute the estimate based on {kMaxFunctions} because we might still add
  // functions later. Assume 1k of code per function.
  int estimated_code_section_length = kMaxFunctions * 1024;
  size_t code_size_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          kMaxFunctions, 0, estimated_code_section_length, kUsesLiftoff,
          DynamicTiering{v8_flags.wasm_dynamic_tiering.value()});
  auto native_module = GetWasmEngine()->NewNativeModule(
      isolate_, enabled_features_, WasmDetectedFeatures{}, CompileTimeImports{},
      test_module_, code_size_estimate);
  native_module->SetWireBytes(base::OwnedVector<const uint8_t>());
  native_module->compilation_state()->set_compilation_id(0);
  constexpr base::Vector<const char> kNoSourceUrl{"", 0};
  DirectHandle<Script> script =
      GetWasmEngine()->GetOrCreateScript(isolate_, native_module, kNoSourceUrl);
  // Asm.js modules are expected to have "normal" scripts, not Wasm scripts.
  if (is_asmjs_module(native_module->module())) {
    script->set_type(Script::Type::kNormal);
    script->set_infos(ReadOnlyRoots{isolate_}.empty_weak_fixed_array());
  }

  DirectHandle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate_, std::move(native_module), script);
  native_module_ = module_object->native_module();
  native_module_->ReserveCodeTableForTesting(kMaxFunctions);

  DirectHandle<WasmTrustedInstanceData> trusted_data =
      WasmTrustedInstanceData::New(isolate_, module_object, false);
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(trusted_data->has_instance_object());
  Handle<WasmInstanceObject> instance_object =
      handle(trusted_data->instance_object(), isolate_);
  trusted_data->set_tags_table(ReadOnlyRoots{isolate_}.empty_fixed_array());
  trusted_data->set_globals_start(globals_data_);
  DirectHandle<FixedArray> feedback_vector =
      isolate_->factory()->NewFixedArrayWithZeroes(kMaxFunctions);
  trusted_data->set_feedback_vectors(*feedback_vector);
  return instance_object;
}

// This struct is just a type tag for Zone::NewArray<T>(size_t) call.
struct WasmFunctionCompilerBuffer {};

void WasmFunctionCompiler::Build(base::Vector<const uint8_t> bytes) {
  size_t locals_size = local_decls_.Size();
  size_t total_size = bytes.size() + locals_size + 1;
  uint8_t* buffer =
      zone_->AllocateArray<uint8_t, WasmFunctionCompilerBuffer>(total_size);
  // Prepend the local decls to the code.
  local_decls_.Emit(buffer);
  // Emit the code.
  memcpy(buffer + locals_size, bytes.begin(), bytes.size());
  // Append an extra end opcode.
  buffer[total_size - 1] = kExprEnd;

  bytes = base::VectorOf(buffer, total_size);

  function_->code = {builder_->AddBytes(bytes),
                     static_cast<uint32_t>(bytes.size())};

  NativeModule* native_module =
      builder_->trusted_instance_data()->native_module();
  base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();

  CompilationEnv env = CompilationEnv::ForModule(native_module);
  base::ScopedVector<uint8_t> func_wire_bytes(function_->code.length());
  memcpy(func_wire_bytes.begin(), wire_bytes.begin() + function_->code.offset(),
         func_wire_bytes.length());
  constexpr bool kIsShared = false;  // TODO(14616): Extend this.

  FunctionBody func_body{function_->sig, function_->code.offset(),
                         func_wire_bytes.begin(), func_wire_bytes.end(),
                         kIsShared};
  ForDebugging for_debugging =
      native_module->IsInDebugState() ? kForDebugging : kNotForDebugging;

  WasmDetectedFeatures unused_detected_features;
  // Validate Wasm modules; asm.js is assumed to be always valid.
  if (env.module->origin == kWasmOrigin) {
    DecodeResult validation_result =
        ValidateFunctionBody(zone_, env.enabled_features, env.module,
                             &unused_detected_features, func_body);
    if (validation_result.failed()) {
      FATAL("Validation failed: %s",
            validation_result.error().message().c_str());
    }
    env.module->set_function_validated(function_->func_index);
  }

  if (v8_flags.wasm_jitless) return;

  std::optional<WasmCompilationResult> result;
  if (builder_->test_execution_tier() ==
      TestExecutionTier::kLiftoffForFuzzing) {
    result.emplace(ExecuteLiftoffCompilation(
        &env, func_body,
        LiftoffOptions{}
            .set_func_index(function_->func_index)
            .set_for_debugging(kForDebugging)
            .set_max_steps(builder_->max_steps_ptr())
            .set_nondeterminism(builder_->non_determinism_ptr())));
  } else {
    WasmCompilationUnit unit(function_->func_index, builder_->execution_tier(),
                             for_debugging);
    result.emplace(unit.ExecuteCompilation(
        &env, native_module->compilation_state()->GetWireBytesStorage().get(),
        nullptr, &unused_detected_features));
  }
  CHECK(result->succeeded());
  WasmCode* code =
      native_module->PublishCode(native_module->AddCompiledCode(*result));
  DCHECK_NOT_NULL(code);
  DisallowGarbageCollection no_gc;
  Tagged<Script> script =
      builder_->instance_object()->module_object()->script();
  std::unique_ptr<char[]> source_url =
      Cast<String>(script->name())->ToCString();
  if (WasmCode::ShouldBeLogged(isolate())) {
    code->LogCode(isolate(), source_url.get(), script->id());
  }
}

WasmFunctionCompiler::WasmFunctionCompiler(Zone* zone, const FunctionSig* sig,
                                           TestingModuleBuilder* builder,
                                           const char* name)
    : zone_(zone), builder_(builder), local_decls_(zone, sig) {
  // Get a new function from the testing module.
  int index = builder->AddFunction(sig, name, TestingModuleBuilder::kWasm);
  function_ = builder_->GetFunctionAt(index);
}

WasmFunctionCompiler::~WasmFunctionCompiler() = default;

/* static */
FunctionSig* WasmRunnerBase::CreateSig(Zone* zone, MachineType return_type,
                                       base::Vector<MachineType> param_types) {
  int return_count = return_type.IsNone() ? 0 : 1;
  int param_count = param_types.length();

  // Allocate storage array in zone.
  ValueType* sig_types =
      zone->AllocateArray<ValueType>(return_count + param_count);

  // Convert machine types to local types, and check that there are no
  // MachineType::None()'s in the parameters.
  int idx = 0;
  if (return_count) sig_types[idx++] = ValueType::For(return_type);
  for (MachineType param : param_types) {
    CHECK_NE(MachineType::None(), param);
    sig_types[idx++] = ValueType::For(param);
  }
  return zone->New<FunctionSig>(return_count, param_count, sig_types);
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```