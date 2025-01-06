Response:
Let's break down the request and the provided C++ header file.

**Request Analysis:**

The core request is to analyze the C++ header file `v8/test/cctest/wasm/wasm-run-utils.h` and explain its functionality within the context of V8's WebAssembly testing framework. Specifically, the request asks for:

1. **Functionality:** A general description of what the header provides.
2. **Torque Connection:**  Confirmation or denial of whether it's a Torque file (checking for `.tq` extension).
3. **JavaScript Relationship:** If it interacts with JavaScript, examples should be provided.
4. **Code Logic Inference:** If there's logic, show examples with inputs and outputs.
5. **Common Programming Errors:** Identify potential errors users might make when using this code.

**Header File Analysis:**

The header file provides a set of utilities and classes designed to simplify writing tests for V8's WebAssembly implementation. It acts as a testing DSL (Domain-Specific Language) tailored for WebAssembly. Here's a breakdown of its key components and their purposes:

* **Includes:** It includes various V8 internal headers related to compilation, WebAssembly, and testing. This immediately signals its purpose is tightly bound to V8's internals.
* **`TestExecutionTier` enum:**  Defines the different execution tiers to test against (Interpreter, Liftoff, Turbofan). This suggests the header is used for testing performance and correctness across different compilation pipelines.
* **Helper Macros (`CHECK_TRAP`, `ADD_CODE`):** These provide concise ways to assert trap conditions and add bytecode to Wasm modules, crucial for testing Wasm behavior.
* **`ManuallyImportedJSFunction` struct:**  Allows for testing scenarios where Wasm modules import JavaScript functions. This highlights the interoperability testing aspect.
* **Helper Functions (`IsSameNan`):**  Provides utility functions, likely for comparing floating-point NaN values correctly.
* **`TestingModuleBuilder` class:**  This is the core of the header. It's a builder pattern for constructing Wasm modules programmatically for testing. It allows adding memories, globals, functions, tables, data segments, etc. It also manages the creation of `WasmInstanceObject` and `WasmModuleObject`, the runtime representations of Wasm modules.
* **`WasmFunctionCompiler` class:**  A helper for compiling individual Wasm functions. It manages local variable declarations and allows building the function's bytecode.
* **`WasmRunnerBase` class:**  A base class for executing Wasm code. It uses the `TestingModuleBuilder` to create the module and provides methods to call the Wasm functions from the test environment (potentially via JavaScript).
* **`WasmRunner` class:**  A template class that simplifies calling Wasm functions with specific parameter and return types. It handles the conversion between JavaScript values and Wasm types.
* **Testing Macros (`WASM_EXEC_TEST`, etc.):**  Define macros to streamline the creation of test cases for different execution tiers.

**Mental Walkthrough & Pre-computation:**

1. **File Extension:** The request explicitly states "目录为v8/test/cctest/wasm/wasm-run-utils.h的一个v8源代码". The `.h` extension means it's a C++ header file, not a Torque (`.tq`) file.

2. **JavaScript Interaction:** The presence of `ManuallyImportedJSFunction`, `WrapCode`, and methods like `CallViaJS` strongly indicate interaction with JavaScript. The `WasmRunner` and `MakeParam` functions further solidify this by handling the marshaling of data between JS and Wasm.

3. **Code Logic:** The `TestingModuleBuilder` class embodies a builder pattern, which has implicit logic for managing the state of the module being built. The `WasmRunner` classes encapsulate the logic for setting up and executing Wasm function calls.

4. **Common Errors:**  Potential user errors could involve:
    * Incorrectly defining function signatures when importing JS functions.
    * Mismatched types when calling Wasm functions from JavaScript.
    * Not handling trap conditions appropriately.
    * Misunderstanding the memory model and accessing memory out of bounds.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes. I can list the functionalities.
* 如果v8/test/cctest/wasm/wasm-run-utils.h以.tq结尾: Yes, I can check the extension.
* 如果它与javascript的功能有关系: Yes, there's a clear relationship.
* 请用javascript举例说明: Yes, I can provide JavaScript examples.
* 如果有代码逻辑推理: Yes, I can discuss the builder pattern and execution flow.
* 请给出假设输入与输出: Yes, I can create examples for function calls.
* 如果涉及用户常见的编程错误: Yes, I can identify potential errors.

Confidence Score: 5/5 - I have a good understanding of the file's purpose and can address all aspects of the request.

Strategizing complete. I will now generate the response based on this analysis.

好的，根据您提供的 V8 源代码头文件 `v8/test/cctest/wasm/wasm-run-utils.h`，以下是其功能列表：

**主要功能:**

这个头文件为 V8 的 WebAssembly 测试框架提供了一组实用工具和类，用于简化编写和执行 WebAssembly 单元测试。它抽象了创建、编译和运行 WebAssembly 模块的复杂性，允许测试人员专注于测试 WebAssembly 代码的特定行为。

**详细功能列表:**

1. **定义测试执行层级 (`TestExecutionTier`):**
   - 允许指定在哪个 V8 的 WebAssembly 执行层级上运行测试，例如：
     - `kInterpreter`:  解释器
     - `kLiftoff`:  Liftoff 编译器
     - `kTurbofan`:  Turbofan 优化编译器
     - `kLiftoffForFuzzing`: 用于模糊测试的 Liftoff

2. **提供辅助宏和类型定义:**
   - `CHECK_TRAP`:  用于检查 WebAssembly 代码是否触发了预期的 trap (运行时错误)。
   - `ADD_CODE`:  方便地向 WebAssembly 字节码向量中添加字节。
   - `ManuallyImportedJSFunction`:  用于描述手动导入的 JavaScript 函数，以便在 WebAssembly 模块中使用。

3. **提供浮点数 NaN 比较函数 (`IsSameNan`):**
   - 提供了用于安全比较浮点数 NaN (Not-a-Number) 值的函数。

4. **提供 `TestingModuleBuilder` 类:**
   - **构建 WebAssembly 模块:**  允许逐步构建 WebAssembly 模块，包括：
     - 添加内存 (`AddMemory`)，可以指定是否共享。
     - 添加全局变量 (`AddGlobal`)。
     - 添加函数签名 (`AddSignature`)。
     - 获取内存大小 (`mem_size`) 和原始内存指针 (`raw_mem_start`, `raw_mem_end`)。
     - 直接读写内存 (`WriteMemory`, `ReadMemory`)。
     - 初始化内存 (清零 `BlankMemory` 或随机化 `RandomizeMemory`)。
     - 设置内存为共享 (`SetMemoryShared`)。
     - 添加导入或 WebAssembly 函数 (`AddFunction`)。
     - 初始化导出包装器的缓存 (`InitializeWrapperCache`)。
     - 包装 WebAssembly 代码以便作为 JavaScript 函数调用 (`WrapCode`)。
     - 添加间接函数表 (`AddIndirectFunctionTable`)。
     - 添加原始字节到模块 (`AddBytes`)。
     - 添加异常 (`AddException`).
     - 添加被动数据段 (`AddPassiveDataSegment`).
   - **访问模块信息:**  提供访问已构建的模块信息的接口，如函数、实例对象等。
   - **设置调试状态 (`SetDebugState`, `SwitchToDebug`):**  用于控制调试相关的设置。
   - **控制执行:**  允许设置最大执行步骤数 (`set_max_steps`) 和访问非确定性计数器。
   - **启用 WebAssembly 特性 (`EnableFeature`):**  用于测试特定 WebAssembly 特性的支持。

5. **提供 `WasmFunctionCompiler` 类:**
   - **编译单个 WebAssembly 函数:**  用于构建单个 WebAssembly 函数的字节码。
   - **分配局部变量 (`AllocateLocal`):**  帮助管理函数内的局部变量。
   - **设置函数签名索引 (`SetSigIndex`):**  关联函数与其签名。

6. **提供 `WasmRunnerBase` 类:**
   - **构建和运行 WebAssembly 代码:**  是执行 WebAssembly 代码的基础类。
   - **管理编译状态:** 跟踪代码是否已经被编译。
   - **创建新的 WebAssembly 函数编译器 (`NewFunction`):**  用于构建多个函数的场景。
   - **访问构建器和区域:**  提供对 `TestingModuleBuilder` 和内存区域的访问。
   - **切换到调试模式 (`SwitchToDebug`):**
   - **创建函数签名 (`CreateSig`):**  方便创建 `FunctionSig` 对象。
   - **通过 JavaScript 调用 WebAssembly 函数 (`CallViaJS`):**  允许从测试代码中调用已编译的 WebAssembly 函数。

7. **提供 `WasmRunner` 模板类:**
   - **类型安全的 WebAssembly 函数调用:**  提供了一种类型安全的方式来调用 WebAssembly 函数，并处理参数和返回值类型的转换。
   - **参数生成 (`MakeParam`):**  将 C++ 类型转换为 JavaScript 的 `Handle<Object>`，以便传递给 WebAssembly 函数。
   - **便捷的调用和检查方法 (`Call`, `CheckCallViaJS`, `CheckCallViaJSTraps`):**  简化了调用 WebAssembly 函数并检查其结果或是否发生 trap 的过程。
   - **设置最大执行步骤数 (`SetMaxSteps`):**

8. **提供测试宏 (`WASM_EXEC_TEST`, `UNINITIALIZED_WASM_EXEC_TEST`, `WASM_COMPILED_EXEC_TEST`):**
   - 用于定义在不同执行层级上运行的测试用例，减少了编写重复测试样板代码的需求。

**关于 .tq 结尾:**

正如您正确指出的，如果 `v8/test/cctest/wasm/wasm-run-utils.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。但是，根据您提供的文件名和内容，它是一个 **C++ 头文件 (.h)**。因此，它不是 Torque 源代码。

**与 JavaScript 的关系及示例:**

`wasm-run-utils.h` 与 JavaScript 的功能有密切关系，因为它旨在测试 WebAssembly 与 JavaScript 的互操作性以及 V8 引擎执行 WebAssembly 代码的能力。

**JavaScript 示例:**

假设我们使用 `WasmRunner` 构建了一个简单的 WebAssembly 模块，该模块导出一个名为 `add` 的函数，该函数接受两个整数并返回它们的和。在测试代码中，我们可能会使用 `CallViaJS` 或 `Call` 方法来从 JavaScript 的角度调用这个 WebAssembly 函数。

```javascript
// 假设在 C++ 测试代码中，我们使用了 WasmRunner 构建了如下 Wasm 模块：
// (module
//   (func $add (param i32 i32) (result i32)
//     local.get 0
//     local.get 1
//     i32.add))
//   (export "add" (func $add)))

// 在 C++ 测试代码中，WrapCode 方法会生成一个可以从 JavaScript 调用的 JSFunction。

// 假设我们已经获得了对导出的 "add" 函数的引用 (例如通过 builder_.WrapCode(0))
// 并将其存储在名为 'wasmAddFunction' 的 JavaScript 变量中。

// 现在，我们可以在 JavaScript 中调用这个 WebAssembly 函数：
let result = wasmAddFunction(5, 10);
console.log(result); // 输出 15

// 或者，在 C++ 测试代码中，WasmRunner 的 Call 方法内部会进行类似的调用：
// 假设 runner 是 WasmRunner 的实例
// int wasm_result = runner.Call<int, int, int>(5, 10);
// CHECK_EQ(15, wasm_result);
```

在这个例子中，`WasmRunner` 帮助我们编译了 WebAssembly 代码，并提供了将其包装成 JavaScript 函数的能力，然后我们就可以像调用普通的 JavaScript 函数一样调用它。

**代码逻辑推理和示例:**

`TestingModuleBuilder` 类使用了建造者模式。我们可以逐步添加模块的各个部分。

**假设输入和输出 (以添加内存为例):**

```c++
// 假设 builder 是 TestingModuleBuilder 的实例
uint32_t memory_size = 65536; // 64KB
uint8_t* memory_start = builder.AddMemory(memory_size);

// 输出:
// memory_start 将指向分配的内存块的起始地址。
// builder 内部的 test_module_ 成员的 memories 向量将包含一个描述新内存的条目。
// builder 内部的 mem0_start_ 将被设置为 memory_start。
// builder 内部的 mem0_size_ 将被设置为 memory_size。
```

**用户常见的编程错误示例:**

1. **函数签名不匹配:**  当手动导入 JavaScript 函数时，如果在 `ManuallyImportedJSFunction` 中定义的签名与实际 JavaScript 函数的签名不匹配，会导致运行时错误。

   ```c++
   // C++ 中定义的签名可能与 JavaScript 函数的实际签名不符
   FunctionSig wrong_sig(nullptr, 1, nullptr, 0);
   ManuallyImportedJSFunction import = {&wrong_sig, ...};
   ```

2. **在调用 WebAssembly 函数时传递了错误的参数类型:**  `WasmRunner` 尝试进行类型转换，但如果参数类型完全不兼容，则会导致错误。

   ```c++
   WasmRunner<int, int> runner(TestExecutionTier::kTurbofan);
   runner.Build({WASM_OPCODE_I32_CONST, 10, WASM_OPCODE_END});
   // 假设 runner 构建了一个接受一个 i32 参数的函数，但我们没有传递参数
   // runner.Call<int>(); // 错误：参数数量不匹配
   ```

3. **没有正确处理 WebAssembly 的 trap:**  如果 WebAssembly 代码可能触发 trap，但测试代码没有使用 `CHECK_TRAP` 或其他机制来验证 trap 是否发生，则测试可能无法捕捉到错误。

   ```c++
   WasmRunner<void> runner(TestExecutionTier::kTurbofan);
   runner.Build({WASM_OPCODE_I32_CONST, 0, WASM_OPCODE_I32_DIV_S}); // 除以零会导致 trap
   // 如果没有检查 trap，下面的调用可能会导致未定义的行为或测试失败，但不明确是 trap
   // runner.Call<void>();
   ```

希望以上详细的功能列表、JavaScript 示例、代码逻辑推理以及常见错误说明能够帮助您理解 `v8/test/cctest/wasm/wasm-run-utils.h` 文件的作用。

Prompt: 
```
这是目录为v8/test/cctest/wasm/wasm-run-utils.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/wasm-run-utils.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef WASM_RUN_UTILS_H
#define WASM_RUN_UTILS_H

#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <array>
#include <memory>

#include "src/base/utils/random-number-generator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/int64-lowering.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/node.h"
#include "src/compiler/wasm-compiler.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/canonical-types.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/local-decl-encoder.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-external-refs.h"
#include "src/wasm/wasm-js.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-tier.h"
#include "src/zone/accounting-allocator.h"
#include "src/zone/zone.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/graph-and-builders.h"
#include "test/common/call-tester.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/flag-utils.h"

#if V8_ENABLE_DRUMBRAKE
#include "src/wasm/interpreter/wasm-interpreter.h"
#endif  // V8_ENABLE_DRUMBRAKE

namespace v8::internal::wasm {

enum class TestExecutionTier : int8_t {
#if V8_ENABLE_DRUMBRAKE
  kInterpreter = static_cast<int8_t>(ExecutionTier::kInterpreter),
#endif  // V8_ENABLE_DRUMBRAKE
  kLiftoff = static_cast<int8_t>(ExecutionTier::kLiftoff),
  kTurbofan = static_cast<int8_t>(ExecutionTier::kTurbofan),
  kLiftoffForFuzzing
};
static_assert(
    std::is_same<std::underlying_type<ExecutionTier>::type,
                 std::underlying_type<TestExecutionTier>::type>::value,
    "enum types match");

using base::ReadLittleEndianValue;
using base::WriteLittleEndianValue;

constexpr uint32_t kMaxFunctions = 10;
constexpr uint32_t kMaxGlobalsSize = 128;
// Don't execute more than 16k steps.
constexpr int kMaxNumSteps = 16 * 1024;

using compiler::CallDescriptor;
using compiler::MachineTypeForC;
using compiler::Node;

// TODO(titzer): check traps more robustly in tests.
// Currently, in tests, we just return 0xDEADBEEF from the function in which
// the trap occurs if the runtime context is not available to throw a JavaScript
// exception.
#define CHECK_TRAP32(x) \
  CHECK_EQ(0xDEADBEEF, (base::bit_cast<uint32_t>(x)) & 0xFFFFFFFF)
#define CHECK_TRAP64(x)        \
  CHECK_EQ(0xDEADBEEFDEADBEEF, \
           (base::bit_cast<uint64_t>(x)) & 0xFFFFFFFFFFFFFFFF)
#define CHECK_TRAP(x) CHECK_TRAP32(x)

#define WASM_WRAPPER_RETURN_VALUE 8754

#define ADD_CODE(vec, ...)                           \
  do {                                               \
    uint8_t __buf[] = {__VA_ARGS__};                 \
    for (size_t __i = 0; __i < sizeof(__buf); __i++) \
      vec.push_back(__buf[__i]);                     \
  } while (false)

// For tests that must manually import a JSFunction with source code.
struct ManuallyImportedJSFunction {
  const FunctionSig* sig;
  Handle<JSFunction> js_function;
};

// Helper Functions.
bool IsSameNan(uint16_t expected, uint16_t actual);
bool IsSameNan(float expected, float actual);
bool IsSameNan(double expected, double actual);

// A  Wasm module builder. Globals are pre-set, however, memory and code may be
// progressively added by a test. In turn, we piecemeal update the runtime
// objects, i.e. {WasmInstanceObject} and {WasmModuleObject}.
class TestingModuleBuilder {
 public:
  TestingModuleBuilder(Zone*, ModuleOrigin origin, ManuallyImportedJSFunction*,
                       TestExecutionTier, Isolate* isolate);
  ~TestingModuleBuilder();

  uint8_t* AddMemory(uint32_t size, SharedFlag shared = SharedFlag::kNotShared,
                     AddressType address_type = wasm::AddressType::kI32,
                     std::optional<size_t> max_size = {});

  size_t CodeTableLength() const { return native_module_->num_functions(); }

  template <typename T>
  T* AddMemoryElems(uint32_t count,
                    AddressType address_type = wasm::AddressType::kI32) {
    AddMemory(count * sizeof(T), SharedFlag::kNotShared, address_type);
    return raw_mem_start<T>();
  }

  template <typename T>
  T* AddGlobal(ValueType type = ValueType::For(MachineTypeForC<T>())) {
    const WasmGlobal* global = AddGlobal(type);
    return reinterpret_cast<T*>(globals_data_ + global->offset);
  }

  // TODO(14034): Allow selecting type finality.
  ModuleTypeIndex AddSignature(const FunctionSig* sig) {
    const bool is_final = true;
    const bool is_shared = false;
    test_module_->AddSignatureForTesting(sig, kNoSuperType, is_final,
                                         is_shared);
    GetTypeCanonicalizer()->AddRecursiveGroup(test_module_.get(), 1);
    size_t size = test_module_->types.size();
    // The {ModuleTypeIndex} can handle more, but users of this class
    // often assume that each generated index fits into a byte, so
    // ensure that here.
    CHECK_GT(127, size);
    return ModuleTypeIndex{static_cast<uint32_t>(size - 1)};
  }

  uint32_t mem_size() const {
    CHECK_EQ(1, test_module_->memories.size());
    return mem0_size_;
  }

  template <typename T>
  T* raw_mem_start() const {
    DCHECK_NOT_NULL(mem0_start_);
    return reinterpret_cast<T*>(mem0_start_);
  }

  template <typename T>
  T* raw_mem_end() const {
    DCHECK_NOT_NULL(mem0_start_);
    return reinterpret_cast<T*>(mem0_start_ + mem0_size_);
  }

  template <typename T>
  T raw_mem_at(int i) {
    DCHECK_NOT_NULL(mem0_start_);
    return ReadMemory(&(reinterpret_cast<T*>(mem0_start_)[i]));
  }

  template <typename T>
  T raw_val_at(int i) {
    return ReadMemory(reinterpret_cast<T*>(mem0_start_ + i));
  }

  template <typename T>
  void WriteMemory(T* p, T val) {
    WriteLittleEndianValue<T>(reinterpret_cast<Address>(p), val);
  }

  template <typename T>
  T ReadMemory(T* p) {
    return ReadLittleEndianValue<T>(reinterpret_cast<Address>(p));
  }

  // Zero-initialize the memory.
  void BlankMemory() {
    uint8_t* raw = raw_mem_start<uint8_t>();
    memset(raw, 0, mem0_size_);
  }

  // Pseudo-randomly initialize the memory.
  void RandomizeMemory(unsigned int seed = 88) {
    uint8_t* raw = raw_mem_start<uint8_t>();
    uint8_t* end = raw_mem_end<uint8_t>();
    v8::base::RandomNumberGenerator rng;
    rng.SetSeed(seed);
    rng.NextBytes(raw, end - raw);
  }

  void SetMemoryShared() {
    CHECK_EQ(1, test_module_->memories.size());
    test_module_->memories[0].is_shared = true;
  }

  enum FunctionType { kImport, kWasm };
  uint32_t AddFunction(const FunctionSig* sig, const char* name,
                       FunctionType type);

  // Freezes the signature map of the module and allocates the storage for
  // export wrappers.
  void InitializeWrapperCache();

  // Wrap the code so it can be called as a JS function.
  Handle<JSFunction> WrapCode(uint32_t index);

  // If function_indexes is {nullptr}, the contents of the table will be
  // initialized with null functions.
  void AddIndirectFunctionTable(const uint16_t* function_indexes,
                                uint32_t table_size,
                                ValueType table_type = kWasmFuncRef);

  uint32_t AddBytes(base::Vector<const uint8_t> bytes);

  uint32_t AddException(const FunctionSig* sig);

  uint32_t AddPassiveDataSegment(base::Vector<const uint8_t> bytes);

  WasmFunction* GetFunctionAt(int index) {
    return &test_module_->functions[index];
  }

  Isolate* isolate() const { return isolate_; }
  Handle<WasmInstanceObject> instance_object() const {
    return instance_object_;
  }
  Handle<WasmTrustedInstanceData> trusted_instance_data() const {
    return trusted_instance_data_;
  }
  WasmCode* GetFunctionCode(uint32_t index) const {
    return native_module_->GetCode(index);
  }
  Address globals_start() const {
    return reinterpret_cast<Address>(globals_data_);
  }

  void SetDebugState() {
    native_module_->SetDebugState(kDebugging);
    execution_tier_ = TestExecutionTier::kLiftoff;
  }

  void SwitchToDebug() {
    SetDebugState();
    WasmCodeRefScope ref_scope;
    native_module_->RemoveCompiledCode(
        NativeModule::RemoveFilter::kRemoveNonDebugCode);
  }

  TestExecutionTier test_execution_tier() const { return execution_tier_; }

  ExecutionTier execution_tier() const {
    switch (execution_tier_) {
#if V8_ENABLE_DRUMBRAKE
      case TestExecutionTier::kInterpreter:
        return ExecutionTier::kInterpreter;
#endif  // V8_ENABLE_DRUMBRAKE
      case TestExecutionTier::kTurbofan:
        return ExecutionTier::kTurbofan;
      case TestExecutionTier::kLiftoff:
        return ExecutionTier::kLiftoff;
      default:
        UNREACHABLE();
    }
  }

  void set_max_steps(int n) { max_steps_ = n; }
  int* max_steps_ptr() { return &max_steps_; }
  int32_t nondeterminism() { return nondeterminism_; }
  int32_t* non_determinism_ptr() { return &nondeterminism_; }

  void EnableFeature(WasmEnabledFeature feature) {
    enabled_features_.Add(feature);
  }

 private:
  std::shared_ptr<WasmModule> test_module_;
  Isolate* isolate_;
  WasmEnabledFeatures enabled_features_;
  uint32_t global_offset = 0;
  // The TestingModuleBuilder only supports one memory currently.
  uint8_t* mem0_start_ = nullptr;
  uint32_t mem0_size_ = 0;
  uint8_t* globals_data_ = nullptr;
  TestExecutionTier execution_tier_;
  Handle<WasmInstanceObject> instance_object_;
  Handle<WasmTrustedInstanceData> trusted_instance_data_;
  NativeModule* native_module_ = nullptr;
  int32_t max_steps_ = kMaxNumSteps;
  int32_t nondeterminism_ = 0;

  // Data segment arrays that are normally allocated on the instance.
  std::vector<uint8_t> data_segment_data_;
  std::vector<Address> data_segment_starts_;
  std::vector<uint32_t> data_segment_sizes_;

  const WasmGlobal* AddGlobal(ValueType type);

  Handle<WasmInstanceObject> InitInstanceObject();
};

// A helper for compiling wasm functions for testing.
// It contains the internal state for compilation (i.e. TurboFan graph).
class WasmFunctionCompiler {
 public:
  ~WasmFunctionCompiler();

  Isolate* isolate() { return builder_->isolate(); }
  uint32_t function_index() { return function_->func_index; }
  ModuleTypeIndex sig_index() { return function_->sig_index; }

  void Build(std::initializer_list<const uint8_t> bytes) {
    Build(base::VectorOf(bytes));
  }
  void Build(base::Vector<const uint8_t> bytes);

  uint8_t AllocateLocal(ValueType type) {
    uint32_t index = local_decls_.AddLocals(1, type);
    uint8_t result = static_cast<uint8_t>(index);
    DCHECK_EQ(index, result);
    return result;
  }

  void SetSigIndex(ModuleTypeIndex sig_index) {
    function_->sig_index = sig_index;
  }

 private:
  friend class WasmRunnerBase;

  WasmFunctionCompiler(Zone* zone, const FunctionSig* sig,
                       TestingModuleBuilder* builder, const char* name);

  Zone* zone_;
  TestingModuleBuilder* builder_;
  WasmFunction* function_;
  LocalDeclEncoder local_decls_;
};

// A helper class to build a module around Wasm bytecode, generate machine
// code, and run that code.
class WasmRunnerBase : public InitializedHandleScope {
 public:
  WasmRunnerBase(ManuallyImportedJSFunction* maybe_import, ModuleOrigin origin,
                 TestExecutionTier execution_tier, int num_params,
                 Isolate* isolate = nullptr)
      : InitializedHandleScope(isolate),
        zone_(&allocator_, ZONE_NAME, kCompressGraphZone),
        builder_(&zone_, origin, maybe_import, execution_tier, isolate) {}

  // Builds a graph from the given Wasm code and generates the machine
  // code and call wrapper for that graph. This method must not be called
  // more than once.
  void Build(const uint8_t* start, const uint8_t* end) {
    Build(base::VectorOf(start, end - start));
  }
  void Build(std::initializer_list<const uint8_t> bytes) {
    Build(base::VectorOf(bytes));
  }
  void Build(base::Vector<const uint8_t> bytes) {
    CHECK(!compiled_);
    compiled_ = true;
    functions_[0]->Build(bytes);
  }

  // Resets the state for building the next function.
  // The main function called will always be the first function.
  template <typename ReturnType, typename... ParamTypes>
  WasmFunctionCompiler& NewFunction(const char* name = nullptr) {
    return NewFunction(CreateSig<ReturnType, ParamTypes...>(), name);
  }

  // Resets the state for building the next function.
  // The main function called will be the last generated function.
  // Returns the index of the previously built function.
  WasmFunctionCompiler& NewFunction(const FunctionSig* sig,
                                    const char* name = nullptr) {
    functions_.emplace_back(
        new WasmFunctionCompiler(&zone_, sig, &builder_, name));
    ModuleTypeIndex sig_index = builder().AddSignature(sig);
    functions_.back()->SetSigIndex(sig_index);
    return *functions_.back();
  }

  uint8_t AllocateLocal(ValueType type) {
    return functions_[0]->AllocateLocal(type);
  }

  uint32_t function_index() { return functions_[0]->function_index(); }
  WasmFunction* function() { return functions_[0]->function_; }
  bool possible_nondeterminism() { return possible_nondeterminism_; }
  TestingModuleBuilder& builder() { return builder_; }
  Zone* zone() { return &zone_; }

  void SwitchToDebug() { builder_.SwitchToDebug(); }

  template <typename ReturnType, typename... ParamTypes>
  const FunctionSig* CreateSig() {
    return WasmRunnerBase::CreateSig<ReturnType, ParamTypes...>(&zone_);
  }

  static const CanonicalSig* CanonicalizeSig(const FunctionSig* sig) {
    // TODO(clemensb): Make this a single function call.
    CanonicalTypeIndex sig_id = GetTypeCanonicalizer()->AddRecursiveGroup(sig);
    return GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);
  }

  template <typename ReturnType, typename... ParamTypes>
  static FunctionSig* CreateSig(Zone* zone) {
    std::array<MachineType, sizeof...(ParamTypes)> param_machine_types{
        {MachineTypeForC<ParamTypes>()...}};
    base::Vector<MachineType> param_vec(param_machine_types.data(),
                                        param_machine_types.size());
    return CreateSig(zone, MachineTypeForC<ReturnType>(), param_vec);
  }

  // TODO(clemensb): Remove, use {CallViaJS} directly.
  void CheckCallApplyViaJS(double expected, uint32_t function_index,
                           Handle<Object>* buffer, int count) {
    MaybeHandle<Object> retval =
        CallViaJS(function_index, base::VectorOf(buffer, count));

    if (retval.is_null()) {
      CHECK_EQ(expected, static_cast<double>(0xDEADBEEF));
    } else {
      DirectHandle<Object> result = retval.ToHandleChecked();
      if (IsSmi(*result)) {
        CHECK_EQ(expected, Smi::ToInt(*result));
      } else {
        CHECK(IsHeapNumber(*result));
        CHECK_DOUBLE_EQ(expected, Cast<HeapNumber>(*result)->value());
      }
    }
  }

  MaybeHandle<Object> CallViaJS(uint32_t function_index,
                                base::Vector<Handle<Object>> parameters) {
    Isolate* isolate = main_isolate();
    // Save the original context, because CEntry (for runtime calls) will
    // reset / invalidate it when returning.
    SaveContext save_context(isolate);

    if (jsfuncs_.size() <= function_index) {
      jsfuncs_.resize(function_index + 1);
    }
    if (jsfuncs_[function_index].is_null()) {
      jsfuncs_[function_index] = builder_.WrapCode(function_index);
    }
    Handle<JSFunction> jsfunc = jsfuncs_[function_index];
    Handle<Object> global(isolate->context()->global_object(), isolate);
    return Execution::TryCall(
        isolate, jsfunc, global, static_cast<int>(parameters.size()),
        parameters.data(), Execution::MessageHandling::kReport, nullptr);
  }

 private:
  static FunctionSig* CreateSig(Zone* zone, MachineType return_type,
                                base::Vector<MachineType> param_types);

 protected:
  wasm::WasmCodeRefScope code_ref_scope_;
  std::vector<Handle<JSFunction>> jsfuncs_;

  v8::internal::AccountingAllocator allocator_;
  Zone zone_;
  TestingModuleBuilder builder_;
  std::vector<std::unique_ptr<WasmFunctionCompiler>> functions_;
  bool compiled_ = false;
  bool possible_nondeterminism_ = false;
  int32_t main_fn_index_ = 0;

  static void SetThreadInWasmFlag() {
    *reinterpret_cast<int*>(trap_handler::GetThreadInWasmThreadLocalAddress()) =
        true;
  }

  static void ClearThreadInWasmFlag() {
    *reinterpret_cast<int*>(trap_handler::GetThreadInWasmThreadLocalAddress()) =
        false;
  }
};

template <typename T>
inline WasmValue WasmValueInitializer(T value) {
  return WasmValue(value);
}
template <>
inline WasmValue WasmValueInitializer(int8_t value) {
  return WasmValue(static_cast<int32_t>(value));
}
template <>
inline WasmValue WasmValueInitializer(int16_t value) {
  return WasmValue(static_cast<int32_t>(value));
}

template <typename ReturnType, typename... ParamTypes>
class WasmRunner : public WasmRunnerBase {
 public:
  explicit WasmRunner(TestExecutionTier execution_tier,
                      ModuleOrigin origin = kWasmOrigin,
                      ManuallyImportedJSFunction* maybe_import = nullptr,
                      const char* main_fn_name = "main",
                      Isolate* isolate = nullptr)
      : WasmRunnerBase(maybe_import, origin, execution_tier,
                       sizeof...(ParamTypes), isolate) {
    WasmFunctionCompiler& main_fn =
        NewFunction<ReturnType, ParamTypes...>(main_fn_name);
    // Non-zero if there is an import.
    main_fn_index_ = main_fn.function_index();
  }

  template <typename T>
  Handle<Object> MakeParam(T t) {
    Factory* factory = builder_.isolate()->factory();
    if constexpr (std::is_integral_v<T> && std::is_signed_v<T> &&
                  sizeof(T) <= sizeof(int)) {
      return factory->NewNumberFromInt(t);
    }
    if constexpr (std::is_integral_v<T> && std::is_unsigned_v<T> &&
                  sizeof(T) <= sizeof(int)) {
      return factory->NewNumberFromUint(t);
    }
    if constexpr (std::is_same_v<T, int64_t>) {
      return BigInt::FromInt64(builder_.isolate(), t);
    }
    if constexpr (std::is_same_v<T, uint64_t>) {
      return BigInt::FromUint64(builder_.isolate(), t);
    }
    if constexpr (std::is_same_v<T, float>) {
      return factory->NewNumber(t);
    }
    if constexpr (std::is_same_v<T, double>) {
      return factory->NewNumber(t);
    }
    UNIMPLEMENTED();
  }

  ReturnType Call(ParamTypes... p) {
    std::array<Handle<Object>, sizeof...(p)> param_objs = {MakeParam(p)...};
    MaybeHandle<Object> retval =
        CallViaJS(function()->func_index, base::VectorOf(param_objs));

    if (retval.is_null()) {
      return static_cast<ReturnType>(0xDEADBEEFDEADBEEF);
    }

    DirectHandle<Object> result = retval.ToHandleChecked();
    // For int64_t and uint64_t returns we will get a BigInt.
    if constexpr (std::is_integral_v<ReturnType> &&
                  sizeof(ReturnType) == sizeof(int64_t)) {
      CHECK(IsBigInt(*result));
      return Cast<BigInt>(*result)->AsInt64();
    }

    // Otherwise it must be a number (Smi or HeapNumber).
    CHECK(IsNumber(*result));
    double value = Object::NumberValue(Cast<Number>(*result));
    // The JS API interprets all Wasm values as signed, hence we cast via the
    // signed equivalent type to avoid undefined behaviour in the casting.
    if constexpr (std::is_integral_v<ReturnType> &&
                  std::is_unsigned_v<ReturnType>) {
      using signed_t = std::make_signed_t<ReturnType>;
      return static_cast<ReturnType>(static_cast<signed_t>(value));
    }
    return static_cast<ReturnType>(value);
  }

  void CheckCallViaJS(double expected, ParamTypes... p) {
    // TODO(clemensb): Inline into callers; use {Call} and {CHECK_EQ} directly.
    ReturnType result = Call(p...);
    if constexpr (std::is_floating_point_v<ReturnType>) {
      if (std::isnan(result)) {
        CHECK(IsSameNan(static_cast<ReturnType>(expected), result));
        return;
      }
    }
    CHECK_EQ(expected, result);
  }

  void CheckCallViaJSTraps(ParamTypes... p) {
    std::array<Handle<Object>, sizeof...(p)> param_objs = {MakeParam(p)...};
    MaybeHandle<Object> retval =
        CallViaJS(function()->func_index, base::VectorOf(param_objs));
    CHECK(retval.is_null());
  }

  void SetMaxSteps(int n) { builder_.set_max_steps(n); }
  bool HasNondeterminism() { return builder_.nondeterminism(); }
};

// A macro to define tests that run in different engine configurations.
#if V8_ENABLE_DRUMBRAKE
#define TEST_IF_DRUMBRAKE(name)                      \
  TEST(RunWasmInterpreter_##name) {                  \
    FLAG_SCOPE(wasm_jitless);                        \
    WasmInterpreterThread::Initialize();             \
    RunWasm_##name(TestExecutionTier::kInterpreter); \
    WasmInterpreterThread::Terminate();              \
  }
#else
#define TEST_IF_DRUMBRAKE(name)
#endif  // V8_ENABLE_DRUMBRAKE
#define WASM_EXEC_TEST(name)                                                   \
  void RunWasm_##name(TestExecutionTier execution_tier);                       \
  TEST(RunWasmTurbofan_##name) {                                               \
    RunWasm_##name(TestExecutionTier::kTurbofan);                              \
  }                                                                            \
  TEST(RunWasmLiftoff_##name) { RunWasm_##name(TestExecutionTier::kLiftoff); } \
  TEST_IF_DRUMBRAKE(name)                                                      \
  void RunWasm_##name(TestExecutionTier execution_tier)

#define UNINITIALIZED_WASM_EXEC_TEST(name)               \
  void RunWasm_##name(TestExecutionTier execution_tier); \
  UNINITIALIZED_TEST(RunWasmTurbofan_##name) {           \
    RunWasm_##name(TestExecutionTier::kTurbofan);        \
  }                                                      \
  UNINITIALIZED_TEST(RunWasmLiftoff_##name) {            \
    RunWasm_##name(TestExecutionTier::kLiftoff);         \
  }                                                      \
  void RunWasm_##name(TestExecutionTier execution_tier)

#define WASM_COMPILED_EXEC_TEST(name)                                          \
  void RunWasm_##name(TestExecutionTier execution_tier);                       \
  TEST(RunWasmTurbofan_##name) {                                               \
    RunWasm_##name(TestExecutionTier::kTurbofan);                              \
  }                                                                            \
  TEST(RunWasmLiftoff_##name) { RunWasm_##name(TestExecutionTier::kLiftoff); } \
  void RunWasm_##name(TestExecutionTier execution_tier)

}  // namespace v8::internal::wasm

#endif

"""

```