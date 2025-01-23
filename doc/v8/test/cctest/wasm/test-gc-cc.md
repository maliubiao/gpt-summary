Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code seems to be a test file for WebAssembly garbage collection (GC) features in the V8 JavaScript engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the file path:** The path `v8/test/cctest/wasm/test-gc.cc` strongly suggests this is a C++ test file within the V8 project specifically for testing WebAssembly GC features. The `.cc` extension confirms it's C++ code.

2. **Examine the includes:** The included headers provide clues about the code's purpose. Headers like `src/wasm/module-decoder.h`, `src/wasm/wasm-arguments.h`, `src/wasm/wasm-engine.h`, `src/wasm/wasm-module-builder.h`, and `src/wasm/wasm-opcodes.h` clearly indicate interaction with WebAssembly internals. The `test/cctest/cctest.h` and `test/cctest/wasm/wasm-run-utils.h` headers confirm this is a testing file.

3. **Look for the main testing class:** The class `WasmGCTester` appears central to the testing process. Its constructor and methods suggest it's responsible for building, compiling, and executing WebAssembly modules with GC features.

4. **Analyze `WasmGCTester` methods:**
    * `AddGlobal`, `DefineFunction`, `DefineExportedFunction`, `DefineStruct`, `DefineArray`, `DefineSignature`, `DefineTable`: These methods clearly point to building the structure of a WebAssembly module, including globals, functions, structs, arrays, and signatures. The presence of `DefineStruct` and `DefineArray` is a strong indicator of GC testing, as these are GC-specific features.
    * `CompileModule`: This method is responsible for taking the built module and compiling it.
    * `CallExportedFunction`, `CheckResult`, `GetResultObject`, `CheckHasThrown`: These methods indicate the execution and verification phase of the tests. They call functions in the compiled WebAssembly module and check the results, including expected return values and thrown exceptions.
    * The presence of `ref` and `refNull` helper functions, along with opcodes like `WASM_STRUCT_NEW`, `WASM_STRUCT_GET`, `WASM_REF_AS_NON_NULL`, `WASM_BR_ON_NULL`, `WASM_REF_CAST`, `WASM_BR_ON_CAST`, and `WASM_REF_EQ`, confirms the focus on testing specific WebAssembly GC instructions.

5. **Consider the test macros:** The `WASM_COMPILED_EXEC_TEST` macro suggests that these are integration tests that compile and execute WebAssembly code. The names of the test cases (e.g., `WasmBasicStruct`, `WasmRefAsNonNull`, `WasmBrOnNull`) directly relate to specific GC features being tested.

6. **Infer the overall functionality:** Based on the above points, the primary function of `test-gc.cc` is to test the implementation of WebAssembly's garbage collection features within the V8 engine. It achieves this by:
    * Programmatically constructing WebAssembly modules that utilize GC features.
    * Compiling and instantiating these modules.
    * Executing specific functions within the modules.
    * Asserting expected outcomes, such as return values or thrown exceptions.

7. **Address the specific questions in the prompt:**
    * **Functionality:**  Summarize the findings from the previous steps.
    * **`.tq` extension:** The code is `.cc`, not `.tq`, so it's standard C++ code.
    * **Relationship to JavaScript:** WebAssembly GC allows for better integration between JavaScript and WebAssembly. While the C++ test code doesn't directly show JavaScript, the tests are implicitly verifying functionality that would be exposed and used by JavaScript when interacting with WebAssembly modules. A simple JavaScript example could be a function that calls a WebAssembly function returning a GC-managed object.
    * **Code logic inference (with assumptions):**  Choose a simple test case, like `WasmBasicStruct` and focus on the `kGet1` function. Describe the input (no explicit input parameters), the WebAssembly code being executed (creating and getting a struct field), and the expected output (the value of the field).
    * **Common programming errors:** Think about common mistakes related to GC, such as trying to access fields of a null reference (leading to a null dereference error), which is explicitly tested in the `kNullDereference` case.
    * **Overall functionality (for Part 1):**  Reiterate the core purpose of the file as a test suite for WebAssembly GC.

8. **Structure the response:** Organize the findings into clear sections addressing each part of the prompt. Use bullet points and code formatting for better readability.

By following these steps, we can arrive at a comprehensive and accurate summary of the provided V8 source code.
好的，这是对提供的 V8 源代码 `v8/test/cctest/wasm/test-gc.cc` 第一部分的分析和功能归纳：

**功能列举:**

`v8/test/cctest/wasm/test-gc.cc` 是 V8 引擎中用于测试 WebAssembly 垃圾回收 (GC) 功能的 C++ 源代码文件。其主要功能包括：

1. **定义和构建 WebAssembly 模块:**  使用 `WasmModuleBuilder` 类来动态构建包含 GC 特性的 WebAssembly 模块，例如定义结构体 (structs)、数组 (arrays)、以及使用引用类型 (references)。
2. **定义 GC 相关指令的测试用例:** 针对 WebAssembly GC 规范中定义的指令（例如 `struct.new`, `struct.get`, `struct.set`, `ref.as_non_null`, `br_on_null`, `br_on_non_null`, `ref.cast`, `br_on_cast`, `br_on_cast_fail`, `ref.eq` 等）编写测试用例。
3. **编译和实例化 WebAssembly 模块:** 使用 V8 的 WebAssembly 编译和实例化功能来加载和准备测试模块。
4. **执行 WebAssembly 函数:** 调用模块中定义的函数来执行包含 GC 指令的代码。
5. **验证执行结果:**  通过 `CheckResult` 和 `CheckHasThrown` 等方法来断言函数执行的返回值或是否抛出了预期的异常。
6. **模拟不同的执行环境:** 可以通过构造 `WasmGCTester` 对象时指定 `TestExecutionTier` 来在不同的执行层级（例如 Liftoff 或 TurboFan）运行测试。
7. **使用 FlagScope 控制 V8 特性开关:**  例如，使用 `FlagScope` 来临时启用或禁用实验性的 WebAssembly 特性，例如跳过空指针检查。

**关于文件后缀名:**

*   `v8/test/cctest/wasm/test-gc.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码文件（Torque 文件的后缀通常是 `.tq`）。

**与 JavaScript 的关系:**

WebAssembly 的 GC 特性允许 WebAssembly 模块管理 JavaScript 堆中的对象，实现更深层次的互操作。虽然这个 C++ 测试文件本身不包含 JavaScript 代码，但它测试的 GC 功能是 WebAssembly 和 JavaScript 交互的基础。

**JavaScript 示例 (概念性):**

假设 WebAssembly 模块中定义了一个返回结构体的函数：

```c++
// WebAssembly (内部表示，不是实际文本格式)
(module
  (type $struct_type (struct (field i32)))
  (func (export "create_struct") (result (ref $struct_type))
    (struct.new $struct_type (i32.const 10)))
)
```

在 JavaScript 中，你可以调用这个函数并操作返回的结构体：

```javascript
async function runWasm() {
  const response = await fetch('your_module.wasm'); // 假设你的 wasm 模块文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  const myStruct = instance.exports.create_struct();
  // 注意：JavaScript 端如何访问和操作 WebAssembly GC 对象取决于 V8 的具体实现
  // 在概念上，你可以访问结构体的字段
  // 例如 (假设 V8 提供了这样的 API):
  // console.log(myStruct.get_field(0)); // 预期输出 10
}

runWasm();
```

**代码逻辑推理 (假设输入与输出):**

以 `WASM_COMPILED_EXEC_TEST(WasmBasicStruct)` 中的 `kGet1` 函数为例：

**假设输入:** 无 (该函数没有参数)

**WebAssembly 代码逻辑 (简化):**

1. 创建一个类型为 `type_index` 的结构体，该结构体有两个 `i32` 类型的字段，分别初始化为 42 和 64。
2. 获取该结构体的第一个字段 (索引为 0)。
3. 返回该字段的值。

**预期输出:** 42

**用户常见的编程错误:**

1. **空引用解引用:**  在 GC 环境中，引用可能为空。尝试访问空引用的字段会导致错误。测试用例 `kNullDereference` 就是为了验证这种情况会抛出异常。

    ```c++
    // C++ 测试代码模拟
    const uint8_t kNullDereference = tester.DefineFunction(
        tester.sigs.i_v(), {},
        {WASM_STRUCT_GET(type_index, 0, WASM_REF_NULL(type_index)), kExprEnd});
    ```

    在概念上，这类似于 JavaScript 中的：

    ```javascript
    let myObject = null;
    console.log(myObject.someProperty); // TypeError: Cannot read properties of null
    ```

2. **错误的类型转换:**  尝试将一个类型的引用强制转换为不兼容的类型可能会导致运行时错误。`RefCast` 测试用例验证了 `ref.cast` 指令的正确行为。

**功能归纳 (针对第 1 部分):**

这部分 `v8/test/cctest/wasm/test-gc.cc` 源代码的主要功能是 **为 V8 引擎的 WebAssembly 垃圾回收 (GC) 特性提供基础的测试框架和一组核心的测试用例**。它涵盖了结构体的创建、字段访问、空引用处理以及一些基本的引用操作指令的测试。它通过 C++ 代码模拟 WebAssembly 的执行环境，并使用 V8 的内部 API 来构建、编译和运行 WebAssembly 模块，最终验证 GC 相关功能的正确性。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-gc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-gc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include "src/base/vector.h"
#include "src/codegen/signature.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/struct-types.h"
#include "src/wasm/wasm-arguments.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/common/wasm/wasm-module-runner.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_gc {

using F = std::pair<ValueType, bool>;

class WasmGCTester {
 public:
  explicit WasmGCTester(
      TestExecutionTier execution_tier = TestExecutionTier::kTurbofan)
      : flag_liftoff(&v8::internal::v8_flags.liftoff,
                     execution_tier == TestExecutionTier::kLiftoff),
        flag_liftoff_only(&v8::internal::v8_flags.liftoff_only,
                          execution_tier == TestExecutionTier::kLiftoff),
        flag_wasm_dynamic_tiering(&v8::internal::v8_flags.wasm_dynamic_tiering,
                                  v8::internal::v8_flags.liftoff_only != true),
        flag_tierup(&v8::internal::v8_flags.wasm_tier_up, false),
        // Manually apply flag implication by disabling deopts in case of
        // --no-liftoff.
        flag_wasm_deopt(&v8::internal::v8_flags.wasm_deopt,
                        v8_flags.wasm_deopt && v8_flags.liftoff),
        zone_(&allocator, ZONE_NAME),
        builder_(&zone_),
        isolate_(CcTest::InitIsolateOnce()),
        scope(isolate_),
        thrower(isolate_, "Test wasm GC") {
    testing::SetupIsolateForWasmModule(isolate_);
  }

  uint8_t AddGlobal(ValueType type, bool mutability, WasmInitExpr init) {
    return builder_.AddGlobal(type, mutability, init);
  }

  uint8_t DefineFunction(FunctionSig* sig,
                         std::initializer_list<ValueType> locals,
                         std::initializer_list<const uint8_t> code) {
    return DefineFunctionImpl(builder_.AddFunction(sig), locals, code);
  }

  uint8_t DefineFunction(ModuleTypeIndex sig_index,
                         std::initializer_list<ValueType> locals,
                         std::initializer_list<const uint8_t> code) {
    return DefineFunctionImpl(builder_.AddFunction(sig_index), locals, code);
  }

  void DefineExportedFunction(const char* name, FunctionSig* sig,
                              std::initializer_list<const uint8_t> code) {
    WasmFunctionBuilder* fun = builder_.AddFunction(sig);
    fun->EmitCode(code);
    builder_.AddExport(base::CStrVector(name), fun);
  }

  MaybeHandle<Object> CallExportedFunction(const char* name, int argc,
                                           Handle<Object> args[]) {
    Handle<WasmExportedFunction> func =
        testing::GetExportedFunction(isolate_, instance_object_, name)
            .ToHandleChecked();
    return Execution::Call(isolate_, func,
                           isolate_->factory()->undefined_value(), argc, args);
  }

  ModuleTypeIndex DefineStruct(std::initializer_list<F> fields,
                               ModuleTypeIndex supertype = kNoSuperType,
                               bool is_final = false) {
    StructType::Builder type_builder(&zone_,
                                     static_cast<uint32_t>(fields.size()));
    for (F field : fields) {
      type_builder.AddField(field.first, field.second);
    }
    return builder_.AddStructType(type_builder.Build(), is_final, supertype);
  }

  ModuleTypeIndex DefineArray(ValueType element_type, bool mutability,
                              ModuleTypeIndex supertype = kNoSuperType,
                              bool is_final = false) {
    return builder_.AddArrayType(zone_.New<ArrayType>(element_type, mutability),
                                 is_final, supertype);
  }

  ModuleTypeIndex DefineSignature(FunctionSig* sig,
                                  ModuleTypeIndex supertype = kNoSuperType,
                                  bool is_final = false) {
    return builder_.ForceAddSignature(sig, is_final, supertype);
  }

  uint8_t DefineTable(ValueType type, uint32_t min_size, uint32_t max_size) {
    return builder_.AddTable(type, min_size, max_size);
  }

  void CompileModule() {
    ZoneBuffer buffer(&zone_);
    builder_.WriteTo(&buffer);
    MaybeHandle<WasmInstanceObject> maybe_instance =
        testing::CompileAndInstantiateForTesting(
            isolate_, &thrower, ModuleWireBytes(buffer.begin(), buffer.end()));
    if (thrower.error()) FATAL("%s", thrower.error_msg());
    instance_object_ = maybe_instance.ToHandleChecked();
    trusted_instance_data_ =
        handle(instance_object_->trusted_data(isolate_), isolate_);
  }

  void CheckResult(uint32_t function_index, int32_t expected) {
    const CanonicalSig* sig = LookupCanonicalSigFor(function_index);
    DCHECK(EquivalentNumericSig(sig, sigs.i_v()));
    CWasmArgumentsPacker packer(CWasmArgumentsPacker::TotalSize(sig));
    CheckResultImpl(function_index, sig, &packer, expected);
  }

  void CheckResult(uint32_t function_index, int32_t expected, int32_t arg) {
    const CanonicalSig* sig = LookupCanonicalSigFor(function_index);
    DCHECK(EquivalentNumericSig(sig, sigs.i_i()));
    CWasmArgumentsPacker packer(CWasmArgumentsPacker::TotalSize(sig));
    packer.Push(arg);
    CheckResultImpl(function_index, sig, &packer, expected);
  }

  MaybeHandle<Object> GetResultObject(uint32_t function_index) {
    const CanonicalSig* sig = LookupCanonicalSigFor(function_index);
    DCHECK_EQ(sig->parameter_count(), 0);
    DCHECK_EQ(sig->return_count(), 1);
    CWasmArgumentsPacker packer(CWasmArgumentsPacker::TotalSize(sig));
    CallFunctionImpl(function_index, sig, &packer);
    CHECK(!isolate_->has_exception());
    packer.Reset();
    return Handle<Object>(Tagged<Object>(packer.Pop<Address>()), isolate_);
  }

  MaybeHandle<Object> GetResultObject(uint32_t function_index, int32_t arg) {
    const CanonicalSig* sig = LookupCanonicalSigFor(function_index);
    DCHECK_EQ(sig->parameter_count(), 1);
    DCHECK_EQ(sig->return_count(), 1);
    DCHECK(sig->parameters()[0] == kCanonicalI32);
    CWasmArgumentsPacker packer(CWasmArgumentsPacker::TotalSize(sig));
    packer.Push(arg);
    CallFunctionImpl(function_index, sig, &packer);
    CHECK(!isolate_->has_exception());
    packer.Reset();
    return Handle<Object>(Tagged<Object>(packer.Pop<Address>()), isolate_);
  }

  void CheckHasThrown(uint32_t function_index, const char* expected = "") {
    const CanonicalSig* sig = LookupCanonicalSigFor(function_index);
    DCHECK_EQ(sig->parameter_count(), 0);
    CWasmArgumentsPacker packer(CWasmArgumentsPacker::TotalSize(sig));
    CheckHasThrownImpl(function_index, sig, &packer, expected);
  }

  void CheckHasThrown(uint32_t function_index, int32_t arg,
                      const char* expected = "") {
    const CanonicalSig* sig = LookupCanonicalSigFor(function_index);
    DCHECK_EQ(sig->parameter_count(), 1);
    DCHECK(sig->parameters()[0] == kCanonicalI32);
    CWasmArgumentsPacker packer(CWasmArgumentsPacker::TotalSize(sig));
    packer.Push(arg);
    CheckHasThrownImpl(function_index, sig, &packer, expected);
  }

  bool HasSimdSupport(TestExecutionTier tier) const {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
    // Liftoff does not have a fallback for executing SIMD instructions if
    // SSE4_1 is not available.
    if (tier == TestExecutionTier::kLiftoff &&
        !CpuFeatures::IsSupported(SSE4_1)) {
      return false;
    }
#endif
    USE(tier);
    return true;
  }

  Handle<WasmInstanceObject> instance_object() const {
    return instance_object_;
  }
  Handle<WasmTrustedInstanceData> trusted_instance_data() const {
    return trusted_instance_data_;
  }
  Isolate* isolate() const { return isolate_; }
  WasmModuleBuilder* builder() { return &builder_; }
  Zone* zone() { return &zone_; }

  TestSignatures sigs;

 private:
  const FlagScope<bool> flag_liftoff;
  const FlagScope<bool> flag_liftoff_only;
  const FlagScope<bool> flag_wasm_dynamic_tiering;
  const FlagScope<bool> flag_tierup;
  const FlagScope<bool> flag_wasm_deopt;

  const CanonicalSig* LookupCanonicalSigFor(uint32_t function_index) const {
    auto* module = instance_object_->module();
    CanonicalTypeIndex sig_id =
        module->canonical_sig_id(module->functions[function_index].sig_index);
    return GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);
  }

  uint8_t DefineFunctionImpl(WasmFunctionBuilder* fun,
                             std::initializer_list<ValueType> locals,
                             std::initializer_list<const uint8_t> code) {
    for (ValueType local : locals) {
      fun->AddLocal(local);
    }
    fun->EmitCode(code);
    return fun->func_index();
  }

  void CheckResultImpl(uint32_t function_index, const CanonicalSig* sig,
                       CWasmArgumentsPacker* packer, int32_t expected) {
    CallFunctionImpl(function_index, sig, packer);
    if (isolate_->has_exception()) {
      DirectHandle<String> message =
          ErrorUtils::ToString(isolate_,
                               handle(isolate_->exception(), isolate_))
              .ToHandleChecked();
      FATAL("%s", message->ToCString().get());
    }
    packer->Reset();
    CHECK_EQ(expected, packer->Pop<int32_t>());
  }

  void CheckHasThrownImpl(uint32_t function_index, const CanonicalSig* sig,
                          CWasmArgumentsPacker* packer, const char* expected) {
    CallFunctionImpl(function_index, sig, packer);
    CHECK(isolate_->has_exception());
    DirectHandle<String> message =
        ErrorUtils::ToString(isolate_, handle(isolate_->exception(), isolate_))
            .ToHandleChecked();
    std::string message_str(message->ToCString().get());
    CHECK_NE(message_str.find(expected), std::string::npos);
    isolate_->clear_exception();
  }

  void CallFunctionImpl(uint32_t function_index, const CanonicalSig* sig,
                        CWasmArgumentsPacker* packer) {
    // The signature must be canonicalized.
    DCHECK(GetTypeCanonicalizer()->Contains(sig));
    WasmCodeRefScope code_ref_scope;
    WasmCodePointer wasm_call_target =
        trusted_instance_data_->GetCallTarget(function_index);
    DirectHandle<Object> object_ref = instance_object_;
    DirectHandle<Code> c_wasm_entry =
        compiler::CompileCWasmEntry(isolate_, sig);
    Execution::CallWasm(isolate_, c_wasm_entry, wasm_call_target, object_ref,
                        packer->argv());
  }

  v8::internal::AccountingAllocator allocator;
  Zone zone_;
  WasmModuleBuilder builder_;

  Isolate* const isolate_;
  const HandleScope scope;
  Handle<WasmInstanceObject> instance_object_;
  Handle<WasmTrustedInstanceData> trusted_instance_data_;
  ErrorThrower thrower;
};

ValueType ref(ModuleTypeIndex type_index) { return ValueType::Ref(type_index); }
ValueType refNull(ModuleTypeIndex type_index) {
  return ValueType::RefNull(type_index);
}

WASM_COMPILED_EXEC_TEST(WasmBasicStruct) {
  WasmGCTester tester(execution_tier);

  const ModuleTypeIndex type_index =
      tester.DefineStruct({F(kWasmI32, true), F(kWasmI32, true)});
  const ModuleTypeIndex empty_struct_index = tester.DefineStruct({});
  ValueType kRefType = ref(type_index);
  ValueType kEmptyStructType = ref(empty_struct_index);
  ValueType kRefNullType = refNull(type_index);
  FunctionSig sig_q_v(1, 0, &kRefType);
  FunctionSig sig_qe_v(1, 0, &kEmptyStructType);

  // Test struct.new and struct.get.
  const uint8_t kGet1 = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_STRUCT_GET(
           type_index, 0,
           WASM_STRUCT_NEW(type_index, WASM_I32V(42), WASM_I32V(64))),
       kExprEnd});

  // Test struct.new and struct.get.
  const uint8_t kGet2 = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_STRUCT_GET(
           type_index, 1,
           WASM_STRUCT_NEW(type_index, WASM_I32V(42), WASM_I32V(64))),
       kExprEnd});

  // Test struct.new, returning struct reference.
  const uint8_t kGetStruct = tester.DefineFunction(
      &sig_q_v, {},
      {WASM_STRUCT_NEW(type_index, WASM_I32V(42), WASM_I32V(64)), kExprEnd});

  const uint8_t kGetStructNominal = tester.DefineFunction(
      &sig_q_v, {},
      {WASM_STRUCT_NEW_DEFAULT(type_index), WASM_DROP,
       WASM_STRUCT_NEW(type_index, WASM_I32V(42), WASM_I32V(64)), kExprEnd});

  // Test struct.new, returning reference to an empty struct.
  const uint8_t kGetEmptyStruct = tester.DefineFunction(
      &sig_qe_v, {},
      {WASM_GC_OP(kExprStructNew), ToByte(empty_struct_index), kExprEnd});

  // Test struct.set, struct refs types in locals.
  const uint8_t j_local_index = 0;
  const uint8_t j_field_index = 0;
  const uint8_t kSet = tester.DefineFunction(
      tester.sigs.i_v(), {kRefNullType},
      {WASM_LOCAL_SET(j_local_index, WASM_STRUCT_NEW(type_index, WASM_I32V(42),
                                                     WASM_I32V(64))),
       WASM_STRUCT_SET(type_index, j_field_index, WASM_LOCAL_GET(j_local_index),
                       WASM_I32V(-99)),
       WASM_STRUCT_GET(type_index, j_field_index,
                       WASM_LOCAL_GET(j_local_index)),
       kExprEnd});

  const uint8_t kNullDereference = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_STRUCT_GET(type_index, 0, WASM_REF_NULL(type_index)), kExprEnd});

  tester.CompileModule();

  tester.CheckResult(kGet1, 42);
  tester.CheckResult(kGet2, 64);
  CHECK(IsWasmStruct(*tester.GetResultObject(kGetStruct).ToHandleChecked()));
  CHECK(IsWasmStruct(
      *tester.GetResultObject(kGetStructNominal).ToHandleChecked()));
  CHECK(
      IsWasmStruct(*tester.GetResultObject(kGetEmptyStruct).ToHandleChecked()));
  tester.CheckResult(kSet, -99);
  tester.CheckHasThrown(kNullDereference);
}

// Test struct.get, ref.as_non_null and ref-typed globals.
WASM_COMPILED_EXEC_TEST(WasmRefAsNonNull) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex type_index =
      tester.DefineStruct({F(kWasmI32, true), F(kWasmI32, true)});
  ValueType kRefTypes[] = {ref(type_index)};
  ValueType kRefNullType = refNull(type_index);
  FunctionSig sig_q_v(1, 0, kRefTypes);

  const uint8_t global_index = tester.AddGlobal(
      kRefNullType, true, WasmInitExpr::RefNullConst(type_index));
  const uint8_t field_index = 0;
  const uint8_t kNonNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_GLOBAL_SET(global_index, WASM_STRUCT_NEW(type_index, WASM_I32V(55),
                                                     WASM_I32V(66))),
       WASM_STRUCT_GET(type_index, field_index,
                       WASM_REF_AS_NON_NULL(WASM_GLOBAL_GET(global_index))),
       kExprEnd});
  const uint8_t kNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_GLOBAL_SET(global_index, WASM_REF_NULL(type_index)),
       WASM_STRUCT_GET(type_index, field_index,
                       WASM_REF_AS_NON_NULL(WASM_GLOBAL_GET(global_index))),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kNonNull, 55);
  tester.CheckHasThrown(kNull);
}

WASM_COMPILED_EXEC_TEST(WasmRefAsNonNullSkipCheck) {
  FlagScope<bool> no_check(&v8_flags.experimental_wasm_skip_null_checks, true);
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex type_index =
      tester.DefineStruct({F(kWasmI32, true), F(kWasmI32, true)});
  ValueType kRefType = ref(type_index);
  FunctionSig sig_q_v(1, 0, &kRefType);

  const uint8_t global_index = tester.AddGlobal(
      refNull(type_index), true, WasmInitExpr::RefNullConst(type_index));
  const uint8_t kFunc = tester.DefineFunction(
      &sig_q_v, {},
      {WASM_GLOBAL_SET(global_index, WASM_REF_NULL(type_index)),
       WASM_REF_AS_NON_NULL(WASM_GLOBAL_GET(global_index)), kExprEnd});

  tester.CompileModule();
  DirectHandle<Object> result = tester.GetResultObject(kFunc).ToHandleChecked();
  // Without null checks, ref.as_non_null can actually return null.
  CHECK(IsWasmNull(*result));
}

WASM_COMPILED_EXEC_TEST(WasmBrOnNull) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex type_index =
      tester.DefineStruct({F(kWasmI32, true), F(kWasmI32, true)});
  ValueType kRefTypes[] = {ref(type_index)};
  ValueType kRefNullType = refNull(type_index);
  FunctionSig sig_q_v(1, 0, kRefTypes);
  const uint8_t local_index = 0;
  const uint8_t kTaken = tester.DefineFunction(
      tester.sigs.i_v(), {kRefNullType},
      {WASM_BLOCK_I(WASM_I32V(42),
                    // Branch will be taken.
                    // 42 left on stack outside the block (not 52).
                    WASM_BR_ON_NULL(0, WASM_LOCAL_GET(local_index)),
                    WASM_I32V(52), WASM_BR(0)),
       kExprEnd});

  const uint8_t field_index = 0;
  const uint8_t kNotTaken = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_BLOCK_I(
           WASM_I32V(42),
           WASM_STRUCT_GET(
               type_index, field_index,
               // Branch will not be taken.
               // 52 left on stack outside the block (not 42).
               WASM_BR_ON_NULL(0, WASM_STRUCT_NEW(type_index, WASM_I32V(52),
                                                  WASM_I32V(62)))),
           WASM_BR(0)),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kTaken, 42);
  tester.CheckResult(kNotTaken, 52);
}

WASM_COMPILED_EXEC_TEST(WasmBrOnNonNull) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex type_index =
      tester.DefineStruct({F(kWasmI32, true), F(kWasmI32, true)});
  ValueType kRefType = ref(type_index);
  ValueType kRefNullType = refNull(type_index);
  FunctionSig sig_q_v(1, 0, &kRefType);
  const uint8_t field_index = 0;

  const uint8_t kTaken = tester.DefineFunction(
      tester.sigs.i_v(), {kRefNullType, kRefNullType},
      {WASM_LOCAL_SET(
           0, WASM_STRUCT_NEW(type_index, WASM_I32V(52), WASM_I32V(62))),
       WASM_LOCAL_SET(
           1, WASM_STRUCT_NEW(type_index, WASM_I32V(11), WASM_I32V(22))),
       WASM_STRUCT_GET(type_index, field_index,
                       WASM_BLOCK_R(ref(type_index),
                                    // Branch will be taken, and the block will
                                    // return struct(52, 62).
                                    WASM_BR_ON_NON_NULL(0, WASM_LOCAL_GET(0)),
                                    WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(1)))),
       kExprEnd});

  const uint8_t kNotTaken = tester.DefineFunction(
      tester.sigs.i_v(), {kRefNullType, kRefNullType},
      {WASM_LOCAL_SET(0, WASM_REF_NULL(type_index)),
       WASM_LOCAL_SET(
           1, WASM_STRUCT_NEW(type_index, WASM_I32V(11), WASM_I32V(22))),
       WASM_STRUCT_GET(type_index, field_index,
                       WASM_BLOCK_R(ref(type_index),
                                    // Branch will not be taken, and the block
                                    // will return struct(11, 22).
                                    WASM_BR_ON_NON_NULL(0, WASM_LOCAL_GET(0)),
                                    WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(1)))),
       kExprEnd});
  tester.CompileModule();
  tester.CheckResult(kTaken, 52);
  tester.CheckResult(kNotTaken, 11);
}

WASM_COMPILED_EXEC_TEST(RefCast) {
  WasmGCTester tester(execution_tier);

  const ModuleTypeIndex supertype_index =
      tester.DefineStruct({F(kWasmI32, true)});
  const ModuleTypeIndex subtype1_index = tester.DefineStruct(
      {F(kWasmI32, true), F(kWasmF32, false)}, supertype_index);
  const ModuleTypeIndex subtype2_index = tester.DefineStruct(
      {F(kWasmI32, true), F(kWasmI64, false)}, supertype_index);
  auto super_sig =
      FixedSizeSignature<ValueType>::Params(ValueType::RefNull(subtype1_index))
          .Returns(ValueType::RefNull(supertype_index));
  auto sub_sig1 =
      FixedSizeSignature<ValueType>::Params(ValueType::RefNull(supertype_index))
          .Returns(ValueType::RefNull(subtype1_index));
  auto sub_sig2 =
      FixedSizeSignature<ValueType>::Params(ValueType::RefNull(supertype_index))
          .Returns(ValueType::RefNull(subtype2_index));
  const ModuleTypeIndex function_type_index =
      tester.DefineSignature(&super_sig);
  const ModuleTypeIndex function_subtype1_index =
      tester.DefineSignature(&sub_sig1, function_type_index);
  const ModuleTypeIndex function_subtype2_index =
      tester.DefineSignature(&sub_sig2, function_type_index);
  const uint8_t function_index = tester.DefineFunction(
      function_subtype1_index, {},
      {WASM_STRUCT_NEW(subtype1_index, WASM_I32V(10), WASM_F32(20)), WASM_END});
  // Just so this function counts as "declared".
  tester.AddGlobal(ValueType::RefNull(function_type_index), false,
                   WasmInitExpr::RefFuncConst(function_index));

  const uint8_t kTestSuccessful = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(supertype_index)},
      {WASM_LOCAL_SET(
           0, WASM_STRUCT_NEW(subtype1_index, WASM_I32V(10), WASM_F32(20))),
       WASM_STRUCT_GET(subtype1_index, 0,
                       WASM_REF_CAST(WASM_LOCAL_GET(0), subtype1_index)),
       WASM_END});

  const uint8_t kTestFailed = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(supertype_index)},
      {WASM_LOCAL_SET(
           0, WASM_STRUCT_NEW(subtype1_index, WASM_I32V(10), WASM_F32(20))),
       WASM_STRUCT_GET(subtype2_index, 0,
                       WASM_REF_CAST(WASM_LOCAL_GET(0), subtype2_index)),
       WASM_END});

  const uint8_t kFuncTestSuccessfulSuper = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(function_type_index)},
      {WASM_LOCAL_SET(0, WASM_REF_FUNC(function_index)),
       WASM_REF_CAST(WASM_LOCAL_GET(0), function_type_index), WASM_DROP,
       WASM_I32V(0), WASM_END});

  const uint8_t kFuncTestSuccessfulSub = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(function_type_index)},
      {WASM_LOCAL_SET(0, WASM_REF_FUNC(function_index)),
       WASM_REF_CAST(WASM_LOCAL_GET(0), function_subtype1_index), WASM_DROP,
       WASM_I32V(0), WASM_END});

  const uint8_t kFuncTestFailed = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(function_type_index)},
      {WASM_LOCAL_SET(0, WASM_REF_FUNC(function_index)),
       WASM_REF_CAST(WASM_LOCAL_GET(0), function_subtype2_index), WASM_DROP,
       WASM_I32V(1), WASM_END});

  tester.CompileModule();
  tester.CheckResult(kTestSuccessful, 10);
  tester.CheckHasThrown(kTestFailed);
  tester.CheckResult(kFuncTestSuccessfulSuper, 0);
  tester.CheckResult(kFuncTestSuccessfulSub, 0);
  tester.CheckHasThrown(kFuncTestFailed);
}

WASM_COMPILED_EXEC_TEST(RefCastNoChecks) {
  FlagScope<bool> scope(&v8_flags.experimental_wasm_assume_ref_cast_succeeds,
                        true);
  WasmGCTester tester(execution_tier);

  const ModuleTypeIndex supertype_index =
      tester.DefineStruct({F(kWasmI32, true)});
  const ModuleTypeIndex subtype1_index = tester.DefineStruct(
      {F(kWasmI32, true), F(kWasmF32, true)}, supertype_index);

  const uint8_t kTestSuccessful = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(supertype_index)},
      {WASM_LOCAL_SET(0, WASM_STRUCT_NEW_DEFAULT(subtype1_index)),
       WASM_STRUCT_GET(subtype1_index, 0,
                       WASM_REF_CAST(WASM_LOCAL_GET(0), subtype1_index)),
       WASM_END});

  tester.CompileModule();
  tester.CheckResult(kTestSuccessful, 0);
}

WASM_COMPILED_EXEC_TEST(BrOnCast) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex type_index = tester.DefineStruct({F(kWasmI32, true)});
  const ModuleTypeIndex other_type_index =
      tester.DefineStruct({F(kWasmF32, true)});

  const uint8_t kTestStructStatic = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmI32, kWasmStructRef},
      {WASM_BLOCK_R(
           ValueType::RefNull(type_index), WASM_LOCAL_SET(0, WASM_I32V(111)),
           // Pipe a struct through a local so it's statically typed
           // as structref.
           WASM_LOCAL_SET(1, WASM_STRUCT_NEW(other_type_index, WASM_F32(1.0))),
           WASM_LOCAL_GET(1),
           // The type check fails, so this branch isn't taken.
           WASM_BR_ON_CAST(0, kStructRefCode, type_index), WASM_DROP,

           WASM_LOCAL_SET(0, WASM_I32V(221)),  // (Final result) - 1
           WASM_LOCAL_SET(1, WASM_STRUCT_NEW(type_index, WASM_I32V(1))),
           WASM_LOCAL_GET(1),
           // This branch is taken.
           WASM_BR_ON_CAST(0, kStructRefCode, type_index),
           WASM_GC_OP(kExprRefCast), ToByte(type_index),

           // Not executed due to the branch.
           WASM_LOCAL_SET(0, WASM_I32V(333))),
       WASM_GC_OP(kExprStructGet), ToByte(type_index), 0, WASM_LOCAL_GET(0),
       kExprI32Add, kExprEnd});

  const uint8_t kTestStructStaticNull = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmI32, kWasmStructRef},
      {WASM_BLOCK_R(
           ValueType::RefNull(type_index), WASM_LOCAL_SET(0, WASM_I32V(111)),
           // Pipe a struct through a local so it's statically typed as
           // structref.
           WASM_LOCAL_SET(1, WASM_STRUCT_NEW(other_type_index, WASM_F32(1.0))),
           WASM_LOCAL_GET(1),
           // The type check fails, so this branch isn't taken.
           WASM_BR_ON_CAST(0, kStructRefCode, type_index), WASM_DROP,

           WASM_LOCAL_SET(0, WASM_I32V(221)),  // (Final result) - 1
           WASM_LOCAL_SET(1, WASM_STRUCT_NEW(type_index, WASM_I32V(1))),
           WASM_LOCAL_GET(1),
           // This branch is taken.
           WASM_BR_ON_CAST_NULL(0, kStructRefCode, type_index),
           WASM_GC_OP(kExprRefCast), ToByte(type_index),

           // Not executed due to the branch.
           WASM_LOCAL_SET(0, WASM_I32V(333))),
       WASM_GC_OP(kExprStructGet), ToByte(type_index), 0, WASM_LOCAL_GET(0),
       kExprI32Add, kExprEnd});

  const uint8_t kTestNull = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmI32, kWasmStructRef},
      {WASM_BLOCK_R(ValueType::RefNull(type_index),
                    WASM_LOCAL_SET(0, WASM_I32V(111)),
                    WASM_LOCAL_GET(1),  // Put a nullref onto the value stack.
                    // Not taken for nullref.
                    WASM_BR_ON_CAST(0, kStructRefCode, type_index),
                    WASM_GC_OP(kExprRefCast),
                    ToByte(type_index)),  // Traps
       WASM_DROP, WASM_LOCAL_GET(0), kExprEnd});

  // "br_on_cast null" also branches on null, treating it as a successful cast.
  const uint8_t kTestNullNull = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmI32, kWasmStructRef},
      {WASM_BLOCK_R(ValueType::RefNull(type_index),
                    WASM_LOCAL_SET(0, WASM_I32V(111)),
                    WASM_LOCAL_GET(1),  // Put a nullref onto the value stack.
                    // Taken for nullref with br_on_cast null.
                    WASM_BR_ON_CAST_NULL(0, kStructRefCode, type_index),
                    WASM_GC_OP(kExprRefCast), ToByte(type_index)),
       WASM_DROP, WASM_LOCAL_GET(0), kExprEnd});

  const uint8_t kTypedAfterBranch = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmI32, kWasmStructRef},
      {WASM_LOCAL_SET(1, WASM_STRUCT_NEW(type_index, WASM_I32V(42))),
       WASM_BLOCK_I(
           // The inner block should take the early branch with a struct
           // on the stack.
           WASM_BLOCK_R(ValueType::Ref(type_index), WASM_LOCAL_GET(1),
                        WASM_BR_ON_CAST(0, kStructRefCode, type_index),
                        // Returning 123 is the unreachable failure case.
                        WASM_I32V(123), WASM_BR(1)),
           // The outer block catches the struct left behind by the inner block
           // and reads its field.
           WASM_GC_OP(kExprStructGet), ToByte(type_index), 0),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kTestStructStatic, 222);
  tester.CheckResult(kTestStructStaticNull, 222);
  tester.CheckHasThrown(kTestNull);
  tester.CheckResult(kTestNullNull, 111);
  tester.CheckResult(kTypedAfterBranch, 42);
}

WASM_COMPILED_EXEC_TEST(BrOnCastFail) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex type0 = tester.DefineStruct({F(kWasmI32, true)});
  const ModuleTypeIndex type1 =
      tester.DefineStruct({F(kWasmI64, true), F(kWasmI32, true)});

  const int field0_value = 5;
  const int field1_value = 25;
  const int null_value = 45;

  //  local_0 = value;
  //  if (!(local_0 instanceof type0)) goto block1;
  //  return static_cast<type0>(local_0).field_0;
  // block1:
  //  if (local_0 == nullptr) goto block2;
  //  return static_cast<type1>(local_0).field_1;
  // block2:
  //  return null_value;
#define FUNCTION_BODY(value)                                                  \
  WASM_LOCAL_SET(0, WASM_SEQ(value)),                                         \
      WASM_BLOCK(WASM_BLOCK_R(kWasmStructRef, WASM_LOCAL_GET(0),              \
                              WASM_BR_ON_CAST_FAIL(0, kStructRefCode, type0), \
                              WASM_GC_OP(kExprStructGet), ToByte(type0), 0,   \
                              kExprReturn),                                   \
                 kExprBrOnNull, 0, WASM_GC_OP(kExprRefCast), ToByte(type1),   \
                 WASM_GC_OP(kExprStructGet), ToByte(type1), 1, kExprReturn),  \
      WASM_I32V(null_value), kExprEnd

  const uint8_t kBranchTaken = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmStructRef},
      {FUNCTION_BODY(
          WASM_STRUCT_NEW(type1, WASM_I64V(10), WASM_I32V(field1_value)))});

  const uint8_t kBranchNotTaken = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmStructRef},
      {FUNCTION_BODY(WASM_STRUCT_NEW(type0, WASM_I32V(field0_value)))});

  const uint8_t kNull =
      tester.DefineFunction(tester.sigs.i_v(), {kWasmStructRef},
                            {FUNCTION_BODY(WASM_REF_NULL(type0))});

  const uint8_t kUnrelatedTypes = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(type1)},
      {FUNCTION_BODY(
          WASM_STRUCT_NEW(type1, WASM_I64V(10), WASM_I32V(field1_value)))});
#undef FUNCTION_BODY

  const uint8_t kBranchTakenStatic = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmStructRef},
      {WASM_LOCAL_SET(
           0, WASM_STRUCT_NEW(type1, WASM_I64V(10), WASM_I32V(field1_value))),
       WASM_BLOCK(WASM_BLOCK_R(kWasmStructRef, WASM_LOCAL_GET(0),
                               WASM_BR_ON_CAST_FAIL(0, kStructRefCode, type0),
                               WASM_GC_OP(kExprStructGet), ToByte(type0), 0,
                               kExprReturn),
                  kExprBrOnNull, 0, WASM_GC_OP(kExprRefCast), ToByte(type1),
                  WASM_GC_OP(kExprStructGet), ToByte(type1), 1, kExprReturn),
       WASM_I32V(null_value), kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kBranchTaken, field1_value);
  tester.CheckResult(kBranchTakenStatic, field1_value);
  tester.CheckResult(kBranchNotTaken, field0_value);
  tester.CheckResult(kNull, null_value);
  tester.CheckResult(kUnrelatedTypes, field1_value);
}

WASM_COMPILED_EXEC_TEST(WasmRefEq) {
  WasmGCTester tester(execution_tier);
  ModuleTypeIndex type_index =
      tester.DefineStruct({F(kWasmI32, true), F(kWasmI32, true)});
  ValueType kRefTypes[] = {ref(type_index)};
  ValueType kRefNullType = refNull(type_index);
  FunctionSig sig_q_v(1, 0, kRefTypes);

  uint8_t local_index = 0;
  const uint8_t kFunc = tester.DefineFunction(
      tester.sigs.i_v(), {kRefNullType},
      {WASM_LOCAL_SET(local_index, WASM_STRUCT_NEW(type_index, WASM_I32V(55),
                                                   WASM_I32V(66))),
       WASM_I32_ADD(
           WASM_I32_SHL(
               WASM_REF_EQ(  // true
                   WASM_LOCAL_GET(local_index), WASM_LOCAL_GET(local_index)),
               WASM_I32V(0)),
           WASM_I32_ADD(
               WASM_I32_SHL(WASM_REF_EQ(  // false
                                WASM_LOCAL_GET(local_index),
                                WASM_STRUCT_NEW(type_index, WASM_I32V(55),
                                                WASM_I32V(66))),
                            WASM_I32V(1)),
               WASM_I32_ADD(WASM_I32_SHL(  // false
                                WASM_REF_EQ(WASM_LOCAL_GET(local_index),
                                            WASM_REF_NULL(type_index)),
                                WASM_I32V(2)),
                            WASM_I32_SHL(WASM_REF_EQ(  // true
                                             WASM_REF_NULL(type_index),
```