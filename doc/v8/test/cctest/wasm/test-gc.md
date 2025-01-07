Response: The user wants me to summarize the functionality of the C++ code provided in `v8/test/cctest/wasm/test-gc.cc`. The file appears to contain tests for WebAssembly's garbage collection features.

Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The filename `test-gc.cc` and the namespace `wasm::test_gc` strongly suggest that this code is for testing garbage collection related features in the V8 WebAssembly implementation.

2. **Examine the `WasmGCTester` Class:** This class seems to be a test fixture. It provides methods for:
    * Building WebAssembly modules (`AddGlobal`, `DefineFunction`, `DefineExportedFunction`, `DefineStruct`, `DefineArray`, `DefineSignature`, `DefineTable`, `CompileModule`).
    * Executing WebAssembly functions and checking their results (`CallExportedFunction`, `CheckResult`, `GetResultObject`, `CheckHasThrown`).
    * Accessing internal V8 structures related to the WebAssembly instance.

3. **Analyze the `WASM_COMPILED_EXEC_TEST` Macros:** These macros indicate individual test cases. The names of these tests give hints about the specific GC features being tested:
    * `WasmBasicStruct`: Testing basic operations on structs (`struct.new`, `struct.get`, `struct.set`).
    * `WasmRefAsNonNull`: Testing the `ref.as_non_null` operator and its interaction with null references.
    * `WasmRefAsNonNullSkipCheck`: Testing the behavior of `ref.as_non_null` when null checks are skipped.
    * `WasmBrOnNull`/`WasmBrOnNonNull`: Testing branching based on null checks for references.
    * `RefCast`: Testing the `ref.cast` operator for downcasting and upcasting.
    * `RefCastNoChecks`: Testing `ref.cast` when type checks are disabled.
    * `BrOnCast`/`BrOnCastFail`: Testing conditional branching based on successful/failed reference casts.
    * `WasmRefEq`: Testing the `ref.eq` operator for reference equality.
    * `WasmPackedStructU`/`WasmPackedStructS`: Testing operations on structs with packed (smaller than word size) fields.
    * `WasmBasicArray`: Testing basic array operations (`array.new`, `array.get`, `array.set`, `array.len`).
    * `WasmPackedArrayU`/`WasmPackedArrayS`: Testing operations on arrays with packed elements.
    * `WasmArrayCopy`: Testing the `array.copy` instruction.
    * `NewDefault`: Testing the `struct.new_default` and `array.new_default` instructions.
    * `RefTrivialCastsStatic`: Testing trivial (always succeeding or failing) casts that can be optimized statically.
    * `TrivialAbstractCasts`: Testing casts to abstract reference types like `arrayref` and `funcref`.
    * `ArrayNewMap`: Testing the creation of arrays and their associated maps.
    * `FunctionRefs`: Testing the use of function references (`funcref`).

4. **Identify Relationships with JavaScript:**  WebAssembly's GC features are designed to interact with JavaScript's garbage collection. Specifically:
    * **`ref` types in WebAssembly correspond to JavaScript objects.** When a WebAssembly function returns a `ref`, it can be passed to JavaScript, and vice versa.
    * **WebAssembly structs and arrays are analogous to JavaScript objects and arrays.**
    * **`ref.cast` operations are similar to type checking and casting in JavaScript.**
    * **`ref.eq` is similar to the `===` operator for objects in JavaScript.**

5. **Construct a JavaScript Example:**  To illustrate the connection, I need a simple JavaScript example that uses the features being tested in the C++ code. A basic example involving creating a WebAssembly instance with GC features, creating a struct, accessing its fields, and potentially casting it would be appropriate.

6. **Formulate the Summary:** Combine the information gathered to create a concise summary of the C++ file's functionality, highlighting its role in testing WebAssembly GC and providing a JavaScript example to illustrate the connection.

7. **Review and Refine:** Ensure the summary is accurate, clear, and addresses all aspects of the prompt. Make sure the JavaScript example is relevant and easy to understand. Since this is part 1 of 2, I should focus on summarizing the features tested in this specific code block.
这个C++源代码文件 `v8/test/cctest/wasm/test-gc.cc` 的主要功能是**测试 V8 引擎中 WebAssembly 的垃圾回收 (GC) 相关特性**。

更具体地说，这个文件包含了一系列的 C++ 测试用例，这些测试用例旨在验证 WebAssembly 的 GC 指令（如 `struct.new`, `struct.get`, `struct.set`, `array.new`, `array.get`, `array.set`, `ref.cast`, `ref.test` 等）在不同场景下的行为是否符合预期。

这些测试覆盖了以下 WebAssembly GC 的关键方面：

* **结构体 (Structs):**  测试结构体的创建、字段访问（读取和写入）、空引用处理等。
* **数组 (Arrays):** 测试数组的创建、元素访问（读取和写入）、长度获取、数组复制等。
* **引用 (References):** 测试引用的类型转换 (`ref.cast`)、类型判断 (`ref.test`)、空引用判断 (`ref.is_null`)、非空断言 (`ref.as_non_null`)、引用相等性比较 (`ref.eq`)，以及基于引用是否为空或能否转换类型的分支指令 (`br_on_null`, `br_on_non_null`, `br_on_cast`, `br_on_cast_fail`)。
* **默认值 (New Default):** 测试使用默认值创建结构体和数组。
* **函数引用 (Function References):** 测试函数引用的创建和类型转换。
* **Packed 类型:** 测试对结构体和数组中 packed 类型 (如 `i8`, `i16`) 的访问。
* **类型系统:** 测试结构体和数组的子类型和父类型之间的转换。

**它与 JavaScript 的功能关系：**

WebAssembly 的 GC 特性旨在与 JavaScript 的 GC 互操作。当 WebAssembly 模块使用 GC 特性创建结构体或数组时，这些对象可以被 JavaScript 代码访问和操作，并且它们的生命周期由 JavaScript 的垃圾回收器管理。

**JavaScript 举例说明：**

假设在 WebAssembly 中定义了一个结构体类型和一个导出函数，该函数创建并返回该结构体的实例：

**WebAssembly (简化示例):**

```wasm
(module
  (type $struct_type (struct (field i32)))
  (func (export "create_struct") (result (ref $struct_type))
    (struct.new $struct_type (i32.const 42))
  )
)
```

在 JavaScript 中，你可以加载并实例化这个 WebAssembly 模块，然后调用导出的函数来获取结构体实例，并访问其字段（尽管 JavaScript 直接访问 WebAssembly 结构体的字段可能需要特定的 API，例如 `WebAssembly.Instance.exports` 返回的对象通常是 JavaScript 包装器）：

**JavaScript:**

```javascript
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm'); // 假设你的 wasm 文件名为 your_wasm_module.wasm
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const myStructRef = instance.exports.create_struct();

  // myStructRef 是一个对 WebAssembly 结构体的引用。
  // 在实际的 JavaScript API 中，你可能需要进一步操作才能访问结构体的字段。
  // 例如，如果 V8 提供了特定的 API，可能会像这样：
  // console.log(myStructRef.get_field(0)); // 假设有这样的 API 来访问字段

  // 或者，更常见的是，WebAssembly 函数会提供访问器函数：
  // WebAssembly (补充示例):
  // (func (export "get_struct_field") (param (ref $struct_type)) (result i32)
  //   (struct.get $struct_type 0 (local.get 0))
  // )
  //
  // JavaScript:
  // console.log(instance.exports.get_struct_field(myStructRef));
}

runWasm();
```

在这个例子中，WebAssembly 代码创建了一个结构体，JavaScript 代码接收了这个结构体的引用。  V8 的 GC 机制确保即使结构体是在 WebAssembly 中创建的，当 JavaScript 中不再有对它的引用时，该结构体也会被回收。 `v8/test/cctest/wasm/test-gc.cc` 中的测试正是为了验证这种跨语言的 GC 交互的正确性。

总结来说，这个 C++ 文件是 V8 引擎中用于测试 WebAssembly 垃圾回收特性的单元测试，它验证了 WebAssembly GC 指令的正确实现，并确保了 WebAssembly 的 GC 能与 JavaScript 的 GC 系统良好地协同工作。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-gc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
                                             WASM_REF_NULL(type_index)),
                                         WASM_I32V(3))))),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kFunc, 0b1001);
}

WASM_COMPILED_EXEC_TEST(WasmPackedStructU) {
  WasmGCTester tester(execution_tier);

  const ModuleTypeIndex type_index = tester.DefineStruct(
      {F(kWasmI8, true), F(kWasmI16, true), F(kWasmI32, true)});
  ValueType struct_type = refNull(type_index);

  const uint8_t local_index = 0;

  int32_t expected_output_0 = 0x1234;
  int32_t expected_output_1 = -1;

  const uint8_t kF0 = tester.DefineFunction(
      tester.sigs.i_v(), {struct_type},
      {WASM_LOCAL_SET(local_index,
                      WASM_STRUCT_NEW(type_index, WASM_I32V(expected_output_0),
                                      WASM_I32V(expected_output_1),
                                      WASM_I32V(0x12345678))),
       WASM_STRUCT_GET_U(type_index, 0, WASM_LOCAL_GET(local_index)),
       kExprEnd});

  const uint8_t kF1 = tester.DefineFunction(
      tester.sigs.i_v(), {struct_type},
      {WASM_LOCAL_SET(local_index,
                      WASM_STRUCT_NEW(type_index, WASM_I32V(expected_output_0),
                                      WASM_I32V(expected_output_1),
                                      WASM_I32V(0x12345678))),
       WASM_STRUCT_GET_U(type_index, 1, WASM_LOCAL_GET(local_index)),
       kExprEnd});
  tester.CompileModule();

  tester.CheckResult(kF0, static_cast<uint8_t>(expected_output_0));
  tester.CheckResult(kF1, static_cast<uint16_t>(expected_output_1));
}

WASM_COMPILED_EXEC_TEST(WasmPackedStructS) {
  WasmGCTester tester(execution_tier);

  const ModuleTypeIndex type_index = tester.DefineStruct(
      {F(kWasmI8, true), F(kWasmI16, true), F(kWasmI32, true)});
  ValueType struct_type = refNull(type_index);

  const uint8_t local_index = 0;

  int32_t expected_output_0 = 0x80;
  int32_t expected_output_1 = 42;

  const uint8_t kF0 = tester.DefineFunction(
      tester.sigs.i_v(), {struct_type},
      {WASM_LOCAL_SET(
           local_index,
           WASM_STRUCT_NEW(type_index, WASM_I32V(expected_output_0),
                           WASM_I32V(expected_output_1), WASM_I32V(0))),
       WASM_STRUCT_GET_S(type_index, 0, WASM_LOCAL_GET(local_index)),
       kExprEnd});

  const uint8_t kF1 = tester.DefineFunction(
      tester.sigs.i_v(), {struct_type},
      {WASM_LOCAL_SET(local_index, WASM_STRUCT_NEW(type_index, WASM_I32V(0x80),
                                                   WASM_I32V(expected_output_1),
                                                   WASM_I32V(0))),
       WASM_STRUCT_GET_S(type_index, 1, WASM_LOCAL_GET(local_index)),
       kExprEnd});

  tester.CompileModule();

  tester.CheckResult(kF0, static_cast<int8_t>(expected_output_0));
  tester.CheckResult(kF1, static_cast<int16_t>(expected_output_1));
}

WASM_COMPILED_EXEC_TEST(WasmBasicArray) {
  WasmGCTester tester(execution_tier);
  if (!tester.HasSimdSupport(execution_tier)) return;

  const ModuleTypeIndex type_index = tester.DefineArray(wasm::kWasmI32, true);
  const ModuleTypeIndex fp_type_index =
      tester.DefineArray(wasm::kWasmF64, true);
  const ModuleTypeIndex immut_type_index =
      tester.DefineArray(wasm::kWasmI32, false);
  ValueType kRefTypes[] = {ref(type_index)};
  FunctionSig sig_q_v(1, 0, kRefTypes);
  ValueType kRefNullType = refNull(type_index);

  // f: a = [12, 12, 12]; a[1] = 42; return a[arg0]
  const uint8_t local_index = 1;
  const uint8_t kGetElem = tester.DefineFunction(
      tester.sigs.i_i(), {kRefNullType},
      {WASM_LOCAL_SET(local_index,
                      WASM_ARRAY_NEW(type_index, WASM_I32V(12), WASM_I32V(3))),
       WASM_ARRAY_SET(type_index, WASM_LOCAL_GET(local_index), WASM_I32V(1),
                      WASM_I32V(42)),
       WASM_ARRAY_GET(type_index, WASM_LOCAL_GET(local_index),
                      WASM_LOCAL_GET(0)),
       kExprEnd});

  // Reads and returns an array's length.
  const uint8_t kGetLength = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_ARRAY_LEN(WASM_ARRAY_NEW(type_index, WASM_I32V(0), WASM_I32V(42))),
       kExprEnd});

  // Create an array of length 2, initialized to [42, 42].
  const uint8_t kAllocate = tester.DefineFunction(
      &sig_q_v, {},
      {WASM_ARRAY_NEW(type_index, WASM_I32V(42), WASM_I32V(2)), kExprEnd});

  const uint8_t kAllocateStatic = tester.DefineFunction(
      &sig_q_v, {},
      {WASM_ARRAY_NEW_DEFAULT(type_index, WASM_I32V(2)), WASM_DROP,
       WASM_ARRAY_NEW(type_index, WASM_I32V(42), WASM_I32V(2)), kExprEnd});

  const uint8_t kInit =
      tester.DefineFunction(&sig_q_v, {},
                            {WASM_ARRAY_NEW_FIXED(type_index, 3, WASM_I32V(10),
                                                  WASM_I32V(20), WASM_I32V(30)),
                             kExprEnd});

  const uint8_t kImmutable = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_ARRAY_GET(immut_type_index,
                      WASM_ARRAY_NEW_FIXED(immut_type_index, 2, WASM_I32V(42),
                                           WASM_I32V(43)),
                      WASM_I32V(0)),
       kExprEnd});

  const uint32_t kLongLength = 1u << 16;
  const uint8_t kAllocateLarge = tester.DefineFunction(
      &sig_q_v, {},
      {WASM_ARRAY_NEW_DEFAULT(type_index, WASM_I32V(kLongLength)), kExprEnd});

  ArrayType array_type(kWasmI32, true);
  const uint32_t kTooLong = WasmArray::MaxLength(&array_type) + 1;
  const uint8_t kAllocateTooLarge = tester.DefineFunction(
      &sig_q_v, {},
      {WASM_ARRAY_NEW_DEFAULT(type_index, WASM_I32V(kTooLong)), kExprEnd});

  // Tests that fp arrays work properly.
  // f: a = [10.0, 10.0, 10.0]; a[1] = 42.42; return static_cast<int64>(a[1]);
  double result_value = 42.42;
  const uint8_t kTestFpArray = tester.DefineFunction(
      tester.sigs.i_v(), {refNull(fp_type_index)},
      {WASM_LOCAL_SET(
           0, WASM_ARRAY_NEW(fp_type_index, WASM_F64(10.0), WASM_I32V(3))),
       WASM_ARRAY_SET(fp_type_index, WASM_LOCAL_GET(0), WASM_I32V(1),
                      WASM_F64(result_value)),
       WASM_I32_SCONVERT_F64(
           WASM_ARRAY_GET(fp_type_index, WASM_LOCAL_GET(0), WASM_I32V(1))),
       kExprEnd});

  tester.CompileModule();

  tester.CheckResult(kGetElem, 12, 0);
  tester.CheckResult(kGetElem, 42, 1);
  tester.CheckResult(kGetElem, 12, 2);
  tester.CheckHasThrown(kGetElem, 3);
  tester.CheckHasThrown(kGetElem, -1);
  tester.CheckResult(kGetLength, 42);
  tester.CheckResult(kImmutable, 42);
  tester.CheckResult(kTestFpArray, static_cast<int32_t>(result_value));

  Handle<Object> h_result = tester.GetResultObject(kAllocate).ToHandleChecked();
  CHECK(IsWasmArray(*h_result));
  CHECK_EQ(2, Cast<WasmArray>(h_result)->length());

  h_result = tester.GetResultObject(kAllocateStatic).ToHandleChecked();
  CHECK(IsWasmArray(*h_result));
  CHECK_EQ(2, Cast<WasmArray>(h_result)->length());

  Handle<Object> init_result = tester.GetResultObject(kInit).ToHandleChecked();
  CHECK(IsWasmArray(*init_result));
  CHECK_EQ(3, Cast<WasmArray>(init_result)->length());
  CHECK_EQ(10, Cast<WasmArray>(init_result)->GetElement(0).to_i32());
  CHECK_EQ(20, Cast<WasmArray>(init_result)->GetElement(1).to_i32());
  CHECK_EQ(30, Cast<WasmArray>(init_result)->GetElement(2).to_i32());

  MaybeHandle<Object> maybe_large_result =
      tester.GetResultObject(kAllocateLarge);
  Handle<Object> large_result = maybe_large_result.ToHandleChecked();
  CHECK(IsWasmArray(*large_result));
  CHECK(Cast<WasmArray>(large_result)->Size() > kMaxRegularHeapObjectSize);

  tester.CheckHasThrown(kAllocateTooLarge, "requested new array is too large");
}

WASM_COMPILED_EXEC_TEST(WasmPackedArrayU) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex array_index = tester.DefineArray(kWasmI8, true);
  ValueType array_type = refNull(array_index);

  const uint8_t param_index = 0;
  const uint8_t local_index = 1;

  int32_t expected_output_3 = 258;

  const uint8_t kF = tester.DefineFunction(
      tester.sigs.i_i(), {array_type},
      {WASM_LOCAL_SET(local_index,
                      WASM_ARRAY_NEW(array_index, WASM_I32V(0), WASM_I32V(4))),
       WASM_ARRAY_SET(array_index, WASM_LOCAL_GET(local_index), WASM_I32V(0),
                      WASM_I32V(1)),
       WASM_ARRAY_SET(array_index, WASM_LOCAL_GET(local_index), WASM_I32V(1),
                      WASM_I32V(10)),
       WASM_ARRAY_SET(array_index, WASM_LOCAL_GET(local_index), WASM_I32V(2),
                      WASM_I32V(200)),
       WASM_ARRAY_SET(array_index, WASM_LOCAL_GET(local_index), WASM_I32V(3),
                      WASM_I32V(expected_output_3)),
       WASM_ARRAY_GET_U(array_index, WASM_LOCAL_GET(local_index),
                        WASM_LOCAL_GET(param_index)),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kF, 1, 0);
  tester.CheckResult(kF, 10, 1);
  tester.CheckResult(kF, 200, 2);
  // Only the 2 lsb's of 258 should be stored in the array.
  tester.CheckResult(kF, static_cast<uint8_t>(expected_output_3), 3);
}

WASM_COMPILED_EXEC_TEST(WasmPackedArrayS) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex array_index = tester.DefineArray(kWasmI16, true);
  ValueType array_type = refNull(array_index);

  int32_t array_elements[] = {0x12345678, 10, 0xFEDC, 0xFF1234};

  const uint8_t param_index = 0;
  const uint8_t local_index = 1;
  const uint8_t kF = tester.DefineFunction(
      tester.sigs.i_i(), {array_type},
      {WASM_LOCAL_SET(local_index,
                      WASM_ARRAY_NEW(array_index, WASM_I32V(array_elements[0]),
                                     WASM_I32V(4))),
       WASM_ARRAY_SET(array_index, WASM_LOCAL_GET(local_index), WASM_I32V(1),
                      WASM_I32V(array_elements[1])),
       WASM_ARRAY_SET(array_index, WASM_LOCAL_GET(local_index), WASM_I32V(2),
                      WASM_I32V(array_elements[2])),
       WASM_ARRAY_SET(array_index, WASM_LOCAL_GET(local_index), WASM_I32V(3),
                      WASM_I32V(array_elements[3])),
       WASM_ARRAY_GET_S(array_index, WASM_LOCAL_GET(local_index),
                        WASM_LOCAL_GET(param_index)),
       kExprEnd});

  tester.CompileModule();
  // Exactly the 2 lsb's should be stored by array.new.
  tester.CheckResult(kF, static_cast<int16_t>(array_elements[0]), 0);
  tester.CheckResult(kF, static_cast<int16_t>(array_elements[1]), 1);
  // Sign should be extended.
  tester.CheckResult(kF, static_cast<int16_t>(array_elements[2]), 2);
  // Exactly the 2 lsb's should be stored by array.set.
  tester.CheckResult(kF, static_cast<int16_t>(array_elements[3]), 3);
}

WASM_COMPILED_EXEC_TEST(WasmArrayCopy) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex array32_index = tester.DefineArray(kWasmI32, true);
  const ModuleTypeIndex array16_index = tester.DefineArray(kWasmI16, true);
  const ModuleTypeIndex arrayref_index =
      tester.DefineArray(refNull(array32_index), true);

  // Copies i32 ranges: local1[0..3] to local2[6..9].
  const uint8_t kCopyI32 = tester.DefineFunction(
      tester.sigs.i_i(), {refNull(array32_index), refNull(array32_index)},
      {WASM_LOCAL_SET(1, WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(10))),
       WASM_ARRAY_SET(array32_index, WASM_LOCAL_GET(1), WASM_I32V(0),
                      WASM_I32V(0)),
       WASM_ARRAY_SET(array32_index, WASM_LOCAL_GET(1), WASM_I32V(1),
                      WASM_I32V(1)),
       WASM_ARRAY_SET(array32_index, WASM_LOCAL_GET(1), WASM_I32V(2),
                      WASM_I32V(2)),
       WASM_ARRAY_SET(array32_index, WASM_LOCAL_GET(1), WASM_I32V(3),
                      WASM_I32V(3)),
       WASM_LOCAL_SET(2, WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(10))),
       WASM_ARRAY_COPY(array32_index, array32_index, WASM_LOCAL_GET(2),
                       WASM_I32V(6), WASM_LOCAL_GET(1), WASM_I32V(0),
                       WASM_I32V(4)),
       WASM_ARRAY_GET(array32_index, WASM_LOCAL_GET(2), WASM_LOCAL_GET(0)),
       kExprEnd});

  // Copies i16 ranges: local1[0..3] to local2[6..9].
  const uint8_t kCopyI16 = tester.DefineFunction(
      tester.sigs.i_i(), {refNull(array16_index), refNull(array16_index)},
      {WASM_LOCAL_SET(1, WASM_ARRAY_NEW_DEFAULT(array16_index, WASM_I32V(10))),
       WASM_ARRAY_SET(array16_index, WASM_LOCAL_GET(1), WASM_I32V(0),
                      WASM_I32V(0)),
       WASM_ARRAY_SET(array16_index, WASM_LOCAL_GET(1), WASM_I32V(1),
                      WASM_I32V(1)),
       WASM_ARRAY_SET(array16_index, WASM_LOCAL_GET(1), WASM_I32V(2),
                      WASM_I32V(2)),
       WASM_ARRAY_SET(array16_index, WASM_LOCAL_GET(1), WASM_I32V(3),
                      WASM_I32V(3)),
       WASM_LOCAL_SET(2, WASM_ARRAY_NEW_DEFAULT(array16_index, WASM_I32V(10))),
       WASM_ARRAY_COPY(array16_index, array16_index, WASM_LOCAL_GET(2),
                       WASM_I32V(6), WASM_LOCAL_GET(1), WASM_I32V(0),
                       WASM_I32V(4)),
       WASM_ARRAY_GET_S(array16_index, WASM_LOCAL_GET(2), WASM_LOCAL_GET(0)),
       kExprEnd});

  // Copies reference ranges: local1[0..3] to local2[6..9].
  const uint8_t kCopyRef = tester.DefineFunction(
      FunctionSig::Build(tester.zone(), {refNull(array32_index)}, {kWasmI32}),
      {refNull(arrayref_index), refNull(arrayref_index)},
      {WASM_LOCAL_SET(1, WASM_ARRAY_NEW_DEFAULT(arrayref_index, WASM_I32V(10))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(0),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(6))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(1),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(7))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(2),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(8))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(3),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(9))),
       WASM_LOCAL_SET(2, WASM_ARRAY_NEW_DEFAULT(arrayref_index, WASM_I32V(10))),
       WASM_ARRAY_COPY(arrayref_index, arrayref_index, WASM_LOCAL_GET(2),
                       WASM_I32V(6), WASM_LOCAL_GET(1), WASM_I32V(0),
                       WASM_I32V(4)),
       WASM_ARRAY_GET(arrayref_index, WASM_LOCAL_GET(2), WASM_LOCAL_GET(0)),
       kExprEnd});

  // Copies overlapping reference ranges: local1[0..3] to local1[2..5].
  const uint8_t kCopyRefOverlapping = tester.DefineFunction(
      FunctionSig::Build(tester.zone(), {refNull(array32_index)}, {kWasmI32}),
      {refNull(arrayref_index)},
      {WASM_LOCAL_SET(1, WASM_ARRAY_NEW_DEFAULT(arrayref_index, WASM_I32V(10))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(0),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(2))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(1),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(3))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(2),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(4))),
       WASM_ARRAY_SET(arrayref_index, WASM_LOCAL_GET(1), WASM_I32V(3),
                      WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(5))),
       WASM_ARRAY_COPY(arrayref_index, arrayref_index, WASM_LOCAL_GET(1),
                       WASM_I32V(2), WASM_LOCAL_GET(1), WASM_I32V(0),
                       WASM_I32V(4)),
       WASM_ARRAY_GET(arrayref_index, WASM_LOCAL_GET(1), WASM_LOCAL_GET(0)),
       kExprEnd});

  const uint8_t kOobSource = tester.DefineFunction(
      tester.sigs.v_v(), {refNull(array32_index), refNull(array32_index)},
      {WASM_LOCAL_SET(0, WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(10))),
       WASM_LOCAL_SET(1, WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(10))),
       WASM_ARRAY_COPY(array32_index, array32_index, WASM_LOCAL_GET(1),
                       WASM_I32V(6), WASM_LOCAL_GET(0), WASM_I32V(8),
                       WASM_I32V(4)),
       kExprEnd});

  const uint8_t kOobDestination = tester.DefineFunction(
      tester.sigs.v_v(), {refNull(array32_index), refNull(array32_index)},
      {WASM_LOCAL_SET(0, WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(10))),
       WASM_LOCAL_SET(1, WASM_ARRAY_NEW_DEFAULT(array32_index, WASM_I32V(10))),
       WASM_ARRAY_COPY(array32_index, array32_index, WASM_LOCAL_GET(1),
                       WASM_I32V(6), WASM_LOCAL_GET(0), WASM_I32V(3),
                       WASM_I32V(5)),
       kExprEnd});

  const uint8_t kZeroLength = tester.DefineFunction(
      tester.sigs.i_v(), {refNull(arrayref_index), refNull(arrayref_index)},
      {WASM_LOCAL_SET(0, WASM_ARRAY_NEW_DEFAULT(arrayref_index, WASM_I32V(10))),
       WASM_LOCAL_SET(1, WASM_ARRAY_NEW_DEFAULT(arrayref_index, WASM_I32V(10))),
       WASM_ARRAY_COPY(arrayref_index, arrayref_index, WASM_LOCAL_GET(1),
                       WASM_I32V(6), WASM_LOCAL_GET(0), WASM_I32V(3),
                       WASM_I32V(0)),
       WASM_I32V(0), kExprEnd});

  tester.CompileModule();

  tester.CheckResult(kCopyI32, 0, 5);
  tester.CheckResult(kCopyI32, 0, 6);
  tester.CheckResult(kCopyI32, 1, 7);
  tester.CheckResult(kCopyI32, 2, 8);
  tester.CheckResult(kCopyI32, 3, 9);

  tester.CheckResult(kCopyI16, 0, 5);
  tester.CheckResult(kCopyI16, 0, 6);
  tester.CheckResult(kCopyI16, 1, 7);
  tester.CheckResult(kCopyI16, 2, 8);
  tester.CheckResult(kCopyI16, 3, 9);

  {
    DirectHandle<Object> result5 =
        tester.GetResultObject(kCopyRef, 5).ToHandleChecked();
    CHECK(IsWasmNull(*result5));
    for (int i = 6; i <= 9; i++) {
      Handle<Object> res =
          tester.GetResultObject(kCopyRef, i).ToHandleChecked();
      CHECK(IsWasmArray(*res));
      CHECK_EQ(Cast<WasmArray>(res)->length(), static_cast<uint32_t>(i));
    }
  }
  CHECK(IsWasmNull(
      *tester.GetResultObject(kCopyRefOverlapping, 6).ToHandleChecked()));
  Handle<Object> res0 =
      tester.GetResultObject(kCopyRefOverlapping, 0).ToHandleChecked();
  CHECK(IsWasmArray(*res0));
  CHECK_EQ(Cast<WasmArray>(res0)->length(), static_cast<uint32_t>(2));
  for (int i = 2; i <= 5; i++) {
    Handle<Object> res =
        tester.GetResultObject(kCopyRefOverlapping, i).ToHandleChecked();
    CHECK(IsWasmArray(*res));
    CHECK_EQ(Cast<WasmArray>(res)->length(), static_cast<uint32_t>(i));
  }

  tester.CheckHasThrown(kOobSource);
  tester.CheckHasThrown(kOobDestination);
  tester.CheckResult(kZeroLength, 0);  // Does not throw.
}

WASM_COMPILED_EXEC_TEST(NewDefault) {
  WasmGCTester tester(execution_tier);
  if (!tester.HasSimdSupport(execution_tier)) return;

  tester.builder()->StartRecursiveTypeGroup();
  const ModuleTypeIndex struct_type =
      tester.DefineStruct({F(wasm::kWasmI32, true), F(wasm::kWasmF64, true),
                           F(refNull(ModuleTypeIndex{0}), true)});
  tester.builder()->EndRecursiveTypeGroup();

  const ModuleTypeIndex array_type = tester.DefineArray(wasm::kWasmI32, true);
  // Returns: struct[0] + f64_to_i32(struct[1]) + (struct[2].is_null ^ 1) == 0.
  const uint8_t allocate_struct = tester.DefineFunction(
      tester.sigs.i_v(), {refNull(struct_type)},
      {WASM_LOCAL_SET(0, WASM_STRUCT_NEW_DEFAULT(struct_type)),
       WASM_I32_ADD(
           WASM_I32_ADD(WASM_STRUCT_GET(struct_type, 0, WASM_LOCAL_GET(0)),
                        WASM_I32_SCONVERT_F64(WASM_STRUCT_GET(
                            struct_type, 1, WASM_LOCAL_GET(0)))),
           WASM_I32_XOR(WASM_REF_IS_NULL(
                            WASM_STRUCT_GET(struct_type, 2, WASM_LOCAL_GET(0))),
                        WASM_I32V(1))),
       kExprEnd});
  const uint8_t allocate_array = tester.DefineFunction(
      tester.sigs.i_v(), {refNull(array_type)},
      {WASM_LOCAL_SET(0, WASM_ARRAY_NEW_DEFAULT(array_type, WASM_I32V(2))),
       WASM_I32_ADD(
           WASM_ARRAY_GET(array_type, WASM_LOCAL_GET(0), WASM_I32V(0)),
           WASM_ARRAY_GET(array_type, WASM_LOCAL_GET(0), WASM_I32V(1))),
       kExprEnd});

  tester.CompileModule();

  tester.CheckResult(allocate_struct, 0);
  tester.CheckResult(allocate_array, 0);
}

WASM_COMPILED_EXEC_TEST(RefTrivialCastsStatic) {
  WasmGCTester tester(execution_tier);
  ModuleTypeIndex type_index = tester.DefineStruct({F(wasm::kWasmI32, true)});
  ModuleTypeIndex subtype_index = tester.DefineStruct(
      {F(wasm::kWasmI32, true), F(wasm::kWasmS128, true)}, type_index);
  ModuleTypeIndex subtype2_index = tester.DefineStruct(
      {F(wasm::kWasmI32, true), F(wasm::kWasmF64, true)}, type_index);

  const uint8_t kRefTestNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(type_index), subtype_index), kExprEnd});
  // Upcasts should be optimized away for nominal types.
  const uint8_t kRefTestUpcast = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_STRUCT_NEW_DEFAULT(subtype_index), type_index),
       kExprEnd});
  const uint8_t kRefTestUpcastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(subtype_index), type_index), kExprEnd});
  const uint8_t kRefTestUnrelatedNullable = tester.DefineFunction(
      tester.sigs.i_v(), {refNull(subtype_index)},
      {WASM_LOCAL_SET(0, WASM_STRUCT_NEW_DEFAULT(subtype_index)),
       WASM_REF_TEST(WASM_LOCAL_GET(0), subtype2_index), kExprEnd});
  const uint8_t kRefTestUnrelatedNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(subtype_index), subtype2_index), kExprEnd});
  const uint8_t kRefTestUnrelatedNonNullable = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_STRUCT_NEW_DEFAULT(type_index), subtype2_index),
       kExprEnd});

  const uint8_t kRefCastNull =
      tester.DefineFunction(tester.sigs.i_v(), {},
                            {WASM_REF_IS_NULL(WASM_REF_CAST(
                                 WASM_REF_NULL(type_index), subtype_index)),
                             kExprEnd});
  const uint8_t kRefCastUpcast = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(
           WASM_REF_CAST(WASM_STRUCT_NEW_DEFAULT(subtype_index), type_index)),
       kExprEnd});
  const uint8_t kRefCastUpcastNull =
      tester.DefineFunction(tester.sigs.i_v(), {},
                            {WASM_REF_IS_NULL(WASM_REF_CAST(
                                 WASM_REF_NULL(subtype_index), type_index)),
                             kExprEnd});

  const uint8_t kBrOnCastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_BLOCK_R(refNull(subtype_index), WASM_REF_NULL(type_index),
                    WASM_BR_ON_CAST(0, type_index, subtype_index), WASM_DROP,
                    WASM_RETURN(WASM_I32V(0))),
       WASM_DROP, WASM_I32V(1), WASM_END});

  // Real upcasts are invalid for br_on_cast. Casting to the same type is
  // however similar to an upcast.
  const uint8_t kBrOnCastUpcast = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_BLOCK_R(refNull(type_index), WASM_STRUCT_NEW_DEFAULT(type_index),
                    WASM_BR_ON_CAST(0, type_index, type_index), WASM_DROP,
                    WASM_RETURN(WASM_I32V(0))),
       WASM_DROP, WASM_I32V(1), WASM_END});

  const uint8_t kBrOnCastUpcastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_BLOCK_R(refNull(type_index), WASM_REF_NULL(type_index),
                    WASM_BR_ON_CAST(0, type_index, type_index), WASM_DROP,
                    WASM_RETURN(WASM_I32V(0))),
       WASM_DROP, WASM_I32V(1), WASM_END});

  const uint8_t kBrOnCastFailNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_BLOCK_R(refNull(type_index), WASM_REF_NULL(type_index),
                    WASM_BR_ON_CAST_FAIL(0, type_index, subtype_index),
                    WASM_DROP, WASM_RETURN(WASM_I32V(0))),
       WASM_DROP, WASM_I32V(1), WASM_END});

  // Real upcasts are invalid for br_on_cast. Casting to the same type is
  // however similar to an upcast.
  const uint8_t kBrOnCastFailUpcast = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_BLOCK_R(refNull(subtype_index),
                    WASM_STRUCT_NEW_DEFAULT(subtype_index),
                    WASM_BR_ON_CAST_FAIL(0, subtype_index, subtype_index),
                    WASM_DROP, WASM_RETURN(WASM_I32V(0))),
       WASM_DROP, WASM_I32V(1), WASM_END});

  const uint8_t kBrOnCastFailUpcastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_BLOCK_R(refNull(subtype_index), WASM_REF_NULL(subtype_index),
                    WASM_BR_ON_CAST_FAIL(0, subtype_index, subtype_index),
                    WASM_DROP, WASM_RETURN(WASM_I32V(0))),
       WASM_DROP, WASM_I32V(1), WASM_END});

  tester.CompileModule();

  tester.CheckResult(kRefTestNull, 0);
  tester.CheckResult(kRefTestUpcast, 1);
  tester.CheckResult(kRefTestUpcastNull, 0);
  tester.CheckResult(kRefTestUnrelatedNullable, 0);
  tester.CheckResult(kRefTestUnrelatedNull, 0);
  tester.CheckResult(kRefTestUnrelatedNonNullable, 0);

  tester.CheckHasThrown(kRefCastNull);
  tester.CheckResult(kRefCastUpcast, 0);
  tester.CheckHasThrown(kRefCastUpcastNull);

  tester.CheckResult(kBrOnCastNull, 0);
  tester.CheckResult(kBrOnCastUpcast, 1);
  tester.CheckResult(kBrOnCastUpcastNull, 0);

  tester.CheckResult(kBrOnCastFailNull, 1);
  tester.CheckResult(kBrOnCastFailUpcast, 0);
  tester.CheckResult(kBrOnCastFailUpcastNull, 1);
}

WASM_COMPILED_EXEC_TEST(TrivialAbstractCasts) {
  WasmGCTester tester(execution_tier);
  ModuleTypeIndex type_index = tester.DefineArray(wasm::kWasmI32, true);
  ModuleTypeIndex struct_type_index =
      tester.DefineStruct({F(wasm::kWasmI32, true)});
  ValueType sig_types[] = {kWasmS128, kWasmI32, kWasmF64};
  FunctionSig sig(1, 2, sig_types);

  const uint8_t kIsArrayNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(kAnyRefCode), kArrayRefCode), kExprEnd});
  const uint8_t kIsArrayUpcast = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_ARRAY_NEW_DEFAULT(type_index, WASM_I32V(10)),
                     kArrayRefCode),
       kExprEnd});
  const uint8_t kIsArrayUpcastNullable = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(type_index)},
      {WASM_LOCAL_SET(0, WASM_ARRAY_NEW_DEFAULT(type_index, WASM_I32V(10))),
       WASM_REF_TEST(WASM_LOCAL_GET(0), kArrayRefCode), kExprEnd});
  const uint8_t kIsArrayUpcastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(type_index), kArrayRefCode), kExprEnd});
  const uint8_t kIsArrayUnrelated = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(struct_type_index)},
      {WASM_LOCAL_SET(0, WASM_STRUCT_NEW_DEFAULT(struct_type_index)),
       WASM_REF_TEST(WASM_LOCAL_GET(0), kArrayRefCode), kExprEnd});
  const uint8_t kIsArrayUnrelatedNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(kI31RefCode), kArrayRefCode), kExprEnd});
  const uint8_t kIsArrayUnrelatedNonNullable = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_I31(WASM_I32V(10)), kArrayRefCode), kExprEnd});

  const uint8_t kAsArrayNull =
      tester.DefineFunction(tester.sigs.i_v(), {},
                            {WASM_REF_IS_NULL(WASM_REF_CAST(
                                 WASM_REF_NULL(kAnyRefCode), kArrayRefCode)),
                             kExprEnd});
  const uint8_t kAsArrayUpcast = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(WASM_REF_CAST(
           WASM_ARRAY_NEW_DEFAULT(type_index, WASM_I32V(10)), kArrayRefCode)),
       kExprEnd});
  const uint8_t kAsArrayUpcastNullable = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(type_index)},
      {WASM_LOCAL_SET(0, WASM_ARRAY_NEW_DEFAULT(type_index, WASM_I32V(10))),
       WASM_REF_IS_NULL(WASM_REF_CAST(WASM_LOCAL_GET(0), kArrayRefCode)),
       kExprEnd});
  const uint8_t kAsArrayUpcastNull =
      tester.DefineFunction(tester.sigs.i_v(), {},
                            {WASM_REF_IS_NULL(WASM_REF_CAST(
                                 WASM_REF_NULL(type_index), kArrayRefCode)),
                             kExprEnd});
  const uint8_t kAsArrayUnrelated = tester.DefineFunction(
      tester.sigs.i_v(), {ValueType::RefNull(struct_type_index)},
      {WASM_LOCAL_SET(0, WASM_STRUCT_NEW_DEFAULT(struct_type_index)),
       WASM_REF_IS_NULL(WASM_REF_CAST(WASM_LOCAL_GET(0), kArrayRefCode)),
       kExprEnd});
  const uint8_t kAsArrayUnrelatedNull =
      tester.DefineFunction(tester.sigs.i_v(), {},
                            {WASM_REF_IS_NULL(WASM_REF_CAST(
                                 WASM_REF_NULL(kI31RefCode), kArrayRefCode)),
                             kExprEnd});
  const uint8_t kAsArrayUnrelatedNonNullable =
      tester.DefineFunction(tester.sigs.i_v(), {},
                            {WASM_REF_IS_NULL(WASM_REF_CAST(
                                 WASM_REF_I31(WASM_I32V(10)), kArrayRefCode)),
                             kExprEnd});

  tester.CompileModule();

  tester.CheckResult(kIsArrayNull, 0);
  tester.CheckResult(kIsArrayUpcast, 1);
  tester.CheckResult(kIsArrayUpcastNullable, 1);
  tester.CheckResult(kIsArrayUpcastNull, 0);
  tester.CheckResult(kIsArrayUnrelated, 0);
  tester.CheckResult(kIsArrayUnrelatedNull, 0);
  tester.CheckResult(kIsArrayUnrelatedNonNullable, 0);

  tester.CheckHasThrown(kAsArrayNull);
  tester.CheckResult(kAsArrayUpcast, 0);
  tester.CheckResult(kAsArrayUpcastNullable, 0);
  tester.CheckHasThrown(kAsArrayUpcastNull);
  tester.CheckHasThrown(kAsArrayUnrelated);
  tester.CheckHasThrown(kAsArrayUnrelatedNull);
  tester.CheckHasThrown(kAsArrayUnrelatedNonNullable);
}

WASM_COMPILED_EXEC_TEST(ArrayNewMap) {
  WasmGCTester tester(execution_tier);

  const ModuleTypeIndex type_index = tester.DefineArray(kWasmI32, true);

  ValueType array_type = ValueType::Ref(type_index);
  FunctionSig sig(1, 0, &array_type);
  const uint8_t array_new = tester.DefineFunction(
      &sig, {},
      {WASM_ARRAY_NEW(type_index, WASM_I32V(10), WASM_I32V(42)), kExprEnd});

  tester.CompileModule();
  Handle<Object> result = tester.GetResultObject(array_new).ToHandleChecked();
  CHECK(IsWasmArray(*result));
  CHECK_EQ(Cast<WasmArray>(result)->map(),
           tester.trusted_instance_data()->managed_object_maps()->get(
               type_index.index));
}

WASM_COMPILED_EXEC_TEST(FunctionRefs) {
  WasmGCTester tester(execution_tier);
  const uint8_t func_index =
      tester.DefineFunction(tester.sigs.i_v(), {}, {WASM_I32V(42), kExprEnd});
  const ModuleTypeIndex sig_index{0};

  const ModuleTypeIndex other_sig_index =
      tester.DefineSignature(tester.sigs.d_d());

  // This is just so func_index counts as "declared".
  tester.AddGlobal(ValueType::RefNull(sig_index), false,
                   WasmInitExpr::RefFuncConst(func_index));

  ValueType func_type = ValueType::RefNull(sig_index);
  FunctionSig sig_func(1, 0, &func_type);

  const uint8_t cast = tester.DefineFunction(
      &sig_func, {kWasmFuncRef},
      {WASM_LOCAL_SET(0, WASM_REF_FUNC(func_index)),
       WASM_REF_CAST(WASM_LOCAL_GET(0), sig_index), kExprEnd});

  const uint8_t cast_reference = tester.DefineFunction(
      &sig_func, {}, {WASM_REF_FUNC(func_index), kExprEnd});

  const uint8_t test = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmFuncRef},
      {WASM_LOCAL_SET(0, WASM_REF_FUNC(func_index)),
       WASM_REF_TEST(WASM_LOCAL_GET(0), sig_index), kExprEnd});

  const uint8_t test_fail = tester.DefineFunction(
      tester.sigs.i_v(), {kWasmFuncRef},
      {WASM_LOCAL_SET(0, WASM_REF_FUNC(func_index)),
       WASM_REF_TEST(WASM_LOCAL_GET(0), other_sig_index), kExprEnd});

  tester.CompileModule();

  i::Isolate* i_isolate = CcTest::i_isolate();
  DirectHandle<Object> result_cast =
      tester.GetResultObject(cast).ToHandleChecked();
  CHECK(IsWasmFuncRef(*result_cast));
  DirectHandle<WasmInternalFunction> result_cast_internal{
      Cast<WasmFuncRef>(*result_cast)->internal(i_isolate), i_isolate};
  DirectHandle<JSFunction> cast_function =
      WasmInternalFunction::GetOrCreateExternal(result_cast_internal);

  DirectHandle<Object> result_cast_reference =
      tester.GetResultObject(cast_reference).ToHandleChecked();
  CHECK(IsWasmFuncRef(*result_cast_reference));
  DirectHandle<WasmInternalFunction> result_cast_reference_internal{
      Cast<WasmFuncRef>(*result_cast_reference)->internal(i_isolate),
      i_isolate};
  DirectHandle<JSFunction> cast_function_reference =
      WasmInternalFunction::GetOrCreateExternal(result_cast_reference_internal);

  CHECK_EQ(cast_function->code(i_isolate)->instruction_start(),
           cast_function_reference->code(i_isolate)->instruction_start());

  tester.CheckResult(test, 1);
  tester.CheckResult(test_fa
"""


```