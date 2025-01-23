Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/wasm/test-gc.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename and the presence of `WASM_COMPILED_EXEC_TEST` macros strongly suggest this code is testing WebAssembly's Garbage Collection (GC) features within V8.

2. **Analyze the `WASM_COMPILED_EXEC_TEST` Macros:** These macros define individual test cases. Each test function focuses on a specific aspect of WebAssembly GC. List the different test names to get an overview of the tested features.

3. **Examine Individual Test Cases:** For each test case, try to understand its objective by looking at the WebAssembly instructions used (e.g., `WASM_CALL_REF`, `WASM_STRUCT_NEW`, `WASM_REF_CAST`, `WASM_TABLE_SET`).

4. **Look for Patterns and Groupings:** Notice that several tests deal with `ref.null`, `ref.cast`, `ref.test`, `br_on_cast`, and `br_on_cast_fail`. These are fundamental operations on reference types in WebAssembly GC. Group related tests together.

5. **Identify Key Concepts:**  The code heavily utilizes concepts like:
    * **Reference Types:** `funcref`, `externref`, `structref`, `arrayref`, `eqref`, `anyref`, `i31ref`.
    * **Null References:**  Testing how `ref.null` behaves with different types.
    * **Casting:**  `ref.cast` and related branching instructions (`br_on_cast`, `br_on_cast_fail`).
    * **Subtyping:**  Testing how subtypes interact with function calls and table operations.
    * **Function Calls:** `call_ref`, indirect calls (`call_indirect`).
    * **Structs and Arrays:** Creating and accessing fields of structs and arrays.
    * **Tables:**  Testing function tables with GC references.
    * **Global Variables:** Initializing globals with other globals.
    * **JavaScript Interop:**  Testing the interaction between WebAssembly GC objects and JavaScript.
    * **Type Checking:** `ref.test`.
    * **Abstract Null Types:** Implicit conversions of different null reference types.

6. **Determine if it's Torque:** The filename ends with `.cc`, not `.tq`, so it's not a Torque file.

7. **Check for JavaScript Relevance:** The `JsAccess` test clearly demonstrates the interaction with JavaScript. Identify the key aspects: exporting WebAssembly functions that produce and consume GC objects, and calling these functions from JavaScript.

8. **Look for Logic and Potential Errors:**
    * **Casting Null:**  Several tests explicitly check that casting a null reference throws an error. This is a common mistake.
    * **Type Mismatches in Calls:**  The `GCTables` test demonstrates how incorrect function signatures in indirect calls lead to traps.

9. **Provide Examples:** For JavaScript interop, provide a basic JavaScript example of calling the exported WebAssembly functions. For common errors, illustrate the scenario of casting a null reference.

10. **Infer Input/Output for Logic:** For tests like `CallRef` and `CallReftypeParameters`, determine the inputs (function arguments) and the expected output based on the WebAssembly code.

11. **Summarize the Functionality:** Combine all the observations into a concise summary of the code's purpose and the features it tests. Emphasize that it's a testing file.

12. **Review and Refine:**  Ensure the explanation is clear, accurate, and addresses all parts of the user's request. Use precise terminology related to WebAssembly GC.

**Self-Correction/Refinement during the process:**

* Initially, I might have just listed all the test names without grouping them. Realizing the overlap in functionality related to casting, null references, etc., helps in creating a more organized and understandable explanation.
* I might have missed the significance of `ModuleTypeIndex`. Recognizing that it represents the index of defined struct and array types is crucial for understanding the code.
* I might have initially focused too much on the low-level WebAssembly instructions. Stepping back and identifying the high-level concepts being tested (casting, subtyping, etc.) provides a better overall understanding.
* Ensuring the JavaScript example is basic and directly relates to the `JsAccess` test is important. Avoid overcomplicating it.
好的，让我们来归纳一下 `v8/test/cctest/wasm/test-gc.cc` 这个文件的功能。

**功能归纳:**

`v8/test/cctest/wasm/test-gc.cc` 是 V8 引擎中用于测试 WebAssembly 垃圾回收 (GC) 相关功能的 C++ 源代码文件。 它包含了一系列编译执行测试 (`WASM_COMPILED_EXEC_TEST`)，用于验证 WebAssembly GC 的各种操作和特性是否按预期工作。

**具体功能点：**

1. **引用类型操作:**
   - **`CallRef`:** 测试使用 `call_ref` 指令调用函数引用。
   - **`CallAbstractNullTypeImplicitConversion`:** 测试当函数期望接收抽象的 null 引用类型时，是否能接受各种具体的 null 引用 (如 `nullref`, `nullfuncref`, `nullexternref`)。
   - **`CastNullRef`:** 测试对 null 引用执行 `ref.cast` 操作，预期会抛出异常。
   - **`CallReftypeParameters`:** 测试调用带有引用类型参数的函数。
   - **`AbstractTypeChecks`:** 测试与抽象引用类型（如 `anyref`, `eqref`, `structref`, `arrayref`, `i31ref`）相关的类型检查 (`ref.test`) 和类型转换 (`ref.cast`) 操作，包括对 null 值的处理，以及 `br_on_cast` 和 `br_on_cast_fail` 指令的行为。

2. **性能测试:**
   - **`CastsBenchmark`:**  一个基准测试，用于评估 WebAssembly 中类型转换的性能。它创建了一个包含父类型和子类型对象的数组，并执行大量的类型转换操作。

3. **全局变量初始化:**
   - **`GlobalInitReferencingGlobal`:** 测试全局变量的初始化，其中一个全局变量的值依赖于另一个全局变量的值。

4. **表 (Table) 操作:**
   - **`GCTables`:** 测试 WebAssembly 中的表 (Table) 功能，特别是与 GC 引用相关的操作。包括：
     - 设置表元素为 null 引用和函数引用。
     - 使用 `call_indirect` 指令调用表中的函数，测试类型匹配、子类型关系以及 null 引用的处理。
     - 使用 `call_ref` 调用从表中获取的函数引用。

5. **JavaScript 互操作:**
   - **`JsAccess`:** 测试 WebAssembly GC 对象与 JavaScript 之间的互操作性。包括：
     - 从 WebAssembly 导出创建 GC 对象的函数。
     - 从 WebAssembly 导出消费 GC 对象的函数。
     - 在 JavaScript 中调用这些导出的函数，并验证类型检查的行为。

6. **`anyref` 和 `externref` 的转换:**
   - **`WasmAnyConvertExtern`:** 测试将 `anyref` 类型的 null 值转换为 `externref` 的操作。
   - **`WasmExternConvertAny`:** 测试将 `externref` 类型的 null 值转换为 `anyref` 的操作。

**关于文件类型:**

`v8/test/cctest/wasm/test-gc.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

**与 JavaScript 的关系（`JsAccess` 测试）：**

`JsAccess` 测试直接演示了 WebAssembly GC 对象如何在 JavaScript 中被使用。

**JavaScript 示例:**

假设 `JsAccess` 测试编译并实例化了一个 WebAssembly 模块，该模块导出了名为 `typed_producer`、`untyped_producer` 和 `consumer` 的函数。

```javascript
// 假设 'wasmModule' 是已实例化的 WebAssembly 模块
const typedProducer = wasmModule.exports.typed_producer;
const untypedProducer = wasmModule.exports.untyped_producer;
const consumer = wasmModule.exports.consumer;

// typedProducer 返回一个具有特定类型的 GC 对象
const typedObject = typedProducer();
console.log(consumer(typedObject)); // 假设 consumer 提取对象的某个属性并返回

// untypedProducer 返回一个被视为更通用类型的 GC 对象
const untypedObject = untypedProducer();
console.log(consumer(untypedObject));

// 尝试使用错误类型的对象调用 consumer 会导致 WebAssembly 抛出异常
try {
  consumer(42); // 传递一个 JavaScript 数字
} catch (error) {
  console.error("调用 consumer 失败:", error);
}
```

**代码逻辑推理（假设输入与输出）：**

以 `CallRef` 测试为例：

**假设输入:** 调用 `caller` 函数。

**代码逻辑:**

1. `caller` 函数调用 `callee` 函数引用。
2. `callee` 函数接收两个 `i32` 参数。
3. `caller` 使用 `WASM_CALL_REF` 调用，传递了函数引用 `callee`、签名索引、以及参数 `42` 和局部变量 `0` 的值。
4. 局部变量 `0` 在 `caller` 的函数签名中定义为 `i32` 类型的输入参数。
5. `callee` 函数将两个输入参数相加并返回结果。

**假设 `caller` 被调用时局部变量 0 的值为 5。**

**预期输出:** `callee` 函数将计算 `42 + 5 = 47`，`caller` 函数将返回这个结果。 `tester.CheckResult(caller, 47, 5);` 验证了这一点。

**用户常见的编程错误示例:**

**1. 对 null 引用进行类型转换：**

```c++
// 错误示例：尝试将 null 引用转换为非 null 类型
uint8_t bad_cast = tester.DefineFunction(
    tester.sigs.i_v(), {},
    {WASM_REF_CAST(WASM_REF_NULL(kNoneCode), kArrayRefCode), // 潜在错误
     WASM_DROP, WASM_I32V(1), kExprEnd});
```

在 WebAssembly 中，直接将 null 引用转换为非 null 的引用类型（如 `arrayref` 或 `structref`）通常会导致运行时错误（trap）。程序员可能会错误地认为 null 可以被强制转换为任何引用类型。`CastNullRef` 测试的目的就是验证这种情况会抛出异常。

**2. 在间接调用中使用错误的函数签名：**

在 `GCTables` 测试中，`call_type_mismatch` 函数展示了这个问题：

```c++
uint8_t call_type_mismatch = tester.DefineFunction(
    tester.sigs.i_v(), {},
    {WASM_CALL_INDIRECT(unrelated_sig_index, // 错误的签名索引
                        WASM_CALL_FUNCTION0(super_struct_producer),
                        WASM_I32V(2)),
     WASM_END});
```

如果尝试使用与表中函数实际签名不匹配的签名索引进行间接调用，WebAssembly 虚拟机将抛出异常。这是用户在使用函数表时容易犯的错误。

总而言之，`v8/test/cctest/wasm/test-gc.cc` 是一个全面的测试套件，用于验证 V8 引擎中 WebAssembly 垃圾回收功能的正确性和性能。它覆盖了引用类型操作、类型转换、表操作、全局变量初始化以及与 JavaScript 的互操作等多个方面，并能帮助开发者理解 WebAssembly GC 的工作原理以及避免常见的编程错误。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-gc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-gc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
il, 0);
}

WASM_COMPILED_EXEC_TEST(CallRef) {
  WasmGCTester tester(execution_tier);
  ModuleTypeIndex sig_index = tester.DefineSignature(tester.sigs.i_ii());
  uint8_t callee = tester.DefineFunction(
      sig_index, {},
      {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprEnd});
  uint8_t caller =
      tester.DefineFunction(tester.sigs.i_i(), {},
                            {WASM_CALL_REF(WASM_REF_FUNC(callee), sig_index,
                                           WASM_I32V(42), WASM_LOCAL_GET(0)),
                             kExprEnd});

  // This is just so func_index counts as "declared".
  tester.AddGlobal(ValueType::RefNull(sig_index), false,
                   WasmInitExpr::RefFuncConst(callee));

  tester.CompileModule();

  tester.CheckResult(caller, 47, 5);
}

// Test that calling a function expecting any ref accepts the abstract null
// type argument (nullref, nullfuncref, nullexternref).
WASM_COMPILED_EXEC_TEST(CallAbstractNullTypeImplicitConversion) {
  FlagScope<bool> exnref(&v8_flags.experimental_wasm_exnref, true);
  const struct {
    ValueType super_type;
    ValueTypeCode sub_type_code;
  } null_ref_types[] = {
      {kWasmFuncRef, kNoFuncCode},
      {kWasmEqRef, kNoneCode},
      {kWasmI31Ref.AsNullable(), kNoneCode},
      {kWasmStructRef.AsNullable(), kNoneCode},
      {kWasmArrayRef.AsNullable(), kNoneCode},
      {kWasmAnyRef, kNoneCode},
      {kWasmExternRef, kNoExternCode},
      {kWasmExnRef, kNoExnCode},
      {refNull(ModuleTypeIndex{0}), kNoneCode},    // struct
      {refNull(ModuleTypeIndex{1}), kNoneCode},    // array
      {refNull(ModuleTypeIndex{2}), kNoFuncCode},  // signature
  };

  for (auto [super_type, sub_type_code] : null_ref_types) {
    CHECK(super_type.is_nullable());
    WasmGCTester tester(execution_tier);
    ModuleTypeIndex struct_idx = tester.DefineStruct({F(wasm::kWasmI32, true)});
    CHECK_EQ(struct_idx, ModuleTypeIndex{0});
    ModuleTypeIndex array_idx = tester.DefineArray(kWasmI32, true);
    CHECK_EQ(array_idx, ModuleTypeIndex{1});
    FunctionSig dummySig(1, 0, &kWasmI32);
    ModuleTypeIndex signature_idx = tester.DefineSignature(&dummySig);
    CHECK_EQ(signature_idx, ModuleTypeIndex{2});

    ValueType ref_sig_types[] = {kWasmI32, super_type};
    FunctionSig sig_ref(1, 1, ref_sig_types);
    uint8_t callee = tester.DefineFunction(
        &sig_ref, {}, {WASM_REF_IS_NULL(WASM_LOCAL_GET(0)), kExprEnd});
    uint8_t caller = tester.DefineFunction(
        tester.sigs.i_v(), {},
        {WASM_CALL_FUNCTION(callee, WASM_REF_NULL(sub_type_code)), kExprEnd});

    tester.CompileModule();
    tester.CheckResult(caller, 1);
  }
}

WASM_COMPILED_EXEC_TEST(CastNullRef) {
  WasmGCTester tester(execution_tier);
  uint8_t to_non_null = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(WASM_REF_AS_NON_NULL(WASM_REF_NULL(kNoneCode))),
       kExprEnd});
  uint8_t to_array = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(WASM_REF_CAST(WASM_REF_NULL(kNoneCode), kArrayRefCode)),
       kExprEnd});
  uint8_t to_struct =
      tester.DefineFunction(tester.sigs.i_v(), {},
                            {WASM_REF_IS_NULL(WASM_REF_CAST(
                                 WASM_REF_NULL(kNoneCode), kStructRefCode)),
                             kExprEnd});
  uint8_t to_i31 = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(WASM_REF_CAST(WASM_REF_NULL(kNoneCode), kI31RefCode)),
       kExprEnd});
  ModuleTypeIndex struct_idx = tester.DefineStruct({F(wasm::kWasmI32, true)});
  uint8_t to_struct_idx = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(WASM_REF_CAST(WASM_REF_NULL(kNoneCode), struct_idx)),
       kExprEnd});
  tester.CompileModule();
  // ref.cast traps on null.
  tester.CheckHasThrown(to_non_null);
  tester.CheckHasThrown(to_array);
  tester.CheckHasThrown(to_struct);
  tester.CheckHasThrown(to_i31);
  tester.CheckHasThrown(to_struct_idx);
}

WASM_COMPILED_EXEC_TEST(CallReftypeParameters) {
  WasmGCTester tester(execution_tier);
  ModuleTypeIndex type_index = tester.DefineStruct({F(wasm::kWasmI32, true)});
  ValueType kRefType{refNull(type_index)};
  ValueType sig_types[] = {kWasmI32, kRefType, kRefType, kRefType, kRefType,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32};
  FunctionSig sig(1, 8, sig_types);
  uint8_t adder = tester.DefineFunction(
      &sig, {},
      {WASM_I32_ADD(
           WASM_STRUCT_GET(type_index, 0, WASM_LOCAL_GET(0)),
           WASM_I32_ADD(
               WASM_STRUCT_GET(type_index, 0, WASM_LOCAL_GET(1)),
               WASM_I32_ADD(
                   WASM_STRUCT_GET(type_index, 0, WASM_LOCAL_GET(2)),
                   WASM_I32_ADD(
                       WASM_STRUCT_GET(type_index, 0, WASM_LOCAL_GET(3)),
                       WASM_I32_ADD(
                           WASM_LOCAL_GET(4),
                           WASM_I32_ADD(WASM_LOCAL_GET(5),
                                        WASM_I32_ADD(WASM_LOCAL_GET(6),
                                                     WASM_LOCAL_GET(7)))))))),
       kExprEnd});
  uint8_t caller = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_CALL_FUNCTION(adder, WASM_STRUCT_NEW(type_index, WASM_I32V(2)),
                          WASM_STRUCT_NEW(type_index, WASM_I32V(4)),
                          WASM_STRUCT_NEW(type_index, WASM_I32V(8)),
                          WASM_STRUCT_NEW(type_index, WASM_I32V(16)),
                          WASM_I32V(32), WASM_I32V(64), WASM_I32V(128),
                          WASM_I32V(256)),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(caller, 510);
}

WASM_COMPILED_EXEC_TEST(AbstractTypeChecks) {
  WasmGCTester tester(execution_tier);

  ModuleTypeIndex array_index = tester.DefineArray(kWasmI32, true);
  ModuleTypeIndex struct_index = tester.DefineStruct({F(kWasmI32, true)});
  uint8_t function_index =
      tester.DefineFunction(tester.sigs.v_v(), {}, {kExprEnd});
  ModuleTypeIndex sig_index{2};

  // This is just so func_index counts as "declared".
  tester.AddGlobal(ValueType::RefNull(sig_index), false,
                   WasmInitExpr::RefFuncConst(function_index));

  uint8_t kStructCheckNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(kAnyRefCode), kStructRefCode), kExprEnd});
  uint8_t kArrayCheckNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(kAnyRefCode), kArrayRefCode), kExprEnd});
  uint8_t kI31CheckNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_TEST(WASM_REF_NULL(kAnyRefCode), kI31RefCode), kExprEnd});

  uint8_t kStructCastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_CAST(WASM_REF_NULL(kAnyRefCode), kStructRefCode), WASM_DROP,
       WASM_I32V(1), kExprEnd});
  uint8_t kArrayCastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_CAST(WASM_REF_NULL(kAnyRefCode), kArrayRefCode), WASM_DROP,
       WASM_I32V(1), kExprEnd});
  uint8_t kI31CastNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_CAST(WASM_REF_NULL(kAnyRefCode), kI31RefCode), WASM_DROP,
       WASM_I32V(1), kExprEnd});

#define TYPE_CHECK(type, value)            \
  tester.DefineFunction(                   \
      tester.sigs.i_v(), {kWasmAnyRef},    \
      {WASM_LOCAL_SET(0, WASM_SEQ(value)), \
       WASM_REF_TEST(WASM_LOCAL_GET(0), k##type##RefCode), kExprEnd})

  uint8_t kStructCheckSuccess =
      TYPE_CHECK(Struct, WASM_STRUCT_NEW_DEFAULT(struct_index));
  uint8_t kStructCheckFailure = TYPE_CHECK(Struct, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kArrayCheckSuccess =
      TYPE_CHECK(Array, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
  uint8_t kArrayCheckFailure =
      TYPE_CHECK(Array, WASM_STRUCT_NEW_DEFAULT(struct_index));
  uint8_t kI31CheckSuccess = TYPE_CHECK(I31, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kI31CheckFailure =
      TYPE_CHECK(I31, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
#undef TYPE_CHECK

#define TYPE_CAST(type, value)                                               \
  tester.DefineFunction(tester.sigs.i_v(), {kWasmAnyRef},                    \
                        {WASM_LOCAL_SET(0, WASM_SEQ(value)),                 \
                         WASM_REF_CAST(WASM_LOCAL_GET(0), k##type##RefCode), \
                         WASM_DROP, WASM_I32V(1), kExprEnd})

  uint8_t kStructCastSuccess =
      TYPE_CAST(Struct, WASM_STRUCT_NEW_DEFAULT(struct_index));
  uint8_t kStructCastFailure = TYPE_CAST(Struct, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kArrayCastSuccess =
      TYPE_CAST(Array, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
  uint8_t kArrayCastFailure = TYPE_CAST(Array, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kI31CastSuccess = TYPE_CAST(I31, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kI31CastFailure =
      TYPE_CAST(I31, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
#undef TYPE_CAST

// If the branch is not taken, we return 0. If it is taken, then the respective
// type check should succeed, and we return 1.
#define BR_ON(type, value)                                                 \
  tester.DefineFunction(                                                   \
      tester.sigs.i_v(), {kWasmAnyRef},                                    \
      {WASM_LOCAL_SET(0, WASM_SEQ(value)),                                 \
       WASM_REF_TEST(                                                      \
           WASM_BLOCK_R(kWasm##type##Ref, WASM_LOCAL_GET(0),               \
                        WASM_BR_ON_CAST(0, kAnyRefCode, k##type##RefCode), \
                        WASM_RETURN(WASM_I32V(0))),                        \
           k##type##RefCode),                                              \
       kExprEnd})

  uint8_t kBrOnStructTaken =
      BR_ON(Struct, WASM_STRUCT_NEW_DEFAULT(struct_index));
  uint8_t kBrOnStructNotTaken = BR_ON(Struct, WASM_REF_NULL(kNoneCode));
  uint8_t kBrOnArrayTaken =
      BR_ON(Array, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
  uint8_t kBrOnArrayNotTaken = BR_ON(Array, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kBrOnI31Taken = BR_ON(I31, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kBrOnI31NotTaken =
      BR_ON(I31, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
#undef BR_ON

// If the branch is not taken, we return 1. If it is taken, then the respective
// type check should fail, and we return 0.
#define BR_ON_NON(type, value)                                            \
  tester.DefineFunction(                                                  \
      tester.sigs.i_v(), {kWasmAnyRef},                                   \
      {WASM_LOCAL_SET(0, WASM_SEQ(value)),                                \
       WASM_REF_TEST(WASM_BLOCK_R(kWasmAnyRef, WASM_LOCAL_GET(0),         \
                                  WASM_BR_ON_CAST_FAIL(0, kAnyRefCode,    \
                                                       k##type##RefCode), \
                                  WASM_RETURN(WASM_I32V(1))),             \
                     k##type##RefCode),                                   \
       kExprEnd})

  uint8_t kBrOnNonStructNotTaken =
      BR_ON_NON(Struct, WASM_STRUCT_NEW_DEFAULT(struct_index));
  uint8_t kBrOnNonStructTaken = BR_ON_NON(Struct, WASM_REF_NULL(kNoneCode));
  uint8_t kBrOnNonArrayNotTaken =
      BR_ON_NON(Array, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
  uint8_t kBrOnNonArrayTaken = BR_ON_NON(Array, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kBrOnNonI31NotTaken = BR_ON_NON(I31, WASM_REF_I31(WASM_I32V(42)));
  uint8_t kBrOnNonI31Taken =
      BR_ON_NON(I31, WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(10)));
#undef BR_ON_NON

  tester.CompileModule();

  tester.CheckResult(kStructCheckNull, 0);
  tester.CheckResult(kArrayCheckNull, 0);
  tester.CheckResult(kI31CheckNull, 0);

  tester.CheckHasThrown(kStructCastNull);
  tester.CheckHasThrown(kArrayCastNull);
  tester.CheckHasThrown(kI31CastNull);

  tester.CheckResult(kStructCheckSuccess, 1);
  tester.CheckResult(kArrayCheckSuccess, 1);
  tester.CheckResult(kI31CheckSuccess, 1);

  tester.CheckResult(kStructCheckFailure, 0);
  tester.CheckResult(kArrayCheckFailure, 0);
  tester.CheckResult(kI31CheckFailure, 0);

  tester.CheckResult(kStructCastSuccess, 1);
  tester.CheckResult(kArrayCastSuccess, 1);
  tester.CheckResult(kI31CastSuccess, 1);

  tester.CheckHasThrown(kStructCastFailure);
  tester.CheckHasThrown(kArrayCastFailure);
  tester.CheckHasThrown(kI31CastFailure);

  tester.CheckResult(kBrOnStructTaken, 1);
  tester.CheckResult(kBrOnStructNotTaken, 0);
  tester.CheckResult(kBrOnArrayTaken, 1);
  tester.CheckResult(kBrOnArrayNotTaken, 0);
  tester.CheckResult(kBrOnI31Taken, 1);
  tester.CheckResult(kBrOnI31NotTaken, 0);

  tester.CheckResult(kBrOnNonStructTaken, 0);
  tester.CheckResult(kBrOnNonStructNotTaken, 1);
  tester.CheckResult(kBrOnNonArrayTaken, 0);
  tester.CheckResult(kBrOnNonArrayNotTaken, 1);
  tester.CheckResult(kBrOnNonI31Taken, 0);
  tester.CheckResult(kBrOnNonI31NotTaken, 1);
}

// This flushed out a few bugs, so it serves as a regression test. It can also
// be modified (made to run longer) to measure performance of casts.
WASM_COMPILED_EXEC_TEST(CastsBenchmark) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex SuperType =
      tester.DefineStruct({F(wasm::kWasmI32, true)});
  const ModuleTypeIndex SubType = tester.DefineStruct(
      {F(wasm::kWasmI32, true), F(wasm::kWasmI32, true)}, SuperType);

  const ModuleTypeIndex ListType = tester.DefineArray(kWasmStructRef, true);

  const uint8_t List = tester.AddGlobal(ValueType::RefNull(ListType), true,
                                        WasmInitExpr::RefNullConst(ListType));

  const uint32_t kListLength = 1024;
  const uint32_t i = 0;
  const uint8_t Prepare = tester.DefineFunction(
      tester.sigs.i_v(), {wasm::kWasmI32},
      {// List = new eqref[kListLength];
       WASM_GLOBAL_SET(
           List, WASM_ARRAY_NEW_DEFAULT(ListType, WASM_I32V(kListLength))),
       // for (int i = 0; i < kListLength; ) {
       //   List[i] = new Super(i);
       //   i++;
       //   List[i] = new Sub(i, 0);
       //   i++;
       // }
       WASM_LOCAL_SET(i, WASM_I32V_1(0)),
       WASM_LOOP(
           WASM_ARRAY_SET(ListType, WASM_GLOBAL_GET(List), WASM_LOCAL_GET(i),
                          WASM_STRUCT_NEW(SuperType, WASM_LOCAL_GET(i))),
           WASM_LOCAL_SET(i, WASM_I32_ADD(WASM_LOCAL_GET(i), WASM_I32V_1(1))),
           WASM_ARRAY_SET(
               ListType, WASM_GLOBAL_GET(List), WASM_LOCAL_GET(i),
               WASM_STRUCT_NEW(SubType, WASM_LOCAL_GET(i), WASM_I32V_1(0))),
           WASM_LOCAL_SET(i, WASM_I32_ADD(WASM_LOCAL_GET(i), WASM_I32V_1(1))),
           WASM_BR_IF(0,
                      WASM_I32_NE(WASM_LOCAL_GET(i), WASM_I32V(kListLength)))),
       // return 42;  // Dummy value, due to test framework.
       WASM_I32V_1(42), kExprEnd});

  const uint32_t sum = 1;  // Index of the local.
  const uint32_t list = 2;
  const uint32_t kLoops = 2;
  const uint32_t kIterations = kLoops * kListLength;
  const uint8_t Main = tester.DefineFunction(
      tester.sigs.i_v(),
      {
          wasm::kWasmI32,
          wasm::kWasmI32,
          ValueType::RefNull(ListType),
      },
      {WASM_LOCAL_SET(list, WASM_GLOBAL_GET(List)),
       // sum = 0;
       WASM_LOCAL_SET(sum, WASM_I32V_1(0)),
       // for (int i = 0; i < kIterations; i++) {
       //   sum += ref.cast<super>(List[i & kListLength]).x
       // }
       WASM_LOCAL_SET(i, WASM_I32V_1(0)),
       WASM_LOOP(
           WASM_LOCAL_SET(
               sum, WASM_I32_ADD(
                        WASM_LOCAL_GET(sum),
                        WASM_STRUCT_GET(
                            SuperType, 0,
                            WASM_REF_CAST(
                                WASM_ARRAY_GET(
                                    ListType, WASM_LOCAL_GET(list),
                                    WASM_I32_AND(WASM_LOCAL_GET(i),
                                                 WASM_I32V(kListLength - 1))),
                                SuperType)))),
           WASM_LOCAL_SET(i, WASM_I32_ADD(WASM_LOCAL_GET(i), WASM_I32V_1(1))),
           WASM_BR_IF(0,
                      WASM_I32_LTS(WASM_LOCAL_GET(i), WASM_I32V(kIterations)))),
       // return sum;
       WASM_LOCAL_GET(sum), kExprEnd});

  tester.CompileModule();
  tester.CheckResult(Prepare, 42);

  // Time this section to get a benchmark for subtyping checks.
  // Note: if you bump kIterations or kListLength, you may have to take i32
  // overflow into account.
  tester.CheckResult(Main, (kListLength * (kListLength - 1) / 2) * kLoops);
}

WASM_COMPILED_EXEC_TEST(GlobalInitReferencingGlobal) {
  WasmGCTester tester(execution_tier);
  const uint8_t from = tester.AddGlobal(kWasmI32, false, WasmInitExpr(42));
  const uint8_t to =
      tester.AddGlobal(kWasmI32, false, WasmInitExpr::GlobalGet(from));

  const uint8_t func = tester.DefineFunction(tester.sigs.i_v(), {},
                                             {WASM_GLOBAL_GET(to), kExprEnd});

  tester.CompileModule();

  tester.CheckResult(func, 42);
}

WASM_COMPILED_EXEC_TEST(GCTables) {
  WasmGCTester tester(execution_tier);

  tester.builder()->StartRecursiveTypeGroup();
  ModuleTypeIndex super_struct = tester.DefineStruct({F(kWasmI32, false)});
  ModuleTypeIndex sub_struct = tester.DefineStruct(
      {F(kWasmI32, false), F(kWasmI32, true)}, super_struct);
  FunctionSig* super_sig =
      FunctionSig::Build(tester.zone(), {kWasmI32}, {refNull(sub_struct)});
  ModuleTypeIndex super_sig_index = tester.DefineSignature(super_sig);
  FunctionSig* sub_sig =
      FunctionSig::Build(tester.zone(), {kWasmI32}, {refNull(super_struct)});
  ModuleTypeIndex sub_sig_index =
      tester.DefineSignature(sub_sig, super_sig_index);
  ModuleTypeIndex unrelated_sig_index =
      tester.DefineSignature(sub_sig, super_sig_index);
  tester.builder()->EndRecursiveTypeGroup();

  tester.DefineTable(refNull(super_sig_index), 10, 10);

  uint8_t super_func = tester.DefineFunction(
      super_sig_index, {},
      {WASM_I32_ADD(WASM_STRUCT_GET(sub_struct, 0, WASM_LOCAL_GET(0)),
                    WASM_STRUCT_GET(sub_struct, 1, WASM_LOCAL_GET(0))),
       WASM_END});

  uint8_t sub_func = tester.DefineFunction(
      sub_sig_index, {},
      {WASM_STRUCT_GET(super_struct, 0, WASM_LOCAL_GET(0)), WASM_END});

  uint8_t setup_func = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_TABLE_SET(0, WASM_I32V(0), WASM_REF_NULL(super_sig_index)),
       WASM_TABLE_SET(0, WASM_I32V(1), WASM_REF_FUNC(super_func)),
       WASM_TABLE_SET(0, WASM_I32V(2), WASM_REF_FUNC(sub_func)),  // --
       WASM_I32V(0), WASM_END});

  uint8_t super_struct_producer = tester.DefineFunction(
      FunctionSig::Build(tester.zone(), {ref(super_struct)}, {}), {},
      {WASM_STRUCT_NEW(super_struct, WASM_I32V(-5)), WASM_END});
  uint8_t sub_struct_producer = tester.DefineFunction(
      FunctionSig::Build(tester.zone(), {ref(sub_struct)}, {}), {},
      {WASM_STRUCT_NEW(sub_struct, WASM_I32V(7), WASM_I32V(11)), WASM_END});

  // Calling a null entry should trap.
  uint8_t call_null = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_CALL_INDIRECT(super_sig_index,
                          WASM_CALL_FUNCTION0(sub_struct_producer),
                          WASM_I32V(0)),
       WASM_END});
  // Calling with a signature identical to the type of the table should work,
  // provided the entry has the same signature.
  uint8_t call_same_type = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_CALL_INDIRECT(super_sig_index,
                          WASM_CALL_FUNCTION0(sub_struct_producer),
                          WASM_I32V(1)),
       WASM_END});
  // Calling with a signature that is a subtype of the type of the table should
  // work, provided the entry has the same signature.
  uint8_t call_subtype = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_CALL_INDIRECT(sub_sig_index,
                          WASM_CALL_FUNCTION0(super_struct_producer),
                          WASM_I32V(2)),
       WASM_END});
  // Calling with a signature that is a subtype of the type of the table should
  // work, provided the entry has a subtype of the declared signature.
  uint8_t call_table_subtype_entry_subtype = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_CALL_INDIRECT(super_sig_index,
                          WASM_CALL_FUNCTION0(sub_struct_producer),
                          WASM_I32V(2)),
       WASM_END});
  // Calling with a signature that is mismatched to that of the entry should
  // trap.
  uint8_t call_type_mismatch = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_CALL_INDIRECT(unrelated_sig_index,
                          WASM_CALL_FUNCTION0(super_struct_producer),
                          WASM_I32V(2)),
       WASM_END});
  // Getting a table element and then calling it with call_ref should work.
  uint8_t table_get_and_call_ref = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_CALL_REF(WASM_TABLE_GET(0, WASM_I32V(2)), super_sig_index,
                     WASM_CALL_FUNCTION0(sub_struct_producer)),
       WASM_END});

  // Only here so these functions count as "declared".
  tester.AddGlobal(refNull(super_sig_index), false,
                   WasmInitExpr::RefFuncConst(super_func));
  tester.AddGlobal(refNull(sub_sig_index), false,
                   WasmInitExpr::RefFuncConst(sub_func));

  tester.CompileModule();

  tester.CheckResult(setup_func, 0);
  tester.CheckHasThrown(call_null);
  tester.CheckResult(call_same_type, 18);
  tester.CheckResult(call_subtype, -5);
  tester.CheckResult(call_table_subtype_entry_subtype, 7);
  tester.CheckHasThrown(call_type_mismatch);
  tester.CheckResult(table_get_and_call_ref, 7);
}

WASM_COMPILED_EXEC_TEST(JsAccess) {
  WasmGCTester tester(execution_tier);
  const ModuleTypeIndex type_index =
      tester.DefineStruct({F(wasm::kWasmI32, true)});
  ValueType kRefType = ref(type_index);
  ValueType kSupertypeToI[] = {kWasmI32, kWasmStructRef};
  FunctionSig sig_t_v(1, 0, &kRefType);
  FunctionSig sig_super_v(1, 0, &kWasmStructRef);
  FunctionSig sig_i_super(1, 1, kSupertypeToI);

  tester.DefineExportedFunction(
      "typed_producer", &sig_t_v,
      {WASM_STRUCT_NEW(type_index, WASM_I32V(42)), kExprEnd});
  // Same code, different signature.
  tester.DefineExportedFunction(
      "untyped_producer", &sig_super_v,
      {WASM_STRUCT_NEW(type_index, WASM_I32V(42)), kExprEnd});
  tester.DefineExportedFunction(
      "consumer", &sig_i_super,
      {WASM_STRUCT_GET(type_index, 0,
                       WASM_REF_CAST(WASM_LOCAL_GET(0), type_index)),
       kExprEnd});

  tester.CompileModule();
  Isolate* isolate = tester.isolate();
  TryCatch try_catch(reinterpret_cast<v8::Isolate*>(isolate));
  for (const char* producer : {"typed_producer", "untyped_producer"}) {
    MaybeHandle<Object> maybe_result =
        tester.CallExportedFunction(producer, 0, nullptr);
    if (maybe_result.is_null()) {
      FATAL("Calling %s failed: %s", producer,
            *v8::String::Utf8Value(reinterpret_cast<v8::Isolate*>(isolate),
                                   try_catch.Message()->Get()));
    }
    {
      Handle<Object> args[] = {maybe_result.ToHandleChecked()};
      maybe_result = tester.CallExportedFunction("consumer", 1, args);
    }
    if (maybe_result.is_null()) {
      FATAL("Calling 'consumer' failed: %s",
            *v8::String::Utf8Value(reinterpret_cast<v8::Isolate*>(isolate),
                                   try_catch.Message()->Get()));
    }
    Handle<Object> result = maybe_result.ToHandleChecked();
    CHECK(IsSmi(*result));
    CHECK_EQ(42, Cast<Smi>(*result).value());
    // Calling {consumer} with any other object (e.g. the Smi we just got as
    // {result}) should trap.
    {
      Handle<Object> args[] = {result};
      maybe_result = tester.CallExportedFunction("consumer", 1, args);
    }
    CHECK(maybe_result.is_null());
    CHECK(try_catch.HasCaught());
    try_catch.Reset();
    isolate->clear_exception();
  }
}

WASM_COMPILED_EXEC_TEST(WasmAnyConvertExtern) {
  WasmGCTester tester(execution_tier);

  const uint8_t kNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(
           WASM_GC_ANY_CONVERT_EXTERN(WASM_REF_NULL(kNoExternCode))),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kNull, 1);
}

WASM_COMPILED_EXEC_TEST(WasmExternConvertAny) {
  WasmGCTester tester(execution_tier);

  const uint8_t kNull = tester.DefineFunction(
      tester.sigs.i_v(), {},
      {WASM_REF_IS_NULL(WASM_GC_EXTERN_CONVERT_ANY(WASM_REF_NULL(kNoneCode))),
       kExprEnd});

  tester.CompileModule();
  tester.CheckResult(kNull, 1);
}

}  // namespace test_gc
}  // namespace wasm
}  // namespace internal
}  // namespace v8
```