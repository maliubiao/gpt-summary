Response: The user wants to understand the functionality of the provided C++ code snippet, which is part 2 of a larger file. This file seems to be testing Garbage Collection (GC) related features in the V8 JavaScript engine's WebAssembly implementation.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename "test-gc.cc" and the function names within the snippet strongly suggest this code tests GC-related WebAssembly functionalities.

2. **Analyze Individual Tests:**  Go through each `WASM_COMPILED_EXEC_TEST` block. These represent individual test cases. Understand what each test is setting up and what it's asserting.

3. **Focus on WebAssembly Instructions:** Pay attention to the WebAssembly instructions used within each test (e.g., `WASM_CALL_REF`, `WASM_REF_NULL`, `WASM_REF_CAST`, `WASM_STRUCT_NEW`, `WASM_ARRAY_NEW`, `WASM_TABLE_SET`, `WASM_CALL_INDIRECT`, `WASM_GC_ANY_CONVERT_EXTERN`, `WASM_GC_EXTERN_CONVERT_ANY`). These instructions are key to understanding the tested features.

4. **Look for Assertions:**  The `tester.CheckResult()` and `tester.CheckHasThrown()` calls are the assertions. They tell you what the expected outcome of each test is.

5. **Relate to JavaScript (if possible):** Think about how the tested WebAssembly features might manifest or be related to JavaScript concepts. This involves understanding the interaction between WebAssembly and JavaScript within the V8 engine. This might involve considering how JavaScript values are represented in WebAssembly or how JavaScript functions can interact with WebAssembly.

6. **Synthesize the Functionality:** Combine the understanding of individual tests to summarize the overall functionality of the code snippet.

7. **Provide JavaScript Examples:** If a connection to JavaScript exists, create simple JavaScript code snippets that illustrate the related functionality or concepts.

**Detailed Analysis of the Snippet:**

* **`CallRef`**: Tests calling a function through a `funcref`. It verifies that `call_ref` works correctly with function references.
* **`CallAbstractNullTypeImplicitConversion`**: Checks if a function expecting a supertype reference can accept different null reference types (e.g., `nullref`, `nullfuncref`, `nullexternref`). This tests implicit conversions for null references.
* **`CastNullRef`**: Verifies that attempting to cast a `nullref` to a non-nullable reference type (like `structref`, `arrayref`, `i31ref`) results in a trap (error).
* **`CallReftypeParameters`**: Tests calling a function with reference type parameters, specifically passing struct instances as arguments.
* **`AbstractTypeChecks`**:  A comprehensive set of tests for various operations involving abstract reference types (`anyref`, `structref`, `arrayref`, `i31ref`). It checks:
    * `ref.test`:  Checks if a reference is of a specific type.
    * `ref.cast`:  Attempts to cast a reference to a specific type (and verifies traps for invalid casts).
    * `br_on_cast`: Conditional branching based on successful type casting.
    * `br_on_cast_fail`: Conditional branching based on failed type casting.
* **`CastsBenchmark`**:  Seems to be a performance test for `ref.cast` operations, involving casting between super and subtype structs within an array.
* **`GlobalInitReferencingGlobal`**: Tests the initialization of a global variable with the value of another global variable. This isn't directly GC-related but is part of the broader WebAssembly module setup.
* **`GCTables`**: Focuses on testing WebAssembly tables that hold function references (`funcref`). It tests:
    * Setting and getting function references in tables.
    * Calling functions indirectly through tables (`call_indirect`).
    * Calling functions through `call_ref` after retrieving them from a table.
    * Handling type compatibility when calling functions indirectly.
* **`JsAccess`**: Examines the interaction between WebAssembly GC objects and JavaScript. It tests:
    * Exporting WebAssembly functions that create GC objects.
    * Importing a WebAssembly function that consumes GC objects.
    * Verifying that JavaScript can correctly interact with these exported/imported functions and that type mismatches cause errors.
* **`WasmAnyConvertExtern`**: Tests the `gc.any_convert_extern` instruction, which attempts to convert an `externref` to an `anyref`. It specifically checks the case of converting `null` `externref`.
* **`WasmExternConvertAny`**: Tests the `gc.extern_convert_any` instruction, which attempts to convert an `anyref` to an `externref`. It specifically checks the case of converting `null` `anyref`.
这是该C++源代码文件的第二部分，延续了第一部分的功能，主要集中在测试V8 JavaScript引擎中WebAssembly的垃圾回收（GC）相关特性。具体来说，这部分代码测试了以下功能：

**主要功能归纳:**

* **`CallRef`**: 测试通过 `call_ref` 指令调用函数引用 (`funcref`)。验证了 `call_ref` 可以正确地调用函数。
* **`CallAbstractNullTypeImplicitConversion`**: 测试当函数期望一个父类型的引用时，是否可以接受抽象的 null 类型参数（例如 `nullref`, `nullfuncref`, `nullexternref`）。这验证了不同 null 引用类型之间的隐式转换。
* **`CastNullRef`**: 测试将 `nullref` 强制转换为非空引用类型（如 `structref`, `arrayref`, `i31ref`）的行为，预期会抛出异常 (trap)。
* **`CallReftypeParameters`**: 测试调用带有引用类型参数的函数，特别是将结构体实例作为参数传递的情况。
* **`AbstractTypeChecks`**:  一个综合性的测试，涵盖了抽象引用类型 (`anyref`) 的各种操作，包括：
    * **`ref.test`**: 检查一个引用是否属于特定的类型。
    * **`ref.cast`**: 尝试将引用强制转换为特定类型，并验证无效转换是否会抛出异常。
    * **`br_on_cast`**: 基于类型转换成功与否进行条件分支。
    * **`br_on_cast_fail`**: 基于类型转换失败与否进行条件分支。
* **`CastsBenchmark`**:  似乎是一个性能测试，用于评估 `ref.cast` 操作的性能，涉及在数组中进行父类型和子类型结构体之间的转换。
* **`GlobalInitReferencingGlobal`**: 测试全局变量的初始化，其中一个全局变量的值依赖于另一个全局变量的值。虽然不直接涉及 GC，但展示了 WebAssembly 模块的初始化能力。
* **`GCTables`**: 主要测试 WebAssembly 的表（tables），这些表可以存储函数引用 (`funcref`)。测试了以下方面：
    * 在表中设置和获取函数引用。
    * 通过表进行间接函数调用 (`call_indirect`)。
    * 从表中获取函数引用后，使用 `call_ref` 进行调用。
    * 间接调用时处理函数签名的兼容性（子类型关系）。
* **`JsAccess`**: 测试 WebAssembly 的 GC 对象与 JavaScript 之间的交互。它测试了：
    * 导出创建 GC 对象的 WebAssembly 函数。
    * 导入使用 GC 对象的 WebAssembly 函数。
    * 验证 JavaScript 可以正确地调用这些导出/导入的函数，并确保类型不匹配时会抛出错误。
* **`WasmAnyConvertExtern`**: 测试 `gc.any_convert_extern` 指令，该指令尝试将 `externref` 转换为 `anyref`。特别测试了将 null `externref` 转换为 `anyref` 的情况。
* **`WasmExternConvertAny`**: 测试 `gc.extern_convert_any` 指令，该指令尝试将 `anyref` 转换为 `externref`。特别测试了将 null `anyref` 转换为 `externref` 的情况。

**与 JavaScript 的关系及示例:**

这部分代码测试的很多 WebAssembly GC 特性与 JavaScript 的对象模型和类型系统息息相关。例如：

* **`ref.cast` 和类型检查:**  类似于 JavaScript 中的 `instanceof` 运算符或类型断言。

```javascript
// JavaScript 示例 (概念类似)
function processObject(obj) {
  if (obj instanceof MyClass) {
    console.log(obj.someMethod());
  } else {
    console.log("Object is not an instance of MyClass");
  }
}
```

* **`CallRef` 和函数引用:**  类似于 JavaScript 中的函数作为一等公民，可以被赋值给变量并调用。

```javascript
// JavaScript 示例
function greet(name) {
  console.log("Hello, " + name + "!");
}

let myFunc = greet;
myFunc("World"); // 调用函数引用
```

* **WebAssembly 表 (`tables`) 和间接调用:**  可以类比于 JavaScript 中使用对象或数组存储函数，然后动态地调用它们。

```javascript
// JavaScript 示例
const actions = {
  "greet": (name) => console.log("Hello, " + name + "!"),
  "farewell": (name) => console.log("Goodbye, " + name + "!")
};

function performAction(actionName, arg) {
  if (actions[actionName]) {
    actions[actionName](arg);
  } else {
    console.log("Action not found");
  }
}

performAction("greet", "JavaScript");
```

* **`JsAccess` 和 WebAssembly 与 JavaScript 的互操作性:**  展示了 WebAssembly 如何创建可以在 JavaScript 中使用的对象，以及 JavaScript 如何将对象传递给 WebAssembly 函数。

```javascript
// JavaScript 示例 (假设 WebAssembly 模块已加载)
const wasmInstance = // ... 加载的 WebAssembly 实例
const myObject = wasmInstance.exports.typed_producer(); // 调用 WebAssembly 函数创建对象
console.log(wasmInstance.exports.consumer(myObject)); // 将对象传递给 WebAssembly 函数
```

总而言之，这部分 `test-gc.cc` 文件深入测试了 WebAssembly 中与垃圾回收密切相关的各种新特性，包括引用类型、类型转换、函数引用、表以及与 JavaScript 的互操作性，确保了这些功能在 V8 引擎中的正确性和稳定性。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-gc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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

"""


```