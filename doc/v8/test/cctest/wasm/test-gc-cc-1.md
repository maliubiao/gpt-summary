Response:
The user wants a summary of the functionality of the provided C++ code snippet.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `test-gc.cc` and the `WasmGCTester` class suggest this code is testing garbage collection related features in the WebAssembly (Wasm) implementation of V8.

2. **Analyze individual tests:**  Each `WASM_COMPILED_EXEC_TEST` macro defines an independent test case. Examine the code within each test to understand what specific Wasm feature or GC interaction it's verifying. Look for keywords like `STRUCT_NEW`, `ARRAY_NEW`, `ARRAY_GET`, `ARRAY_SET`, `REF_TEST`, `REF_CAST`, etc. These indicate the Wasm instructions being tested.

3. **Categorize the tests:** Group tests based on the Wasm feature they are exercising. For instance, tests involving `STRUCT_NEW` and `STRUCT_GET` are related to Wasm structs, and those with `ARRAY_NEW`, `ARRAY_GET`, `ARRAY_SET`, and `ARRAY_COPY` are related to Wasm arrays. Tests involving `REF_TEST` and `REF_CAST` are about reference type operations.

4. **Infer the intended behavior:** For each test, try to deduce the expected outcome based on the Wasm instructions and the input values. The `tester.CheckResult()` and `tester.CheckHasThrown()` calls explicitly state the expected outcomes.

5. **Relate to JavaScript (if applicable):** Consider how the tested Wasm features might correspond to JavaScript concepts. For example, Wasm structs and arrays are similar to JavaScript objects and arrays, though with stricter typing.

6. **Identify potential user errors:**  Look for cases where the tests intentionally trigger errors or boundary conditions. These often highlight common mistakes developers might make when working with the tested features.

7. **Address specific instructions:**  The prompt asks about `.tq` files (Torque - a V8 language). Confirm if this file is Torque.

8. **Formulate the summary:** Combine the information gathered from analyzing the individual tests into a concise description of the overall functionality.

**Detailed Analysis of the Snippet:**

* **Structs:** Several tests (`WasmBasicStruct`, `WasmPackedStructU`, `WasmPackedStructS`) are focused on creating and accessing fields of Wasm structs. The "Packed" variants test how smaller integer types (i8, i16) are handled within structs.
* **Arrays:** A significant portion of the code (`WasmBasicArray`, `WasmPackedArrayU`, `WasmPackedArrayS`, `WasmArrayCopy`, `ArrayNewMap`) tests Wasm array functionality: creation, initialization, getting and setting elements, copying ranges, and handling packed element types.
* **References and Casting:** The `RefTrivialCastsStatic` and `TrivialAbstractCasts` tests explore how different Wasm reference types can be tested and cast. This includes testing for null references and upcasting/downcasting between related types.
* **`new_default`:** The `NewDefault` test checks the creation of structs and arrays with default values.
* **Function References:** The `FunctionRefs` test deals with obtaining and manipulating references to Wasm functions.

**JavaScript Connection:**

While the code is testing Wasm, it's helpful to think about how these concepts relate to JavaScript. Wasm provides lower-level control over memory and data structures.

* Wasm structs can be thought of as similar to JavaScript objects with predefined properties and types.
* Wasm arrays are similar to JavaScript arrays but with more explicit type constraints.
* Reference casting in Wasm is analogous to type checking and casting in JavaScript (though JavaScript is dynamically typed).

**Common Programming Errors:**

The tests reveal potential errors like:

* **Out-of-bounds access:** Attempting to access array elements beyond the valid index range (demonstrated by `tester.CheckHasThrown` in `WasmBasicArray` and `WasmArrayCopy`).
* **Incorrect type casting:** Trying to cast a reference to an incompatible type (demonstrated in `RefTrivialCastsStatic` and `TrivialAbstractCasts`).
* **Creating excessively large arrays:**  The `WasmBasicArray` test checks for limits on array size.

**Synthesis for the Summary:**

Based on the analysis, the code snippet is a part of V8's test suite specifically for verifying the correctness of garbage collection and related operations for various WebAssembly features, including structs, arrays, and reference type manipulations.
好的，我们来归纳一下这段v8源代码的功能。

这段代码是 `v8/test/cctest/wasm/test-gc.cc` 的一部分，正如文件名所示，它的主要功能是**测试 WebAssembly (Wasm) 的垃圾回收 (GC) 相关功能**。

由于文件名以 `.cc` 结尾，它不是 V8 Torque 源代码。

**功能归纳：**

这段代码包含了多个独立的测试用例（以 `WASM_COMPILED_EXEC_TEST` 宏定义），每个用例都针对 Wasm 中与 GC 相关的特定功能进行测试。 主要测试的 Wasm GC 功能包括：

* **结构体 (Structs) 的创建和访问:**
    * 测试使用 `struct.new` 创建结构体实例，并使用 `struct.get` 获取结构体字段的值。
    * 测试了带符号 (`struct.get_s`) 和无符号 (`struct.get_u`) 的结构体字段访问，尤其关注了当结构体字段是较小的整数类型（如 `i8`, `i16`) 时，值的正确读取和符号扩展。
* **数组 (Arrays) 的创建和操作:**
    * 测试使用 `array.new` 创建可变数组，并指定初始值和数组长度。
    * 测试使用 `array.new_default` 创建用默认值初始化的数组。
    * 测试使用 `array.new_fixed` 创建带有固定初始值的数组。
    * 测试使用 `array.get` 和 `array.set` 访问和修改数组元素。
    * 测试了带符号 (`array.get_s`) 和无符号 (`array.get_u`) 的数组元素访问，尤其关注了当数组元素是较小的整数类型时，值的正确读取和符号扩展。
    * 测试使用 `array.len` 获取数组的长度。
    * 测试数组的拷贝操作 `array.copy`，包括不同类型的数组之间的拷贝，以及重叠区域的拷贝。
    * 测试了创建非常大的数组以及超出最大长度限制的情况。
* **引用类型 (References) 的测试和转换:**
    * 测试 `ref.test` 指令，用于检查一个引用是否属于特定的类型。包括对 `null` 引用、父类型引用、子类型引用以及不相关类型引用的测试。
    * 测试 `ref.cast` 指令，用于将一个引用转换为特定的类型。包括向上转型、向下转型以及对 `null` 引用的转换。
    * 测试 `br_on_cast` 和 `br_on_cast_fail` 指令，用于在类型转换成功或失败时进行分支跳转。
    * 测试了抽象引用类型 (`anyref`, `arrayref`, `funcref`, `i31ref`) 的类型测试和转换。
* **默认值 (Default Values) 的创建:**
    * 测试使用 `struct.new_default` 和 `array.new_default` 创建结构体和数组，并验证它们是否被正确地初始化为默认值。
* **函数引用 (Function References) 的使用:**
    * 测试使用 `ref.func` 获取函数的引用。
    * 测试函数引用的类型转换 (`ref.cast`) 和类型测试 (`ref.test`)。

**与 Javascript 的关系：**

虽然这段代码是 C++ 写的 Wasm 测试，但它测试的 Wasm 功能与 JavaScript 中的某些概念有对应关系：

* **结构体 (Structs)** 可以类比为 JavaScript 的 **对象 (Objects)**，它们都包含一组命名的属性。
* **数组 (Arrays)** 在 Wasm 和 JavaScript 中都是有序的数据集合。
* **引用类型 (References)**  在 JavaScript 中也有类似的概念，例如对象的引用。Wasm 中更强调类型的概念。
* **函数引用 (Function References)** 可以类比为 JavaScript 中的 **函数 (Functions)**，可以将函数作为值传递和操作。

**Javascript 示例 (对应 Wasm 数组和结构体):**

```javascript
// 对应 Wasm 结构体
const wasmStructLike = {
  field1: 123,
  field2: -1
};

// 对应 Wasm 数组
const wasmArrayLike = [12, 42, 12];
wasmArrayLike[1] = 42;
console.log(wasmArrayLike[0]); // 对应 WASM_ARRAY_GET

// 在 JavaScript 中没有直接对应 packed array 的概念，但可以模拟
const packedArray = new Uint8Array(4);
packedArray[0] = 1;
packedArray[1] = 10;
packedArray[2] = 200;
packedArray[3] = 258; // 只会存储低 8 位
console.log(packedArray[3]); // 输出 2
```

**代码逻辑推理与假设输入输出：**

以 `WASM_COMPILED_EXEC_TEST(WasmBasicStruct)` 为例：

**假设输入：** 无 (函数没有参数)

**代码逻辑：**

1. 定义一个结构体类型 `type_index`，包含三个 `i32` 类型的字段。
2. 定义一个函数 `kFunc`，该函数：
   - 创建一个结构体实例，三个字段分别初始化为 `1`, `-1`, `3`。
   - 使用 `struct.get` 获取索引为 `arg0` 的字段的值 (参数 `arg0` 来自 `tester.CheckResult` 的第二个参数)。

**假设 `tester.CheckResult(kFunc, 0b1001)`：**

* `kFunc` 是要执行的函数。
* `0b1001` 是一个掩码，表示要检查的返回值的位置（这里可能表示检查多个返回值位）。由于该函数只返回一个 `i32` 值，更合理的解释是这个值会被解释成布尔值或者用于后续的位运算检查。

根据代码，`kFunc` 会返回结构体的第 `arg0` 个字段的值。

* 当 `arg0` 为 0 时，返回第一个字段的值 `1`。
* 当 `arg0` 为 1 时，返回第二个字段的值 `-1`。
* 当 `arg0` 为 2 时，返回第三个字段的值 `3`。

`0b1001` 的具体含义需要查看 `tester.CheckResult` 的实现，但根据上下文，它可能用于验证返回值的特定位。

**用户常见的编程错误：**

* **结构体字段访问越界：**  例如，尝试访问不存在的结构体字段索引。Wasm 会抛出错误。
* **数组索引越界：** 例如，尝试访问超出数组长度的索引。测试用例 `WasmBasicArray` 中有 `tester.CheckHasThrown(kGetElem, 3)` 和 `tester.CheckHasThrown(kGetElem, -1)`，模拟了这种情况。
* **类型转换错误：** 例如，尝试将一个引用强制转换为不兼容的类型。测试用例 `RefTrivialCastsStatic` 和 `TrivialAbstractCasts` 覆盖了这类情况。
* **假设 Packed 数组存储完整的值：**  当使用 `array.set_u` 或 `array.set_s` 向较小类型的数组中写入较大值时，会发生截断或符号扩展，这可能导致意外的结果。测试用例 `WasmPackedArrayU` 和 `WasmPackedArrayS` 强调了这一点。

总而言之，这段代码是 V8 中用于严格测试 WebAssembly 垃圾回收机制和相关特性的重要组成部分，确保了 Wasm 在 V8 中的正确性和可靠性。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-gc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-gc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```