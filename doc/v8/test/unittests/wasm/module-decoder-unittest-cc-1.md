Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine and appears to be unit tests for the WebAssembly module decoder.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `module-decoder-unittest.cc` strongly suggests these are tests for the module decoding process in V8's Wasm implementation.

2. **Analyze the structure:** The code consists of multiple `TEST_F` blocks within a `WasmModuleVerifyTest` fixture. This indicates individual test cases.

3. **Examine individual test cases:** Look for patterns in the test names and the data they use. Keywords like "failure", "verifies", "type error", "length error" are clues about the tested scenarios. The `SECTION` macros likely define parts of a Wasm module's binary format.

4. **Categorize the functionalities:**  Group the tests based on the Wasm features they seem to be verifying. For example, tests involving `STRUCT_FIELD`, `ARRAY_NEW_FIXED`, `EmptyStruct`, `InvalidStructTypeDef`, `InvalidArrayTypeDef` are related to struct and array type definitions and their validation. Tests with "Exception" in their name are related to Wasm exceptions. "TypeCanonicalization" tests the process of normalizing type representations. "DataSegment" tests how data segments are handled. "ElementSection" tests the handling of element segments.

5. **Check for specific instructions:**  Look for Wasm instructions or keywords like `WASM_INIT_EXPR_STRUCT_NEW`, `WASM_INIT_EXPR_ARRAY_NEW_FIXED`, `kWasmStructTypeCode`, `kWasmArrayTypeCode`, `kRefCode`, `kTagCode`. These provide direct insight into the Wasm features being tested.

6. **Consider error handling:**  The presence of `EXPECT_FAILURE_WITH_MSG` indicates tests that expect certain decoding scenarios to fail with specific error messages. This is important for ensuring the decoder handles invalid Wasm modules correctly.

7. **Look for specific Wasm features:**  Identify features like globals, types, structs, arrays, exceptions (tags), data segments, element segments, and type canonicalization.

8. **Infer the overall function:** Combine the observations from individual tests to deduce the general functionalities covered by this part of the test suite.

9. **Address the additional constraints:**
    * `.tq` check:  Determine if the filename ends with `.tq`. It doesn't, so this part is straightforward.
    * JavaScript relation:  Think about the relationship between Wasm features and their potential JavaScript counterparts. For example, Wasm structs and arrays are related to JavaScript objects and arrays.
    * Code logic and I/O: Identify test cases where specific input (Wasm bytecode) is expected to produce a certain outcome (verification success or failure with a specific error message).
    * Common programming errors: Consider what common mistakes a programmer might make when defining Wasm modules, such as type mismatches, incorrect sizes, or invalid indices.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the specific byte sequences. It's important to abstract to the *meaning* of those sequences in terms of Wasm features.
* I need to ensure the summary accurately reflects the balance of different test categories. If many tests focus on type definitions, the summary should reflect that.
* The prompt asks for a summary of *this specific part*. I need to avoid bringing in information from other parts of the file or general Wasm knowledge unless directly supported by the provided code.
这段代码是 `v8/test/unittests/wasm/module-decoder-unittest.cc` 的一部分，主要功能是**测试 WebAssembly 模块解码器在处理特定类型的全局变量初始化表达式时的行为，以及验证结构体 (struct) 和数组 (array) 类型的定义和使用是否正确**。

以下是对代码功能的详细归纳：

**1. 全局变量初始化表达式测试：**

* **`StructNewInitExpr`:** 测试使用 `struct.new` 指令作为全局变量的初始化表达式。
    *  验证了基本情况下（类型匹配）的正确解码。
    *  验证了类型错误的情况，例如尝试用 `i32` 类型的值初始化一个 `(ref 1)` 类型的结构体字段。

* **`ArrayNewFixedInitExpr`:** 测试使用 `array.new_fixed` 指令作为全局变量的初始化表达式。
    *  验证了基本情况下（类型匹配，可变/不可变数组）的正确解码。
    *  验证了类型错误的情况，例如初始化值的类型与数组元素类型不匹配。
    *  验证了数组长度与初始化表达式中元素数量不匹配的情况。

**2. 结构体类型定义测试：**

* **`EmptyStruct`:** 测试定义一个没有字段的空结构体。
* **`InvalidStructTypeDef`:** 测试定义无效结构体类型的情况，包括：
    *  字段类型无效（例如使用 `kWasmArrayTypeCode`）。
    *  字段类型引用超出范围的类型索引。
    *  字段类型引用不可引用的类型。
    *  提供的字段类型数量不足。
    *  字段的可变性值无效。

**3. 数组类型定义测试：**

* **`InvalidArrayTypeDef`:** 测试定义无效数组类型的情况，包括：
    *  元素类型无效（例如使用 `kWasmArrayTypeCode`）。
    *  元素类型引用超出范围的类型索引。
    *  元素类型引用不可引用的类型。
    *  可变性值无效。
* **`immutable`:** 测试定义不可变数组的情况。

**4. 类型规范化测试：**

* **`TypeCanonicalization`:** 测试 WebAssembly 类型规范化的过程，特别是针对递归类型组（recursive type groups）。
    *  验证了当两个递归类型组定义相同时，它们的类型被认为是相同的。
    *  验证了当两个递归类型组定义不同时，它们的类型被认为是不同的。
    *  测试了空的递归类型组。
    *  测试了混合空和非空递归类型组的情况。

* **`InvalidSupertypeInRecGroup`:** 测试在递归类型组中声明无效的父类型（supertype）的情况。
* **`SuperTypeDeclarationWith0Supertypes`:** 测试声明没有父类型的子类型。
* **`NoSupertypeSupertype`:** 测试引用一个不存在的父类型。
* **`NonSpecifiedFinalType` 和 `SpecifiedFinalType`:** 测试继承自被标记为 final 的类型的情况。

**5. 异常 (Tag) 部分测试：**

* **`ZeroExceptions`，`OneI32Exception`，`TwoExceptions`:** 测试定义不同数量和参数类型的异常标签。
* **`Exception_invalid_sig_index`:** 测试引用不存在的签名索引来定义异常标签。
* **`Exception_invalid_sig_return`:** 测试使用具有非 void 返回值的签名来定义异常标签（异常标签的签名必须是 void 返回）。
* **`Exception_invalid_attribute`:** 测试使用不支持的属性值来定义异常标签。
* **`TagSectionCorrectPlacement`，`TagSectionAfterGlobal`，`TagSectionBeforeMemory`，`TagSectionAfterTableBeforeMemory`:** 测试异常标签部分在 WebAssembly 模块中的正确位置。
* **`TagImport`:** 测试导入异常标签。
* **`ExceptionExport`:** 测试导出异常标签。

**6. 签名 (Type) 部分测试：**

* **`OneSignature`:** 测试定义单个函数签名。
* **`MultipleSignatures`:** 测试定义多个不同参数和返回类型的函数签名。
* **`CanonicalTypeIds`:** 测试类型规范化后分配的规范类型 ID。

**7. 数据段 (Data Segment) 部分测试：**

* **`DataSegmentWithImmutableImportedGlobal`:** 测试使用不可变的导入全局变量作为数据段的初始化表达式。
* **`DataSegmentWithMutableImportedGlobal`:** 测试使用可变的导入全局变量作为数据段的初始化表达式（预期会失败，因为只能使用不可变全局变量）。
* **`DataSegmentWithImmutableGlobal`:** 测试使用不可变的本地全局变量作为数据段的初始化表达式。
* **`OneDataSegment`，`TwoDataSegments`:** 测试定义一个或多个数据段，并验证其属性（例如源偏移量和长度）。
* **`DataWithoutMemory`:** 测试在没有定义内存的情况下定义数据段（预期会失败）。
* **`MaxMaximumMemorySize`:** 测试定义最大内存大小的限制。
* **`InvalidMemoryLimits`:** 测试定义无效的内存限制标志。
* **`DataSegment_wrong_init_type`:** 测试数据段初始化表达式的类型错误。
* **`DataSegmentEndOverflow`:** 测试数据段大小导致溢出的情况。

**8. 表 (Table) 和元素段 (Element Segment) 部分测试：**

* **`OneIndirectFunction`:** 测试定义一个包含函数引用的表。
* **`ElementSectionWithInternalTable`:** 测试元素段与内部定义的表一起使用。
* **`ElementSectionWithImportedTable`:** 测试元素段与导入的表一起使用。
* **`ElementSectionWithoutTable`:** 测试在没有定义表的情况下定义元素段（预期会失败）。
* **`Regression_735887`:**  测试元素段中无效函数索引的回归问题。

**关于其他问题：**

* **`.tq` 结尾：**  `v8/test/unittests/wasm/module-decoder-unittest.cc` 以 `.cc` 结尾，说明它是 C++ 源代码，而不是 v8 torque 源代码。
* **与 Javascript 的关系：** WebAssembly 模块最终会在 JavaScript 虚拟机中运行。这些测试确保了 V8 的 Wasm 解码器能够正确解析 Wasm 的各种特性，从而使得 JavaScript 可以安全、高效地调用和管理 Wasm 代码。

**JavaScript 示例 (与 `ArrayNewFixedInitExpr` 相关):**

在 JavaScript 中，你可以创建一个包含特定元素的数组，这与 Wasm 的 `array.new_fixed` 类似：

```javascript
const myArray = [10, 20, 30];
console.log(myArray); // 输出: [10, 20, 30]
```

在 Wasm 中，`WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 3, WASM_I32V(10), WASM_I32V(20), WASM_I32V(30))`  就是定义了一个长度为 3 的数组，并用 10, 20, 30 初始化。

**代码逻辑推理（假设输入与输出 - 以 `StructNewInitExpr` 的类型错误为例）：**

**假设输入 (type_error 数组的内容):**

```c++
static const uint8_t type_error[] = {
    SECTION(Type, ENTRY_COUNT(2),  // --
            WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true))),
    SECTION(Global, ENTRY_COUNT(1),  // --
            kRefCode, 1, 0,          // type, mutability
            WASM_INIT_EXPR_STRUCT_NEW(0, WASM_I32V(42)))};
```

**预期输出 (通过 `EXPECT_FAILURE_WITH_MSG` 断言):**

解码器应该失败，并抛出以下错误消息：

```
"type error in constant expression[0] (expected (ref 1), got (ref 0))"
```

**推理：**

1. `SECTION(Type, ...)` 定义了一个结构体类型（索引为 0），包含一个 `i32` 类型的字段。
2. `SECTION(Global, ...)` 尝试定义一个全局变量，其类型为 `kRefCode, 1`，这表示对索引为 1 的类型的引用。但是，索引 1 的类型并没有定义（只有索引 0 被定义了）。
3. `WASM_INIT_EXPR_STRUCT_NEW(0, WASM_I32V(42))` 试图使用索引为 0 的结构体类型创建一个新的结构体实例，并提供一个 `i32` 类型的值。
4. 由于全局变量声明的类型期望一个对未定义类型 (索引 1) 的引用，而初始化表达式返回的是对已定义结构体类型 (索引 0) 的引用，因此类型不匹配，导致解码失败并产生预期的错误消息。

**用户常见的编程错误举例 (与 `ArrayNewFixedInitExpr` 的 `length_error` 相关):**

用户在手动构建 WebAssembly 模块时，可能会犯以下错误：

```c++
static const uint8_t length_error[] = {
    SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI16Code, true)),
    SECTION(Global, ENTRY_COUNT(1),  // --
            kRefCode, 0, 0,          // type, mutability
            WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 10, WASM_I32V(10),
                                           WASM_I32V(20), WASM_I32V(30)))};
```

**错误：** 在 `WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 10, ...)` 中声明数组长度为 10，但只提供了 3 个初始化值 (`WASM_I32V(10)`, `WASM_I32V(20)`, `WASM_I32V(30)`)。

**错误消息：** 解码器会抛出类似以下的错误消息，明确指出提供的初始化值数量不足：

```
"not enough arguments on the stack for array.new_fixed (need 10, got 3)"
```

**总结这段代码的功能：**

这段代码是 V8 WebAssembly 模块解码器的单元测试，专注于验证以下功能：

* **正确解码和验证全局变量的初始化表达式，特别是涉及到结构体和数组创建的表达式。**
* **正确解析和验证结构体和数组类型的定义，包括字段类型、可变性以及对其他类型的引用。**
* **WebAssembly 类型的规范化过程，特别是针对递归类型组的处理。**
* **异常标签的定义、导入和导出的正确性。**
* **函数签名的定义和解析。**
* **数据段的定义和初始化，包括使用全局变量作为初始化地址。**
* **表和元素段的定义和相互关联。**

这些测试覆盖了 Wasm 模块解码过程中可能出现的各种情况，包括合法的和非法的模块结构，旨在确保 V8 的解码器能够健壮且正确地处理各种 WebAssembly 模块。

### 提示词
```
这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/module-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
(1), STRUCT_FIELD(kI64Code, true))),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 1, 0,          // type, mutability
              WASM_INIT_EXPR_STRUCT_NEW(0, WASM_I32V(42)))};
  EXPECT_FAILURE_WITH_MSG(
      type_error,
      "type error in constant expression[0] (expected (ref 1), got (ref 0))");
}

TEST_F(WasmModuleVerifyTest, ArrayNewFixedInitExpr) {
  static const uint8_t basic[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI16Code, true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 3, WASM_I32V(10), WASM_I32V(20),
                                             WASM_I32V(30)))};
  EXPECT_VERIFIES(basic);

  static const uint8_t basic_static[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI16Code, true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 3, WASM_I32V(10), WASM_I32V(20),
                                             WASM_I32V(30)))};
  EXPECT_VERIFIES(basic_static);

  static const uint8_t basic_immutable[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI32Code, false)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 3, WASM_I32V(10), WASM_I32V(20),
                                             WASM_I32V(30)))};
  EXPECT_VERIFIES(basic_immutable);

  static const uint8_t type_error[] = {
      SECTION(Type, ENTRY_COUNT(2),  // --
              WASM_ARRAY_DEF(kI32Code, true),
              WASM_ARRAY_DEF(WASM_SEQ(kRefCode, 0), true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 1, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 1, WASM_I32V(42)))};
  EXPECT_FAILURE_WITH_MSG(
      type_error,
      "type error in constant expression[0] (expected (ref 1), got (ref 0))");

  static const uint8_t subexpr_type_error[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI64Code, true)),
      SECTION(
          Global, ENTRY_COUNT(1),  // --
          kRefCode, 0, 0,          // type, mutability
          WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 2, WASM_I64V(42), WASM_I32V(142)))};
  EXPECT_FAILURE_WITH_MSG(subexpr_type_error,
                          "array.new_fixed[1] expected type i64, found "
                          "i32.const of type i32");

  static const uint8_t length_error[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI16Code, true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 10, WASM_I32V(10),
                                             WASM_I32V(20), WASM_I32V(30)))};
  EXPECT_FAILURE_WITH_MSG(length_error,
                          "not enough arguments on the stack for "
                          "array.new_fixed (need 10, got 3)");
}

TEST_F(WasmModuleVerifyTest, EmptyStruct) {
  static const uint8_t empty_struct[] = {SECTION(Type, ENTRY_COUNT(1),  // --
                                                 kWasmStructTypeCode,   // --
                                                 U32V_1(0))};  // field count

  EXPECT_VERIFIES(empty_struct);
}

TEST_F(WasmModuleVerifyTest, InvalidStructTypeDef) {
  static const uint8_t all_good[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kI32Code,              // perfectly valid field type
              1)};                   // mutability
  EXPECT_VERIFIES(all_good);

  static const uint8_t invalid_field_type[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kWasmArrayTypeCode,    // bogus field type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(invalid_field_type, "invalid value type");

  static const uint8_t field_type_oob_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kRefNullCode,          // field type: reference...
              3,                     // ...to nonexistent type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_oob_ref, "Type index 3 is out of bounds");

  static const uint8_t field_type_invalid_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kRefNullCode,          // field type: reference...
              U32V_4(1234567),       // ...to a type > kV8MaxWasmTypes
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref, "greater than the maximum");

  static const uint8_t field_type_invalid_ref2[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kRefNullCode,          // field type: reference...
              kI32Code,              // ...to a non-referenceable type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref2, "Unknown heap type");

  static const uint8_t not_enough_field_types[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(2),             // field count
              kI32Code,              // field type 1
              1)};                   // mutability 1
  EXPECT_FAILURE_WITH_MSG(not_enough_field_types, "expected 1 byte");

  static const uint8_t not_enough_field_types2[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(2),             // field count
              kI32Code,              // field type 1
              1,                     // mutability 1
              kI32Code)};            // field type 2
  EXPECT_FAILURE_WITH_MSG(not_enough_field_types2, "expected 1 byte");

  static const uint8_t invalid_mutability[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kI32Code,              // field type
              2)};                   // invalid mutability value
  EXPECT_FAILURE_WITH_MSG(invalid_mutability, "invalid mutability");
}

TEST_F(WasmModuleVerifyTest, InvalidArrayTypeDef) {
  static const uint8_t all_good[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kI32Code,              // perfectly valid field type
              1)};                   // mutability
  EXPECT_VERIFIES(all_good);

  static const uint8_t invalid_field_type[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kWasmArrayTypeCode,    // bogus field type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(invalid_field_type, "invalid value type");

  static const uint8_t field_type_oob_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kRefNullCode,          // field type: reference...
              3,                     // ...to nonexistent type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_oob_ref, "Type index 3 is out of bounds");

  static const uint8_t field_type_invalid_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kRefNullCode,          // field type: reference...
              U32V_3(1234567),       // ...to a type > kV8MaxWasmTypes
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref, "Unknown heap type");

  static const uint8_t field_type_invalid_ref2[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kRefNullCode,          // field type: reference...
              kI32Code,              // ...to a non-referenceable type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref2, "Unknown heap type");

  static const uint8_t invalid_mutability[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kI32Code,              // field type
              2)};                   // invalid mutability value
  EXPECT_FAILURE_WITH_MSG(invalid_mutability, "invalid mutability");

  static const uint8_t immutable[] = {SECTION(Type,
                                              ENTRY_COUNT(1),      // --
                                              kWasmArrayTypeCode,  // --
                                              kI32Code,            // field type
                                              0)};  // immmutability
  EXPECT_VERIFIES(immutable);
}

TEST_F(WasmModuleVerifyTest, TypeCanonicalization) {
  static const uint8_t identical_group[] = {
      SECTION(Type,            // --
              ENTRY_COUNT(2),  // two identical rec. groups
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode, kI32Code, 0,              // --
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode, kI32Code, 0),
      SECTION(Global,                          // --
              ENTRY_COUNT(1), kRefCode, 0, 0,  // Type, mutability
              WASM_ARRAY_NEW_FIXED(1, 1, WASM_I32V(10)),
              kExprEnd)  // initial value
  };

  // Global initializer should verify as identical type in other group
  EXPECT_VERIFIES(identical_group);

  static const uint8_t non_identical_group[] = {
      SECTION(Type,            // --
              ENTRY_COUNT(2),  // two distrinct rec. groups
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode, kI32Code, 0,              // --
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(2),  // --
              kWasmArrayTypeCode, kI32Code, 0,              // --
              kWasmStructTypeCode, ENTRY_COUNT(0)),
      SECTION(Global,                          // --
              ENTRY_COUNT(1), kRefCode, 0, 0,  // Type, mutability
              WASM_ARRAY_NEW_FIXED(1, 1, WASM_I32V(10)),
              kExprEnd)  // initial value
  };

  // Global initializer should not verify as type in distinct rec. group.
  EXPECT_FAILURE_WITH_MSG(
      non_identical_group,
      "type error in constant expression[0] (expected (ref 0), got (ref 1))");

  static const uint8_t empty_group[] = {
      SECTION(Type,            // --
              ENTRY_COUNT(1),  // one rec. group
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(0))};

  EXPECT_VERIFIES(empty_group);

  static const uint8_t mixed_empty_and_nonempty_groups[] = {SECTION(
      Type,                                         // --
      ENTRY_COUNT(4),                               // one rec. group
      kWasmRecursiveTypeGroupCode, ENTRY_COUNT(0),  // empty
      SIG_ENTRY_v_v,                                // one type
      kWasmRecursiveTypeGroupCode, ENTRY_COUNT(0),  // empty
      SIG_ENTRY_v_v                                 // one type
      )};

  EXPECT_VERIFIES(mixed_empty_and_nonempty_groups);
}

// Tests that all types in a rec. group are checked for supertype validity.
TEST_F(WasmModuleVerifyTest, InvalidSupertypeInRecGroup) {
  static const uint8_t invalid_supertype[] = {
      SECTION(Type, ENTRY_COUNT(1),                         // --
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(2),  // --
              kWasmSubtypeCode, 0,              // 0 supertypes, non-final
              kWasmArrayTypeCode, kI32Code, 0,  // --
              kWasmSubtypeCode, 1, 0,           // supertype count, supertype
              kWasmArrayTypeCode, kI64Code, 0)};

  EXPECT_FAILURE_WITH_MSG(invalid_supertype,
                          "type 1 has invalid explicit supertype 0");
}

// Tests supertype declaration with 0 supertypes.
TEST_F(WasmModuleVerifyTest, SuperTypeDeclarationWith0Supertypes) {
  static const uint8_t zero_supertypes[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmSubtypeCode, 0,   // supertype count
              kWasmArrayTypeCode, kI32Code, 0)};

  EXPECT_VERIFIES(zero_supertypes);
}

TEST_F(WasmModuleVerifyTest, NoSupertypeSupertype) {
  static const uint8_t no_supertype[] = {
      SECTION(Type, ENTRY_COUNT(1),          // --
              kWasmSubtypeCode, 1,           // supertype count
              0xff, 0xff, 0xff, 0xff, 0x0f,  // supertype = "kNoSuperType"
              kWasmArrayTypeCode, kI32Code, 0)};

  EXPECT_FAILURE_WITH_MSG(no_supertype, "type 0: invalid supertype 4294967295");
}

TEST_F(WasmModuleVerifyTest, NonSpecifiedFinalType) {
  static const uint8_t final_supertype[] = {
      SECTION(Type, ENTRY_COUNT(2),                 // --
              kWasmStructTypeCode, 1, kI32Code, 1,  // --
              kWasmSubtypeCode, 1, 0,               // --
              kWasmStructTypeCode, 2, kI32Code, 1, kI32Code, 1)};
  EXPECT_FAILURE_WITH_MSG(final_supertype, "type 1 extends final type 0");
}

TEST_F(WasmModuleVerifyTest, SpecifiedFinalType) {
  static const uint8_t final_supertype[] = {
      SECTION(Type, ENTRY_COUNT(2),                 // --
              kWasmSubtypeFinalCode, 0,             // --
              kWasmStructTypeCode, 1, kI32Code, 1,  // --
              kWasmSubtypeCode, 1, 0,               // --
              kWasmStructTypeCode, 2, kI32Code, 1, kI32Code, 1)};
  EXPECT_FAILURE_WITH_MSG(final_supertype, "type 1 extends final type 0");
}

TEST_F(WasmModuleVerifyTest, ZeroExceptions) {
  static const uint8_t data[] = {SECTION(Tag, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(0u, result.value()->tags.size());
}

TEST_F(WasmModuleVerifyTest, OneI32Exception) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_x(kI32Code)),  // sig#0 (i32)
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(SIG_INDEX(0)))};  // except[0] (sig#0)
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(1u, result.value()->tags.size());

  const WasmTag& e0 = result.value()->tags.front();
  EXPECT_EQ(1u, e0.sig->parameter_count());
  EXPECT_EQ(kWasmI32, e0.sig->GetParam(0));
}

TEST_F(WasmModuleVerifyTest, TwoExceptions) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(2),
              SIG_ENTRY_v_x(kI32Code),              // sig#0 (i32)
              SIG_ENTRY_v_xx(kF32Code, kI64Code)),  // sig#1 (f32, i64)
      SECTION(Tag, ENTRY_COUNT(2),
              EXCEPTION_ENTRY(SIG_INDEX(1)),    // except[0] (sig#1)
              EXCEPTION_ENTRY(SIG_INDEX(0)))};  // except[1] (sig#0)
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(2u, result.value()->tags.size());
  const WasmTag& e0 = result.value()->tags.front();
  EXPECT_EQ(2u, e0.sig->parameter_count());
  EXPECT_EQ(kWasmF32, e0.sig->GetParam(0));
  EXPECT_EQ(kWasmI64, e0.sig->GetParam(1));
  const WasmTag& e1 = result.value()->tags.back();
  EXPECT_EQ(kWasmI32, e1.sig->GetParam(0));
}

TEST_F(WasmModuleVerifyTest, Exception_invalid_sig_index) {
  static const uint8_t data[] = {
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(
                  SIG_INDEX(23)))};  // except[0] (sig#23 [out-of-bounds])
  // Should fail decoding exception section.
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "no signature at index 23 (1 types)");
}

TEST_F(WasmModuleVerifyTest, Exception_invalid_sig_return) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_i_i),
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(
                  SIG_INDEX(0)))};  // except[0] (sig#0 [invalid-return-type])
  // Should fail decoding exception section.
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "tag signature 0 has non-void return");
}

TEST_F(WasmModuleVerifyTest, Exception_invalid_attribute) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_i_i),
      SECTION(Tag, ENTRY_COUNT(1), 23,
              SIG_INDEX(0))};  // except[0] (sig#0) [invalid-attribute]
  // Should fail decoding exception section.
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "exception attribute 23 not supported");
}

TEST_F(WasmModuleVerifyTest, TagSectionCorrectPlacement) {
  static const uint8_t data[] = {SECTION(Memory, ENTRY_COUNT(0)),
                                 SECTION(Tag, ENTRY_COUNT(0)),
                                 SECTION(Global, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, TagSectionAfterGlobal) {
  static const uint8_t data[] = {SECTION(Global, ENTRY_COUNT(0)),
                                 SECTION(Tag, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result,
                "The Tag section must appear before the Global section");
}

TEST_F(WasmModuleVerifyTest, TagSectionBeforeMemory) {
  static const uint8_t data[] = {SECTION(Tag, ENTRY_COUNT(0)),
                                 SECTION(Memory, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "unexpected section <Memory>");
}

TEST_F(WasmModuleVerifyTest, TagSectionAfterTableBeforeMemory) {
  static_assert(kMemorySectionCode + 1 == kGlobalSectionCode);
  static const uint8_t data[] = {SECTION(Table, ENTRY_COUNT(0)),
                                 SECTION(Tag, ENTRY_COUNT(0)),
                                 SECTION(Memory, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "unexpected section <Memory>");
}

TEST_F(WasmModuleVerifyTest, TagImport) {
  static const uint8_t data[] = {
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Import,                           // section header
              ENTRY_COUNT(1),                   // number of imports
              ADD_COUNT('m'),                   // module name
              ADD_COUNT('e', 'x'),              // tag name
              kExternalTag,                     // import kind
              EXCEPTION_ENTRY(SIG_INDEX(0)))};  // except[0] (sig#0)
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(1u, result.value()->tags.size());
  EXPECT_EQ(1u, result.value()->import_table.size());
}

TEST_F(WasmModuleVerifyTest, ExceptionExport) {
  static const uint8_t data[] = {
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(SIG_INDEX(0))),  // except[0] (sig#0)
      SECTION(Export, ENTRY_COUNT(1),          // --
              NO_NAME,                         // --
              kExternalTag,                    // --
              EXCEPTION_INDEX(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(1u, result.value()->tags.size());
  EXPECT_EQ(1u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, OneSignature) {
  {
    static const uint8_t data[] = {TYPE_SECTION_ONE_SIG_VOID_VOID};
    EXPECT_VERIFIES(data);
  }

  {
    static const uint8_t data[] = {
        SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_i_i)};
    EXPECT_VERIFIES(data);
  }
}

TEST_F(WasmModuleVerifyTest, MultipleSignatures) {
  static const uint8_t data[] = {
      SECTION(Type,                                           // --
              ENTRY_COUNT(3),                                 // --
              SIG_ENTRY_v_v,                                  // void -> void
              SIG_ENTRY_x_x(kI32Code, kF32Code),              // f32 -> i32
              SIG_ENTRY_x_xx(kI32Code, kF64Code, kF64Code)),  // f64,f64 -> i32
  };

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(3u, result.value()->types.size());
  if (result.value()->types.size() == 3) {
    EXPECT_EQ(0u, result.value()->signature(Idx{0})->return_count());
    EXPECT_EQ(1u, result.value()->signature(Idx{1})->return_count());
    EXPECT_EQ(1u, result.value()->signature(Idx{2})->return_count());

    EXPECT_EQ(0u, result.value()->signature(Idx{0})->parameter_count());
    EXPECT_EQ(1u, result.value()->signature(Idx{1})->parameter_count());
    EXPECT_EQ(2u, result.value()->signature(Idx{2})->parameter_count());
  }

  EXPECT_OFF_END_FAILURE(data, 1);
}

TEST_F(WasmModuleVerifyTest, CanonicalTypeIds) {
  static const uint8_t data[] = {
      SECTION(Type,                               // --
              ENTRY_COUNT(7),                     // --
              WASM_STRUCT_DEF(                    // Struct definition
                  FIELD_COUNT(1),                 // --
                  STRUCT_FIELD(kI32Code, true)),  // --
              SIG_ENTRY_x_x(kI32Code, kF32Code),  // f32 -> i32
              SIG_ENTRY_x_x(kI32Code, kF64Code),  // f64 -> i32
              SIG_ENTRY_x_x(kI32Code, kF32Code),  // f32 -> i32 (again)
              WASM_ARRAY_DEF(kI32Code, true),     // Array definition
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),
              WASM_ARRAY_DEF(kI16Code, true),  // Predefined i16 array
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),
              WASM_ARRAY_DEF(kI8Code, true))  // Predefined i8 array
  };

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  const WasmModule* module = result.value().get();

  EXPECT_EQ(7u, module->types.size());
  EXPECT_EQ(7u, module->isorecursive_canonical_type_ids.size());

  static constexpr uint32_t kBase = TypeCanonicalizer::kNumberOfPredefinedTypes;
  EXPECT_EQ(kBase + 0u, module->isorecursive_canonical_type_ids[0].index);
  EXPECT_EQ(kBase + 1u, module->isorecursive_canonical_type_ids[1].index);
  EXPECT_EQ(kBase + 2u, module->isorecursive_canonical_type_ids[2].index);
  EXPECT_EQ(kBase + 1u, module->isorecursive_canonical_type_ids[3].index);
  EXPECT_EQ(kBase + 3u, module->isorecursive_canonical_type_ids[4].index);

  EXPECT_EQ(TypeCanonicalizer::kPredefinedArrayI16Index,
            module->isorecursive_canonical_type_ids[5]);
  EXPECT_EQ(TypeCanonicalizer::kPredefinedArrayI8Index,
            module->isorecursive_canonical_type_ids[6]);
}

TEST_F(WasmModuleVerifyTest, DataSegmentWithImmutableImportedGlobal) {
  // Import 2 globals so that we can initialize data with a global index != 0.
  const uint8_t data[] = {
      SECTION(Import,           // section header
              ENTRY_COUNT(2),   // number of imports
              ADD_COUNT('m'),   // module name
              ADD_COUNT('f'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              0,                // mutability
              ADD_COUNT('n'),   // module name
              ADD_COUNT('g'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              0),               // mutability
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_GLOBAL(1),  // dest addr
              U32V_1(3),                 // source size
              'a', 'b', 'c')             // data bytes
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, DataSegmentWithMutableImportedGlobal) {
  // Only an immutable global can be used as an init_expr.
  const uint8_t data[] = {
      SECTION(Import,           // section header
              ENTRY_COUNT(1),   // number of imports
              ADD_COUNT('m'),   // module name
              ADD_COUNT('f'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              1),               // mutability
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_GLOBAL(0),  // dest addr
              U32V_1(3),                 // source size
              'a', 'b', 'c')             // data bytes
  };
  EXPECT_FAILURE(data);
}
TEST_F(WasmModuleVerifyTest, DataSegmentWithImmutableGlobal) {
  // An immutable global can be used in an init_expr.
  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Global, ENTRY_COUNT(1),
              kI32Code,                         // local type
              0,                                // immutable
              WASM_INIT_EXPR_I32V_3(0x9BBAA)),  // init
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_GLOBAL(0),  // dest addr
              U32V_1(3),                 // source size
              'a', 'b', 'c')             // data bytes
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, OneDataSegment) {
  const uint8_t kDataSegmentSourceOffset = 24;
  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x9BBAA),  // dest addr
              U32V_1(3),                       // source size
              'a', 'b', 'c')                   // data bytes
  };

  {
    EXPECT_VERIFIES(data);
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(0u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(1u, result.value()->data_segments.size());

    const WasmDataSegment* segment = &result.value()->data_segments.back();

    EXPECT_EQ(kDataSegmentSourceOffset, segment->source.offset());
    EXPECT_EQ(3u, segment->source.length());
  }

  EXPECT_OFF_END_FAILURE(data, 14);
}

TEST_F(WasmModuleVerifyTest, TwoDataSegments) {
  const uint8_t kDataSegment0SourceOffset = 24;
  const uint8_t kDataSegment1SourceOffset = kDataSegment0SourceOffset + 11;

  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data,
              ENTRY_COUNT(2),  // segment count
              LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x7FFEE),  // #0: dest addr
              U32V_1(4),                       // source size
              1, 2, 3, 4,                      // data bytes
              LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x6DDCC),  // #1: dest addr
              U32V_1(10),                      // source size
              1, 2, 3, 4, 5, 6, 7, 8, 9, 10)   // data bytes
  };

  {
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(0u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(2u, result.value()->data_segments.size());

    const WasmDataSegment* s0 = &result.value()->data_segments[0];
    const WasmDataSegment* s1 = &result.value()->data_segments[1];

    EXPECT_EQ(kDataSegment0SourceOffset, s0->source.offset());
    EXPECT_EQ(4u, s0->source.length());

    EXPECT_EQ(kDataSegment1SourceOffset, s1->source.offset());
    EXPECT_EQ(10u, s1->source.length());
  }

  EXPECT_OFF_END_FAILURE(data, 14);
}

TEST_F(WasmModuleVerifyTest, DataWithoutMemory) {
  const uint8_t data[] = {
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x9BBAA),  // dest addr
              U32V_1(3),                       // source size
              'a', 'b', 'c')                   // data bytes
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, MaxMaximumMemorySize) {
  {
    const uint8_t data[] = {
        SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 0, U32V_3(65536))};
    EXPECT_VERIFIES(data);
  }
  {
    const uint8_t data[] = {
        SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 0, U32V_3(65537))};
    EXPECT_FAILURE(data);
  }
}

TEST_F(WasmModuleVerifyTest, InvalidMemoryLimits) {
  {
    const uint8_t kInvalidLimits = 0x15;
    const uint8_t data[] = {
        SECTION(Memory, ENTRY_COUNT(1), kInvalidLimits, 0, 10)};
    EXPECT_FAILURE_WITH_MSG(data, "invalid memory limits flags 0x15");
  }
}

TEST_F(WasmModuleVerifyTest, DataSegment_wrong_init_type) {
  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_F64(9.9),  // dest addr
              U32V_1(3),                // source size
              'a', 'b', 'c')            // data bytes
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, DataSegmentEndOverflow) {
  const uint8_t data[] = {
      SECTION(Memory,  // memory section
              ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data,                      // data section
              ENTRY_COUNT(1),            // one entry
              LINEAR_MEMORY_INDEX_0,     // mem index
              WASM_INIT_EXPR_I32V_1(0),  // offset
              U32V_5(0xFFFFFFFF))        // size
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, OneIndirectFunction) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  if (result.ok()) {
    EXPECT_EQ(1u, result.value()->types.size());
    EXPECT_EQ(1u, result.value()->functions.size());
    EXPECT_EQ(1u, result.value()->tables.size());
    EXPECT_EQ(1u, result.value()->tables[0].initial_size);
  }
}

TEST_F(WasmModuleVerifyTest, ElementSectionWithInternalTable) {
  static const uint8_t data[] = {
      // table ---------------------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // elements ------------------------------------------------------------
      SECTION(Element, ENTRY_COUNT(0))};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionWithImportedTable) {
  static const uint8_t data[] = {
      // imports -------------------------------------------------------------
      SECTION(Import, ENTRY_COUNT(1),
              ADD_COUNT('m'),  // module name
              ADD_COUNT('t'),  // table name
              kExternalTable,  // import kind
              kFuncRefCode,    // elem_type
              kNoMaximum,      // maximum
              1),              // initial size
      // elements ------------------------------------------------------------
      SECTION(Element, ENTRY_COUNT(0))};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionWithoutTable) {
  // Test that an element section without a table causes a validation error.
  static const uint8_t data[] = {
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),  // entry count
              0,               // table index
              0,               // offset
              0)               // number of elements
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, Regression_735887) {
  // Test with an invalid function index in the element section.
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),  //
```