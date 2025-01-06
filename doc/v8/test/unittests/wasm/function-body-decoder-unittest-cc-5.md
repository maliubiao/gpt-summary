Response:
The user wants a summary of the provided C++ code snippet.
The code is part of the V8 JavaScript engine and resides in the `v8/test/unittests/wasm` directory, specifically in a file named `function-body-decoder-unittest.cc`.

This suggests the code is a unit test for the Wasm (WebAssembly) function body decoder. Unit tests verify the functionality of individual components in isolation.

The code contains numerous `TEST_F` macros, which are part of the Google Test framework and indicate individual test cases within the `FunctionBodyDecoderTest` class.

Each test case seems to focus on validating the behavior of the Wasm function body decoder when encountering different Wasm instructions or scenarios.

Keywords like `ExpectValidates`, `ExpectFailure`, `WASM_ARRAY_NEW`, `WASM_ARRAY_GET`, `WASM_STRUCT_NEW`, `WASM_REF_TEST`, `WASM_BR_ON_CAST` suggest the tests cover:
- Correct decoding and validation of various Wasm instructions.
- Handling of type checking and potential errors during decoding.
- Specific Wasm features like arrays, structs, references, and type casting.

The user also asks about the file extension `.tq`. Since the provided file ends in `.cc`, it is a C++ source file, not a Torque file.

Regarding the relationship with JavaScript: WebAssembly is designed to be a compilation target for languages like C, C++, and Rust, but it runs within the same environment as JavaScript in web browsers and Node.js. V8 is the JavaScript engine used in Chrome and Node.js, so these tests are indirectly related to ensuring Wasm interoperability with JavaScript.

The user requests an example in JavaScript. Since the tests are focused on the internal workings of the Wasm decoder, a direct JavaScript equivalent is not straightforward. However, JavaScript can *execute* the Wasm code that these tests are validating.

The request also mentions code logic inference, assuming inputs and outputs. The tests themselves demonstrate this. For instance, `ExpectFailure` tests provide a sequence of Wasm bytes (input) and assert that the decoder will detect an error with a specific message (output).

Common programming errors are also mentioned. The `ExpectFailure` tests often highlight scenarios that would lead to invalid Wasm code, such as type mismatches or accessing array elements with the wrong index type.

Finally, this is part 6 of 7. This implies the full set of files likely covers a broader range of Wasm decoding functionalities.

**Plan for the response:**

1. State that the file is a C++ unit test for the Wasm function body decoder in V8.
2. List the general functionalities covered by the tests, drawing from the keywords and test names.
3. Clarify that it's a C++ file, not a Torque file.
4. Explain the indirect relationship with JavaScript (JavaScript can run the Wasm code being tested).
5. Provide a simplified JavaScript example demonstrating how Wasm code (which these tests validate the decoding of) can be used in a JavaScript environment.
6. Give an example of a code logic inference scenario with an input (Wasm bytes) and expected output (error message).
7. Provide an example of a common programming error in Wasm that the tests cover.
8. Summarize the overall function of this specific part, considering it's part 6 of 7.
这是 v8 源代码 `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 的一部分，它是一个 **C++ 单元测试文件**，专门用于测试 **WebAssembly (Wasm) 函数体解码器 (`FunctionBodyDecoder`) 的功能**。

具体来说，这部分代码主要测试了 `FunctionBodyDecoder` 在处理以下 WebAssembly 指令时的行为，包括 **成功验证 (ExpectValidates)** 和 **预期失败 (ExpectFailure)** 的情况：

- **数组指令 (`array.*`)**:
    - `array.new`: 创建新的数组。
    - `array.new_fixed`: 创建具有固定元素的数组。
    - `array.new_default`: 创建具有默认值的数组。
    - `array.get`: 获取数组元素。
    - `array.get_s`/`array.get_u`: 获取带符号/无符号扩展的打包数组元素。
    - `array.set`: 设置数组元素。
    - `array.len`: 获取数组长度。
- **结构体指令 (`struct.*`)**:
    - `struct.new`: 创建新的结构体。
    - `struct.get`: 获取结构体字段。
    - `struct.get_s`/`struct.get_u`: 获取带符号/无符号扩展的打包结构体字段。
    - `struct.set`: 设置结构体字段。
- **引用类型相关指令 (`ref.*`)**:
    - `ref.test`: 测试引用是否属于特定类型。
    - `ref.cast`: 将引用转换为特定类型。
    - `ref.test_null`: 测试引用是否为 null 并属于特定类型。
    - `ref.cast_null`: 将引用转换为特定类型，如果为 null 则返回 null。
- **类型转换指令 (`br_on_cast`, `br_on_cast_fail`)**:
    - `br_on_cast`: 如果引用可以转换为指定类型，则跳转到目标分支。
    - `br_on_cast_fail`: 如果引用不能转换为指定类型，则跳转到目标分支。
    - `br_on_cast_null`: 类似 `br_on_cast`，但针对可空引用。
    - `br_on_cast_fail_null`: 类似 `br_on_cast_fail`，但针对可空引用。
- **类型转换指令 (`any.convert_extern`, `extern.convert_any`)**:
    - `any.convert_extern`: 将 `externref` 转换为 `anyref`。
    - `extern.convert_any`: 将 `anyref` 转换为 `externref`。
- **其他指令**:
    - `local.tee`: 设置局部变量的值，并将该值推送到栈上。
    - `drop`: 从栈上移除一个值。
    - `br_on_non_null`: 如果栈顶值不为 null，则跳转。

**如果 `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码**。 但实际上，从您提供的目录和文件名来看，它以 `.cc` 结尾，因此是 **C++ 源代码**。 Torque 文件通常用于实现 V8 的内置函数。

**与 JavaScript 的功能关系：**

WebAssembly 旨在与 JavaScript 并行运行在 Web 浏览器和其他环境中。  `FunctionBodyDecoder` 的作用是将 WebAssembly 的字节码指令解码成 V8 能够理解和执行的内部表示。 因此，这个单元测试直接关系到 **V8 如何正确地加载和执行 WebAssembly 代码**。

例如，当 JavaScript 代码加载一个 WebAssembly 模块并调用其中的函数时，V8 的 Wasm 引擎会使用 `FunctionBodyDecoder` 来处理该函数的字节码。

**JavaScript 示例：**

```javascript
// 假设有一个简单的 WebAssembly 模块 (module.wasm) 定义了一个接受两个 i32 参数并返回它们的和的函数。

async function loadAndRunWasm() {
  const response = await fetch('module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5, 10); // 调用 Wasm 模块中的 'add' 函数
  console.log(result); // 输出 15
}

loadAndRunWasm();
```

在这个例子中，`WebAssembly.compile(buffer)` 阶段，V8 内部就会使用类似于 `FunctionBodyDecoder` 的组件来解析 `module.wasm` 中的函数定义。  `function-body-decoder-unittest.cc` 中的测试确保了这个解码过程的正确性。

**代码逻辑推理：**

**假设输入：** 以下 WebAssembly 字节码序列，用于创建一个 `funcref` 类型的数组，长度为 10，然后丢弃结果。

```
{WASM_ARRAY_NEW(struct_type_index, WASM_REF_NULL(kFuncRefCode), WASM_I32V(10)), kExprDrop}
```

在这个假设的上下文中，`struct_type_index` 代表数组的类型索引，`WASM_REF_NULL(kFuncRefCode)` 代表用于初始化的 null `funcref` 值，`WASM_I32V(10)` 代表数组的长度。

**预期输出：**  根据代码中的 `ExpectFailure` 测试，如果 `struct_type_index` 实际上不是数组类型索引，解码器会失败并报告错误信息，例如："invalid array index: 1"。  这是因为 `WASM_ARRAY_NEW` 期望第一个参数是数组类型的索引。

**用户常见的编程错误：**

一个常见的编程错误是在使用数组时 **类型不匹配**。 例如，尝试将一个 `i64` 类型的值赋值给一个预期 `i32` 类型的数组元素。

**C++ 示例 (模拟 Wasm 操作):**

```c++
// 假设有一个 int32 类型的数组
std::vector<int32_t> myArray(10);

// 错误地尝试赋值一个 int64 类型的值
int64_t bigValue = 1234567890123;
// myArray[0] = bigValue; // 编译器会警告或截断

// 在 WebAssembly 中，FunctionBodyDecoder 会在解码阶段捕获这种错误，
// 如测试用例所示：
ExpectFailure(sigs.v_v(),
              {WASM_ARRAY_NEW(array_type_index, WASM_I64V(0), WASM_I32V(5)), kExprDrop},
              kAppendEnd,
              "array.new[0] expected type i32, found i64.const of type i64");
```

**第 6 部分的功能归纳：**

作为第 6 部分，这部分单元测试主要集中在 **验证 `FunctionBodyDecoder` 正确解码和校验 WebAssembly 中关于复杂数据类型（如数组和结构体）的操作指令以及引用类型相关的操作指令和类型转换指令**。它详细测试了各种可能的正确和错误用法，包括类型匹配、索引有效性、可变性以及不同引用类型之间的转换规则。 这有助于确保 V8 在执行涉及这些特性的 WebAssembly 代码时的正确性和安全性。

Prompt: 
```
这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/function-body-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
xpected type i32, found i64.const of type i64");
  // Wrong type index.
  ExpectFailure(sigs.v_v(),
                {WASM_ARRAY_NEW(struct_type_index, WASM_REF_NULL(kFuncRefCode),
                                WASM_I32V(10)),
                 kExprDrop},
                kAppendEnd, "invalid array index: 1");

  /** array.get **/
  ExpectValidates(&sig_c_r, {WASM_ARRAY_GET(array_type_index, WASM_LOCAL_GET(0),
                                            WASM_I32V(5))});
  // With non-nullable array type.
  ExpectValidates(
      &sig_c_r,
      {WASM_ARRAY_GET(array_type_index, WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)),
                      WASM_I32V(5))});
  // Wrongly typed index.
  ExpectFailure(
      &sig_v_r,
      {WASM_ARRAY_GET(array_type_index, WASM_LOCAL_GET(0), WASM_I64V(5)),
       kExprDrop},
      kAppendEnd,
      "array.get[1] expected type i32, found i64.const of type i64");
  // Mistyped expected type.
  ExpectFailure(
      &sig_f_r,
      {WASM_ARRAY_GET(array_type_index, WASM_LOCAL_GET(0), WASM_I32V(5))},
      kAppendEnd, "type error in fallthru[0] (expected f32, got funcref)");

  // array.get_s/u fail.
  ExpectFailure(
      &sig_c_r,
      {WASM_ARRAY_GET_S(array_type_index, WASM_LOCAL_GET(0), WASM_I32V(5))},
      kAppendEnd,
      "array.get_s: Immediate array type 0 has non-packed type funcref. Use "
      "array.get instead.");
  ExpectFailure(
      &sig_c_r,
      {WASM_ARRAY_GET_U(array_type_index, WASM_LOCAL_GET(0), WASM_I32V(5))},
      kAppendEnd,
      "array.get_u: Immediate array type 0 has non-packed type funcref. Use "
      "array.get instead.");

  /** array.set **/
  ExpectValidates(&sig_v_r,
                  {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(0),
                                  WASM_I32V(42), WASM_REF_NULL(kFuncRefCode))});
  // With non-nullable array type.
  ExpectValidates(
      &sig_v_cr,
      {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(1), WASM_I32V(42),
                      WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)))});
  // Non-array type index.
  ExpectFailure(&sig_v_cr,
                {WASM_ARRAY_SET(struct_type_index, WASM_LOCAL_GET(1),
                                WASM_I32V(42), WASM_LOCAL_GET(0))},
                kAppendEnd, "invalid array index: 1");
  // Wrongly typed index.
  ExpectFailure(&sig_v_cr,
                {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(1),
                                WASM_I64V(42), WASM_LOCAL_GET(0))},
                kAppendEnd,
                "array.set[1] expected type i32, found i64.const of type i64");
  // Wrongly typed value.
  ExpectFailure(
      &sig_v_cr,
      {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(1), WASM_I32V(42),
                      WASM_I64V(0))},
      kAppendEnd,
      "array.set[2] expected type funcref, found i64.const of type i64");

  /** array.len **/
  // Works both with conrete array types and arrayref.
  ExpectValidates(&sig_i_r, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))});
  ExpectValidates(&sig_i_a, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))});
  // Wrong return type.
  ExpectFailure(&sig_f_r, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))}, kAppendEnd,
                "type error in fallthru[0] (expected f32, got i32)");
  // Non-array argument.
  ExpectFailure(
      &sig_i_s, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))}, kAppendEnd,
      "array.len[0] expected type arrayref, found local.get of type (ref 1)");

  // Immutable array.
  // Allocating and reading is OK:
  ExpectValidates(
      sigs.i_v(),
      {WASM_ARRAY_GET(
          immutable_array_type_index,
          WASM_ARRAY_NEW_FIXED(immutable_array_type_index, 1, WASM_I32V(42)),
          WASM_I32V(0))});
  // Writing fails:
  ExpectFailure(&sig_v_r2,
                {WASM_ARRAY_SET(immutable_array_type_index, WASM_LOCAL_GET(0),
                                WASM_I32V(0), WASM_I32V(42))},
                kAppendEnd, "array.set: immediate array type 2 is immutable");
}

TEST_F(FunctionBodyDecoderTest, PackedFields) {
  ModuleTypeIndex array_type_index = builder.AddArray(kWasmI8, true);
  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI16, true)});
  uint8_t field_index = 0;

  // *.new with packed fields works.
  ExpectValidates(sigs.v_v(),
                  {WASM_ARRAY_NEW(array_type_index, WASM_I32V(0), WASM_I32V(5)),
                   kExprDrop});
  ExpectValidates(
      sigs.v_v(),
      {WASM_STRUCT_NEW(struct_type_index, WASM_I32V(42)), kExprDrop});
  // It can't unpack types other that i32.
  ExpectFailure(
      sigs.v_v(),
      {WASM_ARRAY_NEW(array_type_index, WASM_I64V(0), WASM_I32V(5)), kExprDrop},
      kAppendEnd,
      "array.new[0] expected type i32, found i64.const of type i64");
  ExpectFailure(sigs.v_v(),
                {WASM_STRUCT_NEW(struct_type_index, WASM_I64V(42)), kExprDrop},
                kAppendEnd,
                "struct.new[0] expected type i32, found i64.const of type i64");

  // *.set with packed fields works.
  ExpectValidates(sigs.v_v(), {WASM_ARRAY_SET(array_type_index,
                                              WASM_REF_NULL(array_type_index),
                                              WASM_I32V(0), WASM_I32V(5))});
  ExpectValidates(sigs.v_v(), {WASM_STRUCT_SET(struct_type_index, field_index,
                                               WASM_REF_NULL(struct_type_index),
                                               WASM_I32V(42))});
  // It can't unpack into types other that i32.
  ExpectFailure(
      sigs.v_v(),
      {WASM_ARRAY_SET(array_type_index, WASM_REF_NULL(array_type_index),
                      WASM_I32V(0), WASM_I64V(5))},
      kAppendEnd,
      "array.set[2] expected type i32, found i64.const of type i64");
  ExpectFailure(
      sigs.v_v(),
      {WASM_STRUCT_NEW(struct_type_index, field_index,
                       WASM_REF_NULL(struct_type_index), WASM_I64V(42))},
      kAppendEnd,
      "struct.new[0] expected type i32, found i64.const of type i64");

  // *.get_s/u works.
  ExpectValidates(sigs.i_v(), {WASM_ARRAY_GET_S(array_type_index,
                                                WASM_REF_NULL(array_type_index),
                                                WASM_I32V(0))});
  ExpectValidates(sigs.i_v(), {WASM_ARRAY_GET_U(array_type_index,
                                                WASM_REF_NULL(array_type_index),
                                                WASM_I32V(0))});
  ExpectValidates(sigs.i_v(),
                  {WASM_STRUCT_GET_S(struct_type_index, field_index,
                                     WASM_REF_NULL(struct_type_index))});
  ExpectValidates(sigs.i_v(),
                  {WASM_STRUCT_GET_U(struct_type_index, field_index,
                                     WASM_REF_NULL(struct_type_index))});

  // *.get fails.
  ExpectFailure(sigs.i_v(),
                {WASM_ARRAY_GET(array_type_index,
                                WASM_REF_NULL(array_type_index), WASM_I32V(0))},
                kAppendEnd,
                "array.get: Immediate array type 0 has packed type i8. Use "
                "array.get_s or array.get_u instead.");
  ExpectFailure(sigs.i_v(),
                {WASM_STRUCT_GET(struct_type_index, field_index,
                                 WASM_REF_NULL(struct_type_index))},
                kAppendEnd,
                "struct.get: Immediate field 0 of type 1 has packed type i16. "
                "Use struct.get_s or struct.get_u instead.");
}

TEST_F(FunctionBodyDecoderTest, PackedTypesAsLocals) {
  AddLocals(kWasmI8, 1);
  ExpectFailure(sigs.v_v(), {}, kAppendEnd, "invalid value type");
}

TEST_F(FunctionBodyDecoderTest, RefTestCast) {
  WASM_FEATURE_SCOPE(exnref);

  HeapType array_heap = HeapType(builder.AddArray(kWasmI8, true));
  HeapType super_struct_heap = HeapType(builder.AddStruct({F(kWasmI16, true)}));

  HeapType sub_struct_heap =
      HeapType(builder.AddStruct({F(kWasmI16, true), F(kWasmI32, false)}));

  HeapType func_heap_1 = HeapType(builder.AddSignature(sigs.i_i()));
  HeapType func_heap_2 = HeapType(builder.AddSignature(sigs.i_v()));

  std::tuple<HeapType, HeapType, bool> tests[] = {
      std::make_tuple(HeapType(HeapType::kArray), array_heap, true),
      std::make_tuple(HeapType(HeapType::kStruct), super_struct_heap, true),
      std::make_tuple(HeapType(HeapType::kFunc), func_heap_1, true),
      std::make_tuple(func_heap_1, func_heap_1, true),
      std::make_tuple(func_heap_1, func_heap_2, true),
      std::make_tuple(super_struct_heap, sub_struct_heap, true),
      std::make_tuple(array_heap, sub_struct_heap, true),
      std::make_tuple(super_struct_heap, func_heap_1, false),
      std::make_tuple(HeapType(HeapType::kEq), super_struct_heap, true),
      std::make_tuple(HeapType(HeapType::kExtern), func_heap_1, false),
      std::make_tuple(HeapType(HeapType::kAny), array_heap, true),
      std::make_tuple(HeapType(HeapType::kI31), array_heap, true),
      std::make_tuple(HeapType(HeapType::kNone), array_heap, true),
      std::make_tuple(HeapType(HeapType::kNone), func_heap_1, false),
      std::make_tuple(HeapType(HeapType::kExn), HeapType(HeapType::kExtern),
                      false),
      std::make_tuple(HeapType(HeapType::kExn), HeapType(HeapType::kAny),
                      false),
  };

  for (auto [from_heap, to_heap, should_pass] : tests) {
    SCOPED_TRACE("from_heap = " + from_heap.name() +
                 ", to_heap = " + to_heap.name());

    ValueType test_reps[] = {kWasmI32, ValueType::RefNull(from_heap)};
    FunctionSig test_sig(1, 1, test_reps);

    ValueType cast_reps[] = {ValueType::RefNull(to_heap),
                             ValueType::RefNull(from_heap)};
    FunctionSig cast_sig(1, 1, cast_reps);

    if (should_pass) {
      ExpectValidates(&test_sig, {WASM_REF_TEST(WASM_LOCAL_GET(0),
                                                WASM_HEAP_TYPE(to_heap))});
      ExpectValidates(&cast_sig, {WASM_REF_CAST(WASM_LOCAL_GET(0),
                                                WASM_HEAP_TYPE(to_heap))});
      ExpectValidates(&test_sig, {WASM_REF_TEST_NULL(WASM_LOCAL_GET(0),
                                                     WASM_HEAP_TYPE(to_heap))});
      ExpectValidates(&cast_sig, {WASM_REF_CAST_NULL(WASM_LOCAL_GET(0),
                                                     WASM_HEAP_TYPE(to_heap))});
    } else {
      std::string error_message =
          "local.get of type " + cast_reps[1].name() +
          " has to be in the same reference type hierarchy as (ref " +
          to_heap.name() + ")";
      ExpectFailure(&test_sig,
                    {WASM_REF_TEST(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
                    kAppendEnd,
                    ("Invalid types for ref.test: " + error_message).c_str());
      ExpectFailure(&cast_sig,
                    {WASM_REF_CAST(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
                    kAppendEnd,
                    ("Invalid types for ref.cast: " + error_message).c_str());
      ExpectFailure(
          &test_sig,
          {WASM_REF_TEST_NULL(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
          kAppendEnd,
          ("Invalid types for ref.test null: " + error_message).c_str());
      ExpectFailure(
          &cast_sig,
          {WASM_REF_CAST_NULL(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
          kAppendEnd,
          ("Invalid types for ref.cast null: " + error_message).c_str());
    }
  }

  // Trivial type error.
  ExpectFailure(
      sigs.v_v(),
      {WASM_REF_TEST(WASM_I32V(1), array_heap.representation()), kExprDrop},
      kAppendEnd,
      "Invalid types for ref.test: i32.const of type i32 has to be "
      "in the same reference type hierarchy as (ref 0)");
  ExpectFailure(
      sigs.v_v(),
      {WASM_REF_CAST(WASM_I32V(1), array_heap.representation()), kExprDrop},
      kAppendEnd,
      "Invalid types for ref.cast: i32.const of type i32 has to be "
      "in the same reference type hierarchy as (ref 0)");
}

TEST_F(FunctionBodyDecoderTest, BrOnCastOrCastFail) {
  ModuleTypeIndex super_struct = builder.AddStruct({F(kWasmI16, true)});
  ModuleTypeIndex sub_struct =
      builder.AddStruct({F(kWasmI16, true), F(kWasmI32, false)}, super_struct);

  ValueType supertype = ValueType::RefNull(super_struct);
  ValueType subtype = ValueType::RefNull(sub_struct);

  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, subtype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST(0, super_struct, sub_struct), WASM_GC_OP(kExprRefCast),
       ToByte(sub_struct)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, subtype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST(0, super_struct, sub_struct), WASM_GC_OP(kExprRefCast),
       ToByte(sub_struct)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, supertype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, supertype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct)});

  // Wrong branch type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {}, {supertype}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, super_struct, sub_struct),
       WASM_UNREACHABLE},
      kAppendEnd, "br_on_cast must target a branch of arity at least 1");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct)},
      kAppendEnd,
      "type error in branch[0] (expected (ref null 1), got (ref null 0))");
  ExpectFailure(FunctionSig::Build(this->zone(), {subtype}, {supertype}),
                {WASM_I32V(42), WASM_LOCAL_GET(0),
                 WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct)},
                kAppendEnd,
                "type error in branch[0] (expected (ref null 1), got (ref 0))");

  // Wrong fallthrough type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {supertype}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, super_struct, sub_struct)},
      kAppendEnd,
      "type error in fallthru[0] (expected (ref null 1), got (ref null 0))");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {supertype}),
      {WASM_BLOCK_I(WASM_LOCAL_GET(0),
                    WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct))},
      kAppendEnd, "type error in branch[0] (expected i32, got (ref null 0))");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {supertype}),
      {WASM_BLOCK_I(WASM_LOCAL_GET(0),
                    WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct))},
      kAppendEnd, "type error in branch[0] (expected i32, got (ref 0))");

  // Wrong argument type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, super_struct, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "br_on_cast[0] expected type (ref null 0), found local.get of type "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_NULL(0, super_struct, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "br_on_cast[0] expected type (ref null 0), found local.get of type "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct)},
      kAppendEnd,
      "br_on_cast_fail[0] expected type (ref null 0), found local.get of type "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct)},
      kAppendEnd,
      "br_on_cast_fail[0] expected type (ref null 0), found local.get of "
      "type externref");

  // Wrong immediate type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kExternRefCode, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast: (ref 1) is not a subtype of externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_NULL(0, kExternRefCode, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast: (ref null 1) is not a subtype of "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, kExternRefCode, sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast_fail: (ref 1) is not a subtype of "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL_NULL(0, kExternRefCode, sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast_fail: (ref null 1) is not a subtype "
      "of externref");
}

TEST_F(FunctionBodyDecoderTest, BrOnAbstractType) {
  ValueType kNonNullableFunc = ValueType::Ref(HeapType::kFunc);

  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmStructRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kStructRefCode),
       WASM_GC_OP(kExprRefCast), kStructRefCode});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kStructRefCode)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI31Ref}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kI31RefCode),
       WASM_GC_OP(kExprRefCast), kI31RefCode});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kI31RefCode)});

  // Wrong branch type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kStructRefCode),
       WASM_UNREACHABLE},
      kAppendEnd, "br_on_cast must target a branch of arity at least 1");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kNonNullableFunc}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kStructRefCode)},
      kAppendEnd, "type error in branch[0] (expected (ref func), got anyref)");

  // Wrong fallthrough type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmStructRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kStructRefCode)},
      kAppendEnd, "type error in fallthru[0] (expected structref, got anyref)");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_BLOCK_I(WASM_LOCAL_GET(0),
                    WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kStructRefCode))},
      kAppendEnd, "type error in branch[0] (expected i32, got anyref)");

  // Argument type error.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmI31Ref}, {kWasmI32}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kI31RefCode),
       WASM_GC_OP(kExprRefCast), kI31RefCode},
      kAppendEnd,
      "br_on_cast[0] expected type anyref, found local.get of type i32");
}

TEST_F(FunctionBodyDecoderTest, BrWithBottom) {
  // Merging an unsatisfiable non-nullable (ref none) into a target that
  // expects a non-null struct is OK.
  ExpectValidates(
      FunctionSig::Build(this->zone(), {ValueType::Ref(HeapType::kStruct)},
                         {ValueType::Ref(HeapType::kStruct)}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoneCode)),
       WASM_LOCAL_GET(0)});
  // Merging the same value into a target that expects a value outside
  // the "anyref" hierarchy is invalid...
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmFuncRef}, {kWasmFuncRef}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoneCode)),
       WASM_LOCAL_GET(0)},
      kAppendEnd, "type error in branch[0] (expected funcref, got (ref none))");
  // ...because it would have to be a (ref nofunc) in that case.
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmFuncRef}, {kWasmFuncRef}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoFuncCode)),
       WASM_LOCAL_GET(0)});
  // (ref nofunc) in turn doesn't match anyref.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoFuncCode)),
       WASM_LOCAL_GET(0)},
      kAppendEnd,
      "type error in branch[0] (expected anyref, got (ref nofunc))");
}

TEST_F(FunctionBodyDecoderTest, LocalTeeTyping) {
  ModuleTypeIndex array_type = builder.AddArray(kWasmI8, true);

  ValueType types[] = {ValueType::Ref(array_type)};
  FunctionSig sig(1, 0, types);

  AddLocals(ValueType::RefNull(array_type), 1);

  ExpectFailure(
      &sig,
      {WASM_LOCAL_TEE(0, WASM_ARRAY_NEW_DEFAULT(array_type, WASM_I32V(5)))},
      kAppendEnd, "expected (ref 0), got (ref null 0)");
}

TEST_F(FunctionBodyDecoderTest, MergeNullableTypes) {
  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI32, true)});
  ValueType struct_type = refNull(struct_type_index);
  FunctionSig loop_sig(0, 1, &struct_type);
  ModuleTypeIndex loop_sig_index = builder.AddSignature(&loop_sig);
  // Verifies that when a loop consuming a nullable type is entered with a
  // statically known non-null value on the stack, its {start_merge_} can
  // consume null values later.
  // Regression test for crbug.com/1234453.
  ExpectValidates(sigs.v_v(),
                  {WASM_GC_OP(kExprStructNewDefault), ToByte(struct_type_index),
                   WASM_LOOP_X(loop_sig_index, kExprDrop, kExprRefNull,
                               ToByte(struct_type_index), kExprBr, 0)});
}

// This tests that num_locals_ in decoder remains consistent, even if we fail
// mid-DecodeLocals().
TEST_F(FunctionBodyDecoderTest, Regress_1154439) {
  AddLocals(kWasmI32, 1);
  AddLocals(kWasmI64, 1000000);
  ExpectFailure(sigs.v_v(), {}, kAppendEnd, "local count too large");
}

TEST_F(FunctionBodyDecoderTest, DropOnEmptyStack) {
  // Valid code:
  ExpectValidates(sigs.v_v(), {kExprI32Const, 1, kExprDrop}, kAppendEnd);
  // Invalid code (dropping from empty stack):
  ExpectFailure(sigs.v_v(), {kExprDrop}, kAppendEnd,
                "not enough arguments on the stack for drop");
  // Valid code (dropping from empty stack in unreachable code):
  ExpectValidates(sigs.v_v(), {kExprUnreachable, kExprDrop}, kAppendEnd);
}

TEST_F(FunctionBodyDecoderTest, AnyConvertExtern) {
  ExpectValidates(FunctionSig::Build(zone(), {kWasmAnyRef}, {}),
                  {WASM_GC_ANY_CONVERT_EXTERN(WASM_REF_NULL(kNoExternCode))});
  ExpectValidates(FunctionSig::Build(zone(), {kWasmAnyRef}, {kWasmExternRef}),
                  {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))});
  ExpectValidates(
      FunctionSig::Build(zone(), {kWasmAnyRef}, {kWasmExternRef.AsNonNull()}),
      {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))});
  ExpectFailure(FunctionSig::Build(zone(), {kWasmAnyRef}, {}),
                {WASM_GC_ANY_CONVERT_EXTERN(kExprNop)}, kAppendEnd,
                "not enough arguments on the stack for any.convert_extern "
                "(need 1, got 0)");
  ExpectFailure(
      FunctionSig::Build(zone(), {kWasmAnyRef.AsNonNull()}, {kWasmExternRef}),
      {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))}, kAppendEnd,
      "type error in fallthru[0] (expected (ref any), got anyref)");
  ExpectFailure(FunctionSig::Build(zone(), {kWasmAnyRef}, {kWasmAnyRef}),
                {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))}, kAppendEnd,
                "any.convert_extern[0] expected type externref, found "
                "local.get of type anyref");
}

TEST_F(FunctionBodyDecoderTest, ExternConvertAny) {
  ExpectValidates(FunctionSig::Build(zone(), {kWasmExternRef}, {}),
                  {WASM_GC_EXTERN_CONVERT_ANY(WASM_REF_NULL(kNoneCode))});
  ExpectValidates(FunctionSig::Build(zone(), {kWasmExternRef}, {kWasmAnyRef}),
                  {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))});
  ExpectValidates(
      FunctionSig::Build(zone(), {kWasmExternRef}, {kWasmAnyRef.AsNonNull()}),
      {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))});
  ExpectFailure(FunctionSig::Build(zone(), {kWasmExternRef}, {}),
                {WASM_GC_EXTERN_CONVERT_ANY(kExprNop)}, kAppendEnd,
                "not enough arguments on the stack for extern.convert_any "
                "(need 1, got 0)");
  ExpectFailure(
      FunctionSig::Build(zone(), {kWasmExternRef.AsNonNull()}, {kWasmAnyRef}),
      {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))}, kAppendEnd,
      "type error in fallthru[0] (expected (ref extern), got externref)");
  ExpectFailure(FunctionSig::Build(zone(), {kWasmExternRef}, {kWasmExternRef}),
                {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))}, kAppendEnd,
                "extern.convert_any[0] expected type anyref, found "
                "local.get of type externref");
}

class BranchTableIteratorTest : public TestWithZone {
 public:
  BranchTableIteratorTest() : TestWithZone() {}
  void CheckBrTableSize(const uint8_t* start, const uint8_t* end) {
    Decoder decoder(start, end);
    BranchTableImmediate operand(&decoder, start + 1, Decoder::kFullValidation);
    BranchTableIterator<Decoder::FullValidationTag> iterator(&decoder, operand);
    EXPECT_EQ(end - start - 1u, iterator.length());
    EXPECT_OK(decoder);
  }
  void CheckBrTableError(const uint8_t* start, const uint8_t* end) {
    Decoder decoder(start, end);
    BranchTableImmediate operand(&decoder, start + 1, Decoder::kFullValidation);
    BranchTableIterator<Decoder::FullValidationTag> iterator(&decoder, operand);
    iterator.length();
    EXPECT_FALSE(decoder.ok());
  }
};

#define CHECK_BR_TABLE_LENGTH(...)                       \
  {                                                      \
    static uint8_t code[] = {kExprBrTable, __VA_ARGS__}; \
    CheckBrTableSize(code, code + sizeof(code));         \
  }

#define CHECK_BR_TABLE_ERROR(...)                        \
  {                                                      \
    static uint8_t code[] = {kExprBrTable, __VA_ARGS__}; \
    CheckBrTableError(code, code + sizeof(code));        \
  }

TEST_F(BranchTableIteratorTest, count0) {
  CHECK_BR_TABLE_LENGTH(0, U32V_1(1));
  CHECK_BR_TABLE_LENGTH(0, U32V_2(200));
  CHECK_BR_TABLE_LENGTH(0, U32V_3(30000));
  CHECK_BR_TABLE_LENGTH(0, U32V_4(400000));

  CHECK_BR_TABLE_LENGTH(0, U32V_1(2));
  CHECK_BR_TABLE_LENGTH(0, U32V_2(300));
  CHECK_BR_TABLE_LENGTH(0, U32V_3(40000));
  CHECK_BR_TABLE_LENGTH(0, U32V_4(500000));
}

TEST_F(BranchTableIteratorTest, count1) {
  CHECK_BR_TABLE_LENGTH(1, U32V_1(1), U32V_1(6));
  CHECK_BR_TABLE_LENGTH(1, U32V_2(200), U32V_1(8));
  CHECK_BR_TABLE_LENGTH(1, U32V_3(30000), U32V_1(9));
  CHECK_BR_TABLE_LENGTH(1, U32V_4(400000), U32V_1(11));

  CHECK_BR_TABLE_LENGTH(1, U32V_1(2), U32V_2(6));
  CHECK_BR_TABLE_LENGTH(1, U32V_2(300), U32V_2(7));
  CHECK_BR_TABLE_LENGTH(1, U32V_3(40000), U32V_2(8));
  CHECK_BR_TABLE_LENGTH(1, U32V_4(500000), U32V_2(9));
}

TEST_F(BranchTableIteratorTest, error0) {
  CHECK_BR_TABLE_ERROR(0);
  CHECK_BR_TABLE_ERROR(1, U32V_1(33));
}

#undef CHECK_BR_TABLE_LENGTH
#undef CHECK_BR_TABLE_ERROR

struct PrintOpcodes {
  const uint8_t* start;
  const uint8_t* end;
};
std::ostream& operator<<(std::ostream& out, const PrintOpcodes& range) {
  out << "First opcode: \""
      << WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(*range.start))
      << "\"\nall bytes: [";
  for (const uint8_t* b = range.start; b < range.end; ++b) {
    out << (b == range.start ? "" : ", ") << uint32_t{*b} << "/"
        << AsHex(*b, 2, true);
  }
  return out << "]";
}

class WasmOpcodeLengthTest : public TestWithZone {
 public:
  WasmOpcodeLengthTest() : TestWithZone() {}

  template <typename... Bytes>
  void ExpectLength(unsigned expected, Bytes... bytes) {
    const uint8_t code[] = {
        static_cast<uint8_t>(bytes)..., 0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_EQ(expected, OpcodeLength(code, code + sizeof(code)))
        << PrintOpcodes{code, code + sizeof...(bytes)};
  }

  // Helper to check for prefixed opcodes, which can have multiple bytes.
  void ExpectLengthPrefixed(unsigned operands, WasmOpcode opcode) {
    uint8_t prefix = WasmOpcodes::ExtractPrefix(opcode);
    DCHECK(WasmOpcodes::IsPrefixOpcode(static_cast<WasmOpcode>(prefix)));
    uint16_t index = ExtractPrefixedOpcodeBytes(opcode);
    uint8_t encoded[2] = {0, 0};
    uint8_t* p = encoded;
    unsigned len = static_cast<unsigned>(LEBHelper::sizeof_u32v(index));
    DCHECK_GE(2, len);
    LEBHelper::write_u32v(&p, index);
    // length of index, + number of operands + prefix bye
    ExpectLength(len + operands + 1, prefix, encoded[0], encoded[1]);
  }

  template <typename... Bytes>
  void ExpectFailure(Bytes... bytes) {
    const uint8_t code[] = {
        static_cast<uint8_t>(bytes)..., 0, 0, 0, 0, 0, 0, 0, 0};
    WasmDetectedFeatures detected_features;
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    WasmDecoder<Decoder::FullValidationTag> decoder(
        this->zone(), nullptr, WasmEnabledFeatures::None(), &detected_features,
        nullptr, kIsShared, code, code + sizeof(code), 0);
    WasmDecoder<Decoder::FullValidationTag>::OpcodeLength(&decoder, code);
    EXPECT_TRUE(decoder.failed());
  }

  void ExpectNonFailure(WasmOpcode opcode) {
    uint8_t maybe_prefix = WasmOpcodes::ExtractPrefix(opcode);
    uint8_t bytes[32]{0};
    if (WasmOpcodes::IsPrefixOpcode(static_cast<WasmOpcode>(maybe_prefix))) {
      bytes[0] = maybe_prefix;
      uint16_t index = ExtractPrefixedOpcodeBytes(opcode);
      uint8_t* p = &bytes[1];
      LEBHelper::write_u32v(&p, index);
    } else {
      DCHECK_LE(static_cast<uint32_t>(opcode), 0xFF);
      bytes[0] = static_cast<uint8_t>(opcode);
      // Special case: select_with_type insists on a {1} immediate.
      if (opcode == kExprSelectWithType) {
        bytes[1] = 1;
        bytes[2] = kAnyRefCode;
      }
    }
    WasmDetectedFeatures detected;
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    WasmDecoder<Decoder::FullValidationTag> decoder(
        this->zone(), nullptr, WasmEnabledFeatures::All(), &detected, nullptr,
        kIsShared, bytes, bytes + sizeof(bytes), 0);
    WasmDecoder<Decoder::FullValidationTag>::OpcodeLength(&decoder, bytes);
    EXPECT_TRUE(decoder.ok())
        << opcode << " aka " << WasmOpcodes::OpcodeName(opcode) << ": "
        << decoder.error().message();
  }
};

TEST_F(WasmOpcodeLengthTest, AllOpcodesImplemented) {
  // Make sure we didn't forget to add an opcode to the switch statements
  // in the {OpcodeLength} function. Due to nested handling of prefixed
  // opcodes, and the desire to support invalid modules, we can't rely on
  // compiler warnings for non-exhaustive cases lists here.
#define OPCODE(opcode, ...) ExpectNonFailure(kExpr##opcode);
  FOREACH_OPCODE(OPCODE)
#undef OPCODE
}

TEST_F(WasmOpcodeLengthTest, Statements) {
  ExpectLength(1, kExprNop);
  ExpectLength(1, kExprElse);
  ExpectLength(1, kExprEnd);
  ExpectLength(1, kExprSelect);
  ExpectLength(2, kExprCatch);
  ExpectLength(2, kExprDelegate);
  ExpectLength(2, kExprRethrow);
  ExpectLength(2, kExprBr);
  ExpectLength(2, kExprBrIf);
  ExpectLength(2, kExprThrow);
  ExpectLength(2, kExprBlock, kI32Code);
  ExpectLength(2, kExprLoop, kI32Code);
  ExpectLength(2, kExprIf, kI32Code);
  ExpectLength(2, kExprTry, kI32Code);
}

TEST_F(WasmOpcodeLengthTest, MiscExpressions) {
  ExpectLength(5, kExprF32Const);
  ExpectLength(9, kExprF64Const);
  ExpectLength(2, kExprRefNull);
  ExpectLength(2, kExprLocalGet);
  ExpectLength(2, kExprLocalSet);
  ExpectLength(2, kExprGlobalGet);
  ExpectLength(2, kExprGlobalSet);
  ExpectLength(2, kExprCallFunction);
  ExpectLength(3, kExprCallIndirect);
  ExpectLength(3, kExprSelectWithType, 1, kI32Code);
}

TEST_F(WasmOpcodeLengthTest, I32Const) {
  ExpectLength(2, kExprI32Const, U32V_1(1));
  ExpectLength(3, kExprI32Const, U32V_2(999));
  ExpectLength(4, kExprI32Const, U32V_3(9999));
  ExpectLength(5, kExprI32Const, U32V_4(999999));
  ExpectLength(6, kExprI32Const, U32V_5(99999999));
}

TEST_F(WasmOpcodeLengthTest, I64Const) {
  ExpectLength(2, kExprI64Const, U32V_1(1));
  ExpectLength(3, kExpr
"""


```