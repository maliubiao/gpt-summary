Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding: The Big Picture**

The filename `function-body-decoder-unittest.cc` immediately tells us this file is testing the *decoding* of WebAssembly function bodies within the V8 JavaScript engine. The `unittest` part indicates these are focused, isolated tests.

**2. Core Functionality Identification: Test Cases**

The primary way to understand what's being tested is to look at the `TEST_F` macros. Each `TEST_F` defines a test case. Reading the names of these test cases gives a good overview of the functionalities being verified:

* `WasmOpcodeLengthTest`:  Likely tests the *length* of different WASM opcodes in their byte representation.
* `TypeReaderTest`:  Focuses on reading and decoding WASM type information.
* `LocalDeclDecoderTest`:  Deals with decoding local variable declarations within a function body.
* `BytecodeIteratorTest`:  Tests iterating over the bytecode (opcodes) of a function body.
* `FunctionBodyDecoderTestOnBothMemoryTypes`:  Specifically tests scenarios involving different memory addressing modes (32-bit and 64-bit).
* `FunctionBodyDecoderTestTable64`: Similar to the above but focused on tables and 64-bit indexing.
* `ExtendedMemoryAccessImmediate`: Tests how memory access opcodes with explicit memory indices are decoded.

**3. Deeper Dive into Key Test Cases:  Understanding the "How"**

* **`WasmOpcodeLengthTest`:** The key here is the `ExpectLength` and `ExpectLengthPrefixed` functions. These functions likely take an expected byte length and the WASM opcode (and potentially operands) as input and verify that the encoding produces the correct number of bytes. The examples within the tests (e.g., `kExprI32Const, U32V_1(99)`) show specific opcode and operand combinations being tested for their length. This directly relates to how V8 parses the bytecode.

* **`TypeReaderTest`:** The `DecodeHeapType` function and the `kFuncRefCode` constant suggest this test verifies the correct decoding of heap types (like function references) from their byte representation. The different byte arrays for `kFuncRefCode` likely test different LEB128 encodings.

* **`LocalDeclDecoderTest`:**  The focus here is on how local variable declarations (count and type) are encoded and decoded. The `DecodeLocalDecls` function likely takes raw bytes and attempts to parse them as local declarations. The various test cases check scenarios like empty locals, no locals, incorrect counts, and combinations of different local variable types.

* **`BytecodeIteratorTest`:** This test uses a `BytecodeIterator` class to traverse the opcodes in a byte array. The `opcodes()` and `offsets()` methods likely provide iterators for accessing the opcodes and their corresponding offsets within the byte stream.

* **`FunctionBodyDecoderTestOnBothMemoryTypes` and `FunctionBodyDecoderTestTable64`:** These test cases use parameterized testing (`::testing::TestWithParam`). The parameters are `AddressType::kI32` and `AddressType::kI64`, indicating they are testing how function body decoding behaves when dealing with 32-bit and 64-bit memory and table addressing, respectively. The test cases within these focus on opcodes related to memory and table access (load, store, size, grow, call_indirect, etc.) and how the address sizes influence the validity of the bytecode.

**4. Connecting to JavaScript (If Applicable):**

While this is a C++ unittest, the functionality it tests is directly related to how JavaScript executes WebAssembly. If a WASM module in a JavaScript environment has a function, V8 needs to decode the bytecode of that function. Errors in this decoding process could lead to crashes or incorrect behavior.

* **Example:**  If `WasmOpcodeLengthTest` fails, it means V8 might misinterpret the boundaries between opcodes in a WASM function, leading to incorrect execution.

**5. Identifying Potential Programming Errors:**

The test cases implicitly highlight potential programming errors in the *decoder implementation*:

* **Incorrect LEB128 decoding:**  Failing to correctly handle variable-length integer encoding (LEB128) used for opcodes, operands, and type information. This is specifically tested in `WasmOpcodeLengthTest` and `TypeReaderTest`.
* **Off-by-one errors in length calculations:**  Miscalculating the number of bytes for an opcode or its operands.
* **Incorrect handling of prefixes and extended opcodes:**  Not properly decoding opcodes that use prefix bytes.
* **Type mismatch errors:**  Incorrectly interpreting the data type associated with an opcode or operand. This is relevant in the memory and table access tests.
* **Boundary conditions:**  Not handling edge cases like empty function bodies or large numbers of locals correctly.

**6. Inferring Input and Output:**

For many test cases, the input is a sequence of bytes representing the encoded WASM bytecode, and the expected output is the correct interpretation of that bytecode (e.g., the decoded opcode, the length of the opcode, the decoded type information). The `ExpectLength`, `DecodeHeapType`, and `DecodeLocalDecls` functions encapsulate these expectations.

**7. Considering `.tq` Files (Torque):**

The prompt mentions `.tq` files. Since this file is `.cc`, it's standard C++. However, the prompt provides a hypothetical scenario. If it were `.tq`, it would indicate the use of V8's Torque language for generating optimized machine code. In that case, the file would define the *implementation* of the decoder logic itself, rather than just testing it.

**8. Summarizing the Functionality (as requested in part 7):**

The core function of `function-body-decoder-unittest.cc` is to comprehensively test the correctness and robustness of V8's WebAssembly function body decoder. It verifies that the decoder can accurately parse and interpret the byte stream representing a WASM function, including:

* **Opcode lengths:** Ensuring the decoder correctly identifies the boundaries between opcodes.
* **Data types:** Confirming accurate decoding of value types, heap types, and function signatures.
* **Local variable declarations:** Validating the parsing of local variable counts and types.
* **Control flow structures:** (Indirectly through opcode testing like `kExprIf`, `kExprElse`, `kExprEnd`).
* **Memory and table access:**  Specifically testing the handling of 32-bit and 64-bit addressing modes for memory and tables.
* **Error handling:** Checking that the decoder correctly identifies and reports invalid or malformed WASM bytecode.

By having these detailed unit tests, the V8 team ensures that the WebAssembly execution engine correctly interprets and executes WASM code, contributing to the overall stability and performance of JavaScript applications using WebAssembly.
这是目录为 `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 的一个 V8 源代码文件，它是一个 C++ 的单元测试文件，专门用于测试 WebAssembly (Wasm) 函数体解码器的功能。

**主要功能:**

该文件的主要功能是验证 V8 的 WebAssembly 函数体解码器是否能够正确地解析和理解 Wasm 函数体的字节码。 它通过创建各种精心设计的 Wasm 指令序列，并使用解码器解析它们，然后断言解码的结果是否符合预期。

**具体功能点:**

1. **测试操作码长度 (Opcode Length):**
   - 验证不同 Wasm 操作码的字节长度是否正确。这包括单字节操作码、带有立即数的操作码以及带有前缀的操作码（例如 SIMD 指令）。
   - 它测试了固定长度的操作码和可变长度的操作码（例如，带有 LEB128 编码索引的操作码）。

2. **测试 LEB128 解码:**
   -  验证解码器是否正确处理了 LEB128 编码的无符号整数 (用于表示索引、数值等)。

3. **测试类型读取 (Type Reading):**
   - 验证解码器是否能够正确读取和解析 Wasm 的类型信息，例如 `funcref`。

4. **测试局部变量声明解码 (Local Declaration Decoding):**
   - 验证解码器是否能够正确解析函数体内的局部变量声明，包括局部变量的数量和类型。

5. **测试字节码迭代器 (Bytecode Iterator):**
   - 验证用于遍历解码后字节码的迭代器是否正常工作，能够正确地访问每个操作码。

6. **测试内存相关指令 (Memory Instructions):**
   - 针对不同的内存寻址模式（32 位和 64 位，通过 `FunctionBodyDecoderTestOnBothMemoryTypes` 测试类实现），验证内存加载、存储、大小、增长等指令的解码是否正确。
   - 测试了多内存的支持，验证了带有显式内存索引的内存访问指令的解码。

7. **测试表相关指令 (Table Instructions):**
   - 针对不同的表索引模式（32 位和 64 位，通过 `FunctionBodyDecoderTestTable64` 测试类实现），验证表的获取、设置、调用间接、增长、大小、填充、初始化、复制等指令的解码是否正确。

**关于文件后缀和 Torque:**

如果 `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于在 V8 中生成高效机器码的领域特定语言。在这种情况下，该文件将包含 *实现* 函数体解码逻辑的 Torque 代码，而不是像现在这样包含测试代码。

**与 JavaScript 的关系:**

`v8/test/unittests/wasm/function-body-decoder-unittest.cc` 测试的解码器是 V8 执行 JavaScript 中 WebAssembly 代码的关键组成部分。当 JavaScript 代码加载和实例化一个 Wasm 模块时，V8 需要解码 Wasm 模块中函数的字节码才能执行它们。这个单元测试确保了解码过程的正确性，从而保证 Wasm 代码在 JavaScript 环境中能够正确运行。

**JavaScript 示例 (概念性):**

```javascript
// 假设我们有一个简单的 Wasm 模块，其中包含一个将两个 i32 相加的函数
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM 标头
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // 类型段：(i32, i32) => i32
  0x03, 0x02, 0x01, 0x00, // 函数段：定义一个函数，使用索引为 0 的类型
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // 代码段：函数体
  // ... (更详细的字节码)
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 当 JavaScript 引擎执行 wasmInstance 中的函数时，
// 就会用到 function-body-decoder-unittest.cc 中测试的解码器
const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出 15
```

在这个例子中，当 JavaScript 引擎执行 `wasmInstance.exports.add(5, 10)` 时，它需要先解码 `add` 函数的字节码（`0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b` 等）。 `function-body-decoder-unittest.cc` 中的测试确保 V8 能够正确地将这些字节码解释为“获取局部变量 0”、“获取局部变量 1”、“i32 相加”等操作。

**代码逻辑推理示例 (假设输入与输出):**

假设我们要测试 `i32.const` 操作码的长度。

**假设输入:**  Wasm 字节码序列 `0x41 0x99` (表示 `i32.const 99`)

**预期输出:** 解码器应该识别出这是一个 `i32.const` 操作码，并且其长度为 2 个字节。`WasmOpcodeLengthTest` 中的 `ExpectLength(2, kExprI32Const, U32V_1(99));`  就是这样的一个测试。 `U32V_1(99)`  会生成表示 99 的 LEB128 编码的字节。

**用户常见的编程错误示例:**

用户在手动生成或修改 Wasm 字节码时，可能会犯一些常见的错误，这些错误 `function-body-decoder-unittest.cc` 可能会覆盖到：

1. **操作码错误:** 使用了不存在或错误的 Wasm 操作码。解码器应该能够识别出这些非法操作码。
2. **立即数编码错误:**  LEB128 编码不正确，例如，使用了过多的 continuation byte，或者编码的数值超出预期范围。
3. **类型不匹配:** 在需要某种类型值的地方使用了错误类型的值。例如，在 `i32.add` 指令的操作数位置提供了 `f64` 类型的值。
4. **块结构不匹配:**  `block`, `loop`, `if` 等控制流指令的 `end` 标记缺失或位置错误，导致解码器无法正确解析代码块的范围。
5. **索引超出范围:** 访问不存在的局部变量、全局变量、函数、表或内存。

**归纳一下它的功能 (第 7 部分):**

作为第七部分，该文件完整地展示了 V8 中 WebAssembly 函数体解码器单元测试的实现。它通过一系列精心设计的测试用例，覆盖了各种 Wasm 指令、编码方式和场景，确保解码器能够准确、可靠地将 Wasm 函数体的字节码转换为 V8 可以执行的内部表示。 这些测试是保证 V8 对 WebAssembly 支持的正确性和稳定性的重要组成部分。

### 提示词
```
这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/function-body-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
I64Const, U32V_2(99));
  ExpectLength(4, kExprI64Const, U32V_3(9999));
  ExpectLength(5, kExprI64Const, U32V_4(99999));
  ExpectLength(6, kExprI64Const, U32V_5(9999999));
  ExpectLength(7, WASM_I64V_6(777777));
  ExpectLength(8, WASM_I64V_7(7777777));
  ExpectLength(9, WASM_I64V_8(77777777));
  ExpectLength(10, WASM_I64V_9(777777777));
}

TEST_F(WasmOpcodeLengthTest, VariableLength) {
  ExpectLength(2, kExprGlobalGet, U32V_1(1));
  ExpectLength(3, kExprGlobalGet, U32V_2(33));
  ExpectLength(4, kExprGlobalGet, U32V_3(44));
  ExpectLength(5, kExprGlobalGet, U32V_4(66));
  ExpectLength(6, kExprGlobalGet, U32V_5(77));

  ExpectLength(2, kExprRefFunc, U32V_1(1));
  ExpectLength(3, kExprRefFunc, U32V_2(33));
  ExpectLength(4, kExprRefFunc, U32V_3(44));
  ExpectLength(5, kExprRefFunc, U32V_4(66));
  ExpectLength(6, kExprRefFunc, U32V_5(77));

  ExpectLength(2, kExprTableGet, U32V_1(1));
  ExpectLength(3, kExprTableGet, U32V_2(33));
  ExpectLength(4, kExprTableGet, U32V_3(44));
  ExpectLength(5, kExprTableGet, U32V_4(66));
  ExpectLength(6, kExprTableGet, U32V_5(77));

  ExpectLength(2, kExprTableSet, U32V_1(1));
  ExpectLength(3, kExprTableSet, U32V_2(33));
  ExpectLength(4, kExprTableSet, U32V_3(44));
  ExpectLength(5, kExprTableSet, U32V_4(66));
  ExpectLength(6, kExprTableSet, U32V_5(77));

  ExpectLength(3, kExprCallIndirect, U32V_1(1), U32V_1(1));
  ExpectLength(4, kExprCallIndirect, U32V_1(1), U32V_2(33));
  ExpectLength(5, kExprCallIndirect, U32V_1(1), U32V_3(44));
  ExpectLength(6, kExprCallIndirect, U32V_1(1), U32V_4(66));
  ExpectLength(7, kExprCallIndirect, U32V_1(1), U32V_5(77));
}

TEST_F(WasmOpcodeLengthTest, LoadsAndStores) {
  ExpectLength(3, kExprI32LoadMem8S);
  ExpectLength(3, kExprI32LoadMem8U);
  ExpectLength(3, kExprI32LoadMem16S);
  ExpectLength(3, kExprI32LoadMem16U);
  ExpectLength(3, kExprI32LoadMem);
  ExpectLength(3, kExprI64LoadMem8S);
  ExpectLength(3, kExprI64LoadMem8U);
  ExpectLength(3, kExprI64LoadMem16S);
  ExpectLength(3, kExprI64LoadMem16U);
  ExpectLength(3, kExprI64LoadMem32S);
  ExpectLength(3, kExprI64LoadMem32U);
  ExpectLength(3, kExprI64LoadMem);
  ExpectLength(3, kExprF32LoadMem);
  ExpectLength(3, kExprF64LoadMem);

  ExpectLength(3, kExprI32StoreMem8);
  ExpectLength(3, kExprI32StoreMem16);
  ExpectLength(3, kExprI32StoreMem);
  ExpectLength(3, kExprI64StoreMem8);
  ExpectLength(3, kExprI64StoreMem16);
  ExpectLength(3, kExprI64StoreMem32);
  ExpectLength(3, kExprI64StoreMem);
  ExpectLength(3, kExprF32StoreMem);
  ExpectLength(3, kExprF64StoreMem);
}

TEST_F(WasmOpcodeLengthTest, MiscMemExpressions) {
  ExpectLength(2, kExprMemorySize);
  ExpectLength(2, kExprMemoryGrow);
}

TEST_F(WasmOpcodeLengthTest, SimpleExpressions) {
#define SIMPLE_OPCODE(name, byte, ...) byte,
  static constexpr uint8_t kSimpleOpcodes[] = {
      FOREACH_SIMPLE_OPCODE(SIMPLE_OPCODE)};
#undef SIMPLE_OPCODE
  for (uint8_t simple_opcode : kSimpleOpcodes) {
    ExpectLength(1, simple_opcode);
  }
}

TEST_F(WasmOpcodeLengthTest, SimdExpressions) {
#define TEST_SIMD(name, ...) ExpectLengthPrefixed(0, kExpr##name);
  FOREACH_SIMD_0_OPERAND_OPCODE(TEST_SIMD)
#undef TEST_SIMD
#define TEST_SIMD(name, ...) ExpectLengthPrefixed(1, kExpr##name);
  FOREACH_SIMD_1_OPERAND_OPCODE(TEST_SIMD)
#undef TEST_SIMD
  ExpectLengthPrefixed(16, kExprI8x16Shuffle);
  // test for bad simd opcode, 0xFF is encoded in two bytes.
  ExpectLength(3, kSimdPrefix, 0xFF, 0x1);
}

TEST_F(WasmOpcodeLengthTest, IllegalRefIndices) {
  ExpectFailure(kExprBlock, kRefNullCode, U32V_3(kV8MaxWasmTypes + 1));
  ExpectFailure(kExprBlock, kRefNullCode, U32V_4(0x01000000));
}

TEST_F(WasmOpcodeLengthTest, GCOpcodes) {
  // br_on_cast[_fail]: prefix + opcode + flags + br_depth + source_type +
  //                    target_type
  ExpectLength(6, 0xfb, kExprBrOnCast & 0xFF);
  ExpectLength(6, 0xfb, kExprBrOnCastFail & 0xFF);

  // struct.new, with leb immediate operand.
  ExpectLength(3, 0xfb, 0x07, 0x42);
  ExpectLength(4, 0xfb, 0x07, 0x80, 0x00);

  // string.new_utf8 with $mem=0.
  ExpectLength(4, 0xfb, 0x80, 0x01, 0x00);

  // string.as_wtf8.
  ExpectLength(3, 0xfb, 0x90, 0x01);
}

TEST_F(WasmOpcodeLengthTest, PrefixedOpcodesLEB) {
  // kExprI8x16Splat with a 3-byte LEB-encoded opcode.
  ExpectLength(4, 0xfd, 0x8f, 0x80, 0x00);

  // kExprI32SConvertSatF32 with a 4-byte LEB-encoded opcode.
  ExpectLength(5, 0xfc, 0x80, 0x80, 0x80, 0x00);

  // kExprAtomicNotify with a 2-byte LEB-encoded opcode, and 2 i32 imm for
  // memarg.
  ExpectLength(5, 0xfe, 0x80, 0x00, 0x00, 0x00);
}

class TypeReaderTest : public TestWithZone {
 public:
  HeapType DecodeHeapType(const uint8_t* start, const uint8_t* end) {
    Decoder decoder(start, end);
    auto [heap_type, length] =
        value_type_reader::read_heap_type<Decoder::FullValidationTag>(
            &decoder, start, enabled_features_);
    return heap_type;
  }

  // This variable is modified by WASM_FEATURE_SCOPE.
  WasmEnabledFeatures enabled_features_;
};

TEST_F(TypeReaderTest, HeapTypeDecodingTest) {
  HeapType heap_func = HeapType(HeapType::kFunc);
  HeapType heap_bottom = HeapType(HeapType::kBottom);

  // 1- to 5-byte representation of kFuncRefCode.
  {
    const uint8_t data[] = {kFuncRefCode};
    HeapType result = DecodeHeapType(data, data + sizeof(data));
    EXPECT_TRUE(result == heap_func);
  }
  {
    const uint8_t data[] = {kFuncRefCode | 0x80, 0x7F};
    HeapType result = DecodeHeapType(data, data + sizeof(data));
    EXPECT_EQ(result, heap_func);
  }
  {
    const uint8_t data[] = {kFuncRefCode | 0x80, 0xFF, 0x7F};
    HeapType result = DecodeHeapType(data, data + sizeof(data));
    EXPECT_EQ(result, heap_func);
  }
  {
    const uint8_t data[] = {kFuncRefCode | 0x80, 0xFF, 0xFF, 0x7F};
    HeapType result = DecodeHeapType(data, data + sizeof(data));
    EXPECT_EQ(result, heap_func);
  }
  {
    const uint8_t data[] = {kFuncRefCode | 0x80, 0xFF, 0xFF, 0xFF, 0x7F};
    HeapType result = DecodeHeapType(data, data + sizeof(data));
    EXPECT_EQ(result, heap_func);
  }

  {
    // Some negative number.
    const uint8_t data[] = {0xB4, 0x7F};
    HeapType result = DecodeHeapType(data, data + sizeof(data));
    EXPECT_EQ(result, heap_bottom);
  }

  {
    // This differs from kFuncRefCode by one bit outside the 1-byte LEB128
    // range. This should therefore NOT be decoded as HeapType::kFunc and
    // instead fail.
    const uint8_t data[] = {kFuncRefCode | 0x80, 0x6F};
    HeapType result = DecodeHeapType(data, data + sizeof(data));
    EXPECT_EQ(result, heap_bottom);
  }
}

class LocalDeclDecoderTest : public TestWithZone {
 public:
  WasmEnabledFeatures enabled_features_;

  size_t ExpectRun(ValueType* local_types, size_t pos, ValueType expected,
                   size_t count) {
    for (size_t i = 0; i < count; i++) {
      EXPECT_EQ(expected, local_types[pos++]);
    }
    return pos;
  }

  bool DecodeLocalDecls(BodyLocalDecls* decls, const uint8_t* start,
                        const uint8_t* end) {
    WasmModule module;
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    return ValidateAndDecodeLocalDeclsForTesting(
        enabled_features_, decls, &module, kIsShared, start, end, zone());
  }
};

TEST_F(LocalDeclDecoderTest, EmptyLocals) {
  BodyLocalDecls decls;
  bool result = DecodeLocalDecls(&decls, nullptr, nullptr);
  EXPECT_FALSE(result);
}

TEST_F(LocalDeclDecoderTest, NoLocals) {
  static const uint8_t data[] = {0};
  BodyLocalDecls decls;
  bool result = DecodeLocalDecls(&decls, data, data + sizeof(data));
  EXPECT_TRUE(result);
  EXPECT_EQ(0u, decls.num_locals);
}

TEST_F(LocalDeclDecoderTest, WrongLocalDeclsCount1) {
  static const uint8_t data[] = {1};
  BodyLocalDecls decls;
  bool result = DecodeLocalDecls(&decls, data, data + sizeof(data));
  EXPECT_FALSE(result);
}

TEST_F(LocalDeclDecoderTest, WrongLocalDeclsCount2) {
  static const uint8_t data[] = {
      2, 1, static_cast<uint8_t>(kWasmI32.value_type_code())};
  BodyLocalDecls decls;
  bool result = DecodeLocalDecls(&decls, data, data + sizeof(data));
  EXPECT_FALSE(result);
}

TEST_F(LocalDeclDecoderTest, OneLocal) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType type = kValueTypes[i];
    const uint8_t data[] = {1, 1, static_cast<uint8_t>(type.value_type_code())};
    BodyLocalDecls decls;
    bool result = DecodeLocalDecls(&decls, data, data + sizeof(data));
    EXPECT_TRUE(result);
    EXPECT_EQ(1u, decls.num_locals);

    EXPECT_EQ(type, decls.local_types[0]);
  }
}

TEST_F(LocalDeclDecoderTest, FiveLocals) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType type = kValueTypes[i];
    const uint8_t data[] = {1, 5, static_cast<uint8_t>(type.value_type_code())};
    BodyLocalDecls decls;
    bool result = DecodeLocalDecls(&decls, data, data + sizeof(data));
    EXPECT_TRUE(result);
    EXPECT_EQ(sizeof(data), decls.encoded_size);
    EXPECT_EQ(5u, decls.num_locals);
    ExpectRun(decls.local_types, 0, type, 5);
  }
}

TEST_F(LocalDeclDecoderTest, MixedLocals) {
  for (uint8_t a = 0; a < 3; a++) {
    for (uint8_t b = 0; b < 3; b++) {
      for (uint8_t c = 0; c < 3; c++) {
        for (uint8_t d = 0; d < 3; d++) {
          const uint8_t data[] = {4, a,        kI32Code, b,       kI64Code,
                                  c, kF32Code, d,        kF64Code};
          BodyLocalDecls decls;
          bool result = DecodeLocalDecls(&decls, data, data + sizeof(data));
          EXPECT_TRUE(result);
          EXPECT_EQ(sizeof(data), decls.encoded_size);
          EXPECT_EQ(static_cast<uint32_t>(a + b + c + d), decls.num_locals);

          size_t pos = 0;
          pos = ExpectRun(decls.local_types, pos, kWasmI32, a);
          pos = ExpectRun(decls.local_types, pos, kWasmI64, b);
          pos = ExpectRun(decls.local_types, pos, kWasmF32, c);
          pos = ExpectRun(decls.local_types, pos, kWasmF64, d);
        }
      }
    }
  }
}

TEST_F(LocalDeclDecoderTest, UseEncoder) {
  const uint8_t* data = nullptr;
  const uint8_t* end = nullptr;
  LocalDeclEncoder local_decls(zone());

  local_decls.AddLocals(5, kWasmF32);
  local_decls.AddLocals(1337, kWasmI32);
  local_decls.AddLocals(212, kWasmI64);
  local_decls.Prepend(zone(), &data, &end);

  BodyLocalDecls decls;
  bool result = DecodeLocalDecls(&decls, data, end);
  EXPECT_TRUE(result);
  EXPECT_EQ(5u + 1337u + 212u, decls.num_locals);

  size_t pos = 0;
  pos = ExpectRun(decls.local_types, pos, kWasmF32, 5);
  pos = ExpectRun(decls.local_types, pos, kWasmI32, 1337);
  pos = ExpectRun(decls.local_types, pos, kWasmI64, 212);
}

TEST_F(LocalDeclDecoderTest, ExnRef) {
  WASM_FEATURE_SCOPE(exnref);
  const uint8_t data[] = {1, 1,
                          static_cast<uint8_t>(kWasmExnRef.value_type_code())};
  BodyLocalDecls decls;
  bool result = DecodeLocalDecls(&decls, data, data + sizeof(data));
  EXPECT_TRUE(result);
  EXPECT_EQ(1u, decls.num_locals);
  EXPECT_EQ(kWasmExnRef, decls.local_types[0]);
}

TEST_F(LocalDeclDecoderTest, InvalidTypeIndex) {
  const uint8_t* data = nullptr;
  const uint8_t* end = nullptr;
  LocalDeclEncoder local_decls(zone());

  local_decls.AddLocals(1, ValueType::RefNull(ModuleTypeIndex{0}));
  BodyLocalDecls decls;
  bool result = DecodeLocalDecls(&decls, data, end);
  EXPECT_FALSE(result);
}

class BytecodeIteratorTest : public TestWithZone {};

TEST_F(BytecodeIteratorTest, SimpleForeach) {
  uint8_t code[] = {WASM_IF_ELSE(WASM_ZERO, WASM_ZERO, WASM_ZERO)};
  BytecodeIterator iter(code, code + sizeof(code));
  WasmOpcode expected[] = {kExprI32Const, kExprIf,       kExprI32Const,
                           kExprElse,     kExprI32Const, kExprEnd};
  size_t pos = 0;
  for (WasmOpcode opcode : iter.opcodes()) {
    if (pos >= arraysize(expected)) {
      EXPECT_TRUE(false);
      break;
    }
    EXPECT_EQ(expected[pos++], opcode);
  }
  EXPECT_EQ(arraysize(expected), pos);
}

TEST_F(BytecodeIteratorTest, ForeachTwice) {
  uint8_t code[] = {WASM_IF_ELSE(WASM_ZERO, WASM_ZERO, WASM_ZERO)};
  BytecodeIterator iter(code, code + sizeof(code));
  int count = 0;

  count = 0;
  for (WasmOpcode opcode : iter.opcodes()) {
    USE(opcode);
    count++;
  }
  EXPECT_EQ(6, count);

  count = 0;
  for (WasmOpcode opcode : iter.opcodes()) {
    USE(opcode);
    count++;
  }
  EXPECT_EQ(6, count);
}

TEST_F(BytecodeIteratorTest, ForeachOffset) {
  uint8_t code[] = {WASM_IF_ELSE(WASM_ZERO, WASM_ZERO, WASM_ZERO)};
  BytecodeIterator iter(code, code + sizeof(code));
  int count = 0;

  count = 0;
  for (auto offset : iter.offsets()) {
    USE(offset);
    count++;
  }
  EXPECT_EQ(6, count);

  count = 0;
  for (auto offset : iter.offsets()) {
    USE(offset);
    count++;
  }
  EXPECT_EQ(6, count);
}

TEST_F(BytecodeIteratorTest, WithLocalDecls) {
  uint8_t code[] = {1, 1, kI32Code, WASM_I32V_1(9), WASM_I32V_1(11)};
  BodyLocalDecls decls;
  BytecodeIterator iter(code, code + sizeof(code), &decls, zone());

  EXPECT_EQ(3u, decls.encoded_size);
  EXPECT_EQ(3u, iter.pc_offset());
  EXPECT_TRUE(iter.has_next());
  EXPECT_EQ(kExprI32Const, iter.current());
  iter.next();
  EXPECT_TRUE(iter.has_next());
  EXPECT_EQ(kExprI32Const, iter.current());
  iter.next();
  EXPECT_FALSE(iter.has_next());
}

/*******************************************************************************
 * Memory64 tests.
 ******************************************************************************/

class FunctionBodyDecoderTestOnBothMemoryTypes
    : public FunctionBodyDecoderTestBase<
          WithDefaultPlatformMixin<::testing::TestWithParam<AddressType>>> {
 public:
  FunctionBodyDecoderTestOnBothMemoryTypes() {
    if (is_memory64()) enabled_features_.Add(WasmEnabledFeature::memory64);
  }

  bool is_memory32() const { return GetParam() == AddressType::kI32; }
  bool is_memory64() const { return GetParam() == AddressType::kI64; }
};

std::string PrintAddressType(::testing::TestParamInfo<AddressType> info) {
  return AddressTypeToStr(info.param);
}

INSTANTIATE_TEST_SUITE_P(MemoryTypes, FunctionBodyDecoderTestOnBothMemoryTypes,
                         ::testing::Values(AddressType::kI32,
                                           AddressType::kI64),
                         PrintAddressType);

TEST_P(FunctionBodyDecoderTestOnBothMemoryTypes, AddressTypes) {
  builder.AddMemory(GetParam());
  Validate(!is_memory64(), sigs.i_v(),
           {WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)});
  Validate(is_memory64(), sigs.i_v(),
           {WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO64)});
  Validate(!is_memory64(), sigs.v_v(),
           {WASM_STORE_MEM(MachineType::Int32(), WASM_ZERO, WASM_ZERO)});
  Validate(is_memory64(), sigs.v_v(),
           {WASM_STORE_MEM(MachineType::Int32(), WASM_ZERO64, WASM_ZERO)});
}

TEST_P(FunctionBodyDecoderTestOnBothMemoryTypes, 64BitOffsetOnMemory32) {
  // Check that with memory64 enabled, the offset is always decoded as u64, even
  // if the memory is declared as 32-bit memory.
  builder.AddMemory(AddressType::kI32);
  // Offset is zero encoded in 5 bytes (always works).
  Validate(true, sigs.i_v(),
           {WASM_LOAD_MEM_OFFSET(MachineType::Int32(), U64V_5(0), WASM_ZERO)});
  // Offset is zero encoded in 6 bytes (works if memory64 is enabled).
  Validate(is_memory64(), sigs.i_v(),
           {WASM_LOAD_MEM_OFFSET(MachineType::Int32(), U64V_6(0), WASM_ZERO)});
  // Same with store.
  Validate(true, sigs.v_v(),
           {WASM_STORE_MEM_OFFSET(MachineType::Int32(), U64V_5(0), WASM_ZERO,
                                  WASM_ZERO)});
  Validate(is_memory64(), sigs.v_v(),
           {WASM_STORE_MEM_OFFSET(MachineType::Int32(), U64V_6(0), WASM_ZERO,
                                  WASM_ZERO)});
  // Offset is 2^32+2 (fails validation on memory32).
  Validate(false, sigs.i_v(),
           {WASM_LOAD_MEM_OFFSET(MachineType::Int32(),
                                 U64V_6((uint64_t{1} << 32) + 2), WASM_ZERO)});
  Validate(false, sigs.v_v(),
           {WASM_STORE_MEM_OFFSET(MachineType::Int32(),
                                  U64V_6((uint64_t{1} << 32) + 2), WASM_ZERO,
                                  WASM_ZERO)});
}

TEST_P(FunctionBodyDecoderTestOnBothMemoryTypes, 64BitOffsetOnMemory64) {
  // Same as above, but on a 64-bit memory.
  builder.AddMemory(AddressType::kI64);
  // Offset is zero encoded in 5 bytes.
  Validate(
      true, sigs.i_v(),
      {WASM_LOAD_MEM_OFFSET(MachineType::Int32(), U64V_5(0), WASM_ZERO64)});
  // Offset is zero encoded in 6 bytes (works if memory64 is enabled).
  Validate(
      is_memory64(), sigs.i_v(),
      {WASM_LOAD_MEM_OFFSET(MachineType::Int32(), U64V_6(0), WASM_ZERO64)});
  // Same with store.
  Validate(true, sigs.v_v(),
           {WASM_STORE_MEM_OFFSET(MachineType::Int32(), U64V_5(0), WASM_ZERO64,
                                  WASM_ZERO)});
  Validate(is_memory64(), sigs.v_v(),
           {WASM_STORE_MEM_OFFSET(MachineType::Int32(), U64V_6(0), WASM_ZERO64,
                                  WASM_ZERO)});
  // Offset is 2^32+2 (validates on memory64).
  Validate(
      is_memory64(), sigs.i_v(),
      {WASM_LOAD_MEM_OFFSET(MachineType::Int32(),
                            U64V_6((uint64_t{1} << 32) + 2), WASM_ZERO64)});
  Validate(is_memory64(), sigs.v_v(),
           {WASM_STORE_MEM_OFFSET(MachineType::Int32(),
                                  U64V_6((uint64_t{1} << 32) + 2), WASM_ZERO64,
                                  WASM_ZERO)});
}

TEST_P(FunctionBodyDecoderTestOnBothMemoryTypes, MemorySize) {
  builder.AddMemory(GetParam());
  // memory.size returns i32 on memory32.
  Validate(!is_memory64(), sigs.v_v(),
           {WASM_MEMORY_SIZE, kExprI32Eqz, kExprDrop});
  // memory.size returns i64 on memory64.
  Validate(is_memory64(), sigs.v_v(),
           {WASM_MEMORY_SIZE, kExprI64Eqz, kExprDrop});
}

TEST_P(FunctionBodyDecoderTestOnBothMemoryTypes, MemoryGrow) {
  builder.AddMemory(GetParam());
  // memory.grow is i32->i32 memory32.
  Validate(!is_memory64(), sigs.i_i(), {WASM_MEMORY_GROW(WASM_LOCAL_GET(0))});
  // memory.grow is i64->i64 memory32.
  Validate(is_memory64(), sigs.l_l(), {WASM_MEMORY_GROW(WASM_LOCAL_GET(0))});
  // any other combination always fails.
  auto sig_l_i = MakeSig::Returns(kWasmI64).Params(kWasmI32);
  ExpectFailure(&sig_l_i, {WASM_MEMORY_GROW(WASM_LOCAL_GET(0))});
  auto sig_i_l = MakeSig::Returns(kWasmI32).Params(kWasmI64);
  ExpectFailure(&sig_i_l, {WASM_MEMORY_GROW(WASM_LOCAL_GET(0))});
}

TEST_P(FunctionBodyDecoderTestOnBothMemoryTypes, CopyDifferentMemTypes) {
  AddressType mem_type = GetParam();
  AddressType other_mem_type =
      is_memory64() ? AddressType::kI32 : AddressType::kI64;
  uint8_t memory0 = builder.AddMemory(mem_type);
  uint8_t memory1 = builder.AddMemory(other_mem_type);

  // Copy from memory0 to memory1 with types i32/i64/i32. Valid if memory0 is
  // 64-bit.
  Validate(
      is_memory64(), sigs.v_v(),
      {WASM_MEMORY_COPY(memory1, memory0, WASM_ZERO, WASM_ZERO64, WASM_ZERO)},
      kAppendEnd);
  // Copy from memory0 to memory1 with types i64/i32/i32. Valid if memory0 is
  // 32-bit.
  Validate(
      is_memory32(), sigs.v_v(),
      {WASM_MEMORY_COPY(memory1, memory0, WASM_ZERO64, WASM_ZERO, WASM_ZERO)},
      kAppendEnd);
  // Passing the size as i64 is always invalid because one memory is always
  // 32-bit.
  ExpectFailure(
      sigs.v_v(),
      {WASM_MEMORY_COPY(memory1, memory0, WASM_ZERO, WASM_ZERO64, WASM_ZERO64)},
      kAppendEnd,
      is_memory32()
          ? "memory.copy[0] expected type i64, found i32.const of type i32"
          : "memory.copy[2] expected type i32, found i64.const of type i64");
  ExpectFailure(
      sigs.v_v(),
      {WASM_MEMORY_COPY(memory1, memory0, WASM_ZERO64, WASM_ZERO, WASM_ZERO64)},
      kAppendEnd,
      is_memory32()
          ? "memory.copy[2] expected type i32, found i64.const of type i64"
          : "memory.copy[0] expected type i32, found i64.const of type i64");
}

/*******************************************************************************
 * Multi-memory tests.
 ******************************************************************************/

TEST_F(FunctionBodyDecoderTest, ExtendedMemoryAccessImmediate) {
  builder.AddMemory();
  // The memory index can be encoded in a separate field, after a 0x40
  // alignment. For now, only memory index 0 is allowed.
  ExpectValidates(sigs.i_v(), {WASM_ZERO, kExprI32LoadMem, 0x40 /* alignment */,
                               0 /* memory index */, 0 /* offset */});
  // The memory index is LEB-encoded, so index 0 can also be store in 5 bytes.
  ExpectValidates(sigs.i_v(), {WASM_ZERO, kExprI32LoadMem, 0x40 /* alignment */,
                               U32V_5(0) /* memory index */, 0 /* offset */});
  // Memory index 1 is invalid.
  ExpectFailure(sigs.i_v(), {WASM_ZERO, kExprI32LoadMem, 0x40 /* alignment */,
                             1 /* memory index */, 0 /* offset */});
  // Add another memory; memory index 1 should be valid then.
  builder.AddMemory();
  ExpectValidates(sigs.i_v(), {WASM_ZERO, kExprI32LoadMem, 0x40 /* alignment */,
                               1 /* memory index */, 0 /* offset */});
  // Memory index 2 is still invalid.
  ExpectFailure(sigs.i_v(), {WASM_ZERO, kExprI32LoadMem, 0x40 /* alignment */,
                             2 /* memory index */, 0 /* offset */});
}

/*******************************************************************************
 * Table64.
 ******************************************************************************/

class FunctionBodyDecoderTestTable64
    : public FunctionBodyDecoderTestBase<
          WithDefaultPlatformMixin<::testing::TestWithParam<AddressType>>> {
 public:
  FunctionBodyDecoderTestTable64() {
    if (is_table64()) enabled_features_.Add(WasmEnabledFeature::memory64);
  }

  bool is_table32() const { return GetParam() == AddressType::kI32; }
  bool is_table64() const { return GetParam() == AddressType::kI64; }
};

INSTANTIATE_TEST_SUITE_P(Table64Tests, FunctionBodyDecoderTestTable64,
                         ::testing::Values(AddressType::kI32,
                                           AddressType::kI64),
                         PrintAddressType);

TEST_P(FunctionBodyDecoderTestTable64, Table64Set) {
  AddressType address_type = GetParam();
  uint8_t tab_ref1 =
      builder.AddTable(kWasmExternRef, 10, true, 20, address_type);
  uint8_t tab_func1 =
      builder.AddTable(kWasmFuncRef, 20, true, 30, address_type);

  ValueType sig_types[]{kWasmExternRef, kWasmFuncRef};
  FunctionSig sig(0, 2, sig_types);
  uint8_t local_ref = 0;
  uint8_t local_func = 1;

  Validate(is_table64(), &sig,
           {WASM_TABLE_SET(tab_ref1, WASM_I64V(6), WASM_LOCAL_GET(local_ref))});
  Validate(
      is_table64(), &sig,
      {WASM_TABLE_SET(tab_func1, WASM_I64V(7), WASM_LOCAL_GET(local_func))});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64Get) {
  AddressType address_type = GetParam();
  uint8_t tab_ref1 =
      builder.AddTable(kWasmExternRef, 10, true, 20, address_type);
  uint8_t tab_func1 =
      builder.AddTable(kWasmFuncRef, 20, true, 30, address_type);

  ValueType sig_types[]{kWasmExternRef, kWasmFuncRef};
  FunctionSig sig(0, 2, sig_types);
  uint8_t local_ref = 0;
  uint8_t local_func = 1;

  Validate(is_table64(), &sig,
           {WASM_LOCAL_SET(local_ref, WASM_TABLE_GET(tab_ref1, WASM_I64V(6)))});
  Validate(
      is_table64(), &sig,
      {WASM_LOCAL_SET(local_func, WASM_TABLE_GET(tab_func1, WASM_I64V(5)))});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64CallIndirect) {
  AddressType address_type = GetParam();
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(kWasmFuncRef, 20, false, 20, address_type);

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_v());
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());

  Validate(is_table64(), sig, {WASM_CALL_INDIRECT(sig0, WASM_ZERO64)});
  Validate(is_table64(), sig,
           {WASM_CALL_INDIRECT(sig1, WASM_I32V_1(22), WASM_ZERO64)});
  Validate(is_table64(), sig,
           {WASM_CALL_INDIRECT(sig2, WASM_I32V_1(32), WASM_I32V_2(72),
                               WASM_ZERO64)});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64ReturnCallIndirect) {
  AddressType address_type = GetParam();
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(kWasmFuncRef, 20, true, 30, address_type);

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_v());
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());

  Validate(is_table64(), sig, {WASM_RETURN_CALL_INDIRECT(sig0, WASM_ZERO64)});
  Validate(is_table64(), sig,
           {WASM_RETURN_CALL_INDIRECT(sig1, WASM_I32V_1(22), WASM_ZERO64)});
  Validate(is_table64(), sig,
           {WASM_RETURN_CALL_INDIRECT(sig2, WASM_I32V_1(32), WASM_I32V_2(72),
                                      WASM_ZERO64)});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64Grow) {
  AddressType address_type = GetParam();
  uint8_t tab_func = builder.AddTable(kWasmFuncRef, 10, true, 20, address_type);
  uint8_t tab_ref =
      builder.AddTable(kWasmExternRef, 10, true, 20, address_type);

  Validate(
      is_table64(), sigs.l_c(),
      {WASM_TABLE_GROW(tab_func, WASM_REF_NULL(kFuncRefCode), WASM_ONE64)});
  Validate(
      is_table64(), sigs.l_a(),
      {WASM_TABLE_GROW(tab_ref, WASM_REF_NULL(kExternRefCode), WASM_ONE64)});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64Size) {
  AddressType address_type = GetParam();
  int tab = builder.AddTable(kWasmFuncRef, 10, true, 20, address_type);
  Validate(is_table64(), sigs.l_v(), {WASM_TABLE_SIZE(tab)});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64Fill) {
  AddressType address_type = GetParam();
  uint8_t tab_func = builder.AddTable(kWasmFuncRef, 10, true, 20, address_type);
  uint8_t tab_ref =
      builder.AddTable(kWasmExternRef, 10, true, 20, address_type);
  Validate(is_table64(), sigs.v_c(),
           {WASM_TABLE_FILL(tab_func, WASM_ONE64, WASM_REF_NULL(kFuncRefCode),
                            WASM_ONE64)});
  Validate(is_table64(), sigs.v_a(),
           {WASM_TABLE_FILL(tab_ref, WASM_ONE64, WASM_REF_NULL(kExternRefCode),
                            WASM_ONE64)});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64Init) {
  AddressType address_type = GetParam();
  uint8_t tab_func = builder.AddTable(kWasmFuncRef, address_type);
  uint8_t elem_seg = builder.AddPassiveElementSegment(wasm::kWasmFuncRef);

  Validate(
      is_table64(), sigs.v_v(),
      {WASM_TABLE_INIT(tab_func, elem_seg, WASM_ZERO64, WASM_ZERO, WASM_ZERO)});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64Copy) {
  AddressType address_type = GetParam();
  uint8_t table = builder.AddTable(wasm::kWasmVoid, address_type);

  Validate(
      is_table64(), sigs.v_v(),
      {WASM_TABLE_COPY(table, table, WASM_ZERO64, WASM_ZERO64, WASM_ZERO64)});
}

TEST_P(FunctionBodyDecoderTestTable64, Table64CopyDifferentTypes) {
  AddressType address_type = GetParam();
  AddressType other_table_type =
      is_table64() ? AddressType::kI32 : AddressType::kI64;
  uint8_t table = builder.AddTable(wasm::kWasmVoid, address_type);
  uint8_t other_table = builder.AddTable(wasm::kWasmVoid, other_table_type);

  // Copy from `table` to `other_table` with types i32/i64/i32. Valid if `table`
  // is table64 (and hence `other_table` is table32).
  Validate(
      is_table64(), sigs.v_v(),
      {WASM_TABLE_COPY(other_table, table, WASM_ZERO, WASM_ZERO64, WASM_ZERO)},
      kAppendEnd);
  // Copy from `table` to `other_table` with types i64/i32/i32. Valid if `table`
  // is table32 (and hence `other_table` is table64).
  Validate(
      is_table32(), sigs.v_v(),
      {WASM_TABLE_COPY(other_table, table, WASM_ZERO64, WASM_ZERO, WASM_ZERO)},
      kAppendEnd);
  // Passing the size as i64 is always invalid because one table is always 32
  // bit.
  ExpectFailure(
      sigs.v_v(),
      {WASM_TABLE_COPY(other_table, table, WASM_ZERO, WASM_ZERO64,
                       WASM_ZERO64)},
      kAppendEnd,
      is_table64()
          ? "table.copy[2] expected type i32, found i64.const of type i64"
          : "table.copy[0] expected type i64, found i32.const of type i32");
  ExpectFailure(
      sigs.v_v(),
      {WASM_TABLE_COPY(other_table, table, WASM_ZERO64, WASM_ZERO,
                       WASM_ZERO64)},
      kAppendEnd,
      is_table32()
          ? "table.copy[2] expected type i32, found i64.const of type i64"
          : "table.copy[0] expected type i32, found i64.const of type i64");
}

#undef B1
#undef B2
#undef B3
#undef WASM_IF_OP
#undef WASM_LOOP_OP
#undef WASM_BRV_IF_ZERO
#undef EXPECT_OK

}  // namespace v8::internal::wasm
```