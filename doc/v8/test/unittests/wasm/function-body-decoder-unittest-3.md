Response: The user wants a summary of the functionality of the C++ source code file `v8/test/unittests/wasm/function-body-decoder-unittest.cc`. This is the fourth part of a four-part file.

Based on the content provided, this part of the file contains a comprehensive suite of unit tests for the WebAssembly function body decoder in V8. These tests verify the correct decoding of various WebAssembly opcodes, including:

* **Opcode Length Tests:** Tests the number of bytes occupied by different opcodes and their operands (immediate values). This includes tests for fixed-length opcodes, variable-length opcodes (with LEB128 encoded immediates), load/store operations, memory-related instructions, simple expressions, and SIMD instructions.
* **Illegal Opcode Tests:**  Tests that the decoder correctly handles and identifies illegal or invalid opcode sequences, like invalid reference indices.
* **GCOpcode Tests:** Specifically tests decoding of garbage collection related opcodes.
* **Prefixed Opcode Tests:** Tests opcodes that are prefixed by special bytes to extend the opcode space.
* **Heap Type Decoding Tests:**  Tests the correct decoding of different heap types used in WebAssembly's type system.
* **Local Declaration Decoding Tests:** Tests the logic for decoding local variable declarations within a function body, including handling different data types and combinations of local variables. It also includes a test using an encoder to generate local declarations and verifying the decoder can read them.
* **Bytecode Iterator Tests:** Tests the functionality of an iterator that helps navigate through the bytecode of a WebAssembly function body.
* **Memory64 Tests:**  Tests related to the `memory64` feature, including handling 64-bit memory addresses and offsets for load, store, size, and grow operations. It also covers `memory.copy` instructions between memories of different address types (32-bit and 64-bit).
* **Multi-memory Tests:** Tests the decoding of memory access instructions when multiple memories are present, focusing on how the memory index is encoded.
* **Table64 Tests:**  Tests related to the `table64` feature, verifying the correct decoding of instructions that operate on tables with 64-bit indices, such as `table.set`, `table.get`, `call_indirect`, `return_call_indirect`, `table.grow`, `table.size`, `table.fill`, `table.init`, and `table.copy`. It also includes tests for copying between tables with different address types (32-bit and 64-bit).

Since this is the last of four parts, it's likely this part contains more advanced or specialized test cases compared to the earlier parts. The file uses a test fixture approach (`TEST_F`) and helper functions like `ExpectLength`, `ExpectFailure`, and `Validate` to structure and assert the correctness of the decoding process.
这个C++源代码文件是V8 JavaScript引擎中WebAssembly功能的一部分，专门用于测试 **函数体解码器 (Function Body Decoder)** 的功能。由于这是第4部分，可以推断前面几部分可能已经涵盖了基础的解码测试。

这部分代码着重于更高级和特定的解码测试，主要涵盖以下几个方面：

**1. 操作码长度测试 (Opcode Length Tests):**
   - 针对不同的WebAssembly指令（操作码），测试解码器是否能够正确识别指令及其操作数所占用的字节数。
   - 包括了固定长度的操作码和可变长度的操作码（使用LEB128编码表示立即数）。
   - 涵盖了各种指令类型，如常量加载 (I32Const, I64Const)、全局变量访问 (GlobalGet)、函数引用 (RefFunc)、表操作 (TableGet, TableSet)、间接调用 (CallIndirect)、加载和存储操作 (LoadsAndStores)、内存操作 (MemorySize, MemoryGrow)、简单表达式 (SimpleExpressions)、SIMD指令 (SimdExpressions) 等。

**2. 非法操作码测试 (Illegal Opcode Tests):**
   - 测试解码器对于非法的或格式错误的操作码的处理能力，例如无效的引用索引。

**3. 垃圾回收操作码测试 (GCOpcodes):**
   - 专门测试与垃圾回收相关的WebAssembly操作码的解码，例如类型转换指令 (`br_on_cast`, `br_on_cast_fail`) 和结构体操作指令 (`struct.new`) 以及字符串操作 (`string.new_utf8`, `string.as_wtf8`)。

**4. 前缀操作码测试 (Prefixed Opcodes Tests):**
   - 测试解码器对使用前缀字节扩展指令集的操作码的解码，例如SIMD指令和一些特殊的转换指令 (`kExprI32SConvertSatF32`) 和原子操作指令 (`kExprAtomicNotify`)。

**5. 堆类型解码测试 (HeapType Decoding Test):**
   - 测试解码器是否能够正确解析表示堆类型的字节序列，例如函数引用类型 (`funcref`)。

**6. 局部变量声明解码测试 (Local Decl Decoder Test):**
   - 测试解码器如何解析函数体内的局部变量声明，包括变量的数量和类型。
   - 包含了空局部变量声明、无局部变量声明、单个局部变量、多个局部变量以及混合类型局部变量的测试。
   - 还测试了使用编码器生成局部变量声明，然后用解码器解析的能力。
   - 涵盖了 `exnref` 类型（异常引用）以及无效类型索引的处理。

**7. 字节码迭代器测试 (Bytecode Iterator Test):**
   - 测试用于迭代函数体字节码的迭代器类的功能，例如遍历操作码和偏移量。

**8. Memory64 特性测试 (Memory64 tests):**
   - 专门测试启用了 `memory64` 特性后，解码器对涉及64位内存地址的操作的处理，包括加载、存储、内存大小、内存增长等操作。
   - 测试了在 `memory32` 和 `memory64` 模式下的不同行为。
   - 包含了跨不同内存类型的 `memory.copy` 指令的测试。

**9. 多内存特性测试 (Multi-memory tests):**
   - 测试当存在多个内存实例时，解码器如何处理内存访问指令，特别是内存索引的解码。

**10. Table64 特性测试 (Table64):**
    - 专门测试启用了 `table64` 特性后，解码器对涉及64位表索引的操作的处理，包括 `table.set`, `table.get`, `call_indirect`, `return_call_indirect`, `table.grow`, `table.size`, `table.fill`, `table.init`, `table.copy` 等操作。
    - 测试了在 `table32` 和 `table64` 模式下的不同行为。
    - 包含了跨不同表类型的 `table.copy` 指令的测试.

总而言之，这部分代码是 `function-body-decoder-unittest.cc` 文件中针对 WebAssembly 函数体解码器进行全面而深入的单元测试的最后一部分，涵盖了各种高级特性和边界情况，确保解码器能够正确、可靠地解析各种合法的 WebAssembly 函数体字节码，并能够正确处理非法的输入。通过这些测试，可以保证 V8 引擎在执行 WebAssembly 代码时的正确性和安全性。

Prompt: ```这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能
这是第4部分，共4部分，请归纳一下它的功能

"""
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

"""

```