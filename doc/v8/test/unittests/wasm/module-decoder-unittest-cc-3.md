Response:
My thinking process to arrive at the summary of the provided C++ code goes like this:

1. **Identify the core purpose:** The filename `module-decoder-unittest.cc` and the presence of `TEST_F` macros immediately signal that this is a unit test file. The "module-decoder" part strongly suggests it's testing the WebAssembly module decoding process in V8.

2. **Scan for key classes and methods:**  I look for the class names used in the `TEST_F` macros. `WasmSignatureDecodeTest`, `WasmFunctionVerifyTest`, and `WasmModuleVerifyTest` stand out. These likely correspond to different aspects of the module decoding process being tested. The presence of `DecodeSig`, `DecodeWasmFunction`, and `DecodeModule` reinforces this.

3. **Analyze each test suite individually:**

   * **`WasmSignatureDecodeTest`:** The test names like `Ok_v_v`, `Ok_i_i`, `Ok_ii_i`, `Ok_i_ii`, `Ok_tt_tt`, and the use of `SIG_ENTRY_*` macros clearly indicate that this suite focuses on testing the decoding of WebAssembly function signatures. The assertions within the tests (`EXPECT_EQ` for parameter and return counts and types) confirm this. Tests like `Simd`, `TooManyParams`, `TooManyReturns`, and the "Fail_" prefixed tests show the testing of edge cases and error conditions in signature decoding.

   * **`WasmFunctionVerifyTest`:** The `DecodeWasmFunction` method name and the `Ok_v_v_empty` test name point to testing the decoding of individual WebAssembly functions. The test case examines the decoding of local variables and the function body.

   * **`WasmModuleVerifyTest`:** This suite is the largest and most varied. The test names reveal a broad range of module structure elements being tested: sections (Type, Import, Export, Code, Data, Element, Custom, Name, Memory, Table), function bodies, and various error conditions like invalid section sizes, type codes, import/export table entries, and function body sizes. The tests with "Regression_" in their names indicate bug fixes being verified. The tests concerning `SourceMappingURLSection` and `MultipleNameSections` highlight the testing of specific metadata sections. Tests involving "PassiveDataSegment" and "ActiveElementSegmentWithElements" reveal tests for data and element segments within the module.

4. **Look for patterns and common themes:**  Across all the test suites, the consistent theme is verifying the correct decoding and validation of different parts of a WebAssembly module. The tests aim to ensure that valid modules are decoded successfully and invalid modules are rejected with appropriate errors.

5. **Connect to JavaScript functionality (if applicable):** The provided code is C++ unit tests for V8's internal WebAssembly decoding logic. While it doesn't directly involve JavaScript *code*, it tests the underlying mechanism that enables JavaScript to *run* WebAssembly. The examples I provided illustrate how the concepts being tested (function signatures, imports, exports) manifest in JavaScript when working with WebAssembly modules.

6. **Identify potential programming errors:** The tests often focus on boundary conditions, incorrect data formats, and exceeding limits. These directly translate to common errors developers might encounter when creating or manipulating WebAssembly modules manually or when tools generate incorrect output.

7. **Summarize the functionality:** Based on the analysis of the test suites and their individual tests, I can synthesize a concise summary of the file's purpose. I focus on the core activities: decoding and verifying WebAssembly modules, specifically testing signatures, functions, and various module sections, including error handling.

8. **Address the specific prompt questions:** Finally, I go through each point in the prompt and ensure my analysis and summary explicitly address them, including:

   * Whether it's Torque (it's C++).
   * Its relationship to JavaScript (indirectly, by enabling WebAssembly execution).
   * Providing JavaScript examples where relevant.
   * Giving examples of code logic inference with assumptions (like signature decoding).
   * Highlighting common programming errors.
   * Ensuring the summary captures the overall functionality.

By following these steps, I can systematically understand the purpose and functionality of a complex C++ test file like the one provided, even without in-depth knowledge of every single test case. The key is to identify the high-level objectives and the specific components being tested.
这是提供的 v8 源代码文件 `v8/test/unittests/wasm/module-decoder-unittest.cc` 的第 4 部分，它是一个 C++ 单元测试文件，用于测试 WebAssembly 模块解码器的功能。

**功能归纳:**

这部分代码主要测试了 V8 的 WebAssembly 模块解码器在处理不同 WebAssembly 模块结构和数据时的正确性，重点包括：

* **函数签名解码的健壮性：**  测试了各种有效的函数签名编码，包括不同参数和返回值类型的组合，以及 SIMD 类型的支持。同时，也测试了无效的签名编码，例如参数或返回值过多，使用了无效的类型代码等。
* **函数解码和验证：** 测试了对 WebAssembly 函数的解码，包括函数签名、局部变量声明和函数体。验证了空函数体的解码是否正确。
* **模块结构验证：** 测试了对 WebAssembly 模块各个部分的验证，包括：
    * **自定义段（Custom Section）：** 测试了对未知自定义段的处理，包括空的和包含数据的自定义段，以及自定义段长度的边界情况。
    * **导入表（Import Table）：** 测试了各种导入表的情况，包括空导入表、导入函数、导入全局变量，以及导入项中签名索引、模块名和名称的有效性。
    * **导出表（Export Table）：** 测试了各种导出表的情况，包括空导出表、导出函数，以及导出名称和函数索引的有效性。
    * **代码段（Code Section）：** 测试了函数体的解码和验证，包括函数体的大小限制，以及代码段和函数段数量不匹配的情况。
    * **名称段（Name Section）：** 测试了名称段的解析，尽管目前的测试似乎并没有严格验证名称段的内容。
    * **数据段（Data Section）：** 测试了被动数据段的解码和验证。
    * **元素段（Element Section）：** 测试了活动元素段的解码和验证，包括使用函数引用和 null 引用。
* **错误处理：**  大量测试用例专注于验证解码器在遇到格式错误、超出限制或无效数据时的错误处理机制，例如：
    * 段长度溢出或欠溢出。
    * 无效的类型代码。
    * 函数参数或返回值数量超出限制。
    * 导入/导出表中的无效索引或名称。
    * 函数体大小超出限制。
    * 代码段和函数段数量不匹配。

**关于 .tq 结尾:**

`v8/test/unittests/wasm/module-decoder-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

虽然这段代码是 C++，但它直接关系到 JavaScript 的 WebAssembly 功能。V8 引擎负责执行 JavaScript 代码，同时也支持 WebAssembly。这段代码测试的模块解码器是 V8 引擎中负责将 WebAssembly 二进制模块转换为 V8 可以理解和执行的内部表示的关键组件。

**JavaScript 示例:**

```javascript
// 假设有一个简单的 WebAssembly 模块的字节数组
const wasmBytes = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // Magic number (\0asm)
  0x01, 0x00, 0x00, 0x00, // Version 1
  0x01, 0x07,             // Type section, length 7
  0x01,                   // One function signature
  0x60,                   // Function signature
  0x00,                   // 0 parameters
  0x01,                   // 1 return value
  0x7f,                   // i32
  0x03, 0x02,             // Function section, length 2
  0x01,                   // One function
  0x00,                   // Signature index 0
  0x0a, 0x05,             // Code section, length 5
  0x01,                   // One function body
  0x03,                   // Body size 3
  0x01,                   // i32.const 1
  0x0f,                   // end
]);

// 加载 WebAssembly 模块
WebAssembly.instantiate(wasmBytes)
  .then(result => {
    console.log("WebAssembly module loaded successfully:", result.instance.exports);
  })
  .catch(error => {
    console.error("Failed to load WebAssembly module:", error);
  });
```

在这个例子中，`WebAssembly.instantiate()` 函数在内部会调用类似这段 C++ 代码中测试的模块解码器来解析 `wasmBytes`。如果 `wasmBytes` 中包含无效的结构（例如，无效的签名、段长度错误等），解码器将会抛出错误，导致 `WebAssembly.instantiate()` 的 Promise 被 reject。

**代码逻辑推理 (假设输入与输出):**

假设 `DecodeSig` 函数接收一个表示函数签名编码的字节数组。

**假设输入:** `data = { 0x60, 0x01, 0x7f, 0x01, 0x7e }`

* `0x60`: 函数类型标识符
* `0x01`: 1 个参数
* `0x7f`: i32 类型
* `0x01`: 1 个返回值
* `0x7e`: i64 类型

**预期输出:**  `FunctionSig` 对象，其 `parameter_count` 为 1，`return_count` 为 1，第一个参数类型为 `kWasmI32`，第一个返回值类型为 `kWasmI64`。

**涉及用户常见的编程错误:**

* **手动创建 WebAssembly 模块时字节编码错误：**  用户可能在手动构建 WebAssembly 模块的字节数组时，错误地编码了函数签名、段长度或类型代码。例如，使用了错误的类型标识符，或者计算的段长度不正确。这段代码中的 `Fail_invalid_type` 测试就模拟了这种情况。

  ```javascript
  // 错误的类型编码
  const badWasmBytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x03, 0x01, 0x60, 0xFF, // 0xFF 不是有效的类型代码
  ]);

  WebAssembly.instantiate(badWasmBytes).catch(e => {
    console.error("加载失败，因为类型编码错误:", e);
  });
  ```

* **生成的 WebAssembly 模块包含超出限制的结构：**  工具或代码生成器可能会生成参数或返回值数量超过 WebAssembly 规范限制的函数签名。`TooManyParams` 和 `TooManyReturns` 测试就涵盖了这类错误。

  ```javascript
  // 假设某个工具生成了参数过多的 WebAssembly 模块
  // 这段代码在实际中可能无法手动构建，因为规范限制了参数数量
  const tooManyParamsWasm = new Uint8Array([...]);

  WebAssembly.instantiate(tooManyParamsWasm).catch(e => {
    console.error("加载失败，因为参数过多:", e);
  });
  ```

* **段长度计算错误：**  在创建包含多个段的 WebAssembly 模块时，错误地计算某个段的长度会导致解码失败。`SectionWithoutNameLength` 和各种 `UnknownSectionOverflow`/`Underflow` 的测试就与此类错误相关。

**总结这部分的功能：**

这部分单元测试代码专注于验证 V8 引擎中 WebAssembly 模块解码器的正确性和健壮性。它涵盖了函数签名解码、函数解码、模块结构验证 (包括各种标准段和自定义段) 以及错误处理等多个方面。 通过大量的测试用例，确保解码器能够正确处理各种有效的 WebAssembly 模块，并且能够可靠地检测和报告无效的模块结构和数据，从而保证 V8 引擎能够安全有效地执行 WebAssembly 代码。

Prompt: 
```
这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/module-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
arraysize(kValueTypes); j++) {
      ValueTypePair p1_type = kValueTypes[j];
      const uint8_t data[] = {
          SIG_ENTRY_x_xx(kI32Code, p0_type.code, p1_type.code)};
      const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

      SCOPED_TRACE("Signature i32(" + p0_type.type.name() + ", " +
                   p1_type.type.name() + ")");
      ASSERT_TRUE(sig != nullptr);
      EXPECT_EQ(2u, sig->parameter_count());
      EXPECT_EQ(1u, sig->return_count());
      EXPECT_EQ(p0_type.type, sig->GetParam(0));
      EXPECT_EQ(p1_type.type, sig->GetParam(1));
    }
  }
}

TEST_F(WasmSignatureDecodeTest, Ok_tt_tt) {
  WASM_FEATURE_SCOPE(stringref);
  WASM_FEATURE_SCOPE(exnref);
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueTypePair p0_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueTypePair p1_type = kValueTypes[j];
      const uint8_t data[] = {SIG_ENTRY_xx_xx(p0_type.code, p1_type.code,
                                              p0_type.code, p1_type.code)};
      const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

      SCOPED_TRACE("p0 = " + p0_type.type.name() +
                   ", p1 = " + p1_type.type.name());
      ASSERT_TRUE(sig != nullptr);
      EXPECT_EQ(2u, sig->parameter_count());
      EXPECT_EQ(2u, sig->return_count());
      EXPECT_EQ(p0_type.type, sig->GetParam(0));
      EXPECT_EQ(p1_type.type, sig->GetParam(1));
      EXPECT_EQ(p0_type.type, sig->GetReturn(0));
      EXPECT_EQ(p1_type.type, sig->GetReturn(1));
    }
  }
}

TEST_F(WasmSignatureDecodeTest, Simd) {
  const uint8_t data[] = {SIG_ENTRY_x(kS128Code)};
  if (!CheckHardwareSupportsSimd()) {
    EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)))
        << "Type S128 should not be allowed on this hardware";
  } else {
    const FunctionSig* sig = DecodeSig(base::ArrayVector(data));
    ASSERT_TRUE(sig != nullptr);
    EXPECT_EQ(0u, sig->parameter_count());
    EXPECT_EQ(1u, sig->return_count());
    EXPECT_EQ(kWasmS128, sig->GetReturn());
  }
}

TEST_F(WasmSignatureDecodeTest, TooManyParams) {
  static const uint8_t data[] = {kWasmFunctionTypeCode,
                                 WASM_I32V_3(kV8MaxWasmFunctionParams + 1),
                                 kI32Code, 0};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

TEST_F(WasmSignatureDecodeTest, TooManyReturns) {
  for (int i = 0; i < 2; i++) {
    uint8_t data[] = {kWasmFunctionTypeCode, 0,
                      WASM_I32V_3(kV8MaxWasmFunctionReturns + 1), kI32Code};
    EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
  }
}

TEST_F(WasmSignatureDecodeTest, Fail_off_end) {
  uint8_t data[256];
  for (int p = 0; p <= 255; p = p + 1 + p * 3) {
    for (int i = 0; i <= p; i++) data[i] = kI32Code;
    data[0] = static_cast<uint8_t>(p);

    for (int i = 0; i < p + 1; i++) {
      // Should fall off the end for all signatures.
      EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
    }
  }
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_type) {
  uint8_t kInvalidType = 76;
  for (size_t i = 0;; i++) {
    uint8_t data[] = {SIG_ENTRY_x_xx(kI32Code, kI32Code, kI32Code)};
    if (i >= arraysize(data)) break;
    data[i] = kInvalidType;
    EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
  }
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_ret_type1) {
  static const uint8_t data[] = {SIG_ENTRY_x_x(kVoidCode, kI32Code)};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_param_type1) {
  static const uint8_t data[] = {SIG_ENTRY_x_x(kI32Code, kVoidCode)};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_param_type2) {
  static const uint8_t data[] = {SIG_ENTRY_x_xx(kI32Code, kI32Code, kVoidCode)};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

class WasmFunctionVerifyTest : public TestWithIsolateAndZone {
 public:
  FunctionResult DecodeWasmFunction(
      ModuleWireBytes wire_bytes, const WasmModule* module,
      base::Vector<const uint8_t> function_bytes) {
    return DecodeWasmFunctionForTesting(WasmEnabledFeatures::All(), zone(),
                                        wire_bytes, module, function_bytes);
  }
};

TEST_F(WasmFunctionVerifyTest, Ok_v_v_empty) {
  static const uint8_t data[] = {
      SIG_ENTRY_v_v,  // signature entry
      4,              // locals
      3,
      kI32Code,  // --
      4,
      kI64Code,  // --
      5,
      kF32Code,  // --
      6,
      kF64Code,  // --
      kExprEnd   // body
  };

  WasmModule module;
  FunctionResult result =
      DecodeWasmFunction(ModuleWireBytes({}), &module, base::ArrayVector(data));
  EXPECT_OK(result);

  if (result.value() && result.ok()) {
    WasmFunction* function = result.value().get();
    EXPECT_EQ(0u, function->sig->parameter_count());
    EXPECT_EQ(0u, function->sig->return_count());
    EXPECT_EQ(COUNT_ARGS(SIG_ENTRY_v_v), function->code.offset());
    EXPECT_EQ(sizeof(data), function->code.end_offset());
    // TODO(titzer): verify encoding of local declarations
  }
}

TEST_F(WasmModuleVerifyTest, SectionWithoutNameLength) {
  const uint8_t data[] = {1};
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, EmptyCustomSectionIsInvalid) {
  // An empty custom section is invalid, because at least one byte for the
  // length of the custom section name is required.
  const uint8_t data[] = {
      0,  // unknown section code.
      0   // section length.
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, TheLoneliestOfValidModulesTheTrulyEmptyOne) {
  const uint8_t data[] = {
      0,  // unknown section code.
      1,  // section length, only one byte for the name length.
      0,  // string length of 0.
          // Empty section name, no content, nothing but sadness.
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, OnlyUnknownSectionEmpty) {
  const uint8_t data[] = {
      UNKNOWN_SECTION(0),
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, OnlyUnknownSectionNonEmpty) {
  const uint8_t data[] = {
      UNKNOWN_SECTION(5),
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,  // section data
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, SignatureFollowedByEmptyUnknownSection) {
  const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // -----------------------------------------------------------
      UNKNOWN_SECTION(0)};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, SignatureFollowedByUnknownSection) {
  const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // -----------------------------------------------------------
      UNKNOWN_SECTION(5),
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, UnknownSectionOverflow) {
  static const uint8_t data[] = {
      UNKNOWN_SECTION(9),
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,  // 10 byte section
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, UnknownSectionUnderflow) {
  static const uint8_t data[] = {
      UNKNOWN_SECTION(333),
      1,
      2,
      3,
      4,  // 4 byte section
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, UnknownSectionSkipped) {
  static const uint8_t data[] = {
      UNKNOWN_SECTION(1),
      0,  // one byte section
      SECTION(Global, ENTRY_COUNT(1),
              kI32Code,                    // memory type
              0,                           // exported
              WASM_INIT_EXPR_I32V_1(33)),  // init
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->globals.size());
  EXPECT_EQ(0u, result.value()->functions.size());
  EXPECT_EQ(0u, result.value()->data_segments.size());

  const WasmGlobal* global = &result.value()->globals.back();

  EXPECT_EQ(kWasmI32, global->type);
  EXPECT_EQ(0u, global->offset);
}

TEST_F(WasmModuleVerifyTest, ImportTable_empty) {
  static const uint8_t data[] = {SECTION(Type, ENTRY_COUNT(0)),
                                 SECTION(Import, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_nosigs1) {
  static const uint8_t data[] = {SECTION(Import, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_mutable_global) {
  {
    static const uint8_t data[] = {
        SECTION(Import,           // section header
                ENTRY_COUNT(1),   // number of imports
                ADD_COUNT('m'),   // module name
                ADD_COUNT('f'),   // global name
                kExternalGlobal,  // import kind
                kI32Code,         // type
                0),               // mutability
    };
    EXPECT_VERIFIES(data);
  }
  {
    static const uint8_t data[] = {
        SECTION(Import,           // section header
                ENTRY_COUNT(1),   // sig table
                ADD_COUNT('m'),   // module name
                ADD_COUNT('f'),   // global name
                kExternalGlobal,  // import kind
                kI32Code,         // type
                1),               // mutability
    };
    EXPECT_VERIFIES(data);
  }
}

TEST_F(WasmModuleVerifyTest, ImportTable_mutability_malformed) {
  static const uint8_t data[] = {
      SECTION(Import,
              ENTRY_COUNT(1),   // --
              ADD_COUNT('m'),   // module name
              ADD_COUNT('g'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              2),               // invalid mutability
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_nosigs2) {
  static const uint8_t data[] = {
      SECTION(Import, ENTRY_COUNT(1),  // sig table
              ADD_COUNT('m'),          // module name
              ADD_COUNT('f'),          // function name
              kExternalFunction,       // import kind
              SIG_INDEX(0)),           // sig index
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_invalid_sig) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(0)),   // --
      SECTION(Import, ENTRY_COUNT(1),  // --
              ADD_COUNT('m'),          // module name
              ADD_COUNT('f'),          // function name
              kExternalFunction,       // import kind
              SIG_INDEX(0)),           // sig index
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_one_sig) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Import,
              ENTRY_COUNT(1),     // --
              ADD_COUNT('m'),     // module name
              ADD_COUNT('f'),     // function name
              kExternalFunction,  // import kind
              SIG_INDEX(0)),      // sig index
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_invalid_module) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,  // --
      SECTION(Import,                  // --
              ENTRY_COUNT(1),          // --
              NO_NAME,                 // module name
              ADD_COUNT('f'),          // function name
              kExternalFunction,       // import kind
              SIG_INDEX(0),            // sig index
              0),                      // auxiliary data
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_off_end) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Import, ENTRY_COUNT(1),
              ADD_COUNT('m'),      // module name
              ADD_COUNT('f'),      // function name
              kExternalFunction),  // import kind
      SIG_INDEX(0),                // sig index (outside import section!)
  };

  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 3);
}

TEST_F(WasmModuleVerifyTest, ExportTable_empty1) {
  static const uint8_t data[] = {                                 // signatures
                                 TYPE_SECTION_ONE_SIG_VOID_VOID,  // --
                                 ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
                                 SECTION(Export, ENTRY_COUNT(0)),  // --
                                 ONE_EMPTY_BODY};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->functions.size());
  EXPECT_EQ(0u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportTable_empty2) {
  static const uint8_t data[] = {SECTION(Type, ENTRY_COUNT(0)),
                                 SECTION(Export, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ExportTable_NoFunctions2) {
  static const uint8_t data[] = {SECTION(Export, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ExportTableOne) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(1),     // exports
              NO_NAME,            // --
              kExternalFunction,  // --
              FUNC_INDEX(0)),     // --
      ONE_EMPTY_BODY};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->functions.size());
  EXPECT_EQ(1u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportNameWithInvalidStringLength) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(1),     // exports
              U32V_1(84),         // invalid string length
              'e',                // --
              kExternalFunction,  // --
              FUNC_INDEX(0),      // --
              0, 0, 0)            // auxiliary data
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ExportTableTwo) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(2),                 // exports
              ADD_COUNT('n', 'a', 'm', 'e'),  // --
              kExternalFunction,              // --
              FUNC_INDEX(0),                  // --
              ADD_COUNT('n', 'o', 'm'),       // --
              kExternalFunction,              // --
              FUNC_INDEX(0)),                 // --
      ONE_EMPTY_BODY};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->functions.size());
  EXPECT_EQ(2u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportTableThree) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, THREE_EMPTY_FUNCTIONS(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(3),  // exports
              ADD_COUNT('a'),  // --
              kExternalFunction,
              FUNC_INDEX(0),   // --
              ADD_COUNT('b'),  // --
              kExternalFunction,
              FUNC_INDEX(1),   // --
              ADD_COUNT('c'),  // --
              kExternalFunction,
              FUNC_INDEX(2)),  // --
      THREE_EMPTY_BODIES};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(3u, result.value()->functions.size());
  EXPECT_EQ(3u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportTableThreeOne) {
  for (int i = 0; i < 6; i++) {
    const uint8_t data[] = {
        // signatures
        TYPE_SECTION_ONE_SIG_VOID_VOID, THREE_EMPTY_FUNCTIONS(SIG_INDEX(0)),
        SECTION(Export,
                ENTRY_COUNT(1),       // exports
                ADD_COUNT('e', 'x'),  // --
                kExternalFunction,
                FUNC_INDEX(i)),  // --
        THREE_EMPTY_BODIES};

    if (i < 3) {
      EXPECT_VERIFIES(data);
    } else {
      EXPECT_FAILURE(data);
    }
  }
}

TEST_F(WasmModuleVerifyTest, ExportTableOne_off_end) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(1),  // exports
              NO_NAME,         // --
              kExternalFunction,
              FUNC_INDEX(0),  // --
              0, 0, 0)        // auxiliary data
  };

  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 3);
}

TEST_F(WasmModuleVerifyTest, Regression_648070) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(0)),         // --
      SECTION(Function, U32V_5(3500228624))  // function count = 3500228624
  };                                         // --
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, Regression_738097) {
  // The function body size caused an integer overflow in the module decoder.
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
      FUNCTION_SECTION(1, 0),          // --
      SECTION(Code,                    // --
              ENTRY_COUNT(1),          // --
              U32V_5(0xFFFFFFFF),      // function size,
              0)                       // No real body
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodySizeLimit) {
  const uint32_t delta = 3;
  for (uint32_t body_size = kV8MaxWasmFunctionSize - delta;
       body_size < kV8MaxWasmFunctionSize + delta; body_size++) {
    uint8_t data[] = {
        TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
        FUNCTION_SECTION(1, 0),          // --
        kCodeSectionCode,                // code section
        U32V_5(1 + body_size + 5),       // section size
        1,                               // # functions
        U32V_5(body_size)                // body size
    };
    size_t total = sizeof(data) + body_size;
    uint8_t* buffer = reinterpret_cast<uint8_t*>(calloc(1, total));
    memcpy(buffer, data, sizeof(data));
    ModuleResult result = DecodeModule(base::VectorOf(buffer, total));
    if (body_size <= kV8MaxWasmFunctionSize) {
      EXPECT_TRUE(result.ok());
    } else {
      EXPECT_FALSE(result.ok());
    }
    free(buffer);
  }
}

TEST_F(WasmModuleVerifyTest, IllegalTypeCode) {
  static const uint8_t data[] = {TYPE_SECTION(1, SIG_ENTRY_v_x(0x41))};
  EXPECT_FAILURE_WITH_MSG(data, "invalid value type");
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_empty) {
  static const uint8_t data[] = {
      EMPTY_TYPE_SECTION,            // --
      EMPTY_FUNCTION_SECTION,        // --
      EMPTY_FUNCTION_BODIES_SECTION  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_one_empty) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
      FUNCTION_SECTION(1, 0),          // --
      ONE_EMPTY_BODY                   // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_one_nop) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),          // --
      FUNCTION_SECTION(1, 0),                  // --
      SECTION(Code, ENTRY_COUNT(1), NOP_BODY)  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_count_mismatch1) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
      FUNCTION_SECTION(2, 0, 0),       // --
      ONE_EMPTY_BODY                   // --
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_count_mismatch2) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),                    // --
      FUNCTION_SECTION(1, 0),                            // --
      SECTION(Code, ENTRY_COUNT(2), NOP_BODY, NOP_BODY)  // --
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, Names_empty) {
  static const uint8_t data[] = {EMPTY_TYPE_SECTION, EMPTY_FUNCTION_SECTION,
                                 EMPTY_FUNCTION_BODIES_SECTION,
                                 EMPTY_NAMES_SECTION};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Names_one_empty) {
  // TODO(wasm): This test does not test anything (corrupt name section does not
  // fail validation).
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),                            // --
      FUNCTION_SECTION(1, 0),                                    // --
      ONE_EMPTY_BODY,                                            // --
      SECTION_NAMES(ENTRY_COUNT(1), FOO_STRING, NO_LOCAL_NAMES)  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Names_two_empty) {
  // TODO(wasm): This test does not test anything (corrupt name section does not
  // fail validation).
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),             // --
      FUNCTION_SECTION(2, 0, 0),                  // --
      TWO_EMPTY_BODIES,                           // --
      SECTION_NAMES(ENTRY_COUNT(2),               // --
                    FOO_STRING, NO_LOCAL_NAMES,   // --
                    FOO_STRING, NO_LOCAL_NAMES),  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Regression684855) {
  static const uint8_t data[] = {
      SECTION_NAMES(0xFB,  // functions count
                    0x27,  // |
                    0x00,  // function name length
                    0xFF,  // local names count
                    0xFF,  // |
                    0xFF,  // |
                    0xFF,  // |
                    0xFF,  // |
                    0xFF,  // error: "varint too large"
                    0xFF,  // |
                    0x00,  // --
                    0x00)  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionSectionWithoutCodeSection) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // Type section.
      FUNCTION_SECTION(1, 0),          // Function section.
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "function count is 1, but code section is absent");
}

TEST_F(WasmModuleVerifyTest, CodeSectionWithoutFunctionSection) {
  static const uint8_t data[] = {ONE_EMPTY_BODY};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "function body count 1 mismatch (0 expected)");
}

TEST_F(WasmModuleVerifyTest, EmptyFunctionSectionWithoutCodeSection) {
  static const uint8_t data[] = {SECTION(Function, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, DoubleNonEmptyFunctionSection) {
  // Regression test for https://crbug.com/1342274.
  static const uint8_t data[] = {TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
                                 FUNCTION_SECTION(1, 0),          // --
                                 FUNCTION_SECTION(1, 0)};
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, EmptyCodeSectionWithoutFunctionSection) {
  static const uint8_t data[] = {SECTION(Code, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

// TODO(manoskouk): Reintroduce tests deleted in
// https://chromium-review.googlesource.com/c/v8/v8/+/2972910 in some other
// form.

TEST_F(WasmModuleVerifyTest, Multiple_Named_Sections) {
  static const uint8_t data[] = {
      SECTION(Unknown, ADD_COUNT('X'), 17, 18),                    // --
      SECTION(Unknown, ADD_COUNT('f', 'o', 'o'), 5, 6, 7, 8, 9),   // --
      SECTION(Unknown, ADD_COUNT('o', 't', 'h', 'e', 'r'), 7, 8),  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Section_Name_No_UTF8) {
  static const uint8_t data[] = {SECTION(Unknown, 1, 0xFF, 17, 18)};
  EXPECT_FAILURE(data);
}

class WasmModuleCustomSectionTest : public TestWithIsolateAndZone {
 public:
  void CheckSections(base::Vector<const uint8_t> wire_bytes,
                     const CustomSectionOffset* expected, size_t num_expected) {
    std::vector<CustomSectionOffset> custom_sections =
        DecodeCustomSections(wire_bytes);

    CHECK_EQ(num_expected, custom_sections.size());

    for (size_t i = 0; i < num_expected; i++) {
      EXPECT_EQ(expected[i].section.offset(),
                custom_sections[i].section.offset());
      EXPECT_EQ(expected[i].section.length(),
                custom_sections[i].section.length());
      EXPECT_EQ(expected[i].name.offset(), custom_sections[i].name.offset());
      EXPECT_EQ(expected[i].name.length(), custom_sections[i].name.length());
      EXPECT_EQ(expected[i].payload.offset(),
                custom_sections[i].payload.offset());
      EXPECT_EQ(expected[i].payload.length(),
                custom_sections[i].payload.length());
    }
  }
};

TEST_F(WasmModuleCustomSectionTest, ThreeUnknownSections) {
  static constexpr uint8_t data[] = {
      U32_LE(kWasmMagic),                                  // --
      U32_LE(kWasmVersion),                                // --
      SECTION(Unknown, 1, 'X', 17, 18),                    // --
      SECTION(Unknown, 3, 'f', 'o', 'o', 5, 6, 7, 8, 9),   // --
      SECTION(Unknown, 5, 'o', 't', 'h', 'e', 'r', 7, 8),  // --
  };

  static const CustomSectionOffset expected[] = {
      // section, name, payload
      {{10, 4}, {11, 1}, {12, 2}},  // --
      {{16, 9}, {17, 3}, {20, 5}},  // --
      {{27, 8}, {28, 5}, {33, 2}},  // --
  };

  CheckSections(base::ArrayVector(data), expected, arraysize(expected));
}

TEST_F(WasmModuleCustomSectionTest, TwoKnownTwoUnknownSections) {
  static const uint8_t data[] = {
      U32_LE(kWasmMagic),                                          // --
      U32_LE(kWasmVersion),                                        // --
      TYPE_SECTION(2, SIG_ENTRY_v_v, SIG_ENTRY_v_v),               // --
      SECTION(Unknown, ADD_COUNT('X'), 17, 18),                    // --
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),                            // --
      SECTION(Unknown, ADD_COUNT('o', 't', 'h', 'e', 'r'), 7, 8),  // --
  };

  static const CustomSectionOffset expected[] = {
      // section, name, payload
      {{19, 4}, {20, 1}, {21, 2}},  // --
      {{29, 8}, {30, 5}, {35, 2}},  // --
  };

  CheckSections(base::ArrayVector(data), expected, arraysize(expected));
}

TEST_F(WasmModuleVerifyTest, SourceMappingURLSection) {
  static const uint8_t data[] = {
      WASM_MODULE_HEADER,
      SECTION_SRC_MAP('s', 'r', 'c', '/', 'x', 'y', 'z', '.', 'c')};
  ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(3u, result.value()->debug_symbols.size());
  EXPECT_EQ(
      WasmDebugSymbols::Type::SourceMap,
      result.value()->debug_symbols[WasmDebugSymbols::Type::SourceMap].type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::EmbeddedDWARF]
                .type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::ExternalDWARF]
                .type);
  ModuleWireBytes wire_bytes(base::ArrayVector(data));
  WasmName external_url = wire_bytes.GetNameOrNull(
      result.value()
          ->debug_symbols[WasmDebugSymbols::Type::SourceMap]
          .external_url);
  EXPECT_EQ("src/xyz.c", std::string(external_url.data(), external_url.size()));
}

TEST_F(WasmModuleVerifyTest, BadSourceMappingURLSection) {
  static const uint8_t data[] = {
      WASM_MODULE_HEADER,
      SECTION_SRC_MAP('s', 'r', 'c', '/', 'x', 0xff, 'z', '.', 'c')};
  ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(3u, result.value()->debug_symbols.size());
  for (size_t i = 0; i < result.value()->debug_symbols.size(); ++i) {
    EXPECT_EQ(WasmDebugSymbols::Type::None,
              result.value()->debug_symbols[i].type);
    EXPECT_EQ(0u, result.value()->debug_symbols[i].external_url.length());
  }
}

TEST_F(WasmModuleVerifyTest, MultipleSourceMappingURLSections) {
  static const uint8_t data[] = {WASM_MODULE_HEADER,
                                 SECTION_SRC_MAP('a', 'b', 'c'),
                                 SECTION_SRC_MAP('p', 'q', 'r')};
  ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(
      WasmDebugSymbols::Type::SourceMap,
      result.value()->debug_symbols[WasmDebugSymbols::Type::SourceMap].type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::EmbeddedDWARF]
                .type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::ExternalDWARF]
                .type);
  ModuleWireBytes wire_bytes(base::ArrayVector(data));
  WasmName external_url = wire_bytes.GetNameOrNull(
      result.value()
          ->debug_symbols[WasmDebugSymbols::Type::SourceMap]
          .external_url);
  EXPECT_EQ("abc", std::string(external_url.data(), external_url.size()));
}

TEST_F(WasmModuleVerifyTest, MultipleNameSections) {
  static const uint8_t data[] = {
      SECTION_NAMES(0, ADD_COUNT(ADD_COUNT('a', 'b', 'c'))),
      SECTION_NAMES(0, ADD_COUNT(ADD_COUNT('p', 'q', 'r', 's')))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(3u, result.value()->name.length());
}

TEST_F(WasmModuleVerifyTest, BadNameSection) {
  static const uint8_t data[] = {SECTION_NAMES(
      0, ADD_COUNT(ADD_COUNT('s', 'r', 'c', '/', 'x', 0xff, 'z', '.', 'c')))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(0u, result.value()->name.length());
}

TEST_F(WasmModuleVerifyTest, PassiveDataSegment) {
  static const uint8_t data[] = {
      // memory declaration ----------------------------------------------------
      SECTION(Memory, ENTRY_COUNT(1), kNoMaximum, 1),
      // data segments  --------------------------------------------------------
      SECTION(Data, ENTRY_COUNT(1), PASSIVE, ADD_COUNT('h', 'i')),
  };
  EXPECT_VERIFIES(data);
  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 5);
}

TEST_F(WasmModuleVerifyTest, ActiveElementSegmentWithElements) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration -----------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // element segments  -----------------------------------------------------
      SECTION(Element, ENTRY_COUNT(1), ACTIVE_WITH_ELEMENTS, TABLE_INDEX0,
              WASM_INIT_EXPR_I32V_1(0), kFuncRefCode, U32V_1(3),
              REF_FUNC_ELEMENT(0), REF_FUNC_ELEMENT(0), REF_NULL_ELEMENT),
      // code ------------------------------------------------------------------
      ONE_EMPTY_BODY};
  EXPECT_VERIFIES(data);
  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 5);
}

TEST_F(WasmModuleVerifyTest, Table64ActiveElementSegmentWithElements) {
  WASM_FEATURE_SCOPE(memory64);
  for (bool enable_table64 : {false, true}) {
    for (bool use_table64 : {false, true}) {
      uint8_t const_opcode = use_table64 ? kExprI64Const : kExprI32Const;
      const uint8_t data[] = {
          // sig#0 -------------------------------------------------------
          TYPE_SECTION_ONE_SIG_VOID_VOID,
          // funcs -------------------------------------------------------
          ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
          // table declaration -------------------------------------------
          SECTION(Table, ENTRY_COUNT(1), kFuncRefCode,
                  enable_table64 ? kMemory64WithMaximum : kWithMaximum, 20, 28),
          // element segments --------------------------------------------
          SECTION(Element, ENTRY_COUNT(1), ACTIVE_WITH_ELEMENTS, TABLE_INDEX0,
                  const_opcode, 0, kExprEnd, kFuncRefCode, U32V_1(3),
                  REF_FUNC_ELEMENT(0), REF_FUNC_ELEMENT(0), REF_NULL_ELEMENT),
          // code --------------------------------------------------------
          ONE_EMPTY_BODY};
      if (enable_table64 == use_table64) {
        EXPECT_VERIFIES(data);
      } else if (enable_table64) {
        EXPECT_FAILURE_WITH_MSG(data, "expected i64, got i32");
      } else {
        EXPECT_FAILURE_WITH_MSG(data, "expected i32, got i64");
      }
    }
  }
}

TEST_F(WasmModuleVerifyTest, PassiveElementSegment) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
      
"""


```