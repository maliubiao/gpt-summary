Response: The user wants a summary of the functionality of the provided C++ source code file. The file is named `function-body-decoder-unittest.cc` and is located within the V8 project's test suite. This strongly suggests it's a unit test file for a component responsible for decoding the bodies of WebAssembly functions.

Here's a breakdown of the code to understand its purpose:

1. **Includes:** The file includes various headers related to WebAssembly within the V8 project, such as `function-body-decoder.h`, `wasm-module.h`, `wasm-opcodes-inl.h`, and `leb-helper.h`. This confirms its connection to WebAssembly decoding. It also includes testing-related headers like `gmock-support.h` and `test-utils.h`.

2. **Namespaces:** It operates within the `v8::internal::wasm` namespace.

3. **Macros:** It defines several macros like `B1`, `B2`, `B3` for creating block structures, `WASM_IF_OP`, `WASM_LOOP_OP` for if and loop opcodes, and `EXPECT_OK` for checking test results. These macros simplify the writing of test cases.

4. **Static Data:** It defines static arrays like `kCodeGetLocal0`, `kCodeSetLocal0`, `kValueTypes`, `machineTypes`, and `kInt32BinopOpcodes`. These are likely used as input or expected values in the unit tests.

5. **`TestModuleBuilder` Class:** This class helps in constructing mock WebAssembly module environments. It allows adding globals, signatures, functions, imports, tables, memories, etc., which are necessary for testing the decoder in various scenarios.

6. **`FunctionBodyDecoderTestBase` Class:** This is the core test fixture. It inherits from `WithZoneMixin` and provides utilities for:
   - Preparing bytecode sequences, including adding local variable declarations.
   - Validating bytecode against a given function signature.
   - Expecting validation to succeed or fail.
   - Helper functions for testing binary and unary operations.

7. **Test Cases (`TEST_F` macros):** The bulk of the file consists of individual test cases using the `TEST_F` macro. Each test case focuses on verifying the `FunctionBodyDecoder`'s behavior for specific WebAssembly instructions or combinations of instructions. These tests cover various scenarios like:
   - Basic instruction decoding (e.g., `i32.const`, `local.get`).
   - Control flow instructions (`block`, `if`, `loop`, `br`).
   - Local variable operations (`local.set`, `local.tee`).
   - Memory access instructions (`memory.size`, `i32.load`, `i32.store`).
   - Function calls (`call`, `return_call`).
   - Type conversions.
   - Handling of unreachable code.
   - Error conditions (invalid bytecode, type mismatches, etc.).

**In summary, the C++ code file `function-body-decoder-unittest.cc` is a unit test suite for the WebAssembly function body decoder in the V8 JavaScript engine. It comprehensively tests the decoder's ability to correctly process various WebAssembly instructions and handle different valid and invalid bytecode sequences.**

Now, let's consider the relationship with JavaScript.

The `FunctionBodyDecoder` is a core component within the V8 engine that is responsible for taking the raw byte stream of a WebAssembly function's body and interpreting it. This interpretation is necessary for V8 to execute the WebAssembly code. JavaScript itself doesn't directly interact with the `FunctionBodyDecoder`. Instead, when JavaScript code loads and instantiates a WebAssembly module, V8 internally uses components like the `FunctionBodyDecoder` to parse and prepare the WebAssembly functions for execution.

Here's a conceptual example in JavaScript to illustrate the connection:

```javascript
// Assume 'wasmCode' is a Uint8Array containing the bytecode of a WebAssembly module.

WebAssembly.instantiate(wasmCode)
  .then(module => {
    // At this point, the WebAssembly module has been successfully loaded and
    // instantiated. Internally, V8's FunctionBodyDecoder has been used to
    // process the bytecode of the functions within the module.

    // Now you can call the exported functions of the module.
    let result = module.instance.exports.add(5, 10);
    console.log(result); // Output: 15
  });
```

**Explanation of the JavaScript example's connection to the C++ code:**

1. **`WebAssembly.instantiate(wasmCode)`:** This JavaScript API call initiates the process of loading and compiling the WebAssembly bytecode.

2. **Internal V8 Processing:**  During the `instantiate` process, V8 (the JavaScript engine) performs several steps, including:
   - **Parsing the module structure:** Identifying sections like the code section.
   - **Decoding function bodies:** When it encounters the code section, for each function, V8 invokes the `FunctionBodyDecoder` (the C++ component being tested in the provided file).
   - **Validation:** The `FunctionBodyDecoder` (along with other components) validates the bytecode to ensure it conforms to the WebAssembly specification. This validation process is what the C++ unit tests are specifically exercising.
   - **Compilation or Interpretation:**  After successful decoding and validation, V8 proceeds to compile the WebAssembly code into machine code or prepares it for interpretation.

3. **`module.instance.exports.add(5, 10)`:** When the JavaScript code calls the `add` function exported from the WebAssembly module, the V8 engine executes the previously decoded and processed WebAssembly instructions for that function.

Therefore, while JavaScript doesn't directly call into the `FunctionBodyDecoder`, the correct functioning of this C++ component is crucial for JavaScript's ability to load, validate, and execute WebAssembly code. The unit tests in `function-body-decoder-unittest.cc` ensure the robustness and correctness of this critical part of the WebAssembly implementation in V8.

这是文件 `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 的第一部分，它是一个 C++ 源代码文件，专门用于测试 WebAssembly 函数体解码器的功能。

**主要功能归纳:**

1. **单元测试框架:**  这个文件使用了 Google Test (gtest) 框架来编写单元测试。它定义了一个测试夹具 `FunctionBodyDecoderTest`，用于组织和执行与函数体解码器相关的测试用例。

2. **测试 WebAssembly 指令解码:**  文件中包含了大量的测试用例（以 `TEST_F` 宏定义），每个测试用例针对 WebAssembly 规范中的不同指令或指令组合，验证解码器是否能够正确地识别、解析和理解这些指令。

3. **验证字节码的有效性:**  测试用例不仅测试了正确的字节码序列，也测试了各种错误的或不完整的字节码序列，以确保解码器能够正确地报告错误。这包括：
    - 指令参数不足或超出范围。
    - 类型不匹配的操作。
    - 控制流结构不完整或错误。

4. **模拟 WebAssembly 模块环境:**  `TestModuleBuilder` 类用于创建一个简化的 WebAssembly 模块环境，允许测试用例定义函数签名、局部变量、全局变量等，从而更真实地模拟解码器在实际场景中的工作。

5. **测试不同的数据类型:**  测试用例覆盖了 WebAssembly 支持的各种数据类型 (i32, i64, f32, f64, ref 等)，确保解码器能够正确处理不同类型的操作。

6. **测试控制流指令:**  重点测试了 `block`、`if`、`loop` 等控制流指令，包括它们的嵌套、分支和返回值。

7. **测试局部变量操作:**  测试了 `local.get`、`local.set`、`local.tee` 等操作局部变量的指令。

8. **测试常量加载:**  测试了加载不同类型的常量 (`i32.const`, `f32.const` 等) 的指令。

9. **使用宏简化测试:**  定义了许多宏（如 `WASM_BLOCK`, `WASM_IF`, `WASM_LOCAL_SET` 等）来简化编写 WebAssembly 字节码序列的过程，提高了测试用例的可读性和编写效率。

**与 Javascript 的关系 (举例说明):**

WebAssembly 代码通常由 Javascript 加载和执行。V8 (Chrome 的 Javascript 引擎) 负责执行这个过程。`FunctionBodyDecoder` 是 V8 内部的一个组件，负责解析 WebAssembly 函数的二进制代码，使其可以被 V8 理解和执行。

**Javascript 示例:**

假设我们有一个简单的 WebAssembly 模块，其中包含一个将两个数字相加的函数：

```wat
(module
  (func $add (param $p1 i32) (param $p2 i32) (result i32)
    local.get $p1
    local.get $p2
    i32.add
  )
  (export "add" (func $add))
)
```

编译成二进制的 WebAssembly 代码后，V8 在执行以下 Javascript 代码时会用到 `FunctionBodyDecoder`:

```javascript
fetch('my_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const addFunction = results.instance.exports.add;
    const sum = addFunction(5, 10);
    console.log(sum); // 输出 15
  });
```

**解释:**

1. **`fetch('my_module.wasm')`:**  Javascript 代码获取 WebAssembly 模块的二进制数据。
2. **`WebAssembly.instantiate(bytes)`:**  这个函数调用会触发 V8 内部的 WebAssembly 处理流程。
3. **`FunctionBodyDecoder` 的作用:**  当 V8 解析 `my_module.wasm` 的代码段时，`FunctionBodyDecoder` 会被用来解码 `$add` 函数的字节码：
   - `local.get $p1`  会被解码为获取第一个局部变量 (对应参数 `$p1`)。
   - `local.get $p2`  会被解码为获取第二个局部变量 (对应参数 `$p2`)。
   - `i32.add`       会被解码为执行 32 位整数加法操作。
4. **执行:**  解码后的指令会被 V8 进一步编译或解释执行，最终完成 `addFunction(5, 10)` 的计算。

因此，`function-body-decoder-unittest.cc` 中的测试用例正是为了确保 V8 的 `FunctionBodyDecoder` 组件能够正确地解码像 `local.get` 和 `i32.add` 这样的 WebAssembly 指令，从而保证 Javascript 能够成功加载和执行 WebAssembly 代码。

总而言之，这个文件的主要功能是提供一个全面的单元测试套件，用于验证 V8 引擎中 WebAssembly 函数体解码器的正确性和健壮性。这对于确保 V8 能够可靠地执行 WebAssembly 代码至关重要。

Prompt: ```这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/function-body-decoder.h"

#include "src/flags/flags.h"
#include "src/utils/ostreams.h"
#include "src/wasm/canonical-types.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/local-decl-encoder.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"
#include "src/zone/zone.h"
#include "test/common/flag-utils.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"

namespace v8::internal::wasm {

#define B1(a) WASM_BLOCK(a)
#define B2(a, b) WASM_BLOCK(a, b)
#define B3(a, b, c) WASM_BLOCK(a, b, c)

#define WASM_IF_OP kExprIf, kVoidCode
#define WASM_LOOP_OP kExprLoop, kVoidCode

#define EXPECT_OK(result)                                        \
  do {                                                           \
    if (!result.ok()) {                                          \
      GTEST_NONFATAL_FAILURE_(result.error().message().c_str()); \
      return;                                                    \
    }                                                            \
  } while (false)

static const uint8_t kCodeGetLocal0[] = {kExprLocalGet, 0};
static const uint8_t kCodeGetLocal1[] = {kExprLocalGet, 1};
static const uint8_t kCodeSetLocal0[] = {WASM_LOCAL_SET(0, WASM_ZERO)};
static const uint8_t kCodeTeeLocal0[] = {WASM_LOCAL_TEE(0, WASM_ZERO)};

static const ValueType kValueTypes[] = {kWasmI32, kWasmI64, kWasmF32, kWasmF64,
                                        kWasmExternRef};
static const MachineType machineTypes[] = {
    MachineType::Int8(),   MachineType::Uint8(),  MachineType::Int16(),
    MachineType::Uint16(), MachineType::Int32(),  MachineType::Uint32(),
    MachineType::Int64(),  MachineType::Uint64(), MachineType::Float32(),
    MachineType::Float64()};

static const WasmOpcode kInt32BinopOpcodes[] = {
    kExprI32Add,  kExprI32Sub,  kExprI32Mul,  kExprI32DivS, kExprI32DivU,
    kExprI32RemS, kExprI32RemU, kExprI32And,  kExprI32Ior,  kExprI32Xor,
    kExprI32Shl,  kExprI32ShrU, kExprI32ShrS, kExprI32Eq,   kExprI32LtS,
    kExprI32LeS,  kExprI32LtU,  kExprI32LeU};

#define WASM_BRV_IF_ZERO(depth, val) \
  val, WASM_ZERO, kExprBrIf, static_cast<uint8_t>(depth)

constexpr size_t kMaxByteSizedLeb128 = 127;

using F = std::pair<ValueType, bool>;

// Used to construct fixed-size signatures: MakeSig::Returns(...).Params(...);
using MakeSig = FixedSizeSignature<ValueType>;

// A helper for tests that require a module environment for functions,
// globals, or memories.
class TestModuleBuilder {
 public:
  explicit TestModuleBuilder(ModuleOrigin origin = kWasmOrigin) : mod(origin) {
    mod.num_declared_functions = 1;
    mod.validated_functions = std::make_unique<std::atomic<uint8_t>[]>(1);
    // Asm.js functions are valid by design.
    if (is_asmjs_module(&mod)) mod.validated_functions[0] = 0xff;
  }
  uint8_t AddGlobal(ValueType type, bool mutability = true) {
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    mod.globals.push_back({type, mutability, {}, {0}, kIsShared, false, false});
    CHECK_LE(mod.globals.size(), kMaxByteSizedLeb128);
    return static_cast<uint8_t>(mod.globals.size() - 1);
  }
  ModuleTypeIndex AddSignature(const FunctionSig* sig,
                               ModuleTypeIndex supertype = kNoSuperType) {
    const bool is_final = true;
    const bool is_shared = false;
    mod.AddSignatureForTesting(sig, supertype, is_final, is_shared);
    CHECK_LE(mod.types.size(), kMaxByteSizedLeb128);
    GetTypeCanonicalizer()->AddRecursiveSingletonGroup(module());
    return ModuleTypeIndex{static_cast<uint8_t>(mod.types.size() - 1)};
  }
  uint8_t AddFunction(const FunctionSig* sig, bool declared = true) {
    ModuleTypeIndex sig_index = AddSignature(sig);
    return AddFunctionImpl(sig, sig_index, declared);
  }
  uint8_t AddFunction(ModuleTypeIndex sig_index, bool declared = true) {
    DCHECK(mod.has_signature(sig_index));
    return AddFunctionImpl(mod.type(sig_index).function_sig, sig_index,
                           declared);
  }
  uint8_t AddImport(const FunctionSig* sig) {
    uint8_t result = AddFunction(sig);
    mod.functions[result].imported = true;
    return result;
  }
  uint8_t AddException(WasmTagSig* sig) {
    mod.tags.emplace_back(sig, AddSignature(sig));
    CHECK_LE(mod.types.size(), kMaxByteSizedLeb128);
    return static_cast<uint8_t>(mod.tags.size() - 1);
  }

  uint8_t AddTable(ValueType type, uint32_t initial_size, bool has_maximum_size,
                   uint32_t maximum_size,
                   AddressType address_type = AddressType::kI32) {
    CHECK(type.is_object_reference());
    mod.tables.emplace_back();
    WasmTable& table = mod.tables.back();
    table.type = type;
    table.initial_size = initial_size;
    table.has_maximum_size = has_maximum_size;
    table.maximum_size = maximum_size;
    table.address_type = address_type;
    return static_cast<uint8_t>(mod.tables.size() - 1);
  }

  ModuleTypeIndex AddStruct(std::initializer_list<F> fields,
                            ModuleTypeIndex supertype = kNoSuperType) {
    StructType::Builder type_builder(&mod.signature_zone,
                                     static_cast<uint32_t>(fields.size()));
    for (F field : fields) {
      type_builder.AddField(field.first, field.second);
    }
    const bool is_final = true;
    const bool is_shared = false;
    mod.AddStructTypeForTesting(type_builder.Build(), supertype, is_final,
                                is_shared);
    GetTypeCanonicalizer()->AddRecursiveSingletonGroup(module());
    return ModuleTypeIndex{static_cast<uint8_t>(mod.types.size() - 1)};
  }

  ModuleTypeIndex AddArray(ValueType type, bool mutability) {
    ArrayType* array = mod.signature_zone.New<ArrayType>(type, mutability);
    const bool is_final = true;
    const bool is_shared = false;
    mod.AddArrayTypeForTesting(array, kNoSuperType, is_final, is_shared);
    GetTypeCanonicalizer()->AddRecursiveSingletonGroup(module());
    return ModuleTypeIndex{static_cast<uint8_t>(mod.types.size() - 1)};
  }

  uint8_t AddMemory(AddressType address_type = AddressType::kI32) {
    mod.memories.push_back(WasmMemory{.initial_pages = 1,
                                      .maximum_pages = 100,
                                      .address_type = address_type});
    CHECK_GE(kMaxUInt8, mod.memories.size());
    return static_cast<uint8_t>(mod.memories.size() - 1);
  }

  uint8_t AddTable(wasm::ValueType type,
                   AddressType address_type = AddressType::kI32) {
    mod.tables.push_back(WasmTable{.type = type, .address_type = address_type});
    CHECK_GE(kMaxUInt8, mod.tables.size());
    return static_cast<uint8_t>(mod.tables.size() - 1);
  }

  uint8_t AddPassiveElementSegment(wasm::ValueType type) {
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    mod.elem_segments.emplace_back(WasmElemSegment::kStatusPassive, kIsShared,
                                   type, WasmElemSegment::kExpressionElements,
                                   0, 0);
    return static_cast<uint8_t>(mod.elem_segments.size() - 1);
  }

  uint8_t AddDeclarativeElementSegment() {
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    mod.elem_segments.emplace_back(WasmElemSegment::kStatusDeclarative,
                                   kIsShared, kWasmFuncRef,
                                   WasmElemSegment::kExpressionElements, 0, 0);
    return static_cast<uint8_t>(mod.elem_segments.size() - 1);
  }

  // Set the number of data segments as declared by the DataCount section.
  void SetDataSegmentCount(uint32_t data_segment_count) {
    // The Data section occurs after the Code section, so we don't need to
    // update mod.data_segments, as it is always empty.
    mod.num_declared_data_segments = data_segment_count;
  }

  WasmModule* module() { return &mod; }

 private:
  uint8_t AddFunctionImpl(const FunctionSig* sig, ModuleTypeIndex sig_index,
                          bool declared) {
    mod.functions.push_back(
        {sig,                                          // sig
         static_cast<uint32_t>(mod.functions.size()),  // func_index
         sig_index,                                    // sig_index
         {0, 0},                                       // code
         false,                                        // import
         false,                                        // export
         declared});                                   // declared
    CHECK_LE(mod.functions.size(), kMaxByteSizedLeb128);
    return static_cast<uint8_t>(mod.functions.size() - 1);
  }

  WasmModule mod;
};

template <class BaseTest>
class FunctionBodyDecoderTestBase : public WithZoneMixin<BaseTest> {
 public:
  using LocalsDecl = std::pair<uint32_t, ValueType>;
  // All features are disabled by default and must be activated with
  // a WASM_FEATURE_SCOPE in individual tests.
  WasmEnabledFeatures enabled_features_ = WasmEnabledFeatures::None();

  TestSignatures sigs;
  TestModuleBuilder builder;
  WasmModule* module = builder.module();
  LocalDeclEncoder local_decls{this->zone()};

  void AddLocals(ValueType type, uint32_t count) {
    local_decls.AddLocals(count, type);
  }

  enum AppendEnd : bool { kAppendEnd, kOmitEnd };

  base::Vector<const uint8_t> PrepareBytecode(base::Vector<const uint8_t> code,
                                              AppendEnd append_end) {
    size_t locals_size = local_decls.Size();
    size_t total_size =
        code.size() + locals_size + (append_end == kAppendEnd ? 1 : 0);
    uint8_t* buffer = this->zone()->template AllocateArray<uint8_t>(total_size);
    // Prepend the local decls to the code.
    local_decls.Emit(buffer);
    // Emit the code.
    if (code.size() > 0) {
      memcpy(buffer + locals_size, code.begin(), code.size());
    }
    if (append_end == kAppendEnd) {
      // Append an extra end opcode.
      buffer[total_size - 1] = kExprEnd;
    }

    return {buffer, total_size};
  }

  template <size_t N>
  base::Vector<const uint8_t> CodeToVector(const uint8_t (&code)[N]) {
    return base::ArrayVector(code);
  }

  base::Vector<const uint8_t> CodeToVector(
      const std::initializer_list<const uint8_t>& code) {
    return base::VectorOf(&*code.begin(), code.size());
  }

  base::Vector<const uint8_t> CodeToVector(base::Vector<const uint8_t> vec) {
    return vec;
  }

  // Prepends local variable declarations and renders nice error messages for
  // verification failures.
  template <typename Code = std::initializer_list<const uint8_t>>
  void Validate(bool expected_success, const FunctionSig* sig, Code&& raw_code,
                AppendEnd append_end = kAppendEnd,
                const char* message = nullptr) {
    base::Vector<const uint8_t> code =
        PrepareBytecode(CodeToVector(std::forward<Code>(raw_code)), append_end);

    // Validate the code.
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    FunctionBody body(sig, 0, code.begin(), code.end(), kIsShared);
    WasmDetectedFeatures unused_detected_features;
    DecodeResult result =
        ValidateFunctionBody(this->zone(), enabled_features_, module,
                             &unused_detected_features, body);

    std::ostringstream str;
    if (result.failed()) {
      str << "Verification failed: pc = +" << result.error().offset()
          << ", msg = " << result.error().message();
    } else {
      str << "Verification succeeded, expected failure";
    }
    EXPECT_EQ(result.ok(), expected_success) << str.str();
    if (result.failed() && message) {
      EXPECT_THAT(result.error().message(), ::testing::HasSubstr(message));
    }
  }

  template <typename Code = std::initializer_list<const uint8_t>>
  void ExpectValidates(const FunctionSig* sig, Code&& raw_code,
                       AppendEnd append_end = kAppendEnd,
                       const char* message = nullptr) {
    Validate(true, sig, std::forward<Code>(raw_code), append_end, message);
  }

  template <typename Code = std::initializer_list<const uint8_t>>
  void ExpectFailure(const FunctionSig* sig, Code&& raw_code,
                     AppendEnd append_end = kAppendEnd,
                     const char* message = nullptr) {
    Validate(false, sig, std::forward<Code>(raw_code), append_end, message);
  }

  void TestBinop(WasmOpcode opcode, const FunctionSig* success) {
    // op(local[0], local[1])
    uint8_t code[] = {WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))};
    ExpectValidates(success, code);

    // Try all combinations of return and parameter types.
    for (size_t i = 0; i < arraysize(kValueTypes); i++) {
      for (size_t j = 0; j < arraysize(kValueTypes); j++) {
        for (size_t k = 0; k < arraysize(kValueTypes); k++) {
          ValueType types[] = {kValueTypes[i], kValueTypes[j], kValueTypes[k]};
          if (types[0] != success->GetReturn(0) ||
              types[1] != success->GetParam(0) ||
              types[2] != success->GetParam(1)) {
            // Test signature mismatch.
            FunctionSig sig(1, 2, types);
            ExpectFailure(&sig, code);
          }
        }
      }
    }
  }

  void TestUnop(WasmOpcode opcode, const FunctionSig* success) {
    TestUnop(opcode, success->GetReturn(), success->GetParam(0));
  }

  void TestUnop(WasmOpcode opcode, ValueType ret_type, ValueType param_type) {
    // Return(op(local[0]))
    uint8_t code[] = {WASM_UNOP(opcode, WASM_LOCAL_GET(0))};
    {
      ValueType types[] = {ret_type, param_type};
      FunctionSig sig(1, 1, types);
      ExpectValidates(&sig, code);
    }

    // Try all combinations of return and parameter types.
    for (size_t i = 0; i < arraysize(kValueTypes); i++) {
      for (size_t j = 0; j < arraysize(kValueTypes); j++) {
        ValueType types[] = {kValueTypes[i], kValueTypes[j]};
        if (types[0] != ret_type || types[1] != param_type) {
          // Test signature mismatch.
          FunctionSig sig(1, 1, types);
          ExpectFailure(&sig, code);
        }
      }
    }
  }
};

using FunctionBodyDecoderTest = FunctionBodyDecoderTestBase<TestWithPlatform>;

TEST_F(FunctionBodyDecoderTest, Int32Const1) {
  uint8_t code[] = {kExprI32Const, 0};
  for (int i = -64; i <= 63; i++) {
    code[1] = static_cast<uint8_t>(i & 0x7F);
    ExpectValidates(sigs.i_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, RefFunc) {
  builder.AddFunction(sigs.v_ii());
  builder.AddFunction(sigs.ii_v());
  ExpectValidates(sigs.c_v(), {kExprRefFunc, 1});
}

TEST_F(FunctionBodyDecoderTest, EmptyFunction) {
  ExpectValidates(sigs.v_v(), {});
  ExpectFailure(sigs.i_i(), {});
}

TEST_F(FunctionBodyDecoderTest, IncompleteIf1) {
  uint8_t code[] = {kExprIf};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, Int32Const_fallthru) {
  ExpectValidates(sigs.i_i(), {WASM_I32V_1(0)});
}

TEST_F(FunctionBodyDecoderTest, Int32Const_fallthru2) {
  ExpectFailure(sigs.i_i(), {WASM_I32V_1(0), WASM_I32V_1(1)});
}

TEST_F(FunctionBodyDecoderTest, Int32Const) {
  const int kInc = 4498211;
  for (int32_t i = kMinInt; i < kMaxInt - kInc; i = i + kInc) {
    // TODO(binji): expand test for other sized int32s; 1 through 5 bytes.
    ExpectValidates(sigs.i_i(), {WASM_I32V(i)});
  }
}

TEST_F(FunctionBodyDecoderTest, Int64Const) {
  const int kInc = 4498211;
  for (int32_t i = kMinInt; i < kMaxInt - kInc; i = i + kInc) {
    ExpectValidates(sigs.l_l(),
                    {WASM_I64V((static_cast<uint64_t>(i) << 32) | i)});
  }
}

TEST_F(FunctionBodyDecoderTest, Float32Const) {
  uint8_t code[] = {kExprF32Const, 0, 0, 0, 0};
  Address ptr = reinterpret_cast<Address>(code + 1);
  for (int i = 0; i < 30; i++) {
    base::WriteLittleEndianValue<float>(ptr, i * -7.75f);
    ExpectValidates(sigs.f_ff(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, Float64Const) {
  uint8_t code[] = {kExprF64Const, 0, 0, 0, 0, 0, 0, 0, 0};
  Address ptr = reinterpret_cast<Address>(code + 1);
  for (int i = 0; i < 30; i++) {
    base::WriteLittleEndianValue<double>(ptr, i * 33.45);
    ExpectValidates(sigs.d_dd(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, Int32Const_off_end) {
  uint8_t code[] = {kExprI32Const, 0xAA, 0xBB, 0xCC, 0x44};

  for (size_t size = 1; size <= 4; ++size) {
    ExpectFailure(sigs.i_i(), base::VectorOf(code, size), kAppendEnd);
    // Should also fail without the trailing 'end' opcode.
    ExpectFailure(sigs.i_i(), base::VectorOf(code, size), kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, GetLocal0_param) {
  ExpectValidates(sigs.i_i(), kCodeGetLocal0);
}

TEST_F(FunctionBodyDecoderTest, GetLocal0_local) {
  AddLocals(kWasmI32, 1);
  ExpectValidates(sigs.i_v(), kCodeGetLocal0);
}

TEST_F(FunctionBodyDecoderTest, TooManyLocals) {
  AddLocals(kWasmI32, 4034986500);
  ExpectFailure(sigs.i_v(), kCodeGetLocal0);
}

TEST_F(FunctionBodyDecoderTest, GetLocal0_param_n) {
  for (const FunctionSig* sig : {sigs.i_i(), sigs.i_ii(), sigs.i_iii()}) {
    ExpectValidates(sig, kCodeGetLocal0);
  }
}

TEST_F(FunctionBodyDecoderTest, GetLocalN_local) {
  for (uint8_t i = 1; i < 8; i++) {
    AddLocals(kWasmI32, 1);
    for (uint8_t j = 0; j < i; j++) {
      ExpectValidates(sigs.i_v(), {kExprLocalGet, j});
    }
  }
}

TEST_F(FunctionBodyDecoderTest, GetLocal0_fail_no_params) {
  ExpectFailure(sigs.i_v(), kCodeGetLocal0);
}

TEST_F(FunctionBodyDecoderTest, GetLocal1_fail_no_locals) {
  ExpectFailure(sigs.i_i(), kCodeGetLocal1);
}

TEST_F(FunctionBodyDecoderTest, GetLocal_off_end) {
  ExpectFailure(sigs.i_i(), {kExprLocalGet});
}

TEST_F(FunctionBodyDecoderTest, NumLocalBelowLimit) {
  AddLocals(kWasmI32, kV8MaxWasmFunctionLocals - 1);
  ExpectValidates(sigs.v_v(), {WASM_NOP});
}

TEST_F(FunctionBodyDecoderTest, NumLocalAtLimit) {
  AddLocals(kWasmI32, kV8MaxWasmFunctionLocals);
  ExpectValidates(sigs.v_v(), {WASM_NOP});
}

TEST_F(FunctionBodyDecoderTest, NumLocalAboveLimit) {
  AddLocals(kWasmI32, kV8MaxWasmFunctionLocals + 1);
  ExpectFailure(sigs.v_v(), {WASM_NOP});
}

TEST_F(FunctionBodyDecoderTest, GetLocal_varint) {
  const int kMaxLocals = kV8MaxWasmFunctionLocals - 1;
  AddLocals(kWasmI32, kMaxLocals);

  ExpectValidates(sigs.i_i(), {kExprLocalGet, U32V_1(66)});
  ExpectValidates(sigs.i_i(), {kExprLocalGet, U32V_2(7777)});
  ExpectValidates(sigs.i_i(), {kExprLocalGet, U32V_3(8888)});
  ExpectValidates(sigs.i_i(), {kExprLocalGet, U32V_4(9999)});

  ExpectValidates(sigs.i_i(), {kExprLocalGet, U32V_5(kMaxLocals - 1)});

  ExpectFailure(sigs.i_i(), {kExprLocalGet, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});

  ExpectValidates(sigs.i_i(), {kExprLocalGet, U32V_4(kMaxLocals - 1)});
  ExpectValidates(sigs.i_i(), {kExprLocalGet, U32V_4(kMaxLocals)});
  ExpectFailure(sigs.i_i(), {kExprLocalGet, U32V_4(kMaxLocals + 1)});

  ExpectFailure(sigs.i_v(), {kExprLocalGet, U32V_4(kMaxLocals)});
  ExpectFailure(sigs.i_v(), {kExprLocalGet, U32V_4(kMaxLocals + 1)});
}

TEST_F(FunctionBodyDecoderTest, GetLocal_toomany) {
  AddLocals(kWasmI32, kV8MaxWasmFunctionLocals - 100);
  AddLocals(kWasmI32, 100);

  ExpectValidates(sigs.i_v(), {kExprLocalGet, U32V_1(66)});
  ExpectFailure(sigs.i_i(), {kExprLocalGet, U32V_1(66)});
}

TEST_F(FunctionBodyDecoderTest, Binops_off_end) {
  uint8_t code1[] = {0};  // [opcode]
  for (size_t i = 0; i < arraysize(kInt32BinopOpcodes); i++) {
    code1[0] = kInt32BinopOpcodes[i];
    ExpectFailure(sigs.i_i(), code1);
  }

  uint8_t code3[] = {kExprLocalGet, 0, 0};  // [expr] [opcode]
  for (size_t i = 0; i < arraysize(kInt32BinopOpcodes); i++) {
    code3[2] = kInt32BinopOpcodes[i];
    ExpectFailure(sigs.i_i(), code3);
  }

  uint8_t code4[] = {kExprLocalGet, 0, 0, 0};  // [expr] [opcode] [opcode]
  for (size_t i = 0; i < arraysize(kInt32BinopOpcodes); i++) {
    code4[2] = kInt32BinopOpcodes[i];
    code4[3] = kInt32BinopOpcodes[i];
    ExpectFailure(sigs.i_i(), code4);
  }
}

TEST_F(FunctionBodyDecoderTest, BinopsAcrossBlock1) {
  ExpectFailure(sigs.i_i(), {WASM_ZERO, kExprBlock, kI32Code, WASM_ZERO,
                             kExprI32Add, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, BinopsAcrossBlock2) {
  ExpectFailure(sigs.i_i(), {WASM_ZERO, WASM_ZERO, kExprBlock, kI32Code,
                             kExprI32Add, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, BinopsAcrossBlock3) {
  ExpectFailure(sigs.i_i(), {WASM_ZERO, WASM_ZERO, kExprIf, kI32Code,
                             kExprI32Add, kExprElse, kExprI32Add, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, Nop) {
  ExpectValidates(sigs.v_v(), {kExprNop});
}

TEST_F(FunctionBodyDecoderTest, SetLocal0_void) {
  ExpectFailure(sigs.i_i(), {WASM_LOCAL_SET(0, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, SetLocal0_param) {
  ExpectFailure(sigs.i_i(), kCodeSetLocal0);
  ExpectFailure(sigs.f_ff(), kCodeSetLocal0);
  ExpectFailure(sigs.d_dd(), kCodeSetLocal0);
}

TEST_F(FunctionBodyDecoderTest, TeeLocal0_param) {
  ExpectValidates(sigs.i_i(), kCodeTeeLocal0);
  ExpectFailure(sigs.f_ff(), kCodeTeeLocal0);
  ExpectFailure(sigs.d_dd(), kCodeTeeLocal0);
}

TEST_F(FunctionBodyDecoderTest, SetLocal0_local) {
  ExpectFailure(sigs.i_v(), kCodeSetLocal0);
  ExpectFailure(sigs.v_v(), kCodeSetLocal0);
  AddLocals(kWasmI32, 1);
  ExpectFailure(sigs.i_v(), kCodeSetLocal0);
  ExpectValidates(sigs.v_v(), kCodeSetLocal0);
}

TEST_F(FunctionBodyDecoderTest, TeeLocal0_local) {
  ExpectFailure(sigs.i_v(), kCodeTeeLocal0);
  AddLocals(kWasmI32, 1);
  ExpectValidates(sigs.i_v(), kCodeTeeLocal0);
}

TEST_F(FunctionBodyDecoderTest, TeeLocalN_local) {
  for (uint8_t i = 1; i < 8; i++) {
    AddLocals(kWasmI32, 1);
    for (uint8_t j = 0; j < i; j++) {
      ExpectFailure(sigs.v_v(), {WASM_LOCAL_TEE(j, WASM_I32V_1(i))});
      ExpectValidates(sigs.i_i(), {WASM_LOCAL_TEE(j, WASM_I32V_1(i))});
    }
  }
}

TEST_F(FunctionBodyDecoderTest, BlockN) {
  constexpr size_t kMaxSize = 200;
  uint8_t buffer[kMaxSize + 3];

  for (size_t i = 0; i <= kMaxSize; i++) {
    memset(buffer, kExprNop, sizeof(buffer));
    buffer[0] = kExprBlock;
    buffer[1] = kVoidCode;
    buffer[i + 2] = kExprEnd;
    ExpectValidates(sigs.v_i(), base::VectorOf(buffer, i + 3), kAppendEnd);
  }
}

#define WASM_EMPTY_BLOCK kExprBlock, kVoidCode, kExprEnd

TEST_F(FunctionBodyDecoderTest, Block0) {
  ExpectValidates(sigs.v_v(), {WASM_EMPTY_BLOCK});
  ExpectFailure(sigs.i_i(), {WASM_EMPTY_BLOCK});
}

TEST_F(FunctionBodyDecoderTest, Block0_fallthru1) {
  ExpectValidates(sigs.v_v(), {WASM_BLOCK(WASM_EMPTY_BLOCK)});
  ExpectFailure(sigs.i_i(), {WASM_BLOCK(WASM_EMPTY_BLOCK)});
}

TEST_F(FunctionBodyDecoderTest, Block0Block0) {
  ExpectValidates(sigs.v_v(), {WASM_EMPTY_BLOCK, WASM_EMPTY_BLOCK});
  ExpectFailure(sigs.i_i(), {WASM_EMPTY_BLOCK, WASM_EMPTY_BLOCK});
}

TEST_F(FunctionBodyDecoderTest, Block0_end) {
  ExpectFailure(sigs.v_v(), {WASM_EMPTY_BLOCK, kExprEnd});
}

#undef WASM_EMPTY_BLOCK

TEST_F(FunctionBodyDecoderTest, Block1) {
  uint8_t code[] = {WASM_BLOCK_I(WASM_LOCAL_GET(0))};
  ExpectValidates(sigs.i_i(), code);
  ExpectFailure(sigs.v_i(), code);
  ExpectFailure(sigs.d_dd(), code);
  ExpectFailure(sigs.i_f(), code);
  ExpectFailure(sigs.i_d(), code);
}

TEST_F(FunctionBodyDecoderTest, Block1_i) {
  uint8_t code[] = {WASM_BLOCK_I(WASM_ZERO)};
  ExpectValidates(sigs.i_i(), code);
  ExpectFailure(sigs.f_ff(), code);
  ExpectFailure(sigs.d_dd(), code);
  ExpectFailure(sigs.l_ll(), code);
}

TEST_F(FunctionBodyDecoderTest, Block1_f) {
  uint8_t code[] = {WASM_BLOCK_F(WASM_F32(0))};
  ExpectFailure(sigs.i_i(), code);
  ExpectValidates(sigs.f_ff(), code);
  ExpectFailure(sigs.d_dd(), code);
  ExpectFailure(sigs.l_ll(), code);
}

TEST_F(FunctionBodyDecoderTest, Block1_continue) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, Block1_br) {
  ExpectValidates(sigs.v_v(), {B1(WASM_BR(0))});
  ExpectValidates(sigs.v_v(), {B1(WASM_BR(1))});
  ExpectFailure(sigs.v_v(), {B1(WASM_BR(2))});
}

TEST_F(FunctionBodyDecoderTest, Block2_br) {
  ExpectValidates(sigs.v_v(), {B2(WASM_NOP, WASM_BR(0))});
  ExpectValidates(sigs.v_v(), {B2(WASM_BR(0), WASM_NOP)});
  ExpectValidates(sigs.v_v(), {B2(WASM_BR(0), WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, Block2) {
  ExpectFailure(sigs.i_i(), {WASM_BLOCK(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_i(), {WASM_BLOCK_I(WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.i_i(), {WASM_BLOCK_I(WASM_NOP, WASM_ZERO)});
  ExpectValidates(sigs.i_i(), {WASM_BLOCK_I(WASM_ZERO, WASM_NOP)});
  ExpectFailure(sigs.i_i(), {WASM_BLOCK_I(WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Block2b) {
  uint8_t code[] = {WASM_BLOCK_I(WASM_LOCAL_SET(0, WASM_ZERO), WASM_ZERO)};
  ExpectValidates(sigs.i_i(), code);
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.f_ff(), code);
}

TEST_F(FunctionBodyDecoderTest, Block2_fallthru) {
  ExpectValidates(sigs.i_i(), {B2(WASM_LOCAL_SET(0, WASM_ZERO),
                                  WASM_LOCAL_SET(0, WASM_ZERO)),
                               WASM_I32V_1(23)});
}

TEST_F(FunctionBodyDecoderTest, Block3) {
  ExpectValidates(sigs.i_i(), {WASM_BLOCK_I(WASM_LOCAL_SET(0, WASM_ZERO),
                                            WASM_LOCAL_SET(0, WASM_ZERO),
                                            WASM_I32V_1(11))});
}

TEST_F(FunctionBodyDecoderTest, Block5) {
  ExpectFailure(sigs.v_i(), {WASM_BLOCK(WASM_ZERO)});

  ExpectFailure(sigs.v_i(), {WASM_BLOCK(WASM_ZERO, WASM_ZERO)});

  ExpectFailure(sigs.v_i(), {WASM_BLOCK(WASM_ZERO, WASM_ZERO, WASM_ZERO)});

  ExpectFailure(sigs.v_i(),
                {WASM_BLOCK(WASM_ZERO, WASM_ZERO, WASM_ZERO, WASM_ZERO)});

  ExpectFailure(sigs.v_i(), {WASM_BLOCK(WASM_ZERO, WASM_ZERO, WASM_ZERO,
                                        WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, BlockType) {
  ExpectValidates(sigs.i_i(), {WASM_BLOCK_I(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.l_l(), {WASM_BLOCK_L(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.f_f(), {WASM_BLOCK_F(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.d_d(), {WASM_BLOCK_D(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, BlockType_fail) {
  ExpectFailure(sigs.i_i(), {WASM_BLOCK_L(WASM_I64V_1(0))}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.i_i(), {WASM_BLOCK_F(WASM_F32(0.0))}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.i_i(), {WASM_BLOCK_D(WASM_F64(1.1))}, kAppendEnd,
                "type error in fallthru[0]");

  ExpectFailure(sigs.l_l(), {WASM_BLOCK_I(WASM_ZERO)}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.l_l(), {WASM_BLOCK_F(WASM_F32(0.0))}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.l_l(), {WASM_BLOCK_D(WASM_F64(1.1))}, kAppendEnd,
                "type error in fallthru[0]");

  ExpectFailure(sigs.f_ff(), {WASM_BLOCK_I(WASM_ZERO)}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.f_ff(), {WASM_BLOCK_L(WASM_I64V_1(0))}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.f_ff(), {WASM_BLOCK_D(WASM_F64(1.1))}, kAppendEnd,
                "type error in fallthru[0]");

  ExpectFailure(sigs.d_dd(), {WASM_BLOCK_I(WASM_ZERO)}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.d_dd(), {WASM_BLOCK_L(WASM_I64V_1(0))}, kAppendEnd,
                "type error in fallthru[0]");
  ExpectFailure(sigs.d_dd(), {WASM_BLOCK_F(WASM_F32(0.0))}, kAppendEnd,
                "type error in fallthru[0]");
}

TEST_F(FunctionBodyDecoderTest, BlockF32) {
  static const uint8_t code[] = {WASM_BLOCK_F(kExprF32Const, 0, 0, 0, 0)};
  ExpectValidates(sigs.f_ff(), code);
  ExpectFailure(sigs.i_i(), code);
  ExpectFailure(sigs.d_dd(), code);
}

TEST_F(FunctionBodyDecoderTest, BlockN_off_end) {
  uint8_t code[] = {WASM_BLOCK(kExprNop, kExprNop, kExprNop, kExprNop)};
  ExpectValidates(sigs.v_v(), code);
  for (size_t i = 1; i < arraysize(code); i++) {
    ExpectFailure(sigs.v_v(), base::VectorOf(code, i), kAppendEnd);
    ExpectFailure(sigs.v_v(), base::VectorOf(code, i), kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, Block2_continue) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP, WASM_BR(0))});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP, WASM_BR(1))});
  ExpectFailure(sigs.v_v(), {WASM_LOOP(WASM_NOP, WASM_BR(2))});
}

TEST_F(FunctionBodyDecoderTest, Block3_continue) {
  ExpectValidates(sigs.v_v(), {B1(WASM_LOOP(WASM_NOP, WASM_BR(0)))});
  ExpectValidates(sigs.v_v(), {B1(WASM_LOOP(WASM_NOP, WASM_BR(1)))});
  ExpectValidates(sigs.v_v(), {B1(WASM_LOOP(WASM_NOP, WASM_BR(2)))});
  ExpectFailure(sigs.v_v(), {B1(WASM_LOOP(WASM_NOP, WASM_BR(3)))});
}

TEST_F(FunctionBodyDecoderTest, NestedBlock_return) {
  ExpectValidates(sigs.i_i(), {B1(B1(WASM_RETURN(WASM_ZERO))), WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, BlockBrBinop) {
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_AND(WASM_BLOCK_I(WASM_BRV(0, WASM_I32V_1(1))),
                                WASM_I32V_1(2))});
}

TEST_F(FunctionBodyDecoderTest, VoidBlockTypeVariants) {
  // Valid kVoidCode encoded in 2 bytes.
  ExpectValidates(sigs.v_v(), {kExprBlock, kVoidCode | 0x80, 0x7F, kExprEnd});
  // Invalid code, whose last 7 bits coincide with kVoidCode.
  ExpectFailure(sigs.v_v(), {kExprBlock, kVoidCode | 0x80, 0x45, kExprEnd},
                kAppendEnd, "invalid block type");
}

TEST_F(FunctionBodyDecoderTest, If_empty1) {
  ExpectValidates(sigs.v_v(), {WASM_ZERO, WASM_IF_OP, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, If_empty2) {
  ExpectValidates(sigs.v_v(), {WASM_ZERO, WASM_IF_OP, kExprElse, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, If_empty3) {
  ExpectValidates(sigs.v_v(),
                  {WASM_ZERO, WASM_IF_OP, WASM_NOP, kExprElse, kExprEnd});
  ExpectFailure(sigs.v_v(),
                {WASM_ZERO, WASM_IF_OP, WASM_ZERO, kExprElse, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, If_empty4) {
  ExpectValidates(sigs.v_v(),
                  {WASM_ZERO, WASM_IF_OP, kExprElse, WASM_NOP, kExprEnd});
  ExpectFailure(sigs.v_v(),
                {WASM_ZERO, WASM_IF_OP, kExprElse, WASM_ZERO, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, If_empty_stack) {
  uint8_t code[] = {kExprIf};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, If_incomplete1) {
  uint8_t code[] = {kExprI32Const, 0, kExprIf};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, If_incomplete2) {
  uint8_t code[] = {kExprI32Const, 0, kExprIf, kExprNop};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, If_else_else) {
  uint8_t code[] = {kExprI32Const, 0,         WASM_IF_OP,
                    kExprElse,     kExprElse, kExprEnd};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, IfEmpty) {
  ExpectValidates(sigs.v_i(), {kExprLocalGet, 0, WASM_IF_OP, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, IfSet) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_ZERO))});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_ZERO),
                                WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfElseEmpty) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOCAL_GET(0), WASM_IF_OP, kExprElse, kExprEnd});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfElseUnreachable1) {
  ExpectValidates(
      sigs.i_i(),
      {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_UNREACHABLE, WASM_LOCAL_GET(0))});
  ExpectValidates(
      sigs.i_i(),
      {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_UNREACHABLE)});
}

TEST_F(FunctionBodyDecoderTest, IfElseUnreachable2) {
  static const uint8_t code[] = {
      WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_UNREACHABLE, WASM_LOCAL_GET(0))};

  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType types[] = {kWasmI32, kValueTypes[i]};
    FunctionSig sig(1, 1, types);

    Validate(kValueTypes[i] == kWasmI32, &sig, code);
  }
}

TEST_F(FunctionBodyDecoderTest, OneArmedIfWithArity) {
  static const uint8_t code[] = {WASM_ZERO, kExprIf, kI32Code, WASM_ONE,
                                 kExprEnd};
  ExpectFailure(sigs.i_v(), code, kAppendEnd,
                "start-arity and end-arity of one-armed if must match");
}

TEST_F(FunctionBodyDecoderTest, IfBreak) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_BR(0))});
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_BR(1))});
  ExpectFailure(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_BR(2))});
}

TEST_F(FunctionBodyDecoderTest, IfElseBreak) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_BR(0))});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_BR(1))});
  ExpectFailure(sigs.v_i(),
                {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_BR(2))});
}

TEST_F(FunctionBodyDecoderTest, Block_else) {
  uint8_t code[] = {kExprI32Const, 0, kExprBlock, kExprElse, kExprEnd};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, IfNop) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_NOP)});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, If_end) {
  ExpectValidates(sigs.v_i(), {kExprLocalGet, 0, WASM_IF_OP, kExprEnd});
  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0, WASM_IF_OP, kExprEnd, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, If_falloff1) {
  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0, kExprIf});
  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0, WASM_IF_OP});
  ExpectFailure(sigs.v_i(),
                {kExprLocalGet, 0, WASM_IF_OP, kExprNop, kExprElse});
}

TEST_F(FunctionBodyDecoderTest, IfElseNop) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_ZERO),
                                WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfBlock1) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0),
                                B1(WASM_LOCAL_SET(0, WASM_ZERO)), WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfBlock1b) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0),
                                       B1(WASM_LOCAL_SET(0, WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, IfBlock2a) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0),
                                       B2(WASM_LOCAL_SET(0, WASM_ZERO),
                                          WASM_LOCAL_SET(0, WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, IfBlock2b) {
  ExpectValidates(sigs.v_i(), {WASM_IF_ELSE(WASM_LOCAL_GET(0),
                                            B2(WASM_LOCAL_SET(0, WASM_ZERO),
                                               WASM_LOCAL_SET(0, WASM_ZERO)),
                                            WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfElseSet) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_ZERO),
                                WASM_LOCAL_SET(0, WASM_I32V_1(1)))});
}

TEST_F(FunctionBodyDecoderTest, Loop0) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP_OP, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, Loop1) {
  static const uint8_t code[] = {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO))};
  ExpectValidates(sigs.v_i(), code);
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.f_ff(), code);
}

TEST_F(FunctionBodyDecoderTest, Loop2) {
  ExpectValidates(sigs.v_i(), {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO),
                                         WASM_LOCAL_SET(0, WASM_ZERO))});
}

TEST_F(FunctionBodyDecoderTest, Loop1_continue) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, Loop1_break) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(1))});
}

TEST_F(FunctionBodyDecoderTest, Loop2_continue) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO), WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, Loop2_break) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO), WASM_BR(1))});
}

TEST_F(FunctionBodyDecoderTest, InfiniteLoop1) {
  ExpectValidates(sigs.i_i(), {WASM_LOOP(WASM_BR(0)), WASM_ZERO});
  ExpectValidates(sigs.i_i(), {WASM_LOOP(WASM_BR(0)), WASM_ZERO});
  ExpectValidates(sigs.i_i(), {WASM_LOOP_I(WASM_BRV(1, WASM_ZERO))});
}

TEST_F(FunctionBodyDecoderTest, InfiniteLoop2) {
  ExpectFailure(sigs.i_i(), {WASM_LOOP(WASM_BR(0), WASM_ZERO), WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, Loop2_unreachable) {
  ExpectValidates(sigs.i_i(), {WASM_LOOP_I(WASM_BR(0), WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, LoopType) {
  ExpectValidates(sigs.i_i(), {WASM_LOOP_I(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.l_l(), {WASM_LOOP_L(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.f_f(), {WASM_LOOP_F(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.d_d(), {WASM_LOOP_D(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, LoopType_void) {
  ExpectFailure(sigs.v_v(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.v_v(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.v_v(), {WASM_LOOP_F(WASM_F32(0.0))});
  ExpectFailure(sigs.v_v(), {WASM_LOOP_D(WASM_F64(1.1))});
}

TEST_F(FunctionBodyDecoderTest, LoopType_fail) {
  ExpectFailure(sigs.i_i(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.i_i(), {WASM_LOOP_F(WASM_F32(0.0))});
  ExpectFailure(sigs.i_i(), {WASM_LOOP_D(WASM_F64(1.1))});

  ExpectFailure(sigs.l_l(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.l_l(), {WASM_LOOP_F(WASM_F32(0.0))});
  ExpectFailure(sigs.l_l(), {WASM_LOOP_D(WASM_F64(1.1))});

  ExpectFailure(sigs.f_ff(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.f_ff(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.f_ff(), {WASM_LOOP_D(WASM_F64(1.1))});

  ExpectFailure(sigs.d_dd(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.d_dd(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.d_dd(), {WASM_LOOP_F(WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, ReturnVoid1) {
  static const uint8_t code[] = {kExprNop};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
  ExpectFailure(sigs.i_f(), code);
}

TEST_F(FunctionBodyDecoderTest, ReturnVoid2) {
  static const uint8_t code[] = {WASM_BLOCK(WASM_BR(0))};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
  ExpectFailure(sigs.i_f(), code);
}

TEST_F(FunctionBodyDecoderTest, ReturnVoid3) {
  ExpectFailure(sigs.v_v(), {kExprI32Const, 0});
  ExpectFailure(sigs.v_v(), {kExprI64Const, 0});
  ExpectFailure(sigs.v_v(), {kExprF32Const, 0, 0, 0, 0});
  ExpectFailure(sigs.v_v(), {kExprF64Const, 0, 0, 0, 0, 0, 0, 0, 0});
  ExpectFailure(sigs.v_v(), {kExprRefNull});
  ExpectFailure(sigs.v_v(), {kExprRefFunc, 0});

  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0});
}

TEST_F(FunctionBodyDecoderTest, Unreachable1) {
  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE});
  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, WASM_UNREACHABLE});
  ExpectValidates(sigs.i_i(), {WASM_UNREACHABLE, WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, Unreachable2) {
  ExpectFailure(sigs.v_v(), {B2(WASM_UNREACHABLE, WASM_ZERO)});
  ExpectFailure(sigs.v_v(), {B2(WASM_BR(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, UnreachableLoop1) {
  ExpectFailure(sigs.v_v(), {WASM_LOOP(WASM_UNREACHABLE, WASM_ZERO)});
  ExpectFailure(sigs.v_v(), {WASM_LOOP(WASM_BR(0), WASM_ZERO)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_UNREACHABLE, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(0), WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_binop1) {
  ExpectValidates(sigs.i_i(), {WASM_I32_AND(WASM_ZERO, WASM_UNREACHABLE)});
  ExpectValidates(sigs.i_i(), {WASM_I32_AND(WASM_UNREACHABLE, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_binop2) {
  ExpectValidates(sigs.i_i(), {WASM_I32_AND(WASM_F32(0.0), WASM_UNREACHABLE)});
  ExpectFailure(sigs.i_i(), {WASM_I32_AND(WASM_UNREACHABLE, WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_select1) {
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_UNREACHABLE, WASM_ZERO, WASM_ZERO)});
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_ZERO, WASM_UNREACHABLE, WASM_ZERO)});
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_ZERO, WASM_ZERO, WASM_UNREACHABLE)});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_select2) {
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_F32(0.0), WASM_UNREACHABLE, WASM_ZERO)});
  ExpectFailure(sigs.i_i(),
                {WASM_SELECT(WASM_UNREACHABLE, WASM_F32(0.0), WASM_ZERO)});
  ExpectFailure(sigs.i_i(),
                {WASM_SELECT(WASM_UNREACHABLE, WASM_ZERO, WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, UnreachableRefTypes) {
  ModuleTypeIndex sig_index = builder.AddSignature(sigs.i_ii());
  uint8_t function_index = builder.AddFunction(sig_index);
  ModuleTypeIndex struct_index =
      builder.AddStruct({F(kWasmI32, true), F(kWasmI64, true)});
  ModuleTypeIndex array_index = builder.AddArray(kWasmI32, true);

  ValueType struct_type = ValueType::Ref(struct_index);
  ValueType struct_type_null = ValueType::RefNull(struct_index);
  FunctionSig sig_v_s(0, 1, &struct_type);
  uint8_t struct_consumer = builder.AddFunction(&sig_v_s);
  uint8_t struct_consumer2 = builder.AddFunction(
      FunctionSig::Build(zone(), {kWasmI32}, {struct_type, struct_type}));

  ExpectValidates(sigs.i_v(), {WASM_UNREACHABLE, kExprRefIsNull});
  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, kExprRefAsNonNull, kExprDrop});

  ExpectValidates(sigs.i_v(),
                  {WASM_UNREACHABLE, kExprCallRef, ToByte(sig_index)});
  ExpectValidates(sigs.i_v(), {WASM_UNREACHABLE, WASM_REF_FUNC(function_index),
                               kExprCallRef, ToByte(sig_index)});
  ExpectValidates(sigs.i_v(),
                  {WASM_UNREACHABLE, kExprReturnCallRef, ToByte(sig_index)});

  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprStructNew),
                   ToByte(struct_index), kExprCallFunction, struct_consumer});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_I64V(42), WASM_GC_OP(kExprStructNew),
                   ToByte(struct_index), kExprCallFunction, struct_consumer});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprStructNewDefault),
                   ToByte(struct_index), kExprDrop});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprStructNewDefault),
                   ToByte(struct_index), kExprCallFunction, struct_consumer});

  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, WASM_GC_OP(kExprArrayNew),
                               ToByte(array_index), kExprDrop});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_I32V(42), WASM_GC_OP(kExprArrayNew),
                   ToByte(array_index), kExprDrop});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprArrayNewDefault),
                   ToByte(array_index), kExprDrop});

  ExpectValidates(sigs.i_v(), {WASM_UNREACHABLE, WASM_GC_OP(kExprRefTest),
                               ToByte(struct_index)});
  ExpectValidates(sigs.i_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprRefTest), kEqRefCode});

  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, WASM_GC_OP(kExprRefCast),
                               ToByte(struct_index), kExprDrop});

  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, kExprBrOnNull, 0, WASM_DROP});

  ExpectValidates(&sig_v_s, {WASM_UNREACHABLE, WASM_LOCAL_GET(0), kExprBrOnNull,
                             0, kExprCallFunction, struct_consumer});

  ExpectValidates(
      FunctionSig::Build(zone(), {struct_type}, {}),
      {WASM_UNREACHABLE, WASM_GC_OP(kExprRefCast), ToByte(struct_index)});

  ExpectValidates(FunctionSig::Build(zone(), {kWasmStructRef}, {}),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprRefCast), kStructRefCode});

  ExpectValidates(FunctionSig::Build(zone(), {}, {struct_type_null}),
                  {WASM_UNREACHABLE, WASM_LOCAL_GET(0), kExprBrOnNull, 0,
                   kExprCallFunction, struct_consumer});

  ExpectFailure(
      sigs.v_v(), {WASM_UNREACHABLE, WASM_I32V(42), kExprBrOnNull, 0},
      kAppendEnd,
      "br_on_null[0] expected object reference, found i32.const of type i32");

  // This tests for a bug where {TypeCheckStackAgainstMerge} did not insert
  // unreachable values into the stack correctly.
  ExpectValidates(FunctionSig::Build(zone(), {kWasmI32}, {struct_type_null}),
                  {WASM_BLOCK_R(struct_type_null, kExprUnreachable,   // --
                                kExprLocalGet, 0, kExprRefAsNonNull,  // --
                                kExprLocalGet, 0, kExprBrOnNull, 0,   // --
                                kExprCallFunction, struct_consumer2,  // --
                                kExprBr, 1),
                   kExprDrop, WASM_I32V(1)});
}

TEST_F(FunctionBodyDecoderTest, If1) {
  ExpectValidates(sigs.i_i(), {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_I32V_1(9),
                                              WASM_I32V_1(8))});
  ExpectValidates(sigs.i_i(), {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_I32V_1(9),
                                              WASM_LOCAL_GET(0))});
  ExpectValidates(
      sigs.i_i(),
      {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_I32V_1(8))});
}

TEST_F(FunctionBodyDecoderTest, If_off_end) {
  static const uint8_t kCode[] = {
      WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))};
  for (size_t len = 3; len < arraysize(kCode); len++) {
    ExpectFailure(sigs.i_i(), base::VectorOf(kCode, len), kAppendEnd);
    ExpectFailure(sigs.i_i(), base::VectorOf(kCode, len), kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, If_type1) {
  // float|double ? 1 : 2
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_I32V_1(0), WASM_I32V_1(2))};
  ExpectValidates(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type2) {
  // 1 ? float|double : 2
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_I32V_1(1), WASM_LOCAL_GET(0), WASM_I32V_1(1))};
  ExpectValidates(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type3) {
  // stmt ? 0 : 1
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_NOP, WASM_I32V_1(0), WASM_I32V_1(1))};
  ExpectFailure(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type4) {
  // 0 ? stmt : 1
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_NOP, WASM_I32V_1(1))};
  ExpectFailure(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type5) {
  // 0 ? 1 : stmt
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_ZERO, WASM_I32V_1(1), WASM_NOP)};
  ExpectFailure(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, Int64Local_param) {
  ExpectValidates(sigs.l_l(), kCodeGetLocal0);
}

TEST_F(FunctionBodyDecoderTest, Int64Locals) {
  for (uint8_t i = 1; i < 8; i++) {
    AddLocals(kWasmI64, 1);
    for (uint8_t j = 0; j < i; j++) {
      ExpectValidates(sigs.l_v(), {WASM_LOCAL_GET(j)});
    }
  }
}

TEST_F(FunctionBodyDecoderTest, Int32Binops) {
  TestBinop(kExprI32Add, sigs.i_ii());
  TestBinop(kExprI32Sub, sigs.i_ii());
  TestBinop(kExprI32Mul, sigs.i_ii());
  TestBinop(kExprI32DivS, sigs.i_ii());
  TestBinop(kExprI32DivU, sigs.i_ii());
  TestBinop(kExprI32RemS, sigs.i_ii());
  TestBinop(kExprI32RemU, sigs.i_ii());
  TestBinop(kExprI32And, sigs.i_ii());
  TestBinop(kExprI32Ior, sigs.i_ii());
  TestBinop(kExprI32Xor, sigs.i_ii());
  TestBinop(kExprI32Shl, sigs.i_ii());
  TestBinop(kExprI32ShrU, sigs.i_ii());
  TestBinop(kExprI32ShrS, sigs.i_ii());
  TestBinop(kExprI32Eq, sigs.i_ii());
  TestBinop(kExprI32LtS, sigs.i_ii());
  TestBinop(kExprI32LeS, sigs.i_ii());
  TestBinop(kExprI32LtU, sigs.i_ii());
  TestBinop(kExprI32LeU, sigs.i_ii());
}

TEST_F(FunctionBodyDecoderTest, DoubleBinops) {
  TestBinop(kExprF64Add, sigs.d_dd());
  TestBinop(kExprF64Sub, sigs.d_dd());
  TestBinop(kExprF64Mul, sigs.d_dd());
  TestBinop(kExprF64Div, sigs.d_dd());

  TestBinop(kExprF64Eq, sigs.i_dd());
  TestBinop(kExprF64Lt, sigs.i_dd());
  TestBinop(kExprF64Le, sigs.i_dd());
}

TEST_F(FunctionBodyDecoderTest, FloatBinops) {
  TestBinop(kExprF32Add, sigs.f_ff());
  TestBinop(kExprF32Sub, sigs.f_ff());
  TestBinop(kExprF32Mul, sigs.f_ff());
  TestBinop(kExprF32Div, sigs.f_ff());

  TestBinop(kExprF32Eq, sigs.i_ff());
  TestBinop(kExprF32Lt, sigs.i_ff());
  TestBinop(kExprF32Le, sigs.i_ff());
}

TEST_F(FunctionBodyDecoderTest, TypeConversions) {
  TestUnop(kExprI32SConvertF32, kWasmI32, kWasmF32);
  TestUnop(kExprI32SConvertF64, kWasmI32, kWasmF64);
  TestUnop(kExprI32UConvertF32, kWasmI32, kWasmF32);
  TestUnop(kExprI32UConvertF64, kWasmI32, kWasmF64);
  TestUnop(kExprF64SConvertI32, kWasmF64, kWasmI32);
  TestUnop(kExprF64UConvertI32, kWasmF64, kWasmI32);
  TestUnop(kExprF64ConvertF32, kWasmF64, kWasmF32);
  TestUnop(kExprF32SConvertI32, kWasmF32, kWasmI32);
  TestUnop(kExprF32UConvertI32, kWasmF32, kWasmI32);
  TestUnop(kExprF32ConvertF64, kWasmF32, kWasmF64);
}

TEST_F(FunctionBodyDecoderTest, MacrosVoid) {
  builder.AddMemory();
  ExpectValidates(sigs.v_i(), {WASM_LOCAL_SET(0, WASM_I32V_3(87348))});
  ExpectValidates(
      sigs.v_i(),
      {WASM_STORE_MEM(MachineType::Int32(), WASM_I32V_1(24), WASM_I32V_1(40))});
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_NOP)});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_NOP});
  ExpectValidates(sigs.v_v(), {B1(WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, MacrosContinue) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_CONTINUE(0))});
}

TEST_F(FunctionBodyDecoderTest, MacrosVariadic) {
  ExpectValidates(sigs.v_v(), {B2(WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {B3(WASM_NOP, WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP, WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, MacrosNestedBlocks) {
  ExpectValidates(sigs.v_v(), {B2(WASM_NOP, B2(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.v_v(), {B3(WASM_NOP,                   // --
                                  B2(WASM_NOP, WASM_NOP),     // --
                                  B2(WASM_NOP, WASM_NOP))});  // --
  ExpectValidates(sigs.v_v(), {B1(B1(B2(WASM_NOP, WASM_NOP)))});
}

TEST_F(FunctionBodyDecoderTest, MultipleReturn) {
  static ValueType kIntTypes5[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                                   kWasmI32};
  FunctionSig sig_ii_v(2, 0, kIntTypes5);
  ExpectValidates(&sig_ii_v, {WASM_RETURN(WASM_ZERO, WASM_ONE)});
  ExpectFailure(&sig_ii_v, {WASM_RETURN(WASM_ZERO)});

  FunctionSig sig_iii_v(3, 0, kIntTypes5);
  ExpectValidates(&sig_iii_v,
                  {WASM_RETURN(WASM_ZERO, WASM_ONE, WASM_I32V_1(44))});
  ExpectFailure(&sig_iii_v, {WASM_RETURN(WASM_ZERO, WASM_ONE)});
}

TEST_F(FunctionBodyDecoderTest, MultipleReturn_fallthru) {
  static ValueType kIntTypes5[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                                   kWasmI32};
  FunctionSig sig_ii_v(2, 0, kIntTypes5);

  ExpectValidates(&sig_ii_v, {WASM_ZERO, WASM_ONE});
  ExpectFailure(&sig_ii_v, {WASM_ZERO});

  FunctionSig sig_iii_v(3, 0, kIntTypes5);
  ExpectValidates(&sig_iii_v, {WASM_ZERO, WASM_ONE, WASM_I32V_1(44)});
  ExpectFailure(&sig_iii_v, {WASM_ZERO, WASM_ONE});
}

TEST_F(FunctionBodyDecoderTest, MacrosInt32) {
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_I32V_1(12))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(13))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_I32V_1(14))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_I32V_1(15))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_DIVU(WASM_LOCAL_GET(0), WASM_I32V_1(16))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_I32V_1(17))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_REMU(WASM_LOCAL_GET(0), WASM_I32V_1(18))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_AND(WASM_LOCAL_GET(0), WASM_I32V_1(19))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_IOR(WASM_LOCAL_GET(0), WASM_I32V_1(20))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_XOR(WASM_LOCAL_GET(0), WASM_I32V_1(21))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SHL(WASM_LOCAL_GET(0), WASM_I32V_1(22))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SHR(WASM_LOCAL_GET(0), WASM_I32V_1(23))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SAR(WASM_LOCAL_GET(0), WASM_I32V_1(24))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_ROR(WASM_LOCAL_GET(0), WASM_I32V_1(24))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_ROL(WASM_LOCAL_GET(0), WASM_I32V_1(24))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(25))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_NE(WASM_LOCAL_GET(0), WASM_I32V_1(25))});

  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LTS(WASM_LOCAL_GET(0), WASM_I32V_1(26))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LES(WASM_LOCAL_GET(0), WASM_I32V_1(27))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LTU(WASM_LOCAL_GET(0), WASM_I32V_1(28))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LEU(WASM_LOCAL_GET(0), WASM_I32V_1(29))});

  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GTS(WASM_LOCAL_GET(0), WASM_I32V_1(26))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GES(WASM_LOCAL_GET(0), WASM_I32V_1(27))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GTU(WASM_LOCAL_GET(0), WASM_I32V_1(28))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GEU(WASM_LOCAL_GET(0), WASM_I32V_1(29))});
}

TEST_F(FunctionBodyDecoderTest, MacrosInt64) {
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_ADD(WASM_LOCAL_GET(0), WASM_I64V_1(12))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SUB(WASM_LOCAL_GET(0), WASM_I64V_1(13))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_MUL(WASM_LOCAL_GET(0), WASM_I64V_1(14))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_DIVS(WASM_LOCAL_GET(0), WASM_I64V_1(15))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_DIVU(WASM_LOCAL_GET(0), WASM_I64V_1(16))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_REMS(WASM_LOCAL_GET(0), WASM_I64V_1(17))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_REMU(WASM_LOCAL_GET(0), WASM_I64V_1(18))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_AND(WASM_LOCAL_GET(0), WASM_I64V_1(19))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_IOR(WASM_LOCAL_GET(0), WASM_I64V_1(20))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_XOR(WASM_LOCAL_GET(0), WASM_I64V_1(21))});

  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_I64V_1(22))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_I64V_1(23))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_I64V_1(24))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_ROR(WASM_LOCAL_GET(0), WASM_I64V_1(24))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_ROL(WASM_LOCAL_GET(0), WASM_I64V_1(24))});

  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LTS(WASM_LOCAL_GET(0), WASM_I64V_1(26))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LES(WASM_LOCAL_GET(0), WASM_I64V_1(27))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LTU(WASM_LOCAL_GET(0), WASM_I64V_1(28))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LEU(WASM_LOCAL_GET(0), WASM_I64V_1(29))});

  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GTS(WASM_LOCAL_GET(0), WASM_I64V_1(26))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GES(WASM_LOCAL_GET(0), WASM_I64V_1(27))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GTU(WASM_LOCAL_GET(0), WASM_I64V_1(28))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GEU(WASM_LOCAL_GET(0), WASM_I64V_1(29))});

  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_EQ(WASM_LOCAL_GET(0), WASM_I64V_1(25))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_NE(WASM_LOCAL_GET(0), WASM_I64V_1(25))});
}

TEST_F(FunctionBodyDecoderTest, AllSimpleExpressions) {
// Test all simple expressions which are described by a signature.
#define DECODE_TEST(name, opcode, sig, ...)                       \
  {                                                               \
    const FunctionSig* sig = WasmOpcodes::Signature(kExpr##name); \
    if (sig->parameter_count() == 1) {                            \
      TestUnop(kExpr##name, sig);                                 \
    } else {                                                      \
      TestBinop(kExpr##name, sig);                                \
    }                                                             \
  }

  FOREACH_SIMPLE_OPCODE(DECODE_TEST);

#undef DECODE_TEST
}

TEST_F(FunctionBodyDecoderTest, MemorySize) {
  builder.AddMemory();
  uint8_t code[] = {kExprMemorySize, 0};
  ExpectValidates(sigs.i_i(), code);
  ExpectFailure(sigs.f_ff(), code);
}

TEST_F(FunctionBodyDecoderTest, LoadMemOffset) {
  builder.AddMemory();
  for (int offset = 0; offset < 128; offset += 7) {
    uint8_t code[] = {kExprI32Const, 0, kExprI32LoadMem, ZERO_ALIGNMENT,
                      static_cast<uint8_t>(offset)};
    ExpectValidates(sigs.i_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, LoadMemAlignment) {
  builder.AddMemory();
  struct {
    WasmOpcode instruction;
    uint32_t maximum_aligment;
  } values[] = {
      {kExprI32LoadMem8U, 0},   // --
      {kExprI32LoadMem8S, 0},   // --
      {kExprI32LoadMem16U, 1},  // --
      {kExprI32LoadMem16S, 1},  // --
      {kExprI64LoadMem8U, 0},   // --
      {kExprI64LoadMem8S, 0},   // --
      {kExprI64LoadMem16U, 1},  // --
      {kExprI64LoadMem16S, 1},  // --
      {kExprI64LoadMem32U, 2},  // --
      {kExprI64LoadMem32S, 2},  // --
      {kExprI32LoadMem, 2},     // --
      {kExprI64LoadMem, 3},     // --
      {kExprF32LoadMem, 2},     // --
      {kExprF64LoadMem, 3},     // --
  };

  for (size_t i = 0; i < arraysize(values); i++) {
    for (uint8_t alignment = 0; alignment <= 4; alignment++) {
      uint8_t code[] = {WASM_ZERO, static_cast<uint8_t>(values[i].instruction),
                        alignment, ZERO_OFFSET, WASM_DROP};
      Validate(alignment <= values[i].maximum_aligment, sigs.v_i(), code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, StoreMemOffset) {
  builder.AddMemory();
  for (uint8_t offset = 0; offset < 128; offset += 7) {
    uint8_t code[] = {WASM_STORE_MEM_OFFSET(MachineType::Int32(), offset,
                                            WASM_ZERO, WASM_ZERO)};
    ExpectValidates(sigs.v_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, StoreMemOffset_void) {
  builder.AddMemory();
  ExpectFailure(sigs.i_i(), {WASM_STORE_MEM_OFFSET(MachineType::Int32(), 0,
                                                   WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, LoadMemOffset_varint) {
  builder.AddMemory();
  ExpectValidates(sigs.i_i(),
                  {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT, U32V_1(0x45)});
  ExpectValidates(sigs.i_i(),
                  {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT, U32V_2(0x3999)});
  ExpectValidates(sigs.i_i(), {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT,
                               U32V_3(0x344445)});
  ExpectValidates(sigs.i_i(), {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT,
                               U32V_4(0x36666667)});
}

TEST_F(FunctionBodyDecoderTest, StoreMemOffset_varint) {
  builder.AddMemory();
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_1(0x33)});
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_2(0x1111)});
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_3(0x222222)});
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_4(0x44444444)});
}

TEST_F(FunctionBodyDecoderTest, AllLoadMemCombinations) {
  builder.AddMemory();
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType local_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(machineTypes); j++) {
      MachineType mem_type = machineTypes[j];
      uint8_t code[] = {WASM_LOAD_MEM(mem_type, WASM_ZERO)};
      FunctionSig sig(1, 0, &local_type);
      Validate(local_type == ValueType::For(mem_type), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, AllStoreMemCombinations) {
  builder.AddMemory();
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType local_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(machineTypes); j++) {
      MachineType mem_type = machineTypes[j];
      uint8_t code[] = {WASM_STORE_MEM(mem_type, WASM_ZERO, WASM_LOCAL_GET(0))};
      FunctionSig sig(0, 1, &local_type);
      Validate(local_type == ValueType::For(mem_type), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, SimpleCalls) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_v());
  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());

  ExpectValidates(sig, {WASM_CALL_FUNCTION0(0)});
  ExpectValidates(sig, {WASM_CALL_FUNCTION(1, WASM_I32V_1(27))});
  ExpectValidates(sig,
                  {WASM_CALL_FUNCTION(2, WASM_I32V_1(37), WASM_I32V_2(77))});
}

TEST_F(FunctionBodyDecoderTest, CallsWithTooFewArguments) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());
  builder.AddFunction(sigs.f_ff());

  ExpectFailure(sig, {WASM_CALL_FUNCTION0(0)});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(2, WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, CallsWithMismatchedSigs2) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_i());

  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_I64V_1(17))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_F32(17.1))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_F64(17.1))});
}

TEST_F(FunctionBodyDecoderTest, CallsWithMismatchedSigs3) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_f());

  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_I32V_1(17))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_I64V_1(27))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_F64(37.2))});

  builder.AddFunction(sigs.i_d());

  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_I32V_1(16))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_I64V_1(16))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_F32(17.6))});
}

TEST_F(FunctionBodyDecoderTest, SimpleReturnCalls) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_v());
  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());

  ExpectValidates(sig, {WASM_RETURN_CALL_FUNCTION0(0)});
  ExpectValidates(sig, {WASM_RETURN_CALL_FUNCTION(1, WASM_I32V_1(27))});
  ExpectValidates(
      sig, {WASM_RETURN_CALL_FUNCTION(2, WASM_I32V_1(37), WASM_I32V_2(77))});
}

TEST_F(FunctionBodyDecoderTest, ReturnCallsWithTooFewArguments) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());
  builder.AddFunction(sigs.f_ff());

  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION0(0)});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(1, WASM_ZERO)});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(2, WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, ReturnCallWithSubtype) {
  auto sig = MakeSig::Returns(kWasmAnyRef);
  auto callee_sig = MakeSig::Returns(kWasmAnyRef.AsNonNull());
  builder.AddFunction(&callee_sig);

  ExpectVa
"""

```