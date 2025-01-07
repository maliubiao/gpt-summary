Response:
My thought process for analyzing the provided C++ code and generating the summary went through these steps:

1. **Understand the Core Objective:** The filename `function-body-decoder-unittest.cc` immediately tells me this code is for testing the `FunctionBodyDecoder` component in V8's WebAssembly implementation. The "unittest" suffix confirms this.

2. **Identify Key Includes:**  The `#include` directives reveal the core components being tested and the testing framework used:
    * `"src/wasm/function-body-decoder.h"`: The header file for the class under test.
    * `"src/wasm/function-body-decoder-impl.h"`:  Likely contains implementation details, though less crucial for a high-level summary.
    * `"src/wasm/wasm-opcodes-inl.h"`:  Indicates the code deals with WebAssembly opcodes.
    * `"test/unittests/test-utils.h"` and `"testing/gmock-support.h"`:  Point to the use of Google Test and Google Mock for writing the unit tests.

3. **Analyze the Test Structure:**  The code uses macros like `TEST_F` and helper functions like `ExpectValidates` and `ExpectFailure`. This confirms the standard Google Test structure for writing unit tests. The `FunctionBodyDecoderTestBase` class provides common setup and utility functions for these tests.

4. **Examine Helper Macros and Data:** The defined macros (`B1`, `B2`, `B3`, `WASM_IF_OP`, `WASM_LOOP_OP`, `EXPECT_OK`) and constant arrays (`kCodeGetLocal0`, `kCodeGetLocal1`, `kCodeSetLocal0`, `kCodeTeeLocal0`, `kValueTypes`, `machineTypes`, `kInt32BinopOpcodes`) are crucial for understanding how the tests are constructed. They provide building blocks for creating WebAssembly bytecode sequences and expected outcomes. The `TestModuleBuilder` class helps create mock WebAssembly module environments.

5. **Identify Test Case Patterns:**  Scanning the `TEST_F` blocks reveals common testing patterns:
    * **Valid Bytecode:** Tests with names like `Int32Const1`, `RefFunc`, `EmptyFunction`, etc., often check if the decoder correctly handles valid WebAssembly bytecode sequences for specific operations. `ExpectValidates` is used here.
    * **Invalid Bytecode/Error Handling:** Tests with names like `IncompleteIf1`, `Int32Const_off_end`, `GetLocal0_fail_no_params`, etc., verify that the decoder correctly identifies and rejects invalid bytecode. `ExpectFailure` is used.
    * **Edge Cases and Limits:** Tests like `TooManyLocals`, `NumLocalAboveLimit`, `GetLocal_varint`, etc., push the boundaries of valid input to ensure robustness.
    * **Type Checking:** Many tests implicitly or explicitly test the decoder's ability to handle different WebAssembly types (integers, floats, references).
    * **Control Flow:** Tests involving `Block`, `If`, and `Loop` check how the decoder handles control flow structures.

6. **Infer Functionality from Test Cases:** Based on the test cases, I can deduce the primary functions of the `FunctionBodyDecoder`:
    * **Decoding Bytecode:**  It reads and interprets raw bytecode representing a WebAssembly function body.
    * **Validation:** It checks the validity of the bytecode according to the WebAssembly specification. This includes:
        * **Opcode Recognition:**  Ensuring valid opcodes are used.
        * **Operand Validation:**  Checking the correctness of operands (e.g., local indices, immediate values).
        * **Type Checking:**  Verifying that operations are performed on compatible types.
        * **Control Flow Correctness:** Ensuring proper nesting and termination of control flow structures (blocks, loops, ifs).
        * **Stack Management:**  Tracking the WebAssembly value stack to prevent underflow or overflow.
    * **Handling Local Variables:**  Decoding and validating declarations and usage of local variables.
    * **Handling Control Flow Instructions:** Correctly interpreting `block`, `loop`, `if`, `br`, `br_if`, `return`, etc.

7. **Address Specific Questions:**  Now I can address the specific questions in the prompt:

    * **Functionality:** Summarize the deduced functionality (decoding, validation, etc.).
    * **`.tq` Extension:** The code uses `.cc`, so it's standard C++, not Torque.
    * **JavaScript Relationship:** WebAssembly is designed to be a compilation target for languages like C/C++ and can run in JavaScript environments (browsers, Node.js). The provided example illustrates a basic WebAssembly function that could be called from JavaScript.
    * **Code Logic Reasoning:**  The `IfElseUnreachable1` test demonstrates how the decoder handles unreachable code branches. I can provide example inputs and the expected validation outcome.
    * **Common Programming Errors:**  Tests like `IncompleteIf1` and `Int32Const_off_end` highlight common errors developers might make when generating WebAssembly bytecode manually.
    * **Overall Functionality (for Part 1):**  Focus on the aspects covered in the provided code snippet, which primarily concern basic instruction decoding, local variable handling, and simple control flow validation.

8. **Structure the Summary:** Organize the findings into a clear and concise summary, addressing each point raised in the prompt. Use bullet points and clear language.

By following these steps, I can systematically analyze the C++ unit test code and generate a comprehensive and accurate summary of the functionality of the `FunctionBodyDecoder`.
这是对V8 JavaScript引擎中 WebAssembly 功能的一部分进行单元测试的 C++ 代码。具体来说，它测试了 `FunctionBodyDecoder` 类的功能。`FunctionBodyDecoder` 的作用是解析 WebAssembly 函数的字节码，并验证其结构和指令的正确性。

以下是根据提供的代码片段，对其功能的详细列举：

**主要功能:**

1. **解码 WebAssembly 函数体:**  `FunctionBodyDecoder` 负责读取 WebAssembly 函数的字节流，并将其分解成单独的指令和操作数。

2. **验证 WebAssembly 函数体:**  这是单元测试的核心目标。代码中的各种 `TEST_F` 函数创建了不同的 WebAssembly 字节码序列，然后使用 `ValidateFunctionBody` 函数来测试这些序列是否符合 WebAssembly 的规范。验证的内容包括：
   - **指令的有效性:** 检查是否存在未知的或不合法的指令。
   - **操作数的正确性:**  验证指令的操作数是否在允许的范围内，例如本地变量的索引。
   - **类型一致性:**  确保指令的操作数和返回值类型匹配。例如，一个需要 `i32` 类型的指令不会接受 `f64` 类型的值。
   - **控制流的正确性:**  验证 `block`、`loop`、`if` 等控制流结构的嵌套和终结是否正确。例如，每个 `block` 和 `if` 都必须有相应的 `end` 指令。
   - **堆栈操作的正确性:** 隐式地测试指令对 WebAssembly 虚拟机堆栈的影响，例如确保二元操作有两个操作数，`if` 指令消耗一个布尔值。

**代码结构和辅助功能:**

* **`FunctionBodyDecoderTestBase`:**  这是一个基类，提供了测试的通用设置和辅助函数，例如：
    * `PrepareBytecode`: 将局部变量声明和指令代码组合成完整的函数体字节码。
    * `Validate`: 执行函数体验证并断言结果是否符合预期。
    * `ExpectValidates`: 断言给定的字节码应该验证通过。
    * `ExpectFailure`: 断言给定的字节码应该验证失败，并可以检查失败信息中是否包含特定的字符串。
    * 用于创建不同 WebAssembly 指令序列的宏，例如 `WASM_BLOCK`、`WASM_IF_OP`、`WASM_LOCAL_GET`、`WASM_I32V` 等。
    * 预定义的 WebAssembly 类型 (`kValueTypes`) 和机器类型 (`machineTypes`)。
    * 预定义的常见指令字节码序列 (`kCodeGetLocal0` 等)。
    * `TestSignatures`:  用于创建不同函数签名的辅助类。
    * `TestModuleBuilder`: 用于构建模拟的 WebAssembly 模块环境，这对于测试涉及全局变量、函数调用等需要模块上下文的操作非常重要。
    * `LocalDeclEncoder`: 用于编码局部变量声明。

* **`TEST_F(FunctionBodyDecoderTest, ...)`:**  一个个独立的测试用例，每个测试用例针对 `FunctionBodyDecoder` 的特定方面或场景进行测试。

**关于代码片段中提出的问题:**

* **`.tq` 后缀:**  代码文件以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。Torque 文件通常以 `.tq` 结尾。

* **与 JavaScript 的关系:** WebAssembly 的设计目标之一就是在 JavaScript 引擎中运行。这段 C++ 代码是 V8 引擎（Chrome 和 Node.js 的 JavaScript 引擎）的一部分，负责处理 WebAssembly 代码。  当 JavaScript 代码加载并执行 WebAssembly 模块时，V8 会调用类似 `FunctionBodyDecoder` 这样的组件来解析和验证 WebAssembly 代码。

   **JavaScript 示例:**

   ```javascript
   const wasmCode = new Uint8Array([
     0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm magic number and version
     0x01, 0x07, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x0a,
     0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x00, 0x6a, 0x0b // 函数体字节码 (i32.add local.get 0 local.get 0)
   ]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);

   // 调用 WebAssembly 导出的函数
   const result = wasmInstance.exports.add(5);
   console.log(result); // 输出 10 (因为函数将输入参数加自身)
   ```

   在这个 JavaScript 例子中，`wasmCode` 包含了一个简单的 WebAssembly 模块，其中定义了一个将输入参数加自身的函数。当 `WebAssembly.Module` 解析 `wasmCode` 时，V8 内部的 `FunctionBodyDecoder` (或类似组件) 会被调用来处理函数体的字节码 (`0x20, 0x00, 0x20, 0x00, 0x6a, 0x0b`)。

* **代码逻辑推理:**

   **假设输入:**  以下 WebAssembly 字节码，表示一个接受一个 `i32` 参数并返回 `i32` 的函数，函数体是将局部变量 0 的值加 1。

   ```
   { kExprLocalGet, 0, kExprI32Const, 1, kExprI32Add }
   ```

   **对应的 `ExpectValidates` 调用可能如下:**

   ```c++
   TEST_F(FunctionBodyDecoderTest, AddOne) {
     ExpectValidates(sigs.i_i(), {kExprLocalGet, 0, kExprI32Const, 1, kExprI32Add});
   }
   ```

   **预期输出:**  `ValidateFunctionBody` 应该成功返回，因为这段字节码是有效的。

* **用户常见的编程错误:**

   1. **不完整的控制流结构:**  忘记添加 `end` 指令来结束 `block`、`loop` 或 `if` 结构。

      ```c++
      TEST_F(FunctionBodyDecoderTest, IncompleteBlock) {
        ExpectFailure(sigs.v_v(), {kExprBlock, kVoidCode, kExprNop}, kAppendEnd, "expected end of block");
      }
      ```

      **JavaScript 角度的错误 (生成 WebAssembly 时):**

      ```javascript
      // 错误的 WebAssembly 文本格式 (WAT)
      // (func (block (nop)))  // 缺少 block 的结束
      ```

   2. **类型不匹配:**  对类型不兼容的值进行操作。

      ```c++
      TEST_F(FunctionBodyDecoderTest, TypeMismatch) {
        ExpectFailure(sigs.i_i(), {kExprLocalGet, 0, kExprF64Const, 0, 0, 0, 0, 0, 0, 0, 0, kExprI32Add}, kAppendEnd, "type mismatch at '+', expected i32, got f64");
      }
      ```

      **JavaScript 角度的错误:**

      ```javascript
      // 假设你尝试在 WebAssembly 中将一个浮点数和一个整数相加
      // (func (param $p i32) (result i32)
      //   (i32.add (local.get $p) (f64.const 1.0)) // 类型错误
      // )
      ```

   3. **访问超出范围的本地变量:**  尝试访问不存在的本地变量。

      ```c++
      TEST_F(FunctionBodyDecoderTest, OutOfBoundsLocal) {
        ExpectFailure(sigs.i_v(), {kExprLocalGet, 0}, kAppendEnd, "access to out-of-bounds local");
      }
      ```

      **JavaScript 角度的错误:**

      ```javascript
      // (func (result i32)
      //   (local.get 0) // 假设没有定义局部变量 0
      // )
      ```

**归纳功能 (针对第 1 部分):**

这段代码片段主要展示了 `FunctionBodyDecoder` 的 **基本解码和验证功能**。它侧重于：

* **基本指令的识别和验证:**  例如 `nop`, 常量加载 (`i32.const`, `f64.const`), 局部变量的获取和设置 (`local.get`, `local.set`, `local.tee`)。
* **简单控制流结构 (`block`) 的验证:**  包括 `block` 的正确开始和结束，以及 `br` 指令在 `block` 中的使用。
* **`if` 指令的基本结构验证:**  包括 `if` 和 `if-else` 的基本形式。
* **局部变量声明和使用的验证:**  测试了局部变量索引的有效性。
* **类型一致性的初步验证:**  虽然更复杂的类型检查可能在后续部分，但这里已经开始检查一些基本类型操作的正确性。

总而言之，这部分单元测试旨在确保 `FunctionBodyDecoder` 能够正确地解析和验证 WebAssembly 函数体的基本结构和指令，为更复杂的 WebAssembly 功能的测试奠定基础。

Prompt: 
```
这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/function-body-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

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
"""


```