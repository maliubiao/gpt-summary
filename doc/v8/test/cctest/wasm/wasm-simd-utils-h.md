Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Goal Identification:**

The first step is to quickly read through the file, noting the includes, namespaces, and major sections. The filename `wasm-simd-utils.h` and the `Copyright 2021 the V8 project authors` immediately tell us it's related to WebAssembly (Wasm) and the V8 JavaScript engine. The "simd" part hints at Single Instruction, Multiple Data operations. The `.h` extension confirms it's a C++ header file, likely containing declarations and potentially some inline implementations. The goal is to understand the *purpose* and *functionality* of this file.

**2. Analyzing Includes:**

The included headers provide clues about dependencies and functionalities:

* `<stddef.h>`, `<stdint.h>`: Standard C definitions for size types and integer types. This is basic C/C++ infrastructure.
* `"src/base/macros.h"`: V8-specific macros. This suggests internal V8 usage.
* `"src/compiler/node-observer.h"`, `"src/compiler/opcodes.h"`:  These clearly indicate involvement in the compilation process, particularly around the concept of "nodes" (likely in an abstract syntax tree or intermediate representation) and operation codes.
* `"src/wasm/compilation-environment.h"`, `"src/wasm/wasm-opcodes.h"`: Strong confirmation of the file's Wasm focus, dealing with the environment needed for compilation and the specific opcodes used in Wasm.
* `"test/cctest/wasm/wasm-run-utils.h"`:  Indicates this header is primarily for *testing* Wasm SIMD functionality within the V8 codebase. The "cctest" part likely signifies component client testing.
* `"test/common/wasm/wasm-macro-gen.h"`: More testing infrastructure, likely for generating Wasm code or test cases.
* `#ifdef V8_ENABLE_WASM_SIMD256_REVEC ...`: Conditional compilation based on a flag. "REVEC" strongly suggests "revectorization," a compiler optimization technique to convert scalar operations into vector operations. The inclusion of  `"src/compiler/turboshaft/wasm-revec-phase.h"` confirms this and points to a specific compiler pipeline (Turboshaft).

**3. Namespace Exploration:**

The code resides within `v8::internal::wasm`. This further reinforces that it's an internal part of V8's Wasm implementation.

**4. Conditional Compilation Block (`V8_ENABLE_WASM_SIMD256_REVEC`):**

This is a significant portion. The `#ifdef` block suggests this functionality is optional or under development. Key elements within this block:

* `SKIP_TEST_IF_NO_TURBOSHAFT`: A macro that prevents tests from running if the Turboshaft compiler (with specific flags) is not enabled. This is crucial for understanding when the code within this block is relevant.
* `enum class ExpectedResult`: Defines possible test outcomes (pass or fail).
* `class TSSimd256VerifyScope`: This looks like a test helper class. Its constructor sets up a "verifier" that examines the compiler's graph (likely the intermediate representation). The methods `VerifyHaveAnySimd256Op`, `VerifyHaveOpcode`, and `VerifyHaveOpWithKind` strongly suggest it's used to assert that certain SIMD256 operations or opcodes are present in the compiler output during testing.
* `class SIMD256NodeObserver`: Another test helper. The name suggests it observes the creation of "nodes" in the compiler's representation, specifically looking for SIMD256 related nodes.
* `class ObserveSIMD256Scope`:  Manages the activation and deactivation of the `SIMD256NodeObserver`.
* `BUILD_AND_CHECK_REVEC_NODE`: A macro for concisely building Wasm expressions and verifying the presence of expected SIMD256 nodes after the "revectorization" process.

**5. Core Functionality (Outside the Conditional Block):**

This section defines type aliases (`Int8UnOp`, `Int8BinOp`, etc.) for function pointers representing unary and binary operations on various integer and floating-point types. These type aliases are used to define test functions for different SIMD operations. The presence of functions like `RunI8x16UnOpTest`, `RunI8x16BinOpTest`, etc., strongly suggests this file provides utilities for testing *individual* SIMD instructions.

**6. Generic Helper Functions:**

Functions like `Negate`, `Minimum`, `Maximum` provide basic implementations of common operations, likely used as "ground truth" when testing the Wasm SIMD implementations.

**7. NaN Testing:**

The `nan_test_array` and `double_nan_test_array` constants indicate a focus on testing the behavior of SIMD operations with Not-a-Number (NaN) values, which is important for ensuring correct floating-point behavior.

**8. Platform Considerations:**

The `PlatformCanRepresent` function with the `#if V8_TARGET_ARCH_ARM` block hints at platform-specific considerations for floating-point representation.

**9. Result Checking:**

Functions like `CheckFloatResult`, `CheckDoubleResult`, and their variations are crucial for comparing the *actual* results of SIMD operations with the *expected* results during testing.

**10. Revectorization Test Functions (Inside the Conditional Block):**

Functions like `RunI8x32UnOpRevecTest`, `RunI8x32BinOpRevecTest`, etc., are specifically designed to test the *revectorization* optimization. They likely build Wasm code that *could* be vectorized and then use the `TSSimd256VerifyScope` or similar mechanisms to verify that the vectorization actually happened in the compiler.

**11. Answering the Specific Questions:**

Now, with a good understanding of the file, we can address the prompt's questions:

* **Functionality:** Summarize the core purpose as providing utilities for testing Wasm SIMD instructions, especially focusing on the correct execution of operations and the success of the "revectorization" optimization.
* **`.tq` Check:**  The filename ends in `.h`, not `.tq`, so it's not a Torque file.
* **JavaScript Relation:** While this is C++, it directly relates to Wasm, which is a target for JavaScript execution in V8. We can provide JavaScript examples of how these SIMD operations might be used *within* a Wasm module called from JavaScript.
* **Code Logic & Assumptions:** Focus on the `TSSimd256VerifyScope` and `BUILD_AND_CHECK_REVEC_NODE` macros as examples of code logic. Demonstrate how they work with hypothetical inputs and outputs in the context of verifying the presence of specific SIMD opcodes.
* **Common Programming Errors:**  Think about potential errors in Wasm SIMD programming (e.g., type mismatches, incorrect lane access, assuming vectorization will always happen) and illustrate them with Wasm or conceptual examples.

By following this structured approach, we can systematically analyze the C++ header file and provide a comprehensive and accurate explanation of its purpose and functionality. The key is to identify the major components and their roles within the V8 testing framework for Wasm SIMD.
This header file, `v8/test/cctest/wasm/wasm-simd-utils.h`, provides utility functions and classes specifically designed for testing the SIMD (Single Instruction, Multiple Data) capabilities within the V8's WebAssembly (Wasm) implementation. It's part of the component client testing (`cctest`) framework for Wasm.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **SIMD Operation Testing Framework:**
   - It defines type aliases for function pointers representing various SIMD operations (unary, binary, comparison, shift) on different data types (int8, int16, int32, int64, float, double, and half-precision float).
   - It provides template functions (`RunI8x16BinOpTest`, `RunF32x4UnOpTest`, etc.) to streamline the process of writing tests for different SIMD instructions. These functions likely take a Wasm opcode and an expected C++ function as input and execute the Wasm instruction, comparing the result with the expected output.

2. **Revectorization Testing (Conditional Compilation):**
   - The code within the `#ifdef V8_ENABLE_WASM_SIMD256_REVEC` block is dedicated to testing the "revectorization" optimization in V8's Turboshaft compiler. Revectorization is a process where the compiler tries to automatically convert scalar operations into vector (SIMD) operations for better performance.
   - **`TSSimd256VerifyScope`:** This class appears to be a key component for verifying if the revectorization process has successfully introduced SIMD256 instructions into the compiled code. It takes a handler function that inspects the compiler's intermediate representation (the "graph") and checks for the presence of specific SIMD256 opcodes.
   - **`SIMD256NodeObserver` and `ObserveSIMD256Scope`:** These classes are used to observe the creation of compiler nodes during compilation. Specifically, they look for nodes representing SIMD256 operations.
   - **`BUILD_AND_CHECK_REVEC_NODE` macro:** This macro simplifies the process of building a Wasm expression, running it through the compiler, and then checking if the expected SIMD256 node was generated.

3. **Helper Functions for Testing:**
   - Functions like `Negate`, `Minimum`, `Maximum` provide basic implementations of common operations, used as ground truth for comparing the results of Wasm SIMD operations.
   - Arrays like `nan_test_array` and `double_nan_test_array` provide specific test inputs, including NaN (Not a Number) values, crucial for testing the robustness of SIMD operations.
   - Functions like `CheckFloatResult`, `CheckDoubleResult`, and `CheckFloat16LaneResult` are used to compare the actual output of Wasm SIMD operations with the expected output, often considering floating-point precision.

**Is `v8/test/cctest/wasm/wasm-simd-utils.h` a Torque source file?**

No, the file ends with `.h`, which is the standard extension for C++ header files. Torque source files in V8 typically end with `.tq`.

**Relationship with JavaScript and Example:**

This header file is indirectly related to JavaScript. V8 is the JavaScript engine that powers Chrome and Node.js. This file helps ensure the correctness and performance of Wasm SIMD instructions, which can be used by JavaScript developers through the WebAssembly API.

**JavaScript Example (Illustrative):**

```javascript
// Assuming you have a WebAssembly module with SIMD instructions

async function runWasmSimd() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // Assuming the Wasm module has an exported function that uses SIMD
  const result = instance.exports.simdOperation(
    [1, 2, 3, 4], // Example input data for a SIMD operation
    [5, 6, 7, 8]
  );

  console.log("SIMD operation result:", result);
}

runWasmSimd();
```

In this JavaScript example, the `my_wasm_module.wasm` could contain SIMD instructions that are being tested using the utilities in `wasm-simd-utils.h`. The header file's tests ensure that when the JavaScript engine executes this Wasm module, the SIMD operations produce the correct results.

**Code Logic Reasoning and Example:**

Let's focus on the `TSSimd256VerifyScope` class and the `VerifyHaveAnySimd256Op` method as an example of code logic.

**Hypothetical Input:**

Imagine a Wasm function that performs a simple vector addition of two `i32x8` (vector of 8 32-bit integers) values.

**Wasm Code (Conceptual):**

```wasm
(module
  (func $add_vectors (param $v1 i32x8) (param $v2 i32x8) (result i32x8)
    local.get $v1
    local.get $v2
    i32x8.add
  )
  (export "addVectors" (func $add_vectors))
)
```

**C++ Test using `TSSimd256VerifyScope`:**

```c++
TEST(WasmSimdRevec, I32x8AddIsRevectorized) {
  SKIP_TEST_IF_NO_TURBOSHAFT; // Assuming Turboshaft and revec are enabled

  v8::internal::wasm::WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);

  // Define the Wasm module with the vector addition
  r.Build({WASM_PARAM(WasmVecType::kI32x8()), WASM_PARAM(WasmVecType::kI32x8()), WASM_RESULT(WasmVecType::kI32x8()),
           WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_I32x8_ADD});

  // Create a TSSimd256VerifyScope to check for SIMD256 operations
  v8::internal::TSSimd256VerifyScope verify_scope(r.zone());

  // Running r.Build again will trigger compilation and the verifier
  r.Build({});

  // If the test passes, it means the compiler likely generated a SIMD256 add instruction
}
```

**Reasoning:**

- The `TSSimd256VerifyScope` is created. Its constructor sets up a verifier that will be called after the Wasm code is compiled by `r.Build()`.
- The default handler for `TSSimd256VerifyScope` is `TSSimd256VerifyScope::VerifyHaveAnySimd256Op`.
- `VerifyHaveAnySimd256Op` iterates through the operations in the compiled graph.
- If a SIMD256 addition operation (or any other SIMD256 operation defined in `TURBOSHAFT_SIMD256_OPERATION_LIST`) is found, the method returns `true`.
- The destructor of `TSSimd256VerifyScope` asserts that `check_pass_` is `true` if `expected_` is `kPass` (the default). This confirms that a SIMD256 operation was indeed present, indicating successful revectorization.

**Hypothetical Output:**

If the revectorization is successful, the `VerifyHaveAnySimd256Op` function would find a `compiler::turboshaft::Opcode::kSimdI32x8Add` (or a similar SIMD256 equivalent) in the graph, and the test would pass. If revectorization doesn't happen for some reason, the test would fail because `check_pass_` would remain `false`.

**Common Programming Errors (Related to SIMD/Wasm):**

1. **Type Mismatches:**  Attempting to perform SIMD operations on vectors with incompatible element types.

   **Example (Conceptual Wasm):**

   ```wasm
   (module
     (func $mismatch (param $v1 i32x4) (param $v2 f32x4) (result i32x4)
       local.get $v1
       local.get $v2
       i32x4.add  ;; Error: Cannot add i32x4 and f32x4 directly
     )
   )
   ```

2. **Incorrect Lane Access:**  Trying to access a lane (element) of a SIMD vector using an out-of-bounds index.

   **Example (Conceptual Wasm):**

   ```wasm
   (module
     (func $out_of_bounds (param $v i32x4) (result i32)
       local.get $v
       i32x4.extract_lane 4 ;; Error: Lane index is 0-3 for i32x4
     )
   )
   ```

3. **Assuming Automatic Vectorization:**  Writing scalar code and expecting the compiler to always automatically vectorize it. Revectorization is not guaranteed and depends on various factors.

   **Example (JavaScript):**

   ```javascript
   function scalarAdd(arr1, arr2) {
     const result = [];
     for (let i = 0; i < arr1.length; i++) {
       result.push(arr1[i] + arr2[i]);
     }
     return result;
   }

   // While V8 might vectorize this in some cases, it's not guaranteed
   const a = [1, 2, 3, 4];
   const b = [5, 6, 7, 8];
   const sum = scalarAdd(a, b);
   ```

   A programmer might incorrectly assume this JavaScript code will always be executed using SIMD instructions under the hood.

4. **Endianness Issues (When interacting with memory):**  When loading or storing SIMD vectors to memory, the byte order (endianness) might need careful consideration if the data is later interpreted differently.

5. **Ignoring Performance Implications:**  While SIMD can be powerful, using it incorrectly (e.g., excessive shuffling or conversions) can sometimes lead to performance degradation instead of improvement.

The `wasm-simd-utils.h` file and its associated tests are crucial for catching these types of errors within V8's Wasm implementation and ensuring that the generated code behaves as expected when developers utilize SIMD instructions in their WebAssembly modules.

### 提示词
```
这是目录为v8/test/cctest/wasm/wasm-simd-utils.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/wasm-simd-utils.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "src/base/macros.h"
#include "src/compiler/node-observer.h"
#include "src/compiler/opcodes.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/wasm/wasm-macro-gen.h"
#ifdef V8_ENABLE_WASM_SIMD256_REVEC
#include "src/compiler/turboshaft/wasm-revec-phase.h"
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

namespace v8 {
namespace internal {

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
#define SKIP_TEST_IF_NO_TURBOSHAFT                                  \
  do {                                                              \
    if (!v8_flags.turboshaft_wasm ||                                \
        !v8_flags.turboshaft_wasm_instruction_selection_staged) {   \
      /* This pattern is only implemented for turboshaft_wasm and*/ \
      /* turboshaft_wasm_instruction_selection*/                    \
      return;                                                       \
    }                                                               \
  } while (0);

enum class ExpectedResult {
  kFail,
  kPass,
};

class TSSimd256VerifyScope {
 public:
  static bool VerifyHaveAnySimd256Op(const compiler::turboshaft::Graph& graph) {
    for (const compiler::turboshaft::Operation& op : graph.AllOperations()) {
      switch (op.opcode) {
#define CASE_SIMD256(name)                      \
  case compiler::turboshaft::Opcode::k##name: { \
    return true;                                \
  }
        TURBOSHAFT_SIMD256_OPERATION_LIST(CASE_SIMD256)
        default:
          break;
      }
#undef CASE_SIMD256
    }
    return false;
  }

  template <compiler::turboshaft::Opcode opcode>
  static bool VerifyHaveOpcode(const compiler::turboshaft::Graph& graph) {
    for (const compiler::turboshaft::Operation& op : graph.AllOperations()) {
      if (op.opcode == opcode) {
        return true;
      }
    }
    return false;
  }

  template <typename TOp, TOp::Kind op_kind>
  static bool VerifyHaveOpWithKind(const compiler::turboshaft::Graph& graph) {
    for (const compiler::turboshaft::Operation& op : graph.AllOperations()) {
      if (const TOp* t_op = op.TryCast<TOp>()) {
        if (t_op->kind == op_kind) {
          return true;
        }
      }
    }
    return false;
  }

  explicit TSSimd256VerifyScope(
      Zone* zone,
      std::function<bool(const compiler::turboshaft::Graph&)> raw_handler =
          TSSimd256VerifyScope::VerifyHaveAnySimd256Op,
      ExpectedResult expected = ExpectedResult::kPass)
      : expected_(expected) {
    SKIP_TEST_IF_NO_TURBOSHAFT;

    std::function<void(const compiler::turboshaft::Graph&)> handler;

    handler = [=, this](const compiler::turboshaft::Graph& graph) {
      check_pass_ = raw_handler(graph);
    };

    verifier_ =
        std::make_unique<compiler::turboshaft::WasmRevecVerifier>(handler);
    isolate_ = CcTest::InitIsolateOnce();
    DCHECK_EQ(isolate_->wasm_revec_verifier_for_test(), nullptr);
    isolate_->set_wasm_revec_verifier_for_test(verifier_.get());
  }

  ~TSSimd256VerifyScope() {
    SKIP_TEST_IF_NO_TURBOSHAFT;
    isolate_->set_wasm_revec_verifier_for_test(nullptr);
    if (expected_ == ExpectedResult::kPass) {
      CHECK(check_pass_);
    } else {
      CHECK(!check_pass_);
    }
  }

  bool check_pass_ = false;
  ExpectedResult expected_ = ExpectedResult::kPass;
  Isolate* isolate_ = nullptr;
  std::unique_ptr<compiler::turboshaft::WasmRevecVerifier> verifier_;
};

class SIMD256NodeObserver : public compiler::NodeObserver {
 public:
  explicit SIMD256NodeObserver(
      std::function<void(const compiler::Node*)> handler)
      : handler_(handler) {
    DCHECK(handler_);
  }

  Observation OnNodeCreated(const compiler::Node* node) override {
    handler_(node);
    return Observation::kContinue;
  }

 private:
  std::function<void(const compiler::Node*)> handler_;
};

class ObserveSIMD256Scope {
 public:
  explicit ObserveSIMD256Scope(Isolate* isolate,
                               compiler::NodeObserver* node_observer)
      : isolate_(isolate), node_observer_(node_observer) {
    DCHECK_NOT_NULL(isolate_);
    DCHECK_NULL(isolate_->node_observer());
    isolate_->set_node_observer(node_observer_);
  }

  ~ObserveSIMD256Scope() {
    DCHECK_NOT_NULL(isolate_->node_observer());
    isolate_->set_node_observer(nullptr);
  }

  Isolate* isolate_;
  compiler::NodeObserver* node_observer_;
};

// Build input wasm expressions and check if the revectorization success
// (create the expected simd256 node).
#define BUILD_AND_CHECK_REVEC_NODE(wasm_runner, expected_simd256_op, ...) \
  bool find_expected_node = false;                                        \
  SIMD256NodeObserver* observer =                                         \
      wasm_runner.zone()->New<SIMD256NodeObserver>(                       \
          [&](const compiler::Node* node) {                               \
            if (node->opcode() == expected_simd256_op) {                  \
              if (expected_simd256_op == compiler::IrOpcode::kStore &&    \
                  StoreRepresentationOf(node->op()).representation() !=   \
                      MachineRepresentation::kSimd256) {                  \
                return;                                                   \
              }                                                           \
              find_expected_node = true;                                  \
            }                                                             \
          });                                                             \
  ObserveSIMD256Scope scope(CcTest::InitIsolateOnce(), observer);         \
  r.Build({__VA_ARGS__});                                                 \
  if (!v8_flags.turboshaft_wasm) {                                        \
    CHECK(find_expected_node);                                            \
  }

#endif  // V8_ENABLE_WASM_SIMD256_REVEC

namespace wasm {

using Int8UnOp = int8_t (*)(int8_t);
using Int8BinOp = int8_t (*)(int8_t, int8_t);
using Uint8BinOp = uint8_t (*)(uint8_t, uint8_t);
using Int8CompareOp = int (*)(int8_t, int8_t);
using Int8ShiftOp = int8_t (*)(int8_t, int);

using Int16UnOp = int16_t (*)(int16_t);
using Int16BinOp = int16_t (*)(int16_t, int16_t);
using Uint16BinOp = uint16_t (*)(uint16_t, uint16_t);
using Int16ShiftOp = int16_t (*)(int16_t, int);
using Int32UnOp = int32_t (*)(int32_t);
using Int32BinOp = int32_t (*)(int32_t, int32_t);
using Uint32BinOp = uint32_t (*)(uint32_t, uint32_t);
using Int32ShiftOp = int32_t (*)(int32_t, int);
using Int64UnOp = int64_t (*)(int64_t);
using Int64BinOp = int64_t (*)(int64_t, int64_t);
using Int64ShiftOp = int64_t (*)(int64_t, int);
using HalfUnOp = uint16_t (*)(uint16_t);
using HalfBinOp = uint16_t (*)(uint16_t, uint16_t);
using HalfCompareOp = int16_t (*)(uint16_t, uint16_t);
using FloatUnOp = float (*)(float);
using FloatBinOp = float (*)(float, float);
using FloatCompareOp = int32_t (*)(float, float);
using DoubleUnOp = double (*)(double);
using DoubleBinOp = double (*)(double, double);
using DoubleCompareOp = int64_t (*)(double, double);
using ConvertToIntOp = int32_t (*)(double, bool);

void RunI8x16UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int8UnOp expected_op);

template <typename T = int8_t, typename OpType = T (*)(T, T)>
void RunI8x16BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       OpType expected_op);

void RunI8x16ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int8ShiftOp expected_op);
void RunI8x16MixedRelationalOpTest(TestExecutionTier execution_tier,
                                   WasmOpcode opcode, Int8BinOp expected_op);

void RunI16x8UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int16UnOp expected_op);
template <typename T = int16_t, typename OpType = T (*)(T, T)>
void RunI16x8BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       OpType expected_op);
void RunI16x8ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int16ShiftOp expected_op);
void RunI16x8MixedRelationalOpTest(TestExecutionTier execution_tier,
                                   WasmOpcode opcode, Int16BinOp expected_op);

void RunI32x4UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int32UnOp expected_op);
void RunI32x4BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       Int32BinOp expected_op);
void RunI32x4ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int32ShiftOp expected_op);

void RunI64x2UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int64UnOp expected_op);
void RunI64x2BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       Int64BinOp expected_op);
void RunI64x2ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int64ShiftOp expected_op);

// Generic expected value functions.
template <typename T, typename = typename std::enable_if<
                          std::is_floating_point<T>::value>::type>
T Negate(T a) {
  return -a;
}

template <typename T>
T Minimum(T a, T b) {
  return std::min(a, b);
}

template <typename T>
T Maximum(T a, T b) {
  return std::max(a, b);
}

#if V8_OS_AIX
template <typename T>
bool MightReverseSign(T float_op) {
  return float_op == static_cast<T>(Negate) ||
         float_op == static_cast<T>(std::abs);
}
#endif

// Test some values not included in the float inputs from value_helper. These
// tests are useful for opcodes that are synthesized during code gen, like Min
// and Max on ia32 and x64.
static constexpr uint32_t nan_test_array[] = {
    // Bit patterns of quiet NaNs and signaling NaNs, with or without
    // additional payload.
    0x7FC00000, 0xFFC00000, 0x7FFFFFFF, 0xFFFFFFFF, 0x7F876543, 0xFF876543,
    // NaN with top payload bit unset.
    0x7FA00000,
    // Both Infinities.
    0x7F800000, 0xFF800000,
    // Some "normal" numbers, 1 and -1.
    0x3F800000, 0xBF800000};

#define FOR_FLOAT32_NAN_INPUTS(i) \
  for (size_t i = 0; i < arraysize(nan_test_array); ++i)

// Test some values not included in the double inputs from value_helper. These
// tests are useful for opcodes that are synthesized during code gen, like Min
// and Max on ia32 and x64.
static constexpr uint64_t double_nan_test_array[] = {
    // quiet NaNs, + and -
    0x7FF8000000000001, 0xFFF8000000000001,
    // with payload
    0x7FF8000000000011, 0xFFF8000000000011,
    // signaling NaNs, + and -
    0x7FF0000000000001, 0xFFF0000000000001,
    // with payload
    0x7FF0000000000011, 0xFFF0000000000011,
    // Both Infinities.
    0x7FF0000000000000, 0xFFF0000000000000,
    // Some "normal" numbers, 1 and -1.
    0x3FF0000000000000, 0xBFF0000000000000};

#define FOR_FLOAT64_NAN_INPUTS(i) \
  for (size_t i = 0; i < arraysize(double_nan_test_array); ++i)

// Returns true if the platform can represent the result.
template <typename T>
bool PlatformCanRepresent(T x) {
#if V8_TARGET_ARCH_ARM
  return std::fpclassify(x) != FP_SUBNORMAL;
#else
  return true;
#endif
}

bool isnan(uint16_t f);
bool IsCanonical(uint16_t actual);
// Returns true for very small and very large numbers. We skip these test
// values for the approximation instructions, which don't work at the extremes.
bool IsExtreme(float x);
bool IsCanonical(float actual);
void CheckFloatResult(float x, float y, float expected, float actual,
                      bool exact = true);
void CheckFloat16LaneResult(float x, float y, float z, uint16_t expected,
                            uint16_t actual, bool exact = true);
void CheckFloat16LaneResult(float x, float y, uint16_t expected,
                            uint16_t actual, bool exact = true);

bool IsExtreme(double x);
bool IsCanonical(double actual);
void CheckDoubleResult(double x, double y, double expected, double actual,
                       bool exact = true);

void RunF16x8UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      HalfUnOp expected_op, bool exact = true);
void RunF16x8BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       HalfBinOp expected_op);
void RunF16x8CompareOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                           HalfCompareOp expected_op);

void RunF32x4UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      FloatUnOp expected_op, bool exact = true);

void RunF32x4BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       FloatBinOp expected_op);

void RunF32x4CompareOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                           FloatCompareOp expected_op);

void RunF64x2UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      DoubleUnOp expected_op, bool exact = true);
void RunF64x2BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       DoubleBinOp expected_op);
void RunF64x2CompareOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                           DoubleCompareOp expected_op);

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
void RunI8x32UnOpRevecTest(WasmOpcode opcode, Int8UnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode);
void RunI16x16UnOpRevecTest(WasmOpcode opcode, Int16UnOp expected_op,
                            compiler::IrOpcode::Value revec_opcode);
void RunI32x8UnOpRevecTest(WasmOpcode opcode, Int32UnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode);
void RunF32x8UnOpRevecTest(WasmOpcode opcode, FloatUnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode);
void RunF64x4UnOpRevecTest(WasmOpcode opcode, DoubleUnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode);

template <typename T = int8_t, typename OpType = T (*)(T, T)>
void RunI8x32BinOpRevecTest(WasmOpcode opcode, OpType expected_op,
                            compiler::IrOpcode::Value revec_opcode);

template <typename T = int16_t, typename OpType = T (*)(T, T)>
void RunI16x16BinOpRevecTest(WasmOpcode opcode, OpType expected_op,
                             compiler::IrOpcode::Value revec_opcode);

template <typename T = int32_t, typename OpType = T (*)(T, T)>
void RunI32x8BinOpRevecTest(WasmOpcode opcode, OpType expected_op,
                            compiler::IrOpcode::Value revec_opcode);

void RunI64x4BinOpRevecTest(WasmOpcode opcode, Int64BinOp expected_op,
                            compiler::IrOpcode::Value revec_opcode);
void RunF64x4BinOpRevecTest(WasmOpcode opcode, DoubleBinOp expected_op,
                            compiler::IrOpcode::Value revec_opcode);
void RunF32x8BinOpRevecTest(WasmOpcode opcode, FloatBinOp expected_op,
                            compiler::IrOpcode::Value revec_opcode);

void RunI16x16ShiftOpRevecTest(WasmOpcode opcode, Int16ShiftOp expected_op,
                               compiler::IrOpcode::Value revec_opcode);
void RunI32x8ShiftOpRevecTest(WasmOpcode opcode, Int32ShiftOp expected_op,
                              compiler::IrOpcode::Value revec_opcode);
void RunI64x4ShiftOpRevecTest(WasmOpcode opcode, Int64ShiftOp expected_op,
                              compiler::IrOpcode::Value revec_opcode);

template <typename IntType>
void RunI32x8ConvertF32x8RevecTest(WasmOpcode opcode,
                                   ConvertToIntOp expected_op,
                                   compiler::IrOpcode::Value revec_opcode);
template <typename IntType>
void RunF32x8ConvertI32x8RevecTest(WasmOpcode opcode,
                                   compiler::IrOpcode::Value revec_opcode);
template <typename NarrowIntType, typename WideIntType>
void RunIntSignExtensionRevecTest(WasmOpcode opcode_low, WasmOpcode opcode_high,
                                  WasmOpcode splat_op,
                                  compiler::IrOpcode::Value revec_opcode);
template <typename S, typename T>
void RunIntToIntNarrowingRevecTest(WasmOpcode opcode,
                                   compiler::IrOpcode::Value revec_opcode);
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

}  // namespace wasm
}  // namespace internal
}  // namespace v8
```