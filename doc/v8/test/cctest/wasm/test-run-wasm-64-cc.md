Response:
Let's break down the thought process to analyze the provided C++ code snippet.

**1. Understanding the Goal:**

The core request is to analyze a V8 JavaScript engine source file (`v8/test/cctest/wasm/test-run-wasm-64.cc`) and determine its functionality. Specifically, I need to identify what aspects of WebAssembly (Wasm) it's testing.

**2. Initial Code Scan and Keywords:**

I'll quickly scan the code for recognizable keywords and patterns. Things that immediately jump out:

* **`// Copyright ...`**: Standard copyright header. Not directly functional.
* **`#include ...`**:  Includes standard C/C++ headers (`stdint.h`, `stdlib.h`, `string.h`) and V8-specific headers (`src/...`, `test/...`). These indicate the code is part of V8's testing framework and interacts with internal V8 components. The presence of `wasm` in the include paths is a strong indicator of Wasm testing.
* **`namespace v8 { namespace internal { namespace wasm { namespace test_run_wasm_64 {`**:  This namespace structure clearly confirms the file's purpose: testing Wasm functionality, likely specifically 64-bit operations.
* **`WASM_EXEC_TEST(...)`**: This macro appears repeatedly. The word "TEST" strongly suggests these are individual test cases. "EXEC" might hint at execution or compilation testing. The names within the parentheses (e.g., `I64Const`, `I64Add`) likely correspond to specific Wasm instructions or features.
* **`WasmRunner<...>`**:  This looks like a helper class for running Wasm code within the tests. The template arguments (e.g., `int64_t`, `int32_t`) probably specify the signature of the Wasm function being tested (return type and parameter types).
* **`r.Build({...})`**: This method is called on the `WasmRunner` object and takes a braced list as an argument. This likely builds the Wasm module under test.
* **`WASM_I64V(...)`, `WASM_LOCAL_GET(...)`, `WASM_I64_ADD(...)`, etc.**: These look like macros or functions used to generate Wasm bytecode. The prefixes (`WASM_I64`, `WASM_I32`) suggest they deal with specific Wasm data types and instructions.
* **`CHECK_EQ(...)`, `CHECK_TRAP64(...)`, `CHECK_FLOAT_EQ(...)`, `CHECK_DOUBLE_EQ(...)`**: These are assertion macros used to verify the correctness of the test execution. They compare expected and actual values, or check for specific conditions like traps.
* **`FOR_INT64_INPUTS(i)`, `FOR_UINT64_INPUTS(i)`, `FOR_FLOAT32_INPUTS(i)`, `FOR_FLOAT64_INPUTS(i)`**: These are likely macros to iterate through various input values for testing.

**3. Deduce the High-Level Functionality:**

Based on the keywords, the file seems to contain a suite of C++ tests designed to verify the correct implementation of various 64-bit integer operations in the V8 JavaScript engine's Wasm implementation. It appears to compile and execute small Wasm code snippets and check if the results match expectations.

**4. Categorize the Test Cases:**

As I go through the `WASM_EXEC_TEST` blocks, I start categorizing the types of tests:

* **Constants:** Testing the loading of 64-bit constants (`I64Const`).
* **Basic Arithmetic:** Testing addition, subtraction, multiplication (`I64Add`, `I64Sub`, `I64Mul`).
* **Bitwise Operations:** Testing AND, OR, XOR, shifts (`I64And`, `I64Ior`, `I64Xor`, `I64Shl`, `I64ShrU`, `I64ShrS`).
* **Division and Remainder:** Testing signed and unsigned division and remainder operations, including checks for division by zero traps (`I64DivS`, `I64DivU`, `I64RemS`, `I64RemU`).
* **Comparisons:** Testing equality, inequality, less than, greater than, etc., for signed and unsigned 64-bit integers (`I64Eq`, `I64Ne`, `I64LtS`, etc.).
* **Conversions:** Testing conversions between 64-bit integers and 32-bit integers, as well as conversions to and from floating-point numbers (`I32ConvertI64`, `I64SConvertI32`, `F32SConvertI64`, etc.). The "Sat" variants likely test saturating conversions.
* **Function Calls:** Testing calling Wasm functions with 64-bit parameters and return values (`CallI64Parameter`, `CallI64Return`).
* **Specific Regression Tests:**  Tests with names like `Regress5800_Add` indicate they are targeting specific bug fixes.
* **Edge Cases and Boundary Conditions:** The use of macros like `FOR_INT64_INPUTS` and the explicit checks for division by zero suggest the tests cover a range of input values, including edge cases.

**5. Answering Specific Questions:**

* **`.tq` suffix:** The code is in `.cc`, so it's C++, not Torque.
* **JavaScript relation:**  Wasm is designed to work with JavaScript. I can create simple JavaScript examples that would invoke similar Wasm functionality.
* **Code logic and input/output:** For each test case, I can infer the intended input and output based on the Wasm instructions being used and the assertions.
* **Common programming errors:** Division by zero and integer overflow are apparent based on the tests.
* **Summarizing functionality:** Based on the categorized test cases, I can provide a comprehensive summary of the file's purpose.

**6. Iteration and Refinement:**

As I go through the code in detail, I might refine my understanding of certain aspects. For example, I might initially think `WASM_I64V` just creates a 64-bit value, but the `_9` and `_10` suffixes suggest variations or optimizations. I would also pay attention to the specific values used in the tests (e.g., `kHasBit33On`) to understand the nuances being tested.

By following this systematic approach, combining keyword analysis, pattern recognition, and understanding the context of V8's Wasm implementation, I can effectively analyze the provided C++ code and answer the user's questions.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/base/bits.h"
#include "src/base/overflowing-math.h"
#include "src/base/safe_conversions.h"
#include "src/codegen/assembler-inl.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_64 {

WASM_EXEC_TEST(I64Const) {
  WasmRunner<int64_t> r(execution_tier);
  const int64_t kExpectedValue = 0x1122334455667788LL;
  // return(kExpectedValue)
  r.Build({WASM_I64V_9(kExpectedValue)});
  CHECK_EQ(kExpectedValue, r.Call());
}

WASM_EXEC_TEST(I64Const_many) {
  int cntr = 0;
  FOR_UINT32_INPUTS(i) {
    WasmRunner<int64_t> r(execution_tier);
    const int64_t kExpectedValue = (static_cast<uint64_t>(i) << 32) | cntr;
    // return(kExpectedValue)
    r.Build({WASM_I64V(kExpectedValue)});
    CHECK_EQ(kExpectedValue, r.Call());
    cntr++;
  }
}

WASM_EXEC_TEST(Return_I64) {
  WasmRunner<int64_t, int64_t> r(execution_tier);

  r.Build({WASM_RETURN(WASM_LOCAL_GET(0))});

  FOR_INT64_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(I64Add) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(base::AddWithWraparound(i, j), r.Call(i, j));
    }
  }
}

// The i64 add and subtract regression tests need a 64-bit value with a non-zero
// upper half. This upper half was clobbering eax, leading to the function
// returning 1 rather than 0.
const int64_t kHasBit33On = 0x100000000;

WASM_EXEC_TEST(Regress5800_Add) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_I64_EQZ(WASM_I64_ADD(
                                        WASM_I64V(0), WASM_I64V(kHasBit33On)))),
                      WASM_RETURN(WASM_I32V(0))),
           WASM_I32V(0)});
  CHECK_EQ(0, r.Call());
}

WASM_EXEC_TEST(I64Sub) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(base::SubWithWraparound(i, j), r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(Regress5800_Sub) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_I64_EQZ(WASM_I64_SUB(
                                        WASM_I64V(0), WASM_I64V(kHasBit33On)))),
                      WASM_RETURN(WASM_I32V(0))),
           WASM_I32V(0)});
  CHECK_EQ(0, r.Call());
}

WASM_EXEC_TEST(I64AddUseOnlyLowWord) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(static_cast<int32_t>(base::AddWithWraparound(i, j)),
               r.Call(i, j));
    }
  }
}

// ... (rest of the code)
```

## 功能列表:

`v8/test/cctest/wasm/test-run-wasm-64.cc` 是 V8 JavaScript 引擎中用于测试 WebAssembly (Wasm) 64 位整数运算功能的 C++ 源代码文件。  它包含了一系列的测试用例，每个用例都针对 Wasm 中特定的 64 位整数操作进行验证。

具体功能包括：

1. **常量加载:** 测试加载 64 位常量到 Wasm 虚拟机中 (`I64Const`, `I64Const_many`).
2. **返回操作:** 测试从 Wasm 函数中返回 64 位整数 (`Return_I64`).
3. **算术运算:** 测试 64 位整数的加法 (`I64Add`), 减法 (`I64Sub`), 乘法 (`I64Mul`, 在 `I64Binops` 中)，带符号除法 (`I64DivS`, 在 `I64Binops` 中)，无符号除法 (`I64DivU`, 在 `I64Binops` 中)，带符号取余 (`I64RemS`, 在 `I64Binops` 中)，无符号取余 (`I64RemU`, 在 `I64Binops` 中)。
4. **位运算:** 测试 64 位整数的按位与 (`I64And`, 在 `I64Binops` 中)，按位或 (`I64Ior`, 在 `I64Binops` 中)，按位异或 (`I64Xor`, 在 `I64Binops` 中)，左移 (`I64Shl`)，无符号右移 (`I64ShrU`)，带符号右移 (`I64ShrS`)。
5. **比较运算:** 测试 64 位整数的相等 (`I64Eq`)，不等 (`I64Ne`)，带符号小于 (`I64LtS`)，带符号小于等于 (`I64LeS`)，无符号小于 (`I64LtU`)，无符号小于等于 (`I64LeU`)，带符号大于 (`I64GtS`)，带符号大于等于 (`I64GeS`)，无符号大于 (`I64GtU`)，无符号大于等于 (`I64GeU`)。
6. **类型转换:** 测试 64 位整数与其他类型之间的转换，例如：
   - 将 64 位整数转换为 32 位整数 (`I32ConvertI64`, `I64AddUseOnlyLowWord` 等).
   - 将 32 位有符号整数转换为 64 位有符号整数 (`I64SConvertI32`).
   - 将 32 位无符号整数转换为 64 位有符号整数 (`I64UConvertI32`).
   - 将 64 位有符号整数转换为 32 位浮点数 (`F32SConvertI64`).
   - 将 64 位无符号整数转换为 32 位浮点数 (`F32UConvertI64`).
   - 将 64 位有符号整数转换为 64 位浮点数 (`F64SConvertI64`).
   - 将 64 位无符号整数转换为 64 位浮点数 (`F64UConvertI64`).
   - 将 32 位浮点数转换为 64 位有符号整数 (`I64SConvertF32`, `I64SConvertSatF32`)，包括饱和转换。
   - 将 64 位浮点数转换为 64 位有符号整数 (`I64SConvertF64`, `I64SConvertSatF64`)，包括饱和转换。
   - 将 32 位浮点数转换为 64 位无符号整数 (`I64UConvertF32`, `I64UConvertSatF32`)，包括饱和转换。
   - 将 64 位浮点数转换为 64 位无符号整数 (`I64UConvertF64`, `I64UConvertSatF64`)，包括饱和转换。
7. **位计数:** 测试计算 64 位整数中置位 (1) 的个数 (`I64Popcnt`).
8. **函数调用:** 测试 Wasm 函数调用，包括传递 64 位参数 (`CallI64Parameter`) 和返回 64 位值 (`CallI64Return`).
9. **回归测试:**  包含针对特定 bug 的回归测试，例如 `Regress5800_Add` 和 `Regress5800_Sub`，用于确保之前修复的缺陷不再出现。
10. **Trapping (异常处理):** 针对可能导致 Wasm 虚拟机抛出异常的操作进行测试，例如除零错误 (`I64DivS_Trap`, `I64DivU_Trap`, `I64RemS_Trap`, `I64RemU_Trap`) 和超出类型范围的转换。

## 关于文件类型和 JavaScript 关系:

* **文件类型:**  `v8/test/cctest/wasm/test-run-wasm-64.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件 (`.tq`)。

* **与 JavaScript 的关系:**  虽然这个文件本身是 C++ 代码，但它直接测试了 V8 引擎中用于执行 WebAssembly 代码的功能。 WebAssembly 的主要目的是作为 JavaScript 的补充，提供一个高性能的执行环境。

**JavaScript 举例说明:**

```javascript
// 假设我们有一个编译好的 WebAssembly 模块 instance

// 对应于 C++ 测试用例 WASM_EXEC_TEST(I64Const)
const i64ConstResult = instance.exports.i64ConstFunc();
console.log(i64ConstResult); // 输出一个 64 位整数

// 对应于 C++ 测试用例 WASM_EXEC_TEST(I64Add)
const sum = instance.exports.i64AddFunc(10n, 20n); // 注意使用 BigInt 表示 64 位整数
console.log(sum); // 输出 30n

// 对应于 C++ 测试用例 WASM_EXEC_TEST(I64DivS) 且会触发 trap 的情况
try {
  instance.exports.i64DivSFunc(10n, 0n);
} catch (error) {
  console.error("Wasm 抛出异常:", error); // 捕获除零错误
}
```

**解释:**

* 在 JavaScript 中，我们可以使用 `WebAssembly` API 加载和执行 Wasm 模块。
* Wasm 模块可以导出函数，这些函数可以被 JavaScript 调用。
* 对于 64 位整数，JavaScript 使用 `BigInt` 类型来表示。
* C++ 测试用例中 `WasmRunner` 构建的 Wasm 代码片段，在 JavaScript 中可以通过 Wasm 模块导出的函数来执行。
* 当 Wasm 代码执行到会触发 trap 的操作时（例如除零），JavaScript 会捕获到相应的错误。

## 代码逻辑推理和假设输入输出:

**示例：`WASM_EXEC_TEST(I64Add)`**

* **假设输入:** 两个 64 位整数，例如 `i = 5` 和 `j = 10`.
* **Wasm 代码:** `{WASM_I64_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))}`  表示将本地变量 0 和本地变量 1 的值相加。
* **预期输出:**  `base::AddWithWraparound(i, j)` 的结果，即 `5 + 10 = 15` (作为 64 位整数)。

**示例：`WASM_EXEC_TEST(I64DivS_Trap)`**

* **假设输入:** 两个 64 位整数，例如 `i = 100` 和 `j = 0`.
* **Wasm 代码:** `{WASM_I64_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))}` 表示将本地变量 0 除以本地变量 1 (带符号除法)。
* **预期输出:** 由于除数为 0，Wasm 虚拟机应该抛出一个 trap (异常)。`CHECK_TRAP64` 宏就是用来验证这种情况的。

## 用户常见的编程错误举例:

这些测试用例也间接反映了用户在编写 WebAssembly 代码或与 WebAssembly 交互时可能遇到的常见编程错误：

1. **整数溢出/回绕:**  `I64Add` 和 `I64Sub` 测试用例中使用了 `base::AddWithWraparound` 和 `base::SubWithWraparound`，这表明 Wasm 的整数运算会发生回绕，用户可能没有考虑到这种情况。
   ```javascript
   // JavaScript (模拟 Wasm 整数回绕)
   let maxInt64 = 9223372036854775807n;
   console.log(maxInt64 + 1n); // 输出 -9223372036854775808n (回绕)
   ```

2. **除零错误:** 多个测试用例 (`I64DivS_Trap`, `I64DivU_Trap`, 等) 专门测试了除零的情况，这表明除零是 Wasm 中一个常见的运行时错误。
   ```javascript
   // JavaScript
   // instance.exports.some_wasm_function(10n, 0n); // 如果 wasm 函数内部执行了除零操作，会抛出异常
   ```

3. **类型转换错误:**  将浮点数转换为整数时，可能会丢失精度或超出整数类型的表示范围。`I64SConvertF32`, `I64UConvertF32` 等测试用例就覆盖了这些情况，包括饱和转换的处理。
   ```javascript
   // JavaScript
   // 假设 wasm 导出函数接受一个 float 并转换为 i64
   // instance.exports.floatToInt64(NaN); // 可能返回 0 或其他默认值
   // instance.exports.floatToInt64(Infinity); // 可能返回 i64 的最大值
   ```

4. **符号错误:**  带符号和无符号整数的运算结果不同，用户可能会混淆使用。`I64DivS` 和 `I64DivU` 等测试用例区分了带符号和无符号运算。

## 功能归纳 (第 1 部分):

总而言之，`v8/test/cctest/wasm/test-run-wasm-64.cc` 的主要功能是 **全面测试 V8 JavaScript 引擎中 WebAssembly 针对 64 位整数的各种操作的正确性**。它涵盖了常量加载、基本算术运算、位运算、比较运算、类型转换（包括与浮点数的转换）、函数调用以及针对已知 bug 的回归测试。此外，它还验证了 Wasm 虚拟机在遇到错误情况（如除零）时的异常处理机制。这些测试确保了 V8 引擎能够准确可靠地执行涉及 64 位整数的 WebAssembly 代码。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/base/bits.h"
#include "src/base/overflowing-math.h"
#include "src/base/safe_conversions.h"
#include "src/codegen/assembler-inl.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_64 {

WASM_EXEC_TEST(I64Const) {
  WasmRunner<int64_t> r(execution_tier);
  const int64_t kExpectedValue = 0x1122334455667788LL;
  // return(kExpectedValue)
  r.Build({WASM_I64V_9(kExpectedValue)});
  CHECK_EQ(kExpectedValue, r.Call());
}

WASM_EXEC_TEST(I64Const_many) {
  int cntr = 0;
  FOR_UINT32_INPUTS(i) {
    WasmRunner<int64_t> r(execution_tier);
    const int64_t kExpectedValue = (static_cast<uint64_t>(i) << 32) | cntr;
    // return(kExpectedValue)
    r.Build({WASM_I64V(kExpectedValue)});
    CHECK_EQ(kExpectedValue, r.Call());
    cntr++;
  }
}

WASM_EXEC_TEST(Return_I64) {
  WasmRunner<int64_t, int64_t> r(execution_tier);

  r.Build({WASM_RETURN(WASM_LOCAL_GET(0))});

  FOR_INT64_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(I64Add) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(base::AddWithWraparound(i, j), r.Call(i, j));
    }
  }
}

// The i64 add and subtract regression tests need a 64-bit value with a non-zero
// upper half. This upper half was clobbering eax, leading to the function
// returning 1 rather than 0.
const int64_t kHasBit33On = 0x100000000;

WASM_EXEC_TEST(Regress5800_Add) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_I64_EQZ(WASM_I64_ADD(
                                        WASM_I64V(0), WASM_I64V(kHasBit33On)))),
                      WASM_RETURN(WASM_I32V(0))),
           WASM_I32V(0)});
  CHECK_EQ(0, r.Call());
}

WASM_EXEC_TEST(I64Sub) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(base::SubWithWraparound(i, j), r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(Regress5800_Sub) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_I64_EQZ(WASM_I64_SUB(
                                        WASM_I64V(0), WASM_I64V(kHasBit33On)))),
                      WASM_RETURN(WASM_I32V(0))),
           WASM_I32V(0)});
  CHECK_EQ(0, r.Call());
}

WASM_EXEC_TEST(I64AddUseOnlyLowWord) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(static_cast<int32_t>(base::AddWithWraparound(i, j)),
               r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64SubUseOnlyLowWord) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(static_cast<int32_t>(base::SubWithWraparound(i, j)),
               r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64MulUseOnlyLowWord) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_MUL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(static_cast<int32_t>(base::MulWithWraparound(i, j)),
               r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64ShlUseOnlyLowWord) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(base::ShlWithWraparound(i, j));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64ShrUseOnlyLowWord) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      int32_t expected = static_cast<int32_t>((i) >> (j & 0x3F));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64SarUseOnlyLowWord) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int32_t expected = static_cast<int32_t>((i) >> (j & 0x3F));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64DivS) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      if (j == 0) {
        CHECK_TRAP64(r.Call(i, j));
      } else if (j == -1 && i == std::numeric_limits<int64_t>::min()) {
        CHECK_TRAP64(r.Call(i, j));
      } else {
        CHECK_EQ(i / j, r.Call(i, j));
      }
    }
  }
}

WASM_EXEC_TEST(I64DivS_Trap) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CHECK_EQ(0, r.Call(int64_t{0}, int64_t{100}));
  CHECK_TRAP64(r.Call(int64_t{100}, int64_t{0}));
  CHECK_TRAP64(r.Call(int64_t{-1001}, int64_t{0}));
  CHECK_TRAP64(r.Call(std::numeric_limits<int64_t>::min(), int64_t{-1}));
  CHECK_TRAP64(r.Call(std::numeric_limits<int64_t>::min(), int64_t{0}));
}

WASM_EXEC_TEST(I64DivS_Byzero_Const) {
  for (int8_t denom = -2; denom < 8; denom++) {
    WasmRunner<int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_DIVS(WASM_LOCAL_GET(0), WASM_I64V_1(denom))});
    for (int64_t val = -7; val < 8; val++) {
      if (denom == 0) {
        CHECK_TRAP64(r.Call(val));
      } else {
        CHECK_EQ(val / denom, r.Call(val));
      }
    }
  }
}

WASM_EXEC_TEST(I64DivU) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  r.Build({WASM_I64_DIVU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      if (j == 0) {
        CHECK_TRAP64(r.Call(i, j));
      } else {
        CHECK_EQ(i / j, r.Call(i, j));
      }
    }
  }
}

WASM_EXEC_TEST(I64DivU_Trap) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  r.Build({WASM_I64_DIVU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CHECK_EQ(0, r.Call(uint64_t{0}, uint64_t{100}));
  CHECK_TRAP64(r.Call(uint64_t{100}, uint64_t{0}));
  CHECK_TRAP64(r.Call(uint64_t{1001}, uint64_t{0}));
  CHECK_TRAP64(r.Call(std::numeric_limits<uint64_t>::max(), uint64_t{0}));
}

WASM_EXEC_TEST(I64DivU_Byzero_Const) {
  for (uint64_t denom = 0xFFFFFFFFFFFFFFFE; denom < 8; denom++) {
    WasmRunner<uint64_t, uint64_t> r(execution_tier);
    r.Build({WASM_I64_DIVU(WASM_LOCAL_GET(0), WASM_I64V_1(denom))});

    for (uint64_t val = 0xFFFFFFFFFFFFFFF0; val < 8; val++) {
      if (denom == 0) {
        CHECK_TRAP64(r.Call(val));
      } else {
        CHECK_EQ(val / denom, r.Call(val));
      }
    }
  }
}

WASM_EXEC_TEST(I64RemS) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_REMS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      if (j == 0) {
        CHECK_TRAP64(r.Call(i, j));
      } else if (j == -1) {
        CHECK_EQ(0, r.Call(i, j));
      } else {
        CHECK_EQ(i % j, r.Call(i, j));
      }
    }
  }
}

WASM_EXEC_TEST(I64RemS_Trap) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_REMS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CHECK_EQ(33, r.Call(int64_t{133}, int64_t{100}));
  CHECK_EQ(0, r.Call(std::numeric_limits<int64_t>::min(), int64_t{-1}));
  CHECK_TRAP64(r.Call(int64_t{100}, int64_t{0}));
  CHECK_TRAP64(r.Call(int64_t{-1001}, int64_t{0}));
  CHECK_TRAP64(r.Call(std::numeric_limits<int64_t>::min(), int64_t{0}));
}

WASM_EXEC_TEST(I64RemU) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  r.Build({WASM_I64_REMU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      if (j == 0) {
        CHECK_TRAP64(r.Call(i, j));
      } else {
        CHECK_EQ(i % j, r.Call(i, j));
      }
    }
  }
}

WASM_EXEC_TEST(I64RemU_Trap) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  r.Build({WASM_I64_REMU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CHECK_EQ(17, r.Call(uint64_t{217}, uint64_t{100}));
  CHECK_TRAP64(r.Call(uint64_t{100}, uint64_t{0}));
  CHECK_TRAP64(r.Call(uint64_t{1001}, uint64_t{0}));
  CHECK_TRAP64(r.Call(std::numeric_limits<uint64_t>::max(), uint64_t{0}));
}

WASM_EXEC_TEST(I64And) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_AND(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ((i) & (j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64Ior) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_IOR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ((i) | (j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64Xor) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_XOR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ((i) ^ (j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64Shl) {
  {
    WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
    r.Build({WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

    FOR_UINT64_INPUTS(i) {
      FOR_UINT64_INPUTS(j) {
        uint64_t expected = (i) << (j & 0x3F);
        CHECK_EQ(expected, r.Call(i, j));
      }
    }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_I64V_1(0))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i << 0, r.Call(i)); }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_I64V_1(32))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i << 32, r.Call(i)); }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_I64V_1(20))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i << 20, r.Call(i)); }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_I64V_1(40))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i << 40, r.Call(i)); }
  }
}

WASM_EXEC_TEST(I64ShrU) {
  {
    WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
    r.Build({WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

    FOR_UINT64_INPUTS(i) {
      FOR_UINT64_INPUTS(j) {
        uint64_t expected = (i) >> (j & 0x3F);
        CHECK_EQ(expected, r.Call(i, j));
      }
    }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_I64V_1(0))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i >> 0, r.Call(i)); }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_I64V_1(32))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i >> 32, r.Call(i)); }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_I64V_1(20))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i >> 20, r.Call(i)); }
  }
  {
    WasmRunner<uint64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_I64V_1(40))});
    FOR_UINT64_INPUTS(i) { CHECK_EQ(i >> 40, r.Call(i)); }
  }
}

WASM_EXEC_TEST(I64ShrS) {
  {
    WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        int64_t expected = (i) >> (j & 0x3F);
        CHECK_EQ(expected, r.Call(i, j));
      }
    }
  }
  {
    WasmRunner<int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_I64V_1(0))});
    FOR_INT64_INPUTS(i) { CHECK_EQ(i >> 0, r.Call(i)); }
  }
  {
    WasmRunner<int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_I64V_1(32))});
    FOR_INT64_INPUTS(i) { CHECK_EQ(i >> 32, r.Call(i)); }
  }
  {
    WasmRunner<int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_I64V_1(20))});
    FOR_INT64_INPUTS(i) { CHECK_EQ(i >> 20, r.Call(i)); }
  }
  {
    WasmRunner<int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_I64V_1(40))});
    FOR_INT64_INPUTS(i) { CHECK_EQ(i >> 40, r.Call(i)); }
  }
}

WASM_EXEC_TEST(I64Eq) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_EQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ(i == j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64Ne) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_NE(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ(i != j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64LtS) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_LTS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ(i < j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64LeS) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_LES(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ(i <= j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64LtU) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_LTU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) { CHECK_EQ(i < j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64LeU) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_LEU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) { CHECK_EQ(i <= j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64GtS) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_GTS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ(i > j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64GeS) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_GES(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) { CHECK_EQ(i >= j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64GtU) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_GTU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) { CHECK_EQ(i > j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I64GeU) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_GEU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) { CHECK_EQ(i >= j ? 1 : 0, r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(I32ConvertI64) {
  FOR_INT64_INPUTS(i) {
    WasmRunner<int32_t> r(execution_tier);
    r.Build({WASM_I32_CONVERT_I64(WASM_I64V(i))});
    CHECK_EQ(static_cast<int32_t>(i), r.Call());
  }
}

WASM_EXEC_TEST(I64SConvertI32) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  r.Build({WASM_I64_SCONVERT_I32(WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(static_cast<int64_t>(i), r.Call(i)); }
}

WASM_EXEC_TEST(I64UConvertI32) {
  WasmRunner<int64_t, uint32_t> r(execution_tier);
  r.Build({WASM_I64_UCONVERT_I32(WASM_LOCAL_GET(0))});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(static_cast<int64_t>(i), r.Call(i)); }
}

WASM_EXEC_TEST(I64Popcnt) {
  struct {
    int64_t expected;
    uint64_t input;
  } values[] = {{64, 0xFFFFFFFFFFFFFFFF},
                {0, 0x0000000000000000},
                {2, 0x0000080000008000},
                {26, 0x1123456782345678},
                {38, 0xFFEDCBA09EDCBA09}};

  WasmRunner<int64_t, uint64_t> r(execution_tier);
  r.Build({WASM_I64_POPCNT(WASM_LOCAL_GET(0))});
  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(values[i].expected, r.Call(values[i].input));
  }
}

WASM_EXEC_TEST(F32SConvertI64) {
  WasmRunner<float, int64_t> r(execution_tier);
  r.Build({WASM_F32_SCONVERT_I64(WASM_LOCAL_GET(0))});
  FOR_INT64_INPUTS(i) { CHECK_FLOAT_EQ(static_cast<float>(i), r.Call(i)); }
}

WASM_EXEC_TEST(F32UConvertI64) {
  struct {
    uint64_t input;
    uint32_t expected;
  } values[] = {{0x0, 0x0},
                {0x1, 0x3F800000},
                {0xFFFFFFFF, 0x4F800000},
                {0x1B09788B, 0x4DD84BC4},
                {0x4C5FCE8, 0x4C98BF9D},
                {0xCC0DE5BF, 0x4F4C0DE6},
                {0x2, 0x40000000},
                {0x3, 0x40400000},
                {0x4, 0x40800000},
                {0x5, 0x40A00000},
                {0x8, 0x41000000},
                {0x9, 0x41100000},
                {0xFFFFFFFFFFFFFFFF, 0x5F800000},
                {0xFFFFFFFFFFFFFFFE, 0x5F800000},
                {0xFFFFFFFFFFFFFFFD, 0x5F800000},
                {0x0, 0x0},
                {0x100000000, 0x4F800000},
                {0xFFFFFFFF00000000, 0x5F800000},
                {0x1B09788B00000000, 0x5DD84BC4},
                {0x4C5FCE800000000, 0x5C98BF9D},
                {0xCC0DE5BF00000000, 0x5F4C0DE6},
                {0x200000000, 0x50000000},
                {0x300000000, 0x50400000},
                {0x400000000, 0x50800000},
                {0x500000000, 0x50A00000},
                {0x800000000, 0x51000000},
                {0x900000000, 0x51100000},
                {0x273A798E187937A3, 0x5E1CE9E6},
                {0xECE3AF835495A16B, 0x5F6CE3B0},
                {0xB668ECC11223344, 0x5D3668ED},
                {0x9E, 0x431E0000},
                {0x43, 0x42860000},
                {0xAF73, 0x472F7300},
                {0x116B, 0x458B5800},
                {0x658ECC, 0x4ACB1D98},
                {0x2B3B4C, 0x4A2CED30},
                {0x88776655, 0x4F087766},
                {0x70000000, 0x4EE00000},
                {0x7200000, 0x4CE40000},
                {0x7FFFFFFF, 0x4F000000},
                {0x56123761, 0x4EAC246F},
                {0x7FFFFF00, 0x4EFFFFFE},
                {0x761C4761EEEEEEEE, 0x5EEC388F},
                {0x80000000EEEEEEEE, 0x5F000000},
                {0x88888888DDDDDDDD, 0x5F088889},
                {0xA0000000DDDDDDDD, 0x5F200000},
                {0xDDDDDDDDAAAAAAAA, 0x5F5DDDDE},
                {0xE0000000AAAAAAAA, 0x5F600000},
                {0xEEEEEEEEEEEEEEEE, 0x5F6EEEEF},
                {0xFFFFFFFDEEEEEEEE, 0x5F800000},
                {0xF0000000DDDDDDDD, 0x5F700000},
                {0x7FFFFFDDDDDDDD, 0x5B000000},
                {0x3FFFFFAAAAAAAA, 0x5A7FFFFF},
                {0x1FFFFFAAAAAAAA, 0x59FFFFFD},
                {0xFFFFF, 0x497FFFF0},
                {0x7FFFF, 0x48FFFFE0},
                {0x3FFFF, 0x487FFFC0},
                {0x1FFFF, 0x47FFFF80},
                {0xFFFF, 0x477FFF00},
                {0x7FFF, 0x46FFFE00},
                {0x3FFF, 0x467FFC00},
                {0x1FFF, 0x45FFF800},
                {0xFFF, 0x457FF000},
                {0x7FF, 0x44FFE000},
                {0x3FF, 0x447FC000},
                {0x1FF, 0x43FF8000},
                {0x3FFFFFFFFFFF, 0x56800000},
                {0x1FFFFFFFFFFF, 0x56000000},
                {0xFFFFFFFFFFF, 0x55800000},
                {0x7FFFFFFFFFF, 0x55000000},
                {0x3FFFFFFFFFF, 0x54800000},
                {0x1FFFFFFFFFF, 0x54000000},
                {0x8000008000000000, 0x5F000000},
                {0x8000008000000001, 0x5F000001},
                {0x8000000000000400, 0x5F000000},
                {0x8000000000000401, 0x5F000000},
                {0x20000020000001, 0x5a000001},
                {0xFFFFFe8000000001, 0x5f7FFFFF}};
  WasmRunner<float, uint64_t> r(execution_tier);
  r.Build({WASM_F32_UCONVERT_I64(WASM_LOCAL_GET(0))});
  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(base::bit_cast<float>(values[i].expected),
             r.Call(values[i].input));
  }
}

WASM_EXEC_TEST(F64SConvertI64) {
  WasmRunner<double, int64_t> r(execution_tier);
  r.Build({WASM_F64_SCONVERT_I64(WASM_LOCAL_GET(0))});
  FOR_INT64_INPUTS(i) { CHECK_DOUBLE_EQ(static_cast<double>(i), r.Call(i)); }
}

WASM_EXEC_TEST(F64UConvertI64) {
  struct {
    uint64_t input;
    uint64_t expected;
  } values[] = {{0x0, 0x0},
                {0x1, 0x3FF0000000000000},
                {0xFFFFFFFF, 0x41EFFFFFFFE00000},
                {0x1B09788B, 0x41BB09788B000000},
                {0x4C5FCE8, 0x419317F3A0000000},
                {0xCC0DE5BF, 0x41E981BCB7E00000},
                {0x2, 0x4000000000000000},
                {0x3, 0x4008000000000000},
                {0x4, 0x4010000000000000},
                {0x5, 0x4014000000000000},
                {0x8, 0x4020000000000000},
                {0x9, 0x4022000000000000},
                {0xFFFFFFFFFFFFFFFF, 0x43F0000000000000},
                {0xFFFFFFFFFFFFFFFE, 0x43F0000000000000},
                {0xFFFFFFFFFFFFFFFD, 0x43F0000000000000},
                {0x100000000, 0x41F0000000000000},
                {0xFFFFFFFF00000000, 0x43EFFFFFFFE00000},
                {0x1B09788B00000000, 0x43BB09788B000000},
                {0x4C5FCE800000000, 0x439317F3A0000000},
                {0xCC0DE5BF00000000, 0x43E981BCB7E00000},
                {0x200000000, 0x4200000000000000},
                {0x300000000, 0x4208000000000000},
                {0x400000000, 0x4210000000000000},
                {0x500000000, 0x4214000000000000},
                {0x800000000, 0x4220000000000000},
                {0x900000000, 0x4222000000000000},
                {0x273A798E187937A3, 0x43C39D3CC70C3C9C},
                {0xECE3AF835495A16B, 0x43ED9C75F06A92B4},
                {0xB668ECC11223344, 0x43A6CD1D98224467},
                {0x9E, 0x4063C00000000000},
                {0x43, 0x4050C00000000000},
                {0xAF73, 0x40E5EE6000000000},
                {0x116B, 0x40B16B0000000000},
                {0x658ECC, 0x415963B300000000},
                {0x2B3B4C, 0x41459DA600000000},
                {0x88776655, 0x41E10EECCAA00000},
                {0x70000000, 0x41DC000000000000},
                {0x7200000, 0x419C800000000000},
                {0x7FFFFFFF, 0x41DFFFFFFFC00000},
                {0x56123761, 0x41D5848DD8400000},
                {0x7FFFFF00, 0x41DFFFFFC0000000},
                {0x761C4761EEEEEEEE, 0x43DD8711D87BBBBC},
                {0x80000000EEEEEEEE, 0x43E00000001DDDDE},
                {0x88888888DDDDDDDD, 0x43E11111111BBBBC},
                {0xA0000000DDDDDDDD, 0x43E40000001BBBBC},
                {0xDDDDDDDDAAAAAAAA, 0x43EBBBBBBBB55555},
                {0xE0000000AAAAAAAA, 0x43EC000000155555},
                {0xEEEEEEEEEEEEEEEE, 0x43EDDDDDDDDDDDDE},
                {0xFFFFFFFDEEEEEEEE, 0x43EFFFFFFFBDDDDE},
                {0xF0000000DDDDDDDD, 0x43EE0000001BBBBC},
                {0x7FFFFFDDDDDDDD, 0x435FFFFFF7777777},
                {0x3FFFFFAAAAAAAA, 0x434FFFFFD5555555},
                {0x1FFFFFAAAAAAAA, 0x433FFFFFAAAAAAAA},
                {0xFFFFF, 0x412FFFFE00000000},
                {0x7FFFF, 0x411FFFFC00000000},
                {0x3FFFF, 0x410FFFF800000000},
                {0x1FFFF, 0x40FFFFF000000000},
                {0xFFFF, 0x40EFFFE000000000},
                {0x7FFF, 0x40DFFFC000000000},
                {0x3FFF, 0x40CFFF8000000000},
                {0x1FFF, 0x40BFFF0000000000},
                {0xFFF, 0x40AFFE0000000000},
                {0x7FF, 0x409FFC0000000000},
                {0x3FF, 0x408FF80000000000},
                {0x1FF, 0x407FF00000000000},
                {0x3FFFFFFFFFFF, 0x42CFFFFFFFFFFF80},
                {0x1FFFFFFFFFFF, 0x42BFFFFFFFFFFF00},
                {0xFFFFFFFFFFF, 0x42AFFFFFFFFFFE00},
                {0x7FFFFFFFFFF, 0x429FFFFFFFFFFC00},
                {0x3FFFFFFFFFF, 0x428FFFFFFFFFF800},
                {0x1FFFFFFFFFF, 0x427FFFFFFFFFF000},
                {0x8000008000000000, 0x43E0000010000000},
                {0x8000008000000001, 0x43E0000010000000},
                {0x8000000000000400, 0x43E0000000000000},
                {0x8000000000000401, 0x43E0000000000001}};
  WasmRunner<double, uint64_t> r(execution_tier);
  r.Build({WASM_F64_UCONVERT_I64(WASM_LOCAL_GET(0))});
  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(base::bit_cast<double>(values[i].expected),
             r.Call(values[i].input));
  }
}

WASM_EXEC_TEST(I64SConvertF32) {
  WasmRunner<int64_t, float> r(execution_tier);
  r.Build({WASM_I64_SCONVERT_F32(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    if (base::IsValueInRangeForNumericType<int64_t>(i)) {
      CHECK_EQ(static_cast<int64_t>(i), r.Call(i));
    } else {
      CHECK_TRAP64(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I64SConvertSatF32) {
  WasmRunner<int64_t, float> r(execution_tier);
  r.Build({WASM_I64_SCONVERT_SAT_F32(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) {
    int64_t expected;
    if (base::IsValueInRangeForNumericType<int64_t>(i)) {
      expected = static_cast<int64_t>(i);
    } else if (std::isnan(i)) {
      expected = static_cast<int64_t>(0);
    } else if (i < 0.0) {
      expected = std::numeric_limits<int64_t>::min();
    } else {
      expected = std::numeric_limits<int64_t>::max();
    }
    int64_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I64SConvertF64) {
  WasmRunner<int64_t, double> r(execution_tier);
  r.Build({WASM_I64_SCONVERT_F64(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    if (base::IsValueInRangeForNumericType<int64_t>(i)) {
      CHECK_EQ(static_cast<int64_t>(i), r.Call(i));
    } else {
      CHECK_TRAP64(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I64SConvertSatF64) {
  WasmRunner<int64_t, double> r(execution_tier);
  r.Build({WASM_I64_SCONVERT_SAT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    int64_t expected;
    if (base::IsValueInRangeForNumericType<int64_t>(i)) {
      expected = static_cast<int64_t>(i);
    } else if (std::isnan(i)) {
      expected = static_cast<int64_t>(0);
    } else if (i < 0.0) {
      expected = std::numeric_limits<int64_t>::min();
    } else {
      expected = std::numeric_limits<int64_t>::max();
    }
    int64_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I64UConvertF32) {
  WasmRunner<uint64_t, float> r(execution_tier);
  r.Build({WASM_I64_UCONVERT_F32(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    if (i < static_cast<float>(std::numeric_limits<uint64_t>::max()) &&
        i > -1) {
      CHECK_EQ(static_cast<uint64_t>(i), r.Call(i));
    } else {
      CHECK_TRAP64(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I64UConvertSatF32) {
  WasmRunner<int64_t, float> r(execution_tier);
  r.Build({WASM_I64_UCONVERT_SAT_F32(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) {
    uint64_t expected;
    if (i < static_cast<float>(std::numeric_limits<uint64_t>::max()) &&
        i > -1) {
      expected = static_cast<uint64_t>(i);
    } else if (std::isnan(i)) {
      expected = static_cast<uint64_t>(0);
    } else if (i < 0.0) {
      expected = std::numeric_limits<uint64_t>::min();
    } else {
      expected = std::numeric_limits<uint64_t>::max();
    }
    uint64_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I64UConvertF64) {
  WasmRunner<uint64_t, double> r(execution_tier);
  r.Build({WASM_I64_UCONVERT_F64(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    if (i < static_cast<float>(std::numeric_limits<uint64_t>::max()) &&
        i > -1) {
      CHECK_EQ(static_cast<uint64_t>(i), r.Call(i));
    } else {
      CHECK_TRAP64(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I64UConvertSatF64) {
  WasmRunner<int64_t, double> r(execution_tier);
  r.Build({WASM_I64_UCONVERT_SAT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    int64_t expected;
    if (i < static_cast<float>(std::numeric_limits<uint64_t>::max()) &&
        i > -1) {
      expected = static_cast<uint64_t>(i);
    } else if (std::isnan(i)) {
      expected = static_cast<uint64_t>(0);
    } else if (i < 0.0) {
      expected = std::numeric_limits<uint64_t>::min();
    } else {
      expected = std::numeric_limits<uint64_t>::max();
    }
    int64_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(CallI64Parameter) {
  ValueType param_types[20];
  for (int i = 0; i < 20; i++) param_types[i] = kWasmI64;
  param_types[3] = kWasmI32;
  param_types[4] = kWasmI32;
  FunctionSig sig(1, 19, param_types);
  for (int i = 0; i < 19; i++) {
    if (i == 2 || i == 3) continue;
    WasmRunner<int32_t> r(execution_tier);
    // Build the target function.
    WasmFunctionCompiler& t = r.NewFunction(&sig);
    t.Build({WASM_LOCAL_GET(i)});

    // Build the calling function.
    r.Build({WASM_I32_CONVERT_I64(WASM_CALL_FUNCTION(
        t.function_index(), WASM_I64V_9(0xBCD12340000000B),
        WASM_I64V_9(0xBCD12340000000C), WASM_I32V_1(0xD),
        WASM_I32_CONVERT_I64(WASM_I64V_9(0xBCD12340000000E)),
        WASM_I64V_9(0xBCD12340000000F), WASM_I64V_10(0xBCD1234000000010),
        WASM_I64V_10(0xBCD1234000000011), WASM_I64V_10(0xBCD1234000000012),
        WASM_I64V_10(0xBCD1234000000013), WASM_I64V_10(0xBCD1234000000014),
        WASM_I64V_10(0xBCD1234000000015), WASM_I64V_10(0xBCD1234000000016),
        WASM_I64V_10(0xBCD1234000000017), WASM_I64V_10(0xBCD1234000000018),
        WASM_I64V_10(0xBCD1234000000019), WASM_I64V_10(0xBCD123400000001A),
        WASM_I64V_10(0xBCD123400000001B), WASM_I64V_10(0xBCD123400000001C),
        WASM_I64V_10(0xBCD123400000001D)))});

    CHECK_EQ(i + 0xB, r.Call());
  }
}

WASM_EXEC_TEST(CallI64Return) {
  ValueType return_types[3];  // TODO(rossberg): support more in the future
  for (int i = 0; i < 3; i++) return_types[i] = kWasmI64;
  return_types[1] = kWasmI32;
  FunctionSig sig(2, 1, return_types);

  WasmRunner<int64_t> r(execution_tier);
  // Build the target function.
  WasmFunctionCompiler& t = r.NewFunction(&sig);
  t.Build({WASM_LOCAL_GET(0), WASM_I32V(7)});

  // Build the first calling function.
  r.Build({WASM_CALL_FUNCTION(t.function_index(), WASM_I64V(0xBCD12340000000B)),
           WASM_DROP});

  CHECK_EQ(0xBCD12340000000B, r.Call());
}

void TestI64Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                  int64_t expected, int64_t a, int64_t b) {
  {
    WasmRunner<int64_t> r(execution_tier);
    // return K op K
    r.Build({WASM_BINOP(opcode, WASM_I64V(a), WASM_I64V(b))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
    // return a op b
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestI64Cmp(TestExecutionTier execution_tier, WasmOpcode opcode,
                int64_t expected, int64_t a, int64_t b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return K op K
    r.Build({WASM_BINOP(opcode, WASM_I64V(a), WASM_I64V(b))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
    // return a op b
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

WASM_EXEC_TEST(I64Binops) {
  TestI64Binop(execution_tier, kExprI64Add, -5586332274295447011,
               0x501B72EBABC26847, 0x625DE9793D8F79D6);
  TestI64Binop(execution_tier, kExprI64Sub, 9001903251710731490,
               0xF24FE6474640002E, 0x7562B6F711991B4C);
  TestI64Binop(execution_tier, kExprI64Mul, -4569547818546064176,
               0x231A263C2CBC6451, 0xEAD44DE6BD3E23D0);
  TestI64Binop(execution_tier, kExprI64Mul, -25963122347507043,
               0x4DA1FA47C9352B73, 0x91FE82317AA035AF);
  TestI64Binop(execution_tier, kExprI64Mul, 7640290486138131960,
               0x185731ABE8EEA47C, 0x714EC59F1380D4C2);
  TestI64Binop(execution_tier, kExprI64DivS, -91517, 0x93B1190A34DE56A0,
               0x00004D8F68863948);
  TestI64Binop(execution_tier, kExprI64DivU, 149016, 0xE15B3727E8A2080A,
               0x0000631BFA72DB8B);
  TestI64Binop(execution_tier, kExprI64RemS, -664128064149968,
               0x9A78B4E4FE708692, 0x0003E0B6B3BE7609);
  TestI64Binop(execution_tier, kExprI64RemU, 1742040017332765,
               0x0CE84708C6258C81, 0x000A6FDE82016697);
  TestI64Binop(executi
```