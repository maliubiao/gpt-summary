Response:
The user wants a summary of the provided C++ code, which is a V8 test file for WebAssembly (Wasm) functionality, specifically focusing on 64-bit integer operations.

Here's a breakdown of the request and a plan to generate the response:

1. **Identify the file's purpose:** The filename `test-run-wasm-64.cc` and the presence of `WASM_EXEC_TEST` macros clearly indicate this file contains execution tests for Wasm features related to 64-bit integers.

2. **List functionalities:** Go through each `WASM_EXEC_TEST` and infer the tested functionality from the test name and the code within the test. Look for patterns like `TestI64Binop`, `TestI64Cmp`, and direct Wasm instructions like `WASM_I64_CLZ`, `WASM_I64_CTZ`, etc.

3. **Check for Torque:** The prompt asks to check if the file ends with `.tq`. This is not the case, so it's a standard C++ file, not a Torque file.

4. **JavaScript relevance:**  While this is a C++ test file, the underlying functionality being tested (Wasm 64-bit integer operations) *is* exposed and used by JavaScript when executing Wasm code. I need to provide JavaScript examples demonstrating these operations.

5. **Code logic and examples:** For tests involving specific operations (like binary operations, comparisons, bit manipulation), create simple scenarios with hypothetical inputs and expected outputs to illustrate the logic.

6. **Common programming errors:**  Think about typical mistakes programmers might make when working with 64-bit integers in Wasm or when mapping Wasm concepts to JavaScript. Examples include overflow, signed/unsigned issues, and incorrect use of bitwise operators.

7. **Summarize the functionality:** Based on the identified functionalities, write a concise summary of the file's purpose.

**Mental Sandbox:**

* I see tests for basic arithmetic (`I64Arith`), bitwise operations (`I64Binop`), comparisons (`I64Compare`), and bit counting (`I64Clz`, `I64Ctz`, `I64Popcnt2`).
* The `WasmRunner` class seems to be a utility for setting up and executing Wasm code within the tests.
* There are tests for memory operations (`LoadStoreI64_sx`, `LoadMemI64`, `StoreMemI64_alignment`), global variables (`I64Global`), and type conversions (`I64ReinterpretF64`, `F64ReinterpretI64`).
* Some tests are specifically designed for edge cases or potential issues like unaligned memory access and out-of-bounds memory access.
* The mixed-type call tests (`MixedCall_i64_...`) are interesting, likely checking the handling of different data types in function calls.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果v8/test/cctest/wasm/test-run-wasm-64.cc以.tq结尾: Yes
3. 如果它与javascript的功能有关系，请用javascript举例说明: Yes
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户常见的编程错误，请举例说明: Yes
6. 这是第2部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. I will now generate the response by systematically addressing each point.
这是一个V8源代码文件，路径为 `v8/test/cctest/wasm/test-run-wasm-64.cc`，它是一个C++文件，用于测试V8引擎中WebAssembly（Wasm）的执行功能，特别关注 **64位整数 (i64)** 相关的操作。

**功能列举:**

这个文件包含了多个独立的测试用例，每个用例都测试了Wasm中关于 `i64` 的不同方面。以下是它主要测试的功能：

* **算术运算 (Arithmetic Operations):**
    * 加法 (`i64.add`)
    * 减法 (`i64.sub`)
    * 乘法 (`i64.mul`)
    * 有符号除法 (`i64.div_s`)
    * 无符号除法 (`i64.div_u`)
    * 有符号取余 (`i64.rem_s`)
    * 无符号取余 (`i64.rem_u`)
* **位运算 (Bitwise Operations):**
    * 与 (`i64.and`)
    * 或 (`i64.or`)
    * 异或 (`i64.xor`)
    * 左移 (`i64.shl`)
    * 无符号右移 (`i64.shr_u`)
    * 有符号右移 (`i64.shr_s`)
    * 右旋转 (`i64.rotr`)
    * 左旋转 (`i64.rotl`)
* **比较运算 (Comparison Operations):**
    * 等于 (`i64.eq`)
    * 不等于 (`i64.ne`)
    * 小于 (有符号) (`i64.lt_s`)
    * 小于等于 (有符号) (`i64.le_s`)
    * 小于 (无符号) (`i64.lt_u`)
    * 小于等于 (无符号) (`i64.le_u`)
    * 大于 (有符号) (`i64.gt_s`)
    * 大于等于 (有符号) (`i64.ge_s`)
    * 大于 (无符号) (`i64.gt_u`)
    * 大于等于 (无符号) (`i64.ge_u`)
* **其他 i64 操作 (Other i64 Operations):**
    * 计算前导零的个数 (`i64.clz`)
    * 计算尾部零的个数 (`i64.ctz`)
    * 计算 population count (设置的位的数量) (`i64.popcnt`)
    * 判断是否为零 (`i64.eqz`)
* **与 WasmRunner 的集成 (Integration with WasmRunner):** 测试 `WasmRunner` 工具类对于不同数量的 `i64` 参数和返回值的支持。
* **函数调用 (Function Calls):** 测试调用返回 `i64` 类型的Wasm函数。
* **内存操作 (Memory Operations):**
    * 加载不同大小和符号扩展的 `i64` 值 (`i64.load8_s`, `i64.load16_s`, `i64.load32_s`, `i64.load`)
    * 存储 `i64` 值 (`i64.store`)
    * 测试对齐的内存访问和非对齐的内存访问
    * 测试内存访问的越界行为
* **类型转换 (Type Conversions):**
    * 将 `f64` 重新解释为 `i64` (`i64.reinterpret_f64`)
    * 将 `i64` 重新解释为 `f64` (`f64.reinterpret_i64`)
    * 将 `i32` 转换为 `i64` (`i64.extend_i32_s`) (在 `I64Global` 测试中体现)
* **全局变量 (Global Variables):** 测试 `i64` 类型的全局变量的读写。
* **间接调用 (Indirect Calls):**  测试带有多个 `i64` 参数的间接函数调用。
* **混合类型调用 (Mixed-Type Calls):** 测试涉及多种参数类型的函数调用，包括 `i64`。
* **回归测试 (Regression Tests):** 包含了一些针对特定bug的回归测试用例。

**关于 .tq 结尾:**

`v8/test/cctest/wasm/test-run-wasm-64.cc` 的文件名以 `.cc` 结尾，这表明它是一个 **C++** 源文件。如果它以 `.tq` 结尾，那么它才是一个 **V8 Torque** 源代码文件。 Torque 是一种 V8 用于定义内置函数和运行时功能的领域特定语言。

**与 JavaScript 的关系及举例:**

虽然 `test-run-wasm-64.cc` 是 C++ 代码，但它测试的是 WebAssembly 的功能，而 WebAssembly 代码最终会在 JavaScript 环境中执行。JavaScript 可以通过 `WebAssembly` API 来加载、编译和运行 Wasm 模块。

以下 JavaScript 示例展示了如何在 JavaScript 中使用 Wasm 的 `i64` 操作：

```javascript
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm'); // 假设你有一个名为 your_wasm_module.wasm 的 Wasm 文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // 假设 Wasm 模块导出了一个名为 'add_i64' 的函数，它接收两个 i64 参数并返回一个 i64
  const lowBitsA = 10n; // JavaScript BigInt 表示低 32 位
  const highBitsA = 0n; // JavaScript BigInt 表示高 32 位
  const lowBitsB = 20n;
  const highBitsB = 0n;

  // WebAssembly 的 JavaScript API 通常会使用两个 32 位数字来表示 i64
  const resultLow = instance.exports.add_i64(Number(lowBitsA), Number(highBitsA), Number(lowBitsB), Number(highBitsB));
  // 注意：实际的 API 和 Wasm 模块的导出方式可能会有所不同，这里只是一个概念性的例子

  console.log("Wasm i64 addition result (low bits):", resultLow);
}

runWasm();
```

**代码逻辑推理及假设输入与输出:**

以 `WASM_EXEC_TEST(I64Binop)` 中的 `TestI64Binop` 函数调用为例：

```c++
TestI64Binop(execution_tier, kExprI64And, 2531040582801836054,
               0xAF257D1602644A16, 0x33B290A91A10D997);
```

* **假设输入:** 两个 64 位整数 `0xAF257D1602644A16` 和 `0x33B290A91A10D997`。
* **操作:**  `kExprI64And` 表示执行按位与操作。
* **代码逻辑:** Wasm 代码会将这两个 64 位整数执行按位与运算。
* **预期输出:**  `0xAF257D1602644A16 & 0x33B290A91A10D997 = 0x2B10100000008916`，转换为十进制即为 `2531040582801836054`。

**用户常见的编程错误举例:**

在 WebAssembly 或与 WebAssembly 交互时，关于 64 位整数，用户可能犯以下错误：

1. **JavaScript 中处理 i64 的方式不当:** JavaScript 的 `Number` 类型只能安全地表示 53 位整数。直接用 `Number` 来表示和操作 Wasm 的 `i64` 类型可能会导致精度丢失。应该使用 `BigInt` 来处理 JavaScript 中的 64 位整数。

   ```javascript
   // 错误示例：使用 Number 可能导致精度丢失
   const wasmI64Value = instance.exports.get_i64_value(); // 假设返回一个 i64
   console.log(wasmI64Value); // 可能不准确

   // 正确示例：使用 BigInt (如果 Wasm 绑定支持)
   // 或者，如果 Wasm API 返回两个 32 位数，需要手动组合
   const lowBits = instance.exports.get_i64_value_low();
   const highBits = instance.exports.get_i64_value_high();
   const bigIntValue = (BigInt(highBits) << 32n) | BigInt(lowBits);
   console.log(bigIntValue);
   ```

2. **有符号和无符号的混淆:** Wasm 区分有符号和无符号的 64 位整数，并且有不同的操作符（例如 `div_s` 和 `div_u`）。在 JavaScript 中与 Wasm 交互时，如果类型转换或理解有误，可能会导致意外的结果。

   ```c++
   // WebAssembly 模块 (text format)
   (module
     (func $unsigned_div (param $a i64) (param $b i64) (result i64)
       local.get $a
       local.get $b
       i64.div_u)
   )
   ```

   ```javascript
   // JavaScript
   const a = -1n; // JavaScript BigInt
   const b = 2n;
   // 假设你正确地调用了 Wasm 的 unsigned_div 函数
   // 结果将是 a 的无符号表示除以 b，与有符号除法不同。
   ```

3. **位运算的理解错误:**  对 64 位整数进行位运算时，需要确保理解各种位运算符的作用，特别是移位操作时，要区分有符号右移和无符号右移。

   ```c++
   // WebAssembly 模块 (text format)
   (module
     (func $signed_shr (param $val i64) (param $shift i32) (result i64)
       local.get $val
       local.get $shift
       i64.shr_s)
     (func $unsigned_shr (param $val i64) (param $shift i32) (result i64)
       local.get $val
       local.get $shift
       i64.shr_u)
   )
   ```

**第2部分功能归纳:**

这部分代码延续了第1部分的测试，继续专注于 WebAssembly 中 64 位整数 (`i64`) 的功能测试。它涵盖了以下主要方面：

* **更多的位操作测试:**  例如 `i64.ror` 和 `i64.rol`。
* **更全面的内存操作测试:** 包括针对特定对齐方式的加载和存储，以及越界访问的测试。
* **类型转换的测试:** 涵盖了 `i64` 和 `f64` 之间的相互转换。
* **全局变量的测试:** 验证了对 `i64` 类型全局变量的正确操作。
* **函数调用的测试:**  包括直接调用和间接调用，以及涉及混合类型参数的调用。
* **回归测试:** 修复已知bug的测试用例。

总而言之，这部分代码与第1部分共同构成了对 V8 引擎中 WebAssembly 64 位整数功能的全面测试，确保了各种操作在不同场景下的正确性和稳定性。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
on_tier, kExprI64And, 2531040582801836054,
               0xAF257D1602644A16, 0x33B290A91A10D997);
  TestI64Binop(execution_tier, kExprI64Ior, 8556201506536114940,
               0x169D9BE7BD3F0A5C, 0x66BCA28D77AF40E8);
  TestI64Binop(execution_tier, kExprI64Xor, -4605655183785456377,
               0xB6EA20A5D48E85B8, 0x76FF4DA6C80688BF);
  TestI64Binop(execution_tier, kExprI64Shl, -7240704056088331264,
               0xEF4DC1ED030E8FFE, 9);
  TestI64Binop(execution_tier, kExprI64ShrU, 12500673744059159,
               0xB1A52FA7DEEC5D14, 10);
  TestI64Binop(execution_tier, kExprI64ShrS, 1725103446999874,
               0x3107C791461A112B, 11);
  TestI64Binop(execution_tier, kExprI64Ror, -8960135652432576946,
               0x73418D1717E4E83A, 12);
  TestI64Binop(execution_tier, kExprI64Ror, 7617662827409989779,
               0xEBFF67CF0C126D36, 13);
  TestI64Binop(execution_tier, kExprI64Rol, -2097714064174346012,
               0x43938B8DB0B0F230, 14);
  TestI64Binop(execution_tier, kExprI64Rol, 8728493013947314237,
               0xE07AF243AC4D219D, 15);
}

WASM_EXEC_TEST(I64Compare) {
  TestI64Cmp(execution_tier, kExprI64Eq, 0, 0xB915D8FA494064F0,
             0x04D700B2536019A3);
  TestI64Cmp(execution_tier, kExprI64Ne, 1, 0xC2FAFAAAB0446CDC,
             0x52A3328F780C97A3);
  TestI64Cmp(execution_tier, kExprI64LtS, 0, 0x673636E6306B0578,
             0x028EC9ECA78F7227);
  TestI64Cmp(execution_tier, kExprI64LeS, 1, 0xAE5214114B86A0FA,
             0x7C1D21DA3DFD0CCF);
  TestI64Cmp(execution_tier, kExprI64LtU, 0, 0x7D52166381EC1CE0,
             0x59F4A6A9E78CD3D8);
  TestI64Cmp(execution_tier, kExprI64LeU, 1, 0xE4169A385C7EA0E0,
             0xFBDBED2C8781E5BC);
  TestI64Cmp(execution_tier, kExprI64GtS, 0, 0x9D08FF8FB5F42E81,
             0xD4E5C9D7FE09F621);
  TestI64Cmp(execution_tier, kExprI64GeS, 1, 0x78DA3B2F73264E0F,
             0x6FE5E2A67C501CBE);
  TestI64Cmp(execution_tier, kExprI64GtU, 0, 0x8F691284E44F7DA9,
             0xD5EA9BC1EE149192);
  TestI64Cmp(execution_tier, kExprI64GeU, 0, 0x0886A0C58C7AA224,
             0x5DDBE5A81FD7EE47);
}

WASM_EXEC_TEST(I64Clz) {
  struct {
    int64_t expected;
    uint64_t input;
  } values[] = {{0, 0x8000100000000000},  {1, 0x4000050000000000},
                {2, 0x2000030000000000},  {3, 0x1000000300000000},
                {4, 0x0805000000000000},  {5, 0x0400600000000000},
                {6, 0x0200000000000000},  {7, 0x010000A000000000},
                {8, 0x00800C0000000000},  {9, 0x0040000000000000},
                {10, 0x0020000D00000000}, {11, 0x00100F0000000000},
                {12, 0x0008000000000000}, {13, 0x0004100000000000},
                {14, 0x0002002000000000}, {15, 0x0001030000000000},
                {16, 0x0000804000000000}, {17, 0x0000400500000000},
                {18, 0x0000205000000000}, {19, 0x0000170000000000},
                {20, 0x0000087000000000}, {21, 0x0000040500000000},
                {22, 0x0000020300000000}, {23, 0x0000010100000000},
                {24, 0x0000008900000000}, {25, 0x0000004100000000},
                {26, 0x0000002200000000}, {27, 0x0000001300000000},
                {28, 0x0000000800000000}, {29, 0x0000000400000000},
                {30, 0x0000000200000000}, {31, 0x0000000100000000},
                {32, 0x0000000080001000}, {33, 0x0000000040000500},
                {34, 0x0000000020000300}, {35, 0x0000000010000003},
                {36, 0x0000000008050000}, {37, 0x0000000004006000},
                {38, 0x0000000002000000}, {39, 0x00000000010000A0},
                {40, 0x0000000000800C00}, {41, 0x0000000000400000},
                {42, 0x000000000020000D}, {43, 0x0000000000100F00},
                {44, 0x0000000000080000}, {45, 0x0000000000041000},
                {46, 0x0000000000020020}, {47, 0x0000000000010300},
                {48, 0x0000000000008040}, {49, 0x0000000000004005},
                {50, 0x0000000000002050}, {51, 0x0000000000001700},
                {52, 0x0000000000000870}, {53, 0x0000000000000405},
                {54, 0x0000000000000203}, {55, 0x0000000000000101},
                {56, 0x0000000000000089}, {57, 0x0000000000000041},
                {58, 0x0000000000000022}, {59, 0x0000000000000013},
                {60, 0x0000000000000008}, {61, 0x0000000000000004},
                {62, 0x0000000000000002}, {63, 0x0000000000000001},
                {64, 0x0000000000000000}};

  WasmRunner<int64_t, uint64_t> r(execution_tier);
  r.Build({WASM_I64_CLZ(WASM_LOCAL_GET(0))});
  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(values[i].expected, r.Call(values[i].input));
  }
}

WASM_EXEC_TEST(I64Ctz) {
  struct {
    int64_t expected;
    uint64_t input;
  } values[] = {{64, 0x0000000000000000}, {63, 0x8000000000000000},
                {62, 0x4000000000000000}, {61, 0x2000000000000000},
                {60, 0x1000000000000000}, {59, 0xA800000000000000},
                {58, 0xF400000000000000}, {57, 0x6200000000000000},
                {56, 0x9100000000000000}, {55, 0xCD80000000000000},
                {54, 0x0940000000000000}, {53, 0xAF20000000000000},
                {52, 0xAC10000000000000}, {51, 0xE0B8000000000000},
                {50, 0x9CE4000000000000}, {49, 0xC792000000000000},
                {48, 0xB8F1000000000000}, {47, 0x3B9F800000000000},
                {46, 0xDB4C400000000000}, {45, 0xE9A3200000000000},
                {44, 0xFCA6100000000000}, {43, 0x6C8A780000000000},
                {42, 0x8CE5A40000000000}, {41, 0xCB7D020000000000},
                {40, 0xCB4DC10000000000}, {39, 0xDFBEC58000000000},
                {38, 0x27A9DB4000000000}, {37, 0xDE3BCB2000000000},
                {36, 0xD7E8A61000000000}, {35, 0x9AFDBC8800000000},
                {34, 0x9AFDBC8400000000}, {33, 0x9AFDBC8200000000},
                {32, 0x9AFDBC8100000000}, {31, 0x0000000080000000},
                {30, 0x0000000040000000}, {29, 0x0000000020000000},
                {28, 0x0000000010000000}, {27, 0x00000000A8000000},
                {26, 0x00000000F4000000}, {25, 0x0000000062000000},
                {24, 0x0000000091000000}, {23, 0x00000000CD800000},
                {22, 0x0000000009400000}, {21, 0x00000000AF200000},
                {20, 0x00000000AC100000}, {19, 0x00000000E0B80000},
                {18, 0x000000009CE40000}, {17, 0x00000000C7920000},
                {16, 0x00000000B8F10000}, {15, 0x000000003B9F8000},
                {14, 0x00000000DB4C4000}, {13, 0x00000000E9A32000},
                {12, 0x00000000FCA61000}, {11, 0x000000006C8A7800},
                {10, 0x000000008CE5A400}, {9, 0x00000000CB7D0200},
                {8, 0x00000000CB4DC100},  {7, 0x00000000DFBEC580},
                {6, 0x0000000027A9DB40},  {5, 0x00000000DE3BCB20},
                {4, 0x00000000D7E8A610},  {3, 0x000000009AFDBC88},
                {2, 0x000000009AFDBC84},  {1, 0x000000009AFDBC82},
                {0, 0x000000009AFDBC81}};

  WasmRunner<int64_t, uint64_t> r(execution_tier);
  r.Build({WASM_I64_CTZ(WASM_LOCAL_GET(0))});
  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(values[i].expected, r.Call(values[i].input));
  }
}

WASM_EXEC_TEST(I64Popcnt2) {
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

// Test the WasmRunner with an Int64 return value and different numbers of
// Int64 parameters.
WASM_EXEC_TEST(I64WasmRunner) {
  FOR_INT64_INPUTS(i) {
    WasmRunner<int64_t> r(execution_tier);
    r.Build({WASM_I64V(i)});
    CHECK_EQ(i, r.Call());
  }
  {
    WasmRunner<int64_t, int64_t> r(execution_tier);
    r.Build({WASM_LOCAL_GET(0)});
    FOR_INT64_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
  }
  {
    WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_XOR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) { CHECK_EQ(i ^ j, r.Call(i, j)); }
    }
  }
  {
    WasmRunner<int64_t, int64_t, int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_XOR(WASM_LOCAL_GET(0),
                          WASM_I64_XOR(WASM_LOCAL_GET(1), WASM_LOCAL_GET(2)))});
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        CHECK_EQ(i ^ j ^ j, r.Call(i, j, j));
        CHECK_EQ(j ^ i ^ j, r.Call(j, i, j));
        CHECK_EQ(j ^ j ^ i, r.Call(j, j, i));
      }
    }
  }
  {
    WasmRunner<int64_t, int64_t, int64_t, int64_t, int64_t> r(execution_tier);
    r.Build({WASM_I64_XOR(
        WASM_LOCAL_GET(0),
        WASM_I64_XOR(WASM_LOCAL_GET(1),
                     WASM_I64_XOR(WASM_LOCAL_GET(2), WASM_LOCAL_GET(3))))});
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        CHECK_EQ(i ^ j ^ j ^ j, r.Call(i, j, j, j));
        CHECK_EQ(j ^ i ^ j ^ j, r.Call(j, i, j, j));
        CHECK_EQ(j ^ j ^ i ^ j, r.Call(j, j, i, j));
        CHECK_EQ(j ^ j ^ j ^ i, r.Call(j, j, j, i));
      }
    }
  }
}

WASM_EXEC_TEST(Call_Int64Sub) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  // Build the target function.
  TestSignatures sigs;
  WasmFunctionCompiler& t = r.NewFunction(sigs.l_ll());
  t.Build({WASM_I64_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  // Build the caller function.
  r.Build({WASM_CALL_FUNCTION(t.function_index(), WASM_LOCAL_GET(0),
                              WASM_LOCAL_GET(1))});

  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      CHECK_EQ(base::SubWithWraparound(i, j), r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(LoadStoreI64_sx) {
  uint8_t loads[] = {kExprI64LoadMem8S, kExprI64LoadMem16S, kExprI64LoadMem32S,
                     kExprI64LoadMem};

  for (size_t m = 0; m < arraysize(loads); m++) {
    WasmRunner<int64_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);

    uint8_t code[] = {
        kExprI32Const,    8,  // --
        kExprI32Const,    0,  // --
        loads[m],             // --
        ZERO_ALIGNMENT,       // --
        ZERO_OFFSET,          // --
        kExprI64StoreMem,     // --
        ZERO_ALIGNMENT,       // --
        ZERO_OFFSET,          // --
        kExprI32Const,    0,  // --
        loads[m],             // --
        ZERO_ALIGNMENT,       // --
        ZERO_OFFSET,          // --
    };

    r.Build(code, code + arraysize(code));

    // Try a bunch of different negative values.
    for (int i = -1; i >= -128; i -= 11) {
      int size = 1 << m;
      r.builder().BlankMemory();
      memory[size - 1] = static_cast<uint8_t>(i);  // set the high order byte.

      int64_t expected = static_cast<uint64_t>(static_cast<int64_t>(i))
                         << ((size - 1) * 8);

      CHECK_EQ(expected, r.Call());
      CHECK_EQ(static_cast<uint8_t>(i), memory[8 + size - 1]);
      for (int j = size; j < 8; j++) {
        CHECK_EQ(255, memory[8 + j]);
      }
    }
  }
}

WASM_EXEC_TEST(I64ReinterpretF64) {
  WasmRunner<int64_t> r(execution_tier);
  int64_t* memory =
      r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));

  r.Build({WASM_I64_REINTERPRET_F64(
      WASM_LOAD_MEM(MachineType::Float64(), WASM_ZERO))});

  FOR_INT32_INPUTS(i) {
    int64_t expected =
        base::MulWithWraparound(static_cast<int64_t>(i), int64_t{0x300010001L});
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(SignallingNanSurvivesI64ReinterpretF64) {
  WasmRunner<int64_t> r(execution_tier);
  r.Build({WASM_I64_REINTERPRET_F64(WASM_SEQ(kExprF64Const, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0xF4, 0x7F))});

  // This is a signalling nan.
  CHECK_EQ(0x7FF4000000000000, r.Call());
}

WASM_EXEC_TEST(F64ReinterpretI64) {
  WasmRunner<int64_t, int64_t> r(execution_tier);
  int64_t* memory =
      r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));

  r.Build({WASM_STORE_MEM(MachineType::Float64(), WASM_ZERO,
                          WASM_F64_REINTERPRET_I64(WASM_LOCAL_GET(0))),
           WASM_LOCAL_GET(0)});

  FOR_INT32_INPUTS(i) {
    int64_t expected =
        base::MulWithWraparound(static_cast<int64_t>(i), int64_t{0x300010001L});
    CHECK_EQ(expected, r.Call(expected));
    CHECK_EQ(expected, r.builder().ReadMemory<int64_t>(&memory[0]));
  }
}

WASM_EXEC_TEST(LoadMemI64) {
  WasmRunner<int64_t> r(execution_tier);
  int64_t* memory =
      r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));
  r.builder().RandomizeMemory(1111);

  r.Build({WASM_LOAD_MEM(MachineType::Int64(), WASM_ZERO)});

  r.builder().WriteMemory<int64_t>(&memory[0], 0x1ABBCCDD00112233LL);
  CHECK_EQ(0x1ABBCCDD00112233LL, r.Call());

  r.builder().WriteMemory<int64_t>(&memory[0], 0x33AABBCCDD001122LL);
  CHECK_EQ(0x33AABBCCDD001122LL, r.Call());

  r.builder().WriteMemory<int64_t>(&memory[0], 77777777);
  CHECK_EQ(77777777, r.Call());
}

WASM_EXEC_TEST(LoadMemI64_alignment) {
  for (uint8_t alignment = 0; alignment <= 3; alignment++) {
    WasmRunner<int64_t> r(execution_tier);
    int64_t* memory =
        r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));
    r.builder().RandomizeMemory(1111);

    r.Build(
        {WASM_LOAD_MEM_ALIGNMENT(MachineType::Int64(), WASM_ZERO, alignment)});

    r.builder().WriteMemory<int64_t>(&memory[0], 0x1ABBCCDD00112233LL);
    CHECK_EQ(0x1ABBCCDD00112233LL, r.Call());

    r.builder().WriteMemory<int64_t>(&memory[0], 0x33AABBCCDD001122LL);
    CHECK_EQ(0x33AABBCCDD001122LL, r.Call());

    r.builder().WriteMemory<int64_t>(&memory[0], 77777777);
    CHECK_EQ(77777777, r.Call());
  }
}

WASM_EXEC_TEST(MemI64_Sum) {
  const int kNumElems = 20;
  WasmRunner<uint64_t, int32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  const uint8_t kSum = r.AllocateLocal(kWasmI64);

  r.Build(
      {WASM_WHILE(
           WASM_LOCAL_GET(0),
           WASM_BLOCK(WASM_LOCAL_SET(
                          kSum, WASM_I64_ADD(WASM_LOCAL_GET(kSum),
                                             WASM_LOAD_MEM(MachineType::Int64(),
                                                           WASM_LOCAL_GET(0)))),
                      WASM_LOCAL_SET(
                          0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(8))))),
       WASM_LOCAL_GET(1)});

  // Run 4 trials.
  for (int i = 0; i < 3; i++) {
    r.builder().RandomizeMemory(i * 33);
    uint64_t expected = 0;
    for (size_t j = kNumElems - 1; j > 0; j--) {
      expected += r.builder().ReadMemory(&memory[j]);
    }
    uint64_t result = r.Call(8 * (kNumElems - 1));
    CHECK_EQ(expected, result);
  }
}

WASM_EXEC_TEST(StoreMemI64_alignment) {
  const int64_t kWritten = 0x12345678ABCD0011ll;

  for (uint8_t i = 0; i <= 3; i++) {
    WasmRunner<int64_t, int64_t> r(execution_tier);
    int64_t* memory =
        r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));
    r.Build({WASM_STORE_MEM_ALIGNMENT(MachineType::Int64(), WASM_ZERO, i,
                                      WASM_LOCAL_GET(0)),
             WASM_LOCAL_GET(0)});
    r.builder().RandomizeMemory(1111);
    r.builder().WriteMemory<int64_t>(&memory[0], 0);

    CHECK_EQ(kWritten, r.Call(kWritten));
    CHECK_EQ(kWritten, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(I64Global) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int64_t* global = r.builder().AddGlobal<int64_t>();
  // global = global + p0
  r.Build({WASM_GLOBAL_SET(
               0, WASM_I64_AND(WASM_GLOBAL_GET(0),
                               WASM_I64_SCONVERT_I32(WASM_LOCAL_GET(0)))),
           WASM_ZERO});

  r.builder().WriteMemory<int64_t>(global, 0xFFFFFFFFFFFFFFFFLL);
  for (int i = 9; i < 444444; i += 111111) {
    int64_t expected = *global & i;
    r.Call(i);
    CHECK_EQ(expected, *global);
  }
}

WASM_EXEC_TEST(I64Eqz) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_EQZ(WASM_LOCAL_GET(0))});

  FOR_INT64_INPUTS(i) {
    int32_t result = i == 0 ? 1 : 0;
    CHECK_EQ(result, r.Call(i));
  }
}

WASM_EXEC_TEST(I64Ror) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_ROR(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      int64_t expected = base::bits::RotateRight64(i, j & 0x3F);
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64Rol) {
  WasmRunner<int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_ROL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      int64_t expected = base::bits::RotateLeft64(i, j & 0x3F);
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(StoreMem_offset_oob_i64) {
  static const MachineType machineTypes[] = {
      MachineType::Int8(),   MachineType::Uint8(),  MachineType::Int16(),
      MachineType::Uint16(), MachineType::Int32(),  MachineType::Uint32(),
      MachineType::Int64(),  MachineType::Uint64(), MachineType::Float32(),
      MachineType::Float64()};

  constexpr size_t num_bytes = kWasmPageSize;

  for (size_t m = 0; m < arraysize(machineTypes); m++) {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(num_bytes);
    r.builder().RandomizeMemory(1119 + static_cast<int>(m));

    r.Build({WASM_STORE_MEM_OFFSET(machineTypes[m], 8, WASM_LOCAL_GET(0),
                                   WASM_LOAD_MEM(machineTypes[m], WASM_ZERO)),
             WASM_ZERO});

    uint8_t memsize = machineTypes[m].MemSize();
    uint32_t boundary = num_bytes - 8 - memsize;
    CHECK_EQ(0, r.Call(boundary));  // in bounds.
    CHECK_EQ(0, memcmp(&memory[0], &memory[8 + boundary], memsize));

    for (uint32_t offset = boundary + 1; offset < boundary + 19; offset++) {
      CHECK_TRAP32(r.Call(offset));  // out of bounds.
    }
  }
}

WASM_EXEC_TEST(Store_i64_narrowed) {
  constexpr uint8_t kOpcodes[] = {kExprI64StoreMem8, kExprI64StoreMem16,
                                  kExprI64StoreMem32, kExprI64StoreMem};
  int stored_size_in_bytes = 0;
  for (auto opcode : kOpcodes) {
    stored_size_in_bytes = std::max(1, stored_size_in_bytes * 2);
    constexpr int kBytes = 24;
    uint8_t expected_memory[kBytes] = {0};
    WasmRunner<int32_t, int32_t, int64_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
    constexpr uint64_t kPattern = 0x0123456789abcdef;

    r.Build({WASM_LOCAL_GET(0),                    // index
             WASM_LOCAL_GET(1),                    // value
             opcode, ZERO_ALIGNMENT, ZERO_OFFSET,  // store
             WASM_ZERO});                          // return value

    for (int i = 0; i <= kBytes - stored_size_in_bytes; ++i) {
      uint64_t pattern = base::bits::RotateLeft64(kPattern, i % 64);
      r.Call(i, pattern);
      for (int b = 0; b < stored_size_in_bytes; ++b) {
        expected_memory[i + b] = static_cast<uint8_t>(pattern >> (b * 8));
      }
      for (int w = 0; w < kBytes; ++w) {
        CHECK_EQ(expected_memory[w], memory[w]);
      }
    }
  }
}

WASM_EXEC_TEST(UnalignedInt64Load) {
  WasmRunner<uint64_t> r(execution_tier);
  r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));
  r.Build({WASM_LOAD_MEM_ALIGNMENT(MachineType::Int64(), WASM_ONE, 3)});
  r.Call();
}

WASM_EXEC_TEST(UnalignedInt64Store) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(int64_t));
  r.Build({WASM_SEQ(WASM_STORE_MEM_ALIGNMENT(MachineType::Int64(), WASM_ONE, 3,
                                             WASM_I64V_1(1)),
                    WASM_I32V_1(12))});
  r.Call();
}

static void CompileCallIndirectMany(TestExecutionTier tier, ValueType param) {
  // Make sure we don't run out of registers when compiling indirect calls
  // with many many parameters.
  TestSignatures sigs;
  for (uint8_t num_params = 0; num_params < 40; num_params++) {
    WasmRunner<void> r(tier);
    FunctionSig* sig = sigs.many(r.zone(), kWasmVoid, param, num_params);

    r.builder().AddSignature(sig);
    r.builder().AddSignature(sig);
    r.builder().AddIndirectFunctionTable(nullptr, 0);

    WasmFunctionCompiler& t = r.NewFunction(sig);

    std::vector<uint8_t> code;
    for (uint8_t p = 0; p < num_params; p++) {
      ADD_CODE(code, kExprLocalGet, p);
    }
    ADD_CODE(code, kExprI32Const, 0);
    ADD_CODE(code, kExprCallIndirect, 1, TABLE_ZERO);

    t.Build(base::VectorOf(code));
  }
}

WASM_EXEC_TEST(Compile_Wasm_CallIndirect_Many_i64) {
  CompileCallIndirectMany(execution_tier, kWasmI64);
}

static void Run_WasmMixedCall_N(TestExecutionTier execution_tier, int start) {
  const int kExpected = 6333;
  const int kElemSize = 8;

  static MachineType mixed[] = {
      MachineType::Int32(),   MachineType::Float32(), MachineType::Int64(),
      MachineType::Float64(), MachineType::Float32(), MachineType::Int64(),
      MachineType::Int32(),   MachineType::Float64(), MachineType::Float32(),
      MachineType::Float64(), MachineType::Int32(),   MachineType::Int64(),
      MachineType::Int32(),   MachineType::Int32()};

  int num_params = static_cast<int>(arraysize(mixed)) - start;
  for (int which = 0; which < num_params; which++) {
    v8::internal::AccountingAllocator allocator;
    Zone zone(&allocator, ZONE_NAME);
    WasmRunner<int32_t> r(execution_tier);
    r.builder().AddMemory(kWasmPageSize);
    MachineType* memtypes = &mixed[start];
    MachineType result = memtypes[which];

    // =========================================================================
    // Build the selector function.
    // =========================================================================
    FunctionSig::Builder b(&zone, 1, num_params);
    b.AddReturn(ValueType::For(result));
    for (int i = 0; i < num_params; i++) {
      b.AddParam(ValueType::For(memtypes[i]));
    }
    WasmFunctionCompiler& f = r.NewFunction(b.Get());
    f.Build({WASM_LOCAL_GET(which)});

    // =========================================================================
    // Build the calling function.
    // =========================================================================
    std::vector<uint8_t> code;

    // Load the arguments.
    for (int i = 0; i < num_params; i++) {
      int offset = (i + 1) * kElemSize;
      ADD_CODE(code, WASM_LOAD_MEM(memtypes[i], WASM_I32V_2(offset)));
    }

    // Call the selector function.
    ADD_CODE(code, WASM_CALL_FUNCTION0(f.function_index()));

    // Store the result in a local.
    uint8_t local_index = r.AllocateLocal(ValueType::For(result));
    ADD_CODE(code, kExprLocalSet, local_index);

    // Store the result in memory.
    ADD_CODE(code,
             WASM_STORE_MEM(result, WASM_ZERO, WASM_LOCAL_GET(local_index)));

    // Return the expected value.
    ADD_CODE(code, WASM_I32V_2(kExpected));

    r.Build(&code[0], &code[0] + code.size());

    // Run the code.
    for (int t = 0; t < 10; t++) {
      r.builder().RandomizeMemory();
      CHECK_EQ(kExpected, r.Call());

      int size = result.MemSize();
      for (int i = 0; i < size; i++) {
        int base = (which + 1) * kElemSize;
        uint8_t expected = r.builder().raw_mem_at<uint8_t>(base + i);
        uint8_t actual = r.builder().raw_mem_at<uint8_t>(i);
        CHECK_EQ(expected, actual);
      }
    }
  }
}

WASM_EXEC_TEST(MixedCall_i64_0) { Run_WasmMixedCall_N(execution_tier, 0); }
WASM_EXEC_TEST(MixedCall_i64_1) { Run_WasmMixedCall_N(execution_tier, 1); }
WASM_EXEC_TEST(MixedCall_i64_2) { Run_WasmMixedCall_N(execution_tier, 2); }
WASM_EXEC_TEST(MixedCall_i64_3) { Run_WasmMixedCall_N(execution_tier, 3); }

WASM_EXEC_TEST(Regress5874) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));

  r.Build({kExprI64Const, 0x00,           // --
           kExprI32ConvertI64,            // --
           kExprI64Const, 0x00,           // --
           kExprI64StoreMem, 0x03, 0x00,  // --
           kExprI32Const, 0x00});         // --

  r.Call();
}

WASM_EXEC_TEST(Regression_6858) {
  // WasmRunner with 5 params and returns, which is the maximum.
  WasmRunner<int64_t, int64_t, int64_t, int64_t, int64_t> r(execution_tier);
  r.Build({WASM_I64_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  int64_t dividend = 15;
  int64_t divisor = 0;
  int64_t filler = 34;
  CHECK_TRAP64(r.Call(dividend, divisor, filler, filler));
}

// clang-format gets confused about these closing parentheses (wants to change
// the first comment to "// namespace v8". Disable it.
// clang-format off
}  // namespace test_run_wasm_64
}  // namespace wasm
}  // namespace internal
}  // namespace v8
// clang-format on

"""


```