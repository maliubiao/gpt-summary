Response:
The user wants a summary of the provided C++ code snippet, which is a part of the V8 JavaScript engine's testing framework.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `test-macro-assembler-riscv32.cc` strongly suggests this code tests the `MacroAssembler` class for the RISC-V 32-bit architecture. The `MacroAssembler` is used for generating machine code at runtime.

2. **Analyze the structure:** The code is organized into a series of `TEST` macros. Each `TEST` macro likely focuses on testing specific functionalities of the `MacroAssembler`.

3. **Examine individual tests:**  Go through each `TEST` block and identify what it's testing:
    * `macro_float_minmax_f32`:  Tests the `Float32Min` and `Float32Max` macros for single-precision floating-point numbers.
    * `macro_float_minmax_f64`: Tests the `Float64Min` and `Float64Max` macros for double-precision floating-point numbers.
    * `FCompare32_Branch`: Tests floating-point comparison instructions for single-precision numbers and branching based on the result. It also tests `CompareIsNanF32`.
    * `CompareI`: Tests integer comparison instructions, including comparisons with immediate values and register-to-register comparisons.
    * `Clz32`: Tests the "count leading zeros" instruction for 32-bit integers.
    * `Ctz32`: Tests the "count trailing zeros" instruction for 32-bit integers.
    * `ByteSwap`: Tests the byte swap instruction.
    * `ByteSwap_no_scratch`: Tests the byte swap instruction without using a scratch register.
    * `Popcnt`: Tests the "population count" (number of set bits) instruction.
    * `DeoptExitSizeIsFixed`: Tests that the size of the generated code for deoptimization exits is fixed, which is crucial for performance and correctness.
    * `AddWithImm`: Tests the `AddWord` and `SubWord` instructions with immediate operands.

4. **Identify common themes and functionalities:**  Notice that many tests involve:
    * **Floating-point operations:** Min/Max, comparisons, NaN checks.
    * **Integer operations:** Comparisons, bit manipulation (clz, ctz, popcnt, byteswap).
    * **Code generation:** The `MacroAssembler` is used to generate code snippets.
    * **Testing with various inputs:**  The tests iterate through different input values to ensure correctness under different conditions.
    * **Checking expected outputs:** The `CHECK_EQ` macro is used to verify that the generated code produces the correct results.

5. **Address specific instructions from the prompt:**
    * **`.tq` suffix:**  The code is `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:** These low-level assembler tests directly support the implementation of JavaScript features. For example, the floating-point min/max and comparison operations are fundamental to JavaScript's number handling.
    * **Code logic reasoning:** The `CHECK_MINMAX` macros in the min/max tests provide clear examples of input/output relationships. The comparison tests also implicitly demonstrate this.
    * **Common programming errors:** The floating-point tests highlight potential issues with NaN and the difference between `-0.0` and `0.0`. Integer comparisons also have subtleties related to signed vs. unsigned interpretations.

6. **Synthesize the summary:** Combine the observations into a coherent summary, highlighting the key functionalities tested and their relevance. Emphasize the focus on RISC-V 32-bit architecture. Address each point raised in the prompt.

7. **Review and refine:** Ensure the summary is accurate, comprehensive, and easy to understand. Check for any missing information or areas that could be clearer. For example, explicitly mention that it tests *code generation* for various instructions. Also, make sure to address the "Part 2" aspect by stating that it's a continuation of testing the `MacroAssembler`.
好的，这是第2部分，让我们来归纳一下 `v8/test/cctest/test-macro-assembler-riscv32.cc` 这个文件的功能。

**归纳总结:**

`v8/test/cctest/test-macro-assembler-riscv32.cc`  这个 C++ 文件是 V8 JavaScript 引擎测试套件的一部分，专门用于测试 RISC-V 32 位架构下的 `MacroAssembler` 类的功能。  `MacroAssembler` 是 V8 中一个核心的组件，它提供了一组宏指令，用于在运行时动态生成 RISC-V 汇编代码。

这个文件的主要功能可以概括为：

1. **测试 RISC-V 32 位指令的生成和执行:**  它包含了多个独立的测试用例（通过 `TEST` 宏定义），每个测试用例都针对 `MacroAssembler` 类的特定方法或一组相关方法。这些测试覆盖了 RISC-V 架构中常见的指令，例如：
    * **浮点运算指令:** `Float32Min`, `Float32Max`, `Float64Min`, `Float64Max` (最小值/最大值计算)。
    * **浮点比较指令:** `CompareF32`, `CompareF64`, `CompareIsNanF32` (浮点数比较，包括 NaN 的判断)。
    * **整数比较指令:** `CompareI` (整数比较，包括与立即数的比较)。
    * **位操作指令:** `Clz32` (计算前导零), `Ctz32` (计算尾部零), `ByteSwap` (字节交换), `Popcnt32` (计算置位位数)。
    * **数据移动指令:**  虽然被注释掉了，但可以看到有测试 `ExtractHighWordFromF64` 和 `ExtractLowWordFromF64` 的意图。
    * **控制流指令:**  通过浮点和整数比较指令来间接测试分支。
    * **算术指令:** `AddWord`, `SubWord` (带立即数的加减)。

2. **验证 `MacroAssembler` 生成代码的正确性:** 每个测试用例都会使用 `MacroAssembler` 生成一段小的汇编代码片段，然后执行这段代码，并将执行结果与预期值进行比较（通过 `CHECK_EQ` 等宏）。 这确保了 `MacroAssembler` 能够正确地将宏指令转换为有效的 RISC-V 机器码，并且这些机器码能够按预期运行。

3. **测试特定场景和边界条件:**  测试用例会覆盖各种不同的输入值，包括正常值、边界值（例如最小值、最大值）、特殊值（例如 NaN，正零，负零），以及不同的寄存器使用方式，以确保 `MacroAssembler` 的健壮性和正确性。

4. **检查代码生成的相关特性:**  例如，`TEST(DeoptExitSizeIsFixed)` 用于验证在生成反优化出口代码时，代码的大小是固定的，这对于 V8 的性能优化至关重要。

**与之前的讨论结合:**

这个文件是 `v8/test/cctest/test-macro-assembler-riscv32.cc` 的第二部分，延续了第一部分的功能，继续对 `MacroAssembler` 类在 RISC-V 32 位架构上的功能进行更全面的测试。它专注于测试更多的指令和更复杂的场景。

**总结来说，`v8/test/cctest/test-macro-assembler-riscv32.cc` 是 V8 引擎中用于验证 RISC-V 32 位代码生成器正确性的关键测试文件。它通过编写和执行各种针对特定 RISC-V 指令的测试用例，确保 V8 能够在 RISC-V 32 位平台上生成正确且高效的机器码。**

**关于您之前提出的问题:**

* **`.tq` 结尾:** 这个文件是 `.cc` 结尾，所以是 C++ 源代码，不是 Torque 源代码。
* **与 JavaScript 的关系:**  `MacroAssembler` 生成的 RISC-V 代码是 V8 引擎执行 JavaScript 代码的基础。例如，JavaScript 中的数学运算（加减乘除、最小值/最大值等）、比较操作、位运算等，最终都会由 `MacroAssembler` 生成相应的 RISC-V 指令来执行。

**JavaScript 例子 (对应浮点数 Min/Max):**

```javascript
function findMinMax(a, b) {
  return { min: Math.min(a, b), max: Math.max(a, b) };
}

console.log(findMinMax(1.5, 0.8)); // 输出: { min: 0.8, max: 1.5 }
console.log(findMinMax(-0.0, 0.0)); // 输出: { min: -0, max: 0 }
console.log(findMinMax(NaN, 5));    // 输出: { min: NaN, max: NaN }
```

当 V8 引擎执行 `Math.min()` 和 `Math.max()` 时，在 RISC-V 32 位架构上，会使用到 `MacroAssembler` 生成的类似于 `fmin.s` 和 `fmax.s` 的指令（在单精度浮点数的情况下）或者 `fmin.d` 和 `fmax.d` 的指令（在双精度浮点数的情况下），就像这个 C++ 测试文件中测试的那样。

**代码逻辑推理 (对应 `CHECK_MINMAX` 宏):**

假设输入 `src1 = 1.0f`, `src2 = -1.0f`。

根据 `CHECK_MINMAX(1.0f, -1.0f, -1.0f, 1.0f)`，预期的输出是：

* `min_abc_`, `min_aab_`, `min_aba_` (最小值): `-1.0f`
* `max_abc_`, `max_aab_`, `max_aba_` (最大值): `1.0f`

测试代码会执行生成的汇编代码，使用 `1.0f` 和 `-1.0f` 作为输入，然后检查计算出的最小值和最大值是否与预期值 `-1.0f` 和 `1.0f` 相符。

**用户常见的编程错误 (与 NaN 比较):**

```javascript
let x = NaN;
console.log(x == NaN);      // 输出: false  (NaN 与任何值（包括自身）都不相等)
console.log(x === NaN);     // 输出: false
console.log(x < 5);         // 输出: false
console.log(x > 5);         // 输出: false
console.log(x <= 5);        // 输出: false
console.log(x >= 5);        // 输出: false

// 正确检查 NaN 的方式
console.log(isNaN(x));     // 输出: true
```

这个 C++ 测试文件中针对 NaN 的测试（例如 `CHECK_MINMAX(0.0f, nan_a, nan_a, nan_a);`）反映了 JavaScript 中处理 NaN 的特殊性。 开发者容易犯的错误是使用 `==` 或 `===` 来判断一个值是否为 NaN，这是不正确的。应该使用全局函数 `isNaN()` 来进行判断。

Prompt: 
```
这是目录为v8/test/cctest/test-macro-assembler-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-macro-assembler-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
.0f);
  CHECK_MINMAX(0.0f, -1.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
  CHECK_MINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
  CHECK_MINMAX(0.0f, 1.0f, 0.0f, 1.0f);
  CHECK_MINMAX(1.0f, 0.0f, 0.0f, 1.0f);

  CHECK_MINMAX(0.0f, 0.0f, 0.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
  CHECK_MINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
  CHECK_MINMAX(0.0f, -0.0f, -0.0f, 0.0f);

  CHECK_MINMAX(0.0f, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0f, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

template <typename T, typename Inputs, typename Results>
static void GenerateMacroFloat64MinMax(MacroAssembler& masm) {
  T a = T::from_code(5);  // ft5
  T b = T::from_code(6);  // ft6
  T c = T::from_code(7);  // ft7

#define FLOAT_MIN_MAX(fminmax, res, x, y, res_field)         \
  __ LoadDouble(x, MemOperand(a0, offsetof(Inputs, src1_))); \
  __ LoadDouble(y, MemOperand(a0, offsetof(Inputs, src2_))); \
  __ fminmax(res, x, y);                                     \
  __ StoreDouble(res, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float64Min, a, b, c, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float64Min, a, a, b, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float64Min, a, b, a, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float64Max, a, b, c, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float64Max, a, a, b, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float64Max, a, b, a, max_aba_);

#undef FLOAT_MIN_MAX
}

TEST(macro_float_minmax_f64) {
  // Test the Float64Min and Float64Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct Inputs {
    double src1_;
    double src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro masm.
    double min_abc_;
    double min_aab_;
    double min_aba_;
    double max_abc_;
    double max_aab_;
    double max_aba_;
  };

  auto f = AssembleCode<F4>(
      isolate, GenerateMacroFloat64MinMax<DoubleRegister, Inputs, Results>);

#define CHECK_MINMAX(src1, src2, min, max)                          \
  do {                                                              \
    Inputs inputs = {src1, src2};                                   \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aba_));           \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
  } while (0)

  double nan_a = qnan_d;
  double nan_b = qnan_d;

  CHECK_MINMAX(1.0, -1.0, -1.0, 1.0);
  CHECK_MINMAX(-1.0, 1.0, -1.0, 1.0);
  CHECK_MINMAX(0.0, -1.0, -1.0, 0.0);
  CHECK_MINMAX(-1.0, 0.0, -1.0, 0.0);
  CHECK_MINMAX(-0.0, -1.0, -1.0, -0.0);
  CHECK_MINMAX(-1.0, -0.0, -1.0, -0.0);
  CHECK_MINMAX(0.0, 1.0, 0.0, 1.0);
  CHECK_MINMAX(1.0, 0.0, 0.0, 1.0);

  CHECK_MINMAX(0.0, 0.0, 0.0, 0.0);
  CHECK_MINMAX(-0.0, -0.0, -0.0, -0.0);
  CHECK_MINMAX(-0.0, 0.0, -0.0, 0.0);
  CHECK_MINMAX(0.0, -0.0, -0.0, 0.0);

  CHECK_MINMAX(0.0, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

template <typename T>
static bool CompareF(T input1, T input2, FPUCondition cond) {
  switch (cond) {
    case EQ:
      return (input1 == input2);
    case LT:
      return (input1 < input2);
    case LE:
      return (input1 <= input2);
    case NE:
      return (input1 != input2);
    case GT:
      return (input1 > input2);
    case GE:
      return (input1 >= input2);
    default:
      UNREACHABLE();
  }
}

static bool CompareU(uint32_t input1, uint32_t input2, Condition cond) {
  switch (cond) {
    case eq:
      return (input1 == input2);
    case ne:
      return (input1 != input2);

    case Uless:
      return (input1 < input2);
    case Uless_equal:
      return (input1 <= input2);
    case Ugreater:
      return (input1 > input2);
    case Ugreater_equal:
      return (input1 >= input2);

    case less:
      return (static_cast<int32_t>(input1) < static_cast<int32_t>(input2));
    case less_equal:
      return (static_cast<int32_t>(input1) <= static_cast<int32_t>(input2));
    case greater:
      return (static_cast<int32_t>(input1) > static_cast<int32_t>(input2));
    case greater_equal:
      return (static_cast<int32_t>(input1) >= static_cast<int32_t>(input2));

    default:
      UNREACHABLE();
  }
}

static void FCompare32Helper(FPUCondition cond) {
  auto fn = [cond](MacroAssembler& masm) { __ CompareF32(a0, cond, fa0, fa1); };
  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) {
      bool comp_res = CompareF(i, j, cond);
      CHECK_EQ(comp_res, GenAndRunTest<int32_t>(i, j, fn));
    }
  }
}

// static void FCompare64Helper(FPUCondition cond) {
//   auto fn = [cond](MacroAssembler& masm) { __ CompareF64(a0, cond, fa0, fa1);
//   }; FOR_FLOAT64_INPUTS(i) {
//     FOR_FLOAT64_INPUTS(j) {
//       bool comp_res = CompareF(i, j, cond);
//       CHECK_EQ(comp_res, GenAndRunTest<int32_t>(i, j, fn));
//     }
//   }
// }

TEST(FCompare32_Branch) {
  CcTest::InitializeVM();

  FCompare32Helper(EQ);
  FCompare32Helper(LT);
  FCompare32Helper(LE);
  FCompare32Helper(NE);
  FCompare32Helper(GT);
  FCompare32Helper(GE);

  // test CompareIsNanF32: return true if any operand isnan
  auto fn = [](MacroAssembler& masm) { __ CompareIsNanF32(a0, fa0, fa1); };
  CHECK_EQ(false, GenAndRunTest<int32_t>(1023.01f, -100.23f, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(1023.01f, snan_f, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(snan_f, -100.23f, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(snan_f, qnan_f, fn));
}

// TEST(FCompare64_Branch) {
//   CcTest::InitializeVM();
//   FCompare64Helper(EQ);
//   FCompare64Helper(LT);
//   FCompare64Helper(LE);
//   FCompare64Helper(NE);
//   FCompare64Helper(GT);
//   FCompare64Helper(GE);

//   // test CompareIsNanF64: return true if any operand isnan
//   auto fn = [](MacroAssembler& masm) { __ CompareIsNanF64(a0, fa0, fa1); };
//   CHECK_EQ(false, GenAndRunTest<int32_t>(1023.01, -100.23, fn));
//   CHECK_EQ(true, GenAndRunTest<int32_t>(1023.01, snan_d, fn));
//   CHECK_EQ(true, GenAndRunTest<int32_t>(snan_d, -100.23, fn));
//   CHECK_EQ(true, GenAndRunTest<int32_t>(snan_d, qnan_d, fn));
// }

static void CompareIHelper(Condition cond) {
  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      auto input1 = i;
      auto input2 = j;
      bool comp_res = CompareU(input1, input2, cond);
      // test compare against immediate value
      auto fn1 = [cond, input2](MacroAssembler& masm) {
        __ CompareI(a0, a0, Operand(input2), cond);
      };
      CHECK_EQ(comp_res, GenAndRunTest<int32_t>(input1, fn1));
      // test compare registers
      auto fn2 = [cond](MacroAssembler& masm) {
        __ CompareI(a0, a0, Operand(a1), cond);
      };
      CHECK_EQ(comp_res, GenAndRunTest<int32_t>(input1, input2, fn2));
    }
  }
}

TEST(CompareI) {
  CcTest::InitializeVM();
  CompareIHelper(eq);
  CompareIHelper(ne);

  CompareIHelper(greater);
  CompareIHelper(greater_equal);
  CompareIHelper(less);
  CompareIHelper(less_equal);

  CompareIHelper(Ugreater);
  CompareIHelper(Ugreater_equal);
  CompareIHelper(Uless);
  CompareIHelper(Uless_equal);
}

TEST(Clz32) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) { __ Clz32(a0, a0); };
  FOR_UINT32_INPUTS(i) {
    // __builtin_clzll(0) is undefined
    if (i == 0) continue;
    CHECK_EQ(__builtin_clz(i), GenAndRunTest<int>(i, fn));
  }
}

TEST(Ctz32) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) { __ Ctz32(a0, a0); };
  FOR_UINT32_INPUTS(i) {
    // __builtin_clzll(0) is undefined
    if (i == 0) continue;
    CHECK_EQ(__builtin_ctz(i), GenAndRunTest<int>(i, fn));
  }
}

template <bool USE_SCRATCH>
static void ByteSwapHelper() {
  Func fn;
  if (USE_SCRATCH) {
    fn = [](MacroAssembler& masm) { __ ByteSwap(a0, a0, 4, t0); };
  } else {
    fn = [](MacroAssembler& masm) { __ ByteSwap(a0, a0, 4); };
  }

  CHECK_EQ((int32_t)0x89ab'cdef, GenAndRunTest<int32_t>(0xefcd'ab89, fn));
}

TEST(ByteSwap) {
  CcTest::InitializeVM();
  ByteSwapHelper<true>();
}

TEST(ByteSwap_no_scratch) {
  CcTest::InitializeVM();
  ByteSwapHelper<false>();
}

TEST(Popcnt) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  uint32_t in[8];
  uint32_t out[8];
  uint32_t result[8];
  uint32_t val = 0xffffffff;
  uint32_t cnt = 32;

  for (int i = 0; i < 6; i++) {
    in[i] = val;
    out[i] = cnt;
    cnt >>= 1;
    val >>= cnt;
  }

  in[6] = 0xaf10000b;
  out[6] = 10;
  in[7] = 0xe03f3000;
  out[7] = 11;

  auto fn = [&in](MacroAssembler& masm) {
    __ mv(a4, a0);
    for (int i = 0; i < 6; i++) {
      // Load constant.
      __ li(a3, Operand(in[i]));
      __ Popcnt32(a5, a3, t0);
      __ Sw(a5, MemOperand(a4));
      __ AddWord(a4, a4, Operand(kSystemPointerSize));
    }

    __ li(a3, Operand(in[6]));
    __ Popcnt32(a5, a3, t0);
    __ Sw(a5, MemOperand(a4));
    __ AddWord(a4, a4, Operand(kSystemPointerSize));

    __ li(a3, Operand(in[7]));
    __ Popcnt32(a5, a3, t0);
    __ Sw(a5, MemOperand(a4));
    __ AddWord(a4, a4, Operand(kSystemPointerSize));
  };
  auto f = AssembleCode<FV>(isolate, fn);

  (void)f.Call(reinterpret_cast<uint32_t>(result), 0, 0, 0, 0);
  // Check results.
  for (int i = 0; i < 8; i++) {
    CHECK(out[i] == result[i]);
  }
}

// TEST(Move) {
//   CcTest::InitializeVM();
//   union {
//     double dval;
//     int32_t ival[2];
//   } t;

//   {
//     auto fn = [](MacroAssembler& masm) { __ ExtractHighWordFromF64(a0, fa0);
//     }; t.ival[0] = 256; t.ival[1] = -123;
//     CHECK_EQ(static_cast<int32_t>(t.ival[1]),
//              GenAndRunTest<int32_t>(t.dval, fn));
//   }

//   {
//     auto fn = [](MacroAssembler& masm) { __ ExtractLowWordFromF64(a0, fa0);
//     }; t.ival[0] = 256; t.ival[1] = -123;
//     CHECK_EQ(static_cast<int32_t>(t.ival[0]),
//              GenAndRunTest<int32_t>(t.dval, fn));

//   }
// }

TEST(DeoptExitSizeIsFixed) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      buffer->CreateView());
  static_assert(static_cast<int>(kFirstDeoptimizeKind) == 0);
  for (int i = 0; i < kDeoptimizeKindCount; i++) {
    DeoptimizeKind kind = static_cast<DeoptimizeKind>(i);
    Label before_exit;
    Builtin target = Deoptimizer::GetDeoptimizationEntry(kind);
    // Mirroring logic in code-generator.cc.
    if (kind == DeoptimizeKind::kLazy) {
      // CFI emits an extra instruction here.
      masm.BindExceptionHandler(&before_exit);
    } else {
      masm.bind(&before_exit);
    }
    masm.CallForDeoptimization(target, 42, &before_exit, kind, &before_exit,
                               &before_exit);
    CHECK_EQ(masm.SizeOfCodeGeneratedSince(&before_exit),
             kind == DeoptimizeKind::kLazy ? Deoptimizer::kLazyDeoptExitSize
                                           : Deoptimizer::kEagerDeoptExitSize);
  }
}

TEST(AddWithImm) {
  CcTest::InitializeVM();
#define Test(Op, Input, Expected)                                       \
  {                                                                     \
    auto fn = [](MacroAssembler& masm) { __ Op(a0, zero_reg, Input); }; \
    CHECK_EQ(static_cast<int64_t>(Expected), GenAndRunTest(fn));        \
  }

  Test(AddWord, 4095, 4095);
  Test(SubWord, 4095, -4095);
#undef Test
}

#undef __

}  // namespace internal
}  // namespace v8

"""


```