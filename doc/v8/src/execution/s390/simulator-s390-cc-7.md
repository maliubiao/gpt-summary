Response:
The user wants a summary of the provided C++ code snippet, which is part of a simulator for the s390 architecture within the V8 JavaScript engine.

Here's a breakdown of the request and how to address it:

1. **Identify the core functionality:** The code defines implementations for various s390 instructions. Each `EVALUATE` macro corresponds to a specific instruction.

2. **Determine if it's Torque:** Check if the filename ends with `.tq`. In this case, it ends with `.cc`, so it's not a Torque file.

3. **Check for JavaScript relevance:** Since this is part of V8, these instructions are used to execute JavaScript code on s390. Instructions related to floating-point numbers (like `ADBR`, `SDBR`, `MDBR`, `DDBR`) are particularly relevant as they directly correspond to JavaScript number operations. Integer operations are also relevant.

4. **Provide JavaScript examples:**  Demonstrate how the s390 instructions (or their simulated counterparts) relate to JavaScript code. Focus on the floating-point operations since those are prominent in the snippet.

5. **Illustrate code logic:** Pick a relatively simple instruction (like `ADBR`) and show how its execution affects the simulated registers and condition codes. Provide sample input and the resulting output.

6. **Highlight common programming errors:** Think about how the simulated instructions could be misused or lead to errors if the underlying architecture was directly exposed to a programmer. For instance, integer division by zero or floating-point NaN handling.

7. **Summarize the overall function:** Synthesize the findings into a concise description of the code's role.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/execution/s390/simulator-s390.cc以.tq结尾: Yes
* 如果它与javascript的功能有关系: Yes
* 请用javascript举例说明: Yes
* 如果有代码逻辑推理: Yes
* 请给出假设输入与输出: Yes
* 如果涉及用户常见的编程错误: Yes
* 请举例说明: Yes
* 这是第8部分，共10部分: Yes
* 请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I'll mentally run through a few of the `EVALUATE` blocks:

* **`ADBR`:**  This is a floating-point addition. It retrieves values from two floating-point registers, adds them, stores the result back, and sets the condition code. A JavaScript example would be `let a = 1.0; let b = 2.0; let c = a + b;`.

* **`CDBR`:** This compares two floating-point numbers and sets the condition code accordingly. JavaScript: `let a = 1.0; let b = 2.0; if (a < b) { ... }`.

* **Unimplemented blocks:** Notice many `EVALUATE` blocks have `UNIMPLEMENTED()`. This is important to mention in the summary.

Now I can generate the response based on these insights.
```cpp
ED();
  USE(instr);
  return 0;
}

EVALUATE(CDBR) {
  DCHECK_OPCODE(CDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  if (isNaN(r1_val) || isNaN(r2_val)) {
    condition_reg_ = CC_OF;
  } else {
    SetS390ConditionCode<double>(r1_val, r2_val);
  }
  return length;
}

EVALUATE(ADBR) {
  DCHECK_OPCODE(ADBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val += r2_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

// ... (rest of the code)
```

这是 `v8/src/execution/s390/simulator-s390.cc` 源代码的第 8 部分，该文件是 V8 JavaScript 引擎中用于模拟 IBM System/390 (s390) 架构处理器的代码。

**功能列举:**

这个代码片段主要定义了 s390 架构中部分浮点运算和一些通用寄存器操作指令的模拟实现。每个 `EVALUATE` 宏定义了一个特定 s390 指令的模拟行为。具体功能包括：

* **浮点比较 (CDBR):**  比较两个双精度浮点寄存器的值，并设置条件码寄存器 (condition_reg_)。
* **浮点加法 (ADBR):** 将两个双精度浮点寄存器的值相加，结果存储回第一个寄存器，并设置条件码。
* **浮点减法 (SDBR):** 将第二个双精度浮点寄存器的值从第一个中减去，结果存储回第一个寄存器，并设置条件码。
* **浮点乘法 (MDBR):** 将两个双精度浮点寄存器的值相乘，结果存储回第一个寄存器。
* **浮点除法 (DDBR):** 将第一个双精度浮点寄存器的值除以第二个，结果存储回第一个寄存器。
* **浮点乘加 (MADBR):** 将两个双精度浮点寄存器的值相乘，然后加到第三个寄存器，结果存储回第一个寄存器，并设置条件码。
* **浮点类型转换 (LEDBRA, CELFBR, CDLFBR, CEFBRA, CDFBRA, CELGBR, CDLGBR, CEGBRA, CDGBRA):** 在浮点寄存器和通用寄存器之间进行数据类型转换，例如将双精度浮点数转换为单精度浮点数，或者将整数转换为浮点数。
* **浮点舍入 (FIDBRA, FIEBRA, CFDBRA, CFEBRA, CGEBRA, CGDBRA, CLFEBR, CLFDBR, CLGDBR, CLGEBR):**  对浮点数进行舍入操作，并将结果存储到寄存器中，同时设置条件码以指示舍入的结果。
* **加载和存储 (LDGR, LGDR):** 在浮点寄存器和通用寄存器之间加载和存储数据。
* **通用寄存器算术和逻辑运算 (LPGR, LNGR, LTGR, LCGR, SGR, ALGR, MSGR, MSGRKC, DSGR, LRVGR, LPGFR, LTGFR, LCGFR, LLGFR, AGFR, SGFR, MSGFR, DSGFR, CGR, CLGR, NGR, OGR, XGR, FLOGR, LLGCR, LLGHR, MGRK, MLGR, DLGR, ALCR, SLBR):**  执行各种通用寄存器上的操作，如加载正数、负数、取反、加法、减法、乘法、除法、逻辑与、逻辑或、逻辑异或、位操作等。
* **条件移动 (LOCGR):**  根据条件码的值，将一个通用寄存器的值移动到另一个寄存器。

**是否为 Torque 源代码:**

`v8/src/execution/s390/simulator-s390.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 V8 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的功能关系及举例:**

这些模拟的 s390 指令最终是为了支持 V8 执行 JavaScript 代码。JavaScript 中的数值运算，特别是浮点数运算，会映射到这些底层的机器指令。

例如：

```javascript
let a = 1.5;
let b = 2.5;
let sum = a + b;
let isGreater = a > b;
let integerValue = Math.floor(a);
```

当 V8 在 s390 架构上执行这段 JavaScript 代码时，加法 `a + b` 可能会对应到模拟器中的 `ADBR` 指令（如果使用双精度浮点数）。比较 `a > b` 可能会对应到 `CDBR` 指令。`Math.floor(a)` 可能会涉及到浮点数到整数的转换，对应到类似 `CFDBRA` 或 `CFEBRA` 这样的指令。

**代码逻辑推理、假设输入与输出:**

以 `ADBR` 指令为例：

**假设输入:**

* 浮点寄存器 `fr1` 的值为 `3.0`。
* 浮点寄存器 `fr2` 的值为 `2.0`。

**代码逻辑:**

1. `DECODE_RRE_INSTRUCTION(r1, r2);`  解码指令，确定操作的是寄存器 `r1` 和 `r2`。假设 `r1` 对应 `fr1`，`r2` 对应 `fr2`。
2. `double r1_val = get_fpr<double>(r1);`  从浮点寄存器 `fr1` 获取双精度浮点数值 `3.0`。
3. `double r2_val = get_fpr<double>(r2);`  从浮点寄存器 `fr2` 获取双精度浮点数值 `2.0`。
4. `r1_val += r2_val;`  执行加法运算，`r1_val` 变为 `5.0`。
5. `set_fpr(r1, r1_val);`  将结果 `5.0` 存储回浮点寄存器 `fr1`。
6. `SetS390ConditionCode<double>(r1_val, 0);`  根据结果 `5.0` 设置条件码。由于结果非零，条件码可能设置为“大于零”。

**输出:**

* 浮点寄存器 `fr1` 的值变为 `5.0`。
* 条件码寄存器 (condition_reg_) 的值被设置为指示结果大于零。

**涉及用户常见的编程错误及举例:**

虽然用户通常不会直接编写 s390 汇编代码，但在 JavaScript 中进行数值运算时，一些常见的错误会反映到这些底层指令的执行上：

1. **浮点数精度问题:** 由于浮点数的二进制表示的限制，进行多次运算可能会出现精度丢失。例如：

   ```javascript
   let sum = 0.1 + 0.2; // sum 的值可能不是精确的 0.3
   ```

   在模拟器层面，这可能体现在多次 `ADBR` 指令执行后，寄存器中的值与预期略有偏差。

2. **除零错误:**  在 JavaScript 中除以零会得到 `Infinity` 或 `NaN`。

   ```javascript
   let result = 1 / 0; // result 为 Infinity
   let result2 = 0 / 0; // result2 为 NaN
   ```

   在模拟器中，`DDBR` 指令在除数为零时，其行为可能会导致特定的状态（例如设置溢出标志或产生特定的浮点数结果）。在 `CDBR` 中，如果比较的数是 `NaN`，条件码会被设置为 `CC_OF`。

3. **整数溢出:**  虽然 JavaScript 的 `Number` 类型可以表示很大的整数，但在某些位运算或者类型转换的场景下，如果超出特定整数类型的范围，可能会发生溢出。 例如在涉及到有符号整数和无符号整数转换时，或者进行位运算时。 这会影响到通用寄存器操作指令的行为。

**功能归纳 (第 8 部分):**

这个代码片段是 `v8/src/execution/s390/simulator-s390.cc` 文件的一部分，专门负责模拟 s390 架构中的**浮点数运算指令**和一部分**通用寄存器操作指令**。它涵盖了浮点数的比较、加减乘除、乘加运算、类型转换、舍入以及通用寄存器的加载、存储、算术和逻辑运算。 这些模拟的指令是 V8 引擎在 s390 架构上执行 JavaScript 代码中数值计算的关键组成部分。  这一部分代码关注于提供这些指令的准确软件模拟，以便在非 s390 平台上也能测试和运行针对该架构的代码。 此外，它还包含了部分通用寄存器操作的模拟，这些操作与整数运算和数据处理密切相关。

Prompt: 
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共10部分，请归纳一下它的功能

"""
ED();
  USE(instr);
  return 0;
}

EVALUATE(CDBR) {
  DCHECK_OPCODE(CDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  if (isNaN(r1_val) || isNaN(r2_val)) {
    condition_reg_ = CC_OF;
  } else {
    SetS390ConditionCode<double>(r1_val, r2_val);
  }
  return length;
}

EVALUATE(ADBR) {
  DCHECK_OPCODE(ADBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val += r2_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(SDBR) {
  DCHECK_OPCODE(SDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val -= r2_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(MDBR) {
  DCHECK_OPCODE(MDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val *= r2_val;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(DDBR) {
  DCHECK_OPCODE(DDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val /= r2_val;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(MADBR) {
  DCHECK_OPCODE(MADBR);
  DECODE_RRD_INSTRUCTION(r1, r2, r3);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  double r3_val = get_fpr<double>(r3);
  r1_val += r2_val * r3_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(MSDBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LNXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LCXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LEDBRA) {
  DCHECK_OPCODE(LEDBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r2_val = get_fpr<double>(r2);
  set_fpr(r1, static_cast<float>(r2_val));
  return length;
}

EVALUATE(LDXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LEXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TBEDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TBDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DIEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(THDER) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(THDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DIDBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPDFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LNDFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LCDFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LZER) {
  DCHECK_OPCODE(LZER);
  DECODE_RRE_INSTRUCTION_NO_R2(r1);
  set_fpr<float>(r1, 0.0);
  return length;
}

EVALUATE(LZDR) {
  DCHECK_OPCODE(LZDR);
  DECODE_RRE_INSTRUCTION_NO_R2(r1);
  set_fpr<double>(r1, 0.0);
  return length;
}

EVALUATE(LZXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SFPC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SFASR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EFPC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CELFBR) {
  DCHECK_OPCODE(CELFBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  float r1_val = static_cast<float>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CDLFBR) {
  DCHECK_OPCODE(CDLFBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXLFBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEFBRA) {
  DCHECK_OPCODE(CEFBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t fr2_val = get_low_register<int32_t>(r2);
  float fr1_val = static_cast<float>(fr2_val);
  set_fpr(r1, fr1_val);
  return length;
}

EVALUATE(CDFBRA) {
  DCHECK_OPCODE(CDFBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXFBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIDBRA) {
  DCHECK_OPCODE(FIDBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  set_fpr(r1, n);
  return length;
}

EVALUATE(FIEBRA) {
  DCHECK_OPCODE(FIEBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  set_fpr(r1, n);
  return length;
}

template <class T, class R>
static int ComputeSignedRoundingConditionCode(T a, T n) {
  constexpr T NINF = -std::numeric_limits<T>::infinity();
  constexpr T PINF = std::numeric_limits<T>::infinity();
  constexpr long double MN =
      static_cast<long double>(std::numeric_limits<R>::min());
  constexpr long double MP =
      static_cast<long double>(std::numeric_limits<R>::max());

  if (NINF <= a && a < MN && n < MN) {
    return 0x1;
  } else if (NINF < a && a < MN && n == MN) {
    return 0x4;
  } else if (MN <= a && a < 0.0) {
    return 0x4;
  } else if (a == 0.0) {
    return 0x8;
  } else if (0.0 < a && a <= MP) {
    return 0x2;
  } else if (MP < a && a <= PINF && n == MP) {
    return 0x2;
  } else if (MP < a && a <= PINF && n > MP) {
    return 0x1;
  } else if (std::isnan(a)) {
    return 0x1;
  }
  UNIMPLEMENTED();
  return 0;
}

EVALUATE(CFDBRA) {
  DCHECK_OPCODE(CFDBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  int32_t r1_val = ComputeSignedRoundingResult<double, int32_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<double, int32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CFEBRA) {
  DCHECK_OPCODE(CFEBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  int32_t r1_val = ComputeSignedRoundingResult<float, int32_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<float, int32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CGEBRA) {
  DCHECK_OPCODE(CGEBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  int64_t r1_val = ComputeSignedRoundingResult<float, int64_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<float, int64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CGDBRA) {
  DCHECK_OPCODE(CGDBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  int64_t r1_val = ComputeSignedRoundingResult<double, int64_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<double, int64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CGXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

template <class T, class R>
static int ComputeLogicalRoundingConditionCode(T a, T n) {
  constexpr T NINF = -std::numeric_limits<T>::infinity();
  constexpr T PINF = std::numeric_limits<T>::infinity();
  constexpr long double MP =
      static_cast<long double>(std::numeric_limits<R>::max());

  if (NINF <= a && a < 0.0) {
    return (n < 0.0) ? 0x1 : 0x4;
  } else if (a == 0.0) {
    return 0x8;
  } else if (0.0 < a && a <= MP) {
    return 0x2;
  } else if (MP < a && a <= PINF) {
    return n == MP ? 0x2 : 0x1;
  } else if (std::isnan(a)) {
    return 0x1;
  }
  UNIMPLEMENTED();
  return 0;
}

EVALUATE(CLFEBR) {
  DCHECK_OPCODE(CLFEBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  uint32_t r1_val = ComputeLogicalRoundingResult<float, uint32_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<float, uint32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CLFDBR) {
  DCHECK_OPCODE(CLFDBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  uint32_t r1_val = ComputeLogicalRoundingResult<double, uint32_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<double, uint32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CLGDBR) {
  DCHECK_OPCODE(CLGDBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  uint64_t r1_val = ComputeLogicalRoundingResult<double, uint64_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<double, uint64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CLGEBR) {
  DCHECK_OPCODE(CLGEBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  uint64_t r1_val = ComputeLogicalRoundingResult<float, uint64_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<float, uint64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CLFXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CELGBR) {
  DCHECK_OPCODE(CELGBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_register(r2);
  float r1_val = static_cast<float>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CDLGBR) {
  DCHECK_OPCODE(CDLGBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_register(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXLGBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEGBRA) {
  DCHECK_OPCODE(CEGBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t fr2_val = get_register(r2);
  float fr1_val = static_cast<float>(fr2_val);
  set_fpr(r1, fr1_val);
  return length;
}

EVALUATE(CDGBRA) {
  DCHECK_OPCODE(CDGBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXGBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFER) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LDGR) {
  DCHECK_OPCODE(LDGR);
  // Load FPR from GPR (L <- 64)
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t int_val = get_register(r2);
  set_fpr(r1, int_val);
  return length;
}

EVALUATE(CGER) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LGDR) {
  DCHECK_OPCODE(LGDR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Load GPR from FPR (64 <- L)
  int64_t double_val = get_fpr<int64_t>(r2);
  set_register(r1, double_val);
  return length;
}

EVALUATE(MDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ADTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LDETR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LXDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LDXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CUDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ESDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CUXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CSXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EEXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ESXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDGTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDUTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDSTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(QADTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RRDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXGTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXUTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXSTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(QAXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IEXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RRXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPGR) {
  DCHECK_OPCODE(LPGR);
  // Load Positive (32)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  SetS390ConditionCode<int64_t>(r2_val, 0);
  if (r2_val == (static_cast<int64_t>(1) << 63)) {
    SetS390OverflowCode(true);
  } else {
    // If negative and not overflowing, then negate it.
    r2_val = (r2_val < 0) ? -r2_val : r2_val;
  }
  set_register(r1, r2_val);
  return length;
}

EVALUATE(LNGR) {
  DCHECK_OPCODE(LNGR);
  // Load Negative (64)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  r2_val = (r2_val >= 0) ? -r2_val : r2_val;  // If pos, then negate it.
  set_register(r1, r2_val);
  condition_reg_ = (r2_val == 0) ? CC_EQ : CC_LT;  // CC0 - result is zero
  // CC1 - result is negative
  return length;
}

EVALUATE(LTGR) {
  DCHECK_OPCODE(LTGR);
  // Load Register (64)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  SetS390ConditionCode<int64_t>(r2_val, 0);
  set_register(r1, get_register(r2));
  return length;
}

EVALUATE(LCGR) {
  DCHECK_OPCODE(LCGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  int64_t result = 0;
  bool isOF = false;
  isOF = __builtin_ssubl_overflow(0L, r2_val, &result);
  set_register(r1, result);
  SetS390ConditionCode<int64_t>(result, 0);
  if (isOF) {
    SetS390OverflowCode(true);
  }
  return length;
}

EVALUATE(SGR) {
  DCHECK_OPCODE(SGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  bool isOF = false;
  isOF = CheckOverflowForIntSub(r1_val, r2_val, int64_t);
  r1_val -= r2_val;
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(ALGR) {
  DCHECK_OPCODE(ALGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // 64-bit Non-clobbering unsigned arithmetics
  uint64_t r1_val = get_register(r1);
  uint64_t r2_val = get_register(r2);
  bool isOF = CheckOverflowForUIntAdd(r1_val, r2_val);
  SetS390ConditionCode<uint64_t>(r1_val + r2_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val + r2_val);
  return length;
}

EVALUATE(SLGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSGR) {
  DCHECK_OPCODE(MSGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  set_register(r1, r1_val * r2_val);
  return length;
}

EVALUATE(MSGRKC) {
  DCHECK_OPCODE(MSGRKC);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  volatile int64_t result64 = r2_val * r3_val;
  bool isOF = ((r2_val == -1 && result64 == (static_cast<int64_t>(1L) << 63)) ||
               (r2_val != 0 && result64 / r2_val != r3_val));
  SetS390ConditionCode<int64_t>(result64, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, result64);
  return length;
}

EVALUATE(DSGR) {
  DCHECK_OPCODE(DSGR);
  DECODE_RRE_INSTRUCTION(r1, r2);

  DCHECK_EQ(r1 % 2, 0);

  int64_t dividend = get_register(r1 + 1);
  int64_t divisor = get_register(r2);
  set_register(r1, dividend % divisor);
  set_register(r1 + 1, dividend / divisor);
  return length;
}

EVALUATE(LRVGR) {
  DCHECK_OPCODE(LRVGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  int64_t r1_val = ByteReverse<int64_t>(r2_val);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(LPGFR) {
  DCHECK_OPCODE(LPGFR);
  // Load Positive (32)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  // If negative, then negate it.
  int64_t r1_val = static_cast<int64_t>((r2_val < 0) ? -r2_val : r2_val);
  set_register(r1, r1_val);
  SetS390ConditionCode<int64_t>(r1_val, 0);
  return length;
}

EVALUATE(LNGFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTGFR) {
  DCHECK_OPCODE(LTGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Load and Test Register (64 <- 32)  (Sign Extends 32-bit val)
  // Load Register (64 <- 32)  (Sign Extends 32-bit val)
  int32_t r2_val = get_low_register<int32_t>(r2);
  int64_t result = static_cast<int64_t>(r2_val);
  set_register(r1, result);
  SetS390ConditionCode<int64_t>(result, 0);
  return length;
}

EVALUATE(LCGFR) {
  DCHECK_OPCODE(LCGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Load and Test Register (64 <- 32)  (Sign Extends 32-bit val)
  // Load Register (64 <- 32)  (Sign Extends 32-bit val)
  int32_t r2_val = get_low_register<int32_t>(r2);
  int64_t result = static_cast<int64_t>(r2_val);
  set_register(r1, result);
  return length;
}

EVALUATE(LLGFR) {
  DCHECK_OPCODE(LLGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  uint64_t r2_finalval = (static_cast<uint64_t>(r2_val) & 0x00000000FFFFFFFF);
  set_register(r1, r2_finalval);
  return length;
}

EVALUATE(LLGTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AGFR) {
  DCHECK_OPCODE(AGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Add Register (64 <- 32)  (Sign Extends 32-bit val)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  bool isOF = CheckOverflowForIntAdd(r1_val, r2_val, int64_t);
  r1_val += r2_val;
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(SGFR) {
  DCHECK_OPCODE(SGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Sub Reg (64 <- 32)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  bool isOF = false;
  isOF = CheckOverflowForIntSub(r1_val, r2_val, int64_t);
  r1_val -= r2_val;
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(ALGFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLGFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSGFR) {
  DCHECK_OPCODE(MSGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  int64_t product = r1_val * r2_val;
  set_register(r1, product);
  return length;
}

EVALUATE(DSGFR) {
  DCHECK_OPCODE(DSGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  DCHECK_EQ(r1 % 2, 0);
  int64_t r1_val = get_register(r1 + 1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  int64_t quotient = r1_val / r2_val;
  int64_t remainder = r1_val % r2_val;
  set_register(r1, remainder);
  set_register(r1 + 1, quotient);
  return length;
}

EVALUATE(KMAC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LRVR) {
  DCHECK_OPCODE(LRVR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r1_val = ByteReverse<int32_t>(r2_val);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CGR) {
  DCHECK_OPCODE(CGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Compare (64)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  SetS390ConditionCode<int64_t>(r1_val, r2_val);
  return length;
}

EVALUATE(CLGR) {
  DCHECK_OPCODE(CLGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Compare Logical (64)
  uint64_t r1_val = static_cast<uint64_t>(get_register(r1));
  uint64_t r2_val = static_cast<uint64_t>(get_register(r2));
  SetS390ConditionCode<uint64_t>(r1_val, r2_val);
  return length;
}

EVALUATE(KMF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KMO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PCC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KMCTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KMC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGFR) {
  DCHECK_OPCODE(CGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Compare (64)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  SetS390ConditionCode<int64_t>(r1_val, r2_val);
  return length;
}

EVALUATE(KIMD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KLMD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLGDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLFDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BCTGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLFXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDLGTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDLFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXLGTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXLFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGRT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NGR) {
  DCHECK_OPCODE(NGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  r1_val &= r2_val;
  SetS390BitWiseConditionCode<uint64_t>(r1_val);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(OGR) {
  DCHECK_OPCODE(OGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  r1_val |= r2_val;
  SetS390BitWiseConditionCode<uint64_t>(r1_val);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(XGR) {
  DCHECK_OPCODE(XGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  r1_val ^= r2_val;
  SetS390BitWiseConditionCode<uint64_t>(r1_val);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(FLOGR) {
  DCHECK_OPCODE(FLOGR);
  DECODE_RRE_INSTRUCTION(r1, r2);

  DCHECK_EQ(r1 % 2, 0);

  int64_t r2_val = get_register(r2);

  int i = 0;
  for (; i < 64; i++) {
    if (r2_val < 0) break;
    r2_val <<= 1;
  }

  r2_val = get_register(r2);

  int64_t mask = ~(1 << (63 - i));
  set_register(r1, i);
  set_register(r1 + 1, r2_val & mask);
  return length;
}

EVALUATE(LLGCR) {
  DCHECK_OPCODE(LLGCR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_low_register<uint64_t>(r2);
  r2_val <<= 56;
  r2_val >>= 56;
  set_register(r1, r2_val);
  return length;
}

EVALUATE(LLGHR) {
  DCHECK_OPCODE(LLGHR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_low_register<uint64_t>(r2);
  r2_val <<= 48;
  r2_val >>= 48;
  set_register(r1, r2_val);
  return length;
}

EVALUATE(MG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MGRK) {
  DCHECK_OPCODE(MGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  set_register(r1, base::bits::SignedMulHigh64(r2_val, r3_val));
  set_register(r1 + 1, r2_val * r3_val);
  return length;
}

EVALUATE(MLGR) {
  DCHECK_OPCODE(MLGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // 64-bit Non-clobbering unsigned arithmetics
  CHECK_EQ(r1 % 2, 0);
  uint64_t r1_plus_1_val = get_register(r1 + 1);
  uint64_t r2_val = get_register(r2);

  set_register(r1, base::bits::UnsignedMulHigh64(r2_val, r1_plus_1_val));
  set_register(r1 + 1, r2_val * r1_plus_1_val);
  return length;
}

EVALUATE(MLG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DLGR) {
  DCHECK_OPCODE(DLGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r1_val = get_register(r1);
  uint64_t r2_val = get_register(r2);
  DCHECK_EQ(r1 % 2, 0);
  unsigned __int128 dividend = static_cast<unsigned __int128>(r1_val) << 64;
  dividend += get_register(r1 + 1);
  uint64_t remainder = dividend % r2_val;
  uint64_t quotient = dividend / r2_val;
  set_register(r1, remainder);
  set_register(r1 + 1, quotient);
  return length;
}

EVALUATE(ALCGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLBGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EPSW) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TROT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TROO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLCR) {
  DCHECK_OPCODE(LLCR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  r2_val <<= 24;
  r2_val >>= 24;
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(LLHR) {
  DCHECK_OPCODE(LLHR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  r2_val <<= 16;
  r2_val >>= 16;
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(MLR) {
  DCHECK_OPCODE(MLR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  DCHECK_EQ(r1 % 2, 0);

  uint32_t r1_val = get_low_register<uint32_t>(r1 + 1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint64_t product =
      static_cast<uint64_t>(r1_val) * static_cast<uint64_t>(r2_val);
  int32_t high_bits = product >> 32;
  int32_t low_bits = product & 0x00000000FFFFFFFF;
  set_low_register(r1, high_bits);
  set_low_register(r1 + 1, low_bits);
  return length;
}

EVALUATE(DLR) {
  DCHECK_OPCODE(DLR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  DCHECK_EQ(r1 % 2, 0);
  uint64_t dividend = static_cast<uint64_t>(r1_val) << 32;
  dividend += get_low_register<uint32_t>(r1 + 1);
  uint32_t remainder = dividend % r2_val;
  uint32_t quotient = dividend / r2_val;
  r1_val = remainder;
  set_low_register(r1, remainder);
  set_low_register(r1 + 1, quotient);
  return length;
}

EVALUATE(ALCR) {
  DCHECK_OPCODE(ALCR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t alu_out = 0;
  bool isOF = false;

  alu_out = r1_val + r2_val;
  bool isOF_original = CheckOverflowForUIntAdd(r1_val, r2_val);
  if (TestConditionCode((Condition)2) || TestConditionCode((Condition)3)) {
    alu_out = alu_out + 1;
    isOF = isOF_original || CheckOverflowForUIntAdd(alu_out, 1);
  } else {
    isOF = isOF_original;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCodeCarry<uint32_t>(alu_out, isOF);
  return length;
}

EVALUATE(SLBR) {
  DCHECK_OPCODE(SLBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t alu_out = 0;
  bool isOF = false;

  alu_out = r1_val - r2_val;
  bool isOF_original = CheckOverflowForUIntSub(r1_val, r2_val);
  if (TestConditionCode((Condition)2) || TestConditionCode((Condition)3)) {
    alu_out = alu_out - 1;
    isOF = isOF_original || CheckOverflowForUIntSub(alu_out, 1);
  } else {
    isOF = isOF_original;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCodeCarry<uint32_t>(alu_out, isOF);
  return length;
}

EVALUATE(CU14) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CU24) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CU41) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CU42) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTRE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRSTU) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ALHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ALHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(POPCNT_Z) {
  DCHECK_OPCODE(POPCNT_Z);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  int64_t r1_val = 0;

  uint8_t* r2_val_ptr = reinterpret_cast<uint8_t*>(&r2_val);
  uint8_t* r1_val_ptr = reinterpret_cast<uint8_t*>(&r1_val);
  for (int i = 0; i < 8; i++) {
    uint32_t x = static_cast<uint32_t>(r2_val_ptr[i]);
#if defined(__GNUC__)
    r1_val_ptr[i] = __builtin_popcount(x);
#else
#error unsupport __builtin_popcount
#endif
  }
  set_register(r1, static_cast<uint64_t>(r1_val));
  return length;
}

EVALUATE(LOCGR) {
  DCHECK_OPCODE(LOCGR);
  DECODE_RRF_C_INSTRUCTION(r1, r2, m3);
  if (TestConditionCode(m3)) {
    set_register(r1, get_register(r2));
  }
  return length;
}

EVALUATE(NGRK) {
  DCHECK_OPCODE(NGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  uint64_t bitwise_result = 0;
  bitwise_result = r2_val & r3_val;
  SetS390BitWiseConditionCode<uint64_t>(bitwise_result);
  set_register(r1, bitwise_result);
  return length;
}

EVALUATE(OGRK) {
  DCHECK_OPCODE(OGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  uint64_t bitwise_result = 0;
  bitwise_result = r2_val | r3_val;
  SetS390BitWiseConditionCode<uint64_t>(bitwise_result);
  set_register(r1, bitwise_result);
  return length;
}

EVALUATE(XGRK) {
  DCHECK_OPCODE(XGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  uint64_t bitwise_result = 0;
  bitwise_result = r2_val ^ r3_val;
  SetS390BitWiseConditionCode<uint64_t>(bitwise_result);
  set_register(r1, bitwise_result);
  return length;
}

EVALUATE(AGRK) {
  DCHECK_OPCODE(AGRK);
  DE
"""


```