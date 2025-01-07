Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/execution/mips64/simulator-mips64.cc`. They have also provided some specific instructions on how to analyze the code.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code is within a class named `Simulator` and contains various methods prefixed with `DecodeTypeRegister`. This strongly suggests that the code is responsible for simulating the execution of MIPS64 instructions, particularly those involving floating-point operations.

2. **Analyze the `DecodeTypeRegister` Methods:**  Each `DecodeTypeRegister` method seems to handle different categories of floating-point instructions based on their format and the data types they operate on (single-precision float, double-precision float, word, long-word). The suffixes `SRsType`, `DRsType`, `WRsType`, `LRsType` likely indicate the types of registers involved.

3. **Examine the Helper Functions:**  There are several template helper functions like `FPUMin`, `FPUMax`, `FPUCanonalizeOperation`, etc. These functions are used within the `DecodeTypeRegister` methods to implement the specific logic of floating-point operations, including handling NaN values, rounding modes, and comparisons.

4. **Check for Torque:** The filename ends in `.cc`, not `.tq`, so it's not a Torque file.

5. **Relate to Javascript:**  Floating-point operations are fundamental in Javascript. The code simulates how these operations would be performed at a low level on a MIPS64 architecture.

6. **Provide Javascript Examples:**  Think of common Javascript operations that would involve the functionalities seen in the C++ code, such as `Math.min()`, `Math.max()`, basic arithmetic, type conversions, and comparisons.

7. **Code Logic and Examples:** Choose a specific `case` within one of the `DecodeTypeRegister` functions and walk through its logic. Select a simple case like `ADD_S` or `ABS_S`. Provide hypothetical input register values and predict the output register value based on the C++ code.

8. **Common Programming Errors:**  Consider typical mistakes developers make when working with floating-point numbers in Javascript (and by extension, the underlying simulated operations), such as comparing floating-point numbers for exact equality, not handling NaN, and assuming specific rounding behavior.

9. **Summarize the Functionality:** Combine the observations from the previous steps to provide a concise summary of the code's purpose within the V8 simulator.

10. **Address the "Part X of 9" Information:** Acknowledge the provided context that this is part of a larger file and that the current analysis focuses on the given snippet.

**Self-Correction/Refinement:**

* Initially, I might have focused too heavily on individual instruction details. The request asks for a functional overview, so I needed to step back and see the bigger picture – it's about simulating floating-point instructions.
* I made sure to connect the C++ code to concrete Javascript examples to make it more understandable for someone familiar with Javascript.
* The "common programming errors" section needed to be relevant to the *simulated* operations, which directly map to how floating-point issues manifest in Javascript.

By following these steps and refining the analysis, I arrived at the provided answer.
这是一个V8源代码文件，路径为 `v8/src/execution/mips64/simulator-mips64.cc`。根据你的描述，我们可以分析一下它的功能：

**主要功能：MIPS64 指令集模拟器 (浮点运算部分)**

这段代码是 V8 JavaScript 引擎中 MIPS64 架构的模拟器实现的一部分，专门负责模拟 MIPS64 架构下的浮点运算指令。

**具体功能分解：**

1. **浮点数辅助函数 (`FPUMin`, `FPUMax`, `FPUCanonalizeOperation` 等):**
   - 提供了用于处理浮点数运算的底层逻辑，例如：
     - `FPUMin`, `FPUMax`: 计算两个浮点数的最小值和最大值，并考虑 NaN 和零的特殊情况。
     - `FPUMinA`, `FPUMaxA`:  计算基于绝对值的最小值和最大值。
     - `FPUProcessNaNsAndZeros`:  处理 NaN 和零值在最小值/最大值运算中的情况。
     - `FPUCanonalizeNaNArg`, `FPUCanonalizeNaNArgs`, `FPUCanonalizeOperation`:  处理 NaN (Not a Number) 值，确保运算结果的规范化。

2. **`DecodeTypeRegisterSRsType()` 函数:**
   - 负责解码并模拟 MIPS64 架构中属于 "Type Register SRs" 类型的浮点指令，这些指令通常操作单精度浮点数。
   - 涵盖了各种单精度浮点运算指令，例如：
     - `ADD_S`, `SUB_S`, `MUL_S`, `DIV_S`: 加、减、乘、除
     - `MADDF_S`, `MSUBF_S`: 乘加、乘减 (MIPS64r6 特有)
     - `ABS_S`, `NEG_S`, `SQRT_S`, `RSQRT_S`, `RECIP_S`: 绝对值、取负、平方根、倒数平方根、倒数
     - `C_F_D`, `C_UN_D`, `C_EQ_D` 等: 浮点比较指令，设置 FCSR (浮点控制状态寄存器) 的条件标志位。
     - `CVT_D_S`, `CVT_L_S`, `CVT_W_S`: 类型转换指令 (单精度转双精度、单精度转长整型、单精度转整型)。
     - `TRUNC_W_S`, `TRUNC_L_S`, `ROUND_W_S`, `ROUND_L_S`, `FLOOR_W_S`, `FLOOR_L_S`, `CEIL_W_S`, `CEIL_L_S`: 舍入到整数的指令。
     - `MINA`, `MAXA`, `MIN`, `MAX`, `SEL`, `SELEQZ_C`, `SELNEZ_C`, `MOVZ_C`, `MOVN_C`, `MOVF`:  其他浮点操作和条件移动指令 (部分为 MIPS64r6 特有)。
     - `CLASS_S`: (MIPS64r6)  判断浮点数的类型 (正零、负零、正无穷、负无穷、NaN 等)。

3. **`DecodeTypeRegisterDRsType()` 函数:**
   - 负责解码并模拟 "Type Register DRs" 类型的浮点指令，这些指令操作双精度浮点数。
   - 包含了与单精度指令类似的双精度版本，例如 `ADD_D`, `SUB_D`, `MUL_D`, `DIV_D`, 以及类型转换指令如 `CVT_W_D`, `CVT_S_D` 等。

4. **`DecodeTypeRegisterWRsType()` 函数:**
   - 负责解码并模拟 "Type Register WRs" 类型的浮点指令，这些指令通常涉及浮点数和整数之间的操作。
   - 包含从整数转换为浮点数的指令 (`CVT_S_W`, `CVT_D_W`) 以及浮点数比较指令 (`CMP_AF`, `CMP_UN`, `CMP_EQ` 等)，结果通常写入通用寄存器。

5. **`DecodeTypeRegisterLRsType()` 函数:**
   - 负责解码并模拟 "Type Register LRs" 类型的浮点指令，这些指令操作双精度浮点数并可能涉及长整型。
   - 包括从长整型转换为浮点数的指令 (`CVT_D_L`, `CVT_S_L`) 和双精度浮点数的比较指令 (`CMP_AF`, `CMP_UN`, `CMP_EQ` 等)，结果写入通用寄存器。

6. **`DecodeTypeRegisterCOP1()` 函数:**
   - 负责解码并模拟属于 COP1 (协处理器 1，通常指浮点单元) 的其他指令。
   - 涵盖了分支指令 (`BC1`, `BC1EQZ`, `BC1NEZ`)，以及在通用寄存器和浮点寄存器之间移动数据的指令 (`CFC1`, `MFC1`, `DMFC1`, `MFHC1`, `CTC1`)。

**关于 .tq 结尾：**

如果 `v8/src/execution/mips64/simulator-mips64.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用于定义内置函数和运行时函数的领域特定语言。然而，根据你提供的文件名，它以 `.cc` 结尾，所以是一个标准的 C++ 源代码文件。

**与 JavaScript 功能的关系（及 JavaScript 示例）：**

这段 C++ 代码直接模拟了 JavaScript 中涉及浮点数运算的底层实现。JavaScript 中的所有数字都以双精度浮点数（IEEE 754 标准）表示。当 JavaScript 代码执行浮点运算时，V8 引擎在底层会执行相应的机器指令。在 MIPS64 架构上，这段模拟器代码就模拟了这些 MIPS64 浮点指令的行为。

**JavaScript 示例：**

```javascript
let a = 1.5;
let b = 2.7;
let sum = a + b; //  对应 C++ 中的 ADD_D (如果 a 和 b 在浮点寄存器中)

let minVal = Math.min(a, b); // 对应 C++ 中的 FPUMin 或 MAX 指令

let sqrtA = Math.sqrt(a); // 对应 C++ 中的 SQRT_D 指令

let roundedA = Math.floor(a); // 对应 C++ 中的 FLOOR_W_D (如果结果要转为整数)

if (a < b) { // 对应 C++ 中的 C_OLT_D 等比较指令
  console.log("a is less than b");
}
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- 浮点寄存器 `fs_reg()` 存储单精度浮点数 `3.0`。
- 浮点寄存器 `ft_reg()` 存储单精度浮点数 `2.0`。
- 指令是 `ADD_S fd, fs, ft` (单精度浮点加法，结果存入 `fd`)。

**C++ 代码逻辑 (`DecodeTypeRegisterSRsType()` 中的 `case ADD_S`):**

```c++
    case ADD_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs + rhs; },
                                 fs, ft));
      break;
```

**输出:**

- 浮点寄存器 `fd_reg()` 将存储单精度浮点数 `5.0` (3.0 + 2.0)。

**涉及用户常见的编程错误 (JavaScript 示例):**

1. **浮点数比较的精度问题:**

   ```javascript
   let x = 0.1 + 0.2;
   if (x === 0.3) { // 这是一个常见的错误！浮点数运算可能存在精度损失
     console.log("相等");
   } else {
     console.log("不相等"); // 实际会输出这个
   }
   ```
   **对应 C++ 代码中的潜在问题:** 在模拟浮点比较指令时，需要精确地实现 IEEE 754 的比较规则，否则模拟结果可能与实际硬件行为不符。

2. **未处理 NaN (Not a Number):**

   ```javascript
   let y = Math.sqrt(-1); // y 的值为 NaN
   if (y > 0) { // 永远不会执行
     console.log("y 大于 0");
   }
   ```
   **对应 C++ 代码中的处理:** `FPUCanonalizeOperation` 和 `FPUProcessNaNsAndZeros` 等函数用于确保 NaN 值在运算中得到正确的处理，模拟硬件的行为。

3. **假设特定的舍入行为:**

   ```javascript
   let z = 1.005;
   let roundedZ = Math.round(z * 100) / 100; // 希望得到 1.01，但可能由于舍入模式不同而得到其他结果
   ```
   **对应 C++ 代码中的处理:**  `DecodeTypeRegisterSRsType` 和 `DecodeTypeRegisterDRsType` 中处理舍入指令时，会根据 FCSR 寄存器中设置的舍入模式 (`kRoundToNearest`, `kRoundToZero` 等) 来模拟不同的舍入行为。

**这是第4部分，共9部分，请归纳一下它的功能:**

作为整个模拟器的第 4 部分，这段代码主要负责 **MIPS64 架构浮点运算指令的模拟**。它实现了各种单精度和双精度浮点运算、类型转换、比较以及舍入操作的逻辑。这部分是 V8 引擎能够在 MIPS64 平台上执行 JavaScript 代码的关键组成部分，因为它模拟了 JavaScript 中浮点数运算在目标架构上的行为。

Prompt: 
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/mips64/simulator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能

"""
   *result = a;
  } else if (b == a) {
    // Handle -0.0 == 0.0 case.
    // std::signbit() returns int 0 or 1 so subtracting MaxMinKind::kMax
    // negates the result.
    *result = std::signbit(b) - static_cast<int>(kind) ? b : a;
  } else {
    return false;
  }
  return true;
}

template <typename T>
static T FPUMin(T a, T b) {
  T result;
  if (FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMin, &result)) {
    return result;
  } else {
    return b < a ? b : a;
  }
}

template <typename T>
static T FPUMax(T a, T b) {
  T result;
  if (FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMax, &result)) {
    return result;
  } else {
    return b > a ? b : a;
  }
}

template <typename T>
static T FPUMinA(T a, T b) {
  T result;
  if (!FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMin, &result)) {
    if (FPAbs(a) < FPAbs(b)) {
      result = a;
    } else if (FPAbs(b) < FPAbs(a)) {
      result = b;
    } else {
      result = a < b ? a : b;
    }
  }
  return result;
}

template <typename T>
static T FPUMaxA(T a, T b) {
  T result;
  if (!FPUProcessNaNsAndZeros(a, b, MaxMinKind::kMin, &result)) {
    if (FPAbs(a) > FPAbs(b)) {
      result = a;
    } else if (FPAbs(b) > FPAbs(a)) {
      result = b;
    } else {
      result = a > b ? a : b;
    }
  }
  return result;
}

enum class KeepSign : bool { no = false, yes };

template <typename T, typename std::enable_if<std::is_floating_point<T>::value,
                                              int>::type = 0>
T FPUCanonalizeNaNArg(T result, T arg, KeepSign keepSign = KeepSign::no) {
  DCHECK(std::isnan(arg));
  T qNaN = std::numeric_limits<T>::quiet_NaN();
  if (keepSign == KeepSign::yes) {
    return std::copysign(qNaN, result);
  }
  return qNaN;
}

template <typename T>
T FPUCanonalizeNaNArgs(T result, KeepSign keepSign, T first) {
  if (std::isnan(first)) {
    return FPUCanonalizeNaNArg(result, first, keepSign);
  }
  return result;
}

template <typename T, typename... Args>
T FPUCanonalizeNaNArgs(T result, KeepSign keepSign, T first, Args... args) {
  if (std::isnan(first)) {
    return FPUCanonalizeNaNArg(result, first, keepSign);
  }
  return FPUCanonalizeNaNArgs(result, keepSign, args...);
}

template <typename Func, typename T, typename... Args>
T FPUCanonalizeOperation(Func f, T first, Args... args) {
  return FPUCanonalizeOperation(f, KeepSign::no, first, args...);
}

template <typename Func, typename T, typename... Args>
T FPUCanonalizeOperation(Func f, KeepSign keepSign, T first, Args... args) {
  T result = f(first, args...);
  if (std::isnan(result)) {
    result = FPUCanonalizeNaNArgs(result, keepSign, first, args...);
  }
  return result;
}

// Handle execution based on instruction types.

void Simulator::DecodeTypeRegisterSRsType() {
  float fs, ft, fd;
  fs = get_fpu_register_float(fs_reg());
  ft = get_fpu_register_float(ft_reg());
  fd = get_fpu_register_float(fd_reg());
  int32_t ft_int = base::bit_cast<int32_t>(ft);
  int32_t fd_int = base::bit_cast<int32_t>(fd);
  uint32_t cc, fcsr_cc;
  cc = instr_.FCccValue();
  fcsr_cc = get_fcsr_condition_bit(cc);
  switch (instr_.FunctionFieldRaw()) {
    case RINT: {
      DCHECK_EQ(kArchVariant, kMips64r6);
      float result, temp_result;
      double temp;
      float upper = std::ceil(fs);
      float lower = std::floor(fs);
      switch (get_fcsr_rounding_mode()) {
        case kRoundToNearest:
          if (upper - fs < fs - lower) {
            result = upper;
          } else if (upper - fs > fs - lower) {
            result = lower;
          } else {
            temp_result = upper / 2;
            float reminder = modf(temp_result, &temp);
            if (reminder == 0) {
              result = upper;
            } else {
              result = lower;
            }
          }
          break;
        case kRoundToZero:
          result = (fs > 0 ? lower : upper);
          break;
        case kRoundToPlusInf:
          result = upper;
          break;
        case kRoundToMinusInf:
          result = lower;
          break;
      }
      SetFPUFloatResult(fd_reg(), result);
      if (result != fs) {
        set_fcsr_bit(kFCSRInexactFlagBit, true);
      }
      break;
    }
    case ADD_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs + rhs; },
                                 fs, ft));
      break;
    case SUB_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs - rhs; },
                                 fs, ft));
      break;
    case MADDF_S:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), std::fma(fs, ft, fd));
      break;
    case MSUBF_S:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), std::fma(-fs, ft, fd));
      break;
    case MUL_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs * rhs; },
                                 fs, ft));
      break;
    case DIV_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float lhs, float rhs) { return lhs / rhs; },
                                 fs, ft));
      break;
    case ABS_S:
      SetFPUFloatResult(fd_reg(), FPUCanonalizeOperation(
                                      [](float fs) { return FPAbs(fs); }, fs));
      break;
    case MOV_S:
      SetFPUFloatResult(fd_reg(), fs);
      break;
    case NEG_S:
      SetFPUFloatResult(fd_reg(),
                        FPUCanonalizeOperation([](float src) { return -src; },
                                               KeepSign::yes, fs));
      break;
    case SQRT_S:
      SetFPUFloatResult(
          fd_reg(),
          FPUCanonalizeOperation([](float src) { return std::sqrt(src); }, fs));
      break;
    case RSQRT_S:
      SetFPUFloatResult(
          fd_reg(), FPUCanonalizeOperation(
                        [](float src) { return 1.0 / std::sqrt(src); }, fs));
      break;
    case RECIP_S:
      SetFPUFloatResult(fd_reg(), FPUCanonalizeOperation(
                                      [](float src) { return 1.0 / src; }, fs));
      break;
    case C_F_D:
      set_fcsr_bit(fcsr_cc, false);
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_UN_D:
      set_fcsr_bit(fcsr_cc, std::isnan(fs) || std::isnan(ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_EQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_UEQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case CVT_D_S:
      SetFPUDoubleResult(fd_reg(), static_cast<double>(fs));
      break;
    case CLASS_S: {  // Mips64r6 instruction
      // Convert float input to uint32_t for easier bit manipulation
      uint32_t classed = base::bit_cast<uint32_t>(fs);

      // Extracting sign, exponent and mantissa from the input float
      uint32_t sign = (classed >> 31) & 1;
      uint32_t exponent = (classed >> 23) & 0x000000FF;
      uint32_t mantissa = classed & 0x007FFFFF;
      uint32_t result;
      float fResult;

      // Setting flags if input float is negative infinity,
      // positive infinity, negative zero or positive zero
      bool negInf = (classed == 0xFF800000);
      bool posInf = (classed == 0x7F800000);
      bool negZero = (classed == 0x80000000);
      bool posZero = (classed == 0x00000000);

      bool signalingNan;
      bool quietNan;
      bool negSubnorm;
      bool posSubnorm;
      bool negNorm;
      bool posNorm;

      // Setting flags if float is NaN
      signalingNan = false;
      quietNan = false;
      if (!negInf && !posInf && (exponent == 0xFF)) {
        quietNan = ((mantissa & 0x00200000) == 0) &&
                   ((mantissa & (0x00200000 - 1)) == 0);
        signalingNan = !quietNan;
      }

      // Setting flags if float is subnormal number
      posSubnorm = false;
      negSubnorm = false;
      if ((exponent == 0) && (mantissa != 0)) {
        DCHECK(sign == 0 || sign == 1);
        posSubnorm = (sign == 0);
        negSubnorm = (sign == 1);
      }

      // Setting flags if float is normal number
      posNorm = false;
      negNorm = false;
      if (!posSubnorm && !negSubnorm && !posInf && !negInf && !signalingNan &&
          !quietNan && !negZero && !posZero) {
        DCHECK(sign == 0 || sign == 1);
        posNorm = (sign == 0);
        negNorm = (sign == 1);
      }

      // Calculating result according to description of CLASS.S instruction
      result = (posZero << 9) | (posSubnorm << 8) | (posNorm << 7) |
               (posInf << 6) | (negZero << 5) | (negSubnorm << 4) |
               (negNorm << 3) | (negInf << 2) | (quietNan << 1) | signalingNan;

      DCHECK_NE(result, 0);

      fResult = base::bit_cast<float>(result);
      SetFPUFloatResult(fd_reg(), fResult);
      break;
    }
    case CVT_L_S: {
      float rounded;
      int64_t result;
      round64_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case CVT_W_S: {
      float rounded;
      int32_t result;
      round_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
      break;
    }
    case TRUNC_W_S: {  // Truncate single to word (round towards 0).
      float rounded = trunc(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
    } break;
    case TRUNC_L_S: {  // Mips64r2 instruction.
      float rounded = trunc(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case ROUND_W_S: {
      float rounded = std::floor(fs + 0.5);
      int32_t result = static_cast<int32_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
      break;
    }
    case ROUND_L_S: {  // Mips64r2 instruction.
      float rounded = std::floor(fs + 0.5);
      int64_t result = static_cast<int64_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      int64_t i64 = static_cast<int64_t>(result);
      SetFPUResult(fd_reg(), i64);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case FLOOR_L_S: {  // Mips64r2 instruction.
      float rounded = floor(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case FLOOR_W_S:  // Round double to word towards negative infinity.
    {
      float rounded = std::floor(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
    } break;
    case CEIL_W_S:  // Round double to word towards positive infinity.
    {
      float rounded = std::ceil(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case CEIL_L_S: {  // Mips64r2 instruction.
      float rounded = ceil(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case MINA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMinA(ft, fs));
      break;
    case MAXA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMaxA(ft, fs));
      break;
    case MIN:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMin(ft, fs));
      break;
    case MAX:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), FPUMax(ft, fs));
      break;
    case SEL:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), (fd_int & 0x1) == 0 ? fs : ft);
      break;
    case SELEQZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), (ft_int & 0x1) == 0
                                      ? get_fpu_register_float(fs_reg())
                                      : 0.0);
      break;
    case SELNEZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUFloatResult(fd_reg(), (ft_int & 0x1) != 0
                                      ? get_fpu_register_float(fs_reg())
                                      : 0.0);
      break;
    case MOVZ_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() == 0) {
        SetFPUFloatResult(fd_reg(), fs);
      }
      break;
    }
    case MOVN_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() != 0) {
        SetFPUFloatResult(fd_reg(), fs);
      }
      break;
    }
    case MOVF: {
      // Same function field for MOVT.D and MOVF.D
      uint32_t ft_cc = (ft_reg() >> 2) & 0x7;
      ft_cc = get_fcsr_condition_bit(ft_cc);

      if (instr_.Bit(16)) {  // Read Tf bit.
        // MOVT.D
        if (test_fcsr_bit(ft_cc)) SetFPUFloatResult(fd_reg(), fs);
      } else {
        // MOVF.D
        if (!test_fcsr_bit(ft_cc)) SetFPUFloatResult(fd_reg(), fs);
      }
      break;
    }
    default:
      // TRUNC_W_S ROUND_W_S ROUND_L_S FLOOR_W_S FLOOR_L_S
      // CEIL_W_S CEIL_L_S CVT_PS_S are unimplemented.
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterDRsType() {
  double ft, fs, fd;
  uint32_t cc, fcsr_cc;
  fs = get_fpu_register_double(fs_reg());
  ft = (instr_.FunctionFieldRaw() != MOVF) ? get_fpu_register_double(ft_reg())
                                           : 0.0;
  fd = get_fpu_register_double(fd_reg());
  cc = instr_.FCccValue();
  fcsr_cc = get_fcsr_condition_bit(cc);
  int64_t ft_int = base::bit_cast<int64_t>(ft);
  int64_t fd_int = base::bit_cast<int64_t>(fd);
  switch (instr_.FunctionFieldRaw()) {
    case RINT: {
      DCHECK_EQ(kArchVariant, kMips64r6);
      double result, temp, temp_result;
      double upper = std::ceil(fs);
      double lower = std::floor(fs);
      switch (get_fcsr_rounding_mode()) {
        case kRoundToNearest:
          if (upper - fs < fs - lower) {
            result = upper;
          } else if (upper - fs > fs - lower) {
            result = lower;
          } else {
            temp_result = upper / 2;
            double reminder = modf(temp_result, &temp);
            if (reminder == 0) {
              result = upper;
            } else {
              result = lower;
            }
          }
          break;
        case kRoundToZero:
          result = (fs > 0 ? lower : upper);
          break;
        case kRoundToPlusInf:
          result = upper;
          break;
        case kRoundToMinusInf:
          result = lower;
          break;
      }
      SetFPUDoubleResult(fd_reg(), result);
      if (result != fs) {
        set_fcsr_bit(kFCSRInexactFlagBit, true);
      }
      break;
    }
    case SEL:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), (fd_int & 0x1) == 0 ? fs : ft);
      break;
    case SELEQZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), (ft_int & 0x1) == 0 ? fs : 0.0);
      break;
    case SELNEZ_C:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), (ft_int & 0x1) != 0 ? fs : 0.0);
      break;
    case MOVZ_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() == 0) {
        SetFPUDoubleResult(fd_reg(), fs);
      }
      break;
    }
    case MOVN_C: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      if (rt() != 0) {
        SetFPUDoubleResult(fd_reg(), fs);
      }
      break;
    }
    case MOVF: {
      // Same function field for MOVT.D and MOVF.D
      uint32_t ft_cc = (ft_reg() >> 2) & 0x7;
      ft_cc = get_fcsr_condition_bit(ft_cc);
      if (instr_.Bit(16)) {  // Read Tf bit.
        // MOVT.D
        if (test_fcsr_bit(ft_cc)) SetFPUDoubleResult(fd_reg(), fs);
      } else {
        // MOVF.D
        if (!test_fcsr_bit(ft_cc)) SetFPUDoubleResult(fd_reg(), fs);
      }
      break;
    }
    case MINA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMinA(ft, fs));
      break;
    case MAXA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMaxA(ft, fs));
      break;
    case MIN:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMin(ft, fs));
      break;
    case MAX:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), FPUMax(ft, fs));
      break;
    case ADD_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs + rhs; }, fs, ft));
      break;
    case SUB_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs - rhs; }, fs, ft));
      break;
    case MADDF_D:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), std::fma(fs, ft, fd));
      break;
    case MSUBF_D:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetFPUDoubleResult(fd_reg(), std::fma(-fs, ft, fd));
      break;
    case MUL_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs * rhs; }, fs, ft));
      break;
    case DIV_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation(
              [](double lhs, double rhs) { return lhs / rhs; }, fs, ft));
      break;
    case ABS_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation([](double fs) { return FPAbs(fs); }, fs));
      break;
    case MOV_D:
      SetFPUDoubleResult(fd_reg(), fs);
      break;
    case NEG_D:
      SetFPUDoubleResult(fd_reg(),
                         FPUCanonalizeOperation([](double src) { return -src; },
                                                KeepSign::yes, fs));
      break;
    case SQRT_D:
      SetFPUDoubleResult(
          fd_reg(),
          FPUCanonalizeOperation([](double fs) { return std::sqrt(fs); }, fs));
      break;
    case RSQRT_D:
      SetFPUDoubleResult(
          fd_reg(), FPUCanonalizeOperation(
                        [](double fs) { return 1.0 / std::sqrt(fs); }, fs));
      break;
    case RECIP_D:
      SetFPUDoubleResult(fd_reg(), FPUCanonalizeOperation(
                                       [](double fs) { return 1.0 / fs; }, fs));
      break;
    case C_UN_D:
      set_fcsr_bit(fcsr_cc, std::isnan(fs) || std::isnan(ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_EQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_UEQ_D:
      set_fcsr_bit(fcsr_cc, (fs == ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULT_D:
      set_fcsr_bit(fcsr_cc, (fs < ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_OLE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case C_ULE_D:
      set_fcsr_bit(fcsr_cc, (fs <= ft) || (std::isnan(fs) || std::isnan(ft)));
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    case CVT_W_D: {  // Convert double to word.
      double rounded;
      int32_t result;
      round_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_word_invalid_result(fs, rounded);
      }
      break;
    }
    case ROUND_W_D:  // Round double to word (round half to even).
    {
      double rounded = std::floor(fs + 0.5);
      int32_t result = static_cast<int32_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case TRUNC_W_D:  // Truncate double to word (round towards 0).
    {
      double rounded = trunc(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case FLOOR_W_D:  // Round double to word towards negative infinity.
    {
      double rounded = std::floor(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case CEIL_W_D:  // Round double to word towards positive infinity.
    {
      double rounded = std::ceil(fs);
      int32_t result = static_cast<int32_t>(rounded);
      SetFPUWordResult2(fd_reg(), result);
      if (set_fcsr_round_error(fs, rounded)) {
        set_fpu_register_invalid_result(fs, rounded);
      }
    } break;
    case CVT_S_D:  // Convert double to float (single).
      SetFPUFloatResult(fd_reg(), static_cast<float>(fs));
      break;
    case CVT_L_D: {  // Mips64r2: Truncate double to 64-bit long-word.
      double rounded;
      int64_t result;
      round64_according_to_fcsr(fs, &rounded, &result, fs);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case ROUND_L_D: {  // Mips64r2 instruction.
      double rounded = std::floor(fs + 0.5);
      int64_t result = static_cast<int64_t>(rounded);
      if ((result & 1) != 0 && result - fs == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        result--;
      }
      int64_t i64 = static_cast<int64_t>(result);
      SetFPUResult(fd_reg(), i64);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case TRUNC_L_D: {  // Mips64r2 instruction.
      double rounded = trunc(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case FLOOR_L_D: {  // Mips64r2 instruction.
      double rounded = floor(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case CEIL_L_D: {  // Mips64r2 instruction.
      double rounded = ceil(fs);
      int64_t result = static_cast<int64_t>(rounded);
      SetFPUResult(fd_reg(), result);
      if (set_fcsr_round64_error(fs, rounded)) {
        set_fpu_register_invalid_result64(fs, rounded);
      }
      break;
    }
    case CLASS_D: {  // Mips64r6 instruction
      // Convert double input to uint64_t for easier bit manipulation
      uint64_t classed = base::bit_cast<uint64_t>(fs);

      // Extracting sign, exponent and mantissa from the input double
      uint32_t sign = (classed >> 63) & 1;
      uint32_t exponent = (classed >> 52) & 0x00000000000007FF;
      uint64_t mantissa = classed & 0x000FFFFFFFFFFFFF;
      uint64_t result;
      double dResult;

      // Setting flags if input double is negative infinity,
      // positive infinity, negative zero or positive zero
      bool negInf = (classed == 0xFFF0000000000000);
      bool posInf = (classed == 0x7FF0000000000000);
      bool negZero = (classed == 0x8000000000000000);
      bool posZero = (classed == 0x0000000000000000);

      bool signalingNan;
      bool quietNan;
      bool negSubnorm;
      bool posSubnorm;
      bool negNorm;
      bool posNorm;

      // Setting flags if double is NaN
      signalingNan = false;
      quietNan = false;
      if (!negInf && !posInf && exponent == 0x7FF) {
        quietNan = ((mantissa & 0x0008000000000000) != 0) &&
                   ((mantissa & (0x0008000000000000 - 1)) == 0);
        signalingNan = !quietNan;
      }

      // Setting flags if double is subnormal number
      posSubnorm = false;
      negSubnorm = false;
      if ((exponent == 0) && (mantissa != 0)) {
        DCHECK(sign == 0 || sign == 1);
        posSubnorm = (sign == 0);
        negSubnorm = (sign == 1);
      }

      // Setting flags if double is normal number
      posNorm = false;
      negNorm = false;
      if (!posSubnorm && !negSubnorm && !posInf && !negInf && !signalingNan &&
          !quietNan && !negZero && !posZero) {
        DCHECK(sign == 0 || sign == 1);
        posNorm = (sign == 0);
        negNorm = (sign == 1);
      }

      // Calculating result according to description of CLASS.D instruction
      result = (posZero << 9) | (posSubnorm << 8) | (posNorm << 7) |
               (posInf << 6) | (negZero << 5) | (negSubnorm << 4) |
               (negNorm << 3) | (negInf << 2) | (quietNan << 1) | signalingNan;

      DCHECK_NE(result, 0);

      dResult = base::bit_cast<double>(result);
      SetFPUDoubleResult(fd_reg(), dResult);
      break;
    }
    case C_F_D: {
      set_fcsr_bit(fcsr_cc, false);
      TraceRegWr(test_fcsr_bit(fcsr_cc));
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterWRsType() {
  float fs = get_fpu_register_float(fs_reg());
  float ft = get_fpu_register_float(ft_reg());
  int64_t alu_out = 0x12345678;
  switch (instr_.FunctionFieldRaw()) {
    case CVT_S_W:  // Convert word to float (single).
      alu_out = get_fpu_register_signed_word(fs_reg());
      SetFPUFloatResult(fd_reg(), static_cast<float>(alu_out));
      break;
    case CVT_D_W:  // Convert word to double.
      alu_out = get_fpu_register_signed_word(fs_reg());
      SetFPUDoubleResult(fd_reg(), static_cast<double>(alu_out));
      break;
    case CMP_AF:
      SetFPUWordResult2(fd_reg(), 0);
      break;
    case CMP_UN:
      if (std::isnan(fs) || std::isnan(ft)) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_EQ:
      if (fs == ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_UEQ:
      if ((fs == ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_LT:
      if (fs < ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_ULT:
      if ((fs < ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_LE:
      if (fs <= ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_ULE:
      if ((fs <= ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_OR:
      if (!std::isnan(fs) && !std::isnan(ft)) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_UNE:
      if ((fs != ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    case CMP_NE:
      if (fs != ft) {
        SetFPUWordResult2(fd_reg(), -1);
      } else {
        SetFPUWordResult2(fd_reg(), 0);
      }
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterLRsType() {
  double fs = get_fpu_register_double(fs_reg());
  double ft = get_fpu_register_double(ft_reg());
  int64_t i64;
  switch (instr_.FunctionFieldRaw()) {
    case CVT_D_L:  // Mips32r2 instruction.
      i64 = get_fpu_register(fs_reg());
      SetFPUDoubleResult(fd_reg(), static_cast<double>(i64));
      break;
    case CVT_S_L:
      i64 = get_fpu_register(fs_reg());
      SetFPUFloatResult(fd_reg(), static_cast<float>(i64));
      break;
    case CMP_AF:
      SetFPUResult(fd_reg(), 0);
      break;
    case CMP_UN:
      if (std::isnan(fs) || std::isnan(ft)) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_EQ:
      if (fs == ft) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_UEQ:
      if ((fs == ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_LT:
      if (fs < ft) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_ULT:
      if ((fs < ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_LE:
      if (fs <= ft) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_ULE:
      if ((fs <= ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_OR:
      if (!std::isnan(fs) && !std::isnan(ft)) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_UNE:
      if ((fs != ft) || (std::isnan(fs) || std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    case CMP_NE:
      if (fs != ft && (!std::isnan(fs) && !std::isnan(ft))) {
        SetFPUResult(fd_reg(), -1);
      } else {
        SetFPUResult(fd_reg(), 0);
      }
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterCOP1() {
  switch (instr_.RsFieldRaw()) {
    case BC1:  // Branch on coprocessor condition.
    case BC1EQZ:
    case BC1NEZ:
      UNREACHABLE();
    case CFC1:
      // At the moment only FCSR is supported.
      DCHECK_EQ(fs_reg(), kFCSRRegister);
      SetResult(rt_reg(), FCSR_);
      break;
    case MFC1:
      set_register(rt_reg(),
                   static_cast<int64_t>(get_fpu_register_word(fs_reg())));
      TraceRegWr(get_register(rt_reg()), WORD_DWORD);
      break;
    case DMFC1:
      SetResult(rt_reg(), get_fpu_register(fs_reg()));
      break;
    case MFHC1:
      SetResult(rt_reg(), get_fpu_register_hi_word(fs_reg()));
      break;
    case CTC1: {
      // At the moment only FCSR is supported.
      DCHECK_EQ(fs_reg(), kFCSRRegist
"""


```