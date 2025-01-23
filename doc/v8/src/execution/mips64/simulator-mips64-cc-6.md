Response:
My thinking process to answer the request about the `simulator-mips64.cc` code goes through these stages:

1. **Understanding the Core Request:** The user wants to know what this specific C++ file does within the V8 JavaScript engine. They provide code snippets and ask for a functional summary, relating it to JavaScript, and identifying potential errors. The crucial detail is that it's part 7 of 9, implying the need for a summarizing perspective.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the provided code snippets, looking for recurring patterns and keywords. Key observations are:
    *  `Simulator::DecodeType...`:  This suggests the code is involved in decoding and simulating MIPS64 instructions.
    *  `msa_reg_t`, `MADD_Q`, `FTQ`, `FEXDO`, `MSA_HALF`, `MSA_WORD`, `MSA_DWORD`: These point to MSA (MIPS SIMD Architecture) instruction handling.
    *  `FCLASS`, `FTRUNC`, `FSQRT`, `FRCP`, `FLOG2`, `FTINT`, `FFINT`: These are floating-point operations.
    *  Bitwise operations (`AND_V`, `OR_V`, `XOR_V`, `BMNZ_V`, `BMZ_V`, `BSEL_V`, `PCNT`, `NLOC`, `NLZC`).
    *  Branch instructions (`beq`, `beqz`, `bne`, `bnez`, and the `BranchHelper` functions).
    *  Memory access (`LWL`, `LWR`, `LDL`, `LDR`).

3. **Formulating the High-Level Function:** Based on the `DecodeType...` functions and the types of instructions being processed, the primary function is **simulating the execution of MIPS64 instructions, especially those related to the MSA extension**. This simulation is done within the V8 engine, likely for environments where native MIPS64 execution isn't available or for testing purposes.

4. **Connecting to JavaScript (Instruction #3):**  Since this is a *simulator*, it doesn't directly *implement* JavaScript features. Instead, it provides the low-level execution environment for the *compiled* JavaScript code. Therefore, the connection is indirect. I need to explain that V8 compiles JavaScript into machine code (or an intermediate representation), and on MIPS64 architectures (or when simulating MIPS64), this code might use instructions that this simulator handles. I'll use a simple JavaScript example and explain how it *could* translate to some of the simulated instructions. For example, a floating-point calculation in JavaScript could eventually be executed by the simulator handling `FADD.D` or similar instructions. Bitwise operations in JavaScript could map to `AND_V`, `OR_V`, etc.

5. **Code Logic Inference (Instruction #4):** The code contains many conditional blocks (`switch`, `if`). To illustrate code logic, I need to pick a relatively self-contained example. The `MUL_Q` case within `DecodeTypeMsa3RF` is suitable. I can create a simple scenario with example input register values and show how the `product` is calculated and how the shift operation is applied. I'll need to consider the data types (`int16_t`, `int32_t`) involved.

6. **Common Programming Errors (Instruction #5):** The code deals with low-level operations and data type conversions. Common errors in this context would involve:
    * **Integer Overflow/Underflow:**  The saturation logic in `MADD_Q` and `MSUB_Q` hints at this. I'll create an example where multiplying two large integers exceeds the maximum value and show how the simulator handles it.
    * **Incorrect Bitwise Operations:** Using the wrong bitwise operator or an incorrect mask can lead to unexpected results. I'll give a brief example.
    * **Floating-Point Precision Issues:** While not explicitly shown in the provided snippets, it's a common issue with floating-point math. I'll briefly mention potential problems like loss of precision or unexpected NaN results.

7. **归纳功能 (Summarizing Function - Instruction #6):**  Given that this is part 7 of 9, it's likely focused on a specific aspect of the simulator. Based on the prevalence of MSA instructions, **this part seems to be primarily responsible for simulating the execution of MIPS64 instructions, particularly those related to the MSA SIMD extension and floating-point operations.**  It also handles some basic integer arithmetic and logical operations.

8. **Structure and Refine:** I'll organize the answer into clear sections corresponding to the user's questions. I'll use precise language and avoid jargon where possible, explaining technical terms when necessary. I'll ensure the JavaScript examples are simple and illustrative, not overly complex. I'll double-check the code logic examples to ensure they are accurate.

By following these steps, I can construct a comprehensive and accurate answer that addresses all the user's points and provides valuable insights into the functionality of the `simulator-mips64.cc` file.
好的，根据您提供的代码片段，我来归纳一下 `v8/src/execution/mips64/simulator-mips64.cc` 这个文件的功能，并解答您提出的问题。

**功能归纳（基于提供的第 7 部分代码）：**

从提供的代码片段来看，`v8/src/execution/mips64/simulator-mips64.cc` 文件的主要功能是 **模拟执行 MIPS64 架构的指令集，特别是针对 MSA (MIPS SIMD Architecture) 扩展的指令**。  这部分代码包含了大量的指令解码和执行的逻辑，涵盖了：

* **MSA 3 操作数指令 (DecodeTypeMsa3R, DecodeTypeMsa3RF):**  处理带有三个操作数的 MSA 指令，包括整数和浮点运算，例如乘法、加法、减法及其饱和及舍入变体 (`MUL_Q`, `MADD_Q`, `MSUB_Q`, `MULR_Q`, `MADDR_Q`, `MSUBR_Q`)，以及浮点数的类型转换 (`FEXDO`, `FTQ`) 和浮点运算 (`FMADD`, `FMSUB`).
* **MSA 向量指令 (DecodeTypeMsaVec):** 处理 MSA 的向量逻辑运算指令，如 `AND_V`, `OR_V`, `NOR_V`, `XOR_V` 以及位选择指令 `BMNZ_V`, `BMZ_V`, `BSEL_V`。
* **MSA 2 操作数指令 (DecodeTypeMsa2R, DecodeTypeMsa2RF):** 处理带有两个操作数的 MSA 指令，包括立即数填充 (`FILL`)，位计数 (`PCNT`)，前导零计数 (`NLOC`, `NLZC`)，以及浮点数的分类 (`FCLASS`)，截断 (`FTRUNC_S`, `FTRUNC_U`)，平方根 (`FSQRT`)，倒数平方根 (`FRSQRT`)，倒数 (`FRCP`)，舍入到整数 (`FRINT`)，以 2 为底的对数 (`FLOG2`)，浮点数转整数 (`FTINT_S`, `FTINT_U`)，整数转浮点数 (`FFINT_S`, `FFINT_U`)，以及半精度浮点数扩展 (`FEXUPL`, `FEXUPR`) 和定点数转换 (`FFQL`, `FFQR`)。
* **通用寄存器指令 (DecodeTypeRegister):**  作为一个调度器，根据指令的操作码，将指令分发到不同的解码和执行函数中，包括浮点运算指令 (`COP1`, `COP1X`)，以及其他特殊指令 (`SPECIAL`, `SPECIAL2`, `SPECIAL3`)。  MSA 指令也在这里被识别和分发。
* **立即数指令 (DecodeTypeImmediate):** 处理带有立即数的指令，例如条件分支指令 (`beq`, `bne` 等)，以及一些加载/存储指令。

**关于 .tq 结尾的文件：**

如果 `v8/src/execution/mips64/simulator-mips64.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码文件**。Torque 是 V8 用来生成高效的 C++ 代码的领域特定语言，常用于实现 V8 的内置函数和运行时库。  然而，根据您提供的路径和文件名，以及文件的内容（C++ 代码），可以确定 `simulator-mips64.cc` 是一个 **C++ 文件**，而不是 Torque 文件。

**与 JavaScript 功能的关系及举例：**

`simulator-mips64.cc` 模拟的是底层的机器指令执行。  当 V8 运行在 MIPS64 架构上，或者需要在其他架构上模拟 MIPS64 指令的执行时（例如在开发和测试阶段），这个文件就发挥作用。

以下 JavaScript 例子展示了一些可能最终通过模拟器执行的底层操作：

```javascript
// 算术运算可能涉及到 MUL_Q, MADD_Q 等指令的模拟
let a = 10;
let b = 5;
let sum = a + b;
let product = a * b;

// 位运算可能涉及到 AND_V, OR_V 等指令的模拟
let x = 0b1010;
let y = 0b1100;
let andResult = x & y;
let orResult = x | y;

// 浮点数运算可能涉及到 FADD.D, FMUL.D 等指令的模拟
let float1 = 3.14;
let float2 = 2.71;
let floatSum = float1 + float2;
let floatSqrt = Math.sqrt(float1);

// 类型转换可能涉及到 FCVTS.W.D, CVTDS.W 等指令的模拟
let intValue = 10;
let floatFromInt = parseFloat(intValue);
let intFromFloat = parseInt(float1);
```

**代码逻辑推理及假设输入输出：**

我们以 `MUL_Q` 指令为例进行代码逻辑推理。

**假设输入：**

* `opcode` 为 `MUL_Q`
* `DecodeMsaDataFormat()` 返回 `MSA_WORD`
* `ws.w[i]` (源寄存器 `ws` 的第 `i` 个字) 的值为 5
* `wt.w[i]` (源寄存器 `wt` 的第 `i` 个字) 的值为 10
* `shift` 的值为 2 (假设)

**执行流程：**

1. 进入 `DecodeTypeMsa3RF` 的 `MUL_Q` 分支。
2. `DecodeMsaDataFormat()` 返回 `MSA_WORD`，进入对应的 `case MSA_WORD:`。
3. 在循环中，`Msa3RFInstrHelper2<int32_t, int64_t>(opcode, ws.w[i], wt.w[i], &(wd.w[i]))` 被调用。
4. 在 `Msa3RFInstrHelper2` 中，`product = static_cast<T_int_dbl>(src) * static_cast<T_int_dbl>(wt);` 计算得到 `product = 5 * 10 = 50`。
5. `*wd = static_cast<T_int>(product >> shift);`  计算得到 `50 >> 2 = 12`。

**假设输出：**

* `wd.w[i]` (目标寄存器 `wd` 的第 `i` 个字) 的值为 12。

**用户常见的编程错误举例：**

在与这类底层代码相关的编程中，常见的错误包括：

* **整数溢出/下溢：** 例如在使用 `MADD_Q` 或 `MSUB_Q` 时，如果结果超出了 `T_int` 的表示范围，可能会导致饱和行为，但如果程序员没有考虑到这一点，可能会得到意想不到的结果。
  ```c++
  // 假设 T_int 是 int16_t
  int16_t a = std::numeric_limits<int16_t>::max();
  int16_t b = 1;
  // 如果没有饱和处理， a + b 会溢出
  // 在有饱和处理的情况下，结果会保持在 int16_t 的最大值
  ```
* **错误的位运算：**  在使用位运算指令时，可能会错误地使用 `&`，`|`，`^` 等运算符，导致逻辑错误。
  ```c++
  uint32_t mask = 0x0F;
  uint32_t value = 0x1A;
  // 错误的假设：我只想保留低 4 位
  uint32_t result = value | mask; // 错误地使用了 OR，应该使用 AND
  ```
* **浮点数精度问题：**  在浮点数运算中，由于精度限制，可能会出现舍入误差。此外，对 NaN (Not a Number) 的处理不当也可能导致错误。
  ```javascript
  let verySmall = 0.000000001;
  let veryLarge = 1000000000;
  let result = veryLarge + verySmall; // result 可能仍然等于 veryLarge，因为精度丢失
  ```

**总结第 7 部分的功能：**

作为共 9 部分的第 7 部分，这段代码主要集中在 **MIPS64 架构中 MSA 扩展指令的模拟执行**。它涵盖了 MSA 的三操作数、向量和双操作数指令，包括整数和浮点运算，以及一些基本的通用寄存器和立即数指令的处理。 这部分是整个模拟器中处理 SIMD 并行计算能力的关键部分。

希望这个详细的解答能够帮助您理解 `v8/src/execution/mips64/simulator-mips64.cc` 文件的功能。

### 提示词
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/mips64/simulator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
>::min()) >>
          1U;
      const T_int_dbl max_fix_dbl = std::numeric_limits<T_int_dbl>::max() >> 1U;
      if (product == min_fix_dbl) {
        product = max_fix_dbl;
      }
      *wd = static_cast<T_int>(product >> shift);
    } break;
    case MADD_Q: {
      result = (product + (static_cast<T_int_dbl>(*wd) << shift)) >> shift;
      *wd = static_cast<T_int>(
          result > max_int ? max_int : result < min_int ? min_int : result);
    } break;
    case MSUB_Q: {
      result = (-product + (static_cast<T_int_dbl>(*wd) << shift)) >> shift;
      *wd = static_cast<T_int>(
          result > max_int ? max_int : result < min_int ? min_int : result);
    } break;
    case MULR_Q: {
      const T_int_dbl min_fix_dbl =
          base::bit_cast<T_uint_dbl>(std::numeric_limits<T_int_dbl>::min()) >>
          1U;
      const T_int_dbl max_fix_dbl = std::numeric_limits<T_int_dbl>::max() >> 1U;
      if (product == min_fix_dbl) {
        *wd = static_cast<T_int>(max_fix_dbl >> shift);
        break;
      }
      *wd = static_cast<T_int>((product + (1 << (shift - 1))) >> shift);
    } break;
    case MADDR_Q: {
      result = (product + (static_cast<T_int_dbl>(*wd) << shift) +
                (1 << (shift - 1))) >>
               shift;
      *wd = static_cast<T_int>(
          result > max_int ? max_int : result < min_int ? min_int : result);
    } break;
    case MSUBR_Q: {
      result = (-product + (static_cast<T_int_dbl>(*wd) << shift) +
                (1 << (shift - 1))) >>
               shift;
      *wd = static_cast<T_int>(
          result > max_int ? max_int : result < min_int ? min_int : result);
    } break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeMsa3RF() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsa3RFMask;
  msa_reg_t wd, ws, wt;
  if (opcode != FCAF) {
    get_msa_register(ws_reg(), &ws);
    get_msa_register(wt_reg(), &wt);
  }
  switch (opcode) {
    case FCAF:
      wd.d[0] = 0;
      wd.d[1] = 0;
      break;
    case FEXDO:
#define PACK_FLOAT16(sign, exp, frac) \
  static_cast<uint16_t>(((sign) << 15) + ((exp) << 10) + (frac))
#define FEXDO_DF(source, dst)                                        \
  do {                                                               \
    element = source;                                                \
    aSign = element >> 31;                                           \
    aExp = element >> 23 & 0xFF;                                     \
    aFrac = element & 0x007FFFFF;                                    \
    if (aExp == 0xFF) {                                              \
      if (aFrac) {                                                   \
        /* Input is a NaN */                                         \
        dst = 0x7DFFU;                                               \
        break;                                                       \
      }                                                              \
      /* Infinity */                                                 \
      dst = PACK_FLOAT16(aSign, 0x1F, 0);                            \
      break;                                                         \
    } else if (aExp == 0 && aFrac == 0) {                            \
      dst = PACK_FLOAT16(aSign, 0, 0);                               \
      break;                                                         \
    } else {                                                         \
      int maxexp = 29;                                               \
      uint32_t mask;                                                 \
      uint32_t increment;                                            \
      bool rounding_bumps_exp;                                       \
      aFrac |= 0x00800000;                                           \
      aExp -= 0x71;                                                  \
      if (aExp < 1) {                                                \
        /* Will be denormal in halfprec */                           \
        mask = 0x00FFFFFF;                                           \
        if (aExp >= -11) {                                           \
          mask >>= 11 + aExp;                                        \
        }                                                            \
      } else {                                                       \
        /* Normal number in halfprec */                              \
        mask = 0x00001FFF;                                           \
      }                                                              \
      switch (MSACSR_ & 3) {                                         \
        case kRoundToNearest:                                        \
          increment = (mask + 1) >> 1;                               \
          if ((aFrac & mask) == increment) {                         \
            increment = aFrac & (increment << 1);                    \
          }                                                          \
          break;                                                     \
        case kRoundToPlusInf:                                        \
          increment = aSign ? 0 : mask;                              \
          break;                                                     \
        case kRoundToMinusInf:                                       \
          increment = aSign ? mask : 0;                              \
          break;                                                     \
        case kRoundToZero:                                           \
          increment = 0;                                             \
          break;                                                     \
      }                                                              \
      rounding_bumps_exp = (aFrac + increment >= 0x01000000);        \
      if (aExp > maxexp || (aExp == maxexp && rounding_bumps_exp)) { \
        dst = PACK_FLOAT16(aSign, 0x1F, 0);                          \
        break;                                                       \
      }                                                              \
      aFrac += increment;                                            \
      if (rounding_bumps_exp) {                                      \
        aFrac >>= 1;                                                 \
        aExp++;                                                      \
      }                                                              \
      if (aExp < -10) {                                              \
        dst = PACK_FLOAT16(aSign, 0, 0);                             \
        break;                                                       \
      }                                                              \
      if (aExp < 0) {                                                \
        aFrac >>= -aExp;                                             \
        aExp = 0;                                                    \
      }                                                              \
      dst = PACK_FLOAT16(aSign, aExp, aFrac >> 13);                  \
    }                                                                \
  } while (0);
      switch (DecodeMsaDataFormat()) {
        case MSA_HALF:
          for (int i = 0; i < kMSALanesWord; i++) {
            uint_fast32_t element;
            uint_fast32_t aSign, aFrac;
            int_fast32_t aExp;
            FEXDO_DF(ws.uw[i], wd.uh[i + kMSALanesHalf / 2])
            FEXDO_DF(wt.uw[i], wd.uh[i])
          }
          break;
        case MSA_WORD:
          for (int i = 0; i < kMSALanesDword; i++) {
            wd.w[i + kMSALanesWord / 2] = base::bit_cast<int32_t>(
                static_cast<float>(base::bit_cast<double>(ws.d[i])));
            wd.w[i] = base::bit_cast<int32_t>(
                static_cast<float>(base::bit_cast<double>(wt.d[i])));
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
#undef PACK_FLOAT16
#undef FEXDO_DF
    case FTQ:
#define FTQ_DF(source, dst, fp_type, int_type)                  \
  element = base::bit_cast<fp_type>(source) *                   \
            (1U << (sizeof(int_type) * kBitsPerByte - 1));      \
  if (element > std::numeric_limits<int_type>::max()) {         \
    dst = std::numeric_limits<int_type>::max();                 \
  } else if (element < std::numeric_limits<int_type>::min()) {  \
    dst = std::numeric_limits<int_type>::min();                 \
  } else if (std::isnan(element)) {                             \
    dst = 0;                                                    \
  } else {                                                      \
    int_type fixed_point;                                       \
    round_according_to_msacsr(element, &element, &fixed_point); \
    dst = fixed_point;                                          \
  }

      switch (DecodeMsaDataFormat()) {
        case MSA_HALF:
          for (int i = 0; i < kMSALanesWord; i++) {
            float element;
            FTQ_DF(ws.w[i], wd.h[i + kMSALanesHalf / 2], float, int16_t)
            FTQ_DF(wt.w[i], wd.h[i], float, int16_t)
          }
          break;
        case MSA_WORD:
          double element;
          for (int i = 0; i < kMSALanesDword; i++) {
            FTQ_DF(ws.d[i], wd.w[i + kMSALanesWord / 2], double, int32_t)
            FTQ_DF(wt.d[i], wd.w[i], double, int32_t)
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
#undef FTQ_DF
#define MSA_3RF_DF(T1, T2, Lanes, ws, wt, wd)         \
  for (int i = 0; i < Lanes; i++) {                   \
    Msa3RFInstrHelper<T1, T2>(opcode, ws, wt, &(wd)); \
  }
#define MSA_3RF_DF2(T1, T2, Lanes, ws, wt, wd)         \
  for (int i = 0; i < Lanes; i++) {                    \
    Msa3RFInstrHelper2<T1, T2>(opcode, ws, wt, &(wd)); \
  }
    case MADD_Q:
    case MSUB_Q:
    case MADDR_Q:
    case MSUBR_Q:
      get_msa_register(wd_reg(), &wd);
      [[fallthrough]];
    case MUL_Q:
    case MULR_Q:
      switch (DecodeMsaDataFormat()) {
        case MSA_HALF:
          MSA_3RF_DF2(int16_t, int32_t, kMSALanesHalf, ws.h[i], wt.h[i],
                      wd.h[i])
          break;
        case MSA_WORD:
          MSA_3RF_DF2(int32_t, int64_t, kMSALanesWord, ws.w[i], wt.w[i],
                      wd.w[i])
          break;
        default:
          UNREACHABLE();
      }
      break;
    default:
      if (opcode == FMADD || opcode == FMSUB) {
        get_msa_register(wd_reg(), &wd);
      }
      switch (DecodeMsaDataFormat()) {
        case MSA_WORD:
          MSA_3RF_DF(int32_t, float, kMSALanesWord, ws.w[i], wt.w[i], wd.w[i])
          break;
        case MSA_DWORD:
          MSA_3RF_DF(int64_t, double, kMSALanesDword, ws.d[i], wt.d[i], wd.d[i])
          break;
        default:
          UNREACHABLE();
      }
      break;
#undef MSA_3RF_DF
#undef MSA_3RF_DF2
  }
  set_msa_register(wd_reg(), &wd);
  TraceMSARegWr(&wd);
}

void Simulator::DecodeTypeMsaVec() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsaVECMask;
  msa_reg_t wd, ws, wt;

  get_msa_register(instr_.WsValue(), ws.d);
  get_msa_register(instr_.WtValue(), wt.d);
  if (opcode == BMNZ_V || opcode == BMZ_V || opcode == BSEL_V) {
    get_msa_register(instr_.WdValue(), wd.d);
  }

  for (int i = 0; i < kMSALanesDword; i++) {
    switch (opcode) {
      case AND_V:
        wd.d[i] = ws.d[i] & wt.d[i];
        break;
      case OR_V:
        wd.d[i] = ws.d[i] | wt.d[i];
        break;
      case NOR_V:
        wd.d[i] = ~(ws.d[i] | wt.d[i]);
        break;
      case XOR_V:
        wd.d[i] = ws.d[i] ^ wt.d[i];
        break;
      case BMNZ_V:
        wd.d[i] = (wt.d[i] & ws.d[i]) | (~wt.d[i] & wd.d[i]);
        break;
      case BMZ_V:
        wd.d[i] = (~wt.d[i] & ws.d[i]) | (wt.d[i] & wd.d[i]);
        break;
      case BSEL_V:
        wd.d[i] = (~wd.d[i] & ws.d[i]) | (wd.d[i] & wt.d[i]);
        break;
      default:
        UNREACHABLE();
    }
  }
  set_msa_register(instr_.WdValue(), wd.d);
  TraceMSARegWr(wd.d);
}

void Simulator::DecodeTypeMsa2R() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsa2RMask;
  msa_reg_t wd, ws;
  switch (opcode) {
    case FILL:
      switch (DecodeMsaDataFormat()) {
        case MSA_BYTE: {
          int64_t rs = get_register(instr_.WsValue());
          for (int i = 0; i < kMSALanesByte; i++) {
            wd.b[i] = rs & 0xFFu;
          }
          set_msa_register(instr_.WdValue(), wd.b);
          TraceMSARegWr(wd.b);
          break;
        }
        case MSA_HALF: {
          int64_t rs = get_register(instr_.WsValue());
          for (int i = 0; i < kMSALanesHalf; i++) {
            wd.h[i] = rs & 0xFFFFu;
          }
          set_msa_register(instr_.WdValue(), wd.h);
          TraceMSARegWr(wd.h);
          break;
        }
        case MSA_WORD: {
          int64_t rs = get_register(instr_.WsValue());
          for (int i = 0; i < kMSALanesWord; i++) {
            wd.w[i] = rs & 0xFFFFFFFFu;
          }
          set_msa_register(instr_.WdValue(), wd.w);
          TraceMSARegWr(wd.w);
          break;
        }
        case MSA_DWORD: {
          int64_t rs = get_register(instr_.WsValue());
          wd.d[0] = wd.d[1] = rs;
          set_msa_register(instr_.WdValue(), wd.d);
          TraceMSARegWr(wd.d);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    case PCNT:
#define PCNT_DF(elem, num_of_lanes)                       \
  get_msa_register(instr_.WsValue(), ws.elem);            \
  for (int i = 0; i < num_of_lanes; i++) {                \
    uint64_t u64elem = static_cast<uint64_t>(ws.elem[i]); \
    wd.elem[i] = base::bits::CountPopulation(u64elem);    \
  }                                                       \
  set_msa_register(instr_.WdValue(), wd.elem);            \
  TraceMSARegWr(wd.elem)

      switch (DecodeMsaDataFormat()) {
        case MSA_BYTE:
          PCNT_DF(ub, kMSALanesByte);
          break;
        case MSA_HALF:
          PCNT_DF(uh, kMSALanesHalf);
          break;
        case MSA_WORD:
          PCNT_DF(uw, kMSALanesWord);
          break;
        case MSA_DWORD:
          PCNT_DF(ud, kMSALanesDword);
          break;
        default:
          UNREACHABLE();
      }
#undef PCNT_DF
      break;
    case NLOC:
#define NLOC_DF(elem, num_of_lanes)                                         \
  get_msa_register(instr_.WsValue(), ws.elem);                              \
  for (int i = 0; i < num_of_lanes; i++) {                                  \
    const uint64_t mask = (num_of_lanes == kMSALanesDword)                  \
                              ? UINT64_MAX                                  \
                              : (1ULL << (kMSARegSize / num_of_lanes)) - 1; \
    uint64_t u64elem = static_cast<uint64_t>(~ws.elem[i]) & mask;           \
    wd.elem[i] = base::bits::CountLeadingZeros64(u64elem) -                 \
                 (64 - kMSARegSize / num_of_lanes);                         \
  }                                                                         \
  set_msa_register(instr_.WdValue(), wd.elem);                              \
  TraceMSARegWr(wd.elem)

      switch (DecodeMsaDataFormat()) {
        case MSA_BYTE:
          NLOC_DF(ub, kMSALanesByte);
          break;
        case MSA_HALF:
          NLOC_DF(uh, kMSALanesHalf);
          break;
        case MSA_WORD:
          NLOC_DF(uw, kMSALanesWord);
          break;
        case MSA_DWORD:
          NLOC_DF(ud, kMSALanesDword);
          break;
        default:
          UNREACHABLE();
      }
#undef NLOC_DF
      break;
    case NLZC:
#define NLZC_DF(elem, num_of_lanes)                         \
  get_msa_register(instr_.WsValue(), ws.elem);              \
  for (int i = 0; i < num_of_lanes; i++) {                  \
    uint64_t u64elem = static_cast<uint64_t>(ws.elem[i]);   \
    wd.elem[i] = base::bits::CountLeadingZeros64(u64elem) - \
                 (64 - kMSARegSize / num_of_lanes);         \
  }                                                         \
  set_msa_register(instr_.WdValue(), wd.elem);              \
  TraceMSARegWr(wd.elem)

      switch (DecodeMsaDataFormat()) {
        case MSA_BYTE:
          NLZC_DF(ub, kMSALanesByte);
          break;
        case MSA_HALF:
          NLZC_DF(uh, kMSALanesHalf);
          break;
        case MSA_WORD:
          NLZC_DF(uw, kMSALanesWord);
          break;
        case MSA_DWORD:
          NLZC_DF(ud, kMSALanesDword);
          break;
        default:
          UNREACHABLE();
      }
#undef NLZC_DF
      break;
    default:
      UNREACHABLE();
  }
}

#define BIT(n) (0x1LL << n)
#define QUIET_BIT_S(nan) (base::bit_cast<int32_t>(nan) & BIT(22))
#define QUIET_BIT_D(nan) (base::bit_cast<int64_t>(nan) & BIT(51))
static inline bool isSnan(float fp) { return !QUIET_BIT_S(fp); }
static inline bool isSnan(double fp) { return !QUIET_BIT_D(fp); }
#undef QUIET_BIT_S
#undef QUIET_BIT_D

template <typename T_int, typename T_fp, typename T_src, typename T_dst>
T_int Msa2RFInstrHelper(uint32_t opcode, T_src src, T_dst* dst,
                        Simulator* sim) {
  using T_uint = typename std::make_unsigned<T_int>::type;
  switch (opcode) {
    case FCLASS: {
#define SNAN_BIT BIT(0)
#define QNAN_BIT BIT(1)
#define NEG_INFINITY_BIT BIT(2)
#define NEG_NORMAL_BIT BIT(3)
#define NEG_SUBNORMAL_BIT BIT(4)
#define NEG_ZERO_BIT BIT(5)
#define POS_INFINITY_BIT BIT(6)
#define POS_NORMAL_BIT BIT(7)
#define POS_SUBNORMAL_BIT BIT(8)
#define POS_ZERO_BIT BIT(9)
      T_fp element = *reinterpret_cast<T_fp*>(&src);
      switch (std::fpclassify(element)) {
        case FP_INFINITE:
          if (std::signbit(element)) {
            *dst = NEG_INFINITY_BIT;
          } else {
            *dst = POS_INFINITY_BIT;
          }
          break;
        case FP_NAN:
          if (isSnan(element)) {
            *dst = SNAN_BIT;
          } else {
            *dst = QNAN_BIT;
          }
          break;
        case FP_NORMAL:
          if (std::signbit(element)) {
            *dst = NEG_NORMAL_BIT;
          } else {
            *dst = POS_NORMAL_BIT;
          }
          break;
        case FP_SUBNORMAL:
          if (std::signbit(element)) {
            *dst = NEG_SUBNORMAL_BIT;
          } else {
            *dst = POS_SUBNORMAL_BIT;
          }
          break;
        case FP_ZERO:
          if (std::signbit(element)) {
            *dst = NEG_ZERO_BIT;
          } else {
            *dst = POS_ZERO_BIT;
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
#undef BIT
#undef SNAN_BIT
#undef QNAN_BIT
#undef NEG_INFINITY_BIT
#undef NEG_NORMAL_BIT
#undef NEG_SUBNORMAL_BIT
#undef NEG_ZERO_BIT
#undef POS_INFINITY_BIT
#undef POS_NORMAL_BIT
#undef POS_SUBNORMAL_BIT
#undef POS_ZERO_BIT
    case FTRUNC_S: {
      T_fp element = base::bit_cast<T_fp>(src);
      const T_int max_int = std::numeric_limits<T_int>::max();
      const T_int min_int = std::numeric_limits<T_int>::min();
      if (std::isnan(element)) {
        *dst = 0;
      } else if (element >= static_cast<T_fp>(max_int) || element <= min_int) {
        *dst = element >= static_cast<T_fp>(max_int) ? max_int : min_int;
      } else {
        *dst = static_cast<T_int>(std::trunc(element));
      }
      break;
    }
    case FTRUNC_U: {
      T_fp element = base::bit_cast<T_fp>(src);
      const T_uint max_int = std::numeric_limits<T_uint>::max();
      if (std::isnan(element)) {
        *dst = 0;
      } else if (element >= static_cast<T_fp>(max_int) || element <= 0) {
        *dst = element >= static_cast<T_fp>(max_int) ? max_int : 0;
      } else {
        *dst = static_cast<T_uint>(std::trunc(element));
      }
      break;
    }
    case FSQRT: {
      T_fp element = base::bit_cast<T_fp>(src);
      if (element < 0 || std::isnan(element)) {
        *dst = base::bit_cast<T_int>(std::numeric_limits<T_fp>::quiet_NaN());
      } else {
        *dst = base::bit_cast<T_int>(std::sqrt(element));
      }
      break;
    }
    case FRSQRT: {
      T_fp element = base::bit_cast<T_fp>(src);
      if (element < 0 || std::isnan(element)) {
        *dst = base::bit_cast<T_int>(std::numeric_limits<T_fp>::quiet_NaN());
      } else {
        *dst = base::bit_cast<T_int>(1 / std::sqrt(element));
      }
      break;
    }
    case FRCP: {
      T_fp element = base::bit_cast<T_fp>(src);
      if (std::isnan(element)) {
        *dst = base::bit_cast<T_int>(std::numeric_limits<T_fp>::quiet_NaN());
      } else {
        *dst = base::bit_cast<T_int>(1 / element);
      }
      break;
    }
    case FRINT: {
      T_fp element = base::bit_cast<T_fp>(src);
      if (std::isnan(element)) {
        *dst = base::bit_cast<T_int>(std::numeric_limits<T_fp>::quiet_NaN());
      } else {
        T_int dummy;
        sim->round_according_to_msacsr<T_fp, T_int>(element, &element, &dummy);
        *dst = base::bit_cast<T_int>(element);
      }
      break;
    }
    case FLOG2: {
      T_fp element = base::bit_cast<T_fp>(src);
      switch (std::fpclassify(element)) {
        case FP_NORMAL:
        case FP_SUBNORMAL:
          *dst = base::bit_cast<T_int>(std::logb(element));
          break;
        case FP_ZERO:
          *dst = base::bit_cast<T_int>(-std::numeric_limits<T_fp>::infinity());
          break;
        case FP_NAN:
          *dst = base::bit_cast<T_int>(std::numeric_limits<T_fp>::quiet_NaN());
          break;
        case FP_INFINITE:
          if (element < 0) {
            *dst =
                base::bit_cast<T_int>(std::numeric_limits<T_fp>::quiet_NaN());
          } else {
            *dst = base::bit_cast<T_int>(std::numeric_limits<T_fp>::infinity());
          }
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
    case FTINT_S: {
      T_fp element = base::bit_cast<T_fp>(src);
      const T_int max_int = std::numeric_limits<T_int>::max();
      const T_int min_int = std::numeric_limits<T_int>::min();
      if (std::isnan(element)) {
        *dst = 0;
      } else if (element < min_int || element > static_cast<T_fp>(max_int)) {
        *dst = element > static_cast<T_fp>(max_int) ? max_int : min_int;
      } else {
        sim->round_according_to_msacsr<T_fp, T_int>(element, &element, dst);
      }
      break;
    }
    case FTINT_U: {
      T_fp element = base::bit_cast<T_fp>(src);
      const T_uint max_uint = std::numeric_limits<T_uint>::max();
      if (std::isnan(element)) {
        *dst = 0;
      } else if (element < 0 || element > static_cast<T_fp>(max_uint)) {
        *dst = element > static_cast<T_fp>(max_uint) ? max_uint : 0;
      } else {
        T_uint res;
        sim->round_according_to_msacsr<T_fp, T_uint>(element, &element, &res);
        *dst = *reinterpret_cast<T_int*>(&res);
      }
      break;
    }
    case FFINT_S:
      *dst = base::bit_cast<T_int>(static_cast<T_fp>(src));
      break;
    case FFINT_U:
      using uT_src = typename std::make_unsigned<T_src>::type;
      *dst =
          base::bit_cast<T_int>(static_cast<T_fp>(base::bit_cast<uT_src>(src)));
      break;
    default:
      UNREACHABLE();
  }
  return 0;
}

template <typename T_int, typename T_fp, typename T_reg>
T_int Msa2RFInstrHelper2(uint32_t opcode, T_reg ws, int i) {
  switch (opcode) {
#define EXTRACT_FLOAT16_SIGN(fp16) (fp16 >> 15)
#define EXTRACT_FLOAT16_EXP(fp16) (fp16 >> 10 & 0x1F)
#define EXTRACT_FLOAT16_FRAC(fp16) (fp16 & 0x3FF)
#define PACK_FLOAT32(sign, exp, frac) \
  static_cast<uint32_t>(((sign) << 31) + ((exp) << 23) + (frac))
#define FEXUP_DF(src_index)                                                    \
  uint_fast16_t element = ws.uh[src_index];                                    \
  uint_fast32_t aSign, aFrac;                                                  \
  int_fast32_t aExp;                                                           \
  aSign = EXTRACT_FLOAT16_SIGN(element);                                       \
  aExp = EXTRACT_FLOAT16_EXP(element);                                         \
  aFrac = EXTRACT_FLOAT16_FRAC(element);                                       \
  if (V8_LIKELY(aExp && aExp != 0x1F)) {                                       \
    return PACK_FLOAT32(aSign, aExp + 0x70, aFrac << 13);                      \
  } else if (aExp == 0x1F) {                                                   \
    if (aFrac) {                                                               \
      return base::bit_cast<int32_t>(std::numeric_limits<float>::quiet_NaN()); \
    } else {                                                                   \
      return base::bit_cast<uint32_t>(                                         \
                 std::numeric_limits<float>::infinity()) |                     \
             static_cast<uint32_t>(aSign) << 31;                               \
    }                                                                          \
  } else {                                                                     \
    if (aFrac == 0) {                                                          \
      return PACK_FLOAT32(aSign, 0, 0);                                        \
    } else {                                                                   \
      int_fast16_t shiftCount =                                                \
          base::bits::CountLeadingZeros32(static_cast<uint32_t>(aFrac)) - 21;  \
      aFrac <<= shiftCount;                                                    \
      aExp = -shiftCount;                                                      \
      return PACK_FLOAT32(aSign, aExp + 0x70, aFrac << 13);                    \
    }                                                                          \
  }
    case FEXUPL:
      if (std::is_same<int32_t, T_int>::value) {
        FEXUP_DF(i + kMSALanesWord)
      } else {
        return base::bit_cast<int64_t>(static_cast<double>(
            base::bit_cast<float>(ws.w[i + kMSALanesDword])));
      }
    case FEXUPR:
      if (std::is_same<int32_t, T_int>::value) {
        FEXUP_DF(i)
      } else {
        return base::bit_cast<int64_t>(
            static_cast<double>(base::bit_cast<float>(ws.w[i])));
      }
    case FFQL: {
      if (std::is_same<int32_t, T_int>::value) {
        return base::bit_cast<int32_t>(
            static_cast<float>(ws.h[i + kMSALanesWord]) / (1U << 15));
      } else {
        return base::bit_cast<int64_t>(
            static_cast<double>(ws.w[i + kMSALanesDword]) / (1U << 31));
      }
      break;
    }
    case FFQR: {
      if (std::is_same<int32_t, T_int>::value) {
        return base::bit_cast<int32_t>(static_cast<float>(ws.h[i]) /
                                       (1U << 15));
      } else {
        return base::bit_cast<int64_t>(static_cast<double>(ws.w[i]) /
                                       (1U << 31));
      }
      break;
      default:
        UNREACHABLE();
    }
  }
#undef EXTRACT_FLOAT16_SIGN
#undef EXTRACT_FLOAT16_EXP
#undef EXTRACT_FLOAT16_FRAC
#undef PACK_FLOAT32
#undef FEXUP_DF
}

void Simulator::DecodeTypeMsa2RF() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsa2RFMask;
  msa_reg_t wd, ws;
  get_msa_register(ws_reg(), &ws);
  if (opcode == FEXUPL || opcode == FEXUPR || opcode == FFQL ||
      opcode == FFQR) {
    switch (DecodeMsaDataFormat()) {
      case MSA_WORD:
        for (int i = 0; i < kMSALanesWord; i++) {
          wd.w[i] = Msa2RFInstrHelper2<int32_t, float>(opcode, ws, i);
        }
        break;
      case MSA_DWORD:
        for (int i = 0; i < kMSALanesDword; i++) {
          wd.d[i] = Msa2RFInstrHelper2<int64_t, double>(opcode, ws, i);
        }
        break;
      default:
        UNREACHABLE();
    }
  } else {
    switch (DecodeMsaDataFormat()) {
      case MSA_WORD:
        for (int i = 0; i < kMSALanesWord; i++) {
          Msa2RFInstrHelper<int32_t, float>(opcode, ws.w[i], &wd.w[i], this);
        }
        break;
      case MSA_DWORD:
        for (int i = 0; i < kMSALanesDword; i++) {
          Msa2RFInstrHelper<int64_t, double>(opcode, ws.d[i], &wd.d[i], this);
        }
        break;
      default:
        UNREACHABLE();
    }
  }
  set_msa_register(wd_reg(), &wd);
  TraceMSARegWr(&wd);
}

void Simulator::DecodeTypeRegister() {
  // ---------- Execution.
  switch (instr_.OpcodeFieldRaw()) {
    case COP1:
      DecodeTypeRegisterCOP1();
      break;
    case COP1X:
      DecodeTypeRegisterCOP1X();
      break;
    case SPECIAL:
      DecodeTypeRegisterSPECIAL();
      break;
    case SPECIAL2:
      DecodeTypeRegisterSPECIAL2();
      break;
    case SPECIAL3:
      DecodeTypeRegisterSPECIAL3();
      break;
    case MSA:
      switch (instr_.MSAMinorOpcodeField()) {
        case kMsaMinor3R:
          DecodeTypeMsa3R();
          break;
        case kMsaMinor3RF:
          DecodeTypeMsa3RF();
          break;
        case kMsaMinorVEC:
          DecodeTypeMsaVec();
          break;
        case kMsaMinor2R:
          DecodeTypeMsa2R();
          break;
        case kMsaMinor2RF:
          DecodeTypeMsa2RF();
          break;
        case kMsaMinorELM:
          DecodeTypeMsaELM();
          break;
        default:
          UNREACHABLE();
      }
      break;
    // Unimplemented opcodes raised an error in the configuration step before,
    // so we can use the default here to set the destination register in common
    // cases.
    default:
      UNREACHABLE();
  }
}

// Type 2: instructions using a 16, 21 or 26 bits immediate. (e.g. beq, beqc).
void Simulator::DecodeTypeImmediate() {
  // Instruction fields.
  Opcode op = instr_.OpcodeFieldRaw();
  int32_t rs_reg = instr_.RsValue();
  int64_t rs = get_register(instr_.RsValue());
  uint64_t rs_u = static_cast<uint64_t>(rs);
  int32_t rt_reg = instr_.RtValue();  // Destination register.
  int64_t rt = get_register(rt_reg);
  int16_t imm16 = instr_.Imm16Value();
  int32_t imm18 = instr_.Imm18Value();

  int32_t ft_reg = instr_.FtValue();  // Destination register.

  // Zero extended immediate.
  uint64_t oe_imm16 = 0xFFFF & imm16;
  // Sign extended immediate.
  int64_t se_imm16 = imm16;
  int64_t se_imm18 = imm18 | ((imm18 & 0x20000) ? 0xFFFFFFFFFFFC0000 : 0);

  // Next pc.
  int64_t next_pc = bad_ra;

  // Used for conditional branch instructions.
  bool execute_branch_delay_instruction = false;

  // Used for arithmetic instructions.
  int64_t alu_out = 0;

  // Used for memory instructions.
  int64_t addr = 0x0;
  // Alignment for 32-bit integers used in LWL, LWR, etc.
  const int kInt32AlignmentMask = sizeof(uint32_t) - 1;
  // Alignment for 64-bit integers used in LDL, LDR, etc.
  const int kInt64AlignmentMask = sizeof(uint64_t) - 1;

  // Branch instructions common part.
  auto BranchAndLinkHelper =
      [this, &next_pc, &execute_branch_delay_instruction](bool do_branch) {
        execute_branch_delay_instruction = true;
        int64_t current_pc = get_pc();
        set_register(31, current_pc + 2 * kInstrSize);
        if (do_branch) {
          int16_t imm16 = instr_.Imm16Value();
          next_pc = current_pc + (imm16 << 2) + kInstrSize;
        } else {
          next_pc = current_pc + 2 * kInstrSize;
        }
      };

  auto BranchHelper = [this, &next_pc,
                       &execute_branch_delay_instruction](bool do_branch) {
    execute_branch_delay_instruction = true;
    int64_t current_pc = get_pc();
    if (do_branch) {
      int16_t imm16 = instr_.Imm16Value();
      next_pc = current_pc + (imm16 << 2) + kInstrSize;
    } else {
      next_pc = current_pc + 2 * kInstrSize;
    }
  };

  auto BranchHelper_MSA = [this, &next_pc, imm16,
                           &execute_branch_delay_instruction](bool do_branch) {
    execute_branch_delay_instruction = true;
    int64_t current_pc = get_pc();
    const int32_t bitsIn16Int = sizeof(int16_t) * kBitsPerByte;
    if (do_branch) {
      if (v8_flags.debug_code) {
        int16_t bits = imm16 & 0xFC;
        if (imm16 >= 0) {
          CHECK_EQ(bits, 0);
        } else {
          CHECK_EQ(bits ^ 0xFC, 0);
        }
      }
      // jump range :[pc + kInstrSize - 512 * kInstrSize,
      //              pc + kInstrSize + 511 * kInstrSize]
      int16_t offset = static_cast<int16_t>(imm16 << (bitsIn16Int - 10)) >>
                       (bitsIn16Int - 12);
      next_pc = current_pc + offset + kInstrSize;
    } else {
      next_pc = current_pc + 2 * kIn
```