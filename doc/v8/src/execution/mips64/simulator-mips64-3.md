Response: The user wants to understand the functionality of a specific part of a C++ file (`simulator-mips64.cc`) within the V8 JavaScript engine. This part (part 4 of 5) seems to be focused on simulating MIPS64 instructions, specifically those related to MSA (MIPS SIMD Architecture).

Here's a breakdown of the thought process to generate the summary:

1. **Identify the file and its context:** The file is `simulator-mips64.cc` within the V8 engine's `execution/mips64` directory. This immediately suggests its purpose: simulating MIPS64 architecture for V8's execution.

2. **Focus on the specified part:** The prompt mentions "part 4 of 5". While the provided code doesn't explicitly demarcate these parts,  the code blocks seem to be grouped by the type of MIPS instruction being simulated. By scanning the function names like `DecodeTypeMsa3RF`, `DecodeTypeMsaVec`, `DecodeTypeMsa2R`, `DecodeTypeMsa2RF`, and the start of `DecodeTypeImmediate`, it's clear this section deals heavily with MSA instructions and then transitions into more general immediate-type instructions.

3. **Analyze the function names and their contents:**
    * `DecodeTypeMsa3RF`:  The "3RF" likely stands for "3 Register Floating-point". The code within this function handles various MSA instructions involving three registers, focusing on floating-point operations like `FCAF`, `FEXDO`, `FTQ`, `MADD_Q`, `MSUB_Q`, `MADDR_Q`, `MSUBR_Q`, `MUL_Q`, `MULR_Q`, `FMADD`, and `FMSUB`. It involves packing/unpacking half-precision floats, converting between float/double and integer types, and performing fused multiply-add/subtract operations.
    * `DecodeTypeMsaVec`: "Vec" signifies vector operations. This function handles logical operations (`AND_V`, `OR_V`, `NOR_V`, `XOR_V`) and bitwise selection (`BMNZ_V`, `BMZ_V`, `BSEL_V`) on MSA registers.
    * `DecodeTypeMsa2R`: "2R" suggests instructions with two registers. This function deals with instructions like `FILL` (filling a register with a value), `PCNT` (population count), `NLOC` (negated leading ones count), and `NLZC` (negated leading zeros count).
    * `DecodeTypeMsa2RF`: "2RF" likely means "2 Register Floating-point". This function handles instructions like `FCLASS` (classifying a floating-point number), `FTRUNC_S`/`FTRUNC_U` (truncating to signed/unsigned integer), `FSQRT` (square root), `FRSQRT` (reciprocal square root), `FRCP` (reciprocal), `FRINT` (round to integer), `FLOG2` (log base 2), `FTINT_S`/`FTINT_U` (convert to signed/unsigned integer), `FFINT_S`/`FFINT_U` (convert integer to float), `FEXUPL`/`FEXUPR` (expand half-precision float), and `FFQL`/`FFQR` (convert half/single-precision float to fixed-point). The code uses helper templates (`Msa2RFInstrHelper`, `Msa2RFInstrHelper2`) to manage these operations.
    * `DecodeTypeRegister`: This function acts as a dispatcher, calling the specific `DecodeTypeMsa...` functions based on the instruction's minor opcode. It also handles other non-MSA register-type instructions.
    * `DecodeTypeImmediate`: This function starts handling instructions that have an immediate value encoded within them. It includes various branching instructions (e.g., `BEQ`, `BNE`, `BLTZ`, `BGEZ`), arithmetic instructions (`ADDIU`, `DADDIU`, `SLTI`, etc.), memory access instructions (`LB`, `LH`, `LW`, `LD`, `SB`, `SH`, `SW`, `SD`, `LWC1`, `SDC1`), and PC-relative addressing instructions (`PCREL`). It also appears to be handling some MSA immediate instructions (`DecodeTypeMsaI8`, `DecodeTypeMsaI5`, etc.).

4. **Identify the connection to JavaScript:** The key is that this code simulates the *execution* of MIPS64 instructions. JavaScript code, when run by V8, is eventually compiled down to machine code. On a MIPS64 architecture, those instructions would be MIPS64 instructions. The simulator allows V8 to run and test this generated machine code even on a non-MIPS64 platform. The examples of floating-point conversions and SIMD operations are areas where JavaScript can leverage underlying hardware (or simulated hardware in this case) for performance.

5. **Construct JavaScript examples:** To illustrate the connection, focus on the functionalities provided by the simulated instructions. Floating-point conversions, SIMD-like array operations, and bitwise manipulations are good candidates.

6. **Summarize the functionality:** Combine the observations about each function and its role in simulating MIPS64 instructions, especially focusing on the MSA extensions. Emphasize the role of the simulator in enabling V8 to execute JavaScript on different architectures.

7. **Review and refine:** Ensure the summary is clear, concise, and accurately reflects the functionality of the code. Double-check the JavaScript examples for correctness and relevance. Make sure to address the "part 4 of 5" aspect by noting the transition into more general immediate instructions.
这是 `v8/src/execution/mips64/simulator-mips64.cc` 文件的第四部分，主要负责 MIPS64 架构中 MSA (MIPS SIMD Architecture) 指令的模拟，并开始处理一些通用的立即数类型的指令。

**功能归纳:**

1. **MSA 指令模拟 (DecodeTypeMsa3RF, DecodeTypeMsaVec, DecodeTypeMsa2R, DecodeTypeMsa2RF):**
   - 这部分代码实现了对各种 MSA 指令的解码和执行。MSA 是一组 SIMD (Single Instruction, Multiple Data) 指令，允许并行处理向量数据。
   - **DecodeTypeMsa3RF:** 处理需要三个 MSA 寄存器的浮点 MSA 指令，例如：
     - `FCAF`:  清零目标寄存器。
     - `FEXDO`: 将单精度浮点数转换为半精度浮点数。
     - `FTQ`: 将浮点数转换为定点数。
     - `MADD_Q`, `MSUB_Q`, `MADDR_Q`, `MSUBR_Q`, `MUL_Q`, `MULR_Q`:  定点数的乘法和乘加/乘减运算。
     - `FMADD`, `FMSUB`: 浮点数的乘加和乘减运算。
   - **DecodeTypeMsaVec:** 处理向量逻辑运算指令，例如：
     - `AND_V`, `OR_V`, `NOR_V`, `XOR_V`:  向量的按位与、或、非或运算。
     - `BMNZ_V`, `BMZ_V`, `BSEL_V`:  向量的位选择操作。
   - **DecodeTypeMsa2R:** 处理需要两个 MSA 寄存器的指令，例如：
     - `FILL`:  用一个通用寄存器的值填充 MSA 寄存器。
     - `PCNT`:  计算 MSA 寄存器中每个元素的 popcount (population count，即二进制表示中 1 的个数)。
     - `NLOC`:  计算 MSA 寄存器中每个元素的 negated leading ones count (前导 1 的个数取反)。
     - `NLZC`:  计算 MSA 寄存器中每个元素的 negated leading zeros count (前导 0 的个数取反)。
   - **DecodeTypeMsa2RF:** 处理需要两个 MSA 寄存器的浮点 MSA 指令，例如：
     - `FCLASS`:  对浮点数进行分类（例如，正零、负无穷大、NaN 等）。
     - `FTRUNC_S`, `FTRUNC_U`: 将浮点数截断为有符号/无符号整数。
     - `FSQRT`, `FRSQRT`, `FRCP`: 浮点数的平方根、倒数平方根和倒数运算。
     - `FRINT`:  将浮点数舍入为整数。
     - `FLOG2`:  计算以 2 为底的对数。
     - `FTINT_S`, `FTINT_U`: 将浮点数转换为有符号/无符号整数，并进行饱和处理。
     - `FFINT_S`, `FFINT_U`: 将有符号/无符号整数转换为浮点数。
     - `FEXUPL`, `FEXUPR`: 将半精度浮点数扩展为单精度浮点数。
     - `FFQL`, `FFQR`: 将半精度/单精度浮点数转换为定点数。

2. **指令分发 (DecodeTypeRegister):**
   - `DecodeTypeRegister` 函数负责根据指令的类型和操作码，将控制流分发到相应的解码和执行函数，包括 MSA 指令和其他寄存器类型的指令。

3. **立即数类型指令的初步处理 (DecodeTypeImmediate):**
   - 这部分开始处理带有立即数的指令。立即数是直接编码在指令中的常量值。
   - 目前的代码涵盖了多种立即数类型的指令，包括：
     - **分支指令 (Branch Instructions):** `BEQ`, `BNE`, `BLTZ`, `BGEZ`, `BLEZ`, `BGTZ` 等，用于控制程序的执行流程，根据条件跳转到不同的代码位置。也包括一些带链接的分支指令，例如 `BLTZAL`, `BGEZAL`，它们在跳转前会将返回地址保存在 `ra` 寄存器中。
     - **算术指令 (Arithmetic Instructions):** `ADDIU`, `DADDIU`, `SLTI`, `SLTIU`, `ANDI`, `ORI`, `XORI`, `LUI`, `DAUI` 等，用于执行基本的算术和逻辑运算。
     - **内存访问指令 (Memory Instructions):** `LB`, `LH`, `LW`, `LD`, `LBU`, `LHU`, `LWL`, `LWR`, `LDL`, `LDR`, `SB`, `SH`, `SW`, `SD`, `SWL`, `SWR`, `SDL`, `SDR`, `LL`, `SC`, `LLD`, `SCD`, `LWC1`, `LDC1`, `SWC1`, `SDC1` 等，用于从内存中加载数据到寄存器或将寄存器中的数据存储到内存中。
     - **PC 相对指令 (PC-Relative Instructions):** `PCREL`，包含 `ALUIPC`, `AUIPC`, `LDPC`, `LWUPC`, `LWPC`, `ADDIUPC` 等，使用相对于程序计数器 (PC) 的偏移量来访问数据或计算地址。
     - **带立即数的 MSA 指令:**  `DecodeTypeMsaI8`, `DecodeTypeMsaI5`, `DecodeTypeMsaI10`, `DecodeTypeMsaELM`, `DecodeTypeMsaBIT`, `DecodeTypeMsaMI10` 这些函数虽然没有在提供的代码片段中完整展示，但 `DecodeTypeImmediate` 函数中的 `MSA` 分支语句表明它会处理带有立即数的 MSA 指令。
   - 代码中还包括处理分支延迟槽 (branch delay slot) 的逻辑。在 MIPS 架构中，紧跟在分支指令后面的指令无论分支是否发生都会被执行。

**与 JavaScript 的关系 (举例说明):**

V8 引擎负责执行 JavaScript 代码。为了在不同的硬件平台上运行，V8 需要能够模拟目标平台的指令集，尤其是在没有实际硬件的情况下进行测试和开发。`simulator-mips64.cc` 文件就是 V8 中用于模拟 MIPS64 指令集的代码。

当 JavaScript 代码执行一些需要高性能计算的操作时，V8 的编译器 (例如 TurboFan) 可能会将这些操作编译成 MIPS64 的 MSA 指令，以便利用 SIMD 的并行处理能力。

**JavaScript 示例 (假设 JavaScript 引擎将其编译为 MSA 指令):**

```javascript
// 假设有一个 JavaScript 数组，我们想并行地将每个元素乘以 2
const arr = [1, 2, 3, 4, 5, 6, 7, 8];
const result = arr.map(x => x * 2);
console.log(result); // 输出: [2, 4, 6, 8, 10, 12, 14, 16]

// 或者对于浮点数操作
const floatArr = [1.5, 2.5, 3.5, 4.5];
const sqrtResult = floatArr.map(Math.sqrt);
console.log(sqrtResult);
```

在 V8 模拟器中，当执行到对应于 `arr.map(x => x * 2)` 或 `floatArr.map(Math.sqrt)`  的编译后的 MIPS64 代码时，如果使用了 MSA 指令，`DecodeTypeMsa3RF` 或其他相应的 MSA 解码函数将会被调用，模拟 MSA 的乘法或平方根运算。

例如，如果 JavaScript 引擎将数组乘法编译成 MSA 的 `MUL_Q` 指令（定点数乘法），`DecodeTypeMsa3RF` 中的 `case MUL_Q:` 代码块会被执行，它会从模拟的 MSA 寄存器中读取数据，执行乘法操作，并将结果写回模拟的 MSA 寄存器。

类似地，对于 `Math.sqrt`，如果编译成了 MSA 的 `FSQRT` 指令，`DecodeTypeMsa2RF` 中的 `case FSQRT:` 代码块会被执行，模拟浮点数的平方根运算。

总而言之，这部分代码是 V8 引擎在非 MIPS64 平台上运行和测试 MIPS64 代码的关键组成部分，它使得开发者能够在没有实际硬件的情况下进行开发和调试，并验证 V8 生成的 MIPS64 代码的正确性。

### 提示词
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
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
      next_pc = current_pc + 2 * kInstrSize;
    }
  };

  auto BranchAndLinkCompactHelper = [this, &next_pc](bool do_branch, int bits) {
    int64_t current_pc = get_pc();
    CheckForbiddenSlot(current_pc);
    if (do_branch) {
      int32_t imm = instr_.ImmValue(bits);
      imm <<= 32 - bits;
      imm >>= 32 - bits;
      next_pc = current_pc + (imm << 2) + kInstrSize;
      set_register(31, current_pc + kInstrSize);
    }
  };

  auto BranchCompactHelper = [this, &next_pc](bool do_branch, int bits) {
    int64_t current_pc = get_pc();
    CheckForbiddenSlot(current_pc);
    if (do_branch) {
      int32_t imm = instr_.ImmValue(bits);
      imm <<= 32 - bits;
      imm >>= 32 - bits;
      next_pc = get_pc() + (imm << 2) + kInstrSize;
    }
  };

  switch (op) {
    // ------------- COP1. Coprocessor instructions.
    case COP1:
      switch (instr_.RsFieldRaw()) {
        case BC1: {  // Branch on coprocessor condition.
          uint32_t cc = instr_.FBccValue();
          uint32_t fcsr_cc = get_fcsr_condition_bit(cc);
          uint32_t cc_value = test_fcsr_bit(fcsr_cc);
          bool do_branch = (instr_.FBtrueValue()) ? cc_value : !cc_value;
          BranchHelper(do_branch);
          break;
        }
        case BC1EQZ:
          BranchHelper(!(get_fpu_register(ft_reg) & 0x1));
          break;
        case BC1NEZ:
          BranchHelper(get_fpu_register(ft_reg) & 0x1);
          break;
        case BZ_V: {
          msa_reg_t wt;
          get_msa_register(wt_reg(), &wt);
          BranchHelper_MSA(wt.d[0] == 0 && wt.d[1] == 0);
        } break;
#define BZ_DF(witdh, lanes)          \
  {                                  \
    msa_reg_t wt;                    \
    get_msa_register(wt_reg(), &wt); \
    int i;                           \
    for (i = 0; i < lanes; ++i) {    \
      if (wt.witdh[i] == 0) {        \
        break;                       \
      }                              \
    }                                \
    BranchHelper_MSA(i != lanes);    \
  }
        case BZ_B:
          BZ_DF(b, kMSALanesByte)
          break;
        case BZ_H:
          BZ_DF(h, kMSALanesHalf)
          break;
        case BZ_W:
          BZ_DF(w, kMSALanesWord)
          break;
        case BZ_D:
          BZ_DF(d, kMSALanesDword)
          break;
#undef BZ_DF
        case BNZ_V: {
          msa_reg_t wt;
          get_msa_register(wt_reg(), &wt);
          BranchHelper_MSA(wt.d[0] != 0 || wt.d[1] != 0);
        } break;
#define BNZ_DF(witdh, lanes)         \
  {                                  \
    msa_reg_t wt;                    \
    get_msa_register(wt_reg(), &wt); \
    int i;                           \
    for (i = 0; i < lanes; ++i) {    \
      if (wt.witdh[i] == 0) {        \
        break;                       \
      }                              \
    }                                \
    BranchHelper_MSA(i == lanes);    \
  }
        case BNZ_B:
          BNZ_DF(b, kMSALanesByte)
          break;
        case BNZ_H:
          BNZ_DF(h, kMSALanesHalf)
          break;
        case BNZ_W:
          BNZ_DF(w, kMSALanesWord)
          break;
        case BNZ_D:
          BNZ_DF(d, kMSALanesDword)
          break;
#undef BNZ_DF
        default:
          UNREACHABLE();
      }
      break;
    // ------------- REGIMM class.
    case REGIMM:
      switch (instr_.RtFieldRaw()) {
        case BLTZ:
          BranchHelper(rs < 0);
          break;
        case BGEZ:
          BranchHelper(rs >= 0);
          break;
        case BLTZAL:
          BranchAndLinkHelper(rs < 0);
          break;
        case BGEZAL:
          BranchAndLinkHelper(rs >= 0);
          break;
        case DAHI:
          SetResult(rs_reg, rs + (se_imm16 << 32));
          break;
        case DATI:
          SetResult(rs_reg, rs + (se_imm16 << 48));
          break;
        default:
          UNREACHABLE();
      }
      break;  // case REGIMM.
    // ------------- Branch instructions.
    // When comparing to zero, the encoding of rt field is always 0, so we don't
    // need to replace rt with zero.
    case BEQ:
      BranchHelper(rs == rt);
      break;
    case BNE:
      BranchHelper(rs != rt);
      break;
    case POP06:  // BLEZALC, BGEZALC, BGEUC, BLEZ (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BLEZALC
            BranchAndLinkCompactHelper(rt <= 0, 16);
          } else {
            if (rs_reg == rt_reg) {  // BGEZALC
              BranchAndLinkCompactHelper(rt >= 0, 16);
            } else {  // BGEUC
              BranchCompactHelper(
                  static_cast<uint64_t>(rs) >= static_cast<uint64_t>(rt), 16);
            }
          }
        } else {  // BLEZ
          BranchHelper(rs <= 0);
        }
      } else {  // BLEZ
        BranchHelper(rs <= 0);
      }
      break;
    case POP07:  // BGTZALC, BLTZALC, BLTUC, BGTZ (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BGTZALC
            BranchAndLinkCompactHelper(rt > 0, 16);
          } else {
            if (rt_reg == rs_reg) {  // BLTZALC
              BranchAndLinkCompactHelper(rt < 0, 16);
            } else {  // BLTUC
              BranchCompactHelper(
                  static_cast<uint64_t>(rs) < static_cast<uint64_t>(rt), 16);
            }
          }
        } else {  // BGTZ
          BranchHelper(rs > 0);
        }
      } else {  // BGTZ
        BranchHelper(rs > 0);
      }
      break;
    case POP26:  // BLEZC, BGEZC, BGEC/BLEC / BLEZL (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BLEZC
            BranchCompactHelper(rt <= 0, 16);
          } else {
            if (rs_reg == rt_reg) {  // BGEZC
              BranchCompactHelper(rt >= 0, 16);
            } else {  // BGEC/BLEC
              BranchCompactHelper(rs >= rt, 16);
            }
          }
        }
      } else {  // BLEZL
        BranchAndLinkHelper(rs <= 0);
      }
      break;
    case POP27:  // BGTZC, BLTZC, BLTC/BGTC / BGTZL (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rt_reg != 0) {
          if (rs_reg == 0) {  // BGTZC
            BranchCompactHelper(rt > 0, 16);
          } else {
            if (rs_reg == rt_reg) {  // BLTZC
              BranchCompactHelper(rt < 0, 16);
            } else {  // BLTC/BGTC
              BranchCompactHelper(rs < rt, 16);
            }
          }
        }
      } else {  // BGTZL
        BranchAndLinkHelper(rs > 0);
      }
      break;
    case POP66:           // BEQZC, JIC
      if (rs_reg != 0) {  // BEQZC
        BranchCompactHelper(rs == 0, 21);
      } else {  // JIC
        next_pc = rt + imm16;
      }
      break;
    case POP76:           // BNEZC, JIALC
      if (rs_reg != 0) {  // BNEZC
        BranchCompactHelper(rs != 0, 21);
      } else {  // JIALC
        int64_t current_pc = get_pc();
        set_register(31, current_pc + kInstrSize);
        next_pc = rt + imm16;
      }
      break;
    case BC:
      BranchCompactHelper(true, 26);
      break;
    case BALC:
      BranchAndLinkCompactHelper(true, 26);
      break;
    case POP10:  // BOVC, BEQZALC, BEQC / ADDI (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rs_reg >= rt_reg) {  // BOVC
          bool condition = !is_int32(rs) || !is_int32(rt) || !is_int32(rs + rt);
          BranchCompactHelper(condition, 16);
        } else {
          if (rs_reg == 0) {  // BEQZALC
            BranchAndLinkCompactHelper(rt == 0, 16);
          } else {  // BEQC
            BranchCompactHelper(rt == rs, 16);
          }
        }
      } else {  // ADDI
        if (HaveSameSign(rs, se_imm16)) {
          if (rs > 0) {
            if (rs <= Registers::kMaxValue - se_imm16) {
              SignalException(kIntegerOverflow);
            }
          } else if (rs < 0) {
            if (rs >= Registers::kMinValue - se_imm16) {
              SignalException(kIntegerUnderflow);
            }
          }
        }
        SetResult(rt_reg, rs + se_imm16);
      }
      break;
    case POP30:  // BNVC, BNEZALC, BNEC / DADDI (pre-r6)
      if (kArchVariant == kMips64r6) {
        if (rs_reg >= rt_reg) {  // BNVC
          bool condition = is_int32(rs) && is_int32(rt) && is_int32(rs + rt);
          BranchCompactHelper(condition, 16);
        } else {
          if (rs_reg == 0) {  // BNEZALC
            BranchAndLinkCompactHelper(rt != 0, 16);
          } else {  // BNEC
            BranchCompactHelper(rt != rs, 16);
          }
        }
      }
      break;
    // ------------- Arithmetic instructions.
    case ADDIU: {
      int32_t alu32_out = static_cast<int32_t>(rs + se_imm16);
      // Sign-extend result of 32bit operation into 64bit register.
      SetResult(rt_reg, static_cast<int64_t>(alu32_out));
      break;
    }
    case DADDIU:
      SetResult(rt_reg, rs + se_imm16);
      break;
    case SLTI:
      SetResult(rt_reg, rs < se_imm16 ? 1 : 0);
      break;
    case SLTIU:
      SetResult(rt_reg, rs_u < static_cast<uint64_t>(se_imm16) ? 1 : 0);
      break;
    case ANDI:
      SetResult(rt_reg, rs & oe_imm16);
      break;
    case ORI:
      SetResult(rt_reg, rs | oe_imm16);
      break;
    case XORI:
      SetResult(rt_reg, rs ^ oe_imm16);
      break;
    case LUI:
      if (rs_reg != 0) {
        // AUI instruction.
        DCHECK_EQ(kArchVariant, kMips64r6);
        int32_t alu32_out = static_cast<int32_t>(rs + (se_imm16 << 16));
        SetResult(rt_reg, static_cast<int64_t>(alu32_out));
      } else {
        // LUI instruction.
        int32_t alu32_out = static_cast<int32_t>(oe_imm16 << 16);
        // Sign-extend result of 32bit operation into 64bit register.
        SetResult(rt_reg, static_cast<int64_t>(alu32_out));
      }
      break;
    case DAUI:
      DCHECK_EQ(kArchVariant, kMips64r6);
      DCHECK_NE(rs_reg, 0);
      SetResult(rt_reg, rs + (se_imm16 << 16));
      break;
    // ------------- Memory instructions.
    case LB:
      set_register(rt_reg, ReadB(rs + se_imm16));
      break;
    case LH:
      set_register(rt_reg, ReadH(rs + se_imm16, instr_.instr()));
      break;
    case LWL: {
      local_monitor_.NotifyLoad();
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint8_t byte_shift = kInt32AlignmentMask - al_offset;
      uint32_t mask = (1 << byte_shift * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      int32_t val = ReadW(addr, instr_.instr());
      val <<= byte_shift * 8;
      val |= rt & mask;
      set_register(rt_reg, static_cast<int64_t>(val));
      break;
    }
    case LW:
      set_register(rt_reg, ReadW(rs + se_imm16, instr_.instr()));
      break;
    case LWU:
      set_register(rt_reg, ReadWU(rs + se_imm16, instr_.instr()));
      break;
    case LD:
      set_register(rt_reg, Read2W(rs + se_imm16, instr_.instr()));
      break;
    case LBU:
      set_register(rt_reg, ReadBU(rs + se_imm16));
      break;
    case LHU:
      set_register(rt_reg, ReadHU(rs + se_imm16, instr_.instr()));
      break;
    case LWR: {
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint8_t byte_shift = kInt32AlignmentMask - al_offset;
      uint32_t mask = al_offset ? (~0 << (byte_shift + 1) * 8) : 0;
      addr = rs + se_imm16 - al_offset;
      alu_out = ReadW(addr, instr_.instr());
      alu_out = static_cast<uint32_t>(alu_out) >> al_offset * 8;
      alu_out |= rt & mask;
      set_register(rt_reg, alu_out);
      break;
    }
    case LDL: {
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint8_t byte_shift = kInt64AlignmentMask - al_offset;
      uint64_t mask = (1UL << byte_shift * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      alu_out = Read2W(addr, instr_.instr());
      alu_out <<= byte_shift * 8;
      alu_out |= rt & mask;
      set_register(rt_reg, alu_out);
      break;
    }
    case LDR: {
      // al_offset is offset of the effective address within an aligned word.
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint8_t byte_shift = kInt64AlignmentMask - al_offset;
      uint64_t mask = al_offset ? (~0UL << (byte_shift + 1) * 8) : 0UL;
      addr = rs + se_imm16 - al_offset;
      alu_out = Read2W(addr, instr_.instr());
      alu_out = alu_out >> al_offset * 8;
      alu_out |= rt & mask;
      set_register(rt_reg, alu_out);
      break;
    }
    case SB:
      WriteB(rs + se_imm16, static_cast<int8_t>(rt));
      break;
    case SH:
      WriteH(rs + se_imm16, static_cast<uint16_t>(rt), instr_.instr());
      break;
    case SWL: {
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint8_t byte_shift = kInt32AlignmentMask - al_offset;
      uint32_t mask = byte_shift ? (~0 << (al_offset + 1) * 8) : 0;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = ReadW(addr, instr_.instr()) & mask;
      mem_value |= static_cast<uint32_t>(rt) >> byte_shift * 8;
      WriteW(addr, static_cast<int32_t>(mem_value), instr_.instr());
      break;
    }
    case SW:
      WriteW(rs + se_imm16, static_cast<int32_t>(rt), instr_.instr());
      break;
    case SD:
      Write2W(rs + se_imm16, rt, instr_.instr());
      break;
    case SWR: {
      uint8_t al_offset = (rs + se_imm16) & kInt32AlignmentMask;
      uint32_t mask = (1 << al_offset * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = ReadW(addr, instr_.instr());
      mem_value = (rt << al_offset * 8) | (mem_value & mask);
      WriteW(addr, static_cast<int32_t>(mem_value), instr_.instr());
      break;
    }
    case SDL: {
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint8_t byte_shift = kInt64AlignmentMask - al_offset;
      uint64_t mask = byte_shift ? (~0UL << (al_offset + 1) * 8) : 0;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = Read2W(addr, instr_.instr()) & mask;
      mem_value |= static_cast<uint64_t>(rt) >> byte_shift * 8;
      Write2W(addr, mem_value, instr_.instr());
      break;
    }
    case SDR: {
      uint8_t al_offset = (rs + se_imm16) & kInt64AlignmentMask;
      uint64_t mask = (1UL << al_offset * 8) - 1;
      addr = rs + se_imm16 - al_offset;
      uint64_t mem_value = Read2W(addr, instr_.instr());
      mem_value = (rt << al_offset * 8) | (mem_value & mask);
      Write2W(addr, mem_value, instr_.instr());
      break;
    }
    case LL: {
      DCHECK(kArchVariant != kMips64r6);
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      addr = rs + se_imm16;
      set_register(rt_reg, ReadW(addr, instr_.instr()));
      local_monitor_.NotifyLoadLinked(addr, TransactionSize::Word);
      GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                    &global_monitor_thread_);
      break;
    }
    case SC: {
      DCHECK(kArchVariant != kMips64r6);
      addr = rs + se_imm16;
      WriteConditionalW(addr, static_cast<int32_t>(rt), instr_.instr(), rt_reg);
      break;
    }
    case LLD: {
      DCHECK(kArchVariant != kMips64r6);
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      addr = rs + se_imm16;
      set_register(rt_reg, Read2W(addr, instr_.instr()));
      local_monitor_.NotifyLoadLinked(addr, TransactionSize::DoubleWord);
      GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                    &global_monitor_thread_);
      break;
    }
    case SCD: {
      DCHECK(kArchVariant != kMips64r6);
      addr = rs + se_imm16;
      WriteConditional2W(addr, rt, instr_.instr(), rt_reg);
      break;
    }
    case LWC1:
      set_fpu_register(ft_reg, kFPUInvalidResult);  // Trash upper 32 bits.
      set_fpu_register_word(ft_reg,
                            ReadW(rs + se_imm16, instr_.instr(), FLOAT_DOUBLE));
      break;
    case LDC1:
      set_fpu_register_double(ft_reg, ReadD(rs + se_imm16, instr_.instr()));
      TraceMemRd(addr, get_fpu_register(ft_reg), DOUBLE);
      break;
    case SWC1: {
      int32_t alu_out_32 = static_cast<int32_t>(get_fpu_register(ft_reg));
      WriteW(rs + se_imm16, alu_out_32, instr_.instr());
      break;
    }
    case SDC1:
      WriteD(rs + se_imm16, get_fpu_register_double(ft_reg), instr_.instr());
      TraceMemWr(rs + se_imm16, get_fpu_register(ft_reg), DWORD);
      break;
    // ------------- PC-Relative instructions.
    case PCREL: {
      // rt field: checking 5-bits.
      int32_t imm21 = instr_.Imm21Value();
      int64_t current_pc = get_pc();
      uint8_t rt = (imm21 >> kImm16Bits);
      switch (rt) {
        case ALUIPC:
          addr = current_pc + (se_imm16 << 16);
          alu_out = static_cast<int64_t>(~0x0FFFF) & addr;
          break;
        case AUIPC:
          alu_out = current_pc + (se_imm16 << 16);
          break;
        default: {
          int32_t imm19 = instr_.Imm19Value();
          // rt field: checking the most significant 3-bits.
          rt = (imm21 >> kImm18Bits);
          switch (rt) {
            case LDPC:
              addr =
                  (current_pc & static_cast<int64_t>(~0x7)) + (se_imm18 << 3);
              alu_out = Read2W(addr, instr_.instr());
              break;
            default: {
              // rt field: checking the most significant 2-bits.
              rt = (imm21 >> kImm19Bits);
              switch (rt) {
                case LWUPC: {
                  // Set sign.
                  imm19 <<= (kOpcodeBits + kRsBits + 2);
                  imm19 >>= (kOpcodeBits + kRsBits + 2);
                  addr = current_pc + (imm19 << 2);
                  alu_out = ReadWU(addr, instr_.instr());
                  break;
                }
                case LWPC: {
                  // Set sign.
                  imm19 <<= (kOpcodeBits + kRsBits + 2);
                  imm19 >>= (kOpcodeBits + kRsBits + 2);
                  addr = current_pc + (imm19 << 2);
                  alu_out = ReadW(addr, instr_.instr());
                  break;
                }
                case ADDIUPC: {
                  int64_t se_imm19 =
                      imm19 | ((imm19 & 0x40000) ? 0xFFFFFFFFFFF80000 : 0);
                  alu_out = current_pc + (se_imm19 << 2);
                  break;
                }
                default:
                  UNREACHABLE();
              }
              break;
            }
          }
          break;
        }
      }
      SetResult(rs_reg, alu_out);
      break;
    }
    case SPECIAL3: {
      switch (instr_.FunctionFieldRaw()) {
        case LL_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & 0x3, 0);
          set_register(rt_reg, ReadW(addr, instr_.instr()));
          local_monitor_.NotifyLoadLinked(addr, TransactionSize::Word);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              addr, &global_monitor_thread_);
          break;
        }
        case LLD_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & kPointerAlignmentMask, 0);
          set_register(rt_reg, Read2W(addr, instr_.instr()));
          local_monitor_.NotifyLoadLinked(addr, TransactionSize::DoubleWord);
          GlobalMonitor::Get()->NotifyLoadLinked_Locked(
              addr, &global_monitor_thread_);
          break;
        }
        case SC_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & 0x3, 0);
          WriteConditionalW(addr, static_cast<int32_t>(rt), instr_.instr(),
                            rt_reg);
          break;
        }
        case SCD_R6: {
          DCHECK_EQ(kArchVariant, kMips64r6);
          int64_t base = get_register(instr_.BaseValue());
          int32_t offset9 = instr_.Imm9Value();
          addr = base + offset9;
          DCHECK_EQ(addr & kPointerAlignmentMask, 0);
          WriteConditional2W(addr, rt, instr_.instr(), rt_reg);
          break;
        }
        default:
          UNREACHABLE();
      }
      break;
    }

    case MSA:
      switch (instr_.MSAMinorOpcodeField()) {
        case kMsaMinorI8:
          DecodeTypeMsaI8();
          break;
        case kMsaMinorI5:
          DecodeTypeMsaI5();
          break;
        case kMsaMinorI10:
          DecodeTypeMsaI10();
          break;
        case kMsaMinorELM:
          DecodeTypeMsaELM();
          break;
        case kMsaMinorBIT:
          DecodeTypeMsaBIT();
          break;
        case kMsaMinorMI10:
          DecodeTypeMsaMI10();
          break;
        default:
          UNREACHABLE();
      }
      break;
    default:
      UNREACHABLE();
  }

  if (execute_branch_delay_instruction) {
    // Execute branch delay slot
    // We don't check for end_sim_pc. First it should not be met as the current
    // pc is valid. Secondly a jump should always execute its branch delay slot.
    Instruction* branch_delay_instr =
        reinterpret_cast<Instruction*>(get_pc() + kInstrSize);
    BranchDelayInstructionDecode(branch_delay_instr);
  }

  // If needed update pc after the branch delay execution.
  if (next_pc != bad_ra) {
    set_pc(next_pc);
  }
}

// Type 3: instructions using a 26 bytes immediate. (e.g. j, jal).
void Simulator::DecodeTypeJump() {
  // instr_ will be overwritten by BranchDelayInstructionDecode(), so we save
  // the result of IsLinkingInstruction now.
  bool isLinkingInstr = instr_.IsLinkingInstruction();
  // Get current pc.
  int64_t current_pc = get_pc();
  // Get unchanged bits of pc.
  int64_t pc_high_bits = current_pc & 0xFFFFFFFFF0000000;
  // Next pc.
  int64_t next_pc = pc_high_bits | (instr_.Imm26Value() << 2);

  // Execute branch delay slot.
  // We don't check for end_sim_pc. First it should not be met as the current pc
  // is valid. Secondly a jump should always execute its branch delay slot.
  Instruction* branch_delay_instr =
      reinterpret_cast<Instruction*>(current_pc + kInstrSize);
  BranchDelayInstructionDecode(branch_delay_instr);

  // Update pc and ra if necessary.
  // Do this after the branch delay execution.
  if (isLinkingInstr) {
    set_register(31, current_pc + 2 * kInstrSize);
  }
  set_pc(next_pc);
  pc_modified_ = true;
}

// Executes the current instruction.
void Simulator::InstructionDecode(Instruction* instr) {
  if (v8_flags.check_icache) {
    CheckICache(i_cache(), instr);
  }
  pc_modified_ = false;

  v8::base::EmbeddedVector<char, 256> buffer;

  if (v8_flags.trace_sim) {
    base::SNPrintF(trace_buf_, " ");
    disasm::NameConverter converter;
    disasm::Disassembler dasm(converter);
    // Use a reasonably large buffer.
    dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(instr));
  }

  instr_ = instr;
  switch (instr_.InstructionType()) {
    case Instruction::kRegisterType:
      DecodeTypeRegister();
      break;
    case Instruction::kImmediateType:
      DecodeTypeImmediate();
      break;
    case Instruction::kJumpType:
      DecodeTypeJump();
      break;
    default:
      UNSUPPORTED();
  }

  if (v8_flags.trace_sim) {
    PrintF("  0x%08" PRIxPTR "   %-44s   %s\n",
           reinterpret_cast<intptr_t>(instr), buffer.begin(),
           trace_buf_.begin());
  }

  if (!pc_modified_) {
    set_register(pc, reinterpret_cast<int64_t>(instr) + kInstrSize);
  }
}

void Simulator::Execute() {
  // Get the PC to simulate. Cannot use the accessor here as we need the
  // raw PC value and not the one used as input to arithmetic instructions.
  int64_t program_counter = get_pc();
  if (v8_flags.stop_sim_at == 0) {
    // Fast version of the dispatch loop without checking whether the simulator
    // should be stopping at a particular executed instruction.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_++;
      InstructionDecode(instr);
      program_counter = get_pc();
    }
  } else {
    // v8_flags.stop_sim_at is at the non-default value. Stop in the debugger
    // when we reach the particular instruction count.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      icount_++;
      if (icount_ == static_cast<int64_t>(v8_flags.stop_sim_at)) {
        MipsDebugger dbg(this);
        dbg.Debug();
      } else {
        InstructionDecode(instr);
      }
      program_counter = get_pc();
    }
  }
}

void Simulator::CallInternal(Address entry) {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

  // Prepare to execute the code at entry.
  set_register(pc, static_cast<int64_t>(entry));
  // Put down marker for end of simulation. The simulator will stop simulation
  // when the PC reaches this value. By saving the "end simulation" value into
  // the LR the simulation stops when returning to this call point.
  set_register(ra, end_sim_pc);

  // Remember the values of callee-saved registers.
  // The code below assumes that r9 is not used as sb (static base) in
  // simulator code and therefore is regarded as a callee-saved register.
  int64_t s0_val = get_register(s0);
  int64_t s1_val = get_register(s1);
  int64_t s2_val = get_register(s2);
  int64_t s3_val = get_register(s3);
  int64_t s4_val = get_register(s4);
  int64_t s5_val = get_register(s5);
  int64_t s6_val = get_register(s6);
  int64_t s7_val = get_register(s7);
  int64_t gp_val = get_register(gp);
  int64_t sp_val = get_register(sp);
  int64_t fp_val = get_register(fp);

  // Set up the callee-saved registers with a known value. To be able to check
  // that they are preserved properly across JS execution.
  int64_t callee_saved_value = icount_;
  set_register(s0, callee_saved_value);
  set_register(s1, callee_saved_value);
  set_register(s2, callee_saved_value);
  set_register(s3, callee_saved_value);
  set_register(s4, callee_saved_value);
  set_register(s5, callee_saved_value);
  set_register(s6, callee_saved_value);
  set_register(s7, callee_saved_value);
  set_register(gp, callee_saved_value);
  set_register(fp, callee_saved_value);

  // Start the simulation.
  Execute();

  // Check that the callee-saved registers have been preserved.
  CHECK_EQ(callee_saved_value, get_register(s0));
  CHECK_EQ(callee_saved_value, get_register(s1));
  CHECK_EQ(callee_saved_value, get_register(s2));
  CHECK_EQ(callee_saved_value, get_register(s3));
  CHECK_EQ(callee_saved_value, get_register(s4));
  CHECK_EQ(callee_saved_value, get_register(s5));
  CHECK_EQ(callee_saved_value, get_register(s6));
  CHECK_EQ(callee_saved_value, get_register(s7));
  CHECK_EQ(callee_saved_value, get_register(gp));
  CHECK_EQ(callee_saved_value, get_register(fp));

  // Restore callee-saved registers with the original value.
  set_register(s0, s0_val);
  set_register(s1, s1_val);
  set_register(s2, s2_val);
  set_register(s3, s3_val);
  set_register(s4, s4_val);
  set_register(s5, s5_val);
  set_register(s6, s6_val);
  set_register(s7, s7_val);
  set_register(gp, gp_val);
  set_register(sp, sp_val);
  set_register(fp, fp_val);
}

void Simulator::CallImpl(Address entry, CallArgument* args) {
  std::vector<int64_t> stack_args(0);
  for (int i = 0; !args[i].IsEnd(); i++) {
    CallArgument arg = args[i];
    if (i < 8) {
      if (arg.IsGP()) {
        set_register(i + 4, arg.bits());
      } else {
        DCHECK(arg.IsFP());
        set_fpu_register(i + 12, arg.bits());
      }
    } else {
      DCHECK(arg.IsFP() || arg.IsGP());
      stack_args.push_back(arg.bits());
    }
  }

  // Remaining arguments passed on stack.
  int64_t original_stack = get_register(sp);
  // Compute position of stack on entry to generated code.
  int64_t stack_args_size =
      stack_args.size() * sizeof(stack_args[0]) + kCArgsSlotsSize;
  int64_t entry_stack = original_stack - stack_args_size;

  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }
  // Store remaining arguments on stack, from low to high memory.
  char* stack_argument = reinterpret_cast<char*>(entry_stack);
  memcpy(stack_argument + kCArgSlotCount, stack_args.data(),
         stack_args.size() * sizeof(int64_t));
  set_register(sp, entry_stack);

  CallInternal(entry);

  // Pop stack passed arguments.
  CHECK_EQ(entry_stack, get_register(sp));
  set_register(sp, original_stack);
}

double Simulator::CallFP(Address entry, double d0, double d1) {
  if (!IsMipsSoftFloatABI) {
    const FPURegister fparg2 = f13;
    set_fpu_register_double(f12, d0);
    set_fpu_register_double(fparg2, d1);
  } else {
    int buffer[2];
    DCHECK(sizeof(buffer[0]) * 2 == sizeof(d0));
    memcpy(buffer, &d0, sizeof(d0));
    set_dw_register(a0, buffer);
    memcpy(buffer, &d1, sizeof(d1));
    set_dw_register(a2, buffer);
  }
  CallInternal(entry);
  if (!IsMipsSoftFloatABI) {
    return get_fpu_register_double(f0);
  } else {
    return get_double_from_register_pair(v0);
  }
}

uintptr_t Simulator::PushAddress(uintptr_t address) {
  int64_t new_sp = get_register(sp) - sizeof(uintptr_t);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(new_sp);
  *stack_slot = address;
  set_register(sp, new_sp);
  return new_sp;
}

uintptr_t Simulator::PopAddress() {
  int64_t current_sp = get_register(sp);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(current_sp);
  uintptr_t address = *stack_slot;
  set_register(sp, current_sp + sizeof(uintptr_t));
  return address;
}

Simulator::LocalMonitor::LocalMonitor()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      size_(TransactionSize::None) {}

void Simulator::LocalMonitor::Clear() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
  size_ = TransactionSize::None;
}

void Simulator::LocalMonitor::NotifyLoad() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non linked load could clear the local monitor. As a result, it's
    // most strict to unconditionally clear the local monitor on load.
    Clear();
  }
}

void Simulator::LocalMonitor::NotifyLoadLinked(uintptr_t addr,
                                               TransactionSize size) {
  access_state_ = MonitorAccess::RMW;
  tagged_addr_ = addr;
  size_ = size;
}

void Simulator::LocalMonitor::NotifyStore() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non exclusive store could clear the local monitor. As a result, it's
    // most strict to unconditionally clear the local monitor on store.
    Clear();
  }
}

bool Simulator::LocalMonitor::NotifyStoreConditional(uintptr_t addr,
                                                     TransactionSize size) {
  if (access_state_ == MonitorAccess::RMW) {
    if (addr == tagged_addr_ && size_ == size) {
      Clear();
      return true;
    } else {
      return false;
    }
  } else {
    DCHECK(access_state_ == MonitorAccess::Open);
    return false;
  }
}

Simulator::GlobalMonitor::LinkedAddress::LinkedAddress()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      next_(nullptr),
      prev_(nullptr),
      failure_counter_(0) {}

void Simulator::GlobalMonitor::LinkedAddress::Clear_Locked() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
}

void Simulator::GlobalMonitor::LinkedAddress::NotifyLoadLinked_Locked(
    uintptr_t addr) {
  access_state_ = MonitorAccess::RMW;
  tagged_addr_ = addr;
}

void Simulator::GlobalMonitor::LinkedAddress::NotifyStore_Locked() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non exclusive store could clear the global monitor. As a result, it's
    // most strict to unconditionally clear global monitors on store.
    Clear_Locked();
  }
}

bool Simulator::GlobalMonitor::LinkedAddress::NotifyStoreConditional_Locked(
    uintptr_t addr, bool is_requesting_thread) {
  if (access_state_ == MonitorAccess::RMW) {
    if (is_requesting_thread) {
      if (addr == tagged_addr_) {
        Clear_Locked();
        // Introduce occasional sc/scd failures. This is to simulate the
        // behavior of hardware, which can randomly fail due to background
        // cache evictions.
        if (failure_counter_++ >= kMaxFailureCounter) {
```