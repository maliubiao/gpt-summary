Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the 6th part of a 10-part code.

Here's a plan to generate the answer:

1. **Identify the main purpose of the code:** The code seems to be implementing an instruction simulator for the s390 architecture within the V8 JavaScript engine. It defines functions to execute various s390 instructions.

2. **Analyze the code structure:** The code is organized as a series of `EVALUATE` macros, each handling a specific s390 instruction. These macros decode the instruction and then perform the corresponding operation on the simulated CPU state (registers, memory, condition codes).

3. **Categorize the instructions:** Group the instructions by their function (e.g., arithmetic, logical, memory access, control flow, floating-point).

4. **Check for Torque usage:** The code does not end with `.tq`, so it's not a Torque file.

5. **Identify JavaScript relationships:**  While this code directly simulates the architecture, it's related to JavaScript because V8 uses this simulator for running JavaScript code on s390 platforms. I'll need to provide a generic example of how JavaScript relies on the underlying architecture.

6. **Look for code logic and examples:** The `EVALUATE` blocks themselves represent logic. I can pick a simple instruction and demonstrate its effect with example inputs and outputs for the simulated registers.

7. **Identify common programming errors:**  The code includes checks for overflow conditions. I can discuss common integer overflow errors in general programming.

8. **Summarize the overall functionality:** Combine the identified functionalities into a concise summary for this part of the code.
这是文件 `v8/src/execution/s390/simulator-s390.cc` 的第 6 部分，主要功能是 **模拟 S390 架构的各种指令的执行**。

以下是更详细的功能列表：

1. **SIMD 浮点比较指令 (VFCE, VFCHE, VFCH):**  实现了向量浮点比较指令，可以比较两个 SIMD 寄存器的内容，并将比较结果（通常是 -1 或 0）存储到目标寄存器中。还可以根据比较结果设置条件码。
2. **SIMD 浮点一元操作指令 (VFPSO, VFSQ, VFI):**
    - `VFPSO`:  实现向量浮点符号操作，例如取负、取绝对值并取负、取绝对值。
    - `VFSQ`:  实现向量浮点平方根运算。
    - `VFI`:  实现向量浮点舍入运算，根据不同的模式进行舍入。
3. **空指令 (DUMY):**  一个不执行任何操作的占位指令。
4. **比较逻辑寄存器指令 (CLR):**  比较两个通用寄存器的低 32 位，并设置条件码。
5. **加载指令 (LR, L):**
    - `LR`: 将一个通用寄存器的低 32 位的值加载到另一个通用寄存器的低 32 位。
    - `L`: 从内存中加载一个字（32 位）到通用寄存器的低 32 位。
6. **加法指令 (AR):**  将两个通用寄存器的低 32 位相加，结果存储到第一个寄存器，并设置条件码和溢出标志。
7. **条件分支指令 (BRC):**  根据条件码的值，跳转到指定的相对地址。
8. **立即数运算指令 (AHI, AGHI):**
    - `AHI`: 将一个立即数加到一个通用寄存器的低 32 位，并设置条件码和溢出标志。
    - `AGHI`: 将一个立即数加到一个通用寄存器（64 位），并设置条件码和溢出标志。
9. **长条件分支指令 (BRCL):**  类似于 `BRC`，但使用更长的立即数偏移量。
10. **立即数加载指令 (IIHF, IILF):**
    - `IIHF`: 将一个立即数加载到通用寄存器的高 32 位。
    - `IILF`: 将一个立即数加载到通用寄存器的低 32 位。
11. **加载指令 (LGR, LG, LGF):**
    - `LGR`: 将一个通用寄存器的值（64 位）加载到另一个通用寄存器。
    - `LG`: 从内存中加载一个双字（64 位）到通用寄存器。
    - `LGF`: 从内存中加载一个字（32 位）并符号扩展到 64 位后存储到通用寄存器。
12. **加法指令 (AGR):** 将两个通用寄存器的值（64 位）相加，结果存储到第一个寄存器，并设置条件码和溢出标志。
13. **类型转换加载指令 (LGFR):** 将一个通用寄存器的低 32 位的值符号扩展到 64 位后加载到另一个通用寄存器。
14. **符号扩展加载指令 (LBR, LGBR, LHR, LGHR):**
    - `LBR`: 从通用寄存器的低 32 位中加载最低字节并符号扩展到 32 位。
    - `LGBR`: 从通用寄存器的低 64 位中加载最低字节并符号扩展到 64 位。
    - `LHR`: 从通用寄存器的低 32 位中加载低 16 位并符号扩展到 32 位。
    - `LGHR`: 从通用寄存器的低 64 位中加载低 16 位并符号扩展到 64 位。
15. **存储指令 (ST, STG, STY):**
    - `ST`: 将一个通用寄存器的低 32 位存储到内存中。
    - `STG`: 将一个通用寄存器的值（64 位）存储到内存中。
    - `STY`: 将一个通用寄存器的低 32 位存储到内存中。
16. **无符号加载指令 (LY):** 从内存中加载一个字（32 位）并零扩展到 32 位后存储到通用寄存器的低 32 位。
17. **加载字节指令 (LLGC, LLC):**
    - `LLGC`: 从内存加载一个字节并零扩展到 64 位后存储到通用寄存器。
    - `LLC`: 从内存加载一个字节并零扩展到 32 位后存储到通用寄存器的低 32 位。
18. **循环左移指令 (RLL):**  将一个通用寄存器的低 32 位循环左移指定的位数。
19. **位插入指令 (RISBG):**  从一个通用寄存器中选择一部分位，旋转后插入到另一个通用寄存器中。
20. **带立即数的加法指令 (AHIK, AGHIK):**
    - `AHIK`: 将一个立即数加到一个通用寄存器的低 32 位，并设置条件码和溢出标志。
    - `AGHIK`: 将一个立即数加到一个通用寄存器（64 位），并设置条件码和溢出标志。
21. **断点指令 (BKPT):**  触发一个调试断点。
22. **未实现的指令 (SPM, BALR, BCTR, SVC, BSM, BASSM, MVCL, CLCL, BAS, CVD, CVB, LAE, D, AL, SL, CD):**  这些指令的执行逻辑尚未在此部分代码中实现。
23. **无条件分支指令 (BCR, BASR):**
    - `BCR`: 根据条件码的值，跳转到指定通用寄存器中的地址。
    - `BASR`: 将下一条指令的地址保存到第一个通用寄存器中，并跳转到第二个通用寄存器中的地址。
24. **加载正数、负数、测试、取反指令 (LPR, LNR, LTR, LCR):**
    - `LPR`: 将通用寄存器的低 32 位加载到另一个寄存器，并使其为正数（如果原来是负数）。
    - `LNR`: 将通用寄存器的低 32 位加载到另一个寄存器，并使其为负数（如果原来是正数）。
    - `LTR`: 将通用寄存器的低 32 位加载到另一个寄存器，并设置条件码。
    - `LCR`: 将通用寄存器的低 32 位取反后加载到另一个寄存器，并设置条件码和溢出标志。
25. **逻辑运算指令 (NR, OR, XR, CR):**
    - `NR`:  两个通用寄存器的低 32 位进行按位与运算。
    - `OR`:  两个通用寄存器的低 32 位进行按位或运算。
    - `XR`:  两个通用寄存器的低 32 位进行按位异或运算。
    - `CR`:  比较两个通用寄存器的低 32 位，并设置条件码。
26. **减法指令 (SR):** 将一个通用寄存器的低 32 位减去另一个通用寄存器的低 32 位，结果存储到第一个寄存器，并设置条件码和溢出标志。
27. **乘法和除法指令 (MR, DR):**
    - `MR`:  将两个通用寄存器的低 32 位相乘，结果的高 32 位存储到一个寄存器，低 32 位存储到另一个寄存器。
    - `DR`:  将一个由两个通用寄存器组成的 64 位数除以另一个通用寄存器的低 32 位，商和余数分别存储到不同的寄存器。
28. **无符号加法和减法指令 (ALR, SLR):**
    - `ALR`: 将两个通用寄存器的低 32 位进行无符号加法，并设置条件码（进位）。
    - `SLR`: 将一个通用寄存器的低 32 位减去另一个通用寄存器的低 32 位（无符号），并设置条件码（借位）。
29. **浮点加载和比较指令 (LDR, CDR, LER):**
    - `LDR`: 将一个浮点寄存器的值（64 位）加载到另一个浮点寄存器。
    - `CDR`:  (未实现) 比较两个浮点寄存器的值（64 位）。
    - `LER`: 将一个浮点寄存器的值（32 位提升到 64 位）加载到另一个浮点寄存器。
30. **存储半字指令 (STH):** 将一个通用寄存器的低 16 位存储到内存中。
31. **加载地址指令 (LA):**  计算内存地址并将其存储到通用寄存器中。
32. **存储字节指令 (STC):** 将一个通用寄存器的最低字节存储到内存中。
33. **未实现的指令 (IC_z):**  指令执行逻辑尚未实现。
34. **执行指令 (EX):**  根据指定地址的指令执行，并且可以将一个通用寄存器的低 8 位与该指令合并。
35. **未实现的指令 (BAL, BCT, BC):** 指令执行逻辑尚未实现。
36. **加载半字指令 (LH):** 从内存中加载一个半字（16 位）并符号扩展到 32 位后存储到通用寄存器的低 32 位。
37. **未实现的指令 (CH):** 指令执行逻辑尚未实现。
38. **半字算术指令 (AH, SH, MH):**
    - `AH`: 将一个通用寄存器的低 32 位加上从内存中加载的半字（符号扩展），结果存储到第一个寄存器，并设置条件码和溢出标志。
    - `SH`: 将一个通用寄存器的低 32 位减去从内存中加载的半字（符号扩展），结果存储到第一个寄存器，并设置条件码和溢出标志。
    - `MH`: 将一个通用寄存器的低 32 位乘以从内存中加载的半字（符号扩展），结果存储到第一个寄存器的低 32 位。
39. **32 位寄存器-内存操作指令 (N, CL, O, X, C, A, S, M):** 这些指令执行逻辑运算、比较、算术运算，其中一个操作数来自通用寄存器，另一个操作数来自内存。
40. **浮点存储和加载指令 (STD, LD, STE, LE):**
    - `STD`: 将一个浮点寄存器的值（64 位）存储到内存中。
    - `LD`:  从内存中加载一个双精度浮点数（64 位）到浮点寄存器。
    - `STE`: 将一个浮点寄存器的值（32 位）存储到内存中。
    - `LE`:  从内存中加载一个单精度浮点数（32 位）到浮点寄存器。
41. **乘法指令 (MS):** 将一个通用寄存器的低 32 位乘以内存中的一个字，结果存储到该通用寄存器的低 32 位。
42. **带索引和限制的跳转指令 (BRXH, BRXLE, BXH):** 这些指令根据寄存器的值与比较值进行比较，并可能进行跳转。

**如果 `v8/src/execution/s390/simulator-s390.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  但目前来看，它以 `.cc` 结尾，因此是 C++ 源代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

虽然这个 C++ 代码是模拟器，不直接是 JavaScript 代码，但 V8 引擎在 s390 架构上执行 JavaScript 代码时，会使用这个模拟器来执行底层的机器指令。

例如，当你执行一段简单的 JavaScript 代码时：

```javascript
let a = 10;
let b = 5;
let sum = a + b;
console.log(sum);
```

V8 引擎会将这段代码编译成 s390 的机器指令。在某些情况下，特别是当没有硬件支持或者进行调试时，V8 会使用 `simulator-s390.cc` 中的代码来模拟 `a + b` 这个加法操作对应的 s390 加法指令（例如 `AR` 或 `A`）。

**如果有代码逻辑推理，请给出假设输入与输出:**

以 `AR` 指令为例：

**假设输入:**

- `r1` 寄存器（假设是通用寄存器 3）的低 32 位值为 `5`。
- `r2` 寄存器（假设是通用寄存器 4）的低 32 位值为 `10`。
- 溢出标志为 `false`。
- 条件码为任意值。

**代码逻辑推理:**

`AR` 指令会将 `r1` 和 `r2` 的低 32 位值相加，结果存储回 `r1`，并根据结果设置条件码和溢出标志。

**输出:**

- `r1` 寄存器（通用寄存器 3）的低 32 位值变为 `15` (5 + 10)。
- 条件码被设置为 0x02 (结果为正)。
- 溢出标志仍然为 `false`，因为没有发生溢出。

**如果涉及用户常见的编程错误，请举例说明:**

这个模拟器本身是为了模拟 CPU 指令，但它模拟的指令操作可以反映用户在编程时可能犯的错误，例如：

**整数溢出:**  像 `AR`、`AHI`、`AGR` 等指令会检查溢出。用户在 C++ 或其他语言中进行整数运算时，如果没有进行溢出检查，可能会得到意想不到的结果。

```c++
int max_int = 2147483647;
int result = max_int + 1; // 发生溢出，result 的值会变成负数
```

在模拟器中，执行对应的 `AR` 指令时，会设置溢出标志，帮助开发者理解问题的根源。

**第 6 部分的功能归纳:**

这部分代码主要集中在 **实现 S390 架构中大量的整数和浮点运算、加载、存储以及控制流指令的模拟**。它涵盖了基本的算术运算、逻辑运算、数据搬运以及条件分支等功能，是整个模拟器中核心的执行逻辑部分。这些指令的模拟为 V8 引擎在 s390 平台上运行 JavaScript 代码提供了基础。

Prompt: 
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共10部分，请归纳一下它的功能

"""
e size");
  bool some_zero = false;
  bool all_zero = true;
  FOR_EACH_LANE(i, D) {
    S src1_val = sim->get_simd_register_by_lane<S>(src1, i);
    S src2_val = sim->get_simd_register_by_lane<S>(src2, i);
    D value = op(src1_val, src2_val);
    sim->set_simd_register_by_lane<D>(dst, i, value);
    if (value) {
      all_zero = false;
    } else {
      some_zero = true;
    }
  }
  // TODO(miladfarca) implement other conditions.
  if (m6) {
    if (all_zero) {
      sim->condition_reg_ = CC_OF;
    } else if (some_zero) {
      sim->condition_reg_ = 0x04;
    }
  }
}

#define VECTOR_FP_COMPARE_FOR_TYPE(S, D, op)  \
  VectorFPCompare<S, D>(this, r1, r2, r3, m6, \
                        [](S a, S b) { return (a op b) ? -1 : 0; });

#define VECTOR_FP_COMPARE(op)                                               \
  switch (m4) {                                                             \
    case 2:                                                                 \
      DCHECK(CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1));          \
      if (m5 == 8) {                                                        \
        float src1 = get_simd_register_by_lane<float>(r2, 0);               \
        float src2 = get_simd_register_by_lane<float>(r3, 0);               \
        set_simd_register_by_lane<int32_t>(r1, 0, (src1 op src2) ? -1 : 0); \
      } else {                                                              \
        DCHECK_EQ(m5, 0);                                                   \
        VECTOR_FP_COMPARE_FOR_TYPE(float, int32_t, op)                      \
      }                                                                     \
      break;                                                                \
    case 3:                                                                 \
      if (m5 == 8) {                                                        \
        double src1 = get_simd_register_by_lane<double>(r2, 0);             \
        double src2 = get_simd_register_by_lane<double>(r3, 0);             \
        set_simd_register_by_lane<int64_t>(r1, 0, (src1 op src2) ? -1 : 0); \
      } else {                                                              \
        DCHECK_EQ(m5, 0);                                                   \
        VECTOR_FP_COMPARE_FOR_TYPE(double, int64_t, op)                     \
      }                                                                     \
      break;                                                                \
    default:                                                                \
      UNREACHABLE();                                                        \
      break;                                                                \
  }

EVALUATE(VFCE) {
  DCHECK_OPCODE(VFCE);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  VECTOR_FP_COMPARE(==)
  return length;
}

EVALUATE(VFCHE) {
  DCHECK_OPCODE(VFCHE);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  VECTOR_FP_COMPARE(>=)
  return length;
}

EVALUATE(VFCH) {
  DCHECK_OPCODE(VFCH);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  VECTOR_FP_COMPARE(>)  // NOLINT
  return length;
}

// TODO(john): unify most fp unary operations
// sec = Single Element Control mask
template <class T, class Op>
static void VectorUnaryOp(Simulator* sim, int dst, int src, int sec, Op op) {
  if (sec == 8) {
    T value = op(sim->get_fpr<T>(src));
    sim->set_fpr(dst, value);
  } else {
    CHECK_EQ(sec, 0);
    FOR_EACH_LANE(i, T) {
      T value = op(sim->get_simd_register_by_lane<T>(src, i));
      sim->set_simd_register_by_lane<T>(dst, i, value);
    }
  }
}

#define CASE(i, T, op)                       \
  case i:                                    \
    VectorUnaryOp<T>(sim, dst, src, m4, op); \
    break;

template <class T>
void VectorSignOp(Simulator* sim, int dst, int src, int m4, int m5) {
  switch (m5) {
    CASE(0, T, [](T value) { return -value; });
    CASE(1, T, [](T value) { return -std::abs(value); });
    CASE(2, T, [](T value) { return std::abs(value); });
    default:
      UNREACHABLE();
  }
}
#undef CASE

EVALUATE(VFPSO) {
  DCHECK_OPCODE(VFPSO);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  switch (m3) {
#define CASE(i, T)                         \
  case i:                                  \
    VectorSignOp<T>(this, r1, r2, m4, m5); \
    break;
    CASE(2, float);
    CASE(3, double);
    default:
      UNREACHABLE();
#undef CASE
  }
  return length;
}

EVALUATE(VFSQ) {
  DCHECK_OPCODE(VFSQ);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  switch (m3) {
#define CASE(i, T)                                                            \
  case i:                                                                     \
    VectorUnaryOp<T>(this, r1, r2, m4, [](T val) { return std::sqrt(val); }); \
    break;
    CASE(2, float);
    CASE(3, double);
    default:
      UNREACHABLE();
#undef CASE
  }
  return length;
}

EVALUATE(VFI) {
  DCHECK_OPCODE(VFI);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  DCHECK_EQ(m4, 0);
  USE(m4);

  switch (m3) {
    case 2:
      DCHECK(CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1));
      for (int i = 0; i < 4; i++) {
        float value = get_simd_register_by_lane<float>(r2, i);
        float n = ComputeRounding<float>(value, m5);
        set_simd_register_by_lane<float>(r1, i, n);
      }
      break;
    case 3:
      for (int i = 0; i < 2; i++) {
        double value = get_simd_register_by_lane<double>(r2, i);
        double n = ComputeRounding<double>(value, m5);
        set_simd_register_by_lane<double>(r1, i, n);
      }
      break;
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(DUMY) {
  DCHECK_OPCODE(DUMY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  USE(r1);
  USE(x2);
  USE(b2);
  USE(d2);
  // dummy instruction does nothing.
  return length;
}

EVALUATE(CLR) {
  DCHECK_OPCODE(CLR);
  DECODE_RR_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  SetS390ConditionCode<uint32_t>(r1_val, r2_val);
  return length;
}

EVALUATE(LR) {
  DCHECK_OPCODE(LR);
  DECODE_RR_INSTRUCTION(r1, r2);
  set_low_register(r1, get_low_register<int32_t>(r2));
  return length;
}

EVALUATE(AR) {
  DCHECK_OPCODE(AR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  bool isOF = CheckOverflowForIntAdd(r1_val, r2_val, int32_t);
  r1_val += r2_val;
  SetS390ConditionCode<int32_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(L) {
  DCHECK_OPCODE(L);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int32_t mem_val = ReadW(addr);
  set_low_register(r1, mem_val);
  return length;
}

EVALUATE(BRC) {
  DCHECK_OPCODE(BRC);
  DECODE_RI_C_INSTRUCTION(instr, m1, i2);

  if (TestConditionCode(m1)) {
    intptr_t offset = 2 * i2;
    set_pc(get_pc() + offset);
  }
  return length;
}

EVALUATE(AHI) {
  DCHECK_OPCODE(AHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  bool isOF = CheckOverflowForIntAdd(r1_val, i2, int32_t);
  r1_val += i2;
  set_low_register(r1, r1_val);
  SetS390ConditionCode<int32_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(AGHI) {
  DCHECK_OPCODE(AGHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  int64_t r1_val = get_register(r1);
  bool isOF = false;
  isOF = CheckOverflowForIntAdd(r1_val, i2, int64_t);
  r1_val += i2;
  set_register(r1, r1_val);
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(BRCL) {
  DCHECK_OPCODE(BRCL);
  DECODE_RIL_C_INSTRUCTION(m1, ri2);

  if (TestConditionCode(m1)) {
    intptr_t offset = 2 * ri2;
    set_pc(get_pc() + offset);
  }
  return length;
}

EVALUATE(IIHF) {
  DCHECK_OPCODE(IIHF);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  set_high_register(r1, imm);
  return length;
}

EVALUATE(IILF) {
  DCHECK_OPCODE(IILF);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  set_low_register(r1, imm);
  return length;
}

EVALUATE(LGR) {
  DCHECK_OPCODE(LGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  set_register(r1, get_register(r2));
  return length;
}

EVALUATE(LG) {
  DCHECK_OPCODE(LG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int64_t mem_val = ReadDW(addr);
  set_register(r1, mem_val);
  return length;
}

EVALUATE(AGR) {
  DCHECK_OPCODE(AGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  bool isOF = CheckOverflowForIntAdd(r1_val, r2_val, int64_t);
  r1_val += r2_val;
  set_register(r1, r1_val);
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(LGFR) {
  DCHECK_OPCODE(LGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  int64_t result = static_cast<int64_t>(r2_val);
  set_register(r1, result);

  return length;
}

EVALUATE(LBR) {
  DCHECK_OPCODE(LBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  r2_val <<= 24;
  r2_val >>= 24;
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(LGBR) {
  DCHECK_OPCODE(LGBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_low_register<int64_t>(r2);
  r2_val <<= 56;
  r2_val >>= 56;
  set_register(r1, r2_val);
  return length;
}

EVALUATE(LHR) {
  DCHECK_OPCODE(LHR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  r2_val <<= 16;
  r2_val >>= 16;
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(LGHR) {
  DCHECK_OPCODE(LGHR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_low_register<int64_t>(r2);
  r2_val <<= 48;
  r2_val >>= 48;
  set_register(r1, r2_val);
  return length;
}

EVALUATE(LGF) {
  DCHECK_OPCODE(LGF);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int64_t mem_val = static_cast<int64_t>(ReadW(addr));
  set_register(r1, mem_val);
  return length;
}

EVALUATE(ST) {
  DCHECK_OPCODE(ST);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  WriteW(addr, r1_val);
  return length;
}

EVALUATE(STG) {
  DCHECK_OPCODE(STG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  uint64_t value = get_register(r1);
  WriteDW(addr, value);
  return length;
}

EVALUATE(STY) {
  DCHECK_OPCODE(STY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  uint32_t value = get_low_register<uint32_t>(r1);
  WriteW(addr, value);
  return length;
}

EVALUATE(LY) {
  DCHECK_OPCODE(LY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  uint32_t mem_val = ReadWU(addr);
  set_low_register(r1, mem_val);
  return length;
}

EVALUATE(LLGC) {
  DCHECK_OPCODE(LLGC);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  uint8_t mem_val = ReadBU(GET_ADDRESS(x2, b2, d2));
  set_register(r1, static_cast<uint64_t>(mem_val));
  return length;
}

EVALUATE(LLC) {
  DCHECK_OPCODE(LLC);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  uint8_t mem_val = ReadBU(GET_ADDRESS(x2, b2, d2));
  set_low_register(r1, static_cast<uint32_t>(mem_val));
  return length;
}

EVALUATE(RLL) {
  DCHECK_OPCODE(RLL);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // only takes rightmost 6 bits
  int shiftBits = GET_ADDRESS(0, b2, d2) & 0x3F;
  // unsigned
  uint32_t r3_val = get_low_register<uint32_t>(r3);
  uint32_t alu_out = 0;
  uint32_t rotateBits = r3_val >> (32 - shiftBits);
  alu_out = (r3_val << shiftBits) | (rotateBits);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(RISBG) {
  DCHECK_OPCODE(RISBG);
  DECODE_RIE_F_INSTRUCTION(r1, r2, i3, i4, i5);
  // Starting Bit Position is Bits 2-7 of I3 field
  uint32_t start_bit = i3 & 0x3F;
  // Ending Bit Position is Bits 2-7 of I4 field
  uint32_t end_bit = i4 & 0x3F;
  // Shift Amount is Bits 2-7 of I5 field
  uint32_t shift_amount = i5 & 0x3F;
  // Zero out Remaining (unslected) bits if Bit 0 of I4 is 1.
  bool zero_remaining = (0 != (i4 & 0x80));

  uint64_t src_val = get_register(r2);

  // Rotate Left by Shift Amount first
  uint64_t rotated_val =
      (src_val << shift_amount) | (src_val >> (64 - shift_amount));
  int32_t width = end_bit - start_bit + 1;

  uint64_t selection_mask = 0;
  if (width < 64) {
    selection_mask = (static_cast<uint64_t>(1) << width) - 1;
  } else {
    selection_mask = static_cast<uint64_t>(static_cast<int64_t>(-1));
  }
  selection_mask = selection_mask << (63 - end_bit);

  uint64_t selected_val = rotated_val & selection_mask;

  if (!zero_remaining) {
    // Merged the unselected bits from the original value
    selected_val = (get_register(r1) & ~selection_mask) | selected_val;
  }

  // Condition code is set by treating result as 64-bit signed int
  SetS390ConditionCode<int64_t>(selected_val, 0);
  set_register(r1, selected_val);
  return length;
}

EVALUATE(AHIK) {
  DCHECK_OPCODE(AHIK);
  DECODE_RIE_D_INSTRUCTION(r1, r2, i2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t imm = static_cast<int32_t>(i2);
  bool isOF = CheckOverflowForIntAdd(r2_val, imm, int32_t);
  set_low_register(r1, r2_val + imm);
  SetS390ConditionCode<int32_t>(r2_val + imm, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(AGHIK) {
  // 64-bit Add
  DCHECK_OPCODE(AGHIK);
  DECODE_RIE_D_INSTRUCTION(r1, r2, i2);
  int64_t r2_val = get_register(r2);
  int64_t imm = static_cast<int64_t>(i2);
  bool isOF = CheckOverflowForIntAdd(r2_val, imm, int64_t);
  set_register(r1, r2_val + imm);
  SetS390ConditionCode<int64_t>(r2_val + imm, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(BKPT) {
  DCHECK_OPCODE(BKPT);
  set_pc(get_pc() + 2);
  S390Debugger dbg(this);
  dbg.Debug();
  int length = 2;
  return length;
}

EVALUATE(SPM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BALR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BCTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BCR) {
  DCHECK_OPCODE(BCR);
  DECODE_RR_INSTRUCTION(r1, r2);
  if (TestConditionCode(Condition(r1))) {
    intptr_t r2_val = get_register(r2);
    set_pc(r2_val);
  }

  return length;
}

EVALUATE(SVC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BSM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BASSM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BASR) {
  DCHECK_OPCODE(BASR);
  DECODE_RR_INSTRUCTION(r1, r2);
  intptr_t link_addr = get_pc() + 2;
  // If R2 is zero, the BASR does not branch.
  int64_t r2_val = (r2 == 0) ? link_addr : get_register(r2);
  set_register(r1, link_addr);
  set_pc(r2_val);
  return length;
}

EVALUATE(MVCL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLCL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPR) {
  DCHECK_OPCODE(LPR);
  // Load Positive (32)
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  SetS390ConditionCode<int32_t>(r2_val, 0);
  if (r2_val == (static_cast<int32_t>(1) << 31)) {
    SetS390OverflowCode(true);
  } else {
    // If negative and not overflowing, then negate it.
    r2_val = (r2_val < 0) ? -r2_val : r2_val;
  }
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(LNR) {
  DCHECK_OPCODE(LNR);
  // Load Negative (32)
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  r2_val = (r2_val >= 0) ? -r2_val : r2_val;  // If pos, then negate it.
  set_low_register(r1, r2_val);
  condition_reg_ = (r2_val == 0) ? CC_EQ : CC_LT;  // CC0 - result is zero
  // CC1 - result is negative
  return length;
}

EVALUATE(LTR) {
  DCHECK_OPCODE(LTR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  SetS390ConditionCode<int32_t>(r2_val, 0);
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(LCR) {
  DCHECK_OPCODE(LCR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t result = 0;
  bool isOF = false;
  isOF = __builtin_ssub_overflow(0, r2_val, &result);
  set_low_register(r1, result);
  SetS390ConditionCode<int32_t>(r2_val, 0);
  // Checks for overflow where r2_val = -2147483648.
  // Cannot do int comparison due to GCC 4.8 bug on x86.
  // Detect INT_MIN alternatively, as it is the only value where both
  // original and result are negative due to overflow.
  if (isOF) {
    SetS390OverflowCode(true);
  }
  return length;
}

EVALUATE(NR) {
  DCHECK_OPCODE(NR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  r1_val &= r2_val;
  SetS390BitWiseConditionCode<uint32_t>(r1_val);
  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(OR) {
  DCHECK_OPCODE(OR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  r1_val |= r2_val;
  SetS390BitWiseConditionCode<uint32_t>(r1_val);
  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(XR) {
  DCHECK_OPCODE(XR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  r1_val ^= r2_val;
  SetS390BitWiseConditionCode<uint32_t>(r1_val);
  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CR) {
  DCHECK_OPCODE(CR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  SetS390ConditionCode<int32_t>(r1_val, r2_val);
  return length;
}

EVALUATE(SR) {
  DCHECK_OPCODE(SR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  bool isOF = false;
  isOF = CheckOverflowForIntSub(r1_val, r2_val, int32_t);
  r1_val -= r2_val;
  SetS390ConditionCode<int32_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(MR) {
  DCHECK_OPCODE(MR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  DCHECK_EQ(r1 % 2, 0);
  r1_val = get_low_register<int32_t>(r1 + 1);
  int64_t product = static_cast<int64_t>(r1_val) * static_cast<int64_t>(r2_val);
  int32_t high_bits = product >> 32;
  r1_val = high_bits;
  int32_t low_bits = product & 0x00000000FFFFFFFF;
  set_low_register(r1, high_bits);
  set_low_register(r1 + 1, low_bits);
  return length;
}

EVALUATE(DR) {
  DCHECK_OPCODE(DR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  // reg-reg pair should be even-odd pair, assert r1 is an even register
  DCHECK_EQ(r1 % 2, 0);
  // leftmost 32 bits of the dividend are in r1
  // rightmost 32 bits of the dividend are in r1+1
  // get the signed value from r1
  int64_t dividend = static_cast<int64_t>(r1_val) << 32;
  // get unsigned value from r1+1
  // avoid addition with sign-extended r1+1 value
  dividend += get_low_register<uint32_t>(r1 + 1);
  int32_t remainder = dividend % r2_val;
  int32_t quotient = dividend / r2_val;
  r1_val = remainder;
  set_low_register(r1, remainder);
  set_low_register(r1 + 1, quotient);
  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(ALR) {
  DCHECK_OPCODE(ALR);
  DECODE_RR_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t alu_out = 0;
  bool isOF = false;
  alu_out = r1_val + r2_val;
  isOF = CheckOverflowForUIntAdd(r1_val, r2_val);
  set_low_register(r1, alu_out);
  SetS390ConditionCodeCarry<uint32_t>(alu_out, isOF);
  return length;
}

EVALUATE(SLR) {
  DCHECK_OPCODE(SLR);
  DECODE_RR_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t alu_out = 0;
  bool isOF = false;
  alu_out = r1_val - r2_val;
  isOF = CheckOverflowForUIntSub(r1_val, r2_val);
  set_low_register(r1, alu_out);
  SetS390ConditionCodeCarry<uint32_t>(alu_out, isOF);
  return length;
}

EVALUATE(LDR) {
  DCHECK_OPCODE(LDR);
  DECODE_RR_INSTRUCTION(r1, r2);
  int64_t r2_val = get_fpr<int64_t>(r2);
  set_fpr(r1, r2_val);
  return length;
}

EVALUATE(CDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LER) {
  DCHECK_OPCODE(LER);
  DECODE_RR_INSTRUCTION(r1, r2);
  int64_t r2_val = get_fpr<int64_t>(r2);
  set_fpr(r1, r2_val);
  return length;
}

EVALUATE(STH) {
  DCHECK_OPCODE(STH);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int16_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t mem_addr = b2_val + x2_val + d2_val;
  WriteH(mem_addr, r1_val);

  return length;
}

EVALUATE(LA) {
  DCHECK_OPCODE(LA);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  set_register(r1, addr);
  return length;
}

EVALUATE(STC) {
  DCHECK_OPCODE(STC);
  // Store Character/Byte
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  uint8_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t mem_addr = b2_val + x2_val + d2_val;
  WriteB(mem_addr, r1_val);
  return length;
}

EVALUATE(IC_z) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EX) {
  DCHECK_OPCODE(EX);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int32_t r1_val = get_low_register<int32_t>(r1);

  SixByteInstr the_instr = Instruction::InstructionBits(
      reinterpret_cast<const uint8_t*>(b2_val + x2_val + d2_val));
  int inst_length = Instruction::InstructionLength(
      reinterpret_cast<const uint8_t*>(b2_val + x2_val + d2_val));

  char new_instr_buf[8];
  char* addr = reinterpret_cast<char*>(&new_instr_buf[0]);
  the_instr |= static_cast<SixByteInstr>(r1_val & 0xFF)
               << (8 * inst_length - 16);
  Instruction::SetInstructionBits<SixByteInstr>(
      reinterpret_cast<uint8_t*>(addr), static_cast<SixByteInstr>(the_instr));
  ExecuteInstruction(reinterpret_cast<Instruction*>(addr), false);
  return length;
}

EVALUATE(BAL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BCT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LH) {
  DCHECK_OPCODE(LH);
  // Load Halfword
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);

  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t mem_addr = x2_val + b2_val + d2_val;

  int32_t result = static_cast<int32_t>(ReadH(mem_addr));
  set_low_register(r1, result);
  return length;
}

EVALUATE(CH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AH) {
  DCHECK_OPCODE(AH);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int32_t mem_val = static_cast<int32_t>(ReadH(addr));
  int32_t alu_out = 0;
  bool isOF = false;
  isOF = CheckOverflowForIntAdd(r1_val, mem_val, int32_t);
  alu_out = r1_val + mem_val;
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);

  return length;
}

EVALUATE(SH) {
  DCHECK_OPCODE(SH);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int32_t mem_val = static_cast<int32_t>(ReadH(addr));
  int32_t alu_out = 0;
  bool isOF = false;
  isOF = CheckOverflowForIntSub(r1_val, mem_val, int32_t);
  alu_out = r1_val - mem_val;
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);

  return length;
}

EVALUATE(MH) {
  DCHECK_OPCODE(MH);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int32_t mem_val = static_cast<int32_t>(ReadH(addr));
  int32_t alu_out = 0;
  alu_out = r1_val * mem_val;
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(BAS) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CVD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CVB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LAE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(N) {
  DCHECK_OPCODE(N);
  // 32-bit Reg-Mem instructions
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int32_t mem_val = ReadW(b2_val + x2_val + d2_val);
  int32_t alu_out = 0;
  alu_out = r1_val & mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(CL) {
  DCHECK_OPCODE(CL);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int32_t mem_val = ReadW(addr);
  SetS390ConditionCode<uint32_t>(r1_val, mem_val);
  return length;
}

EVALUATE(O) {
  DCHECK_OPCODE(O);
  // 32-bit Reg-Mem instructions
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int32_t mem_val = ReadW(b2_val + x2_val + d2_val);
  int32_t alu_out = 0;
  alu_out = r1_val | mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(X) {
  DCHECK_OPCODE(X);
  // 32-bit Reg-Mem instructions
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int32_t mem_val = ReadW(b2_val + x2_val + d2_val);
  int32_t alu_out = 0;
  alu_out = r1_val ^ mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(C) {
  DCHECK_OPCODE(C);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int32_t mem_val = ReadW(addr);
  SetS390ConditionCode<int32_t>(r1_val, mem_val);
  return length;
}

EVALUATE(A) {
  DCHECK_OPCODE(A);
  // 32-bit Reg-Mem instructions
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int32_t mem_val = ReadW(b2_val + x2_val + d2_val);
  int32_t alu_out = 0;
  bool isOF = false;
  isOF = CheckOverflowForIntAdd(r1_val, mem_val, int32_t);
  alu_out = r1_val + mem_val;
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(S) {
  DCHECK_OPCODE(S);
  // 32-bit Reg-Mem instructions
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int32_t mem_val = ReadW(b2_val + x2_val + d2_val);
  int32_t alu_out = 0;
  bool isOF = false;
  isOF = CheckOverflowForIntSub(r1_val, mem_val, int32_t);
  alu_out = r1_val - mem_val;
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(M) {
  DCHECK_OPCODE(M);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  DCHECK_EQ(r1 % 2, 0);
  int32_t mem_val = ReadW(addr);
  int32_t r1_val = get_low_register<int32_t>(r1 + 1);
  int64_t product =
      static_cast<int64_t>(r1_val) * static_cast<int64_t>(mem_val);
  int32_t high_bits = product >> 32;
  r1_val = high_bits;
  int32_t low_bits = product & 0x00000000FFFFFFFF;
  set_low_register(r1, high_bits);
  set_low_register(r1 + 1, low_bits);
  return length;
}

EVALUATE(D) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STD) {
  DCHECK_OPCODE(STD);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int64_t frs_val = get_fpr<int64_t>(r1);
  WriteDW(addr, frs_val);
  return length;
}

EVALUATE(LD) {
  DCHECK_OPCODE(LD);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int64_t dbl_val = *reinterpret_cast<int64_t*>(addr);
  set_fpr(r1, dbl_val);
  return length;
}

EVALUATE(CD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STE) {
  DCHECK_OPCODE(STE);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  int32_t frs_val = get_fpr<int32_t>(r1);
  WriteW(addr, frs_val);
  return length;
}

EVALUATE(MS) {
  DCHECK_OPCODE(MS);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int32_t mem_val = ReadW(b2_val + x2_val + d2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  set_low_register(r1, r1_val * mem_val);
  return length;
}

EVALUATE(LE) {
  DCHECK_OPCODE(LE);
  DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t addr = b2_val + x2_val + d2_val;
  float float_val = *reinterpret_cast<float*>(addr);
  set_fpr(r1, float_val);
  return length;
}

EVALUATE(BRXH) {
  DCHECK_OPCODE(BRXH);
  DECODE_RSI_INSTRUCTION(r1, r3, i2);
  int32_t r1_val = (r1 == 0) ? 0 : get_low_register<int32_t>(r1);
  int32_t r3_val = (r3 == 0) ? 0 : get_low_register<int32_t>(r3);
  intptr_t branch_address = get_pc() + (2 * i2);
  r1_val += r3_val;
  int32_t compare_val =
      r3 % 2 == 0 ? get_low_register<int32_t>(r3 + 1) : r3_val;
  if (r1_val > compare_val) {
    set_pc(branch_address);
  }
  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(BRXLE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BXH) {
  DCHECK_OPCODE(BXH);
  DECODE_RS_A_INSTRUCTION(r1, r3, b2, d2);

  // r1_val is the first operand, r3_val is the increment
  int32_t r1_val = (r1 == 0) ? 0 : get_register(r1);
  int32_t r3_val = (r3 == 0) ? 0 : get_register(r3);
  intptr_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t branch_address = b2_val + d2;
  // increment r1_val
  r1_val += r3_val;

  // if the increment is even, then it designates a pair of registers
  // and the contents of the even and odd registers of the pair are used as
  // the increment and compare value respectively. If the increment is odd,
  // the increment itself is used as both the increment and compare value
  int32_t compare_val = r3 % 2 == 0 ? get_register(r3 + 1) : r3_val;
  if (r1_val > compare_val) {
    // branch to address if r1_val is greater than compare value
    set_pc(branch_address);
  }

  // update contents of register in r1 with the new incremented value
  set_register(r1, r1_val);


"""


```