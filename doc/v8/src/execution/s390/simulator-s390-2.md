Response: The user wants a summary of the functionality of a C++ source code file, specifically the third part of a five-part file. The file seems to be implementing a simulator for the s390 architecture, focusing on instruction evaluation.

Therefore, the summary should focus on the types of s390 instructions being simulated in this specific part of the file. I need to look for the `EVALUATE` macros and identify the corresponding s390 instruction mnemonics. If there's a clear relationship to JavaScript concepts, I need to provide a concise example.

Let's go through the code blocks marked with `EVALUATE`:

- Vector instructions (VME, VMO, VMLE, VMLO, VNC, VSUM, VSUMG, VMRL, VMRH, VPK, VPKS, VPKLS, VUPH, VUPLH, VPOPCT, VCDG, VCDLG, VCGD, VCLGD, VUPL, VUPLL, VMX, VMXL, VMN, VMNL, VCEQ, VCH, VCHL, VO, VN, VX, VNO, VLC, VPERM, VBPERM, VSEL, VESL, VESRA, VESRL, VESLV, VESRAV, VESRLV, VTM, VFA, VFS, VFM, VFD, VFMA, VFNMS, VFMIN, VFMAX, VFCE, VFCHE, VFCH, VFPSO, VFSQ, VFI) - these are mostly SIMD operations.
- General-purpose instructions (DUMY, CLR, LR, AR, L, BRC, AHI, AGHI, BRCL, IIHF, IILF, LGR, LG, AGR, LGFR, LBR, LGBR, LHR, LGHR, LGF, ST, STG, STY, LY, LLGC, LLC, RLL, RISBG, AHIK, AGHIK, BKPT, SPM, BALR, BCTR, BCR, SVC, BSM, BASSM, BASR, MVCL, CLCL, LPR, LNR, LTR, LCR, NR, OR, XR, CR, SR, MR, DR, ALR, SLR, LDR, CDR, LER, STH, LA, STC, IC_z, EX, BAL, BCT, BC, LH, CH, AH, SH, MH, BAS, CVD, CVB, LAE, N, CL, O, X, C, A, S, M, D, AL, SL, STD, LD, CD, STE, MS, LE, BRXH, BRXLE, BXH) - a wide range of arithmetic, logical, load/store, and control flow instructions.

It appears this part of the simulator is heavily focused on implementing both vector and general-purpose instructions. The vector instructions strongly suggest support for Single Instruction, Multiple Data operations, likely to optimize parallel computations. The inclusion of floating-point vector instructions (VF*, VFPSO, VFSQ, VFI) indicates support for SIMD floating-point arithmetic.

JavaScript itself doesn't directly expose SIMD instructions at the language level in the same way as assembly or C/C++. However, JavaScript engines like V8 (the context of this file) can utilize SIMD instructions under the hood to optimize certain operations.

For example, when performing operations on large arrays of numbers, V8 might internally use SIMD instructions to process multiple elements in parallel, even if the JavaScript code appears as a simple loop.

Let's craft a summary that captures these points and provide a JavaScript example, focusing on array operations as a relatable scenario.
这是目录为`v8/src/execution/s390/simulator-s390.cc`的C++源代码文件的第3部分，主要功能是 **模拟 IBM System/390 (s390) 架构的指令执行**。

具体来说，这部分代码实现了大量 s390 架构的指令的模拟逻辑，涵盖了以下几个方面：

1. **向量 (SIMD) 指令模拟:**  这部分包含了大量的以 `V` 开头的 `EVALUATE` 宏定义的函数，例如 `VME`, `VMO`, `VSUM`, `VMRL`, `VPK`, `VUPH`, `VPOPCT`, `VFA`, `VFMA`, `VFMIN` 等。这些函数模拟了 s390 向量扩展 (Vector Extensions) 中的各种指令，用于执行单指令多数据 (SIMD) 操作，可以并行处理多个数据元素。这些指令涵盖了算术运算（加、减、乘、除）、逻辑运算（与、或、异或、非）、比较、数据重排、类型转换等。

2. **通用目的指令模拟:** 除了向量指令，这部分还实现了许多通用的 s390 指令，例如 `CLR` (比较逻辑寄存器), `LR` (加载寄存器), `AR` (加寄存器), `L` (加载), `BRC` (条件分支), `AHI` (加半字立即数), `LGR` (加载通用寄存器), `ST` (存储), `LY` (加载逻辑字), `RLL` (循环左移),  `AHIK` (加半字立即数扩展), `BCR` (条件分支寄存器), `BASR` (带链接的转移寄存器), `LPR` (加载正数), `LNR` (加载负数), `LTR` (加载并测试), `LCR` (加载补码), `NR` (与), `OR` (或), `XR` (异或), `CR` (比较), `SR` (减), `MR` (乘), `DR` (除), `ALR` (逻辑加), `SLR` (逻辑减), `LA` (加载地址), `STC` (存储字符), `EX` (执行), `LH` (加载半字), `AH` (加半字), `SH` (减半字), `MH` (乘半字), `N` (与), `CL` (比较逻辑), `O` (或), `X` (异或), `C` (比较), `A` (加), `S` (减), `M` (乘), `STD` (存储双精度浮点数), `LD` (加载双精度浮点数), `LE` (加载单精度浮点数), `BRXH` (索引高位分支) 等。 这些指令覆盖了整数运算、逻辑运算、数据加载和存储、控制流转移等基本操作。

3. **浮点指令模拟:** 代码中也包含了对浮点指令的模拟，例如 `VFA`, `VFS`, `VFM`, `VFD`, `VFMA`, `VFMIN`, `VFMAX`, `VFCE`, `VFSQ`, `VFI`, `LDR`, `LER`, `STE`, `LE`. 这些指令用于执行浮点数的算术运算、比较和类型转换。

**与 JavaScript 的关系 (通过 V8 引擎):**

这个文件是 V8 JavaScript 引擎的一部分，V8 负责将 JavaScript 代码编译成机器码并执行。  V8 包含了一个模拟器，用于在某些情况下执行生成的机器码，例如：

* **测试和调试:**  模拟器可以用来测试 V8 生成的 s390 机器码是否正确。
* **不支持硬件执行的环境:** 在没有实际 s390 硬件的情况下，模拟器可以运行为 s390 架构编译的 JavaScript 代码。

JavaScript 本身并没有直接对应这些底层的 s390 指令。但是，V8 引擎在执行 JavaScript 代码时，可能会将一些高级的 JavaScript 操作转换成底层的机器码指令，其中就可能包括这里模拟的 s390 指令。

**JavaScript 例子:**

假设一段 JavaScript 代码执行了对两个数组进行逐元素相加的操作，V8 引擎在 s390 架构上可能最终会利用向量指令 `VFA` (向量浮点加法) 来加速这个过程 (如果数组包含浮点数)。

```javascript
function addArrays(arr1, arr2) {
  if (arr1.length !== arr2.length) {
    throw new Error("Arrays must have the same length");
  }
  const result = [];
  for (let i = 0; i < arr1.length; i++) {
    result.push(arr1[i] + arr2[i]);
  }
  return result;
}

const a = [1.0, 2.0, 3.0, 4.0];
const b = [5.0, 6.0, 7.0, 8.0];
const sum = addArrays(a, b);
console.log(sum); // 输出: [6, 8, 10, 12]
```

在这个例子中，虽然 JavaScript 代码看起来是一个简单的循环，但 V8 引擎在底层可能会将循环内的加法操作优化为 s390 的 `VFA` 指令，一次性处理多个浮点数的加法，从而提高执行效率。`simulator-s390.cc` 文件中的 `EVALUATE(VFA)` 函数就是模拟了这条底层指令的行为。

**总结:**

这部分 `simulator-s390.cc` 代码的核心功能是 **模拟 s390 架构的指令集，特别是向量指令和常见的通用目的指令**。它作为 V8 引擎的一部分，用于在非 s390 硬件上执行或测试为 s390 架构编译的 JavaScript 代码。虽然 JavaScript 开发者不会直接编写这些 s390 指令，但 V8 引擎在执行 JavaScript 代码时可能会在底层使用它们进行优化。

### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```
\
      VECTOR_MULTIPLY_EVEN_ODD_TYPE(r1, r2, r3, sign##int32_t, sign##int64_t, \
                                    is_odd)                                   \
      break;                                                                  \
    }                                                                         \
    default:                                                                  \
      UNREACHABLE();                                                          \
  }
EVALUATE(VME) {
  DCHECK_OPCODE(VME);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MULTIPLY_EVEN_ODD(r1, r2, r3, false, )
  return length;
}

EVALUATE(VMO) {
  DCHECK_OPCODE(VMO);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MULTIPLY_EVEN_ODD(r1, r2, r3, true, )
  return length;
}
EVALUATE(VMLE) {
  DCHECK_OPCODE(VMLE);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MULTIPLY_EVEN_ODD(r1, r2, r3, false, u)
  return length;
}

EVALUATE(VMLO) {
  DCHECK_OPCODE(VMLO);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MULTIPLY_EVEN_ODD(r1, r2, r3, true, u)
  return length;
}
#undef VECTOR_MULTIPLY_EVEN_ODD
#undef VECTOR_MULTIPLY_EVEN_ODD_TYPE

EVALUATE(VNC) {
  DCHECK_OPCODE(VNC);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  USE(m4);
  for (int i = 0; i < 2; i++) {
    int64_t lane_1 = get_simd_register_by_lane<uint64_t>(r2, i);
    int64_t lane_2 = get_simd_register_by_lane<uint64_t>(r3, i);
    set_simd_register_by_lane<uint64_t>(r1, i, lane_1 & ~lane_2);
  }
  return length;
}

template <class S, class D>
void VectorSum(Simulator* sim, int dst, int src1, int src2) {
  D value = 0;
  FOR_EACH_LANE(i, S) {
    value += sim->get_simd_register_by_lane<S>(src1, i);
    if ((i + 1) % (sizeof(D) / sizeof(S)) == 0) {
      value += sim->get_simd_register_by_lane<S>(src2, i);
      sim->set_simd_register_by_lane<D>(dst, i / (sizeof(D) / sizeof(S)),
                                        value);
      value = 0;
    }
  }
}

#define CASE(i, S, D)                  \
  case i:                              \
    VectorSum<S, D>(this, r1, r2, r3); \
    break;
EVALUATE(VSUM) {
  DCHECK_OPCODE(VSUM);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  switch (m4) {
    CASE(0, uint8_t, uint32_t);
    CASE(1, uint16_t, uint32_t);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VSUMG) {
  DCHECK_OPCODE(VSUMG);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  switch (m4) {
    CASE(1, uint16_t, uint64_t);
    CASE(2, uint32_t, uint64_t);
    default:
      UNREACHABLE();
  }
  return length;
}
#undef CASE

#define VECTOR_MERGE(type, is_low_side)                                      \
  constexpr size_t index_limit = (kSimd128Size / sizeof(type)) / 2;          \
  for (size_t i = 0, source_index = is_low_side ? i + index_limit : i;       \
       i < index_limit; i++, source_index++) {                               \
    set_simd_register_by_lane<type>(                                         \
        r1, 2 * i, get_simd_register_by_lane<type>(r2, source_index));       \
    set_simd_register_by_lane<type>(                                         \
        r1, (2 * i) + 1, get_simd_register_by_lane<type>(r3, source_index)); \
  }
#define CASE(i, type, is_low_side)  \
  case i: {                         \
    VECTOR_MERGE(type, is_low_side) \
  } break;
EVALUATE(VMRL) {
  DCHECK_OPCODE(VMRL);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  switch (m4) {
    CASE(0, int8_t, true);
    CASE(1, int16_t, true);
    CASE(2, int32_t, true);
    CASE(3, int64_t, true);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VMRH) {
  DCHECK_OPCODE(VMRH);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  switch (m4) {
    CASE(0, int8_t, false);
    CASE(1, int16_t, false);
    CASE(2, int32_t, false);
    CASE(3, int64_t, false);
    default:
      UNREACHABLE();
  }
  return length;
}
#undef CASE
#undef VECTOR_MERGE

template <class S, class D>
void VectorPack(Simulator* sim, int dst, int src1, int src2, bool saturate,
                const D& max = 0, const D& min = 0) {
  int src = src1;
  int count = 0;
  S value = 0;
  // Setup a temp array to avoid overwriting dst mid loop.
  D temps[kSimd128Size / sizeof(D)] = {0};
  for (size_t i = 0; i < kSimd128Size / sizeof(D); i++, count++) {
    if (count == kSimd128Size / sizeof(S)) {
      src = src2;
      count = 0;
    }
    value = sim->get_simd_register_by_lane<S>(src, count);
    if (saturate) {
      if (value > max)
        value = max;
      else if (value < min)
        value = min;
    }
    temps[i] = value;
  }
  FOR_EACH_LANE(i, D) { sim->set_simd_register_by_lane<D>(dst, i, temps[i]); }
}

#define CASE(i, S, D, SAT, MAX, MIN)                   \
  case i:                                              \
    VectorPack<S, D>(this, r1, r2, r3, SAT, MAX, MIN); \
    break;
EVALUATE(VPK) {
  DCHECK_OPCODE(VPK);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  switch (m4) {
    CASE(1, uint16_t, uint8_t, false, 0, 0);
    CASE(2, uint32_t, uint16_t, false, 0, 0);
    CASE(3, uint64_t, uint32_t, false, 0, 0);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VPKS) {
  DCHECK_OPCODE(VPKS);
  DECODE_VRR_B_INSTRUCTION(r1, r2, r3, m5, m4);
  USE(m5);
  USE(m4);
  switch (m4) {
    CASE(1, int16_t, int8_t, true, INT8_MAX, INT8_MIN);
    CASE(2, int32_t, int16_t, true, INT16_MAX, INT16_MIN);
    CASE(3, int64_t, int32_t, true, INT32_MAX, INT32_MIN);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VPKLS) {
  DCHECK_OPCODE(VPKLS);
  DECODE_VRR_B_INSTRUCTION(r1, r2, r3, m5, m4);
  USE(m5);
  USE(m4);
  switch (m4) {
    CASE(1, uint16_t, uint8_t, true, UINT8_MAX, 0);
    CASE(2, uint32_t, uint16_t, true, UINT16_MAX, 0);
    CASE(3, uint64_t, uint32_t, true, UINT32_MAX, 0);
    default:
      UNREACHABLE();
  }
  return length;
}

#undef CASE
template <class S, class D>
void VectorUnpackHigh(Simulator* sim, int dst, int src) {
  constexpr size_t kItemCount = kSimd128Size / sizeof(D);
  D temps[kItemCount] = {0};
  // About overwriting if src and dst are the same register.
  FOR_EACH_LANE(i, D) { temps[i] = sim->get_simd_register_by_lane<S>(src, i); }
  FOR_EACH_LANE(i, D) { sim->set_simd_register_by_lane<D>(dst, i, temps[i]); }
}

#define CASE(i, S, D)                     \
  case i:                                 \
    VectorUnpackHigh<S, D>(this, r1, r2); \
    break;

EVALUATE(VUPH) {
  DCHECK_OPCODE(VUPH);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  switch (m3) {
    CASE(0, int8_t, int16_t);
    CASE(1, int16_t, int32_t);
    CASE(2, int32_t, int64_t);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VUPLH) {
  DCHECK_OPCODE(VUPLH);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  switch (m3) {
    CASE(0, uint8_t, uint16_t);
    CASE(1, uint16_t, uint32_t);
    CASE(2, uint32_t, uint64_t);
    default:
      UNREACHABLE();
  }
  return length;
}
#undef CASE

template <class S>
void VectorPopulationCount(Simulator* sim, int dst, int src) {
  FOR_EACH_LANE(i, S) {
    sim->set_simd_register_by_lane<S>(
        dst, i,
        base::bits::CountPopulation(sim->get_simd_register_by_lane<S>(src, i)));
  }
}

#define CASE(i, S)                          \
  case i:                                   \
    VectorPopulationCount<S>(this, r1, r2); \
    break;
EVALUATE(VPOPCT) {
  DCHECK_OPCODE(VPOPCT);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  switch (m3) {
    CASE(0, uint8_t);
    default:
      UNREACHABLE();
  }
  return length;
}
#undef CASE

#define CASE(i, S, D)                                                          \
  case i: {                                                                    \
    FOR_EACH_LANE(index, S) {                                                  \
      set_simd_register_by_lane<D>(                                            \
          r1, index, static_cast<D>(get_simd_register_by_lane<S>(r2, index))); \
    }                                                                          \
    break;                                                                     \
  }
EVALUATE(VCDG) {
  DCHECK_OPCODE(VCDG);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m4);
  USE(m5);
  switch (m3) {
    CASE(2, int32_t, float);
    CASE(3, int64_t, double);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VCDLG) {
  DCHECK_OPCODE(VCDLG);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m4);
  USE(m5);
  switch (m3) {
    CASE(2, uint32_t, float);
    CASE(3, uint64_t, double);
    default:
      UNREACHABLE();
  }
  return length;
}
#undef CASE

#define CASE(i, S, D, type)                                           \
  case i: {                                                           \
    FOR_EACH_LANE(index, S) {                                         \
      S a = get_simd_register_by_lane<S>(r2, index);                  \
      S n = ComputeRounding<S>(a, m5);                                \
      set_simd_register_by_lane<D>(                                   \
          r1, index,                                                  \
          static_cast<D>(Compute##type##RoundingResult<S, D>(a, n))); \
    }                                                                 \
    break;                                                            \
  }
EVALUATE(VCGD) {
  DCHECK_OPCODE(VCGD);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m4);
  switch (m3) {
    CASE(2, float, int32_t, Signed);
    CASE(3, double, int64_t, Signed);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VCLGD) {
  DCHECK_OPCODE(VCLGD);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m4);
  switch (m3) {
    CASE(2, float, uint32_t, Logical);
    CASE(3, double, uint64_t, Logical);
    default:
      UNREACHABLE();
  }
  return length;
}
#undef CASE

template <class S, class D>
void VectorUnpackLow(Simulator* sim, int dst, int src) {
  constexpr size_t kItemCount = kSimd128Size / sizeof(D);
  D temps[kItemCount] = {0};
  // About overwriting if src and dst are the same register.
  // Using the "false" argument here to make sure we use the "Low" side of the
  // Simd register, being simulated by the LSB in memory.
  FOR_EACH_LANE(i, D) {
    temps[i] = sim->get_simd_register_by_lane<S>(src, i, false);
  }
  FOR_EACH_LANE(i, D) {
    sim->set_simd_register_by_lane<D>(dst, i, temps[i], false);
  }
}

#define CASE(i, S, D)                    \
  case i:                                \
    VectorUnpackLow<S, D>(this, r1, r2); \
    break;
EVALUATE(VUPL) {
  DCHECK_OPCODE(VUPL);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  switch (m3) {
    CASE(0, int8_t, int16_t);
    CASE(1, int16_t, int32_t);
    CASE(2, int32_t, int64_t);
    default:
      UNREACHABLE();
  }
  return length;
}

EVALUATE(VUPLL) {
  DCHECK_OPCODE(VUPLL);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  switch (m3) {
    CASE(0, uint8_t, uint16_t);
    CASE(1, uint16_t, uint32_t);
    CASE(2, uint32_t, uint64_t);
    default:
      UNREACHABLE();
  }
  return length;
}
#undef CASE

#define VECTOR_MAX_MIN_FOR_TYPE(type, op) \
  VectorBinaryOp<type>(this, r1, r2, r3,  \
                       [](type a, type b) { return (a op b) ? a : b; });

#define VECTOR_MAX_MIN(op, sign)                 \
  switch (m4) {                                  \
    case 0:                                      \
      VECTOR_MAX_MIN_FOR_TYPE(sign##int8_t, op)  \
      break;                                     \
    case 1:                                      \
      VECTOR_MAX_MIN_FOR_TYPE(sign##int16_t, op) \
      break;                                     \
    case 2:                                      \
      VECTOR_MAX_MIN_FOR_TYPE(sign##int32_t, op) \
      break;                                     \
    case 3:                                      \
      VECTOR_MAX_MIN_FOR_TYPE(sign##int64_t, op) \
      break;                                     \
    default:                                     \
      UNREACHABLE();                             \
      break;                                     \
  }

EVALUATE(VMX) {
  DCHECK_OPCODE(VMX);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MAX_MIN(>, )
  return length;
}

EVALUATE(VMXL) {
  DCHECK_OPCODE(VMXL);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MAX_MIN(>, u)
  return length;
}

EVALUATE(VMN) {
  DCHECK_OPCODE(VMN);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MAX_MIN(<, )
  return length;
}

EVALUATE(VMNL) {
  DCHECK_OPCODE(VMNL);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_MAX_MIN(<, u);
  return length;
}

#define VECTOR_COMPARE_FOR_TYPE(type, op) \
  VectorBinaryOp<type>(this, r1, r2, r3,  \
                       [](type a, type b) { return (a op b) ? -1 : 0; });

#define VECTOR_COMPARE(op, sign)                 \
  switch (m4) {                                  \
    case 0:                                      \
      VECTOR_COMPARE_FOR_TYPE(sign##int8_t, op)  \
      break;                                     \
    case 1:                                      \
      VECTOR_COMPARE_FOR_TYPE(sign##int16_t, op) \
      break;                                     \
    case 2:                                      \
      VECTOR_COMPARE_FOR_TYPE(sign##int32_t, op) \
      break;                                     \
    case 3:                                      \
      VECTOR_COMPARE_FOR_TYPE(sign##int64_t, op) \
      break;                                     \
    default:                                     \
      UNREACHABLE();                             \
      break;                                     \
  }

EVALUATE(VCEQ) {
  DCHECK_OPCODE(VCEQ);
  DECODE_VRR_B_INSTRUCTION(r1, r2, r3, m5, m4);
  USE(m5);
  DCHECK_EQ(m5, 0);
  VECTOR_COMPARE(==, )
  return length;
}

EVALUATE(VCH) {
  DCHECK_OPCODE(VCH);
  DECODE_VRR_B_INSTRUCTION(r1, r2, r3, m5, m4);
  USE(m5);
  DCHECK_EQ(m5, 0);
  VECTOR_COMPARE(>, )
  return length;
}

EVALUATE(VCHL) {
  DCHECK_OPCODE(VCHL);
  DECODE_VRR_B_INSTRUCTION(r1, r2, r3, m5, m4);
  USE(m5);
  DCHECK_EQ(m5, 0);
  VECTOR_COMPARE(>, u)
  return length;
}

EVALUATE(VO) {
  DCHECK_OPCODE(VO);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  USE(m4);
  VECTOR_BINARY_OP_FOR_TYPE(int64_t, |)
  return length;
}

EVALUATE(VN) {
  DCHECK_OPCODE(VN);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  USE(m4);
  VECTOR_BINARY_OP_FOR_TYPE(int64_t, &)
  return length;
}

EVALUATE(VX) {
  DCHECK_OPCODE(VX);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m4);
  USE(m5);
  USE(m6);
  VECTOR_BINARY_OP_FOR_TYPE(int64_t, ^)
  return length;
}

#define VECTOR_NOR(r1, r2, r3, type)                                    \
  for (size_t i = 0, j = 0; j < kSimd128Size; i++, j += sizeof(type)) { \
    type src0 = get_simd_register_by_lane<type>(r2, i);                 \
    type src1 = get_simd_register_by_lane<type>(r3, i);                 \
    set_simd_register_by_lane<type>(r1, i, ~(src0 | src1));             \
  }
EVALUATE(VNO) {
  DCHECK_OPCODE(VNO);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  switch (m4) {
    case 0: {
      VECTOR_NOR(r1, r2, r3, int8_t)
      break;
    }
    case 1: {
      VECTOR_NOR(r1, r2, r3, int16_t)
      break;
    }
    case 2: {
      VECTOR_NOR(r1, r2, r3, int32_t)
      break;
    }
    case 3: {
      VECTOR_NOR(r1, r2, r3, int64_t)
      break;
    }
    default:
      UNREACHABLE();
  }

  return length;
}
#undef VECTOR_NOR

template <class T>
void VectorLoadComplement(Simulator* sim, int dst, int src) {
  FOR_EACH_LANE(i, T) {
    T src_val = sim->get_simd_register_by_lane<T>(src, i);
    sim->set_simd_register_by_lane<T>(dst, i, -src_val);
  }
}

EVALUATE(VLC) {
  DCHECK_OPCODE(VLC);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  switch (m3) {
#define CASE(i, type)                         \
  case i:                                     \
    VectorLoadComplement<type>(this, r1, r2); \
    break;
    CASE(0, int8_t);
    CASE(1, int16_t);
    CASE(2, int32_t);
    CASE(3, int64_t);
    default:
      UNREACHABLE();
#undef CASE
  }
  return length;
}

EVALUATE(VPERM) {
  DCHECK_OPCODE(VPERM);
  DECODE_VRR_E_INSTRUCTION(r1, r2, r3, r4, m6, m5);
  USE(m5);
  USE(m6);
  int8_t temp[kSimd128Size] = {0};
  for (int i = 0; i < kSimd128Size; i++) {
    int8_t lane_num = get_simd_register_by_lane<int8_t>(r4, i);
    // Get the five least significant bits.
    lane_num = (lane_num << 3) >> 3;
    int reg = r2;
    if (lane_num >= kSimd128Size) {
      lane_num = lane_num - kSimd128Size;
      reg = r3;
    }
    temp[i] = get_simd_register_by_lane<int8_t>(reg, lane_num);
  }
  for (int i = 0; i < kSimd128Size; i++) {
    set_simd_register_by_lane<int8_t>(r1, i, temp[i]);
  }
  return length;
}

EVALUATE(VBPERM) {
  DCHECK_OPCODE(VBPERM);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m4);
  USE(m5);
  USE(m6);
  uint16_t result_bits = 0;
  unsigned __int128 src_bits =
      base::bit_cast<__int128>(get_simd_register(r2).int8);
  for (int i = 0; i < kSimd128Size; i++) {
    result_bits <<= 1;
    uint8_t selected_bit_index = get_simd_register_by_lane<uint8_t>(r3, i);
    if (selected_bit_index < (kSimd128Size * kBitsPerByte)) {
      unsigned __int128 bit_value =
          (src_bits << selected_bit_index) >> (kSimd128Size * kBitsPerByte - 1);
      result_bits |= bit_value;
    }
  }
  set_simd_register_by_lane<uint64_t>(r1, 0, 0);
  set_simd_register_by_lane<uint64_t>(r1, 1, 0);
  // Write back in bytes to avoid endianness problems.
  set_simd_register_by_lane<uint8_t>(r1, 6,
                                     static_cast<uint8_t>(result_bits >> 8));
  set_simd_register_by_lane<uint8_t>(
      r1, 7, static_cast<uint8_t>((result_bits << 8) >> 8));
  return length;
}

EVALUATE(VSEL) {
  DCHECK_OPCODE(VSEL);
  DECODE_VRR_E_INSTRUCTION(r1, r2, r3, r4, m6, m5);
  USE(m5);
  USE(m6);
  unsigned __int128 src_1 =
      base::bit_cast<__int128>(get_simd_register(r2).int8);
  unsigned __int128 src_2 =
      base::bit_cast<__int128>(get_simd_register(r3).int8);
  unsigned __int128 src_3 =
      base::bit_cast<__int128>(get_simd_register(r4).int8);
  unsigned __int128 tmp = (src_1 & src_3) | (src_2 & ~src_3);
  fpr_t result = base::bit_cast<fpr_t>(tmp);
  set_simd_register(r1, result);
  return length;
}

template <class T, class Operation>
void VectorShift(Simulator* sim, int dst, int src, unsigned int shift,
                 Operation op) {
  FOR_EACH_LANE(i, T) {
    T src_val = sim->get_simd_register_by_lane<T>(src, i);
    T dst_val = op(src_val, shift);
    sim->set_simd_register_by_lane<T>(dst, i, dst_val);
  }
}

#define VECTOR_SHIFT_FOR_TYPE(type, op, shift) \
  VectorShift<type>(this, r1, r3, shift,       \
                    [](type a, unsigned int shift) { return a op shift; });

#define VECTOR_SHIFT(op, sign)                        \
  switch (m4) {                                       \
    case 0:                                           \
      VECTOR_SHIFT_FOR_TYPE(sign##int8_t, op, shift)  \
      break;                                          \
    case 1:                                           \
      VECTOR_SHIFT_FOR_TYPE(sign##int16_t, op, shift) \
      break;                                          \
    case 2:                                           \
      VECTOR_SHIFT_FOR_TYPE(sign##int32_t, op, shift) \
      break;                                          \
    case 3:                                           \
      VECTOR_SHIFT_FOR_TYPE(sign##int64_t, op, shift) \
      break;                                          \
    default:                                          \
      UNREACHABLE();                                  \
      break;                                          \
  }

EVALUATE(VESL) {
  DCHECK_OPCODE(VESL);
  DECODE_VRS_INSTRUCTION(r1, r3, b2, d2, m4);
  unsigned int shift = get_register(b2) + d2;
  VECTOR_SHIFT(<<, )
  return length;
}

EVALUATE(VESRA) {
  DCHECK_OPCODE(VESRA);
  DECODE_VRS_INSTRUCTION(r1, r3, b2, d2, m4);
  unsigned int shift = get_register(b2) + d2;
  VECTOR_SHIFT(>>, )
  return length;
}

EVALUATE(VESRL) {
  DCHECK_OPCODE(VESRL);
  DECODE_VRS_INSTRUCTION(r1, r3, b2, d2, m4);
  unsigned int shift = get_register(b2) + d2;
  VECTOR_SHIFT(>>, u)
  return length;
}

#define VECTOR_SHIFT_WITH_OPERAND_TYPE(r1, r2, r3, type, op)             \
  for (size_t i = 0, j = 0; j < kSimd128Size; i++, j += sizeof(type)) {  \
    type src0 = get_simd_register_by_lane<type>(r2, i);                  \
    type src1 = get_simd_register_by_lane<type>(r3, i);                  \
    set_simd_register_by_lane<type>(r1, i,                               \
                                    src0 op(src1 % (sizeof(type) * 8))); \
  }

#define VECTOR_SHIFT_WITH_OPERAND(r1, r2, r3, op, sign)             \
  switch (m4) {                                                     \
    case 0: {                                                       \
      VECTOR_SHIFT_WITH_OPERAND_TYPE(r1, r2, r3, sign##int8_t, op)  \
      break;                                                        \
    }                                                               \
    case 1: {                                                       \
      VECTOR_SHIFT_WITH_OPERAND_TYPE(r1, r2, r3, sign##int16_t, op) \
      break;                                                        \
    }                                                               \
    case 2: {                                                       \
      VECTOR_SHIFT_WITH_OPERAND_TYPE(r1, r2, r3, sign##int32_t, op) \
      break;                                                        \
    }                                                               \
    case 3: {                                                       \
      VECTOR_SHIFT_WITH_OPERAND_TYPE(r1, r2, r3, sign##int64_t, op) \
      break;                                                        \
    }                                                               \
    default:                                                        \
      UNREACHABLE();                                                \
  }

EVALUATE(VESLV) {
  DCHECK_OPCODE(VESLV);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  VECTOR_SHIFT_WITH_OPERAND(r1, r2, r3, <<, )
  return length;
}

EVALUATE(VESRAV) {
  DCHECK_OPCODE(VESRAV);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  VECTOR_SHIFT_WITH_OPERAND(r1, r2, r3, >>, )
  return length;
}

EVALUATE(VESRLV) {
  DCHECK_OPCODE(VESRLV);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  VECTOR_SHIFT_WITH_OPERAND(r1, r2, r3, >>, u)
  return length;
}
#undef VECTOR_SHIFT_WITH_OPERAND
#undef VECTOR_SHIFT_WITH_OPERAND_TYPE

EVALUATE(VTM) {
  DCHECK_OPCODE(VTM);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  USE(m3);
  int64_t src1 = get_simd_register_by_lane<int64_t>(r1, 0);
  int64_t src2 = get_simd_register_by_lane<int64_t>(r1, 1);
  int64_t mask1 = get_simd_register_by_lane<int64_t>(r2, 0);
  int64_t mask2 = get_simd_register_by_lane<int64_t>(r2, 1);
  if ((src1 & mask1) == 0 && (src2 & mask2) == 0) {
    condition_reg_ = 0x8;
    return length;
  }
  if ((src1 & mask1) == mask1 && (src2 & mask2) == mask2) {
    condition_reg_ = 0x1;
    return length;
  }
  condition_reg_ = 0x4;
  return length;
}

#define VECTOR_FP_BINARY_OP(op)                                    \
  switch (m4) {                                                    \
    case 2:                                                        \
      DCHECK(CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)); \
      if (m5 == 8) {                                               \
        float src1 = get_simd_register_by_lane<float>(r2, 0);      \
        float src2 = get_simd_register_by_lane<float>(r3, 0);      \
        set_simd_register_by_lane<float>(r1, 0, src1 op src2);     \
      } else {                                                     \
        DCHECK_EQ(m5, 0);                                          \
        VECTOR_BINARY_OP_FOR_TYPE(float, op)                       \
      }                                                            \
      break;                                                       \
    case 3:                                                        \
      if (m5 == 8) {                                               \
        double src1 = get_simd_register_by_lane<double>(r2, 0);    \
        double src2 = get_simd_register_by_lane<double>(r3, 0);    \
        set_simd_register_by_lane<double>(r1, 0, src1 op src2);    \
      } else {                                                     \
        DCHECK_EQ(m5, 0);                                          \
        VECTOR_BINARY_OP_FOR_TYPE(double, op)                      \
      }                                                            \
      break;                                                       \
    default:                                                       \
      UNREACHABLE();                                               \
      break;                                                       \
  }

EVALUATE(VFA) {
  DCHECK_OPCODE(VFA);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  VECTOR_FP_BINARY_OP(+)
  return length;
}

EVALUATE(VFS) {
  DCHECK_OPCODE(VFS);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  VECTOR_FP_BINARY_OP(-)
  return length;
}

EVALUATE(VFM) {
  DCHECK_OPCODE(VFM);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  VECTOR_FP_BINARY_OP(*)
  return length;
}

EVALUATE(VFD) {
  DCHECK_OPCODE(VFD);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  VECTOR_FP_BINARY_OP(/)
  return length;
}

#define VECTOR_FP_MULTIPLY_QFMS_OPERATION(type, op, sign, first_lane_only, \
                                          function)                        \
  for (size_t i = 0, j = 0; j < kSimd128Size; i++, j += sizeof(type)) {    \
    type src0 = get_simd_register_by_lane<type>(r2, i);                    \
    type src1 = get_simd_register_by_lane<type>(r3, i);                    \
    type src2 = get_simd_register_by_lane<type>(r4, i);                    \
    type result = sign * function(src0, src1, op src2);                    \
    if (isinf(src0)) result = src0;                                        \
    if (isinf(src1)) result = src1;                                        \
    if (isinf(src2)) result = src2;                                        \
    set_simd_register_by_lane<type>(r1, i, result);                        \
    if (first_lane_only) break;                                            \
  }

#define VECTOR_FP_MULTIPLY_QFMS(op, sign)                               \
  switch (m6) {                                                         \
    case 2:                                                             \
      DCHECK(CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1));      \
      if (m5 == 8) {                                                    \
        VECTOR_FP_MULTIPLY_QFMS_OPERATION(float, op, sign, true, fmaf)  \
      } else {                                                          \
        DCHECK_EQ(m5, 0);                                               \
        VECTOR_FP_MULTIPLY_QFMS_OPERATION(float, op, sign, false, fmaf) \
      }                                                                 \
      break;                                                            \
    case 3:                                                             \
      if (m5 == 8) {                                                    \
        VECTOR_FP_MULTIPLY_QFMS_OPERATION(double, op, sign, true, fma)  \
      } else {                                                          \
        DCHECK_EQ(m5, 0);                                               \
        VECTOR_FP_MULTIPLY_QFMS_OPERATION(double, op, sign, false, fma) \
      }                                                                 \
      break;                                                            \
    default:                                                            \
      UNREACHABLE();                                                    \
      break;                                                            \
  }

EVALUATE(VFMA) {
  DCHECK_OPCODE(VFMA);
  DECODE_VRR_E_INSTRUCTION(r1, r2, r3, r4, m6, m5);
  USE(m5);
  USE(m6);
  VECTOR_FP_MULTIPLY_QFMS(+, 1)
  return length;
}

EVALUATE(VFNMS) {
  DCHECK_OPCODE(VFNMS);
  DECODE_VRR_E_INSTRUCTION(r1, r2, r3, r4, m6, m5);
  USE(m5);
  USE(m6);
  VECTOR_FP_MULTIPLY_QFMS(-, -1)
  return length;
}
#undef VECTOR_FP_MULTIPLY_QFMS
#undef VECTOR_FP_MULTIPLY_QFMS_OPERATION

template <class FP_Type>
static FP_Type JavaMathMax(FP_Type x, FP_Type y) {
  if (std::isnan(x) || std::isnan(y)) return NAN;
  if (std::signbit(x) < std::signbit(y)) return x;
  return x > y ? x : y;
}

template <class FP_Type>
static FP_Type IEEE_maxNum(FP_Type x, FP_Type y) {
  if (x > y) return x;
  if (x < y) return y;
  if (x == y) return x;
  if (!std::isnan(x)) return x;
  if (!std::isnan(y)) return y;
  return NAN;
}

template <class FP_Type>
static FP_Type FPMax(int m6, FP_Type lhs, FP_Type rhs) {
  switch (m6) {
    case 0:
      return IEEE_maxNum(lhs, rhs);
    case 1:
      return JavaMathMax(lhs, rhs);
    case 3:
      return std::max(lhs, rhs);
    case 4:
      return std::fmax(lhs, rhs);
    default:
      UNIMPLEMENTED();
  }
  return static_cast<FP_Type>(0);
}

template <class FP_Type>
static FP_Type JavaMathMin(FP_Type x, FP_Type y) {
  if (isnan(x) || isnan(y))
    return NAN;
  else if (signbit(y) < signbit(x))
    return x;
  else if (signbit(y) != signbit(x))
    return y;
  return (x < y) ? x : y;
}

template <class FP_Type>
static FP_Type IEEE_minNum(FP_Type x, FP_Type y) {
  if (x > y) return y;
  if (x < y) return x;
  if (x == y) return x;
  if (!std::isnan(x)) return x;
  if (!std::isnan(y)) return y;
  return NAN;
}

template <class FP_Type>
static FP_Type FPMin(int m6, FP_Type lhs, FP_Type rhs) {
  switch (m6) {
    case 0:
      return IEEE_minNum(lhs, rhs);
    case 1:
      return JavaMathMin(lhs, rhs);
    case 3:
      return std::min(lhs, rhs);
    case 4:
      return std::fmin(lhs, rhs);
    default:
      UNIMPLEMENTED();
  }
  return static_cast<FP_Type>(0);
}

// TODO(john.yan): use generic binary operation
template <class FP_Type, class Operation>
static void FPMinMaxForEachLane(Simulator* sim, Operation Op, int dst, int lhs,
                                int rhs, int m5, int m6) {
  DCHECK(m5 == 8 || m5 == 0);
  if (m5 == 8) {
    FP_Type src1 = sim->get_fpr<FP_Type>(lhs);
    FP_Type src2 = sim->get_fpr<FP_Type>(rhs);
    FP_Type res = Op(m6, src1, src2);
    sim->set_fpr(dst, res);
  } else {
    FOR_EACH_LANE(i, FP_Type) {
      FP_Type src1 = sim->get_simd_register_by_lane<FP_Type>(lhs, i);
      FP_Type src2 = sim->get_simd_register_by_lane<FP_Type>(rhs, i);
      FP_Type res = Op(m6, src1, src2);
      sim->set_simd_register_by_lane<FP_Type>(dst, i, res);
    }
  }
}

#define CASE(i, type, op)                                          \
  case i:                                                          \
    FPMinMaxForEachLane<type>(this, op<type>, r1, r2, r3, m5, m6); \
    break;
EVALUATE(VFMIN) {
  DCHECK(CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1));
  DCHECK_OPCODE(VFMIN);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  switch (m4) {
    CASE(2, float, FPMin);
    CASE(3, double, FPMin);
    default:
      UNIMPLEMENTED();
  }
  return length;
}

EVALUATE(VFMAX) {
  DCHECK(CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1));
  DCHECK_OPCODE(VFMAX);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  switch (m4) {
    CASE(2, float, FPMax);
    CASE(3, double, FPMax);
    default:
      UNIMPLEMENTED();
  }
  return length;
}
#undef CASE

template <class S, class D, class Operation>
void VectorFPCompare(Simulator* sim, int dst, int src1, int src2, int m6,
                     Operation op) {
  static_assert(sizeof(S) == sizeof(D),
                "Expect input type size == output type size");
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
```