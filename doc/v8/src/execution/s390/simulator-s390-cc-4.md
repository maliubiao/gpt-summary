Response:
The user wants me to analyze a C++ source code snippet from the V8 JavaScript engine, specifically the `simulator-s390.cc` file. I need to identify its functionalities based on the provided code.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:** The filename `simulator-s390.cc` strongly suggests that this code is part of a simulator for the s390 architecture within V8. Simulators are used for development and testing when the actual hardware isn't readily available or for exploring different architectural features.

2. **Analyze the `EVALUATE` Macros:**  The code heavily uses macros like `EVALUATE(VME)`, `EVALUATE(VMO)`, etc. The names inside the parentheses (e.g., `VME`, `VMO`) likely correspond to specific s390 vector instructions. The `EVALUATE` macro probably defines a function or a code block that simulates the behavior of that instruction.

3. **Examine Instruction Decoding:**  Inside each `EVALUATE` block, there are calls to `DECODE_VRR_C_INSTRUCTION`, `DECODE_VRR_B_INSTRUCTION`, etc. These macros are responsible for parsing the instruction's operands (registers, immediate values, etc.) from the instruction stream. The suffixes like `_C`, `_B`, `_A`, `_E` likely indicate different instruction formats.

4. **Recognize Vector Operations:**  The code deals with `simd_register` and operations on individual "lanes" within these registers. Functions like `get_simd_register_by_lane` and `set_simd_register_by_lane` are key indicators of vector processing.

5. **Categorize Operations:** By looking at the names of the `EVALUATE` blocks and the operations performed within them, I can start to categorize the functionalities:
    * **Arithmetic:** `VME`, `VMO`, `VMLE`, `VMLO` (multiply)
    * **Logical:** `VNC` (AND NOT), `VSUM`, `VSUMG` (sum), `VO` (OR), `VN` (AND), `VX` (XOR), `VNO` (NOR)
    * **Data Movement/Manipulation:** `VMRL`, `VMRH` (merge), `VPK`, `VPKS`, `VPKLS` (pack), `VUPH`, `VUPLH`, `VUPL`, `VUPLL` (unpack), `VPERM`, `VBPERM`, `VSEL` (permute/select)
    * **Bit Manipulation:** `VPOPCT` (population count)
    * **Type Conversion:** `VCDG`, `VCDLG`, `VCGD`, `VCLGD` (convert data types)
    * **Comparison:** `VMX`, `VMXL`, `VMN`, `VMNL` (min/max), `VCEQ`, `VCH`, `VCHL` (compare)
    * **Shifts:** `VESL`, `VESRA`, `VESRL`, `VESLV`, `VESRAV`, `VESRLV` (shift operations)
    * **Conditional:** `VTM` (test under mask)
    * **Floating-Point:** `VFA`, `VFS`, `VFM`, `VFD` (add, subtract, multiply, divide), `VFMA`, `VFNMS` (fused multiply-add/subtract), `VFMIN`, `VFMAX` (min/max)
    * **Load Complement:** `VLC`

6. **Address Specific Questions:**

    * **`.tq` Extension:** The code snippet is C++, not Torque, so the answer is straightforward.
    * **Relationship to JavaScript:** Since this is a simulator for the s390 architecture within V8, it directly relates to how JavaScript code *could* be executed on s390 if the V8 engine were targeting that architecture. However, this is simulation code, not the actual JavaScript execution logic. I need to come up with a conceptual JavaScript example that *could* potentially be optimized using some of these vector instructions if the underlying architecture supported them.
    * **Code Logic Inference:** Choose a simple operation, like `VNC` (bitwise AND NOT), and provide sample input and output values for the registers.
    * **Common Programming Errors:** Think about potential pitfalls when dealing with vector operations, such as incorrect assumptions about lane sizes or data types, or not handling edge cases.
    * **Summary:**  Combine the categorized functionalities into a concise summary of the file's purpose.

7. **Refine and Organize:** Structure the answer logically, addressing each part of the user's request clearly. Use appropriate terminology and provide code examples where necessary.

By following these steps, I can generate a comprehensive and accurate response to the user's query.
```cpp
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
  D
### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                "Expect input type size == output typ
```