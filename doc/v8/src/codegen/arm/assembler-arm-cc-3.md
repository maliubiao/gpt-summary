Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/arm/assembler-arm.cc`. I need to analyze the code and identify its purpose. The code mainly deals with generating ARM assembly instructions, particularly those related to VFP (Vector Floating Point) and NEON (Advanced SIMD) units.

Here's a breakdown of the functionalities and how to address each part of the user's request:

1. **List the functionalities:** The code defines methods within the `Assembler` class to emit specific ARM/NEON/VFP instructions. These instructions perform operations like moving data, converting data types, and performing arithmetic/logical operations on floating-point and SIMD registers.

2. **Check for .tq extension:** The provided code snippet is C++, not Torque, so this condition is false.

3. **Relate to Javascript:**  V8 compiles Javascript code into machine code. Operations on floating-point numbers in Javascript (e.g., addition, subtraction, multiplication, division, comparisons, square roots) often translate to the VFP/NEON instructions defined in this code. I can provide a simple Javascript example and show how it might conceptually map to these instructions.

4. **Code logic and I/O:** The functions are primarily about instruction encoding. The "input" is the desired operation and the registers/immediate values involved, and the "output" is the encoded machine instruction. I can provide an example with a specific `vmov` instruction.

5. **Common programming errors:**  This code is low-level and used internally by the compiler. Common errors related to these instructions would occur during compiler development (e.g., incorrect encoding). From a Javascript perspective, errors might arise from incorrect type handling that leads to unexpected floating-point behavior (although this code doesn't directly handle those errors).

6. **Summarize the functionality (Part 4 of 6):**  Given this is part 4, I should focus on the functionality within this specific snippet, which is heavily focused on VFP/NEON instructions for data movement and some arithmetic/comparison operations.

**Plan:**

*   Identify the main categories of instructions covered in the snippet (data movement, conversions, arithmetic, comparisons).
*   For the Javascript example, choose a simple floating-point operation.
*   For the code logic, demonstrate a basic `vmov` with specific register names and an immediate value.
*   For common errors, focus on conceptual Javascript errors related to floating-point.
*   Summarize the functionality based on the instructions present in this segment.
这是 `v8/src/codegen/arm/assembler-arm.cc` 源代码的**第四部分**，主要集中在为 ARM 架构生成**浮点 (VFP - Vector Floating Point) 和 SIMD (NEON)** 指令的功能。

**功能归纳:**

这部分代码定义了 `Assembler` 类中的方法，用于生成以下类型的 ARM/VFP/NEON 指令：

*   **数据移动指令 (vmov):**
    *   在 NEON 寄存器之间移动数据 (`vmov(const QwNeonRegister dst, const QwNeonRegister src)`)。
    *   将立即数加载到 NEON 寄存器 (`vmov(const QwNeonRegister dst, uint64_t imm)`).
    *   将立即数加载到 VFP 单精度和双精度寄存器 (`vmov(const SwVfpRegister dst, Float32 imm)`, `vmov(const DwVfpRegister dst, base::Double imm, ...)`). 支持特定的浮点立即数编码优化。
    *   在 VFP 寄存器之间移动数据 (`vmov(const SwVfpRegister dst, const SwVfpRegister src, ...)`, `vmov(const DwVfpRegister dst, const DwVfpRegister src, ...)`).
    *   在 VFP 寄存器和 ARM 通用寄存器之间移动数据 (`vmov(const DwVfpRegister dst, const Register src1, const Register src2, ...)`, `vmov(const Register dst1, const Register dst2, const DwVfpRegister src, ...)`, `vmov(const SwVfpRegister dst, const Register src, ...)`, `vmov(const Register dst, const SwVfpRegister src, ...)`).

*   **数据类型转换指令 (vcvt):**
    *   在浮点数和整数之间进行转换 (`vcvt_f64_s32`, `vcvt_f32_s32`, `vcvt_f64_u32`, `vcvt_f32_u32`, `vcvt_s32_f32`, `vcvt_u32_f32`, `vcvt_s32_f64`, `vcvt_u32_f64`).
    *   在单精度和双精度浮点数之间进行转换 (`vcvt_f64_f32`, `vcvt_f32_f64`).
    *   将浮点数转换为具有指定小数位数的定点数 (`vcvt_f64_s32(const DwVfpRegister dst, int fraction_bits, ...)`).

*   **算术运算指令:**
    *   取反 (`vneg`).
    *   绝对值 (`vabs`).
    *   加法 (`vadd`).
    *   减法 (`vsub`).
    *   乘法 (`vmul`).
    *   乘法累加 (`vmla`).
    *   乘法减法 (`vmls`).
    *   除法 (`vdiv`).
    *   最大值 (忽略 NaN) (`vmaxnm`).
    *   最小值 (忽略 NaN) (`vminnm`).
    *   条件选择 (`vsel`).
    *   平方根 (`vsqrt`).

*   **比较指令 (vcmp):**
    *   比较两个 VFP 寄存器 (`vcmp(const DwVfpRegister src1, const DwVfpRegister src2, ...)`, `vcmp(const SwVfpRegister src1, const SwVfpRegister src2, ...)`).
    *   比较 VFP 寄存器与零 (`vcmp(const DwVfpRegister src1, const double src2, ...)`, `vcmp(const SwVfpRegister src1, const float src2, ...)`).

*   **其他指令:**
    *   将 VFP 状态寄存器的内容移动到 ARM 通用寄存器 (`vmsr`).

**关于代码特征：**

*   **`UNIMPLEMENTED()`:**  表示某些功能尚未实现或当前代码路径不支持。
*   **`CpuFeatures::IsSupported(NEON)` 和 `CpuFeatureScope`:**  这些用于检查当前 CPU 是否支持特定的特性（如 NEON 或 VFPv3），并确保只有在支持的情况下才生成相应的指令。
*   **位域操作 (如 `B23`, `B22` 等):**  这些常量用于构造机器码指令，通过位移和按位或操作设置指令的不同字段。
*   **寄存器编码:** 代码中经常出现将 VFP 寄存器拆分成 `vd`, `d`, `vm`, `m` 等部分，这是因为 ARM 的 VFP 寄存器编码方式需要将寄存器号分解成不同的位域。

**与 Javascript 的关系:**

这段代码是 V8 引擎将 Javascript 代码编译成 ARM 机器码的一部分。当 Javascript 代码执行涉及浮点数或 SIMD 操作时，V8 的编译器会生成相应的 VFP 或 NEON 指令。

**Javascript 示例:**

```javascript
function add_floats(a, b) {
  return a + b;
}

let result = add_floats(3.14, 2.71);
console.log(result);
```

在这个简单的 Javascript 函数中，`a + b` 的浮点数加法操作，在 ARM 架构上，V8 可能会生成类似 `vadd.f64 Dd, Dn, Dm` (如果使用双精度浮点数) 或 `vadd.f32 Sd, Sn, Sm` (如果使用单精度浮点数) 的指令。这里的 `Dd`, `Dn`, `Dm` 和 `Sd`, `Sn`, `Sm` 代表 VFP 寄存器。`assembler-arm.cc` 中的 `Assembler::vadd` 方法就负责生成这些指令的机器码。

**代码逻辑推理 (假设输入与输出):**

假设我们要生成将立即数 `3.0` 加载到单精度 VFP 寄存器 `s0` 的指令。

**假设输入:**
*   `dst`: `s0` (SwVfpRegister)
*   `imm`: `3.0f` (Float32)

**代码逻辑 (简化):**

1. `Assembler::vmov(const SwVfpRegister dst, Float32 imm)` 被调用。
2. `FitsVmovFPImmediate` 检查 `3.0f` 是否能被编码为 VFP 的立即数。在这个例子中，`3.0` 不能直接编码为 VFP 立即数。
3. 进入 `else` 分支。
4. `UseScratchRegisterScope` 获取一个临时寄存器，例如 `r0`。
5. `mov(scratch, Operand(imm.get_bits()))` 生成指令将 `3.0f` 的位表示加载到 `r0` 中。
6. `vmov(dst, scratch)` 生成指令将 `r0` 中的值移动到 `s0` 寄存器。 这会调用 `Assembler::vmov(const SwVfpRegister dst, const Register src, const Condition cond)`.

**可能的输出 (汇编指令序列):**

```assembly
mov r0, #0x40400000  // 3.0f 的 IEEE 754 表示
vmov s0, r0
```

**用户常见的编程错误:**

这段代码是编译器内部的代码，用户通常不会直接与之交互。但是，了解这些底层指令可以帮助理解一些与浮点数相关的常见错误：

*   **精度问题:** 浮点数的表示是有限的，进行多次运算可能会累积误差。例如，连续进行小数值的加法或乘法可能导致结果与预期略有偏差。
*   **NaN (Not a Number) 和 Infinity:**  某些操作（如除以零、对负数开平方根）会产生 NaN 或 Infinity。不正确地处理这些特殊值可能导致程序出现意外行为。
*   **浮点数比较:**  由于精度问题，直接使用 `==` 比较两个浮点数是否相等通常是不可靠的。应该使用一个小的容差值（epsilon）来判断两个浮点数是否足够接近。

**示例 (Javascript 中可能导致相关 VFP 指令执行的错误概念):**

```javascript
let a = 0.1 + 0.2;
console.log(a == 0.3); // 输出 false，因为浮点数表示的精度问题

let b = 1.0 / 0.0;
console.log(b); // 输出 Infinity

let c = Math.sqrt(-1);
console.log(c); // 输出 NaN
```

在 V8 内部，执行这些 Javascript 代码时，可能会生成涉及到浮点数运算的 VFP 指令，而浮点数运算的特性会导致上述的精度问题和特殊值。这段 C++ 代码正是用来生成这些底层 VFP 指令的。

Prompt: 
```
这是目录为v8/src/codegen/arm/assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
e {
    UNIMPLEMENTED();
  }
}

void Assembler::vmov(const QwNeonRegister dst, uint64_t imm) {
  uint32_t enc;
  uint8_t cmode;
  uint8_t op = 0;
  if (CpuFeatures::IsSupported(NEON) && FitsVmovIntImm(imm, &enc, &cmode)) {
    CpuFeatureScope scope(this, NEON);
    // Instruction details available in ARM DDI 0406C.b, A8-937.
    // 001i1(27-23) | D(22) | 000(21-19) | imm3(18-16) | Vd(15-12) | cmode(11-8)
    // | 0(7) | Q(6) | op(5) | 4(1) | imm4(3-0)
    int vd, d;
    dst.split_code(&vd, &d);
    emit(kSpecialCondition | 0x05 * B23 | d * B22 | vd * B12 | cmode * B8 |
         0x1 * B6 | op * B5 | 0x1 * B4 | enc);
  } else {
    UNIMPLEMENTED();
  }
}

// Only works for little endian floating point formats.
// We don't support VFP on the mixed endian floating point platform.
static bool FitsVmovFPImmediate(base::Double d, uint32_t* encoding) {
  // VMOV can accept an immediate of the form:
  //
  //  +/- m * 2^(-n) where 16 <= m <= 31 and 0 <= n <= 7
  //
  // The immediate is encoded using an 8-bit quantity, comprised of two
  // 4-bit fields. For an 8-bit immediate of the form:
  //
  //  [abcdefgh]
  //
  // where a is the MSB and h is the LSB, an immediate 64-bit double can be
  // created of the form:
  //
  //  [aBbbbbbb,bbcdefgh,00000000,00000000,
  //      00000000,00000000,00000000,00000000]
  //
  // where B = ~b.
  //

  uint32_t lo, hi;
  DoubleAsTwoUInt32(d, &lo, &hi);

  // The most obvious constraint is the long block of zeroes.
  if ((lo != 0) || ((hi & 0xFFFF) != 0)) {
    return false;
  }

  // Bits 61:54 must be all clear or all set.
  if (((hi & 0x3FC00000) != 0) && ((hi & 0x3FC00000) != 0x3FC00000)) {
    return false;
  }

  // Bit 62 must be NOT bit 61.
  if (((hi ^ (hi << 1)) & (0x40000000)) == 0) {
    return false;
  }

  // Create the encoded immediate in the form:
  //  [00000000,0000abcd,00000000,0000efgh]
  *encoding = (hi >> 16) & 0xF;       // Low nybble.
  *encoding |= (hi >> 4) & 0x70000;   // Low three bits of the high nybble.
  *encoding |= (hi >> 12) & 0x80000;  // Top bit of the high nybble.

  return true;
}

void Assembler::vmov(const SwVfpRegister dst, Float32 imm) {
  uint32_t enc;
  if (CpuFeatures::IsSupported(VFPv3) &&
      FitsVmovFPImmediate(base::Double(imm.get_scalar()), &enc)) {
    CpuFeatureScope scope(this, VFPv3);
    // The float can be encoded in the instruction.
    //
    // Sd = immediate
    // Instruction details available in ARM DDI 0406C.b, A8-936.
    // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | imm4H(19-16) |
    // Vd(15-12) | 101(11-9) | sz=0(8) | imm4L(3-0)
    int vd, d;
    dst.split_code(&vd, &d);
    emit(al | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | enc);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    mov(scratch, Operand(imm.get_bits()));
    vmov(dst, scratch);
  }
}

void Assembler::vmov(const DwVfpRegister dst, base::Double imm,
                     const Register extra_scratch) {
  DCHECK(VfpRegisterIsAvailable(dst));
  uint32_t enc;
  if (CpuFeatures::IsSupported(VFPv3) && FitsVmovFPImmediate(imm, &enc)) {
    CpuFeatureScope scope(this, VFPv3);
    // The double can be encoded in the instruction.
    //
    // Dd = immediate
    // Instruction details available in ARM DDI 0406C.b, A8-936.
    // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | imm4H(19-16) |
    // Vd(15-12) | 101(11-9) | sz=1(8) | imm4L(3-0)
    int vd, d;
    dst.split_code(&vd, &d);
    emit(al | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B8 |
         enc);
  } else {
    // Synthesise the double from ARM immediates.
    uint32_t lo, hi;
    DoubleAsTwoUInt32(imm, &lo, &hi);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();

    if (lo == hi) {
      // Move the low and high parts of the double to a D register in one
      // instruction.
      mov(scratch, Operand(lo));
      vmov(dst, scratch, scratch);
    } else if (extra_scratch == no_reg) {
      // We only have one spare scratch register.
      mov(scratch, Operand(lo));
      vmov(NeonS32, dst, 0, scratch);
      if (((lo & 0xFFFF) == (hi & 0xFFFF)) && CpuFeatures::IsSupported(ARMv7)) {
        CpuFeatureScope scope(this, ARMv7);
        movt(scratch, hi >> 16);
      } else {
        mov(scratch, Operand(hi));
      }
      vmov(NeonS32, dst, 1, scratch);
    } else {
      // Move the low and high parts of the double to a D register in one
      // instruction.
      mov(scratch, Operand(lo));
      mov(extra_scratch, Operand(hi));
      vmov(dst, scratch, extra_scratch);
    }
  }
}

void Assembler::vmov(const SwVfpRegister dst, const SwVfpRegister src,
                     const Condition cond) {
  // Sd = Sm
  // Instruction details available in ARM DDI 0406B, A8-642.
  int sd, d, sm, m;
  dst.split_code(&sd, &d);
  src.split_code(&sm, &m);
  emit(cond | 0xE * B24 | d * B22 | 0xB * B20 | sd * B12 | 0xA * B8 | B6 |
       m * B5 | sm);
}

void Assembler::vmov(const DwVfpRegister dst, const DwVfpRegister src,
                     const Condition cond) {
  // Dd = Dm
  // Instruction details available in ARM DDI 0406C.b, A8-938.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0000(19-16) | Vd(15-12) |
  // 101(11-9) | sz=1(8) | 0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B8 | B6 |
       m * B5 | vm);
}

void Assembler::vmov(const DwVfpRegister dst, const Register src1,
                     const Register src2, const Condition cond) {
  // Dm = <Rt,Rt2>.
  // Instruction details available in ARM DDI 0406C.b, A8-948.
  // cond(31-28) | 1100(27-24)| 010(23-21) | op=0(20) | Rt2(19-16) |
  // Rt(15-12) | 1011(11-8) | 00(7-6) | M(5) | 1(4) | Vm
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(src1 != pc && src2 != pc);
  int vm, m;
  dst.split_code(&vm, &m);
  emit(cond | 0xC * B24 | B22 | src2.code() * B16 | src1.code() * B12 |
       0xB * B8 | m * B5 | B4 | vm);
}

void Assembler::vmov(const Register dst1, const Register dst2,
                     const DwVfpRegister src, const Condition cond) {
  // <Rt,Rt2> = Dm.
  // Instruction details available in ARM DDI 0406C.b, A8-948.
  // cond(31-28) | 1100(27-24)| 010(23-21) | op=1(20) | Rt2(19-16) |
  // Rt(15-12) | 1011(11-8) | 00(7-6) | M(5) | 1(4) | Vm
  DCHECK(VfpRegisterIsAvailable(src));
  DCHECK(dst1 != pc && dst2 != pc);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0xC * B24 | B22 | B20 | dst2.code() * B16 | dst1.code() * B12 |
       0xB * B8 | m * B5 | B4 | vm);
}

void Assembler::vmov(const SwVfpRegister dst, const Register src,
                     const Condition cond) {
  // Sn = Rt.
  // Instruction details available in ARM DDI 0406A, A8-642.
  // cond(31-28) | 1110(27-24)| 000(23-21) | op=0(20) | Vn(19-16) |
  // Rt(15-12) | 1010(11-8) | N(7)=0 | 00(6-5) | 1(4) | 0000(3-0)
  DCHECK(src != pc);
  int sn, n;
  dst.split_code(&sn, &n);
  emit(cond | 0xE * B24 | sn * B16 | src.code() * B12 | 0xA * B8 | n * B7 | B4);
}

void Assembler::vmov(const Register dst, const SwVfpRegister src,
                     const Condition cond) {
  // Rt = Sn.
  // Instruction details available in ARM DDI 0406A, A8-642.
  // cond(31-28) | 1110(27-24)| 000(23-21) | op=1(20) | Vn(19-16) |
  // Rt(15-12) | 1010(11-8) | N(7)=0 | 00(6-5) | 1(4) | 0000(3-0)
  DCHECK(dst != pc);
  int sn, n;
  src.split_code(&sn, &n);
  emit(cond | 0xE * B24 | B20 | sn * B16 | dst.code() * B12 | 0xA * B8 |
       n * B7 | B4);
}

// Type of data to read from or write to VFP register.
// Used as specifier in generic vcvt instruction.
enum VFPType { S32, U32, F32, F64 };

static bool IsSignedVFPType(VFPType type) {
  switch (type) {
    case S32:
      return true;
    case U32:
      return false;
    default:
      UNREACHABLE();
  }
}

static bool IsIntegerVFPType(VFPType type) {
  switch (type) {
    case S32:
    case U32:
      return true;
    case F32:
    case F64:
      return false;
    default:
      UNREACHABLE();
  }
}

static bool IsDoubleVFPType(VFPType type) {
  switch (type) {
    case F32:
      return false;
    case F64:
      return true;
    default:
      UNREACHABLE();
  }
}

// Split five bit reg_code based on size of reg_type.
//  32-bit register codes are Vm:M
//  64-bit register codes are M:Vm
// where Vm is four bits, and M is a single bit.
static void SplitRegCode(VFPType reg_type, int reg_code, int* vm, int* m) {
  DCHECK((reg_code >= 0) && (reg_code <= 31));
  if (IsIntegerVFPType(reg_type) || !IsDoubleVFPType(reg_type)) {
    SwVfpRegister::split_code(reg_code, vm, m);
  } else {
    DwVfpRegister::split_code(reg_code, vm, m);
  }
}

// Encode vcvt.src_type.dst_type instruction.
static Instr EncodeVCVT(const VFPType dst_type, const int dst_code,
                        const VFPType src_type, const int src_code,
                        VFPConversionMode mode, const Condition cond) {
  DCHECK(src_type != dst_type);
  int D, Vd, M, Vm;
  SplitRegCode(src_type, src_code, &Vm, &M);
  SplitRegCode(dst_type, dst_code, &Vd, &D);

  if (IsIntegerVFPType(dst_type) || IsIntegerVFPType(src_type)) {
    // Conversion between IEEE floating point and 32-bit integer.
    // Instruction details available in ARM DDI 0406B, A8.6.295.
    // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 1(19) | opc2(18-16) |
    // Vd(15-12) | 101(11-9) | sz(8) | op(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
    DCHECK(!IsIntegerVFPType(dst_type) || !IsIntegerVFPType(src_type));

    int sz, opc2, op;

    if (IsIntegerVFPType(dst_type)) {
      opc2 = IsSignedVFPType(dst_type) ? 0x5 : 0x4;
      sz = IsDoubleVFPType(src_type) ? 0x1 : 0x0;
      op = mode;
    } else {
      DCHECK(IsIntegerVFPType(src_type));
      opc2 = 0x0;
      sz = IsDoubleVFPType(dst_type) ? 0x1 : 0x0;
      op = IsSignedVFPType(src_type) ? 0x1 : 0x0;
    }

    return (cond | 0xE * B24 | B23 | D * B22 | 0x3 * B20 | B19 | opc2 * B16 |
            Vd * B12 | 0x5 * B9 | sz * B8 | op * B7 | B6 | M * B5 | Vm);
  } else {
    // Conversion between IEEE double and single precision.
    // Instruction details available in ARM DDI 0406B, A8.6.298.
    // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0111(19-16) |
    // Vd(15-12) | 101(11-9) | sz(8) | 1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
    int sz = IsDoubleVFPType(src_type) ? 0x1 : 0x0;
    return (cond | 0xE * B24 | B23 | D * B22 | 0x3 * B20 | 0x7 * B16 |
            Vd * B12 | 0x5 * B9 | sz * B8 | B7 | B6 | M * B5 | Vm);
  }
}

void Assembler::vcvt_f64_s32(const DwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(dst));
  emit(EncodeVCVT(F64, dst.code(), S32, src.code(), mode, cond));
}

void Assembler::vcvt_f32_s32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(F32, dst.code(), S32, src.code(), mode, cond));
}

void Assembler::vcvt_f64_u32(const DwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(dst));
  emit(EncodeVCVT(F64, dst.code(), U32, src.code(), mode, cond));
}

void Assembler::vcvt_f32_u32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(F32, dst.code(), U32, src.code(), mode, cond));
}

void Assembler::vcvt_s32_f32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(S32, dst.code(), F32, src.code(), mode, cond));
}

void Assembler::vcvt_u32_f32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(U32, dst.code(), F32, src.code(), mode, cond));
}

void Assembler::vcvt_s32_f64(const SwVfpRegister dst, const DwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeVCVT(S32, dst.code(), F64, src.code(), mode, cond));
}

void Assembler::vcvt_u32_f64(const SwVfpRegister dst, const DwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeVCVT(U32, dst.code(), F64, src.code(), mode, cond));
}

void Assembler::vcvt_f64_f32(const DwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(dst));
  emit(EncodeVCVT(F64, dst.code(), F32, src.code(), mode, cond));
}

void Assembler::vcvt_f32_f64(const SwVfpRegister dst, const DwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeVCVT(F32, dst.code(), F64, src.code(), mode, cond));
}

void Assembler::vcvt_f64_s32(const DwVfpRegister dst, int fraction_bits,
                             const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-874.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 1010(19-16) | Vd(15-12) |
  // 101(11-9) | sf=1(8) | sx=1(7) | 1(6) | i(5) | 0(4) | imm4(3-0)
  DCHECK(IsEnabled(VFPv3));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(fraction_bits > 0 && fraction_bits <= 32);
  int vd, d;
  dst.split_code(&vd, &d);
  int imm5 = 32 - fraction_bits;
  int i = imm5 & 1;
  int imm4 = (imm5 >> 1) & 0xF;
  emit(cond | 0xE * B24 | B23 | d * B22 | 0x3 * B20 | B19 | 0x2 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B7 | B6 | i * B5 | imm4);
}

void Assembler::vneg(const DwVfpRegister dst, const DwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-968.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0001(19-16) | Vd(15-12) |
  // 101(11-9) | sz=1(8) | 0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);

  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       B8 | B6 | m * B5 | vm);
}

void Assembler::vneg(const SwVfpRegister dst, const SwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-968.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0001(19-16) | Vd(15-12) |
  // 101(11-9) | sz=0(8) | 0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);

  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       B6 | m * B5 | vm);
}

void Assembler::vabs(const DwVfpRegister dst, const DwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-524.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0000(19-16) | Vd(15-12) |
  // 101(11-9) | sz=1(8) | 1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B8 | B7 |
       B6 | m * B5 | vm);
}

void Assembler::vabs(const SwVfpRegister dst, const SwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-524.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0000(19-16) | Vd(15-12) |
  // 101(11-9) | sz=0(8) | 1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B7 | B6 |
       m * B5 | vm);
}

void Assembler::vadd(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vadd(Dn, Dm) double precision floating point addition.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-830.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | m * B5 | vm);
}

void Assembler::vadd(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vadd(Sn, Sm) single precision floating point addition.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-830.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | m * B5 | vm);
}

void Assembler::vsub(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vsub(Dn, Dm) double precision floating point subtraction.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-1086.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vsub(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vsub(Sn, Sm) single precision floating point subtraction.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-1086.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vmul(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vmul(Dn, Dm) double precision floating point multiplication.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  // cond(31-28) | 11100(27-23)| D(22) | 10(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x2 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmul(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vmul(Sn, Sm) single precision floating point multiplication.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  // cond(31-28) | 11100(27-23)| D(22) | 10(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x2 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | m * B5 | vm);
}

void Assembler::vmla(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | op=0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | B8 |
       n * B7 | m * B5 | vm);
}

void Assembler::vmla(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | op=0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | n * B7 |
       m * B5 | vm);
}

void Assembler::vmls(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | op=1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | B8 |
       n * B7 | B6 | m * B5 | vm);
}

void Assembler::vmls(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | op=1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | n * B7 |
       B6 | m * B5 | vm);
}

void Assembler::vdiv(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vdiv(Dn, Dm) double precision floating point division.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-882.
  // cond(31-28) | 11101(27-23)| D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | B8 |
       n * B7 | m * B5 | vm);
}

void Assembler::vdiv(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vdiv(Sn, Sm) single precision floating point division.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-882.
  // cond(31-28) | 11101(27-23)| D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | n * B7 |
       m * B5 | vm);
}

void Assembler::vcmp(const DwVfpRegister src1, const DwVfpRegister src2,
                     const Condition cond) {
  // vcmp(Dd, Dm) double precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0100(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | E=0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  src1.split_code(&vd, &d);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x4 * B16 | vd * B12 |
       0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vcmp(const SwVfpRegister src1, const SwVfpRegister src2,
                     const Condition cond) {
  // vcmp(Sd, Sm) single precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0100(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | E=0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  src1.split_code(&vd, &d);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x4 * B16 | vd * B12 |
       0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vcmp(const DwVfpRegister src1, const double src2,
                     const Condition cond) {
  // vcmp(Dd, #0.0) double precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0101(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | E=0(7) | 1(6) | 0(5) | 0(4) | 0000(3-0)
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK_EQ(src2, 0.0);
  int vd, d;
  src1.split_code(&vd, &d);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x5 * B16 | vd * B12 |
       0x5 * B9 | B8 | B6);
}

void Assembler::vcmp(const SwVfpRegister src1, const float src2,
                     const Condition cond) {
  // vcmp(Sd, #0.0) single precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0101(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | E=0(7) | 1(6) | 0(5) | 0(4) | 0000(3-0)
  DCHECK_EQ(src2, 0.0);
  int vd, d;
  src1.split_code(&vd, &d);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x5 * B16 | vd * B12 |
       0x5 * B9 | B6);
}

void Assembler::vmaxnm(const DwVfpRegister dst, const DwVfpRegister src1,
                       const DwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmaxnm(const SwVfpRegister dst, const SwVfpRegister src1,
                       const SwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | m * B5 | vm);
}

void Assembler::vminnm(const DwVfpRegister dst, const DwVfpRegister src1,
                       const DwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vminnm(const SwVfpRegister dst, const SwVfpRegister src1,
                       const SwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vsel(Condition cond, const DwVfpRegister dst,
                     const DwVfpRegister src1, const DwVfpRegister src2) {
  // cond=kSpecialCondition(31-28) | 11100(27-23) | D(22) |
  // vsel_cond=XX(21-20) | Vn(19-16) | Vd(15-12) | 101(11-9) | sz=1(8) | N(7) |
  // 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int sz = 1;

  // VSEL has a special (restricted) condition encoding.
  //   eq(0b0000)... -> 0b00
  //   ge(0b1010)... -> 0b10
  //   gt(0b1100)... -> 0b11
  //   vs(0b0110)... -> 0b01
  // No other conditions are supported.
  int vsel_cond = (cond >> 30) & 0x3;
  if ((cond != eq) && (cond != ge) && (cond != gt) && (cond != vs)) {
    // We can implement some other conditions by swapping the inputs.
    DCHECK((cond == ne) | (cond == lt) | (cond == le) | (cond == vc));
    std::swap(vn, vm);
    std::swap(n, m);
  }

  emit(kSpecialCondition | 0x1C * B23 | d * B22 | vsel_cond * B20 | vn * B16 |
       vd * B12 | 0x5 * B9 | sz * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vsel(Condition cond, const SwVfpRegister dst,
                     const SwVfpRegister src1, const SwVfpRegister src2) {
  // cond=kSpecialCondition(31-28) | 11100(27-23) | D(22) |
  // vsel_cond=XX(21-20) | Vn(19-16) | Vd(15-12) | 101(11-9) | sz=0(8) | N(7) |
  // 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int sz = 0;

  // VSEL has a special (restricted) condition encoding.
  //   eq(0b0000)... -> 0b00
  //   ge(0b1010)... -> 0b10
  //   gt(0b1100)... -> 0b11
  //   vs(0b0110)... -> 0b01
  // No other conditions are supported.
  int vsel_cond = (cond >> 30) & 0x3;
  if ((cond != eq) && (cond != ge) && (cond != gt) && (cond != vs)) {
    // We can implement some other conditions by swapping the inputs.
    DCHECK((cond == ne) | (cond == lt) | (cond == le) | (cond == vc));
    std::swap(vn, vm);
    std::swap(n, m);
  }

  emit(kSpecialCondition | 0x1C * B23 | d * B22 | vsel_cond * B20 | vn * B16 |
       vd * B12 | 0x5 * B9 | sz * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vsqrt(const DwVfpRegister dst, const DwVfpRegister src,
                      const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-1058.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0001(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | 11(7-6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       B8 | 0x3 * B6 | m * B5 | vm);
}

void Assembler::vsqrt(const SwVfpRegister dst, const SwVfpRegister src,
                      const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-1058.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0001(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | 11(7-6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       0x3 * B6 | m * B5 | vm);
}

void Assembler::vmsr(Register dst, Condition cond) {
  // Instruction details available in ARM DDI 0406A, A8-652.
  // cond(31-28) | 1110 (27-24) | 1110(23-20)| 0001 (19-16) |
  // Rt(15-12) | 1010 (11-8) | 0(7) | 00 (6-5) | 1(4) | 0000(3-0)
  emit(cond | 0xE * B24 | 0xE * B20 | B16 
"""


```