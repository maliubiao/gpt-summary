Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part 3 of a larger file. The file path `v8/src/codegen/arm/assembler-arm.cc` suggests this code is related to the ARM architecture code generation within the V8 JavaScript engine.

The code consists of several methods within an `Assembler` class. These methods seem to correspond to individual ARM assembly instructions, especially those related to VFP (Vector Floating Point) and NEON (Advanced SIMD) extensions. They take register operands (both scalar and vector) and other parameters, then emit the corresponding machine code.

To illustrate the connection to JavaScript, I need to identify a pattern in the provided assembly instructions and show how a JavaScript operation might be compiled down to these instructions. The NEON instructions seem particularly relevant, as they deal with vector operations, which are often used to optimize JavaScript array manipulations.

**Plan:**

1. **Identify the core functionality:** The code is about emitting ARM assembly instructions, particularly for floating-point and SIMD operations.
2. **Find a representative example:** Look for a NEON instruction and its corresponding C++ method.
3. **Connect it to a JavaScript operation:**  Consider a JavaScript operation that could benefit from vectorization and show how it might translate to the chosen NEON instruction.
This C++代码文件是V8 JavaScript引擎中ARM架构汇编器（Assembler）的一部分， 专门负责生成ARMv7及更高版本架构上的浮点（VFP）和SIMD（NEON）指令的机器码。

**主要功能归纳:**

* **封装ARMv7/ARMv8浮点和NEON指令:**  该文件包含了一系列C++方法，每个方法对应一个或一组特定的ARM浮点或NEON指令。这些方法接收表示寄存器、内存地址、立即数等操作数的参数。
* **生成机器码:**  每个方法的核心功能是将传入的参数编码成符合ARM指令格式的32位机器码，并通过 `emit()` 方法将这些机器码写入到汇编器的缓冲区中。
* **支持不同数据类型和寄存器:** 代码中区分了单精度浮点寄存器 (`SwVfpRegister`)、双精度浮点寄存器 (`DwVfpRegister`) 以及NEON寄存器 (`QwNeonRegister`)，并根据指令的不同支持不同的数据类型，例如：整数 (`NeonS8`, `NeonU32`) 和浮点数 (`F32`).
* **实现各种浮点运算:**  包括绝对值 (`vabs`)、取反 (`vneg`)、舍入 (`vrinta`, `vrintn`, `vrintp`, `vrintz`)、类型转换 (`vcvt_f32_s32`, `vcvt_s32_f32`) 等。
* **实现各种NEON SIMD运算:** 包括加载/存储 (`vld1`, `vst1`)、数据复制 (`vdup`)、位运算 (`vand`, `vorr`, `veor`)、算术运算 (`vadd`, `vsub`, `vmul`, `vmin`, `vmax`)、移位操作 (`vshl`, `vshr`)、比较运算 (`vceq`, `vcge`, `vcgt`)、以及更高级的SIMD操作如通道操作 (`vzip`, `vuzp`, `vtrn`, `vext`)、累加 (`vpadal`) 等。

**与JavaScript功能的关系以及JavaScript示例:**

这个文件是V8引擎将JavaScript代码编译成机器码的关键部分。当V8优化JavaScript代码时，特别是涉及到数组操作、图形处理或需要并行计算的场景，它会尝试使用NEON指令来提高性能。

**JavaScript示例:**

假设有以下简单的JavaScript代码，对两个数组进行逐元素相加：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const array1 = [1.0, 2.0, 3.0, 4.0];
const array2 = [5.0, 6.0, 7.0, 8.0];
const sum = addArrays(array1, array2);
console.log(sum); // 输出: [6, 8, 10, 12]
```

在V8引擎的优化编译过程中，`addArrays` 函数内部的循环可以被向量化，利用NEON指令并行处理多个数组元素。  `Assembler::vadd` 等方法就会被用来生成相应的NEON加法指令。

例如，当处理单精度浮点数时，JavaScript中的 `a[i] + b[i]` 操作可能最终被编译成类似以下的ARM汇编指令（对应的C++方法是 `Assembler::vadd(QwNeonRegister dst, QwNeonRegister src1, QwNeonRegister src2)`）：

```assembly
vadd.f32 q0, q1, q2  // 将 q1 和 q2 寄存器中的浮点数向量相加，结果存储到 q0
```

这里的 `q0`, `q1`, `q2` 代表NEON的128位寄存器，可以一次性存储和处理多个单精度浮点数。 V8会加载 `a` 和 `b` 数组的部分元素到这些寄存器中，执行向量加法，然后将结果存储到 `result` 数组对应的内存位置。

其他NEON指令也会用于处理更复杂的JavaScript数组操作，例如，`vld1` 用于加载数组元素到NEON寄存器， `vst1` 用于将NEON寄存器中的数据存储回数组， `vmul` 用于向量乘法等等。

总而言之，这个C++代码文件是V8引擎生成高性能ARM机器码的关键组成部分，它直接支持了JavaScript在ARM架构上利用硬件加速进行浮点和SIMD运算，从而提升了JavaScript应用的执行效率，尤其是在处理大量数据时。

Prompt: 
```
这是目录为v8/src/codegen/arm/assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
| dst.code() * B12 | 0xA * B8 | B4);
}

void Assembler::vmrs(Register dst, Condition cond) {
  // Instruction details available in ARM DDI 0406A, A8-652.
  // cond(31-28) | 1110 (27-24) | 1111(23-20)| 0001 (19-16) |
  // Rt(15-12) | 1010 (11-8) | 0(7) | 00 (6-5) | 1(4) | 0000(3-0)
  emit(cond | 0xE * B24 | 0xF * B20 | B16 | dst.code() * B12 | 0xA * B8 | B4);
}

void Assembler::vrinta(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=00(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | vd * B12 |
       0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrinta(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=00(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | vd * B12 |
       0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintn(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=01(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x1 * B16 |
       vd * B12 | 0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrintn(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=01(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x1 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintp(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=10(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x2 * B16 |
       vd * B12 | 0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrintp(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=10(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x2 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintm(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=11(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x3 * B16 |
       vd * B12 | 0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrintm(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=11(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x3 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintz(const SwVfpRegister dst, const SwVfpRegister src,
                       const Condition cond) {
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 011(19-17) | 0(16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | op=1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x3 * B17 | vd * B12 |
       0x5 * B9 | B7 | B6 | m * B5 | vm);
}

void Assembler::vrintz(const DwVfpRegister dst, const DwVfpRegister src,
                       const Condition cond) {
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 011(19-17) | 0(16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | op=1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x3 * B17 | vd * B12 |
       0x5 * B9 | B8 | B7 | B6 | m * B5 | vm);
}

// Support for NEON.

void Assembler::vld1(NeonSize size, const NeonListOperand& dst,
                     const NeonMemOperand& src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.320.
  // 1111(31-28) | 01000(27-23) | D(22) | 10(21-20) | Rn(19-16) |
  // Vd(15-12) | type(11-8) | size(7-6) | align(5-4) | Rm(3-0)
  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | d * B22 | 2 * B20 | src.rn().code() * B16 |
       vd * B12 | dst.type() * B8 | size * B6 | src.align() * B4 |
       src.rm().code());
}

// vld1s(ingle element to one lane).
void Assembler::vld1s(NeonSize size, const NeonListOperand& dst, uint8_t index,
                      const NeonMemOperand& src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.322.
  // 1111(31-28) | 01001(27-23) | D(22) | 10(21-20) | Rn(19-16) |
  // Vd(15-12) | size(11-10) | index_align(7-4) | Rm(3-0)
  // See vld1 (single element to all lanes) if size == 0x3, implemented as
  // vld1r(eplicate).
  DCHECK_NE(size, 0x3);
  // Check for valid lane indices.
  DCHECK_GT(1 << (3 - size), index);
  // Specifying alignment not supported, use standard alignment.
  uint8_t index_align = index << (size + 1);

  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | 1 * B23 | d * B22 | 2 * B20 |
       src.rn().code() * B16 | vd * B12 | size * B10 | index_align * B4 |
       src.rm().code());
}

// vld1r(eplicate)
void Assembler::vld1r(NeonSize size, const NeonListOperand& dst,
                      const NeonMemOperand& src) {
  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | 1 * B23 | d * B22 | 2 * B20 |
       src.rn().code() * B16 | vd * B12 | 0xC * B8 | size * B6 |
       dst.length() * B5 | src.rm().code());
}

void Assembler::vst1(NeonSize size, const NeonListOperand& src,
                     const NeonMemOperand& dst) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.404.
  // 1111(31-28) | 01000(27-23) | D(22) | 00(21-20) | Rn(19-16) |
  // Vd(15-12) | type(11-8) | size(7-6) | align(5-4) | Rm(3-0)
  DCHECK(IsEnabled(NEON));
  int vd, d;
  src.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | d * B22 | dst.rn().code() * B16 | vd * B12 |
       src.type() * B8 | size * B6 | dst.align() * B4 | dst.rm().code());
}

void Assembler::vst1s(NeonSize size, const NeonListOperand& src, uint8_t index,
                      const NeonMemOperand& dst) {
  // Instruction details available in ARM DDI 0487F.b F6.1.236.
  // 1111(31-28) | 01001(27-23) | D(22) | 00(21-20) | Rn(19-16) |
  // Vd(15-12) | size(11-10) | 00(9-8) | index_align(7-4) | Rm(3-0)
  DCHECK(IsEnabled(NEON));
  DCHECK_NE(size, 0x3);
  DCHECK_GT(1 << (3 - size), index);
  // Specifying alignment not supported, use standard alignment.
  uint8_t index_align = index << (size + 1);
  int vd, d;
  src.base().split_code(&vd, &d);
  emit(0xFU * B28 | 9 * B23 | d * B22 | dst.rn().code() * B16 | vd * B12 |
       size * B10 | index_align * B4 | dst.rm().code());
}

void Assembler::vmovl(NeonDataType dt, QwNeonRegister dst, DwVfpRegister src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.346.
  // 1111(31-28) | 001(27-25) | U(24) | 1(23) | D(22) | imm3(21-19) |
  // 000(18-16) | Vd(15-12) | 101000(11-6) | M(5) | 1(4) | Vm(3-0)
  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  int U = NeonU(dt);
  int imm3 = 1 << NeonSz(dt);
  emit(0xFU * B28 | B25 | U * B24 | B23 | d * B22 | imm3 * B19 | vd * B12 |
       0xA * B8 | m * B5 | B4 | vm);
}

void Assembler::vqmovn(NeonDataType dst_dt, NeonDataType src_dt,
                       DwVfpRegister dst, QwNeonRegister src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.1004.
  // vqmovn.<type><size> Dd, Qm. ARM vector narrowing move with saturation.
  // vqmovun.<type><size> Dd, Qm. Same as above, but produces unsigned results.
  DCHECK(IsEnabled(NEON));
  DCHECK_IMPLIES(NeonU(src_dt), NeonU(dst_dt));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  int size = NeonSz(dst_dt);
  DCHECK_NE(3, size);
  int op = NeonU(src_dt) ? 0b11 : NeonU(dst_dt) ? 0b01 : 0b10;
  emit(0x1E7U * B23 | d * B22 | 0x3 * B20 | size * B18 | 0x2 * B16 | vd * B12 |
       0x2 * B8 | op * B6 | m * B5 | vm);
}

static int EncodeScalar(NeonDataType dt, int index) {
  int opc1_opc2 = 0;
  DCHECK_LE(0, index);
  switch (dt) {
    case NeonS8:
    case NeonU8:
      DCHECK_GT(8, index);
      opc1_opc2 = 0x8 | index;
      break;
    case NeonS16:
    case NeonU16:
      DCHECK_GT(4, index);
      opc1_opc2 = 0x1 | (index << 1);
      break;
    case NeonS32:
    case NeonU32:
      DCHECK_GT(2, index);
      opc1_opc2 = index << 2;
      break;
    default:
      UNREACHABLE();
  }
  return (opc1_opc2 >> 2) * B21 | (opc1_opc2 & 0x3) * B5;
}

void Assembler::vmov(NeonDataType dt, DwVfpRegister dst, int index,
                     Register src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.940.
  // vmov ARM core register to scalar.
  DCHECK(dt == NeonS32 || dt == NeonU32 || IsEnabled(NEON));
  int vd, d;
  dst.split_code(&vd, &d);
  int opc1_opc2 = EncodeScalar(dt, index);
  emit(0xEEu * B24 | vd * B16 | src.code() * B12 | 0xB * B8 | d * B7 | B4 |
       opc1_opc2);
}

void Assembler::vmov(NeonDataType dt, Register dst, DwVfpRegister src,
                     int index) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.942.
  // vmov Arm scalar to core register.
  DCHECK(dt == NeonS32 || dt == NeonU32 || IsEnabled(NEON));
  int vn, n;
  src.split_code(&vn, &n);
  int opc1_opc2 = EncodeScalar(dt, index);
  // NeonS32 and NeonU32 both encoded as u = 0.
  int u = NeonDataTypeToSize(dt) == Neon32 ? 0 : NeonU(dt);
  emit(0xEEu * B24 | u * B23 | B20 | vn * B16 | dst.code() * B12 | 0xB * B8 |
       n * B7 | B4 | opc1_opc2);
}

void Assembler::vmov(QwNeonRegister dst, QwNeonRegister src) {
  // Instruction details available in ARM DDI 0406C.b, A8-938.
  // vmov is encoded as vorr.
  vorr(dst, src, src);
}

void Assembler::vdup(NeonSize size, QwNeonRegister dst, Register src) {
  DCHECK(IsEnabled(NEON));
  // Instruction details available in ARM DDI 0406C.b, A8-886.
  int B = 0, E = 0;
  switch (size) {
    case Neon8:
      B = 1;
      break;
    case Neon16:
      E = 1;
      break;
    case Neon32:
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  dst.split_code(&vd, &d);

  emit(al | 0x1D * B23 | B * B22 | B21 | vd * B16 | src.code() * B12 |
       0xB * B8 | d * B7 | E * B5 | B4);
}

enum NeonRegType { NEON_D, NEON_Q };

void NeonSplitCode(NeonRegType type, int code, int* vm, int* m, int* encoding) {
  if (type == NEON_D) {
    DwVfpRegister::split_code(code, vm, m);
  } else {
    DCHECK_EQ(type, NEON_Q);
    QwNeonRegister::split_code(code, vm, m);
    *encoding |= B6;
  }
}

static Instr EncodeNeonDupOp(NeonSize size, NeonRegType reg_type, int dst_code,
                             DwVfpRegister src, int index) {
  DCHECK_NE(Neon64, size);
  int sz = static_cast<int>(size);
  DCHECK_LE(0, index);
  DCHECK_GT(kSimd128Size / (1 << sz), index);
  int imm4 = (1 << sz) | ((index << (sz + 1)) & 0xF);
  int qbit = 0;
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &qbit);
  int vm, m;
  src.split_code(&vm, &m);

  return 0x1E7U * B23 | d * B22 | 0x3 * B20 | imm4 * B16 | vd * B12 |
         0x18 * B7 | qbit | m * B5 | vm;
}

void Assembler::vdup(NeonSize size, DwVfpRegister dst, DwVfpRegister src,
                     int index) {
  DCHECK(IsEnabled(NEON));
  // Instruction details available in ARM DDI 0406C.b, A8-884.
  emit(EncodeNeonDupOp(size, NEON_D, dst.code(), src, index));
}

void Assembler::vdup(NeonSize size, QwNeonRegister dst, DwVfpRegister src,
                     int index) {
  // Instruction details available in ARM DDI 0406C.b, A8-884.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonDupOp(size, NEON_Q, dst.code(), src, index));
}

// Encode NEON vcvt.src_type.dst_type instruction.
static Instr EncodeNeonVCVT(VFPType dst_type, QwNeonRegister dst,
                            VFPType src_type, QwNeonRegister src) {
  DCHECK(src_type != dst_type);
  DCHECK(src_type == F32 || dst_type == F32);
  // Instruction details available in ARM DDI 0406C.b, A8.8.868.
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);

  int op = 0;
  if (src_type == F32) {
    DCHECK(dst_type == S32 || dst_type == U32);
    op = dst_type == U32 ? 3 : 2;
  } else {
    DCHECK(src_type == S32 || src_type == U32);
    op = src_type == U32 ? 1 : 0;
  }

  return 0x1E7U * B23 | d * B22 | 0x3B * B16 | vd * B12 | 0x3 * B9 | op * B7 |
         B6 | m * B5 | vm;
}

void Assembler::vcvt_f32_s32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(F32, dst, S32, src));
}

void Assembler::vcvt_f32_u32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(F32, dst, U32, src));
}

void Assembler::vcvt_s32_f32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(S32, dst, F32, src));
}

void Assembler::vcvt_u32_f32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(U32, dst, F32, src));
}

enum UnaryOp {
  VMVN,
  VSWP,
  VABS,
  VABSF,
  VNEG,
  VNEGF,
  VRINTM,
  VRINTN,
  VRINTP,
  VRINTZ,
  VZIP,
  VUZP,
  VREV16,
  VREV32,
  VREV64,
  VTRN,
  VRECPE,
  VRSQRTE,
  VPADAL_S,
  VPADAL_U,
  VPADDL_S,
  VPADDL_U,
  VCEQ0,
  VCLT0,
  VCNT
};

// Encoding helper for "Advanced SIMD two registers misc" decode group. See ARM
// DDI 0487F.b, F4-4228.
static Instr EncodeNeonUnaryOp(UnaryOp op, NeonRegType reg_type, NeonSize size,
                               int dst_code, int src_code) {
  int op_encoding = 0;
  switch (op) {
    case VMVN:
      DCHECK_EQ(Neon8, size);  // size == 0 for vmvn
      op_encoding = B10 | 0x3 * B7;
      break;
    case VSWP:
      DCHECK_EQ(Neon8, size);  // size == 0 for vswp
      op_encoding = B17;
      break;
    case VABS:
      op_encoding = B16 | 0x6 * B7;
      break;
    case VABSF:
      DCHECK_EQ(Neon32, size);
      op_encoding = B16 | B10 | 0x6 * B7;
      break;
    case VNEG:
      op_encoding = B16 | 0x7 * B7;
      break;
    case VNEGF:
      DCHECK_EQ(Neon32, size);
      op_encoding = B16 | B10 | 0x7 * B7;
      break;
    case VRINTM:
      op_encoding = B17 | 0xD * B7;
      break;
    case VRINTN:
      op_encoding = B17 | 0x8 * B7;
      break;
    case VRINTP:
      op_encoding = B17 | 0xF * B7;
      break;
    case VRINTZ:
      op_encoding = B17 | 0xB * B7;
      break;
    case VZIP:
      op_encoding = 0x2 * B16 | 0x3 * B7;
      break;
    case VUZP:
      op_encoding = 0x2 * B16 | 0x2 * B7;
      break;
    case VREV16:
      op_encoding = 0x2 * B7;
      break;
    case VREV32:
      op_encoding = 0x1 * B7;
      break;
    case VREV64:
      // op_encoding is 0;
      break;
    case VTRN:
      op_encoding = 0x2 * B16 | B7;
      break;
    case VRECPE:
      // Only support floating point.
      op_encoding = 0x3 * B16 | 0xA * B7;
      break;
    case VRSQRTE:
      // Only support floating point.
      op_encoding = 0x3 * B16 | 0xB * B7;
      break;
    case VPADAL_S:
      op_encoding = 0xC * B7;
      break;
    case VPADAL_U:
      op_encoding = 0xD * B7;
      break;
    case VPADDL_S:
      op_encoding = 0x4 * B7;
      break;
    case VPADDL_U:
      op_encoding = 0x5 * B7;
      break;
    case VCEQ0:
      // Only support integers.
      op_encoding = 0x1 * B16 | 0x2 * B7;
      break;
    case VCLT0:
      // Only support signed integers.
      op_encoding = 0x1 * B16 | 0x4 * B7;
      break;
    case VCNT:
      op_encoding = 0xA * B7;
      break;
  }
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &op_encoding);
  int vm, m;
  NeonSplitCode(reg_type, src_code, &vm, &m, &op_encoding);

  return 0x1E7U * B23 | d * B22 | 0x3 * B20 | size * B18 | vd * B12 | m * B5 |
         vm | op_encoding;
}

void Assembler::vmvn(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vmvn(Qn, Qm) SIMD bitwise negate.
  // Instruction details available in ARM DDI 0406C.b, A8-966.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VMVN, NEON_Q, Neon8, dst.code(), src.code()));
}

void Assembler::vswp(DwVfpRegister dst, DwVfpRegister src) {
  DCHECK(IsEnabled(NEON));
  // Dd = vswp(Dn, Dm) SIMD d-register swap.
  // Instruction details available in ARM DDI 0406C.b, A8.8.418.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VSWP, NEON_D, Neon8, dst.code(), src.code()));
}

void Assembler::vswp(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vswp(Qn, Qm) SIMD q-register swap.
  // Instruction details available in ARM DDI 0406C.b, A8.8.418.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VSWP, NEON_Q, Neon8, dst.code(), src.code()));
}

void Assembler::vabs(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.f<size>(Qn, Qm) SIMD floating point absolute value.
  // Instruction details available in ARM DDI 0406C.b, A8.8.824.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VABSF, NEON_Q, Neon32, dst.code(), src.code()));
}

void Assembler::vabs(NeonSize size, QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.s<size>(Qn, Qm) SIMD integer absolute value.
  // Instruction details available in ARM DDI 0406C.b, A8.8.824.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VABS, NEON_Q, size, dst.code(), src.code()));
}

void Assembler::vneg(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.f<size>(Qn, Qm) SIMD floating point negate.
  // Instruction details available in ARM DDI 0406C.b, A8.8.968.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VNEGF, NEON_Q, Neon32, dst.code(), src.code()));
}

void Assembler::vneg(NeonSize size, QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.s<size>(Qn, Qm) SIMD integer negate.
  // Instruction details available in ARM DDI 0406C.b, A8.8.968.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VNEG, NEON_Q, size, dst.code(), src.code()));
}

enum BinaryBitwiseOp { VAND, VBIC, VBIF, VBIT, VBSL, VEOR, VORR, VORN };

static Instr EncodeNeonBinaryBitwiseOp(BinaryBitwiseOp op, NeonRegType reg_type,
                                       int dst_code, int src_code1,
                                       int src_code2) {
  int op_encoding = 0;
  switch (op) {
    case VBIC:
      op_encoding = 0x1 * B20;
      break;
    case VBIF:
      op_encoding = B24 | 0x3 * B20;
      break;
    case VBIT:
      op_encoding = B24 | 0x2 * B20;
      break;
    case VBSL:
      op_encoding = B24 | 0x1 * B20;
      break;
    case VEOR:
      op_encoding = B24;
      break;
    case VORR:
      op_encoding = 0x2 * B20;
      break;
    case VORN:
      op_encoding = 0x3 * B20;
      break;
    case VAND:
      // op_encoding is 0.
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &op_encoding);
  int vn, n;
  NeonSplitCode(reg_type, src_code1, &vn, &n, &op_encoding);
  int vm, m;
  NeonSplitCode(reg_type, src_code2, &vm, &m, &op_encoding);

  return 0x1E4U * B23 | op_encoding | d * B22 | vn * B16 | vd * B12 | B8 |
         n * B7 | m * B5 | B4 | vm;
}

void Assembler::vand(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vand(Qn, Qm) SIMD AND.
  // Instruction details available in ARM DDI 0406C.b, A8.8.836.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VAND, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vbic(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vbic(Qn, Qm) SIMD AND.
  // Instruction details available in ARM DDI 0406C.b, A8-840.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VBIC, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vbsl(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vbsl(Qn, Qm) SIMD bitwise select.
  // Instruction details available in ARM DDI 0406C.b, A8-844.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VBSL, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::veor(DwVfpRegister dst, DwVfpRegister src1,
                     DwVfpRegister src2) {
  // Dd = veor(Dn, Dm) SIMD exclusive OR.
  // Instruction details available in ARM DDI 0406C.b, A8.8.888.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VEOR, NEON_D, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::veor(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = veor(Qn, Qm) SIMD exclusive OR.
  // Instruction details available in ARM DDI 0406C.b, A8.8.888.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VEOR, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vorr(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vorr(Qn, Qm) SIMD OR.
  // Instruction details available in ARM DDI 0406C.b, A8.8.976.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VORR, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vorn(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vorn(Qn, Qm) SIMD OR NOT.
  // Instruction details available in ARM DDI 0406C.d, A8.8.359.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VORN, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

enum FPBinOp {
  VADDF,
  VSUBF,
  VMULF,
  VMINF,
  VMAXF,
  VRECPS,
  VRSQRTS,
  VCEQF,
  VCGEF,
  VCGTF
};

static Instr EncodeNeonBinOp(FPBinOp op, QwNeonRegister dst,
                             QwNeonRegister src1, QwNeonRegister src2) {
  int op_encoding = 0;
  switch (op) {
    case VADDF:
      op_encoding = 0xD * B8;
      break;
    case VSUBF:
      op_encoding = B21 | 0xD * B8;
      break;
    case VMULF:
      op_encoding = B24 | 0xD * B8 | B4;
      break;
    case VMINF:
      op_encoding = B21 | 0xF * B8;
      break;
    case VMAXF:
      op_encoding = 0xF * B8;
      break;
    case VRECPS:
      op_encoding = 0xF * B8 | B4;
      break;
    case VRSQRTS:
      op_encoding = B21 | 0xF * B8 | B4;
      break;
    case VCEQF:
      op_encoding = 0xE * B8;
      break;
    case VCGEF:
      op_encoding = B24 | 0xE * B8;
      break;
    case VCGTF:
      op_encoding = B24 | B21 | 0xE * B8;
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  return 0x1E4U * B23 | d * B22 | vn * B16 | vd * B12 | n * B7 | B6 | m * B5 |
         vm | op_encoding;
}

enum IntegerBinOp {
  VADD,
  VQADD,
  VSUB,
  VQSUB,
  VMUL,
  VMIN,
  VMAX,
  VTST,
  VCEQ,
  VCGE,
  VCGT,
  VRHADD,
  VQRDMULH
};

static Instr EncodeNeonDataTypeBinOp(IntegerBinOp op, NeonDataType dt,
                                     QwNeonRegister dst, QwNeonRegister src1,
                                     QwNeonRegister src2) {
  int op_encoding = 0;
  switch (op) {
    case VADD:
      op_encoding = 0x8 * B8;
      break;
    case VQADD:
      op_encoding = B4;
      break;
    case VSUB:
      op_encoding = B24 | 0x8 * B8;
      break;
    case VQSUB:
      op_encoding = 0x2 * B8 | B4;
      break;
    case VMUL:
      op_encoding = 0x9 * B8 | B4;
      break;
    case VMIN:
      op_encoding = 0x6 * B8 | B4;
      break;
    case VMAX:
      op_encoding = 0x6 * B8;
      break;
    case VTST:
      op_encoding = 0x8 * B8 | B4;
      break;
    case VCEQ:
      op_encoding = B24 | 0x8 * B8 | B4;
      break;
    case VCGE:
      op_encoding = 0x3 * B8 | B4;
      break;
    case VCGT:
      op_encoding = 0x3 * B8;
      break;
    case VRHADD:
      op_encoding = B8;
      break;
    case VQRDMULH:
      op_encoding = B24 | 0xB * B8;
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int size = NeonSz(dt);
  int u = NeonU(dt);
  return 0x1E4U * B23 | u * B24 | d * B22 | size * B20 | vn * B16 | vd * B12 |
         n * B7 | B6 | m * B5 | vm | op_encoding;
}

static Instr EncodeNeonSizeBinOp(IntegerBinOp op, NeonSize size,
                                 QwNeonRegister dst, QwNeonRegister src1,
                                 QwNeonRegister src2) {
  // Map NeonSize values to the signed values in NeonDataType, so the U bit
  // will be 0.
  return EncodeNeonDataTypeBinOp(op, static_cast<NeonDataType>(size), dst, src1,
                                 src2);
}

void Assembler::vadd(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD floating point addition.
  // Instruction details available in ARM DDI 0406C.b, A8-830.
  emit(EncodeNeonBinOp(VADDF, dst, src1, src2));
}

void Assembler::vadd(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD integer addition.
  // Instruction details available in ARM DDI 0406C.b, A8-828.
  emit(EncodeNeonSizeBinOp(VADD, size, dst, src1, src2));
}

void Assembler::vqadd(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                      QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vqadd(Qn, Qm) SIMD integer saturating addition.
  // Instruction details available in ARM DDI 0406C.b, A8-996.
  emit(EncodeNeonDataTypeBinOp(VQADD, dt, dst, src1, src2));
}

void Assembler::vsub(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vsub(Qn, Qm) SIMD floating point subtraction.
  // Instruction details available in ARM DDI 0406C.b, A8-1086.
  emit(EncodeNeonBinOp(VSUBF, dst, src1, src2));
}

void Assembler::vsub(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vsub(Qn, Qm) SIMD integer subtraction.
  // Instruction details available in ARM DDI 0406C.b, A8-1084.
  emit(EncodeNeonSizeBinOp(VSUB, size, dst, src1, src2));
}

void Assembler::vqsub(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                      QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vqsub(Qn, Qm) SIMD integer saturating subtraction.
  // Instruction details available in ARM DDI 0406C.b, A8-1020.
  emit(EncodeNeonDataTypeBinOp(VQSUB, dt, dst, src1, src2));
}

void Assembler::vmlal(NeonDataType dt, QwNeonRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmlal(Dn, Dm) Vector Multiply Accumulate Long (integer)
  // Instruction details available in ARM DDI 0406C.b, A8-931.
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int size = NeonSz(dt);
  int u = NeonU(dt);
  if (!u) UNIMPLEMENTED();
  DCHECK_NE(size, 3);  // SEE "Related encodings"
  emit(0xFU * B28 | B25 | u * B24 | B23 | d * B22 | size * B20 | vn * B16 |
       vd * B12 | 0x8 * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmul(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD floating point multiply.
  // Instruction details available in ARM DDI 0406C.b, A8-958.
  emit(EncodeNeonBinOp(VMULF, dst, src1, src2));
}

void Assembler::vmul(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD integer multiply.
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  emit(EncodeNeonSizeBinOp(VMUL, size, dst, src1, src2));
}

void Assembler::vmull(NeonDataType dt, QwNeonRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmull(Dn, Dm) Vector Multiply Long (integer).
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int size = NeonSz(dt);
  int u = NeonU(dt);
  emit(0xFU * B28 | B25 | u * B24 | B23 | d * B22 | size * B20 | vn * B16 |
       vd * B12 | 0xC * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmin(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmin(Qn, Qm) SIMD floating point MIN.
  // Instruction details available in ARM DDI 0406C.b, A8-928.
  emit(EncodeNeonBinOp(VMINF, dst, src1, src2));
}

void Assembler::vmin(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmin(Qn, Qm) SIMD integer MIN.
  // Instruction details available in ARM DDI 0406C.b, A8-926.
  emit(EncodeNeonDataTypeBinOp(VMIN, dt, dst, src1, src2));
}

void Assembler::vmax(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmax(Qn, Qm) SIMD floating point MAX.
  // Instruction details available in ARM DDI 0406C.b, A8-928.
  emit(EncodeNeonBinOp(VMAXF, dst, src1, src2));
}

void Assembler::vmax(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmax(Qn, Qm) SIMD integer MAX.
  // Instruction details available in ARM DDI 0406C.b, A8-926.
  emit(EncodeNeonDataTypeBinOp(VMAX, dt, dst, src1, src2));
}

enum NeonShiftOp { VSHL, VSHR, VSLI, VSRI, VSRA };

static Instr EncodeNeonShiftRegisterOp(NeonShiftOp op, NeonDataType dt,
                                       NeonRegType reg_type, int dst_code,
                                       int src_code, int shift_code) {
  DCHECK_EQ(op, VSHL);
  int op_encoding = 0;
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &op_encoding);
  int vm, m;
  NeonSplitCode(reg_type, src_code, &vm, &m, &op_encoding);
  int vn, n;
  NeonSplitCode(reg_type, shift_code, &vn, &n, &op_encoding);
  int size = NeonSz(dt);
  int u = NeonU(dt);

  return 0x1E4U * B23 | u * B24 | d * B22 | size * B20 | vn * B16 | vd * B12 |
         0x4 * B8 | n * B7 | m * B5 | vm | op_encoding;
}

static Instr EncodeNeonShiftOp(NeonShiftOp op, NeonSize size, bool is_unsigned,
                               NeonRegType reg_type, int dst_code, int src_code,
                               int shift) {
  int size_in_bits = kBitsPerByte << static_cast<int>(size);
  int op_encoding = 0, imm6 = 0, L = 0;
  switch (op) {
    case VSHL: {
      DCHECK(shift >= 0 && size_in_bits > shift);
      imm6 = size_in_bits + shift;
      op_encoding = 0x5 * B8;
      break;
    }
    case VSHR: {
      DCHECK(shift > 0 && size_in_bits >= shift);
      imm6 = 2 * size_in_bits - shift;
      if (is_unsigned) op_encoding |= B24;
      break;
    }
    case VSLI: {
      DCHECK(shift >= 0 && size_in_bits > shift);
      imm6 = size_in_bits + shift;
      op_encoding = B24 | 0x5 * B8;
      break;
    }
    case VSRI: {
      DCHECK(shift > 0 && size_in_bits >= shift);
      imm6 = 2 * size_in_bits - shift;
      op_encoding = B24 | 0x4 * B8;
      break;
    }
    case VSRA: {
      DCHECK(shift > 0 && size_in_bits >= shift);
      imm6 = 2 * size_in_bits - shift;
      op_encoding = B8;
      if (is_unsigned) op_encoding |= B24;
      break;
    }
    default:
      UNREACHABLE();
  }

  L = imm6 >> 6;
  imm6 &= 0x3F;

  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &op_encoding);
  int vm, m;
  NeonSplitCode(reg_type, src_code, &vm, &m, &op_encoding);

  return 0x1E5U * B23 | d * B22 | imm6 * B16 | vd * B12 | L * B7 | m * B5 | B4 |
         vm | op_encoding;
}

void Assembler::vshl(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src,
                     int shift) {
  DCHECK(IsEnabled(NEON));
  // Qd = vshl(Qm, bits) SIMD shift left immediate.
  // Instruction details available in ARM DDI 0406C.b, A8-1046.
  emit(EncodeNeonShiftOp(VSHL, NeonDataTypeToSize(dt), false, NEON_Q,
                         dst.code(), src.code(), shift));
}

void Assembler::vshl(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src,
                     QwNeonRegister shift) {
  DCHECK(IsEnabled(NEON));
  // Qd = vshl(Qm, Qn) SIMD shift left Register.
  // Instruction details available in ARM DDI 0487A.a, F8-3340..
  emit(EncodeNeonShiftRegisterOp(VSHL, dt, NEON_Q, dst.code(), src.code(),
                                 shift.code()));
}

void Assembler::vshr(NeonDataType dt, DwVfpRegister dst, DwVfpRegister src,
                     int shift) {
  DCHECK(IsEnabled(NEON));
  // Dd = vshr(Dm, bits) SIMD shift right immediate.
  // Instruction details available in ARM DDI 0406C.b, A8-1052.
  emit(EncodeNeonShiftOp(VSHR, NeonDataTypeToSize(dt), NeonU(dt), NEON_D,
                         dst.code(), src.code(), shift));
}

void Assembler::vshr(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src,
                     int shift) {
  DCHECK(IsEnabled(NEON));
  // Qd = vshr(Qm, bits) SIMD shift right immediate.
  // Instruction details available in ARM DDI 0406C.b, A8-1052.
  emit(EncodeNeonShiftOp(VSHR, NeonDataTypeToSize(dt), NeonU(dt), NEON_Q,
                         dst.code(), src.code(), shift));
}

void Assembler::vsli(NeonSize size, DwVfpRegister dst, DwVfpRegister src,
                     int shift) {
  DCHECK(IsEnabled(NEON));
  // Dd = vsli(Dm, bits) SIMD shift left and insert.
  // Instruction details available in ARM DDI 0406C.b, A8-1056.
  emit(EncodeNeonShiftOp(VSLI, size, false, NEON_D, dst.code(), src.code(),
                         shift));
}

void Assembler::vsri(NeonSize size, DwVfpRegister dst, DwVfpRegister src,
                     int shift) {
  DCHECK(IsEnabled(NEON));
  // Dd = vsri(Dm, bits) SIMD shift right and insert.
  // Instruction details available in ARM DDI 0406C.b, A8-1062.
  emit(EncodeNeonShiftOp(VSRI, size, false, NEON_D, dst.code(), src.code(),
                         shift));
}

void Assembler::vsra(NeonDataType dt, DwVfpRegister dst, DwVfpRegister src,
                     int imm) {
  DCHECK(IsEnabled(NEON));
  // Dd = vsra(Dm, imm) SIMD shift right and accumulate.
  // Instruction details available in ARM DDI 0487F.b, F6-5569.
  emit(EncodeNeonShiftOp(VSRA, NeonDataTypeToSize(dt), NeonU(dt), NEON_D,
                         dst.code(), src.code(), imm));
}

void Assembler::vrecpe(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrecpe(Qm) SIMD reciprocal estimate.
  // Instruction details available in ARM DDI 0406C.b, A8-1024.
  emit(EncodeNeonUnaryOp(VRECPE, NEON_Q, Neon32, dst.code(), src.code()));
}

void Assembler::vrsqrte(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrsqrte(Qm) SIMD reciprocal square root estimate.
  // Instruction details available in ARM DDI 0406C.b, A8-1038.
  emit(EncodeNeonUnaryOp(VRSQRTE, NEON_Q, Neon32, dst.code(), src.code()));
}

void Assembler::vrecps(QwNeonRegister dst, QwNeonRegister src1,
                       QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrecps(Qn, Qm) SIMD reciprocal refinement step.
  // Instruction details available in ARM DDI 0406C.b, A8-1026.
  emit(EncodeNeonBinOp(VRECPS, dst, src1, src2));
}

void Assembler::vrsqrts(QwNeonRegister dst, QwNeonRegister src1,
                        QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrsqrts(Qn, Qm) SIMD reciprocal square root refinement step.
  // Instruction details available in ARM DDI 0406C.b, A8-1040.
  emit(EncodeNeonBinOp(VRSQRTS, dst, src1, src2));
}

enum NeonPairwiseOp { VPADD, VPMIN, VPMAX };

static Instr EncodeNeonPairwiseOp(NeonPairwiseOp op, NeonDataType dt,
                                  DwVfpRegister dst, DwVfpRegister src1,
                                  DwVfpRegister src2) {
  int op_encoding = 0;
  switch (op) {
    case VPADD:
      op_encoding = 0xB * B8 | B4;
      break;
    case VPMIN:
      op_encoding = 0xA * B8 | B4;
      break;
    case VPMAX:
      op_encoding = 0xA * B8;
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int size = NeonSz(dt);
  int u = NeonU(dt);
  return 0x1E4U * B23 | u * B24 | d * B22 | size * B20 | vn * B16 | vd * B12 |
         n * B7 | m * B5 | vm | op_encoding;
}

void Assembler::vpadd(DwVfpRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Dd = vpadd(Dn, Dm) SIMD floating point pairwise ADD.
  // Instruction details available in ARM DDI 0406C.b, A8-982.
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(0x1E6U * B23 | d * B22 | vn * B16 | vd * B12 | 0xD * B8 | n * B7 |
       m * B5 | vm);
}

void Assembler::vpadd(NeonSize size, DwVfpRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Dd = vpadd(Dn, Dm) SIMD integer pairwise ADD.
  // Instruction details available in ARM DDI 0406C.b, A8-980.
  emit(EncodeNeonPairwiseOp(VPADD, NeonSizeToDataType(size), dst, src1, src2));
}

void Assembler::vpmin(NeonDataType dt, DwVfpRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Dd = vpmin(Dn, Dm) SIMD integer pairwise MIN.
  // Instruction details available in ARM DDI 0406C.b, A8-986.
  emit(EncodeNeonPairwiseOp(VPMIN, dt, dst, src1, src2));
}

void Assembler::vpmax(NeonDataType dt, DwVfpRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Dd = vpmax(Dn, Dm) SIMD integer pairwise MAX.
  // Instruction details available in ARM DDI 0406C.b, A8-986.
  emit(EncodeNeonPairwiseOp(VPMAX, dt, dst, src1, src2));
}

void Assembler::vrintm(NeonDataType dt, const QwNeonRegister dst,
                       const QwNeonRegister src) {
  // SIMD vector round floating-point to integer towards -Infinity.
  // See ARM DDI 0487F.b, F6-5493.
  DCHECK(IsEnabled(ARMv8));
  emit(EncodeNeonUnaryOp(VRINTM, NEON_Q, NeonSize(dt), dst.code(), src.code()));
}

void Assembler::vrintn(NeonDataType dt, const QwNeonRegister dst,
                       const QwNeonRegister src) {
  // SIMD vector round floating-point to integer to Nearest.
  // See ARM DDI 0487F.b, F6-5497.
  DCHECK(IsEnabled(ARMv8));
  emit(EncodeNeonUnaryOp(VRINTN, NEON_Q, NeonSize(dt), dst.code(), src.code()));
}

void Assembler::vrintp(NeonDataType dt, const QwNeonRegister dst,
                       const QwNeonRegister src) {
  // SIMD vector round floating-point to integer towards +Infinity.
  // See ARM DDI 0487F.b, F6-5501.
  DCHECK(IsEnabled(ARMv8));
  emit(EncodeNeonUnaryOp(VRINTP, NEON_Q, NeonSize(dt), dst.code(), src.code()));
}

void Assembler::vrintz(NeonDataType dt, const QwNeonRegister dst,
                       const QwNeonRegister src) {
  // SIMD vector round floating-point to integer towards Zero.
  // See ARM DDI 0487F.b, F6-5511.
  DCHECK(IsEnabled(ARMv8));
  emit(EncodeNeonUnaryOp(VRINTZ, NEON_Q, NeonSize(dt), dst.code(), src.code()));
}

void Assembler::vtst(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vtst(Qn, Qm) SIMD test integer operands.
  // Instruction details available in ARM DDI 0406C.b, A8-1098.
  emit(EncodeNeonSizeBinOp(VTST, size, dst, src1, src2));
}

void Assembler::vceq(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vceq(Qn, Qm) SIMD floating point compare equal.
  // Instruction details available in ARM DDI 0406C.b, A8-844.
  emit(EncodeNeonBinOp(VCEQF, dst, src1, src2));
}

void Assembler::vceq(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vceq(Qn, Qm) SIMD integer compare equal.
  // Instruction details available in ARM DDI 0406C.b, A8-844.
  emit(EncodeNeonSizeBinOp(VCEQ, size, dst, src1, src2));
}

void Assembler::vceq(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     int value) {
  DCHECK(IsEnabled(NEON));
  DCHECK_EQ(0, value);
  // Qd = vceq(Qn, Qm, #0) Vector Compare Equal to Zero.
  // Instruction details available in ARM DDI 0406C.d, A8-847.
  emit(EncodeNeonUnaryOp(VCEQ0, NEON_Q, size, dst.code(), src1.code()));
}

void Assembler::vcge(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vcge(Qn, Qm) SIMD floating point compare greater or equal.
  // Instruction details available in ARM DDI 0406C.b, A8-848.
  emit(EncodeNeonBinOp(VCGEF, dst, src1, src2));
}

void Assembler::vcge(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vcge(Qn, Qm) SIMD integer compare greater or equal.
  // Instruction details available in ARM DDI 0406C.b, A8-848.
  emit(EncodeNeonDataTypeBinOp(VCGE, dt, dst, src1, src2));
}

void Assembler::vcgt(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vcgt(Qn, Qm) SIMD floating point compare greater than.
  // Instruction details available in ARM DDI 0406C.b, A8-852.
  emit(EncodeNeonBinOp(VCGTF, dst, src1, src2));
}

void Assembler::vcgt(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vcgt(Qn, Qm) SIMD integer compare greater than.
  // Instruction details available in ARM DDI 0406C.b, A8-852.
  emit(EncodeNeonDataTypeBinOp(VCGT, dt, dst, src1, src2));
}

void Assembler::vclt(NeonSize size, QwNeonRegister dst, QwNeonRegister src,
                     int value) {
  DCHECK(IsEnabled(NEON));
  DCHECK_EQ(0, value);
  // vclt.<size>(Qn, Qm, #0) SIMD Vector Compare Less Than Zero.
  // Instruction details available in ARM DDI 0487F.b, F6-5072.
  emit(EncodeNeonUnaryOp(VCLT0, NEON_Q, size, dst.code(), src.code()));
}

void Assembler::vrhadd(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                       QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrhadd(Qn, Qm) SIMD integer rounding halving add.
  // Instruction details available in ARM DDI 0406C.b, A8-1030.
  emit(EncodeNeonDataTypeBinOp(VRHADD, dt, dst, src1, src2));
}

void Assembler::vext(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2, int bytes) {
  DCHECK(IsEnabled(NEON));
  // Qd = vext(Qn, Qm) SIMD byte extract.
  // Instruction details available in ARM DDI 0406C.b, A8-890.
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  DCHECK_GT(16, bytes);
  emit(0x1E5U * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 | bytes * B8 |
       n * B7 | B6 | m * B5 | vm);
}

void Assembler::vzip(NeonSize size, DwVfpRegister src1, DwVfpRegister src2) {
  if (size == Neon32) {  // vzip.32 Dd, Dm is a pseudo-op for vtrn.32 Dd, Dm.
    vtrn(size, src1, src2);
  } else {
    DCHECK(IsEnabled(NEON));
    // vzip.<size>(Dn, Dm) SIMD zip (interleave).
    // Instruction details available in ARM DDI 0406C.b, A8-1102.
    emit(EncodeNeonUnaryOp(VZIP, NEON_D, size, src1.code(), src2.code()));
  }
}

void Assembler::vzip(NeonSize size, QwNeonRegister src1, QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // vzip.<size>(Qn, Qm) SIMD zip (interleave).
  // Instruction details available in ARM DDI 0406C.b, A8-1102.
  emit(EncodeNeonUnaryOp(VZIP, NEON_Q, size, src1.code(), src2.code()));
}

void Assembler::vuzp(NeonSize size, DwVfpRegister src1, DwVfpRegister src2) {
  if (size == Neon32) {  // vuzp.32 Dd, Dm is a pseudo-op for vtrn.32 Dd, Dm.
    vtrn(size, src1, src2);
  } else {
    DCHECK(IsEnabled(NEON));
    // vuzp.<size>(Dn, Dm) SIMD un-zip (de-interleave).
    // Instruction details available in ARM DDI 0406C.b, A8-1100.
    emit(EncodeNeonUnaryOp(VUZP, NEON_D, size, src1.code(), src2.code()));
  }
}

void Assembler::vuzp(NeonSize size, QwNeonRegister src1, QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // vuzp.<size>(Qn, Qm) SIMD un-zip (de-interleave).
  // Instruction details available in ARM DDI 0406C.b, A8-1100.
  emit(EncodeNeonUnaryOp(VUZP, NEON_Q, size, src1.code(), src2.code()));
}

void Assembler::vrev16(NeonSize size, QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrev16.<size>(Qm) SIMD element reverse.
  // Instruction details available in ARM DDI 0406C.b, A8-1028.
  emit(EncodeNeonUnaryOp(VREV16, NEON_Q, size, dst.code(), src.code()));
}

void Assembler::vrev32(NeonSize size, QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrev32.<size>(Qm) SIMD element reverse.
  // Instruction details available in ARM DDI 0406C.b, A8-1028.
  emit(EncodeNeonUnaryOp(VREV32, NEON_Q, size, dst.code(), src.code()));
}

void Assembler::vrev64(NeonSize size, QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  // Qd = vrev64.<size>(Qm) SIMD element reverse.
  // Instruction details available in ARM DDI 0406C.b, A8-1028.
  emit(EncodeNeonUnaryOp(VREV64, NEON_Q, size, dst.code(), src.code()));
}

void Assembler::vtrn(NeonSize size, DwVfpRegister src1, DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // vtrn.<size>(Dn, Dm) SIMD element transpose.
  // Instruction details available in ARM DDI 0406C.b, A8-1096.
  emit(EncodeNeonUnaryOp(VTRN, NEON_D, size, src1.code(), src2.code()));
}

void Assembler::vtrn(NeonSize size, QwNeonRegister src1, QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // vtrn.<size>(Qn, Qm) SIMD element transpose.
  // Instruction details available in ARM DDI 0406C.b, A8-1096.
  emit(EncodeNeonUnaryOp(VTRN, NEON_Q, size, src1.code(), src2.code()));
}

void Assembler::vpadal(NeonDataType dt, QwNeonRegister dst,
                       QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  // vpadal.<dt>(Qd, Qm) SIMD Vector Pairwise Add and Accumulate Long
  emit(EncodeNeonUnaryOp(NeonU(dt) ? VPADAL_U : VPADAL_S, NEON_Q,
                         NeonDataTypeToSize(dt), dst.code(), src.code()));
}

void Assembler::vpaddl(NeonDataType dt, QwNeonRegister dst,
                       QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  // vpaddl.<dt>(Qd, Qm) SIMD Vector Pairwise Add Long.
  emit(EncodeNeonUnaryOp(NeonU(dt) ? VPADDL_U : VPADDL_S, NEON_Q,
                         NeonDataTypeToSize(dt), dst.code(), src.code()));
}

void Assembler::vqrdmulh(NeonDataType dt, QwNeonRegister dst,
                         QwNeonRegister src1, QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  DCHECK(dt == NeonS16 || dt == NeonS32);
  emit(EncodeNeonDataTypeBinOp(VQRDMULH, dt, dst, src1, src2));
}

void Assembler::vcnt(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vcnt(Qm) SIMD Vector Count Set Bits.
  // Instruction details available at ARM DDI 0487F.b, F6-5094.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VCNT, NEON_Q, Neon8, dst.code(), src.code()));
}

// Encode NEON vtbl / vtbx instruction.
static Instr EncodeNeonVTB(DwVfpRegister dst, const NeonListOperand& list,
                           DwVfpRegister index, bool vtbx) {
  // Dd = vtbl(table, Dm) SIMD vector permute, zero at out of range indices.
  // Instruction details available in ARM DDI 0406C.b, A8-1094.
  // Dd = vtbx(table, Dm) SIMD vector permute, skip out of range indices.
  // Instruction details available in ARM DDI 0406C.b, A8-1094.
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  list.base().split_code(&vn, &n);
  int vm, m;
  index.split_code(&vm, &m);
  int op = vtbx ? 1 : 0;  // vtbl = 0, vtbx = 1.
  return 0x1E7U * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 | 0x2 * B10 |
         list.length() * B8 | n * B7 | op * B6 | m * B5 | vm;
}

void Assembler::vtbl(DwVfpRegister dst, const NeonListOperand& list,
                     DwVfpRegister index) {
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonVTB(dst, list, index, false));
}

void Assembler::vtbx(DwVfpRegister dst, const NeonListOperand& list,
                     DwVfpRegister index) {
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonVTB(dst, list, index, true));
}

// Pseudo instructions.
void Assembler::nop(int type) {
  // ARMv6{K/T2} and v7 have an actual NOP instruction but it serializes
  // some of the CPU's pipeline and has to issue. Older ARM chips simply used
  // MOV Rx, Rx as NOP and it performs better even in newer CPUs.
  // We therefore use MOV Rx, Rx, even on newer CPUs, and use Rx to encode
  // a type.
  DCHECK(0 <= type && type <= 14);  // mov pc, pc isn't a nop.
  emit(al | 13 * B21 | type * B12 | type);
}

void Assembler::pop() { add(sp, sp, Operand(kPointerSize)); }

bool Assembler::IsMovT(Instr instr) {
  instr &= ~(((kNumberOfConditions - 1) << 28) |  // Mask off conditions
             ((kNumRegisters - 1) * B12) |        // mask out register
             EncodeMovwImmediate(0xFFFF));        // mask out immediate value
  return instr == kMovtPattern;
}

bool Assembler::IsMovW(Instr instr) {
  instr &= ~(((kNumberOfConditions - 1) << 28) |  // Mask off conditions
             ((kNumRegisters - 1) * B12) |        // mask out destination
             EncodeMovwImmediate(0xFFFF));        // mask out immediate value
  return instr == kMovwPattern;
}

Instr Assembler::GetMovTPattern() { return kMovtPattern; }

Instr Assembler::GetMovWPattern() { return kMovwPattern; }

Instr Assembler::EncodeMovwImmediate(uint32_t immediate) {
  DCHECK_LT(immediate, 0x10000);
  return ((immediate & 0xF000) << 4) | (immediate & 0xFFF);
}

Instr Assembler::PatchMovwImmediate(Instr instruction, uint32_t immediate) {
  instruction &= ~EncodeMovwImmediate(0xFFFF);
  return instruction | EncodeMovwImmediate(immediate);
}

int Assembler::DecodeShiftImm(Instr instr) {
  int rotate = Instruction::RotateValue(instr) * 2;
  int immed8 = Instruction::Immed8Value(instr);
  return base::bits::RotateRight32(immed8, rotate);
}

Instr Assembler::PatchShiftImm(Instr instr, int immed) {
  uint32_t rotate_imm = 0;
  uint32_t immed_8 = 0;
  bool immed_fits = FitsShifter(immed, &rotate_imm, &immed_8, nullptr);
  DCHECK(immed_fits);
  USE(immed_fits);
  return (instr & ~kOff12Mask) | (rotate_imm << 8) | immed_8;
}

bool Assembler::IsNop(Instr instr, int type) {
  DCHECK(0 <= type && type <= 14);  // mov pc, pc isn't a nop.
  // Check for mov rx, rx where x = type.
  return instr == (al | 13 * B21 | type * B12 | type);
}

bool Assembler::IsMovImmed(Instr instr) {
  return (instr & kMovImmedMask) == kMovImmedPattern;
}

bool Assembler::IsOrrImmed(Instr instr) {
  return (instr & kOrrImmedMask) == kOrrImmedPattern;
}

// static
bool Assembler::ImmediateFitsAddrMode1Instruction(int32_t imm32) {
  uint32_t dummy1;
  uint32_t dummy2;
  return FitsShifter(imm32, &dummy1, &dummy2, nullptr);
}

bool Assembler::ImmediateFitsAddrMode2Instruction(int32_t imm32) {
  return is_uint12(abs(imm32));
}

// Debugging.
void Assembler::RecordConstPool(int size) {
  // We only need this for debugger support, to correctly compute offsets in the
  // code.
  RecordRelocInfo(RelocInfo::CONST_POOL, static_cast<intptr_t>(size));
}

void Assembler::GrowBuffer() {
  DCHECK_EQ(buffer_start_, buffer_->start());

  // Compute new buffer size.
  int old_size = buffer_->size();
  int new_size = std::min(2 * old_size, old_size + 1 * MB);

  // Some internal data structures overflow for very large buffers,
  // they must ensure that kMaximalBufferSize is not too large.
  if (new_size > kMaximalBufferSize) {
    V8::FatalProcessOutOfMemory(nullptr, "Assembler::GrowBuffer");
  }

  // Set up new buffer.
  std::unique_ptr<AssemblerBuffer> new_buffer = buffer_->Grow(new_size);
  DCHECK_EQ(new_size, new_buffer->size());
  uint8_t* new_start = new_buffer->start();

  // Copy the data.
  int pc_delta = new_start - buffer_start_;
  int rc_delta = (new_start + new_size) - (buffer_start_ + old_size);
  size_t reloc_size = (buffer_start_ + old_size) - reloc_info_writer.pos();
  MemMove(new_start, buffer_start_, pc_offset());
  uint8_t* new_reloc_start = reinterpret_cast<uint8_t*>(
      reinterpret_cast<Address>(reloc_info_writer.pos()) + rc_delta);
  MemMove(new_reloc_start, reloc_info_writer.pos(), reloc_size);

  // Switch buffers.
  buffer_ = std::move(new_buffer);
  buffer_start_ = new_start;
  pc_ = reinterpret_cast<uint8_t*>(reinterpret_cast<Address>(pc_) + pc_delta);
  uint8_t* new_last_pc = reinterpret_cast<uint8_t*>(
      reinterpret_cast<Address>(reloc_info_writer.last_pc()) + pc_delta);
  reloc_info_writer.Reposition(new_reloc_start, new_last_pc);

  // None of our relocation types are pc relative pointing outside the code
  // buffer nor pc absolute pointing inside the code buffer, so there is no need
  // to relocate any emitted relocation entries.
}

void Assembler::db(uint8_t data) {
  // db is used to write raw data. The constant pool should be emitted or
  // blocked before using db.
  DCHECK(is_const_pool_blocked() || pending_32_bit_constants_.empty());
  CheckBuffer();
  *reinterpret_cast<uint8_t*>(pc_) = data;
  pc_ += sizeof(uint8_t);
}

void Assembler::dd(uint32_t data) {
  // dd is used to write raw data. The constant pool should be emitted or
  // blocked before using dd.
  DCHECK(is_const_pool_blocked() || pending_32_bit_constants_.empty());
  CheckBuffer();
  base::WriteUnalignedValue(reinterpret_cast<Address>(pc_), data);
  pc_ += sizeof(uint32_t);
}

void Assembler::dq(uint64_t value) {
  // dq is used to write raw data. The constant pool should be emitted or
  // blocked before using dq.
  DCHECK(is_const_pool_blocked() || pending_32_bit_constants_.empty());
  CheckBuffer();
  base::WriteUnalignedValue(reinterpret_cast<Address>(pc_), value);
  pc_ += sizeof(uint64_t);
}

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data) {
  if (!ShouldRecordRelocInfo(rmode)) return;
  DCHECK_GE(buffer_space(), kMaxRelocSize);  // too late to grow buffer here
  RelocInfo rinfo(reinterpret_cast<Address>(pc_), rmode, data);
  reloc_info_writer.Write(&rinfo);
}

void Assembler::ConstantPoolAddEntry(int position, RelocInfo::Mode rmode,
                                     intptr_t value) {
  DCHECK(rmode != RelocInfo::CONST_POOL);
  // We can share CODE_TARGETs and embedded objects, but we must make sure we
  // only emit one reloc info for them (thus delta patching will apply the delta
  // only once). At the moment, we do not deduplicate heap object request which
  // are indicated by value == 0.
  bool sharing_ok = RelocInfo::IsShareableRelocMode(rmode) ||
                    (rmode == RelocInfo::CODE_TARGET && value != 0) ||
                    (RelocInfo::IsEmbeddedObjectMode(rmode) && value != 0);
  DCHECK_LT(pending_32_bit_constants_.size(), kMaxNumPending32Constants);
  if (first_const_pool_32_use_ < 0) {
    DCHECK(pending_32_bit_constants_.empty());
    DCHECK_EQ(constant_pool_deadline_, kMaxInt);
    first_const_pool_32_use_ = position;
    constant_pool_deadline_ = position + kCheckPoolDeadline;
  } else {
    DCHECK(!pending_32_bit_constants_.empty());
  }
  ConstantPoolEntry entry(position, value, sharing_ok, rmode);

  bool shared = false;
  if (sharing_ok) {
    // Merge the constant, if possible.
    for (size_t i = 0; i < pending_32_bit_constants_.size(); i++) {
      ConstantPoolEntry& current_entry = pending_32_bit_constants_[i];
      if (!current_entry.sharing_ok()) continue;
      if (entry.value() == current_entry.value() &&
          entry.rmode() == current_entry.rmode()) {
        entry.set_merged_index(i);
        shared = true;
        break;
      }
    }
  }

  pending_32_bit_constants_.emplace_back(entry);

  // Make sure the constant pool is not emitted in place of the next
  // instruction for which we just recorded relocation info.
  BlockConstPoolFor(1);

  // Emit relocation info.
  if (MustOutputRelocInfo(rmode, this) && !shared) {
    RecordRelocInfo(rmode);
  }
}

void Assembler::BlockConstPoolFor(int instructions) {
  int pc_limit = pc_offset() + instructions * kInstrSize;
  if (no_const_pool_before_ < pc_limit) {
    no_const_pool_before_ = pc_limit;
  }

  // If we're due a const pool check before the block finishes, move it to just
  // after the block.
  if (constant_pool_deadline_ < no_const_pool_before_) {
    // Make sure that the new deadline isn't too late (including a jump and the
    // constant pool marker).
    DCHECK_LE(no_const_pool_before_,
              first_const_pool_32_use_ + kMaxDistToIntPool);
    constant_pool_deadline_ = no_const_pool_before_;
  }
}

void Assembler::CheckConstPool(bool force_emit, bool require_jump) {
  // Some short sequence of instruction mustn't be broken up by constant pool
  // emission, such sequences are protected by calls to BlockConstPoolFor and
  // BlockConstPoolScope.
  if (is_const_pool_blocked()) {
    // Something is wrong if emission is forced and blocked at the same time.
    DCHECK(!force_emit);
    return;
  }

  // There is nothing to do if there are no pending constant pool entries.
  if (pending_32_bit_constants_.empty()) {
    // We should only fall into this case if we're either trying to forcing
    // emission or opportunistically checking after a jump.
    DCHECK(force_emit || !require_jump);
    return;
  }

  // We emit a constant pool when:
  //  * requested to do so by parameter force_emit (e.g. after each function).
  //  * the distance from the first instruction accessing the constant pool to
  //    the first constant pool entry will exceed its limit the next time the
  //    pool is checked.
  //  * the instruction doesn't require a jump after itself to jump over the
  //    constant pool, and we're getting close to running out of range.
  if (!force_emit) {
    DCHECK_NE(first_const_pool_32_use_, -1);
    int dist32 = pc_offset() - first_const_pool_32_use_;
    if (require_jump) {
      // We should only be on this path if we've exceeded our deadline.
      DCHECK_GE(dist32, kCheckPoolDeadline);
    } else if (dist32 < kCheckPoolDeadline / 2) {
      return;
    }
  }

  int size_after_marker = pending_32_bit_constants_.size() * kPointerSize;

  // Deduplicate constants.
  for (size_t i = 0; i < pending_32_bit_constants_.size(); i++) {
    ConstantPoolEntry& entry = pending_32_bit_constants_[i];
    if (entry.is_merged()) size_after_marker -= kPointerSize;
  }

  // Check that the code buffer is large enough before emitting the constant
  // pool (include the jump over the pool and the constant pool marker and
  // the gap to the relocation information).
  int jump_instr = require_jump ? kInstrSize : 0;
  int size_up_to_marker = jump_instr + kInstrSize;
  int size = size_up_to_marker + size_after_marker;
  int needed_space = size + kGap;
  while (buffer_space() <= needed_space) GrowBuffer();

  {
    ASM_CODE_COMMENT_STRING(this, "Constant Pool");
    // Block recursive calls to CheckConstPool.
    BlockConstPoolScope block_const_pool(this);
    RecordConstPool(size);

    Label size_check;
    bind(&size_check);

    // Emit jump over constant pool if necessary.
    Label after_pool;
    if (require_jump) {
      b(&after_pool);
    }

    // Put down constant pool marker "Undefined instruction".
    // The data size helps disassembly know what to print.
    emit(kConstantPoolMarker |
         EncodeConstantPoolLength(size_after_marker / kPointerSize));

    // The first entry in the constant pool should also be the first
    CHECK_EQ(first_const_pool_32_use_, pending_32_bit_constants_[0].position());
    CHECK(!pending_32_bit_constants_[0].is_merged());

    // Make sure we're not emitting the constant too late.
    CHECK_LE(pc_offset(),
             first_const_pool_32_use_ + kMaxDistToPcRelativeConstant);

    // Check that the code buffer is large enough before emitting the constant
    // pool (this includes the gap to the relocation information).
    int needed_space = pending_32_bit_constants_.size() * kPointerSize + kGap;
    while (buffer_space() <= needed_space) {
      GrowBuffer();
    }

    // Emit 32-bit constant pool entries.
    for (size_t i = 0; i < pending_32_bit_constants_.size(); i++) {
      ConstantPoolEntry& entry = pending_32_bit_constants_[i];
      Instr instr = instr_at(entry.position());

      // 64-bit loads shouldn't get here.
      DCHECK(!IsVldrDPcImmediateOffset(instr));
      DCHECK(!IsMovW(instr));
      DCHECK(IsLdrPcImmediateOffset(instr) &&
             GetLdrRegisterImmediateOffset(instr) == 0);

      int delta = pc_offset() - entry.position() - Instruction::kPcLoadDelta;
      DCHECK(is_uint12(delta));
      // 0 is the smallest delta:
      //   ldr rd, [pc, #0]
      //   constant pool marker
      //   data

      if (entry.is_merged()) {
        DCHECK(entry.sharing_ok());
        ConstantPoolEntry& merged =
            pending_32_bit_constants_[entry.merged_index()];
        DCHECK(entry.value() == merged.value());
        DCHECK_LT(merged.position(), entry.position());
        Instr merged_instr = instr_at(merged.position());
        DCHECK(IsLdrPcImmediateOffset(merged_instr));
        delta = GetLdrRegisterImmediateOffset(merged_instr);
        delta += merged.position() - entry.position();
      }
      instr_at_put(entry.position(),
                   SetLdrRegisterImmediateOffset(instr, delta));
      if (!entry.is_merged()) {
        emit(entry.value());
      }
    }

    pending_32_bit_constants_.clear();

    first_const_pool_32_use_ = -1;

    DCHECK_EQ(size, SizeOfCodeGeneratedSince(&size_check));

    if (after_pool.is_linked()) {
      bind(&after_pool);
    }
  }

  // Since a constant pool was just emitted, we don't need another check until
  // the next constant pool entry is added.
  constant_pool_deadline_ = kMaxInt;
}

PatchingAssembler::PatchingAssembler(const AssemblerOptions& options,
                                     uint8_t* address, int instructions)
    : Assembler(options, ExternalAssemblerBuffer(
                             address, instructions * kInstrSize + kGap)) {
  DCHECK_EQ(reloc_info_writer.pos(), buffer_start_ + buffer_->size());
}

PatchingAssembler::~PatchingAssembler() {
  // Check that we don't have any pending constant pools.
  DCHECK(pending_32_bit_constants_.empty());

  // Check that the code was patched as expected.
  DCHECK_EQ(pc_, buffer_start_ + buffer_->size() - kGap);
  DCHECK_EQ(reloc_info_writer.pos(), buffer_start_ + buffer_->size());
}

void PatchingAssembler::Emit(Address addr) { emit(static_cast<Instr>(addr)); }

void PatchingAssembler::PadWithNops() {
  DCHECK_LE(pc_, buffer_start_ + buffer_->size() - kGap);
  while (pc_ < buffer_start_ + buffer_->size() - kGap) {
    nop();
  }
}

LoadStoreLaneParams::LoadStoreLaneParams(MachineRepresentation rep,
                                         uint8_t laneidx) {
  if (rep == MachineRepresentation::kWord8) {
    *this = LoadStoreLaneParams(laneidx, Neon8, 8);
  } else if (rep == MachineRepresentation::kWord16) {
    *this = LoadStoreLaneParams(laneidx, Neon16, 4);
  } else if (rep == MachineRepresentation::kWord32) {
    *this = LoadStoreLaneParams(laneidx, Neon32, 2);
  } else if (rep == MachineRepresentation::kWord64) {
    *this = LoadStoreLaneParams(laneidx, Neon64, 1);
  } else {
    UNREACHABLE();
  }
}

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM

"""


```