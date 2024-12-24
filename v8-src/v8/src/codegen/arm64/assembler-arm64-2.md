Response: The user wants to understand the functionality of the C++ code provided, which is a part of the V8 JavaScript engine's ARM64 assembler.

The code seems to define a class `Assembler` with methods for emitting ARM64 instructions. It's the third part of a larger file.

**Plan:**

1. Identify the main purpose of the code by looking at the class name and the types of methods.
2. Focus on the methods related to instruction emission (e.g., `rbit`, `ext`, `dup`, `add`, `sub`, `ldr`, `str`, etc.).
3. Look for connections to JavaScript concepts, if any. Consider how these low-level instructions might be used to implement higher-level JavaScript features.
4. If a connection is found, construct a simple JavaScript example to illustrate the relationship.
这是 `v8/src/codegen/arm64/assembler-arm64.cc` 文件第三部分的代码，它延续了前两部分的功能，主要负责 **生成 ARM64 汇编指令**。

具体来说，这部分代码继续实现了 `Assembler` 类中的各种方法，用于生成特定的 ARM64 指令。这些指令涵盖了：

*   **位操作指令**: `rbit` (位反转)。
*   **向量操作指令 (NEON)**: `ext` (提取元素), `dup` (复制元素), `pmull`, `pmull2` (多项式乘法)。
*   **数据处理指令**: `add`, `sub`, `adds`, `subs` (加减运算), `hlt`, `brk` (断点指令), `Logical` (逻辑运算), `ConditionalCompare` (条件比较), `DataProcessing1Source`, `FPDataProcessing1Source`, `FPDataProcessing2Source`, `FPDataProcessing3Source` (通用数据处理), `NEONModifiedImmShiftLsl`, `NEONModifiedImmShiftMsl` (带立即数的 NEON 操作)。
*   **移位和扩展指令**: `EmitShift`, `EmitExtendShift`。
*   **加载和存储指令**: `LoadStore` (包括立即数偏移和寄存器偏移)。
*   **伪指令和辅助功能**: `dcptr` (定义常量指针), `debug` (插入调试信息), `EmitStringData` (发射字符串数据), `MoveWide` (移动宽立即数)。
*   **浮点数立即数处理**: `FPToImm8`, `ImmFP`, `ImmNEONFP`。
*   **常量池管理**: `ConstantPool` 类的相关方法，用于高效地存储和加载常量。
*   **Veneer 池管理**: 用于处理超出直接寻址范围的分支指令。
*   **缓冲管理**: `GrowBuffer` 用于动态扩展汇编代码缓冲区。
*   **重定位信息记录**: `RecordRelocInfo` 用于记录生成代码中需要进行重定位的信息。
*   **近跳转和近调用**: `near_jump`, `near_call`。
*   **补丁功能**: `PatchAdrFar`, `PatchSubSp` 用于在运行时修改已生成的代码。
*   **辅助判断函数**: `IsImmLogical`, `IsImmFP32`, `IsImmFP64` 用于判断立即数是否能被特定指令编码。

**与 JavaScript 功能的关系:**

虽然这些都是底层的汇编指令，但它们是 JavaScript 引擎执行 JavaScript 代码的基础。V8 使用这种 `Assembler` 类来将 JavaScript 代码编译成机器码。

例如，**NEON 指令**通常用于加速 JavaScript 中处理数组或进行数值计算的操作，特别是那些可以并行化的任务。

**JavaScript 示例 (假设 NEON 指令被用于优化数组操作):**

```javascript
function multiplyArrays(arr1, arr2) {
  if (arr1.length !== arr2.length) {
    return [];
  }
  const result = [];
  for (let i = 0; i < arr1.length; i++) {
    result.push(arr1[i] * arr2[i]);
  }
  return result;
}

const a = [1, 2, 3, 4, 5, 6, 7, 8];
const b = [9, 10, 11, 12, 13, 14, 15, 16];
const c = multiplyArrays(a, b);
console.log(c); // 输出 [9, 20, 33, 48, 65, 84, 105, 128]
```

当 V8 编译 `multiplyArrays` 函数时，如果它可以识别出循环中的乘法操作可以并行化，它可能会生成使用 NEON 指令的代码。例如，`pmull` 指令可以同时执行多个乘法操作。

**对应的 ARM64 汇编指令 (简化示例):**

虽然实际生成的汇编代码会更复杂，但为了说明目的，可以想象 V8 可能会生成类似于以下的 NEON 指令：

```assembly
// 假设 arr1 和 arr2 的数据已加载到 v0 和 v1 寄存器中 (可能是 8B 格式)
pmull v2.8h, v0.8b, v1.8b  // 将 v0 和 v1 中的 8 个字节元素进行多项式乘法，结果存入 v2 (8 个半字)
// ... 将 v2 的结果存储回内存 ...
```

在这个简化的例子中，`pmull` 指令同时执行了多个乘法操作，这比逐个元素相乘效率更高。

**总结:**

这部分 `assembler-arm64.cc` 代码是 V8 引擎的核心组成部分，它提供了生成各种 ARM64 汇编指令的能力。这些指令直接对应于计算机硬件的操作，是执行 JavaScript 代码的基石。NEON 指令等向量操作指令能够显著提升 JavaScript 中某些计算密集型任务的性能。常量池和 Veneer 池的管理则保证了生成代码的效率和正确性。

Prompt: 
```
这是目录为v8/src/codegen/arm64/assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
) || vd.Is16B());
  Emit(VFormat(vd) | NEON_RBIT_NOT | Rn(vn) | Rd(vd));
}

void Assembler::rbit(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B());
  Emit(VFormat(vn) | (1 << NEONSize_offset) | NEON_RBIT_NOT | Rn(vn) | Rd(vd));
}

void Assembler::ext(const VRegister& vd, const VRegister& vn,
                    const VRegister& vm, int index) {
  DCHECK(AreSameFormat(vd, vn, vm));
  DCHECK(vd.Is8B() || vd.Is16B());
  DCHECK((0 <= index) && (index < vd.LaneCount()));
  Emit(VFormat(vd) | NEON_EXT | Rm(vm) | ImmNEONExt(index) | Rn(vn) | Rd(vd));
}

void Assembler::dup(const VRegister& vd, const VRegister& vn, int vn_index) {
  Instr q, scalar;

  // We support vn arguments of the form vn.VxT() or vn.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vn.LaneSizeInBytes();
  NEONFormatField format;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      break;
    case 2:
      format = NEON_8H;
      break;
    case 4:
      format = NEON_4S;
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      format = NEON_2D;
      break;
  }

  if (vd.IsScalar()) {
    q = NEON_Q;
    scalar = NEONScalar;
  } else {
    DCHECK(!vd.Is1D());
    q = vd.IsD() ? 0 : NEON_Q;
    scalar = 0;
  }
  Emit(q | scalar | NEON_DUP_ELEMENT | ImmNEON5(format, vn_index) | Rn(vn) |
       Rd(vd));
}

void Assembler::dcptr(Label* label) {
  BlockPoolsScope no_pool_inbetween(this);
  RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
  if (label->is_bound()) {
    // The label is bound, so it does not need to be updated and the internal
    // reference should be emitted.
    //
    // In this case, label->pos() returns the offset of the label from the
    // start of the buffer.
    internal_reference_positions_.push_back(pc_offset());
    dc64(reinterpret_cast<uintptr_t>(buffer_start_ + label->pos()));
  } else {
    int32_t offset;
    if (label->is_linked()) {
      // The label is linked, so the internal reference should be added
      // onto the end of the label's link chain.
      //
      // In this case, label->pos() returns the offset of the last linked
      // instruction from the start of the buffer.
      offset = label->pos() - pc_offset();
      DCHECK_NE(offset, kStartOfLabelLinkChain);
    } else {
      // The label is unused, so it now becomes linked and the internal
      // reference is at the start of the new link chain.
      offset = kStartOfLabelLinkChain;
    }
    // The instruction at pc is now the last link in the label's chain.
    label->link_to(pc_offset());

    // Traditionally the offset to the previous instruction in the chain is
    // encoded in the instruction payload (e.g. branch range) but internal
    // references are not instructions so while unbound they are encoded as
    // two consecutive brk instructions. The two 16-bit immediates are used
    // to encode the offset.
    offset >>= kInstrSizeLog2;
    DCHECK(is_int32(offset));
    uint32_t high16 = unsigned_bitextract_32(31, 16, offset);
    uint32_t low16 = unsigned_bitextract_32(15, 0, offset);

    brk(high16);
    brk(low16);
  }
}

// Below, a difference in case for the same letter indicates a
// negated bit. If b is 1, then B is 0.
uint32_t Assembler::FPToImm8(double imm) {
  uint64_t bits = base::bit_cast<uint64_t>(imm);
  DCHECK(IsImmFP64(bits));
  // bits: aBbb.bbbb.bbcd.efgh.0000.0000.0000.0000
  //       0000.0000.0000.0000.0000.0000.0000.0000
  // bit7: a000.0000
  uint64_t bit7 = ((bits >> 63) & 0x1) << 7;
  // bit6: 0b00.0000
  uint64_t bit6 = ((bits >> 61) & 0x1) << 6;
  // bit5_to_0: 00cd.efgh
  uint64_t bit5_to_0 = (bits >> 48) & 0x3F;

  return static_cast<uint32_t>(bit7 | bit6 | bit5_to_0);
}

Instr Assembler::ImmFP(double imm) { return FPToImm8(imm) << ImmFP_offset; }
Instr Assembler::ImmNEONFP(double imm) {
  return ImmNEONabcdefgh(FPToImm8(imm));
}

// InstructionStream generation helpers.
void Assembler::MoveWide(const Register& rd, uint64_t imm, int shift,
                         MoveWideImmediateOp mov_op) {
  // Ignore the top 32 bits of an immediate if we're moving to a W register.
  if (rd.Is32Bits()) {
    // Check that the top 32 bits are zero (a positive 32-bit number) or top
    // 33 bits are one (a negative 32-bit number, sign extended to 64 bits).
    DCHECK(((imm >> kWRegSizeInBits) == 0) ||
           ((imm >> (kWRegSizeInBits - 1)) == 0x1FFFFFFFF));
    imm &= kWRegMask;
  }

  if (shift >= 0) {
    // Explicit shift specified.
    DCHECK((shift == 0) || (shift == 16) || (shift == 32) || (shift == 48));
    DCHECK(rd.Is64Bits() || (shift == 0) || (shift == 16));
    shift /= 16;
  } else {
    // Calculate a new immediate and shift combination to encode the immediate
    // argument.
    shift = 0;
    if ((imm & ~0xFFFFULL) == 0) {
      // Nothing to do.
    } else if ((imm & ~(0xFFFFULL << 16)) == 0) {
      imm >>= 16;
      shift = 1;
    } else if ((imm & ~(0xFFFFULL << 32)) == 0) {
      DCHECK(rd.Is64Bits());
      imm >>= 32;
      shift = 2;
    } else if ((imm & ~(0xFFFFULL << 48)) == 0) {
      DCHECK(rd.Is64Bits());
      imm >>= 48;
      shift = 3;
    }
  }

  DCHECK(is_uint16(imm));

  Emit(SF(rd) | MoveWideImmediateFixed | mov_op | Rd(rd) |
       ImmMoveWide(static_cast<int>(imm)) | ShiftMoveWide(shift));
}

void Assembler::AddSub(const Register& rd, const Register& rn,
                       const Operand& operand, FlagsUpdate S, AddSubOp op) {
  DCHECK_EQ(rd.SizeInBits(), rn.SizeInBits());
  DCHECK(!operand.NeedsRelocation(this));
  if (operand.IsImmediate()) {
    int64_t immediate = operand.ImmediateValue();
    DCHECK(IsImmAddSub(immediate));
    Instr dest_reg = (S == SetFlags) ? Rd(rd) : RdSP(rd);
    Emit(SF(rd) | AddSubImmediateFixed | op | Flags(S) |
         ImmAddSub(static_cast<int>(immediate)) | dest_reg | RnSP(rn));
  } else if (operand.IsShiftedRegister()) {
    DCHECK_EQ(operand.reg().SizeInBits(), rd.SizeInBits());
    DCHECK_NE(operand.shift(), ROR);

    // For instructions of the form:
    //   add/sub   wsp, <Wn>, <Wm> [, LSL #0-3 ]
    //   add/sub   <Wd>, wsp, <Wm> [, LSL #0-3 ]
    //   add/sub   wsp, wsp, <Wm> [, LSL #0-3 ]
    //   adds/subs <Wd>, wsp, <Wm> [, LSL #0-3 ]
    // or their 64-bit register equivalents, convert the operand from shifted to
    // extended register mode, and emit an add/sub extended instruction.
    if (rn.IsSP() || rd.IsSP()) {
      DCHECK(!(rd.IsSP() && (S == SetFlags)));
      DataProcExtendedRegister(rd, rn, operand.ToExtendedRegister(), S,
                               AddSubExtendedFixed | op);
    } else {
      DataProcShiftedRegister(rd, rn, operand, S, AddSubShiftedFixed | op);
    }
  } else {
    DCHECK(operand.IsExtendedRegister());
    DataProcExtendedRegister(rd, rn, operand, S, AddSubExtendedFixed | op);
  }
}

void Assembler::AddSubWithCarry(const Register& rd, const Register& rn,
                                const Operand& operand, FlagsUpdate S,
                                AddSubWithCarryOp op) {
  DCHECK_EQ(rd.SizeInBits(), rn.SizeInBits());
  DCHECK_EQ(rd.SizeInBits(), operand.reg().SizeInBits());
  DCHECK(operand.IsShiftedRegister() && (operand.shift_amount() == 0));
  DCHECK(!operand.NeedsRelocation(this));
  Emit(SF(rd) | op | Flags(S) | Rm(operand.reg()) | Rn(rn) | Rd(rd));
}

void Assembler::hlt(int code) {
  DCHECK(is_uint16(code));
  Emit(HLT | ImmException(code));
}

void Assembler::brk(int code) {
  DCHECK(is_uint16(code));
  Emit(BRK | ImmException(code));
}

void Assembler::EmitStringData(const char* string) {
  size_t len = strlen(string) + 1;
  DCHECK_LE(RoundUp(len, kInstrSize), static_cast<size_t>(kGap));
  EmitData(string, static_cast<int>(len));
  // Pad with nullptr characters until pc_ is aligned.
  const char pad[] = {'\0', '\0', '\0', '\0'};
  static_assert(sizeof(pad) == kInstrSize,
                "Size of padding must match instruction size.");
  EmitData(pad, RoundUp(pc_offset(), kInstrSize) - pc_offset());
}

void Assembler::debug(const char* message, uint32_t code, Instr params) {
  if (options().enable_simulator_code) {
    size_t size_of_debug_sequence =
        4 * kInstrSize + RoundUp<kInstrSize>(strlen(message) + 1);

    // The arguments to the debug marker need to be contiguous in memory, so
    // make sure we don't try to emit pools.
    BlockPoolsScope scope(this, size_of_debug_sequence);

    Label start;
    bind(&start);

    // Refer to instructions-arm64.h for a description of the marker and its
    // arguments.
    hlt(kImmExceptionIsDebug);
    DCHECK_EQ(SizeOfCodeGeneratedSince(&start), kDebugCodeOffset);
    dc32(code);
    DCHECK_EQ(SizeOfCodeGeneratedSince(&start), kDebugParamsOffset);
    dc32(params);
    DCHECK_EQ(SizeOfCodeGeneratedSince(&start), kDebugMessageOffset);
    EmitStringData(message);
    hlt(kImmExceptionIsUnreachable);
    DCHECK_EQ(SizeOfCodeGeneratedSince(&start), size_of_debug_sequence);

    return;
  }

  if (params & BREAK) {
    brk(0);
  }
}

void Assembler::Logical(const Register& rd, const Register& rn,
                        const Operand& operand, LogicalOp op) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(!operand.NeedsRelocation(this));
  if (operand.IsImmediate()) {
    int64_t immediate = operand.ImmediateValue();
    unsigned reg_size = rd.SizeInBits();

    DCHECK_NE(immediate, 0);
    DCHECK_NE(immediate, -1);
    DCHECK(rd.Is64Bits() || is_uint32(immediate));

    // If the operation is NOT, invert the operation and immediate.
    if ((op & NOT) == NOT) {
      op = static_cast<LogicalOp>(op & ~NOT);
      immediate = rd.Is64Bits() ? ~immediate : (~immediate & kWRegMask);
    }

    unsigned n, imm_s, imm_r;
    if (IsImmLogical(immediate, reg_size, &n, &imm_s, &imm_r)) {
      // Immediate can be encoded in the instruction.
      LogicalImmediate(rd, rn, n, imm_s, imm_r, op);
    } else {
      // This case is handled in the macro assembler.
      UNREACHABLE();
    }
  } else {
    DCHECK(operand.IsShiftedRegister());
    DCHECK(operand.reg().SizeInBits() == rd.SizeInBits());
    Instr dp_op = static_cast<Instr>(op | LogicalShiftedFixed);
    DataProcShiftedRegister(rd, rn, operand, LeaveFlags, dp_op);
  }
}

void Assembler::LogicalImmediate(const Register& rd, const Register& rn,
                                 unsigned n, unsigned imm_s, unsigned imm_r,
                                 LogicalOp op) {
  unsigned reg_size = rd.SizeInBits();
  Instr dest_reg = (op == ANDS) ? Rd(rd) : RdSP(rd);
  Emit(SF(rd) | LogicalImmediateFixed | op | BitN(n, reg_size) |
       ImmSetBits(imm_s, reg_size) | ImmRotate(imm_r, reg_size) | dest_reg |
       Rn(rn));
}

void Assembler::ConditionalCompare(const Register& rn, const Operand& operand,
                                   StatusFlags nzcv, Condition cond,
                                   ConditionalCompareOp op) {
  Instr ccmpop;
  DCHECK(!operand.NeedsRelocation(this));
  if (operand.IsImmediate()) {
    int64_t immediate = operand.ImmediateValue();
    DCHECK(IsImmConditionalCompare(immediate));
    ccmpop = ConditionalCompareImmediateFixed | op |
             ImmCondCmp(static_cast<unsigned>(immediate));
  } else {
    DCHECK(operand.IsShiftedRegister() && (operand.shift_amount() == 0));
    ccmpop = ConditionalCompareRegisterFixed | op | Rm(operand.reg());
  }
  Emit(SF(rn) | ccmpop | Cond(cond) | Rn(rn) | Nzcv(nzcv));
}

void Assembler::DataProcessing1Source(const Register& rd, const Register& rn,
                                      DataProcessing1SourceOp op) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  Emit(SF(rn) | op | Rn(rn) | Rd(rd));
}

void Assembler::FPDataProcessing1Source(const VRegister& vd,
                                        const VRegister& vn,
                                        FPDataProcessing1SourceOp op) {
  Emit(FPType(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::FPDataProcessing2Source(const VRegister& fd,
                                        const VRegister& fn,
                                        const VRegister& fm,
                                        FPDataProcessing2SourceOp op) {
  DCHECK(fd.SizeInBits() == fn.SizeInBits());
  DCHECK(fd.SizeInBits() == fm.SizeInBits());
  Emit(FPType(fd) | op | Rm(fm) | Rn(fn) | Rd(fd));
}

void Assembler::FPDataProcessing3Source(const VRegister& fd,
                                        const VRegister& fn,
                                        const VRegister& fm,
                                        const VRegister& fa,
                                        FPDataProcessing3SourceOp op) {
  DCHECK(AreSameSizeAndType(fd, fn, fm, fa));
  Emit(FPType(fd) | op | Rm(fm) | Rn(fn) | Rd(fd) | Ra(fa));
}

void Assembler::NEONModifiedImmShiftLsl(const VRegister& vd, const int imm8,
                                        const int left_shift,
                                        NEONModifiedImmediateOp op) {
  DCHECK(vd.Is8B() || vd.Is16B() || vd.Is4H() || vd.Is8H() || vd.Is2S() ||
         vd.Is4S());
  DCHECK((left_shift == 0) || (left_shift == 8) || (left_shift == 16) ||
         (left_shift == 24));
  DCHECK(is_uint8(imm8));

  int cmode_1, cmode_2, cmode_3;
  if (vd.Is8B() || vd.Is16B()) {
    DCHECK_EQ(op, NEONModifiedImmediate_MOVI);
    cmode_1 = 1;
    cmode_2 = 1;
    cmode_3 = 1;
  } else {
    cmode_1 = (left_shift >> 3) & 1;
    cmode_2 = left_shift >> 4;
    cmode_3 = 0;
    if (vd.Is4H() || vd.Is8H()) {
      DCHECK((left_shift == 0) || (left_shift == 8));
      cmode_3 = 1;
    }
  }
  int cmode = (cmode_3 << 3) | (cmode_2 << 2) | (cmode_1 << 1);

  Instr q = vd.IsQ() ? NEON_Q : 0;

  Emit(q | op | ImmNEONabcdefgh(imm8) | NEONCmode(cmode) | Rd(vd));
}

void Assembler::NEONModifiedImmShiftMsl(const VRegister& vd, const int imm8,
                                        const int shift_amount,
                                        NEONModifiedImmediateOp op) {
  DCHECK(vd.Is2S() || vd.Is4S());
  DCHECK((shift_amount == 8) || (shift_amount == 16));
  DCHECK(is_uint8(imm8));

  int cmode_0 = (shift_amount >> 4) & 1;
  int cmode = 0xC | cmode_0;

  Instr q = vd.IsQ() ? NEON_Q : 0;

  Emit(q | op | ImmNEONabcdefgh(imm8) | NEONCmode(cmode) | Rd(vd));
}

void Assembler::EmitShift(const Register& rd, const Register& rn, Shift shift,
                          unsigned shift_amount) {
  switch (shift) {
    case LSL:
      lsl(rd, rn, shift_amount);
      break;
    case LSR:
      lsr(rd, rn, shift_amount);
      break;
    case ASR:
      asr(rd, rn, shift_amount);
      break;
    case ROR:
      ror(rd, rn, shift_amount);
      break;
    default:
      UNREACHABLE();
  }
}

void Assembler::EmitExtendShift(const Register& rd, const Register& rn,
                                Extend extend, unsigned left_shift) {
  DCHECK(rd.SizeInBits() >= rn.SizeInBits());
  unsigned reg_size = rd.SizeInBits();
  // Use the correct size of register.
  Register rn_ = Register::Create(rn.code(), rd.SizeInBits());
  // Bits extracted are high_bit:0.
  unsigned high_bit = (8 << (extend & 0x3)) - 1;
  // Number of bits left in the result that are not introduced by the shift.
  unsigned non_shift_bits = (reg_size - left_shift) & (reg_size - 1);

  if ((non_shift_bits > high_bit) || (non_shift_bits == 0)) {
    switch (extend) {
      case UXTB:
      case UXTH:
      case UXTW:
        ubfm(rd, rn_, non_shift_bits, high_bit);
        break;
      case SXTB:
      case SXTH:
      case SXTW:
        sbfm(rd, rn_, non_shift_bits, high_bit);
        break;
      case UXTX:
      case SXTX: {
        DCHECK_EQ(rn.SizeInBits(), kXRegSizeInBits);
        // Nothing to extend. Just shift.
        lsl(rd, rn_, left_shift);
        break;
      }
      default:
        UNREACHABLE();
    }
  } else {
    // No need to extend as the extended bits would be shifted away.
    lsl(rd, rn_, left_shift);
  }
}

void Assembler::DataProcShiftedRegister(const Register& rd, const Register& rn,
                                        const Operand& operand, FlagsUpdate S,
                                        Instr op) {
  DCHECK(operand.IsShiftedRegister());
  DCHECK(rn.Is64Bits() || (rn.Is32Bits() && is_uint5(operand.shift_amount())));
  DCHECK(!operand.NeedsRelocation(this));
  Emit(SF(rd) | op | Flags(S) | ShiftDP(operand.shift()) |
       ImmDPShift(operand.shift_amount()) | Rm(operand.reg()) | Rn(rn) |
       Rd(rd));
}

void Assembler::DataProcExtendedRegister(const Register& rd, const Register& rn,
                                         const Operand& operand, FlagsUpdate S,
                                         Instr op) {
  DCHECK(!operand.NeedsRelocation(this));
  Instr dest_reg = (S == SetFlags) ? Rd(rd) : RdSP(rd);
  Emit(SF(rd) | op | Flags(S) | Rm(operand.reg()) |
       ExtendMode(operand.extend()) | ImmExtendShift(operand.shift_amount()) |
       dest_reg | RnSP(rn));
}

void Assembler::LoadStore(const CPURegister& rt, const MemOperand& addr,
                          LoadStoreOp op) {
  Instr memop = op | Rt(rt) | RnSP(addr.base());

  if (addr.IsImmediateOffset()) {
    unsigned size_log2 = CalcLSDataSizeLog2(op);
    int offset = static_cast<int>(addr.offset());
    if (IsImmLSScaled(addr.offset(), size_log2)) {
      LoadStoreScaledImmOffset(memop, offset, size_log2);
    } else {
      DCHECK(IsImmLSUnscaled(addr.offset()));
      LoadStoreUnscaledImmOffset(memop, offset);
    }
  } else if (addr.IsRegisterOffset()) {
    Extend ext = addr.extend();
    Shift shift = addr.shift();
    unsigned shift_amount = addr.shift_amount();

    // LSL is encoded in the option field as UXTX.
    if (shift == LSL) {
      ext = UXTX;
    }

    // Shifts are encoded in one bit, indicating a left shift by the memory
    // access size.
    DCHECK(shift_amount == 0 || shift_amount == CalcLSDataSizeLog2(op));
    Emit(LoadStoreRegisterOffsetFixed | memop | Rm(addr.regoffset()) |
         ExtendMode(ext) | ImmShiftLS((shift_amount > 0) ? 1 : 0));
  } else {
    // Pre-index and post-index modes.
    DCHECK(IsImmLSUnscaled(addr.offset()));
    DCHECK_NE(rt, addr.base());
    int offset = static_cast<int>(addr.offset());
    if (addr.IsPreIndex()) {
      Emit(LoadStorePreIndexFixed | memop | ImmLS(offset));
    } else {
      DCHECK(addr.IsPostIndex());
      Emit(LoadStorePostIndexFixed | memop | ImmLS(offset));
    }
  }
}

void Assembler::pmull(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(AreSameFormat(vn, vm));
  DCHECK((vn.Is8B() && vd.Is8H()) || (vn.Is1D() && vd.Is1Q()));
  DCHECK(IsEnabled(PMULL1Q) || vd.Is8H());
  Emit(VFormat(vn) | NEON_PMULL | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::pmull2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(AreSameFormat(vn, vm));
  DCHECK((vn.Is16B() && vd.Is8H()) || (vn.Is2D() && vd.Is1Q()));
  DCHECK(IsEnabled(PMULL1Q) || vd.Is8H());
  Emit(VFormat(vn) | NEON_PMULL2 | Rm(vm) | Rn(vn) | Rd(vd));
}

bool Assembler::IsImmLSPair(int64_t offset, unsigned size) {
  bool offset_is_size_multiple =
      (static_cast<int64_t>(static_cast<uint64_t>(offset >> size) << size) ==
       offset);
  return offset_is_size_multiple && is_int7(offset >> size);
}

bool Assembler::IsImmLLiteral(int64_t offset) {
  int inst_size = static_cast<int>(kInstrSizeLog2);
  bool offset_is_inst_multiple =
      (static_cast<int64_t>(static_cast<uint64_t>(offset >> inst_size)
                            << inst_size) == offset);
  DCHECK_GT(offset, 0);
  offset >>= kLoadLiteralScaleLog2;
  return offset_is_inst_multiple && is_intn(offset, ImmLLiteral_width);
}

// Test if a given value can be encoded in the immediate field of a logical
// instruction.
// If it can be encoded, the function returns true, and values pointed to by n,
// imm_s and imm_r are updated with immediates encoded in the format required
// by the corresponding fields in the logical instruction.
// If it can not be encoded, the function returns false, and the values pointed
// to by n, imm_s and imm_r are undefined.
bool Assembler::IsImmLogical(uint64_t value, unsigned width, unsigned* n,
                             unsigned* imm_s, unsigned* imm_r) {
  DCHECK((n != nullptr) && (imm_s != nullptr) && (imm_r != nullptr));
  DCHECK((width == kWRegSizeInBits) || (width == kXRegSizeInBits));

  bool negate = false;

  // Logical immediates are encoded using parameters n, imm_s and imm_r using
  // the following table:
  //
  //    N   imms    immr    size        S             R
  //    1  ssssss  rrrrrr    64    UInt(ssssss)  UInt(rrrrrr)
  //    0  0sssss  xrrrrr    32    UInt(sssss)   UInt(rrrrr)
  //    0  10ssss  xxrrrr    16    UInt(ssss)    UInt(rrrr)
  //    0  110sss  xxxrrr     8    UInt(sss)     UInt(rrr)
  //    0  1110ss  xxxxrr     4    UInt(ss)      UInt(rr)
  //    0  11110s  xxxxxr     2    UInt(s)       UInt(r)
  // (s bits must not be all set)
  //
  // A pattern is constructed of size bits, where the least significant S+1 bits
  // are set. The pattern is rotated right by R, and repeated across a 32 or
  // 64-bit value, depending on destination register width.
  //
  // Put another way: the basic format of a logical immediate is a single
  // contiguous stretch of 1 bits, repeated across the whole word at intervals
  // given by a power of 2. To identify them quickly, we first locate the
  // lowest stretch of 1 bits, then the next 1 bit above that; that combination
  // is different for every logical immediate, so it gives us all the
  // information we need to identify the only logical immediate that our input
  // could be, and then we simply check if that's the value we actually have.
  //
  // (The rotation parameter does give the possibility of the stretch of 1 bits
  // going 'round the end' of the word. To deal with that, we observe that in
  // any situation where that happens the bitwise NOT of the value is also a
  // valid logical immediate. So we simply invert the input whenever its low bit
  // is set, and then we know that the rotated case can't arise.)

  if (value & 1) {
    // If the low bit is 1, negate the value, and set a flag to remember that we
    // did (so that we can adjust the return values appropriately).
    negate = true;
    value = ~value;
  }

  if (width == kWRegSizeInBits) {
    // To handle 32-bit logical immediates, the very easiest thing is to repeat
    // the input value twice to make a 64-bit word. The correct encoding of that
    // as a logical immediate will also be the correct encoding of the 32-bit
    // value.

    // The most-significant 32 bits may not be zero (ie. negate is true) so
    // shift the value left before duplicating it.
    value <<= kWRegSizeInBits;
    value |= value >> kWRegSizeInBits;
  }

  // The basic analysis idea: imagine our input word looks like this.
  //
  //    0011111000111110001111100011111000111110001111100011111000111110
  //                                                          c  b    a
  //                                                          |<--d-->|
  //
  // We find the lowest set bit (as an actual power-of-2 value, not its index)
  // and call it a. Then we add a to our original number, which wipes out the
  // bottommost stretch of set bits and replaces it with a 1 carried into the
  // next zero bit. Then we look for the new lowest set bit, which is in
  // position b, and subtract it, so now our number is just like the original
  // but with the lowest stretch of set bits completely gone. Now we find the
  // lowest set bit again, which is position c in the diagram above. Then we'll
  // measure the distance d between bit positions a and c (using CLZ), and that
  // tells us that the only valid logical immediate that could possibly be equal
  // to this number is the one in which a stretch of bits running from a to just
  // below b is replicated every d bits.
  uint64_t a = LargestPowerOf2Divisor(value);
  uint64_t value_plus_a = value + a;
  uint64_t b = LargestPowerOf2Divisor(value_plus_a);
  uint64_t value_plus_a_minus_b = value_plus_a - b;
  uint64_t c = LargestPowerOf2Divisor(value_plus_a_minus_b);

  int d, clz_a, out_n;
  uint64_t mask;

  if (c != 0) {
    // The general case, in which there is more than one stretch of set bits.
    // Compute the repeat distance d, and set up a bitmask covering the basic
    // unit of repetition (i.e. a word with the bottom d bits set). Also, in all
    // of these cases the N bit of the output will be zero.
    clz_a = CountLeadingZeros(a, kXRegSizeInBits);
    int clz_c = CountLeadingZeros(c, kXRegSizeInBits);
    d = clz_a - clz_c;
    mask = ((uint64_t{1} << d) - 1);
    out_n = 0;
  } else {
    // Handle degenerate cases.
    //
    // If any of those 'find lowest set bit' operations didn't find a set bit at
    // all, then the word will have been zero thereafter, so in particular the
    // last lowest_set_bit operation will have returned zero. So we can test for
    // all the special case conditions in one go by seeing if c is zero.
    if (a == 0) {
      // The input was zero (or all 1 bits, which will come to here too after we
      // inverted it at the start of the function), for which we just return
      // false.
      return false;
    } else {
      // Otherwise, if c was zero but a was not, then there's just one stretch
      // of set bits in our word, meaning that we have the trivial case of
      // d == 64 and only one 'repetition'. Set up all the same variables as in
      // the general case above, and set the N bit in the output.
      clz_a = CountLeadingZeros(a, kXRegSizeInBits);
      d = 64;
      mask = ~uint64_t{0};
      out_n = 1;
    }
  }

  // If the repeat period d is not a power of two, it can't be encoded.
  if (!base::bits::IsPowerOfTwo(d)) {
    return false;
  }

  if (((b - a) & ~mask) != 0) {
    // If the bit stretch (b - a) does not fit within the mask derived from the
    // repeat period, then fail.
    return false;
  }

  // The only possible option is b - a repeated every d bits. Now we're going to
  // actually construct the valid logical immediate derived from that
  // specification, and see if it equals our original input.
  //
  // To repeat a value every d bits, we multiply it by a number of the form
  // (1 + 2^d + 2^(2d) + ...), i.e. 0x0001000100010001 or similar. These can
  // be derived using a table lookup on CLZ(d).
  static const uint64_t multipliers[] = {
      0x0000000000000001UL, 0x0000000100000001UL, 0x0001000100010001UL,
      0x0101010101010101UL, 0x1111111111111111UL, 0x5555555555555555UL,
  };
  int multiplier_idx = CountLeadingZeros(d, kXRegSizeInBits) - 57;
  // Ensure that the index to the multipliers array is within bounds.
  DCHECK((multiplier_idx >= 0) &&
         (static_cast<size_t>(multiplier_idx) < arraysize(multipliers)));
  uint64_t multiplier = multipliers[multiplier_idx];
  uint64_t candidate = (b - a) * multiplier;

  if (value != candidate) {
    // The candidate pattern doesn't match our input value, so fail.
    return false;
  }

  // We have a match! This is a valid logical immediate, so now we have to
  // construct the bits and pieces of the instruction encoding that generates
  // it.

  // Count the set bits in our basic stretch. The special case of clz(0) == -1
  // makes the answer come out right for stretches that reach the very top of
  // the word (e.g. numbers like 0xFFFFC00000000000).
  int clz_b = (b == 0) ? -1 : CountLeadingZeros(b, kXRegSizeInBits);
  int s = clz_a - clz_b;

  // Decide how many bits to rotate right by, to put the low bit of that basic
  // stretch in position a.
  int r;
  if (negate) {
    // If we inverted the input right at the start of this function, here's
    // where we compensate: the number of set bits becomes the number of clear
    // bits, and the rotation count is based on position b rather than position
    // a (since b is the location of the 'lowest' 1 bit after inversion).
    s = d - s;
    r = (clz_b + 1) & (d - 1);
  } else {
    r = (clz_a + 1) & (d - 1);
  }

  // Now we're done, except for having to encode the S output in such a way that
  // it gives both the number of set bits and the length of the repeated
  // segment. The s field is encoded like this:
  //
  //     imms    size        S
  //    ssssss    64    UInt(ssssss)
  //    0sssss    32    UInt(sssss)
  //    10ssss    16    UInt(ssss)
  //    110sss     8    UInt(sss)
  //    1110ss     4    UInt(ss)
  //    11110s     2    UInt(s)
  //
  // So we 'or' (-d * 2) with our computed s to form imms.
  *n = out_n;
  *imm_s = ((-d * 2) | (s - 1)) & 0x3F;
  *imm_r = r;

  return true;
}

bool Assembler::IsImmFP32(uint32_t bits) {
  // Valid values will have the form:
  // aBbb.bbbc.defg.h000.0000.0000.0000.0000
  // bits[19..0] are cleared.
  if ((bits & 0x7FFFF) != 0) {
    return false;
  }

  // bits[29..25] are all set or all cleared.
  uint32_t b_pattern = (bits >> 16) & 0x3E00;
  if (b_pattern != 0 && b_pattern != 0x3E00) {
    return false;
  }

  // bit[30] and bit[29] are opposite.
  if (((bits ^ (bits << 1)) & 0x40000000) == 0) {
    return false;
  }

  return true;
}

bool Assembler::IsImmFP64(uint64_t bits) {
  // Valid values will have the form:
  // aBbb.bbbb.bbcd.efgh.0000.0000.0000.0000
  // 0000.0000.0000.0000.0000.0000.0000.0000
  // bits[47..0] are cleared.
  if ((bits & 0xFFFFFFFFFFFFL) != 0) {
    return false;
  }

  // bits[61..54] are all set or all cleared.
  uint32_t b_pattern = (bits >> 48) & 0x3FC0;
  if (b_pattern != 0 && b_pattern != 0x3FC0) {
    return false;
  }

  // bit[62] and bit[61] are opposite.
  if (((bits ^ (bits << 1)) & 0x4000000000000000L) == 0) {
    return false;
  }

  return true;
}

void Assembler::GrowBuffer() {
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
  intptr_t pc_delta = new_start - buffer_start_;
  intptr_t rc_delta = (new_start + new_size) - (buffer_start_ + old_size);
  size_t reloc_size = (buffer_start_ + old_size) - reloc_info_writer.pos();
  memmove(new_start, buffer_start_, pc_offset());
  memmove(reloc_info_writer.pos() + rc_delta, reloc_info_writer.pos(),
          reloc_size);

  // Switch buffers.
  buffer_ = std::move(new_buffer);
  buffer_start_ = new_start;
  pc_ += pc_delta;
  reloc_info_writer.Reposition(reloc_info_writer.pos() + rc_delta,
                               reloc_info_writer.last_pc() + pc_delta);

  // None of our relocation types are pc relative pointing outside the code
  // buffer nor pc absolute pointing inside the code buffer, so there is no need
  // to relocate any emitted relocation entries.

  // Relocate internal references.
  for (auto pos : internal_reference_positions_) {
    Address address = reinterpret_cast<intptr_t>(buffer_start_) + pos;
    intptr_t internal_ref = ReadUnalignedValue<intptr_t>(address);
    internal_ref += pc_delta;
    WriteUnalignedValue<intptr_t>(address, internal_ref);
  }

  // Pending relocation entries are also relative, no need to relocate.
}

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data,
                                ConstantPoolMode constant_pool_mode) {
  if (rmode == RelocInfo::INTERNAL_REFERENCE ||
      rmode == RelocInfo::CONST_POOL || rmode == RelocInfo::VENEER_POOL ||
      rmode == RelocInfo::DEOPT_SCRIPT_OFFSET ||
      rmode == RelocInfo::DEOPT_INLINING_ID ||
      rmode == RelocInfo::DEOPT_REASON || rmode == RelocInfo::DEOPT_ID ||
      rmode == RelocInfo::DEOPT_NODE_ID) {
    // Adjust code for new modes.
    DCHECK(RelocInfo::IsDeoptReason(rmode) || RelocInfo::IsDeoptId(rmode) ||
           RelocInfo::IsDeoptNodeId(rmode) ||
           RelocInfo::IsDeoptPosition(rmode) ||
           RelocInfo::IsInternalReference(rmode) ||
           RelocInfo::IsConstPool(rmode) || RelocInfo::IsVeneerPool(rmode));
    // These modes do not need an entry in the constant pool.
  } else if (constant_pool_mode == NEEDS_POOL_ENTRY) {
    if (RelocInfo::IsEmbeddedObjectMode(rmode)) {
      Handle<HeapObject> handle(reinterpret_cast<Address*>(data));
      data = AddEmbeddedObject(handle);
    }
    if (rmode == RelocInfo::COMPRESSED_EMBEDDED_OBJECT) {
      if (constpool_.RecordEntry(static_cast<uint32_t>(data), rmode) ==
          RelocInfoStatus::kMustOmitForDuplicate) {
        return;
      }
    } else {
      if (constpool_.RecordEntry(static_cast<uint64_t>(data), rmode) ==
          RelocInfoStatus::kMustOmitForDuplicate) {
        return;
      }
    }
  }
  // For modes that cannot use the constant pool, a different sequence of
  // instructions will be emitted by this function's caller.

  if (!ShouldRecordRelocInfo(rmode)) return;

  // Callers should ensure that constant pool emission is blocked until the
  // instruction the reloc info is associated with has been emitted.
  DCHECK(constpool_.IsBlocked());

  // We do not try to reuse pool constants.
  RelocInfo rinfo(reinterpret_cast<Address>(pc_), rmode, data);
  DCHECK_GE(buffer_space(), kMaxRelocSize);  // too late to grow buffer here
  reloc_info_writer.Write(&rinfo);
}

void Assembler::near_jump(int offset, RelocInfo::Mode rmode) {
  BlockPoolsScope no_pool_before_b_instr(this);
  if (!RelocInfo::IsNoInfo(rmode))
    RecordRelocInfo(rmode, offset, NO_POOL_ENTRY);
  b(offset);
}

void Assembler::near_call(int offset, RelocInfo::Mode rmode) {
  BlockPoolsScope no_pool_before_bl_instr(this);
  if (!RelocInfo::IsNoInfo(rmode))
    RecordRelocInfo(rmode, offset, NO_POOL_ENTRY);
  bl(offset);
}

void Assembler::near_call(HeapNumberRequest request) {
  BlockPoolsScope no_pool_before_bl_instr(this);
  RequestHeapNumber(request);
  EmbeddedObjectIndex index = AddEmbeddedObject(Handle<Code>());
  RecordRelocInfo(RelocInfo::CODE_TARGET, index, NO_POOL_ENTRY);
  DCHECK(is_int32(index));
  bl(static_cast<int>(index));
}

// Constant Pool

void ConstantPool::EmitPrologue(Alignment require_alignment) {
  // Recorded constant pool size is expressed in number of 32-bits words,
  // and includes prologue and alignment, but not the jump around the pool
  // and the size of the marker itself.
  const int marker_size = 1;
  int word_count =
      ComputeSize(Jump::kOmitted, require_alignment) / kInt32Size - marker_size;
  assm_->Emit(LDR_x_lit | Assembler::ImmLLiteral(word_count) |
              Assembler::Rt(xzr));
  assm_->EmitPoolGuard();
}

int ConstantPool::PrologueSize(Jump require_jump) const {
  // Prologue is:
  //   b   over  ;; if require_jump
  //   ldr xzr, #pool_size
  //   blr xzr
  int prologue_size = require_jump == Jump::kRequired ? kInstrSize : 0;
  prologue_size += 2 * kInstrSize;
  return prologue_size;
}

void ConstantPool::SetLoadOffsetToConstPoolEntry(int load_offset,
                                                 Instruction* entry_offset,
                                                 const ConstantPoolKey& key) {
  Instruction* instr = assm_->InstructionAt(load_offset);
  // Instruction to patch must be 'ldr rd, [pc, #offset]' with offset == 0.
  DCHECK(instr->IsLdrLiteral() && instr->ImmLLiteral() == 0);
  instr->SetImmPCOffsetTarget(assm_->zone(), assm_->options(), entry_offset);
}

void ConstantPool::Check(Emission force_emit, Jump require_jump,
                         size_t margin) {
  // Some short sequence of instruction must not be broken up by constant pool
  // emission, such sequences are protected by a ConstPool::BlockScope.
  if (IsBlocked()) {
    // Something is wrong if emission is forced and blocked at the same time.
    DCHECK_EQ(force_emit, Emission::kIfNeeded);
    return;
  }

  // We emit a constant pool only if :
  //  * it is not empty
  //  * emission is forced by parameter force_emit (e.g. at function end).
  //  * emission is mandatory or opportune according to {ShouldEmitNow}.
  if (!IsEmpty() && (force_emit == Emission::kForced ||
                     ShouldEmitNow(require_jump, margin))) {
    // Emit veneers for branches that would go out of range during emission of
    // the constant pool.
    int worst_case_size = ComputeSize(Jump::kRequired, Alignment::kRequired);
    assm_->CheckVeneerPool(false, require_jump == Jump::kRequired,
                           assm_->kVeneerDistanceMargin + worst_case_size +
                               static_cast<int>(margin));

    // Check that the code buffer is large enough before emitting the constant
    // pool (this includes the gap to the relocation information).
    int needed_space = worst_case_size + assm_->kGap;
    while (assm_->buffer_space() <= needed_space) {
      assm_->GrowBuffer();
    }

    EmitAndClear(require_jump);
  }
  // Since a constant pool is (now) empty, move the check offset forward by
  // the standard interval.
  SetNextCheckIn(ConstantPool::kCheckInterval);
}

// Pool entries are accessed with pc relative load therefore this cannot be more
// than 1 * MB. Since constant pool emission checks are interval based, and we
// want to keep entries close to the code, we try to emit every 64KB.
const size_t ConstantPool::kMaxDistToPool32 = 1 * MB;
const size_t ConstantPool::kMaxDistToPool64 = 1 * MB;
const size_t ConstantPool::kCheckInterval = 128 * kInstrSize;
const size_t ConstantPool::kApproxDistToPool32 = 64 * KB;
const size_t ConstantPool::kApproxDistToPool64 = kApproxDistToPool32;

const size_t ConstantPool::kOpportunityDistToPool32 = 64 * KB;
const size_t ConstantPool::kOpportunityDistToPool64 = 64 * KB;
const size_t ConstantPool::kApproxMaxEntryCount = 512;

intptr_t Assembler::MaxPCOffsetAfterVeneerPoolIfEmittedNow(size_t margin) {
  // Account for the branch and guard around the veneers.
  static constexpr int kBranchSizeInBytes = kInstrSize;
  static constexpr int kGuardSizeInBytes = kInstrSize;
  const size_t max_veneer_size_in_bytes =
      unresolved_branches_.size() * kVeneerCodeSize;
  return static_cast<intptr_t>(pc_offset() + kBranchSizeInBytes +
                               kGuardSizeInBytes + max_veneer_size_in_bytes +
                               margin);
}

void Assembler::RecordVeneerPool(int location_offset, int size) {
  Assembler::BlockPoolsScope block_pools(this, PoolEmissionCheck::kSkip);
  RelocInfo rinfo(reinterpret_cast<Address>(buffer_start_) + location_offset,
                  RelocInfo::VENEER_POOL, static_cast<intptr_t>(size));
  reloc_info_writer.Write(&rinfo);
}

void Assembler::EmitVeneers(bool force_emit, bool need_protection,
                            size_t margin) {
  ASM_CODE_COMMENT(this);
  BlockPoolsScope scope(this, PoolEmissionCheck::kSkip);

  // The exact size of the veneer pool must be recorded (see the comment at the
  // declaration site of RecordConstPool()), but computing the number of
  // veneers that will be generated is not obvious. So instead we remember the
  // current position and will record the size after the pool has been
  // generated.
  Label size_check;
  bind(&size_check);
  int veneer_pool_relocinfo_loc = pc_offset();

  Label end;
  if (need_protection) {
    b(&end);
  }

  EmitVeneersGuard();

  // We only emit veneers if needed (unless emission is forced), i.e. when the
  // max-reachable-pc of the branch has been exhausted by the current codegen
  // state. Specifically, we emit when the max-reachable-pc of the branch <= the
  // max-pc-after-veneers (over-approximated).
  const intptr_t max_pc_after_veneers =
      MaxPCOffsetAfterVeneerPoolIfEmittedNow(margin);

  {
    // The `unresolved_branches_` map is sorted by max-reachable-pc in ascending
    // order.
    auto it = unresolved_branches_.begin();
    while (it != unresolved_branches_.end()) {
      const int max_reachable_pc = it->first & ~1;
      if (!force_emit && max_reachable_pc > max_pc_after_veneers) break;

      // Found a task. We'll emit a veneer for this.

      // Calculate the branch location from the maximum reachable PC. Only
      // B.cond, CB[N]Z and TB[N]Z are veneered, and the first two branch types
      // have the same range. The LSB (branch type tag bit) is set for TB[N]Z,
      // clear otherwise.
      int pc_offset = it->first;
      if (pc_offset & 1) {
        pc_offset -= (Instruction::ImmBranchRange(TestBranchType) + 1);
      } else {
        static_assert(Instruction::ImmBranchRange(CondBranchType) ==
                      Instruction::ImmBranchRange(CompareBranchType));
        pc_offset -= Instruction::ImmBranchRange(CondBranchType);
      }
#ifdef DEBUG
      Label veneer_size_check;
      bind(&veneer_size_check);
#endif
      Label* label = it->second;
      Instruction* veneer = reinterpret_cast<Instruction*>(pc_);
      Instruction* branch = InstructionAt(pc_offset);
      RemoveBranchFromLabelLinkChain(branch, label, veneer);
      branch->SetImmPCOffsetTarget(zone(), options(), veneer);
      b(label);  // This may end up pointing at yet another veneer later on.
      DCHECK_EQ(SizeOfCodeGeneratedSince(&veneer_size_check),
                static_cast<uint64_t>(kVeneerCodeSize));
      it = unresolved_branches_.erase(it);
    }
  }

  // Update next_veneer_pool_check_ (tightly coupled with unresolved_branches_).
  // This must happen after the calls to {RemoveBranchFromLabelLinkChain},
  // because that function can resolve additional branches.
  if (unresolved_branches_.empty()) {
    next_veneer_pool_check_ = kMaxInt;
  } else {
    next_veneer_pool_check_ =
        unresolved_branches_first_limit() - kVeneerDistanceCheckMargin;
  }

  // Record the veneer pool size.
  int pool_size = static_cast<int>(SizeOfCodeGeneratedSince(&size_check));
  RecordVeneerPool(veneer_pool_relocinfo_loc, pool_size);

  bind(&end);
}

void Assembler::CheckVeneerPool(bool force_emit, bool require_jump,
                                size_t margin) {
  // There is nothing to do if there are no pending veneer pool entries.
  if (unresolved_branches_.empty()) {
    DCHECK_EQ(next_veneer_pool_check_, kMaxInt);
    return;
  }

  DCHECK(pc_offset() < unresolved_branches_first_limit());

  // Some short sequence of instruction mustn't be broken up by veneer pool
  // emission, such sequences are protected by calls to BlockVeneerPoolFor and
  // BlockVeneerPoolScope.
  if (is_veneer_pool_blocked()) {
    DCHECK(!force_emit);
    return;
  }

  if (!require_jump) {
    // Prefer emitting veneers protected by an existing instruction.
    margin *= kVeneerNoProtectionFactor;
  }
  if (force_emit || ShouldEmitVeneers(margin)) {
    EmitVeneers(force_emit, require_jump, margin);
  } else {
    next_veneer_pool_check_ =
        unresolved_branches_first_limit() - kVeneerDistanceCheckMargin;
  }
}

int Assembler::buffer_space() const {
  return static_cast<int>(reloc_info_writer.pos() - pc_);
}

void Assembler::RecordConstPool(int size) {
  // We only need this for debugger support, to correctly compute offsets in the
  // code.
  Assembler::BlockPoolsScope block_pools(this);
  RecordRelocInfo(RelocInfo::CONST_POOL, static_cast<intptr_t>(size));
}

void PatchingAssembler::PatchAdrFar(int64_t target_offset) {
  // The code at the current instruction should be:
  //   adr  rd, 0
  //   nop  (adr_far)
  //   nop  (adr_far)
  //   movz scratch, 0

  // Verify the expected code.
  Instruction* expected_adr = InstructionAt(0);
  CHECK(expected_adr->IsAdr() && (expected_adr->ImmPCRel() == 0));
  int rd_code = expected_adr->Rd();
  for (int i = 0; i < kAdrFarPatchableNNops; ++i) {
    CHECK(InstructionAt((i + 1) * kInstrSize)->IsNop(ADR_FAR_NOP));
  }
  Instruction* expected_movz =
      InstructionAt((kAdrFarPatchableNInstrs - 1) * kInstrSize);
  CHECK(expected_movz->IsMovz() && (expected_movz->ImmMoveWide() == 0) &&
        (expected_movz->ShiftMoveWide() == 0));
  int scratch_code = expected_movz->Rd();

  // Patch to load the correct address.
  Register rd = Register::XRegFromCode(rd_code);
  Register scratch = Register::XRegFromCode(scratch_code);
  // Addresses are only 48 bits.
  adr(rd, target_offset & 0xFFFF);
  movz(scratch, (target_offset >> 16) & 0xFFFF, 16);
  movk(scratch, (target_offset >> 32) & 0xFFFF, 32);
  DCHECK_EQ(target_offset >> 48, 0);
  add(rd, rd, scratch);
}

void PatchingAssembler::PatchSubSp(uint32_t immediate) {
  // The code at the current instruction should be:
  //   sub sp, sp, #0

  // Verify the expected code.
  Instruction* expected_adr = InstructionAt(0);
  CHECK(expected_adr->IsAddSubImmediate());
  sub(sp, sp, immediate);
}

#undef NEON_3DIFF_LONG_LIST
#undef NEON_3DIFF_HN_LIST
#undef NEON_ACROSSLANES_LIST
#undef NEON_FP2REGMISC_FCVT_LIST
#undef NEON_FP2REGMISC_LIST
#undef NEON_3SAME_LIST
#undef NEON_FP3SAME_LIST_V2
#undef NEON_BYELEMENT_LIST
#undef NEON_FPBYELEMENT_LIST
#undef NEON_BYELEMENT_LONG_LIST

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM64

"""


```