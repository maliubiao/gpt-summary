Response: The user wants a summary of the C++ source code file `v8/src/diagnostics/arm64/disasm-arm64.cc`. The request specifies that this is part 1 of 2. The key elements to identify are the purpose of the code and its relation to JavaScript.

**Plan:**

1. **Identify the Core Functionality:** Analyze the class name `DisassemblingDecoder` and the various `Visit` methods. These strongly suggest the code is involved in the process of taking raw machine code (ARM64 in this case) and converting it into a human-readable assembly representation (disassembly).
2. **Connect to JavaScript (if possible):**  Consider how the V8 JavaScript engine might use such a disassembler. Disassembly is crucial for debugging, profiling, and understanding the generated machine code. Think about scenarios where V8 needs to examine the compiled code.
3. **Provide a Concise Summary:**  Synthesize the findings into a brief explanation of the code's purpose.
4. **Illustrate with a JavaScript Example (if applicable):**  Show a JavaScript code snippet and explain how the disassembler might be used in relation to its compiled form within V8.
这个C++源代码文件 `disasm-arm64.cc` 的主要功能是**将 ARM64 架构的机器码指令反汇编成人类可读的汇编代码**。

具体来说，它定义了一个名为 `DisassemblingDecoder` 的类，该类包含了一系列 `Visit` 方法，每个方法对应一种或多种 ARM64 指令格式。当给定一个 ARM64 指令时，相应的 `Visit` 方法会被调用，该方法会解析指令的各个字段，并根据指令的类型和操作数生成汇编代码字符串。

**它与 JavaScript 的功能有很强的关系：**

V8 JavaScript 引擎会将 JavaScript 代码编译成机器码以便执行。为了进行调试、性能分析或者理解 V8 的代码生成过程，开发者需要查看这些生成的机器码的汇编表示。`disasm-arm64.cc` 文件中的代码就是 V8 引擎中负责将编译后的 JavaScript 代码（以 ARM64 机器码的形式存在）反汇编成汇编代码的关键部分。

**JavaScript 示例说明:**

假设我们有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 引擎编译 `add` 函数时，它会生成 ARM64 机器码。我们可以通过 V8 提供的一些内部工具或者调试方法来获取这段机器码。然后，V8 内部会使用 `DisassemblingDecoder` 类（或者类似功能的代码）将这段机器码转换成类似下面的 ARM64 汇编代码：

```assembly
// 假设的反汇编结果 (实际结果可能更复杂)
push {lr}              // 将链接寄存器入栈
add w0, w0, w1         // 将 w0 和 w1 寄存器的值相加，结果存入 w0
pop {pc}               // 将栈顶的值弹出到程序计数器，返回
```

在这个例子中，`disasm-arm64.cc` 提供的功能就是将 V8 生成的 `add w0, w0, w1` 这样的机器码指令转换成我们能理解的汇编字符串。

总而言之，`disasm-arm64.cc` 文件是 V8 引擎中一个重要的组成部分，它负责将 ARM64 架构的机器码指令转换成可读的汇编代码，这对于理解 V8 的内部工作原理和调试优化 JavaScript 代码至关重要。

### 提示词
```
这是目录为v8/src/diagnostics/arm64/disasm-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <bitset>

#if V8_TARGET_ARCH_ARM64

#include "src/base/platform/platform.h"
#include "src/base/platform/wrappers.h"
#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/codegen/arm64/decoder-arm64-inl.h"
#include "src/codegen/arm64/utils-arm64.h"
#include "src/diagnostics/arm64/disasm-arm64.h"
#include "src/diagnostics/disasm.h"

namespace v8 {
namespace internal {

DisassemblingDecoder::DisassemblingDecoder() {
  buffer_size_ = 256;
  buffer_ = reinterpret_cast<char*>(base::Malloc(buffer_size_));
  buffer_pos_ = 0;
  own_buffer_ = true;
}

DisassemblingDecoder::DisassemblingDecoder(char* text_buffer, int buffer_size) {
  buffer_size_ = buffer_size;
  buffer_ = text_buffer;
  buffer_pos_ = 0;
  own_buffer_ = false;
}

DisassemblingDecoder::~DisassemblingDecoder() {
  if (own_buffer_) {
    base::Free(buffer_);
  }
}

char* DisassemblingDecoder::GetOutput() { return buffer_; }

void DisassemblingDecoder::VisitAddSubImmediate(Instruction* instr) {
  bool rd_is_zr = RdIsZROrSP(instr);
  bool stack_op = (rd_is_zr || RnIsZROrSP(instr)) && (instr->ImmAddSub() == 0)
                      ? true
                      : false;
  const char* mnemonic = "";
  const char* form = "'Rds, 'Rns, 'IAddSub";
  const char* form_cmp = "'Rns, 'IAddSub";
  const char* form_mov = "'Rds, 'Rns";

  switch (instr->Mask(AddSubImmediateMask)) {
    case ADD_w_imm:
    case ADD_x_imm: {
      mnemonic = "add";
      if (stack_op) {
        mnemonic = "mov";
        form = form_mov;
      }
      break;
    }
    case ADDS_w_imm:
    case ADDS_x_imm: {
      mnemonic = "adds";
      if (rd_is_zr) {
        mnemonic = "cmn";
        form = form_cmp;
      }
      break;
    }
    case SUB_w_imm:
    case SUB_x_imm:
      mnemonic = "sub";
      break;
    case SUBS_w_imm:
    case SUBS_x_imm: {
      mnemonic = "subs";
      if (rd_is_zr) {
        mnemonic = "cmp";
        form = form_cmp;
      }
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitAddSubShifted(Instruction* instr) {
  bool rd_is_zr = RdIsZROrSP(instr);
  bool rn_is_zr = RnIsZROrSP(instr);
  const char* mnemonic = "";
  const char* form = "'Rd, 'Rn, 'Rm'NDP";
  const char* form_cmp = "'Rn, 'Rm'NDP";
  const char* form_neg = "'Rd, 'Rm'NDP";

  switch (instr->Mask(AddSubShiftedMask)) {
    case ADD_w_shift:
    case ADD_x_shift:
      mnemonic = "add";
      break;
    case ADDS_w_shift:
    case ADDS_x_shift: {
      mnemonic = "adds";
      if (rd_is_zr) {
        mnemonic = "cmn";
        form = form_cmp;
      }
      break;
    }
    case SUB_w_shift:
    case SUB_x_shift: {
      mnemonic = "sub";
      if (rn_is_zr) {
        mnemonic = "neg";
        form = form_neg;
      }
      break;
    }
    case SUBS_w_shift:
    case SUBS_x_shift: {
      mnemonic = "subs";
      if (rd_is_zr) {
        mnemonic = "cmp";
        form = form_cmp;
      } else if (rn_is_zr) {
        mnemonic = "negs";
        form = form_neg;
      }
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitAddSubExtended(Instruction* instr) {
  bool rd_is_zr = RdIsZROrSP(instr);
  const char* mnemonic = "";
  Extend mode = static_cast<Extend>(instr->ExtendMode());
  const char* form = ((mode == UXTX) || (mode == SXTX)) ? "'Rds, 'Rns, 'Xm'Ext"
                                                        : "'Rds, 'Rns, 'Wm'Ext";
  const char* form_cmp =
      ((mode == UXTX) || (mode == SXTX)) ? "'Rns, 'Xm'Ext" : "'Rns, 'Wm'Ext";

  switch (instr->Mask(AddSubExtendedMask)) {
    case ADD_w_ext:
    case ADD_x_ext:
      mnemonic = "add";
      break;
    case ADDS_w_ext:
    case ADDS_x_ext: {
      mnemonic = "adds";
      if (rd_is_zr) {
        mnemonic = "cmn";
        form = form_cmp;
      }
      break;
    }
    case SUB_w_ext:
    case SUB_x_ext:
      mnemonic = "sub";
      break;
    case SUBS_w_ext:
    case SUBS_x_ext: {
      mnemonic = "subs";
      if (rd_is_zr) {
        mnemonic = "cmp";
        form = form_cmp;
      }
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitAddSubWithCarry(Instruction* instr) {
  bool rn_is_zr = RnIsZROrSP(instr);
  const char* mnemonic = "";
  const char* form = "'Rd, 'Rn, 'Rm";
  const char* form_neg = "'Rd, 'Rm";

  switch (instr->Mask(AddSubWithCarryMask)) {
    case ADC_w:
    case ADC_x:
      mnemonic = "adc";
      break;
    case ADCS_w:
    case ADCS_x:
      mnemonic = "adcs";
      break;
    case SBC_w:
    case SBC_x: {
      mnemonic = "sbc";
      if (rn_is_zr) {
        mnemonic = "ngc";
        form = form_neg;
      }
      break;
    }
    case SBCS_w:
    case SBCS_x: {
      mnemonic = "sbcs";
      if (rn_is_zr) {
        mnemonic = "ngcs";
        form = form_neg;
      }
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitLogicalImmediate(Instruction* instr) {
  bool rd_is_zr = RdIsZROrSP(instr);
  bool rn_is_zr = RnIsZROrSP(instr);
  const char* mnemonic = "";
  const char* form = "'Rds, 'Rn, 'ITri";

  if (instr->ImmLogical() == 0) {
    // The immediate encoded in the instruction is not in the expected format.
    Format(instr, "unallocated", "(LogicalImmediate)");
    return;
  }

  switch (instr->Mask(LogicalImmediateMask)) {
    case AND_w_imm:
    case AND_x_imm:
      mnemonic = "and";
      break;
    case ORR_w_imm:
    case ORR_x_imm: {
      mnemonic = "orr";
      unsigned reg_size =
          (instr->SixtyFourBits() == 1) ? kXRegSizeInBits : kWRegSizeInBits;
      if (rn_is_zr && !IsMovzMovnImm(reg_size, instr->ImmLogical())) {
        mnemonic = "mov";
        form = "'Rds, 'ITri";
      }
      break;
    }
    case EOR_w_imm:
    case EOR_x_imm:
      mnemonic = "eor";
      break;
    case ANDS_w_imm:
    case ANDS_x_imm: {
      mnemonic = "ands";
      if (rd_is_zr) {
        mnemonic = "tst";
        form = "'Rn, 'ITri";
      }
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

bool DisassemblingDecoder::IsMovzMovnImm(unsigned reg_size, uint64_t value) {
  DCHECK((reg_size == kXRegSizeInBits) ||
         ((reg_size == kWRegSizeInBits) && (value <= 0xFFFFFFFF)));

  // Test for movz: 16-bits set at positions 0, 16, 32 or 48.
  if (((value & 0xFFFFFFFFFFFF0000UL) == 0UL) ||
      ((value & 0xFFFFFFFF0000FFFFUL) == 0UL) ||
      ((value & 0xFFFF0000FFFFFFFFUL) == 0UL) ||
      ((value & 0x0000FFFFFFFFFFFFUL) == 0UL)) {
    return true;
  }

  // Test for movn: NOT(16-bits set at positions 0, 16, 32 or 48).
  if ((reg_size == kXRegSizeInBits) &&
      (((value & 0xFFFFFFFFFFFF0000UL) == 0xFFFFFFFFFFFF0000UL) ||
       ((value & 0xFFFFFFFF0000FFFFUL) == 0xFFFFFFFF0000FFFFUL) ||
       ((value & 0xFFFF0000FFFFFFFFUL) == 0xFFFF0000FFFFFFFFUL) ||
       ((value & 0x0000FFFFFFFFFFFFUL) == 0x0000FFFFFFFFFFFFUL))) {
    return true;
  }
  if ((reg_size == kWRegSizeInBits) && (((value & 0xFFFF0000) == 0xFFFF0000) ||
                                        ((value & 0x0000FFFF) == 0x0000FFFF))) {
    return true;
  }
  return false;
}

void DisassemblingDecoder::VisitLogicalShifted(Instruction* instr) {
  bool rd_is_zr = RdIsZROrSP(instr);
  bool rn_is_zr = RnIsZROrSP(instr);
  const char* mnemonic = "";
  const char* form = "'Rd, 'Rn, 'Rm'NLo";

  switch (instr->Mask(LogicalShiftedMask)) {
    case AND_w:
    case AND_x:
      mnemonic = "and";
      break;
    case BIC_w:
    case BIC_x:
      mnemonic = "bic";
      break;
    case EOR_w:
    case EOR_x:
      mnemonic = "eor";
      break;
    case EON_w:
    case EON_x:
      mnemonic = "eon";
      break;
    case BICS_w:
    case BICS_x:
      mnemonic = "bics";
      break;
    case ANDS_w:
    case ANDS_x: {
      mnemonic = "ands";
      if (rd_is_zr) {
        mnemonic = "tst";
        form = "'Rn, 'Rm'NLo";
      }
      break;
    }
    case ORR_w:
    case ORR_x: {
      mnemonic = "orr";
      if (rn_is_zr && (instr->ImmDPShift() == 0) && (instr->ShiftDP() == LSL)) {
        mnemonic = "mov";
        form = "'Rd, 'Rm";
      }
      break;
    }
    case ORN_w:
    case ORN_x: {
      mnemonic = "orn";
      if (rn_is_zr) {
        mnemonic = "mvn";
        form = "'Rd, 'Rm'NLo";
      }
      break;
    }
    default:
      UNREACHABLE();
  }

  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitConditionalCompareRegister(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Rn, 'Rm, 'INzcv, 'Cond";

  switch (instr->Mask(ConditionalCompareRegisterMask)) {
    case CCMN_w:
    case CCMN_x:
      mnemonic = "ccmn";
      break;
    case CCMP_w:
    case CCMP_x:
      mnemonic = "ccmp";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitConditionalCompareImmediate(
    Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Rn, 'IP, 'INzcv, 'Cond";

  switch (instr->Mask(ConditionalCompareImmediateMask)) {
    case CCMN_w_imm:
    case CCMN_x_imm:
      mnemonic = "ccmn";
      break;
    case CCMP_w_imm:
    case CCMP_x_imm:
      mnemonic = "ccmp";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitConditionalSelect(Instruction* instr) {
  bool rnm_is_zr = (RnIsZROrSP(instr) && RmIsZROrSP(instr));
  bool rn_is_rm = (instr->Rn() == instr->Rm());
  const char* mnemonic = "";
  const char* form = "'Rd, 'Rn, 'Rm, 'Cond";
  const char* form_test = "'Rd, 'CInv";
  const char* form_update = "'Rd, 'Rn, 'CInv";

  Condition cond = static_cast<Condition>(instr->Condition());
  bool invertible_cond = (cond != al) && (cond != nv);

  switch (instr->Mask(ConditionalSelectMask)) {
    case CSEL_w:
    case CSEL_x:
      mnemonic = "csel";
      break;
    case CSINC_w:
    case CSINC_x: {
      mnemonic = "csinc";
      if (rnm_is_zr && invertible_cond) {
        mnemonic = "cset";
        form = form_test;
      } else if (rn_is_rm && invertible_cond) {
        mnemonic = "cinc";
        form = form_update;
      }
      break;
    }
    case CSINV_w:
    case CSINV_x: {
      mnemonic = "csinv";
      if (rnm_is_zr && invertible_cond) {
        mnemonic = "csetm";
        form = form_test;
      } else if (rn_is_rm && invertible_cond) {
        mnemonic = "cinv";
        form = form_update;
      }
      break;
    }
    case CSNEG_w:
    case CSNEG_x: {
      mnemonic = "csneg";
      if (rn_is_rm && invertible_cond) {
        mnemonic = "cneg";
        form = form_update;
      }
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitBitfield(Instruction* instr) {
  unsigned s = instr->ImmS();
  unsigned r = instr->ImmR();
  unsigned rd_size_minus_1 =
      ((instr->SixtyFourBits() == 1) ? kXRegSizeInBits : kWRegSizeInBits) - 1;
  const char* mnemonic = "";
  const char* form = "";
  const char* form_shift_right = "'Rd, 'Rn, 'IBr";
  const char* form_extend = "'Rd, 'Wn";
  const char* form_bfiz = "'Rd, 'Rn, 'IBZ-r, 'IBs+1";
  const char* form_bfx = "'Rd, 'Rn, 'IBr, 'IBs-r+1";
  const char* form_lsl = "'Rd, 'Rn, 'IBZ-r";

  switch (instr->Mask(BitfieldMask)) {
    case SBFM_w:
    case SBFM_x: {
      mnemonic = "sbfx";
      form = form_bfx;
      if (r == 0) {
        form = form_extend;
        if (s == 7) {
          mnemonic = "sxtb";
        } else if (s == 15) {
          mnemonic = "sxth";
        } else if ((s == 31) && (instr->SixtyFourBits() == 1)) {
          mnemonic = "sxtw";
        } else {
          form = form_bfx;
        }
      } else if (s == rd_size_minus_1) {
        mnemonic = "asr";
        form = form_shift_right;
      } else if (s < r) {
        mnemonic = "sbfiz";
        form = form_bfiz;
      }
      break;
    }
    case UBFM_w:
    case UBFM_x: {
      mnemonic = "ubfx";
      form = form_bfx;
      if (r == 0) {
        form = form_extend;
        if (s == 7) {
          mnemonic = "uxtb";
        } else if (s == 15) {
          mnemonic = "uxth";
        } else {
          form = form_bfx;
        }
      }
      if (s == rd_size_minus_1) {
        mnemonic = "lsr";
        form = form_shift_right;
      } else if (r == s + 1) {
        mnemonic = "lsl";
        form = form_lsl;
      } else if (s < r) {
        mnemonic = "ubfiz";
        form = form_bfiz;
      }
      break;
    }
    case BFM_w:
    case BFM_x: {
      mnemonic = "bfxil";
      form = form_bfx;
      if (s < r) {
        mnemonic = "bfi";
        form = form_bfiz;
      }
    }
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitExtract(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Rd, 'Rn, 'Rm, 'IExtract";

  switch (instr->Mask(ExtractMask)) {
    case EXTR_w:
    case EXTR_x: {
      if (instr->Rn() == instr->Rm()) {
        mnemonic = "ror";
        form = "'Rd, 'Rn, 'IExtract";
      } else {
        mnemonic = "extr";
      }
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitPCRelAddressing(Instruction* instr) {
  switch (instr->Mask(PCRelAddressingMask)) {
    case ADR:
      Format(instr, "adr", "'Xd, 'AddrPCRelByte");
      break;
    // ADRP is not implemented.
    default:
      Format(instr, "unimplemented", "(PCRelAddressing)");
  }
}

void DisassemblingDecoder::VisitConditionalBranch(Instruction* instr) {
  switch (instr->Mask(ConditionalBranchMask)) {
    case B_cond:
      Format(instr, "b.'CBrn", "'TImmCond");
      break;
    default:
      UNREACHABLE();
  }
}

void DisassemblingDecoder::VisitUnconditionalBranchToRegister(
    Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Xn";

  switch (instr->Mask(UnconditionalBranchToRegisterMask)) {
    case BR:
      mnemonic = "br";
      break;
    case BLR:
      mnemonic = "blr";
      break;
    case RET: {
      mnemonic = "ret";
      if (instr->Rn() == kLinkRegCode) {
        form = nullptr;
      }
      break;
    }
    default:
      form = "(UnconditionalBranchToRegister)";
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitUnconditionalBranch(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'TImmUncn";

  switch (instr->Mask(UnconditionalBranchMask)) {
    case B:
      mnemonic = "b";
      break;
    case BL:
      mnemonic = "bl";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitDataProcessing1Source(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Rd, 'Rn";

  switch (instr->Mask(DataProcessing1SourceMask)) {
#define FORMAT(A, B) \
  case A##_w:        \
  case A##_x:        \
    mnemonic = B;    \
    break;
    FORMAT(RBIT, "rbit");
    FORMAT(REV16, "rev16");
    FORMAT(REV, "rev");
    FORMAT(CLZ, "clz");
    FORMAT(CLS, "cls");
#undef FORMAT
    case REV32_x:
      mnemonic = "rev32";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitDataProcessing2Source(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Rd, 'Rn, 'Rm";

  switch (instr->Mask(DataProcessing2SourceMask)) {
#define FORMAT(A, B) \
  case A##_w:        \
  case A##_x:        \
    mnemonic = B;    \
    break;
    FORMAT(UDIV, "udiv");
    FORMAT(SDIV, "sdiv");
    FORMAT(LSLV, "lsl");
    FORMAT(LSRV, "lsr");
    FORMAT(ASRV, "asr");
    FORMAT(RORV, "ror");
#undef FORMAT
    default:
      form = "(DataProcessing2Source)";
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitDataProcessing3Source(Instruction* instr) {
  bool ra_is_zr = RaIsZROrSP(instr);
  const char* mnemonic = "";
  const char* form = "'Xd, 'Wn, 'Wm, 'Xa";
  const char* form_rrr = "'Rd, 'Rn, 'Rm";
  const char* form_rrrr = "'Rd, 'Rn, 'Rm, 'Ra";
  const char* form_xww = "'Xd, 'Wn, 'Wm";
  const char* form_xxx = "'Xd, 'Xn, 'Xm";

  switch (instr->Mask(DataProcessing3SourceMask)) {
    case MADD_w:
    case MADD_x: {
      mnemonic = "madd";
      form = form_rrrr;
      if (ra_is_zr) {
        mnemonic = "mul";
        form = form_rrr;
      }
      break;
    }
    case MSUB_w:
    case MSUB_x: {
      mnemonic = "msub";
      form = form_rrrr;
      if (ra_is_zr) {
        mnemonic = "mneg";
        form = form_rrr;
      }
      break;
    }
    case SMADDL_x: {
      mnemonic = "smaddl";
      if (ra_is_zr) {
        mnemonic = "smull";
        form = form_xww;
      }
      break;
    }
    case SMSUBL_x: {
      mnemonic = "smsubl";
      if (ra_is_zr) {
        mnemonic = "smnegl";
        form = form_xww;
      }
      break;
    }
    case UMADDL_x: {
      mnemonic = "umaddl";
      if (ra_is_zr) {
        mnemonic = "umull";
        form = form_xww;
      }
      break;
    }
    case UMSUBL_x: {
      mnemonic = "umsubl";
      if (ra_is_zr) {
        mnemonic = "umnegl";
        form = form_xww;
      }
      break;
    }
    case SMULH_x: {
      mnemonic = "smulh";
      form = form_xxx;
      break;
    }
    case UMULH_x: {
      mnemonic = "umulh";
      form = form_xxx;
      break;
    }
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitCompareBranch(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Rt, 'TImmCmpa";

  switch (instr->Mask(CompareBranchMask)) {
    case CBZ_w:
    case CBZ_x:
      mnemonic = "cbz";
      break;
    case CBNZ_w:
    case CBNZ_x:
      mnemonic = "cbnz";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitTestBranch(Instruction* instr) {
  const char* mnemonic = "";
  // If the top bit of the immediate is clear, the tested register is
  // disassembled as Wt, otherwise Xt. As the top bit of the immediate is
  // encoded in bit 31 of the instruction, we can reuse the Rt form, which
  // uses bit 31 (normally "sf") to choose the register size.
  const char* form = "'Rt, 'IS, 'TImmTest";

  switch (instr->Mask(TestBranchMask)) {
    case TBZ:
      mnemonic = "tbz";
      break;
    case TBNZ:
      mnemonic = "tbnz";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitMoveWideImmediate(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Rd, 'IMoveImm";

  // Print the shift separately for movk, to make it clear which half word will
  // be overwritten. Movn and movz print the computed immediate, which includes
  // shift calculation.
  switch (instr->Mask(MoveWideImmediateMask)) {
    case MOVN_w:
    case MOVN_x:
      mnemonic = "movn";
      break;
    case MOVZ_w:
    case MOVZ_x:
      mnemonic = "movz";
      break;
    case MOVK_w:
    case MOVK_x:
      mnemonic = "movk";
      form = "'Rd, 'IMoveLSL";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

#define LOAD_STORE_LIST(V)   \
  V(STRB_w, "strb", "'Wt")   \
  V(STRH_w, "strh", "'Wt")   \
  V(STR_w, "str", "'Wt")     \
  V(STR_x, "str", "'Xt")     \
  V(LDRB_w, "ldrb", "'Wt")   \
  V(LDRH_w, "ldrh", "'Wt")   \
  V(LDR_w, "ldr", "'Wt")     \
  V(LDR_x, "ldr", "'Xt")     \
  V(LDRSB_x, "ldrsb", "'Xt") \
  V(LDRSH_x, "ldrsh", "'Xt") \
  V(LDRSW_x, "ldrsw", "'Xt") \
  V(LDRSB_w, "ldrsb", "'Wt") \
  V(LDRSH_w, "ldrsh", "'Wt") \
  V(STR_b, "str", "'Bt")     \
  V(STR_h, "str", "'Ht")     \
  V(STR_s, "str", "'St")     \
  V(STR_d, "str", "'Dt")     \
  V(LDR_b, "ldr", "'Bt")     \
  V(LDR_h, "ldr", "'Ht")     \
  V(LDR_s, "ldr", "'St")     \
  V(LDR_d, "ldr", "'Dt")     \
  V(STR_q, "str", "'Qt")     \
  V(LDR_q, "ldr", "'Qt")

void DisassemblingDecoder::VisitLoadStorePreIndex(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStorePreIndex)";

  switch (instr->Mask(LoadStorePreIndexMask)) {
#define LS_PREINDEX(A, B, C)  \
  case A##_pre:               \
    mnemonic = B;             \
    form = C ", ['Xns'ILS]!"; \
    break;
    LOAD_STORE_LIST(LS_PREINDEX)
#undef LS_PREINDEX
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitLoadStorePostIndex(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStorePostIndex)";

  switch (instr->Mask(LoadStorePostIndexMask)) {
#define LS_POSTINDEX(A, B, C) \
  case A##_post:              \
    mnemonic = B;             \
    form = C ", ['Xns]'ILS";  \
    break;
    LOAD_STORE_LIST(LS_POSTINDEX)
#undef LS_POSTINDEX
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitLoadStoreUnsignedOffset(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStoreUnsignedOffset)";

  switch (instr->Mask(LoadStoreUnsignedOffsetMask)) {
#define LS_UNSIGNEDOFFSET(A, B, C) \
  case A##_unsigned:               \
    mnemonic = B;                  \
    form = C ", ['Xns'ILU]";       \
    break;
    LOAD_STORE_LIST(LS_UNSIGNEDOFFSET)
#undef LS_UNSIGNEDOFFSET
    case PRFM_unsigned:
      mnemonic = "prfm";
      form = "'PrefOp, ['Xn'ILU]";
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitLoadStoreRegisterOffset(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStoreRegisterOffset)";

  switch (instr->Mask(LoadStoreRegisterOffsetMask)) {
#define LS_REGISTEROFFSET(A, B, C)   \
  case A##_reg:                      \
    mnemonic = B;                    \
    form = C ", ['Xns, 'Offsetreg]"; \
    break;
    LOAD_STORE_LIST(LS_REGISTEROFFSET)
#undef LS_REGISTEROFFSET
    case PRFM_reg:
      mnemonic = "prfm";
      form = "'PrefOp, ['Xns, 'Offsetreg]";
  }
  Format(instr, mnemonic, form);
}

#undef LOAD_STORE_LIST

#define LOAD_STORE_UNSCALED_LIST(V) \
  V(STURB_w, "sturb", "'Wt")        \
  V(STURH_w, "sturh", "'Wt")        \
  V(STUR_w, "stur", "'Wt")          \
  V(STUR_x, "stur", "'Xt")          \
  V(LDURB_w, "ldurb", "'Wt")        \
  V(LDURH_w, "ldurh", "'Wt")        \
  V(LDUR_w, "ldur", "'Wt")          \
  V(LDUR_x, "ldur", "'Xt")          \
  V(LDURSB_x, "ldursb", "'Xt")      \
  V(LDURSH_x, "ldursh", "'Xt")      \
  V(LDURSW_x, "ldursw", "'Xt")      \
  V(LDURSB_w, "ldursb", "'Wt")      \
  V(LDURSH_w, "ldursh", "'Wt")      \
  V(STUR_b, "stur", "'Bt")          \
  V(STUR_h, "stur", "'Ht")          \
  V(STUR_s, "stur", "'St")          \
  V(STUR_d, "stur", "'Dt")          \
  V(LDUR_b, "ldur", "'Bt")          \
  V(LDUR_h, "ldur", "'Ht")          \
  V(LDUR_s, "ldur", "'St")          \
  V(LDUR_d, "ldur", "'Dt")          \
  V(STUR_q, "stur", "'Qt")          \
  V(LDUR_q, "ldur", "'Qt")

void DisassemblingDecoder::VisitLoadStoreUnscaledOffset(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStoreUnscaledOffset)";

  switch (instr->Mask(LoadStoreUnscaledOffsetMask)) {
#define LS_UNSCALEDOFFSET(A, B, C) \
  case A:                          \
    mnemonic = B;                  \
    form = C ", ['Xns'ILS]";       \
    break;
    LOAD_STORE_UNSCALED_LIST(LS_UNSCALEDOFFSET)
#undef LS_UNSCALEDOFFSET
  }
  Format(instr, mnemonic, form);
}

#undef LOAD_STORE_UNSCALED_LIST

void DisassemblingDecoder::VisitLoadLiteral(Instruction* instr) {
  const char* mnemonic = "ldr";
  const char* form = "(LoadLiteral)";

  switch (instr->Mask(LoadLiteralMask)) {
    case LDR_w_lit:
      form = "'Wt, 'ILLiteral 'LValue";
      break;
    case LDR_x_lit:
      form = "'Xt, 'ILLiteral 'LValue";
      break;
    case LDR_s_lit:
      form = "'St, 'ILLiteral 'LValue";
      break;
    case LDR_d_lit:
      form = "'Dt, 'ILLiteral 'LValue";
      break;
    default:
      mnemonic = "unimplemented";
  }
  Format(instr, mnemonic, form);
}

#define LOAD_STORE_PAIR_LIST(V)         \
  V(STP_w, "stp", "'Wt, 'Wt2", "2")     \
  V(LDP_w, "ldp", "'Wt, 'Wt2", "2")     \
  V(LDPSW_x, "ldpsw", "'Xt, 'Xt2", "2") \
  V(STP_x, "stp", "'Xt, 'Xt2", "3")     \
  V(LDP_x, "ldp", "'Xt, 'Xt2", "3")     \
  V(STP_s, "stp", "'St, 'St2", "2")     \
  V(LDP_s, "ldp", "'St, 'St2", "2")     \
  V(STP_d, "stp", "'Dt, 'Dt2", "3")     \
  V(LDP_d, "ldp", "'Dt, 'Dt2", "3")     \
  V(LDP_q, "ldp", "'Qt, 'Qt2", "4")     \
  V(STP_q, "stp", "'Qt, 'Qt2", "4")

void DisassemblingDecoder::VisitLoadStorePairPostIndex(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStorePairPostIndex)";

  switch (instr->Mask(LoadStorePairPostIndexMask)) {
#define LSP_POSTINDEX(A, B, C, D) \
  case A##_post:                  \
    mnemonic = B;                 \
    form = C ", ['Xns]'ILP" D;    \
    break;
    LOAD_STORE_PAIR_LIST(LSP_POSTINDEX)
#undef LSP_POSTINDEX
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitLoadStorePairPreIndex(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStorePairPreIndex)";

  switch (instr->Mask(LoadStorePairPreIndexMask)) {
#define LSP_PREINDEX(A, B, C, D)   \
  case A##_pre:                    \
    mnemonic = B;                  \
    form = C ", ['Xns'ILP" D "]!"; \
    break;
    LOAD_STORE_PAIR_LIST(LSP_PREINDEX)
#undef LSP_PREINDEX
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitLoadStorePairOffset(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(LoadStorePairOffset)";

  switch (instr->Mask(LoadStorePairOffsetMask)) {
#define LSP_OFFSET(A, B, C, D)    \
  case A##_off:                   \
    mnemonic = B;                 \
    form = C ", ['Xns'ILP" D "]"; \
    break;
    LOAD_STORE_PAIR_LIST(LSP_OFFSET)
#undef LSP_OFFSET
  }
  Format(instr, mnemonic, form);
}

#undef LOAD_STORE_PAIR_LIST

#define LOAD_STORE_ACQUIRE_RELEASE_LIST(V)      \
  V(STLXR_b, "stlxrb", "'Ws, 'Wt")              \
  V(STLXR_h, "stlxrh", "'Ws, 'Wt")              \
  V(STLXR_w, "stlxr", "'Ws, 'Wt")               \
  V(STLXR_x, "stlxr", "'Ws, 'Xt")               \
  V(LDAXR_b, "ldaxrb", "'Wt")                   \
  V(LDAXR_h, "ldaxrh", "'Wt")                   \
  V(LDAXR_w, "ldaxr", "'Wt")                    \
  V(LDAXR_x, "ldaxr", "'Xt")                    \
  V(STLR_b, "stlrb", "'Wt")                     \
  V(STLR_h, "stlrh", "'Wt")                     \
  V(STLR_w, "stlr", "'Wt")                      \
  V(STLR_x, "stlr", "'Xt")                      \
  V(LDAR_b, "ldarb", "'Wt")                     \
  V(LDAR_h, "ldarh", "'Wt")                     \
  V(LDAR_w, "ldar", "'Wt")                      \
  V(LDAR_x, "ldar", "'Xt")                      \
  V(CAS_w, "cas", "'Ws, 'Wt")                   \
  V(CAS_x, "cas", "'Xs, 'Xt")                   \
  V(CASA_w, "casa", "'Ws, 'Wt")                 \
  V(CASA_x, "casa", "'Xs, 'Xt")                 \
  V(CASL_w, "casl", "'Ws, 'Wt")                 \
  V(CASL_x, "casl", "'Xs, 'Xt")                 \
  V(CASAL_w, "casal", "'Ws, 'Wt")               \
  V(CASAL_x, "casal", "'Xs, 'Xt")               \
  V(CASB, "casb", "'Ws, 'Wt")                   \
  V(CASAB, "casab", "'Ws, 'Wt")                 \
  V(CASLB, "caslb", "'Ws, 'Wt")                 \
  V(CASALB, "casalb", "'Ws, 'Wt")               \
  V(CASH, "cash", "'Ws, 'Wt")                   \
  V(CASAH, "casah", "'Ws, 'Wt")                 \
  V(CASLH, "caslh", "'Ws, 'Wt")                 \
  V(CASALH, "casalh", "'Ws, 'Wt")               \
  V(CASP_w, "casp", "'Ws, 'Ws+, 'Wt, 'Wt+")     \
  V(CASP_x, "casp", "'Xs, 'Xs+, 'Xt, 'Xt+")     \
  V(CASPA_w, "caspa", "'Ws, 'Ws+, 'Wt, 'Wt+")   \
  V(CASPA_x, "caspa", "'Xs, 'Xs+, 'Xt, 'Xt+")   \
  V(CASPL_w, "caspl", "'Ws, 'Ws+, 'Wt, 'Wt+")   \
  V(CASPL_x, "caspl", "'Xs, 'Xs+, 'Xt, 'Xt+")   \
  V(CASPAL_w, "caspal", "'Ws, 'Ws+, 'Wt, 'Wt+") \
  V(CASPAL_x, "caspal", "'Xs, 'Xs+, 'Xt, 'Xt+")

void DisassemblingDecoder::VisitLoadStoreAcquireRelease(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form;

  switch (instr->Mask(LoadStoreAcquireReleaseMask)) {
#define LSAR(A, B, C)    \
  case A:                \
    mnemonic = B;        \
    form = C ", ['Xns]"; \
    break;
    LOAD_STORE_ACQUIRE_RELEASE_LIST(LSAR)
#undef LSAR
    default:
      form = "(LoadStoreAcquireRelease)";
  }

  switch (instr->Mask(LoadStoreAcquireReleaseMask)) {
    case CASP_w:
    case CASP_x:
    case CASPA_w:
    case CASPA_x:
    case CASPL_w:
    case CASPL_x:
    case CASPAL_w:
    case CASPAL_x:
      if ((instr->Rs() % 2 == 1) || (instr->Rt() % 2 == 1)) {
        mnemonic = "unallocated";
        form = "(LoadStoreExclusive)";
      }
      break;
  }

  Format(instr, mnemonic, form);
}

#undef LOAD_STORE_ACQUIRE_RELEASE_LIST

#define ATOMIC_MEMORY_SIMPLE_LIST(V) \
  V(LDADD, "add")                    \
  V(LDCLR, "clr")                    \
  V(LDEOR, "eor")                    \
  V(LDSET, "set")                    \
  V(LDSMAX, "smax")                  \
  V(LDSMIN, "smin")                  \
  V(LDUMAX, "umax")                  \
  V(LDUMIN, "umin")

void DisassemblingDecoder::VisitAtomicMemory(Instruction* instr) {
  const int kMaxAtomicOpMnemonicLength = 16;
  const char* mnemonic;
  const char* form = "'Ws, 'Wt, ['Xns]";

  switch (instr->Mask(AtomicMemoryMask)) {
#define AMS(A, MN)             \
  case A##B:                   \
    mnemonic = MN "b";         \
    break;                     \
  case A##AB:                  \
    mnemonic = MN "ab";        \
    break;                     \
  case A##LB:                  \
    mnemonic = MN "lb";        \
    break;                     \
  case A##ALB:                 \
    mnemonic = MN "alb";       \
    break;                     \
  case A##H:                   \
    mnemonic = MN "h";         \
    break;                     \
  case A##AH:                  \
    mnemonic = MN "ah";        \
    break;                     \
  case A##LH:                  \
    mnemonic = MN "lh";        \
    break;                     \
  case A##ALH:                 \
    mnemonic = MN "alh";       \
    break;                     \
  case A##_w:                  \
    mnemonic = MN;             \
    break;                     \
  case A##A_w:                 \
    mnemonic = MN "a";         \
    break;                     \
  case A##L_w:                 \
    mnemonic = MN "l";         \
    break;                     \
  case A##AL_w:                \
    mnemonic = MN "al";        \
    break;                     \
  case A##_x:                  \
    mnemonic = MN;             \
    form = "'Xs, 'Xt, ['Xns]"; \
    break;                     \
  case A##A_x:                 \
    mnemonic = MN "a";         \
    form = "'Xs, 'Xt, ['Xns]"; \
    break;                     \
  case A##L_x:                 \
    mnemonic = MN "l";         \
    form = "'Xs, 'Xt, ['Xns]"; \
    break;                     \
  case A##AL_x:                \
    mnemonic = MN "al";        \
    form = "'Xs, 'Xt, ['Xns]"; \
    break;
    ATOMIC_MEMORY_SIMPLE_LIST(AMS)

    // SWP has the same semantics as ldadd etc but without the store aliases.
    AMS(SWP, "swp")
#undef AMS

    default:
      mnemonic = "unimplemented";
      form = "(AtomicMemory)";
  }

  const char* prefix = "";
  switch (instr->Mask(AtomicMemoryMask)) {
#define AMS(A, MN)             \
  case A##AB:                  \
  case A##ALB:                 \
  case A##AH:                  \
  case A##ALH:                 \
  case A##A_w:                 \
  case A##AL_w:                \
  case A##A_x:                 \
  case A##AL_x:                \
    prefix = "ld";             \
    break;                     \
  case A##B:                   \
  case A##LB:                  \
  case A##H:                   \
  case A##LH:                  \
  case A##_w:                  \
  case A##L_w: {               \
    prefix = "ld";             \
    unsigned rt = instr->Rt(); \
    if (rt == kZeroRegCode) {  \
      prefix = "st";           \
      form = "'Ws, ['Xns]";    \
    }                          \
    break;                     \
  }                            \
  case A##_x:                  \
  case A##L_x: {               \
    prefix = "ld";             \
    unsigned rt = instr->Rt(); \
    if (rt == kZeroRegCode) {  \
      prefix = "st";           \
      form = "'Xs, ['Xns]";    \
    }                          \
    break;                     \
  }
    ATOMIC_MEMORY_SIMPLE_LIST(AMS)
#undef AMS
  }

  char buffer[kMaxAtomicOpMnemonicLength];
  if (strlen(prefix) > 0) {
    snprintf(buffer, kMaxAtomicOpMnemonicLength, "%s%s", prefix, mnemonic);
    mnemonic = buffer;
  }

  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPCompare(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Fn, 'Fm";
  const char* form_zero = "'Fn, #0.0";

  switch (instr->Mask(FPCompareMask)) {
    case FCMP_s_zero:
    case FCMP_d_zero:
      form = form_zero;
      [[fallthrough]];
    case FCMP_s:
    case FCMP_d:
      mnemonic = "fcmp";
      break;
    default:
      form = "(FPCompare)";
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPConditionalCompare(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Fn, 'Fm, 'INzcv, 'Cond";

  switch (instr->Mask(FPConditionalCompareMask)) {
    case FCCMP_s:
    case FCCMP_d:
      mnemonic = "fccmp";
      break;
    case FCCMPE_s:
    case FCCMPE_d:
      mnemonic = "fccmpe";
      break;
    default:
      form = "(FPConditionalCompare)";
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPConditionalSelect(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Fd, 'Fn, 'Fm, 'Cond";

  switch (instr->Mask(FPConditionalSelectMask)) {
    case FCSEL_s:
    case FCSEL_d:
      mnemonic = "fcsel";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPDataProcessing1Source(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Fd, 'Fn";

  switch (instr->Mask(FPDataProcessing1SourceMask)) {
#define FORMAT(A, B) \
  case A##_s:        \
  case A##_d:        \
    mnemonic = B;    \
    break;
    FORMAT(FMOV, "fmov");
    FORMAT(FABS, "fabs");
    FORMAT(FNEG, "fneg");
    FORMAT(FSQRT, "fsqrt");
    FORMAT(FRINTN, "frintn");
    FORMAT(FRINTP, "frintp");
    FORMAT(FRINTM, "frintm");
    FORMAT(FRINTZ, "frintz");
    FORMAT(FRINTA, "frinta");
    FORMAT(FRINTX, "frintx");
    FORMAT(FRINTI, "frinti");
#undef FORMAT
    case FCVT_ds:
      mnemonic = "fcvt";
      form = "'Dd, 'Sn";
      break;
    case FCVT_sd:
      mnemonic = "fcvt";
      form = "'Sd, 'Dn";
      break;
    case FCVT_hs:
      mnemonic = "fcvt";
      form = "'Hd, 'Sn";
      break;
    case FCVT_sh:
      mnemonic = "fcvt";
      form = "'Sd, 'Hn";
      break;
    case FCVT_dh:
      mnemonic = "fcvt";
      form = "'Dd, 'Hn";
      break;
    case FCVT_hd:
      mnemonic = "fcvt";
      form = "'Hd, 'Dn";
      break;
    default:
      form = "(FPDataProcessing1Source)";
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPDataProcessing2Source(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Fd, 'Fn, 'Fm";

  switch (instr->Mask(FPDataProcessing2SourceMask)) {
#define FORMAT(A, B) \
  case A##_s:        \
  case A##_d:        \
    mnemonic = B;    \
    break;
    FORMAT(FMUL, "fmul");
    FORMAT(FDIV, "fdiv");
    FORMAT(FADD, "fadd");
    FORMAT(FSUB, "fsub");
    FORMAT(FMAX, "fmax");
    FORMAT(FMIN, "fmin");
    FORMAT(FMAXNM, "fmaxnm");
    FORMAT(FMINNM, "fminnm");
    FORMAT(FNMUL, "fnmul");
#undef FORMAT
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPDataProcessing3Source(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Fd, 'Fn, 'Fm, 'Fa";

  switch (instr->Mask(FPDataProcessing3SourceMask)) {
#define FORMAT(A, B) \
  case A##_s:        \
  case A##_d:        \
    mnemonic = B;    \
    break;
    FORMAT(FMADD, "fmadd");
    FORMAT(FMSUB, "fmsub");
    FORMAT(FNMADD, "fnmadd");
    FORMAT(FNMSUB, "fnmsub");
#undef FORMAT
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPImmediate(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "(FPImmediate)";

  switch (instr->Mask(FPImmediateMask)) {
    case FMOV_s_imm:
      mnemonic = "fmov";
      form = "'Sd, 'IFPSingle";
      break;
    case FMOV_d_imm:
      mnemonic = "fmov";
      form = "'Dd, 'IFPDouble";
      break;
    default:
      UNREACHABLE();
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPIntegerConvert(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(FPIntegerConvert)";
  const char* form_rf = "'Rd, 'Fn";
  const char* form_fr = "'Fd, 'Rn";

  switch (instr->Mask(FPIntegerConvertMask)) {
    case FMOV_ws:
    case FMOV_xd:
      mnemonic = "fmov";
      form = form_rf;
      break;
    case FMOV_sw:
    case FMOV_dx:
      mnemonic = "fmov";
      form = form_fr;
      break;
    case FMOV_d1_x:
      mnemonic = "fmov";
      form = "'Vd.D[1], 'Rn";
      break;
    case FMOV_x_d1:
      mnemonic = "fmov";
      form = "'Rd, 'Vn.D[1]";
      break;
    case FCVTAS_ws:
    case FCVTAS_xs:
    case FCVTAS_wd:
    case FCVTAS_xd:
      mnemonic = "fcvtas";
      form = form_rf;
      break;
    case FCVTAU_ws:
    case FCVTAU_xs:
    case FCVTAU_wd:
    case FCVTAU_xd:
      mnemonic = "fcvtau";
      form = form_rf;
      break;
    case FCVTMS_ws:
    case FCVTMS_xs:
    case FCVTMS_wd:
    case FCVTMS_xd:
      mnemonic = "fcvtms";
      form = form_rf;
      break;
    case FCVTMU_ws:
    case FCVTMU_xs:
    case FCVTMU_wd:
    case FCVTMU_xd:
      mnemonic = "fcvtmu";
      form = form_rf;
      break;
    case FCVTNS_ws:
    case FCVTNS_xs:
    case FCVTNS_wd:
    case FCVTNS_xd:
      mnemonic = "fcvtns";
      form = form_rf;
      break;
    case FCVTNU_ws:
    case FCVTNU_xs:
    case FCVTNU_wd:
    case FCVTNU_xd:
      mnemonic = "fcvtnu";
      form = form_rf;
      break;
    case FCVTZU_xd:
    case FCVTZU_ws:
    case FCVTZU_wd:
    case FCVTZU_xs:
      mnemonic = "fcvtzu";
      form = form_rf;
      break;
    case FCVTZS_xd:
    case FCVTZS_wd:
    case FCVTZS_xs:
    case FCVTZS_ws:
      mnemonic = "fcvtzs";
      form = form_rf;
      break;
    case FCVTPU_xd:
    case FCVTPU_ws:
    case FCVTPU_wd:
    case FCVTPU_xs:
      mnemonic = "fcvtpu";
      form = form_rf;
      break;
    case FCVTPS_xd:
    case FCVTPS_wd:
    case FCVTPS_xs:
    case FCVTPS_ws:
      mnemonic = "fcvtps";
      form = form_rf;
      break;
    case SCVTF_sw:
    case SCVTF_sx:
    case SCVTF_dw:
    case SCVTF_dx:
      mnemonic = "scvtf";
      form = form_fr;
      break;
    case UCVTF_sw:
    case UCVTF_sx:
    case UCVTF_dw:
    case UCVTF_dx:
      mnemonic = "ucvtf";
      form = form_fr;
      break;
    case FJCVTZS:
      mnemonic = "fjcvtzs";
      form = form_rf;
      break;
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitFPFixedPointConvert(Instruction* instr) {
  const char* mnemonic = "";
  const char* form = "'Rd, 'Fn, 'IFPFBits";
  const char* form_fr = "'Fd, 'Rn, 'IFPFBits";

  switch (instr->Mask(FPFixedPointConvertMask)) {
    case FCVTZS_ws_fixed:
    case FCVTZS_xs_fixed:
    case FCVTZS_wd_fixed:
    case FCVTZS_xd_fixed:
      mnemonic = "fcvtzs";
      break;
    case FCVTZU_ws_fixed:
    case FCVTZU_xs_fixed:
    case FCVTZU_wd_fixed:
    case FCVTZU_xd_fixed:
      mnemonic = "fcvtzu";
      break;
    case SCVTF_sw_fixed:
    case SCVTF_sx_fixed:
    case SCVTF_dw_fixed:
    case SCVTF_dx_fixed:
      mnemonic = "scvtf";
      form = form_fr;
      break;
    case UCVTF_sw_fixed:
    case UCVTF_sx_fixed:
    case UCVTF_dw_fixed:
    case UCVTF_dx_fixed:
      mnemonic = "ucvtf";
      form = form_fr;
      break;
  }
  Format(instr, mnemonic, form);
}

// clang-format off
#define PAUTH_SYSTEM_MNEMONICS(V) \
  V(PACIB1716, "pacib1716")       \
  V(AUTIB1716, "autib1716")       \
  V(PACIBSP,   "pacibsp")         \
  V(AUTIBSP,   "autibsp")
// clang-format on

void DisassemblingDecoder::VisitSystem(Instruction* instr) {
  // Some system instructions hijack their Op and Cp fields to represent a
  // range of immediates instead of indicating a different instruction. This
  // makes the decoding tricky.
  const char* mnemonic = "unimplemented";
  const char* form = "(System)";
  if (instr->Mask(SystemPAuthFMask) == SystemPAuthFixed) {
    switch (instr->Mask(SystemPAuthMask)) {
#define PAUTH_CASE(NAME, MN) \
  case NAME:                 \
    mnemonic = MN;           \
    form = nullptr;          \
    break;

      PAUTH_SYSTEM_MNEMONICS(PAUTH_CASE)
#undef PAUTH_CASE
#undef PAUTH_SYSTEM_MNEMONICS
    }
  } else if (instr->Mask(SystemSysRegFMask) == SystemSysRegFixed) {
    switch (instr->Mask(SystemSysRegMask)) {
      case MRS: {
        mnemonic = "mrs";
        switch (instr->ImmSystemRegister()) {
          case NZCV:
            form = "'Xt, nzcv";
            break;
          case FPCR:
            form = "'Xt, fpcr";
            break;
          default:
            form = "'Xt, (unknown)";
            break;
        }
        break;
      }
      case MSR: {
        mnemonic = "msr";
        switch (instr->ImmSystemRegister()) {
          case NZCV:
            form = "nzcv, 'Xt";
            break;
          case FPCR:
            form = "fpcr, 'Xt";
            break;
          default:
            form = "(unknown), 'Xt";
            break;
        }
        break;
      }
    }
  } else if (instr->Mask(SystemHintFMask) == SystemHintFixed) {
    DCHECK(instr->Mask(SystemHintMask) == HINT);
    form = nullptr;
    switch (instr->ImmHint()) {
      case NOP:
        mnemonic = "nop";
        break;
      case YIELD:
        mnemonic = "yield";
        break;
      case CSDB:
        mnemonic = "csdb";
        break;
      case BTI:
        mnemonic = "bti";
        break;
      case BTI_c:
        mnemonic = "bti c";
        break;
      case BTI_j:
        mnemonic = "bti j";
        break;
      case BTI_jc:
        mnemonic = "bti jc";
        break;
      default:
        // Fall back to 'hint #<imm7>'.
        form = "'IH";
        mnemonic = "hint";
    }
  } else if (instr->Mask(MemBarrierFMask) == MemBarrierFixed) {
    switch (instr->Mask(MemBarrierMask)) {
      case DMB: {
        mnemonic = "dmb";
        form = "'M";
        break;
      }
      case DSB: {
        mnemonic = "dsb";
        form = "'M";
        break;
      }
      case ISB: {
        mnemonic = "isb";
        form = nullptr;
        break;
      }
    }
  }

  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitException(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'IDebug";

  switch (instr->Mask(ExceptionMask)) {
    case HLT:
      mnemonic = "hlt";
      break;
    case BRK:
      mnemonic = "brk";
      break;
    case SVC:
      mnemonic = "svc";
      break;
    case HVC:
      mnemonic = "hvc";
      break;
    case SMC:
      mnemonic = "smc";
      break;
    case DCPS1:
      mnemonic = "dcps1";
      form = "{'IDebug}";
      break;
    case DCPS2:
      mnemonic = "dcps2";
      form = "{'IDebug}";
      break;
    case DCPS3:
      mnemonic = "dcps3";
      form = "{'IDebug}";
      break;
    default:
      form = "(Exception)";
  }
  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitNEON3Same(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Vd.%s, 'Vn.%s, 'Vm.%s";
  NEONFormatDecoder nfd(instr);

  if (instr->Mask(NEON3SameLogicalFMask) == NEON3SameLogicalFixed) {
    switch (instr->Mask(NEON3SameLogicalMask)) {
      case NEON_AND:
        mnemonic = "and";
        break;
      case NEON_ORR:
        mnemonic = "orr";
        if (instr->Rm() == instr->Rn()) {
          mnemonic = "mov";
          form = "'Vd.%s, 'Vn.%s";
        }
        break;
      case NEON_ORN:
        mnemonic = "orn";
        break;
      case NEON_EOR:
        mnemonic = "eor";
        break;
      case NEON_BIC:
        mnemonic = "bic";
        break;
      case NEON_BIF:
        mnemonic = "bif";
        break;
      case NEON_BIT:
        mnemonic = "bit";
        break;
      case NEON_BSL:
        mnemonic = "bsl";
        break;
      default:
        form = "(NEON3Same)";
    }
    nfd.SetFormatMaps(nfd.LogicalFormatMap());
  } else {
    static const char* mnemonics[] = {
        "shadd",       "uhadd",       "shadd",       "uhadd",
        "sqadd",       "uqadd",       "sqadd",       "uqadd",
        "srhadd",      "urhadd",      "srhadd",      "urhadd",
        nullptr,       nullptr,       nullptr,
        nullptr,  // Handled by logical cases above.
        "shsub",       "uhsub",       "shsub",       "uhsub",
        "sqsub",       "uqsub",       "sqsub",       "uqsub",
        "cmgt",        "cmhi",        "cmgt",        "cmhi",
        "cmge",        "cmhs",        "cmge",        "cmhs",
        "sshl",        "ushl",        "sshl",        "ushl",
        "sqshl",       "uqshl",       "sqshl",       "uqshl",
        "srshl",       "urshl",       "srshl",       "urshl",
        "sqrshl",      "uqrshl",      "sqrshl",      "uqrshl",
        "smax",        "umax",        "smax",        "umax",
        "smin",        "umin",        "smin",        "umin",
        "sabd",        "uabd",        "sabd",        "uabd",
        "saba",        "uaba",        "saba",        "uaba",
        "add",         "sub",         "add",         "sub",
        "cmtst",       "cmeq",        "cmtst",       "cmeq",
        "mla",         "mls",         "mla",         "mls",
        "mul",         "pmul",        "mul",         "pmul",
        "smaxp",       "umaxp",       "smaxp",       "umaxp",
        "sminp",       "uminp",       "sminp",       "uminp",
        "sqdmulh",     "sqrdmulh",    "sqdmulh",     "sqrdmulh",
        "addp",        "unallocated", "addp",        "unallocated",
        "fmaxnm",      "fmaxnmp",     "fminnm",      "fminnmp",
        "fmla",        "unallocated", "fmls",        "unallocated",
        "fadd",        "faddp",       "fsub",        "fabd",
        "fmulx",       "fmul",        "unallocated", "unallocated",
        "fcmeq",       "fcmge",       "unallocated", "fcmgt",
        "unallocated", "facge",       "unallocated", "facgt",
        "fmax",        "fmaxp",       "fmin",        "fminp",
        "frecps",      "fdiv",        "frsqrts",     "unallocated"};

    // Operation is determined by the opcode bits (15-11), the top bit of
    // size (23) and the U bit (29).
    unsigned index =
        (instr->Bits(15, 11) << 2) | (instr->Bit(23) << 1) | instr->Bit(29);
    DCHECK_LT(index, arraysize(mnemonics));
    mnemonic = mnemonics[index];
    // Assert that index is not one of the previously handled logical
    // instructions.
    DCHECK_NOT_NULL(mnemonic);

    if (instr->Mask(NEON3SameFPFMask) == NEON3SameFPFixed) {
      nfd.SetFormatMaps(nfd.FPFormatMap());
    }
  }
  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEON3SameHP(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Vd.%s, 'Vn.%s, 'Vm.%s";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::FPHPFormatMap());

  static const char* mnemonics[] = {
      "fmaxnm", "fmaxnmp", "fminnm",  "fminnmp", "fmla",  "uqadd", "fmls",
      "uqadd",  "fadd",    "faddp",   "fsub",    "fabd",  "fmulx", "fmul",
      "fmul",   "fmul",    "fcmeq",   "fcmge",   "shsub", "fcmgt", "sqsub",
      "facge",  "sqsub",   "facgt",   "fmax",    "fmaxp", "fmin",  "fminp",
      "frecps", "fdiv",    "frsqrts", "fdiv"};

  // Operation is determined by the opcode bits (13-11), the top bit of
  // size (23) and the U bit (29).
  unsigned index =
      (instr->Bits(13, 11) << 2) | (instr->Bit(23) << 1) | instr->Bit(29);
  DCHECK_LT(index, arraysize(mnemonics));
  mnemonic = mnemonics[index];

  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEON2RegMisc(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Vd.%s, 'Vn.%s";
  const char* form_cmp_zero = "'Vd.%s, 'Vn.%s, #0";
  const char* form_fcmp_zero = "'Vd.%s, 'Vn.%s, #0.0";
  NEONFormatDecoder nfd(instr);

  static const NEONFormatMap map_lp_ta = {
      {23, 22, 30}, {NF_4H, NF_8H, NF_2S, NF_4S, NF_1D, NF_2D}};

  static const NEONFormatMap map_cvt_ta = {{22}, {NF_4S, NF_2D}};

  static const NEONFormatMap map_cvt_tb = {{22, 30},
                                           {NF_4H, NF_8H, NF_2S, NF_4S}};

  if (instr->Mask(NEON2RegMiscOpcode) <= NEON_NEG_opcode) {
    // These instructions all use a two bit size field, except NOT and RBIT,
    // which use the field to encode the operation.
    switch (instr->Mask(NEON2RegMiscMask)) {
      case NEON_REV64:
        mnemonic = "rev64";
        break;
      case NEON_REV32:
        mnemonic = "rev32";
        break;
      case NEON_REV16:
        mnemonic = "rev16";
        break;
      case NEON_SADDLP:
        mnemonic = "saddlp";
        nfd.SetFormatMap(0, &map_lp_ta);
        break;
      case NEON_UADDLP:
        mnemonic = "uaddlp";
        nfd.SetFormatMap(0, &map_lp_ta);
        break;
      case NEON_SUQADD:
        mnemonic = "suqadd";
        break;
      case NEON_USQADD:
        mnemonic = "usqadd";
        break;
      case NEON_CLS:
        mnemonic = "cls";
        break;
      case NEON_CLZ:
        mnemonic = "clz";
        break;
      case NEON_CNT:
        mnemonic = "cnt";
        break;
      case NEON_SADALP:
        mnemonic = "sadalp";
        nfd.SetFormatMap(0, &map_lp_ta);
        break;
      case NEON_UADALP:
        mnemonic = "uadalp";
        nfd.SetFormatMap(0, &map_lp_ta);
        break;
      case NEON_SQABS:
        mnemonic = "sqabs";
        break;
      case NEON_SQNEG:
        mnemonic = "sqneg";
        break;
      case NEON_CMGT_zero:
        mnemonic = "cmgt";
        form = form_cmp_zero;
        break;
      case NEON_CMGE_zero:
        mnemonic = "cmge";
        form = form_cmp_zero;
        break;
      case NEON_CMEQ_zero:
        mnemonic = "cmeq";
        form = form_cmp_zero;
        break;
      case NEON_CMLE_zero:
        mnemonic = "cmle";
        form = form_cmp_zero;
        break;
      case NEON_CMLT_zero:
        mnemonic = "cmlt";
        form = form_cmp_zero;
        break;
      case NEON_ABS:
        mnemonic = "abs";
        break;
      case NEON_NEG:
        mnemonic = "neg";
        break;
      case NEON_RBIT_NOT:
        switch (instr->FPType()) {
          case 0:
            mnemonic = "mvn";
            break;
          case 1:
            mnemonic = "rbit";
            break;
          default:
            form = "(NEON2RegMisc)";
        }
        nfd.SetFormatMaps(nfd.LogicalFormatMap());
        break;
    }
  } else {
    // These instructions all use a one bit size field, except XTN, SQXTUN,
    // SHLL, SQXTN and UQXTN, which use a two bit size field.
    if (instr->Mask(NEON2RegMiscHPFixed) == NEON2RegMiscHPFixed) {
      nfd.SetFormatMaps(nfd.FPHPFormatMap());
    } else {
      nfd.SetFormatMaps(nfd.FPFormatMap());
    }
    switch (instr->Mask(NEON2RegMiscFPMask ^ NEON2RegMiscHPFixed)) {
      case NEON_FABS:
        mnemonic = "fabs";
        break;
      case NEON_FNEG:
        mnemonic = "fneg";
        break;
      case NEON_FCVTN:
        mnemonic = instr->Mask(NEON_Q) ? "fcvtn2" : "fcvtn";
        nfd.SetFormatMap(0, &map_cvt_tb);
        nfd.SetFormatMap(1, &map_cvt_ta);
        break;
      case NEON_FCVTXN:
        mnemonic = instr->Mask(NEON_Q) ? "fcvtxn2" : "fcvtxn";
        nfd.SetFormatMap(0, &map_cvt_tb);
        nfd.SetFormatMap(1, &map_cvt_ta);
        break;
      case NEON_FCVTL:
        mnemonic = instr->Mask(NEON_Q) ? "fcvtl2" : "fcvtl";
        nfd.SetFormatMap(0, &map_cvt_ta);
        nfd.SetFormatMap(1, &map_cvt_tb);
        break;
      case NEON_FRINTN:
        mnemonic = "frintn";
        break;
      case NEON_FRINTA:
        mnemonic = "frinta";
        break;
      case NEON_FRINTP:
        mnemonic = "frintp";
        break;
      case NEON_FRINTM:
        mnemonic = "frintm";
        break;
      case NEON_FRINTX:
        mnemonic = "frintx";
        break;
      case NEON_FRINTZ:
        mnemonic = "frintz";
        break;
      case NEON_FRINTI:
        mnemonic = "frinti";
        break;
      case NEON_FCVTNS:
        mnemonic = "fcvtns";
        break;
      case NEON_FCVTNU:
        mnemonic = "fcvtnu";
        break;
      case NEON_FCVTPS:
        mnemonic = "fcvtps";
        break;
      case NEON_FCVTPU:
        mnemonic = "fcvtpu";
        break;
      case NEON_FCVTMS:
        mnemonic = "fcvtms";
        break;
      case NEON_FCVTMU:
        mnemonic = "fcvtmu";
        break;
      case NEON_FCVTZS:
        mnemonic = "fcvtzs";
        break;
      case NEON_FCVTZU:
        mnemonic = "fcvtzu";
        break;
      case NEON_FCVTAS:
        mnemonic = "fcvtas";
        break;
      case NEON_FCVTAU:
        mnemonic = "fcvtau";
        break;
      case NEON_FSQRT:
        mnemonic = "fsqrt";
        break;
      case NEON_SCVTF:
        mnemonic = "scvtf";
        break;
      case NEON_UCVTF:
        mnemonic = "ucvtf";
        break;
      case NEON_URSQRTE:
        mnemonic = "ursqrte";
        break;
      case NEON_URECPE:
        mnemonic = "urecpe";
        break;
      case NEON_FRSQRTE:
        mnemonic = "frsqrte";
        break;
      case NEON_FRECPE:
        mnemonic = "frecpe";
        break;
      case NEON_FCMGT_zero:
        mnemonic = "fcmgt";
        form = form_fcmp_zero;
        break;
      case NEON_FCMGE_zero:
        mnemonic = "fcmge";
        form = form_fcmp_zero;
        break;
      case NEON_FCMEQ_zero:
        mnemonic = "fcmeq";
        form = form_fcmp_zero;
        break;
      case NEON_FCMLE_zero:
        mnemonic = "fcmle";
        form = form_fcmp_zero;
        break;
      case NEON_FCMLT_zero:
        mnemonic = "fcmlt";
        form = form_fcmp_zero;
        break;
      default:
        if ((NEON_XTN_opcode <= instr->Mask(NEON2RegMiscOpcode)) &&
            (instr->Mask(NEON2RegMiscOpcode) <= NEON_UQXTN_opcode)) {
          nfd.SetFormatMap(0, nfd.IntegerFormatMap());
          nfd.SetFormatMap(1, nfd.LongIntegerFormatMap());

          switch (instr->Mask(NEON2RegMiscMask)) {
            case NEON_XTN:
              mnemonic = "xtn";
              break;
            case NEON_SQXTN:
              mnemonic = "sqxtn";
              break;
            case NEON_UQXTN:
              mnemonic = "uqxtn";
              break;
            case NEON_SQXTUN:
              mnemonic = "sqxtun";
              break;
            case NEON_SHLL:
              mnemonic = "shll";
              nfd.SetFormatMap(0, nfd.LongIntegerFormatMap());
              nfd.SetFormatMap(1, nfd.IntegerFormatMap());
              switch (instr->NEONSize()) {
                case 0:
                  form = "'Vd.%s, 'Vn.%s, #8";
                  break;
                case 1:
                  form = "'Vd.%s, 'Vn.%s, #16";
                  break;
                case 2:
                  form = "'Vd.%s, 'Vn.%s, #32";
                  break;
                default:
                  Format(instr, "unallocated", "(NEON2RegMisc)");
                  return;
              }
          }
          Format(instr, nfd.Mnemonic(mnemonic), nfd.Substitute(form));
          return;
        } else {
          form = "(NEON2RegMisc)";
        }
    }
  }
  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEON3Different(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Vd.%s, 'Vn.%s, 'Vm.%s";

  NEONFormatDecoder nfd(instr);
  nfd.SetFormatMap(0, nfd.LongIntegerFormatMap());

  // Ignore the Q bit. Appending a "2" suffix is handled later.
  switch (instr->Mask(NEON3DifferentMask) & ~NEON_Q) {
    case NEON_PMULL:
      DisassembleNEONPolynomialMul(instr);
      return;
    case NEON_SABAL:
      mnemonic = "sabal";
      break;
    case NEON_SABDL:
      mnemonic = "sabdl";
      break;
    case NEON_SADDL:
      mnemonic = "saddl";
      break;
    case NEON_SMLAL:
      mnemonic = "smlal";
      break;
    case NEON_SMLSL:
      mnemonic = "smlsl";
      break;
    case NEON_SMULL:
      mnemonic = "smull";
      break;
    case NEON_SSUBL:
      mnemonic = "ssubl";
      break;
    case NEON_SQDMLAL:
      mnemonic = "sqdmlal";
      break;
    case NEON_SQDMLSL:
      mnemonic = "sqdmlsl";
      break;
    case NEON_SQDMULL:
      mnemonic = "sqdmull";
      break;
    case NEON_UABAL:
      mnemonic = "uabal";
      break;
    case NEON_UABDL:
      mnemonic = "uabdl";
      break;
    case NEON_UADDL:
      mnemonic = "uaddl";
      break;
    case NEON_UMLAL:
      mnemonic = "umlal";
      break;
    case NEON_UMLSL:
      mnemonic = "umlsl";
      break;
    case NEON_UMULL:
      mnemonic = "umull";
      break;
    case NEON_USUBL:
      mnemonic = "usubl";
      break;
    case NEON_SADDW:
      mnemonic = "saddw";
      nfd.SetFormatMap(1, nfd.LongIntegerFormatMap());
      break;
    case NEON_SSUBW:
      mnemonic = "ssubw";
      nfd.SetFormatMap(1, nfd.LongIntegerFormatMap());
      break;
    case NEON_UADDW:
      mnemonic = "uaddw";
      nfd.SetFormatMap(1, nfd.LongIntegerFormatMap());
      break;
    case NEON_USUBW:
      mnemonic = "usubw";
      nfd.SetFormatMap(1, nfd.LongIntegerFormatMap());
      break;
    case NEON_ADDHN:
      mnemonic = "addhn";
      nfd.SetFormatMaps(nfd.LongIntegerFormatMap());
      nfd.SetFormatMap(0, nfd.IntegerFormatMap());
      break;
    case NEON_RADDHN:
      mnemonic = "raddhn";
      nfd.SetFormatMaps(nfd.LongIntegerFormatMap());
      nfd.SetFormatMap(0, nfd.IntegerFormatMap());
      break;
    case NEON_RSUBHN:
      mnemonic = "rsubhn";
      nfd.SetFormatMaps(nfd.LongIntegerFormatMap());
      nfd.SetFormatMap(0, nfd.IntegerFormatMap());
      break;
    case NEON_SUBHN:
      mnemonic = "subhn";
      nfd.SetFormatMaps(nfd.LongIntegerFormatMap());
      nfd.SetFormatMap(0, nfd.IntegerFormatMap());
      break;
    default:
      form = "(NEON3Different)";
  }
  Format(instr, nfd.Mnemonic(mnemonic), nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEON3Extension(Instruction* instr) {
  const char* form = "'Vd.%s, 'Vn.%s, 'Vm.%s";
  const char* mnemonic = "unimplemented";

  switch (instr->Mask(NEON3ExtensionMask)) {
    case NEON_SDOT:
      if (instr->NEONSize() != 2) {
        VisitUnallocated(instr);
        return;
      }

      form = instr->Bit(30) == 1 ? "'Vd.4s, 'Vn.16b, 'Vm.16b"
                                 : "'Vd.2s, 'Vn.8b, 'Vm.8b";
      mnemonic = "sdot";
      break;
    default:
      form = "(NEON3Extension)";
  }

  Format(instr, mnemonic, form);
}

void DisassemblingDecoder::VisitNEONAcrossLanes(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "%sd, 'Vn.%s";

  NEONFormatDecoder nfd(instr, NEONFormatDecoder::ScalarFormatMap(),
                        NEONFormatDecoder::IntegerFormatMap());

  if (instr->Mask(NEONAcrossLanesFPFMask) == NEONAcrossLanesFPFixed) {
    nfd.SetFormatMap(0, nfd.FPScalarFormatMap());
    nfd.SetFormatMap(1, nfd.FPFormatMap());
    switch (instr->Mask(NEONAcrossLanesFPMask)) {
      case NEON_FMAXV:
        mnemonic = "fmaxv";
        break;
      case NEON_FMINV:
        mnemonic = "fminv";
        break;
      case NEON_FMAXNMV:
        mnemonic = "fmaxnmv";
        break;
      case NEON_FMINNMV:
        mnemonic = "fminnmv";
        break;
      default:
        form = "(NEONAcrossLanes)";
        break;
    }
  } else if (instr->Mask(NEONAcrossLanesFMask) == NEONAcrossLanesFixed) {
    switch (instr->Mask(NEONAcrossLanesMask)) {
      case NEON_ADDV:
        mnemonic = "addv";
        break;
      case NEON_SMAXV:
        mnemonic = "smaxv";
        break;
      case NEON_SMINV:
        mnemonic = "sminv";
        break;
      case NEON_UMAXV:
        mnemonic = "umaxv";
        break;
      case NEON_UMINV:
        mnemonic = "uminv";
        break;
      case NEON_SADDLV:
        mnemonic = "saddlv";
        nfd.SetFormatMap(0, nfd.LongScalarFormatMap());
        break;
      case NEON_UADDLV:
        mnemonic = "uaddlv";
        nfd.SetFormatMap(0, nfd.LongScalarFormatMap());
        break;
      default:
        form = "(NEONAcrossLanes)";
        break;
    }
  }
  Format(instr, mnemonic,
         nfd.Substitute(form, NEONFormatDecoder::kPlaceholder,
                        NEONFormatDecoder::kFormat));
}

void DisassemblingDecoder::VisitNEONByIndexedElement(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  bool l_instr = false;
  bool fp_instr = false;

  const char* form = "'Vd.%s, 'Vn.%s, 'Ve.%s['IVByElemIndex]";

  static const NEONFormatMap map_ta = {{23, 22}, {NF_UNDEF, NF_4S, NF_2D}};
  NEONFormatDecoder nfd(instr, &map_ta, NEONFormatDecoder::IntegerFormatMap(),
                        NEONFormatDecoder::ScalarFormatMap());

  switch (instr->Mask(NEONByIndexedElementMask)) {
    case NEON_SMULL_byelement:
      mnemonic = "smull";
      l_instr = true;
      break;
    case NEON_UMULL_byelement:
      mnemonic = "umull";
      l_instr = true;
      break;
    case NEON_SMLAL_byelement:
      mnemonic = "smlal";
      l_instr = true;
      break;
    case NEON_UMLAL_byelement:
      mnemonic = "umlal";
      l_instr = true;
      break;
    case NEON_SMLSL_byelement:
      mnemonic = "smlsl";
      l_instr = true;
      break;
    case NEON_UMLSL_byelement:
      mnemonic = "umlsl";
      l_instr = true;
      break;
    case NEON_SQDMULL_byelement:
      mnemonic = "sqdmull";
      l_instr = true;
      break;
    case NEON_SQDMLAL_byelement:
      mnemonic = "sqdmlal";
      l_instr = true;
      break;
    case NEON_SQDMLSL_byelement:
      mnemonic = "sqdmlsl";
      l_instr = true;
      break;
    case NEON_MUL_byelement:
      mnemonic = "mul";
      break;
    case NEON_MLA_byelement:
      mnemonic = "mla";
      break;
    case NEON_MLS_byelement:
      mnemonic = "mls";
      break;
    case NEON_SQDMULH_byelement:
      mnemonic = "sqdmulh";
      break;
    case NEON_SQRDMULH_byelement:
      mnemonic = "sqrdmulh";
      break;
    default:
      switch (instr->Mask(NEONByIndexedElementFPMask)) {
        case NEON_FMUL_byelement:
          mnemonic = "fmul";
          fp_instr = true;
          break;
        case NEON_FMLA_byelement:
          mnemonic = "fmla";
          fp_instr = true;
          break;
        case NEON_FMLS_byelement:
          mnemonic = "fmls";
          fp_instr = true;
          break;
        case NEON_FMULX_byelement:
          mnemonic = "fmulx";
          fp_instr = true;
          break;
      }
  }

  if (l_instr) {
    Format(instr, nfd.Mnemonic(mnemonic), nfd.Substitute(form));
  } else if (fp_instr) {
    nfd.SetFormatMap(0, nfd.FPFormatMap());
    Format(instr, mnemonic, nfd.Substitute(form));
  } else {
    nfd.SetFormatMap(0, nfd.IntegerFormatMap());
    Format(instr, mnemonic, nfd.Substitute(form));
  }
}

void DisassemblingDecoder::VisitNEONCopy(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(NEONCopy)";

  NEONFormatDecoder nfd(instr, NEONFormatDecoder::TriangularFormatMap(),
                        NEONFormatDecoder::TriangularScalarFormatMap());

  if (instr->Mask(NEONCopyInsElementMask) == NEON_INS_ELEMENT) {
    mnemonic = "mov";
    nfd.SetFormatMap(0, nfd.TriangularScalarFormatMap());
    form = "'Vd.%s['IVInsIndex1], 'Vn.%s['IVInsIndex2]";
  } else if (instr->Mask(NEONCopyInsGeneralMask) == NEON_INS_GENERAL) {
    mnemonic = "mov";
    nfd.SetFormatMap(0, nfd.TriangularScalarFormatMap());
    if (nfd.GetVectorFormat() == kFormatD) {
      form = "'Vd.%s['IVInsIndex1], 'Xn";
    } else {
      form = "'Vd.%s['IVInsIndex1], 'Wn";
    }
  } else if (instr->Mask(NEONCopyUmovMask) == NEON_UMOV) {
    if (instr->Mask(NEON_Q) || ((instr->ImmNEON5() & 7) == 4)) {
      mnemonic = "mov";
    } else {
      mnemonic = "umov";
    }
    nfd.SetFormatMap(0, nfd.TriangularScalarFormatMap());
    if (nfd.GetVectorFormat() == kFormatD) {
      form = "'Xd, 'Vn.%s['IVInsIndex1]";
    } else {
      form = "'Wd, 'Vn.%s['IVInsIndex1]";
    }
  } else if (instr->Mask(NEONCopySmovMask) == NEON_SMOV) {
    mnemonic = "smov";
    nfd.SetFormatMap(0, nfd.TriangularScalarFormatMap());
    form = "'Rdq, 'Vn.%s['IVInsIndex1]";
  } else if (instr->Mask(NEONCopyDupElementMask) == NEON_DUP_ELEMENT) {
    mnemonic = "dup";
    form = "'Vd.%s, 'Vn.%s['IVInsIndex1]";
  } else if (instr->Mask(NEONCopyDupGeneralMask) == NEON_DUP_GENERAL) {
    mnemonic = "dup";
    if (nfd.GetVectorFormat() == kFormat2D) {
      form = "'Vd.%s, 'Xn";
    } else {
      form = "'Vd.%s, 'Wn";
    }
  }
  Format(instr, mnemonic, nfd.Substitute(form));
}

void Dis
```