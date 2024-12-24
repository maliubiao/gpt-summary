Response: The user wants a summary of the functionality of the provided C++ code snippet. This code seems to be part of a PowerPC simulator within the V8 JavaScript engine. It handles the execution of individual PowerPC instructions.

Therefore, the core functionality is **simulating the execution of PowerPC instructions**.

Key aspects to consider in the summary:
- Instruction processing logic (switch statement based on opcode).
- Manipulation of simulated registers (general purpose, condition, special purpose).
- Memory access simulation (read/write functions).
- Handling of different instruction types (arithmetic, logical, memory, branch, floating-point).
- Potential relationship to JavaScript (V8 context).

For the JavaScript example, I should choose a simple operation that can be represented by a corresponding PowerPC instruction handled in this code. A basic arithmetic operation or a comparison followed by a branch would be suitable.
这段C++代码是PowerPC架构模拟器的一部分，负责**模拟执行PowerPC架构的指令**。

具体来说，这段代码是模拟器中处理各种PowerPC指令的核心逻辑。它通过一个大的 `switch` 语句，根据当前要执行的指令的 `opcode` (操作码)，来模拟该指令的行为。

以下是这段代码所涵盖的主要功能点：

1. **指令解码和执行:**  代码接收一个 `Instruction` 对象 (可能是对原始指令的封装)，从中提取操作码和操作数，然后模拟指令执行的步骤。

2. **寄存器操作:**  模拟了PowerPC架构的各种寄存器，包括：
   - **通用寄存器 (GPRs):** 通过 `get_register()` 和 `set_register()` 函数来读取和写入。
   - **条件寄存器 (CR):** 通过 `condition_reg_` 变量和相关的位操作来模拟条件码的设置和读取。
   - **特殊寄存器:** 例如 `special_reg_lr_` (链接寄存器), `special_reg_ctr_` (计数器寄存器), `special_reg_xer_` (定点异常寄存器)。
   - **浮点寄存器 (FPRs):** 通过 `get_d_register()`, `set_d_register()`, `get_double_from_d_register()`, `set_d_register_from_double()` 等函数进行操作。

3. **内存访问模拟:**  通过 `ReadW()`, `ReadDW()`, `WriteW()`, `WriteDW()`, `ReadB()`, `WriteB()`, `ReadH()`, `WriteH()` 等函数来模拟从内存中读取数据和向内存中写入数据。 这些函数模拟了不同大小的数据访问。

4. **算术和逻辑运算:**  模拟了各种算术和逻辑指令，例如加法 (`ADDI`, `ADD`, `ADDCX`, `ADDEX`), 减法 (`SUBF`, `SUBFCX`, `SUBFEX`), 乘法 (`MULLW`, `MULLD`, `MULHWX`, `MULHWUX`), 除法 (`DIVW`, `DIVWU`, `DIVD`, `DIVDU`),  与 (`AND`, `ANDI`), 或 (`OR`, `ORI`), 异或 (`XOR`, `XORI`),  移位 (`SLW`, `SRW`, `SRA`) 等。

5. **分支指令处理:**  模拟了条件分支 (`BCX`, `BCLRX`, `BCCTRX`) 和无条件分支 (`BX`) 指令，涉及到程序计数器 (PC) 的更新。

6. **浮点运算模拟:**  模拟了各种浮点运算指令，例如加法 (`FADD`), 减法 (`FSUB`), 乘法 (`FMUL`), 除法 (`FDIV`), 平方根 (`FSQRT`), 类型转换 (`FCFID`, `FCTID`, `FCTIW`), 比较 (`FCMPU`) 等。

7. **其他指令模拟:**  还包括一些其他的指令模拟，例如位操作 (`RLWIMI`, `RLWINM`),  系统调用 (`TW`),  以及一些内存操作指令。

**与JavaScript的功能关系 (通过V8):**

这段代码是V8 JavaScript引擎的一部分，这意味着它直接参与了JavaScript代码的执行。 当V8需要执行JavaScript代码时，它会将JavaScript代码编译成机器码 (在这个例子中是PowerPC机器码，虽然V8通常会为目标架构生成代码，但模拟器用于在非PowerPC平台上运行或调试PowerPC代码)。

这个模拟器的作用是在非PowerPC架构的机器上**模拟执行这些编译后的PowerPC机器码**。 这对于以下场景非常重要：

* **在非PowerPC平台上测试V8:**  开发者可以在他们的开发机器上 (例如x86) 运行和测试V8的PowerPC版本。
* **PowerPC平台上的调试:**  可以提供更细粒度的控制和观察代码执行的能力，例如单步执行、查看寄存器状态等。

**JavaScript 示例:**

假设有一段简单的JavaScript代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当V8执行这段代码时，`add(5, 10)` 这个加法操作可能会被编译成一系列PowerPC指令。 其中一个可能的PowerPC指令是 `add` 指令。  在模拟器中，当执行到这个 `add` 指令时，就会进入到 `simulator-ppc.cc` 中 `case ADDX:` 的代码块。

```c++
case ADDX: {
  int rt = instr->RTValue(); // 获取目标寄存器
  int ra = instr->RAValue(); // 获取第一个操作数寄存器
  int rb = instr->RBValue(); // 获取第二个操作数寄存器
  // int oe = instr->Bit(10);
  intptr_t ra_val = get_register(ra); // 从寄存器中读取第一个操作数的值 (5)
  intptr_t rb_val = get_register(rb); // 从寄存器中读取第二个操作数的值 (10)
  intptr_t alu_out = ra_val + rb_val; // 执行加法运算 (5 + 10 = 15)
  set_register(rt, alu_out);       // 将结果 (15) 写入目标寄存器
  if (instr->Bit(0)) {  // RC bit set
    SetCR0(alu_out);
  }
  // todo - handle OE bit
  break;
}
```

在这个模拟执行的过程中，模拟器会读取存储着数值 5 和 10 的模拟寄存器的值，执行加法运算，并将结果 15 存储到另一个模拟寄存器中。  最终，这个结果会被用于后续的JavaScript操作，例如赋值给 `result` 变量。

总而言之， `simulator-ppc.cc` 的这段代码是V8引擎在非PowerPC平台上执行或调试PowerPC代码的关键组成部分，它通过软件的方式精确地模拟了PowerPC架构的指令行为，从而使得V8能够在更广泛的平台上运行。

Prompt: 
```
这是目录为v8/src/execution/ppc/simulator-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
t_register(ra);
        if (ra_val < im_val) {
          bf |= 0x80000000;
        }
        if (ra_val > im_val) {
          bf |= 0x40000000;
        }
        if (ra_val == im_val) {
          bf |= 0x20000000;
        }
      }
      uint32_t condition_mask = 0xF0000000U >> (cr * 4);
      uint32_t condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      break;
    }
    case ADDIC: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      uintptr_t ra_val = get_register(ra);
      uintptr_t im_val = SIGN_EXT_IMM16(instr->Bits(15, 0));
      uintptr_t alu_out = ra_val + im_val;
      // Check overflow
      if (~ra_val < im_val) {
        special_reg_xer_ = (special_reg_xer_ & ~0xF0000000) | 0x20000000;
      } else {
        special_reg_xer_ &= ~0xF0000000;
      }
      set_register(rt, alu_out);
      break;
    }
    case ADDI: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t im_val = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t alu_out;
      if (ra == 0) {
        alu_out = im_val;
      } else {
        intptr_t ra_val = get_register(ra);
        alu_out = ra_val + im_val;
      }
      set_register(rt, alu_out);
      // todo - handle RC bit
      break;
    }
    case ADDIS: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t im_val = (instr->Bits(15, 0) << 16);
      intptr_t alu_out;
      if (ra == 0) {  // treat r0 as zero
        alu_out = im_val;
      } else {
        intptr_t ra_val = get_register(ra);
        alu_out = ra_val + im_val;
      }
      set_register(rt, alu_out);
      break;
    }
    case BCX: {
      ExecuteBranchConditional(instr, BC_OFFSET);
      break;
    }
    case BX: {
      int offset = (instr->Bits(25, 2) << 8) >> 6;
      if (instr->Bit(0) == 1) {  // LK flag set
        special_reg_lr_ = get_pc() + 4;
      }
      set_pc(get_pc() + offset);
      // todo - AA flag
      break;
    }
    case MCRF:
      UNIMPLEMENTED();  // Not used by V8.
    case BCLRX:
      ExecuteBranchConditional(instr, BC_LINK_REG);
      break;
    case BCCTRX:
      ExecuteBranchConditional(instr, BC_CTR_REG);
      break;
    case CRNOR:
    case RFI:
    case CRANDC:
      UNIMPLEMENTED();
    case ISYNC: {
      // todo - simulate isync
      break;
    }
    case CRXOR: {
      int bt = instr->Bits(25, 21);
      int ba = instr->Bits(20, 16);
      int bb = instr->Bits(15, 11);
      int ba_val = ((0x80000000 >> ba) & condition_reg_) == 0 ? 0 : 1;
      int bb_val = ((0x80000000 >> bb) & condition_reg_) == 0 ? 0 : 1;
      int bt_val = ba_val ^ bb_val;
      bt_val = bt_val << (31 - bt);  // shift bit to correct destination
      condition_reg_ &= ~(0x80000000 >> bt);
      condition_reg_ |= bt_val;
      break;
    }
    case CREQV: {
      int bt = instr->Bits(25, 21);
      int ba = instr->Bits(20, 16);
      int bb = instr->Bits(15, 11);
      int ba_val = ((0x80000000 >> ba) & condition_reg_) == 0 ? 0 : 1;
      int bb_val = ((0x80000000 >> bb) & condition_reg_) == 0 ? 0 : 1;
      int bt_val = 1 - (ba_val ^ bb_val);
      bt_val = bt_val << (31 - bt);  // shift bit to correct destination
      condition_reg_ &= ~(0x80000000 >> bt);
      condition_reg_ |= bt_val;
      break;
    }
    case CRNAND:
    case CRAND:
    case CRORC:
    case CROR: {
      UNIMPLEMENTED();  // Not used by V8.
    }
    case RLWIMIX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uint32_t rs_val = get_register(rs);
      int32_t ra_val = get_register(ra);
      int sh = instr->Bits(15, 11);
      int mb = instr->Bits(10, 6);
      int me = instr->Bits(5, 1);
      uint32_t result = base::bits::RotateLeft32(rs_val, sh);
      int mask = 0;
      if (mb < me + 1) {
        int bit = 0x80000000 >> mb;
        for (; mb <= me; mb++) {
          mask |= bit;
          bit >>= 1;
        }
      } else if (mb == me + 1) {
        mask = 0xFFFFFFFF;
      } else {                             // mb > me+1
        int bit = 0x80000000 >> (me + 1);  // needs to be tested
        mask = 0xFFFFFFFF;
        for (; me < mb; me++) {
          mask ^= bit;
          bit >>= 1;
        }
      }
      result &= mask;
      ra_val &= ~mask;
      result |= ra_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case RLWINMX:
    case RLWNMX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uint32_t rs_val = get_register(rs);
      int sh = 0;
      if (opcode == RLWINMX) {
        sh = instr->Bits(15, 11);
      } else {
        int rb = instr->RBValue();
        uint32_t rb_val = get_register(rb);
        sh = (rb_val & 0x1F);
      }
      int mb = instr->Bits(10, 6);
      int me = instr->Bits(5, 1);
      uint32_t result = base::bits::RotateLeft32(rs_val, sh);
      int mask = 0;
      if (mb < me + 1) {
        int bit = 0x80000000 >> mb;
        for (; mb <= me; mb++) {
          mask |= bit;
          bit >>= 1;
        }
      } else if (mb == me + 1) {
        mask = 0xFFFFFFFF;
      } else {                             // mb > me+1
        int bit = 0x80000000 >> (me + 1);  // needs to be tested
        mask = 0xFFFFFFFF;
        for (; me < mb; me++) {
          mask ^= bit;
          bit >>= 1;
        }
      }
      result &= mask;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case ORI: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val | im_val;
      set_register(ra, alu_out);
      break;
    }
    case ORIS: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val | (im_val << 16);
      set_register(ra, alu_out);
      break;
    }
    case XORI: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val ^ im_val;
      set_register(ra, alu_out);
      // todo - set condition based SO bit
      break;
    }
    case XORIS: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val ^ (im_val << 16);
      set_register(ra, alu_out);
      break;
    }
    case ANDIx: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val & im_val;
      set_register(ra, alu_out);
      SetCR0(alu_out);
      break;
    }
    case ANDISx: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val & (im_val << 16);
      set_register(ra, alu_out);
      SetCR0(alu_out);
      break;
    }
    case SRWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x3F;
      intptr_t result = (rb_val > 31) ? 0 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SRDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x7F;
      intptr_t result = (rb_val > 63) ? 0 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case MODUW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t ra_val = get_register(ra);
      uint32_t rb_val = get_register(rb);
      uint32_t alu_out = (rb_val == 0) ? -1 : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case MODUD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint64_t ra_val = get_register(ra);
      uint64_t rb_val = get_register(rb);
      uint64_t alu_out = (rb_val == 0) ? -1 : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case MODSW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = get_register(ra);
      int32_t rb_val = get_register(rb);
      bool overflow = (ra_val == kMinInt && rb_val == -1);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000 / -1.
      int32_t alu_out = (rb_val == 0 || overflow) ? -1 : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case MODSD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t one = 1;  // work-around gcc
      int64_t kMinLongLong = (one << 63);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000_00000000 / -1.
      int64_t alu_out =
          (rb_val == 0 || (ra_val == kMinLongLong && rb_val == -1))
              ? -1
              : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case SRAW: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb) & 0x3F;
      intptr_t result = (rb_val > 31) ? rs_val >> 31 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SRAD: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb) & 0x7F;
      intptr_t result = (rb_val > 63) ? rs_val >> 63 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SRAWIX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      int sh = instr->Bits(15, 11);
      int32_t rs_val = get_register(rs);
      intptr_t result = rs_val >> sh;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case EXTSW: {
      const int shift = kBitsPerSystemPointer - 32;
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t rs_val = get_register(rs);
      intptr_t ra_val = (rs_val << shift) >> shift;
      set_register(ra, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      break;
    }
    case EXTSH: {
      const int shift = kBitsPerSystemPointer - 16;
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t rs_val = get_register(rs);
      intptr_t ra_val = (rs_val << shift) >> shift;
      set_register(ra, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      break;
    }
    case EXTSB: {
      const int shift = kBitsPerSystemPointer - 8;
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t rs_val = get_register(rs);
      intptr_t ra_val = (rs_val << shift) >> shift;
      set_register(ra, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      break;
    }
    case LFSUX:
    case LFSX: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      int32_t val = ReadW(ra_val + rb_val);
      float* fptr = reinterpret_cast<float*>(&val);
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      if ((val & 0x7F800000) == 0x7F800000) {
        int64_t dval = static_cast<int64_t>(val);
        dval = ((dval & 0xC0000000) << 32) | ((dval & 0x40000000) << 31) |
               ((dval & 0x40000000) << 30) | ((dval & 0x7FFFFFFF) << 29) | 0x0;
        set_d_register(frt, dval);
      } else {
        set_d_register_from_double(frt, static_cast<double>(*fptr));
      }
#else
      set_d_register_from_double(frt, static_cast<double>(*fptr));
#endif
      if (opcode == LFSUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LFDUX:
    case LFDX: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      int64_t dptr = ReadDW(ra_val + rb_val);
      set_d_register(frt, dptr);
      if (opcode == LFDUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STFSUX:
      [[fallthrough]];
    case STFSX: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      float frs_val = static_cast<float>(get_double_from_d_register(frs));
      int32_t* p = reinterpret_cast<int32_t*>(&frs_val);
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      int32_t sval = 0;
      int64_t dval = get_d_register(frs);
      if ((dval & 0x7FF0000000000000) == 0x7FF0000000000000) {
        sval = ((dval & 0xC000000000000000) >> 32) |
               ((dval & 0x07FFFFFFE0000000) >> 29);
        p = &sval;
      } else {
        p = reinterpret_cast<int32_t*>(&frs_val);
      }
#else
      p = reinterpret_cast<int32_t*>(&frs_val);
#endif
      WriteW(ra_val + rb_val, *p);
      if (opcode == STFSUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STFDUX:
      [[fallthrough]];
    case STFDX: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      int64_t frs_val = get_d_register(frs);
      WriteDW(ra_val + rb_val, frs_val);
      if (opcode == STFDUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case POPCNTW: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x80000000;
      for (; n < 32; n++) {
        if (bit & rs_val) count++;
        bit >>= 1;
      }
      set_register(ra, count);
      break;
    }
    case POPCNTD: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x8000000000000000UL;
      for (; n < 64; n++) {
        if (bit & rs_val) count++;
        bit >>= 1;
      }
      set_register(ra, count);
      break;
    }
    case SYNC: {
      // todo - simulate sync
      __sync_synchronize();
      break;
    }
    case ICBI: {
      // todo - simulate icbi
      break;
    }

    case LWZU:
    case LWZ: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      set_register(rt, ReadWU(ra_val + offset));
      if (opcode == LWZU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LBZU:
    case LBZ: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      set_register(rt, ReadB(ra_val + offset) & 0xFF);
      if (opcode == LBZU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case STWU:
    case STW: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t rs_val = get_register(rs);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      WriteW(ra_val + offset, rs_val);
      if (opcode == STWU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }
    case SRADIX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      int sh = (instr->Bits(15, 11) | (instr->Bit(1) << 5));
      intptr_t rs_val = get_register(rs);
      intptr_t result = rs_val >> sh;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case STBCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int8_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExB(ra_val + rb_val, rs_val));
      break;
    }
    case STHCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int16_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExH(ra_val + rb_val, rs_val));
      break;
    }
    case STWCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExW(ra_val + rb_val, rs_val));
      break;
    }
    case STDCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int64_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExDW(ra_val + rb_val, rs_val));
      break;
    }
    case TW: {
      // used for call redirection in simulation mode
      SoftwareInterrupt(instr);
      break;
    }
    case CMP: {
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int cr = instr->Bits(25, 23);
      uint32_t bf = 0;
      int L = instr->Bit(21);
      if (L) {
        intptr_t ra_val = get_register(ra);
        intptr_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      } else {
        int32_t ra_val = get_register(ra);
        int32_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      }
      uint32_t condition_mask = 0xF0000000U >> (cr * 4);
      uint32_t condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      break;
    }
    case SUBFCX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ~ra_val + rb_val + 1;
      // Set carry
      if (ra_val <= rb_val) {
        special_reg_xer_ = (special_reg_xer_ & ~0xF0000000) | 0x20000000;
      } else {
        special_reg_xer_ &= ~0xF0000000;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case SUBFEX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ~ra_val + rb_val;
      if (special_reg_xer_ & 0x20000000) {
        alu_out += 1;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      // todo - handle OE bit
      break;
    }
    case ADDCX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ra_val + rb_val;
      // Set carry
      if (~ra_val < rb_val) {
        special_reg_xer_ = (special_reg_xer_ & ~0xF0000000) | 0x20000000;
      } else {
        special_reg_xer_ &= ~0xF0000000;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      // todo - handle OE bit
      break;
    }
    case ADDEX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ra_val + rb_val;
      if (special_reg_xer_ & 0x20000000) {
        alu_out += 1;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      // todo - handle OE bit
      break;
    }
    case MULHWX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = (get_register(ra) & 0xFFFFFFFF);
      int32_t rb_val = (get_register(rb) & 0xFFFFFFFF);
      int64_t alu_out = (int64_t)ra_val * (int64_t)rb_val;
      // High 32 bits of the result is undefined,
      // Which is simulated here by adding random bits.
      alu_out = (alu_out >> 32) | 0x421000000000000;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case MULHWUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t ra_val = (get_register(ra) & 0xFFFFFFFF);
      uint32_t rb_val = (get_register(rb) & 0xFFFFFFFF);
      uint64_t alu_out = (uint64_t)ra_val * (uint64_t)rb_val;
      // High 32 bits of the result is undefined,
      // Which is simulated here by adding random bits.
      alu_out = (alu_out >> 32) | 0x421000000000000;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case MULHD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t alu_out = base::bits::SignedMulHigh64(ra_val, rb_val);
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case MULHDU: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint64_t ra_val = get_register(ra);
      uint64_t rb_val = get_register(rb);
      uint64_t alu_out = base::bits::UnsignedMulHigh64(ra_val, rb_val);
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case NEGX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      intptr_t ra_val = get_register(ra);
      intptr_t alu_out = 1 + ~ra_val;
      intptr_t one = 1;  // work-around gcc
      intptr_t kOverflowVal = (one << 63);
      set_register(rt, alu_out);
      if (instr->Bit(10)) {  // OE bit set
        if (ra_val == kOverflowVal) {
          special_reg_xer_ |= 0xC0000000;  // set SO,OV
        } else {
          special_reg_xer_ &= ~0x40000000;  // clear OV
        }
      }
      if (instr->Bit(0)) {  // RC bit set
        bool setSO = (special_reg_xer_ & 0x80000000);
        SetCR0(alu_out, setSO);
      }
      break;
    }
    case SLWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x3F;
      uint32_t result = (rb_val > 31) ? 0 : rs_val << rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SLDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x7F;
      uintptr_t result = (rb_val > 63) ? 0 : rs_val << rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case MFVSRD: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t frt_val;
      if (!instr->Bit(0)) {
        // if double reg (TX=0).
        frt_val = get_d_register(frt);
      } else {
        // if simd reg (TX=1).
        DCHECK_EQ(instr->Bit(0), 1);
        frt_val = get_simd_register_by_lane<int64_t>(frt, 0);
      }
      set_register(ra, frt_val);
      break;
    }
    case MFVSRWZ: {
      DCHECK(!instr->Bit(0));
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t frt_val = get_d_register(frt);
      set_register(ra, static_cast<uint32_t>(frt_val));
      break;
    }
    case MTVSRD: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t ra_val = get_register(ra);
      if (!instr->Bit(0)) {
        // if double reg (TX=0).
        set_d_register(frt, ra_val);
      } else {
        // if simd reg (TX=1).
        DCHECK_EQ(instr->Bit(0), 1);
        set_simd_register_by_lane<int64_t>(frt, 0,
                                           static_cast<int64_t>(ra_val));
        // Low 64 bits of the result is undefined,
        // Which is simulated here by adding random bits.
        set_simd_register_by_lane<int64_t>(
            frt, 1, static_cast<int64_t>(0x123456789ABCD));
      }
      break;
    }
    case MTVSRDD: {
      int xt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      set_simd_register_by_lane<int64_t>(
          xt, 0, static_cast<int64_t>(get_register(ra)));
      set_simd_register_by_lane<int64_t>(
          xt, 1, static_cast<int64_t>(get_register(rb)));
      break;
    }
    case MTVSRWA: {
      DCHECK(!instr->Bit(0));
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t ra_val = static_cast<int32_t>(get_register(ra));
      set_d_register(frt, ra_val);
      break;
    }
    case MTVSRWZ: {
      DCHECK(!instr->Bit(0));
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      uint64_t ra_val = static_cast<uint32_t>(get_register(ra));
      set_d_register(frt, ra_val);
      break;
    }
    case CNTLZWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x80000000;
      for (; n < 32; n++) {
        if (bit & rs_val) break;
        count++;
        bit >>= 1;
      }
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case CNTLZDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x8000000000000000UL;
      for (; n < 64; n++) {
        if (bit & rs_val) break;
        count++;
        bit >>= 1;
      }
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case CNTTZWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint32_t rs_val = static_cast<uint32_t>(get_register(rs));
      uintptr_t count = rs_val == 0 ? 32 : __builtin_ctz(rs_val);
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case CNTTZDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint64_t rs_val = get_register(rs);
      uintptr_t count = rs_val == 0 ? 64 : __builtin_ctzl(rs_val);
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case ANDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val & rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC Bit set
        SetCR0(alu_out);
      }
      break;
    }
    case ANDCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val & ~rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC Bit set
        SetCR0(alu_out);
      }
      break;
    }
    case CMPL: {
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int cr = instr->Bits(25, 23);
      uint32_t bf = 0;
      int L = instr->Bit(21);
      if (L) {
        uintptr_t ra_val = get_register(ra);
        uintptr_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      } else {
        uint32_t ra_val = get_register(ra);
        uint32_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      }
      uint32_t condition_mask = 0xF0000000U >> (cr * 4);
      uint32_t condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      break;
    }
    case SUBFX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      intptr_t ra_val = get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rb_val - ra_val;
      // todo - figure out underflow
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC Bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case ADDZEX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      intptr_t ra_val = get_register(ra);
      if (special_reg_xer_ & 0x20000000) {
        ra_val += 1;
      }
      set_register(rt, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      // todo - handle OE bit
      break;
    }
    case NORX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = ~(rs_val | rb_val);
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case MULLW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = (get_register(ra) & 0xFFFFFFFF);
      int32_t rb_val = (get_register(rb) & 0xFFFFFFFF);
      int32_t alu_out = ra_val * rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case MULLD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t alu_out = ra_val * rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case DIVW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = get_register(ra);
      int32_t rb_val = get_register(rb);
      bool overflow = (ra_val == kMinInt && rb_val == -1);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000 / -1.
      int32_t alu_out = (rb_val == 0 || overflow) ? -1 : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(10)) {  // OE bit set
        if (overflow) {
          special_reg_xer_ |= 0xC0000000;  // set SO,OV
        } else {
          special_reg_xer_ &= ~0x40000000;  // clear OV
        }
      }
      if (instr->Bit(0)) {  // RC bit set
        bool setSO = (special_reg_xer_ & 0x80000000);
        SetCR0(alu_out, setSO);
      }
      break;
    }
    case DIVWU: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t ra_val = get_register(ra);
      uint32_t rb_val = get_register(rb);
      bool overflow = (rb_val == 0);
      // result is undefined if divisor is zero
      uint32_t alu_out = (overflow) ? -1 : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(10)) {  // OE bit set
        if (overflow) {
          special_reg_xer_ |= 0xC0000000;  // set SO,OV
        } else {
          special_reg_xer_ &= ~0x40000000;  // clear OV
        }
      }
      if (instr->Bit(0)) {  // RC bit set
        bool setSO = (special_reg_xer_ & 0x80000000);
        SetCR0(alu_out, setSO);
      }
      break;
    }
    case DIVD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t one = 1;  // work-around gcc
      int64_t kMinLongLong = (one << 63);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000_00000000 / -1.
      int64_t alu_out =
          (rb_val == 0 || (ra_val == kMinLongLong && rb_val == -1))
              ? -1
              : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case DIVDU: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint64_t ra_val = get_register(ra);
      uint64_t rb_val = get_register(rb);
      // result is undefined if divisor is zero
      uint64_t alu_out = (rb_val == 0) ? -1 : ra_val / rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case ADDX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      intptr_t ra_val = get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = ra_val + rb_val;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case XORX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val ^ rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case ORX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val | rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case ORC: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val | ~rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      break;
    }
    case MFSPR: {
      int rt = instr->RTValue();
      int spr = instr->Bits(20, 11);
      if (spr != 256) {
        UNIMPLEMENTED();  // Only LRLR supported
      }
      set_register(rt, special_reg_lr_);
      break;
    }
    case MTSPR: {
      int rt = instr->RTValue();
      intptr_t rt_val = get_register(rt);
      int spr = instr->Bits(20, 11);
      if (spr == 256) {
        special_reg_lr_ = rt_val;
      } else if (spr == 288) {
        special_reg_ctr_ = rt_val;
      } else if (spr == 32) {
        special_reg_xer_ = rt_val;
      } else {
        UNIMPLEMENTED();  // Only LR supported
      }
      break;
    }
    case MFCR: {
      int rt = instr->RTValue();
      set_register(rt, condition_reg_);
      break;
    }
    case STWUX:
    case STWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteW(ra_val + rb_val, rs_val);
      if (opcode == STWUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STBUX:
    case STBX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int8_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteB(ra_val + rb_val, rs_val);
      if (opcode == STBUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STHUX:
    case STHX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int16_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteH(ra_val + rb_val, rs_val);
      if (opcode == STHUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LWZX:
    case LWZUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadWU(ra_val + rb_val));
      if (opcode == LWZUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LWAX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadW(ra_val + rb_val));
      break;
    }
    case LDX:
    case LDUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t result = ReadDW(ra_val + rb_val);
      set_register(rt, result);
      if (opcode == LDUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LDBRX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t result = ByteReverse<int64_t>(ReadDW(ra_val + rb_val));
      set_register(rt, result);
      break;
    }
    case LWBRX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t result = ByteReverse<int32_t>(ReadW(ra_val + rb_val));
      set_register(rt, result);
      break;
    }
    case STDBRX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteDW(ra_val + rb_val, ByteReverse<int64_t>(rs_val));
      break;
    }
    case STWBRX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteW(ra_val + rb_val, ByteReverse<int32_t>(rs_val));
      break;
    }
    case STHBRX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteH(ra_val + rb_val, ByteReverse<int16_t>(rs_val));
      break;
    }
    case STDX:
    case STDUX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      WriteDW(ra_val + rb_val, rs_val);
      if (opcode == STDUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LBZX:
    case LBZUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadBU(ra_val + rb_val) & 0xFF);
      if (opcode == LBZUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LHZX:
    case LHZUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadHU(ra_val + rb_val) & 0xFFFF);
      if (opcode == LHZUX) {
        DCHECK(ra != 0 && ra != rt);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LHAX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadH(ra_val + rb_val));
      break;
    }
    case LBARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExBU(ra_val + rb_val) & 0xFF);
      break;
    }
    case LHARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExHU(ra_val + rb_val));
      break;
    }
    case LWARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExWU(ra_val + rb_val));
      break;
    }
    case LDARX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      set_register(rt, ReadExDWU(ra_val + rb_val));
      break;
    }
    case DCBF: {
      // todo - simulate dcbf
      break;
    }
    case ISEL: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int condition_bit = instr->RCValue();
      int condition_mask = 0x80000000 >> condition_bit;
      intptr_t ra_val = (ra == 0) ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t value = (condition_reg_ & condition_mask) ? ra_val : rb_val;
      set_register(rt, value);
      break;
    }

    case STBU:
    case STB: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int8_t rs_val = get_register(rs);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      WriteB(ra_val + offset, rs_val);
      if (opcode == STBU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LHZU:
    case LHZ: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      uintptr_t result = ReadHU(ra_val + offset) & 0xFFFF;
      set_register(rt, result);
      if (opcode == LHZU) {
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LHA:
    case LHAU: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t result = ReadH(ra_val + offset);
      set_register(rt, result);
      if (opcode == LHAU) {
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case STHU:
    case STH: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int16_t rs_val = get_register(rs);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      WriteH(ra_val + offset, rs_val);
      if (opcode == STHU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LMW:
    case STMW: {
      UNIMPLEMENTED();
    }

    case LFSU:
    case LFS: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t val = ReadW(ra_val + offset);
      float* fptr = reinterpret_cast<float*>(&val);
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      if ((val & 0x7F800000) == 0x7F800000) {
        int64_t dval = static_cast<int64_t>(val);
        dval = ((dval & 0xC0000000) << 32) | ((dval & 0x40000000) << 31) |
               ((dval & 0x40000000) << 30) | ((dval & 0x7FFFFFFF) << 29) | 0x0;
        set_d_register(frt, dval);
      } else {
        set_d_register_from_double(frt, static_cast<double>(*fptr));
      }
#else
      set_d_register_from_double(frt, static_cast<double>(*fptr));
#endif
      if (opcode == LFSU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LFDU:
    case LFD: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int64_t dptr = ReadDW(ra_val + offset);
      set_d_register(frt, dptr);
      if (opcode == LFDU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case STFSU:
      [[fallthrough]];
    case STFS: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      float frs_val = static_cast<float>(get_double_from_d_register(frs));
      int32_t* p;
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      int32_t sval = 0;
      int64_t dval = get_d_register(frs);
      if ((dval & 0x7FF0000000000000) == 0x7FF0000000000000) {
        sval = ((dval & 0xC000000000000000) >> 32) |
               ((dval & 0x07FFFFFFE0000000) >> 29);
        p = &sval;
      } else {
        p = reinterpret_cast<int32_t*>(&frs_val);
      }
#else
      p = reinterpret_cast<int32_t*>(&frs_val);
#endif
      WriteW(ra_val + offset, *p);
      if (opcode == STFSU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }
    case STFDU:
    case STFD: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int32_t offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int64_t frs_val = get_d_register(frs);
      WriteDW(ra_val + offset, frs_val);
      if (opcode == STFDU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }
    case BRW: {
      constexpr int kBitsPerWord = 32;
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint64_t rs_val = get_register(rs);
      uint32_t rs_high = rs_val >> kBitsPerWord;
      uint32_t rs_low = (rs_val << kBitsPerWord) >> kBitsPerWord;
      uint64_t result = ByteReverse<int32_t>(rs_high);
      result = (result << kBitsPerWord) | ByteReverse<int32_t>(rs_low);
      set_register(ra, result);
      break;
    }
    case BRD: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint64_t rs_val = get_register(rs);
      set_register(ra, ByteReverse<int64_t>(rs_val));
      break;
    }
    case FCFIDS: {
      // fcfids
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<float>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCFIDUS: {
      // fcfidus
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      uint64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<float>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }

    case FDIV: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val / frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FSUB: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val - frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FADD: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frt_val = fra_val + frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FSQRT: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::sqrt(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FSEL: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = ((fra_val >= 0.0) ? frc_val : frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMUL: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = fra_val * frc_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMSUB: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = (fra_val * frc_val) - frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMADD: {
      int frt = instr->RTValue();
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      int frc = instr->RCValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      double frc_val = get_double_from_d_register(frc);
      double frt_val = (fra_val * frc_val) + frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCMPU: {
      int fra = instr->RAValue();
      int frb = instr->RBValue();
      double fra_val = get_double_from_d_register(fra);
      double frb_val = get_double_from_d_register(frb);
      int cr = instr->Bits(25, 23);
      int bf = 0;
      if (fra_val < frb_val) {
        bf |= 0x80000000;
      }
      if (fra_val > frb_val) {
        bf |= 0x40000000;
      }
      if (fra_val == frb_val) {
        bf |= 0x20000000;
      }
      if (std::isunordered(fra_val, frb_val)) {
        bf |= 0x10000000;
      }
      int condition_mask = 0xF0000000 >> (cr * 4);
      int condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      return;
    }
    case FRIN: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::round(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRIZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::trunc(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRIP: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::ceil(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRIM: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = std::floor(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FRSP: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      // frsp round 8-byte double-precision value to
      // single-precision value
      double frb_val = get_double_from_d_register(frb);
      double frt_val = static_cast<float>(frb_val);
      set_d_register_from_double(frt, frt_val);
      if (instr->Bit(0)) {  // RC bit set
                            //  UNIMPLEMENTED();
      }
      return;
    }
    case FCFID: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<double>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCFIDU: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      uint64_t frb_val = get_d_register(frb);
      double frt_val = static_cast<double>(frb_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCTID:
    case FCTIDZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIDZ) ? kRoundToZero
                                    : (fp_condition_reg_ & kFPRoundingModeMask);
      int64_t frt_val;
      int64_t one = 1;  // work-around gcc
      int64_t kMinVal = (one << 63);
      int64_t kMaxVal = kMinVal - 1;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
        invalid_convert = true;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < static_cast<double>(kMinVal)) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val >= static_cast<double>(kMaxVal)) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (int64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FCTIDU:
    case FCTIDUZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIDUZ)
                     ? kRoundToZero
                     : (fp_condition_reg_ & kFPRoundingModeMask);
      uint64_t frt_val;
      uint64_t kMinVal = 0;
      uint64_t kMaxVal = kMinVal - 1;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
        invalid_convert = true;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < static_cast<double>(kMinVal)) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val >= static_cast<double>(kMaxVal)) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (uint64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FCTIW:
    case FCTIWZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIWZ) ? kRoundToZero
                                    : (fp_condition_reg_ & kFPRoundingModeMask);
      int64_t frt_val;
      int64_t kMinVal = kMinInt;
      int64_t kMaxVal = kMaxInt;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          case kRoundToNearest: {
            double orig = frb_val;
            frb_val = lround(frb_val);
            // Round to even if exactly halfway.  (lround rounds up)
            if (std::fabs(frb_val - orig) == 0.5 && ((int64_t)frb_val % 2)) {
              frb_val += ((frb_val > 0) ? -1.0 : 1.0);
            }
            break;
          }
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < kMinVal) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val > kMaxVal) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (int64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FCTIWU:
    case FCTIWUZ: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      int mode = (opcode == FCTIWUZ)
                     ? kRoundToZero
                     : (fp_condition_reg_ & kFPRoundingModeMask);
      uint64_t frt_val;
      uint64_t kMinVal = kMinUInt32;
      uint64_t kMaxVal = kMaxUInt32;
      bool invalid_convert = false;

      if (std::isnan(frb_val)) {
        frt_val = kMinVal;
      } else {
        switch (mode) {
          case kRoundToZero:
            frb_val = std::trunc(frb_val);
            break;
          case kRoundToPlusInf:
            frb_val = std::ceil(frb_val);
            break;
          case kRoundToMinusInf:
            frb_val = std::floor(frb_val);
            break;
          default:
            UNIMPLEMENTED();  // Not used by V8.
        }
        if (frb_val < kMinVal) {
          frt_val = kMinVal;
          invalid_convert = true;
        } else if (frb_val > kMaxVal) {
          frt_val = kMaxVal;
          invalid_convert = true;
        } else {
          frt_val = (uint64_t)frb_val;
        }
      }
      set_d_register(frt, frt_val);
      if (invalid_convert) SetFPSCR(VXCVI);
      return;
    }
    case FNEG: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      double frb_val = get_double_from_d_register(frb);
      double frt_val = -frb_val;
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FCPSGN: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int fra = instr->RAValue();
      double frb_val = get_double_from_d_register(frb);
      double fra_val = get_double_from_d_register(fra);
      double frt_val = std::copysign(frb_val, fra_val);
      set_d_register_from_double(frt, frt_val);
      return;
    }
    case FMR: {
      int frt = instr->RTValue();
      int frb = instr->RBValue();
      int64_t frb_val = get_d_register(frb);
      set_d_register(frt, frb_val);
      return;
    }
    case MTFSFI: {
      int bf = instr->Bits(25, 23);
      int imm = instr->Bits(15, 12);
      int fp_condition_mask = 0xF0000000 >> (bf * 4);
      fp_condition_reg_ &= ~fp_condition_mask;
      fp_condition_reg_ |= (imm << (28 - (bf * 4)));
      if (instr->Bit(0)) {  // RC bit set
        condition_reg_ &= 0xF0FFFFFF;
        condition_reg_ |= (imm << 23);
      }
      return;
    }
    case MTFSF: {
      int frb = instr->RBValue();
      int64_t frb_dval = get_d_register(frb);
      int32_t frb_ival = static_cast<int32_t>((frb_dval)&0xFFFFFFFF);
      int l = instr->Bits(25, 25);
      if (l == 1) {
        fp_condition_reg_ = frb_ival;
      } else {
        UNIMPLEMENTED();
      }
      if (instr->Bit(0)) {  // RC bit set
        UNIMPLEMENTED();
        // int w = instr->Bits(16, 16);
        // int flm = instr->Bits(24, 17);
      }
      return;
    }
    case MFFS: {
      int frt = instr->RTValue();
      int64_t lval = static_cast<int64_t>(fp_condition_reg_);
      set_d_register(frt, lval);
      return;
    }
    case MCRFS: {
      int bf = instr->Bits(25, 23);
      int bfa = instr->Bits(20, 18);
      int cr_shift = (7 - bf) * CRWIDTH;
      int fp_shift = (7 - bfa) * CRWIDTH;
      int field_val = (fp_condition_reg_ >> fp_shift) & 0xF;
      condition_reg_ &= ~(0x0F << cr_shift);
      condition_reg_ |= (field_val << cr_shift);
      // Clear copied exception bits
 
"""


```