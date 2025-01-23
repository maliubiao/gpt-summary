Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/arm/assembler-arm.cc`.

Here's a breakdown of the code and its functions:

1. **Label Management:** The code deals with labels for branching and code patching. It includes functions to bind labels to specific memory addresses (`bind`, `bind_to`), check if a label is bound (`is_bound`), and move to the next linked label (`next`).

2. **Instruction Encoding:**  A significant part of the code focuses on encoding ARM instructions. This involves:
    *   Determining if immediate values can be directly encoded in the instruction (`FitsShifter`).
    *   Handling cases where immediate values are too large and need to be loaded from the constant pool or using `movw`/`movt` (for ARMv7).
    *   Functions like `AddrMode1`, `AddrMode2`, `AddrMode3`, `AddrMode4`, `AddrMode5` which encode instructions based on different addressing modes.
    *   Specific functions for moving 32-bit immediates (`Move32BitImmediate`).

3. **Branch Instructions:** The code includes functions to emit different branch instructions (`b`, `bl`, `blx`, `bx`) and calculate branch offsets.

4. **Data Processing Instructions:** It defines functions for various ARM data processing instructions like `and_`, `eor`, `sub`, `add`, `cmp`, `mov`, `orr`, `bic`, `mvn`, `asr`, `lsl`, `lsr`. These functions take registers and operands as arguments and encode the corresponding machine instructions.

5. **Multiply Instructions:**  Functions for encoding ARM multiply instructions such as `mla`, `mls`, `mul`, `smmla`, `smmul`, `smlal`, `smull`, `umlal`, `umull`. It also includes division instructions like `sdiv` and `udiv`.

6. **Miscellaneous Instructions:**  Includes `clz` (count leading zeros) and saturating arithmetic instructions (`usat`).

7. **Constant Pool Management:** The code implicitly manages a constant pool, used to store immediate values that cannot be directly encoded in instructions. Functions like `ConstantPoolAddEntry` and `CheckConstPool` (not shown in the snippet but implied by context) are involved in this process.

**Relationship to JavaScript:** This code is a fundamental part of the V8 JavaScript engine. It's used during the compilation process to translate JavaScript code into native ARM machine code. Operations in JavaScript will eventually be represented by sequences of these ARM instructions.

**Torque:** The prompt asks about `.tq` files. This code is `.cc`, so it's C++ and not Torque. Torque is a higher-level language used within V8 to generate some of the lower-level code, including potentially parts of the assembler.

**Hypothetical Input/Output:** Consider the `add` instruction:

*   **Input:** `add(r0, r1, Operand(5))` (add the immediate value 5 to the contents of register r1 and store the result in r0).
*   **Output:** A sequence of bytes representing the encoded ARM instruction for this operation. The exact bytes depend on the instruction format and the specific registers involved.

**Common Programming Errors:**  One common error when working with assembly is incorrect register usage or providing immediate values that don't fit the instruction's encoding constraints. The `FitsShifter` function and the handling of the constant pool are mechanisms to mitigate some of these issues.

**Summary of Functionality for Part 2:** This specific part of the `assembler-arm.cc` file primarily deals with **encoding ARM branch instructions and various data processing instructions**. It includes logic to calculate branch offsets, handle immediate values that may not fit directly into instructions (using constant pools or `movw`/`movt`), and provides functions to emit the corresponding machine code bytes. It also manages label binding for control flow within the generated code.
这是 `v8/src/codegen/arm/assembler-arm.cc` 文件的第二部分代码片段，主要功能集中在 **ARM 汇编指令的生成和编码** 上。具体来说，这部分代码负责处理以下几个方面：

1. **标签 (Label) 的绑定和跳转：**
    *   `PrintLabel(Label* L)` 函数用于打印标签信息，辅助调试。它会检查标签是否被绑定，以及跳转指令的目标地址是否合法。
    *   `bind_to(Label* L, int pos)` 函数将一个标签绑定到一个特定的代码位置 `pos`。如果该标签之前有未解析的跳转指令指向它，则会回填这些跳转指令的目标地址。
    *   `bind(Label* L)` 函数将标签绑定到当前的汇编位置。
    *   `next(Label* L)` 函数用于在标签链表中移动到下一个链接的标签。

2. **立即数处理和指令编码：**
    *   `FitsShifter(uint32_t imm32, uint32_t* rotate_imm, uint32_t* immed_8, Instr* instr)` 函数用于检查一个 32 位立即数 `imm32` 是否可以通过 ARM 指令的移位器进行编码。如果可以，它会计算出相应的 `rotate_imm` 和 `immed_8` 值。该函数还会尝试通过改变指令的操作码来适应立即数，例如将 `mov` 变为 `mvn` 如果取反后的立即数可以编码。
    *   `MustOutputRelocInfo(RelocInfo::Mode rmode, const Assembler* assembler)` 函数判断是否需要输出重定位信息，这通常与代码是否会被动态修改有关。
    *   `UseMovImmediateLoad(const Operand& x, const Assembler* assembler)` 函数判断在加载立即数时是否应该使用 `movw`/`movt` 指令（ARMv7 及以上）。
    *   `Operand::MustOutputRelocInfo(const Assembler* assembler)` 判断 `Operand` 是否需要输出重定位信息。
    *   `Operand::InstructionsRequired(const Assembler* assembler, Instr instr)` 函数计算表示一个 `Operand` 需要的指令数量，这取决于立即数是否能直接编码以及是否需要重定位信息。
    *   `Assembler::Move32BitImmediate(Register rd, const Operand& x, Condition cond)` 函数用于将一个 32 位的立即数加载到寄存器 `rd` 中。如果立即数无法直接编码，它会使用 `movw`/`movt` 指令序列（ARMv7）或者从常量池加载。
    *   `Assembler::AddrMode1(Instr instr, Register rd, Register rn, const Operand& x)` 函数处理寻址模式 1 的指令编码，包括算术和逻辑运算指令。它会尝试将立即数编码到指令中，如果不行，则会使用临时寄存器或者常量池。
    *   `Assembler::AddrMode1TryEncodeOperand(Instr* instr, const Operand& x)` 尝试将 `Operand` 编码到寻址模式 1 的指令中。

3. **分支指令的编码：**
    *   `Assembler::branch_offset(Label* L)` 计算从当前位置到标签 `L` 的分支偏移量。
    *   `Assembler::b(int branch_offset, Condition cond, RelocInfo::Mode rmode)` 函数编码无条件或条件分支指令 `b`。
    *   `Assembler::bl(int branch_offset, Condition cond, RelocInfo::Mode rmode)` 函数编码带链接的分支指令 `bl` (Branch with Link)。
    *   `Assembler::blx(int branch_offset)` 函数编码带链接的交换分支指令 `blx`，目标地址是立即数。
    *   `Assembler::blx(Register target, Condition cond)` 函数编码带链接的交换分支指令 `blx`，目标地址是寄存器。
    *   `Assembler::bx(Register target, Condition cond)` 函数编码交换分支指令 `bx`。
    *   `Assembler::b(Label* L, Condition cond)`、`Assembler::bl(Label* L, Condition cond)`、`Assembler::blx(Label* L)` 是使用标签作为目标地址的分支指令的便捷封装。

4. **数据处理指令的编码：**
    *   提供了一系列函数用于编码各种 ARM 数据处理指令，例如：
        *   逻辑运算：`and_`, `eor`, `orr`, `bic`, `mvn`
        *   算术运算：`sub`, `rsb`, `add`, `adc`, `sbc`, `rsc`
        *   比较指令：`tst`, `teq`, `cmp`, `cmn`, `cmp_raw_immediate`
        *   移动指令：`mov`, `movw`, `movt`, `mov_label_offset`
        *   移位指令：`asr`, `lsl`, `lsr`

5. **乘法和除法指令的编码：**
    *   提供了一系列函数用于编码各种 ARM 乘法和除法指令，例如：
        *   乘法：`mla`, `mls`, `mul`, `smmla`, `smmul`, `smlal`, `smull`, `umlal`, `umull`
        *   除法：`sdiv`, `udiv`

6. **其他指令的编码：**
    *   `clz(Register dst, Register src, Condition cond)`：编码计算前导零的指令。
    *   `usat(Register dst, int satpos, const Operand& src, Condition cond)`：编码无符号饱和指令。

**如果 `v8/src/codegen/arm/assembler-arm.cc` 以 `.tq` 结尾：**

如果该文件以 `.tq` 结尾，那么它将是 **V8 的 Torque 源代码**。Torque 是一种用于定义 V8 运行时函数的领域特定语言。在这种情况下，该文件将包含用 Torque 编写的代码，这些代码最终会被编译成 C++ 代码，用于生成 ARM 汇编指令。

**与 JavaScript 的功能关系 (JavaScript 示例)：**

这部分代码是 V8 JavaScript 引擎的核心组成部分，它负责将 JavaScript 代码编译成底层的 ARM 机器码。例如，考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 执行这段代码时，`add` 函数会被编译成 ARM 汇编指令。`Assembler::add` 函数会被调用来生成加法操作的机器码。例如，如果 `a` 和 `b` 的值分别存储在寄存器 `r0` 和 `r1` 中，那么 `Assembler::add(r0, r0, Operand(r1))` 可能会被调用来生成将 `r1` 的值加到 `r0` 的指令。

**代码逻辑推理 (假设输入与输出)：**

假设有以下调用：

```c++
Assembler assembler;
Label my_label;
assembler.bind(&my_label);
assembler.add(r0, r1, Operand(5));
assembler.b(&my_label);
```

*   **输入:**  调用 `bind(&my_label)` 时，`my_label` 处于未绑定状态。调用 `add(r0, r1, Operand(5))` 和 `b(&my_label)` 时，假设 `assembler` 的内部状态记录了当前的汇编位置。
*   **输出:**
    1. `bind(&my_label)` 会将 `my_label` 绑定到当前的汇编位置。
    2. `add(r0, r1, Operand(5))` 会生成 ARM 的 `add` 指令的机器码，将立即数 5 加到寄存器 `r1` 并存储到 `r0`。由于 5 可以直接编码为立即数，所以会使用短格式的 `add` 指令。
    3. `b(&my_label)` 会计算从当前位置到 `my_label` 绑定位置的分支偏移量，并生成相应的 `b` 指令的机器码。

**用户常见的编程错误 (举例说明)：**

在使用汇编器时，一个常见的编程错误是 **使用超出指令编码范围的立即数**。例如，如果尝试使用 `mov` 指令直接将一个大于 8 位且不能通过移位表示的立即数加载到寄存器，就会出错。

```c++
// 错误示例，假设 Assembler::mov 不会处理这种情况
assembler.mov(r0, Operand(0x12345678));
```

在这种情况下，正确的做法是使用 `Assembler::Move32BitImmediate` 函数，或者让 `Assembler::mov` 自动处理常量池加载。V8 的 `Assembler` 提供了便利的封装来避免这些底层的细节。

**归纳一下它的功能 (第 2 部分)：**

这部分代码的核心功能是 **为 ARM 架构提供一个汇编器接口**，允许 V8 编译器生成底层的机器码指令。它涵盖了标签管理、立即数处理、各种 ARM 指令（包括分支、数据处理和乘法/除法）的编码，并提供了一些辅助函数来处理指令编码的细节和常见的汇编编程问题。这部分是 V8 将 JavaScript 代码转化为可执行机器码的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/arm/assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
& ~kImm24Mask) == 0) {
        PrintF("value\n");
      } else {
        DCHECK_EQ(instr & 7 * B25, 5 * B25);  // b, bl, or blx
        Condition cond = Instruction::ConditionField(instr);
        const char* b;
        const char* c;
        if (cond == kSpecialCondition) {
          b = "blx";
          c = "";
        } else {
          if ((instr & B24) != 0)
            b = "bl";
          else
            b = "b";

          switch (cond) {
            case eq:
              c = "eq";
              break;
            case ne:
              c = "ne";
              break;
            case hs:
              c = "hs";
              break;
            case lo:
              c = "lo";
              break;
            case mi:
              c = "mi";
              break;
            case pl:
              c = "pl";
              break;
            case vs:
              c = "vs";
              break;
            case vc:
              c = "vc";
              break;
            case hi:
              c = "hi";
              break;
            case ls:
              c = "ls";
              break;
            case ge:
              c = "ge";
              break;
            case lt:
              c = "lt";
              break;
            case gt:
              c = "gt";
              break;
            case le:
              c = "le";
              break;
            case al:
              c = "";
              break;
            default:
              c = "";
              UNREACHABLE();
          }
        }
        PrintF("%s%s\n", b, c);
      }
      next(&l);
    }
  } else {
    PrintF("label in inconsistent state (pos = %d)\n", L->pos_);
  }
}

void Assembler::bind_to(Label* L, int pos) {
  DCHECK(0 <= pos && pos <= pc_offset());  // must have a valid binding position
  while (L->is_linked()) {
    int fixup_pos = L->pos();
    next(L);  // call next before overwriting link with target at fixup_pos
    target_at_put(fixup_pos, pos);
  }
  L->bind_to(pos);

  // Keep track of the last bound label so we don't eliminate any instructions
  // before a bound label.
  if (pos > last_bound_pos_) last_bound_pos_ = pos;
}

void Assembler::bind(Label* L) {
  DCHECK(!L->is_bound());  // label can only be bound once
  bind_to(L, pc_offset());
}

void Assembler::next(Label* L) {
  DCHECK(L->is_linked());
  int link = target_at(L->pos());
  if (link == L->pos()) {
    // Branch target points to the same instruction. This is the end of the link
    // chain.
    L->Unuse();
  } else {
    DCHECK_GE(link, 0);
    L->link_to(link);
  }
}

namespace {

// Low-level code emission routines depending on the addressing mode.
// If this returns true then you have to use the rotate_imm and immed_8
// that it returns, because it may have already changed the instruction
// to match them!
bool FitsShifter(uint32_t imm32, uint32_t* rotate_imm, uint32_t* immed_8,
                 Instr* instr) {
  // imm32 must be unsigned.
  {
    // 32-bit immediates can be encoded as:
    //   (8-bit value, 2*N bit left rotation)
    // e.g. 0xab00 can be encoded as 0xab shifted left by 8 == 2*4, i.e.
    //   (0xab, 4)
    //
    // Check three categories which cover all possible shifter fits:
    //   1. 0x000000FF: The value is already 8-bit (no shifting necessary),
    //   2. 0x000FF000: The 8-bit value is somewhere in the middle of the 32-bit
    //                  value, and
    //   3. 0xF000000F: The 8-bit value is split over the beginning and end of
    //                  the 32-bit value.

    // For 0x000000FF.
    if (imm32 <= 0xFF) {
      *rotate_imm = 0;
      *immed_8 = imm32;
      return true;
    }
    // For 0x000FF000, count trailing zeros and shift down to 0x000000FF. Note
    // that we have to round the trailing zeros down to the nearest multiple of
    // two, since we can only encode shifts of 2*N. Note also that we know that
    // imm32 isn't zero, since we already checked if it's less than 0xFF.
    int half_trailing_zeros = base::bits::CountTrailingZerosNonZero(imm32) / 2;
    uint32_t imm8 = imm32 >> (half_trailing_zeros * 2);
    if (imm8 <= 0xFF) {
      DCHECK_GT(half_trailing_zeros, 0);
      // Rotating right by trailing_zeros is equivalent to rotating left by
      // 32 - trailing_zeros. We return rotate_right / 2, so calculate
      // (32 - trailing_zeros)/2 == 16 - trailing_zeros/2.
      *rotate_imm = (16 - half_trailing_zeros);
      *immed_8 = imm8;
      return true;
    }
    // For 0xF000000F, rotate by 16 to get 0x000FF000 and continue as if it
    // were that case.
    uint32_t imm32_rot16 = base::bits::RotateLeft32(imm32, 16);
    half_trailing_zeros =
        base::bits::CountTrailingZerosNonZero(imm32_rot16) / 2;
    imm8 = imm32_rot16 >> (half_trailing_zeros * 2);
    if (imm8 <= 0xFF) {
      // We've rotated left by 2*8, so we can't have more than that many
      // trailing zeroes.
      DCHECK_LT(half_trailing_zeros, 8);
      // We've already rotated by 2*8, before calculating trailing_zeros/2,
      // so we need (32 - (16 + trailing_zeros))/2 == 8 - trailing_zeros/2.
      *rotate_imm = 8 - half_trailing_zeros;
      *immed_8 = imm8;
      return true;
    }
  }
  // If the opcode is one with a complementary version and the complementary
  // immediate fits, change the opcode.
  if (instr != nullptr) {
    if ((*instr & kMovMvnMask) == kMovMvnPattern) {
      if (FitsShifter(~imm32, rotate_imm, immed_8, nullptr)) {
        *instr ^= kMovMvnFlip;
        return true;
      } else if ((*instr & kMovLeaveCCMask) == kMovLeaveCCPattern) {
        if (CpuFeatures::IsSupported(ARMv7)) {
          if (imm32 < 0x10000) {
            *instr ^= kMovwLeaveCCFlip;
            *instr |= Assembler::EncodeMovwImmediate(imm32);
            *rotate_imm = *immed_8 = 0;  // Not used for movw.
            return true;
          }
        }
      }
    } else if ((*instr & kCmpCmnMask) == kCmpCmnPattern) {
      if (FitsShifter(-static_cast<int>(imm32), rotate_imm, immed_8, nullptr)) {
        *instr ^= kCmpCmnFlip;
        return true;
      }
    } else {
      Instr alu_insn = (*instr & kALUMask);
      if (alu_insn == ADD || alu_insn == SUB) {
        if (FitsShifter(-static_cast<int>(imm32), rotate_imm, immed_8,
                        nullptr)) {
          *instr ^= kAddSubFlip;
          return true;
        }
      } else if (alu_insn == AND || alu_insn == BIC) {
        if (FitsShifter(~imm32, rotate_imm, immed_8, nullptr)) {
          *instr ^= kAndBicFlip;
          return true;
        }
      }
    }
  }
  return false;
}

// We have to use the temporary register for things that can be relocated even
// if they can be encoded in the ARM's 12 bits of immediate-offset instruction
// space.  There is no guarantee that the relocated location can be similarly
// encoded.
bool MustOutputRelocInfo(RelocInfo::Mode rmode, const Assembler* assembler) {
  if (RelocInfo::IsOnlyForSerializer(rmode)) {
    if (assembler->predictable_code_size()) return true;
    return assembler->options().record_reloc_info_for_serialization;
  } else if (RelocInfo::IsNoInfo(rmode)) {
    return false;
  }
  return true;
}

bool UseMovImmediateLoad(const Operand& x, const Assembler* assembler) {
  DCHECK_NOT_NULL(assembler);
  if (x.MustOutputRelocInfo(assembler)) {
    // Prefer constant pool if data is likely to be patched.
    return false;
  } else {
    // Otherwise, use immediate load if movw / movt is available.
    return CpuFeatures::IsSupported(ARMv7);
  }
}

}  // namespace

bool Operand::MustOutputRelocInfo(const Assembler* assembler) const {
  return v8::internal::MustOutputRelocInfo(rmode_, assembler);
}

int Operand::InstructionsRequired(const Assembler* assembler,
                                  Instr instr) const {
  DCHECK_NOT_NULL(assembler);
  if (rm_.is_valid()) return 1;
  uint32_t dummy1, dummy2;
  if (MustOutputRelocInfo(assembler) ||
      !FitsShifter(immediate(), &dummy1, &dummy2, &instr)) {
    // The immediate operand cannot be encoded as a shifter operand, or use of
    // constant pool is required.  First account for the instructions required
    // for the constant pool or immediate load
    int instructions;
    if (UseMovImmediateLoad(*this, assembler)) {
      DCHECK(CpuFeatures::IsSupported(ARMv7));
      // A movw / movt immediate load.
      instructions = 2;
    } else {
      // A small constant pool load.
      instructions = 1;
    }
    if ((instr & ~kCondMask) != 13 * B21) {  // mov, S not set
      // For a mov or mvn instruction which doesn't set the condition
      // code, the constant pool or immediate load is enough, otherwise we need
      // to account for the actual instruction being requested.
      instructions += 1;
    }
    return instructions;
  } else {
    // No use of constant pool and the immediate operand can be encoded as a
    // shifter operand.
    return 1;
  }
}

void Assembler::Move32BitImmediate(Register rd, const Operand& x,
                                   Condition cond) {
  if (UseMovImmediateLoad(x, this)) {
    CpuFeatureScope scope(this, ARMv7);
    // UseMovImmediateLoad should return false when we need to output
    // relocation info, since we prefer the constant pool for values that
    // can be patched.
    DCHECK(!x.MustOutputRelocInfo(this));
    UseScratchRegisterScope temps(this);
    // Re-use the destination register as a scratch if possible.
    Register target = rd != pc && rd != sp ? rd : temps.Acquire();
    uint32_t imm32 = static_cast<uint32_t>(x.immediate());
    movw(target, imm32 & 0xFFFF, cond);
    movt(target, imm32 >> 16, cond);
    if (target.code() != rd.code()) {
      mov(rd, target, LeaveCC, cond);
    }
  } else {
    int32_t immediate;
    if (x.IsHeapNumberRequest()) {
      RequestHeapNumber(x.heap_number_request());
      immediate = 0;
    } else {
      immediate = x.immediate();
    }
    ConstantPoolAddEntry(pc_offset(), x.rmode_, immediate);
    ldr_pcrel(rd, 0, cond);
  }
}

void Assembler::AddrMode1(Instr instr, Register rd, Register rn,
                          const Operand& x) {
  CheckBuffer();
  uint32_t opcode = instr & kOpCodeMask;
  bool set_flags = (instr & S) != 0;
  DCHECK((opcode == ADC) || (opcode == ADD) || (opcode == AND) ||
         (opcode == BIC) || (opcode == EOR) || (opcode == ORR) ||
         (opcode == RSB) || (opcode == RSC) || (opcode == SBC) ||
         (opcode == SUB) || (opcode == CMN) || (opcode == CMP) ||
         (opcode == TEQ) || (opcode == TST) || (opcode == MOV) ||
         (opcode == MVN));
  // For comparison instructions, rd is not defined.
  DCHECK(rd.is_valid() || (opcode == CMN) || (opcode == CMP) ||
         (opcode == TEQ) || (opcode == TST));
  // For move instructions, rn is not defined.
  DCHECK(rn.is_valid() || (opcode == MOV) || (opcode == MVN));
  DCHECK(rd.is_valid() || rn.is_valid());
  DCHECK_EQ(instr & ~(kCondMask | kOpCodeMask | S), 0);
  if (!AddrMode1TryEncodeOperand(&instr, x)) {
    DCHECK(x.IsImmediate());
    // Upon failure to encode, the opcode should not have changed.
    DCHECK(opcode == (instr & kOpCodeMask));
    UseScratchRegisterScope temps(this);
    Condition cond = Instruction::ConditionField(instr);
    if ((opcode == MOV) && !set_flags) {
      // Generate a sequence of mov instructions or a load from the constant
      // pool only for a MOV instruction which does not set the flags.
      DCHECK(!rn.is_valid());
      Move32BitImmediate(rd, x, cond);
    } else if ((opcode == ADD || opcode == SUB) && !set_flags && (rd == rn) &&
               !temps.CanAcquire()) {
      // Split the operation into a sequence of additions if we cannot use a
      // scratch register. In this case, we cannot re-use rn and the assembler
      // does not have any scratch registers to spare.
      uint32_t imm = x.immediate();
      do {
        // The immediate encoding format is composed of 8 bits of data and 4
        // bits encoding a rotation. Each of the 16 possible rotations accounts
        // for a rotation by an even number.
        //   4 bits -> 16 rotations possible
        //          -> 16 rotations of 2 bits each fits in a 32-bit value.
        // This means that finding the even number of trailing zeroes of the
        // immediate allows us to more efficiently split it:
        int trailing_zeroes = base::bits::CountTrailingZeros(imm) & ~1u;
        uint32_t mask = (0xFF << trailing_zeroes);
        if (opcode == ADD) {
          add(rd, rd, Operand(imm & mask), LeaveCC, cond);
        } else {
          DCHECK_EQ(opcode, SUB);
          sub(rd, rd, Operand(imm & mask), LeaveCC, cond);
        }
        imm = imm & ~mask;
      } while (!ImmediateFitsAddrMode1Instruction(imm));
      if (opcode == ADD) {
        add(rd, rd, Operand(imm), LeaveCC, cond);
      } else {
        DCHECK_EQ(opcode, SUB);
        sub(rd, rd, Operand(imm), LeaveCC, cond);
      }
    } else {
      // The immediate operand cannot be encoded as a shifter operand, so load
      // it first to a scratch register and change the original instruction to
      // use it.
      // Re-use the destination register if possible.
      Register scratch = (rd.is_valid() && rd != rn && rd != pc && rd != sp)
                             ? rd
                             : temps.Acquire();
      mov(scratch, x, LeaveCC, cond);
      AddrMode1(instr, rd, rn, Operand(scratch));
    }
    return;
  }
  if (!rd.is_valid()) {
    // Emit a comparison instruction.
    emit(instr | rn.code() * B16);
  } else if (!rn.is_valid()) {
    // Emit a move instruction. If the operand is a register-shifted register,
    // then prevent the destination from being PC as this is unpredictable.
    DCHECK(!x.IsRegisterShiftedRegister() || rd != pc);
    emit(instr | rd.code() * B12);
  } else {
    emit(instr | rn.code() * B16 | rd.code() * B12);
  }
  if (rn == pc || x.rm_ == pc) {
    // Block constant pool emission for one instruction after reading pc.
    BlockConstPoolFor(1);
  }
}

bool Assembler::AddrMode1TryEncodeOperand(Instr* instr, const Operand& x) {
  if (x.IsImmediate()) {
    // Immediate.
    uint32_t rotate_imm;
    uint32_t immed_8;
    if (x.MustOutputRelocInfo(this) ||
        !FitsShifter(x.immediate(), &rotate_imm, &immed_8, instr)) {
      // Let the caller handle generating multiple instructions.
      return false;
    }
    *instr |= I | rotate_imm * B8 | immed_8;
  } else if (x.IsImmediateShiftedRegister()) {
    *instr |= x.shift_imm_ * B7 | x.shift_op_ | x.rm_.code();
  } else {
    DCHECK(x.IsRegisterShiftedRegister());
    // It is unpredictable to use the PC in this case.
    DCHECK(x.rm_ != pc && x.rs_ != pc);
    *instr |= x.rs_.code() * B8 | x.shift_op_ | B4 | x.rm_.code();
  }

  return true;
}

void Assembler::AddrMode2(Instr instr, Register rd, const MemOperand& x) {
  DCHECK((instr & ~(kCondMask | B | L)) == B26);
  // This method does not handle pc-relative addresses. ldr_pcrel() should be
  // used instead.
  DCHECK(x.rn_ != pc);
  int am = x.am_;
  if (!x.rm_.is_valid()) {
    // Immediate offset.
    int offset_12 = x.offset_;
    if (offset_12 < 0) {
      offset_12 = -offset_12;
      am ^= U;
    }
    if (!is_uint12(offset_12)) {
      // Immediate offset cannot be encoded, load it first to a scratch
      // register.
      UseScratchRegisterScope temps(this);
      // Allow re-using rd for load instructions if possible.
      bool is_load = (instr & L) == L;
      Register scratch = (is_load && rd != x.rn_ && rd != pc && rd != sp)
                             ? rd
                             : temps.Acquire();
      mov(scratch, Operand(x.offset_), LeaveCC,
          Instruction::ConditionField(instr));
      AddrMode2(instr, rd, MemOperand(x.rn_, scratch, x.am_));
      return;
    }
    DCHECK_GE(offset_12, 0);  // no masking needed
    instr |= offset_12;
  } else {
    // Register offset (shift_imm_ and shift_op_ are 0) or scaled
    // register offset the constructors make sure than both shift_imm_
    // and shift_op_ are initialized.
    DCHECK(x.rm_ != pc);
    instr |= B25 | x.shift_imm_ * B7 | x.shift_op_ | x.rm_.code();
  }
  DCHECK((am & (P | W)) == P || x.rn_ != pc);  // no pc base with writeback
  emit(instr | am | x.rn_.code() * B16 | rd.code() * B12);
}

void Assembler::AddrMode3(Instr instr, Register rd, const MemOperand& x) {
  DCHECK((instr & ~(kCondMask | L | S6 | H)) == (B4 | B7));
  DCHECK(x.rn_.is_valid());
  // This method does not handle pc-relative addresses. ldr_pcrel() should be
  // used instead.
  DCHECK(x.rn_ != pc);
  int am = x.am_;
  bool is_load = (instr & L) == L;
  if (!x.rm_.is_valid()) {
    // Immediate offset.
    int offset_8 = x.offset_;
    if (offset_8 < 0) {
      offset_8 = -offset_8;
      am ^= U;
    }
    if (!is_uint8(offset_8)) {
      // Immediate offset cannot be encoded, load it first to a scratch
      // register.
      UseScratchRegisterScope temps(this);
      // Allow re-using rd for load instructions if possible.
      Register scratch = (is_load && rd != x.rn_ && rd != pc && rd != sp)
                             ? rd
                             : temps.Acquire();
      mov(scratch, Operand(x.offset_), LeaveCC,
          Instruction::ConditionField(instr));
      AddrMode3(instr, rd, MemOperand(x.rn_, scratch, x.am_));
      return;
    }
    DCHECK_GE(offset_8, 0);  // no masking needed
    instr |= B | (offset_8 >> 4) * B8 | (offset_8 & 0xF);
  } else if (x.shift_imm_ != 0) {
    // Scaled register offsets are not supported, compute the offset separately
    // to a scratch register.
    UseScratchRegisterScope temps(this);
    // Allow re-using rd for load instructions if possible.
    Register scratch =
        (is_load && rd != x.rn_ && rd != pc && rd != sp) ? rd : temps.Acquire();
    mov(scratch, Operand(x.rm_, x.shift_op_, x.shift_imm_), LeaveCC,
        Instruction::ConditionField(instr));
    AddrMode3(instr, rd, MemOperand(x.rn_, scratch, x.am_));
    return;
  } else {
    // Register offset.
    DCHECK((am & (P | W)) == P || x.rm_ != pc);  // no pc index with writeback
    instr |= x.rm_.code();
  }
  DCHECK((am & (P | W)) == P || x.rn_ != pc);  // no pc base with writeback
  emit(instr | am | x.rn_.code() * B16 | rd.code() * B12);
}

void Assembler::AddrMode4(Instr instr, Register rn, RegList rl) {
  DCHECK((instr & ~(kCondMask | P | U | W | L)) == B27);
  DCHECK(!rl.is_empty());
  DCHECK(rn != pc);
  emit(instr | rn.code() * B16 | rl.bits());
}

void Assembler::AddrMode5(Instr instr, CRegister crd, const MemOperand& x) {
  // Unindexed addressing is not encoded by this function.
  DCHECK_EQ((B27 | B26),
            (instr & ~(kCondMask | kCoprocessorMask | P | U | N | W | L)));
  DCHECK(x.rn_.is_valid() && !x.rm_.is_valid());
  int am = x.am_;
  int offset_8 = x.offset_;
  DCHECK_EQ(offset_8 & 3, 0);  // offset must be an aligned word offset
  offset_8 >>= 2;
  if (offset_8 < 0) {
    offset_8 = -offset_8;
    am ^= U;
  }
  DCHECK(is_uint8(offset_8));  // unsigned word offset must fit in a byte
  DCHECK((am & (P | W)) == P || x.rn_ != pc);  // no pc base with writeback

  // Post-indexed addressing requires W == 1; different than in AddrMode2/3.
  if ((am & P) == 0) am |= W;

  DCHECK_GE(offset_8, 0);  // no masking needed
  emit(instr | am | x.rn_.code() * B16 | crd.code() * B12 | offset_8);
}

int Assembler::branch_offset(Label* L) {
  int target_pos;
  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      // Point to previous instruction that uses the link.
      target_pos = L->pos();
    } else {
      // First entry of the link chain points to itself.
      target_pos = pc_offset();
    }
    L->link_to(pc_offset());
  }

  return target_pos - (pc_offset() + Instruction::kPcLoadDelta);
}

// Branch instructions.
void Assembler::b(int branch_offset, Condition cond, RelocInfo::Mode rmode) {
  if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode);
  DCHECK_EQ(branch_offset & 3, 0);
  int imm24 = branch_offset >> 2;
  const bool b_imm_check = is_int24(imm24);
  CHECK(b_imm_check);

  // Block the emission of the constant pool before the next instruction.
  // Otherwise the passed-in branch offset would be off.
  BlockConstPoolFor(1);

  emit(cond | B27 | B25 | (imm24 & kImm24Mask));

  if (cond == al) {
    // Dead code is a good location to emit the constant pool.
    CheckConstPool(false, false);
  }
}

void Assembler::bl(int branch_offset, Condition cond, RelocInfo::Mode rmode) {
  if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode);
  DCHECK_EQ(branch_offset & 3, 0);
  int imm24 = branch_offset >> 2;
  const bool bl_imm_check = is_int24(imm24);
  CHECK(bl_imm_check);

  // Block the emission of the constant pool before the next instruction.
  // Otherwise the passed-in branch offset would be off.
  BlockConstPoolFor(1);

  emit(cond | B27 | B25 | B24 | (imm24 & kImm24Mask));
}

void Assembler::blx(int branch_offset) {
  DCHECK_EQ(branch_offset & 1, 0);
  int h = ((branch_offset & 2) >> 1) * B24;
  int imm24 = branch_offset >> 2;
  const bool blx_imm_check = is_int24(imm24);
  CHECK(blx_imm_check);

  // Block the emission of the constant pool before the next instruction.
  // Otherwise the passed-in branch offset would be off.
  BlockConstPoolFor(1);

  emit(kSpecialCondition | B27 | B25 | h | (imm24 & kImm24Mask));
}

void Assembler::blx(Register target, Condition cond) {
  DCHECK(target != pc);
  emit(cond | B24 | B21 | 15 * B16 | 15 * B12 | 15 * B8 | BLX | target.code());
}

void Assembler::bx(Register target, Condition cond) {
  DCHECK(target != pc);  // use of pc is actually allowed, but discouraged
  emit(cond | B24 | B21 | 15 * B16 | 15 * B12 | 15 * B8 | BX | target.code());
}

void Assembler::b(Label* L, Condition cond) {
  CheckBuffer();
  b(branch_offset(L), cond);
}

void Assembler::bl(Label* L, Condition cond) {
  CheckBuffer();
  bl(branch_offset(L), cond);
}

void Assembler::blx(Label* L) {
  CheckBuffer();
  blx(branch_offset(L));
}

// Data-processing instructions.

void Assembler::and_(Register dst, Register src1, const Operand& src2, SBit s,
                     Condition cond) {
  AddrMode1(cond | AND | s, dst, src1, src2);
}

void Assembler::and_(Register dst, Register src1, Register src2, SBit s,
                     Condition cond) {
  and_(dst, src1, Operand(src2), s, cond);
}

void Assembler::eor(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | EOR | s, dst, src1, src2);
}

void Assembler::eor(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | EOR | s, dst, src1, Operand(src2));
}

void Assembler::sub(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | SUB | s, dst, src1, src2);
}

void Assembler::sub(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  sub(dst, src1, Operand(src2), s, cond);
}

void Assembler::rsb(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | RSB | s, dst, src1, src2);
}

void Assembler::add(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | ADD | s, dst, src1, src2);
}

void Assembler::add(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  add(dst, src1, Operand(src2), s, cond);
}

void Assembler::adc(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | ADC | s, dst, src1, src2);
}

void Assembler::sbc(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | SBC | s, dst, src1, src2);
}

void Assembler::rsc(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | RSC | s, dst, src1, src2);
}

void Assembler::tst(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | TST | S, no_reg, src1, src2);
}

void Assembler::tst(Register src1, Register src2, Condition cond) {
  tst(src1, Operand(src2), cond);
}

void Assembler::teq(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | TEQ | S, no_reg, src1, src2);
}

void Assembler::cmp(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | CMP | S, no_reg, src1, src2);
}

void Assembler::cmp(Register src1, Register src2, Condition cond) {
  cmp(src1, Operand(src2), cond);
}

void Assembler::cmp_raw_immediate(Register src, int raw_immediate,
                                  Condition cond) {
  DCHECK(is_uint12(raw_immediate));
  emit(cond | I | CMP | S | src.code() << 16 | raw_immediate);
}

void Assembler::cmn(Register src1, const Operand& src2, Condition cond) {
  AddrMode1(cond | CMN | S, no_reg, src1, src2);
}

void Assembler::orr(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | ORR | s, dst, src1, src2);
}

void Assembler::orr(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  orr(dst, src1, Operand(src2), s, cond);
}

void Assembler::mov(Register dst, const Operand& src, SBit s, Condition cond) {
  // Don't allow nop instructions in the form mov rn, rn to be generated using
  // the mov instruction. They must be generated using nop(int/NopMarkerTypes).
  DCHECK(!(src.IsRegister() && src.rm() == dst && s == LeaveCC && cond == al));
  AddrMode1(cond | MOV | s, dst, no_reg, src);
}

void Assembler::mov(Register dst, Register src, SBit s, Condition cond) {
  mov(dst, Operand(src), s, cond);
}

void Assembler::mov_label_offset(Register dst, Label* label) {
  if (label->is_bound()) {
    mov(dst, Operand(label->pos() +
                     (InstructionStream::kHeaderSize - kHeapObjectTag)));
  } else {
    // Emit the link to the label in the code stream followed by extra nop
    // instructions.
    // If the label is not linked, then start a new link chain by linking it to
    // itself, emitting pc_offset().
    int link = label->is_linked() ? label->pos() : pc_offset();
    label->link_to(pc_offset());

    // When the label is bound, these instructions will be patched with a
    // sequence of movw/movt or mov/orr/orr instructions. They will load the
    // destination register with the position of the label from the beginning
    // of the code.
    //
    // The link will be extracted from the first instruction and the destination
    // register from the second.
    //   For ARMv7:
    //      link
    //      mov dst, dst
    //   For ARMv6:
    //      link
    //      mov dst, dst
    //      mov dst, dst
    //
    // When the label gets bound: target_at extracts the link and target_at_put
    // patches the instructions.
    CHECK(is_uint24(link));
    BlockConstPoolScope block_const_pool(this);
    emit(link);
    nop(dst.code());
    if (!CpuFeatures::IsSupported(ARMv7)) {
      nop(dst.code());
    }
  }
}

void Assembler::movw(Register reg, uint32_t immediate, Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  emit(cond | 0x30 * B20 | reg.code() * B12 | EncodeMovwImmediate(immediate));
}

void Assembler::movt(Register reg, uint32_t immediate, Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  emit(cond | 0x34 * B20 | reg.code() * B12 | EncodeMovwImmediate(immediate));
}

void Assembler::bic(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  AddrMode1(cond | BIC | s, dst, src1, src2);
}

void Assembler::mvn(Register dst, const Operand& src, SBit s, Condition cond) {
  AddrMode1(cond | MVN | s, dst, no_reg, src);
}

void Assembler::asr(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  if (src2.IsRegister()) {
    mov(dst, Operand(src1, ASR, src2.rm()), s, cond);
  } else {
    mov(dst, Operand(src1, ASR, src2.immediate()), s, cond);
  }
}

void Assembler::lsl(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  if (src2.IsRegister()) {
    mov(dst, Operand(src1, LSL, src2.rm()), s, cond);
  } else {
    mov(dst, Operand(src1, LSL, src2.immediate()), s, cond);
  }
}

void Assembler::lsr(Register dst, Register src1, const Operand& src2, SBit s,
                    Condition cond) {
  if (src2.IsRegister()) {
    mov(dst, Operand(src1, LSR, src2.rm()), s, cond);
  } else {
    mov(dst, Operand(src1, LSR, src2.immediate()), s, cond);
  }
}

// Multiply instructions.
void Assembler::mla(Register dst, Register src1, Register src2, Register srcA,
                    SBit s, Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc && srcA != pc);
  emit(cond | A | s | dst.code() * B16 | srcA.code() * B12 | src2.code() * B8 |
       B7 | B4 | src1.code());
}

void Assembler::mls(Register dst, Register src1, Register src2, Register srcA,
                    Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc && srcA != pc);
  DCHECK(IsEnabled(ARMv7));
  emit(cond | B22 | B21 | dst.code() * B16 | srcA.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::sdiv(Register dst, Register src1, Register src2,
                     Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  DCHECK(IsEnabled(SUDIV));
  emit(cond | B26 | B25 | B24 | B20 | dst.code() * B16 | 0xF * B12 |
       src2.code() * B8 | B4 | src1.code());
}

void Assembler::udiv(Register dst, Register src1, Register src2,
                     Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  DCHECK(IsEnabled(SUDIV));
  emit(cond | B26 | B25 | B24 | B21 | B20 | dst.code() * B16 | 0xF * B12 |
       src2.code() * B8 | B4 | src1.code());
}

void Assembler::mul(Register dst, Register src1, Register src2, SBit s,
                    Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  // dst goes in bits 16-19 for this instruction!
  emit(cond | s | dst.code() * B16 | src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::smmla(Register dst, Register src1, Register src2, Register srcA,
                      Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc && srcA != pc);
  emit(cond | B26 | B25 | B24 | B22 | B20 | dst.code() * B16 |
       srcA.code() * B12 | src2.code() * B8 | B4 | src1.code());
}

void Assembler::smmul(Register dst, Register src1, Register src2,
                      Condition cond) {
  DCHECK(dst != pc && src1 != pc && src2 != pc);
  emit(cond | B26 | B25 | B24 | B22 | B20 | dst.code() * B16 | 0xF * B12 |
       src2.code() * B8 | B4 | src1.code());
}

void Assembler::smlal(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | B22 | A | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::smull(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | B22 | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::umlal(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | A | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

void Assembler::umull(Register dstL, Register dstH, Register src1,
                      Register src2, SBit s, Condition cond) {
  DCHECK(dstL != pc && dstH != pc && src1 != pc && src2 != pc);
  DCHECK(dstL != dstH);
  emit(cond | B23 | s | dstH.code() * B16 | dstL.code() * B12 |
       src2.code() * B8 | B7 | B4 | src1.code());
}

// Miscellaneous arithmetic instructions.
void Assembler::clz(Register dst, Register src, Condition cond) {
  DCHECK(dst != pc && src != pc);
  emit(cond | B24 | B22 | B21 | 15 * B16 | dst.code() * B12 | 15 * B8 | CLZ |
       src.code());
}

// Saturating instructions.

// Unsigned saturate.
void Assembler::usat(Register dst, int satpos, const Operand& src,
                     Condition cond) {
  DCHECK(dst != pc && src.rm_ != pc);
  DCHECK((satpos >= 0) && (satpos <= 31));
  DCHECK(src.IsImmediateShiftedRegister());
  DCHECK((src.shift_op_ == ASR) || (src.shift_op_ == LSL));

  int sh = 0;
  if (src.shift_op_ == ASR) {
    sh = 1;
  }

  emit(cond | 0x6 * B24 | 0xE * B20 | satpos * B16 | dst.code() * B12 |
```