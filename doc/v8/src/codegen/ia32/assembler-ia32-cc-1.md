Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/ia32/assembler-ia32.cc`. This is the second part of a three-part snippet.

Here's a breakdown of the code:

1. **Shift Instructions:**  `hld_cl`, `shl`, `shl_cl`, `shr`, `shr_cl`, `shrd`, `shrd_cl`. These functions implement various bitwise shift operations on registers and memory locations.
2. **Subtraction Instructions:** `sub`, `sub_sp_32`. These implement subtraction operations.
3. **Test Instructions:** `test`, `test_b`, `test_w`. These functions implement bitwise AND operations that set flags without modifying operands.
4. **XOR Instruction:** `xor_`. This implements bitwise XOR operations.
5. **Bit Manipulation Instructions:** `bswap`, `bt`, `bts`, `bsr`, `bsf`. These instructions manipulate individual bits within operands.
6. **Control Flow and Miscellaneous Instructions:** `hlt`, `int3`, `nop`, `ret`, `ud2`. These are instructions for halting execution, triggering breakpoints, doing nothing, returning from a function, and causing an undefined instruction exception.
7. **Label Handling:**  `print`, `bind_to`, `bind`, `record_farjmp_position`, `is_optimizable_farjmp`. These functions deal with labels, which are used to mark positions in the generated code for jumps and calls. They handle binding labels to addresses and optimizing jump distances.
8. **Call and Jump Instructions:** `call`, `jmp`, `j`. These functions implement function calls and jumps, both conditional and unconditional.
9. **Floating-Point Unit (FPU) Instructions:** A large block of functions starting with `fld`. These are instructions for performing operations on the FPU stack, including loading, storing, arithmetic, and comparisons.
10. **Streaming SIMD Extensions (SSE) Instructions:** A block of functions starting with `cvttss2si`. These are instructions for performing operations on XMM registers, which are used for single-instruction, multiple-data (SIMD) operations on floating-point and integer values.

Based on this analysis, the main function of this code snippet is to provide a set of methods for generating IA-32 machine code instructions within the V8 JavaScript engine. It covers arithmetic, logical, control flow, and floating-point operations.

Considering that this is part 2 of 3, the functionality likely builds upon the foundation laid in part 1 and prepares for the functionality in part 3.
这是 `v8/src/codegen/ia32/assembler-ia32.cc` 文件的一部分代码，它主要提供了以下功能：

1. **实现了多种 IA-32 架构的汇编指令:**  这段代码定义了 `Assembler` 类中的成员函数，每个函数对应一条或一组 IA-32 汇编指令。这些指令涵盖了：
    *   **位操作指令:**  例如 `hld_cl` (双精度移位逻辑左移), `shl` (逻辑左移), `shr` (逻辑右移), `shrd` (双精度移位右移)。
    *   **算术运算指令:** 例如 `sub` (减法)。
    *   **位测试指令:** 例如 `test` (逻辑与测试)。
    *   **逻辑运算指令:** 例如 `xor_` (异或)。
    *   **位扫描指令:** 例如 `bswap` (字节序反转), `bt` (位测试), `bts` (位测试并置位), `bsr` (位反向扫描), `bsf` (位正向扫描)。
    *   **控制流指令:** 例如 `hlt` (停止), `int3` (断点), `nop` (空操作), `ret` (返回)。
    *   **标签 (Label) 管理:**  提供了绑定标签、链接标签以及打印标签信息的功能，用于生成跳转和调用指令。
    *   **调用和跳转指令:** 例如 `call` (调用), `jmp` (跳转), `j` (条件跳转)。
    *   **浮点运算指令 (FPU):**  提供了大量的 FPU 指令，例如 `fld` (加载浮点数), `fstp` (存储浮点数并弹出), `fadd` (浮点数加法), `fsub` (浮点数减法), `fmul` (浮点数乘法), `fdiv` (浮点数除法) 等。
    *   **SSE 指令:**  提供了 Streaming SIMD Extensions (SSE) 指令，用于处理单指令多数据操作，例如 `cvttss2si` (将单精度浮点数转换为有符号整数), `movaps` (移动对齐的单精度浮点数), `movups` (移动非对齐的单精度浮点数),  `addps` (单精度浮点数加法) 等。

2. **封装了指令的编码细节:** 每个成员函数负责生成对应汇编指令的机器码。例如，`EMIT()` 宏用于将字节写入到代码缓冲区中，`emit_operand()` 函数用于编码操作数。

3. **提供了用于生成可执行代码的基础构建块:**  `Assembler` 类是 V8 代码生成器的核心组件之一，它允许 V8 将 JavaScript 代码翻译成底层的机器码。

**关于 .tq 结尾：**

如果 `v8/src/codegen/ia32/assembler-ia32.cc` 文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用来定义内置函数和运行时函数的领域特定语言。由于这里的文件名是 `.cc`，所以它不是 Torque 文件，而是 C++ 文件。

**与 JavaScript 功能的关系：**

`v8/src/codegen/ia32/assembler-ia32.cc` 中定义的汇编指令直接服务于 JavaScript 的执行。当 V8 编译 JavaScript 代码时，它会将 JavaScript 代码转换为一系列的机器指令，这些指令就包括了这里定义的各种 IA-32 指令。

**JavaScript 示例：**

虽然不能直接用 JavaScript 代码来“调用”这些汇编指令，但 JavaScript 的某些操作在底层会被编译成这些指令。例如：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
```

在 V8 的 IA-32 架构上，`add` 函数中的加法操作 `a + b` 很可能会被编译成 `add` 相关的汇编指令。

再例如，浮点数操作：

```javascript
let x = 2.5;
let y = 1.2;
let sum = x + y;
```

这里的浮点数加法操作在底层可能会被编译成 `fadd` 或类似的 FPU 指令。

**代码逻辑推理 (假设输入与输出)：**

假设我们调用 `Assembler::add(eax, ebx)`，其中 `eax` 和 `ebx` 是寄存器。

*   **假设输入:**  `dst = eax`, `src = ebx`
*   **代码逻辑:**  `Assembler::add(Register dst, Operand src)` 函数会执行以下操作：
    *   调用 `EnsureSpace` 确保有足够的空间写入指令。
    *   发出 `0x01` 字节 (add 指令的操作码)。
    *   调用 `emit_operand(dst, src)` 来编码操作数，这将根据 `eax` 和 `ebx` 的寄存器编码生成相应的 ModR/M 字节。
*   **可能输出 (机器码片段):**  `01 D8` (假设 `eax` 编码为 `000`，`ebx` 编码为 `011`)。

**用户常见的编程错误：**

这段代码是 V8 内部的代码，普通 JavaScript 开发者不会直接编写或修改它。然而，理解汇编层面有助于理解一些性能问题或 JavaScript 引擎的内部行为。

一个相关的常见编程错误（虽然不是直接操作汇编），是 **在 JavaScript 中进行大量的、密集的数值计算**，特别是浮点数计算，可能会因为底层硬件的限制而导致精度问题或性能下降。了解 FPU 和 SSE 指令的存在，可以帮助开发者意识到这些操作在底层需要进行大量的处理。

**归纳一下它的功能 (第 2 部分):**

作为 `v8/src/codegen/ia32/assembler-ia32.cc` 的第二部分，这段代码延续了第一部分的功能，继续 **提供了用于生成 IA-32 架构机器码的各种汇编指令的实现**。它涵盖了更广泛的指令集，包括位操作、算术运算、逻辑运算、控制流、标签管理，以及重要的 **浮点运算 (FPU) 和 SSE 指令**。这些指令是 V8 将 JavaScript 代码转化为可执行机器码的关键组成部分，使得 JavaScript 能够在 IA-32 架构的处理器上高效运行。这部分代码增强了 `Assembler` 类的能力，使其能够处理更复杂的代码生成任务。

### 提示词
```
这是目录为v8/src/codegen/ia32/assembler-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ia32/assembler-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
hld_cl(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xA5);
  emit_operand(src, Operand(dst));
}

void Assembler::shl(Operand dst, uint8_t imm8) {
  EnsureSpace ensure_space(this);
  DCHECK(is_uint5(imm8));  // illegal shift count
  if (imm8 == 1) {
    EMIT(0xD1);
    emit_operand(esp, dst);
  } else {
    EMIT(0xC1);
    emit_operand(esp, dst);
    EMIT(imm8);
  }
}

void Assembler::shl_cl(Operand dst) {
  EnsureSpace ensure_space(this);
  EMIT(0xD3);
  emit_operand(esp, dst);
}

void Assembler::shr(Operand dst, uint8_t imm8) {
  EnsureSpace ensure_space(this);
  DCHECK(is_uint5(imm8));  // illegal shift count
  if (imm8 == 1) {
    EMIT(0xD1);
    emit_operand(ebp, dst);
  } else {
    EMIT(0xC1);
    emit_operand(ebp, dst);
    EMIT(imm8);
  }
}

void Assembler::shr_cl(Operand dst) {
  EnsureSpace ensure_space(this);
  EMIT(0xD3);
  emit_operand(ebp, dst);
}

void Assembler::shrd(Register dst, Register src, uint8_t shift) {
  DCHECK(is_uint5(shift));
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xAC);
  emit_operand(src, Operand(dst));
  EMIT(shift);
}

void Assembler::shrd_cl(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xAD);
  emit_operand(src, dst);
}

void Assembler::sub(Operand dst, const Immediate& x) {
  EnsureSpace ensure_space(this);
  emit_arith(5, dst, x);
}

void Assembler::sub(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x2B);
  emit_operand(dst, src);
}

void Assembler::sub(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  EMIT(0x29);
  emit_operand(src, dst);
}

void Assembler::sub_sp_32(uint32_t imm) {
  EnsureSpace ensure_space(this);
  EMIT(0x81);  // using a literal 32-bit immediate.
  static constexpr Register ireg = Register::from_code(5);
  emit_operand(ireg, Operand(esp));
  emit(imm);
}

void Assembler::test(Register reg, const Immediate& imm) {
  if (imm.is_uint8()) {
    test_b(reg, imm);
    return;
  }

  EnsureSpace ensure_space(this);
  // This is not using emit_arith because test doesn't support
  // sign-extension of 8-bit operands.
  if (reg == eax) {
    EMIT(0xA9);
  } else {
    EMIT(0xF7);
    EMIT(0xC0 | reg.code());
  }
  emit(imm);
}

void Assembler::test(Register reg, Operand op) {
  EnsureSpace ensure_space(this);
  EMIT(0x85);
  emit_operand(reg, op);
}

void Assembler::test_b(Register reg, Operand op) {
  CHECK(reg.is_byte_register());
  EnsureSpace ensure_space(this);
  EMIT(0x84);
  emit_operand(reg, op);
}

void Assembler::test(Operand op, const Immediate& imm) {
  if (op.is_reg_only()) {
    test(op.reg(), imm);
    return;
  }
  if (imm.is_uint8()) {
    return test_b(op, imm);
  }
  EnsureSpace ensure_space(this);
  EMIT(0xF7);
  emit_operand(eax, op);
  emit(imm);
}

void Assembler::test_b(Register reg, Immediate imm8) {
  DCHECK(imm8.is_uint8());
  EnsureSpace ensure_space(this);
  // Only use test against byte for registers that have a byte
  // variant: eax, ebx, ecx, and edx.
  if (reg == eax) {
    EMIT(0xA8);
    emit_b(imm8);
  } else if (reg.is_byte_register()) {
    emit_arith_b(0xF6, 0xC0, reg, static_cast<uint8_t>(imm8.immediate()));
  } else {
    EMIT(0x66);
    EMIT(0xF7);
    EMIT(0xC0 | reg.code());
    emit_w(imm8);
  }
}

void Assembler::test_b(Operand op, Immediate imm8) {
  if (op.is_reg_only()) {
    test_b(op.reg(), imm8);
    return;
  }
  EnsureSpace ensure_space(this);
  EMIT(0xF6);
  emit_operand(eax, op);
  emit_b(imm8);
}

void Assembler::test_w(Register reg, Immediate imm16) {
  DCHECK(imm16.is_int16() || imm16.is_uint16());
  EnsureSpace ensure_space(this);
  if (reg == eax) {
    EMIT(0xA9);
    emit_w(imm16);
  } else {
    EMIT(0x66);
    EMIT(0xF7);
    EMIT(0xC0 | reg.code());
    emit_w(imm16);
  }
}

void Assembler::test_w(Register reg, Operand op) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x85);
  emit_operand(reg, op);
}

void Assembler::test_w(Operand op, Immediate imm16) {
  DCHECK(imm16.is_int16() || imm16.is_uint16());
  if (op.is_reg_only()) {
    test_w(op.reg(), imm16);
    return;
  }
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0xF7);
  emit_operand(eax, op);
  emit_w(imm16);
}

void Assembler::xor_(Register dst, int32_t imm32) {
  EnsureSpace ensure_space(this);
  emit_arith(6, Operand(dst), Immediate(imm32));
}

void Assembler::xor_(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x33);
  emit_operand(dst, src);
}

void Assembler::xor_(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  EMIT(0x31);
  emit_operand(src, dst);
}

void Assembler::xor_(Operand dst, const Immediate& x) {
  EnsureSpace ensure_space(this);
  emit_arith(6, dst, x);
}

void Assembler::bswap(Register dst) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xC8 + dst.code());
}

void Assembler::bt(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xA3);
  emit_operand(src, dst);
}

void Assembler::bts(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xAB);
  emit_operand(src, dst);
}

void Assembler::bsr(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xBD);
  emit_operand(dst, src);
}

void Assembler::bsf(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xBC);
  emit_operand(dst, src);
}

void Assembler::hlt() {
  EnsureSpace ensure_space(this);
  EMIT(0xF4);
}

void Assembler::int3() {
  EnsureSpace ensure_space(this);
  EMIT(0xCC);
}

void Assembler::nop() {
  EnsureSpace ensure_space(this);
  EMIT(0x90);
}

void Assembler::ret(int imm16) {
  EnsureSpace ensure_space(this);
  DCHECK(is_uint16(imm16));
  if (imm16 == 0) {
    EMIT(0xC3);
  } else {
    EMIT(0xC2);
    EMIT(imm16 & 0xFF);
    EMIT((imm16 >> 8) & 0xFF);
  }
}

void Assembler::ud2() {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x0B);
}

// Labels refer to positions in the (to be) generated code.
// There are bound, linked, and unused labels.
//
// Bound labels refer to known positions in the already
// generated code. pos() is the position the label refers to.
//
// Linked labels refer to unknown positions in the code
// to be generated; pos() is the position of the 32bit
// Displacement of the last instruction using the label.

void Assembler::print(const Label* L) {
  if (L->is_unused()) {
    PrintF("unused label\n");
  } else if (L->is_bound()) {
    PrintF("bound label to %d\n", L->pos());
  } else if (L->is_linked()) {
    Label l;
    l.link_to(L->pos());
    PrintF("unbound label");
    while (l.is_linked()) {
      Displacement disp = disp_at(&l);
      PrintF("@ %d ", l.pos());
      disp.print();
      PrintF("\n");
      disp.next(&l);
    }
  } else {
    PrintF("label in inconsistent state (pos = %d)\n", L->pos_);
  }
}

void Assembler::bind_to(Label* L, int pos) {
  EnsureSpace ensure_space(this);
  DCHECK(0 <= pos && pos <= pc_offset());  // must have a valid binding position
  while (L->is_linked()) {
    Displacement disp = disp_at(L);
    int fixup_pos = L->pos();
    if (disp.type() == Displacement::CODE_ABSOLUTE) {
      long_at_put(fixup_pos, reinterpret_cast<int>(buffer_start_ + pos));
      internal_reference_positions_.push_back(fixup_pos);
    } else if (disp.type() == Displacement::CODE_RELATIVE) {
      // Relative to InstructionStream heap object pointer.
      long_at_put(fixup_pos,
                  pos + InstructionStream::kHeaderSize - kHeapObjectTag);
    } else {
      if (disp.type() == Displacement::UNCONDITIONAL_JUMP) {
        DCHECK_EQ(byte_at(fixup_pos - 1), 0xE9);  // jmp expected
      }
      // Relative address, relative to point after address.
      int imm32 = pos - (fixup_pos + sizeof(int32_t));
      long_at_put(fixup_pos, imm32);
    }
    disp.next(L);
  }
  while (L->is_near_linked()) {
    int fixup_pos = L->near_link_pos();
    int offset_to_next =
        static_cast<int>(*reinterpret_cast<int8_t*>(addr_at(fixup_pos)));
    DCHECK_LE(offset_to_next, 0);
    // Relative address, relative to point after address.
    int disp = pos - fixup_pos - sizeof(int8_t);
    CHECK(0 <= disp && disp <= 127);
    set_byte_at(fixup_pos, disp);
    if (offset_to_next < 0) {
      L->link_to(fixup_pos + offset_to_next, Label::kNear);
    } else {
      L->UnuseNear();
    }
  }

  // Optimization stage
  auto jump_opt = jump_optimization_info();
  if (jump_opt && jump_opt->is_optimizing()) {
    auto it = jump_opt->label_farjmp_maps.find(L);
    if (it != jump_opt->label_farjmp_maps.end()) {
      auto& pos_vector = it->second;
      for (auto fixup_pos : pos_vector) {
        int disp = pos - (fixup_pos + sizeof(int8_t));
        CHECK(is_int8(disp));
        set_byte_at(fixup_pos, disp);
      }
      jump_opt->label_farjmp_maps.erase(it);
    }
  }
  L->bind_to(pos);
}

void Assembler::bind(Label* L) {
  EnsureSpace ensure_space(this);
  DCHECK(!L->is_bound());  // label can only be bound once
  bind_to(L, pc_offset());
}

void Assembler::record_farjmp_position(Label* L, int pos) {
  auto& pos_vector = jump_optimization_info()->label_farjmp_maps[L];
  pos_vector.push_back(pos);
}

bool Assembler::is_optimizable_farjmp(int idx) {
  if (predictable_code_size()) return false;

  auto jump_opt = jump_optimization_info();
  CHECK(jump_opt->is_optimizing());

  auto& dict = jump_opt->may_optimizable_farjmp;
  if (dict.find(idx) != dict.end()) {
    auto record_jmp_info = dict[idx];

    int record_pos = record_jmp_info.pos;

    // 4 bytes for jmp rel32 operand.
    const int operand_size = 4;
    int record_dest = record_jmp_info.pos + record_jmp_info.opcode_size +
                      operand_size + record_jmp_info.distance;

    const int max_align_in_jmp_range =
        jump_opt->MaxAlignInRange(record_pos, record_dest);

    if (max_align_in_jmp_range == 0) {
      return true;
    }

    // ja rel32 -> ja rel8, the opcode size 2bytes -> 1byte
    // 0F 87 -> 77
    const int saved_opcode_size = record_jmp_info.opcode_size - 1;

    // jmp rel32 -> rel8, the operand size 4bytes -> 1byte
    constexpr int saved_operand_size = 4 - 1;

    // The shorter encoding may further decrease the base address of the
    // relative jump, while the jump target could stay in place because of
    // alignment.
    int cur_jmp_length_max_increase =
        (record_pos - pc_offset() + saved_opcode_size + saved_operand_size) %
        max_align_in_jmp_range;

    if (is_int8(record_jmp_info.distance + cur_jmp_length_max_increase)) {
      return true;
    }
  }
  return false;
}

void Assembler::call(Label* L) {
  EnsureSpace ensure_space(this);
  if (L->is_bound()) {
    const int long_size = 5;
    int offs = L->pos() - pc_offset();
    DCHECK_LE(offs, 0);
    // 1110 1000 #32-bit disp.
    EMIT(0xE8);
    emit(offs - long_size);
  } else {
    // 1110 1000 #32-bit disp.
    EMIT(0xE8);
    emit_disp(L, Displacement::OTHER);
  }
}

void Assembler::call(Address entry, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  EMIT(0xE8);
  emit(entry - (reinterpret_cast<Address>(pc_) + sizeof(int32_t)), rmode);
}

void Assembler::wasm_call(Address entry, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  EMIT(0xE8);
  emit(entry, rmode);
}

void Assembler::call(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xFF);
  emit_operand(edx, adr);
}

void Assembler::call(Handle<Code> code, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  EMIT(0xE8);
  emit(code, rmode);
}

void Assembler::jmp_rel(int offset) {
  EnsureSpace ensure_space(this);
  const int short_size = 2;
  const int long_size = 5;
  if (is_int8(offset - short_size) && !predictable_code_size()) {
    // 1110 1011 #8-bit disp.
    EMIT(0xEB);
    EMIT((offset - short_size) & 0xFF);
  } else {
    // 1110 1001 #32-bit disp.
    EMIT(0xE9);
    emit(offset - long_size);
  }
}

void Assembler::jmp(Label* L, Label::Distance distance) {
  if (L->is_bound()) {
    int offset = L->pos() - pc_offset();
    DCHECK_LE(offset, 0);  // backward jump.
    jmp_rel(offset);
    return;
  }

  EnsureSpace ensure_space(this);
  if (distance == Label::kNear) {
    EMIT(0xEB);
    emit_near_disp(L);
  } else {
    auto jump_opt = jump_optimization_info();
    if (V8_UNLIKELY(jump_opt)) {
      if (jump_opt->is_optimizing() &&
          is_optimizable_farjmp(jump_opt->farjmp_num++)) {
        EMIT(0xEB);
        record_farjmp_position(L, pc_offset());
        EMIT(0);
        return;
      }
      if (jump_opt->is_collecting()) {
        jump_opt->farjmps.push_back({pc_offset(), 1, 0});
      }
    }
    // 1110 1001 #32-bit disp.
    EMIT(0xE9);
    emit_disp(L, Displacement::UNCONDITIONAL_JUMP);
  }
}

void Assembler::jmp(Address entry, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  EMIT(0xE9);
  if (RelocInfo::IsWasmCall(rmode)) {
    emit(entry, rmode);
  } else {
    emit(entry - (reinterpret_cast<Address>(pc_) + sizeof(int32_t)), rmode);
  }
}

void Assembler::jmp(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xFF);
  emit_operand(esp, adr);
}

void Assembler::jmp(Handle<Code> code, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  EMIT(0xE9);
  emit(code, rmode);
}

void Assembler::j(Condition cc, Label* L, Label::Distance distance) {
  EnsureSpace ensure_space(this);
  DCHECK(0 <= cc && static_cast<int>(cc) < 16);
  if (L->is_bound()) {
    const int short_size = 2;
    const int long_size = 6;
    int offs = L->pos() - pc_offset();
    DCHECK_LE(offs, 0);
    if (is_int8(offs - short_size)) {
      // 0111 tttn #8-bit disp
      EMIT(0x70 | cc);
      EMIT((offs - short_size) & 0xFF);
    } else {
      // 0000 1111 1000 tttn #32-bit disp
      EMIT(0x0F);
      EMIT(0x80 | cc);
      emit(offs - long_size);
    }
  } else if (distance == Label::kNear) {
    EMIT(0x70 | cc);
    emit_near_disp(L);
  } else {
    auto jump_opt = jump_optimization_info();
    if (V8_UNLIKELY(jump_opt)) {
      if (jump_opt->is_optimizing() &&
          is_optimizable_farjmp(jump_opt->farjmp_num++)) {
        // 0111 tttn #8-bit disp
        EMIT(0x70 | cc);
        record_farjmp_position(L, pc_offset());
        EMIT(0);
        return;
      }
      if (jump_opt->is_collecting()) {
        jump_opt->farjmps.push_back({pc_offset(), 2, 0});
      }
    }
    // 0000 1111 1000 tttn #32-bit disp
    // Note: could eliminate cond. jumps to this jump if condition
    //       is the same however, seems to be rather unlikely case.
    EMIT(0x0F);
    EMIT(0x80 | cc);
    emit_disp(L, Displacement::OTHER);
  }
}

void Assembler::j(Condition cc, uint8_t* entry, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  DCHECK((0 <= cc) && (static_cast<int>(cc) < 16));
  // 0000 1111 1000 tttn #32-bit disp.
  EMIT(0x0F);
  EMIT(0x80 | cc);
  emit(entry - (pc_ + sizeof(int32_t)), rmode);
}

void Assembler::j(Condition cc, Handle<Code> code, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  // 0000 1111 1000 tttn #32-bit disp
  EMIT(0x0F);
  EMIT(0x80 | cc);
  emit(code, rmode);
}

// FPU instructions.

void Assembler::fld(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD9, 0xC0, i);
}

void Assembler::fstp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDD, 0xD8, i);
}

void Assembler::fld1() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xE8);
}

void Assembler::fldpi() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xEB);
}

void Assembler::fldz() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xEE);
}

void Assembler::fldln2() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xED);
}

void Assembler::fld_s(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  emit_operand(eax, adr);
}

void Assembler::fld_d(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDD);
  emit_operand(eax, adr);
}

void Assembler::fstp_s(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  emit_operand(ebx, adr);
}

void Assembler::fst_s(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  emit_operand(edx, adr);
}

void Assembler::fstp_d(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDD);
  emit_operand(ebx, adr);
}

void Assembler::fst_d(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDD);
  emit_operand(edx, adr);
}

void Assembler::fild_s(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDB);
  emit_operand(eax, adr);
}

void Assembler::fild_d(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDF);
  emit_operand(ebp, adr);
}

void Assembler::fistp_s(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDB);
  emit_operand(ebx, adr);
}

void Assembler::fisttp_s(Operand adr) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  EMIT(0xDB);
  emit_operand(ecx, adr);
}

void Assembler::fisttp_d(Operand adr) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  EMIT(0xDD);
  emit_operand(ecx, adr);
}

void Assembler::fist_s(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDB);
  emit_operand(edx, adr);
}

void Assembler::fistp_d(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDF);
  emit_operand(edi, adr);
}

void Assembler::fabs() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xE1);
}

void Assembler::fchs() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xE0);
}

void Assembler::fcos() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xFF);
}

void Assembler::fsin() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xFE);
}

void Assembler::fptan() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xF2);
}

void Assembler::fyl2x() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xF1);
}

void Assembler::f2xm1() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xF0);
}

void Assembler::fscale() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xFD);
}

void Assembler::fninit() {
  EnsureSpace ensure_space(this);
  EMIT(0xDB);
  EMIT(0xE3);
}

void Assembler::fadd(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xC0, i);
}

void Assembler::fadd_i(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD8, 0xC0, i);
}

void Assembler::fsub(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xE8, i);
}

void Assembler::fsub_i(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD8, 0xE0, i);
}

void Assembler::fisub_s(Operand adr) {
  EnsureSpace ensure_space(this);
  EMIT(0xDA);
  emit_operand(esp, adr);
}

void Assembler::fmul_i(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD8, 0xC8, i);
}

void Assembler::fmul(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xC8, i);
}

void Assembler::fdiv(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xF8, i);
}

void Assembler::fdiv_i(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD8, 0xF0, i);
}

void Assembler::faddp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xC0, i);
}

void Assembler::fsubp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xE8, i);
}

void Assembler::fsubrp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xE0, i);
}

void Assembler::fmulp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xC8, i);
}

void Assembler::fdivp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xF8, i);
}

void Assembler::fprem() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xF8);
}

void Assembler::fprem1() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xF5);
}

void Assembler::fxch(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD9, 0xC8, i);
}

void Assembler::fincstp() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xF7);
}

void Assembler::ffree(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDD, 0xC0, i);
}

void Assembler::ftst() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xE4);
}

void Assembler::fucomp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDD, 0xE8, i);
}

void Assembler::fucompp() {
  EnsureSpace ensure_space(this);
  EMIT(0xDA);
  EMIT(0xE9);
}

void Assembler::fucomi(int i) {
  EnsureSpace ensure_space(this);
  EMIT(0xDB);
  EMIT(0xE8 + i);
}

void Assembler::fucomip() {
  EnsureSpace ensure_space(this);
  EMIT(0xDF);
  EMIT(0xE9);
}

void Assembler::fcompp() {
  EnsureSpace ensure_space(this);
  EMIT(0xDE);
  EMIT(0xD9);
}

void Assembler::fnstsw_ax() {
  EnsureSpace ensure_space(this);
  EMIT(0xDF);
  EMIT(0xE0);
}

void Assembler::fwait() {
  EnsureSpace ensure_space(this);
  EMIT(0x9B);
}

void Assembler::frndint() {
  EnsureSpace ensure_space(this);
  EMIT(0xD9);
  EMIT(0xFC);
}

void Assembler::fnclex() {
  EnsureSpace ensure_space(this);
  EMIT(0xDB);
  EMIT(0xE2);
}

void Assembler::sahf() {
  EnsureSpace ensure_space(this);
  EMIT(0x9E);
}

void Assembler::setcc(Condition cc, Register reg) {
  DCHECK(reg.is_byte_register());
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x90 | cc);
  EMIT(0xC0 | reg.code());
}

void Assembler::cvttss2si(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  // The [src] might contain ebx's register code, but in
  // this case, it refers to xmm3, so it is OK to emit.
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x2C);
  emit_operand(dst, src);
}

void Assembler::cvttsd2si(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  // The [src] might contain ebx's register code, but in
  // this case, it refers to xmm3, so it is OK to emit.
  EMIT(0xF2);
  EMIT(0x0F);
  EMIT(0x2C);
  emit_operand(dst, src);
}

void Assembler::cvtsd2si(Register dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF2);
  EMIT(0x0F);
  EMIT(0x2D);
  emit_sse_operand(dst, src);
}

void Assembler::cvtsi2ss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtsi2sd(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF2);
  EMIT(0x0F);
  EMIT(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtss2sd(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x5A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtdq2pd(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0xE6);
  emit_sse_operand(dst, src);
}

void Assembler::cvtpd2ps(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x5A);
  emit_sse_operand(dst, src);
}

void Assembler::cvttps2dq(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x5B);
  emit_sse_operand(dst, src);
}

void Assembler::cvttpd2dq(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0xE6);
  emit_sse_operand(dst, src);
}

void Assembler::cmpps(XMMRegister dst, Operand src, uint8_t cmp) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xC2);
  emit_sse_operand(dst, src);
  EMIT(cmp);
}

void Assembler::cmppd(XMMRegister dst, Operand src, uint8_t cmp) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0xC2);
  emit_sse_operand(dst, src);
  EMIT(cmp);
}

void Assembler::haddps(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  EMIT(0xF2);
  EMIT(0x0F);
  EMIT(0x7C);
  emit_sse_operand(dst, src);
}

void Assembler::ucomisd(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::roundps(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x08);
  emit_sse_operand(dst, src);
  // Mask precision exeption.
  EMIT(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundpd(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x09);
  emit_sse_operand(dst, src);
  // Mask precision exeption.
  EMIT(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundss(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x0A);
  emit_sse_operand(dst, src);
  // Mask precision exeption.
  EMIT(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundsd(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x0B);
  emit_sse_operand(dst, src);
  // Mask precision exeption.
  EMIT(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::movmskpd(Register dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x50);
  emit_sse_operand(dst, src);
}

void Assembler::movmskps(Register dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x50);
  emit_sse_operand(dst, src);
}

void Assembler::pmovmskb(Register dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0xD7);
  emit_sse_operand(dst, src);
}

void Assembler::cmpltsd(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF2);
  EMIT(0x0F);
  EMIT(0xC2);
  emit_sse_operand(dst, src);
  EMIT(1);  // LT == 1
}

void Assembler::movaps(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x28);
  emit_sse_operand(dst, src);
}

void Assembler::movups(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x10);
  emit_sse_operand(dst, src);
}

void Assembler::movups(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x11);
  emit_sse_operand(src, dst);
}

void Assembler::movddup(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  EMIT(0xF2);
  EMIT(0x0F);
  EMIT(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movshdup(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x16);
  emit_sse_operand(dst, src);
}

void Assembler::shufps(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  DCHECK(is_uint8(imm8));
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0xC6);
  emit_sse_operand(dst, src);
  EMIT(imm8);
}

void Assembler::shufpd(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  DCHECK(is_uint8(imm8));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0xC6);
  emit_sse_operand(dst, src);
  EMIT(imm8);
}

void Assembler::movhlps(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movlhps(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x16);
  emit_sse_operand(dst, src);
}

void Assembler::movlps(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movlps(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x13);
  emit_sse_operand(src, dst);
}

void Assembler::movhps(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x16);
  emit_sse_operand(dst, src);
}

void Assembler::movhps(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x17);
  emit_sse_operand(src, dst);
}

void Assembler::movdqa(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::movdqa(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::movdqa(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::movdqu(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::movdqu(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::movdqu(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::prefetch(Operand src, int level) {
  DCHECK(is_uint2(level));
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x18);
  // Emit hint number in Reg position of RegR/M.
  XMMRegister code = XMMRegister::from_code(level);
  emit_sse_operand(code, src);
}

void Assembler::movsd(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF2);  // double
  EMIT(0x0F);
  EMIT(0x11);  // store
  emit_sse_operand(src, dst);
}

void Assembler::movsd(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF2);  // double
  EMIT(0x0F);
  EMIT(0x10);  // load
  emit_sse_operand(dst, src);
}

void Assembler::movss(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);  // float
  EMIT(0x0F);
  EMIT(0x11);  // store
  emit_sse_operand(src, dst);
}

void Assembler::movss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);  // float
  EMIT(0x0F);
  EMIT(0x10);  // load
  emit_sse_operand(dst, src);
}

void Assembler::movd(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::movd(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x7E);
  emit_sse_operand(src, dst);
}

void Assembler::extractps(Operand dst, XMMRegister src, uint8_t imm8) {
  DCHECK(IsEnabled(SSE4_1));
  DCHECK(is_uint8(imm8));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x17);
  emit_sse_operand(src, dst);
  EMIT(imm8);
}

void Assembler::extractps(Register dst, XMMRegister src, uint8_t imm8) {
  DCHECK(IsEnabled(SSE4_1));
  DCHECK(is_uint8(imm8));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x17);
  emit_sse_operand(src, dst);
  EMIT(imm8);
}

void Assembler::pcmpgtq(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(SSE4_2));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x38);
  EMIT(0x37);
  emit_sse_operand(dst, src);
}

void Assembler::psllw(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x71);
  emit_sse_operand(esi, reg);  // esi == 6
  EMIT(shift);
}

void Assembler::pslld(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x72);
  emit_sse_operand(esi, reg);  // esi == 6
  EMIT(shift);
}

void Assembler::psrlw(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x71);
  emit_sse_operand(edx, reg);  // edx == 2
  EMIT(shift);
}

void Assembler::psrld(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x72);
  emit_sse_operand(edx, reg);  // edx == 2
  EMIT(shift);
}

void Assembler::psraw(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x71);
  emit_sse_operand(esp, reg);  // esp == 4
  EMIT(shift);
}

void Assembler::psrad(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x72);
  emit_sse_operand(esp, reg);  // esp == 4
  EMIT(shift);
}

void Assembler::psllq(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x73);
  emit_sse_operand(esi, reg);  // esi == 6
  EMIT(shift);
}

void Assembler::psrlq(XMMRegister reg, uint8_t shift) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x73);
  emit_sse_operand(edx, reg);  // edx == 2
  EMIT(shift);
}

void Assembler::pshufhw(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x70);
  emit_sse_operand(dst, src);
  EMIT(shuffle);
}

void Assembler::pshuflw(XMMRegister dst, Operan
```