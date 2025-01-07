Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is part 2 of 4. The code is from `v8/src/codegen/x64/assembler-x64.cc`. I need to extract the core purpose of the functions defined in this part.

Based on the function names and the operations they perform (e.g., `shift`, `bswap`, `call`, `cmov`, `cmp`, `xadd`, `cmpxchg`, `mfence`, `lfence`, `cpuid`, `cqo`, `dec`, `idiv`, `div`, `imul`, `inc`, `int3`, `j`, `jmp`, `lea`, `load_rax`, `leave`, `mov`, `movsx`, `movzx`, `repmovs`, `mull`, `mulq`, `neg`, `nop`, `not`, `pop`, `push`), this part of the `Assembler` class seems to be responsible for emitting x64 machine code instructions.

Here's a breakdown of the functionality by groups of related instructions:

*   **Bit Manipulation:** `shift`, `bswap`, `btq`, `btsq`, `btrq`, `bsr`, `bsf`, `pblendw`, `palignr` - these functions manipulate bits within registers or memory.
*   **Control Flow:** `call`, `near_call`, `near_jmp`, `near_j`, `j`, `jmp` - these functions alter the program's execution flow.
*   **Flag Manipulation:** `clc`, `cld` - these functions clear specific processor flags.
*   **Data Movement (Conditional):** `cmovq`, `cmovl` - these functions move data based on the state of processor flags.
*   **Comparison:** `cmpb_al` - this function compares a byte with the AL register.
*   **Synchronization/Atomic Operations:** `lock`, `xadd`, `cmpxchg`, `mfence`, `lfence`, `cpuid` - these functions ensure atomic operations or provide memory ordering guarantees.
*   **Sign Extension:** `cdq`, `cqo`, `movsxbl`, `movsxbq`, `movsxwl`, `movsxwq`, `movsxlq` - these functions extend the sign of a value when moving it to a larger register.
*   **Arithmetic Operations:** `emit_dec`, `emit_idiv`, `emit_div`, `emit_imul`, `emit_inc`, `mull`, `mulq`, `neg` - these functions perform arithmetic operations.
*   **Logical Operations:** `emit_not` - this function performs a bitwise NOT operation.
*   **No Operation:** `nop` - this function does nothing, often used for padding or timing.
*   **Stack Manipulation:** `pushq`, `popq`, `popfq`, `leave` - these functions operate on the program stack.
*   **Data Movement:** `mov`, `lea`, `load_rax`, `emit_mov`, `emit_movzxb`, `emit_movzxw`, `repmovsb`, `repmovsw`, `emit_repmovs`, `repstosl`, `repstosq` - these functions move data between registers, memory, and immediate values.
*   **Special Instructions:** `hlt`, `endbr64`, `int3`, `emit_trace_instruction` - these are special purpose instructions.

Considering this is part 2 of 4, it's likely focused on a subset of the instruction set. The previous part probably deals with basic setup and the later parts with more complex instructions or utility functions.
这是 `v8/src/codegen/x64/assembler-x64.cc` 源代码的第二个部分，它主要负责实现 x64 汇编指令的生成功能。

**归纳一下它的功能：**

这个部分定义了 `Assembler` 类中用于生成各种 x64 汇编指令的方法。这些方法对应着不同的汇编指令操作，例如：

*   **位操作指令:**  例如 `shift`（移位）, `bswap`（字节序交换）, `btq`, `btsq`, `btrq`（位测试和修改）, `bsr`, `bsf`（位扫描）, `pblendw`, `palignr`（SSE4.1/SSSE3 混合和对齐）。
*   **控制流指令:** 例如 `call`（调用）, `near_call`, `near_jmp`, `near_j`（近跳转）, `j`（条件跳转）, `jmp`（无条件跳转）。
*   **标志位操作指令:** 例如 `clc`（清除进位标志）, `cld`（清除方向标志）。
*   **条件传送指令:** 例如 `cmovq`, `cmovl`（条件移动）。
*   **比较指令:** 例如 `cmpb_al`（比较 AL 寄存器）。
*   **原子操作指令:** 例如 `lock`（锁定）, `xadd`（交换并加法）, `cmpxchg`（比较并交换）。
*   **内存屏障指令:** 例如 `mfence`（内存栅栏）, `lfence`（轻量级内存栅栏）。
*   **CPU 信息指令:** 例如 `cpuid`（获取 CPU 信息）。
*   **符号扩展指令:** 例如 `cdq`（转换双字为四字）, `cqo`（转换四字为八字）, `movsxbl`, `movsxbq`, `movsxwl`, `movsxwq`, `movsxlq`（带符号扩展的移动）。
*   **算术运算指令:** 例如 `emit_dec`（递减）, `emit_idiv`（带符号除法）, `emit_div`（无符号除法）, `emit_imul`（带符号乘法）, `emit_inc`（递增）, `mull`, `mulq`（乘法）, `negb`, `negw`, `negl`, `negq`（取负数）。
*   **逻辑运算指令:** 例如 `emit_not`（按位取反）。
*   **空操作指令:** 例如 `nop`。
*   **堆栈操作指令:** 例如 `popq`（出栈）, `popfq`（出标志位栈）, `pushq`（入栈）。
*   **数据移动指令:** 例如 `movb`, `movw`, `emit_mov`（移动数据）, `emit_lea`（加载有效地址）, `load_rax`（加载到 RAX 寄存器）, `emit_movzxb`, `emit_movzxw`（零扩展移动）, `repmovsb`, `repmovsw`, `emit_repmovs`（重复移动字符串）, `repstosl`, `repstosq`（重复存储）。
*   **其他指令:** 例如 `hlt`（暂停）, `endbr64` (用于 Intel CET IBT 的间接分支终端), `int3`（断点指令）, `emit_trace_instruction`（用于跟踪指令）。

**如果 `v8/src/codegen/x64/assembler-x64.cc` 以 `.tq` 结尾，那它是个 v8 Torque 源代码。** 但实际上，以 `.cc` 结尾，表明它是 C++ 源代码。

**与 JavaScript 功能的关系：**

`assembler-x64.cc` 中生成的汇编指令是 V8 JavaScript 引擎执行 JavaScript 代码的基础。当 V8 编译 JavaScript 代码时，它会将 JavaScript 代码转换为机器码，而 `Assembler` 类就是用来生成这些机器码的。

**JavaScript 例子：**

例如，JavaScript 中的加法操作 `a + b`，在 V8 的编译过程中，可能会被翻译成如下的 x64 汇编指令（简化版本）：

```assembly
movq rax, [memory_location_of_a]  ; 将变量 a 的值加载到 rax 寄存器
addq rax, [memory_location_of_b]  ; 将变量 b 的值加到 rax 寄存器
movq [memory_location_of_result], rax ; 将 rax 寄存器中的结果存储到结果变量的内存位置
```

`assembler-x64.cc` 中的 `movq(Register dst, Operand src)` 和 `addq(Register dst, Operand src)` 等方法就负责生成类似的机器码。

**代码逻辑推理：**

假设输入以下代码片段：

```c++
Assembler a;
Register rax = rax;
Register rbx = rbx;
Immediate imm(10);

a.movq(rax, imm);      // 将立即数 10 移动到 rax 寄存器
a.addq(rax, rbx);      // 将 rbx 寄存器的值加到 rax 寄存器
```

**假设输入：**

*   `rbx` 寄存器的值在执行 `a.addq(rax, rbx)` 之前为 5。

**输出：**

生成的机器码将执行以下操作：

1. 将立即数 10 加载到 `rax` 寄存器。执行后，`rax` 的值为 10。
2. 将 `rbx` 寄存器的值（假设为 5）加到 `rax` 寄存器。执行后，`rax` 的值为 15。

**用户常见的编程错误：**

在直接编写汇编代码或使用类似 `Assembler` 的接口时，用户可能会犯以下错误：

*   **寄存器类型不匹配:**  例如，尝试将一个 64 位寄存器的值移动到一个 8 位寄存器，可能会导致数据截断或错误。
    ```c++
    // 错误示例：尝试将 64 位 rax 的值移动到 8 位 bl
    // 在实际的 Assembler 中，可能会有检查，但假设没有
    // a.movb(bl, rax); // 错误！
    ```
*   **操作数类型错误:** 例如，某些指令只能接受寄存器作为操作数，而用户提供了内存地址。
*   **立即数大小超出范围:** 某些指令的立即数有大小限制。
    ```c++
    // 错误示例：某些指令可能不支持这么大的立即数
    // Immediate large_imm(0xFFFFFFFFFFFFFFFF);
    // a.movq(rax, large_imm); // 可能报错
    ```
*   **不理解指令的副作用:** 某些指令会修改标志位或其他寄存器的值，如果用户没有考虑到这些副作用，可能会导致程序逻辑错误。
*   **栈操作不平衡:**  `push` 和 `pop` 指令必须成对使用，否则会导致栈指针错误，最终导致程序崩溃。

总而言之，这个部分的 `assembler-x64.cc` 代码是 V8 引擎的核心组成部分，它提供了生成底层机器码的能力，使得 V8 能够执行 JavaScript 代码。 它涵盖了 x64 架构中大量的基本指令，为构建更高级的编译器功能提供了基础。

Prompt: 
```
这是目录为v8/src/codegen/x64/assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
s not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(dst);
  }
  DCHECK(is_int8(src.value_) || is_uint8(src.value_));
  if (dst == rax) {
    emit(0x04 | (subcode << 3));
    emit(src.value_);
  } else {
    emit(0x80);
    emit_modrm(subcode, dst);
    emit(src.value_);
  }
}

void Assembler::shift(Register dst, Immediate shift_amount, int subcode,
                      int size) {
  EnsureSpace ensure_space(this);
  DCHECK(size == kInt64Size ? is_uint6(shift_amount.value_)
                            : is_uint5(shift_amount.value_));
  if (shift_amount.value_ == 1) {
    emit_rex(dst, size);
    emit(0xD1);
    emit_modrm(subcode, dst);
  } else {
    emit_rex(dst, size);
    emit(0xC1);
    emit_modrm(subcode, dst);
    emit(shift_amount.value_);
  }
}

void Assembler::shift(Operand dst, Immediate shift_amount, int subcode,
                      int size) {
  EnsureSpace ensure_space(this);
  DCHECK(size == kInt64Size ? is_uint6(shift_amount.value_)
                            : is_uint5(shift_amount.value_));
  if (shift_amount.value_ == 1) {
    emit_rex(dst, size);
    emit(0xD1);
    emit_operand(subcode, dst);
  } else {
    emit_rex(dst, size);
    emit(0xC1);
    emit_operand(subcode, dst);
    emit(shift_amount.value_);
  }
}

void Assembler::shift(Register dst, int subcode, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xD3);
  emit_modrm(subcode, dst);
}

void Assembler::shift(Operand dst, int subcode, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xD3);
  emit_operand(subcode, dst);
}

void Assembler::bswapl(Register dst) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst);
  emit(0x0F);
  emit(0xC8 + dst.low_bits());
}

void Assembler::bswapq(Register dst) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst);
  emit(0x0F);
  emit(0xC8 + dst.low_bits());
}

void Assembler::btq(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0xA3);
  emit_operand(src, dst);
}

void Assembler::btsq(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0xAB);
  emit_operand(src, dst);
}

void Assembler::btsq(Register dst, Immediate imm8) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst);
  emit(0x0F);
  emit(0xBA);
  emit_modrm(0x5, dst);
  emit(imm8.value_);
}

void Assembler::btrq(Register dst, Immediate imm8) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst);
  emit(0x0F);
  emit(0xBA);
  emit_modrm(0x6, dst);
  emit(imm8.value_);
}

void Assembler::bsrl(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_modrm(dst, src);
}

void Assembler::bsrl(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_operand(dst, src);
}

void Assembler::bsrq(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_modrm(dst, src);
}

void Assembler::bsrq(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_operand(dst, src);
}

void Assembler::bsfl(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_modrm(dst, src);
}

void Assembler::bsfl(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_operand(dst, src);
}

void Assembler::bsfq(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_modrm(dst, src);
}

void Assembler::bsfq(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_operand(dst, src);
}

void Assembler::pblendw(XMMRegister dst, Operand src, uint8_t mask) {
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0E);
  emit(mask);
}

void Assembler::pblendw(XMMRegister dst, XMMRegister src, uint8_t mask) {
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0E);
  emit(mask);
}

void Assembler::palignr(XMMRegister dst, Operand src, uint8_t mask) {
  ssse3_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0F);
  emit(mask);
}

void Assembler::palignr(XMMRegister dst, XMMRegister src, uint8_t mask) {
  ssse3_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0F);
  emit(mask);
}

void Assembler::call(Label* L) {
  EnsureSpace ensure_space(this);
  // 1110 1000 #32-bit disp.
  emit(0xE8);
  if (L->is_bound()) {
    int offset = L->pos() - pc_offset() - sizeof(int32_t);
    DCHECK_LE(offset, 0);
    emitl(offset);
  } else if (L->is_linked()) {
    emitl(L->pos());
    L->link_to(pc_offset() - sizeof(int32_t));
  } else {
    DCHECK(L->is_unused());
    int32_t current = pc_offset();
    emitl(current);
    L->link_to(current);
  }
}

void Assembler::call(Handle<Code> target, RelocInfo::Mode rmode) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  EnsureSpace ensure_space(this);
  // 1110 1000 #32-bit disp.
  emit(0xE8);
  RecordRelocInfo(rmode);
  int code_target_index = AddCodeTarget(target);
  emitl(code_target_index);
}

void Assembler::near_call(intptr_t disp, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  // 1110 1000 #32-bit disp.
  emit(0xE8);
  DCHECK(is_int32(disp));
  RecordRelocInfo(rmode);
  emitl(static_cast<int32_t>(disp));
}

void Assembler::near_jmp(intptr_t disp, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  // 1110 1001 #32-bit disp.
  emit(0xE9);
  DCHECK(is_int32(disp));
  if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode);
  emitl(static_cast<int32_t>(disp));
}

void Assembler::near_j(Condition cc, intptr_t disp, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  // 0000 1111 1000 tttn #32-bit disp.
  emit(0x0F);
  emit(0x80 | cc);
  DCHECK(is_int32(disp));
  if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode);
  emitl(static_cast<int32_t>(disp));
}

void Assembler::call(Register adr) {
  EnsureSpace ensure_space(this);
  // Opcode: FF /2 r64.
  emit_optional_rex_32(adr);
  emit(0xFF);
  emit_modrm(0x2, adr);
}

void Assembler::call(Operand op) {
  EnsureSpace ensure_space(this);
  // Opcode: FF /2 m64.
  emit_optional_rex_32(op);
  emit(0xFF);
  emit_operand(0x2, op);
}

void Assembler::clc() {
  EnsureSpace ensure_space(this);
  emit(0xF8);
}

void Assembler::cld() {
  EnsureSpace ensure_space(this);
  emit(0xFC);
}

void Assembler::cdq() {
  EnsureSpace ensure_space(this);
  emit(0x99);
}

void Assembler::cmovq(Condition cc, Register dst, Register src) {
  EnsureSpace ensure_space(this);
  // Opcode: REX.W 0f 40 + cc /r.
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x40 + cc);
  emit_modrm(dst, src);
}

void Assembler::cmovq(Condition cc, Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  // Opcode: REX.W 0f 40 + cc /r.
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x40 + cc);
  emit_operand(dst, src);
}

void Assembler::cmovl(Condition cc, Register dst, Register src) {
  EnsureSpace ensure_space(this);
  // Opcode: 0f 40 + cc /r.
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x40 + cc);
  emit_modrm(dst, src);
}

void Assembler::cmovl(Condition cc, Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  // Opcode: 0f 40 + cc /r.
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x40 + cc);
  emit_operand(dst, src);
}

void Assembler::cmpb_al(Immediate imm8) {
  DCHECK(is_int8(imm8.value_) || is_uint8(imm8.value_));
  EnsureSpace ensure_space(this);
  emit(0x3C);
  emit(imm8.value_);
}

void Assembler::lock() {
  EnsureSpace ensure_space(this);
  emit(0xF0);
}

void Assembler::xaddb(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_8(src, dst);
  emit(0x0F);
  emit(0xC0);
  emit_operand(src, dst);
}

void Assembler::xaddw(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0xC1);
  emit_operand(src, dst);
}

void Assembler::xaddl(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0xC1);
  emit_operand(src, dst);
}

void Assembler::xaddq(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex(src, dst, kInt64Size);
  emit(0x0F);
  emit(0xC1);
  emit_operand(src, dst);
}

void Assembler::cmpxchgb(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  if (!src.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(src, dst);
  } else {
    emit_optional_rex_32(src, dst);
  }
  emit(0x0F);
  emit(0xB0);
  emit_operand(src, dst);
}

void Assembler::cmpxchgw(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0xB1);
  emit_operand(src, dst);
}

void Assembler::emit_cmpxchg(Operand dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(src, dst, size);
  emit(0x0F);
  emit(0xB1);
  emit_operand(src, dst);
}

void Assembler::mfence() {
  EnsureSpace ensure_space(this);
  emit(0x0F);
  emit(0xAE);
  emit(0xF0);
}

void Assembler::lfence() {
  EnsureSpace ensure_space(this);
  emit(0x0F);
  emit(0xAE);
  emit(0xE8);
}

void Assembler::cpuid() {
  EnsureSpace ensure_space(this);
  emit(0x0F);
  emit(0xA2);
}

void Assembler::cqo() {
  EnsureSpace ensure_space(this);
  emit_rex_64();
  emit(0x99);
}

void Assembler::emit_dec(Register dst, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xFF);
  emit_modrm(0x1, dst);
}

void Assembler::emit_dec(Operand dst, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xFF);
  emit_operand(1, dst);
}

void Assembler::decb(Register dst) {
  EnsureSpace ensure_space(this);
  if (!dst.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(dst);
  }
  emit(0xFE);
  emit_modrm(0x1, dst);
}

void Assembler::decb(Operand dst) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst);
  emit(0xFE);
  emit_operand(1, dst);
}

void Assembler::hlt() {
  EnsureSpace ensure_space(this);
  emit(0xF4);
}

void Assembler::endbr64() {
#ifdef V8_ENABLE_CET_IBT
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit(0x0f);
  emit(0x1e);
  emit(0xfa);
#endif
}

void Assembler::emit_idiv(Register src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(src, size);
  emit(0xF7);
  emit_modrm(0x7, src);
}

void Assembler::emit_div(Register src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(src, size);
  emit(0xF7);
  emit_modrm(0x6, src);
}

void Assembler::emit_imul(Register src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(src, size);
  emit(0xF7);
  emit_modrm(0x5, src);
}

void Assembler::emit_imul(Operand src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(src, size);
  emit(0xF7);
  emit_operand(0x5, src);
}

void Assembler::emit_imul(Register dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, src, size);
  emit(0x0F);
  emit(0xAF);
  emit_modrm(dst, src);
}

void Assembler::emit_imul(Register dst, Operand src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, src, size);
  emit(0x0F);
  emit(0xAF);
  emit_operand(dst, src);
}

void Assembler::emit_imul(Register dst, Register src, Immediate imm, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, src, size);
  if (is_int8(imm.value_)) {
    emit(0x6B);
    emit_modrm(dst, src);
    emit(imm.value_);
  } else {
    emit(0x69);
    emit_modrm(dst, src);
    emitl(imm.value_);
  }
}

void Assembler::emit_imul(Register dst, Operand src, Immediate imm, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, src, size);
  if (is_int8(imm.value_)) {
    emit(0x6B);
    emit_operand(dst, src);
    emit(imm.value_);
  } else {
    emit(0x69);
    emit_operand(dst, src);
    emitl(imm.value_);
  }
}

void Assembler::emit_inc(Register dst, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xFF);
  emit_modrm(0x0, dst);
}

void Assembler::emit_inc(Operand dst, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xFF);
  emit_operand(0, dst);
}

void Assembler::int3() {
  EnsureSpace ensure_space(this);
  emit(0xCC);
}

void Assembler::j(Condition cc, Label* L, Label::Distance distance) {
  EnsureSpace ensure_space(this);
  DCHECK(is_uint4(cc));
  if (L->is_bound()) {
    const int short_size = 2;
    const int long_size = 6;
    int offs = L->pos() - pc_offset();
    DCHECK_LE(offs, 0);
    // Determine whether we can use 1-byte offsets for backwards branches,
    // which have a max range of 128 bytes.

    // We also need to check predictable_code_size() flag here, because on x64,
    // when the full code generator recompiles code for debugging, some places
    // need to be padded out to a certain size. The debugger is keeping track of
    // how often it did this so that it can adjust return addresses on the
    // stack, but if the size of jump instructions can also change, that's not
    // enough and the calculated offsets would be incorrect.
    if (is_int8(offs - short_size) && !predictable_code_size()) {
      // 0111 tttn #8-bit disp.
      emit(0x70 | cc);
      emit((offs - short_size) & 0xFF);
    } else {
      // 0000 1111 1000 tttn #32-bit disp.
      emit(0x0F);
      emit(0x80 | cc);
      emitl(offs - long_size);
    }
  } else if (distance == Label::kNear) {
    // 0111 tttn #8-bit disp
    emit(0x70 | cc);
    uint8_t disp = 0x00;
    if (L->is_near_linked()) {
      int offset = L->near_link_pos() - pc_offset();
      DCHECK(is_int8(offset));
      disp = static_cast<uint8_t>(offset & 0xFF);
    }
    L->link_to(pc_offset(), Label::kNear);
    emit(disp);
  } else {
    auto jump_opt = jump_optimization_info();
    if (V8_UNLIKELY(jump_opt)) {
      if (jump_opt->is_optimizing() &&
          is_optimizable_farjmp(jump_opt->farjmp_num++)) {
        // 0111 tttn #8-bit disp
        emit(0x70 | cc);
        record_farjmp_position(L, pc_offset());
        emit(0);
        return;
      }
      if (jump_opt->is_collecting()) {
        jump_opt->farjmps.push_back({pc_offset(), 2, 0});
      }
    }
    if (L->is_linked()) {
      // 0000 1111 1000 tttn #32-bit disp.
      emit(0x0F);
      emit(0x80 | cc);
      emitl(L->pos());
      L->link_to(pc_offset() - sizeof(int32_t));
    } else {
      // If this fires a near label is reused for a far jump, missing an
      // optimization opportunity.
      DCHECK(!L->is_near_linked());
      DCHECK(L->is_unused());
      emit(0x0F);
      emit(0x80 | cc);
      int32_t current = pc_offset();
      emitl(current);
      L->link_to(current);
    }
  }
}

void Assembler::j(Condition cc, Address entry, RelocInfo::Mode rmode) {
  DCHECK(RelocInfo::IsWasmStubCall(rmode));
  EnsureSpace ensure_space(this);
  DCHECK(is_uint4(cc));
  emit(0x0F);
  emit(0x80 | cc);
  RecordRelocInfo(rmode);
  emitl(static_cast<int32_t>(entry));
}

void Assembler::j(Condition cc, Handle<Code> target, RelocInfo::Mode rmode) {
  EnsureSpace ensure_space(this);
  DCHECK(is_uint4(cc));
  // 0000 1111 1000 tttn #32-bit disp.
  emit(0x0F);
  emit(0x80 | cc);
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  RecordRelocInfo(rmode);
  int code_target_index = AddCodeTarget(target);
  emitl(code_target_index);
}

void Assembler::jmp_rel(int32_t offset) {
  EnsureSpace ensure_space(this);
  // The offset is encoded relative to the next instruction.
  constexpr int32_t kShortJmpDisplacement = 1 + sizeof(int8_t);
  constexpr int32_t kNearJmpDisplacement = 1 + sizeof(int32_t);
  DCHECK_LE(std::numeric_limits<int32_t>::min() + kNearJmpDisplacement, offset);
  if (is_int8(offset - kShortJmpDisplacement) && !predictable_code_size()) {
    // 0xEB #8-bit disp.
    emit(0xEB);
    emit(offset - kShortJmpDisplacement);
  } else {
    // 0xE9 #32-bit disp.
    emit(0xE9);
    emitl(offset - kNearJmpDisplacement);
  }
}

void Assembler::jmp(Label* L, Label::Distance distance) {
  const int long_size = sizeof(int32_t);

  if (L->is_bound()) {
    int offset = L->pos() - pc_offset();
    DCHECK_LE(offset, 0);  // backward jump.
    jmp_rel(offset);
    return;
  }

  EnsureSpace ensure_space(this);
  if (distance == Label::kNear) {
    emit(0xEB);
    uint8_t disp = 0x00;
    if (L->is_near_linked()) {
      int offset = L->near_link_pos() - pc_offset();
      DCHECK(is_int8(offset));
      disp = static_cast<uint8_t>(offset & 0xFF);
    }
    L->link_to(pc_offset(), Label::kNear);
    emit(disp);
  } else {
    auto jump_opt = jump_optimization_info();
    if (V8_UNLIKELY(jump_opt)) {
      if (jump_opt->is_optimizing() &&
          is_optimizable_farjmp(jump_opt->farjmp_num++)) {
        emit(0xEB);
        record_farjmp_position(L, pc_offset());
        emit(0);
        return;
      }
      if (jump_opt->is_collecting()) {
        jump_opt->farjmps.push_back({pc_offset(), 1, 0});
      }
    }
    if (L->is_linked()) {
      // 1110 1001 #32-bit disp.
      emit(0xE9);
      emitl(L->pos());
      L->link_to(pc_offset() - long_size);
    } else {
      // 1110 1001 #32-bit disp.
      // If this fires a near label is reused for a far jump, missing an
      // optimization opportunity.
      DCHECK(!L->is_near_linked());
      DCHECK(L->is_unused());
      emit(0xE9);
      int32_t current = pc_offset();
      emitl(current);
      L->link_to(current);
    }
  }
}

void Assembler::jmp(Handle<Code> target, RelocInfo::Mode rmode) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  EnsureSpace ensure_space(this);
  // 1110 1001 #32-bit disp.
  emit(0xE9);
  RecordRelocInfo(rmode);
  int code_target_index = AddCodeTarget(target);
  emitl(code_target_index);
}

void Assembler::jmp(Register target, bool notrack) {
  EnsureSpace ensure_space(this);
#ifdef V8_ENABLE_CET_IBT
  // The notrack prefix is only useful if we compile with IBT support.
  if (notrack) {
    emit(0x3e);
  }
#endif
  // Opcode FF/4 r64.
  emit_optional_rex_32(target);
  emit(0xFF);
  emit_modrm(0x4, target);
}

void Assembler::jmp(Operand src, bool notrack) {
  EnsureSpace ensure_space(this);
#ifdef V8_ENABLE_CET_IBT
  // The notrack prefix is only useful if we compile with IBT support.
  if (notrack) {
    emit(0x3e);
  }
#endif
  // Opcode FF/4 m64.
  emit_optional_rex_32(src);
  emit(0xFF);
  emit_operand(0x4, src);
}

void Assembler::emit_lea(Register dst, Operand src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, src, size);
  emit(0x8D);
  emit_operand(dst, src);
}

void Assembler::load_rax(Address value, RelocInfo::Mode mode) {
  EnsureSpace ensure_space(this);
  emit(0x48);  // REX.W
  emit(0xA1);
  emit(Immediate64(value, mode));
}

void Assembler::load_rax(ExternalReference ref) {
  load_rax(ref.address(), RelocInfo::EXTERNAL_REFERENCE);
}

void Assembler::leave() {
  EnsureSpace ensure_space(this);
  emit(0xC9);
}

void Assembler::movb(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  if (!dst.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(dst, src);
  } else {
    emit_optional_rex_32(dst, src);
  }
  emit(0x8A);
  emit_operand(dst, src);
}

void Assembler::movb(Register dst, Immediate imm) {
  EnsureSpace ensure_space(this);
  if (!dst.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(dst);
  }
  emit(0xB0 + dst.low_bits());
  emit(imm.value_);
}

void Assembler::movb(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  if (!src.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(src, dst);
  } else {
    emit_optional_rex_32(src, dst);
  }
  emit(0x88);
  emit_operand(src, dst);
}

void Assembler::movb(Operand dst, Immediate imm) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst);
  emit(0xC6);
  emit_operand(0x0, dst);
  emit(static_cast<uint8_t>(imm.value_));
}

void Assembler::movw(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x8B);
  emit_operand(dst, src);
}

void Assembler::movw(Operand dst, Register src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(src, dst);
  emit(0x89);
  emit_operand(src, dst);
}

void Assembler::movw(Operand dst, Immediate imm) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst);
  emit(0xC7);
  emit_operand(0x0, dst);
  emit(static_cast<uint8_t>(imm.value_ & 0xFF));
  emit(static_cast<uint8_t>(imm.value_ >> 8));
}

void Assembler::emit_mov(Register dst, Operand src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, src, size);
  emit(0x8B);
  emit_operand(dst, src);
}

void Assembler::emit_mov(Register dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  if (src.low_bits() == 4) {
    emit_rex(src, dst, size);
    emit(0x89);
    emit_modrm(src, dst);
  } else {
    emit_rex(dst, src, size);
    emit(0x8B);
    emit_modrm(dst, src);
  }

#if defined(V8_OS_WIN_X64)
  if (xdata_encoder_ && dst == rbp && src == rsp) {
    xdata_encoder_->onMovRbpRsp();
  }
#endif
}

void Assembler::emit_mov(Operand dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(src, dst, size);
  emit(0x89);
  emit_operand(src, dst);
}

void Assembler::emit_mov(Register dst, Immediate value, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  if (size == kInt64Size) {
    emit(0xC7);
    emit_modrm(0x0, dst);
  } else {
    DCHECK_EQ(size, kInt32Size);
    emit(0xB8 + dst.low_bits());
  }
  emit(value);
}

void Assembler::emit_mov(Operand dst, Immediate value, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xC7);
  emit_operand(0x0, dst);
  emit(value);
}

void Assembler::emit_mov(Register dst, Immediate64 value, int size) {
  DCHECK_EQ(size, kInt64Size);
  if (constpool_.TryRecordEntry(value.value_, value.rmode_)) {
    // Emit rip-relative move with offset = 0
    Label label;
    emit_mov(dst, Operand(&label, 0), size);
    bind(&label);
  } else {
    EnsureSpace ensure_space(this);
    emit_rex(dst, size);
    emit(0xB8 | dst.low_bits());
    emit(value);
  }
}

void Assembler::movq_imm64(Register dst, int64_t value) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, kInt64Size);
  emit(0xB8 | dst.low_bits());
  emitq(static_cast<uint64_t>(value));
}

void Assembler::movq_heap_number(Register dst, double value) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, kInt64Size);
  emit(0xB8 | dst.low_bits());
  RequestHeapNumber(HeapNumberRequest(value));
  emit(Immediate64(kNullAddress, RelocInfo::FULL_EMBEDDED_OBJECT));
}

// Loads the ip-relative location of the src label into the target location
// (as a 32-bit offset sign extended to 64-bit).
void Assembler::movl(Operand dst, Label* src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst);
  emit(0xC7);
  emit_operand(0, dst);
  if (src->is_bound()) {
    int offset = src->pos() - pc_offset() - sizeof(int32_t);
    DCHECK_LE(offset, 0);
    emitl(offset);
  } else if (src->is_linked()) {
    emitl(src->pos());
    src->link_to(pc_offset() - sizeof(int32_t));
  } else {
    DCHECK(src->is_unused());
    int32_t current = pc_offset();
    emitl(current);
    src->link_to(current);
  }
}

void Assembler::movsxbl(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  if (!src.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(dst, src);
  } else {
    emit_optional_rex_32(dst, src);
  }
  emit(0x0F);
  emit(0xBE);
  emit_modrm(dst, src);
}

void Assembler::movsxbl(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBE);
  emit_operand(dst, src);
}

void Assembler::movsxbq(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBE);
  emit_operand(dst, src);
}

void Assembler::movsxbq(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBE);
  emit_modrm(dst, src);
}

void Assembler::movsxwl(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBF);
  emit_modrm(dst, src);
}

void Assembler::movsxwl(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBF);
  emit_operand(dst, src);
}

void Assembler::movsxwq(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBF);
  emit_operand(dst, src);
}

void Assembler::movsxwq(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBF);
  emit_modrm(dst, src);
}

void Assembler::movsxlq(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x63);
  emit_modrm(dst, src);
}

void Assembler::movsxlq(Register dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(dst, src);
  emit(0x63);
  emit_operand(dst, src);
}

void Assembler::emit_movzxb(Register dst, Operand src, int size) {
  EnsureSpace ensure_space(this);
  // 32 bit operations zero the top 32 bits of 64 bit registers.  Therefore
  // there is no need to make this a 64 bit operation.
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xB6);
  emit_operand(dst, src);
}

void Assembler::emit_movzxb(Register dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  // 32 bit operations zero the top 32 bits of 64 bit registers.  Therefore
  // there is no need to make this a 64 bit operation.
  if (!src.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(dst, src);
  } else {
    emit_optional_rex_32(dst, src);
  }
  emit(0x0F);
  emit(0xB6);
  emit_modrm(dst, src);
}

void Assembler::emit_movzxw(Register dst, Operand src, int size) {
  EnsureSpace ensure_space(this);
  // 32 bit operations zero the top 32 bits of 64 bit registers.  Therefore
  // there is no need to make this a 64 bit operation.
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xB7);
  emit_operand(dst, src);
}

void Assembler::emit_movzxw(Register dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  // 32 bit operations zero the top 32 bits of 64 bit registers.  Therefore
  // there is no need to make this a 64 bit operation.
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xB7);
  emit_modrm(dst, src);
}

void Assembler::repmovsb() {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit(0xA4);
}

void Assembler::repmovsw() {
  EnsureSpace ensure_space(this);
  emit(0x66);  // Operand size override.
  emit(0xF3);
  emit(0xA4);
}

void Assembler::emit_repmovs(int size) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex(size);
  emit(0xA5);
}

void Assembler::repstosl() {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit(0xAB);
}

void Assembler::repstosq() {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64();
  emit(0xAB);
}

void Assembler::mull(Register src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(src);
  emit(0xF7);
  emit_modrm(0x4, src);
}

void Assembler::mull(Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(src);
  emit(0xF7);
  emit_operand(0x4, src);
}

void Assembler::mulq(Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(src);
  emit(0xF7);
  emit_modrm(0x4, src);
}

void Assembler::mulq(Operand src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(src);
  emit(0xF7);
  emit_operand(0x4, src);
}

void Assembler::negb(Register reg) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_8(reg);
  emit(0xF6);
  emit_modrm(0x3, reg);
}

void Assembler::negw(Register reg) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(reg);
  emit(0xF7);
  emit_modrm(0x3, reg);
}

void Assembler::negl(Register reg) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(reg);
  emit(0xF7);
  emit_modrm(0x3, reg);
}

void Assembler::negq(Register reg) {
  EnsureSpace ensure_space(this);
  emit_rex_64(reg);
  emit(0xF7);
  emit_modrm(0x3, reg);
}

void Assembler::negb(Operand op) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(op);
  emit(0xF6);
  emit_operand(0x3, op);
}

void Assembler::negw(Operand op) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(op);
  emit(0xF7);
  emit_operand(0x3, op);
}

void Assembler::negl(Operand op) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(op);
  emit(0xF7);
  emit_operand(0x3, op);
}

void Assembler::negq(Operand op) {
  EnsureSpace ensure_space(this);
  emit_rex_64(op);
  emit(0xF7);
  emit_operand(0x3, op);
}

void Assembler::nop() {
  EnsureSpace ensure_space(this);
  emit(0x90);
}

void Assembler::emit_not(Register dst, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xF7);
  emit_modrm(0x2, dst);
}

void Assembler::emit_not(Operand dst, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, size);
  emit(0xF7);
  emit_operand(2, dst);
}

void Assembler::Nop(int n) {
  DCHECK_LE(0, n);
  // The recommended muti-byte sequences of NOP instructions from the Intel 64
  // and IA-32 Architectures Software Developer's Manual.
  //
  // Len Assembly                                    Byte Sequence
  // 2   66 NOP                                      66 90H
  // 3   NOP DWORD ptr [EAX]                         0F 1F 00H
  // 4   NOP DWORD ptr [EAX + 00H]                   0F 1F 40 00H
  // 5   NOP DWORD ptr [EAX + EAX*1 + 00H]           0F 1F 44 00 00H
  // 6   66 NOP DWORD ptr [EAX + EAX*1 + 00H]        66 0F 1F 44 00 00H
  // 7   NOP DWORD ptr [EAX + 00000000H]             0F 1F 80 00 00 00 00H
  // 8   NOP DWORD ptr [EAX + EAX*1 + 00000000H]     0F 1F 84 00 00 00 00 00H
  // 9   66 NOP DWORD ptr [EAX + EAX*1 + 00000000H]  66 0F 1F 84 00 00 00 00 00H

  constexpr const char* kNopSequences =
      "\x66\x90"                               // length 1 (@1) / 2 (@0)
      "\x0F\x1F\x00"                           // length 3 (@2)
      "\x0F\x1F\x40\x00"                       // length 4 (@5)
      "\x66\x0F\x1F\x44\x00\x00"               // length 5 (@10) / 6 (@9)
      "\x0F\x1F\x80\x00\x00\x00\x00"           // length 7 (@15)
      "\x66\x0F\x1F\x84\x00\x00\x00\x00\x00";  // length 8 (@23) / 9 (@22)
  constexpr int8_t kNopOffsets[10] = {0, 1, 0, 2, 5, 10, 9, 15, 23, 22};

  do {
    EnsureSpace ensure_space(this);
    int nop_bytes = std::min(n, 9);
    const char* sequence = kNopSequences + kNopOffsets[nop_bytes];
    memcpy(pc_, sequence, nop_bytes);
    pc_ += nop_bytes;
    n -= nop_bytes;
  } while (n);
}

void Assembler::emit_trace_instruction(Immediate markid) {
  EnsureSpace ensure_space(this);
  if (v8_flags.wasm_trace_native != nullptr &&
      !strcmp(v8_flags.wasm_trace_native, "cpuid")) {
    // This is the optionally selected cpuid sequence which computes a magic
    // number based upon the markid. The low 16 bits of the magic number are
    // 0x4711 and the high 16 bits are the low 16 bits of the markid. This
    // magic number gets moved into the eax register.
    uint32_t magic_num = 0x4711 | (static_cast<uint32_t>(markid.value_) << 16);

    pushq(rax);
    pushq(rbx);
    pushq(rcx);
    pushq(rdx);
    movl(rax, Immediate(magic_num));
    cpuid();
    popq(rdx);
    popq(rcx);
    popq(rbx);
    popq(rax);
  } else {
    // This is the default triple-nop sequence, an sscmark. The markid is moved
    // into the ebx register and then the triple-nop sequence is executed. The
    // three nops are prefixed by prefix.64 and prefix.67. The entire sequence
    // becomes "prefix.64 prefix.67 nop nop nop".
    pushq(rbx);
    movl(rbx, markid);
    emit(0x64);
    emit(0x67);
    nop();
    nop();
    nop();
    popq(rbx);
  }
}

void Assembler::popq(Register dst) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst);
  emit(0x58 | dst.low_bits());
}

void Assembler::popq(Operand dst) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst);
  emit(0x8F);
  emit_operand(0, dst);
}

void Assembler::popfq() {
  EnsureSpace ensure_space(this);
  emit(0x9D);
}

void Assembler::pushq(Register src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(src);
  emit(0x50 | src.low_bits());

#if defined(V8_OS_WIN_X64)
  if (xdata_encoder_ && src == rbp) {
    xdata_encoder_->onPushRbp();
  }
#endif
}
"""


```