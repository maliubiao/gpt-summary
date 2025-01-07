Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/ppc/assembler-ppc.cc`.

Here's a breakdown of the request and how to approach it:

1. **Identify the core purpose:** The filename and code structure clearly indicate this is an assembler implementation for the PowerPC architecture within the V8 JavaScript engine. Assemblers are responsible for translating assembly instructions into machine code.

2. **Analyze the code blocks:**  Group the functions based on their operations. The code is organized around common assembly instructions (load, store, arithmetic, logical, floating-point, etc.).

3. **Infer functionality from instruction names:**  Familiarity with assembly language is crucial here. Function names like `stw`, `ld`, `add`, `mul`, `fadd`, `fmul` directly correspond to PowerPC instructions for storing words, loading, addition, multiplication, floating-point addition, and floating-point multiplication, respectively.

4. **Pay attention to specific instruction variants:** Note the suffixes like 'u' for update, 'i' for immediate, and the presence of 32-bit and 64-bit variants (e.g., `stw` vs. `std`, `lwz` vs. `ld`).

5. **Recognize architectural features:** Look for code related to special registers (like `mflr`, `mtlr`, `mtctr`), condition registers (`crxor`, `creqv`), and floating-point status and control registers (FPSCR).

6. **Identify prefixed instructions:**  The code includes functions like `paddi`, `pli`, `plbz`, etc., which represent prefixed instructions in PowerPC, allowing for larger immediate values or offsets.

7. **Understand the `mov` instruction logic:** The `mov` function and its related helpers are complex due to the need to handle various operand types (immediate values, memory locations, labels) and optimization strategies (constant pool).

8. **Note control flow and debugging features:** Instructions like `b` (branch), `stop`, and `bkpt` are for controlling program flow and inserting breakpoints for debugging.

9. **Consider potential connections to JavaScript:** Think about how these low-level operations might be used in a JavaScript engine. Loading and storing values are fundamental for accessing variables and objects. Arithmetic and logical operations are used for computations. Floating-point instructions are used for handling JavaScript numbers.

10. **Address the specific questions:**
    * **.tq extension:**  The code doesn't have a `.tq` extension, so it's not Torque code.
    * **JavaScript relation:** Provide examples of how the assembly instructions could be used in the context of JavaScript.
    * **Code logic and examples:** Offer simple examples demonstrating the behavior of some instructions with hypothetical inputs and outputs.
    * **Common programming errors:**  Highlight potential errors related to register usage, offset calculations, and data types.

11. **Synthesize a summary:**  Combine the observations into a concise description of the file's role.

**Self-Correction/Refinement:**

* Initially, I might focus too much on individual instructions. It's important to group them by functionality for a more coherent summary.
*  I need to ensure the JavaScript examples are clear and relevant to the assembly instructions. Abstract examples are better than trying to reverse-engineer complex V8 internals.
* When explaining potential errors, focus on common mistakes a programmer might make when thinking about low-level operations, even if they aren't directly writing assembly.
* The request specifically asks for a summary of the *functionality*, so avoid getting bogged down in implementation details unless they directly relate to the observable behavior.
这是 `v8/src/codegen/ppc/assembler-ppc.cc` 文件代码的第二部分，延续了第一部分的功能，主要负责实现 PowerPC 架构的汇编指令生成。以下是其功能的归纳：

**核心功能：生成 PowerPC 汇编指令的函数**

这部分代码定义了 `Assembler` 类中的成员函数，每个函数对应一个或一组特定的 PowerPC 汇编指令。这些函数接收操作数（寄存器、内存地址、立即数等）作为参数，并将这些参数编码成对应的机器码（二进制指令），添加到 `Assembler` 实例管理的缓冲区中。

**具体功能点：**

1. **数据存储指令 (Store Instructions):**
   - `sth`: 存储半字 (16位)
   - `stw`: 存储字 (32位)
   - `stwu`: 存储字并更新基址寄存器
   - `std`: 存储双字 (64位)
   - `stdu`: 存储双字并更新基址寄存器

2. **算术运算指令 (Arithmetic Instructions):**
   - `neg`: 取反 (Negate)

3. **数据加载指令 (Load Instructions - 64bit specific):**
   - `ld`: 加载双字
   - `ldu`: 加载双字并更新基址寄存器

4. **位操作指令 (Bit Manipulation Instructions):**
   - `rldic`: Rotate Left Doubleword Immediate then Clear Left
   - `rldicl`: Rotate Left Doubleword Immediate then Clear Left
   - `rldcl`: Rotate Left Doubleword then Clear Left
   - `rldicr`: Rotate Left Doubleword Immediate then Clear Right
   - `sldi`: Shift Left Doubleword Immediate
   - `srdi`: Shift Right Doubleword Immediate
   - `clrrdi`: Clear Right Doubleword Immediate
   - `clrldi`: Clear Left Doubleword Immediate
   - `rldimi`: Rotate Left Doubleword Immediate then Mask Insert
   - `sradi`: Shift Right Algebraic Doubleword Immediate
   - `rotld`: Rotate Left Doubleword
   - `rotldi`: Rotate Left Doubleword Immediate
   - `rotrdi`: Rotate Right Doubleword Immediate

5. **乘法和除法指令 (Multiply and Divide Instructions - 64bit):**
   - `mulld`: 乘法双字
   - `divd`: 除法双字 (有符号)
   - `divdu`: 除法双字 (无符号)

6. **前缀指令 (Prefixed Instructions - 扩展寻址范围):**
   - `paddi`: 前缀加立即数
   - `pli`: 前缀加载立即数
   - `psubi`: 前缀减立即数
   - `plbz`: 前缀加载字节并零扩展
   - `plhz`: 前缀加载半字并零扩展
   - `plha`: 前缀加载半字并符号扩展
   - `plwz`: 前缀加载字并零扩展
   - `plwa`: 前缀加载字并符号扩展
   - `pld`: 前缀加载双字
   - `plfs`: 前缀加载单精度浮点数
   - `plfd`: 前缀加载双精度浮点数
   - `pstb`: 前缀存储字节
   - `psth`: 前缀存储半字
   - `pstw`: 前缀存储字
   - `pstd`: 前缀存储双字
   - `pstfs`: 前缀存储单精度浮点数
   - `pstfd`: 前缀存储双精度浮点数

7. **`mov` 指令的复杂实现:**
   - `instructions_required_for_mov`: 计算 `mov` 指令所需的指令数量，考虑到常量池等优化。
   - `use_constant_pool_for_mov`:  判断是否使用常量池来优化 `mov` 指令。
   - `mov`: 实现将立即数或内存地址加载到寄存器的复杂逻辑，包括常量池的使用、立即数范围的判断和不同的指令序列选择。
   - `bitwise_mov`: 使用位操作指令序列加载 64 位立即数。
   - `bitwise_mov32`: 使用位操作指令序列加载 32 位立即数。
   - `bitwise_add32`: 使用位操作指令序列进行 32 位加法。

8. **标签和跳转相关功能:**
   - `patch_pc_address`:  在特定偏移量处修改指令，通常用于修复相对跳转地址。
   - `mov_label_offset`: 将标签的偏移地址加载到寄存器。
   - `add_label_offset`: 将标签的偏移地址加上基址寄存器的值加载到目标寄存器。
   - `mov_label_addr`: 将标签的绝对地址加载到寄存器。
   - `emit_label_addr`: 将标签的地址作为跳转表条目发出。

9. **特殊寄存器操作指令:**
   - `crxor`, `creqv`: 条件寄存器逻辑运算。
   - `mflr`, `mtlr`: 移动到/从链接寄存器。
   - `mtctr`: 移动到计数器寄存器。
   - `mtxer`: 移动到异常寄存器。
   - `mcrfs`: 移动条件寄存器域到浮点状态和控制寄存器。
   - `mfcr`: 移动到条件寄存器。
   - `mtcrf`: 移动到条件寄存器域。
   - `mffprd`, `mffprwz`, `mtfprd`, `mtfprwz`, `mtfprwa`: 浮点寄存器与通用寄存器之间的数据传输。

10. **异常和调试支持指令:**
    - `stop`: 停止执行，用于调试。
    - `bkpt`: 断点指令。
    - `dcbf`: 数据缓存块刷新。
    - `sync`: 内存屏障，确保所有加载/存储操作完成。
    - `lwsync`: 轻量级内存屏障。
    - `icbi`: 指令缓存块无效化。
    - `isync`: 指令同步。

11. **浮点运算指令 (Floating Point Instructions):**
    - `lfd`, `lfdu`, `lfs`, `lfsu`: 加载浮点数。
    - `stfd`, `stfdu`, `stfs`, `stfsu`: 存储浮点数。
    - `fsub`, `fadd`, `fmul`, `fcpsgn`, `fdiv`: 浮点算术运算。
    - `fcmpu`: 浮点比较。
    - `fmr`: 浮点数移动。
    - `fctiwz`, `fctiw`, `fctiwuz`: 浮点数转换为整数。
    - `frin`, `friz`, `frip`, `frim`: 浮点数舍入。
    - `frsp`: 浮点数转换为单精度。
    - `fcfid`, `fcfidu`, `fcfids`, `fcfidus`:  浮点数类型转换。
    - `fctid`, `fctidz`, `fctidu`, `fctiduz`: 浮点数转换为双精度整数。
    - `fsel`: 浮点数选择。
    - `fneg`: 浮点数取负。
    - `mtfsb0`, `mtfsb1`, `mtfsfi`, `mffs`, `mtfsf`:  浮点状态和控制寄存器操作。
    - `fsqrt`: 浮点数平方根。
    - `fabs`: 浮点数绝对值。
    - `fmadd`, `fmsub`: 浮点数乘加/乘减。

12. **向量指令 (Vector Instructions):**
    - `mfvsrd`, `mfvsrwz`, `mtvsrd`, `mtvsrdd`: 向量寄存器和通用寄存器之间的数据传输。
    - `lxvd`, `lxvx`, `lxsdx`, `lxsibzx`, `lxsihzx`: 加载向量数据。

**与 JavaScript 的关系:**

这部分代码生成的汇编指令是 V8 引擎执行 JavaScript 代码的基础。例如：

```javascript
let a = 10;
let b = 20;
let sum = a + b;
```

当 V8 引擎执行这段 JavaScript 代码时，`Assembler-ppc.cc` 中的函数会被调用，生成类似以下的汇编指令 (简化示例)：

```assembly
li r3, 10       // 将立即数 10 加载到寄存器 r3 (对应变量 a)
li r4, 20       // 将立即数 20 加载到寄存器 r4 (对应变量 b)
add r5, r3, r4  // 将 r3 和 r4 的值相加，结果存入 r5 (对应变量 sum)
```

对于更复杂的操作，比如对象属性访问、函数调用、浮点数运算等，也会生成相应的 PowerPC 汇编指令。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `Assembler::add(r5, r3, r4)`，其中 `r3` 和 `r4` 分别代表 PowerPC 的通用寄存器，并且它们的值在之前的指令中被设置为 10 和 20。

**假设输入:**
- `dst`: 寄存器 `r5`
- `src1`: 寄存器 `r3` (假设值为 10)
- `src2`: 寄存器 `r4` (假设值为 20)

**输出 (添加到汇编缓冲区的机器码):**
- 生成的机器码将对应 PowerPC 的 `add` 指令，其操作码和寄存器编码将 `r3` 和 `r4` 的值相加并将结果存储到 `r5`。具体的机器码会根据 PowerPC 指令的编码格式而定。

**用户常见的编程错误 (在使用 V8 或其 API 时):**

虽然用户通常不直接编写 PowerPC 汇编，但在与 V8 的底层交互或编写需要高性能的 JavaScript 代码时，了解一些底层概念可以避免一些潜在的性能问题或错误：

1. **类型假设错误:** JavaScript 是动态类型语言，但 V8 在底层会进行类型优化。如果代码中的类型变化过于频繁，会导致 V8 频繁地生成和优化机器码，可能影响性能。例如，一个循环中变量的类型不断变化。

   ```javascript
   function calculate(input) {
     let result = 0;
     for (let i = 0; i < input.length; i++) {
       if (typeof input[i] === 'number') {
         result += input[i];
       } else if (typeof input[i] === 'string') {
         result += parseInt(input[i]); // 类型转换可能导致性能下降
       }
     }
     return result;
   }
   ```

2. **内存分配和垃圾回收:**  过度创建临时对象会导致频繁的垃圾回收，这涉及到 V8 的内存管理机制，底层的汇编指令会涉及到内存的分配和释放。

   ```javascript
   function createPoints(count) {
     const points = [];
     for (let i = 0; i < count; i++) {
       points.push({ x: i, y: i * 2 }); // 大量创建临时对象
     }
     return points;
   }
   ```

**总结:**

`v8/src/codegen/ppc/assembler-ppc.cc` 的第二部分主要负责定义 `Assembler` 类中用于生成各种 PowerPC 汇编指令的函数，涵盖了数据存储、加载、算术运算、位操作、跳转、特殊寄存器操作、浮点运算和向量运算等多个方面。这些函数是 V8 引擎将 JavaScript 代码翻译成机器码的关键组成部分。了解这部分代码的功能有助于理解 V8 引擎的底层执行机制。

Prompt: 
```
这是目录为v8/src/codegen/ppc/assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
er dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(STH, dst, src.ra(), src.offset(), true);
}

void Assembler::stw(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(STW, dst, src.ra(), src.offset(), true);
}

void Assembler::stwu(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  d_form(STWU, dst, src.ra(), src.offset(), true);
}

void Assembler::neg(Register rt, Register ra, OEBit o, RCBit r) {
  emit(EXT2 | NEGX | rt.code() * B21 | ra.code() * B16 | o | r);
}

// 64bit specific instructions
void Assembler::ld(Register rd, const MemOperand& src) {
  int offset = src.offset();
  DCHECK(src.ra_ != r0);
  CHECK(!(offset & 3) && is_int16(offset));
  offset = kImm16Mask & offset;
  emit(LD | rd.code() * B21 | src.ra().code() * B16 | offset);
}

void Assembler::ldu(Register rd, const MemOperand& src) {
  int offset = src.offset();
  DCHECK(src.ra_ != r0);
  CHECK(!(offset & 3) && is_int16(offset));
  offset = kImm16Mask & offset;
  emit(LD | rd.code() * B21 | src.ra().code() * B16 | offset | 1);
}

void Assembler::std(Register rs, const MemOperand& src) {
  int offset = src.offset();
  DCHECK(src.ra_ != r0);
  CHECK(!(offset & 3) && is_int16(offset));
  offset = kImm16Mask & offset;
  emit(STD | rs.code() * B21 | src.ra().code() * B16 | offset);
}

void Assembler::stdu(Register rs, const MemOperand& src) {
  int offset = src.offset();
  DCHECK(src.ra_ != r0);
  CHECK(!(offset & 3) && is_int16(offset));
  offset = kImm16Mask & offset;
  emit(STD | rs.code() * B21 | src.ra().code() * B16 | offset | 1);
}

void Assembler::rldic(Register ra, Register rs, int sh, int mb, RCBit r) {
  md_form(EXT5 | RLDIC, ra, rs, sh, mb, r);
}

void Assembler::rldicl(Register ra, Register rs, int sh, int mb, RCBit r) {
  md_form(EXT5 | RLDICL, ra, rs, sh, mb, r);
}

void Assembler::rldcl(Register ra, Register rs, Register rb, int mb, RCBit r) {
  mds_form(EXT5 | RLDCL, ra, rs, rb, mb, r);
}

void Assembler::rldicr(Register ra, Register rs, int sh, int me, RCBit r) {
  md_form(EXT5 | RLDICR, ra, rs, sh, me, r);
}

void Assembler::sldi(Register dst, Register src, const Operand& val, RCBit rc) {
  DCHECK((64 > val.immediate()) && (val.immediate() >= 0));
  rldicr(dst, src, val.immediate(), 63 - val.immediate(), rc);
}

void Assembler::srdi(Register dst, Register src, const Operand& val, RCBit rc) {
  DCHECK((64 > val.immediate()) && (val.immediate() >= 0));
  rldicl(dst, src, 64 - val.immediate(), val.immediate(), rc);
}

void Assembler::clrrdi(Register dst, Register src, const Operand& val,
                       RCBit rc) {
  DCHECK((64 > val.immediate()) && (val.immediate() >= 0));
  rldicr(dst, src, 0, 63 - val.immediate(), rc);
}

void Assembler::clrldi(Register dst, Register src, const Operand& val,
                       RCBit rc) {
  DCHECK((64 > val.immediate()) && (val.immediate() >= 0));
  rldicl(dst, src, 0, val.immediate(), rc);
}

void Assembler::rldimi(Register ra, Register rs, int sh, int mb, RCBit r) {
  md_form(EXT5 | RLDIMI, ra, rs, sh, mb, r);
}

void Assembler::sradi(Register ra, Register rs, int sh, RCBit r) {
  int sh0_4 = sh & 0x1F;
  int sh5 = (sh >> 5) & 0x1;

  emit(EXT2 | SRADIX | rs.code() * B21 | ra.code() * B16 | sh0_4 * B11 |
       sh5 * B1 | r);
}

void Assembler::rotld(Register ra, Register rs, Register rb, RCBit r) {
  rldcl(ra, rs, rb, 0, r);
}

void Assembler::rotldi(Register ra, Register rs, int sh, RCBit r) {
  rldicl(ra, rs, sh, 0, r);
}

void Assembler::rotrdi(Register ra, Register rs, int sh, RCBit r) {
  rldicl(ra, rs, 64 - sh, 0, r);
}

void Assembler::mulld(Register dst, Register src1, Register src2, OEBit o,
                      RCBit r) {
  xo_form(EXT2 | MULLD, dst, src1, src2, o, r);
}

void Assembler::divd(Register dst, Register src1, Register src2, OEBit o,
                     RCBit r) {
  xo_form(EXT2 | DIVD, dst, src1, src2, o, r);
}

void Assembler::divdu(Register dst, Register src1, Register src2, OEBit o,
                      RCBit r) {
  xo_form(EXT2 | DIVDU, dst, src1, src2, o, r);
}

// Prefixed instructions.
#define GENERATE_PREFIX_SUFFIX_BITS(immediate, prefix, suffix)      \
  CHECK(is_int34(immediate));                                       \
  int32_t prefix =                                                  \
      SIGN_EXT_IMM18((immediate >> 16) & kImm18Mask); /* 18 bits.*/ \
  int16_t suffix = immediate & kImm16Mask;            /* 16 bits.*/ \
  DCHECK(is_int18(prefix));

void Assembler::paddi(Register dst, Register src, const Operand& imm) {
  CHECK(CpuFeatures::IsSupported(PPC_10_PLUS));
  DCHECK(src != r0);  // use pli instead to show intent.
  intptr_t immediate = imm.immediate();
  GENERATE_PREFIX_SUFFIX_BITS(immediate, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  addi(dst, src, Operand(lo));
}

void Assembler::pli(Register dst, const Operand& imm) {
  CHECK(CpuFeatures::IsSupported(PPC_10_PLUS));
  intptr_t immediate = imm.immediate();
  GENERATE_PREFIX_SUFFIX_BITS(immediate, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  li(dst, Operand(lo));
}

void Assembler::psubi(Register dst, Register src, const Operand& imm) {
  paddi(dst, src, Operand(-(imm.immediate())));
}

void Assembler::plbz(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  lbz(dst, MemOperand(src.ra(), lo));
}

void Assembler::plhz(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  lhz(dst, MemOperand(src.ra(), lo));
}

void Assembler::plha(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  lha(dst, MemOperand(src.ra(), lo));
}

void Assembler::plwz(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  lwz(dst, MemOperand(src.ra(), lo));
}

void Assembler::plwa(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_8ls(Operand(hi));
  emit(PPLWA | dst.code() * B21 | src.ra().code() * B16 | (lo & kImm16Mask));
}

void Assembler::pld(Register dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_8ls(Operand(hi));
  emit(PPLD | dst.code() * B21 | src.ra().code() * B16 | (lo & kImm16Mask));
}

void Assembler::plfs(DoubleRegister dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  lfs(dst, MemOperand(src.ra(), lo));
}

void Assembler::plfd(DoubleRegister dst, const MemOperand& src) {
  DCHECK(src.ra_ != r0);
  int64_t offset = src.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  lfd(dst, MemOperand(src.ra(), lo));
}

void Assembler::pstb(Register src, const MemOperand& dst) {
  DCHECK(dst.ra_ != r0);
  int64_t offset = dst.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  stb(src, MemOperand(dst.ra(), lo));
}

void Assembler::psth(Register src, const MemOperand& dst) {
  DCHECK(dst.ra_ != r0);
  int64_t offset = dst.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  sth(src, MemOperand(dst.ra(), lo));
}

void Assembler::pstw(Register src, const MemOperand& dst) {
  DCHECK(dst.ra_ != r0);
  int64_t offset = dst.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  stw(src, MemOperand(dst.ra(), lo));
}

void Assembler::pstd(Register src, const MemOperand& dst) {
  DCHECK(dst.ra_ != r0);
  int64_t offset = dst.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_8ls(Operand(hi));
  emit(PPSTD | src.code() * B21 | dst.ra().code() * B16 | (lo & kImm16Mask));
}

void Assembler::pstfs(const DoubleRegister src, const MemOperand& dst) {
  DCHECK(dst.ra_ != r0);
  int64_t offset = dst.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  stfs(src, MemOperand(dst.ra(), lo));
}

void Assembler::pstfd(const DoubleRegister src, const MemOperand& dst) {
  DCHECK(dst.ra_ != r0);
  int64_t offset = dst.offset();
  GENERATE_PREFIX_SUFFIX_BITS(offset, hi, lo)
  BlockTrampolinePoolScope block_trampoline_pool(this);
  pload_store_mls(Operand(hi));
  stfd(src, MemOperand(dst.ra(), lo));
}
#undef GENERATE_PREFIX_SUFFIX_BITS

int Assembler::instructions_required_for_mov(Register dst,
                                             const Operand& src) const {
  bool canOptimize =
      !(src.must_output_reloc_info(this) || is_trampoline_pool_blocked());
  if (use_constant_pool_for_mov(dst, src, canOptimize)) {
    if (ConstantPoolAccessIsInOverflow()) {
      return kMovInstructionsConstantPool + 1;
    }
    return kMovInstructionsConstantPool;
  }
  DCHECK(!canOptimize);
  return kMovInstructionsNoConstantPool;
}

bool Assembler::use_constant_pool_for_mov(Register dst, const Operand& src,
                                          bool canOptimize) const {
  if (!V8_EMBEDDED_CONSTANT_POOL_BOOL || !is_constant_pool_available()) {
    // If there is no constant pool available, we must use a mov
    // immediate sequence.
    return false;
  }
  intptr_t value = src.immediate();
  bool allowOverflow = !((canOptimize && is_int32(value)) || dst == r0);
  if (canOptimize &&
      (is_int16(value) ||
       (CpuFeatures::IsSupported(PPC_10_PLUS) && is_int34(value)))) {
    // Prefer a single-instruction load-immediate.
    return false;
  }
  if (!allowOverflow && ConstantPoolAccessIsInOverflow()) {
    // Prefer non-relocatable two-instruction bitwise-mov32 over
    // overflow sequence.
    return false;
  }

  return true;
}

void Assembler::EnsureSpaceFor(int space_needed) {
  if (buffer_space() <= (kGap + space_needed)) {
    GrowBuffer(space_needed);
  }
}

bool Operand::must_output_reloc_info(const Assembler* assembler) const {
  if (rmode_ == RelocInfo::EXTERNAL_REFERENCE) {
    if (assembler != nullptr && assembler->predictable_code_size()) return true;
    return assembler->options().record_reloc_info_for_serialization;
  } else if (RelocInfo::IsNoInfo(rmode_)) {
    return false;
  }
  return true;
}

// Primarily used for loading constants
// This should really move to be in macro-assembler as it
// is really a pseudo instruction
// Some usages of this intend for a FIXED_SEQUENCE to be used
// Todo - break this dependency so we can optimize mov() in general
// and only use the generic version when we require a fixed sequence
void Assembler::mov(Register dst, const Operand& src) {
  intptr_t value;
  if (src.IsHeapNumberRequest()) {
    RequestHeapNumber(src.heap_number_request());
    value = 0;
  } else {
    value = src.immediate();
  }
  bool relocatable = src.must_output_reloc_info(this);
  bool canOptimize;

  if (src.rmode_ == RelocInfo::WASM_CANONICAL_SIG_ID) {
    if (relocatable) {
      RecordRelocInfo(src.rmode_);
    }
    CHECK(is_int32(value));
    // If this is changed then also change `uint32_constant_at` and
    // `set_uint32_constant_at`.
    bitwise_mov32(dst, value);
    return;
  }

  canOptimize =
      !(relocatable ||
        (is_trampoline_pool_blocked() &&
         (!is_int16(value) ||
          !(CpuFeatures::IsSupported(PPC_10_PLUS) && is_int34(value)))));

  if (!src.IsHeapNumberRequest() &&
      use_constant_pool_for_mov(dst, src, canOptimize)) {
    DCHECK(is_constant_pool_available());
    if (relocatable) {
      RecordRelocInfo(src.rmode_);
    }
    ConstantPoolEntry::Access access = ConstantPoolAddEntry(src.rmode_, value);
    if (access == ConstantPoolEntry::OVERFLOWED) {
      addis(dst, kConstantPoolRegister, Operand::Zero());
      ld(dst, MemOperand(dst, 0));
    } else {
      ld(dst, MemOperand(kConstantPoolRegister, 0));
    }
    return;
  }

  if (canOptimize) {
    if (is_int16(value)) {
      li(dst, Operand(value));
    } else if (CpuFeatures::IsSupported(PPC_10_PLUS) && is_int34(value)) {
      pli(dst, Operand(value));
    } else {
      uint16_t u16;
      if (is_int32(value)) {
        lis(dst, Operand(value >> 16));
      } else {
        if (is_int48(value)) {
          li(dst, Operand(value >> 32));
        } else {
          lis(dst, Operand(value >> 48));
          u16 = ((value >> 32) & 0xFFFF);
          if (u16) {
            ori(dst, dst, Operand(u16));
          }
        }
        sldi(dst, dst, Operand(32));
        u16 = ((value >> 16) & 0xFFFF);
        if (u16) {
          oris(dst, dst, Operand(u16));
        }
      }
      u16 = (value & 0xFFFF);
      if (u16) {
        ori(dst, dst, Operand(u16));
      }
    }
    return;
  }

  DCHECK(!canOptimize);
  if (relocatable) {
    RecordRelocInfo(src.rmode_);
  }
  bitwise_mov(dst, value);
}

void Assembler::bitwise_mov(Register dst, intptr_t value) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  int32_t hi_32 = static_cast<int32_t>(value >> 32);
  int32_t lo_32 = static_cast<int32_t>(value);
  int hi_word = static_cast<int>(hi_32 >> 16);
  int lo_word = static_cast<int>(hi_32 & 0xFFFF);
  lis(dst, Operand(SIGN_EXT_IMM16(hi_word)));
  ori(dst, dst, Operand(lo_word));
  sldi(dst, dst, Operand(32));
  hi_word = static_cast<int>(((lo_32 >> 16) & 0xFFFF));
  lo_word = static_cast<int>(lo_32 & 0xFFFF);
  oris(dst, dst, Operand(hi_word));
  ori(dst, dst, Operand(lo_word));
}

void Assembler::bitwise_mov32(Register dst, int32_t value) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  int hi_word = static_cast<int>(value >> 16);
  int lo_word = static_cast<int>(value & 0xFFFF);
  lis(dst, Operand(SIGN_EXT_IMM16(hi_word)));
  ori(dst, dst, Operand(lo_word));
}

void Assembler::bitwise_add32(Register dst, Register src, int32_t value) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (is_int16(value)) {
    addi(dst, src, Operand(value));
    nop();
  } else {
    int hi_word = static_cast<int>(value >> 16);
    int lo_word = static_cast<int>(value & 0xFFFF);
    if (lo_word & 0x8000) hi_word++;
    addis(dst, src, Operand(SIGN_EXT_IMM16(hi_word)));
    addic(dst, dst, Operand(SIGN_EXT_IMM16(lo_word)));
  }
}

void Assembler::patch_pc_address(Register dst, int pc_offset,
                                 int return_address_offset) {
  DCHECK(is_int16(return_address_offset));
  Assembler patching_assembler(
      AssemblerOptions{},
      ExternalAssemblerBuffer(buffer_start_ + pc_offset, kInstrSize + kGap));
  patching_assembler.addi(dst, dst, Operand(return_address_offset));
}

void Assembler::mov_label_offset(Register dst, Label* label) {
  int position = link(label);
  if (label->is_bound()) {
    // Load the position of the label relative to the generated code object.
    mov(dst,
        Operand(position + InstructionStream::kHeaderSize - kHeapObjectTag));
  } else {
    // Encode internal reference to unbound label. We use a dummy opcode
    // such that it won't collide with any opcode that might appear in the
    // label's chain.  Encode the destination register in the 2nd instruction.
    int link = position - pc_offset();
    DCHECK_EQ(0, link & 3);
    link >>= 2;
    DCHECK(is_int26(link));

    // When the label is bound, these instructions will be patched
    // with a 2 instruction mov sequence that will load the
    // destination register with the position of the label from the
    // beginning of the code.
    //
    // target_at extracts the link and target_at_put patches the instructions.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    emit(kUnboundMovLabelOffsetOpcode | (link & kImm26Mask));
    emit(dst.code());
  }
}

void Assembler::add_label_offset(Register dst, Register base, Label* label,
                                 int delta) {
  int position = link(label);
  if (label->is_bound()) {
    // dst = base + position + delta
    position += delta;
    bitwise_add32(dst, base, position);
  } else {
    // Encode internal reference to unbound label. We use a dummy opcode
    // such that it won't collide with any opcode that might appear in the
    // label's chain.  Encode the operands in the 2nd instruction.
    int link = position - pc_offset();
    DCHECK_EQ(0, link & 3);
    link >>= 2;
    DCHECK(is_int26(link));
    BlockTrampolinePoolScope block_trampoline_pool(this);

    emit((is_int22(delta) ? kUnboundAddLabelOffsetOpcode
                          : kUnboundAddLabelLongOffsetOpcode) |
         (link & kImm26Mask));
    emit(dst.code() * B27 | base.code() * B22 | (delta & kImm22Mask));

    if (!is_int22(delta)) {
      emit(delta);
    }
  }
}

void Assembler::mov_label_addr(Register dst, Label* label) {
  CheckBuffer();
  RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE_ENCODED);
  int position = link(label);
  if (label->is_bound()) {
    // Keep internal references relative until EmitRelocations.
    bitwise_mov(dst, position);
  } else {
    // Encode internal reference to unbound label. We use a dummy opcode
    // such that it won't collide with any opcode that might appear in the
    // label's chain.  Encode the destination register in the 2nd instruction.
    int link = position - pc_offset();
    DCHECK_EQ(0, link & 3);
    link >>= 2;
    DCHECK(is_int26(link));

    // When the label is bound, these instructions will be patched
    // with a multi-instruction mov sequence that will load the
    // destination register with the address of the label.
    //
    // target_at extracts the link and target_at_put patches the instructions.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    emit(kUnboundMovLabelAddrOpcode | (link & kImm26Mask));
    emit(dst.code());
    DCHECK_GE(kMovInstructionsNoConstantPool, 2);
    for (int i = 0; i < kMovInstructionsNoConstantPool - 2; i++) nop();
  }
}

void Assembler::emit_label_addr(Label* label) {
  CheckBuffer();
  RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
  int position = link(label);
  if (label->is_bound()) {
    // Keep internal references relative until EmitRelocations.
    dp(position);
  } else {
    // Encode internal reference to unbound label. We use a dummy opcode
    // such that it won't collide with any opcode that might appear in the
    // label's chain.
    int link = position - pc_offset();
    DCHECK_EQ(0, link & 3);
    link >>= 2;
    DCHECK(is_int26(link));

    // When the label is bound, the instruction(s) will be patched
    // as a jump table entry containing the label address.  target_at extracts
    // the link and target_at_put patches the instruction(s).
    BlockTrampolinePoolScope block_trampoline_pool(this);
    emit(kUnboundJumpTableEntryOpcode | (link & kImm26Mask));
    nop();
  }
}

// Special register instructions
void Assembler::crxor(int bt, int ba, int bb) {
  emit(EXT1 | CRXOR | bt * B21 | ba * B16 | bb * B11);
}

void Assembler::creqv(int bt, int ba, int bb) {
  emit(EXT1 | CREQV | bt * B21 | ba * B16 | bb * B11);
}

void Assembler::mflr(Register dst) {
  emit(EXT2 | MFSPR | dst.code() * B21 | 256 << 11);  // Ignore RC bit
}

void Assembler::mtlr(Register src) {
  emit(EXT2 | MTSPR | src.code() * B21 | 256 << 11);  // Ignore RC bit
}

void Assembler::mtctr(Register src) {
  emit(EXT2 | MTSPR | src.code() * B21 | 288 << 11);  // Ignore RC bit
}

void Assembler::mtxer(Register src) {
  emit(EXT2 | MTSPR | src.code() * B21 | 32 << 11);
}

void Assembler::mcrfs(CRegister cr, FPSCRBit bit) {
  DCHECK_LT(static_cast<int>(bit), 32);
  int bf = cr.code();
  int bfa = bit / CRWIDTH;
  emit(EXT4 | MCRFS | bf * B23 | bfa * B18);
}

void Assembler::mfcr(Register dst) { emit(EXT2 | MFCR | dst.code() * B21); }

void Assembler::mtcrf(Register src, uint8_t FXM) {
  emit(MTCRF | src.code() * B21 | FXM * B12);
}
void Assembler::mffprd(Register dst, DoubleRegister src) {
  emit(EXT2 | MFVSRD | src.code() * B21 | dst.code() * B16);
}

void Assembler::mffprwz(Register dst, DoubleRegister src) {
  emit(EXT2 | MFVSRWZ | src.code() * B21 | dst.code() * B16);
}

void Assembler::mtfprd(DoubleRegister dst, Register src) {
  emit(EXT2 | MTVSRD | dst.code() * B21 | src.code() * B16);
}

void Assembler::mtfprwz(DoubleRegister dst, Register src) {
  emit(EXT2 | MTVSRWZ | dst.code() * B21 | src.code() * B16);
}

void Assembler::mtfprwa(DoubleRegister dst, Register src) {
  emit(EXT2 | MTVSRWA | dst.code() * B21 | src.code() * B16);
}

// Exception-generating instructions and debugging support.
// Stops with a non-negative code less than kNumOfWatchedStops support
// enabling/disabling and a counter feature. See simulator-ppc.h .
void Assembler::stop(Condition cond, int32_t code, CRegister cr) {
  if (cond != al) {
    Label skip;
    b(NegateCondition(cond), &skip, cr);
    bkpt(0);
    bind(&skip);
  } else {
    bkpt(0);
  }
}

void Assembler::bkpt(uint32_t imm16) { emit(0x7D821008); }

void Assembler::dcbf(Register ra, Register rb) {
  emit(EXT2 | DCBF | ra.code() * B16 | rb.code() * B11);
}

void Assembler::sync() { emit(EXT2 | SYNC); }

void Assembler::lwsync() { emit(EXT2 | SYNC | 1 * B21); }

void Assembler::icbi(Register ra, Register rb) {
  emit(EXT2 | ICBI | ra.code() * B16 | rb.code() * B11);
}

void Assembler::isync() { emit(EXT1 | ISYNC); }

// Floating point support

void Assembler::lfd(const DoubleRegister frt, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  DCHECK(ra != r0);
  CHECK(is_int16(offset));
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(LFD | frt.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::lfdu(const DoubleRegister frt, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  DCHECK(ra != r0);
  CHECK(is_int16(offset));
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(LFDU | frt.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::lfs(const DoubleRegister frt, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  CHECK(is_int16(offset));
  DCHECK(ra != r0);
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(LFS | frt.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::lfsu(const DoubleRegister frt, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  CHECK(is_int16(offset));
  DCHECK(ra != r0);
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(LFSU | frt.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::stfd(const DoubleRegister frs, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  CHECK(is_int16(offset));
  DCHECK(ra != r0);
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(STFD | frs.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::stfdu(const DoubleRegister frs, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  CHECK(is_int16(offset));
  DCHECK(ra != r0);
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(STFDU | frs.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::stfs(const DoubleRegister frs, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  CHECK(is_int16(offset));
  DCHECK(ra != r0);
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(STFS | frs.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::stfsu(const DoubleRegister frs, const MemOperand& src) {
  int offset = src.offset();
  Register ra = src.ra();
  CHECK(is_int16(offset));
  DCHECK(ra != r0);
  int imm16 = offset & kImm16Mask;
  // could be x_form instruction with some casting magic
  emit(STFSU | frs.code() * B21 | ra.code() * B16 | imm16);
}

void Assembler::fsub(const DoubleRegister frt, const DoubleRegister fra,
                     const DoubleRegister frb, RCBit rc) {
  a_form(EXT4 | FSUB, frt, fra, frb, rc);
}

void Assembler::fadd(const DoubleRegister frt, const DoubleRegister fra,
                     const DoubleRegister frb, RCBit rc) {
  a_form(EXT4 | FADD, frt, fra, frb, rc);
}

void Assembler::fmul(const DoubleRegister frt, const DoubleRegister fra,
                     const DoubleRegister frc, RCBit rc) {
  emit(EXT4 | FMUL | frt.code() * B21 | fra.code() * B16 | frc.code() * B6 |
       rc);
}

void Assembler::fcpsgn(const DoubleRegister frt, const DoubleRegister fra,
                       const DoubleRegister frb, RCBit rc) {
  emit(EXT4 | FCPSGN | frt.code() * B21 | fra.code() * B16 | frb.code() * B11 |
       rc);
}

void Assembler::fdiv(const DoubleRegister frt, const DoubleRegister fra,
                     const DoubleRegister frb, RCBit rc) {
  a_form(EXT4 | FDIV, frt, fra, frb, rc);
}

void Assembler::fcmpu(const DoubleRegister fra, const DoubleRegister frb,
                      CRegister cr) {
  DCHECK(cr.code() >= 0 && cr.code() <= 7);
  emit(EXT4 | FCMPU | cr.code() * B23 | fra.code() * B16 | frb.code() * B11);
}

void Assembler::fmr(const DoubleRegister frt, const DoubleRegister frb,
                    RCBit rc) {
  emit(EXT4 | FMR | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fctiwz(const DoubleRegister frt, const DoubleRegister frb) {
  emit(EXT4 | FCTIWZ | frt.code() * B21 | frb.code() * B11);
}

void Assembler::fctiw(const DoubleRegister frt, const DoubleRegister frb) {
  emit(EXT4 | FCTIW | frt.code() * B21 | frb.code() * B11);
}

void Assembler::fctiwuz(const DoubleRegister frt, const DoubleRegister frb) {
  emit(EXT4 | FCTIWUZ | frt.code() * B21 | frb.code() * B11);
}

void Assembler::frin(const DoubleRegister frt, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FRIN | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::friz(const DoubleRegister frt, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FRIZ | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::frip(const DoubleRegister frt, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FRIP | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::frim(const DoubleRegister frt, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FRIM | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::frsp(const DoubleRegister frt, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FRSP | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fcfid(const DoubleRegister frt, const DoubleRegister frb,
                      RCBit rc) {
  emit(EXT4 | FCFID | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fcfidu(const DoubleRegister frt, const DoubleRegister frb,
                       RCBit rc) {
  emit(EXT4 | FCFIDU | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fcfidus(const DoubleRegister frt, const DoubleRegister frb,
                        RCBit rc) {
  emit(EXT3 | FCFIDUS | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fcfids(const DoubleRegister frt, const DoubleRegister frb,
                       RCBit rc) {
  emit(EXT3 | FCFIDS | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fctid(const DoubleRegister frt, const DoubleRegister frb,
                      RCBit rc) {
  emit(EXT4 | FCTID | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fctidz(const DoubleRegister frt, const DoubleRegister frb,
                       RCBit rc) {
  emit(EXT4 | FCTIDZ | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fctidu(const DoubleRegister frt, const DoubleRegister frb,
                       RCBit rc) {
  emit(EXT4 | FCTIDU | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fctiduz(const DoubleRegister frt, const DoubleRegister frb,
                        RCBit rc) {
  emit(EXT4 | FCTIDUZ | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fsel(const DoubleRegister frt, const DoubleRegister fra,
                     const DoubleRegister frc, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FSEL | frt.code() * B21 | fra.code() * B16 | frb.code() * B11 |
       frc.code() * B6 | rc);
}

void Assembler::fneg(const DoubleRegister frt, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FNEG | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::mtfsb0(FPSCRBit bit, RCBit rc) {
  DCHECK_LT(static_cast<int>(bit), 32);
  int bt = bit;
  emit(EXT4 | MTFSB0 | bt * B21 | rc);
}

void Assembler::mtfsb1(FPSCRBit bit, RCBit rc) {
  DCHECK_LT(static_cast<int>(bit), 32);
  int bt = bit;
  emit(EXT4 | MTFSB1 | bt * B21 | rc);
}

void Assembler::mtfsfi(int bf, int immediate, RCBit rc) {
  emit(EXT4 | MTFSFI | bf * B23 | immediate * B12 | rc);
}

void Assembler::mffs(const DoubleRegister frt, RCBit rc) {
  emit(EXT4 | MFFS | frt.code() * B21 | rc);
}

void Assembler::mtfsf(const DoubleRegister frb, bool L, int FLM, bool W,
                      RCBit rc) {
  emit(EXT4 | MTFSF | frb.code() * B11 | W * B16 | FLM * B17 | L * B25 | rc);
}

void Assembler::fsqrt(const DoubleRegister frt, const DoubleRegister frb,
                      RCBit rc) {
  emit(EXT4 | FSQRT | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fabs(const DoubleRegister frt, const DoubleRegister frb,
                     RCBit rc) {
  emit(EXT4 | FABS | frt.code() * B21 | frb.code() * B11 | rc);
}

void Assembler::fmadd(const DoubleRegister frt, const DoubleRegister fra,
                      const DoubleRegister frc, const DoubleRegister frb,
                      RCBit rc) {
  emit(EXT4 | FMADD | frt.code() * B21 | fra.code() * B16 | frb.code() * B11 |
       frc.code() * B6 | rc);
}

void Assembler::fmsub(const DoubleRegister frt, const DoubleRegister fra,
                      const DoubleRegister frc, const DoubleRegister frb,
                      RCBit rc) {
  emit(EXT4 | FMSUB | frt.code() * B21 | fra.code() * B16 | frb.code() * B11 |
       frc.code() * B6 | rc);
}

// Vector instructions
void Assembler::mfvsrd(const Register ra, const Simd128Register rs) {
  int SX = 1;
  emit(MFVSRD | rs.code() * B21 | ra.code() * B16 | SX);
}

void Assembler::mfvsrwz(const Register ra, const Simd128Register rs) {
  int SX = 1;
  emit(MFVSRWZ | rs.code() * B21 | ra.code() * B16 | SX);
}

void Assembler::mtvsrd(const Simd128Register rt, const Register ra) {
  int TX = 1;
  emit(MTVSRD | rt.code() * B21 | ra.code() * B16 | TX);
}

void Assembler::mtvsrdd(const Simd128Register rt, const Register ra,
                        const Register rb) {
  int TX = 1;
  emit(MTVSRDD | rt.code() * B21 | ra.code() * B16 | rb.code() * B11 | TX);
}

void Assembler::lxvd(const Simd128Register rt, const MemOperand& src) {
  CHECK(src.rb().is_valid());
  int TX = 1;
  emit(LXVD | rt.code() * B21 | src.ra().code() * B16 | src.rb().code() * B11 |
       TX);
}

void Assembler::lxvx(const Simd128Register rt, const MemOperand& src) {
  CHECK(src.rb().is_valid());
  int TX = 1;
  emit(LXVX | rt.code() * B21 | src.ra().code() * B16 | src.rb().code() * B11 |
       TX);
}

void Assembler::lxsdx(const Simd128Register rt, const MemOperand& src) {
  CHECK(src.rb().is_valid());
  int TX = 1;
  emit(LXSDX | rt.code() * B21 | src.ra().code() * B16 | src.rb().code() * B11 |
       TX);
}

void Assembler::lxsibzx(const Simd128Register rt, const MemOperand& src) {
  CHECK(src.rb().is_valid());
  int TX = 1;
  emit(LXSIBZX | rt.code() * B21 | src.ra().code() * B16 |
       src.rb().code() * B11 | TX);
}

void Assembler::lxsihzx(const Simd128Register rt, const MemOperand& src) 
"""


```