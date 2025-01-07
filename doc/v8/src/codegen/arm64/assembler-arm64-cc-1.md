Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/arm64/assembler-arm64.cc`.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the Core Functionality:** The code consists of many methods within the `Assembler` class. These methods seem to correspond to ARM64 assembly instructions. The core function is clearly to *emit* or generate these assembly instructions.

2. **Categorize the Instructions:**  Scan through the method names and their implementations. Notice patterns:
    * **Branching:** `b`, `bl`, `cbz`, `cbnz`, `tbz`, `tbnz`, `adr`.
    * **Arithmetic/Logical:** `add`, `adds`, `sub`, `subs`, `cmn`, `cmp`, `neg`, `negs`, `adc`, `adcs`, `sbc`, `sbcs`, `ngc`, `ngcs`, `and_`, `ands`, `orr`, `orn`, `eor`, `eon`, `lslv`, `lsrv`, `asrv`, `rorv`.
    * **Bit Manipulation:** `bfm`, `sbfm`, `ubfm`, `extr`, `rbit`, `rev`, `clz`, `cls`.
    * **Conditional Operations:** `csel`, `csinc`, `csinv`, `csneg`, `cset`, `csetm`, `cinc`, `cinv`, `cneg`, `ccmn`, `ccmp`.
    * **Multiplication/Division:** `mul`, `madd`, `mneg`, `msub`, `smaddl`, `smsubl`, `umaddl`, `umsubl`, `smull`, `smulh`, `umulh`, `sdiv`, `udiv`.
    * **Memory Access:** `ldp`, `stp`, `ldpsw`, `ldrb`, `strb`, `ldrsb`, `ldrh`, `strh`, `ldrsh`, `ldr`, `str`, `ldrsw`, `ldar`, `ldaxr`, `stlr`, `stlxr`, and their byte/half-word variants, and atomic operations like `cas`, `ldadd`, `stclr`, etc.
    * **SIMD (NEON):** Methods starting with `NEON` like `sdot`, `saddl`, `trn1`, `zip1`, etc.

3. **Determine the File Type:** The prompt explicitly states: "如果v8/src/codegen/arm64/assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码". Since the filename ends with `.cc`, it's a C++ source file, *not* a Torque file.

4. **Relate to JavaScript:**  Consider how these low-level assembly instructions relate to JavaScript. JavaScript code gets compiled into machine code. The `Assembler` class is used during this compilation process to generate the ARM64 instructions that will eventually be executed by the processor. Simple arithmetic operations, comparisons, and memory accesses in JavaScript will translate to these assembly instructions.

5. **Provide JavaScript Examples:** Create simple JavaScript snippets that would likely involve the generated assembly instructions. For example, `+`, `-`, `*`, `/`, `<`, `>`, `&&`, `||`, accessing array elements, and object properties.

6. **Illustrate Code Logic and Input/Output:** Choose a simple method, like `add`, and demonstrate its functionality with hypothetical register inputs and the resulting output register. This shows the direct effect of the assembly instruction.

7. **Identify Common Programming Errors:** Think about mistakes developers make that relate to the *effects* of these instructions. Off-by-one errors leading to incorrect memory access, incorrect assumptions about register values after an operation, and neglecting potential overflow are relevant examples.

8. **Summarize the Functionality (Part 2):** Focus on the instructions present in the provided snippet. Group them into logical categories (arithmetic, logical, bit manipulation, conditional, multiplication/division, and basic memory operations excluding pairs and atomics, which will likely be in later parts).

9. **Review and Refine:**  Read through the generated answer to ensure clarity, accuracy, and completeness based on the provided code snippet and the user's prompt. Ensure the JavaScript examples are simple and illustrative. Double-check the assumptions and input/output examples. Make sure the common errors are relevant to the presented instructions. Confirm the summarization accurately reflects the code in Part 2.
这是v8源代码文件 `v8/src/codegen/arm64/assembler-arm64.cc` 的第二部分代码。延续第一部分的分析，这部分代码继续定义了 `Assembler` 类中用于生成 ARM64 汇编指令的方法。

**功能归纳 (第二部分):**

这部分代码主要定义了以下功能的汇编指令生成方法：

1. **条件分支指令:**
   - `cbz`:  比较并为零分支 (Compare and Branch if Zero)
   - `cbnz`: 比较并为非零分支 (Compare and Branch if Non-Zero)
   - `tbz`:  测试位并为零分支 (Test bit and Branch if Zero)
   - `tbnz`: 测试位并为非零分支 (Test bit and Branch if Non-Zero)

2. **地址加载指令:**
   - `adr`: 加载程序计数器相对地址 (Address to Register)

3. **空操作指令:**
   - `nop`: 无操作 (No Operation) - 可以用于标记特定用途。

4. **算术运算指令:**
   - `add`: 加法 (Add)
   - `adds`: 加法并设置标志位 (Add and Set Flags)
   - `cmn`: 比较负数 (Compare Negative) - 实际上是加法并设置标志位，结果不保存。
   - `sub`: 减法 (Subtract)
   - `subs`: 减法并设置标志位 (Subtract and Set Flags)
   - `cmp`: 比较 (Compare) - 实际上是减法并设置标志位，结果不保存。
   - `neg`: 取反 (Negate)
   - `negs`: 取反并设置标志位 (Negate and Set Flags)
   - `adc`: 带进位加法 (Add with Carry)
   - `adcs`: 带进位加法并设置标志位 (Add with Carry and Set Flags)
   - `sbc`: 带借位减法 (Subtract with Carry)
   - `sbcs`: 带借位减法并设置标志位 (Subtract with Carry and Set Flags)
   - `ngc`: 带借位取反 (Negate with Carry)
   - `ngcs`: 带借位取反并设置标志位 (Negate with Carry and Set Flags)

5. **逻辑运算指令:**
   - `and_`: 按位与 (Bitwise AND)
   - `ands`: 按位与并设置标志位 (Bitwise AND and Set Flags)
   - `tst`: 位测试 (Test bits) - 实际上是按位与并设置标志位，结果不保存。
   - `bic`: 位清除 (Bit Clear) - 按位与非
   - `bics`: 位清除并设置标志位 (Bit Clear and Set Flags)
   - `orr`: 按位或 (Bitwise OR)
   - `orn`: 按位或非 (Bitwise OR NOT)
   - `eor`: 按位异或 (Bitwise XOR)
   - `eon`: 按位异或非 (Bitwise XOR NOT)

6. **移位运算指令 (变量移位量):**
   - `lslv`: 逻辑左移 (Logical Shift Left Variable)
   - `lsrv`: 逻辑右移 (Logical Shift Right Variable)
   - `asrv`: 算术右移 (Arithmetic Shift Right Variable)
   - `rorv`: 循环右移 (Rotate Right Variable)

7. **位域操作指令:**
   - `bfm`: 位域移动 (Bitfield Move)
   - `sbfm`: 符号位扩展位域移动 (Signed Bitfield Move)
   - `ubfm`: 无符号位扩展位域移动 (Unsigned Bitfield Move)
   - `extr`: 提取位域 (Extract from pair of registers)

8. **条件选择指令:**
   - `csel`: 条件选择 (Conditional Select)
   - `csinc`: 条件选择增一 (Conditional Select Increment)
   - `csinv`: 条件选择取反 (Conditional Select Invert)
   - `csneg`: 条件选择取负 (Conditional Select Negate)
   - `cset`: 条件设置 (Conditional Set to 1 or 0)
   - `csetm`: 条件设置取反 (Conditional Set to 0 or -1)
   - `cinc`: 条件自增 (Conditional Increment)
   - `cinv`: 条件取反 (Conditional Invert)
   - `cneg`: 条件取负 (Conditional Negate)

9. **条件比较指令:**
   - `ccmn`: 条件比较负数 (Conditional Compare Negative)
   - `ccmp`: 条件比较 (Conditional Compare)

10. **三源操作数的数据处理指令:**
    - `mul`: 乘法 (Multiply)
    - `madd`: 乘加 (Multiply-Add)
    - `mneg`: 乘法取负 (Multiply-Negate)
    - `msub`: 乘减 (Multiply-Subtract)
    - `smaddl`: 符号位扩展乘加长整型 (Signed Multiply-Add Long)
    - `smsubl`: 符号位扩展乘减长整型 (Signed Multiply-Subtract Long)
    - `umaddl`: 无符号位扩展乘加长整型 (Unsigned Multiply-Add Long)
    - `umsubl`: 无符号位扩展乘减长整型 (Unsigned Multiply-Subtract Long)
    - `smull`: 符号位扩展乘法长整型 (Signed Multiply Long)
    - `smulh`: 符号位扩展乘法高位 (Signed Multiply High)
    - `umulh`: 无符号位扩展乘法高位 (Unsigned Multiply High)

11. **除法指令:**
    - `sdiv`: 符号位除法 (Signed Divide)
    - `udiv`: 无符号位除法 (Unsigned Divide)

12. **单源操作数的数据处理指令:**
    - `rbit`: 位反转 (Reverse Bits)
    - `rev16`: 反转每 16 位的字节顺序 (Reverse bytes in 16-bit chunks)
    - `rev32`: 反转每 32 位的字节顺序 (Reverse bytes in 32-bit chunks)
    - `rev`: 反转寄存器内的字节顺序 (Reverse the order of bytes in a register)
    - `clz`: 计数前导零 (Count Leading Zeros)
    - `cls`: 计数前导符号位 (Count Leading Sign bits)

13. **指针认证指令 (PAC):**
    - `pacib1716`:  使用密钥 B 对寄存器 I17 的地址进行签名，并将结果放入 I16 (Pointer Authentication Code for Instruction address, using key B)
    - `autib1716`: 使用密钥 B 验证寄存器 I17 的地址 (Authenticate Instruction address, using key B)
    - `pacibsp`:  使用密钥 B 对堆栈指针进行签名 (Pointer Authentication Code for Instruction address, using key B, storing in SP)
    - `autibsp`: 使用密钥 B 验证堆栈指针 (Authenticate Instruction address, using key B, using SP)

14. **分支目标标识 (BTI) 指令:**
    - `bti`:  分支目标指示 (Branch Target Identification) - 用于标记有效的跳转目标。

15. **加载/存储对指令:**
    - `ldp`: 加载一对寄存器 (Load Pair of registers)
    - `stp`: 存储一对寄存器 (Store Pair of registers)
    - `ldpsw`: 加载一对字并符号扩展 (Load Pair of Signed Words)

16. **基本的加载/存储指令 (非成对):**
    - `ldrb`: 加载字节 (Load Register Byte)
    - `strb`: 存储字节 (Store Register Byte)
    - `ldrsb`: 加载符号扩展字节 (Load Register Signed Byte)
    - `ldrh`: 加载半字 (Load Register Halfword)
    - `strh`: 存储半字 (Store Register Halfword)
    - `ldrsh`: 加载符号扩展半字 (Load Register Signed Halfword)
    - `ldr`: 加载字或双字 (Load Register)
    - `str`: 存储字或双字 (Store Register)
    - `ldrsw`: 加载符号扩展字 (Load Register Signed Word)
    - `ldr_pcrel`:  程序计数器相对加载 (Load Register, PC-relative) - 用于加载字面量。

17. **加载字面量指令:**
    - `ldr` (带 `Operand::EmbeddedNumber` 和 `Operand::EmbeddedHeapNumber` 的重载): 用于加载立即数或嵌入的堆对象（如浮点数）。

18. **原子加载/存储指令 (具有 Acquire/Release 语义):**
    - `ldar`: 加载原子寄存器 (Load Acquire Register)
    - `ldaxr`: 加载原子独占寄存器 (Load Acquire Exclusive Register)
    - `stlr`: 存储原子寄存器 (Store Release Register)
    - `stlxr`: 存储原子独占寄存器 (Store Release Exclusive Register)
    - `ldarb`, `ldaxrb`, `stlrb`, `stlxrb`: 字节版本的原子加载/存储。
    - `ldarh`, `ldaxrh`, `stlrh`, `stlxrh`: 半字版本的原子加载/存储。

19. **原子比较和交换指令:**
    - `cas`, `casa`, `casl`, `casal`: 原子比较并交换字或双字 (Compare and Swap)
    - `casb`, `casab`, `caslb`, `casalb`: 原子比较并交换字节。
    - `cash`, `casah`, `caslh`, `casalh`: 原子比较并交换半字。
    - `casp`, `caspa`, `caspl`, `caspal`: 原子比较并交换一对字或双字。

20. **其他原子内存操作指令:**
    - `ldadd`, `ldclr`, `ldeor`, `ldset`, `ldsmax`, `ldsmin`, `ldumax`, `ldumin`: 原子加载并执行操作 (加、清零、异或、设置、有符号最大值、有符号最小值、无符号最大值、无符号最小值)。 对应的存储指令 `stadd`, `stclr` 等。
    - `swp`: 原子交换寄存器内容与内存 (Swap register with memory)。

21. **NEON (SIMD) 指令:**
    - `sdot`: 有符号点积 (Signed Dot Product)
    - `NEON3DifferentL`, `NEON3DifferentW`, `NEON3DifferentHN`: 用于处理不同大小元素的 NEON 指令。
    - `saddl`, `sabal`, `uabal`, `sabdl`, `uabdl`, `smlal`, `umlal`, `smlsl`, `umlsl`, `smull`, `umull`, `ssubl`, `uaddl`, `usubl`, `sqdmlal`, `sqdmlsl`, `sqdmull`:  处理长向量的 NEON 指令。
    - `addhn`, `raddhn`, `subhn`, `rsubhn`:  缩小和舍入的 NEON 指令。
    - `NEONPerm`:  NEON 排列指令的基础方法。
    - `trn1`, `trn2`, `uzp1`, `uzp2`, `zip1`, `zip2`:  NEON 转置和交错指令。
    - `NEONShiftImmediate`:  带立即数移位的 NEON 指令。

**关于文件类型:**

正如您所说，如果 `v8/src/codegen/arm64/assembler-arm64.cc` 以 `.tq` 结尾，它将是一个 V8 Torque 源代码文件。然而，由于它以 `.cc` 结尾，它是一个 **C++ 源代码文件**。

**与 JavaScript 的关系及示例:**

`assembler-arm64.cc` 中的代码直接负责将 V8 的中间表示 (IR) 或其他形式的编译输出转换为实际的 ARM64 机器码。  当 JavaScript 代码执行时，V8 的编译器 (TurboFan, Crankshaft 等) 会生成这些汇编指令。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let x = 10;
let y = 5;
let sum = add(x, y); // 这里会调用生成的汇编代码
console.log(sum);

let arr = [1, 2, 3];
let first = arr[0]; // 访问数组元素也会生成汇编代码

if (x > y) {      // 条件判断会生成条件分支指令
  console.log("x is greater than y");
}
```

在 V8 编译上述 JavaScript 代码时，`Assembler` 类中的方法会被调用来生成相应的 ARM64 指令：

- `a + b` 可能会生成 `add` 或 `adds` 指令。
- 数组元素访问 `arr[0]` 可能会生成 `ldr` 指令。
- `x > y` 可能会生成 `cmp` 指令和条件分支指令（如 `b.gt`，它会用到 `cbz` 或 `cbnz` 的概念）。

**代码逻辑推理和假设输入/输出:**

以 `add` 指令为例：

```c++
void Assembler::add(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSub(rd, rn, operand, LeaveFlags, ADD);
}
```

**假设输入:**

- `rd`: 寄存器 `x0`
- `rn`: 寄存器 `x1`，假设其值为 5
- `operand`:  `Immediate(10)`，表示立即数 10

**输出:**

生成的 ARM64 汇编指令会执行 `x0 = x1 + 10`。 因此，寄存器 `x0` 的值将变为 15。

**用户常见的编程错误:**

1. **位运算理解错误：**  不理解按位与、或、异或的真正作用，导致逻辑错误。例如，错误地使用按位与来检查多个标志位是否都被设置。

   ```javascript
   // 错误示例：期望检查 FLAG_A 和 FLAG_B 是否都被设置
   const FLAG_A = 1; // 0001
   const FLAG_B = 2; // 0010
   let flags = 3;    // 0011

   if (flags & (FLAG_A && FLAG_B)) { // 错误的用法，&& 会先进行逻辑与
     console.log("Both flags are set");
   }

   // 正确示例：使用按位与
   if ((flags & FLAG_A) && (flags & FLAG_B)) {
     console.log("Both flags are set");
   }
   ```

   在汇编层面，这涉及到 `and_` 指令的使用。错误的逻辑会导致生成的汇编代码无法实现预期的功能.

2. **条件分支使用不当：**  混淆有符号和无符号比较，或者条件码使用错误，导致程序流程错误。

   ```javascript
   let a = -1;
   let b = 1;

   if (a > b) { // 在某些上下文中，有符号比较可能与预期不符
     console.log("a is greater than b");
   }
   ```

   这会影响到 `cbz`, `cbnz`, 以及其他条件分支指令的生成和行为。

3. **内存访问越界：**  在数组或缓冲区操作中，索引计算错误导致访问到非法内存地址，这会在汇编层面生成错误的 `ldr` 或 `str` 指令，可能导致程序崩溃。

   ```javascript
   let arr = [1, 2, 3];
   console.log(arr[10]); // 越界访问
   ```

   虽然 JavaScript 引擎通常会进行边界检查，但在某些底层操作或优化中，这种错误可能导致问题。

总而言之，这部分 `assembler-arm64.cc` 代码是 V8 引擎中至关重要的一部分，它定义了生成各种 ARM64 汇编指令的能力，这些指令是执行 JavaScript 代码的基础。理解这些指令的功能有助于深入理解 JavaScript 引擎的工作原理和性能优化。

Prompt: 
```
这是目录为v8/src/codegen/arm64/assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
ts)));
  Emit(TBNZ | ImmTestBranchBit(bit_pos) | ImmTestBranch(imm14) | Rt(rt));
}

void Assembler::tbnz(const Register& rt, unsigned bit_pos, Label* label) {
  tbnz(rt, bit_pos, LinkAndGetBranchInstructionOffsetTo(label));
}

void Assembler::adr(const Register& rd, int imm21) {
  DCHECK(rd.Is64Bits());
  Emit(ADR | ImmPCRelAddress(imm21) | Rd(rd));
}

void Assembler::adr(const Register& rd, Label* label) {
  adr(rd, LinkAndGetByteOffsetTo(label));
}

void Assembler::nop(NopMarkerTypes n) {
  DCHECK((FIRST_NOP_MARKER <= n) && (n <= LAST_NOP_MARKER));
  mov(Register::XRegFromCode(n), Register::XRegFromCode(n));
}

void Assembler::add(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSub(rd, rn, operand, LeaveFlags, ADD);
}

void Assembler::adds(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSub(rd, rn, operand, SetFlags, ADD);
}

void Assembler::cmn(const Register& rn, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rn);
  adds(zr, rn, operand);
}

void Assembler::sub(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSub(rd, rn, operand, LeaveFlags, SUB);
}

void Assembler::subs(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSub(rd, rn, operand, SetFlags, SUB);
}

void Assembler::cmp(const Register& rn, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rn);
  subs(zr, rn, operand);
}

void Assembler::neg(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  sub(rd, zr, operand);
}

void Assembler::negs(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  subs(rd, zr, operand);
}

void Assembler::adc(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, LeaveFlags, ADC);
}

void Assembler::adcs(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, SetFlags, ADC);
}

void Assembler::sbc(const Register& rd, const Register& rn,
                    const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, LeaveFlags, SBC);
}

void Assembler::sbcs(const Register& rd, const Register& rn,
                     const Operand& operand) {
  AddSubWithCarry(rd, rn, operand, SetFlags, SBC);
}

void Assembler::ngc(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  sbc(rd, zr, operand);
}

void Assembler::ngcs(const Register& rd, const Operand& operand) {
  Register zr = AppropriateZeroRegFor(rd);
  sbcs(rd, zr, operand);
}

// Logical instructions.
void Assembler::and_(const Register& rd, const Register& rn,
                     const Operand& operand) {
  Logical(rd, rn, operand, AND);
}

void Assembler::ands(const Register& rd, const Register& rn,
                     const Operand& operand) {
  Logical(rd, rn, operand, ANDS);
}

void Assembler::tst(const Register& rn, const Operand& operand) {
  ands(AppropriateZeroRegFor(rn), rn, operand);
}

void Assembler::bic(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, BIC);
}

void Assembler::bics(const Register& rd, const Register& rn,
                     const Operand& operand) {
  Logical(rd, rn, operand, BICS);
}

void Assembler::orr(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, ORR);
}

void Assembler::orn(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, ORN);
}

void Assembler::eor(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, EOR);
}

void Assembler::eon(const Register& rd, const Register& rn,
                    const Operand& operand) {
  Logical(rd, rn, operand, EON);
}

void Assembler::lslv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | LSLV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::lsrv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | LSRV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::asrv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | ASRV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::rorv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | RORV | Rm(rm) | Rn(rn) | Rd(rd));
}

// Bitfield operations.
void Assembler::bfm(const Register& rd, const Register& rn, int immr,
                    int imms) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | BFM | N | ImmR(immr, rd.SizeInBits()) |
       ImmS(imms, rn.SizeInBits()) | Rn(rn) | Rd(rd));
}

void Assembler::sbfm(const Register& rd, const Register& rn, int immr,
                     int imms) {
  DCHECK(rd.Is64Bits() || rn.Is32Bits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | SBFM | N | ImmR(immr, rd.SizeInBits()) |
       ImmS(imms, rn.SizeInBits()) | Rn(rn) | Rd(rd));
}

void Assembler::ubfm(const Register& rd, const Register& rn, int immr,
                     int imms) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | UBFM | N | ImmR(immr, rd.SizeInBits()) |
       ImmS(imms, rn.SizeInBits()) | Rn(rn) | Rd(rd));
}

void Assembler::extr(const Register& rd, const Register& rn, const Register& rm,
                     int lsb) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Instr N = SF(rd) >> (kSFOffset - kBitfieldNOffset);
  Emit(SF(rd) | EXTR | N | Rm(rm) | ImmS(lsb, rn.SizeInBits()) | Rn(rn) |
       Rd(rd));
}

void Assembler::csel(const Register& rd, const Register& rn, const Register& rm,
                     Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSEL);
}

void Assembler::csinc(const Register& rd, const Register& rn,
                      const Register& rm, Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSINC);
}

void Assembler::csinv(const Register& rd, const Register& rn,
                      const Register& rm, Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSINV);
}

void Assembler::csneg(const Register& rd, const Register& rn,
                      const Register& rm, Condition cond) {
  ConditionalSelect(rd, rn, rm, cond, CSNEG);
}

void Assembler::cset(const Register& rd, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  Register zr = AppropriateZeroRegFor(rd);
  csinc(rd, zr, zr, NegateCondition(cond));
}

void Assembler::csetm(const Register& rd, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  Register zr = AppropriateZeroRegFor(rd);
  csinv(rd, zr, zr, NegateCondition(cond));
}

void Assembler::cinc(const Register& rd, const Register& rn, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  csinc(rd, rn, rn, NegateCondition(cond));
}

void Assembler::cinv(const Register& rd, const Register& rn, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  csinv(rd, rn, rn, NegateCondition(cond));
}

void Assembler::cneg(const Register& rd, const Register& rn, Condition cond) {
  DCHECK((cond != al) && (cond != nv));
  csneg(rd, rn, rn, NegateCondition(cond));
}

void Assembler::ConditionalSelect(const Register& rd, const Register& rn,
                                  const Register& rm, Condition cond,
                                  ConditionalSelectOp op) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | op | Rm(rm) | Cond(cond) | Rn(rn) | Rd(rd));
}

void Assembler::ccmn(const Register& rn, const Operand& operand,
                     StatusFlags nzcv, Condition cond) {
  ConditionalCompare(rn, operand, nzcv, cond, CCMN);
}

void Assembler::ccmp(const Register& rn, const Operand& operand,
                     StatusFlags nzcv, Condition cond) {
  ConditionalCompare(rn, operand, nzcv, cond, CCMP);
}

void Assembler::DataProcessing3Source(const Register& rd, const Register& rn,
                                      const Register& rm, const Register& ra,
                                      DataProcessing3SourceOp op) {
  Emit(SF(rd) | op | Rm(rm) | Ra(ra) | Rn(rn) | Rd(rd));
}

void Assembler::mul(const Register& rd, const Register& rn,
                    const Register& rm) {
  DCHECK(AreSameSizeAndType(rd, rn, rm));
  Register zr = AppropriateZeroRegFor(rn);
  DataProcessing3Source(rd, rn, rm, zr, MADD);
}

void Assembler::madd(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra) {
  DCHECK(AreSameSizeAndType(rd, rn, rm, ra));
  DataProcessing3Source(rd, rn, rm, ra, MADD);
}

void Assembler::mneg(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(AreSameSizeAndType(rd, rn, rm));
  Register zr = AppropriateZeroRegFor(rn);
  DataProcessing3Source(rd, rn, rm, zr, MSUB);
}

void Assembler::msub(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra) {
  DCHECK(AreSameSizeAndType(rd, rn, rm, ra));
  DataProcessing3Source(rd, rn, rm, ra, MSUB);
}

void Assembler::smaddl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, SMADDL_x);
}

void Assembler::smsubl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, SMSUBL_x);
}

void Assembler::umaddl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, UMADDL_x);
}

void Assembler::umsubl(const Register& rd, const Register& rn,
                       const Register& rm, const Register& ra) {
  DCHECK(rd.Is64Bits() && ra.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, ra, UMSUBL_x);
}

void Assembler::smull(const Register& rd, const Register& rn,
                      const Register& rm) {
  DCHECK(rd.Is64Bits());
  DCHECK(rn.Is32Bits() && rm.Is32Bits());
  DataProcessing3Source(rd, rn, rm, xzr, SMADDL_x);
}

void Assembler::smulh(const Register& rd, const Register& rn,
                      const Register& rm) {
  DCHECK(rd.Is64Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rm.Is64Bits());
  DataProcessing3Source(rd, rn, rm, xzr, SMULH_x);
}

void Assembler::umulh(const Register& rd, const Register& rn,
                      const Register& rm) {
  DCHECK(rd.Is64Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rm.Is64Bits());
  DataProcessing3Source(rd, rn, rm, xzr, UMULH_x);
}

void Assembler::sdiv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | SDIV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::udiv(const Register& rd, const Register& rn,
                     const Register& rm) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  DCHECK(rd.SizeInBits() == rm.SizeInBits());
  Emit(SF(rd) | UDIV | Rm(rm) | Rn(rn) | Rd(rd));
}

void Assembler::rbit(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, RBIT);
}

void Assembler::rev16(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, REV16);
}

void Assembler::rev32(const Register& rd, const Register& rn) {
  DCHECK(rd.Is64Bits());
  DataProcessing1Source(rd, rn, REV);
}

void Assembler::rev(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, rd.Is64Bits() ? REV_x : REV_w);
}

void Assembler::clz(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, CLZ);
}

void Assembler::cls(const Register& rd, const Register& rn) {
  DataProcessing1Source(rd, rn, CLS);
}

void Assembler::pacib1716() { Emit(PACIB1716); }
void Assembler::autib1716() { Emit(AUTIB1716); }
void Assembler::pacibsp() { Emit(PACIBSP); }
void Assembler::autibsp() { Emit(AUTIBSP); }

void Assembler::bti(BranchTargetIdentifier id) {
  SystemHint op;
  switch (id) {
    case BranchTargetIdentifier::kBti:
      op = BTI;
      break;
    case BranchTargetIdentifier::kBtiCall:
      op = BTI_c;
      break;
    case BranchTargetIdentifier::kBtiJump:
      op = BTI_j;
      break;
    case BranchTargetIdentifier::kBtiJumpCall:
      op = BTI_jc;
      break;
    case BranchTargetIdentifier::kNone:
    case BranchTargetIdentifier::kPacibsp:
      // We always want to generate a BTI instruction here, so disallow
      // skipping its generation or generating a PACIBSP instead.
      UNREACHABLE();
  }
  hint(op);
}

void Assembler::ldp(const CPURegister& rt, const CPURegister& rt2,
                    const MemOperand& src) {
  LoadStorePair(rt, rt2, src, LoadPairOpFor(rt, rt2));
}

void Assembler::stp(const CPURegister& rt, const CPURegister& rt2,
                    const MemOperand& dst) {
  LoadStorePair(rt, rt2, dst, StorePairOpFor(rt, rt2));

#if defined(V8_OS_WIN)
  if (xdata_encoder_ && rt == x29 && rt2 == lr && dst.base().IsSP()) {
    xdata_encoder_->onSaveFpLr();
  }
#endif
}

void Assembler::ldpsw(const Register& rt, const Register& rt2,
                      const MemOperand& src) {
  DCHECK(rt.Is64Bits());
  LoadStorePair(rt, rt2, src, LDPSW_x);
}

void Assembler::LoadStorePair(const CPURegister& rt, const CPURegister& rt2,
                              const MemOperand& addr, LoadStorePairOp op) {
  // 'rt' and 'rt2' can only be aliased for stores.
  DCHECK(((op & LoadStorePairLBit) == 0) || rt != rt2);
  DCHECK(AreSameSizeAndType(rt, rt2));
  DCHECK(IsImmLSPair(addr.offset(), CalcLSPairDataSize(op)));
  int offset = static_cast<int>(addr.offset());

  Instr memop = op | Rt(rt) | Rt2(rt2) | RnSP(addr.base()) |
                ImmLSPair(offset, CalcLSPairDataSize(op));

  Instr addrmodeop;
  if (addr.IsImmediateOffset()) {
    addrmodeop = LoadStorePairOffsetFixed;
  } else {
    // Pre-index and post-index modes.
    DCHECK_NE(rt, addr.base());
    DCHECK_NE(rt2, addr.base());
    DCHECK_NE(addr.offset(), 0);
    if (addr.IsPreIndex()) {
      addrmodeop = LoadStorePairPreIndexFixed;
    } else {
      DCHECK(addr.IsPostIndex());
      addrmodeop = LoadStorePairPostIndexFixed;
    }
  }
  Emit(addrmodeop | memop);
}

// Memory instructions.
void Assembler::ldrb(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, LDRB_w);
}

void Assembler::strb(const Register& rt, const MemOperand& dst) {
  LoadStore(rt, dst, STRB_w);
}

void Assembler::ldrsb(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, rt.Is64Bits() ? LDRSB_x : LDRSB_w);
}

void Assembler::ldrh(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, LDRH_w);
}

void Assembler::strh(const Register& rt, const MemOperand& dst) {
  LoadStore(rt, dst, STRH_w);
}

void Assembler::ldrsh(const Register& rt, const MemOperand& src) {
  LoadStore(rt, src, rt.Is64Bits() ? LDRSH_x : LDRSH_w);
}

void Assembler::ldr(const CPURegister& rt, const MemOperand& src) {
  LoadStore(rt, src, LoadOpFor(rt));
}

void Assembler::str(const CPURegister& rt, const MemOperand& src) {
  LoadStore(rt, src, StoreOpFor(rt));
}

void Assembler::ldrsw(const Register& rt, const MemOperand& src) {
  DCHECK(rt.Is64Bits());
  LoadStore(rt, src, LDRSW_x);
}

void Assembler::ldr_pcrel(const CPURegister& rt, int imm19) {
  // The pattern 'ldr xzr, #offset' is used to indicate the beginning of a
  // constant pool. It should not be emitted.
  DCHECK(!rt.IsZero());
  Emit(LoadLiteralOpFor(rt) | ImmLLiteral(imm19) | Rt(rt));
}

Operand Operand::EmbeddedNumber(double number) {
  int32_t smi;
  if (DoubleToSmiInteger(number, &smi)) {
    return Operand(Immediate(Smi::FromInt(smi)));
  }
  return EmbeddedHeapNumber(number);
}

Operand Operand::EmbeddedHeapNumber(double number) {
  Operand result(0, RelocInfo::FULL_EMBEDDED_OBJECT);
  result.heap_number_request_.emplace(number);
  DCHECK(result.IsHeapNumberRequest());
  return result;
}

void Assembler::ldr(const CPURegister& rt, const Operand& operand) {
  if (operand.IsHeapNumberRequest()) {
    BlockPoolsScope no_pool_before_ldr_of_heap_number_request(this);
    RequestHeapNumber(operand.heap_number_request());
    ldr(rt, operand.immediate_for_heap_number_request());
  } else {
    ldr(rt, operand.immediate());
  }
}

void Assembler::ldr(const CPURegister& rt, const Immediate& imm) {
  BlockPoolsScope no_pool_before_ldr_pcrel_instr(this);
  RecordRelocInfo(imm.rmode(), imm.value());
  // The load will be patched when the constpool is emitted, patching code
  // expect a load literal with offset 0.
  ldr_pcrel(rt, 0);
}

void Assembler::ldar(const Register& rt, const Register& rn) {
  DCHECK(rn.Is64Bits());
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? LDAR_w : LDAR_x;
  Emit(op | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldaxr(const Register& rt, const Register& rn) {
  DCHECK(rn.Is64Bits());
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? LDAXR_w : LDAXR_x;
  Emit(op | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlr(const Register& rt, const Register& rn) {
  DCHECK(rn.Is64Bits());
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? STLR_w : STLR_x;
  Emit(op | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlxr(const Register& rs, const Register& rt,
                      const Register& rn) {
  DCHECK(rn.Is64Bits());
  DCHECK(rs != rt && rs != rn);
  LoadStoreAcquireReleaseOp op = rt.Is32Bits() ? STLXR_w : STLXR_x;
  Emit(op | Rs(rs) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldarb(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAR_b | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldaxrb(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAXR_b | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlrb(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(STLR_b | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlxrb(const Register& rs, const Register& rt,
                       const Register& rn) {
  DCHECK(rs.Is32Bits());
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rs != rt && rs != rn);
  Emit(STLXR_b | Rs(rs) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldarh(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAR_h | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::ldaxrh(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(LDAXR_h | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlrh(const Register& rt, const Register& rn) {
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  Emit(STLR_h | Rs(x31) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

void Assembler::stlxrh(const Register& rs, const Register& rt,
                       const Register& rn) {
  DCHECK(rs.Is32Bits());
  DCHECK(rt.Is32Bits());
  DCHECK(rn.Is64Bits());
  DCHECK(rs != rt && rs != rn);
  Emit(STLXR_h | Rs(rs) | Rt2(x31) | RnSP(rn) | Rt(rt));
}

#define COMPARE_AND_SWAP_W_X_LIST(V) \
  V(cas, CAS)                        \
  V(casa, CASA)                      \
  V(casl, CASL)                      \
  V(casal, CASAL)

#define DEFINE_ASM_FUNC(FN, OP)                                     \
  void Assembler::FN(const Register& rs, const Register& rt,        \
                     const MemOperand& src) {                       \
    DCHECK(IsEnabled(LSE));                                         \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));         \
    LoadStoreAcquireReleaseOp op = rt.Is64Bits() ? OP##_x : OP##_w; \
    Emit(op | Rs(rs) | Rt(rt) | Rt2_mask | RnSP(src.base()));       \
  }
COMPARE_AND_SWAP_W_X_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define COMPARE_AND_SWAP_W_LIST(V) \
  V(casb, CASB)                    \
  V(casab, CASAB)                  \
  V(caslb, CASLB)                  \
  V(casalb, CASALB)                \
  V(cash, CASH)                    \
  V(casah, CASAH)                  \
  V(caslh, CASLH)                  \
  V(casalh, CASALH)

#define DEFINE_ASM_FUNC(FN, OP)                               \
  void Assembler::FN(const Register& rs, const Register& rt,  \
                     const MemOperand& src) {                 \
    DCHECK(IsEnabled(LSE));                                   \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));   \
    Emit(OP | Rs(rs) | Rt(rt) | Rt2_mask | RnSP(src.base())); \
  }
COMPARE_AND_SWAP_W_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define COMPARE_AND_SWAP_PAIR_LIST(V) \
  V(casp, CASP)                       \
  V(caspa, CASPA)                     \
  V(caspl, CASPL)                     \
  V(caspal, CASPAL)

#define DEFINE_ASM_FUNC(FN, OP)                                     \
  void Assembler::FN(const Register& rs, const Register& rs1,       \
                     const Register& rt, const Register& rt1,       \
                     const MemOperand& src) {                       \
    DCHECK(IsEnabled(LSE));                                         \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));         \
    DCHECK(AreEven(rs, rt));                                        \
    DCHECK(AreConsecutive(rs, rs1));                                \
    DCHECK(AreConsecutive(rt, rt1));                                \
    DCHECK(AreSameFormat(rs, rs1, rt, rt1));                        \
    LoadStoreAcquireReleaseOp op = rt.Is64Bits() ? OP##_x : OP##_w; \
    Emit(op | Rs(rs) | Rt(rt) | Rt2_mask | RnSP(src.base()));       \
  }
COMPARE_AND_SWAP_PAIR_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

// These macros generate all the variations of the atomic memory operations,
// e.g. ldadd, ldadda, ldaddb, staddl, etc.
// For a full list of the methods with comments, see the assembler header file.

#define ATOMIC_MEMORY_SIMPLE_OPERATION_LIST(V, DEF) \
  V(DEF, add, LDADD)                                \
  V(DEF, clr, LDCLR)                                \
  V(DEF, eor, LDEOR)                                \
  V(DEF, set, LDSET)                                \
  V(DEF, smax, LDSMAX)                              \
  V(DEF, smin, LDSMIN)                              \
  V(DEF, umax, LDUMAX)                              \
  V(DEF, umin, LDUMIN)

#define ATOMIC_MEMORY_STORE_MODES(V, NAME, OP) \
  V(NAME, OP##_x, OP##_w)                      \
  V(NAME##l, OP##L_x, OP##L_w)                 \
  V(NAME##b, OP##B, OP##B)                     \
  V(NAME##lb, OP##LB, OP##LB)                  \
  V(NAME##h, OP##H, OP##H)                     \
  V(NAME##lh, OP##LH, OP##LH)

#define ATOMIC_MEMORY_LOAD_MODES(V, NAME, OP) \
  ATOMIC_MEMORY_STORE_MODES(V, NAME, OP)      \
  V(NAME##a, OP##A_x, OP##A_w)                \
  V(NAME##al, OP##AL_x, OP##AL_w)             \
  V(NAME##ab, OP##AB, OP##AB)                 \
  V(NAME##alb, OP##ALB, OP##ALB)              \
  V(NAME##ah, OP##AH, OP##AH)                 \
  V(NAME##alh, OP##ALH, OP##ALH)

#define DEFINE_ASM_LOAD_FUNC(FN, OP_X, OP_W)                     \
  void Assembler::ld##FN(const Register& rs, const Register& rt, \
                         const MemOperand& src) {                \
    DCHECK(IsEnabled(LSE));                                      \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));      \
    AtomicMemoryOp op = rt.Is64Bits() ? OP_X : OP_W;             \
    Emit(op | Rs(rs) | Rt(rt) | RnSP(src.base()));               \
  }
#define DEFINE_ASM_STORE_FUNC(FN, OP_X, OP_W)                         \
  void Assembler::st##FN(const Register& rs, const MemOperand& src) { \
    DCHECK(IsEnabled(LSE));                                           \
    ld##FN(rs, AppropriateZeroRegFor(rs), src);                       \
  }

ATOMIC_MEMORY_SIMPLE_OPERATION_LIST(ATOMIC_MEMORY_LOAD_MODES,
                                    DEFINE_ASM_LOAD_FUNC)
ATOMIC_MEMORY_SIMPLE_OPERATION_LIST(ATOMIC_MEMORY_STORE_MODES,
                                    DEFINE_ASM_STORE_FUNC)

#define DEFINE_ASM_SWP_FUNC(FN, OP_X, OP_W)                  \
  void Assembler::FN(const Register& rs, const Register& rt, \
                     const MemOperand& src) {                \
    DCHECK(IsEnabled(LSE));                                  \
    DCHECK(src.IsImmediateOffset() && (src.offset() == 0));  \
    AtomicMemoryOp op = rt.Is64Bits() ? OP_X : OP_W;         \
    Emit(op | Rs(rs) | Rt(rt) | RnSP(src.base()));           \
  }

ATOMIC_MEMORY_LOAD_MODES(DEFINE_ASM_SWP_FUNC, swp, SWP)

#undef DEFINE_ASM_LOAD_FUNC
#undef DEFINE_ASM_STORE_FUNC
#undef DEFINE_ASM_SWP_FUNC

void Assembler::sdot(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  DCHECK(IsEnabled(DOTPROD));
  DCHECK((vn.Is16B() && vd.Is4S()) || (vn.Is8B() && vd.Is2S()));
  DCHECK(AreSameFormat(vn, vm));
  Emit(VFormat(vd) | NEON_SDOT | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEON3DifferentL(const VRegister& vd, const VRegister& vn,
                                const VRegister& vm, NEON3DifferentOp vop) {
  DCHECK(AreSameFormat(vn, vm));
  DCHECK((vn.Is1H() && vd.Is1S()) || (vn.Is1S() && vd.Is1D()) ||
         (vn.Is8B() && vd.Is8H()) || (vn.Is4H() && vd.Is4S()) ||
         (vn.Is2S() && vd.Is2D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Instr format, op = vop;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
    format = SFormat(vn);
  } else {
    format = VFormat(vn);
  }
  Emit(format | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEON3DifferentW(const VRegister& vd, const VRegister& vn,
                                const VRegister& vm, NEON3DifferentOp vop) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK((vm.Is8B() && vd.Is8H()) || (vm.Is4H() && vd.Is4S()) ||
         (vm.Is2S() && vd.Is2D()) || (vm.Is16B() && vd.Is8H()) ||
         (vm.Is8H() && vd.Is4S()) || (vm.Is4S() && vd.Is2D()));
  Emit(VFormat(vm) | vop | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEON3DifferentHN(const VRegister& vd, const VRegister& vn,
                                 const VRegister& vm, NEON3DifferentOp vop) {
  DCHECK(AreSameFormat(vm, vn));
  DCHECK((vd.Is8B() && vn.Is8H()) || (vd.Is4H() && vn.Is4S()) ||
         (vd.Is2S() && vn.Is2D()) || (vd.Is16B() && vn.Is8H()) ||
         (vd.Is8H() && vn.Is4S()) || (vd.Is4S() && vn.Is2D()));
  Emit(VFormat(vd) | vop | Rm(vm) | Rn(vn) | Rd(vd));
}

#define NEON_3DIFF_LONG_LIST(V)                                                \
  V(saddl, NEON_SADDL, vn.IsVector() && vn.IsD())                              \
  V(saddl2, NEON_SADDL2, vn.IsVector() && vn.IsQ())                            \
  V(sabal, NEON_SABAL, vn.IsVector() && vn.IsD())                              \
  V(sabal2, NEON_SABAL2, vn.IsVector() && vn.IsQ())                            \
  V(uabal, NEON_UABAL, vn.IsVector() && vn.IsD())                              \
  V(uabal2, NEON_UABAL2, vn.IsVector() && vn.IsQ())                            \
  V(sabdl, NEON_SABDL, vn.IsVector() && vn.IsD())                              \
  V(sabdl2, NEON_SABDL2, vn.IsVector() && vn.IsQ())                            \
  V(uabdl, NEON_UABDL, vn.IsVector() && vn.IsD())                              \
  V(uabdl2, NEON_UABDL2, vn.IsVector() && vn.IsQ())                            \
  V(smlal, NEON_SMLAL, vn.IsVector() && vn.IsD())                              \
  V(smlal2, NEON_SMLAL2, vn.IsVector() && vn.IsQ())                            \
  V(umlal, NEON_UMLAL, vn.IsVector() && vn.IsD())                              \
  V(umlal2, NEON_UMLAL2, vn.IsVector() && vn.IsQ())                            \
  V(smlsl, NEON_SMLSL, vn.IsVector() && vn.IsD())                              \
  V(smlsl2, NEON_SMLSL2, vn.IsVector() && vn.IsQ())                            \
  V(umlsl, NEON_UMLSL, vn.IsVector() && vn.IsD())                              \
  V(umlsl2, NEON_UMLSL2, vn.IsVector() && vn.IsQ())                            \
  V(smull, NEON_SMULL, vn.IsVector() && vn.IsD())                              \
  V(smull2, NEON_SMULL2, vn.IsVector() && vn.IsQ())                            \
  V(umull, NEON_UMULL, vn.IsVector() && vn.IsD())                              \
  V(umull2, NEON_UMULL2, vn.IsVector() && vn.IsQ())                            \
  V(ssubl, NEON_SSUBL, vn.IsVector() && vn.IsD())                              \
  V(ssubl2, NEON_SSUBL2, vn.IsVector() && vn.IsQ())                            \
  V(uaddl, NEON_UADDL, vn.IsVector() && vn.IsD())                              \
  V(uaddl2, NEON_UADDL2, vn.IsVector() && vn.IsQ())                            \
  V(usubl, NEON_USUBL, vn.IsVector() && vn.IsD())                              \
  V(usubl2, NEON_USUBL2, vn.IsVector() && vn.IsQ())                            \
  V(sqdmlal, NEON_SQDMLAL, vn.Is1H() || vn.Is1S() || vn.Is4H() || vn.Is2S())   \
  V(sqdmlal2, NEON_SQDMLAL2, vn.Is1H() || vn.Is1S() || vn.Is8H() || vn.Is4S()) \
  V(sqdmlsl, NEON_SQDMLSL, vn.Is1H() || vn.Is1S() || vn.Is4H() || vn.Is2S())   \
  V(sqdmlsl2, NEON_SQDMLSL2, vn.Is1H() || vn.Is1S() || vn.Is8H() || vn.Is4S()) \
  V(sqdmull, NEON_SQDMULL, vn.Is1H() || vn.Is1S() || vn.Is4H() || vn.Is2S())   \
  V(sqdmull2, NEON_SQDMULL2, vn.Is1H() || vn.Is1S() || vn.Is8H() || vn.Is4S())

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm) {                    \
    DCHECK(AS);                                                \
    NEON3DifferentL(vd, vn, vm, OP);                           \
  }
NEON_3DIFF_LONG_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_3DIFF_HN_LIST(V)        \
  V(addhn, NEON_ADDHN, vd.IsD())     \
  V(addhn2, NEON_ADDHN2, vd.IsQ())   \
  V(raddhn, NEON_RADDHN, vd.IsD())   \
  V(raddhn2, NEON_RADDHN2, vd.IsQ()) \
  V(subhn, NEON_SUBHN, vd.IsD())     \
  V(subhn2, NEON_SUBHN2, vd.IsQ())   \
  V(rsubhn, NEON_RSUBHN, vd.IsD())   \
  V(rsubhn2, NEON_RSUBHN2, vd.IsQ())

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm) {                    \
    DCHECK(AS);                                                \
    NEON3DifferentHN(vd, vn, vm, OP);                          \
  }
NEON_3DIFF_HN_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::NEONPerm(const VRegister& vd, const VRegister& vn,
                         const VRegister& vm, NEONPermOp op) {
  DCHECK(AreSameFormat(vd, vn, vm));
  DCHECK(!vd.Is1D());
  Emit(VFormat(vd) | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::trn1(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_TRN1);
}

void Assembler::trn2(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_TRN2);
}

void Assembler::uzp1(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_UZP1);
}

void Assembler::uzp2(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_UZP2);
}

void Assembler::zip1(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_ZIP1);
}

void Assembler::zip2(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm) {
  NEONPerm(vd, vn, vm, NEON_ZIP2);
}

void Assembler::NEONShiftImmediate(const VRegister& vd, const VRegister& vn,
                                   NEONShiftImmediateOp op, int immh_immb) {
  DCHECK(AreSameFormat(vd, vn));
  Instr q, scalar;
  if (vn.IsScalar()) {
    q = NEON_Q;
    scalar = NEON
"""


```