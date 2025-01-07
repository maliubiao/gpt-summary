Response:
The user wants me to analyze a C++ source code snippet from V8, specifically the `assembler-arm64.cc` file. I need to identify its functionalities related to ARM64 assembly code generation within the V8 JavaScript engine.

Here's a breakdown of the user's requests and how I'll address them:

1. **List its functions:** I need to examine the provided code and list the methods defined within the `Assembler` class. These methods likely correspond to ARM64 assembly instructions.

2. **Check for .tq extension:** I need to verify if the file extension is `.tq`. Based on the provided information, it's `.cc`, so it's C++, not Torque.

3. **Relate to JavaScript with examples:** Since this is an assembler, it directly translates to low-level operations. I need to think about common JavaScript operations that would require specific assembly instructions and provide those examples.

4. **Provide code logic inference with input/output:** For some of the more complex functions, I can try to infer the logic. I'll need to make assumptions about the input `VRegister` values and the `shift` amount and then predict the output `VRegister` value after the operation.

5. **Illustrate common programming errors:** I'll focus on errors related to incorrect register usage (e.g., using the wrong size or type of register) or invalid shift amounts, as these are common when working with assembly or low-level code generation.

6. **Summarize its functionality (Part 3):** I need to provide a concise summary of the capabilities demonstrated in this specific code snippet. This part seems heavily focused on NEON (Advanced SIMD) instructions.

**Mental Sandbox:**

* **Instruction Identification:** I'll iterate through the code and identify methods like `NEONShiftLeftImmediate`, `shl`, `sri`, `ld1`, `st1`, etc. These are strong indicators of assembly instruction generation.
* **NEON Focus:** The prevalence of "NEON" in the function names suggests a strong focus on SIMD operations.
* **Register Handling:** The code deals with `VRegister` objects, which represent SIMD registers. I need to pay attention to the size and type checks (e.g., `IsD()`, `IsQ()`, `IsScalar()`).
* **Shift Operations:**  Many functions relate to shifting bits within registers. I'll need to explain the different types of shifts (left, right, logical, arithmetic).
* **Load/Store Operations:**  Functions like `ld1`, `st1`, `ld2`, `st2` suggest memory access operations for SIMD data.

**Constraint Checklist & Confidence Score:**

1. List functions: Yes
2. Check .tq: Yes
3. JavaScript relation: Yes
4. Code logic inference: Yes (for some)
5. Common errors: Yes
6. Summarize functionality: Yes

Confidence Score: 5/5 - I'm confident I can address all the user's requirements based on the code snippet.

Strategizing complete. I will now generate the response following the above steps.
这是提供的 `v8/src/codegen/arm64/assembler-arm64.cc` 文件的一部分代码，主要关注 ARM64 架构下的 NEON (Advanced SIMD) 指令的汇编生成。

**功能列举:**

这段代码定义了 `Assembler` 类的一些成员函数，这些函数用于生成各种 ARM64 NEON 指令。 主要功能可以归纳为：

1. **NEON 移位操作 (Shift Operations):**
   - 提供了一系列函数用于生成 NEON 向量和标量的移位指令，包括逻辑左移 (`shl`, `sli`), 有符号/无符号饱和左移 (`sqshl`, `sqshlu`, `uqshl`), 有符号/无符号长左移 (`sshll`, `ushll`),  逻辑右移 (`sri`), 有符号/无符号右移 (`sshr`, `ushr`), 有符号/无符号四舍五入右移 (`srshr`, `urshr`), 有符号/无符号带符号扩展的右移 (`ssra`, `usra`), 有符号/无符号四舍五入带符号扩展的右移 (`srsra`, `ursra`),  有符号/无符号缩小右移 (`shrn`), 有符号/无符号四舍五入缩小右移 (`rshrn`), 有符号/无符号饱和缩小右移 (`sqshrn`), 有符号/无符号饱和四舍五入缩小右移 (`sqrshrn`), 以及对应的无符号变体 (`uqshrn`, `uqrshrn`)。

2. **NEON 扩展操作 (Extension Operations):**
   - `sxtl`, `sxtl2`:  有符号扩展到长向量。
   - `uxtl`, `uxtl2`:  无符号扩展到长向量。

3. **NEON 加宽/减窄操作 (Widening/Narrowing Operations):**
   - `uaddw`, `uaddw2`, `saddw`, `saddw2`: 无符号和有符号加宽加法。
   - `usubw`, `usubw2`, `ssubw`, `ssubw2`: 无符号和有符号加宽减法。

4. **NEON 数据移动和插入操作 (Data Movement and Insertion):**
   - `mov(Register, Register)`:  在通用寄存器之间移动数据。
   - `ins(VRegister, int, Register)`: 将通用寄存器的值插入到 NEON 向量寄存器的指定元素。
   - `mov(Register, VRegister, int)`, `smov(Register, VRegister, int)`, `umov(Register, VRegister, int)`: 从 NEON 向量寄存器的指定元素移动到通用寄存器。
   - `mov(VRegister, int, Register)`:  与 `ins` 相同。
   - `mov(VRegister, VRegister, int)`: 将 NEON 向量寄存器的指定元素复制到另一个 NEON 向量寄存器 (标量形式)。
   - `dup(VRegister, Register)`: 将通用寄存器的值复制到 NEON 向量寄存器的所有元素。
   - `ins(VRegister, int, VRegister, int)`: 将一个 NEON 向量寄存器的元素插入到另一个 NEON 向量寄存器的指定元素。

5. **NEON 其他单操作数指令 (Other Unary Operations):**
   - `cls`: 计算每个元素的最高有效位的符号位数。
   - `clz`: 计算每个元素的前导零位数。
   - `cnt`: 计算每个字节中设置的位数。
   - `rev16`, `rev32`, `rev64`: 反转向量中 16 位、32 位或 64 位元素的字节顺序。
   - `ursqrte`: 无符号倒数平方根估计。
   - `urecpe`: 无符号倒数估计。

6. **NEON 规约加法操作 (Reduction Add Operations):**
   - `saddlp`, `uaddlp`: 有符号和无符号成对加法。
   - `sadalp`, `uadalp`: 有符号和无符号累加成对加法。
   - `saddlv`, `uaddlv`: 有符号和无符号向量元素加法。
   - `fmaxv`, `fminv`, `fmaxnmv`, `fminnmv`, `addv`, `smaxv`, `sminv`, `umaxv`, `uminv`: 各种跨通道操作，用于计算向量中的最大值、最小值或总和。

7. **NEON 表查找操作 (Table Lookup Operations):**
   - `tbl`: 使用一个或多个向量作为查找表，从表中选择元素并放入目标向量。
   - `tbx`: 与 `tbl` 类似，但如果索引超出范围，则目标向量中的相应元素将保持不变。

8. **通用指令 (General Instructions):**
   - `mvn`:  按位取反并移动。
   - `mrs`: 将系统寄存器的内容移动到通用寄存器。
   - `msr`: 将通用寄存器的内容移动到系统寄存器。
   - `hint`: 发出系统提示指令。

9. **NEON 结构体加载和存储指令 (Structure Load and Store Instructions):**
   - 提供了一系列的 `ld1`, `ld2`, `ld3`, `ld4` 用于加载 1 到 4 个向量寄存器的结构体。
   - 提供了对应的带重复的加载指令 `ld1r`, `ld2r`, `ld3r`, `ld4r`。
   - 提供了 `st1`, `st2`, `st3`, `st4` 用于存储 1 到 4 个向量寄存器的结构体。
   - 提供了加载和存储单个元素的指令，例如 `ld1(Vt, lane, MemOperand)` 和 `st1(Vt, lane, MemOperand)`。

10. **内存屏障指令 (Memory Barrier Instruction):**
    - `dmb`: 数据内存屏障。

**关于文件扩展名和 Torque:**

根据您的描述，如果 `v8/src/codegen/arm64/assembler-arm64.cc` 以 `.tq` 结尾，那它才是一个 V8 Torque 源代码。 由于这里提供的代码是 `.cc` 结尾，因此它是 **C++** 源代码，而不是 Torque 源代码。

**与 JavaScript 的关系及示例:**

这段代码直接负责将 V8 的内部表示（通常是中间代码或抽象语法树）转换为底层的 ARM64 汇编指令。 这些指令最终会在 CPU 上执行，从而实现 JavaScript 代码的功能。

例如，JavaScript 中的数组操作、数学运算、位运算等，在 V8 内部可能会使用 NEON 指令来加速处理 SIMD (单指令多数据) 操作。

```javascript
// JavaScript 示例：对数组进行向量化加法

function vectorAdd(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const array1 = [1, 2, 3, 4, 5, 6, 7, 8];
const array2 = [9, 10, 11, 12, 13, 14, 15, 16];
const sum = vectorAdd(array1, array2);
console.log(sum); // 输出: [10, 12, 14, 16, 18, 20, 22, 24]
```

在 V8 内部，当优化这段 JavaScript 代码时，`vectorAdd` 函数中的循环可能会被向量化，即一次处理多个数组元素。 这时，`assembler-arm64.cc` 中的 NEON 加法指令（如 `addv` 或更基础的加法指令）就会被用来生成相应的汇编代码。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下代码：

```c++
Assembler a;
VRegister d0 = VRegister::D0();
VRegister d1 = VRegister::D1();

// 假设 d1 包含 [1, 2, 3, 4, 5, 6, 7, 8] (8个字节)
// 执行左移 2 位的操作
a.shl(d0, d1, 2);
```

**假设输入:**

- `d1` 寄存器（源寄存器）包含 8 个字节的值: `[1, 2, 3, 4, 5, 6, 7, 8]`。

**代码逻辑:**

`a.shl(d0, d1, 2)` 会生成一条 NEON 左移指令，将 `d1` 寄存器中的每个字节逻辑左移 2 位，并将结果存储到 `d0` 寄存器。

**预期输出:**

- `d0` 寄存器（目标寄存器）将包含:
  - `1 << 2 = 4`
  - `2 << 2 = 8`
  - `3 << 2 = 12`
  - `4 << 2 = 16`
  - `5 << 2 = 20`
  - `6 << 2 = 24`
  - `7 << 2 = 28`
  - `8 << 2 = 32`
  即 `d0` 包含 `[4, 8, 12, 16, 20, 24, 28, 32]`。

**用户常见的编程错误举例:**

1. **错误的寄存器大小:**  尝试对大小不匹配的寄存器进行操作。例如，将一个 64 位寄存器的值插入到一个 32 位寄存器的元素中，或者在需要双字寄存器时使用了单字寄存器。

   ```c++
   Assembler a;
   Register w0 = w0; // 32位寄存器
   VRegister d0 = VRegister::D0(); // 64位 NEON 寄存器

   // 错误：尝试将 32 位寄存器的值插入到 64 位 NEON 寄存器的字节元素中，
   // 但 `ins` 指令可能对寄存器类型有特定要求。
   // 常见的错误是假设可以直接混合使用不同大小的寄存器而没有显式的转换。
   // a.ins(d0, 0, w0); // 这可能会导致汇编错误或未定义的行为
   ```

2. **移位量超出范围:**  NEON 移位指令的移位量通常有有效范围限制（例如，对于字节移位，通常在 0 到 7 之间）。 提供超出此范围的移位量会导致错误。

   ```c++
   Assembler a;
   VRegister d0 = VRegister::D0();
   VRegister d1 = VRegister::D1();

   // 假设 d1 是一个字节向量
   // 错误：对于字节向量，左移 10 位是无效的。
   a.shl(d0, d1, 10);
   ```

3. **错误的指令使用:**  使用不适合特定数据类型的指令。例如，尝试对浮点数使用整数移位指令。

   ```c++
   Assembler a;
   VRegister s0 = VRegister::S0(); // 单精度浮点数 NEON 寄存器

   // 错误：`shl` 是整数移位指令，不应该用于浮点数寄存器。
   // a.shl(s0, s0, 2);
   ```

**功能归纳 (第 3 部分):**

这段代码片段主要提供了用于生成 ARM64 架构下 **NEON (Advanced SIMD) 移位、扩展、加宽/减窄、数据移动、插入、单操作数、规约加法以及表查找** 指令的接口。 它还包含了生成**通用寄存器操作、系统寄存器访问、提示指令以及 NEON 结构体加载和存储指令**的功能。 总体而言，这部分代码是 `Assembler` 类中用于处理 SIMD 和数据处理操作的关键组成部分。

Prompt: 
```
这是目录为v8/src/codegen/arm64/assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
Scalar;
  } else {
    q = vd.IsD() ? 0 : NEON_Q;
    scalar = 0;
  }
  Emit(q | op | scalar | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::NEONShiftLeftImmediate(const VRegister& vd, const VRegister& vn,
                                       int shift, NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 0) && (shift < laneSizeInBits));
  NEONShiftImmediate(vd, vn, op, (laneSizeInBits + shift) << 16);
}

void Assembler::NEONShiftRightImmediate(const VRegister& vd,
                                        const VRegister& vn, int shift,
                                        NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 1) && (shift <= laneSizeInBits));
  NEONShiftImmediate(vd, vn, op, ((2 * laneSizeInBits) - shift) << 16);
}

void Assembler::NEONShiftImmediateL(const VRegister& vd, const VRegister& vn,
                                    int shift, NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 0) && (shift < laneSizeInBits));
  int immh_immb = (laneSizeInBits + shift) << 16;

  DCHECK((vn.Is8B() && vd.Is8H()) || (vn.Is4H() && vd.Is4S()) ||
         (vn.Is2S() && vd.Is2D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Instr q;
  q = vn.IsD() ? 0 : NEON_Q;
  Emit(q | op | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::NEONShiftImmediateN(const VRegister& vd, const VRegister& vn,
                                    int shift, NEONShiftImmediateOp op) {
  Instr q, scalar;
  int laneSizeInBits = vd.LaneSizeInBits();
  DCHECK((shift >= 1) && (shift <= laneSizeInBits));
  int immh_immb = (2 * laneSizeInBits - shift) << 16;

  if (vn.IsScalar()) {
    DCHECK((vd.Is1B() && vn.Is1H()) || (vd.Is1H() && vn.Is1S()) ||
           (vd.Is1S() && vn.Is1D()));
    q = NEON_Q;
    scalar = NEONScalar;
  } else {
    DCHECK((vd.Is8B() && vn.Is8H()) || (vd.Is4H() && vn.Is4S()) ||
           (vd.Is2S() && vn.Is2D()) || (vd.Is16B() && vn.Is8H()) ||
           (vd.Is8H() && vn.Is4S()) || (vd.Is4S() && vn.Is2D()));
    scalar = 0;
    q = vd.IsD() ? 0 : NEON_Q;
  }
  Emit(q | op | scalar | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::shl(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SHL);
}

void Assembler::sli(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SLI);
}

void Assembler::sqshl(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SQSHL_imm);
}

void Assembler::sqshlu(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SQSHLU);
}

void Assembler::uqshl(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_UQSHL_imm);
}

void Assembler::sshll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsD());
  NEONShiftImmediateL(vd, vn, shift, NEON_SSHLL);
}

void Assembler::sshll2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsQ());
  NEONShiftImmediateL(vd, vn, shift, NEON_SSHLL);
}

void Assembler::sxtl(const VRegister& vd, const VRegister& vn) {
  sshll(vd, vn, 0);
}

void Assembler::sxtl2(const VRegister& vd, const VRegister& vn) {
  sshll2(vd, vn, 0);
}

void Assembler::ushll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsD());
  NEONShiftImmediateL(vd, vn, shift, NEON_USHLL);
}

void Assembler::ushll2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsQ());
  NEONShiftImmediateL(vd, vn, shift, NEON_USHLL);
}

void Assembler::uxtl(const VRegister& vd, const VRegister& vn) {
  ushll(vd, vn, 0);
}

void Assembler::uxtl2(const VRegister& vd, const VRegister& vn) {
  ushll2(vd, vn, 0);
}

void Assembler::sri(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRI);
}

void Assembler::sshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SSHR);
}

void Assembler::ushr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_USHR);
}

void Assembler::srshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRSHR);
}

void Assembler::urshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_URSHR);
}

void Assembler::ssra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SSRA);
}

void Assembler::usra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_USRA);
}

void Assembler::srsra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRSRA);
}

void Assembler::ursra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_URSRA);
}

void Assembler::shrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsD());
  NEONShiftImmediateN(vd, vn, shift, NEON_SHRN);
}

void Assembler::shrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SHRN);
}

void Assembler::rshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsD());
  NEONShiftImmediateN(vd, vn, shift, NEON_RSHRN);
}

void Assembler::rshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_RSHRN);
}

void Assembler::sqshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRN);
}

void Assembler::sqshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRN);
}

void Assembler::sqrshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRN);
}

void Assembler::sqrshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRN);
}

void Assembler::sqshrun(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRUN);
}

void Assembler::sqshrun2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRUN);
}

void Assembler::sqrshrun(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRUN);
}

void Assembler::sqrshrun2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRUN);
}

void Assembler::uqshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_UQSHRN);
}

void Assembler::uqshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_UQSHRN);
}

void Assembler::uqrshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_UQRSHRN);
}

void Assembler::uqrshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_UQRSHRN);
}

void Assembler::uaddw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_UADDW);
}

void Assembler::uaddw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_UADDW2);
}

void Assembler::saddw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_SADDW);
}

void Assembler::saddw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_SADDW2);
}

void Assembler::usubw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_USUBW);
}

void Assembler::usubw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_USUBW2);
}

void Assembler::ssubw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_SSUBW);
}

void Assembler::ssubw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_SSUBW2);
}

void Assembler::mov(const Register& rd, const Register& rm) {
  // Moves involving the stack pointer are encoded as add immediate with
  // second operand of zero. Otherwise, orr with first operand zr is
  // used.
  if (rd.IsSP() || rm.IsSP()) {
    add(rd, rm, 0);
  } else {
    orr(rd, AppropriateZeroRegFor(rd), rm);
  }
}

void Assembler::ins(const VRegister& vd, int vd_index, const Register& rn) {
  // We support vd arguments of the form vd.VxT() or vd.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vd.LaneSizeInBytes();
  NEONFormatField format;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      DCHECK(rn.IsW());
      break;
    case 2:
      format = NEON_8H;
      DCHECK(rn.IsW());
      break;
    case 4:
      format = NEON_4S;
      DCHECK(rn.IsW());
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      DCHECK(rn.IsX());
      format = NEON_2D;
      break;
  }

  DCHECK((0 <= vd_index) &&
         (vd_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(NEON_INS_GENERAL | ImmNEON5(format, vd_index) | Rn(rn) | Rd(vd));
}

void Assembler::mov(const Register& rd, const VRegister& vn, int vn_index) {
  DCHECK_GE(vn.SizeInBytes(), 4);
  umov(rd, vn, vn_index);
}

void Assembler::smov(const Register& rd, const VRegister& vn, int vn_index) {
  // We support vn arguments of the form vn.VxT() or vn.T(), where x is the
  // number of lanes, and T is b, h, s.
  int lane_size = vn.LaneSizeInBytes();
  NEONFormatField format;
  Instr q = 0;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      break;
    case 2:
      format = NEON_8H;
      break;
    default:
      DCHECK_EQ(lane_size, 4);
      DCHECK(rd.IsX());
      format = NEON_4S;
      break;
  }
  q = rd.IsW() ? 0 : NEON_Q;
  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(q | NEON_SMOV | ImmNEON5(format, vn_index) | Rn(vn) | Rd(rd));
}

void Assembler::cls(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_CLS | Rn(vn) | Rd(vd));
}

void Assembler::clz(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_CLZ | Rn(vn) | Rd(vd));
}

void Assembler::cnt(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B());
  Emit(VFormat(vn) | NEON_CNT | Rn(vn) | Rd(vd));
}

void Assembler::rev16(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B());
  Emit(VFormat(vn) | NEON_REV16 | Rn(vn) | Rd(vd));
}

void Assembler::rev32(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B() || vd.Is4H() || vd.Is8H());
  Emit(VFormat(vn) | NEON_REV32 | Rn(vn) | Rd(vd));
}

void Assembler::rev64(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_REV64 | Rn(vn) | Rd(vd));
}

void Assembler::ursqrte(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is2S() || vd.Is4S());
  Emit(VFormat(vn) | NEON_URSQRTE | Rn(vn) | Rd(vd));
}

void Assembler::urecpe(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is2S() || vd.Is4S());
  Emit(VFormat(vn) | NEON_URECPE | Rn(vn) | Rd(vd));
}

void Assembler::NEONAddlp(const VRegister& vd, const VRegister& vn,
                          NEON2RegMiscOp op) {
  DCHECK((op == NEON_SADDLP) || (op == NEON_UADDLP) || (op == NEON_SADALP) ||
         (op == NEON_UADALP));

  DCHECK((vn.Is8B() && vd.Is4H()) || (vn.Is4H() && vd.Is2S()) ||
         (vn.Is2S() && vd.Is1D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::saddlp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_SADDLP);
}

void Assembler::uaddlp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_UADDLP);
}

void Assembler::sadalp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_SADALP);
}

void Assembler::uadalp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_UADALP);
}

void Assembler::NEONAcrossLanesL(const VRegister& vd, const VRegister& vn,
                                 NEONAcrossLanesOp op) {
  DCHECK((vn.Is8B() && vd.Is1H()) || (vn.Is16B() && vd.Is1H()) ||
         (vn.Is4H() && vd.Is1S()) || (vn.Is8H() && vd.Is1S()) ||
         (vn.Is4S() && vd.Is1D()));
  Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::saddlv(const VRegister& vd, const VRegister& vn) {
  NEONAcrossLanesL(vd, vn, NEON_SADDLV);
}

void Assembler::uaddlv(const VRegister& vd, const VRegister& vn) {
  NEONAcrossLanesL(vd, vn, NEON_UADDLV);
}

void Assembler::NEONAcrossLanes(const VRegister& vd, const VRegister& vn,
                                NEONAcrossLanesOp op) {
  DCHECK((vn.Is8B() && vd.Is1B()) || (vn.Is16B() && vd.Is1B()) ||
         (vn.Is4H() && vd.Is1H()) || (vn.Is8H() && vd.Is1H()) ||
         (vn.Is4S() && vd.Is1S()));
  if ((op & NEONAcrossLanesFPFMask) == NEONAcrossLanesFPFixed) {
    Emit(FPFormat(vn) | op | Rn(vn) | Rd(vd));
  } else {
    Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
  }
}

#define NEON_ACROSSLANES_LIST(V)      \
  V(fmaxv, NEON_FMAXV, vd.Is1S())     \
  V(fminv, NEON_FMINV, vd.Is1S())     \
  V(fmaxnmv, NEON_FMAXNMV, vd.Is1S()) \
  V(fminnmv, NEON_FMINNMV, vd.Is1S()) \
  V(addv, NEON_ADDV, true)            \
  V(smaxv, NEON_SMAXV, true)          \
  V(sminv, NEON_SMINV, true)          \
  V(umaxv, NEON_UMAXV, true)          \
  V(uminv, NEON_UMINV, true)

#define DEFINE_ASM_FUNC(FN, OP, AS)                              \
  void Assembler::FN(const VRegister& vd, const VRegister& vn) { \
    DCHECK(AS);                                                  \
    NEONAcrossLanes(vd, vn, OP);                                 \
  }
NEON_ACROSSLANES_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::mov(const VRegister& vd, int vd_index, const Register& rn) {
  ins(vd, vd_index, rn);
}

void Assembler::umov(const Register& rd, const VRegister& vn, int vn_index) {
  // We support vn arguments of the form vn.VxT() or vn.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vn.LaneSizeInBytes();
  NEONFormatField format;
  Instr q = 0;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      DCHECK(rd.IsW());
      break;
    case 2:
      format = NEON_8H;
      DCHECK(rd.IsW());
      break;
    case 4:
      format = NEON_4S;
      DCHECK(rd.IsW());
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      DCHECK(rd.IsX());
      format = NEON_2D;
      q = NEON_Q;
      break;
  }

  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(q | NEON_UMOV | ImmNEON5(format, vn_index) | Rn(vn) | Rd(rd));
}

void Assembler::mov(const VRegister& vd, const VRegister& vn, int vn_index) {
  DCHECK(vd.IsScalar());
  dup(vd, vn, vn_index);
}

void Assembler::dup(const VRegister& vd, const Register& rn) {
  DCHECK(!vd.Is1D());
  DCHECK_EQ(vd.Is2D(), rn.IsX());
  Instr q = vd.IsD() ? 0 : NEON_Q;
  Emit(q | NEON_DUP_GENERAL | ImmNEON5(VFormat(vd), 0) | Rn(rn) | Rd(vd));
}

void Assembler::ins(const VRegister& vd, int vd_index, const VRegister& vn,
                    int vn_index) {
  DCHECK(AreSameFormat(vd, vn));
  // We support vd arguments of the form vd.VxT() or vd.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vd.LaneSizeInBytes();
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

  DCHECK((0 <= vd_index) &&
         (vd_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(NEON_INS_ELEMENT | ImmNEON5(format, vd_index) |
       ImmNEON4(format, vn_index) | Rn(vn) | Rd(vd));
}

void Assembler::NEONTable(const VRegister& vd, const VRegister& vn,
                          const VRegister& vm, NEONTableOp op) {
  DCHECK(vd.Is16B() || vd.Is8B());
  DCHECK(vn.Is16B());
  DCHECK(AreSameFormat(vd, vm));
  Emit(op | (vd.IsQ() ? NEON_Q : 0) | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vm) {
  NEONTable(vd, vn, vm, NEON_TBL_1v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vm) {
  USE(vn2);
  DCHECK(AreSameFormat(vn, vn2));
  DCHECK(AreConsecutive(vn, vn2));
  NEONTable(vd, vn, vm, NEON_TBL_2v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  DCHECK(AreSameFormat(vn, vn2, vn3));
  DCHECK(AreConsecutive(vn, vn2, vn3));
  NEONTable(vd, vn, vm, NEON_TBL_3v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vn4, const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  USE(vn4);
  DCHECK(AreSameFormat(vn, vn2, vn3, vn4));
  DCHECK(AreConsecutive(vn, vn2, vn3, vn4));
  NEONTable(vd, vn, vm, NEON_TBL_4v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vm) {
  NEONTable(vd, vn, vm, NEON_TBX_1v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vm) {
  USE(vn2);
  DCHECK(AreSameFormat(vn, vn2));
  DCHECK(AreConsecutive(vn, vn2));
  NEONTable(vd, vn, vm, NEON_TBX_2v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  DCHECK(AreSameFormat(vn, vn2, vn3));
  DCHECK(AreConsecutive(vn, vn2, vn3));
  NEONTable(vd, vn, vm, NEON_TBX_3v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vn4, const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  USE(vn4);
  DCHECK(AreSameFormat(vn, vn2, vn3, vn4));
  DCHECK(AreConsecutive(vn, vn2, vn3, vn4));
  NEONTable(vd, vn, vm, NEON_TBX_4v);
}

void Assembler::mov(const VRegister& vd, int vd_index, const VRegister& vn,
                    int vn_index) {
  ins(vd, vd_index, vn, vn_index);
}

void Assembler::mvn(const Register& rd, const Operand& operand) {
  orn(rd, AppropriateZeroRegFor(rd), operand);
}

void Assembler::mrs(const Register& rt, SystemRegister sysreg) {
  DCHECK(rt.Is64Bits());
  Emit(MRS | ImmSystemRegister(sysreg) | Rt(rt));
}

void Assembler::msr(SystemRegister sysreg, const Register& rt) {
  DCHECK(rt.Is64Bits());
  Emit(MSR | Rt(rt) | ImmSystemRegister(sysreg));
}

void Assembler::hint(SystemHint code) { Emit(HINT | ImmHint(code) | Rt(xzr)); }

// NEON structure loads and stores.
Instr Assembler::LoadStoreStructAddrModeField(const MemOperand& addr) {
  Instr addr_field = RnSP(addr.base());

  if (addr.IsPostIndex()) {
    static_assert(NEONLoadStoreMultiStructPostIndex ==
                      static_cast<NEONLoadStoreMultiStructPostIndexOp>(
                          NEONLoadStoreSingleStructPostIndex),
                  "Opcodes must match for NEON post index memop.");

    addr_field |= NEONLoadStoreMultiStructPostIndex;
    if (addr.offset() == 0) {
      addr_field |= RmNot31(addr.regoffset());
    } else {
      // The immediate post index addressing mode is indicated by rm = 31.
      // The immediate is implied by the number of vector registers used.
      addr_field |= (0x1F << Rm_offset);
    }
  } else {
    DCHECK(addr.IsImmediateOffset() && (addr.offset() == 0));
  }
  return addr_field;
}

void Assembler::LoadStoreStructVerify(const VRegister& vt,
                                      const MemOperand& addr, Instr op) {
#ifdef DEBUG
  // Assert that addressing mode is either offset (with immediate 0), post
  // index by immediate of the size of the register list, or post index by a
  // value in a core register.
  if (addr.IsImmediateOffset()) {
    DCHECK_EQ(addr.offset(), 0);
  } else {
    int offset = vt.SizeInBytes();
    switch (op) {
      case NEON_LD1_1v:
      case NEON_ST1_1v:
        offset *= 1;
        break;
      case NEONLoadStoreSingleStructLoad1:
      case NEONLoadStoreSingleStructStore1:
      case NEON_LD1R:
        offset = (offset / vt.LaneCount()) * 1;
        break;

      case NEON_LD1_2v:
      case NEON_ST1_2v:
      case NEON_LD2:
      case NEON_ST2:
        offset *= 2;
        break;
      case NEONLoadStoreSingleStructLoad2:
      case NEONLoadStoreSingleStructStore2:
      case NEON_LD2R:
        offset = (offset / vt.LaneCount()) * 2;
        break;

      case NEON_LD1_3v:
      case NEON_ST1_3v:
      case NEON_LD3:
      case NEON_ST3:
        offset *= 3;
        break;
      case NEONLoadStoreSingleStructLoad3:
      case NEONLoadStoreSingleStructStore3:
      case NEON_LD3R:
        offset = (offset / vt.LaneCount()) * 3;
        break;

      case NEON_LD1_4v:
      case NEON_ST1_4v:
      case NEON_LD4:
      case NEON_ST4:
        offset *= 4;
        break;
      case NEONLoadStoreSingleStructLoad4:
      case NEONLoadStoreSingleStructStore4:
      case NEON_LD4R:
        offset = (offset / vt.LaneCount()) * 4;
        break;
      default:
        UNREACHABLE();
    }
    DCHECK(addr.regoffset() != NoReg || addr.offset() == offset);
  }
#else
  USE(vt);
  USE(addr);
  USE(op);
#endif
}

void Assembler::LoadStoreStruct(const VRegister& vt, const MemOperand& addr,
                                NEONLoadStoreMultiStructOp op) {
  LoadStoreStructVerify(vt, addr, op);
  DCHECK(vt.IsVector() || vt.Is1D());
  Emit(op | LoadStoreStructAddrModeField(addr) | LSVFormat(vt) | Rt(vt));
}

void Assembler::LoadStoreStructSingleAllLanes(const VRegister& vt,
                                              const MemOperand& addr,
                                              NEONLoadStoreSingleStructOp op) {
  LoadStoreStructVerify(vt, addr, op);
  Emit(op | LoadStoreStructAddrModeField(addr) | LSVFormat(vt) | Rt(vt));
}

void Assembler::ld1(const VRegister& vt, const MemOperand& src) {
  LoadStoreStruct(vt, src, NEON_LD1_1v);
}

void Assembler::ld1(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, src, NEON_LD1_2v);
}

void Assembler::ld1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, src, NEON_LD1_3v);
}

void Assembler::ld1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, src, NEON_LD1_4v);
}

void Assembler::ld2(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, src, NEON_LD2);
}

void Assembler::ld2(const VRegister& vt, const VRegister& vt2, int lane,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad2);
}

void Assembler::ld2r(const VRegister& vt, const VRegister& vt2,
                     const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD2R);
}

void Assembler::ld3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, src, NEON_LD3);
}

void Assembler::ld3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, int lane, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad3);
}

void Assembler::ld3r(const VRegister& vt, const VRegister& vt2,
                     const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD3R);
}

void Assembler::ld4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, src, NEON_LD4);
}

void Assembler::ld4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4, int lane,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad4);
}

void Assembler::ld4r(const VRegister& vt, const VRegister& vt2,
                     const VRegister& vt3, const VRegister& vt4,
                     const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD4R);
}

void Assembler::st1(const VRegister& vt, const MemOperand& src) {
  LoadStoreStruct(vt, src, NEON_ST1_1v);
}

void Assembler::st1(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, src, NEON_ST1_2v);
}

void Assembler::st1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, src, NEON_ST1_3v);
}

void Assembler::st1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, src, NEON_ST1_4v);
}

void Assembler::st2(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& dst) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, dst, NEON_ST2);
}

void Assembler::st2(const VRegister& vt, const VRegister& vt2, int lane,
                    const MemOperand& dst) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore2);
}

void Assembler::st3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, dst, NEON_ST3);
}

void Assembler::st3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, int lane, const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore3);
}

void Assembler::st4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, dst, NEON_ST4);
}

void Assembler::st4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4, int lane,
                    const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore4);
}

void Assembler::LoadStoreStructSingle(const VRegister& vt, uint32_t lane,
                                      const MemOperand& addr,
                                      NEONLoadStoreSingleStructOp op) {
  LoadStoreStructVerify(vt, addr, op);

  // We support vt arguments of the form vt.VxT() or vt.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  unsigned lane_size = vt.LaneSizeInBytes();
  DCHECK_LT(lane, kQRegSize / lane_size);

  // Lane size is encoded in the opcode field. Lane index is encoded in the Q,
  // S and size fields.
  lane *= lane_size;

  // Encodings for S[0]/D[0] and S[2]/D[1] are distinguished using the least-
  // significant bit of the size field, so we increment lane here to account for
  // that.
  if (lane_size == 8) lane++;

  Instr size = (lane << NEONLSSize_offset) & NEONLSSize_mask;
  Instr s = (lane << (NEONS_offset - 2)) & NEONS_mask;
  Instr q = (lane << (NEONQ_offset - 3)) & NEONQ_mask;

  Instr instr = op;
  switch (lane_size) {
    case 1:
      instr |= NEONLoadStoreSingle_b;
      break;
    case 2:
      instr |= NEONLoadStoreSingle_h;
      break;
    case 4:
      instr |= NEONLoadStoreSingle_s;
      break;
    default:
      DCHECK_EQ(lane_size, 8U);
      instr |= NEONLoadStoreSingle_d;
  }

  Emit(instr | LoadStoreStructAddrModeField(addr) | q | size | s | Rt(vt));
}

void Assembler::ld1(const VRegister& vt, int lane, const MemOperand& src) {
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad1);
}

void Assembler::ld1r(const VRegister& vt, const MemOperand& src) {
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD1R);
}

void Assembler::st1(const VRegister& vt, int lane, const MemOperand& dst) {
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore1);
}

void Assembler::dmb(BarrierDomain domain, BarrierType type) {
  Emit(DMB | ImmBarrierDomain(domain) | ImmBarrierType(
"""


```