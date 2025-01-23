Response:
Let's break down the thought process for analyzing this C++ header file snippet.

1. **Identify the Core Purpose:** The file is `assembler-arm64.h` within the `v8/src/codegen/arm64` directory. Keywords like "assembler" and "arm64" immediately suggest its purpose: generating ARM64 assembly code. The `.h` extension confirms it's a header file, likely defining a class or set of functionalities.

2. **Scan for Key Data Structures and Operations:** Quickly skim the content, looking for patterns and repeated elements. The prevalence of names like `ld2`, `ld3`, `ld4`, `cls`, `clz`, `shl`, `addp`, `mul`, `tbl`, etc., strongly suggests these are mnemonics for ARM64 instructions. The arguments to these functions (e.g., `VRegister`, `MemOperand`) point to data structures representing registers and memory locations.

3. **Categorize the Functionality:** Group the identified operations into logical categories. The provided snippet clearly shows:
    * **Load/Store Instructions:**  `ld2`, `ld3`, `ld4`, `ldr`, `str` (though `ldr` and `str` aren't in *this* snippet, they are common assembler instructions, so the presence of `ld2`, `ld3`, `ld4` strongly implies load/store functionality). The variations (e.g., with `r` suffix, with `lane` argument) suggest different addressing modes and data handling.
    * **Vector Operations (NEON):** The `VRegister` type and functions like `cls`, `clz`, `cnt`, `rbit`, `rev16`, `rev32`, `rev64`, `sadalp`, `saddlp`, `uaddlp`, `uadalp`,  `shl`, `sqshl`, etc., indicate support for SIMD (Single Instruction, Multiple Data) operations using ARM's NEON instruction set.
    * **Arithmetic Operations:** `srhadd`, `uhsub`, `shsub`, `uqadd`, `sqadd`, `uqsub`, `sqsub`, `addp`, `mla`, `mls`, `mul`.
    * **Table Lookup Operations:** `tbl`, `tbx`.
    * **Raw Instruction Emission:** `dci`, `dc8`, `dc32`, `dc64`, `dcptr`, `EmitStringData`. This suggests a way to directly insert arbitrary bytes into the generated code.
    * **Pseudo-instructions:** `debug`, `db`, `dd`, `dq`, `dp`. These are higher-level abstractions.

4. **Infer the Class Structure:** The fact that these functions are members of a class (implicitly, given the context of a header file) and operate on internal state (like `pc_`, `buffer_`) leads to the conclusion that `Assembler` is likely the central class responsible for managing the assembly process.

5. **Consider the "Torque" Aspect:** The instruction about the `.tq` extension is a specific V8 detail. Recognize that Torque is V8's internal language for implementing built-in functions and that this header likely provides low-level primitives for Torque-generated code.

6. **Connect to JavaScript (If Applicable):** Since V8 executes JavaScript, think about how these low-level operations relate to JavaScript features. Vector operations map to TypedArrays and potentially future SIMD APIs. Basic arithmetic operations are fundamental. Memory access is essential for object manipulation.

7. **Think about Code Logic and Examples:** For specific instructions, imagine how they might be used. For instance, `addp` (add pairwise) could sum elements in an array efficiently. Consider potential inputs and outputs.

8. **Identify Potential Programming Errors:**  Reflect on common mistakes when working with assembly or low-level code. Incorrect register usage, misaligned memory access, and incorrect immediate values are typical problems.

9. **Address the "Part X of Y" Instruction:**  This emphasizes the need to summarize the *specific* functionality presented in the given snippet, while acknowledging it's part of a larger system.

10. **Structure the Answer:** Organize the findings into a clear and logical structure, covering the requested points: functionality, Torque connection, JavaScript relevance, code logic, common errors, and a summary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe this is just about basic arithmetic."  **Correction:** The presence of `VRegister` and NEON-specific instructions makes it clear that vector/SIMD operations are a significant part.
* **Initial thought:** "How does this relate to JavaScript exactly?" **Refinement:** Focus on the *capabilities* provided by these instructions and how those capabilities enable higher-level JavaScript features (e.g., efficient array manipulation). Don't try to map every instruction to a specific JavaScript keyword.
* **Initial thought:** "Just list all the functions." **Refinement:** Group them by functionality to provide a more meaningful overview.

By following these steps,  you can systematically analyze the code snippet and generate a comprehensive and accurate description of its purpose and features.
好的，让我们来分析一下提供的 `assembler-arm64.h` 代码片段的功能。

**核心功能：ARM64 汇编指令的生成**

这段代码是 `v8/src/codegen/arm64/assembler-arm64.h` 文件的一部分，它定义了 `Assembler` 类的一些成员函数。从函数命名和参数类型来看，这些函数的主要功能是 **生成 ARM64 架构的汇编指令**。

具体来说，这些函数涵盖了以下类型的指令：

* **加载/存储指令 (Load/Store Instructions):**
    * `ld2`, `ld3`, `ld4`:  用于加载 2、3 或 4 个元素的结构体到多个向量寄存器。
    * `ld2r`, `ld3r`, `ld4r`: 用于加载结构体的单个元素到所有向量通道。
    * `ld2` (带有 `lane` 参数): 用于加载结构体的单个元素到特定的向量通道。

* **向量操作指令 (Vector Operations - NEON):**
    * `cls` (Count leading sign bits)
    * `clz` (Count leading zero bits)
    * `cnt` (Population count per byte)
    * `rbit` (Reverse bit order)
    * `rev16`, `rev32`, `rev64` (Reverse elements)
    * `ursqrte` (Unsigned reciprocal square root estimate)
    * `urecpe` (Unsigned reciprocal estimate)
    * `sadalp`, `saddlp`, `uaddlp`, `uadalp` (Pairwise add)
    * `shl`, `sqshl`, `sqshlu`, `uqshl`, `sshll`, `sshll2`, `sxtl`, `sxtl2`, `ushll`, `ushll2`, `shll`, `shll2`, `uxtl`, `uxtl2` (移位操作)
    * `srhadd`, `uhsub`, `shsub`, `uqadd`, `sqadd`, `uqsub`, `sqsub` (算术运算)
    * `addp` (Pairwise add)
    * `mla`, `mls`, `mul` (乘法和乘加/减)
    * `tbl`, `tbx` (查表操作)

* **原始数据注入 (Raw Data Emission):**
    * `dci`:  发射原始指令。
    * `dc8`, `dc32`, `dc64`: 发射特定大小的数据。
    * `dcptr`: 发射地址。
    * `EmitStringData`: 发射字符串数据。

* **伪指令 (Pseudo-instructions):**
    * `debug`:  用于调试目的，插入包含消息和代码的断点。
    * `db`, `dd`, `dq`, `dp`:  分别用于发射字节、双字、四字和指针大小的数据（在特定的作用域内）。

* **指令流管理助手 (Instruction Stream Generation Helpers):**
    * `pc()`: 获取当前指令指针。
    * `InstructionAt()`: 获取指定偏移处的指令。
    * `InstructionOffset()`: 获取指令的偏移。

* **寄存器和标志编码助手 (Register and Flags Encoding Helpers):**
    * `Rd`, `Rn`, `Rm`, `Ra`, `Rt`, `Rt2`, `Rs`: 用于将 `CPURegister` 或 `Register` 编码到指令中。
    * `RdSP`, `RnSP`:  允许栈指针的编码，但不允许零寄存器。
    * `Flags`, `Cond`: 用于编码标志更新和条件码。

* **地址和分支编码助手 (Address and Branch Encoding Helpers):**
    * `ImmPCRelAddress`, `ImmUncondBranch`, `ImmCondBranch`, `ImmCmpBranch`, `ImmTestBranch`, `ImmTestBranchBit`: 用于编码不同类型的地址和分支指令的立即数。

* **数据处理编码助手 (Data Processing Encoding Helpers):**
    * `SF`, `ImmAddSub`, `Imms`, `ImmR`, `ImmSetBits`, `ImmRotate`, `ImmLLiteral`, `BitN`, `ShiftDP`, `ImmDPShift`, `ExtendMode`, `ImmExtendShift`, `ImmCondCmp`, `Nzcv`:  用于编码数据处理指令的不同部分。
    * `IsImmAddSub`, `IsImmConditionalCompare`, `IsImmLogical`:  用于检查立即数的有效性。

* **内存操作数偏移编码助手 (MemOperand Offset Encoding Helpers):**
    * `ImmLSUnsigned`, `ImmLS`, `ImmLSPair`, `ImmShiftLS`, `ImmException`, `ImmSystemRegister`, `ImmHint`, `ImmBarrierDomain`, `ImmBarrierType`, `CalcLSDataSizeLog2`: 用于编码内存操作数的偏移量。
    * `IsImmLSUnscaled`, `IsImmLSScaled`, `IsImmLLiteral`: 用于检查内存偏移量的有效性。

* **向量格式编码助手 (Vector Format Encoding Helpers):**
    * `VFormat`, `FPFormat`, `LSVFormat`, `SFormat`: 用于指定向量指令的操作数格式。
    * `ImmNEONHLM`, `ImmNEONExt`, `ImmNEON5`, `ImmNEON4`, `ImmNEONabcdefgh`, `NEONCmode`, `NEONModImmOp`: 用于编码 NEON 指令特定的立即数和操作码。

* **立即数移动编码助手 (Move Immediates Encoding Helpers):**
    * `ImmMoveWide`, `ShiftMoveWide`: 用于编码移动立即数到寄存器的指令。

* **浮点立即数编码助手 (FP Immediates Encoding Helpers):**
    * `ImmFP`, `ImmNEONFP`, `FPScale`: 用于编码浮点立即数。

* **浮点寄存器类型编码助手 (FP Register Type Encoding Helpers):**
    * `FPType`: 用于编码浮点寄存器类型。

* **常量池管理 (Constant Pool Management):**
    * `MaybeEmitOutOfLineConstantPool`, `ForceConstantPoolEmissionWithoutJump`, `ForceConstantPoolEmissionWithJump`, `EmitConstPoolWithJumpIfNeeded`:  用于管理常量池的生成，提高代码效率。

* **Veneer 池管理 (Veneer Pool Management):**
    * `MaxPCOffsetAfterVeneerPoolIfEmittedNow`, `ShouldEmitVeneer`, `ShouldEmitVeneers`, `RecordVeneerPool`, `EmitVeneers`, `EmitVeneersGuard`, `CheckVeneerPool`: 用于处理跳转范围限制，在必要时插入 veneer 代码段。

* **块级作用域管理 (Block Scope Management):**
    * `BlockPoolsScope`: 用于在代码块的开始和结束时管理常量池和 veneer 池的发射。

* **Windows 异常处理信息 (Windows Exception Handling Information):**
    * `GetXdataEncoder`, `GetUnwindInfo`:  用于生成 Windows 平台所需的异常处理信息。

**如果 `v8/src/codegen/arm64/assembler-arm64.h` 以 `.tq` 结尾:**

如果该文件以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。Torque 是 V8 用来定义其内置函数（例如 `Array.prototype.map`）的一种高级类型化的中间语言。在这种情况下，该文件将包含使用 Torque 语法编写的代码，这些代码会被编译成更底层的 C++ 代码，最终可能使用到 `assembler-arm64.h` 中定义的汇编指令生成功能。

**与 JavaScript 的关系：**

`assembler-arm64.h` 中定义的汇编指令生成功能是 V8 JavaScript 引擎的核心组成部分。当 V8 编译 JavaScript 代码时，它会将 JavaScript 代码转换成 ARM64 汇编指令，然后由 CPU 执行。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译这个简单的 `add` 函数时，`assembler-arm64.h` 中定义的函数（例如，用于加载操作数、执行加法运算并将结果存储回来的指令生成函数）将被用来生成相应的 ARM64 汇编代码。

更具体地，对于向量操作，JavaScript 的 `TypedArray` 和未来的 SIMD API 可以直接受益于这里定义的指令。例如，对一个 `Float32Array` 中的元素进行批量加法运算，就可以使用 `addp` 等 NEON 指令来高效实现。

```javascript
const arr1 = new Float32Array([1, 2, 3, 4]);
const arr2 = new Float32Array([5, 6, 7, 8]);
const resultArr = new Float32Array(4);

for (let i = 0; i < arr1.length; i++) {
  resultArr[i] = arr1[i] + arr2[i];
}
```

在 V8 的底层实现中，如果可以优化，这个循环内的加法操作可能会被编译成使用 NEON 向量指令，而 `assembler-arm64.h` 就提供了生成这些指令的能力。

**代码逻辑推理 (假设输入与输出):**

假设我们想生成 ARM64 汇编代码来实现两个 64 位整数的加法，并将结果存储到另一个寄存器。

**假设输入：**

* 目标寄存器 `rd`:  `x0`
* 源寄存器 1 `rn`: `x1`
* 源寄存器 2 `operand`: `x2`

**调用的 `Assembler` 函数 (简化)：**

可能调用类似 `Add(x0, x1, Operand(x2))` 的函数，这个函数内部会使用 `assembler-arm64.h` 中定义的更底层的函数来生成 `ADD x0, x1, x2` 指令。

**假设输出 (生成的汇编指令的二进制表示，仅为示例):**

`0x8b010000` (这只是一个假设的例子，实际的指令编码会更复杂)

**用户常见的编程错误：**

* **寄存器使用错误：**  使用了错误的寄存器，导致数据被写入或读取到错误的位置。
    ```c++
    // 错误地将结果存储到源寄存器
    void AddAndStore(Register rd, Register rn, Register rm) {
      Assembler masm;
      masm.add(rn, rn, rm); // 应该使用 rd 来存储结果
    }
    ```
* **内存访问错误：**  使用 `ld` 或 `st` 指令时，内存地址计算错误或未对齐，导致程序崩溃。
    ```c++
    void LoadValue(Register rd, intptr_t address) {
      Assembler masm;
      MemOperand mem(address); // 可能未对齐，导致错误
      masm.ldr(rd, mem);
    }
    ```
* **立即数范围错误：** 某些指令的立即数有范围限制，使用了超出范围的值会导致汇编错误或运行时错误。
    ```c++
    void ShiftLeft(Register rd, Register rn, int shift) {
      Assembler masm;
      masm.lsl(rd, rn, shift); // 如果 shift 值过大，可能会出错
    }
    ```
* **条件码使用错误：** 在条件分支指令中使用了错误的条件码，导致程序执行流程错误。
    ```c++
    void CompareAndBranch(Register r1, Register r2, Label& target) {
      Assembler masm;
      masm.cmp(r1, r2);
      masm.b(lt, &target); // 如果本意是大于时跳转，则条件码错误
    }
    ```

**第 4 部分功能归纳：**

作为第 4 部分，提供的代码片段主要集中在 **向量（NEON）指令** 的生成以及与内存操作相关的指令。它扩展了 `Assembler` 类生成 ARM64 汇编代码的能力，特别是针对 SIMD 并行计算和结构化数据的加载/存储。此外，它还包含了用于直接注入原始数据和定义伪指令的功能。这些功能是 V8 引擎优化 JavaScript 代码执行效率的关键组成部分。

总的来说，`v8/src/codegen/arm64/assembler-arm64.h` 定义了一个用于生成 ARM64 汇编代码的工具类，这段代码片段展示了其生成向量运算、加载/存储以及其他辅助指令的能力。这对于 V8 引擎将 JavaScript 代码高效地编译为机器码至关重要。

### 提示词
```
这是目录为v8/src/codegen/arm64/assembler-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/assembler-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
ement structure load.
  void ld2(const VRegister& vt, const VRegister& vt2, const MemOperand& src);

  // Two-element single structure load to one lane.
  void ld2(const VRegister& vt, const VRegister& vt2, int lane,
           const MemOperand& src);

  // Two-element single structure load to all lanes.
  void ld2r(const VRegister& vt, const VRegister& vt2, const MemOperand& src);

  // Three-element structure load.
  void ld3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const MemOperand& src);

  // Three-element single structure load to one lane.
  void ld3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           int lane, const MemOperand& src);

  // Three-element single structure load to all lanes.
  void ld3r(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
            const MemOperand& src);

  // Four-element structure load.
  void ld4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, const MemOperand& src);

  // Four-element single structure load to one lane.
  void ld4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, int lane, const MemOperand& src);

  // Four-element single structure load to all lanes.
  void ld4r(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
            const VRegister& vt4, const MemOperand& src);

  // Count leading sign bits.
  void cls(const VRegister& vd, const VRegister& vn);

  // Count leading zero bits (vector).
  void clz(const VRegister& vd, const VRegister& vn);

  // Population count per byte.
  void cnt(const VRegister& vd, const VRegister& vn);

  // Reverse bit order.
  void rbit(const VRegister& vd, const VRegister& vn);

  // Reverse elements in 16-bit halfwords.
  void rev16(const VRegister& vd, const VRegister& vn);

  // Reverse elements in 32-bit words.
  void rev32(const VRegister& vd, const VRegister& vn);

  // Reverse elements in 64-bit doublewords.
  void rev64(const VRegister& vd, const VRegister& vn);

  // Unsigned reciprocal square root estimate.
  void ursqrte(const VRegister& vd, const VRegister& vn);

  // Unsigned reciprocal estimate.
  void urecpe(const VRegister& vd, const VRegister& vn);

  // Signed pairwise long add and accumulate.
  void sadalp(const VRegister& vd, const VRegister& vn);

  // Signed pairwise long add.
  void saddlp(const VRegister& vd, const VRegister& vn);

  // Unsigned pairwise long add.
  void uaddlp(const VRegister& vd, const VRegister& vn);

  // Unsigned pairwise long add and accumulate.
  void uadalp(const VRegister& vd, const VRegister& vn);

  // Shift left by immediate.
  void shl(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating shift left by immediate.
  void sqshl(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating shift left unsigned by immediate.
  void sqshlu(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned saturating shift left by immediate.
  void uqshl(const VRegister& vd, const VRegister& vn, int shift);

  // Signed shift left long by immediate.
  void sshll(const VRegister& vd, const VRegister& vn, int shift);

  // Signed shift left long by immediate (second part).
  void sshll2(const VRegister& vd, const VRegister& vn, int shift);

  // Signed extend long.
  void sxtl(const VRegister& vd, const VRegister& vn);

  // Signed extend long (second part).
  void sxtl2(const VRegister& vd, const VRegister& vn);

  // Unsigned shift left long by immediate.
  void ushll(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned shift left long by immediate (second part).
  void ushll2(const VRegister& vd, const VRegister& vn, int shift);

  // Shift left long by element size.
  void shll(const VRegister& vd, const VRegister& vn, int shift);

  // Shift left long by element size (second part).
  void shll2(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned extend long.
  void uxtl(const VRegister& vd, const VRegister& vn);

  // Unsigned extend long (second part).
  void uxtl2(const VRegister& vd, const VRegister& vn);

  // Signed rounding halving add.
  void srhadd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned halving sub.
  void uhsub(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed halving sub.
  void shsub(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned saturating add.
  void uqadd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating add.
  void sqadd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned saturating subtract.
  void uqsub(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating subtract.
  void sqsub(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Add pairwise.
  void addp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Add pair of elements scalar.
  void addp(const VRegister& vd, const VRegister& vn);

  // Multiply-add to accumulator.
  void mla(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Multiply-subtract to accumulator.
  void mls(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Multiply.
  void mul(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Table lookup from one register.
  void tbl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Table lookup from two registers.
  void tbl(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vm);

  // Table lookup from three registers.
  void tbl(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vn3, const VRegister& vm);

  // Table lookup from four registers.
  void tbl(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vn3, const VRegister& vn4, const VRegister& vm);

  // Table lookup extension from one register.
  void tbx(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Table lookup extension from two registers.
  void tbx(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vm);

  // Table lookup extension from three registers.
  void tbx(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vn3, const VRegister& vm);

  // Table lookup extension from four registers.
  void tbx(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vn3, const VRegister& vn4, const VRegister& vm);

  // Instruction functions used only for test, debug, and patching.
  // Emit raw instructions in the instruction stream.
  void dci(Instr raw_inst) { Emit(raw_inst); }

  // Emit 8 bits of data in the instruction stream.
  void dc8(uint8_t data) { EmitData(&data, sizeof(data)); }

  // Emit 32 bits of data in the instruction stream.
  void dc32(uint32_t data) { EmitData(&data, sizeof(data)); }

  // Emit 64 bits of data in the instruction stream.
  void dc64(uint64_t data) { EmitData(&data, sizeof(data)); }

  // Emit an address in the instruction stream.
  void dcptr(Label* label);

  // Copy a string into the instruction stream, including the terminating
  // nullptr character. The instruction pointer (pc_) is then aligned correctly
  // for subsequent instructions.
  void EmitStringData(const char* string);

  // Pseudo-instructions ------------------------------------------------------

  // Parameters are described in arm64/instructions-arm64.h.
  void debug(const char* message, uint32_t code, Instr params = BREAK);

  // Required by V8.
  void db(uint8_t data) { dc8(data); }
  void dd(uint32_t data) {
    BlockPoolsScope no_pool_scope(this);
    dc32(data);
  }
  void dq(uint64_t data) {
    BlockPoolsScope no_pool_scope(this);
    dc64(data);
  }
  void dp(uintptr_t data) {
    BlockPoolsScope no_pool_scope(this);
    dc64(data);
  }

  // InstructionStream generation helpers
  // --------------------------------------------------

  Instruction* pc() const { return Instruction::Cast(pc_); }

  Instruction* InstructionAt(ptrdiff_t offset) const {
    return reinterpret_cast<Instruction*>(buffer_start_ + offset);
  }

  ptrdiff_t InstructionOffset(Instruction* instr) const {
    return reinterpret_cast<uint8_t*>(instr) - buffer_start_;
  }

  // Register encoding.
  static Instr Rd(CPURegister rd) {
    DCHECK_NE(rd.code(), kSPRegInternalCode);
    return rd.code() << Rd_offset;
  }

  static Instr Rn(CPURegister rn) {
    DCHECK_NE(rn.code(), kSPRegInternalCode);
    return rn.code() << Rn_offset;
  }

  static Instr Rm(CPURegister rm) {
    DCHECK_NE(rm.code(), kSPRegInternalCode);
    return rm.code() << Rm_offset;
  }

  static Instr RmNot31(CPURegister rm) {
    DCHECK_NE(rm.code(), kSPRegInternalCode);
    DCHECK(!rm.IsZero());
    return Rm(rm);
  }

  static Instr Ra(CPURegister ra) {
    DCHECK_NE(ra.code(), kSPRegInternalCode);
    return ra.code() << Ra_offset;
  }

  static Instr Rt(CPURegister rt) {
    DCHECK_NE(rt.code(), kSPRegInternalCode);
    return rt.code() << Rt_offset;
  }

  static Instr Rt2(CPURegister rt2) {
    DCHECK_NE(rt2.code(), kSPRegInternalCode);
    return rt2.code() << Rt2_offset;
  }

  static Instr Rs(CPURegister rs) {
    DCHECK_NE(rs.code(), kSPRegInternalCode);
    return rs.code() << Rs_offset;
  }

  // These encoding functions allow the stack pointer to be encoded, and
  // disallow the zero register.
  static Instr RdSP(Register rd) {
    DCHECK(!rd.IsZero());
    return (rd.code() & kRegCodeMask) << Rd_offset;
  }

  static Instr RnSP(Register rn) {
    DCHECK(!rn.IsZero());
    return (rn.code() & kRegCodeMask) << Rn_offset;
  }

  // Flags encoding.
  inline static Instr Flags(FlagsUpdate S);
  inline static Instr Cond(Condition cond);

  // PC-relative address encoding.
  inline static Instr ImmPCRelAddress(int imm21);

  // Branch encoding.
  inline static Instr ImmUncondBranch(int imm26);
  inline static Instr ImmCondBranch(int imm19);
  inline static Instr ImmCmpBranch(int imm19);
  inline static Instr ImmTestBranch(int imm14);
  inline static Instr ImmTestBranchBit(unsigned bit_pos);

  // Data Processing encoding.
  inline static Instr SF(Register rd);
  inline static Instr ImmAddSub(int imm);
  inline static Instr ImmS(unsigned imms, unsigned reg_size);
  inline static Instr ImmR(unsigned immr, unsigned reg_size);
  inline static Instr ImmSetBits(unsigned imms, unsigned reg_size);
  inline static Instr ImmRotate(unsigned immr, unsigned reg_size);
  inline static Instr ImmLLiteral(int imm19);
  inline static Instr BitN(unsigned bitn, unsigned reg_size);
  inline static Instr ShiftDP(Shift shift);
  inline static Instr ImmDPShift(unsigned amount);
  inline static Instr ExtendMode(Extend extend);
  inline static Instr ImmExtendShift(unsigned left_shift);
  inline static Instr ImmCondCmp(unsigned imm);
  inline static Instr Nzcv(StatusFlags nzcv);

  static constexpr bool IsImmAddSub(int64_t immediate) {
    return is_uint12(immediate) ||
           (is_uint12(immediate >> 12) && ((immediate & 0xFFF) == 0));
  }

  static constexpr bool IsImmConditionalCompare(int64_t immediate) {
    return is_uint5(immediate);
  }

  static bool IsImmLogical(uint64_t value, unsigned width, unsigned* n,
                           unsigned* imm_s, unsigned* imm_r);

  // MemOperand offset encoding.
  inline static Instr ImmLSUnsigned(int imm12);
  inline static Instr ImmLS(int imm9);
  inline static Instr ImmLSPair(int imm7, unsigned size);
  inline static Instr ImmShiftLS(unsigned shift_amount);
  inline static Instr ImmException(int imm16);
  inline static Instr ImmSystemRegister(int imm15);
  inline static Instr ImmHint(int imm7);
  inline static Instr ImmBarrierDomain(int imm2);
  inline static Instr ImmBarrierType(int imm2);
  inline static unsigned CalcLSDataSizeLog2(LoadStoreOp op);

  // Instruction bits for vector format in data processing operations.
  static Instr VFormat(VRegister vd) {
    if (vd.Is64Bits()) {
      switch (vd.LaneCount()) {
        case 1:
          return NEON_1D;
        case 2:
          return NEON_2S;
        case 4:
          return NEON_4H;
        case 8:
          return NEON_8B;
        default:
          UNREACHABLE();
      }
    } else {
      DCHECK(vd.Is128Bits());
      switch (vd.LaneCount()) {
        case 2:
          return NEON_2D;
        case 4:
          return NEON_4S;
        case 8:
          return NEON_8H;
        case 16:
          return NEON_16B;
        default:
          UNREACHABLE();
      }
    }
  }

  // Instruction bits for vector format in floating point data processing
  // operations.
  static Instr FPFormat(VRegister vd) {
    if (vd.LaneCount() == 1) {
      // Floating point scalar formats.
      DCHECK(vd.Is32Bits() || vd.Is64Bits());
      return vd.Is64Bits() ? FP64 : FP32;
    }

    // Two lane floating point vector formats.
    if (vd.LaneCount() == 2) {
      DCHECK(vd.Is64Bits() || vd.Is128Bits());
      return vd.Is128Bits() ? NEON_FP_2D : NEON_FP_2S;
    }

    // Four lane floating point vector formats.
    if (vd.LaneCount() == 4) {
      DCHECK(vd.Is64Bits() || vd.Is128Bits());
      return vd.Is128Bits() ? NEON_FP_4S : NEON_FP_4H;
    }

    // Eight lane floating point vector format.
    DCHECK((vd.LaneCount() == 8) && vd.Is128Bits());
    return NEON_FP_8H;
  }

  // Instruction bits for vector format in load and store operations.
  static Instr LSVFormat(VRegister vd) {
    if (vd.Is64Bits()) {
      switch (vd.LaneCount()) {
        case 1:
          return LS_NEON_1D;
        case 2:
          return LS_NEON_2S;
        case 4:
          return LS_NEON_4H;
        case 8:
          return LS_NEON_8B;
        default:
          UNREACHABLE();
      }
    } else {
      DCHECK(vd.Is128Bits());
      switch (vd.LaneCount()) {
        case 2:
          return LS_NEON_2D;
        case 4:
          return LS_NEON_4S;
        case 8:
          return LS_NEON_8H;
        case 16:
          return LS_NEON_16B;
        default:
          UNREACHABLE();
      }
    }
  }

  // Instruction bits for scalar format in data processing operations.
  static Instr SFormat(VRegister vd) {
    DCHECK(vd.IsScalar());
    switch (vd.SizeInBytes()) {
      case 1:
        return NEON_B;
      case 2:
        return NEON_H;
      case 4:
        return NEON_S;
      case 8:
        return NEON_D;
      default:
        UNREACHABLE();
    }
  }

  static Instr ImmNEONHLM(int index, int num_bits) {
    int h, l, m;
    if (num_bits == 3) {
      DCHECK(is_uint3(index));
      h = (index >> 2) & 1;
      l = (index >> 1) & 1;
      m = (index >> 0) & 1;
    } else if (num_bits == 2) {
      DCHECK(is_uint2(index));
      h = (index >> 1) & 1;
      l = (index >> 0) & 1;
      m = 0;
    } else {
      DCHECK(is_uint1(index) && (num_bits == 1));
      h = (index >> 0) & 1;
      l = 0;
      m = 0;
    }
    return (h << NEONH_offset) | (l << NEONL_offset) | (m << NEONM_offset);
  }

  static Instr ImmNEONExt(int imm4) {
    DCHECK(is_uint4(imm4));
    return imm4 << ImmNEONExt_offset;
  }

  static Instr ImmNEON5(Instr format, int index) {
    DCHECK(is_uint4(index));
    int s = LaneSizeInBytesLog2FromFormat(static_cast<VectorFormat>(format));
    int imm5 = (index << (s + 1)) | (1 << s);
    return imm5 << ImmNEON5_offset;
  }

  static Instr ImmNEON4(Instr format, int index) {
    DCHECK(is_uint4(index));
    int s = LaneSizeInBytesLog2FromFormat(static_cast<VectorFormat>(format));
    int imm4 = index << s;
    return imm4 << ImmNEON4_offset;
  }

  static Instr ImmNEONabcdefgh(int imm8) {
    DCHECK(is_uint8(imm8));
    Instr instr;
    instr = ((imm8 >> 5) & 7) << ImmNEONabc_offset;
    instr |= (imm8 & 0x1f) << ImmNEONdefgh_offset;
    return instr;
  }

  static Instr NEONCmode(int cmode) {
    DCHECK(is_uint4(cmode));
    return cmode << NEONCmode_offset;
  }

  static Instr NEONModImmOp(int op) {
    DCHECK(is_uint1(op));
    return op << NEONModImmOp_offset;
  }

  static constexpr bool IsImmLSUnscaled(int64_t offset) {
    return is_int9(offset);
  }
  static constexpr bool IsImmLSScaled(int64_t offset, unsigned size_log2) {
    bool offset_is_size_multiple =
        (static_cast<int64_t>(static_cast<uint64_t>(offset >> size_log2)
                              << size_log2) == offset);
    return offset_is_size_multiple && is_uint12(offset >> size_log2);
  }
  static bool IsImmLLiteral(int64_t offset);

  // Move immediates encoding.
  inline static Instr ImmMoveWide(int imm);
  inline static Instr ShiftMoveWide(int shift);

  // FP Immediates.
  static Instr ImmFP(double imm);
  static Instr ImmNEONFP(double imm);
  inline static Instr FPScale(unsigned scale);

  // FP register type.
  inline static Instr FPType(VRegister fd);

  // Unused on this architecture.
  void MaybeEmitOutOfLineConstantPool() {}

  void ForceConstantPoolEmissionWithoutJump() {
    constpool_.Check(Emission::kForced, Jump::kOmitted);
  }
  void ForceConstantPoolEmissionWithJump() {
    constpool_.Check(Emission::kForced, Jump::kRequired);
  }
  // Check if the const pool needs to be emitted while pretending that {margin}
  // more bytes of instructions have already been emitted.
  void EmitConstPoolWithJumpIfNeeded(size_t margin = 0) {
    if (constpool_.IsEmpty()) return;
    constpool_.Check(Emission::kIfNeeded, Jump::kRequired, margin);
  }

  // Used by veneer checks below - returns the max (= overapproximated) pc
  // offset after the veneer pool, if the veneer pool were to be emitted
  // immediately.
  intptr_t MaxPCOffsetAfterVeneerPoolIfEmittedNow(size_t margin);
  // Returns true if we should emit a veneer as soon as possible for a branch
  // which can at most reach to specified pc.
  bool ShouldEmitVeneer(int max_reachable_pc, size_t margin) {
    return max_reachable_pc < MaxPCOffsetAfterVeneerPoolIfEmittedNow(margin);
  }
  bool ShouldEmitVeneers(size_t margin = kVeneerDistanceMargin) {
    return ShouldEmitVeneer(unresolved_branches_first_limit(), margin);
  }

  // The code size generated for a veneer. Currently one branch
  // instruction. This is for code size checking purposes, and can be extended
  // in the future for example if we decide to add nops between the veneers.
  static constexpr int kVeneerCodeSize = 1 * kInstrSize;

  void RecordVeneerPool(int location_offset, int size);
  // Emits veneers for branches that are approaching their maximum range.
  // If need_protection is true, the veneers are protected by a branch jumping
  // over the code.
  void EmitVeneers(bool force_emit, bool need_protection,
                   size_t margin = kVeneerDistanceMargin);
  void EmitVeneersGuard() { EmitPoolGuard(); }
  // Checks whether veneers need to be emitted at this point.
  // If force_emit is set, a veneer is generated for *all* unresolved branches.
  void CheckVeneerPool(bool force_emit, bool require_jump,
                       size_t margin = kVeneerDistanceMargin);

  using BlockConstPoolScope = ConstantPool::BlockScope;

  class V8_NODISCARD BlockPoolsScope {
   public:
    // Block veneer and constant pool. Emits pools if necessary to ensure that
    // {margin} more bytes can be emitted without triggering pool emission.
    explicit BlockPoolsScope(Assembler* assem, size_t margin = 0)
        : assem_(assem), block_const_pool_(assem, margin) {
      assem_->CheckVeneerPool(false, true, margin);
      assem_->StartBlockVeneerPool();
    }

    BlockPoolsScope(Assembler* assem, PoolEmissionCheck check)
        : assem_(assem), block_const_pool_(assem, check) {
      assem_->StartBlockVeneerPool();
    }
    ~BlockPoolsScope() { assem_->EndBlockVeneerPool(); }

   private:
    Assembler* assem_;
    BlockConstPoolScope block_const_pool_;
    DISALLOW_IMPLICIT_CONSTRUCTORS(BlockPoolsScope);
  };

#if defined(V8_OS_WIN)
  win64_unwindinfo::XdataEncoder* GetXdataEncoder() {
    return xdata_encoder_.get();
  }

  win64_unwindinfo::BuiltinUnwindInfo GetUnwindInfo() const;
#endif

 protected:
  inline const Register& AppropriateZeroRegFor(const CPURegister& reg) const;

  void LoadStore(const CPURegister& rt, const MemOperand& addr, LoadStoreOp op);
  inline void LoadStoreScaledImmOffset(Instr memop, int offset, unsigned size);
  inline void LoadStoreUnscaledImmOffset(Instr memop, int offset);
  inline void LoadStoreWRegOffset(Instr memop, const Register& regoffset);
  void LoadStorePair(const CPURegister& rt, const CPURegister& rt2,
                     const MemOperand& addr, LoadStorePairOp op);
  void LoadStoreStruct(const VRegister& vt, const MemOperand& addr,
                       NEONLoadStoreMultiStructOp op);
  void LoadStoreStruct1(const VRegister& vt, int reg_count,
                        const MemOperand& addr);
  void LoadStoreStructSingle(const VRegister& vt, uint32_t lane,
                             const MemOperand& addr,
                             NEONLoadStoreSingleStructOp op);
  void LoadStoreStructSingleAllLanes(const VRegister& vt,
                                     const MemOperand& addr,
                                     NEONLoadStoreSingleStructOp op);
  void LoadStoreStructVerify(const VRegister& vt, const MemOperand& addr,
                             Instr op);

  static bool IsImmLSPair(int64_t offset, unsigned size);

  void Logical(const Register& rd, const Register& rn, const Operand& operand,
               LogicalOp op);
  void LogicalImmediate(const Register& rd, const Register& rn, unsigned n,
                        unsigned imm_s, unsigned imm_r, LogicalOp op);

  void ConditionalCompare(const Register& rn, const Operand& operand,
                          StatusFlags nzcv, Condition cond,
                          ConditionalCompareOp op);

  void AddSubWithCarry(const Register& rd, const Register& rn,
                       const Operand& operand, FlagsUpdate S,
                       AddSubWithCarryOp op);

  // Functions for emulating operands not directly supported by the instruction
  // set.
  void EmitShift(const Register& rd, const Register& rn, Shift shift,
                 unsigned amount);
  void EmitExtendShift(const Register& rd, const Register& rn, Extend extend,
                       unsigned left_shift);

  void AddSub(const Register& rd, const Register& rn, const Operand& operand,
              FlagsUpdate S, AddSubOp op);

  inline void DataProcPlainRegister(const Register& rd, const Register& rn,
                                    const Register& rm, Instr op);
  inline void CmpPlainRegister(const Register& rn, const Register& rm);
  inline void DataProcImmediate(const Register& rd, const Register& rn,
                                int immediate, Instr op);

  static bool IsImmFP32(uint32_t bits);
  static bool IsImmFP64(uint64_t bits);

  // Find an appropriate LoadStoreOp or LoadStorePairOp for the specified
  // registers. Only simple loads are supported; sign- and zero-extension (such
  // as in LDPSW_x or LDRB_w) are not supported.
  static inline LoadStoreOp LoadOpFor(const CPURegister& rt);
  static inline LoadStorePairOp LoadPairOpFor(const CPURegister& rt,
                                              const CPURegister& rt2);
  static inline LoadStoreOp StoreOpFor(const CPURegister& rt);
  static inline LoadStorePairOp StorePairOpFor(const CPURegister& rt,
                                               const CPURegister& rt2);
  static inline LoadLiteralOp LoadLiteralOpFor(const CPURegister& rt);

  // Remove the specified branch from the unbound label link chain.
  // If available, a veneer for this label can be used for other branches in the
  // chain if the link chain cannot be fixed up without this branch.
  void RemoveBranchFromLabelLinkChain(Instruction* branch, Label* label,
                                      Instruction* label_veneer = nullptr);

 private:
  static uint32_t FPToImm8(double imm);

  // Instruction helpers.
  void MoveWide(const Register& rd, uint64_t imm, int shift,
                MoveWideImmediateOp mov_op);
  void DataProcShiftedRegister(const Register& rd, const Register& rn,
                               const Operand& operand, FlagsUpdate S, Instr op);
  void DataProcExtendedRegister(const Register& rd, const Register& rn,
                                const Operand& operand, FlagsUpdate S,
                                Instr op);
  void ConditionalSelect(const Register& rd, const Register& rn,
                         const Register& rm, Condition cond,
                         ConditionalSelectOp op);
  void DataProcessing1Source(const Register& rd, const Register& rn,
                             DataProcessing1SourceOp op);
  void DataProcessing3Source(const Register& rd, const Register& rn,
                             const Register& rm, const Register& ra,
                             DataProcessing3SourceOp op);
  void FPDataProcessing1Source(const VRegister& fd, const VRegister& fn,
                               FPDataProcessing1SourceOp op);
  void FPDataProcessing2Source(const VRegister& fd, const VRegister& fn,
                               const VRegister& fm,
                               FPDataProcessing2SourceOp op);
  void FPDataProcessing3Source(const VRegister& fd, const VRegister& fn,
                               const VRegister& fm, const VRegister& fa,
                               FPDataProcessing3SourceOp op);
  void NEONAcrossLanesL(const VRegister& vd, const VRegister& vn,
                        NEONAcrossLanesOp op);
  void NEONAcrossLanes(const VRegister& vd, const VRegister& vn,
                       NEONAcrossLanesOp op);
  void NEONModifiedImmShiftLsl(const VRegister& vd, const int imm8,
                               const int left_shift,
                               NEONModifiedImmediateOp op);
  void NEONModifiedImmShiftMsl(const VRegister& vd, const int imm8,
                               const int shift_amount,
                               NEONModifiedImmediateOp op);
  void NEON3Same(const VRegister& vd, const VRegister& vn, const VRegister& vm,
                 NEON3SameOp vop);
  void NEONFP3Same(const VRegister& vd, const VRegister& vn,
                   const VRegister& vm, Instr op);
  void NEON3DifferentL(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm, NEON3DifferentOp vop);
  void NEON3DifferentW(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm, NEON3DifferentOp vop);
  void NEON3DifferentHN(const VRegister& vd, const VRegister& vn,
                        const VRegister& vm, NEON3DifferentOp vop);
  void NEONFP2RegMisc(const VRegister& vd, const VRegister& vn,
                      NEON2RegMiscOp vop, double value);
  void NEON2RegMisc(const VRegister& vd, const VRegister& vn,
                    NEON2RegMiscOp vop, int value = 0);
  void NEONFP2RegMisc(const VRegister& vd, const VRegister& vn, Instr op);
  void NEONAddlp(const VRegister& vd, const VRegister& vn, NEON2RegMiscOp op);
  void NEONPerm(const VRegister& vd, const VRegister& vn, const VRegister& vm,
                NEONPermOp op);
  void NEONFPByElement(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm, int vm_index,
                       NEONByIndexedElementOp op);
  void NEONByElement(const VRegister& vd, const VRegister& vn,
                     const VRegister& vm, int vm_index,
                     NEONByIndexedElementOp op);
  void NEONByElementL(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm, int vm_index,
                      NEONByIndexedElementOp op);
  void NEONShiftImmediate(const VRegister& vd, const VRegister& vn,
                          NEONShiftImmediateOp op, int immh_immb);
  void NEONShiftLeftImmediate(const VRegister& vd, const VRegister& vn,
                              int shift, NEONShiftImmediateOp op);
  void NEONShiftRightImmediate(const VRegister& vd, const VRegister& vn,
                               int shift, NEONShiftImmediateOp op);
  void NEONShiftImmediateL(const VRegister& vd, const VRegister& vn, int shift,
                           NEONShiftImmediateOp op);
  void NEONShiftImmediateN(const VRegister& vd, const VRegister& vn, int shift,
                           NEONShiftImmediateOp op);
  void NEONXtn(const VRegister& vd, const VRegister& vn, NEON2RegMiscOp vop);
  void NEONTable(const VRegister& vd, const VRegister& vn, const VRegister& vm,
                 NEONTableOp op);

  Instr LoadStoreStructAddrModeField(const MemOperand& addr);

  // Label helpers.

  // Return an offset for a label-referencing instruction, typically a branch.
  int LinkAndGetByteOffsetTo(Label* label);

  // This is the same as LinkAndGetByteOffsetTo, but return an offset
  // suitable for fields that take instruction offsets: branches.
  inline int LinkAndGetBranchInstructionOffsetTo(Label* label);

  static constexpr int kStartOfLabelLinkChain = 0;

  // Verify that a label's link chain is intact.
  void CheckLabelLinkChain(Label const* label);

  // Emit the instruction at pc_.
  void Emit(Instr instruction) {
    static_assert(sizeof(*pc_) == 1);
    static_assert(sizeof(instruction) == kInstrSize);
    DCHECK_LE(pc_ + sizeof(instruction), buffer_start_ + buffer_->size());

    memcpy(pc_, &instruction, sizeof(instruction));
    pc_ += sizeof(instruction);
    CheckBuffer();
  }

  // Emit data inline in the instruction stream.
  void EmitData(void const* data, unsigned size) {
    DCHECK_EQ(sizeof(*pc_), 1);
    DCHECK_LE(pc_ + size, buffer_start_ + buffer_->size());

    // TODO(all): Somehow register we have some data here. Then we can
    // disassemble it correctly.
    memcpy(pc_, data, size);
    pc_ += size;
    CheckBuffer();
  }

  void GrowBuffer();

  void CheckBufferSpace() {
    DCHECK_LT(pc_, buffer_start_ + buffer_->size());
    if (V8_UNLIKELY(buffer_space() < kGap)) {
      GrowBuffer();
    }
  }

  void CheckBuffer() {
    CheckBufferSpace();
    if (pc_offset() >= next_veneer_pool_check_) {
      CheckVeneerPool(false, true);
    }
    constpool_.MaybeCheck();
  }

  // Emission of the veneer pools may be blocked in some code sequences.
  int veneer_pool_blocked_nesting_ = 0;  // Block emission if this is not zero.

  // Relocation info generation
  // Each relocation is encoded as a variable size value
  static constexpr int kMaxRelocSize = RelocInfoWriter::kMaxSize;
  RelocInfoWriter reloc_info_writer;

  // Internal reference positions, required for (potential) patching in
  // GrowBuffer(); contains only those internal references whose labels
  // are already bound.
  std::deque<int> internal_reference_positions_;

 protected:
  // InstructionStream generation
  // The relocation writer's position is at least kGap bytes below the end of
  // the generated instructions. This is so that multi-instruction sequences do
  // not have to check for overflow. The same is true for writes of large
  // relocation info entries, and debug strings encoded in the instruction
  // stream.
  static constexpr int kGap = 64;
  static_assert(AssemblerBase::kMinimalBufferSize >= 2 * kGap);

 public:
#ifdef DEBUG
  // Functions used for testing.
  size_t GetConstantPoolEntriesSizeForTesting() const {
    // Do not include branch over the pool.
    return constpool_.Entry32Count() * kInt32Size +
           constpool_.Entry64Count() * kInt64Size;
  }

  static size_t GetCheckConstPoolIntervalForTesting() {
    return ConstantPool::kCheckInterval;
  }

  static size_t GetApproxMaxDistToConstPoolForTesting() {
    return ConstantPool::kApproxDistToPool64;
  }
#endif

 protected:
  const AssemblerZone zone_;

  // Information about unresolved (forward) branches.
  // The Assembler is only allowed to delete out-of-date information from here
  // after a label is bound. The MacroAssembler uses this information to
  // generate veneers.
  //
  // The first member of the pair (max_pc) is the maximum offset that the branch
  // can reach in the buffer, with the bottom bit set to indicate a
  // test-and-branch instruction. This bit is used to help in calculating the
  // address of the branch, ie.
  //
  //   branch_addr = { max_pc - 2^21,     if max_pc<0> == 0 (B.cond, CB[N]Z)
  //                 { max_pc - 2^16 - 1, if max_pc<0> == 1 (TB[N]Z)
  //
  // The second member is a pointer to the Label targetted by the branch.
  //
  // The map is sorted according to the reachable offset, max_pc, allowing to
  // check easily when veneers need to be emitted.
  // Note that the maximum reachable offset (first member of the pa
```