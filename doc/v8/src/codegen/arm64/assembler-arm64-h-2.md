Response:
The user is asking for a summary of the functionality provided by a snippet of C++ header file for the ARM64 architecture within the V8 JavaScript engine.

The header file appears to define methods for an `Assembler` class, specifically related to generating ARM64 SIMD (NEON) instructions.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The code snippet contains numerous methods with names that strongly suggest ARM64 SIMD instructions (e.g., `addv`, `fadd`, `ld1`, `st1`, `sqdmlal`). The presence of `VRegister` as a common parameter reinforces this. Thus, the core purpose is providing an interface for generating these instructions.

2. **Categorize the instructions:**  The methods can be grouped by their operation type. Obvious categories emerge:
    * **Arithmetic operations:**  `add`, `sub`, `mul`, `div` (integer and floating-point variants)
    * **Logical operations:** `cmeq`, `cmge`, `cmgt`, `cmtst` (comparison operations)
    * **Shift operations:** `shl`, `shr` (logical and arithmetic shifts, with variations like rounding and saturation)
    * **Data movement:** `mov`, `dup`, `ins`, `ext` (moving data between registers, and within vectors)
    * **Load/Store operations:** `ld1`, `st1`, `ld2`, `st2`, etc. (moving data between memory and registers)
    * **Floating-point specific operations:**  `fadd`, `fmul`, `fdiv`, `fsqrt`, `fcmp`, `fcvt` (a wide range of FP operations, including conversions)
    * **Long/Wide operations:**  Methods with suffixes like `l`, `w`, `hn` indicate operations on different data sizes.
    * **Saturating operations:** Methods starting with `sq` or `uq` indicate operations that clamp results to a maximum or minimum value.
    * **Across-lane operations:** Methods ending in `v` or containing `p` often operate across the elements of a vector.

3. **Check for Torque connection:** The prompt explicitly asks about `.tq` files. Since the provided code is a `.h` file, it's not a Torque source file. Therefore, this part is easy to answer: it's not a Torque file.

4. **Consider JavaScript relevance:**  V8 is a JavaScript engine. These ARM64 instructions are used to optimize the execution of JavaScript code. Specifically, they are used to implement various JavaScript operations efficiently at the machine code level. Think about common JavaScript scenarios that benefit from SIMD: array manipulations, mathematical calculations, image processing (on the canvas), etc. This leads to the example of vector addition.

5. **Look for code logic/reasoning:** The provided snippet is a header file, defining an interface. There isn't explicit logic to follow in the sense of input-output transformations within this file itself. The logic resides in the *implementation* of these methods (likely in a corresponding `.cc` file). So, this aspect will be limited to the *intended* purpose of these methods.

6. **Identify common programming errors:** When using assembly language (or an assembler interface), errors often revolve around incorrect register usage, memory access violations, and misunderstanding the precise behavior of instructions (e.g., overflow, saturation). An example of incorrect register usage in the *context of this interface* would be passing the wrong type of register or an invalid register number.

7. **Synthesize the summary:** Combine the categorized functionalities into a concise summary. Emphasize the role of this header in providing a way to generate low-level ARM64 instructions for optimized JavaScript execution.

8. **Address each point in the prompt:** Ensure that the answer explicitly addresses every point raised in the user's prompt (file type, Torque, JavaScript relation, examples, logic, errors, and finally the overall summary).
这是v8源代码`v8/src/codegen/arm64/assembler-arm64.h`中定义的一部分关于ARM64汇编器的接口，专注于SIMD（Single Instruction, Multiple Data）或称为NEON指令集的生成。

**功能列举:**

这部分代码定义了`Assembler`类中用于生成各种ARM64 NEON指令的方法。这些指令允许对向量寄存器（VRegister）中的多个数据元素并行执行相同的操作，从而显著提高性能。  以下是根据提供的代码片段归纳的功能类别：

* **算术运算:**  提供了向量的加法、减法、乘法等操作，包括长操作（结果位宽是操作数位宽的两倍）、宽操作（一个操作数位宽大于另一个）以及饱和运算（结果超出范围时被限制在最大/最小值）。
* **逻辑和比较运算:**  包括按位比较、大于、小于、等于等比较操作，以及按位测试。
* **移位操作:**  支持向量的左移和右移操作，包括逻辑移位、算术移位、以及带饱和和舍入的移位。
* **数据搬移和重排:**  提供了在向量寄存器之间以及向量寄存器和内存之间移动数据的指令，例如加载 (ld1, ld2, ld3, ld4)、存储 (st1, st2, st3, st4)、提取 (ext)、复制 (dup)、插入 (ins)、移动 (mov)、转置 (trn)、解压缩 (uzp)、压缩 (zip) 等。
* **浮点运算:**  包含了大量的浮点向量运算，如加法、减法、乘法、除法、比较、绝对值、取反、平方根、舍入、融合乘加/减 (fmla, fmls, fmadd, fmsub, fnmadd, fnmsub) 等。
* **类型转换:**  提供了向量浮点数与整数之间的转换操作，包括不同舍入模式。
* **点积运算:**  支持有符号向量的点积运算 (sdot)。
* **绝对差运算:**  提供了计算绝对差的指令 (sabd, uabd) 以及与累加结合的指令 (uaba, saba, sabal, uabal, sabdl, uabdl)。
* **多项式乘法:**  支持多项式乘法运算 (pmull)。

**是否为Torque源代码:**

`v8/src/codegen/arm64/assembler-arm64.h` 以 `.h` 结尾，这是一个C++头文件，因此它**不是**一个V8 Torque源代码。Torque源代码文件通常以 `.tq` 结尾。

**与JavaScript功能的关联和示例:**

这些NEON指令与JavaScript的执行性能密切相关。V8利用这些指令来优化JavaScript代码中的向量化操作，尤其是在处理数组、图形、多媒体等数据时。

例如，考虑以下JavaScript代码，对两个数组进行逐元素相加：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] + b[i];
  }
  return result;
}

const arr1 = [1, 2, 3, 4];
const arr2 = [5, 6, 7, 8];
const sum = addArrays(arr1, arr2);
console.log(sum); // 输出 [6, 8, 10, 12]
```

在V8的底层实现中，对于这种循环操作，当数组足够大并且运行时配置允许时，V8可能会生成使用NEON指令的代码。例如，`addArrays` 中的加法操作可能会被编译成类似 `addv` 或 `fadd` 的ARM64 NEON指令，一次性处理多个数组元素，从而提高执行效率。

**代码逻辑推理 (假设输入与输出):**

由于这里是头文件，只定义了接口，具体的代码逻辑在对应的 `.cc` 文件中。但是，我们可以根据指令名称推断其行为。

**假设输入:**

* `vd`, `vn`, `vm` 是向量寄存器，假设它们都是包含四个32位整数的寄存器。
* `vd` 的初始值为 `[0, 0, 0, 0]`
* `vn` 的值为 `[1, 2, 3, 4]`
* `vm` 的值为 `[5, 6, 7, 8]`

**指令:** `addv(vd, vn);`

**输出:**

* `vd` 的值将变为 `[1+2+3+4, ?, ?, ?]` 或 `[10, ?, ?, ?]` (取决于 `addv` 的具体实现，它可能是将 `vn` 的元素累加到 `vd` 的第一个元素，或者产生一个包含累加结果的向量)。

**指令:** `fadd(vd, vn, vm);` (假设 `vn` 和 `vm` 包含浮点数)

**输出:**

* `vd` 的值将变为 `[1.0+5.0, 2.0+6.0, 3.0+7.0, 4.0+8.0]` 或 `[6.0, 8.0, 10.0, 12.0]`。

**用户常见的编程错误示例:**

在使用这些底层指令时，常见的错误包括：

1. **类型不匹配:**  例如，将整数向量传递给期望浮点向量的指令，或者反之。
   ```c++
   VRegister int_vec;
   VRegister float_vec;
   // 错误地使用浮点加法指令操作整数向量
   masm()->fadd(float_vec, int_vec, int_vec);
   ```
   **在JavaScript中，这可能体现为对数据类型理解不足，导致V8无法进行有效的向量化优化。** 例如，如果数组中混合了字符串和数字，V8可能就无法使用SIMD指令进行高效的数值计算。

2. **寄存器分配错误:**  在手动编写汇编代码时，错误地使用或覆盖了正在使用的寄存器。
   ```c++
   VRegister reg1, reg2, reg3;
   // ... 一些操作使用了 reg1 和 reg2 ...
   // 错误地将结果存储到已经包含重要数据的 reg1
   masm()->fadd(reg1, reg2, reg3);
   ```
   **在V8的上下文中，这种错误通常由代码生成器处理，但如果手写汇编或者JIT编译器存在缺陷，就可能发生。**

3. **内存访问错误:**  加载或存储指令访问了无效的内存地址。
   ```c++
   MemOperand invalid_address;
   VRegister vec;
   // 尝试从无效地址加载数据
   masm()->ld1(vec, invalid_address);
   ```
   **这在JavaScript中通常表现为数组越界访问等错误。**

4. **指令参数错误:**  传递了超出指令允许范围的立即数或索引。
   ```c++
   VRegister vec1, vec2;
   // 假设 shift 的有效范围是 0-31，但传递了 64
   masm()->sshr(vec1, vec2, 64);
   ```

**功能归纳 (第3部分):**

这部分 `assembler-arm64.h` 头文件定义了ARM64汇编器中用于生成**向量化算术运算、逻辑比较、移位操作、复杂乘法运算（如长乘法和饱和乘法）、以及数据重排指令**的接口。 这些指令是NEON指令集的关键组成部分，用于在ARM64架构上实现高效的并行数据处理，对于V8引擎优化JavaScript代码的执行至关重要。  这部分内容侧重于**整数和部分浮点向量操作的增强功能**，包括带饱和、舍入以及长/宽操作的变体。

### 提示词
```
这是目录为v8/src/codegen/arm64/assembler-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/assembler-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
int vm_index);

  // Unsigned long multiply-sub by scalar element (second part).
  void umlsl2(const VRegister& vd, const VRegister& vn, const VRegister& vm,
              int vm_index);

  // Signed long multiply by scalar element.
  void smull(const VRegister& vd, const VRegister& vn, const VRegister& vm,
             int vm_index);

  // Signed long multiply by scalar element (second part).
  void smull2(const VRegister& vd, const VRegister& vn, const VRegister& vm,
              int vm_index);

  // Unsigned long multiply by scalar element.
  void umull(const VRegister& vd, const VRegister& vn, const VRegister& vm,
             int vm_index);

  // Unsigned long multiply by scalar element (second part).
  void umull2(const VRegister& vd, const VRegister& vn, const VRegister& vm,
              int vm_index);

  // Add narrow returning high half.
  void addhn(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Add narrow returning high half (second part).
  void addhn2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating double long multiply by element.
  void sqdmull(const VRegister& vd, const VRegister& vn, const VRegister& vm,
               int vm_index);

  // Signed saturating double long multiply by element (second part).
  void sqdmull2(const VRegister& vd, const VRegister& vn, const VRegister& vm,
                int vm_index);

  // Signed saturating doubling long multiply-add by element.
  void sqdmlal(const VRegister& vd, const VRegister& vn, const VRegister& vm,
               int vm_index);

  // Signed saturating doubling long multiply-add by element (second part).
  void sqdmlal2(const VRegister& vd, const VRegister& vn, const VRegister& vm,
                int vm_index);

  // Signed saturating doubling long multiply-sub by element.
  void sqdmlsl(const VRegister& vd, const VRegister& vn, const VRegister& vm,
               int vm_index);

  // Signed saturating doubling long multiply-sub by element (second part).
  void sqdmlsl2(const VRegister& vd, const VRegister& vn, const VRegister& vm,
                int vm_index);

  // Compare bitwise to zero.
  void cmeq(const VRegister& vd, const VRegister& vn, int value);

  // Compare signed greater than or equal to zero.
  void cmge(const VRegister& vd, const VRegister& vn, int value);

  // Compare signed greater than zero.
  void cmgt(const VRegister& vd, const VRegister& vn, int value);

  // Compare signed less than or equal to zero.
  void cmle(const VRegister& vd, const VRegister& vn, int value);

  // Compare signed less than zero.
  void cmlt(const VRegister& vd, const VRegister& vn, int value);

  // Unsigned rounding halving add.
  void urhadd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Compare equal.
  void cmeq(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Compare signed greater than or equal.
  void cmge(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Compare signed greater than.
  void cmgt(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Compare unsigned higher.
  void cmhi(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Compare unsigned higher or same.
  void cmhs(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Compare bitwise test bits nonzero.
  void cmtst(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed shift left by register.
  void sshl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned shift left by register.
  void ushl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling long multiply-subtract.
  void sqdmlsl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling long multiply-subtract (second part).
  void sqdmlsl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling long multiply.
  void sqdmull(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling long multiply (second part).
  void sqdmull2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling multiply returning high half.
  void sqdmulh(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating rounding doubling multiply returning high half.
  void sqrdmulh(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling multiply element returning high half.
  void sqdmulh(const VRegister& vd, const VRegister& vn, const VRegister& vm,
               int vm_index);

  // Signed saturating rounding doubling multiply element returning high half.
  void sqrdmulh(const VRegister& vd, const VRegister& vn, const VRegister& vm,
                int vm_index);

  // Unsigned long multiply long.
  void umull(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned long multiply (second part).
  void umull2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Rounding add narrow returning high half.
  void raddhn(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Subtract narrow returning high half.
  void subhn(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Subtract narrow returning high half (second part).
  void subhn2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Rounding add narrow returning high half (second part).
  void raddhn2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Rounding subtract narrow returning high half.
  void rsubhn(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Rounding subtract narrow returning high half (second part).
  void rsubhn2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating shift left by register.
  void sqshl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned saturating shift left by register.
  void uqshl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed rounding shift left by register.
  void srshl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned rounding shift left by register.
  void urshl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating rounding shift left by register.
  void sqrshl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned saturating rounding shift left by register.
  void uqrshl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed absolute difference.
  void sabd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned absolute difference and accumulate.
  void uaba(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Shift left by immediate and insert.
  void sli(const VRegister& vd, const VRegister& vn, int shift);

  // Shift right by immediate and insert.
  void sri(const VRegister& vd, const VRegister& vn, int shift);

  // Signed maximum.
  void smax(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed pairwise maximum.
  void smaxp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Add across vector.
  void addv(const VRegister& vd, const VRegister& vn);

  // Signed add long across vector.
  void saddlv(const VRegister& vd, const VRegister& vn);

  // Unsigned add long across vector.
  void uaddlv(const VRegister& vd, const VRegister& vn);

  // FP maximum number across vector.
  void fmaxnmv(const VRegister& vd, const VRegister& vn);

  // FP maximum across vector.
  void fmaxv(const VRegister& vd, const VRegister& vn);

  // FP minimum number across vector.
  void fminnmv(const VRegister& vd, const VRegister& vn);

  // FP minimum across vector.
  void fminv(const VRegister& vd, const VRegister& vn);

  // Signed maximum across vector.
  void smaxv(const VRegister& vd, const VRegister& vn);

  // Signed minimum.
  void smin(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed minimum pairwise.
  void sminp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed minimum across vector.
  void sminv(const VRegister& vd, const VRegister& vn);

  // Signed dot product
  void sdot(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // One-element structure store from one register.
  void st1(const VRegister& vt, const MemOperand& src);

  // One-element structure store from two registers.
  void st1(const VRegister& vt, const VRegister& vt2, const MemOperand& src);

  // One-element structure store from three registers.
  void st1(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const MemOperand& src);

  // One-element structure store from four registers.
  void st1(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, const MemOperand& src);

  // One-element single structure store from one lane.
  void st1(const VRegister& vt, int lane, const MemOperand& src);

  // Two-element structure store from two registers.
  void st2(const VRegister& vt, const VRegister& vt2, const MemOperand& src);

  // Two-element single structure store from two lanes.
  void st2(const VRegister& vt, const VRegister& vt2, int lane,
           const MemOperand& src);

  // Three-element structure store from three registers.
  void st3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const MemOperand& src);

  // Three-element single structure store from three lanes.
  void st3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           int lane, const MemOperand& src);

  // Four-element structure store from four registers.
  void st4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, const MemOperand& src);

  // Four-element single structure store from four lanes.
  void st4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, int lane, const MemOperand& src);

  // Unsigned add long.
  void uaddl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned add long (second part).
  void uaddl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned add wide.
  void uaddw(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned add wide (second part).
  void uaddw2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed add long.
  void saddl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed add long (second part).
  void saddl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed add wide.
  void saddw(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed add wide (second part).
  void saddw2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned subtract long.
  void usubl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned subtract long (second part).
  void usubl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned subtract wide.
  void usubw(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed subtract long.
  void ssubl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed subtract long (second part).
  void ssubl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed integer subtract wide.
  void ssubw(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed integer subtract wide (second part).
  void ssubw2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned subtract wide (second part).
  void usubw2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned maximum.
  void umax(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned pairwise maximum.
  void umaxp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned maximum across vector.
  void umaxv(const VRegister& vd, const VRegister& vn);

  // Unsigned minimum.
  void umin(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned pairwise minimum.
  void uminp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned minimum across vector.
  void uminv(const VRegister& vd, const VRegister& vn);

  // Transpose vectors (primary).
  void trn1(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Transpose vectors (secondary).
  void trn2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unzip vectors (primary).
  void uzp1(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unzip vectors (secondary).
  void uzp2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Zip vectors (primary).
  void zip1(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Zip vectors (secondary).
  void zip2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed shift right by immediate.
  void sshr(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned shift right by immediate.
  void ushr(const VRegister& vd, const VRegister& vn, int shift);

  // Signed rounding shift right by immediate.
  void srshr(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned rounding shift right by immediate.
  void urshr(const VRegister& vd, const VRegister& vn, int shift);

  // Signed shift right by immediate and accumulate.
  void ssra(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned shift right by immediate and accumulate.
  void usra(const VRegister& vd, const VRegister& vn, int shift);

  // Signed rounding shift right by immediate and accumulate.
  void srsra(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned rounding shift right by immediate and accumulate.
  void ursra(const VRegister& vd, const VRegister& vn, int shift);

  // Shift right narrow by immediate.
  void shrn(const VRegister& vd, const VRegister& vn, int shift);

  // Shift right narrow by immediate (second part).
  void shrn2(const VRegister& vd, const VRegister& vn, int shift);

  // Rounding shift right narrow by immediate.
  void rshrn(const VRegister& vd, const VRegister& vn, int shift);

  // Rounding shift right narrow by immediate (second part).
  void rshrn2(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned saturating shift right narrow by immediate.
  void uqshrn(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned saturating shift right narrow by immediate (second part).
  void uqshrn2(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned saturating rounding shift right narrow by immediate.
  void uqrshrn(const VRegister& vd, const VRegister& vn, int shift);

  // Unsigned saturating rounding shift right narrow by immediate (second part).
  void uqrshrn2(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating shift right narrow by immediate.
  void sqshrn(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating shift right narrow by immediate (second part).
  void sqshrn2(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating rounded shift right narrow by immediate.
  void sqrshrn(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating rounded shift right narrow by immediate (second part).
  void sqrshrn2(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating shift right unsigned narrow by immediate.
  void sqshrun(const VRegister& vd, const VRegister& vn, int shift);

  // Signed saturating shift right unsigned narrow by immediate (second part).
  void sqshrun2(const VRegister& vd, const VRegister& vn, int shift);

  // Signed sat rounded shift right unsigned narrow by immediate.
  void sqrshrun(const VRegister& vd, const VRegister& vn, int shift);

  // Signed sat rounded shift right unsigned narrow by immediate (second part).
  void sqrshrun2(const VRegister& vd, const VRegister& vn, int shift);

  // FP reciprocal step.
  void frecps(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP reciprocal estimate.
  void frecpe(const VRegister& vd, const VRegister& vn);

  // FP reciprocal square root estimate.
  void frsqrte(const VRegister& vd, const VRegister& vn);

  // FP reciprocal square root step.
  void frsqrts(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed absolute difference and accumulate long.
  void sabal(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed absolute difference and accumulate long (second part).
  void sabal2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned absolute difference and accumulate long.
  void uabal(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned absolute difference and accumulate long (second part).
  void uabal2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed absolute difference long.
  void sabdl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed absolute difference long (second part).
  void sabdl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned absolute difference long.
  void uabdl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned absolute difference long (second part).
  void uabdl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Polynomial multiply long.
  void pmull(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Polynomial multiply long (second part).
  void pmull2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed long multiply-add.
  void smlal(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed long multiply-add (second part).
  void smlal2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned long multiply-add.
  void umlal(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned long multiply-add (second part).
  void umlal2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed long multiply-sub.
  void smlsl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed long multiply-sub (second part).
  void smlsl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned long multiply-sub.
  void umlsl(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned long multiply-sub (second part).
  void umlsl2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed long multiply.
  void smull(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed long multiply (second part).
  void smull2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling long multiply-add.
  void sqdmlal(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed saturating doubling long multiply-add (second part).
  void sqdmlal2(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Unsigned absolute difference.
  void uabd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // Signed absolute difference and accumulate.
  void saba(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP instructions.
  // Move immediate to FP register.
  void fmov(const VRegister& fd, double imm);
  void fmov(const VRegister& fd, float imm);

  // Move FP register to register.
  void fmov(const Register& rd, const VRegister& fn);

  // Move register to FP register.
  void fmov(const VRegister& fd, const Register& rn);

  // Move FP register to FP register.
  void fmov(const VRegister& fd, const VRegister& fn);

  // Move 64-bit register to top half of 128-bit FP register.
  void fmov(const VRegister& vd, int index, const Register& rn);

  // Move top half of 128-bit FP register to 64-bit register.
  void fmov(const Register& rd, const VRegister& vn, int index);

  // FP add.
  void fadd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP subtract.
  void fsub(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP multiply.
  void fmul(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP compare equal to zero.
  void fcmeq(const VRegister& vd, const VRegister& vn, double imm);

  // FP greater than zero.
  void fcmgt(const VRegister& vd, const VRegister& vn, double imm);

  // FP greater than or equal to zero.
  void fcmge(const VRegister& vd, const VRegister& vn, double imm);

  // FP less than or equal to zero.
  void fcmle(const VRegister& vd, const VRegister& vn, double imm);

  // FP less than to zero.
  void fcmlt(const VRegister& vd, const VRegister& vn, double imm);

  // FP absolute difference.
  void fabd(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP pairwise add vector.
  void faddp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP pairwise add scalar.
  void faddp(const VRegister& vd, const VRegister& vn);

  // FP pairwise maximum scalar.
  void fmaxp(const VRegister& vd, const VRegister& vn);

  // FP pairwise maximum number scalar.
  void fmaxnmp(const VRegister& vd, const VRegister& vn);

  // FP pairwise minimum number scalar.
  void fminnmp(const VRegister& vd, const VRegister& vn);

  // FP vector multiply accumulate.
  void fmla(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP vector multiply subtract.
  void fmls(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP vector multiply extended.
  void fmulx(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP absolute greater than or equal.
  void facge(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP absolute greater than.
  void facgt(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP multiply by element.
  void fmul(const VRegister& vd, const VRegister& vn, const VRegister& vm,
            int vm_index);

  // FP fused multiply-add to accumulator by element.
  void fmla(const VRegister& vd, const VRegister& vn, const VRegister& vm,
            int vm_index);

  // FP fused multiply-sub from accumulator by element.
  void fmls(const VRegister& vd, const VRegister& vn, const VRegister& vm,
            int vm_index);

  // FP multiply extended by element.
  void fmulx(const VRegister& vd, const VRegister& vn, const VRegister& vm,
             int vm_index);

  // FP compare equal.
  void fcmeq(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP greater than.
  void fcmgt(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP greater than or equal.
  void fcmge(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP pairwise maximum vector.
  void fmaxp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP pairwise minimum vector.
  void fminp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP pairwise minimum scalar.
  void fminp(const VRegister& vd, const VRegister& vn);

  // FP pairwise maximum number vector.
  void fmaxnmp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP pairwise minimum number vector.
  void fminnmp(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP fused multiply-add.
  void fmadd(const VRegister& vd, const VRegister& vn, const VRegister& vm,
             const VRegister& va);

  // FP fused multiply-subtract.
  void fmsub(const VRegister& vd, const VRegister& vn, const VRegister& vm,
             const VRegister& va);

  // FP fused multiply-add and negate.
  void fnmadd(const VRegister& vd, const VRegister& vn, const VRegister& vm,
              const VRegister& va);

  // FP fused multiply-subtract and negate.
  void fnmsub(const VRegister& vd, const VRegister& vn, const VRegister& vm,
              const VRegister& va);

  // FP multiply-negate scalar.
  void fnmul(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP reciprocal exponent scalar.
  void frecpx(const VRegister& vd, const VRegister& vn);

  // FP divide.
  void fdiv(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP maximum.
  void fmax(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP minimum.
  void fmin(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP maximum.
  void fmaxnm(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP minimum.
  void fminnm(const VRegister& vd, const VRegister& vn, const VRegister& vm);

  // FP absolute.
  void fabs(const VRegister& vd, const VRegister& vn);

  // FP negate.
  void fneg(const VRegister& vd, const VRegister& vn);

  // FP square root.
  void fsqrt(const VRegister& vd, const VRegister& vn);

  // FP round to integer nearest with ties to away.
  void frinta(const VRegister& vd, const VRegister& vn);

  // FP round to integer, implicit rounding.
  void frinti(const VRegister& vd, const VRegister& vn);

  // FP round to integer toward minus infinity.
  void frintm(const VRegister& vd, const VRegister& vn);

  // FP round to integer nearest with ties to even.
  void frintn(const VRegister& vd, const VRegister& vn);

  // FP round to integer towards plus infinity.
  void frintp(const VRegister& vd, const VRegister& vn);

  // FP round to integer, exact, implicit rounding.
  void frintx(const VRegister& vd, const VRegister& vn);

  // FP round to integer towards zero.
  void frintz(const VRegister& vd, const VRegister& vn);

  // FP compare registers.
  void fcmp(const VRegister& vn, const VRegister& vm);

  // FP compare immediate.
  void fcmp(const VRegister& vn, double value);

  // FP conditional compare.
  void fccmp(const VRegister& vn, const VRegister& vm, StatusFlags nzcv,
             Condition cond);

  // FP conditional select.
  void fcsel(const VRegister& vd, const VRegister& vn, const VRegister& vm,
             Condition cond);

  // Common FP Convert functions.
  void NEONFPConvertToInt(const Register& rd, const VRegister& vn, Instr op);
  void NEONFPConvertToInt(const VRegister& vd, const VRegister& vn, Instr op);

  // FP convert between precisions.
  void fcvt(const VRegister& vd, const VRegister& vn);

  // FP convert to higher precision.
  void fcvtl(const VRegister& vd, const VRegister& vn);

  // FP convert to higher precision (second part).
  void fcvtl2(const VRegister& vd, const VRegister& vn);

  // FP convert to lower precision.
  void fcvtn(const VRegister& vd, const VRegister& vn);

  // FP convert to lower prevision (second part).
  void fcvtn2(const VRegister& vd, const VRegister& vn);

  // FP convert to lower precision, rounding to odd.
  void fcvtxn(const VRegister& vd, const VRegister& vn);

  // FP convert to lower precision, rounding to odd (second part).
  void fcvtxn2(const VRegister& vd, const VRegister& vn);

  // FP convert to signed integer, nearest with ties to away.
  void fcvtas(const Register& rd, const VRegister& vn);

  // FP convert to unsigned integer, nearest with ties to away.
  void fcvtau(const Register& rd, const VRegister& vn);

  // FP convert to signed integer, nearest with ties to away.
  void fcvtas(const VRegister& vd, const VRegister& vn);

  // FP convert to unsigned integer, nearest with ties to away.
  void fcvtau(const VRegister& vd, const VRegister& vn);

  // FP convert to signed integer, round towards -infinity.
  void fcvtms(const Register& rd, const VRegister& vn);

  // FP convert to unsigned integer, round towards -infinity.
  void fcvtmu(const Register& rd, const VRegister& vn);

  // FP convert to signed integer, round towards -infinity.
  void fcvtms(const VRegister& vd, const VRegister& vn);

  // FP convert to unsigned integer, round towards -infinity.
  void fcvtmu(const VRegister& vd, const VRegister& vn);

  // FP convert to signed integer, nearest with ties to even.
  void fcvtns(const Register& rd, const VRegister& vn);

  // FP JavaScript convert to signed integer, rounding toward zero [Armv8.3].
  void fjcvtzs(const Register& rd, const VRegister& vn);

  // FP convert to unsigned integer, nearest with ties to even.
  void fcvtnu(const Register& rd, const VRegister& vn);

  // FP convert to signed integer, nearest with ties to even.
  void fcvtns(const VRegister& rd, const VRegister& vn);

  // FP convert to unsigned integer, nearest with ties to even.
  void fcvtnu(const VRegister& rd, const VRegister& vn);

  // FP convert to signed integer or fixed-point, round towards zero.
  void fcvtzs(const Register& rd, const VRegister& vn, int fbits = 0);

  // FP convert to unsigned integer or fixed-point, round towards zero.
  void fcvtzu(const Register& rd, const VRegister& vn, int fbits = 0);

  // FP convert to signed integer or fixed-point, round towards zero.
  void fcvtzs(const VRegister& vd, const VRegister& vn, int fbits = 0);

  // FP convert to unsigned integer or fixed-point, round towards zero.
  void fcvtzu(const VRegister& vd, const VRegister& vn, int fbits = 0);

  // FP convert to signed integer, round towards +infinity.
  void fcvtps(const Register& rd, const VRegister& vn);

  // FP convert to unsigned integer, round towards +infinity.
  void fcvtpu(const Register& rd, const VRegister& vn);

  // FP convert to signed integer, round towards +infinity.
  void fcvtps(const VRegister& vd, const VRegister& vn);

  // FP convert to unsigned integer, round towards +infinity.
  void fcvtpu(const VRegister& vd, const VRegister& vn);

  // Convert signed integer or fixed point to FP.
  void scvtf(const VRegister& fd, const Register& rn, int fbits = 0);

  // Convert unsigned integer or fixed point to FP.
  void ucvtf(const VRegister& fd, const Register& rn, int fbits = 0);

  // Convert signed integer or fixed-point to FP.
  void scvtf(const VRegister& fd, const VRegister& vn, int fbits = 0);

  // Convert unsigned integer or fixed-point to FP.
  void ucvtf(const VRegister& fd, const VRegister& vn, int fbits = 0);

  // Extract vector from pair of vectors.
  void ext(const VRegister& vd, const VRegister& vn, const VRegister& vm,
           int index);

  // Duplicate vector element to vector or scalar.
  void dup(const VRegister& vd, const VRegister& vn, int vn_index);

  // Duplicate general-purpose register to vector.
  void dup(const VRegister& vd, const Register& rn);

  // Insert vector element from general-purpose register.
  void ins(const VRegister& vd, int vd_index, const Register& rn);

  // Move general-purpose register to a vector element.
  void mov(const VRegister& vd, int vd_index, const Register& rn);

  // Unsigned move vector element to general-purpose register.
  void umov(const Register& rd, const VRegister& vn, int vn_index);

  // Move vector element to general-purpose register.
  void mov(const Register& rd, const VRegister& vn, int vn_index);

  // Move vector element to scalar.
  void mov(const VRegister& vd, const VRegister& vn, int vn_index);

  // Insert vector element from another vector element.
  void ins(const VRegister& vd, int vd_index, const VRegister& vn,
           int vn_index);

  // Move vector element to another vector element.
  void mov(const VRegister& vd, int vd_index, const VRegister& vn,
           int vn_index);

  // Signed move vector element to general-purpose register.
  void smov(const Register& rd, const VRegister& vn, int vn_index);

  // One-element structure load to one register.
  void ld1(const VRegister& vt, const MemOperand& src);

  // One-element structure load to two registers.
  void ld1(const VRegister& vt, const VRegister& vt2, const MemOperand& src);

  // One-element structure load to three registers.
  void ld1(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const MemOperand& src);

  // One-element structure load to four registers.
  void ld1(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, const MemOperand& src);

  // One-element single structure load to one lane.
  void ld1(const VRegister& vt, int lane, const MemOperand& src);

  // One-element single structure load to all lanes.
  void ld1r(const VRegister& vt, const MemOperand& src);

  // Two-el
```