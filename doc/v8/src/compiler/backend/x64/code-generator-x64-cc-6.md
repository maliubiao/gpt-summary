Response:
My thinking process to analyze the provided C++ code snippet and generate the response involved these steps:

1. **Understanding the Context:** The prompt states the code is from `v8/src/compiler/backend/x64/code-generator-x64.cc`, part of the V8 JavaScript engine's optimizing compiler. This tells me the code is responsible for generating machine code (specifically x64 assembly) from an intermediate representation. The fact that it's "backend" implies it's a late stage in the compilation process.

2. **Initial Scan and Pattern Recognition:** I quickly scanned the code, looking for repeated patterns and keywords. The `case` statements within a `switch` are immediately apparent. This suggests the code is handling different types of operations or instructions. The prefixes like `kX64I`, `kX64S`, and the assembly mnemonics (`__ Pmovzxdq`, `__ I64x2UConvertI32x4High`, `ASSEMBLE_SIMD_BINOP`, etc.) are also key indicators. The presence of `Simd128Register`, `Simd256Register`, `XMMRegister`, `YMMRegister` strongly suggests the code deals with SIMD (Single Instruction, Multiple Data) operations.

3. **Decoding the `case` Labels:** I examined the structure of the `case` labels (e.g., `kX64I64x2UConvertI32x4High`). I inferred that:
    * `kX64` indicates an x64-specific instruction.
    * `I` likely stands for "integer".
    * `S` likely stands for "SIMD" or "scalar" (in the context of SIMD operations).
    * Numbers like `64x2`, `32x4`, `16x8` probably denote the data type and the number of lanes in a SIMD vector (e.g., 64-bit integers, 2 lanes).
    * Terms like `Convert`, `Min`, `Max`, `Add`, `Sub`, `Mul`, `Shift`, `Extract`, `Insert` describe the operation being performed.
    * `Low`, `High`, `U` (unsigned), `S` (signed) provide further details about the operation.

4. **Analyzing the Code within `case` Blocks:**  I looked at the code inside each `case`. The `__` prefix indicates calls to an assembly emitter or builder (likely part of V8's internal assembler). The names of the assembly functions often correspond directly to x64 instructions (e.g., `Pmovzxdq`, `vpmovzxdq`, `pminsb`, `pmaxsb`). This confirms the code's purpose of generating x64 assembly instructions. The use of `CpuFeatureScope` indicates conditional code generation based on CPU capabilities (like AVX2). Macros like `ASSEMBLE_SIMD_BINOP` and `ASSEMBLE_SIMD256_BINOP` abstract common patterns for binary SIMD operations.

5. **Identifying Functional Groups:** I started grouping the `case` statements based on their apparent function. For instance, many cases involve conversions between different SIMD vector types (e.g., `kX64I64x2UConvertI32x4High`). Others perform arithmetic operations (`kX64IMinS`, `kX64IMaxS`, `kX64IAddSatS`, etc.). Some deal with bitwise operations (`kX64SAnd`, `kX64SOr`, `kX64SXor`). There are also instructions for extracting and inserting elements (`kX64IExtractLaneS`, `kX64Pinsrb`).

6. **Considering the "Torque" Check:** The prompt asks about `.tq` files. Based on my knowledge of V8, Torque is a higher-level language used within V8 for defining built-in functions and sometimes low-level code. The C++ file extension `.cc` immediately tells me this is *not* a Torque file.

7. **Thinking about JavaScript Relevance:**  Since this is part of a JavaScript engine, I considered how these low-level SIMD operations relate to JavaScript. JavaScript's Typed Arrays and the WebAssembly SIMD proposal (now standardized) allow JavaScript code to directly leverage these kinds of vector operations for performance-critical tasks.

8. **Formulating Examples and Hypothetical Scenarios:** To illustrate the JavaScript connection and provide concrete examples, I imagined how these SIMD instructions might be used. For instance, the integer min/max instructions (`kX64IMinS`, `kX64IMaxS`) would be useful in image processing or other data manipulation tasks. The conversion instructions are needed when moving data between different representations.

9. **Identifying Potential Programming Errors:** I thought about common mistakes programmers might make when working with SIMD operations, such as:
    * Incorrect data types leading to unexpected results.
    * Not considering CPU feature support.
    * Off-by-one errors in lane indexing.

10. **Synthesizing the Information:**  Finally, I organized my findings into the requested format:

    * **Functionality:** I listed the main categories of operations the code handles (SIMD integer conversions, arithmetic, comparisons, bitwise operations, element access, etc.).
    * **Torque Check:** I explicitly stated that the file is C++ and not Torque.
    * **JavaScript Examples:** I provided JavaScript code snippets using Typed Arrays to demonstrate how these SIMD operations could be used.
    * **Hypothetical Input/Output:** I created a simple example for the `kX64I32x4SConvertF32x4` instruction to illustrate a concrete case.
    * **Common Programming Errors:** I listed some typical pitfalls when using SIMD.
    * **Part Summary:**  Given it's part 7 of 10, and focusing on the SIMD instructions, I summarized the functionality as generating x64 code for SIMD integer operations, type conversions, and related tasks, highlighting its role in optimizing JavaScript execution.

By following these steps, I could systematically analyze the code snippet and generate a comprehensive and informative response. My process involved understanding the context, recognizing patterns, decoding the instructions, relating them to JavaScript, and then structuring the information clearly.
这是一个V8 JavaScript引擎中用于x64架构的代码生成器的C++源代码文件（`code-generator-x64.cc`）。从提供的代码片段来看，它专注于处理SIMD（Single Instruction, Multiple Data）相关的指令生成。

以下是它的功能列表：

1. **SIMD 数据类型转换:**  代码中包含了大量的 `case` 语句，对应于不同的SIMD数据类型转换指令，例如：
   - `kX64I64x2UConvertI32x4High`: 将 4 个 32 位整数向量的高 2 个转换为 2 个 64 位无符号整数。
   - `kX64I32x4SConvertF32x4`: 将 4 个 32 位浮点数转换为 4 个 32 位有符号整数。
   - `kX64I16x8SConvertI8x16Low`: 将 16 个 8 位整数向量的低 8 个转换为 8 个 16 位有符号整数。
   - 以及各种无符号 (`U`) 和有符号 (`S`)，以及不同位宽之间的转换。

2. **SIMD 最小值和最大值操作:**
   - `kX64IMinS`:  计算两个 SIMD 向量中对应元素的有符号最小值 (支持 8 位、16 位和 32 位)。
   - `kX64IMaxS`:  计算两个 SIMD 向量中对应元素的有符号最大值。
   - `kX64IMinU`:  计算两个 SIMD 向量中对应元素的无符号最小值。
   - `kX64IMaxU`:  计算两个 SIMD 向量中对应元素的无符号最大值。

3. **SIMD 比较操作 (大于等于):**
   - `kX64IGtU`:  比较两个 SIMD 向量中对应元素的无符号大于关系。
   - `kX64IGeU`:  比较两个 SIMD 向量中对应元素的无符号大于等于关系。

4. **SIMD 点积操作:**
   - `kX64I32x4DotI16x8S`: 计算 8 个 16 位有符号整数与另一个向量的点积，结果为 4 个 32 位整数。
   - `kX64I32x4DotI8x16I7x16AddS`:  对 16 个 8 位整数进行带饱和加法的点积运算。
   - `kX64I32x8DotI8x32I7x32AddS`:  与上类似，但处理 32 个 8 位整数。
   - `kX64I16x8DotI8x16I7x16S`: 计算 16 个 8 位有符号整数的点积，结果为 8 个 16 位整数。
   - `kX64I16x16DotI8x32I7x32S`: 与上类似，但处理 32 个 8 位整数。

5. **SIMD 扩展加法操作:**
   - `kX64I32x4ExtAddPairwiseI16x8S`: 将 8 个 16 位整数对进行成对的扩展加法，得到 4 个 32 位整数。
   - `kX64I32x8ExtAddPairwiseI16x16S`: 与上类似，处理 16 个 16 位整数。
   - 提供了有符号 (`S`) 和无符号 (`U`) 版本。

6. **SIMD 移位和零扩展操作:**
   - `kX64I32X4ShiftZeroExtendI8x16`: 将 16 个 8 位整数移动指定位数并进行零扩展得到 4 个 32 位整数。

7. **SIMD 常量操作:**
   - `kX64S128Const`: 加载 128 位常量到 SIMD 寄存器。
   - `kX64SZero`: 将 SIMD 寄存器设置为全零。
   - `kX64SAllOnes`: 将 SIMD 寄存器设置为全一。

8. **SIMD 元素提取:**
   - `kX64IExtractLaneS`: 从 SIMD 向量中提取指定索引的元素 (支持 8 位和 16 位有符号整数)。

9. **SIMD 加法和减法饱和运算:**
   - `kX64IAddSatS`:  有符号饱和加法。
   - `kX64ISubSatS`:  有符号饱和减法。
   - `kX64IAddSatU`:  无符号饱和加法。
   - `kX64ISubSatU`:  无符号饱和减法。

10. **SIMD 平均值运算:**
    - `kX64IRoundingAverageU`: 计算两个 SIMD 向量对应元素的无符号平均值并进行舍入。

11. **SIMD 扩展乘法操作:**
    - `kX64I16x8ExtMulLowI8x16S`: 将 16 个 8 位有符号整数与另一个向量进行扩展乘法，取低 8 个 16 位结果。
    - `kX64I16x8ExtMulHighI8x16S`:  与上类似，取高 8 个 16 位结果。
    - 提供了有符号 (`S`) 和无符号 (`U`) 版本。

12. **SIMD Q15 乘法操作:**
    - `kX64I16x8Q15MulRSatS`:  将两个 16 位有符号整数向量进行 Q15 乘法，结果进行舍入和饱和。
    - `kX64I16x8RelaxedQ15MulRS`:  宽松的 Q15 乘法。

13. **SIMD 按位逻辑运算:**
    - `kX64SAnd`:  按位与。
    - `kX64SOr`:   按位或。
    - `kX64SXor`:  按位异或。
    - `kX64SNot`:  按位取反。
    - `kX64SSelect`:  按条件选择。
    - `kX64SAndNot`: 按位与非。

14. **SIMD 混洗和置换操作:**
    - `kX64I8x16Swizzle`:  根据指定的索引混洗 16 个 8 位字节。
    - `kX64Vpshufd`:  混洗 256 位向量中的 32 位双字。
    - `kX64I8x16Shuffle`:  根据指定的掩码混洗字节。

15. **SIMD 元素插入和提取到/从通用寄存器/内存:**
    - `kX64Pextrb`: 从 SIMD 寄存器提取字节到通用寄存器或内存。
    - `kX64Pextrw`: 从 SIMD 寄存器提取字到通用寄存器或内存。
    - `kX64Pinsrb`: 将通用寄存器或内存中的字节插入到 SIMD 寄存器。
    - `kX64Pinsrw`: 将通用寄存器或内存中的字插入到 SIMD 寄存器。
    - `kX64Pinsrd`: 将通用寄存器或内存中的双字插入到 SIMD 寄存器。
    - `kX64Pinsrq`: 将通用寄存器或内存中的四字插入到 SIMD 寄存器。

**关于文件类型和 JavaScript 关系:**

* 该文件以 `.cc` 结尾，这是一个标准的 C++ 源代码文件。因此，`v8/src/compiler/backend/x64/code-generator-x64.cc` **不是**一个 v8 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

* 这个文件与 JavaScript 的功能有密切关系。V8 引擎负责执行 JavaScript 代码，而这个文件是 V8 编译器的一部分，专门负责将 JavaScript 中涉及 SIMD 操作的代码（例如，使用 `TypedArray` 和 WebAssembly SIMD 指令）转换为底层的 x64 汇编指令，以便 CPU 可以高效地执行这些操作。

**JavaScript 举例说明:**

```javascript
// 假设我们使用了 Float32Array 和 SIMD 数据类型

const floatArray = new Float32Array([1.5, 2.5, 3.5, 4.5]);
const i32x4 = SIMD.int32x4(0, 0, 0, 0);

// 将 Float32Array 的数据转换为 int32x4 (对应 kX64I32x4SConvertF32x4)
const convertedInts = SIMD.float32x4.fromFloat32Array(floatArray).toI32x4();

console.log(convertedInts); // 输出类似: SIMD.int32x4(1, 2, 3, 4)  (小数部分被截断)

// 假设有两个 int32x4 向量
const a = SIMD.int32x4(1, 5, 2, 8);
const b = SIMD.int32x4(3, 2, 7, 1);

// 计算两个向量的最小值 (对应 kX64IMinS)
const minResult = SIMD.int32x4.min(a, b);
console.log(minResult); // 输出: SIMD.int32x4(1, 2, 2, 1)
```

**代码逻辑推理示例 (假设输入与输出):**

考虑 `kX64I32x4SConvertF32x4` 的情况：

**假设输入:** 一个 `Float32Array`，其值为 `[1.7, -2.3, 3.9, -4.1]`。

**对应到指令:**  `__ I32x4SConvertF32x4(i.OutputSimd128Register(), i.InputSimd128Register(0), kScratchDoubleReg, kScratchRegister);`

**推理:** 这段代码会生成将浮点数转换为有符号 32 位整数的 x64 汇编指令。转换过程中，小数部分会被截断。

**预期输出:**  生成的 SIMD 寄存器中的值将相当于 `SIMD.int32x4(1, -2, 3, -4)`。

**用户常见的编程错误举例 (与 SIMD 相关):**

1. **数据类型不匹配:**  尝试将不兼容的数据类型传递给 SIMD 操作。例如，将一个包含字符串的数组尝试进行 SIMD 整数运算。
   ```javascript
   const mixedArray = [1, 2, "hello", 4];
   // 尝试将 mixedArray 转换为 SIMD.int32x4 会导致错误或不可预测的结果。
   ```

2. **未检查 CPU 特性支持:** 某些 SIMD 指令可能需要特定的 CPU 特性（例如 AVX2）。如果代码不检查这些特性，在不支持的 CPU 上运行会崩溃或产生错误。V8 内部会处理这些，但直接编写汇编或使用底层 API 时需要注意。

3. **错误的 Lane 索引:** 在提取或插入 SIMD 向量元素时，使用了超出范围的索引。
   ```javascript
   const vec = SIMD.int32x4(1, 2, 3, 4);
   // 尝试访问 vec 的第五个 lane 会导致错误 (有效的索引是 0, 1, 2, 3)。
   // vec.extractLane(4); // 错误
   ```

**第 7 部分功能归纳:**

作为第 7 部分，并且结合代码片段的内容，可以归纳出这部分 `code-generator-x64.cc` 的主要功能是：

**为 x64 架构生成执行 SIMD 整数运算和类型转换的机器代码。** 它涵盖了多种 SIMD 数据类型的转换、基本的算术和比较操作（如最小值、最大值、大于等于）、点积运算、扩展加法、移位和零扩展、常量加载、元素提取和插入、饱和运算、平均值运算、扩展乘法、Q15 乘法以及按位逻辑运算和混洗操作。这部分代码是 V8 引擎优化 JavaScript 中 SIMD 相关操作的关键组成部分。

### 提示词
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/code-generator-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
__ Pmovzxdq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I64x2UConvertI32x4High: {
      __ I64x2UConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kX64I64x4UConvertI32x4: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovzxdq(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I32x4SConvertF32x4: {
      __ I32x4SConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchRegister);
      break;
    }
    case kX64I32x8SConvertF32x8: {
      __ I32x8SConvertF32x8(i.OutputSimd256Register(),
                            i.InputSimd256Register(0), kScratchSimd256Reg,
                            kScratchRegister);
      break;
    }
    case kX64I32x4SConvertI16x8Low: {
      __ Pmovsxwd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I32x4SConvertI16x8High: {
      __ I32x4SConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kX64I32x8SConvertI16x8: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovsxwd(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64IMinS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MinS
            ASSEMBLE_SIMD_BINOP(pminsb);
            break;
          }
          case kL16: {
            // I16x8MinS
            ASSEMBLE_SIMD_BINOP(pminsw);
            break;
          }
          case kL32: {
            // I32x4MinS
            ASSEMBLE_SIMD_BINOP(pminsd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MinS
            ASSEMBLE_SIMD256_BINOP(pminsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16MinS
            ASSEMBLE_SIMD256_BINOP(pminsw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MinS
            ASSEMBLE_SIMD256_BINOP(pminsd, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IMaxS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MaxS
            ASSEMBLE_SIMD_BINOP(pmaxsb);
            break;
          }
          case kL16: {
            // I16x8MaxS
            ASSEMBLE_SIMD_BINOP(pmaxsw);
            break;
          }
          case kL32: {
            // I32x4MaxS
            ASSEMBLE_SIMD_BINOP(pmaxsd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MaxS
            ASSEMBLE_SIMD256_BINOP(pmaxsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16MaxS
            ASSEMBLE_SIMD256_BINOP(pmaxsw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MaxS
            ASSEMBLE_SIMD256_BINOP(pmaxsd, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I32x4UConvertF32x4: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp = i.TempSimd128Register(0);
      XMMRegister tmp2 = i.TempSimd128Register(1);
      __ I32x4TruncF32x4U(dst, dst, tmp, tmp2);
      break;
    }
    case kX64I32x8UConvertF32x8: {
      DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
      CpuFeatureScope avx_scope(masm(), AVX);
      CpuFeatureScope avx2_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      YMMRegister tmp1 = i.TempSimd256Register(0);
      YMMRegister tmp2 = i.TempSimd256Register(1);
      // NAN->0, negative->0
      __ vpxor(tmp2, tmp2, tmp2);
      __ vmaxps(dst, dst, tmp2);
      // scratch: float representation of max_signed
      __ vpcmpeqd(tmp2, tmp2, tmp2);
      __ vpsrld(tmp2, tmp2, uint8_t{1});  // 0x7fffffff
      __ vcvtdq2ps(tmp2, tmp2);           // 0x4f000000
      // tmp1: convert (src-max_signed).
      // Positive overflow lanes -> 0x7FFFFFFF
      // Negative lanes -> 0
      __ vmovaps(tmp1, dst);
      __ vsubps(tmp1, tmp1, tmp2);
      __ vcmpleps(tmp2, tmp2, tmp1);
      __ vcvttps2dq(tmp1, tmp1);
      __ vpxor(tmp1, tmp1, tmp2);
      __ vpxor(tmp2, tmp2, tmp2);
      __ vpmaxsd(tmp1, tmp1, tmp2);
      // convert. Overflow lanes above max_signed will be 0x80000000
      __ vcvttps2dq(dst, dst);
      // Add (src-max_signed) for overflow lanes.
      __ vpaddd(dst, dst, tmp1);
      break;
    }
    case kX64I32x4UConvertI16x8Low: {
      __ Pmovzxwd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I32x4UConvertI16x8High: {
      __ I32x4UConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kX64I32x8UConvertI16x8: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovzxwd(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64IMinU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MinU
            ASSEMBLE_SIMD_BINOP(pminub);
            break;
          }
          case kL16: {
            // I16x8MinU
            ASSEMBLE_SIMD_BINOP(pminuw);
            break;
          }
          case kL32: {
            // I32x4MinU
            ASSEMBLE_SIMD_BINOP(pminud);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MinU
            ASSEMBLE_SIMD256_BINOP(pminub, AVX2);
            break;
          }
          case kL16: {
            // I16x16MinU
            ASSEMBLE_SIMD256_BINOP(pminuw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MinU
            ASSEMBLE_SIMD256_BINOP(pminud, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IMaxU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MaxU
            ASSEMBLE_SIMD_BINOP(pmaxub);
            break;
          }
          case kL16: {
            // I16x8MaxU
            ASSEMBLE_SIMD_BINOP(pmaxuw);
            break;
          }
          case kL32: {
            // I32x4MaxU
            ASSEMBLE_SIMD_BINOP(pmaxud);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MaxU
            ASSEMBLE_SIMD256_BINOP(pmaxub, AVX2);
            break;
          }
          case kL16: {
            // I16x16MaxU
            ASSEMBLE_SIMD256_BINOP(pmaxuw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MaxU
            ASSEMBLE_SIMD256_BINOP(pmaxud, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IGtU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        XMMRegister dst = i.OutputSimd128Register();
        XMMRegister src = i.InputSimd128Register(1);
        switch (lane_size) {
          case kL8: {
            __ Pmaxub(dst, src);
            __ Pcmpeqb(dst, src);
            __ Pcmpeqb(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          case kL16: {
            // I16x8GtU
            __ Pmaxuw(dst, src);
            __ Pcmpeqw(dst, src);
            __ Pcmpeqw(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          case kL32: {
            // I32x4GtU
            __ Pmaxud(dst, src);
            __ Pcmpeqd(dst, src);
            __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(1);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32GtU
            __ vpmaxub(dst, dst, src);
            __ vpcmpeqb(dst, dst, src);
            __ vpcmpeqb(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          case kL16: {
            // I16x16GtU
            __ vpmaxuw(dst, dst, src);
            __ vpcmpeqw(dst, dst, src);
            __ vpcmpeqw(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          case kL32: {
            // I32x8GtU
            __ vpmaxud(dst, dst, src);
            __ vpcmpeqd(dst, dst, src);
            __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IGeU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        XMMRegister dst = i.OutputSimd128Register();
        XMMRegister src = i.InputSimd128Register(1);
        switch (lane_size) {
          case kL8: {
            // I8x16GeU
            __ Pminub(dst, src);
            __ Pcmpeqb(dst, src);
            break;
          }
          case kL16: {
            // I16x8GeU
            __ Pminuw(dst, src);
            __ Pcmpeqw(dst, src);
            break;
          }
          case kL32: {
            // I32x4GeU
            __ Pminud(dst, src);
            __ Pcmpeqd(dst, src);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(1);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32GeU
            __ vpminub(dst, dst, src);
            __ vpcmpeqb(dst, dst, src);
            break;
          }
          case kL16: {
            // I16x16GeU
            __ vpminuw(dst, dst, src);
            __ vpcmpeqw(dst, dst, src);
            break;
          }
          case kL32: {
            // I32x8GeU
            __ vpminud(dst, dst, src);
            __ vpcmpeqd(dst, dst, src);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I32x4DotI16x8S: {
      ASSEMBLE_SIMD_BINOP(pmaddwd);
      break;
    }
    case kX64I32x4DotI8x16I7x16AddS: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(2));
      // If AVX_VNNI supported, pass kScratchDoubleReg twice as unused
      // arguments.
      XMMRegister tmp = kScratchDoubleReg;
      if (!(CpuFeatures::IsSupported(AVX_VNNI) ||
            CpuFeatures::IsSupported(AVX_VNNI_INT8))) {
        tmp = i.TempSimd128Register(0);
      }
      __ I32x4DotI8x16I7x16AddS(
          i.OutputSimd128Register(), i.InputSimd128Register(0),
          i.InputSimd128Register(1), i.InputSimd128Register(2),
          kScratchDoubleReg, tmp);
      break;
    }
    case kX64I32x8DotI8x32I7x32AddS: {
      DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(2));
      // If AVX_VNNI supported, pass kScratchSimd256Reg twice as unused
      // arguments.
      YMMRegister tmp = kScratchSimd256Reg;
      if (!CpuFeatures::IsSupported(AVX_VNNI)) {
        tmp = i.TempSimd256Register(0);
      }
      __ I32x8DotI8x32I7x32AddS(
          i.OutputSimd256Register(), i.InputSimd256Register(0),
          i.InputSimd256Register(1), i.InputSimd256Register(2),
          kScratchSimd256Reg, tmp);
      break;
    }
    case kX64I32x4ExtAddPairwiseI16x8S: {
      __ I32x4ExtAddPairwiseI16x8S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchRegister);
      break;
    }
    case kX64I32x8ExtAddPairwiseI16x16S: {
      __ I32x8ExtAddPairwiseI16x16S(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I32x4ExtAddPairwiseI16x8U: {
      __ I32x4ExtAddPairwiseI16x8U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   kScratchDoubleReg);
      break;
    }
    case kX64I32x8ExtAddPairwiseI16x16U: {
      __ I32x8ExtAddPairwiseI16x16U(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I32X4ShiftZeroExtendI8x16: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      uint8_t shift = i.InputUint8(1);
      if (shift != 0) {
        __ Palignr(dst, src, shift);
        __ Pmovzxbd(dst, dst);
      } else {
        __ Pmovzxbd(dst, src);
      }
      break;
    }
    case kX64S128Const: {
      // Emit code for generic constants as all zeros, or ones cases will be
      // handled separately by the selector.
      XMMRegister dst = i.OutputSimd128Register();
      uint32_t imm[4] = {};
      for (int j = 0; j < 4; j++) {
        imm[j] = i.InputUint32(j);
      }
      SetupSimdImmediateInRegister(masm(), imm, dst);
      break;
    }
    case kX64SZero: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Zero
        XMMRegister dst = i.OutputSimd128Register();
        __ Pxor(dst, dst);
      } else if (vec_len == kV256) {  // S256Zero
        YMMRegister dst = i.OutputSimd256Register();
        CpuFeatureScope avx2_scope(masm(), AVX2);
        __ vpxor(dst, dst, dst);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SAllOnes: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128AllOnes
        XMMRegister dst = i.OutputSimd128Register();
        __ Pcmpeqd(dst, dst);
      } else if (vec_len == kV256) {  // S256AllOnes
        YMMRegister dst = i.OutputSimd256Register();
        CpuFeatureScope avx2_scope(masm(), AVX2);
        __ vpcmpeqd(dst, dst, dst);
      } else {
        UNREACHABLE();
      }
      break;
    }
    // case kX64I16x8ExtractLaneS: {
    case kX64IExtractLaneS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16ExtractLaneS
            Register dst = i.OutputRegister();
            __ Pextrb(dst, i.InputSimd128Register(0), i.InputUint8(1));
            __ movsxbl(dst, dst);
            break;
          }
          case kL16: {
            // I16x8ExtractLaneS
            Register dst = i.OutputRegister();
            __ Pextrw(dst, i.InputSimd128Register(0), i.InputUint8(1));
            __ movsxwl(dst, dst);
            break;
          }
          default:
            UNREACHABLE();
        }

      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I16x8SConvertI8x16Low: {
      __ Pmovsxbw(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8SConvertI8x16High: {
      __ I16x8SConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kX64I16x16SConvertI8x16: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovsxbw(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8SConvertI32x4: {
      ASSEMBLE_SIMD_BINOP(packssdw);
      break;
    }
    case kX64IAddSatS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16AddSatS
            ASSEMBLE_SIMD_BINOP(paddsb);
            break;
          }
          case kL16: {
            // I16x8AddSatS
            ASSEMBLE_SIMD_BINOP(paddsw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32AddSatS
            ASSEMBLE_SIMD256_BINOP(paddsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16AddSatS
            ASSEMBLE_SIMD256_BINOP(paddsw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64ISubSatS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16SubSatS
            ASSEMBLE_SIMD_BINOP(psubsb);
            break;
          }
          case kL16: {
            // I16x8SubSatS
            ASSEMBLE_SIMD_BINOP(psubsw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32SubSatS
            ASSEMBLE_SIMD256_BINOP(psubsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16SubSatS
            ASSEMBLE_SIMD256_BINOP(psubsw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I16x8UConvertI8x16Low: {
      __ Pmovzxbw(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8UConvertI8x16High: {
      __ I16x8UConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kX64I16x16UConvertI8x16: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovzxbw(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8UConvertI32x4: {
      ASSEMBLE_SIMD_BINOP(packusdw);
      break;
    }
    case kX64IAddSatU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16AddSatU
            ASSEMBLE_SIMD_BINOP(paddusb);
            break;
          }
          case kL16: {
            // I16x8AddSatU
            ASSEMBLE_SIMD_BINOP(paddusw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32AddSatU
            ASSEMBLE_SIMD256_BINOP(paddusb, AVX2);
            break;
          }
          case kL16: {
            // I16x16AddSatU
            ASSEMBLE_SIMD256_BINOP(paddusw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64ISubSatU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16SubSatU
            ASSEMBLE_SIMD_BINOP(psubusb);
            break;
          }
          case kL16: {
            // I16x8SubSatU
            ASSEMBLE_SIMD_BINOP(psubusw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32SubSatU
            ASSEMBLE_SIMD256_BINOP(psubusb, AVX2);
            break;
          }
          case kL16: {
            // I16x16SubSatU
            ASSEMBLE_SIMD256_BINOP(psubusw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IRoundingAverageU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16RoundingAverageU
            ASSEMBLE_SIMD_BINOP(pavgb);
            break;
          }
          case kL16: {
            // I16x8RoundingAverageU
            ASSEMBLE_SIMD_BINOP(pavgw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32RoundingAverageU
            ASSEMBLE_SIMD256_BINOP(pavgb, AVX2);
            break;
          }
          case kL16: {
            // I16x16RoundingAverageU
            ASSEMBLE_SIMD256_BINOP(pavgw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I16x8ExtMulLowI8x16S: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/true);
      break;
    }
    case kX64I16x8ExtMulHighI8x16S: {
      __ I16x8ExtMulHighS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kX64I16x8ExtMulLowI8x16U: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/false);
      break;
    }
    case kX64I16x8ExtMulHighI8x16U: {
      __ I16x8ExtMulHighU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kX64I16x8ExtAddPairwiseI8x16S: {
      __ I16x8ExtAddPairwiseI8x16S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchDoubleReg,
                                   kScratchRegister);
      break;
    }
    case kX64I16x16ExtAddPairwiseI8x32S: {
      __ I16x16ExtAddPairwiseI8x32S(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I16x8ExtAddPairwiseI8x16U: {
      __ I16x8ExtAddPairwiseI8x16U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchRegister);
      break;
    }
    case kX64I16x16ExtAddPairwiseI8x32U: {
      __ I16x16ExtAddPairwiseI8x32U(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I16x8Q15MulRSatS: {
      __ I16x8Q15MulRSatS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kX64I16x8RelaxedQ15MulRS: {
      __ Pmulhrsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kX64I16x8DotI8x16I7x16S: {
      __ I16x8DotI8x16I7x16S(i.OutputSimd128Register(),
                             i.InputSimd128Register(0),
                             i.InputSimd128Register(1));
      break;
    }
    case kX64I16x16DotI8x32I7x32S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      __ vpmaddubsw(i.OutputSimd256Register(), i.InputSimd256Register(1),
                    i.InputSimd256Register(0));
      break;
    }
    case kX64Pextrb: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      if (HasAddressingMode(instr)) {
        Operand operand = i.MemoryOperand(&index);
        __ Pextrb(operand, i.InputSimd128Register(index),
                  i.InputUint8(index + 1));
      } else {
        __ Pextrb(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputUint8(1));
      }
      break;
    }
    case kX64Pextrw: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      if (HasAddressingMode(instr)) {
        Operand operand = i.MemoryOperand(&index);
        __ Pextrw(operand, i.InputSimd128Register(index),
                  i.InputUint8(index + 1));
      } else {
        __ Pextrw(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputUint8(1));
      }
      break;
    }
    case kX64Pinsrb: {
      ASSEMBLE_PINSR(Pinsrb);
      break;
    }
    case kX64Pinsrw: {
      ASSEMBLE_PINSR(Pinsrw);
      break;
    }
    case kX64Pinsrd: {
      ASSEMBLE_PINSR(Pinsrd);
      break;
    }
    case kX64Pinsrq: {
      ASSEMBLE_PINSR(Pinsrq);
      break;
    }
    case kX64I8x16SConvertI16x8: {
      ASSEMBLE_SIMD_BINOP(packsswb);
      break;
    }
    case kX64I8x16UConvertI16x8: {
      ASSEMBLE_SIMD_BINOP(packuswb);
      break;
    }
    case kX64I32x4ExtMulLowI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true,
                     /*is_signed=*/true);
      break;
    }
    case kX64I32x4ExtMulHighI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false,
                     /*is_signed=*/true);
      break;
    }
    case kX64I32x4ExtMulLowI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true,
                     /*is_signed=*/false);
      break;
    }
    case kX64I32x4ExtMulHighI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false,
                     /*is_signed=*/false);
      break;
    }
    case kX64SAnd: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128And
        ASSEMBLE_SIMD_BINOP(pand);
      } else if (vec_len == kV256) {  // S256And
        ASSEMBLE_SIMD256_BINOP(pand, AVX2);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SOr: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Or
        ASSEMBLE_SIMD_BINOP(por);
      } else if (vec_len == kV256) {  // S256Or
        ASSEMBLE_SIMD256_BINOP(por, AVX2);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SXor: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Xor
        ASSEMBLE_SIMD_BINOP(pxor);
      } else if (vec_len == kV256) {  // S256Xor
        ASSEMBLE_SIMD256_BINOP(pxor, AVX2);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SNot: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Not
        __ S128Not(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kScratchDoubleReg);
      } else if (vec_len == kV256) {  // S256Not
        __ S256Not(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   kScratchSimd256Reg);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SSelect: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Select
        __ S128Select(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), i.InputSimd128Register(2),
                      kScratchDoubleReg);
      } else if (vec_len == kV256) {  // S256Select
        __ S256Select(i.OutputSimd256Register(), i.InputSimd256Register(0),
                      i.InputSimd256Register(1), i.InputSimd256Register(2),
                      kScratchSimd256Reg);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SAndNot: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128AndNot
        // The inputs have been inverted by instruction selector, so we can call
        // andnps here without any modifications.
        ASSEMBLE_SIMD_BINOP(andnps);
      } else if (vec_len == kV256) {  // S256AndNot
        // The inputs have been inverted by instruction selector, so we can call
        // andnps here without any modifications.
        ASSEMBLE_SIMD256_BINOP(andnps, AVX);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I8x16Swizzle: {
      __ I8x16Swizzle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), kScratchDoubleReg,
                      kScratchRegister, MiscField::decode(instr->opcode()));
      break;
    }
    case kX64Vpshufd: {
      if (instr->InputCount() == 2 && instr->InputAt(1)->IsImmediate()) {
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(0);
        uint8_t imm = i.InputUint8(1);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        __ vpshufd(dst, src, imm);
      } else {
        UNIMPLEMENTED();
      }
      break;
    }
    case kX64I8x16Shuffle: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp_simd = i.TempSimd128Register(0);
      DCHECK_NE(tmp_simd, i.InputSimd128Register(0));
      if (instr->InputCount() == 5) {  // only one input operand
        uint32_t mask[4] = {};
        DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
        for (int j = 4; j > 0; j--) {
          mask[j - 1] = i.InputUint32(j);
        }

        SetupSimdImmediateInRegister(masm(), mask, tmp_simd);
        __ Pshufb(dst, tmp_simd);
      } else {  // two input operands
        DCHECK_NE(tmp_simd, i.InputSimd128Register(1));
        DCHECK_EQ(6, instr->InputCount());
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 0);
        uint32_t mask1[4] = {};
        for (int j = 5; j > 1; j--) {
          uint32_t lanes = i.InputUint32(j);
          for (int k = 0; k < 32; k += 8) {
            uint8_t lane = lanes >> k;
            mask1[j - 2] |= (lane < kSimd128Size ? lane : 0x80) << k;
          }
        }
        SetupSimdImmediateInRegister(masm(), mask1, tmp_simd);
        __ Pshufb(kScratchDoubleReg, tmp_simd);
        uint32_t mask2[4] = {};
        if (instr->I
```