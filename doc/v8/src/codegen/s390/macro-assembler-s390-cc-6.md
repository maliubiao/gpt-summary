Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/s390/macro-assembler-s390.cc`. I need to analyze the code, identify its purpose, and then address the specific points raised in the prompt:

1. **List the functionality:**  I'll go through the code and describe what each function does. The code appears to implement various SIMD (Single Instruction, Multiple Data) operations for the s390 architecture.

2. **`.tq` extension:** I need to check if the file name ending is `.tq`. In this case, it's `.cc`, so it's not a Torque file.

3. **Relationship to JavaScript:**  SIMD operations are used to optimize certain JavaScript operations, especially those involving arrays and numerical computations. I'll need to provide a relevant JavaScript example.

4. **Code logic and I/O:** For functions with clear input-output transformations, I'll provide example inputs and outputs. This will be more straightforward for functions like conversions and packing.

5. **Common programming errors:**  I'll consider potential mistakes developers might make when using or implementing these kinds of low-level SIMD operations.

6. **Part number:** The prompt indicates this is part 7 of 8. I'll keep this in mind for the final summary, focusing on the types of SIMD operations covered in this section.

7. **Overall function:**  I'll synthesize the individual function descriptions into a concise summary of the section's purpose within the `macro-assembler-s390.cc` file.

**Detailed breakdown of the code:**

* **Float to Integer Conversions (`F32x4SConvertI32x4`, `F32x4UConvertI32x4`):** These functions convert four single-precision floating-point numbers to signed and unsigned 32-bit integers, respectively. They use either vector instructions (if `VECTOR_ENHANCE_FACILITY_2` is supported) or a loop-based approach.

* **Integer to Float Conversions (`F32x4SConvertI32x4`, `F32x4UConvertI32x4`):** These functions perform the reverse operation, converting four 32-bit integers to single-precision floats. Similar to the float-to-int conversions, they adapt based on CPU feature support.

* **Integer Packing (`I16x8SConvertI32x4`, `I8x16SConvertI16x8`, `I16x8UConvertI32x4`, `I8x16UConvertI16x8`):** These functions pack larger integer types into smaller ones. The 'S' variants likely handle signed saturation, while 'U' handles unsigned saturation (clamping negative values to zero).

* **Saturated Arithmetic (`I16x8AddSatS`, `I16x8SubSatS`, `I16x8AddSatU`, `I16x8SubSatU`, `I8x16AddSatS`, `I8x16SubSatS`, `I8x16AddSatU`, `I8x16SubSatU`):** These functions perform addition and subtraction with saturation, preventing overflow or underflow by clamping the results to the maximum or minimum representable values. The 'S' and 'U' suffixes denote signed and unsigned saturation, respectively. They use a macro `BINOP_EXTRACT` to handle the high and low parts of the vector.

* **Float Promotion and Demotion (`F64x2PromoteLowF32x4`, `F32x4DemoteF64x2Zero`):** These functions convert between different floating-point precisions. `PromoteLow` takes the lower two floats from a `F32x4` and converts them to two `F64` values. `Demote` does the opposite, taking two `F64` values and converting them to `F32`, filling the other two lanes with zero.

* **Pairwise Addition (`I32x4ExtAddPairwiseI16x8S`, `I32x4ExtAddPairwiseI16x8U`, `I16x8ExtAddPairwiseI8x16S`, `I16x8ExtAddPairwiseI8x16U`):** These functions add adjacent elements within the vector. The 'Ext' prefix suggests the result might have a larger element size.

* **Truncated Conversion (`I32x4TruncSatF64x2SZero`, `I32x4TruncSatF64x2UZero`):** These functions truncate 64-bit floats to 32-bit integers with saturation. The 'Zero' suffix indicates how NaN values are handled (converted to zero).

* **Constant Loading (`S128Const`):** This function loads a 128-bit constant value into a SIMD register.

* **Swizzle and Shuffle (`I8x16Swizzle`, `I8x16Shuffle`):** These functions rearrange elements within a vector. `Swizzle` uses an index vector to select elements, while `Shuffle` uses immediate values to specify the permutation.

* **Dot Product (`I32x4DotI16x8S`, `I32x4DotI8x16AddS`, `I16x8DotI8x16S`):** These functions calculate the dot product of vectors. The different suffixes indicate the data types involved.

* **Q15 Multiplication (`I16x8Q15MulRSatS`):** This function performs a Q15 (fixed-point) multiplication with rounding and saturation.

* **Load and Store with Transform (LE - Little-Endian):**  A series of `LoadAndSplat...LE`, `LoadAndExtend...LE`, `LoadV...ZeroLE`, `LoadLane...LE`, and `StoreLane...LE` functions are defined using macros. These functions load data from memory into SIMD registers, potentially performing operations like splatting (duplicating a value across the vector), extending (converting to larger types), or loading/storing specific lanes. The `LE` suffix indicates these are little-endian specific operations. They leverage vector instructions when available and fall back to scalar loads otherwise.

* **Stack Limit Loading (`LoadStackLimit`):** This function loads the stack limit from the Isolate data.

* **Switch Statement (`Switch`):** This function implements a jump table based on the value of a register.

* **Code Marking Checks (`JumpIfCodeIsMarkedForDeoptimization`, `JumpIfCodeIsTurbofanned`):** These functions check flags in a Code object to determine if it has been marked for deoptimization or is a Turbofan-generated code.

* **Optimized OSR Code Loading (`TryLoadOptimizedOsrCode`):** This function attempts to load optimized code for on-stack replacement (OSR) from the feedback vector.

* **API Function Calling (`CallApiFunctionAndReturn`):** This is a more complex function responsible for calling C++ API functions from V8. It manages handle scopes, checks for exceptions, and handles profiling.

After this detailed analysis, I can formulate the response.
这是目录为`v8/src/codegen/s390/macro-assembler-s390.cc` 的一个 V8 源代码文件的第 7 部分，共 8 部分。根据提供的代码片段，这一部分的主要功能是 **实现针对 s390 架构的 SIMD (Single Instruction, Multiple Data) 向量操作的宏汇编指令**。

具体来说，这段代码实现了以下类型的向量操作：

1. **浮点数和整数之间的转换：**
   - `F32x4SConvertI32x4`: 将 4 个单精度浮点数转换为带符号 32 位整数。
   - `F32x4UConvertI32x4`: 将 4 个单精度浮点数转换为无符号 32 位整数。
   - `F32x4SConvertI32x4`: 将 4 个带符号 32 位整数转换为单精度浮点数。
   - `F32x4UConvertI32x4`: 将 4 个无符号 32 位整数转换为单精度浮点数。

2. **整数类型的打包和转换：**
   - `I16x8SConvertI32x4`: 将 4 个 32 位整数打包成 8 个 16 位带符号整数。
   - `I8x16SConvertI16x8`: 将 8 个 16 位整数打包成 16 个 8 位带符号整数。
   - `I16x8UConvertI32x4`: 将 4 个 32 位整数打包成 8 个 16 位无符号整数（负数饱和为 0）。
   - `I8x16UConvertI16x8`: 将 8 个 16 位整数打包成 16 个 8 位无符号整数（负数饱和为 0）。

3. **饱和算术运算：**
   - `I16x8AddSatS`, `I16x8SubSatS`: 对 16 位带符号整数进行饱和加法和减法。
   - `I16x8AddSatU`, `I16x8SubSatU`: 对 16 位无符号整数进行饱和加法和减法。
   - `I8x16AddSatS`, `I8x16SubSatS`: 对 8 位带符号整数进行饱和加法和减法。
   - `I8x16AddSatU`, `I8x16SubSatU`: 对 8 位无符号整数进行饱和加法和减法。

4. **浮点数精度转换：**
   - `F64x2PromoteLowF32x4`: 将 `F32x4` 向量的低 2 个单精度浮点数提升为 2 个双精度浮点数。
   - `F32x4DemoteF64x2Zero`: 将 `F64x2` 向量的 2 个双精度浮点数降级为单精度浮点数，并将结果存储到 `F32x4` 向量的前两个元素，其余元素置零。

5. **成对运算：**
   - `I32x4ExtAddPairwiseI16x8S`: 将 8 个 16 位带符号整数成对相加得到 4 个 32 位整数。
   - `I32x4ExtAddPairwiseI16x8U`: 将 8 个 16 位无符号整数成对相加得到 4 个 32 位整数。
   - `I16x8ExtAddPairwiseI8x16S`: 将 16 个 8 位带符号整数成对相加得到 8 个 16 位整数。
   - `I16x8ExtAddPairwiseI8x16U`: 将 16 个 8 位无符号整数成对相加得到 8 个 16 位整数。

6. **截断转换：**
   - `I32x4TruncSatF64x2SZero`: 将 2 个双精度浮点数截断为带符号 32 位整数（NaN 转换为 0）。
   - `I32x4TruncSatF64x2UZero`: 将 2 个双精度浮点数截断为无符号 32 位整数（NaN 转换为 0）。

7. **常量加载：**
   - `S128Const`: 将 64 位的高位和低位值加载到 128 位 SIMD 寄存器中。

8. **向量元素重排：**
   - `I8x16Swizzle`: 根据索引向量 `src2` 的值，从 `src1` 中选择元素生成新的向量 `dst`。索引值大于 31 的元素将返回 0。
   - `I8x16Shuffle`: 根据立即数指定的掩码，从两个源向量 `src1` 和 `src2` 中选择元素生成新的向量 `dst`。

9. **点积运算：**
   - `I32x4DotI16x8S`: 计算两个 16 位带符号整数向量的点积，结果为 32 位整数向量。
   - `I32x4DotI8x16AddS`: 计算两个 8 位带符号整数向量的点积，并将结果与第三个向量 `src3` 相加。
   - `I16x8DotI8x16S`: 计算两个 8 位带符号整数向量的点积，结果为 16 位整数向量。

10. **Q15 定点乘法：**
    - `I16x8Q15MulRSatS`: 对两个 16 位整数向量进行 Q15 定点乘法，结果进行舍入和饱和处理。

11. **向量加载和存储操作 (Little-Endian)：**
    - 提供了一系列以 `LE` 结尾的函数，用于从内存加载数据到 SIMD 寄存器，以及将 SIMD 寄存器中的数据存储到内存。这些操作包括加载并复制（`LoadAndSplat`）、加载并扩展（`LoadAndExtend`）、加载并置零（`LoadVZeroLE`）、加载/存储特定通道（`LoadLaneLE`, `StoreLaneLE`）等。 这些函数会根据 CPU 是否支持 `VECTOR_ENHANCE_FACILITY_2` 以及内存操作数的偏移量是否在 12 位无符号整数范围内来选择使用向量指令或标量指令。

12. **其他辅助功能：**
    - `LoadStackLimit`: 加载堆栈限制。
    - `Switch`: 实现跳转表。
    - `JumpIfCodeIsMarkedForDeoptimization`: 如果代码被标记为需要反优化则跳转。
    - `JumpIfCodeIsTurbofanned`: 如果代码是 Turbofan 生成的则跳转。
    - `TryLoadOptimizedOsrCode`: 尝试加载用于 On-Stack Replacement (OSR) 的优化代码。
    - `CallApiFunctionAndReturn`: 调用 API 函数并处理返回值和异常。

**关于文件类型：**

`v8/src/codegen/s390/macro-assembler-s390.cc` 的文件扩展名是 `.cc`，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件的扩展名通常是 `.tq`）。

**与 JavaScript 的关系：**

这些宏汇编指令直接为 V8 引擎的 s390 架构后端提供底层的 SIMD 操作支持。JavaScript 代码本身不能直接调用这些指令，但 V8 引擎会利用这些指令来优化某些 JavaScript 操作，特别是那些涉及大量数值计算或数据并行处理的操作。

**JavaScript 示例：**

JavaScript 的 `TypedArray` 和 `WebAssembly SIMD` API 可以受益于这些底层的 SIMD 指令。例如，一个简单的数组元素相加操作：

```javascript
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  c[i] = a[i] + b[i];
}

console.log(c); // 输出: Float32Array [ 6, 8, 10, 12 ]
```

在 V8 引擎中，如果目标架构支持 SIMD，并且开启了相应的优化，那么这个循环中的加法操作可能会被编译成类似 `F32x4Add` 的 SIMD 指令，从而一次性处理 4 个浮点数的加法，提高性能。虽然提供的代码片段中没有直接的 `F32x4Add`，但其他操作如浮点数转换是构建更复杂 SIMD 操作的基础。

**代码逻辑推理 (假设输入与输出):**

以 `I16x8AddSatS` 为例，它执行 8 个 16 位带符号整数的饱和加法。

**假设输入:**
- `src1` 的 8 个 16 位元素为: `[10000, 20000, -15000, -30000, 5000, 10000, -5000, -10000]`
- `src2` 的 8 个 16 位元素为: `[5000, -10000, 20000, 10000, 15000, -20000, -10000, 5000]`

**输出 (饱和后):**
- `dst` 的 8 个 16 位元素为: `[15000, 10000, 5000, -20000, 20000, -10000, -15000, -5000]`

例如，第一个元素的计算是 `10000 + 5000 = 15000`。第二个元素的计算是 `20000 + (-10000) = 10000`。第三个元素的计算是 `-15000 + 20000 = 5000`。第四个元素的计算是 `-30000 + 10000 = -20000`。

**用户常见的编程错误举例:**

在使用类似 SIMD 指令时，用户可能会犯以下错误：

1. **数据类型不匹配:** 将不兼容的数据类型传递给 SIMD 操作，例如将浮点数向量传递给需要整数向量的操作。
2. **向量长度不匹配:** 假设所有的 SIMD 寄存器都具有相同的长度，但实际上不同的操作可能处理不同数量的元素。
3. **忽略饱和行为:**  在进行饱和算术运算时，没有考虑到溢出或下溢会被限制在最大或最小值，导致对结果的预期错误。例如，两个很大的正数相加，如果期望得到一个更大的数，但实际由于饱和，结果会是最大值。
4. **字节序问题:** 在处理内存加载和存储时，没有正确处理字节序（例如 Little-Endian 和 Big-Endian）可能导致数据解析错误。提供的代码中 `Load...LE` 表明是针对 Little-Endian 的操作。
5. **错误的索引或掩码:** 在使用 `Swizzle` 或 `Shuffle` 等重排指令时，使用了错误的索引或掩码，导致元素排列顺序不符合预期。

**功能归纳 (第 7 部分):**

这部分 `macro-assembler-s390.cc` 的代码主要集中在 **为 s390 架构实现各种 SIMD 向量操作，包括浮点数和整数之间的转换、整数类型的打包和转换、饱和算术运算、浮点数精度转换、成对运算、截断转换、常量加载、向量元素重排、点积运算以及 Q15 定点乘法。此外，还包含了一些辅助功能，如加载堆栈限制、实现跳转表、检查代码标记以及调用 API 函数。**  这些底层的宏汇编指令是 V8 引擎在 s390 架构上执行高性能 JavaScript 代码的关键组成部分。尤其值得注意的是，这一部分还详细定义了针对 Little-Endian 架构的向量加载和存储操作，体现了对不同字节序的支持。

### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
Register scratch2) {
  // vclgd or ConvertFloat32ToUnsignedInt32 will convert NaN to 0, negative to 0
  // automatically.
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vclgd(dst, src, Condition(5), Condition(0), Condition(2));
  } else {
    CONVERT_FLOAT_TO_INT32(ConvertFloat32ToUnsignedInt32, dst, src, scratch1,
                           scratch2)
  }
}
#undef CONVERT_FLOAT_TO_INT32

#define CONVERT_INT32_TO_FLOAT(convert, dst, src, scratch1, scratch2) \
  for (int index = 0; index < 4; index++) {                           \
    vlgv(scratch2, src, MemOperand(r0, index), Condition(2));         \
    convert(scratch1, scratch2);                                      \
    MovFloatToInt(scratch2, scratch1);                                \
    vlvg(dst, scratch2, MemOperand(r0, index), Condition(2));         \
  }
void MacroAssembler::F32x4SConvertI32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
                                        Register scratch2) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vcdg(dst, src, Condition(4), Condition(0), Condition(2));
  } else {
    CONVERT_INT32_TO_FLOAT(ConvertIntToFloat, dst, src, scratch1, scratch2)
  }
}
void MacroAssembler::F32x4UConvertI32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
                                        Register scratch2) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vcdlg(dst, src, Condition(4), Condition(0), Condition(2));
  } else {
    CONVERT_INT32_TO_FLOAT(ConvertUnsignedIntToFloat, dst, src, scratch1,
                           scratch2)
  }
}
#undef CONVERT_INT32_TO_FLOAT

void MacroAssembler::I16x8SConvertI32x4(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpks(dst, src2, src1, Condition(0), Condition(2));
}

void MacroAssembler::I8x16SConvertI16x8(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpks(dst, src2, src1, Condition(0), Condition(1));
}

#define VECTOR_PACK_UNSIGNED(dst, src1, src2, scratch, mode)       \
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), \
     Condition(0), Condition(mode));                               \
  vmx(scratch, src1, kDoubleRegZero, Condition(0), Condition(0),   \
      Condition(mode));                                            \
  vmx(dst, src2, kDoubleRegZero, Condition(0), Condition(0), Condition(mode));
void MacroAssembler::I16x8UConvertI32x4(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2,
                                        Simd128Register scratch) {
  // treat inputs as signed, and saturate to unsigned (negative to 0).
  VECTOR_PACK_UNSIGNED(dst, src1, src2, scratch, 2)
  vpkls(dst, dst, scratch, Condition(0), Condition(2));
}

void MacroAssembler::I8x16UConvertI16x8(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2,
                                        Simd128Register scratch) {
  // treat inputs as signed, and saturate to unsigned (negative to 0).
  VECTOR_PACK_UNSIGNED(dst, src1, src2, scratch, 1)
  vpkls(dst, dst, scratch, Condition(0), Condition(1));
}
#undef VECTOR_PACK_UNSIGNED

#define BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, op, extract_high, \
                      extract_low, mode)                                     \
  DCHECK(dst != scratch1 && dst != scratch2);                                \
  DCHECK(dst != src1 && dst != src2);                                        \
  extract_high(scratch1, src1, Condition(0), Condition(0), Condition(mode)); \
  extract_high(scratch2, src2, Condition(0), Condition(0), Condition(mode)); \
  op(dst, scratch1, scratch2, Condition(0), Condition(0),                    \
     Condition(mode + 1));                                                   \
  extract_low(scratch1, src1, Condition(0), Condition(0), Condition(mode));  \
  extract_low(scratch2, src2, Condition(0), Condition(0), Condition(mode));  \
  op(scratch1, scratch1, scratch2, Condition(0), Condition(0),               \
     Condition(mode + 1));
void MacroAssembler::I16x8AddSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuph, vupl, 1)
  vpks(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I16x8SubSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuph, vupl, 1)
  vpks(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I16x8AddSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuplh, vupll, 1)
  vpkls(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I16x8SubSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuplh, vupll, 1)
  // negative intermediate values to 0.
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(0));
  vmx(dst, kDoubleRegZero, dst, Condition(0), Condition(0), Condition(2));
  vmx(scratch1, kDoubleRegZero, scratch1, Condition(0), Condition(0),
      Condition(2));
  vpkls(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I8x16AddSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuph, vupl, 0)
  vpks(dst, dst, scratch1, Condition(0), Condition(1));
}

void MacroAssembler::I8x16SubSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuph, vupl, 0)
  vpks(dst, dst, scratch1, Condition(0), Condition(1));
}

void MacroAssembler::I8x16AddSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuplh, vupll, 0)
  vpkls(dst, dst, scratch1, Condition(0), Condition(1));
}

void MacroAssembler::I8x16SubSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuplh, vupll, 0)
  // negative intermediate values to 0.
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(0));
  vmx(dst, kDoubleRegZero, dst, Condition(0), Condition(0), Condition(1));
  vmx(scratch1, kDoubleRegZero, scratch1, Condition(0), Condition(0),
      Condition(1));
  vpkls(dst, dst, scratch1, Condition(0), Condition(1));
}
#undef BINOP_EXTRACT

void MacroAssembler::F64x2PromoteLowF32x4(Simd128Register dst,
                                          Simd128Register src,
                                          Simd128Register scratch1,
                                          Register scratch2, Register scratch3,
                                          Register scratch4) {
  Register holder = scratch3;
  for (int index = 0; index < 2; ++index) {
    vlgv(scratch2, src, MemOperand(scratch2, index + 2), Condition(2));
    MovIntToFloat(scratch1, scratch2);
    ldebr(scratch1, scratch1);
    MovDoubleToInt64(holder, scratch1);
    holder = scratch4;
  }
  vlvgp(dst, scratch3, scratch4);
}

void MacroAssembler::F32x4DemoteF64x2Zero(Simd128Register dst,
                                          Simd128Register src,
                                          Simd128Register scratch1,
                                          Register scratch2, Register scratch3,
                                          Register scratch4) {
  Register holder = scratch3;
  for (int index = 0; index < 2; ++index) {
    vlgv(scratch2, src, MemOperand(r0, index), Condition(3));
    MovInt64ToDouble(scratch1, scratch2);
    ledbr(scratch1, scratch1);
    MovFloatToInt(holder, scratch1);
    holder = scratch4;
  }
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(2));
  vlvg(dst, scratch3, MemOperand(r0, 2), Condition(2));
  vlvg(dst, scratch4, MemOperand(r0, 3), Condition(2));
}

#define EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, lane_size, mul_even, \
                         mul_odd)                                           \
  CHECK_NE(src, scratch2);                                                  \
  vrepi(scratch2, Operand(1), Condition(lane_size));                        \
  mul_even(scratch1, src, scratch2, Condition(0), Condition(0),             \
           Condition(lane_size));                                           \
  mul_odd(scratch2, src, scratch2, Condition(0), Condition(0),              \
          Condition(lane_size));                                            \
  va(dst, scratch1, scratch2, Condition(0), Condition(0),                   \
     Condition(lane_size + 1));
void MacroAssembler::I32x4ExtAddPairwiseI16x8S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, 1, vme, vmo)
}

void MacroAssembler::I32x4ExtAddPairwiseI16x8U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register /* scratch1 */,
                                               Simd128Register /* scratch2 */) {
  // Unnamed scratch parameters are still kept to make this function
  // have the same signature as the other ExtAddPairwise functions.
  // TF and Liftoff use a uniform Macro for all of them.
  // TODO(miladfarca): Add a default argument or separate them in TF and
  // Liftoff.
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(3));
  vsum(dst, src, kDoubleRegZero, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I16x8ExtAddPairwiseI8x16S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, 0, vme, vmo)
}

void MacroAssembler::I16x8ExtAddPairwiseI8x16U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, 0, vmle, vmlo)
}
#undef EXT_ADD_PAIRWISE

void MacroAssembler::I32x4TruncSatF64x2SZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  // NaN to 0.
  vfce(scratch, src, src, Condition(0), Condition(0), Condition(3));
  vn(scratch, src, scratch, Condition(0), Condition(0), Condition(0));
  vcgd(scratch, scratch, Condition(5), Condition(0), Condition(3));
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(2));
  vpks(dst, dst, scratch, Condition(0), Condition(3));
}

void MacroAssembler::I32x4TruncSatF64x2UZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  vclgd(scratch, src, Condition(5), Condition(0), Condition(3));
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(2));
  vpkls(dst, dst, scratch, Condition(0), Condition(3));
}

void MacroAssembler::S128Const(Simd128Register dst, uint64_t high, uint64_t low,
                               Register scratch1, Register scratch2) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  vlvgp(dst, scratch2, scratch1);
}

void MacroAssembler::I8x16Swizzle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2, Register scratch1,
                                  Register scratch2, Simd128Register scratch3) {
  DCHECK(!AreAliased(src1, src2, scratch3));
  // Saturate the indices to 5 bits. Input indices more than 31 should
  // return 0.
  vrepi(scratch3, Operand(31), Condition(0));
  vmnl(scratch3, src2, scratch3, Condition(0), Condition(0), Condition(0));
  // Input needs to be reversed.
  vlgv(scratch1, src1, MemOperand(r0, 0), Condition(3));
  vlgv(scratch2, src1, MemOperand(r0, 1), Condition(3));
  lrvgr(scratch1, scratch1);
  lrvgr(scratch2, scratch2);
  vlvgp(dst, scratch2, scratch1);
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(0));
  vperm(dst, dst, kDoubleRegZero, scratch3, Condition(0), Condition(0));
}

void MacroAssembler::I8x16Shuffle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2, uint64_t high,
                                  uint64_t low, Register scratch1,
                                  Register scratch2, Simd128Register scratch3) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  vlvgp(scratch3, scratch2, scratch1);
  vperm(dst, src1, src2, scratch3, Condition(0), Condition(0));
}

void MacroAssembler::I32x4DotI16x8S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2,
                                    Simd128Register scratch) {
  vme(scratch, src1, src2, Condition(0), Condition(0), Condition(1));
  vmo(dst, src1, src2, Condition(0), Condition(0), Condition(1));
  va(dst, scratch, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I32x4DotI8x16AddS(
    Simd128Register dst, Simd128Register src1, Simd128Register src2,
    Simd128Register src3, Simd128Register scratch1, Simd128Register scratch2) {
  DCHECK_NE(dst, src3);
  // I8 -> I16.
  vme(scratch1, src1, src2, Condition(0), Condition(0), Condition(0));
  vmo(dst, src1, src2, Condition(0), Condition(0), Condition(0));
  va(dst, scratch1, dst, Condition(0), Condition(0), Condition(1));
  // I16 -> I32.
  vrepi(scratch2, Operand(1), Condition(1));
  vme(scratch1, dst, scratch2, Condition(0), Condition(0), Condition(1));
  vmo(dst, dst, scratch2, Condition(0), Condition(0), Condition(1));
  va(dst, scratch1, dst, Condition(0), Condition(0), Condition(2));
  // Add src3.
  va(dst, dst, src3, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I16x8DotI8x16S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2,
                                    Simd128Register scratch) {
  vme(scratch, src1, src2, Condition(0), Condition(0), Condition(0));
  vmo(dst, src1, src2, Condition(0), Condition(0), Condition(0));
  va(dst, scratch, dst, Condition(0), Condition(0), Condition(1));
}

#define Q15_MUL_ROAUND(accumulator, src1, src2, const_val, scratch, unpack) \
  unpack(scratch, src1, Condition(0), Condition(0), Condition(1));          \
  unpack(accumulator, src2, Condition(0), Condition(0), Condition(1));      \
  vml(accumulator, scratch, accumulator, Condition(0), Condition(0),        \
      Condition(2));                                                        \
  va(accumulator, accumulator, const_val, Condition(0), Condition(0),       \
     Condition(2));                                                         \
  vrepi(scratch, Operand(15), Condition(2));                                \
  vesrav(accumulator, accumulator, scratch, Condition(0), Condition(0),     \
         Condition(2));
void MacroAssembler::I16x8Q15MulRSatS(Simd128Register dst, Simd128Register src1,
                                      Simd128Register src2,
                                      Simd128Register scratch1,
                                      Simd128Register scratch2,
                                      Simd128Register scratch3) {
  DCHECK(!AreAliased(src1, src2, scratch1, scratch2, scratch3));
  vrepi(scratch1, Operand(0x4000), Condition(2));
  Q15_MUL_ROAUND(scratch2, src1, src2, scratch1, scratch3, vupl)
  Q15_MUL_ROAUND(dst, src1, src2, scratch1, scratch3, vuph)
  vpks(dst, dst, scratch2, Condition(0), Condition(2));
}
#undef Q15_MUL_ROAUND

// Vector LE Load and Transform instructions.
#ifdef V8_TARGET_BIG_ENDIAN
#define IS_BIG_ENDIAN true
#else
#define IS_BIG_ENDIAN false
#endif

#define CAN_LOAD_STORE_REVERSE \
  IS_BIG_ENDIAN&& CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)

#define LOAD_SPLAT_LIST(V)       \
  V(64x2, vlbrrep, LoadU64LE, 3) \
  V(32x4, vlbrrep, LoadU32LE, 2) \
  V(16x8, vlbrrep, LoadU16LE, 1) \
  V(8x16, vlrep, LoadU8, 0)

#define LOAD_SPLAT(name, vector_instr, scalar_instr, condition)       \
  void MacroAssembler::LoadAndSplat##name##LE(                        \
      Simd128Register dst, const MemOperand& mem, Register scratch) { \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {          \
      vector_instr(dst, mem, Condition(condition));                   \
      return;                                                         \
    }                                                                 \
    scalar_instr(scratch, mem);                                       \
    vlvg(dst, scratch, MemOperand(r0, 0), Condition(condition));      \
    vrep(dst, dst, Operand(0), Condition(condition));                 \
  }
LOAD_SPLAT_LIST(LOAD_SPLAT)
#undef LOAD_SPLAT
#undef LOAD_SPLAT_LIST

#define LOAD_EXTEND_LIST(V) \
  V(32x2U, vuplh, 2)        \
  V(32x2S, vuph, 2)         \
  V(16x4U, vuplh, 1)        \
  V(16x4S, vuph, 1)         \
  V(8x8U, vuplh, 0)         \
  V(8x8S, vuph, 0)

#define LOAD_EXTEND(name, unpack_instr, condition)                            \
  void MacroAssembler::LoadAndExtend##name##LE(                               \
      Simd128Register dst, const MemOperand& mem, Register scratch) {         \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {                  \
      vlebrg(dst, mem, Condition(0));                                         \
    } else {                                                                  \
      LoadU64LE(scratch, mem);                                                \
      vlvg(dst, scratch, MemOperand(r0, 0), Condition(3));                    \
    }                                                                         \
    unpack_instr(dst, dst, Condition(0), Condition(0), Condition(condition)); \
  }
LOAD_EXTEND_LIST(LOAD_EXTEND)
#undef LOAD_EXTEND
#undef LOAD_EXTEND

void MacroAssembler::LoadV32ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch) {
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(0));
  if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {
    vlebrf(dst, mem, Condition(3));
    return;
  }
  LoadU32LE(scratch, mem);
  vlvg(dst, scratch, MemOperand(r0, 3), Condition(2));
}

void MacroAssembler::LoadV64ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch) {
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(0));
  if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {
    vlebrg(dst, mem, Condition(1));
    return;
  }
  LoadU64LE(scratch, mem);
  vlvg(dst, scratch, MemOperand(r0, 1), Condition(3));
}

#define LOAD_LANE_LIST(V)     \
  V(64, vlebrg, LoadU64LE, 3) \
  V(32, vlebrf, LoadU32LE, 2) \
  V(16, vlebrh, LoadU16LE, 1) \
  V(8, vleb, LoadU8, 0)

#define LOAD_LANE(name, vector_instr, scalar_instr, condition)             \
  void MacroAssembler::LoadLane##name##LE(Simd128Register dst,             \
                                          const MemOperand& mem, int lane, \
                                          Register scratch) {              \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {               \
      vector_instr(dst, mem, Condition(lane));                             \
      return;                                                              \
    }                                                                      \
    scalar_instr(scratch, mem);                                            \
    vlvg(dst, scratch, MemOperand(r0, lane), Condition(condition));        \
  }
LOAD_LANE_LIST(LOAD_LANE)
#undef LOAD_LANE
#undef LOAD_LANE_LIST

#define STORE_LANE_LIST(V)      \
  V(64, vstebrg, StoreU64LE, 3) \
  V(32, vstebrf, StoreU32LE, 2) \
  V(16, vstebrh, StoreU16LE, 1) \
  V(8, vsteb, StoreU8, 0)

#define STORE_LANE(name, vector_instr, scalar_instr, condition)             \
  void MacroAssembler::StoreLane##name##LE(Simd128Register src,             \
                                           const MemOperand& mem, int lane, \
                                           Register scratch) {              \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {                \
      vector_instr(src, mem, Condition(lane));                              \
      return;                                                               \
    }                                                                       \
    vlgv(scratch, src, MemOperand(r0, lane), Condition(condition));         \
    scalar_instr(scratch, mem);                                             \
  }
STORE_LANE_LIST(STORE_LANE)
#undef STORE_LANE
#undef STORE_LANE_LIST
#undef CAN_LOAD_STORE_REVERSE
#undef IS_BIG_ENDIAN

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();
  CHECK(is_int32(offset));
  LoadU64(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::Switch(Register scratch, Register value,
                            int case_value_base, Label** labels,
                            int num_labels) {
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    SubS64(value, value, Operand(case_value_base));
  }
  CmpU64(value, Operand(num_labels));
  bge(&fallthrough);

  int entry_size_log2 = 3;
  ShiftLeftU32(value, value, Operand(entry_size_log2));
  larl(r1, &jump_table);
  lay(r1, MemOperand(value, r1));
  b(r1);

  bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    b(labels[i]);
    dh(0);
  }
  bind(&fallthrough);
}

void MacroAssembler::JumpIfCodeIsMarkedForDeoptimization(
    Register code, Register scratch, Label* if_marked_for_deoptimization) {
  TestCodeIsMarkedForDeoptimization(code, scratch);
  bne(if_marked_for_deoptimization);
}

void MacroAssembler::JumpIfCodeIsTurbofanned(Register code, Register scratch,
                                             Label* if_turbofanned) {
  LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  TestBit(scratch, Code::kIsTurbofannedBit, scratch);
  bne(if_turbofanned);
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance) {
  Label fallthrough, clear_slot;
  LoadTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    // The entry references a CodeWrapper object. Unwrap it now.
    LoadTaggedField(
        scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    JumpIfCodeIsMarkedForDeoptimization(scratch_and_result, temp, &clear_slot);
    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      JumpIfCodeIsTurbofanned(scratch_and_result, temp, on_result);
      b(&fallthrough);
    } else {
      b(on_result);
    }
  }

  bind(&clear_slot);
  mov(scratch_and_result, ClearedValue());
  StoreTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));

  bind(&fallthrough);
  mov(scratch_and_result, Operand::Zero());
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand) {
  using ER = ExternalReference;

  Isolate* isolate = masm->isolate();
  MemOperand next_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_next_address(isolate), no_reg);
  MemOperand limit_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_limit_address(isolate), no_reg);
  MemOperand level_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_level_address(isolate), no_reg);

  Register return_value = r2;
#if V8_OS_ZOS
  Register scratch = r6;
#else
  Register scratch = ip;
#endif
  Register scratch2 = r1;

  // Allocate HandleScope in callee-saved registers.
  // We will need to restore the HandleScope after the call to the API function,
  // by allocating it in callee-saved registers it'll be preserved by C code.
#if V8_OS_ZOS
  Register prev_next_address_reg = r14;
#else
  Register prev_next_address_reg = r6;
#endif
  Register prev_limit_reg = r7;
  Register prev_level_reg = r8;

  // C arguments (kCArgRegs[0/1]) are expected to be initialized outside, so
  // this function must not corrupt them (return_value overlaps with
  // kCArgRegs[0] but that's ok because we start using it only after the C
  // call).
  DCHECK(!AreAliased(kCArgRegs[0], kCArgRegs[1],  // C args
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  // function_address and thunk_arg might overlap but this function must not
  // corrupted them until the call is made (i.e. overlap with return_value is
  // fine).
  DCHECK(!AreAliased(function_address,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  DCHECK(!AreAliased(thunk_arg,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Allocate HandleScope in callee-save registers.");
    __ LoadU64(prev_next_address_reg, next_mem_op);
    __ LoadU64(prev_limit_reg, limit_mem_op);
    __ LoadU32(prev_level_reg, level_mem_op);
    __ AddS64(scratch, prev_level_reg, Operand(1));
    __ StoreU32(scratch, level_mem_op);
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ LoadU8(scratch,
              __ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode));
    __ CmpS64(scratch, Operand::Zero());
    __ bne(&profiler_or_side_effects_check_enabled, Label::kNear);
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ Move(scratch, ER::address_of_runtime_stats_flag());
    __ LoadU32(scratch, MemOperand(scratch, 0));
    __ CmpS64(scratch, Operand::Zero());
    __ bne(&profiler_or_side_effects_check_enabled, Label::kNear);
#endif  // V8_RUNTIME_CALL_STATS
  }

  __ RecordComment("Call the api function directly.");
#if V8_OS_ZOS
  __ mov(scratch, function_address);
  __ zosStoreReturnAddressAndCall(function_address, scratch);
#else
  __ StoreReturnAddressAndCall(function_address);
#endif
  __ bind(&done_api_call);

  Label propagate_exception;
  Label delete_allocated_handles;
  Label leave_exit_frame;

  __ RecordComment("Load the value from ReturnValue");
  __ LoadU64(r2, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ StoreU64(prev_next_address_reg, next_mem_op);
    if (v8_flags.debug_code) {
      __ LoadU32(scratch, level_mem_op);
      __ SubS64(scratch, Operand(1));
      __ CmpS64(scratch, prev_level_reg);
      __ Check(eq, AbortReason::kUnexpectedLevelAfterReturnFromApiCall);
    }
    __ StoreU32(prev_level_reg, level_mem_op);
    __ CmpS64(prev_limit_reg, limit_mem_op);
    __ bne(&delete_allocated_handles, Label::kNear);
  }

  __ RecordComment("Leave the API exit frame.");
  __ bind(&leave_exit_frame);
  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    // Load the number of stack slots to drop before LeaveExitFrame modifies sp.
    __ LoadU64(argc_reg, *argc_operand);
  }
  __ LeaveExitFrame(scratch);

  // Check if the function scheduled an exception.
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ LoadU64(scratch2, __ ExternalReferenceAsOperand(
                             ER::exception_address(isolate), no_reg));
    __ CompareRoot(scratch2, RootIndex::kTheHoleValue);
    __ bne(&propagate_exception, Label::kNear);
  }

  __ AssertJSAny(return_value, scratch, scratch2,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ AddS64(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));

  } else {
    // {argc_operand} was loaded into {argc_reg} above.
    __ AddS64(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));
    __ ShiftLeftU64(r0, argc_reg, Operand(kSystemPointerSizeLog2));
    __ AddS64(sp, sp, r0);
  }

  __ b(r14);

  if (with_profiling) {
    ASM_CODE_COMMENT_STRING(masm, "Call the api function via thunk wrapper.");
    __ bind(&profiler_or_side_effects_check_enabled);
    // Additional parameter is the address of the actual callback function.
    if (thunk_arg.is_valid()) {
      MemOperand thunk_arg_mem_op = __ ExternalReferenceAsOperand(
          IsolateFieldId::kApiCallbackThunkArgument);
      __ StoreU64(thunk_arg, thunk_arg_mem_op);
    }
    __ Move(scratch, thunk_ref);
#if V8_OS_ZOS
    __ zosStoreReturnAddressAndCall(function_address, scratch);
#else
    __ StoreReturnAddressAndCall(scratch);
#endif
    __ b(&done_api_call);
  }

  __ RecordComment("An exception was thrown. Propagate it.");
  __ bind(&propagate_exception);
  __ TailCallRuntime(Runtime::kPropagateException);

  // HandleScope limit has change
```