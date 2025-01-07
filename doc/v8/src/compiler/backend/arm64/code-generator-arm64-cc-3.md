Response:
My thinking process to analyze the provided C++ code snippet and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to know the functionality of this specific part of the `code-generator-arm64.cc` file. They're also asking about its relation to Torque, JavaScript, code logic, common errors, and a summary of its function within the larger file.

2. **Initial Scan for Keywords and Patterns:** I quickly scanned the code for recognizable patterns and keywords. I saw:
    * `#define`:  This immediately tells me these are preprocessor macros, used for code generation and abstraction.
    * `SIMD_`:  This strongly suggests the code is dealing with SIMD (Single Instruction, Multiple Data) operations, which are crucial for performance when processing arrays of numbers.
    * `kArm64`: This confirms the code is specific to the ARM64 architecture.
    * Instruction mnemonics like `Fmin`, `Fmax`, `Fadd`, `Mul`, `Shl`, `Ldr`, `Str`, etc. These are assembly language instructions for the ARM64 architecture.
    * `VectorFormat`: This likely represents the data type and size of SIMD vectors (e.g., 128-bit vectors holding floats, integers, etc.).
    * `VRegister`, `Register`:  These represent registers, the CPU's fast memory locations.
    * `i.OutputSimd128Register()`, `i.InputSimd128Register()`: These look like accessors to get the input and output registers for an instruction.
    * `MemoryOperand`: This clearly deals with loading and storing data from memory.
    * `case Op:` inside a `switch` statement:  This implies a dispatch mechanism, where different operations are handled based on the `opcode`.

3. **Deconstruct the Macros:** I focused on the macros because they encapsulate common patterns. I analyzed what each macro does:
    * `SIMD_BINOP_LANE_SIZE_CASE`: Handles binary SIMD operations where the lane size (data type within the vector) can vary. It extracts the lane size, formats the registers, and emits the corresponding assembly instruction.
    * `SIMD_UNOP_LANE_SIZE_CASE`: Similar to the binary case, but for unary operations.
    * `SIMD_CM_L_CASE`, `SIMD_CM_G_CASE`: Handle SIMD comparison operations (less than, greater than, etc.).
    * `SIMD_DESTRUCTIVE_BINOP_CASE`, `SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE`, `SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE`: These are for operations where one of the input registers is also the destination register (in-place operations). The "RELAXED_FUSED" likely indicates a specific type of fused operation (like fused multiply-add).

4. **Identify the Core Functionality:** Based on the keywords, macros, and assembly instructions, I concluded that this code snippet is responsible for **generating ARM64 assembly code for various SIMD operations**. It takes a high-level representation of a SIMD instruction (likely from the compiler's intermediate representation) and translates it into concrete assembly instructions.

5. **Address the Specific Questions:**

    * **Functionality:**  List the types of SIMD operations handled (arithmetic, logical, bitwise, comparisons, conversions, shuffles, loads, stores, etc.).
    * **Torque:** Explain that the `.cc` extension means it's C++, not Torque.
    * **JavaScript Relationship:**  Connect SIMD operations to JavaScript's TypedArrays and the SIMD.js API (even though SIMD.js is no longer a standard, the concept is relevant). Provide a JavaScript example showing how these operations might be used in JavaScript.
    * **Code Logic Inference:** Choose a simple case (like `kArm64FAdd`) and demonstrate how the macro would expand and what assembly instruction would be generated for specific input/output registers.
    * **Common Programming Errors:**  Think about errors related to SIMD, such as incorrect lane sizes, type mismatches, out-of-bounds access, and performance pitfalls due to unnecessary data movement. Provide illustrative C++ (as the target is assembly generation from C++) examples.
    * **Summary:**  Reiterate that this section focuses on generating ARM64 assembly for SIMD instructions based on the provided opcode.

6. **Structure the Answer:** Organize the information clearly, addressing each part of the user's request in a logical order. Use headings and bullet points for better readability.

7. **Refine and Elaborate:**  Review the answer for clarity, accuracy, and completeness. Add details and explanations where needed to make the concepts understandable to someone who might not be deeply familiar with compiler internals or assembly language. For instance, briefly explain what SIMD is and why it's important.

By following these steps, I could analyze the code snippet effectively and provide a comprehensive and informative answer to the user's question. The key was to recognize the patterns and keywords related to assembly code generation and SIMD operations.
这是 v8 源代码文件 `v8/src/compiler/backend/arm64/code-generator-arm64.cc` 的一个代码片段，主要负责为 ARM64 架构生成机器码，特别是针对 SIMD (Single Instruction, Multiple Data) 操作。

**功能归纳:**

这段代码的主要功能是处理各种 SIMD 指令的生成，包括算术运算、比较运算、类型转换、位运算、数据提取和替换、通道操作、以及内存加载和存储等。它使用了一系列的宏来简化不同 SIMD 指令的代码生成过程。

**详细功能列举:**

1. **SIMD 算术运算:**
   - 浮点数运算：加法 (`Fadd`)、减法 (`Fsub`)、乘法 (`Fmul`)、除法 (`Fdiv`)、绝对值 (`Fabs`)、平方根 (`Fsqrt`)、取反 (`Fneg`)、最小值 (`Fmin`)、最大值 (`Fmax`)、带符号/无符号四舍五入平均值 (`Urhadd`)。
   - 整数运算：加法 (`Add`)、减法 (`Sub`)、绝对值 (`Abs`)、取反 (`Neg`)、最小值 (`Smin`, `Umin`)、最大值 (`Smax`, `Umax`)、乘加 (`Mla`)、乘减 (`Mls`)。

2. **SIMD 类型转换:**
   - 扩展转换：有符号扩展 (`Sxtl`, `Sxtl2`)、无符号扩展 (`Uxtl`, `Uxtl2`)。
   - 浮点数和整数之间的转换：
     - `F64x2ConvertLowI32x4S/U`: 将 `i32x4` 低 64 位转换为 `f64x2`。
     - `I32x4TruncSatF64x2SZero/UZero`: 将 `f64x2` 截断为 `i32x4` 并饱和。
     - `F32x4DemoteF64x2Zero`: 将 `f64x2` 降级为 `f32x4`。
     - `F64x2PromoteLowF32x4`: 将 `f32x4` 的低 64 位升级为 `f64x2`。
     - `F16x8` 和 `I16x8` 之间的转换 (`Scvtf`, `Ucvtf`, `Fcvtzs`, `Fcvtzu`)。
     - `F16x8DemoteF32x4/F64x2Zero`: 将 `f32x4`/`f64x2` 降级为 `f16x8`。
     - `F32x4PromoteLowF16x8`: 将 `f16x8` 的低 64 位升级为 `f32x4`。
   - 整数类型之间的转换 (`I16x8SConvertI32x4`, `I16x8UConvertI32x4`, `I8x16SConvertI16x8`, `I8x16UConvertI16x8`)。

3. **SIMD 数据提取和替换:**
   - `FExtractLane`, `IExtractLane`, `IExtractLaneU`, `IExtractLaneS`: 从 SIMD 寄存器中提取指定通道的值。
   - `FReplaceLane`, `IReplaceLane`: 将值替换到 SIMD 寄存器的指定通道。

4. **SIMD 比较运算:**
   - 浮点数比较：相等 (`FEq`)、不等 (`FNe`)、小于 (`FLt`)、小于等于 (`FLe`)、大于 (`FGt`)、大于等于 (`FGe`)。
   - 整数比较：相等 (`IEq`)、不等 (`INe`)、小于 (`ILtS`)、小于等于 (`ILeS`)、大于 (`IGtS`)、大于等于 (`IGeS`)、大于（无符号 `IGtU`）、大于等于（无符号 `IGeU`）。

5. **SIMD 乘加/减运算 (Fused Multiply-Add/Subtract):**
   - `F64x2Qfma`, `F64x2Qfms`, `F32x4Qfma`, `F32x4Qfms`, `F16x8Qfma`, `F16x8Qfms`。

6. **SIMD 成对最小值/最大值:**
   - `F64x2Pmin`, `F64x2Pmax`, `F32x4Pmin`, `F32x4Pmax`, `F16x8Pmin`, `F16x8Pmax`.

7. **SIMD 乘法变种:**
   - `FMulElement`: 浮点数按元素乘法。
   - `I64x2Mul`: 64 位整数乘法。
   - `I32x4Mul`: 32 位整数乘法。
   - `I16x8Mul`: 16 位整数乘法。
   - `I16x8Q15MulRSatS`: 16 位整数 Q15 乘法并饱和。

8. **SIMD 位运算:**
   - `I64x2Shl`, `I64x2ShrS`, `I64x2ShrU`: 64 位整数移位。
   - `I32x4Shl`, `I32x4ShrS`, `I32x4ShrU`: 32 位整数移位。
   - `I16x8Shl`, `I16x8ShrS`, `I16x8ShrU`: 16 位整数移位。
   - `I8x16Shl`, `I8x16ShrS`, `I8x16ShrU`: 8 位整数移位。
   - `S128And`, `S128Or`, `S128Xor`, `S128Not`, `S128AndNot`: 128 位逻辑运算。

9. **SIMD 数据重排和组合:**
   - `I64x2BitMask`, `I32x4BitMask`, `I16x8BitMask`, `I8x16BitMask`: 生成 SIMD 向量的位掩码。
   - `I8x16Addv`, `I16x8Addv`, `I32x4Addv`: 向量元素求和。
   - `I64x2AddPair`, `F32x4AddReducePairwise`, `F64x2AddPair`: 相邻元素对求和。
   - `I32x4DotI16x8S`, `I16x8DotI8x16S`, `I32x4DotI8x16AddS`: 点积运算。
   - `S128Const`: 加载常量到 SIMD 寄存器。
   - `S128Dup`: 复制 SIMD 寄存器中的某个通道到整个寄存器。
   - `S128Select`: 按位选择。
   - `Ssra`, `Usra`: 带符号/无符号右移并累加。
   - `S32x4Shuffle`, `I8x16Shuffle`: SIMD 向量的混洗操作。
   - `S32x4ZipLeft/Right`, `S16x8ZipLeft/Right`, `S8x16ZipLeft/Right`: 向量的交叉合并操作。
   - `S32x4UnzipLeft/Right`, `S16x8UnzipLeft/Right`, `S8x16UnzipLeft/Right`: 向量的反交叉合并操作。
   - `S32x4TransposeLeft/Right`, `S16x8TransposeLeft/Right`, `S8x16TransposeLeft/Right`: 向量的转置操作。
   - `S8x16Concat`: 向量的连接操作。
   - `I8x16Swizzle`: 使用一个向量的值作为索引来重新排列另一个向量的元素。
   - `S32x4Reverse`, `S32x2Reverse`, `S16x4Reverse`, `S16x2Reverse`, `S8x8Reverse`, `S8x4Reverse`, `S8x2Reverse`: 反转向量中元素的字节序。

10. **SIMD 内存操作:**
    - `LoadSplat`: 从内存加载一个值并填充到整个 SIMD 寄存器。
    - `LoadLane`: 从内存加载一个值并存储到 SIMD 寄存器的指定通道。
    - `StoreLane`: 将 SIMD 寄存器指定通道的值存储到内存。
    - `S128Load8x8S/U`, `S128Load16x4S/U`, `S128Load32x2S/U`: 从内存加载并进行符号/无符号扩展。

**关于文件类型和 JavaScript 关系:**

- `v8/src/compiler/backend/arm64/code-generator-arm64.cc` **不是**以 `.tq` 结尾，因此它是一个 **C++ 源代码**文件，而不是 v8 Torque 源代码。 Torque 文件通常用于定义内置函数和类型。

- **与 JavaScript 的功能关系:** 这段代码直接关系到 JavaScript 中使用 SIMD (Single Instruction, Multiple Data) 功能的性能。 JavaScript 提供了 `TypedArray` 和早期版本的 `SIMD.js` (尽管 `SIMD.js` 已被移除，但概念仍然适用) 来操作向量数据。 V8 引擎在编译这些 JavaScript 代码时，会调用像 `code-generator-arm64.cc` 这样的后端代码生成器，将高级的 SIMD 操作翻译成底层的 ARM64 汇编指令，从而实现高效的并行计算。

**JavaScript 示例:**

```javascript
// 假设我们有使用 SIMD 功能的 JavaScript 代码 (概念上)

// 创建一个 Float32Array
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);

// 使用 SIMD 进行向量加法 (早期 SIMD.js 的概念)
// let av = SIMD.float32x4(a[0], a[1], a[2], a[3]);
// let bv = SIMD.float32x4(b[0], b[1], b[2], b[3]);
// let cv = SIMD.float32x4.add(av, bv);

// 现代 JavaScript 中，可能更多地依赖 WebAssembly SIMD 或者库来实现

// 手动模拟向量加法
const c = new Float32Array(4);
for (let i = 0; i < 4; i++) {
  c[i] = a[i] + b[i];
}

console.log(c); // 输出 Float32Array [6, 8, 10, 12]
```

当 V8 编译类似上述操作的代码时，`code-generator-arm64.cc` 中的代码（例如处理 `kArm64FAdd` 的部分）会被用来生成对应的 ARM64 SIMD 加法指令，以加速数组元素的并行加法运算。

**代码逻辑推理示例:**

**假设输入:** 一个需要执行 `f32x4` 向量加法的指令，输入寄存器分别为 `v1` 和 `v2`，输出寄存器为 `v0`。

**对应的 opcode:**  `kArm64FAdd`，且 `LaneSizeField::decode(opcode)` 解码为 4 (表示 32 位浮点数)。

**根据代码逻辑:**

```c++
#define SIMD_BINOP_LANE_SIZE_CASE(Op, Instr)                               \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    __ Instr(i.OutputSimd128Register().Format(f),                  \
             i.InputSimd128Register(0).Format(f),                  \
             i.InputSimd128Register(1).Format(f));                  \
    break;                                                             \
  }

// ...

SIMD_BINOP_LANE_SIZE_CASE(kArm64FAdd, Fadd);

// ...

case kArm64FAdd: {
  VectorFormat f = VectorFormatFillQ(4); // f 将会是 kFormat4S
  __ Fadd(i.OutputSimd128Register().V4S(), // v0
          i.InputSimd128Register(0).V4S(),  // v1
          i.InputSimd128Register(1).V4S());  // v2
  break;
}
```

**输出:** 生成的 ARM64 汇编指令将会是 `fadd v0.4s, v1.4s, v2.4s`。这条指令会将 `v1` 和 `v2` 寄存器中的四个单精度浮点数分别相加，并将结果存储到 `v0` 寄存器中。

**用户常见的编程错误示例:**

1. **类型不匹配:** 在 JavaScript 中使用 `TypedArray` 时，如果尝试对不同类型的数组进行 SIMD 操作，可能会导致错误或者性能下降，因为 V8 需要进行额外的类型转换。

   ```javascript
   const floatArray = new Float32Array([1.0, 2.0, 3.0, 4.0]);
   const intArray = new Int32Array([5, 6, 7, 8]);

   // 尝试将浮点数向量和整数向量相加 (在概念的 SIMD.js 中)
   // 可能会导致类型错误或意外行为
   // let floatVec = SIMD.float32x4(...floatArray);
   // let intVec = SIMD.int32x4(...intArray);
   // let resultVec = SIMD.float32x4.add(floatVec, intVec);
   ```

2. **通道数量或大小不匹配:** 在使用 SIMD 操作时，确保操作的向量和目标向量的通道数量和数据类型大小一致。例如，尝试将 `f32x4` 的结果存储到只能容纳 `f64x2` 的寄存器中会导致错误。

3. **不正确的内存对齐:** 对于某些 SIMD 加载和存储指令，内存对齐非常重要。如果数据没有正确对齐，可能会导致性能下降甚至程序崩溃。

4. **滥用 SIMD 而没有性能提升:** 不是所有的计算都适合使用 SIMD。对于小规模的数据或者控制流复杂的代码，使用 SIMD 可能不会带来性能提升，反而会增加代码的复杂性。

这段代码是 V8 引擎中非常核心的部分，它直接影响了 JavaScript 在 ARM64 架构上的 SIMD 性能。通过使用宏和仔细处理每种 SIMD 指令，V8 能够生成高效的本地机器码，从而加速 JavaScript 应用的执行速度。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/code-generator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/code-generator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
LaneSizeField::decode(opcode)); \
    DCHECK_EQ(instr->InputCount(), 1);                                 \
    __ Cm##ImmOp(i.OutputSimd128Register().Format(f),                  \
                 i.InputSimd128Register(0).Format(f), 0);              \
    break;                                                             \
  }
#define SIMD_CM_G_CASE(Op, CmOp)                                       \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    if (instr->InputCount() == 1) {                                    \
      __ Cm##CmOp(i.OutputSimd128Register().Format(f),                 \
                  i.InputSimd128Register(0).Format(f), 0);             \
    } else {                                                           \
      __ Cm##CmOp(i.OutputSimd128Register().Format(f),                 \
                  i.InputSimd128Register(0).Format(f),                 \
                  i.InputSimd128Register(1).Format(f));                \
    }                                                                  \
    break;                                                             \
  }
#define SIMD_DESTRUCTIVE_BINOP_CASE(Op, Instr, FORMAT)     \
  case Op: {                                               \
    VRegister dst = i.OutputSimd128Register().V##FORMAT(); \
    DCHECK_EQ(dst, i.InputSimd128Register(0).V##FORMAT()); \
    __ Instr(dst, i.InputSimd128Register(1).V##FORMAT(),   \
             i.InputSimd128Register(2).V##FORMAT());       \
    break;                                                 \
  }
#define SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE(Op, Instr)               \
  case Op: {                                                           \
    VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode)); \
    VRegister dst = i.OutputSimd128Register().Format(f);               \
    DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));               \
    __ Instr(dst, i.InputSimd128Register(1).Format(f),                 \
             i.InputSimd128Register(2).Format(f));                     \
    break;                                                             \
  }
#define SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(Op, Instr, FORMAT) \
  case Op: {                                                   \
    VRegister dst = i.OutputSimd128Register().V##FORMAT();     \
    DCHECK_EQ(dst, i.InputSimd128Register(2).V##FORMAT());     \
    __ Instr(dst, i.InputSimd128Register(0).V##FORMAT(),       \
             i.InputSimd128Register(1).V##FORMAT());           \
    break;                                                     \
  }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FMin, Fmin);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FMax, Fmax);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64FAbs, Fabs);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64FSqrt, Fsqrt);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FAdd, Fadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FSub, Fsub);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FMul, Fmul);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64FDiv, Fdiv);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64FNeg, Fneg);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64IAbs, Abs);
      SIMD_UNOP_LANE_SIZE_CASE(kArm64INeg, Neg);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64RoundingAverageU, Urhadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMinS, Smin);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMaxS, Smax);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMinU, Umin);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IMaxU, Umax);
      SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE(kArm64Mla, Mla);
      SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE(kArm64Mls, Mls);
    case kArm64Sxtl: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidth(wide);
      __ Sxtl(i.OutputSimd128Register().Format(wide),
              i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64Sxtl2: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidthDoubleLanes(wide);
      __ Sxtl2(i.OutputSimd128Register().Format(wide),
               i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64Uxtl: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidth(wide);
      __ Uxtl(i.OutputSimd128Register().Format(wide),
              i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64Uxtl2: {
      VectorFormat wide = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VectorFormat narrow = VectorFormatHalfWidthDoubleLanes(wide);
      __ Uxtl2(i.OutputSimd128Register().Format(wide),
               i.InputSimd128Register(0).Format(narrow));
      break;
    }
    case kArm64F64x2ConvertLowI32x4S: {
      VRegister dst = i.OutputSimd128Register().V2D();
      __ Sxtl(dst, i.InputSimd128Register(0).V2S());
      __ Scvtf(dst, dst);
      break;
    }
    case kArm64F64x2ConvertLowI32x4U: {
      VRegister dst = i.OutputSimd128Register().V2D();
      __ Uxtl(dst, i.InputSimd128Register(0).V2S());
      __ Ucvtf(dst, dst);
      break;
    }
    case kArm64I32x4TruncSatF64x2SZero: {
      VRegister dst = i.OutputSimd128Register();
      __ Fcvtzs(dst.V2D(), i.InputSimd128Register(0).V2D());
      __ Sqxtn(dst.V2S(), dst.V2D());
      break;
    }
    case kArm64I32x4TruncSatF64x2UZero: {
      VRegister dst = i.OutputSimd128Register();
      __ Fcvtzu(dst.V2D(), i.InputSimd128Register(0).V2D());
      __ Uqxtn(dst.V2S(), dst.V2D());
      break;
    }
    case kArm64F32x4DemoteF64x2Zero: {
      __ Fcvtn(i.OutputSimd128Register().V2S(),
               i.InputSimd128Register(0).V2D());
      break;
    }
    case kArm64F64x2PromoteLowF32x4: {
      __ Fcvtl(i.OutputSimd128Register().V2D(),
               i.InputSimd128Register(0).V2S());
      break;
    }
      SIMD_UNOP_CASE(kArm64F16x8SConvertI16x8, Scvtf, 8H);
      SIMD_UNOP_CASE(kArm64F16x8UConvertI16x8, Ucvtf, 8H);
      SIMD_UNOP_CASE(kArm64I16x8UConvertF16x8, Fcvtzu, 8H);
      SIMD_UNOP_CASE(kArm64I16x8SConvertF16x8, Fcvtzs, 8H);
    case kArm64F16x8DemoteF32x4Zero: {
      __ Fcvtn(i.OutputSimd128Register().V4H(),
               i.InputSimd128Register(0).V4S());
      break;
    }
    case kArm64F16x8DemoteF64x2Zero: {
      // There is no vector f64 -> f16 conversion instruction,
      // so convert them by component using scalar version.
      // Convert high double to a temp reg first, because dst and src
      // can overlap.
      __ Mov(fp_scratch.D(), i.InputSimd128Register(0).V2D(), 1);
      __ Fcvt(fp_scratch.H(), fp_scratch.D());

      __ Fcvt(i.OutputSimd128Register().H(), i.InputSimd128Register(0).D());
      __ Mov(i.OutputSimd128Register().V8H(), 1, fp_scratch.V8H(), 0);
      break;
    }
    case kArm64F32x4PromoteLowF16x8: {
      __ Fcvtl(i.OutputSimd128Register().V4S(),
               i.InputSimd128Register(0).V4H());
      break;
    }
    case kArm64FExtractLane: {
      VectorFormat dst_f =
          ScalarFormatFromLaneSize(LaneSizeField::decode(opcode));
      VectorFormat src_f = VectorFormatFillQ(dst_f);
      __ Mov(i.OutputSimd128Register().Format(dst_f),
             i.InputSimd128Register(0).Format(src_f), i.InputInt8(1));
      if (dst_f == kFormatH) {
        __ Fcvt(i.OutputSimd128Register().S(), i.OutputSimd128Register().H());
      }
      break;
    }
    case kArm64FReplaceLane: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f),
                src1 = i.InputSimd128Register(0).Format(f);
      if (dst != src1) {
        __ Mov(dst, src1);
      }
      if (f == kFormat8H) {
        UseScratchRegisterScope scope(masm());
        VRegister tmp = scope.AcquireV(kFormat8H);
        __ Fcvt(tmp.H(), i.InputSimd128Register(2).S());
        __ Mov(dst, i.InputInt8(1), tmp.Format(f), 0);
      } else {
        __ Mov(dst, i.InputInt8(1), i.InputSimd128Register(2).Format(f), 0);
      }
      break;
    }
      SIMD_FCM_L_CASE(kArm64FEq, eq, eq);
    case kArm64FNe: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f);
      if (instr->InputCount() == 1) {
        __ Fcmeq(dst, i.InputSimd128Register(0).Format(f), +0.0);
      } else {
        __ Fcmeq(dst, i.InputSimd128Register(0).Format(f),
                 i.InputSimd128Register(1).Format(f));
      }
      __ Mvn(dst, dst);
      break;
    }
      SIMD_FCM_L_CASE(kArm64FLt, lt, gt);
      SIMD_FCM_L_CASE(kArm64FLe, le, ge);
      SIMD_FCM_G_CASE(kArm64FGt, gt);
      SIMD_FCM_G_CASE(kArm64FGe, ge);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F64x2Qfma, Fmla, 2D);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F64x2Qfms, Fmls, 2D);
    case kArm64F64x2Pmin: {
      VRegister dst = i.OutputSimd128Register().V2D();
      VRegister lhs = i.InputSimd128Register(0).V2D();
      VRegister rhs = i.InputSimd128Register(1).V2D();
      // f64x2.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f64x2.lt(rhs,lhs))
      // = v128.bitselect(rhs, lhs, f64x2.gt(lhs,rhs))
      __ Fcmgt(dst, lhs, rhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F64x2Pmax: {
      VRegister dst = i.OutputSimd128Register().V2D();
      VRegister lhs = i.InputSimd128Register(0).V2D();
      VRegister rhs = i.InputSimd128Register(1).V2D();
      // f64x2.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f64x2.gt(rhs, lhs))
      __ Fcmgt(dst, rhs, lhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
      SIMD_UNOP_CASE(kArm64F32x4SConvertI32x4, Scvtf, 4S);
      SIMD_UNOP_CASE(kArm64F32x4UConvertI32x4, Ucvtf, 4S);
    case kArm64FMulElement: {
      VectorFormat s_f =
          ScalarFormatFromLaneSize(LaneSizeField::decode(opcode));
      VectorFormat v_f = VectorFormatFillQ(s_f);
      __ Fmul(i.OutputSimd128Register().Format(v_f),
              i.InputSimd128Register(0).Format(v_f),
              i.InputSimd128Register(1).Format(s_f), i.InputInt8(2));
      break;
    }
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F32x4Qfma, Fmla, 4S);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F32x4Qfms, Fmls, 4S);
    case kArm64F32x4Pmin: {
      VRegister dst = i.OutputSimd128Register().V4S();
      VRegister lhs = i.InputSimd128Register(0).V4S();
      VRegister rhs = i.InputSimd128Register(1).V4S();
      // f32x4.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.lt(rhs, lhs))
      // = v128.bitselect(rhs, lhs, f32x4.gt(lhs, rhs))
      __ Fcmgt(dst, lhs, rhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F32x4Pmax: {
      VRegister dst = i.OutputSimd128Register().V4S();
      VRegister lhs = i.InputSimd128Register(0).V4S();
      VRegister rhs = i.InputSimd128Register(1).V4S();
      // f32x4.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.gt(rhs, lhs))
      __ Fcmgt(dst, rhs, lhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F16x8Pmin: {
      VRegister dst = i.OutputSimd128Register().V8H();
      VRegister lhs = i.InputSimd128Register(0).V8H();
      VRegister rhs = i.InputSimd128Register(1).V8H();
      // f16x8.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f16x8.lt(rhs, lhs))
      // = v128.bitselect(rhs, lhs, f16x8.gt(lhs, rhs))
      __ Fcmgt(dst, lhs, rhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
    case kArm64F16x8Pmax: {
      VRegister dst = i.OutputSimd128Register().V8H();
      VRegister lhs = i.InputSimd128Register(0).V8H();
      VRegister rhs = i.InputSimd128Register(1).V8H();
      // f16x8.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f16x8.gt(rhs, lhs))
      __ Fcmgt(dst, rhs, lhs);
      __ Bsl(dst.V16B(), rhs.V16B(), lhs.V16B());
      break;
    }
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F16x8Qfma, Fmla, 8H);
      SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE(kArm64F16x8Qfms, Fmls, 8H);
    case kArm64IExtractLane: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      Register dst =
          f == kFormat2D ? i.OutputRegister64() : i.OutputRegister32();
      __ Mov(dst, i.InputSimd128Register(0).Format(f), i.InputInt8(1));
      break;
    }
    case kArm64IReplaceLane: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f),
                src1 = i.InputSimd128Register(0).Format(f);
      Register src2 =
          f == kFormat2D ? i.InputRegister64(2) : i.InputRegister32(2);
      if (dst != src1) {
        __ Mov(dst, src1);
      }
      __ Mov(dst, i.InputInt8(1), src2);
      break;
    }
    case kArm64I64x2Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 6, V2D, Sshl, X);
      break;
    }
    case kArm64I64x2ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 6, V2D, Sshl, X);
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IAdd, Add);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64ISub, Sub);
    case kArm64I64x2Mul: {
      UseScratchRegisterScope scope(masm());
      VRegister dst = i.OutputSimd128Register();
      VRegister src1 = i.InputSimd128Register(0);
      VRegister src2 = i.InputSimd128Register(1);
      VRegister tmp1 = scope.AcquireSameSizeAs(dst);
      VRegister tmp2 = scope.AcquireSameSizeAs(dst);
      VRegister tmp3 = i.ToSimd128Register(instr->TempAt(0));

      // This 2x64-bit multiplication is performed with several 32-bit
      // multiplications.

      // 64-bit numbers x and y, can be represented as:
      //   x = a + 2^32(b)
      //   y = c + 2^32(d)

      // A 64-bit multiplication is:
      //   x * y = ac + 2^32(ad + bc) + 2^64(bd)
      // note: `2^64(bd)` can be ignored, the value is too large to fit in
      // 64-bits.

      // This sequence implements a 2x64bit multiply, where the registers
      // `src1` and `src2` are split up into 32-bit components:
      //   src1 = |d|c|b|a|
      //   src2 = |h|g|f|e|
      //
      //   src1 * src2 = |cg + 2^32(ch + dg)|ae + 2^32(af + be)|

      // Reverse the 32-bit elements in the 64-bit words.
      //   tmp2 = |g|h|e|f|
      __ Rev64(tmp2.V4S(), src2.V4S());

      // Calculate the high half components.
      //   tmp2 = |dg|ch|be|af|
      __ Mul(tmp2.V4S(), tmp2.V4S(), src1.V4S());

      // Extract the low half components of src1.
      //   tmp1 = |c|a|
      __ Xtn(tmp1.V2S(), src1.V2D());

      // Sum the respective high half components.
      //   tmp2 = |dg+ch|be+af||dg+ch|be+af|
      __ Addp(tmp2.V4S(), tmp2.V4S(), tmp2.V4S());

      // Extract the low half components of src2.
      //   tmp3 = |g|e|
      __ Xtn(tmp3.V2S(), src2.V2D());

      // Shift the high half components, into the high half.
      //   dst = |dg+ch << 32|be+af << 32|
      __ Shll(dst.V2D(), tmp2.V2S(), 32);

      // Multiply the low components together, and accumulate with the high
      // half.
      //   dst = |dst[1] + cg|dst[0] + ae|
      __ Umlal(dst.V2D(), tmp3.V2S(), tmp1.V2S());

      break;
    }
      SIMD_CM_G_CASE(kArm64IEq, eq);
    case kArm64INe: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      VRegister dst = i.OutputSimd128Register().Format(f);
      if (instr->InputCount() == 1) {
        __ Cmeq(dst, i.InputSimd128Register(0).Format(f), 0);
      } else {
        __ Cmeq(dst, i.InputSimd128Register(0).Format(f),
                i.InputSimd128Register(1).Format(f));
      }
      __ Mvn(dst, dst);
      break;
    }
      SIMD_CM_L_CASE(kArm64ILtS, lt);
      SIMD_CM_L_CASE(kArm64ILeS, le);
      SIMD_CM_G_CASE(kArm64IGtS, gt);
      SIMD_CM_G_CASE(kArm64IGeS, ge);
    case kArm64I64x2ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 6, V2D, Ushl, X);
      break;
    }
    case kArm64I64x2BitMask: {
      __ I64x2BitMask(i.OutputRegister32(), i.InputSimd128Register(0));
      break;
    }
      SIMD_UNOP_CASE(kArm64I32x4SConvertF32x4, Fcvtzs, 4S);
    case kArm64I32x4Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 5, V4S, Sshl, W);
      break;
    }
    case kArm64I32x4ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 5, V4S, Sshl, W);
      break;
    }
      SIMD_BINOP_CASE(kArm64I32x4Mul, Mul, 4S);
      SIMD_UNOP_CASE(kArm64I32x4UConvertF32x4, Fcvtzu, 4S);
    case kArm64I32x4ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 5, V4S, Ushl, W);
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IGtU, Cmhi);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IGeU, Cmhs);
    case kArm64I32x4BitMask: {
      __ I32x4BitMask(i.OutputRegister32(), i.InputSimd128Register(0));
      break;
    }
    case kArm64I8x16Addv: {
      __ Addv(i.OutputSimd128Register().B(), i.InputSimd128Register(0).V16B());
      break;
    }
    case kArm64I16x8Addv: {
      __ Addv(i.OutputSimd128Register().H(), i.InputSimd128Register(0).V8H());
      break;
    }
    case kArm64I32x4Addv: {
      __ Addv(i.OutputSimd128Register().S(), i.InputSimd128Register(0).V4S());
      break;
    }
    case kArm64I64x2AddPair: {
      __ Addp(i.OutputSimd128Register().D(), i.InputSimd128Register(0).V2D());
      break;
    }
    case kArm64F32x4AddReducePairwise: {
      UseScratchRegisterScope scope(masm());
      VRegister tmp = scope.AcquireV(kFormat4S);
      __ Faddp(tmp.V4S(), i.InputSimd128Register(0).V4S(),
               i.InputSimd128Register(0).V4S());
      __ Faddp(i.OutputSimd128Register().S(), tmp.V2S());
      break;
    }
    case kArm64F64x2AddPair: {
      __ Faddp(i.OutputSimd128Register().D(), i.InputSimd128Register(0).V2D());
      break;
    }
    case kArm64I32x4DotI16x8S: {
      UseScratchRegisterScope scope(masm());
      VRegister lhs = i.InputSimd128Register(0);
      VRegister rhs = i.InputSimd128Register(1);
      VRegister tmp1 = scope.AcquireV(kFormat4S);
      VRegister tmp2 = scope.AcquireV(kFormat4S);
      __ Smull(tmp1, lhs.V4H(), rhs.V4H());
      __ Smull2(tmp2, lhs.V8H(), rhs.V8H());
      __ Addp(i.OutputSimd128Register().V4S(), tmp1, tmp2);
      break;
    }
    case kArm64I16x8DotI8x16S: {
      UseScratchRegisterScope scope(masm());
      VRegister lhs = i.InputSimd128Register(0);
      VRegister rhs = i.InputSimd128Register(1);
      VRegister tmp1 = scope.AcquireV(kFormat8H);
      VRegister tmp2 = scope.AcquireV(kFormat8H);
      __ Smull(tmp1, lhs.V8B(), rhs.V8B());
      __ Smull2(tmp2, lhs.V16B(), rhs.V16B());
      __ Addp(i.OutputSimd128Register().V8H(), tmp1, tmp2);
      break;
    }
    case kArm64I32x4DotI8x16AddS: {
      if (CpuFeatures::IsSupported(DOTPROD)) {
        CpuFeatureScope scope(masm(), DOTPROD);

        DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(2));
        __ Sdot(i.InputSimd128Register(2).V4S(),
                i.InputSimd128Register(0).V16B(),
                i.InputSimd128Register(1).V16B());

      } else {
        UseScratchRegisterScope scope(masm());
        VRegister lhs = i.InputSimd128Register(0);
        VRegister rhs = i.InputSimd128Register(1);
        VRegister tmp1 = scope.AcquireV(kFormat8H);
        VRegister tmp2 = scope.AcquireV(kFormat8H);
        __ Smull(tmp1, lhs.V8B(), rhs.V8B());
        __ Smull2(tmp2, lhs.V16B(), rhs.V16B());
        __ Addp(tmp1, tmp1, tmp2);
        __ Saddlp(tmp1.V4S(), tmp1);
        __ Add(i.OutputSimd128Register().V4S(), tmp1.V4S(),
               i.InputSimd128Register(2).V4S());
      }
      break;
    }
    case kArm64IExtractLaneU: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      __ Umov(i.OutputRegister32(), i.InputSimd128Register(0).Format(f),
              i.InputInt8(1));
      break;
    }
    case kArm64IExtractLaneS: {
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      __ Smov(i.OutputRegister32(), i.InputSimd128Register(0).Format(f),
              i.InputInt8(1));
      break;
    }
    case kArm64I16x8Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 4, V8H, Sshl, W);
      break;
    }
    case kArm64I16x8ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 4, V8H, Sshl, W);
      break;
    }
    case kArm64I16x8SConvertI32x4: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat4S);
      if (dst == src1) {
        __ Mov(temp, src1.V4S());
        src1 = temp;
      }
      __ Sqxtn(dst.V4H(), src0.V4S());
      __ Sqxtn2(dst.V8H(), src1.V4S());
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IAddSatS, Sqadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64ISubSatS, Sqsub);
      SIMD_BINOP_CASE(kArm64I16x8Mul, Mul, 8H);
    case kArm64I16x8ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 4, V8H, Ushl, W);
      break;
    }
    case kArm64I16x8UConvertI32x4: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat4S);
      if (dst == src1) {
        __ Mov(temp, src1.V4S());
        src1 = temp;
      }
      __ Sqxtun(dst.V4H(), src0.V4S());
      __ Sqxtun2(dst.V8H(), src1.V4S());
      break;
    }
      SIMD_BINOP_LANE_SIZE_CASE(kArm64IAddSatU, Uqadd);
      SIMD_BINOP_LANE_SIZE_CASE(kArm64ISubSatU, Uqsub);
      SIMD_BINOP_CASE(kArm64I16x8Q15MulRSatS, Sqrdmulh, 8H);
    case kArm64I16x8BitMask: {
      __ I16x8BitMask(i.OutputRegister32(), i.InputSimd128Register(0));
      break;
    }
    case kArm64I8x16Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(Shl, 3, V16B, Sshl, W);
      break;
    }
    case kArm64I8x16ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Sshr, 3, V16B, Sshl, W);
      break;
    }
    case kArm64I8x16SConvertI16x8: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat8H);
      if (dst == src1) {
        __ Mov(temp, src1.V8H());
        src1 = temp;
      }
      __ Sqxtn(dst.V8B(), src0.V8H());
      __ Sqxtn2(dst.V16B(), src1.V8H());
      break;
    }
    case kArm64I8x16ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(Ushr, 3, V16B, Ushl, W);
      break;
    }
    case kArm64I8x16UConvertI16x8: {
      VRegister dst = i.OutputSimd128Register(),
                src0 = i.InputSimd128Register(0),
                src1 = i.InputSimd128Register(1);
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat8H);
      if (dst == src1) {
        __ Mov(temp, src1.V8H());
        src1 = temp;
      }
      __ Sqxtun(dst.V8B(), src0.V8H());
      __ Sqxtun2(dst.V16B(), src1.V8H());
      break;
    }
    case kArm64I8x16BitMask: {
      VRegister temp = NoVReg;

      if (CpuFeatures::IsSupported(PMULL1Q)) {
        temp = i.TempSimd128Register(0);
      }

      __ I8x16BitMask(i.OutputRegister32(), i.InputSimd128Register(0), temp);
      break;
    }
    case kArm64S128Const: {
      uint64_t imm1 = make_uint64(i.InputUint32(1), i.InputUint32(0));
      uint64_t imm2 = make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ Movi(i.OutputSimd128Register().V16B(), imm2, imm1);
      break;
    }
      SIMD_BINOP_CASE(kArm64S128And, And, 16B);
      SIMD_BINOP_CASE(kArm64S128Or, Orr, 16B);
      SIMD_BINOP_CASE(kArm64S128Xor, Eor, 16B);
      SIMD_UNOP_CASE(kArm64S128Not, Mvn, 16B);
    case kArm64S128Dup: {
      VRegister dst = i.OutputSimd128Register(),
                src = i.InputSimd128Register(0);
      int lanes = i.InputInt32(1);
      int index = i.InputInt32(2);
      switch (lanes) {
        case 4:
          __ Dup(dst.V4S(), src.V4S(), index);
          break;
        case 8:
          __ Dup(dst.V8H(), src.V8H(), index);
          break;
        case 16:
          __ Dup(dst.V16B(), src.V16B(), index);
          break;
        default:
          UNREACHABLE();
      }
      break;
    }
      SIMD_DESTRUCTIVE_BINOP_CASE(kArm64S128Select, Bsl, 16B);
    case kArm64S128AndNot:
      if (instr->InputAt(1)->IsImmediate()) {
        VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
        VRegister dst = i.OutputSimd128Register().Format(f);
        DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));
        __ Bic(dst, i.InputInt32(1), i.InputInt8(2));
      } else {
        __ Bic(i.OutputSimd128Register().V16B(),
               i.InputSimd128Register(0).V16B(),
               i.InputSimd128Register(1).V16B());
      }
      break;
    case kArm64Ssra: {
      int8_t laneSize = LaneSizeField::decode(opcode);
      VectorFormat f = VectorFormatFillQ(laneSize);
      int8_t mask = laneSize - 1;
      VRegister dst = i.OutputSimd128Register().Format(f);
      DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));
      __ Ssra(dst, i.InputSimd128Register(1).Format(f), i.InputInt8(2) & mask);
      break;
    }
    case kArm64Usra: {
      int8_t laneSize = LaneSizeField::decode(opcode);
      VectorFormat f = VectorFormatFillQ(laneSize);
      int8_t mask = laneSize - 1;
      VRegister dst = i.OutputSimd128Register().Format(f);
      DCHECK_EQ(dst, i.InputSimd128Register(0).Format(f));
      __ Usra(dst, i.InputSimd128Register(1).Format(f), i.InputUint8(2) & mask);
      break;
    }
    case kArm64S32x4Shuffle: {
      Simd128Register dst = i.OutputSimd128Register().V4S(),
                      src0 = i.InputSimd128Register(0).V4S(),
                      src1 = i.InputSimd128Register(1).V4S();
      // Check for in-place shuffles.
      // If dst == src0 == src1, then the shuffle is unary and we only use src0.
      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat4S);
      if (dst == src0) {
        __ Mov(temp, src0);
        src0 = temp;
      } else if (dst == src1) {
        __ Mov(temp, src1);
        src1 = temp;
      }
      int32_t shuffle = i.InputInt32(2);

      // Check whether we can reduce the number of vmovs by performing a dup
      // first.
      if (src0 == src1) {
        const std::array<int, 4> lanes{shuffle & 0x3, shuffle >> 8 & 0x3,
                                       shuffle >> 16 & 0x3,
                                       shuffle >> 24 & 0x3};
        std::array<int, 4> lane_counts{};
        for (int lane : lanes) {
          ++lane_counts[lane];
        }

        int duplicate_lane = -1;
        for (int lane = 0; lane < 4; ++lane) {
          if (lane_counts[lane] > 1) {
            duplicate_lane = lane;
            break;
          }
        }

        if (duplicate_lane != -1) {
          __ Dup(dst, src0, duplicate_lane);
          for (int i = 0; i < 4; ++i) {
            int lane = lanes[i];
            if (lane == duplicate_lane) continue;
            __ Mov(dst, i, src0, lane);
          }
          break;
        }
      }

      // Perform shuffle as a vmov per lane.
      for (int i = 0; i < 4; i++) {
        VRegister src = src0;
        int lane = shuffle & 0x7;
        if (lane >= 4) {
          src = src1;
          lane &= 0x3;
        }
        __ Mov(dst, i, src, lane);
        shuffle >>= 8;
      }
      break;
    }
      SIMD_BINOP_CASE(kArm64S32x4ZipLeft, Zip1, 4S);
      SIMD_BINOP_CASE(kArm64S32x4ZipRight, Zip2, 4S);
      SIMD_BINOP_CASE(kArm64S32x4UnzipLeft, Uzp1, 4S);
      SIMD_BINOP_CASE(kArm64S32x4UnzipRight, Uzp2, 4S);
      SIMD_BINOP_CASE(kArm64S32x4TransposeLeft, Trn1, 4S);
      SIMD_BINOP_CASE(kArm64S32x4TransposeRight, Trn2, 4S);
      SIMD_BINOP_CASE(kArm64S16x8ZipLeft, Zip1, 8H);
      SIMD_BINOP_CASE(kArm64S16x8ZipRight, Zip2, 8H);
      SIMD_BINOP_CASE(kArm64S16x8UnzipLeft, Uzp1, 8H);
      SIMD_BINOP_CASE(kArm64S16x8UnzipRight, Uzp2, 8H);
      SIMD_BINOP_CASE(kArm64S16x8TransposeLeft, Trn1, 8H);
      SIMD_BINOP_CASE(kArm64S16x8TransposeRight, Trn2, 8H);
      SIMD_BINOP_CASE(kArm64S8x16ZipLeft, Zip1, 16B);
      SIMD_BINOP_CASE(kArm64S8x16ZipRight, Zip2, 16B);
      SIMD_BINOP_CASE(kArm64S8x16UnzipLeft, Uzp1, 16B);
      SIMD_BINOP_CASE(kArm64S8x16UnzipRight, Uzp2, 16B);
      SIMD_BINOP_CASE(kArm64S8x16TransposeLeft, Trn1, 16B);
      SIMD_BINOP_CASE(kArm64S8x16TransposeRight, Trn2, 16B);
    case kArm64S8x16Concat: {
      __ Ext(i.OutputSimd128Register().V16B(), i.InputSimd128Register(0).V16B(),
             i.InputSimd128Register(1).V16B(), i.InputInt4(2));
      break;
    }
    case kArm64I8x16Swizzle: {
      __ Tbl(i.OutputSimd128Register().V16B(), i.InputSimd128Register(0).V16B(),
             i.InputSimd128Register(1).V16B());
      break;
    }
    case kArm64I8x16Shuffle: {
      Simd128Register dst = i.OutputSimd128Register().V16B(),
                      src0 = i.InputSimd128Register(0).V16B(),
                      src1 = i.InputSimd128Register(1).V16B();
      // Unary shuffle table is in src0, binary shuffle table is in src0, src1,
      // which must be consecutive.
      if (src0 != src1) {
        DCHECK(AreConsecutive(src0, src1));
      }

      int64_t imm1 = make_uint64(i.InputInt32(3), i.InputInt32(2));
      int64_t imm2 = make_uint64(i.InputInt32(5), i.InputInt32(4));
      DCHECK_EQ(0, (imm1 | imm2) & (src0 == src1 ? 0xF0F0F0F0F0F0F0F0
                                                 : 0xE0E0E0E0E0E0E0E0));

      UseScratchRegisterScope scope(masm());
      VRegister temp = scope.AcquireV(kFormat16B);
      __ Movi(temp, imm2, imm1);

      if (src0 == src1) {
        __ Tbl(dst, src0, temp.V16B());
      } else {
        __ Tbl(dst, src0, src1, temp.V16B());
      }
      break;
    }
    case kArm64S32x4Reverse: {
      Simd128Register dst = i.OutputSimd128Register().V16B(),
                      src = i.InputSimd128Register(0).V16B();
      __ Rev64(dst.V4S(), src.V4S());
      __ Ext(dst.V16B(), dst.V16B(), dst.V16B(), 8);
      break;
    }
      SIMD_UNOP_CASE(kArm64S32x2Reverse, Rev64, 4S);
      SIMD_UNOP_CASE(kArm64S16x4Reverse, Rev64, 8H);
      SIMD_UNOP_CASE(kArm64S16x2Reverse, Rev32, 8H);
      SIMD_UNOP_CASE(kArm64S8x8Reverse, Rev64, 16B);
      SIMD_UNOP_CASE(kArm64S8x4Reverse, Rev32, 16B);
      SIMD_UNOP_CASE(kArm64S8x2Reverse, Rev16, 16B);
    case kArm64LoadSplat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      __ ld1r(i.OutputSimd128Register().Format(f), i.MemoryOperand(0));
      break;
    }
    case kArm64LoadLane: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      int laneidx = i.InputInt8(1);
      __ ld1(i.OutputSimd128Register().Format(f), laneidx, i.MemoryOperand(2));
      break;
    }
    case kArm64StoreLane: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      VectorFormat f = VectorFormatFillQ(LaneSizeField::decode(opcode));
      int laneidx = i.InputInt8(1);
      __ st1(i.InputSimd128Register(0).Format(f), laneidx, i.MemoryOperand(2));
      break;
    }
    case kArm64S128Load8x8S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V8B(), i.MemoryOperand(0));
      __ Sxtl(i.OutputSimd128Register().V8H(), i.OutputSimd128Register().V8B());
      break;
    }
    case kArm64S128Load8x8U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V8B(), i.MemoryOperand(0));
      __ Uxtl(i.OutputSimd128Register().V8H(), i.OutputSimd128Register().V8B());
      break;
    }
    case kArm64S128Load16x4S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V4H(), i.MemoryOperand(0));
      __ Sxtl(i.OutputSimd128Register().V4S(), i.OutputSimd128Register().V4H());
      break;
    }
    case kArm64S128Load16x4U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V4H(), i.MemoryOperand(0));
      __ Uxtl(i.OutputSimd128Register().V4S(), i.OutputSimd128Register().V4H());
      break;
    }
    case kArm64S128Load32x2S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V2S(), i.MemoryOperand(0));
      __ Sxtl(i.OutputSimd128Register().V2D(), i.OutputSimd128Register().V2S());
      break;
    }
    case kArm64S128Load32x2U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ldr(i.OutputSimd128Register().V2S(), i.MemoryOperand(0));
      __ Uxtl(i.OutputSimd128Register().V2D()
"""


```