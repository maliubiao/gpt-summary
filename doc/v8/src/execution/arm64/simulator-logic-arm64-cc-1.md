Response:
The user wants a summary of the provided C++ code snippet.
The code defines several member functions of a `Simulator` class, specifically focusing on implementing ARM64 SIMD (Single Instruction, Multiple Data) instructions.
These functions operate on `LogicVRegister` objects, representing SIMD registers, and perform various arithmetic, logical, and bitwise operations.

Here's a breakdown of the functions by category:

*   **Arithmetic:** `sqdmlal`, `sqdmlal2`, `sqdmlsl`, `sqdmlsl2`, `sqdmulh`, `sqrdmulh`, `sub`, `addp`, `addv`, `saddlv`, `uaddlv`, `neg`, `suqadd`, `usqadd`, `abs`.
*   **Logical:** `and_`, `orr`, `orn`, `eor`, `bic`, `bif`, `bit`, `bsl`.
*   **Min/Max:** `SMinMax`, `smax`, `smin`, `SMinMaxP`, `smaxp`, `sminp`, `SMinMaxV`, `smaxv`, `sminv`, `UMinMax`, `umax`, `umin`, `UMinMaxP`, `umaxp`, `uminp`, `UMinMaxV`, `umaxv`, `uminv`.
*   **Polynomial Multiplication:** `PolynomialMult`, `pmul`, `pmull`, `pmull2`.
*   **Shift/Rotate:** `shl`, `sshll`, `sshll2`, `shll`, `shll2`, `ushll`, `ushll2`, `sli`, `sqshl`, `uqshl`, `sqshlu`, `sri`, `ushr`, `sshr`, `ssra`, `usra`, `srsra`, `ursra`, `sshl`, `ushl`.
*   **Bit Counting:** `cls`, `clz`, `cnt`.
*   **Data Extraction:** `ExtractNarrow`, `xtn`.

The code also uses helper functions and types like `VectorFormat`, `LogicVRegister`, `SimVRegister`, and constants like `kMaxLanesPerVector`.

Based on the file path, it's part of the V8 JavaScript engine's simulator for the ARM64 architecture. It provides software implementations of ARM64 SIMD instructions, allowing V8 to run on platforms that may not have native hardware support for these instructions or during development and testing.

The naming convention of the functions closely matches the ARM64 assembly instruction names (e.g., `sqdmlal` likely corresponds to the "Signed saturating doubling multiply-accumulate long" instruction).

The functions manipulate data within SIMD registers, performing element-wise operations based on the provided `VectorFormat`. They also handle saturation behavior, where results are clamped to the maximum or minimum representable values.
这是v8源代码文件 `v8/src/execution/arm64/simulator-logic-arm64.cc` 的第二部分，它主要负责实现 **ARM64 架构的 SIMD (Single Instruction, Multiple Data) 向量运算的模拟逻辑**。

以下是对这部分代码功能的归纳：

**核心功能：**

这部分代码实现了多种 ARM64 SIMD 指令的模拟，这些指令通常用于处理向量数据，即同时对多个数据元素进行相同的操作。  这些指令涵盖了：

*   **算术运算 (Arithmetic Operations):**
    *   带符号饱和的倍长乘加/减 (Signed Saturating Doubling Multiply-Accumulate/Subtract Long): `sqdmlal`, `sqdmlal2`, `sqdmlsl`, `sqdmlsl2`。这些指令将两个源向量的元素相乘，结果加到/减到目标向量对应元素的扩展值上，并进行饱和处理。
    *   带符号饱和的倍长乘高半部分 (Signed Saturating Doubling Multiply High): `sqdmulh`, `sqrdmulh`。这些指令将两个源向量的元素相乘，取结果的高半部分，并进行饱和处理。
    *   减法 (Subtraction): `sub`。
    *   向量对位相加 (Pairwise Add): `addp`。将一个双字向量的两个元素相加。
    *   向量归约加法 (Add across vector): `addv`, `saddlv`, `uaddlv`。将向量的所有元素相加，结果存储到标量寄存器中。
    *   取反 (Negation): `neg`。
    *   带符号/无符号饱和加后加到累加器 (Signed/Unsigned saturating add and accumulate): `suqadd`, `usqadd`。
    *   绝对值 (Absolute value): `abs`。

*   **逻辑运算 (Logical Operations):**
    *   按位与 (AND): `and_`。
    *   按位或 (OR): `orr`。
    *   按位或非 (OR NOT): `orn`。
    *   按位异或 (XOR): `eor`。
    *   按位清除 (Bit Clear): `bic`。
    *   位选择 (Bitfield Select): `bif`, `bit`, `bsl`。根据掩码向量从两个源向量中选择位。

*   **最小值/最大值运算 (Minimum/Maximum Operations):**
    *   带符号最小值/最大值 (Signed Minimum/Maximum): `SMinMax`, `smax`, `smin`。
    *   带符号成对最小值/最大值 (Signed Pairwise Minimum/Maximum): `SMinMaxP`, `smaxp`, `sminp`。
    *   带符号向量归约最小值/最大值 (Signed Minimum/Maximum across vector): `SMinMaxV`, `smaxv`, `sminv`。
    *   无符号最小值/最大值 (Unsigned Minimum/Maximum): `UMinMax`, `umax`, `umin`。
    *   无符号成对最小值/最大值 (Unsigned Pairwise Minimum/Maximum): `UMinMaxP`, `umaxp`, `uminp`。
    *   无符号向量归约最小值/最大值 (Unsigned Minimum/Maximum across vector): `UMinMaxV`, `umaxv`, `uminv`。

*   **多项式乘法 (Polynomial Multiplication):**
    *   8位多项式乘法 (Polynomial Multiply 8-bit): `PolynomialMult`。
    *   向量多项式乘法 (Polynomial Multiply): `pmul`。
    *   向量长多项式乘法 (Polynomial Multiply Long): `pmull`, `pmull2`。

*   **移位/循环移位运算 (Shift/Rotate Operations):**
    *   左移 (Shift Left): `shl`。
    *   带符号扩展左移 (Signed Shift Left Long): `sshll`, `sshll2`。
    *   无符号扩展左移 (Unsigned Shift Left Long): `ushll`, `ushll2`。
    *   向量左移指定位 (Shift Left by Immediate): `sli`。
    *   带符号饱和左移 (Signed Saturating Shift Left): `sqshl`。
    *   无符号饱和左移 (Unsigned Saturating Shift Left): `uqshl`。
    *   带符号饱和左移并转换为无符号 (Signed Saturating Shift Left, Unsigned result): `sqshlu`。
    *   向量右移指定位 (Shift Right by Immediate): `sri`。
    *   无符号右移 (Unsigned Shift Right): `ushr`。
    *   带符号右移 (Signed Shift Right): `sshr`。
    *   带符号右移并加到累加器 (Signed Shift Right and Accumulate): `ssra`, `srsra` (带舍入)。
    *   无符号右移并加到累加器 (Unsigned Shift Right and Accumulate): `usra`, `ursra` (带舍入)。
    *   带符号饱和左移，移位量由向量指定 (Signed Saturating Shift Left by Register): `sshl`。
    *   无符号饱和左移，移位量由向量指定 (Unsigned Saturating Shift Left by Register): `ushl`。

*   **位计数运算 (Bit Counting Operations):**
    *   计数前导符号位 (Count Leading Sign Bits): `cls`。
    *   计数前导零位 (Count Leading Zeros): `clz`。
    *   计数设置位 (Count Set Bits): `cnt`。

*   **数据提取 (Data Extraction):**
    *   窄化提取 (Extract Narrow): `ExtractNarrow`, `xtn`。将较大元素的向量转换为较小元素的向量，并可能进行饱和处理。

**关于文件后缀和 JavaScript 关系：**

*   这段代码是以 `.cc` 结尾的，因此它是 **C++ 源代码**，而不是 Torque 源代码。
*   这些函数模拟的 ARM64 SIMD 指令与 JavaScript 的 **Typed Arrays** 和 **WebAssembly SIMD** 功能有关系。 JavaScript 引擎可以使用这些指令来加速对数组和 WebAssembly 线性内存的操作。

**JavaScript 示例：**

虽然这段代码是 C++，用于模拟底层硬件指令，但其功能直接影响 JavaScript 中对数组的 SIMD 操作。 例如，`addp` 函数模拟了成对相加的操作，这在 JavaScript 中可以通过 Typed Arrays 和 SIMD API 实现：

```javascript
const a = new Uint32Array([1, 2, 3, 4]);
const b = new Uint32Array([5, 6, 7, 8]);

// 假设有 SIMD 类型和操作对应 addp
const vecA = Uint32x2(a[0], a[1]);
const vecB = Uint32x2(a[2], a[3]);
const vecC = Uint32x2(b[0], b[1]);
const vecD = Uint32x2(b[2], b[3]);

const result1 = vecA.add(vecB); // 模拟对 [1, 2] 和 [3, 4] 的某种操作
const result2 = vecC.add(vecD); // 模拟对 [5, 6] 和 [7, 8] 的某种操作

console.log(result1);
console.log(result2);
```

**代码逻辑推理示例：**

以 `sub` 函数为例，假设输入：

*   `vform`: `kFormat4S` (4个32位元素的向量)
*   `src1`: 寄存器包含值 `[10, 20, 30, 40]`
*   `src2`: 寄存器包含值 `[5, 15, 35, 25]`

`sub` 函数会执行以下操作：

1. 遍历向量的每个元素。
2. 对每个元素进行减法：`src1[i] - src2[i]`。
3. 检查是否发生无符号饱和（underflow）。
4. 检查是否发生有符号饱和（overflow/underflow）。
5. 将结果写入目标寄存器 `dst`。

输出：

*   `dst`: 寄存器包含值 `[5, 5, -5, 15]`

**用户常见编程错误示例：**

在涉及到 SIMD 指令时，用户常见的编程错误包括：

*   **数据类型不匹配：**  尝试对不同数据类型的向量进行操作，例如将整数向量与浮点数向量相加。模拟器可以帮助检测这类错误。
*   **向量长度不匹配：**  某些 SIMD 指令要求操作数具有相同的向量长度。
*   **未考虑饱和：** 在进行算术运算时，结果可能会超出目标数据类型的范围。不理解饱和行为可能导致意外的结果。例如，使用 `sqdmlal` 时，如果乘法结果太大，会被限制在最大/最小值，而不是溢出。
*   **位运算的误用：**  不理解按位逻辑运算的特性，例如 `and_`、`orr`、`eor` 等。
*   **移位操作的边界情况：**  对向量进行移位操作时，移位量过大或过小可能导致未定义的行为或错误的结果。模拟器可以帮助理解这些边界情况。 例如，左移操作可能导致数据丢失，而右移操作则会根据数据类型进行零扩展或符号扩展。

**总结：**

这部分 `simulator-logic-arm64.cc` 代码的核心功能是 **模拟 ARM64 架构的 SIMD 向量运算指令**，为 V8 引擎在不支持硬件 SIMD 的环境或开发测试阶段提供软件支持。它实现了各种算术、逻辑、比较、移位和数据提取等向量操作，这些操作直接影响 JavaScript 中 Typed Arrays 和 WebAssembly SIMD 的性能和功能。理解这部分代码有助于深入理解 V8 引擎如何执行底层的向量运算，并能帮助开发者避免与 SIMD 编程相关的常见错误。

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-logic-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-logic-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
imulator::sqdmlal(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlal(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmlal2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlal2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmlsl(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlsl(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmlsl2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlsl2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmulh(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform = VectorFormatFillQ(vform);
  return sqdmulh(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqrdmulh(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform = VectorFormatFillQ(vform);
  return sqrdmulh(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

uint16_t Simulator::PolynomialMult(uint8_t op1, uint8_t op2) {
  return PolynomialMult128(op1, op2, 8).second;
}

LogicVRegister Simulator::pmul(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i,
                PolynomialMult(src1.Uint(vform, i), src2.Uint(vform, i)));
  }
  return dst;
}

LogicVRegister Simulator::pmull(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  VectorFormat vform_src = VectorFormatHalfWidth(vform);
  dst.ClearForWrite(vform);
  // Process the elements in reverse to avoid problems when the destination
  // register is the same as a source.
  for (int i = LaneCountFromFormat(vform) - 1; i > -1; i--) {
    dst.SetUint(
        vform, i,
        PolynomialMult128(src1.Uint(vform_src, i), src2.Uint(vform_src, i),
                          LaneSizeInBitsFromFormat(vform_src)));
  }
  return dst;
}

LogicVRegister Simulator::pmull2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  VectorFormat vform_src = VectorFormatHalfWidthDoubleLanes(vform);
  dst.ClearForWrite(vform);
  int lane_count = LaneCountFromFormat(vform);
  for (int i = 0; i < lane_count; i++) {
    dst.SetUint(vform, i,
                PolynomialMult128(src1.Uint(vform_src, lane_count + i),
                                  src2.Uint(vform_src, lane_count + i),
                                  LaneSizeInBitsFromFormat(vform_src)));
  }
  return dst;
}

LogicVRegister Simulator::sub(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  int lane_size = LaneSizeInBitsFromFormat(vform);
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    // Test for unsigned saturation.
    uint64_t ua = src1.UintLeftJustified(vform, i);
    uint64_t ub = src2.UintLeftJustified(vform, i);
    uint64_t ur = ua - ub;
    if (ub > ua) {
      dst.SetUnsignedSat(i, false);
    }

    // Test for signed saturation.
    bool pos_a = (ua >> 63) == 0;
    bool pos_b = (ub >> 63) == 0;
    bool pos_r = (ur >> 63) == 0;
    // If the signs of the operands are different, and the sign of the first
    // operand doesn't match the result, there was an overflow.
    if ((pos_a != pos_b) && (pos_a != pos_r)) {
      dst.SetSignedSat(i, pos_a);
    }

    dst.SetInt(vform, i, ur >> (64 - lane_size));
  }
  return dst;
}

LogicVRegister Simulator::and_(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) & src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::orr(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) | src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::orn(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) | ~src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::eor(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i,
                src1.Is(src2) ? 0 : src1.Uint(vform, i) ^ src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::bic(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) & ~src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::bic(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, uint64_t imm) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; ++i) {
    result[i] = src.Uint(vform, i) & ~imm;
  }
  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::bif(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t operand1 = dst.Uint(vform, i);
    uint64_t operand2 = ~src2.Uint(vform, i);
    uint64_t operand3 = src1.Uint(vform, i);
    uint64_t result = operand1 ^ ((operand1 ^ operand3) & operand2);
    dst.SetUint(vform, i, result);
  }
  return dst;
}

LogicVRegister Simulator::bit(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t operand1 = dst.Uint(vform, i);
    uint64_t operand2 = src2.Uint(vform, i);
    uint64_t operand3 = src1.Uint(vform, i);
    uint64_t result = operand1 ^ ((operand1 ^ operand3) & operand2);
    dst.SetUint(vform, i, result);
  }
  return dst;
}

LogicVRegister Simulator::bsl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t operand1 = src2.Uint(vform, i);
    uint64_t operand2 = dst.Uint(vform, i);
    uint64_t operand3 = src1.Uint(vform, i);
    uint64_t result = operand1 ^ ((operand1 ^ operand3) & operand2);
    dst.SetUint(vform, i, result);
  }
  return dst;
}

LogicVRegister Simulator::SMinMax(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, bool max) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int64_t src1_val = src1.Int(vform, i);
    int64_t src2_val = src2.Int(vform, i);
    int64_t dst_val;
    if (max) {
      dst_val = (src1_val > src2_val) ? src1_val : src2_val;
    } else {
      dst_val = (src1_val < src2_val) ? src1_val : src2_val;
    }
    dst.SetInt(vform, i, dst_val);
  }
  return dst;
}

LogicVRegister Simulator::smax(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return SMinMax(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::smin(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return SMinMax(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::SMinMaxP(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, bool max) {
  int lanes = LaneCountFromFormat(vform);
  int64_t result[kMaxLanesPerVector];
  const LogicVRegister* src = &src1;
  for (int j = 0; j < 2; j++) {
    for (int i = 0; i < lanes; i += 2) {
      int64_t first_val = src->Int(vform, i);
      int64_t second_val = src->Int(vform, i + 1);
      int64_t dst_val;
      if (max) {
        dst_val = (first_val > second_val) ? first_val : second_val;
      } else {
        dst_val = (first_val < second_val) ? first_val : second_val;
      }
      DCHECK_LT((i >> 1) + (j * lanes / 2), kMaxLanesPerVector);
      result[(i >> 1) + (j * lanes / 2)] = dst_val;
    }
    src = &src2;
  }
  dst.SetIntArray(vform, result);
  return dst;
}

LogicVRegister Simulator::smaxp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return SMinMaxP(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::sminp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return SMinMaxP(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::addp(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  DCHECK_EQ(vform, kFormatD);

  uint64_t dst_val = src.Uint(kFormat2D, 0) + src.Uint(kFormat2D, 1);
  dst.ClearForWrite(vform);
  dst.SetUint(vform, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::addv(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  VectorFormat vform_dst =
      ScalarFormatFromLaneSize(LaneSizeInBitsFromFormat(vform));

  int64_t dst_val = 0;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst_val += src.Int(vform, i);
  }

  dst.ClearForWrite(vform_dst);
  dst.SetInt(vform_dst, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::saddlv(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  VectorFormat vform_dst =
      ScalarFormatFromLaneSize(LaneSizeInBitsFromFormat(vform) * 2);

  int64_t dst_val = 0;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst_val += src.Int(vform, i);
  }

  dst.ClearForWrite(vform_dst);
  dst.SetInt(vform_dst, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::uaddlv(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  VectorFormat vform_dst =
      ScalarFormatFromLaneSize(LaneSizeInBitsFromFormat(vform) * 2);

  uint64_t dst_val = 0;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst_val += src.Uint(vform, i);
  }

  dst.ClearForWrite(vform_dst);
  dst.SetUint(vform_dst, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::SMinMaxV(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, bool max) {
  int64_t dst_val = max ? INT64_MIN : INT64_MAX;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int64_t src_val = src.Int(vform, i);
    if (max) {
      dst_val = (src_val > dst_val) ? src_val : dst_val;
    } else {
      dst_val = (src_val < dst_val) ? src_val : dst_val;
    }
  }
  dst.ClearForWrite(ScalarFormatFromFormat(vform));
  dst.SetInt(vform, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::smaxv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  SMinMaxV(vform, dst, src, true);
  return dst;
}

LogicVRegister Simulator::sminv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  SMinMaxV(vform, dst, src, false);
  return dst;
}

LogicVRegister Simulator::UMinMax(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, bool max) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t src1_val = src1.Uint(vform, i);
    uint64_t src2_val = src2.Uint(vform, i);
    uint64_t dst_val;
    if (max) {
      dst_val = (src1_val > src2_val) ? src1_val : src2_val;
    } else {
      dst_val = (src1_val < src2_val) ? src1_val : src2_val;
    }
    dst.SetUint(vform, i, dst_val);
  }
  return dst;
}

LogicVRegister Simulator::umax(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return UMinMax(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::umin(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return UMinMax(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::UMinMaxP(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, bool max) {
  int lanes = LaneCountFromFormat(vform);
  uint64_t result[kMaxLanesPerVector];
  const LogicVRegister* src = &src1;
  for (int j = 0; j < 2; j++) {
    for (int i = 0; i < LaneCountFromFormat(vform); i += 2) {
      uint64_t first_val = src->Uint(vform, i);
      uint64_t second_val = src->Uint(vform, i + 1);
      uint64_t dst_val;
      if (max) {
        dst_val = (first_val > second_val) ? first_val : second_val;
      } else {
        dst_val = (first_val < second_val) ? first_val : second_val;
      }
      DCHECK_LT((i >> 1) + (j * lanes / 2), kMaxLanesPerVector);
      result[(i >> 1) + (j * lanes / 2)] = dst_val;
    }
    src = &src2;
  }
  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::umaxp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return UMinMaxP(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::uminp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return UMinMaxP(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::UMinMaxV(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, bool max) {
  uint64_t dst_val = max ? 0 : UINT64_MAX;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t src_val = src.Uint(vform, i);
    if (max) {
      dst_val = (src_val > dst_val) ? src_val : dst_val;
    } else {
      dst_val = (src_val < dst_val) ? src_val : dst_val;
    }
  }
  dst.ClearForWrite(ScalarFormatFromFormat(vform));
  dst.SetUint(vform, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::umaxv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  UMinMaxV(vform, dst, src, true);
  return dst;
}

LogicVRegister Simulator::uminv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  UMinMaxV(vform, dst, src, false);
  return dst;
}

LogicVRegister Simulator::shl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return ushl(vform, dst, src, shiftreg);
}

LogicVRegister Simulator::sshll(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = sxtl(vform, temp2, src);
  return sshl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::sshll2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = sxtl2(vform, temp2, src);
  return sshl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::shll(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  int shift = LaneSizeInBitsFromFormat(vform) / 2;
  return sshll(vform, dst, src, shift);
}

LogicVRegister Simulator::shll2(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  int shift = LaneSizeInBitsFromFormat(vform) / 2;
  return sshll2(vform, dst, src, shift);
}

LogicVRegister Simulator::ushll(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = uxtl(vform, temp2, src);
  return ushl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::ushll2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = uxtl2(vform, temp2, src);
  return ushl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::sli(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, int shift) {
  dst.ClearForWrite(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    uint64_t src_lane = src.Uint(vform, i);
    uint64_t dst_lane = dst.Uint(vform, i);
    uint64_t shifted = src_lane << shift;
    uint64_t mask = MaxUintFromFormat(vform) << shift;
    dst.SetUint(vform, i, (dst_lane & ~mask) | shifted);
  }
  return dst;
}

LogicVRegister Simulator::sqshl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return sshl(vform, dst, src, shiftreg).SignedSaturate(vform);
}

LogicVRegister Simulator::uqshl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return ushl(vform, dst, src, shiftreg).UnsignedSaturate(vform);
}

LogicVRegister Simulator::sqshlu(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return sshl(vform, dst, src, shiftreg).UnsignedSaturate(vform);
}

LogicVRegister Simulator::sri(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, int shift) {
  dst.ClearForWrite(vform);
  int laneCount = LaneCountFromFormat(vform);
  DCHECK((shift > 0) &&
         (shift <= static_cast<int>(LaneSizeInBitsFromFormat(vform))));
  for (int i = 0; i < laneCount; i++) {
    uint64_t src_lane = src.Uint(vform, i);
    uint64_t dst_lane = dst.Uint(vform, i);
    uint64_t shifted;
    uint64_t mask;
    if (shift == 64) {
      shifted = 0;
      mask = 0;
    } else {
      shifted = src_lane >> shift;
      mask = MaxUintFromFormat(vform) >> shift;
    }
    dst.SetUint(vform, i, (dst_lane & ~mask) | shifted);
  }
  return dst;
}

LogicVRegister Simulator::ushr(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, -shift);
  return ushl(vform, dst, src, shiftreg);
}

LogicVRegister Simulator::sshr(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, -shift);
  return sshl(vform, dst, src, shiftreg);
}

LogicVRegister Simulator::ssra(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = sshr(vform, temp, src, shift);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::usra(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = ushr(vform, temp, src, shift);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::srsra(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = sshr(vform, temp, src, shift).Round(vform);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::ursra(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = ushr(vform, temp, src, shift).Round(vform);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::cls(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  uint64_t result[16];
  int laneSizeInBits = LaneSizeInBitsFromFormat(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    result[i] = CountLeadingSignBits(src.Int(vform, i), laneSizeInBits);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::clz(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  uint64_t result[16];
  int laneSizeInBits = LaneSizeInBitsFromFormat(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    result[i] = CountLeadingZeros(src.Uint(vform, i), laneSizeInBits);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::cnt(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  uint64_t result[16];
  int laneSizeInBits = LaneSizeInBitsFromFormat(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    uint64_t value = src.Uint(vform, i);
    result[i] = 0;
    for (int j = 0; j < laneSizeInBits; j++) {
      result[i] += (value & 1);
      value >>= 1;
    }
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::sshl(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int8_t shift_val = src2.Int(vform, i);
    int64_t lj_src_val = src1.IntLeftJustified(vform, i);

    // Set signed saturation state.
    if ((shift_val > CountLeadingSignBits(lj_src_val, 64)) &&
        (lj_src_val != 0)) {
      dst.SetSignedSat(i, lj_src_val >= 0);
    }

    // Set unsigned saturation state.
    if (lj_src_val < 0) {
      dst.SetUnsignedSat(i, false);
    } else if ((shift_val > CountLeadingZeros(lj_src_val, 64)) &&
               (lj_src_val != 0)) {
      dst.SetUnsignedSat(i, true);
    }

    int64_t src_val = src1.Int(vform, i);
    bool src_is_negative = src_val < 0;
    if (shift_val > 63) {
      dst.SetInt(vform, i, 0);
    } else if (shift_val < -63) {
      dst.SetRounding(i, src_is_negative);
      dst.SetInt(vform, i, src_is_negative ? -1 : 0);
    } else {
      // Use unsigned types for shifts, as behaviour is undefined for signed
      // lhs.
      uint64_t usrc_val = static_cast<uint64_t>(src_val);

      if (shift_val < 0) {
        // Convert to right shift.
        shift_val = -shift_val;

        // Set rounding state by testing most-significant bit shifted out.
        // Rounding only needed on right shifts.
        if (((usrc_val >> (shift_val - 1)) & 1) == 1) {
          dst.SetRounding(i, true);
        }

        usrc_val >>= shift_val;

        if (src_is_negative) {
          // Simulate sign-extension.
          usrc_val |= (~UINT64_C(0) << (64 - shift_val));
        }
      } else {
        usrc_val <<= shift_val;
      }
      dst.SetUint(vform, i, usrc_val);
    }
  }
  return dst;
}

LogicVRegister Simulator::ushl(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int8_t shift_val = src2.Int(vform, i);
    uint64_t lj_src_val = src1.UintLeftJustified(vform, i);

    // Set saturation state.
    if ((shift_val > CountLeadingZeros(lj_src_val, 64)) && (lj_src_val != 0)) {
      dst.SetUnsignedSat(i, true);
    }

    uint64_t src_val = src1.Uint(vform, i);
    if ((shift_val > 63) || (shift_val < -64)) {
      dst.SetUint(vform, i, 0);
    } else {
      if (shift_val < 0) {
        // Set rounding state. Rounding only needed on right shifts.
        if (((src_val >> (-shift_val - 1)) & 1) == 1) {
          dst.SetRounding(i, true);
        }

        if (shift_val == -64) {
          src_val = 0;
        } else {
          src_val >>= -shift_val;
        }
      } else {
        src_val <<= shift_val;
      }
      dst.SetUint(vform, i, src_val);
    }
  }
  return dst;
}

LogicVRegister Simulator::neg(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    // Test for signed saturation.
    int64_t sa = src.Int(vform, i);
    if (sa == MinIntFromFormat(vform)) {
      dst.SetSignedSat(i, true);
    }
    dst.SetInt(vform, i, (sa == INT64_MIN) ? sa : -sa);
  }
  return dst;
}

LogicVRegister Simulator::suqadd(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int64_t sa = dst.IntLeftJustified(vform, i);
    uint64_t ub = src.UintLeftJustified(vform, i);
    uint64_t ur = sa + ub;

    int64_t sr = base::bit_cast<int64_t>(ur);
    if (sr < sa) {  // Test for signed positive saturation.
      dst.SetInt(vform, i, MaxIntFromFormat(vform));
    } else {
      dst.SetUint(vform, i, dst.Int(vform, i) + src.Uint(vform, i));
    }
  }
  return dst;
}

LogicVRegister Simulator::usqadd(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t ua = dst.UintLeftJustified(vform, i);
    int64_t sb = src.IntLeftJustified(vform, i);
    uint64_t ur = ua + sb;

    if ((sb > 0) && (ur <= ua)) {
      dst.SetUint(vform, i, MaxUintFromFormat(vform));  // Positive saturation.
    } else if ((sb < 0) && (ur >= ua)) {
      dst.SetUint(vform, i, 0);  // Negative saturation.
    } else {
      dst.SetUint(vform, i, dst.Uint(vform, i) + src.Int(vform, i));
    }
  }
  return dst;
}

LogicVRegister Simulator::abs(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    // Test for signed saturation.
    int64_t sa = src.Int(vform, i);
    if (sa == MinIntFromFormat(vform)) {
      dst.SetSignedSat(i, true);
    }
    if (sa < 0) {
      dst.SetInt(vform, i, (sa == INT64_MIN) ? sa : -sa);
    } else {
      dst.SetInt(vform, i, sa);
    }
  }
  return dst;
}

LogicVRegister Simulator::ExtractNarrow(VectorFormat dstform,
                                        LogicVRegister dst, bool dstIsSigned,
                                        const LogicVRegister& src,
                                        bool srcIsSigned) {
  bool upperhalf = false;
  VectorFormat srcform = kFormatUndefined;
  int64_t ssrc[8];
  uint64_t usrc[8];

  switch (dstform) {
    case kFormat8B:
      upperhalf = false;
      srcform = kFormat8H;
      break;
    case kFormat16B:
      upperhalf = true;
      srcform = kFormat8H;
      break;
    case kFormat4H:
      upperhalf = false;
      srcform = kFormat4S;
      break;
    case kFormat8H:
      upperhalf = true;
      srcform = kFormat4S;
      break;
    case kFormat2S:
      upperhalf = false;
      srcform = kFormat2D;
      break;
    case kFormat4S:
      upperhalf = true;
      srcform = kFormat2D;
      break;
    case kFormatB:
      upperhalf = false;
      srcform = kFormatH;
      break;
    case kFormatH:
      upperhalf = false;
      srcform = kFormatS;
      break;
    case kFormatS:
      upperhalf = false;
      srcform = kFormatD;
      break;
    default:
      UNIMPLEMENTED();
  }

  for (int i = 0; i < LaneCountFromFormat(srcform); i++) {
    ssrc[i] = src.Int(srcform, i);
    usrc[i] = src.Uint(srcform, i);
  }

  int offset;
  if (upperhalf) {
    offset = LaneCountFromFormat(dstform) / 2;
  } else {
    offset = 0;
    dst.ClearForWrite(dstform);
  }

  for (int i = 0; i < LaneCountFromFormat(srcform); i++) {
    // Test for signed saturation
    if (ssrc[i] > MaxIntFromFormat(dstform)) {
      dst.SetSignedSat(offset + i, true);
    } else if (ssrc[i] < MinIntFromFormat(dstform)) {
      dst.SetSignedSat(offset + i, false);
    }

    // Test for unsigned saturation
    if (srcIsSigned) {
      if (ssrc[i] > static_cast<int64_t>(MaxUintFromFormat(dstform))) {
        dst.SetUnsignedSat(offset + i, true);
      } else if (ssrc[i] < 0) {
        dst.SetUnsignedSat(offset + i, false);
      }
    } else {
      if (usrc[i] > MaxUintFromFormat(dstform)) {
        dst.SetUnsignedSat(offset + i, true);
      }
    }

    int64_t result;
    if (srcIsSigned) {
      result = ssrc[i] & MaxUintFromFormat(dstform);
    } else {
      result = usrc[i] & MaxUintFromFormat(dstform);
    }

    if (dstIsSigned) {
      dst.SetInt(dstform, offset + i, result);
    } else {
      dst.SetUint(dstform, offset + i, result);
    }
  }
  return dst;
}

LogicVRegister Simulator::xtn(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  return ExtractNarrow(vform, dst, true, src, true
```