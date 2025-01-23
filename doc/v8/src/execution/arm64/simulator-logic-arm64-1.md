Response: The user wants a summary of the functionality of the provided C++ code snippet. This code seems to implement a simulator for ARM64 vector (NEON) instructions, focusing on logical operations. The request also asks to illustrate the connection with JavaScript if any exists.

Here's a breakdown of the code's functionality:

1. **Vector Logical Operations:** The code defines various functions that simulate ARM64 NEON instructions. These functions operate on `LogicVRegister` objects, which represent vector registers. The operations include:
    * **Extracting and Saturating:** `sqxtn`, `sqxtun`, `uqxtn` for narrowing vector elements and optionally saturating the results.
    * **Absolute Difference:** `AbsDiff`, `saba`, `uaba` for calculating the absolute difference between vector elements.
    * **Bitwise NOT:** `not_` for inverting bits in a vector.
    * **Bit Reversal:** `rbit` for reversing the bits in each element.
    * **Byte/Element Reversal:** `rev`, `rev16`, `rev32`, `rev64` for reversing the order of bytes or elements within vector lanes.
    * **Adding Pairs:** `addlp`, `saddlp`, `uaddlp`, `sadalp`, `uadalp` for adding adjacent pairs of elements in a vector.
    * **Vector Extension:** `ext` for creating a new vector by combining parts of two existing vectors.
    * **Element Duplication:** `dup_element`, `dup_immediate` for creating vectors with duplicated elements.
    * **Element Insertion:** `ins_element`, `ins_immediate` for inserting elements into a vector.
    * **Move Immediate:** `movi`, `mvni` for moving immediate values into vectors.
    * **Bitwise OR with Immediate:** `orr` for performing bitwise OR with an immediate value.
    * **Unsigned/Signed Extend and Load:** `uxtl`, `sxtl`, `uxtl2`, `sxtl2` for extending smaller elements to larger ones.
    * **Shift Right Narrow:** `shrn`, `shrn2`, `rshrn`, `rshrn2` for shifting elements right and narrowing the result.
    * **Table Lookup:** `Table`, `tbl`, `tbx` for looking up values in a table based on an index vector.
    * **Unsigned/Signed Saturating Shift Right Narrow:** `uqshrn`, `uqshrn2`, `uqrshrn`, `uqrshrn2`, `sqshrn`, `sqshrn2`, `sqrshrn`, `sqrshrn2`, `sqshrun`, `sqshrun2`, `sqrshrun`, `sqrshrun2`.
    * **Unsigned/Signed Add Long:** `uaddl`, `uaddl2`, `uaddw`, `uaddw2`, `saddl`, `saddl2`, `saddw`, `saddw2`.
    * **Unsigned/Signed Subtract Long:** `usubl`, `usubl2`, `usubw`, `usubw2`, `ssubl`, `ssubl2`, `ssubw`, `ssubw2`.
    * **Unsigned/Signed Accumulate Absolute Difference Long:** `uabal`, `uabal2`, `sabal`, `sabal2`.
    * **Unsigned/Signed Absolute Difference Long:** `uabdl`, `uabdl2`, `sabdl`, `sabdl2`.
    * **Unsigned/Signed Multiply Long:** `umull`, `umull2`, `smull`, `smull2`.
    * **Unsigned/Signed Multiply Subtract Long:** `umlsl`, `umlsl2`, `smlsl`, `smlsl2`.
    * **Unsigned/Signed Multiply Accumulate Long:** `umlal`, `umlal2`, `smlal`, `smlal2`.
    * **Signed Saturating Doubling Multiply Accumulate Long:** `sqdmlal`, `sqdmlal2`.
    * **Signed Saturating Doubling Multiply Subtract Long:** `sqdmlsl`, `sqdmlsl2`.
    * **Signed Saturating Doubling Multiply Long:** `sqdmull`, `sqdmull2`.
    * **Signed Saturating Rounding Doubling Multiply High:** `sqrdmulh`, `sqdmulh`.
    * **Add/Subtract High Narrow:** `addhn`, `addhn2`, `raddhn`, `raddhn2`, `subhn`, `subhn2`, `rsubhn`, `rsubhn2`.
    * **Transpose:** `trn1`, `trn2`.
    * **Zip:** `zip1`, `zip2`.
    * **Unzip:** `uzp1`, `uzp2`.

2. **Floating-Point Emulation:** The code also includes functions for simulating floating-point operations, handling NaN and infinity cases according to IEEE 754 standards. This includes:
    * **Basic Arithmetic:** `FPAdd`, `FPSub`, `FPMul`, `FPDiv`.
    * **Fused Multiply-Add:** `FPMulAdd`.
    * **Square Root:** `FPSqrt`.
    * **Max/Min:** `FPMax`, `FPMin`, `FPMaxNM`, `FPMinNM`.
    * **Reciprocal and Reciprocal Square Root Step:** `FPRecipStepFused`, `FPRSqrtStepFused`.
    * **Rounding to Integer:** `FPRoundInt`.
    * **Floating-Point to Integer Conversion:** `FPToInt16`, `FPToInt32`, `FPToInt64`, `FPToUInt16`, `FPToUInt32`, `FPToUInt64`.
    * **Vectorized Floating-Point Operations:**  Macros are used to define vectorized versions of basic floating-point operations like addition, subtraction, multiplication, division, negation, absolute value, square root, compare, and fused multiply-add/subtract.

3. **JavaScript Relationship:**  This code is part of the V8 JavaScript engine, specifically the simulator used for testing and development on ARM64 architectures when a native ARM64 environment isn't available. JavaScript doesn't directly expose these low-level SIMD instructions. However, V8 internally uses these instructions (or their simulated counterparts) to optimize JavaScript code execution, especially for tasks involving:
    * **Typed Arrays:** JavaScript's `TypedArray` objects (like `Float32Array`, `Int32Array`, etc.) can be efficiently processed using SIMD instructions for operations on numerical data.
    * **WebAssembly (Wasm):**  WebAssembly allows developers to write code in languages like C or C++ and compile it to a bytecode format that can be executed in the browser. Wasm has explicit support for SIMD instructions, which map closely to NEON instructions. V8 uses this simulator when running Wasm code with SIMD on non-ARM64 hardware or for testing.
    * **Internal Optimizations:** V8's optimizing compiler (TurboFan) can sometimes automatically vectorize JavaScript code when it detects opportunities for parallel execution on array elements. This might involve the internal use of SIMD operations.

**JavaScript Examples:**

Let's illustrate how these simulated instructions relate to JavaScript concepts, even though direct mapping isn't there:

**Example 1:  `add` (Vector Addition) and `TypedArray`**

```javascript
// JavaScript (Conceptual - the underlying engine might use SIMD)
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const result = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  result[i] = a[i] + b[i];
}

console.log(result); // Output: Float32Array [ 6, 8, 10, 12 ]
```

Internally, if V8 detects this pattern (adding elements of two arrays), it might use SIMD instructions like the simulated `add` function to perform the addition more efficiently on multiple elements at once.

**Example 2: `fmul` (Vector Floating-Point Multiplication) and WebAssembly**

```javascript
// JavaScript (Loading and running a WebAssembly module with SIMD)
async function runWasmSimd() {
  const response = await fetch('simd_module.wasm'); // Assume a WASM module with SIMD
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);

  const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
  const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
  const result = new Float32Array(4);

  // Assuming the WASM module has a function 'multiplyVectors' that uses SIMD
  module.instance.exports.multiplyVectors(a, b, result);

  console.log(result); // Output: Float32Array [ 5, 12, 21, 32 ]
}

runWasmSimd();
```

In this case, the WebAssembly module might contain instructions that directly map to NEON instructions (and thus, are simulated by the provided C++ code when running on a non-ARM64 platform). The `multiplyVectors` function in the Wasm module could use SIMD instructions similar to the `fmul` simulator function.

**In summary, this C++ code provides a software implementation of the ARM64 architecture's vector logic and floating-point instructions. It's a crucial part of the V8 JavaScript engine's simulator, allowing the engine to run and test ARM64-specific optimizations and WebAssembly code on different platforms.**

这是文件 `v8/src/execution/arm64/simulator-logic-arm64.cc` 的第二部分代码，延续了第一部分的功能，主要负责**模拟 ARM64 架构中向量（NEON）逻辑运算相关的指令**。

具体来说，这部分代码定义了 `Simulator` 类的成员函数，用于模拟各种 ARM64 NEON 指令的行为，包括：

**1. 向量元素的提取和饱和 (Extract and Saturate):**
   - `sqxtn`: 将向量元素缩小一半，并进行有符号饱和。
   - `sqxtun`: 将向量元素缩小一半，并进行无符号饱和。
   - `uqxtn`: 将向量元素缩小一半，并进行无符号饱和。

**2. 向量元素的绝对差值运算 (Absolute Difference):**
   - `AbsDiff`: 计算两个向量对应元素的绝对差值。
   - `saba`: 计算两个向量对应元素的绝对差值，并将结果累加到目标向量（有符号）。
   - `uaba`: 计算两个向量对应元素的绝对差值，并将结果累加到目标向量（无符号）。

**3. 向量按位取反 (Bitwise NOT):**
   - `not_`: 对向量的每个元素进行按位取反操作。

**4. 向量位反转 (Bit Reversal):**
   - `rbit`: 反转向量中每个元素的位顺序。

**5. 向量元素/字节反转 (Reverse):**
   - `rev`: 反转向量中指定大小（revSize）的元素或字节顺序。
   - `rev16`, `rev32`, `rev64`: 分别反转向量中 2 字节、4 字节、8 字节的元素顺序。

**6. 向量元素对相加 (Add Pairwise):**
   - `addlp`: 将向量中相邻的元素对相加，结果放入目标向量。
   - `saddlp`: 有符号的元素对相加。
   - `uaddlp`: 无符号的元素对相加。
   - `sadalp`: 有符号的元素对相加，并将结果累加到目标向量。
   - `uadalp`: 无符号的元素对相加，并将结果累加到目标向量。

**7. 向量扩展 (Extend):**
   - `ext`: 从两个源向量中提取元素，创建一个新的向量。

**8. 向量元素复制 (Duplicate):**
   - `dup_element`: 将源向量中指定索引的元素复制到目标向量的所有元素中。
   - `dup_immediate`: 将一个立即数复制到目标向量的所有元素中。

**9. 向量元素插入 (Insert):**
   - `ins_element`: 将源向量中指定索引的元素插入到目标向量的指定索引位置。
   - `ins_immediate`: 将一个立即数插入到目标向量的指定索引位置。

**10. 向量移动立即数 (Move Immediate):**
    - `movi`: 将一个立即数移动到向量的所有通道。
    - `mvni`: 将一个立即数的按位取反移动到向量的所有通道。

**11. 向量按位或立即数 (OR with Immediate):**
    - `orr`: 将向量的每个元素与一个立即数进行按位或运算。

**12. 向量扩展加载 (Extend and Load):**
    - `uxtl`: 将源向量的低半部分无符号扩展并加载到目标向量。
    - `sxtl`: 将源向量的低半部分有符号扩展并加载到目标向量。
    - `uxtl2`: 将源向量的高半部分无符号扩展并加载到目标向量。
    - `sxtl2`: 将源向量的高半部分有符号扩展并加载到目标向量。

**13. 向量缩小右移 (Shift Right Narrow):**
    - `shrn`: 将双字长的源向量右移指定位数，并将结果缩小到单字长。
    - `shrn2`:  将双字长的源向量的高半部分右移指定位数，并将结果缩小到单字长。
    - `rshrn`: 将双字长的源向量右移指定位数，并将结果舍入后缩小到单字长。
    - `rshrn2`: 将双字长的源向量的高半部分右移指定位数，并将结果舍入后缩小到单字长。

**14. 向量表查找 (Table Lookup):**
    - `Table`: 使用索引向量在多个表向量中查找元素。
    - `tbl`:  使用索引向量在一个或多个表向量中查找元素，超出范围的索引返回零。
    - `tbx`:  使用索引向量在一个或多个表向量中查找元素，超出范围的索引保持目标向量原值。

**15. 向量饱和缩小右移 (Saturating Shift Right Narrow):**
    - `uqshrn`, `uqshrn2`, `uqrshrn`, `uqrshrn2`: 无符号饱和缩小右移。
    - `sqshrn`, `sqshrn2`, `sqrshrn`, `sqrshrn2`: 有符号饱和缩小右移。
    - `sqshrun`, `sqshrun2`, `sqrshrun`, `sqrshrun2`: 有符号饱和缩小右移到无符号。

**16. 向量加长 (Add Long):**
    - `uaddl`, `uaddl2`: 无符号加长。
    - `uaddw`, `uaddw2`: 无符号加宽加法。
    - `saddl`, `saddl2`: 有符号加长。
    - `saddw`, `saddw2`: 有符号加宽加法。

**17. 向量减长 (Subtract Long):**
    - `usubl`, `usubl2`: 无符号减长。
    - `usubw`, `usubw2`: 无符号加宽减法。
    - `ssubl`, `ssubl2`: 有符号减长。
    - `ssubw`, `ssubw2`: 有符号加宽减法。

**18. 向量累加绝对差值长 (Accumulate Absolute Difference Long):**
    - `uabal`, `uabal2`: 无符号累加绝对差值长。
    - `sabal`, `sabal2`: 有符号累加绝对差值长。

**19. 向量绝对差值长 (Absolute Difference Long):**
    - `uabdl`, `uabdl2`: 无符号绝对差值长。
    - `sabdl`, `sabdl2`: 有符号绝对差值长。

**20. 向量乘长 (Multiply Long):**
    - `umull`, `umull2`: 无符号乘长。
    - `smull`, `smull2`: 有符号乘长。

**21. 向量乘减长 (Multiply Subtract Long):**
    - `umlsl`, `umlsl2`: 无符号乘减长。
    - `smlsl`, `smlsl2`: 有符号乘减长。

**22. 向量乘加长 (Multiply Accumulate Long):**
    - `umlal`, `umlal2`: 无符号乘加长。
    - `smlal`, `smlal2`: 有符号乘加长。

**23. 向量饱和倍增乘加长 (Saturating Doubling Multiply Accumulate Long):**
    - `sqdmlal`, `sqdmlal2`: 有符号饱和倍增乘加长。

**24. 向量饱和倍增乘减长 (Saturating Doubling Multiply Subtract Long):**
    - `sqdmlsl`, `sqdmlsl2`: 有符号饱和倍增乘减长。

**25. 向量饱和倍增乘长 (Saturating Doubling Multiply Long):**
    - `sqdmull`, `sqdmull2`: 有符号饱和倍增乘长。

**26. 向量饱和舍入倍增乘高 (Saturating Rounding Doubling Multiply High):**
    - `sqrdmulh`, `sqdmulh`: 有符号饱和舍入倍增乘高。

**27. 向量加/减窄 (Add/Subtract High Narrow):**
    - `addhn`, `addhn2`, `raddhn`, `raddhn2`: 加法并缩小。
    - `subhn`, `subhn2`, `rsubhn`, `rsubhn2`: 减法并缩小。

**28. 向量转置 (Transpose):**
    - `trn1`, `trn2`:  将两个向量的元素交错放置。

**29. 向量交叉 (Zip):**
    - `zip1`, `zip2`: 将两个向量的低/高半部分交叉放置。

**30. 向量解交错 (Unzip):**
    - `uzp1`, `uzp2`: 将一个向量的偶数/奇数索引元素分别放置到目标向量。

**与 JavaScript 的关系：**

虽然这段 C++ 代码是 V8 引擎的内部实现，JavaScript 代码本身并不能直接调用这些底层的向量指令，但 V8 引擎会在以下几种情况下利用这些指令来优化 JavaScript 代码的执行：

* **Typed Arrays:** 当 JavaScript 代码操作 `TypedArray` (例如 `Float32Array`, `Int32Array`) 时，V8 可能会在底层使用 NEON 指令来并行处理数组中的多个元素，从而提高性能。
* **WebAssembly (Wasm):** WebAssembly 允许使用 SIMD 指令，这些指令会映射到 ARM64 的 NEON 指令。当在 ARM64 架构上运行包含 SIMD 指令的 WebAssembly 代码时，V8 会使用这些模拟函数来执行。
* **内部优化:** V8 的优化编译器 (TurboFan) 可能会将某些 JavaScript 代码模式识别为可以向量化的操作，并在底层使用 NEON 指令进行优化。

**JavaScript 示例 (概念性):**

```javascript
// JavaScript (使用 TypedArray 进行向量操作，V8 可能会在底层使用 SIMD 指令)
const a = new Float32Array([1, 2, 3, 4]);
const b = new Float32Array([5, 6, 7, 8]);
const result = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  result[i] = a[i] + b[i]; // V8 可能会使用类似 Simulator::add 的函数
}

console.log(result); // 输出: Float32Array [6, 8, 10, 12]

// WebAssembly 示例 (如果 WebAssembly 代码使用了 SIMD)
// (假设有一个名为 'add_vectors' 的 WebAssembly 函数，它使用 SIMD 加法)
const wasmCode = /* ... 包含 SIMD 指令的 WebAssembly 代码 ... */;
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

const aWasm = new Float32Array(wasmInstance.exports.memory.buffer, 0, 4);
const bWasm = new Float32Array(wasmInstance.exports.memory.buffer, 16, 4);
const resultWasm = new Float32Array(wasmInstance.exports.memory.buffer, 32, 4);

aWasm.set([1, 2, 3, 4]);
bWasm.set([5, 6, 7, 8]);

wasmInstance.exports.add_vectors(aWasm.byteOffset, bWasm.byteOffset, resultWasm.byteOffset); // 底层会调用模拟的 SIMD 加法

console.log(resultWasm); // 输出: Float32Array [6, 8, 10, 12]
```

总而言之，这段 C++ 代码是 V8 引擎用于模拟 ARM64 体系结构中向量逻辑运算指令的关键组成部分，这对于在非 ARM64 平台上运行和测试 V8 以及优化 JavaScript 和 WebAssembly 代码的执行至关重要。

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-logic-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
);
}

LogicVRegister Simulator::sqxtn(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  return ExtractNarrow(vform, dst, true, src, true).SignedSaturate(vform);
}

LogicVRegister Simulator::sqxtun(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  return ExtractNarrow(vform, dst, false, src, true).UnsignedSaturate(vform);
}

LogicVRegister Simulator::uqxtn(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  return ExtractNarrow(vform, dst, false, src, false).UnsignedSaturate(vform);
}

LogicVRegister Simulator::AbsDiff(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, bool issigned) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    if (issigned) {
      int64_t sr = src1.Int(vform, i) - src2.Int(vform, i);
      sr = sr > 0 ? sr : -sr;
      dst.SetInt(vform, i, sr);
    } else {
      int64_t sr = src1.Uint(vform, i) - src2.Uint(vform, i);
      sr = sr > 0 ? sr : -sr;
      dst.SetUint(vform, i, sr);
    }
  }
  return dst;
}

LogicVRegister Simulator::saba(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  SimVRegister temp;
  dst.ClearForWrite(vform);
  AbsDiff(vform, temp, src1, src2, true);
  add(vform, dst, dst, temp);
  return dst;
}

LogicVRegister Simulator::uaba(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  SimVRegister temp;
  dst.ClearForWrite(vform);
  AbsDiff(vform, temp, src1, src2, false);
  add(vform, dst, dst, temp);
  return dst;
}

LogicVRegister Simulator::not_(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, ~src.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::rbit(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  int laneSizeInBits = LaneSizeInBitsFromFormat(vform);
  uint64_t reversed_value;
  uint64_t value;
  for (int i = 0; i < laneCount; i++) {
    value = src.Uint(vform, i);
    reversed_value = 0;
    for (int j = 0; j < laneSizeInBits; j++) {
      reversed_value = (reversed_value << 1) | (value & 1);
      value >>= 1;
    }
    result[i] = reversed_value;
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::rev(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, int revSize) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  int laneSize = LaneSizeInBytesFromFormat(vform);
  int lanesPerLoop = revSize / laneSize;
  for (int i = 0; i < laneCount; i += lanesPerLoop) {
    for (int j = 0; j < lanesPerLoop; j++) {
      result[i + lanesPerLoop - 1 - j] = src.Uint(vform, i + j);
    }
  }
  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::rev16(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  return rev(vform, dst, src, 2);
}

LogicVRegister Simulator::rev32(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  return rev(vform, dst, src, 4);
}

LogicVRegister Simulator::rev64(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  return rev(vform, dst, src, 8);
}

LogicVRegister Simulator::addlp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, bool is_signed,
                                bool do_accumulate) {
  VectorFormat vformsrc = VectorFormatHalfWidthDoubleLanes(vform);
  DCHECK_LE(LaneSizeInBitsFromFormat(vformsrc), 32U);
  DCHECK_LE(LaneCountFromFormat(vform), 8);

  uint64_t result[8];
  int lane_count = LaneCountFromFormat(vform);
  for (int i = 0; i < lane_count; i++) {
    if (is_signed) {
      result[i] = static_cast<uint64_t>(src.Int(vformsrc, 2 * i) +
                                        src.Int(vformsrc, 2 * i + 1));
    } else {
      result[i] = src.Uint(vformsrc, 2 * i) + src.Uint(vformsrc, 2 * i + 1);
    }
  }

  dst.ClearForWrite(vform);
  for (int i = 0; i < lane_count; ++i) {
    if (do_accumulate) {
      result[i] += dst.Uint(vform, i);
    }
    dst.SetUint(vform, i, result[i]);
  }

  return dst;
}

LogicVRegister Simulator::saddlp(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  return addlp(vform, dst, src, true, false);
}

LogicVRegister Simulator::uaddlp(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  return addlp(vform, dst, src, false, false);
}

LogicVRegister Simulator::sadalp(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  return addlp(vform, dst, src, true, true);
}

LogicVRegister Simulator::uadalp(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  return addlp(vform, dst, src, false, true);
}

LogicVRegister Simulator::ext(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2, int index) {
  uint8_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount - index; ++i) {
    result[i] = src1.Uint(vform, i + index);
  }
  for (int i = 0; i < index; ++i) {
    result[laneCount - index + i] = src2.Uint(vform, i);
  }
  dst.ClearForWrite(vform);
  for (int i = 0; i < laneCount; ++i) {
    dst.SetUint(vform, i, result[i]);
  }
  return dst;
}

LogicVRegister Simulator::dup_element(VectorFormat vform, LogicVRegister dst,
                                      const LogicVRegister& src,
                                      int src_index) {
  int laneCount = LaneCountFromFormat(vform);
  uint64_t value = src.Uint(vform, src_index);
  dst.ClearForWrite(vform);
  for (int i = 0; i < laneCount; ++i) {
    dst.SetUint(vform, i, value);
  }
  return dst;
}

LogicVRegister Simulator::dup_immediate(VectorFormat vform, LogicVRegister dst,
                                        uint64_t imm) {
  int laneCount = LaneCountFromFormat(vform);
  uint64_t value = imm & MaxUintFromFormat(vform);
  dst.ClearForWrite(vform);
  for (int i = 0; i < laneCount; ++i) {
    dst.SetUint(vform, i, value);
  }
  return dst;
}

LogicVRegister Simulator::ins_element(VectorFormat vform, LogicVRegister dst,
                                      int dst_index, const LogicVRegister& src,
                                      int src_index) {
  dst.SetUint(vform, dst_index, src.Uint(vform, src_index));
  return dst;
}

LogicVRegister Simulator::ins_immediate(VectorFormat vform, LogicVRegister dst,
                                        int dst_index, uint64_t imm) {
  uint64_t value = imm & MaxUintFromFormat(vform);
  dst.SetUint(vform, dst_index, value);
  return dst;
}

LogicVRegister Simulator::movi(VectorFormat vform, LogicVRegister dst,
                               uint64_t imm) {
  int laneCount = LaneCountFromFormat(vform);
  dst.ClearForWrite(vform);
  for (int i = 0; i < laneCount; ++i) {
    dst.SetUint(vform, i, imm);
  }
  return dst;
}

LogicVRegister Simulator::mvni(VectorFormat vform, LogicVRegister dst,
                               uint64_t imm) {
  int laneCount = LaneCountFromFormat(vform);
  dst.ClearForWrite(vform);
  for (int i = 0; i < laneCount; ++i) {
    dst.SetUint(vform, i, ~imm);
  }
  return dst;
}

LogicVRegister Simulator::orr(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, uint64_t imm) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; ++i) {
    result[i] = src.Uint(vform, i) | imm;
  }
  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::uxtl(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  VectorFormat vform_half = VectorFormatHalfWidth(vform);

  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src.Uint(vform_half, i));
  }
  return dst;
}

LogicVRegister Simulator::sxtl(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  VectorFormat vform_half = VectorFormatHalfWidth(vform);

  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetInt(vform, i, src.Int(vform_half, i));
  }
  return dst;
}

LogicVRegister Simulator::uxtl2(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  VectorFormat vform_half = VectorFormatHalfWidth(vform);
  int lane_count = LaneCountFromFormat(vform);

  dst.ClearForWrite(vform);
  for (int i = 0; i < lane_count; i++) {
    dst.SetUint(vform, i, src.Uint(vform_half, lane_count + i));
  }
  return dst;
}

LogicVRegister Simulator::sxtl2(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  VectorFormat vform_half = VectorFormatHalfWidth(vform);
  int lane_count = LaneCountFromFormat(vform);

  dst.ClearForWrite(vform);
  for (int i = 0; i < lane_count; i++) {
    dst.SetInt(vform, i, src.Int(vform_half, lane_count + i));
  }
  return dst;
}

LogicVRegister Simulator::shrn(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vform_src = VectorFormatDoubleWidth(vform);
  VectorFormat vform_dst = vform;
  LogicVRegister shifted_src = ushr(vform_src, temp, src, shift);
  return ExtractNarrow(vform_dst, dst, false, shifted_src, false);
}

LogicVRegister Simulator::shrn2(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(VectorFormatHalfLanes(vform));
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = ushr(vformsrc, temp, src, shift);
  return ExtractNarrow(vformdst, dst, false, shifted_src, false);
}

LogicVRegister Simulator::rshrn(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(vform);
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = ushr(vformsrc, temp, src, shift).Round(vformsrc);
  return ExtractNarrow(vformdst, dst, false, shifted_src, false);
}

LogicVRegister Simulator::rshrn2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(VectorFormatHalfLanes(vform));
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = ushr(vformsrc, temp, src, shift).Round(vformsrc);
  return ExtractNarrow(vformdst, dst, false, shifted_src, false);
}

LogicVRegister Simulator::Table(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& ind,
                                bool zero_out_of_bounds,
                                const LogicVRegister* tab1,
                                const LogicVRegister* tab2,
                                const LogicVRegister* tab3,
                                const LogicVRegister* tab4) {
  DCHECK_NOT_NULL(tab1);
  const LogicVRegister* tab[4] = {tab1, tab2, tab3, tab4};
  uint64_t result[kMaxLanesPerVector];
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    result[i] = zero_out_of_bounds ? 0 : dst.Uint(kFormat16B, i);
  }
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t j = ind.Uint(vform, i);
    int tab_idx = static_cast<int>(j >> 4);
    int j_idx = static_cast<int>(j & 15);
    if ((tab_idx < 4) && (tab[tab_idx] != nullptr)) {
      result[i] = tab[tab_idx]->Uint(kFormat16B, j_idx);
    }
  }
  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::tbl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, true, &tab);
}

LogicVRegister Simulator::tbl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& tab2,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, true, &tab, &tab2);
}

LogicVRegister Simulator::tbl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& tab2,
                              const LogicVRegister& tab3,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, true, &tab, &tab2, &tab3);
}

LogicVRegister Simulator::tbl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& tab2,
                              const LogicVRegister& tab3,
                              const LogicVRegister& tab4,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, true, &tab, &tab2, &tab3, &tab4);
}

LogicVRegister Simulator::tbx(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, false, &tab);
}

LogicVRegister Simulator::tbx(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& tab2,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, false, &tab, &tab2);
}

LogicVRegister Simulator::tbx(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& tab2,
                              const LogicVRegister& tab3,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, false, &tab, &tab2, &tab3);
}

LogicVRegister Simulator::tbx(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& tab,
                              const LogicVRegister& tab2,
                              const LogicVRegister& tab3,
                              const LogicVRegister& tab4,
                              const LogicVRegister& ind) {
  return Table(vform, dst, ind, false, &tab, &tab2, &tab3, &tab4);
}

LogicVRegister Simulator::uqshrn(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  return shrn(vform, dst, src, shift).UnsignedSaturate(vform);
}

LogicVRegister Simulator::uqshrn2(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src, int shift) {
  return shrn2(vform, dst, src, shift).UnsignedSaturate(vform);
}

LogicVRegister Simulator::uqrshrn(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src, int shift) {
  return rshrn(vform, dst, src, shift).UnsignedSaturate(vform);
}

LogicVRegister Simulator::uqrshrn2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, int shift) {
  return rshrn2(vform, dst, src, shift).UnsignedSaturate(vform);
}

LogicVRegister Simulator::sqshrn(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(vform);
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift);
  return sqxtn(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::sqshrn2(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(VectorFormatHalfLanes(vform));
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift);
  return sqxtn(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::sqrshrn(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(vform);
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift).Round(vformsrc);
  return sqxtn(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::sqrshrn2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(VectorFormatHalfLanes(vform));
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift).Round(vformsrc);
  return sqxtn(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::sqshrun(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(vform);
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift);
  return sqxtun(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::sqshrun2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(VectorFormatHalfLanes(vform));
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift);
  return sqxtun(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::sqrshrun(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(vform);
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift).Round(vformsrc);
  return sqxtun(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::sqrshrun2(VectorFormat vform, LogicVRegister dst,
                                    const LogicVRegister& src, int shift) {
  SimVRegister temp;
  VectorFormat vformsrc = VectorFormatDoubleWidth(VectorFormatHalfLanes(vform));
  VectorFormat vformdst = vform;
  LogicVRegister shifted_src = sshr(vformsrc, temp, src, shift).Round(vformsrc);
  return sqxtun(vformdst, dst, shifted_src);
}

LogicVRegister Simulator::uaddl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl(vform, temp1, src1);
  uxtl(vform, temp2, src2);
  add(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::uaddl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl2(vform, temp1, src1);
  uxtl2(vform, temp2, src2);
  add(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::uaddw(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp;
  uxtl(vform, temp, src2);
  add(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::uaddw2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  uxtl2(vform, temp, src2);
  add(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::saddl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl(vform, temp1, src1);
  sxtl(vform, temp2, src2);
  add(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::saddl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl2(vform, temp1, src1);
  sxtl2(vform, temp2, src2);
  add(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::saddw(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp;
  sxtl(vform, temp, src2);
  add(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::saddw2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  sxtl2(vform, temp, src2);
  add(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::usubl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl(vform, temp1, src1);
  uxtl(vform, temp2, src2);
  sub(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::usubl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl2(vform, temp1, src1);
  uxtl2(vform, temp2, src2);
  sub(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::usubw(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp;
  uxtl(vform, temp, src2);
  sub(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::usubw2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  uxtl2(vform, temp, src2);
  sub(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::ssubl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl(vform, temp1, src1);
  sxtl(vform, temp2, src2);
  sub(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::ssubl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl2(vform, temp1, src1);
  sxtl2(vform, temp2, src2);
  sub(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::ssubw(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp;
  sxtl(vform, temp, src2);
  sub(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::ssubw2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  sxtl2(vform, temp, src2);
  sub(vform, dst, src1, temp);
  return dst;
}

LogicVRegister Simulator::uabal(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl(vform, temp1, src1);
  uxtl(vform, temp2, src2);
  uaba(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::uabal2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl2(vform, temp1, src1);
  uxtl2(vform, temp2, src2);
  uaba(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::sabal(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl(vform, temp1, src1);
  sxtl(vform, temp2, src2);
  saba(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::sabal2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl2(vform, temp1, src1);
  sxtl2(vform, temp2, src2);
  saba(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::uabdl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl(vform, temp1, src1);
  uxtl(vform, temp2, src2);
  AbsDiff(vform, dst, temp1, temp2, false);
  return dst;
}

LogicVRegister Simulator::uabdl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl2(vform, temp1, src1);
  uxtl2(vform, temp2, src2);
  AbsDiff(vform, dst, temp1, temp2, false);
  return dst;
}

LogicVRegister Simulator::sabdl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl(vform, temp1, src1);
  sxtl(vform, temp2, src2);
  AbsDiff(vform, dst, temp1, temp2, true);
  return dst;
}

LogicVRegister Simulator::sabdl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl2(vform, temp1, src1);
  sxtl2(vform, temp2, src2);
  AbsDiff(vform, dst, temp1, temp2, true);
  return dst;
}

LogicVRegister Simulator::umull(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl(vform, temp1, src1);
  uxtl(vform, temp2, src2);
  mul(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::umull2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl2(vform, temp1, src1);
  uxtl2(vform, temp2, src2);
  mul(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::smull(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl(vform, temp1, src1);
  sxtl(vform, temp2, src2);
  mul(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::smull2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl2(vform, temp1, src1);
  sxtl2(vform, temp2, src2);
  mul(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::umlsl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl(vform, temp1, src1);
  uxtl(vform, temp2, src2);
  mls(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::umlsl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl2(vform, temp1, src1);
  uxtl2(vform, temp2, src2);
  mls(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::smlsl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl(vform, temp1, src1);
  sxtl(vform, temp2, src2);
  mls(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::smlsl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl2(vform, temp1, src1);
  sxtl2(vform, temp2, src2);
  mls(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::umlal(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl(vform, temp1, src1);
  uxtl(vform, temp2, src2);
  mla(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::umlal2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uxtl2(vform, temp1, src1);
  uxtl2(vform, temp2, src2);
  mla(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::smlal(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl(vform, temp1, src1);
  sxtl(vform, temp2, src2);
  mla(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::smlal2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  sxtl2(vform, temp1, src1);
  sxtl2(vform, temp2, src2);
  mla(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::sqdmlal(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  SimVRegister temp;
  LogicVRegister product = sqdmull(vform, temp, src1, src2);
  return add(vform, dst, dst, product).SignedSaturate(vform);
}

LogicVRegister Simulator::sqdmlal2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2) {
  SimVRegister temp;
  LogicVRegister product = sqdmull2(vform, temp, src1, src2);
  return add(vform, dst, dst, product).SignedSaturate(vform);
}

LogicVRegister Simulator::sqdmlsl(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  SimVRegister temp;
  LogicVRegister product = sqdmull(vform, temp, src1, src2);
  return sub(vform, dst, dst, product).SignedSaturate(vform);
}

LogicVRegister Simulator::sqdmlsl2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2) {
  SimVRegister temp;
  LogicVRegister product = sqdmull2(vform, temp, src1, src2);
  return sub(vform, dst, dst, product).SignedSaturate(vform);
}

LogicVRegister Simulator::sqdmull(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  SimVRegister temp;
  LogicVRegister product = smull(vform, temp, src1, src2);
  return add(vform, dst, product, product).SignedSaturate(vform);
}

LogicVRegister Simulator::sqdmull2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2) {
  SimVRegister temp;
  LogicVRegister product = smull2(vform, temp, src1, src2);
  return add(vform, dst, product, product).SignedSaturate(vform);
}

LogicVRegister Simulator::sqrdmulh(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, bool round) {
  // 2 * INT_32_MIN * INT_32_MIN causes int64_t to overflow.
  // To avoid this, we use (src1 * src2 + 1 << (esize - 2)) >> (esize - 1)
  // which is same as (2 * src1 * src2 + 1 << (esize - 1)) >> esize.

  int esize = LaneSizeInBitsFromFormat(vform);
  int round_const = round ? (1 << (esize - 2)) : 0;
  int64_t product;

  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    product = src1.Int(vform, i) * src2.Int(vform, i);
    product += round_const;
    product = product >> (esize - 1);

    if (product > MaxIntFromFormat(vform)) {
      product = MaxIntFromFormat(vform);
    } else if (product < MinIntFromFormat(vform)) {
      product = MinIntFromFormat(vform);
    }
    dst.SetInt(vform, i, product);
  }
  return dst;
}

LogicVRegister Simulator::sqdmulh(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  return sqrdmulh(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::addhn(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp;
  add(VectorFormatDoubleWidth(vform), temp, src1, src2);
  shrn(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::addhn2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  add(VectorFormatDoubleWidth(VectorFormatHalfLanes(vform)), temp, src1, src2);
  shrn2(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::raddhn(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  add(VectorFormatDoubleWidth(vform), temp, src1, src2);
  rshrn(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::raddhn2(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  SimVRegister temp;
  add(VectorFormatDoubleWidth(VectorFormatHalfLanes(vform)), temp, src1, src2);
  rshrn2(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::subhn(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp;
  sub(VectorFormatDoubleWidth(vform), temp, src1, src2);
  shrn(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::subhn2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  sub(VectorFormatDoubleWidth(VectorFormatHalfLanes(vform)), temp, src1, src2);
  shrn2(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::rsubhn(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  SimVRegister temp;
  sub(VectorFormatDoubleWidth(vform), temp, src1, src2);
  rshrn(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::rsubhn2(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  SimVRegister temp;
  sub(VectorFormatDoubleWidth(VectorFormatHalfLanes(vform)), temp, src1, src2);
  rshrn2(vform, dst, temp, LaneSizeInBitsFromFormat(vform));
  return dst;
}

LogicVRegister Simulator::trn1(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  int pairs = laneCount / 2;
  for (int i = 0; i < pairs; ++i) {
    result[2 * i] = src1.Uint(vform, 2 * i);
    result[(2 * i) + 1] = src2.Uint(vform, 2 * i);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::trn2(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  int pairs = laneCount / 2;
  for (int i = 0; i < pairs; ++i) {
    result[2 * i] = src1.Uint(vform, (2 * i) + 1);
    result[(2 * i) + 1] = src2.Uint(vform, (2 * i) + 1);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::zip1(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  int pairs = laneCount / 2;
  for (int i = 0; i < pairs; ++i) {
    result[2 * i] = src1.Uint(vform, i);
    result[(2 * i) + 1] = src2.Uint(vform, i);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::zip2(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  int pairs = laneCount / 2;
  for (int i = 0; i < pairs; ++i) {
    result[2 * i] = src1.Uint(vform, pairs + i);
    result[(2 * i) + 1] = src2.Uint(vform, pairs + i);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::uzp1(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  uint64_t result[32];
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; ++i) {
    result[i] = src1.Uint(vform, i);
    result[laneCount + i] = src2.Uint(vform, i);
  }

  dst.ClearForWrite(vform);
  for (int i = 0; i < laneCount; ++i) {
    dst.SetUint(vform, i, result[2 * i]);
  }
  return dst;
}

LogicVRegister Simulator::uzp2(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  uint64_t result[32];
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; ++i) {
    result[i] = src1.Uint(vform, i);
    result[laneCount + i] = src2.Uint(vform, i);
  }

  dst.ClearForWrite(vform);
  for (int i = 0; i < laneCount; ++i) {
    dst.SetUint(vform, i, result[(2 * i) + 1]);
  }
  return dst;
}

template <typename T>
T Simulator::FPAdd(T op1, T op2) {
  T result = FPProcessNaNs(op1, op2);
  if (std::isnan(result)) return result;

  if (std::isinf(op1) && std::isinf(op2) && (op1 != op2)) {
    // inf + -inf returns the default NaN.
    FPProcessException();
    return FPDefaultNaN<T>();
  } else {
    // Other cases should be handled by standard arithmetic.
    return op1 + op2;
  }
}

template <typename T>
T Simulator::FPSub(T op1, T op2) {
  // NaNs should be handled elsewhere.
  DCHECK(!std::isnan(op1) && !std::isnan(op2));

  if (std::isinf(op1) && std::isinf(op2) && (op1 == op2)) {
    // inf - inf returns the default NaN.
    FPProcessException();
    return FPDefaultNaN<T>();
  } else {
    // Other cases should be handled by standard arithmetic.
    return op1 - op2;
  }
}

template <typename T>
T Simulator::FPMul(T op1, T op2) {
  // NaNs should be handled elsewhere.
  DCHECK(!std::isnan(op1) && !std::isnan(op2));

  if ((std::isinf(op1) && (op2 == 0.0)) || (std::isinf(op2) && (op1 == 0.0))) {
    // inf * 0.0 returns the default NaN.
    FPProcessException();
    return FPDefaultNaN<T>();
  } else {
    // Other cases should be handled by standard arithmetic.
    return op1 * op2;
  }
}

template <typename T>
T Simulator::FPMulx(T op1, T op2) {
  if ((std::isinf(op1) && (op2 == 0.0)) || (std::isinf(op2) && (op1 == 0.0))) {
    // inf * 0.0 returns +/-2.0.
    T two = 2.0;
    return copysign(1.0, op1) * copysign(1.0, op2) * two;
  }
  return FPMul(op1, op2);
}

template <typename T>
T Simulator::FPMulAdd(T a, T op1, T op2) {
  T result = FPProcessNaNs3(a, op1, op2);

  T sign_a = copysign(1.0, a);
  T sign_prod = copysign(1.0, op1) * copysign(1.0, op2);
  bool isinf_prod = std::isinf(op1) || std::isinf(op2);
  bool operation_generates_nan =
      (std::isinf(op1) && (op2 == 0.0)) ||                     // inf * 0.0
      (std::isinf(op2) && (op1 == 0.0)) ||                     // 0.0 * inf
      (std::isinf(a) && isinf_prod && (sign_a != sign_prod));  // inf - inf

  if (std::isnan(result)) {
    // Generated NaNs override quiet NaNs propagated from a.
    if (operation_generates_nan && IsQuietNaN(a)) {
      FPProcessException();
      return FPDefaultNaN<T>();
    } else {
      return result;
    }
  }

  // If the operation would produce a NaN, return the default NaN.
  if (operation_generates_nan) {
    FPProcessException();
    return FPDefaultNaN<T>();
  }

  // Work around broken fma implementations for exact zero results: The sign of
  // exact 0.0 results is positive unless both a and op1 * op2 are negative.
  if (((op1 == 0.0) || (op2 == 0.0)) && (a == 0.0)) {
    return ((sign_a < 0) && (sign_prod < 0)) ? -0.0 : 0.0;
  }

  result = FusedMultiplyAdd(op1, op2, a);
  DCHECK(!std::isnan(result));

  // Work around broken fma implementations for rounded zero results: If a is
  // 0.0, the sign of the result is the sign of op1 * op2 before rounding.
  if ((a == 0.0) && (result == 0.0)) {
    return copysign(0.0, sign_prod);
  }

  return result;
}

template <typename T>
T Simulator::FPDiv(T op1, T op2) {
  // NaNs should be handled elsewhere.
  DCHECK(!std::isnan(op1) && !std::isnan(op2));

  if ((std::isinf(op1) && std::isinf(op2)) || ((op1 == 0.0) && (op2 == 0.0))) {
    // inf / inf and 0.0 / 0.0 return the default NaN.
    FPProcessException();
    return FPDefaultNaN<T>();
  } else {
    if (op2 == 0.0) {
      FPProcessException();
      if (!std::isnan(op1)) {
        double op1_sign = copysign(1.0, op1);
        double op2_sign = copysign(1.0, op2);
        return static_cast<T>(op1_sign * op2_sign * kFP64PositiveInfinity);
      }
    }

    // Other cases should be handled by standard arithmetic.
    return op1 / op2;
  }
}

template <typename T>
T Simulator::FPSqrt(T op) {
  if (std::isnan(op)) {
    return FPProcessNaN(op);
  } else if (op < 0.0) {
    FPProcessException();
    return FPDefaultNaN<T>();
  } else {
    return std::sqrt(op);
  }
}

template <typename T>
T Simulator::FPMax(T a, T b) {
  T result = FPProcessNaNs(a, b);
  if (std::isnan(result)) return result;

  if ((a == 0.0) && (b == 0.0) && (copysign(1.0, a) != copysign(1.0, b))) {
    // a and b are zero, and the sign differs: return +0.0.
    return 0.0;
  } else {
    return (a > b) ? a : b;
  }
}

template <typename T>
T Simulator::FPMaxNM(T a, T b) {
  if (IsQuietNaN(a) && !IsQuietNaN(b)) {
    a = kFP64NegativeInfinity;
  } else if (!IsQuietNaN(a) && IsQuietNaN(b)) {
    b = kFP64NegativeInfinity;
  }

  T result = FPProcessNaNs(a, b);
  return std::isnan(result) ? result : FPMax(a, b);
}

template <typename T>
T Simulator::FPMin(T a, T b) {
  T result = FPProcessNaNs(a, b);
  if (std::isnan(result)) return result;

  if ((a == 0.0) && (b == 0.0) && (copysign(1.0, a) != copysign(1.0, b))) {
    // a and b are zero, and the sign differs: return -0.0.
    return -0.0;
  } else {
    return (a < b) ? a : b;
  }
}

template <typename T>
T Simulator::FPMinNM(T a, T b) {
  if (IsQuietNaN(a) && !IsQuietNaN(b)) {
    a = kFP64PositiveInfinity;
  } else if (!IsQuietNaN(a) && IsQuietNaN(b)) {
    b = kFP64PositiveInfinity;
  }

  T result = FPProcessNaNs(a, b);
  return std::isnan(result) ? result : FPMin(a, b);
}

template <typename T>
T Simulator::FPRecipStepFused(T op1, T op2) {
  const T two = 2.0;
  if ((std::isinf(op1) && (op2 == 0.0)) ||
      ((op1 == 0.0) && (std::isinf(op2)))) {
    return two;
  } else if (std::isinf(op1) || std::isinf(op2)) {
    // Return +inf if signs match, otherwise -inf.
    return ((op1 >= 0.0) == (op2 >= 0.0)) ? kFP64PositiveInfinity
                                          : kFP64NegativeInfinity;
  } else {
    return FusedMultiplyAdd(op1, op2, two);
  }
}

template <typename T>
T Simulator::FPRSqrtStepFused(T op1, T op2) {
  const T one_point_five = 1.5;
  const T two = 2.0;

  if ((std::isinf(op1) && (op2 == 0.0)) ||
      ((op1 == 0.0) && (std::isinf(op2)))) {
    return one_point_five;
  } else if (std::isinf(op1) || std::isinf(op2)) {
    // Return +inf if signs match, otherwise -inf.
    return ((op1 >= 0.0) == (op2 >= 0.0)) ? kFP64PositiveInfinity
                                          : kFP64NegativeInfinity;
  } else {
    // The multiply-add-halve operation must be fully fused, so avoid interim
    // rounding by checking which operand can be losslessly divided by two
    // before doing the multiply-add.
    if (isnormal(op1 / two)) {
      return FusedMultiplyAdd(op1 / two, op2, one_point_five);
    } else if (isnormal(op2 / two)) {
      return FusedMultiplyAdd(op1, op2 / two, one_point_five);
    } else {
      // Neither operand is normal after halving: the result is dominated by
      // the addition term, so just return that.
      return one_point_five;
    }
  }
}

double Simulator::FPRoundInt(double value, FPRounding round_mode) {
  if ((value == 0.0) || (value == kFP64PositiveInfinity) ||
      (value == kFP64NegativeInfinity)) {
    return value;
  } else if (std::isnan(value)) {
    return FPProcessNaN(value);
  }

  double int_result = std::floor(value);
  double error = value - int_result;
  switch (round_mode) {
    case FPTieAway: {
      // Take care of correctly handling the range ]-0.5, -0.0], which must
      // yield -0.0.
      if ((-0.5 < value) && (value < 0.0)) {
        int_result = -0.0;

      } else if ((error > 0.5) || ((error == 0.5) && (int_result >= 0.0))) {
        // If the error is greater than 0.5, or is equal to 0.5 and the integer
        // result is positive, round up.
        int_result++;
      }
      break;
    }
    case FPTieEven: {
      // Take care of correctly handling the range [-0.5, -0.0], which must
      // yield -0.0.
      if ((-0.5 <= value) && (value < 0.0)) {
        int_result = -0.0;

        // If the error is greater than 0.5, or is equal to 0.5 and the integer
        // result is odd, round up.
      } else if ((error > 0.5) ||
                 ((error == 0.5) && (std::fmod(int_result, 2) != 0))) {
        int_result++;
      }
      break;
    }
    case FPZero: {
      // If value>0 then we take floor(value)
      // otherwise, ceil(value).
      if (value < 0) {
        int_result = ceil(value);
      }
      break;
    }
    case FPNegativeInfinity: {
      // We always use floor(value).
      break;
    }
    case FPPositiveInfinity: {
      // Take care of correctly handling the range ]-1.0, -0.0], which must
      // yield -0.0.
      if ((-1.0 < value) && (value < 0.0)) {
        int_result = -0.0;

        // If the error is non-zero, round up.
      } else if (error > 0.0) {
        int_result++;
      }
      break;
    }
    default:
      UNIMPLEMENTED();
  }
  return int_result;
}

int16_t Simulator::FPToInt16(double value, FPRounding rmode) {
  value = FPRoundInt(value, rmode);
  return base::saturated_cast<int16_t>(value);
}

int32_t Simulator::FPToInt32(double value, FPRounding rmode) {
  value = FPRoundInt(value, rmode);
  return base::saturated_cast<int32_t>(value);
}

int64_t Simulator::FPToInt64(double value, FPRounding rmode) {
  value = FPRoundInt(value, rmode);
  return base::saturated_cast<int64_t>(value);
}

uint16_t Simulator::FPToUInt16(double value, FPRounding rmode) {
  value = FPRoundInt(value, rmode);
  return base::saturated_cast<uint16_t>(value);
}

uint32_t Simulator::FPToUInt32(double value, FPRounding rmode) {
  value = FPRoundInt(value, rmode);
  return base::saturated_cast<uint32_t>(value);
}

uint64_t Simulator::FPToUInt64(double value, FPRounding rmode) {
  value = FPRoundInt(value, rmode);
  return base::saturated_cast<uint64_t>(value);
}

#define DEFINE_NEON_FP_VECTOR_OP(FN, OP, PROCNAN)                      \
  template <typename T>                                                \
  LogicVRegister Simulator::FN(VectorFormat vform, LogicVRegister dst, \
                               const LogicVRegister& src1,             \
                               const LogicVRegister& src2) {           \
    dst.ClearForWrite(vform);                                          \
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {             \
      T op1 = src1.Float<T>(i);                                        \
      T op2 = src2.Float<T>(i);                                        \
      T result;                                                        \
      if (PROCNAN) {                                                   \
        result = FPProcessNaNs(op1, op2);                              \
        if (!isnan(result)) {                                          \
          result = OP(op1, op2);                                       \
        }                                                              \
      } else {                                                         \
        result = OP(op1, op2);                                         \
      }                                                                \
      dst.SetFloat(i, result);                                         \
    }                                                                  \
    return dst;                                                        \
  }                                                                    \
                                                                       \
  LogicVRegister Simulator::FN(VectorFormat vform, LogicVRegister dst, \
                               const LogicVRegister& src1,             \
                               const LogicVRegister& src2) {           \
    if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {               \
      FN<half>(vform, dst, src1, src2);                                \
    } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {        \
      FN<float>(vform, dst, src1, src2);                               \
    } else {                                                           \
      DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);          \
      FN<double>(vform, dst, src1, src2);                              \
    }                                                                  \
    return dst;                                                        \
  }
NEON_FP3SAME_LIST(DEFINE_NEON_FP_VECTOR_OP)
#undef DEFINE_NEON_FP_VECTOR_OP

LogicVRegister Simulator::fnmul(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  SimVRegister temp;
  LogicVRegister product = fmul(vform, temp, src1, src2);
  return fneg(vform, dst, product);
}

template <typename T>
LogicVRegister Simulator::frecps(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    T op1 = -src1.Float<T>(i);
    T op2 = src2.Float<T>(i);
    T result = FPProcessNaNs(op1, op2);
    dst.SetFloat(i, isnan(result) ? result : FPRecipStepFused(op1, op2));
  }
  return dst;
}

LogicVRegister Simulator::frecps(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    frecps<half>(vform, dst, src1, src2);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    frecps<float>(vform, dst, src1, src2);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    frecps<double>(vform, dst, src1, src2);
  }
  return dst;
}

template <typename T>
LogicVRegister Simulator::frsqrts(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    T op1 = -src1.Float<T>(i);
    T op2 = src2.Float<T>(i);
    T result = FPProcessNaNs(op1, op2);
    dst.SetFloat(i, std::isnan(result) ? result : FPRSqrtStepFused(op1, op2));
  }
  return dst;
}

int32_t Simulator::FPToFixedJS(double value) {
  // The Z-flag is set when the conversion from double precision floating-point
  // to 32-bit integer is exact. If the source value is +/-Infinity, -0.0, NaN,
  // outside the bounds of a 32-bit integer, or isn't an exact integer then the
  // Z-flag is unset.
  int Z = 1;
  int32_t result;
  if ((value == 0.0) || (value == kFP64PositiveInfinity) ||
      (value == kFP64NegativeInfinity)) {
    // +/- zero and infinity all return zero, however -0 and +/- Infinity also
    // unset the Z-flag.
    result = 0.0;
    if ((value != 0.0) || std::signbit(value)) {
      Z = 0;
    }
  } else if (std::isnan(value)) {
    // NaN values unset the Z-flag and set the result to 0.
    result = 0;
    Z = 0;
  } else {
    // All other values are converted to an integer representation, rounded
    // toward zero.
    double int_result = std::floor(value);
    double error = value - int_result;
    if ((error != 0.0) && (int_result < 0.0)) {
      int_result++;
    }
    // Constrain the value into the range [INT32_MIN, INT32_MAX]. We can almost
    // write a one-liner with std::round, but the behaviour on ties is incorrect
    // for our purposes.
    double mod_const = static_cast<double>(UINT64_C(1) << 32);
    double mod_error =
        (int_result / mod_const) - std::floor(int_result / mod_const);
    double constrained;
    if (mod_error == 0.5) {
      constrained = INT32_MIN;
    } else {
      constrained = int_result - mod_const * round(int_result / mod_const);
    }
    DCHECK(std::floor(constrained) == constrained);
    DCHECK(constrained >= INT32_MIN);
    DCHECK(constrained <= INT32_MAX);
    // Take the bottom 32 bits of the result as a 32-bit integer.
    result = static_cast<int32_t>(constrained);
    if ((int_result < INT32_MIN) || (int_result > INT32_MAX) ||
        (error != 0.0)) {
      // If the integer result is out of range or the conversion isn't exact,
      // take exception and unset the Z-flag.
      FPProcessException();
      Z = 0;
    }
  }
  nzcv().SetN(0);
  nzcv().SetZ(Z);
  nzcv().SetC(0);
  nzcv().SetV(0);
  return result;
}

LogicVRegister Simulator::frsqrts(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    frsqrts<half>(vform, dst, src1, src2);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    frsqrts<float>(vform, dst, src1, src2);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    frsqrts<double>(vform, dst, src1, src2);
  }
  return dst;
}

template <typename T>
LogicVRegister Simulator::fcmp(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2, Condition cond) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    bool result = false;
    T op1 = src1.Float<T>(i);
    T op2 = src2.Float<T>(i);
    T nan_result = FPProcessNaNs(op1, op2);
    if (!std::isnan(nan_result)) {
      switch (cond) {
        case eq:
          result = (op1 == op2);
          break;
        case ge:
          result = (op1 >= op2);
          break;
        case gt:
          result = (op1 > op2);
          break;
        case le:
          result = (op1 <= op2);
          break;
        case lt:
          result = (op1 < op2);
          break;
        default:
          UNREACHABLE();
      }
    }
    dst.SetUint(vform, i, result ? MaxUintFromFormat(vform) : 0);
  }
  return dst;
}

LogicVRegister Simulator::fcmp(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2, Condition cond) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    fcmp<half>(vform, dst, src1, src2, cond);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    fcmp<float>(vform, dst, src1, src2, cond);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    fcmp<double>(vform, dst, src1, src2, cond);
  }
  return dst;
}

LogicVRegister Simulator::fcmp_zero(VectorFormat vform, LogicVRegister dst,
                                    const LogicVRegister& src, Condition cond) {
  SimVRegister temp;
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    LogicVRegister zero_reg = dup_immediate(vform, temp, uint16_t{0});
    fcmp<half>(vform, dst, src, zero_reg, cond);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    LogicVRegister zero_reg = dup_immediate(vform, temp, uint32_t{0});
    fcmp<float>(vform, dst, src, zero_reg, cond);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    LogicVRegister zero_reg = dup_immediate(vform, temp, uint64_t{0});
    fcmp<double>(vform, dst, src, zero_reg, cond);
  }
  return dst;
}

LogicVRegister Simulator::fabscmp(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, Condition cond) {
  SimVRegister temp1, temp2;
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    LogicVRegister abs_src1 = fabs_<half>(vform, temp1, src1);
    LogicVRegister abs_src2 = fabs_<half>(vform, temp2, src2);
    fcmp<half>(vform, dst, abs_src1, abs_src2, cond);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    LogicVRegister abs_src1 = fabs_<float>(vform, temp1, src1);
    LogicVRegister abs_src2 = fabs_<float>(vform, temp2, src2);
    fcmp<float>(vform, dst, abs_src1, abs_src2, cond);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    LogicVRegister abs_src1 = fabs_<double>(vform, temp1, src1);
    LogicVRegister abs_src2 = fabs_<double>(vform, temp2, src2);
    fcmp<double>(vform, dst, abs_src1, abs_src2, cond);
  }
  return dst;
}

template <typename T>
LogicVRegister Simulator::fmla(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    T op1 = src1.Float<T>(i);
    T op2 = src2.Float<T>(i);
    T acc = dst.Float<T>(i);
    T result = FPMulAdd(acc, op1, op2);
    dst.SetFloat(i, result);
  }
  return dst;
}

LogicVRegister Simulator::fmla(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    fmla<half>(vform, dst, src1, src2);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    fmla<float>(vform, dst, src1, src2);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    fmla<double>(vform, dst, src1, src2);
  }
  return dst;
}

template <typename T>
LogicVRegister Simulator::fmls(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    T op1 = -src1.Float<T>(i);
    T op2 = src2.Float<T>(i);
    T acc = dst.Float<T>(i);
    T result = FPMulAdd(acc, op1, op2);
    dst.SetFloat(i, result);
  }
  return dst;
}

LogicVRegister Simulator::fmls(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    fmls<half>(vform, dst, src1, src2);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    fmls<float>(vform, dst, src1, src2);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    fmls<double>(vform, dst, src1, src2);
  }
  return dst;
}

template <typename T>
LogicVRegister Simulator::fneg(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    T op = src.Float<T>(i);
    op = -op;
    dst.SetFloat(i, op);
  }
  return dst;
}

LogicVRegister Simulator::fneg(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    fneg<half>(vform, dst, src);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    fneg<float>(vform, dst, src);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    fneg<double>(vform, dst, src);
  }
  return dst;
}

template <typename T>
LogicVRegister Simulator::fabs_(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    T op = src.Float<T>(i);
    if (copysign(1.0, op) < 0.0) {
      op = -op;
    }
    dst.SetFloat(i, op);
  }
  return dst;
}

LogicVRegister Simulator::fabs_(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    fabs_<half>(vform, dst, src);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    fabs_<float>(vform, dst, src);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    fabs_<double>(vform, dst, src);
  }
  return dst;
}

LogicVRegister Simulator::fabd(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  SimVRegister temp;
  fsub(vform, temp, src1, src2);
  fabs_(vform, dst, temp);
  return dst;
}

LogicVRegister Simulator::fsqrt(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      half result = FPSqrt(src.Float<half>(i));
      dst.SetFloat(i, result);
    }
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      float result = FPSqrt(src.Float<float>(i));
      dst.SetFloat(i, result);
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      double result = FPSqrt(src.Float<double>(i));
      dst.SetFloat(i, result);
    }
  }
  return dst;
}

#define DEFINE_NEON_FP_PAIR_OP(FNP, FN, OP)                             \
  LogicVRegister Simulator::FNP(VectorFormat vform, LogicVRegister dst, \
                                const LogicVRegister& src1,             \
                                const LogicVRegister& src2) {           \
    SimVRegister temp1, temp2;                                          \
    uzp1(vform, temp1, src1, src2);                                     \
    uzp2(vform, temp2, src1, src2);                                     \
    FN(vform, dst, temp1, temp2);                                       \
    return dst;                                                         \
  }                                                                     \
```