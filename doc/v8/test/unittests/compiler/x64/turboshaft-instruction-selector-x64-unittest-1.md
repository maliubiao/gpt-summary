Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a unit test file for the Turboshaft instruction selector for the x64 architecture in the V8 JavaScript engine.

Here's a plan to generate the response:

1. **Identify the core purpose:** The file tests the correct selection of x64 instructions for various operations in the Turboshaft compiler.
2. **Analyze individual test cases:** Group the test cases by the type of operation they are testing (e.g., arithmetic, shifts, bitwise operations, SIMD).
3. **Explain the testing methodology:** The tests use `StreamBuilder` to create a sequence of operations and `Stream` to represent the selected instructions. `ASSERT_EQ` and `EXPECT_EQ` are used for verifying the correctness of the selected instructions.
4. **Address specific instructions:** If certain instructions are frequently tested or have specific optimizations, mention them (e.g., `kX64Movzxbl`, `kX64SZero`).
5. **Check for Torque usage:** The filename doesn't end with `.tq`, so it's not a Torque file.
6. **Relate to JavaScript:** Explain how the tested operations map to JavaScript functionality.
7. **Provide example with JavaScript:**  Demonstrate a simple JavaScript snippet that would involve some of the tested operations.
8. **Give an example of code logic reasoning:** Create a simplified test case with assumed inputs and outputs.
9. **Illustrate common programming errors:** Show a common mistake related to the tested operations.
10. **Summarize the functionality:**  Provide a concise summary of the file's purpose.
这是第三部分，总结一下`v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc` 的功能：

**总体功能归纳：**

这个C++代码文件是V8 JavaScript引擎中Turboshaft编译器的一部分，专门用于测试在x64架构下，指令选择器是否能够为各种中间表示（IR）操作选择正确的x64汇编指令。

**具体功能点：**

* **浮点运算测试 (第1部分和第2部分，延续到此部分):**
    * 测试 `Float64Add`, `Float64Sub`, `Float64Mul` 等浮点运算操作，并验证是否根据目标架构（SSE或AVX）选择了正确的指令 (`kSSEFloat64Add`, `kAVXFloat64Add` 等)。
    * 测试涉及从内存加载浮点数的情况。

* **位操作和类型转换测试:**
    * 测试各种位移操作 (`Word64ShiftLeft`, `Word64ShiftRightLogical`, `Word64ShiftRightArithmetic`)，并验证是否选择了正确的指令 (`kX64Shl`, `kX64Movl`, `kX64Movsxlq`)。
    * 测试了类型转换操作 (`ChangeInt32ToInt64`, `ChangeUint32ToUint64`, `TruncateWord64ToWord32`) 对指令选择的影响。
    * 测试了位与操作 (`Word32BitwiseAnd`, `Word64BitwiseAnd`)，并验证是否针对特定常量值进行了优化，选择了更高效的指令 (`kX64Movzxbl`, `kX64Movl`, `kX64Movzxwq`, `kX64Movzxbq`, `kX64And32`, `kX64And`)。
    * 测试了计算前导零的指令 (`Word32CountLeadingZeros`，对应 `kX64Lzcnt32`)。

* **加载和位移组合优化:**
    * 测试了加载 64 位数据后进行右移 32 位的操作，并验证是否优化成了直接加载低 32 位的指令 (`kX64Movl`, `kX64Movsxlq`)。

* **SIMD 指令测试 (仅在 `V8_ENABLE_WEBASSEMBLY` 宏定义启用时):**
    * 测试了 SIMD (Single Instruction, Multiple Data) 向量操作的指令选择。
    * 测试了 `Splat` 操作，特别是针对常量 0 的优化，使用了 `kX64SZero` 指令。
    * 测试了各种 SIMD shuffle 指令，包括架构特定的 shuffle (`kX64S64x2UnpackLow` 等) 和通用 shuffle (`kX64I8x16Shuffle`)，以及各种优化匹配模式 (`TryMatchConcat`, `TryMatch32x4Rotate`, `TryMatchBlend` 等)。
    * 测试了 SIMD shuffle 操作与零输入结合的优化 (`kX64I32X4ShiftZeroExtendI8x16`)。
    * 测试了 SIMD swizzle 操作，特别是使用常量索引的情况。
    * 测试了 SIMD 类型转换和加载操作的组合 (`F64x2PromoteLowF32x4WithS128Load64Zero`)。
    * 测试了 SIMD 类型转换优化 (`F32x4SConvert`)。

**关于是否为 Torque 代码：**

根据您的描述，`v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc`  **不以 `.tq` 结尾**，因此它不是一个 V8 Torque 源代码文件，而是一个标准的 C++ 文件。

**与 JavaScript 的功能关系：**

这些测试覆盖了 JavaScript 中常见的数值运算、类型转换和位操作等功能，特别是在执行 WebAssembly 代码时，SIMD 指令会被大量使用。

**JavaScript 示例：**

```javascript
// 浮点运算
let a = 1.5;
let b = 2.5;
let sum = a + b;
let diff = a - b;
let product = a * b;

// 位操作
let num1 = 10; // 二进制 1010
let num2 = 3;  // 二进制 0011
let andResult = num1 & num2; // 位与
let leftShift = num1 << 2;   // 左移

// 类型转换 (在引擎内部可能涉及)
let intValue = 10;
let bigIntValue = BigInt(intValue);
let floatValue = parseFloat(intValue);

// SIMD (WebAssembly)
// 假设有 wasm 模块使用了 SIMD
// const simdArray = new Float32x4Array([1, 2, 3, 4]);
// const splatZero = Float32x4.splat(0);
// const shuffled = simdArray.shuffle([0, 0, 1, 1]);
```

**代码逻辑推理示例：**

假设输入：

* `p0` (参数 0): 浮点数 3.0
* `p1` (参数 1): 指向内存地址 X 的指针，该地址存储浮点数 1.0
* `p2` (参数 2): 指向内存地址 Y 的指针，该地址存储浮点数 2.0

对应的代码片段：

```c++
{
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const p2 = m.Parameter(2);
  OpIndex add = m.Float64Add(p0, m.Load(MachineType::Float64(), p1));
  OpIndex sub = m.Float64Sub(add, m.Load(MachineType::Float64(), p1));
  OpIndex ret = m.Float64Mul(m.Load(MachineType::Float64(), p2), sub);
  m.Return(ret);
  Stream s = m.Build();
  // ... assertions ...
}
```

推理过程：

1. `add` 操作会计算 `p0` (3.0) 加上从 `p1` 指向的内存加载的值 (1.0)，结果为 4.0。
2. `sub` 操作会计算 `add` 的结果 (4.0) 减去从 `p1` 指向的内存加载的值 (1.0)，结果为 3.0。
3. `ret` 操作会计算从 `p2` 指向的内存加载的值 (2.0) 乘以 `sub` 的结果 (3.0)，结果为 6.0。

预期输出：最终返回值为 6.0。同时，测试会验证选择了正确的 x64 浮点运算指令。

**用户常见的编程错误示例：**

```javascript
// 错误的位运算：期望左移，却使用了右移
let value = 5; // 二进制 0101
let result = value >> 2; // 错误地使用了右移，结果为 1，期望的是左移

// 类型转换错误：将字符串直接用于数值运算
let strValue = "10";
let numValue = 5;
let sum = strValue + numValue; // 错误：字符串拼接，结果为 "105"，而不是数值加法

// SIMD 使用错误 (WebAssembly)：shuffle mask 超出范围
// const simdArray = new Float32x4Array([1, 2, 3, 4]);
// const shuffled = simdArray.shuffle([0, 1, 2, 16]); // 错误：索引 16 超出了数组范围
```

这些错误在编译或运行时可能导致非预期的结果，指令选择器的正确性对于确保这些操作按照预期执行至关重要。

总而言之，这个测试文件是 V8 引擎质量保证的关键部分，它确保了 Turboshaft 编译器能够针对 x64 架构生成正确且高效的机器码，涵盖了基础的数值运算到更高级的 SIMD 操作。

### 提示词
```
这是目录为v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float64Sub(
        add, m.Load(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float64Mul(
        m.Load(MachineType::Float64(), p2, m.Int64Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build(AVX);
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kAVXFloat64Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kAVXFloat64Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kAVXFloat64Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float64Add(
        p0, m.Load(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float64Sub(
        add, m.Load(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float64Mul(
        m.Load(MachineType::Float64(), p2, m.Int64Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kSSEFloat64Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kSSEFloat64Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kSSEFloat64Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
}

// -----------------------------------------------------------------------------
// Miscellaneous.

TEST_F(TurboshaftInstructionSelectorTest,
       Word64ShiftLeftWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeInt32ToInt64(p0), m.Int32Constant(x));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Shl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(x, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word64ShiftLeftWithChangeUint32ToUint64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Uint32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeUint32ToUint64(p0), m.Int32Constant(x));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Shl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(x, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32BitwiseAndWith0xFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word32BitwiseAnd(p0, m.Int32Constant(0xFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxbl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWith0xFFFFFFFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0xFFFFFFFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0xFFFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxwq, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWith0xFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0xFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxbq, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWithInt64FitsUint32) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(15));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64And32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word64BitwiseAndWithInt64DontFitsUint32) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0x100000000));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64And, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32BitwiseAndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word32BitwiseAnd(p0, m.Int32Constant(0xFFFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxwl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Word32CountLeadingZeros(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lzcnt32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAndWord64ShiftRight32) {
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const load = m.Load(MachineType::Uint64(), p0);
    OpIndex const shift = m.Word64ShiftRightLogical(load, m.Int32Constant(32));
    m.Return(shift);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(4, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(shift), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const load = m.Load(MachineType::Int64(), p0);
    OpIndex const shift =
        m.Word64ShiftRightArithmetic(load, m.Int32Constant(32));
    m.Return(shift);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movsxlq, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(4, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(shift), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const load = m.Load(MachineType::Int64(), p0);
    OpIndex const shift =
        m.Word64ShiftRightArithmetic(load, m.Int32Constant(32));
    OpIndex const truncate = m.TruncateWord64ToWord32(shift);
    m.Return(truncate);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(4, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(shift), s.ToVreg(s[0]->Output()));
  }
}

#if V8_ENABLE_WEBASSEMBLY
// -----------------------------------------------------------------------------
// SIMD.

TEST_F(TurboshaftInstructionSelectorTest, SIMDSplatZero) {
  // Test optimization for splat of contant 0.
  // {i8x16,i16x8,i32x4,i64x2}.splat(const(0)) -> v128.zero().
  // Optimizations for f32x4.splat and f64x2.splat not implemented since it
  // doesn't improve the codegen as much (same number of instructions).
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I64x2Splat(m.Int64Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I32x4Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I16x8Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I8x16Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

struct ArchShuffle {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode arch_opcode;
  size_t input_count;
};

static constexpr ArchShuffle kArchShuffles[] = {
    // These are architecture specific shuffles defined in
    // instruction-selecor-x64.cc arch_shuffles.
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23},
        kX64S64x2UnpackLow,
        2,
    },
    {
        {8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31},
        kX64S64x2UnpackHigh,
        2,
    },
    {
        {0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
        kX64S32x4UnpackLow,
        2,
    },
    {
        {8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
        kX64S32x4UnpackHigh,
        2,
    },
    {
        {0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
        kX64S16x8UnpackLow,
        2,
    },
    {
        {8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
        kX64S16x8UnpackHigh,
        2,
    },
    {
        {0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
        kX64S8x16UnpackLow,
        2,
    },
    {
        {8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
        kX64S8x16UnpackHigh,
        2,
    },
    {
        {0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
        kX64S16x8UnzipLow,
        2,
    },
    {
        {2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
        kX64S16x8UnzipHigh,
        2,
    },
    {
        {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
        kX64S8x16UnzipLow,
        2,
    },
    {
        {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
        kX64S8x16UnzipHigh,
        2,
    },
    {
        {0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
        kX64S8x16TransposeLow,
        2,
    },
    {
        {1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
        kX64S8x16TransposeHigh,
        2,
    },
    {
        {7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
        kX64S8x8Reverse,
        1,
    },
    {
        {3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
        kX64S8x4Reverse,
        1,
    },
    {
        {1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
        kX64S8x2Reverse,
        1,
    },
    // These are matched by TryMatchConcat && TryMatch32x4Rotate.
    {
        {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3},
        kX64S32x4Rotate,
        2,
    },
    {
        {8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7},
        kX64S32x4Rotate,
        2,
    },
    {
        {12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
        kX64S32x4Rotate,
        2,
    },
    // These are matched by TryMatchConcat && !TryMatch32x4Rotate.
    {
        {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2},
        kX64S8x16Alignr,
        3,
    },
    {
        {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1},
        kX64S8x16Alignr,
        3,
    },
    {
        {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
        kX64S8x16Alignr,
        3,
    },
    // These are matched by TryMatch32x4Shuffle && is_swizzle.
    {
        {0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15},
        kX64S32x4Swizzle,
        2,
    },
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 8, 9, 10, 11},
        kX64S32x4Swizzle,
        2,
    },
    // These are matched by TryMatch32x4Shuffle && !is_swizzle && TryMatchBlend.
    {
        {0, 1, 2, 3, 20, 21, 22, 23, 8, 9, 10, 11, 28, 29, 30, 31},
        kX64S16x8Blend,
        3,
    },
    {
        {16, 17, 18, 19, 4, 5, 6, 7, 24, 25, 26, 27, 12, 13, 14, 15},
        kX64S16x8Blend,
        3,
    },
    // These are matched by TryMatch32x4Shuffle && !is_swizzle &&
    // TryMatchShufps.
    {
        {0, 1, 2, 3, 8, 9, 10, 11, 28, 29, 30, 31, 28, 29, 30, 31},
        kX64Shufps,
        3,
    },
    {
        {8, 9, 10, 11, 0, 1, 2, 3, 28, 29, 30, 31, 28, 29, 30, 31},
        kX64Shufps,
        3,
    },
    // These are matched by TryMatch32x4Shuffle && !is_swizzle.
    {
        {28, 29, 30, 31, 0, 1, 2, 3, 28, 29, 30, 31, 28, 29, 30, 31},
        kX64S32x4Shuffle,
        4,
    },
    // These are matched by TryMatch16x8Shuffle && TryMatchBlend.
    {
        {16, 17, 2, 3, 4, 5, 6, 7, 24, 25, 26, 27, 12, 13, 14, 15},
        kX64S16x8Blend,
        3,
    },
    // These are matched by TryMatch16x8Shuffle && TryMatchSplat<8>.
    {
        {2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3},
        kX64S16x8Dup,
        2,
    },
    // These are matched by TryMatch16x8Shuffle && TryMatch16x8HalfShuffle.
    {
        {6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
        kX64S16x8HalfShuffle1,
        3,
    },
    {
        {6, 7, 4, 5, 2, 3, 0, 1, 30, 31, 28, 29, 26, 27, 24, 25},
        kX64S16x8HalfShuffle2,
        5,
    },
    // These are matched by TryMatchSplat<16>.
    {
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        kX64S8x16Dup,
        2,
    },
    // Generic shuffle that only uses 1 input.
    {
        {1, 15, 2, 14, 3, 13, 4, 12, 5, 11, 6, 10, 7, 9, 8},
        kX64I8x16Shuffle,
        5,
    },
    // Generic shuffle that uses both input.
    {
        {1, 31, 2, 14, 3, 13, 4, 12, 5, 11, 6, 10, 7, 9, 8},
        kX64I8x16Shuffle,
        6,
    },
};

using TurboshaftInstructionSelectorSIMDArchShuffleTest =
    TurboshaftInstructionSelectorTestWithParam<ArchShuffle>;

TEST_P(TurboshaftInstructionSelectorSIMDArchShuffleTest, SIMDArchShuffle) {
  MachineType type = MachineType::Simd128();
  {
    // Tests various shuffle optimizations
    StreamBuilder m(this, type, type, type);
    auto param = GetParam();
    OpIndex n = m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), param.shuffle);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDArchShuffleTest,
                         ::testing::ValuesIn(kArchShuffles));

// TODO(dmercadier): port to Turboshaft once Turboshaft supports Simd256
// shuffles.
#if 0

struct ArchShuffle256 {
  uint8_t shuffle[kSimd256Size];
  ArchOpcode arch_opcode;
  size_t input_count;
};

static constexpr ArchShuffle256 kArchShuffles256[] = {
    {{4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 0,  1,  2,  3,
      20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19},
     kX64Vpshufd,
     2}};

using TurboshaftInstructionSelectorSIMDArchShuffle256Test =
    TurboshaftInstructionSelectorTestWithParam<ArchShuffle256>;

TEST_P(TurboshaftInstructionSelectorSIMDArchShuffle256Test,
       SIMDArchShuffle256) {
  MachineType type = MachineType::Simd128();
  {
    // Tests various shuffle optimizations
    StreamBuilder m(this, type, type, type);
    auto param = GetParam();
    auto shuffle = param.shuffle;
    const Operator* op = m.machine()->I8x32Shuffle(shuffle);
    OpIndex n = m.AddNode(op, m.Parameter(0), m.Parameter(1));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDArchShuffle256Test,
                         ::testing::ValuesIn(kArchShuffles256));

#endif

struct ShuffleWithZeroInput {
  uint8_t shuffle_mask[kSimd128Size];
  ArchOpcode arch_opcode;
  size_t input_count;
};

static constexpr ShuffleWithZeroInput kShuffleWithZeroInput[] = {
    // These are matched by TryMatchByteToDwordZeroExtend.
    {
        {16, 1, 2, 3, 17, 4, 5, 6, 18, 7, 8, 9, 19, 10, 11, 12},
        kX64I32X4ShiftZeroExtendI8x16,
        2,
    },
    // Generic shuffle that uses one zero input.
    {
        {16, 1, 2, 3, 17, 4, 5, 6, 18, 7, 8, 9, 19, 20, 21, 22},
        kX64I8x16Shuffle,
        5,
    },
};

using TurboshaftInstructionSelectorSIMDShuffleWithZeroInputTest =
    TurboshaftInstructionSelectorTestWithParam<ShuffleWithZeroInput>;

TEST_P(TurboshaftInstructionSelectorSIMDShuffleWithZeroInputTest,
       SIMDShuffleWithZeroInputTest) {
  MachineType type = MachineType::Simd128();
  {
    // Tests shuffle to packed zero extend optimization
    uint8_t zeros[kSimd128Size] = {0};
    StreamBuilder m(this, type, type);
    auto param = GetParam();
    OpIndex const c = m.Simd128Constant(zeros);
    OpIndex n = m.Simd128Shuffle(c, m.Parameter(0), param.shuffle_mask);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorSIMDShuffleWithZeroInputTest,
    ::testing::ValuesIn(kShuffleWithZeroInput));

struct SwizzleConstants {
  uint8_t shuffle[kSimd128Size];
  bool omit_add;
};

static constexpr SwizzleConstants kSwizzleConstants[] = {
    {
        // all lanes < kSimd128Size
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        true,
    },
    {
        // lanes that are >= kSimd128Size have top bit set
        {12, 13, 14, 15, 0x90, 0x91, 0x92, 0x93, 0xA0, 0xA1, 0xA2, 0xA3, 0xFC,
         0xFD, 0xFE, 0xFF},
        true,
    },
    {
        {12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27},
        false,
    },
};

using TurboshaftInstructionSelectorSIMDSwizzleConstantTest =
    TurboshaftInstructionSelectorTestWithParam<SwizzleConstants>;

TEST_P(TurboshaftInstructionSelectorSIMDSwizzleConstantTest,
       SimdSwizzleConstant) {
  // Test optimization of swizzle with constant indices.
  auto param = GetParam();
  StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
  OpIndex const c = m.Simd128Constant(param.shuffle);
  OpIndex swizzle = m.I8x16Swizzle(m.Parameter(0), c);
  m.Return(swizzle);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  ASSERT_EQ(kX64I8x16Swizzle, s[1]->arch_opcode());
  ASSERT_EQ(param.omit_add, s[1]->misc());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDSwizzleConstantTest,
                         ::testing::ValuesIn(kSwizzleConstants));

TEST_F(TurboshaftInstructionSelectorTest,
       F64x2PromoteLowF32x4WithS128Load64Zero) {
  StreamBuilder m(this, MachineType::Simd128(), MachineType::Int64());
  V<Simd128> const load = m.Simd128LoadTransform(
      m.Parameter(0), m.Int64Constant(2),
      Simd128LoadTransformOp::LoadKind::RawAligned().Protected(),
      Simd128LoadTransformOp::TransformKind::k64Zero, 0);
  V<Simd128> const promote = m.F64x2PromoteLowF32x4(load);
  m.Return(promote);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  ASSERT_EQ(kX64F64x2PromoteLowF32x4, s[0]->arch_opcode());
  ASSERT_EQ(kMode_MRI, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest, SIMDF32x4SConvert) {
  // Test optimization for F32x4UConvertI32x4.
  // If the input of F32x4UConvertI32x4 is zero-extend from I16x8,
  // F32x4SConvertI32x4 can be used, it's more efficient.
  StreamBuilder m(this, MachineType::Simd128());
  V<Simd128> const splat = m.I16x8Splat(m.Int32Constant(0xFFFF));
  V<Simd128> const extend = m.I32x4UConvertI16x8Low(splat);
  V<Simd128> const convert = m.F32x4UConvertI32x4(extend);
  m.Return(convert);
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kX64F32x4SConvertI32x4, s[2]->arch_opcode());
  ASSERT_EQ(1U, s[2]->InputCount());
  EXPECT_EQ(1U, s[2]->OutputCount());
}

#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace v8::internal::compiler::turboshaft
```