Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is a unit test file for a component called `MachineOperatorReducer` in the V8 JavaScript engine.
The filename suggests it's about reducing or simplifying machine-level operations in the compiler.
The tests use the Google Test framework (`TEST_F`, `ASSERT_TRUE`, `EXPECT_THAT`, `EXPECT_EQ`).
Each `TEST_F` function seems to focus on a specific optimization or reduction rule applied to certain machine operations.
The tests often involve creating a graph of machine operations and then using `Reduce` to check if the `MachineOperatorReducer` can simplify it.

Here's a breakdown of the functionality of each test case:

- `Word32AndWithInt32AddAndConstant`: Checks if `(x + y) & (-1 << L)` can be reduced to `(x & (-1 << L)) + y`
- `Word32AndWithInt32MulAndConstant`: Checks if `(x * (K << L)) & (-1 << L)` can be reduced to `x * (K << L)`
- `Word32AndWithInt32AddAndInt32MulAndConstant`: Checks if `(y * (K << L) + x) & (-1 << L)` can be reduced to `(x & (-1 << L)) + y * (K << L)`
- `Word32AndWithComparisonAndConstantOne`: Checks if `cmp & 1` or `1 & cmp` can be reduced to `cmp` when `cmp` is a comparison operation.
- `Word32AndWithBitFields`: Checks if a series of `Word32And` operations representing bitfield checks can be combined into a single `Word32Equal` with a combined mask and value.
- `Word32AndWithIncorrectBitField`: Checks a case where a bitfield reduction should not occur.
- `Word32OrWithWord32And`: Checks if `(x & K1) | K2` can be reduced based on the values of `K1` and `K2`.
- `Word32XorWithWord32XorAndMinusOne`: Checks if double XORing with -1 simplifies to the original value.
- `ReduceToWord32RorWithParameters`: Checks if combinations of `Word32Shl` and `Word32Shr` with parameter shifts can be reduced to `Word32Ror`.
- `ReduceToWord32RorWithConstant`: Checks if combinations of `Word32Shl` and `Word32Shr` with constant shifts can be reduced to `Word32Ror`.
- `Word32RorWithZeroShift`: Checks if `Word32Ror` with a zero shift is reduced to the input value.
- `Word32RorWithConstants`: Checks if `Word32Ror` with constant inputs is reduced to the constant result.
- `Word32SarWithWord32ShlAndComparison`: Checks if `cmp << 31 >> 31` is reduced to `0 - cmp` for comparison operations.
- `Word32SarWithWord32ShlAndLoad`: Checks if sign-extending loads using shifts and `Word32Sar` are reduced back to the load.
- `Word32ShrWithWord32And`: Checks if `(x & mask) >> shift` can be reduced to 0 in certain cases.
- `Word32ShlWithZeroShift`: Checks if `Word32Shl` with a zero shift is reduced to the input value.
- `Word32ShlWithWord32Sar`: Checks if `(x >> y) << y` is reduced using a mask.
- `Word32ShlWithWord32SarAndInt32AddAndConstant`: Checks a more complex reduction involving shifts, adds, and constants.
- `Word32ShlWithWord32Shr`: Checks if `(x >>> y) << y` is reduced using a mask.
- `Word32ShlWithWord32SarShiftOutZeros`: Checks reductions involving `Word32Sar` with `ShiftKind::kShiftOutZeros`.
- `Word64ShlWithZeroShift`: Checks if `Word64Shl` with a zero shift is reduced to the input value.
- `Word64ShlWithWord64Sar`: Checks if `(x >> y) << y` is reduced using a mask for 64-bit values.
- `Word64ShlWithWord64SarAndInt64AddAndConstant`: Checks a more complex reduction involving 64-bit shifts, adds, and constants.
- `Word64ShlWithWord64Shr`: Checks if `(x >>> y) << y` is reduced using a mask for 64-bit values.
- `Word64ShlWithWord64SarShiftOutZeros`: Checks reductions involving 64-bit `Word64Sar` with `ShiftKind::kShiftOutZeros`.
- `Word32EqualWithShiftedMaskedValueAndConstant`: Checks if `((x >> K1) & K2) == K3` can be reduced to `(x & (K2 << K1)) == (K3 << K1)`.
- `Word32EqualWithAddAndConstant`: Checks if `(x + k1) == k2` can be reduced to `x == (k2 - k1)`.
- `Word64EqualWithShiftedMaskedValueAndConstant`: Checks the 64-bit version of the shifted masked value equality reduction.
- `Word64EqualWithAddAndConstant`: Checks if `(x + k1) == k2` can be reduced to `x == (k2 - k1)` for 64-bit values.
- `BranchWithShiftedMaskedValue`: Checks if a branch condition with a shifted and masked value can be simplified.
- `Int32SubWithConstant`: Checks if subtracting a constant is replaced with adding the negation of the constant.
- `Int32DivWithConstant`: Checks various reductions for integer division with constant divisors.
该C++代码文件 `v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 是 V8 引擎的一部分，专门用于测试 `MachineOperatorReducer` 组件的功能。 `MachineOperatorReducer` 的作用是在编译器的优化阶段，对机器指令进行简化和优化。 这个单元测试文件通过构造不同的机器指令图，并调用 `Reduce` 方法来验证 `MachineOperatorReducer` 是否能正确地将这些指令图简化为更高效的形式。

具体来说，这个代码片段（第2部分）包含了一系列针对特定机器指令组合的测试用例，主要集中在以下几种操作及其优化：

1. **Word32And (32位按位与):**
   - 测试 `(x + y << L) & (-1 << L)` 和 `(x + y) & (-1 << L)` 是否能被优化为 `(x & (-1 << L)) + y << L` 或 `(x & (-1 << L)) + y`。
   - 测试 `(x * (K << L)) & (-1 << L)` 和 `((K << L) * x) & (-1 << L)` 是否能被优化为 `x * (K << L)`。
   - 测试 `(y * (K << L) + x) & (-1 << L)` 和 `(x + y * (K << L)) & (-1 << L)` 是否能被优化为 `(x & (-1 << L)) + y * (K << L)`。
   - 测试与比较操作结果进行 `And 1` 的情况，例如 `cmp & 1`，会被优化为 `cmp` 本身。
   - 测试涉及位域（bit fields）的复杂 `And` 操作，试图将多个独立的比较和 `And` 操作合并成一个针对整个位域的比较。

2. **Word32Or (32位按位或):**
   - 测试 `(x & K1) | K2` 的优化，例如当 `K2` 为 0 时，优化为 `x & K1`；当 `K2` 为 -1 时，优化为 -1；当 `K1 | K2` 为 -1 时，优化为 `x | K2`。

3. **Word32Xor (32位按位异或):**
   - 测试连续与 -1 进行异或操作的优化，例如 `(x ^ -1) ^ -1` 会被优化为 `x`。

4. **Word32Ror (32位循环右移):**
   - 测试由 `Word32Shl` (左移) 和 `Word32Shr` (无符号右移) 组合而成的模式是否能被识别并优化为 `Word32Ror`。包括使用参数作为位移量和使用常量作为位移量的情况。
   - 测试位移量为 0 的情况，会被优化为原值。
   - 测试输入和位移量均为常量的情况，会被直接计算出结果。

5. **Word32Sar (32位算术右移):**
   - 测试与 `Word32Shl` 和比较操作的组合，例如 `cmp << 31 >> 31` 会被优化为 `0 - cmp`。
   - 测试与 `Word32Shl` 和 `Load` 操作的组合，用于检测符号扩展的模式。

6. **Word32Shr (32位无符号右移):**
   - 测试与 `Word32And` 的组合，某些情况下可以优化为常量 0。

7. **Word32Shl (32位左移):**
   - 测试位移量为 0 的情况，会被优化为原值。
   - 测试与 `Word32Sar` 的组合，可以用于提取特定位。
   - 测试与 `Word32Sar` 以及加法和常量的复杂组合优化。
   - 测试与 `Word32Shr` 的组合，可以用于提取特定位。
   - 测试带有 `ShiftKind::kShiftOutZeros` 标志的 `Word32Sar` 与 `Word32Shl` 的组合优化。

8. **Word64Shl (64位左移):**
   - 提供了与 `Word32Shl` 类似的针对 64 位操作的测试用例，包括与 `Word64Sar` 的组合优化等。

9. **Word32Equal (32位相等比较):**
   - 测试 `((x >> K1) & K2) == K3` 类型的模式是否能被优化为 `(x & (K2 << K1)) == (K3 << K1)`。
   - 测试 `(x + k1) == k2` 是否能被优化为 `x == (k2 - k1)`。

10. **Word64Equal (64位相等比较):**
    - 提供了与 `Word32Equal` 类似的针对 64 位操作的测试用例。

11. **Branch (分支指令):**
    - 测试分支条件为 `(x >> K1) & K2` 的情况，是否能被优化为 `x & (K2 << K1)`。

12. **Int32Sub (32位减法):**
    - 测试减去一个常量的情况，例如 `p0 - k` 会被优化为 `p0 + (-k)`。

13. **Int32Div (32位除法):**
    - 测试除以不同常量的情况的优化，例如除以 0、1、-1、2、-2、2的幂等。负数除法的优化会转换为正数除法再取反。

**如果 `v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 以 `.tq` 结尾，那它是个 v8 Torque 源代码。**  然而，根据您提供的文件名，它以 `.cc` 结尾，所以它是 C++ 源代码。 Torque 是一种用于 V8 内部实现的领域特定语言。

**如果它与 JavaScript 的功能有关系，请用 JavaScript 举例说明:**

这些底层的机器码优化直接影响 JavaScript 代码的执行效率。例如，考虑以下 JavaScript 代码：

```javascript
function test(x) {
  const y = 5;
  const shiftedY = y << 4; // 相当于乘以 16
  const result = (x + shiftedY) & 0xF0; // 0xF0 是二进制的 11110000
  return result;
}
```

在这个例子中，`MachineOperatorReducer` 可能会将 `(x + (5 << 4)) & 0xF0` 优化为 `(x & 0xF0) + (5 << 4)`， 这样可能在某些架构上执行效率更高。

再比如位域操作：

```javascript
function getBitfields(flags) {
  const isEnabled = (flags & 0b00000001) !== 0;
  const type = (flags & 0b00000110) >> 1;
  return { isEnabled, type };
}
```

`MachineOperatorReducer` 的 `Word32AndWithBitFields` 测试就是为了确保类似这样的 JavaScript 位域操作能被高效地编译。

**如果有代码逻辑推理，请给出假设输入与输出:**

以 `TEST_F(MachineOperatorReducerTest, Word32AndWithInt32AddAndConstant)` 为例：

**假设输入:** 一个表示 `(p0 + (s1 << l)) & (-1 << l)` 的机器指令图，其中 `p0` 是一个参数节点，`s1` 是另一个参数节点，`l` 是一个介于 1 和 31 之间的整数。

**预期输出:** 一个表示 `(p0 & (-1 << l)) + (s1 << l)` 的机器指令图。

以 `TEST_F(MachineOperatorReducerTest, Word32RorWithConstants)` 为例：

**假设输入:** 一个表示 `Word32Ror(Int32Constant(10), Int32Constant(2))` 的机器指令节点。

**预期输出:** 一个表示 `Int32Constant(RotateRight32(10, 2))` 的机器指令节点，即 `Int32Constant(4026531840)` (假设 32 位整数)。

**如果涉及用户常见的编程错误，请举例说明:**

虽然这个测试文件主要关注编译器的优化，但其中一些优化也间接与用户可能犯的编程错误有关。 例如，用户可能为了性能手动进行一些位运算优化，但编译器可能已经能够自动完成。

一个例子是手动实现循环移位：

```javascript
function rotateRight(x, n) {
  return (x >>> n) | (x << (32 - n)); // 假设是 32 位整数
}
```

`MachineOperatorReducer` 的 `ReduceToWord32RorWithParameters` 和 `ReduceToWord32RorWithConstant` 测试确保了编译器能够识别这种模式并将其优化为更底层的 `ror` 指令，即使程序员没有直接使用位运算符。

**这是第2部分，共4部分，请归纳一下它的功能:**

这部分代码主要集中测试 `MachineOperatorReducer` 对 **32 位和 64 位按位逻辑运算 (AND, OR, XOR)、循环右移 (ROR)、算术右移 (SAR)、无符号右移 (SHR)、左移 (SHL)** 以及 **相等比较 (Equal)** 和 **减法 (Sub)**、**除法 (Div)** 等操作的优化能力。它验证了在各种常量和变量组合的情况下，`MachineOperatorReducer` 能否正确地识别出可以简化的模式，并将其转换为更高效的等价形式。 这部分测试覆盖了大量的边界情况和常见的使用场景，确保了编译器在处理这些基本机器指令时能够达到最佳的性能。

Prompt: 
```
这是目录为v8/test/unittests/compiler/machine-operator-reducer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/machine-operator-reducer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
);
    ASSERT_TRUE(r1.Changed());
    EXPECT_THAT(r1.replacement(),
                IsInt32Add(IsWord32And(p0, IsInt32Constant(Shl(-1, l))), s1));

    // (x + y << L) & (-1 << L) => (x & (-1 << L)) + y << L
    Reduction const r2 = Reduce(graph()->NewNode(
        machine()->Word32And(), graph()->NewNode(machine()->Int32Add(), p0, s1),
        Int32Constant(Shl(-1, l))));
    ASSERT_TRUE(r2.Changed());
    EXPECT_THAT(r2.replacement(),
                IsInt32Add(IsWord32And(p0, IsInt32Constant(Shl(-1, l))), s1));
  }
}


TEST_F(MachineOperatorReducerTest, Word32AndWithInt32MulAndConstant) {
  Node* const p0 = Parameter(0);

  TRACED_FORRANGE(int32_t, l, 1, 31) {
    TRACED_FOREACH(int32_t, k, kInt32Values) {
      if (Shl(k, l) == 0) continue;

      // (x * (K << L)) & (-1 << L) => x * (K << L)
      Reduction const r1 = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Int32Mul(), p0, Int32Constant(Shl(k, l))),
          Int32Constant(Shl(-1, l))));
      ASSERT_TRUE(r1.Changed());
      EXPECT_THAT(r1.replacement(), IsInt32Mul(p0, IsInt32Constant(Shl(k, l))));

      // ((K << L) * x) & (-1 << L) => x * (K << L)
      Reduction const r2 = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Int32Mul(), Int32Constant(Shl(k, l)), p0),
          Int32Constant(Shl(-1, l))));
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(), IsInt32Mul(p0, IsInt32Constant(Shl(k, l))));
    }
  }
}


TEST_F(MachineOperatorReducerTest,
       Word32AndWithInt32AddAndInt32MulAndConstant) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);

  TRACED_FORRANGE(int32_t, l, 1, 31) {
    TRACED_FOREACH(int32_t, k, kInt32Values) {
      if (Shl(k, l) == 0) continue;
      // (y * (K << L) + x) & (-1 << L) => (x & (-1 << L)) + y * (K << L)
      Reduction const r1 = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Int32Add(),
                           graph()->NewNode(machine()->Int32Mul(), p1,
                                            Int32Constant(Shl(k, l))),
                           p0),
          Int32Constant(Shl(-1, l))));
      ASSERT_TRUE(r1.Changed());
      EXPECT_THAT(r1.replacement(),
                  IsInt32Add(IsWord32And(p0, IsInt32Constant(Shl(-1, l))),
                             IsInt32Mul(p1, IsInt32Constant(Shl(k, l)))));

      // (x + y * (K << L)) & (-1 << L) => (x & (-1 << L)) + y * (K << L)
      Reduction const r2 = Reduce(graph()->NewNode(
          machine()->Word32And(),
          graph()->NewNode(machine()->Int32Add(), p0,
                           graph()->NewNode(machine()->Int32Mul(), p1,
                                            Int32Constant(Shl(k, l)))),
          Int32Constant(Shl(-1, l))));
      ASSERT_TRUE(r2.Changed());
      EXPECT_THAT(r2.replacement(),
                  IsInt32Add(IsWord32And(p0, IsInt32Constant(Shl(-1, l))),
                             IsInt32Mul(p1, IsInt32Constant(Shl(k, l)))));
    }
  }
}


TEST_F(MachineOperatorReducerTest, Word32AndWithComparisonAndConstantOne) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  TRACED_FOREACH(ComparisonBinaryOperator, cbop, kComparisonBinaryOperators) {
    Node* cmp = graph()->NewNode((machine()->*cbop.constructor)(), p0, p1);

    // cmp & 1 => cmp
    Reduction const r1 =
        Reduce(graph()->NewNode(machine()->Word32And(), cmp, Int32Constant(1)));
    ASSERT_TRUE(r1.Changed());
    EXPECT_EQ(cmp, r1.replacement());

    // 1 & cmp => cmp
    Reduction const r2 =
        Reduce(graph()->NewNode(machine()->Word32And(), Int32Constant(1), cmp));
    ASSERT_TRUE(r2.Changed());
    EXPECT_EQ(cmp, r2.replacement());
  }
}

TEST_F(MachineOperatorReducerTest, Word32AndWithBitFields) {
  Node* const p = Parameter(0);

  for (int i = 0; i < 2; ++i) {
    bool truncate_from_64_bit = i == 1;

    auto truncate = [&](Node* const input) {
      return truncate_from_64_bit
                 ? graph()->NewNode(machine()->TruncateInt64ToInt32(), input)
                 : input;
    };

    // Simulate getting some bitfields from a Torque bitfield struct and
    // checking them all, like `x.a == 5 & x.b & !x.c & x.d == 2`. This is
    // looking for the pattern: xxxxxxxxxxxxxxxxxxxx10xxx0x1x101. The inputs are
    // in an already-reduced state as would be created by
    // ReduceWord32EqualForConstantRhs, so the only shift operation remaining is
    // the one for selecting a single true bit.
    Node* three_bits =
        graph()->NewNode(machine()->Word32Equal(), Int32Constant(5),
                         graph()->NewNode(machine()->Word32And(),
                                          Int32Constant(7), truncate(p)));
    Node* single_bit_true =
        truncate_from_64_bit
            ? truncate(graph()->NewNode(machine()->Word64And(),
                                        Int64Constant(1),
                                        graph()->NewNode(machine()->Word64Shr(),
                                                         p, Int64Constant(4))))
            : graph()->NewNode(machine()->Word32And(), Int32Constant(1),
                               graph()->NewNode(machine()->Word32Shr(), p,
                                                Int32Constant(4)));
    Node* single_bit_false =
        graph()->NewNode(machine()->Word32Equal(), Int32Constant(0),
                         graph()->NewNode(machine()->Word32And(),
                                          Int32Constant(1 << 6), truncate(p)));
    Node* two_bits =
        graph()->NewNode(machine()->Word32Equal(), Int32Constant(2 << 10),
                         graph()->NewNode(machine()->Word32And(),
                                          Int32Constant(3 << 10), truncate(p)));

    Reduction r1 = Reduce(
        graph()->NewNode(machine()->Word32And(), three_bits, single_bit_true));
    ASSERT_TRUE(r1.Changed());
    EXPECT_THAT(
        r1.replacement(),
        IsWord32Equal(
            IsWord32And(truncate_from_64_bit ? IsTruncateInt64ToInt32(p) : p,
                        IsInt32Constant(7 | (1 << 4))),
            IsInt32Constant(5 | (1 << 4))));

    Reduction r2 = Reduce(
        graph()->NewNode(machine()->Word32And(), single_bit_false, two_bits));
    ASSERT_TRUE(r2.Changed());
    EXPECT_THAT(
        r2.replacement(),
        IsWord32Equal(
            IsWord32And(truncate_from_64_bit ? IsTruncateInt64ToInt32(p) : p,
                        IsInt32Constant((1 << 6) | (3 << 10))),
            IsInt32Constant(2 << 10)));

    Reduction const r3 = Reduce(graph()->NewNode(
        machine()->Word32And(), r1.replacement(), r2.replacement()));
    ASSERT_TRUE(r3.Changed());
    EXPECT_THAT(
        r3.replacement(),
        IsWord32Equal(
            IsWord32And(truncate_from_64_bit ? IsTruncateInt64ToInt32(p) : p,
                        IsInt32Constant(7 | (1 << 4) | (1 << 6) | (3 << 10))),
            IsInt32Constant(5 | (1 << 4) | (2 << 10))));
  }
}

TEST_F(MachineOperatorReducerTest, Word32AndWithIncorrectBitField) {
  Reduction const r = Reduce(graph()->NewNode(
      machine()->Word32And(), Parameter(0),
      graph()->NewNode(machine()->Word32Equal(),
                       graph()->NewNode(machine()->Word32And(), Parameter(0),
                                        Int32Constant(4)),
                       Parameter(0))));
  ASSERT_FALSE(r.Changed());
}

// -----------------------------------------------------------------------------
// Word32Or

TEST_F(MachineOperatorReducerTest, Word32OrWithWord32And) {
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(int32_t, m, kUint32Values) {
    TRACED_FOREACH(int32_t, rhs, kUint32Values) {
      // To get better coverage of interesting cases, run this test twice:
      // once with the mask from kUint32Values, and once with its inverse.
      for (int32_t mask : {m, ~m}) {
        Reduction const r = Reduce(graph()->NewNode(
            machine()->Word32Or(),
            graph()->NewNode(machine()->Word32And(), p0, Int32Constant(mask)),
            Int32Constant(rhs)));
        switch (rhs) {
          case 0:  // x | 0 => x
            ASSERT_TRUE(r.Changed());
            EXPECT_THAT(r.replacement(),
                        IsWord32And(p0, IsInt32Constant(mask)));
            break;
          case -1:  // x | -1 => -1
            ASSERT_TRUE(r.Changed());
            EXPECT_THAT(r.replacement(), IsInt32Constant(-1));
            break;
          default:  // (x & K1) | K2 => x | K2, if K1 | K2 == -1
            if ((mask | rhs) == -1) {
              ASSERT_TRUE(r.Changed());
              EXPECT_THAT(r.replacement(),
                          IsWord32Or(p0, IsInt32Constant(rhs)));
            } else {
              ASSERT_TRUE(!r.Changed());
            }
            break;
        }
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Word32Xor


TEST_F(MachineOperatorReducerTest, Word32XorWithWord32XorAndMinusOne) {
  Node* const p0 = Parameter(0);

  // (x ^ -1) ^ -1 => x
  Reduction r1 = Reduce(graph()->NewNode(
      machine()->Word32Xor(),
      graph()->NewNode(machine()->Word32Xor(), p0, Int32Constant(-1)),
      Int32Constant(-1)));
  ASSERT_TRUE(r1.Changed());
  EXPECT_EQ(r1.replacement(), p0);

  // -1 ^ (x ^ -1) => x
  Reduction r2 = Reduce(graph()->NewNode(
      machine()->Word32Xor(), Int32Constant(-1),
      graph()->NewNode(machine()->Word32Xor(), p0, Int32Constant(-1))));
  ASSERT_TRUE(r2.Changed());
  EXPECT_EQ(r2.replacement(), p0);

  // (-1 ^ x) ^ -1 => x
  Reduction r3 = Reduce(graph()->NewNode(
      machine()->Word32Xor(),
      graph()->NewNode(machine()->Word32Xor(), Int32Constant(-1), p0),
      Int32Constant(-1)));
  ASSERT_TRUE(r3.Changed());
  EXPECT_EQ(r3.replacement(), p0);

  // -1 ^ (-1 ^ x) => x
  Reduction r4 = Reduce(graph()->NewNode(
      machine()->Word32Xor(), Int32Constant(-1),
      graph()->NewNode(machine()->Word32Xor(), Int32Constant(-1), p0)));
  ASSERT_TRUE(r4.Changed());
  EXPECT_EQ(r4.replacement(), p0);
}


// -----------------------------------------------------------------------------
// Word32Ror


TEST_F(MachineOperatorReducerTest, ReduceToWord32RorWithParameters) {
  Node* value = Parameter(0);
  Node* shift = Parameter(1);
  Node* sub = graph()->NewNode(machine()->Int32Sub(), Int32Constant(32), shift);

  // Testing rotate left.
  Node* shl_l = graph()->NewNode(machine()->Word32Shl(), value, shift);
  Node* shr_l = graph()->NewNode(machine()->Word32Shr(), value, sub);

  // (x << y) | (x >>> (32 - y)) => x ror (32 - y)
  Node* node1 = graph()->NewNode(machine()->Word32Or(), shl_l, shr_l);
  Reduction reduction1 = Reduce(node1);
  EXPECT_TRUE(reduction1.Changed());
  EXPECT_EQ(reduction1.replacement(), node1);
  EXPECT_THAT(reduction1.replacement(), IsWord32Ror(value, sub));

  // (x >>> (32 - y)) | (x << y) => x ror (32 - y)
  Node* node2 = graph()->NewNode(machine()->Word32Or(), shr_l, shl_l);
  Reduction reduction2 = Reduce(node2);
  EXPECT_TRUE(reduction2.Changed());
  EXPECT_EQ(reduction2.replacement(), node2);
  EXPECT_THAT(reduction2.replacement(), IsWord32Ror(value, sub));

  // (x << y) ^ (x >>> (32 - y)) => x ror (32 - y)
  Node* node3 = graph()->NewNode(machine()->Word32Xor(), shl_l, shr_l);
  Reduction reduction3 = Reduce(node3);
  EXPECT_FALSE(reduction3.Changed());

  // (x >>> (32 - y)) ^ (x << y) => x ror (32 - y)
  Node* node4 = graph()->NewNode(machine()->Word32Xor(), shr_l, shl_l);
  Reduction reduction4 = Reduce(node4);
  EXPECT_FALSE(reduction4.Changed());

  // Testing rotate right.
  Node* shl_r = graph()->NewNode(machine()->Word32Shl(), value, sub);
  Node* shr_r = graph()->NewNode(machine()->Word32Shr(), value, shift);

  // (x << (32 - y)) | (x >>> y) => x ror y
  Node* node5 = graph()->NewNode(machine()->Word32Or(), shl_r, shr_r);
  Reduction reduction5 = Reduce(node5);
  EXPECT_TRUE(reduction5.Changed());
  EXPECT_EQ(reduction5.replacement(), node5);
  EXPECT_THAT(reduction5.replacement(), IsWord32Ror(value, shift));

  // (x >>> y) | (x << (32 - y)) => x ror y
  Node* node6 = graph()->NewNode(machine()->Word32Or(), shr_r, shl_r);
  Reduction reduction6 = Reduce(node6);
  EXPECT_TRUE(reduction6.Changed());
  EXPECT_EQ(reduction6.replacement(), node6);
  EXPECT_THAT(reduction6.replacement(), IsWord32Ror(value, shift));

  // (x << (32 - y)) ^ (x >>> y) => x ror y
  Node* node7 = graph()->NewNode(machine()->Word32Xor(), shl_r, shr_r);
  Reduction reduction7 = Reduce(node7);
  EXPECT_FALSE(reduction7.Changed());

  // (x >>> y) ^ (x << (32 - y)) => x ror y
  Node* node8 = graph()->NewNode(machine()->Word32Xor(), shr_r, shl_r);
  Reduction reduction8 = Reduce(node8);
  EXPECT_FALSE(reduction8.Changed());
}

TEST_F(MachineOperatorReducerTest, ReduceToWord32RorWithConstant) {
  Node* value = Parameter(0);
  TRACED_FORRANGE(int32_t, k, 0, 31) {
    Node* shl =
        graph()->NewNode(machine()->Word32Shl(), value, Int32Constant(k));
    Node* shr =
        graph()->NewNode(machine()->Word32Shr(), value, Int32Constant(32 - k));

    // (x << K) | (x >>> ((32 - K) - y)) => x ror (32 - K)
    Node* node1 = graph()->NewNode(machine()->Word32Or(), shl, shr);
    Reduction reduction1 = Reduce(node1);
    EXPECT_TRUE(reduction1.Changed());
    EXPECT_EQ(reduction1.replacement(), node1);
    EXPECT_THAT(reduction1.replacement(),
                IsWord32Ror(value, IsInt32Constant(32 - k)));

    // (x >>> (32 - K)) | (x << K) => x ror (32 - K)
    Node* node2 = graph()->NewNode(machine()->Word32Or(), shr, shl);
    Reduction reduction2 = Reduce(node2);
    EXPECT_TRUE(reduction2.Changed());
    EXPECT_EQ(reduction2.replacement(), node2);
    EXPECT_THAT(reduction2.replacement(),
                IsWord32Ror(value, IsInt32Constant(32 - k)));
  }
}


TEST_F(MachineOperatorReducerTest, Word32RorWithZeroShift) {
  Node* value = Parameter(0);
  Node* node =
      graph()->NewNode(machine()->Word32Ror(), value, Int32Constant(0));
  Reduction reduction = Reduce(node);
  EXPECT_TRUE(reduction.Changed());
  EXPECT_EQ(reduction.replacement(), value);
}


TEST_F(MachineOperatorReducerTest, Word32RorWithConstants) {
  TRACED_FOREACH(int32_t, x, kUint32Values) {
    TRACED_FORRANGE(int32_t, y, 0, 31) {
      Node* node = graph()->NewNode(machine()->Word32Ror(), Int32Constant(x),
                                    Int32Constant(y));
      Reduction reduction = Reduce(node);
      EXPECT_TRUE(reduction.Changed());
      EXPECT_THAT(reduction.replacement(),
                  IsInt32Constant(base::bits::RotateRight32(x, y)));
    }
  }
}


// -----------------------------------------------------------------------------
// Word32Sar


TEST_F(MachineOperatorReducerTest, Word32SarWithWord32ShlAndComparison) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);

  TRACED_FOREACH(ComparisonBinaryOperator, cbop, kComparisonBinaryOperators) {
    Node* cmp = graph()->NewNode((machine()->*cbop.constructor)(), p0, p1);

    // cmp << 31 >> 31 => 0 - cmp
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Word32Sar(),
        graph()->NewNode(machine()->Word32Shl(), cmp, Int32Constant(31)),
        Int32Constant(31)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Sub(IsInt32Constant(0), cmp));
  }
}


TEST_F(MachineOperatorReducerTest, Word32SarWithWord32ShlAndLoad) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  {
    Node* const l = graph()->NewNode(machine()->Load(MachineType::Int8()), p0,
                                     p1, graph()->start(), graph()->start());
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Word32Sar(),
        graph()->NewNode(machine()->Word32Shl(), l, Int32Constant(24)),
        Int32Constant(24)));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(l, r.replacement());
  }
  {
    Node* const l = graph()->NewNode(machine()->Load(MachineType::Int16()), p0,
                                     p1, graph()->start(), graph()->start());
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Word32Sar(),
        graph()->NewNode(machine()->Word32Shl(), l, Int32Constant(16)),
        Int32Constant(16)));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(l, r.replacement());
  }
}


// -----------------------------------------------------------------------------
// Word32Shr

TEST_F(MachineOperatorReducerTest, Word32ShrWithWord32And) {
  Node* const p0 = Parameter(0);
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    uint32_t mask =
        base::SubWithWraparound(base::ShlWithWraparound(1, shift), 1);
    Node* node = graph()->NewNode(
        machine()->Word32Shr(),
        graph()->NewNode(machine()->Word32And(), p0, Int32Constant(mask)),
        Int32Constant(shift));
    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
}

// -----------------------------------------------------------------------------
// Word32Shl

TEST_F(MachineOperatorReducerTest, Word32ShlWithZeroShift) {
  Node* p0 = Parameter(0);
  Node* node = graph()->NewNode(machine()->Word32Shl(), p0, Int32Constant(0));
  Reduction r = Reduce(node);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p0, r.replacement());
}


TEST_F(MachineOperatorReducerTest, Word32ShlWithWord32Sar) {
  Node* p0 = Parameter(0);
  TRACED_FORRANGE(int32_t, x, 1, 31) {
    Node* node = graph()->NewNode(
        machine()->Word32Shl(),
        graph()->NewNode(machine()->Word32Sar(), p0, Int32Constant(x)),
        Int32Constant(x));
    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    int32_t m = static_cast<int32_t>(~((1U << x) - 1U));
    EXPECT_THAT(r.replacement(), IsWord32And(p0, IsInt32Constant(m)));
  }
}


TEST_F(MachineOperatorReducerTest,
       Word32ShlWithWord32SarAndInt32AddAndConstant) {
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(int32_t, k, kInt32Values) {
    TRACED_FORRANGE(int32_t, l, 1, 31) {
      if (Shl(k, l) == 0) continue;
      // (x + (K << L)) >> L << L => (x & (-1 << L)) + (K << L)
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Word32Shl(),
          graph()->NewNode(machine()->Word32Sar(),
                           graph()->NewNode(machine()->Int32Add(), p0,
                                            Int32Constant(Shl(k, l))),
                           Int32Constant(l)),
          Int32Constant(l)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Add(IsWord32And(p0, IsInt32Constant(Shl(-1, l))),
                             IsInt32Constant(Shl(k, l))));
    }
  }
}


TEST_F(MachineOperatorReducerTest, Word32ShlWithWord32Shr) {
  Node* p0 = Parameter(0);
  TRACED_FORRANGE(int32_t, x, 1, 31) {
    Node* node = graph()->NewNode(
        machine()->Word32Shl(),
        graph()->NewNode(machine()->Word32Shr(), p0, Int32Constant(x)),
        Int32Constant(x));
    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    int32_t m = static_cast<int32_t>(std::numeric_limits<uint32_t>::max() << x);
    EXPECT_THAT(r.replacement(), IsWord32And(p0, IsInt32Constant(m)));
  }
}

TEST_F(MachineOperatorReducerTest, Word32ShlWithWord32SarShiftOutZeros) {
  Node* p = Parameter(0);
  TRACED_FORRANGE(int32_t, x, 1, 31) {
    TRACED_FORRANGE(int32_t, y, 0, 31) {
      Node* node = graph()->NewNode(
          machine()->Word32Shl(),
          graph()->NewNode(machine()->Word32Sar(ShiftKind::kShiftOutZeros), p,
                           Int32Constant(x)),
          Int32Constant(y));
      Reduction r = Reduce(node);
      ASSERT_TRUE(r.Changed());
      if (x == y) {
        // (p >> x) << y => p
        EXPECT_THAT(r.replacement(), p);
      } else if (x < y) {
        // (p >> x) << y => p << (y - x)
        EXPECT_THAT(r.replacement(), IsWord32Shl(p, IsInt32Constant(y - x)));
      } else {
        // (p >> x) << y => p >> (x - y)
        EXPECT_THAT(r.replacement(), IsWord32Sar(p, IsInt32Constant(x - y)));
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Word64Shl

TEST_F(MachineOperatorReducerTest, Word64ShlWithZeroShift) {
  Node* p0 = Parameter(0);
  Node* node = graph()->NewNode(machine()->Word64Shl(), p0, Int64Constant(0));
  Reduction r = Reduce(node);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p0, r.replacement());
}

TEST_F(MachineOperatorReducerTest, Word64ShlWithWord64Sar) {
  Node* p0 = Parameter(0);
  TRACED_FORRANGE(int64_t, x, 1, 63) {
    Node* node = graph()->NewNode(
        machine()->Word64Shl(),
        graph()->NewNode(machine()->Word64Sar(), p0, Int64Constant(x)),
        Int64Constant(x));
    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    int64_t m = static_cast<int64_t>(~((uint64_t{1} << x) - 1));
    EXPECT_THAT(r.replacement(), IsWord64And(p0, IsInt64Constant(m)));
  }
}

TEST_F(MachineOperatorReducerTest,
       Word64ShlWithWord64SarAndInt64AddAndConstant) {
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(int64_t, k, kInt64Values) {
    TRACED_FORRANGE(int64_t, l, 1, 63) {
      if (Shl(k, l) == 0) continue;
      // (x + (K << L)) >> L << L => (x & (-1 << L)) + (K << L)
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Word64Shl(),
          graph()->NewNode(machine()->Word64Sar(),
                           graph()->NewNode(machine()->Int64Add(), p0,
                                            Int64Constant(Shl(k, l))),
                           Int64Constant(l)),
          Int64Constant(l)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(
          r.replacement(),
          IsInt64Add(IsWord64And(p0, IsInt64Constant(Shl(int64_t{-1}, l))),
                     IsInt64Constant(Shl(k, l))));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Word64ShlWithWord64Shr) {
  Node* p0 = Parameter(0);
  TRACED_FORRANGE(int64_t, x, 1, 63) {
    Node* node = graph()->NewNode(
        machine()->Word64Shl(),
        graph()->NewNode(machine()->Word64Shr(), p0, Int64Constant(x)),
        Int64Constant(x));
    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    int64_t m = static_cast<int64_t>(std::numeric_limits<uint64_t>::max() << x);
    EXPECT_THAT(r.replacement(), IsWord64And(p0, IsInt64Constant(m)));
  }
}

TEST_F(MachineOperatorReducerTest, Word64ShlWithWord64SarShiftOutZeros) {
  Node* p = Parameter(0);
  TRACED_FORRANGE(int64_t, x, 1, 63) {
    TRACED_FORRANGE(int64_t, y, 0, 63) {
      Node* node = graph()->NewNode(
          machine()->Word64Shl(),
          graph()->NewNode(machine()->Word64Sar(ShiftKind::kShiftOutZeros), p,
                           Int64Constant(x)),
          Int64Constant(y));
      Reduction r = Reduce(node);
      ASSERT_TRUE(r.Changed());
      if (x == y) {
        // (p >> x) << y => p
        EXPECT_THAT(r.replacement(), p);
      } else if (x < y) {
        // (p >> x) << y => p << (y - x)
        EXPECT_THAT(r.replacement(), IsWord64Shl(p, IsInt64Constant(y - x)));
      } else {
        // (p >> x) << y => p >> (x - y)
        EXPECT_THAT(r.replacement(), IsWord64Sar(p, IsInt64Constant(x - y)));
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Word32Equal

TEST_F(MachineOperatorReducerTest,
       Word32EqualWithShiftedMaskedValueAndConstant) {
  // ((x >> K1) & K2) == K3 => (x & (K2 << K1)) == (K3 << K1)
  TRACED_FOREACH(uint32_t, mask, kUint32Values) {
    TRACED_FOREACH(uint32_t, rhs, kUint32Values) {
      Node* const p0 = Parameter(0);
      TRACED_FORRANGE(uint32_t, shift_bits, 1, 31) {
        Node* node = graph()->NewNode(
            machine()->Word32Equal(),
            graph()->NewNode(machine()->Word32And(),
                             graph()->NewNode(machine()->Word32Shr(), p0,
                                              Uint32Constant(shift_bits)),
                             Uint32Constant(mask)),
            Uint32Constant(rhs));
        Reduction r = Reduce(node);
        uint32_t new_mask = mask << shift_bits;
        uint32_t new_rhs = rhs << shift_bits;
        if (new_mask >> shift_bits == mask && new_rhs >> shift_bits == rhs) {
          ASSERT_TRUE(r.Changed());
          // The left-hand side of the equality is now a Word32And operation,
          // unless the mask is zero in which case the newly-created Word32And
          // is immediately reduced away.
          Matcher<Node*> lhs = mask == 0
                                   ? IsInt32Constant(0)
                                   : IsWord32And(p0, IsInt32Constant(new_mask));
          EXPECT_THAT(r.replacement(),
                      IsWord32Equal(lhs, IsInt32Constant(new_rhs)));
        } else {
          ASSERT_FALSE(r.Changed());
        }
      }
      // This test uses too much memory if we don't periodically reset.
      Reset();
    }
  }
}

TEST_F(MachineOperatorReducerTest, Word32EqualWithAddAndConstant) {
  // (x+k1)==k2 => x==(k2-k1)
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(int32_t, k1, kInt32Values) {
    TRACED_FOREACH(int32_t, k2, kInt32Values) {
      Node* node = graph()->NewNode(
          machine()->Word32Equal(),
          graph()->NewNode(machine()->Int32Add(), p0, Int32Constant(k1)),
          Int32Constant(k2));
      Reduction r = Reduce(node);
      ASSERT_TRUE(r.Changed());
    }
  }
}

// -----------------------------------------------------------------------------
// Word64Equal

TEST_F(MachineOperatorReducerTest,
       Word64EqualWithShiftedMaskedValueAndConstant) {
  // ((x >> K1) & K2) == K3 => (x & (K2 << K1)) == (K3 << K1)
  TRACED_FOREACH(uint64_t, mask, kUint64Values) {
    TRACED_FOREACH(uint64_t, rhs, kUint64Values) {
      Node* const p0 = Parameter(0);
      TRACED_FORRANGE(uint64_t, shift_bits, 1, 63) {
        Node* node = graph()->NewNode(
            machine()->Word64Equal(),
            graph()->NewNode(machine()->Word64And(),
                             graph()->NewNode(machine()->Word64Shr(), p0,
                                              Uint64Constant(shift_bits)),
                             Uint64Constant(mask)),
            Uint64Constant(rhs));
        Reduction r = Reduce(node);
        uint64_t new_mask = mask << shift_bits;
        uint64_t new_rhs = rhs << shift_bits;
        if (new_mask >> shift_bits == mask && new_rhs >> shift_bits == rhs) {
          ASSERT_TRUE(r.Changed());
          // The left-hand side of the equality is now a Word64And operation,
          // unless the mask is zero in which case the newly-created Word64And
          // is immediately reduced away.
          Matcher<Node*> lhs = mask == 0
                                   ? IsInt64Constant(0)
                                   : IsWord64And(p0, IsInt64Constant(new_mask));
          EXPECT_THAT(r.replacement(),
                      IsWord64Equal(lhs, IsInt64Constant(new_rhs)));
        } else {
          ASSERT_FALSE(r.Changed());
        }
      }
      // This test uses too much memory if we don't periodically reset.
      Reset();
    }
  }
}

TEST_F(MachineOperatorReducerTest, Word64EqualWithAddAndConstant) {
  // (x+k1)==k2 => x==(k2-k1)
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(int64_t, k1, kInt64Values) {
    TRACED_FOREACH(int64_t, k2, kInt64Values) {
      Node* node = graph()->NewNode(
          machine()->Word64Equal(),
          graph()->NewNode(machine()->Int64Add(), p0, Int64Constant(k1)),
          Int64Constant(k2));
      Reduction r = Reduce(node);
      ASSERT_TRUE(r.Changed());
    }
  }
}

// -----------------------------------------------------------------------------
// Branch

TEST_F(MachineOperatorReducerTest, BranchWithShiftedMaskedValue) {
  // Branch condition (x >> K1) & K2 => x & (K2 << K1)
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(uint32_t, mask, kUint32Values) {
    TRACED_FORRANGE(uint32_t, shift_bits, 1, 31) {
      Node* node = graph()->NewNode(
          common()->Branch(),
          graph()->NewNode(machine()->Word32And(),
                           graph()->NewNode(machine()->Word32Shr(), p0,
                                            Uint32Constant(shift_bits)),
                           Uint32Constant(mask)),
          graph()->start());
      Reduction r = Reduce(node);
      uint32_t new_mask = mask << shift_bits;
      if (new_mask >> shift_bits == mask) {
        ASSERT_TRUE(r.Changed());
        // The branch condition is now a Word32And operation, unless the mask is
        // zero in which case the newly-created Word32And is immediately reduced
        // away.
        Matcher<Node*> lhs = mask == 0
                                 ? IsInt32Constant(0)
                                 : IsWord32And(p0, IsInt32Constant(new_mask));
        EXPECT_THAT(r.replacement(), IsBranch(lhs, graph()->start()));
      } else {
        ASSERT_FALSE(r.Changed());
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Int32Sub


TEST_F(MachineOperatorReducerTest, Int32SubWithConstant) {
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(int32_t, k, kInt32Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Int32Sub(), p0, Int32Constant(k)));
    ASSERT_TRUE(r.Changed());
    if (k == 0) {
      EXPECT_EQ(p0, r.replacement());
    } else {
      EXPECT_THAT(
          r.replacement(),
          IsInt32Add(p0, IsInt32Constant(base::NegateWithWraparound(k))));
    }
  }
}

// -----------------------------------------------------------------------------
// Int32Div, Int64Div

TEST_F(MachineOperatorReducerTest, Int32DivWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Div(), p0, Int32Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Div(), p0, Int32Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(r.replacement(), p0);
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Div(), p0, Int32Constant(-1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Sub(IsInt32Constant(0), p0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Div(), p0, Int32Constant(2), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsWord32Sar(IsInt32Add(IsWord32Shr(p0, IsInt32Constant(31)), p0),
                    IsInt32Constant(1)));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Div(), p0, Int32Constant(-2), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsInt32Sub(
            IsInt32Constant(0),
            IsWord32Sar(IsInt32Add(IsWord32Shr(p0, IsInt32Constant(31)), p0),
                        IsInt32Constant(1))));
  }
  TRACED_FORRANGE(int32_t, shift, 2, 30) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Int32Div(), p0,
                                Int32Constant(1 << shift), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsWord32Sar(IsInt32Add(IsWord32Shr(IsWord32Sar(p0, IsInt32Constant(31)),
                                           IsInt32Constant(32 - shift)),
                               p0),
                    IsInt32Constant(shift)));
  }
  TRACED_FORRANGE(int32_t, shift, 2, 31) {
    Reduction const r = Reduce(graph()->NewNode(machine()->Int32Div(), p0,
                                                Int32Constant(Shl(-1, shift)),
                                                graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsInt32Sub(
            IsInt32Constant(0),
            IsWord32Sar(
                IsInt32Add(IsWord32Shr(IsWord32Sar(p0, IsInt32Constant(31)),
                                       IsInt32Constant(32 - shift)),
                           p0),
                IsInt32Constant(shift))));
  }
  TRACED_FOREACH(int32_t, divisor, kInt32Values) {
    if (divisor < 0) {
      if (divisor == kMinInt || base::bits::IsPowerOfTwo(-divisor)) continue;
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Int32Div(), p0, Int32Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Sub(IsInt32Constant(0),
                                              IsTruncatingDiv(p0, -divisor)));
    } else if (divisor > 0) {
      if (base::bits::IsPowerOfTwo(divisor)) continue;
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Int32Div(), p0, Int32Constant(divisor), gra
"""


```