Response: The user wants to understand the functionality of the provided C++ code snippet, which is part 2 of a larger file. This file seems to be related to compiler optimizations within the V8 JavaScript engine.

Based on the naming conventions (`MachineOperatorReducerTest`, `Reduce`, `IsInt32Constant`, `IsFloat64Add`, etc.), this code likely tests the `MachineOperatorReducer` component. The purpose of this reducer is to simplify or optimize machine-level operations in the compiler's intermediate representation.

Each `TEST_F` block focuses on a specific machine operation (e.g., `Int32Div`, `Float64Mul`, `Uint32Mod`) and explores scenarios where the reducer can apply optimizations. These optimizations often involve:

1. **Constant Folding:** Replacing operations with constant inputs with their computed constant result.
2. **Identity/Inverse Element Elimination:** Removing operations involving identity elements (e.g., `x + 0` becomes `x`) or inverse elements.
3. **Algebraic Simplification:** Applying algebraic identities to simplify expressions (e.g., `x * 2` can become `x + x` or a left shift).
4. **Pattern Matching:** Recognizing specific patterns of operations and replacing them with more efficient equivalents.

The code uses a fluent assertion library (`ASSERT_TRUE`, `EXPECT_THAT`, `EXPECT_EQ`) to check if the reducer made the expected transformations. The `TRACED_FOREACH` and `TRACED_FORRANGE` macros suggest that the tests are run against a range of input values to ensure correctness.

To relate this to JavaScript, I need to identify which JavaScript operations would eventually be lowered to the machine operations tested here and show how these optimizations could impact the generated machine code.
这是v8 JavaScript引擎中`MachineOperatorReducer`单元测试的第二部分。 该文件的主要功能是测试`MachineOperatorReducer`这个编译器组件的优化能力。 `MachineOperatorReducer`负责在编译过程中简化和优化底层的机器操作，从而提高JavaScript代码的执行效率。

具体来说，这部分代码继续测试了各种机器指令在特定情况下的简化和优化：

**主要功能归纳:**

* **整数除法 (`Int32Div`, `Int64Div`, `Uint32Div`, `Uint64Div`):**
    * 测试了除以常量的情况，例如除以0，1，-1，以及2的幂次方等，验证了是否能正确地替换为更简单的操作，例如常量替换、直接返回参数、位移操作等。
    * 测试了被除数和除数是相同参数的情况。
* **整数取模 (`Int32Mod`, `Int64Mod`, `Uint32Mod`, `Uint64Mod`):**
    * 类似除法，测试了对常量取模的情况，例如模0，1，-1，以及2的幂次方等，验证了是否能正确替换为常量或位运算。
    * 测试了被模数和模数是相同参数的情况。
* **整数加法 (`Int32Add`, `Int64Add`):**
    * 测试了合并连续的加法常量。
    * 测试了与减零操作的组合。
* **整数乘法 (`Int32Mul`, `Int64Mul`):**
    * 测试了合并连续的乘法常量。
    * 测试了乘以0，1，-1，以及2的幂次方的情况，验证了是否能替换为常量或位移操作。
* **带溢出检查的整数运算 (`Int32AddWithOverflow`, `Int32SubWithOverflow`, `Int32MulWithOverflow`):**
    * 测试了与常量0，1，-1，2的运算，验证了是否能正确计算结果和溢出标志。
* **整数比较 (`Int32LessThan`, `Uint32LessThan`, `Uint64LessThan`, `Int64LessThan`):**
    * 测试了与位运算的组合，例如`Word32Or`，`Word32SarShiftOutZeros`等，验证了在特定位运算后是否能简化比较操作。
    * 测试了无符号比较中，将有符号整数转换为无符号整数的情况。
* **浮点数乘法 (`Float64Mul`):**
    * 测试了乘以-1和2的情况，验证了是否能替换为减法或加法操作。
* **浮点数除法 (`Float64Div`):**
    * 测试了除以-1和2的幂次方的情况，验证了是否能替换为乘法操作。
* **浮点数数学函数 (`Float64Acos`, `Float64Acosh`, `Float64Asin`, `Float64Asinh`, `Float64Atan`, `Float64Atanh`, `Float64Atan2`, `Float64Cos`, `Float64Cosh`, `Float64Exp`, `Float64Log`, `Float64Log1p`, `Float64Pow`, `Float64Sin`, `Float64Sinh`, `Float64Tan`, `Float64Tanh`):**
    * 测试了使用常量作为参数时，是否能直接计算出结果并替换为常量。
* **浮点数位操作 (`Float64InsertLowWord32`, `Float64InsertHighWord32`):**
    * 测试了使用常量作为参数时，是否能正确计算出结果并替换为常量。
* **浮点数比较 (`Float64Equal`, `Float64LessThan`, `Float64LessThanOrEqual`):**
    * 测试了与常量的比较，验证了是否能直接计算出布尔结果并替换为整数常量 (0 或 1)。
    * 测试了比较由 `ChangeFloat32ToFloat64` 转换而来的值的情况，验证了是否能简化为 `Float32` 级别的比较。
* **浮点数取整 (`Float64RoundDown`):**
    * 测试了使用常量作为参数时，是否能直接计算出结果并替换为常量。
* **内存存储 (`Store`):**
    * 测试了在存储操作之前进行位运算 (`Word32And`, `Word32Sar`, `Word32Shl`) 的情况，验证了在某些情况下，可以消除这些位运算。
* **选择 (`Select`):**
    * 测试了 `Select` 操作在条件为常量 true 或 false 时的简化，即直接返回其中一个输入参数。

**与 JavaScript 的关系及示例:**

`MachineOperatorReducer` 的优化直接影响到 JavaScript 代码的执行效率。许多 JavaScript 操作最终会被编译成这些底层的机器指令。

**例子 1: 整数除法优化**

```javascript
function divideByTwo(x) {
  return x / 2;
}

// 在 V8 编译器的优化过程中，'/' 操作可能会被降低为 Int32Div 或 Int64Div
// MachineOperatorReducer 会识别出除以常量 2 的情况，并将其替换为更高效的右移操作 (Word32Sar 或 Word64Sar)

// 优化后的机器指令可能类似于:
// Word32Sar  input, 1  (对于 32 位整数)
// 或者
// Word64Sar  input, 1  (对于 64 位整数)
```

**例子 2: 整数取模优化**

```javascript
function moduloEight(x) {
  return x % 8;
}

// '%' 操作可能会被降低为 Int32Mod 或 Int64Mod
// MachineOperatorReducer 会识别出模数为 8 (2 的 3 次方) 的情况，并将其替换为按位与操作

// 优化后的机器指令可能类似于:
// Word32And input, 7  (对于 32 位整数，7 是二进制的 0111)
// 或者
// Word64And input, 7  (对于 64 位整数)
```

**例子 3: 浮点数乘法优化**

```javascript
function multiplyByTwo(y) {
  return y * 2.0;
}

// '*' 操作可能会被降低为 Float64Mul
// MachineOperatorReducer 会识别出乘以常量 2.0 的情况，并将其替换为浮点数加法

// 优化后的机器指令可能类似于:
// Float64Add input, input
```

**例子 4: 浮点数比较优化**

```javascript
function compareWithZero(z) {
  return z < 0.0;
}

// '<' 操作可能会被降低为 Float64LessThan
// 如果 z 的类型可以确定为 float，并且与常量 0.0 比较，
// MachineOperatorReducer 可能会尝试将其优化为 Float32LessThan 操作以提高效率。
```

总而言之，这个 C++ 文件是 V8 引擎中一个关键组件的测试，它确保了编译器能够正确地进行底层的机器指令优化，从而显著提升 JavaScript 代码的性能。这些优化对于保证 V8 引擎的高效运行至关重要。

Prompt: 
```
这是目录为v8/test/unittests/compiler/machine-operator-reducer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsTruncatingDiv(p0, divisor));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Int64DivWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Div(), p0, Int64Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Div(), p0, Int64Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(r.replacement(), p0);
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Div(), p0, Int64Constant(-1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Sub(IsInt64Constant(0), p0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Div(), p0, Int64Constant(2), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsWord64Sar(IsInt64Add(IsWord64Shr(p0, IsInt64Constant(63)), p0),
                    IsInt64Constant(1)));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Div(), p0, Int64Constant(-2), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsInt64Sub(
            IsInt64Constant(0),
            IsWord64Sar(IsInt64Add(IsWord64Shr(p0, IsInt64Constant(63)), p0),
                        IsInt64Constant(1))));
  }
  TRACED_FORRANGE(int64_t, shift, 2, 62) {
    Reduction const r = Reduce(
        graph()->NewNode(machine()->Int64Div(), p0,
                         Int64Constant(int64_t{1} << shift), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsWord64Sar(IsInt64Add(IsWord64Shr(IsWord64Sar(p0, IsInt64Constant(63)),
                                           IsInt64Constant(64 - shift)),
                               p0),
                    IsInt64Constant(shift)));
  }
  TRACED_FORRANGE(int64_t, shift, 2, 63) {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Div(), p0, Int64Constant(Shl(int64_t{-1}, shift)),
        graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsInt64Sub(
            IsInt64Constant(0),
            IsWord64Sar(
                IsInt64Add(IsWord64Shr(IsWord64Sar(p0, IsInt64Constant(63)),
                                       IsInt64Constant(64 - shift)),
                           p0),
                IsInt64Constant(shift))));
  }
  TRACED_FOREACH(int64_t, divisor, kInt64Values) {
    if (divisor < 0) {
      if (divisor == std::numeric_limits<int64_t>::min() ||
          base::bits::IsPowerOfTwo(-divisor)) {
        continue;
      }
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Int64Div(), p0, Int64Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt64Sub(IsInt64Constant(0),
                                              IsTruncatingDiv64(p0, -divisor)));
    } else if (divisor > 0) {
      if (base::bits::IsPowerOfTwo(divisor)) continue;
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Int64Div(), p0, Int64Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsTruncatingDiv64(p0, divisor));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Int32DivWithParameters) {
  Node* const p0 = Parameter(0);
  Reduction const r =
      Reduce(graph()->NewNode(machine()->Int32Div(), p0, p0, graph()->start()));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(
      r.replacement(),
      IsWord32Equal(IsWord32Equal(p0, IsInt32Constant(0)), IsInt32Constant(0)));
}

// -----------------------------------------------------------------------------
// Uint32Div, Uint64Div

TEST_F(MachineOperatorReducerTest, Uint32DivWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint32Div(), Int32Constant(0), p0, graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint32Div(), p0, Int32Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint32Div(), p0, Int32Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(r.replacement(), p0);
  }
  TRACED_FOREACH(uint32_t, dividend, kUint32Values) {
    TRACED_FOREACH(uint32_t, divisor, kUint32Values) {
      Reduction const r = Reduce(
          graph()->NewNode(machine()->Uint32Div(), Uint32Constant(dividend),
                           Uint32Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Constant(base::bit_cast<int32_t>(
                      base::bits::UnsignedDiv32(dividend, divisor))));
    }
  }
  TRACED_FORRANGE(uint32_t, shift, 1, 31) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Uint32Div(), p0,
                                Uint32Constant(1u << shift), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsWord32Shr(p0, IsInt32Constant(static_cast<int32_t>(shift))));
  }
}

TEST_F(MachineOperatorReducerTest, Uint64DivWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Div(), Int64Constant(0), p0, graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Div(), p0, Int64Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Div(), p0, Int64Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(r.replacement(), p0);
  }
  TRACED_FOREACH(uint64_t, dividend, kUint64Values) {
    TRACED_FOREACH(uint64_t, divisor, kUint64Values) {
      Reduction const r = Reduce(
          graph()->NewNode(machine()->Uint64Div(), Uint64Constant(dividend),
                           Uint64Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt64Constant(base::bit_cast<int64_t>(
                      base::bits::UnsignedDiv64(dividend, divisor))));
    }
  }
  TRACED_FORRANGE(uint64_t, shift, 1, 63) {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Div(), p0, Uint64Constant(uint64_t{1} << shift),
        graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsWord64Shr(p0, IsInt64Constant(static_cast<int64_t>(shift))));
  }
}

TEST_F(MachineOperatorReducerTest, Uint32DivWithParameters) {
  Node* const p0 = Parameter(0);
  Reduction const r = Reduce(
      graph()->NewNode(machine()->Uint32Div(), p0, p0, graph()->start()));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(
      r.replacement(),
      IsWord32Equal(IsWord32Equal(p0, IsInt32Constant(0)), IsInt32Constant(0)));
}

// -----------------------------------------------------------------------------
// Int32Mod, Uint64Mod

TEST_F(MachineOperatorReducerTest, Int32ModWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Mod(), Int32Constant(0), p0, graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Mod(), p0, Int32Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Mod(), p0, Int32Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Mod(), p0, Int32Constant(-1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  TRACED_FOREACH(int32_t, dividend, kInt32Values) {
    TRACED_FOREACH(int32_t, divisor, kInt32Values) {
      Reduction const r = Reduce(
          graph()->NewNode(machine()->Int32Mod(), Int32Constant(dividend),
                           Int32Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Constant(base::bits::SignedMod32(dividend, divisor)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, 1, 30) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Int32Mod(), p0,
                                Int32Constant(1 << shift), graph()->start()));
    int32_t const mask = (1 << shift) - 1;
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsPhi(
            MachineRepresentation::kWord32,
            IsInt32Sub(IsInt32Constant(0),
                       IsWord32And(IsInt32Sub(IsInt32Constant(0), p0),
                                   IsInt32Constant(mask))),
            IsWord32And(p0, IsInt32Constant(mask)),
            IsMerge(IsIfTrue(IsBranch(IsInt32LessThan(p0, IsInt32Constant(0)),
                                      graph()->start())),
                    IsIfFalse(IsBranch(IsInt32LessThan(p0, IsInt32Constant(0)),
                                       graph()->start())))));
  }
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    Reduction const r = Reduce(graph()->NewNode(machine()->Int32Mod(), p0,
                                                Int32Constant(Shl(-1, shift)),
                                                graph()->start()));
    int32_t const mask = static_cast<int32_t>((1U << shift) - 1U);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsPhi(
            MachineRepresentation::kWord32,
            IsInt32Sub(IsInt32Constant(0),
                       IsWord32And(IsInt32Sub(IsInt32Constant(0), p0),
                                   IsInt32Constant(mask))),
            IsWord32And(p0, IsInt32Constant(mask)),
            IsMerge(IsIfTrue(IsBranch(IsInt32LessThan(p0, IsInt32Constant(0)),
                                      graph()->start())),
                    IsIfFalse(IsBranch(IsInt32LessThan(p0, IsInt32Constant(0)),
                                       graph()->start())))));
  }
  TRACED_FOREACH(int32_t, divisor, kInt32Values) {
    if (divisor == 0 || base::bits::IsPowerOfTwo(Abs(divisor))) continue;
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int32Mod(), p0, Int32Constant(divisor), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsInt32Sub(p0, IsInt32Mul(IsTruncatingDiv(p0, Abs(divisor)),
                                          IsInt32Constant(Abs(divisor)))));
  }
}

TEST_F(MachineOperatorReducerTest, Int64ModWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Mod(), Int64Constant(0), p0, graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Mod(), p0, Int64Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Mod(), p0, Int64Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Mod(), p0, Int64Constant(-1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  TRACED_FOREACH(int64_t, dividend, kInt64Values) {
    TRACED_FOREACH(int64_t, divisor, kInt64Values) {
      Reduction const r = Reduce(
          graph()->NewNode(machine()->Int64Mod(), Int64Constant(dividend),
                           Int64Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt64Constant(base::bits::SignedMod64(dividend, divisor)));
    }
  }
  TRACED_FORRANGE(int64_t, shift, 1, 62) {
    Reduction const r = Reduce(
        graph()->NewNode(machine()->Int64Mod(), p0,
                         Int64Constant(int64_t{1} << shift), graph()->start()));
    int64_t const mask = (int64_t{1} << shift) - 1;
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsPhi(
            MachineRepresentation::kWord64,
            IsInt64Sub(IsInt64Constant(0),
                       IsWord64And(IsInt64Sub(IsInt64Constant(0), p0),
                                   IsInt64Constant(mask))),
            IsWord64And(p0, IsInt64Constant(mask)),
            IsMerge(IsIfTrue(IsBranch(IsInt64LessThan(p0, IsInt64Constant(0)),
                                      graph()->start())),
                    IsIfFalse(IsBranch(IsInt64LessThan(p0, IsInt64Constant(0)),
                                       graph()->start())))));
  }
  TRACED_FORRANGE(int64_t, shift, 1, 63) {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Mod(), p0, Int64Constant(Shl(int64_t{-1}, shift)),
        graph()->start()));
    int64_t const mask = static_cast<int64_t>((uint64_t{1} << shift) - 1U);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsPhi(
            MachineRepresentation::kWord64,
            IsInt64Sub(IsInt64Constant(0),
                       IsWord64And(IsInt64Sub(IsInt64Constant(0), p0),
                                   IsInt64Constant(mask))),
            IsWord64And(p0, IsInt64Constant(mask)),
            IsMerge(IsIfTrue(IsBranch(IsInt64LessThan(p0, IsInt64Constant(0)),
                                      graph()->start())),
                    IsIfFalse(IsBranch(IsInt64LessThan(p0, IsInt64Constant(0)),
                                       graph()->start())))));
  }
  TRACED_FOREACH(int64_t, divisor, kInt64Values) {
    if (divisor == 0 || base::bits::IsPowerOfTwo(Abs(divisor))) continue;
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Int64Mod(), p0, Int64Constant(divisor), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsInt64Sub(p0, IsInt64Mul(IsTruncatingDiv64(p0, Abs(divisor)),
                                          IsInt64Constant(Abs(divisor)))));
  }
}

TEST_F(MachineOperatorReducerTest, Int32ModWithParameters) {
  Node* const p0 = Parameter(0);
  Reduction const r =
      Reduce(graph()->NewNode(machine()->Int32Mod(), p0, p0, graph()->start()));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsInt32Constant(0));
}

// -----------------------------------------------------------------------------
// Uint32Mod, Uint64Mod

TEST_F(MachineOperatorReducerTest, Uint32ModWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint32Mod(), p0, Int32Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint32Mod(), Int32Constant(0), p0, graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint32Mod(), p0, Int32Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  TRACED_FOREACH(uint32_t, dividend, kUint32Values) {
    TRACED_FOREACH(uint32_t, divisor, kUint32Values) {
      Reduction const r = Reduce(
          graph()->NewNode(machine()->Uint32Mod(), Uint32Constant(dividend),
                           Uint32Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Constant(base::bit_cast<int32_t>(
                      base::bits::UnsignedMod32(dividend, divisor))));
    }
  }
  TRACED_FORRANGE(uint32_t, shift, 1, 31) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Uint32Mod(), p0,
                                Uint32Constant(1u << shift), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsWord32And(p0, IsInt32Constant(
                                    static_cast<int32_t>((1u << shift) - 1u))));
  }
}

TEST_F(MachineOperatorReducerTest, Uint64ModWithConstant) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Mod(), p0, Int64Constant(0), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Mod(), Int64Constant(0), p0, graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Mod(), p0, Int64Constant(1), graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  TRACED_FOREACH(uint64_t, dividend, kUint64Values) {
    TRACED_FOREACH(uint64_t, divisor, kUint64Values) {
      Reduction const r = Reduce(
          graph()->NewNode(machine()->Uint64Mod(), Uint64Constant(dividend),
                           Uint64Constant(divisor), graph()->start()));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt64Constant(base::bit_cast<int64_t>(
                      base::bits::UnsignedMod64(dividend, divisor))));
    }
  }
  TRACED_FORRANGE(uint64_t, shift, 1, 63) {
    Reduction const r = Reduce(graph()->NewNode(
        machine()->Uint64Mod(), p0, Uint64Constant(uint64_t{1} << shift),
        graph()->start()));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsWord64And(p0, IsInt64Constant(static_cast<int64_t>(
                                    (uint64_t{1} << shift) - 1u))));
  }
}

TEST_F(MachineOperatorReducerTest, Uint32ModWithParameters) {
  Node* const p0 = Parameter(0);
  Reduction const r = Reduce(
      graph()->NewNode(machine()->Uint32Mod(), p0, p0, graph()->start()));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsInt32Constant(0));
}

// -----------------------------------------------------------------------------
// Int32Add, Int64Add

TEST_F(MachineOperatorReducerTest, Int32AddWithInt32SubWithConstantZero) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);

  Reduction const r1 = Reduce(graph()->NewNode(
      machine()->Int32Add(),
      graph()->NewNode(machine()->Int32Sub(), Int32Constant(0), p0), p1));
  ASSERT_TRUE(r1.Changed());
  EXPECT_THAT(r1.replacement(), IsInt32Sub(p1, p0));

  Reduction const r2 = Reduce(graph()->NewNode(
      machine()->Int32Add(), p0,
      graph()->NewNode(machine()->Int32Sub(), Int32Constant(0), p1)));
  ASSERT_TRUE(r2.Changed());
  EXPECT_THAT(r2.replacement(), IsInt32Sub(p0, p1));
}

TEST_F(MachineOperatorReducerTest, Int32AddMergeConstants) {
  Node* const p0 = Parameter(0);

  Reduction const r1 = Reduce(graph()->NewNode(
      machine()->Int32Add(),
      graph()->NewNode(machine()->Int32Add(), p0, Int32Constant(1)),
      Int32Constant(2)));
  ASSERT_TRUE(r1.Changed());
  EXPECT_THAT(r1.replacement(), IsInt32Add(p0, IsInt32Constant(3)));

  Reduction const r2 = Reduce(graph()->NewNode(
      machine()->Int32Add(), Int32Constant(2),
      graph()->NewNode(machine()->Int32Add(), p0, Int32Constant(1))));
  ASSERT_TRUE(r2.Changed());
  EXPECT_THAT(r2.replacement(), IsInt32Add(p0, IsInt32Constant(3)));
}

TEST_F(MachineOperatorReducerTest, Int64AddMergeConstants) {
  Node* const p0 = Parameter(0);

  Reduction const r1 = Reduce(graph()->NewNode(
      machine()->Int64Add(),
      graph()->NewNode(machine()->Int64Add(), p0, Int64Constant(1)),
      Int64Constant(2)));
  ASSERT_TRUE(r1.Changed());
  EXPECT_THAT(r1.replacement(), IsInt64Add(p0, IsInt64Constant(3)));

  Reduction const r2 = Reduce(graph()->NewNode(
      machine()->Int64Add(), Int64Constant(2),
      graph()->NewNode(machine()->Int64Add(), p0, Int64Constant(1))));
  ASSERT_TRUE(r2.Changed());
  EXPECT_THAT(r2.replacement(), IsInt64Add(p0, IsInt64Constant(3)));
}

// -----------------------------------------------------------------------------
// Int32Mul, Int64Mul

TEST_F(MachineOperatorReducerTest, Int32MulMergeConstants) {
  Node* const p0 = Parameter(0);

  Reduction const r1 = Reduce(graph()->NewNode(
      machine()->Int32Mul(),
      graph()->NewNode(machine()->Int32Mul(), p0, Int32Constant(5)),
      Int32Constant(3)));
  ASSERT_TRUE(r1.Changed());
  EXPECT_THAT(r1.replacement(), IsInt32Mul(p0, IsInt32Constant(15)));

  Reduction const r2 = Reduce(graph()->NewNode(
      machine()->Int32Mul(), Int32Constant(5),
      graph()->NewNode(machine()->Int32Mul(), p0, Int32Constant(3))));
  ASSERT_TRUE(r2.Changed());
  EXPECT_THAT(r2.replacement(), IsInt32Mul(p0, IsInt32Constant(15)));
}

TEST_F(MachineOperatorReducerTest, Int64MulMergeConstants) {
  Node* const p0 = Parameter(0);

  Reduction const r1 = Reduce(graph()->NewNode(
      machine()->Int64Mul(),
      graph()->NewNode(machine()->Int64Mul(), p0, Int64Constant(5)),
      Int64Constant(3)));
  ASSERT_TRUE(r1.Changed());
  EXPECT_THAT(r1.replacement(), IsInt64Mul(p0, IsInt64Constant(15)));

  Reduction const r2 = Reduce(graph()->NewNode(
      machine()->Int64Mul(), Int64Constant(5),
      graph()->NewNode(machine()->Int64Mul(), p0, Int64Constant(3))));
  ASSERT_TRUE(r2.Changed());
  EXPECT_THAT(r2.replacement(), IsInt64Mul(p0, IsInt64Constant(15)));
}

// -----------------------------------------------------------------------------
// Int32AddWithOverflow


TEST_F(MachineOperatorReducerTest, Int32AddWithOverflowWithZero) {
  Node* control = graph()->start();
  Node* p0 = Parameter(0);
  {
    Node* add = graph()->NewNode(machine()->Int32AddWithOverflow(),
                                 Int32Constant(0), p0, control);

    Reduction r =
        Reduce(graph()->NewNode(common()->Projection(1), add, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));

    r = Reduce(graph()->NewNode(common()->Projection(0), add, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(p0, r.replacement());
  }
  {
    Node* add = graph()->NewNode(machine()->Int32AddWithOverflow(), p0,
                                 Int32Constant(0), control);

    Reduction r =
        Reduce(graph()->NewNode(common()->Projection(1), add, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));

    r = Reduce(graph()->NewNode(common()->Projection(0), add, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(p0, r.replacement());
  }
}


TEST_F(MachineOperatorReducerTest, Int32AddWithOverflowWithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Node* control = graph()->start();
    TRACED_FOREACH(int32_t, y, kInt32Values) {
      int32_t z;
      Node* add = graph()->NewNode(machine()->Int32AddWithOverflow(),
                                   Int32Constant(x), Int32Constant(y), control);

      Reduction r =
          Reduce(graph()->NewNode(common()->Projection(1), add, control));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Constant(base::bits::SignedAddOverflow32(x, y, &z)));

      r = Reduce(graph()->NewNode(common()->Projection(0), add, control));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Constant(z));
    }
    // This test uses too much memory if we don't periodically reset.
    Reset();
  }
}


// -----------------------------------------------------------------------------
// Int32SubWithOverflow


TEST_F(MachineOperatorReducerTest, Int32SubWithOverflowWithZero) {
  Node* control = graph()->start();
  Node* p0 = Parameter(0);
  Node* add = graph()->NewNode(machine()->Int32SubWithOverflow(), p0,
                               Int32Constant(0), control);

  Reduction r = Reduce(graph()->NewNode(common()->Projection(1), add, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsInt32Constant(0));

  r = Reduce(graph()->NewNode(common()->Projection(0), add, control));
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(p0, r.replacement());
}


TEST_F(MachineOperatorReducerTest, Int32SubWithOverflowWithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Node* control = graph()->start();
    TRACED_FOREACH(int32_t, y, kInt32Values) {
      int32_t z;
      Node* add = graph()->NewNode(machine()->Int32SubWithOverflow(),
                                   Int32Constant(x), Int32Constant(y), control);

      Reduction r =
          Reduce(graph()->NewNode(common()->Projection(1), add, control));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Constant(base::bits::SignedSubOverflow32(x, y, &z)));

      r = Reduce(graph()->NewNode(common()->Projection(0), add, control));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Constant(z));
    }
    // This test uses too much memory if we don't periodically reset.
    Reset();
  }
}


// -----------------------------------------------------------------------------
// Int32MulWithOverflow

TEST_F(MachineOperatorReducerTest, Int32MulWithOverflowWithZero) {
  Node* control = graph()->start();
  Node* p0 = Parameter(0);
  {
    Node* mul = graph()->NewNode(machine()->Int32MulWithOverflow(),
                                 Int32Constant(0), p0, control);

    Reduction r =
        Reduce(graph()->NewNode(common()->Projection(1), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));

    r = Reduce(graph()->NewNode(common()->Projection(0), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
  {
    Node* mul = graph()->NewNode(machine()->Int32MulWithOverflow(), p0,
                                 Int32Constant(0), control);

    Reduction r =
        Reduce(graph()->NewNode(common()->Projection(1), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));

    r = Reduce(graph()->NewNode(common()->Projection(0), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));
  }
}

TEST_F(MachineOperatorReducerTest, Int32MulWithOverflowWithOne) {
  Node* control = graph()->start();
  Node* p0 = Parameter(0);
  {
    Node* mul = graph()->NewNode(machine()->Int32MulWithOverflow(),
                                 Int32Constant(1), p0, control);

    Reduction r =
        Reduce(graph()->NewNode(common()->Projection(1), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));

    r = Reduce(graph()->NewNode(common()->Projection(0), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(p0, r.replacement());
  }
  {
    Node* mul = graph()->NewNode(machine()->Int32MulWithOverflow(), p0,
                                 Int32Constant(1), control);

    Reduction r =
        Reduce(graph()->NewNode(common()->Projection(1), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32Constant(0));

    r = Reduce(graph()->NewNode(common()->Projection(0), mul, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(p0, r.replacement());
  }
}

TEST_F(MachineOperatorReducerTest, Int32MulWithOverflowWithMinusOne) {
  Node* control = graph()->start();
  Node* p0 = Parameter(0);

  {
    Reduction r = Reduce(graph()->NewNode(machine()->Int32MulWithOverflow(),
                                          Int32Constant(-1), p0, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsInt32SubWithOverflow(IsInt32Constant(0), p0));
  }

  {
    Reduction r = Reduce(graph()->NewNode(machine()->Int32MulWithOverflow(), p0,
                                          Int32Constant(-1), control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsInt32SubWithOverflow(IsInt32Constant(0), p0));
  }
}

TEST_F(MachineOperatorReducerTest, Int32MulWithOverflowWithTwo) {
  Node* control = graph()->start();
  Node* p0 = Parameter(0);

  {
    Reduction r = Reduce(graph()->NewNode(machine()->Int32MulWithOverflow(),
                                          Int32Constant(2), p0, control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32AddWithOverflow(p0, p0));
  }

  {
    Reduction r = Reduce(graph()->NewNode(machine()->Int32MulWithOverflow(), p0,
                                          Int32Constant(2), control));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt32AddWithOverflow(p0, p0));
  }
}

TEST_F(MachineOperatorReducerTest, Int32MulWithOverflowWithConstant) {
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Node* control = graph()->start();
    TRACED_FOREACH(int32_t, y, kInt32Values) {
      int32_t z;
      Node* mul = graph()->NewNode(machine()->Int32MulWithOverflow(),
                                   Int32Constant(x), Int32Constant(y), control);

      Reduction r =
          Reduce(graph()->NewNode(common()->Projection(1), mul, control));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32Constant(base::bits::SignedMulOverflow32(x, y, &z)));

      r = Reduce(graph()->NewNode(common()->Projection(0), mul, control));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Constant(z));
    }
    // This test uses too much memory if we don't periodically reset.
    Reset();
  }
}

// -----------------------------------------------------------------------------
// Int64Mul

TEST_F(MachineOperatorReducerTest, Int64MulWithZero) {
  Node* p0 = Parameter(0);
  {
    Node* mul = graph()->NewNode(machine()->Int64Mul(), Int64Constant(0), p0);

    Reduction r = Reduce(mul);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
  {
    Node* mul = graph()->NewNode(machine()->Int64Mul(), p0, Int64Constant(0));

    Reduction r = Reduce(mul);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Constant(0));
  }
}

TEST_F(MachineOperatorReducerTest, Int64MulWithOne) {
  Node* p0 = Parameter(0);
  {
    Node* mul = graph()->NewNode(machine()->Int64Mul(), Int64Constant(1), p0);

    Reduction r = Reduce(mul);
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(p0, r.replacement());
  }
  {
    Node* mul = graph()->NewNode(machine()->Int64Mul(), p0, Int64Constant(1));

    Reduction r = Reduce(mul);
    ASSERT_TRUE(r.Changed());
    EXPECT_EQ(p0, r.replacement());
  }
}

TEST_F(MachineOperatorReducerTest, Int64MulWithMinusOne) {
  Node* p0 = Parameter(0);

  {
    Reduction r =
        Reduce(graph()->NewNode(machine()->Int64Mul(), Int64Constant(-1), p0));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Sub(IsInt64Constant(0), p0));
  }

  {
    Reduction r =
        Reduce(graph()->NewNode(machine()->Int64Mul(), p0, Int64Constant(-1)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsInt64Sub(IsInt64Constant(0), p0));
  }
}

TEST_F(MachineOperatorReducerTest, Int64MulWithPowerOfTwo) {
  Node* p0 = Parameter(0);

  {
    Reduction r =
        Reduce(graph()->NewNode(machine()->Int64Mul(), Int64Constant(8), p0));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsWord64Shl(p0, IsInt64Constant(3)));
  }

  {
    Reduction r =
        Reduce(graph()->NewNode(machine()->Int64Mul(), p0, Int64Constant(8)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsWord64Shl(p0, IsInt64Constant(3)));
  }
}

TEST_F(MachineOperatorReducerTest, Int64MulWithConstant) {
  TRACED_FOREACH(int64_t, x, kInt64Values) {
    TRACED_FOREACH(int64_t, y, kInt64Values) {
      Node* mul = graph()->NewNode(machine()->Int64Mul(), Int64Constant(x),
                                   Int64Constant(y));

      Reduction r = Reduce(mul);
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt64Constant(base::MulWithWraparound(x, y)));
    }
  }
}

// -----------------------------------------------------------------------------
// Int32LessThan

TEST_F(MachineOperatorReducerTest, Int32LessThanWithWord32Or) {
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(int32_t, x, kInt32Values) {
    Node* word32_or =
        graph()->NewNode(machine()->Word32Or(), p0, Int32Constant(x));
    Node* less_than = graph()->NewNode(machine()->Int32LessThan(), word32_or,
                                       Int32Constant(0));
    Reduction r = Reduce(less_than);
    if (x < 0) {
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Constant(1));
    } else {
      ASSERT_FALSE(r.Changed());
    }
  }
}

TEST_F(MachineOperatorReducerTest, Int32LessThanWithWord32SarShiftOutZeros) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  TRACED_FORRANGE(int32_t, shift0, 1, 3) {
    TRACED_FORRANGE(int32_t, shift1, 1, 3) {
      Node* const node =
          graph()->NewNode(machine()->Int32LessThan(),
                           graph()->NewNode(machine()->Word32SarShiftOutZeros(),
                                            p0, Int32Constant(shift0)),
                           graph()->NewNode(machine()->Word32SarShiftOutZeros(),
                                            p1, Int32Constant(shift1)));

      Reduction r = Reduce(node);
      if (shift0 == shift1) {
        ASSERT_TRUE(r.Changed());
        EXPECT_THAT(r.replacement(), IsInt32LessThan(p0, p1));
      } else {
        ASSERT_FALSE(r.Changed());
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Uint32LessThan

TEST_F(MachineOperatorReducerTest, Uint32LessThanWithWord32Sar) {
  Node* const p0 = Parameter(0);
  TRACED_FORRANGE(uint32_t, shift, 1, 3) {
    const uint32_t limit = (kMaxInt >> shift) - 1;
    Node* const node = graph()->NewNode(
        machine()->Uint32LessThan(),
        graph()->NewNode(machine()->Word32Sar(), p0, Uint32Constant(shift)),
        Uint32Constant(limit));

    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsUint32LessThan(
                    p0, IsInt32Constant(static_cast<int32_t>(limit << shift))));
  }
}

TEST_F(MachineOperatorReducerTest, Uint32LessThanWithWord32SarShiftOutZeros) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  TRACED_FORRANGE(int32_t, shift0, 1, 3) {
    TRACED_FORRANGE(int32_t, shift1, 1, 3) {
      Node* const node =
          graph()->NewNode(machine()->Uint32LessThan(),
                           graph()->NewNode(machine()->Word32SarShiftOutZeros(),
                                            p0, Int32Constant(shift0)),
                           graph()->NewNode(machine()->Word32SarShiftOutZeros(),
                                            p1, Int32Constant(shift1)));

      Reduction r = Reduce(node);
      if (shift0 == shift1) {
        ASSERT_TRUE(r.Changed());
        EXPECT_THAT(r.replacement(), IsUint32LessThan(p0, p1));
      } else {
        ASSERT_FALSE(r.Changed());
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Uint64LessThan

TEST_F(MachineOperatorReducerTest, Uint64LessThanWithWord64SarShiftOutZeros) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  TRACED_FORRANGE(int64_t, shift0, 1, 3) {
    TRACED_FORRANGE(int64_t, shift1, 1, 3) {
      Node* const node =
          graph()->NewNode(machine()->Uint64LessThan(),
                           graph()->NewNode(machine()->Word64SarShiftOutZeros(),
                                            p0, Int64Constant(shift0)),
                           graph()->NewNode(machine()->Word64SarShiftOutZeros(),
                                            p1, Int64Constant(shift1)));

      Reduction r = Reduce(node);
      if (shift0 == shift1) {
        ASSERT_TRUE(r.Changed());
        EXPECT_THAT(r.replacement(), IsUint64LessThan(p0, p1));
      } else {
        ASSERT_FALSE(r.Changed());
      }
    }
  }
}

TEST_F(MachineOperatorReducerTest, Uint64LessThanWithUint32Reduction) {
  Node* const p = Parameter(0);
  TRACED_FORRANGE(int64_t, shift, 1, 3) {
    TRACED_FORRANGE(int64_t, rhs, 1, 3) {
      Node* const node = graph()->NewNode(
          machine()->Uint64LessThan(),
          graph()->NewNode(
              machine()->Word64SarShiftOutZeros(),
              graph()->NewNode(machine()->ChangeUint32ToUint64(), p),
              Int64Constant(shift)),
          Int64Constant(rhs));
      Reduction r = Reduce(node);
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsUint32LessThan(
                      p, IsInt32Constant(static_cast<int32_t>(rhs << shift))));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Uint64LessThanWithInt64AddDontReduce) {
  Node* const p0 = Parameter(0);

  TRACED_FOREACH(uint64_t, k1, kUint64Values) {
    TRACED_FOREACH(uint64_t, k2, kUint64Values) {
      Node* node = graph()->NewNode(
          machine()->Uint64LessThan(),
          graph()->NewNode(machine()->Int64Add(), p0, Int64Constant(k1)),
          Int64Constant(k2));
      Reduction r = Reduce(node);
      // Don't reduce because of potential overflow
      ASSERT_FALSE(r.Changed());
    }
  }
}

TEST_F(MachineOperatorReducerTest,
       Uint64LessThanOrEqualWithInt64AddDontReduce) {
  Node* const p0 = Parameter(0);

  TRACED_FOREACH(uint64_t, k1, kUint64Values) {
    TRACED_FOREACH(uint64_t, k2, kUint64Values) {
      uint64_t k1 = 0;
      uint64_t k2 = 18446744073709551615u;
      Node* node = graph()->NewNode(
          machine()->Uint64LessThanOrEqual(),
          graph()->NewNode(machine()->Int64Add(), p0, Int64Constant(k1)),
          Int64Constant(k2));
      Reduction r = Reduce(node);
      if (k2 == 0) {
        // x <= 0  =>  x == 0
        ASSERT_TRUE(r.Changed());
      } else if (k2 == std::numeric_limits<uint64_t>::max()) {
        // x <= Max  =>  true
        ASSERT_TRUE(r.Changed());
      } else {
        // Don't reduce because of potential overflow
        ASSERT_FALSE(r.Changed());
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Int64LessThan

TEST_F(MachineOperatorReducerTest, Int64LessThanWithWord64SarShiftOutZeros) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  TRACED_FORRANGE(int64_t, shift0, 1, 3) {
    TRACED_FORRANGE(int64_t, shift1, 1, 3) {
      Node* const node =
          graph()->NewNode(machine()->Int64LessThan(),
                           graph()->NewNode(machine()->Word64SarShiftOutZeros(),
                                            p0, Int64Constant(shift0)),
                           graph()->NewNode(machine()->Word64SarShiftOutZeros(),
                                            p1, Int64Constant(shift1)));

      Reduction r = Reduce(node);
      if (shift0 == shift1) {
        ASSERT_TRUE(r.Changed());
        EXPECT_THAT(r.replacement(), IsInt64LessThan(p0, p1));
      } else {
        ASSERT_FALSE(r.Changed());
      }
    }
  }
}

TEST_F(MachineOperatorReducerTest, Int64LessThanWithInt32Reduction) {
  Node* const p = Parameter(0);
  TRACED_FORRANGE(int64_t, shift, 1, 3) {
    TRACED_FORRANGE(int64_t, rhs, 1, 3) {
      Node* const node = graph()->NewNode(
          machine()->Int64LessThan(),
          graph()->NewNode(machine()->Word64SarShiftOutZeros(),
                           graph()->NewNode(machine()->ChangeInt32ToInt64(), p),
                           Int64Constant(shift)),
          Int64Constant(rhs));
      Reduction r = Reduce(node);
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsInt32LessThan(
                      p, IsInt32Constant(static_cast<int32_t>(rhs << shift))));
    }
  }
}

// -----------------------------------------------------------------------------
// Float64Mul


TEST_F(MachineOperatorReducerTest, Float64MulWithMinusOne) {
  Node* const p0 = Parameter(0);
  {
    Reduction r = Reduce(
        graph()->NewNode(machine()->Float64Mul(), p0, Float64Constant(-1.0)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Sub(IsFloat64Constant(BitEq(-0.0)), p0));
  }
  {
    Reduction r = Reduce(
        graph()->NewNode(machine()->Float64Mul(), Float64Constant(-1.0), p0));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Sub(IsFloat64Constant(BitEq(-0.0)), p0));
  }
}

TEST_F(MachineOperatorReducerTest, Float64SubMinusZeroMinusX) {
  Node* const p0 = Parameter(0);
  {
    Reduction r = Reduce(
        graph()->NewNode(machine()->Float64Sub(), Float64Constant(-0.0), p0));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Neg(p0));
  }
}

TEST_F(MachineOperatorReducerTest, Float32SubMinusZeroMinusX) {
  Node* const p0 = Parameter(0);
  {
    Reduction r = Reduce(
        graph()->NewNode(machine()->Float32Sub(), Float32Constant(-0.0), p0));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat32Neg(p0));
  }
}

TEST_F(MachineOperatorReducerTest, Float64MulWithTwo) {
  Node* const p0 = Parameter(0);
  {
    Reduction r = Reduce(
        graph()->NewNode(machine()->Float64Mul(), Float64Constant(2.0), p0));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Add(p0, p0));
  }
  {
    Reduction r = Reduce(
        graph()->NewNode(machine()->Float64Mul(), p0, Float64Constant(2.0)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Add(p0, p0));
  }
}

// -----------------------------------------------------------------------------
// Float64Div

TEST_F(MachineOperatorReducerTest, Float64DivWithMinusOne) {
  Node* const p0 = Parameter(0);
  {
    Reduction r = Reduce(
        graph()->NewNode(machine()->Float64Div(), p0, Float64Constant(-1.0)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Neg(p0));
  }
}

TEST_F(MachineOperatorReducerTest, Float64DivWithPowerOfTwo) {
  Node* const p0 = Parameter(0);
  TRACED_FORRANGE(uint64_t, exponent, 1, 0x7FE) {
    base::Double divisor =
        base::Double(exponent << base::Double::kPhysicalSignificandSize);
    if (divisor.value() == 1.0) continue;  // Skip x / 1.0 => x.
    Reduction r = Reduce(graph()->NewNode(machine()->Float64Div(), p0,
                                          Float64Constant(divisor.value())));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Mul(p0, IsFloat64Constant(1.0 / divisor.value())));
  }
}

// -----------------------------------------------------------------------------
// Float64Acos

TEST_F(MachineOperatorReducerTest, Float64AcosWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Acos(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::acos(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Acosh

TEST_F(MachineOperatorReducerTest, Float64AcoshWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Acosh(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::acosh(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Asin

TEST_F(MachineOperatorReducerTest, Float64AsinWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Asin(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::asin(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Asinh

TEST_F(MachineOperatorReducerTest, Float64AsinhWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Asinh(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::asinh(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Atan

TEST_F(MachineOperatorReducerTest, Float64AtanWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Atan(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::atan(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Atanh

TEST_F(MachineOperatorReducerTest, Float64AtanhWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Atanh(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::atanh(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Atan2

TEST_F(MachineOperatorReducerTest, Float64Atan2WithConstant) {
  TRACED_FOREACH(double, y, kFloat64Values) {
    TRACED_FOREACH(double, x, kFloat64Values) {
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Float64Atan2(), Float64Constant(y), Float64Constant(x)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(
          r.replacement(),
          IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::atan2(y, x))));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Float64Atan2WithNaN) {
  Node* const p0 = Parameter(0);
  const double nan = std::numeric_limits<double>::quiet_NaN();
  Node* const nan_node = Float64Constant(nan);
  {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Atan2(), p0, nan_node));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Constant(NanSensitiveDoubleEq(nan)));
  }
  {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Atan2(), nan_node, p0));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Constant(NanSensitiveDoubleEq(nan)));
  }
}

// -----------------------------------------------------------------------------
// Float64Cos

TEST_F(MachineOperatorReducerTest, Float64CosWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Cos(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Constant(NanSensitiveDoubleEq(COS_IMPL(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Cosh

TEST_F(MachineOperatorReducerTest, Float64CoshWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Cosh(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::cosh(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Exp

TEST_F(MachineOperatorReducerTest, Float64ExpWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Exp(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::exp(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Log

TEST_F(MachineOperatorReducerTest, Float64LogWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Log(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::log(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Log1p

TEST_F(MachineOperatorReducerTest, Float64Log1pWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Log1p(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::log1p(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Pow

TEST_F(MachineOperatorReducerTest, Float64PowWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    TRACED_FOREACH(double, y, kFloat64Values) {
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Float64Pow(), Float64Constant(x), Float64Constant(y)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsFloat64Constant(NanSensitiveDoubleEq(math::pow(x, y))));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Float64PowWithZeroExponent) {
  Node* const p0 = Parameter(0);
  {
    Reduction const r = Reduce(
        graph()->NewNode(machine()->Float64Pow(), p0, Float64Constant(-0.0)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Constant(1.0));
  }
  {
    Reduction const r = Reduce(
        graph()->NewNode(machine()->Float64Pow(), p0, Float64Constant(0.0)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Constant(1.0));
  }
}

// -----------------------------------------------------------------------------
// Float64Sin

TEST_F(MachineOperatorReducerTest, Float64SinWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Sin(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Constant(NanSensitiveDoubleEq(SIN_IMPL(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Sinh

TEST_F(MachineOperatorReducerTest, Float64SinhWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Sinh(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::sinh(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Tan

TEST_F(MachineOperatorReducerTest, Float64TanWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Tan(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::tan(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64Tanh

TEST_F(MachineOperatorReducerTest, Float64TanhWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction const r =
        Reduce(graph()->NewNode(machine()->Float64Tanh(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(
        r.replacement(),
        IsFloat64Constant(NanSensitiveDoubleEq(base::ieee754::tanh(x))));
  }
}

// -----------------------------------------------------------------------------
// Float64InsertLowWord32

TEST_F(MachineOperatorReducerTest, Float64InsertLowWord32WithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    TRACED_FOREACH(uint32_t, y, kUint32Values) {
      Reduction const r =
          Reduce(graph()->NewNode(machine()->Float64InsertLowWord32(),
                                  Float64Constant(x), Uint32Constant(y)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(
          r.replacement(),
          IsFloat64Constant(BitEq(base::bit_cast<double>(
              (base::bit_cast<uint64_t>(x) & uint64_t{0xFFFFFFFF00000000}) |
              y))));
    }
  }
}


// -----------------------------------------------------------------------------
// Float64InsertHighWord32


TEST_F(MachineOperatorReducerTest, Float64InsertHighWord32WithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    TRACED_FOREACH(uint32_t, y, kUint32Values) {
      Reduction const r =
          Reduce(graph()->NewNode(machine()->Float64InsertHighWord32(),
                                  Float64Constant(x), Uint32Constant(y)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsFloat64Constant(BitEq(base::bit_cast<double>(
                      (base::bit_cast<uint64_t>(x) & uint64_t{0xFFFFFFFF}) |
                      (static_cast<uint64_t>(y) << 32)))));
    }
  }
}


// -----------------------------------------------------------------------------
// Float64Equal

TEST_F(MachineOperatorReducerTest, Float64EqualWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    TRACED_FOREACH(double, y, kFloat64Values) {
      Reduction const r = Reduce(graph()->NewNode(
          machine()->Float64Equal(), Float64Constant(x), Float64Constant(y)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Constant(x == y));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Float64EqualWithFloat32Conversions) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  Reduction const r = Reduce(graph()->NewNode(
      machine()->Float64Equal(),
      graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0),
      graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p1)));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsFloat32Equal(p0, p1));
}


TEST_F(MachineOperatorReducerTest, Float64EqualWithFloat32Constant) {
  Node* const p0 = Parameter(0);
  TRACED_FOREACH(float, x, kFloat32Values) {
    Reduction r = Reduce(graph()->NewNode(
        machine()->Float64Equal(),
        graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0),
        Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat32Equal(p0, IsFloat32Constant(x)));
  }
}


// -----------------------------------------------------------------------------
// Float64LessThan

TEST_F(MachineOperatorReducerTest, Float64LessThanWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    TRACED_FOREACH(double, y, kFloat64Values) {
      Reduction const r =
          Reduce(graph()->NewNode(machine()->Float64LessThan(),
                                  Float64Constant(x), Float64Constant(y)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Constant(x < y));
    }
  }
}

TEST_F(MachineOperatorReducerTest, Float64LessThanWithFloat32Conversions) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  Reduction const r = Reduce(graph()->NewNode(
      machine()->Float64LessThan(),
      graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0),
      graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p1)));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsFloat32LessThan(p0, p1));
}


TEST_F(MachineOperatorReducerTest, Float64LessThanWithFloat32Constant) {
  Node* const p0 = Parameter(0);
  {
    TRACED_FOREACH(float, x, kFloat32Values) {
      Reduction r = Reduce(graph()->NewNode(
          machine()->Float64LessThan(),
          graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0),
          Float64Constant(x)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsFloat32LessThan(p0, IsFloat32Constant(x)));
    }
  }
  {
    TRACED_FOREACH(float, x, kFloat32Values) {
      Reduction r = Reduce(graph()->NewNode(
          machine()->Float64LessThan(), Float64Constant(x),
          graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsFloat32LessThan(IsFloat32Constant(x), p0));
    }
  }
}


// -----------------------------------------------------------------------------
// Float64LessThanOrEqual

TEST_F(MachineOperatorReducerTest, Float64LessThanOrEqualWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    TRACED_FOREACH(double, y, kFloat64Values) {
      Reduction const r =
          Reduce(graph()->NewNode(machine()->Float64LessThanOrEqual(),
                                  Float64Constant(x), Float64Constant(y)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(), IsInt32Constant(x <= y));
    }
  }
}

TEST_F(MachineOperatorReducerTest,
       Float64LessThanOrEqualWithFloat32Conversions) {
  Node* const p0 = Parameter(0);
  Node* const p1 = Parameter(1);
  Reduction const r = Reduce(graph()->NewNode(
      machine()->Float64LessThanOrEqual(),
      graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0),
      graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p1)));
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsFloat32LessThanOrEqual(p0, p1));
}


TEST_F(MachineOperatorReducerTest, Float64LessThanOrEqualWithFloat32Constant) {
  Node* const p0 = Parameter(0);
  {
    TRACED_FOREACH(float, x, kFloat32Values) {
      Reduction r = Reduce(graph()->NewNode(
          machine()->Float64LessThanOrEqual(),
          graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0),
          Float64Constant(x)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsFloat32LessThanOrEqual(p0, IsFloat32Constant(x)));
    }
  }
  {
    TRACED_FOREACH(float, x, kFloat32Values) {
      Reduction r = Reduce(graph()->NewNode(
          machine()->Float64LessThanOrEqual(), Float64Constant(x),
          graph()->NewNode(machine()->ChangeFloat32ToFloat64(), p0)));
      ASSERT_TRUE(r.Changed());
      EXPECT_THAT(r.replacement(),
                  IsFloat32LessThanOrEqual(IsFloat32Constant(x), p0));
    }
  }
}


// -----------------------------------------------------------------------------
// Float64RoundDown

TEST_F(MachineOperatorReducerTest, Float64RoundDownWithConstant) {
  TRACED_FOREACH(double, x, kFloat64Values) {
    Reduction r = Reduce(graph()->NewNode(
        machine()->Float64RoundDown().placeholder(), Float64Constant(x)));
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(), IsFloat64Constant(std::floor(x)));
  }
}

// -----------------------------------------------------------------------------
// Store

TEST_F(MachineOperatorReducerTest, StoreRepWord8WithWord32And) {
  const StoreRepresentation rep(MachineRepresentation::kWord8, kNoWriteBarrier);
  Node* const base = Parameter(0);
  Node* const index = Parameter(1);
  Node* const value = Parameter(2);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FOREACH(uint32_t, x, kUint32Values) {
    Node* const node =
        graph()->NewNode(machine()->Store(rep), base, index,
                         graph()->NewNode(machine()->Word32And(), value,
                                          Uint32Constant(x | 0xFFu)),
                         effect, control);

    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsStore(rep, base, index, value, effect, control));
  }
}


TEST_F(MachineOperatorReducerTest, StoreRepWord8WithWord32SarAndWord32Shl) {
  const StoreRepresentation rep(MachineRepresentation::kWord8, kNoWriteBarrier);
  Node* const base = Parameter(0);
  Node* const index = Parameter(1);
  Node* const value = Parameter(2);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FORRANGE(int32_t, x, 1, 24) {
    Node* const node = graph()->NewNode(
        machine()->Store(rep), base, index,
        graph()->NewNode(
            machine()->Word32Sar(),
            graph()->NewNode(machine()->Word32Shl(), value, Int32Constant(x)),
            Int32Constant(x)),
        effect, control);

    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsStore(rep, base, index, value, effect, control));
  }
}


TEST_F(MachineOperatorReducerTest, StoreRepWord16WithWord32And) {
  const StoreRepresentation rep(MachineRepresentation::kWord16,
                                kNoWriteBarrier);
  Node* const base = Parameter(0);
  Node* const index = Parameter(1);
  Node* const value = Parameter(2);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FOREACH(uint32_t, x, kUint32Values) {
    Node* const node =
        graph()->NewNode(machine()->Store(rep), base, index,
                         graph()->NewNode(machine()->Word32And(), value,
                                          Uint32Constant(x | 0xFFFFu)),
                         effect, control);

    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsStore(rep, base, index, value, effect, control));
  }
}


TEST_F(MachineOperatorReducerTest, StoreRepWord16WithWord32SarAndWord32Shl) {
  const StoreRepresentation rep(MachineRepresentation::kWord16,
                                kNoWriteBarrier);
  Node* const base = Parameter(0);
  Node* const index = Parameter(1);
  Node* const value = Parameter(2);
  Node* const effect = graph()->start();
  Node* const control = graph()->start();
  TRACED_FORRANGE(int32_t, x, 1, 16) {
    Node* const node = graph()->NewNode(
        machine()->Store(rep), base, index,
        graph()->NewNode(
            machine()->Word32Sar(),
            graph()->NewNode(machine()->Word32Shl(), value, Int32Constant(x)),
            Int32Constant(x)),
        effect, control);

    Reduction r = Reduce(node);
    ASSERT_TRUE(r.Changed());
    EXPECT_THAT(r.replacement(),
                IsStore(rep, base, index, value, effect, control));
  }
}

TEST_F(MachineOperatorReducerTest, Select) {
  static const std::vector<const Operator*> ops = {
      machine()->Float32Select().op(), machine()->Float64Select().op(),
      machine()->Word32Select().op(), machine()->Word64Select().op()};

  TRACED_FOREACH(const Operator*, op, ops) {
    Node* arg0 = Parameter(0);
    Node* arg1 = Parameter(1);

    Node* select_true = graph()->NewNode(op, Int32Constant(1), arg0, arg1);
    Reduction r_true = Reduce(select_true);
    ASSERT_TRUE(r_true.Changed());
    EXPECT_THAT(r_true.replacement(), IsParameter(0));

    Node* select_false = graph()->NewNode(op, Int32Constant(0), arg0, arg1);
    Reduction r_false = Reduce(select_false);
    ASSERT_TRUE(r_false.Changed());
    EXPECT_THAT(r_false.replacement(), IsParameter(1));
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```