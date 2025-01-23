Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/unittests/compiler/machine-operator-reducer-unittest.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The file name and the test structure (`TEST_F`) strongly suggest this is a unit test file for a component called `machine-operator-reducer`. This reducer likely performs optimizations or simplifications on machine-level operations within V8's compiler.

2. **Analyze the Test Cases:**  Each `TEST_F` block focuses on a specific machine operation (e.g., `Int64DivWithConstant`, `Uint32DivWithConstant`, `Int32ModWithConstant`, `Int32AddWithOverflowWithZero`, etc.). The structure within each test case is usually:
    * Set up input nodes (often using `Parameter()` or constant nodes like `Int32Constant()`).
    * Create a node representing the operation being tested using `graph()->NewNode()`.
    * Call `Reduce()` on the created node. This is the action of the `machine-operator-reducer` being tested.
    * Assert that a change occurred (`ASSERT_TRUE(r.Changed())`).
    * Check the result of the reduction (`EXPECT_THAT(r.replacement(), ...)`), verifying the simplified or optimized form of the operation.

3. **Categorize the Operations:**  The tests cover various arithmetic and bitwise operations: division (`Div`), modulo (`Mod`), addition (`Add`), subtraction (`Sub`), multiplication (`Mul`), shifts (`Shl`, `Shr`, `Sar`), and operations with overflow checks (`AddWithOverflow`, `SubWithOverflow`, `MulWithOverflow`). The tests also differentiate between signed (`Int`) and unsigned (`Uint`) integers and different bit widths (32-bit, 64-bit).

4. **Infer the Reducer's Functionality:** Based on the tests, the `machine-operator-reducer` aims to optimize machine operations in the following ways:
    * **Constant Folding:** When both operands are constants, the operation is performed at compile time, and the result is a constant node (e.g., adding two constant integers).
    * **Identity/Zero Element Elimination:** Operations involving identity elements (like multiplying by 1) or zero elements (like adding 0) are simplified.
    * **Strength Reduction:**  More expensive operations are replaced with cheaper equivalents. For example, multiplication by a power of two is replaced with a left shift. Division by a constant might be transformed into a sequence of other operations (as seen with the more complex `Int64DivWithConstant` cases).
    * **Handling Special Cases:** The reducer handles edge cases like division by zero, or specific values like -1.
    * **Overflow Handling:** For operations with overflow, the reducer might directly compute the overflow flag when both inputs are constants.

5. **Relate to JavaScript (if applicable):**  Since V8 is the JavaScript engine, these low-level optimizations directly impact how JavaScript code is executed. Arithmetic operations in JavaScript are eventually translated into these machine-level operations. Examples are needed to show how a JavaScript snippet might be optimized by these reductions.

6. **Provide Code Logic Reasoning (with assumptions):**  For some of the more complex reductions (like `Int64DivWithConstant`), it's possible to deduce the transformation logic by analyzing the expected output. This involves making assumptions about the underlying machine instructions and optimization strategies.

7. **Illustrate Common Programming Errors:** Some of the reductions address common errors, such as division by zero. Demonstrating these errors in JavaScript clarifies the importance of these optimizations.

8. **Address the File Type and Name:** Explicitly confirm that the file is a C++ unit test and not a Torque file based on its extension (`.cc`).

9. **Synthesize the Information:** Organize the findings into a clear and structured explanation covering the different aspects requested by the user. Use clear headings and bullet points.

10. **Review and Refine:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Check if all parts of the prompt have been addressed. For instance, make sure to mention that this is part 3 of a 4-part series and summarize the functionality accordingly. Since this is part 3, focus on the integer arithmetic and logic operations covered in this specific snippet.
```cpp
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
                                 Int
### 提示词
```
这是目录为v8/test/unittests/compiler/machine-operator-reducer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/machine-operator-reducer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
                  IsInt64Constant(bas
```