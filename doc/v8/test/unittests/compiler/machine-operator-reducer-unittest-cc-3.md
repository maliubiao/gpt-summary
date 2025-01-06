Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the desired output.

**1. Understanding the Goal:**

The request asks for a functional description of a V8 source code file (`machine-operator-reducer-unittest.cc`), specifically focusing on its purpose, potential JavaScript relevance, code logic, and common programming errors it might address. It also emphasizes this is the *final* part of a larger series, requiring a summary.

**2. Initial Scan and Key Observations:**

* **Filename:** `machine-operator-reducer-unittest.cc`. The "unittest" suffix immediately signals this is a testing file. "machine-operator-reducer" strongly suggests it's testing a component responsible for optimizing machine-level operations.
* **Includes:** The file includes various V8 headers, including those related to the compiler (`compiler/`), machine code generation (`codegen/`, `machine/`), and testing (`test/unittests/`). This reinforces the idea of compiler optimization testing.
* **Test Fixture:** The code uses `TEST_F(MachineOperatorReducerTest, ...)` which is a Google Test construct. This confirms it's a unit test suite for the `MachineOperatorReducerTest` class.
* **Focus on Operations:** The individual tests often involve creating `Node` objects representing machine operations like `Word32Or`, `Int32LessThan`, `Float64Mul`, etc. The `Reduce()` function is central, suggesting the reducer's job is to simplify or transform these operations.
* **Assertions and Expectations:**  `ASSERT_TRUE(r.Changed())` and `EXPECT_THAT(r.replacement(), ...)` are used to verify that the `Reduce()` function modifies the operation and that the resulting replacement is as expected. This is the core of testing the reducer's transformations.
* **Specific Operation Tests:**  The tests cover a wide range of machine operations and their potential simplifications, often with constant operands or specific bitwise manipulations.

**3. Deeper Analysis and Deduction:**

* **Reducer Functionality:**  The `MachineOperatorReducer` appears to be a compiler optimization pass. It examines machine-level operations and tries to replace them with simpler or more efficient equivalents. The tests demonstrate specific reduction rules.
* **JavaScript Relevance:** While the code is C++, the operations being optimized directly correspond to low-level operations performed when executing JavaScript code. For instance, `Int32LessThan` is a fundamental comparison, `Float64Mul` is multiplication, and bitwise operations are often used in JavaScript, especially in performance-sensitive areas.
* **Code Logic and Transformations:** Each `TEST_F` function demonstrates a specific reduction. The tests set up an initial machine operation graph (represented by `Node` objects) and then call `Reduce()`. The assertions check if the reduction occurred and if the result is the expected simplified operation. The `TRACED_FOREACH` and `TRACED_FORRANGE` macros indicate the tests are run with various input values to ensure correctness across a range of scenarios.
* **Common Programming Errors:** The reductions often address inefficiencies or potential issues that might arise from naive code generation. For example, multiplying by -1 can be optimized to a negation, or comparing values after certain bitwise operations can be simplified.

**4. Structuring the Output:**

Based on the analysis, the output needs to address the specific points raised in the request:

* **Functionality:** Clearly state that it tests the `MachineOperatorReducer`, which optimizes machine-level operations in the V8 compiler. Provide examples of the types of optimizations performed.
* **Torque:**  Confirm it's not a Torque file based on the `.cc` extension.
* **JavaScript Relevance:**  Explain the connection to JavaScript execution by providing concrete JavaScript examples that would lead to the machine operations being tested. Illustrate how the optimizations benefit JavaScript performance.
* **Code Logic and Examples:** Give specific examples of input and output for a few representative tests (e.g., `Int32LessThanWithWord32Or`, `Float64MulWithMinusOne`). Explain the reasoning behind the reduction.
* **Common Programming Errors:** Describe how the reductions can prevent performance issues or address potentially less efficient code patterns a programmer might inadvertently create. Focus on the *outcome* of the optimization, not necessarily direct JavaScript coding errors.
* **Summary (Part 4):** Emphasize the testing nature of the file and its role in ensuring the correctness of the machine operator reducer.

**5. Refinement and Language:**

* Use clear and concise language.
* Avoid overly technical jargon where possible, or explain it briefly.
* Use code examples effectively to illustrate the connection between C++ and JavaScript.
* Ensure the summary accurately reflects the overall purpose of the file.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the C++ implementation details. However, the prompt specifically asks for JavaScript relevance. I would then need to consciously shift the focus to explaining *why* these C++ tests are important for JavaScript performance. This would involve thinking about what JavaScript constructs translate to these machine operations. Similarly, when discussing "common programming errors,"  it's more effective to frame it in terms of potential inefficiencies in generated machine code, rather than direct JavaScript syntax errors.

By following this systematic approach, combining code analysis with an understanding of the request's intent, the detailed and accurate output can be generated.
这是对v8源代码文件 `v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 的分析，这是第 4 部分，总结其功能。

**功能归纳:**

`v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 文件包含了针对 V8 编译器中 `MachineOperatorReducer` 组件的单元测试。`MachineOperatorReducer` 的主要功能是**在编译过程中优化机器操作**，通过识别可以被简化或替换为更高效形式的特定模式。

该文件中的测试用例旨在验证 `MachineOperatorReducer` 是否能够正确地执行各种优化转换。  这些转换通常涉及以下几个方面：

* **常量折叠和传播:**  如果操作的输入是常量，则在编译时计算结果并替换为常量。
* **代数简化:**  利用代数恒等式简化表达式，例如将乘以 -1 替换为取反。
* **位运算优化:**  识别和简化涉及位运算的模式，例如通过移位操作来优化乘除法。
* **比较运算优化:**  简化比较操作，例如在已知输入范围的情况下。
* **浮点运算优化:**  针对特定的浮点运算进行优化，例如乘以或除以 2 的幂。
* **类型转换优化:**  在某些情况下，可以消除或简化类型转换操作。

**与 JavaScript 的功能关系:**

`MachineOperatorReducer` 的优化直接影响 JavaScript 代码的执行效率。当 V8 编译 JavaScript 代码时，它会将其转换为一系列底层的机器操作。`MachineOperatorReducer` 的优化减少了需要执行的机器操作的数量，或者将它们替换为更快的操作，从而提高了 JavaScript 代码的执行速度。

**JavaScript 示例说明 (与本部分代码相关的):**

虽然本部分代码主要关注底层的机器操作，但我们可以通过一些 JavaScript 例子来理解其背后的优化逻辑：

* **整数比较和位运算:**
   ```javascript
   function test(x) {
     if ((x | 10) < 0) { //  Word32Or 和 Int32LessThan 的组合
       return 1;
     }
     return 0;
   }
   ```
   `MachineOperatorReducerTest` 中的 `Int32LessThanWithWord32Or` 测试用例就验证了当 `x | 10` 的结果已知为负数时，比较操作会被优化。

* **浮点数乘法和除法:**
   ```javascript
   function multiplyByMinusOne(y) {
     return y * -1; // Float64MulWithMinusOne 测试用例相关
   }

   function divideByTwo(z) {
     return z / 2; // Float64DivWithPowerOfTwo 测试用例相关
   }
   ```
   `Float64MulWithMinusOne` 测试确保了乘以 -1 的操作被优化为取反。 `Float64DivWithPowerOfTwo` 测试确保了除以 2 的幂的操作被优化为乘以其倒数。

* **三角函数和数学函数:**
   ```javascript
   function calculateCos(angle) {
     return Math.cos(angle); // Float64CosWithConstant 等测试用例相关
   }
   ```
   `Float64CosWithConstant` 等测试用例验证了当这些数学函数的参数是常量时，结果会在编译时被计算出来。

**代码逻辑推理和假设输入/输出:**

**示例 1: `Int32LessThanWithWord32Or`**

* **假设输入:**  一个 `Int32LessThan` 节点，其左操作数是一个 `Word32Or` 节点，右操作数是一个常量 0。`Word32Or` 的一个输入是参数 `p0`，另一个输入是一个常量 `x`。
* **代码逻辑:** `MachineOperatorReducer` 会尝试简化这个比较。如果 `x` 的值使得 `p0 | x` 总是小于 0，那么 `Int32LessThan` 节点可以被替换为常量 1 (true)。
* **假设输入/输出:**
    * **输入:** `Int32LessThan(Word32Or(p0, 0xFFFFFFFF), 0)`
    * **输出:** `Int32Constant(1)` (因为任何数与 `0xFFFFFFFF` 进行 OR 运算结果都是 -1，小于 0)
    * **输入:** `Int32LessThan(Word32Or(p0, 10), 0)`
    * **输出:**  如果 `p0` 的范围已知，可能可以简化，否则不改变。例如，如果已知 `p0` 始终小于 -11，则输出为 `Int32Constant(1)`。

**示例 2: `Float64MulWithMinusOne`**

* **假设输入:** 一个 `Float64Mul` 节点，其中一个操作数是参数 `p0`，另一个操作数是常量 -1.0。
* **代码逻辑:**  `MachineOperatorReducer` 识别出乘以 -1.0 等价于取反操作。
* **假设输入/输出:**
    * **输入:** `Float64Mul(p0, -1.0)`
    * **输出:** `Float64Sub(-0.0, p0)` (因为 IEEE 754 中 -0.0 的存在，这里用减法来实现取反)

**涉及用户常见的编程错误:**

`MachineOperatorReducer` 的优化在一定程度上可以缓解一些用户编程上的低效写法，但它主要关注的是编译器生成的中间代码的优化，而不是直接纠正用户的 JavaScript 代码错误。  然而，理解其优化原理可以帮助开发者编写更高效的 JavaScript 代码。

例如，考虑以下情况：

```javascript
function inefficientMultiply(x) {
  return x * 2.0;
}

function efficientMultiply(x) {
  return x + x;
}
```

`MachineOperatorReducerTest` 中的 `Float64MulWithTwo` 测试表明，即使开发者写成乘 2.0 的形式，编译器也能够将其优化为加法，因为加法通常比乘法更快。  这并不意味着第一种写法是“错误”，而是说编译器能够进行优化。

另一个例子是多次进行相同的计算：

```javascript
function calculate(y) {
  const a = Math.cos(0); // 假设在循环或频繁调用的函数中
  return y + a;
}
```

`Float64CosWithConstant` 等测试表明，如果 `Math.cos()` 的参数是常量，那么这个计算在编译时就会完成，避免了运行时的重复计算。

**总结 (第 4 部分):**

作为系列的一部分，`v8/test/unittests/compiler/machine-operator-reducer-unittest.cc` 的第 4 部分继续深入测试 `MachineOperatorReducer` 组件的各种优化能力。  它涵盖了整数和浮点数的比较、位运算、算术运算以及数学函数的优化。  这些测试用例验证了在特定的输入模式下，`MachineOperatorReducer` 能够正确地将机器操作简化为更高效的形式，从而提升最终生成的机器码的性能，并间接提升 JavaScript 代码的执行效率。  该文件通过大量的具体测试用例，确保了 `MachineOperatorReducer` 的正确性和有效性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/machine-operator-reducer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/machine-operator-reducer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
e::MulWithWraparound(x, y)));
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