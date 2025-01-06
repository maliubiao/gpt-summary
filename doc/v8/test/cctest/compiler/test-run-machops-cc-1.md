Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/compiler/test-run-machops.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Function:** The code defines several `TEST` functions. Each test seems to focus on a specific machine operation (machop) or a control flow construct (like `Goto`, `Branch`, `Loop`, `Switch`).

2. **Understand the Testing Framework:** The code uses a testing framework (`TEST(...)`). It appears to involve creating a `RawMachineAssemblerTester` object and using its methods to construct a sequence of machine operations. The `CHECK_EQ` macro is used to assert that the actual output matches the expected output.

3. **Analyze Individual Tests:**
    * **Arithmetic Operations:**  Look for tests with names like `RunInt64AddP`, `RunInt64SubWithOverflowP`, `RunInt32AddP`, etc. These tests are checking the behavior of specific arithmetic operations, potentially including overflow conditions.
    * **Control Flow:** Tests like `RunGoto`, `RunBranch`, `RunLoop`, `RunSwitch` are testing different control flow mechanisms.
    * **Phi Nodes:** Tests involving "Phi" (e.g., `RunDiamondPhiConst`, `RunLoopPhiParam`) are related to how data is merged at control flow join points.
    * **Bitwise Operations:** Look for operations like `Word32Shl`, `Word32Sar`, etc., often used in conjunction with arithmetic operations to test combined behavior.
    * **Comparisons:** Tests might use operations like `Word32Equal`, `Word32LessThan` to check comparison results.

4. **Look for Patterns:**  Notice the use of `FOR_INT64_INPUTS`, `FOR_INT32_INPUTS`, `FOR_UINT32_INPUTS`, and `FOR_UINT32_SHIFTS`. This indicates the tests are running the generated code with a range of input values to ensure correctness.

5. **Consider Edge Cases and Overflow:** Pay attention to tests with "Overflow" in their name, as they specifically check how the operations handle situations where the result exceeds the maximum or minimum representable value.

6. **Infer High-Level Functionality:**  The overall purpose of this file is to test the correctness of the machine code generation within the V8 compiler. It verifies that the basic machine operations and control flow constructs are implemented correctly.

7. **Address Specific User Queries:**
    * **.tq extension:** The code doesn't have a `.tq` extension, so it's not a Torque file.
    * **JavaScript relation:** While this C++ code directly tests machine operations, these operations underpin the execution of JavaScript code. Think of JavaScript arithmetic, comparisons, and control flow – these C++ tests are verifying the low-level implementation of those features.
    * **Code Logic Inference:** For tests with clear arithmetic operations, it's possible to provide example inputs and outputs based on the expected behavior of those operations (e.g., addition, subtraction, shifts).
    * **Common Programming Errors:** Overflow handling is a common source of errors in programming. The overflow tests in the code relate to this.
    * **Summarize Functionality (for part 2):** Focus on the specific operations and control flow elements covered in the provided snippet.

**Self-Correction/Refinement:**

* Initially, I might just say it tests machine operations. However, it's important to be more specific about *which* machine operations and control flow constructs are being tested in this particular snippet.
* I need to ensure that the JavaScript examples are relevant to the underlying machine operations being tested.
* When providing input/output examples, I should focus on the tests that perform basic arithmetic or logical operations for clarity.这是 V8 引擎中 `test-run-machops.cc` 文件的第二部分，主要功能是 **测试 V8 编译器生成的机器码中各种算术和逻辑运算的正确性，以及控制流语句的正确执行**。

**功能归纳（第二部分）：**

这部分代码主要测试了以下功能：

* **带溢出检查的 64 位整数运算:**  包括加法 (`RunInt64AddWithOverflowP`)、减法 (`RunInt64SubWithOverflowP`, `RunInt64SubWithOverflowImm`, `RunInt64SubWithOverflowInBranchP`) 和乘法 (`RunInt64MulWithOverflowImm`, `RunInt64MulWithOverflowInBranchP`)。这些测试验证了在进行 64 位整数运算时，溢出标志是否被正确设置和处理。
* **64 位整数的加法与移位操作组合 (`RunInt64AddShift`):** 测试了先进行移位操作，再与另一个 64 位整数相加的组合操作。
* **基本的控制流语句:** 包括 `goto` (`RunGoto`, `RunGotoMultiple`) 和 `branch` (`RunBranch`, `RunDiamond2`)。这些测试验证了程序跳转的正确性。
* **循环结构 (`RunLoop`):**  测试了基本的 `while` 循环的执行。
* **Phi 节点在控制流中的使用:** 通过 `RunDiamondPhiConst`, `RunDiamondPhiNumber`, `RunDiamondPhiString`, `RunDiamondPhiParam`, `RunLoopPhiConst`, `RunLoopPhiParam`, `RunLoopPhiInduction` 等测试，验证了 Phi 节点在合并不同执行路径上的值时的正确性。
* **循环中的自增/自减操作:** 包括整数 (`RunLoopIncrement`, `RunLoopIncrement2`, `RunLoopIncrement3`, `RunLoopDecrement`) 和浮点数 (`RunLoopIncrementFloat32`, `RunLoopIncrementFloat64`) 的自增/自减操作。
* **`switch` 语句 (`RunSwitch1`, `RunSwitch2`, `RunSwitch3`, `RunSwitch4`):**  测试了 `switch` 语句在不同 case 下的正确跳转和执行。
* **32 位整数加法 (`RunInt32AddP`):**  测试了基本的 32 位整数加法运算。
* **32 位整数加法与其他位运算/比较运算的组合:**  包括与 `Word32Equal` (`RunInt32AddAndWord32EqualP`, `RunInt32AddAndWord32EqualImm`)、`Word32NotEqual` (`RunInt32AddAndWord32NotEqualP`, `RunInt32AddAndWord32NotEqualImm`)、`Word32Sar` (算术右移, `RunInt32AddAndWord32SarP`)、`Word32Shl` (左移, `RunInt32AddAndWord32ShlP`)、`Word32Shr` (逻辑右移, `RunInt32AddAndWord32ShrP`) 的组合。
* **在 `branch` 语句中使用 32 位整数加法 (`RunInt32AddInBranch`):** 测试了在条件判断语句中使用加法运算的情况。
* **在比较运算中使用 32 位整数加法 (`RunInt32AddInComparison`):** 测试了将加法运算的结果用于比较的情况。

**关于其他问题：**

* **.tq 结尾:**  `v8/test/cctest/compiler/test-run-machops.cc` 以 `.cc` 结尾，所以它是 **C++ 源代码**，而不是 V8 Torque 源代码。
* **与 Javascript 的关系:** 这些测试直接测试的是 V8 编译器生成的 **机器码** 的正确性。虽然不是直接的 JavaScript 代码，但这些机器码是 **JavaScript 代码执行的基础**。例如，JavaScript 中的加法运算符 `+` 在底层就会被编译成类似的机器指令。

   ```javascript
   // JavaScript 示例
   let a = 10;
   let b = 5;
   let sum = a + b; // 这行代码在底层会涉及到类似的机器码加法操作
   console.log(sum);

   if (a > b) { // 这行代码在底层会涉及到类似的机器码比较和分支操作
       console.log("a is greater than b");
   }

   let count = 0;
   while (count < 3) { // 这行代码在底层会涉及到类似的机器码循环和比较操作
       console.log(count);
       count++;
   }
   ```

* **代码逻辑推理 (假设输入与输出):**

   **`TEST(RunInt64AddWithOverflowP)` 示例:**

   * **假设输入 `i`:** `INT64_MAX` (64 位有符号整数的最大值)
   * **假设输入 `j`:** `1`
   * **预期输出 (溢出标志):** `1` (表示溢出)
   * **预期输出 (运算结果，存储在 `actual_val`):**  根据有符号溢出的行为，结果会回绕，可能是 `INT64_MIN` (64 位有符号整数的最小值)。

   **`TEST(RunInt32AddP)` 示例:**

   * **假设输入 `i`:** `10`
   * **假设输入 `j`:** `20`
   * **预期输出:** `30`

   * **假设输入 `i`:** `2147483647` (32 位有符号整数的最大值)
   * **假设输入 `j`:** `1`
   * **预期输出:** `-2147483648` (发生有符号溢出，结果回绕)

* **用户常见的编程错误:**

   * **整数溢出:**  很多程序员可能没有意识到整数运算会发生溢出，导致计算结果不正确。例如，在 `RunInt64AddWithOverflowP` 中测试的就是这种情况。

     ```c++
     // C++ 示例 (类似问题)
     int max_int = std::numeric_limits<int>::max();
     int result = max_int + 1; // 发生溢出，result 的值可能不是期望的
     ```

   * **位运算的优先级错误:**  在复杂的表达式中，可能会因为不熟悉位运算符的优先级而导致计算错误。例如，在测试 `RunInt32AddAndWord32EqualP` 时，确保了加法和等于比较的正确组合。

     ```c++
     // C++ 示例 (类似问题)
     int a = 5;
     int b = 3;
     if (a & 2 == 0) { // 错误，== 的优先级高于 &，应该写成 (a & 2) == 0
         // ...
     }
     ```

**总结来说，`v8/test/cctest/compiler/test-run-machops.cc` 的这一部分是 V8 引擎编译器的重要测试，它细致地检验了编译器在生成处理各种算术、逻辑运算以及控制流的机器码时的正确性，确保了 JavaScript 代码在底层能够可靠地执行。**

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
CHECK_EQ(expected, bt.call(i, j));
    }
  }
}


TEST(RunInt64SubWithOverflowP) {
  int64_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* add = m.Int64SubWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
  bt.AddReturn(ovf);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int64_t expected_val;
      int expected_ovf = base::bits::SignedSubOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt64SubWithOverflowImm) {
  int64_t actual_val = -1, expected_val = 0;
  FOR_INT64_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* add = m.Int64SubWithOverflow(m.Int64Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow64(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* add = m.Int64SubWithOverflow(m.Parameter(0), m.Int64Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow64(j, i, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT64_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int64SubWithOverflow(m.Int64Constant(i), m.Int64Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedSubOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt64SubWithOverflowInBranchP) {
  int constant = 911999;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* sub = m.Int64SubWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, sub);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int64Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, sub);
  Node* truncated = m.TruncateInt64ToInt32(val);
  bt.AddReturn(truncated);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int32_t expected = constant;
      int64_t result;
      if (!base::bits::SignedSubOverflow64(i, j, &result)) {
        expected = static_cast<int32_t>(result);
      }
      CHECK_EQ(expected, static_cast<int32_t>(bt.call(i, j)));
    }
  }
}

TEST(RunInt64MulWithOverflowImm) {
  int64_t actual_val = -1, expected_val = 0;
  FOR_INT64_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* mul = m.Int64MulWithOverflow(m.Int64Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, mul);
      Node* ovf = m.Projection(1, mul);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow64(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* mul = m.Int64MulWithOverflow(m.Parameter(0), m.Int64Constant(i));
      Node* val = m.Projection(0, mul);
      Node* ovf = m.Projection(1, mul);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow64(j, i, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT64_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* mul =
          m.Int64MulWithOverflow(m.Int64Constant(i), m.Int64Constant(j));
      Node* val = m.Projection(0, mul);
      Node* ovf = m.Projection(1, mul);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedMulOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}

TEST(RunInt64MulWithOverflowInBranchP) {
  int constant = 911999;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* mul = m.Int64MulWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, mul);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int64Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, mul);
  Node* truncated = m.TruncateInt64ToInt32(val);
  bt.AddReturn(truncated);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int32_t expected = constant;
      int64_t result;
      if (!base::bits::SignedMulOverflow64(i, j, &result)) {
        expected = static_cast<int32_t>(result);
      }
      CHECK_EQ(expected, static_cast<int32_t>(bt.call(i, j)));
    }
  }
}

static int64_t RunInt64AddShift(bool is_left, int64_t add_left,
                                int64_t add_right, int64_t shift_left,
                                int64_t shift_right) {
  RawMachineAssemblerTester<int64_t> m;
  Node* shift =
      m.Word64Shl(m.Int64Constant(shift_left), m.Int64Constant(shift_right));
  Node* add = m.Int64Add(m.Int64Constant(add_left), m.Int64Constant(add_right));
  Node* dlsa = is_left ? m.Int64Add(shift, add) : m.Int64Add(add, shift);
  m.Return(dlsa);
  return m.Call();
}

TEST(RunInt64AddShift) {
  struct Test_case {
    int64_t add_left, add_right, shift_left, shift_right, expected;
  };

  Test_case tc[] = {
      {20, 22, 4, 2, 58},
      {20, 22, 4, 1, 50},
      {20, 22, 1, 6, 106},
      {INT64_MAX - 2, 1, 1, 1,
       INT64_MIN},  // INT64_MAX - 2 + 1 + (1 << 1), overflow.
  };
  const size_t tc_size = sizeof(tc) / sizeof(Test_case);

  for (size_t i = 0; i < tc_size; ++i) {
    CHECK_EQ(tc[i].expected,
             RunInt64AddShift(false, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
    CHECK_EQ(tc[i].expected,
             RunInt64AddShift(true, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
  }
}

// TODO(titzer): add tests that run 64-bit integer operations.
#endif  // V8_TARGET_ARCH_64_BIT


TEST(RunGoto) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 99999;

  RawMachineLabel next;
  m.Goto(&next);
  m.Bind(&next);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunGotoMultiple) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 9999977;

  RawMachineLabel labels[10];
  for (size_t i = 0; i < arraysize(labels); i++) {
    m.Goto(&labels[i]);
    m.Bind(&labels[i]);
  }
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunBranch) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 999777;

  RawMachineLabel blocka, blockb;
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(0 - constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunDiamond2) {
  RawMachineAssemblerTester<int32_t> m;

  int constant = 995666;

  RawMachineLabel blocka, blockb, end;
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);
  m.Bind(&end);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunLoop) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 999555;

  RawMachineLabel header, body, exit;
  m.Goto(&header);
  m.Bind(&header);
  m.Branch(m.Int32Constant(0), &body, &exit);
  m.Bind(&body);
  m.Goto(&header);
  m.Bind(&exit);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


template <typename R>
static void BuildDiamondPhi(RawMachineAssemblerTester<R>* m, Node* cond_node,
                            MachineRepresentation rep, Node* true_node,
                            Node* false_node) {
  RawMachineLabel blocka, blockb, end;
  m->Branch(cond_node, &blocka, &blockb);
  m->Bind(&blocka);
  m->Goto(&end);
  m->Bind(&blockb);
  m->Goto(&end);

  m->Bind(&end);
  Node* phi = m->Phi(rep, true_node, false_node);
  m->Return(phi);
}


TEST(RunDiamondPhiConst) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int false_val = 0xFF666;
  int true_val = 0x00DDD;
  Node* true_node = m.Int32Constant(true_val);
  Node* false_node = m.Int32Constant(false_val);
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kWord32, true_node,
                  false_node);
  CHECK_EQ(false_val, m.Call(0));
  CHECK_EQ(true_val, m.Call(1));
}


TEST(RunDiamondPhiNumber) {
  RawMachineAssemblerTester<Tagged<Object>> m(MachineType::Int32());
  double false_val = -11.1;
  double true_val = 200.1;
  Node* true_node = m.NumberConstant(true_val);
  Node* false_node = m.NumberConstant(false_val);
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kTagged, true_node,
                  false_node);
  m.CheckNumber(false_val, m.Call(0));
  m.CheckNumber(true_val, m.Call(1));
}


TEST(RunDiamondPhiString) {
  RawMachineAssemblerTester<Tagged<Object>> m(MachineType::Int32());
  const char* false_val = "false";
  const char* true_val = "true";
  Node* true_node = m.StringConstant(true_val);
  Node* false_node = m.StringConstant(false_val);
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kTagged, true_node,
                  false_node);
  m.CheckString(false_val, m.Call(0));
  m.CheckString(true_val, m.Call(1));
}


TEST(RunDiamondPhiParam) {
  RawMachineAssemblerTester<int32_t> m(
      MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kWord32,
                  m.Parameter(1), m.Parameter(2));
  int32_t c1 = 0x260CB75A;
  int32_t c2 = 0xCD3E9C8B;
  int result = m.Call(0, c1, c2);
  CHECK_EQ(c2, result);
  result = m.Call(1, c1, c2);
  CHECK_EQ(c1, result);
}


TEST(RunLoopPhiConst) {
  RawMachineAssemblerTester<int32_t> m;
  int true_val = 0x44000;
  int false_val = 0x00888;

  Node* cond_node = m.Int32Constant(0);
  Node* true_node = m.Int32Constant(true_val);
  Node* false_node = m.Int32Constant(false_val);

  // x = false_val; while(false) { x = true_val; } return x;
  RawMachineLabel body, header, end;

  m.Goto(&header);
  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, false_node, true_node);
  m.Branch(cond_node, &body, &end);
  m.Bind(&body);
  m.Goto(&header);
  m.Bind(&end);
  m.Return(phi);

  CHECK_EQ(false_val, m.Call());
}


TEST(RunLoopPhiParam) {
  RawMachineAssemblerTester<int32_t> m(
      MachineType::Int32(), MachineType::Int32(), MachineType::Int32());

  RawMachineLabel blocka, blockb, end;

  m.Goto(&blocka);

  m.Bind(&blocka);
  Node* phi =
      m.Phi(MachineRepresentation::kWord32, m.Parameter(1), m.Parameter(2));
  Node* cond =
      m.Phi(MachineRepresentation::kWord32, m.Parameter(0), m.Int32Constant(0));
  m.Branch(cond, &blockb, &end);

  m.Bind(&blockb);
  m.Goto(&blocka);

  m.Bind(&end);
  m.Return(phi);

  int32_t c1 = 0xA81903B4;
  int32_t c2 = 0x5A1207DA;
  int result = m.Call(0, c1, c2);
  CHECK_EQ(c1, result);
  result = m.Call(1, c1, c2);
  CHECK_EQ(c2, result);
}


TEST(RunLoopPhiInduction) {
  RawMachineAssemblerTester<int32_t> m;

  int false_val = 0x10777;

  // x = false_val; while(false) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* false_node = m.Int32Constant(false_val);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, false_node, false_node);
  m.Branch(m.Int32Constant(0), &body, &end);

  m.Bind(&body);
  Node* add = m.Int32Add(phi, m.Int32Constant(1));
  phi->ReplaceInput(1, add);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(phi);

  CHECK_EQ(false_val, m.Call());
}


TEST(RunLoopIncrement) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = 0; while(x ^ param) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* zero = m.Int32Constant(0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Branch(m.WordXor(phi, bt.param0), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Add(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(11, bt.call(11, 0));
  CHECK_EQ(110, bt.call(110, 0));
  CHECK_EQ(176, bt.call(176, 0));
}


TEST(RunLoopIncrement2) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = 0; while(x < param) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* zero = m.Int32Constant(0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Branch(m.Int32LessThan(phi, bt.param0), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Add(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(11, bt.call(11, 0));
  CHECK_EQ(110, bt.call(110, 0));
  CHECK_EQ(176, bt.call(176, 0));
  CHECK_EQ(0, bt.call(-200, 0));
}


TEST(RunLoopIncrement3) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = 0; while(x < param) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* zero = m.Int32Constant(0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Branch(m.Uint32LessThan(phi, bt.param0), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Add(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(11, bt.call(11, 0));
  CHECK_EQ(110, bt.call(110, 0));
  CHECK_EQ(176, bt.call(176, 0));
  CHECK_EQ(200, bt.call(200, 0));
}


TEST(RunLoopDecrement) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = param; while(x) { x--; } return x;
  RawMachineLabel header, body, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* phi =
      m.Phi(MachineRepresentation::kWord32, bt.param0, m.Int32Constant(0));
  m.Branch(phi, &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Sub(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(0, bt.call(11, 0));
  CHECK_EQ(0, bt.call(110, 0));
  CHECK_EQ(0, bt.call(197, 0));
}


TEST(RunLoopIncrementFloat32) {
  RawMachineAssemblerTester<int32_t> m;

  // x = -3.0f; while(x < 10f) { x = x + 0.5f; } return (int) (double) x;
  RawMachineLabel header, body, end;
  Node* minus_3 = m.Float32Constant(-3.0f);
  Node* ten = m.Float32Constant(10.0f);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kFloat32, minus_3, ten);
  m.Branch(m.Float32LessThan(phi, ten), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Float32Add(phi, m.Float32Constant(0.5f)));
  m.Goto(&header);

  m.Bind(&end);
  m.Return(m.ChangeFloat64ToInt32(m.ChangeFloat32ToFloat64(phi)));

  CHECK_EQ(10, m.Call());
}


TEST(RunLoopIncrementFloat64) {
  RawMachineAssemblerTester<int32_t> m;

  // x = -3.0; while(x < 10) { x = x + 0.5; } return (int) x;
  RawMachineLabel header, body, end;
  Node* minus_3 = m.Float64Constant(-3.0);
  Node* ten = m.Float64Constant(10.0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kFloat64, minus_3, ten);
  m.Branch(m.Float64LessThan(phi, ten), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Float64Add(phi, m.Float64Constant(0.5)));
  m.Goto(&header);

  m.Bind(&end);
  m.Return(m.ChangeFloat64ToInt32(phi));

  CHECK_EQ(10, m.Call());
}


TEST(RunSwitch1) {
  RawMachineAssemblerTester<int32_t> m;

  int constant = 11223344;

  RawMachineLabel block0, block1, def, end;
  RawMachineLabel* case_labels[] = {&block0, &block1};
  int32_t case_values[] = {0, 1};
  m.Switch(m.Int32Constant(0), &def, case_values, case_labels,
           arraysize(case_labels));
  m.Bind(&block0);
  m.Goto(&end);
  m.Bind(&block1);
  m.Goto(&end);
  m.Bind(&def);
  m.Goto(&end);
  m.Bind(&end);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunSwitch2) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());

  RawMachineLabel blocka, blockb, blockc;
  RawMachineLabel* case_labels[] = {&blocka, &blockb};
  int32_t case_values[] = {std::numeric_limits<int32_t>::min(),
                           std::numeric_limits<int32_t>::max()};
  m.Switch(m.Parameter(0), &blockc, case_values, case_labels,
           arraysize(case_labels));
  m.Bind(&blocka);
  m.Return(m.Int32Constant(-1));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(1));
  m.Bind(&blockc);
  m.Return(m.Int32Constant(0));

  CHECK_EQ(1, m.Call(std::numeric_limits<int32_t>::max()));
  CHECK_EQ(-1, m.Call(std::numeric_limits<int32_t>::min()));
  for (int i = -100; i < 100; i += 25) {
    CHECK_EQ(0, m.Call(i));
  }
}


TEST(RunSwitch3) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());

  RawMachineLabel blocka, blockb, blockc;
  RawMachineLabel* case_labels[] = {&blocka, &blockb};
  int32_t case_values[] = {std::numeric_limits<int32_t>::min() + 0,
                           std::numeric_limits<int32_t>::min() + 1};
  m.Switch(m.Parameter(0), &blockc, case_values, case_labels,
           arraysize(case_labels));
  m.Bind(&blocka);
  m.Return(m.Int32Constant(0));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(1));
  m.Bind(&blockc);
  m.Return(m.Int32Constant(2));

  CHECK_EQ(0, m.Call(std::numeric_limits<int32_t>::min() + 0));
  CHECK_EQ(1, m.Call(std::numeric_limits<int32_t>::min() + 1));
  for (int i = -100; i < 100; i += 25) {
    CHECK_EQ(2, m.Call(i));
  }
}


TEST(RunSwitch4) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());

  const size_t kNumCases = 512;
  const size_t kNumValues = kNumCases + 1;
  int32_t values[kNumValues];
  m.main_isolate()->random_number_generator()->NextBytes(values,
                                                         sizeof(values));
  RawMachineLabel end, def;
  int32_t case_values[kNumCases];
  RawMachineLabel* case_labels[kNumCases];
  Node* results[kNumValues];
  for (size_t i = 0; i < kNumCases; ++i) {
    case_values[i] = static_cast<int32_t>(i);
    case_labels[i] = m.main_zone()->New<RawMachineLabel>();
  }
  m.Switch(m.Parameter(0), &def, case_values, case_labels,
           arraysize(case_labels));
  for (size_t i = 0; i < kNumCases; ++i) {
    m.Bind(case_labels[i]);
    results[i] = m.Int32Constant(values[i]);
    m.Goto(&end);
  }
  m.Bind(&def);
  results[kNumCases] = m.Int32Constant(values[kNumCases]);
  m.Goto(&end);
  m.Bind(&end);
  const int num_results = static_cast<int>(arraysize(results));
  Node* phi =
      m.AddNode(m.common()->Phi(MachineRepresentation::kWord32, num_results),
                num_results, results);
  m.Return(phi);

  for (size_t i = 0; i < kNumValues; ++i) {
    CHECK_EQ(values[i], m.Call(static_cast<int>(i)));
  }
}


TEST(RunInt32AddP) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  bt.AddReturn(m.Int32Add(bt.param0, bt.param1));

  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      // Use uint32_t because signed overflow is UB in C.
      int expected = static_cast<int32_t>(static_cast<uint32_t>(i) +
                                          static_cast<uint32_t>(j));
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}


TEST(RunInt32AddAndWord32EqualP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Equal(m.Parameter(1), m.Parameter(2))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j == k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Word32Equal(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i == j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32EqualImm) {
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
  m.Return(m.Int32Add(m.Int32Constant(i),
                      m.Word32Equal(m.Parameter(0), m.Parameter(1))));
  FOR_INT32_INPUTS(j) {
    FOR_INT32_INPUTS(k) {
      // Use uint32_t because signed overflow is UB in C.
      int32_t const expected =
          base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j == k));
      CHECK_EQ(expected, m.Call(j, k));
    }
  }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
      m.Return(m.Int32Add(m.Word32Equal(m.Int32Constant(i), m.Parameter(0)),
                          m.Parameter(1)));
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i == j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32NotEqualP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32NotEqual(m.Parameter(1), m.Parameter(2))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j != k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Word32NotEqual(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i != j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32NotEqualImm) {
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
  m.Return(m.Int32Add(m.Int32Constant(i),
                      m.Word32NotEqual(m.Parameter(0), m.Parameter(1))));
  FOR_INT32_INPUTS(j) {
    FOR_INT32_INPUTS(k) {
      // Use uint32_t because signed overflow is UB in C.
      int32_t const expected =
          base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j != k));
      CHECK_EQ(expected, m.Call(j, k));
    }
  }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
      m.Return(m.Int32Add(m.Word32NotEqual(m.Int32Constant(i), m.Parameter(0)),
                          m.Parameter(1)));
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i != j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32SarP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Int32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Sar(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = i + (j >> shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Word32Sar(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = (i >> shift) + k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32ShlP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Shl(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = i + (j << shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Word32Shl(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = (i << shift) + k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32ShrP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Shr(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = i + (j >> shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Word32Shr(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = (i >> shift) + k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32AddInBranch) {
  static const int32_t constant = 987654321;
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32Equal(m.Int32Add(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32NotEqual(m.Int32Add(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32Equal(m.Int32Add(m.Int32Constant(i), m.Parameter(0)),
                             m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32NotEqual(m.Int32Add(m.Int32Constant(i), m.Parameter(0)),
                                m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    RawMachineAssemblerTester<void> m;
    const Operator* shops[] = {m.machine()->Word32Sar(),
                               m.machine()->Word32Shl(),
                               m.machine()->Word32Shr()};
    for (size_t n = 0; n < arraysize(shops); n++) {
      RawMachineAssemblerTester<int32_t> t(
          MachineType::Uint32(), MachineType::Int32(), MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      t.Branch(t.Word32Equal(t.Int32Add(t.Parameter(0),
                                        t.AddNode(shops[n], t.Parameter(1),
                                                  t.Parameter(2))),
                             t.Int32Constant(0)),
               &blocka, &blockb);
      t.Bind(&blocka);
      t.Return(t.Int32Constant(constant));
      t.Bind(&blockb);
      t.Return(t.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(i) {
        FOR_INT32_INPUTS(j) {
          FOR_UINT32_SHIFTS(shift) {
            int32_t right;
            switch (shops[n]->opcode()) {
              default:
                UNREACHABLE();
              case IrOpcode::kWord32Sar:
                right = j >> shift;
                break;
              case IrOpcode::kWord32Shl:
                right = static_cast<uint32_t>(j) << shift;
                break;
              case IrOpcode::kWord32Shr:
                right = static_cast<uint32_t>(j) >> shift;
                break;
            }
            int32_t expected = ((i + right) == 0) ? constant : 0 - constant;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunInt32AddInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Add(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i + j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Int32Add(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i + j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Retu
"""


```