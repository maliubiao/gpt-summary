Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. The code is from a V8 test file (`v8/test/cctest/compiler/test-run-machops.cc`).

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename and the presence of `TEST` macros strongly suggest this is a unit test file. It's testing the behavior of machine-level operations within the V8 compiler.

2. **Analyze the `TEST` blocks:** Each `TEST` block focuses on a specific machine operation or a combination of operations. Look for patterns in how these tests are structured. They generally:
    - Create a `RawMachineAssemblerTester` (or a variation). This class likely allows for constructing machine code snippets.
    - Define input values using `FOR_INT32_INPUTS`, `FOR_UINT32_INPUTS`, `FOR_FLOAT32_INPUTS`, etc. These macros iterate through various input values to ensure comprehensive testing.
    - Perform operations using methods like `m.Word32Or()`, `m.Int32Add()`, `m.Float32Add()`, etc. These correspond to machine-level instructions.
    - Use `CHECK_EQ` or `CHECK_FLOAT_EQ`/`CHECK_DOUBLE_EQ` to compare the actual result of the operation with the expected result.

3. **Infer the functionality of each `TEST`:** Based on the operations used within each `TEST` block, determine what aspect of the machine operations is being tested. For example, `TEST(RunWord32OrP)` is testing the "Word32Or" operation.

4. **Check for language features:** The code uses C++ and V8-specific testing infrastructure. The prompt asks about Torque. There's no `.tq` suffix, so this isn't Torque code. It also asks about JavaScript relevance. Since these are machine-level operations, they underpin JavaScript execution, but the tests themselves aren't direct JavaScript code.

5. **Look for code logic and error examples:**  Some tests involve conditional branching (`m.Branch`). These can be used to illustrate logic flow. The tests themselves are designed to avoid user errors but understanding what the tested operations do can help prevent errors.

6. **Consolidate the findings:** Summarize the overall purpose of the file and the specific functionalities tested in this particular part.

**Mental Walkthrough of the Code:**

- The code heavily uses the `RawMachineAssemblerTester` to create small snippets of machine code.
- It tests various bitwise operations (`Word32Or`, `Word32Xor`, `Word32Shl`, `Word32Shr`, `Word32Sar`, `Word32Ror`, `Word32BitwiseNot`).
- It tests integer arithmetic (`Int32Neg`).
- It tests how these operations behave in comparisons (`Word32Equal`) and conditional branches (`m.Branch`).
- It tests floating-point arithmetic (`Float32Add`, `Float32Sub`, `Float32Mul`, `Float32Div`, `Float64Add`, `Float64Sub`, `Float64Mul`, `Float64Div`, `Float64Mod`).
- It tests the `Float32Max`, `Float32Min`, `Float64Max`, `Float64Min` operations.
- There are tests for "dead nodes" and "dead binops", which likely check that the compiler can optimize away unused computations.

**Constraint Checklist and Confidence Score:**

1. List functionality? Yes.
2. Check for `.tq`? Yes, it's not a Torque file.
3. Relation to Javascript and examples? Yes, the underlying machine operations are crucial for JavaScript. Example provided.
4. Code logic and examples? Yes, examples with branching are present.
5. User programming errors? Yes, examples provided.
6. This is part 4/8? Acknowledged.
7. Summarize functionality? Yes.

Confidence Score: 5/5 - I can confidently address all parts of the request.
这是 V8 源代码文件 `v8/test/cctest/compiler/test-run-machops.cc` 的第 4 部分，它是一个 C++ 文件，用于测试 V8 编译器中 **机器操作 (machine operations)** 的执行情况。

**功能归纳:**

这部分代码主要测试以下方面的机器指令的正确执行：

* **位运算 (Bitwise Operations):**
    * **`Word32Or` (按位或):**  测试 `Word32Or` 操作在不同场景下的行为，包括直接运算、在比较中的使用以及在条件分支中的使用。
    * **`Word32Xor` (按位异或):** 测试 `Word32Xor` 操作的直接运算以及在比较和条件分支中的使用。
    * **`Word32Shl` (左移):** 测试 `Word32Shl` 操作的直接运算以及在比较中的使用。
    * **`Word32Shr` (逻辑右移):** 测试 `Word32Shr` 操作的直接运算以及在比较和条件分支中的使用。
    * **`Word32Sar` (算术右移):** 测试 `Word32Sar` 操作的直接运算以及在比较中的使用。
    * **`Word32Ror` (循环右移):** 测试 `Word32Ror` 操作的直接运算以及在比较中的使用。
    * **`Word32BitwiseNot` (按位取反):** 测试 `Word32BitwiseNot` 操作。
* **算术运算 (Arithmetic Operations):**
    * **`Int32Neg` (取负):** 测试 `Int32Neg` 操作。
* **组合运算:**
    * 测试比较操作 (`Word32Equal`) 与位移操作 (`Word32Sar`, `Word32Shl`, `Word32Shr`) 的结合使用。
* **处理无效节点 (Dead Nodes):** 测试编译器是否能正确处理和优化掉未使用的节点。
* **处理无效的二进制操作 (Dead Int32 Binops):** 测试编译器是否能正确处理和优化掉结果未被使用的二进制操作。
* **浮点数运算 (Float Operations):**
    * **`Float32Add` (单精度浮点数加法):** 测试 `Float32Add` 操作。
    * **`Float32Sub` (单精度浮点数减法):** 测试 `Float32Sub` 操作。
    * **`Float32Neg` (单精度浮点数取负):** 测试 `Float32Neg` 操作。
    * **`Float32Mul` (单精度浮点数乘法):** 测试 `Float32Mul` 操作。
    * **`Float32Div` (单精度浮点数除法):** 测试 `Float32Div` 操作。
    * **`Float64Add` (双精度浮点数加法):** 测试 `Float64Add` 操作。
    * **`Float64Sub` (双精度浮点数减法):** 测试 `Float64Sub` 操作。
    * **`Float64Neg` (双精度浮点数取负):** 测试 `Float64Neg` 操作。
    * **`Float64Mul` (双精度浮点数乘法):** 测试 `Float64Mul` 操作。
    * **`Float64Div` (双精度浮点数除法):** 测试 `Float64Div` 操作。
    * **`Float64Mod` (双精度浮点数取模):** 测试 `Float64Mod` 操作。
* **处理无效的浮点数二进制操作 (Dead Float Binops):** 测试编译器是否能正确处理和优化掉结果未被使用的浮点数二进制操作。
* **浮点数运算的各种组合形式:**
    * 使用 `Float32BinopTester` 和 `Float64BinopTester` 测试浮点数加法、减法、最大值和最小值操作的不同调用方式。

**关于 .tq 结尾:**

`v8/test/cctest/compiler/test-run-machops.cc` 以 `.cc` 结尾，表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

这些机器操作是 JavaScript 代码在底层执行时所依赖的基本指令。例如，JavaScript 中的位运算符、算术运算符以及浮点数运算最终会被编译成类似的机器操作。

**JavaScript 举例 (与 `Word32Or` 相关):**

```javascript
function testOr(a, b) {
  return a | b;
}

console.log(testOr(5, 3)); // 输出 7 (二进制 0101 | 0011 = 0111)

// 代码中的一些测试用例模拟了这种情况：
let i = 5;
let j = 3;
let expected = i | j; // 在 JavaScript 中执行按位或

// V8 的测试会确保编译器生成的机器码对于 i | j 操作能够得到正确的结果 (expected)。
```

**代码逻辑推理 (以 `TEST(RunWord32OrInBranch)` 为例):**

**假设输入:**

* `i = 5` (二进制 `0101`)
* `j = 3` (二进制 `0011`)
* `constant = 987654321`

**执行流程:**

1. `m.Word32Or(bt.param0, bt.param1)` 计算 `i | j`，结果为 `7` (二进制 `0111`)。
2. `m.Word32Equal(..., m.Int32Constant(0))` 比较 `7` 是否等于 `0`。结果为 `false`。
3. 由于比较结果为 `false`，程序跳转到 `blockb`。
4. `bt.AddReturn(m.Int32Constant(0 - constant))` 返回 `0 - 987654321`，即 `-987654321`。

**预期输出:** `-987654321`

**假设输入:**

* `i = 0` (二进制 `0000`)
* `j = 0` (二进制 `0000`)
* `constant = 987654321`

**执行流程:**

1. `m.Word32Or(bt.param0, bt.param1)` 计算 `i | j`，结果为 `0` (二进制 `0000`)。
2. `m.Word32Equal(..., m.Int32Constant(0))` 比较 `0` 是否等于 `0`。结果为 `true`。
3. 由于比较结果为 `true`，程序跳转到 `blocka`。
4. `bt.AddReturn(m.Int32Constant(constant))` 返回 `987654321`。

**预期输出:** `987654321`

**用户常见的编程错误 (与位运算相关):**

* **误用逻辑运算符和位运算符:** 常见的错误是将逻辑 AND (`&&`) 或逻辑 OR (`||`) 误用于位运算，导致意想不到的结果。
    ```javascript
    let a = 5; // 二进制 0101
    let b = 3; // 二进制 0011

    if (a & b) { // 正确：按位与，结果为 1 (真)
      console.log("Both bits are set");
    }

    if (a && b) { // 错误：逻辑与，结果为 true (因为 5 和 3 都是真值)
      console.log("Both values are truthy");
    }
    ```
* **忽视有符号数的右移:**  对于有符号数，逻辑右移 (`>>>=`) 和算术右移 (`>>`) 的行为不同。算术右移会保留符号位。
    ```javascript
    let negativeNumber = -10; // 二进制 (补码) ...11110110

    console.log(negativeNumber >> 2);  // 算术右移，结果仍然是负数
    console.log(negativeNumber >>> 2); // 逻辑右移，结果变成一个很大的正数
    ```
* **位移量超出范围:** 位移量应该在 0 到 31 之间 (对于 32 位整数)。超出此范围的行为可能不一致或产生意外结果。

总而言之，这部分测试代码专注于验证 V8 编译器在生成和执行各种基本的整数和浮点数机器操作时的正确性，确保 JavaScript 代码能够在底层得到正确的执行。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
) {
      FOR_INT32_INPUTS(j) {
        int32_t expected = (i | j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32Equal(m.Word32Or(m.Int32Constant(i), m.Parameter(0)),
                             m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_INT32_INPUTS(j) {
        int32_t expected = (i | j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32NotEqual(m.Word32Or(m.Int32Constant(i), m.Parameter(0)),
                                m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_INT32_INPUTS(j) {
        int32_t expected = (i | j) != 0 ? constant : 0 - constant;
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
      t.Branch(t.Word32Equal(t.Word32Or(t.Parameter(0),
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
            int32_t expected = ((i | right) == 0) ? constant : 0 - constant;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunWord32OrInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Word32Or(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i | j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Word32Or(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i | j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32Equal(m.Word32Or(m.Int32Constant(i), m.Parameter(0)),
                         m.Int32Constant(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = (i | j) == 0;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(m.Word32Equal(m.Word32Or(m.Parameter(0), m.Int32Constant(i)),
                             m.Int32Constant(0)));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (j | i) == 0;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
}


TEST(RunWord32XorP) {
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32Xor(m.Int32Constant(i), m.Parameter(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = i ^ j;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Word32Xor(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i ^ j;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Word32Xor(bt.param0, m.Word32BitwiseNot(bt.param1)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int32_t expected = i ^ ~(j);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Word32Xor(m.Word32BitwiseNot(bt.param0), bt.param1));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int32_t expected = ~(i) ^ j;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Xor(m.Int32Constant(i), m.Word32BitwiseNot(m.Parameter(0))));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i ^ ~(j);
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
}


TEST(RunWord32XorInBranch) {
  static const uint32_t constant = 987654321;
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32Equal(m.Word32Xor(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i ^ j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32NotEqual(m.Word32Xor(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i ^ j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32Equal(m.Word32Xor(m.Int32Constant(i), m.Parameter(0)),
                             m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i ^ j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32NotEqual(m.Word32Xor(m.Int32Constant(i), m.Parameter(0)),
                                m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i ^ j) != 0 ? constant : 0 - constant;
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
      t.Branch(t.Word32Equal(t.Word32Xor(t.Parameter(0),
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
            int32_t expected = ((i ^ right) == 0) ? constant : 0 - constant;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunWord32ShlP) {
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(m.Word32Shl(m.Parameter(0), m.Int32Constant(shift)));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = j << shift;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Word32Shl(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = i << shift;
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
}


TEST(RunWord32ShlInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Word32Shl(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = 0 == (i << shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Word32Shl(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = 0 == (i << shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Equal(m.Int32Constant(0),
                        m.Word32Shl(m.Parameter(0), m.Int32Constant(shift))));
      FOR_UINT32_INPUTS(i) {
        uint32_t expected = 0 == (i << shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Equal(m.Word32Shl(m.Parameter(0), m.Int32Constant(shift)),
                        m.Int32Constant(0)));
      FOR_UINT32_INPUTS(i) {
        uint32_t expected = 0 == (i << shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
}


TEST(RunWord32ShrP) {
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(m.Word32Shr(m.Parameter(0), m.Int32Constant(shift)));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = j >> shift;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Word32Shr(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = i >> shift;
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
    CHECK_EQ(0x00010000u, bt.call(0x80000000, 15));
  }
}

TEST(RunWordShiftInBranch) {
  static const uint32_t constant = 987654321;
  FOR_UINT32_SHIFTS(shift) {
    RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
    RawMachineLabel blocka, blockb;
    m.Branch(m.Word32Equal(m.Word32Shl(m.Parameter(0), m.Int32Constant(shift)),
                           m.Int32Constant(0)),
             &blocka, &blockb);
    m.Bind(&blocka);
    m.Return(m.Int32Constant(constant));
    m.Bind(&blockb);
    m.Return(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      int32_t expected = ((i << shift) == 0) ? constant : 0 - constant;
      CHECK_EQ(expected, m.Call(i));
    }
  }
  FOR_UINT32_SHIFTS(shift) {
    RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
    RawMachineLabel blocka, blockb;
    m.Branch(m.Word32Equal(m.Word32Shr(m.Parameter(0), m.Int32Constant(shift)),
                           m.Int32Constant(0)),
             &blocka, &blockb);
    m.Bind(&blocka);
    m.Return(m.Int32Constant(constant));
    m.Bind(&blockb);
    m.Return(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      int32_t expected = ((i >> shift) == 0) ? constant : 0 - constant;
      CHECK_EQ(expected, m.Call(i));
    }
  }
  FOR_UINT32_SHIFTS(shift) {
    RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
    RawMachineLabel blocka, blockb;
    m.Branch(m.Word32Equal(m.Word32Sar(m.Parameter(0), m.Int32Constant(shift)),
                           m.Int32Constant(0)),
             &blocka, &blockb);
    m.Bind(&blocka);
    m.Return(m.Int32Constant(constant));
    m.Bind(&blockb);
    m.Return(m.Int32Constant(0 - constant));
    FOR_INT32_INPUTS(i) {
      int32_t expected = ((i >> shift) == 0) ? constant : 0 - constant;
      CHECK_EQ(expected, m.Call(i));
    }
  }
}

TEST(RunWord32ShrInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Word32Shr(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Word32Shr(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Equal(m.Int32Constant(0),
                        m.Word32Shr(m.Parameter(0), m.Int32Constant(shift))));
      FOR_UINT32_INPUTS(i) {
        uint32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Equal(m.Word32Shr(m.Parameter(0), m.Int32Constant(shift)),
                        m.Int32Constant(0)));
      FOR_UINT32_INPUTS(i) {
        uint32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
}


TEST(RunWord32SarP) {
  {
    FOR_INT32_SHIFTS(shift) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      m.Return(m.Word32Sar(m.Parameter(0), m.Int32Constant(shift)));
      FOR_INT32_INPUTS(j) {
        int32_t expected = j >> shift;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Word32Sar(bt.param0, bt.param1));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_SHIFTS(shift) {
        int32_t expected = i >> shift;
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
    CHECK_EQ(base::bit_cast<int32_t>(0xFFFF0000), bt.call(0x80000000, 15));
  }
}


TEST(RunWord32SarInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Word32Sar(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_SHIFTS(shift) {
        int32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Word32Sar(bt.param0, bt.param1)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_SHIFTS(shift) {
        int32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    FOR_INT32_SHIFTS(shift) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      m.Return(
          m.Word32Equal(m.Int32Constant(0),
                        m.Word32Sar(m.Parameter(0), m.Int32Constant(shift))));
      FOR_INT32_INPUTS(i) {
        int32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
  {
    FOR_INT32_SHIFTS(shift) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      m.Return(
          m.Word32Equal(m.Word32Sar(m.Parameter(0), m.Int32Constant(shift)),
                        m.Int32Constant(0)));
      FOR_INT32_INPUTS(i) {
        int32_t expected = 0 == (i >> shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
}


TEST(RunWord32RorP) {
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      m.Return(m.Word32Ror(m.Parameter(0), m.Int32Constant(shift)));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = base::bits::RotateRight32(j, shift);
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Word32Ror(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = base::bits::RotateRight32(i, shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
}


TEST(RunWord32RorInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Word32Ror(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = 0 == base::bits::RotateRight32(i, shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Word32Ror(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        uint32_t expected = 0 == base::bits::RotateRight32(i, shift);
        CHECK_EQ(expected, bt.call(i, shift));
      }
    }
  }
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Equal(m.Int32Constant(0),
                        m.Word32Ror(m.Parameter(0), m.Int32Constant(shift))));
      FOR_UINT32_INPUTS(i) {
        uint32_t expected = 0 == base::bits::RotateRight32(i, shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
  {
    FOR_UINT32_SHIFTS(shift) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Equal(m.Word32Ror(m.Parameter(0), m.Int32Constant(shift)),
                        m.Int32Constant(0)));
      FOR_UINT32_INPUTS(i) {
        uint32_t expected = 0 == base::bits::RotateRight32(i, shift);
        CHECK_EQ(expected, m.Call(i));
      }
    }
  }
}

TEST(RunWord32BitwiseNotP) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  m.Return(m.Word32BitwiseNot(m.Parameter(0)));
  FOR_INT32_INPUTS(i) {
    int expected = ~(i);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunInt32NegP) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  m.Return(m.Int32Neg(m.Parameter(0)));
  FOR_INT32_INPUTS(i) {
    int expected = base::NegateWithWraparound(i);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunWord32EqualAndWord32SarP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Uint32());
    m.Return(m.Word32Equal(m.Parameter(0),
                           m.Word32Sar(m.Parameter(1), m.Parameter(2))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          int32_t expected = (i == (j >> shift));
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Uint32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Word32Sar(m.Parameter(0), m.Parameter(1)),
                           m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_INT32_INPUTS(k) {
          int32_t expected = ((i >> shift) == k);
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunWord32EqualAndWord32ShlP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Word32Equal(m.Parameter(0),
                           m.Word32Shl(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          int32_t expected = (i == (j << shift));
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Word32Equal(m.Word32Shl(m.Parameter(0), m.Parameter(1)),
                           m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          int32_t expected = ((i << shift) == k);
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunWord32EqualAndWord32ShrP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Word32Equal(m.Parameter(0),
                           m.Word32Shr(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          int32_t expected = (i == (j >> shift));
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Word32Equal(m.Word32Shr(m.Parameter(0), m.Parameter(1)),
                           m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          int32_t expected = ((i >> shift) == k);
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunDeadNodes) {
  for (int i = 0; true; i++) {
    RawMachineAssemblerTester<int32_t> m_v;
    RawMachineAssemblerTester<int32_t> m_i(MachineType::Int32());
    RawMachineAssemblerTester<int32_t>& m = i == 5 ? m_i : m_v;

    int constant = 0x55 + i;
    switch (i) {
      case 0:
        m.Int32Constant(44);
        break;
      case 1:
        m.StringConstant("unused");
        break;
      case 2:
        m.NumberConstant(11.1);
        break;
      case 3:
        m.PointerConstant(&constant);
        break;
      case 4:
        m.LoadFromPointer(&constant, MachineType::Int32());
        break;
      case 5:
        m.Parameter(0);
        break;
      default:
        return;
    }
    m.Return(m.Int32Constant(constant));
    if (i != 5) {
      CHECK_EQ(constant, m.Call());
    } else {
      CHECK_EQ(constant, m.Call(0));
    }
  }
}


TEST(RunDeadInt32Binops) {
  RawMachineAssemblerTester<int32_t> m;

  const Operator* kOps[] = {
      m.machine()->Word32And(),            m.machine()->Word32Or(),
      m.machine()->Word32Xor(),            m.machine()->Word32Shl(),
      m.machine()->Word32Shr(),            m.machine()->Word32Sar(),
      m.machine()->Word32Ror(),            m.machine()->Word32Equal(),
      m.machine()->Int32Add(),             m.machine()->Int32Sub(),
      m.machine()->Int32Mul(),             m.machine()->Int32MulHigh(),
      m.machine()->Int32Div(),             m.machine()->Uint32Div(),
      m.machine()->Int32Mod(),             m.machine()->Uint32Mod(),
      m.machine()->Uint32MulHigh(),        m.machine()->Int32LessThan(),
      m.machine()->Int32LessThanOrEqual(), m.machine()->Uint32LessThan(),
      m.machine()->Uint32LessThanOrEqual()};

  for (size_t i = 0; i < arraysize(kOps); ++i) {
    RawMachineAssemblerTester<int32_t> t(MachineType::Int32(),
                                         MachineType::Int32());
    int32_t constant = static_cast<int32_t>(0x55555 + i);
    t.AddNode(kOps[i], t.Parameter(0), t.Parameter(1));
    t.Return(t.Int32Constant(constant));

    CHECK_EQ(constant, t.Call(1, 1));
  }
}


TEST(RunFloat32Add) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(m.Float32Add(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(i + j, m.Call(i, j)); }
  }
}


TEST(RunFloat32Sub) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(m.Float32Sub(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(i - j, m.Call(i, j)); }
  }
}

TEST(RunFloat32Neg) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  m.Return(m.AddNode(m.machine()->Float32Neg(), m.Parameter(0)));
  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(-0.0f - i, m.Call(i)); }
}

TEST(RunFloat32Mul) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(m.Float32Mul(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(i * j, m.Call(i, j)); }
  }
}


TEST(RunFloat32Div) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(m.Float32Div(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(base::Divide(i, j), m.Call(i, j)); }
  }
}


TEST(RunFloat64Add) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Add(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(i + j, m.Call(i, j)); }
  }
}


TEST(RunFloat64Sub) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Sub(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(i - j, m.Call(i, j)); }
  }
}

TEST(RunFloat64Neg) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.AddNode(m.machine()->Float64Neg(), m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(-0.0 - i, m.Call(i)); }
}

TEST(RunFloat64Mul) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Mul(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(i * j, m.Call(i, j)); }
  }
}


TEST(RunFloat64Div) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Div(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(base::Divide(i, j), m.Call(i, j)); }
  }
}


TEST(RunFloat64Mod) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Mod(m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(Modulo(i, j), m.Call(i, j)); }
  }
}


TEST(RunDeadFloat32Binops) {
  RawMachineAssemblerTester<int32_t> m;

  const Operator* ops[] = {m.machine()->Float32Add(), m.machine()->Float32Sub(),
                           m.machine()->Float32Mul(), m.machine()->Float32Div(),
                           nullptr};

  for (int i = 0; ops[i] != nullptr; i++) {
    RawMachineAssemblerTester<int32_t> t;
    int constant = 0x53355 + i;
    t.AddNode(ops[i], t.Float32Constant(0.1f), t.Float32Constant(1.11f));
    t.Return(t.Int32Constant(constant));
    CHECK_EQ(constant, t.Call());
  }
}


TEST(RunDeadFloat64Binops) {
  RawMachineAssemblerTester<int32_t> m;

  const Operator* ops[] = {m.machine()->Float64Add(), m.machine()->Float64Sub(),
                           m.machine()->Float64Mul(), m.machine()->Float64Div(),
                           m.machine()->Float64Mod(), nullptr};

  for (int i = 0; ops[i] != nullptr; i++) {
    RawMachineAssemblerTester<int32_t> t;
    int constant = 0x53355 + i;
    t.AddNode(ops[i], t.Float64Constant(0.1), t.Float64Constant(1.11));
    t.Return(t.Int32Constant(constant));
    CHECK_EQ(constant, t.Call());
  }
}


TEST(RunFloat32AddP) {
  RawMachineAssemblerTester<int32_t> m;
  Float32BinopTester bt(&m);

  bt.AddReturn(m.Float32Add(bt.param0, bt.param1));

  FOR_FLOAT32_INPUTS(pl) {
    FOR_FLOAT32_INPUTS(pr) { CHECK_FLOAT_EQ(pl + pr, bt.call(pl, pr)); }
  }
}


TEST(RunFloat64AddP) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);

  bt.AddReturn(m.Float64Add(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) { CHECK_DOUBLE_EQ(pl + pr, bt.call(pl, pr)); }
  }
}

TEST(RunFloat64MaxP) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);
  bt.AddReturn(m.Float64Max(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) { CHECK_DOUBLE_EQ(JSMax(pl, pr), bt.call(pl, pr)); }
  }
}


TEST(RunFloat64MinP) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);
  bt.AddReturn(m.Float64Min(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) { CHECK_DOUBLE_EQ(JSMin(pl, pr), bt.call(pl, pr)); }
  }
}

TEST(RunFloat32Max) {
  RawMachineAssemblerTester<int32_t> m;
  Float32BinopTester bt(&m);
  bt.AddReturn(m.Float32Max(bt.param0, bt.param1));

  FOR_FLOAT32_INPUTS(pl) {
    FOR_FLOAT32_INPUTS(pr) { CHECK_FLOAT_EQ(JSMax(pl, pr), bt.call(pl, pr)); }
  }
}

TEST(RunFloat32Min) {
  RawMachineAssemblerTester<int32_t> m;
  Float32BinopTester bt(&m);
  bt.AddReturn(m.Float32Min(bt.param0, bt.param1));

  FOR_FLOAT32_INPUTS(pl) {
    FOR_FLOAT32_INPUTS(pr) { CHECK_FLOAT_EQ(JSMin(pl, pr), bt.call(pl, pr)); }
  }
}

TEST(RunFloat64Max) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);
  bt.AddReturn(m.Float64Max(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) { CHECK_DOUBLE_EQ(JSMax(pl, pr), bt.call(pl, pr)); }
  }
}

TEST(RunFloat64Min) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);
  bt.AddReturn(m.Float64Min(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) { CHECK_DOUBLE_EQ(JSMin(pl, pr), bt.call(pl, pr)); }
  }
}

TEST(RunFloat32SubP) {
  RawMachineAssemblerTester<int32_t> m;
  Float32BinopTester bt(&m);

  bt.AddReturn(m.Float32Sub(bt.param0, bt.param1));

  FOR_FLOAT32_INPUTS(pl) {
    FOR_FLOAT32_INPUTS(pr) { CHECK_FLOAT_EQ(pl - pr, bt.call(pl, pr)); }
  }
}


TEST(RunFloat32SubImm1) {
  FOR_FLOAT32_INPUTS(i) {
    BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
    m.Return(m.Float32Sub(m.Float32Constant(i), m.Parameter(0)));

    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(i - j, m.Call(j)); }
  }
}


TEST(RunFloat32SubImm2) {
  FOR_FLOAT32_INPUTS(i) {
    BufferedRawMachineAssemblerTester<float> m
```