Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is a part of the V8 JavaScript engine's test suite.
It tests the behavior of various low-level machine operations (machops) by generating machine code snippets and verifying their output against expected results.

Here's a plan to summarize the code:
1. Identify the main functionalities being tested.
2. Note the testing methodology.
3. Look for patterns in the test structure.
4. Summarize the purpose of the code.
```
v8/test/cctest/compiler/test-run-machops.cc
```

这是 V8 JavaScript 引擎的测试代码，专门用于测试编译器生成的机器码中各种算术和位运算操作的正确性。这个文件不是 Torque 源代码，因为它以 `.cc` 结尾，而不是 `.tq`。

**功能归纳 (第 3 部分):**

这个代码片段主要测试以下机器操作（machops）的执行结果是否符合预期：

* **`Int32Sub` (带符号 32 位整数减法):**
    * 测试两个参数相减，包括参数直接相减和立即数相减的情况。
    * 测试减法操作与位移操作 (`Word32Sar`, `Word32Shl`, `Word32Shr`) 组合使用时的结果。
    * 测试减法结果用于条件分支 (`Branch`) 的情况。
    * 测试减法结果用于比较 (`Word32Equal`, `Word32NotEqual`) 的情况。

* **`Int32Mul` (带符号 32 位整数乘法):**
    * 测试两个参数相乘，包括带符号和无符号整数的情况。
    * 测试乘法结果的高 32 位 (`Int32MulHigh`, `Uint32MulHigh`)。
    * 测试乘法操作与加法 (`Int32Add`) 和减法 (`Int32Sub`) 组合使用时的结果。

* **`Int32Div` (带符号 32 位整数除法):**
    * 测试两个参数相除，并考虑除数为零以及最小值除以 -1 的特殊情况。
    * 测试除法结果与加法操作组合使用的情况。

* **`Uint32Div` (无符号 32 位整数除法):**
    * 测试两个参数相除，并考虑除数为零的情况。
    * 测试除法结果与加法操作组合使用的情况。

* **`Int32Mod` (带符号 32 位整数取模):**
    * 测试两个参数取模，并考虑除数为零以及最小值除以 -1 的特殊情况。
    * 测试取模结果与加法操作组合使用的情况。

* **`Uint32Mod` (无符号 32 位整数取模):**
    * 测试两个参数取模，并考虑除数为零的情况。
    * 测试取模结果与加法操作组合使用的情况。

* **`Word32And` (32 位按位与):**
    * 测试两个参数进行按位与操作，包括与自身取反的结果进行按位与的情况。
    * 测试按位与操作与位移操作 (`Word32Shl`, `Word32Shr`, `Word32Sar`) 组合使用，并使用掩码 (`0x1F`) 的情况。
    * 测试按位与操作与立即数进行的情况。
    * 测试按位与结果用于条件分支 (`Branch`) 的情况。
    * 测试按位与结果用于比较 (`Word32Equal`) 的情况。

* **`Word32Or` (32 位按位或):**
    * 测试两个参数进行按位或操作，包括与自身取反的结果进行按位或的情况。
    * 测试按位或操作与立即数进行的情况。
    * 测试按位或结果用于条件分支 (`Branch`) 的情况。

**与 JavaScript 的关系：**

这些测试直接关系到 JavaScript 中对整数进行各种算术和位运算的实现。例如，JavaScript 中的加法、减法、乘法、除法、取模以及位运算符 (`&`, `|`, `<<`, `>>`, `>>>`) 等操作，最终都会被 V8 编译成类似的机器码指令。

**JavaScript 示例：**

```javascript
// 对应 RunInt32AddP, RunInt32AddImm 等测试
let a = 10;
let b = 5;
let sum = a + b; // JavaScript 的加法操作最终会使用类似的 Int32Add 机器指令

// 对应 RunInt32SubP, RunInt32SubImm 等测试
let difference = a - b; // JavaScript 的减法操作最终会使用类似的 Int32Sub 机器指令

// 对应 RunInt32MulP, RunInt32MulImm 等测试
let product = a * b; // JavaScript 的乘法操作最终会使用类似的 Int32Mul 机器指令

// 对应 RunInt32DivP, RunUint32DivP 等测试
let quotient = a / b; // JavaScript 的除法操作会使用类似的 Int32Div 或 Uint32Div 机器指令

// 对应 RunInt32ModP, RunUint32ModP 等测试
let remainder = a % b; // JavaScript 的取模操作会使用类似的 Int32Mod 或 Uint32Mod 机器指令

// 对应 RunWord32AndP, RunWord32AndImm 等测试
let andResult = a & b; // JavaScript 的按位与操作最终会使用类似的 Word32And 机器指令

// 对应 RunWord32OrP, RunWord32OrImm 等测试
let orResult = a | b;  // JavaScript 的按位或操作最终会使用类似的 Word32Or 机器指令

// 对应 RunInt32AddInBranch, RunWord32AndInBranch 等测试
if (a + b === 15) {
  console.log("Sum is 15");
}

if (a & b !== 0) {
  console.log("Bitwise AND is not zero");
}
```

**代码逻辑推理与假设输入输出：**

以 `TEST(RunInt32AddP)` 为例：

* **假设输入:** 两个无符号 32 位整数 `i` 和 `j`。
* **代码逻辑:**  创建一个 `RawMachineAssemblerTester`，将两个输入参数相加 (`m.Int32Add`)，然后返回结果。
* **预期输出:**  `i + j` 的结果（无符号 32 位整数）。
* **测试:** 循环遍历所有可能的无符号 32 位整数输入对，调用生成的机器码，并使用 `CHECK_EQ` 宏断言实际输出与预期输出是否相等。

**用户常见的编程错误：**

* **整数溢出：**  在进行加法、减法或乘法运算时，如果结果超出了 32 位有符号或无符号整数的表示范围，会导致溢出。C++ 中有符号整数溢出是未定义行为，而无符号整数溢出则会发生回绕。JavaScript 中数值类型是双精度浮点数，可以表示更大的范围，但当进行位运算时，会先转换为 32 位整数。

    ```javascript
    // JavaScript 示例
    let maxInt32 = 2147483647;
    let overflow = maxInt32 + 1; // JavaScript 中不会真正溢出，结果是 2147483648
    let bitwiseOverflow = maxInt32 | 1; // 位运算会先转换为 32 位有符号整数，结果是 2147483647

    // C++ 可能出现的错误 (对应测试用例需要处理溢出情况)
    int a = 2147483647;
    int b = 1;
    // int sum = a + b; // 有符号整数溢出，行为未定义
    unsigned int ua = 4294967295;
    unsigned int ub = 1;
    unsigned int usum = ua + ub; // 无符号整数溢出，usum 的结果是 0
    ```

* **除零错误：**  在进行除法或取模运算时，如果除数为零，会导致程序崩溃或抛出异常。测试用例中会特意排除除数为零的情况。

    ```javascript
    // JavaScript 示例
    let a = 10;
    let b = 0;
    // let result = a / b; // 除零会得到 Infinity 或 -Infinity
    // let remainder = a % b; // 取模零会得到 NaN

    // C++ 可能出现的错误
    int x = 10;
    int y = 0;
    // int division = x / y; // 除零错误，程序可能崩溃
    ```

* **位运算的理解错误：**  对位运算符的功能和优先级理解不透彻，可能导致意想不到的结果。例如，左移操作可能导致符号位的变化，右移操作分为逻辑右移和算术右移。

    ```javascript
    // JavaScript 示例
    let num = -10;
    let leftShift = num << 2;  // 左移
    let rightShift = num >> 2; // 有符号右移 (算术右移)
    let unsignedRightShift = num >>> 2; // 无符号右移 (逻辑右移)

    // C++ 中也需要注意位移操作的类型和行为
    int c_num = -10;
    int c_leftShift = c_num << 2;
    int c_rightShift = c_num >> 2; // 算术右移
    unsigned int c_unsignedRightShift = static_cast<unsigned int>(c_num) >> 2; // 逻辑右移
    ```

总而言之，这个代码片段是 V8 引擎中非常基础但至关重要的测试，它确保了编译器能够正确地生成执行基本算术和位运算的机器码，这是保证 JavaScript 代码正确执行的基石。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能

"""
rn(m.Word32Equal(m.Int32Add(m.Int32Constant(i), m.Parameter(0)),
                         m.Int32Constant(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = (i + j) == 0;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32Equal(m.Int32Add(m.Parameter(0), m.Int32Constant(i)),
                         m.Int32Constant(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = (j + i) == 0;
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
      t.Return(t.Word32Equal(
          t.Int32Add(t.Parameter(0),
                     t.AddNode(shops[n], t.Parameter(1), t.Parameter(2))),
          t.Int32Constant(0)));
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
            int32_t expected = (i + right) == 0;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunInt32SubP) {
  RawMachineAssemblerTester<int32_t> m;
  Uint32BinopTester bt(&m);

  m.Return(m.Int32Sub(bt.param0, bt.param1));

  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      uint32_t expected = i - j;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}

TEST(RunInt32SubImm) {
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Int32Sub(m.Int32Constant(i), m.Parameter(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = i - j;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(m.Int32Sub(m.Parameter(0), m.Int32Constant(i)));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = j - i;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
}

TEST(RunInt32SubImm2) {
  BufferedRawMachineAssemblerTester<int32_t> r;
  r.Return(r.Int32Sub(r.Int32Constant(-1), r.Int32Constant(0)));
  CHECK_EQ(-1, r.Call());
}

TEST(RunInt32SubAndWord32SarP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Int32(), MachineType::Uint32());
    m.Return(m.Int32Sub(m.Parameter(0),
                        m.Word32Sar(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          int32_t expected = i - (j >> shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Sub(m.Word32Sar(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          int32_t expected = (i >> shift) - k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32SubAndWord32ShlP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Sub(m.Parameter(0),
                        m.Word32Shl(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          int32_t expected = i - (j << shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Sub(m.Word32Shl(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = (i << shift) - k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32SubAndWord32ShrP) {
  {
    RawMachineAssemblerTester<uint32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Sub(m.Parameter(0),
                        m.Word32Shr(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          // Use uint32_t because signed overflow is UB in C.
          uint32_t expected = i - (j >> shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<uint32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Sub(m.Word32Shr(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          uint32_t expected = (i >> shift) - k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32SubInBranch) {
  static const int constant = 987654321;
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32Equal(m.Int32Sub(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i - j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32NotEqual(m.Int32Sub(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i - j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32Equal(m.Int32Sub(m.Int32Constant(i), m.Parameter(0)),
                             m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i - j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32NotEqual(m.Int32Sub(m.Int32Constant(i), m.Parameter(0)),
                                m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i - j) != 0 ? constant : 0 - constant;
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
      t.Branch(t.Word32Equal(t.Int32Sub(t.Parameter(0),
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
            int32_t expected = ((i - right) == 0) ? constant : 0 - constant;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunInt32SubInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Sub(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i - j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Int32Sub(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i - j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32Equal(m.Int32Sub(m.Int32Constant(i), m.Parameter(0)),
                         m.Int32Constant(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = (i - j) == 0;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32Equal(m.Int32Sub(m.Parameter(0), m.Int32Constant(i)),
                         m.Int32Constant(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = (j - i) == 0;
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
      t.Return(t.Word32Equal(
          t.Int32Sub(t.Parameter(0),
                     t.AddNode(shops[n], t.Parameter(1), t.Parameter(2))),
          t.Int32Constant(0)));
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
            int32_t expected = (i - right) == 0;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunInt32MulP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Int32Mul(bt.param0, bt.param1));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int expected = base::MulWithWraparound(i, j);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Int32Mul(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i * j;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
}


TEST(RunInt32MulHighP) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  bt.AddReturn(m.Int32MulHigh(bt.param0, bt.param1));
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(
          (static_cast<int64_t>(i) * static_cast<int64_t>(j)) >> 32);
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}


TEST(RunInt32MulImm) {
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Int32Mul(m.Int32Constant(i), m.Parameter(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = i * j;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(m.Int32Mul(m.Parameter(0), m.Int32Constant(i)));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = j * i;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
}

TEST(RunInt32MulAndInt32AddP) {
  {
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int32_t p0 = i;
  int32_t p1 = j;
  m.Return(m.Int32Add(m.Int32Constant(p0),
                      m.Int32Mul(m.Parameter(0), m.Int32Constant(p1))));
  FOR_INT32_INPUTS(k) {
    int32_t p2 = k;
    int expected = base::AddWithWraparound(p0, base::MulWithWraparound(p1, p2));
    CHECK_EQ(expected, m.Call(p2));
  }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Int32Add(m.Parameter(0), m.Int32Mul(m.Parameter(1), m.Parameter(2))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          int32_t p0 = i;
          int32_t p1 = j;
          int32_t p2 = k;
          int expected =
              base::AddWithWraparound(p0, base::MulWithWraparound(p1, p2));
          CHECK_EQ(expected, m.Call(p0, p1, p2));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Int32Add(m.Int32Mul(m.Parameter(0), m.Parameter(1)), m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          int32_t p0 = i;
          int32_t p1 = j;
          int32_t p2 = k;
          int expected =
              base::AddWithWraparound(base::MulWithWraparound(p0, p1), p2);
          CHECK_EQ(expected, m.Call(p0, p1, p2));
        }
      }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m;
      Int32BinopTester bt(&m);
      bt.AddReturn(
          m.Int32Add(m.Int32Constant(i), m.Int32Mul(bt.param0, bt.param1)));
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          int32_t p0 = j;
          int32_t p1 = k;
          int expected =
              base::AddWithWraparound(i, base::MulWithWraparound(p0, p1));
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
}


TEST(RunInt32MulAndInt32SubP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Int32Sub(m.Parameter(0), m.Int32Mul(m.Parameter(1), m.Parameter(2))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          int32_t p0 = i;
          int32_t p1 = j;
          int32_t p2 = k;
          int expected =
              base::SubWithWraparound(p0, base::MulWithWraparound(p1, p2));
          CHECK_EQ(expected, m.Call(p0, p1, p2));
        }
      }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m;
      Int32BinopTester bt(&m);
      bt.AddReturn(
          m.Int32Sub(m.Int32Constant(i), m.Int32Mul(bt.param0, bt.param1)));
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          int32_t p0 = j;
          int32_t p1 = k;
          int expected =
              base::SubWithWraparound(i, base::MulWithWraparound(p0, p1));
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
}


TEST(RunUint32MulHighP) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  bt.AddReturn(m.Uint32MulHigh(bt.param0, bt.param1));
  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      int32_t expected = base::bit_cast<int32_t>(static_cast<uint32_t>(
          (static_cast<uint64_t>(i) * static_cast<uint64_t>(j)) >> 32));
      CHECK_EQ(expected,
               bt.call(base::bit_cast<int32_t>(i), base::bit_cast<int32_t>(j)));
    }
  }
}


TEST(RunInt32DivP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Int32Div(bt.param0, bt.param1));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int p0 = i;
        int p1 = j;
        if (p1 != 0 && (static_cast<uint32_t>(p0) != 0x80000000 || p1 != -1)) {
          int expected = static_cast<int32_t>(p0 / p1);
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Int32Add(bt.param0, m.Int32Div(bt.param0, bt.param1)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int p0 = i;
        int p1 = j;
        if (p1 != 0 && (static_cast<uint32_t>(p0) != 0x80000000 || p1 != -1)) {
          int expected =
              static_cast<int32_t>(base::AddWithWraparound(p0, (p0 / p1)));
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
}


TEST(RunUint32DivP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Uint32Div(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t p0 = i;
        uint32_t p1 = j;
        if (p1 != 0) {
          int32_t expected = base::bit_cast<int32_t>(p0 / p1);
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Int32Add(bt.param0, m.Uint32Div(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t p0 = i;
        uint32_t p1 = j;
        if (p1 != 0) {
          int32_t expected = base::bit_cast<int32_t>(p0 + (p0 / p1));
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
}


TEST(RunInt32ModP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Int32Mod(bt.param0, bt.param1));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int p0 = i;
        int p1 = j;
        if (p1 != 0 && (static_cast<uint32_t>(p0) != 0x80000000 || p1 != -1)) {
          int expected = static_cast<int32_t>(p0 % p1);
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Int32Add(bt.param0, m.Int32Mod(bt.param0, bt.param1)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int p0 = i;
        int p1 = j;
        if (p1 != 0 && (static_cast<uint32_t>(p0) != 0x80000000 || p1 != -1)) {
          int expected =
              static_cast<int32_t>(base::AddWithWraparound(p0, (p0 % p1)));
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
}


TEST(RunUint32ModP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Uint32Mod(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t p0 = i;
        uint32_t p1 = j;
        if (p1 != 0) {
          uint32_t expected = static_cast<uint32_t>(p0 % p1);
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Int32Add(bt.param0, m.Uint32Mod(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t p0 = i;
        uint32_t p1 = j;
        if (p1 != 0) {
          uint32_t expected = static_cast<uint32_t>(p0 + (p0 % p1));
          CHECK_EQ(expected, bt.call(p0, p1));
        }
      }
    }
  }
}


TEST(RunWord32AndP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Word32And(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = i & j;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Word32And(bt.param0, m.Word32BitwiseNot(bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = i & ~(j);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(m.Word32And(m.Word32BitwiseNot(bt.param0), bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = ~(i)&j;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
}


TEST(RunWord32AndAndWord32ShlP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Shl(bt.param0, m.Word32And(bt.param1, m.Int32Constant(0x1F))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i << (j & 0x1F);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Shl(bt.param0, m.Word32And(m.Int32Constant(0x1F), bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i << (0x1F & j);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
}


TEST(RunWord32AndAndWord32ShrP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Shr(bt.param0, m.Word32And(bt.param1, m.Int32Constant(0x1F))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i >> (j & 0x1F);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Shr(bt.param0, m.Word32And(m.Int32Constant(0x1F), bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i >> (0x1F & j);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
}


TEST(RunWord32AndAndWord32SarP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Sar(bt.param0, m.Word32And(bt.param1, m.Int32Constant(0x1F))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int32_t expected = i >> (j & 0x1F);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Sar(bt.param0, m.Word32And(m.Int32Constant(0x1F), bt.param1)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int32_t expected = i >> (0x1F & j);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
}


TEST(RunWord32AndImm) {
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32And(m.Int32Constant(i), m.Parameter(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = i & j;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32And(m.Int32Constant(i), m.Word32BitwiseNot(m.Parameter(0))));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i & ~(j);
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
}


TEST(RunWord32AndInBranch) {
  static const int constant = 987654321;
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32Equal(m.Word32And(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i & j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32NotEqual(m.Word32And(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i & j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32Equal(m.Word32And(m.Int32Constant(i), m.Parameter(0)),
                             m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i & j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32NotEqual(m.Word32And(m.Int32Constant(i), m.Parameter(0)),
                                m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i & j) != 0 ? constant : 0 - constant;
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
      t.Branch(t.Word32Equal(t.Word32And(t.Parameter(0),
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
            int32_t expected = ((i & right) == 0) ? constant : 0 - constant;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunWord32AndInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Word32And(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i & j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Word32And(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i & j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32Equal(m.Word32And(m.Int32Constant(i), m.Parameter(0)),
                         m.Int32Constant(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = (i & j) == 0;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(m.Word32Equal(m.Word32And(m.Parameter(0), m.Int32Constant(i)),
                             m.Int32Constant(0)));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (j & i) == 0;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
}


TEST(RunWord32OrP) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Word32Or(bt.param0, bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i | j;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Word32Or(bt.param0, m.Word32BitwiseNot(bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i | ~(j);
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(m.Word32Or(m.Word32BitwiseNot(bt.param0), bt.param1));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = ~(i) | j;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
}


TEST(RunWord32OrImm) {
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.Word32Or(m.Int32Constant(i), m.Parameter(0)));
  FOR_UINT32_INPUTS(j) {
    uint32_t expected = i | j;
    CHECK_EQ(expected, m.Call(j));
  }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
      m.Return(
          m.Word32Or(m.Int32Constant(i), m.Word32BitwiseNot(m.Parameter(0))));
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = i | ~(j);
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
}


TEST(RunWord32OrInBranch) {
  static const int constant = 987654321;
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32Equal(m.Word32Or(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        int32_t expected = (i | j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32NotEqual(m.Word32Or(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_INT32_INPUTS(i
"""


```