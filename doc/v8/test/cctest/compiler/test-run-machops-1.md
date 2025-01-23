Response: The user wants me to summarize the functionality of a C++ source code file.
The file seems to be testing various machine operations within the V8 JavaScript engine.
It uses a testing framework to verify the behavior of low-level operations like addition, subtraction, bitwise operations, and floating-point operations.

Each `TEST` block defines a specific scenario, often involving:
1. Creating a `RawMachineAssemblerTester` or `BufferedRawMachineAssemblerTester` to generate machine code snippets.
2. Defining input parameters using `FOR_..._INPUTS` macros, which iterate through various integer or floating-point values.
3. Performing machine operations using methods like `m.Int32Add`, `m.Word32And`, `m.Float32Sub`, etc.
4. Comparing the result of the machine operation with the expected outcome using `CHECK_EQ` or `CHECK_FLOAT_EQ`.

The tests cover different aspects of each operation, such as:
- Binary operations with two parameters (`RunInt32AddP`, `RunFloat32Mul`).
- Operations with immediate values (`RunInt32AddImm`).
- Operations used in conditional branches (`RunInt32AddInBranch`).
- Operations used in comparisons (`RunInt32AddInComparison`).
- Combinations of operations (`RunInt32AddAndWord32SarP`).

The code also uses helper classes like `Int32BinopTester` and `Uint32BinopTester` to simplify testing binary operations.

The file seems to be verifying that the machine code generated for these basic operations in V8 behaves as expected. This is crucial for the correctness and performance of the JavaScript engine.

Since this is part 2 of 4, the overall file likely covers a wider range of machine operations.这个C++源代码文件（`v8/test/cctest/compiler/test-run-machops.cc`）的第2部分主要功能是**测试V8 JavaScript引擎在底层执行各种机器操作的正确性**。

具体来说，它使用了一系列的单元测试（以`TEST`宏定义），每个测试针对一个特定的机器操作或者操作的组合，例如：

* **整数运算:** 加法 (`Int32Add`), 减法 (`Int32Sub`), 乘法 (`Int32Mul`), 除法 (`Int32Div`, `Uint32Div`), 取模 (`Int32Mod`, `Uint32Mod`)
* **位运算:** 与 (`Word32And`), 或 (`Word32Or`), 异或 (`Word32Xor`), 左移 (`Word32Shl`), 右移 (`Word32Shr`, `Word32Sar`), 循环右移 (`Word32Ror`), 位反 (`Word32BitwiseNot`)
* **浮点数运算:** 加法 (`Float32Add`, `Float64Add`), 减法 (`Float32Sub`, `Float64Sub`), 乘法 (`Float32Mul`, `Float64Mul`), 除法 (`Float32Div`, `Float64Div`), 取模 (`Float64Mod`), 取负 (`Float32Neg`, `Float64Neg`), 最大值 (`Float32Max`, `Float64Max`), 最小值 (`Float32Min`, `Float64Min`)
* **比较运算:**  测试这些运算的结果是否能正确地用于条件分支 (`...InBranch`) 和比较 (`...InComparison`)。

每个测试用例通常会：

1. **创建一个 `RawMachineAssemblerTester` 或 `BufferedRawMachineAssemblerTester` 对象:**  这个对象用于构建底层的机器代码片段。
2. **定义输入参数:** 使用 `FOR_UINT32_INPUTS`, `FOR_INT32_INPUTS`, `FOR_FLOAT32_INPUTS`, `FOR_FLOAT64_INPUTS` 等宏来遍历各种可能的输入值组合。
3. **执行机器操作:** 使用 `m.Int32Add()`, `m.Word32And()`, `m.Float32Sub()` 等方法来模拟底层的机器指令。
4. **断言结果:** 使用 `CHECK_EQ` 或 `CHECK_FLOAT_EQ` 来比较实际的运算结果和预期的结果是否一致。

**与 JavaScript 的关系和示例:**

这些底层的机器操作是 JavaScript 代码执行的基础。当 JavaScript 引擎需要执行算术运算、位运算或比较操作时，它最终会转化为这些底层的机器指令。

**JavaScript 示例 (对应代码中的 `TEST(RunInt32AddP)`)：**

```javascript
function testAdd(a, b) {
  return a + b;
}

// V8 引擎在执行这个函数时，会将其中的加法操作转化为底层的 Int32Add 机器指令。
// testAdd(5, 3); // 预期结果是 8
```

**JavaScript 示例 (对应代码中的 `TEST(RunWord32AndP)`)：**

```javascript
function testAnd(a, b) {
  return a & b;
}

// V8 引擎在执行这个函数时，会将其中的位与操作转化为底层的 Word32And 机器指令。
// testAnd(10, 5); // 10 的二进制是 1010，5 的二进制是 0101，位与结果是 0000，即 0
```

**JavaScript 示例 (对应代码中的 `TEST(RunFloat32Sub)`)：**

```javascript
function testFloatSub(a, b) {
  return a - b;
}

// V8 引擎在执行这个函数时，会将其中的浮点数减法操作转化为底层的 Float32Sub 机器指令。
// testFloatSub(3.14, 1.1); // 预期结果大约是 2.04
```

总而言之，这个代码文件的第2部分通过大量的测试用例，确保 V8 引擎能够正确地执行各种基本的数值和位运算，这是 JavaScript 代码能够正确运行的关键保证。  它关注的是这些操作在机器层面的行为和结果。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
    FOR_INT32_INPUTS(i) {
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