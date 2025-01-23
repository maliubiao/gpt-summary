Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the third part of a four-part file. The code consists of a series of tests for machine operations within the V8 JavaScript engine. Each `TEST` function sets up a small code snippet using the `BufferedRawMachineAssemblerTester` or `RawMachineAssemblerTester` and then checks if the generated machine code produces the expected result for various inputs. The operations being tested are primarily arithmetic and type conversions for both 32-bit floats (`float`) and 64-bit floats (`double`), as well as some integer operations.

To summarize, this part of the file continues testing the correctness of machine code generated for floating-point arithmetic (subtraction, multiplication, division, modulo), type conversions between integers and floats, and truncation of floats to integers. It also includes tests for bitwise operations on pairs of 32-bit integers, and comparisons for floating-point numbers.

I should also provide a Javascript example if there's a clear connection to Javascript functionality. Many of these low-level machine operations correspond directly to Javascript's numeric operations.
这是 `v8/test/cctest/compiler/test-run-machops.cc` 文件的一部分，主要功能是**测试 V8 编译器生成的机器码中各种浮点数和整数运算的正确性**。

具体来说，这部分代码涵盖了以下方面的测试：

* **浮点数运算 (Float32 和 Float64):**
    * 减法 (`Float32Sub`, `Float64Sub`)：包括立即数和参数之间的减法，以及两个参数之间的减法。
    * 乘法 (`Float32Mul`, `Float64Mul`)：包括两个参数的乘法，以及与负号结合的乘法运算。
    * 除法 (`Float32Div`, `Float64Div`)。
    * 取模 (`Float64Mod`)。
* **类型转换:**
    * 整数到浮点数的转换 (`ChangeInt32ToFloat64`, `ChangeUint32ToFloat64`)。
    * 浮点数到整数的截断 (`TruncateFloat32ToInt32`, `TruncateFloat32ToUint32`)，测试了不同的截断行为（默认行为和溢出时设置为最小值）。
    * 双精度浮点数到单精度浮点数的截断 (`TruncateFloat64ToFloat32`)。
    * 双精度浮点数到整数的转换 (`ChangeFloat64ToInt32`, `ChangeFloat64ToUint32`)。
* **双字 (64位) 整数运算 (在 32 位架构上模拟):**
    * 加法 (`Int32PairAdd`)。
    * 减法 (`Int32PairSub`)。
    * 乘法 (`Int32PairMul`)。
    * 左移 (`Word32PairShl`)。
    * 右移 (`Word32PairShr`)。
    * 算术右移 (`Word32PairSar`)。
* **其他操作:**
    * 死代码消除测试 (`RunDeadChangeFloat64ToInt32`, `RunDeadChangeInt32ToFloat64`)，确保编译器能够移除无用的转换操作。
    * 控制流测试（循环和分支）：测试 `Phi` 节点的正确性，用于在控制流汇聚点合并值。
    * 比较操作 (`RunFloat64Compare`, `RunFloat64UnorderedCompare`, `RunFloat64Equal`, `RunFloat64LessThan`, `RunIntPtrCompare`)。
    * 指针运算 (`RunTestIntPtrArithmetic`)。
    * 寄存器溢出测试 (`RunSpillLotsOfThings`, `RunSpillConstantsAndParameters`)，确保在需要时能够正确地将值存储到内存中。
    * 常量在 `Phi` 节点中的使用 (`RunNewSpaceConstantsInPhi`)。
    * 带溢出检查的整数运算 (`RunInt32AddWithOverflowP`, `RunInt32SubWithOverflowP`, `RunInt32MulWithOverflowP`)。
    * 64 位整数比较 (`RunWord64EqualInBranchP`)。
    * 整数类型扩展和截断 (`RunChangeInt32ToInt64P`, `RunChangeUint32ToUint64P`, `RunTruncateInt64ToInt32P`)。
    * 浮点数到无符号 32 位整数的截断 (`RunTruncateFloat64ToWord32P`)。
    * 单精度浮点数到双精度浮点数的转换 (`RunChangeFloat32ToFloat64`)。
    * 浮点数常量加载 (`RunFloat32Constant`)。
    * 浮点数的位操作 (`RunFloat64ExtractLowWord32`, `RunFloat64ExtractHighWord32`, `RunFloat64InsertLowWord32`, `RunFloat64InsertHighWord32`)。
    * 浮点数的绝对值 (`RunFloat32Abs`, `RunFloat64Abs`)。
    * 浮点数的数学函数 (`RunFloat64Acos`, `RunFloat64Acosh`, `RunFloat64Asin`, `RunFloat64Asinh`, `RunFloat64Atan`)。

**与 JavaScript 的关系和示例:**

这些测试直接关系到 JavaScript 中数字类型的运算。JavaScript 中的 `number` 类型底层通常使用双精度浮点数 (Float64)。当 JavaScript 代码执行各种数学运算或类型转换时，V8 编译器会生成相应的机器码，而这些测试正是用来验证这些机器码的正确性。

**JavaScript 示例:**

* **浮点数运算:**

```javascript
let a = 5.5;
let b = 2.2;
let sum = a + b; // 对应 Float64Add 的测试
let difference = a - b; // 对应 Float64Sub 的测试
let product = a * b; // 对应 Float64Mul 的测试
let quotient = a / b; // 对应 Float64Div 的测试
let remainder = a % b; // 对应 Float64Mod 的测试
```

* **类型转换:**

```javascript
let integer = 10;
let floatFromInteger = parseFloat(integer); // 对应 ChangeInt32ToFloat64 的测试

let floatValue = 3.14;
let integerFromFloat = parseInt(floatValue); // 对应 TruncateFloat64ToInt32 的测试
```

* **带溢出检查的整数运算 (虽然 JavaScript 中整数运算会自动转换为浮点数，但在底层实现中可能会用到带溢出检查的指令):**

```javascript
// JavaScript 中 Number.MAX_SAFE_INTEGER 和 Number.MIN_SAFE_INTEGER 定义了安全整数范围
let maxInt = Number.MAX_SAFE_INTEGER;
let willOverflow = maxInt + 1; // JavaScript 会自动转换为浮点数，但在底层可能测试溢出情况
```

总之，这部分 C++ 代码是 V8 引擎质量保证的关键部分，它确保了 JavaScript 中数字运算的准确性和可靠性。这些测试模拟了各种可能的输入和场景，以验证编译器生成的机器码是否符合预期。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
(MachineType::Float32());
    m.Return(m.Float32Sub(m.Parameter(0), m.Float32Constant(i)));

    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(j - i, m.Call(j)); }
  }
}


TEST(RunFloat64SubImm1) {
  FOR_FLOAT64_INPUTS(i) {
    BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
    m.Return(m.Float64Sub(m.Float64Constant(i), m.Parameter(0)));

    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(i - j, m.Call(j)); }
  }
}


TEST(RunFloat64SubImm2) {
  FOR_FLOAT64_INPUTS(i) {
    BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
    m.Return(m.Float64Sub(m.Parameter(0), m.Float64Constant(i)));

    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(j - i, m.Call(j)); }
  }
}


TEST(RunFloat64SubP) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);

  bt.AddReturn(m.Float64Sub(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      double expected = pl - pr;
      CHECK_DOUBLE_EQ(expected, bt.call(pl, pr));
    }
  }
}


TEST(RunFloat32MulP) {
  RawMachineAssemblerTester<int32_t> m;
  Float32BinopTester bt(&m);

  bt.AddReturn(m.Float32Mul(bt.param0, bt.param1));

  FOR_FLOAT32_INPUTS(pl) {
    FOR_FLOAT32_INPUTS(pr) { CHECK_FLOAT_EQ(pl * pr, bt.call(pl, pr)); }
  }
}


TEST(RunFloat64MulP) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);

  bt.AddReturn(m.Float64Mul(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      double expected = pl * pr;
      CHECK_DOUBLE_EQ(expected, bt.call(pl, pr));
    }
  }
}

TEST(RunFloat32MulAndFloat32Neg) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(m.Float32Neg(m.Float32Mul(m.Parameter(0), m.Parameter(1))));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(-(i * j), m.Call(i, j)); }
  }
}

TEST(RunFloat64MulAndFloat64Neg) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Neg(m.Float64Mul(m.Parameter(0), m.Parameter(1))));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(-(i * j), m.Call(i, j)); }
  }
}

TEST(RunFloat32NegAndFloat32Mul1) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(m.Float32Mul(m.Float32Neg(m.Parameter(0)), m.Parameter(1)));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ((-i * j), m.Call(i, j)); }
  }
}

TEST(RunFloat64NegAndFloat64Mul1) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Mul(m.Float64Neg(m.Parameter(0)), m.Parameter(1)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ((-i * j), m.Call(i, j)); }
  }
}

TEST(RunFloat32NegAndFloat32Mul2) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(m.Float32Mul(m.Parameter(0), m.Float32Neg(m.Parameter(1))));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ((i * -j), m.Call(i, j)); }
  }
}

TEST(RunFloat64NegAndFloat64Mul2) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Mul(m.Parameter(0), m.Float64Neg(m.Parameter(1))));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ((i * -j), m.Call(i, j)); }
  }
}

TEST(RunFloat32NegAndFloat32Mul3) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  m.Return(
      m.Float32Mul(m.Float32Neg(m.Parameter(0)), m.Float32Neg(m.Parameter(1))));

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ((-i * -j), m.Call(i, j)); }
  }
}

TEST(RunFloat64NegAndFloat64Mul3) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(
      m.Float64Mul(m.Float64Neg(m.Parameter(0)), m.Float64Neg(m.Parameter(1))));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ((-i * -j), m.Call(i, j)); }
  }
}

TEST(RunFloat64MulAndFloat64Add1) {
  BufferedRawMachineAssemblerTester<double> m(
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64());
  m.Return(m.Float64Add(m.Float64Mul(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      FOR_FLOAT64_INPUTS(k) { CHECK_DOUBLE_EQ((i * j) + k, m.Call(i, j, k)); }
    }
  }
}


TEST(RunFloat64MulAndFloat64Add2) {
  BufferedRawMachineAssemblerTester<double> m(
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64());
  m.Return(m.Float64Add(m.Parameter(0),
                        m.Float64Mul(m.Parameter(1), m.Parameter(2))));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      FOR_FLOAT64_INPUTS(k) { CHECK_DOUBLE_EQ(i + (j * k), m.Call(i, j, k)); }
    }
  }
}


TEST(RunFloat64MulAndFloat64Sub1) {
  BufferedRawMachineAssemblerTester<double> m(
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64());
  m.Return(m.Float64Sub(m.Float64Mul(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      FOR_FLOAT64_INPUTS(k) { CHECK_DOUBLE_EQ((i * j) - k, m.Call(i, j, k)); }
    }
  }
}


TEST(RunFloat64MulAndFloat64Sub2) {
  BufferedRawMachineAssemblerTester<double> m(
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64());
  m.Return(m.Float64Sub(m.Parameter(0),
                        m.Float64Mul(m.Parameter(1), m.Parameter(2))));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      FOR_FLOAT64_INPUTS(k) { CHECK_DOUBLE_EQ(i - (j * k), m.Call(i, j, k)); }
    }
  }
}


TEST(RunFloat64MulImm1) {
  FOR_FLOAT64_INPUTS(i) {
    BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
    m.Return(m.Float64Mul(m.Float64Constant(i), m.Parameter(0)));

    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(i * j, m.Call(j)); }
  }
}


TEST(RunFloat64MulImm2) {
  FOR_FLOAT64_INPUTS(i) {
    BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
    m.Return(m.Float64Mul(m.Parameter(0), m.Float64Constant(i)));

    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(j * i, m.Call(j)); }
  }
}


TEST(RunFloat32DivP) {
  RawMachineAssemblerTester<int32_t> m;
  Float32BinopTester bt(&m);

  bt.AddReturn(m.Float32Div(bt.param0, bt.param1));

  FOR_FLOAT32_INPUTS(pl) {
    FOR_FLOAT32_INPUTS(pr) {
      CHECK_FLOAT_EQ(base::Divide(pl, pr), bt.call(pl, pr));
    }
  }
}


TEST(RunFloat64DivP) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);

  bt.AddReturn(m.Float64Div(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      CHECK_DOUBLE_EQ(base::Divide(pl, pr), bt.call(pl, pr));
    }
  }
}


TEST(RunFloat64ModP) {
  RawMachineAssemblerTester<int32_t> m;
  Float64BinopTester bt(&m);

  bt.AddReturn(m.Float64Mod(bt.param0, bt.param1));

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(Modulo(i, j), bt.call(i, j)); }
  }
}


TEST(RunChangeInt32ToFloat64_A) {
  int32_t magic = 0x986234;
  BufferedRawMachineAssemblerTester<double> m;
  m.Return(m.ChangeInt32ToFloat64(m.Int32Constant(magic)));
  CHECK_DOUBLE_EQ(static_cast<double>(magic), m.Call());
}


TEST(RunChangeInt32ToFloat64_B) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Int32());
  m.Return(m.ChangeInt32ToFloat64(m.Parameter(0)));

  FOR_INT32_INPUTS(i) { CHECK_DOUBLE_EQ(static_cast<double>(i), m.Call(i)); }
}


TEST(RunChangeUint32ToFloat64) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Uint32());
  m.Return(m.ChangeUint32ToFloat64(m.Parameter(0)));

  FOR_UINT32_INPUTS(i) { CHECK_DOUBLE_EQ(static_cast<double>(i), m.Call(i)); }
}


TEST(RunTruncateFloat32ToInt32) {
  // The upper bound is (INT32_MAX + 1), which is the lowest float-representable
  // number above INT32_MAX which cannot be represented as int32.
  float upper_bound = 2147483648.0f;
  // We use INT32_MIN as a lower bound because (INT32_MIN - 1) is not
  // representable as float, and no number between (INT32_MIN - 1) and INT32_MIN
  // is.
  float lower_bound = static_cast<float>(INT32_MIN);
  {
    BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Float32());
    m.Return(m.TruncateFloat32ToInt32(m.Parameter(0),
                                      TruncateKind::kArchitectureDefault));
    FOR_FLOAT32_INPUTS(i) {
      if (i < upper_bound && i >= lower_bound) {
        CHECK_EQ(static_cast<int32_t>(i), m.Call(i));
      } else if (i < lower_bound) {
#if V8_TARGET_ARCH_MIPS64 && !_MIPS_ARCH_MIPS64R6
        CHECK_EQ(std::numeric_limits<int32_t>::max(), m.Call(i));
#else
        CHECK_EQ(std::numeric_limits<int32_t>::min(), m.Call(i));
#endif
      } else if (i >= upper_bound) {
#if V8_TARGET_ARCH_IA32 || V8_TARGET_ARCH_X64
        CHECK_EQ(std::numeric_limits<int32_t>::min(), m.Call(i));
#else
        CHECK_EQ(std::numeric_limits<int32_t>::max(), m.Call(i));
#endif
      } else {
        DCHECK(std::isnan(i));
#if V8_TARGET_ARCH_IA32 || V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_S390X || \
    V8_TARGET_ARCH_PPC64
        CHECK_EQ(std::numeric_limits<int32_t>::min(), m.Call(i));
#elif V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_LOONG64
        CHECK_EQ(0, m.Call(i));
#elif V8_TARGET_ARCH_RISCV64 || V8_TARGET_ARCH_RISCV32
        CHECK_EQ(std::numeric_limits<int32_t>::max(), m.Call(i));
#endif
      }
    }
  }
  {
    BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Float32());
    m.Return(m.TruncateFloat32ToInt32(m.Parameter(0),
                                      TruncateKind::kSetOverflowToMin));
    FOR_FLOAT32_INPUTS(i) {
      if (i < upper_bound && i >= lower_bound) {
        CHECK_EQ(static_cast<int32_t>(i), m.Call(i));
      } else if (!std::isnan(i)) {
        CHECK_EQ(std::numeric_limits<int32_t>::min(), m.Call(i));
      } else {
        DCHECK(std::isnan(i));
#if V8_TARGET_ARCH_IA32 || V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_S390X || \
    V8_TARGET_ARCH_PPC64
        CHECK_EQ(std::numeric_limits<int32_t>::min(), m.Call(i));
#elif V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_LOONG64
        CHECK_EQ(0, m.Call(i));
#endif
      }
    }
  }
}

TEST(RunTruncateFloat32ToUint32) {
  // The upper bound is (UINT32_MAX + 1), which is the lowest
  // float-representable number above UINT32_MAX which cannot be represented as
  // uint32.
  double upper_bound = 4294967296.0f;
  double lower_bound = -1.0f;

  // No tests outside the range of UINT32 are performed, as the semantics are
  // tricky on x64. On this architecture, the assembler transforms float32 into
  // a signed int64 instead of an unsigned int32. Overflow can then be detected
  // by converting back to float and testing for equality as done in
  // wasm-compiler.cc .
  //
  // On arm architectures, TruncateKind::kArchitectureDefault rounds towards 0
  // upon overflow and returns 0 if the input is NaN.
  // TruncateKind::kSetOverflowToMin returns 0 on overflow and NaN.
  {
    BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Float32());
    m.Return(m.TruncateFloat32ToUint32(m.Parameter(0),
                                       TruncateKind::kArchitectureDefault));
    FOR_UINT32_INPUTS(i) {
      volatile float input = static_cast<float>(i);
      if (input < upper_bound) {
        CHECK_EQ(static_cast<uint32_t>(input), m.Call(input));
      }
    }
    FOR_FLOAT32_INPUTS(j) {
      if ((j < upper_bound) && (j > lower_bound)) {
        CHECK_EQ(static_cast<uint32_t>(j), m.Call(j));
      }
    }
  }
  {
    BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Float32());
    m.Return(m.TruncateFloat32ToUint32(m.Parameter(0),
                                       TruncateKind::kSetOverflowToMin));
    FOR_UINT32_INPUTS(i) {
      volatile float input = static_cast<float>(i);
      if (input < upper_bound) {
        CHECK_EQ(static_cast<uint32_t>(input), m.Call(input));
      }
    }
    FOR_FLOAT32_INPUTS(j) {
      if ((j < upper_bound) && (j > lower_bound)) {
        CHECK_EQ(static_cast<uint32_t>(j), m.Call(j));
      }
    }
  }
}


TEST(RunChangeFloat64ToInt32_A) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  double magic = 11.1;
  m.Return(m.ChangeFloat64ToInt32(m.Float64Constant(magic)));
  CHECK_EQ(static_cast<int32_t>(magic), m.Call());
}


TEST(RunChangeFloat64ToInt32_B) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Float64());
  m.Return(m.ChangeFloat64ToInt32(m.Parameter(0)));

  // Note we don't check fractional inputs, or inputs outside the range of
  // int32, because these Convert operators really should be Change operators.
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, m.Call(static_cast<double>(i))); }

  for (int32_t n = 1; n < 31; ++n) {
    CHECK_EQ(1 << n, m.Call(static_cast<double>(1 << n)));
  }

  for (int32_t n = 1; n < 31; ++n) {
    CHECK_EQ(3 << n, m.Call(static_cast<double>(3 << n)));
  }
}

TEST(RunChangeFloat64ToUint32) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Float64());
  m.Return(m.ChangeFloat64ToUint32(m.Parameter(0)));

  {
    FOR_UINT32_INPUTS(i) { CHECK_EQ(i, m.Call(static_cast<double>(i))); }
  }

  // Check various powers of 2.
  for (int32_t n = 1; n < 31; ++n) {
    { CHECK_EQ(1u << n, m.Call(static_cast<double>(1u << n))); }

    { CHECK_EQ(3u << n, m.Call(static_cast<double>(3u << n))); }
  }
  // Note we don't check fractional inputs, because these Convert operators
  // really should be Change operators.
}


TEST(RunTruncateFloat64ToFloat32) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float64());

  m.Return(m.TruncateFloat64ToFloat32(m.Parameter(0)));

  FOR_FLOAT64_INPUTS(i) { CHECK_FLOAT_EQ(DoubleToFloat32(i), m.Call(i)); }
}

uint64_t ToInt64(uint32_t low, uint32_t high) {
  return (static_cast<uint64_t>(high) << 32) | static_cast<uint64_t>(low);
}

#if V8_TARGET_ARCH_32_BIT
TEST(RunInt32PairAdd) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
      MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairAdd = m.Int32PairAdd(m.Parameter(0), m.Parameter(1), m.Parameter(2),
                                 m.Parameter(3));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairAdd));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairAdd));
  m.Return(m.Int32Constant(74));

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
             static_cast<uint32_t>(i >> 32),
             static_cast<uint32_t>(j & 0xFFFFFFFF),
             static_cast<uint32_t>(j >> 32));
      CHECK_EQ(i + j, ToInt64(low, high));
    }
  }
}

TEST(RunInt32PairAddUseOnlyHighWord) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
      MachineType::Uint32());

  m.Return(m.Projection(1, m.Int32PairAdd(m.Parameter(0), m.Parameter(1),
                                          m.Parameter(2), m.Parameter(3))));

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      CHECK_EQ(
          static_cast<uint32_t>((i + j) >> 32),
          static_cast<uint32_t>(m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
                                       static_cast<uint32_t>(i >> 32),
                                       static_cast<uint32_t>(j & 0xFFFFFFFF),
                                       static_cast<uint32_t>(j >> 32))));
    }
  }
}

void TestInt32PairAddWithSharedInput(int a, int b, int c, int d) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                               MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairAdd = m.Int32PairAdd(m.Parameter(a), m.Parameter(b), m.Parameter(c),
                                 m.Parameter(d));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairAdd));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairAdd));
  m.Return(m.Int32Constant(74));

  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      m.Call(i, j);
      uint32_t inputs[] = {i, j};
      CHECK_EQ(ToInt64(inputs[a], inputs[b]) + ToInt64(inputs[c], inputs[d]),
               ToInt64(low, high));
    }
  }
}

TEST(RunInt32PairAddWithSharedInput) {
  TestInt32PairAddWithSharedInput(0, 0, 0, 0);
  TestInt32PairAddWithSharedInput(1, 0, 0, 0);
  TestInt32PairAddWithSharedInput(0, 1, 0, 0);
  TestInt32PairAddWithSharedInput(0, 0, 1, 0);
  TestInt32PairAddWithSharedInput(0, 0, 0, 1);
  TestInt32PairAddWithSharedInput(1, 1, 0, 0);
}

TEST(RunInt32PairSub) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
      MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairSub = m.Int32PairSub(m.Parameter(0), m.Parameter(1), m.Parameter(2),
                                 m.Parameter(3));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairSub));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairSub));
  m.Return(m.Int32Constant(74));

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
             static_cast<uint32_t>(i >> 32),
             static_cast<uint32_t>(j & 0xFFFFFFFF),
             static_cast<uint32_t>(j >> 32));
      CHECK_EQ(i - j, ToInt64(low, high));
    }
  }
}

TEST(RunInt32PairSubUseOnlyHighWord) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
      MachineType::Uint32());

  m.Return(m.Projection(1, m.Int32PairSub(m.Parameter(0), m.Parameter(1),
                                          m.Parameter(2), m.Parameter(3))));

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      CHECK_EQ(
          static_cast<uint32_t>((i - j) >> 32),
          static_cast<uint32_t>(m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
                                       static_cast<uint32_t>(i >> 32),
                                       static_cast<uint32_t>(j & 0xFFFFFFFF),
                                       static_cast<uint32_t>(j >> 32))));
    }
  }
}

void TestInt32PairSubWithSharedInput(int a, int b, int c, int d) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                               MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairSub = m.Int32PairSub(m.Parameter(a), m.Parameter(b), m.Parameter(c),
                                 m.Parameter(d));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairSub));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairSub));
  m.Return(m.Int32Constant(74));

  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      m.Call(i, j);
      uint32_t inputs[] = {i, j};
      CHECK_EQ(ToInt64(inputs[a], inputs[b]) - ToInt64(inputs[c], inputs[d]),
               ToInt64(low, high));
    }
  }
}

TEST(RunInt32PairSubWithSharedInput) {
  TestInt32PairSubWithSharedInput(0, 0, 0, 0);
  TestInt32PairSubWithSharedInput(1, 0, 0, 0);
  TestInt32PairSubWithSharedInput(0, 1, 0, 0);
  TestInt32PairSubWithSharedInput(0, 0, 1, 0);
  TestInt32PairSubWithSharedInput(0, 0, 0, 1);
  TestInt32PairSubWithSharedInput(1, 1, 0, 0);
}

TEST(RunInt32PairMul) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
      MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairMul = m.Int32PairMul(m.Parameter(0), m.Parameter(1), m.Parameter(2),
                                 m.Parameter(3));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairMul));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairMul));
  m.Return(m.Int32Constant(74));

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
             static_cast<uint32_t>(i >> 32),
             static_cast<uint32_t>(j & 0xFFFFFFFF),
             static_cast<uint32_t>(j >> 32));
      CHECK_EQ(i * j, ToInt64(low, high));
    }
  }
}

TEST(RunInt32PairMulUseOnlyHighWord) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
      MachineType::Uint32());

  m.Return(m.Projection(1, m.Int32PairMul(m.Parameter(0), m.Parameter(1),
                                          m.Parameter(2), m.Parameter(3))));

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      CHECK_EQ(
          static_cast<uint32_t>((i * j) >> 32),
          static_cast<uint32_t>(m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
                                       static_cast<uint32_t>(i >> 32),
                                       static_cast<uint32_t>(j & 0xFFFFFFFF),
                                       static_cast<uint32_t>(j >> 32))));
    }
  }
}

void TestInt32PairMulWithSharedInput(int a, int b, int c, int d) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                               MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairMul = m.Int32PairMul(m.Parameter(a), m.Parameter(b), m.Parameter(c),
                                 m.Parameter(d));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairMul));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairMul));
  m.Return(m.Int32Constant(74));

  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      m.Call(i, j);
      uint32_t inputs[] = {i, j};
      CHECK_EQ(ToInt64(inputs[a], inputs[b]) * ToInt64(inputs[c], inputs[d]),
               ToInt64(low, high));
    }
  }
}

TEST(RunInt32PairMulWithSharedInput) {
  TestInt32PairMulWithSharedInput(0, 0, 0, 0);
  TestInt32PairMulWithSharedInput(1, 0, 0, 0);
  TestInt32PairMulWithSharedInput(0, 1, 0, 0);
  TestInt32PairMulWithSharedInput(0, 0, 1, 0);
  TestInt32PairMulWithSharedInput(0, 0, 0, 1);
  TestInt32PairMulWithSharedInput(1, 1, 0, 0);
  TestInt32PairMulWithSharedInput(0, 1, 1, 0);
}

TEST(RunWord32PairShl) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairShl =
      m.Word32PairShl(m.Parameter(0), m.Parameter(1), m.Parameter(2));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairShl));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairShl));
  m.Return(m.Int32Constant(74));

  FOR_UINT64_INPUTS(i) {
    for (uint32_t j = 0; j < 64; j++) {
      m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
             static_cast<uint32_t>(i >> 32), j);
      CHECK_EQ(i << j, ToInt64(low, high));
    }
  }
}

TEST(RunWord32PairShlUseOnlyHighWord) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());

  m.Return(m.Projection(
      1, m.Word32PairShl(m.Parameter(0), m.Parameter(1), m.Parameter(2))));

  FOR_UINT64_INPUTS(i) {
    for (uint32_t j = 0; j < 64; j++) {
      CHECK_EQ(
          static_cast<uint32_t>((i << j) >> 32),
          static_cast<uint32_t>(m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
                                       static_cast<uint32_t>(i >> 32), j)));
    }
  }
}

void TestWord32PairShlWithSharedInput(int a, int b) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                               MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairAdd =
      m.Word32PairShl(m.Parameter(a), m.Parameter(b), m.Parameter(1));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairAdd));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairAdd));
  m.Return(m.Int32Constant(74));

  FOR_UINT32_INPUTS(i) {
    for (uint32_t j = 0; j < 64; j++) {
      m.Call(i, j);
      uint32_t inputs[] = {i, j};
      CHECK_EQ(ToInt64(inputs[a], inputs[b]) << j, ToInt64(low, high));
    }
  }
}

TEST(RunWord32PairShlWithSharedInput) {
  TestWord32PairShlWithSharedInput(0, 0);
  TestWord32PairShlWithSharedInput(0, 1);
  TestWord32PairShlWithSharedInput(1, 0);
  TestWord32PairShlWithSharedInput(1, 1);
}

TEST(RunWord32PairShr) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairAdd =
      m.Word32PairShr(m.Parameter(0), m.Parameter(1), m.Parameter(2));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairAdd));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairAdd));
  m.Return(m.Int32Constant(74));

  FOR_UINT64_INPUTS(i) {
    for (uint32_t j = 0; j < 64; j++) {
      m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
             static_cast<uint32_t>(i >> 32), j);
      CHECK_EQ(i >> j, ToInt64(low, high));
    }
  }
}

TEST(RunWord32PairShrUseOnlyHighWord) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());

  m.Return(m.Projection(
      1, m.Word32PairShr(m.Parameter(0), m.Parameter(1), m.Parameter(2))));

  FOR_UINT64_INPUTS(i) {
    for (uint32_t j = 0; j < 64; j++) {
      CHECK_EQ(
          static_cast<uint32_t>((i >> j) >> 32),
          static_cast<uint32_t>(m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
                                       static_cast<uint32_t>(i >> 32), j)));
    }
  }
}

TEST(RunWord32PairSar) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());

  uint32_t high;
  uint32_t low;

  Node* PairAdd =
      m.Word32PairSar(m.Parameter(0), m.Parameter(1), m.Parameter(2));

  m.StoreToPointer(&low, MachineRepresentation::kWord32,
                   m.Projection(0, PairAdd));
  m.StoreToPointer(&high, MachineRepresentation::kWord32,
                   m.Projection(1, PairAdd));
  m.Return(m.Int32Constant(74));

  FOR_INT64_INPUTS(i) {
    for (uint32_t j = 0; j < 64; j++) {
      m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
             static_cast<uint32_t>(i >> 32), j);
      CHECK_EQ(i >> j, static_cast<int64_t>(ToInt64(low, high)));
    }
  }
}

TEST(RunWord32PairSarUseOnlyHighWord) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());

  m.Return(m.Projection(
      1, m.Word32PairSar(m.Parameter(0), m.Parameter(1), m.Parameter(2))));

  FOR_INT64_INPUTS(i) {
    for (uint32_t j = 0; j < 64; j++) {
      CHECK_EQ(
          static_cast<uint32_t>((i >> j) >> 32),
          static_cast<uint32_t>(m.Call(static_cast<uint32_t>(i & 0xFFFFFFFF),
                                       static_cast<uint32_t>(i >> 32), j)));
    }
  }
}
#endif

TEST(RunDeadChangeFloat64ToInt32) {
  RawMachineAssemblerTester<int32_t> m;
  const int magic = 0x88ABCDA4;
  m.ChangeFloat64ToInt32(m.Float64Constant(999.78));
  m.Return(m.Int32Constant(magic));
  CHECK_EQ(magic, m.Call());
}


TEST(RunDeadChangeInt32ToFloat64) {
  RawMachineAssemblerTester<int32_t> m;
  const int magic = 0x8834ABCD;
  m.ChangeInt32ToFloat64(m.Int32Constant(magic - 6888));
  m.Return(m.Int32Constant(magic));
  CHECK_EQ(magic, m.Call());
}


TEST(RunLoopPhiInduction2) {
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


TEST(RunFloatDiamond) {
  RawMachineAssemblerTester<int32_t> m;

  const int magic = 99645;
  float buffer = 0.1f;
  float constant = 99.99f;

  RawMachineLabel blocka, blockb, end;
  Node* k1 = m.Float32Constant(constant);
  Node* k2 = m.Float32Constant(0 - constant);
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);
  m.Bind(&end);
  Node* phi = m.Phi(MachineRepresentation::kFloat32, k2, k1);
  m.Store(MachineRepresentation::kFloat32, m.PointerConstant(&buffer),
          m.IntPtrConstant(0), phi, kNoWriteBarrier);
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
  CHECK(constant == buffer);
}


TEST(RunDoubleDiamond) {
  RawMachineAssemblerTester<int32_t> m;

  const int magic = 99645;
  double buffer = 0.1;
  double constant = 99.99;

  RawMachineLabel blocka, blockb, end;
  Node* k1 = m.Float64Constant(constant);
  Node* k2 = m.Float64Constant(0 - constant);
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);
  m.Bind(&end);
  Node* phi = m.Phi(MachineRepresentation::kFloat64, k2, k1);
  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&buffer),
          m.Int32Constant(0), phi, kNoWriteBarrier);
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
  CHECK_EQ(constant, buffer);
}


TEST(RunRefDiamond) {
  RawMachineAssemblerTester<int32_t> m;

  const int magic = 99644;
  DirectHandle<String> rexpected =
      CcTest::i_isolate()->factory()->InternalizeUtf8String("A");
  Tagged<String> buffer;

  RawMachineLabel blocka, blockb, end;
  Node* k1 = m.StringConstant("A");
  Node* k2 = m.StringConstant("B");
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);
  m.Bind(&end);
  Node* phi = m.Phi(MachineRepresentation::kTagged, k2, k1);
  if (COMPRESS_POINTERS_BOOL) {
    // Since |buffer| is located off-heap, use full pointer store.
    m.Store(MachineType::PointerRepresentation(), m.PointerConstant(&buffer),
            m.Int32Constant(0), m.BitcastTaggedToWord(phi), kNoWriteBarrier);
  } else {
    m.Store(MachineRepresentation::kTagged, m.PointerConstant(&buffer),
            m.Int32Constant(0), phi, kNoWriteBarrier);
  }
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
  CHECK(Object::SameValue(*rexpected, buffer));
}


TEST(RunDoubleRefDiamond) {
  RawMachineAssemblerTester<int32_t> m;

  const int magic = 99648;
  double dbuffer = 0.1;
  double dconstant = 99.99;
  DirectHandle<String> rexpected =
      CcTest::i_isolate()->factory()->InternalizeUtf8String("AX");
  Tagged<String> rbuffer;

  RawMachineLabel blocka, blockb, end;
  Node* d1 = m.Float64Constant(dconstant);
  Node* d2 = m.Float64Constant(0 - dconstant);
  Node* r1 = m.StringConstant("AX");
  Node* r2 = m.StringConstant("BX");
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);
  m.Bind(&end);
  Node* dphi = m.Phi(MachineRepresentation::kFloat64, d2, d1);
  Node* rphi = m.Phi(MachineRepresentation::kTagged, r2, r1);
  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&dbuffer),
          m.Int32Constant(0), dphi, kNoWriteBarrier);
  if (COMPRESS_POINTERS_BOOL) {
    // Since |buffer| is located off-heap, use full pointer store.
    m.Store(MachineType::PointerRepresentation(), m.PointerConstant(&rbuffer),
            m.Int32Constant(0), m.BitcastTaggedToWord(rphi), kNoWriteBarrier);
  } else {
    m.Store(MachineRepresentation::kTagged, m.PointerConstant(&rbuffer),
            m.Int32Constant(0), rphi, kNoWriteBarrier);
  }
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
  CHECK_EQ(dconstant, dbuffer);
  CHECK(Object::SameValue(*rexpected, rbuffer));
}


TEST(RunDoubleRefDoubleDiamond) {
  RawMachineAssemblerTester<int32_t> m;

  const int magic = 99649;
  double dbuffer = 0.1;
  double dconstant = 99.997;
  DirectHandle<String> rexpected =
      CcTest::i_isolate()->factory()->InternalizeUtf8String("AD");
  Tagged<String> rbuffer;

  RawMachineLabel blocka, blockb, mid, blockd, blocke, end;
  Node* d1 = m.Float64Constant(dconstant);
  Node* d2 = m.Float64Constant(0 - dconstant);
  Node* r1 = m.StringConstant("AD");
  Node* r2 = m.StringConstant("BD");
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&mid);
  m.Bind(&blockb);
  m.Goto(&mid);
  m.Bind(&mid);
  Node* dphi1 = m.Phi(MachineRepresentation::kFloat64, d2, d1);
  Node* rphi1 = m.Phi(MachineRepresentation::kTagged, r2, r1);
  m.Branch(m.Int32Constant(0), &blockd, &blocke);

  m.Bind(&blockd);
  m.Goto(&end);
  m.Bind(&blocke);
  m.Goto(&end);
  m.Bind(&end);
  Node* dphi2 = m.Phi(MachineRepresentation::kFloat64, d1, dphi1);
  Node* rphi2 = m.Phi(MachineRepresentation::kTagged, r1, rphi1);

  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&dbuffer),
          m.Int32Constant(0), dphi2, kNoWriteBarrier);
  if (COMPRESS_POINTERS_BOOL) {
    // Since |buffer| is located off-heap, use full pointer store.
    m.Store(MachineType::PointerRepresentation(), m.PointerConstant(&rbuffer),
            m.Int32Constant(0), m.BitcastTaggedToWord(rphi2), kNoWriteBarrier);
  } else {
    m.Store(MachineRepresentation::kTagged, m.PointerConstant(&rbuffer),
            m.Int32Constant(0), rphi2, kNoWriteBarrier);
  }
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
  CHECK_EQ(dconstant, dbuffer);
  CHECK(Object::SameValue(*rexpected, rbuffer));
}


TEST(RunDoubleLoopPhi) {
  RawMachineAssemblerTester<int32_t> m;
  RawMachineLabel header, body, end;

  int magic = 99773;
  double buffer = 0.99;
  double dconstant = 777.1;

  Node* zero = m.Int32Constant(0);
  Node* dk = m.Float64Constant(dconstant);

  m.Goto(&header);
  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kFloat64, dk, dk);
  phi->ReplaceInput(1, phi);
  m.Branch(zero, &body, &end);
  m.Bind(&body);
  m.Goto(&header);
  m.Bind(&end);
  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&buffer),
          m.Int32Constant(0), phi, kNoWriteBarrier);
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
}


TEST(RunCountToTenAccRaw) {
  RawMachineAssemblerTester<int32_t> m;

  Node* zero = m.Int32Constant(0);
  Node* ten = m.Int32Constant(10);
  Node* one = m.Int32Constant(1);

  RawMachineLabel header, body, body_cont, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* i = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* j = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Goto(&body);

  m.Bind(&body);
  Node* next_i = m.Int32Add(i, one);
  Node* next_j = m.Int32Add(j, one);
  m.Branch(m.Word32Equal(next_i, ten), &end, &body_cont);

  m.Bind(&body_cont);
  i->ReplaceInput(1, next_i);
  j->ReplaceInput(1, next_j);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(ten);

  CHECK_EQ(10, m.Call());
}


TEST(RunCountToTenAccRaw2) {
  RawMachineAssemblerTester<int32_t> m;

  Node* zero = m.Int32Constant(0);
  Node* ten = m.Int32Constant(10);
  Node* one = m.Int32Constant(1);

  RawMachineLabel header, body, body_cont, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* i = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* j = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* k = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Goto(&body);

  m.Bind(&body);
  Node* next_i = m.Int32Add(i, one);
  Node* next_j = m.Int32Add(j, one);
  Node* next_k = m.Int32Add(j, one);
  m.Branch(m.Word32Equal(next_i, ten), &end, &body_cont);

  m.Bind(&body_cont);
  i->ReplaceInput(1, next_i);
  j->ReplaceInput(1, next_j);
  k->ReplaceInput(1, next_k);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(ten);

  CHECK_EQ(10, m.Call());
}


TEST(RunAddTree) {
  RawMachineAssemblerTester<int32_t> m;
  int32_t inputs[] = {11, 12, 13, 14, 15, 16, 17, 18};

  Node* base = m.PointerConstant(inputs);
  Node* n0 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(0 * sizeof(int32_t)));
  Node* n1 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(1 * sizeof(int32_t)));
  Node* n2 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(2 * sizeof(int32_t)));
  Node* n3 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(3 * sizeof(int32_t)));
  Node* n4 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(4 * sizeof(int32_t)));
  Node* n5 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(5 * sizeof(int32_t)));
  Node* n6 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(6 * sizeof(int32_t)));
  Node* n7 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(7 * sizeof(int32_t)));

  Node* i1 = m.Int32Add(n0, n1);
  Node* i2 = m.Int32Add(n2, n3);
  Node* i3 = m.Int32Add(n4, n5);
  Node* i4 = m.Int32Add(n6, n7);

  Node* i5 = m.Int32Add(i1, i2);
  Node* i6 = m.Int32Add(i3, i4);

  Node* i7 = m.Int32Add(i5, i6);

  m.Return(i7);

  CHECK_EQ(116, m.Call());
}


static const int kFloat64CompareHelperTestCases = 15;
static const int kFloat64CompareHelperNodeType = 4;

static int Float64CompareHelper(RawMachineAssemblerTester<int32_t>* m,
                                int test_case, int node_type, double x,
                                double y) {
  static double buffer[2];
  buffer[0] = x;
  buffer[1] = y;
  CHECK(0 <= test_case && test_case < kFloat64CompareHelperTestCases);
  CHECK(0 <= node_type && node_type < kFloat64CompareHelperNodeType);
  CHECK(x < y);
  bool load_a = node_type / 2 == 1;
  bool load_b = node_type % 2 == 1;
  Node* a =
      load_a ? m->Load(MachineType::Float64(), m->PointerConstant(&buffer[0]))
             : m->Float64Constant(x);
  Node* b =
      load_b ? m->Load(MachineType::Float64(), m->PointerConstant(&buffer[1]))
             : m->Float64Constant(y);
  Node* cmp = nullptr;
  bool expected = false;
  switch (test_case) {
    // Equal tests.
    case 0:
      cmp = m->Float64Equal(a, b);
      expected = false;
      break;
    case 1:
      cmp = m->Float64Equal(a, a);
      expected = true;
      break;
    // LessThan tests.
    case 2:
      cmp = m->Float64LessThan(a, b);
      expected = true;
      break;
    case 3:
      cmp = m->Float64LessThan(b, a);
      expected = false;
      break;
    case 4:
      cmp = m->Float64LessThan(a, a);
      expected = false;
      break;
    // LessThanOrEqual tests.
    case 5:
      cmp = m->Float64LessThanOrEqual(a, b);
      expected = true;
      break;
    case 6:
      cmp = m->Float64LessThanOrEqual(b, a);
      expected = false;
      break;
    case 7:
      cmp = m->Float64LessThanOrEqual(a, a);
      expected = true;
      break;
    // NotEqual tests.
    case 8:
      cmp = m->Float64NotEqual(a, b);
      expected = true;
      break;
    case 9:
      cmp = m->Float64NotEqual(b, a);
      expected = true;
      break;
    case 10:
      cmp = m->Float64NotEqual(a, a);
      expected = false;
      break;
    // GreaterThan tests.
    case 11:
      cmp = m->Float64GreaterThan(a, a);
      expected = false;
      break;
    case 12:
      cmp = m->Float64GreaterThan(a, b);
      expected = false;
      break;
    // GreaterThanOrEqual tests.
    case 13:
      cmp = m->Float64GreaterThanOrEqual(a, a);
      expected = true;
      break;
    case 14:
      cmp = m->Float64GreaterThanOrEqual(b, a);
      expected = true;
      break;
    default:
      UNREACHABLE();
  }
  m->Return(cmp);
  return expected;
}


TEST(RunFloat64Compare) {
  double inf = V8_INFINITY;
  // All pairs (a1, a2) are of the form a1 < a2.
  double inputs[] = {0.0,  1.0,  -1.0, 0.22, -1.22, 0.22,
                     -inf, 0.22, 0.22, inf,  -inf,  inf};

  for (int test = 0; test < kFloat64CompareHelperTestCases; test++) {
    for (int node_type = 0; node_type < kFloat64CompareHelperNodeType;
         node_type++) {
      for (size_t input = 0; input < arraysize(inputs); input += 2) {
        RawMachineAssemblerTester<int32_t> m;
        int expected = Float64CompareHelper(&m, test, node_type, inputs[input],
                                            inputs[input + 1]);
        CHECK_EQ(expected, m.Call());
      }
    }
  }
}


TEST(RunFloat64UnorderedCompare) {
  RawMachineAssemblerTester<int32_t> m;

  const Operator* operators[] = {m.machine()->Float64Equal(),
                                 m.machine()->Float64LessThan(),
                                 m.machine()->Float64LessThanOrEqual()};

  double nan = std::numeric_limits<double>::quiet_NaN();

  FOR_FLOAT64_INPUTS(i) {
    for (size_t o = 0; o < arraysize(operators); ++o) {
      for (int j = 0; j < 2; j++) {
        RawMachineAssemblerTester<int32_t> t;
        Node* a = t.Float64Constant(i);
        Node* b = t.Float64Constant(nan);
        if (j == 1) std::swap(a, b);
        t.Return(t.AddNode(operators[o], a, b));
        CHECK_EQ(0, t.Call());
      }
    }
  }
}


TEST(RunFloat64Equal) {
  double input_a = 0.0;
  double input_b = 0.0;

  RawMachineAssemblerTester<int32_t> m;
  Node* a = m.LoadFromPointer(&input_a, MachineType::Float64());
  Node* b = m.LoadFromPointer(&input_b, MachineType::Float64());
  m.Return(m.Float64Equal(a, b));

  CompareWrapper cmp(IrOpcode::kFloat64Equal);
  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      input_a = pl;
      input_b = pr;
      int32_t expected = cmp.Float64Compare(input_a, input_b) ? 1 : 0;
      CHECK_EQ(expected, m.Call());
    }
  }
}


TEST(RunFloat64LessThan) {
  double input_a = 0.0;
  double input_b = 0.0;

  RawMachineAssemblerTester<int32_t> m;
  Node* a = m.LoadFromPointer(&input_a, MachineType::Float64());
  Node* b = m.LoadFromPointer(&input_b, MachineType::Float64());
  m.Return(m.Float64LessThan(a, b));

  CompareWrapper cmp(IrOpcode::kFloat64LessThan);
  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      input_a = pl;
      input_b = pr;
      int32_t expected = cmp.Float64Compare(input_a, input_b) ? 1 : 0;
      CHECK_EQ(expected, m.Call());
    }
  }
}


static void IntPtrCompare(intptr_t left, intptr_t right) {
  for (int test = 0; test < 7; test++) {
    RawMachineAssemblerTester<bool> m(MachineType::Pointer(),
                                      MachineType::Pointer());
    Node* p0 = m.Parameter(0);
    Node* p1 = m.Parameter(1);
    Node* res = nullptr;
    bool expected = false;
    switch (test) {
      case 0:
        res = m.IntPtrLessThan(p0, p1);
        expected = true;
        break;
      case 1:
        res = m.IntPtrLessThanOrEqual(p0, p1);
        expected = true;
        break;
      case 2:
        res = m.IntPtrEqual(p0, p1);
        expected = false;
        break;
      case 3:
        res = m.IntPtrGreaterThanOrEqual(p0, p1);
        expected = false;
        break;
      case 4:
        res = m.IntPtrGreaterThan(p0, p1);
        expected = false;
        break;
      case 5:
        res = m.IntPtrEqual(p0, p0);
        expected = true;
        break;
      case 6:
        res = m.IntPtrNotEqual(p0, p1);
        expected = true;
        break;
      default:
        UNREACHABLE();
    }
    m.Return(res);
    CHECK_EQ(expected, m.Call(reinterpret_cast<int32_t*>(left),
                              reinterpret_cast<int32_t*>(right)));
  }
}


TEST(RunIntPtrCompare) {
  intptr_t min = std::numeric_limits<intptr_t>::min();
  intptr_t max = std::numeric_limits<intptr_t>::max();
  // An ascending chain of intptr_t
  intptr_t inputs[] = {min, min / 2, -1, 0, 1, max / 2, max};
  for (size_t i = 0; i < arraysize(inputs) - 1; i++) {
    IntPtrCompare(inputs[i], inputs[i + 1]);
  }
}


TEST(RunTestIntPtrArithmetic) {
  static const int kInputSize = 10;
  int32_t inputs[kInputSize];
  int32_t outputs[kInputSize];
  for (int i = 0; i < kInputSize; i++) {
    inputs[i] = i;
    outputs[i] = -1;
  }
  RawMachineAssemblerTester<int32_t*> m;
  Node* input = m.PointerConstant(&inputs[0]);
  Node* output = m.PointerConstant(&outputs[kInputSize - 1]);
  Node* elem_size = m.IntPtrConstant(sizeof(inputs[0]));
  for (int i = 0; i < kInputSize; i++) {
    m.Store(MachineRepresentation::kWord32, output,
            m.Load(MachineType::Int32(), input), kNoWriteBarrier);
    input = m.IntPtrAdd(input, elem_size);
    output = m.IntPtrSub(output, elem_size);
  }
  m.Return(input);
  CHECK_EQ(&inputs[kInputSize], m.Call());
  for (int i = 0; i < kInputSize; i++) {
    CHECK_EQ(i, inputs[i]);
    CHECK_EQ(kInputSize - i - 1, outputs[i]);
  }
}


TEST(RunSpillLotsOfThings) {
  static const int kInputSize = 1000;
  RawMachineAssemblerTester<int32_t> m;
  Node* accs[kInputSize];
  int32_t outputs[kInputSize];
  Node* one = m.Int32Constant(1);
  Node* acc = one;
  for (int i = 0; i < kInputSize; i++) {
    acc = m.Int32Add(acc, one);
    accs[i] = acc;
  }
  for (int i = 0; i < kInputSize; i++) {
    m.StoreToPointer(&outputs[i], MachineRepresentation::kWord32, accs[i]);
  }
  m.Return(one);
  m.Call();
  for (int i = 0; i < kInputSize; i++) {
    CHECK_EQ(outputs[i], i + 2);
  }
}


TEST(RunSpillConstantsAndParameters) {
  static const int kInputSize = 1000;
  static const int32_t kBase = 987;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  int32_t outputs[kInputSize];
  Node* csts[kInputSize];
  Node* accs[kInputSize];
  Node* acc = m.Int32Constant(0);
  for (int i = 0; i < kInputSize; i++) {
    csts[i] = m.Int32Constant(base::AddWithWraparound(kBase, i));
  }
  for (int i = 0; i < kInputSize; i++) {
    acc = m.Int32Add(acc, csts[i]);
    accs[i] = acc;
  }
  for (int i = 0; i < kInputSize; i++) {
    m.StoreToPointer(&outputs[i], MachineRepresentation::kWord32, accs[i]);
  }
  m.Return(m.Int32Add(acc, m.Int32Add(m.Parameter(0), m.Parameter(1))));
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = base::AddWithWraparound(i, j);
      for (int k = 0; k < kInputSize; k++) {
        expected = base::AddWithWraparound(expected, kBase + k);
      }
      CHECK_EQ(expected, m.Call(i, j));
      expected = 0;
      for (int k = 0; k < kInputSize; k++) {
        expected += kBase + k;
        CHECK_EQ(expected, outputs[k]);
      }
    }
  }
}


TEST(RunNewSpaceConstantsInPhi) {
  RawMachineAssemblerTester<Tagged<Object>> m(MachineType::Int32());

  Isolate* isolate = CcTest::i_isolate();
  Handle<HeapNumber> true_val = isolate->factory()->NewHeapNumber(11.2);
  Handle<HeapNumber> false_val = isolate->factory()->NewHeapNumber(11.3);
  Node* true_node = m.HeapConstant(true_val);
  Node* false_node = m.HeapConstant(false_val);

  RawMachineLabel blocka, blockb, end;
  m.Branch(m.Parameter(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);

  m.Bind(&end);
  Node* phi = m.Phi(MachineRepresentation::kTagged, true_node, false_node);
  m.Return(phi);

  CHECK_EQ(*false_val, m.Call(0));
  CHECK_EQ(*true_val, m.Call(1));
}


TEST(RunInt32AddWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32AddWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32AddWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32AddWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32AddWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32AddWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32AddWithOverflowInBranchP) {
  int constant = 911777;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32AddWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, add);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int32Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, add);
  bt.AddReturn(val);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected;
      if (base::bits::SignedAddOverflow32(i, j, &expected)) expected = constant;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}


TEST(RunInt32SubWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32SubWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32SubWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32SubWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32SubWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow32(j, i, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32SubWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32SubWithOverflowInBranchP) {
  int constant = 911999;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* sub = m.Int32SubWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, sub);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int32Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, sub);
  bt.AddReturn(val);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected;
      if (base::bits::SignedSubOverflow32(i, j, &expected)) expected = constant;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}

TEST(RunInt32MulWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32MulWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      if (!expected_ovf) {
        CHECK_EQ(expected_val, actual_val);
      }
    }
  }
}

TEST(RunInt32MulWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32MulWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        if (!expected_ovf) {
          CHECK_EQ(expected_val, actual_val);
        }
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32MulWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        if (!expected_ovf) {
          CHECK_EQ(expected_val, actual_val);
        }
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32MulWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      if (!expected_ovf) {
        CHECK_EQ(expected_val, actual_val);
      }
    }
  }
}

TEST(RunInt32MulWithOverflowInBranchP) {
  int constant = 911777;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32MulWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, add);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int32Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, add);
  bt.AddReturn(val);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected;
      if (base::bits::SignedMulOverflow32(i, j, &expected)) expected = constant;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}

TEST(RunWord64EqualInBranchP) {
  int64_t input;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  if (!m.machine()->Is64()) return;
  Node* value = m.LoadFromPointer(&input, MachineType::Int64());
  m.Branch(m.Word64Equal(value, m.Int64Constant(0)), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(1));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(2));
  input = int64_t{0};
  CHECK_EQ(1, m.Call());
  input = int64_t{1};
  CHECK_EQ(2, m.Call());
  input = int64_t{0x100000000};
  CHECK_EQ(2, m.Call());
}


TEST(RunChangeInt32ToInt64P) {
  if (kSystemPointerSize < 8) return;
  int64_t actual = -1;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  m.StoreToPointer(&actual, MachineRepresentation::kWord64,
                   m.ChangeInt32ToInt64(m.Parameter(0)));
  m.Return(m.Int32Constant(0));
  FOR_INT32_INPUTS(i) {
    int64_t expected = i;
    CHECK_EQ(0, m.Call(i));
    CHECK_EQ(expected, actual);
  }
}


TEST(RunChangeUint32ToUint64P) {
  if (kSystemPointerSize < 8) return;
  int64_t actual = -1;
  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  m.StoreToPointer(&actual, MachineRepresentation::kWord64,
                   m.ChangeUint32ToUint64(m.Parameter(0)));
  m.Return(m.Int32Constant(0));
  FOR_UINT32_INPUTS(i) {
    int64_t expected = static_cast<uint64_t>(i);
    CHECK_EQ(0, m.Call(i));
    CHECK_EQ(expected, actual);
  }
}


TEST(RunTruncateInt64ToInt32P) {
  if (kSystemPointerSize < 8) return;
  int64_t expected = -1;
  RawMachineAssemblerTester<int32_t> m;
  m.Return(m.TruncateInt64ToInt32(
      m.LoadFromPointer(&expected, MachineType::Int64())));
  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      expected = (static_cast<uint64_t>(j) << 32) | i;
      CHECK_EQ(static_cast<int32_t>(expected), m.Call());
    }
  }
}

TEST(RunTruncateFloat64ToWord32P) {
  struct {
    double from;
    double raw;
  } kValues[] = {{0, 0},
                 {0.5, 0},
                 {-0.5, 0},
                 {1.5, 1},
                 {-1.5, -1},
                 {5.5, 5},
                 {-5.0, -5},
                 {std::numeric_limits<double>::quiet_NaN(), 0},
                 {std::numeric_limits<double>::infinity(), 0},
                 {-std::numeric_limits<double>::quiet_NaN(), 0},
                 {-std::numeric_limits<double>::infinity(), 0},
                 {4.94065645841e-324, 0},
                 {-4.94065645841e-324, 0},
                 {0.9999999999999999, 0},
                 {-0.9999999999999999, 0},
                 {4294967296.0, 0},
                 {-4294967296.0, 0},
                 {9223372036854775000.0, 4294966272.0},
                 {-9223372036854775000.0, -4294966272.0},
                 {4.5036e+15, 372629504},
                 {-4.5036e+15, -372629504},
                 {287524199.5377777, 0x11234567},
                 {-287524199.5377777, -0x11234567},
                 {2300193596.302222, 2300193596.0},
                 {-2300193596.302222, -2300193596.0},
                 {4600387192.604444, 305419896},
                 {-4600387192.604444, -305419896},
                 {4823855600872397.0, 1737075661},
                 {-4823855600872397.0, -1737075661},
                 {4503603922337791.0, -1},
                 {-4503603922337791.0, 1},
                 {4503601774854143.0, 2147483647},
                 {-4503601774854143.0, -2147483647},
                 {9007207844675582.0, -2},
                 {-9007207844675582.0, 2},
                 {2.4178527921507624e+24, -536870912},
                 {-2.4178527921507624e+24, 536870912},
                 {2.417853945072267e+24, -536870912},
                 {-2.417853945072267e+24, 536870912},
                 {4.8357055843015248e+24, -1073741824},
                 {-4.8357055843015248e+24, 1073741824},
                 {4.8357078901445341e+24, -1073741824},
                 {-4.8357078901445341e+24, 1073741824},
                 {2147483647.0, 2147483647.0},
                 {-2147483648.0, -2147483648.0},
                 {9.6714111686030497e+24, -2147483648.0},
                 {-9.6714111686030497e+24, -2147483648.0},
                 {9.6714157802890681e+24, -2147483648.0},
                 {-9.6714157802890681e+24, -2147483648.0},
                 {1.9342813113834065e+25, 2147483648.0},
                 {-1.9342813113834065e+25, 2147483648.0},
                 {3.868562622766813e+25, 0},
                 {-3.868562622766813e+25, 0},
                 {1.7976931348623157e+308, 0},
                 {-1.7976931348623157e+308, 0}};
  double input = -1.0;
  RawMachineAssemblerTester<int32_t> m;
  m.Return(m.TruncateFloat64ToWord32(
      m.LoadFromPointer(&input, MachineType::Float64())));
  for (size_t i = 0; i < arraysize(kValues); ++i) {
    input = kValues[i].from;
    uint64_t expected = static_cast<int64_t>(kValues[i].raw);
    CHECK_EQ(static_cast<int>(expected), m.Call());
  }
}

TEST(RunTruncateFloat64ToWord32SignExtension) {
  BufferedRawMachineAssemblerTester<int32_t> r;
  r.Return(r.Int32Sub(r.TruncateFloat64ToWord32(r.Float64Constant(-1.0)),
                      r.Int32Constant(0)));
  CHECK_EQ(-1, r.Call());
}

TEST(RunChangeFloat32ToFloat64) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float32());

  m.Return(m.ChangeFloat32ToFloat64(m.Parameter(0)));

  FOR_FLOAT32_INPUTS(i) { CHECK_DOUBLE_EQ(static_cast<double>(i), m.Call(i)); }
}


TEST(RunFloat32Constant) {
  FOR_FLOAT32_INPUTS(i) {
    BufferedRawMachineAssemblerTester<float> m;
    m.Return(m.Float32Constant(i));
    CHECK_FLOAT_EQ(i, m.Call());
  }
}


TEST(RunFloat64ExtractLowWord32) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Float64());
  m.Return(m.Float64ExtractLowWord32(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) {
    uint32_t expected = static_cast<uint32_t>(base::bit_cast<uint64_t>(i));
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunFloat64ExtractHighWord32) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Float64());
  m.Return(m.Float64ExtractHighWord32(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) {
    uint32_t expected =
        static_cast<uint32_t>(base::bit_cast<uint64_t>(i) >> 32);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunFloat64InsertLowWord32) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Int32());
  m.Return(m.Float64InsertLowWord32(m.Parameter(0), m.Parameter(1)));
  FOR_FLOAT64_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      double expected = base::bit_cast<double>(
          (base::bit_cast<uint64_t>(i) & ~(uint64_t{0xFFFFFFFF})) |
          (static_cast<uint64_t>(base::bit_cast<uint32_t>(j))));
      CHECK_DOUBLE_EQ(expected, m.Call(i, j));
    }
  }
}


TEST(RunFloat64InsertHighWord32) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Uint32());
  m.Return(m.Float64InsertHighWord32(m.Parameter(0), m.Parameter(1)));
  FOR_FLOAT64_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      uint64_t expected = (base::bit_cast<uint64_t>(i) & 0xFFFFFFFF) |
                          (static_cast<uint64_t>(j) << 32);

      CHECK_DOUBLE_EQ(base::bit_cast<double>(expected), m.Call(i, j));
    }
  }
}


TEST(RunFloat32Abs) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  m.Return(m.Float32Abs(m.Parameter(0)));
  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(std::abs(i), m.Call(i)); }
}


TEST(RunFloat64Abs) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Abs(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(std::abs(i), m.Call(i)); }
}

TEST(RunFloat64Acos) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Acos(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::acos(i), m.Call(i)); }
}

TEST(RunFloat64Acosh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Acosh(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::acosh(i), m.Call(i)); }
}

TEST(RunFloat64Asin) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Asin(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::asin(i), m.Call(i)); }
}

TEST(RunFloat64Asinh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Asinh(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::asinh(i), m.Call(i)); }
}

TEST(RunFloat64Atan) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Atan(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHEC
```