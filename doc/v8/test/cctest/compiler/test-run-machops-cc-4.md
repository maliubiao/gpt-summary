Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Understanding the Goal:**

The core request is to analyze a C++ file (`v8/test/cctest/compiler/test-run-machops.cc`) and describe its functionality, especially in the context of V8, JavaScript, and common programming errors. The prompt also mentions it's part 5 of 8, suggesting a larger series of similar files.

**2. Initial Scan and Keyword Identification:**

Quickly scanning the code reveals key elements:

* **`#include` directives:**  These indicate dependencies and give hints about the domain (e.g., "test/cctest/cctest.h", "v8/src/codegen/machine-assembler.h"). The `BufferedRawMachineAssemblerTester` and `RawMachineAssemblerTester` are particularly important.
* **`TEST(...)` macros:** This strongly suggests a testing framework (likely Google Test, commonly used in Chromium/V8). Each `TEST` block defines an independent test case.
* **Arithmetic Operations:**  `Float32Sub`, `Float64Sub`, `Float32Mul`, `Float64Mul`, `Float32Div`, `Float64Div`, `Float64Mod`, `Float32Neg`.
* **Type Conversions:** `ChangeInt32ToFloat64`, `ChangeUint32ToFloat64`, `TruncateFloat32ToInt32`, `TruncateFloat32ToUint32`, `ChangeFloat64ToInt32`, `ChangeFloat64ToUint32`, `TruncateFloat64ToFloat32`.
* **Bitwise Operations (in the latter part):** `Int32PairAdd`, `Int32PairSub`, `Int32PairMul`, `Word32PairShl`, `Word32PairShr`, `Word32PairSar`.
* **Control Flow:** `Branch`, `Goto`, `Bind`, `Phi`.
* **Constants:**  `Float32Constant`, `Float64Constant`, `Int32Constant`, `StringConstant`.
* **Input Generation:** `FOR_FLOAT32_INPUTS`, `FOR_FLOAT64_INPUTS`, `FOR_INT32_INPUTS`, `FOR_UINT32_INPUTS`, `FOR_UINT64_INPUTS`, `FOR_INT64_INPUTS`.
* **Assertions:** `CHECK_FLOAT_EQ`, `CHECK_DOUBLE_EQ`, `CHECK_EQ`, `CHECK`.

**3. Deduce the Core Purpose:**

Based on the keywords, the file clearly focuses on testing the implementation of *machine-level operations* within V8's compiler. The `BufferedRawMachineAssemblerTester` and `RawMachineAssemblerTester` strongly suggest this is about generating and executing sequences of low-level instructions. The "machops" in the filename confirms this.

**4. Analyze Individual Test Cases:**

Examine the structure of each `TEST` block:

* **Setup:** Creation of a `BufferedRawMachineAssemblerTester` or `RawMachineAssemblerTester`. This object is used to build a sequence of machine operations.
* **Operation(s):**  Calls like `m.Float32Sub(...)`, `m.ChangeInt32ToFloat64(...)`, etc. These represent the machine instructions being tested.
* **Return:** `m.Return(...)` signifies the final result of the generated machine code.
* **Input Generation:** The `FOR_...INPUTS` macros generate a range of input values.
* **Execution:** `m.Call(...)` executes the generated machine code with the given inputs.
* **Verification:** The `CHECK_...` macros assert that the actual output matches the expected output.

**5. Connect to JavaScript (if applicable):**

Consider how these low-level operations relate to JavaScript. For instance:

* Floating-point arithmetic (`Float32Sub`, `Float64Mul`) directly corresponds to JavaScript's number operations.
* Type conversions (`ChangeInt32ToFloat64`, `TruncateFloat32ToInt32`) are involved in implicit and explicit type coercion in JavaScript.
* Bitwise operations (`Word32PairShl`) are exposed through JavaScript's bitwise operators.

**6. Identify Potential Programming Errors:**

Think about common mistakes developers make with these kinds of operations:

* **Type mismatches:** Trying to add a float and an integer without proper conversion.
* **Overflow/underflow:**  Exceeding the limits of integer or floating-point types.
* **Precision issues:**  The inherent imprecision of floating-point numbers.
* **Incorrect assumptions about truncation:**  Not understanding how floating-point numbers are converted to integers.

**7. Code Logic and Assumptions (where applicable):**

For tests with more complex logic (like the `Phi` nodes and control flow), consider:

* **Input assumptions:** What types and ranges of inputs are being used?
* **Expected output:**  Trace the logic to determine the expected result for given inputs. The `Phi` node is a key concept in compiler intermediate representations, representing the merging of values from different control flow paths.

**8. Address Specific Prompt Points:**

Go back to the original prompt and ensure all points are addressed:

* **Functionality:** Describe what the code does at a high level.
* **Torque:** Check if the filename ends in `.tq`. In this case, it doesn't.
* **JavaScript Relation:** Provide examples of how the tested operations relate to JavaScript.
* **Code Logic/Reasoning:** Explain the logic of more complex tests, including input/output examples.
* **Common Programming Errors:** Give concrete examples of errors related to the tested operations.
* **Part of a Series:** Acknowledge that this is part of a larger set of tests and infer the overall purpose.

**9. Structure the Response:**

Organize the information logically:

* Start with a high-level summary of the file's purpose.
* Discuss the testing methodology.
* Explain the relationship to JavaScript.
* Provide examples of code logic and potential errors.
* Summarize the overall function based on this specific part.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This just tests basic arithmetic."  **Correction:** While arithmetic is a significant part, it also tests type conversions, bitwise operations (later in the snippet), and control flow constructs like `Phi`.
* **Focusing too much on individual tests:** **Correction:**  Step back and synthesize the common thread across all the tests – validating the correctness of machine-level operations.
* **Not explicitly linking to JavaScript:** **Correction:** Make the JavaScript connections more explicit with code examples.

By following these steps, you can systematically analyze the C++ code snippet and generate a comprehensive and informative response that addresses all aspects of the prompt.
```cpp
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
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint
Prompt: 
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能

"""
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
  double d
"""


```