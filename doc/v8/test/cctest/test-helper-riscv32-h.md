Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Purpose:** The filename `test-helper-riscv32.h` immediately suggests this is a utility file specifically for testing RISC-V 32-bit architecture within the V8 JavaScript engine. The `test-helper` part indicates it provides helper functions to simplify test creation.

2. **Examine Includes:**  The included headers give clues about the file's functionality:
    * `"src/codegen/assembler-inl.h"` and `"src/codegen/macro-assembler.h"`:  Strong indicators that the file deals with generating machine code.
    * `"src/diagnostics/disassembler.h"`: Suggests the ability to inspect generated code.
    * `"src/execution/simulator.h"`:  Implies the ability to run generated code within a simulated environment (important for cross-architecture testing).
    * `"src/heap/factory.h"`:  Points to interaction with V8's memory management.
    * `"src/init/v8.h"`: Basic V8 initialization.
    * `"src/utils/utils.h"`: General utility functions.
    * `"test/cctest/cctest.h"`:  The core testing framework within V8.

3. **Analyze the Macros:** The `PRINT_RES` macro is a simple debugging aid for printing results of tests. It shows the actual result and the expected result, optionally in hexadecimal format.

4. **Focus on Key Functions (Templates are Crucial):** The core of the file lies in the template functions `GenAndRunTest`. The template parameters `<typename OUTPUT_T, typename INPUT_T>` suggest these functions are designed to run generated code snippets with different input and output types.

5. **Decipher `GenAndRunTest` Logic:**
    * **Common Structure:**  All `GenAndRunTest` overloads follow a similar pattern:
        * Get an `Isolate` (V8's isolated execution environment).
        * Create a `MacroAssembler` to generate RISC-V assembly code.
        * **Handle Floating-Point:**  The code explicitly checks for `float` and `double` types. The `assm.fmv_w_x` and `assm.fmv_x_w` instructions are RISC-V instructions for moving data between floating-point and general-purpose registers. This highlights a key aspect of the helper: dealing with the calling convention differences for floating-point numbers in varargs scenarios.
        * **Call the `test_generator`:** This `Func` (a `std::function`) is where the actual test logic is injected. The helper provides the scaffolding.
        * **More Floating-Point Handling:** Again, handling the return value.
        * **Generate and Run Code:**  The code is assembled into a `Code` object, and then executed using `GeneratedCode`. The `base::bit_cast` is used to reinterpret the raw integer representation of floating-point numbers.

6. **Specialized `GenAndRunTest` Variants:**
    * `GenAndRunTestForLoadStore`: Specifically designed for testing load and store instructions. It sets up a memory location and a value to be stored/loaded.
    * `GenAndRunTestForLRSC`:  Focuses on testing Load-Reserved and Store-Conditional instructions (atomic operations). It initializes a value, runs the test, and checks if the store-conditional was successful (returns 0 on success).
    * `GenAndRunTestForAMO`:  Tests Atomic Memory Operations. It sets up a value in memory and another value to be used in the atomic operation.

7. **`AssembleCodeImpl` and `AssembleCode`:** These functions provide a way to generate and obtain executable code directly from an assembly generation function, without the input/output parameter handling of `GenAndRunTest`.

8. **`UseCanonicalNan`:** A small utility function to normalize NaN (Not-a-Number) values, ensuring consistent comparisons in tests.

9. **Relate to JavaScript (If Applicable):**  Since this is a *test helper* for the RISC-V architecture within V8, it indirectly relates to JavaScript. When V8 needs to execute JavaScript code on a RISC-V processor, it will generate machine code similar to what these test helpers are generating. The helper allows developers to test the correctness of that code generation.

10. **Identify Potential Programming Errors:** The handling of floating-point numbers as integers via `base::bit_cast` is a prime example of a place where developers might make mistakes if they aren't careful about data types and representations. Also, the usage of raw pointers and memory manipulation in the load/store and atomic operation tests could lead to errors like segmentation faults if not handled correctly.

11. **Structure the Explanation:** Organize the findings into clear categories: purpose, key functionalities, relationship to JavaScript, code logic examples, and common errors. Use clear and concise language.

12. **Self-Correction/Refinement:**  Initially, I might have focused too heavily on the individual RISC-V instructions. However, realizing the *helper* nature of the file, the focus should shift to the overall testing framework and the abstractions it provides. The handling of floating-point numbers as integers in the context of varargs is a crucial detail to highlight. Also, emphasizing that this code *tests the code generator* is important for understanding its place in the V8 ecosystem.
This header file, `v8/test/cctest/test-helper-riscv32.h`, is a **test utility file** specifically designed for writing C++ tests for the **RISC-V 32-bit architecture** within the V8 JavaScript engine. It provides a set of helper functions to simplify the process of generating and executing small snippets of RISC-V assembly code within the testing environment.

Here's a breakdown of its key functionalities:

**1. Simplifying RISC-V Assembly Code Generation and Execution for Tests:**

* **`GenAndRunTest` family of functions:** These are the core functions. They take a `Func` (a `std::function` that accepts a `MacroAssembler&`) as an argument. This `Func` is responsible for generating the specific RISC-V assembly instructions to be tested using the provided `MacroAssembler`.
* **Automatic Setup and Teardown:** `GenAndRunTest` handles the boilerplate code needed to set up an isolated V8 environment (`Isolate`), create a `MacroAssembler`, finalize the generated code, and execute it.
* **Handling Function Calls:**  The template overloads of `GenAndRunTest` are designed to handle functions with 0, 1, 2, or 3 input arguments. They take input values and pass them to the generated assembly code.
* **Retrieving Results:** They also handle retrieving the result of the executed assembly code and returning it to the C++ test.

**2. Handling Floating-Point Values in Tests:**

* **Specialized Handling for `float` and `double`:**  The `GenAndRunTest` functions have specific logic to handle floating-point input and output values. This is because in V8's internal calling conventions (especially with varargs), floating-point numbers might be passed and returned in general-purpose registers (GPRs) as their integer representations, requiring explicit conversion.
* **`fmv_w_x` and `fmv_x_w` instructions:** These RISC-V instructions are used to move data between floating-point registers (like `fa0`) and general-purpose registers (like `a0`). This is crucial for correctly passing floating-point arguments to and from the generated assembly code.
* **`UNIMPLEMENTED()` for `double`:**  Interestingly, the code shows `UNIMPLEMENTED()` for `double` in some places. This might indicate that the initial focus was on testing with single-precision floats, or that double-precision support in these helper functions was pending at the time of writing.

**3. Specific Test Scenarios:**

* **`GenAndRunTestForLoadStore`:** This function is specialized for testing load and store instructions. It sets up a memory location and a value, generates assembly to perform the load or store, and then verifies the result.
* **`GenAndRunTestForLRSC`:** This function is designed for testing Load-Reserved (LR) and Store-Conditional (SC) instructions, which are used for atomic operations.
* **`GenAndRunTestForAMO`:** This function is for testing Atomic Memory Operations (AMOs).

**4. Direct Assembly Code Generation:**

* **`AssembleCodeImpl` and `AssembleCode`:** These functions allow for more direct assembly code generation without the input/output parameter handling of `GenAndRunTest`. This is useful for tests that don't require passing specific input values.

**5. Utility Function:**

* **`UseCanonicalNan`:** This function helps in comparing floating-point NaN (Not-a-Number) values. Different NaN representations can exist, and this function canonicalizes them for consistent comparisons in tests.

**Is `v8/test/cctest/test-helper-riscv32.h` a Torque Source?**

No, the file extension is `.h`, which indicates a C++ header file. Torque source files in V8 typically have a `.tq` extension.

**Relationship to JavaScript:**

This file is not directly involved in executing JavaScript code. Instead, it's a **tool for testing the *code generation* process** of the V8 engine for the RISC-V 32-bit architecture. When V8 compiles JavaScript code for RISC-V, it generates assembly instructions. These helper functions allow developers to write targeted tests that verify the correctness of those generated instructions for specific operations.

**Example using JavaScript (Conceptual):**

While this header is C++, let's illustrate the *kind* of JavaScript functionality it helps test with a conceptual example. Imagine the V8 code generator needs to translate the following JavaScript addition for RISC-V:

```javascript
function add(a, b) {
  return a + b;
}
```

The `test-helper-riscv32.h` would be used to write a C++ test that generates RISC-V assembly for a similar addition operation and verifies if the generated instructions are correct. The test might look something like this (simplified):

```c++
TEST(RISCV32Add) {
  int32_t input1 = 5;
  int32_t input2 = 10;
  int32_t expected_output = 15;

  auto test_generator = [&](MacroAssembler& assm) {
    // Simulate the addition operation in RISC-V assembly
    assm.mv(a0, input1); // Move input1 to register a0
    assm.mv(a1, input2); // Move input2 to register a1
    assm.addw(a0, a0, a1); // Add a1 to a0, store result in a0
    assm.mv(ra, a0);      // Move result to return register (ra is a convention here)
  };

  int32_t actual_output = GenAndRunTest<int32_t, int32_t>(input1, input2, test_generator);
  ASSERT_EQ(actual_output, expected_output);
}
```

In this simplified example, the `test_generator` function defines the RISC-V assembly instructions to perform the addition. `GenAndRunTest` then executes this code and compares the result.

**Code Logic Reasoning with Assumptions:**

Let's take the `GenAndRunTest` function that handles one input:

**Assumptions:**

* `INPUT_T` is `int32_t` and `OUTPUT_T` is `int32_t`.
* `test_generator` contains RISC-V assembly that takes an integer in register `a0` and leaves the result in `a0`.

**Input:** `input0 = 10`

**Execution Flow:**

1. `GenAndRunTest` creates a `MacroAssembler`.
2. The `test_generator` is called with the `MacroAssembler`. Let's assume it generates the following assembly:
   ```assembly
   addi a0, a0, 5  // Add 5 to the value in a0
   ```
3. `assm.jr(ra)` is added to return from the generated code.
4. The assembly is compiled into executable code.
5. A function pointer `f` is created to this code, expecting an `int32_t` input and returning an `int32_t`.
6. `f.Call(10)` is executed.
7. The generated assembly runs:
   * `a0` is initialized to `10` (because `input0` was `10`).
   * `addi a0, a0, 5` executes, setting `a0` to `15`.
   * The code returns.
8. `res` in `GenAndRunTest` becomes `15`.
9. `GenAndRunTest` returns `15`.

**Output:** `15`

**Common Programming Errors (Illustrative):**

1. **Incorrect Register Usage:** If the `test_generator` incorrectly assumed the input was in `a1` instead of `a0`, the generated code would operate on an uninitialized value, leading to unexpected results.

   ```c++
   auto test_generator_error = [&](MacroAssembler& assm) {
     assm.addi(a0, a1, 5); // Oops, using a1 instead of a0
   };
   ```

2. **Forgetting to Return:** If the `test_generator` didn't include a return instruction (`assm.jr(ra)`), the execution would likely crash or continue into memory it shouldn't.

3. **Type Mismatches (Less likely with the template safety):** While the templates provide some type safety, if the `OUTPUT_T` in `GenAndRunTest` didn't match the actual type of the result left in the registers by the assembly, the `base::bit_cast` could lead to incorrect interpretation of the result. For example, if the assembly calculated a float but `OUTPUT_T` was `int32_t`.

4. **Incorrect Floating-Point Register Handling:** If the assembly code for floating-point operations didn't correctly use the `f` registers (e.g., used `a0` instead of `fa0`), the results would be wrong.

   ```c++
   auto float_test_generator_error = [&](MacroAssembler& assm) {
     assm.li(a0, 1.0f); // Incorrectly trying to load a float into an integer register
   };
   ```

In summary, `v8/test/cctest/test-helper-riscv32.h` is a crucial component of V8's testing infrastructure for the RISC-V architecture. It significantly simplifies the process of writing focused tests that validate the correctness of the generated machine code.

Prompt: 
```
这是目录为v8/test/cctest/test-helper-riscv32.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-helper-riscv32.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CCTEST_TEST_HELPER_RISCV_H_
#define V8_CCTEST_TEST_HELPER_RISCV_H_

#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "src/utils/utils.h"
#include "test/cctest/cctest.h"

#define PRINT_RES(res, expected_res, in_hex)                         \
  if (in_hex) std::cout << "[hex-form]" << std::hex;                 \
  std::cout << "res = " << (res) << " expected = " << (expected_res) \
            << std::endl;

namespace v8 {
namespace internal {

using Func = std::function<void(MacroAssembler&)>;

int32_t GenAndRunTest(Func test_generator);

// f.Call(...) interface is implemented as varargs in V8. For varargs,
// floating-point arguments and return values are passed in GPRs, therefore
// the special handling to reinterpret floating-point as integer values when
// passed in and out of f.Call()
template <typename OUTPUT_T, typename INPUT_T>
OUTPUT_T GenAndRunTest(INPUT_T input0, Func test_generator) {
  DCHECK((sizeof(INPUT_T) == 4 || sizeof(INPUT_T) == 8));

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // handle floating-point parameters
  if (std::is_same<float, INPUT_T>::value) {
    assm.fmv_w_x(fa0, a0);
  } else if (std::is_same<double, INPUT_T>::value) {
    UNIMPLEMENTED();
  }

  test_generator(assm);

  // handle floating-point result
  if (std::is_same<float, OUTPUT_T>::value) {
    assm.fmv_x_w(a0, fa0);
  } else if (std::is_same<double, OUTPUT_T>::value) {
    UNIMPLEMENTED();
  }
  assm.jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  using OINT_T = typename std::conditional<
      std::is_integral<OUTPUT_T>::value, OUTPUT_T,
      typename std::conditional<sizeof(OUTPUT_T) == 4, int32_t,
                                int64_t>::type>::type;
  using IINT_T = typename std::conditional<
      std::is_integral<INPUT_T>::value, INPUT_T,
      typename std::conditional<sizeof(INPUT_T) == 4, int32_t,
                                int64_t>::type>::type;

  auto f = GeneratedCode<OINT_T(IINT_T)>::FromCode(isolate, *code);

  auto res = f.Call(base::bit_cast<IINT_T>(input0));
  return base::bit_cast<OUTPUT_T>(res);
}

template <typename OUTPUT_T, typename INPUT_T>
OUTPUT_T GenAndRunTest(INPUT_T input0, INPUT_T input1, Func test_generator) {
  DCHECK((sizeof(INPUT_T) == 4 || sizeof(INPUT_T) == 8));

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // handle floating-point parameters
  if (std::is_same<float, INPUT_T>::value) {
    assm.fmv_w_x(fa0, a0);
    assm.fmv_w_x(fa1, a1);
  } else if (std::is_same<double, INPUT_T>::value) {
    UNIMPLEMENTED();
  }

  test_generator(assm);

  // handle floating-point result
  if (std::is_same<float, OUTPUT_T>::value) {
    assm.fmv_x_w(a0, fa0);
  } else if (std::is_same<double, OUTPUT_T>::value) {
    UNIMPLEMENTED();
  }
  assm.jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  using OINT_T = typename std::conditional<
      std::is_integral<OUTPUT_T>::value, OUTPUT_T,
      typename std::conditional<sizeof(OUTPUT_T) == 4, int32_t,
                                int64_t>::type>::type;
  using IINT_T = typename std::conditional<
      std::is_integral<INPUT_T>::value, INPUT_T,
      typename std::conditional<sizeof(INPUT_T) == 4, int32_t,
                                int64_t>::type>::type;
  auto f = GeneratedCode<OINT_T(IINT_T, IINT_T)>::FromCode(isolate, *code);

  auto res =
      f.Call(base::bit_cast<IINT_T>(input0), base::bit_cast<IINT_T>(input1));
  return base::bit_cast<OUTPUT_T>(res);
}

template <typename OUTPUT_T, typename INPUT_T>
OUTPUT_T GenAndRunTest(INPUT_T input0, INPUT_T input1, INPUT_T input2,
                       Func test_generator) {
  DCHECK((sizeof(INPUT_T) == 4 || sizeof(INPUT_T) == 8));

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // handle floating-point parameters
  if (std::is_same<float, INPUT_T>::value) {
    assm.fmv_w_x(fa0, a0);
    assm.fmv_w_x(fa1, a1);
    assm.fmv_w_x(fa2, a2);
  } else if (std::is_same<double, INPUT_T>::value) {
    UNIMPLEMENTED();
  }

  test_generator(assm);

  // handle floating-point result
  if (std::is_same<float, OUTPUT_T>::value) {
    assm.fmv_x_w(a0, fa0);
  } else if (std::is_same<double, OUTPUT_T>::value) {
    UNIMPLEMENTED();
  }
  assm.jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  using OINT_T = typename std::conditional<
      std::is_integral<OUTPUT_T>::value, OUTPUT_T,
      typename std::conditional<sizeof(OUTPUT_T) == 4, int32_t,
                                int64_t>::type>::type;
  using IINT_T = typename std::conditional<
      std::is_integral<INPUT_T>::value, INPUT_T,
      typename std::conditional<sizeof(INPUT_T) == 4, int32_t,
                                int64_t>::type>::type;
  auto f =
      GeneratedCode<OINT_T(IINT_T, IINT_T, IINT_T)>::FromCode(isolate, *code);

  auto res =
      f.Call(base::bit_cast<IINT_T>(input0), base::bit_cast<IINT_T>(input1),
             base::bit_cast<IINT_T>(input2));
  return base::bit_cast<OUTPUT_T>(res);
}

template <typename T>
void GenAndRunTestForLoadStore(T value, Func test_generator) {
  DCHECK(sizeof(T) == 4 || sizeof(T) == 8);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  if (std::is_same<float, T>::value) {
    assm.fmv_w_x(fa0, a1);
  } else if (std::is_same<double, T>::value) {
    UNIMPLEMENTED();
  }

  test_generator(assm);

  if (std::is_same<float, T>::value) {
    assm.fmv_x_w(a0, fa0);
  } else if (std::is_same<double, T>::value) {
    UNIMPLEMENTED();
  }
  assm.jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  using INT_T = typename std::conditional<
      std::is_integral<T>::value, T,
      typename std::conditional<sizeof(T) == 4, int32_t, int64_t>::type>::type;

  auto f =
      GeneratedCode<INT_T(void* base, INT_T val)>::FromCode(isolate, *code);

  int64_t tmp = 0;
  auto res = f.Call(&tmp, base::bit_cast<INT_T>(value));
  CHECK_EQ(base::bit_cast<T>(res), value);
}

template <typename T, typename Func>
void GenAndRunTestForLRSC(T value, Func test_generator) {
  DCHECK(sizeof(T) == 4 || sizeof(T) == 8);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  if (std::is_same<float, T>::value) {
    assm.fmv_w_x(fa0, a1);
  } else if (std::is_same<double, T>::value) {
    UNIMPLEMENTED();
  }

  if (std::is_same<int32_t, T>::value) {
    assm.sw(a1, a0, 0);
  } else if (std::is_same<int64_t, T>::value) {
    UNREACHABLE();
  }
  test_generator(assm);

  if (std::is_same<float, T>::value) {
    assm.fmv_x_w(a0, fa0);
  } else if (std::is_same<double, T>::value) {
    UNIMPLEMENTED();
  }
  assm.jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#if defined(DEBUG)
  Print(*code);
#endif
  using INT_T =
      typename std::conditional<sizeof(T) == 4, int32_t, int64_t>::type;

  T tmp = 0;
  auto f =
      GeneratedCode<INT_T(void* base, INT_T val)>::FromCode(isolate, *code);
  auto res = f.Call(&tmp, base::bit_cast<T>(value));
  CHECK_EQ(base::bit_cast<T>(res), static_cast<T>(0));
}

template <typename INPUT_T, typename OUTPUT_T, typename Func>
OUTPUT_T GenAndRunTestForAMO(INPUT_T input0, INPUT_T input1,
                             Func test_generator) {
  DCHECK(sizeof(INPUT_T) == 4 || sizeof(INPUT_T) == 8);
  DCHECK(sizeof(OUTPUT_T) == 4 || sizeof(OUTPUT_T) == 8);
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // handle floating-point parameters
  if (std::is_same<float, INPUT_T>::value) {
    assm.fmv_w_x(fa0, a1);
    assm.fmv_w_x(fa1, a2);
  } else if (std::is_same<double, INPUT_T>::value) {
    UNIMPLEMENTED();
  }

  // store base integer
  if (std::is_same<int32_t, INPUT_T>::value ||
      std::is_same<uint32_t, INPUT_T>::value) {
    assm.sw(a1, a0, 0);
  } else if (std::is_same<int64_t, INPUT_T>::value ||
             std::is_same<uint64_t, INPUT_T>::value) {
    UNREACHABLE();
  }
  test_generator(assm);

  // handle floating-point result
  if (std::is_same<float, OUTPUT_T>::value) {
    assm.fmv_x_w(a0, fa0);
  } else if (std::is_same<double, OUTPUT_T>::value) {
    UNIMPLEMENTED();
  }

  // load written integer
  if (std::is_same<int32_t, INPUT_T>::value ||
      std::is_same<uint32_t, INPUT_T>::value) {
    assm.lw(a0, a0, 0);
  } else if (std::is_same<int64_t, INPUT_T>::value ||
             std::is_same<uint64_t, INPUT_T>::value) {
    UNREACHABLE();
  }

  assm.jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#if defined(DEBUG)
  Print(*code);
#endif
  OUTPUT_T tmp = 0;
  auto f = GeneratedCode<OUTPUT_T(void* base, INPUT_T, INPUT_T)>::FromCode(
      isolate, *code);
  auto res = f.Call(&tmp, base::bit_cast<INPUT_T>(input0),
                    base::bit_cast<INPUT_T>(input1));
  return base::bit_cast<OUTPUT_T>(res);
}

Handle<Code> AssembleCodeImpl(Isolate* isolate, Func assemble);

template <typename Signature>
GeneratedCode<Signature> AssembleCode(Isolate* isolate, Func assemble) {
  return GeneratedCode<Signature>::FromCode(
      isolate, *AssembleCodeImpl(isolate, assemble));
}

template <typename T>
T UseCanonicalNan(T x) {
  return isnan(x) ? std::numeric_limits<T>::quiet_NaN() : x;
}

}  // namespace internal
}  // namespace v8

#endif  // V8_CCTEST_TEST_HELPER_RISCV_H_

"""

```