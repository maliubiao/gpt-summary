Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `bigint-shell.cc` file within the V8 project. It also includes conditional information about Torque files and requests for JavaScript connections, code logic, and common errors.

2. **Initial Scan and Keywords:**  I'd first scan the code for prominent keywords and structures. Things like `#include`, `namespace`, `main`, function names (`PrintHelp`, `Run`, `Test...`), enums (`Operation`, `Test`), macros (`TESTS`, `#define`), classes (`RNG`, `Runner`), and standard C++ elements like `std::cerr`, `std::cout`, `std::string`, loops (`for`), and conditional statements (`if`, `else if`). These provide a high-level overview.

3. **Identify Core Components:**
    * **`main` function:**  This is the entry point. It creates a `Runner` object, parses command-line arguments, initializes the runner, and executes the run. This immediately tells me it's an executable program.
    * **`Runner` class:** This seems to be the central orchestrator. It handles parsing arguments, running tests, and managing the random number generator and the `Processor`.
    * **`RNG` class:**  Clearly responsible for generating random numbers, essential for testing.
    * **`Processor` (and `ProcessorImpl`):**  Indicates interaction with the core BigInt implementation in V8. The presence of `Multiply...`, `Divide...`, `ToStringImpl`, and `FromString...` methods strongly suggests this.
    * **`enum Operation` and `enum Test`:** These define the possible actions (listing or running) and the specific tests available. The `TESTS` macro helps define the test names.
    * **Helper functions:**  `PrintHelp`, `FormatHex`, `AssertEquals` are for utility purposes like displaying help, formatting output, and verifying test results.

4. **Analyze Functionality based on Components:**

    * **Command-line Interface:** The `ParseOptions` function analyzes command-line arguments like `--help`, `--list`, `--random-seed`, `--runs`, and specific test names. This confirms it's a command-line tool.
    * **Test Execution:** The `Run` function decides whether to list tests or run a specific test. The `RunTest` function then executes the selected test based on the `test_` enum value.
    * **Individual Tests (`TestKaratsuba`, `TestToom`, etc.):** These functions focus on testing specific BigInt algorithms (Karatsuba, Toom-Cook, FFT, Burnikel, Barrett). They generate random BigInt inputs, call the corresponding BigInt functions through the `Processor`, and compare the results against a known correct implementation (often a simpler algorithm like schoolbook multiplication or Karatsuba as a baseline for Toom-Cook).
    * **String Conversion Tests (`TestToString`, `TestFromString`, `TestFromStringBaseTwo`):** These verify the conversion between BigInts and their string representations in different bases.
    * **Random Number Generation:** The `RNG` class uses Xorshift128 and MurmurHash3 for generating pseudo-random numbers, ensuring test repeatability when a specific seed is provided.
    * **Assertions:** The `AssertEquals` functions are crucial for verifying the correctness of the BigInt operations. They compare expected and actual results and print error messages if they don't match.

5. **Address Specific Questions:**

    * **Torque:** The request specifically asks about `.tq` files. I see the `.cc` extension, so I can confidently state it's *not* a Torque file.
    * **JavaScript Relationship:** The file tests the *implementation* of BigInts in V8. JavaScript's `BigInt` type relies on this underlying C++ implementation. I can provide a simple JavaScript example demonstrating the use of `BigInt` operators.
    * **Code Logic and Input/Output:** For a test function like `TestKaratsuba`, I can infer that the input is two `Digits` objects (representing BigInts) and the output is another `Digits` object representing their product. I can create hypothetical (though potentially simplified) input and output examples based on the test logic.
    * **Common Programming Errors:** Based on the tests (especially string conversion), I can infer common errors like incorrect radix handling, off-by-one errors in string length calculations, and potential issues with leading zeros or signs (though the provided code doesn't explicitly handle signs in the string conversion tests).

6. **Structure the Answer:**  Organize the findings logically, starting with the overall functionality, then addressing the specific questions in order. Use clear headings and bullet points for readability. Provide code examples where requested.

7. **Review and Refine:** Before submitting, reread the answer to ensure accuracy, clarity, and completeness. Double-check that all aspects of the request have been addressed. For instance, I initially focused on the algorithmic tests, but needed to ensure the string conversion aspects were also well-explained.

This systematic approach of scanning, identifying components, analyzing functionality, and addressing specific points helps to create a comprehensive and accurate explanation of the code.
好的，让我们来分析一下 `v8/test/bigint/bigint-shell.cc` 这个 V8 源代码文件的功能。

**核心功能总结:**

`v8/test/bigint/bigint-shell.cc` 是一个用于测试 V8 中 BigInt 相关的 C++ 代码的命令行工具。 它允许开发者运行针对 BigInt 运算的特定测试，并可以指定运行次数和随机种子以进行更全面的测试。

**功能分解:**

1. **命令行接口:**  该文件定义了一个命令行工具，可以接受以下参数：
   - `--help`: 打印帮助信息并退出。
   - `--list`: 列出所有支持的测试名称。
   - `<testname>`: 运行指定的测试 (例如 `barrett`, `karatsuba`)。
   - `--random-seed R`: 使用指定的种子 `R` 初始化随机数生成器，以实现可重复的测试。
   - `--runs N`: 将每个测试重复运行 `N` 次。

2. **测试框架:** 它建立了一个简单的测试框架，允许注册和执行不同的 BigInt 相关的测试。
   - 使用宏 `TESTS(V)` 来定义一组测试，每个测试都有一个枚举值和一个字符串名称。
   - `enum Test` 定义了所有可能的测试名称。
   - `Runner` 类负责解析命令行参数，初始化测试环境，并运行指定的测试。

3. **随机数生成:** `RNG` 类提供了一个用于生成 64 位随机数的机制。这对于生成各种 BigInt 输入以进行测试至关重要。  它使用 Xorshift128 算法作为其核心。

4. **BigInt 操作测试:**  文件中定义了多个以 `Test` 开头的函数，每个函数负责测试 BigInt 的特定操作或算法，例如：
   - `TestBarrett`: 测试 Barrett 约减算法。
   - `TestBurnikel`: 测试 Burnikel-Ziegler 除法算法。
   - `TestFFT`: 测试基于快速傅里叶变换 (FFT) 的乘法算法。
   - `TestFromString`: 测试从字符串解析 BigInt 的功能。
   - `TestFromStringBase2`: 测试从二进制字符串解析 BigInt 的功能。
   - `TestKaratsuba`: 测试 Karatsuba 乘法算法。
   - `TestToom`: 测试 Toom-Cook 乘法算法。
   - `TestToString`: 测试将 BigInt 转换为字符串的功能。

5. **断言机制:** `AssertEquals` 函数用于比较预期结果和实际结果。如果结果不匹配，它会打印错误信息，包括输入和期望/实际输出的十六进制表示。

6. **BigInt 的格式化输出:** `FormatHex` 函数用于将 BigInt (以 `Digits` 结构表示) 格式化为十六进制字符串，方便调试和错误报告。

7. **与 V8 BigInt 实现的交互:**  `Runner` 类持有一个 `Processor` 对象的智能指针，`Processor` 可能是对 V8 核心 BigInt 实现的抽象接口。测试通过 `Processor` 对象调用底层的 BigInt 运算函数。

**关于文件类型和 JavaScript 关系:**

* **文件类型:** `v8/test/bigint/bigint-shell.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。  因此，你提供的关于 `.tq` 后缀的推断是不正确的。`.tq` 后缀通常用于 **Torque** 源代码文件，Torque 是 V8 用来生成高效 JavaScript 内置函数的领域特定语言。

* **JavaScript 功能关系:**  `v8/test/bigint/bigint-shell.cc` 测试的是 V8 引擎中 **BigInt 的 C++ 实现**。JavaScript 中的 `BigInt` 类型正是基于这底层的 C++ 实现。  当你在 JavaScript 中使用 `BigInt` 进行运算时，V8 引擎会调用这些底层的 C++ 代码来完成实际的计算。

**JavaScript 举例说明:**

```javascript
// JavaScript 中使用 BigInt
const a = 9007199254740991n; // 超出 Number 安全范围的整数
const b = BigInt(9007199254740991);
const c = a + b; // BigInt 的加法运算
console.log(c); // 输出一个更大的 BigInt

// JavaScript 中的字符串到 BigInt 的转换
const str = "123456789012345678901234567890";
const bigIntFromString = BigInt(str);
console.log(bigIntFromString);

// JavaScript 中的 BigInt 到字符串的转换
const bigIntValue = 98765432109876543210n;
const stringFromBigInt = bigIntValue.toString(16); // 转换为十六进制字符串
console.log(stringFromBigInt);
```

`v8/test/bigint/bigint-shell.cc` 中的 `TestFromString` 和 `TestToString` 等测试正是用来验证 V8 的 C++ BigInt 实现是否正确地处理了 JavaScript 中 `BigInt()` 构造函数和 `toString()` 方法的功能。

**代码逻辑推理和假设输入/输出:**

以 `TestKaratsuba` 函数为例：

**假设输入:**

* 两个随机生成的 `Digits` 对象 `A` 和 `B`，分别代表两个 BigInt。
* 假设 `A` 代表十六进制数 `0x1234567890abcdef`
* 假设 `B` 代表十六进制数 `0xfedcba0987654321`

**代码逻辑:**

1. 使用 `GenerateRandom(A)` 和 `GenerateRandom(B)` 生成两个随机的 BigInt。
2. 使用两种不同的乘法算法计算 `A` 和 `B` 的乘积：
   - `processor()->MultiplyKaratsuba(result, A, B)`: 使用 Karatsuba 算法。
   - `processor()->MultiplySchoolbook(result_schoolbook, A, B)`: 使用学校算法（一种更基础的乘法算法，作为验证 Karatsuba 结果的基准）。
3. 使用 `AssertEquals(A, B, result_schoolbook, result)` 比较两种算法的结果。如果结果不一致，则断言失败并报告错误。

**假设输出 (如果测试通过):**

测试通过时，不会有直接的输出到终端，但内部的断言会确保 `result` (Karatsuba 算法的输出) 与 `result_schoolbook` (学校算法的输出) 在数值上是相等的。

**如果测试失败:**

如果两种算法的计算结果不一致，`AssertEquals` 函数会打印类似以下的错误信息：

```
Input 1:  1234567890abcdef
Input 2:  fedcba0987654321
Expected: <学校算法计算的十六进制结果>
Actual:   <Karatsuba 算法计算的十六进制结果>
```

**涉及用户常见的编程错误 (与 BigInt 相关):**

虽然这个 C++ 文件本身是测试代码，但它测试的功能与用户在使用 JavaScript `BigInt` 时可能遇到的错误相关：

1. **精度丢失:** 在 JavaScript 中，如果直接使用普通的 `Number` 类型进行超出其安全范围的整数运算，会导致精度丢失。`BigInt` 的引入正是为了解决这个问题。`bigint-shell.cc` 通过各种算法测试确保 BigInt 运算的精度。

   ```javascript
   // 错误的例子 (使用 Number)
   let num1 = 9007199254740991;
   let num2 = num1 + 1;
   console.log(num1 === num2); // 输出 true，精度丢失

   // 正确的例子 (使用 BigInt)
   let bigNum1 = 9007199254740991n;
   let bigNum2 = bigNum1 + 1n;
   console.log(bigNum1 === bigNum2); // 输出 false
   ```

2. **类型错误:**  `BigInt` 不能与 `Number` 类型直接进行混合运算。必须显式地将 `Number` 转换为 `BigInt`，或者只进行 `BigInt` 之间的运算。

   ```javascript
   let bigInt = 10n;
   let number = 5;
   // let result = bigInt + number; // 错误：TypeError

   let result = bigInt + BigInt(number); // 正确
   console.log(result);
   ```

3. **字符串转换错误:**  在使用 `BigInt()` 构造函数将字符串转换为 `BigInt` 时，如果字符串包含无效字符，会导致错误。

   ```javascript
   // 错误的例子
   // const invalidBigInt = BigInt("123abc456"); // 错误：SyntaxError

   // 正确的例子
   const validBigInt = BigInt("1234567890");
   console.log(validBigInt);
   ```

4. **除法取整行为:**  `BigInt` 的除法运算会向下取整，这可能与 `Number` 的除法行为不同。

   ```javascript
   console.log(10 / 3);      // 输出 3.333...
   console.log(10n / 3n);    // 输出 3n
   ```

`v8/test/bigint/bigint-shell.cc` 中的测试（例如 `TestFromString`）帮助确保 V8 引擎能够正确处理这些字符串转换，避免用户在使用 JavaScript `BigInt` 时遇到解析错误。

总而言之，`v8/test/bigint/bigint-shell.cc` 是 V8 引擎中 BigInt 功能的基石测试工具，它通过各种算法和场景的测试，保证了 JavaScript `BigInt` 类型的正确性和可靠性。

### 提示词
```
这是目录为v8/test/bigint/bigint-shell.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/bigint/bigint-shell.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>
#include <memory>
#include <string>

#include "src/bigint/bigint-internal.h"
#include "src/bigint/util.h"

namespace v8 {
namespace bigint {
namespace test {

int PrintHelp(char** argv) {
  std::cerr << "Usage:\n"
            << argv[0] << " --help\n"
            << "    Print this help and exit.\n"
            << argv[0] << " --list\n"
            << "    List supported tests.\n"
            << argv[0] << " <testname>\n"
            << "    Run the specified test (see --list for a list).\n"
            << "\nOptions when running tests:\n"
            << "--random-seed R\n"
            << "    Initialize the random number generator with this seed.\n"
            << "--runs N\n"
            << "    Repeat the test N times.\n";
  return 1;
}

#define TESTS(V)                     \
  V(kBarrett, "barrett")             \
  V(kBurnikel, "burnikel")           \
  V(kFFT, "fft")                     \
  V(kFromString, "fromstring")       \
  V(kFromStringBase2, "fromstring2") \
  V(kKaratsuba, "karatsuba")         \
  V(kToom, "toom")                   \
  V(kToString, "tostring")

enum Operation { kNoOp, kList, kTest };

enum Test {
#define TEST(kName, name) kName,
  TESTS(TEST)
#undef TEST
};

class RNG {
 public:
  RNG() = default;

  void Initialize(int64_t seed) {
    state0_ = MurmurHash3(static_cast<uint64_t>(seed));
    state1_ = MurmurHash3(~state0_);
    CHECK(state0_ != 0 || state1_ != 0);
  }

  uint64_t NextUint64() {
    XorShift128(&state0_, &state1_);
    return static_cast<uint64_t>(state0_ + state1_);
  }

  static inline void XorShift128(uint64_t* state0, uint64_t* state1) {
    uint64_t s1 = *state0;
    uint64_t s0 = *state1;
    *state0 = s0;
    s1 ^= s1 << 23;
    s1 ^= s1 >> 17;
    s1 ^= s0;
    s1 ^= s0 >> 26;
    *state1 = s1;
  }

  static uint64_t MurmurHash3(uint64_t h) {
    h ^= h >> 33;
    h *= uint64_t{0xFF51AFD7ED558CCD};
    h ^= h >> 33;
    h *= uint64_t{0xC4CEB9FE1A85EC53};
    h ^= h >> 33;
    return h;
  }

 private:
  uint64_t state0_;
  uint64_t state1_;
};

static constexpr int kCharsPerDigit = kDigitBits / 4;

static const char kConversionChars[] = "0123456789abcdefghijklmnopqrstuvwxyz";

std::string FormatHex(Digits X) {
  X.Normalize();
  if (X.len() == 0) return "0";
  digit_t msd = X.msd();
  const int msd_leading_zeros = CountLeadingZeros(msd);
  const size_t bit_length = X.len() * kDigitBits - msd_leading_zeros;
  const size_t chars = DIV_CEIL(bit_length, 4);

  if (chars > 100000) {
    return std::string("<BigInt with ") + std::to_string(bit_length) +
           std::string(" bits>");
  }

  std::unique_ptr<char[]> result(new char[chars]);
  for (size_t i = 0; i < chars; i++) result[i] = '?';
  // Print the number into the string, starting from the last position.
  int pos = static_cast<int>(chars - 1);
  for (int i = 0; i < X.len() - 1; i++) {
    digit_t d = X[i];
    for (int j = 0; j < kCharsPerDigit; j++) {
      result[pos--] = kConversionChars[d & 15];
      d = static_cast<digit_t>(d >> 4u);
    }
  }
  while (msd != 0) {
    result[pos--] = kConversionChars[msd & 15];
    msd = static_cast<digit_t>(msd >> 4u);
  }
  CHECK(pos == -1);
  return std::string(result.get(), chars);
}

class Runner {
 public:
  Runner() = default;

  void Initialize() {
    rng_.Initialize(random_seed_);
    processor_.reset(Processor::New(new Platform()));
  }

  ProcessorImpl* processor() {
    return static_cast<ProcessorImpl*>(processor_.get());
  }

  int Run() {
    if (op_ == kList) {
      ListTests();
    } else if (op_ == kTest) {
      RunTest();
    } else {
      DCHECK(false);  // Unreachable.
    }
    return 0;
  }

  void ListTests() {
#define PRINT(kName, name) std::cout << name << "\n";
    TESTS(PRINT)
#undef PRINT
  }

  void AssertEquals(Digits input1, Digits input2, Digits expected,
                    Digits actual) {
    if (Compare(expected, actual) == 0) return;
    std::cerr << "Input 1:  " << FormatHex(input1) << "\n";
    std::cerr << "Input 2:  " << FormatHex(input2) << "\n";
    std::cerr << "Expected: " << FormatHex(expected) << "\n";
    std::cerr << "Actual:   " << FormatHex(actual) << "\n";
    error_ = true;
  }

  void AssertEquals(Digits X, int radix, char* expected, int expected_length,
                    char* actual, int actual_length) {
    if (expected_length == actual_length &&
        std::memcmp(expected, actual, actual_length) == 0) {
      return;
    }
    std::cerr << "Input:    " << FormatHex(X) << "\n";
    std::cerr << "Radix:    " << radix << "\n";
    std::cerr << "Expected: " << std::string(expected, expected_length) << "\n";
    std::cerr << "Actual:   " << std::string(actual, actual_length) << "\n";
    error_ = true;
  }

  void AssertEquals(const char* input, int input_length, int radix,
                    Digits expected, Digits actual) {
    if (Compare(expected, actual) == 0) return;
    std::cerr << "Input:    " << std::string(input, input_length) << "\n";
    std::cerr << "Radix:    " << radix << "\n";
    std::cerr << "Expected: " << FormatHex(expected) << "\n";
    std::cerr << "Actual:   " << FormatHex(actual) << "\n";
    error_ = true;
  }

  int RunTest() {
    int count = 0;
    if (test_ == kBarrett) {
      for (int i = 0; i < runs_; i++) {
        TestBarrett(&count);
      }
    } else if (test_ == kBurnikel) {
      for (int i = 0; i < runs_; i++) {
        TestBurnikel(&count);
      }
    } else if (test_ == kFFT) {
      for (int i = 0; i < runs_; i++) {
        TestFFT(&count);
      }
    } else if (test_ == kKaratsuba) {
      for (int i = 0; i < runs_; i++) {
        TestKaratsuba(&count);
      }
    } else if (test_ == kToom) {
      for (int i = 0; i < runs_; i++) {
        TestToom(&count);
      }
    } else if (test_ == kToString) {
      for (int i = 0; i < runs_; i++) {
        TestToString(&count);
      }
    } else if (test_ == kFromString) {
      for (int i = 0; i < runs_; i++) {
        TestFromString(&count);
      }
    } else if (test_ == kFromStringBase2) {
      for (int i = 0; i < runs_; i++) {
        TestFromStringBaseTwo(&count);
      }
    } else {
      DCHECK(false);  // Unreachable.
    }
    if (error_) return 1;
    std::cout << count << " tests run, no error reported.\n";
    return 0;
  }

  void TestKaratsuba(int* count) {
    // Calling {MultiplyKaratsuba} directly is only valid if
    // left_size >= right_size and right_size >= kKaratsubaThreshold.
    constexpr int kMin = kKaratsubaThreshold;
    constexpr int kMax = 3 * kKaratsubaThreshold;
    for (int right_size = kMin; right_size <= kMax; right_size++) {
      for (int left_size = right_size; left_size <= kMax; left_size++) {
        ScratchDigits A(left_size);
        ScratchDigits B(right_size);
        int result_len = MultiplyResultLength(A, B);
        ScratchDigits result(result_len);
        ScratchDigits result_schoolbook(result_len);
        GenerateRandom(A);
        GenerateRandom(B);
        processor()->MultiplyKaratsuba(result, A, B);
        processor()->MultiplySchoolbook(result_schoolbook, A, B);
        AssertEquals(A, B, result_schoolbook, result);
        if (error_) return;
        (*count)++;
      }
    }
  }

  void TestToom(int* count) {
#if V8_ADVANCED_BIGINT_ALGORITHMS
    // {MultiplyToomCook} works fine even below the threshold, so we can
    // save some time by starting small.
    constexpr int kMin = kToomThreshold - 60;
    constexpr int kMax = kToomThreshold + 10;
    for (int right_size = kMin; right_size <= kMax; right_size++) {
      for (int left_size = right_size; left_size <= kMax; left_size++) {
        ScratchDigits A(left_size);
        ScratchDigits B(right_size);
        int result_len = MultiplyResultLength(A, B);
        ScratchDigits result(result_len);
        ScratchDigits result_karatsuba(result_len);
        GenerateRandom(A);
        GenerateRandom(B);
        processor()->MultiplyToomCook(result, A, B);
        // Using Karatsuba as reference.
        processor()->MultiplyKaratsuba(result_karatsuba, A, B);
        AssertEquals(A, B, result_karatsuba, result);
        if (error_) return;
        (*count)++;
      }
    }
#endif  // V8_ADVANCED_BIGINT_ALGORITHMS
  }

  void TestFFT(int* count) {
#if V8_ADVANCED_BIGINT_ALGORITHMS
    // Larger multiplications are slower, so to keep individual runs fast,
    // we test a few random samples. With build bots running 24/7, we'll
    // get decent coverage over time.
    uint64_t random_bits = rng_.NextUint64();
    int min = kFftThreshold - static_cast<int>(random_bits & 1023);
    random_bits >>= 10;
    int max = kFftThreshold + static_cast<int>(random_bits & 1023);
    random_bits >>= 10;
    // If delta is too small, then this run gets too slow. If it happened
    // to be zero, we'd even loop forever!
    int delta = 10 + (random_bits & 127);
    std::cout << "min " << min << " max " << max << " delta " << delta << "\n";
    for (int right_size = min; right_size <= max; right_size += delta) {
      for (int left_size = right_size; left_size <= max; left_size += delta) {
        ScratchDigits A(left_size);
        ScratchDigits B(right_size);
        int result_len = MultiplyResultLength(A, B);
        ScratchDigits result(result_len);
        ScratchDigits result_toom(result_len);
        GenerateRandom(A);
        GenerateRandom(B);
        processor()->MultiplyFFT(result, A, B);
        // Using Toom-Cook as reference.
        processor()->MultiplyToomCook(result_toom, A, B);
        AssertEquals(A, B, result_toom, result);
        if (error_) return;
        (*count)++;
      }
    }
#endif  // V8_ADVANCED_BIGINT_ALGORITHMS
  }

  void TestBurnikel(int* count) {
    // Start small to save test execution time.
    constexpr int kMin = kBurnikelThreshold / 2;
    constexpr int kMax = 2 * kBurnikelThreshold;
    for (int right_size = kMin; right_size <= kMax; right_size++) {
      for (int left_size = right_size; left_size <= kMax; left_size++) {
        ScratchDigits A(left_size);
        ScratchDigits B(right_size);
        GenerateRandom(A);
        GenerateRandom(B);
        int quotient_len = DivideResultLength(A, B);
        int remainder_len = right_size;
        ScratchDigits quotient(quotient_len);
        ScratchDigits quotient_schoolbook(quotient_len);
        ScratchDigits remainder(remainder_len);
        ScratchDigits remainder_schoolbook(remainder_len);
        processor()->DivideBurnikelZiegler(quotient, remainder, A, B);
        processor()->DivideSchoolbook(quotient_schoolbook, remainder_schoolbook,
                                      A, B);
        AssertEquals(A, B, quotient_schoolbook, quotient);
        AssertEquals(A, B, remainder_schoolbook, remainder);
        if (error_) return;
        (*count)++;
      }
    }
  }

#if V8_ADVANCED_BIGINT_ALGORITHMS
  void TestBarrett_Internal(int left_size, int right_size) {
    ScratchDigits A(left_size);
    ScratchDigits B(right_size);
    GenerateRandom(A);
    GenerateRandom(B);
    int quotient_len = DivideResultLength(A, B);
    // {DivideResultLength} doesn't expect to be called for sizes below
    // {kBarrettThreshold} (which we do here to save time), so we have to
    // manually adjust the allocated result length.
    if (B.len() < kBarrettThreshold) quotient_len++;
    int remainder_len = right_size;
    ScratchDigits quotient(quotient_len);
    ScratchDigits quotient_burnikel(quotient_len);
    ScratchDigits remainder(remainder_len);
    ScratchDigits remainder_burnikel(remainder_len);
    processor()->DivideBarrett(quotient, remainder, A, B);
    processor()->DivideBurnikelZiegler(quotient_burnikel, remainder_burnikel, A,
                                       B);
    AssertEquals(A, B, quotient_burnikel, quotient);
    AssertEquals(A, B, remainder_burnikel, remainder);
  }

  void TestBarrett(int* count) {
    // We pick a range around kBurnikelThreshold (instead of kBarrettThreshold)
    // to save test execution time.
    constexpr int kMin = kBurnikelThreshold / 2;
    constexpr int kMax = 2 * kBurnikelThreshold;
    // {DivideBarrett(A, B)} requires that A.len > B.len!
    for (int right_size = kMin; right_size <= kMax; right_size++) {
      for (int left_size = right_size + 1; left_size <= kMax; left_size++) {
        TestBarrett_Internal(left_size, right_size);
        if (error_) return;
        (*count)++;
      }
    }
    // We also test one random large case.
    uint64_t random_bits = rng_.NextUint64();
    int right_size = kBarrettThreshold + static_cast<int>(random_bits & 0x3FF);
    random_bits >>= 10;
    int left_size = right_size + 1 + static_cast<int>(random_bits & 0x3FFF);
    random_bits >>= 14;
    TestBarrett_Internal(left_size, right_size);
    if (error_) return;
    (*count)++;
  }
#else
  void TestBarrett(int* count) {}
#endif  // V8_ADVANCED_BIGINT_ALGORITHMS

  void TestToString(int* count) {
    constexpr int kMin = kToStringFastThreshold / 2;
    constexpr int kMax = kToStringFastThreshold * 2;
    for (int size = kMin; size < kMax; size++) {
      ScratchDigits X(size);
      GenerateRandom(X);
      for (int radix = 2; radix <= 36; radix++) {
        uint32_t chars_required = ToStringResultLength(X, radix, false);
        uint32_t result_len = chars_required;
        uint32_t reference_len = chars_required;
        std::unique_ptr<char[]> result(new char[result_len]);
        std::unique_ptr<char[]> reference(new char[reference_len]);
        processor()->ToStringImpl(result.get(), &result_len, X, radix, false,
                                  true);
        processor()->ToStringImpl(reference.get(), &reference_len, X, radix,
                                  false, false);
        AssertEquals(X, radix, reference.get(), reference_len, result.get(),
                     result_len);
        if (error_) return;
        (*count)++;
      }
    }
  }

  void TestFromString(int* count) {
    constexpr int kMaxDigits = 1 << 20;  // Any large-enough value will do.
    constexpr int kMin = kFromStringLargeThreshold / 2;
    constexpr int kMax = kFromStringLargeThreshold * 2;
    for (int size = kMin; size < kMax; size++) {
      // To keep test execution times low, test one random radix every time.
      // Generally, radixes 2 through 36 (inclusive) are supported; however
      // the functions {FromStringLarge} and {FromStringClassic} can't deal
      // with the data format that {Parse} creates for power-of-two radixes,
      // so we skip power-of-two radixes here (and test them separately below).
      // We round up the number of radixes in the list to 32 by padding with
      // 10, giving decimal numbers extra test coverage, and making it easy
      // to evenly map a random number into the index space.
      constexpr uint8_t radixes[] = {3,  5,  6,  7,  9,  10, 11, 12, 13, 14, 15,
                                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                                     28, 29, 30, 31, 33, 34, 35, 36, 10, 10};
      int radix_index = (rng_.NextUint64() & 31);
      int radix = radixes[radix_index];
      int num_chars = std::round(size * kDigitBits / std::log2(radix));
      std::unique_ptr<char[]> chars(new char[num_chars]);
      GenerateRandomString(chars.get(), num_chars, radix);
      FromStringAccumulator accumulator(kMaxDigits);
      FromStringAccumulator ref_accumulator(kMaxDigits);
      const char* start = chars.get();
      const char* end = chars.get() + num_chars;
      accumulator.Parse(start, end, radix);
      ref_accumulator.Parse(start, end, radix);
      ScratchDigits result(accumulator.ResultLength());
      ScratchDigits reference(ref_accumulator.ResultLength());
      processor()->FromStringLarge(result, &accumulator);
      processor()->FromStringClassic(reference, &ref_accumulator);
      AssertEquals(start, num_chars, radix, result, reference);
      if (error_) return;
      (*count)++;
    }
  }

  void TestFromStringBaseTwo(int* count) {
    constexpr int kMaxDigits = 1 << 20;  // Any large-enough value will do.
    constexpr int kMin = 1;
    constexpr int kMax = 100;
    for (int size = kMin; size < kMax; size++) {
      ScratchDigits X(size);
      GenerateRandom(X);
      for (int bits = 1; bits <= 5; bits++) {
        uint32_t radix = 1 << bits;
        uint32_t chars_required = ToStringResultLength(X, radix, false);
        uint32_t string_len = chars_required;
        std::unique_ptr<char[]> chars(new char[string_len]);
        processor()->ToStringImpl(chars.get(), &string_len, X, radix, false,
                                  true);
        // Fill any remaining allocated characters with garbage to test that
        // too.
        for (uint32_t i = string_len; i < chars_required; i++) {
          chars[i] = '?';
        }
        const char* start = chars.get();
        const char* end = start + chars_required;
        FromStringAccumulator accumulator(kMaxDigits);
        accumulator.Parse(start, end, radix);
        ScratchDigits result(accumulator.ResultLength());
        processor()->FromString(result, &accumulator);
        AssertEquals(start, chars_required, radix, X, result);
        if (error_) return;
        (*count)++;
      }
    }
  }

  template <typename I>
  bool ParseInt(char* s, I* out) {
    char* end;
    if (s[0] == '\0') return false;
    errno = 0;
    long l = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0' || l > std::numeric_limits<I>::max() ||
        l < std::numeric_limits<I>::min()) {
      return false;
    }
    *out = static_cast<I>(l);
    return true;
  }

  int ParseOptions(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "--list") == 0) {
        op_ = kList;
      } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
        PrintHelp(argv);
        return 0;
      } else if (strcmp(argv[i], "--random-seed") == 0 ||
                 strcmp(argv[i], "--random_seed") == 0) {
        if (++i == argc || !ParseInt(argv[i], &random_seed_)) {
          return PrintHelp(argv);
        }
      } else if (strncmp(argv[i], "--random-seed=", 14) == 0 ||
                 strncmp(argv[i], "--random_seed=", 14) == 0) {
        if (!ParseInt(argv[i] + 14, &random_seed_)) return PrintHelp(argv);
      } else if (strcmp(argv[i], "--runs") == 0) {
        if (++i == argc || !ParseInt(argv[i], &runs_)) return PrintHelp(argv);
      } else if (strncmp(argv[i], "--runs=", 7) == 0) {
        if (!ParseInt(argv[i] + 7, &runs_)) return PrintHelp(argv);
      }
#define TEST(kName, name)                \
  else if (strcmp(argv[i], name) == 0) { \
    op_ = kTest;                         \
    test_ = kName;                       \
  }
      TESTS(TEST)
#undef TEST
      else {
        std::cerr << "Warning: ignored argument: " << argv[i] << "\n";
      }
    }
    if (op_ == kNoOp) return PrintHelp(argv);  // op is mandatory.
    return 0;
  }

 private:
  void GenerateRandom(RWDigits Z) {
    if (Z.len() == 0) return;
    int mode = static_cast<int>(rng_.NextUint64() & 3);
    if (mode == 0) {
      // Generate random bits.
      if (sizeof(digit_t) == 8) {
        for (int i = 0; i < Z.len(); i++) {
          Z[i] = static_cast<digit_t>(rng_.NextUint64());
        }
      } else {
        for (int i = 0; i < Z.len(); i += 2) {
          uint64_t random = rng_.NextUint64();
          Z[i] = static_cast<digit_t>(random);
          if (i + 1 < Z.len()) Z[i + 1] = static_cast<digit_t>(random >> 32);
        }
      }
      // Special case: we don't want the MSD to be zero.
      while (Z.msd() == 0) {
        Z[Z.len() - 1] = static_cast<digit_t>(rng_.NextUint64());
      }
      return;
    }
    if (mode == 1) {
      // Generate a power of 2, with the lone 1-bit somewhere in the MSD.
      int bit_in_msd = static_cast<int>(rng_.NextUint64() % kDigitBits);
      Z[Z.len() - 1] = digit_t{1} << bit_in_msd;
      for (int i = 0; i < Z.len() - 1; i++) Z[i] = 0;
      return;
    }
    // For mode == 2 and mode == 3, generate a random number of 1-bits in the
    // MSD, aligned to the least-significant end.
    int bits_in_msd = static_cast<int>(rng_.NextUint64() % kDigitBits);
    digit_t msd = (digit_t{1} << bits_in_msd) - 1;
    if (msd == 0) msd = ~digit_t{0};
    Z[Z.len() - 1] = msd;
    if (mode == 2) {
      // The non-MSD digits are all 1-bits.
      for (int i = 0; i < Z.len() - 1; i++) Z[i] = ~digit_t{0};
    } else {
      // mode == 3
      // Each non-MSD digit is either all ones or all zeros.
      uint64_t random;
      int random_bits = 0;
      for (int i = 0; i < Z.len() - 1; i++) {
        if (random_bits == 0) {
          random = rng_.NextUint64();
          random_bits = 64;
        }
        Z[i] = random & 1 ? ~digit_t{0} : digit_t{0};
        random >>= 1;
        random_bits--;
      }
    }
  }

  void GenerateRandomString(char* str, int len, int radix) {
    DCHECK(2 <= radix && radix <= 36);
    if (len == 0) return;
    uint64_t random;
    int available_bits = 0;
    const int char_bits = BitLength(radix - 1);
    const uint64_t char_mask = (1u << char_bits) - 1u;
    for (int i = 0; i < len; i++) {
      while (true) {
        if (available_bits < char_bits) {
          random = rng_.NextUint64();
          available_bits = 64;
        }
        int next_char = static_cast<int>(random & char_mask);
        random = random >> char_bits;
        available_bits -= char_bits;
        if (next_char >= radix) continue;
        *str = kConversionChars[next_char];
        str++;
        break;
      };
    }
  }

  Operation op_{kNoOp};
  Test test_;
  bool error_{false};
  int runs_ = 1;
  int64_t random_seed_{314159265359};
  RNG rng_;
  std::unique_ptr<Processor, Processor::Destroyer> processor_;
};

}  // namespace test
}  // namespace bigint
}  // namespace v8

int main(int argc, char** argv) {
  v8::bigint::test::Runner runner;
  int ret = runner.ParseOptions(argc, argv);
  if (ret != 0) return ret;
  runner.Initialize();
  return runner.Run();
}
```