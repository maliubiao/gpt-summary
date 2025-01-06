Response:
Let's break down the thought process for analyzing the C++ code and answering the prompt's questions.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ code (`v8/test/cctest/test-utils.cc`) and describe its functionality, especially in the context of V8 testing. The prompt also specifically asks about Torque, JavaScript relationships, code logic, and common programming errors.

**2. Initial Scan and Identification of Key Areas:**

I'll first scan the code for obvious patterns and keywords:

* **`// Copyright ...`**: Standard copyright and licensing information. Ignore for functional analysis.
* **`#include ...`**:  Includes standard library headers (`stdlib.h`, `vector`) and V8-specific headers (`src/api/api-inl.h`, `src/base/...`, `test/cctest/...`). These includes suggest that the code interacts with core V8 components and is part of the testing framework. The `test/cctest/cctest.h` strongly confirms this is testing code.
* **`namespace v8 { namespace internal { ... } }`**:  The code resides within the `v8::internal` namespace, indicating it deals with V8's internal implementation details.
* **`TEST(...) { ... }`**: This macro is a strong indicator of unit tests. The names of the tests (e.g., `Utils1`, `BitSetComputer`, `SNPrintF`, `MemMove`, `Collector`, `SequenceCollector`, `CPlusPlus11Features`) provide clues about the functionality being tested.

**3. Analyzing Individual Tests:**

Now, I'll go through each `TEST` block and try to understand what it's testing:

* **`TEST(Utils1)`**:
    * **`FastD2I` and `FastD2IChecked`**: These functions convert doubles to integers. The tests check various inputs, including negative numbers, fractional parts, and edge cases like `INT_MAX`, `INT_MIN`, and `NaN`. The comment about arithmetic shift right is important for understanding a specific bitwise operation.
    * **Inference:** This test seems to be focused on the correctness of double-to-integer conversion functions.

* **`TEST(BitSetComputer)`**:
    * **`base::BitSetComputer`**:  This class seems to be for managing bitsets efficiently, possibly for storing boolean flags or small integer values. The tests verify the calculation of word counts, indices, and the encoding/decoding of bits.
    * **Inference:**  This test validates the functionality of the `BitSetComputer` utility.

* **`TEST(SNPrintF)`**:
    * **`SNPrintF`**:  This looks like a safe version of `sprintf`, preventing buffer overflows. The test iterates through different buffer sizes to ensure null termination and correct truncation behavior.
    * **Inference:** This test focuses on the safety and correctness of the `SNPrintF` function.

* **`TEST(MemMove)`**:
    * **`MemMove`**:  This is a memory copying function, likely a V8 implementation of `memmove`. The test compares its behavior to the standard `memmove` for various source and destination offsets and lengths, including overlapping regions.
    * **Inference:** This tests the correctness of the V8's `MemMove` implementation.

* **`TEST(Collector)`**:
    * **`Collector<int>`**: This appears to be a utility for efficiently collecting integer values, potentially in blocks. The test adds individual elements and blocks of elements and then verifies the order and content of the collected data.
    * **Inference:** This tests the `Collector` utility.

* **`TEST(SequenceCollector)`**:
    * **`SequenceCollector<int>`**:  Similar to `Collector`, but specifically designed for collecting sequences of values. The test creates multiple sequences of varying lengths and verifies the collected data.
    * **Inference:** This tests the `SequenceCollector` utility.

* **`TEST(SequenceCollectorRegression)`**:
    * This test specifically targets a potential regression issue in `SequenceCollector`, adding a single character and then a longer string.
    * **Inference:** This is a specific regression test for `SequenceCollector`.

* **`TEST(CPlusPlus11Features)`**:
    * This test uses C++11 features like initializer lists and range-based for loops.
    * **Inference:** This likely checks if the V8 build environment supports these C++11 features.

**4. Answering Specific Questions from the Prompt:**

Now, I'll address the prompt's specific questions based on the analysis:

* **Functionality:** List the functionalities of each test based on the above analysis.
* **Torque:** Check the file extension. It's `.cc`, not `.tq`, so it's not Torque.
* **JavaScript Relationship:** Look for any direct interaction with JavaScript concepts or APIs. `FastD2I` (Double to Integer) has a potential link, as JavaScript numbers are double-precision floats. Think about where this conversion might be used (e.g., when coercing JavaScript numbers to integers).
* **JavaScript Examples:** If a relationship exists, create simple JavaScript examples demonstrating the related functionality. For `FastD2I`, demonstrate JavaScript's implicit and explicit type coercion.
* **Code Logic Inference:** For tests involving algorithms (like `BitSetComputer`, `Collector`, `SequenceCollector`),  try to deduce the underlying logic based on the test cases. For example, `BitSetComputer` clearly involves bit manipulation, and the collectors involve adding and retrieving data. Provide example inputs and expected outputs.
* **Common Programming Errors:** Consider the potential pitfalls the code might be guarding against. For example, `SNPrintF` directly addresses buffer overflows, and the `MemMove` test covers scenarios where naive memory copying could lead to errors (overlapping memory regions). Provide examples of these errors in C/C++.

**5. Structuring the Output:**

Finally, organize the findings into a clear and structured response, addressing each point in the prompt. Use clear headings and bullet points for readability. Ensure the JavaScript examples are concise and illustrate the connection to the C++ code. For code logic inference, present the assumed inputs and the expected outputs. For common errors, provide concrete C/C++ examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe `Utils1` is just random utility functions."
* **Correction:** "The names `FastD2I` and `FastD2IChecked` are very specific. They likely handle double-to-integer conversions within V8."
* **Initial thought:** "The `Collector` and `SequenceCollector` tests seem similar."
* **Refinement:** "While both collect data, `SequenceCollector` explicitly deals with *sequences*, suggesting a specific use case, possibly for ordered or related data."
* **Considering the JavaScript connection more deeply:**  Don't just say "it's related to numbers." Think about *how* it's related. Double-to-integer conversion is a common operation when interacting between JavaScript's number type and internal integer representations.

By following this iterative process of scanning, analyzing, inferring, and refining, I can arrive at a comprehensive and accurate answer to the prompt.这个文件 `v8/test/cctest/test-utils.cc` 是 V8 JavaScript 引擎的测试代码，位于 `cctest` (C++ 兼容性测试) 目录下，名为 `test-utils.cc`，很明显它包含了一些用于测试 V8 内部工具函数的单元测试。

**功能列举:**

这个文件主要包含以下功能的测试：

1. **快速双精度浮点数到整数的转换 (`FastD2I`, `FastD2IChecked`):**
   - 测试将 `double` 类型快速转换为 `int` 类型的函数。
   - `FastD2I` 假设输入在 `int` 的范围内，不做溢出检查。
   - `FastD2IChecked` 会进行溢出检查。

2. **位集合计算机 (`BitSetComputer`):**
   - 测试一个用于高效管理位集合的工具类。
   - 可以用于存储和检索布尔值或小范围的整数值，通过位运算优化存储空间。

3. **安全的格式化字符串 (`SNPrintF`):**
   - 测试一个安全的 `printf` 风格的格式化字符串函数，可以防止缓冲区溢出。
   - 确保即使缓冲区太小，也会添加 null 终止符。

4. **内存移动 (`MemMove`):**
   - 测试内存移动函数，类似于标准的 `memmove`。
   - 能够正确处理源地址和目标地址重叠的情况。

5. **数据收集器 (`Collector`):**
   - 测试一个用于收集数据的工具类，可以按顺序添加单个元素或块状元素。

6. **序列数据收集器 (`SequenceCollector`):**
   - 测试一个用于收集数据序列的工具类，可以收集多个独立的序列并将它们合并成一个大的向量。

7. **C++11 特性测试 (`CPlusPlus11Features`):**
   - 验证 V8 的构建环境是否支持一些 C++11 的语言特性，例如统一初始化列表和范围 for 循环。

**关于 Torque：**

文件 `v8/test/cctest/test-utils.cc` 的扩展名是 `.cc`，表示这是一个 C++ 源文件。如果它的扩展名是 `.tq`，那么它才是 V8 Torque 的源代码。 Torque 是一种 V8 内部使用的领域特定语言，用于定义运行时函数的实现。

**与 JavaScript 的关系：**

`v8/test/cctest/test-utils.cc` 中的某些功能与 JavaScript 的功能有间接关系，特别是 **快速双精度浮点数到整数的转换 (`FastD2I`, `FastD2IChecked`)**。 JavaScript 中的 Number 类型本质上是 IEEE 754 双精度浮点数。在 JavaScript 运行时环境中，很多操作需要将 JavaScript 的数字转换为整数。

**JavaScript 示例：**

```javascript
// JavaScript 中将浮点数转换为整数的几种方式

// 1. 隐式转换 (例如位运算)
console.log(10.5 | 0);   // 输出: 10 (相当于 FastD2I，但不做溢出检查，且只保留低32位)
console.log(-10.5 | 0);  // 输出: -10

// 2. Math.floor(), Math.ceil(), Math.round()
console.log(Math.floor(10.5)); // 输出: 10
console.log(Math.ceil(10.5));  // 输出: 11
console.log(Math.round(10.5)); // 输出: 11

// 3. parseInt()
console.log(parseInt(10.5)); // 输出: 10

// 4. Number.isInteger() 检查是否为整数
console.log(Number.isInteger(10));   // 输出: true
console.log(Number.isInteger(10.5));  // 输出: false

// V8 内部的 FastD2I 类似于将浮点数直接截断为整数部分，
// 但它是在 C++ 层面实现的，用于 V8 的内部逻辑。
```

**代码逻辑推理：**

**`FastD2I` 和 `FastD2IChecked` 假设输入与输出：**

* **假设输入 (FastD2I):**
    * `input = -1000000.0`
    * `input = -1.234`
    * `input = 0.345`
    * `input = 1.234`
    * `input = 1000000.123`

* **预期输出 (FastD2I):**
    * `-1000000`
    * `-1`
    * `0`
    * `1`
    * `1000000`

* **假设输入 (FastD2IChecked):**
    * `input = 1.0e100` (一个非常大的数，超出 `int` 范围)
    * `input = -1.0e100` (一个非常小的数，超出 `int` 范围)
    * `input = std::numeric_limits<double>::quiet_NaN()` (非数字)

* **预期输出 (FastD2IChecked):**
    * `INT_MAX` (整数最大值，表示溢出)
    * `INT_MIN` (整数最小值，表示溢出)
    * `INT_MIN` (对于 NaN，也返回最小值)

**`BitSetComputer` 假设输入与输出：**

* **假设输入 (编码和解码):**
    * `data = 0`
    * 编码索引 1 设置为 `true`
    * 编码索引 4 设置为 `true`

* **预期输出 (解码):**
    * 解码索引 1 得到 `true`
    * 解码索引 4 得到 `true`
    * 解码索引 0 得到 `false`
    * 解码索引 2 得到 `false`
    * 解码索引 3 得到 `false`

**涉及用户常见的编程错误：**

1. **缓冲区溢出 (`SNPrintF` 旨在避免):**
   - **错误示例 (C/C++):**
     ```c++
     char buffer[10];
     char* long_string = "This is a very long string";
     sprintf(buffer, "%s", long_string); // 可能导致缓冲区溢出
     ```
   - **说明:** `sprintf` 如果格式化的字符串长度超过 `buffer` 的大小，就会覆盖 `buffer` 之外的内存，导致程序崩溃或安全漏洞。`SNPrintF` 通过指定最大写入长度来避免这个问题。

2. **内存操作错误 (`MemMove` 旨在测试正确性):**
   - **错误示例 (C/C++，假设使用不安全的内存复制函数):**
     ```c++
     char data[10] = "012345678";
     // 尝试将 data[0...4] 复制到 data[3...7]，内存区域重叠
     // 使用 memcpy 可能导致错误的结果，因为它不处理重叠
     memcpy(data + 3, data, 5);
     // 预期结果："012012378"，但 memcpy 可能会得到错误结果
     ```
   - **说明:** 当源内存区域和目标内存区域重叠时，使用 `memcpy` 可能会导致数据损坏。`memmove` 能够正确处理这种情况，先将源数据复制到一个临时缓冲区，然后再复制到目标位置，或者从后向前复制。

3. **未检查的类型转换 (与 `FastD2I` 的溢出检查相关):**
   - **错误示例 (C/C++):**
     ```c++
     double large_number = 1e18;
     int integer_value = static_cast<int>(large_number); // 溢出，但不会报错
     ```
   - **说明:** 将超出 `int` 范围的 `double` 值强制转换为 `int`，会导致数据丢失或未定义的行为。`FastD2IChecked` 的存在就是为了在转换前进行范围检查，避免这种错误。

总而言之，`v8/test/cctest/test-utils.cc` 是 V8 引擎的基础测试套件的一部分，它专注于测试一些底层的、通用的工具函数，这些函数在 V8 的内部实现中被广泛使用。这些测试覆盖了数值转换、内存操作、数据结构等方面，并间接地反映了 JavaScript 引擎在处理数据时的一些内部机制和需要注意的问题。

Prompt: 
```
这是目录为v8/test/cctest/test-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdlib.h>

#include <vector>

#include "src/api/api-inl.h"
#include "src/base/bit-field.h"
#include "src/numbers/conversions.h"
#include "test/cctest/cctest.h"
#include "test/cctest/collector.h"

namespace v8 {
namespace internal {

TEST(Utils1) {
  CHECK_EQ(-1000000, FastD2I(-1000000.0));
  CHECK_EQ(-1, FastD2I(-1.0));
  CHECK_EQ(0, FastD2I(0.0));
  CHECK_EQ(1, FastD2I(1.0));
  CHECK_EQ(1000000, FastD2I(1000000.0));

  CHECK_EQ(-1000000, FastD2I(-1000000.123));
  CHECK_EQ(-1, FastD2I(-1.234));
  CHECK_EQ(0, FastD2I(0.345));
  CHECK_EQ(1, FastD2I(1.234));
  CHECK_EQ(1000000, FastD2I(1000000.123));
  // Check that >> is implemented as arithmetic shift right.
  // If this is not true, then ArithmeticShiftRight() must be changed,
  // There are also documented right shifts in assembler.cc of
  // int8_t and intptr_t signed integers.
  CHECK_EQ(-2, -8 >> 2);
  CHECK_EQ(-2, static_cast<int8_t>(-8) >> 2);
  CHECK_EQ(-2, static_cast<int>(static_cast<intptr_t>(-8) >> 2));

  CHECK_EQ(-1000000, FastD2IChecked(-1000000.0));
  CHECK_EQ(-1, FastD2IChecked(-1.0));
  CHECK_EQ(0, FastD2IChecked(0.0));
  CHECK_EQ(1, FastD2IChecked(1.0));
  CHECK_EQ(1000000, FastD2IChecked(1000000.0));

  CHECK_EQ(-1000000, FastD2IChecked(-1000000.123));
  CHECK_EQ(-1, FastD2IChecked(-1.234));
  CHECK_EQ(0, FastD2IChecked(0.345));
  CHECK_EQ(1, FastD2IChecked(1.234));
  CHECK_EQ(1000000, FastD2IChecked(1000000.123));

  CHECK_EQ(INT_MAX, FastD2IChecked(1.0e100));
  CHECK_EQ(INT_MIN, FastD2IChecked(-1.0e100));
  CHECK_EQ(INT_MIN, FastD2IChecked(std::numeric_limits<double>::quiet_NaN()));
}


TEST(BitSetComputer) {
  using BoolComputer = base::BitSetComputer<bool, 1, kSmiValueSize, uint32_t>;
  CHECK_EQ(0, BoolComputer::word_count(0));
  CHECK_EQ(1, BoolComputer::word_count(8));
  CHECK_EQ(2, BoolComputer::word_count(50));
  CHECK_EQ(0, BoolComputer::index(0, 8));
  CHECK_EQ(100, BoolComputer::index(100, 8));
  CHECK_EQ(1, BoolComputer::index(0, 40));

  {
    uint32_t data = 0;
    data = BoolComputer::encode(data, 1, true);
    data = BoolComputer::encode(data, 4, true);
    CHECK(BoolComputer::decode(data, 1));
    CHECK(BoolComputer::decode(data, 4));
    CHECK(!BoolComputer::decode(data, 0));
    CHECK(!BoolComputer::decode(data, 2));
    CHECK(!BoolComputer::decode(data, 3));
  }

  // Lets store 2 bits per item with 3000 items and verify the values are
  // correct.
  using TwoBits = base::BitSetComputer<unsigned char, 2, 8, unsigned char>;
  const int words = 750;
  CHECK_EQ(words, TwoBits::word_count(3000));
  const int offset = 10;
  base::Vector<unsigned char> buffer =
      base::Vector<unsigned char>::New(offset + words);
  memset(buffer.begin(), 0, sizeof(unsigned char) * buffer.length());
  for (int i = 0; i < words; i++) {
    const int index = TwoBits::index(offset, i);
    unsigned char data = buffer[index];
    data = TwoBits::encode(data, i, i % 4);
    buffer[index] = data;
  }

  for (int i = 0; i < words; i++) {
    const int index = TwoBits::index(offset, i);
    unsigned char data = buffer[index];
    CHECK_EQ(i % 4, TwoBits::decode(data, i));
  }
  buffer.Dispose();
}


TEST(SNPrintF) {
  // Make sure that strings that are truncated because of too small
  // buffers are zero-terminated anyway.
  const char* s = "the quick lazy .... oh forget it!";
  int length = static_cast<int>(strlen(s));
  for (int i = 1; i < length * 2; i++) {
    static const char kMarker = static_cast<char>(42);
    base::Vector<char> buffer = base::Vector<char>::New(i + 1);
    buffer[i] = kMarker;
    int n = SNPrintF(base::Vector<char>(buffer.begin(), i), "%s", s);
    CHECK(n <= i);
    CHECK(n == length || n == -1);
    CHECK_EQ(0, strncmp(buffer.begin(), s, i - 1));
    CHECK_EQ(kMarker, buffer[i]);
    if (i <= length) {
      CHECK_EQ(i - 1, strlen(buffer.begin()));
    } else {
      CHECK_EQ(length, strlen(buffer.begin()));
    }
    buffer.Dispose();
  }
}


static const int kAreaSize = 512;

void TestMemMove(uint8_t* area1, uint8_t* area2, int src_offset,
                 int dest_offset, int length) {
  for (int i = 0; i < kAreaSize; i++) {
    area1[i] = i & 0xFF;
    area2[i] = i & 0xFF;
  }
  MemMove(area1 + dest_offset, area1 + src_offset, length);
  memmove(area2 + dest_offset, area2 + src_offset, length);
  if (memcmp(area1, area2, kAreaSize) != 0) {
    printf("MemMove(): src_offset: %d, dest_offset: %d, length: %d\n",
           src_offset, dest_offset, length);
    for (int i = 0; i < kAreaSize; i++) {
      if (area1[i] == area2[i]) continue;
      printf("diff at offset %d (%p): is %d, should be %d\n", i,
             reinterpret_cast<void*>(area1 + i), area1[i], area2[i]);
    }
    FATAL("memmove error");
  }
}

TEST(MemMove) {
  uint8_t* area1 = new uint8_t[kAreaSize];
  uint8_t* area2 = new uint8_t[kAreaSize];

  static const int kMinOffset = 32;
  static const int kMaxOffset = 64;
  static const int kMaxLength = 128;
  static_assert(kMaxOffset + kMaxLength < kAreaSize);

  for (int src_offset = kMinOffset; src_offset <= kMaxOffset; src_offset++) {
    for (int dst_offset = kMinOffset; dst_offset <= kMaxOffset; dst_offset++) {
      for (int length = 0; length <= kMaxLength; length++) {
        TestMemMove(area1, area2, src_offset, dst_offset, length);
      }
    }
  }
  delete[] area1;
  delete[] area2;
}

TEST(Collector) {
  Collector<int> collector(8);
  const int kLoops = 5;
  const int kSequentialSize = 1000;
  const int kBlockSize = 7;
  for (int loop = 0; loop < kLoops; loop++) {
    base::Vector<int> block = collector.AddBlock(7, 0xBADCAFE);
    for (int i = 0; i < kSequentialSize; i++) {
      collector.Add(i);
    }
    for (int i = 0; i < kBlockSize - 1; i++) {
      block[i] = i * 7;
    }
  }
  base::Vector<int> result = collector.ToVector();
  CHECK_EQ(kLoops * (kBlockSize + kSequentialSize), result.length());
  for (int i = 0; i < kLoops; i++) {
    int offset = i * (kSequentialSize + kBlockSize);
    for (int j = 0; j < kBlockSize - 1; j++) {
      CHECK_EQ(j * 7, result[offset + j]);
    }
    CHECK_EQ(0xBADCAFE, result[offset + kBlockSize - 1]);
    for (int j = 0; j < kSequentialSize; j++) {
      CHECK_EQ(j, result[offset + kBlockSize + j]);
    }
  }
  result.Dispose();
}


TEST(SequenceCollector) {
  SequenceCollector<int> collector(8);
  const int kLoops = 5000;
  const int kMaxSequenceSize = 13;
  int total_length = 0;
  for (int loop = 0; loop < kLoops; loop++) {
    int seq_length = loop % kMaxSequenceSize;
    collector.StartSequence();
    for (int j = 0; j < seq_length; j++) {
      collector.Add(j);
    }
    base::Vector<int> sequence = collector.EndSequence();
    for (int j = 0; j < seq_length; j++) {
      CHECK_EQ(j, sequence[j]);
    }
    total_length += seq_length;
  }
  base::Vector<int> result = collector.ToVector();
  CHECK_EQ(total_length, result.length());
  int offset = 0;
  for (int loop = 0; loop < kLoops; loop++) {
    int seq_length = loop % kMaxSequenceSize;
    for (int j = 0; j < seq_length; j++) {
      CHECK_EQ(j, result[offset]);
      offset++;
    }
  }
  result.Dispose();
}


TEST(SequenceCollectorRegression) {
  SequenceCollector<char> collector(16);
  collector.StartSequence();
  collector.Add('0');
  collector.AddBlock(
      base::Vector<const char>("12345678901234567890123456789012", 32));
  base::Vector<char> seq = collector.EndSequence();
  CHECK_EQ(0, strncmp("0123456789012345678901234567890123", seq.begin(),
                      seq.length()));
}


TEST(CPlusPlus11Features) {
  struct S {
    bool x;
    struct T {
      double y;
      int z[3];
    } t;
  };
  S s{true, {3.1415, {1, 2, 3}}};
  CHECK_EQ(2, s.t.z[1]);

  std::vector<int> vec{11, 22, 33, 44};
  vec.push_back(55);
  vec.push_back(66);
  for (auto& i : vec) {
    ++i;
  }
  int j = 12;
  for (auto i : vec) {
    CHECK_EQ(j, i);
    j += 11;
  }
}

}  // namespace internal
}  // namespace v8

"""

```