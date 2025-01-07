Response:
Let's break down the thought process to analyze the given C++ code and generate the comprehensive explanation.

**1. Understanding the Goal:**

The request asks for a functional description of the provided C++ code (`decoder-unittest.cc`), along with specific considerations like its relationship to Torque, JavaScript, code logic examples, and common programming errors.

**2. Initial Code Scan and Identification of Key Elements:**

A quick scan reveals the following:

* **Headers:** Includes like `test-utils.h`, `objects-inl.h`, and `decoder.h` suggest this is a unit test file for a decoder component. The `wasm` namespace confirms it's related to WebAssembly.
* **Test Fixture:** The `DecoderTest` class inheriting from `TestWithZone` is a standard Google Test pattern for setting up test environments.
* **Decoder Instance:** The `Decoder decoder;` declaration indicates the code is testing the `Decoder` class.
* **Macros:**  `CHECK_UINT32V_INLINE`, `CHECK_INT32V_INLINE`, etc., are macros that appear to be testing the decoding of variable-length integers (varints). The `U32V_1`, `U32V_2` hints at the byte representation.
* **Test Cases:**  Functions starting with `TEST_F(DecoderTest, ...)` are individual test cases, each focused on a specific aspect of the decoder. The names (e.g., `ReadU32v_OneByte`, `ReadU32v_off_end1`) give clues about what's being tested.

**3. Deciphering the Macros:**

The macros are crucial. Let's take `CHECK_UINT32V_INLINE` as an example:

* **Input:** `expected`, `expected_length`, and a variable number of bytes (`__VA_ARGS__`).
* **Actions:**
    * Creates a `data` array from the provided bytes.
    * Resets the `decoder` with this data.
    * Calls `decoder.read_u32v` (implying this is the function being tested).
    * Asserts that the decoded `value` and `length` match the `expected` values.
    * Checks that the decoder's internal pointer (`pc()`) is in the correct place.
    * Verifies `decoder.ok()` (meaning no errors occurred).
    * Calls `decoder.consume_u32v` (another decoding method).
    * Asserts the result of `consume_u32v` is correct and the pointer is updated.

This analysis reveals the core functionality being tested: reading and consuming variable-length unsigned 32-bit integers. The other `CHECK_*V_INLINE` macros follow a similar pattern for signed 32-bit and 64-bit integers.

**4. Understanding the Test Cases:**

Now, let's connect the macros to the test cases:

* **`ReadU32v_OneByte`:** Tests decoding single-byte unsigned 32-bit varints.
* **`ReadU32v_TwoByte`, `ReadU32v_ThreeByte`, etc.:** Test decoding multi-byte unsigned 32-bit varints.
* **`ReadI32v_OneByte`, `ReadI32v_TwoByte`, etc.:** Test decoding signed 32-bit varints.
* **`ReadU64v_*`, `ReadI64v_*`:** Test decoding unsigned and signed 64-bit varints.
* **`ReadU32v_off_end*`:** Test error handling when the input data ends prematurely.
* **`ReadU32v_extra_bits`, `ReadI32v_extra_bits_*`:** Test error handling related to extra bits in the varint encoding.
* **`ReadU32v_Bits`, `ReadU64v_Bits`, `ReadI64v_Bits`:** More exhaustive tests with a range of values and bit lengths.
* **`FailOnNullData`:** Tests how the decoder handles null input.

**5. Answering the Specific Questions:**

* **Functionality:** Based on the macros and test cases, the primary function is to test the `Decoder` class's ability to correctly decode variable-length unsigned and signed 32-bit and 64-bit integers.
* **Torque:** The filename extension is `.cc`, not `.tq`, so it's C++, not Torque.
* **JavaScript Relationship:** WebAssembly (and thus its encoding) is directly related to JavaScript as it's a compilation target for web browsers. The varint encoding is used in the binary format of WebAssembly modules. An example can be given demonstrating how JavaScript might receive a WebAssembly module, which uses this encoding.
* **Code Logic Inference:** The macros provide clear examples of input byte sequences and their expected decoded values and lengths. These can be presented as input/output pairs.
* **Common Programming Errors:**  The "off_end" and "extra_bits" test cases directly point to common errors when implementing or using varint decoders:
    * **Insufficient data:** Trying to read a varint when not enough bytes are available.
    * **Invalid encoding:**  Having extra high-order bits set incorrectly.

**6. Structuring the Explanation:**

Organize the findings into a clear and logical structure, covering each aspect of the request:

* Start with a general overview of the file's purpose.
* Address the Torque question directly.
* Explain the connection to JavaScript with an example.
* Provide input/output examples based on the macros.
* Illustrate common programming errors using the relevant test cases.
* Summarize the core functionality.

**7. Refinement and Review:**

Read through the generated explanation to ensure clarity, accuracy, and completeness. Double-check the code examples and the explanation of the varint encoding. Ensure the language is precise and avoids jargon where possible, or explains it if necessary. For instance, explicitly mentioning the "most significant bit" in the varint encoding explanation is helpful.

By following these steps, we arrive at the detailed and accurate explanation provided previously. The key is to systematically analyze the code, understand its structure and purpose, and then address each specific part of the request.
好的，让我们来分析一下 `v8/test/unittests/wasm/decoder-unittest.cc` 这个文件。

**功能概述**

`v8/test/unittests/wasm/decoder-unittest.cc` 是 V8 引擎中用于测试 WebAssembly (Wasm) 解码器 (`decoder.h`) 功能的单元测试文件。它包含了一系列测试用例，用于验证解码器在处理不同格式的 Wasm 二进制数据时的正确性。

**具体功能分解**

这个文件主要测试以下 `wasm::Decoder` 类的功能：

1. **读取变长编码的整数 (Varints)：**
   - `read_u32v` 和 `consume_u32v`:  测试读取和消费无符号 32 位变长整数的功能。
   - `read_i32v` 和 `consume_i32v`:  测试读取和消费有符号 32 位变长整数的功能。
   - `read_u64v`: 测试读取无符号 64 位变长整数的功能。
   - `read_i64v`: 测试读取有符号 64 位变长整数的功能。

2. **错误处理：**
   - 测试当输入数据不足以构成一个完整的变长整数时，解码器是否能正确检测并处理错误（例如 `ReadU32v_off_end1` 等测试用例）。
   - 测试当变长整数编码中存在额外的、不应该存在的 bit 时，解码器是否能正确检测并处理错误（例如 `ReadU32v_extra_bits` 等测试用例）。
   - 测试当传入空数据时，解码器是否能正确处理（`FailOnNullData`）。

**关于文件类型和 JavaScript 关系**

- **文件类型：** `v8/test/unittests/wasm/decoder-unittest.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是以 `.tq` 结尾的 Torque 源代码文件。

- **与 JavaScript 的关系：** WebAssembly 是一种可以在现代网络浏览器中运行的新型代码，并且是 JavaScript 的补充。V8 引擎负责执行 JavaScript 和 WebAssembly 代码。`decoder-unittest.cc` 中测试的解码器是将 WebAssembly 的二进制格式转换为 V8 内部表示的关键组件。当浏览器加载一个 `.wasm` 文件时，V8 的解码器会解析这个二进制文件。

**JavaScript 举例说明**

以下是一个简单的 JavaScript 例子，展示了如何加载和使用 WebAssembly 模块，其中 V8 的解码器在幕后工作：

```javascript
async function loadWasm() {
  try {
    const response = await fetch('my_wasm_module.wasm'); // 假设有一个名为 my_wasm_module.wasm 的文件
    const buffer = await response.arrayBuffer();
    const module = await WebAssembly.compile(buffer); // V8 的解码器在这里解析 buffer
    const instance = await WebAssembly.instantiate(module);

    // 调用 Wasm 模块导出的函数
    const result = instance.exports.add(5, 3);
    console.log(result); // 输出 8
  } catch (error) {
    console.error("加载 Wasm 模块失败:", error);
  }
}

loadWasm();
```

在这个例子中，`WebAssembly.compile(buffer)` 这一步会触发 V8 的 WebAssembly 解码器去解析 `buffer` 中包含的 WebAssembly 二进制数据。`decoder-unittest.cc` 中的测试正是为了确保这个解码过程的正确性。

**代码逻辑推理 (假设输入与输出)**

让我们以 `TEST_F(DecoderTest, ReadU32v_OneByte)` 中的一个测试用例为例：

```c++
CHECK_UINT32V_INLINE(37, 1, 37);
```

**假设输入：** 一个包含单个字节的数组 `{37}` (十进制)。

**代码逻辑：**

1. `decoder.Reset(data, data + sizeof(data));`：解码器被设置为处理这个包含一个字节的数据。
2. `decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());`：解码器尝试从数据的起始位置读取一个无符号 32 位变长整数。
3. 由于输入只有一个字节 `37` (二进制 `00100101`)，其最高位不是 1，所以它被解析为一个单字节的变长整数。
4. `EXPECT_EQ(static_cast<uint32_t>(expected), value);`：断言解码得到的值 (`value`) 等于预期的值 `37`。
5. `EXPECT_EQ(static_cast<unsigned>(expected_length), length);`：断言解码所用的字节数 (`length`) 等于预期的长度 `1`。
6. `EXPECT_EQ(data, decoder.pc());`：断言解码后，解码器的程序计数器 (`pc()`) 指向数据的起始位置（因为 `read_u32v` 不会消耗数据，只是读取）。
7. `EXPECT_TRUE(decoder.ok());`：断言解码过程中没有发生错误。
8. `EXPECT_EQ(static_cast<uint32_t>(expected), decoder.consume_u32v());`：断言消费（读取并移动程序计数器）得到的无符号 32 位变长整数等于预期的值 `37`。
9. `EXPECT_EQ(data + expected_length, decoder.pc());`：断言消费后，解码器的程序计数器指向数据的末尾 (`data + 1`)。

**输出：**  如果所有断言都通过，则这个测试用例成功。

**涉及用户常见的编程错误**

在处理变长整数时，用户可能会犯以下编程错误，这些错误也是该单元测试试图覆盖的：

1. **缓冲区溢出/读取越界：**  如果解码器在没有足够数据的情况下尝试读取变长整数，可能会读取到缓冲区之外的内存。 `ReadU32v_off_end*` 系列的测试用例就是为了检测这种情况。

   **C++ 示例：**
   ```c++
   uint8_t data[] = {0x80}; // 这是一个不完整的变长整数
   Decoder decoder(data, data + sizeof(data));
   decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());
   // 错误的假设：认为 read_u32v 会返回一个有效值
   uint32_t value = decoder.consume_u32v(); // 可能会导致错误或未定义行为
   ```

2. **未正确处理变长整数的结束标志：** 变长整数的编码方式中，每个字节的最高位用于指示是否还有后续字节。如果解码器没有正确处理这个标志，可能会过早停止读取或读取过多的字节。

3. **假设了固定的整数大小：**  用户可能会错误地假设所有的整数都占用固定数量的字节，而忽略了变长编码的存在。

   **JavaScript 示例 (概念上的错误，因为 JavaScript 本身处理了 Wasm 的加载)：**
   ```javascript
   // 假设我们手动解析 Wasm 二进制数据，这是不推荐的，但为了说明问题
   const wasmBytes = new Uint8Array([0x85, 0x03]); // 代表数字 389 的变长编码
   // 错误地假设这是一个单字节整数
   const value = wasmBytes[0]; // 结果是 133，而不是 389
   ```

4. **符号扩展错误：** 在处理有符号变长整数时，解码器需要正确进行符号扩展。如果实现不正确，可能会导致负数被错误地解码为正数，反之亦然。

   **C++ 示例 (假设 `Decoder` 类有错误):**
   ```c++
   uint8_t data[] = {0x7F}; // 代表 -1 的有符号变长编码
   Decoder decoder(data, data + sizeof(data));
   int32_t value = decoder.consume_i32v();
   // 如果解码器有错误，可能会错误地将 0x7F 解码为 127 而不是 -1
   ```

`decoder-unittest.cc` 通过各种测试用例，包括边界情况和错误情况，来确保 `wasm::Decoder` 类能够正确地处理这些潜在的编程错误，并提供可靠的解码功能。

Prompt: 
```
这是目录为v8/test/unittests/wasm/decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/test-utils.h"

#include "src/base/overflowing-math.h"
#include "src/objects/objects-inl.h"
#include "src/wasm/decoder.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {

class DecoderTest : public TestWithZone {
 public:
  DecoderTest() : decoder(nullptr, nullptr) {}

  Decoder decoder;
};

#define CHECK_UINT32V_INLINE(expected, expected_length, ...)            \
  do {                                                                  \
    const uint8_t data[] = {__VA_ARGS__};                               \
    decoder.Reset(data, data + sizeof(data));                           \
    auto [value, length] =                                              \
        decoder.read_u32v<Decoder::FullValidationTag>(decoder.start()); \
    EXPECT_EQ(static_cast<uint32_t>(expected), value);                  \
    EXPECT_EQ(static_cast<unsigned>(expected_length), length);          \
    EXPECT_EQ(data, decoder.pc());                                      \
    EXPECT_TRUE(decoder.ok());                                          \
    EXPECT_EQ(static_cast<uint32_t>(expected), decoder.consume_u32v()); \
    EXPECT_EQ(data + expected_length, decoder.pc());                    \
  } while (false)

#define CHECK_INT32V_INLINE(expected, expected_length, ...)             \
  do {                                                                  \
    const uint8_t data[] = {__VA_ARGS__};                               \
    decoder.Reset(data, data + sizeof(data));                           \
    auto [value, length] =                                              \
        decoder.read_i32v<Decoder::FullValidationTag>(decoder.start()); \
    EXPECT_EQ(expected, value);                                         \
    EXPECT_EQ(static_cast<unsigned>(expected_length), length);          \
    EXPECT_EQ(data, decoder.pc());                                      \
    EXPECT_TRUE(decoder.ok());                                          \
    EXPECT_EQ(expected, decoder.consume_i32v());                        \
    EXPECT_EQ(data + expected_length, decoder.pc());                    \
  } while (false)

#define CHECK_UINT64V_INLINE(expected, expected_length, ...)            \
  do {                                                                  \
    const uint8_t data[] = {__VA_ARGS__};                               \
    decoder.Reset(data, data + sizeof(data));                           \
    auto [value, length] =                                              \
        decoder.read_u64v<Decoder::FullValidationTag>(decoder.start()); \
    EXPECT_EQ(static_cast<uint64_t>(expected), value);                  \
    EXPECT_EQ(static_cast<unsigned>(expected_length), length);          \
  } while (false)

#define CHECK_INT64V_INLINE(expected, expected_length, ...)             \
  do {                                                                  \
    const uint8_t data[] = {__VA_ARGS__};                               \
    decoder.Reset(data, data + sizeof(data));                           \
    auto [value, length] =                                              \
        decoder.read_i64v<Decoder::FullValidationTag>(decoder.start()); \
    EXPECT_EQ(expected, value);                                         \
    EXPECT_EQ(static_cast<unsigned>(expected_length), length);          \
  } while (false)

TEST_F(DecoderTest, ReadU32v_OneByte) {
  CHECK_UINT32V_INLINE(0, 1, 0);
  CHECK_UINT32V_INLINE(5, 1, 5);
  CHECK_UINT32V_INLINE(7, 1, 7);
  CHECK_UINT32V_INLINE(9, 1, 9);
  CHECK_UINT32V_INLINE(37, 1, 37);
  CHECK_UINT32V_INLINE(69, 1, 69);
  CHECK_UINT32V_INLINE(110, 1, 110);
  CHECK_UINT32V_INLINE(125, 1, 125);
  CHECK_UINT32V_INLINE(126, 1, 126);
  CHECK_UINT32V_INLINE(127, 1, 127);
}

TEST_F(DecoderTest, ReadU32v_TwoByte) {
  CHECK_UINT32V_INLINE(0, 1, 0, 0);
  CHECK_UINT32V_INLINE(10, 1, 10, 0);
  CHECK_UINT32V_INLINE(27, 1, 27, 0);
  CHECK_UINT32V_INLINE(100, 1, 100, 0);

  CHECK_UINT32V_INLINE(444, 2, U32V_2(444));
  CHECK_UINT32V_INLINE(544, 2, U32V_2(544));
  CHECK_UINT32V_INLINE(1311, 2, U32V_2(1311));
  CHECK_UINT32V_INLINE(2333, 2, U32V_2(2333));

  for (uint32_t i = 0; i < 1 << 14; i = i * 13 + 1) {
    CHECK_UINT32V_INLINE(i, 2, U32V_2(i));
  }

  const uint32_t max = (1 << 14) - 1;
  CHECK_UINT32V_INLINE(max, 2, U32V_2(max));
}

TEST_F(DecoderTest, ReadU32v_ThreeByte) {
  CHECK_UINT32V_INLINE(0, 1, 0, 0, 0, 0);
  CHECK_UINT32V_INLINE(10, 1, 10, 0, 0, 0);
  CHECK_UINT32V_INLINE(27, 1, 27, 0, 0, 0);
  CHECK_UINT32V_INLINE(100, 1, 100, 0, 0, 0);

  CHECK_UINT32V_INLINE(11, 3, U32V_3(11));
  CHECK_UINT32V_INLINE(101, 3, U32V_3(101));
  CHECK_UINT32V_INLINE(446, 3, U32V_3(446));
  CHECK_UINT32V_INLINE(546, 3, U32V_3(546));
  CHECK_UINT32V_INLINE(1319, 3, U32V_3(1319));
  CHECK_UINT32V_INLINE(2338, 3, U32V_3(2338));
  CHECK_UINT32V_INLINE(8191, 3, U32V_3(8191));
  CHECK_UINT32V_INLINE(9999, 3, U32V_3(9999));
  CHECK_UINT32V_INLINE(14444, 3, U32V_3(14444));
  CHECK_UINT32V_INLINE(314444, 3, U32V_3(314444));
  CHECK_UINT32V_INLINE(614444, 3, U32V_3(614444));

  const uint32_t max = (1 << 21) - 1;

  for (uint32_t i = 0; i <= max; i = i * 13 + 3) {
    CHECK_UINT32V_INLINE(i, 3, U32V_3(i), 0);
  }

  CHECK_UINT32V_INLINE(max, 3, U32V_3(max));
}

TEST_F(DecoderTest, ReadU32v_FourByte) {
  CHECK_UINT32V_INLINE(0, 1, 0, 0, 0, 0, 0);
  CHECK_UINT32V_INLINE(10, 1, 10, 0, 0, 0, 0);
  CHECK_UINT32V_INLINE(27, 1, 27, 0, 0, 0, 0);
  CHECK_UINT32V_INLINE(100, 1, 100, 0, 0, 0, 0);

  CHECK_UINT32V_INLINE(13, 4, U32V_4(13));
  CHECK_UINT32V_INLINE(107, 4, U32V_4(107));
  CHECK_UINT32V_INLINE(449, 4, U32V_4(449));
  CHECK_UINT32V_INLINE(541, 4, U32V_4(541));
  CHECK_UINT32V_INLINE(1317, 4, U32V_4(1317));
  CHECK_UINT32V_INLINE(2334, 4, U32V_4(2334));
  CHECK_UINT32V_INLINE(8191, 4, U32V_4(8191));
  CHECK_UINT32V_INLINE(9994, 4, U32V_4(9994));
  CHECK_UINT32V_INLINE(14442, 4, U32V_4(14442));
  CHECK_UINT32V_INLINE(314442, 4, U32V_4(314442));
  CHECK_UINT32V_INLINE(614442, 4, U32V_4(614442));
  CHECK_UINT32V_INLINE(1614442, 4, U32V_4(1614442));
  CHECK_UINT32V_INLINE(5614442, 4, U32V_4(5614442));
  CHECK_UINT32V_INLINE(19614442, 4, U32V_4(19614442));

  const uint32_t max = (1 << 28) - 1;

  for (uint32_t i = 0; i <= max; i = i * 13 + 5) {
    CHECK_UINT32V_INLINE(i, 4, U32V_4(i), 0);
  }

  CHECK_UINT32V_INLINE(max, 4, U32V_4(max));
}

TEST_F(DecoderTest, ReadU32v_FiveByte) {
  CHECK_UINT32V_INLINE(0, 1, 0, 0, 0, 0, 0);
  CHECK_UINT32V_INLINE(10, 1, 10, 0, 0, 0, 0);
  CHECK_UINT32V_INLINE(27, 1, 27, 0, 0, 0, 0);
  CHECK_UINT32V_INLINE(100, 1, 100, 0, 0, 0, 0);

  CHECK_UINT32V_INLINE(13, 5, U32V_5(13));
  CHECK_UINT32V_INLINE(107, 5, U32V_5(107));
  CHECK_UINT32V_INLINE(449, 5, U32V_5(449));
  CHECK_UINT32V_INLINE(541, 5, U32V_5(541));
  CHECK_UINT32V_INLINE(1317, 5, U32V_5(1317));
  CHECK_UINT32V_INLINE(2334, 5, U32V_5(2334));
  CHECK_UINT32V_INLINE(8191, 5, U32V_5(8191));
  CHECK_UINT32V_INLINE(9994, 5, U32V_5(9994));
  CHECK_UINT32V_INLINE(24442, 5, U32V_5(24442));
  CHECK_UINT32V_INLINE(414442, 5, U32V_5(414442));
  CHECK_UINT32V_INLINE(714442, 5, U32V_5(714442));
  CHECK_UINT32V_INLINE(1614442, 5, U32V_5(1614442));
  CHECK_UINT32V_INLINE(6614442, 5, U32V_5(6614442));
  CHECK_UINT32V_INLINE(89614442, 5, U32V_5(89614442));
  CHECK_UINT32V_INLINE(2219614442u, 5, U32V_5(2219614442u));
  CHECK_UINT32V_INLINE(3219614442u, 5, U32V_5(3219614442u));
  CHECK_UINT32V_INLINE(4019614442u, 5, U32V_5(4019614442u));

  const uint32_t max = 0xFFFFFFFFu;

  for (uint32_t i = 1; i < 32; i++) {
    uint32_t val = 0x983489AAu << i;
    CHECK_UINT32V_INLINE(val, 5, U32V_5(val), 0);
  }

  CHECK_UINT32V_INLINE(max, 5, U32V_5(max));
}

TEST_F(DecoderTest, ReadU32v_various) {
  for (int i = 0; i < 10; i++) {
    uint32_t x = 0xCCCCCCCCu * i;
    for (int width = 0; width < 32; width++) {
      uint32_t val = x >> width;

      CHECK_UINT32V_INLINE(val & MASK_7, 1, U32V_1(val));
      CHECK_UINT32V_INLINE(val & MASK_14, 2, U32V_2(val));
      CHECK_UINT32V_INLINE(val & MASK_21, 3, U32V_3(val));
      CHECK_UINT32V_INLINE(val & MASK_28, 4, U32V_4(val));
      CHECK_UINT32V_INLINE(val, 5, U32V_5(val));
    }
  }
}

TEST_F(DecoderTest, ReadI32v_OneByte) {
  CHECK_INT32V_INLINE(0, 1, 0);
  CHECK_INT32V_INLINE(4, 1, 4);
  CHECK_INT32V_INLINE(6, 1, 6);
  CHECK_INT32V_INLINE(9, 1, 9);
  CHECK_INT32V_INLINE(33, 1, 33);
  CHECK_INT32V_INLINE(61, 1, 61);
  CHECK_INT32V_INLINE(63, 1, 63);

  CHECK_INT32V_INLINE(-1, 1, 127);
  CHECK_INT32V_INLINE(-2, 1, 126);
  CHECK_INT32V_INLINE(-11, 1, 117);
  CHECK_INT32V_INLINE(-62, 1, 66);
  CHECK_INT32V_INLINE(-63, 1, 65);
  CHECK_INT32V_INLINE(-64, 1, 64);
}

TEST_F(DecoderTest, ReadI32v_TwoByte) {
  CHECK_INT32V_INLINE(0, 2, U32V_2(0));
  CHECK_INT32V_INLINE(9, 2, U32V_2(9));
  CHECK_INT32V_INLINE(61, 2, U32V_2(61));
  CHECK_INT32V_INLINE(63, 2, U32V_2(63));

  CHECK_INT32V_INLINE(-1, 2, U32V_2(-1));
  CHECK_INT32V_INLINE(-2, 2, U32V_2(-2));
  CHECK_INT32V_INLINE(-63, 2, U32V_2(-63));
  CHECK_INT32V_INLINE(-64, 2, U32V_2(-64));

  CHECK_INT32V_INLINE(-200, 2, U32V_2(-200));
  CHECK_INT32V_INLINE(-1002, 2, U32V_2(-1002));
  CHECK_INT32V_INLINE(-2004, 2, U32V_2(-2004));
  CHECK_INT32V_INLINE(-4077, 2, U32V_2(-4077));

  CHECK_INT32V_INLINE(207, 2, U32V_2(207));
  CHECK_INT32V_INLINE(1009, 2, U32V_2(1009));
  CHECK_INT32V_INLINE(2003, 2, U32V_2(2003));
  CHECK_INT32V_INLINE(4072, 2, U32V_2(4072));

  const int32_t min = 0 - (1 << 13);
  for (int i = min; i < min + 10; i++) {
    CHECK_INT32V_INLINE(i, 2, U32V_2(i));
  }

  const int32_t max = (1 << 13) - 1;
  for (int i = max; i > max - 10; i--) {
    CHECK_INT32V_INLINE(i, 2, U32V_2(i));
  }
}

TEST_F(DecoderTest, ReadI32v_ThreeByte) {
  CHECK_INT32V_INLINE(0, 3, U32V_3(0));
  CHECK_INT32V_INLINE(9, 3, U32V_3(9));
  CHECK_INT32V_INLINE(61, 3, U32V_3(61));
  CHECK_INT32V_INLINE(63, 3, U32V_3(63));

  CHECK_INT32V_INLINE(-1, 3, U32V_3(-1));
  CHECK_INT32V_INLINE(-2, 3, U32V_3(-2));
  CHECK_INT32V_INLINE(-63, 3, U32V_3(-63));
  CHECK_INT32V_INLINE(-64, 3, U32V_3(-64));

  CHECK_INT32V_INLINE(-207, 3, U32V_3(-207));
  CHECK_INT32V_INLINE(-1012, 3, U32V_3(-1012));
  CHECK_INT32V_INLINE(-4067, 3, U32V_3(-4067));
  CHECK_INT32V_INLINE(-14067, 3, U32V_3(-14067));
  CHECK_INT32V_INLINE(-234061, 3, U32V_3(-234061));

  CHECK_INT32V_INLINE(237, 3, U32V_3(237));
  CHECK_INT32V_INLINE(1309, 3, U32V_3(1309));
  CHECK_INT32V_INLINE(4372, 3, U32V_3(4372));
  CHECK_INT32V_INLINE(64372, 3, U32V_3(64372));
  CHECK_INT32V_INLINE(374372, 3, U32V_3(374372));

  const int32_t min = 0 - (1 << 20);
  for (int i = min; i < min + 10; i++) {
    CHECK_INT32V_INLINE(i, 3, U32V_3(i));
  }

  const int32_t max = (1 << 20) - 1;
  for (int i = max; i > max - 10; i--) {
    CHECK_INT32V_INLINE(i, 3, U32V_3(i));
  }
}

TEST_F(DecoderTest, ReadI32v_FourByte) {
  CHECK_INT32V_INLINE(0, 4, U32V_4(0));
  CHECK_INT32V_INLINE(9, 4, U32V_4(9));
  CHECK_INT32V_INLINE(61, 4, U32V_4(61));
  CHECK_INT32V_INLINE(63, 4, U32V_4(63));

  CHECK_INT32V_INLINE(-1, 4, U32V_4(-1));
  CHECK_INT32V_INLINE(-2, 4, U32V_4(-2));
  CHECK_INT32V_INLINE(-63, 4, U32V_4(-63));
  CHECK_INT32V_INLINE(-64, 4, U32V_4(-64));

  CHECK_INT32V_INLINE(-267, 4, U32V_4(-267));
  CHECK_INT32V_INLINE(-1612, 4, U32V_4(-1612));
  CHECK_INT32V_INLINE(-4667, 4, U32V_4(-4667));
  CHECK_INT32V_INLINE(-16067, 4, U32V_4(-16067));
  CHECK_INT32V_INLINE(-264061, 4, U32V_4(-264061));
  CHECK_INT32V_INLINE(-1264061, 4, U32V_4(-1264061));
  CHECK_INT32V_INLINE(-6264061, 4, U32V_4(-6264061));
  CHECK_INT32V_INLINE(-8264061, 4, U32V_4(-8264061));

  CHECK_INT32V_INLINE(277, 4, U32V_4(277));
  CHECK_INT32V_INLINE(1709, 4, U32V_4(1709));
  CHECK_INT32V_INLINE(4772, 4, U32V_4(4772));
  CHECK_INT32V_INLINE(67372, 4, U32V_4(67372));
  CHECK_INT32V_INLINE(374372, 4, U32V_4(374372));
  CHECK_INT32V_INLINE(2374372, 4, U32V_4(2374372));
  CHECK_INT32V_INLINE(7374372, 4, U32V_4(7374372));
  CHECK_INT32V_INLINE(9374372, 4, U32V_4(9374372));

  const int32_t min = 0 - (1 << 27);
  for (int i = min; i < min + 10; i++) {
    CHECK_INT32V_INLINE(i, 4, U32V_4(i));
  }

  const int32_t max = (1 << 27) - 1;
  for (int i = max; i > max - 10; i--) {
    CHECK_INT32V_INLINE(i, 4, U32V_4(i));
  }
}

TEST_F(DecoderTest, ReadI32v_FiveByte) {
  CHECK_INT32V_INLINE(0, 5, U32V_5(0));
  CHECK_INT32V_INLINE(16, 5, U32V_5(16));
  CHECK_INT32V_INLINE(94, 5, U32V_5(94));
  CHECK_INT32V_INLINE(127, 5, U32V_5(127));

  CHECK_INT32V_INLINE(-1, 5, U32V_5(-1));
  CHECK_INT32V_INLINE(-2, 5, U32V_5(-2));
  CHECK_INT32V_INLINE(-63, 5, U32V_5(-63));
  CHECK_INT32V_INLINE(-64, 5, U32V_5(-64));

  CHECK_INT32V_INLINE(-257, 5, U32V_5(-257));
  CHECK_INT32V_INLINE(-1512, 5, U32V_5(-1512));
  CHECK_INT32V_INLINE(-4567, 5, U32V_5(-4567));
  CHECK_INT32V_INLINE(-15067, 5, U32V_5(-15067));
  CHECK_INT32V_INLINE(-254061, 5, U32V_5(-254061));
  CHECK_INT32V_INLINE(-1364061, 5, U32V_5(-1364061));
  CHECK_INT32V_INLINE(-6364061, 5, U32V_5(-6364061));
  CHECK_INT32V_INLINE(-8364061, 5, U32V_5(-8364061));
  CHECK_INT32V_INLINE(-28364061, 5, U32V_5(-28364061));
  CHECK_INT32V_INLINE(-228364061, 5, U32V_5(-228364061));

  CHECK_INT32V_INLINE(227, 5, U32V_5(227));
  CHECK_INT32V_INLINE(1209, 5, U32V_5(1209));
  CHECK_INT32V_INLINE(4272, 5, U32V_5(4272));
  CHECK_INT32V_INLINE(62372, 5, U32V_5(62372));
  CHECK_INT32V_INLINE(324372, 5, U32V_5(324372));
  CHECK_INT32V_INLINE(2274372, 5, U32V_5(2274372));
  CHECK_INT32V_INLINE(7274372, 5, U32V_5(7274372));
  CHECK_INT32V_INLINE(9274372, 5, U32V_5(9274372));
  CHECK_INT32V_INLINE(42374372, 5, U32V_5(42374372));
  CHECK_INT32V_INLINE(429374372, 5, U32V_5(429374372));

  const int32_t min = kMinInt;
  for (int i = min; i < min + 10; i++) {
    CHECK_INT32V_INLINE(i, 5, U32V_5(i));
  }

  const int32_t max = kMaxInt;
  for (int i = max; i > max - 10; i--) {
    CHECK_INT32V_INLINE(i, 5, U32V_5(i));
  }
}

TEST_F(DecoderTest, ReadU32v_off_end1) {
  static const uint8_t data[] = {U32V_1(11)};
  decoder.Reset(data, data);
  decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());
  EXPECT_FALSE(decoder.ok());
}

TEST_F(DecoderTest, ReadU32v_off_end2) {
  static const uint8_t data[] = {U32V_2(1111)};
  for (size_t i = 0; i < sizeof(data); i++) {
    decoder.Reset(data, data + i);
    decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());
    EXPECT_FALSE(decoder.ok());
  }
}

TEST_F(DecoderTest, ReadU32v_off_end3) {
  static const uint8_t data[] = {U32V_3(111111)};
  for (size_t i = 0; i < sizeof(data); i++) {
    decoder.Reset(data, data + i);
    decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());
    EXPECT_FALSE(decoder.ok());
  }
}

TEST_F(DecoderTest, ReadU32v_off_end4) {
  static const uint8_t data[] = {U32V_4(11111111)};
  for (size_t i = 0; i < sizeof(data); i++) {
    decoder.Reset(data, data + i);
    decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());
    EXPECT_FALSE(decoder.ok());
  }
}

TEST_F(DecoderTest, ReadU32v_off_end5) {
  static const uint8_t data[] = {U32V_5(111111111)};
  for (size_t i = 0; i < sizeof(data); i++) {
    decoder.Reset(data, data + i);
    decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());
    EXPECT_FALSE(decoder.ok());
  }
}

TEST_F(DecoderTest, ReadU32v_extra_bits) {
  uint8_t data[] = {0x80, 0x80, 0x80, 0x80, 0x00};
  for (int i = 1; i < 16; i++) {
    data[4] = static_cast<uint8_t>(i << 4);
    decoder.Reset(data, data + sizeof(data));
    decoder.read_u32v<Decoder::FullValidationTag>(decoder.start());
    EXPECT_FALSE(decoder.ok());
  }
}

TEST_F(DecoderTest, ReadI32v_extra_bits_negative) {
  // OK for negative signed values to have extra ones.
  uint8_t data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
  decoder.Reset(data, data + sizeof(data));
  auto [result, length] =
      decoder.read_i32v<Decoder::FullValidationTag>(decoder.start());
  EXPECT_EQ(5u, length);
  EXPECT_TRUE(decoder.ok());
}

TEST_F(DecoderTest, ReadI32v_extra_bits_positive) {
  // Not OK for positive signed values to have extra ones.
  uint8_t data[] = {0x80, 0x80, 0x80, 0x80, 0x77};
  decoder.Reset(data, data + sizeof(data));
  decoder.read_i32v<Decoder::FullValidationTag>(decoder.start());
  EXPECT_FALSE(decoder.ok());
}

TEST_F(DecoderTest, ReadU32v_Bits) {
  // A more exhaustive test.
  const int kMaxSize = 5;
  const uint32_t kVals[] = {
      0xAABBCCDD, 0x11223344, 0x33445566, 0xFFEEDDCC, 0xF0F0F0F0, 0x0F0F0F0F,
      0xEEEEEEEE, 0xAAAAAAAA, 0x12345678, 0x9ABCDEF0, 0x80309488, 0x729ED997,
      0xC4A0CF81, 0x16C6EB85, 0x4206DB8E, 0xF3B089D5, 0xAA2E223E, 0xF99E29C8,
      0x4A4357D8, 0x1890B1C1, 0x8D80A085, 0xACB6AE4C, 0x1B827E10, 0xEB5C7BD9,
      0xBB1BC146, 0xDF57A33l};
  uint8_t data[kMaxSize];

  // foreach value in above array
  for (size_t v = 0; v < arraysize(kVals); v++) {
    // foreach length 1...32
    for (int i = 1; i <= 32; i++) {
      uint32_t val = kVals[v];
      if (i < 32)
        val &= base::SubWithWraparound(base::ShlWithWraparound(1, i), 1);

      unsigned length = 1 + i / 7;
      for (unsigned j = 0; j < kMaxSize; j++) {
        data[j] = static_cast<uint8_t>((val >> (7 * j)) & MASK_7);
      }
      for (unsigned j = 0; j < length - 1; j++) {
        data[j] |= 0x80;
      }

      // foreach buffer size 0...5
      for (unsigned limit = 0; limit <= kMaxSize; limit++) {
        decoder.Reset(data, data + limit);
        auto [result, rlen] =
            decoder.read_u32v<Decoder::FullValidationTag>(data);
        if (limit < length) {
          EXPECT_FALSE(decoder.ok());
        } else {
          EXPECT_TRUE(decoder.ok());
          EXPECT_EQ(val, result);
          EXPECT_EQ(length, rlen);
        }
      }
    }
  }
}

TEST_F(DecoderTest, ReadU64v_OneByte) {
  CHECK_UINT64V_INLINE(0, 1, 0);
  CHECK_UINT64V_INLINE(6, 1, 6);
  CHECK_UINT64V_INLINE(8, 1, 8);
  CHECK_UINT64V_INLINE(12, 1, 12);
  CHECK_UINT64V_INLINE(33, 1, 33);
  CHECK_UINT64V_INLINE(59, 1, 59);
  CHECK_UINT64V_INLINE(110, 1, 110);
  CHECK_UINT64V_INLINE(125, 1, 125);
  CHECK_UINT64V_INLINE(126, 1, 126);
  CHECK_UINT64V_INLINE(127, 1, 127);
}

TEST_F(DecoderTest, ReadI64v_OneByte) {
  CHECK_INT64V_INLINE(0, 1, 0);
  CHECK_INT64V_INLINE(4, 1, 4);
  CHECK_INT64V_INLINE(6, 1, 6);
  CHECK_INT64V_INLINE(9, 1, 9);
  CHECK_INT64V_INLINE(33, 1, 33);
  CHECK_INT64V_INLINE(61, 1, 61);
  CHECK_INT64V_INLINE(63, 1, 63);

  CHECK_INT64V_INLINE(-1, 1, 127);
  CHECK_INT64V_INLINE(-2, 1, 126);
  CHECK_INT64V_INLINE(-11, 1, 117);
  CHECK_INT64V_INLINE(-62, 1, 66);
  CHECK_INT64V_INLINE(-63, 1, 65);
  CHECK_INT64V_INLINE(-64, 1, 64);
}

TEST_F(DecoderTest, ReadU64v_PowerOf2) {
  const int kMaxSize = 10;
  uint8_t data[kMaxSize];

  for (unsigned i = 0; i < 64; i++) {
    const uint64_t val = 1ull << i;
    unsigned index = i / 7;
    data[index] = 1 << (i % 7);
    memset(data, 0x80, index);

    for (unsigned limit = 0; limit <= kMaxSize; limit++) {
      decoder.Reset(data, data + limit);
      auto [result, length] =
          decoder.read_u64v<Decoder::FullValidationTag>(data);
      if (limit <= index) {
        EXPECT_FALSE(decoder.ok());
      } else {
        EXPECT_TRUE(decoder.ok());
        EXPECT_EQ(val, result);
        EXPECT_EQ(index + 1, length);
      }
    }
  }
}

TEST_F(DecoderTest, ReadU64v_Bits) {
  const int kMaxSize = 10;
  const uint64_t kVals[] = {
      0xAABBCCDD11223344ull, 0x33445566FFEEDDCCull, 0xF0F0F0F0F0F0F0F0ull,
      0x0F0F0F0F0F0F0F0Full, 0xEEEEEEEEEEEEEEEEull, 0xAAAAAAAAAAAAAAAAull,
      0x123456789ABCDEF0ull, 0x80309488729ED997ull, 0xC4A0CF8116C6EB85ull,
      0x4206DB8EF3B089D5ull, 0xAA2E223EF99E29C8ull, 0x4A4357D81890B1C1ull,
      0x8D80A085ACB6AE4Cull, 0x1B827E10EB5C7BD9ull, 0xBB1BC146DF57A338ull};
  uint8_t data[kMaxSize];

  // foreach value in above array
  for (size_t v = 0; v < arraysize(kVals); v++) {
    // foreach length 1...64
    for (int i = 1; i <= 64; i++) {
      uint64_t val = kVals[v];
      if (i < 64) val &= ((1ull << i) - 1);

      unsigned length = 1 + i / 7;
      for (unsigned j = 0; j < kMaxSize; j++) {
        data[j] = static_cast<uint8_t>((val >> (7 * j)) & MASK_7);
      }
      for (unsigned j = 0; j < length - 1; j++) {
        data[j] |= 0x80;
      }

      // foreach buffer size 0...10
      for (unsigned limit = 0; limit <= kMaxSize; limit++) {
        decoder.Reset(data, data + limit);
        auto [result, rlen] =
            decoder.read_u64v<Decoder::FullValidationTag>(data);
        if (limit < length) {
          EXPECT_FALSE(decoder.ok());
        } else {
          EXPECT_TRUE(decoder.ok());
          EXPECT_EQ(val, result);
          EXPECT_EQ(length, rlen);
        }
      }
    }
  }
}

TEST_F(DecoderTest, ReadI64v_Bits) {
  const int kMaxSize = 10;
  // Exhaustive signedness test.
  const uint64_t kVals[] = {
      0xAABBCCDD11223344ull, 0x33445566FFEEDDCCull, 0xF0F0F0F0F0F0F0F0ull,
      0x0F0F0F0F0F0F0F0Full, 0xEEEEEEEEEEEEEEEEull, 0xAAAAAAAAAAAAAAAAull,
      0x123456789ABCDEF0ull, 0x80309488729ED997ull, 0xC4A0CF8116C6EB85ull,
      0x4206DB8EF3B089D5ull, 0xAA2E223EF99E29C8ull, 0x4A4357D81890B1C1ull,
      0x8D80A085ACB6AE4Cull, 0x1B827E10EB5C7BD9ull, 0xBB1BC146DF57A338ull};
  uint8_t data[kMaxSize];

  // foreach value in above array
  for (size_t v = 0; v < arraysize(kVals); v++) {
    // foreach length 1...64
    for (int i = 1; i <= 64; i++) {
      const int64_t val =
          base::bit_cast<int64_t>(kVals[v] << (64 - i)) >> (64 - i);

      unsigned length = 1 + i / 7;
      for (unsigned j = 0; j < kMaxSize; j++) {
        data[j] = static_cast<uint8_t>((val >> (7 * j)) & MASK_7);
      }
      for (unsigned j = 0; j < length - 1; j++) {
        data[j] |= 0x80;
      }

      // foreach buffer size 0...10
      for (unsigned limit = 0; limit <= kMaxSize; limit++) {
        decoder.Reset(data, data + limit);
        auto [result, rlen] =
            decoder.read_i64v<Decoder::FullValidationTag>(data);
        if (limit < length) {
          EXPECT_FALSE(decoder.ok());
        } else {
          EXPECT_TRUE(decoder.ok());
          EXPECT_EQ(val, result);
          EXPECT_EQ(length, rlen);
        }
      }
    }
  }
}

TEST_F(DecoderTest, ReadU64v_extra_bits) {
  uint8_t data[] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00};
  for (int i = 1; i < 128; i++) {
    data[9] = static_cast<uint8_t>(i << 1);
    decoder.Reset(data, data + sizeof(data));
    decoder.read_u64v<Decoder::FullValidationTag>(decoder.start());
    EXPECT_FALSE(decoder.ok());
  }
}

TEST_F(DecoderTest, ReadI64v_extra_bits_negative) {
  // OK for negative signed values to have extra ones.
  uint8_t data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
  decoder.Reset(data, data + sizeof(data));
  auto [result, length] =
      decoder.read_i64v<Decoder::FullValidationTag>(decoder.start());
  EXPECT_EQ(10u, length);
  EXPECT_TRUE(decoder.ok());
}

TEST_F(DecoderTest, ReadI64v_extra_bits_positive) {
  // Not OK for positive signed values to have extra ones.
  uint8_t data[] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x77};
  decoder.Reset(data, data + sizeof(data));
  decoder.read_i64v<Decoder::FullValidationTag>(decoder.start());
  EXPECT_FALSE(decoder.ok());
}

TEST_F(DecoderTest, FailOnNullData) {
  decoder.Reset(nullptr, nullptr);
  decoder.checkAvailable(1);
  EXPECT_FALSE(decoder.ok());
  EXPECT_FALSE(decoder.toResult(nullptr).ok());
}

#undef CHECK_UINT32V_INLINE
#undef CHECK_INT32V_INLINE
#undef CHECK_UINT64V_INLINE
#undef CHECK_INT64V_INLINE

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```