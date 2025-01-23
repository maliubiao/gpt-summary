Response:
Let's break down the thought process for analyzing the `decoder.h` file.

1. **Understand the Goal:** The request asks for a functional summary of the C++ header file, explanations using JavaScript examples where applicable, and discussions of potential programming errors.

2. **Initial Scan and Keyword Spotting:**  Read through the file, looking for key terms and patterns. Immediately, these stand out:
    * `WebAssembly` (multiple times): This confirms the file's context.
    * `Decoder`: This is the central class, so its purpose is crucial.
    * `read_`, `consume_`: These suggest methods for data extraction.
    * `LEB128`, `varint`:  These indicate specific encoding schemes.
    * `ValidationTag`:  Highlights different levels of input checking.
    * `ITracer`:  Suggests a debugging or logging mechanism.
    * `error`, `errorf`: Indicate error handling.

3. **High-Level Functionality Deduction:** Based on the keywords, it's clear this file defines a `Decoder` class responsible for parsing WebAssembly binary data. It reads various data types (integers, bytes) and handles variable-length encoding (LEB128). The presence of validation options suggests a concern for malformed WebAssembly.

4. **Deconstruct the `Decoder` Class:**  Go through the `Decoder` class member by member:
    * **Constructors:**  Note the different ways to initialize a `Decoder` (from raw pointers, vectors).
    * **`read_` methods:** Focus on what data types they handle (u8, u16, u32, u64, variable-length integers). Notice the `ValidationTag` template parameter.
    * **`consume_` methods:**  Similar to `read_`, but they also advance the internal pointer (`pc_`). Pay attention to the `ITracer` usage here.
    * **`read_prefixed_opcode`:**  Recognize this as specific to WebAssembly's instruction format.
    * **`consume_bytes`:**  A simple method for skipping data.
    * **`available_bytes`, `checkAvailable`:**  Methods for managing the remaining data.
    * **`error`, `errorf`, `onFirstError`:**  The error reporting and handling mechanism.
    * **`traceByteRange`, `traceOffEnd`:** Debugging utilities.
    * **`toResult`:**  A helper for converting decoding outcomes into a `Result` type (indicating success or failure).
    * **`Reset`:**  Allows reusing the `Decoder` instance.
    * **`ok`, `failed`, `more`, `error`:**  Status accessors.
    * **`start`, `pc`, `position`, `pc_offset`, `buffer_offset`, `GetBufferRelativeOffset`, `end`, `set_end`:** Accessors for internal state, crucial for tracking the parsing progress.
    * **`lookahead`:**  A utility for peeking at the next bytes without consuming them.
    * **Private members:** Understand their roles (`start_`, `pc_`, `end_`, `buffer_offset_`, `error_`).
    * **`verrorf`:** The core formatting function for errors.
    * **`read_little_endian`:** The underlying function for reading fixed-size integers.
    * **`consume_little_endian`:** The underlying function for consuming fixed-size integers.
    * **`read_leb` and its related helper functions (`read_leb_slowpath`, `read_leb_tail`):** These are the core of variable-length integer decoding. The template metaprogramming here is important to note.

5. **Analyze `ITracer`:** Understand its role as an interface for tracing/logging the decoding process. List the methods and their purpose (tracking offsets, dumping bytes, describing elements).

6. **Address the Specific Questions:**
    * **Functionality:** Summarize the findings from the previous steps.
    * **`.tq` extension:** State that this file is `.h`, not `.tq`, so it's standard C++ and not Torque.
    * **Relationship to JavaScript:**  Connect the `Decoder` to the underlying process when JavaScript runs WebAssembly. Crucially, explain that the *binary format* is being decoded, not the JavaScript API. Provide a JavaScript example of *using* WebAssembly to illustrate the context, even though the `decoder.h` isn't directly writing JavaScript.
    * **Code Logic/Reasoning:** Focus on the LEB128 decoding. Explain the process with a simple example, including the input bytes and the decoded value. Clearly state the assumptions (little-endian, continuation bit).
    * **Common Programming Errors:** Think about mistakes developers might make when *generating* or *handling* WebAssembly, rather than *using* the `Decoder` directly. Focus on validation issues (incorrect sizes, malformed LEB128).

7. **Refine and Organize:** Structure the answer logically with clear headings and bullet points. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Double-check for accuracy and completeness. For example, initially, I might have focused too much on the low-level bit manipulation of LEB128. Refining would involve making sure the explanation is accessible and highlights the *purpose* rather than getting bogged down in implementation details. Similarly, clarifying the distinction between *decoding the binary* and *interacting with the JS API* is important.

8. **Self-Correction Example During the Process:**  Initially, I might have thought about providing C++ code examples of *using* the `Decoder`. However, the request specifically asks for *JavaScript* examples if there's a relationship. Realizing that the `Decoder` is internal V8 code not directly exposed to JavaScript, the better approach is to show how WebAssembly is used *from* JavaScript to provide the necessary context. This demonstrates understanding the user's perspective and providing relevant information.
好的，让我们来分析一下 `v8/src/wasm/decoder.h` 这个文件。

**功能概要**

`v8/src/wasm/decoder.h` 文件定义了用于解码 WebAssembly 字节码的 `Decoder` 类以及相关的辅助结构体和宏。它的主要功能是：

1. **读取和解析 WebAssembly 字节流:**  `Decoder` 类提供了各种方法来从字节流中读取不同类型的数据，包括固定大小的整数（8位、16位、32位、64位）和变长整数 (LEB128 编码)。
2. **处理 WebAssembly 特定的编码:**  它支持读取 LEB128 格式的无符号和有符号整数，这是 WebAssembly 中常用的编码方式。
3. **提供错误处理机制:**  `Decoder` 类可以检测并报告解码过程中遇到的错误，例如超出边界或格式不正确。它使用 `WasmError` 结构体来存储错误信息。
4. **支持不同的验证级别:**  通过 `ValidationTag` 模板参数，`Decoder` 可以选择是否进行严格的输入验证，这在开发和生产环境中可以有不同的需求。
5. **提供跟踪和调试功能:**  通过 `TRACE` 和 `TRACE_IF` 宏，以及 `ITracer` 接口，可以方便地跟踪解码过程，输出调试信息。
6. **管理解码器的状态:**  `Decoder` 类维护了当前读取位置 (`pc_`)、起始位置 (`start_`)、结束位置 (`end_`) 等信息。
7. **支持前缀操作码:**  能够解析带有前缀字节的操作码，这是 WebAssembly 扩展指令的一种方式。

**关于文件扩展名和 Torque**

你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。`v8/src/wasm/decoder.h` 文件以 `.h` 结尾，因此**它是一个标准的 C++ 头文件，而不是 Torque 文件**。Torque 文件通常用于定义 V8 内部的内置函数和类型。

**与 JavaScript 的关系**

`v8/src/wasm/decoder.h` 中的代码是 V8 引擎实现 WebAssembly 支持的关键部分。当 JavaScript 代码加载和编译 WebAssembly 模块时，V8 会使用这里的 `Decoder` 类来解析 WebAssembly 模块的二进制格式。

**JavaScript 示例**

以下 JavaScript 示例展示了如何加载和使用 WebAssembly 模块，这会间接地触发 V8 内部的解码过程：

```javascript
async function loadWasm() {
  try {
    const response = await fetch('my_wasm_module.wasm'); // 假设有一个名为 my_wasm_module.wasm 的 WebAssembly 文件
    const buffer = await response.arrayBuffer();
    const module = await WebAssembly.instantiate(buffer);
    console.log("WebAssembly 模块加载成功:", module.instance.exports.add(5, 3)); // 假设导出一个 add 函数
  } catch (error) {
    console.error("加载 WebAssembly 模块失败:", error);
  }
}

loadWasm();
```

在这个例子中，`WebAssembly.instantiate(buffer)` 函数接收一个包含 WebAssembly 字节码的 `ArrayBuffer`。V8 引擎内部会使用 `decoder.h` 中定义的类来解析这个字节码，验证其结构，并将其转换为可执行的代码。

**代码逻辑推理**

让我们关注 `read_leb` 函数，它用于读取 LEB128 编码的整数。

**假设输入:** 一个字节数组 `[0x85, 0x02]` (表示十进制的 133)

**解码过程 (简化):**

1. `read_leb` 函数读取第一个字节 `0x85`。
2. 检查最高位是否为 1 (即 `0x80`)。因为 `0x85 & 0x80` 不为零，表示这不是最后一个字节，需要继续读取。
3. 将当前字节的低 7 位取出 (`0x85 & 0x7F` 得到 `0x05`)。
4. 读取下一个字节 `0x02`。
5. 检查最高位是否为 1。因为 `0x02 & 0x80` 为零，表示这是最后一个字节。
6. 将当前字节的值 `0x02` 左移 7 位 (`0x02 << 7` 得到 `0x100`，即十进制的 256)。
7. 将之前取出的低 7 位与左移后的值相加 (`0x05 + 0x100` 得到 `0x105`，即十进制的 261)。  *更正: 应该是 `0x05 | (0x02 << 7)`，即 `5 | 256 = 261`*
8. 返回解码后的值 261 以及读取的字节数 2。

**输出:**  解码后的值为 261，读取了 2 个字节。

**更正:**  我的描述中存在一个计算错误。LEB128 的计算方式是，每个字节的低 7 位构成数值的一部分，后续字节的低 7 位需要左移 7 的倍数。

对于输入 `[0x85, 0x02]`：

1. 第一个字节 `0x85`: 低 7 位是 `0x05` (5)。最高位为 1，表示还有后续字节。
2. 第二个字节 `0x02`: 低 7 位是 `0x02` (2)。最高位为 0，表示是最后一个字节。
3. 计算结果: `(0x02 << 7) | 0x05` = `(2 * 128) + 5` = `256 + 5` = `261`。

**用户常见的编程错误**

虽然用户通常不会直接操作 `decoder.h` 中的类，但在编写生成 WebAssembly 字节码的工具时，可能会犯以下错误，这些错误会被 V8 的解码器检测到：

1. **LEB128 编码错误:**
   - **过早终止:** LEB128 编码的非最后一个字节的最高位必须为 1。如果中间某个字节的最高位为 0，解码器会报错。
     ```
     // 错误示例：本应是多字节的 LEB128 数值，但中间字节最高位为 0
     const buffer = new Uint8Array([0x85, 0x00]); // 0x00 的最高位为 0，如果预期还有后续字节则错误
     ```
   - **溢出:**  对于有符号 LEB128，需要正确进行符号扩展。如果编码不正确导致解码后的值超出预期范围，可能会导致错误。
   - **超长编码:**  虽然 LEB128 可以表示很大的数字，但 WebAssembly 规范对某些类型的数值有大小限制。如果编码的数值超过这些限制，解码器会报错。

2. **节 (Section) 结构错误:** WebAssembly 模块由多个节组成，每个节有特定的 ID 和大小。
   - **错误的节 ID:**  使用了未定义的节 ID。
   - **错误的节大小:**  声明的节大小与实际内容不符。

3. **指令编码错误:**
   - **无效的操作码:**  使用了 WebAssembly 规范中不存在的操作码。
   - **操作数类型不匹配:**  指令的操作数类型与预期不符。
   - **操作数数量错误:**  指令需要的操作数数量与实际提供的数量不符。

4. **类型定义错误:**
   - **无效的类型签名:** 函数类型、全局变量类型等定义不符合规范。

**示例：错误的 LEB128 编码**

假设一个生成 WebAssembly 的工具错误地将数字 `133` (二进制 `10000101`) 编码为 `[0x05, 0x01]` 而不是正确的 `[0x85, 0x01]`。

```javascript
const invalidLEB128 = new Uint8Array([0x05, 0x01]);

WebAssembly.instantiate(invalidLEB128).catch(error => {
  console.error("加载失败，因为 LEB128 编码错误:", error);
  // V8 的解码器会检测到 0x05 的最高位为 0，认为编码过早结束
});
```

在这个例子中，`0x05` 的最高位是 0，解码器会认为这是 LEB128 编码的结束，解码出的值是 5。但如果上下文中期望的是更大的值，或者这是一个多字节数值的中间部分，则会产生错误。V8 的解码器会抛出异常，指示 WebAssembly 模块格式不正确。

总结来说，`v8/src/wasm/decoder.h` 定义了 V8 引擎中用于解析 WebAssembly 字节码的关键组件，它负责读取、验证和转换二进制数据，使得 JavaScript 引擎能够理解和执行 WebAssembly 代码。理解这个文件的功能有助于深入了解 WebAssembly 在 V8 中的实现原理。

### 提示词
```
这是目录为v8/src/wasm/decoder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/decoder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_DECODER_H_
#define V8_WASM_DECODER_H_

#include <cinttypes>
#include <cstdarg>
#include <memory>

#include "src/base/compiler-specific.h"
#include "src/base/memory.h"
#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/flags/flags.h"
#include "src/utils/utils.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-result.h"

namespace v8 {
namespace internal {
namespace wasm {

#define TRACE(...)                                        \
  do {                                                    \
    if (v8_flags.trace_wasm_decoder) PrintF(__VA_ARGS__); \
  } while (false)
#define TRACE_IF(cond, ...)                                         \
  do {                                                              \
    if (v8_flags.trace_wasm_decoder && (cond)) PrintF(__VA_ARGS__); \
  } while (false)

// A {DecodeResult} only stores the failure / success status, but no data.
using DecodeResult = VoidResult;

struct WasmFunction;

class ITracer {
 public:
  static constexpr ITracer* NoTrace = nullptr;

  // Hooks for extracting byte offsets of things.
  virtual void TypeOffset(uint32_t offset) = 0;
  virtual void ImportOffset(uint32_t offset) = 0;
  virtual void ImportsDone(const WasmModule* module) = 0;
  virtual void TableOffset(uint32_t offset) = 0;
  virtual void MemoryOffset(uint32_t offset) = 0;
  virtual void TagOffset(uint32_t offset) = 0;
  virtual void GlobalOffset(uint32_t offset) = 0;
  virtual void StartOffset(uint32_t offset) = 0;
  virtual void ElementOffset(uint32_t offset) = 0;
  virtual void DataOffset(uint32_t offset) = 0;
  virtual void StringOffset(uint32_t offset) = 0;
  virtual void RecGroupOffset(uint32_t offset, uint32_t group_size) = 0;

  // Hooks for annotated hex dumps.
  virtual void Bytes(const uint8_t* start, uint32_t count) = 0;

  virtual void Description(const char* desc) = 0;
  virtual void Description(const char* desc, size_t length) = 0;
  virtual void Description(uint32_t number) = 0;
  virtual void Description(uint64_t number) = 0;
  virtual void Description(ValueType type) = 0;
  virtual void Description(HeapType type) = 0;
  virtual void Description(const FunctionSig* sig) = 0;

  virtual void NextLine() = 0;
  virtual void NextLineIfFull() = 0;
  virtual void NextLineIfNonEmpty() = 0;

  virtual void InitializerExpression(const uint8_t* start, const uint8_t* end,
                                     ValueType expected_type) = 0;
  virtual void FunctionBody(const WasmFunction* func, const uint8_t* start) = 0;
  virtual void FunctionName(uint32_t func_index) = 0;
  virtual void NameSection(const uint8_t* start, const uint8_t* end,
                           uint32_t offset) = 0;

  virtual ~ITracer() = default;
};

// A helper utility to decode bytes, integers, fields, varints, etc, from
// a buffer of bytes.
class Decoder {
 public:
  // Don't run validation, assume valid input.
  static constexpr struct NoValidationTag {
    static constexpr bool validate = false;
  } kNoValidation = {};
  // Run full validation with error message and location.
  static constexpr struct FullValidationTag {
    static constexpr bool validate = true;
  } kFullValidation = {};

  struct NoName {
    constexpr NoName(const char*) {}
    operator const char*() const { UNREACHABLE(); }
  };
  // Pass a {NoName} if we know statically that we do not use it anyway (we are
  // not tracing (in release mode) and not running full validation).
#ifdef DEBUG
  template <typename ValidationTag>
  using Name = const char*;
#else
  template <typename ValidationTag>
  using Name = std::conditional_t<ValidationTag::validate, const char*, NoName>;
#endif

  enum TraceFlag : bool { kTrace = true, kNoTrace = false };

  Decoder(const uint8_t* start, const uint8_t* end, uint32_t buffer_offset = 0)
      : Decoder(start, start, end, buffer_offset) {}
  explicit Decoder(const base::Vector<const uint8_t> bytes,
                   uint32_t buffer_offset = 0)
      : Decoder(bytes.begin(), bytes.begin() + bytes.length(), buffer_offset) {}
  Decoder(const uint8_t* start, const uint8_t* pc, const uint8_t* end,
          uint32_t buffer_offset = 0)
      : start_(start), pc_(pc), end_(end), buffer_offset_(buffer_offset) {
    DCHECK_LE(start, pc);
    DCHECK_LE(pc, end);
    DCHECK_EQ(static_cast<uint32_t>(end - start), end - start);
  }

  virtual ~Decoder() = default;

  // Reads an 8-bit unsigned integer.
  template <typename ValidationTag>
  uint8_t read_u8(const uint8_t* pc,
                  Name<ValidationTag> msg = "expected 1 byte") {
    return read_little_endian<uint8_t, ValidationTag>(pc, msg);
  }

  // Reads a 16-bit unsigned integer (little endian).
  template <typename ValidationTag>
  uint16_t read_u16(const uint8_t* pc,
                    Name<ValidationTag> msg = "expected 2 bytes") {
    return read_little_endian<uint16_t, ValidationTag>(pc, msg);
  }

  // Reads a 32-bit unsigned integer (little endian).
  template <typename ValidationTag>
  uint32_t read_u32(const uint8_t* pc,
                    Name<ValidationTag> msg = "expected 4 bytes") {
    return read_little_endian<uint32_t, ValidationTag>(pc, msg);
  }

  // Reads a 64-bit unsigned integer (little endian).
  template <typename ValidationTag>
  uint64_t read_u64(const uint8_t* pc,
                    Name<ValidationTag> msg = "expected 8 bytes") {
    return read_little_endian<uint64_t, ValidationTag>(pc, msg);
  }

  // Reads a variable-length unsigned integer (little endian). Returns the read
  // value and the number of bytes read.
  template <typename ValidationTag>
  std::pair<uint32_t, uint32_t> read_u32v(const uint8_t* pc,
                                          Name<ValidationTag> name = "LEB32") {
    return read_leb<uint32_t, ValidationTag, kNoTrace>(pc, name);
  }

  // Reads a variable-length signed integer (little endian). Returns the read
  // value and the number of bytes read.
  template <typename ValidationTag>
  std::pair<int32_t, uint32_t> read_i32v(
      const uint8_t* pc, Name<ValidationTag> name = "signed LEB32") {
    return read_leb<int32_t, ValidationTag, kNoTrace>(pc, name);
  }

  // Reads a variable-length unsigned integer (little endian). Returns the read
  // value and the number of bytes read.
  template <typename ValidationTag>
  std::pair<uint64_t, uint32_t> read_u64v(const uint8_t* pc,
                                          Name<ValidationTag> name = "LEB64") {
    return read_leb<uint64_t, ValidationTag, kNoTrace>(pc, name);
  }

  // Reads a variable-length signed integer (little endian). Returns the read
  // value and the number of bytes read.
  template <typename ValidationTag>
  std::pair<int64_t, uint32_t> read_i64v(
      const uint8_t* pc, Name<ValidationTag> name = "signed LEB64") {
    return read_leb<int64_t, ValidationTag, kNoTrace>(pc, name);
  }

  // Reads a variable-length 33-bit signed integer (little endian). Returns the
  // read value and the number of bytes read.
  template <typename ValidationTag>
  std::pair<int64_t, uint32_t> read_i33v(
      const uint8_t* pc, Name<ValidationTag> name = "signed LEB33") {
    return read_leb<int64_t, ValidationTag, kNoTrace, 33>(pc, name);
  }

  // Reads a prefixed-opcode, possibly with variable-length index.
  // Returns the read opcode and the number of bytes that make up this opcode,
  // *including* the prefix byte. For most opcodes, it will be 2.
  template <typename ValidationTag>
  std::pair<WasmOpcode, uint32_t> read_prefixed_opcode(
      const uint8_t* pc, Name<ValidationTag> name = "prefixed opcode") {
    // Prefixed opcodes all use LEB128 encoding.
    auto [index, index_length] =
        read_u32v<ValidationTag>(pc + 1, "prefixed opcode index");
    uint32_t length = index_length + 1;  // 1 for prefix byte.
    // Only support opcodes that go up to 0xFFF (when decoded). Anything
    // bigger will need more than 2 bytes, and the '<< 12' below will be wrong.
    if (ValidationTag::validate && V8_UNLIKELY(index > 0xfff)) {
      errorf(pc, "Invalid prefixed opcode %d", index);
      // On validation failure we return "unreachable" (opcode 0).
      static_assert(kExprUnreachable == 0);
      return {kExprUnreachable, 0};
    }

    if (index > 0xff) {
      return {static_cast<WasmOpcode>((*pc) << 12 | index), length};
    }

    return {static_cast<WasmOpcode>((*pc) << 8 | index), length};
  }

  // Reads a 8-bit unsigned integer (byte) and advances {pc_}.
  uint8_t consume_u8(const char* name = "uint8_t") {
    return consume_little_endian<uint8_t, kTrace>(name);
  }
  uint8_t consume_u8(const char* name, ITracer* tracer) {
    if (tracer) {
      tracer->Bytes(pc_, sizeof(uint8_t));
      tracer->Description(name);
    }
    return consume_little_endian<uint8_t, kNoTrace>(name);
  }

  // Reads a 16-bit unsigned integer (little endian) and advances {pc_}.
  uint16_t consume_u16(const char* name = "uint16_t") {
    return consume_little_endian<uint16_t, kTrace>(name);
  }

  // Reads a single 32-bit unsigned integer (little endian) and advances {pc_}.
  uint32_t consume_u32(const char* name, ITracer* tracer) {
    if (tracer) {
      tracer->Bytes(pc_, sizeof(uint32_t));
      tracer->Description(name);
    }
    return consume_little_endian<uint32_t, kNoTrace>(name);
  }

  // Reads a LEB128 variable-length unsigned 32-bit integer and advances {pc_}.
  uint32_t consume_u32v(const char* name = "var_uint32") {
    auto [result, length] =
        read_leb<uint32_t, FullValidationTag, kTrace>(pc_, name);
    pc_ += length;
    return result;
  }
  uint32_t consume_u32v(const char* name, ITracer* tracer) {
    auto [result, length] =
        read_leb<uint32_t, FullValidationTag, kNoTrace>(pc_, name);
    if (tracer) {
      tracer->Bytes(pc_, length);
      tracer->Description(name);
    }
    pc_ += length;
    return result;
  }

  // Reads a LEB128 variable-length signed 32-bit integer and advances {pc_}.
  int32_t consume_i32v(const char* name = "var_int32") {
    auto [result, length] =
        read_leb<int32_t, FullValidationTag, kTrace>(pc_, name);
    pc_ += length;
    return result;
  }

  // Reads a LEB128 variable-length unsigned 64-bit integer and advances {pc_}.
  uint64_t consume_u64v(const char* name, ITracer* tracer) {
    auto [result, length] =
        read_leb<uint64_t, FullValidationTag, kNoTrace>(pc_, name);
    if (tracer) {
      tracer->Bytes(pc_, length);
      tracer->Description(name);
    }
    pc_ += length;
    return result;
  }

  // Reads a LEB128 variable-length signed 64-bit integer and advances {pc_}.
  int64_t consume_i64v(const char* name = "var_int64") {
    auto [result, length] =
        read_leb<int64_t, FullValidationTag, kTrace>(pc_, name);
    pc_ += length;
    return result;
  }

  // Consume {size} bytes and send them to the bit bucket, advancing {pc_}.
  void consume_bytes(uint32_t size, const char* name = "skip") {
    // Only trace if the name is not null.
    TRACE_IF(name, "  +%u  %-20s: %u bytes\n", pc_offset(), name, size);
    if (checkAvailable(size)) {
      pc_ += size;
    } else {
      pc_ = end_;
    }
  }
  void consume_bytes(uint32_t size, const char* name, ITracer* tracer) {
    if (tracer) {
      tracer->Bytes(pc_, size);
      tracer->Description(name);
    }
    consume_bytes(size, nullptr);
  }

  uint32_t available_bytes() const {
    DCHECK_LE(pc_, end_);
    DCHECK_GE(kMaxUInt32, end_ - pc_);
    return static_cast<uint32_t>(end_ - pc_);
  }

  // Check that at least {size} bytes exist between {pc_} and {end_}.
  bool checkAvailable(uint32_t size) {
    if (V8_UNLIKELY(size > available_bytes())) {
      errorf(pc_, "expected %u bytes, fell off end", size);
      return false;
    }
    return true;
  }

  // Do not inline error methods. This has measurable impact on validation time,
  // see https://crbug.com/910432.
  void V8_NOINLINE V8_PRESERVE_MOST error(const char* msg) {
    errorf(pc_offset(), "%s", msg);
  }
  void V8_NOINLINE V8_PRESERVE_MOST error(const uint8_t* pc, const char* msg) {
    errorf(pc_offset(pc), "%s", msg);
  }
  void V8_NOINLINE V8_PRESERVE_MOST error(uint32_t offset, const char* msg) {
    errorf(offset, "%s", msg);
  }

  template <typename... Args>
  void V8_NOINLINE V8_PRESERVE_MOST errorf(const char* format, Args... args) {
    errorf(pc_offset(), format, args...);
  }

  template <typename... Args>
  void V8_NOINLINE V8_PRESERVE_MOST errorf(const uint8_t* pc,
                                           const char* format, Args... args) {
    errorf(pc_offset(pc), format, args...);
  }

  template <typename... Args>
  void V8_NOINLINE V8_PRESERVE_MOST errorf(uint32_t offset, const char* format,
                                           Args... args) {
    static_assert(
        sizeof...(Args) > 0,
        "Use error instead of errorf if the format string has no placeholders");
    verrorf(offset, format, args...);
  }

  // Behavior triggered on first error, overridden in subclasses.
  virtual void onFirstError() {}

  // Debugging helper to print a bytes range as hex bytes.
  void traceByteRange(const uint8_t* start, const uint8_t* end) {
    DCHECK_LE(start, end);
    for (const uint8_t* p = start; p < end; ++p) TRACE("%02x ", *p);
  }

  // Debugging helper to print bytes up to the end.
  void traceOffEnd() {
    traceByteRange(pc_, end_);
    TRACE("<end>\n");
  }

  // Converts the given value to a {Result}, copying the error if necessary.
  template <typename T, typename R = std::decay_t<T>>
  Result<R> toResult(T&& val) {
    if (failed()) {
      TRACE("Result error: %s\n", error_.message().c_str());
      return Result<R>{error_};
    }
    return Result<R>{std::forward<T>(val)};
  }

  // Resets the boundaries of this decoder.
  void Reset(const uint8_t* start, const uint8_t* end,
             uint32_t buffer_offset = 0) {
    DCHECK_LE(start, end);
    DCHECK_EQ(static_cast<uint32_t>(end - start), end - start);
    start_ = start;
    pc_ = start;
    end_ = end;
    buffer_offset_ = buffer_offset;
    error_ = {};
  }

  void Reset(base::Vector<const uint8_t> bytes, uint32_t buffer_offset = 0) {
    Reset(bytes.begin(), bytes.end(), buffer_offset);
  }

  bool ok() const { return !failed(); }
  bool failed() const { return error_.has_error(); }
  bool more() const { return pc_ < end_; }
  const WasmError& error() const { return error_; }

  const uint8_t* start() const { return start_; }
  const uint8_t* pc() const { return pc_; }
  uint32_t V8_INLINE position() const {
    return static_cast<uint32_t>(pc_ - start_);
  }
  // This needs to be inlined for performance (see https://crbug.com/910432).
  uint32_t V8_INLINE pc_offset(const uint8_t* pc) const {
    DCHECK_LE(start_, pc);
    DCHECK_GE(kMaxUInt32 - buffer_offset_, pc - start_);
    return static_cast<uint32_t>(pc - start_) + buffer_offset_;
  }
  uint32_t pc_offset() const { return pc_offset(pc_); }
  uint32_t buffer_offset() const { return buffer_offset_; }
  // Takes an offset relative to the module start and returns an offset relative
  // to the current buffer of the decoder.
  uint32_t GetBufferRelativeOffset(uint32_t offset) const {
    DCHECK_LE(buffer_offset_, offset);
    return offset - buffer_offset_;
  }
  const uint8_t* end() const { return end_; }
  void set_end(const uint8_t* end) { end_ = end; }

  // Check if the uint8_t at {offset} from the current pc equals {expected}.
  bool lookahead(int offset, uint8_t expected) {
    DCHECK_LE(pc_, end_);
    return end_ - pc_ > offset && pc_[offset] == expected;
  }

 protected:
  const uint8_t* start_;
  const uint8_t* pc_;
  const uint8_t* end_;
  // The offset of the current buffer in the module. Needed for streaming.
  uint32_t buffer_offset_;
  WasmError error_;

 private:
  void V8_NOINLINE PRINTF_FORMAT(3, 4)
      verrorf(uint32_t offset, const char* format, ...) {
    // Only report the first error.
    if (!ok()) return;
    constexpr int kMaxErrorMsg = 256;
    base::EmbeddedVector<char, kMaxErrorMsg> buffer;
    va_list args;
    va_start(args, format);
    int len = base::VSNPrintF(buffer, format, args);
    va_end(args);
    CHECK_LT(0, len);
    error_ = {offset, {buffer.begin(), static_cast<size_t>(len)}};
    onFirstError();
  }

  template <typename IntType, typename ValidationTag>
  IntType read_little_endian(const uint8_t* pc, Name<ValidationTag> msg) {
    DCHECK_LE(start_, pc);

    if (!ValidationTag::validate) {
      DCHECK_LE(pc, end_);
      DCHECK_LE(sizeof(IntType), end_ - pc);
    } else if (V8_UNLIKELY(ptrdiff_t{sizeof(IntType)} > end_ - pc)) {
      error(pc, msg);
      return 0;
    }
    return base::ReadLittleEndianValue<IntType>(reinterpret_cast<Address>(pc));
  }

  template <typename IntType, TraceFlag trace>
  IntType consume_little_endian(const char* name) {
    TRACE_IF(trace, "  +%u  %-20s: ", pc_offset(), name);
    if (!checkAvailable(sizeof(IntType))) {
      traceOffEnd();
      pc_ = end_;
      return IntType{0};
    }
    IntType val = read_little_endian<IntType, NoValidationTag>(pc_, name);
    traceByteRange(pc_, pc_ + sizeof(IntType));
    TRACE_IF(trace, "= %d\n", val);
    pc_ += sizeof(IntType);
    return val;
  }

  // The implementation of LEB-decoding; returns the value and the number of
  // bytes read.
  template <typename IntType, typename ValidationTag, TraceFlag trace,
            size_t size_in_bits = 8 * sizeof(IntType)>
  V8_INLINE std::pair<IntType, uint32_t> read_leb(
      const uint8_t* pc, Name<ValidationTag> name = "varint") {
    static_assert(size_in_bits <= 8 * sizeof(IntType),
                  "leb does not fit in type");
    TRACE_IF(trace, "  +%u  %-20s: ", pc_offset(),
             implicit_cast<const char*>(name));
    // Fast path for single-byte integers.
    if (V8_LIKELY((!ValidationTag::validate || pc < end_) && !(*pc & 0x80))) {
      TRACE_IF(trace, "%02x ", *pc);
      IntType result = *pc;
      if (std::is_signed<IntType>::value) {
        // Perform sign extension.
        constexpr int sign_ext_shift = int{8 * sizeof(IntType)} - 7;
        result = (result << sign_ext_shift) >> sign_ext_shift;
        TRACE_IF(trace, "= %" PRIi64 "\n", static_cast<int64_t>(result));
      } else {
        TRACE_IF(trace, "= %" PRIu64 "\n", static_cast<uint64_t>(result));
      }
      return {result, 1};
    }
    auto [result, length] =
        read_leb_slowpath<IntType, ValidationTag, trace, size_in_bits>(pc,
                                                                       name);
    V8_ASSUME(length >= 0 && length <= (size_in_bits + 6) / 7);
    V8_ASSUME(ValidationTag::validate || length >= 1);
    return {result, length};
  }

  template <typename IntType, typename ValidationTag, TraceFlag trace,
            size_t size_in_bits = 8 * sizeof(IntType)>
  V8_NOINLINE V8_PRESERVE_MOST std::pair<IntType, uint32_t> read_leb_slowpath(
      const uint8_t* pc, Name<ValidationTag> name) {
    // Create an unrolled LEB decoding function per integer type.
    return read_leb_tail<IntType, ValidationTag, trace, size_in_bits, 0>(
        pc, name, 0);
  }

  template <typename IntType, typename ValidationTag, TraceFlag trace,
            size_t size_in_bits, int byte_index>
  V8_INLINE std::pair<IntType, uint32_t> read_leb_tail(
      const uint8_t* pc, Name<ValidationTag> name,
      IntType intermediate_result) {
    constexpr bool is_signed = std::is_signed<IntType>::value;
    constexpr int kMaxLength = (size_in_bits + 6) / 7;
    static_assert(byte_index < kMaxLength, "invalid template instantiation");
    constexpr int shift = byte_index * 7;
    constexpr bool is_last_byte = byte_index == kMaxLength - 1;
    const bool at_end = ValidationTag::validate && pc >= end_;
    uint8_t b = 0;
    if (V8_LIKELY(!at_end)) {
      DCHECK_LT(pc, end_);
      b = *pc;
      TRACE_IF(trace, "%02x ", b);
      using Unsigned = typename std::make_unsigned<IntType>::type;
      intermediate_result |=
          (static_cast<Unsigned>(static_cast<IntType>(b) & 0x7f) << shift);
    }
    if (!is_last_byte && (b & 0x80)) {
      // Make sure that we only instantiate the template for valid byte indexes.
      // Compilers are not smart enough to figure out statically that the
      // following call is unreachable if is_last_byte is false.
      constexpr int next_byte_index = byte_index + (is_last_byte ? 0 : 1);
      return read_leb_tail<IntType, ValidationTag, trace, size_in_bits,
                           next_byte_index>(pc + 1, name, intermediate_result);
    }
    if (ValidationTag::validate && V8_UNLIKELY(at_end || (b & 0x80))) {
      TRACE_IF(trace, at_end ? "<end> " : "<length overflow> ");
      errorf(pc, "%s while decoding %s",
             at_end ? "reached end" : "length overflow", name);
      return {0, 0};
    }
    if constexpr (is_last_byte) {
      // A signed-LEB128 must sign-extend the final byte, excluding its
      // most-significant bit; e.g. for a 32-bit LEB128:
      //   kExtraBits = 4  (== 32 - (5-1) * 7)
      // For unsigned values, the extra bits must be all zero.
      // For signed values, the extra bits *plus* the most significant bit must
      // either be 0, or all ones.
      constexpr int kExtraBits = size_in_bits - ((kMaxLength - 1) * 7);
      constexpr int kSignExtBits = kExtraBits - (is_signed ? 1 : 0);
      const uint8_t checked_bits = b & (0xFF << kSignExtBits);
      constexpr uint8_t kSignExtendedExtraBits = 0x7f & (0xFF << kSignExtBits);
      const bool valid_extra_bits =
          checked_bits == 0 ||
          (is_signed && checked_bits == kSignExtendedExtraBits);
      if (!ValidationTag::validate) {
        DCHECK(valid_extra_bits);
      } else if (V8_UNLIKELY(!valid_extra_bits)) {
        error(pc, "extra bits in varint");
        return {0, 0};
      }
    }
    constexpr int sign_ext_shift =
        is_signed ? std::max(0, int{8 * sizeof(IntType)} - shift - 7) : 0;
    // Perform sign extension.
    intermediate_result =
        (intermediate_result << sign_ext_shift) >> sign_ext_shift;
    if (trace && is_signed) {
      TRACE("= %" PRIi64 "\n", static_cast<int64_t>(intermediate_result));
    } else if (trace) {
      TRACE("= %" PRIu64 "\n", static_cast<uint64_t>(intermediate_result));
    }
    const uint32_t length = byte_index + 1;
    return {intermediate_result, length};
  }
};

#undef TRACE
}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_DECODER_H_
```