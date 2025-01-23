Response:
Let's break down the thought process for analyzing the C++ header file.

1. **Initial Scan and Keywords:**  My first step is to quickly scan the code for recognizable keywords and structures. I see `#ifndef`, `#define`, `struct`, `enum`, `static inline`, `constexpr`, and comments. This tells me it's a C++ header defining a structure with an embedded enum and a static inline function. The `#ifndef` and `#define` suggest it's a header guard, preventing multiple inclusions.

2. **Understanding the Purpose from Comments:** I pay close attention to the comments at the top. They mention "generalized UTF-8," a link to a decoder DFA, and the allowance of surrogates (WTF-8). This immediately signals the core function: decoding UTF-8, with a twist for handling surrogates. The reference to the DFA (Deterministic Finite Automaton) hints at the underlying decoding mechanism.

3. **Analyzing the `GeneralizedUtf8DfaDecoder` Structure:**

   * **`enum State`:** This defines the different states the decoder can be in during the decoding process. The names like `kReject`, `kAccept`, `kTwoByte`, etc., are highly indicative of the different stages of decoding a UTF-8 character. The numeric values likely relate to indexing into the `states` array.

   * **`Decode` function:** This is the core logic. It takes a byte, the current `state`, and a `buffer` as input. The `static inline` keyword suggests it's intended for performance by encouraging the compiler to inline the function.

4. **Deep Dive into the `Decode` Function:**

   * **`transitions` array:** The comment explains the mapping from byte to a "transition value."  This value is crucial, as it dictates how many bits from the current byte contribute to the decoded codepoint. The constraints listed in the comments are key to understanding *why* this array is structured the way it is. I'd mentally connect the byte ranges (0x00-0x7F, 0x80-0xBF, etc.) to the UTF-8 encoding scheme.

   * **`states` array:** This array seems to represent the state transitions based on the current state and the `type` (derived from the `transitions` array). The layout suggests a state transition table where rows are current states and columns (implicitly through the `type` offset) are the transition types.

   * **Decoding Logic:** The lines `uint8_t type = transitions[byte];` and `*state = static_cast<State>(states[*state + type]);` are the heart of the DFA. The `transitions` array determines the `type`, and then the `states` array uses the current `state` and `type` to determine the next `state`. The line `*buffer = (*buffer << 6) | (byte & (0x7F >> (type >> 1)));` extracts the relevant bits from the byte and shifts them into the `buffer`. The bit manipulation is crucial for understanding how multi-byte UTF-8 sequences are assembled.

5. **Connecting to JavaScript (If Applicable):** I consider how this low-level C++ functionality might relate to JavaScript. JavaScript natively handles UTF-8 encoding. The connection is that V8 (the JavaScript engine) uses code like this internally to decode UTF-8 strings that JavaScript code manipulates.

6. **Code Logic Reasoning and Examples:**  To demonstrate understanding, I'd think about simple UTF-8 byte sequences and trace how the `Decode` function would process them. This helps solidify the DFA concept. I'd start with a single-byte ASCII character, then a two-byte character, and perhaps a case that leads to a `kReject` state (an invalid UTF-8 sequence). This leads to the "Assumptions and Examples" section in the generated answer.

7. **Common Programming Errors:** I'd consider how developers might misuse or misunderstand UTF-8 encoding, such as incorrect handling of byte sequences or assuming ASCII when dealing with potentially non-ASCII characters. This leads to the "Common Programming Errors" section.

8. **Torque Check:**  The prompt specifically asks about `.tq` files. I check the filename and confirm it ends in `.h`, not `.tq`.

9. **Structuring the Answer:** Finally, I'd organize my observations into clear sections like "Functionality," "Relationship to JavaScript," "Code Logic Reasoning," and "Common Programming Errors" for readability and clarity, mirroring the request's structure.

**Self-Correction/Refinement during the process:**

* Initially, I might just say "decodes UTF-8."  But the comments highlight "generalized UTF-8" and WTF-8, so I need to be more precise and mention the handling of surrogates.
* When looking at the `transitions` and `states` arrays, I might initially just describe *what* they do. But the prompt implicitly asks *why*. So I delve deeper into explaining the constraints and the DFA logic.
* I need to ensure the JavaScript examples are relevant and illustrate the high-level concept related to the low-level C++ code. A simple string encoding/decoding example is appropriate.
* For the code logic reasoning, vague descriptions aren't enough. I need concrete examples with input and expected output.

By following this structured analysis and constantly questioning "why" and "how," I can effectively understand and explain the functionality of the given C++ header file.
```cpp
// See http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ and the sibling file
// utf8-decoder.h for details.
//
// This file decodes "generalized UTF-8", which is the same as UTF-8 except that
// it allows surrogates: https://simonsapin.github.io/wtf-8/#generalized-utf8

#include <stdint.h>

#ifndef __GENERALIZED_UTF8_DFA_DECODER_H
#define __GENERALIZED_UTF8_DFA_DECODER_H

struct GeneralizedUtf8DfaDecoder {
  enum State : uint8_t {
    kReject = 0,
    kAccept = 11,
    kTwoByte = 22,
    kThreeByte = 33,
    kFourByte = 44,
    kFourByteLow = 55,
    kThreeByteHigh = 66,
    kFourByteMidHigh = 77,
  };

  static inline void Decode(uint8_t byte, State* state, uint32_t* buffer) {
    // This first table maps bytes to character to a transition.
    //
    // The transition value takes a state to a new state, but it also determines
    // the set of bits from the current byte that contribute to the decoded
    // codepoint:
    //
    //   Transition | Current byte bits that contribute to decoded codepoint
    //   -------------------------------------------------------------------
    //    0, 1      | 0b01111111
    //    2, 3      | 0b00111111
    //    4, 5      | 0b00011111
    //    6, 7      | 0b00001111
    //    8, 9      | 0b00000111
    //    10        | 0b00000011
    //
    // Given the WTF-8 encoding, we therefore have the following constraints:

    //   1. The transition value for 1-byte encodings should have the value 0 or
    //      1 so that we preserve all of the low 7 bits.
    //   2. Continuation bytes (0x80 to 0xBF) are of the form 0b10xxxxxx, and
    //      therefore should have transition value between 0 and 3.
    //   3. Leading bytes for 2-byte encodings are of the form 0b110yyyyy, and
    //      therefore the transition value can be between 2 and 5.
    //   4. Leading bytes for 3-byte encodings (0b1110zzzz) need transition
    //      value between 4 and 7.
    //   5. Leading bytes for 4-byte encodings (0b11110uuu) need transition
    //      value between 6 and 9.
    //   6. We need more states to impose irregular constraints. Sometimes we
    //      can use the knowldege that e.g. some high significant bits of the
    //      xxxx in 0b1110xxxx are 0, then we can use a higher transition value.
    //   7. Transitions to invalid states can use any transition value.
    static constexpr uint8_t transitions[] = {
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 00-0F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 10-1F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 20-2F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 30-3F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 40-4F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 50-5F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 60-6F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 70-7F
        1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 80-8F
        2,  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 90-9F
        3,  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  // A0-AF
        3,  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  // B0-BF
        8,  8, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  // C0-CF
        4,  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  // D0-DF
        9,  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  // E0-EF
        10, 6, 6, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  // F0-FF
    };

    // This second table maps a state to a new state when adding a transition.
    //  00-7F
    //  |   80-8F
    //  |   |   90-9F
    //  |   |   |   A0-BF
    //  |   |   |   |   C2-DF
    //  |   |   |   |   |   E1-EF
    //  |   |   |   |   |   |   F1-F3
    //  |   |   |   |   |   |   |   F4
    //  |   |   |   |   |   |   |   |   C0, C1, F5-FF
    //  |   |   |   |   |   |   |   |   |  E0
    //  |   |   |   |   |   |   |   |   |  |   F0
    static constexpr uint8_t states[] = {
        0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,   // REJECT = 0
        11, 0,  0,  0,  22, 33, 44, 55, 0, 66, 77,  // ACCEPT = 11
        0,  11, 11, 11, 0,  0,  0,  0,  0, 0,  0,   // 2-byte = 22
        0,  22, 22, 22, 0,  0,  0,  0,  0, 0,  0,   // 3-byte = 33
        0,  33, 33, 33, 0,  0,  0,  0,  0, 0,  0,   // 4-byte = 44
        0,  33, 0,  0,  0,  0,  0,  0,  0, 0,  0,   // 4-byte low = 55
        0,  0,  0,  22, 0,  0,  0,  0,  0, 0,  0,   // 3-byte high = 66
        0,  0,  33, 33, 0,  0,  0,  0,  0, 0,  0,   // 4-byte mid/high = 77
    };

    uint8_t type = transitions[byte];
    *state = static_cast<State>(states[*state + type]);
    *buffer = (*buffer << 6) | (byte & (0x7F >> (type >> 1)));
  }
};

#endif  // __GENERALIZED_UTF8_DFA_DECODER_H
```

## 功能列举

`v8/src/third_party/utf8-decoder/generalized-utf8-decoder.h` 文件定义了一个用于解码 "generalized UTF-8" 的 C++ 结构体 `GeneralizedUtf8DfaDecoder`。其核心功能是：

1. **解码 Generalized UTF-8 编码:** 该解码器能够将字节序列解码成 Unicode 码点。与标准的 UTF-8 解码器不同，它还允许解码 surrogate 码点，这是 WTF-8 编码的特性。

2. **基于确定性有限自动机 (DFA):**  解码过程基于一个预定义的 DFA，通过状态转换来实现。`enum State` 定义了 DFA 的各个状态，包括接受状态 (`kAccept`)、拒绝状态 (`kReject`) 以及中间状态（表示正在解码多字节字符）。

3. **状态驱动的解码:** `Decode` 函数接收一个字节、当前状态和缓冲区作为输入，根据当前状态和输入的字节，更新解码器的状态和缓冲区。

4. **使用查找表进行状态转换:**
   - `transitions` 数组：根据输入的字节值，查找对应的转换类型。这个转换类型决定了当前字节中哪些位属于当前要解码的码点。
   - `states` 数组：根据当前状态和转换类型，查找下一个状态。

5. **按位操作组装码点:**  `Decode` 函数使用位运算 (`<<`, `|`, `&`) 将字节中的有效位提取出来，并组装到 `buffer` 中，最终形成解码后的 Unicode 码点。

## 关于 .tq 结尾

`v8/src/third_party/utf8-decoder/generalized-utf8-decoder.h` 的文件名以 `.h` 结尾，而不是 `.tq`。因此，它是一个 **C++ 头文件**，而不是 V8 Torque 源代码。Torque 文件通常用于定义 V8 的内置函数和类型系统。

## 与 JavaScript 的功能关系

虽然这个头文件是 C++ 代码，但它与 JavaScript 的功能有着密切的关系。JavaScript 引擎 V8 在内部处理字符串时需要进行 UTF-8 解码。

**JavaScript 中的字符串本质上是 UTF-16 编码的。当 V8 接收到外部数据（例如从网络请求或文件中读取）时，这些数据通常是 UTF-8 编码的。`GeneralizedUtf8DfaDecoder` 这样的解码器就在 V8 内部用于将 UTF-8 字节流转换成 V8 内部使用的 UTF-16 字符串。**

**JavaScript 示例：**

```javascript
// 假设我们从某个来源获得了 UTF-8 编码的字节数据
const utf8Bytes = new Uint8Array([
  0xF0, 0x9D, 0x84, 0x9E // U+1D11E 𝄞 Musical Symbol G Clef
]);

// 在 V8 内部，会使用类似 GeneralizedUtf8DfaDecoder 的机制来解码
// 这里我们无法直接在 JavaScript 中模拟 V8 的内部解码过程
// 但可以展示 JavaScript 如何处理最终解码后的字符串

const decoder = new TextDecoder(); // 使用 JavaScript 内置的 TextDecoder API
const decodedString = decoder.decode(utf8Bytes);

console.log(decodedString); // 输出: "𝄞"
console.log(decodedString.codePointAt(0).toString(16)); // 输出: "1d11e"
```

**解释:**

尽管 JavaScript 代码本身没有直接调用 `GeneralizedUtf8DfaDecoder`，但 V8 引擎在解析和处理字符串时会使用类似的底层机制。`TextDecoder` API 提供了一种在 JavaScript 中进行文本解码的方式，它在底层依赖于类似 `GeneralizedUtf8DfaDecoder` 这样的解码器。

## 代码逻辑推理

**假设输入：**

我们连续解码三个字节，构成一个 3 字节的 UTF-8 字符 '你' (U+4F60)。其 UTF-8 编码为 `0xE4 0xBD 0xA0`。

**初始状态：** `state = kAccept`, `buffer = 0`

**解码过程：**

1. **输入字节 0xE4:**
   - `transitions[0xE4]` 的值为 `9`。
   - 新状态为 `states[kAccept + 9]`，即 `states[11 + 9] = states[20] = 33` (对应 `kThreeByte` 状态)。
   - `buffer = (0 << 6) | (0xE4 & (0x7F >> (9 >> 1)))`
     - `0x7F >> 4` (9 >> 1 = 4) 结果为 `0x07`
     - `0xE4 & 0x07` 结果为 `0x04`
     - `buffer = 0x04`

2. **输入字节 0xBD:**
   - 当前状态为 `kThreeByte` (33)。
   - `transitions[0xBD]` 的值为 `3`。
   - 新状态为 `states[kThreeByte + 3]`，即 `states[33 + 3] = states[36] = 22` (对应 `kTwoByte` 状态)。
   - `buffer = (0x04 << 6) | (0xBD & (0x7F >> (3 >> 1)))`
     - `0x7F >> 1` (3 >> 1 = 1) 结果为 `0x3F`
     - `0xBD & 0x3F` 结果为 `0x3D`
     - `buffer = 0x100 | 0x3D = 0x13D`

3. **输入字节 0xA0:**
   - 当前状态为 `kTwoByte` (22)。
   - `transitions[0xA0]` 的值为 `3`。
   - 新状态为 `states[kTwoByte + 3]`，即 `states[22 + 3] = states[25] = 11` (对应 `kAccept` 状态)。
   - `buffer = (0x13D << 6) | (0xA0 & (0x7F >> (3 >> 1)))`
     - `0x7F >> 1` 结果为 `0x3F`
     - `0xA0 & 0x3F` 结果为 `0x20`
     - `buffer = 0x4F40 | 0x20 = 0x4F60`

**最终状态：** `state = kAccept`, `buffer = 0x4F60`

**输出：** 当状态为 `kAccept` 时，`buffer` 中的值 `0x4F60` 就是解码得到的码点。 这与 '你' 的 Unicode 码点 `U+4F60` 相符。

**注意：**  实际使用中，`buffer` 会在开始解码新字符时被重置。上面的例子展示了如何逐步解码一个多字节字符。

## 涉及用户常见的编程错误

使用 UTF-8 解码时，用户常犯的错误包括：

1. **假设所有文本都是 ASCII:**  很多旧的程序或新手开发者可能会假设文本只包含 ASCII 字符，而忽略了多字节的 UTF-8 字符。这会导致在处理非 ASCII 字符时出现乱码或截断。

   **JavaScript 示例:**

   ```javascript
   const text = "你好";
   console.log(text.length); // 输出 2，因为 JavaScript 计算的是 UTF-16 编码单元

   // 错误地假设每个字符占用一个字节
   const utf8Encoder = new TextEncoder();
   const bytes = utf8Encoder.encode(text);
   console.log(bytes.length); // 输出 6，因为 '你' 和 '好' 各占 3 个字节的 UTF-8

   // 尝试按字节截断字符串可能会破坏 UTF-8 编码
   const truncatedBytes = bytes.slice(0, 4);
   const truncatedText = new TextDecoder().decode(truncatedBytes);
   console.log(truncatedText); // 可能输出不完整的字符或者乱码
   ```

2. **不正确地处理字节流:** 在处理来自网络或文件的字节流时，如果没有正确地按照 UTF-8 的规则读取和解码字节，可能会导致解码失败。例如，将一个多字节字符的字节序列分割开来单独解码。

3. **混淆字符编码:**  不清楚数据的实际编码格式，误以为是 UTF-8 而用 UTF-8 解码，但实际可能是其他编码（如 Latin-1, GBK 等）。这会导致严重的乱码问题。

4. **没有处理 BOM (Byte Order Mark):** 虽然 UTF-8 通常不需要 BOM，但在某些情况下会出现 BOM。不处理 BOM 可能会导致某些软件将 BOM 字符显示出来。

5. **对 Surrogate 码点的错误处理:**  在需要处理超出 BMP (基本多文种平面) 的字符时（码点大于 U+FFFF），需要理解 Surrogate Pair 的概念。在某些情况下，可能会错误地将 Surrogate High 和 Surrogate Low 分开处理，导致显示错误。 Generalized UTF-8 (WTF-8) 允许单独存在 Surrogate 码点，但标准 UTF-8 不允许。

理解 `GeneralizedUtf8DfaDecoder` 这样的底层解码器的工作原理，有助于开发者更好地理解字符编码，并避免在处理文本数据时出现常见的错误。

### 提示词
```
这是目录为v8/src/third_party/utf8-decoder/generalized-utf8-decoder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/third_party/utf8-decoder/generalized-utf8-decoder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// See http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ and the sibling file
// utf8-decoder.h for details.
//
// This file decodes "generalized UTF-8", which is the same as UTF-8 except that
// it allows surrogates: https://simonsapin.github.io/wtf-8/#generalized-utf8

#include <stdint.h>

#ifndef __GENERALIZED_UTF8_DFA_DECODER_H
#define __GENERALIZED_UTF8_DFA_DECODER_H

struct GeneralizedUtf8DfaDecoder {
  enum State : uint8_t {
    kReject = 0,
    kAccept = 11,
    kTwoByte = 22,
    kThreeByte = 33,
    kFourByte = 44,
    kFourByteLow = 55,
    kThreeByteHigh = 66,
    kFourByteMidHigh = 77,
  };

  static inline void Decode(uint8_t byte, State* state, uint32_t* buffer) {
    // This first table maps bytes to character to a transition.
    //
    // The transition value takes a state to a new state, but it also determines
    // the set of bits from the current byte that contribute to the decoded
    // codepoint:
    //
    //   Transition | Current byte bits that contribute to decoded codepoint
    //   -------------------------------------------------------------------
    //    0, 1      | 0b01111111
    //    2, 3      | 0b00111111
    //    4, 5      | 0b00011111
    //    6, 7      | 0b00001111
    //    8, 9      | 0b00000111
    //    10        | 0b00000011
    //
    // Given the WTF-8 encoding, we therefore have the following constraints:

    //   1. The transition value for 1-byte encodings should have the value 0 or
    //      1 so that we preserve all of the low 7 bits.
    //   2. Continuation bytes (0x80 to 0xBF) are of the form 0b10xxxxxx, and
    //      therefore should have transition value between 0 and 3.
    //   3. Leading bytes for 2-byte encodings are of the form 0b110yyyyy, and
    //      therefore the transition value can be between 2 and 5.
    //   4. Leading bytes for 3-byte encodings (0b1110zzzz) need transition
    //      value between 4 and 7.
    //   5. Leading bytes for 4-byte encodings (0b11110uuu) need transition
    //      value between 6 and 9.
    //   6. We need more states to impose irregular constraints.  Sometimes we
    //      can use the knowldege that e.g. some high significant bits of the
    //      xxxx in 0b1110xxxx are 0, then we can use a higher transition value.
    //   7. Transitions to invalid states can use any transition value.
    static constexpr uint8_t transitions[] = {
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 00-0F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 10-1F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 20-2F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 30-3F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 40-4F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 50-5F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 60-6F
        0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 70-7F
        1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 80-8F
        2,  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 90-9F
        3,  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  // A0-AF
        3,  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  // B0-BF
        8,  8, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  // C0-CF
        4,  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  // D0-DF
        9,  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  // E0-EF
        10, 6, 6, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  // F0-FF
    };

    // This second table maps a state to a new state when adding a transition.
    //  00-7F
    //  |   80-8F
    //  |   |   90-9F
    //  |   |   |   A0-BF
    //  |   |   |   |   C2-DF
    //  |   |   |   |   |   E1-EF
    //  |   |   |   |   |   |   F1-F3
    //  |   |   |   |   |   |   |   F4
    //  |   |   |   |   |   |   |   |   C0, C1, F5-FF
    //  |   |   |   |   |   |   |   |   |  E0
    //  |   |   |   |   |   |   |   |   |  |   F0
    static constexpr uint8_t states[] = {
        0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,   // REJECT = 0
        11, 0,  0,  0,  22, 33, 44, 55, 0, 66, 77,  // ACCEPT = 11
        0,  11, 11, 11, 0,  0,  0,  0,  0, 0,  0,   // 2-byte = 22
        0,  22, 22, 22, 0,  0,  0,  0,  0, 0,  0,   // 3-byte = 33
        0,  33, 33, 33, 0,  0,  0,  0,  0, 0,  0,   // 4-byte = 44
        0,  33, 0,  0,  0,  0,  0,  0,  0, 0,  0,   // 4-byte low = 55
        0,  0,  0,  22, 0,  0,  0,  0,  0, 0,  0,   // 3-byte high = 66
        0,  0,  33, 33, 0,  0,  0,  0,  0, 0,  0,   // 4-byte mid/high = 77
    };

    uint8_t type = transitions[byte];
    *state = static_cast<State>(states[*state + type]);
    *buffer = (*buffer << 6) | (byte & (0x7F >> (type >> 1)));
  }
};

#endif  // __GENERALIZED_UTF8_DFA_DECODER_H
```