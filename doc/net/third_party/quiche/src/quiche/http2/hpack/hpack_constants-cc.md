Response:
Let's break down the thought process for analyzing the C++ code and answering the prompt's questions.

**1. Understanding the Goal:**

The primary goal is to understand the function of the C++ file `hpack_constants.cc` within the Chromium network stack, specifically its role in HTTP/2's HPACK header compression. The prompt also asks about its relation to JavaScript, example usage, common errors, and debugging.

**2. Initial Code Scan & Keyword Identification:**

I'd first scan the code for obvious keywords and structures:

* `#include`:  This tells me about dependencies. `hpack_constants.h`, `vector`, `absl/base/macros.h`, `hpack_static_table.h`, and `quiche_logging.h` are key.
* `namespace spdy`: This indicates the code belongs to the SPDY (now effectively HTTP/2) domain.
* Comments mentioning Python scripts and IETF drafts: This points towards the data being generated and based on standards.
* `std::vector<HpackHuffmanSymbol>`: This strongly suggests Huffman coding is involved.
* `HpackHuffmanCodeVector()`: This function likely returns the Huffman code table.
* The large list of `{code, length, id}`: This is the Huffman code table data.
* `#define STATIC_ENTRY`: This is a macro for creating static table entries.
* `std::vector<HpackStaticEntry>`: This suggests a static table of HTTP header fields.
* `HpackStaticTableVector()`: This function likely returns the static table.
* The list of `STATIC_ENTRY`: This is the static table data (common HTTP headers).
* `ObtainHpackStaticTable()`: This function likely provides access to the initialized static table.

**3. Deduction of Core Functionality:**

Based on the keywords and structures, I can deduce the core functionality:

* **Huffman Coding:** The `HpackHuffmanCodeVector()` function and the `HpackHuffmanSymbol` structure strongly suggest this file defines the Huffman code table used for HPACK compression. The comments link this to a Python script for generating the table, further reinforcing this.
* **Static Table:** The `HpackStaticTableVector()` function and the `HpackStaticEntry` structure indicate this file defines the HPACK static table. The list of common HTTP headers confirms this.
* **Constants:**  The filename "hpack_constants.cc" and the content confirm that the file's purpose is to store constant data related to HPACK.

**4. Relating to HPACK and HTTP/2:**

Knowing the core functionalities, I can connect them to HPACK:

* **Huffman Coding in HPACK:**  HPACK uses Huffman coding to compress header values. This table is crucial for the encoding and decoding process.
* **Static Table in HPACK:** HPACK uses a static table of common header fields to reduce redundancy. This table allows for representing common headers with a small index.

**5. Considering the JavaScript Relationship:**

I need to consider how this *C++* code interacts with JavaScript in a browser context.

* **Indirect Relationship:**  JavaScript running in a browser uses the browser's underlying networking stack, which is often implemented in C++. Therefore, when a JavaScript application makes an HTTP/2 request, the browser's C++ networking code (including this file) will be involved in the HPACK compression. JavaScript doesn't directly access these C++ constants.
* **Developer Tools:**  JavaScript developers can *observe* the effects of HPACK through browser developer tools (Network tab). They can see compressed headers, but they don't directly manipulate these C++ structures.

**6. Constructing Examples (Logical Reasoning):**

For the logical reasoning part, I need to illustrate how the tables are used:

* **Huffman Encoding Example:**  Choose a common header value (e.g., "gzip"). Look up its Huffman code, length, and ID. Show how the binary representation is constructed.
* **Static Table Example:** Select a common header (e.g., `:method: GET`). Show how it can be represented by its index (2) in HPACK.

**7. Identifying Common Errors:**

Think about how developers might misuse or misunderstand HPACK:

* **Assuming No Compression:** Developers might not realize headers are compressed and send overly verbose headers.
* **Incorrect Header Names:** Using slightly different header names prevents static table matching, reducing efficiency.
* **Large Custom Headers:**  While allowed, excessive custom headers can impact compression efficiency.

**8. Tracing User Actions (Debugging):**

Consider how a user action leads to this code being used:

* **Basic Web Request:** A user types a URL or clicks a link, triggering an HTTP/2 request.
* **Browser's Network Stack:**  The browser's networking code handles the request, including HPACK compression/decompression.
* **Debugging Scenarios:** When debugging network issues, developers might examine headers, which leads them to investigate HPACK.

**9. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the prompt clearly:

* **Functionality:** Start with a concise summary, then elaborate on the Huffman and static table aspects.
* **JavaScript Relationship:** Explain the indirect connection.
* **Logical Reasoning:** Provide clear examples with inputs and outputs.
* **Common Errors:**  Give practical examples of mistakes.
* **Debugging:** Describe the user journey and how this code becomes relevant for debugging.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe JavaScript directly uses these constants. **Correction:**  Realized JavaScript interacts at a higher level and relies on the browser's C++ implementation.
* **Example Selection:** Initially considered very complex examples. **Refinement:** Chose simpler, more illustrative examples.
* **Debugging Detail:** Initially focused on code-level debugging. **Refinement:** Included the user's perspective and how they might reach a point of needing to understand HPACK.
这个C++源代码文件 `hpack_constants.cc` 的功能是定义了用于HTTP/2 HPACK (Header Compression for HTTP/2) 算法的常量数据。HPACK 是一种专门为 HTTP/2 设计的头部压缩格式，旨在减小头部的大小，从而提高网络性能。

具体来说，这个文件定义了两个关键的常量数据结构：

1. **Huffman 编码表 (`HpackHuffmanCodeVector`)**:  HPACK 可以选择使用 Huffman 编码来压缩头部字段的值。这个函数返回一个静态的 `std::vector<HpackHuffmanSymbol>`，其中包含了 Huffman 编码的符号表。每个 `HpackHuffmanSymbol` 结构体包含：
    * `code`: Huffman 编码。
    * `length`: 编码的比特长度。
    * `id`:  对应字符或符号的 ID。

   这个表是通过一个 Python 脚本 `net/tools/build_hpack_constants.py` 生成的，该脚本基于 IETF 的 HTTPbis 草案中的数据。

2. **静态表 (`HpackStaticTableVector` 和 `ObtainHpackStaticTable`)**: HPACK 利用一个静态的头部字段名和值的表来减少重复。这个文件中定义了一个静态的 `std::vector<HpackStaticEntry>`，包含了 HTTP/2 规范中预定义的 61 个常见的头部字段名和值。每个 `HpackStaticEntry` 结构体包含：
    * `name`: 头部字段名。
    * `name_len`: 头部字段名的长度。
    * `value`: 头部字段值。
    * `value_len`: 头部字段值的长度。

   `ObtainHpackStaticTable` 函数负责初始化并返回这个静态表的一个单例实例。

**它与 JavaScript 的功能关系：**

这个 C++ 文件本身与 JavaScript 没有直接的代码级别的交互。然而，它间接地影响了 JavaScript 在浏览器环境中的网络性能：

* **性能提升：** 当浏览器使用 HTTP/2 与服务器通信时，网络栈（用 C++ 实现）会使用这里定义的 HPACK 常量来压缩 HTTP 头部。这减少了传输的数据量，使得 JavaScript 发起的网络请求（例如，通过 `fetch` API 或 `XMLHttpRequest`）可以更快地完成。JavaScript 代码本身不需要知道这些底层的 HPACK 细节。

**举例说明：**

假设一个 JavaScript 应用发起一个 HTTP/2 GET 请求到服务器，请求的头部包含 `accept-encoding: gzip, deflate`。

1. **JavaScript 发起请求：** JavaScript 代码调用 `fetch('/data')`，并且浏览器会自动添加一些默认头部，包括 `accept-encoding: gzip, deflate`。

2. **浏览器网络栈处理：** 浏览器底层的网络栈（C++ 实现）会处理这个请求。在 HTTP/2 中，它会尝试使用 HPACK 压缩头部。

3. **静态表匹配：** 网络栈会查找静态表 `HpackStaticTableVector`。它会找到第 16 项是 `accept-encoding: gzip, deflate`。

4. **HPACK 编码：**  由于找到了匹配项，HPACK 编码器可以将这个头部表示为一个简单的索引 `0x10 + 16 = 0x20` (假设使用了索引头部字段表示法)。这比传输完整的字符串要小得多。

5. **Huffman 编码 (可能)：** 如果要压缩的头部值不在静态表中或者选择对值进行 Huffman 编码，那么 `HpackHuffmanCodeVector` 中定义的 Huffman 编码表会被用来将头部值（比如一个自定义的头部值）转换为更短的二进制表示。

6. **数据传输：** 压缩后的头部会和请求的其他部分一起发送到服务器。

7. **服务器解码：** 服务器接收到数据后，会使用相同的 HPACK 规则和常量来解码头部。

**逻辑推理（假设输入与输出）：**

**假设输入：** 想要编码字符串 "www.example.com" 使用 Huffman 编码。

**输出（基于 `HpackHuffmanCodeVector`）：**  需要遍历 Huffman 树或者查找表来确定每个字符的 Huffman 编码。由于这个字符串不在预定义的符号中，它会被拆分成单个字符，然后查找每个字符的编码。例如，字符 'w' 的编码是 `1111000` (来自 `0xf0000000ul, 7, 119`),  '.' 的编码是 `010111` (来自 `0x5c000000ul, 6, 46`) 等等。  最终的 Huffman 编码是这些编码的拼接，并可能需要填充位。

**假设输入：**  需要将头部 `content-type: application/json` 进行 HPACK 编码。

**输出：**
* 检查静态表，`content-type` 在静态表中（第 31 项），但 `application/json` 不在。
* HPACK 编码器可能会选择使用索引头部字段表示法来编码头部名称（索引为 31），然后将 `application/json` 作为字面值进行编码，可能还会使用 Huffman 编码。

**用户或编程常见的使用错误：**

* **误解静态表的作用：** 开发者可能会错误地认为所有常见的头部都会被静态表优化。如果使用了稍微不同的头部名称或值，就可能无法利用静态表。例如，使用 `Content-Type` 而不是 `content-type` (大小写敏感)。

* **过度依赖自定义头部：** 虽然自定义头部是允许的，但过度使用会导致 HPACK 压缩效率降低，因为这些自定义头部不太可能在静态表中找到，并且可能会增加需要进行 Huffman 编码的数据量。

* **不理解 Huffman 编码的原理：**  开发者不需要直接操作 Huffman 编码，但了解其基本原理有助于理解为什么某些头部值比其他值更“便宜”（字节数更少）。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入网址或点击链接。**
2. **浏览器解析 URL 并决定需要发起一个 HTTP 请求。**
3. **如果服务器支持 HTTP/2，浏览器会尝试与服务器建立 HTTP/2 连接。** 这涉及到 TLS 握手和 ALPN (Application-Layer Protocol Negotiation) 协商。
4. **一旦 HTTP/2 连接建立，当浏览器需要发送 HTTP 请求时，它会构建 HTTP 头部。**
5. **浏览器的网络栈的 HPACK 编码器会被调用。**
6. **HPACK 编码器会查找 `hpack_constants.cc` 中定义的静态表 `HpackStaticTableVector`，尝试匹配头部字段名和值。** 如果找到匹配项，就使用索引进行编码。
7. **对于不在静态表中的头部值，HPACK 编码器可能会使用 `HpackHuffmanCodeVector` 中定义的 Huffman 编码表进行压缩。**
8. **压缩后的头部信息会作为 HTTP/2 帧的一部分发送到服务器。**

**作为调试线索：**

当开发者需要调试与 HTTP 头部相关的问题时，理解 `hpack_constants.cc` 的作用可以提供以下线索：

* **检查头部是否在静态表中：** 如果某些头部性能表现良好（传输大小小），可能是因为它们在静态表中被高效地编码了。开发者可以通过查看 `HpackStaticTableVector` 来确认。
* **分析 Huffman 编码效率：** 如果某些头部值很大，即使使用了 HPACK，也可能是因为这些值的 Huffman 编码效率不高，或者根本没有使用 Huffman 编码。开发者可以尝试理解 `HpackHuffmanCodeVector` 的结构，虽然直接分析编码很复杂。
* **排查头部压缩失败的原因：** 如果怀疑头部压缩没有生效，可以检查发送的原始头部，看是否有拼写错误或大小写不一致，导致无法利用静态表。
* **理解浏览器如何优化头部：**  对于网络性能优化，了解浏览器如何使用 HPACK 可以指导开发者编写更友好的头部信息，例如，尽量使用标准头部名称和常见的值。

总而言之，`hpack_constants.cc` 虽然是一个底层的 C++ 文件，但它对于理解 HTTP/2 的头部压缩机制至关重要，并间接地影响了 JavaScript 应用的网络性能。在网络调试和性能优化方面，了解其内容可以帮助开发者更好地理解浏览器行为。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/hpack_constants.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/hpack_constants.h"

#include <vector>

#include "absl/base/macros.h"
#include "quiche/http2/hpack/hpack_static_table.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace spdy {

// Produced by applying the python program [1] with tables provided by [2]
// (inserted into the source of the python program) and copy-paste them into
// this file.
//
// [1] net/tools/build_hpack_constants.py in Chromium
// [2] http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

// HpackHuffmanSymbol entries are initialized as {code, length, id}.
// Codes are specified in the |length| most-significant bits of |code|.
const std::vector<HpackHuffmanSymbol>& HpackHuffmanCodeVector() {
  static const auto* kHpackHuffmanCode = new std::vector<HpackHuffmanSymbol>{
      {0xffc00000ul, 13, 0},    //     11111111|11000
      {0xffffb000ul, 23, 1},    //     11111111|11111111|1011000
      {0xfffffe20ul, 28, 2},    //     11111111|11111111|11111110|0010
      {0xfffffe30ul, 28, 3},    //     11111111|11111111|11111110|0011
      {0xfffffe40ul, 28, 4},    //     11111111|11111111|11111110|0100
      {0xfffffe50ul, 28, 5},    //     11111111|11111111|11111110|0101
      {0xfffffe60ul, 28, 6},    //     11111111|11111111|11111110|0110
      {0xfffffe70ul, 28, 7},    //     11111111|11111111|11111110|0111
      {0xfffffe80ul, 28, 8},    //     11111111|11111111|11111110|1000
      {0xffffea00ul, 24, 9},    //     11111111|11111111|11101010
      {0xfffffff0ul, 30, 10},   //     11111111|11111111|11111111|111100
      {0xfffffe90ul, 28, 11},   //     11111111|11111111|11111110|1001
      {0xfffffea0ul, 28, 12},   //     11111111|11111111|11111110|1010
      {0xfffffff4ul, 30, 13},   //     11111111|11111111|11111111|111101
      {0xfffffeb0ul, 28, 14},   //     11111111|11111111|11111110|1011
      {0xfffffec0ul, 28, 15},   //     11111111|11111111|11111110|1100
      {0xfffffed0ul, 28, 16},   //     11111111|11111111|11111110|1101
      {0xfffffee0ul, 28, 17},   //     11111111|11111111|11111110|1110
      {0xfffffef0ul, 28, 18},   //     11111111|11111111|11111110|1111
      {0xffffff00ul, 28, 19},   //     11111111|11111111|11111111|0000
      {0xffffff10ul, 28, 20},   //     11111111|11111111|11111111|0001
      {0xffffff20ul, 28, 21},   //     11111111|11111111|11111111|0010
      {0xfffffff8ul, 30, 22},   //     11111111|11111111|11111111|111110
      {0xffffff30ul, 28, 23},   //     11111111|11111111|11111111|0011
      {0xffffff40ul, 28, 24},   //     11111111|11111111|11111111|0100
      {0xffffff50ul, 28, 25},   //     11111111|11111111|11111111|0101
      {0xffffff60ul, 28, 26},   //     11111111|11111111|11111111|0110
      {0xffffff70ul, 28, 27},   //     11111111|11111111|11111111|0111
      {0xffffff80ul, 28, 28},   //     11111111|11111111|11111111|1000
      {0xffffff90ul, 28, 29},   //     11111111|11111111|11111111|1001
      {0xffffffa0ul, 28, 30},   //     11111111|11111111|11111111|1010
      {0xffffffb0ul, 28, 31},   //     11111111|11111111|11111111|1011
      {0x50000000ul, 6, 32},    // ' ' 010100
      {0xfe000000ul, 10, 33},   // '!' 11111110|00
      {0xfe400000ul, 10, 34},   // '"' 11111110|01
      {0xffa00000ul, 12, 35},   // '#' 11111111|1010
      {0xffc80000ul, 13, 36},   // '$' 11111111|11001
      {0x54000000ul, 6, 37},    // '%' 010101
      {0xf8000000ul, 8, 38},    // '&' 11111000
      {0xff400000ul, 11, 39},   // ''' 11111111|010
      {0xfe800000ul, 10, 40},   // '(' 11111110|10
      {0xfec00000ul, 10, 41},   // ')' 11111110|11
      {0xf9000000ul, 8, 42},    // '*' 11111001
      {0xff600000ul, 11, 43},   // '+' 11111111|011
      {0xfa000000ul, 8, 44},    // ',' 11111010
      {0x58000000ul, 6, 45},    // '-' 010110
      {0x5c000000ul, 6, 46},    // '.' 010111
      {0x60000000ul, 6, 47},    // '/' 011000
      {0x00000000ul, 5, 48},    // '0' 00000
      {0x08000000ul, 5, 49},    // '1' 00001
      {0x10000000ul, 5, 50},    // '2' 00010
      {0x64000000ul, 6, 51},    // '3' 011001
      {0x68000000ul, 6, 52},    // '4' 011010
      {0x6c000000ul, 6, 53},    // '5' 011011
      {0x70000000ul, 6, 54},    // '6' 011100
      {0x74000000ul, 6, 55},    // '7' 011101
      {0x78000000ul, 6, 56},    // '8' 011110
      {0x7c000000ul, 6, 57},    // '9' 011111
      {0xb8000000ul, 7, 58},    // ':' 1011100
      {0xfb000000ul, 8, 59},    // ';' 11111011
      {0xfff80000ul, 15, 60},   // '<' 11111111|1111100
      {0x80000000ul, 6, 61},    // '=' 100000
      {0xffb00000ul, 12, 62},   // '>' 11111111|1011
      {0xff000000ul, 10, 63},   // '?' 11111111|00
      {0xffd00000ul, 13, 64},   // '@' 11111111|11010
      {0x84000000ul, 6, 65},    // 'A' 100001
      {0xba000000ul, 7, 66},    // 'B' 1011101
      {0xbc000000ul, 7, 67},    // 'C' 1011110
      {0xbe000000ul, 7, 68},    // 'D' 1011111
      {0xc0000000ul, 7, 69},    // 'E' 1100000
      {0xc2000000ul, 7, 70},    // 'F' 1100001
      {0xc4000000ul, 7, 71},    // 'G' 1100010
      {0xc6000000ul, 7, 72},    // 'H' 1100011
      {0xc8000000ul, 7, 73},    // 'I' 1100100
      {0xca000000ul, 7, 74},    // 'J' 1100101
      {0xcc000000ul, 7, 75},    // 'K' 1100110
      {0xce000000ul, 7, 76},    // 'L' 1100111
      {0xd0000000ul, 7, 77},    // 'M' 1101000
      {0xd2000000ul, 7, 78},    // 'N' 1101001
      {0xd4000000ul, 7, 79},    // 'O' 1101010
      {0xd6000000ul, 7, 80},    // 'P' 1101011
      {0xd8000000ul, 7, 81},    // 'Q' 1101100
      {0xda000000ul, 7, 82},    // 'R' 1101101
      {0xdc000000ul, 7, 83},    // 'S' 1101110
      {0xde000000ul, 7, 84},    // 'T' 1101111
      {0xe0000000ul, 7, 85},    // 'U' 1110000
      {0xe2000000ul, 7, 86},    // 'V' 1110001
      {0xe4000000ul, 7, 87},    // 'W' 1110010
      {0xfc000000ul, 8, 88},    // 'X' 11111100
      {0xe6000000ul, 7, 89},    // 'Y' 1110011
      {0xfd000000ul, 8, 90},    // 'Z' 11111101
      {0xffd80000ul, 13, 91},   // '[' 11111111|11011
      {0xfffe0000ul, 19, 92},   // '\' 11111111|11111110|000
      {0xffe00000ul, 13, 93},   // ']' 11111111|11100
      {0xfff00000ul, 14, 94},   // '^' 11111111|111100
      {0x88000000ul, 6, 95},    // '_' 100010
      {0xfffa0000ul, 15, 96},   // '`' 11111111|1111101
      {0x18000000ul, 5, 97},    // 'a' 00011
      {0x8c000000ul, 6, 98},    // 'b' 100011
      {0x20000000ul, 5, 99},    // 'c' 00100
      {0x90000000ul, 6, 100},   // 'd' 100100
      {0x28000000ul, 5, 101},   // 'e' 00101
      {0x94000000ul, 6, 102},   // 'f' 100101
      {0x98000000ul, 6, 103},   // 'g' 100110
      {0x9c000000ul, 6, 104},   // 'h' 100111
      {0x30000000ul, 5, 105},   // 'i' 00110
      {0xe8000000ul, 7, 106},   // 'j' 1110100
      {0xea000000ul, 7, 107},   // 'k' 1110101
      {0xa0000000ul, 6, 108},   // 'l' 101000
      {0xa4000000ul, 6, 109},   // 'm' 101001
      {0xa8000000ul, 6, 110},   // 'n' 101010
      {0x38000000ul, 5, 111},   // 'o' 00111
      {0xac000000ul, 6, 112},   // 'p' 101011
      {0xec000000ul, 7, 113},   // 'q' 1110110
      {0xb0000000ul, 6, 114},   // 'r' 101100
      {0x40000000ul, 5, 115},   // 's' 01000
      {0x48000000ul, 5, 116},   // 't' 01001
      {0xb4000000ul, 6, 117},   // 'u' 101101
      {0xee000000ul, 7, 118},   // 'v' 1110111
      {0xf0000000ul, 7, 119},   // 'w' 1111000
      {0xf2000000ul, 7, 120},   // 'x' 1111001
      {0xf4000000ul, 7, 121},   // 'y' 1111010
      {0xf6000000ul, 7, 122},   // 'z' 1111011
      {0xfffc0000ul, 15, 123},  // '{' 11111111|1111110
      {0xff800000ul, 11, 124},  // '|' 11111111|100
      {0xfff40000ul, 14, 125},  // '}' 11111111|111101
      {0xffe80000ul, 13, 126},  // '~' 11111111|11101
      {0xffffffc0ul, 28, 127},  //     11111111|11111111|11111111|1100
      {0xfffe6000ul, 20, 128},  //     11111111|11111110|0110
      {0xffff4800ul, 22, 129},  //     11111111|11111111|010010
      {0xfffe7000ul, 20, 130},  //     11111111|11111110|0111
      {0xfffe8000ul, 20, 131},  //     11111111|11111110|1000
      {0xffff4c00ul, 22, 132},  //     11111111|11111111|010011
      {0xffff5000ul, 22, 133},  //     11111111|11111111|010100
      {0xffff5400ul, 22, 134},  //     11111111|11111111|010101
      {0xffffb200ul, 23, 135},  //     11111111|11111111|1011001
      {0xffff5800ul, 22, 136},  //     11111111|11111111|010110
      {0xffffb400ul, 23, 137},  //     11111111|11111111|1011010
      {0xffffb600ul, 23, 138},  //     11111111|11111111|1011011
      {0xffffb800ul, 23, 139},  //     11111111|11111111|1011100
      {0xffffba00ul, 23, 140},  //     11111111|11111111|1011101
      {0xffffbc00ul, 23, 141},  //     11111111|11111111|1011110
      {0xffffeb00ul, 24, 142},  //     11111111|11111111|11101011
      {0xffffbe00ul, 23, 143},  //     11111111|11111111|1011111
      {0xffffec00ul, 24, 144},  //     11111111|11111111|11101100
      {0xffffed00ul, 24, 145},  //     11111111|11111111|11101101
      {0xffff5c00ul, 22, 146},  //     11111111|11111111|010111
      {0xffffc000ul, 23, 147},  //     11111111|11111111|1100000
      {0xffffee00ul, 24, 148},  //     11111111|11111111|11101110
      {0xffffc200ul, 23, 149},  //     11111111|11111111|1100001
      {0xffffc400ul, 23, 150},  //     11111111|11111111|1100010
      {0xffffc600ul, 23, 151},  //     11111111|11111111|1100011
      {0xffffc800ul, 23, 152},  //     11111111|11111111|1100100
      {0xfffee000ul, 21, 153},  //     11111111|11111110|11100
      {0xffff6000ul, 22, 154},  //     11111111|11111111|011000
      {0xffffca00ul, 23, 155},  //     11111111|11111111|1100101
      {0xffff6400ul, 22, 156},  //     11111111|11111111|011001
      {0xffffcc00ul, 23, 157},  //     11111111|11111111|1100110
      {0xffffce00ul, 23, 158},  //     11111111|11111111|1100111
      {0xffffef00ul, 24, 159},  //     11111111|11111111|11101111
      {0xffff6800ul, 22, 160},  //     11111111|11111111|011010
      {0xfffee800ul, 21, 161},  //     11111111|11111110|11101
      {0xfffe9000ul, 20, 162},  //     11111111|11111110|1001
      {0xffff6c00ul, 22, 163},  //     11111111|11111111|011011
      {0xffff7000ul, 22, 164},  //     11111111|11111111|011100
      {0xffffd000ul, 23, 165},  //     11111111|11111111|1101000
      {0xffffd200ul, 23, 166},  //     11111111|11111111|1101001
      {0xfffef000ul, 21, 167},  //     11111111|11111110|11110
      {0xffffd400ul, 23, 168},  //     11111111|11111111|1101010
      {0xffff7400ul, 22, 169},  //     11111111|11111111|011101
      {0xffff7800ul, 22, 170},  //     11111111|11111111|011110
      {0xfffff000ul, 24, 171},  //     11111111|11111111|11110000
      {0xfffef800ul, 21, 172},  //     11111111|11111110|11111
      {0xffff7c00ul, 22, 173},  //     11111111|11111111|011111
      {0xffffd600ul, 23, 174},  //     11111111|11111111|1101011
      {0xffffd800ul, 23, 175},  //     11111111|11111111|1101100
      {0xffff0000ul, 21, 176},  //     11111111|11111111|00000
      {0xffff0800ul, 21, 177},  //     11111111|11111111|00001
      {0xffff8000ul, 22, 178},  //     11111111|11111111|100000
      {0xffff1000ul, 21, 179},  //     11111111|11111111|00010
      {0xffffda00ul, 23, 180},  //     11111111|11111111|1101101
      {0xffff8400ul, 22, 181},  //     11111111|11111111|100001
      {0xffffdc00ul, 23, 182},  //     11111111|11111111|1101110
      {0xffffde00ul, 23, 183},  //     11111111|11111111|1101111
      {0xfffea000ul, 20, 184},  //     11111111|11111110|1010
      {0xffff8800ul, 22, 185},  //     11111111|11111111|100010
      {0xffff8c00ul, 22, 186},  //     11111111|11111111|100011
      {0xffff9000ul, 22, 187},  //     11111111|11111111|100100
      {0xffffe000ul, 23, 188},  //     11111111|11111111|1110000
      {0xffff9400ul, 22, 189},  //     11111111|11111111|100101
      {0xffff9800ul, 22, 190},  //     11111111|11111111|100110
      {0xffffe200ul, 23, 191},  //     11111111|11111111|1110001
      {0xfffff800ul, 26, 192},  //     11111111|11111111|11111000|00
      {0xfffff840ul, 26, 193},  //     11111111|11111111|11111000|01
      {0xfffeb000ul, 20, 194},  //     11111111|11111110|1011
      {0xfffe2000ul, 19, 195},  //     11111111|11111110|001
      {0xffff9c00ul, 22, 196},  //     11111111|11111111|100111
      {0xffffe400ul, 23, 197},  //     11111111|11111111|1110010
      {0xffffa000ul, 22, 198},  //     11111111|11111111|101000
      {0xfffff600ul, 25, 199},  //     11111111|11111111|11110110|0
      {0xfffff880ul, 26, 200},  //     11111111|11111111|11111000|10
      {0xfffff8c0ul, 26, 201},  //     11111111|11111111|11111000|11
      {0xfffff900ul, 26, 202},  //     11111111|11111111|11111001|00
      {0xfffffbc0ul, 27, 203},  //     11111111|11111111|11111011|110
      {0xfffffbe0ul, 27, 204},  //     11111111|11111111|11111011|111
      {0xfffff940ul, 26, 205},  //     11111111|11111111|11111001|01
      {0xfffff100ul, 24, 206},  //     11111111|11111111|11110001
      {0xfffff680ul, 25, 207},  //     11111111|11111111|11110110|1
      {0xfffe4000ul, 19, 208},  //     11111111|11111110|010
      {0xffff1800ul, 21, 209},  //     11111111|11111111|00011
      {0xfffff980ul, 26, 210},  //     11111111|11111111|11111001|10
      {0xfffffc00ul, 27, 211},  //     11111111|11111111|11111100|000
      {0xfffffc20ul, 27, 212},  //     11111111|11111111|11111100|001
      {0xfffff9c0ul, 26, 213},  //     11111111|11111111|11111001|11
      {0xfffffc40ul, 27, 214},  //     11111111|11111111|11111100|010
      {0xfffff200ul, 24, 215},  //     11111111|11111111|11110010
      {0xffff2000ul, 21, 216},  //     11111111|11111111|00100
      {0xffff2800ul, 21, 217},  //     11111111|11111111|00101
      {0xfffffa00ul, 26, 218},  //     11111111|11111111|11111010|00
      {0xfffffa40ul, 26, 219},  //     11111111|11111111|11111010|01
      {0xffffffd0ul, 28, 220},  //     11111111|11111111|11111111|1101
      {0xfffffc60ul, 27, 221},  //     11111111|11111111|11111100|011
      {0xfffffc80ul, 27, 222},  //     11111111|11111111|11111100|100
      {0xfffffca0ul, 27, 223},  //     11111111|11111111|11111100|101
      {0xfffec000ul, 20, 224},  //     11111111|11111110|1100
      {0xfffff300ul, 24, 225},  //     11111111|11111111|11110011
      {0xfffed000ul, 20, 226},  //     11111111|11111110|1101
      {0xffff3000ul, 21, 227},  //     11111111|11111111|00110
      {0xffffa400ul, 22, 228},  //     11111111|11111111|101001
      {0xffff3800ul, 21, 229},  //     11111111|11111111|00111
      {0xffff4000ul, 21, 230},  //     11111111|11111111|01000
      {0xffffe600ul, 23, 231},  //     11111111|11111111|1110011
      {0xffffa800ul, 22, 232},  //     11111111|11111111|101010
      {0xffffac00ul, 22, 233},  //     11111111|11111111|101011
      {0xfffff700ul, 25, 234},  //     11111111|11111111|11110111|0
      {0xfffff780ul, 25, 235},  //     11111111|11111111|11110111|1
      {0xfffff400ul, 24, 236},  //     11111111|11111111|11110100
      {0xfffff500ul, 24, 237},  //     11111111|11111111|11110101
      {0xfffffa80ul, 26, 238},  //     11111111|11111111|11111010|10
      {0xffffe800ul, 23, 239},  //     11111111|11111111|1110100
      {0xfffffac0ul, 26, 240},  //     11111111|11111111|11111010|11
      {0xfffffcc0ul, 27, 241},  //     11111111|11111111|11111100|110
      {0xfffffb00ul, 26, 242},  //     11111111|11111111|11111011|00
      {0xfffffb40ul, 26, 243},  //     11111111|11111111|11111011|01
      {0xfffffce0ul, 27, 244},  //     11111111|11111111|11111100|111
      {0xfffffd00ul, 27, 245},  //     11111111|11111111|11111101|000
      {0xfffffd20ul, 27, 246},  //     11111111|11111111|11111101|001
      {0xfffffd40ul, 27, 247},  //     11111111|11111111|11111101|010
      {0xfffffd60ul, 27, 248},  //     11111111|11111111|11111101|011
      {0xffffffe0ul, 28, 249},  //     11111111|11111111|11111111|1110
      {0xfffffd80ul, 27, 250},  //     11111111|11111111|11111101|100
      {0xfffffda0ul, 27, 251},  //     11111111|11111111|11111101|101
      {0xfffffdc0ul, 27, 252},  //     11111111|11111111|11111101|110
      {0xfffffde0ul, 27, 253},  //     11111111|11111111|11111101|111
      {0xfffffe00ul, 27, 254},  //     11111111|11111111|11111110|000
      {0xfffffb80ul, 26, 255},  //     11111111|11111111|11111011|10
      {0xfffffffcul, 30, 256},  // EOS 11111111|11111111|11111111|111111
  };
  return *kHpackHuffmanCode;
}

// The "constructor" for a HpackStaticEntry that computes the lengths at
// compile time.
#define STATIC_ENTRY(name, value) \
  { name, ABSL_ARRAYSIZE(name) - 1, value, ABSL_ARRAYSIZE(value) - 1 }

const std::vector<HpackStaticEntry>& HpackStaticTableVector() {
  static const auto* kHpackStaticTable = new std::vector<HpackStaticEntry>{
      STATIC_ENTRY(":authority", ""),                    // 1
      STATIC_ENTRY(":method", "GET"),                    // 2
      STATIC_ENTRY(":method", "POST"),                   // 3
      STATIC_ENTRY(":path", "/"),                        // 4
      STATIC_ENTRY(":path", "/index.html"),              // 5
      STATIC_ENTRY(":scheme", "http"),                   // 6
      STATIC_ENTRY(":scheme", "https"),                  // 7
      STATIC_ENTRY(":status", "200"),                    // 8
      STATIC_ENTRY(":status", "204"),                    // 9
      STATIC_ENTRY(":status", "206"),                    // 10
      STATIC_ENTRY(":status", "304"),                    // 11
      STATIC_ENTRY(":status", "400"),                    // 12
      STATIC_ENTRY(":status", "404"),                    // 13
      STATIC_ENTRY(":status", "500"),                    // 14
      STATIC_ENTRY("accept-charset", ""),                // 15
      STATIC_ENTRY("accept-encoding", "gzip, deflate"),  // 16
      STATIC_ENTRY("accept-language", ""),               // 17
      STATIC_ENTRY("accept-ranges", ""),                 // 18
      STATIC_ENTRY("accept", ""),                        // 19
      STATIC_ENTRY("access-control-allow-origin", ""),   // 20
      STATIC_ENTRY("age", ""),                           // 21
      STATIC_ENTRY("allow", ""),                         // 22
      STATIC_ENTRY("authorization", ""),                 // 23
      STATIC_ENTRY("cache-control", ""),                 // 24
      STATIC_ENTRY("content-disposition", ""),           // 25
      STATIC_ENTRY("content-encoding", ""),              // 26
      STATIC_ENTRY("content-language", ""),              // 27
      STATIC_ENTRY("content-length", ""),                // 28
      STATIC_ENTRY("content-location", ""),              // 29
      STATIC_ENTRY("content-range", ""),                 // 30
      STATIC_ENTRY("content-type", ""),                  // 31
      STATIC_ENTRY("cookie", ""),                        // 32
      STATIC_ENTRY("date", ""),                          // 33
      STATIC_ENTRY("etag", ""),                          // 34
      STATIC_ENTRY("expect", ""),                        // 35
      STATIC_ENTRY("expires", ""),                       // 36
      STATIC_ENTRY("from", ""),                          // 37
      STATIC_ENTRY("host", ""),                          // 38
      STATIC_ENTRY("if-match", ""),                      // 39
      STATIC_ENTRY("if-modified-since", ""),             // 40
      STATIC_ENTRY("if-none-match", ""),                 // 41
      STATIC_ENTRY("if-range", ""),                      // 42
      STATIC_ENTRY("if-unmodified-since", ""),           // 43
      STATIC_ENTRY("last-modified", ""),                 // 44
      STATIC_ENTRY("link", ""),                          // 45
      STATIC_ENTRY("location", ""),                      // 46
      STATIC_ENTRY("max-forwards", ""),                  // 47
      STATIC_ENTRY("proxy-authenticate", ""),            // 48
      STATIC_ENTRY("proxy-authorization", ""),           // 49
      STATIC_ENTRY("range", ""),                         // 50
      STATIC_ENTRY("referer", ""),                       // 51
      STATIC_ENTRY("refresh", ""),                       // 52
      STATIC_ENTRY("retry-after", ""),                   // 53
      STATIC_ENTRY("server", ""),                        // 54
      STATIC_ENTRY("set-cookie", ""),                    // 55
      STATIC_ENTRY("strict-transport-security", ""),     // 56
      STATIC_ENTRY("transfer-encoding", ""),             // 57
      STATIC_ENTRY("user-agent", ""),                    // 58
      STATIC_ENTRY("vary", ""),                          // 59
      STATIC_ENTRY("via", ""),                           // 60
      STATIC_ENTRY("www-authenticate", ""),              // 61
  };
  return *kHpackStaticTable;
}

#undef STATIC_ENTRY

const HpackStaticTable& ObtainHpackStaticTable() {
  static const HpackStaticTable* const shared_static_table = []() {
    auto* table = new HpackStaticTable();
    table->Initialize(HpackStaticTableVector().data(),
                      HpackStaticTableVector().size());
    QUICHE_CHECK(table->IsInitialized());
    return table;
  }();
  return *shared_static_table;
}

}  // namespace spdy
```