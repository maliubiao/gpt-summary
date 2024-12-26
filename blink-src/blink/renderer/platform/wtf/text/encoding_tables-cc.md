Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `encoding_tables.cc` file in the Chromium Blink engine. It specifically wants to know about its relationship to web technologies (HTML, CSS, JavaScript), logical inferences, and potential usage errors.

2. **Initial Scan for Keywords and Structure:**  Quickly read through the code, looking for recognizable patterns and keywords. Notice:
    *  `Copyright` and licensing information.
    *  `#include` directives indicating dependencies on other modules (`encoding_tables.h`, `<unicode/ucnv.h>`, etc.). This immediately suggests the file deals with character encoding.
    *  `namespace WTF`. This is a good starting point for understanding the scope of the code.
    *  `constexpr std::array`, which suggests static data tables.
    *  Function definitions like `EnsureJis0208EncodeIndexForDecode()`, `EnsureJis0208EncodeIndexForEncode()`, etc. The "Ensure" prefix often implies lazy initialization or on-demand creation. The "ForDecode" and "ForEncode" suffixes clearly point towards different directions of encoding conversion.
    *  Use of ICU (`<unicode/ucnv.h>`). ICU is a well-known library for Unicode support, further confirming the file's purpose.
    *  Comments like "These are values from https://encoding.spec.whatwg.org/..." which directly links the code to web standards.
    *  `LEAK_SANITIZER_IGNORE_OBJECT` and `std::once_flag`, suggesting optimizations and thread-safety considerations.
    *  `DCHECK` and `SECURITY_DCHECK`, indicating internal assertions for debugging and security.

3. **Identify Core Functionality - Character Encoding Tables:** Based on the includes, function names, and comments, the central function is clearly related to character encoding tables. The different `Ensure...` functions likely correspond to different character encodings (JIS0208, JIS0212, EUC-KR, GB18030).

4. **Analyze Individual Functions:** Now, examine each `Ensure...` function in more detail.
    * **`EnsureJis0208EncodeIndexForDecode()`:**
        *  Comments indicate it handles JIS0208 encoding and specifically includes extra mappings not present in ICU.
        *  It uses ICU to convert from EUC-JP (a superset of JIS0208) to Unicode.
        *  It populates a static `Jis0208EncodeIndex` array.
    * **`EnsureJis0208EncodeIndexForEncode()`:**
        *  It reuses the data from `EnsureJis0208EncodeIndexForDecode()`.
        *  It swaps the key-value pairs (Unicode to encoded value) and sorts the table, which is a common optimization for efficient lookups during encoding.
    * **`EnsureJis0212EncodeIndexForDecode()`:** Similar to JIS0208 decode, but for JIS0212.
    * **`EnsureEucKrEncodeIndexForDecode()`:**  Handles EUC-KR encoding using ICU and a loop to map code points.
    * **`EnsureEucKrEncodeIndexForEncode()`:**  Similar to JIS0208 encode, reuses decode data, swaps, and sorts.
    * **`EnsureGb18030EncodeTable()`:** Creates a mapping table for GB18030 from encoded values to Unicode. It also incorporates specific differences based on a later version of the standard.
    * **`EnsureGb18030EncodeIndexForEncode()`:**  Creates the inverse mapping for GB18030, from Unicode to encoded values.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**  This is a crucial step. How does character encoding relate to web pages?
    * **HTML:** The `<meta charset>` tag directly specifies the encoding of an HTML document. The browser needs these encoding tables to correctly interpret the bytes received from the server and display the characters.
    * **CSS:** While CSS itself is mostly ASCII, it can contain Unicode characters (e.g., in `content` properties). The underlying rendering engine needs to understand the encoding to display these correctly.
    * **JavaScript:** JavaScript strings are typically UTF-16 internally. However, when JavaScript interacts with external data (e.g., fetching data from a server), it needs to handle different encodings. The browser uses these tables during the decoding/encoding process.

6. **Logical Inferences (Assumptions and Outputs):**  Think about the input and output of these functions.
    * **Decode functions:** Input is an encoded byte sequence (e.g., a byte from a JIS0208 encoded document). Output is the corresponding Unicode character.
    * **Encode functions:** Input is a Unicode character. Output is the corresponding encoded byte sequence.

7. **Common Usage Errors:** Consider how developers might misuse encoding.
    * **Incorrect `charset` declaration:**  This is a classic problem. If the declared encoding in the HTML doesn't match the actual encoding of the file, garbled text appears.
    * **Assuming default encoding:**  Relying on browser defaults can lead to inconsistencies.
    * **Mixing encodings:**  Embedding content with different encodings within the same page without proper handling.
    * **Server-side encoding issues:** The server might send data with an incorrect `Content-Type` header, leading to misinterpretation by the browser.

8. **Structure the Answer:** Organize the findings into logical sections as requested: functionality, relationship to web technologies, logical inferences, and common errors. Use clear language and examples.

9. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing details. For instance, initially, I might focus too heavily on the *implementation* details of the tables. The prompt asks for *functionality*, so I need to abstract that a bit more and focus on *what* the tables do rather than *how* they are built internally. Also, ensuring the examples are concrete and easy to understand is important.
这个文件 `blink/renderer/platform/wtf/text/encoding_tables.cc` 在 Chromium Blink 渲染引擎中扮演着至关重要的角色，它的主要功能是**提供各种字符编码的映射表，用于在不同的字符编码和 Unicode 之间进行转换**。

更具体地说，它包含了以下几个方面的功能：

**1. 提供特定字符编码的编码和解码映射表：**

*   这个文件定义并初始化了用于特定字符编码（如 JIS0208, JIS0212, EUC-KR, GB18030）的查找表。
*   这些表存储了编码值与 Unicode 字符之间的对应关系。
*   为了优化性能和减少内存占用，这些表的初始化通常是延迟的，只在第一次需要时才进行。

**2. 补充 ICU (International Components for Unicode) 库的不足：**

*   ICU 是一个强大的 Unicode 处理库，Blink 也使用了它。然而，对于某些特定的字符编码，ICU 的支持可能并不完整或者与 WHATWG 编码标准略有差异。
*   `encoding_tables.cc` 包含了一些 ICU 中缺失或者不同的映射关系，例如 JIS0208 编码中一些特殊的字符。

**3. 为文本编码和解码提供基础数据：**

*   Blink 引擎在处理网页内容时，需要根据网页声明的字符编码（例如在 HTML 的 `<meta charset>` 标签中指定）将接收到的字节流转换为 Unicode 字符，以便进行后续的渲染和处理。
*   反之，在将用户输入或者需要发送到网络的数据进行编码时，也需要将 Unicode 字符转换为特定的字节序列。
*   `encoding_tables.cc` 提供的映射表就是完成这些转换的关键数据。

**与 JavaScript, HTML, CSS 功能的关系及举例说明：**

`encoding_tables.cc` 虽然是一个底层的 C++ 文件，但它与 JavaScript, HTML, CSS 的功能息息相关，因为它直接影响着浏览器如何正确地**理解和显示网页上的文本**。

*   **HTML:**
    *   **功能关系：** HTML 文档的 `<meta charset>` 标签声明了文档的字符编码。浏览器会读取这个声明，并使用 `encoding_tables.cc` 中的映射表来解析 HTML 文件中的文本内容。
    *   **举例说明：**
        *   假设一个 HTML 文件声明了 `<meta charset="gbk">`。当浏览器解析这个文件时，会使用 GBK 编码表（可能是 GB18030 的子集，GB18030 包含了 GBK）来将 HTML 文件中的字节流转换为 Unicode 字符，从而正确显示中文文本。如果缺少或错误的编码表，中文可能会显示为乱码。
        *   用户在 HTML 表单中输入文本，浏览器需要根据表单的 `accept-charset` 属性（如果指定了）或文档的字符编码将用户输入的 Unicode 字符编码为字节流发送到服务器。这个过程也会用到这里的编码表。

*   **CSS:**
    *   **功能关系：** CSS 文件本身通常使用 UTF-8 编码，但 CSS 的 `content` 属性中可以包含 Unicode 字符。浏览器需要能够正确解析这些 Unicode 字符。
    *   **举例说明：**
        *   在 CSS 文件中，可以使用 Unicode 转义序列来表示特殊字符，例如 `content: "\201C"` 表示左双引号。浏览器在解析 CSS 时，需要知道 `\201C` 对应哪个 Unicode 字符。虽然这部分可能更多依赖于 ICU，但对于某些特殊情况，`encoding_tables.cc` 提供的补充映射可能也会被用到。

*   **JavaScript:**
    *   **功能关系：** JavaScript 字符串在内部使用 UTF-16 编码。当 JavaScript 代码处理来自网页的内容（例如通过 `document.getElementById().textContent` 获取文本）或者需要将文本写入网页时，都需要进行字符编码的转换。
    *   **举例说明：**
        *   如果一个网页使用 GBK 编码，JavaScript 通过 DOM API 获取的文本会被浏览器解码为 Unicode 字符。这个解码过程依赖于 `encoding_tables.cc` 中的 GBK 编码表。
        *   JavaScript 可以使用 `TextEncoder` 和 `TextDecoder` API 来进行文本编码和解码。这些 API 的底层实现会使用到 Blink 引擎提供的字符编码支持，包括 `encoding_tables.cc` 中的映射表。例如，可以使用 `new TextDecoder('gbk').decode(buffer)` 将 GBK 编码的 `ArrayBuffer` 解码为 JavaScript 字符串。

**逻辑推理 (假设输入与输出)：**

假设我们以 JIS0208 编码为例进行逻辑推理。

**假设输入（解码）：**

*   一个字节序列，例如 `0xB3 0xA3`，这是一个 JIS0208 编码的字符。

**输出（解码）：**

*   对应的 Unicode 字符。根据 JIS0208 编码表，`0xB3 0xA3` 对应着 Unicode 字符 `あ` (U+3042)。  `EnsureJis0208EncodeIndexForDecode()` 函数及其相关数据结构负责提供这种映射。

**假设输入（编码）：**

*   一个 Unicode 字符，例如 `い` (U+3044)。

**输出（编码）：**

*   对应的 JIS0208 编码字节序列。根据 JIS0208 编码表，`い` (U+3044) 对应着字节序列 `0xB3 0xA4`。 `EnsureJis0208EncodeIndexForEncode()` 函数及其相关数据结构负责提供这种反向映射。

**涉及用户或者编程常见的使用错误举例说明：**

虽然用户通常不直接与 `encoding_tables.cc` 交互，但编程错误或配置错误会导致浏览器依赖这些编码表时出现问题，最终影响用户体验。

*   **HTML 声明的编码与实际文件编码不一致：**
    *   **错误举例：** 一个 HTML 文件实际上是使用 UTF-8 编码保存的，但 `<meta charset="gbk">` 声明了使用 GBK 编码。
    *   **结果：** 浏览器会使用 GBK 编码表来解析 UTF-8 编码的文本，导致中文或其他非 ASCII 字符显示为乱码。这是用户最常遇到的编码问题。

*   **服务器发送错误的 `Content-Type` 头部：**
    *   **错误举例：** 服务器发送一个 UTF-8 编码的 HTML 文件，但 `Content-Type` 头部设置为 `text/html; charset=iso-8859-1`。
    *   **结果：** 浏览器会按照 ISO-8859-1 编码来解析 UTF-8 编码的文本，导致乱码。这会影响浏览器对页面字符编码的判断，即使 HTML 中声明了正确的编码也可能被覆盖。

*   **JavaScript 中使用错误的编码进行解码：**
    *   **错误举例：** 从服务器接收到一个 GBK 编码的文本数据，但在 JavaScript 中使用 `TextDecoder('utf-8').decode(buffer)` 进行解码。
    *   **结果：** 解码后的 JavaScript 字符串会包含错误的字符，导致后续的文本处理或显示出现问题。

*   **依赖浏览器默认编码而没有明确指定：**
    *   **错误举例：**  一些旧的网页可能没有明确声明字符编码。
    *   **结果：** 浏览器会尝试猜测或者使用默认编码，不同的浏览器或不同的用户区域设置可能使用不同的默认编码，导致在某些情况下页面显示正常，但在其他情况下出现乱码。

总而言之，`blink/renderer/platform/wtf/text/encoding_tables.cc` 是 Blink 引擎处理字符编码的核心组件之一，它确保了浏览器能够正确地理解和显示各种字符编码的网页内容，对于用户浏览体验至关重要。 开发者需要注意正确设置和处理字符编码，避免因编码问题导致显示错误。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/encoding_tables.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2020 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/text/encoding_tables.h"

#include <memory>
#include <mutex>

#include <unicode/ucnv.h>

#include "base/feature_list.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/text_codec_icu.h"

namespace WTF {

// These are values from https://encoding.spec.whatwg.org/index-jis0208.txt that
// are not in ICU.
constexpr std::array<std::pair<uint16_t, UChar>, 388> kJis0208Extras{
    {{10716, 0x2170}, {10717, 0x2171}, {10718, 0x2172}, {10719, 0x2173},
     {10720, 0x2174}, {10721, 0x2175}, {10722, 0x2176}, {10723, 0x2177},
     {10724, 0x2178}, {10725, 0x2179}, {10726, 0x2160}, {10727, 0x2161},
     {10728, 0x2162}, {10729, 0x2163}, {10730, 0x2164}, {10731, 0x2165},
     {10732, 0x2166}, {10733, 0x2167}, {10734, 0x2168}, {10735, 0x2169},
     {10736, 0xffe2}, {10737, 0xffe4}, {10738, 0xff07}, {10739, 0xff02},
     {10740, 0x3231}, {10741, 0x2116}, {10742, 0x2121}, {10743, 0x2235},
     {10744, 0x7e8a}, {10745, 0x891c}, {10746, 0x9348}, {10747, 0x9288},
     {10748, 0x84dc}, {10749, 0x4fc9}, {10750, 0x70bb}, {10751, 0x6631},
     {10752, 0x68c8}, {10753, 0x92f9}, {10754, 0x66fb}, {10755, 0x5f45},
     {10756, 0x4e28}, {10757, 0x4ee1}, {10758, 0x4efc}, {10759, 0x4f00},
     {10760, 0x4f03}, {10761, 0x4f39}, {10762, 0x4f56}, {10763, 0x4f92},
     {10764, 0x4f8a}, {10765, 0x4f9a}, {10766, 0x4f94}, {10767, 0x4fcd},
     {10768, 0x5040}, {10769, 0x5022}, {10770, 0x4fff}, {10771, 0x501e},
     {10772, 0x5046}, {10773, 0x5070}, {10774, 0x5042}, {10775, 0x5094},
     {10776, 0x50f4}, {10777, 0x50d8}, {10778, 0x514a}, {10779, 0x5164},
     {10780, 0x519d}, {10781, 0x51be}, {10782, 0x51ec}, {10783, 0x5215},
     {10784, 0x529c}, {10785, 0x52a6}, {10786, 0x52c0}, {10787, 0x52db},
     {10788, 0x5300}, {10789, 0x5307}, {10790, 0x5324}, {10791, 0x5372},
     {10792, 0x5393}, {10793, 0x53b2}, {10794, 0x53dd}, {10795, 0xfa0e},
     {10796, 0x549c}, {10797, 0x548a}, {10798, 0x54a9}, {10799, 0x54ff},
     {10800, 0x5586}, {10801, 0x5759}, {10802, 0x5765}, {10803, 0x57ac},
     {10804, 0x57c8}, {10805, 0x57c7}, {10806, 0xfa0f}, {10807, 0xfa10},
     {10808, 0x589e}, {10809, 0x58b2}, {10810, 0x590b}, {10811, 0x5953},
     {10812, 0x595b}, {10813, 0x595d}, {10814, 0x5963}, {10815, 0x59a4},
     {10816, 0x59ba}, {10817, 0x5b56}, {10818, 0x5bc0}, {10819, 0x752f},
     {10820, 0x5bd8}, {10821, 0x5bec}, {10822, 0x5c1e}, {10823, 0x5ca6},
     {10824, 0x5cba}, {10825, 0x5cf5}, {10826, 0x5d27}, {10827, 0x5d53},
     {10828, 0xfa11}, {10829, 0x5d42}, {10830, 0x5d6d}, {10831, 0x5db8},
     {10832, 0x5db9}, {10833, 0x5dd0}, {10834, 0x5f21}, {10835, 0x5f34},
     {10836, 0x5f67}, {10837, 0x5fb7}, {10838, 0x5fde}, {10839, 0x605d},
     {10840, 0x6085}, {10841, 0x608a}, {10842, 0x60de}, {10843, 0x60d5},
     {10844, 0x6120}, {10845, 0x60f2}, {10846, 0x6111}, {10847, 0x6137},
     {10848, 0x6130}, {10849, 0x6198}, {10850, 0x6213}, {10851, 0x62a6},
     {10852, 0x63f5}, {10853, 0x6460}, {10854, 0x649d}, {10855, 0x64ce},
     {10856, 0x654e}, {10857, 0x6600}, {10858, 0x6615}, {10859, 0x663b},
     {10860, 0x6609}, {10861, 0x662e}, {10862, 0x661e}, {10863, 0x6624},
     {10864, 0x6665}, {10865, 0x6657}, {10866, 0x6659}, {10867, 0xfa12},
     {10868, 0x6673}, {10869, 0x6699}, {10870, 0x66a0}, {10871, 0x66b2},
     {10872, 0x66bf}, {10873, 0x66fa}, {10874, 0x670e}, {10875, 0xf929},
     {10876, 0x6766}, {10877, 0x67bb}, {10878, 0x6852}, {10879, 0x67c0},
     {10880, 0x6801}, {10881, 0x6844}, {10882, 0x68cf}, {10883, 0xfa13},
     {10884, 0x6968}, {10885, 0xfa14}, {10886, 0x6998}, {10887, 0x69e2},
     {10888, 0x6a30}, {10889, 0x6a6b}, {10890, 0x6a46}, {10891, 0x6a73},
     {10892, 0x6a7e}, {10893, 0x6ae2}, {10894, 0x6ae4}, {10895, 0x6bd6},
     {10896, 0x6c3f}, {10897, 0x6c5c}, {10898, 0x6c86}, {10899, 0x6c6f},
     {10900, 0x6cda}, {10901, 0x6d04}, {10902, 0x6d87}, {10903, 0x6d6f},
     {10904, 0x6d96}, {10905, 0x6dac}, {10906, 0x6dcf}, {10907, 0x6df8},
     {10908, 0x6df2}, {10909, 0x6dfc}, {10910, 0x6e39}, {10911, 0x6e5c},
     {10912, 0x6e27}, {10913, 0x6e3c}, {10914, 0x6ebf}, {10915, 0x6f88},
     {10916, 0x6fb5}, {10917, 0x6ff5}, {10918, 0x7005}, {10919, 0x7007},
     {10920, 0x7028}, {10921, 0x7085}, {10922, 0x70ab}, {10923, 0x710f},
     {10924, 0x7104}, {10925, 0x715c}, {10926, 0x7146}, {10927, 0x7147},
     {10928, 0xfa15}, {10929, 0x71c1}, {10930, 0x71fe}, {10931, 0x72b1},
     {10932, 0x72be}, {10933, 0x7324}, {10934, 0xfa16}, {10935, 0x7377},
     {10936, 0x73bd}, {10937, 0x73c9}, {10938, 0x73d6}, {10939, 0x73e3},
     {10940, 0x73d2}, {10941, 0x7407}, {10942, 0x73f5}, {10943, 0x7426},
     {10944, 0x742a}, {10945, 0x7429}, {10946, 0x742e}, {10947, 0x7462},
     {10948, 0x7489}, {10949, 0x749f}, {10950, 0x7501}, {10951, 0x756f},
     {10952, 0x7682}, {10953, 0x769c}, {10954, 0x769e}, {10955, 0x769b},
     {10956, 0x76a6}, {10957, 0xfa17}, {10958, 0x7746}, {10959, 0x52af},
     {10960, 0x7821}, {10961, 0x784e}, {10962, 0x7864}, {10963, 0x787a},
     {10964, 0x7930}, {10965, 0xfa18}, {10966, 0xfa19}, {10967, 0xfa1a},
     {10968, 0x7994}, {10969, 0xfa1b}, {10970, 0x799b}, {10971, 0x7ad1},
     {10972, 0x7ae7}, {10973, 0xfa1c}, {10974, 0x7aeb}, {10975, 0x7b9e},
     {10976, 0xfa1d}, {10977, 0x7d48}, {10978, 0x7d5c}, {10979, 0x7db7},
     {10980, 0x7da0}, {10981, 0x7dd6}, {10982, 0x7e52}, {10983, 0x7f47},
     {10984, 0x7fa1}, {10985, 0xfa1e}, {10986, 0x8301}, {10987, 0x8362},
     {10988, 0x837f}, {10989, 0x83c7}, {10990, 0x83f6}, {10991, 0x8448},
     {10992, 0x84b4}, {10993, 0x8553}, {10994, 0x8559}, {10995, 0x856b},
     {10996, 0xfa1f}, {10997, 0x85b0}, {10998, 0xfa20}, {10999, 0xfa21},
     {11000, 0x8807}, {11001, 0x88f5}, {11002, 0x8a12}, {11003, 0x8a37},
     {11004, 0x8a79}, {11005, 0x8aa7}, {11006, 0x8abe}, {11007, 0x8adf},
     {11008, 0xfa22}, {11009, 0x8af6}, {11010, 0x8b53}, {11011, 0x8b7f},
     {11012, 0x8cf0}, {11013, 0x8cf4}, {11014, 0x8d12}, {11015, 0x8d76},
     {11016, 0xfa23}, {11017, 0x8ecf}, {11018, 0xfa24}, {11019, 0xfa25},
     {11020, 0x9067}, {11021, 0x90de}, {11022, 0xfa26}, {11023, 0x9115},
     {11024, 0x9127}, {11025, 0x91da}, {11026, 0x91d7}, {11027, 0x91de},
     {11028, 0x91ed}, {11029, 0x91ee}, {11030, 0x91e4}, {11031, 0x91e5},
     {11032, 0x9206}, {11033, 0x9210}, {11034, 0x920a}, {11035, 0x923a},
     {11036, 0x9240}, {11037, 0x923c}, {11038, 0x924e}, {11039, 0x9259},
     {11040, 0x9251}, {11041, 0x9239}, {11042, 0x9267}, {11043, 0x92a7},
     {11044, 0x9277}, {11045, 0x9278}, {11046, 0x92e7}, {11047, 0x92d7},
     {11048, 0x92d9}, {11049, 0x92d0}, {11050, 0xfa27}, {11051, 0x92d5},
     {11052, 0x92e0}, {11053, 0x92d3}, {11054, 0x9325}, {11055, 0x9321},
     {11056, 0x92fb}, {11057, 0xfa28}, {11058, 0x931e}, {11059, 0x92ff},
     {11060, 0x931d}, {11061, 0x9302}, {11062, 0x9370}, {11063, 0x9357},
     {11064, 0x93a4}, {11065, 0x93c6}, {11066, 0x93de}, {11067, 0x93f8},
     {11068, 0x9431}, {11069, 0x9445}, {11070, 0x9448}, {11071, 0x9592},
     {11072, 0xf9dc}, {11073, 0xfa29}, {11074, 0x969d}, {11075, 0x96af},
     {11076, 0x9733}, {11077, 0x973b}, {11078, 0x9743}, {11079, 0x974d},
     {11080, 0x974f}, {11081, 0x9751}, {11082, 0x9755}, {11083, 0x9857},
     {11084, 0x9865}, {11085, 0xfa2a}, {11086, 0xfa2b}, {11087, 0x9927},
     {11088, 0xfa2c}, {11089, 0x999e}, {11090, 0x9a4e}, {11091, 0x9ad9},
     {11092, 0x9adc}, {11093, 0x9b75}, {11094, 0x9b72}, {11095, 0x9b8f},
     {11096, 0x9bb1}, {11097, 0x9bbb}, {11098, 0x9c00}, {11099, 0x9d70},
     {11100, 0x9d6b}, {11101, 0xfa2d}, {11102, 0x9e19}, {11103, 0x9ed1}}};

const Jis0208EncodeIndex& EnsureJis0208EncodeIndexForDecode() {
  // Allocate this at runtime because building it at compile time would make the
  // binary much larger and this is often not used.
  static Jis0208EncodeIndex* array;
  LEAK_SANITIZER_IGNORE_OBJECT(array);
  static std::once_flag flag;
  std::call_once(flag, [] {
    array = new Jis0208EncodeIndex;
    size_t array_index = 0;

    UErrorCode error = U_ZERO_ERROR;
    ICUConverterWrapper icu_converter;
    icu_converter.converter = ucnv_open("EUC-JP", &error);
    DCHECK(U_SUCCESS(error));

    constexpr size_t kRange = 94;
    uint8_t icu_input[2];
    UChar icu_output;
    for (size_t i = 0; i < kRange; ++i) {
      for (size_t j = 0; j < kRange; ++j) {
        icu_input[0] = 0xA1 + i;
        icu_input[1] = 0xA1 + j;

        UChar* output = &icu_output;
        const char* input = reinterpret_cast<const char*>(icu_input);
        ucnv_toUnicode(icu_converter.converter, &output, output + 1, &input,
                       input + sizeof(icu_input), nullptr, true, &error);
        DCHECK(U_SUCCESS(error));
        if (icu_output != kReplacementCharacter) {
          uint16_t pointer = i * kRange + j;
          (*array)[array_index++] = {pointer, icu_output};
        }
      }
    }

    for (auto& extra : kJis0208Extras)
      (*array)[array_index++] = extra;
    SECURITY_DCHECK(array_index == kJis0208EncodeIndexSize);
  });
  return *array;
}

const Jis0208EncodeIndex& EnsureJis0208EncodeIndexForEncode() {
  // Allocate this at runtime because building it at compile time would make the
  // binary much larger and this is often not used.
  static Jis0208EncodeIndex* table;
  LEAK_SANITIZER_IGNORE_OBJECT(table);
  static std::once_flag once;
  std::call_once(once, [&] {
    table = new Jis0208EncodeIndex;
    auto& index = EnsureJis0208EncodeIndexForDecode();
    for (size_t i = 0; i < index.size(); ++i)
      (*table)[i] = {index[i].second, index[i].first};
    base::ranges::stable_sort(*table, CompareFirst{});
  });
  return *table;
}

const Jis0212EncodeIndex& EnsureJis0212EncodeIndexForDecode() {
  // Allocate this at runtime because building it at compile time would make the
  // binary much larger and this is often not used.
  static Jis0212EncodeIndex* array;
  LEAK_SANITIZER_IGNORE_OBJECT(array);
  static std::once_flag flag;
  std::call_once(flag, [] {
    array = new Jis0212EncodeIndex;
    size_t array_index = 0;

    UErrorCode error = U_ZERO_ERROR;
    ICUConverterWrapper icu_converter;
    icu_converter.converter = ucnv_open("EUC-JP", &error);
    DCHECK(U_SUCCESS(error));

    constexpr size_t kRange = 94;
    uint8_t icu_input[3];
    UChar icu_output;
    for (size_t i = 0; i < kRange; ++i) {
      for (size_t j = 0; j < kRange; ++j) {
        icu_input[0] = 0x8F;
        icu_input[1] = 0xA1 + i;
        icu_input[2] = 0xA1 + j;

        UChar* output = &icu_output;
        const char* input = reinterpret_cast<const char*>(icu_input);
        ucnv_toUnicode(icu_converter.converter, &output, output + 1, &input,
                       input + sizeof(icu_input), nullptr, true, &error);
        DCHECK(U_SUCCESS(error));
        if (icu_output != kReplacementCharacter) {
          uint16_t pointer = i * kRange + j;
          // ICU has some pointers above 7708 that are not in the encoding
          // standard.
          if (pointer < 7708)
            (*array)[array_index++] = {pointer, icu_output};
        }
      }
    }

    SECURITY_DCHECK(array_index == kJis0212EncodeIndexSize);
  });
  return *array;
}

const EucKrEncodeIndex& EnsureEucKrEncodeIndexForDecode() {
  // Allocate this at runtime because building it at compile time would make the
  // binary much larger and this is often not used.
  static EucKrEncodeIndex* array;
  LEAK_SANITIZER_IGNORE_OBJECT(array);
  static std::once_flag flag;
  std::call_once(flag, [] {
    array = new EucKrEncodeIndex;
    UErrorCode error = U_ZERO_ERROR;
    ICUConverterWrapper icu_converter;
    icu_converter.converter = ucnv_open("windows-949", &error);
    DCHECK(U_SUCCESS(error));
    auto get_pair =
        [&icu_converter](
            uint16_t pointer) -> std::optional<std::pair<uint16_t, UChar>> {
      std::array<uint8_t, 2> icu_input{
          static_cast<uint8_t>(pointer / 190u + 0x81),
          static_cast<uint8_t>(pointer % 190u + 0x41)};
      const char* input = reinterpret_cast<const char*>(icu_input.data());
      UChar icu_output[2];
      UChar* output = icu_output;
      UErrorCode error = U_ZERO_ERROR;
      ucnv_toUnicode(icu_converter.converter, &output, output + 2, &input,
                     input + sizeof(icu_input), nullptr, true, &error);
      DCHECK(U_SUCCESS(error));
      if (icu_output[0] == kReplacementCharacter)
        return std::nullopt;
      return {{pointer, icu_output[0]}};
    };
    size_t array_index = 0;
    for (uint16_t pointer = 0; pointer < 13776; pointer++) {
      if (auto pair = get_pair(pointer))
        (*array)[array_index++] = std::move(*pair);
    }
    for (uint16_t pointer = 13870; pointer < 23750; pointer++) {
      if (auto pair = get_pair(pointer))
        (*array)[array_index++] = std::move(*pair);
    }
    SECURITY_DCHECK(array_index == kEucKrEncodeIndexSize);
  });
  return *array;
}

const EucKrEncodeIndex& EnsureEucKrEncodeIndexForEncode() {
  // Allocate this at runtime because building it at compile time would make the
  // binary much larger and this is often not used.
  static EucKrEncodeIndex* table;
  LEAK_SANITIZER_IGNORE_OBJECT(table);
  static std::once_flag once;
  std::call_once(once, [&] {
    table = new EucKrEncodeIndex;
    auto& index = EnsureEucKrEncodeIndexForDecode();
    for (size_t i = 0; i < index.size(); ++i)
      (*table)[i] = {index[i].second, index[i].first};
    base::ranges::sort(*table, CompareFirst{});
    DCHECK(SortedFirstsAreUnique(*table));
  });
  return *table;
}

const Gb18030EncodeTable& EnsureGb18030EncodeTable() {
  // Allocate this at runtime because building it at compile time would make the
  // binary much larger and this is often not used.
  static Gb18030EncodeTable* array;
  LEAK_SANITIZER_IGNORE_OBJECT(array);
  static std::once_flag flag;
  std::call_once(flag, [] {
    array = new Gb18030EncodeTable;
    UErrorCode error = U_ZERO_ERROR;
    ICUConverterWrapper icu_converter;
    icu_converter.converter = ucnv_open("gb18030", &error);
    DCHECK(U_SUCCESS(error));
    for (size_t pointer = 0; pointer < 23940; pointer++) {
      uint8_t icu_input[2];
      icu_input[0] = pointer / 190 + 0x81;
      icu_input[1] = pointer % 190;
      icu_input[1] += (icu_input[1] < 0x3F) ? 0x40 : 0x41;
      UChar icu_output{0};
      UChar* output = &icu_output;
      const char* input = reinterpret_cast<const char*>(icu_input);
      ucnv_toUnicode(icu_converter.converter, &output, output + 1, &input,
                     input + sizeof(icu_input), nullptr, true, &error);
      DCHECK(U_SUCCESS(error));
      DCHECK_NE(icu_output, kReplacementCharacter);
      (*array)[pointer] = icu_output;
    }

    // Note: ICU4C that WebKit use has difference, but Chromium does not.
    DCHECK_EQ((*array)[6555], 0x3000);
  });

  constexpr std::array<std::pair<size_t, UChar>, 18> kGb18030_2022Differences{
      {{7182, 0xfe10},
       {7183, 0xfe12},
       {7184, 0xfe11},
       {7185, 0xfe13},
       {7186, 0xfe14},
       {7187, 0xfe15},
       {7188, 0xfe16},
       {7201, 0xfe17},
       {7202, 0xfe18},
       {7208, 0xfe19},
       {23775, 0x9fb4},
       {23783, 0x9fb5},
       {23788, 0x9fb6},
       {23789, 0x9fb7},
       {23795, 0x9fb8},
       {23812, 0x9fb9},
       {23829, 0x9fba},
       {23845, 0x9fbb}}};
  for (auto& pair : kGb18030_2022Differences) {
    (*array)[pair.first] = pair.second;
  }

  return *array;
}

const Gb18030EncodeIndex& EnsureGb18030EncodeIndexForEncode() {
  // Allocate this at runtime because building it at compile time would make the
  // binary much larger and this is often not used.
  static Gb18030EncodeIndex* table;
  LEAK_SANITIZER_IGNORE_OBJECT(table);
  static std::once_flag once;
  std::call_once(once, [&] {
    table = new Gb18030EncodeIndex;
    auto& index = EnsureGb18030EncodeTable();
    for (uint16_t i = 0; i < index.size(); ++i)
      (*table)[i] = {index[i], i};
    base::ranges::stable_sort(*table, CompareFirst{});
  });
  return *table;
}

}  // namespace WTF

"""

```