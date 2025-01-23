Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed response.

1. **Understanding the Request:** The request asks for a functional description of the `cert_compressor.cc` file, its relation to JavaScript (if any), logical reasoning examples, common usage errors, and debugging hints.

2. **Initial Code Scan and High-Level Understanding:**  The first step is to quickly scan the code to grasp its overall purpose. Keywords like "compress," "decompress," "zlib," "cert," "hash," and "cached" immediately jump out. The file clearly deals with compressing and decompressing X.509 certificates, likely for efficiency in network communication. The presence of `kCommonCertSubstrings` suggests a dictionary-based compression approach.

3. **Deconstructing the Functionality (by Section/Function):**  Next, analyze the code section by section, focusing on each function and its role.

    * **`kCommonCertSubstrings`:**  Recognize this as a pre-defined dictionary used for zlib compression. Note its origin (Alexa Top 5000) and potential for improvement.

    * **`CertEntry` struct:**  Understand its purpose in representing a certificate, either as compressed data or a reference to a cached certificate using its hash. Pay attention to the `Type` enum.

    * **`MatchCerts`:** This is crucial for the core compression logic. It determines whether a certificate can be represented by a hash (if the client already has it) or needs to be compressed. The logic for checking against `client_cached_cert_hashes` is important.

    * **`CertEntriesSize`:**  A utility function to calculate the serialized size of the `CertEntry` vector. This is necessary before actual serialization.

    * **`SerializeCertEntries`:**  The function responsible for writing the `CertEntry` information into a byte stream. The format (type byte, optional hash) is key.

    * **`ZlibDictForEntries`:**  This function constructs the zlib dictionary. It combines client-cached certificates (in reverse order) and the `kCommonCertSubstrings`. This is a critical part of the compression strategy.

    * **`HashCerts`:**  A helper function to calculate the FNV-1a hashes of a list of certificates. This is used internally for comparing against cached certificates.

    * **`ParseEntries`:** The reverse of `SerializeCertEntries`. It reads the `CertEntry` stream and reconstructs the entries, potentially retrieving cached certificates based on hashes.

    * **`ScopedZLib`:**  A RAII wrapper for managing the zlib context (`z_stream`). This ensures proper initialization and cleanup (deflateEnd/inflateEnd).

    * **`CompressChain`:** The main compression function. It orchestrates the process:
        * Calls `MatchCerts` to determine the representation of each certificate.
        * Calculates the uncompressed size.
        * Initializes the zlib context with the dictionary.
        * Serializes the `CertEntry` vector.
        * Compresses the non-cached certificates using zlib.

    * **`DecompressChain`:** The main decompression function:
        * Parses the `CertEntry` vector using `ParseEntries`.
        * Reads the compressed data size (if present).
        * Initializes the zlib context, potentially setting the dictionary.
        * Decompresses the data.
        * Reconstructs the full certificates, retrieving cached ones.

4. **Identifying Functionality:** Based on the function analysis, summarize the core functionalities: certificate compression, decompression, leveraging cached certificates, and using a pre-shared dictionary.

5. **JavaScript Relationship:**  Realize that this C++ code runs on the server-side. The connection to JavaScript is indirect, through the network communication in a browser. Think about how certificates are used in HTTPS and TLS handshakes, which are initiated by the browser (running JavaScript). Focus on the *purpose* of this code in that context – reducing the size of certificate chains sent to the browser.

6. **Logical Reasoning (Input/Output):**  Choose simple scenarios to illustrate the logic of `MatchCerts`, `CompressChain`, and `DecompressChain`.

    * **Caching:**  Show how a certificate present in the `client_cached_cert_hashes` is represented differently.
    * **Compression:** Demonstrate the compression of a new certificate.
    * **Decompression:** Illustrate the reverse process.

7. **Common Usage Errors:**  Think about typical mistakes developers might make when using *or interacting with* this kind of code (even if they don't directly call these C++ functions).

    * **Mismatched Cached Hashes:** The client and server having different views of cached certificates.
    * **Incorrect Data Format:** Sending malformed compressed data.
    * **Resource Limits:**  Extremely large certificate chains.

8. **Debugging Hints (User Journey):**  Imagine a user encountering a problem related to certificates in a browser. Trace the steps that might lead to this code being involved in the debugging process. Start from the user's perspective (visiting a website) and go down to the network layer.

9. **Structuring the Response:** Organize the information logically using clear headings and bullet points. Provide specific examples and details where necessary. Use the information gathered in the previous steps to address each part of the request.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, ensure the JavaScript relationship is clearly explained as indirect. Double-check the assumptions made in the logical reasoning examples.

This methodical approach, breaking down the code into manageable parts, considering the broader context, and addressing each aspect of the request systematically, leads to a comprehensive and accurate response.
这个文件 `cert_compressor.cc` 实现了 Chromium 网络栈中用于压缩和解压缩 TLS 证书链的功能。其目的是为了减少在 TLS 握手过程中传输的证书数据量，从而加速连接建立和降低带宽消耗。

**以下是 `cert_compressor.cc` 的主要功能：**

1. **证书链压缩 (`CompressChain` 函数):**
   - 接收一个证书链（一个包含多个证书字符串的向量）和一个客户端缓存的证书哈希列表。
   - **利用客户端缓存：** 检查证书链中的每个证书是否已存在于客户端缓存中（通过哈希比对）。如果存在，则在压缩后的表示中用一个 64 位的哈希值来代替整个证书。
   - **Zlib 压缩：** 对于不在客户端缓存中的证书，使用 zlib 库进行压缩。
   - **预共享字典：**  为了提高 zlib 的压缩效率，使用了一个预定义的常见证书子字符串字典 (`kCommonCertSubstrings`)。此外，最近使用的（或缓存的）证书也会被添加到临时的 zlib 字典中。
   - **序列化：** 将压缩后的证书链信息序列化成一个字节流，包括：
     - 每个证书的条目信息 (`CertEntry`)，指示该证书是已缓存还是已压缩。
     - 如果是已缓存，包含证书的 64 位哈希值。
     - 如果是已压缩，包含原始证书的大小和压缩后的数据。

2. **证书链解压缩 (`DecompressChain` 函数):**
   - 接收一个包含压缩后证书链信息的字节流和一个客户端缓存的证书列表。
   - **解析条目信息：**  解析字节流，还原每个证书的条目信息 (`CertEntry`)。
   - **利用客户端缓存：** 如果条目指示证书已缓存，则通过哈希值在客户端缓存中查找对应的证书。
   - **Zlib 解压缩：** 对于条目指示证书已压缩的情况，使用 zlib 库进行解压缩，并使用相同的预共享字典和可能存在的临时字典。
   - **重建证书链：** 将解压缩后的证书和从缓存中获取的证书重新组合成完整的证书链。

**与 JavaScript 功能的关系：**

这个 C++ 文件本身并不直接与 JavaScript 代码交互。它是在 Chromium 浏览器的底层网络栈中运行的。然而，它的功能对运行在浏览器中的 JavaScript 代码有重要的影响，具体体现在以下方面：

- **HTTPS 连接速度：**  当 JavaScript 代码发起 HTTPS 请求时，浏览器会与服务器进行 TLS 握手。`cert_compressor.cc` 负责压缩服务器发送给浏览器的证书链，减少了网络传输的数据量，从而加快了 HTTPS 连接建立的速度。用户会感觉网页加载更快。
- **数据传输量减少：** 尤其是在移动网络等带宽受限的环境下，减少证书链的大小可以显著减少数据消耗，这对用户体验至关重要。
- **性能优化：**  更快的连接建立可以提升网页的整体性能，使得 JavaScript 代码能够更快地执行和与服务器交互。

**举例说明 (间接关系):**

假设一个 JavaScript 应用程序使用 `fetch` API 发起一个 HTTPS 请求：

```javascript
fetch('https://example.com/api/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，浏览器会与 `example.com` 的服务器建立 TLS 连接。`cert_compressor.cc` 的功能就在于优化这个 TLS 连接建立的过程：

1. 服务器会将它的证书链发送给浏览器。
2. 在发送之前，如果服务器也使用了类似的证书压缩机制，证书链会被压缩。
3. 浏览器接收到压缩后的证书链数据。
4. `net/third_party/quiche/src/quiche/quic/core/crypto/cert_compressor.cc` (或其他类似的解压缩代码) 会负责解压缩这些数据。
5. 浏览器验证证书链的有效性，并完成 TLS 握手。
6. 一旦 TLS 连接建立成功，JavaScript 的 `fetch` 请求才能安全地发送和接收数据。

**逻辑推理、假设输入与输出：**

**假设输入 (CompressChain):**

- `certs`:  一个包含两个证书的向量：
  - 证书 1: "MIICXg..." (一个较长的证书字符串)
  - 证书 2: "MIIBYz..." (另一个较长的证书字符串)
- `client_cached_cert_hashes`: 一个包含证书 2 哈希值的字节串 (假设证书 2 已经在客户端缓存中)。

**预期输出 (CompressChain):**

- 一个字节流，其结构可能如下：
  - 第一个字节表示证书 1 的类型 (COMPRESSED)。
  - 接下来 4 个字节表示证书 1 的原始大小。
  - 接下来的是证书 1 压缩后的数据 (使用 zlib 压缩)。
  - 接下来一个字节表示证书 2 的类型 (CACHED)。
  - 接下来 8 个字节是证书 2 的 64 位哈希值。
  - 最后一个字节是结束标记 (0)。

**假设输入 (DecompressChain):**

- `in`: 上面 `CompressChain` 的预期输出字节流。
- `cached_certs`: 一个包含证书 2 原始字符串的向量。

**预期输出 (DecompressChain):**

- `out_certs`: 一个包含两个证书的向量：
  - 第一个元素是证书 1 的原始字符串 ("MIICXg...") (已解压缩)。
  - 第二个元素是证书 2 的原始字符串 ("MIIBYz...") (从缓存中获取)。

**用户或编程常见的使用错误：**

1. **客户端和服务器缓存不一致：**  如果客户端声称缓存了某个证书，但实际上服务器发送的是该证书的压缩版本，解压缩过程可能会失败。这可能是由于缓存管理的错误或者客户端和服务端配置不同步导致的。

   **例子：** 用户清除浏览器缓存后，服务器仍然认为客户端缓存了某些证书，并发送压缩后的数据。客户端尝试解压缩，但找不到对应的缓存，导致连接失败。

2. **压缩数据损坏：**  在网络传输过程中，压缩后的证书数据可能发生损坏。`DecompressChain` 会因为 zlib 解压缩错误而返回失败。

   **例子：**  网络环境不稳定，导致压缩后的证书数据在传输过程中丢失或被篡改，解压缩时校验和不匹配。

3. **错误的缓存哈希传递：**  在 `CompressChain` 中，如果传递的 `client_cached_cert_hashes` 不正确，服务器可能错误地认为客户端没有缓存某个证书，从而不必要地压缩发送。虽然不会导致功能错误，但会降低效率。

   **例子：**  服务器端代码在获取客户端缓存哈希时出现错误，导致传递了过时或不完整的哈希列表。

4. **内存分配问题：**  在极少数情况下，如果证书链非常庞大，压缩或解压缩过程可能导致内存分配失败，尤其是在资源受限的环境中。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在浏览器中输入网址并访问一个 HTTPS 网站。**
2. **浏览器发起与服务器的 TCP 连接。**
3. **浏览器和服务器开始 TLS 握手过程。**
4. **服务器需要向浏览器证明其身份，这需要发送服务器的证书链。**
5. **服务器的网络栈代码（可能会使用类似的证书压缩逻辑）准备发送证书链。**
6. **浏览器接收到服务器发送的证书链数据。**
7. **浏览器的网络栈中的代码会调用 `CertCompressor::DecompressChain` 来解压缩接收到的证书链数据。**
8. **如果解压缩失败，可能会导致 TLS 握手失败，浏览器会显示连接不安全或证书错误的提示。**

**作为调试线索，可以检查以下方面：**

- **网络抓包：**  使用 Wireshark 等工具抓取网络包，查看服务器发送的证书链数据是否被压缩，以及压缩的格式是否正确。
- **浏览器网络日志：**  Chromium 浏览器的开发者工具 (F12) 的 "Network" 标签可以查看请求的详细信息，包括 TLS 握手的状态和证书信息。
- **Chromium 内部日志：**  可以通过启动带有特定标志的 Chromium 浏览器来收集更详细的网络栈日志，以查看证书压缩和解压缩过程中的错误信息。例如，可以使用 `--log-net-log` 标志来记录网络事件。
- **检查客户端缓存：**  查看浏览器本地缓存的证书信息，确认与服务器的假设是否一致。
- **服务端配置：**  确认服务器是否启用了证书压缩，以及使用的压缩算法和字典是否与客户端兼容。

总而言之，`cert_compressor.cc` 是 Chromium 网络栈中一个重要的性能优化组件，它通过高效地压缩和解压缩 TLS 证书链，提升了 HTTPS 连接的速度和效率，对最终用户的网络体验有着直接的影响。尽管 JavaScript 代码不直接调用这个 C++ 文件，但它的功能是支撑安全和快速 Web 连接的关键基础。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/cert_compressor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/cert_compressor.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "zlib.h"

namespace quic {

namespace {

// kCommonCertSubstrings contains ~1500 bytes of common certificate substrings
// in order to help zlib. This was generated via a fairly dumb algorithm from
// the Alexa Top 5000 set - we could probably do better.
static const unsigned char kCommonCertSubstrings[] = {
    0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
    0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
    0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30,
    0x5f, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x04, 0x01,
    0x06, 0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x86, 0xfd, 0x6d, 0x01, 0x07,
    0x17, 0x01, 0x30, 0x33, 0x20, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65,
    0x64, 0x20, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x20, 0x53, 0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x34,
    0x20, 0x53, 0x53, 0x4c, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31,
    0x32, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x53, 0x65, 0x72,
    0x76, 0x65, 0x72, 0x20, 0x43, 0x41, 0x30, 0x2d, 0x61, 0x69, 0x61, 0x2e,
    0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d,
    0x2f, 0x45, 0x2d, 0x63, 0x72, 0x6c, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x73,
    0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x45, 0x2e, 0x63, 0x65,
    0x72, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x4a, 0x2e, 0x63,
    0x6f, 0x6d, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73,
    0x2f, 0x63, 0x70, 0x73, 0x20, 0x28, 0x63, 0x29, 0x30, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05,
    0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x7b, 0x30, 0x1d, 0x06, 0x03, 0x55,
    0x1d, 0x0e, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
    0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd2,
    0x6f, 0x64, 0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x2e,
    0x63, 0x72, 0x6c, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
    0x04, 0x14, 0xb4, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69,
    0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x30, 0x0b, 0x06, 0x03,
    0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x01, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30,
    0x81, 0xca, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x08,
    0x13, 0x07, 0x41, 0x72, 0x69, 0x7a, 0x6f, 0x6e, 0x61, 0x31, 0x13, 0x30,
    0x11, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0a, 0x53, 0x63, 0x6f, 0x74,
    0x74, 0x73, 0x64, 0x61, 0x6c, 0x65, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x13, 0x11, 0x47, 0x6f, 0x44, 0x61, 0x64, 0x64, 0x79,
    0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x33,
    0x30, 0x31, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x2a, 0x68, 0x74, 0x74,
    0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
    0x61, 0x74, 0x65, 0x73, 0x2e, 0x67, 0x6f, 0x64, 0x61, 0x64, 0x64, 0x79,
    0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74,
    0x6f, 0x72, 0x79, 0x31, 0x30, 0x30, 0x2e, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x27, 0x47, 0x6f, 0x20, 0x44, 0x61, 0x64, 0x64, 0x79, 0x20, 0x53,
    0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
    0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68,
    0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55,
    0x04, 0x05, 0x13, 0x08, 0x30, 0x37, 0x39, 0x36, 0x39, 0x32, 0x38, 0x37,
    0x30, 0x1e, 0x17, 0x0d, 0x31, 0x31, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
    0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0c,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
    0x30, 0x1d, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55,
    0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x03, 0x02, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
    0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x33, 0x06, 0x03, 0x55, 0x1d,
    0x1f, 0x04, 0x2c, 0x30, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0xa0, 0x24, 0x86,
    0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e,
    0x67, 0x6f, 0x64, 0x61, 0x64, 0x64, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
    0x67, 0x64, 0x73, 0x31, 0x2d, 0x32, 0x30, 0x2a, 0x30, 0x28, 0x06, 0x08,
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1c, 0x68, 0x74,
    0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x76, 0x65,
    0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63,
    0x70, 0x73, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17,
    0x0d, 0x31, 0x33, 0x30, 0x35, 0x30, 0x39, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x2d, 0x68, 0x74, 0x74, 0x70, 0x3a,
    0x2f, 0x2f, 0x73, 0x30, 0x39, 0x30, 0x37, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x05, 0x05, 0x07, 0x02, 0x30, 0x44, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
    0x3d, 0x30, 0x3b, 0x30, 0x39, 0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x86,
    0xf8, 0x45, 0x01, 0x07, 0x17, 0x06, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x1b, 0x53, 0x31, 0x17,
    0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0e, 0x56, 0x65, 0x72,
    0x69, 0x53, 0x69, 0x67, 0x6e, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31,
    0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x16, 0x56, 0x65,
    0x72, 0x69, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74,
    0x20, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x31, 0x3b, 0x30, 0x39,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x32, 0x54, 0x65, 0x72, 0x6d, 0x73,
    0x20, 0x6f, 0x66, 0x20, 0x75, 0x73, 0x65, 0x20, 0x61, 0x74, 0x20, 0x68,
    0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x76,
    0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
    0x72, 0x70, 0x61, 0x20, 0x28, 0x63, 0x29, 0x30, 0x31, 0x10, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x53, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0a, 0x47, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01,
    0x03, 0x13, 0x02, 0x55, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x14, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
    0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0f, 0x13, 0x14, 0x50,
    0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x20, 0x4f, 0x72, 0x67, 0x61, 0x6e,
    0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x12, 0x31, 0x21, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x18, 0x44, 0x6f, 0x6d, 0x61,
    0x69, 0x6e, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20, 0x56,
    0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x64, 0x31, 0x14, 0x31, 0x31,
    0x30, 0x2f, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x28, 0x53, 0x65, 0x65,
    0x20, 0x77, 0x77, 0x77, 0x2e, 0x72, 0x3a, 0x2f, 0x2f, 0x73, 0x65, 0x63,
    0x75, 0x72, 0x65, 0x2e, 0x67, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53,
    0x69, 0x67, 0x6e, 0x31, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x41,
    0x2e, 0x63, 0x72, 0x6c, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67, 0x6e,
    0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x33, 0x20, 0x45, 0x63, 0x72,
    0x6c, 0x2e, 0x67, 0x65, 0x6f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x63,
    0x6f, 0x6d, 0x2f, 0x63, 0x72, 0x6c, 0x73, 0x2f, 0x73, 0x64, 0x31, 0x1a,
    0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x68, 0x74, 0x74, 0x70, 0x3a,
    0x2f, 0x2f, 0x45, 0x56, 0x49, 0x6e, 0x74, 0x6c, 0x2d, 0x63, 0x63, 0x72,
    0x74, 0x2e, 0x67, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x69, 0x63, 0x65, 0x72,
    0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x31, 0x6f, 0x63, 0x73, 0x70, 0x2e,
    0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d,
    0x30, 0x39, 0x72, 0x61, 0x70, 0x69, 0x64, 0x73, 0x73, 0x6c, 0x2e, 0x63,
    0x6f, 0x73, 0x2e, 0x67, 0x6f, 0x64, 0x61, 0x64, 0x64, 0x79, 0x2e, 0x63,
    0x6f, 0x6d, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72,
    0x79, 0x2f, 0x30, 0x81, 0x80, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
    0x07, 0x01, 0x01, 0x04, 0x74, 0x30, 0x72, 0x30, 0x24, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74,
    0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x67, 0x6f, 0x64,
    0x61, 0x64, 0x64, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x30, 0x4a, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x3e, 0x68,
    0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
    0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2e, 0x67, 0x6f, 0x64, 0x61, 0x64,
    0x64, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73,
    0x69, 0x74, 0x6f, 0x72, 0x79, 0x2f, 0x67, 0x64, 0x5f, 0x69, 0x6e, 0x74,
    0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x2e, 0x63, 0x72,
    0x74, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0xfd, 0xac, 0x61, 0x32, 0x93, 0x6c, 0x45, 0xd6, 0xe2, 0xee,
    0x85, 0x5f, 0x9a, 0xba, 0xe7, 0x76, 0x99, 0x68, 0xcc, 0xe7, 0x30, 0x27,
    0x86, 0x29, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x86, 0x30,
    0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73,
};

// CertEntry represents a certificate in compressed form. Each entry is one of
// the three types enumerated in |Type|.
struct CertEntry {
 public:
  enum Type {
    // Type 0 is reserved to mean "end of list" in the wire format.

    // COMPRESSED means that the certificate is included in the trailing zlib
    // data.
    COMPRESSED = 1,
    // CACHED means that the certificate is already known to the peer and will
    // be replaced by its 64-bit hash (in |hash|).
    CACHED = 2,
  };

  Type type;
  uint64_t hash;
  uint64_t set_hash;
  uint32_t index;
};

// MatchCerts returns a vector of CertEntries describing how to most
// efficiently represent |certs| to a peer who has cached the certificates
// with the 64-bit, FNV-1a hashes in |client_cached_cert_hashes|.
std::vector<CertEntry> MatchCerts(const std::vector<std::string>& certs,
                                  absl::string_view client_cached_cert_hashes) {
  std::vector<CertEntry> entries;
  entries.reserve(certs.size());

  const bool cached_valid =
      client_cached_cert_hashes.size() % sizeof(uint64_t) == 0 &&
      !client_cached_cert_hashes.empty();

  for (auto i = certs.begin(); i != certs.end(); ++i) {
    CertEntry entry;

    if (cached_valid) {
      bool cached = false;

      uint64_t hash = QuicUtils::FNV1a_64_Hash(*i);
      // This assumes that the machine is little-endian.
      for (size_t j = 0; j < client_cached_cert_hashes.size();
           j += sizeof(uint64_t)) {
        uint64_t cached_hash;
        memcpy(&cached_hash, client_cached_cert_hashes.data() + j,
               sizeof(uint64_t));
        if (hash != cached_hash) {
          continue;
        }

        entry.type = CertEntry::CACHED;
        entry.hash = hash;
        entries.push_back(entry);
        cached = true;
        break;
      }

      if (cached) {
        continue;
      }
    }

    entry.type = CertEntry::COMPRESSED;
    entries.push_back(entry);
  }

  return entries;
}

// CertEntriesSize returns the size, in bytes, of the serialised form of
// |entries|.
size_t CertEntriesSize(const std::vector<CertEntry>& entries) {
  size_t entries_size = 0;

  for (auto i = entries.begin(); i != entries.end(); ++i) {
    entries_size++;
    switch (i->type) {
      case CertEntry::COMPRESSED:
        break;
      case CertEntry::CACHED:
        entries_size += sizeof(uint64_t);
        break;
    }
  }

  entries_size++;  // for end marker

  return entries_size;
}

// SerializeCertEntries serialises |entries| to |out|, which must have enough
// space to contain them.
void SerializeCertEntries(uint8_t* out, const std::vector<CertEntry>& entries) {
  for (auto i = entries.begin(); i != entries.end(); ++i) {
    *out++ = static_cast<uint8_t>(i->type);
    switch (i->type) {
      case CertEntry::COMPRESSED:
        break;
      case CertEntry::CACHED:
        memcpy(out, &i->hash, sizeof(i->hash));
        out += sizeof(uint64_t);
        break;
    }
  }

  *out++ = 0;  // end marker
}

// ZlibDictForEntries returns a string that contains the zlib pre-shared
// dictionary to use in order to decompress a zlib block following |entries|.
// |certs| is one-to-one with |entries| and contains the certificates for those
// entries that are CACHED.
std::string ZlibDictForEntries(const std::vector<CertEntry>& entries,
                               const std::vector<std::string>& certs) {
  std::string zlib_dict;

  // The dictionary starts with the cached certs in reverse order.
  size_t zlib_dict_size = 0;
  for (size_t i = certs.size() - 1; i < certs.size(); i--) {
    if (entries[i].type != CertEntry::COMPRESSED) {
      zlib_dict_size += certs[i].size();
    }
  }

  // At the end of the dictionary is a block of common certificate substrings.
  zlib_dict_size += sizeof(kCommonCertSubstrings);

  zlib_dict.reserve(zlib_dict_size);

  for (size_t i = certs.size() - 1; i < certs.size(); i--) {
    if (entries[i].type != CertEntry::COMPRESSED) {
      zlib_dict += certs[i];
    }
  }

  zlib_dict += std::string(reinterpret_cast<const char*>(kCommonCertSubstrings),
                           sizeof(kCommonCertSubstrings));

  QUICHE_DCHECK_EQ(zlib_dict.size(), zlib_dict_size);

  return zlib_dict;
}

// HashCerts returns the FNV-1a hashes of |certs|.
std::vector<uint64_t> HashCerts(const std::vector<std::string>& certs) {
  std::vector<uint64_t> ret;
  ret.reserve(certs.size());

  for (auto i = certs.begin(); i != certs.end(); ++i) {
    ret.push_back(QuicUtils::FNV1a_64_Hash(*i));
  }

  return ret;
}

// ParseEntries parses the serialised form of a vector of CertEntries from
// |in_out| and writes them to |out_entries|. CACHED entries are resolved using
// |cached_certs| and written to |out_certs|. |in_out| is updated to contain
// the trailing data.
bool ParseEntries(absl::string_view* in_out,
                  const std::vector<std::string>& cached_certs,
                  std::vector<CertEntry>* out_entries,
                  std::vector<std::string>* out_certs) {
  absl::string_view in = *in_out;
  std::vector<uint64_t> cached_hashes;

  out_entries->clear();
  out_certs->clear();

  for (;;) {
    if (in.empty()) {
      return false;
    }
    CertEntry entry;
    const uint8_t type_byte = in[0];
    in.remove_prefix(1);

    if (type_byte == 0) {
      break;
    }

    entry.type = static_cast<CertEntry::Type>(type_byte);

    switch (entry.type) {
      case CertEntry::COMPRESSED:
        out_certs->push_back(std::string());
        break;
      case CertEntry::CACHED: {
        if (in.size() < sizeof(uint64_t)) {
          return false;
        }
        memcpy(&entry.hash, in.data(), sizeof(uint64_t));
        in.remove_prefix(sizeof(uint64_t));

        if (cached_hashes.size() != cached_certs.size()) {
          cached_hashes = HashCerts(cached_certs);
        }
        bool found = false;
        for (size_t i = 0; i < cached_hashes.size(); i++) {
          if (cached_hashes[i] == entry.hash) {
            out_certs->push_back(cached_certs[i]);
            found = true;
            break;
          }
        }
        if (!found) {
          return false;
        }
        break;
      }

      default:
        return false;
    }
    out_entries->push_back(entry);
  }

  *in_out = in;
  return true;
}

// ScopedZLib deals with the automatic destruction of a zlib context.
class ScopedZLib {
 public:
  enum Type {
    INFLATE,
    DEFLATE,
  };

  explicit ScopedZLib(Type type) : z_(nullptr), type_(type) {}

  void reset(z_stream* z) {
    Clear();
    z_ = z;
  }

  ~ScopedZLib() { Clear(); }

 private:
  void Clear() {
    if (!z_) {
      return;
    }

    if (type_ == DEFLATE) {
      deflateEnd(z_);
    } else {
      inflateEnd(z_);
    }
    z_ = nullptr;
  }

  z_stream* z_;
  const Type type_;
};

}  // anonymous namespace

// static
std::string CertCompressor::CompressChain(
    const std::vector<std::string>& certs,
    absl::string_view client_cached_cert_hashes) {
  const std::vector<CertEntry> entries =
      MatchCerts(certs, client_cached_cert_hashes);
  QUICHE_DCHECK_EQ(entries.size(), certs.size());

  size_t uncompressed_size = 0;
  for (size_t i = 0; i < entries.size(); i++) {
    if (entries[i].type == CertEntry::COMPRESSED) {
      uncompressed_size += 4 /* uint32_t length */ + certs[i].size();
    }
  }

  size_t compressed_size = 0;
  z_stream z;
  ScopedZLib scoped_z(ScopedZLib::DEFLATE);

  if (uncompressed_size > 0) {
    memset(&z, 0, sizeof(z));
    int rv = deflateInit(&z, Z_DEFAULT_COMPRESSION);
    QUICHE_DCHECK_EQ(Z_OK, rv);
    if (rv != Z_OK) {
      return "";
    }
    scoped_z.reset(&z);

    std::string zlib_dict = ZlibDictForEntries(entries, certs);

    rv = deflateSetDictionary(
        &z, reinterpret_cast<const uint8_t*>(&zlib_dict[0]), zlib_dict.size());
    QUICHE_DCHECK_EQ(Z_OK, rv);
    if (rv != Z_OK) {
      return "";
    }

    compressed_size = deflateBound(&z, uncompressed_size);
  }

  const size_t entries_size = CertEntriesSize(entries);

  std::string result;
  result.resize(entries_size + (uncompressed_size > 0 ? 4 : 0) +
                compressed_size);

  uint8_t* j = reinterpret_cast<uint8_t*>(&result[0]);
  SerializeCertEntries(j, entries);
  j += entries_size;

  if (uncompressed_size == 0) {
    return result;
  }

  uint32_t uncompressed_size_32 = uncompressed_size;
  memcpy(j, &uncompressed_size_32, sizeof(uint32_t));
  j += sizeof(uint32_t);

  int rv;

  z.next_out = j;
  z.avail_out = compressed_size;

  for (size_t i = 0; i < certs.size(); i++) {
    if (entries[i].type != CertEntry::COMPRESSED) {
      continue;
    }

    uint32_t length32 = certs[i].size();
    z.next_in = reinterpret_cast<uint8_t*>(&length32);
    z.avail_in = sizeof(length32);
    rv = deflate(&z, Z_NO_FLUSH);
    QUICHE_DCHECK_EQ(Z_OK, rv);
    QUICHE_DCHECK_EQ(0u, z.avail_in);
    if (rv != Z_OK || z.avail_in) {
      return "";
    }

    z.next_in =
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(certs[i].data()));
    z.avail_in = certs[i].size();
    rv = deflate(&z, Z_NO_FLUSH);
    QUICHE_DCHECK_EQ(Z_OK, rv);
    QUICHE_DCHECK_EQ(0u, z.avail_in);
    if (rv != Z_OK || z.avail_in) {
      return "";
    }
  }

  z.avail_in = 0;
  rv = deflate(&z, Z_FINISH);
  QUICHE_DCHECK_EQ(Z_STREAM_END, rv);
  if (rv != Z_STREAM_END) {
    return "";
  }

  result.resize(result.size() - z.avail_out);
  return result;
}

// static
bool CertCompressor::DecompressChain(
    absl::string_view in, const std::vector<std::string>& cached_certs,
    std::vector<std::string>* out_certs) {
  std::vector<CertEntry> entries;
  if (!ParseEntries(&in, cached_certs, &entries, out_certs)) {
    return false;
  }
  QUICHE_DCHECK_EQ(entries.size(), out_certs->size());

  std::unique_ptr<uint8_t[]> uncompressed_data;
  absl::string_view uncompressed;

  if (!in.empty()) {
    if (in.size() < sizeof(uint32_t)) {
      return false;
    }

    uint32_t uncompressed_size;
    memcpy(&uncompressed_size, in.data(), sizeof(uncompressed_size));
    in.remove_prefix(sizeof(uint32_t));

    if (uncompressed_size > 128 * 1024) {
      return false;
    }

    uncompressed_data = std::make_unique<uint8_t[]>(uncompressed_size);
    z_stream z;
    ScopedZLib scoped_z(ScopedZLib::INFLATE);

    memset(&z, 0, sizeof(z));
    z.next_out = uncompressed_data.get();
    z.avail_out = uncompressed_size;
    z.next_in =
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(in.data()));
    z.avail_in = in.size();

    if (Z_OK != inflateInit(&z)) {
      return false;
    }
    scoped_z.reset(&z);

    int rv = inflate(&z, Z_FINISH);
    if (rv == Z_NEED_DICT) {
      std::string zlib_dict = ZlibDictForEntries(entries, *out_certs);
      const uint8_t* dict = reinterpret_cast<const uint8_t*>(zlib_dict.data());
      if (Z_OK != inflateSetDictionary(&z, dict, zlib_dict.size())) {
        return false;
      }
      rv = inflate(&z, Z_FINISH);
    }

    if (Z_STREAM_END != rv || z.avail_out > 0 || z.avail_in > 0) {
      return false;
    }

    uncompressed = absl::string_view(
        reinterpret_cast<char*>(uncompressed_data.get()), uncompressed_size);
  }

  for (size_t i = 0; i < entries.size(); i++) {
    switch (entries[i].type) {
      case CertEntry::COMPRESSED:
        if (uncompressed.size() < sizeof(uint32_t)) {
          return false;
        }
        uint32_t cert_len;
        memcpy(&cert_len, uncompressed.data(), sizeof(cert_len));
        uncompressed.remove_prefix(sizeof(uint32_t));
        if (uncompressed.size() < cert_len) {
          return false;
        }
        (*out_certs)[i] = std::string(uncompressed.substr(0, cert_len));
        uncompressed.remove_prefix(cert_len);
        break;
      case CertEntry::CACHED:
        break;
    }
  }

  if (!uncompressed.empty()) {
    return false;
  }

  return true;
}

}  // namespace quic
```