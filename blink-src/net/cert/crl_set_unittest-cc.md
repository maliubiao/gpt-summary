Response:
Let's break down the thought process for analyzing the C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the functionality of `crl_set_unittest.cc` within the Chromium networking stack. This involves identifying its purpose, how it relates to other concepts (like JavaScript), common errors, and debugging context.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for familiar keywords and structures. This immediately reveals:

* **`#include` directives:**  These tell us the code interacts with files related to:
    * `crl_set.h`:  The primary subject of the tests.
    * `base/files/file_util.h`: File system operations.
    * `crypto/sha2.h`: Cryptographic hashing.
    * `net/cert/...`: Various certificate-related functionalities.
    * `net/test/...`: Testing utilities.
    * `testing/gtest/...`: Google Test framework.
* **`namespace net { ... }`:**  Indicates this code belongs to the `net` namespace within Chromium.
* **`static const uint8_t ...`:**  Declaration of constant byte arrays likely representing serialized data.
* **`TEST(CRLSetTest, ...)` and `TEST(CertVerifyProcTest, ...)`:**  These are Google Test macros, clearly indicating this file contains unit tests.
* **Function calls like `CRLSet::Parse()`, `set->CheckSerial()`, `set->CheckSPKI()`, `set->CheckSubject()`, `set->IsExpired()`:** These suggest the `CRLSet` class has methods for parsing CRL data and checking certificate revocation status based on serial numbers, Subject Public Key Info (SPKI) hashes, and certificate subjects.

**3. Identifying the Core Functionality:**

Based on the keywords and test names, the central theme is **testing the `CRLSet` class**. `CRLSet` likely deals with Certificate Revocation Lists (CRLs) – data structures that list revoked certificates. The tests verify how `CRLSet` parses, stores, and uses this revocation information.

**4. Analyzing Individual Tests:**

Now, examine each `TEST` function in more detail:

* **`Parse`:**  Tests if `CRLSet::Parse()` correctly deserializes CRL data from a byte array (`kGIACRLSet`). It verifies the number of revoked serials and checks if specific serials are correctly identified as revoked or good.
* **`BlockedSPKIs`:** Focuses on testing the blocking of specific Subject Public Key Info (SPKI) hashes. It checks if `CRLSet::CheckSPKI()` correctly identifies a hardcoded SPKI hash as revoked.
* **`CertVerifyProcTest, CRLSetIncorporatesStaticBlocklist`:** This test verifies that the `CRLSet` (both a parsed instance and the built-in one) includes a static list of blocked certificates, specifically those related to DigiNotar. It loads DigiNotar certificates and checks if their SPKI hashes are marked as revoked.
* **`BlockedSubjects`:** Examines how `CRLSet` handles blocking based on certificate subjects. It verifies that a specific subject is considered revoked when associated with an unknown SPKI but accepted when the correct SPKI is provided. This suggests a mechanism to block certificates issued by certain authorities unless they are used with a known good key.
* **`Expired`:** Checks if `CRLSet::IsExpired()` correctly identifies a CRL set with an expired timestamp.

**5. Addressing the Prompt's Specific Questions:**

* **Functionality:**  Summarize the core functionalities observed in the tests (parsing, checking serials, SPKIs, subjects, expiration).
* **Relationship to JavaScript:** Consider if any of the tested functionalities directly translate to JavaScript in a browser context. Certificate revocation checking *does* happen in browsers, but the low-level implementation using `CRLSet` is typically hidden from direct JavaScript interaction. JavaScript might trigger certificate validation, but it doesn't directly manipulate `CRLSet` objects.
* **Logic and Assumptions:** For each test, identify the assumed input (the byte array, certificate data) and the expected output (true/false for parsing, `REVOKED`/`GOOD` status).
* **User/Programming Errors:** Think about how misuse of the `CRLSet` class or related concepts could lead to errors. For instance, providing invalid CRL data, not updating CRL sets, or assuming a certificate is valid when it's on a CRL.
* **User Steps to Reach This Code (Debugging):**  Imagine the scenarios where this code would be relevant during debugging. This involves SSL/TLS connection failures, certificate validation errors, and security-related issues where CRLs play a role.

**6. Structuring the Answer:**

Organize the findings into clear sections addressing each part of the prompt. Use headings and bullet points for readability. Provide concrete examples where possible (like the DigiNotar case).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Might initially focus too much on the byte arrays without understanding their purpose. Realize they represent serialized CRL data.
* **Considering JavaScript:** Initially might think there's no connection, but then refine it to explain that while JavaScript doesn't directly use `CRLSet`, it's indirectly involved in the higher-level process of certificate validation.
* **Debugging:** Initially might be too general. Focus on specific scenarios where CRLs are relevant (e.g., a website's certificate being revoked).

By following this systematic approach, combining code analysis with an understanding of the surrounding concepts (like certificate revocation and testing), one can effectively answer the prompt and provide a comprehensive explanation of the `crl_set_unittest.cc` file.
好的，让我们来分析一下 `net/cert/crl_set_unittest.cc` 这个文件。

**文件功能概述**

`crl_set_unittest.cc` 是 Chromium 网络栈中用于测试 `CRLSet` 类的单元测试文件。`CRLSet` 类主要负责处理证书撤销列表（Certificate Revocation Lists，CRLs）。这个文件包含了多个测试用例，用于验证 `CRLSet` 类的各种功能是否正常工作。

具体来说，这个文件测试了以下功能：

1. **解析 CRLSet 数据:** 测试 `CRLSet::Parse()` 方法能否正确解析预先定义好的二进制 CRLSet 数据 (例如 `kGIACRLSet`, `kBlockedSPKICRLSet`, `kExpiredCRLSet`)。这包括验证数据结构是否被正确解析，例如撤销证书的序列号列表。
2. **检查证书序列号是否被撤销:** 测试 `CRLSet::CheckSerial()` 方法，判断给定的证书序列号是否在 CRLSet 中被标记为已撤销。这需要提供证书的序列号以及颁发者公钥信息 (SPKI) 的哈希值。
3. **检查 SPKI 是否被阻止:** 测试 `CRLSet::CheckSPKI()` 方法，判断给定的 SPKI 哈希值是否在 CRLSet 中被明确阻止。这用于实现对特定 CA 或中间 CA 的全面阻止。
4. **集成静态阻止列表:** 验证 `CRLSet` 类是否包含了静态配置的证书阻止列表，例如针对 DigiNotar 事件中涉及的证书。
5. **检查证书主题是否被阻止:** 测试 `CRLSet::CheckSubject()` 方法，判断给定的证书主题 (Subject DN) 是否在 CRLSet 中被阻止。这通常与特定的 SPKI 哈希关联。
6. **检查 CRLSet 是否过期:** 测试 `CRLSet::IsExpired()` 方法，判断 CRLSet 是否已过期。

**与 JavaScript 的关系**

`crl_set_unittest.cc` 本身是用 C++ 编写的，直接与 JavaScript 没有代码级别的交互。然而，它测试的 `CRLSet` 类在浏览器安全机制中扮演着关键角色，而这些安全机制会影响到 JavaScript 代码的执行环境。

**举例说明:**

当一个网站使用 HTTPS 连接时，浏览器会验证服务器提供的 SSL/TLS 证书。这个验证过程包括检查证书是否在 CRL 中被撤销。

1. **用户在浏览器地址栏输入一个 HTTPS 网站的 URL，或者点击一个 HTTPS 链接。**
2. **浏览器发起 HTTPS 连接请求。**
3. **服务器返回其 SSL/TLS 证书。**
4. **浏览器网络栈会使用 `CRLSet` (或其他机制，如 OCSP) 来检查该证书是否已被撤销。**
5. **如果 `CRLSet` 判断证书已被撤销，浏览器会阻止连接，并可能向用户显示一个安全警告页面。**
6. **JavaScript 代码在这种情况下可能根本无法执行，或者只能在一个受限的环境中执行，因为浏览器阻止了与不安全站点的连接。**

**假设输入与输出 (逻辑推理)**

以下是一些基于测试用例的假设输入和输出：

**测试 `Parse`:**

* **假设输入:**  一个包含有效 CRLSet 数据的 `std::string_view`，例如 `reinterpret_cast<const char*>(kGIACRLSet)`.
* **预期输出:** `CRLSet::Parse()` 返回 `true`，并且输出参数 `set` 指向一个成功解析的 `CRLSet` 对象。该对象的内部数据结构应该包含从输入数据中提取的撤销证书序列号等信息。

**测试 `CheckSerial`:**

* **假设输入:**
    * `serial_number`: 一个表示证书序列号的 `std::string`，例如 `"\x16\x7D\x75\x9D\x00\x03\x00\x00\x14\x55"`.
    * `spki_hash`: 颁发者公钥信息的 SHA256 哈希值，例如 `kGIASPKISHA256`.
* **预期输出:**
    * 如果序列号在 CRLSet 中且与 SPKI 哈希匹配，`CheckSerial()` 返回 `CRLSet::REVOKED`.
    * 如果序列号不在 CRLSet 中，`CheckSerial()` 返回 `CRLSet::GOOD`.

**测试 `CheckSPKI`:**

* **假设输入:** 一个 SPKI 的 SHA256 哈希值，例如 DigiNotar 根证书的哈希值。
* **预期输出:** 如果该 SPKI 哈希在 CRLSet 的阻止列表中，`CheckSPKI()` 返回 `CRLSet::REVOKED`.

**测试 `IsExpired`:**

* **假设输入:** 一个包含过期时间戳的 CRLSet 数据，例如 `kExpiredCRLSet`.
* **预期输出:** `IsExpired()` 方法返回 `true`.

**用户或编程常见的使用错误**

1. **CRLSet 数据损坏或解析失败:**
   * **错误示例:**  手动修改 CRLSet 数据导致格式错误。
   * **后果:** `CRLSet::Parse()` 返回 `false`，导致证书撤销检查功能失效或异常。
2. **未能及时更新 CRLSet:**
   * **错误示例:** 用户或程序使用了过时的 CRLSet 数据。
   * **后果:** 新近被撤销的证书可能被错误地认为是有效的，导致安全风险。
3. **错误地假设 CRLSet 包含了所有撤销信息:**
   * **错误示例:** 依赖 CRLSet 作为唯一的证书撤销来源，而忽略了 OCSP 等其他机制。
   * **后果:**  可能无法检测到所有被撤销的证书。
4. **在性能敏感的场景中频繁解析大型 CRLSet:**
   * **错误示例:**  在每次连接时都重新解析整个 CRLSet。
   * **后果:** 导致性能下降。`CRLSet` 通常会被缓存以提高效率。

**用户操作如何到达这里 (调试线索)**

当开发者在 Chromium 网络栈中遇到与证书撤销相关的问题时，可能会需要查看 `crl_set_unittest.cc` 中的测试用例来理解 `CRLSet` 的行为。以下是一些可能的场景：

1. **证书验证失败:** 用户报告某些网站连接失败，出现证书相关的错误。开发者可能会查看 `CRLSet` 的相关代码来确认是否由于证书被撤销导致。
2. **安全漏洞调查:** 如果发现某个被撤销的证书仍然被浏览器信任，开发者可能会检查 `CRLSet` 的更新机制和实现逻辑。
3. **性能优化:**  如果证书撤销检查被认为是性能瓶颈，开发者可能会研究 `CRLSet` 的数据结构和查找算法。
4. **新功能开发:** 在开发与证书处理相关的新功能时，开发者可能会参考 `CRLSet` 的实现来确保新功能的正确性和安全性。

**调试步骤示例:**

假设用户报告访问某个网站时出现 `NET::ERR_CERT_REVOKED` 错误，开发者可以按照以下步骤进行调试，其中可能涉及到 `crl_set_unittest.cc`：

1. **确认错误信息:** 用户看到的错误信息是 `NET::ERR_CERT_REVOKED`，表明浏览器认为服务器证书已被撤销。
2. **检查证书信息:**  开发者需要获取该网站的证书详细信息（例如，使用 Chrome 的开发者工具 -> 安全）。
3. **分析证书链:** 查看证书链中的各个证书，包括服务器证书和中间 CA 证书。
4. **检查 CRL 和 OCSP 信息:** 查看证书中是否包含 CRL 分发点（CRL Distribution Points）或权威证书状态协议（OCSP）信息。
5. **本地 CRLSet 检查 (模拟):**  开发者可能会尝试使用 `crl_set_unittest.cc` 中的测试用例来模拟 `CRLSet` 的检查过程。例如，他们可能会尝试解析一个已知的 CRLSet 文件，并使用证书的序列号和颁发者 SPKI 哈希来测试 `CheckSerial()` 方法。
6. **查看 Chromium 源码:**  如果本地测试无法重现问题，开发者可能会深入研究 `net/cert/crl_set.cc` 和 `net/cert/cert_verify_proc.cc` 等相关源码，了解证书撤销检查的完整流程。
7. **动态调试:**  在开发环境中，可以使用调试器来跟踪证书验证过程，查看 `CRLSet` 的状态和 `CheckSerial()` 等方法的返回值。

总而言之，`crl_set_unittest.cc` 是 Chromium 网络栈中一个重要的测试文件，它确保了 `CRLSet` 类能够正确地处理证书撤销信息，从而维护浏览器的安全性和用户的信任。虽然它本身是 C++ 代码，但其功能直接影响到 Web 浏览的安全性，并间接地影响到 JavaScript 代码的执行环境。

Prompt: 
```
这是目录为net/cert/crl_set_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/cert/crl_set.h"

#include <string_view>

#include "base/files/file_util.h"
#include "crypto/sha2.h"
#include "net/cert/asn1_util.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

// These data blocks were generated using a lot of code that is still in
// development. For now, if you need to update them, you have to contact agl.
static const uint8_t kGIACRLSet[] = {
  0x60, 0x00, 0x7b, 0x22, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a,
  0x30, 0x2c, 0x22, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70,
  0x65, 0x22, 0x3a, 0x22, 0x43, 0x52, 0x4c, 0x53, 0x65, 0x74, 0x22, 0x2c, 0x22,
  0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x22, 0x3a, 0x30, 0x2c, 0x22,
  0x44, 0x65, 0x6c, 0x74, 0x61, 0x46, 0x72, 0x6f, 0x6d, 0x22, 0x3a, 0x30, 0x2c,
  0x22, 0x4e, 0x75, 0x6d, 0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x3a,
  0x31, 0x2c, 0x22, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x53, 0x50, 0x4b,
  0x49, 0x73, 0x22, 0x3a, 0x5b, 0x5d, 0x7d, 0xb6, 0xb9, 0x54, 0x32, 0xab, 0xae,
  0x57, 0xfe, 0x02, 0x0c, 0xb2, 0xb7, 0x4f, 0x4f, 0x9f, 0x91, 0x73, 0xc8, 0xc7,
  0x08, 0xaf, 0xc9, 0xe7, 0x32, 0xac, 0xe2, 0x32, 0x79, 0x04, 0x7c, 0x6d, 0x05,
  0x0d, 0x00, 0x00, 0x00, 0x0a, 0x10, 0x0d, 0x7f, 0x30, 0x00, 0x03, 0x00, 0x00,
  0x23, 0xb0, 0x0a, 0x10, 0x0e, 0x37, 0x06, 0x00, 0x03, 0x00, 0x00, 0x23, 0xb1,
  0x0a, 0x16, 0x25, 0x42, 0x54, 0x00, 0x03, 0x00, 0x00, 0x14, 0x51, 0x0a, 0x16,
  0x69, 0xd1, 0xd7, 0x00, 0x03, 0x00, 0x00, 0x14, 0x52, 0x0a, 0x16, 0x70, 0x8c,
  0x22, 0x00, 0x03, 0x00, 0x00, 0x14, 0x53, 0x0a, 0x16, 0x71, 0x31, 0x2c, 0x00,
  0x03, 0x00, 0x00, 0x14, 0x54, 0x0a, 0x16, 0x7d, 0x75, 0x9d, 0x00, 0x03, 0x00,
  0x00, 0x14, 0x55, 0x0a, 0x1f, 0xee, 0xf9, 0x49, 0x00, 0x03, 0x00, 0x00, 0x23,
  0xae, 0x0a, 0x1f, 0xfc, 0xd1, 0x89, 0x00, 0x03, 0x00, 0x00, 0x23, 0xaf, 0x0a,
  0x61, 0xdd, 0xc7, 0x48, 0x00, 0x03, 0x00, 0x00, 0x18, 0x0e, 0x0a, 0x61, 0xe6,
  0x12, 0x64, 0x00, 0x03, 0x00, 0x00, 0x18, 0x0f, 0x0a, 0x61, 0xe9, 0x46, 0x56,
  0x00, 0x03, 0x00, 0x00, 0x18, 0x10, 0x0a, 0x64, 0x63, 0x49, 0xd2, 0x00, 0x03,
  0x00, 0x00, 0x1d, 0x77,
};

static const uint8_t kBlockedSPKICRLSet[] = {
  0x8e, 0x00, 0x7b, 0x22, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a,
  0x30, 0x2c, 0x22, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70,
  0x65, 0x22, 0x3a, 0x22, 0x43, 0x52, 0x4c, 0x53, 0x65, 0x74, 0x22, 0x2c, 0x22,
  0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x22, 0x3a, 0x30, 0x2c, 0x22,
  0x44, 0x65, 0x6c, 0x74, 0x61, 0x46, 0x72, 0x6f, 0x6d, 0x22, 0x3a, 0x30, 0x2c,
  0x22, 0x4e, 0x75, 0x6d, 0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x3a,
  0x30, 0x2c, 0x22, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x53, 0x50, 0x4b,
  0x49, 0x73, 0x22, 0x3a, 0x5b, 0x22, 0x34, 0x37, 0x44, 0x45, 0x51, 0x70, 0x6a,
  0x38, 0x48, 0x42, 0x53, 0x61, 0x2b, 0x2f, 0x54, 0x49, 0x6d, 0x57, 0x2b, 0x35,
  0x4a, 0x43, 0x65, 0x75, 0x51, 0x65, 0x52, 0x6b, 0x6d, 0x35, 0x4e, 0x4d, 0x70,
  0x4a, 0x57, 0x5a, 0x47, 0x33, 0x68, 0x53, 0x75, 0x46, 0x55, 0x3d, 0x22, 0x5d,
  0x7d,
};

static const uint8_t kExpiredCRLSet[] = {
  0x6d, 0x00, 0x7b, 0x22, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a,
  0x30, 0x2c, 0x22, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70,
  0x65, 0x22, 0x3a, 0x22, 0x43, 0x52, 0x4c, 0x53, 0x65, 0x74, 0x22, 0x2c, 0x22,
  0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x22, 0x3a, 0x31, 0x2c, 0x22,
  0x44, 0x65, 0x6c, 0x74, 0x61, 0x46, 0x72, 0x6f, 0x6d, 0x22, 0x3a, 0x30, 0x2c,
  0x22, 0x4e, 0x75, 0x6d, 0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x3a,
  0x30, 0x2c, 0x22, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x53, 0x50, 0x4b,
  0x49, 0x73, 0x22, 0x3a, 0x5b, 0x5d, 0x2c, 0x22, 0x4e, 0x6f, 0x74, 0x41, 0x66,
  0x74, 0x65, 0x72, 0x22, 0x3a, 0x31, 0x7d,
};

// kGIASPKISHA256 is the SHA256 digest the Google Internet Authority's
// SubjectPublicKeyInfo.
static const uint8_t kGIASPKISHA256[32] = {
  0xb6, 0xb9, 0x54, 0x32, 0xab, 0xae, 0x57, 0xfe, 0x02, 0x0c, 0xb2, 0xb7, 0x4f,
  0x4f, 0x9f, 0x91, 0x73, 0xc8, 0xc7, 0x08, 0xaf, 0xc9, 0xe7, 0x32, 0xac, 0xe2,
  0x32, 0x79, 0x04, 0x7c, 0x6d, 0x05,
};

TEST(CRLSetTest, Parse) {
  std::string_view s(reinterpret_cast<const char*>(kGIACRLSet),
                     sizeof(kGIACRLSet));
  scoped_refptr<CRLSet> set;
  EXPECT_TRUE(CRLSet::Parse(s, &set));
  ASSERT_TRUE(set.get() != nullptr);

  const CRLSet::CRLList& crls = set->CrlsForTesting();
  ASSERT_EQ(1u, crls.size());
  const std::vector<std::string>& serials = crls.begin()->second;
  static const unsigned kExpectedNumSerials = 13;
  ASSERT_EQ(kExpectedNumSerials, serials.size());
  EXPECT_EQ(std::string("\x10\x0D\x7F\x30\x00\x03\x00\x00\x23\xB0", 10),
            serials[0]);
  EXPECT_EQ(std::string("\x64\x63\x49\xD2\x00\x03\x00\x00\x1D\x77", 10),
            serials[kExpectedNumSerials - 1]);

  const std::string gia_spki_hash(reinterpret_cast<const char*>(kGIASPKISHA256),
                                  sizeof(kGIASPKISHA256));
  EXPECT_EQ(CRLSet::REVOKED,
            set->CheckSerial(
                std::string("\x16\x7D\x75\x9D\x00\x03\x00\x00\x14\x55", 10),
                gia_spki_hash));
  EXPECT_EQ(CRLSet::GOOD,
            set->CheckSerial(
                std::string("\x47\x54\x3E\x79\x00\x03\x00\x00\x14\xF5", 10),
                gia_spki_hash));

  EXPECT_FALSE(set->IsExpired());
}

TEST(CRLSetTest, BlockedSPKIs) {
  std::string_view s(reinterpret_cast<const char*>(kBlockedSPKICRLSet),
                     sizeof(kBlockedSPKICRLSet));
  scoped_refptr<CRLSet> set;
  EXPECT_TRUE(CRLSet::Parse(s, &set));
  ASSERT_TRUE(set.get() != nullptr);

  const uint8_t spki_hash[] = {
    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36,
    39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
    0,
  };

  EXPECT_EQ(CRLSet::GOOD, set->CheckSPKI(""));
  EXPECT_EQ(CRLSet::REVOKED,
            set->CheckSPKI(reinterpret_cast<const char*>(spki_hash)));
}

TEST(CertVerifyProcTest, CRLSetIncorporatesStaticBlocklist) {
  // Test both the builtin CRLSet and a parsed CRLSet to be sure that both
  // include the block list.
  scoped_refptr<CRLSet> set1 = CRLSet::BuiltinCRLSet();
  ASSERT_TRUE(set1);
  std::string_view s(reinterpret_cast<const char*>(kGIACRLSet),
                     sizeof(kGIACRLSet));
  scoped_refptr<CRLSet> set2;
  EXPECT_TRUE(CRLSet::Parse(s, &set2));
  ASSERT_TRUE(set2);

  static const char* const kDigiNotarFilenames[] = {
      "diginotar_root_ca.pem",          "diginotar_cyber_ca.pem",
      "diginotar_services_1024_ca.pem", "diginotar_pkioverheid.pem",
      "diginotar_pkioverheid_g2.pem",   nullptr,
  };

  base::FilePath certs_dir = GetTestCertsDirectory();

  for (size_t i = 0; kDigiNotarFilenames[i]; i++) {
    scoped_refptr<X509Certificate> diginotar_cert =
        ImportCertFromFile(certs_dir, kDigiNotarFilenames[i]);
    ASSERT_TRUE(diginotar_cert);
    std::string_view spki;
    ASSERT_TRUE(asn1::ExtractSPKIFromDERCert(
        x509_util::CryptoBufferAsStringPiece(diginotar_cert->cert_buffer()),
        &spki));

    std::string spki_sha256 = crypto::SHA256HashString(spki);

    EXPECT_EQ(CRLSet::REVOKED, set1->CheckSPKI(spki_sha256))
        << "Public key not blocked for " << kDigiNotarFilenames[i];
    EXPECT_EQ(CRLSet::REVOKED, set2->CheckSPKI(spki_sha256))
        << "Public key not blocked for " << kDigiNotarFilenames[i];
  }
}

TEST(CRLSetTest, BlockedSubjects) {
  std::string crl_set_bytes;
  EXPECT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_root_subject.raw"),
      &crl_set_bytes));
  scoped_refptr<CRLSet> set;
  EXPECT_TRUE(CRLSet::Parse(crl_set_bytes, &set));
  ASSERT_TRUE(set.get() != nullptr);

  scoped_refptr<X509Certificate> root = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  std::string_view root_der =
      net::x509_util::CryptoBufferAsStringPiece(root->cert_buffer());

  std::string_view spki;
  ASSERT_TRUE(asn1::ExtractSPKIFromDERCert(root_der, &spki));
  SHA256HashValue spki_sha256;
  crypto::SHA256HashString(spki, spki_sha256.data, sizeof(spki_sha256.data));

  std::string_view subject;
  ASSERT_TRUE(asn1::ExtractSubjectFromDERCert(root_der, &subject));

  // Unrelated subjects are unaffected.
  EXPECT_EQ(CRLSet::GOOD, set->CheckSubject("abcdef", ""));

  // The subject in question is considered revoked if used with an unknown SPKI
  // hash.
  EXPECT_EQ(CRLSet::REVOKED,
            set->CheckSubject(
                subject,
                std::string_view(reinterpret_cast<const char*>(kGIASPKISHA256),
                                 sizeof(kGIASPKISHA256))));

  // When used with the correct hash, that subject should be accepted.
  EXPECT_EQ(CRLSet::GOOD,
            set->CheckSubject(
                subject, std::string_view(
                             reinterpret_cast<const char*>(spki_sha256.data),
                             sizeof(spki_sha256.data))));
}

TEST(CRLSetTest, Expired) {
  // This CRLSet has an expiry value set to one second past midnight, 1st Jan,
  // 1970.
  std::string_view s(reinterpret_cast<const char*>(kExpiredCRLSet),
                     sizeof(kExpiredCRLSet));
  scoped_refptr<CRLSet> set;
  EXPECT_TRUE(CRLSet::Parse(s, &set));
  ASSERT_TRUE(set.get() != nullptr);

  EXPECT_TRUE(set->IsExpired());
}

}  // namespace net

"""

```