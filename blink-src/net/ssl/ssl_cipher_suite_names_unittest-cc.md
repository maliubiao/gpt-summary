Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding of the File's Purpose:**

The filename `ssl_cipher_suite_names_unittest.cc` immediately suggests this file is a unit test for functionality related to SSL/TLS cipher suite names within the Chromium networking stack. The presence of `#include "net/ssl/ssl_cipher_suite_names.h"` confirms this. Unit tests are designed to verify individual units of code, in this case, functions and logic related to cipher suites.

**2. Identifying Key Functions and Data Structures:**

I scanned the code for function definitions and important data structures. The core function under test seems to be `SSLCipherSuiteToStrings`. The `ParseSSLCipherString` function is also clearly targeted. The `ObsoleteSSLStatus` and `IsTLSCipherSuiteAllowedByHTTP2` functions are also tested. The constant definitions like `kObsoleteVersion`, `kModernVersion`, and the various `k...Cipher...` values are clearly test inputs or expected outputs. The `MakeConnectionStatus` helper function simplifies creating test inputs.

**3. Analyzing Individual Test Cases:**

I then examined each `TEST` block to understand what specific aspect of the functions it was testing.

* **`Basic`:** This test case calls `SSLCipherSuiteToStrings` with various cipher suite values and checks the resulting key exchange, cipher, MAC, AEAD status, and TLS 1.3 status. This tests the core functionality of translating a numerical cipher suite into its string components and flags.

* **`ParseSSLCipherString`:**  This test checks if the function can correctly parse hexadecimal string representations of cipher suites into their numerical `uint16_t` values. It has positive test cases.

* **`ParseSSLCipherStringFails`:** This test focuses on negative test cases for `ParseSSLCipherString`, providing invalid string formats and ensuring the function correctly returns `false`.

* **`ObsoleteSSLStatusProtocol`:** This test uses `MakeConnectionStatus` to create connection statuses with different TLS versions but the same modern cipher suite. It checks if `ObsoleteSSLStatus` correctly identifies older protocols as obsolete.

* **`ObsoleteSSLStatusProtocolAndCipherSuite`:** This is a more complex test that covers various combinations of obsolete and modern protocols, cipher suites (with obsolete and modern key exchange mechanisms), and signatures. It thoroughly tests the logic within `ObsoleteSSLStatus` for identifying various obsolete aspects of the SSL/TLS connection.

* **`HTTP2CipherSuites`:** This test checks if `IsTLSCipherSuiteAllowedByHTTP2` correctly identifies cipher suites that are compatible with HTTP/2. It includes both allowed and disallowed cipher suites.

**4. Inferring Functionality and Purpose:**

Based on the test cases, I could deduce the following about the tested functions:

* **`SSLCipherSuiteToStrings`:** Takes a cipher suite (numeric) and outputs its components as strings (key exchange, cipher, MAC) and boolean flags (AEAD, TLS 1.3). This is likely used for logging, debugging, or displaying information about the negotiated SSL/TLS connection.

* **`ParseSSLCipherString`:** Converts a string representation of a cipher suite (like "0xC02F") into its numerical equivalent. This could be used for configuration parsing or user input.

* **`ObsoleteSSLStatus`:** Takes a connection status (including protocol version and cipher suite) and a signature algorithm and returns a bitmask indicating which aspects of the connection are considered obsolete (protocol, key exchange, cipher, signature). This function is important for security auditing and informing users about potential vulnerabilities.

* **`IsTLSCipherSuiteAllowedByHTTP2`:** Determines if a given cipher suite is permitted for use with the HTTP/2 protocol. This is crucial because HTTP/2 has stricter requirements for security and efficiency.

**5. Identifying Relationships with JavaScript (Hypothetical):**

Since the question asked about connections to JavaScript, I considered where this information might be used in a browser context. JavaScript in a web browser often interacts with the underlying network stack to establish secure connections.

* **Developer Tools:**  Browser developer tools often display information about the security of a connection, including the negotiated cipher suite. JavaScript within the DevTools could potentially use an API (likely a C++ API exposed to the browser's UI layer) that leverages `SSLCipherSuiteToStrings` to present human-readable information about the cipher suite.

* **`navigator.connection` API:** While this API doesn't directly expose cipher suite details, a more detailed or internal API could exist that allows JavaScript to query this information. This could be used for advanced network monitoring or security analysis tools.

**6. Formulating Assumptions, Inputs, and Outputs (Logical Reasoning):**

For `ObsoleteSSLStatus`, I constructed examples to illustrate how different inputs would lead to different outputs based on the defined constants and logic. This involved creating scenarios with obsolete protocols, ciphers, and signatures, and noting the corresponding bitmask output.

**7. Identifying Potential User/Programming Errors:**

I considered how these functions might be misused or lead to errors:

* **Incorrect String Format in `ParseSSLCipherString`:** Users providing non-hexadecimal or incorrectly formatted strings.

* **Misinterpreting `ObsoleteSSLStatus`:**  Developers might not correctly interpret the bitmask returned by `ObsoleteSSLStatus` or might fail to handle different combinations of obsolete features.

**8. Tracing User Operations (Debugging Clues):**

I tried to envision the user actions that would lead to this code being executed:

* **Visiting an HTTPS Website:** This is the most common scenario. The browser negotiates an SSL/TLS connection, and the cipher suite used is a key part of this negotiation.

* **Developer Tools Inspection:** A developer might open the Security tab in the browser's DevTools, which would trigger the display of connection details, potentially using the functions in this file.

* **Internal Browser Processes:**  Various internal processes within the browser, such as certificate verification or security policy enforcement, might utilize this code to assess the security of a connection.

By following these steps, I aimed to provide a comprehensive and well-reasoned explanation of the provided C++ unit test file. The process involved understanding the core purpose, analyzing individual test cases, inferring functionality, connecting it (hypothetically) to related concepts like JavaScript, performing logical reasoning, and considering potential errors and debugging scenarios.
这是目录为 `net/ssl/ssl_cipher_suite_names_unittest.cc` 的 Chromium 网络栈的源代码文件。顾名思义，这是一个单元测试文件，用于测试与 SSL/TLS 密码套件名称相关的函数功能。

**功能列表:**

这个文件的主要功能是测试 `net/ssl/ssl_cipher_suite_names.h` 中定义的以下函数的功能是否正确：

1. **`SSLCipherSuiteToStrings(const char** key_exchange, const char** cipher, const char** mac, bool* is_aead, bool* is_tls13, uint16_t cipher_suite)`:**
   - 功能：将一个数字形式的 TLS 密码套件代码 (`uint16_t`) 转换为人类可读的字符串表示，包括密钥交换算法、加密算法、消息认证码（MAC）算法，并指示是否是 AEAD (Authenticated Encryption with Associated Data) 算法以及是否是 TLS 1.3 的密码套件。
   - 测试目的：验证对于不同的密码套件代码，该函数是否能正确解析并返回相应的字符串和标志。

2. **`ParseSSLCipherString(const std::string& cipher_string, uint16_t* cipher_suite)`:**
   - 功能：将一个字符串形式的 TLS 密码套件（例如 "0xC02F"）转换为数字形式 (`uint16_t`)。
   - 测试目的：验证该函数是否能正确解析有效的密码套件字符串，并拒绝无效的字符串格式。

3. **`ObsoleteSSLStatus(int connection_status, uint16_t signature_algorithm)`:**
   - 功能：根据连接状态（包含协议版本和密码套件）和签名算法，判断 SSL/TLS 连接中是否存在过时的组件（例如过时的协议版本、密钥交换算法、加密算法或签名算法）。
   - 测试目的：验证该函数是否能正确识别不同类型的过时 SSL/TLS 组件组合。

4. **`IsTLSCipherSuiteAllowedByHTTP2(uint16_t cipher_suite)`:**
   - 功能：判断一个给定的 TLS 密码套件是否被 HTTP/2 协议允许使用。HTTP/2 对密码套件有特定的要求。
   - 测试目的：验证该函数是否能正确判断哪些密码套件符合 HTTP/2 的要求。

**与 Javascript 功能的关系 (举例说明):**

虽然这个文件是 C++ 代码，直接在浏览器内核中运行，但其功能最终会影响到 Javascript 在浏览器中的行为。以下是一些可能的关联：

* **`navigator.connection.getSecurityInfo()` (实验性 API):**  虽然 Chrome 目前移除了这个 API，但未来可能会有类似的 API 允许 Javascript 获取当前连接的安全信息，其中可能包括协商的密码套件。在这种情况下，浏览器内核会调用 `SSLCipherSuiteToStrings` 来格式化密码套件信息，然后通过某种机制传递给 Javascript。

   **举例说明:**

   假设 Javascript 可以调用一个虚构的 API `getDetailedSecurityInfo()`：

   ```javascript
   navigator.connection.getDetailedSecurityInfo().then(info => {
     console.log("协商的密码套件:", info.cipherSuite);
     // 浏览器内核可能会使用 SSLCipherSuiteToStrings 将数字密码套件转换为 info.cipherSuite 这样的字符串
   });
   ```

* **开发者工具 (DevTools):**  当用户在 Chrome 开发者工具的 "Security" 面板查看 HTTPS 连接信息时，显示的密码套件名称很可能就是通过 `SSLCipherSuiteToStrings` 函数获取并格式化的。这个信息虽然不是直接暴露给网页 Javascript，但会影响开发者对网站安全性的理解。

* **Content Security Policy (CSP):**  虽然 CSP 主要关注资源加载和执行，但未来也可能扩展到更细粒度的网络安全控制，例如限制允许使用的密码套件。如果实现这样的功能，Javascript 的 CSP 指令可能会影响浏览器内核对密码套件的选择，而内核在处理时可能会用到这里的函数进行校验和信息展示。

**逻辑推理 (假设输入与输出):**

**1. `SSLCipherSuiteToStrings`:**

* **假设输入:** `cipher_suite = 0xc02f` (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
* **预期输出:**
    * `key_exchange` 指向的字符串为 "ECDHE_RSA"
    * `cipher` 指向的字符串为 "AES_128_GCM"
    * `mac` 为 `nullptr` (因为是 AEAD 算法)
    * `is_aead` 为 `true`
    * `is_tls13` 为 `false`

**2. `ParseSSLCipherString`:**

* **假设输入:** `cipher_string = "0x002f"`
* **预期输出:** `cipher_suite` 的值为 `0x002f`，函数返回 `true`。

* **假设输入:** `cipher_string = "invalid"`
* **预期输出:** 函数返回 `false`。

**3. `ObsoleteSSLStatus`:**

* **假设输入:**
    * `connection_status` 表示使用 TLS 1.0 (过时版本) 和密码套件 `kModernCipherSuite` (现代密码套件)。
    * `signature_algorithm` 为 `kModernSignature` (现代签名算法)。
* **预期输出:** `OBSOLETE_SSL_MASK_PROTOCOL` (指示协议版本过时)。

* **假设输入:**
    * `connection_status` 表示使用 TLS 1.2 (现代版本) 和密码套件 `kObsoleteCipherObsoleteKeyExchange` (包含过时密钥交换和加密算法的密码套件)。
    * `signature_algorithm` 为 `kModernSignature`。
* **预期输出:** `OBSOLETE_SSL_MASK_KEY_EXCHANGE | OBSOLETE_SSL_MASK_CIPHER` (指示密钥交换和加密算法过时)。

**4. `IsTLSCipherSuiteAllowedByHTTP2`:**

* **假设输入:** `cipher_suite = 0xc02f` (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
* **预期输出:** `true` (HTTP/2 允许该密码套件)。

* **假设输入:** `cipher_suite = 0x000a` (TLS_RSA_WITH_3DES_EDE_CBC_SHA)
* **预期输出:** `false` (HTTP/2 不允许该密码套件)。

**涉及用户或编程常见的使用错误 (举例说明):**

* **编程错误：硬编码过时的密码套件:**  开发者可能错误地在代码中硬编码了过时的密码套件，例如 `TLS_RSA_WITH_RC4_128_SHA`。 `ObsoleteSSLStatus` 可以帮助检测到这种情况，但前提是代码中使用了这个函数进行检查。

   ```c++
   // 错误示例：硬编码过时的密码套件
   int MakeInsecureConnectionStatus() {
     int connection_status = 0;
     SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_2, &connection_status);
     SSLConnectionStatusSetCipherSuite(0x0005, &connection_status); // TLS_RSA_WITH_RC4_128_SHA (已废弃)
     return connection_status;
   }
   ```

* **用户操作错误：访问配置不安全的网站:** 用户访问的网站可能配置了过时的 SSL/TLS 协议或密码套件。虽然用户本身无法直接影响浏览器使用的密码套件，但浏览器会根据服务器的配置进行协商。`ObsoleteSSLStatus` 的结果会影响浏览器如何向用户展示连接的安全性（例如，显示警告或错误）。

* **编程错误：错误地解析密码套件字符串:**  开发者可能在使用 `ParseSSLCipherString` 时没有进行充分的错误处理，导致程序在遇到无效的密码套件字符串时崩溃或产生未预期的行为。

   ```c++
   std::string userInput = GetUserInput(); // 假设用户输入了密码套件字符串
   uint16_t cipherSuite;
   if (ParseSSLCipherString(userInput, &cipherSuite)) {
     // 使用 cipherSuite
   } else {
     // 缺少错误处理
     // 应该提示用户输入无效
   }
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户遇到一个 HTTPS 网站连接安全警告，而你是 Chromium 开发者，需要调试相关的密码套件问题，你可能会采取以下步骤：

1. **用户访问 HTTPS 网站:** 用户在 Chrome 浏览器地址栏输入一个 `https://` 开头的网址并访问。

2. **浏览器发起 TLS 握手:** 浏览器与服务器进行 TLS 握手，协商加密协议和密码套件。这个过程中，浏览器和服务器会根据各自支持的协议和密码套件列表，选择一个双方都支持的、最安全的密码套件。

3. **连接状态记录:** 浏览器内部会记录连接的各种状态信息，包括最终协商的 TLS 版本和密码套件。这些信息可能存储在 `SSLConnectionStatus` 结构体中。

4. **安全指示器显示:**  浏览器会根据连接的安全状态，在地址栏显示相应的安全指示器（例如，锁形图标，或带有警告的图标）。

5. **开发者打开 DevTools:** 用户（或开发者）如果对连接的安全性有疑问，可能会打开 Chrome 开发者工具，并切换到 "Security" 面板。

6. **DevTools 请求连接信息:** 当 "Security" 面板加载时，它会向浏览器内核请求当前连接的详细安全信息，包括协商的密码套件。

7. **调用 `SSLCipherSuiteToStrings`:**  浏览器内核在获取到协商的密码套件的数字代码后，会调用 `SSLCipherSuiteToStrings` 函数，将该代码转换为人类可读的字符串（密钥交换、加密算法、MAC 等），以便在 DevTools 中显示。

8. **调用 `ObsoleteSSLStatus` (可能):** 为了判断连接是否存在安全风险，浏览器内核可能会调用 `ObsoleteSSLStatus` 函数，传入连接状态和签名算法，以检查是否存在过时的协议、密码套件或签名算法。`ObsoleteSSLStatus` 的返回结果会影响 DevTools 中显示的警告信息。

9. **DevTools 展示信息:** DevTools 的 "Security" 面板会显示 `SSLCipherSuiteToStrings` 返回的密码套件名称，以及 `ObsoleteSSLStatus` 判断出的安全风险。

10. **调试线索:** 如果用户看到连接不安全的警告，并且 DevTools 中显示的密码套件是过时的，那么你作为开发者就可以检查以下几个方面：
    * 服务器配置是否允许更安全的密码套件？
    * 浏览器是否正确地实现了密码套件协商逻辑？
    * `ObsoleteSSLStatus` 函数是否正确地判断了过时状态？

通过分析这个单元测试文件，你可以了解到浏览器内核是如何处理和展示密码套件信息的，以及如何判断连接的安全性，从而更好地定位和解决用户遇到的安全警告问题。

Prompt: 
```
这是目录为net/ssl/ssl_cipher_suite_names_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2011 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_cipher_suite_names.h"

#include "net/ssl/ssl_connection_status_flags.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace net {

namespace {

int kObsoleteVersion = SSL_CONNECTION_VERSION_TLS1;
int kModernVersion = SSL_CONNECTION_VERSION_TLS1_2;

uint16_t kModernCipherSuite =
    0xc02f; /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */

uint16_t kObsoleteCipherObsoleteKeyExchange =
    0x2f; /* TLS_RSA_WITH_AES_128_CBC_SHA */
uint16_t kObsoleteCipherModernKeyExchange =
    0xc014; /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
uint16_t kModernCipherObsoleteKeyExchange =
    0x9c; /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
uint16_t kModernCipherModernKeyExchange =
    0xc02f; /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */

uint16_t kObsoleteSignature = SSL_SIGN_RSA_PKCS1_SHA1;
uint16_t kModernSignature = SSL_SIGN_RSA_PSS_RSAE_SHA256;

int MakeConnectionStatus(int version, uint16_t cipher_suite) {
  int connection_status = 0;

  SSLConnectionStatusSetVersion(version, &connection_status);
  SSLConnectionStatusSetCipherSuite(cipher_suite, &connection_status);

  return connection_status;
}

TEST(CipherSuiteNamesTest, Basic) {
  const char *key_exchange, *cipher, *mac;
  bool is_aead, is_tls13;

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0x000a);
  EXPECT_STREQ("RSA", key_exchange);
  EXPECT_STREQ("3DES_EDE_CBC", cipher);
  EXPECT_STREQ("HMAC-SHA1", mac);
  EXPECT_FALSE(is_aead);
  EXPECT_FALSE(is_tls13);

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0x002f);
  EXPECT_STREQ("RSA", key_exchange);
  EXPECT_STREQ("AES_128_CBC", cipher);
  EXPECT_STREQ("HMAC-SHA1", mac);
  EXPECT_FALSE(is_aead);
  EXPECT_FALSE(is_tls13);

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0xc030);
  EXPECT_STREQ("ECDHE_RSA", key_exchange);
  EXPECT_STREQ("AES_256_GCM", cipher);
  EXPECT_TRUE(is_aead);
  EXPECT_FALSE(is_tls13);
  EXPECT_EQ(nullptr, mac);

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0xcca9);
  EXPECT_STREQ("ECDHE_ECDSA", key_exchange);
  EXPECT_STREQ("CHACHA20_POLY1305", cipher);
  EXPECT_TRUE(is_aead);
  EXPECT_FALSE(is_tls13);
  EXPECT_EQ(nullptr, mac);

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0xff31);
  EXPECT_STREQ("???", key_exchange);
  EXPECT_STREQ("???", cipher);
  EXPECT_STREQ("???", mac);
  EXPECT_FALSE(is_aead);
  EXPECT_FALSE(is_tls13);

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0x1301);
  EXPECT_STREQ("AES_128_GCM", cipher);
  EXPECT_TRUE(is_aead);
  EXPECT_TRUE(is_tls13);
  EXPECT_EQ(nullptr, mac);
  EXPECT_EQ(nullptr, key_exchange);

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0x1302);
  EXPECT_STREQ("AES_256_GCM", cipher);
  EXPECT_TRUE(is_aead);
  EXPECT_TRUE(is_tls13);
  EXPECT_EQ(nullptr, mac);
  EXPECT_EQ(nullptr, key_exchange);

  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          0x1303);
  EXPECT_STREQ("CHACHA20_POLY1305", cipher);
  EXPECT_TRUE(is_aead);
  EXPECT_TRUE(is_tls13);
  EXPECT_EQ(nullptr, mac);
  EXPECT_EQ(nullptr, key_exchange);
}

TEST(CipherSuiteNamesTest, ParseSSLCipherString) {
  uint16_t cipher_suite = 0;
  EXPECT_TRUE(ParseSSLCipherString("0x0004", &cipher_suite));
  EXPECT_EQ(0x00004u, cipher_suite);

  EXPECT_TRUE(ParseSSLCipherString("0xBEEF", &cipher_suite));
  EXPECT_EQ(0xBEEFu, cipher_suite);
}

TEST(CipherSuiteNamesTest, ParseSSLCipherStringFails) {
  const char* const cipher_strings[] = {
    "0004",
    "0x004",
    "0xBEEFY",
  };

  for (const auto* cipher_string : cipher_strings) {
    uint16_t cipher_suite = 0;
    EXPECT_FALSE(ParseSSLCipherString(cipher_string, &cipher_suite));
  }
}

TEST(CipherSuiteNamesTest, ObsoleteSSLStatusProtocol) {
  // Obsolete
  // Note all of these combinations are impossible; TLS 1.2 is necessary for
  // kModernCipherSuite.
  EXPECT_EQ(OBSOLETE_SSL_MASK_PROTOCOL,
            ObsoleteSSLStatus(MakeConnectionStatus(SSL_CONNECTION_VERSION_SSL2,
                                                   kModernCipherSuite),
                              kModernSignature));
  EXPECT_EQ(OBSOLETE_SSL_MASK_PROTOCOL,
            ObsoleteSSLStatus(MakeConnectionStatus(SSL_CONNECTION_VERSION_SSL3,
                                                   kModernCipherSuite),
                              kModernSignature));
  EXPECT_EQ(OBSOLETE_SSL_MASK_PROTOCOL,
            ObsoleteSSLStatus(MakeConnectionStatus(SSL_CONNECTION_VERSION_TLS1,
                                                   kModernCipherSuite),
                              kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_PROTOCOL,
      ObsoleteSSLStatus(MakeConnectionStatus(SSL_CONNECTION_VERSION_TLS1_1,
                                             kModernCipherSuite),
                        kModernSignature));

  // Modern
  EXPECT_EQ(
      OBSOLETE_SSL_NONE,
      ObsoleteSSLStatus(MakeConnectionStatus(SSL_CONNECTION_VERSION_TLS1_2,
                                             kModernCipherSuite),
                        kModernSignature));
  EXPECT_EQ(OBSOLETE_SSL_NONE,
            ObsoleteSSLStatus(MakeConnectionStatus(SSL_CONNECTION_VERSION_QUIC,
                                                   kModernCipherSuite),
                              kModernSignature));
}

TEST(CipherSuiteNamesTest, ObsoleteSSLStatusProtocolAndCipherSuite) {
  // Cartesian combos
  // As above, some of these combinations can't happen in practice.
  EXPECT_EQ(OBSOLETE_SSL_MASK_PROTOCOL | OBSOLETE_SSL_MASK_KEY_EXCHANGE |
                OBSOLETE_SSL_MASK_CIPHER | OBSOLETE_SSL_MASK_SIGNATURE,
            ObsoleteSSLStatus(
                MakeConnectionStatus(kObsoleteVersion,
                                     kObsoleteCipherObsoleteKeyExchange),
                kObsoleteSignature));
  EXPECT_EQ(OBSOLETE_SSL_MASK_PROTOCOL | OBSOLETE_SSL_MASK_KEY_EXCHANGE |
                OBSOLETE_SSL_MASK_CIPHER,
            ObsoleteSSLStatus(
                MakeConnectionStatus(kObsoleteVersion,
                                     kObsoleteCipherObsoleteKeyExchange),
                kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_PROTOCOL | OBSOLETE_SSL_MASK_KEY_EXCHANGE,
      ObsoleteSSLStatus(MakeConnectionStatus(kObsoleteVersion,
                                             kModernCipherObsoleteKeyExchange),
                        kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_PROTOCOL | OBSOLETE_SSL_MASK_CIPHER,
      ObsoleteSSLStatus(MakeConnectionStatus(kObsoleteVersion,
                                             kObsoleteCipherModernKeyExchange),
                        kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_PROTOCOL,
      ObsoleteSSLStatus(MakeConnectionStatus(kObsoleteVersion,
                                             kModernCipherModernKeyExchange),
                        kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_KEY_EXCHANGE | OBSOLETE_SSL_MASK_CIPHER,
      ObsoleteSSLStatus(MakeConnectionStatus(
                            kModernVersion, kObsoleteCipherObsoleteKeyExchange),
                        kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_KEY_EXCHANGE,
      ObsoleteSSLStatus(MakeConnectionStatus(kModernVersion,
                                             kModernCipherObsoleteKeyExchange),
                        kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_CIPHER,
      ObsoleteSSLStatus(MakeConnectionStatus(kModernVersion,
                                             kObsoleteCipherModernKeyExchange),
                        kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_NONE,
      ObsoleteSSLStatus(
          MakeConnectionStatus(kModernVersion, kModernCipherModernKeyExchange),
          kModernSignature));
  EXPECT_EQ(
      OBSOLETE_SSL_NONE,
      ObsoleteSSLStatus(MakeConnectionStatus(SSL_CONNECTION_VERSION_TLS1_3,
                                             0x1301 /* AES_128_GCM_SHA256 */),
                        kModernSignature));

  // Don't flag the signature as obsolete if not present. It may be an old cache
  // entry or a key exchange that doesn't involve a signature. (Though, in the
  // latter case, we would always flag a bad key exchange.)
  EXPECT_EQ(
      OBSOLETE_SSL_NONE,
      ObsoleteSSLStatus(
          MakeConnectionStatus(kModernVersion, kModernCipherModernKeyExchange),
          0));
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_KEY_EXCHANGE,
      ObsoleteSSLStatus(MakeConnectionStatus(kModernVersion,
                                             kModernCipherObsoleteKeyExchange),
                        0));

  // Flag obsolete signatures.
  EXPECT_EQ(
      OBSOLETE_SSL_MASK_SIGNATURE,
      ObsoleteSSLStatus(
          MakeConnectionStatus(kModernVersion, kModernCipherModernKeyExchange),
          kObsoleteSignature));
}

TEST(CipherSuiteNamesTest, HTTP2CipherSuites) {
  // Picked some random cipher suites.
  EXPECT_FALSE(
      IsTLSCipherSuiteAllowedByHTTP2(0x0 /* TLS_NULL_WITH_NULL_NULL */));
  EXPECT_FALSE(IsTLSCipherSuiteAllowedByHTTP2(
      0xc014 /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */));
  EXPECT_FALSE(IsTLSCipherSuiteAllowedByHTTP2(
      0x9c /* TLS_RSA_WITH_AES_128_GCM_SHA256 */));

  // Non-existent cipher suite.
  EXPECT_FALSE(IsTLSCipherSuiteAllowedByHTTP2(0xffff)) << "Doesn't exist!";

  // HTTP/2-compatible ones.
  EXPECT_TRUE(IsTLSCipherSuiteAllowedByHTTP2(
      0xc02f /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */));
  EXPECT_TRUE(IsTLSCipherSuiteAllowedByHTTP2(
      0xcca8 /* ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */));
  EXPECT_TRUE(IsTLSCipherSuiteAllowedByHTTP2(
      0xcca9 /* ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */));
  EXPECT_TRUE(IsTLSCipherSuiteAllowedByHTTP2(0x1301 /* AES_128_GCM_SHA256 */));
  EXPECT_TRUE(IsTLSCipherSuiteAllowedByHTTP2(0x1302 /* AES_256_GCM_SHA384 */));
  EXPECT_TRUE(IsTLSCipherSuiteAllowedByHTTP2(0x1303 /* CHACHA20_POLY1305 */));
}

}  // anonymous namespace

}  // namespace net

"""

```