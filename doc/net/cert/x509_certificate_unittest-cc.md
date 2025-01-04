Response:
The user is asking for a summary of the functionality of the C++ source code file `net/cert/x509_certificate_unittest.cc` in the Chromium project.

To address this, I need to:

1. **Identify the core purpose of the file:** Based on the name, it's clearly a unit test file for `X509Certificate`.
2. **Analyze the included headers:** These provide clues about the functionalities being tested (e.g., parsing, time handling, cryptography).
3. **Examine the test cases:** Each `TEST` macro defines a specific test scenario. I need to understand what aspects of `X509Certificate` are being validated in each test.
4. **Look for patterns and common themes:** Group similar tests together to identify major functional areas.
5. **Address the specific questions:**
    * **Relationship to Javascript:**  Consider if any tests touch on web-related aspects that might interact with Javascript (e.g., domain name matching).
    * **Logic and Inference:**  Identify tests that involve comparisons or checks based on input data.
    * **Common Usage Errors:**  Look for tests that validate error handling or prevent misuse of the `X509Certificate` class.
    * **User Operation to Reach Here:** Explain the context of how this code is used in a browser.
6. **Summarize the overall functionality:**  Provide a concise overview of the file's purpose.

Based on my initial scan, the file primarily focuses on testing the parsing and attribute extraction of X.509 certificates. It also covers functionalities like fingerprint calculation, subject alternative name retrieval, and serialization.
这个文件 `net/cert/x509_certificate_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net/cert/x509_certificate.h` 中定义的 `X509Certificate` 类的功能。  `X509Certificate` 类是 Chromium 中表示 X.509 证书的核心类。

以下是这个单元测试文件的主要功能归纳：

1. **证书解析测试:**  验证 `X509Certificate` 类能否正确地从不同的编码格式（DER, PEM）的证书数据中解析出证书的各项属性，例如：
    * 主题 (Subject) 和颁发者 (Issuer) 的信息 (Common Name, Locality, State, Country, Organization, Organization Unit)。
    * 证书的有效期 (Valid From 和 Valid To)。
    * 主题备用名称 (Subject Alternative Names, SANs)，包括 DNS 名称和 IP 地址。
    * 证书的序列号 (Serial Number)。

2. **证书属性访问测试:**  测试是否能正确访问和获取已解析的证书属性，例如：
    * 主题和颁发者的各个字段。
    * 证书的有效期。
    * 主题备用名称列表。
    * 证书的序列号。

3. **证书指纹计算测试:** 验证 `X509Certificate` 类计算证书指纹（例如 SHA-256 指纹）的功能是否正确。

4. **证书链指纹计算测试:** 测试计算包含中间证书的证书链的指纹是否正确。

5. **特殊编码处理测试:** 验证对于证书中一些特殊编码格式的处理，例如：
    * 多值 RDN (Relative Distinguished Name)。
    * 未转义的特殊字符。
    * PrintableString 编码的字符串是否可以作为 UTF-8 处理。
    * TeletexString 编码的字符串是否可以作为 Latin-1 处理。

6. **扩展字段提取测试:** 测试从证书中提取特定扩展字段的功能，例如：
    * `BasicConstraints` 扩展。
    * `CanSignHttpExchanges` 草案扩展。

7. **证书缓存测试:** 验证 `X509Certificate` 类在创建时是否会缓存相同的证书数据，以避免重复解析和内存占用。

8. **证书克隆测试:**  测试 `CloneWithDifferentIntermediates` 方法，该方法用于创建一个具有相同叶子证书但中间证书不同的新证书对象。

9. **证书序列化 (Pickle) 测试:** 验证 `X509Certificate` 对象是否可以被序列化和反序列化。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 `X509Certificate` 类在 Chromium 浏览器中扮演着关键角色，直接影响到浏览器处理 HTTPS 连接的安全性。  当浏览器建立 HTTPS 连接时，服务器会提供一个或多个 X.509 证书。浏览器会使用 `X509Certificate` 类来解析和验证这些证书。

以下是一些与 JavaScript 功能相关的举例说明：

* **HTTPS 连接安全性:**  JavaScript 发起的 `fetch` 或 `XMLHttpRequest` 请求如果目标是 HTTPS 站点，那么底层会使用这个 C++ 代码来验证服务器提供的证书。 如果证书验证失败，JavaScript 代码可能会收到一个网络错误，从而阻止不安全的连接。
    * **假设输入:**  一个恶意网站提供了一个无效的 HTTPS 证书。
    * **输出:**  `X509Certificate` 的解析或验证会失败，Chromium 会阻止连接，JavaScript 代码会收到一个错误，例如 `net::ERR_CERT_AUTHORITY_INVALID`。

* **内容安全策略 (CSP):** CSP 允许网站指定浏览器可以加载哪些资源的来源。  `X509Certificate` 的信息，例如证书的指纹 (SHA-256) 可以用于 CSP 的 `require-sri-for` 指令中，来确保加载的子资源（例如脚本或样式表）的完整性。
    * **假设输入:**  CSP 头中指定了一个脚本的 SHA-256 指纹。
    * **输出:**  浏览器下载脚本后，会计算脚本的 SHA-256 并与 CSP 中指定的指纹进行比较。  `X509Certificate` 的指纹计算功能与此类似，虽然直接比较的是证书的指纹。

* **Public Key Pinning (HPKP，虽然已被弃用，但概念类似):**  HPKP 允许网站指定浏览器应该“记住”某些 HTTPS 证书的公钥哈希值。后续连接到该网站时，浏览器会检查服务器提供的证书的公钥哈希是否匹配。 `X509Certificate` 提供了访问和处理证书公钥的能力。

**逻辑推理的假设输入与输出：**

许多测试都涉及到逻辑推理，例如验证解析出的证书属性是否与预期值一致。以下是一些例子：

* **假设输入:** 一个包含特定主题名称的 DER 编码证书数据。
* **输出:**  调用 `X509Certificate::CreateFromBytes` 后，`google_cert->subject().common_name` 应该返回预期的主题名称字符串 (例如 "www.google.com")。

* **假设输入:**  一个包含特定有效起始日期和结束日期的 DER 编码证书数据。
* **输出:** 调用 `X509Certificate::CreateFromBytes` 后，`google_cert->valid_start()` 和 `google_cert->valid_expiry()` 返回的 `Time` 对象应该与预期的日期和时间相符。

* **假设输入:** 一个包含特定 Subject Alternative Name 扩展的证书数据。
* **输出:** 调用 `san_cert->GetSubjectAltName(&dns_names, nullptr)` 后，`dns_names` 向量应该包含预期的 DNS 名称 (例如 "test.example")。

**用户或编程常见的使用错误：**

* **证书数据格式错误:**  如果用户或程序提供了格式错误的证书数据（例如，不是有效的 DER 或 PEM 格式），`X509Certificate::CreateFromBytes` 或 `X509Certificate::CreateFromBuffer` 会返回空指针。
    * **示例:**  尝试使用一个文本文件而不是实际的证书文件来创建 `X509Certificate` 对象。

* **假设输入:**  一个包含随意文本的字符串。
    * **预期结果:** `X509Certificate::CreateFromBytes(invalid_der_data)` 返回 `nullptr`。

* **假设输入:**  一个部分损坏的 DER 编码证书。
    * **预期结果:** `X509Certificate::CreateFromBytes(corrupted_der_data)` 可能会返回 `nullptr` 或一个解析不完整的 `X509Certificate` 对象，后续访问其属性可能会导致错误。

* **未检查返回值:** 程序员可能会忘记检查 `X509Certificate::CreateFromBytes` 等函数的返回值是否为空指针，导致后续对空指针解引用。

* **错误的指纹比较:**  在进行证书指纹比较时，可能会使用错误的哈希算法或比较的是不同证书的指纹。

**用户操作如何一步步到达这里，作为调试线索：**

当用户在 Chromium 浏览器中访问一个 HTTPS 网站时，会触发证书的加载和验证过程。以下是一个可能的步骤：

1. **用户在地址栏输入 HTTPS 网址 (例如 `https://www.example.com`) 并按下回车。**
2. **Chromium 的网络栈发起与服务器的 TCP 连接。**
3. **TCP 连接建立后，网络栈发起 TLS 握手。**
4. **在 TLS 握手过程中，服务器会将它的 X.509 证书发送给浏览器。**
5. **Chromium 的网络栈接收到证书数据。**
6. **网络栈会调用 `net::X509Certificate::CreateFromBytes` 或 `net::X509Certificate::CreateFromBuffer` 来解析接收到的证书数据。**  这正是此单元测试所覆盖的代码区域。
7. **`X509Certificate` 对象创建成功后，网络栈会进行一系列的证书验证，例如：**
    * 检查证书的有效期。
    * 检查证书是否被吊销。
    * 检查证书链的信任关系，即是否由受信任的根 CA 签发。
    * 检查证书的主题名称是否与请求的域名匹配。
8. **如果证书验证成功，浏览器会继续完成 TLS 握手，并建立安全的 HTTPS 连接。**  用户可以看到网页内容。
9. **如果证书验证失败，Chromium 会阻止连接，并向用户显示一个安全警告页面 (例如 "您的连接不是私密连接")。**

作为调试线索，如果用户报告了 HTTPS 连接问题，例如证书错误，开发人员可能会查看 Chromium 的网络日志，其中会包含证书的详细信息，以及证书验证失败的原因。  这个单元测试文件中的测试用例可以帮助开发人员重现和修复与证书解析和验证相关的 Bug。

**总结：**

总而言之，`net/cert/x509_certificate_unittest.cc` 是一个至关重要的单元测试文件，它全面地测试了 Chromium 中 `X509Certificate` 类的各项功能，确保了浏览器能够安全可靠地处理 HTTPS 连接中使用的 X.509 证书。 它涵盖了证书的解析、属性访问、指纹计算、特殊编码处理、扩展字段提取、缓存机制和序列化等多个方面。这些测试对于保障 Chromium 浏览器的网络安全至关重要。

Prompt: 
```
这是目录为net/cert/x509_certificate_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include <stdint.h>

#include <memory>
#include <string_view>

#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/hash/sha1.h"
#include "base/pickle.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "crypto/rsa_private_key.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/x509_util.h"
#include "net/test/cert_builder.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"
#include "third_party/boringssl/src/pki/pem.h"

using base::HexEncode;
using base::Time;

namespace net {

namespace {

// Certificates for test data. They're obtained with:
//
// $ openssl s_client -connect [host]:443 -showcerts > /tmp/host.pem < /dev/null
// $ openssl x509 -inform PEM -outform DER < /tmp/host.pem > /tmp/host.der
//
// For fingerprint
// $ openssl x509 -inform DER -fingerprint -noout < /tmp/host.der

// For valid_start, valid_expiry
// $ openssl x509 -inform DER -text -noout < /tmp/host.der |
//    grep -A 2 Validity
// $ date +%s -d '<date str>'

// Google's cert.
SHA256HashValue google_fingerprint = {
    {0x21, 0xaf, 0x58, 0x74, 0xea, 0x6b, 0xad, 0xbd, 0xe4, 0xb3, 0xb1,
     0xaa, 0x53, 0x32, 0x80, 0x8f, 0xbf, 0x8a, 0x24, 0x7d, 0x98, 0xec,
     0x7f, 0x77, 0x49, 0x38, 0x42, 0x81, 0x26, 0x7f, 0xed, 0x38}};

// The fingerprint of the Google certificate used in the parsing tests,
// which is newer than the one included in the x509_certificate_data.h
SHA256HashValue google_parse_fingerprint = {
    {0xf6, 0x41, 0xc3, 0x6c, 0xfe, 0xf4, 0x9b, 0xc0, 0x71, 0x35, 0x9e,
     0xcf, 0x88, 0xee, 0xd9, 0x31, 0x7b, 0x73, 0x8b, 0x59, 0x89, 0x41,
     0x6a, 0xd4, 0x01, 0x72, 0x0c, 0x0a, 0x4e, 0x2e, 0x63, 0x52}};

// The fingerprint for the Thawte SGC certificate
SHA256HashValue thawte_parse_fingerprint = {
    {0x10, 0x85, 0xa6, 0xf4, 0x54, 0xd0, 0xc9, 0x11, 0x98, 0xfd, 0xda,
     0xb1, 0x1a, 0x31, 0xc7, 0x16, 0xd5, 0xdc, 0xd6, 0x8d, 0xf9, 0x1c,
     0x03, 0x9c, 0xe1, 0x8d, 0xca, 0x9b, 0xeb, 0x3c, 0xde, 0x3d}};

// Dec 18 00:00:00 2009 GMT
const double kGoogleParseValidFrom = 1261094400;
// Dec 18 23:59:59 2011 GMT
const double kGoogleParseValidTo = 1324252799;

void CheckGoogleCert(const scoped_refptr<X509Certificate>& google_cert,
                     const SHA256HashValue& expected_fingerprint,
                     double valid_from,
                     double valid_to) {
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), google_cert.get());

  const CertPrincipal& subject = google_cert->subject();
  EXPECT_EQ("www.google.com", subject.common_name);
  EXPECT_EQ("Mountain View", subject.locality_name);
  EXPECT_EQ("California", subject.state_or_province_name);
  EXPECT_EQ("US", subject.country_name);
  ASSERT_EQ(1U, subject.organization_names.size());
  EXPECT_EQ("Google Inc", subject.organization_names[0]);
  EXPECT_EQ(0U, subject.organization_unit_names.size());

  const CertPrincipal& issuer = google_cert->issuer();
  EXPECT_EQ("Thawte SGC CA", issuer.common_name);
  EXPECT_EQ("", issuer.locality_name);
  EXPECT_EQ("", issuer.state_or_province_name);
  EXPECT_EQ("ZA", issuer.country_name);
  ASSERT_EQ(1U, issuer.organization_names.size());
  EXPECT_EQ("Thawte Consulting (Pty) Ltd.", issuer.organization_names[0]);
  EXPECT_EQ(0U, issuer.organization_unit_names.size());

  // Use DoubleT because its epoch is the same on all platforms
  const Time& valid_start = google_cert->valid_start();
  EXPECT_EQ(valid_from, valid_start.InSecondsFSinceUnixEpoch());

  const Time& valid_expiry = google_cert->valid_expiry();
  EXPECT_EQ(valid_to, valid_expiry.InSecondsFSinceUnixEpoch());

  EXPECT_EQ(expected_fingerprint, X509Certificate::CalculateFingerprint256(
                                      google_cert->cert_buffer()));

}

void ExpectX509CertificateMembersEqual(
    const scoped_refptr<X509Certificate>& a,
    const scoped_refptr<X509Certificate>& b) {
  EXPECT_TRUE(a->subject().EqualsForTesting(b->subject()));
  EXPECT_TRUE(a->issuer().EqualsForTesting(b->issuer()));
  EXPECT_EQ(a->valid_start(), b->valid_start());
  EXPECT_EQ(a->valid_expiry(), b->valid_expiry());
  EXPECT_EQ(a->serial_number(), b->serial_number());
}

}  // namespace

TEST(X509CertificateTest, GoogleCertParsing) {
  scoped_refptr<X509Certificate> google_cert(
      X509Certificate::CreateFromBytes(google_der));

  CheckGoogleCert(google_cert, google_fingerprint,
                  1238192407,   // Mar 27 22:20:07 2009 GMT
                  1269728407);  // Mar 27 22:20:07 2010 GMT
}

TEST(X509CertificateTest, WebkitCertParsing) {
  scoped_refptr<X509Certificate> webkit_cert(
      X509Certificate::CreateFromBytes(webkit_der));

  ASSERT_NE(static_cast<X509Certificate*>(nullptr), webkit_cert.get());

  const CertPrincipal& subject = webkit_cert->subject();
  EXPECT_EQ("Cupertino", subject.locality_name);
  EXPECT_EQ("California", subject.state_or_province_name);
  EXPECT_EQ("US", subject.country_name);
  ASSERT_EQ(1U, subject.organization_names.size());
  EXPECT_EQ("Apple Inc.", subject.organization_names[0]);
  ASSERT_EQ(1U, subject.organization_unit_names.size());
  EXPECT_EQ("Mac OS Forge", subject.organization_unit_names[0]);

  const CertPrincipal& issuer = webkit_cert->issuer();
  EXPECT_EQ("Go Daddy Secure Certification Authority", issuer.common_name);
  EXPECT_EQ("Scottsdale", issuer.locality_name);
  EXPECT_EQ("Arizona", issuer.state_or_province_name);
  EXPECT_EQ("US", issuer.country_name);
  ASSERT_EQ(1U, issuer.organization_names.size());
  EXPECT_EQ("GoDaddy.com, Inc.", issuer.organization_names[0]);
  ASSERT_EQ(1U, issuer.organization_unit_names.size());
  EXPECT_EQ("http://certificates.godaddy.com/repository",
            issuer.organization_unit_names[0]);

  // Use DoubleT because its epoch is the same on all platforms
  const Time& valid_start = webkit_cert->valid_start();
  EXPECT_EQ(
      1205883319,
      valid_start.InSecondsFSinceUnixEpoch());  // Mar 18 23:35:19 2008 GMT

  const Time& valid_expiry = webkit_cert->valid_expiry();
  EXPECT_EQ(
      1300491319,
      valid_expiry.InSecondsFSinceUnixEpoch());  // Mar 18 23:35:19 2011 GMT

  std::vector<std::string> dns_names;
  EXPECT_TRUE(webkit_cert->GetSubjectAltName(&dns_names, nullptr));
  ASSERT_EQ(2U, dns_names.size());
  EXPECT_EQ("*.webkit.org", dns_names[0]);
  EXPECT_EQ("webkit.org", dns_names[1]);

  // Test that the wildcard cert matches properly.
  EXPECT_TRUE(webkit_cert->VerifyNameMatch("www.webkit.org"));
  EXPECT_TRUE(webkit_cert->VerifyNameMatch("foo.webkit.org"));
  EXPECT_TRUE(webkit_cert->VerifyNameMatch("webkit.org"));
  EXPECT_FALSE(webkit_cert->VerifyNameMatch("www.webkit.com"));
  EXPECT_FALSE(webkit_cert->VerifyNameMatch("www.foo.webkit.com"));
}

TEST(X509CertificateTest, ThawteCertParsing) {
  scoped_refptr<X509Certificate> thawte_cert(
      X509Certificate::CreateFromBytes(thawte_der));

  ASSERT_NE(static_cast<X509Certificate*>(nullptr), thawte_cert.get());

  const CertPrincipal& subject = thawte_cert->subject();
  EXPECT_EQ("www.thawte.com", subject.common_name);
  EXPECT_EQ("Mountain View", subject.locality_name);
  EXPECT_EQ("California", subject.state_or_province_name);
  EXPECT_EQ("US", subject.country_name);
  ASSERT_EQ(1U, subject.organization_names.size());
  EXPECT_EQ("Thawte Inc", subject.organization_names[0]);
  EXPECT_EQ(0U, subject.organization_unit_names.size());

  const CertPrincipal& issuer = thawte_cert->issuer();
  EXPECT_EQ("thawte Extended Validation SSL CA", issuer.common_name);
  EXPECT_EQ("", issuer.locality_name);
  EXPECT_EQ("", issuer.state_or_province_name);
  EXPECT_EQ("US", issuer.country_name);
  ASSERT_EQ(1U, issuer.organization_names.size());
  EXPECT_EQ("thawte, Inc.", issuer.organization_names[0]);
  ASSERT_EQ(1U, issuer.organization_unit_names.size());
  EXPECT_EQ("Terms of use at https://www.thawte.com/cps (c)06",
            issuer.organization_unit_names[0]);

  // Use DoubleT because its epoch is the same on all platforms
  const Time& valid_start = thawte_cert->valid_start();
  EXPECT_EQ(
      1227052800,
      valid_start.InSecondsFSinceUnixEpoch());  // Nov 19 00:00:00 2008 GMT

  const Time& valid_expiry = thawte_cert->valid_expiry();
  EXPECT_EQ(
      1263772799,
      valid_expiry.InSecondsFSinceUnixEpoch());  // Jan 17 23:59:59 2010 GMT
}

// Test that all desired AttributeAndValue pairs can be extracted when only
// a single bssl::RelativeDistinguishedName is present. "Normally" there is only
// one AVA per RDN, but some CAs place all AVAs within a single RDN.
// This is a regression test for http://crbug.com/101009
TEST(X509CertificateTest, MultivalueRDN) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> multivalue_rdn_cert =
      ImportCertFromFile(certs_dir, "multivalue_rdn.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), multivalue_rdn_cert.get());

  const CertPrincipal& subject = multivalue_rdn_cert->subject();
  EXPECT_EQ("Multivalue RDN Test", subject.common_name);
  EXPECT_EQ("", subject.locality_name);
  EXPECT_EQ("", subject.state_or_province_name);
  EXPECT_EQ("US", subject.country_name);
  ASSERT_EQ(1U, subject.organization_names.size());
  EXPECT_EQ("Chromium", subject.organization_names[0]);
  ASSERT_EQ(1U, subject.organization_unit_names.size());
  EXPECT_EQ("Chromium net_unittests", subject.organization_unit_names[0]);
}

// Test that characters which would normally be escaped in the string form,
// such as '=' or '"', are not escaped when parsed as individual components.
// This is a regression test for http://crbug.com/102839
TEST(X509CertificateTest, UnescapedSpecialCharacters) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> unescaped_cert =
      ImportCertFromFile(certs_dir, "unescaped.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), unescaped_cert.get());

  const CertPrincipal& subject = unescaped_cert->subject();
  EXPECT_EQ("127.0.0.1", subject.common_name);
  EXPECT_EQ("Mountain View", subject.locality_name);
  EXPECT_EQ("California", subject.state_or_province_name);
  EXPECT_EQ("US", subject.country_name);
  ASSERT_EQ(1U, subject.organization_names.size());
  EXPECT_EQ("Chromium = \"net_unittests\"", subject.organization_names[0]);
  ASSERT_EQ(2U, subject.organization_unit_names.size());
  EXPECT_EQ("net_unittests", subject.organization_unit_names[0]);
  EXPECT_EQ("Chromium", subject.organization_unit_names[1]);
}

TEST(X509CertificateTest, InvalidPrintableStringIsUtf8) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");

  std::string file_data;
  ASSERT_TRUE(base::ReadFileToString(
      certs_dir.AppendASCII(
          "subject_printable_string_containing_utf8_client_cert.pem"),
      &file_data));

  bssl::PEMTokenizer pem_tokenizer(file_data, {"CERTIFICATE"});
  ASSERT_TRUE(pem_tokenizer.GetNext());
  std::string cert_der(pem_tokenizer.data());
  ASSERT_FALSE(pem_tokenizer.GetNext());

  bssl::UniquePtr<CRYPTO_BUFFER> cert_handle =
      x509_util::CreateCryptoBuffer(cert_der);
  ASSERT_TRUE(cert_handle);

  EXPECT_FALSE(
      X509Certificate::CreateFromBuffer(bssl::UpRef(cert_handle.get()), {}));

  X509Certificate::UnsafeCreateOptions options;
  options.printable_string_is_utf8 = true;
  scoped_refptr<X509Certificate> cert =
      X509Certificate::CreateFromBufferUnsafeOptions(
          bssl::UpRef(cert_handle.get()), {}, options);

  const CertPrincipal& subject = cert->subject();
  EXPECT_EQ("Foo@#_ Clïênt Cërt", subject.common_name);
}

TEST(X509CertificateTest, TeletexStringIsLatin1) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "subject_t61string.pem");
  ASSERT_TRUE(cert);

  const CertPrincipal& subject = cert->subject();
  EXPECT_EQ(
      " !\"#$%&'()*+,-./"
      "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
      "abcdefghijklmnopqrstuvwxyz{|}~"
      " ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæç"
      "èéêëìíîïðñòóôõö÷øùúûüýþÿ",
      subject.organization_names[0]);
}

TEST(X509CertificateTest, TeletexStringControlChars) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "subject_t61string_1-32.pem");
  ASSERT_TRUE(cert);

  const CertPrincipal& subject = cert->subject();
  EXPECT_EQ(
      "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12"
      "\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20",
      subject.organization_names[0]);
}

TEST(X509CertificateTest, TeletexStringIsLatin1NotCp1252) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "subject_t61string_126-160.pem");
  ASSERT_TRUE(cert);

  const CertPrincipal& subject = cert->subject();
  // TeletexString is decoded as latin1, so 127-160 get decoded to equivalent
  // unicode control chars.
  EXPECT_EQ(
      "~\x7F\xC2\x80\xC2\x81\xC2\x82\xC2\x83\xC2\x84\xC2\x85\xC2\x86\xC2\x87"
      "\xC2\x88\xC2\x89\xC2\x8A\xC2\x8B\xC2\x8C\xC2\x8D\xC2\x8E\xC2\x8F\xC2\x90"
      "\xC2\x91\xC2\x92\xC2\x93\xC2\x94\xC2\x95\xC2\x96\xC2\x97\xC2\x98\xC2\x99"
      "\xC2\x9A\xC2\x9B\xC2\x9C\xC2\x9D\xC2\x9E\xC2\x9F\xC2\xA0",
      subject.organization_names[0]);
}

TEST(X509CertificateTest, TeletexStringIsNotARealT61String) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "subject_t61string_actual.pem");
  ASSERT_TRUE(cert);

  const CertPrincipal& subject = cert->subject();
  // If TeletexStrings were actually parsed according to T.61, this would be
  // "あ". (Probably. Not verified against a real implementation.)
  EXPECT_EQ("\x1B$@$\"", subject.organization_names[0]);
}

TEST(X509CertificateTest, SerialNumbers) {
  scoped_refptr<X509Certificate> google_cert(
      X509Certificate::CreateFromBytes(google_der));
  ASSERT_TRUE(google_cert);

  static const uint8_t google_serial[16] = {
    0x01,0x2a,0x39,0x76,0x0d,0x3f,0x4f,0xc9,
    0x0b,0xe7,0xbd,0x2b,0xcf,0x95,0x2e,0x7a,
  };
  EXPECT_EQ(google_cert->serial_number(), base::as_string_view(google_serial));
}

TEST(X509CertificateTest, SerialNumberZeroPadded) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "serial_zero_padded.pem");
  ASSERT_TRUE(cert);

  // Check a serial number where the first byte is >= 0x80, the DER returned by
  // serial() should contain the leading 0 padding byte.
  static const uint8_t expected_serial[3] = {0x00, 0x80, 0x01};
  EXPECT_EQ(cert->serial_number(), base::as_string_view(expected_serial));
}

TEST(X509CertificateTest, SerialNumberZeroPadded21BytesLong) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "serial_zero_padded_21_bytes.pem");
  ASSERT_TRUE(cert);

  // Check a serial number where the first byte is >= 0x80, causing the encoded
  // length to be 21 bytes long. This should be an error, but serial number
  // parsing is currently permissive.
  static const uint8_t expected_serial[21] = {
      0x00, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};
  EXPECT_EQ(cert->serial_number(), base::as_string_view(expected_serial));
}

TEST(X509CertificateTest, SerialNumberNegative) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "serial_negative.pem");
  ASSERT_TRUE(cert);

  // RFC 5280 does not allow serial numbers to be negative, but serial number
  // parsing is currently permissive, so this does not cause an error.
  static const uint8_t expected_serial[2] = {0x80, 0x01};
  EXPECT_EQ(cert->serial_number(), base::as_string_view(expected_serial));
}

TEST(X509CertificateTest, SerialNumber37BytesLong) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "serial_37_bytes.pem");
  ASSERT_TRUE(cert);

  // Check a serial number which is very long. This should be an error, but
  // serial number parsing is currently permissive.
  static const uint8_t expected_serial[37] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
      0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
      0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25};
  EXPECT_EQ(cert->serial_number(), base::as_string_view(expected_serial));
}

TEST(X509CertificateTest, SHA256FingerprintsCorrectly) {
  scoped_refptr<X509Certificate> google_cert(
      X509Certificate::CreateFromBytes(google_der));
  ASSERT_TRUE(google_cert);

  const SHA256HashValue google_sha256_fingerprint = {
      {0x21, 0xaf, 0x58, 0x74, 0xea, 0x6b, 0xad, 0xbd, 0xe4, 0xb3, 0xb1,
       0xaa, 0x53, 0x32, 0x80, 0x8f, 0xbf, 0x8a, 0x24, 0x7d, 0x98, 0xec,
       0x7f, 0x77, 0x49, 0x38, 0x42, 0x81, 0x26, 0x7f, 0xed, 0x38}};

  EXPECT_EQ(google_sha256_fingerprint, X509Certificate::CalculateFingerprint256(
                                           google_cert->cert_buffer()));
}

TEST(X509CertificateTest, CAFingerprints) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> server_cert =
      ImportCertFromFile(certs_dir, "salesforce_com_test.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), server_cert.get());

  scoped_refptr<X509Certificate> intermediate_cert1 =
      ImportCertFromFile(certs_dir, "verisign_intermediate_ca_2011.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), intermediate_cert1.get());

  scoped_refptr<X509Certificate> intermediate_cert2 =
      ImportCertFromFile(certs_dir, "verisign_intermediate_ca_2016.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), intermediate_cert2.get());

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(bssl::UpRef(intermediate_cert1->cert_buffer()));
  scoped_refptr<X509Certificate> cert_chain1 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(server_cert->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_TRUE(cert_chain1);

  intermediates.clear();
  intermediates.push_back(bssl::UpRef(intermediate_cert2->cert_buffer()));
  scoped_refptr<X509Certificate> cert_chain2 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(server_cert->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_TRUE(cert_chain2);

  // No intermediate CA certicates.
  intermediates.clear();
  scoped_refptr<X509Certificate> cert_chain3 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(server_cert->cert_buffer()),
                                        std::move(intermediates));
  ASSERT_TRUE(cert_chain3);

  SHA256HashValue cert_chain1_chain_fingerprint_256 = {
      {0xac, 0xff, 0xcc, 0x63, 0x0d, 0xd0, 0xa7, 0x19, 0x78, 0xb5, 0x8a,
       0x47, 0x8b, 0x67, 0x97, 0xcb, 0x8d, 0xe1, 0x6a, 0x8a, 0x57, 0x70,
       0xda, 0x9a, 0x53, 0x72, 0xe2, 0xa0, 0x08, 0xab, 0xcc, 0x8f}};
  SHA256HashValue cert_chain2_chain_fingerprint_256 = {
      {0x67, 0x3a, 0x11, 0x20, 0xd6, 0x94, 0x14, 0xe4, 0x16, 0x9f, 0x58,
       0xe2, 0x8b, 0xf7, 0x27, 0xed, 0xbb, 0xe8, 0xa7, 0xff, 0x1c, 0x8c,
       0x0f, 0x21, 0x38, 0x16, 0x7c, 0xad, 0x1f, 0x22, 0x6f, 0x9b}};
  SHA256HashValue cert_chain3_chain_fingerprint_256 = {
      {0x16, 0x7a, 0xbd, 0xb4, 0x57, 0x04, 0x65, 0x3c, 0x3b, 0xef, 0x6e,
       0x6a, 0xa6, 0x02, 0x73, 0x30, 0x3e, 0x34, 0x1b, 0x43, 0xc2, 0x7c,
       0x98, 0x52, 0x9f, 0x34, 0x7f, 0x55, 0x97, 0xe9, 0x1a, 0x10}};
  EXPECT_EQ(cert_chain1_chain_fingerprint_256,
            cert_chain1->CalculateChainFingerprint256());
  EXPECT_EQ(cert_chain2_chain_fingerprint_256,
            cert_chain2->CalculateChainFingerprint256());
  EXPECT_EQ(cert_chain3_chain_fingerprint_256,
            cert_chain3->CalculateChainFingerprint256());
}

TEST(X509CertificateTest, ParseSubjectAltNames) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> san_cert =
      ImportCertFromFile(certs_dir, "subjectAltName_sanity_check.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), san_cert.get());

  // Ensure that testing for SAN without using it is accepted.
  EXPECT_TRUE(san_cert->GetSubjectAltName(nullptr, nullptr));

  // Ensure that it's possible to get just dNSNames.
  std::vector<std::string> dns_names;
  EXPECT_TRUE(san_cert->GetSubjectAltName(&dns_names, nullptr));

  // Ensure that it's possible to get just iPAddresses.
  std::vector<std::string> ip_addresses;
  EXPECT_TRUE(san_cert->GetSubjectAltName(nullptr, &ip_addresses));

  // Ensure that DNS names are correctly parsed.
  ASSERT_EQ(1U, dns_names.size());
  EXPECT_EQ("test.example", dns_names[0]);

  // Ensure that both IPv4 and IPv6 addresses are correctly parsed.
  ASSERT_EQ(2U, ip_addresses.size());

  static const uint8_t kIPv4Address[] = {
      0x7F, 0x00, 0x00, 0x02
  };
  EXPECT_EQ(ip_addresses[0], base::as_string_view(kIPv4Address));

  static const uint8_t kIPv6Address[] = {
      0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
  };
  EXPECT_EQ(ip_addresses[1], base::as_string_view(kIPv6Address));

  // Ensure the subjectAltName dirName has not influenced the handling of
  // the subject commonName.
  EXPECT_EQ("127.0.0.1", san_cert->subject().common_name);

  scoped_refptr<X509Certificate> no_san_cert =
      ImportCertFromFile(certs_dir, "salesforce_com_test.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), no_san_cert.get());

  EXPECT_NE(0u, dns_names.size());
  EXPECT_NE(0u, ip_addresses.size());
  EXPECT_FALSE(no_san_cert->GetSubjectAltName(&dns_names, &ip_addresses));
  EXPECT_EQ(0u, dns_names.size());
  EXPECT_EQ(0u, ip_addresses.size());
}

TEST(X509CertificateTest, ExtractSPKIFromDERCert) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "nist.der");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), cert.get());

  std::string_view spkiBytes;
  EXPECT_TRUE(asn1::ExtractSPKIFromDERCert(
      base::as_string_view(cert->cert_span()), &spkiBytes));
  base::SHA1Digest hash = base::SHA1Hash(base::as_byte_span(spkiBytes));
  EXPECT_EQ(base::span(hash), base::as_byte_span(kNistSPKIHash));
}

TEST(X509CertificateTest, HasCanSignHttpExchangesDraftExtension) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert = ImportCertFromFile(
      certs_dir, "can_sign_http_exchanges_draft_extension.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), cert.get());

  EXPECT_TRUE(asn1::HasCanSignHttpExchangesDraftExtension(
      x509_util::CryptoBufferAsStringPiece(cert->cert_buffer())));
}

TEST(X509CertificateTest, HasCanSignHttpExchangesDraftExtensionInvalid) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert = ImportCertFromFile(
      certs_dir, "can_sign_http_exchanges_draft_extension_invalid.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), cert.get());

  EXPECT_FALSE(asn1::HasCanSignHttpExchangesDraftExtension(
      x509_util::CryptoBufferAsStringPiece(cert->cert_buffer())));
}

TEST(X509CertificateTest, DoesNotHaveCanSignHttpExchangesDraftExtension) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "ok_cert.pem");
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), cert.get());

  EXPECT_FALSE(asn1::HasCanSignHttpExchangesDraftExtension(
      x509_util::CryptoBufferAsStringPiece(cert->cert_buffer())));
}

TEST(X509CertificateTest, ExtractExtension) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(certs_dir, "ok_cert.pem");
  ASSERT_TRUE(cert);

  bool present, critical;
  std::string_view contents;
  ASSERT_TRUE(asn1::ExtractExtensionFromDERCert(
      x509_util::CryptoBufferAsStringPiece(cert->cert_buffer()),
      bssl::der::Input(bssl::kBasicConstraintsOid).AsStringView(), &present,
      &critical, &contents));
  EXPECT_TRUE(present);
  EXPECT_TRUE(critical);
  ASSERT_EQ(std::string_view("\x30\x00", 2), contents);

  static constexpr uint8_t kNonsenseOID[] = {0x56, 0x1d, 0x13};
  ASSERT_TRUE(asn1::ExtractExtensionFromDERCert(
      x509_util::CryptoBufferAsStringPiece(cert->cert_buffer()),
      base::as_string_view(kNonsenseOID), &present, &critical, &contents));
  ASSERT_FALSE(present);

  scoped_refptr<X509Certificate> uid_cert =
      ImportCertFromFile(certs_dir, "ct-test-embedded-with-uids.pem");
  ASSERT_TRUE(uid_cert);
  ASSERT_TRUE(asn1::ExtractExtensionFromDERCert(
      x509_util::CryptoBufferAsStringPiece(uid_cert->cert_buffer()),
      bssl::der::Input(bssl::kBasicConstraintsOid).AsStringView(), &present,
      &critical, &contents));
  EXPECT_TRUE(present);
  EXPECT_FALSE(critical);
  ASSERT_EQ(std::string_view("\x30\x00", 2), contents);
}

// Tests CRYPTO_BUFFER deduping via X509Certificate::CreateFromBuffer.  We
// call X509Certificate::CreateFromBuffer several times and observe whether
// it returns a cached or new CRYPTO_BUFFER.
TEST(X509CertificateTest, Cache) {
  bssl::UniquePtr<CRYPTO_BUFFER> google_cert_handle;
  bssl::UniquePtr<CRYPTO_BUFFER> thawte_cert_handle;

  // Add a single certificate to the certificate cache.
  google_cert_handle = x509_util::CreateCryptoBuffer(google_der);
  ASSERT_TRUE(google_cert_handle);
  scoped_refptr<X509Certificate> cert1(
      X509Certificate::CreateFromBuffer(std::move(google_cert_handle), {}));
  ASSERT_TRUE(cert1);

  // Add the same certificate, but as a new handle.
  google_cert_handle = x509_util::CreateCryptoBuffer(google_der);
  ASSERT_TRUE(google_cert_handle);
  scoped_refptr<X509Certificate> cert2(
      X509Certificate::CreateFromBuffer(std::move(google_cert_handle), {}));
  ASSERT_TRUE(cert2);

  // A new X509Certificate should be returned.
  EXPECT_NE(cert1.get(), cert2.get());
  // But both instances should share the underlying OS certificate handle.
  EXPECT_EQ(cert1->cert_buffer(), cert2->cert_buffer());
  EXPECT_EQ(0u, cert1->intermediate_buffers().size());
  EXPECT_EQ(0u, cert2->intermediate_buffers().size());

  // Add the same certificate, but this time with an intermediate. This
  // should result in the intermediate being cached. Note that this is not
  // a legitimate chain, but is suitable for testing.
  google_cert_handle = x509_util::CreateCryptoBuffer(google_der);
  thawte_cert_handle = x509_util::CreateCryptoBuffer(thawte_der);
  ASSERT_TRUE(google_cert_handle);
  ASSERT_TRUE(thawte_cert_handle);
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(std::move(thawte_cert_handle));
  scoped_refptr<X509Certificate> cert3(X509Certificate::CreateFromBuffer(
      std::move(google_cert_handle), std::move(intermediates)));
  ASSERT_TRUE(cert3);

  // Test that the new certificate, even with intermediates, results in the
  // same underlying handle being used.
  EXPECT_EQ(cert1->cert_buffer(), cert3->cert_buffer());
  // Though they use the same OS handle, the intermediates should be different.
  EXPECT_NE(cert1->intermediate_buffers().size(),
            cert3->intermediate_buffers().size());
}

TEST(X509CertificateTest, CloneWithDifferentIntermediates) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "multi-root-chain1.pem",
      X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  ASSERT_EQ(4u, certs.size());

  auto leaf_with_no_intermediates = certs[0];

  {
    auto cloned =
        leaf_with_no_intermediates->CloneWithDifferentIntermediates({});
    // Intermediates are equal, so should return a reference to the same object.
    EXPECT_EQ(leaf_with_no_intermediates.get(), cloned.get());
  }
  {
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
    intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
    intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));
    auto cloned = leaf_with_no_intermediates->CloneWithDifferentIntermediates(
        std::move(intermediates));
    ASSERT_TRUE(cloned);
    EXPECT_NE(leaf_with_no_intermediates.get(), cloned.get());
    EXPECT_EQ(leaf_with_no_intermediates->cert_buffer(), cloned->cert_buffer());
    ExpectX509CertificateMembersEqual(leaf_with_no_intermediates, cloned);
    ASSERT_EQ(2u, cloned->intermediate_buffers().size());
    EXPECT_TRUE(x509_util::CryptoBufferEqual(
        certs[1]->cert_buffer(), cloned->intermediate_buffers()[0].get()));
    EXPECT_TRUE(x509_util::CryptoBufferEqual(
        certs[2]->cert_buffer(), cloned->intermediate_buffers()[1].get()));
  }

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> leaf_intermediates;
  leaf_intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  leaf_intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));
  auto leaf_with_intermediates = X509Certificate::CreateFromBuffer(
      bssl::UpRef(certs[0]->cert_buffer()), std::move(leaf_intermediates));
  ASSERT_TRUE(leaf_with_intermediates);

  {
    auto cloned = leaf_with_intermediates->CloneWithDifferentIntermediates({});
    EXPECT_NE(leaf_with_intermediates.get(), cloned.get());
    EXPECT_EQ(leaf_with_intermediates->cert_buffer(), cloned->cert_buffer());
    ExpectX509CertificateMembersEqual(leaf_with_intermediates, cloned);
    ASSERT_EQ(0u, cloned->intermediate_buffers().size());
  }
  {
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
    intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
    intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));
    auto cloned = leaf_with_intermediates->CloneWithDifferentIntermediates(
        std::move(intermediates));
    // Intermediates are equal, so should return a reference to the same object.
    EXPECT_EQ(leaf_with_intermediates.get(), cloned.get());
  }
  {
    std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
    intermediates.push_back(bssl::UpRef(certs[2]->cert_buffer()));
    intermediates.push_back(bssl::UpRef(certs[1]->cert_buffer()));
    auto cloned = leaf_with_intermediates->CloneWithDifferentIntermediates(
        std::move(intermediates));
    // Intermediates are different (same buffers but in different order).
    ASSERT_TRUE(cloned);
    EXPECT_NE(leaf_with_intermediates.get(), cloned.get());
    EXPECT_EQ(leaf_with_intermediates->cert_buffer(), cloned->cert_buffer());
    ExpectX509CertificateMembersEqual(leaf_with_intermediates, cloned);
    ASSERT_EQ(2u, cloned->intermediate_buffers().size());
    EXPECT_TRUE(x509_util::CryptoBufferEqual(
        certs[2]->cert_buffer(), cloned->intermediate_buffers()[0].get()));
    EXPECT_TRUE(x509_util::CryptoBufferEqual(
        certs[1]->cert_buffer(), cloned->intermediate_buffers()[1].get()));
  }
}

TEST(X509CertificateTest, Pickle) {
  bssl::UniquePtr<CRYPTO_BUFFER> google_cert_handle =
      x509_util::CreateCryptoBuffer(google_der);
  ASSERT_TRUE(google_cert_handle);
  bssl::UniquePtr<CRYPTO_BUFFER> thawte_cert_handle =
      x509_util::CreateCryptoBuffer(thawte_der);
  ASSERT_TRUE(thawte_cert_handle);

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  intermediates.push_back(std::move(thawte_cert_handle));
  scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromBuffer(
      std::move(google_cert_handle), std::move(intermediates));
  ASSERT_TRUE(cert);

  base::Pickle pickle;
  cert->Persist(&pickle);

  base::PickleIterator iter(pickle);
  scoped_refptr<X509Certificate> cert_from_pickle =
      X509Certificate::Creat
"""


```