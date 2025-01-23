Response:
The user wants me to analyze the provided C++ code snippet, which is part of a unit test file for X.509 certificates in the Chromium project.

Here's a breakdown of the analysis I need to perform:

1. **Functionality Listing**: Identify what the code tests. This involves looking at the `TEST` macros and the operations performed within them.
2. **JavaScript Relationship**: Determine if any of the tested functionalities directly relate to how JavaScript interacts with certificates in a browser environment.
3. **Logic Inference (Hypothetical I/O)**: For tests that involve comparisons or specific operations, create hypothetical input and expected output scenarios.
4. **Common Usage Errors**: Identify potential mistakes developers might make when using the `X509Certificate` API based on the test cases.
5. **User Operation to Reach Code**: Explain how a user's actions in a browser could indirectly lead to this code being executed (as part of certificate handling).
6. **Overall Functionality Summary**:  Provide a concise summary of the code's purpose.

**Plan:**

* Go through each `TEST` function and describe its purpose.
* Analyze the interactions with `X509Certificate` methods.
* Consider how these tests might reflect real-world scenarios.
这是对 `net/cert/x509_certificate_unittest.cc` 文件剩余部分的分析，主要关注 X.509 证书的各种功能测试。

**功能列举:**

* **序列化和反序列化测试 (Pickling/Unpickling):** 测试将 `X509Certificate` 对象序列化到数据流（Pickle）以及从数据流恢复的能力，确保证书及其中间证书在序列化和反序列化后保持不变。
* **中间证书处理测试 (Intermediate Certificates):** 测试创建包含中间证书的 `X509Certificate` 对象的能力，并验证是否正确存储和访问了这些中间证书。
* **相等性比较测试 (Equals):** 测试比较两个 `X509Certificate` 对象是否相等的功能，区分是否需要比较证书链 (包含中间证书)。
* **颁发者验证测试 (IsIssuedByEncoded):** 测试判断一个证书是否由指定的颁发者颁发的功能，可以指定多个颁发者。
* **自签名证书测试 (IsSelfSigned):** 测试判断一个证书是否为自签名证书的功能。
* **包含中间证书的颁发者验证测试 (IsIssuedByEncodedWithIntermediates):** 测试当 `X509Certificate` 对象包含中间证书时，判断其是否由指定的颁发者 (包括根证书) 颁发的功能。
* **证书格式解析测试 (Certificate Format Parsing):** 测试解析不同格式 (DER, PEM, PKCS#7) 的证书数据，并验证解析后的证书指纹是否与预期一致。
* **主机名验证测试 (Hostname Verification):** 测试使用证书中的 DNS 名称或 IP 地址验证给定主机名的功能，涵盖通配符、IDN、IP 地址等情况。
* **公钥信息获取测试 (Public Key Information):** 测试获取证书公钥信息 (位数和类型) 的功能。

**与 Javascript 功能的关系及举例说明:**

`X509Certificate` 的功能直接关系到浏览器如何验证 HTTPS 连接的安全性。当 JavaScript 发起 HTTPS 请求时，浏览器底层会使用类似 `X509Certificate` 这样的类来处理服务器返回的证书链。

* **证书格式解析和验证:** 当浏览器接收到服务器发送的证书时，需要解析证书的格式 (DER 或 PEM)。JavaScript 本身不直接处理这些底层细节，但可以通过浏览器提供的 API (例如 `fetch` 或 `XMLHttpRequest`) 发起请求，浏览器会自动处理证书验证。如果解析失败或格式不正确，浏览器会阻止连接，并可能在开发者工具中显示错误信息。
* **主机名验证:**  浏览器需要验证服务器证书中的域名是否与用户在地址栏中输入的域名一致，以防止中间人攻击。JavaScript 可以通过 `window.location.hostname` 获取当前页面的主机名，但这主要是用于页面逻辑，底层的证书验证是由浏览器内核完成的，涉及到 `X509Certificate::VerifyHostname` 这样的函数。
* **颁发者验证:** 浏览器会检查服务器证书是否由受信任的证书颁发机构 (CA) 签名。用户可以通过浏览器设置查看受信任的根证书列表。JavaScript 可以使用 `navigator.credentials.get()` 等 API 来获取客户端证书，但这与服务器证书的验证是不同的概念。

**举例说明:**

假设用户在浏览器的地址栏中输入 `https://www.example.com`。

1. 浏览器建立 TCP 连接后，服务器会发送其 SSL/TLS 证书。
2. 浏览器内核会使用类似 `X509Certificate::CreateFromBytes` 的函数解析服务器发送的证书数据。
3. 浏览器会调用 `X509Certificate::VerifyHostname("www.example.com", ...)` 来验证证书中的域名是否包含 `www.example.com`。
4. 浏览器会遍历证书链，并使用 `X509Certificate::IsIssuedByEncoded` 等函数验证证书链中的每个证书是否由其上级证书颁发，最终验证根证书是否在受信任的 CA 列表中。
5. 如果证书验证失败 (例如，域名不匹配，证书过期，颁发者不可信)，浏览器会阻止页面加载，并显示安全警告。JavaScript 代码将无法成功发起后续的资源请求。

**逻辑推理 (假设输入与输出):**

* **`TEST(X509CertificateTest, Equals)`:**
    * **假设输入:** 两个 `X509Certificate` 对象，`certA` 和 `certB`，它们具有相同的证书内容但 `certB` 包含一个额外的中间证书。
    * **预期输出:**
        * `certA->EqualsExcludingChain(certB.get())` 返回 `true` (因为只比较证书本身)。
        * `certA->EqualsIncludingChain(certB.get())` 返回 `false` (因为证书链不同)。

* **`TEST(X509CertificateTest, IsIssuedByEncoded)`:**
    * **假设输入:** 一个由 "MITDN" 颁发的证书 `mit_cert` 和一个由 "ThawteDN" 颁发的证书 `google_cert`。
    * **预期输出:**
        * `mit_cert->IsIssuedByEncoded({"MITDN"})` 返回 `true`。
        * `mit_cert->IsIssuedByEncoded({"ThawteDN"})` 返回 `false`。
        * `google_cert->IsIssuedByEncoded({"ThawteDN"})` 返回 `true`。
        * `google_cert->IsIssuedByEncoded({"MITDN"})` 返回 `false`。

* **`TEST_P(X509CertificateNameVerifyTest, VerifyHostname)`:**
    * **假设输入:** `test_data.hostname = "www.example.com"`, `test_data.dns_names = "*.example.com"`, `test_data.expected = true`.
    * **预期输出:** `X509Certificate::VerifyHostname("www.example.com", {"*.example.com"}, {})` 返回 `true`.

**用户或编程常见的使用错误及举例说明:**

* **在比较证书时没有考虑证书链:**  开发者可能错误地使用 `EqualsExcludingChain` 来比较需要包含证书链的场景，导致误判两个具有不同中间证书链但根证书相同的证书为相等。
    * **例子:** 开发者在缓存证书时，可能只比较了证书本身，而忽略了中间证书的变化，导致后续连接时使用了错误的证书链。
* **在进行主机名验证时，对通配符的理解有误:**  开发者可能错误地认为 `*.example.*` 可以匹配 `foo.example.com`，而实际上 RFC 6125 规定通配符只能出现在最左边的标签。
    * **例子:** 开发者编写代码来校验证书域名时，可能错误地使用了不符合规范的通配符匹配逻辑。
* **没有正确处理不同格式的证书数据:** 开发者可能假设所有证书都是 PEM 格式，而没有处理 DER 或 PKCS#7 格式的情况，导致解析错误。
    * **例子:** 开发者从某个 API 获取证书数据时，没有检查返回的格式，直接按照 PEM 格式解析，当遇到 DER 格式的证书时就会失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 HTTPS 网址并访问。** 例如：`https://www.example.com`。
2. **浏览器发起网络请求，与服务器建立 TLS 连接。**  这个过程中会涉及到证书的协商和交换。
3. **服务器向浏览器发送其 SSL/TLS 证书链。**
4. **浏览器接收到证书数据后，会调用 Chromium 网络栈中与证书处理相关的代码，例如 `X509Certificate::CreateFromBytes` 来解析证书。**
5. **浏览器会进行一系列的证书验证，包括:**
    * **格式验证:** 确保证书是有效的 DER 或 PEM 格式。
    * **签名验证:** 验证证书的签名是否有效。
    * **有效期验证:** 检查证书是否在有效期内。
    * **吊销状态检查:** (可能) 检查证书是否被吊销。
    * **主机名验证:** 调用 `X509Certificate::VerifyHostname` 检查证书中的域名是否与用户访问的域名匹配。
    * **颁发者验证:** 调用 `X509Certificate::IsIssuedByEncoded` 等函数验证证书链的信任关系。
6. **如果任何验证步骤失败，浏览器会终止连接并显示安全警告。**
7. **如果开发者需要调试证书相关的问题，他们可能会使用 Chromium 的网络日志 (net-internals) 或抓包工具来查看证书的详细信息，并查看相关的错误信息。**  如果问题涉及到 `X509Certificate` 类的具体行为，那么相关的单元测试 (如本文件) 可以作为理解代码逻辑和验证修复方案的参考。

**功能归纳:**

这部分代码主要对 `net/cert/x509_certificate.cc` 中 `X509Certificate` 类的核心功能进行单元测试，包括证书的创建、序列化、相等性比较、颁发者验证、自签名判断、格式解析以及主机名验证等关键操作。这些测试旨在确保 `X509Certificate` 类能够正确可靠地处理各种类型的 X.509 证书数据，是 Chromium 网络栈安全性的重要组成部分。

### 提示词
```
这是目录为net/cert/x509_certificate_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
eFromPickle(&iter);
  ASSERT_TRUE(cert_from_pickle);
  EXPECT_TRUE(x509_util::CryptoBufferEqual(cert->cert_buffer(),
                                           cert_from_pickle->cert_buffer()));
  const auto& cert_intermediates = cert->intermediate_buffers();
  const auto& pickle_intermediates = cert_from_pickle->intermediate_buffers();
  ASSERT_EQ(cert_intermediates.size(), pickle_intermediates.size());
  for (size_t i = 0; i < cert_intermediates.size(); ++i) {
    EXPECT_TRUE(x509_util::CryptoBufferEqual(cert_intermediates[i].get(),
                                             pickle_intermediates[i].get()));
  }
}

TEST(X509CertificateTest, IntermediateCertificates) {
  scoped_refptr<X509Certificate> webkit_cert(
      X509Certificate::CreateFromBytes(webkit_der));
  ASSERT_TRUE(webkit_cert);

  scoped_refptr<X509Certificate> thawte_cert(
      X509Certificate::CreateFromBytes(thawte_der));
  ASSERT_TRUE(thawte_cert);

  bssl::UniquePtr<CRYPTO_BUFFER> google_handle;
  // Create object with no intermediates:
  google_handle = x509_util::CreateCryptoBuffer(google_der);
  scoped_refptr<X509Certificate> cert1;
  cert1 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(google_handle.get()), {});
  ASSERT_TRUE(cert1);
  EXPECT_EQ(0u, cert1->intermediate_buffers().size());

  // Create object with 2 intermediates:
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates2;
  intermediates2.push_back(bssl::UpRef(webkit_cert->cert_buffer()));
  intermediates2.push_back(bssl::UpRef(thawte_cert->cert_buffer()));
  scoped_refptr<X509Certificate> cert2 = X509Certificate::CreateFromBuffer(
      std::move(google_handle), std::move(intermediates2));
  ASSERT_TRUE(cert2);

  // Verify it has all the intermediates:
  const auto& cert2_intermediates = cert2->intermediate_buffers();
  ASSERT_EQ(2u, cert2_intermediates.size());
  EXPECT_TRUE(x509_util::CryptoBufferEqual(cert2_intermediates[0].get(),
                                           webkit_cert->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(cert2_intermediates[1].get(),
                                           thawte_cert->cert_buffer()));
}

TEST(X509CertificateTest, Equals) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "multi-root-chain1.pem",
      X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  ASSERT_EQ(4u, certs.size());

  // Comparing X509Certificates with no intermediates.
  EXPECT_TRUE(certs[0]->EqualsExcludingChain(certs[0].get()));
  EXPECT_FALSE(certs[1]->EqualsExcludingChain(certs[0].get()));
  EXPECT_FALSE(certs[0]->EqualsExcludingChain(certs[1].get()));
  EXPECT_TRUE(certs[0]->EqualsIncludingChain(certs[0].get()));
  EXPECT_FALSE(certs[1]->EqualsIncludingChain(certs[0].get()));
  EXPECT_FALSE(certs[0]->EqualsIncludingChain(certs[1].get()));

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates1;
  intermediates1.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  scoped_refptr<X509Certificate> cert0_with_intermediate =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates1));
  ASSERT_TRUE(cert0_with_intermediate);

  // Comparing X509Certificate with one intermediate to X509Certificate with no
  // intermediates.
  EXPECT_TRUE(certs[0]->EqualsExcludingChain(cert0_with_intermediate.get()));
  EXPECT_TRUE(cert0_with_intermediate->EqualsExcludingChain(certs[0].get()));
  EXPECT_FALSE(certs[0]->EqualsIncludingChain(cert0_with_intermediate.get()));
  EXPECT_FALSE(cert0_with_intermediate->EqualsIncludingChain(certs[0].get()));

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates2;
  intermediates2.push_back(bssl::UpRef(certs[2]->cert_buffer()));
  scoped_refptr<X509Certificate> cert0_with_intermediate2 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates2));
  ASSERT_TRUE(cert0_with_intermediate2);

  // Comparing X509Certificate with one intermediate to X509Certificate with
  // one different intermediate.
  EXPECT_TRUE(cert0_with_intermediate2->EqualsExcludingChain(
      cert0_with_intermediate.get()));
  EXPECT_TRUE(cert0_with_intermediate->EqualsExcludingChain(
      cert0_with_intermediate2.get()));
  EXPECT_FALSE(cert0_with_intermediate2->EqualsIncludingChain(
      cert0_with_intermediate.get()));
  EXPECT_FALSE(cert0_with_intermediate->EqualsIncludingChain(
      cert0_with_intermediate2.get()));

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates12;
  intermediates12.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  intermediates12.push_back(bssl::UpRef(certs[2]->cert_buffer()));
  scoped_refptr<X509Certificate> cert0_with_intermediates12 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates12));
  ASSERT_TRUE(cert0_with_intermediates12);

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates21;
  intermediates21.push_back(bssl::UpRef(certs[2]->cert_buffer()));
  intermediates21.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  scoped_refptr<X509Certificate> cert0_with_intermediates21 =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates21));
  ASSERT_TRUE(cert0_with_intermediates21);

  // Comparing X509Certificate with two intermediates to X509Certificate with
  // same two intermediates but in reverse order
  EXPECT_TRUE(cert0_with_intermediates21->EqualsExcludingChain(
      cert0_with_intermediates12.get()));
  EXPECT_TRUE(cert0_with_intermediates12->EqualsExcludingChain(
      cert0_with_intermediates21.get()));
  EXPECT_FALSE(cert0_with_intermediates21->EqualsIncludingChain(
      cert0_with_intermediates12.get()));
  EXPECT_FALSE(cert0_with_intermediates12->EqualsIncludingChain(
      cert0_with_intermediates21.get()));

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates12b;
  intermediates12b.push_back(bssl::UpRef(certs[1]->cert_buffer()));
  intermediates12b.push_back(bssl::UpRef(certs[2]->cert_buffer()));
  scoped_refptr<X509Certificate> cert0_with_intermediates12b =
      X509Certificate::CreateFromBuffer(bssl::UpRef(certs[0]->cert_buffer()),
                                        std::move(intermediates12b));
  ASSERT_TRUE(cert0_with_intermediates12b);

  // Comparing X509Certificate with two intermediates to X509Certificate with
  // same two intermediates in same order.
  EXPECT_TRUE(cert0_with_intermediates12->EqualsExcludingChain(
      cert0_with_intermediates12b.get()));
  EXPECT_TRUE(cert0_with_intermediates12b->EqualsExcludingChain(
      cert0_with_intermediates12.get()));
  EXPECT_TRUE(cert0_with_intermediates12->EqualsIncludingChain(
      cert0_with_intermediates12b.get()));
  EXPECT_TRUE(cert0_with_intermediates12b->EqualsIncludingChain(
      cert0_with_intermediates12.get()));
}

TEST(X509CertificateTest, IsIssuedByEncoded) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  // Test a client certificate from MIT.
  scoped_refptr<X509Certificate> mit_davidben_cert(
      ImportCertFromFile(certs_dir, "mit.davidben.der"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), mit_davidben_cert.get());

  std::string mit_issuer{base::as_string_view(MITDN)};

  // Test a certificate from Google, issued by Thawte
  scoped_refptr<X509Certificate> google_cert(
      ImportCertFromFile(certs_dir, "google.single.der"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), google_cert.get());

  std::string thawte_issuer{base::as_string_view(ThawteDN)};

  // Check that the David Ben certificate is issued by MIT, but not
  // by Thawte.
  std::vector<std::string> issuers;
  issuers.clear();
  issuers.push_back(mit_issuer);
  EXPECT_TRUE(mit_davidben_cert->IsIssuedByEncoded(issuers));
  EXPECT_FALSE(google_cert->IsIssuedByEncoded(issuers));

  // Check that the Google certificate is issued by Thawte and not
  // by MIT.
  issuers.clear();
  issuers.push_back(thawte_issuer);
  EXPECT_FALSE(mit_davidben_cert->IsIssuedByEncoded(issuers));
  EXPECT_TRUE(google_cert->IsIssuedByEncoded(issuers));

  // Check that they both pass when given a list of the two issuers.
  issuers.clear();
  issuers.push_back(mit_issuer);
  issuers.push_back(thawte_issuer);
  EXPECT_TRUE(mit_davidben_cert->IsIssuedByEncoded(issuers));
  EXPECT_TRUE(google_cert->IsIssuedByEncoded(issuers));
}

TEST(X509CertificateTest, IsSelfSigned) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(certs_dir, "mit.davidben.der"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), cert.get());
  EXPECT_FALSE(X509Certificate::IsSelfSigned(cert->cert_buffer()));

  scoped_refptr<X509Certificate> self_signed(
      ImportCertFromFile(certs_dir, "root_ca_cert.pem"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), self_signed.get());
  EXPECT_TRUE(X509Certificate::IsSelfSigned(self_signed->cert_buffer()));

  scoped_refptr<X509Certificate> bad_name(
      ImportCertFromFile(certs_dir, "self-signed-invalid-name.pem"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), bad_name.get());
  EXPECT_FALSE(X509Certificate::IsSelfSigned(bad_name->cert_buffer()));

  scoped_refptr<X509Certificate> bad_sig(
      ImportCertFromFile(certs_dir, "self-signed-invalid-sig.pem"));
  ASSERT_NE(static_cast<X509Certificate*>(nullptr), bad_sig.get());
  EXPECT_FALSE(X509Certificate::IsSelfSigned(bad_sig->cert_buffer()));

  constexpr char invalid_cert_data[] = "this is not a certificate";
  bssl::UniquePtr<CRYPTO_BUFFER> invalid_cert_handle =
      x509_util::CreateCryptoBuffer(std::string_view(invalid_cert_data));
  ASSERT_TRUE(invalid_cert_handle);
  EXPECT_FALSE(X509Certificate::IsSelfSigned(invalid_cert_handle.get()));
}

TEST(X509CertificateTest, IsIssuedByEncodedWithIntermediates) {
  auto [leaf, intermediate, root] = CertBuilder::CreateSimpleChain3();

  std::string intermediate_dn = intermediate->GetSubject();
  std::string root_dn = root->GetSubject();

  // Create an X509Certificate object containing the leaf and the intermediate
  // but not the root.
  scoped_refptr<X509Certificate> cert_chain = leaf->GetX509CertificateChain();
  ASSERT_TRUE(cert_chain);

  // Check that the chain is issued by the intermediate.
  EXPECT_TRUE(cert_chain->IsIssuedByEncoded({intermediate_dn}));

  // Check that the chain is also issued by the root.
  EXPECT_TRUE(cert_chain->IsIssuedByEncoded({root_dn}));

  // Check that the chain is issued by either the intermediate or the root.
  EXPECT_TRUE(cert_chain->IsIssuedByEncoded({intermediate_dn, root_dn}));

  // Check that an empty issuers list returns false.
  EXPECT_FALSE(cert_chain->IsIssuedByEncoded({}));

  // Check that the chain is not issued by Verisign
  std::string verisign_issuer{base::as_string_view(VerisignDN)};
  EXPECT_FALSE(cert_chain->IsIssuedByEncoded({verisign_issuer}));

  // Check that the chain is issued by root, though the extraneous Verisign
  // name is also given.
  EXPECT_TRUE(cert_chain->IsIssuedByEncoded({verisign_issuer, root_dn}));
}

const struct CertificateFormatTestData {
  const char* file_name;
  X509Certificate::Format format;
  std::array<SHA256HashValue*, 3> chain_fingerprints;
} kFormatTestData[] = {
    // DER Parsing - single certificate, DER encoded
    {"google.single.der",
     X509Certificate::FORMAT_SINGLE_CERTIFICATE,
     {
         &google_parse_fingerprint,
         nullptr,
     }},
    // DER parsing - single certificate, PEM encoded
    {"google.single.pem",
     X509Certificate::FORMAT_SINGLE_CERTIFICATE,
     {
         &google_parse_fingerprint,
         nullptr,
     }},
    // PEM parsing - single certificate, PEM encoded with a PEB of
    // "CERTIFICATE"
    {"google.single.pem",
     X509Certificate::FORMAT_PEM_CERT_SEQUENCE,
     {
         &google_parse_fingerprint,
         nullptr,
     }},
    // PEM parsing - sequence of certificates, PEM encoded with a PEB of
    // "CERTIFICATE"
    {"google.chain.pem",
     X509Certificate::FORMAT_PEM_CERT_SEQUENCE,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
    // PKCS#7 parsing - "degenerate" SignedData collection of certificates, DER
    // encoding
    {"google.binary.p7b",
     X509Certificate::FORMAT_PKCS7,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
    // PKCS#7 parsing - "degenerate" SignedData collection of certificates, PEM
    // encoded with a PEM PEB of "CERTIFICATE"
    {"google.pem_cert.p7b",
     X509Certificate::FORMAT_PKCS7,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
    // PKCS#7 parsing - "degenerate" SignedData collection of certificates, PEM
    // encoded with a PEM PEB of "PKCS7"
    {"google.pem_pkcs7.p7b",
     X509Certificate::FORMAT_PKCS7,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
    // All of the above, this time using auto-detection
    {"google.single.der",
     X509Certificate::FORMAT_AUTO,
     {
         &google_parse_fingerprint,
         nullptr,
     }},
    {"google.single.pem",
     X509Certificate::FORMAT_AUTO,
     {
         &google_parse_fingerprint,
         nullptr,
     }},
    {"google.chain.pem",
     X509Certificate::FORMAT_AUTO,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
    {"google.binary.p7b",
     X509Certificate::FORMAT_AUTO,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
    {"google.pem_cert.p7b",
     X509Certificate::FORMAT_AUTO,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
    {"google.pem_pkcs7.p7b",
     X509Certificate::FORMAT_AUTO,
     {
         &google_parse_fingerprint,
         &thawte_parse_fingerprint,
         nullptr,
     }},
};

class X509CertificateParseTest
    : public testing::TestWithParam<CertificateFormatTestData> {
 public:
  ~X509CertificateParseTest() override = default;
  void SetUp() override { test_data_ = GetParam(); }
  void TearDown() override {}

 protected:
  CertificateFormatTestData test_data_;
};

TEST_P(X509CertificateParseTest, CanParseFormat) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, test_data_.file_name, test_data_.format);
  ASSERT_FALSE(certs.empty());
  ASSERT_LE(certs.size(), std::size(test_data_.chain_fingerprints));
  CheckGoogleCert(certs.front(), google_parse_fingerprint,
                  kGoogleParseValidFrom, kGoogleParseValidTo);

  for (size_t i = 0; i < std::size(test_data_.chain_fingerprints); ++i) {
    if (!test_data_.chain_fingerprints[i]) {
      // No more test certificates expected - make sure no more were
      // returned before marking this test a success.
      EXPECT_EQ(i, certs.size());
      break;
    }

    // A cert is expected - make sure that one was parsed.
    ASSERT_LT(i, certs.size());
    ASSERT_TRUE(certs[i]);

    // Compare the parsed certificate with the expected certificate, by
    // comparing fingerprints.
    EXPECT_EQ(
        *test_data_.chain_fingerprints[i],
        X509Certificate::CalculateFingerprint256(certs[i]->cert_buffer()));
  }
}

INSTANTIATE_TEST_SUITE_P(All,
                         X509CertificateParseTest,
                         testing::ValuesIn(kFormatTestData));

struct CertificateNameVerifyTestData {
  // true iff we expect hostname to match an entry in cert_names.
  bool expected;
  // The hostname to match.
  const char* hostname;
  // Comma separated list of certificate names to match against. Any occurrence
  // of '#' will be replaced with a null character before processing.
  const char* dns_names;
  // Comma separated list of certificate IP Addresses to match against. Each
  // address is x prefixed 16 byte hex code for v6 or dotted-decimals for v4.
  const char* ip_addrs;
};

// GTest 'magic' pretty-printer, so that if/when a test fails, it knows how
// to output the parameter that was passed. Without this, it will simply
// attempt to print out the first twenty bytes of the object, which depending
// on platform and alignment, may result in an invalid read.
void PrintTo(const CertificateNameVerifyTestData& data, std::ostream* os) {
  ASSERT_TRUE(data.hostname);
  ASSERT_TRUE(data.dns_names || data.ip_addrs);
  *os << " expected: " << data.expected << "; hostname: " << data.hostname
      << "; dns_names: " << (data.dns_names ? data.dns_names : "")
      << "; ip_addrs: " << (data.ip_addrs ? data.ip_addrs : "");
}

const CertificateNameVerifyTestData kNameVerifyTestData[] = {
    {true, "foo.com", "foo.com"},
    {true, "f", "f"},
    {false, "h", "i"},
    {true, "bar.foo.com", "*.foo.com"},
    {true, "www.test.fr", "*.test.com,*.test.co.uk,*.test.de,*.test.fr"},
    {true, "wwW.tESt.fr", ",*.*,*.test.de,*.test.FR,www"},
    {false, "f.uk", ".uk"},
    {false, "w.bar.foo.com", "?.bar.foo.com"},
    {false, "www.foo.com", "(www|ftp).foo.com"},
    {false, "www.foo.com", "www.foo.com#"},  // # = null char.
    {false, "www.foo.com", "www.foo.com#*.foo.com,#,#"},
    {false, "www.house.example", "ww.house.example"},
    {false, "test.org", "www.test.org,*.test.org,*.org"},
    {false, "w.bar.foo.com", "w*.bar.foo.com"},
    {false, "www.bar.foo.com", "ww*ww.bar.foo.com"},
    {false, "wwww.bar.foo.com", "ww*ww.bar.foo.com"},
    {false, "wwww.bar.foo.com", "w*w.bar.foo.com"},
    {false, "wwww.bar.foo.com", "w*w.bar.foo.c0m"},
    {false, "WALLY.bar.foo.com", "wa*.bar.foo.com"},
    {false, "wally.bar.foo.com", "*Ly.bar.foo.com"},
    // Hostname escaping tests
    {true, "ww%57.foo.com", "www.foo.com"},
    {true, "www%2Efoo.com", "www.foo.com"},
    {false, "www%00.foo.com", "www,foo.com,www.foo.com"},
    {false, "www%0D.foo.com", "www.foo.com,www\r.foo.com"},
    {false, "www%40foo.com", "www@foo.com"},
    {false, "www%2E%2Efoo.com", "www.foo.com,www..foo.com"},
    {false, "www%252Efoo.com", "www.foo.com"},
    // IDN tests
    {true, "xn--poema-9qae5a.com.br", "xn--poema-9qae5a.com.br"},
    {true, "www.xn--poema-9qae5a.com.br", "*.xn--poema-9qae5a.com.br"},
    {false, "xn--poema-9qae5a.com.br",
     "*.xn--poema-9qae5a.com.br,"
     "xn--poema-*.com.br,"
     "xn--*-9qae5a.com.br,"
     "*--poema-9qae5a.com.br"},
    // The following are adapted from the  examples quoted from
    // http://tools.ietf.org/html/rfc6125#section-6.4.3
    //  (e.g., *.example.com would match foo.example.com but
    //   not bar.foo.example.com or example.com).
    {true, "foo.example.com", "*.example.com"},
    {false, "bar.foo.example.com", "*.example.com"},
    {false, "example.com", "*.example.com"},
    //   Partial wildcards are disallowed, though RFC 2818 rules allow them.
    //   That is, forms such as baz*.example.net, *baz.example.net, and
    //   b*z.example.net should NOT match domains. Instead, the wildcard must
    //   always be the left-most label, and only a single label.
    {false, "baz1.example.net", "baz*.example.net"},
    {false, "foobaz.example.net", "*baz.example.net"},
    {false, "buzz.example.net", "b*z.example.net"},
    {false, "www.test.example.net", "www.*.example.net"},
    // Wildcards should not be valid for public registry controlled domains,
    // and unknown/unrecognized domains, at least three domain components must
    // be present.
    {true, "www.test.example", "*.test.example"},
    {true, "test.example.co.uk", "*.example.co.uk"},
    {false, "test.example", "*.example"},
    {false, "example.co.uk", "*.co.uk"},
    {false, "foo.com", "*.com"},
    {false, "foo.us", "*.us"},
    {false, "foo", "*"},
    // IDN variants of wildcards and registry controlled domains.
    {true, "www.xn--poema-9qae5a.com.br", "*.xn--poema-9qae5a.com.br"},
    {true, "test.example.xn--mgbaam7a8h", "*.example.xn--mgbaam7a8h"},
    {false, "xn--poema-9qae5a.com.br", "*.com.br"},
    {false, "example.xn--mgbaam7a8h", "*.xn--mgbaam7a8h"},
    // Wildcards should be permissible for 'private' registry controlled
    // domains.
    {true, "www.appspot.com", "*.appspot.com"},
    {true, "foo.s3.amazonaws.com", "*.s3.amazonaws.com"},
    // Multiple wildcards are not valid.
    {false, "foo.example.com", "*.*.com"},
    {false, "foo.bar.example.com", "*.bar.*.com"},
    // Absolute vs relative DNS name tests. Although not explicitly specified
    // in RFC 6125, absolute reference names (those ending in a .) should
    // match either absolute or relative presented names.
    {true, "foo.com", "foo.com."},
    {true, "foo.com.", "foo.com"},
    {true, "foo.com.", "foo.com."},
    {true, "f", "f."},
    {true, "f.", "f"},
    {true, "f.", "f."},
    {true, "www-3.bar.foo.com", "*.bar.foo.com."},
    {true, "www-3.bar.foo.com.", "*.bar.foo.com"},
    {true, "www-3.bar.foo.com.", "*.bar.foo.com."},
    {false, ".", "."},
    {false, "example.com", "*.com."},
    {false, "example.com.", "*.com"},
    {false, "example.com.", "*.com."},
    {false, "foo.", "*."},
    {false, "foo", "*."},
    {false, "foo.co.uk", "*.co.uk."},
    {false, "foo.co.uk.", "*.co.uk."},
    // IP addresses in subject alternative name
    {true, "10.1.2.3", "", "10.1.2.3"},
    {true, "14.15", "", "14.0.0.15"},
    {false, "10.1.2.7", "", "10.1.2.6,10.1.2.8"},
    {false, "10.1.2.8", "foo"},
    {true, "::4.5.6.7", "", "x00000000000000000000000004050607"},
    {false, "::6.7.8.9", "::6.7.8.9",
     "x00000000000000000000000006070808,x0000000000000000000000000607080a,"
     "xff000000000000000000000006070809,6.7.8.9"},
    {true, "FE80::200:f8ff:fe21:67cf", "",
     "x00000000000000000000000006070808,xfe800000000000000200f8fffe2167cf,"
     "xff0000000000000000000000060708ff,10.0.0.1"},
    // Invalid hostnames with final numeric component.
    {false, "121.2.3.512", "1*1.2.3.512,*1.2.3.512,1*.2.3.512,*.2.3.512",
     "121.2.3.0"},
    {false, "1.2.3.4.5.6", "*.2.3.4.5.6"},
    {false, "1.2.3.4.5", "1.2.3.4.5"},
    {false, "a.0.0.1", "*.0.0.1"},
    // IP addresses in dNSName should not match commonName
    {false, "127.0.0.1", "127.0.0.1"},
    {false, "127.0.0.1", "*.0.0.1"},
    // Invalid host names.
    {false, ".", ""},
    {false, ".", "."},
    {false, "1.2.3.4..", "", "1.2.3.4"},
    {false, "www..domain.example", "www.domain.example"},
    {false, "www^domain.example", "www^domain.example"},
    {false, "www%20.domain.example", "www .domain.example"},
    {false, "www%2520.domain.example", "www .domain.example"},
    {false, "www%5E.domain.example", "www^domain.example"},
    {false, "www,domain.example", "www,domain.example"},
    {false, "0x000000002200037955161..", "0x000000002200037955161"},
    {false, "junk)(£)$*!@~#", "junk)(£)$*!@~#"},
    {false, "www.*.com", "www.*.com"},
    {false, "w$w.f.com", "w$w.f.com"},
    {false, "nocolonallowed:example", "nocolonallowed:example"},
    {false, "www-1.[::FFFF:129.144.52.38]", "*.[::FFFF:129.144.52.38]"},
    {false, "[::4.5.6.9]", "", "x00000000000000000000000004050609"},
};

class X509CertificateNameVerifyTest
    : public testing::TestWithParam<CertificateNameVerifyTestData> {
};

TEST_P(X509CertificateNameVerifyTest, VerifyHostname) {
  CertificateNameVerifyTestData test_data = GetParam();

  std::vector<std::string> dns_names, ip_addressses;
  if (test_data.dns_names) {
    // Build up the certificate DNS names list.
    std::string dns_name_line(test_data.dns_names);
    std::replace(dns_name_line.begin(), dns_name_line.end(), '#', '\0');
    dns_names = base::SplitString(dns_name_line, ",", base::TRIM_WHITESPACE,
                                  base::SPLIT_WANT_ALL);
  }

  if (test_data.ip_addrs) {
    // Build up the certificate IP address list.
    std::string ip_addrs_line(test_data.ip_addrs);
    std::vector<std::string> ip_addressses_ascii = base::SplitString(
        ip_addrs_line, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    for (size_t i = 0; i < ip_addressses_ascii.size(); ++i) {
      std::string& addr_ascii = ip_addressses_ascii[i];
      ASSERT_NE(0U, addr_ascii.length());
      if (addr_ascii[0] == 'x') {  // Hex encoded address
        addr_ascii.erase(0, 1);
        std::string bytes;
        EXPECT_TRUE(base::HexStringToString(addr_ascii, &bytes))
            << "Could not parse hex address " << addr_ascii << " i = " << i;
        ip_addressses.push_back(std::move(bytes));
        ASSERT_EQ(16U, ip_addressses.back().size()) << i;
      } else {  // Decimal groups
        std::vector<std::string> decimals_ascii_list = base::SplitString(
            addr_ascii, ".", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
        EXPECT_EQ(4U, decimals_ascii_list.size()) << i;
        std::string addr_bytes;
        for (const auto& decimals_ascii : decimals_ascii_list) {
          int decimal_value;
          EXPECT_TRUE(base::StringToInt(decimals_ascii, &decimal_value));
          EXPECT_GE(decimal_value, 0);
          EXPECT_LE(decimal_value, 255);
          addr_bytes.push_back(static_cast<char>(decimal_value));
        }
        ip_addressses.push_back(addr_bytes);
        ASSERT_EQ(4U, ip_addressses.back().size()) << i;
      }
    }
  }

  EXPECT_EQ(test_data.expected,
            X509Certificate::VerifyHostname(test_data.hostname, dns_names,
                                            ip_addressses));
}

INSTANTIATE_TEST_SUITE_P(All,
                         X509CertificateNameVerifyTest,
                         testing::ValuesIn(kNameVerifyTestData));

const struct PublicKeyInfoTestData {
  const char* file_name;
  size_t expected_bits;
  X509Certificate::PublicKeyType expected_type;
} kPublicKeyInfoTestData[] = {
    {"rsa-768", 768, X509Certificate::kPublicKeyTypeRSA},
    {"rsa-1024", 1024, X509Certificate::kPublicKeyTypeRSA},
    {"rsa-2048", 2048, X509Certificate::kPublicKeyTypeRSA},
    {"rsa-8200", 8200, X509Certificate::kPublicKeyTypeRSA},
    {"ec-prime256v1", 256, X509Certificate::kPublicKeyTypeECDSA},
};

class X509CertificatePublicKeyInfoTest
    : public testing::TestWithParam<PublicKeyInfoTestData> {
};

TEST_P(X509CertificatePublicKeyInfoTest, GetPublicKeyInfo) {
  PublicKeyInfoTestData data = GetParam();

  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  ASSERT_TRUE(leaf->UseKeyFromFile(GetTestCertsDirectory().AppendASCII(
      base::StrCat({data.file_name, "-1.key"}))));

  size_t actual_bits = 0;
  X509Certificate::PublicKeyType actual_type =
      X509Certificate::kPublicKeyTypeUnknown;

  X509Certificate::GetPublicKeyInfo(leaf->GetCertBuffer(), &actual_bits,
                                    &actual_type);

  EXPECT_EQ(data.expected_bits, actual_bits);
  EXPECT_EQ(data.expected_type, actual_type);
}

INSTANTIATE_TEST_SUITE_P(All,
                         X509CertificatePublicKeyInfoTest,
                         testing::ValuesIn(kPublicKeyInfoTestData));

}  // namespace net
```