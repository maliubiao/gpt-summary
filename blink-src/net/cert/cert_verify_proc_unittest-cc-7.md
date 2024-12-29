Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Core Task:**

The primary goal is to analyze a C++ unit test file (`cert_verify_proc_unittest.cc`) related to certificate verification in Chromium's network stack. The user wants to know its functionality, connections to JavaScript (if any), logical reasoning, potential user errors, debugging hints, and a final summary. The fact that it's part 8 of 8 suggests this is the concluding piece and likely focuses on broader aspects or edge cases.

**2. Initial Scan and Keyword Identification:**

I'll quickly scan the code for keywords and patterns. I see:

* `TEST_F`, `TEST`:  Indicates this is a unit testing file using a testing framework (likely Google Test).
* `CertVerifyProc`, `CertVerifyResult`, `X509Certificate`:  These strongly suggest the code deals with certificate verification logic.
* `VerifyCertName`, `MatchesDnsSan`, `DoesntMatchDnsSan`:  Points towards testing hostname matching against Subject Alternative Names (SANs) in certificates.
* `HistogramTester`, `kTrustAnchorVerifyHistogram`, `kTrustAnchorVerifyOutOfDateHistogram`:  Suggests the code is testing metrics and logging related to trust anchors.
* `MockCertVerifyProc`: Indicates the use of a mock object for testing, isolating the specific `CertVerifyProc` being tested.
* `OCSP`:  Shows the code is testing Online Certificate Status Protocol related functionality.
* `ImportCertFromFile`, `CreateCertificateChainFromFile`:  Confirms the tests involve loading and manipulating certificates.
* `OK`, `EXPECT_EQ`, `ASSERT_TRUE`:  Standard assertions in Google Test.

**3. Deeper Analysis of Individual Tests:**

I'll go through each test function to understand its specific purpose:

* **`CertVerifyProcNameTest` (multiple tests):** These tests focus on verifying hostname matching against DNS SANs in certificates. They test both positive (matches) and negative (doesn't match) cases, including variations like trailing dots and invalid formats.
* **`HasTrustAnchorVerifyUMA`:** This test checks if a specific trust anchor is correctly recorded in a UMA (User Metrics Analysis) histogram during certificate verification. It simulates a known trusted root certificate.
* **`LogsOnlyMostSpecificTrustAnchorUMA`:**  This test verifies that when multiple trust anchors are potentially involved, only the most specific one is logged in UMA.
* **`HasTrustAnchorVerifyOutOfDateUMA`:** This test checks if the "out of date" status of trust anchors (when a certificate is issued by a known root but not a *tracked* trust anchor) is correctly recorded in UMA.
* **`DoesNotRecalculateStapledOCSPResult`:** This test verifies that if OCSP stapling information is already present in the `CertVerifyResult`, the `CertVerifyProc` doesn't recalculate it.
* **`CalculateStapledOCSPResultIfNotAlreadyDone`:** This test confirms that if OCSP stapling information is missing, the `CertVerifyProc` attempts to calculate it.

**4. Identifying Core Functionality:**

Based on the individual tests, I can summarize the main functionalities of this code:

* **Hostname Matching:** Testing the logic for matching hostnames against DNS SANs in certificates.
* **Trust Anchor Logging (UMA):** Verifying that trust anchor information is correctly logged using UMA histograms. This includes identifying specific trust anchors and handling cases where the trust anchor is "out of date."
* **OCSP Stapling Handling:**  Testing how the certificate verification process handles OCSP stapling information, specifically whether it re-calculates it unnecessarily.

**5. Connections to JavaScript:**

Now, consider how this relates to JavaScript. Since this is part of Chromium's network stack, and web browsers use this stack:

* **Implicit Connection:** When a user navigates to a website in Chrome, the browser uses this certificate verification logic (or similar code) to validate the website's SSL/TLS certificate. JavaScript code running on the webpage indirectly depends on this verification being correct for secure communication.
* **No Direct JavaScript API:** There's likely no direct JavaScript API that allows web developers to directly call these specific C++ functions. The interaction is at a lower level.
* **Error Handling:** If certificate verification fails, this might surface in the browser as an error page or a security warning, which could affect the execution of JavaScript on the page (e.g., preventing secure API calls).

**6. Logical Reasoning (Input/Output):**

For the name matching tests:

* **Input:** A hostname string and a certificate (implicitly, as the tests set up the environment).
* **Output:** A boolean indicating whether the hostname matches the DNS SAN in the certificate.

For the UMA tests:

* **Input:**  A certificate chain (potentially with simulated trust anchors).
* **Output:**  The presence and values of specific entries in UMA histograms.

For the OCSP tests:

* **Input:** A certificate and potentially pre-existing OCSP information.
* **Output:** The state of the `ocsp_result` in the `CertVerifyResult` after verification.

**7. User/Programming Errors:**

* **Incorrect Certificate Configuration:**  A website administrator might configure their SSL certificate with incorrect or missing SANs, leading to hostname mismatch errors (tested by the `CertVerifyProcNameTest` functions).
* **Outdated Root Certificates:**  A user's operating system or browser might have outdated root certificates, causing the `HasTrustAnchorVerifyOutOfDateUMA` scenario.
* **Misconfigured OCSP Stapling:**  A server might be misconfigured to provide invalid or no OCSP stapling information, which the OCSP tests cover.
* **Mocking Issues (for programmers):** When writing tests using mocks, incorrect setup of the mock object (`MockCertVerifyProc`) could lead to misleading test results.

**8. Debugging Clues:**

* **Network Panel:** In Chrome's developer tools, the "Security" tab provides information about the certificate chain and its validity. This could indicate if the certificate itself has issues.
* **`chrome://net-internals/#ssl`:** This page in Chrome provides detailed information about SSL/TLS connections, including certificate verification steps. It can help diagnose why a certificate is being rejected.
* **Logging:** Chromium's networking stack has extensive logging. Enabling network logging might provide more granular details about the certificate verification process.
* **Stepping through the code (for developers):**  A developer could set breakpoints in the `CertVerifyProc::Verify` function and related code to understand the exact flow and identify the point of failure.

**9. Summarizing the Functionality (Part 8 of 8):**

Given that this is the last part, it likely focuses on:

* **Edge Cases and Robustness:** Testing less common scenarios like different hostname formats, multiple trust anchors, and handling of OCSP stapling.
* **Metrics and Monitoring:** Ensuring that important metrics related to trust anchor verification are being correctly tracked.
* **Integration Testing:**  While still unit tests, these tests verify the interaction of different components within the certificate verification process.

**Self-Correction/Refinement:**

Initially, I might focus too much on the individual tests without seeing the bigger picture. Recognizing the repeated use of `HistogramTester` helps to identify the UMA logging aspect as a core function. Also, understanding the role of `MockCertVerifyProc` is crucial for understanding the testing methodology. The "Part 8 of 8" clue is essential for framing the summary to reflect broader concerns beyond basic functionality. Finally, explicitly considering the JavaScript connection, even if indirect, provides a more complete picture for the user.
这个C++源代码文件 `net/cert/cert_verify_proc_unittest.cc` 是 Chromium 网络栈中用于测试证书验证过程 (`CertVerifyProc`) 功能的单元测试文件。

**它的主要功能可以归纳为：**

1. **测试主机名与证书中 Subject Alternative Name (SAN) 的匹配逻辑：**
   -  `CertVerifyProcNameTest` 测试套件专门用于测试主机名是否能正确匹配证书中定义的 DNS SAN。
   -  它包含了各种测试用例，涵盖了匹配成功、匹配失败、以及各种边缘情况，例如主机名或 SAN 中包含或缺少末尾的点号等。这确保了证书验证逻辑在处理不同格式的主机名和 SAN 时的正确性。

2. **测试信任锚 (Trust Anchor) 的记录和统计：**
   -  `CertVerifyProcTest` 中的 `HasTrustAnchorVerifyUMA` 和 `LogsOnlyMostSpecificTrustAnchorUMA` 测试用例验证了在证书验证过程中，是否正确地记录了作为信任锚的根证书信息到 UMA (User Metrics Analysis) 统计数据中。
   -  这些测试模拟了不同的证书链场景，包括只有一个信任锚和有多个潜在信任锚的情况，确保只记录最具体的那个信任锚。
   -  `HasTrustAnchorVerifyOutOfDateUMA` 测试用例则测试了当证书是由已知的根证书颁发，但该根证书未被明确跟踪为信任锚时，是否正确记录了这种“过期”状态。

3. **测试 OCSP Stapling 结果的处理：**
   -  `DoesNotRecalculateStapledOCSPResult` 测试用例验证了当 `CertVerifyResult` 中已经包含了 OCSP Stapling 的结果时，`CertVerifyProc::Verify` 方法不会重新计算。这避免了不必要的重复计算。
   -  `CalculateStapledOCSPResultIfNotAlreadyDone` 测试用例则验证了当 `CertVerifyResult` 中没有 OCSP Stapling 结果时，`CertVerifyProc::Verify` 方法会尝试计算。

**与 JavaScript 的功能关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能直接影响着基于 Chromium 的浏览器（例如 Chrome）中 JavaScript 代码的网络请求安全性。

* **HTTPS 连接的安全基石：** 当 JavaScript 代码发起 HTTPS 请求时，浏览器会使用网络栈中的证书验证逻辑来验证服务器提供的 SSL/TLS 证书的有效性。`CertVerifyProc` 就是负责执行这项核心验证工作的组件之一。
* **域名匹配和安全策略：**  `CertVerifyProcNameTest` 测试的域名匹配功能确保了用户访问的域名与服务器提供的证书上的域名一致，防止中间人攻击。如果匹配失败，浏览器会阻止 JavaScript 代码的进一步交互，保障用户安全。
* **信任和身份验证：**  信任锚的记录和统计对于浏览器建立对网站的信任至关重要。JavaScript 代码依赖浏览器提供的安全上下文，而这个安全上下文的建立离不开对服务器证书的成功验证。
* **OCSP Stapling 的性能优化：**  OCSP Stapling 允许服务器主动提供证书的吊销状态，减少了浏览器与 CA 服务器的额外通信，提升了页面加载速度。`CertVerifyProc` 对 OCSP Stapling 结果的处理直接影响着这种优化机制的有效性。

**JavaScript 功能的举例说明：**

假设一段 JavaScript 代码尝试通过 HTTPS 请求一个域名为 `test.example` 的服务器：

```javascript
fetch('https://test.example/data')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('请求失败:', error));
```

在这个过程中，`net/cert/cert_verify_proc_unittest.cc` 中 `CertVerifyProcNameTest` 的测试用例模拟的场景就与此相关。

* **假设输入（对应 `MatchesDnsSan` 测试）：** 服务器提供的证书的 SAN 中包含 `test.example`。
* **预期输出：** `CertVerifyProc` 的验证结果为成功，浏览器认为证书有效，允许建立安全的 HTTPS 连接，JavaScript 代码可以成功获取数据。

* **假设输入（对应 `DoesntMatchDnsSan` 测试）：** 服务器提供的证书的 SAN 中只包含 `example.com`，不包含 `test.example`。
* **预期输出：** `CertVerifyProc` 的验证结果为失败，浏览器会阻止建立连接，JavaScript 代码会捕获到 `error`，提示连接不安全。

**逻辑推理的假设输入与输出：**

* **假设输入 (针对 `HasTrustAnchorVerifyUMA`):**  一个由 "C=US, O=Google Trust Services LLC, CN=GTS Root R4" 签名的证书链。
* **预期输出:** UMA 统计中 `kTrustAnchorVerifyHistogram` 对应的 `kGTSRootR4HistogramID` 的计数会增加 1。

* **假设输入 (针对 `DoesNotRecalculateStapledOCSPResult`):**  一个证书和已经设置了有效 OCSP Stapling 结果的 `CertVerifyResult` 对象。
* **预期输出:**  `CertVerifyProc::Verify` 方法返回后，`CertVerifyResult` 中的 OCSP 结果保持不变，即使传入了无效的 `ocsp_response` 参数。

**涉及用户或编程常见的使用错误：**

* **用户错误：**
    * **访问使用了无效或过期证书的网站：** 用户可能会访问到一个证书 SAN 不匹配当前域名，或者证书已过期的网站。这会导致证书验证失败，浏览器会显示安全警告，阻止用户访问。这对应了 `CertVerifyProcNameTest` 中匹配失败的场景。
    * **系统时间不正确：** 如果用户的计算机系统时间不正确，可能会导致证书的有效期判断错误，例如将一个尚未生效的证书判断为有效，或将一个仍在有效期内的证书判断为过期。虽然这个文件没有直接测试时间问题，但证书验证过程依赖于正确的时间。

* **编程错误 (针对开发者)：**
    * **服务器配置错误的证书：** 网站开发者可能配置了 SAN 列表中缺少必要域名，或者证书链不完整的证书。这会导致用户的浏览器在访问该网站时证书验证失败。
    * **Mock 测试设置不正确：**  在编写涉及 `CertVerifyProc` 的测试时，如果 mock 对象的行为设置不正确，可能会导致测试结果与实际情况不符。例如，`MockCertVerifyProc` 的构造函数接收一个 `CertVerifyResult`，如果这个 `CertVerifyResult` 的模拟结果与测试意图不符，就会导致测试失败。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在 Chrome 浏览器地址栏输入一个 HTTPS 网址，例如 `https://test.example`，并按下回车键。**
2. **Chrome 的网络模块发起与 `test.example` 服务器的连接请求。**
3. **服务器响应连接请求，并提供其 SSL/TLS 证书。**
4. **Chrome 的网络模块接收到服务器的证书。**
5. **`net/cert/cert_verify_proc.cc` 中的 `CertVerifyProc::Verify` 方法被调用，开始对接收到的证书进行验证。**
6. **在 `CertVerifyProc::Verify` 内部，会调用相应的逻辑来检查证书的各个方面，包括：**
   - 证书的签名是否有效。
   - 证书是否在有效期内。
   - 证书的 revocation 状态 (例如通过 OCSP 或 CRL)。
   - **最相关的，会调用主机名匹配逻辑，检查用户输入的域名 `test.example` 是否与证书的 SAN 列表匹配 (这部分逻辑在 `cert_verify_proc_unittest.cc` 中被测试)。**
7. **如果证书验证失败 (例如域名不匹配)，`CertVerifyProc::Verify` 方法会返回一个错误状态。**
8. **Chrome 的网络模块根据错误状态，可能会阻止连接，并显示一个安全警告页面，告知用户连接不安全。**
9. **对于开发者而言，如果需要调试证书验证相关问题，可以使用 Chrome 的 `chrome://net-internals/#ssl` 页面查看详细的 SSL/TLS 连接信息，或者在 Chromium 源代码中设置断点，逐步跟踪 `CertVerifyProc::Verify` 的执行过程。** 这个单元测试文件中的测试用例可以帮助开发者理解在各种场景下 `CertVerifyProc` 的行为。

**功能归纳（第 8 部分，共 8 部分）：**

作为最后一部分，这个文件更侧重于 **证书验证过程的健壮性和覆盖各种边界情况的测试**。它不再局限于单一的核心功能，而是覆盖了：

* **更全面的主机名匹配场景：** 包括各种特殊格式的主机名和 SAN。
* **信任锚的精细化管理和统计：**  不仅仅是简单的记录，还包括对多个信任锚的处理和“过期”状态的监控。
* **性能优化相关的逻辑验证：**  例如，避免重复计算 OCSP Stapling 结果。

因此，可以认为这部分测试旨在确保证书验证逻辑在各种复杂和边缘情况下都能正确、高效地运行，并提供必要的监控数据，为 Chromium 的网络安全提供坚实的基础。

Prompt: 
```
这是目录为net/cert/cert_verify_proc_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共8部分，请归纳一下它的功能

"""
rocNameTest, MatchesDnsSan) {
  VerifyCertName("test.example", true);
}

// Matches the dNSName SAN (trailing . ignored)
TEST_F(CertVerifyProcNameTest, MatchesDnsSanTrailingDot) {
  VerifyCertName("test.example.", true);
}

// Should not match the dNSName SAN
TEST_F(CertVerifyProcNameTest, DoesntMatchDnsSan) {
  VerifyCertName("www.test.example", false);
}

// Should not match the dNSName SAN
TEST_F(CertVerifyProcNameTest, DoesntMatchDnsSanInvalid) {
  VerifyCertName("test..example", false);
}

// Should not match the dNSName SAN
TEST_F(CertVerifyProcNameTest, DoesntMatchDnsSanTwoTrailingDots) {
  VerifyCertName("test.example..", false);
}

// Should not match the dNSName SAN
TEST_F(CertVerifyProcNameTest, DoesntMatchDnsSanLeadingAndTrailingDot) {
  VerifyCertName(".test.example.", false);
}

// Should not match the dNSName SAN
TEST_F(CertVerifyProcNameTest, DoesntMatchDnsSanTrailingDot) {
  VerifyCertName(".test.example", false);
}

// Test that trust anchors are appropriately recorded via UMA.
TEST(CertVerifyProcTest, HasTrustAnchorVerifyUMA) {
  base::HistogramTester histograms;
  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(cert);

  CertVerifyResult result;

  // Simulate a certificate chain issued by "C=US, O=Google Trust Services LLC,
  // CN=GTS Root R4". This publicly-trusted root was chosen as it was included
  // in 2017 and is not anticipated to be removed from all supported platforms
  // for a few decades.
  // Note: The actual cert in |cert| does not matter for this testing, so long
  // as it's not violating any CertVerifyProc::Verify() policies.
  SHA256HashValue leaf_hash = {{0}};
  SHA256HashValue intermediate_hash = {{1}};
  SHA256HashValue root_hash = {
      {0x98, 0x47, 0xe5, 0x65, 0x3e, 0x5e, 0x9e, 0x84, 0x75, 0x16, 0xe5,
       0xcb, 0x81, 0x86, 0x06, 0xaa, 0x75, 0x44, 0xa1, 0x9b, 0xe6, 0x7f,
       0xd7, 0x36, 0x6d, 0x50, 0x69, 0x88, 0xe8, 0xd8, 0x43, 0x47}};
  result.public_key_hashes.push_back(HashValue(leaf_hash));
  result.public_key_hashes.push_back(HashValue(intermediate_hash));
  result.public_key_hashes.push_back(HashValue(root_hash));

  const base::HistogramBase::Sample kGTSRootR4HistogramID = 486;

  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

  histograms.ExpectTotalCount(kTrustAnchorVerifyHistogram, 0);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(
      cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_EQ(OK, error);
  histograms.ExpectUniqueSample(kTrustAnchorVerifyHistogram,
                                kGTSRootR4HistogramID, 1);
}

// Test that certificates with multiple trust anchors present result in
// only a single trust anchor being recorded, and that being the most specific
// trust anchor.
TEST(CertVerifyProcTest, LogsOnlyMostSpecificTrustAnchorUMA) {
  base::HistogramTester histograms;
  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));
  ASSERT_TRUE(cert);

  CertVerifyResult result;

  // Simulate a chain of "C=US, O=Google Trust Services LLC, CN=GTS Root R4"
  // signing "C=US, O=Google Trust Services LLC, CN=GTS Root R3" signing an
  // intermediate and a leaf.
  // Note: The actual cert in |cert| does not matter for this testing, so long
  // as it's not violating any CertVerifyProc::Verify() policies.
  SHA256HashValue leaf_hash = {{0}};
  SHA256HashValue intermediate_hash = {{1}};
  SHA256HashValue gts_root_r3_hash = {
      {0x41, 0x79, 0xed, 0xd9, 0x81, 0xef, 0x74, 0x74, 0x77, 0xb4, 0x96,
       0x26, 0x40, 0x8a, 0xf4, 0x3d, 0xaa, 0x2c, 0xa7, 0xab, 0x7f, 0x9e,
       0x08, 0x2c, 0x10, 0x60, 0xf8, 0x40, 0x96, 0x77, 0x43, 0x48}};
  SHA256HashValue gts_root_r4_hash = {
      {0x98, 0x47, 0xe5, 0x65, 0x3e, 0x5e, 0x9e, 0x84, 0x75, 0x16, 0xe5,
       0xcb, 0x81, 0x86, 0x06, 0xaa, 0x75, 0x44, 0xa1, 0x9b, 0xe6, 0x7f,
       0xd7, 0x36, 0x6d, 0x50, 0x69, 0x88, 0xe8, 0xd8, 0x43, 0x47}};
  result.public_key_hashes.push_back(HashValue(leaf_hash));
  result.public_key_hashes.push_back(HashValue(intermediate_hash));
  result.public_key_hashes.push_back(HashValue(gts_root_r3_hash));
  result.public_key_hashes.push_back(HashValue(gts_root_r4_hash));

  const base::HistogramBase::Sample kGTSRootR3HistogramID = 485;

  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

  histograms.ExpectTotalCount(kTrustAnchorVerifyHistogram, 0);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(
      cert.get(), "127.0.0.1", /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_EQ(OK, error);

  // Only GTS Root R3 should be recorded.
  histograms.ExpectUniqueSample(kTrustAnchorVerifyHistogram,
                                kGTSRootR3HistogramID, 1);
}

// Test that trust anchors histograms record whether or not
// is_issued_by_known_root was derived from the OS.
TEST(CertVerifyProcTest, HasTrustAnchorVerifyOutOfDateUMA) {
  base::HistogramTester histograms;
  // Since we are setting is_issued_by_known_root=true, the certificate to be
  // verified needs to have a validity period that satisfies
  // HasTooLongValidity.
  auto [leaf, root] = CertBuilder::CreateSimpleChain2();

  CertVerifyResult result;

  // Simulate a certificate chain that is recognized as trusted (from a known
  // root), but no certificates in the chain are tracked as known trust
  // anchors.
  SHA256HashValue leaf_hash = {{0}};
  SHA256HashValue intermediate_hash = {{1}};
  SHA256HashValue root_hash = {{2}};
  result.public_key_hashes.push_back(HashValue(leaf_hash));
  result.public_key_hashes.push_back(HashValue(intermediate_hash));
  result.public_key_hashes.push_back(HashValue(root_hash));
  result.is_issued_by_known_root = true;

  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

  histograms.ExpectTotalCount(kTrustAnchorVerifyHistogram, 0);
  histograms.ExpectTotalCount(kTrustAnchorVerifyOutOfDateHistogram, 0);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(
      leaf->GetX509Certificate().get(), "www.example.com",
      /*ocsp_response=*/std::string(),
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_EQ(OK, error);
  const base::HistogramBase::Sample kUnknownRootHistogramID = 0;
  histograms.ExpectUniqueSample(kTrustAnchorVerifyHistogram,
                                kUnknownRootHistogramID, 1);
  histograms.ExpectUniqueSample(kTrustAnchorVerifyOutOfDateHistogram, true, 1);
}

// If the CertVerifyProc::VerifyInternal implementation calculated the stapled
// OCSP results in the CertVerifyResult, CertVerifyProc::Verify should not
// re-calculate them.
TEST(CertVerifyProcTest, DoesNotRecalculateStapledOCSPResult) {
  scoped_refptr<X509Certificate> cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);
  ASSERT_EQ(1U, cert->intermediate_buffers().size());

  CertVerifyResult result;

  result.ocsp_result.response_status = bssl::OCSPVerifyResult::PROVIDED;
  result.ocsp_result.revocation_status = bssl::OCSPRevocationStatus::GOOD;

  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(cert.get(), "127.0.0.1",
                                  /*ocsp_response=*/"invalid OCSP data",
                                  /*sct_list=*/std::string(), flags,
                                  &verify_result, NetLogWithSource());
  EXPECT_EQ(OK, error);

  EXPECT_EQ(bssl::OCSPVerifyResult::PROVIDED,
            verify_result.ocsp_result.response_status);
  EXPECT_EQ(bssl::OCSPRevocationStatus::GOOD,
            verify_result.ocsp_result.revocation_status);
}

TEST(CertVerifyProcTest, CalculateStapledOCSPResultIfNotAlreadyDone) {
  scoped_refptr<X509Certificate> cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);
  ASSERT_EQ(1U, cert->intermediate_buffers().size());

  CertVerifyResult result;

  // Confirm the default-constructed values are as expected.
  EXPECT_EQ(bssl::OCSPVerifyResult::NOT_CHECKED,
            result.ocsp_result.response_status);
  EXPECT_EQ(bssl::OCSPRevocationStatus::UNKNOWN,
            result.ocsp_result.revocation_status);

  auto verify_proc = base::MakeRefCounted<MockCertVerifyProc>(result);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = verify_proc->Verify(
      cert.get(), "127.0.0.1", /*ocsp_response=*/"invalid OCSP data",
      /*sct_list=*/std::string(), flags, &verify_result, NetLogWithSource());
  EXPECT_EQ(OK, error);

  EXPECT_EQ(bssl::OCSPVerifyResult::PARSE_RESPONSE_ERROR,
            verify_result.ocsp_result.response_status);
  EXPECT_EQ(bssl::OCSPRevocationStatus::UNKNOWN,
            verify_result.ocsp_result.revocation_status);
}

}  // namespace net

"""


```