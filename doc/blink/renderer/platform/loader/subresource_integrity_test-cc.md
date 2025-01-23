Response:
My thought process to answer the request about `subresource_integrity_test.cc` goes like this:

1. **Understand the Goal:** The core request is to explain the functionality of this test file, focusing on its relationship to web technologies (JavaScript, HTML, CSS), demonstrating logic through examples, and highlighting potential usage errors.

2. **Initial Scan and Keywords:** I quickly scanned the code for key terms and patterns. I noticed includes like `SubresourceIntegrity.h`, `gtest/gtest.h`, `Resource.h`, `ResourceResponse.h`, `IntegrityMetadata.h`, and constants like `kBasicScript`, `kSha256Integrity`, etc. This immediately tells me it's a C++ test file for a feature related to resource loading and security, specifically "Subresource Integrity" (SRI).

3. **Identify Core Functionality:**  The presence of `ParseIntegrityAttribute`, `CheckSubresourceIntegrity`, and test cases involving different hash algorithms (SHA-256, SHA-384, SHA-512) strongly suggests the file tests the parsing and validation of SRI attributes.

4. **Relate to Web Technologies:**  I know SRI is a web security feature used in HTML `<script>` and `<link>` tags. The test cases using `kBasicScript` reinforce the connection to JavaScript. While the tests don't directly manipulate HTML or CSS syntax, the *purpose* of SRI is to secure these resource types. Therefore, I need to explain this indirect relationship.

5. **Break Down the Tests:** I started analyzing individual test functions:
    * `Prioritization`: Tests the internal logic for choosing the strongest hash algorithm. This is important for SRI's fallback mechanism.
    * `ParseAlgorithm`: Focuses on parsing the hash algorithm name (e.g., "sha256-"). This is a foundational step for SRI.
    * `ParseDigest`:  Tests the extraction of the base64-encoded cryptographic hash.
    * `Parsing`: This is the core parsing test, covering various valid and invalid SRI attribute formats, including multiple hashes and options. I noted the `ExpectParse` and `ExpectParseMultipleHashes` helper functions.
    * `ParsingBase64`: Specifically checks parsing of base64 encoded digests, crucial for the actual hash values.
    * `OriginIntegrity`: This is a significant test. The `TestCase` struct and the loops indicate testing SRI under various conditions: secure/insecure origins, CORS, service workers, and different response types. This is where the real-world application of SRI is tested.
    * `FindBestAlgorithm`:  Again, tests the logic for selecting the strongest algorithm from a set of provided hashes.

6. **Construct Explanations:** For each area, I tried to:
    * **State the function's purpose clearly.**
    * **Provide specific examples from the code.** For instance, when explaining `ParseAlgorithm`, I used examples like "sha256-" and "sha1-".
    * **Connect to web technologies.** I explained how the parsed information is used for `<script>` and `<link>` tags.
    * **Illustrate logic with input/output assumptions.**  For `ParseAlgorithm`, I showed how "sha256-" as input leads to `IntegrityAlgorithm::kSha256` as output. For `CheckSubresourceIntegrity`, I outlined scenarios where a matching hash leads to success and a mismatch leads to failure.
    * **Highlight potential user errors.**  I focused on common mistakes like providing incorrect hashes, using unsupported algorithms, or not understanding how SRI interacts with CORS.

7. **Address Specific Instructions:** I made sure to explicitly address each point in the request:
    * **List of functionalities:** I provided a comprehensive list based on the test functions.
    * **Relationship to JavaScript/HTML/CSS:** I explained the connection through the `<script>` and `<link>` tags.
    * **Examples for JavaScript/HTML/CSS:** I provided concrete HTML examples demonstrating SRI usage.
    * **Logical reasoning (input/output):** I gave examples for parsing and integrity checking.
    * **Common usage errors:** I listed common mistakes users might make when implementing SRI.

8. **Refine and Organize:** I organized the information logically, starting with a general overview and then diving into specific details for each test area. I used clear headings and bullet points to improve readability. I also double-checked that my examples and explanations were accurate and easy to understand.

By following this process, I could effectively analyze the C++ test file and generate a comprehensive answer that addresses all aspects of the original request. The key was to combine code analysis with knowledge of web security concepts and how they are applied in practice.
这个文件 `subresource_integrity_test.cc` 是 Chromium Blink 引擎的源代码文件，它专门用于测试 **Subresource Integrity (SRI)** 功能的实现。

以下是该文件的主要功能以及与 JavaScript、HTML、CSS 的关系、逻辑推理和常见使用错误的说明：

**主要功能：**

1. **测试 SRI 属性的解析：** 验证 Blink 引擎能否正确解析 HTML 中 `<script>` 或 `<link>` 标签的 `integrity` 属性。该属性包含一个或多个加密哈希值，用于校验加载的资源是否被篡改。
2. **测试 SRI 校验逻辑：**  测试 Blink 引擎在加载子资源时，能否根据 `integrity` 属性中提供的哈希值，比对下载资源的实际哈希值，从而判断资源是否完整。
3. **测试不同哈希算法的支持：** 测试 Blink 引擎是否支持 SRI 规范中定义的各种哈希算法，如 SHA-256、SHA-384 和 SHA-512。
4. **测试 SRI 与跨域请求 (CORS) 的交互：** 验证 SRI 在跨域场景下是否能正确工作，包括不同的 CORS 响应头和请求模式。
5. **测试 SRI 与 Service Workers 的交互：** 验证当资源通过 Service Worker 提供时，SRI 校验是否仍然有效。
6. **测试 SRI 属性中选项 (options) 的处理：** 尽管目前 SRI 规范中对 options 的定义有限，但测试文件涵盖了对带有 options 的 `integrity` 属性的解析，确保引擎能正确忽略或处理这些选项。
7. **测试错误情况处理：** 验证当 `integrity` 属性格式错误、提供的哈希值与实际资源不匹配等情况下，Blink 引擎的错误处理机制是否正确。

**与 JavaScript, HTML, CSS 的关系：**

SRI 是一种 Web 安全特性，主要应用于 HTML 中的 `<script>` 和 `<link>` 标签，用于确保浏览器加载的 JavaScript 和 CSS 资源没有被恶意篡改。

* **HTML:**  `integrity` 属性直接在 HTML 标签中使用。例如：
   ```html
   <script src="https://example.com/script.js"
           integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R
### 提示词
```
这是目录为blink/renderer/platform/loader/subresource_integrity_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"

#include <algorithm>

#include "base/memory/scoped_refptr.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/crypto.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_scheduler.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

static const char kBasicScript[] = "alert('test');";
static const char kSha256Integrity[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4=";
static const char kSha256IntegrityLenientSyntax[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4=";
static const char kSha256IntegrityWithEmptyOption[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4=?";
static const char kSha256IntegrityWithOption[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4=?foo=bar";
static const char kSha256IntegrityWithOptions[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4=?foo=bar?baz=foz";
static const char kSha256IntegrityWithMimeOption[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4=?ct=application/"
    "javascript";
static const char kSha384Integrity[] =
    "sha384-nep3XpvhUxpCMOVXIFPecThAqdY_uVeiD4kXSqXpx0YJUWU4fTTaFgciTuZk7fmE";
static const char kSha512Integrity[] =
    "sha512-TXkJw18PqlVlEUXXjeXbGetop1TKB3wYQIp1_"
    "ihxCOFGUfG9TYOaA1MlkpTAqSV6yaevLO8Tj5pgH1JmZ--ItA==";
static const char kSha384IntegrityLabeledAs256[] =
    "sha256-nep3XpvhUxpCMOVXIFPecThAqdY_uVeiD4kXSqXpx0YJUWU4fTTaFgciTuZk7fmE";
static const char kSha256AndSha384Integrities[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4= "
    "sha384-nep3XpvhUxpCMOVXIFPecThAqdY_uVeiD4kXSqXpx0YJUWU4fTTaFgciTuZk7fmE";
static const char kBadSha256AndGoodSha384Integrities[] =
    "sha256-deadbeef "
    "sha384-nep3XpvhUxpCMOVXIFPecThAqdY_uVeiD4kXSqXpx0YJUWU4fTTaFgciTuZk7fmE";
static const char kGoodSha256AndBadSha384Integrities[] =
    "sha256-GAF48QOoxRvu0gZAmQivUdJPyBacqznBAXwnkfpmQX4= sha384-deadbeef";
static const char kBadSha256AndBadSha384Integrities[] =
    "sha256-deadbeef sha384-deadbeef";
static const char kUnsupportedHashFunctionIntegrity[] =
    "sha1-JfLW308qMPKfb4DaHpUBEESwuPc=";

class SubresourceIntegrityTest : public testing::Test {
 public:
  SubresourceIntegrityTest()
      : sec_url("https://example.test:443"),
        insec_url("http://example.test:80"),
        context(MakeGarbageCollected<MockFetchContext>()) {}

 protected:
  SubresourceIntegrity::IntegrityFeatures Features() const {
    return RuntimeEnabledFeatures::SignatureBasedIntegrityEnabledByRuntimeFlag()
               ? SubresourceIntegrity::IntegrityFeatures::kSignatures
               : SubresourceIntegrity::IntegrityFeatures::kDefault;
  }

  void ExpectAlgorithm(const String& text,
                       IntegrityAlgorithm expected_algorithm) {
    Vector<UChar> characters;
    text.AppendTo(characters);
    const UChar* position = characters.data();
    const UChar* end = characters.data() + characters.size();
    IntegrityAlgorithm algorithm;

    EXPECT_EQ(SubresourceIntegrity::kAlgorithmValid,
              SubresourceIntegrity::ParseAttributeAlgorithm(
                  position, end, Features(), algorithm));
    EXPECT_EQ(expected_algorithm, algorithm);
    EXPECT_EQ(end, position);
  }

  void ExpectAlgorithmFailure(
      const String& text,
      SubresourceIntegrity::AlgorithmParseResult expected_result) {
    Vector<UChar> characters;
    text.AppendTo(characters);
    const UChar* position = characters.data();
    const UChar* begin = characters.data();
    const UChar* end = characters.data() + characters.size();
    IntegrityAlgorithm algorithm;

    EXPECT_EQ(expected_result, SubresourceIntegrity::ParseAttributeAlgorithm(
                                   position, end, Features(), algorithm));
    EXPECT_EQ(begin, position);
  }

  void ExpectDigest(const String& text, const char* expected_digest) {
    Vector<UChar> characters;
    text.AppendTo(characters);
    const UChar* position = characters.data();
    const UChar* end = characters.data() + characters.size();
    String digest;

    EXPECT_TRUE(SubresourceIntegrity::ParseDigest(position, end, digest));
    EXPECT_EQ(expected_digest, digest);
  }

  void ExpectDigestFailure(const String& text) {
    Vector<UChar> characters;
    text.AppendTo(characters);
    const UChar* position = characters.data();
    const UChar* end = characters.data() + characters.size();
    String digest;

    EXPECT_FALSE(SubresourceIntegrity::ParseDigest(position, end, digest));
    EXPECT_TRUE(digest.empty());
  }

  void ExpectParse(const char* integrity_attribute,
                   const char* expected_digest,
                   IntegrityAlgorithm expected_algorithm) {
    IntegrityMetadataSet metadata_set;
    SubresourceIntegrity::ParseIntegrityAttribute(integrity_attribute,
                                                  Features(), metadata_set);
    EXPECT_EQ(1u, metadata_set.size());
    if (metadata_set.size() > 0) {
      IntegrityMetadata metadata = *metadata_set.begin();
      EXPECT_EQ(expected_digest, metadata.Digest());
      EXPECT_EQ(expected_algorithm, metadata.Algorithm());
    }
  }

  void ExpectParseMultipleHashes(
      const char* integrity_attribute,
      const IntegrityMetadata expected_metadata_array[],
      size_t expected_metadata_array_size) {
    IntegrityMetadataSet expected_metadata_set;
    for (size_t i = 0; i < expected_metadata_array_size; i++) {
      expected_metadata_set.insert(expected_metadata_array[i].ToPair());
    }
    IntegrityMetadataSet metadata_set;
    SubresourceIntegrity::ParseIntegrityAttribute(integrity_attribute,
                                                  Features(), metadata_set);
    EXPECT_TRUE(
        IntegrityMetadata::SetsEqual(expected_metadata_set, metadata_set));
  }

  void ExpectParseFailure(const char* integrity_attribute) {
    IntegrityMetadataSet metadata_set;
    SubresourceIntegrity::ParseIntegrityAttribute(integrity_attribute,
                                                  Features(), metadata_set);
    EXPECT_EQ(metadata_set.size(), 0u);
  }

  void ExpectEmptyParseResult(const char* integrity_attribute) {
    IntegrityMetadataSet metadata_set;

    SubresourceIntegrity::ParseIntegrityAttribute(integrity_attribute,
                                                  Features(), metadata_set);
    EXPECT_EQ(0u, metadata_set.size());
  }

  enum ServiceWorkerMode {
    kNoServiceWorker,
    kSWOpaqueResponse,
    kSWClearResponse
  };

  enum Expectation { kIntegritySuccess, kIntegrityFailure };

  struct TestCase {
    const KURL url;
    network::mojom::RequestMode request_mode;
    network::mojom::FetchResponseType response_type;
    const Expectation expectation;
  };

  void CheckExpectedIntegrity(const char* integrity, const TestCase& test) {
    CheckExpectedIntegrity(integrity, test, test.expectation);
  }

  // Allows to overwrite the test expectation for cases that are always expected
  // to fail:
  void CheckExpectedIntegrity(const char* integrity,
                              const TestCase& test,
                              Expectation expectation) {
    IntegrityMetadataSet metadata_set;
    SubresourceIntegrity::ParseIntegrityAttribute(String(integrity), Features(),
                                                  metadata_set);
    SegmentedBuffer buffer;
    buffer.Append(base::make_span(kBasicScript, strlen(kBasicScript)));
    SubresourceIntegrity::ReportInfo report_info;
    EXPECT_EQ(expectation == kIntegritySuccess,
              SubresourceIntegrity::CheckSubresourceIntegrity(
                  metadata_set, &buffer, test.url,
                  *CreateTestResource(test.url, test.request_mode,
                                      test.response_type),
                  report_info));
  }

  Resource* CreateTestResource(
      const KURL& url,
      network::mojom::RequestMode request_mode,
      network::mojom::FetchResponseType response_type) {
    ResourceRequest request;
    request.SetUrl(url);
    request.SetMode(request_mode);
    request.SetRequestorOrigin(SecurityOrigin::CreateUniqueOpaque());
    Resource* resource =
        RawResource::CreateForTest(request, ResourceType::kRaw);

    ResourceResponse response(url);
    response.SetHttpStatusCode(200);
    response.SetType(response_type);

    resource->SetResponse(response);
    return resource;
  }

  KURL sec_url;
  KURL insec_url;

  Persistent<MockFetchContext> context;
};

// Test the prioritization (i.e. selecting the "strongest" algorithm.
// This effectively tests the definition of IntegrityAlgorithm in
// IntegrityMetadata. The test is here, because SubresourceIntegrity is the
// class that relies on this working as expected.)
TEST_F(SubresourceIntegrityTest, Prioritization) {
  // Check that each algorithm is it's own "strongest".
  EXPECT_EQ(
      IntegrityAlgorithm::kSha256,
      std::max({IntegrityAlgorithm::kSha256, IntegrityAlgorithm::kSha256}));
  EXPECT_EQ(
      IntegrityAlgorithm::kSha384,
      std::max({IntegrityAlgorithm::kSha384, IntegrityAlgorithm::kSha384}));

  EXPECT_EQ(
      IntegrityAlgorithm::kSha512,
      std::max({IntegrityAlgorithm::kSha512, IntegrityAlgorithm::kSha512}));

  // Check a mix of algorithms.
  EXPECT_EQ(IntegrityAlgorithm::kSha384,
            std::max({IntegrityAlgorithm::kSha256, IntegrityAlgorithm::kSha384,
                      IntegrityAlgorithm::kSha256}));
  EXPECT_EQ(IntegrityAlgorithm::kSha512,
            std::max({IntegrityAlgorithm::kSha384, IntegrityAlgorithm::kSha512,
                      IntegrityAlgorithm::kSha256}));
}

TEST_F(SubresourceIntegrityTest, ParseAlgorithm) {
  ExpectAlgorithm("sha256-", IntegrityAlgorithm::kSha256);
  ExpectAlgorithm("sha384-", IntegrityAlgorithm::kSha384);
  ExpectAlgorithm("sha512-", IntegrityAlgorithm::kSha512);
  ExpectAlgorithm("sha-256-", IntegrityAlgorithm::kSha256);
  ExpectAlgorithm("sha-384-", IntegrityAlgorithm::kSha384);
  ExpectAlgorithm("sha-512-", IntegrityAlgorithm::kSha512);

  ScopedSignatureBasedIntegrityForTest signature_based_integrity(false);

  ExpectAlgorithmFailure("sha1-", SubresourceIntegrity::kAlgorithmUnknown);
  ExpectAlgorithmFailure("sha-1-", SubresourceIntegrity::kAlgorithmUnknown);
  ExpectAlgorithmFailure("foobarsha256-",
                         SubresourceIntegrity::kAlgorithmUnknown);
  ExpectAlgorithmFailure("foobar-", SubresourceIntegrity::kAlgorithmUnknown);
  ExpectAlgorithmFailure("-", SubresourceIntegrity::kAlgorithmUnknown);

  ExpectAlgorithmFailure("sha256", SubresourceIntegrity::kAlgorithmUnparsable);
  ExpectAlgorithmFailure("", SubresourceIntegrity::kAlgorithmUnparsable);
}

TEST_F(SubresourceIntegrityTest, ParseDigest) {
  ExpectDigest("abcdefg", "abcdefg");
  ExpectDigest("abcdefg?", "abcdefg");
  ExpectDigest("ab+de/g", "ab+de/g");
  ExpectDigest("ab-de_g", "ab+de/g");

  ExpectDigestFailure("?");
  ExpectDigestFailure("&&&foobar&&&");
  ExpectDigestFailure("\x01\x02\x03\x04");
}

//
// End-to-end parsing tests.
//

TEST_F(SubresourceIntegrityTest, Parsing) {
  ExpectParseFailure("not_really_a_valid_anything");
  ExpectParseFailure("sha256-&&&foobar&&&");
  ExpectParseFailure("sha256-\x01\x02\x03\x04");
  ExpectParseFailure("sha256-!!! sha256-!!!");

  ExpectEmptyParseResult("foobar:///sha256-abcdefg");
  ExpectEmptyParseResult("ni://sha256-abcdefg");
  ExpectEmptyParseResult("ni:///sha256-abcdefg");
  ExpectEmptyParseResult("notsha256atall-abcdefg");

  ExpectParse("sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);

  ExpectParse("sha-256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);

  ExpectParse("     sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=     ",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);

  ExpectParse(
      "sha384-XVVXBGoYw6AJOh9J-Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup_tA1v5GPr",
      "XVVXBGoYw6AJOh9J+Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup/tA1v5GPr",
      IntegrityAlgorithm::kSha384);

  ExpectParse(
      "sha-384-XVVXBGoYw6AJOh9J_Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup_"
      "tA1v5GPr",
      "XVVXBGoYw6AJOh9J/Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup/tA1v5GPr",
      IntegrityAlgorithm::kSha384);

  ExpectParse(
      "sha512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ-"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      "tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      IntegrityAlgorithm::kSha512);

  ExpectParse(
      "sha-512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ-"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      "tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      IntegrityAlgorithm::kSha512);

  ExpectParse(
      "sha-512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ-"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==?ct=application/javascript",
      "tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      IntegrityAlgorithm::kSha512);

  ExpectParse(
      "sha-512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ-"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==?ct=application/xhtml+xml",
      "tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      IntegrityAlgorithm::kSha512);

  ExpectParse(
      "sha-512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ-"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==?foo=bar?ct=application/xhtml+xml",
      "tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      IntegrityAlgorithm::kSha512);

  ExpectParse(
      "sha-512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ-"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==?ct=application/xhtml+xml?foo=bar",
      "tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      IntegrityAlgorithm::kSha512);

  ExpectParse(
      "sha-512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ-"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==?baz=foz?ct=application/"
      "xhtml+xml?foo=bar",
      "tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      IntegrityAlgorithm::kSha512);

  ExpectParseMultipleHashes("", nullptr, 0);
  ExpectParseMultipleHashes("    ", nullptr, 0);

  const IntegrityMetadata valid_sha384_and_sha512[] = {
      IntegrityMetadata(
          "XVVXBGoYw6AJOh9J+Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup/tA1v5GPr",
          IntegrityAlgorithm::kSha384),
      IntegrityMetadata("tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
                        "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
                        IntegrityAlgorithm::kSha512),
  };
  ExpectParseMultipleHashes(
      "sha384-XVVXBGoYw6AJOh9J+Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup/tA1v5GPr "
      "sha512-tbUPioKbVBplr0b1ucnWB57SJWt4x9dOE0Vy2mzCXvH3FepqDZ+"
      "07yMK81ytlg0MPaIrPAjcHqba5csorDWtKg==",
      valid_sha384_and_sha512, std::size(valid_sha384_and_sha512));

  const IntegrityMetadata valid_sha256_and_sha256[] = {
      IntegrityMetadata("BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
                        IntegrityAlgorithm::kSha256),
      IntegrityMetadata("deadbeef", IntegrityAlgorithm::kSha256),
  };
  ExpectParseMultipleHashes(
      "sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE= sha256-deadbeef",
      valid_sha256_and_sha256, std::size(valid_sha256_and_sha256));

  const IntegrityMetadata valid_sha256_and_invalid_sha256[] = {
      IntegrityMetadata("BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
                        IntegrityAlgorithm::kSha256),
  };
  ExpectParseMultipleHashes(
      "sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE= sha256-!!!!",
      valid_sha256_and_invalid_sha256,
      std::size(valid_sha256_and_invalid_sha256));

  const IntegrityMetadata invalid_sha256_and_valid_sha256[] = {
      IntegrityMetadata("BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
                        IntegrityAlgorithm::kSha256),
  };
  ExpectParseMultipleHashes(
      "sha256-!!! sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
      invalid_sha256_and_valid_sha256,
      std::size(invalid_sha256_and_valid_sha256));

  ExpectParse("sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?foo=bar",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);

  ExpectParse(
      "sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?foo=bar?baz=foz",
      "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
      IntegrityAlgorithm::kSha256);

  ExpectParse("sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);
  ExpectParse("sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?foo=bar",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);
  ExpectParse(
      "sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?foo=bar?baz=foz",
      "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
      IntegrityAlgorithm::kSha256);
  ExpectParse("sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?foo",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);
  ExpectParse("sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?foo=bar?",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);
  ExpectParse("sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=?foo:bar",
              "BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
              IntegrityAlgorithm::kSha256);
}

TEST_F(SubresourceIntegrityTest, ParsingBase64) {
  ExpectParse(
      "sha384-XVVXBGoYw6AJOh9J+Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup/tA1v5GPr",
      "XVVXBGoYw6AJOh9J+Z8pBDMVVPfkBpngexkA7JqZu8d5GENND6TEIup/tA1v5GPr",
      IntegrityAlgorithm::kSha384);
}

// Tests that SubresourceIntegrity::CheckSubresourceIntegrity behaves correctly
// when faced with secure or insecure origins, same origin and cross origin
// requests, successful and failing CORS checks as well as when the response was
// handled by a service worker.
TEST_F(SubresourceIntegrityTest, OriginIntegrity) {
  using network::mojom::FetchResponseType;
  using network::mojom::RequestMode;
  constexpr auto kOk = kIntegritySuccess;
  constexpr auto kFail = kIntegrityFailure;
  const KURL& url = sec_url;

  const TestCase cases[] = {
      // FetchResponseType::kError never arrives because it is a loading error.
      {url, RequestMode::kNoCors, FetchResponseType::kBasic, kOk},
      {url, RequestMode::kNoCors, FetchResponseType::kCors, kOk},
      {url, RequestMode::kNoCors, FetchResponseType::kDefault, kOk},
      {url, RequestMode::kNoCors, FetchResponseType::kOpaque, kFail},
      {url, RequestMode::kNoCors, FetchResponseType::kOpaqueRedirect, kFail},

      // FetchResponseType::kError never arrives because it is a loading error.
      // FetchResponseType::kOpaque and FetchResponseType::kOpaqueResponse
      // never arrives: even when service worker is involved, it's handled as
      // an error.
      {url, RequestMode::kCors, FetchResponseType::kBasic, kOk},
      {url, RequestMode::kCors, FetchResponseType::kCors, kOk},
      {url, RequestMode::kCors, FetchResponseType::kDefault, kOk},
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message()
                 << ", target: " << test.url.BaseAsString()
                 << ", request mode: " << test.request_mode
                 << ", response type: " << test.response_type
                 << ", expected result: "
                 << (test.expectation == kIntegritySuccess ? "integrity"
                                                           : "failure"));

    // Verify basic sha256, sha384, and sha512 integrity checks.
    CheckExpectedIntegrity(kSha256Integrity, test);
    CheckExpectedIntegrity(kSha256IntegrityLenientSyntax, test);
    CheckExpectedIntegrity(kSha384Integrity, test);
    CheckExpectedIntegrity(kSha512Integrity, test);

    // Verify multiple hashes in an attribute.
    CheckExpectedIntegrity(kSha256AndSha384Integrities, test);
    CheckExpectedIntegrity(kBadSha256AndGoodSha384Integrities, test);

    // Unsupported hash functions should succeed.
    CheckExpectedIntegrity(kUnsupportedHashFunctionIntegrity, test);

    // Options should be ignored
    CheckExpectedIntegrity(kSha256IntegrityWithEmptyOption, test);
    CheckExpectedIntegrity(kSha256IntegrityWithOption, test);
    CheckExpectedIntegrity(kSha256IntegrityWithOptions, test);
    CheckExpectedIntegrity(kSha256IntegrityWithMimeOption, test);

    // The following tests are expected to fail in every scenario:

    // The hash label must match the hash value.
    CheckExpectedIntegrity(kSha384IntegrityLabeledAs256, test,
                           Expectation::kIntegrityFailure);

    // With multiple values, at least one must match, and it must be the
    // strongest hash algorithm.
    CheckExpectedIntegrity(kGoodSha256AndBadSha384Integrities, test,
                           Expectation::kIntegrityFailure);
    CheckExpectedIntegrity(kBadSha256AndBadSha384Integrities, test,
                           Expectation::kIntegrityFailure);
  }
}

TEST_F(SubresourceIntegrityTest, FindBestAlgorithm) {
  // Each algorithm is its own best.
  EXPECT_EQ(IntegrityAlgorithm::kSha256,
            SubresourceIntegrity::FindBestAlgorithm(
                IntegrityMetadataSet({{"", IntegrityAlgorithm::kSha256}})));
  EXPECT_EQ(IntegrityAlgorithm::kSha384,
            SubresourceIntegrity::FindBestAlgorithm(
                IntegrityMetadataSet({{"", IntegrityAlgorithm::kSha384}})));
  EXPECT_EQ(IntegrityAlgorithm::kSha512,
            SubresourceIntegrity::FindBestAlgorithm(
                IntegrityMetadataSet({{"", IntegrityAlgorithm::kSha512}})));

  // Test combinations of multiple algorithms.
  EXPECT_EQ(IntegrityAlgorithm::kSha384,
            SubresourceIntegrity::FindBestAlgorithm(
                IntegrityMetadataSet({{"", IntegrityAlgorithm::kSha256},
                                      {"", IntegrityAlgorithm::kSha384}})));
  EXPECT_EQ(IntegrityAlgorithm::kSha512,
            SubresourceIntegrity::FindBestAlgorithm(
                IntegrityMetadataSet({{"", IntegrityAlgorithm::kSha256},
                                      {"", IntegrityAlgorithm::kSha512},
                                      {"", IntegrityAlgorithm::kSha384}})));
}

}  // namespace blink
```