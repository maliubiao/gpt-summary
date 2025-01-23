Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name, `alternate_signed_exchange_resource_info_test.cc`, strongly suggests that it's a test file for a class named `AlternateSignedExchangeResourceInfo`. The `_test.cc` suffix is a common convention in Chromium.

2. **Understand the Tested Class:**  Reading the includes at the top reveals `#include "third_party/blink/renderer/core/loader/alternate_signed_exchange_resource_info.h"`. This confirms the class being tested and its location within the Blink rendering engine (specifically, the loader component). The name itself hints at the functionality: dealing with information about alternate versions of resources delivered via Signed Exchanges.

3. **Examine the Test Structure:** The file uses Google Test (`testing/gtest/include/gtest/gtest.h`). This means we'll see test fixtures (classes inheriting from `testing::Test`) and individual test cases using `TEST_F`.

4. **Analyze Individual Test Cases:** Go through each `TEST_F` function and understand what it's testing:

    * **`Empty`:** Checks that creating an `AlternateSignedExchangeResourceInfo` with empty strings fails (returns `nullptr`). This is a basic sanity check.

    * **`Simple`:**  Tests the creation with valid, simple header values for a single resource. It verifies that the data is parsed correctly (URLs, integrity, etc.) and that `FindMatchingEntry` works for a match and a non-match.

    * **`MultipleResources`:**  Similar to `Simple`, but tests the case where multiple alternate resources are specified in the headers. It verifies that all resources are parsed and accessible.

    * **`NoMatchingOuterAlternateLinkHeader`:** Tests the scenario where the outer `Link` header is empty. It checks that while the inner `allowed-alt-sxg` is processed, the `alternative_url` remains invalid.

    * **`NoType`:** Tests what happens when the `type` parameter in the outer `Link` header is missing or incorrect. It verifies that the outer link is ignored, but the inner link is still processed.

    * **`InvalidOuterURL`:** Tests the case where the URL in the outer `Link` header is invalid. It verifies that the outer link is ignored.

    * **`InvalidInnerURL`:** Tests the case where the URL in the inner `Link` header is invalid. It expects the entire creation to fail (return `nullptr`).

    * **`Variants`:**  This is the most complex test. It deals with content negotiation using the `variants` and `variant-key` attributes. It checks that multiple variants of the same resource are correctly parsed and that `FindMatchingEntry` can differentiate between them based on the `Accept` header (implicitly tested by using `network::mojom::RequestDestination::kImage`).

5. **Infer Functionality of the Tested Class:** Based on the tests, we can deduce the core responsibilities of `AlternateSignedExchangeResourceInfo`:

    * **Parsing HTTP `Link` headers:** Specifically looking for `rel="alternate"` with `type="application/signed-exchange"` and `rel="allowed-alt-sxg"`.
    * **Extracting information:**  URLs (original and alternate), integrity hashes, and variant information.
    * **Storing the information:**  Likely in a map or similar data structure.
    * **Matching:**  Providing a method (`FindMatchingEntry`) to find the appropriate alternate resource based on the original URL and potentially other criteria like `Accept` headers (for content negotiation).

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:**  A JavaScript fetch request might trigger the loading of a resource described by these headers. The browser would use the `AlternateSignedExchangeResourceInfo` to determine if an alternate (signed exchange) version is available.
    * **HTML:**  `<link>` tags in HTML headers can specify alternate resources. This is the *primary* way this information reaches the browser. The test directly uses string representations of these headers.
    * **CSS:**  While CSS itself doesn't directly define alternate signed exchanges, resources referenced *by* CSS (like fonts or background images) could be served via signed exchanges, and thus this logic would apply.

7. **Consider User/Developer Errors:**

    * **Incorrect Header Syntax:**  The tests explore various syntax errors (missing types, invalid URLs). Developers manually configuring servers or CDNs could make these mistakes.
    * **Mismatched Integrity Hashes:** While not directly tested here, incorrect integrity hashes in the `header-integrity` attribute would be a common error, leading to the browser rejecting the signed exchange.

8. **Think About Debugging:** How would a developer end up looking at this test file?

    * **Investigating Signed Exchange Issues:** If a website using signed exchanges isn't loading correctly, or if there are errors related to integrity checks, a Chromium developer might look at this code to understand how the browser parses and handles these headers.
    * **Working on the Loader Component:** Anyone working on the part of the browser responsible for fetching and processing resources would likely interact with this code.
    * **Writing New Signed Exchange Features:** If new features related to signed exchanges are being added, new tests in this file (or a similar one) would be necessary.

9. **Structure the Explanation:** Organize the findings into logical categories (functionality, relationship to web tech, errors, debugging) for a clear and comprehensive explanation. Use examples to illustrate the concepts.

10. **Review and Refine:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation.
这个C++源代码文件 `alternate_signed_exchange_resource_info_test.cc` 是 Chromium Blink 引擎的一部分，其主要功能是**测试 `AlternateSignedExchangeResourceInfo` 类的正确性**。

`AlternateSignedExchangeResourceInfo` 类负责解析和存储关于资源的可选签名交换 (Alternate Signed Exchange, SXG) 版本的信息。这些信息通常通过 HTTP 的 `Link` 头字段传递。

以下是该测试文件中的功能点的详细说明：

**1. 测试 `AlternateSignedExchangeResourceInfo` 类的创建和解析功能：**

* **解析 `Link` 头字段:**  测试文件模拟了各种 `Link` 头字段的场景，包括：
    * **外层链接 (Outer Link):** 指向 SXG 文件的链接，包含 `rel="alternate"`, `type="application/signed-exchange"` 和 `anchor` 属性，指定原始资源的 URL。
    * **内层链接 (Inner Link):** 指向原始资源的链接，包含 `rel="allowed-alt-sxg"` 和 `header-integrity` 属性，提供 SXG 内容的完整性校验信息。
* **存储解析后的信息:** 测试用例验证了 `AlternateSignedExchangeResourceInfo` 对象是否正确地存储了从 `Link` 头字段中解析出的信息，例如：
    * `alternative_url()`:  SXG 文件的 URL。
    * `anchor_url()`: 原始资源的 URL。
    * `header_integrity()`: SXG 内容的完整性哈希值。
    * `variants()` 和 `variant_key()`:  用于内容协商的变体信息。

**2. 测试不同 `Link` 头字段组合下的行为：**

测试用例覆盖了各种边缘情况和正常情况，以确保 `AlternateSignedExchangeResourceInfo` 的健壮性：

* **`Empty`:** 测试当传入空字符串时，是否能正确处理并返回 `nullptr`。
* **`Simple`:** 测试最基本的场景，包含一个有效的外部和内部链接。
    * **假设输入:**
        * 外层链接头: `<https://distributor.example/publisher.example/script.js.sxg>;rel="alternate";type="application/signed-exchange;v=b3";anchor="https://publisher.example/script.js"`
        * 内层链接头: `<https://publisher.example/script.js>;rel="allowed-alt-sxg";header-integrity="sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg="`
    * **预期输出:**  成功创建一个 `AlternateSignedExchangeResourceInfo` 对象，其中包含了正确的 SXG 文件 URL、原始资源 URL 和完整性信息。
* **`MultipleResources`:** 测试当 `Link` 头字段中包含多个 SXG 资源信息时的解析。
* **`NoMatchingOuterAlternateLinkHeader`:** 测试当没有外层链接头时，是否能正确处理内层链接头。此时，SXG 的 `alternative_url` 应该无效。
* **`NoType`:** 测试当外层链接头缺少 `type="application/signed-exchange"` 属性时，外层链接是否会被忽略。
* **`InvalidOuterURL`:** 测试当外层链接头中的 URL 无效时，外层链接是否会被忽略。
* **`InvalidInnerURL`:** 测试当内层链接头中的 URL 无效时，是否会导致 `AlternateSignedExchangeResourceInfo::CreateIfValid` 返回 `nullptr`。
* **`Variants`:** 测试处理带有内容协商变体信息的 `Link` 头字段。
    * **假设输入:**  包含多个指向同一原始资源但具有不同变体（例如，不同图像格式）的 SXG 文件的链接，通过 `variants` 和 `variant-key` 属性指定。
    * **预期输出:**  成功解析并存储所有变体信息，并且可以通过 `FindMatchingEntry` 方法根据请求的 `Accept` 头找到匹配的变体。

**3. 测试 `FindMatchingEntry` 方法：**

* 该方法用于根据原始资源的 URL 和一些可选的匹配条件（例如，`Accept` 头信息）查找对应的 SXG 资源信息。
* 测试用例验证了在不同情况下，`FindMatchingEntry` 是否能正确找到匹配的条目或者返回空指针。

**与 JavaScript, HTML, CSS 的关系：**

`AlternateSignedExchangeResourceInfo` 类直接影响浏览器如何加载资源，尤其是与性能优化和离线访问相关的场景。它与以下 Web 技术功能相关：

* **HTML:**
    * **`<link>` 标签:**  网站可以通过 `<link>` 标签在 HTML 文档的 `<head>` 部分声明可选的 SXG 资源。例如：
        ```html
        <link rel="alternate" href="https://distributor.example/publisher.example/script.js.sxg"
              type="application/signed-exchange;v=b3"
              anchor="https://publisher.example/script.js">
        ```
    * 当浏览器遇到这样的 `<link>` 标签时，会解析这些属性并最终调用到 `AlternateSignedExchangeResourceInfo::CreateIfValid` 来处理这些信息。

* **HTTP Header:**
    * **`Link` Header:**  服务器通常通过 `Link` HTTP 响应头来声明可选的 SXG 资源。这是 `AlternateSignedExchangeResourceInfo` 主要处理的信息来源。例如：
        ```
        Link: <https://distributor.example/publisher.example/script.js.sxg>; rel="alternate"; type="application/signed-exchange;v=b3"; anchor="https://publisher.example/script.js",
              <https://publisher.example/script.js>; rel="allowed-alt-sxg"; header-integrity="sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg="
        ```
    * 当浏览器接收到包含这些 `Link` 头的响应时，会将其传递给 Blink 引擎进行解析，并使用 `AlternateSignedExchangeResourceInfo` 来存储这些信息。

* **JavaScript:**
    * **`fetch()` API:**  当 JavaScript 代码使用 `fetch()` API 请求资源时，浏览器会检查是否存在可用的 SXG 版本。`AlternateSignedExchangeResourceInfo` 提供的信息将被用于判断是否应该请求并使用 SXG 版本。
    * **Service Workers:** Service Workers 可以拦截 `fetch` 请求，并根据 `AlternateSignedExchangeResourceInfo` 中存储的信息，提供来自缓存的 SXG 响应，从而实现离线访问或更快的加载速度。

* **CSS:**
    * **资源引用:** CSS 文件中引用的资源（例如，背景图片、字体）也可能存在 SXG 版本。当浏览器加载 CSS 文件并需要获取这些资源时，同样会利用 `AlternateSignedExchangeResourceInfo` 来查找并加载 SXG 版本。

**用户或编程常见的使用错误举例：**

* **错误的 `Link` 头语法:**  开发者在配置服务器或 CDN 时，可能会错误地编写 `Link` 头字段，例如：
    * 拼写错误 `rel` 属性值 (例如: `rel="aternate"`)。
    * 缺少必要的属性，如 `anchor` 或 `type="application/signed-exchange;v=b3"`。
    * URL 格式错误。
    * 完整性哈希值计算错误或与实际 SXG 内容不匹配。

    **假设输入:**  `Link: <https://example.com/resource.sxg>; rel="alternate"; ankor="https://example.com/resource"` (拼写错误的 `anchor`)
    **预期结果:**  `AlternateSignedExchangeResourceInfo::CreateIfValid` 可能返回 `nullptr` 或者解析出的信息不完整，导致浏览器无法正确识别或加载 SXG 版本。

* **`header-integrity` 值与 SXG 内容不匹配:** 如果 `header-integrity` 值与实际 SXG 文件的哈希值不符，浏览器会拒绝加载该 SXG 文件，以防止内容被篡改。

    **假设输入:**  `Link: <https://example.com/resource.sxg>; rel="alternate"; type="application/signed-exchange;v=b3"; anchor="https://example.com/resource", <https://example.com/resource>; rel="allowed-alt-sxg"; header-integrity="incorrect_hash_value"`
    **预期结果:** 即使 `AlternateSignedExchangeResourceInfo` 成功解析了这些信息，当浏览器尝试加载 SXG 文件并进行完整性校验时，校验会失败，导致资源加载失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入 URL 或点击链接访问一个网页。**
2. **浏览器向服务器发送 HTTP 请求。**
3. **服务器返回包含 `Link` HTTP 响应头的 HTML 文档或其他资源。**
4. **Blink 渲染引擎接收到响应头。**
5. **Blink 的 HTTP 引擎或资源加载器会解析 `Link` 头字段。**
6. **如果 `Link` 头中包含 `rel="alternate"` 和 `type="application/signed-exchange"`，以及 `rel="allowed-alt-sxg"`，则会调用 `AlternateSignedExchangeResourceInfo::CreateIfValid` 来解析这些信息。**
7. **`alternate_signed_exchange_resource_info_test.cc` 中的测试用例模拟了步骤 5 和 6 中可能出现的各种输入情况，用于验证解析逻辑的正确性。**

**作为调试线索，当开发者遇到与 SXG 加载相关的问题时，可以参考这个测试文件来理解 Blink 引擎是如何解析和处理 SXG 信息的。** 例如：

* **SXG 文件无法加载:** 开发者可以检查服务器返回的 `Link` 头是否符合预期格式，参考测试用例中正确的 `Link` 头示例。
* **SXG 的完整性校验失败:** 可以检查 `header-integrity` 的值是否与 SXG 文件的实际哈希值一致。
* **浏览器没有加载 SXG 版本:** 可以检查 `Link` 头中是否包含了必要的属性，以及属性值是否正确。

总而言之，`alternate_signed_exchange_resource_info_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎能够正确地处理和利用 Alternate Signed Exchange 技术，从而提升网页加载性能和安全性。它通过各种测试用例覆盖了不同的场景，为开发者提供了理解和调试 SXG 相关问题的参考。

### 提示词
```
这是目录为blink/renderer/core/loader/alternate_signed_exchange_resource_info_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/alternate_signed_exchange_resource_info.h"

#include "services/network/public/mojom/fetch_api.mojom-shared.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"

namespace blink {

class AlternateSignedExchangeResourceInfoTest : public testing::Test {
 public:
  AlternateSignedExchangeResourceInfoTest() = default;
  AlternateSignedExchangeResourceInfoTest(
      const AlternateSignedExchangeResourceInfoTest&) = delete;
  AlternateSignedExchangeResourceInfoTest& operator=(
      const AlternateSignedExchangeResourceInfoTest&) = delete;
  ~AlternateSignedExchangeResourceInfoTest() override = default;

 protected:
  const AlternateSignedExchangeResourceInfo::EntryMap& GetEntries(
      const AlternateSignedExchangeResourceInfo* info) {
    return info->alternative_resources_;
  }
};

TEST_F(AlternateSignedExchangeResourceInfoTest, Empty) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid("", "");
  EXPECT_FALSE(info);
}

TEST_F(AlternateSignedExchangeResourceInfoTest, Simple) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid(
          // Outer link header
          "<https://distributor.example/publisher.example/script.js.sxg>;"
          "rel=\"alternate\";"
          "type=\"application/signed-exchange;v=b3\";"
          "anchor=\"https://publisher.example/script.js\"",
          // Inner link header
          "<https://publisher.example/script.js>;"
          "rel=\"allowed-alt-sxg\";"
          "header-integrity="
          "\"sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=\"");
  ASSERT_TRUE(info);
  const auto& entries = GetEntries(info.get());
  ASSERT_EQ(1u, entries.size());
  const auto& it = entries.find(KURL("https://publisher.example/script.js"));
  ASSERT_TRUE(it != entries.end());
  ASSERT_EQ(1u, it->value.size());
  const auto& resource = it->value.at(0);
  EXPECT_EQ(KURL("https://publisher.example/script.js"),
            resource->anchor_url());
  EXPECT_EQ(KURL("https://distributor.example/publisher.example/script.js.sxg"),
            resource->alternative_url());
  EXPECT_EQ("sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=",
            resource->header_integrity());
  EXPECT_TRUE(resource->variants().empty());
  EXPECT_TRUE(resource->variant_key().empty());

  EXPECT_EQ(resource.get(),
            info->FindMatchingEntry(KURL("https://publisher.example/script.js"),
                                    std::nullopt, {"en"}));
  EXPECT_EQ(nullptr,
            info->FindMatchingEntry(KURL("https://publisher.example/image"),
                                    std::nullopt, {"en"}));
}

TEST_F(AlternateSignedExchangeResourceInfoTest, MultipleResources) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid(
          // The first outer link header
          "<https://distributor.example/publisher.example/script.js.sxg>;"
          "rel=\"alternate\";"
          "type=\"application/signed-exchange;v=b3\";"
          "anchor=\"https://publisher.example/script.js\","
          // The second outer_link_header
          "<https://distributor.example/publisher.example/image.sxg>;"
          "rel=\"alternate\";"
          "type=\"application/signed-exchange;v=b3\";"
          "anchor=\"https://publisher.example/image\";",
          // The first inner link header
          "<https://publisher.example/script.js>;"
          "rel=\"allowed-alt-sxg\";"
          "header-integrity="
          "\"sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=\","
          // The second inner link header
          "<https://publisher.example/image>;"
          "rel=\"allowed-alt-sxg\";"
          "header-integrity="
          "\"sha256-q1phjFcR+umcl0zBaEz6E5AGVlnc9yF0zOjDYi5c6aM=\"");
  ASSERT_TRUE(info);
  const auto& entries = GetEntries(info.get());
  ASSERT_EQ(2u, entries.size());
  {
    const auto& it = entries.find(KURL("https://publisher.example/script.js"));
    ASSERT_TRUE(it != entries.end());
    ASSERT_EQ(1u, it->value.size());
    const auto& resource = it->value.at(0);
    EXPECT_EQ(KURL("https://publisher.example/script.js"),
              resource->anchor_url());
    EXPECT_EQ(
        KURL("https://distributor.example/publisher.example/script.js.sxg"),
        resource->alternative_url());
    EXPECT_EQ("sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=",
              resource->header_integrity());
    EXPECT_TRUE(resource->variants().empty());
    EXPECT_TRUE(resource->variant_key().empty());
    EXPECT_EQ(resource.get(), info->FindMatchingEntry(
                                  KURL("https://publisher.example/script.js"),
                                  std::nullopt, {"en"}));
  }
  {
    const auto& it = entries.find(KURL("https://publisher.example/image"));
    ASSERT_TRUE(it != entries.end());
    ASSERT_EQ(1u, it->value.size());
    const auto& resource = it->value.at(0);
    EXPECT_EQ(KURL("https://publisher.example/image"), resource->anchor_url());
    EXPECT_EQ(KURL("https://distributor.example/publisher.example/image.sxg"),
              resource->alternative_url());
    EXPECT_EQ("sha256-q1phjFcR+umcl0zBaEz6E5AGVlnc9yF0zOjDYi5c6aM=",
              resource->header_integrity());
    EXPECT_TRUE(resource->variants().empty());
    EXPECT_TRUE(resource->variant_key().empty());
    EXPECT_EQ(resource.get(),
              info->FindMatchingEntry(KURL("https://publisher.example/image"),
                                      std::nullopt, {"en"}));
  }
}

TEST_F(AlternateSignedExchangeResourceInfoTest,
       NoMatchingOuterAlternateLinkHeader) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid(
          // Empty outer link header
          "",
          // Inner link header
          "<https://publisher.example/script.js>;"
          "rel=\"allowed-alt-sxg\";"
          "header-integrity="
          "\"sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=\"");
  ASSERT_TRUE(info);
  const auto& entries = GetEntries(info.get());
  ASSERT_EQ(1u, entries.size());
  const auto& it = entries.find(KURL("https://publisher.example/script.js"));
  ASSERT_TRUE(it != entries.end());
  ASSERT_EQ(1u, it->value.size());
  const auto& resource = it->value.at(0);
  EXPECT_EQ(KURL("https://publisher.example/script.js"),
            resource->anchor_url());
  EXPECT_FALSE(resource->alternative_url().IsValid());
  EXPECT_EQ("sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=",
            resource->header_integrity());
  EXPECT_TRUE(resource->variants().empty());
  EXPECT_TRUE(resource->variant_key().empty());

  EXPECT_EQ(resource.get(),
            info->FindMatchingEntry(KURL("https://publisher.example/script.js"),
                                    std::nullopt, {"en"}));
}

TEST_F(AlternateSignedExchangeResourceInfoTest, NoType) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid(
          // Outer link header
          "<https://distributor.example/publisher.example/script.js.sxg>;"
          "rel=\"alternate\";"
          "anchor=\"https://publisher.example/script.js\"",
          // Inner link header
          "<https://publisher.example/script.js>;"
          "rel=\"allowed-alt-sxg\";"
          "header-integrity="
          "\"sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=\"");
  ASSERT_TRUE(info);
  const auto& entries = GetEntries(info.get());
  ASSERT_EQ(1u, entries.size());
  const auto& it = entries.find(KURL("https://publisher.example/script.js"));
  ASSERT_TRUE(it != entries.end());
  ASSERT_EQ(1u, it->value.size());
  const auto& resource = it->value.at(0);
  EXPECT_EQ(KURL("https://publisher.example/script.js"),
            resource->anchor_url());
  // If type is not "application/signed-exchange;v=b3", outer alternate link
  // header is ignored.
  EXPECT_FALSE(resource->alternative_url().IsValid());
  EXPECT_EQ("sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=",
            resource->header_integrity());
  EXPECT_TRUE(resource->variants().empty());
  EXPECT_TRUE(resource->variant_key().empty());

  EXPECT_EQ(resource.get(),
            info->FindMatchingEntry(KURL("https://publisher.example/script.js"),
                                    std::nullopt, {"en"}));
  EXPECT_EQ(nullptr,
            info->FindMatchingEntry(KURL("https://publisher.example/image"),
                                    std::nullopt, {"en"}));
}

TEST_F(AlternateSignedExchangeResourceInfoTest, InvalidOuterURL) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid(
          // Outer link header: Outer URL is invalid.
          "<INVALID_OUTER_URL>;"
          "rel=\"alternate\";"
          "type=\"application/signed-exchange;v=b3\";"
          "anchor=\"https://publisher.example/script.js\"",
          // Inner link header
          "<https://publisher.example/script.js>;"
          "rel=\"allowed-alt-sxg\";"
          "header-integrity="
          "\"sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=\"");
  ASSERT_TRUE(info);
  const auto& entries = GetEntries(info.get());
  ASSERT_EQ(1u, entries.size());
  const auto& it = entries.find(KURL("https://publisher.example/script.js"));
  ASSERT_TRUE(it != entries.end());
  ASSERT_EQ(1u, it->value.size());
  const auto& resource = it->value.at(0);
  EXPECT_EQ(KURL("https://publisher.example/script.js"),
            resource->anchor_url());
  EXPECT_FALSE(resource->alternative_url().IsValid());
  EXPECT_EQ("sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=",
            resource->header_integrity());
  EXPECT_TRUE(resource->variants().empty());
  EXPECT_TRUE(resource->variant_key().empty());

  EXPECT_EQ(resource.get(),
            info->FindMatchingEntry(KURL("https://publisher.example/script.js"),
                                    std::nullopt, {"en"}));
}

TEST_F(AlternateSignedExchangeResourceInfoTest, InvalidInnerURL) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid(
          // Outer link header: Inner URL is invalid.
          "<https://distributor.example/publisher.example/script.js.sxg>;"
          "rel=\"alternate\";"
          "type=\"application/signed-exchange;v=b3\";"
          "anchor=\"INVALID_INNER_URL\"",
          // Inner link header: Inner URL is invalid.
          "<INVALID_INNER_URL>;"
          "rel=\"allowed-alt-sxg\";"
          "header-integrity="
          "\"sha256-7KheEN4nyNxE3c4yQZdgCBJthJ2UwgpLSBeSUpII+jg=\"");
  ASSERT_FALSE(info);
}

TEST_F(AlternateSignedExchangeResourceInfoTest, Variants) {
  std::unique_ptr<AlternateSignedExchangeResourceInfo> info =
      AlternateSignedExchangeResourceInfo::CreateIfValid(
          // The first outer link header
          "<https://distributor.example/publisher.example/image_jpeg.sxg>;"
          "rel=\"alternate\";"
          "type=\"application/signed-exchange;v=b3\";"
          "variants-04=\"accept;image/jpeg;image/webp\";"
          "variant-key-04=\"image/jpeg\";"
          "anchor=\"https://publisher.example/image\";,"
          // The second outer link header
          "<https://distributor.example/publisher.example/image_webp.sxg>;"
          "rel=\"alternate\";"
          "type=\"application/signed-exchange;v=b3\";"
          "variants-04=\"accept;image/jpeg;image/webp\";"
          "variant-key-04=\"image/webp\";"
          "anchor=\"https://publisher.example/image\"",
          // The first inner link header
          "<https://publisher.example/image>;"
          "rel=\"allowed-alt-sxg\";"
          "variants-04=\"accept;image/jpeg;image/webp\";"
          "variant-key-04=\"image/jpeg\";"
          "header-integrity="
          "\"sha256-q1phjFcR+umcl0zBaEz6E5AGVlnc9yF0zOjDYi5c6aM=\","
          // The second inner link header
          "<https://publisher.example/image>;"
          "rel=\"allowed-alt-sxg\";"
          "variants-04=\"accept;image/jpeg;image/webp\";"
          "variant-key-04=\"image/webp\";"
          "header-integrity="
          "\"sha256-KRcYU+BZK8Sb2ccJfDPz+uUKXDdB1PVToPugItdzRXY=\"");
  ASSERT_TRUE(info);
  const auto& entries = GetEntries(info.get());
  ASSERT_EQ(1u, entries.size());
  const auto& it = entries.find(KURL("https://publisher.example/image"));
  ASSERT_TRUE(it != entries.end());
  ASSERT_EQ(2u, it->value.size());
  {
    const auto& resource = it->value.at(0);
    EXPECT_EQ(KURL("https://publisher.example/image"), resource->anchor_url());
    EXPECT_EQ(
        KURL("https://distributor.example/publisher.example/image_jpeg.sxg"),
        resource->alternative_url());
    EXPECT_EQ("sha256-q1phjFcR+umcl0zBaEz6E5AGVlnc9yF0zOjDYi5c6aM=",
              resource->header_integrity());
    EXPECT_EQ("accept;image/jpeg;image/webp", resource->variants());
    EXPECT_EQ("image/jpeg", resource->variant_key());
  }
  {
    const auto& resource = it->value.at(1);
    EXPECT_EQ(KURL("https://publisher.example/image"), resource->anchor_url());
    EXPECT_EQ(
        KURL("https://distributor.example/publisher.example/image_webp.sxg"),
        resource->alternative_url());
    EXPECT_EQ("sha256-KRcYU+BZK8Sb2ccJfDPz+uUKXDdB1PVToPugItdzRXY=",
              resource->header_integrity());
    EXPECT_EQ("accept;image/jpeg;image/webp", resource->variants());
    EXPECT_EQ("image/webp", resource->variant_key());

    EXPECT_EQ(resource.get(),
              info->FindMatchingEntry(
                  KURL("https://publisher.example/image"),
                  network::mojom::RequestDestination::kImage, {"en"}));
  }
}

}  // namespace blink
```