Response: Let's break down the thought process for analyzing this C++ code and generating the comprehensive explanation.

1. **Understand the Core Purpose:** The file name `web_package_request_matcher.cc` and the namespace `blink::web_package` immediately suggest its purpose: matching requests to resources within a Web Package (like Signed Exchanges). The key term here is "matching," which implies criteria and a decision (match or no match).

2. **Identify Key Data Structures:**  Look for the main classes and structs. Here, `WebPackageRequestMatcher` is central. The nested `ContentNegotiationAlgorithm` and its subclasses (`ContentTypeNegotiation`, `AcceptEncodingNegotiation`, `AcceptLanguageNegotiation`) are also crucial. The `WeightedValue` struct within the algorithm hints at preference handling.

3. **Trace the Matching Logic:** The `MatchRequest` methods are the entry points for determining if a request aligns with a packaged resource. Notice there are two `MatchRequest` methods: one taking `HeaderMap` and another taking `HttpRequestHeaders` and `HeaderMap`. This suggests different contexts or levels of detail. The second `MatchRequest` seems more complex and handles the `Variants` and `Variant-Key` headers.

4. **Analyze Content Negotiation:** The `ContentNegotiationAlgorithm` hierarchy is a significant part. Recognize that these algorithms handle the standard HTTP content negotiation mechanisms (`Accept`, `Accept-Encoding`, `Accept-Language`). Examine the `run` methods in each subclass to understand how they use the available values and request header values to determine the preferred options. Pay attention to the use of `ParseRequestHeaderValue` and how it handles weights (`q` values).

5. **Focus on `Variants` and `Variant-Key` Headers:** The code explicitly handles these headers. Understand their purpose: `Variants` describes the available variations of a resource, and `Variant-Key` identifies the specific variation being served. The parsing logic (`ParseVariants`, `ParseVariantKey`) and the `CacheBehavior` function are vital for grasping how these headers are processed.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Think about how content negotiation and resource variations impact web development. Different versions of an image (WebP vs. JPEG), different language versions of a page, or compressed vs. uncompressed resources are common examples. This connection helps illustrate the practical implications of the code.

7. **Logical Reasoning and Examples:** For functions like `GetPossibleKeysIndex`, devise simple input examples to illustrate the logic. Consider edge cases or common scenarios. The example provided in the code comments for `GetPossibleKeysIndex` is a good starting point.

8. **Identify Potential User/Programming Errors:** Think about how developers might misuse the concepts related to `Variants` and `Variant-Key`. Incorrect header formatting, inconsistencies between `Variants` and `Variant-Key`, and not understanding the implications of content negotiation are all possibilities.

9. **Structure the Explanation:** Organize the findings into logical sections:
    * Overall Functionality
    * Relationship to Web Technologies (with examples)
    * Logical Reasoning (with input/output examples)
    * Common Errors

10. **Refine and Elaborate:** Review the generated explanation for clarity, accuracy, and completeness. Expand on key concepts, provide more detailed examples, and ensure the language is accessible. For instance, initially, I might just say "parses headers."  Then, I'd refine it to specify *which* headers and *why* they are parsed. I'd also ensure the explanations align with the provided code snippets and comments.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "It just matches requests."  **Correction:**  It's more nuanced. It uses content negotiation principles and specifically handles `Variants` and `Variant-Key` for more complex matching scenarios in web packages.
* **Initial thought:** "The algorithms are simple." **Correction:** While the individual steps in the algorithms are relatively straightforward, understanding the overall flow and the interaction between the different algorithms requires careful reading.
* **Initial thought:** "Just list the functions." **Correction:** Explaining *what* the functions do and *why* they are needed provides much more valuable insight. The examples are crucial for this.
* **Initial thought:**  "Focus only on the C++ code." **Correction:**  Connecting it to web technologies and common web development practices makes the explanation more relevant and understandable.

By following these steps and continually refining the understanding and explanation, a comprehensive and helpful answer can be generated.
这个文件 `blink/common/web_package/web_package_request_matcher.cc` 的主要功能是**根据 HTTP 请求头和 Web Package 中的响应头信息，判断请求是否与特定的 Web Package 资源相匹配。** 它特别关注于处理 HTTP 的内容协商机制和 `Variants` / `Variant-Key` 头部，以实现更精细的资源匹配。

以下是该文件的详细功能分解：

**1. 内容协商 (Content Negotiation)：**

* **实现多种内容协商算法:** 该文件实现了针对 `Accept`, `Accept-Encoding`, 和 `Accept-Language` 这三个常见 HTTP 请求头的协商算法。这些算法根据客户端的偏好（通过请求头指定）和服务器提供的资源变体（通过 `Variants` 头部指定），确定最佳的匹配项。
* **`ContentNegotiationAlgorithm` 抽象类:** 定义了内容协商算法的通用接口，包含一个 `run` 方法，用于根据可用的值和请求头值，返回满足请求的值的有序列表。
* **具体算法实现:**
    * **`ContentTypeNegotiation`:** 处理 `Accept` 请求头，根据 MIME 类型进行匹配。
    * **`AcceptEncodingNegotiation`:** 处理 `Accept-Encoding` 请求头，根据编码方式进行匹配，并特别处理 `identity`（无编码）。
    * **`AcceptLanguageNegotiation`:** 处理 `Accept-Language` 请求头，根据语言标签进行匹配，支持通配符 (`*`)。
* **`GetContentNegotiationAlgorithm` 函数:** 根据给定的头部名称，返回相应的协商算法实例。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**  当 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发起网络请求时，浏览器会自动设置 `Accept`, `Accept-Encoding`, `Accept-Language` 等请求头。`WebPackageRequestMatcher` 的功能确保了 Web Package 中提供的不同版本的 JavaScript 文件（例如，针对不同浏览器的优化版本或不同语言的版本）能够根据这些请求头正确匹配。
    * **假设输入：**
        * **Web Package 中的 JavaScript 文件：** `script.js`, `script.js.br` (Brotli 压缩版本)
        * **`Variants` 头部：** `accept-encoding=("br")`
        * **请求头：** `Accept-Encoding: br, gzip`
        * **输出：** `WebPackageRequestMatcher` 会匹配到 `script.js.br` 文件，因为它符合客户端的 `Accept-Encoding` 偏好。
* **HTML:** HTML 页面可能包含指向不同资源（如图片、CSS、JavaScript）的链接。浏览器在加载 HTML 页面时，也会根据其设置发送相应的请求头。`WebPackageRequestMatcher` 确保了 Web Package 中提供的不同版本的 HTML 页面（例如，不同语言版本）能够正确匹配。
    * **假设输入：**
        * **Web Package 中的 HTML 文件：** `index.html`, `index.zh-CN.html`
        * **`Variants` 头部：** `accept-language=("zh-CN")`
        * **请求头：** `Accept-Language: zh-CN, en-US;q=0.9, en;q=0.8`
        * **输出：** `WebPackageRequestMatcher` 会匹配到 `index.zh-CN.html` 文件，因为它符合客户端的 `Accept-Language` 偏好。
* **CSS:**  与 HTML 类似，Web Package 中可以包含针对不同屏幕尺寸或设备优化的 CSS 文件。`WebPackageRequestMatcher` 可以根据自定义的 `Variants` 头部（虽然标准 CSS 不直接参与内容协商，但 `Variants` 机制允许自定义协商）进行匹配。
    * **假设输入：**
        * **Web Package 中的 CSS 文件：** `style.css`, `style.mobile.css`
        * **自定义 `Variants` 头部（假设）：** `viewport=("mobile")`
        * **自定义请求头（假设）：** `Viewport: mobile`
        * **输出：**  如果实现了处理 `Viewport` 头的自定义协商逻辑，`WebPackageRequestMatcher` 可能会匹配到 `style.mobile.css`。

**2. 处理 `Variants` 和 `Variant-Key` 头部：**

* **`ParseVariants` 函数:** 解析 `Variants` 头部的值，将其转换为一个包含字段名和可用值的列表的结构。
* **`ParseVariantKey` 函数:** 解析 `Variant-Key` 头部的值，将其转换为一个包含多个变体键的列表的结构。每个变体键对应 `Variants` 头部中定义的变体轴。
* **`GetPossibleKeysIndex` 函数:**  根据排序后的 `Variants` 和 `Variant-Key`，计算出匹配的索引。
* **`CacheBehavior` 函数:**  模拟缓存行为，根据 `Variants` 头部和请求头，确定可接受的变体键。
* **`MatchRequest` 函数 (两个重载版本):**
    * **版本一 (输入 `HeaderMap`):**  一个简化的匹配方法。
    * **版本二 (输入 `HttpRequestHeaders` 和 `HeaderMap`):**  更完整的匹配逻辑，考虑了 `Variants` 和 `Variant-Key` 头部。它实现了 Web Package 加载规范中定义的请求匹配步骤，判断请求是否与包含 `Variants` 和 `Variant-Key` 头部的响应相匹配。
* **`FindBestMatchingVariantKey` 函数:**  在给定的 `Variants` 头部和一组 `Variant-Key` 中，找到最佳匹配的 `Variant-Key`。
* **`FindBestMatchingIndex` 函数:**  根据 `Variants` 头部和请求头，找到最佳匹配的变体索引。

**逻辑推理和假设输入输出：**

假设我们有以下 Web Package 中的资源和头部：

* **资源:**
    * `page.html` (默认版本)
    * `page.html.gz` (Gzip 压缩版本)
    * `page.html;lang=en` (英文版本)
    * `page.html;lang=zh-CN` (中文版本)
* **响应头 (针对 `page.html`):**
    * `Variants: accept-encoding=("gzip"), accept-language=("en" "zh-CN")`
* **请求头 1:**
    * `Accept-Encoding: gzip, deflate`
    * `Accept-Language: zh-CN, en-US;q=0.9, en;q=0.8`
* **请求头 2:**
    * `Accept-Encoding: br`
    * `Accept-Language: ja`

**逻辑推理：**

1. **对于请求头 1:**
   * `Accept-Encoding` 中 `gzip` 的权重高于 `deflate`，并且服务器提供了 `gzip` 版本。
   * `Accept-Language` 中 `zh-CN` 的权重最高，并且服务器提供了 `zh-CN` 版本。
   * **`WebPackageRequestMatcher::MatchRequest` 的输出 (假设针对包含 `Variants` 头的响应):** `true` (因为存在匹配的变体)
   * **`WebPackageRequestMatcher::FindBestMatchingIndex` 的输出:**  可能会返回一个索引，指示最佳匹配是中文 Gzip 版本。

2. **对于请求头 2:**
   * `Accept-Encoding` 中首选 `br`，但服务器只提供了 `gzip` 版本。
   * `Accept-Language` 中首选 `ja`，但服务器只提供了 `en` 和 `zh-CN` 版本。
   * **`WebPackageRequestMatcher::MatchRequest` 的输出 (假设针对包含 `Variants` 头的响应):** `false` (因为没有完全匹配的变体)
   * **`WebPackageRequestMatcher::FindBestMatchingIndex` 的输出:** 可能会返回空或一个指示没有最佳匹配的值。

**用户或编程常见的使用错误举例说明：**

1. **`Variants` 头部格式错误:**  `Variants` 头部的值必须符合特定的语法。如果格式错误，`ParseVariants` 函数会返回空，导致匹配失败。
   * **错误示例:** `Variants: accept-encoding=gzip, accept-language=en` (缺少引号和括号)
   * **后果:** 请求无法与任何变体匹配，可能导致服务器返回默认版本或错误。

2. **`Variant-Key` 头部与 `Variants` 头部不一致:** `Variant-Key` 头部中变体键的数量和顺序必须与 `Variants` 头部中定义的变体轴一致。
   * **错误示例：**
      * `Variants: accept-encoding=("gzip"), accept-language=("en" "zh-CN")`
      * `Variant-Key: "gzip"` (缺少语言信息)
   * **后果:** `ParseVariantKey` 可能会返回空，或者匹配逻辑会出错，导致返回错误的资源。

3. **不支持的协商头部:**  `WebPackageRequestMatcher` 只实现了对 `Accept`, `Accept-Encoding`, 和 `Accept-Language` 的协商。如果 `Variants` 头部中使用了其他头部名称，则该变体轴会被忽略。
   * **错误示例：** `Variants: viewport=("mobile", "desktop")` (`viewport` 不是标准的内容协商头部)
   * **后果:**  `viewport` 变体轴不会被用于匹配，可能导致服务器返回不适合客户端视口的资源。

4. **误解 `identity` 编码:** 在 `Accept-Encoding` 协商中，`identity` 代表无编码。如果服务器错误地认为客户端不支持 `identity` 并只提供压缩版本，即使客户端可以处理未压缩的版本，也可能导致不必要的解压操作。

5. **忽略大小写:** HTTP 头部名称通常是不区分大小写的。但是，`Variants` 头部中的字段名是区分大小写的。如果大小写不匹配，可能导致匹配失败。
   * **错误示例：** `Variants: Accept-Encoding=("gzip")` (应该使用 `accept-encoding`)

总而言之，`blink/common/web_package/web_package_request_matcher.cc` 是 Chromium 浏览器 Blink 引擎中负责 Web Package 请求匹配的关键组件，它利用 HTTP 内容协商机制和 `Variants`/`Variant-Key` 头部，为用户提供最佳的 Web Package 资源体验。正确理解和使用这些机制对于构建高效和适应性强的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/common/web_package/web_package_request_matcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/web_package/web_package_request_matcher.h"

#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/numerics/checked_math.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "net/base/mime_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_util.h"
#include "net/http/structured_headers.h"
#include "third_party/blink/public/common/web_package/signed_exchange_consts.h"

namespace blink {

namespace {

constexpr char kIdentity[] = "identity";

class ContentNegotiationAlgorithm {
 public:
  virtual ~ContentNegotiationAlgorithm() = default;
  // Returns items from |available_values| that satisfy the request, in
  // preference order. Each subclass should implement the algorithm defined by
  // content negotiation mechanism.
  virtual std::vector<std::string> run(
      base::span<const std::string> available_values,
      std::optional<std::string> request_header_value) = 0;

 protected:
  struct WeightedValue {
    std::string value;
    double weight;

    bool operator<(const WeightedValue& other) const {
      return weight > other.weight;  // Descending order
    }
  };

  // Parses an Accept (Section 5.3.2 of [RFC7231]), an Accept-Encoding (Section
  // 5.3.3 of [RFC7231]), or an Accept-Language (Section 5.3.5 of [RFC7231]).
  // Returns items sorted by descending order of their weight, omitting items
  // with weight of 0.
  std::vector<WeightedValue> ParseRequestHeaderValue(
      const std::optional<std::string>& request_header_value) {
    std::vector<WeightedValue> items;
    if (!request_header_value)
      return items;

    // Value can start with '*', so it cannot be parsed by
    // net::structured_headers::ParseParameterisedList.
    net::HttpUtil::ValuesIterator values(*request_header_value,
                                         /*delimiter=*/',');
    while (values.GetNext()) {
      net::HttpUtil::NameValuePairsIterator name_value_pairs(
          values.value(), /*delimiter=*/';',
          net::HttpUtil::NameValuePairsIterator::Values::NOT_REQUIRED,
          net::HttpUtil::NameValuePairsIterator::Quotes::STRICT_QUOTES);
      if (!name_value_pairs.GetNext())
        continue;
      WeightedValue item;
      item.value = name_value_pairs.name();
      item.weight = 1.0;
      while (name_value_pairs.GetNext()) {
        if (base::EqualsCaseInsensitiveASCII(name_value_pairs.name(), "q")) {
          if (auto value = GetQValue(name_value_pairs.value())) {
            item.weight = *value;
          }
        } else {
          // Parameters except for "q" are included in the output.
          base::StrAppend(&item.value, {";", name_value_pairs.name(), "=",
                                        name_value_pairs.value()});
        }
      }
      if (item.weight != 0.0)
        items.push_back(std::move(item));
    }
    std::stable_sort(items.begin(), items.end());
    return items;
  }

 private:
  std::optional<double> GetQValue(std::string_view str) {
    // TODO(ksakamoto): Validate the syntax per Section 5.3.1 of [RFC7231],
    // by factoring out the logic in HttpUtil::ParseAcceptEncoding().
    double val;
    if (!base::StringToDouble(str, &val))
      return std::nullopt;
    if (val < 0.0 || val > 1.0)
      return std::nullopt;
    return val;
  }
};

// https://httpwg.org/http-extensions/draft-ietf-httpbis-variants.html#content-type
class ContentTypeNegotiation final : public ContentNegotiationAlgorithm {
  std::vector<std::string> run(
      base::span<const std::string> available_values,
      std::optional<std::string> request_header_value) override {
    // Step 1. Let preferred-available be an empty list. [spec text]
    std::vector<std::string> preferred_available;

    // Step 2. Let preferred-types be a list of the types in the request-value
    // (or the empty list if request-value is null), ordered by their weight,
    // highest to lowest, as per Section 5.3.2 of [RFC7231] (omitting any coding
    // with a weight of 0). If a type lacks an explicit weight, an
    // implementation MAY assign one.
    std::vector<WeightedValue> preferred_types =
        ParseRequestHeaderValue(request_header_value);

    // Step 3. For each preferred-type in preferred-types: [spec text]
    for (const WeightedValue& preferred_type : preferred_types) {
      // 3.1. If any member of available-values matches preferred-type, using
      // the media-range matching mechanism specified in Section 5.3.2 of
      // [RFC7231] (which is case-insensitive), append those members of
      // available-values to preferred-available (preserving the precedence
      // order implied by the media ranges' specificity).
      for (const std::string& available : available_values) {
        if (net::MatchesMimeType(preferred_type.value, available))
          preferred_available.push_back(available);
      }
    }

    // Step 4. If preferred-available is empty, append the first member of
    // available-values to preferred-available. This makes the first
    // available-value the default when none of the client's preferences are
    // available. [spec text]
    if (preferred_available.empty() && !available_values.empty())
      preferred_available.push_back(available_values[0]);

    // Step 5. Return preferred-available. [spec text]
    return preferred_available;
  }
};

// https://httpwg.org/http-extensions/draft-ietf-httpbis-variants.html#content-encoding
class AcceptEncodingNegotiation final : public ContentNegotiationAlgorithm {
  std::vector<std::string> run(
      base::span<const std::string> available_values,
      std::optional<std::string> request_header_value) override {
    // Step 1. Let preferred-available be an empty list. [spec text]
    std::vector<std::string> preferred_available;

    // Step 2. Let preferred-codings be a list of the codings in the
    // request-value (or the empty list if request-value is null), ordered by
    // their weight, highest to lowest, as per Section 5.3.1 of [RFC7231]
    // (omitting any coding with a weight of 0). If a coding lacks an explicit
    // weight, an implementation MAY assign one. [spec text]
    std::vector<WeightedValue> preferred_codings =
        ParseRequestHeaderValue(request_header_value);

    // Step 3. If "identity" is not a member of preferred-codings, append
    // "identity". [spec text]
    if (!base::Contains(preferred_codings, kIdentity, &WeightedValue::value)) {
      preferred_codings.push_back({kIdentity, 0.0});
    }

    // Step 4. Append "identity" to available-values. [spec text]
    // Instead, we explicitly check "identity" in Step 5.1 below.

    // Step 5. For each preferred-coding in preferred-codings: [spec text]
    for (const WeightedValue& preferred_coding : preferred_codings) {
      // Step 5.1. If there is a case-insensitive, character-for-character match
      // for preferred-coding in available-values, append that member of
      // available-values to preferred-available. [spec text]
      if (preferred_coding.value == kIdentity) {
        preferred_available.push_back(kIdentity);
        continue;
      }
      for (const std::string& available : available_values) {
        if (base::EqualsCaseInsensitiveASCII(preferred_coding.value,
                                             available)) {
          preferred_available.push_back(available);
          break;
        }
      }
    }

    // Step 6. Return preferred-available. [spec text]
    return preferred_available;
  }
};

// https://httpwg.org/http-extensions/draft-ietf-httpbis-variants.html#content-language
class AcceptLanguageNegotiation final : public ContentNegotiationAlgorithm {
 public:
  std::vector<std::string> run(
      base::span<const std::string> available_values,
      std::optional<std::string> request_header_value) override {
    // Step 1. Let preferred-available be an empty list. [spec text]
    std::vector<std::string> preferred_available;

    // Step 2. Let preferred-langs be a list of the language-ranges in the
    // request-value (or the empty list if request-value is null), ordered by
    // their weight, highest to lowest, as per Section 5.3.1 of [RFC7231]
    // (omitting any language-range with a weight of 0). If a language-range
    // lacks a weight, an implementation MAY assign one. [spec text]
    std::vector<WeightedValue> preferred_langs =
        ParseRequestHeaderValue(request_header_value);

    // Step 3. For each preferred-lang in preferred-langs: [spec text]
    for (const WeightedValue& preferred_lang : preferred_langs) {
      // Step 3.1. If any member of available-values matches preferred-lang,
      // using either the Basic or Extended Filtering scheme defined in
      // Section 3.3 of [RFC4647], append those members of available-values to
      // preferred-available (preserving their order). [spec text]
      AppendMatchedLanguages(available_values, preferred_lang.value,
                             &preferred_available);
    }

    // Step 4. If preferred-available is empty, append the first member of
    // available-values to preferred-available. This makes the first
    // available-value the default when none of the client's preferences are
    // available. [spec text]
    if (preferred_available.empty() && !available_values.empty())
      preferred_available.push_back(available_values[0]);

    // Step 5. Return preferred-available. [spec text]
    return preferred_available;
  }

 private:
  // Performs the Basic Filtering (Section 3.3.1 of [RFC4647]).
  void AppendMatchedLanguages(base::span<const std::string> available_values,
                              const std::string& preferred_lang,
                              std::vector<std::string>* output) {
    if (preferred_lang == "*") {
      base::ranges::copy(available_values, std::back_inserter(*output));
      return;
    }

    const std::string prefix = preferred_lang + '-';
    for (const std::string& available : available_values) {
      if (base::EqualsCaseInsensitiveASCII(preferred_lang, available) ||
          base::StartsWith(available, prefix,
                           base::CompareCase::INSENSITIVE_ASCII)) {
        output->push_back(available);
      }
    }
  }
};

std::unique_ptr<ContentNegotiationAlgorithm> GetContentNegotiationAlgorithm(
    const std::string& field_name) {
  if (field_name == "accept")
    return std::make_unique<ContentTypeNegotiation>();
  if (field_name == "accept-encoding")
    return std::make_unique<AcceptEncodingNegotiation>();
  if (field_name == "accept-language")
    return std::make_unique<AcceptLanguageNegotiation>();
  return nullptr;
}

// https://tools.ietf.org/id/draft-ietf-httpbis-variants-04.html#variants
std::optional<std::vector<std::pair<std::string, std::vector<std::string>>>>
ParseVariants(const std::string_view& str) {
  // Compatibility note: Draft 4 of Variants
  // (https://tools.ietf.org/id/draft-ietf-httpbis-variants-04.html#variants)
  // uses a custom format for the Variants-04 header, which this method attempts
  // to parse as a Structured Headers list-of-lists. This means that quoted
  // string values as well as unquoted tokens will be accepted by this parser,
  // which is strictly more lenient than the actual draft spec. Draft 5
  // (https://tools.ietf.org/id/draft-ietf-httpbis-variants-05.html#variants,
  // which we don't actually support yet) uses a Structured-Headers-Draft-9
  // list-of-lists syntax for the Variants-05 header, and explicitly allows both
  // strings and tokens.
  // TODO(iclelland): As of October 2019, the latest editor's draft of Variants
  // (https://httpwg.org/http-extensions/draft-ietf-httpbis-variants.html#variants)
  // specifies a Structured-Headers-Draft-13 dictionary for the Variants header.
  // Once the specs are updated, also parse the new Variants dictionary header
  // as well. The same data structure should be returned.
  std::optional<net::structured_headers::ListOfLists> parsed =
      net::structured_headers::ParseListOfLists(str);
  if (!parsed)
    return std::nullopt;
  std::vector<std::pair<std::string, std::vector<std::string>>> variants;
  // Each inner-list in the Variants header field value is parsed into a
  // variant-axis.  The first list-member of the inner-list is interpreted as
  // the field-name, and the remaining list-members are the available-values.
  // [spec text]
  for (const auto& inner_list : *parsed) {
    auto it = inner_list.begin();
    // Any list-member that is a token is interpreted as a string containing the
    // same characters.
    // [spec text]
    if (!it->is_string() && !it->is_token())
      return std::nullopt;
    std::string field_name = it->GetString();
    std::vector<std::string> available_values;
    available_values.reserve(inner_list.size() - 1);
    for (++it; it != inner_list.end(); ++it) {
      // Any list-member that is a token is interpreted as a string containing
      // the same characters.
      // [spec text]
      if (!it->is_string() && !it->is_token())
        return std::nullopt;
      available_values.push_back(it->GetString());
    }
    variants.push_back(std::make_pair(field_name, available_values));
  }
  return variants;
}

// https://tools.ietf.org/id/draft-ietf-httpbis-variants-04.html#variant-key
std::optional<std::vector<std::vector<std::string>>> ParseVariantKey(
    const std::string_view& str,
    size_t num_variant_axes) {
  // Compatibility note: Draft 4 of Variants
  // (https://tools.ietf.org/id/draft-ietf-httpbis-variants-04.html#variant-key)
  // uses a custom format for the Variant-Key-04 header, which this method
  // attempts to parse as a Structured Headers list-of-lists. This means that
  // quoted string values as well as unquoted tokens will be accepted by this
  // parser, which is strictly more lenient than the actual draft spec. Draft 5
  // (https://tools.ietf.org/id/draft-ietf-httpbis-variants-05.html#variant-key,
  // which we don't actually support yet) uses a Structured-Headers-Draft-9
  // list-of-lists syntax for the Variant-Key-05 header, and explicitly allows
  // both strings and tokens.
  // TODO(iclelland): Once the specs are updated, also parse the new
  // Variants-Key header as well. The same data structure should be returned.
  std::optional<net::structured_headers::ListOfLists> parsed =
      net::structured_headers::ParseListOfLists(str);
  if (!parsed)
    return std::nullopt;
  std::vector<std::vector<std::string>> variant_keys;
  variant_keys.reserve(parsed->size());
  // Each inner-list MUST have the same number of list-members as there are
  // variant-axes in the representation's Variants header field. Additionally,
  // every element of each inner-list must be a string. If not, the client MUST
  // treat the representation as having no Variant-Key header field.
  // [spec text]
  for (const auto& inner_list : *parsed) {
    std::vector<std::string> list_members;
    list_members.reserve(inner_list.size());
    if (inner_list.size() != num_variant_axes)
      return std::nullopt;
    for (const net::structured_headers::Item& item : inner_list) {
      if (!item.is_string() && !item.is_token())
        return std::nullopt;
      list_members.push_back(item.GetString());
    }
    variant_keys.push_back(list_members);
  }
  return variant_keys;
}

// Returns the index of matching entry in Possible Keys [1] which is the cross
// product of |sorted_variants|. If there is no matching entry returns nullopt.
// Example:
//   sorted_variants: [["image/webp","image/jpg"], ["en", "fr", "ja"]]
//   variant_key: ["image/jpg", "fr"]
//   Possible Keys list for this sorted_variants:
//     [["image/webp", "en"], ["image/webp", "fr"], ["image/webp", "ja"],
//      ["image/jpg", "en"], ["image/jpg", "fr"], ["image/jpg", "ja"]]
//   Result: 4
// [1] https://httpwg.org/http-extensions/draft-ietf-httpbis-variants.html#find
std::optional<size_t> GetPossibleKeysIndex(
    const std::vector<std::vector<std::string>>& sorted_variants,
    const std::vector<std::string>& variant_key) {
  DCHECK_EQ(variant_key.size(), sorted_variants.size());
  size_t index = 0;
  for (size_t i = 0; i < sorted_variants.size(); ++i) {
    auto found = base::ranges::find(sorted_variants[i], variant_key[i]);
    if (found == sorted_variants[i].end())
      return std::nullopt;

    index = index * sorted_variants[i].size() +
            (found - sorted_variants[i].begin());
  }
  return index;
}

}  // namespace

WebPackageRequestMatcher::WebPackageRequestMatcher(
    const net::HttpRequestHeaders& request_headers,
    const std::string& accept_langs)
    : request_headers_(request_headers) {
  request_headers_.SetHeaderIfMissing(
      net::HttpRequestHeaders::kAcceptLanguage,
      net::HttpUtil::GenerateAcceptLanguageHeader(
          net::HttpUtil::ExpandLanguageList(accept_langs)));
  // We accept only "mi-sha256-03" as the inner content encoding.
  // TODO(ksakamoto): Revisit once
  // https://github.com/WICG/webpackage/issues/390 is settled.
  request_headers_.SetHeader(net::HttpRequestHeaders::kAcceptEncoding,
                             "mi-sha256-03");
}

bool WebPackageRequestMatcher::MatchRequest(
    const HeaderMap& response_headers) const {
  return MatchRequest(request_headers_, response_headers);
}

std::vector<std::string>::const_iterator
WebPackageRequestMatcher::FindBestMatchingVariantKey(
    const std::string& variants,
    const std::vector<std::string>& variant_key_list) const {
  return FindBestMatchingVariantKey(request_headers_, variants,
                                    variant_key_list);
}

std::optional<size_t> WebPackageRequestMatcher::FindBestMatchingIndex(
    const std::string& variants) const {
  return FindBestMatchingIndex(request_headers_, variants);
}

// Implements "Cache Behaviour" [1] when "stored-responses" is a singleton list
// containing a response that has "Variants" header whose value is |variants|.
// [1] https://httpwg.org/http-extensions/draft-ietf-httpbis-variants.html#cache
std::vector<std::vector<std::string>> WebPackageRequestMatcher::CacheBehavior(
    const std::vector<std::pair<std::string, std::vector<std::string>>>&
        variants,
    const net::HttpRequestHeaders& request_headers) {
  // Step 1. If stored-responses is empty, return an empty list. [spec text]
  // The size of stored-responses is always 1.

  // Step 2. Order stored-responses by the "Date" header field, most recent to
  // least recent. [spec text]
  // This is no-op because stored-responses is a single-element list.

  // Step 3. Let sorted-variants be an empty list. [spec text]
  std::vector<std::vector<std::string>> sorted_variants;

  // Step 4. If the freshest member of stored-responses (as per [RFC7234],
  // Section 4.2) has one or more "Variants" header field(s) that successfully
  // parse according to Section 2: [spec text]

  // Step 4.1. Select one member of stored-responses with a "Variants" header
  // field-value(s) that successfully parses according to Section 2 and let
  // variants-header be this parsed value. This SHOULD be the most recent
  // response, but MAY be from an older one as long as it is still fresh.
  // [spec text]
  // |variants| is the parsed "Variants" header field value.

  // Step 4.2. For each variant-axis in variants-header: [spec text]
  for (const auto& variant_axis : variants) {
    // Step 4.2.1. If variant-axis' field-name corresponds to the request header
    // field identified by a content negotiation mechanism that the
    // implementation supports: [spec text]
    std::string field_name = base::ToLowerASCII(variant_axis.first);
    std::unique_ptr<ContentNegotiationAlgorithm> negotiation_algorithm =
        GetContentNegotiationAlgorithm(field_name);
    if (negotiation_algorithm) {
      // Step 4.2.1.1. Let request-value be the field-value associated with
      // field-name in incoming-request (after being combined as allowed by
      // Section 3.2.2 of [RFC7230]), or null if field-name is not in
      // incoming-request. [spec text]
      std::optional<std::string> request_value =
          request_headers.GetHeader(field_name);
      // Step 4.2.1.2. Let sorted-values be the result of running the algorithm
      // defined by the content negotiation mechanism with request-value and
      // variant-axis' available-values. [spec text]
      std::vector<std::string> sorted_values =
          negotiation_algorithm->run(variant_axis.second, request_value);

      // Step 4.2.1.3. Append sorted-values to sorted-variants. [spec text]
      sorted_variants.push_back(std::move(sorted_values));
    }
  }
  // At this point, sorted-variants will be a list of lists, each member of the
  // top-level list corresponding to a variant-axis in the Variants header
  // field-value, containing zero or more items indicating available-values
  // that are acceptable to the client, in order of preference, greatest to
  // least. [spec text]

  // Step 5. Return result of running Compute Possible Keys (Section 4.1) on
  // sorted-variants, an empty list and an empty list. [spec text]
  // Instead of computing the cross product of sorted_variants, this
  // implementation just returns sorted_variants.
  return sorted_variants;
}

// Implements step 3- of
// https://wicg.github.io/webpackage/loading.html#request-matching
bool WebPackageRequestMatcher::MatchRequest(
    const net::HttpRequestHeaders& request_headers,
    const HeaderMap& response_headers) {
  auto variants_found =
      response_headers.find(blink::kSignedExchangeVariantsHeader);
  auto variant_key_found =
      response_headers.find(blink::kSignedExchangeVariantKeyHeader);

  // Step 3. If storedExchange's response's header list contains:
  // - Neither a `Variants` nor a `Variant-Key` header
  //   Return "match". [spec text]
  if (variants_found == response_headers.end() &&
      variant_key_found == response_headers.end()) {
    return true;
  }
  // - A `Variant-Key` header but no `Variants` header
  //   Return "mismatch". [spec text]
  if (variants_found == response_headers.end())
    return false;
  // - A `Variants` header but no `Variant-Key` header
  //   Return "mismatch". [spec text]
  if (variant_key_found == response_headers.end())
    return false;
  // - Both a `Variants` and a `Variant-Key` header
  //   Proceed to the following steps. [spec text]

  // Step 4. If getting `Variants` from storedExchange's response's header list
  // returns a value that fails to parse according to the instructions for the
  // Variants Header Field, return "mismatch". [spec text]
  auto parsed_variants = ParseVariants(variants_found->second);
  if (!parsed_variants)
    return false;

  // Step 5. Let acceptableVariantKeys be the result of running the Variants
  // Cache Behavior on an incoming-request of browserRequest and
  // stored-responses of a list containing storedExchange's response.
  // [spec text]
  std::vector<std::vector<std::string>> sorted_variants =
      CacheBehavior(*parsed_variants, request_headers);

  // This happens when `Variant` has unknown field names. In such cases,
  // this algorithm never returns "match", so we do an early return.
  if (sorted_variants.size() != parsed_variants->size())
    return false;

  // Step 6. Let variantKeys be the result of getting `Variant-Key` from
  // storedExchange's response's header list, and parsing it into a list of
  // lists as described in Variant-Key Header Field. [spec text]
  auto parsed_variant_key =
      ParseVariantKey(variant_key_found->second, parsed_variants->size());

  // Step 7. If parsing variantKeys failed, return "mismatch". [spec text]
  if (!parsed_variant_key)
    return false;

  // Step 8. If the intersection of acceptableVariantKeys and variantKeys is
  // empty, return "mismatch". [spec text]
  // Step 9. Return "match". [spec text]

  // AcceptableVariantKeys is the cross product of sorted_variants. Instead of
  // computing AcceptableVariantKeys and taking the intersection of it and
  // variantKeys, we check its equivalent, i.e.: Return "match" if there is a vk
  // in variantKeys such that for all i, vk[i] is in sorted_variants[i].
  for (const std::vector<std::string>& vk : *parsed_variant_key) {
    DCHECK_EQ(vk.size(), sorted_variants.size());
    size_t i = 0;
    for (; i < sorted_variants.size(); ++i) {
      if (!base::Contains(sorted_variants[i], vk[i]))
        break;
    }
    if (i == sorted_variants.size())
      return true;
  }
  // Otherwise return "mismatch".
  return false;
}

// static
std::vector<std::string>::const_iterator
WebPackageRequestMatcher::FindBestMatchingVariantKey(
    const net::HttpRequestHeaders& request_headers,
    const std::string& variants,
    const std::vector<std::string>& variant_keys_list) {
  auto parsed_variants = ParseVariants(variants);
  if (!parsed_variants)
    return variant_keys_list.end();

  std::vector<std::vector<std::string>> sorted_variants =
      CacheBehavior(*parsed_variants, request_headers);
  // This happens when `Variant` has unknown field names. In such cases,
  // this algorithm never returns "match", so we do an early return.
  if (sorted_variants.size() != parsed_variants->size())
    return variant_keys_list.end();

  // Check that the combination count of Possible Keys doesn't overflow.
  // Currently we have only three ContentNegotiationAlgorithms, so it is
  // impossible to overflow. But we check to protect for future extension.
  size_t possible_keys_count = 1;
  for (const auto& key : sorted_variants) {
    if (!base::CheckMul(possible_keys_count, key.size())
             .AssignIfValid(&possible_keys_count)) {
      return variant_keys_list.end();
    }
  }

  size_t minimum_index = std::numeric_limits<size_t>::max();
  auto found_variant_key = variant_keys_list.end();

  for (auto variant_keys_list_it = variant_keys_list.begin();
       variant_keys_list_it < variant_keys_list.end(); ++variant_keys_list_it) {
    auto parsed_variant_keys =
        ParseVariantKey(*variant_keys_list_it, parsed_variants->size());
    if (!parsed_variant_keys)
      continue;
    for (const std::vector<std::string>& variant_key : *parsed_variant_keys) {
      auto maching_index = GetPossibleKeysIndex(sorted_variants, variant_key);
      if (maching_index.has_value() && *maching_index < minimum_index) {
        minimum_index = *maching_index;
        found_variant_key = variant_keys_list_it;
      }
    }
  }
  return found_variant_key;
}

// static
std::optional<size_t> WebPackageRequestMatcher::FindBestMatchingIndex(
    const net::HttpRequestHeaders& request_headers,
    const std::string& variants) {
  auto parsed_variants = ParseVariants(variants);
  if (!parsed_variants)
    return std::nullopt;

  size_t best_match_index = 0;
  for (const auto& variant_axis : *parsed_variants) {
    const std::string field_name = base::ToLowerASCII(variant_axis.first);
    std::unique_ptr<ContentNegotiationAlgorithm> negotiation_algorithm =
        GetContentNegotiationAlgorithm(field_name);
    if (!negotiation_algorithm)
      return std::nullopt;
    std::optional<std::string> request_value =
        request_headers.GetHeader(field_name);

    std::vector<std::string> sorted_values =
        negotiation_algorithm->run(variant_axis.second, request_value);
    if (sorted_values.empty())
      return std::nullopt;
    auto it = base::ranges::find(variant_axis.second, sorted_values.front());
    if (it == variant_axis.second.end())
      return std::nullopt;
    size_t best_value_index = it - variant_axis.second.begin();

    if (!base::CheckMul(best_match_index, variant_axis.second.size())
             .AssignIfValid(&best_match_index)) {
      return std::nullopt;
    }
    if (!base::CheckAdd(best_match_index, best_value_index)
             .AssignIfValid(&best_match_index)) {
      return std::nullopt;
    }
  }
  return best_match_index;
}

}  // namespace blink

"""

```