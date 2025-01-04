Response:
Let's break down the thought process for analyzing this C++ code related to Subresource Integrity (SRI).

**1. Initial Understanding & Keyword Identification:**

* **Goal:** Understand the functionality of `subresource_integrity.cc`.
* **Keywords:**  `SubresourceIntegrity`, `integrity`, `hash`, `digest`, `algorithm`, `metadata`, `CORS`, `base64`, `javascript`, `html`, `css`. These words immediately point to the core purpose of the code.

**2. High-Level Functionality Identification (Skimming and Structure):**

* The `#include` statements reveal dependencies: `WebCrypto`, `Resource`, `KURL`, `SecurityOrigin`, `Base64`. This indicates involvement in cryptographic operations, network requests, URLs, and security considerations.
* The namespace `blink` confirms this is part of the Chromium rendering engine.
* The class `SubresourceIntegrity` and its methods (`CheckSubresourceIntegrity`, `ParseIntegrityAttribute`, etc.) are central.
* There's a `ReportInfo` struct, suggesting a mechanism for logging or reporting SRI-related events.

**3. Core Functionality - Deciphering the Methods:**

* **`CheckSubresourceIntegrity` (multiple overloads):**  This is the core verification logic. It takes integrity metadata (likely from an HTML attribute) and the actual content of the resource, compares them, and returns a boolean indicating success or failure. The presence of `Resource` and `KURL` in the parameters confirms it's dealing with fetched resources. The overload accepting a string suggests parsing of the `integrity` attribute. The overload with a `SegmentedBuffer` suggests it works directly with the downloaded content.
* **`ParseIntegrityAttribute`:** This method is responsible for taking the string value of the `integrity` attribute from HTML and breaking it down into usable components (algorithm and digest). The logic involving `SkipToken`, `SkipUntil`, and the regular expression-like checks (e.g., `IsIntegrityCharacter`) indicates string parsing. The handling of `AlgorithmParseResult` further confirms this.
* **`CheckSubresourceIntegrityImpl`:** Likely a shared implementation detail between the different `CheckSubresourceIntegrity` overloads. It handles the core comparison logic after the metadata is parsed.
* **`FindBestAlgorithm`:**  SRI allows specifying multiple algorithms. This function determines the "strongest" algorithm to use for verification.
* **`CheckSubresourceIntegrityDigest`:**  Performs the actual cryptographic hash comparison between the calculated digest of the downloaded resource and the digest specified in the `integrity` attribute.
* **`IntegrityAlgorithmToString`, `IntegrityAlgorithmToHashAlgorithm`:** Utility functions for converting between the internal `IntegrityAlgorithm` enum and string representations or `blink::HashAlgorithm` values used by the crypto library.
* **`ParseAttributeAlgorithm`, `ParseAlgorithmPrefix`:**  Specifically handles parsing the algorithm part of the integrity string (e.g., "sha256").
* **`ParseDigest`:** Extracts and normalizes the base64-encoded digest from the integrity string.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **HTML:**  The most direct connection. The `integrity` attribute is an HTML attribute. This code is directly responsible for processing it.
* **JavaScript:** JavaScript interacts with fetched resources. SRI ensures that scripts (and other resources) fetched via JavaScript APIs (like `fetch`) haven't been tampered with. The `Resource` parameter hints at this integration.
* **CSS:** CSS files can also be integrity-protected using the `integrity` attribute on `<link>` elements. This code handles the verification for these resources as well.

**5. Logical Reasoning and Examples (Hypothetical Input/Output):**

* **Parsing:** Imagine the input `integrity="sha256-abcdefg sha384-hijklmnop"`. The parser would need to split this, identify "sha256" and "sha384" as algorithms, and "abcdefg" and "hijklmnop" as digests. The output would be a data structure (likely `IntegrityMetadataSet`) containing this information.
* **Verification:**  If the parsed metadata contains `sha256-abcdefg` and the downloaded resource's SHA-256 hash matches the decoded "abcdefg", the verification succeeds. Otherwise, it fails. Consider the CORS requirement – if the `crossorigin` attribute is missing or incorrectly set, the check would fail.

**6. Common Usage Errors:**

* **Incorrect Digests:**  The most common error. Typos in the base64-encoded digest will cause verification failures.
* **Mismatched Algorithms:** Specifying "sha256" in the `integrity` attribute but providing a SHA-384 digest.
* **CORS Issues:** For cross-origin resources, forgetting the `crossorigin` attribute or setting it incorrectly will prevent SRI from working.
* **Incorrect Base64 Encoding:** Providing a non-base64 string as the digest.

**7. Review and Refinement:**

* Reread the code and comments to ensure a thorough understanding. The comments often provide valuable context.
* Check for edge cases or potential ambiguities. For example, how does the code handle multiple integrity values?  The "strongest" algorithm logic answers this.
* Ensure the explanation is clear, concise, and addresses all parts of the prompt.

This methodical approach, combining code inspection with knowledge of web technologies and potential usage scenarios, allows for a comprehensive understanding of the `subresource_integrity.cc` file.这个 C++ 源代码文件 `subresource_integrity.cc` 是 Chromium Blink 引擎的一部分，它的主要功能是 **实现和处理子资源完整性 (Subresource Integrity, SRI)**。

SRI 是一种安全特性，允许浏览器验证从 CDN 或其他来源加载的资源（例如 JavaScript、CSS 文件）是否被篡改。它通过比较资源下载后的哈希值与 HTML 元素（`<script>` 或 `<link>`） `integrity` 属性中提供的哈希值来实现这一点。

以下是该文件功能的详细列举：

**核心功能：**

1. **解析 `integrity` 属性：**
   - `ParseIntegrityAttribute` 函数负责解析 HTML 元素（`<script>`, `<link>` 等）的 `integrity` 属性值。
   - `integrity` 属性可以包含一个或多个由空格分隔的哈希值，每个哈希值都与特定的加密算法关联（例如 `sha256-`, `sha384-`, `sha512-`）。
   - 该函数会提取算法名称和对应的 base64 编码的摘要值。
   - **与 HTML 的关系：**  直接处理 HTML 属性。例如，解析 `<script src="https://example.com/script.js" integrity="sha256-abcdefg...">` 中的 `integrity` 属性。

2. **计算下载资源的哈希值：**
   - `CheckSubresourceIntegrityDigest` 函数使用指定的加密算法（从 `integrity` 属性中解析得到）计算下载资源的实际哈希值。
   - 它使用 Blink 提供的加密 API (`blink::Crypto` 和 `blink::WebCrypto`) 来完成哈希计算。

3. **比较哈希值：**
   - `CheckSubresourceIntegrityImpl` 函数比较从 `integrity` 属性解析出的哈希值和下载资源的实际哈希值。
   - 如果两者匹配，则认为资源是完整的，可以被使用。
   - 如果不匹配，则浏览器会阻止该资源的执行或应用，并可能在控制台中输出错误信息。

4. **处理跨域 (CORS) 情况：**
   - `CheckSubresourceIntegrity` 函数会检查资源是否是跨域请求。
   - **与 HTML 的关系：** 只有当跨域资源设置了正确的 CORS 头 (`Access-Control-Allow-Origin`) 时，SRI 才能正常工作。如果缺少 CORS 头，即使哈希值匹配，SRI 也会阻止资源，因为浏览器无法安全地检查其完整性。
   - **示例：** 如果 `<script src="https://other-domain.com/script.js" integrity="sha256-xyz...">` 加载的资源没有 `Access-Control-Allow-Origin: *` 或 `Access-Control-Allow-Origin: your-domain.com` 头，SRI 校验会失败。

5. **选择最佳哈希算法：**
   - `FindBestAlgorithm` 函数用于在 `integrity` 属性中指定了多个哈希值时，选择最强的受支持的哈希算法进行校验。

6. **报告错误信息：**
   - `ReportInfo` 结构体用于存储 SRI 校验的结果，包括是否成功以及任何错误消息。
   - 错误消息会输出到浏览器的开发者控制台，帮助开发者诊断 SRI 相关的问题。

7. **使用计数：**
   - 记录 SRI 功能的使用情况，例如 `ReportInfo::UseCounterFeature::kSRIElementWithMatchingIntegrityAttribute`。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:** `integrity` 属性直接在 HTML 的 `<script>` 和 `<link>` 标签中使用，用于指定资源的预期哈希值。
   ```html
   <script src="https://cdn.example.com/script.js" integrity="sha384-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"></script>
   <link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha512-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"></link>
   ```

* **JavaScript:** 虽然这个文件本身是 C++ 代码，但 SRI 保护的正是通过 JavaScript 加载的资源。如果通过 JavaScript 动态创建 `<script>` 标签并设置 `integrity` 属性，这个文件中的代码也会被调用来验证下载的脚本。

* **CSS:**  类似于 JavaScript，SRI 可以用于保护通过 `<link>` 标签加载的 CSS 文件，确保样式表没有被恶意修改。

**逻辑推理的假设输入与输出：**

**假设输入：**

1. **`integrity` 属性值：** `"sha256-abcdefg"`
2. **下载资源的哈希值 (SHA-256)：** `abcdefg` (解码后的 base64)

**输出：**

* `CheckSubresourceIntegrityDigest` 函数返回 `true` (哈希值匹配)。
* 浏览器允许加载和执行该资源。

**假设输入：**

1. **`integrity` 属性值：** `"sha256-hijklmn"`
2. **下载资源的哈希值 (SHA-256)：** `abcdefg` (解码后的 base64)

**输出：**

* `CheckSubresourceIntegrityDigest` 函数返回 `false` (哈希值不匹配)。
* 浏览器会阻止加载或执行该资源。
* 开发者控制台会输出类似 "Failed to find a valid digest in the 'integrity' attribute..." 的错误消息。

**用户或编程常见的使用错误举例：**

1. **`integrity` 属性值错误：**
   - **错误示例：** `<script src="script.js" integrity="sha256-xyz"` (哈希值不完整或错误)。
   - **结果：** SRI 校验失败，资源被阻止。
   - **控制台错误：** "Error parsing 'integrity' attribute..."

2. **使用了错误的哈希算法：**
   - **错误示例：** `<script src="script.js" integrity="sha256-abcdefg"`，但实际生成的是 SHA-384 的哈希值。
   - **结果：** SRI 校验失败，资源被阻止。
   - **控制台错误：** "Failed to find a valid digest in the 'integrity' attribute..." (会显示计算出的哈希值，方便开发者对比)。

3. **跨域资源缺少 CORS 头：**
   - **错误示例：**  `<script src="https://other-domain.com/script.js" integrity="sha256-xyz">`，但 `https://other-domain.com/script.js` 的响应头中缺少 `Access-Control-Allow-Origin`。
   - **结果：** SRI 校验失败，资源被阻止。
   - **控制台错误：** "Subresource Integrity: The resource ... has an integrity attribute, but the resource requires the request to be CORS enabled to check the integrity..."

4. **修改了资源但未更新 `integrity` 属性：**
   - **错误示例：**  开发者修改了 `script.js` 文件，但忘记重新生成并更新 HTML 中 `integrity` 属性的值。
   - **结果：** SRI 校验失败，资源被阻止。
   - **控制台错误：** "Failed to find a valid digest in the 'integrity' attribute..."

5. **使用了浏览器不支持的哈希算法：**
   - 虽然当前主流浏览器都支持 `sha256`, `sha384`, `sha512`，但如果使用了不标准的算法，SRI 将无法工作。
   - **控制台错误：**  可能显示 "The specified hash algorithm must be one of ..."

总而言之，`subresource_integrity.cc` 文件是 Blink 引擎中实现 SRI 这一关键安全特性的核心组件，它负责解析、计算和比较哈希值，以确保网页加载的资源没有被恶意篡改，从而提高 Web 应用的安全性。

Prompt: 
```
这是目录为blink/renderer/platform/loader/subresource_integrity.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"

#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/public/platform/web_crypto.h"
#include "third_party/blink/public/platform/web_crypto_algorithm.h"
#include "third_party/blink/renderer/platform/crypto.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/parsing_utilities.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

// FIXME: This should probably use common functions with ContentSecurityPolicy.
static bool IsIntegrityCharacter(UChar c) {
  // Check if it's a base64 encoded value. We're pretty loose here, as there's
  // not much risk in it, and it'll make it simpler for developers.
  return IsASCIIAlphanumeric(c) || c == '_' || c == '-' || c == '+' ||
         c == '/' || c == '=';
}

static bool IsValueCharacter(UChar c) {
  // VCHAR per https://tools.ietf.org/html/rfc5234#appendix-B.1
  return c >= 0x21 && c <= 0x7e;
}

static bool DigestsEqual(const DigestValue& digest1,
                         const DigestValue& digest2) {
  return digest1 == digest2;
}

void SubresourceIntegrity::ReportInfo::AddUseCount(UseCounterFeature feature) {
  use_counts_.push_back(feature);
}

void SubresourceIntegrity::ReportInfo::AddConsoleErrorMessage(
    const String& message) {
  console_error_messages_.push_back(message);
}

void SubresourceIntegrity::ReportInfo::Clear() {
  use_counts_.clear();
  console_error_messages_.clear();
}

bool SubresourceIntegrity::CheckSubresourceIntegrity(
    const IntegrityMetadataSet& metadata_set,
    const SegmentedBuffer* buffer,
    const KURL& resource_url,
    const Resource& resource,
    ReportInfo& report_info) {
  // FetchResponseType::kError never arrives because it is a loading error.
  DCHECK_NE(resource.GetResponse().GetType(),
            network::mojom::FetchResponseType::kError);
  if (!resource.GetResponse().IsCorsSameOrigin()) {
    report_info.AddConsoleErrorMessage(
        "Subresource Integrity: The resource '" + resource_url.ElidedString() +
        "' has an integrity attribute, but the resource "
        "requires the request to be CORS enabled to check "
        "the integrity, and it is not. The resource has been "
        "blocked because the integrity cannot be enforced.");
    report_info.AddUseCount(ReportInfo::UseCounterFeature::
                                kSRIElementIntegrityAttributeButIneligible);
    return false;
  }

  return CheckSubresourceIntegrityImpl(metadata_set, buffer, resource_url,
                                       report_info);
}

bool SubresourceIntegrity::CheckSubresourceIntegrity(
    const String& integrity_metadata,
    IntegrityFeatures features,
    const SegmentedBuffer* buffer,
    const KURL& resource_url,
    ReportInfo& report_info) {
  if (integrity_metadata.empty())
    return true;

  IntegrityMetadataSet metadata_set;
  ParseIntegrityAttribute(integrity_metadata, features, metadata_set,
                          &report_info);
  return CheckSubresourceIntegrityImpl(metadata_set, buffer, resource_url,
                                       report_info);
}

String IntegrityAlgorithmToString(IntegrityAlgorithm algorithm) {
  switch (algorithm) {
    case IntegrityAlgorithm::kSha256:
      return "SHA-256";
    case IntegrityAlgorithm::kSha384:
      return "SHA-384";
    case IntegrityAlgorithm::kSha512:
      return "SHA-512";
  }
  NOTREACHED();
}

blink::HashAlgorithm IntegrityAlgorithmToHashAlgorithm(
    IntegrityAlgorithm algorithm) {
  switch (algorithm) {
    case IntegrityAlgorithm::kSha256:
      return kHashAlgorithmSha256;
    case IntegrityAlgorithm::kSha384:
      return kHashAlgorithmSha384;
    case IntegrityAlgorithm::kSha512:
      return kHashAlgorithmSha512;
  }
  NOTREACHED();
}

bool SubresourceIntegrity::CheckSubresourceIntegrityImpl(
    const IntegrityMetadataSet& metadata_set,
    const SegmentedBuffer* buffer,
    const KURL& resource_url,
    ReportInfo& report_info) {
  if (!metadata_set.size())
    return true;

  // Check any of the "strongest" integrity constraints.
  IntegrityAlgorithm max_algorithm = FindBestAlgorithm(metadata_set);
  for (const IntegrityMetadata& metadata : metadata_set) {
    if (metadata.Algorithm() == max_algorithm &&
        CheckSubresourceIntegrityDigest(metadata, buffer)) {
      report_info.AddUseCount(ReportInfo::UseCounterFeature::
                                  kSRIElementWithMatchingIntegrityAttribute);
      return true;
    }
  }

  // If we arrive here, none of the "strongest" constaints have validated
  // the data we received. Report this fact.
  DigestValue digest;
  if (ComputeDigest(IntegrityAlgorithmToHashAlgorithm(max_algorithm), buffer,
                    digest)) {
    // This message exposes the digest of the resource to the console.
    // Because this is only to the console, that's okay for now, but we
    // need to be very careful not to expose this in exceptions or
    // JavaScript, otherwise it risks exposing information about the
    // resource cross-origin.
    report_info.AddConsoleErrorMessage(
        "Failed to find a valid digest in the 'integrity' attribute for "
        "resource '" +
        resource_url.ElidedString() + "' with computed " +
        IntegrityAlgorithmToString(max_algorithm) + " integrity '" +
        Base64Encode(digest) + "'. The resource has been blocked.");
  } else {
    report_info.AddConsoleErrorMessage(
        "There was an error computing an integrity value for resource '" +
        resource_url.ElidedString() + "'. The resource has been blocked.");
  }
  report_info.AddUseCount(ReportInfo::UseCounterFeature::
                              kSRIElementWithNonMatchingIntegrityAttribute);
  return false;
}

IntegrityAlgorithm SubresourceIntegrity::FindBestAlgorithm(
    const IntegrityMetadataSet& metadata_set) {
  // Find the "strongest" algorithm in the set. (This relies on
  // IntegrityAlgorithm declaration order matching the "strongest" order, so
  // make the compiler check this assumption first.)
  static_assert(IntegrityAlgorithm::kSha256 < IntegrityAlgorithm::kSha384 &&
                    IntegrityAlgorithm::kSha384 < IntegrityAlgorithm::kSha512,
                "IntegrityAlgorithm enum order should match the priority "
                "of the integrity algorithms.");

  // metadata_set is non-empty, so we are guaranteed to always have a result.
  // This is effectively an implementation of std::max_element (C++17).
  DCHECK(!metadata_set.empty());
  auto iter = metadata_set.begin();
  IntegrityAlgorithm max_algorithm = iter->second;
  ++iter;
  for (; iter != metadata_set.end(); ++iter) {
    max_algorithm = std::max(iter->second, max_algorithm);
  }
  return max_algorithm;
}

bool SubresourceIntegrity::CheckSubresourceIntegrityDigest(
    const IntegrityMetadata& metadata,
    const SegmentedBuffer* buffer) {
  blink::HashAlgorithm hash_algo =
      IntegrityAlgorithmToHashAlgorithm(metadata.Algorithm());

  DigestValue digest;
  if (!ComputeDigest(hash_algo, buffer, digest)) {
    return false;
  }

  Vector<char> hash_vector;
  Base64Decode(metadata.Digest(), hash_vector);
  DigestValue converted_hash_vector;
  converted_hash_vector.AppendSpan(base::as_byte_span(hash_vector));
  return DigestsEqual(digest, converted_hash_vector);
}

SubresourceIntegrity::AlgorithmParseResult
SubresourceIntegrity::ParseAttributeAlgorithm(const UChar*& begin,
                                              const UChar* end,
                                              IntegrityFeatures features,
                                              IntegrityAlgorithm& algorithm) {
  static const AlgorithmPrefixPair kPrefixes[] = {
      {"sha256", IntegrityAlgorithm::kSha256},
      {"sha-256", IntegrityAlgorithm::kSha256},
      {"sha384", IntegrityAlgorithm::kSha384},
      {"sha-384", IntegrityAlgorithm::kSha384},
      {"sha512", IntegrityAlgorithm::kSha512},
      {"sha-512", IntegrityAlgorithm::kSha512}};

  // The last algorithm prefix is the ed25519 signature algorithm, which should
  // only be enabled if kSignatures is requested. We'll implement this by
  // adjusting the last_prefix index into the array.
  size_t last_prefix = std::size(kPrefixes);
  if (features != IntegrityFeatures::kSignatures)
    last_prefix--;

  return ParseAlgorithmPrefix(begin, end, kPrefixes, last_prefix, algorithm);
}

SubresourceIntegrity::AlgorithmParseResult
SubresourceIntegrity::ParseAlgorithmPrefix(
    const UChar*& string_position,
    const UChar* string_end,
    const AlgorithmPrefixPair* prefix_table,
    size_t prefix_table_size,
    IntegrityAlgorithm& algorithm) {
  for (size_t i = 0; i < prefix_table_size; i++) {
    const UChar* pos = string_position;
    if (SkipToken<UChar>(pos, string_end, prefix_table[i].first) &&
        SkipExactly<UChar>(pos, string_end, '-')) {
      string_position = pos;
      algorithm = prefix_table[i].second;
      return kAlgorithmValid;
    }
  }

  const UChar* dash_position = string_position;
  SkipUntil<UChar>(dash_position, string_end, '-');
  return dash_position < string_end ? kAlgorithmUnknown : kAlgorithmUnparsable;
}

// Before:
//
// [algorithm]-[hash]      OR     [algorithm]-[hash]?[options]
//             ^     ^                        ^               ^
//      position   end                 position             end
//
// After (if successful: if the method returns false, we make no promises and
// the caller should exit early):
//
// [algorithm]-[hash]      OR     [algorithm]-[hash]?[options]
//                   ^                              ^         ^
//        position/end                       position       end
bool SubresourceIntegrity::ParseDigest(const UChar*& position,
                                       const UChar* end,
                                       String& digest) {
  base::span<const UChar> input_span(position, end);
  SkipWhile<UChar, IsIntegrityCharacter>(position, end);
  if (position == input_span.data() || (position != end && *position != '?')) {
    digest = g_empty_string;
    return false;
  }

  // We accept base64url encoding, but normalize to "normal" base64 internally:
  digest = NormalizeToBase64(String(
      input_span.first(static_cast<wtf_size_t>(position - input_span.data()))));
  return true;
}

void SubresourceIntegrity::ParseIntegrityAttribute(
    const WTF::String& attribute,
    IntegrityFeatures features,
    IntegrityMetadataSet& metadata_set) {
  return ParseIntegrityAttribute(attribute, features, metadata_set, nullptr);
}

void SubresourceIntegrity::ParseIntegrityAttribute(
    const WTF::String& attribute,
    IntegrityFeatures features,
    IntegrityMetadataSet& metadata_set,
    ReportInfo* report_info) {
  // We expect a "clean" metadata_set, since metadata_set should only be filled
  // once.
  DCHECK(metadata_set.empty());

  Vector<UChar> characters;
  attribute.StripWhiteSpace().AppendTo(characters);
  const UChar* position = characters.data();
  const UChar* end = characters.data() + characters.size();
  const UChar* current_integrity_end;

  // The integrity attribute takes the form:
  //    *WSP hash-with-options *( 1*WSP hash-with-options ) *WSP / *WSP
  // To parse this, break on whitespace, parsing each algorithm/digest/option
  // in order.
  while (position < end) {
    WTF::String digest;
    IntegrityAlgorithm algorithm;

    SkipWhile<UChar, IsASCIISpace>(position, end);
    current_integrity_end = position;
    SkipUntil<UChar, IsASCIISpace>(current_integrity_end, end);

    // Algorithm parsing errors are non-fatal (the subresource should
    // still be loaded) because strong hash algorithms should be used
    // without fear of breaking older user agents that don't support
    // them.
    AlgorithmParseResult parse_result = ParseAttributeAlgorithm(
        position, current_integrity_end, features, algorithm);
    if (parse_result == kAlgorithmUnknown) {
      // Unknown hash algorithms are treated as if they're not present,
      // and thus are not marked as an error, they're just skipped.
      SkipUntil<UChar, IsASCIISpace>(position, end);
      if (report_info) {
        report_info->AddConsoleErrorMessage(
            "Error parsing 'integrity' attribute ('" + attribute +
            "'). The specified hash algorithm must be one of "
            "'sha256', 'sha384', or 'sha512'.");
        report_info->AddUseCount(
            ReportInfo::UseCounterFeature::
                kSRIElementWithUnparsableIntegrityAttribute);
      }
      continue;
    }

    if (parse_result == kAlgorithmUnparsable) {
      SkipUntil<UChar, IsASCIISpace>(position, end);
      if (report_info) {
        report_info->AddConsoleErrorMessage(
            "Error parsing 'integrity' attribute ('" + attribute +
            "'). The hash algorithm must be one of 'sha256', "
            "'sha384', or 'sha512', followed by a '-' "
            "character.");
        report_info->AddUseCount(
            ReportInfo::UseCounterFeature::
                kSRIElementWithUnparsableIntegrityAttribute);
      }
      continue;
    }

    DCHECK_EQ(parse_result, kAlgorithmValid);

    if (!ParseDigest(position, current_integrity_end, digest)) {
      SkipUntil<UChar, IsASCIISpace>(position, end);
      if (report_info) {
        report_info->AddConsoleErrorMessage(
            "Error parsing 'integrity' attribute ('" + attribute +
            "'). The digest must be a valid, base64-encoded value.");
        report_info->AddUseCount(
            ReportInfo::UseCounterFeature::
                kSRIElementWithUnparsableIntegrityAttribute);
      }
      continue;
    }

    // The spec defines a space in the syntax for options, separated by a
    // '?' character followed by unbounded VCHARs, but no actual options
    // have been defined yet. Thus, for forward compatibility, ignore any
    // options specified.
    if (SkipExactly<UChar>(position, end, '?')) {
      base::span<const UChar> input_span(position, end);
      SkipWhile<UChar, IsValueCharacter>(position, end);
      if (input_span.data() != position && report_info) {
        report_info->AddConsoleErrorMessage(
            "Ignoring unrecogized 'integrity' attribute option '" +
            String(input_span.first(
                static_cast<wtf_size_t>(position - input_span.data()))) +
            "'.");
      }
    }

    IntegrityMetadata integrity_metadata(digest, algorithm);
    metadata_set.insert(integrity_metadata.ToPair());
  }
}

}  // namespace blink

"""

```