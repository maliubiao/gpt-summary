Response:
The user wants a summary of the functionalities of the `http_parsers.cc` file in the Chromium Blink engine, based on the provided code snippet.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name `http_parsers.cc` strongly suggests its primary function is parsing HTTP-related data. The included headers like `net/http/http_response_headers.h` and the namespace `network::mojom` further confirm this.

2. **Analyze Included Headers:** Examine the included headers for clues about specific parsing tasks.
    * `net/http/http_content_disposition.h`: Parsing `Content-Disposition` headers.
    * `net/http/http_response_headers.h`:  General HTTP response header parsing.
    * `services/network/public/cpp/content_security_policy/content_security_policy.h`: Parsing `Content-Security-Policy` headers.
    * `services/network/public/cpp/timing_allow_origin_parser.h`: Parsing `Timing-Allow-Origin` headers.
    * `third_party/blink/public/common/mime_util/mime_util.h`: Working with MIME types.
    * `third_party/blink/renderer/platform/network/header_field_tokenizer.h`:  Tokenizing header fields.
    * `third_party/blink/renderer/platform/network/http_names.h`:  Constants for HTTP header names.
    * `third_party/blink/renderer/platform/wtf/text/parsing_utilities.h`:  General text parsing utilities.
    * `third_party/blink/renderer/platform/wtf/text/string_builder.h`: Building strings.

3. **Examine the Code Structure:**
    * **Namespace `network::mojom`:**  Contains conversion functions `ConvertToBlink`. This indicates the file is involved in translating network data structures (likely from the network service process) into Blink's internal representations. The various `ConvertToBlink` overloads for different header types (CSP, Link, Timing-Allow-Origin, etc.) highlight the file's role in parsing and structuring this information.
    * **Helper Functions:** Look for standalone functions that perform specific parsing tasks. Examples include `ParseHTTPRefresh`, `ParseDate`, `ExtractMIMETypeFromMediaType`, `ParseContentTypeOptionsHeader`, `ParseCacheHeader`, `ParseCacheControlDirectives`, `ParseCommaDelimitedHeader`, `ParseMultipartHeadersFromBody`, `ParseMultipartFormHeadersFromBody`. These functions directly implement the parsing logic for various HTTP header fields and related data.
    * **Utility Functions:** Identify functions that provide general utility, such as `IsValidHTTPHeaderValue`, `IsValidHTTPToken`, `IsContentDispositionAttachment`, `IsWhitespace`, `SkipWhiteSpace`, `TrimToNextSeparator`, `MinimizedMIMEType`.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** Think about how HTTP headers influence these technologies:
    * **JavaScript:** `Content-Security-Policy` directly affects the execution of JavaScript. `Timing-Allow-Origin` controls which origins can measure resource loading times. MIME types determine how the browser handles JavaScript files.
    * **HTML:** The `Refresh` header can trigger redirects. `Content-Disposition` influences how the browser handles downloads. `Content-Type` is crucial for interpreting HTML content. `Link` headers can preload or prefetch resources. CSP impacts what resources can be loaded.
    * **CSS:** Similar to JavaScript, `Content-Security-Policy` restricts CSS loading. MIME types are important for interpreting CSS files. `Link` headers can load stylesheets.

5. **Consider Logic and Assumptions:**  Analyze functions with conditional logic and parameter handling. For example, `ParseHTTPRefresh` has different parsing paths depending on whether a URL is present. `ParseCacheControlDirectives` handles multiple directives. Think of plausible inputs and the expected outputs.

6. **Identify Potential User/Programming Errors:** Look for places where incorrect header values could lead to issues. Examples include malformed dates, invalid MIME types, incorrect `Content-Security-Policy` syntax, or misuse of the `Refresh` header.

7. **Structure the Summary:** Organize the findings into logical categories:
    * Core Functionality
    * Relationship to Web Technologies (with examples)
    * Logical Inference (with input/output examples)
    * Common Errors (with examples)
    * Overall Function (the requested summarization)

8. **Refine and Elaborate:** Flesh out the descriptions with more details based on the code analysis. Use clear and concise language.

**(Self-Correction during the process):**

* Initially, I might have focused too much on the `ConvertToBlink` functions. It's important to recognize that while these are crucial for internal data representation, the *parsing* logic resides in the other functions.
* I needed to ensure the examples for JavaScript, HTML, and CSS were specific and directly related to the parsing functions in the code.
* The "Logical Inference" section needs concrete examples to be understandable, not just a general description.
* For "Common Errors," providing *specific* examples of incorrect header syntax makes the explanation more impactful.

By following this structured approach, combining code analysis with knowledge of web technologies and potential issues, a comprehensive and accurate summary can be generated.
这是对 `blink/renderer/platform/network/http_parsers.cc` 文件（第一部分）的功能进行归纳的总结。根据提供的代码片段，这个文件的主要功能是**解析各种 HTTP 头部字段（headers）的值，并将这些解析后的信息转换为 Blink 引擎内部使用的数据结构**。

更具体地说，它做了以下事情：

**核心功能：HTTP 头部解析**

* **通用的 HTTP 头部处理:**
    * 提供了验证 HTTP 头部值 (`IsValidHTTPHeaderValue`) 和 token (`IsValidHTTPToken`) 的函数。
    * 实现了从媒体类型字符串中提取 MIME 类型 (`ExtractMIMETypeFromMediaType`)。
    * 提供了最小化 MIME 类型的函数，用于规范化常见的类型 (`MinimizedMIMEType`)。
    * 提供了通用的逗号分隔的头部解析 (`ParseCommaDelimitedHeader`)。

* **特定 HTTP 头部的解析:**
    * **`Refresh` 头部:**  解析 `Refresh` 头部的值，提取延迟时间和 URL (`ParseHTTPRefresh`)。
    * **`Content-Disposition` 头部:** 判断 `Content-Disposition` 头部是否指示附件下载 (`IsContentDispositionAttachment`)。
    * **日期头部:** 解析各种格式的日期字符串为 `base::Time` 对象 (`ParseDate`)。
    * **`Content-Type-Options` 头部:** 解析 `X-Content-Type-Options` 头部，判断是否包含 `nosniff` 指令 (`ParseContentTypeOptionsHeader`)。
    * **缓存控制头部 (`Cache-Control`, `Pragma`):** 解析 `Cache-Control` 和 `Pragma` 头部，提取缓存相关的指令，如 `no-cache`, `no-store`, `max-age` 等 (`ParseCacheControlDirectives`, `ParseCacheHeader`)。
    * **Multipart 响应头部:** 解析 multipart 响应体中的头部信息 (`ParseMultipartHeadersFromBody`, `ParseMultipartFormHeadersFromBody`)。

* **将网络层数据转换为 Blink 数据结构:**
    * 使用 `network::mojom` 命名空间下的 `ConvertToBlink` 函数，将来自网络层的 Mojo 数据结构（例如 `CSPSourcePtr`, `ContentSecurityPolicyPtr`, `LinkHeaderPtr` 等）转换为 Blink 引擎内部使用的对应结构（例如 `blink::CSPSourcePtr`, `blink::ContentSecurityPolicyPtr`, `blink::LinkHeaderPtr`）。这涉及各种类型转换，包括基本类型、字符串、URL、枚举、以及复杂的结构体。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    * **`Content-Security-Policy` (CSP) 头部解析:** 文件中存在大量解析 CSP 相关头部的代码 (`ConvertToBlink` 函数涉及到 `CSPSourcePtr`, `CSPDirectiveName`, `ContentSecurityPolicyPtr` 等)。浏览器会根据解析后的 CSP 策略来限制 JavaScript 的执行，例如禁止执行内联脚本，限制可以加载的脚本来源等。
        * **假设输入:**  HTTP 响应头包含 `Content-Security-Policy: script-src 'self' https://example.com;`
        * **输出:**  `ConvertToBlink` 函数会将其解析为一个 `blink::ContentSecurityPolicyPtr` 对象，其中 `script-src` 指令对应的值是包含 `'self'` 和 `https://example.com` 的源列表。Blink 引擎会根据这个对象来决定是否允许执行某个 JavaScript 脚本。
    * **`Timing-Allow-Origin` 头部解析:** `ConvertToBlink(const TimingAllowOriginPtr& in)` 函数负责解析这个头部。这个头部决定了哪些源可以获取资源加载的详细时间信息，这对于 JavaScript 中的性能监控 API (如 `performance.timing`) 有影响。
        * **假设输入:** HTTP 响应头包含 `Timing-Allow-Origin: https://another-example.com`
        * **输出:** `ConvertToBlink` 会将其解析为 `blink::TimingAllowOriginPtr` 对象，指示只有来自 `https://another-example.com` 的页面才能使用 JavaScript 获取该资源的加载时间信息。

* **HTML:**
    * **`Refresh` 头部解析:** `ParseHTTPRefresh` 函数解析 `Refresh` 头部，这会影响 HTML 页面的跳转或刷新行为。
        * **假设输入:** HTTP 响应头包含 `Refresh: 5; url=https://new-page.com`
        * **输出:** `ParseHTTPRefresh` 会解析出 5 秒的延迟和目标 URL `https://new-page.com`，浏览器会在 5 秒后跳转到新页面。
    * **`Link` 头部解析:** `ConvertToBlink(const LinkHeaderPtr& in)` 函数解析 `Link` 头部，HTML 可以通过 `<link>` 标签或者 HTTP `Link` 头部来指定资源的预加载、预连接等。
        * **假设输入:** HTTP 响应头包含 `Link: <style.css>; rel=preload; as=style`
        * **输出:** `ConvertToBlink` 会将其解析为 `blink::LinkHeaderPtr` 对象，指示浏览器应该预加载 `style.css` 文件，并将其视为样式表。

* **CSS:**
    * **`Content-Type` 头部解析:** `ExtractMIMETypeFromMediaType` 和 `MinimizedMIMEType` 用于处理 `Content-Type` 头部，这决定了浏览器如何解释接收到的资源，包括 CSS 文件。
        * **假设输入:** HTTP 响应头包含 `Content-Type: text/css; charset=utf-8`
        * **输出:** `ExtractMIMETypeFromMediaType` 会提取出 `text/css`。`MinimizedMIMEType` 可能将其保持不变。浏览器会根据 `text/css` 将其渲染为样式表。

**逻辑推理的假设输入与输出：**

* **函数：`ParseCacheControlDirectives`**
    * **假设输入:** `cache_control_value = "max-age=3600, public, must-revalidate"`, `pragma_value = ""`
    * **输出:** `CacheControlHeader` 对象，其 `max_age` 值为 `base::Seconds(3600)`, `contains_no_cache` 为 `false`, `contains_no_store` 为 `false`, `contains_must_revalidate` 为 `true`。

* **函数：`ParseHTTPRefresh`**
    * **假设输入:** `refresh = "10"`
    * **输出:** `delay` 为 `base::Seconds(10)`, `url` 为空字符串。
    * **假设输入:** `refresh = "0;URL=newpage.html"`
    * **输出:** `delay` 为 `base::Seconds(0)`, `url` 为 `"newpage.html"`。

**用户或编程常见的使用错误举例：**

* **`ParseDate` 函数:**
    * **错误输入:**  HTTP 响应头包含 `Date: Invalid Date Format`
    * **结果:** `ParseDate` 函数返回 `std::nullopt`，表示解析失败。开发者如果未处理这种情况，可能会导致程序出现异常或显示错误的日期信息。
* **`ParseHTTPRefresh` 函数:**
    * **错误输入:** HTTP 响应头包含 `Refresh: abc; url=target.html` (非法的延迟时间)
    * **结果:** `ParseHTTPRefresh` 函数返回 `false`，表示解析失败。浏览器可能忽略这个 `Refresh` 头部或采取默认行为，这可能与开发者预期不符。
* **使用 `ConvertToBlink` 时类型不匹配:**  虽然代码中使用了 `DCHECK` 来进行断言检查，但如果网络层传递的 Mojo 数据结构与 Blink 期望的类型不一致（例如，枚举值的范围不匹配），则可能导致程序崩溃或出现未定义的行为。

**总结：**

总而言之，`blink/renderer/platform/network/http_parsers.cc` (第一部分) 的主要功能是**实现各种 HTTP 头部字段的解析逻辑，并将解析结果转换为 Blink 引擎内部使用的数据结构**。这对于浏览器正确理解和处理来自服务器的 HTTP 响应至关重要，直接影响到网页的渲染、资源加载、安全策略执行以及各种 Web API 的行为。 它充当了网络层和 Blink 渲染引擎之间的桥梁，负责将网络数据转化为 Blink 可以理解和操作的信息。

### 提示词
```
这是目录为blink/renderer/platform/network/http_parsers.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2006, 2007, 2008, 2009 Apple Inc. All rights reserved.
 * Copyright (C) 2009 Torch Mobile Inc. http://www.torchmobile.com/
 * Copyright (C) 2009 Google Inc. All rights reserved.
 * Copyright (C) 2011 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/network/http_parsers.h"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "base/containers/flat_map.h"
#include "base/feature_list.h"
#include "base/time/time.h"
#include "net/http/http_content_disposition.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "services/network/public/cpp/content_security_policy/content_security_policy.h"
#include "services/network/public/cpp/no_vary_search_header_parser.h"
#include "services/network/public/cpp/parsed_headers.h"
#include "services/network/public/cpp/timing_allow_origin_parser.h"
#include "services/network/public/mojom/no_vary_search.mojom-blink-forward.h"
#include "services/network/public/mojom/no_vary_search.mojom-blink.h"
#include "services/network/public/mojom/parsed_headers.mojom-blink.h"
#include "services/network/public/mojom/supports_loading_mode.mojom-blink.h"
#include "services/network/public/mojom/timing_allow_origin.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/mime_util/mime_util.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/network/header_field_tokenizer.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/parsing_utilities.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

// We would like finding a way to convert from/to blink type automatically.
// The following attempt has been withdrawn:
// https://chromium-review.googlesource.com/c/chromium/src/+/2126933/7
//
// Note: nesting these helpers inside network::mojom bypasses warnings from
// audit_non_blink_style.py, as well as saving a bunch of typing to qualify the
// types below.
namespace network {
namespace mojom {

// When adding a new conversion, define a new `ConvertToBlink` overload to map
// the non-Blink type (passing by value for primitive types or passing by const
// reference otherwise). The generic converters for container types relies on
// the presence of `ConvertToBlink` overloads to determine the correct return
// type.

// ===== Identity converters =====
// Converts where the input type and output type are identical(-ish).
uint8_t ConvertToBlink(uint8_t in) {
  return in;
}

// Note: for identity enum conversions, there should be `static_assert`s that
// the input enumerator and the output enumerator define matching values.
blink::CSPDirectiveName ConvertToBlink(CSPDirectiveName name) {
  return static_cast<blink::CSPDirectiveName>(name);
}

// `in` is a Mojo enum type, which is type aliased to the same underlying type
// by both the non-Blink Mojo variant and the Blink Mojo variant.
blink::WebClientHintsType ConvertToBlink(WebClientHintsType in) {
  return in;
}

blink::LoadingMode ConvertToBlink(LoadingMode in) {
  return static_cast<blink::LoadingMode>(in);
}

// ===== Converters for other basic Blink types =====
String ConvertToBlink(const std::string& in) {
  return String::FromUTF8(in);
}

String ConvertToBlink(const std::optional<std::string>& in) {
  return in ? String::FromUTF8(*in) : String();
}

::blink::KURL ConvertToBlink(const GURL& in) {
  return ::blink::KURL(in);
}

scoped_refptr<const ::blink::SecurityOrigin> ConvertToBlink(
    const url::Origin& in) {
  return ::blink::SecurityOrigin::CreateFromUrlOrigin(in);
}

// ====== Generic container converters =====
template <
    typename InElement,
    typename OutElement = decltype(ConvertToBlink(std::declval<InElement>()))>
Vector<OutElement> ConvertToBlink(const std::vector<InElement>& in) {
  Vector<OutElement> out;
  out.reserve(base::checked_cast<wtf_size_t>(in.size()));
  for (const auto& element : in) {
    out.push_back(ConvertToBlink(element));
  }
  return out;
}

template <typename InKey,
          typename InValue,
          typename OutKey = decltype(ConvertToBlink(std::declval<InKey>())),
          typename OutValue = decltype(ConvertToBlink(std::declval<InValue>()))>
HashMap<OutKey, OutValue> ConvertToBlink(
    const base::flat_map<InKey, InValue>& in) {
  HashMap<OutKey, OutValue> out;
  for (const auto& element : in) {
    out.insert(ConvertToBlink(element.first), ConvertToBlink(element.second));
  }
  return out;
}

// ===== Converters from non-Blink to Blink variant of Mojo structs =====
blink::CSPSourcePtr ConvertToBlink(const CSPSourcePtr& in) {
  DCHECK(in);
  return blink::CSPSource::New(
      ConvertToBlink(in->scheme), ConvertToBlink(in->host), in->port,
      ConvertToBlink(in->path), in->is_host_wildcard, in->is_port_wildcard);
}

blink::CSPHashSourcePtr ConvertToBlink(const CSPHashSourcePtr& in) {
  DCHECK(in);
  Vector<uint8_t> hash_value = ConvertToBlink(in->value);

  return blink::CSPHashSource::New(in->algorithm, std::move(hash_value));
}

blink::CSPSourceListPtr ConvertToBlink(const CSPSourceListPtr& source_list) {
  DCHECK(source_list);

  Vector<blink::CSPSourcePtr> sources = ConvertToBlink(source_list->sources);
  Vector<String> nonces = ConvertToBlink(source_list->nonces);
  Vector<blink::CSPHashSourcePtr> hashes = ConvertToBlink(source_list->hashes);

  return blink::CSPSourceList::New(
      std::move(sources), std::move(nonces), std::move(hashes),
      source_list->allow_self, source_list->allow_star,
      source_list->allow_inline, source_list->allow_inline_speculation_rules,
      source_list->allow_eval, source_list->allow_wasm_eval,
      source_list->allow_wasm_unsafe_eval, source_list->allow_dynamic,
      source_list->allow_unsafe_hashes, source_list->report_sample);
}

blink::ContentSecurityPolicyHeaderPtr ConvertToBlink(
    const ContentSecurityPolicyHeaderPtr& in) {
  DCHECK(in);
  return blink::ContentSecurityPolicyHeader::New(
      ConvertToBlink(in->header_value), in->type, in->source);
}

blink::CSPTrustedTypesPtr ConvertToBlink(const CSPTrustedTypesPtr& in) {
  if (!in)
    return nullptr;
  return blink::CSPTrustedTypes::New(ConvertToBlink(in->list), in->allow_any,
                                     in->allow_duplicates);
}

blink::ContentSecurityPolicyPtr ConvertToBlink(
    const ContentSecurityPolicyPtr& in) {
  DCHECK(in);
  return blink::ContentSecurityPolicy::New(
      ConvertToBlink(in->self_origin), ConvertToBlink(in->raw_directives),
      ConvertToBlink(in->directives), in->upgrade_insecure_requests,
      in->treat_as_public_address, in->block_all_mixed_content, in->sandbox,
      ConvertToBlink(in->header), in->use_reporting_api,
      ConvertToBlink(in->report_endpoints), in->require_trusted_types_for,
      ConvertToBlink(in->trusted_types), ConvertToBlink(in->parsing_errors));
}

blink::AllowCSPFromHeaderValuePtr ConvertToBlink(
    const AllowCSPFromHeaderValuePtr& allow_csp_from) {
  if (!allow_csp_from)
    return nullptr;
  switch (allow_csp_from->which()) {
    case AllowCSPFromHeaderValue::Tag::kAllowStar:
      return blink::AllowCSPFromHeaderValue::NewAllowStar(
          allow_csp_from->get_allow_star());
    case AllowCSPFromHeaderValue::Tag::kOrigin:
      return blink::AllowCSPFromHeaderValue::NewOrigin(
          ConvertToBlink(allow_csp_from->get_origin()));
    case AllowCSPFromHeaderValue::Tag::kErrorMessage:
      return blink::AllowCSPFromHeaderValue::NewErrorMessage(
          ConvertToBlink(allow_csp_from->get_error_message()));
  }
}

blink::LinkHeaderPtr ConvertToBlink(const LinkHeaderPtr& in) {
  DCHECK(in);
  return blink::LinkHeader::New(
      ConvertToBlink(in->href),
      // TODO(dcheng): Make these use ConvertToBlink
      static_cast<blink::LinkRelAttribute>(in->rel),
      static_cast<blink::LinkAsAttribute>(in->as),
      static_cast<blink::CrossOriginAttribute>(in->cross_origin),
      static_cast<blink::FetchPriorityAttribute>(in->fetch_priority),
      ConvertToBlink(in->mime_type));
}

blink::TimingAllowOriginPtr ConvertToBlink(const TimingAllowOriginPtr& in) {
  if (!in) {
    return nullptr;
  }

  switch (in->which()) {
    case TimingAllowOrigin::Tag::kSerializedOrigins:
      return blink::TimingAllowOrigin::NewSerializedOrigins(
          ConvertToBlink(in->get_serialized_origins()));
    case TimingAllowOrigin::Tag::kAll:
      return blink::TimingAllowOrigin::NewAll(/*ignored=*/0);
  }
}

blink::NoVarySearchWithParseErrorPtr ConvertToBlink(
    const NoVarySearchWithParseErrorPtr& in) {
  if (!in)
    return nullptr;

  if (in->is_parse_error()) {
    return blink::NoVarySearchWithParseError::NewParseError(
        in->get_parse_error());
  }

  const NoVarySearchPtr& no_vary_search = in->get_no_vary_search();
  CHECK(no_vary_search);
  CHECK(no_vary_search->search_variance);
  if (no_vary_search->search_variance->is_no_vary_params()) {
    return blink::NoVarySearchWithParseError::NewNoVarySearch(
        blink::NoVarySearch::New(
            blink::SearchParamsVariance::NewNoVaryParams(ConvertToBlink(
                no_vary_search->search_variance->get_no_vary_params())),
            no_vary_search->vary_on_key_order));
  }

  CHECK(no_vary_search->search_variance->is_vary_params());
  return blink::NoVarySearchWithParseError::NewNoVarySearch(
      blink::NoVarySearch::New(
          blink::SearchParamsVariance::NewVaryParams(ConvertToBlink(
              no_vary_search->search_variance->get_vary_params())),
          no_vary_search->vary_on_key_order));
}

blink::ParsedHeadersPtr ConvertToBlink(const ParsedHeadersPtr& in) {
  DCHECK(in);
  return blink::ParsedHeaders::New(
      ConvertToBlink(in->content_security_policy),
      ConvertToBlink(in->allow_csp_from), in->cross_origin_embedder_policy,
      in->cross_origin_opener_policy, in->document_isolation_policy,
      in->origin_agent_cluster,
      in->accept_ch.has_value()
          ? std::make_optional(ConvertToBlink(in->accept_ch.value()))
          : std::nullopt,
      in->critical_ch.has_value()
          ? std::make_optional(ConvertToBlink(in->critical_ch.value()))
          : std::nullopt,
      in->client_hints_ignored_due_to_clear_site_data_header, in->xfo,
      ConvertToBlink(in->link_headers), ConvertToBlink(in->timing_allow_origin),
      ConvertToBlink(in->supports_loading_mode),
      in->reporting_endpoints.has_value()
          ? std::make_optional(ConvertToBlink(in->reporting_endpoints.value()))
          : std::nullopt,
      in->cookie_indices.has_value()
          ? std::make_optional(ConvertToBlink(in->cookie_indices.value()))
          : std::nullopt,
      in->avail_language.has_value()
          ? std::make_optional(ConvertToBlink(in->avail_language.value()))
          : std::nullopt,
      in->content_language.has_value()
          ? std::make_optional(ConvertToBlink(in->content_language.value()))
          : std::nullopt,
      ConvertToBlink(in->no_vary_search_with_parse_error),
      in->observe_browsing_topics, in->allow_cross_origin_event_reporting);
}

}  // namespace mojom
}  // namespace network

namespace blink {

namespace {

const Vector<AtomicString>& ReplaceHeaders() {
  // The list of response headers that we do not copy from the original
  // response when generating a ResourceResponse for a MIME payload.
  // Note: this is called only on the main thread.
  DEFINE_STATIC_LOCAL(
      Vector<AtomicString>, headers,
      ({http_names::kLowerContentType, http_names::kLowerContentLength,
        http_names::kLowerContentDisposition, http_names::kLowerContentRange,
        http_names::kLowerRange, http_names::kLowerSetCookie}));
  return headers;
}

bool IsWhitespace(UChar chr) {
  return (chr == ' ') || (chr == '\t');
}

// true if there is more to parse, after incrementing pos past whitespace.
// Note: Might return pos == str.length()
// if |matcher| is nullptr, isWhitespace() is used.
inline bool SkipWhiteSpace(const String& str,
                           unsigned& pos,
                           WTF::CharacterMatchFunctionPtr matcher = nullptr) {
  unsigned len = str.length();

  if (matcher) {
    while (pos < len && matcher(str[pos]))
      ++pos;
  } else {
    while (pos < len && IsWhitespace(str[pos]))
      ++pos;
  }

  return pos < len;
}

template <typename CharType>
inline bool IsASCIILowerAlphaOrDigit(CharType c) {
  return IsASCIILower(c) || IsASCIIDigit(c);
}

template <typename CharType>
inline bool IsASCIILowerAlphaOrDigitOrHyphen(CharType c) {
  return IsASCIILowerAlphaOrDigit(c) || c == '-';
}

// Parse a number with ignoring trailing [0-9.].
// Returns false if the source contains invalid characters.
bool ParseRefreshTime(const String& source, base::TimeDelta& delay) {
  int full_stop_count = 0;
  unsigned number_end = source.length();
  for (unsigned i = 0; i < source.length(); ++i) {
    UChar ch = source[i];
    if (ch == kFullstopCharacter) {
      if (++full_stop_count == 2)
        number_end = i;
    } else if (!IsASCIIDigit(ch)) {
      return false;
    }
  }
  bool ok;
  double time = source.Left(number_end).ToDouble(&ok);
  if (RuntimeEnabledFeatures::MetaRefreshNoFractionalEnabled()) {
    time = floor(time);
  }
  if (!ok)
    return false;
  delay = base::Seconds(time);
  return true;
}

}  // namespace

bool IsValidHTTPHeaderValue(const String& name) {
  // FIXME: This should really match name against
  // field-value in section 4.2 of RFC 2616.

  return name.ContainsOnlyLatin1OrEmpty() && !name.Contains('\r') &&
         !name.Contains('\n') && !name.Contains('\0');
}

// See RFC 7230, Section 3.2.6.
bool IsValidHTTPToken(const String& characters) {
  if (characters.empty())
    return false;
  for (unsigned i = 0; i < characters.length(); ++i) {
    UChar c = characters[i];
    if (c > 0x7F || !net::HttpUtil::IsTokenChar(c))
      return false;
  }
  return true;
}

bool IsContentDispositionAttachment(const String& content_disposition) {
  return net::HttpContentDisposition(content_disposition.Utf8(), std::string())
      .is_attachment();
}

// https://html.spec.whatwg.org/C/#attr-meta-http-equiv-refresh
bool ParseHTTPRefresh(const String& refresh,
                      WTF::CharacterMatchFunctionPtr matcher,
                      base::TimeDelta& delay,
                      String& url) {
  unsigned len = refresh.length();
  unsigned pos = 0;
  matcher = matcher ? matcher : IsWhitespace;

  if (!SkipWhiteSpace(refresh, pos, matcher))
    return false;

  while (pos != len && refresh[pos] != ',' && refresh[pos] != ';' &&
         !matcher(refresh[pos]))
    ++pos;

  if (pos == len) {  // no URL
    url = String();
    return ParseRefreshTime(refresh.StripWhiteSpace(), delay);
  } else {
    if (!ParseRefreshTime(refresh.Left(pos).StripWhiteSpace(), delay))
      return false;

    SkipWhiteSpace(refresh, pos, matcher);
    if (pos < len && (refresh[pos] == ',' || refresh[pos] == ';'))
      ++pos;
    SkipWhiteSpace(refresh, pos, matcher);
    unsigned url_start_pos = pos;
    if (refresh.FindIgnoringASCIICase("url", url_start_pos) == url_start_pos) {
      url_start_pos += 3;
      SkipWhiteSpace(refresh, url_start_pos, matcher);
      if (refresh[url_start_pos] == '=') {
        ++url_start_pos;
        SkipWhiteSpace(refresh, url_start_pos, matcher);
      } else {
        url_start_pos = pos;  // e.g. "Refresh: 0; url.html"
      }
    }

    unsigned url_end_pos = len;

    if (refresh[url_start_pos] == '"' || refresh[url_start_pos] == '\'') {
      UChar quotation_mark = refresh[url_start_pos];
      url_start_pos++;
      while (url_end_pos > url_start_pos) {
        url_end_pos--;
        if (refresh[url_end_pos] == quotation_mark)
          break;
      }

      // https://bugs.webkit.org/show_bug.cgi?id=27868
      // Sometimes there is no closing quote for the end of the URL even though
      // there was an opening quote.  If we looped over the entire alleged URL
      // string back to the opening quote, just go ahead and use everything
      // after the opening quote instead.
      if (url_end_pos == url_start_pos)
        url_end_pos = len;
    }

    url = refresh.Substring(url_start_pos, url_end_pos - url_start_pos)
              .StripWhiteSpace();
    return true;
  }
}

std::optional<base::Time> ParseDate(const String& value,
                                    UseCounter& use_counter) {
  const std::string utf8_value = value.Utf8();
  std::optional<base::Time> maybe_parsed_time =
      ParseDateFromNullTerminatedCharacters(utf8_value.c_str());
  {
    // Assumes UTC if timezone isn't specified.
    std::optional<base::Time> maybe_parsed_time_fromutcstring;
    base::Time parsed_time;
    if (base::Time::FromUTCString(utf8_value.c_str(), &parsed_time)) {
      maybe_parsed_time_fromutcstring = parsed_time;
    }
    if (maybe_parsed_time != maybe_parsed_time_fromutcstring) {
      use_counter.CountUse(
          WebFeature::kHttpParsersParseDateFromUTCStringDifferent);
    }
  }
  {
    // Assumes local time if timezone isn't specified.
    std::optional<base::Time> maybe_parsed_time_fromstring;
    base::Time parsed_time;
    if (base::Time::FromString(utf8_value.c_str(), &parsed_time)) {
      maybe_parsed_time_fromstring = parsed_time;
    }
    if (maybe_parsed_time != maybe_parsed_time_fromstring) {
      use_counter.CountUse(
          WebFeature::kHttpParsersParseDateFromStringDifferent);
    }
  }
  return maybe_parsed_time;
}

AtomicString ExtractMIMETypeFromMediaType(const AtomicString& media_type) {
  unsigned length = media_type.length();

  unsigned pos = 0;

  while (pos < length) {
    UChar c = media_type[pos];
    if (c != '\t' && c != ' ')
      break;
    ++pos;
  }

  if (pos == length)
    return media_type;

  unsigned type_start = pos;

  unsigned type_end = pos;
  while (pos < length) {
    UChar c = media_type[pos];

    // While RFC 2616 does not allow it, other browsers allow multiple values in
    // the HTTP media type header field, Content-Type. In such cases, the media
    // type string passed here may contain the multiple values separated by
    // commas. For now, this code ignores text after the first comma, which
    // prevents it from simply failing to parse such types altogether.  Later
    // for better compatibility we could consider using the first or last valid
    // MIME type instead.
    // See https://bugs.webkit.org/show_bug.cgi?id=25352 for more discussion.
    if (c == ',' || c == ';')
      break;

    if (c != '\t' && c != ' ')
      type_end = pos + 1;

    ++pos;
  }

  // Use a StringView to create an AtomicString here so we do not allocate an
  // intermediate string.
  return AtomicString(
      StringView(media_type, type_start, type_end - type_start));
}

bool IsHTTPTabOrSpace(UChar c) {
  // https://fetch.spec.whatwg.org/#http-tab-or-space
  return c == kSpaceCharacter || c == kTabulationCharacter;
}

// https://mimesniff.spec.whatwg.org/#minimize-a-supported-mime-type
// Note that `mime_type` should already have been stripped of parameters by
// `ExtractMIMETypeFromMediaType`.
AtomicString MinimizedMIMEType(const AtomicString& mime_type) {
  StringUTF8Adaptor mime_utf8(mime_type);

  if (IsSupportedJavascriptMimeType(mime_utf8.AsStringView())) {
    return AtomicString("text/javascript");
  }

  if (IsJSONMimeType(mime_utf8.AsStringView())) {
    return AtomicString("application/json");
  }

  if (IsSVGMimeType(mime_utf8.AsStringView())) {
    return AtomicString("image/svg+xml");
  }

  if (IsXMLMimeType(mime_utf8.AsStringView())) {
    return AtomicString("application/xml");
  }

  if (IsSupportedMimeType(mime_utf8.AsStringView())) {
    return mime_type;
  }

  return g_empty_atom;
}

ContentTypeOptionsDisposition ParseContentTypeOptionsHeader(
    const String& value) {
  // The spec prescribes how to split the header value, and wants to include
  // empty entries and to strip only particular type of whitespace.
  // Spec: https://fetch.spec.whatwg.org/#x-content-type-options-header
  // Test: external/wpt/fetch/nosniff/parsing-nosniff.window.html

  if (value.empty())
    return kContentTypeOptionsNone;

  String decoded_and_split_header_value;
  if (base::FeatureList::IsEnabled(
          features::kLegacyParsingOfXContentTypeOptions)) {
    // Header parsing, as used until M120.
    Vector<String> results;
    value.Split(",", results);
    if (results.size()) {
      decoded_and_split_header_value = results[0].StripWhiteSpace();
    }
  } else {
    // Header parsing, as demanded by the spec.
    Vector<String> results;
    value.Split(",", /* allow_empty_entries */ true, results);
    CHECK(results.size());  // allow_empty_entries guarantees >= 1 results.
    decoded_and_split_header_value =
        results[0].StripWhiteSpace(IsHTTPTabOrSpace);
  }

  if (EqualIgnoringASCIICase(decoded_and_split_header_value, "nosniff")) {
    return kContentTypeOptionsNosniff;
  }
  return kContentTypeOptionsNone;
}

static bool IsCacheHeaderSeparator(UChar c) {
  // See RFC 2616, Section 2.2
  switch (c) {
    case '(':
    case ')':
    case '<':
    case '>':
    case '@':
    case ',':
    case ';':
    case ':':
    case '\\':
    case '"':
    case '/':
    case '[':
    case ']':
    case '?':
    case '=':
    case '{':
    case '}':
    case ' ':
    case '\t':
      return true;
    default:
      return false;
  }
}

static bool IsControlCharacter(UChar c) {
  return c < ' ' || c == 127;
}

static inline String TrimToNextSeparator(const String& str) {
  return str.Substring(0, str.Find(IsCacheHeaderSeparator));
}

static void ParseCacheHeader(const String& header,
                             Vector<std::pair<String, String>>& result) {
  const String safe_header = header.RemoveCharacters(IsControlCharacter);
  wtf_size_t max = safe_header.length();
  for (wtf_size_t pos = 0; pos < max; /* pos incremented in loop */) {
    wtf_size_t next_comma_position = safe_header.find(',', pos);
    wtf_size_t next_equal_sign_position = safe_header.find('=', pos);
    if (next_equal_sign_position != kNotFound &&
        (next_equal_sign_position < next_comma_position ||
         next_comma_position == kNotFound)) {
      // Get directive name, parse right hand side of equal sign, then add to
      // map
      String directive = TrimToNextSeparator(
          safe_header.Substring(pos, next_equal_sign_position - pos)
              .StripWhiteSpace());
      pos += next_equal_sign_position - pos + 1;

      String value = safe_header.Substring(pos, max - pos).StripWhiteSpace();
      if (value[0] == '"') {
        // The value is a quoted string
        wtf_size_t next_double_quote_position = value.find('"', 1);
        if (next_double_quote_position != kNotFound) {
          // Store the value as a quoted string without quotes
          result.push_back(std::pair<String, String>(
              directive, value.Substring(1, next_double_quote_position - 1)
                             .StripWhiteSpace()));
          pos += (safe_header.find('"', pos) - pos) +
                 next_double_quote_position + 1;
          // Move past next comma, if there is one
          wtf_size_t next_comma_position2 = safe_header.find(',', pos);
          if (next_comma_position2 != kNotFound)
            pos += next_comma_position2 - pos + 1;
          else
            return;  // Parse error if there is anything left with no comma
        } else {
          // Parse error; just use the rest as the value
          result.push_back(std::pair<String, String>(
              directive,
              TrimToNextSeparator(
                  value.Substring(1, value.length() - 1).StripWhiteSpace())));
          return;
        }
      } else {
        // The value is a token until the next comma
        wtf_size_t next_comma_position2 = value.find(',');
        if (next_comma_position2 != kNotFound) {
          // The value is delimited by the next comma
          result.push_back(std::pair<String, String>(
              directive,
              TrimToNextSeparator(
                  value.Substring(0, next_comma_position2).StripWhiteSpace())));
          pos += (safe_header.find(',', pos) - pos) + 1;
        } else {
          // The rest is the value; no change to value needed
          result.push_back(
              std::pair<String, String>(directive, TrimToNextSeparator(value)));
          return;
        }
      }
    } else if (next_comma_position != kNotFound &&
               (next_comma_position < next_equal_sign_position ||
                next_equal_sign_position == kNotFound)) {
      // Add directive to map with empty string as value
      result.push_back(std::pair<String, String>(
          TrimToNextSeparator(
              safe_header.Substring(pos, next_comma_position - pos)
                  .StripWhiteSpace()),
          ""));
      pos += next_comma_position - pos + 1;
    } else {
      // Add last directive to map with empty string as value
      result.push_back(std::pair<String, String>(
          TrimToNextSeparator(
              safe_header.Substring(pos, max - pos).StripWhiteSpace()),
          ""));
      return;
    }
  }
}

CacheControlHeader ParseCacheControlDirectives(
    const AtomicString& cache_control_value,
    const AtomicString& pragma_value) {
  CacheControlHeader cache_control_header;
  cache_control_header.parsed = true;
  cache_control_header.max_age = std::nullopt;
  cache_control_header.stale_while_revalidate = std::nullopt;

  static const char kNoCacheDirective[] = "no-cache";
  static const char kNoStoreDirective[] = "no-store";
  static const char kMustRevalidateDirective[] = "must-revalidate";
  static const char kMaxAgeDirective[] = "max-age";
  static const char kStaleWhileRevalidateDirective[] = "stale-while-revalidate";

  if (!cache_control_value.empty()) {
    Vector<std::pair<String, String>> directives;
    ParseCacheHeader(cache_control_value, directives);

    wtf_size_t directives_size = directives.size();
    for (wtf_size_t i = 0; i < directives_size; ++i) {
      // RFC2616 14.9.1: A no-cache directive with a value is only meaningful
      // for proxy caches.  It should be ignored by a browser level cache.
      if (EqualIgnoringASCIICase(directives[i].first, kNoCacheDirective) &&
          directives[i].second.empty()) {
        cache_control_header.contains_no_cache = true;
      } else if (EqualIgnoringASCIICase(directives[i].first,
                                        kNoStoreDirective)) {
        cache_control_header.contains_no_store = true;
      } else if (EqualIgnoringASCIICase(directives[i].first,
                                        kMustRevalidateDirective)) {
        cache_control_header.contains_must_revalidate = true;
      } else if (EqualIgnoringASCIICase(directives[i].first,
                                        kMaxAgeDirective)) {
        if (cache_control_header.max_age) {
          // First max-age directive wins if there are multiple ones.
          continue;
        }
        bool ok;
        double max_age = directives[i].second.ToDouble(&ok);
        if (ok)
          cache_control_header.max_age = base::Seconds(max_age);
      } else if (EqualIgnoringASCIICase(directives[i].first,
                                        kStaleWhileRevalidateDirective)) {
        if (cache_control_header.stale_while_revalidate) {
          // First stale-while-revalidate directive wins if there are multiple
          // ones.
          continue;
        }
        bool ok;
        double stale_while_revalidate = directives[i].second.ToDouble(&ok);
        if (ok) {
          cache_control_header.stale_while_revalidate =
              base::Seconds(stale_while_revalidate);
        }
      }
    }
  }

  if (!cache_control_header.contains_no_cache) {
    // Handle Pragma: no-cache
    // This is deprecated and equivalent to Cache-control: no-cache
    // Don't bother tokenizing the value, it is not important
    cache_control_header.contains_no_cache =
        pragma_value.LowerASCII().Contains(kNoCacheDirective);
  }
  return cache_control_header;
}

void ParseCommaDelimitedHeader(const String& header_value,
                               CommaDelimitedHeaderSet& header_set) {
  Vector<String> results;
  header_value.Split(",", results);
  for (auto& value : results)
    header_set.insert(value.StripWhiteSpace(IsWhitespace));
}

bool ParseMultipartHeadersFromBody(base::span<const uint8_t> bytes,
                                   ResourceResponse* response,
                                   wtf_size_t* end) {
  DCHECK(IsMainThread());

  size_t headers_end_pos =
      net::HttpUtil::LocateEndOfAdditionalHeaders(bytes, 0);

  if (headers_end_pos == std::string::npos)
    return false;

  *end = static_cast<wtf_size_t>(headers_end_pos);

  // Eat headers and prepend a status line as is required by
  // HttpResponseHeaders.
  std::string headers("HTTP/1.1 200 OK\r\n");
  headers.append(base::as_string_view(bytes.first(headers_end_pos)));

  auto response_headers = base::MakeRefCounted<net::HttpResponseHeaders>(
      net::HttpUtil::AssembleRawHeaders(headers));

  std::string mime_type, charset;
  response_headers->GetMimeTypeAndCharset(&mime_type, &charset);
  response->SetMimeType(WebString::FromUTF8(mime_type));
  response->SetTextEncodingName(WebString::FromUTF8(charset));

  // Copy headers listed in replaceHeaders to the response.
  for (const AtomicString& header : ReplaceHeaders()) {
    std::string value;
    StringUTF8Adaptor adaptor(header);
    std::string_view header_string_piece(adaptor.AsStringView());
    size_t iterator = 0;

    response->ClearHttpHeaderField(header);
    Vector<AtomicString> values;
    while (response_headers->EnumerateHeader(&iterator, header_string_piece,
                                             &value)) {
      const AtomicString atomic_value = WebString::FromLatin1(value);
      values.push_back(atomic_value);
    }
    response->AddHttpHeaderFieldWithMultipleValues(header, values);
  }
  return true;
}

bool ParseMultipartFormHeadersFromBody(base::span<const uint8_t> bytes,
                                       HTTPHeaderMap* header_fields,
                                       wtf_size_t* end) {
  DCHECK_EQ(0u,
```