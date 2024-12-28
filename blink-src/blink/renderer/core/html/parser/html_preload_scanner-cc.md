Response:
My thought process for summarizing the `HTMLPreloadScanner` functionality goes like this:

1. **Understand the Goal:** The core purpose of this code is to *proactively* identify resources needed by the HTML document *before* the full parsing is complete. This allows the browser to start fetching these resources earlier, improving page load performance.

2. **Identify Key Data Structures and Concepts:** I scan the included headers and the code itself for recurring terms and important data structures. This reveals:
    * `HTMLPreloadScanner`: The central class.
    * `HTMLToken`: The input unit, representing parts of the HTML.
    * `PreloadRequest`: The output, representing a request for a resource.
    * Resource types (script, image, CSS, etc.).
    * Attributes like `src`, `href`, `srcset`, `rel`, `media`, `crossorigin`, `integrity`, `type`, etc.
    * Concepts like preloading, preconnecting, and lazy loading.
    * Media queries.
    * Subresource Integrity (SRI).
    * Content Security Policy (implied by `Nonce`).
    * Fetch priorities.

3. **Trace the Workflow (Implicitly):**  Although the provided code snippet doesn't show the complete workflow, I can infer it. The scanner processes HTML tokens, examines attributes, and, based on these, decides whether to generate a `PreloadRequest`.

4. **Group Functionality by Resource Type:**  The code handles different HTML tags (`<script>`, `<img>`, `<link>`, etc.) differently. This suggests a natural way to categorize the scanner's functions:

    * **Scripts:** Look for `src`, `type`, `async`, `defer`, `nomodule`, `integrity`, `crossorigin`, `nonce`, `blocking`, `attributionsrc`. Consider module vs. classic scripts.
    * **Images:** Look for `src`, `srcset`, `sizes`, `crossorigin`, `referrerpolicy`, `fetchpriority`, `loading`, `attributionsrc`, `sharedstoragewritable`, `data-src`. Handle `<picture>` and `<source>` elements.
    * **Stylesheets:** Look for `<link rel="stylesheet">`, `href`, `media`, `crossorigin`, `integrity`, `blocking`, `disabled`.
    * **Other `<link>` types:** Handle `preconnect`, `preload`, `modulepreload`.
    * **Inputs:** Recognize `type="image"`.
    * **Videos:** Look for `poster`.

5. **Identify Core Operations:** Beyond handling specific tags, the scanner performs general operations:

    * **URL Extraction:**  Getting URLs from `src` and `href` attributes.
    * **Media Query Matching:** Evaluating `media` attributes.
    * **`srcset` Parsing:** Choosing the best image source from `srcset`.
    * **Integrity Check (SRI):** Parsing `integrity` attributes.
    * **Cross-origin Handling:**  Recognizing `crossorigin`.
    * **Fetch Priority:** Recognizing `fetchpriority`.
    * **Lazy Loading:** Recognizing `loading="lazy"`.
    * **Blocking/Non-blocking:**  Determining if a resource blocks rendering.

6. **Consider Interactions with Other Technologies:**

    * **JavaScript:**  Directly related through `<script>` tags, `type="module"`, `async`, `defer`, `nomodule`, and module preloading.
    * **HTML:** The input to the scanner. It parses HTML tags and attributes.
    * **CSS:** Directly related through `<link rel="stylesheet">` and inline styles (though inline styles are likely handled differently). `media` queries are a crucial interaction point.

7. **Think About Potential Errors:**  What could go wrong?

    * **Incorrect URLs:** Typographical errors in `src` or `href`.
    * **Invalid `integrity` values:**  Leading to failed subresource integrity checks.
    * **Incorrect `type` attributes:**  Potentially preventing resource loading or causing incorrect interpretation.
    * **Conflicting attributes:**  Though the scanner seems to prioritize the first encountered value in some cases.

8. **Formulate the Summary (Iterative Process):**  I start with a high-level description and then add more detail, grouping related functionalities. I focus on *what* the scanner does and *why* it's important. I use the identified keywords and concepts to make the explanation clear and accurate. I also explicitly link the functionality to JavaScript, HTML, and CSS where appropriate.

9. **Review and Refine:** I reread the summary to ensure it's comprehensive, concise, and easy to understand. I check for any jargon that needs explanation. I make sure I've addressed all parts of the prompt.

This iterative process of examining the code, identifying key concepts, inferring the workflow, and grouping functionality allows me to build a comprehensive and accurate summary of the `HTMLPreloadScanner`'s role.
好的，根据提供的代码片段，以下是对 `blink/renderer/core/html/parser/html_preload_scanner.cc` 文件功能的归纳：

**功能概述:**

`HTMLPreloadScanner` 的主要功能是在 HTML 文档解析的早期阶段（通常是预扫描阶段或在后台线程中），**快速扫描 HTML 标记的属性，识别并预加载关键资源，以提高页面加载性能。** 它专注于寻找可能需要尽早加载的资源，例如脚本、样式表、图片和其他通过 `<link>` 标签声明的资源。

**详细功能点:**

1. **快速解析 HTML 标记：**  它不是一个完整的 HTML 解析器，而是针对性能优化设计的轻量级扫描器，主要关注特定的 HTML 标签（如 `<script>`, `<link>`, `<img>`, `<input>`, `<source>`, `<video>`, `<style>`)及其相关属性。

2. **提取资源 URL：** 从标签的 `src`、`href`、`srcset` 等属性中提取资源的 URL。

3. **识别资源类型：**  根据标签名和属性（如 `<link>` 的 `rel` 和 `as` 属性，`<script>` 的 `type` 属性）判断资源的类型（例如：脚本、样式表、图片、字体等）。

4. **处理媒体查询：**  解析并匹配 `<link>` 和 `<source>` 标签中的 `media` 属性，以确定资源是否适用于当前的视口或设备特性。

5. **处理 `srcset` 和 `sizes` 属性：**  对于 `<img>` 和 `<source>` 标签，解析 `srcset` 和 `sizes` 属性，选择最合适的图片资源进行预加载。

6. **处理 `<link>` 标签的 `rel` 属性：**
   - **`preload`：** 识别声明为 `preload` 的资源，并根据 `as` 属性确定资源类型进行预加载。
   - **`preconnect`：** 识别声明为 `preconnect` 的链接，发起与服务器的早期连接。
   - **`stylesheet`：** 识别样式表链接。
   - **`modulepreload`:** 识别模块脚本的预加载。

7. **处理脚本标签属性：**
   - **`async` 和 `defer`：**  识别异步和延迟加载的脚本。
   - **`type="module"`：**  识别模块脚本。
   - **`nomodule`：** 识别不应在模块化环境中执行的脚本。
   - **`integrity`：**  处理用于子资源完整性 (SRI) 校验的属性。
   - **`crossorigin`：** 处理跨域资源请求的属性。
   - **`nonce`：** 处理内容安全策略 (CSP) nonce。
   - **`blocking`:** 处理渲染阻塞属性。
   - **`attributionsrc`:** 处理与归因报告相关的属性。

8. **处理图片标签属性：**
   - **`loading="lazy"`：** 识别声明为延迟加载的图片。
   - **`crossorigin`：** 处理跨域图片请求的属性。
   - **`referrerpolicy`：** 处理引荐来源策略。
   - **`fetchpriority`：** 处理提取优先级提示。
   - **`attributionsrc`:** 处理与归因报告相关的属性。
   - **`sharedstoragewritable`:** 处理共享存储写入权限相关的属性。
   - **`data-src`:** 一种用于延迟加载图片的常见模式。

9. **创建预加载请求：**  对于识别出的需要预加载的资源，创建一个 `PreloadRequest` 对象，其中包含了资源的 URL、类型、优先级等信息。

10. **处理子资源完整性 (SRI)：** 解析 `integrity` 属性，用于在加载资源后验证其完整性。

11. **处理跨域属性：**  解析 `crossorigin` 属性，以确定是否需要使用 CORS 进行资源请求。

12. **处理提取优先级：**  解析 `fetchpriority` 属性，以提示浏览器资源的加载优先级。

13. **处理渲染阻塞行为：**  根据标签和属性（如 `<script>` 的 `async`、`defer` 和 `blocking` 属性，以及 `<link>` 的 `rel` 属性）判断资源是否会阻塞页面的渲染。

14. **排除特定资源：**  通过 `ExclusionInfo` 来排除某些不需要预加载的资源。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * **`<script src="script.js"></script>`:**  `HTMLPreloadScanner` 会提取 `script.js` 的 URL，并识别这是一个 JavaScript 资源，可能会根据 `async` 或 `defer` 属性创建不同的预加载请求。
    * **`<link rel="modulepreload" href="module.js">`:**  `HTMLPreloadScanner` 会识别这是一个模块脚本，并进行预加载。
    * **`<script type="module" src="module.js"></script>`:** 同样会识别并预加载模块脚本。

* **HTML:**
    * **`<img src="image.png">`:** `HTMLPreloadScanner` 会提取 `image.png` 的 URL，并识别这是一个图片资源。
    * **`<link rel="stylesheet" href="style.css">`:**  `HTMLPreloadScanner` 会提取 `style.css` 的 URL，并识别这是一个 CSS 样式表。
    * **`<link rel="preload" href="font.woff2" as="font" crossorigin>`:**  `HTMLPreloadScanner` 会识别这是一个需要预加载的字体资源。

* **CSS:**
    * **`<link rel="stylesheet" href="style.css" media="screen and (max-width: 600px)">`:** `HTMLPreloadScanner` 会解析 `media` 属性，只有当屏幕宽度小于等于 600px 时，才会认为这个样式表需要预加载。

**逻辑推理的假设输入与输出示例:**

**假设输入:**  HTML 片段 `<img src="lazy.jpg" loading="lazy">`

**输出:**  `HTMLPreloadScanner` **可能不会** 为 `lazy.jpg` 创建立即的预加载请求，因为它识别到 `loading="lazy"` 属性，表明这是一个需要延迟加载的图片。

**假设输入:** HTML 片段 `<link rel="preload" href="important.js" as="script">`

**输出:** `HTMLPreloadScanner` 会创建一个 `PreloadRequest` 对象，指示浏览器预加载 `important.js` 文件，并将其类型标记为 "script"。

**涉及用户或编程常见的使用错误举例:**

* **`integrity` 属性值错误:** 如果 `<script>` 或 `<link>` 标签的 `integrity` 属性值与实际资源的哈希值不匹配，浏览器在加载资源后会拒绝执行或应用，导致页面功能异常或样式丢失。 这不是 `HTMLPreloadScanner` 直接导致的错误，而是它处理的属性相关的潜在问题。
* **`as` 属性与实际资源类型不符:**  在使用 `<link rel="preload">` 时，如果 `as` 属性的值与实际资源的类型不匹配（例如，`as="style"` 但实际链接的是一个脚本文件），浏览器可能无法正确加载或应用资源。
* **错误的 URL 路径:**  `src` 或 `href` 属性中的 URL 路径错误会导致资源加载失败。

**功能归纳（针对第 1 部分）：**

`HTMLPreloadScanner` 的主要功能是在 HTML 解析的早期阶段，通过快速扫描 HTML 标签的属性，**主动识别并请求加载关键的外部资源 (如脚本, 样式表, 图片等)**。 它通过分析特定的标签和属性（例如 `<script>` 的 `src`, `type`, `async`, `defer`, `integrity`； `<link>` 的 `href`, `rel`, `as`, `media`, `integrity`； `<img>` 的 `src`, `srcset`, `loading` 等），来判断哪些资源需要尽早加载以优化页面加载性能。 该扫描器还负责处理诸如媒体查询、子资源完整性、跨域请求和提取优先级等相关属性。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_preload_scanner.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 * Copyright (C) 2009 Torch Mobile, Inc. http://www.torchmobile.com/
 * Copyright (C) 2010 Google Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/parser/html_preload_scanner.h"

#include <memory>
#include <optional>

#include "base/task/sequenced_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/script/script_type.mojom-blink.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_name.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/media_query_evaluator.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/sizes_attribute_parser.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/html/blocking_attribute.h"
#include "third_party/blink/renderer/core/html/client_hints_util.h"
#include "third_party/blink/renderer/core/html/cross_origin_attribute.h"
#include "third_party/blink/renderer/core/html/html_dimension.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/link_rel_attribute.h"
#include "third_party/blink/renderer/core/html/loading_attribute.h"
#include "third_party/blink/renderer/core/html/parser/background_html_scanner.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/parser/html_srcset_parser.h"
#include "third_party/blink/renderer/core/html/parser/html_tokenizer.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/fetch_priority_attribute.h"
#include "third_party/blink/renderer/core/loader/preload_helper.h"
#include "third_party/blink/renderer/core/loader/subresource_integrity_helper.h"
#include "third_party/blink/renderer/core/loader/web_bundle/script_web_bundle_rule.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/script_loader.h"
#include "third_party/blink/renderer/core/script_type_names.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/client_hints_preferences.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"

namespace blink {

namespace {

bool Match(const AtomicString& name, const QualifiedName& q_name) {
  return q_name.LocalName() == name;
}

String InitiatorFor(const StringImpl* tag_impl, bool link_is_modulepreload) {
  DCHECK(tag_impl);
  if (Match(tag_impl, html_names::kImgTag))
    return html_names::kImgTag.LocalName();
  if (Match(tag_impl, html_names::kInputTag))
    return html_names::kInputTag.LocalName();
  if (Match(tag_impl, html_names::kLinkTag)) {
    if (link_is_modulepreload)
      return fetch_initiator_type_names::kOther;
    return html_names::kLinkTag.LocalName();
  }
  if (Match(tag_impl, html_names::kScriptTag))
    return html_names::kScriptTag.LocalName();
  if (Match(tag_impl, html_names::kVideoTag))
    return html_names::kVideoTag.LocalName();
  NOTREACHED();
}

bool MediaAttributeMatches(const MediaValuesCached& media_values,
                           const String& attribute_value) {
  // Since this is for preload scanning only, ExecutionContext-based origin
  // trials for media queries are not needed.
  MediaQuerySet* media_queries =
      MediaQuerySet::Create(attribute_value, nullptr);
  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(&media_values);
  return media_query_evaluator->Eval(*media_queries);
}

void ScanScriptWebBundle(
    const String& inline_text,
    const KURL& base_url,
    scoped_refptr<const PreloadRequest::ExclusionInfo>& exclusion_info) {
  auto rule_or_error =
      ScriptWebBundleRule::ParseJson(inline_text, base_url, /*logger*/ nullptr);
  if (!absl::holds_alternative<ScriptWebBundleRule>(rule_or_error))
    return;
  auto& rule = absl::get<ScriptWebBundleRule>(rule_or_error);

  HashSet<KURL> scopes;
  HashSet<KURL> resources;
  if (exclusion_info) {
    scopes = exclusion_info->scopes();
    resources = exclusion_info->resources();
  }

  for (const KURL& scope_url : rule.scope_urls())
    scopes.insert(scope_url);
  for (const KURL& resource_url : rule.resource_urls())
    resources.insert(resource_url);

  exclusion_info = base::MakeRefCounted<PreloadRequest::ExclusionInfo>(
      base_url, std::move(scopes), std::move(resources));
}

void ScanScriptWebBundle(
    const HTMLToken::DataVector& data,
    const KURL& base_url,
    scoped_refptr<const PreloadRequest::ExclusionInfo>& exclusion_info) {
  ScanScriptWebBundle(data.AsString(), base_url, exclusion_info);
}

}  // namespace

bool Match(const StringImpl* impl, const QualifiedName& q_name) {
  return impl == q_name.LocalName().Impl();
}

const StringImpl* TagImplFor(const HTMLToken::DataVector& data) {
  AtomicString tag_name = data.AsAtomicString();
  const StringImpl* result = tag_name.Impl();
  if (result->IsStatic())
    return result;
  return nullptr;
}

class TokenPreloadScanner::StartTagScanner {
  STACK_ALLOCATED();

 public:
  StartTagScanner(
      const StringImpl* tag_impl,
      MediaValuesCached* media_values,
      SubresourceIntegrity::IntegrityFeatures features,
      TokenPreloadScanner::ScannerType scanner_type,
      const HashSet<String>* disabled_image_types,
      features::LcppPreloadLazyLoadImageType preload_lazy_load_image_type)
      : tag_impl_(tag_impl),
        media_values_(media_values),
        integrity_features_(features),
        scanner_type_(scanner_type),
        disabled_image_types_(disabled_image_types),
        preload_lazy_load_image_type_(preload_lazy_load_image_type) {
    switch (preload_lazy_load_image_type_) {
      case features::LcppPreloadLazyLoadImageType::kCustomLazyLoading:
      case features::LcppPreloadLazyLoadImageType::kAll:
        use_data_src_attr_match_for_image_ = true;
        break;
      case features::LcppPreloadLazyLoadImageType::kNone:
      case features::LcppPreloadLazyLoadImageType::kNativeLazyLoading:
        use_data_src_attr_match_for_image_ = false;
        break;
    }
    if (Match(tag_impl_, html_names::kImgTag) ||
        Match(tag_impl_, html_names::kSourceTag) ||
        Match(tag_impl_, html_names::kLinkTag)) {
      source_size_ =
          SizesAttributeParser(media_values_, String(), nullptr).Size();
      return;
    }
    if (!Match(tag_impl_, html_names::kInputTag) &&
        !Match(tag_impl_, html_names::kScriptTag) &&
        !Match(tag_impl_, html_names::kVideoTag) &&
        !Match(tag_impl_, html_names::kStyleTag))
      tag_impl_ = nullptr;
  }

  enum URLReplacement { kAllowURLReplacement, kDisallowURLReplacement };

  bool GetMatched() const { return matched_; }

  void ProcessAttributes(const HTMLToken::AttributeList& attributes) {
    if (!tag_impl_)
      return;
    for (const HTMLToken::Attribute& html_token_attribute : attributes) {
      AtomicString attribute_name(html_token_attribute.GetName());
      String attribute_value = html_token_attribute.Value();
      ProcessAttribute(attribute_name, attribute_value);
    }
    PostProcessAfterAttributes();
  }

  void PostProcessAfterAttributes() {
    if (Match(tag_impl_, html_names::kImgTag) ||
        (link_is_preload_ && as_attribute_value_ == "image"))
      SetUrlFromImageAttributes();
  }

  void HandlePictureSourceURL(PictureData& picture_data) {
    if (Match(tag_impl_, html_names::kSourceTag) && matched_ &&
        picture_data.source_url.empty()) {
      picture_data.source_url = srcset_image_candidate_.ToString();
      picture_data.source_size_set = source_size_set_;
      picture_data.source_size = source_size_;
      picture_data.picked = true;
    } else if (Match(tag_impl_, html_names::kImgTag) &&
               !picture_data.source_url.empty()) {
      SetUrlToLoad(picture_data.source_url, kAllowURLReplacement);
    }
  }

  std::unique_ptr<PreloadRequest> CreatePreloadRequest(
      const KURL& predicted_base_url,
      const PictureData& picture_data,
      const CachedDocumentParameters& document_parameters,
      const PreloadRequest::ExclusionInfo* exclusion_info,
      bool treat_links_as_in_body,
      bool is_potentially_lcp_element) {
    PreloadRequest::RequestType request_type =
        PreloadRequest::kRequestTypePreload;
    std::optional<ResourceType> type;
    if (ShouldPreconnect()) {
      request_type = PreloadRequest::kRequestTypePreconnect;
    } else {
      if (IsLinkRelPreload()) {
        request_type = PreloadRequest::kRequestTypeLinkRelPreload;
        type = ResourceTypeForLinkPreload();
        if (type == std::nullopt) {
          return nullptr;
        }
      } else if (IsLinkRelModulePreload()) {
        request_type = PreloadRequest::kRequestTypeLinkRelPreload;
        type = ResourceType::kScript;
      }
      if (!ShouldPreload(type)) {
        return nullptr;
      }
    }

    float source_size = source_size_;
    bool source_size_set = source_size_set_;
    if (picture_data.picked) {
      source_size_set = picture_data.source_size_set;
      source_size = picture_data.source_size;
    }
    ResourceFetcher::IsImageSet is_image_set =
        (picture_data.picked || !srcset_image_candidate_.IsEmpty())
            ? ResourceFetcher::kImageIsImageSet
            : ResourceFetcher::kImageNotImageSet;

    if (source_size_set) {
      // resource_width_ may have originally been set by an explicit width
      // attribute on an img tag but it gets overridden by sizes if present.
      resource_width_ = source_size;
    }

    if (type == std::nullopt) {
      type = GetResourceType();
    }

    // The element's 'referrerpolicy' attribute (if present) takes precedence
    // over the document's referrer policy.
    network::mojom::ReferrerPolicy referrer_policy =
        (referrer_policy_ != network::mojom::ReferrerPolicy::kDefault)
            ? referrer_policy_
            : document_parameters.referrer_policy;
    auto request = PreloadRequest::CreateIfNeeded(
        InitiatorFor(tag_impl_, link_is_modulepreload_), url_to_load_,
        predicted_base_url, type.value(), referrer_policy, is_image_set,
        exclusion_info, resource_width_, resource_height_, request_type);
    if (!request)
      return nullptr;

    bool is_module = (type_attribute_value_ == script_type_names::kModule);
    bool is_script = Match(tag_impl_, html_names::kScriptTag);
    bool is_img = Match(tag_impl_, html_names::kImgTag);
    if ((is_script && is_module) || IsLinkRelModulePreload()) {
      is_module = true;
      request->SetScriptType(mojom::blink::ScriptType::kModule);
    }

    request->SetCrossOrigin(cross_origin_);
    request->SetFetchPriorityHint(fetch_priority_hint_);
    request->SetNonce(nonce_);
    request->SetCharset(Charset());
    request->SetDefer(defer_);

    RenderBlockingBehavior render_blocking_behavior =
        RenderBlockingBehavior::kUnset;
    if (request_type == PreloadRequest::kRequestTypeLinkRelPreload) {
      render_blocking_behavior = RenderBlockingBehavior::kNonBlocking;
    } else if (is_script &&
               (is_module || defer_ == FetchParameters::kLazyLoad)) {
      render_blocking_behavior =
          BlockingAttribute::HasRenderToken(blocking_attribute_value_)
              ? RenderBlockingBehavior::kBlocking
              : (is_async_ ? RenderBlockingBehavior::kPotentiallyBlocking
                           : RenderBlockingBehavior::kNonBlocking);
    } else if (is_script || type == ResourceType::kCSSStyleSheet) {
      // CSS here is render blocking unless it's disabled, as non blocking
      // doesn't get preloaded. JS here is a blocking one, as others would've
      // been caught by the previous condition.
      render_blocking_behavior =
          type == ResourceType::kCSSStyleSheet && disabled_attr_set_
              ? RenderBlockingBehavior::kNonBlocking
          : treat_links_as_in_body
              ? RenderBlockingBehavior::kInBodyParserBlocking
              : RenderBlockingBehavior::kBlocking;
    }
    request->SetRenderBlockingBehavior(render_blocking_behavior);

    if (type == ResourceType::kImage && is_img &&
        IsLazyLoadImageDeferable(document_parameters,
                                 is_potentially_lcp_element)) {
      return nullptr;
    }
    // Do not set integrity metadata for <link> elements for destinations not
    // supporting SRI (crbug.com/1058045).
    // A corresponding check for non-preload-scanner code path is in
    // PreloadHelper::PreloadIfNeeded().
    // TODO(crbug.com/981419): Honor the integrity attribute value for all
    // supported preload destinations, not just the destinations that support
    // SRI in the first place.
    if (type == ResourceType::kScript || type == ResourceType::kCSSStyleSheet ||
        type == ResourceType::kFont) {
      request->SetIntegrityMetadata(integrity_metadata_);
    }

    if (scanner_type_ == ScannerType::kInsertion)
      request->SetFromInsertionScanner(true);

    if (attributionsrc_attr_set_) {
      DCHECK(is_script || is_img);
      request->SetAttributionReportingEligibleImgOrScript(true);
    }

    if (shared_storage_writable_opted_in_) {
      DCHECK(is_img);
      request->SetSharedStorageWritableOptedIn(true);
    }

    return request;
  }

 private:
  void ProcessScriptAttribute(const AtomicString& attribute_name,
                              const String& attribute_value) {
    // FIXME - Don't set crossorigin multiple times.
    if (Match(attribute_name, html_names::kSrcAttr)) {
      SetUrlToLoad(attribute_value, kDisallowURLReplacement);
    } else if (Match(attribute_name, html_names::kCrossoriginAttr)) {
      SetCrossOrigin(attribute_value);
    } else if (Match(attribute_name, html_names::kNonceAttr)) {
      SetNonce(attribute_value);
    } else if (Match(attribute_name, html_names::kAsyncAttr)) {
      is_async_ = true;
      SetDefer(FetchParameters::kLazyLoad);
    } else if (Match(attribute_name, html_names::kDeferAttr)) {
      SetDefer(FetchParameters::kLazyLoad);
    } else if (!integrity_attr_set_ &&
               Match(attribute_name, html_names::kIntegrityAttr)) {
      integrity_attr_set_ = true;
      SubresourceIntegrity::ParseIntegrityAttribute(
          attribute_value, integrity_features_, integrity_metadata_);
    } else if (Match(attribute_name, html_names::kTypeAttr)) {
      type_attribute_value_ = attribute_value;
    } else if (Match(attribute_name, html_names::kLanguageAttr)) {
      language_attribute_value_ = attribute_value;
    } else if (Match(attribute_name, html_names::kNomoduleAttr)) {
      nomodule_attribute_value_ = true;
    } else if (!referrer_policy_set_ &&
               Match(attribute_name, html_names::kReferrerpolicyAttr) &&
               !attribute_value.IsNull()) {
      SetReferrerPolicy(attribute_value,
                        kDoNotSupportReferrerPolicyLegacyKeywords);
    } else if (!fetch_priority_hint_set_ &&
               Match(attribute_name, html_names::kFetchpriorityAttr)) {
      SetFetchPriorityHint(attribute_value);
    } else if (Match(attribute_name, html_names::kBlockingAttr)) {
      blocking_attribute_value_ = attribute_value;
    } else if (Match(attribute_name, html_names::kAttributionsrcAttr)) {
      attributionsrc_attr_set_ = true;
    }
  }

  void ProcessImgAttribute(const AtomicString& attribute_name,
                           const String& attribute_value) {
    if (Match(attribute_name, html_names::kSrcAttr) && img_src_url_.IsNull()) {
      img_src_url_ = attribute_value;
    } else if (Match(attribute_name, html_names::kCrossoriginAttr)) {
      SetCrossOrigin(attribute_value);
    } else if (Match(attribute_name, html_names::kSrcsetAttr) &&
               srcset_attribute_value_.IsNull()) {
      srcset_attribute_value_ = attribute_value;
    } else if (Match(attribute_name, html_names::kSizesAttr) &&
               !source_size_set_) {
      ParseSourceSize(attribute_value);
    } else if (!referrer_policy_set_ &&
               Match(attribute_name, html_names::kReferrerpolicyAttr) &&
               !attribute_value.IsNull()) {
      SetReferrerPolicy(attribute_value, kSupportReferrerPolicyLegacyKeywords);
    } else if (!fetch_priority_hint_set_ &&
               Match(attribute_name, html_names::kFetchpriorityAttr)) {
      SetFetchPriorityHint(attribute_value);
    } else if (Match(attribute_name, html_names::kWidthAttr)) {
      HTMLDimension dimension;
      if (ParseDimensionValue(attribute_value, dimension) &&
          dimension.IsAbsolute()) {
        resource_width_ = dimension.Value();
      }
    } else if (Match(attribute_name, html_names::kHeightAttr)) {
      HTMLDimension dimension;
      if (ParseDimensionValue(attribute_value, dimension) &&
          dimension.IsAbsolute()) {
        resource_height_ = dimension.Value();
      }
    } else if (loading_attr_value_ == LoadingAttributeValue::kAuto &&
               Match(attribute_name, html_names::kLoadingAttr)) {
      loading_attr_value_ = GetLoadingAttributeValue(attribute_value);
    } else if (Match(attribute_name, html_names::kAttributionsrcAttr)) {
      attributionsrc_attr_set_ = true;
    } else if (Match(attribute_name, html_names::kSharedstoragewritableAttr)) {
      shared_storage_writable_opted_in_ = true;
    } else if (use_data_src_attr_match_for_image_ &&
               Match(attribute_name, html_names::kDataSrcAttr) &&
               img_src_url_.IsNull()) {
      img_src_url_ = attribute_value;
    }
  }

  void SetUrlFromImageAttributes() {
    srcset_image_candidate_ =
        BestFitSourceForSrcsetAttribute(media_values_->DevicePixelRatio(),
                                        source_size_, srcset_attribute_value_);
    SetUrlToLoad(BestFitSourceForImageAttributes(
                     media_values_->DevicePixelRatio(), source_size_,
                     img_src_url_, srcset_image_candidate_),
                 kAllowURLReplacement);
  }

  void ProcessStyleAttribute(const AtomicString& attribute_name,
                             const String& attribute_value) {
    if (Match(attribute_name, html_names::kMediaAttr)) {
      matched_ &= MediaAttributeMatches(*media_values_, attribute_value);
    }
    // No need to parse the `blocking` attribute. Parser-created style elements
    // are implicitly render-blocking as long as the media attribute matches.
  }

  void ProcessLinkAttribute(const AtomicString& attribute_name,
                            const String& attribute_value) {
    // FIXME - Don't set rel/media/crossorigin multiple times.
    if (Match(attribute_name, html_names::kHrefAttr)) {
      SetUrlToLoad(attribute_value, kDisallowURLReplacement);
      // Used in SetUrlFromImageAttributes() when as=image.
      img_src_url_ = attribute_value;
    } else if (Match(attribute_name, html_names::kRelAttr)) {
      LinkRelAttribute rel(attribute_value);
      link_is_style_sheet_ =
          rel.IsStyleSheet() && !rel.IsAlternate() &&
          rel.GetIconType() == mojom::blink::FaviconIconType::kInvalid &&
          !rel.IsDNSPrefetch();
      link_is_preconnect_ = rel.IsPreconnect();
      link_is_preload_ = rel.IsLinkPreload();
      link_is_modulepreload_ = rel.IsModulePreload();
    } else if (Match(attribute_name, html_names::kMediaAttr)) {
      matched_ &= MediaAttributeMatches(*media_values_, attribute_value);
    } else if (Match(attribute_name, html_names::kCrossoriginAttr)) {
      SetCrossOrigin(attribute_value);
    } else if (Match(attribute_name, html_names::kNonceAttr)) {
      SetNonce(attribute_value);
    } else if (Match(attribute_name, html_names::kAsAttr)) {
      as_attribute_value_ = attribute_value.DeprecatedLower();
    } else if (Match(attribute_name, html_names::kTypeAttr)) {
      type_attribute_value_ = attribute_value;
    } else if (!referrer_policy_set_ &&
               Match(attribute_name, html_names::kReferrerpolicyAttr) &&
               !attribute_value.IsNull()) {
      SetReferrerPolicy(attribute_value,
                        kDoNotSupportReferrerPolicyLegacyKeywords);
    } else if (!integrity_attr_set_ &&
               Match(attribute_name, html_names::kIntegrityAttr)) {
      integrity_attr_set_ = true;
      SubresourceIntegrity::ParseIntegrityAttribute(
          attribute_value, integrity_features_, integrity_metadata_);
    } else if (Match(attribute_name, html_names::kImagesrcsetAttr) &&
               srcset_attribute_value_.IsNull()) {
      srcset_attribute_value_ = attribute_value;
    } else if (Match(attribute_name, html_names::kImagesizesAttr) &&
               !source_size_set_) {
      ParseSourceSize(attribute_value);
    } else if (!fetch_priority_hint_set_ &&
               Match(attribute_name, html_names::kFetchpriorityAttr)) {
      SetFetchPriorityHint(attribute_value);
    } else if (Match(attribute_name, html_names::kBlockingAttr)) {
      blocking_attribute_value_ = attribute_value;
    } else if (Match(attribute_name, html_names::kDisabledAttr)) {
      disabled_attr_set_ = true;
    }
  }

  void ProcessInputAttribute(const AtomicString& attribute_name,
                             const String& attribute_value) {
    // FIXME - Don't set type multiple times.
    if (Match(attribute_name, html_names::kSrcAttr)) {
      SetUrlToLoad(attribute_value, kDisallowURLReplacement);
    } else if (Match(attribute_name, html_names::kTypeAttr)) {
      input_is_image_ =
          EqualIgnoringASCIICase(attribute_value, input_type_names::kImage);
    }
  }

  void ProcessSourceAttribute(const AtomicString& attribute_name,
                              const String& attribute_value) {
    if (Match(attribute_name, html_names::kSrcsetAttr) &&
        srcset_image_candidate_.IsEmpty()) {
      srcset_attribute_value_ = attribute_value;
      srcset_image_candidate_ = BestFitSourceForSrcsetAttribute(
          media_values_->DevicePixelRatio(), source_size_, attribute_value);
    } else if (Match(attribute_name, html_names::kSizesAttr) &&
               !source_size_set_) {
      ParseSourceSize(attribute_value);
      if (!srcset_image_candidate_.IsEmpty()) {
        srcset_image_candidate_ = BestFitSourceForSrcsetAttribute(
            media_values_->DevicePixelRatio(), source_size_,
            srcset_attribute_value_);
      }
    } else if (Match(attribute_name, html_names::kMediaAttr)) {
      // FIXME - Don't match media multiple times.
      matched_ &= MediaAttributeMatches(*media_values_, attribute_value);
    } else if (Match(attribute_name, html_names::kTypeAttr)) {
      matched_ &= HTMLImageElement::SupportedImageType(attribute_value,
                                                       disabled_image_types_);
    }
  }

  void ProcessVideoAttribute(const AtomicString& attribute_name,
                             const String& attribute_value) {
    if (Match(attribute_name, html_names::kPosterAttr))
      SetUrlToLoad(attribute_value, kDisallowURLReplacement);
    else if (Match(attribute_name, html_names::kCrossoriginAttr))
      SetCrossOrigin(attribute_value);
  }

  void ProcessAttribute(const AtomicString& attribute_name,
                        const String& attribute_value) {
    if (Match(attribute_name, html_names::kCharsetAttr))
      charset_ = attribute_value;

    if (Match(tag_impl_, html_names::kScriptTag))
      ProcessScriptAttribute(attribute_name, attribute_value);
    else if (Match(tag_impl_, html_names::kImgTag))
      ProcessImgAttribute(attribute_name, attribute_value);
    else if (Match(tag_impl_, html_names::kLinkTag))
      ProcessLinkAttribute(attribute_name, attribute_value);
    else if (Match(tag_impl_, html_names::kInputTag))
      ProcessInputAttribute(attribute_name, attribute_value);
    else if (Match(tag_impl_, html_names::kSourceTag))
      ProcessSourceAttribute(attribute_name, attribute_value);
    else if (Match(tag_impl_, html_names::kVideoTag))
      ProcessVideoAttribute(attribute_name, attribute_value);
    else if (Match(tag_impl_, html_names::kStyleTag))
      ProcessStyleAttribute(attribute_name, attribute_value);
  }

  bool IsLazyLoadImageDeferable(
      const CachedDocumentParameters& document_parameters,
      bool is_potentially_lcp_element) {
    if (document_parameters.lazy_load_image_setting ==
        LocalFrame::LazyLoadImageSetting::kDisabled) {
      return false;
    }

    // LCPP experiment in crbug.com/1498777. If the image is potentially a LCP
    // element, the scanner doesn't mark it as a deferable image regardless of
    // whether it has loading="lazy" attribute or not, in order to make the LCP
    // image load completion faster. An exception to this is "lazy load auto
    // sizes" which must defer because sizes=auto requires layout information.
    //
    // If the dry run mode is enabled, prevents the actual preload request from
    // being created.
    const bool dry_run_mode = features::kLCPPLazyLoadImagePreloadDryRun.Get();
    if (is_potentially_lcp_element && !source_size_is_auto_ && !dry_run_mode) {
      switch (document_parameters.preload_lazy_load_image_type) {
        case features::LcppPreloadLazyLoadImageType::kNativeLazyLoading:
        case features::LcppPreloadLazyLoadImageType::kCustomLazyLoading:
        case features::LcppPreloadLazyLoadImageType::kAll:
          return false;
        case features::LcppPreloadLazyLoadImageType::kNone:
          break;
      }
    }

    return loading_attr_value_ == LoadingAttributeValue::kLazy;
  }

  void SetUrlToLoad(const String& value, URLReplacement replacement) {
    // We only respect the first src/href, per HTML5:
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#attribute-name-state
    if (replacement == kDisallowURLReplacement && !url_to_load_.empty())
      return;
    String url = StripLeadingAndTrailingHTMLSpaces(value);
    if (url.empty())
      return;
    url_to_load_ = url;
  }

  const String& Charset() const {
    // FIXME: Its not clear that this if is needed, the loader probably ignores
    // charset for image requests anyway.
    if (Match(tag_impl_, html_names::kImgTag) ||
        Match(tag_impl_, html_names::kVideoTag))
      return g_empty_string;
    return charset_;
  }

  std::optional<ResourceType> ResourceTypeForLinkPreload() const {
    DCHECK(link_is_preload_);
    return PreloadHelper::GetResourceTypeFromAsAttribute(as_attribute_value_);
  }

  ResourceType GetResourceType() const {
    if (Match(tag_impl_, html_names::kScriptTag))
      return ResourceType::kScript;
    if (Match(tag_impl_, html_names::kImgTag) ||
        Match(tag_impl_, html_names::kVideoTag) ||
        (Match(tag_impl_, html_names::kInputTag) && input_is_image_))
      return ResourceType::kImage;
    if (Match(tag_impl_, html_names::kLinkTag) && link_is_style_sheet_)
      return ResourceType::kCSSStyleSheet;
    if (link_is_preconnect_)
      return ResourceType::kRaw;
    NOTREACHED();
  }

  bool ShouldPreconnect() const {
    return Match(tag_impl_, html_names::kLinkTag) && link_is_preconnect_ &&
           !url_to_load_.empty();
  }

  bool IsLinkRelPreload() const {
    return Match(tag_impl_, html_names::kLinkTag) && link_is_preload_ &&
           !url_to_load_.empty();
  }

  bool IsLinkRelModulePreload() const {
    return Match(tag_impl_, html_names::kLinkTag) && link_is_modulepreload_ &&
           !url_to_load_.empty();
  }

  bool ShouldPreloadLink(std::optional<ResourceType>& type) const {
    if (link_is_style_sheet_) {
      return type_attribute_value_.empty() ||
             MIMETypeRegistry::IsSupportedStyleSheetMIMEType(
                 ContentType(type_attribute_value_).GetType());
    } else if (link_is_preload_) {
      if (type == ResourceType::kImage) {
        return HTMLImageElement::SupportedImageType(type_attribute_value_,
                                                    disabled_image_types_);
      }
      if (type_attribute_value_.empty())
        return true;
      String type_from_attribute = ContentType(type_attribute_value_).GetType();
      if ((type == ResourceType::kFont &&
           !MIMETypeRegistry::IsSupportedFontMIMEType(type_from_attribute)) ||
          (type == ResourceType::kCSSStyleSheet &&
           !MIMETypeRegistry::IsSupportedStyleSheetMIMEType(
               type_from_attribute))) {
        return false;
      }
      return true;
    } else if (link_is_modulepreload_) {
      return true;
    }
    return false;
  }

  bool ShouldPreload(std::optional<ResourceType>& type) const {
    if (url_to_load_.empty())
      return false;
    if (!matched_)
      return false;
    if (Match(tag_impl_, html_names::kLinkTag))
      return ShouldPreloadLink(type);
    if (Match(tag_impl_, html_names::kInputTag) && !input_is_image_)
      return false;
    if (Match(tag_impl_, html_names::kScriptTag)) {
      ScriptLoader::ScriptTypeAtPrepare script_type =
          ScriptLoader::GetScriptTypeAtPrepare(type_attribute_value_,
                                               language_attribute_value_);
      switch (script_type) {
        case ScriptLoader::ScriptTypeAtPrepare::kInvalid:
          return false;

        case ScriptLoader::ScriptTypeAtPrepare::kImportMap:
          // TODO(crbug.com/922212): External import maps are not yet supported.
          return false;

        case ScriptLoader::ScriptTypeAtPrepare::kSpeculationRules:
          // TODO(crbug.com/1182803): External speculation rules are not yet
          // supported.
          return false;

        case ScriptLoader::ScriptTypeAtPrepare::kWebBundle:
          // External webbundle is not yet supported.
          return false;

        case ScriptLoader::ScriptTypeAtPrepare::kClassic:
        case ScriptLoader::Script
"""


```