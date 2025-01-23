Response:
The user wants a summary of the functionality of the provided C++ code snippet from `html_preload_scanner.cc`. They also want to understand its relationship with web technologies (HTML, CSS, JavaScript), including examples, logical reasoning with input/output, and potential user/programming errors. Since this is part 2 of 2, I should focus on the functionality within *this specific* snippet and integrate it with the understanding gained from part 1.

**Plan:**

1. **High-level Functionality:** Summarize the purpose of the `TokenPreloadScanner` and the data structures it manipulates, based on the provided code.
2. **Relationship with Web Technologies:**
    - **HTML:**  Explain how the scanner analyzes HTML attributes (like `src`, `srcset`, `type`, `rel`, `media`, `nonce`, `defer`, `async`, `integrity`, `loading`). Provide examples of how these attributes trigger specific actions or data extraction within the scanner.
    - **CSS:** Explain how the scanner interacts with CSS, specifically in the context of `<link rel="stylesheet">` and media queries.
    - **JavaScript:** Explain the handling of `<script>` tags, including `type="module"` and `nomodule` attributes.
3. **Logical Reasoning (Hypothetical Input/Output):**  Provide a simple HTML snippet and trace how the `TokenPreloadScanner` would process it, focusing on the data stored in the `StartTagScanner` and the resulting `PreloadRequest`.
4. **User/Programming Errors:** Identify potential mistakes a developer might make in their HTML that could affect the behavior of the preload scanner (e.g., incorrect `rel` values, invalid URLs, typos in attributes).
5. **Integration with Part 1:** Combine the understanding of `TokenPreloadScanner` with the broader context of `HTMLPreloadScanner` from part 1. Emphasize how `TokenPreloadScanner` is used within `HTMLPreloadScanner`.
这是 `blink/renderer/core/html/parser/html_preload_scanner.cc` 文件的第二部分代码，主要关注的是 `TokenPreloadScanner` 类的实现细节，以及它如何处理 HTML 标签的属性来识别需要预加载的资源。

**功能归纳:**

这部分代码主要实现了 `TokenPreloadScanner` 类的核心功能，负责解析 HTML 标签的属性，并从中提取出需要预加载的资源的 URL 和相关信息。它会根据不同的标签和属性，创建 `PreloadRequest` 对象，用于后续的资源预加载。此外，它还处理了一些与页面行为相关的 meta 标签，例如 viewport 和 referrer。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`TokenPreloadScanner` 的主要作用是分析 HTML 结构，因此它与 HTML 的关系最为紧密。它会检查各种 HTML 标签和属性，以确定需要预加载的资源。它与 JavaScript 和 CSS 的关系主要体现在识别和处理加载这些资源的标签。

**HTML:**

*   **`<link>` 标签:**
    *   **功能:**  识别 `<link>` 标签，并根据 `rel` 属性的值判断其类型，例如 `stylesheet` (CSS), `preload`, `preconnect`, `modulepreload`。
    *   **举例:**
        *   假设输入 `<link rel="stylesheet" href="style.css">`:  `link_is_style_sheet_` 会被设置为 `true`，`url_to_load_` 会被设置为 "style.css"。
        *   假设输入 `<link rel="preload" href="image.png" as="image">`: `link_is_preload_` 会被设置为 `true`，`url_to_load_` 会被设置为 "image.png"，`as_attribute_value_` 会被设置为 "image"。
        *   假设输入 `<link rel="modulepreload" href="module.js">`: `link_is_modulepreload_` 会被设置为 `true`，`url_to_load_` 会被设置为 "module.js"。
        *   假设输入 `<link rel="preconnect" href="https://example.com">`: `link_is_preconnect_` 会被设置为 `true`，`url_to_load_` 会被设置为 "https://example.com"。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** `<link rel="preload" href="font.woff2" as="font" crossorigin>`
        *   **输出:** `link_is_preload_ = true`, `url_to_load_ = "font.woff2"`, `as_attribute_value_ = "font"`, `cross_origin_ = kCrossOriginAttributeAnonymous` (假设没有提供具体的 crossorigin 值，默认为 anonymous)。
*   **`<script>` 标签:**
    *   **功能:** 识别 `<script>` 标签，并根据 `type` 属性判断脚本类型，例如 JavaScript 模块 (`module`)。会检查 `nomodule` 属性。
    *   **举例:**
        *   假设输入 `<script src="script.js"></script>`:  `url_to_load_` 会被设置为 "script.js"。
        *   假设输入 `<script type="module" src="module.js"></script>`:  在 `CanLoadScript()` 中会根据 `ScriptTypeAtPrepare::kModule` 进行判断。
        *   假设输入 `<script nomodule src="fallback.js"></script>`: `nomodule_attribute_value_` 会被设置为 `true`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** `<script type="module" src="app.mjs"></script>`
        *   **输出:**  在 `CanLoadScript()` 中，当 `script_type` 为 `ScriptLoader::ScriptTypeAtPrepare::kModule` 时，且 `nomodule_attribute_value_` 为 `false`，函数返回 `true`。
*   **`<img>` 标签:**
    *   **功能:** 识别 `<img>` 标签，提取 `src` 和 `srcset` 属性的值。
    *   **举例:**
        *   假设输入 `<img src="image.jpg">`: `img_src_url_` 会被设置为 "image.jpg"。
        *   假设输入 `<img srcset="image-1x.jpg 1x, image-2x.jpg 2x">`: `srcset_attribute_value_` 会被设置为 "image-1x.jpg 1x, image-2x.jpg 2x"。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** `<img src="lazy.png" loading="lazy">`
        *   **输出:** `img_src_url_ = "lazy.png"`, `loading_attr_value_ = LoadingAttributeValue::kLazy`.
*   **`<source>` 标签 (在 `<picture>` 中):**
    *   **功能:** 识别 `<source>` 标签，提取 `srcset`、`media` 和 `sizes` 属性的值，用于确定在不同条件下加载哪个图片资源。
    *   **举例:**
        *   假设输入 `<source srcset="small.jpg" media="(max-width: 600px)">`: `srcset_attribute_value_` 会被设置为 "small.jpg"，media query 会被解析并存储。
*   **`<meta>` 标签:**
    *   **功能:**  处理特定的 `<meta>` 标签，例如 `viewport` 和 `referrer`，以及与 Client Hints 相关的 `http-equiv="Accept-CH"` 和 `http-equiv="Delegate-CH"`。
    *   **举例:**
        *   假设输入 `<meta name="viewport" content="width=device-width, initial-scale=1.0">`: `HandleMetaViewport` 函数会被调用，解析 content 属性的值并更新 `media_values_`。
        *   假设输入 `<meta name="referrer" content="no-referrer">`: `HandleMetaReferrer` 函数会被调用，解析 content 属性的值并更新 `document_parameters_->referrer_policy`。
        *   假设输入 `<meta http-equiv="Accept-CH" content="viewport-width, dpr">`:  `meta_ch_values` 会存储相关信息。
*   **其他属性:**
    *   **`crossorigin`:**  使用 `GetCrossOriginAttributeValue` 解析。
    *   **`referrerpolicy`:** 使用 `SecurityPolicy::ReferrerPolicyFromString` 解析。
    *   **`fetchpriority`:** 使用 `GetFetchPriorityAttributeValue` 解析。
    *   **`nonce`:** 直接存储。
    *   **`defer` 和 `async` (在 `<script>` 标签中):**  设置 `defer_` 和 `is_async_` 标志。
    *   **`integrity`:**  设置 `integrity_attr_set_` 并解析 `integrity_metadata_`。
    *   **`loading="lazy"` (在 `<img>` 和 `<iframe>` 标签中):** 设置 `loading_attr_value_`。

**CSS:**

*   **`<link rel="stylesheet">`:**  `link_is_style_sheet_` 被设置为 `true`，表明需要加载 CSS 文件。
*   **`media` 属性 (在 `<link>` 和 `<source>` 标签中):**  `ParseSourceSize` 函数会解析 media query，并存储在 `media_values_` 中，用于判断当前条件是否匹配。CSS 预加载扫描器 (`css_scanner_`) 会根据 `scanner.GetMatched()` 的结果来判断是否匹配媒体查询。

**JavaScript:**

*   **`<script type="module">`:**  `CanLoadScript` 函数会根据 `ScriptLoader::ScriptTypeAtPrepare::kModule` 进行判断，决定是否需要预加载模块脚本。
*   **`<script nomodule>`:** `nomodule_attribute_value_` 会被设置为 `true`，用于处理不支持模块的浏览器的回退脚本。

**逻辑推理 (假设输入与输出):**

假设 HTML 片段如下：

```html
<link rel="preload" href="important.woff2" as="font" crossorigin>
<img src="header.jpg" loading="lazy">
<script src="app.js"></script>
```

1. **`<link>` 标签:**
    *   `StartTagScanner` 会识别 `<link>` 标签和属性。
    *   `link_is_preload_` 会设置为 `true`。
    *   `url_to_load_` 会设置为 "important.woff2"。
    *   `as_attribute_value_` 会设置为 "font"。
    *   `cross_origin_` 会设置为 `kCrossOriginAttributeAnonymous`。
    *   最终会创建一个 `PreloadRequest` 对象，包含这些信息。
2. **`<img>` 标签:**
    *   `StartTagScanner` 会识别 `<img>` 标签和属性。
    *   `img_src_url_` 会设置为 "header.jpg"。
    *   `loading_attr_value_` 会设置为 `LoadingAttributeValue::kLazy`。
    *   会创建一个 `PreloadRequest` 对象，但由于 `loading="lazy"`，预加载可能会被推迟或取消，具体取决于浏览器的实现和配置。
3. **`<script>` 标签:**
    *   `StartTagScanner` 会识别 `<script>` 标签和属性。
    *   `url_to_load_` 会设置为 "app.js"。
    *   会创建一个 `PreloadRequest` 对象，用于加载 JavaScript 文件。

**用户或者编程常见的使用错误举例说明:**

*   **`<link rel="preload">` 缺少 `as` 属性:**
    *   **错误:** `<link rel="preload" href="resource.js">`
    *   **说明:**  `as` 属性告知浏览器预加载资源的类型，缺少它可能导致浏览器无法正确处理预加载的资源，甚至忽略该预加载指示。
*   **`<link rel="preload">` 的 `as` 属性值不正确:**
    *   **错误:** `<link rel="preload" href="style.css" as="script">`
    *   **说明:**  `as` 属性的值必须与预加载资源的类型匹配。将 CSS 文件声明为 "script" 会导致浏览器无法正确加载和应用样式。
*   **`srcset` 属性中的 URL 拼写错误:**
    *   **错误:** `<img srcset="image1x.jpgg 1x, image2x.jpg 2x">` (注意 `image1x.jpgg`)
    *   **说明:**  URL 拼写错误会导致浏览器无法找到对应的资源，预加载失败。
*   **`media` 属性中的 media query 语法错误:**
    *   **错误:** `<source srcset="small.jpg" media="max-width: 600">` (缺少 "px")
    *   **说明:**  media query 语法错误会导致浏览器无法正确解析，预加载逻辑可能不会按预期执行。
*   **在不支持模块的浏览器中使用 `<script type="module">` 但没有提供 `<script nomodule>` 回退:**
    *   **错误:** 仅有 `<script type="module" src="module.js"></script>`
    *   **说明:**  旧版本浏览器无法识别 `type="module"`，会导致脚本无法执行。应该同时提供一个 `<script nomodule>` 标签来包含回退脚本。
*   **`integrity` 属性值错误或与资源内容不匹配:**
    *   **错误:** `<script src="library.js" integrity="sha384-incorrecthash"></script>`
    *   **说明:**  如果 `integrity` 属性值与下载资源的实际哈希值不匹配，浏览器会拒绝执行该资源，导致加载失败。

**结合第 1 部分的功能:**

这部分代码实现的 `TokenPreloadScanner` 类是 `HTMLPreloadScanner` 的核心组成部分。在第 1 部分中，`HTMLPreloadScanner` 负责从 HTML 文本流中提取 token，并将 token 传递给 `TokenPreloadScanner` 进行分析。`TokenPreloadScanner` 负责具体的标签和属性解析，创建 `PreloadRequest` 对象，这些请求会被存储起来，最终用于指导浏览器的资源预加载行为。`HTMLPreloadScanner` 还处理了整体的扫描流程和与文档相关的参数。

总而言之，`TokenPreloadScanner` 就像一个细致的侦探，专门检查 HTML 标签的各种细节，找出所有值得预先加载的宝贵资源，从而加速网页的加载速度。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_preload_scanner.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
TypeAtPrepare::kModule:
          if (ScriptLoader::BlockForNoModule(script_type,
                                             nomodule_attribute_value_)) {
            return false;
          }
      }
    }
    return true;
  }

  void ParseSourceSize(const String& attribute_value) {
    SizesAttributeParser sizes_parser(media_values_, attribute_value, nullptr);
    source_size_ = sizes_parser.Size();
    source_size_is_auto_ = sizes_parser.IsAuto();
    source_size_set_ = true;
  }

  void SetCrossOrigin(const String& cors_setting) {
    cross_origin_ = GetCrossOriginAttributeValue(cors_setting);
  }

  void SetReferrerPolicy(
      const String& attribute_value,
      ReferrerPolicyLegacyKeywordsSupport legacy_keywords_support) {
    referrer_policy_set_ = true;
    SecurityPolicy::ReferrerPolicyFromString(
        attribute_value, legacy_keywords_support, &referrer_policy_);
  }

  void SetFetchPriorityHint(const String& fetch_priority_hint) {
    fetch_priority_hint_set_ = true;
    fetch_priority_hint_ = GetFetchPriorityAttributeValue(fetch_priority_hint);
  }

  void SetNonce(const String& nonce) { nonce_ = nonce; }

  void SetDefer(FetchParameters::DeferOption defer) { defer_ = defer; }

  bool Defer() const { return defer_ != FetchParameters::kNoDefer; }

  const StringImpl* tag_impl_;
  String url_to_load_;
  ImageCandidate srcset_image_candidate_;
  String charset_;
  bool link_is_style_sheet_ = false;
  bool link_is_preconnect_ = false;
  bool link_is_preload_ = false;
  bool link_is_modulepreload_ = false;
  bool matched_ = true;
  bool input_is_image_ = false;
  String img_src_url_;
  String srcset_attribute_value_;
  String as_attribute_value_;
  String type_attribute_value_;
  String language_attribute_value_;
  String blocking_attribute_value_;
  AtomicString scopes_attribute_value_;
  AtomicString resources_attribute_value_;
  bool nomodule_attribute_value_ = false;
  float source_size_ = 0;
  bool source_size_is_auto_ = false;
  bool source_size_set_ = false;
  FetchParameters::DeferOption defer_ = FetchParameters::kNoDefer;
  CrossOriginAttributeValue cross_origin_ = kCrossOriginAttributeNotSet;
  mojom::blink::FetchPriorityHint fetch_priority_hint_ =
      mojom::blink::FetchPriorityHint::kAuto;
  bool fetch_priority_hint_set_ = false;
  String nonce_;
  MediaValuesCached* media_values_;
  bool referrer_policy_set_ = false;
  network::mojom::ReferrerPolicy referrer_policy_ =
      network::mojom::ReferrerPolicy::kDefault;
  bool integrity_attr_set_ = false;
  bool is_async_ = false;
  bool disabled_attr_set_ = false;
  IntegrityMetadataSet integrity_metadata_;
  SubresourceIntegrity::IntegrityFeatures integrity_features_;
  LoadingAttributeValue loading_attr_value_ = LoadingAttributeValue::kAuto;
  TokenPreloadScanner::ScannerType scanner_type_;
  // For explanation, see TokenPreloadScanner's declaration.
  const HashSet<String>* disabled_image_types_;
  bool attributionsrc_attr_set_ = false;
  bool shared_storage_writable_opted_in_ = false;
  std::optional<float> resource_width_;
  std::optional<float> resource_height_;
  features::LcppPreloadLazyLoadImageType preload_lazy_load_image_type_;
  bool use_data_src_attr_match_for_image_ = false;
};

TokenPreloadScanner::TokenPreloadScanner(
    const KURL& document_url,
    std::unique_ptr<CachedDocumentParameters> document_parameters,
    std::unique_ptr<MediaValuesCached::MediaValuesCachedData>
        media_values_cached_data,
    const ScannerType scanner_type,
    Vector<ElementLocator> locators)
    : document_url_(document_url),
      in_style_(false),
      in_picture_(false),
      in_script_(false),
      in_script_web_bundle_(false),
      seen_body_(false),
      seen_img_(false),
      template_count_(0),
      document_parameters_(std::move(document_parameters)),
      media_values_cached_data_(std::move(media_values_cached_data)),
      scanner_type_(scanner_type),
      lcp_element_matcher_(std::move(locators)) {
  CHECK(document_parameters_.get());
  CHECK(media_values_cached_data_.get());
  DCHECK(document_url.IsValid());
  css_scanner_.SetReferrerPolicy(document_parameters_->referrer_policy);
}

TokenPreloadScanner::~TokenPreloadScanner() = default;

static void HandleMetaViewport(
    const String& attribute_value,
    const CachedDocumentParameters* document_parameters,
    MediaValuesCached* media_values,
    std::optional<ViewportDescription>* viewport) {
  if (!document_parameters->viewport_meta_enabled)
    return;
  ViewportDescription description(ViewportDescription::kViewportMeta);
  HTMLMetaElement::GetViewportDescriptionFromContentAttribute(
      attribute_value, description, nullptr,
      document_parameters->viewport_meta_zero_values_quirk);
  if (viewport)
    *viewport = description;
  gfx::SizeF initial_viewport(media_values->DeviceWidth(),
                              media_values->DeviceHeight());
  PageScaleConstraints constraints = description.Resolve(
      initial_viewport, document_parameters->default_viewport_min_width);
  media_values->OverrideViewportDimensions(constraints.layout_size.width(),
                                           constraints.layout_size.height());
}

static void HandleMetaReferrer(const String& attribute_value,
                               CachedDocumentParameters* document_parameters,
                               CSSPreloadScanner* css_scanner) {
  network::mojom::ReferrerPolicy meta_referrer_policy =
      network::mojom::ReferrerPolicy::kDefault;
  if (!attribute_value.empty() && !attribute_value.IsNull() &&
      SecurityPolicy::ReferrerPolicyFromString(
          attribute_value, kSupportReferrerPolicyLegacyKeywords,
          &meta_referrer_policy)) {
    document_parameters->referrer_policy = meta_referrer_policy;
  }
  css_scanner->SetReferrerPolicy(document_parameters->referrer_policy);
}

void TokenPreloadScanner::HandleMetaNameAttribute(
    const HTMLToken& token,
    MetaCHValues& meta_ch_values,
    std::optional<ViewportDescription>* viewport) {
  const HTMLToken::Attribute* name_attribute =
      token.GetAttributeItem(html_names::kNameAttr);
  if (!name_attribute)
    return;

  String name_attribute_value(name_attribute->Value());
  const HTMLToken::Attribute* content_attribute =
      token.GetAttributeItem(html_names::kContentAttr);
  if (!content_attribute)
    return;

  String content_attribute_value(content_attribute->Value());
  if (EqualIgnoringASCIICase(name_attribute_value, "viewport")) {
    HandleMetaViewport(content_attribute_value, document_parameters_.get(),
                       EnsureMediaValues(), viewport);
    return;
  }

  if (EqualIgnoringASCIICase(name_attribute_value, "referrer")) {
    HandleMetaReferrer(content_attribute_value, document_parameters_.get(),
                       &css_scanner_);
  }
}

void TokenPreloadScanner::Scan(const HTMLToken& token,
                               const SegmentedString& source,
                               PreloadRequestStream& requests,
                               MetaCHValues& meta_ch_values,
                               std::optional<ViewportDescription>* viewport,
                               int* csp_meta_tag_count) {
  if (!document_parameters_->do_html_preload_scanning)
    return;

  switch (token.GetType()) {
    case HTMLToken::kCharacter: {
      if (in_style_) {
        css_scanner_.Scan(token.Data(), source, requests,
                          predicted_base_element_url_, exclusion_info_.get());
      }
      if (in_script_web_bundle_) {
        ScanScriptWebBundle(token.Data(),
                            predicted_base_element_url_.IsEmpty()
                                ? document_url_
                                : predicted_base_element_url_,
                            exclusion_info_);
      }
      return;
    }
    case HTMLToken::kEndTag: {
      const StringImpl* tag_impl = TagImplFor(token.Data());
      lcp_element_matcher_.ObserveEndTag(tag_impl);
      if (Match(tag_impl, html_names::kTemplateTag)) {
        if (template_count_)
          --template_count_;
        return;
      }
      if (template_count_) {
        return;
      }
      if (Match(tag_impl, html_names::kStyleTag)) {
        if (in_style_)
          css_scanner_.Reset();
        in_style_ = false;
        return;
      }
      if (Match(tag_impl, html_names::kScriptTag)) {
        in_script_ = false;
        in_script_web_bundle_ = false;
        return;
      }
      if (Match(tag_impl, html_names::kPictureTag)) {
        in_picture_ = false;
        picture_data_.picked = false;
      }
      return;
    }
    case HTMLToken::kStartTag: {
      const StringImpl* tag_impl = TagImplFor(token.Data());
      const bool potentially_lcp_element =
          lcp_element_matcher_.ObserveStartTagAndReportMatch(tag_impl, token);
      if (potentially_lcp_element) {
        seen_potential_lcp_element_ = true;
      }

      if (Match(tag_impl, html_names::kTemplateTag)) {
        bool is_declarative_shadow_root = false;
        const HTMLToken::Attribute* shadowrootmode_attribute =
            token.GetAttributeItem(html_names::kShadowrootmodeAttr);
        if (shadowrootmode_attribute) {
          String shadowrootmode_value(shadowrootmode_attribute->Value());
          is_declarative_shadow_root =
              EqualIgnoringASCIICase(shadowrootmode_value, "open") ||
              EqualIgnoringASCIICase(shadowrootmode_value, "closed");
        }
        // If this is a declarative shadow root <template shadowrootmode>
        // element *and* we're not already inside a non-DSD <template> element,
        // then we leave the template count at zero. Otherwise, increment it.
        if (!(is_declarative_shadow_root && !template_count_)) {
          ++template_count_;
        }
      }
      if (template_count_)
        return;
      // Don't early return, because the StartTagScanner needs to look at these
      // too.
      if (Match(tag_impl, html_names::kStyleTag)) {
        in_style_ = true;
        css_scanner_.SetInBody(seen_img_ || seen_body_);
      }
      if (Match(tag_impl, html_names::kScriptTag)) {
        in_script_ = true;

        const HTMLToken::Attribute* type_attribute =
            token.GetAttributeItem(html_names::kTypeAttr);
        if (type_attribute &&
            ScriptLoader::GetScriptTypeAtPrepare(
                type_attribute->Value(),
                /*language_attribute_value=*/g_empty_atom) ==
                ScriptLoader::ScriptTypeAtPrepare::kWebBundle) {
          in_script_web_bundle_ = true;
        }
      }
      if (Match(tag_impl, html_names::kBaseTag)) {
        // The first <base> element is the one that wins.
        if (!predicted_base_element_url_.IsEmpty())
          return;
        UpdatePredictedBaseURL(token);
        return;
      }
      if (Match(tag_impl, html_names::kMetaTag)) {
        const HTMLToken::Attribute* equiv_attribute =
            token.GetAttributeItem(html_names::kHttpEquivAttr);
        if (equiv_attribute) {
          String equiv_attribute_value(equiv_attribute->Value());
          if (EqualIgnoringASCIICase(equiv_attribute_value,
                                     "content-security-policy")) {
            ++(*csp_meta_tag_count);
          } else if (EqualIgnoringASCIICase(equiv_attribute_value,
                                            http_names::kAcceptCH)) {
            const HTMLToken::Attribute* content_attribute =
                token.GetAttributeItem(html_names::kContentAttr);
            if (content_attribute) {
              meta_ch_values.push_back(
                  MetaCHValue{.value = content_attribute->GetValue(),
                              .type = network::MetaCHType::HttpEquivAcceptCH,
                              .is_doc_preloader =
                                  scanner_type_ == ScannerType::kMainDocument});
            }
          } else if (EqualIgnoringASCIICase(equiv_attribute_value,
                                            http_names::kDelegateCH)) {
            const HTMLToken::Attribute* content_attribute =
                token.GetAttributeItem(html_names::kContentAttr);
            if (content_attribute) {
              meta_ch_values.push_back(
                  MetaCHValue{.value = content_attribute->GetValue(),
                              .type = network::MetaCHType::HttpEquivDelegateCH,
                              .is_doc_preloader =
                                  scanner_type_ == ScannerType::kMainDocument});
            }
          }
          return;
        }

        HandleMetaNameAttribute(token, meta_ch_values, viewport);
      }

      if (Match(tag_impl, html_names::kBodyTag)) {
        seen_body_ = true;
      } else if (Match(tag_impl, html_names::kImgTag)) {
        seen_img_ = true;
        if (base::FeatureList::IsEnabled(
                features::kSimplifyLoadingTransparentPlaceholderImage)) {
          // Skip trying to create a preload request if we know the image is a
          // data URI, as we do not preload data URIs anyway.
          const HTMLToken::Attribute* source_attribute =
              token.GetAttributeItem(html_names::kSrcAttr);
          if (source_attribute) {
            String source_attribute_value(source_attribute->Value());
            if (source_attribute_value.StartsWithIgnoringASCIICase("data:")) {
              return;
            }
          }
        }
      } else if (Match(tag_impl, html_names::kPictureTag)) {
        in_picture_ = true;
        picture_data_ = PictureData();
        return;
      } else if (!Match(tag_impl, html_names::kSourceTag) &&
                 !Match(tag_impl, html_names::kImgTag)) {
        // If found an "atypical" picture child, don't process it as a picture
        // child.
        in_picture_ = false;
        picture_data_.picked = false;
      }

      MediaValuesCached* media_values = EnsureMediaValues();
      StartTagScanner scanner(
          tag_impl, media_values, document_parameters_->integrity_features,
          scanner_type_, &document_parameters_->disabled_image_types,
          document_parameters_->preload_lazy_load_image_type);
      scanner.ProcessAttributes(token.Attributes());

      if (in_picture_ && media_values->Width()) {
        scanner.HandlePictureSourceURL(picture_data_);
      }
      if (in_style_) {
        css_scanner_.SetMediaMatches(scanner.GetMatched());
      }
      std::unique_ptr<PreloadRequest> request = scanner.CreatePreloadRequest(
          predicted_base_element_url_, picture_data_, *document_parameters_,
          exclusion_info_.get(), seen_img_ || seen_body_,
          potentially_lcp_element);
      if (request) {
        request->SetInitiatorPosition(
            TextPosition(source.CurrentLine(), source.CurrentColumn()));
        request->SetIsPotentiallyLCPElement(potentially_lcp_element);
        requests.push_back(std::move(request));
      }
      return;
    }
    default: {
      return;
    }
  }
}

void TokenPreloadScanner::UpdatePredictedBaseURL(const HTMLToken& token) {
  DCHECK(predicted_base_element_url_.IsEmpty());
  if (const HTMLToken::Attribute* href_attribute =
          token.GetAttributeItem(html_names::kHrefAttr)) {
    KURL url(document_url_,
             StripLeadingAndTrailingHTMLSpaces(href_attribute->Value()));
    bool is_valid_base_url =
        url.IsValid() && !url.ProtocolIsData() && !url.ProtocolIsJavaScript();
    predicted_base_element_url_ = is_valid_base_url ? url : KURL();
  }
}

// static
std::unique_ptr<HTMLPreloadScanner> HTMLPreloadScanner::Create(
    Document& document,
    HTMLParserOptions options,
    TokenPreloadScanner::ScannerType scanner_type) {
  Vector<ElementLocator> locators;
  if (LocalFrame* frame = document.GetFrame()) {
    if (LCPCriticalPathPredictor* lcpp = frame->GetLCPP()) {
      locators = lcpp->lcp_element_locators();
    }
  }

  bool skip_preload_scan = IsSkipPreloadScanEnabled(&document);
  if (skip_preload_scan) {
    UseCounter::Count(document, WebFeature::kSkippedPreloadScanning);
  }

  return std::make_unique<HTMLPreloadScanner>(
      std::make_unique<HTMLTokenizer>(options), document.Url(),
      std::make_unique<CachedDocumentParameters>(&document),
      std::make_unique<MediaValuesCached::MediaValuesCachedData>(document),
      scanner_type, /* script_token_scanner=*/nullptr, TakePreloadFn(),
      std::move(locators), skip_preload_scan);
}

// static
bool HTMLPreloadScanner::IsSkipPreloadScanEnabled(const Document* document) {
  if (const auto* context = document->GetExecutionContext()) {
    if (RuntimeEnabledFeatures::SkipPreloadScanningEnabled(context)) {
      return true;
    }
  }
  return false;
}

// static
HTMLPreloadScanner::BackgroundPtr HTMLPreloadScanner::CreateBackground(
    HTMLDocumentParser* parser,
    HTMLParserOptions options,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    TakePreloadFn take_preload) {
  auto* document = parser->GetDocument();

  Vector<ElementLocator> locators;
  if (LocalFrame* frame = document->GetFrame()) {
    if (LCPCriticalPathPredictor* lcpp = frame->GetLCPP()) {
      locators = lcpp->lcp_element_locators();
    }
  }

  bool skip_preload_scan = IsSkipPreloadScanEnabled(document);
  if (skip_preload_scan) {
    UseCounter::Count(document, WebFeature::kSkippedPreloadScanning);
  }

  return BackgroundPtr(
      new HTMLPreloadScanner(
          std::make_unique<HTMLTokenizer>(options), document->Url(),
          std::make_unique<CachedDocumentParameters>(document),
          std::make_unique<MediaValuesCached::MediaValuesCachedData>(*document),
          TokenPreloadScanner::ScannerType::kMainDocument,
          BackgroundHTMLScanner::ScriptTokenScanner::Create(parser),
          std::move(take_preload), std::move(locators), skip_preload_scan),
      Deleter{task_runner});
}

HTMLPreloadScanner::HTMLPreloadScanner(
    std::unique_ptr<HTMLTokenizer> tokenizer,
    const KURL& document_url,
    std::unique_ptr<CachedDocumentParameters> document_parameters,
    std::unique_ptr<MediaValuesCached::MediaValuesCachedData>
        media_values_cached_data,
    const TokenPreloadScanner::ScannerType scanner_type,
    std::unique_ptr<BackgroundHTMLScanner::ScriptTokenScanner>
        script_token_scanner,
    TakePreloadFn take_preload,
    Vector<ElementLocator> locators,
    bool skip_preload_scanning)
    : scanner_(document_url,
               std::move(document_parameters),
               std::move(media_values_cached_data),
               scanner_type,
               std::move(locators)),
      tokenizer_(std::move(tokenizer)),
      script_token_scanner_(std::move(script_token_scanner)),
      take_preload_(std::move(take_preload)),
      skip_preload_scanning_(skip_preload_scanning) {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLPreloadScanner::HTMLPreloadScanner",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_OUT);
}

HTMLPreloadScanner::~HTMLPreloadScanner() {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLPreloadScanner::~HTMLPreloadScanner",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_IN);
}

void HTMLPreloadScanner::AppendToEnd(const SegmentedString& source) {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLPreloadScanner::AppendToEnd",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  source_.Append(source);
}

std::unique_ptr<PendingPreloadData> HTMLPreloadScanner::Scan(
    const KURL& starting_base_element_url) {
  auto pending_data = std::make_unique<PendingPreloadData>();

  if (skip_preload_scanning_) {
    // Skip PreloadScan origin trial is enabled.
    return pending_data;
  }

  TRACE_EVENT_WITH_FLOW1("blink", "HTMLPreloadScanner::scan",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "source_length", source_.length());

  // When we start scanning, our best prediction of the baseElementURL is the
  // real one!
  if (!starting_base_element_url.IsEmpty())
    scanner_.SetPredictedBaseElementURL(starting_base_element_url);

  // The script scanner needs to know whether this is the first script in the
  // chunk being scanned, since it may have different script compile behavior
  // depending on this.
  if (script_token_scanner_)
    script_token_scanner_->set_first_script_in_scan(true);

  while (HTMLToken* token = tokenizer_->NextToken(source_)) {
    if (token->GetType() == HTMLToken::kStartTag)
      tokenizer_->UpdateStateFor(*token);
    int csp_meta_tag_count = 0;
    scanner_.Scan(*token, source_, pending_data->requests,
                  pending_data->meta_ch_values, &pending_data->viewport,
                  &csp_meta_tag_count);
    if (script_token_scanner_)
      script_token_scanner_->ScanToken(*token);
    pending_data->csp_meta_tag_count += csp_meta_tag_count;
    token->Clear();

    if (!RuntimeEnabledFeatures::AllowPreloadingWithCSPMetaTagEnabled()) {
      // Don't preload anything if a CSP meta tag is found. We should rarely
      // find them here because the HTMLPreloadScanner is only used for the
      // synchronous parsing path.
      CHECK(csp_meta_tag_count >= 0);
      if (csp_meta_tag_count) {
        // Reset the tokenizer, to avoid re-scanning tokens that we are about to
        // start parsing.
        source_.Clear();
        tokenizer_->Reset();
        return pending_data;
      }
    }

    // Incrementally add preloads when scanning in the background.
    if (take_preload_ && !pending_data->requests.empty()) {
      take_preload_.Run(std::move(pending_data));
      pending_data = std::make_unique<PendingPreloadData>();
    }
  }

  pending_data->has_located_potential_lcp_element =
      scanner_.HasLocatedPotentialLcpElement();

  return pending_data;
}

void HTMLPreloadScanner::ScanInBackground(
    const String& source,
    const KURL& document_base_element_url) {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLPreloadScanner::ScanInBackground",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  source_.Append(source);
  take_preload_.Run(Scan(document_base_element_url));
}

CachedDocumentParameters::CachedDocumentParameters(Document* document) {
  DCHECK(IsMainThread());
  DCHECK(document);
  do_html_preload_scanning =
      !document->GetSettings() ||
      document->GetSettings()->GetDoHtmlPreloadScanning();
  default_viewport_min_width =
      document->GetViewportData().ViewportDefaultMinWidth();
  viewport_meta_zero_values_quirk =
      document->GetSettings() &&
      document->GetSettings()->GetViewportMetaZeroValuesQuirk();
  viewport_meta_enabled = document->GetSettings() &&
                          document->GetSettings()->GetViewportMetaEnabled();
  referrer_policy = document->GetReferrerPolicy();
  integrity_features =
      SubresourceIntegrityHelper::GetFeatures(document->GetExecutionContext());
  if (document->Loader() && document->Loader()->GetFrame()) {
    lazy_load_image_setting =
        document->Loader()->GetFrame()->GetLazyLoadImageSetting();
  } else {
    lazy_load_image_setting = LocalFrame::LazyLoadImageSetting::kDisabled;
  }
  const features::LcppPreloadLazyLoadImageType
      kPreloadLazyLoadImageType =
          features::kLCPCriticalPathPredictorPreloadLazyLoadImageType.Get();
  preload_lazy_load_image_type =
      preload_lazy_load_image_type_for_testing.has_value()
          ? preload_lazy_load_image_type_for_testing.value()
          : kPreloadLazyLoadImageType;
  probe::GetDisabledImageTypes(document->GetExecutionContext(),
                               &disabled_image_types);
}

// static
std::optional<features::LcppPreloadLazyLoadImageType>
    CachedDocumentParameters::preload_lazy_load_image_type_for_testing =
        std::nullopt;
// static
void CachedDocumentParameters::SetLcppPreloadLazyLoadImageTypeForTesting(
    std::optional<features::LcppPreloadLazyLoadImageType> type) {
  preload_lazy_load_image_type_for_testing = type;
}

}  // namespace blink
```