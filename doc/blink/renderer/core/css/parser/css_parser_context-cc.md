Response:
Let's break down the thought process for analyzing the `CSSParserContext.cc` file and generating the comprehensive explanation.

**1. Understanding the Goal:**

The primary goal is to understand the *purpose* and *functionality* of the `CSSParserContext` class in the Blink rendering engine. This involves figuring out what information it holds and how that information is used during CSS parsing. The request also emphasizes connections to HTML, CSS, and JavaScript, common errors, debugging, and logical inference.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for key terms and patterns:

* **Class Name:** `CSSParserContext` - This immediately suggests it's about the context in which CSS parsing happens.
* **Constructor Overloads:**  Multiple constructors taking different arguments hint at various ways this context can be created, reflecting different scenarios.
* **Member Variables:**  `base_url_`, `origin_clean_`, `charset_`, `mode_`, `referrer_`, `is_html_document_`, `secure_context_mode_`, `world_`, `document_`, `resource_fetch_restriction_`, `is_ad_related_`. These are the core data the context holds.
* **Methods:**  `CompleteURL`, `CompleteNonEmptyURL`, `Count`, `CountDeprecation`, `IsOriginClean`, `IsSecureContext`, `GetDocument`, `GetExecutionContext`, `IsForMarkupSanitization`, `operator==`. These are the actions the context supports.
* **Includes:**  The included header files provide clues about related functionalities (e.g., `CSSStyleSheet`, `HTMLDocument`, `ContentSecurityPolicy`, `ExecutionContext`).
* **`DEFINE_THREAD_SAFE_STATIC_LOCAL`:**  This indicates a singleton-like pattern for `StrictCSSParserContext`.
* **Comments:** The comments, though brief, offer some insights (e.g., the TODO about returning a const reference).
* **Namespaces:** The code is within the `blink` namespace, confirming it's part of the Blink engine.

**3. Inferring Functionality from Member Variables:**

This is a crucial step. By looking at the member variables, we can deduce what aspects of the parsing process the `CSSParserContext` manages:

* **`base_url_`:**  The base URL is fundamental for resolving relative URLs in CSS.
* **`origin_clean_`:**  Indicates if the origin is considered "clean," which is important for security and cross-origin restrictions.
* **`charset_`:**  The character encoding is necessary to interpret the CSS correctly.
* **`mode_`:**  The parsing mode (e.g., quirks mode, standard mode) affects how CSS is interpreted.
* **`referrer_`:**  The referrer policy influences how the referring URL is sent in requests for CSS resources.
* **`is_html_document_`:**  Indicates if the context is associated with an HTML document, which can affect parsing behavior.
* **`secure_context_mode_`:**  Determines if the context is considered secure, impacting features like accessing certain APIs.
* **`world_`:**  Relates to isolated worlds in extensions and user scripts.
* **`document_`:**  A pointer to the associated document, providing access to document-level information.
* **`resource_fetch_restriction_`:**  Controls how CSS resources can be fetched, influencing security and performance.
* **`is_ad_related_`:**  Potentially used for ad-specific CSS handling or restrictions.

**4. Analyzing Methods:**

The methods provide concrete actions and further clarify the class's role:

* **Constructors:**  Show how `CSSParserContext` instances are created in different scenarios. The various constructor overloads reveal that the context can be initialized with information from existing contexts, style sheets, documents, or execution contexts.
* **`CompleteURL` and `CompleteNonEmptyURL`:** Clearly related to resolving URLs, a core CSS parsing task.
* **`Count` and `CountDeprecation`:** Indicate the class is involved in tracking usage of CSS features and deprecated features for metrics and compatibility analysis.
* **`IsOriginClean` and `IsSecureContext`:** Accessors for key security-related properties.
* **`GetDocument` and `GetExecutionContext`:** Allow access to related document and execution context information.
* **`IsForMarkupSanitization`:** Suggests a use case in sanitizing HTML, potentially involving CSS filtering.
* **`operator==`:** Defines how to compare two `CSSParserContext` objects for equality.
* **`StrictCSSParserContext`:** The static method for obtaining a strict parsing context, which is likely used in situations requiring a default, controlled environment.

**5. Connecting to HTML, CSS, and JavaScript:**

With the understanding of the class's members and methods, it's possible to draw connections to the core web technologies:

* **HTML:** The `document_` member and the `is_html_document_` flag directly link the context to HTML documents. The parsing mode (quirks vs. standard) is also HTML-related.
* **CSS:** This is the primary domain. The class manages crucial information needed to parse CSS correctly (URLs, charset, parsing mode, etc.). The `Count` methods directly relate to CSS features and properties.
* **JavaScript:**  The `ExecutionContext` link, the `world_` member (related to extension scripts), and the ability to influence resource fetching connect the context to the JavaScript environment. JavaScript can manipulate CSS, and the parsing context ensures consistency.

**6. Developing Examples and Scenarios:**

To make the explanation concrete, it's important to create illustrative examples:

* **URL Resolution:** Demonstrate how `CompleteURL` works with different base URLs and relative URLs.
* **Parsing Modes:** Show the difference between standard and quirks mode, though the code doesn't directly *implement* the parsing logic.
* **Security Context:** Explain how secure context affects parsing.
* **Common Errors:** Highlight potential mistakes related to incorrect base URLs or character encodings.

**7. Considering Debugging:**

Thinking about how a developer might end up inspecting this code is helpful:

* **CSS Loading Issues:** Problems with CSS not loading or rendering correctly are a likely trigger.
* **Security Errors:** CSP violations or mixed content issues might lead to investigating the parsing context.
* **Feature Detection:** Trying to understand why a specific CSS feature isn't working as expected could involve examining the context.

**8. Structuring the Explanation:**

Organizing the information logically is crucial for clarity:

* **Overview/Purpose:** Start with a high-level summary of the class's function.
* **Key Responsibilities:** Break down the core tasks.
* **Relationship to Technologies:** Explicitly connect to HTML, CSS, and JavaScript.
* **Logical Inference:** Provide concrete examples with inputs and outputs.
* **Common Errors:**  Highlight potential pitfalls.
* **Debugging:** Explain how the context can be relevant for debugging.

**9. Refinement and Review:**

After drafting the initial explanation, review it for accuracy, completeness, and clarity. Ensure the language is precise and easy to understand. Check if all aspects of the prompt have been addressed. For example, I initially missed emphasizing the use of `CSSParserContext` in different scenarios (style sheets, inline styles, etc.), which was added during the refinement process.

By following these steps, a comprehensive and informative explanation of the `CSSParserContext.cc` file can be generated. The process involves understanding the code, inferring its purpose, connecting it to broader concepts, and illustrating its functionality with examples.## 对 blink/renderer/core/css/parser/css_parser_context.cc 的功能分析

`blink/renderer/core/css/parser/css_parser_context.cc` 文件定义了 `CSSParserContext` 类，这个类在 Chromium Blink 引擎的 CSS 解析过程中扮演着至关重要的角色。它的主要功能是 **为 CSS 解析器提供解析时所需的上下文信息**。

**具体功能列举：**

1. **存储 CSS 解析的基础信息：**
    * **Base URL (`base_url_`)：** 用于解析 CSS 中相对 URL 的基础地址。
    * **Origin Clean 状态 (`origin_clean_`)：** 指示文档的来源是否被认为是“干净的”（例如，通过 `data:` URL 加载的资源不是 origin-clean）。这会影响某些 CSS 特性的行为。
    * **字符编码 (`charset_`)：** 用于解码 CSS 文件内容。
    * **解析模式 (`mode_`)：** 指示 CSS 的解析模式，例如 `kHTMLStandardMode`（标准模式）或 `kHTMLQuirksMode`（怪异模式）。这会影响某些 CSS 语法的解析规则。
    * **Referrer (`referrer_`)：** 用于控制 CSS 资源请求时的 Referer 请求头。
    * **是否为 HTML 文档 (`is_html_document_`)：** 区分 CSS 是否在 HTML 文档的上下文中解析，这可能影响某些行为。
    * **安全上下文模式 (`secure_context_mode_`)：** 指示当前上下文是否为安全上下文（HTTPS）。某些 CSS 特性可能只在安全上下文中可用。
    * **World (`world_`)：**  与扩展或用户脚本的隔离 World 相关。
    * **关联的 Document (`document_`)：**  指向与当前 CSS 解析相关的 `Document` 对象，允许访问文档级别的属性和功能。
    * **资源获取限制 (`resource_fetch_restriction_`)：** 用于限制 CSS 中资源的获取方式，例如阻止从混合内容上下文中加载资源。
    * **是否与广告相关 (`is_ad_related_`)：**  指示当前 CSS 是否与广告相关，可能影响某些处理或限制。

2. **提供便捷的方法访问和操作上下文信息：**
    * **构造函数：** 提供了多种构造函数，允许根据不同的场景创建 `CSSParserContext` 对象，例如从已有的上下文、样式表、文档等创建。
    * **访问器方法：** 提供 `IsOriginClean()`, `IsSecureContext()`, `GetDocument()`, `GetExecutionContext()` 等方法用于获取上下文信息。
    * **URL 完成方法：** `CompleteURL(const String& url)` 和 `CompleteNonEmptyURL(const String& url)` 方法用于将相对 URL 解析为绝对 URL，并考虑了字符编码。
    * **使用计数方法：** `Count(WebFeature feature)`, `CountDeprecation(WebFeature feature)`, `Count(CSSParserMode mode, CSSPropertyID property)` 方法用于记录 CSS 特性和属性的使用情况，用于统计和分析。

3. **支持严格的 CSS 解析上下文：**
    * `StrictCSSParserContext(SecureContextMode secure_context_mode)` 方法返回一个预定义的、严格的 CSS 解析上下文，通常用于不需要特定文档上下文的场景。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML：**
    * **关系：** `CSSParserContext` 通常与一个特定的 HTML `Document` 对象关联。HTML 中的 `<style>` 标签或外部 CSS 文件链接 (`<link rel="stylesheet">`) 会触发 CSS 解析，并创建一个与该 HTML 文档相关的 `CSSParserContext`。
    * **举例：** 当浏览器解析一个包含 `<link rel="stylesheet" href="style.css">` 的 HTML 文件时，会创建一个 `CSSParserContext` 对象，其 `base_url_` 会被设置为 HTML 文件的 URL，用于解析 `style.css` 中的相对路径。`is_html_document_` 会被设置为 `true`。如果 HTML 文档处于怪异模式，`mode_` 也会相应设置为 `kHTMLQuirksMode`。

* **CSS：**
    * **关系：** `CSSParserContext` 是 CSS 解析过程的核心上下文。解析器使用其中的信息来理解 CSS 规则的含义，例如如何解析 URL、处理字符编码、应用特定的解析规则等。
    * **举例：** 在 CSS 文件 `background-image: url('images/logo.png');` 中，`CSSParserContext` 的 `base_url_` 决定了 `images/logo.png` 被解析成哪个具体的 URL。如果 `charset_` 设置错误，CSS 文件中的非 ASCII 字符可能无法正确解析。`mode_` 的不同可能导致对某些 CSS hack 的处理方式不同。

* **JavaScript：**
    * **关系：** JavaScript 可以动态创建和修改 CSS 样式。例如，通过 `document.createElement('style')` 创建的 `<style>` 元素或通过 `element.style.setProperty()` 设置的内联样式，在解析时也会使用 `CSSParserContext`。此外，JavaScript 可以访问和修改文档的 `baseURI`，这会影响后续 CSS 的 URL 解析。
    * **举例：** 当 JavaScript 代码执行 `document.head.innerHTML = '<style>body { background-image: url("new_bg.jpg"); }</style>';` 时，浏览器会创建一个 `CSSParserContext`，其 `base_url_` 通常是当前文档的 URL，用于解析 `"new_bg.jpg"`。如果 JavaScript 运行在特定的 `DOMWrapperWorld` 中（例如，扩展的隔离世界），`world_` 属性也会被相应设置。

**逻辑推理 (假设输入与输出)：**

**假设输入：**

1. **场景：** 解析一个通过 `data:` URL 加载的 CSS 样式表：
    ```html
    <link rel="stylesheet" href="data:text/css;base64,Ym9keSB7IGJhY2tncm91bmQtY29sb3I6IHJlZDsgfQ==">
    ```
2. **相关信息：** 加载该 HTML 页面的 URL 为 `https://example.com/page.html`。

**逻辑推理与输出：**

*   **`base_url_`：**  会是 `data:text/css;base64,Ym9keSB7IGJhY2tncm91bmQtY29sb3I6IHJlZDsgfQ==` 本身，因为 `data:` URL 没有可以作为基础的路径部分。
*   **`origin_clean_`：** 将为 `false`，因为 `data:` URL 被认为是 opaque origin，不是 origin-clean。
*   **`charset_`：** 可能会根据 HTTP 头部或默认值进行推断，如果没有指定，可能是默认的 UTF-8。
*   **`mode_`：** 取决于包含该 `link` 标签的 HTML 文档的解析模式。
*   **`secure_context_mode_`：** 将继承包含该 `link` 标签的 HTML 文档的安全上下文，如果 `https://example.com/page.html` 是 HTTPS，则为 `kSecureContext`。

**假设输入：**

1. **场景：** 解析一个外部 CSS 文件，其中包含一个相对 URL 引用图片：
    *   CSS 文件 `style.css` 的内容： `background-image: url('../images/logo.png');`
    *   `style.css` 文件的 URL： `https://example.com/css/style.css`

**逻辑推理与输出：**

*   **`base_url_`：** 将为 `https://example.com/css/`，因为基础 URL 是 CSS 文件本身的 URL。
*   **`CompleteURL('../images/logo.png')` 的输出：**  将是 `https://example.com/images/logo.png`，通过将相对路径与 `base_url_` 拼接得到。

**用户或编程常见的使用错误及举例说明：**

1. **错误的 Base URL：**
    *   **错误场景：** 在某些特殊情况下（例如，使用 Shadow DOM 或 Service Worker），如果没有正确地设置或传递 `CSSParserContext`，可能导致 `base_url_` 不正确。
    *   **后果：** CSS 文件中的相对 URL 解析错误，导致图片、字体等资源加载失败。
    *   **调试线索：** 检查网络请求，看请求的资源路径是否正确。查看控制台是否有关于资源加载失败的错误信息。

2. **错误的字符编码：**
    *   **错误场景：** CSS 文件使用的字符编码与 `CSSParserContext` 中设置的 `charset_` 不一致。
    *   **后果：** CSS 文件中的非 ASCII 字符（例如中文、日文）显示为乱码或无法正确解析，导致样式错误。
    *   **调试线索：** 检查 CSS 文件的实际编码和 HTTP 头部中指定的编码是否一致。在浏览器开发者工具中查看 CSS 内容是否显示正常。

3. **在错误的安全上下文中使用需要安全上下文的 CSS 特性：**
    *   **错误场景：** 在非安全上下文（HTTP）中使用某些 CSS 特性，例如某些涉及到设备访问的 API 或需要 secure context 的功能。
    *   **后果：** 这些 CSS 特性可能被禁用或行为异常。
    *   **调试线索：** 检查浏览器的安全警告，查看控制台是否有关于安全上下文的错误信息。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览一个网页时发现 CSS 样式没有正确加载，或者某些样式规则没有生效。作为开发者，在进行调试时，可能会按以下步骤追踪到 `CSSParserContext`：

1. **检查网络请求：** 在浏览器开发者工具的 "Network" 面板中查看 CSS 文件的请求状态，确保文件成功加载。如果加载失败，问题可能出在网络层面，与 `CSSParserContext` 的关系较远。

2. **查看 CSS 内容：** 如果 CSS 文件加载成功，检查 "Elements" 面板中 Computed 样式或查看 Sources 面板中的 CSS 文件内容，确认 CSS 代码是否正确。

3. **检查是否有解析错误：** 浏览器的开发者工具通常会在 "Console" 面板中显示 CSS 解析错误。这些错误信息可能指示了哪些 CSS 规则无法被正确解析。

4. **定位到具体的 CSS 规则：**  如果存在解析错误，根据错误信息定位到具体的 CSS 规则。

5. **分析 URL 解析问题：** 如果问题涉及到背景图片、字体等资源的加载失败，怀疑是 URL 解析问题。此时，开发者可能会想知道浏览器是如何解析 CSS 中的 URL 的。

6. **进入 Blink 源码进行调试：**  为了深入了解 URL 解析过程，开发者可能会设置断点在 Blink 引擎的 CSS 解析相关代码中，例如 `CSSParser::parseValue()` 或 `CSSParserContext::CompleteURL()` 等方法。

7. **查看 `CSSParserContext` 的实例：** 在断点处，开发者可以查看当前的 `CSSParserContext` 实例，检查其 `base_url_`, `charset_` 等属性是否符合预期，从而判断是否是上下文信息导致了解析问题。

**总结：**

`CSSParserContext` 类在 Blink 引擎的 CSS 解析流程中扮演着核心角色，它为解析器提供了必要的上下文信息，确保 CSS 能够被正确地理解和应用。理解 `CSSParserContext` 的功能和作用对于调试 CSS 相关问题至关重要。通过分析其包含的信息和提供的功能，我们可以更好地理解 CSS 的解析过程，并有效地定位和解决问题。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"

#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/style_rule_keyframe.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

CSSParserContext::CSSParserContext(const CSSParserContext* other,
                                   const CSSStyleSheet* style_sheet)
    : CSSParserContext(other, CSSStyleSheet::SingleOwnerDocument(style_sheet)) {
}

CSSParserContext::CSSParserContext(
    const CSSParserContext* other,
    const StyleSheetContents* style_sheet_contents)
    : CSSParserContext(
          other,
          StyleSheetContents::SingleOwnerDocument(style_sheet_contents)) {}

CSSParserContext::CSSParserContext(const CSSParserContext* other,
                                   const Document* use_counter_document)
    : CSSParserContext(other->base_url_,
                       other->origin_clean_,
                       other->charset_,
                       other->mode_,
                       other->referrer_,
                       other->is_html_document_,
                       other->secure_context_mode_,
                       other->world_,
                       use_counter_document,
                       other->resource_fetch_restriction_) {
  is_ad_related_ = other->is_ad_related_;
}

CSSParserContext::CSSParserContext(const CSSParserContext* other,
                                   const KURL& base_url,
                                   bool origin_clean,
                                   const Referrer& referrer,
                                   const WTF::TextEncoding& charset,
                                   const Document* use_counter_document)
    : CSSParserContext(base_url,
                       origin_clean,
                       charset,
                       other->mode_,
                       referrer,
                       other->is_html_document_,
                       other->secure_context_mode_,
                       other->world_,
                       use_counter_document,
                       other->resource_fetch_restriction_) {
  is_ad_related_ = other->is_ad_related_;
}

CSSParserContext::CSSParserContext(CSSParserMode mode,
                                   SecureContextMode secure_context_mode,
                                   const Document* use_counter_document)
    : CSSParserContext(KURL(),
                       true /* origin_clean */,
                       WTF::TextEncoding(),
                       mode,
                       Referrer(),
                       false,
                       secure_context_mode,
                       nullptr,
                       use_counter_document,
                       ResourceFetchRestriction::kNone) {}

CSSParserContext::CSSParserContext(const Document& document)
    : CSSParserContext(document, document.BaseURL()) {}

CSSParserContext::CSSParserContext(const Document& document,
                                   const KURL& base_url_override)
    : CSSParserContext(
          document,
          base_url_override,
          true /* origin_clean */,
          Referrer(document.GetExecutionContext()
                       ? document.GetExecutionContext()->OutgoingReferrer()
                       : String(),  // GetExecutionContext() only returns null
                                    // in tests.
                   document.GetReferrerPolicy())) {}

CSSParserContext::CSSParserContext(
    const Document& document,
    const KURL& base_url_override,
    bool origin_clean,
    const Referrer& referrer,
    const WTF::TextEncoding& charset,
    enum ResourceFetchRestriction resource_fetch_restriction)
    : CSSParserContext(
          base_url_override,
          origin_clean,
          charset,
          document.InQuirksMode() ? kHTMLQuirksMode : kHTMLStandardMode,
          referrer,
          IsA<HTMLDocument>(document),
          document.GetExecutionContext()
              ? document.GetExecutionContext()->GetSecureContextMode()
              : SecureContextMode::kInsecureContext,
          document.GetExecutionContext()
              ? document.GetExecutionContext()->GetCurrentWorld()
              : nullptr,
          &document,
          resource_fetch_restriction) {}

CSSParserContext::CSSParserContext(const ExecutionContext& context)
    : CSSParserContext(context.Url(),
                       true /* origin_clean */,
                       WTF::TextEncoding(),
                       kHTMLStandardMode,
                       Referrer(context.Url().StrippedForUseAsReferrer(),
                                context.GetReferrerPolicy()),
                       true,
                       context.GetSecureContextMode(),
                       context.GetCurrentWorld(),
                       IsA<LocalDOMWindow>(&context)
                           ? To<LocalDOMWindow>(context).document()
                           : nullptr,
                       ResourceFetchRestriction::kNone) {}

CSSParserContext::CSSParserContext(
    const KURL& base_url,
    bool origin_clean,
    const WTF::TextEncoding& charset,
    CSSParserMode mode,
    const Referrer& referrer,
    bool is_html_document,
    SecureContextMode secure_context_mode,
    const DOMWrapperWorld* world,
    const Document* use_counter_document,
    enum ResourceFetchRestriction resource_fetch_restriction)
    : base_url_(base_url),
      world_(world),
      origin_clean_(origin_clean),
      mode_(mode),
      referrer_(referrer),
      is_html_document_(is_html_document),
      secure_context_mode_(secure_context_mode),
      document_(use_counter_document),
      resource_fetch_restriction_(resource_fetch_restriction) {
  if (!RuntimeEnabledFeatures::CSSParserIgnoreCharsetForURLsEnabled()) {
    charset_ = charset;
  }
}

bool CSSParserContext::operator==(const CSSParserContext& other) const {
  return base_url_ == other.base_url_ && origin_clean_ == other.origin_clean_ &&
         charset_ == other.charset_ && mode_ == other.mode_ &&
         is_ad_related_ == other.is_ad_related_ &&
         is_html_document_ == other.is_html_document_ &&
         secure_context_mode_ == other.secure_context_mode_ &&
         resource_fetch_restriction_ == other.resource_fetch_restriction_;
}

// TODO(xiaochengh): This function never returns null. Change it to return a
// const reference to avoid confusion.
const CSSParserContext* StrictCSSParserContext(
    SecureContextMode secure_context_mode) {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ThreadSpecific<Persistent<CSSParserContext>>,
                                  strict_context_pool, ());
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ThreadSpecific<Persistent<CSSParserContext>>,
                                  secure_strict_context_pool, ());

  Persistent<CSSParserContext>& context =
      secure_context_mode == SecureContextMode::kSecureContext
          ? *secure_strict_context_pool
          : *strict_context_pool;
  if (!context) {
    context = MakeGarbageCollected<CSSParserContext>(kHTMLStandardMode,
                                                     secure_context_mode);
    LEAK_SANITIZER_IGNORE_OBJECT(&context);
  }

  return context;
}

bool CSSParserContext::IsOriginClean() const {
  return origin_clean_;
}

bool CSSParserContext::IsSecureContext() const {
  return secure_context_mode_ == SecureContextMode::kSecureContext;
}

KURL CSSParserContext::CompleteURL(const String& url) const {
  if (url.IsNull()) {
    return KURL();
  }
  if (!Charset().IsValid()) {
    return KURL(BaseURL(), url);
  }
  return KURL(BaseURL(), url, Charset());
}

KURL CSSParserContext::CompleteNonEmptyURL(const String& url) const {
  if (url.empty() && !url.IsNull()) {
    return KURL(g_empty_string);
  }
  return CompleteURL(url);
}

void CSSParserContext::Count(WebFeature feature) const {
  if (IsUseCounterRecordingEnabled()) {
    document_->CountUse(feature);
  }
}

void CSSParserContext::CountDeprecation(WebFeature feature) const {
  if (IsUseCounterRecordingEnabled() && document_) {
    Deprecation::CountDeprecation(document_->GetExecutionContext(), feature);
  }
}

void CSSParserContext::Count(CSSParserMode mode, CSSPropertyID property) const {
  if (IsUseCounterRecordingEnabled() && IsUseCounterEnabledForMode(mode)) {
    document_->CountProperty(property);
  }
}

bool CSSParserContext::IsDocumentHandleEqual(const Document* other) const {
  return document_.Get() == other;
}

const Document* CSSParserContext::GetDocument() const {
  return document_.Get();
}

// Fuzzers may execution CSS parsing code without a Document being available,
// thus this method can return null.
ExecutionContext* CSSParserContext::GetExecutionContext() const {
  return (document_.Get()) ? document_.Get()->GetExecutionContext() : nullptr;
}

bool CSSParserContext::IsForMarkupSanitization() const {
  return document_ && document_->IsForMarkupSanitization();
}

void CSSParserContext::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(world_);
}

}  // namespace blink
```