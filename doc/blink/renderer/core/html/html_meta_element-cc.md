Response:
Let's break down the thought process to arrive at the comprehensive answer about `HTMLMetaElement.cc`.

1. **Understand the Core Task:** The primary goal is to explain the functionality of the `HTMLMetaElement.cc` file in the Blink rendering engine, focusing on its relationships with HTML, CSS, and JavaScript, and highlighting potential user/developer errors.

2. **Identify the Subject:** The file is named `html_meta_element.cc`, so the central theme is the `<meta>` HTML element. This element is crucial for providing metadata about an HTML document.

3. **Scan the Code for Key Areas:**  A quick scan reveals several distinct sections and patterns:
    * **Includes:** These tell us about dependencies and related functionalities (e.g., `css/style_engine.h`, `dom/document.h`, `frame/settings.h`, `loader/http_equiv.h`).
    * **Class Definition:**  The `HTMLMetaElement` class is the main focus.
    * **Parsing Functions:**  Functions like `ParseViewportContentAttribute`, `ProcessViewportKeyValuePair`, `ParseViewportValueAsLength`, etc., indicate the file's role in interpreting the `content` attribute of `<meta>` tags.
    * **Specific Attribute Handling:**  Sections dealing with `name`, `content`, `http-equiv`, and `property` attributes are present.
    * **Viewport Logic:** A significant portion is dedicated to processing the `viewport` meta tag.
    * **`http-equiv` Processing:** The `ProcessHttpEquiv` function signals handling of HTTP header equivalents.
    * **Client Hints:** The presence of `ProcessMetaCH` suggests involvement in client hints.
    * **Error Handling and Warnings:**  Functions like `ReportViewportWarning` indicate how parsing errors are handled.
    * **Use Counters:**  References to `UseCounter::Count` suggest tracking of feature usage.

4. **Categorize Functionality:** Based on the scan, we can group the functionalities:
    * **Core Meta Tag Processing:** Handling of `name`, `content`, `property` attributes for various metadata purposes.
    * **Viewport Configuration:**  Parsing and applying settings from the `viewport` meta tag.
    * **HTTP Header Equivalents:** Processing `http-equiv` attributes.
    * **Client Hints:** Handling `http-equiv` for client hints.
    * **Error Reporting:**  Generating warnings for invalid meta tag configurations.

5. **Detail Each Category with Examples and Relationships:**

    * **Core Meta Tag Processing:**
        * **Description:** Explain how it provides document descriptions.
        * **Keywords:** Illustrate its use for SEO.
        * **Author:**  Show how it identifies the author.
        * **Character Set:**  Explain its role in encoding. *Crucially connect this to HTML rendering.*
        * **Theme Color:** Explain how it affects the browser UI. *Connect this to CSS theming.*
        * **Open Graph:**  Show how it's used for social sharing.

    * **Viewport Configuration:**
        * **Explanation:** Describe its purpose in responsive design.
        * **Examples:** Provide concrete examples of `width`, `initial-scale`, `maximum-scale`, `user-scalable`. *Link these to CSS media queries and JavaScript for dynamic adjustments.*

    * **HTTP Header Equivalents:**
        * **Explanation:** Clarify how it can mimic HTTP headers.
        * **Examples:** Demonstrate `content-type`, `refresh`, `content-security-policy`. *Link CSP to JavaScript security.*

    * **Client Hints:**
        * **Explanation:** Describe how it signals browser capabilities.
        * **Examples:**  Illustrate `Accept-CH` and `Delegate-CH`. *Connect this to how JavaScript might use this information.*

    * **Error Reporting:**
        * **Explanation:**  Show how the browser warns about invalid syntax.
        * **Examples:**  Point out common errors like incorrect separators or invalid values.

6. **Address Specific Requirements:**

    * **JavaScript, HTML, CSS Relationships:**  Explicitly connect the functionalities to these technologies with examples.
    * **Logic Reasoning (Hypothetical Inputs and Outputs):** Provide examples of how the parsing functions work. For instance, give a `content` string and predict how the `ViewportDescription` would be populated. Focus on the viewport parsing as it's the most complex.
    * **User/Programming Errors:**  Provide specific, actionable examples of common mistakes when using `<meta>` tags, like typos, incorrect syntax, or misunderstanding viewport properties.

7. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Use precise language and avoid jargon where possible. Ensure the examples are easy to understand. Review for clarity and completeness. Make sure to explicitly call out the relationships with HTML, CSS, and JavaScript.

8. **Self-Correction/Refinement during the process:**

    * **Initial Thought:** Maybe just list the functions.
    * **Correction:**  That's too low-level. Need to focus on the *purpose* and *impact* of the code.
    * **Initial Thought:** Focus heavily on the code structure.
    * **Correction:** The user wants to understand what the code *does*, not just how it's organized. Shift focus to the *functionality* and how it relates to web development.
    * **Initial Thought:**  Provide only simple examples.
    * **Correction:** More detailed examples, especially for viewport, will be more helpful to illustrate the parsing logic.
    * **Initial Thought:**  Assume the user understands Blink internals.
    * **Correction:** Explain concepts like "rendering engine" and "metadata" briefly for broader understanding.

By following these steps and iterating on the approach, we arrive at a comprehensive and informative answer that addresses all aspects of the prompt. The key is to move from the code itself to its *purpose* and its interactions within the web development ecosystem.
这个 `html_meta_element.cc` 文件是 Chromium Blink 渲染引擎中处理 HTML `<meta>` 元素的核心代码。它的主要功能是解析和应用 `<meta>` 标签中定义的元数据，这些元数据可以影响页面的渲染、行为和与外部服务的交互。

以下是该文件功能的详细列表，并附带与 JavaScript、HTML 和 CSS 相关的示例：

**核心功能:**

1. **解析 `<meta>` 标签的属性:** 该文件负责读取并解析 `<meta>` 标签的各种属性，如 `name`、`content`、`http-equiv`、`charset`、`property` 和 `media`。

2. **处理 `name` 属性:**  根据 `name` 属性的值，执行不同的操作：
   * **`description`:**  提供页面的简短描述，常用于搜索引擎结果页面。
      * **HTML:** `<meta name="description" content="这是一个关于 Blink 渲染引擎 HTMLMetaElement 的描述。">`
   * **`keywords`:**  提供页面的关键词，用于搜索引擎优化。
      * **HTML:** `<meta name="keywords" content="Blink, Chromium, 渲染引擎, HTML, meta">`
   * **`author`:**  指定页面的作者。
      * **HTML:** `<meta name="author" content="Blink 开发者">`
   * **`viewport`:**  控制视口的尺寸和缩放行为，对于响应式设计至关重要。这是该文件处理的重点之一。
      * **HTML:** `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
      * **与 CSS 的关系:** `viewport` 的设置会影响 CSS 媒体查询的计算，从而应用不同的样式。例如，`width=device-width` 会让页面的宽度适应设备的屏幕宽度。
      * **与 JavaScript 的关系:** JavaScript 可以读取和修改 `viewport` 的设置，或者监听视口变化事件，从而实现更复杂的响应式行为。
   * **`theme-color`:**  定义浏览器的工具栏和任务栏的颜色。
      * **HTML:** `<meta name="theme-color" content="#f0f0f0">`
      * **与 CSS 的关系:** 尽管 `theme-color` 不是 CSS 属性，但它影响浏览器的渲染，可以被视为一种浏览器级别的样式设置。
   * **`referrer`:**  控制在导航时发送的 HTTP Referer 头信息。
      * **HTML:** `<meta name="referrer" content="no-referrer">`
      * **与 JavaScript 的关系:** 这会影响 JavaScript 发起的请求（如 `fetch`）的 Referer 头信息。
   * **`robots`:**  指示搜索引擎爬虫如何索引和跟踪页面。
      * **HTML:** `<meta name="robots" content="index, follow">`
   * **`googlebot`:** 针对 Google 搜索引擎爬虫的指令。
      * **HTML:** `<meta name="googlebot" content="noindex">`
   * **`application-name`:**  指定 Web 应用的名称。
      * **HTML:** `<meta name="application-name" content="我的应用">`
   * **`apple-mobile-web-app-title`:**  用于添加到 iOS 主屏幕的 Web 应用的标题。
      * **HTML:** `<meta name="apple-mobile-web-app-title" content="我的WebApp">`
   * **`color-scheme`:**  指示页面支持的配色方案（`light`、`dark` 或两者）。
      * **HTML:** `<meta name="color-scheme" content="light dark">`
      * **与 CSS 的关系:** 浏览器可以根据此信息选择默认的配色方案，或者允许用户切换配色方案，CSS 可以使用媒体查询 `@media (prefers-color-scheme: dark)` 来针对不同的配色方案应用不同的样式。
   * **`supports-reduced-motion`:**  告知浏览器页面是否尊重用户的“减少动画”偏好。
      * **HTML:** `<meta name="supports-reduced-motion" content="reduce">`
      * **与 CSS 的关系:** CSS 可以使用媒体查询 `@media (prefers-reduced-motion: reduce)` 来禁用或减少动画。
      * **与 JavaScript 的关系:** JavaScript 可以读取此信息，并相应地调整动画效果。
   * **`app-title`:**  (如果启用了相关特性) 用于设置 Web 应用的标题。
      * **HTML:** `<meta name="app-title" content="App Title">`
   * **其他自定义 `name` 值:** 开发者可以定义自定义的 `name` 属性，并通过 JavaScript 来读取 `content` 属性的值，用于特定的应用逻辑。
      * **HTML:** `<meta name="custom-data" content="一些自定义数据">`
      * **JavaScript:** `const meta = document.querySelector('meta[name="custom-data"]'); const data = meta.content;`

3. **处理 `http-equiv` 属性:**  模拟 HTTP 头部信息，影响浏览器的行为：
   * **`content-type`:**  指定文档的 MIME 类型和字符编码。
      * **HTML:** `<meta http-equiv="content-type" content="text/html; charset=UTF-8">`
      * **与 HTML 的关系:** 告知浏览器如何解析 HTML 文档。
   * **`refresh`:**  实现页面重定向或刷新。
      * **HTML:** `<meta http-equiv="refresh" content="5;url=https://example.com">` (5秒后重定向)
   * **`content-security-policy` (CSP):**  定义浏览器被允许加载的资源的来源，增强安全性。
      * **HTML:** `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`
      * **与 JavaScript 的关系:**  CSP 可以阻止执行来自未授权来源的 JavaScript 代码，从而防止 XSS 攻击。
   * **`x-ua-compatible`:**  指定浏览器渲染页面的兼容模式。
      * **HTML:** `<meta http-equiv="X-UA-Compatible" content="IE=edge">`
   * **`Accept-CH` 和 `Delegate-CH`:**  用于客户端提示 (Client Hints)，告知服务器浏览器支持的客户端提示头信息。
      * **HTML:** `<meta http-equiv="Accept-CH" content="DPR, Viewport-Width, Width">`
      * **与 JavaScript 的关系:**  客户端提示可以影响 JavaScript 发起的请求头。

4. **处理 `charset` 属性:**  指定文档的字符编码。
   * **HTML:** `<meta charset="UTF-8">`
   * **与 HTML 的关系:** 浏览器使用指定的字符编码来正确解析 HTML 文档中的字符。

5. **处理 `property` 属性:**  主要用于 Open Graph 协议和 Schema.org 等结构化数据，用于社交媒体分享和搜索引擎理解页面内容。
   * **Open Graph:**
      * **HTML:** `<meta property="og:title" content="我的网页标题">`
      * **HTML:** `<meta property="og:description" content="网页描述">`
      * **与外部服务的关系:** 社交媒体平台（如 Facebook、Twitter）会读取这些元数据来展示分享链接的信息。
   * **Schema.org:**
      * **HTML:** `<meta property="schema:name" content="产品名称">`

6. **处理 `media` 属性:**  指定 `<meta>` 标签应用的媒体类型，类似于 CSS 的媒体查询。这允许根据不同的媒体条件应用不同的元数据，尽管这种用法相对较少。
   * **HTML:** `<meta name="viewport" content="width=1024" media="screen and (min-width: 1024px)">`

7. **处理 `viewport` 内容:**  这是该文件的一个重要职责，它解析 `content` 属性中的各种键值对，如 `width`、`height`、`initial-scale`、`minimum-scale`、`maximum-scale`、`user-scalable` 等，并更新页面的视口设置。
   * **详细的 `viewport` 解析逻辑:** 文件中包含了复杂的逻辑来解析 `viewport` 属性的值，并处理各种边界情况和兼容性问题。

8. **报告错误和警告:**  当解析 `<meta>` 标签的内容时，如果遇到无效的语法或不支持的值，该文件会生成控制台警告信息，帮助开发者调试问题。

**逻辑推理 (假设输入与输出):**

**假设输入:**  HTML 中包含以下 `<meta>` 标签：

```html
<meta name="viewport" content="width=device-width, initial-scale=0.5, maximum-scale=2.0">
```

**输出 (经过 `HTMLMetaElement.cc` 的处理):**

* **`viewport_description.min_width`:**  等于设备宽度 (由 Blink 计算得出)。
* **`viewport_description.max_width`:**  等于设备宽度。
* **`viewport_description.zoom` (initial-scale):** 0.5。
* **`viewport_description.min_zoom`:**  (通常有默认值，除非另行指定)。
* **`viewport_description.max_zoom`:** 2.0。
* **`viewport_description.user_zoom`:**  true (默认允许用户缩放)。

**假设输入 (错误示例):**

```html
<meta name="viewport" content="width=device-width; initial-scale=0.5">
```

**输出:**

* 该文件会检测到使用了无效的分隔符 `;`，并在控制台中输出警告信息：`Error parsing a meta element's content: ';' is not a valid key-value pair separator. Please use ',' instead.`
* 视口设置可能不会按预期生效，因为解析过程可能会中断或产生错误的结果。

**用户或编程常见的使用错误:**

1. **拼写错误:**  `name` 或 `http-equiv` 属性的值拼写错误会导致浏览器无法识别，从而忽略该 `<meta>` 标签。
   * **错误示例:** `<meta nmae="description" content="...">`

2. **`viewport` 属性值语法错误:**  使用错误的分隔符（如 `;` 而不是 `,`），或提供无效的值，会导致 `viewport` 设置失效。
   * **错误示例:** `<meta name="viewport" content="width=device-width;initial-scale=1.0">`
   * **错误示例:** `<meta name="viewport" content="width=abc">` (非法的宽度值)

3. **滥用 `http-equiv="refresh"`:**  过度使用或不当使用 `refresh` 可能会导致用户体验不佳。

4. **CSP 配置错误:**  `content-security-policy` 配置错误可能会阻止页面加载必要的资源或执行合法的 JavaScript 代码。

5. **字符编码声明错误:**  错误的 `charset` 声明会导致页面显示乱码。

6. **混淆 `name` 和 `property` 属性:**  `name` 用于标准元数据，而 `property` 主要用于 Open Graph 和 Schema.org 等协议。混淆使用会导致信息无法被正确解析。
   * **错误示例:** `<meta property="description" content="...">` (应该使用 `name`)

7. **在 `content` 属性中使用特殊字符未进行转义:**  某些特殊字符在 `content` 属性中需要进行 HTML 实体转义，否则可能导致解析错误。

总而言之，`html_meta_element.cc` 文件在 Blink 渲染引擎中扮演着至关重要的角色，它负责理解和应用 HTML 文档中 `<meta>` 标签提供的各种元数据，从而影响页面的渲染、行为、安全性以及与外部服务的交互。正确理解和使用 `<meta>` 标签对于 Web 开发至关重要。

### 提示词
```
这是目录为blink/renderer/core/html/html_meta_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003, 2010 Apple Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/html_meta_element.h"

#include "base/metrics/histogram_macros.h"
#include "base/trace_event/typed_macros.h"
#include "third_party/blink/public/mojom/frame/color_scheme.mojom-blink.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/html/client_hints_util.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/frame_client_hints_preferences_context.h"
#include "third_party/blink/renderer/core/loader/frame_fetch_context.h"
#include "third_party/blink/renderer/core/loader/http_equiv.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/client_hints_preferences.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"

namespace blink {

HTMLMetaElement::HTMLMetaElement(Document& document,
                                 const CreateElementFlags flags)
    : HTMLElement(html_names::kMetaTag, document),
      is_sync_parser_(flags.IsCreatedByParser() &&
                      !flags.IsAsyncCustomElements() &&
                      !document.IsInDocumentWrite()) {}

static bool IsInvalidSeparator(UChar c) {
  return c == ';';
}

// Though absl::ascii_isspace() considers \t and \v to be whitespace, Win IE
// doesn't.
static bool IsSeparator(UChar c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '=' ||
         c == ',' || c == '\0';
}

void HTMLMetaElement::ParseViewportContentAttribute(
    const String& content,
    ViewportDescription& viewport_description,
    Document* document,
    bool viewport_meta_zero_values_quirk) {
  bool has_invalid_separator = false;

  // Tread lightly in this code -- it was specifically designed to mimic Win
  // IE's parsing behavior.
  unsigned key_begin, key_end;
  unsigned value_begin, value_end;

  String buffer = content.LowerASCII();
  unsigned length = buffer.length();
  for (unsigned i = 0; i < length; /* no increment here */) {
    // skip to first non-separator, but don't skip past the end of the string
    while (IsSeparator(buffer[i])) {
      if (i >= length)
        break;
      i++;
    }
    key_begin = i;

    // skip to first separator
    while (!IsSeparator(buffer[i])) {
      has_invalid_separator |= IsInvalidSeparator(buffer[i]);
      if (i >= length)
        break;
      i++;
    }
    key_end = i;

    // skip to first '=', but don't skip past a ',' or the end of the string
    while (buffer[i] != '=') {
      has_invalid_separator |= IsInvalidSeparator(buffer[i]);
      if (buffer[i] == ',' || i >= length)
        break;
      i++;
    }

    // Skip to first non-separator, but don't skip past a ',' or the end of the
    // string.
    while (IsSeparator(buffer[i])) {
      if (buffer[i] == ',' || i >= length)
        break;
      i++;
    }
    value_begin = i;

    // skip to first separator
    while (!IsSeparator(buffer[i])) {
      has_invalid_separator |= IsInvalidSeparator(buffer[i]);
      if (i >= length)
        break;
      i++;
    }
    value_end = i;

    SECURITY_DCHECK(i <= length);

    String key_string = buffer.Substring(key_begin, key_end - key_begin);
    String value_string =
        buffer.Substring(value_begin, value_end - value_begin);
    ProcessViewportKeyValuePair(document, !has_invalid_separator, key_string,
                                value_string, viewport_meta_zero_values_quirk,
                                viewport_description);
  }
  if (has_invalid_separator && document) {
    String message =
        "Error parsing a meta element's content: ';' is not a valid key-value "
        "pair separator. Please use ',' instead.";
    document->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kRendering,
        mojom::ConsoleMessageLevel::kWarning, message));
  }
}

static inline float ClampLengthValue(float value) {
  // Limits as defined in the css-device-adapt spec.
  if (value != ViewportDescription::kValueAuto)
    return std::min(float(10000), std::max(value, float(1)));
  return value;
}

static inline float ClampScaleValue(float value) {
  // Limits as defined in the css-device-adapt spec.
  if (value != ViewportDescription::kValueAuto)
    return std::min(float(10), std::max(value, float(0.1)));
  return value;
}

float HTMLMetaElement::ParsePositiveNumber(Document* document,
                                           bool report_warnings,
                                           const String& key_string,
                                           const String& value_string,
                                           bool* ok) {
  size_t parsed_length;
  float value = WTF::VisitCharacters(value_string, [&](auto chars) {
    return CharactersToFloat(chars, parsed_length);
  });
  if (!parsed_length) {
    if (report_warnings)
      ReportViewportWarning(document, kUnrecognizedViewportArgumentValueError,
                            value_string, key_string);
    if (ok)
      *ok = false;
    return 0;
  }
  if (parsed_length < value_string.length() && report_warnings)
    ReportViewportWarning(document, kTruncatedViewportArgumentValueError,
                          value_string, key_string);
  if (ok)
    *ok = true;
  return value;
}

Length HTMLMetaElement::ParseViewportValueAsLength(Document* document,
                                                   bool report_warnings,
                                                   const String& key_string,
                                                   const String& value_string) {
  // 1) Non-negative number values are translated to px lengths.
  // 2) Negative number values are translated to auto.
  // 3) device-width and device-height are used as keywords.
  // 4) Other keywords and unknown values translate to auto.

  if (EqualIgnoringASCIICase(value_string, "device-width"))
    return Length::DeviceWidth();
  if (EqualIgnoringASCIICase(value_string, "device-height"))
    return Length::DeviceHeight();

  bool ok;

  float value = ParsePositiveNumber(document, report_warnings, key_string,
                                    value_string, &ok);

  if (!ok)
    return Length();  // auto

  if (value < 0)
    return Length();  // auto

  value = ClampLengthValue(value);
  if (document && document->GetPage()) {
    value = document->GetPage()->GetChromeClient().WindowToViewportScalar(
        document->GetFrame(), value);
  }
  return Length::Fixed(value);
}

float HTMLMetaElement::ParseViewportValueAsZoom(
    Document* document,
    bool report_warnings,
    const String& key_string,
    const String& value_string,
    bool& computed_value_matches_parsed_value,
    bool viewport_meta_zero_values_quirk) {
  // 1) Non-negative number values are translated to <number> values.
  // 2) Negative number values are translated to auto.
  // 3) yes is translated to 1.0.
  // 4) device-width and device-height are translated to 10.0.
  // 5) no and unknown values are translated to 0.0

  computed_value_matches_parsed_value = false;
  if (EqualIgnoringASCIICase(value_string, "yes"))
    return 1;
  if (EqualIgnoringASCIICase(value_string, "no"))
    return 0;
  if (EqualIgnoringASCIICase(value_string, "device-width"))
    return 10;
  if (EqualIgnoringASCIICase(value_string, "device-height"))
    return 10;

  float value =
      ParsePositiveNumber(document, report_warnings, key_string, value_string);

  if (value < 0)
    return ViewportDescription::kValueAuto;

  if (value > 10.0 && report_warnings)
    ReportViewportWarning(document, kMaximumScaleTooLargeError, String(),
                          String());

  if (!value && viewport_meta_zero_values_quirk)
    return ViewportDescription::kValueAuto;

  float clamped_value = ClampScaleValue(value);
  if (clamped_value == value)
    computed_value_matches_parsed_value = true;

  return clamped_value;
}

bool HTMLMetaElement::ParseViewportValueAsUserZoom(
    Document* document,
    bool report_warnings,
    const String& key_string,
    const String& value_string,
    bool& computed_value_matches_parsed_value) {
  // yes and no are used as keywords.
  // Numbers >= 1, numbers <= -1, device-width and device-height are mapped to
  // yes.
  // Numbers in the range <-1, 1>, and unknown values, are mapped to no.

  computed_value_matches_parsed_value = false;
  if (EqualIgnoringASCIICase(value_string, "yes")) {
    computed_value_matches_parsed_value = true;
    return true;
  }
  if (EqualIgnoringASCIICase(value_string, "no")) {
    computed_value_matches_parsed_value = true;
    return false;
  }
  if (EqualIgnoringASCIICase(value_string, "device-width"))
    return true;
  if (EqualIgnoringASCIICase(value_string, "device-height"))
    return true;

  float value =
      ParsePositiveNumber(document, report_warnings, key_string, value_string);
  if (fabs(value) < 1)
    return false;

  return true;
}

float HTMLMetaElement::ParseViewportValueAsDPI(Document* document,
                                               bool report_warnings,
                                               const String& key_string,
                                               const String& value_string) {
  if (EqualIgnoringASCIICase(value_string, "device-dpi"))
    return ViewportDescription::kValueDeviceDPI;
  if (EqualIgnoringASCIICase(value_string, "low-dpi"))
    return ViewportDescription::kValueLowDPI;
  if (EqualIgnoringASCIICase(value_string, "medium-dpi"))
    return ViewportDescription::kValueMediumDPI;
  if (EqualIgnoringASCIICase(value_string, "high-dpi"))
    return ViewportDescription::kValueHighDPI;

  bool ok;
  float value = ParsePositiveNumber(document, report_warnings, key_string,
                                    value_string, &ok);
  if (!ok || value < 70 || value > 400)
    return ViewportDescription::kValueAuto;

  return value;
}

blink::mojom::ViewportFit HTMLMetaElement::ParseViewportFitValueAsEnum(
    bool& unknown_value,
    const String& value_string) {
  if (EqualIgnoringASCIICase(value_string, "auto"))
    return mojom::ViewportFit::kAuto;
  if (EqualIgnoringASCIICase(value_string, "contain"))
    return mojom::ViewportFit::kContain;
  if (EqualIgnoringASCIICase(value_string, "cover"))
    return mojom::ViewportFit::kCover;

  unknown_value = true;
  return mojom::ViewportFit::kAuto;
}

// static
std::optional<ui::mojom::blink::VirtualKeyboardMode>
HTMLMetaElement::ParseVirtualKeyboardValueAsEnum(const String& value) {
  if (EqualIgnoringASCIICase(value, "resizes-content"))
    return ui::mojom::blink::VirtualKeyboardMode::kResizesContent;
  else if (EqualIgnoringASCIICase(value, "resizes-visual"))
    return ui::mojom::blink::VirtualKeyboardMode::kResizesVisual;
  else if (EqualIgnoringASCIICase(value, "overlays-content"))
    return ui::mojom::blink::VirtualKeyboardMode::kOverlaysContent;

  return std::nullopt;
}

void HTMLMetaElement::ProcessViewportKeyValuePair(
    Document* document,
    bool report_warnings,
    const String& key_string,
    const String& value_string,
    bool viewport_meta_zero_values_quirk,
    ViewportDescription& description) {
  if (key_string == "width") {
    const Length& width = ParseViewportValueAsLength(document, report_warnings,
                                                     key_string, value_string);
    if (!width.IsAuto()) {
      description.min_width = Length::ExtendToZoom();
      description.max_width = width;
    }
  } else if (key_string == "height") {
    const Length& height = ParseViewportValueAsLength(document, report_warnings,
                                                      key_string, value_string);
    if (!height.IsAuto()) {
      description.min_height = Length::ExtendToZoom();
      description.max_height = height;
    }
  } else if (key_string == "initial-scale") {
    description.zoom = ParseViewportValueAsZoom(
        document, report_warnings, key_string, value_string,
        description.zoom_is_explicit, viewport_meta_zero_values_quirk);
  } else if (key_string == "minimum-scale") {
    description.min_zoom = ParseViewportValueAsZoom(
        document, report_warnings, key_string, value_string,
        description.min_zoom_is_explicit, viewport_meta_zero_values_quirk);
  } else if (key_string == "maximum-scale") {
    description.max_zoom = ParseViewportValueAsZoom(
        document, report_warnings, key_string, value_string,
        description.max_zoom_is_explicit, viewport_meta_zero_values_quirk);
  } else if (key_string == "user-scalable") {
    description.user_zoom = ParseViewportValueAsUserZoom(
        document, report_warnings, key_string, value_string,
        description.user_zoom_is_explicit);
  } else if (key_string == "target-densitydpi") {
    description.deprecated_target_density_dpi = ParseViewportValueAsDPI(
        document, report_warnings, key_string, value_string);
    if (report_warnings)
      ReportViewportWarning(document, kTargetDensityDpiUnsupported, String(),
                            String());
  } else if (key_string == "minimal-ui") {
    // Ignore vendor-specific argument.
  } else if (key_string == "viewport-fit") {
    if (RuntimeEnabledFeatures::DisplayCutoutAPIEnabled()) {
      bool unknown_value = false;
      description.SetViewportFit(
          ParseViewportFitValueAsEnum(unknown_value, value_string));

      // If we got an unknown value then report a warning.
      if (unknown_value) {
        ReportViewportWarning(document, kViewportFitUnsupported, value_string,
                              String());
      }
    }
  } else if (key_string == "shrink-to-fit") {
    // Ignore vendor-specific argument.
  } else if (key_string == "interactive-widget") {
    std::optional<ui::mojom::blink::VirtualKeyboardMode> resize_type =
        ParseVirtualKeyboardValueAsEnum(value_string);

    if (resize_type) {
      description.virtual_keyboard_mode = resize_type.value();
      switch (resize_type.value()) {
        case ui::mojom::blink::VirtualKeyboardMode::kOverlaysContent: {
          UseCounter::Count(document,
                            WebFeature::kInteractiveWidgetOverlaysContent);
        } break;
        case ui::mojom::blink::VirtualKeyboardMode::kResizesContent: {
          UseCounter::Count(document,
                            WebFeature::kInteractiveWidgetResizesContent);
        } break;
        case ui::mojom::blink::VirtualKeyboardMode::kResizesVisual: {
          UseCounter::Count(document,
                            WebFeature::kInteractiveWidgetResizesVisual);
        } break;
        case ui::mojom::blink::VirtualKeyboardMode::kUnset: {
          NOTREACHED();
        }
      }
    } else {
      description.virtual_keyboard_mode =
          ui::mojom::blink::VirtualKeyboardMode::kUnset;
      ReportViewportWarning(document, kUnrecognizedViewportArgumentValueError,
                            value_string, key_string);
    }
  } else if (report_warnings) {
    ReportViewportWarning(document, kUnrecognizedViewportArgumentKeyError,
                          key_string, String());
  }
}

static const char* ViewportErrorMessageTemplate(ViewportErrorCode error_code) {
  static const char* const kErrors[] = {
      "The key \"%replacement1\" is not recognized and ignored.",
      "The value \"%replacement1\" for key \"%replacement2\" is invalid, and "
      "has been ignored.",
      "The value \"%replacement1\" for key \"%replacement2\" was truncated to "
      "its numeric prefix.",
      "The value for key \"maximum-scale\" is out of bounds and the value has "
      "been clamped.",
      "The key \"target-densitydpi\" is not supported.",
      "The value \"%replacement1\" for key \"viewport-fit\" is not supported.",
  };

  return kErrors[error_code];
}

static mojom::ConsoleMessageLevel ViewportErrorMessageLevel(
    ViewportErrorCode error_code) {
  switch (error_code) {
    case kTruncatedViewportArgumentValueError:
    case kTargetDensityDpiUnsupported:
    case kUnrecognizedViewportArgumentKeyError:
    case kUnrecognizedViewportArgumentValueError:
    case kMaximumScaleTooLargeError:
    case kViewportFitUnsupported:
      return mojom::ConsoleMessageLevel::kWarning;
  }

  NOTREACHED();
}

void HTMLMetaElement::ReportViewportWarning(Document* document,
                                            ViewportErrorCode error_code,
                                            const String& replacement1,
                                            const String& replacement2) {
  if (!document || !document->GetFrame())
    return;

  String message = ViewportErrorMessageTemplate(error_code);
  if (!replacement1.IsNull())
    message.Replace("%replacement1", replacement1);
  if (!replacement2.IsNull())
    message.Replace("%replacement2", replacement2);

  // FIXME: This message should be moved off the console once a solution to
  // https://bugs.webkit.org/show_bug.cgi?id=103274 exists.
  document->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kRendering,
      ViewportErrorMessageLevel(error_code), message));
}

void HTMLMetaElement::GetViewportDescriptionFromContentAttribute(
    const String& content,
    ViewportDescription& description,
    Document* document,
    bool viewport_meta_zero_values_quirk) {
  ParseViewportContentAttribute(content, description, document,
                                viewport_meta_zero_values_quirk);

  if (description.min_zoom == ViewportDescription::kValueAuto)
    description.min_zoom = 0.25;

  if (description.max_zoom == ViewportDescription::kValueAuto) {
    description.max_zoom = 5;
    description.min_zoom = std::min(description.min_zoom, float(5));
  }
}

void HTMLMetaElement::ProcessViewportContentAttribute(
    const String& content,
    ViewportDescription::Type origin) {
  DCHECK(!content.IsNull());

  ViewportData& viewport_data = GetDocument().GetViewportData();
  if (!viewport_data.ShouldOverrideLegacyDescription(origin))
    return;

  ViewportDescription description_from_legacy_tag(origin);
  if (viewport_data.ShouldMergeWithLegacyDescription(origin))
    description_from_legacy_tag = viewport_data.GetViewportDescription();

  GetViewportDescriptionFromContentAttribute(
      content, description_from_legacy_tag, &GetDocument(),
      GetDocument().GetSettings() &&
          GetDocument().GetSettings()->GetViewportMetaZeroValuesQuirk());

  viewport_data.SetViewportDescription(description_from_legacy_tag);

  TRACE_EVENT_INSTANT(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "ParseMetaViewport",
      "data", [&](perfetto::TracedValue context) {
        auto dict = std::move(context).WriteDictionary();
        if (GetDocument().GetFrame()) {
          dict.Add("frame", GetDocument().GetFrame()->GetFrameIdForTracing());
        }
        dict.Add("node_id", GetDomNodeId());
        dict.Add("content", content);
      });
}

void HTMLMetaElement::NameRemoved(const AtomicString& name_value) {
  const AtomicString& content_value =
      FastGetAttribute(html_names::kContentAttr);
  if (content_value.IsNull())
    return;
  if (EqualIgnoringASCIICase(name_value, "theme-color") &&
      GetDocument().GetFrame()) {
    GetDocument().GetFrame()->DidChangeThemeColor(
        /*update_theme_color_cache=*/true);
  } else if (EqualIgnoringASCIICase(name_value, keywords::kColorScheme)) {
    GetDocument().ColorSchemeMetaChanged();
  } else if (EqualIgnoringASCIICase(name_value, "supports-reduced-motion")) {
    GetDocument().SupportsReducedMotionMetaChanged();
  } else if (RuntimeEnabledFeatures::AppTitleEnabled(GetExecutionContext()) &&
             EqualIgnoringASCIICase(name_value, "app-title")) {
    GetDocument().UpdateAppTitle();
  }
}

void HTMLMetaElement::ParseAttribute(
    const AttributeModificationParams& params) {
  if (params.name == html_names::kNameAttr) {
    if (IsInDocumentTree())
      NameRemoved(params.old_value);
    ProcessContent();
  } else if (params.name == html_names::kContentAttr) {
    ProcessContent();
    ProcessHttpEquiv();
  } else if (params.name == html_names::kHttpEquivAttr) {
    ProcessHttpEquiv();
  } else if (params.name == html_names::kMediaAttr) {
    ProcessContent();
  } else {
    HTMLElement::ParseAttribute(params);
  }
}

Node::InsertionNotificationRequest HTMLMetaElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLElement::InsertedInto(insertion_point);
  return kInsertionShouldCallDidNotifySubtreeInsertions;
}

void HTMLMetaElement::DidNotifySubtreeInsertionsToDocument() {
  ProcessContent();
  ProcessHttpEquiv();
}

void HTMLMetaElement::RemovedFrom(ContainerNode& insertion_point) {
  HTMLElement::RemovedFrom(insertion_point);
  if (!insertion_point.IsInDocumentTree())
    return;
  const AtomicString& name_value = FastGetAttribute(html_names::kNameAttr);
  if (!name_value.empty())
    NameRemoved(name_value);
}

static bool InDocumentHead(HTMLMetaElement* element) {
  if (!element->isConnected())
    return false;

  return Traversal<HTMLHeadElement>::FirstAncestor(*element);
}

void HTMLMetaElement::ProcessHttpEquiv() {
  if (!IsInDocumentTree())
    return;
  const AtomicString& content_value =
      FastGetAttribute(html_names::kContentAttr);
  if (content_value.IsNull())
    return;
  const AtomicString& http_equiv_value =
      FastGetAttribute(html_names::kHttpEquivAttr);
  if (http_equiv_value.empty())
    return;
  HttpEquiv::Process(GetDocument(), http_equiv_value, content_value,
                     InDocumentHead(this), is_sync_parser_, this);
}

// Open Graph Protocol Content Classification types used for logging.
enum class ContentClassificationOpenGraph {
  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  kUnknown = 0,
  kWebsite = 1,
  kMusic = 2,
  kVideo = 3,
  kArticle = 4,
  kBook = 5,
  kProfile = 6,
  kMaxValue = kProfile
};

ContentClassificationOpenGraph GetContentClassification(
    const AtomicString& open_graph_type) {
  const AtomicString lowercase_type(open_graph_type.LowerASCII());
  if (lowercase_type.StartsWithIgnoringASCIICase("website")) {
    return ContentClassificationOpenGraph::kWebsite;
  } else if (lowercase_type.StartsWithIgnoringASCIICase("music")) {
    return ContentClassificationOpenGraph::kMusic;
  } else if (lowercase_type.StartsWithIgnoringASCIICase("video")) {
    return ContentClassificationOpenGraph::kVideo;
  } else if (lowercase_type.StartsWithIgnoringASCIICase("article")) {
    return ContentClassificationOpenGraph::kArticle;
  } else if (lowercase_type.StartsWithIgnoringASCIICase("book")) {
    return ContentClassificationOpenGraph::kBook;
  } else if (lowercase_type.StartsWithIgnoringASCIICase("profile")) {
    return ContentClassificationOpenGraph::kProfile;
  }
  return ContentClassificationOpenGraph::kUnknown;
}

void HTMLMetaElement::ProcessContent() {
  if (!IsInDocumentTree())
    return;

  const AtomicString& property_value =
      FastGetAttribute(html_names::kPropertyAttr);
  const AtomicString& content_value =
      FastGetAttribute(html_names::kContentAttr);

  if (EqualIgnoringASCIICase(property_value, "og:type")) {
    UMA_HISTOGRAM_ENUMERATION("Content.Classification.OpenGraph",
                              GetContentClassification(content_value));
  }

  const AtomicString& name_value = FastGetAttribute(html_names::kNameAttr);
  if (name_value.empty())
    return;

  if (EqualIgnoringASCIICase(name_value, "theme-color") &&
      GetDocument().GetFrame()) {
    GetDocument().GetFrame()->DidChangeThemeColor(
        /*update_theme_color_cache=*/true);
    return;
  }
  if (EqualIgnoringASCIICase(name_value, keywords::kColorScheme)) {
    GetDocument().ColorSchemeMetaChanged();
    return;
  }

  if (EqualIgnoringASCIICase(name_value, "supports-reduced-motion")) {
    GetDocument().SupportsReducedMotionMetaChanged();
    return;
  }

  // All situations below require a content attribute (which can be the empty
  // string).
  if (content_value.IsNull())
    return;

  if (EqualIgnoringASCIICase(name_value, "viewport")) {
    ProcessViewportContentAttribute(content_value,
                                    ViewportDescription::kViewportMeta);
  } else if (EqualIgnoringASCIICase(name_value, "referrer") &&
             GetExecutionContext()) {
    UseCounter::Count(&GetDocument(),
                      WebFeature::kHTMLMetaElementReferrerPolicy);
    if (!IsDescendantOf(GetDocument().head())) {
      UseCounter::Count(&GetDocument(),
                        WebFeature::kHTMLMetaElementReferrerPolicyOutsideHead);
    }
    network::mojom::ReferrerPolicy old_referrer_policy =
        GetExecutionContext()->GetReferrerPolicy();
    GetExecutionContext()->ParseAndSetReferrerPolicy(content_value,
                                                     kPolicySourceMetaTag);
    network::mojom::ReferrerPolicy new_referrer_policy =
        GetExecutionContext()->GetReferrerPolicy();
    if (old_referrer_policy != new_referrer_policy) {
      if (auto* document_rules =
              DocumentSpeculationRules::FromIfExists(GetDocument())) {
        document_rules->DocumentReferrerPolicyChanged();
      }
    }
  } else if (EqualIgnoringASCIICase(name_value, "handheldfriendly") &&
             EqualIgnoringASCIICase(content_value, "true")) {
    ProcessViewportContentAttribute("width=device-width",
                                    ViewportDescription::kHandheldFriendlyMeta);
  } else if (EqualIgnoringASCIICase(name_value, "mobileoptimized")) {
    ProcessViewportContentAttribute("width=device-width, initial-scale=1",
                                    ViewportDescription::kMobileOptimizedMeta);
  } else if (EqualIgnoringASCIICase(name_value, "monetization")) {
    // TODO(1031476): The Web Monetization specification is an unofficial draft,
    // available at https://webmonetization.org/specification.html
    // For now, only use counters are implemented in Blink.
    if (GetDocument().IsInOutermostMainFrame()) {
      UseCounter::Count(&GetDocument(),
                        WebFeature::kHTMLMetaElementMonetization);
    }
  } else if (RuntimeEnabledFeatures::AppTitleEnabled(GetExecutionContext()) &&
             EqualIgnoringASCIICase(name_value, "app-title")) {
    UseCounter::Count(&GetDocument(), WebFeature::kWebAppTitle);
    GetDocument().UpdateAppTitle();
  }
}

WTF::TextEncoding HTMLMetaElement::ComputeEncoding() const {
  HTMLAttributeList attribute_list;
  for (const Attribute& attr : Attributes())
    attribute_list.push_back(
        std::make_pair(attr.GetName().LocalName(), attr.Value().GetString()));
  return EncodingFromMetaAttributes(attribute_list);
}

const AtomicString& HTMLMetaElement::Content() const {
  return FastGetAttribute(html_names::kContentAttr);
}

const AtomicString& HTMLMetaElement::HttpEquiv() const {
  return FastGetAttribute(html_names::kHttpEquivAttr);
}

const AtomicString& HTMLMetaElement::Media() const {
  return FastGetAttribute(html_names::kMediaAttr);
}

const AtomicString& HTMLMetaElement::GetName() const {
  return FastGetAttribute(html_names::kNameAttr);
}

const AtomicString& HTMLMetaElement::Property() const {
  return FastGetAttribute(html_names::kPropertyAttr);
}

const AtomicString& HTMLMetaElement::Itemprop() const {
  return FastGetAttribute(html_names::kItempropAttr);
}

// static
void HTMLMetaElement::ProcessMetaCH(Document& document,
                                    const AtomicString& content,
                                    network::MetaCHType type,
                                    bool is_doc_preloader,
                                    bool is_sync_parser) {

  LocalFrame* frame = document.GetFrame();
  if (!frame)
    return;

  if (!frame->IsMainFrame()) {
    return;
  }

  if (!frame->ScriptEnabled()) {
    // Do not allow configuring client hints if JavaScript is disabled.
    return;
  }

  switch (type) {
    case network::MetaCHType::HttpEquivAcceptCH:
      UseCounter::Count(document,
                        WebFeature::kClientHintsMetaHTTPEquivAcceptCH);
      break;
    case network::MetaCHType::HttpEquivDelegateCH:
      UseCounter::Count(document, WebFeature::kClientHintsMetaEquivDelegateCH);
      break;
  }
  FrameClientHintsPreferencesContext hints_context(frame);
  UpdateWindowPermissionsPolicyWithDelegationSupportForClientHints(
      frame->GetClientHintsPreferences(), document.domWindow(), content,
      document.Url(), &hints_context, type, is_doc_preloader, is_sync_parser);
}

void HTMLMetaElement::FinishParsingChildren() {
  // Flag the tag was parsed so if it's re-read we know it was modified.
  is_sync_parser_ = false;
  HTMLElement::FinishParsingChildren();
}

}  // namespace blink
```