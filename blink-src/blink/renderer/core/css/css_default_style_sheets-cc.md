Response:
Let's break down the thought process to answer the request about `css_default_style_sheets.cc`.

**1. Understanding the Core Purpose:**

The filename and the initial comments strongly suggest this file is responsible for managing *default* CSS styles in the Blink rendering engine. The key is "default" – these are the styles that apply to HTML elements even *without* any explicitly provided CSS by the webpage author. The copyright notices indicate a long history and contribution from various organizations, reinforcing its fundamental role.

**2. Identifying Key Functionality:**

Skimming through the code, I'm looking for actions or methods that reveal the file's responsibilities. I see:

* **`Instance()`:**  A classic singleton pattern, meaning there's only one instance of this class, suggesting it's a central point for default style management.
* **`ParseUASheet()`:**  "UA" likely stands for "User Agent". This function parses CSS strings, strongly hinting at loading and processing default styles. The "insecure context" comment is a detail to note but not central to the core function.
* **`Init()`:**  A common initialization function, likely called early in the Blink startup process.
* **`CSSDefaultStyleSheets()` (constructor):**  This is where the initial default stylesheets are loaded. The loading of `IDR_UASTYLE_HTML_CSS` and `IDR_UASTYLE_QUIRKS_CSS` confirms the loading of basic HTML styles. The interaction with `LayoutTheme` is an interesting detail.
* **`Reset()`:**  Indicates the ability to clear and reload default styles, useful for testing or internal engine resets.
* **`PrepareForLeakDetection()`:** A Chromium-specific mechanism, but reinforces the idea that these default stylesheets have a long lifecycle.
* **`AddRulesFromSheet()`:** This method directly adds parsed CSS rules to internal data structures (`default_html_style_`, etc.). This is a core operation.
* **`EnsureDefaultStyleSheetsForElement()` and `EnsureDefaultStyleSheetsForPseudoElement()`:** These functions handle the lazy loading of stylesheets for specific elements (like SVG, MathML, media controls) or pseudo-elements (like `::marker`). This optimization avoids loading all stylesheets upfront.
* **`SetMediaControlsStyleSheetLoader()`:**  Shows a mechanism for customizing or providing media control styles.
* **`EnsureDefaultStyleSheetForFullscreen()` and `RebuildFullscreenRuleSetIfMediaQueriesChanged()`:**  Handles styles specifically for fullscreen mode and dynamically updates them based on media queries.
* **`EnsureDefaultStyleSheetForForcedColors()`:**  Deals with high-contrast or forced-colors mode.
* **`CollectFeaturesTo()`:**  Suggests this class contributes to tracking CSS features used by a document.

**3. Relating to HTML, CSS, and JavaScript:**

Now, connect these functionalities to the core web technologies:

* **HTML:** The default stylesheets provide the basic rendering of HTML elements. Without them, web pages would be unstyled plain text. Examples:  Default margins for `<body>`, default font for `<p>`, default styling for form elements.
* **CSS:** This file is all about CSS! It *manages* the default CSS rules. The parsing, loading, and application of these rules are central to how CSS works in the browser.
* **JavaScript:** While this file doesn't directly execute JavaScript, the *effects* of the default stylesheets are visible to JavaScript. JavaScript can inspect the computed styles of elements, which are influenced by these defaults. JavaScript might also interact with elements styled by these defaults (e.g., manipulating a button's appearance).

**4. Logical Reasoning (Input/Output):**

Think about the flow of how default styles are applied:

* **Input:**  An HTML document is loaded. The browser needs to render it.
* **Process:** The `CSSDefaultStyleSheets` instance is consulted. It provides the default styles for the elements in the document.
* **Output:** The HTML elements are rendered with their initial, default styling.

Consider conditional loading:

* **Input:** An HTML document contains an `<svg>` element.
* **Process:** `EnsureDefaultStyleSheetsForElement()` is called for the `<svg>` element. Since the SVG stylesheet hasn't been loaded yet, it's loaded and applied.
* **Output:** The `<svg>` element is rendered with its default SVG styling.

**5. Common User/Programming Errors:**

Think about scenarios where the default styles might cause confusion or issues:

* **User Error:**  A user might be surprised by the default appearance of an element if they haven't explicitly styled it. They might not realize that the browser provides default styling.
* **Programming Error:**  A developer might try to override default styles with very specific CSS rules, only to find that the default styles have high specificity due to the "user-agent stylesheet" origin. They might also forget that certain elements have UA-specific styling.

**6. Debugging Scenario:**

How would you end up looking at this file during debugging?

* **Scenario:** A developer notices that an HTML element has unexpected default styling. They suspect it's not coming from their own CSS.
* **Steps:**
    1. They open the browser's developer tools.
    2. They inspect the element and look at the "Computed" styles.
    3. They see styles applied by the "User-Agent Stylesheet."
    4. They want to understand *where* these styles come from in the browser's source code.
    5. They might search the Chromium codebase for "User-Agent Stylesheet" or the names of the CSS properties they see.
    6. This search could lead them to `css_default_style_sheets.cc`, which is responsible for loading and managing these UA styles.

**7. Structuring the Answer:**

Finally, organize the information logically with clear headings and examples, as demonstrated in the good example answer. Use the insights gained from the thought process to address each part of the prompt comprehensively. Start with the core function, then elaborate on relationships, reasoning, errors, and debugging.
这是 blink 引擎中 `blink/renderer/core/css/css_default_style_sheets.cc` 文件的功能列表和相关说明：

**核心功能:**

1. **管理和提供默认的用户代理 (User-Agent) 样式表:**  这个文件负责加载、解析和存储浏览器内置的默认 CSS 样式表。这些样式表定义了在没有任何开发者提供的 CSS 样式的情况下，HTML 元素应该如何呈现。

2. **区分标准模式和怪异模式 (Quirks Mode) 的样式:**  它加载并维护两套默认样式表，一套用于标准的 HTML 渲染模式，另一套用于处理历史遗留的怪异模式，以保证对旧网站的兼容性。

3. **按需加载特定命名空间的样式:**  除了 HTML 的默认样式，它还负责加载 SVG 和 MathML 等特定命名空间的默认样式，并在需要时（当页面包含相应的元素时）进行初始化。

4. **处理媒体控制元素的样式:**  它负责加载和管理 `<video>` 和 `<audio>` 元素默认的媒体控制组件的样式。

5. **支持打印样式:**  它维护一套专门用于打印的默认样式。

6. **支持强制颜色模式 (Forced Colors Mode):**  当操作系统启用高对比度或强制颜色模式时，该文件会加载相应的默认样式，以确保内容的可访问性。

7. **支持全屏模式样式:**  它管理全屏模式下元素的默认样式。

8. **支持可定制的选择元素样式:**  对于 `<select>` 元素，它提供可定制的默认样式。

9. **支持 `::marker` 伪元素的样式:**  它为列表项的 `::marker` 伪元素提供默认样式。

10. **支持 View Source 和 JSON 文档的样式:**  当用户查看网页源代码或 JSON 文档时，它会提供相应的默认样式。

11. **延迟加载和初始化:** 为了性能考虑，一些特定的样式表（例如 SVG、MathML、媒体控制）是按需加载的，只有当页面包含相应的元素时才会进行初始化。

12. **提供访问默认样式的接口:**  该文件提供了访问这些默认样式表的接口，例如 `DefaultStyleSheet()`, `QuirksStyleSheet()`, `SvgStyleSheet()` 等，供 Blink 渲染引擎的其他部分使用。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 这个文件提供的默认样式是 HTML 元素的基础呈现方式。
    * **举例:**
        * 默认情况下，`<h1>` 到 `<h6>` 元素会以不同大小和粗细的字体显示，这是由 `css_default_style_sheets.cc` 中加载的默认样式定义的。
        * `<body>` 元素默认会有一定的 margin，这也是默认样式的一部分。
        * 链接 `<a>` 元素默认会有下划线和特定的颜色。

* **CSS:**  `css_default_style_sheets.cc` 本身就是用来管理 CSS 样式的。它加载的样式表遵循 CSS 语法，并定义了各种 CSS 属性的默认值。
    * **举例:**
        * 文件中会包含类似 `display: block;` 这样的规则，用于定义某些元素的默认 `display` 属性。
        * 针对 `<video>` 元素，可能会定义默认的 `width`, `height` 以及控制条的样式。
        * 对于 `::marker` 伪元素，会定义 `content`, `color` 等属性。

* **JavaScript:** JavaScript 可以读取和修改由默认样式表定义的样式，也可以通过 JavaScript API (例如 `getComputedStyle`) 获取元素的最终样式，其中就包含了默认样式。
    * **举例:**
        * JavaScript 可以使用 `element.style.display = 'none'` 来覆盖默认的 `display` 属性。
        * 使用 `window.getComputedStyle(element).getPropertyValue('margin-top')` 可以获取元素最终计算出的 `margin-top` 值，这个值可能来源于默认样式表。

**逻辑推理 (假设输入与输出):**

假设输入一个包含 `<svg>` 元素的 HTML 文档，并且这是该类型的第一个元素。

* **假设输入:** 一个 HTML 文档字符串，其中包含 `<svg>` 元素。
  ```html
  <!DOCTYPE html>
  <html>
  <head>
    <title>SVG Example</title>
  </head>
  <body>
    <svg width="100" height="100">
      <circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />
    </svg>
  </body>
  </html>
  ```

* **逻辑推理过程:**
    1. Blink 渲染引擎开始解析 HTML 文档。
    2. 当遇到 `<svg>` 元素时，`CSSDefaultStyleSheets::EnsureDefaultStyleSheetsForElement()` 方法会被调用。
    3. 该方法检查 `svg_style_sheet_` 是否已加载。由于这是第一个 SVG 元素，`svg_style_sheet_` 为空。
    4. 从资源中加载 `IDR_UASTYLE_SVG_CSS` 对应的 SVG 默认样式表。
    5. 将加载的样式表添加到 `default_svg_style_` 中。
    6. `EnsureDefaultStyleSheetsForElement()` 返回 `true`，表示默认样式已更改。

* **输出:**  SVG 元素会应用默认的 SVG 样式，例如设置默认的 `fill`, `stroke` 等属性（如果 SVG 样式表中有定义）。即使开发者没有为 SVG 元素显式设置样式，它也会有一定的呈现效果，这归功于默认样式表。

**用户或编程常见的使用错误及举例说明:**

* **误认为所有样式都需要自己定义:**  新手开发者可能没有意识到浏览器会提供默认样式，导致在不需要的情况下也重复定义了一些基本的样式。
    * **举例:** 开发者可能会为所有的 `<div>` 元素设置 `display: block;`，但实际上 `div` 元素的默认 `display` 值就是 `block`。

* **忽略默认样式的影响:**  当开发者想要实现特定的样式效果时，如果没有考虑到默认样式的影响，可能会遇到一些意想不到的结果。
    * **举例:** 开发者为一个 `<a>` 元素设置了背景颜色，但可能没有注意到默认样式中定义了链接的颜色，导致文本颜色与背景颜色冲突，难以阅读。

* **过度使用 `!important` 来覆盖默认样式:**  虽然 `!important` 可以提高样式的优先级，但过度使用会使样式调试和维护变得困难。了解默认样式可以帮助开发者更精准地覆盖它们，而不需要总是使用 `!important`。
    * **举例:**  开发者想要修改 `<body>` 元素的 `margin`，可能会直接使用 `body { margin: 0 !important; }`，但更好的做法是了解默认的 margin 值，并使用更具体的选择器或较低的优先级来覆盖。

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在调试 CSS 相关问题时，可能会需要查看这个文件作为线索：

1. **用户打开一个网页:** 浏览器开始加载和解析 HTML、CSS 和 JavaScript 资源。
2. **渲染引擎初始化:**  Blink 渲染引擎在初始化阶段会创建 `CSSDefaultStyleSheets` 的实例，并加载默认样式表。
3. **构建 DOM 树:** 渲染引擎解析 HTML，构建 DOM 树。
4. **样式计算:** 对于 DOM 树中的每个元素，渲染引擎需要计算其最终的样式。这个过程会考虑以下几个来源的样式：
    * 浏览器默认样式 (由 `css_default_style_sheets.cc` 提供)
    * 开发者提供的外部 CSS 文件
    * 开发者提供的 `<style>` 标签内的 CSS
    * 元素的 `style` 属性中的内联样式
5. **发现意外的样式:** 开发者在查看元素样式时，可能会在 "Computed" 标签中看到一些自己没有定义的样式，并且来源是 "User-Agent Stylesheet"。
6. **查找默认样式来源:**  为了理解这些 "User-Agent Stylesheet" 的具体内容和来源，开发者可能会：
    * 在开发者工具中查看样式规则的来源链接，这可能会指向 Blink 源代码中的相关文件，包括 `css_default_style_sheets.cc`。
    * 在 Blink 源代码中搜索相关的 CSS 属性名或者选择器，看是否在 `css_default_style_sheets.cc` 或其加载的资源文件中定义。
    * 如果怀疑是特定元素的默认样式问题，可能会搜索 `EnsureDefaultStyleSheetsForElement` 方法，查看是否为该元素类型加载了特定的默认样式表。

因此，当开发者遇到与浏览器默认样式相关的疑惑或问题时，`blink/renderer/core/css/css_default_style_sheets.cc` 文件及其加载的资源文件就成为了重要的调试线索，帮助开发者理解默认样式的来源和作用方式。

Prompt: 
```
这是目录为blink/renderer/core/css/css_default_style_sheets.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007, 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"

#include "third_party/blink/public/resources/grit/blink_resources.h"
#include "third_party/blink/renderer/core/css/media_query_evaluator.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/rule_set.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_permission_element.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/platform/data_resource_helper.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/leak_annotations.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace {
String MaybeRemoveCSSImportant(String string) {
  const StringView kImportantSuffix(" !important");
  return string.EndsWith(kImportantSuffix)
             ? string.Substring(0, string.length() - kImportantSuffix.length())
             : string;
}
}  // namespace

namespace blink {

CSSDefaultStyleSheets& CSSDefaultStyleSheets::Instance() {
  DEFINE_STATIC_LOCAL(Persistent<CSSDefaultStyleSheets>,
                      css_default_style_sheets,
                      (MakeGarbageCollected<CSSDefaultStyleSheets>()));
  return *css_default_style_sheets;
}

static const MediaQueryEvaluator& PrintEval() {
  DEFINE_STATIC_LOCAL(const Persistent<MediaQueryEvaluator>, static_print_eval,
                      (MakeGarbageCollected<MediaQueryEvaluator>("print")));
  return *static_print_eval;
}

static const MediaQueryEvaluator& ForcedColorsEval() {
  // We use "ua-forced-colors" here instead of "forced-colors" to indicate that
  // this is a UA hack for the "forced-colors" media query.
  DEFINE_STATIC_LOCAL(
      Persistent<MediaQueryEvaluator>, forced_colors_eval,
      (MakeGarbageCollected<MediaQueryEvaluator>("ua-forced-colors")));
  return *forced_colors_eval;
}

// static
void CSSDefaultStyleSheets::Init() {
  Instance();
}

// static
StyleSheetContents* CSSDefaultStyleSheets::ParseUASheet(const String& str) {
  // UA stylesheets always parse in the insecure context mode.
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(
          kUASheetMode, SecureContextMode::kInsecureContext));
  sheet->ParseString(str);
  // User Agent stylesheets are parsed once for the lifetime of the renderer
  // process and are intentionally leaked.
  LEAK_SANITIZER_IGNORE_OBJECT(sheet);
  return sheet;
}

// static
const MediaQueryEvaluator& CSSDefaultStyleSheets::ScreenEval() {
  DEFINE_STATIC_LOCAL(const Persistent<MediaQueryEvaluator>, static_screen_eval,
                      (MakeGarbageCollected<MediaQueryEvaluator>("screen")));
  return *static_screen_eval;
}

CSSDefaultStyleSheets::CSSDefaultStyleSheets()
    : media_controls_style_sheet_loader_(nullptr) {
  // Strict-mode rules.
  String default_rules = UncompressResourceAsASCIIString(IDR_UASTYLE_HTML_CSS) +
                         LayoutTheme::GetTheme().ExtraDefaultStyleSheet();

  default_style_sheet_ = ParseUASheet(default_rules);

  // Quirks-mode rules.
  String quirks_rules = UncompressResourceAsASCIIString(IDR_UASTYLE_QUIRKS_CSS);
  quirks_style_sheet_ = ParseUASheet(quirks_rules);

  InitializeDefaultStyles();
}

void CSSDefaultStyleSheets::PrepareForLeakDetection() {
  Reset();
}

void CSSDefaultStyleSheets::Reset() {
  // Clear the optional style sheets.
  svg_style_sheet_.Clear();
  mathml_style_sheet_.Clear();
  media_controls_style_sheet_.Clear();
  text_track_style_sheet_.Clear();
  forced_colors_style_sheet_.Clear();
  fullscreen_style_sheet_.Clear();
  customizable_select_style_sheet_.Clear();
  customizable_select_forced_colors_style_sheet_.Clear();
  marker_style_sheet_.Clear();
  permission_element_style_sheet_.Clear();
  // Recreate the default style sheet to clean up possible SVG resources.
  String default_rules = UncompressResourceAsASCIIString(IDR_UASTYLE_HTML_CSS) +
                         LayoutTheme::GetTheme().ExtraDefaultStyleSheet();
  default_style_sheet_ = ParseUASheet(default_rules);

  // Initialize the styles that have the lazily loaded style sheets.
  InitializeDefaultStyles();
  default_view_source_style_.Clear();
}

void CSSDefaultStyleSheets::VerifyUniversalRuleCount() {
#if EXPENSIVE_DCHECKS_ARE_ON()
  // Universal bucket rules need to be checked against every single element,
  // thus we want avoid them in UA stylesheets.
  default_html_style_->CompactRulesIfNeeded();
  DCHECK(default_html_style_->UniversalRules().empty());
  default_html_quirks_style_->CompactRulesIfNeeded();
  DCHECK(default_html_quirks_style_->UniversalRules().empty());

  // The RuleSets below currently contain universal bucket rules.
  // Ideally these should also be empty, DCHECK the current size to only
  // consciously add more universal bucket rules.
  if (mathml_style_sheet_) {
    default_mathml_style_->CompactRulesIfNeeded();
    DCHECK_EQ(default_mathml_style_->UniversalRules().size(), 24u);
  }

  if (svg_style_sheet_) {
    default_svg_style_->CompactRulesIfNeeded();
    DCHECK_EQ(default_svg_style_->UniversalRules().size(), 1u);
  }

  if (media_controls_style_sheet_) {
    default_media_controls_style_->CompactRulesIfNeeded();
    DCHECK_EQ(default_media_controls_style_->UniversalRules().size(), 4u);
  }

  if (fullscreen_style_sheet_) {
    default_fullscreen_style_->CompactRulesIfNeeded();
    // There are 7 rules by default but if the viewport segments MQs are
    // resolved then we have an additional rule.
    DCHECK(default_fullscreen_style_->UniversalRules().size() == 7u ||
           default_fullscreen_style_->UniversalRules().size() == 8u);
  }

  if (marker_style_sheet_) {
    default_pseudo_element_style_->CompactRulesIfNeeded();
    DCHECK_EQ(default_pseudo_element_style_->UniversalRules().size(), 3u);
  }
#endif
}

void CSSDefaultStyleSheets::InitializeDefaultStyles() {
  // This must be called only from constructor / PrepareForLeakDetection.
  default_html_style_ = MakeGarbageCollected<RuleSet>();
  default_mathml_style_ = MakeGarbageCollected<RuleSet>();
  default_svg_style_ = MakeGarbageCollected<RuleSet>();
  default_html_quirks_style_ = MakeGarbageCollected<RuleSet>();
  default_print_style_ = MakeGarbageCollected<RuleSet>();
  default_media_controls_style_ = MakeGarbageCollected<RuleSet>();
  default_fullscreen_style_ = MakeGarbageCollected<RuleSet>();
  default_forced_color_style_.Clear();
  default_pseudo_element_style_.Clear();
  default_forced_colors_media_controls_style_.Clear();

  default_html_style_->AddRulesFromSheet(DefaultStyleSheet(), ScreenEval());
  default_html_quirks_style_->AddRulesFromSheet(QuirksStyleSheet(),
                                                ScreenEval());
  default_print_style_->AddRulesFromSheet(DefaultStyleSheet(), PrintEval());

  CHECK(default_html_style_->ViewTransitionRules().empty())
      << "@view-transition is not implemented for the UA stylesheet.";

  VerifyUniversalRuleCount();
}

RuleSet* CSSDefaultStyleSheets::DefaultViewSourceStyle() {
  if (!default_view_source_style_) {
    default_view_source_style_ = MakeGarbageCollected<RuleSet>();
    // Loaded stylesheet is leaked on purpose.
    StyleSheetContents* stylesheet = ParseUASheet(
        UncompressResourceAsASCIIString(IDR_UASTYLE_VIEW_SOURCE_CSS));
    default_view_source_style_->AddRulesFromSheet(stylesheet, ScreenEval());
  }
  return default_view_source_style_.Get();
}

RuleSet* CSSDefaultStyleSheets::DefaultJSONDocumentStyle() {
  if (!default_json_document_style_) {
    StyleSheetContents* stylesheet = ParseUASheet(
        UncompressResourceAsASCIIString(IDR_UASTYLE_JSON_DOCUMENT_CSS));
    default_json_document_style_ = MakeGarbageCollected<RuleSet>();
    default_json_document_style_->AddRulesFromSheet(stylesheet, ScreenEval());
  }
  return default_json_document_style_.Get();
}

static void AddTextTrackCSSProperties(StringBuilder* builder,
                                      CSSPropertyID propertyId,
                                      String value) {
  builder->Append(CSSProperty::Get(propertyId).GetPropertyNameString());
  builder->Append(": ");
  builder->Append(value);
  builder->Append("; ");
}

void CSSDefaultStyleSheets::AddRulesToDefaultStyleSheets(
    StyleSheetContents* rules,
    NamespaceType type) {
  switch (type) {
    case NamespaceType::kHTML:
      default_html_style_->AddRulesFromSheet(rules, ScreenEval());
      break;
    case NamespaceType::kSVG:
      default_svg_style_->AddRulesFromSheet(rules, ScreenEval());
      break;
    case NamespaceType::kMathML:
      default_mathml_style_->AddRulesFromSheet(rules, ScreenEval());
      break;
    case NamespaceType::kMediaControls:
      default_media_controls_style_->AddRulesFromSheet(rules, ScreenEval());
      break;
  }
  // Add to print and forced color for all namespaces.
  default_print_style_->AddRulesFromSheet(rules, PrintEval());
  if (default_forced_color_style_) {
    switch (type) {
      case NamespaceType::kMediaControls:
        if (!default_forced_colors_media_controls_style_) {
          default_forced_colors_media_controls_style_ =
              MakeGarbageCollected<RuleSet>();
        }
        default_forced_colors_media_controls_style_->AddRulesFromSheet(
            rules, ForcedColorsEval());
        break;
      default:
        default_forced_color_style_->AddRulesFromSheet(rules,
                                                       ForcedColorsEval());
        break;
    }
  }
  VerifyUniversalRuleCount();
}

bool CSSDefaultStyleSheets::EnsureDefaultStyleSheetsForElement(
    const Element& element) {
  bool changed_default_style = false;
  // FIXME: We should assert that the sheet only styles SVG elements.
  if (element.IsSVGElement() && !svg_style_sheet_) {
    svg_style_sheet_ =
        ParseUASheet(UncompressResourceAsASCIIString(IDR_UASTYLE_SVG_CSS));
    AddRulesToDefaultStyleSheets(svg_style_sheet_, NamespaceType::kSVG);
    changed_default_style = true;
  }

  // FIXME: We should assert that the sheet only styles MathML elements.
  if (element.namespaceURI() == mathml_names::kNamespaceURI &&
      !mathml_style_sheet_) {
    mathml_style_sheet_ =
        ParseUASheet(UncompressResourceAsASCIIString(IDR_UASTYLE_MATHML_CSS));
    AddRulesToDefaultStyleSheets(mathml_style_sheet_, NamespaceType::kMathML);
    changed_default_style = true;
  }

  if (!media_controls_style_sheet_ && HasMediaControlsStyleSheetLoader() &&
      (IsA<HTMLVideoElement>(element) || IsA<HTMLAudioElement>(element))) {
    // FIXME: We should assert that this sheet only contains rules for <video>
    // and <audio>.
    media_controls_style_sheet_ =
        ParseUASheet(media_controls_style_sheet_loader_->GetUAStyleSheet());
    AddRulesToDefaultStyleSheets(media_controls_style_sheet_,
                                 NamespaceType::kMediaControls);
    changed_default_style = true;
  }

  if (!permission_element_style_sheet_ && IsA<HTMLPermissionElement>(element)) {
    CHECK(RuntimeEnabledFeatures::PermissionElementEnabled(
        element.GetExecutionContext()));
    permission_element_style_sheet_ = ParseUASheet(
        UncompressResourceAsASCIIString(IDR_UASTYLE_PERMISSION_ELEMENT_CSS));
    AddRulesToDefaultStyleSheets(permission_element_style_sheet_,
                                 NamespaceType::kHTML);
    changed_default_style = true;
  }

  if (!text_track_style_sheet_ && IsA<HTMLVideoElement>(element)) {
    Settings* settings = element.GetDocument().GetSettings();
    if (settings) {
      // Rules below override rules from html.css and other UA sheets regardless
      // of specificity. See comment in StyleResolver::MatchUARules().
      StringBuilder builder;
      Color color;
      // Use the text track window color if it is set and non-transparent,
      // otherwise use the background color. This is only applicable to caption
      // settings on MacOS, which allows users to specify a window color in
      // addition to a background color. The WebVTT spec does not have a concept
      // of a window background, so this workaround allows the default caption
      // styles on MacOS to render as expected.
      builder.Append("video::cue { ");
      if (CSSParser::ParseColor(
              color,
              MaybeRemoveCSSImportant(settings->GetTextTrackWindowColor()),
              /*strict=*/true) &&
          color.Alpha() > 0) {
        AddTextTrackCSSProperties(&builder, CSSPropertyID::kBackgroundColor,
                                  settings->GetTextTrackWindowColor());
        AddTextTrackCSSProperties(&builder, CSSPropertyID::kBorderRadius,
                                  settings->GetTextTrackWindowRadius());
      } else {
        AddTextTrackCSSProperties(&builder, CSSPropertyID::kBackgroundColor,
                                  settings->GetTextTrackBackgroundColor());
      }
      AddTextTrackCSSProperties(&builder, CSSPropertyID::kFontFamily,
                                settings->GetTextTrackFontFamily());
      AddTextTrackCSSProperties(&builder, CSSPropertyID::kFontStyle,
                                settings->GetTextTrackFontStyle());
      AddTextTrackCSSProperties(&builder, CSSPropertyID::kFontVariant,
                                settings->GetTextTrackFontVariant());
      AddTextTrackCSSProperties(&builder, CSSPropertyID::kColor,
                                settings->GetTextTrackTextColor());
      AddTextTrackCSSProperties(&builder, CSSPropertyID::kTextShadow,
                                settings->GetTextTrackTextShadow());
      AddTextTrackCSSProperties(&builder, CSSPropertyID::kFontSize,
                                settings->GetTextTrackTextSize());
      builder.Append(" } ");
      text_track_style_sheet_ = ParseUASheet(builder.ReleaseString());
      AddRulesToDefaultStyleSheets(text_track_style_sheet_,
                                   NamespaceType::kMediaControls);
      changed_default_style = true;
    }
  }

  if (!customizable_select_style_sheet_ && IsA<HTMLSelectElement>(element) &&
      RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    // TODO(crbug.com/1511354): Merge customizable_select.css into html.css and
    // remove this code.
    customizable_select_style_sheet_ = ParseUASheet(
        UncompressResourceAsASCIIString(IDR_UASTYLE_CUSTOMIZABLE_SELECT_CSS));
    AddRulesToDefaultStyleSheets(customizable_select_style_sheet_,
                                 NamespaceType::kHTML);
    changed_default_style = true;
  }

  DCHECK(!default_html_style_->Features()
              .GetRuleInvalidationData()
              .HasIdsInSelectors());
  return changed_default_style;
}

bool CSSDefaultStyleSheets::EnsureDefaultStyleSheetsForPseudoElement(
    PseudoId pseudo_id) {
  switch (pseudo_id) {
    case kPseudoIdMarker: {
      if (marker_style_sheet_) {
        return false;
      }
      marker_style_sheet_ =
          ParseUASheet(UncompressResourceAsASCIIString(IDR_UASTYLE_MARKER_CSS));
      if (!default_pseudo_element_style_) {
        default_pseudo_element_style_ = MakeGarbageCollected<RuleSet>();
      }
      default_pseudo_element_style_->AddRulesFromSheet(MarkerStyleSheet(),
                                                       ScreenEval());
      return true;
    }
    default:
      return false;
  }
}

void CSSDefaultStyleSheets::SetMediaControlsStyleSheetLoader(
    std::unique_ptr<UAStyleSheetLoader> loader) {
  media_controls_style_sheet_loader_.swap(loader);
}

void CSSDefaultStyleSheets::EnsureDefaultStyleSheetForFullscreen(
    const Element& element) {
  if (fullscreen_style_sheet_) {
    DCHECK(!default_fullscreen_style_->DidMediaQueryResultsChange(
        MediaQueryEvaluator(element.GetDocument().GetFrame())));
    return;
  }

  String fullscreen_rules =
      UncompressResourceAsASCIIString(IDR_UASTYLE_FULLSCREEN_CSS) +
      LayoutTheme::GetTheme().ExtraFullscreenStyleSheet();
  fullscreen_style_sheet_ = ParseUASheet(fullscreen_rules);

  default_fullscreen_style_->AddRulesFromSheet(
      fullscreen_style_sheet_,
      MediaQueryEvaluator(element.GetDocument().GetFrame()));
  VerifyUniversalRuleCount();
}

void CSSDefaultStyleSheets::RebuildFullscreenRuleSetIfMediaQueriesChanged(
    const Element& element) {
  if (!fullscreen_style_sheet_) {
    return;
  }

  if (!default_fullscreen_style_->DidMediaQueryResultsChange(
          MediaQueryEvaluator(element.GetDocument().GetFrame()))) {
    return;
  }

  default_fullscreen_style_ = MakeGarbageCollected<RuleSet>();
  default_fullscreen_style_->AddRulesFromSheet(
      fullscreen_style_sheet_,
      MediaQueryEvaluator(element.GetDocument().GetFrame()));
  VerifyUniversalRuleCount();
}

bool CSSDefaultStyleSheets::EnsureDefaultStyleSheetForForcedColors() {
  if (forced_colors_style_sheet_) {
    return false;
  }

  String forced_colors_rules = String();
  if (RuntimeEnabledFeatures::ForcedColorsEnabled()) {
    forced_colors_rules =
        forced_colors_rules +
        UncompressResourceAsASCIIString(IDR_UASTYLE_THEME_FORCED_COLORS_CSS);
    if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
      forced_colors_rules =
          forced_colors_rules +
          UncompressResourceAsASCIIString(
              IDR_UASTYLE_CUSTOMIZABLE_SELECT_FORCED_COLORS_CSS);
    }
  }
  forced_colors_style_sheet_ = ParseUASheet(forced_colors_rules);

  if (!default_forced_color_style_) {
    default_forced_color_style_ = MakeGarbageCollected<RuleSet>();
  }
  default_forced_color_style_->AddRulesFromSheet(DefaultStyleSheet(),
                                                 ForcedColorsEval());
  default_forced_color_style_->AddRulesFromSheet(ForcedColorsStyleSheet(),
                                                 ForcedColorsEval());
  if (svg_style_sheet_) {
    default_forced_color_style_->AddRulesFromSheet(SvgStyleSheet(),
                                                   ForcedColorsEval());
  }

  if (media_controls_style_sheet_) {
    CHECK(!default_forced_colors_media_controls_style_);
    default_forced_colors_media_controls_style_ =
        MakeGarbageCollected<RuleSet>();
    default_forced_colors_media_controls_style_->AddRulesFromSheet(
        MediaControlsStyleSheet(), ForcedColorsEval());
  }

  return true;
}

void CSSDefaultStyleSheets::CollectFeaturesTo(const Document& document,
                                              RuleFeatureSet& features) {
  if (DefaultHtmlStyle()) {
    features.Merge(DefaultHtmlStyle()->Features());
  }
  if (DefaultMediaControlsStyle()) {
    features.Merge(DefaultMediaControlsStyle()->Features());
  }
  if (DefaultMathMLStyle()) {
    features.Merge(DefaultMathMLStyle()->Features());
  }
  if (DefaultFullscreenStyle()) {
    features.Merge(DefaultFullscreenStyle()->Features());
  }
  if (document.IsViewSource() && DefaultViewSourceStyle()) {
    features.Merge(DefaultViewSourceStyle()->Features());
  }
  if (document.IsJSONDocument() && DefaultJSONDocumentStyle()) {
    features.Merge(DefaultJSONDocumentStyle()->Features());
  }
}

void CSSDefaultStyleSheets::Trace(Visitor* visitor) const {
  visitor->Trace(default_html_style_);
  visitor->Trace(default_mathml_style_);
  visitor->Trace(default_svg_style_);
  visitor->Trace(default_html_quirks_style_);
  visitor->Trace(default_print_style_);
  visitor->Trace(default_view_source_style_);
  visitor->Trace(default_forced_color_style_);
  visitor->Trace(default_pseudo_element_style_);
  visitor->Trace(default_media_controls_style_);
  visitor->Trace(default_fullscreen_style_);
  visitor->Trace(default_style_sheet_);
  visitor->Trace(quirks_style_sheet_);
  visitor->Trace(svg_style_sheet_);
  visitor->Trace(mathml_style_sheet_);
  visitor->Trace(media_controls_style_sheet_);
  visitor->Trace(permission_element_style_sheet_);
  visitor->Trace(text_track_style_sheet_);
  visitor->Trace(forced_colors_style_sheet_);
  visitor->Trace(fullscreen_style_sheet_);
  visitor->Trace(customizable_select_style_sheet_);
  visitor->Trace(customizable_select_forced_colors_style_sheet_);
  visitor->Trace(marker_style_sheet_);
  visitor->Trace(default_json_document_style_);
  visitor->Trace(default_forced_colors_media_controls_style_);
}

CSSDefaultStyleSheets::TestingScope::TestingScope() = default;
CSSDefaultStyleSheets::TestingScope::~TestingScope() {
  Instance().Reset();
}

}  // namespace blink

"""

```