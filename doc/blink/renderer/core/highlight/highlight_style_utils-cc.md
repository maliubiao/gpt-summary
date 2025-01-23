Response:
Let's break down the thought process for analyzing this code and generating the explanation.

1. **Understand the Goal:** The request is to analyze the `highlight_style_utils.cc` file and explain its functionalities, its relation to web technologies (HTML, CSS, JavaScript), provide examples, and highlight potential usage errors.

2. **Initial Scan and Keyword Identification:** I'd start by quickly scanning the code, looking for recognizable keywords and structures. Things that immediately stand out are:

    * `#include` directives: These tell us about dependencies (CSS properties, style resolution, DOM elements, selection, etc.).
    * `namespace blink`: This confirms it's part of the Blink rendering engine.
    * Function names like `ForcedForegroundColor`, `ForcedBackgroundColor`, `DefaultForegroundColor`, `DefaultBackgroundColor`, `ResolveColor`, `HighlightPseudoStyle`, `HighlightBackgroundColor`, `HighlightPaintingStyle`. These strongly suggest the file is about calculating and applying styles to highlighted text.
    * Pseudo-selectors: `kPseudoIdSearchText`, `kPseudoIdTargetText`, `kPseudoIdSelection`, `kPseudoIdHighlight`, etc. This confirms the focus on CSS pseudo-elements related to highlighting.
    * References to `ComputedStyle`:  A core Blink class representing the final computed styles of an element.
    * References to `LayoutTheme`:  Indicates interaction with the browser's native theming.
    * `document.InForcedColorsMode()`: Points to accessibility features.

3. **Categorize Functionality:** Based on the initial scan, I'd start grouping the functions by their apparent purpose.

    * **Forced Colors:** Functions starting with `Forced` seem related to handling the "forced colors" accessibility feature.
    * **Default Colors:** Functions starting with `Default` likely provide browser defaults for highlight styles.
    * **Style Resolution:** Functions like `ResolveColor` and `MaybeResolveColor` are involved in determining the final color value based on various factors.
    * **Pseudo-Style Retrieval:** Functions like `HighlightPseudoStyle` and `HighlightPseudoStyleWithOriginatingInheritance` are responsible for getting the `ComputedStyle` for highlight pseudo-elements.
    * **Specific Highlight Types:**  Functions like `HighlightBackgroundColor` seem tailored to specific highlight properties.
    * **Painting Style:** `HighlightPaintingStyle` appears to assemble a comprehensive style object for painting highlighted text.
    * **Invalidation:** `ShouldInvalidateVisualOverflow` deals with triggering layout updates.

4. **Analyze Key Functions in Detail:**  I'd then pick out the most important functions and delve deeper into their logic.

    * **`ForcedForegroundColor` and `ForcedBackgroundColor`:** Note the switch statements mapping pseudo-selectors to system color keywords (`kHighlighttext`, `kHighlight`, etc.). This directly links highlighting to the OS/browser theme.
    * **`DefaultForegroundColor` and `DefaultBackgroundColor`:**  Observe how these functions handle different highlight types (selection, search, target text) and consider factors like focus and active states. The interaction with `LayoutTheme` is crucial.
    * **`ResolveColor` and `MaybeResolveColor`:**  Pay attention to the order of checks: forced colors, default highlight colors, and then author styles. This reflects the CSS cascading order. The concept of "paired cascade" is important here.
    * **`HighlightPseudoStyle`:**  Distinguish between the inheriting and non-inheriting versions and how they fetch the `ComputedStyle` for the pseudo-elements. The interaction with `HighlightData` in `ComputedStyle` is key.
    * **`HighlightPaintingStyle`:**  See how it combines styles from previous layers and considers properties like `text-decoration`, `text-shadow`, etc.

5. **Identify Connections to Web Technologies:**  As I analyze the functions, I'd explicitly think about how they relate to HTML, CSS, and JavaScript.

    * **CSS:**  The entire file is about implementing CSS highlighting features, particularly pseudo-elements like `::selection`, `::search-text`, `::target-text`, `::spelling-error`, `::grammar-error`, and `::highlight`. The functions directly manipulate CSS properties.
    * **HTML:**  Highlighting is applied to elements in the HTML document. The code interacts with `Node` and `Element` objects representing the HTML structure.
    * **JavaScript:** While this specific file isn't JavaScript, it's part of the rendering engine that interprets and applies styles set by JavaScript (e.g., through setting CSS properties or manipulating the DOM). The highlighting logic is *used* when rendering based on styles that might have originated from JavaScript.

6. **Construct Examples:**  For each connection to web technologies, create simple, illustrative examples. Focus on demonstrating how the code's functionality manifests in a web page.

7. **Consider Logic and Assumptions:**  Where the code performs conditional logic (e.g., checking for forced colors, active selection), think about the inputs and outputs. For instance, in `HighlightBackgroundColor` for selection, consider the case where `!style.IsSelectable()`.

8. **Identify Potential Errors:** Based on the code's logic and the way web developers use these features, think about common mistakes. For example, misunderstanding pseudo-element specificity or the interaction of forced colors with custom styles.

9. **Structure the Explanation:** Organize the information logically:

    * Start with a high-level summary of the file's purpose.
    * Detail the individual functionalities.
    * Explain the relationships to HTML, CSS, and JavaScript with examples.
    * Provide examples of logical reasoning with input/output scenarios.
    * Highlight common usage errors.

10. **Refine and Review:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation. Ensure the examples are easy to understand.

Essentially, it's a process of dissecting the code, understanding its purpose within the larger Blink architecture, and then connecting that understanding to the everyday experiences of web developers and users. The key is to move from the code's implementation details to its observable behavior and practical implications.
这个文件 `highlight_style_utils.cc` 的主要功能是提供一系列实用工具函数，用于计算和解析应用于文本高亮显示的样式。这些高亮显示可以是浏览器内置的（例如，用户选择的文本），也可以是网页通过CSS伪元素（例如 `::selection`, `::highlight`, `::target-text` 等）或API请求的。

以下是其功能的详细列表以及与 JavaScript, HTML, CSS 的关系：

**核心功能:**

1. **管理和计算高亮伪元素样式:**
   - 针对不同的高亮伪元素（例如 `::selection`, `::search-text`, `::target-text`, `::spelling-error`, `::grammar-error`, 以及自定义的 `::highlight`），提供获取其 `ComputedStyle` 的方法。
   - `HighlightPseudoStyle`:  根据节点和伪元素类型，返回相应的 `ComputedStyle` 对象。这个函数考虑了高亮伪元素的继承规则。
   - `HighlightPseudoStyleWithOriginatingInheritance`:  提供一种只从原始元素继承样式的方式，用于一些历史遗留的实现。

2. **处理强制颜色模式 (Forced Colors Mode):**
   -  在强制颜色模式下，根据不同的高亮伪元素，返回系统预定义的颜色。
   - `ForcedForegroundColor`:  返回指定高亮伪元素在强制颜色模式下的前景色（例如，文本颜色）。
   - `ForcedBackgroundColor`:  返回指定高亮伪元素在强制颜色模式下的背景色。
   - `ForcedColor`:  根据 CSS 属性是 `background-color` 还是其他颜色属性，调用 `ForcedBackgroundColor` 或 `ForcedForegroundColor`。
   - `UseForcedColors`: 判断当前是否应该使用强制颜色模式来渲染高亮。

3. **处理默认高亮颜色:**
   - 提供获取浏览器默认高亮颜色的方法。
   - `DefaultForegroundColor`:  返回指定高亮伪元素的默认前景色。例如，选中文本的默认前景色取决于窗口是否激活。
   - `DefaultBackgroundColor`:  返回指定高亮伪元素的默认背景色。
   - `DefaultHighlightColor`:  根据 CSS 属性是 `color` 还是 `background-color`，调用 `DefaultForegroundColor` 或 `DefaultBackgroundColor`。
   - `UseDefaultHighlightColors`: 判断是否应该使用默认的高亮颜色（例如，当作者没有明确指定高亮颜色时）。

4. **解析和合并高亮颜色值:**
   - `ResolveColor`:  解析高亮颜色属性的值，考虑强制颜色、默认颜色和作者样式。如果最终解析出的颜色是 `currentColor`，则返回前一层的颜色。
   - `MaybeResolveColor`:  类似于 `ResolveColor`，但如果解析结果是 `currentColor`，则返回 `std::nullopt`。

5. **计算高亮背景色:**
   - `HighlightBackgroundColor`:  计算指定节点和高亮伪元素的最终背景色，考虑可选择性、被替换元素以及默认颜色反转等特殊情况。

6. **获取高亮文本装饰:**
   - `SelectionTextDecoration`:  获取选中文本的文本装饰（例如，下划线）。

7. **计算高亮绘制样式 (Painting Style):**
   - `HighlightPaintingStyle`:  创建一个 `HighlightTextPaintStyle` 对象，包含了用于绘制高亮文本的各种样式信息，例如颜色、描边、阴影、文本装饰等。这个函数会考虑强制颜色、默认颜色和作者样式。
   - `ResolveColorsFromPreviousLayer`:  当高亮样式中的某些颜色值是 `currentColor` 时，从前一层的样式中解析出实际的颜色值。

8. **判断是否需要重绘:**
   - `ShouldInvalidateVisualOverflow`: 判断某种类型的高亮标记是否会导致视觉溢出，从而需要重新渲染。
   - `CustomHighlightHasVisualOverflow`: 判断自定义高亮是否会导致视觉溢出。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:** 这个文件是 Blink 渲染引擎处理 CSS 高亮相关特性的核心部分。它实现了 CSS 规范中关于 `::selection` 以及其他高亮伪元素的行为。
    - **例子:** 当 CSS 规则中设置了 `::selection { background-color: yellow; color: black; }` 时，这个文件中的函数会被调用来计算选中文本的背景色和前景色。
    - **例子:** 对于自定义高亮，例如通过 JavaScript API 添加的，其样式会通过这里的方法进行解析和应用。

* **HTML:**  高亮效果应用于 HTML 文档中的元素。这个文件中的函数接收 `Node` 和 `Element` 对象作为输入，这些对象代表了 HTML 文档的结构。
    - **例子:** 当用户在浏览器中选择一段文本（对应 HTML 中的一些 `Text` 节点），`HighlightBackgroundColor` 等函数会被用来确定选中文本的背景色。

* **JavaScript:** 虽然这个文件本身是 C++ 代码，但它支撑着 JavaScript API 暴露的高亮相关功能。
    - **例子:**  JavaScript 可以使用 Selection API 来获取用户选择的文本，而这个文件中的代码负责渲染选择效果。
    - **例子:**  一些实验性的 JavaScript API 允许开发者创建自定义的高亮效果，这些效果的样式计算也会涉及到这个文件。

**逻辑推理示例:**

假设输入一个 `Text` 节点，并且该节点当前被用户选中。

**假设输入:**
- `node`: 指向被选中的 `Text` 节点的指针。
- `pseudo`: `kPseudoIdSelection` (表示 ::selection 伪元素)。
- `originating_style`:  该 `Text` 节点所在元素的 `ComputedStyle`。
- CSS 样式表中有规则： `::selection { background-color: rgba(255, 0, 0, 0.5); }`

**输出:**
- 调用 `HighlightBackgroundColor(document, originating_style, node, std::nullopt, kPseudoIdSelection, ...)`
- `HighlightPseudoStyle(node, originating_style, kPseudoIdSelection)` 将返回一个 `ComputedStyle` 对象，其中包含 `background-color: rgba(255, 0, 0, 0.5);`。
- `ResolveColor` 函数会被调用，并最终返回 `Color::RGBA(255, 0, 0, 128)` (因为 alpha 值 0.5 对应 128)。
- `HighlightBackgroundColor` 最终可能会返回一个混合了白色背景的颜色，如果该节点是一个被替换元素（例如 `<img>`）。

**用户或编程常见的使用错误示例:**

1. **误解伪元素继承:**  开发者可能认为高亮伪元素的样式会像普通元素一样继承自父元素，但实际上它们的继承规则可能有所不同。例如，`::selection` 通常不会继承父元素的 `background-color`。

   **错误示例 (CSS):**
   ```css
   .parent {
     background-color: lightblue;
   }

   ::selection { /* 期望继承 .parent 的背景色 */ }
   ```
   **说明:**  开发者可能期望选中文本的背景色是 `lightblue`，但实际上如果没有明确设置 `::selection` 的 `background-color`，浏览器会使用默认的选中背景色。

2. **在强制颜色模式下的样式覆盖:** 开发者可能没有考虑到强制颜色模式会覆盖他们自定义的高亮颜色。

   **错误示例 (CSS):**
   ```css
   ::selection {
     background-color: yellow; /* 在非强制颜色模式下生效 */
   }
   ```
   **说明:**  如果用户启用了强制颜色模式，浏览器会忽略这里的 `background-color: yellow;`，而使用系统定义的选中背景色。

3. **不恰当的使用 `currentColor`:** 开发者可能在不理解 `currentColor` 上下文的情况下在高亮伪元素中使用它，导致意外的颜色。

   **错误示例 (CSS):**
   ```css
   ::selection {
     background-color: currentColor; /* 这里的 currentColor 指的是什么？ */
   }
   ```
   **说明:**  `currentColor` 的值取决于应用该样式的元素的 `color` 属性。在高亮伪元素中，如果没有正确理解继承或初始值，可能会得到意想不到的颜色。

4. **忘记处理被替换元素的选中状态:**  开发者可能没有意识到选中文本的背景色在被替换元素上可能会有特殊处理，例如与白色混合以避免完全遮挡内容。

   **错误示例 (假设 JavaScript 操作 DOM):**
   ```javascript
   // 假设动态创建一个可选择的图片
   const img = document.createElement('img');
   img.src = '...';
   // ... 添加到 DOM ...
   ```
   **说明:**  开发者可能期望通过 CSS 设置的 `::selection` 背景色完全覆盖图片，但浏览器可能会为了可读性进行混合。

总而言之，`highlight_style_utils.cc` 是 Blink 渲染引擎中一个关键的模块，负责处理各种高亮场景下的样式计算和应用，确保用户能够在不同的浏览器设置和网页样式下获得一致且符合预期的视觉反馈。理解其功能有助于开发者更好地掌握 CSS 高亮特性的工作原理，避免常见的样式错误。

### 提示词
```
这是目录为blink/renderer/core/highlight/highlight_style_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/highlight/highlight_style_utils.h"

#include "components/shared_highlighting/core/common/fragment_directives_constants.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_request.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/text_paint_style.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

bool NodeIsReplaced(Node* node) {
  return node && node->GetLayoutObject() &&
         node->GetLayoutObject()->IsLayoutReplaced();
}

mojom::blink::ColorScheme UsedColorScheme(
    const ComputedStyle& originating_style,
    const ComputedStyle* pseudo_style) {
  return pseudo_style ? pseudo_style->UsedColorScheme()
                      : originating_style.UsedColorScheme();
}

// Returns the forced foreground color for the given |pseudo|.
Color ForcedForegroundColor(PseudoId pseudo,
                            mojom::blink::ColorScheme color_scheme,
                            const ui::ColorProvider* color_provider,
                            bool is_in_web_app_scope) {
  CSSValueID keyword = CSSValueID::kHighlighttext;
  switch (pseudo) {
    case kPseudoIdSearchText:
      keyword = CSSValueID::kInternalSearchTextColor;
      break;
    case kPseudoIdTargetText:
      // TODO(futhark): According to the spec, the UA style should use Marktext.
      keyword = CSSValueID::kHighlighttext;
      break;
    case kPseudoIdSelection:
      keyword = CSSValueID::kHighlighttext;
      break;
    case kPseudoIdHighlight:
      keyword = CSSValueID::kHighlighttext;
      break;
    case kPseudoIdSpellingError:
    case kPseudoIdGrammarError:
      keyword = CSSValueID::kCanvastext;
      break;
    default:
      NOTREACHED();
  }
  return LayoutTheme::GetTheme().SystemColor(
      keyword, color_scheme, color_provider, is_in_web_app_scope);
}

// Returns the forced ‘background-color’ for the given |pseudo|.
Color ForcedBackgroundColor(PseudoId pseudo,
                            mojom::blink::ColorScheme color_scheme,
                            const ui::ColorProvider* color_provider,
                            bool is_in_web_app_scope) {
  CSSValueID keyword = CSSValueID::kHighlight;
  switch (pseudo) {
    case kPseudoIdSearchText:
      keyword = CSSValueID::kInternalSearchColor;
      break;
    case kPseudoIdTargetText:
      // TODO(futhark): According to the spec, the UA style should use Mark.
      keyword = CSSValueID::kHighlight;
      break;
    case kPseudoIdSelection:
      keyword = CSSValueID::kHighlight;
      break;
    case kPseudoIdHighlight:
      keyword = CSSValueID::kHighlight;
      break;
    case kPseudoIdSpellingError:
    case kPseudoIdGrammarError:
      keyword = CSSValueID::kCanvas;
      break;
    default:
      NOTREACHED();
  }
  return LayoutTheme::GetTheme().SystemColor(
      keyword, color_scheme, color_provider, is_in_web_app_scope);
}

// Returns the forced background color if |property| is ‘background-color’,
// or the forced foreground color for all other properties (e.g. ‘color’,
// ‘text-decoration-color’, ‘-webkit-text-fill-color’).
Color ForcedColor(const ComputedStyle& originating_style,
                  const ComputedStyle* pseudo_style,
                  PseudoId pseudo,
                  const CSSProperty& property,
                  const ui::ColorProvider* color_provider,
                  bool is_in_web_app_scope) {
  mojom::blink::ColorScheme color_scheme =
      UsedColorScheme(originating_style, pseudo_style);
  if (property.IDEquals(CSSPropertyID::kBackgroundColor)) {
    return ForcedBackgroundColor(pseudo, color_scheme, color_provider,
                                 is_in_web_app_scope);
  }
  return ForcedForegroundColor(pseudo, color_scheme, color_provider,
                               is_in_web_app_scope);
}

// Returns the UA default ‘color’ for the given |pseudo|.
std::optional<Color> DefaultForegroundColor(
    const Document& document,
    PseudoId pseudo,
    mojom::blink::ColorScheme color_scheme,
    SearchTextIsActiveMatch search_text_is_active_match) {
  switch (pseudo) {
    case kPseudoIdSelection:
      if (!LayoutTheme::GetTheme().SupportsSelectionForegroundColors()) {
        return std::nullopt;
      }
      if (document.GetFrame()->Selection().FrameIsFocusedAndActive()) {
        return LayoutTheme::GetTheme().ActiveSelectionForegroundColor(
            color_scheme);
      }
      return LayoutTheme::GetTheme().InactiveSelectionForegroundColor(
          color_scheme);
    case kPseudoIdSearchText:
      return LayoutTheme::GetTheme().PlatformTextSearchColor(
          search_text_is_active_match == SearchTextIsActiveMatch::kYes,
          document.InForcedColorsMode(), color_scheme,
          document.GetColorProviderForPainting(color_scheme),
          document.IsInWebAppScope());
    case kPseudoIdTargetText:
      return LayoutTheme::GetTheme().PlatformTextSearchColor(
          false /* active match */, document.InForcedColorsMode(), color_scheme,
          document.GetColorProviderForPainting(color_scheme),
          document.IsInWebAppScope());
    case kPseudoIdSpellingError:
    case kPseudoIdGrammarError:
    case kPseudoIdHighlight:
      return std::nullopt;
    default:
      NOTREACHED();
  }
}

// Returns the UA default ‘background-color’ for the given |pseudo|.
Color DefaultBackgroundColor(
    const Document& document,
    PseudoId pseudo,
    mojom::blink::ColorScheme color_scheme,
    SearchTextIsActiveMatch search_text_is_active_match) {
  switch (pseudo) {
    case kPseudoIdSelection:
      return document.GetFrame()->Selection().FrameIsFocusedAndActive()
                 ? LayoutTheme::GetTheme().ActiveSelectionBackgroundColor(
                       color_scheme)
                 : LayoutTheme::GetTheme().InactiveSelectionBackgroundColor(
                       color_scheme);
    case kPseudoIdSearchText:
      return LayoutTheme::GetTheme().PlatformTextSearchHighlightColor(
          search_text_is_active_match == SearchTextIsActiveMatch::kYes,
          document.InForcedColorsMode(), color_scheme,
          document.GetColorProviderForPainting(color_scheme),
          document.IsInWebAppScope());
    case kPseudoIdTargetText:
      return Color::FromRGBA32(
          shared_highlighting::kFragmentTextBackgroundColorARGB);
    case kPseudoIdSpellingError:
    case kPseudoIdGrammarError:
    case kPseudoIdHighlight:
      return Color::kTransparent;
    default:
      NOTREACHED();
  }
}

// Returns the UA default highlight color for a paired cascade |property|,
// that is, ‘color’ or ‘background-color’. Paired cascade only applies to those
// properties, not ‘-webkit-text-fill-color’ or ‘-webkit-text-stroke-color’.
std::optional<Color> DefaultHighlightColor(
    const Document& document,
    const ComputedStyle& originating_style,
    const ComputedStyle* pseudo_style,
    PseudoId pseudo,
    const CSSProperty& property,
    SearchTextIsActiveMatch search_text_is_active_match) {
  mojom::blink::ColorScheme color_scheme =
      UsedColorScheme(originating_style, pseudo_style);
  if (property.IDEquals(CSSPropertyID::kBackgroundColor)) {
    return DefaultBackgroundColor(document, pseudo, color_scheme,
                                  search_text_is_active_match);
  }
  DCHECK(property.IDEquals(CSSPropertyID::kColor));
  return DefaultForegroundColor(document, pseudo, color_scheme,
                                search_text_is_active_match);
}

// Returns highlight styles for the given node, inheriting from the originating
// element only, like most impls did before highlights were added to css-pseudo.
const ComputedStyle* HighlightPseudoStyleWithOriginatingInheritance(
    Node* node,
    PseudoId pseudo,
    const AtomicString& pseudo_argument = g_null_atom) {
  if (!node) {
    return nullptr;
  }

  Element* element = nullptr;

  // In Blink, highlight pseudo style only applies to direct children of the
  // element on which the highlight pseudo is matched. In order to be able to
  // style highlight inside elements implemented with a UA shadow tree, like
  // input::selection, we calculate highlight style on the shadow host for
  // elements inside the UA shadow.
  ShadowRoot* root = node->ContainingShadowRoot();
  if (root && root->IsUserAgent()) {
    element = node->OwnerShadowHost();
  }

  // If we request highlight style for LayoutText, query highlight style on the
  // parent element instead, as that is the node for which the highligh pseudo
  // matches. This should most likely have used FlatTreeTraversal, but since we
  // don't implement inheritance of highlight styles, it would probably break
  // cases where you style a shadow host with a highlight pseudo and expect
  // light tree text children to be affected by that style.
  if (!element) {
    element = Traversal<Element>::FirstAncestorOrSelf(*node);
  }

  if (!element || element->IsPseudoElement()) {
    return nullptr;
  }

  if (pseudo == kPseudoIdSelection &&
      element->GetDocument().GetStyleEngine().UsesWindowInactiveSelector() &&
      !element->GetDocument().GetPage()->GetFocusController().IsActive()) {
    // ::selection and ::selection:window-inactive styles may be different. Only
    // cache the styles for ::selection if there are no :window-inactive
    // selector, or if the page is active.
    // With Originating Inheritance the originating element is also the parent
    // element.
    return element->UncachedStyleForPseudoElement(
        StyleRequest(pseudo, element->GetComputedStyle(),
                     element->GetComputedStyle(), pseudo_argument));
  }

  return element->CachedStyleForPseudoElement(pseudo, pseudo_argument);
}

bool UseForcedColors(const Document& document,
                     const ComputedStyle& originating_style,
                     const ComputedStyle* pseudo_style) {
  if (!document.InForcedColorsMode()) {
    return false;
  }
  // TODO(crbug.com/1309835) simplify when valid_for_highlight_legacy is removed
  if (pseudo_style) {
    return pseudo_style->ForcedColorAdjust() == EForcedColorAdjust::kAuto;
  }
  return originating_style.ForcedColorAdjust() == EForcedColorAdjust::kAuto;
}

// Paired cascade: when we encounter any highlight colors, we make all other
// highlight color properties default to initial, rather than the UA default.
// https://drafts.csswg.org/css-pseudo-4/#paired-defaults
bool UseDefaultHighlightColors(const ComputedStyle* pseudo_style,
                               PseudoId pseudo,
                               const CSSProperty& property) {
  switch (property.PropertyID()) {
    case CSSPropertyID::kColor:
    case CSSPropertyID::kBackgroundColor:
      return !pseudo_style || (UsesHighlightPseudoInheritance(pseudo) &&
                               !pseudo_style->HasAuthorHighlightColors());
    default:
      return false;
  }
}

}  // anonymous namespace

Color HighlightStyleUtils::ResolveColor(
    const Document& document,
    const ComputedStyle& originating_style,
    const ComputedStyle* pseudo_style,
    PseudoId pseudo,
    const CSSProperty& property,
    std::optional<Color> current_color,
    SearchTextIsActiveMatch search_text_is_active_match) {
  std::optional<Color> maybe_color =
      MaybeResolveColor(document, originating_style, pseudo_style, pseudo,
                        property, search_text_is_active_match);
  if (maybe_color) {
    return maybe_color.value();
  }
  if (!current_color) {
    return originating_style.VisitedDependentColor(GetCSSPropertyColor());
  }
  return current_color.value();
}

// Returns the used value of the given <color>-valued |property|, taking into
// account forced colors and default highlight colors. If the final result is
// ‘currentColor’, return nullopt so that the color may later be resolved
// against the previous layer.
std::optional<Color> HighlightStyleUtils::MaybeResolveColor(
    const Document& document,
    const ComputedStyle& originating_style,
    const ComputedStyle* pseudo_style,
    PseudoId pseudo,
    const CSSProperty& property,
    SearchTextIsActiveMatch search_text_is_active_match) {
  if (UseForcedColors(document, originating_style, pseudo_style)) {
    return ForcedColor(originating_style, pseudo_style, pseudo, property,
                       document.GetColorProviderForPainting(
                           UsedColorScheme(originating_style, pseudo_style)),
                       document.IsInWebAppScope());
  }
  if (UseDefaultHighlightColors(pseudo_style, pseudo, property)) {
    return DefaultHighlightColor(document, originating_style, pseudo_style,
                                 pseudo, property, search_text_is_active_match);
  }
  if (pseudo_style) {
    bool is_current_color;
    Color result = pseudo_style->VisitedDependentColor(To<Longhand>(property),
                                                       &is_current_color);
    if (!is_current_color) {
      return result;
    }
  }
  if (!property.IDEquals(CSSPropertyID::kColor)) {
    return MaybeResolveColor(document, originating_style, pseudo_style, pseudo,
                             GetCSSPropertyColor(),
                             search_text_is_active_match);
  }
  return std::nullopt;
}

// Returns highlight styles for the given node, inheriting through the “tree” of
// highlight pseudo styles mirroring the originating element tree. None of the
// returned styles are influenced by originating elements or pseudo-elements.
const ComputedStyle* HighlightStyleUtils::HighlightPseudoStyle(
    Node* node,
    const ComputedStyle& style,
    PseudoId pseudo,
    const AtomicString& pseudo_argument) {
  if (!UsesHighlightPseudoInheritance(pseudo)) {
    return HighlightPseudoStyleWithOriginatingInheritance(node, pseudo,
                                                          pseudo_argument);
  }

  switch (pseudo) {
    case kPseudoIdSelection:
      return style.HighlightData().Selection();
    case kPseudoIdSearchText:
      // For ::search-text:current, call SearchTextCurrent() directly.
      return style.HighlightData().SearchTextNotCurrent();
    case kPseudoIdTargetText:
      return style.HighlightData().TargetText();
    case kPseudoIdSpellingError:
      return style.HighlightData().SpellingError();
    case kPseudoIdGrammarError:
      return style.HighlightData().GrammarError();
    case kPseudoIdHighlight:
      return style.HighlightData().CustomHighlight(pseudo_argument);
    default:
      NOTREACHED();
  }
}

Color HighlightStyleUtils::HighlightBackgroundColor(
    const Document& document,
    const ComputedStyle& style,
    Node* node,
    std::optional<Color> current_layer_color,
    PseudoId pseudo,
    SearchTextIsActiveMatch search_text_is_active_match) {
  if (pseudo == kPseudoIdSelection) {
    if (node && !style.IsSelectable()) {
      return Color::kTransparent;
    }
  }

  const ComputedStyle* pseudo_style = HighlightPseudoStyle(node, style, pseudo);
  Color result = ResolveColor(document, style, pseudo_style, pseudo,
                              GetCSSPropertyBackgroundColor(),
                              current_layer_color, search_text_is_active_match);
  if (pseudo == kPseudoIdSelection) {
    if (NodeIsReplaced(node)) {
      // Avoid that ::selection full obscures selected replaced elements like
      // images.
      return result.BlendWithWhite();
    }
    if (result.IsFullyTransparent()) {
      return Color::kTransparent;
    }
    if (UseDefaultHighlightColors(pseudo_style, pseudo,
                                  GetCSSPropertyColor()) &&
        UseDefaultHighlightColors(pseudo_style, pseudo,
                                  GetCSSPropertyBackgroundColor())) {
      // If the text color ends up being the same as the selection background
      // and we are using default colors, invert the background color. We do not
      // do this when the author has requested colors in a ::selection pseudo.
      if (current_layer_color && *current_layer_color == result) {
        return Color(0xff - result.Red(), 0xff - result.Green(),
                     0xff - result.Blue());
      }
    }
  }
  return result;
}

std::optional<AppliedTextDecoration>
HighlightStyleUtils::SelectionTextDecoration(
    const Document& document,
    const ComputedStyle& style,
    const ComputedStyle& pseudo_style) {
  std::optional<AppliedTextDecoration> decoration =
      style.LastAppliedTextDecoration();
  if (!decoration) {
    return std::nullopt;
  }

  std::optional<AppliedTextDecoration> pseudo_decoration =
      pseudo_style.LastAppliedTextDecoration();
  if (pseudo_decoration && decoration->Lines() == pseudo_decoration->Lines()) {
    decoration = pseudo_decoration;
  }

  return decoration;
}

HighlightStyleUtils::HighlightTextPaintStyle
HighlightStyleUtils::HighlightPaintingStyle(
    const Document& document,
    const ComputedStyle& originating_style,
    const ComputedStyle* pseudo_style,
    Node* node,
    PseudoId pseudo,
    const TextPaintStyle& previous_layer_text_style,
    const PaintInfo& paint_info,
    SearchTextIsActiveMatch search_text_is_active_match) {
  TextPaintStyle highlight_style = previous_layer_text_style;
  HighlightColorPropertySet colors_from_previous_layer;
  const PaintFlags paint_flags = paint_info.GetPaintFlags();
  bool uses_text_as_clip = paint_info.phase == PaintPhase::kTextClip;
  bool ignored_selection = false;

  if (pseudo == kPseudoIdSelection) {
    if ((node && !originating_style.IsSelectable()) ||
        (paint_flags & PaintFlag::kSelectionDragImageOnly)) {
      ignored_selection = true;
    }
    highlight_style.selection_decoration_lines = TextDecorationLine::kNone;
    highlight_style.selection_decoration_color = Color::kBlack;
  }
  Color text_decoration_color = Color::kBlack;
  Color background_color = Color::kTransparent;

  // Each highlight overlay’s shadows are completely independent of any shadows
  // specified on the originating element (or the other highlight overlays).
  highlight_style.shadow = nullptr;

  if (!uses_text_as_clip && !ignored_selection) {
    std::optional<Color> maybe_color;

    maybe_color =
        MaybeResolveColor(document, originating_style, pseudo_style, pseudo,
                          GetCSSPropertyColor(), search_text_is_active_match);
    if (maybe_color) {
      highlight_style.current_color = maybe_color.value();
    } else {
      colors_from_previous_layer.Put(HighlightColorProperty::kCurrentColor);
    }

    maybe_color = MaybeResolveColor(document, originating_style, pseudo_style,
                                    pseudo, GetCSSPropertyWebkitTextFillColor(),
                                    search_text_is_active_match);
    if (maybe_color) {
      highlight_style.fill_color = maybe_color.value();
    } else {
      colors_from_previous_layer.Put(HighlightColorProperty::kFillColor);
    }

    // TODO(crbug.com/1147859) ignore highlight ‘text-emphasis-color’
    // https://github.com/w3c/csswg-drafts/issues/7101
    maybe_color = MaybeResolveColor(document, originating_style, pseudo_style,
                                    pseudo, GetCSSPropertyTextEmphasisColor(),
                                    search_text_is_active_match);
    if (maybe_color) {
      highlight_style.emphasis_mark_color = maybe_color.value();
    } else {
      colors_from_previous_layer.Put(HighlightColorProperty::kEmphasisColor);
    }

    maybe_color = MaybeResolveColor(
        document, originating_style, pseudo_style, pseudo,
        GetCSSPropertyWebkitTextStrokeColor(), search_text_is_active_match);
    if (maybe_color) {
      highlight_style.stroke_color = maybe_color.value();
    } else {
      colors_from_previous_layer.Put(HighlightColorProperty::kStrokeColor);
    }

    maybe_color = MaybeResolveColor(document, originating_style, pseudo_style,
                                    pseudo, GetCSSPropertyTextDecorationColor(),
                                    search_text_is_active_match);
    if (maybe_color) {
      text_decoration_color = maybe_color.value();
    } else {
      colors_from_previous_layer.Put(
          HighlightColorProperty::kTextDecorationColor);
    }

    maybe_color = MaybeResolveColor(document, originating_style, pseudo_style,
                                    pseudo, GetCSSPropertyBackgroundColor(),
                                    search_text_is_active_match);
    if (maybe_color) {
      background_color = maybe_color.value();
    } else {
      colors_from_previous_layer.Put(HighlightColorProperty::kBackgroundColor);
    }
  }

  if (pseudo_style) {
    highlight_style.stroke_width = pseudo_style->TextStrokeWidth();
    // TODO(crbug.com/1164461) For now, don't paint text shadows for ::highlight
    // because some details of how this will be standardized aren't yet
    // settled. Once the final standardization and implementation of highlight
    // text-shadow behavior is complete, remove the following check.
    if (pseudo != kPseudoIdHighlight) {
      highlight_style.shadow =
          uses_text_as_clip ? nullptr : pseudo_style->TextShadow();
    }
    std::optional<AppliedTextDecoration> selection_decoration =
        SelectionTextDecoration(document, originating_style, *pseudo_style);
    if (selection_decoration) {
      highlight_style.selection_decoration_lines =
          selection_decoration->Lines();
      std::optional<Color> selection_decoration_color = MaybeResolveColor(
          document, originating_style, pseudo_style, kPseudoIdSelection,
          GetCSSPropertyTextDecorationColor(), search_text_is_active_match);
      if (selection_decoration_color) {
        highlight_style.selection_decoration_color =
            selection_decoration_color.value();
      } else {
        // Some code paths that do not use the highlight overlay painting system
        // may not resolve the color, so set it now.
        highlight_style.selection_decoration_color =
            previous_layer_text_style.current_color;
        colors_from_previous_layer.Put(
            HighlightColorProperty::kSelectionDecorationColor);
      }
    }
  }

  // Text shadows are disabled when printing. http://crbug.com/258321
  if (document.Printing()) {
    highlight_style.shadow = nullptr;
  }

  return {highlight_style, text_decoration_color, background_color,
          colors_from_previous_layer};
}

void HighlightStyleUtils::ResolveColorsFromPreviousLayer(
    HighlightTextPaintStyle& text_style,
    const HighlightTextPaintStyle& previous_layer_style) {
  if (text_style.properties_using_current_color.empty()) {
    return;
  }

  if (text_style.properties_using_current_color.Has(
          HighlightColorProperty::kCurrentColor)) {
    text_style.style.current_color = previous_layer_style.style.current_color;
  }
  if (text_style.properties_using_current_color.Has(
          HighlightColorProperty::kFillColor)) {
    text_style.style.fill_color = previous_layer_style.style.current_color;
  }
  if (text_style.properties_using_current_color.Has(
          HighlightColorProperty::kStrokeColor)) {
    text_style.style.stroke_color = previous_layer_style.style.current_color;
  }
  if (text_style.properties_using_current_color.Has(
          HighlightColorProperty::kEmphasisColor)) {
    text_style.style.emphasis_mark_color =
        previous_layer_style.style.current_color;
  }
  if (text_style.properties_using_current_color.Has(
          HighlightColorProperty::kSelectionDecorationColor)) {
    text_style.style.selection_decoration_color =
        previous_layer_style.style.current_color;
  }
  if (text_style.properties_using_current_color.Has(
          HighlightColorProperty::kTextDecorationColor)) {
    text_style.text_decoration_color = previous_layer_style.style.current_color;
  }
  if (text_style.properties_using_current_color.Has(
          HighlightColorProperty::kBackgroundColor)) {
    text_style.background_color = previous_layer_style.style.current_color;
  }
}

bool HighlightStyleUtils::ShouldInvalidateVisualOverflow(
    const LayoutObject& layout_object,
    DocumentMarker::MarkerType type) {
  // Custom highlights and selection are handled separately. Here we just need
  // to handle spelling, grammar and target-text.
  if (type == DocumentMarker::kSpelling || type == DocumentMarker::kGrammar) {
    return true;
  }

  if (type != DocumentMarker::kTextFragment) {
    return false;
  }
  const ComputedStyle* pseudo_style =
      layout_object.StyleRef().HighlightData().TargetText();
  if (!pseudo_style) {
    return false;
  }
  return (pseudo_style->HasAppliedTextDecorations() ||
          pseudo_style->HasVisualOverflowingEffect());
}

bool HighlightStyleUtils::CustomHighlightHasVisualOverflow(
    const Text& text_node,
    const AtomicString& pseudo_argument) {
  LayoutObject* layout_object = text_node.GetLayoutObject();
  if (!layout_object) {
    return false;
  }
  const ComputedStyle* pseudo_style =
      layout_object->StyleRef().HighlightData().CustomHighlight(
          pseudo_argument);
  if (!pseudo_style) {
    return false;
  }
  return (pseudo_style->HasAppliedTextDecorations() ||
          pseudo_style->HasVisualOverflowingEffect());
}

}  // namespace blink
```