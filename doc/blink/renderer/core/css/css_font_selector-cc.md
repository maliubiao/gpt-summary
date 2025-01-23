Response:
Let's break down the thought process for analyzing the provided C++ code for `CSSFontSelector`.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific file within the Chromium/Blink rendering engine. This involves identifying its purpose, its relationship to web technologies (HTML, CSS, JavaScript), potential errors, and how a user's actions might lead to its execution.

2. **Initial Code Scan (Keywords and Structure):**  Start by quickly scanning the code for recognizable keywords and structural elements:
    * **Includes:** Pay attention to the included header files (e.g., `css_font_selector.h`, `css_value_list.h`, `document.h`, `font_cache.h`). These hints at the dependencies and responsibilities of the class. Seeing `css`, `font`, `selector`, `document` immediately suggests it's related to CSS font handling within a web page.
    * **Namespace:**  The `blink` namespace confirms it's part of the Blink rendering engine.
    * **Class Declaration:**  The `CSSFontSelector` class is the core focus.
    * **Member Functions:** Look for public and private member functions. Their names often reveal their purpose (e.g., `GetFontData`, `RegisterForInvalidationCallbacks`, `FontFaceInvalidated`).
    * **Data Members:**  Identify important data members (e.g., `tree_scope_`, `clients_`, `font_face_cache_`).
    * **Comments:**  Read any existing comments, even the license information, as they might provide context. The initial copyright mentions font rendering, confirming the area of focus.

3. **Deduce Core Functionality (Based on Initial Scan):**
    * The name `CSSFontSelector` strongly suggests it's responsible for *selecting* the appropriate font based on CSS rules.
    * The inclusion of `FontCache` and `FontFaceCache` points to managing and accessing font data.
    * The presence of `FontDescription` indicates that the selection process involves considering various font properties (family, size, weight, style, etc.).
    * The `clients_` member and the invalidation callbacks (`DispatchInvalidationCallbacks`) suggest a mechanism for notifying other parts of the engine when font-related information changes.

4. **Deep Dive into Key Functions:**  Focus on the most important-looking functions:
    * **`GetFontData`:** This seems like the central function. It takes a `FontDescription` and `FontFamily` as input and returns `FontData`. This confirms the font selection role. The logic within `GetFontData` is crucial to understand how the selection process works, including handling custom and interpolable palettes, font variant alternates, and generic font family settings.
    * **Constructor/Destructor:**  See how the object is initialized and cleaned up. The constructor's interaction with `FontCache` is important.
    * **Invalidation Functions:** Understand how changes in fonts (e.g., due to `@font-face` rules) are propagated.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **CSS:**  The class name and the handling of `FontDescription` and `FontFamily` directly link it to CSS font properties. Consider how CSS rules like `font-family`, `font-size`, `font-weight`, etc., are used to create a `FontDescription`. The handling of `@font-face` and font palettes further strengthens this connection.
    * **HTML:**  The `tree_scope_` member and the connection to `Document` indicate that the font selection is context-aware within the HTML document. Different parts of the document might have different effective font styles.
    * **JavaScript:**  While the C++ code itself doesn't directly interact with JavaScript, JavaScript APIs like the Font API (`document.fonts`) can trigger changes that might lead to the execution of this code (e.g., loading a new font, triggering a re-layout).

6. **Identify Potential Issues and User Errors:**
    * **Font Not Found:** If `GetFontData` returns `nullptr`, it means a suitable font couldn't be found. This could be due to typos in font family names, missing font files, or incorrect `@font-face` declarations.
    * **Performance:**  Repeated font lookups or complex `@font-face` rules could impact performance.
    * **Incorrect Palette Definition:** Errors in defining custom font palettes in CSS might lead to unexpected results.

7. **Construct Debugging Scenario:** Think about the chain of events that leads to the execution of `CSSFontSelector::GetFontData`. A typical scenario involves the browser parsing HTML and CSS, encountering a text node, and then needing to determine the font to use for rendering that text.

8. **Structure the Output:** Organize the findings into clear sections addressing the different aspects of the prompt: functionality, relationships to web technologies, logical reasoning (with examples), common errors, and debugging.

9. **Refine and Elaborate:** Review the initial analysis and add more details and specific examples. For instance, when explaining the relationship with CSS, mention specific CSS properties. When discussing logical reasoning, create simple hypothetical scenarios.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just picks fonts."  **Correction:** It's more than just picking; it's managing, caching, and handling invalidation, considering complex features like font palettes and alternates.
* **Initially overlooked:** The significance of `tree_scope_`. **Correction:** Recognize its importance for context-aware font selection within different parts of a document (shadow DOM, iframes).
* **Vague explanation of invalidation:**  **Correction:** Clarify that invalidation happens due to changes like loading new fonts or CSS updates.

By following this structured thought process, combining code analysis with knowledge of web technologies, and iteratively refining the understanding, we can arrive at a comprehensive and accurate description of the `CSSFontSelector`'s functionality.
好的，让我们来分析一下 `blink/renderer/core/css/css_font_selector.cc` 这个 Chromium Blink 引擎源代码文件。

**功能概述:**

`CSSFontSelector` 的核心功能是 **根据 CSS 样式规则来选择合适的字体进行渲染**。它负责管理和查询可用的字体，并根据指定的字体描述（`FontDescription`）和字体族（`FontFamily`）找到最佳匹配的字体数据（`FontData`）。

更具体地说，它的功能包括：

1. **字体查找:**  接收一个包含字体属性（如字体族名、字重、字形等）的 `FontDescription` 和一个 `FontFamily` 对象，然后从字体缓存（`FontCache`）和自定义字体（通过 `@font-face` 规则注册的字体）中查找匹配的字体数据。
2. **自定义字体管理:** 管理通过 CSS `@font-face` 规则定义的字体。它维护了一个 `FontFaceCache` 来存储这些自定义字体的信息。
3. **字体失效通知:** 当字体资源发生变化时（例如，加载了新的字体文件，或者 `@font-face` 规则被更新），它会通知相关的客户端（`FontSelectorClient`），以便它们可以更新渲染。
4. **通用字体族处理:** 处理 CSS 中的通用字体族名（如 `serif`, `sans-serif`, `monospace` 等），根据用户的系统设置或浏览器默认设置将其映射到具体的字体族名。
5. **字体调色板支持:** 处理 CSS 字体调色板 (Font Palette) 功能，包括查找和应用指定的调色板，以及处理动画中的调色板插值。
6. **字体变体候选项 (Font Variant Alternates) 处理:**  处理 CSS 字体变体候选项相关的特性，例如 `stylistic`, `styleset`, `character-variant` 等，这些特性允许通过 `@font-feature-values` 规则为字体定义不同的变体。
7. **字体大小调整 (Font Size Adjust) 支持:**  处理 CSS 属性 `size-adjust`，允许根据字体的实际尺寸进行调整。

**与 JavaScript, HTML, CSS 的关系:**

`CSSFontSelector` 是连接 CSS 样式和实际字体渲染的关键桥梁。

* **CSS:**  `CSSFontSelector` 直接解析和应用 CSS 中与字体相关的属性，例如 `font-family`, `font-weight`, `font-style`, `font-size`, `@font-face`, `font-palette`, `font-variant-alternates`, `size-adjust` 等。
    * **举例:** 当 CSS 规则中指定了 `font-family: "Arial", sans-serif;` 时，`CSSFontSelector` 首先尝试查找名为 "Arial" 的字体。如果找不到，它会根据通用字体族设置查找一个合适的无衬线字体。
    * **举例 (@font-face):** 当遇到 `@font-face { font-family: "MyCustomFont"; src: url(my-font.woff2); }` 时，`CSSFontSelector` 会将 "MyCustomFont" 注册到 `FontFaceCache` 中，并在后续遇到 `font-family: "MyCustomFont"` 时使用这个自定义字体。
    * **举例 (Font Palette):** 当 CSS 中使用了 `font-palette: dark;` 并且定义了名为 `dark` 的 `@font-palette-values` 时，`CSSFontSelector` 会查找并应用相应的颜色调色板。

* **HTML:**  HTML 定义了文档的结构和文本内容。浏览器解析 HTML，并结合 CSS 样式来确定每个元素的字体样式。`CSSFontSelector` 为 HTML 元素提供最终的字体数据用于渲染。
    * **举例:**  当浏览器渲染一个 `<p style="font-family: 'Times New Roman'">Hello</p>` 标签时，会调用 `CSSFontSelector` 来获取 "Times New Roman" 字体的相关信息。

* **JavaScript:**  JavaScript 可以动态地修改元素的 CSS 样式，从而间接地影响 `CSSFontSelector` 的工作。例如，JavaScript 可以修改元素的 `style.fontFamily` 属性。此外，Font API (如 `document.fonts.load()`) 允许 JavaScript 与字体系统进行交互，这也会触发 `CSSFontSelector` 的相关操作。
    * **举例:** JavaScript 代码 `document.getElementById('myText').style.fontFamily = 'Verdana';` 会导致浏览器重新评估该元素的字体，并调用 `CSSFontSelector` 来查找 "Verdana" 字体。
    * **举例 (Font API):** 使用 `document.fonts.load("16px MyCustomFont")` 加载一个尚未加载的自定义字体会触发 `CSSFontSelector` 的字体加载和管理逻辑。

**逻辑推理与假设输入输出:**

假设输入以下 CSS 规则应用于一个 HTML 元素：

```css
.my-text {
  font-family: "MySpecialFont", cursive;
  font-weight: bold;
  font-style: italic;
}
```

并且假设系统中没有名为 "MySpecialFont" 的字体，但有一个可用的草书字体（例如 "Brush Script MT"）。

**假设输入:**

* `FontDescription`: 包含 `font-weight: bold`, `font-style: italic`
* `FontFamily`: 包含 "MySpecialFont" 和 "cursive"

**逻辑推理:**

1. `CSSFontSelector::GetFontData` 首先尝试查找名为 "MySpecialFont" 的字体。
2. 由于系统中不存在 "MySpecialFont"，查找失败。
3. 接下来，`CSSFontSelector` 会处理通用字体族 "cursive"。
4. 它会根据系统或浏览器的通用字体族设置，将 "cursive" 映射到一个具体的字体族名，例如 "Brush Script MT"。
5. 它会尝试查找 "Brush Script MT" 并且满足 `bold` 和 `italic` 要求的字体变体。
6. 如果找到了匹配的字体数据，则返回该字体数据。

**假设输出:**

返回 "Brush Script MT" 的粗体、斜体变体的 `FontData` 对象（如果存在）。如果找不到完全匹配的变体，可能会返回最接近的匹配项，或者默认的草书字体。

**用户或编程常见的使用错误:**

1. **字体名称拼写错误:** 用户在 CSS 中输入了错误的字体名称，例如 `font-family: Ariial;` 而不是 `font-family: Arial;`。这会导致 `CSSFontSelector` 找不到指定的字体，最终可能会使用通用字体族或默认字体。
2. **自定义字体路径错误:**  在 `@font-face` 规则中指定了错误的字体文件路径，例如 `src: url(fonts/MyFont.woff2);` 但实际文件不存在或路径不正确。这会导致自定义字体加载失败，`CSSFontSelector` 无法使用该字体。
3. **字体格式不支持:**  使用了浏览器不支持的字体格式，例如过时的 `.eot` 格式，而没有提供其他格式的回退。`CSSFontSelector` 将无法加载和使用该字体。
4. **`font-variant-alternates` 使用错误:**  错误地使用了 `@font-feature-values` 或 `font-variant-alternates` 属性，导致无法正确激活字体的 OpenType 特性。例如，使用了不存在的别名或值。
5. **本地字体未安装:**  CSS 中引用了用户本地系统中未安装的字体。`CSSFontSelector` 无法找到该字体。

**用户操作如何一步步到达这里 (调试线索):**

假设用户访问一个包含以下 HTML 和 CSS 的网页：

**HTML:**

```html
<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: "CustomFont", sans-serif; }
  @font-face {
    font-family: "CustomFont";
    src: url("fonts/custom-font.woff2"); /* 假设路径错误 */
  }
</style>
</head>
<body>
  <p>This is some text.</p>
</body>
</html>
```

**用户操作步骤:**

1. **用户在浏览器中输入网址并访问该网页。**
2. **浏览器开始解析 HTML 文档。**
3. **浏览器解析到 `<style>` 标签中的 CSS 规则。**
4. **CSS 解析器遇到 `body { font-family: "CustomFont", sans-serif; }` 规则。**
5. **浏览器需要渲染 `<body>` 标签内的文本内容。**
6. **渲染引擎需要确定用于渲染文本的字体。**
7. **渲染引擎调用 `CSSFontSelector` 的 `GetFontData` 方法，传入 "CustomFont" 作为首选字体。**
8. **`CSSFontSelector` 在 `FontFaceCache` 中查找 "CustomFont"。**
9. **`CSSFontSelector` 尝试加载 `@font-face` 规则中指定的字体文件 "fonts/custom-font.woff2"。**
10. **由于路径错误，字体文件加载失败。**
11. **`CSSFontSelector` 无法找到 "CustomFont"。**
12. **`CSSFontSelector` 接着处理备选字体 "sans-serif"。**
13. **`CSSFontSelector` 根据系统或浏览器设置，将 "sans-serif" 映射到一个具体的无衬线字体，例如 "Arial" 或 "Helvetica"。**
14. **`CSSFontSelector` 从字体缓存中获取 "Arial" 或 "Helvetica" 的 `FontData`。**
15. **渲染引擎使用获取到的无衬线字体来渲染 "This is some text."。**

**调试线索:**

在调试过程中，如果用户发现网页上的文本使用了错误的字体（例如，期望的自定义字体没有显示），可以按照以下步骤排查：

1. **检查浏览器的开发者工具 (特别是 "Elements" 或 "审查元素" 面板)。** 查看元素的 "Computed" 样式，确认最终应用的 `font-family` 是什么。如果不是预期的自定义字体，而是备选的通用字体，则说明自定义字体加载失败。
2. **检查开发者工具的 "Network" 面板。** 查看字体文件 (例如 "custom-font.woff2") 的加载状态。如果状态码是 404 (Not Found) 或其他错误，则表示字体文件加载失败。
3. **检查开发者工具的 "Console" 面板。**  浏览器可能会输出与字体加载失败相关的错误或警告信息。
4. **检查 `@font-face` 规则的语法和字体文件路径是否正确。**
5. **确认字体文件是否存在于指定的路径，并且服务器配置允许访问该文件。**
6. **如果使用了 `font-variant-alternates`，检查 `@font-feature-values` 的定义和使用是否正确。**

通过以上分析，我们可以了解到 `blink/renderer/core/css/css_font_selector.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它负责将 CSS 中对字体的抽象描述转化为实际可用的字体数据，直接影响着网页文本的最终渲染效果。理解其功能有助于我们更好地理解浏览器如何处理字体以及排查与字体相关的渲染问题。

### 提示词
```
这是目录为blink/renderer/core/css/css_font_selector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2007, 2008, 2011 Apple Inc. All rights reserved.
 *           (C) 2007, 2008 Nikolas Zimmermann <zimmermann@kde.org>
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/css_font_selector.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/animation/interpolable_color.h"
#include "third_party/blink/renderer/core/css/css_segmented_font_face.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/css/font_size_functions.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_selector_client.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

scoped_refptr<FontPalette> RetrieveFontPaletteFromStyleEngine(
    scoped_refptr<const FontPalette> request_palette,
    StyleEngine& style_engine,
    const AtomicString& family_name) {
  AtomicString requested_palette_values =
      request_palette->GetPaletteValuesName();
  StyleRuleFontPaletteValues* font_palette_values =
      style_engine.FontPaletteValuesForNameAndFamily(requested_palette_values,
                                                     family_name);
  if (font_palette_values) {
    scoped_refptr<FontPalette> new_request_palette =
        FontPalette::Create(requested_palette_values);
    new_request_palette->SetMatchFamilyName(family_name);
    new_request_palette->SetBasePalette(
        font_palette_values->GetBasePaletteIndex());
    Vector<FontPalette::FontPaletteOverride> override_colors =
        font_palette_values->GetOverrideColorsAsVector();
    if (override_colors.size()) {
      new_request_palette->SetColorOverrides(std::move(override_colors));
    }
    return new_request_palette;
  }
  return nullptr;
}

scoped_refptr<const FontPalette> ResolveInterpolableFontPalette(
    scoped_refptr<const FontPalette> font_palette,
    StyleEngine& style_engine,
    const AtomicString& family_name) {
  if (!font_palette->IsInterpolablePalette()) {
    if (font_palette->IsCustomPalette()) {
      scoped_refptr<FontPalette> retrieved_palette =
          RetrieveFontPaletteFromStyleEngine(font_palette, style_engine,
                                             family_name);
      return retrieved_palette ? retrieved_palette : FontPalette::Create();
    } else {
      return font_palette;
    }
  }
  scoped_refptr<const FontPalette> start_palette =
      ResolveInterpolableFontPalette(font_palette->GetStart(), style_engine,
                                     family_name);
  scoped_refptr<const FontPalette> end_palette = ResolveInterpolableFontPalette(
      font_palette->GetEnd(), style_engine, family_name);

  // If two endpoints of the interpolation are equal, we can simplify the tree
  if (*start_palette.get() == *end_palette.get()) {
    return start_palette;
  }

  scoped_refptr<FontPalette> new_palette;
  new_palette = FontPalette::Mix(
      start_palette, end_palette, font_palette->GetStartPercentage(),
      font_palette->GetEndPercentage(), font_palette->GetNormalizedPercentage(),
      font_palette->GetAlphaMultiplier(),
      font_palette->GetColorInterpolationSpace(),
      font_palette->GetHueInterpolationMethod());
  return new_palette;
}

}  // namespace

CSSFontSelector::CSSFontSelector(const TreeScope& tree_scope)
    : tree_scope_(&tree_scope) {
  DCHECK(tree_scope.GetDocument().GetExecutionContext()->IsContextThread());
  DCHECK(tree_scope.GetDocument().GetFrame());
  generic_font_family_settings_ = tree_scope.GetDocument()
                                      .GetFrame()
                                      ->GetSettings()
                                      ->GetGenericFontFamilySettings();
  FontCache::Get().AddClient(this);
  if (tree_scope.RootNode().IsDocumentNode()) {
    font_face_cache_ = MakeGarbageCollected<FontFaceCache>();
    FontFaceSetDocument::From(tree_scope.GetDocument())
        ->AddFontFacesToFontFaceCache(font_face_cache_);
  }
}

CSSFontSelector::~CSSFontSelector() = default;

UseCounter* CSSFontSelector::GetUseCounter() const {
  auto* const context = GetExecutionContext();
  return context && context->IsContextThread() ? context : nullptr;
}

void CSSFontSelector::RegisterForInvalidationCallbacks(
    FontSelectorClient* client) {
  CHECK(client);
  clients_.insert(client);
}

void CSSFontSelector::UnregisterForInvalidationCallbacks(
    FontSelectorClient* client) {
  clients_.erase(client);
}

void CSSFontSelector::DispatchInvalidationCallbacks(
    FontInvalidationReason reason) {
  font_face_cache_->IncrementVersion();

  HeapVector<Member<FontSelectorClient>> clients(clients_);
  for (auto& client : clients) {
    if (client) {
      client->FontsNeedUpdate(this, reason);
    }
  }
}

void CSSFontSelector::FontFaceInvalidated(FontInvalidationReason reason) {
  DispatchInvalidationCallbacks(reason);
}

void CSSFontSelector::FontCacheInvalidated() {
  DispatchInvalidationCallbacks(FontInvalidationReason::kGeneralInvalidation);
}

const FontData* CSSFontSelector::GetFontData(
    const FontDescription& font_description,
    const FontFamily& font_family) {
  const auto& family_name = font_family.FamilyName();
  Document& document = GetTreeScope()->GetDocument();

  FontDescription request_description(font_description);
  const FontPalette* request_palette = request_description.GetFontPalette();

  if (request_palette && request_palette->IsCustomPalette()) {
    scoped_refptr<FontPalette> new_request_palette =
        RetrieveFontPaletteFromStyleEngine(
            request_palette, document.GetStyleEngine(), family_name);
    if (new_request_palette) {
      request_description.SetFontPalette(std::move(new_request_palette));
    }
  }

  if (request_palette && request_palette->IsInterpolablePalette()) {
    scoped_refptr<const FontPalette> computed_interpolable_palette =
        ResolveInterpolableFontPalette(request_palette,
                                       document.GetStyleEngine(), family_name);
    request_description.SetFontPalette(
        std::move(computed_interpolable_palette));
  }

  if (request_description.GetFontVariantAlternates()) {
    // TODO(https://crbug.com/1382722): For scoping to work correctly, we'd need
    // to traverse the TreeScopes here and fuse / override values of
    // @font-feature-values from these.
    const FontFeatureValuesStorage* feature_values_storage =
        document.GetScopedStyleResolver()
            ? document.GetScopedStyleResolver()->FontFeatureValuesForFamily(
                  family_name)
            : nullptr;
    scoped_refptr<FontVariantAlternates> new_alternates = nullptr;
    if (feature_values_storage) {
      new_alternates = request_description.GetFontVariantAlternates()->Resolve(
          [feature_values_storage](const AtomicString& alias) {
            return feature_values_storage->ResolveStylistic(alias);
          },
          [feature_values_storage](const AtomicString& alias) {
            return feature_values_storage->ResolveStyleset(alias);
          },
          [feature_values_storage](const AtomicString& alias) {
            return feature_values_storage->ResolveCharacterVariant(alias);
          },
          [feature_values_storage](const AtomicString& alias) {
            return feature_values_storage->ResolveSwash(alias);
          },
          [feature_values_storage](const AtomicString& alias) {
            return feature_values_storage->ResolveOrnaments(alias);
          },
          [feature_values_storage](const AtomicString& alias) {
            return feature_values_storage->ResolveAnnotation(alias);
          });
    } else {
      // If no StyleRuleFontFeature alias table values for this font was found,
      // it still needs a resolve call to convert historical-forms state (which
      // is not looked-up against StyleRuleFontFeatureValues) to an internal
      // feature.
      auto no_lookup = [](const AtomicString&) -> Vector<uint32_t> {
        return {};
      };
      new_alternates = request_description.GetFontVariantAlternates()->Resolve(
          no_lookup, no_lookup, no_lookup, no_lookup, no_lookup, no_lookup);
    }

    if (new_alternates) {
      request_description.SetFontVariantAlternates(std::move(new_alternates));
    }
  }

  if (!font_family.FamilyIsGeneric()) {
    if (CSSSegmentedFontFace* face =
            font_face_cache_->Get(request_description, family_name)) {
      return face->GetFontData(request_description);
    }
  }

  // Try to return the correct font based off our settings, in case we were
  // handed the generic font family name.
  AtomicString settings_family_name =
      FamilyNameFromSettings(request_description, font_family);
  if (settings_family_name.empty()) {
    return nullptr;
  }

  ReportFontFamilyLookupByGenericFamily(
      family_name, request_description.GetScript(),
      request_description.GenericFamily(), settings_family_name);

  const SimpleFontData* font_data =
      FontCache::Get().GetFontData(request_description, settings_family_name);
  if (font_data && request_description.HasSizeAdjust()) {
    DCHECK(RuntimeEnabledFeatures::CSSFontSizeAdjustEnabled());
    if (auto adjusted_size =
            FontSizeFunctions::MetricsMultiplierAdjustedFontSize(
                font_data, request_description)) {
      FontDescription size_adjusted_description(request_description);
      size_adjusted_description.SetAdjustedSize(adjusted_size.value());
      font_data = FontCache::Get().GetFontData(size_adjusted_description,
                                               settings_family_name);
    }
  }

  ReportFontLookupByUniqueOrFamilyName(settings_family_name,
                                       request_description, font_data);

  return font_data;
}

void CSSFontSelector::UpdateGenericFontFamilySettings(Document& document) {
  if (!document.GetSettings()) {
    return;
  }
  generic_font_family_settings_ =
      document.GetSettings()->GetGenericFontFamilySettings();
  FontCacheInvalidated();
}

FontMatchingMetrics* CSSFontSelector::GetFontMatchingMetrics() const {
  return GetDocument().GetFontMatchingMetrics();
}

bool CSSFontSelector::IsAlive() const {
  return tree_scope_ != nullptr;
}

void CSSFontSelector::Trace(Visitor* visitor) const {
  visitor->Trace(tree_scope_);
  visitor->Trace(clients_);
  CSSFontSelectorBase::Trace(visitor);
}

}  // namespace blink
```