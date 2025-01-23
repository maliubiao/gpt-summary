Response:
Let's break down the thought process to analyze the `css_segmented_font_face.cc` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the file, including its functionality, relationship with web technologies (JavaScript, HTML, CSS), logical inferences, potential errors, and debugging steps.

**2. Initial Skim and Keyword Spotting:**

First, quickly read through the code, looking for key terms and structures. This gives a high-level understanding. Keywords like `CSSSegmentedFontFace`, `FontFace`, `FontDescription`, `FontData`, `unicode-range`, `AddFontFace`, `RemoveFontFace`, `GetFontData`, and comments related to CSS and font loading immediately stand out. The copyright notice indicates its origin and licensing. The `#include` directives show dependencies on other Blink components.

**3. Identifying Core Functionality:**

Based on the keywords and structure, it's clear this file is about managing a collection of `FontFace` objects. The "segmented" aspect suggests dealing with fonts that might be defined in parts (e.g., different glyphs in different font files).

*   **Collection Management:** The `FontFaceList` and the `font_faces_` member variable strongly suggest managing a list of font faces. The `AddFontFace` and `RemoveFontFace` functions confirm this.
*   **Font Data Retrieval:**  `GetFontData` is a crucial function, suggesting it's responsible for finding the appropriate font data based on a `FontDescription`. The caching mechanism (`font_data_table_`) is also important here.
*   **Font Loading Hints:**  `WillUseFontData` and `WillUseRange` indicate mechanisms for hinting to the system that certain font data or ranges will be needed, potentially triggering lazy loading.
*   **Font Matching:** `CheckFont` and `Match` relate to determining if a given character or text can be rendered using the managed font faces.
*   **Prioritization:** The `FontFaceList::Insert` function and the `CascadePriorityHigherThan` helper function reveal logic for ordering font faces based on CSS cascade rules.

**4. Connecting to Web Technologies:**

*   **CSS:** The file name itself (`css_segmented_font_face.cc`) directly links it to CSS. The presence of `CSSFontFace`, `unicode-range`, and discussions of cascade priority solidify this connection. The `@font-face` rule in CSS is the primary mechanism for defining custom fonts, which directly relates to this code.
*   **HTML:**  While not directly interacting with HTML parsing, this code is essential for *rendering* text within HTML documents using custom fonts defined via CSS. The browser needs to load and manage these fonts to display the HTML content correctly.
*   **JavaScript:** JavaScript interacts with fonts indirectly. While JavaScript doesn't directly manipulate `CSSSegmentedFontFace`, it can trigger layout and rendering that depends on the font system. For example, dynamically changing CSS styles that involve fonts will lead to this code being executed. The `document.fonts` API in JavaScript provides a way to interact with the browser's font loading and management.

**5. Logical Inferences and Assumptions:**

*   **Assumption:** The "segmented" aspect implies that a single logical font family might be composed of multiple physical font files, potentially to support different character ranges or variations.
*   **Inference:** The caching in `font_data_table_` is an optimization to avoid repeatedly creating `FontData` objects, especially during animations or when the same font styles are used multiple times.
*   **Inference:** The prioritization logic in `FontFaceList::Insert` ensures that font faces defined later in the CSS (or with higher specificity) take precedence.

**6. Identifying Potential Errors:**

Think about common mistakes developers make when working with custom fonts:

*   **Incorrect `unicode-range`:** Specifying the wrong character ranges in the `@font-face` rule can lead to characters not being rendered correctly.
*   **Missing Font Files:** If the font files specified in the `src` property of `@font-face` are not accessible, the font will fail to load.
*   **Conflicting Font Definitions:** If multiple `@font-face` rules with the same `font-family` but different properties (e.g., `font-weight`) are defined, the cascade rules determine which one is used, potentially leading to unexpected results if not understood.
*   **Performance Issues:**  Using too many custom fonts or large font files can negatively impact page load time and rendering performance.

**7. Debugging Clues and User Actions:**

Consider how a developer might end up investigating this code:

*   **Visual Rendering Issues:**  The most common trigger would be seeing incorrect characters or fallback fonts being displayed on a webpage.
*   **Performance Profiling:**  A developer might use browser developer tools to profile rendering performance and notice delays related to font loading or processing.
*   **Browser Console Errors:**  Failed font loads often result in errors in the browser's developer console.
*   **Inspecting Computed Styles:** Using the "Inspect" tool in the browser, a developer can examine the computed styles of an element and see which font is being used (or failing to be used).
*   **Network Tab:**  The network tab in developer tools can be used to check if font files are being requested and loaded successfully.

**8. Structuring the Output:**

Finally, organize the gathered information into the requested categories: functionality, relationship to web technologies, logical inferences, potential errors, and debugging steps. Use clear and concise language, providing specific examples where appropriate. The "assumed input/output" for logical inference helps illustrate the behavior of specific functions.

By following this thought process, systematically analyzing the code, and considering the context of web development, we can arrive at a comprehensive and accurate explanation of the `css_segmented_font_face.cc` file.
好的，让我们来分析一下 `blink/renderer/core/css/css_segmented_font_face.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能：**

`CSSSegmentedFontFace` 类的主要功能是管理一组相关的 `FontFace` 对象，这些 `FontFace` 对象可能对应于同一个字体家族的不同片段（segment），例如针对不同的 Unicode 字符范围。它充当一个容器和协调者的角色，负责：

1. **存储和管理多个 `FontFace` 对象:**  使用 `FontFaceList` 来存储相关的 `FontFace` 实例。
2. **确定合适的字体数据 (`FontData`)**:  当需要特定字符的字体数据时，它会遍历其管理的 `FontFace` 对象，找到包含该字符并且样式匹配的字体数据。
3. **处理字体加载**: 它会追踪其管理的 `FontFace` 的加载状态，并根据需要触发字体加载。
4. **缓存字体数据**:  使用 `font_data_table_` 缓存已经创建的 `FontData` 对象，以提高性能。尤其是在处理可变字体动画时，可以缓存不同实例的字体数据。
5. **根据 CSS 级联规则排序字体**:  `FontFaceList` 中的字体会根据其在 CSS 中的定义顺序和层叠优先级进行排序，确保使用正确的字体。
6. **支持 `unicode-range`**:  通过管理多个具有不同 `unicode-range` 的 `FontFace`，它能够实现根据字符选择合适的字体片段。
7. **提供查找匹配字体的方法**:  例如 `CheckFont` 判断某个字符是否在该 `CSSSegmentedFontFace` 管理的字体中，`Match` 找出与给定文本相关的 `FontFace`。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件与 CSS 的关系最为直接，因为它处理的是 CSS 中 `@font-face` 规则定义的字体。它也间接地与 HTML 和 JavaScript 相关，因为它们共同构成了网页内容和交互。

* **CSS:**
    * **功能关联:** `CSSSegmentedFontFace` 的存在是为了实现 CSS 的字体特性，特别是 `@font-face` 规则中的 `unicode-range` 属性。
    * **举例说明:** 假设 CSS 中定义了以下 `@font-face` 规则：

      ```css
      @font-face {
        font-family: 'MyFont';
        src: url('myfont-latin.woff2');
        unicode-range: U+0000-00FF; /* Latin characters */
      }

      @font-face {
        font-family: 'MyFont';
        src: url('myfont-cyrillic.woff2');
        unicode-range: U+0400-04FF; /* Cyrillic characters */
      }
      ```

      当浏览器解析这段 CSS 时，会创建两个 `CSSFontFace` 对象，它们都属于同一个 `CSSSegmentedFontFace` 实例（因为 `font-family` 相同）。当渲染包含拉丁字符的文本时，`CSSSegmentedFontFace::GetFontData` 会选择第一个 `FontFace` 的字体数据；当渲染包含西里尔字符的文本时，会选择第二个 `FontFace` 的字体数据。

* **HTML:**
    * **功能关联:** HTML 定义了网页的内容，而 `CSSSegmentedFontFace` 负责确保这些内容能够使用正确的字体进行渲染。
    * **举例说明:**  如果 HTML 中有 `<p style="font-family: 'MyFont'">Привет мир</p>`，浏览器需要使用 `CSSSegmentedFontFace` 来找到能够渲染西里尔字符的 "MyFont" 字体。

* **JavaScript:**
    * **功能关联:** JavaScript 可以动态修改 HTML 结构和 CSS 样式，这些修改可能会触发新的字体选择和加载过程，从而间接地使用到 `CSSSegmentedFontFace`。
    * **举例说明:**  JavaScript 可以动态添加一个包含特定字符的元素，或者修改元素的 `font-family` 样式。例如：

      ```javascript
      const newElement = document.createElement('div');
      newElement.textContent = '你好';
      newElement.style.fontFamily = 'MyFont';
      document.body.appendChild(newElement);
      ```

      当这段 JavaScript 代码执行时，浏览器会再次通过 `CSSSegmentedFontFace` 查找能够渲染中文的 "MyFont" 字体（假设有相应的 `@font-face` 规则）。JavaScript 的 `document.fonts` API 也可以用来监测字体加载状态，这与 `CSSSegmentedFontFace` 管理的字体加载过程相关。

**逻辑推理 (假设输入与输出):**

假设我们有以下 `@font-face` 规则：

```css
@font-face {
  font-family: 'TestFont';
  src: url('test-regular.woff2');
}

@font-face {
  font-family: 'TestFont';
  src: url('test-bold.woff2');
  font-weight: bold;
}
```

**假设输入:**

1. 创建了一个 `CSSSegmentedFontFace` 实例来管理 'TestFont'。
2. 添加了两个 `FontFace` 对象到这个 `CSSSegmentedFontFace`，分别对应上述两个 `@font-face` 规则。
3. 调用 `GetFontData` 方法，并传入一个 `FontDescription` 对象，该对象指定了 `font-family: 'TestFont'` 和 `font-weight: bold`。

**输出:**

`GetFontData` 方法会返回与第二个 `FontFace` 对象关联的 `FontData`，因为它的 `font-weight` 属性与请求匹配。

**假设输入:**

1. 同上，创建并添加了两个 `FontFace` 对象。
2. 调用 `CheckFont` 方法，并传入字符 'A' (U+0041)。

**输出:**

`CheckFont` 方法会返回 `false`，如果两个 `FontFace` 都尚未加载完成。如果至少有一个 `FontFace` 已经加载并且包含了字符 'A'，则返回 `true`。更精确地说，它会检查是否有 *未加载* 的 `FontFace` 的 `unicode-range` 包含 'A'。如果找到了这样的 `FontFace`，就返回 `false`（因为我们可能需要等待它加载）。

**用户或编程常见的使用错误：**

1. **`unicode-range` 设置错误:** 用户可能错误地设置了 `unicode-range`，导致某些字符无法使用预期的字体。例如，定义了拉丁字符的范围，但忘记包含基本的标点符号。
   * **例子:** `@font-face { font-family: 'MyFont'; src: url('...'); unicode-range: U+0041-005A; }` (仅包含大写字母，不包含小写字母)。
2. **字体文件路径错误:**  `src` 属性中指定的字体文件路径可能不正确，导致字体加载失败。
   * **例子:** `@font-face { font-family: 'MyFont'; src: url('fonts/MyFont.woff2'); }` 但实际上字体文件位于 `assets/fonts/` 目录下。
3. **CSS 优先级问题:**  当多个 `@font-face` 规则定义了相同的 `font-family` 时，CSS 的层叠规则可能会导致意外的字体被选中。
   * **例子:**  在全局样式表中定义了一个通用的 'MyFont'，然后在某个组件的样式中又定义了一个不同版本的 'MyFont'，但由于选择器优先级问题，全局的字体仍然被应用。
4. **字体文件格式不支持:**  使用了浏览器不支持的字体文件格式。
   * **例子:**  只提供了 `.ttf` 文件，但旧版本的浏览器可能只支持 `.eot`。
5. **混合内容问题 (HTTPS):**  在 HTTPS 页面中加载 HTTP 的字体资源会导致混合内容错误，字体加载会被阻止。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页:**  这是最开始的操作。
2. **网页的 HTML 被解析，CSS 被加载和解析:** 浏览器会解析 HTML 结构，并加载 `<link>` 标签引用的 CSS 文件或 `<style>` 标签内的 CSS 代码。
3. **CSS 解析器遇到 `@font-face` 规则:**  当解析到 `@font-face` 规则时，Blink 引擎会创建 `CSSFontFace` 对象来表示这些规则。
4. **多个 `CSSFontFace` 对象因为相同的 `font-family` 属性被关联到同一个 `CSSSegmentedFontFace` 对象:** 如果有多个 `@font-face` 规则指定了相同的 `font-family`，它们会被组织到一起。
5. **浏览器需要渲染文本:** 当浏览器需要渲染包含使用了通过 `@font-face` 定义的字体的文本时。
6. **布局引擎请求字体数据:** 布局引擎会根据元素的样式（`font-family`, `font-weight` 等）向字体选择器请求合适的字体数据。
7. **`CSSSegmentedFontFace::GetFontData` 被调用:**  字体选择器会调用 `CSSSegmentedFontFace` 的 `GetFontData` 方法，传入 `FontDescription` 对象。
8. **`GetFontData` 方法遍历其管理的 `FontFace` 对象，找到匹配的字体数据:**  它会根据 `FontDescription` 中的属性（例如 `font-weight`）和 `FontFace` 的属性（例如 `unicode-range`）来查找。
9. **如果需要，触发字体加载:** 如果所需的字体尚未加载，`CSSSegmentedFontFace` 或其管理的 `FontFace` 对象会触发字体文件的加载。
10. **渲染引擎使用返回的字体数据来绘制文本:** 最终，渲染引擎会使用 `GetFontData` 返回的 `FontData` 来生成文本的字形。

**作为调试线索，当你看到与 `CSSSegmentedFontFace` 相关的代码被执行时，可能意味着：**

* 浏览器正在处理使用了自定义字体的文本。
* 遇到了包含 `unicode-range` 的 `@font-face` 规则。
* 正在进行字体选择，尝试找到最合适的字体片段来渲染特定字符。
* 可能存在字体加载延迟或失败的情况。
* 性能分析可能显示字体处理是渲染过程中的一个瓶颈。

希望这个详细的解释能够帮助你理解 `css_segmented_font_face.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/css/css_segmented_font_face.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/css_segmented_font_face.h"

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/css_font_face.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_face_creation_params.h"
#include "third_party/blink/renderer/platform/fonts/segmented_font_data.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"

namespace blink {

CSSSegmentedFontFace::CSSSegmentedFontFace(
    FontSelectionCapabilities font_selection_capabilities)
    : font_selection_capabilities_(font_selection_capabilities),
      font_faces_(MakeGarbageCollected<FontFaceList>()),
      approximate_character_count_(0) {}

CSSSegmentedFontFace::~CSSSegmentedFontFace() = default;

bool CSSSegmentedFontFace::IsValid() const {
  // Valid if at least one font face is valid.
  return font_faces_->ForEachUntilTrue(
      [](const Member<FontFace>& font_face) -> bool {
        return font_face->CssFontFace()->IsValid();
      });
}

void CSSSegmentedFontFace::FontFaceInvalidated() {
  font_data_table_.clear();
}

void CSSSegmentedFontFace::AddFontFace(FontFace* font_face,
                                       bool css_connected) {
  font_data_table_.clear();
  font_face->CssFontFace()->AddSegmentedFontFace(this);
  font_faces_->Insert(font_face, css_connected);
}

void CSSSegmentedFontFace::RemoveFontFace(FontFace* font_face) {
  if (!font_faces_->Erase(font_face)) {
    return;
  }

  font_data_table_.clear();
  font_face->CssFontFace()->RemoveSegmentedFontFace(this);
}

const FontData* CSSSegmentedFontFace::GetFontData(
    const FontDescription& font_description) {
  if (!IsValid()) {
    return nullptr;
  }

  bool is_unique_match = false;
  FontCacheKey key =
      font_description.CacheKey(FontFaceCreationParams(), is_unique_match);

  // font_data_table_ caches FontData and SegmentedFontData instances, which
  // provide SimpleFontData objects containing FontPlatformData objects. In the
  // case of variable font animations, the variable instance SkTypeface is
  // contained in these FontPlatformData objects. In other words, this cache
  // stores the recently used variable font instances during a variable font
  // animation. The cache reflects in how many different sizes, synthetic styles
  // (bold / italic synthetic versions), or for variable fonts, in how many
  // variable instances (stretch/style/weightand font-variation-setings
  // variations) the font is instantiated. In non animation scenarios, there is
  // usually only a small number of FontData/SegmentedFontData instances created
  // per CSSSegmentedFontFace. Whereas in variable font animations, this number
  // grows rapidly.
  auto it = font_data_table_.find(key);
  if (it != font_data_table_.end()) {
    const SegmentedFontData* cached_font_data = it->value.Get();
    if (cached_font_data && cached_font_data->NumFaces()) {
      return cached_font_data;
    }
  }

  SegmentedFontData* created_font_data =
      MakeGarbageCollected<SegmentedFontData>();

  FontDescription requested_font_description(font_description);
  const FontSelectionRequest& font_selection_request =
      font_description.GetFontSelectionRequest();
  requested_font_description.SetSyntheticBold(
      font_selection_capabilities_.weight.maximum < kBoldThreshold &&
      font_selection_request.weight >= kBoldThreshold &&
      font_description.SyntheticBoldAllowed());
  requested_font_description.SetSyntheticItalic(
      font_selection_capabilities_.slope.maximum < kItalicSlopeValue &&
      font_selection_request.slope >= kItalicSlopeValue &&
      font_description.SyntheticItalicAllowed());

  font_faces_->ForEachReverse([&requested_font_description, &created_font_data](
                                  const Member<FontFace>& font_face) {
    if (!font_face->CssFontFace()->IsValid()) {
      return;
    }
    if (const SimpleFontData* face_font_data =
            font_face->CssFontFace()->GetFontData(requested_font_description)) {
      DCHECK(!face_font_data->IsSegmented());
      created_font_data->AppendFace(MakeGarbageCollected<FontDataForRangeSet>(
          std::move(face_font_data), font_face->CssFontFace()->Ranges()));
    }
  });

  if (created_font_data->NumFaces()) {
    font_data_table_.insert(std::move(key), created_font_data);
    return created_font_data;
  }

  return nullptr;
}

void CSSSegmentedFontFace::WillUseFontData(
    const FontDescription& font_description,
    const String& text) {
  approximate_character_count_ += text.length();

  font_faces_->ForEachReverseUntilTrue(
      [&font_description, &text](const Member<FontFace>& font_face) -> bool {
        return font_face->LoadStatus() != FontFace::kUnloaded ||
               font_face->CssFontFace()->MaybeLoadFont(font_description, text);
      });
}

void CSSSegmentedFontFace::WillUseRange(
    const blink::FontDescription& font_description,
    const blink::FontDataForRangeSet& range_set) {
  // Iterating backwards since later defined unicode-range faces override
  // previously defined ones, according to the CSS3 fonts module.
  // https://drafts.csswg.org/css-fonts/#composite-fonts
  font_faces_->ForEachReverseUntilTrue(
      [&font_description,
       &range_set](const Member<FontFace>& font_face) -> bool {
        return font_face->CssFontFace()->MaybeLoadFont(font_description,
                                                       range_set);
      });
}

bool CSSSegmentedFontFace::CheckFont(UChar32 c) const {
  return !font_faces_->ForEachUntilTrue(
      [&c](const Member<FontFace>& font_face) -> bool {
        return font_face->LoadStatus() != FontFace::kLoaded &&
               font_face->CssFontFace()->Ranges()->Contains(c);
      });
}

void CSSSegmentedFontFace::Match(const String& text,
                                 HeapVector<Member<FontFace>>* faces) const {
  font_faces_->ForEach([&text, &faces](const Member<FontFace>& font_face) {
    if (font_face->CssFontFace()->Ranges()->IntersectsWith(text)) {
      faces->push_back(font_face);
    }
  });
}

void CSSSegmentedFontFace::Trace(Visitor* visitor) const {
  visitor->Trace(font_data_table_);
  visitor->Trace(font_faces_);
}

bool FontFaceList::IsEmpty() const {
  return css_connected_face_.empty() && non_css_connected_face_.empty();
}

namespace {

bool CascadePriorityHigherThan(const FontFace& new_font_face,
                               const FontFace& existing_font_face) {
  // We should reach here only for CSS-connected font faces, which must have an
  // owner document. However, there are cases where we don't have a document
  // here, possibly caused by ExecutionContext or Document lifecycle issues.
  // TODO(crbug.com/1250831): Find out the root cause and fix it.
  // Used to have base::debug::DumpWithoutCrashing(), but caused a lot of
  // crashes, particularly on Android (crbug.com/1468721).
  if (!new_font_face.GetDocument() || !existing_font_face.GetDocument()) {
    // In the buggy case, to ensure a stable ordering, font faces without a
    // document are considered higher priority.
    return !new_font_face.GetDocument();
  }
  DCHECK_EQ(new_font_face.GetDocument(), existing_font_face.GetDocument());
  DCHECK(new_font_face.GetStyleRule());
  DCHECK(existing_font_face.GetStyleRule());
  if (new_font_face.IsUserStyle() != existing_font_face.IsUserStyle()) {
    return existing_font_face.IsUserStyle();
  }
  const CascadeLayerMap* map = nullptr;
  if (new_font_face.IsUserStyle()) {
    map =
        new_font_face.GetDocument()->GetStyleEngine().GetUserCascadeLayerMap();
  } else if (new_font_face.GetDocument()->GetScopedStyleResolver()) {
    map = new_font_face.GetDocument()
              ->GetScopedStyleResolver()
              ->GetCascadeLayerMap();
  }
  if (!map) {
    return true;
  }
  return map->CompareLayerOrder(
             existing_font_face.GetStyleRule()->GetCascadeLayer(),
             new_font_face.GetStyleRule()->GetCascadeLayer()) <= 0;
}

}  // namespace

void FontFaceList::Insert(FontFace* font_face, bool css_connected) {
  if (!css_connected) {
    non_css_connected_face_.insert(font_face);
    return;
  }

  auto it = css_connected_face_.end();
  while (it != css_connected_face_.begin()) {
    auto prev = it;
    --prev;
    if (CascadePriorityHigherThan(*font_face, **prev)) {
      break;
    }
    it = prev;
  }

  css_connected_face_.InsertBefore(it, font_face);
}

bool FontFaceList::Erase(FontFace* font_face) {
  FontFaceListPart::iterator it = css_connected_face_.find(font_face);
  if (it != css_connected_face_.end()) {
    css_connected_face_.erase(it);
    return true;
  }
  it = non_css_connected_face_.find(font_face);
  if (it != non_css_connected_face_.end()) {
    non_css_connected_face_.erase(it);
    return true;
  }
  return false;
}

bool FontFaceList::ForEachUntilTrue(
    base::FunctionRef<bool(const Member<FontFace>&)> func) const {
  for (auto& font_face : css_connected_face_) {
    if (func(font_face)) {
      return true;
    }
  }
  for (auto& font_face : non_css_connected_face_) {
    if (func(font_face)) {
      return true;
    }
  }
  return false;
}

void FontFaceList::ForEach(
    base::FunctionRef<void(const Member<FontFace>&)> func) const {
  for (auto& font_face : css_connected_face_) {
    func(font_face);
  }
  for (auto& font_face : non_css_connected_face_) {
    func(font_face);
  }
}

void FontFaceList::ForEachReverseUntilTrue(
    base::FunctionRef<bool(const Member<FontFace>&)> func) const {
  for (auto& font_face : base::Reversed(non_css_connected_face_)) {
    if (func(font_face)) {
      return;
    }
  }
  for (auto& font_face : base::Reversed(css_connected_face_)) {
    if (func(font_face)) {
      return;
    }
  }
}

void FontFaceList::ForEachReverse(
    base::FunctionRef<void(const Member<FontFace>&)> func) const {
  for (auto& font_face : base::Reversed(non_css_connected_face_)) {
    func(font_face);
  }
  for (auto& font_face : base::Reversed(css_connected_face_)) {
    func(font_face);
  }
}

void FontFaceList::Trace(Visitor* visitor) const {
  visitor->Trace(css_connected_face_);
  visitor->Trace(non_css_connected_face_);
}

}  // namespace blink
```