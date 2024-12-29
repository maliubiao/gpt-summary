Response:
Let's break down the thought process for analyzing the `css_font_face.cc` file.

**1. Understanding the Goal:**

The core request is to understand the functionality of this specific Chromium/Blink source file. This involves identifying its purpose, its interactions with other parts of the system (especially Javascript, HTML, and CSS), potential usage errors, and how one might end up needing to debug this code.

**2. Initial Scan and Keyword Spotting:**

The first step is to quickly read through the code, paying attention to class names, method names, and included headers. This gives a high-level overview.

* **Class Name:** `CSSFontFace` - Immediately suggests this class is related to how CSS font faces are handled.
* **Included Headers:**  `css_font_face_source.h`, `css_font_selector.h`, `css_segmented_font_face.h`, `font_face_set_document.h`, `font_face_set_worker.h`, `remote_font_face_source.h`, `font_description.h`, `simple_font_data.h` - These tell us about the classes `CSSFontFace` interacts with. It manages sources of fonts, interacts with font selectors, handles segmented font faces, and is involved in document and worker contexts.
* **Method Names:** `AddSource`, `FontLoaded`, `GetFontData`, `Load`, `SetLoadStatus`, `MaybeLoadFont` -  These describe the key actions performed by the class.

**3. Deconstructing the Functionality (Method by Method):**

Now, go through each method and try to understand its role.

* **`AddSource`:**  Clearly adds a `CSSFontFaceSource`. This suggests a `CSSFontFace` can have multiple sources for a font (e.g., different formats, URLs).
* **`AddSegmentedFontFace`, `RemoveSegmentedFontFace`:** These manage a collection of `CSSSegmentedFontFace` objects. This likely relates to optimization or handling of large fonts.
* **`DidBeginLoad`:** Updates the load status to `kLoading`.
* **`FontLoaded`:** This is crucial. It handles the logic when a font source finishes loading (successfully or with an error). The checks for `IsValid`, `IsInFailurePeriod`, and the recursive `Load()` call are important. The notification to `segmented_font_faces_` indicates dependency.
* **`SetDisplay`:**  Propagates the `font-display` value to its sources.
* **`ApproximateBlankCharacterCount`:**  Seems related to performance and how long to show fallback text while a font loads.
* **`FallbackVisibilityChanged`:** Another notification mechanism, likely related to `font-display: swap`.
* **`GetFontData`:**  This is a core method. It iterates through the sources, tries to get the font data, and handles `size-adjust` and font metrics overrides. The handling of the `LoadStatus` within this method is significant.
* **`MaybeLoadFont` (two overloads):** These appear to be optimization pathways to initiate font loading based on character presence or range sets. They are "maybe" because the full loading might happen later.
* **`Load` (two overloads):**  The core loading mechanism. It iterates through sources, checks availability, and initiates loading. The handling of local vs. remote fonts is visible here.
* **`SetLoadStatus`:** Updates the font's loading state and informs related document/worker contexts.
* **`UpdatePeriod`:**  Likely related to checking the status of loading fonts periodically.
* **`Trace`:** For debugging and memory management.

**4. Identifying Relationships with Javascript, HTML, and CSS:**

Now, connect the dots between the code and the web technologies:

* **CSS:** The very name `CSSFontFace` screams CSS. The file directly implements how `@font-face` rules are processed. Properties like `font-family`, `src`, `unicode-range`, `font-display`, and `size-adjust` are directly related.
* **HTML:**  The use of fonts in HTML content triggers the need for this code. When the browser renders text, it needs to find and load the correct font.
* **Javascript:** The Font Loading API (`document.fonts`) directly interacts with the functionality implemented here. Javascript can monitor font loading status and trigger actions based on it.

**5. Logical Reasoning and Examples:**

For each significant method, think about the inputs and outputs and create illustrative examples:

* **`GetFontData`:** Consider scenarios where a font is available locally, remotely, or fails to load. Include `size-adjust`.
* **`Load`:** Think about the different types of sources (local, remote) and how loading is initiated.
* **`FontLoaded`:**  Imagine a successful load, a failed load, and the scenario where multiple sources are listed.

**6. Identifying User/Programming Errors:**

Think about common mistakes developers make when working with web fonts:

* Incorrect `src` URLs.
* Mismatched `unicode-range`.
* Not understanding `font-display`.
* Issues with local font availability.

**7. Debugging Scenario:**

Consider how a developer might end up looking at this specific file during debugging. A common scenario involves a web font not loading correctly. The developer might:

* Use browser developer tools (Network tab, Computed styles).
* Look for error messages in the console.
* Step through the browser's rendering engine (if they have access to the source code).

**8. Structuring the Answer:**

Finally, organize the information in a clear and logical way, addressing each part of the original request:

* **Functionality:**  Provide a concise summary, then detail each method's purpose.
* **Relationships:** Explicitly state the connections to Javascript, HTML, and CSS with examples.
* **Logical Reasoning:**  Present the "if input X, then output Y" scenarios.
* **User Errors:** List common mistakes.
* **Debugging:** Describe the steps a developer might take to reach this file.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This file just loads fonts."
* **Correction:**  "No, it *manages* the loading process, including handling multiple sources, errors, and interaction with other font-related classes."
* **Initial thought:** "The `Load` method directly fetches the font file."
* **Correction:** "The `Load` method *initiates* the loading process, but the actual fetching is likely handled by the `CSSFontFaceSource` classes."
* **Initial thought:**  "The `MaybeLoadFont` methods are redundant."
* **Correction:** "They seem to be performance optimizations for specific cases, avoiding full loading if only a subset of characters is needed initially."

By following this systematic approach, combining code analysis with knowledge of web technologies and common developer practices, we can arrive at a comprehensive and accurate understanding of the `css_font_face.cc` file.
好的，让我们来分析一下 `blink/renderer/core/css/css_font_face.cc` 这个文件。

**文件功能概述:**

`CSSFontFace.cc` 文件定义了 `CSSFontFace` 类，它是 Chromium Blink 渲染引擎中负责处理 CSS `@font-face` 规则的核心组件。它的主要功能可以概括为：

1. **管理字体来源 (Font Sources):**  一个 `@font-face` 规则可以有多个 `src` 属性，指向不同的字体文件（本地或远程）。`CSSFontFace` 负责存储和管理这些 `CSSFontFaceSource` 对象。
2. **处理字体加载状态:** 跟踪字体的加载状态，包括 `kUnloaded` (未加载), `kLoading` (加载中), `kLoaded` (已加载), `kError` (加载失败)。
3. **字体数据获取:**  当需要使用某个字体时，`CSSFontFace` 负责从可用的 `CSSFontFaceSource` 中获取字体的实际数据 (`SimpleFontData`)。它会按照 `src` 声明的顺序尝试加载，直到成功或全部失败。
4. **处理 `font-display` 属性:**  根据 CSS `font-display` 属性（如 `auto`, `block`, `swap`, `fallback`, `optional`）控制字体的加载和显示行为。
5. **处理 `unicode-range` 属性:**  根据 CSS `unicode-range` 属性，判断当前需要的字符是否在这个字体支持的范围内，从而决定是否需要加载该字体。
6. **处理 `size-adjust` 属性:**  应用 CSS `size-adjust` 属性来调整字体大小。
7. **处理字体度量覆盖 (Font Metrics Override):**  应用 CSS 提供的字体度量覆盖，例如 `ascent-override`, `descent-override`, `line-gap-override`。
8. **通知字体加载状态变化:**  当字体加载状态发生变化时，通知相关的组件，例如 `CSSSegmentedFontFace` (用于优化大型字体)。
9. **与文档和 Worker 上下文交互:** 在文档 (`FontFaceSetDocument`) 和 Worker (`FontFaceSetWorker`) 上下文中管理字体加载。

**与 Javascript, HTML, CSS 的关系及举例:**

* **CSS:** `CSSFontFace` 直接对应 CSS 的 `@font-face` 规则。
    * **举例:**  以下 CSS 代码会创建一个 `CSSFontFace` 对象，其中 `font-family`、`src`、`unicode-range` 等属性会被解析并存储在 `CSSFontFace` 及其相关的 `CSSFontFaceSource` 对象中。

      ```css
      @font-face {
        font-family: 'MyCustomFont';
        src: url('my-font.woff2') format('woff2'),
             url('my-font.woff') format('woff');
        unicode-range: U+0020-00FF; /* Basic Latin */
        font-display: swap;
      }

      body {
        font-family: 'MyCustomFont', sans-serif;
      }
      ```

* **HTML:**  HTML 中使用带有 `font-family` 属性的元素，当浏览器遇到一个需要使用特定字体的文本时，会查找匹配的 `CSSFontFace` 对象。
    * **举例:**  在上面的 CSS 示例中，`<body>` 元素的文本将尝试使用 'MyCustomFont'。浏览器会找到对应的 `CSSFontFace` 对象并开始加载字体。

* **Javascript:**  Javascript 的 Font Loading API (`document.fonts`) 允许开发者在运行时检查和控制字体加载。`CSSFontFace` 对象的加载状态变化会影响 `document.fonts.ready` promise 的解析和 `document.fonts.onloadingdone` 事件的触发。
    * **举例:**  以下 Javascript 代码可以检查名为 'MyCustomFont' 的字体是否已加载：

      ```javascript
      document.fonts.load("1em MyCustomFont").then(function(fonts) {
        if (fonts.length > 0) {
          console.log("MyCustomFont is loaded!");
        } else {
          console.log("MyCustomFont is not loaded.");
        }
      });
      ```

**逻辑推理及假设输入与输出:**

假设有以下 CSS `@font-face` 规则：

```css
@font-face {
  font-family: 'MyWebFont';
  src: url('remote-font.woff2') format('woff2'),
       local('Arial'),
       url('backup-font.ttf') format('truetype');
  unicode-range: U+4E00-9FFF; /* CJK Unified Ideographs */
}
```

并且 HTML 中有包含中文的文本：

```html
<p style="font-family: 'MyWebFont'">你好</p>
```

**假设输入:**

1. 浏览器解析到上述 `@font-face` 规则，创建 `CSSFontFace` 对象。
2. 浏览器解析到 `<p>` 元素，需要渲染文本 "你好"。
3. 浏览器计算出需要使用 'MyWebFont' 字体。
4. 浏览器检查字符 "你" 和 "好" 的 Unicode 编码，确定它们在 `U+4E00-9FFF` 范围内。

**逻辑推理:**

1. `CSSFontFace::MaybeLoadFont()` 或 `CSSFontFace::GetFontData()` 会被调用，因为需要使用 'MyWebFont'。
2. 由于 `unicode-range` 匹配，`CSSFontFace` 会尝试加载字体。
3. 它会首先尝试加载远程字体 `remote-font.woff2`。
    * **输出 (如果加载成功):** `CSSFontFace` 的加载状态变为 `kLoaded`，文本 "你好" 使用 `remote-font.woff2` 显示。
    * **输出 (如果加载失败):** `CSSFontFace` 会尝试下一个来源 `local('Arial')`。
4. 如果本地系统有 'Arial' 字体，则 `CSSFontFace` 的加载状态变为 `kLoaded`，文本 "你好" 使用本地 'Arial' 字体显示。
5. 如果本地 'Arial' 不可用，则 `CSSFontFace` 会尝试加载远程字体 `backup-font.ttf`。
    * **输出 (如果加载成功):** `CSSFontFace` 的加载状态变为 `kLoaded`，文本 "你好" 使用 `backup-font.ttf` 显示。
    * **输出 (如果加载失败):** `CSSFontFace` 的加载状态变为 `kError`，浏览器可能会使用默认的回退字体显示文本。

**用户或编程常见的使用错误及举例:**

1. **`src` 路径错误:**  `url()` 中的字体文件路径不正确，导致浏览器无法找到字体文件。
   * **举例:** `@font-face { font-family: 'BrokenFont'; src: url('wont-find-this.woff2'); }`
2. **`format()` 声明错误:**  `format()` 声明与实际字体文件格式不符。
   * **举例:** `@font-face { font-family: 'WrongFormat'; src: url('my-font.ttf') format('woff2'); }`
3. **`unicode-range` 设置不当:**  `unicode-range` 设置过于狭窄，导致某些字符无法使用该字体。
   * **举例:** `@font-face { font-family: 'LimitedFont'; src: url('my-font.woff2'); unicode-range: U+0041-005A; }` (只包含大写字母，如果文本包含小写字母或中文则不会使用此字体)。
4. **`font-family` 名称冲突:**  与系统默认字体或其他自定义字体名称冲突，导致样式覆盖或加载混乱。
5. **服务器配置问题 (CORS):**  如果字体文件托管在不同的域上，服务器可能没有配置正确的 CORS 头，导致浏览器阻止字体加载。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览网页时发现某个自定义字体没有正确加载。作为开发者，你可能会进行以下调试步骤，最终可能需要查看 `css_font_face.cc` 的代码：

1. **检查开发者工具的 "Network" 选项卡:**  查看字体文件是否被成功下载。如果状态码是 404 或其他错误，说明 `src` 路径或服务器配置有问题。
2. **检查开发者工具的 "Console" 选项卡:**  浏览器可能会输出与字体加载相关的错误信息，例如 CORS 错误或格式不支持。
3. **检查开发者工具的 "Elements" 或 "Sources" 选项卡，查看 "Computed" 样式:**  确认目标元素的 `font-family` 属性是否正确应用，以及浏览器最终选择了哪个字体。
4. **如果字体文件下载正常，但字体仍然显示不正确:**
    * **检查 `@font-face` 规则:**  确认 `font-family`、`src`、`unicode-range`、`font-display` 等属性是否正确。
    * **使用浏览器的 "字体" 面板 (如果存在):** 一些浏览器提供了专门的字体调试工具，可以查看已加载的字体和它们的属性。
5. **如果以上步骤都无法解决问题，并且怀疑是浏览器引擎本身的问题 (可能性较小但存在):**
    * **设置断点调试 Blink 渲染引擎:**  开发者可能需要在 `css_font_face.cc` 中的关键函数（例如 `GetFontData`, `Load`, `FontLoaded`）设置断点，来跟踪字体的加载过程，查看 `sources_` 中的字体来源，以及加载状态的变化。
    * **查看日志输出:** Blink 引擎可能有相关的日志输出，可以帮助理解字体加载的流程。

**总结:**

`css_font_face.cc` 是 Blink 引擎中处理 CSS 自定义字体的核心组件，它负责管理字体来源、跟踪加载状态、获取字体数据，并与 Javascript、HTML 和 CSS 紧密关联。理解其功能有助于开发者诊断和解决与 Web 字体相关的各种问题。

Prompt: 
```
这是目录为blink/renderer/core/css/css_font_face.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2007, 2008, 2011 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/css_font_face.h"

#include <algorithm>
#include "third_party/blink/renderer/core/css/css_font_face_source.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_segmented_font_face.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/css/font_face_set_worker.h"
#include "third_party/blink/renderer/core/css/font_size_functions.h"
#include "third_party/blink/renderer/core/css/remote_font_face_source.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

void CSSFontFace::AddSource(CSSFontFaceSource* source) {
  sources_.push_back(source);
}

void CSSFontFace::AddSegmentedFontFace(
    CSSSegmentedFontFace* segmented_font_face) {
  DCHECK(!segmented_font_faces_.Contains(segmented_font_face));
  segmented_font_faces_.insert(segmented_font_face);
}

void CSSFontFace::RemoveSegmentedFontFace(
    CSSSegmentedFontFace* segmented_font_face) {
  DCHECK(segmented_font_faces_.Contains(segmented_font_face));
  segmented_font_faces_.erase(segmented_font_face);
}

void CSSFontFace::DidBeginLoad() {
  if (LoadStatus() == FontFace::kUnloaded) {
    SetLoadStatus(FontFace::kLoading);
  }
}

bool CSSFontFace::FontLoaded(CSSFontFaceSource* source) {
  if (!IsValid() || source != sources_.front()) {
    return false;
  }

  if (LoadStatus() == FontFace::kLoading) {
    if (source->IsValid()) {
      SetLoadStatus(FontFace::kLoaded);
    } else if (source->IsInFailurePeriod()) {
      sources_.clear();
      SetLoadStatus(FontFace::kError);
    } else {
      sources_.pop_front();
      Load();
    }
  }

  for (CSSSegmentedFontFace* segmented_font_face : segmented_font_faces_) {
    segmented_font_face->FontFaceInvalidated();
  }
  return true;
}

void CSSFontFace::SetDisplay(FontDisplay value) {
  for (auto& source : sources_) {
    source->SetDisplay(value);
  }
}

size_t CSSFontFace::ApproximateBlankCharacterCount() const {
  if (sources_.empty() || !sources_.front()->IsInBlockPeriod()) {
    return 0;
  }
  size_t approximate_character_count_ = 0;
  for (CSSSegmentedFontFace* segmented_font_face : segmented_font_faces_) {
    approximate_character_count_ +=
        segmented_font_face->ApproximateCharacterCount();
  }
  return approximate_character_count_;
}

bool CSSFontFace::FallbackVisibilityChanged(RemoteFontFaceSource* source) {
  if (!IsValid() || source != sources_.front()) {
    return false;
  }
  for (CSSSegmentedFontFace* segmented_font_face : segmented_font_faces_) {
    segmented_font_face->FontFaceInvalidated();
  }
  return true;
}

const SimpleFontData* CSSFontFace::GetFontData(
    const FontDescription& font_description) {
  if (!IsValid()) {
    return nullptr;
  }

  // Apply the 'size-adjust' descriptor before font selection.
  // https://drafts.csswg.org/css-fonts-5/#descdef-font-face-size-adjust
  FontDescription size_adjusted_description =
      font_face_->HasSizeAdjust()
          ? font_description.SizeAdjustedFontDescription(
                font_face_->GetSizeAdjust())
          : font_description;

  // https://www.w3.org/TR/css-fonts-4/#src-desc
  // "When a font is needed the user agent iterates over the set of references
  // listed, using the first one it can successfully activate."
  while (!sources_.empty()) {
    Member<CSSFontFaceSource>& source = sources_.front();

    // Bail out if the first source is in the Failure period, causing fallback
    // to next font-family.
    if (source->IsInFailurePeriod()) {
      return nullptr;
    }

    if (const SimpleFontData* result =
            source->GetFontData(size_adjusted_description,
                                font_face_->GetFontSelectionCapabilities())) {
      // The font data here is created using the primary font's description.
      // We need to adjust the size of a fallback font with actual font metrics
      // if the description has font-size-adjust.
      if (size_adjusted_description.HasSizeAdjust()) {
        if (auto adjusted_size =
                FontSizeFunctions::MetricsMultiplierAdjustedFontSize(
                    result, size_adjusted_description)) {
          size_adjusted_description.SetAdjustedSize(adjusted_size.value());
          result =
              source->GetFontData(size_adjusted_description,
                                  font_face_->GetFontSelectionCapabilities());
        }
      }

      if (font_face_->HasFontMetricsOverride()) {
        // TODO(xiaochengh): Try not to create a temporary
        // SimpleFontData.
        result = result->MetricsOverriddenFontData(
            font_face_->GetFontMetricsOverride());
      }
      // The active source may already be loading or loaded. Adjust our
      // FontFace status accordingly.
      if (LoadStatus() == FontFace::kUnloaded &&
          (source->IsLoading() || source->IsLoaded())) {
        SetLoadStatus(FontFace::kLoading);
      }
      if (LoadStatus() == FontFace::kLoading && source->IsLoaded()) {
        SetLoadStatus(FontFace::kLoaded);
      }
      return result;
    }
    sources_.pop_front();
  }

  // We ran out of source. Set the FontFace status to "error" and return.
  if (LoadStatus() == FontFace::kUnloaded) {
    SetLoadStatus(FontFace::kLoading);
  }
  if (LoadStatus() == FontFace::kLoading) {
    SetLoadStatus(FontFace::kError);
  }
  return nullptr;
}

bool CSSFontFace::MaybeLoadFont(const FontDescription& font_description,
                                const String& text) {
  // This is a fast path of loading web font in style phase. For speed, this
  // only checks if the first character of the text is included in the font's
  // unicode range. If this font is needed by subsequent characters, load is
  // kicked off in layout phase.
  UChar32 character = text.CharacterStartingAt(0);
  if (ranges_->Contains(character)) {
    if (LoadStatus() == FontFace::kUnloaded) {
      Load(font_description);
    }
    return true;
  }
  return false;
}

bool CSSFontFace::MaybeLoadFont(const FontDescription& font_description,
                                const FontDataForRangeSet& range_set) {
  if (ranges_ == range_set.Ranges()) {
    if (LoadStatus() == FontFace::kUnloaded) {
      Load(font_description);
    }
    return true;
  }
  return false;
}

void CSSFontFace::Load() {
  FontDescription font_description;
  font_description.SetFamily(
      FontFamily(font_face_->family(), FontFamily::Type::kFamilyName));
  Load(font_description);
}

void CSSFontFace::Load(const FontDescription& font_description) {
  if (LoadStatus() == FontFace::kUnloaded) {
    SetLoadStatus(FontFace::kLoading);
  }
  DCHECK_EQ(LoadStatus(), FontFace::kLoading);

  while (!sources_.empty()) {
    Member<CSSFontFaceSource>& source = sources_.front();
    if (source->IsValid()) {
      if (source->IsLocalNonBlocking()) {
        if (source->IsLocalFontAvailable(font_description)) {
          SetLoadStatus(FontFace::kLoaded);
          return;
        }
      } else {
        if (!source->IsLoaded()) {
          source->BeginLoadIfNeeded();
        } else {
          SetLoadStatus(FontFace::kLoaded);
        }
        return;
      }
    }
    sources_.pop_front();
  }
  SetLoadStatus(FontFace::kError);
}

void CSSFontFace::SetLoadStatus(FontFace::LoadStatusType new_status) {
  DCHECK(font_face_);
  if (new_status == FontFace::kError) {
    font_face_->SetError();
  } else {
    font_face_->SetLoadStatus(new_status);
  }

  if (segmented_font_faces_.empty() || !font_face_->GetExecutionContext()) {
    return;
  }

  if (auto* window =
          DynamicTo<LocalDOMWindow>(font_face_->GetExecutionContext())) {
    if (new_status == FontFace::kLoading) {
      FontFaceSetDocument::From(*window->document())
          ->BeginFontLoading(font_face_);
    }
  } else if (auto* scope = DynamicTo<WorkerGlobalScope>(
                 font_face_->GetExecutionContext())) {
    if (new_status == FontFace::kLoading) {
      FontFaceSetWorker::From(*scope)->BeginFontLoading(font_face_);
    }
  }
}

bool CSSFontFace::UpdatePeriod() {
  if (LoadStatus() == FontFace::kLoaded) {
    return false;
  }
  bool changed = false;
  for (CSSFontFaceSource* source : sources_) {
    if (source->UpdatePeriod()) {
      changed = true;
    }
  }
  return changed;
}

void CSSFontFace::Trace(Visitor* visitor) const {
  visitor->Trace(segmented_font_faces_);
  visitor->Trace(sources_);
  visitor->Trace(ranges_);
  visitor->Trace(font_face_);
}

}  // namespace blink

"""

```