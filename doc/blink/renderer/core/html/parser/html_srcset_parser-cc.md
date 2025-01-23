Response:
Let's break down the thought process for analyzing the `html_srcset_parser.cc` file and generating the detailed response.

1. **Understand the Core Functionality:** The filename itself, `html_srcset_parser.cc`, strongly suggests the primary purpose: parsing the `srcset` attribute in HTML. The code within confirms this, dealing with extracting image URLs and their associated descriptors (like `w`, `x`, `h`).

2. **Identify Key Data Structures:**  Look for classes or structs that represent the parsed data. The `ImageCandidate` class stands out as holding information about each potential image source. `DescriptorParsingResult` stores the parsed values of the descriptors. `DescriptorToken` helps in the tokenization process.

3. **Trace the Parsing Flow:** Follow the execution path of the core parsing functions. The `ParseImageCandidatesFromSrcsetAttribute` function is the main entry point. Notice how it iterates through the `srcset` string, identifies URLs, and then calls `TokenizeDescriptors` and `ParseDescriptors` to handle the descriptor part.

4. **Analyze Descriptor Handling:**  Focus on the `TokenizeDescriptors` and `ParseDescriptors` functions. Understand how they break down the descriptor string into individual tokens and interpret them (e.g., recognizing 'w', 'x', 'h' and converting their values). Pay attention to the error handling within `ParseDescriptors`.

5. **Understand the Image Selection Logic:** The `PickBestImageCandidate` function is crucial. Analyze how it uses the parsed `ImageCandidate` data and the `device_scale_factor` and `source_size` to determine the most appropriate image. Note the `SelectionLogic` and `AvoidDownloadIfHigherDensityResourceIsInCache` helper functions.

6. **Connect to HTML, CSS, and JavaScript:**
    * **HTML:** The `srcset` attribute is an HTML feature. The parser directly processes this attribute.
    * **CSS:** The `source_size` parameter hints at a connection to the `<picture>` element and the `sizes` attribute, which can be influenced by CSS media queries.
    * **JavaScript:** While this code is C++, it's part of the browser engine. JavaScript code running on a webpage interacts with the DOM, which includes elements with `srcset` attributes. The browser uses this parser to determine which image to load.

7. **Consider Error Handling and Edge Cases:** The code includes `SrcsetError` for reporting parsing issues. Think about common mistakes users might make when writing `srcset` values (e.g., invalid descriptor values, mixing incompatible descriptors).

8. **Infer Logical Reasoning and Assumptions:** The image selection logic makes assumptions about how browsers should choose the best image based on device pixel ratio and available bandwidth (especially with the "Save-Data" mode). The prioritization of cached resources is another logical step.

9. **Formulate Examples:**  Create illustrative examples for each connection (HTML, CSS, JavaScript) and for potential user errors. These examples should clearly demonstrate the interaction or the problematic scenario.

10. **Structure the Response:** Organize the information logically. Start with a high-level overview of the file's purpose, then delve into the details of its functionality, relationships with web technologies, logical reasoning, and potential errors. Use clear headings and formatting for readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This just parses `srcset`."
* **Correction:** "It *primarily* parses `srcset`, but it also interacts with the browser's resource loading mechanism and needs to consider factors like device pixel ratio and caching."
* **Initial thought:** "Just list the functions."
* **Refinement:** "Explain *what* the functions do and *how* they contribute to the overall process. Emphasize the data flow and the decision-making involved."
* **Initial thought:** "JavaScript has no direct interaction."
* **Correction:** "While the parser is C++, JavaScript indirectly uses its results when the browser renders images based on the `srcset` attribute."

By following this structured approach and continuously refining the understanding, a comprehensive and accurate response can be generated. The key is to go beyond just reading the code and think about its purpose within the larger browser ecosystem.
这个文件 `blink/renderer/core/html/parser/html_srcset_parser.cc` 的主要功能是**解析 HTML `srcset` 属性的值**，并将解析后的信息用于**选择最适合当前环境的图像资源**。

更具体地说，它负责执行以下操作：

1. **解析 `srcset` 字符串:**  将 `srcset` 属性的值分解成一系列的图像候选项。每个候选项包含一个图像 URL 和一组描述符（descriptor）。

2. **解析描述符:**  理解每个图像候选项关联的描述符，例如：
   - `w` (宽度描述符):  指定图像的固有宽度（以像素为单位）。
   - `x` (像素密度描述符):  指定图像的目标像素密度（例如，`2x` 表示该图像适用于设备像素比为 2 的屏幕）。
   - `h` (高度描述符):  指定图像的固有高度（以像素为单位）。虽然目前 Blink 中 `h` 描述符的值未使用，但解析器会进行处理以保证未来兼容性。

3. **创建图像候选项对象:**  为每个解析成功的图像 URL 和其描述符创建一个 `ImageCandidate` 对象，存储其 URL、像素密度、宽度等信息。

4. **根据设备环境选择最佳图像:**  根据当前设备的像素密度 (`device_scale_factor`) 和图像的显示尺寸 (`source_size`)，从解析出的图像候选项中选择最合适的图像 URL。选择逻辑会考虑：
   - 设备的像素密度。
   - 图像的像素密度描述符 (`x`) 或计算出的像素密度 (`w` 描述符的情况)。
   - 避免下载更高密度的已缓存资源。
   - "节省数据"模式下的特殊处理。

**与 JavaScript, HTML, CSS 的关系：**

这个文件在浏览器引擎的底层工作，直接处理 HTML 结构中的属性，并影响图像资源的加载。它与 JavaScript, HTML, 和 CSS 的关系如下：

**1. HTML:**

- **核心功能就是解析 HTML 属性:**  `srcset` 属性是 HTML 的一部分，用于为 `<img>` 元素或 `<source>` 元素提供响应式图像资源。 `html_srcset_parser.cc` 的任务就是理解这个属性的内容。

   **例子:**

   ```html
   <img srcset="image-320w.jpg 320w, image-480w.jpg 480w, image-800w.jpg 800w"
        sizes="(max-width: 480px) 100vw,
               (max-width: 800px) 50vw,
               800px"
        src="image-800w.jpg" alt="Responsive Image">
   ```

   在这个例子中，`html_srcset_parser.cc` 会解析 `srcset` 属性的值，提取出三个图像 URL 及其对应的宽度描述符 (`320w`, `480w`, `800w`). 结合 `sizes` 属性（虽然不在该文件的直接处理范围内，但会影响图像的选择），浏览器会根据视口宽度选择合适的图像。

**2. CSS:**

- **`sizes` 属性的间接影响:**  虽然 `html_srcset_parser.cc` 本身不解析 CSS，但 `sizes` 属性的值可能包含 CSS 单位（例如 `vw`），并会受到 CSS 布局的影响。  `sizes` 属性定义了图像在不同视口大小下的显示宽度，这个宽度会作为 `source_size` 参数传递给图像选择逻辑。

   **例子 (继续上面的 HTML):**

   CSS 可能会影响 `sizes` 属性中 `vw` 单位的实际像素值。例如，如果页面有边距或内边距，`100vw` 就不是屏幕的完整宽度。浏览器在计算 `source_size` 时会考虑这些 CSS 布局信息。

- **设备像素比 (DPR):**  设备的像素密度 (`device_scale_factor`) 是图像选择的关键因素。虽然 DPR 不是直接由 CSS 设置，但 CSS 媒体查询可以基于 DPR 应用不同的样式，这间接说明了 DPR 的重要性。

**3. JavaScript:**

- **可以通过 JavaScript 获取和修改 `srcset` 属性:**  JavaScript 可以通过 DOM API 读取和修改元素的 `srcset` 属性。当 `srcset` 属性被修改时，浏览器会重新运行解析和图像选择逻辑，`html_srcset_parser.cc` 会再次发挥作用。

   **例子:**

   ```javascript
   const img = document.querySelector('img');
   img.srcset = 'new-image-400.jpg 400w, new-image-800.jpg 800w';
   ```

   这段 JavaScript 代码修改了 `<img>` 元素的 `srcset` 属性。浏览器会使用 `html_srcset_parser.cc` 解析新的属性值，并可能加载不同的图像。

- **JavaScript 可以获取选择的图像 URL:**  虽然 `html_srcset_parser.cc` 的内部逻辑是 C++，但最终选择的图像 URL 会被浏览器使用，JavaScript 可以通过 `img.currentSrc` 属性获取到这个 URL。

**逻辑推理的假设输入与输出:**

**假设输入:**

- `srcset` 属性字符串: `"image-small.jpg 320w, image-medium.jpg 640w, image-large.jpg 1024w"`
- `device_scale_factor`: 2 (Retina 屏幕)
- `source_size`: 500 (图像的显示宽度为 500 像素)
- `document`: 指向当前文档的指针 (用于日志记录和获取完整 URL)

**逻辑推理过程:**

1. **解析 `srcset`:** 解析器会提取出三个图像候选项：
   - `image-small.jpg`, 宽度 320px
   - `image-medium.jpg`, 宽度 640px
   - `image-large.jpg`, 宽度 1024px

2. **计算目标密度:**  对于每个候选项，根据其宽度描述符和 `source_size` 计算出目标像素密度：
   - `image-small.jpg`: 320w / 500px = 0.64x
   - `image-medium.jpg`: 640w / 500px = 1.28x
   - `image-large.jpg`: 1024w / 500px = 2.048x

3. **选择最佳匹配:**  根据 `device_scale_factor` (2) 和计算出的目标密度，选择最合适的图像。通常会选择目标密度略高于或接近设备像素比的图像，以保证清晰度，同时避免下载过大的资源。

**可能输出:**

- 最合适的 `ImageCandidate` 对象可能指向 `image-large.jpg`，因为其目标密度 (2.048x) 最接近设备的像素密度 (2x)。

**用户或编程常见的使用错误举例:**

1. **`srcset` 属性语法错误:**

   ```html
   <!-- 缺少单位 -->
   <img srcset="image.jpg 320, image-hd.jpg 640">

   <!-- 错误的描述符类型 -->
   <img srcset="image.jpg small, image-hd.jpg large">

   <!-- 混合使用 w 和 x 描述符在一个候选项中 (不推荐) -->
   <img srcset="image.jpg 320w 1x">
   ```

   这些错误会导致解析失败或得到意外的结果。`html_srcset_parser.cc` 会尝试解析，但可能会生成警告信息到控制台。

2. **提供不合适的图像密度:**

   ```html
   <!-- 只有低密度的图像，在高 DPI 屏幕上会模糊 -->
   <img srcset="low-res.jpg 1x">

   <!-- 只有高密度的图像，在低 DPI 屏幕上浪费带宽 -->
   <img srcset="high-res.jpg 3x">
   ```

   虽然语法上正确，但这种用法没有充分利用 `srcset` 的优势。

3. **`sizes` 属性与 `srcset` 的不匹配:**  如果 `sizes` 属性定义的图像显示尺寸与 `srcset` 中提供的图像宽度不匹配，可能会导致浏览器选择错误的图像。

   ```html
   <img srcset="small.jpg 200w, large.jpg 800w"
        sizes="50vw"  <!-- 即使在小屏幕上，也可能显示很大 -->
        src="fallback.jpg" alt="Image">
   ```

   如果视口很大，`50vw` 可能导致图像显示宽度远大于 `200w`，但小于 `800w`。浏览器可能会选择 `large.jpg`，即使 `small.jpg` 更合适。

4. **服务端配置错误:**  即使 `srcset` 属性正确，如果服务器没有正确配置图像资源的 MIME 类型或缓存策略，也可能导致加载问题。这不属于 `html_srcset_parser.cc` 的职责范围，但会影响最终用户体验。

总之，`html_srcset_parser.cc` 是 Blink 引擎中一个关键的组件，负责解析 HTML 中用于响应式图像的 `srcset` 属性，并根据设备环境选择最佳的图像资源，从而优化网页加载性能和用户体验。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_srcset_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/parser/html_srcset_parser.h"

#include <algorithm>

#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_network_state_notifier.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/parsing_utilities.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"

namespace blink {

static bool CompareByDensity(const ImageCandidate& first,
                             const ImageCandidate& second) {
  return first.Density() < second.Density();
}

enum DescriptorTokenizerState {
  kTokenStart,
  kInParenthesis,
  kAfterToken,
};

struct DescriptorToken {
  unsigned start;
  unsigned length;

  DescriptorToken(unsigned start, unsigned length)
      : start(start), length(length) {}

  unsigned LastIndex() { return start + length - 1; }

  template <typename CharType>
  int ToInt(const CharType* attribute, bool& is_valid) {
    unsigned position = 0;
    // Make sure the integer is a valid non-negative integer
    // https://html.spec.whatwg.org/C/#valid-non-negative-integer
    unsigned length_excluding_descriptor = length - 1;
    while (position < length_excluding_descriptor) {
      if (!IsASCIIDigit(*(attribute + start + position))) {
        is_valid = false;
        return 0;
      }
      ++position;
    }
    return CharactersToInt(base::span<const CharType>(
                               attribute + start, length_excluding_descriptor),
                           WTF::NumberParsingOptions(), &is_valid);
  }

  template <typename CharType>
  float ToFloat(const CharType* attribute, bool& is_valid) {
    // Make sure the is a valid floating point number
    // https://html.spec.whatwg.org/C/#valid-floating-point-number
    unsigned length_excluding_descriptor = length - 1;
    if (length_excluding_descriptor > 0 && *(attribute + start) == '+') {
      is_valid = false;
      return 0;
    }
    Decimal result = ParseToDecimalForNumberType(
        String(base::span(attribute + start, length_excluding_descriptor)));
    is_valid = result.IsFinite();
    if (!is_valid)
      return 0;
    return static_cast<float>(result.ToDouble());
  }
};

template <typename CharType>
static void AppendDescriptorAndReset(const CharType* attribute_start,
                                     const CharType*& descriptor_start,
                                     const CharType* position,
                                     Vector<DescriptorToken>& descriptors) {
  if (position > descriptor_start) {
    descriptors.push_back(DescriptorToken(
        static_cast<unsigned>(descriptor_start - attribute_start),
        static_cast<unsigned>(position - descriptor_start)));
  }
  descriptor_start = nullptr;
}

// The following is called appendCharacter to match the spec's terminology.
template <typename CharType>
static void AppendCharacter(const CharType* descriptor_start,
                            const CharType* position) {
  // Since we don't copy the tokens, this just set the point where the
  // descriptor tokens start.
  if (!descriptor_start)
    descriptor_start = position;
}

template <typename CharType>
static bool IsEOF(const CharType* position, const CharType* end) {
  return position >= end;
}

template <typename CharType>
static void TokenizeDescriptors(const CharType* attribute_start,
                                const CharType*& position,
                                const CharType* attribute_end,
                                Vector<DescriptorToken>& descriptors) {
  DescriptorTokenizerState state = kTokenStart;
  const CharType* descriptors_start = position;
  const CharType* current_descriptor_start = descriptors_start;
  while (true) {
    switch (state) {
      case kTokenStart:
        if (IsEOF(position, attribute_end)) {
          AppendDescriptorAndReset(attribute_start, current_descriptor_start,
                                   attribute_end, descriptors);
          return;
        }
        if (IsComma(*position)) {
          AppendDescriptorAndReset(attribute_start, current_descriptor_start,
                                   position, descriptors);
          ++position;
          return;
        }
        if (IsHTMLSpace(*position)) {
          AppendDescriptorAndReset(attribute_start, current_descriptor_start,
                                   position, descriptors);
          current_descriptor_start = position + 1;
          state = kAfterToken;
        } else if (*position == '(') {
          AppendCharacter(current_descriptor_start, position);
          state = kInParenthesis;
        } else {
          AppendCharacter(current_descriptor_start, position);
        }
        break;
      case kInParenthesis:
        if (IsEOF(position, attribute_end)) {
          AppendDescriptorAndReset(attribute_start, current_descriptor_start,
                                   attribute_end, descriptors);
          return;
        }
        if (*position == ')') {
          AppendCharacter(current_descriptor_start, position);
          state = kTokenStart;
        } else {
          AppendCharacter(current_descriptor_start, position);
        }
        break;
      case kAfterToken:
        if (IsEOF(position, attribute_end))
          return;
        if (!IsHTMLSpace(*position)) {
          state = kTokenStart;
          current_descriptor_start = position;
          --position;
        }
        break;
    }
    ++position;
  }
}

static void SrcsetError(Document* document, String message) {
  if (document && document->GetFrame()) {
    StringBuilder warning_message;
    warning_message.Append("Failed parsing 'srcset' attribute value since ");
    warning_message.Append(message);
    document->GetFrame()->Console().AddMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kOther,
            mojom::ConsoleMessageLevel::kWarning, warning_message.ToString()));
  }
}

template <typename CharType>
static bool ParseDescriptors(const CharType* attribute,
                             Vector<DescriptorToken>& descriptors,
                             DescriptorParsingResult& result,
                             Document* document) {
  for (DescriptorToken& descriptor : descriptors) {
    if (descriptor.length == 0)
      continue;
    CharType c = attribute[descriptor.LastIndex()];
    bool is_valid = false;
    if (c == 'w') {
      if (result.HasDensity() || result.HasWidth()) {
        SrcsetError(document,
                    "it has multiple 'w' descriptors or a mix of 'x' and 'w' "
                    "descriptors.");
        return false;
      }
      int resource_width = descriptor.ToInt(attribute, is_valid);
      if (!is_valid || resource_width <= 0) {
        SrcsetError(document, "its 'w' descriptor is invalid.");
        return false;
      }
      result.SetResourceWidth(resource_width);
    } else if (c == 'h') {
      // This is here only for future compat purposes. The value of the 'h'
      // descriptor is not used.
      if (result.HasDensity() || result.HasHeight()) {
        SrcsetError(document,
                    "it has multiple 'h' descriptors or a mix of 'x' and 'h' "
                    "descriptors.");
        return false;
      }
      int resource_height = descriptor.ToInt(attribute, is_valid);
      if (!is_valid || resource_height <= 0) {
        SrcsetError(document, "its 'h' descriptor is invalid.");
        return false;
      }
      result.SetResourceHeight(resource_height);
    } else if (c == 'x') {
      if (result.HasDensity() || result.HasHeight() || result.HasWidth()) {
        SrcsetError(document,
                    "it has multiple 'x' descriptors or a mix of 'x' and "
                    "'w'/'h' descriptors.");
        return false;
      }
      float density = descriptor.ToFloat(attribute, is_valid);
      if (!is_valid || density < 0) {
        SrcsetError(document, "its 'x' descriptor is invalid.");
        return false;
      }
      result.SetDensity(density);
    } else {
      SrcsetError(document, "it has an unknown descriptor.");
      return false;
    }
  }
  bool res = !result.HasHeight() || result.HasWidth();
  if (!res)
    SrcsetError(document, "it has an 'h' descriptor and no 'w' descriptor.");
  return res;
}

static bool ParseDescriptors(const String& attribute,
                             Vector<DescriptorToken>& descriptors,
                             DescriptorParsingResult& result,
                             Document* document) {
  // FIXME: See if StringView can't be extended to replace DescriptorToken here.
  return WTF::VisitCharacters(attribute, [&](auto chars) {
    return ParseDescriptors(chars.data(), descriptors, result, document);
  });
}

// http://picture.responsiveimages.org/#parse-srcset-attr
template <typename CharType>
static void ParseImageCandidatesFromSrcsetAttribute(
    const String& attribute,
    const CharType* attribute_start,
    unsigned length,
    Vector<ImageCandidate>& image_candidates,
    Document* document) {
  const CharType* position = attribute_start;
  const CharType* attribute_end = position + length;

  while (position < attribute_end) {
    // 4. Splitting loop: Collect a sequence of characters that are space
    // characters or U+002C COMMA characters.
    SkipWhile<CharType, IsHTMLSpaceOrComma<CharType>>(position, attribute_end);
    if (position == attribute_end) {
      // Contrary to spec language - descriptor parsing happens on each
      // candidate, so when we reach the attributeEnd, we can exit.
      break;
    }
    const CharType* image_url_start = position;

    // 6. Collect a sequence of characters that are not space characters, and
    // let that be url.
    SkipUntil<CharType, IsHTMLSpace<CharType>>(position, attribute_end);
    const CharType* image_url_end = position;

    DescriptorParsingResult result;

    // 8. If url ends with a U+002C COMMA character (,)
    if (IsComma(*(position - 1))) {
      // Remove all trailing U+002C COMMA characters from url.
      image_url_end = position - 1;
      ReverseSkipWhile<CharType, IsComma>(image_url_end, image_url_start);
      ++image_url_end;
      // If url is empty, then jump to the step labeled splitting loop.
      if (image_url_start == image_url_end)
        continue;
    } else {
      SkipWhile<CharType, IsHTMLSpace<CharType>>(position, attribute_end);
      Vector<DescriptorToken> descriptor_tokens;
      TokenizeDescriptors(attribute_start, position, attribute_end,
                          descriptor_tokens);
      // Contrary to spec language - descriptor parsing happens on each
      // candidate. This is a black-box equivalent, to avoid storing descriptor
      // lists for each candidate.
      if (!ParseDescriptors(attribute, descriptor_tokens, result, document)) {
        if (document) {
          UseCounter::Count(document, WebFeature::kSrcsetDroppedCandidate);
          if (document->GetFrame()) {
            document->GetFrame()->Console().AddMessage(
                MakeGarbageCollected<ConsoleMessage>(
                    mojom::ConsoleMessageSource::kOther,
                    mojom::ConsoleMessageLevel::kWarning,
                    String("Dropped srcset candidate ") +
                        JSONValue::QuoteString(String(
                            base::span(image_url_start, image_url_end)))));
          }
        }
        continue;
      }
    }

    DCHECK_GT(image_url_end, attribute_start);
    unsigned image_url_starting_position =
        static_cast<unsigned>(image_url_start - attribute_start);
    DCHECK_GT(image_url_end, image_url_start);
    unsigned image_url_length =
        static_cast<unsigned>(image_url_end - image_url_start);
    image_candidates.push_back(
        ImageCandidate(attribute, image_url_starting_position, image_url_length,
                       result, ImageCandidate::kSrcsetOrigin));
    // 11. Return to the step labeled splitting loop.
  }
}

static void ParseImageCandidatesFromSrcsetAttribute(
    const String& attribute,
    Vector<ImageCandidate>& image_candidates,
    Document* document) {
  if (attribute.IsNull())
    return;

  if (attribute.Is8Bit())
    ParseImageCandidatesFromSrcsetAttribute<LChar>(
        attribute, attribute.Characters8(), attribute.length(),
        image_candidates, document);
  else
    ParseImageCandidatesFromSrcsetAttribute<UChar>(
        attribute, attribute.Characters16(), attribute.length(),
        image_candidates, document);
}

static unsigned SelectionLogic(Vector<ImageCandidate*>& image_candidates,
                               float device_scale_factor) {
  unsigned i = 0;

  for (; i < image_candidates.size() - 1; ++i) {
    unsigned next = i + 1;
    float next_density;
    float current_density;
    float geometric_mean;

    next_density = image_candidates[next]->Density();
    if (next_density < device_scale_factor)
      continue;

    current_density = image_candidates[i]->Density();
    geometric_mean = sqrt(current_density * next_density);
    if (((device_scale_factor <= 1.0) &&
         (device_scale_factor > current_density)) ||
        (device_scale_factor >= geometric_mean))
      return next;
    break;
  }
  return i;
}

static unsigned AvoidDownloadIfHigherDensityResourceIsInCache(
    Vector<ImageCandidate*>& image_candidates,
    unsigned winner,
    Document* document) {
  if (!document)
    return winner;
  for (unsigned i = image_candidates.size() - 1; i > winner; --i) {
    KURL url = document->CompleteURL(
        StripLeadingAndTrailingHTMLSpaces(image_candidates[i]->Url()));
    auto* resource = MemoryCache::Get()->ResourceForURL(
        url,
        document->Fetcher()->GetCacheIdentifier(url,
                                                /*skip_service_worker=*/false));
    if ((resource && resource->IsLoaded()) || url.ProtocolIsData()) {
      return i;
    }
  }
  return winner;
}

static ImageCandidate PickBestImageCandidate(
    float device_scale_factor,
    float source_size,
    Vector<ImageCandidate>& image_candidates,
    Document* document = nullptr) {
  const float kDefaultDensityValue = 1.0;
  // The srcset image source selection mechanism is user-agent specific:
  // https://html.spec.whatwg.org/multipage/images.html#selecting-an-image-source
  //
  // Setting max density value based on https://github.com/whatwg/html/pull/5901
  const float kMaxDensity = 2.2;
  bool ignore_src = false;
  if (image_candidates.empty())
    return ImageCandidate();

  if (RuntimeEnabledFeatures::SrcsetMaxDensityEnabled() &&
      device_scale_factor > kMaxDensity) {
    device_scale_factor = kMaxDensity;
  }

  // http://picture.responsiveimages.org/#normalize-source-densities
  for (ImageCandidate& image : image_candidates) {
    if (image.GetResourceWidth() > 0) {
      image.SetDensity((float)image.GetResourceWidth() / source_size);
      ignore_src = true;
    } else if (image.Density() < 0) {
      image.SetDensity(kDefaultDensityValue);
    }
  }

  std::stable_sort(image_candidates.begin(), image_candidates.end(),
                   CompareByDensity);

  Vector<ImageCandidate*> de_duped_image_candidates;
  float prev_density = -1.0;
  for (ImageCandidate& image : image_candidates) {
    if (image.Density() != prev_density && (!ignore_src || !image.SrcOrigin()))
      de_duped_image_candidates.push_back(&image);
    prev_density = image.Density();
  }

  unsigned winner =
      blink::WebNetworkStateNotifier::SaveDataEnabled() &&
              base::FeatureList::IsEnabled(blink::features::kSaveDataImgSrcset)
          ? 0
          : SelectionLogic(de_duped_image_candidates, device_scale_factor);
  DCHECK_LT(winner, de_duped_image_candidates.size());
  winner = AvoidDownloadIfHigherDensityResourceIsInCache(
      de_duped_image_candidates, winner, document);

  float winning_density = de_duped_image_candidates[winner]->Density();
  // 16. If an entry b in candidates has the same associated ... pixel density
  // as an earlier entry a in candidates,
  // then remove entry b
  while ((winner > 0) &&
         (de_duped_image_candidates[winner - 1]->Density() == winning_density))
    --winner;

  return *de_duped_image_candidates[winner];
}

ImageCandidate BestFitSourceForSrcsetAttribute(float device_scale_factor,
                                               float source_size,
                                               const String& srcset_attribute,
                                               Document* document) {
  Vector<ImageCandidate> image_candidates;

  ParseImageCandidatesFromSrcsetAttribute(srcset_attribute, image_candidates,
                                          document);

  return PickBestImageCandidate(device_scale_factor, source_size,
                                image_candidates, document);
}

ImageCandidate BestFitSourceForImageAttributes(float device_scale_factor,
                                               float source_size,
                                               const String& src_attribute,
                                               const String& srcset_attribute,
                                               Document* document) {
  if (srcset_attribute.IsNull()) {
    if (src_attribute.IsNull())
      return ImageCandidate();
    return ImageCandidate(src_attribute, 0, src_attribute.length(),
                          DescriptorParsingResult(),
                          ImageCandidate::kSrcOrigin);
  }

  Vector<ImageCandidate> image_candidates;

  ParseImageCandidatesFromSrcsetAttribute(srcset_attribute, image_candidates,
                                          document);

  if (!src_attribute.empty())
    image_candidates.push_back(
        ImageCandidate(src_attribute, 0, src_attribute.length(),
                       DescriptorParsingResult(), ImageCandidate::kSrcOrigin));

  return PickBestImageCandidate(device_scale_factor, source_size,
                                image_candidates, document);
}

String BestFitSourceForImageAttributes(float device_scale_factor,
                                       float source_size,
                                       const String& src_attribute,
                                       ImageCandidate& srcset_image_candidate) {
  if (srcset_image_candidate.IsEmpty())
    return src_attribute;

  Vector<ImageCandidate> image_candidates;
  image_candidates.push_back(srcset_image_candidate);

  if (!src_attribute.empty())
    image_candidates.push_back(
        ImageCandidate(src_attribute, 0, src_attribute.length(),
                       DescriptorParsingResult(), ImageCandidate::kSrcOrigin));

  return PickBestImageCandidate(device_scale_factor, source_size,
                                image_candidates)
      .ToString();
}

}  // namespace blink
```