Response:
Let's break down the thought process for analyzing the `first_letter_pseudo_element.cc` file.

1. **Understanding the Goal:** The request asks for an analysis of this specific Chromium Blink file, focusing on its functionality, relationships with web technologies (HTML, CSS, JavaScript), potential errors, debugging information, and any logical deductions.

2. **Initial Code Scan (Keywords and Structure):**  My first step is to quickly scan the code for important keywords and understand its structure. I look for:
    * `#include`:  This tells me the dependencies. I see things like `first_letter_pseudo_element.h`, `style_resolver.h`, `element.h`, `layout_object.h`, `layout_text.h`, and importantly, files from the `platform/wtf` directory (indicating foundational utilities).
    * `namespace blink`: Confirms this is Blink-specific code.
    * Class definition: `class FirstLetterPseudoElement`. This is the core of the file.
    * Public methods: I scan for public methods like `FirstLetterLength`, `FirstLetterTextLayoutObject`, `UpdateTextFragments`, `AttachLayoutTree`, `DetachLayoutTree`, `CreateLayoutObject`, `CustomStyleForLayoutObject`, `AttachFirstLetterTextLayoutObjects`, and `InnerNodeForHitTesting`. These give me high-level insights into what the class *does*.
    * Private methods/namespaces: The anonymous namespace at the top (`namespace { ... }`) suggests helper functions. I note the functions related to punctuation and finding the first inline descendant.
    * Member variables:  `remaining_text_layout_object_`. This hints at how the first-letter pseudo-element is linked to the rest of the text.
    * Copyright notices:  Standard boilerplate, but confirms the file's age and multiple contributors.

3. **Deconstructing Functionality (Method by Method):** Now I delve deeper into each public method, trying to understand its specific purpose:
    * **`FirstLetterLength`:** The name is self-explanatory. The code confirms it calculates the length of the first-letter pseudo-element, including leading punctuation and handling spaces/line breaks. The `Punctuation` enum and logic for handling it are crucial here.
    * **`FirstLetterTextLayoutObject`:**  This is clearly about finding the *actual* text node in the layout tree that contains the first letter. The code iterates through descendants, checks for specific conditions (like secure text, line breaks, nested `::first-letter`), and handles punctuation.
    * **`UpdateTextFragments`:** This suggests a process of splitting the original text node into two fragments: one for the `::first-letter` and one for the remaining text.
    * **`ClearRemainingTextLayoutObject`:**  Related to cleanup and ensuring updates happen correctly.
    * **`AttachLayoutTree` and `DetachLayoutTree`:** These are standard methods in Blink's rendering pipeline, responsible for adding and removing the `::first-letter` and the remaining text to/from the layout tree.
    * **`CreateLayoutObject`:**  Creates the actual layout object for the `::first-letter` pseudo-element.
    * **`CustomStyleForLayoutObject`:**  Handles the application of CSS styles to the `::first-letter`, potentially inheriting styles from the parent.
    * **`AttachFirstLetterTextLayoutObjects`:**  This appears to be the core function that actually creates the `LayoutTextFragment` objects for both the `::first-letter` and the remaining text.
    * **`InnerNodeForHitTesting`:**  Crucial for event handling and ensuring clicks on the `::first-letter` trigger events on the correct parent element.

4. **Connecting to Web Technologies:**  As I understand the functionality, I actively make connections to HTML, CSS, and JavaScript:
    * **CSS:** The core concept of the `::first-letter` pseudo-element is a CSS feature. I know it's used to style the first letter of a block-level element. I consider examples like `p::first-letter { font-size: 2em; }`.
    * **HTML:** The `::first-letter` applies to elements in the HTML structure. I think about how different HTML structures (paragraphs, divs with text) would be affected.
    * **JavaScript:** While this file is C++, I consider how JavaScript might indirectly interact. For instance, JavaScript manipulating the DOM could trigger updates that involve this code. JavaScript setting CSS properties would definitely influence the styling.

5. **Logical Reasoning and Assumptions:** When analyzing functions like `FirstLetterLength` and `FirstLetterTextLayoutObject`, I try to trace the logic with hypothetical inputs:
    * **Input:**  `"<p> Hello world!</p>"` and CSS `p::first-letter { ... }`. I mentally walk through how the code would identify "H" as the first letter.
    * **Input:** `"<p>  \"Hello world!</p>"` and CSS `p::first-letter { ... }`. I see how leading spaces and punctuation are handled.
    * **Input:**  A more complex nested structure with inline elements. I consider the logic for finding the "first in-flow inline descendant."

6. **Identifying Potential Errors:** Based on my understanding of the code and web development experience, I think about common mistakes:
    * **Incorrect CSS:**  Trying to apply `::first-letter` to inline elements.
    * **Unexpected HTML:**  Having non-text content before the actual text.
    * **JavaScript DOM manipulation:**  Dynamically changing content and potentially breaking the `::first-letter` logic.

7. **Debugging Information (User Operations):** I consider how a developer might end up looking at this file during debugging. This usually involves:
    * **Visual issues:** The styling of the first letter is wrong.
    * **Event handling problems:** Clicks or hovers on the first letter don't behave as expected.
    * **Performance issues:**  Layout or style recalculation related to `::first-letter` is slow. I imagine a developer inspecting the layout tree or stepping through the rendering code.

8. **Structuring the Output:** Finally, I organize my findings into a coherent structure, using headings and bullet points to address each aspect of the request. I try to use clear and concise language, providing examples where necessary. I make sure to explicitly mention the relationships with HTML, CSS, and JavaScript, and provide concrete examples of potential errors and debugging scenarios.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file directly handles the *drawing* of the first letter. **Correction:** Realized it's more about identifying and managing the *layout* and *styling* of the first letter within the rendering pipeline. The actual drawing happens later in the rendering process.
* **Focus too much on low-level details:**  Realized the request is about understanding the *functionality* and *relationships*, not a line-by-line code explanation. Shifted focus to the bigger picture.
* **Missed a key aspect:** Initially didn't emphasize the importance of the layout tree manipulation (`AttachLayoutTree`, `DetachLayoutTree`). Recognized this as a core responsibility of this class.
* **Not enough concrete examples:** Added specific CSS and HTML examples to illustrate the concepts.

By following these steps, iteratively analyzing the code, and relating it back to the broader web development context, I can generate a comprehensive and informative analysis of the `first_letter_pseudo_element.cc` file.
好的，让我们来分析一下 `blink/renderer/core/dom/first_letter_pseudo_element.cc` 这个文件。

**文件功能概述**

这个文件的核心功能是 **实现 CSS 的 `::first-letter` 伪元素**。它负责识别和创建一个特殊的布局对象，用于表示元素的首字母（或首个排版单元），并允许开发者通过 CSS 对其进行样式化。

**与 JavaScript, HTML, CSS 的关系及举例说明**

1. **CSS:**  这是该文件最直接关联的技术。
   * **功能实现:** 该文件中的代码负责实现 `::first-letter` 伪元素在 Blink 渲染引擎中的行为。它决定了哪些字符被认为是“首字母”，以及如何创建一个特殊的布局对象来应用相关的 CSS 样式。
   * **举例:** 当 CSS 规则中定义了如下样式时：
     ```css
     p::first-letter {
       font-size: 2em;
       color: red;
     }
     ```
     这个文件中的代码会找到 `<p>` 标签内的首字母，创建一个表示该首字母的布局对象，并将 `font-size: 2em;` 和 `color: red;` 这些样式应用到该布局对象上。

2. **HTML:** `::first-letter` 伪元素是应用于 HTML 元素的。
   * **应用目标:**  该文件中的逻辑需要识别 HTML 元素，特别是那些可以应用 `::first-letter` 的块级容器元素。
   * **举例:** 考虑以下 HTML 结构：
     ```html
     <p>This is a paragraph.</p>
     ```
     当浏览器渲染这个页面时，`first_letter_pseudo_element.cc` 中的代码会找到 `<p>` 元素，并识别出 "T" 是首字母。

3. **JavaScript:** JavaScript 可以间接地影响 `::first-letter` 的行为。
   * **DOM 操作:** JavaScript 可以动态地修改 HTML 结构或元素的内容。这些修改可能会触发重新渲染，并导致 `first_letter_pseudo_element.cc` 中的代码被重新执行，以找到新的首字母并应用样式。
   * **CSSOM 操作:** JavaScript 可以修改 CSS 样式，包括与 `::first-letter` 相关的样式。这些修改也会触发重新渲染，并影响首字母的显示。
   * **举例:**
     ```javascript
     // 修改段落的文本内容
     document.querySelector('p').textContent = 'New text starts here.';
     ```
     这段 JavaScript 代码执行后，浏览器会重新渲染段落，并且 `first_letter_pseudo_element.cc` 会识别出 "N" 作为新的首字母。

**逻辑推理 (假设输入与输出)**

假设输入一个包含以下 HTML 和 CSS 的文档：

**HTML:**
```html
<div>
  <p id="myParagraph"> Hello world! </p>
</div>
```

**CSS:**
```css
#myParagraph::first-letter {
  font-size: 30px;
  color: blue;
}
```

**逻辑推理过程:**

1. **解析 HTML 和 CSS:** Blink 引擎开始解析 HTML 和 CSS，构建 DOM 树和 CSSOM 树。
2. **创建布局树:** 基于 DOM 树和 CSSOM 树，Blink 创建布局树。在处理 `#myParagraph` 元素时，引擎会检查是否有针对 `::first-letter` 伪元素的样式。
3. **识别首字母:** `FirstLetterPseudoElement::FirstLetterTextLayoutObject` 函数会被调用，它会遍历 `#myParagraph` 的内容，跳过前导空格，并识别出 "H" 是首字母。
4. **创建伪元素布局对象:**  `FirstLetterPseudoElement` 类会创建一个特殊的布局对象来表示这个首字母 "H"。
5. **应用样式:**  CSS 中定义的 `font-size: 30px;` 和 `color: blue;` 会被应用到这个伪元素的布局对象上。
6. **创建文本片段:**  `AttachFirstLetterTextLayoutObjects` 函数会将原始文本分割成两个片段：一个是首字母 ("H")，另一个是剩余的文本 ("ello world!")。
7. **输出 (渲染结果):**  在浏览器中，你会看到 "Hello world!" 这段文本，其中 "H" 的字体大小是 30 像素，颜色是蓝色，而剩余的文本保持默认样式。

**用户或编程常见的使用错误及举例说明**

1. **尝试将 `::first-letter` 应用于行内元素:** `::first-letter` 只能应用于块级容器元素。如果尝试将其应用于行内元素（如 `<span>`），样式将不会生效。
   * **错误示例:**
     ```html
     <span>This is some text.</span>
     ```
     ```css
     span::first-letter {
       font-size: 2em; /* 不会生效 */
     }
     ```

2. **误解首字母的定义:**  用户可能认为只有字母才会被认为是首字母，但实际上，标点符号和一些其他字符也可能包含在内。
   * **示例:**
     ```html
     <p>"Hello world!"</p>
     ```
     如果 CSS 中定义了 `p::first-letter` 的样式，则双引号 `"` 也可能被包含在首字母中，这取决于具体的实现逻辑。代码中 `IsPunctuationForFirstLetter` 函数就体现了这一点。

3. **与 `initial-letter` 属性混淆:**  `initial-letter` 是一个 CSS 属性，用于设置首字母的下沉和大小，与 `::first-letter` 伪元素一起使用，但它们是不同的概念。用户可能会尝试直接使用 `initial-letter` 来设置样式，而忽略了 `::first-letter` 伪元素。

**用户操作是如何一步步的到达这里 (作为调试线索)**

假设开发者在调试一个关于 `::first-letter` 样式不生效的问题，他们可能会采取以下步骤：

1. **查看元素:**  使用浏览器的开发者工具（通常是 Elements 或 Inspector 标签）检查目标 HTML 元素，确认该元素是否是块级容器。
2. **检查 CSS 规则:**  在开发者工具的 Styles 或 Computed 标签中查看应用于该元素的 CSS 规则，确认是否定义了针对 `::first-letter` 的样式。
3. **查看伪元素:**  在开发者工具中，展开元素的节点，查看是否存在 `::first-letter` 伪元素。如果没有，可能是因为该元素不符合应用 `::first-letter` 的条件，或者引擎在识别首字母时遇到了问题。
4. **断点调试 (C++):**  如果开发者需要深入了解 Blink 引擎的内部行为，他们可能会在 `first_letter_pseudo_element.cc` 文件中的关键函数（如 `FirstLetterTextLayoutObject` 或 `AttachFirstLetterTextLayoutObjects`) 设置断点。
5. **重现问题:**  开发者会在浏览器中执行导致 `::first-letter` 样式问题的用户操作，例如加载包含特定 HTML 和 CSS 的页面，或者通过 JavaScript 动态修改内容。
6. **单步执行代码:** 当断点命中时，开发者可以单步执行代码，查看变量的值，了解引擎是如何识别首字母、创建布局对象以及应用样式的。
7. **分析调用堆栈:**  查看调用堆栈可以帮助开发者理解 `first_letter_pseudo_element.cc` 中的代码是如何被调用的，以及与哪些其他 Blink 组件交互。
8. **检查日志输出:**  Blink 引擎可能会输出相关的日志信息，帮助开发者诊断问题。

**总结**

`blink/renderer/core/dom/first_letter_pseudo_element.cc` 文件是 Chromium Blink 渲染引擎中实现 CSS `::first-letter` 伪元素的核心组件。它负责识别首字母，创建相应的布局对象，并应用相关的 CSS 样式。理解这个文件的功能对于理解浏览器如何渲染带有 `::first-letter` 样式的网页至关重要，并且在调试相关问题时提供重要的线索。

### 提示词
```
这是目录为blink/renderer/core/dom/first_letter_pseudo_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2007 David Smith (catfish.man@gmail.com)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc.
 * All rights reserved.
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
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

#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"

#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_request.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/layout/generated_children.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// CSS 2.1 http://www.w3.org/TR/CSS21/selector.html#first-letter "Punctuation
// (i.e, characters defined in Unicode [UNICODE] in the "open" (Ps), "close"
// (Pe), "initial" (Pi). "final" (Pf) and "other" (Po) punctuation classes),
// that precedes or follows the first letter should be included"
inline bool IsPunctuationForFirstLetter(UChar32 c) {
  WTF::unicode::CharCategory char_category = WTF::unicode::Category(c);
  return char_category == WTF::unicode::kPunctuation_Open ||
         char_category == WTF::unicode::kPunctuation_Close ||
         char_category == WTF::unicode::kPunctuation_InitialQuote ||
         char_category == WTF::unicode::kPunctuation_FinalQuote ||
         char_category == WTF::unicode::kPunctuation_Other;
}

bool IsPunctuationForFirstLetter(const String& string, unsigned offset) {
  return IsPunctuationForFirstLetter(*StringView(string, offset).begin());
}

inline bool IsNewLine(UChar c) {
  if (c == 0xA || c == 0xD) {
    return true;
  }

  return false;
}

inline bool IsSpace(UChar c) {
  if (IsNewLine(c)) {
    return false;
  }

  return IsSpaceOrNewline(c);
}

inline bool IsSpaceForFirstLetter(UChar c, bool preserve_breaks) {
  return (preserve_breaks ? IsSpace(c) : IsSpaceOrNewline(c)) ||
         c == WTF::unicode::kNoBreakSpaceCharacter;
}

bool IsParentInlineLayoutObject(const LayoutObject* layout_object) {
  return layout_object && IsA<LayoutInline>(layout_object->Parent());
}

}  // namespace

unsigned FirstLetterPseudoElement::FirstLetterLength(const String& text,
                                                     bool preserve_breaks,
                                                     Punctuation& punctuation) {
  DCHECK_NE(punctuation, Punctuation::kDisallow);

  unsigned length = 0;
  unsigned text_length = text.length();

  if (text_length == 0) {
    return length;
  }

  // Account for leading spaces first. If there is leading punctuation from a
  // different text node, spaces can not appear in between to form valid
  // ::first-letter text.
  if (punctuation == Punctuation::kNotSeen) {
    while (length < text_length &&
           IsSpaceForFirstLetter(text[length], preserve_breaks)) {
      length++;
    }
    if (length == text_length) {
      // Only contains spaces.
      return 0;
    }
  }

  unsigned punctuation_start = length;
  // Now account for leading punctuation.
  while (length < text_length && IsPunctuationForFirstLetter(text, length)) {
    length += LengthOfGraphemeCluster(text, length);
  }

  if (length == text_length) {
    if (length > punctuation_start) {
      // Text ends at allowed leading punctuation. Signal that we may continue
      // looking for ::first-letter text in the next text node, including more
      // punctuation.
      punctuation = Punctuation::kSeen;
      return length;
    }
  }

  // Stop allowing leading punctuation.
  punctuation = Punctuation::kDisallow;

  DCHECK_LT(length, text_length);
  if (IsSpaceForFirstLetter(text[length], preserve_breaks) ||
      IsNewLine(text[length])) {
    return 0;
  }

  // Account the next character for first letter.
  length += LengthOfGraphemeCluster(text, length);

  // Keep looking for allowed punctuation for the ::first-letter within the same
  // text node. We are allowed to ignore trailing punctuation in following text
  // nodes per spec.
  unsigned num_code_units = 0;
  for (; length < text_length; length += num_code_units) {
    if (!IsPunctuationForFirstLetter(text, length)) {
      break;
    }
    num_code_units = LengthOfGraphemeCluster(text, length);
  }
  return length;
}

void FirstLetterPseudoElement::Trace(Visitor* visitor) const {
  visitor->Trace(remaining_text_layout_object_);
  PseudoElement::Trace(visitor);
}

namespace {

LayoutObject* FirstInFlowInlineDescendantForFirstLetter(LayoutObject& parent) {
  // https://drafts.csswg.org/css-pseudo/#first-text-line:
  //
  // - The first formatted line of a block container that establishes an inline
  //   formatting context represents the inline-level content of its first line
  //   box.
  // - The first formatted line of a block container or multi-column container
  //   that contains block-level content (and is not a table wrapper box) is the
  //   first formatted line of its first in-flow block-level child. If no such
  //   line exists, it has no first formatted line.
  LayoutObject* first_inline = parent.SlowFirstChild();

  while (first_inline) {
    if (first_inline->IsFloatingOrOutOfFlowPositioned()) {
      first_inline = first_inline->NextSibling();
      continue;
    }
    if (first_inline->IsListMarker()) {
      LayoutObject* list_item = first_inline;
      while (list_item && !list_item->IsLayoutListItem()) {
        DCHECK_NE(list_item, &parent);
        list_item = list_item->Parent();
      }
      // Skip the marker contents, but don't escape the list item.
      first_inline = first_inline->NextInPreOrderAfterChildren(list_item);
      continue;
    }
    if (first_inline->IsInline()) {
      return first_inline;
    }
    if (!first_inline->BehavesLikeBlockContainer()) {
      // Block level in-flow displays like flex, grid, and table do not have a
      // first formatted line.
      return nullptr;
    }
    if (first_inline->IsButtonOrInputButton()) {
      // Buttons do not accept the first-letter.
      return nullptr;
    }
    if (first_inline->StyleRef().HasPseudoElementStyle(kPseudoIdFirstLetter)) {
      // Applying ::first-letter styles from multiple nested containers is not
      // supported. ::first-letter styles from the inner-most container is
      // applied - bail out.
      return nullptr;
    }
    first_inline = first_inline->SlowFirstChild();
  }
  return nullptr;
}

}  // namespace

LayoutText* FirstLetterPseudoElement::FirstLetterTextLayoutObject(
    const Element& element) {
  LayoutObject* parent_layout_object = nullptr;

  if (element.IsFirstLetterPseudoElement()) {
    // If the passed-in element is a ::first-letter pseudo element we need to
    // start from the originating element.
    parent_layout_object =
        element.ParentOrShadowHostElement()->GetLayoutObject();
  } else {
    parent_layout_object = element.GetLayoutObject();
  }

  if (!parent_layout_object ||
      !parent_layout_object->StyleRef().HasPseudoElementStyle(
          kPseudoIdFirstLetter) ||
      !CanHaveGeneratedChildren(*parent_layout_object) ||
      !parent_layout_object->BehavesLikeBlockContainer()) {
    // This element can not have a styleable ::first-letter.
    return nullptr;
  }

  LayoutObject* inline_child =
      FirstInFlowInlineDescendantForFirstLetter(*parent_layout_object);
  if (!inline_child) {
    return nullptr;
  }

  LayoutObject* stay_inside = inline_child->Parent();
  LayoutText* punctuation_text = nullptr;
  Punctuation punctuation = Punctuation::kNotSeen;

  while (inline_child) {
    if (inline_child->StyleRef().StyleType() == kPseudoIdFirstLetter) {
      // This can be called when the ::first-letter LayoutObject is already in
      // the tree. We do not want to consider that LayoutObject for our text
      // LayoutObject so we go to the sibling (which is the LayoutTextFragment
      // for the remaining text).
      inline_child = inline_child->NextSibling();
    } else if (inline_child->IsListMarker()) {
      inline_child = inline_child->NextInPreOrderAfterChildren(stay_inside);
    } else if (inline_child->IsInline()) {
      if (auto* layout_text = DynamicTo<LayoutText>(inline_child)) {
        // Don't apply first letter styling to passwords and other elements
        // obfuscated by -webkit-text-security. Also, see
        // ShouldUpdateLayoutByReattaching() in text.cc.
        if (layout_text->IsSecure()) {
          return nullptr;
        }
        if (layout_text->IsBR() || layout_text->IsWordBreak()) {
          return nullptr;
        }
        String str = layout_text->IsTextFragment()
                         ? To<LayoutTextFragment>(inline_child)->CompleteText()
                         : layout_text->OriginalText();
        bool preserve_breaks = ShouldPreserveBreaks(
            inline_child->StyleRef().GetWhiteSpaceCollapse());

        if (FirstLetterLength(str, preserve_breaks, punctuation)) {
          // A prefix, or the whole text for the current layout_text is
          // included in the valid ::first-letter text.

          if (punctuation == Punctuation::kSeen) {
            // So far, we have only seen punctuation. Need to continue looking
            // for a typographic character unit to go along with the
            // punctuation.
            if (!punctuation_text) {
              punctuation_text = layout_text;
            }
          } else {
            // We have found valid ::first-letter text. When the ::first-letter
            // text spans multiple elements, the UA is free to style only one of
            // the elements, all of the elements, or none of the elements. Here
            // we choose to return the first, which matches the Firefox
            // behavior.
            if (punctuation_text) {
              return punctuation_text;
            } else {
              return layout_text;
            }
          }
        } else if (punctuation == Punctuation::kDisallow) {
          // No ::first-letter text seen in this text node. Non-null
          // punctuation_text means we have seen punctuation in a previous text
          // node, but leading_punctuation was reset to false as we encountered
          // spaces or other content that is neither punctuation nor a valid
          // typographic character unit for ::first-letter.
          return nullptr;
        }
      } else if (inline_child->IsAtomicInlineLevel() ||
                 inline_child->IsMenuList()) {
        return nullptr;
      }
      inline_child = inline_child->NextInPreOrder(stay_inside);
    } else if (inline_child->IsFloatingOrOutOfFlowPositioned()) {
      if (inline_child->StyleRef().StyleType() == kPseudoIdFirstLetter) {
        inline_child = inline_child->SlowFirstChild();
      } else {
        inline_child = inline_child->NextInPreOrderAfterChildren(stay_inside);
      }
    } else {
      return nullptr;
    }
  }
  return nullptr;
}

FirstLetterPseudoElement::FirstLetterPseudoElement(Element* parent)
    : PseudoElement(parent, kPseudoIdFirstLetter),
      remaining_text_layout_object_(nullptr) {}

FirstLetterPseudoElement::~FirstLetterPseudoElement() {
  DCHECK(!remaining_text_layout_object_);
}

void FirstLetterPseudoElement::UpdateTextFragments() {
  String old_text(remaining_text_layout_object_->CompleteText());
  DCHECK(old_text.Impl());

  bool preserve_breaks = ShouldPreserveBreaks(
      remaining_text_layout_object_->StyleRef().GetWhiteSpaceCollapse());
  FirstLetterPseudoElement::Punctuation punctuation =
      FirstLetterPseudoElement::Punctuation::kNotSeen;
  unsigned length = FirstLetterPseudoElement::FirstLetterLength(
      old_text, preserve_breaks, punctuation);
  remaining_text_layout_object_->SetTextFragment(
      old_text.Impl()->Substring(length, old_text.length()), length,
      old_text.length() - length);
  remaining_text_layout_object_->InvalidateInlineItems();

  for (auto* child = GetLayoutObject()->SlowFirstChild(); child;
       child = child->NextSibling()) {
    if (!child->IsText() || !To<LayoutText>(child)->IsTextFragment())
      continue;
    auto* child_fragment = To<LayoutTextFragment>(child);
    if (child_fragment->GetFirstLetterPseudoElement() != this)
      continue;

    child_fragment->SetTextFragment(old_text.Impl()->Substring(0, length), 0,
                                    length);
    child_fragment->InvalidateInlineItems();

    // Make sure the first-letter layoutObject is set to require a layout as it
    // needs to re-create the line boxes. The remaining text layoutObject
    // will be marked by the LayoutText::setText.
    child_fragment->SetNeedsLayoutAndIntrinsicWidthsRecalc(
        layout_invalidation_reason::kTextChanged);
    break;
  }
}

void FirstLetterPseudoElement::ClearRemainingTextLayoutObject() {
  DCHECK(remaining_text_layout_object_);
  remaining_text_layout_object_ = nullptr;

  if (GetDocument().InStyleRecalc()) {
    // UpdateFirstLetterPseudoElement will handle remaining_text_layout_object_
    // changes during style recalc and layout tree rebuild.
    return;
  }

  // When we remove nodes from the tree, we do not mark ancestry for
  // ChildNeedsStyleRecalc(). When removing the text node which contains the
  // first letter, we need to UpdateFirstLetter to render the new first letter
  // or remove the ::first-letter pseudo if there is no text left. Do that as
  // part of a style recalc for this ::first-letter.
  SetNeedsStyleRecalc(
      kLocalStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kPseudoClass));
}

void FirstLetterPseudoElement::AttachLayoutTree(AttachContext& context) {
  LayoutText* first_letter_text =
      FirstLetterPseudoElement::FirstLetterTextLayoutObject(*this);
  // The FirstLetterPseudoElement should have been removed in
  // Element::UpdateFirstLetterPseudoElement(). However if there existed a first
  // letter before updating it, the layout tree will be different after
  // DetachLayoutTree() called right before this method.
  // If there is a bug in FirstLetterTextLayoutObject(), we might end up with
  // null here. DCHECKing here, but handling the null pointer below to avoid
  // crashes.
  DCHECK(first_letter_text);

  AttachContext first_letter_context(context);
  first_letter_context.next_sibling = first_letter_text;
  first_letter_context.next_sibling_valid = true;
  if (first_letter_text) {
    first_letter_context.parent = first_letter_text->Parent();
  }
  PseudoElement::AttachLayoutTree(first_letter_context);
  if (first_letter_text)
    AttachFirstLetterTextLayoutObjects(first_letter_text);
}

void FirstLetterPseudoElement::DetachLayoutTree(bool performing_reattach) {
  if (remaining_text_layout_object_) {
    if (remaining_text_layout_object_->GetNode() && GetDocument().IsActive()) {
      auto* text_node = To<Text>(remaining_text_layout_object_->GetNode());
      remaining_text_layout_object_->SetTextFragment(
          text_node->data(), 0, text_node->data().length());
    }
    remaining_text_layout_object_->SetFirstLetterPseudoElement(nullptr);
    remaining_text_layout_object_->SetIsRemainingTextLayoutObject(false);
  }
  remaining_text_layout_object_ = nullptr;

  PseudoElement::DetachLayoutTree(performing_reattach);
}

LayoutObject* FirstLetterPseudoElement::CreateLayoutObject(
    const ComputedStyle& style) {
  if (!style.InitialLetter().IsNormal()) [[unlikely]] {
    return LayoutObject::CreateBlockFlowOrListItem(this, style);
  }

  return PseudoElement::CreateLayoutObject(style);
}

const ComputedStyle* FirstLetterPseudoElement::CustomStyleForLayoutObject(
    const StyleRecalcContext& style_recalc_context) {
  LayoutObject* first_letter_text =
      FirstLetterPseudoElement::FirstLetterTextLayoutObject(*this);
  if (!first_letter_text)
    return nullptr;
  DCHECK(first_letter_text->Parent());
  return ParentOrShadowHostElement()->StyleForPseudoElement(
      style_recalc_context,
      StyleRequest(GetPseudoId(),
                   first_letter_text->Parent()->FirstLineStyle()));
}

void FirstLetterPseudoElement::AttachFirstLetterTextLayoutObjects(
    LayoutText* first_letter_text) {
  DCHECK(first_letter_text);

  // The original string is going to be either a generated content string or a
  // DOM node's string. We want the original string before it got transformed in
  // case first-letter has no text-transform or a different text-transform
  // applied to it.
  String old_text =
      first_letter_text->IsTextFragment()
          ? To<LayoutTextFragment>(first_letter_text)->CompleteText()
          : first_letter_text->OriginalText();
  DCHECK(old_text.Impl());

  // FIXME: This would already have been calculated in firstLetterLayoutObject.
  // Can we pass the length through?
  bool preserve_breaks = ShouldPreserveBreaks(
      first_letter_text->StyleRef().GetWhiteSpaceCollapse());
  FirstLetterPseudoElement::Punctuation punctuation =
      FirstLetterPseudoElement::Punctuation::kNotSeen;
  unsigned length = FirstLetterPseudoElement::FirstLetterLength(
      old_text, preserve_breaks, punctuation);

  // In case of inline level content made of punctuation, we use
  // the whole text length instead of FirstLetterLength.
  if (IsParentInlineLayoutObject(first_letter_text) && length == 0 &&
      old_text.length()) {
    length = old_text.length();
  }

  unsigned remaining_length = old_text.length() - length;

  // Construct a text fragment for the text after the first letter.
  // This text fragment might be empty.
  LayoutTextFragment* remaining_text;

  if (first_letter_text->GetNode()) {
    remaining_text =
        LayoutTextFragment::Create(first_letter_text->GetNode(),
                                   old_text.Impl(), length, remaining_length);
  } else {
    remaining_text = LayoutTextFragment::CreateAnonymous(
        GetDocument(), old_text.Impl(), length, remaining_length);
  }

  remaining_text->SetFirstLetterPseudoElement(this);
  remaining_text->SetIsRemainingTextLayoutObject(true);
  remaining_text->SetStyle(first_letter_text->Style());

  if (remaining_text->GetNode())
    remaining_text->GetNode()->SetLayoutObject(remaining_text);

  remaining_text_layout_object_ = remaining_text;

  LayoutObject* next_sibling = GetLayoutObject()->NextSibling();
  GetLayoutObject()->Parent()->AddChild(remaining_text, next_sibling);

  // Construct text fragment for the first letter.
  const ComputedStyle* const letter_style = GetComputedStyle();
  LayoutTextFragment* letter = LayoutTextFragment::CreateAnonymous(
      GetDocument(), old_text.Impl(), 0, length);
  letter->SetFirstLetterPseudoElement(this);
  if (GetLayoutObject()->IsInitialLetterBox()) [[unlikely]] {
    const LayoutBlock& paragraph = *GetLayoutObject()->ContainingBlock();
    // TODO(crbug.com/1393280): Once we can store used font somewhere, we should
    // compute initial-letter font during layout to take proper effective style.
    const ComputedStyle& paragraph_style =
        paragraph.EffectiveStyle(StyleVariant::kFirstLine);
    const ComputedStyle* initial_letter_text_style =
        GetDocument().GetStyleResolver().StyleForInitialLetterText(
            *letter_style, paragraph_style);
    letter->SetStyle(std::move(initial_letter_text_style));
  } else {
    letter->SetStyle(letter_style);
  }
  GetLayoutObject()->AddChild(letter);

  // AXObjects are normally removed from destroyed layout objects in
  // Node::DetachLayoutTree(), but as the ::first-letter implementation manually
  // destroys the layout object for the first letter text, it must manually
  // remove the accessibility object for it as well.
  if (auto* cache = GetDocument().ExistingAXObjectCache()) {
    cache->RemoveAXObjectsInLayoutSubtree(first_letter_text);
  }
  first_letter_text->Destroy();
}

Node* FirstLetterPseudoElement::InnerNodeForHitTesting() {
  // When we hit a first letter during hit testing, hover state and events
  // should be triggered on the parent of the real text node where the first
  // letter is taken from. The first letter may not come from a real node - for
  // quotes and generated text in ::before/::after. In that case walk up the
  // layout tree to find the closest ancestor which is not anonymous. Note that
  // display:contents will not be skipped since we generate anonymous
  // LayoutInline boxes for ::before/::after with display:contents.
  DCHECK(remaining_text_layout_object_);
  LayoutObject* layout_object = remaining_text_layout_object_;
  while (layout_object->IsAnonymous()) {
    layout_object = layout_object->Parent();
    DCHECK(layout_object);
  }
  Node* node = layout_object->GetNode();
  DCHECK(node);
  if (layout_object == remaining_text_layout_object_) {
    // The text containing the first-letter is a real node, return its flat tree
    // parent. If we used the layout tree parent, we would have incorrectly
    // skipped display:contents ancestors.
    return FlatTreeTraversal::Parent(*node);
  }
  if (node->IsPseudoElement()) {
    // ::first-letter in generated content for ::before/::after. Use pseudo
    // element parent.
    return node->ParentOrShadowHostNode();
  }
  return node;
}

}  // namespace blink
```