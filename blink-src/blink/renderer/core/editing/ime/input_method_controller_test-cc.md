Response:
The user wants to understand the functionality of the `input_method_controller_test.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and explain its purpose.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name strongly suggests it's a test file for `InputMethodController`. Tests generally verify the behavior of a component.

2. **Examine included headers:** The headers provide clues about what aspects of `InputMethodController` are being tested. Keywords like `editing`, `ime`, `dom`, `events`, `html`, and `frame` are important.

3. **Analyze the test fixture:** The `InputMethodControllerTest` class inherits from `EditingTestBase`, indicating it's setting up an environment for editing-related tests. The helper methods within the fixture (`Controller()`, `GetCompositionRange()`, `InsertHTMLElement()`, `CreateHTMLWithCompositionInputEventListeners()`, `CreateHTMLWithCompositionEndEventListener()`) provide insights into the test scenarios.

4. **Examine the individual tests:**  The `TEST_F` macros define individual test cases. Their names (e.g., `BackspaceFromEndOfInput`, `SetCompositionFromExistingText`) clearly indicate the specific functionalities of `InputMethodController` being tested.

5. **Relate to web technologies (JavaScript, HTML, CSS):**  Consider how the tested functionalities interact with web standards. For example, IME input directly affects how users enter text in HTML elements, and JavaScript event listeners can observe and manipulate this process.

6. **Consider logical reasoning:** Some tests might involve comparing expected outcomes with actual behavior. I need to identify these and potentially provide examples of input and output.

7. **Identify potential user/programming errors:**  Think about common mistakes developers might make when working with IME or text input, and how the tests might be designed to catch these errors.

8. **Trace user actions:** Consider the steps a user might take in a browser that would trigger the code being tested. IME input is the primary driver here.

9. **Summarize the functionality:** Based on the analysis, provide a concise overview of the file's purpose.

**High-Level Plan:**

* State that the file contains tests for `InputMethodController`.
* List the core functionalities being tested based on the `TEST_F` names and helper functions.
* Explain the relationship to JavaScript, HTML, and CSS with examples.
* Provide examples of logical reasoning (input/output).
* Give examples of common user/programming errors.
* Describe the user actions that lead to this code.
* Summarize the file's function.

**Detailed Analysis of the Provided Snippet:**

* **Headers:**  Indicate the test focuses on IME functionality, DOM manipulation, event handling, and interactions with HTML elements like input fields and contenteditable divs.
* **`InputMethodControllerTest` fixture:**  Provides helper methods to create HTML, focus elements, and access the `InputMethodController`. The methods for setting up event listeners are particularly relevant for testing IME behavior in conjunction with JavaScript.
* **`BackspaceFromEndOfInput`:** Tests how backspace works in input fields at the end of the text.
* **`SetCompositionFromExistingText`:** Tests setting IME composition based on existing text content.
* **`AddImeTextSpansToExistingText` and `AddGrammarCheckSpans`:** Test adding visual indicators (spans) related to IME input, including grammar and spelling suggestions.
* **`GetImeTextSpans`:** Tests retrieving the information about the active IME text spans.
* **`SetCompositionAfterEmoji` and `SetCompositionWithGraphemeCluster`:** Test handling of complex characters like emojis and grapheme clusters during IME composition.
* **`SetCompositionKeepingStyle` and `SetCompositionWithEmojiKeepingStyle`:** Test that IME composition maintains existing text styles.
* **`FinishComposingTextKeepingStyle` and `CommitTextKeepingStyle`:** Test the finalization of IME input and ensuring styles are preserved.
* **`InsertTextWithNewLine` and `InsertTextWithNewLineIncrementally`:** Test how newlines are handled during IME input.
* **`SelectionOnConfirmExistingText`:** Tests the selection state after confirming IME input on existing text.
* **`DeleteBySettingEmptyComposition`:** Tests deleting text by setting an empty composition.
* **`SetCompositionFromExistingTextWithCollapsedWhiteSpace`:** Tests handling of whitespace during IME composition.
* **`SetCompositionFromExistingTextWithInvalidOffsets`:** Tests error handling for invalid offset ranges.
* **`ConfirmPasswordComposition`:** Tests IME input in password fields.
* **`DeleteSurroundingText...`:** Tests the `DeleteSurroundingText` functionality with various selection states.

Now I can generate the response.
好的，让我们来分析一下 `blink/renderer/core/editing/ime/input_method_controller_test.cc` 这个文件的功能。

**核心功能:**

这个文件主要用于测试 Blink 渲染引擎中 `InputMethodController` 类的各项功能。`InputMethodController` 负责处理输入法相关的逻辑，例如：

* **IME (Input Method Editor) 输入:**  处理用户通过输入法进行的输入，包括拼音输入、日语假名输入等。
* **文本组合 (Composition):**  在用户完成输入之前，临时显示正在输入的文本（例如，输入拼音时的候选词）。
* **光标和选区管理:**  管理输入过程中的光标位置和选区变化。
* **文本的提交和删除:**  将最终的输入文本提交到文档中，以及处理删除操作。
* **文本样式保持:**  在输入过程中尽量保持原有的文本样式。
* **事件处理:**  响应与输入法相关的事件，例如 `compositionstart`、`compositionupdate`、`compositionend` 等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`InputMethodController` 的功能直接关系到用户在网页中通过输入法进行文本输入时的体验。因此，它与 JavaScript、HTML 有着密切的联系：

1. **HTML 元素:**  `InputMethodController` 作用于可编辑的 HTML 元素，例如 `<input>`、`<textarea>` 以及设置了 `contenteditable` 属性的 `<div>` 等元素。测试文件中可以看到创建和操作这些元素的例子：

   ```c++
   InsertHTMLElement("<input id='sample'>", "sample"); // 创建一个 input 元素
   InsertHTMLElement("<div id='sample' contenteditable></div>", "sample"); // 创建一个可编辑的 div 元素
   ```

2. **JavaScript 事件:**  JavaScript 可以监听与输入法相关的事件，并对这些事件进行处理。测试文件中模拟了这些事件的交互，并验证了 `InputMethodController` 的行为。例如，测试了 `beforeinput`、`input` 和 `compositionend` 事件：

   ```c++
   void CreateHTMLWithCompositionInputEventListeners() {
     // ... 省略 ...
     script->setInnerHTML(
         "document.getElementById('sample').addEventListener('beforeinput', ...);"
         "document.getElementById('sample').addEventListener('input', ...);"
         "document.getElementById('sample').addEventListener('compositionend', ...);");
     // ... 省略 ...
   }
   ```

   * **`beforeinput` 事件:** 在文本被修改之前触发，可以用来获取即将发生的修改信息。测试中检查了 `event.data`（要插入的数据）和 `event.getTargetRanges()`（受影响的文本范围）。
     * **假设输入:** 用户在可编辑的 `<div>` 中输入拼音 "zhong"。
     * **输出 (测试标题):** `beforeinput.data:z;beforeinput.targetRanges:0-0;` (假设第一次输入 'z')
   * **`input` 事件:** 在文本被修改之后触发。测试中检查了 `event.data`。
     * **假设输入:** 用户输入拼音 "zhong" 后按下空格键确认输入 "中"。
     * **输出 (测试标题):** `input.data:中;`
   * **`compositionend` 事件:**  在输入法完成文本组合（例如，用户选择了最终的汉字）时触发。测试中检查了 `event.data`。
     * **假设输入:** 用户输入拼音 "zhong" 并最终输入 "中"。
     * **输出 (测试标题):** `compositionend.data:中;`

3. **CSS 样式:**  虽然 `InputMethodController` 本身不直接处理 CSS，但它在处理文本时需要考虑到文本的样式。例如，在进行文本替换或删除时，需要尽量保持原有的样式。测试文件中部分用例涉及到带有样式的 HTML 结构，例如：

   ```c++
   InsertHTMLElement(
       "<div id='sample' "
       "contenteditable>abc1<b>2</b>34567<b>8</b>9d<b>e</b>f</div>",
       "sample");
   ```
   这些测试验证了在进行 IME 操作时，`InputMethodController` 是否能正确地保持 `<b>` 标签等样式。

**逻辑推理举例 (基于测试用例):**

* **测试用例:** `BackspaceFromEndOfInput`
  * **假设输入:**  一个 `<input>` 元素的值为 "fooX"，光标在末尾。
  * **操作:** 调用 `Controller().ExtendSelectionAndDelete(1, 0)`，模拟按下 Backspace 键。
  * **预期输出:** `<input>` 元素的值变为 "foo"。
  * **逻辑:**  `ExtendSelectionAndDelete(1, 0)` 表示向左扩展选区一个字符并删除，模拟了 Backspace 的行为。

* **测试用例:** `SetCompositionFromExistingText`
  * **假设输入:**  一个 `contenteditable` 的 `<div>` 元素包含文本 "hello world"。
  * **操作:** 调用 `Controller().SetCompositionFromExistingText(ime_text_spans, 0, 5)`，设置前 5 个字符为组合文本。
  * **预期输出:**  `GetCompositionRange()` 返回的 Range 对象指向 "hello" 这部分文本。
  * **逻辑:**  该函数旨在将已存在的文本标记为正在通过 IME 输入的组合文本，以便进行后续的输入操作。

**用户或编程常见的使用错误举例:**

* **编程错误:**  开发者可能错误地计算了 IME 组合文本的起始和结束位置，导致 `SetCompositionFromExistingText` 等函数传入错误的参数。测试用例 `SetCompositionFromExistingTextWithInvalidOffsets` 就是为了检测这种情况。如果传入的偏移量超出了文本范围，`GetCompositionRange()` 应该返回空指针，表示操作失败。
* **用户错误 (间接体现):** 虽然测试代码不直接模拟用户错误，但某些测试用例覆盖了用户在输入过程中可能遇到的情况，例如在输入一半时进行删除或修改。`BackspaceFromEndOfInput` 和 `DeleteSurroundingTextWithCursorSelection` 等用例间接地覆盖了这些场景。

**用户操作到达这里的步骤 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **网页包含一个可编辑的元素 (例如 `<input>`, `<textarea>`, 或 `contenteditable` 元素)。**
3. **用户点击该元素，激活输入焦点。**
4. **用户开始使用输入法进行输入 (例如，输入拼音或日语假名)。**
5. **当用户输入字符、选择候选词、或者完成输入时，浏览器底层的 IME 系统会与 Blink 引擎进行交互。**
6. **Blink 引擎的 `InputMethodController` 接收到来自 IME 系统的事件和数据。**
7. **`InputMethodController` 根据接收到的信息更新文档的内容、光标位置、以及组合文本的状态。**

**作为调试线索:** 如果在用户使用输入法输入时出现异常行为（例如，输入错误、光标位置不正确、样式丢失等），开发者可能会查看 `InputMethodController` 相关的代码和测试用例，以理解输入法处理的流程，并找到潜在的 bug 来源。测试用例可以帮助开发者重现问题场景，并验证修复方案的正确性。

**文件功能归纳 (第 1 部分):**

这个 `input_method_controller_test.cc` 文件的主要功能是为 Blink 渲染引擎的 `InputMethodController` 类提供单元测试。这些测试覆盖了 `InputMethodController` 在处理各种输入法操作时的行为，包括文本组合、提交、删除、光标管理以及与 JavaScript 事件的交互。通过这些测试，可以确保 `InputMethodController` 的功能正确可靠，从而保证用户在网页上使用输入法进行文本输入的良好体验。

Prompt: 
```
这是目录为blink/renderer/core/editing/ime/input_method_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"

#include <memory>
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"

using ui::mojom::ImeTextSpanThickness;
using ui::mojom::ImeTextSpanUnderlineStyle;

namespace blink {

class InputMethodControllerTest : public EditingTestBase {
 protected:
  enum SelectionType { kNoSelection, kCaretSelection, kRangeSelection };

  InputMethodController& Controller() {
    return GetFrame().GetInputMethodController();
  }

  // TODO(editing-dev): We should use |CompositionEphemeralRange()| instead
  // of having |GetCompositionRange()| and marking |InputMethodControllerTest|
  // as friend class.
  Range* GetCompositionRange() { return Controller().composition_range_.Get(); }

  Element* InsertHTMLElement(const char* element_code, const char* element_id);
  void CreateHTMLWithCompositionInputEventListeners();
  void CreateHTMLWithCompositionEndEventListener(const SelectionType);
};

Element* InputMethodControllerTest::InsertHTMLElement(const char* element_code,
                                                      const char* element_id) {
  GetDocument().write(element_code);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Element* element = GetElementById(element_id);
  element->Focus();
  return element;
}

void InputMethodControllerTest::CreateHTMLWithCompositionInputEventListeners() {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* editable =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.getElementById('sample').addEventListener('beforeinput', "
      "event => {"
      "  document.title = `beforeinput.data:${event.data};`;"
      "  document.title += 'beforeinput.targetRanges:';"
      "  const range = event.getTargetRanges()[0];"
      "  if (range !== undefined) {"
      "    document.title += `${range.startOffset}-${range.endOffset};`;"
      "  } else document.title += ';';"
      "});"
      "document.getElementById('sample').addEventListener('input', "
      "  event => document.title += `input.data:${event.data};`);"
      "document.getElementById('sample').addEventListener('compositionend', "
      "  event => document.title += `compositionend.data:${event.data};`);");
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();
  editable->Focus();
}

void InputMethodControllerTest::CreateHTMLWithCompositionEndEventListener(
    const SelectionType type) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* editable =
      InsertHTMLElement("<div id='sample' contentEditable></div>", "sample");
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);

  switch (type) {
    case kNoSelection:
      script->setInnerHTML(
          // If the caret position is set before firing 'compositonend' event
          // (and it should), the final caret position will be reset to null.
          "document.getElementById('sample').addEventListener('compositionend',"
          "  event => getSelection().removeAllRanges());");
      break;
    case kCaretSelection:
      script->setInnerHTML(
          // If the caret position is set before firing 'compositonend' event
          // (and it should), the final caret position will be reset to [3,3].
          "document.getElementById('sample').addEventListener('compositionend',"
          "  event => {"
          "    const node = document.getElementById('sample').firstChild;"
          "    getSelection().collapse(node, 3);"
          "});");
      break;
    case kRangeSelection:
      script->setInnerHTML(
          // If the caret position is set before firing 'compositonend' event
          // (and it should), the final caret position will be reset to [2,4].
          "document.getElementById('sample').addEventListener('compositionend',"
          "  event => {"
          "    const node = document.getElementById('sample').firstChild;"
          "    const selection = getSelection();"
          "    selection.collapse(node, 2);"
          "    selection.extend(node, 4);"
          "});");
      break;
    default:
      NOTREACHED();
  }
  GetDocument().body()->AppendChild(script);
  UpdateAllLifecyclePhasesForTest();
  editable->Focus();
}

TEST_F(InputMethodControllerTest, BackspaceFromEndOfInput) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  input->SetValue("fooX");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("fooX", input->Value());
  Controller().ExtendSelectionAndDelete(0, 0);
  EXPECT_EQ("fooX", input->Value());

  input->SetValue("fooX");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("fooX", input->Value());
  Controller().ExtendSelectionAndDelete(1, 0);
  EXPECT_EQ("foo", input->Value());

  input->SetValue(
      String::FromUTF8("foo\xE2\x98\x85"));  // U+2605 == "black star"
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("foo\xE2\x98\x85", input->Value().Utf8());
  Controller().ExtendSelectionAndDelete(1, 0);
  EXPECT_EQ("foo", input->Value());

  input->SetValue(
      String::FromUTF8("foo\xF0\x9F\x8F\x86"));  // U+1F3C6 == "trophy"
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("foo\xF0\x9F\x8F\x86", input->Value().Utf8());
  Controller().ExtendSelectionAndDelete(1, 0);
  EXPECT_EQ("foo", input->Value());

  // composed U+0E01 "ka kai" + U+0E49 "mai tho"
  input->SetValue(String::FromUTF8("foo\xE0\xB8\x81\xE0\xB9\x89"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("foo\xE0\xB8\x81\xE0\xB9\x89", input->Value().Utf8());
  Controller().ExtendSelectionAndDelete(1, 0);
  EXPECT_EQ("foo", input->Value());

  input->SetValue("fooX");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("fooX", input->Value());
  Controller().ExtendSelectionAndDelete(0, 1);
  EXPECT_EQ("fooX", input->Value());
}

TEST_F(InputMethodControllerTest, SetCompositionFromExistingText) {
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>hello world</div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 0, 5);

  Range* range = GetCompositionRange();
  EXPECT_EQ(0u, range->startOffset());
  EXPECT_EQ(5u, range->endOffset());

  PlainTextRange plain_text_range(PlainTextRange::Create(*div, *range));
  EXPECT_EQ(0u, plain_text_range.Start());
  EXPECT_EQ(5u, plain_text_range.End());
}

TEST_F(InputMethodControllerTest, AddImeTextSpansToExistingText) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kAutocorrect, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().AddImeTextSpansToExistingText(ime_text_spans, 0, 5);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());
  EXPECT_EQ(DocumentMarker::MarkerType::kSuggestion,
            GetDocument().Markers().Markers()[0]->GetType());
  EXPECT_EQ(SuggestionMarker::SuggestionType::kAutocorrect,
            To<SuggestionMarker>(GetDocument().Markers().Markers()[0].Get())
                ->GetSuggestionType());
}

TEST_F(InputMethodControllerTest, AddGrammarCheckSpans) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();

  GetDocument().Markers().AddSpellingMarker(
      EphemeralRange(Position(text, 0), Position(text, 5)));

  Vector<ImeTextSpan> grammar_ime_text_spans;
  grammar_ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kGrammarSuggestion, 3, 6, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  grammar_ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kGrammarSuggestion, 8, 10, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().AddImeTextSpansToExistingText(grammar_ime_text_spans, 0, 10);
  // The first grammar check span should not be added because it overlaps with
  // the existing spellcheck span.
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
  EXPECT_EQ(0u, GetDocument().Markers().Markers()[0]->StartOffset());
  EXPECT_EQ(5u, GetDocument().Markers().Markers()[0]->EndOffset());
  EXPECT_EQ(DocumentMarker::MarkerType::kSpelling,
            GetDocument().Markers().Markers()[0]->GetType());
  EXPECT_EQ(8u, GetDocument().Markers().Markers()[1]->StartOffset());
  EXPECT_EQ(10u, GetDocument().Markers().Markers()[1]->EndOffset());
  EXPECT_EQ(DocumentMarker::MarkerType::kSuggestion,
            GetDocument().Markers().Markers()[1]->GetType());
}

TEST_F(InputMethodControllerTest, GetImeTextSpans) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");
  ImeTextSpan span1 = ImeTextSpan(ImeTextSpan::Type::kAutocorrect, 0, 5,
                                  Color(255, 0, 0), ImeTextSpanThickness::kThin,
                                  ImeTextSpanUnderlineStyle::kSolid,
                                  Color::kTransparent, Color::kTransparent);
  ImeTextSpan span2 = ImeTextSpan(ImeTextSpan::Type::kComposition, 1, 3,
                                  Color(255, 0, 0), ImeTextSpanThickness::kThin,
                                  ImeTextSpanUnderlineStyle::kSolid,
                                  Color::kTransparent, Color::kTransparent);
  ImeTextSpan span3 = ImeTextSpan(
      ImeTextSpan::Type::kMisspellingSuggestion, 1, 3, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent);
  ImeTextSpan span4 = ImeTextSpan(
      ImeTextSpan::Type::kGrammarSuggestion, 6, 8, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent, Color::kTransparent, false,
      false, {String("fake_suggestion")});

  Controller().AddImeTextSpansToExistingText({span1, span2, span3, span4}, 0,
                                             10);
  Controller().SetEditableSelectionOffsets(PlainTextRange(1, 1));

  const WebVector<ui::ImeTextSpan>& ime_text_spans =
      Controller().TextInputInfo().ime_text_spans;

  EXPECT_EQ(2u, ime_text_spans.size());
  EXPECT_EQ(0u, ime_text_spans[0].start_offset);
  EXPECT_EQ(5u, ime_text_spans[0].end_offset);
  EXPECT_EQ(ui::ImeTextSpan::Type::kAutocorrect, ime_text_spans[0].type);
  EXPECT_EQ(0u, ime_text_spans[0].suggestions.size());

  EXPECT_EQ(6u, ime_text_spans[1].start_offset);
  EXPECT_EQ(8u, ime_text_spans[1].end_offset);
  EXPECT_EQ(ui::ImeTextSpan::Type::kGrammarSuggestion, ime_text_spans[1].type);
  EXPECT_EQ(1u, ime_text_spans[1].suggestions.size());
  EXPECT_EQ("fake_suggestion", ime_text_spans[1].suggestions[0]);
}

TEST_F(InputMethodControllerTest, SetCompositionAfterEmoji) {
  // "trophy" = U+1F3C6 = 0xF0 0x9F 0x8F 0x86 (UTF8).
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>&#x1f3c6</div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 2, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  EXPECT_EQ(2, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
  EXPECT_EQ(2, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Focus()
                   .ComputeOffsetInContainerNode());

  Controller().SetComposition(String("a"), ime_text_spans, 1, 1);
  EXPECT_EQ("\xF0\x9F\x8F\x86\x61", div->innerText().Utf8());

  Controller().SetComposition(String("ab"), ime_text_spans, 2, 2);
  EXPECT_EQ("\xF0\x9F\x8F\x86\x61\x62", div->innerText().Utf8());
}

TEST_F(InputMethodControllerTest, SetCompositionWithGraphemeCluster) {
  InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 6, 6, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // UTF16 = 0x0939 0x0947 0x0932 0x0932. Note that 0x0932 0x0932 is a grapheme
  // cluster.
  Controller().SetComposition(
      String::FromUTF8("\xE0\xA4\xB9\xE0\xA5\x87\xE0\xA4\xB2\xE0\xA4\xB2"),
      ime_text_spans, 4, 4);
  EXPECT_EQ(4u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(4u, Controller().GetSelectionOffsets().End());

  // UTF16 = 0x0939 0x0947 0x0932 0x094D 0x0932 0x094B.
  Controller().SetComposition(
      String::FromUTF8("\xE0\xA4\xB9\xE0\xA5\x87\xE0\xA4\xB2\xE0\xA5\x8D\xE0"
                       "\xA4\xB2\xE0\xA5\x8B"),
      ime_text_spans, 6, 6);
  EXPECT_EQ(6u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(6u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest,
       SetCompositionWithGraphemeClusterAndMultipleNodes) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 12, 12, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // UTF16 = 0x0939 0x0947 0x0932 0x094D 0x0932 0x094B. 0x0939 0x0947 0x0932 is
  // a grapheme cluster, so is the remainding 0x0932 0x094B.
  Controller().CommitText(
      String::FromUTF8("\xE0\xA4\xB9\xE0\xA5\x87\xE0\xA4\xB2\xE0\xA5\x8D\xE0"
                       "\xA4\xB2\xE0\xA5\x8B"),
      ime_text_spans, 1);
  Controller().CommitText("\nab ", ime_text_spans, 1);
  Controller().SetComposition(String("c"), ime_text_spans, 1, 1);
  EXPECT_EQ(
      "\xE0\xA4\xB9\xE0\xA5\x87\xE0\xA4\xB2\xE0\xA5\x8D\xE0\xA4\xB2\xE0\xA5"
      "\x8B\nab c",
      div->innerText().Utf8());
  EXPECT_EQ(11u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(11u, Controller().GetSelectionOffsets().End());

  Controller().SetComposition(String("cd"), ime_text_spans, 2, 2);
  EXPECT_EQ(
      "\xE0\xA4\xB9\xE0\xA5\x87\xE0\xA4\xB2\xE0\xA5\x8D\xE0\xA4\xB2\xE0\xA5"
      "\x8B\nab cd",
      div->innerText().Utf8());
  EXPECT_EQ(12u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(12u, Controller().GetSelectionOffsets().End());
}

TEST_F(InputMethodControllerTest, SetCompositionKeepingStyle) {
  Element* div = InsertHTMLElement(
      "<div id='sample' "
      "contenteditable>abc1<b>2</b>34567<b>8</b>9d<b>e</b>f</div>",
      "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 3, 12, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 3, 12);

  // Subtract a character.
  Controller().SetComposition(String("12345789"), ime_text_spans, 8, 8);
  EXPECT_EQ("abc1<b>2</b>3457<b>8</b>9d<b>e</b>f", div->innerHTML().Utf8());
  EXPECT_EQ(11u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(11u, Controller().GetSelectionOffsets().End());

  // Append a character.
  Controller().SetComposition(String("123456789"), ime_text_spans, 9, 9);
  EXPECT_EQ("abc1<b>2</b>34567<b>8</b>9d<b>e</b>f", div->innerHTML().Utf8());
  EXPECT_EQ(12u, Controller().GetSelectionOffsets().Start());
  EXPECT_EQ(12u, Controller().GetSelectionOffsets().End());

  // Subtract and append characters.
  Controller().SetComposition(String("123hello789"), ime_text_spans, 11, 11);
  EXPECT_EQ("abc1<b>2</b>3hello7<b>8</b>9d<b>e</b>f", div->innerHTML().Utf8());
}

TEST_F(InputMethodControllerTest, SetCompositionWithEmojiKeepingStyle) {
  // U+1F3E0 = 0xF0 0x9F 0x8F 0xA0 (UTF8). It's an emoji character.
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable><b>&#x1f3e0</b></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 2, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().SetCompositionFromExistingText(ime_text_spans, 0, 2);

  // 0xF0 0x9F 0x8F 0xAB is also an emoji character, with the same leading
  // surrogate pair to the previous one.
  Controller().SetComposition(String::FromUTF8("\xF0\x9F\x8F\xAB"),
                              ime_text_spans, 2, 2);
  EXPECT_EQ("<b>\xF0\x9F\x8F\xAB</b>", div->innerHTML().Utf8());

  Controller().SetComposition(String::FromUTF8("\xF0\x9F\x8F\xA0"),
                              ime_text_spans, 2, 2);
  EXPECT_EQ("<b>\xF0\x9F\x8F\xA0</b>", div->innerHTML().Utf8());
}

TEST_F(InputMethodControllerTest,
       SetCompositionWithTeluguSignVisargaKeepingStyle) {
  // U+0C03 = 0xE0 0xB0 0x83 (UTF8), a telugu sign visarga with one code point.
  // It's one grapheme cluster if separated. It can also form one grapheme
  // cluster with another code point(e.g, itself).
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable><b>&#xc03</b></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 2, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 0, 1);

  // 0xE0 0xB0 0x83 0xE0 0xB0 0x83, a telugu character with 2 code points in
  // 1 grapheme cluster.
  Controller().SetComposition(String::FromUTF8("\xE0\xB0\x83\xE0\xB0\x83"),
                              ime_text_spans, 2, 2);
  EXPECT_EQ("<b>\xE0\xB0\x83\xE0\xB0\x83</b>", div->innerHTML().Utf8());

  Controller().SetComposition(String::FromUTF8("\xE0\xB0\x83"), ime_text_spans,
                              1, 1);
  EXPECT_EQ("<b>\xE0\xB0\x83</b>", div->innerHTML().Utf8());
}

TEST_F(InputMethodControllerTest, FinishComposingTextKeepingStyle) {
  Element* div = InsertHTMLElement(
      "<div id='sample' "
      "contenteditable>abc1<b>2</b>34567<b>8</b>9</div>",
      "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 3, 12, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 3, 12);

  Controller().SetComposition(String("123hello789"), ime_text_spans, 11, 11);
  EXPECT_EQ("abc1<b>2</b>3hello7<b>8</b>9", div->innerHTML());

  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  EXPECT_EQ("abc1<b>2</b>3hello7<b>8</b>9", div->innerHTML());
}

TEST_F(InputMethodControllerTest, FinishComposingTextKeepingBackwardSelection) {
  GetFrame().Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>|abc^</div>"),
      SetSelectionOptions());

  Controller().FinishComposingText(InputMethodController::kKeepSelection);

  EXPECT_EQ("<div contenteditable>|abc^</div>", GetSelectionTextFromBody());
}

TEST_F(InputMethodControllerTest, CommitTextKeepingStyle) {
  Element* div = InsertHTMLElement(
      "<div id='sample' "
      "contenteditable>abc1<b>2</b>34567<b>8</b>9</div>",
      "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 3, 12, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 3, 12);

  Controller().CommitText(String("123789"), ime_text_spans, 0);
  EXPECT_EQ("abc1<b>2</b>37<b>8</b>9", div->innerHTML());
}

TEST_F(InputMethodControllerTest, InsertTextWithNewLine) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");
  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 11, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));

  Controller().CommitText(String("hello\nworld"), ime_text_spans, 0);
  EXPECT_EQ("hello<div>world</div>", div->innerHTML());
}

TEST_F(InputMethodControllerTest, InsertTextWithNewLineIncrementally) {
  Element* div =
      InsertHTMLElement("<div id='sample' contenteditable></div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  Controller().CommitText("a", ime_text_spans, 0);
  Controller().SetComposition("bcd", ime_text_spans, 0, 2);
  EXPECT_EQ("abcd", div->innerHTML());

  Controller().CommitText(String("bcd\nefgh\nijkl"), ime_text_spans, 0);
  EXPECT_EQ("abcd<div>efgh</div><div>ijkl</div>", div->innerHTML());
}

TEST_F(InputMethodControllerTest, SelectionOnConfirmExistingText) {
  InsertHTMLElement("<div id='sample' contenteditable>hello world</div>",
                    "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 0, 5);

  Controller().FinishComposingText(InputMethodController::kKeepSelection);
  EXPECT_EQ(0, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Anchor()
                   .ComputeOffsetInContainerNode());
  EXPECT_EQ(0, GetFrame()
                   .Selection()
                   .GetSelectionInDOMTree()
                   .Focus()
                   .ComputeOffsetInContainerNode());
}

TEST_F(InputMethodControllerTest, DeleteBySettingEmptyComposition) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  input->SetValue("foo ");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("foo ", input->Value());
  Controller().ExtendSelectionAndDelete(0, 0);
  EXPECT_EQ("foo ", input->Value());

  input->SetValue("foo ");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Controller().SetEditableSelectionOffsets(PlainTextRange(4, 4));
  EXPECT_EQ("foo ", input->Value());
  Controller().ExtendSelectionAndDelete(1, 0);
  EXPECT_EQ("foo", input->Value());

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 3, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 0, 3);

  Controller().SetComposition(String(""), ime_text_spans, 0, 3);

  EXPECT_EQ("", input->Value());
}

TEST_F(InputMethodControllerTest,
       SetCompositionFromExistingTextWithCollapsedWhiteSpace) {
  // Creates a div with one leading new line char. The new line char is hidden
  // from the user and IME, but is visible to InputMethodController.
  Element* div = InsertHTMLElement(
      "<div id='sample' contenteditable>\nhello world</div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 0, 5);

  Range* range = GetCompositionRange();
  EXPECT_EQ(1u, range->startOffset());
  EXPECT_EQ(6u, range->endOffset());

  PlainTextRange plain_text_range(PlainTextRange::Create(*div, *range));
  EXPECT_EQ(0u, plain_text_range.Start());
  EXPECT_EQ(5u, plain_text_range.End());
}

TEST_F(InputMethodControllerTest,
       SetCompositionFromExistingTextWithInvalidOffsets) {
  InsertHTMLElement("<div id='sample' contenteditable>test</div>", "sample");

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 7, 8, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetCompositionFromExistingText(ime_text_spans, 7, 8);

  EXPECT_FALSE(GetCompositionRange());
}

TEST_F(InputMethodControllerTest, ConfirmPasswordComposition) {
  auto* input = To<HTMLInputElement>(InsertHTMLElement(
      "<input id='sample' type='password' size='24'>", "sample"));

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  Controller().SetComposition("foo", ime_text_spans, 0, 3);
  Controller().FinishComposingText(InputMethodController::kKeepSelection);

  EXPECT_EQ("foo", input->Value());
}

TEST_F(InputMethodControllerTest, DeleteSurroundingTextWithEmptyText) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  input->SetValue("");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("", input->Value());
  Controller().DeleteSurroundingText(0, 0);
  EXPECT_EQ("", input->Value());

  input->SetValue("");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("", input->Value());
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("", input->Value());

  input->SetValue("");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("", input->Value());
  Controller().DeleteSurroundingText(0, 1);
  EXPECT_EQ("", input->Value());

  input->SetValue("");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("", input->Value());
  Controller().DeleteSurroundingText(1, 1);
  EXPECT_EQ("", input->Value());
}

TEST_F(InputMethodControllerTest, DeleteSurroundingTextWithRangeSelection) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(1, 4));
  Controller().DeleteSurroundingText(0, 0);
  EXPECT_EQ("hello", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(1, 4));
  Controller().DeleteSurroundingText(1, 1);
  EXPECT_EQ("ell", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(1, 4));
  Controller().DeleteSurroundingText(100, 0);
  EXPECT_EQ("ello", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(1, 4));
  Controller().DeleteSurroundingText(0, 100);
  EXPECT_EQ("hell", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(1, 4));
  Controller().DeleteSurroundingText(100, 100);
  EXPECT_EQ("ell", input->Value());
}

TEST_F(InputMethodControllerTest, DeleteSurroundingTextWithCursorSelection) {
  auto* input =
      To<HTMLInputElement>(InsertHTMLElement("<input id='sample'>", "sample"));

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  Controller().DeleteSurroundingText(1, 0);
  EXPECT_EQ("hllo", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  Controller().DeleteSurroundingText(0, 1);
  EXPECT_EQ("helo", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  Controller().DeleteSurroundingText(0, 0);
  EXPECT_EQ("hello", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  Controller().DeleteSurroundingText(1, 1);
  EXPECT_EQ("hlo", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  Controller().DeleteSurroundingText(100, 0);
  EXPECT_EQ("llo", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", input->Value());
  Controller().SetEditableSelectionOffsets(PlainTextRange(2, 2));
  Controller().DeleteSurroundingText(0, 100);
  EXPECT_EQ("he", input->Value());

  input->SetValue("hello");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_EQ("hello", inp
"""


```