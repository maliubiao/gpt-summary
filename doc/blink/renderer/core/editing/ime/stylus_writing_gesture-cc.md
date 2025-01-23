Response:
Let's break down the thought process for analyzing the `stylus_writing_gesture.cc` file.

1. **Understand the Goal:** The request asks for a functional breakdown of the code, connections to web technologies, logic flow, potential errors, and debugging hints. Essentially, it's a request for a comprehensive code analysis targeting a specific audience (likely someone working with or debugging this part of Blink).

2. **Initial Scan and High-Level Understanding:**  The filename itself (`stylus_writing_gesture.cc`) immediately suggests this code deals with handling stylus-based input gestures for text editing. The `#include` directives confirm this, mentioning `mojom::blink::StylusWritingGesture.mojom-blink.h` (the data structure for gesture information), `Editor`, `FrameSelection`, `InputMethodController`, etc. This initial scan sets the context.

3. **Identify Key Classes:**  The code defines several classes: `StylusWritingGesture`, `StylusWritingTwoRectGesture`, and specific gesture types like `StylusWritingGestureDelete`, `StylusWritingGestureRemoveSpaces`, `StylusWritingGestureSelect`, `StylusWritingGestureAddText`, and `StylusWritingGestureSplitOrMerge`. Recognizing these classes is crucial for understanding the code's organization and purpose.

4. **Analyze Each Class:**  For each class, consider:
    * **Purpose:** What specific gesture or functionality does it represent? (e.g., `StylusWritingGestureDelete` clearly handles deleting text).
    * **Data Members:** What data does it hold? (e.g., `start_rect_`, `end_rect_`, `text_alternative_`, `granularity_`).
    * **Key Methods:** What are the important methods, and what do they do? (`MaybeApplyGesture` is central to all gesture types).
    * **Inheritance:**  How does it relate to other classes?  (e.g., the specific gesture types inherit from `StylusWritingTwoRectGesture` or `StylusWritingGesture`).

5. **Identify Key Functions (Non-Class Members):**  Pay attention to standalone functions like `CreateGesture`, `ExpandWithWordGranularity`, `GestureRangeForPoints`, and `GetTextRangeForSpaces`. These often represent core logic or utility functions.

6. **Trace the Execution Flow (Implicitly):** While not explicitly running the code, infer the sequence of operations. For example, `ApplyGesture` seems to be the entry point, then `CreateGesture` is used to instantiate the correct gesture object, and then `MaybeApplyGesture` is called.

7. **Look for Web Technology Connections:**  Consider how these gestures relate to user interaction with web content.
    * **JavaScript:**  JavaScript event listeners could trigger actions that eventually lead to these native code functions.
    * **HTML:** The gestures directly manipulate text within HTML elements (like `<textarea>`, `<input>`, or content-editable divs).
    * **CSS:**  While not directly manipulated *by* this code, CSS styling affects the visual presentation of the text being edited, and thus influences the user's interaction with the stylus. The `gfx::Rect` coordinates are screen-related and thus indirectly tied to the rendered layout.

8. **Consider Logic and Assumptions:**  Analyze the conditional statements and algorithms.
    * **Assumptions:** The code assumes a valid editable context. It checks for this. It also makes assumptions about the gesture data being correctly formed.
    * **Logic:** The `GestureRangeForPoints` function is a good example of logic to analyze. It converts screen coordinates to document coordinates and finds the corresponding text range. The different `MaybeApplyGesture` implementations show the specific logic for each gesture.

9. **Think About Potential Errors and User Mistakes:**
    * **User Errors:** What could a user do that might cause unexpected behavior or for the gesture to fail?  Drawing outside an input field, performing a gesture on non-editable content.
    * **Programming Errors:**  What could a developer do wrong?  Incorrectly passing gesture data, not handling fallback scenarios, issues with focus and editable contexts.

10. **Consider Debugging:**  How could a developer investigate issues in this code?  Logging, breakpoints, inspecting the state of variables, tracing the execution path back from a user action.

11. **Structure the Answer:** Organize the information logically using headings and bullet points to make it easy to understand. Start with a high-level summary, then delve into specifics. Use examples to illustrate the connections to web technologies and potential errors. Provide a clear step-by-step explanation of user interaction leading to this code.

12. **Refine and Review:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any ambiguities or missing information. For example, initially, I might not have explicitly mentioned the role of `mojom` files, but upon review, I'd realize it's important to explain that these define the data structures passed across process boundaries.

This iterative process of scanning, analyzing, connecting, considering errors, and structuring the answer helps to create a comprehensive and helpful explanation of the code's functionality.
这个 C++ 源代码文件 `stylus_writing_gesture.cc` 位于 Chromium Blink 引擎中，负责处理用户使用触控笔在可编辑区域（例如文本输入框）进行书写时产生的各种手势。它的主要功能是将这些手势转换为相应的编辑操作。

下面详细列举其功能，并解释与 JavaScript、HTML、CSS 的关系，以及逻辑推理、用户错误和调试线索：

**文件功能：**

1. **定义触控笔书写手势的抽象基类 `StylusWritingGesture`：**
   - 包含手势的起始矩形区域 `start_rect_` 和识别出的替代文本 `text_alternative_`。
   - 提供获取起始文本索引的方法 `GetStartTextIndex`。
   - 定义了静态方法 `ApplyGesture`，作为处理所有触控笔书写手势的入口点。

2. **定义基于两个矩形的触控笔书写手势基类 `StylusWritingTwoRectGesture`：**
   - 继承自 `StylusWritingGesture`，并额外包含手势的结束矩形区域 `end_rect_`。
   - 提供获取手势覆盖文本范围的方法 `GestureRange`，可以根据不同的粒度（字符或单词）获取。
   - 提供调整手势范围的方法 `AdjustRange`，允许子类根据具体手势进行调整。

3. **定义具体的触控笔书写手势类，并实现相应的功能：**
   - **`StylusWritingGestureDelete` (删除文本)：**
     -  根据起始和结束矩形定义删除的文本范围。
     -  `MaybeApplyGesture` 方法实现删除指定范围的文本。
     -  `AdjustRange` 方法会根据文本内容进行微调，例如处理空格。
   - **`StylusWritingGestureRemoveSpaces` (移除空格)：**
     - 根据起始和结束矩形定义包含空格的文本范围。
     - `MaybeApplyGesture` 方法实现移除指定范围内的空格。
   - **`StylusWritingGestureSelect` (选择文本)：**
     - 根据起始和结束矩形定义要选择的文本范围。
     - `MaybeApplyGesture` 方法实现选中指定范围的文本。
     - `AdjustRange` 方法会根据文本内容进行微调，例如去除首尾空格。
   - **`StylusWritingGestureAddText` (添加文本)：**
     - 根据起始矩形确定插入位置。
     - `MaybeApplyGesture` 方法实现在指定位置插入文本。
   - **`StylusWritingGestureSplitOrMerge` (分割或合并文本，通常指插入或删除空格)：**
     - 根据起始矩形确定操作位置。
     - `MaybeApplyGesture` 方法实现在指定位置插入空格（分割）或删除周围空格（合并）。

4. **提供创建手势对象的工厂函数 `CreateGesture`：**
   - 接收 `mojom::blink::StylusWritingGestureDataPtr` 类型的参数，其中包含了手势的类型和相关数据。
   - 根据手势类型创建相应的具体手势对象。

5. **提供辅助函数：**
   - `ExpandWithWordGranularity`:  将给定的文本范围扩展到整个单词。
   - `GestureRangeForPoints`:  根据给定的起始和结束点，以及粒度，获取对应的文本范围。
   - `GetTextRangeForSpaces`: 在给定的文本范围内查找空格，并返回包含这些空格的文本范围。

**与 JavaScript, HTML, CSS 的关系：**

- **JavaScript:**
    - **事件触发:** 用户在网页上使用触控笔书写时，浏览器会捕获相应的触摸事件（例如 `touchstart`, `touchmove`, `touchend`）。JavaScript 代码可以通过事件监听器（例如 `addEventListener`) 捕获这些事件。
    - **手势识别 (可能在 Renderer 进程的更高层处理):**  浏览器引擎内部的逻辑（可能涉及到 JavaScript 或 C++ 代码）会分析这些触摸事件序列，识别出特定的触控笔书写手势（例如删除线、插入符号等）。
    - **数据传递:** 识别出的手势信息（例如起始位置、结束位置、识别出的替代文本）会被封装成消息（例如通过 Mojo 接口）传递给 Blink 渲染引擎的 C++ 代码，最终到达 `stylus_writing_gesture.cc` 进行处理。

    **举例说明:**  当用户在 `<textarea>` 中画一条删除线时，JavaScript 可能会捕获到触摸事件，然后一些逻辑判断出这是一个删除手势，并将手势的起始和结束坐标以及识别出的替代文本（如果适用）传递给后端。

- **HTML:**
    - **可编辑区域:** 这些手势操作的目标是 HTML 中的可编辑元素，例如 `<input type="text">`、`<textarea>` 或设置了 `contenteditable` 属性的元素。
    - **结构影响:** 手势操作会直接修改 HTML 文档的结构，例如插入或删除文本节点。

    **举例说明:**  用户在一个 `contenteditable` 的 `<div>` 中画一个插入空格的手势，`StylusWritingGestureSplitOrMerge` 最终会修改该 `<div>` 的 DOM 结构，插入一个空格字符。

- **CSS:**
    - **视觉呈现:** CSS 决定了可编辑元素的样式和布局。触控笔手势操作作用于这些元素上，CSS 的样式会影响用户与这些元素的交互体验。
    - **坐标系统:**  `gfx::Rect` 等数据结构中使用的坐标是基于 CSS 渲染的布局计算出来的。

    **举例说明:**  如果一个 `<input>` 元素设置了特定的字体和行高，那么 `GestureRangeForPoints` 函数在根据触控笔的屏幕坐标计算文本范围时，会考虑到这些 CSS 样式带来的影响。

**逻辑推理、假设输入与输出：**

**假设输入 (来自 `mojom::blink::StylusWritingGestureDataPtr`):**

```
gesture_data = {
  action: mojom::blink::StylusWritingGestureAction::DELETE_TEXT,
  start_rect: gfx::Rect(10, 20, 5, 5), // 删除手势的起始小方块
  end_rect: gfx::Rect(50, 20, 5, 5),   // 删除手势的结束小方块
  text_alternative: "删除",
  granularity: mojom::blink::StylusWritingGestureGranularity::CHARACTER
}
```

**假设场景:** 用户在一个文本框中，用触控笔从 "Hello" 中的 "e" 字母开始划到 "l" 字母上，试图删除 "ell" 这几个字符。

**逻辑推理:**

1. `ApplyGesture` 函数接收 `gesture_data`。
2. `CreateGesture` 函数根据 `action` 创建 `StylusWritingGestureDelete` 对象。
3. `MaybeApplyGesture` 方法被调用。
4. `GestureRange` 方法根据 `start_rect` 和 `end_rect`，以及当前文本框的内容和布局，计算出要删除的文本范围（可能是 "ell"）。
5. `InputMethodController` 的相关方法被调用，删除计算出的文本范围。

**预期输出:**  文本框中的 "Hello" 变为 "Ho"。

**用户或编程常见的使用错误：**

1. **用户错误：**
   - **在不可编辑区域进行手势操作:** 用户尝试在静态文本或非可编辑元素上使用触控笔手势，这时 `RootEditableElementOrDocumentElement()` 会返回空，导致手势无法应用。
   - **手势不清晰或超出预期:** 用户画的手势不符合预定义的模式，或者起始和结束位置不明确，导致 `GestureRange` 计算出的范围不正确。
   - **在合成输入法激活时进行操作:**  如果在输入法正在进行组合输入时进行手势操作，可能会导致意想不到的结果，因为组合文本的处理逻辑可能与手势操作冲突。代码中 `ApplyGesture` 会先 `FinishComposingText` 来避免这种情况。

2. **编程错误：**
   - **传递错误的 `gesture_data`:**  例如，`start_rect` 或 `end_rect` 的坐标不正确，或者 `action` 类型与实际手势不符。
   - **没有正确处理 `MaybeApplyGesture` 的返回值:**  如果 `MaybeApplyGesture` 返回 `false`，表示手势无法应用，通常应该插入 `text_alternative` 作为回退，但如果代码没有正确处理这种情况，可能会导致手势失效。
   - **在手势处理过程中没有更新布局:**  某些手势操作可能需要最新的布局信息才能正确计算文本范围。如果布局没有及时更新，可能会导致计算错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在支持触控笔的设备上打开一个网页。**
2. **网页包含一个可编辑的元素（如 `<textarea>`）。**
3. **用户使用触控笔与该可编辑元素进行交互，执行一个特定的书写手势，例如画一条删除线穿过一段文字。**
4. **操作系统或浏览器内核捕获到触控笔的输入事件（例如 `WM_POINTER*` 或 `touchstart`/`touchmove`/`touchend` 等）。**
5. **浏览器渲染进程（Renderer Process）中的事件处理代码（可能涉及 JavaScript）接收到这些事件。**
6. **Blink 引擎内部的手势识别模块分析这些触摸事件序列，判断这是一个触控笔书写手势，并识别出具体的意图（例如删除文本）。**
7. **手势识别模块将手势的相关信息（起始位置、结束位置等）封装成 `mojom::blink::StylusWritingGestureDataPtr` 对象。**
8. **该 `StylusWritingGestureDataPtr` 对象通过 Chromium 的 IPC 机制（Inter-Process Communication）传递到 Blink 渲染引擎的输入处理模块。**
9. **输入处理模块最终调用 `StylusWritingGesture::ApplyGesture` 函数，并将 `gesture_data` 作为参数传入。**
10. **在 `ApplyGesture` 函数内部，会根据 `gesture_data->action` 创建具体的 `StylusWritingGesture` 子类对象，并调用其 `MaybeApplyGesture` 方法执行相应的编辑操作。**

**调试线索：**

- **检查触摸事件:**  在 JavaScript 代码中添加事件监听器，记录触摸事件的坐标和时间戳，确认触摸事件是否被正确捕获。
- **查看手势数据:**  在 `CreateGesture` 函数入口处打断点，查看 `gesture_data` 的内容，确认手势类型和相关参数是否正确。
- **跟踪 `GestureRange` 的计算:**  在 `GestureRange` 函数中打断点，查看计算出的文本范围是否符合预期，以及起始和结束节点的偏移量。
- **检查 `InputMethodController` 的调用:**  查看是否调用了正确的 `InputMethodController` 方法，以及传递的参数是否正确。
- **查看日志输出:**  在关键路径上添加日志输出，例如手势开始、结束、计算出的范围、执行的操作等，帮助理解代码的执行流程。
- **使用 Chromium 的 tracing 工具:**  启用 Chromium 的 tracing 功能，可以更详细地跟踪事件的传递和函数的调用，帮助定位问题。

总而言之，`stylus_writing_gesture.cc` 文件是 Blink 引擎中处理触控笔书写手势的核心组件，它接收来自上层的抽象手势描述，并将其转换为对可编辑 HTML 内容的具体操作。理解其功能和与 web 技术的关系，对于调试和扩展相关功能至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/ime/stylus_writing_gesture.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/ime/stylus_writing_gesture.h"

#include "third_party/blink/public/mojom/input/stylus_writing_gesture.mojom-blink.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"

namespace blink {

namespace {

class StylusWritingTwoRectGesture : public StylusWritingGesture {
 public:
  ~StylusWritingTwoRectGesture() override = default;

 protected:
  StylusWritingTwoRectGesture(const gfx::Rect& start_rect,
                              const gfx::Rect& end_rect,
                              const String& text_alternative);

  // Gets the text range in input between the start and end points of this
  // gesture. Returns null if the gesture is not over valid text input. Takes
  // granularity as a default parameter as not all gestures have a granularity.
  std::optional<PlainTextRange> GestureRange(
      LocalFrame*,
      const mojom::blink::StylusWritingGestureGranularity granularity =
          mojom::blink::StylusWritingGestureGranularity::CHARACTER);

  virtual std::optional<PlainTextRange> AdjustRange(
      std::optional<PlainTextRange> range,
      InputMethodController& input_method_controller) {
    return range;
  }

  // End rectangle of the gesture.
  gfx::Rect end_rect_;
};

class StylusWritingGestureDelete : public StylusWritingTwoRectGesture {
 public:
  ~StylusWritingGestureDelete() override = default;

  StylusWritingGestureDelete(
      const gfx::Rect& start_rect,
      const gfx::Rect& end_rect,
      const String& text_alternative,
      const mojom::blink::StylusWritingGestureGranularity granularity);
  bool MaybeApplyGesture(LocalFrame*) override;

 protected:
  std::optional<PlainTextRange> AdjustRange(std::optional<PlainTextRange>,
                                            InputMethodController&) override;

 private:
  const mojom::blink::StylusWritingGestureGranularity granularity_;
};

class StylusWritingGestureRemoveSpaces : public StylusWritingTwoRectGesture {
 public:
  ~StylusWritingGestureRemoveSpaces() override = default;

  StylusWritingGestureRemoveSpaces(const gfx::Rect& start_rect,
                                   const gfx::Rect& end_rect,
                                   const String& text_alternative);
  bool MaybeApplyGesture(LocalFrame*) override;
};

class StylusWritingGestureSelect : public StylusWritingTwoRectGesture {
 public:
  ~StylusWritingGestureSelect() override = default;

  StylusWritingGestureSelect(
      const gfx::Rect& start_rect,
      const gfx::Rect& end_rect,
      const String& text_alternative,
      const mojom::StylusWritingGestureGranularity granularity);
  bool MaybeApplyGesture(LocalFrame*) override;

 protected:
  std::optional<PlainTextRange> AdjustRange(std::optional<PlainTextRange>,
                                            InputMethodController&) override;

 private:
  const mojom::StylusWritingGestureGranularity granularity_;
};

class StylusWritingGestureAddText : public StylusWritingGesture {
 public:
  ~StylusWritingGestureAddText() override = default;

  StylusWritingGestureAddText(const gfx::Rect& start_rect,
                              const String& text_to_insert,
                              const String& text_alternative);
  bool MaybeApplyGesture(LocalFrame*) override;

 private:
  // Text to insert for the add text gesture. This also includes adding space
  // character.
  String text_to_insert_;
};

class StylusWritingGestureSplitOrMerge : public StylusWritingGesture {
 public:
  ~StylusWritingGestureSplitOrMerge() override = default;

  StylusWritingGestureSplitOrMerge(const gfx::Rect& start_rect,
                                   const String& text_alternative);
  bool MaybeApplyGesture(LocalFrame*) override;
};

std::unique_ptr<StylusWritingGesture> CreateGesture(
    mojom::blink::StylusWritingGestureDataPtr gesture_data) {
  if (!gesture_data) {
    return nullptr;
  }
  String text_alternative = gesture_data->text_alternative;

  switch (gesture_data->action) {
    case mojom::blink::StylusWritingGestureAction::DELETE_TEXT: {
      if (!gesture_data->end_rect.has_value()) {
        return nullptr;
      }
      return std::make_unique<blink::StylusWritingGestureDelete>(
          gesture_data->start_rect, gesture_data->end_rect.value(),
          text_alternative, gesture_data->granularity);
    }
    case mojom::blink::StylusWritingGestureAction::ADD_SPACE_OR_TEXT: {
      return std::make_unique<blink::StylusWritingGestureAddText>(
          gesture_data->start_rect, gesture_data->text_to_insert,
          text_alternative);
    }
    case mojom::blink::StylusWritingGestureAction::REMOVE_SPACES: {
      if (!gesture_data->end_rect.has_value()) {
        return nullptr;
      }
      return std::make_unique<blink::StylusWritingGestureRemoveSpaces>(
          gesture_data->start_rect, gesture_data->end_rect.value(),
          text_alternative);
    }
    case mojom::blink::StylusWritingGestureAction::SPLIT_OR_MERGE: {
      return std::make_unique<blink::StylusWritingGestureSplitOrMerge>(
          gesture_data->start_rect, text_alternative);
    }
    case mojom::blink::StylusWritingGestureAction::SELECT_TEXT: {
      if (!gesture_data->end_rect.has_value()) {
        return nullptr;
      }
      return std::make_unique<blink::StylusWritingGestureSelect>(
          gesture_data->start_rect, gesture_data->end_rect.value(),
          text_alternative, gesture_data->granularity);
    }
    default: {
      NOTREACHED();
    }
  }
}

PlainTextRange ExpandWithWordGranularity(
    EphemeralRange ephemeral_range,
    Element* const root_editable_element,
    InputMethodController& input_method_controller) {
  SelectionInDOMTree expanded_selection = ExpandWithGranularity(
      SelectionInDOMTree::Builder().SetBaseAndExtent(ephemeral_range).Build(),
      TextGranularity::kWord, WordInclusion::kMiddle);
  PlainTextRange expanded_range = PlainTextRange::Create(
      *root_editable_element, expanded_selection.ComputeRange());
  return expanded_range;
}

std::optional<PlainTextRange> GestureRangeForPoints(
    LocalFrame* local_frame,
    const gfx::Point& start_point,
    const gfx::Point& end_point,
    const mojom::blink::StylusWritingGestureGranularity granularity) {
  auto* frame_view = local_frame->View();
  DCHECK(frame_view);
  Element* const root_editable_element =
      local_frame->Selection().RootEditableElementOrDocumentElement();
  if (!root_editable_element) {
    return std::nullopt;
  }
  EphemeralRange ephemeral_range = local_frame->GetEditor().RangeBetweenPoints(
      frame_view->ViewportToFrame(start_point),
      frame_view->ViewportToFrame(end_point));
  if (ephemeral_range.IsCollapsed()) {
    return std::nullopt;
  }

  PlainTextRange gesture_range =
      PlainTextRange::Create(*root_editable_element, ephemeral_range);

  if (gesture_range.IsNull() || gesture_range.Start() >= gesture_range.End()) {
    // Gesture points do not have valid offsets in input.
    return std::nullopt;
  }
  switch (granularity) {
    case mojom::blink::StylusWritingGestureGranularity::CHARACTER:
      return gesture_range;
    case mojom::blink::StylusWritingGestureGranularity::WORD:
      return ExpandWithWordGranularity(ephemeral_range, root_editable_element,
                                       local_frame->GetInputMethodController());
    default:
      return std::nullopt;
  }
}

// Gets the text range for continuous spaces, or range for first spaces found in
// given gesture range.
std::optional<PlainTextRange> GetTextRangeForSpaces(
    PlainTextRange& gesture_range,
    const String& gesture_text) {
  wtf_size_t space_start = kNotFound;
  wtf_size_t space_end = kNotFound;
  // Use this boolean to set the start/end offsets of space range.
  bool space_found = false;

  for (wtf_size_t index = 0; index < gesture_text.length(); index++) {
    if (IsHTMLSpace(gesture_text[index])) {
      if (!space_found) {
        space_found = true;
        space_start = index;
      }
      space_end = index + 1;
    } else if (space_found) {
      break;
    }
  }

  if (!space_found)
    return std::nullopt;

  // Return range for space wrt input text range.
  return PlainTextRange(space_start + gesture_range.Start(),
                        space_end + gesture_range.Start());
}

}  // namespace

// static
mojom::blink::HandwritingGestureResult StylusWritingGesture::ApplyGesture(
    LocalFrame* local_frame,
    mojom::blink::StylusWritingGestureDataPtr gesture_data) {
  if (!local_frame->GetEditor().CanEdit())
    return mojom::blink::HandwritingGestureResult::kFailed;

  if (!local_frame->Selection().RootEditableElementOrDocumentElement())
    return mojom::blink::HandwritingGestureResult::kFailed;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. See http://crbug.com/590369 for more details.
  local_frame->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);

  InputMethodController& input_method_controller =
      local_frame->GetInputMethodController();
  // Finish composition if its active before doing gesture actions.
  if (input_method_controller.HasComposition()) {
    input_method_controller.FinishComposingText(
        InputMethodController::kKeepSelection);
  }

  // Create gesture corresponding to gesture data action.
  std::unique_ptr<StylusWritingGesture> gesture =
      CreateGesture(std::move(gesture_data));
  if (gesture == nullptr) {
    return mojom::blink::HandwritingGestureResult::kUnsupported;
  }
  if (!gesture->MaybeApplyGesture(local_frame)) {
    // If the Stylus writing gesture could not be applied due the gesture
    // coordinates not being over a valid text position in the current focused
    // input, then insert the alternative text recognized.
    local_frame->GetEditor().InsertText(gesture->text_alternative_,
                                        /* triggering_event = */ nullptr);
    return mojom::blink::HandwritingGestureResult::kFallback;
  }
  return mojom::blink::HandwritingGestureResult::kSuccess;
}

StylusWritingGesture::StylusWritingGesture(const gfx::Rect& start_rect,
                                           const String& text_alternative)
    : start_rect_(start_rect), text_alternative_(text_alternative) {}

wtf_size_t StylusWritingGesture::GetStartTextIndex(LocalFrame* local_frame) {
  auto* frame_view = local_frame->View();
  DCHECK(frame_view);
  // This method should only be called on zero sized rectangles.
  DCHECK(start_rect_.IsEmpty());
  return local_frame->Selection().CharacterIndexForPoint(
      frame_view->ViewportToFrame(start_rect_.origin()));
}

StylusWritingTwoRectGesture::StylusWritingTwoRectGesture(
    const gfx::Rect& start_rect,
    const gfx::Rect& end_rect,
    const String& text_alternative)
    : StylusWritingGesture(start_rect, text_alternative), end_rect_(end_rect) {}

std::optional<PlainTextRange> StylusWritingTwoRectGesture::GestureRange(
    LocalFrame* local_frame,
    const mojom::blink::StylusWritingGestureGranularity granularity) {
  Element* const root_editable_element =
      local_frame->Selection().RootEditableElementOrDocumentElement();
  if (!root_editable_element) {
    return std::nullopt;
  }
  if (start_rect_.IsEmpty() && end_rect_.IsEmpty()) {
    start_rect_.UnionEvenIfEmpty(end_rect_);
    start_rect_.InclusiveIntersect(root_editable_element->BoundsInWidget());
    return AdjustRange(
        GestureRangeForPoints(local_frame, start_rect_.left_center(),
                              start_rect_.right_center(), granularity),
        local_frame->GetInputMethodController());
  }
  start_rect_.InclusiveIntersect(root_editable_element->BoundsInWidget());
  std::optional<PlainTextRange> first_range =
      GestureRangeForPoints(local_frame, start_rect_.left_center(),
                            start_rect_.right_center(), granularity);
  end_rect_.InclusiveIntersect(root_editable_element->BoundsInWidget());
  std::optional<PlainTextRange> last_range =
      GestureRangeForPoints(local_frame, end_rect_.left_center(),
                            end_rect_.right_center(), granularity);
  if (!first_range.has_value() || !last_range.has_value()) {
    return std::nullopt;
  }
  // TODO(crbug.com/1411758): Add support for gestures with vertical text.

  // Combine the ranges' indices such that regardless of if the text is LTR or
  // RTL, the correct range is used.
  return AdjustRange(PlainTextRange(first_range->Start(), last_range->End()),
                     local_frame->GetInputMethodController());
}

StylusWritingGestureDelete::StylusWritingGestureDelete(
    const gfx::Rect& start_rect,
    const gfx::Rect& end_rect,
    const String& text_alternative,
    const mojom::blink::StylusWritingGestureGranularity granularity)
    : StylusWritingTwoRectGesture(start_rect, end_rect, text_alternative),
      granularity_(granularity) {}

bool StylusWritingGestureDelete::MaybeApplyGesture(LocalFrame* frame) {
  std::optional<PlainTextRange> gesture_range =
      GestureRange(frame, granularity_);
  if (!gesture_range.has_value()) {
    // Invalid gesture, return false to insert the alternative text.
    return false;
  }

  // Delete the text between offsets and set cursor.
  InputMethodController& input_method_controller =
      frame->GetInputMethodController();
  input_method_controller.SetEditableSelectionOffsets(
      PlainTextRange(gesture_range->End(), gesture_range->End()));
  input_method_controller.DeleteSurroundingText(
      gesture_range->End() - gesture_range->Start(), 0);
  return true;
}

std::optional<PlainTextRange> StylusWritingGestureDelete::AdjustRange(
    std::optional<PlainTextRange> range,
    InputMethodController& input_method_controller) {
  if (!range.has_value() || range->length() < 2) {
    return range;
  }
  String input_text = input_method_controller.TextInputInfo().value;
  // When there is a space at the start and end of the gesture, remove one.
  if (IsHTMLSpaceNotLineBreak(input_text[range->Start()]) &&
      IsHTMLSpaceNotLineBreak(input_text[range->End() - 1])) {
    return PlainTextRange(range->Start() + 1, range->End());
  }
  // When there are spaces either side of the gesture, include one.
  if (input_text.length() > range->End() && range->Start() - 1 >= 0 &&
      IsHTMLSpaceNotLineBreak(input_text[range->Start() - 1]) &&
      !IsHTMLSpaceNotLineBreak(input_text[range->End() - 1])) {
    return PlainTextRange(range->Start() - 1, range->End());
  }
  return range;
}

StylusWritingGestureRemoveSpaces::StylusWritingGestureRemoveSpaces(
    const gfx::Rect& start_rect,
    const gfx::Rect& end_rect,
    const String& text_alternative)
    : StylusWritingTwoRectGesture(start_rect, end_rect, text_alternative) {}

bool StylusWritingGestureRemoveSpaces::MaybeApplyGesture(LocalFrame* frame) {
  std::optional<PlainTextRange> gesture_range = GestureRange(frame);
  if (!gesture_range.has_value()) {
    // Invalid gesture, return false to insert the alternative text.
    return false;
  }

  Element* const root_editable_element =
      frame->Selection().RootEditableElementOrDocumentElement();
  if (!root_editable_element) {
    return false;
  }
  String gesture_text =
      PlainText(gesture_range->CreateRange(*root_editable_element));
  std::optional<PlainTextRange> space_range =
      GetTextRangeForSpaces(gesture_range.value(), gesture_text);
  if (!space_range.has_value())
    return false;

  InputMethodController& input_method_controller =
      frame->GetInputMethodController();
  input_method_controller.ReplaceTextAndMoveCaret(
      "", space_range.value(),
      InputMethodController::MoveCaretBehavior::kDoNotMove);
  input_method_controller.SetEditableSelectionOffsets(
      PlainTextRange(space_range->Start(), space_range->Start()));
  return true;
}

StylusWritingGestureSelect::StylusWritingGestureSelect(
    const gfx::Rect& start_rect,
    const gfx::Rect& end_rect,
    const String& text_alternative,
    const mojom::StylusWritingGestureGranularity granularity)
    : StylusWritingTwoRectGesture(start_rect, end_rect, text_alternative),
      granularity_(granularity) {}

bool StylusWritingGestureSelect::MaybeApplyGesture(LocalFrame* frame) {
  std::optional<PlainTextRange> gesture_range =
      GestureRange(frame, granularity_);
  if (!gesture_range.has_value()) {
    // Invalid gesture, return false to insert the alternative text.
    return false;
  }

  // Select the text between offsets.
  InputMethodController& input_method_controller =
      frame->GetInputMethodController();
  input_method_controller.SetEditableSelectionOffsets(
      gesture_range.value(), /*show_handle=*/true, /*show_context_menu=*/true);
  return true;
}

std::optional<PlainTextRange> StylusWritingGestureSelect::AdjustRange(
    std::optional<PlainTextRange> range,
    InputMethodController& input_method_controller) {
  if (!range.has_value() || range->length() < 2) {
    return range;
  }
  String input_text = input_method_controller.TextInputInfo().value;
  return PlainTextRange(
      range->Start() + IsHTMLSpaceNotLineBreak(input_text[range->Start()]),
      range->End() - IsHTMLSpaceNotLineBreak(input_text[range->End() - 1]));
}

StylusWritingGestureAddText::StylusWritingGestureAddText(
    const gfx::Rect& start_rect,
    const String& text_to_insert,
    const String& text_alternative)
    : StylusWritingGesture(start_rect, text_alternative),
      text_to_insert_(text_to_insert) {}

bool StylusWritingGestureAddText::MaybeApplyGesture(LocalFrame* frame) {
  wtf_size_t gesture_text_index = GetStartTextIndex(frame);
  // When the gesture point is outside the input text range, we get a kNotFound.
  // Return false here to insert the text alternative.
  if (gesture_text_index == kNotFound)
    return false;

  InputMethodController& input_method_controller =
      frame->GetInputMethodController();
  input_method_controller.SetEditableSelectionOffsets(
      PlainTextRange(gesture_text_index, gesture_text_index));
  frame->GetEditor().InsertText(text_to_insert_,
                                /* triggering_event = */ nullptr);
  return true;
}

StylusWritingGestureSplitOrMerge::StylusWritingGestureSplitOrMerge(
    const gfx::Rect& start_rect,
    const String& text_alternative)
    : StylusWritingGesture(start_rect, text_alternative) {}

bool StylusWritingGestureSplitOrMerge::MaybeApplyGesture(LocalFrame* frame) {
  wtf_size_t gesture_text_index = GetStartTextIndex(frame);
  // When the gesture point is outside the input text range, we get a kNotFound.
  // Return false here to insert the text alternative.
  if (gesture_text_index == kNotFound) {
    return false;
  }

  InputMethodController& input_method_controller =
      frame->GetInputMethodController();
  String input_text = input_method_controller.TextInputInfo().value;
  // Gesture cannot be applied if there is no input text.
  if (input_text.empty()) {
    return false;
  }

  // Look for spaces on both side of gesture index.
  wtf_size_t space_start = kNotFound;
  wtf_size_t space_end = kNotFound;
  for (wtf_size_t index = gesture_text_index;
       index < input_text.length() && IsHTMLSpace(input_text[index]); ++index) {
    if (space_start == kNotFound) {
      space_start = index;
    }
    space_end = index + 1;
  }

  for (wtf_size_t index = gesture_text_index;
       index && IsHTMLSpace(input_text[index - 1]); --index) {
    if (space_end == kNotFound) {
      space_end = index;
    }
    space_start = index - 1;
  }

  // No spaces found.
  if (space_start == space_end) {
    // Do not insert space at start of the input text.
    if (gesture_text_index == 0) {
      return false;
    }

    // Insert space at gesture location.
    input_method_controller.SetEditableSelectionOffsets(
        PlainTextRange(gesture_text_index, gesture_text_index));
    frame->GetEditor().InsertText(" ", /* triggering_event = */ nullptr);
    return true;
  }

  // Remove spaces found.
  input_method_controller.ReplaceTextAndMoveCaret(
      "", PlainTextRange(space_start, space_end),
      InputMethodController::MoveCaretBehavior::kDoNotMove);
  input_method_controller.SetEditableSelectionOffsets(
      PlainTextRange(space_start, space_start));
  return true;
}

}  // namespace blink
```