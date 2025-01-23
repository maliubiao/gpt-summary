Response:
Let's break down the thought process for analyzing this C++ file and generating the response.

1. **Understand the Goal:** The request asks for the functionality of the `FrameWidgetInputHandlerImpl.cc` file within the Chromium Blink rendering engine. It also specifically asks for connections to JavaScript, HTML, CSS, logical reasoning with examples, and potential user/programming errors.

2. **Initial Skim for Core Functionality:**  Read through the file quickly to get a general idea. Keywords like "input," "handler," "IME," "selection," "edit command," and `RunOnMainThread` stand out. This suggests the file is responsible for handling input events and manipulating the content of a web page. The "Impl" suffix often indicates an implementation class for an interface (likely `FrameWidgetInputHandler`).

3. **Identify Key Classes and Data Structures:** Note the classes being used:
    * `FrameWidgetInputHandlerImpl`: The main class.
    * `WidgetBase`:  Represents a basic UI element, likely the frame itself.
    * `mojom::blink::FrameWidgetInputHandler`:  A Mojo interface, suggesting communication between processes or threads.
    * `MainThreadEventQueue`:  Handles queuing tasks for the main thread.
    * `ui::ImeTextSpan`:  Related to input method editor functionality.
    * `gfx::Point`: Represents screen coordinates.
    * `mojom::blink::StylusWritingGestureDataPtr`, `mojom::blink::HandwritingGestureResult`:  Related to stylus input.

4. **Analyze Individual Methods:**  Go through each method and determine its purpose:
    * **Constructor/Destructor:** Standard lifecycle management.
    * `RunOnMainThread`:  Crucial for understanding threading. It ensures certain operations happen on the main thread, which is essential for interacting with the DOM.
    * **IME-related methods (`AddImeTextSpansToExistingText`, `ClearImeTextSpansByType`, `SetCompositionFromExistingText`):**  Handle input method interactions, like displaying candidate characters.
    * **Selection Manipulation methods (`ExtendSelectionAndDelete`, `ExtendSelectionAndReplace`, `DeleteSurroundingText`, `DeleteSurroundingTextInCodePoints`, `SetEditableSelectionOffsets`, `SelectRange`, `SelectAroundCaret`, `AdjustSelectionByCharacterOffset`, `MoveRangeSelectionExtent`, `CollapseSelection`):**  Functions to change the selected text on the page.
    * **Editing Command methods (`ExecuteEditCommand`, `Undo`, `Redo`, `Cut`, `Copy`, `Paste`, `PasteAndMatchStyle`, `Replace`, `ReplaceMisspelling`, `Delete`, `SelectAll`):**  Standard editing operations.
    * **Stylus Gesture Handling (`HandleStylusWritingGestureAction`):** Specific to stylus input.
    * **Miscellaneous (`CenterSelection`, `CopyToFindPboard`, `ScrollFocusedEditableNodeIntoView`, `WaitForPageScaleAnimationForTesting`, `MoveCaret`):** Other functionalities related to view manipulation and testing.
    * `ExecuteCommandOnMainThread`: A helper function to execute editing commands on the main thread.
    * `HandlingState`: A helper class for managing the state of the `WidgetBase` during certain operations.

5. **Identify Relationships with Web Technologies:**
    * **JavaScript:**  Many of these functions are triggered by JavaScript events or API calls. For example, selecting text via mouse drag (handled by `SelectRange`) or using JavaScript's `document.execCommand()` (related to `ExecuteEditCommand`).
    * **HTML:** The actions performed by these functions directly manipulate the content and structure of the HTML document. Inserting text, deleting text, and changing selections all affect the underlying HTML.
    * **CSS:** While this file doesn't directly manipulate CSS styles, some of its actions can indirectly trigger CSS changes (e.g., selecting text might change the background color based on CSS rules). `PasteAndMatchStyle` explicitly aims to preserve styling.

6. **Consider Logical Reasoning and Examples:** For each major functional area (IME, selection, editing commands), think about typical user interactions and how this code might be involved. Create simple scenarios with inputs and expected outputs.

7. **Think About Potential Errors:**  Consider common mistakes developers might make or how users might encounter unexpected behavior.
    * **WeakPtr issues:** The code uses `base::WeakPtr`, which can become invalid if the referenced object is destroyed. This is a common source of errors.
    * **Threading issues:**  Incorrectly calling methods that should run on the main thread from a different thread can lead to crashes or undefined behavior.
    * **Incorrect parameter usage:**  Passing invalid start/end offsets for selection or IME operations.

8. **Structure the Response:** Organize the information logically. Start with a general overview of the file's purpose. Then, break down the functionalities into categories (IME, selection, editing, etc.). Provide specific examples for the connections to JavaScript, HTML, and CSS. Clearly present the logical reasoning with input/output examples. Finally, list potential errors.

9. **Refine and Elaborate:**  Review the generated response for clarity, accuracy, and completeness. Add details and explanations where needed. For example, explaining *why* certain operations need to happen on the main thread is important. Similarly, elaborating on the role of Mojo interfaces enhances understanding.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just handles input events."  **Correction:**  It's more than just *receiving* events; it's about *processing* them and triggering actions that modify the DOM and UI.
* **Initial thought:**  Focus heavily on the individual methods. **Correction:**  Group related methods to provide a higher-level understanding of the functionalities (e.g., grouping all the selection-related methods).
* **Initial thought:**  Only mention direct interactions with JS/HTML/CSS. **Correction:**  Also consider indirect interactions and the *purpose* of these C++ functions in the broader web development context.
* **Initial thought:**  Provide very technical explanations. **Correction:**  Balance technical detail with explanations that are understandable to someone with a general understanding of web development. Use clear and concise language.

By following these steps, with iterations and refinements, you can generate a comprehensive and informative response like the example provided. The key is to move from a general understanding to a detailed analysis, while constantly considering the context and the intended audience of the explanation.
这个C++源代码文件 `frame_widget_input_handler_impl.cc` 是 Chromium Blink 渲染引擎中处理输入事件的一个关键组件。它的主要功能是 **将来自浏览器进程的输入事件（例如键盘输入、鼠标点击、触摸事件等）转发到主线程的 `FrameWidget` 对象进行处理**。 这是一个在渲染进程中，特别是在合成器线程（如果启用）和主线程之间协调输入处理的关键类。

**以下是它的具体功能列表：**

1. **线程安全地将输入操作转发到主线程:**
   - 该类的大部分方法都使用 `RunOnMainThread` 函数来确保输入相关的操作在 Blink 渲染引擎的主线程上执行。这是因为 Blink 的 DOM 和 JavaScript 环境只能在主线程上安全地访问和修改。
   - 它使用了 `MainThreadEventQueue` 来在合成器线程（或任何调用此方法的线程）和主线程之间排队和传递闭包 (closures)。

2. **处理输入法编辑器 (IME) 相关的操作:**
   - `AddImeTextSpansToExistingText`: 将 IME 文本跨度添加到现有文本中，用于高亮显示或标记候选词。
   - `ClearImeTextSpansByType`: 清除指定类型的 IME 文本跨度。
   - `SetCompositionFromExistingText`: 从现有文本设置输入法组合字符串。
   - `ExtendSelectionAndDelete`, `ExtendSelectionAndReplace`, `DeleteSurroundingText`, `DeleteSurroundingTextInCodePoints`:  这些方法涉及到在 IME 输入过程中，根据用户的输入删除或替换文本。

3. **处理文本选择和光标操作:**
   - `SetEditableSelectionOffsets`: 设置可编辑区域的选择偏移量。
   - `HandleStylusWritingGestureAction`: 处理手写笔输入手势。
   - `SelectRange`:  选择指定范围的文本。
   - `SelectAroundCaret`:  围绕光标选择文本，例如选择单词或句子。
   - `AdjustSelectionByCharacterOffset`:  按字符偏移调整选择范围。
   - `MoveRangeSelectionExtent`: 移动范围选择的终点。
   - `CollapseSelection`: 折叠当前的选择。
   - `MoveCaret`: 移动文本光标到指定位置。

4. **处理编辑命令:**
   - `ExecuteEditCommand`: 执行各种编辑命令，例如插入文本、删除文本等。
   - `Undo`, `Redo`, `Cut`, `Copy`, `Paste`, `PasteAndMatchStyle`, `Replace`, `ReplaceMisspelling`, `Delete`, `SelectAll`:  这些都是常见的编辑操作，它们最终会调用 `ExecuteEditCommand` 在主线程上执行。
   - `CopyToFindPboard`: 将选定的文本复制到查找剪贴板 (macOS 特有)。
   - `CenterSelection`: 将选择的文本滚动到视图中心。

5. **处理与视图相关的操作:**
   - `ScrollFocusedEditableNodeIntoView`: 将焦点所在的可编辑节点滚动到视图中。
   - `WaitForPageScaleAnimationForTesting`:  用于测试，等待页面缩放动画完成。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件本身不直接操作 JavaScript, HTML, 或 CSS 的代码，但它是连接用户输入和这些 Web 技术之间的桥梁。 用户在网页上的操作会触发浏览器事件，这些事件会被传递到这个类进行处理，最终导致 HTML 内容的改变、JavaScript 代码的执行或者 CSS 样式的应用。

* **JavaScript:**
    - **举例:** 当用户在一个 `<input>` 元素中输入文本时，键盘事件首先被浏览器捕获，然后通过消息传递到达 `FrameWidgetInputHandlerImpl`。 这个类会将 IME 相关的操作（例如，显示候选词）转发到主线程。最终，主线程上的 JavaScript 代码可能会监听 `input` 事件，并根据用户的输入执行相应的逻辑。例如，一个自动完成功能的 JavaScript 代码会根据用户的输入向服务器发送请求。
    - **假设输入:** 用户在输入框中输入 "你好" 的拼音 "nihao"，并且 IME 显示了候选词。
    - **输出:** `FrameWidgetInputHandlerImpl` 会调用 `AddImeTextSpansToExistingText` 或 `SetCompositionFromExistingText` 等方法，指示 `FrameWidget` 在输入框中显示拼音和候选词。 用户选择候选词后，会调用 `ExtendSelectionAndReplace` 将拼音替换为汉字。 JavaScript 可能会监听到 `input` 事件并执行进一步的操作。

* **HTML:**
    - **举例:** 当用户使用鼠标拖拽选中一段文本时，鼠标事件被捕获并传递到 `FrameWidgetInputHandlerImpl`。 该类会调用 `SelectRange` 方法，最终导致 `FrameWidget` 更新 HTML 中文本的选择状态。浏览器会根据选择状态高亮显示 HTML 文本。
    - **假设输入:** 用户用鼠标从 HTML 文档中选中了一段文字。
    - **输出:** `FrameWidgetInputHandlerImpl` 的 `SelectRange` 方法会被调用，并将选区的起始和结束坐标传递给主线程的 `FrameWidget`。`FrameWidget` 会更新内部的选区表示，浏览器会根据这个选区信息来渲染高亮显示的文本。

* **CSS:**
    - **举例:** 虽然这个类不直接操作 CSS，但用户输入导致的选择变化会触发浏览器应用不同的 CSS 样式。例如，选中的文本通常会有一个不同的背景颜色和文本颜色，这些样式是通过 CSS 定义的。
    - **假设输入:** 用户通过双击选中一个单词。
    - **输出:** `FrameWidgetInputHandlerImpl` 会调用相应的选择方法，更新选区。浏览器会根据预定义的 CSS 规则，为选中的单词应用高亮样式。

**逻辑推理和假设输入与输出:**

假设用户在一个可编辑的 `<div>` 元素中进行输入。

* **假设输入:** 用户按下键盘上的字母键 'a'。
* **逻辑推理:**
    1. 键盘事件被操作系统捕获。
    2. 浏览器进程接收到键盘事件。
    3. 浏览器进程将键盘事件传递给渲染进程的 `FrameWidgetInputHandlerImpl`。
    4. `FrameWidgetInputHandlerImpl` 调用 `RunOnMainThread` 将一个闭包添加到主线程的 `MainThreadEventQueue` 中。
    5. 主线程从队列中取出闭包并执行。
    6. 闭包中会调用主线程 `FrameWidget` 的相应方法来处理键盘输入，例如插入字符 'a' 到当前光标位置。
    7. `FrameWidget` 会更新其内部表示的 HTML 结构。
    8. 渲染引擎会重新渲染页面，显示新插入的字符 'a'。
* **输出:**  在网页上，光标所在的位置会显示字母 'a'。

**用户或编程常见的使用错误举例:**

1. **在非主线程直接访问 DOM 或 JavaScript 对象:**  `FrameWidgetInputHandlerImpl` 的设计初衷就是为了避免这种情况。 如果开发者尝试在其他线程直接修改 DOM，会导致数据竞争和崩溃。这就是为什么所有关键操作都通过 `RunOnMainThread` 转发到主线程。

2. **不正确的选择范围计算:** 在使用例如 `SetEditableSelectionOffsets` 或 `SelectRange` 等方法时，如果传递的起始和结束偏移量超出了文本的范围，或者起始位置大于结束位置，可能会导致不可预测的行为或者崩溃。

   - **举例:** 假设一个文本框只有 10 个字符，开发者错误地调用 `SetEditableSelectionOffsets(5, 15)`，尝试选择超出范围的文本。这可能导致程序错误或崩溃。

3. **在不应该调用回调时调用了回调:** 像 `HandleStylusWritingGestureAction` 和 `SelectAroundCaret` 这样的方法会接收回调函数。如果在 `handler` 为空的情况下仍然尝试执行回调，可能会导致程序崩溃。代码中已经有针对 `handler` 为空时的检查，并执行 `std::move(callback).Run(...)` 来确保回调被执行，即使操作失败，避免内存泄漏。

4. **对 `WeakPtr` 的生命周期管理不当:**  `FrameWidgetInputHandlerImpl` 持有 `WidgetBase` 和 `mojom::blink::FrameWidgetInputHandler` 的 `WeakPtr`。 如果这些对象在 `FrameWidgetInputHandlerImpl` 尝试访问它们之前被销毁，那么 `WeakPtr::get()` 会返回 `nullptr`，需要进行判空处理以避免解引用空指针。代码中可以看到大量的 `if (!widget)` 和 `if (handler)` 检查来避免这种情况。

总而言之，`frame_widget_input_handler_impl.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责协调和处理用户输入，确保这些操作能够安全有效地影响网页的内容和交互。它通过线程安全的机制将输入事件传递到主线程，最终驱动 JavaScript 的执行、HTML 的修改和 CSS 样式的应用。

### 提示词
```
这是目录为blink/renderer/platform/widget/input/frame_widget_input_handler_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/frame_widget_input_handler_impl.h"

#include <utility>

#include "base/check.h"
#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "third_party/blink/public/mojom/input/handwriting_gesture_result.mojom-blink.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/widget/input/ime_event_guard.h"
#include "third_party/blink/renderer/platform/widget/input/main_thread_event_queue.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "third_party/blink/renderer/platform/widget/widget_base_client.h"

namespace blink {

FrameWidgetInputHandlerImpl::FrameWidgetInputHandlerImpl(
    base::WeakPtr<WidgetBase> widget,
    base::WeakPtr<mojom::blink::FrameWidgetInputHandler>
        frame_widget_input_handler,
    scoped_refptr<MainThreadEventQueue> input_event_queue)
    : widget_(std::move(widget)),
      main_thread_frame_widget_input_handler_(
          std::move(frame_widget_input_handler)),
      input_event_queue_(input_event_queue) {}

FrameWidgetInputHandlerImpl::~FrameWidgetInputHandlerImpl() = default;

void FrameWidgetInputHandlerImpl::RunOnMainThread(base::OnceClosure closure) {
  if (ThreadedCompositingEnabled()) {
    input_event_queue_->QueueClosure(std::move(closure));
  } else {
    std::move(closure).Run();
  }
}

void FrameWidgetInputHandlerImpl::AddImeTextSpansToExistingText(
    uint32_t start,
    uint32_t end,
    const Vector<ui::ImeTextSpan>& ui_ime_text_spans) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         uint32_t start, uint32_t end,
         const Vector<ui::ImeTextSpan>& ui_ime_text_spans) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        ImeEventGuard guard(widget);
        handler->AddImeTextSpansToExistingText(start, end, ui_ime_text_spans);
      },
      widget_, main_thread_frame_widget_input_handler_, start, end,
      ui_ime_text_spans));
}

void FrameWidgetInputHandlerImpl::ClearImeTextSpansByType(
    uint32_t start,
    uint32_t end,
    ui::ImeTextSpan::Type type) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         uint32_t start, uint32_t end, ui::ImeTextSpan::Type type) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        ImeEventGuard guard(widget);
        handler->ClearImeTextSpansByType(start, end, type);
      },
      widget_, main_thread_frame_widget_input_handler_, start, end, type));
}

void FrameWidgetInputHandlerImpl::SetCompositionFromExistingText(
    int32_t start,
    int32_t end,
    const Vector<ui::ImeTextSpan>& ui_ime_text_spans) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         int32_t start, int32_t end,
         const Vector<ui::ImeTextSpan>& ui_ime_text_spans) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        ImeEventGuard guard(widget);
        handler->SetCompositionFromExistingText(start, end, ui_ime_text_spans);
      },
      widget_, main_thread_frame_widget_input_handler_, start, end,
      ui_ime_text_spans));
}

void FrameWidgetInputHandlerImpl::ExtendSelectionAndDelete(int32_t before,
                                                           int32_t after) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         int32_t before, int32_t after) {
        if (handler)
          handler->ExtendSelectionAndDelete(before, after);
      },
      main_thread_frame_widget_input_handler_, before, after));
}

void FrameWidgetInputHandlerImpl::ExtendSelectionAndReplace(
    uint32_t before,
    uint32_t after,
    const String& replacement_text) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         uint32_t before, uint32_t after, const String& replacement_text) {
        if (handler) {
          handler->ExtendSelectionAndReplace(before, after, replacement_text);
        }
      },
      main_thread_frame_widget_input_handler_, before, after,
      replacement_text));
}

void FrameWidgetInputHandlerImpl::DeleteSurroundingText(int32_t before,
                                                        int32_t after) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         int32_t before, int32_t after) {
        if (handler)
          handler->DeleteSurroundingText(before, after);
      },
      main_thread_frame_widget_input_handler_, before, after));
}

void FrameWidgetInputHandlerImpl::DeleteSurroundingTextInCodePoints(
    int32_t before,
    int32_t after) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         int32_t before, int32_t after) {
        if (handler)
          handler->DeleteSurroundingTextInCodePoints(before, after);
      },
      main_thread_frame_widget_input_handler_, before, after));
}

void FrameWidgetInputHandlerImpl::SetEditableSelectionOffsets(int32_t start,
                                                              int32_t end) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         int32_t start, int32_t end) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        HandlingState handling_state(widget, UpdateState::kIsSelectingRange);
        handler->SetEditableSelectionOffsets(start, end);
      },
      widget_, main_thread_frame_widget_input_handler_, start, end));
}

void FrameWidgetInputHandlerImpl::HandleStylusWritingGestureAction(
    mojom::blink::StylusWritingGestureDataPtr gesture_data,
    HandleStylusWritingGestureActionCallback callback) {
  if (ThreadedCompositingEnabled()) {
    callback = base::BindOnce(
        [](scoped_refptr<base::SingleThreadTaskRunner> callback_task_runner,
           HandleStylusWritingGestureActionCallback callback,
           mojom::blink::HandwritingGestureResult result) {
          callback_task_runner->PostTask(
              FROM_HERE,
              base::BindOnce(std::move(callback), std::move(result)));
        },
        base::SingleThreadTaskRunner::GetCurrentDefault(), std::move(callback));
  }

  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         mojom::blink::StylusWritingGestureDataPtr gesture_data,
         HandleStylusWritingGestureActionCallback callback) {
        if (handler) {
          handler->HandleStylusWritingGestureAction(std::move(gesture_data),
                                                    std::move(callback));
        } else {
          std::move(callback).Run(
              mojom::blink::HandwritingGestureResult::kFailed);
        }
      },
      main_thread_frame_widget_input_handler_, std::move(gesture_data),
      std::move(callback)));
}

void FrameWidgetInputHandlerImpl::ExecuteEditCommand(const String& command,
                                                     const String& value) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         const String& command, const String& value) {
        if (handler)
          handler->ExecuteEditCommand(command, value);
      },
      main_thread_frame_widget_input_handler_, command, value));
}

void FrameWidgetInputHandlerImpl::Undo() {
  RunOnMainThread(base::BindOnce(
      &FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread, widget_,
      main_thread_frame_widget_input_handler_, "Undo", UpdateState::kNone));
}

void FrameWidgetInputHandlerImpl::Redo() {
  RunOnMainThread(base::BindOnce(
      &FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread, widget_,
      main_thread_frame_widget_input_handler_, "Redo", UpdateState::kNone));
}

void FrameWidgetInputHandlerImpl::Cut() {
  RunOnMainThread(
      base::BindOnce(&FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread,
                     widget_, main_thread_frame_widget_input_handler_, "Cut",
                     UpdateState::kIsSelectingRange));
}

void FrameWidgetInputHandlerImpl::Copy() {
  RunOnMainThread(
      base::BindOnce(&FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread,
                     widget_, main_thread_frame_widget_input_handler_, "Copy",
                     UpdateState::kIsSelectingRange));
}

void FrameWidgetInputHandlerImpl::CopyToFindPboard() {
#if BUILDFLAG(IS_MAC)
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler) {
        if (handler)
          handler->CopyToFindPboard();
      },
      main_thread_frame_widget_input_handler_));
#endif
}

void FrameWidgetInputHandlerImpl::CenterSelection() {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler) {
        if (handler) {
          handler->CenterSelection();
        }
      },
      main_thread_frame_widget_input_handler_));
}

void FrameWidgetInputHandlerImpl::Paste() {
  RunOnMainThread(
      base::BindOnce(&FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread,
                     widget_, main_thread_frame_widget_input_handler_, "Paste",
                     UpdateState::kIsPasting));
}

void FrameWidgetInputHandlerImpl::PasteAndMatchStyle() {
  RunOnMainThread(
      base::BindOnce(&FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread,
                     widget_, main_thread_frame_widget_input_handler_,
                     "PasteAndMatchStyle", UpdateState::kIsPasting));
}

void FrameWidgetInputHandlerImpl::Replace(const String& word) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         const String& word) {
        if (handler)
          handler->Replace(word);
      },
      main_thread_frame_widget_input_handler_, word));
}

void FrameWidgetInputHandlerImpl::ReplaceMisspelling(const String& word) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         const String& word) {
        if (handler)
          handler->ReplaceMisspelling(word);
      },
      main_thread_frame_widget_input_handler_, word));
}

void FrameWidgetInputHandlerImpl::Delete() {
  RunOnMainThread(base::BindOnce(
      &FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread, widget_,
      main_thread_frame_widget_input_handler_, "Delete", UpdateState::kNone));
}

void FrameWidgetInputHandlerImpl::SelectAll() {
  RunOnMainThread(
      base::BindOnce(&FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread,
                     widget_, main_thread_frame_widget_input_handler_,
                     "SelectAll", UpdateState::kIsSelectingRange));
}

void FrameWidgetInputHandlerImpl::CollapseSelection() {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        HandlingState handling_state(widget, UpdateState::kIsSelectingRange);
        handler->CollapseSelection();
      },
      widget_, main_thread_frame_widget_input_handler_));
}

void FrameWidgetInputHandlerImpl::SelectRange(const gfx::Point& base,
                                              const gfx::Point& extent) {
  // TODO(dtapuska): This event should be coalesced. Chrome IPC uses
  // one outstanding event and an ACK to handle coalescing on the browser
  // side. We should be able to clobber them in the main thread event queue.
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         const gfx::Point& base, const gfx::Point& extent) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        HandlingState handling_state(widget, UpdateState::kIsSelectingRange);
        handler->SelectRange(base, extent);
      },
      widget_, main_thread_frame_widget_input_handler_, base, extent));
}

void FrameWidgetInputHandlerImpl::SelectAroundCaret(
    mojom::blink::SelectionGranularity granularity,
    bool should_show_handle,
    bool should_show_context_menu,
    SelectAroundCaretCallback callback) {
  // If the mojom channel is registered with compositor thread, we have to run
  // the callback on compositor thread. Otherwise run it on main thread. Mojom
  // requires the callback runs on the same thread.
  if (ThreadedCompositingEnabled()) {
    callback = base::BindOnce(
        [](scoped_refptr<base::SingleThreadTaskRunner> callback_task_runner,
           SelectAroundCaretCallback callback,
           mojom::blink::SelectAroundCaretResultPtr result) {
          callback_task_runner->PostTask(
              FROM_HERE,
              base::BindOnce(std::move(callback), std::move(result)));
        },
        base::SingleThreadTaskRunner::GetCurrentDefault(), std::move(callback));
  }

  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         mojom::blink::SelectionGranularity granularity,
         bool should_show_handle, bool should_show_context_menu,
         SelectAroundCaretCallback callback) {
        if (handler) {
          handler->SelectAroundCaret(granularity, should_show_handle,
                                     should_show_context_menu,
                                     std::move(callback));
        } else {
          std::move(callback).Run(std::move(nullptr));
        }
      },
      main_thread_frame_widget_input_handler_, granularity, should_show_handle,
      should_show_context_menu, std::move(callback)));
}

void FrameWidgetInputHandlerImpl::AdjustSelectionByCharacterOffset(
    int32_t start,
    int32_t end,
    blink::mojom::SelectionMenuBehavior selection_menu_behavior) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         int32_t start, int32_t end,
         blink::mojom::SelectionMenuBehavior selection_menu_behavior) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        HandlingState handling_state(widget, UpdateState::kIsSelectingRange);
        handler->AdjustSelectionByCharacterOffset(start, end,
                                                  selection_menu_behavior);
      },
      widget_, main_thread_frame_widget_input_handler_, start, end,
      selection_menu_behavior));
}

void FrameWidgetInputHandlerImpl::MoveRangeSelectionExtent(
    const gfx::Point& extent) {
  // TODO(dtapuska): This event should be coalesced. Chrome IPC uses
  // one outstanding event and an ACK to handle coalescing on the browser
  // side. We should be able to clobber them in the main thread event queue.
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<WidgetBase> widget,
         base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         const gfx::Point& extent) {
        DCHECK_EQ(!!widget, !!handler);
        if (!widget)
          return;
        HandlingState handling_state(widget, UpdateState::kIsSelectingRange);
        handler->MoveRangeSelectionExtent(extent);
      },
      widget_, main_thread_frame_widget_input_handler_, extent));
}

void FrameWidgetInputHandlerImpl::ScrollFocusedEditableNodeIntoView() {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler) {
        if (handler)
          handler->ScrollFocusedEditableNodeIntoView();
      },
      main_thread_frame_widget_input_handler_));
}

void FrameWidgetInputHandlerImpl::WaitForPageScaleAnimationForTesting(
    WaitForPageScaleAnimationForTestingCallback callback) {
  // Ensure the Mojo callback is invoked from the thread on which the message
  // was received.
  if (ThreadedCompositingEnabled()) {
    callback = base::BindOnce(
        [](scoped_refptr<base::SingleThreadTaskRunner> callback_task_runner,
           WaitForPageScaleAnimationForTestingCallback callback) {
          callback_task_runner->PostTask(FROM_HERE,
                                         base::BindOnce(std::move(callback)));
        },
        base::SingleThreadTaskRunner::GetCurrentDefault(), std::move(callback));
  }

  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         WaitForPageScaleAnimationForTestingCallback callback) {
        if (handler)
          handler->WaitForPageScaleAnimationForTesting(std::move(callback));
        else
          std::move(callback).Run();
      },
      main_thread_frame_widget_input_handler_, std::move(callback)));
}

void FrameWidgetInputHandlerImpl::MoveCaret(const gfx::Point& point) {
  RunOnMainThread(base::BindOnce(
      [](base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
         const gfx::Point& point) {
        if (handler)
          handler->MoveCaret(point);
      },
      main_thread_frame_widget_input_handler_, point));
}

void FrameWidgetInputHandlerImpl::ExecuteCommandOnMainThread(
    base::WeakPtr<WidgetBase> widget,
    base::WeakPtr<mojom::blink::FrameWidgetInputHandler> handler,
    const char* command,
    UpdateState update_state) {
  DCHECK_EQ(!!widget, !!handler);
  if (!widget)
    return;
  HandlingState handling_state(widget, update_state);
  handler->ExecuteEditCommand(command, String());
}

FrameWidgetInputHandlerImpl::HandlingState::HandlingState(
    const base::WeakPtr<WidgetBase>& widget,
    UpdateState state)
    : widget_(widget),
      original_select_range_value_(widget->handling_select_range()),
      original_pasting_value_(widget->is_pasting()) {
  switch (state) {
    case UpdateState::kIsPasting:
      widget->set_is_pasting(true);
      [[fallthrough]];  // Set both
    case UpdateState::kIsSelectingRange:
      widget->set_handling_select_range(true);
      break;
    case UpdateState::kNone:
      break;
  }
}

FrameWidgetInputHandlerImpl::HandlingState::~HandlingState() {
  // FrameWidget may have been destroyed while this object was on the stack.
  if (!widget_)
    return;
  widget_->set_handling_select_range(original_select_range_value_);
  widget_->set_is_pasting(original_pasting_value_);
}

}  // namespace blink
```