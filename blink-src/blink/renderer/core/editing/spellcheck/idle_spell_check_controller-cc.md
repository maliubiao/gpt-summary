Response:
Let's break down the thought process to analyze this C++ code for the `IdleSpellCheckController`.

**1. Initial Reading and Identifying the Core Purpose:**

The name `IdleSpellCheckController` strongly suggests this class manages spell checking, specifically when the browser is idle. The file path `blink/renderer/core/editing/spellcheck/` confirms this. The "idle" part hints at optimizing spell checking to avoid impacting user interaction.

**2. Identifying Key Dependencies and Members:**

Scanning the `#include` directives reveals dependencies:

* **`base/time/time.h`**:  Time-related operations, likely for delays and timeouts.
* **`third_party/blink/public/platform/task_type.h`**: Task scheduling, indicating asynchronous operations.
* **`third_party/blink/renderer/bindings/core/v8/v8_idle_request_options.h`**: Interaction with the JavaScript engine's idle API. This is a significant clue about the integration.
* **Editing-related headers (`commands`, `editing_utilities`, `editor`, `ephemeral_range`, `frame_selection`, `iterators`, `selection_template`, `visible_selection`, `visible_units`):** Core text editing functionality within Blink.
* **Spellcheck-specific headers (`cold_mode_spell_check_requester.h`, `hot_mode_spell_check_requester.h`, `spell_check_requester.h`, `spell_checker.h`):**  The heart of the spell checking logic, suggesting different strategies (cold vs. hot).
* **Frame-related headers (`local_dom_window.h`, `local_frame.h`):**  Integration with the browser's frame structure.
* **`scheduler/scripted_idle_task_controller.h`**:  Direct interaction with the browser's idle task scheduling mechanism.

Looking at the class members:

* **`idle_callback_handle_`**:  Likely used to manage the registration and cancellation of idle callbacks.
* **`cold_mode_requester_`**: Handles "cold mode" spell checking, probably a more comprehensive, background check.
* **`spell_check_requeseter_`**: A general spell check requester, potentially used by both cold and hot modes.
* **`cold_mode_timer_`**:  A timer specifically for the cold mode, suggesting periodic checks.
* **`state_`**:  An enumeration (`State`) to track the current state of the controller (inactive, hot mode, cold mode, etc.).
* **`needs_invocation_...` flags**: Indicate reasons for triggering a spell check.
* **`last_processed_undo_step_sequence_`**:  Keeps track of which undo steps have been considered for spell checking.

**3. Understanding the Core Workflow (Hot vs. Cold):**

The names "hot mode" and "cold mode" suggest different approaches to spell checking:

* **Hot Mode:** Triggered by immediate user actions like typing or selection changes. It seems to focus on the currently edited area and recent undo steps. The timeout `kHotModeRequestTimeoutMS` reinforces this immediate nature. The connection to `IdleRequestOptions` indicates it's leveraging the browser's idle API but with a short timeout, suggesting it should run quickly.

* **Cold Mode:** Likely a more comprehensive, background check. The timers (`kColdModeTimerInterval`, `kConsecutiveColdModeTimerInterval`) point to periodic execution. The goal is to cover areas not immediately affected by user input.

**4. Tracing User Interactions and Debugging:**

The methods like `RespondToChangedSelection`, `RespondToChangedContents`, and `RespondToChangedEnablement` are key entry points. Thinking about how a user interacts with a text field:

* **Typing:** Triggers `RespondToChangedContents`.
* **Selecting Text:** Triggers `RespondToChangedSelection`.
* **Enabling/Disabling Spell Check (via browser settings or context menu):** Triggers `RespondToChangedEnablement`.
* **Undoing/Redoing:** The `HotModeInvocation` iterates through recent undo steps.

The `SetNeedsInvocation` and `SetNeedsColdModeInvocation` methods act as triggers, and the idle callbacks are the actual execution mechanisms.

**5. Identifying Potential Issues and Edge Cases:**

* **Performance:**  Excessive or poorly timed spell checking can impact performance. The idle mechanism is designed to mitigate this, but configuration and logic within the controller are important.
* **Race Conditions:**  Handling concurrent events (typing while an idle check is running) needs careful management, likely addressed by the state machine and the cancellation of idle callbacks.
* **Undo Stack Handling:**  Incorrectly processing undo steps could lead to missed or redundant spell checks.

**6. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The crucial link here is `ScriptedIdleTaskController` and `IdleRequestOptions`. This directly relates to the JavaScript `requestIdleCallback` API. Therefore:

* **JavaScript:**  A web page's JavaScript can indirectly influence this by triggering re-renders or content changes, which in turn trigger the controller's methods. However, the *direct* interaction is through the browser's idle scheduling mechanism.
* **HTML:** The structure of the HTML (especially editable elements) determines where spell checking is applied.
* **CSS:**  CSS styles don't directly trigger spell checking, but they can affect the layout and visibility of text, which indirectly influences what needs to be checked.

**7. Logical Inferences and Assumptions:**

The "assumptions" made in the prompt are actually logical deductions based on the code:

* **Assumption about input/output:**  This is inferred from the purpose. Input is text content, output is marking spelling errors (though the *controller* itself doesn't do the marking; it *requests* the check).
* **Assumption about user errors:** These come from understanding how the system is intended to work and where things could go wrong.

**Self-Correction/Refinement:**

Initially, one might focus too much on the low-level C++ details. The key is to abstract and understand the *purpose* and *interactions*. Recognizing the connection to `requestIdleCallback` is a critical step in understanding the JavaScript relationship. Also, distinguishing between the controller's role (managing the *timing* and *triggering* of checks) and the `SpellCheckRequester`'s role (actually performing the spell check) is important.
好的，让我们详细分析一下 `idle_spell_check_controller.cc` 文件的功能。

**功能概述**

`IdleSpellCheckController` 的主要职责是在 Chromium Blink 渲染引擎中，**利用浏览器空闲时间执行拼写检查**。 它的目标是在不影响用户交互性能的前提下，异步地完成拼写检查任务。

**核心功能点：**

1. **管理拼写检查的时机：** 该控制器决定何时启动拼写检查，利用浏览器的空闲时间，避免在用户正在输入或进行其他操作时进行，从而优化用户体验。
2. **区分“热模式”和“冷模式”拼写检查：**
   - **热模式 (Hot Mode):**  当用户进行编辑操作（例如输入、删除、移动光标）或启用/禁用拼写检查时触发。它专注于检查用户刚刚编辑或光标所在的区域以及最近的 undo 操作涉及的区域。这种模式响应迅速，针对性强。
   - **冷模式 (Cold Mode):**  在浏览器空闲时进行，用于检查当前可编辑区域中尚未检查过的部分。它是一种更全面的后台检查，确保整个可编辑区域都被覆盖到。
3. **利用 `requestIdleCallback` API：**  `IdleSpellCheckController` 核心是通过 `ScriptedIdleTaskController` 注册 idle callback，利用浏览器的 `requestIdleCallback` 机制。当浏览器空闲时，注册的回调函数会被调用，执行拼写检查任务。
4. **管理拼写检查请求：**  它与 `ColdModeSpellCheckRequester` 和 `HotModeSpellCheckRequester` 协作，实际发起拼写检查请求。
5. **处理选择和内容变化：**  监听文本选择和内容的变化，根据这些变化触发相应的拼写检查模式。
6. **与 Undo 栈集成：**  在热模式下，会检查最近的 Undo 操作涉及的文本，确保即使是撤销操作也触发拼写检查。
7. **状态管理：**  维护内部状态（例如 `kInactive`, `kHotModeRequested`, `kColdModeRequested` 等），用于跟踪当前的拼写检查状态，避免重复或不必要的检查。

**与 JavaScript, HTML, CSS 的关系**

`IdleSpellCheckController` 虽然是 C++ 代码，但它与 Web 技术 JavaScript 和 HTML 有着密切的联系：

* **JavaScript (通过 `requestIdleCallback`)：**  `IdleSpellCheckController` 利用了 JavaScript 的 `requestIdleCallback` API (在 Blink 内部通过 `ScriptedIdleTaskController` 实现)。
    * **举例：** 当网页加载完成，并且没有其他高优先级的任务时，浏览器会调用 `IdleSpellCheckController` 注册的 idle callback，启动冷模式拼写检查。这就像 JavaScript 代码中使用 `requestIdleCallback` 来执行一些低优先级的任务一样。
    * **假设输入与输出：**
        * **假设输入：** 用户在网页中停止输入文本一段时间，浏览器进入空闲状态。
        * **逻辑推理：**  `ScriptedIdleTaskController` 检测到空闲，调用 `IdleSpellCheckController::Invoke`。如果状态是 `kColdModeRequested`，则启动冷模式拼写检查。
        * **假设输出：**  拼写检查服务（未在当前文件中实现，但通过 `SpellCheckRequester` 间接调用）返回拼写错误的单词列表。这些错误后续可能会通过下划线等方式在 HTML 页面上呈现。

* **HTML：**  `IdleSpellCheckController` 作用于 HTML 文档中的可编辑元素（例如 `<textarea>`, 带有 `contenteditable` 属性的元素）。
    * **举例：**  当用户在一个 `<textarea>` 元素中输入文本时，`RespondToChangedContents` 会被调用，触发热模式拼写检查。
    * **假设输入与输出：**
        * **假设输入：** 用户在 HTML 页面上的 `<textarea>` 中输入了 "teh" (拼写错误)。
        * **逻辑推理：** `RespondToChangedContents` 被触发，`SetNeedsInvocation` 设置热模式请求。当浏览器空闲或超时时间到达时，`HotModeInvocation` 会调用拼写检查服务检查 "teh"。
        * **假设输出：**  拼写检查服务识别出 "teh" 是一个拼写错误。虽然 `IdleSpellCheckController` 本身不负责标记错误，但这个信息会被传递给其他 Blink 组件，最终可能在 HTML 页面上将 "teh" 标记为拼写错误。

* **CSS：**  CSS 本身不直接与 `IdleSpellCheckController` 交互，但 CSS 样式会影响文本的布局和渲染，从而间接影响拼写检查的范围和呈现。

**逻辑推理，假设输入与输出**

我们已经在上面 JavaScript 和 HTML 的例子中给出了一些逻辑推理和假设输入输出。再补充一个关于冷模式的例子：

* **假设输入：** 用户打开一个包含大量文本的网页，并且拼写检查已启用。用户没有进行任何编辑操作，浏览器处于空闲状态。
* **逻辑推理：**
    * 初始状态可能是 `kInactive`。
    * 经过一段时间的空闲，`SetNeedsColdModeInvocation` 被调用，启动冷模式定时器。
    * 定时器触发后，状态变为 `kColdModeRequested`。
    * 当浏览器真正空闲时，`Invoke` 方法被调用，启动冷模式拼写检查，逐步检查可编辑区域。
* **假设输出：**  拼写检查服务遍历整个可编辑区域，识别出所有拼写错误的单词。这些错误最终会在页面上标记出来。

**用户或编程常见的使用错误**

虽然开发者不会直接“使用” `IdleSpellCheckController` 这个类，但理解其工作原理有助于避免一些与拼写检查相关的常见问题：

1. **性能问题：** 如果拼写检查过于频繁或检查范围过大，可能会影响页面性能。`IdleSpellCheckController` 的设计目标就是避免这种情况，但如果配置不当或拼写检查服务本身耗时过长，仍然可能出现问题。
2. **误判或漏判：** 拼写检查算法可能存在误判（将正确单词标记为错误）或漏判（未标记出错误单词）。这与 `IdleSpellCheckController` 本身关系不大，更多取决于拼写检查服务的能力。
3. **与自定义编辑器的集成问题：** 如果开发者实现了自定义的富文本编辑器，可能需要确保其与浏览器的拼写检查机制良好集成，否则可能导致拼写检查失效或行为异常。
4. **不理解热模式和冷模式的区别：**  开发者如果对这两种模式不了解，可能会疑惑为什么某些拼写错误在输入后立即被标记，而另一些则需要等待一段时间。

**用户操作如何一步步到达这里，作为调试线索**

以下是一些用户操作，以及这些操作如何最终触发 `IdleSpellCheckController` 中的代码执行，可以作为调试线索：

1. **用户在可编辑区域输入文本：**
   - 用户在 `<textarea>` 或 `contenteditable` 元素中输入字符。
   - 这会触发浏览器的事件，例如 `input` 或 `textInput`.
   - Blink 的事件处理机制会将这些事件传递到相应的 DOM 节点。
   - 编辑相关的代码（在 `blink/renderer/core/editing/` 目录下）会处理这些输入事件，更新文档内容。
   - `IdleSpellCheckController::RespondToChangedContents()` 方法会被调用，因为它监听了内容的变化。
   - `RespondToChangedContents()` 内部会调用 `SetNeedsInvocation()`，设置热模式检查的标志。
   - 当浏览器空闲或热模式超时时间到达时，`ScriptedIdleTaskController` 会调用 `IdleSpellCheckController::Invoke()`。
   - 如果状态是 `kHotModeRequested`，则 `HotModeInvocation()` 会被执行，发起针对当前光标位置附近文本的拼写检查。

2. **用户选择文本：**
   - 用户使用鼠标或键盘选择一段文本。
   - 这会触发浏览器的选择变化事件。
   - Blink 的选择管理代码 (`blink/renderer/core/editing/frame_selection.h`) 会更新选择状态。
   - `IdleSpellCheckController::RespondToChangedSelection()` 方法会被调用。
   - 如果需要进行热模式检查（例如，当前选择的区域尚未被冷模式检查过），则后续流程与输入文本类似，触发热模式检查。

3. **用户启用或禁用拼写检查：**
   - 用户通过浏览器设置或右键菜单中的选项来更改拼写检查的启用状态。
   - 这会触发 Blink 中拼写检查相关的设置变更。
   - `IdleSpellCheckController::RespondToChangedEnablement()` 方法会被调用。
   - 该方法会根据新的启用状态，激活或停用拼写检查控制器，并可能触发一次检查。

4. **浏览器处于空闲状态（冷模式）：**
   - 当用户停止操作一段时间，并且没有其他高优先级的任务运行时，浏览器会进入空闲状态。
   - `ScriptedIdleTaskController` 会检测到这种空闲状态。
   - 如果 `IdleSpellCheckController` 之前调用了 `SetNeedsColdModeInvocation()`，并且定时器到期，`IdleSpellCheckController::ColdModeTimerFired()` 会被调用。
   - 接着，`IdleSpellCheckController::Invoke()` 会被调用，状态为 `kColdModeRequested` 时，`ColdModeSpellCheckRequester::Invoke()` 会被调用，执行后台的全面拼写检查。

**总结**

`idle_spell_check_controller.cc` 文件中的 `IdleSpellCheckController` 类是 Blink 渲染引擎中负责优化拼写检查的关键组件。它通过利用浏览器的空闲时间，区分热模式和冷模式，以及与 JavaScript 的 `requestIdleCallback` API 集成，实现了高效且不影响用户体验的拼写检查功能。理解这个类的工作原理有助于理解 Chromium 中拼写检查机制，并在调试相关问题时提供有价值的线索。

Prompt: 
```
这是目录为blink/renderer/core/editing/spellcheck/idle_spell_check_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/spellcheck/idle_spell_check_controller.h"

#include <array>

#include "base/check_deref.h"
#include "base/debug/crash_logging.h"
#include "base/time/time.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_idle_request_options.h"
#include "third_party/blink/renderer/core/editing/commands/undo_stack.h"
#include "third_party/blink/renderer/core/editing/commands/undo_step.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/spellcheck/cold_mode_spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/spellcheck/hot_mode_spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/scheduler/scripted_idle_task_controller.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cancellable_task.h"

namespace blink {

namespace {

constexpr base::TimeDelta kColdModeTimerInterval = base::Milliseconds(1000);
constexpr base::TimeDelta kConsecutiveColdModeTimerInterval =
    base::Milliseconds(200);
const int kHotModeRequestTimeoutMS = 200;
const int kInvalidHandle = -1;
const int kDummyHandleForForcedInvocation = -2;
constexpr base::TimeDelta kIdleSpellcheckTestTimeout = base::Seconds(10);

}  // namespace

class IdleSpellCheckController::IdleCallback final : public IdleTask {
 public:
  explicit IdleCallback(IdleSpellCheckController* controller)
      : controller_(controller) {}
  IdleCallback(const IdleCallback&) = delete;
  IdleCallback& operator=(const IdleCallback&) = delete;

  void Trace(Visitor* visitor) const final {
    visitor->Trace(controller_);
    IdleTask::Trace(visitor);
  }

 private:
  void invoke(IdleDeadline* deadline) final { controller_->Invoke(deadline); }

  const Member<IdleSpellCheckController> controller_;
};

IdleSpellCheckController::~IdleSpellCheckController() = default;

void IdleSpellCheckController::Trace(Visitor* visitor) const {
  visitor->Trace(cold_mode_requester_);
  visitor->Trace(spell_check_requeseter_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

IdleSpellCheckController::IdleSpellCheckController(
    LocalDOMWindow& window,
    SpellCheckRequester& requester)
    : ExecutionContextLifecycleObserver(&window),
      idle_callback_handle_(kInvalidHandle),
      cold_mode_requester_(
          MakeGarbageCollected<ColdModeSpellCheckRequester>(window)),
      spell_check_requeseter_(requester) {}

LocalDOMWindow& IdleSpellCheckController::GetWindow() const {
  DCHECK(GetExecutionContext());
  return *To<LocalDOMWindow>(GetExecutionContext());
}

Document& IdleSpellCheckController::GetDocument() const {
  DCHECK(GetExecutionContext());
  return *GetWindow().document();
}

bool IdleSpellCheckController::IsSpellCheckingEnabled() const {
  if (!GetExecutionContext())
    return false;
  return GetWindow().GetSpellChecker().IsSpellCheckingEnabled();
}

void IdleSpellCheckController::DisposeIdleCallback() {
  if (idle_callback_handle_ != kInvalidHandle && GetExecutionContext()) {
    ScriptedIdleTaskController::From(*GetExecutionContext())
        .CancelCallback(idle_callback_handle_);
  }
  idle_callback_handle_ = kInvalidHandle;
}

void IdleSpellCheckController::Deactivate() {
  state_ = State::kInactive;
  if (cold_mode_timer_.IsActive())
    cold_mode_timer_.Cancel();
  cold_mode_requester_->Deactivate();
  DisposeIdleCallback();
  spell_check_requeseter_->Deactivate();
}

void IdleSpellCheckController::RespondToChangedSelection() {
  if (!IsSpellCheckingEnabled()) {
    Deactivate();
    return;
  }

  if (IsInInvocation())
    return;

  needs_invocation_for_changed_selection_ = true;
  SetNeedsInvocation();
}

void IdleSpellCheckController::RespondToChangedContents() {
  if (!IsSpellCheckingEnabled()) {
    Deactivate();
    return;
  }

  if (IsInInvocation())
    return;

  needs_invocation_for_changed_contents_ = true;
  SetNeedsInvocation();
}

void IdleSpellCheckController::RespondToChangedEnablement() {
  if (!IsSpellCheckingEnabled()) {
    Deactivate();
    return;
  }

  if (IsInInvocation())
    return;

  needs_invocation_for_changed_enablement_ = true;
  SetNeedsInvocation();
}

void IdleSpellCheckController::SetNeedsInvocation() {
  DCHECK(IsSpellCheckingEnabled());

  if (state_ == State::kHotModeRequested)
    return;

  cold_mode_requester_->ClearProgress();

  if (state_ == State::kColdModeTimerStarted) {
    DCHECK(cold_mode_timer_.IsActive());
    cold_mode_timer_.Cancel();
  }

  if (state_ == State::kColdModeRequested)
    DisposeIdleCallback();

  IdleRequestOptions* options = IdleRequestOptions::Create();
  options->setTimeout(kHotModeRequestTimeoutMS);
  idle_callback_handle_ =
      ScriptedIdleTaskController::From(CHECK_DEREF(GetExecutionContext()))
          .RegisterCallback(MakeGarbageCollected<IdleCallback>(this), options);
  state_ = State::kHotModeRequested;
}

void IdleSpellCheckController::SetNeedsColdModeInvocation() {
  DCHECK(IsSpellCheckingEnabled());
  if (state_ != State::kInactive && state_ != State::kInHotModeInvocation &&
      state_ != State::kInColdModeInvocation)
    return;

  DCHECK(!cold_mode_timer_.IsActive());
  base::TimeDelta interval = state_ == State::kInColdModeInvocation
                                 ? kConsecutiveColdModeTimerInterval
                                 : kColdModeTimerInterval;
  cold_mode_timer_ = PostDelayedCancellableTask(
      *GetWindow().GetTaskRunner(TaskType::kInternalDefault), FROM_HERE,
      WTF::BindOnce(&IdleSpellCheckController::ColdModeTimerFired,
                    WrapPersistent(this)),
      interval);
  state_ = State::kColdModeTimerStarted;
}

void IdleSpellCheckController::ColdModeTimerFired() {
  DCHECK_EQ(State::kColdModeTimerStarted, state_);

  if (!IsSpellCheckingEnabled()) {
    Deactivate();
    return;
  }

  idle_callback_handle_ =
      ScriptedIdleTaskController::From(CHECK_DEREF(GetExecutionContext()))
          .RegisterCallback(MakeGarbageCollected<IdleCallback>(this),
                            IdleRequestOptions::Create());
  state_ = State::kColdModeRequested;
}

bool IdleSpellCheckController::NeedsHotModeCheckingUnderCurrentSelection()
    const {
  if (needs_invocation_for_changed_contents_ ||
      needs_invocation_for_changed_enablement_) {
    return true;
  }

  // If there's only selection movement, we skip hot mode if cold mode has
  // already fully checked the current element.
  DCHECK(needs_invocation_for_changed_selection_);
  const Position& position =
      GetWindow().GetFrame()->Selection().GetSelectionInDOMTree().Focus();
  const auto* element = DynamicTo<Element>(HighestEditableRoot(position));
  if (!element || !element->isConnected())
    return false;
  return !cold_mode_requester_->HasFullyChecked(*element);
}

void IdleSpellCheckController::HotModeInvocation(IdleDeadline* deadline) {
  TRACE_EVENT0("blink", "IdleSpellCheckController::hotModeInvocation");

  // TODO(xiaochengh): Figure out if this has any performance impact.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  HotModeSpellCheckRequester requester(*spell_check_requeseter_);

  if (NeedsHotModeCheckingUnderCurrentSelection()) {
    requester.CheckSpellingAt(
        GetWindow().GetFrame()->Selection().GetSelectionInDOMTree().Focus());
  }

  const uint64_t watermark = last_processed_undo_step_sequence_;
  for (const UndoStep* step :
       GetWindow().GetFrame()->GetEditor().GetUndoStack().UndoSteps()) {
    if (step->SequenceNumber() <= watermark)
      break;
    last_processed_undo_step_sequence_ =
        std::max(step->SequenceNumber(), last_processed_undo_step_sequence_);
    if (deadline->timeRemaining() == 0)
      break;
    // The ending selection stored in undo stack can be invalid, disconnected
    // or have been moved to another document, so we should check its validity
    // before using it.
    if (!step->EndingSelection().IsValidFor(GetDocument()))
      continue;
    requester.CheckSpellingAt(step->EndingSelection().Focus());
  }

  needs_invocation_for_changed_selection_ = false;
  needs_invocation_for_changed_contents_ = false;
  needs_invocation_for_changed_enablement_ = false;
}

void IdleSpellCheckController::Invoke(IdleDeadline* deadline) {
  DCHECK_NE(idle_callback_handle_, kInvalidHandle);
  idle_callback_handle_ = kInvalidHandle;

  if (!IsSpellCheckingEnabled()) {
    Deactivate();
    return;
  }

  if (state_ == State::kHotModeRequested) {
    state_ = State::kInHotModeInvocation;
    HotModeInvocation(deadline);
    SetNeedsColdModeInvocation();
  } else if (state_ == State::kColdModeRequested) {
    state_ = State::kInColdModeInvocation;
    cold_mode_requester_->Invoke(deadline);
    if (cold_mode_requester_->FullyCheckedCurrentRootEditable()) {
      state_ = State::kInactive;
    } else {
      SetNeedsColdModeInvocation();
    }
  } else {
    // TODO(crbug.com/1424540): The other states are unexpected but reached in
    // real world. We work around it and dump debugging information.
    static auto* state_data = base::debug::AllocateCrashKeyString(
        "spellchecker-state-on-invocation", base::debug::CrashKeySize::Size32);
    base::debug::SetCrashKeyString(state_data, GetStateAsString());
    DUMP_WILL_BE_NOTREACHED() << GetStateAsString();
    Deactivate();
  }
}

void IdleSpellCheckController::ContextDestroyed() {
  Deactivate();
}

void IdleSpellCheckController::ForceInvocationForTesting() {
  if (!IsSpellCheckingEnabled())
    return;

  bool cross_origin_isolated_capability =
      GetExecutionContext()
          ? GetExecutionContext()->CrossOriginIsolatedCapability()
          : false;

  auto* deadline = MakeGarbageCollected<IdleDeadline>(
      base::TimeTicks::Now() + kIdleSpellcheckTestTimeout,
      cross_origin_isolated_capability,
      IdleDeadline::CallbackType::kCalledWhenIdle);

  switch (state_) {
    case State::kColdModeTimerStarted:
      cold_mode_timer_.Cancel();
      state_ = State::kColdModeRequested;
      idle_callback_handle_ = kDummyHandleForForcedInvocation;
      Invoke(deadline);
      break;
    case State::kHotModeRequested:
    case State::kColdModeRequested:
      if (GetExecutionContext()) {
        ScriptedIdleTaskController::From(*GetExecutionContext())
            .CancelCallback(idle_callback_handle_);
      }
      Invoke(deadline);
      break;
    case State::kInactive:
    case State::kInHotModeInvocation:
    case State::kInColdModeInvocation:
      NOTREACHED();
  }
}

void IdleSpellCheckController::SkipColdModeTimerForTesting() {
  DCHECK(cold_mode_timer_.IsActive());
  cold_mode_timer_.Cancel();
  ColdModeTimerFired();
}

void IdleSpellCheckController::SetNeedsMoreColdModeInvocationForTesting() {
  cold_mode_requester_->SetNeedsMoreInvocationForTesting();
}

void IdleSpellCheckController::SetSpellCheckingDisabled(
    const Element& element) {
  cold_mode_requester_->RemoveFromFullyChecked(element);
}

const char* IdleSpellCheckController::GetStateAsString() const {
  static const auto kTexts = std::to_array<const char*>({
#define V(state) #state,
      FOR_EACH_IDLE_SPELL_CHECK_CONTROLLER_STATE(V)
#undef V
  });

  unsigned index = static_cast<unsigned>(state_);
  if (index < std::size(kTexts)) {
    return kTexts[index];
  }
  return "Invalid";
}

}  // namespace blink

"""

```