Response:
Let's break down the thought process for analyzing the `find_task_controller.cc` file.

1. **Understand the Goal:** The core request is to explain the functionality of this specific Chromium/Blink source code file. Beyond that, it asks to connect it to web technologies (JavaScript, HTML, CSS), provide examples of logical flow, discuss potential user errors, and trace the user interaction leading to this code.

2. **Initial Scan for Keywords and Structure:**  I'd first quickly scan the code for important keywords and structural elements:
    * `#include`: Lists dependencies, hinting at related components (`FindBuffer`, `TextFinder`, `Document`, `Range`, etc.). This gives an initial idea of the file's scope.
    * `namespace blink`: Confirms this is part of the Blink rendering engine.
    * Class definitions (`FindTaskController`, `FindTask`):  Indicates the primary actors and their responsibilities.
    * Method names (`StartRequest`, `CancelPendingRequest`, `RequestFindTask`, `DidFinishTask`, `DidFindMatch`): These are the actions the controller can perform.
    * Member variables (`owner_frame_`, `text_finder_`, `resume_finding_from_range_`):  These hold the controller's state and relationships.
    * Constants (`kFindTaskTimeAllotment`, `kMatchYieldCheckIntervalStart`, `kMatchYieldCheckIntervalLimit`):  Suggest performance considerations and incremental processing.
    * Comments (`// Copyright ...`, `// Check if we need to yield ...`): Offer valuable insights into the logic.
    * `TRACE_EVENT_NESTABLE_ASYNC_BEGIN0`: Indicates instrumentation for performance monitoring.

3. **Focus on the Core Class: `FindTaskController`:**  This is clearly the central piece. I'd analyze its methods:
    * **`StartRequest`:**  The entry point for a find-in-page operation. It initializes state, creates a `FindTask`, and kicks it off. The `TRACE_EVENT` tells me this is where a find request begins.
    * **`CancelPendingRequest`:**  Handles stopping an ongoing search. It cleans up resources and resets state.
    * **`RequestFindTask`:**  Creates and schedules a `FindTask` to run on a dedicated thread. This hints at asynchronous processing.
    * **`DidFinishTask`:**  Called when a `FindTask` completes (or times out). It updates the UI, decides whether to continue searching, and handles the completion of the overall find operation.
    * **`ShouldFindMatches`:**  An optimization to avoid unnecessary searches based on previous results and visibility.
    * **`DidFindMatch`:**  Informs the `TextFinder` about a found match.
    * **`GetMatchYieldCheckInterval`:**  Controls the frequency of yielding during long searches.

4. **Analyze the Helper Class: `FindTask`:** This class performs the actual searching.
    * **Constructor:** Takes the search parameters and schedules the `Invoke` method.
    * **`Invoke`:** The core logic. It iterates through the document, uses `FindBuffer` to locate matches, and reports them back to the controller. The time allotment and yielding logic are crucial here for responsiveness. The use of `DisplayLockDocumentState` suggests a synchronization mechanism with rendering.

5. **Connect to Web Technologies:** Now, consider how the functionality relates to JavaScript, HTML, and CSS:
    * **JavaScript:**  The `window.find()` method or custom JavaScript that triggers a search. The results might be manipulated or displayed via JavaScript.
    * **HTML:** The content being searched within the HTML document. The structure of the HTML affects how the search is performed (block by block).
    * **CSS:** CSS can influence the visibility of content, which affects whether it's searched (`HasVisibleContent`). CSS can also be used to highlight found matches (though the highlighting logic isn't in *this* file).

6. **Logical Flow Examples:** Think of concrete scenarios:
    * **Successful Search:** User enters text, matches are found, highlighting occurs.
    * **Incremental Search:** User types more characters, the search refines. The `ShouldFindMatches` logic is relevant here.
    * **No Matches:** User searches for something not present.
    * **Large Document:** The yielding mechanism becomes important to prevent UI freezes.

7. **User/Programming Errors:**  Consider common mistakes:
    * **Case Sensitivity:**  User not realizing the case sensitivity option.
    * **Incorrect Search Term:**  Typographical errors.
    * **JavaScript Interference:**  Custom scripts might interfere with the browser's find functionality.
    * **Infinite Loops (Hypothetical Programming Error):** Though less likely in this specific file, it's a general debugging consideration.

8. **Tracing User Interaction:** Work backward from the code:
    * The `FindTaskController` is involved in the find-in-page feature.
    * This feature is typically initiated by user actions like Ctrl+F (or Cmd+F) or using the browser's menu.
    * The browser's UI then communicates the search request to the rendering engine.

9. **Debugging Clues:** The file offers several debugging hints:
    * **Logging (`DCHECK`):**  Assertions that can help identify unexpected conditions during development.
    * **Histograms (`SCOPED_UMA_HISTOGRAM_TIMER`):** Performance metrics that can be analyzed.
    * **Trace Events (`TRACE_EVENT_NESTABLE_ASYNC_BEGIN0`):**  Detailed tracing information for understanding the sequence of events.

10. **Structure the Output:** Organize the information logically, using headings and bullet points for clarity. Start with a high-level summary of the file's purpose and then delve into more specific details. Address each part of the original prompt.

11. **Refine and Review:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check for any ambiguities or areas that could be explained better. For example, initially, I might forget to mention the `RubySupport` in `FindBuffer`, but a second pass would catch it. Similarly, elaborating on *why* the yielding is necessary is important.

By following this structured approach, I can systematically analyze the code and generate a comprehensive explanation that addresses all aspects of the prompt. The key is to move from a general understanding to specific details and to connect the technical aspects of the code to the user's experience and the broader web ecosystem.
好的，让我们来详细分析 `blink/renderer/core/editing/finder/find_task_controller.cc` 这个文件。

**功能概述:**

`find_task_controller.cc` 文件的核心功能是**管理在 Blink 渲染引擎中执行“在页面中查找” (Find in Page) 功能时的查找任务。** 它负责协调查找操作的启动、执行、暂停、恢复和完成，并管理查找过程中的状态和资源。

更具体地说，它的职责包括：

* **接收查找请求:**  从上层模块（如 UI 或 JavaScript API）接收查找请求，包括要查找的文本、查找选项（例如是否区分大小写、向前或向后查找）以及唯一的查找标识符。
* **创建和调度查找任务:** 将查找请求分解为可执行的 `FindTask` 对象，并将这些任务调度到专门的线程上执行，以避免阻塞主渲染线程，保证用户界面的响应性。
* **管理查找状态:** 跟踪当前正在进行的查找操作的状态，包括查找标识符、搜索文本、查找选项以及已找到的匹配项数量。
* **控制查找执行:**  协调查找任务的执行，包括初始启动、暂停（当分配的时间片用完时）以及恢复（继续查找）。
* **与文本查找器交互:**  与 `TextFinder` 类协作，`TextFinder` 负责实际的文本搜索算法和逻辑。`FindTaskController` 将查找结果（找到的匹配项）传递给 `TextFinder` 进行处理和高亮显示。
* **优化查找性能:**  通过将查找任务分配到后台线程、设置查找任务的时间限制以及在找到一定数量的匹配项后暂停来优化查找性能，防止长时间运行的查找操作导致浏览器卡顿。
* **处理查找结果:**  接收 `FindTask` 的执行结果，包括是否完成整个查找、下一个查找的起始位置以及找到的匹配项数量。
* **取消查找请求:**  允许取消正在进行的查找请求。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`find_task_controller.cc` 的功能与 JavaScript, HTML, CSS 都有密切的关系：

* **JavaScript:**
    * **启动查找:**  用户可以通过 JavaScript 的 `window.find()` 方法或自定义的 JavaScript 代码来触发“在页面中查找”功能。这些 JavaScript 调用最终会传递到 Blink 渲染引擎，并由 `FindTaskController` 接收和处理。
    * **获取查找结果:**  虽然 `FindTaskController` 本身不直接与 JavaScript 交互返回结果，但它会将找到的匹配项信息传递给 `TextFinder`，而 `TextFinder` 的结果会影响到页面 DOM 的状态，JavaScript 可以通过监听 DOM 变化或调用相关 API 来获取查找结果，例如获取当前高亮的匹配项。
    * **自定义查找行为:**  虽然不常见，但理论上可以通过扩展或修改 Blink 引擎来允许 JavaScript 更细粒度地控制查找行为，但这通常不推荐，因为浏览器的内置查找功能已经足够强大。

    **举例:**  一个简单的 JavaScript 示例，用户按下 Ctrl+F 后，浏览器内部会调用相关的 C++ 代码，最终会实例化 `FindTaskController` 并调用其 `StartRequest` 方法。

* **HTML:**
    * **被查找的内容:** HTML 文档是“在页面中查找”功能的目标。`FindTaskController` 和 `FindTask` 的核心任务就是在 HTML 文档的文本内容中搜索指定的字符串。
    * **DOM 结构的影响:**  HTML 文档的 DOM 结构会影响查找过程。例如，查找操作需要遍历 DOM 树来找到所有的文本节点。`FindTaskController` 中使用了 `PositionInFlatTree` 和 `Range` 等概念，这些都与 DOM 树的遍历和定位密切相关。

    **举例:**  如果一个 HTML 页面包含大量的 `<p>` 标签，`FindTask` 会遍历这些标签中的文本内容来查找匹配项。

* **CSS:**
    * **影响可见性:** CSS 的 `display: none;` 或 `visibility: hidden;` 属性可以隐藏页面元素。`FindTaskController` 通常会忽略不可见的内容，只在可见的内容中进行查找。 `ShouldFindMatches` 方法中会检查 `OwnerFrame().HasVisibleContent()` 来判断是否需要执行查找，这与 CSS 的渲染结果有关。
    * **高亮显示:**  虽然 `FindTaskController` 不负责高亮显示，但找到的匹配项最终会通过 `TextFinder` 在页面上高亮显示，这通常是通过添加特定的 CSS 类或样式来实现的。

    **举例:** 如果用户在 CSS 中设置了某些文本的 `display: none;`，那么“在页面中查找”功能通常不会在这些隐藏的文本中找到匹配项。

**逻辑推理和假设输入/输出:**

假设用户在浏览器地址栏输入了以下网址并加载了页面：

```html
<!DOCTYPE html>
<html>
<head>
<title>查找示例</title>
</head>
<body>
  <p>这是一个包含一些文本的段落，用于演示查找功能。</p>
  <p>这是第二个段落，其中也包含一些文本。</p>
  <div>这里也有一些文本。</div>
</body>
</html>
```

**假设输入:**

1. **用户操作:** 用户按下 `Ctrl+F` (或 `Cmd+F`) 快捷键，打开浏览器的“在页面中查找”框。
2. **搜索文本:** 用户在查找框中输入 "文本"。
3. **查找选项:** 默认选项（通常不区分大小写，向前查找）。
4. **查找标识符:** 假设浏览器内部为这次查找分配的标识符是 `123`。

**`FindTaskController` 的处理过程 (简化):**

1. `StartRequest(123, "文本", { forward: true, match_case: false, ... })` 被调用。
2. `FindTaskController` 创建一个新的 `FindTask` 对象，用于执行实际的查找。
3. `FindTask` 将被调度到后台线程执行其 `Invoke` 方法。
4. `Invoke` 方法会：
   * 获取当前文档的 DOM 树。
   * 创建一个 `FindBuffer` 对象，用于高效地访问和搜索文档内容。
   * 调用 `FindBuffer` 的 `FindMatches` 方法，在文档中搜索 "文本"。
   * 遍历找到的匹配项，例如：
     * 第一个匹配项可能在第一个 `<p>` 标签中。
     * 第二个匹配项可能在第二个 `<p>` 标签中。
     * 第三个匹配项可能在 `<div>` 标签中。
   * 对于每个找到的匹配项，`FindTask` 会调用 `controller_->DidFindMatch(123, match_range)`，将匹配的 `Range` 对象传递给 `FindTaskController`。
   * `FindTaskController` 会调用 `text_finder_->DidFindMatch(123, current_match_count_, result_range)`，通知 `TextFinder` 找到了一个匹配项。
5. 如果整个文档搜索完成，`FindTask` 会调用 `controller_->DidFinishTask(123, "文本", ..., true, ..., 3, false, ...)`，通知 `FindTaskController` 查找已完成，共找到 3 个匹配项。
6. `FindTaskController` 会调用 `text_finder_->UpdateMatches(123, 3, true)` 和 `text_finder_->FinishCurrentScopingEffort(123)`，更新 UI 以高亮显示找到的匹配项。

**假设输出:**

1. 浏览器窗口中，所有包含 "文本" 的部分（不区分大小写）都会被高亮显示。
2. 查找框可能会显示 "1/3" (如果只高亮显示第一个匹配项) 或者其他表示匹配项数量和当前位置的信息。

**用户或编程常见的使用错误及举例说明:**

* **用户错误:**
    * **拼写错误:** 用户在查找框中输入了错误的搜索文本，导致找不到预期的结果。例如，输入 "本本" 而不是 "文本"。
    * **区分大小写混淆:** 用户没有注意到“区分大小写”选项，导致找不到大小写不匹配的文本。例如，搜索 "文本"，但页面中只有 "文本"。
    * **在隐藏内容中查找:** 用户期望在 CSS 隐藏的内容中找到匹配项，但浏览器的默认行为通常是不在隐藏内容中查找。

* **编程错误 (Blink 引擎开发者):**
    * **死循环或性能问题:** 在 `FindTask` 的 `Invoke` 方法中，如果查找逻辑存在错误，可能导致无限循环或执行时间过长，最终导致浏览器卡顿甚至崩溃。例如，在遍历 DOM 树时出现逻辑错误，导致重复访问相同的节点。
    * **线程同步问题:** 由于查找任务在后台线程执行，如果与主线程或其他线程共享数据时没有进行正确的同步，可能导致数据竞争或不一致的问题。
    * **内存泄漏:** 如果 `FindTask` 或相关的对象没有正确释放，可能导致内存泄漏。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户执行“在页面中查找”操作时，以下步骤可能会导致代码执行到 `find_task_controller.cc`：

1. **用户触发查找:** 用户按下 `Ctrl+F` (或 `Cmd+F`) 快捷键，或者通过浏览器的菜单选项触发“在页面中查找”功能。
2. **浏览器 UI 处理:** 浏览器的 UI 组件（例如查找框）接收用户的输入。
3. **发送 IPC 消息:** 浏览器进程（Browser Process）会将查找请求信息（包括搜索文本和选项）通过 Inter-Process Communication (IPC) 发送给渲染进程（Renderer Process），其中包含页面的 Blink 引擎。
4. **渲染进程接收请求:** 渲染进程中的相应模块接收到查找请求。
5. **调用 WebFrame API:**  通常会调用 `WebLocalFrameImpl::find()` 或类似的方法。
6. **创建 FindTaskController:**  `WebLocalFrameImpl` 或其关联的组件会创建或获取 `FindTaskController` 的实例。
7. **调用 StartRequest:** `FindTaskController` 的 `StartRequest` 方法被调用，传入查找标识符、搜索文本和查找选项。
8. **创建并调度 FindTask:**  `StartRequest` 方法会创建一个 `FindTask` 对象，并将其实例化，指定要查找的文档、搜索文本和选项。然后，它会将 `FindTask` 调度到专门的线程上执行，通常使用 `LocalFrame::GetTaskRunner(blink::TaskType::kInternalFindInPage)->PostTask(...)`。
9. **FindTask 执行:**  后台线程执行 `FindTask::Invoke()` 方法，进行实际的文本搜索。

**调试线索:**

* **断点:** 在 `FindTaskController::StartRequest`、`FindTask::Invoke`、`FindTaskController::DidFinishTask` 等关键方法设置断点，可以跟踪查找请求的生命周期和执行过程。
* **日志输出:** 在关键代码路径添加日志输出，可以记录查找的状态、参数和执行结果。
* **Trace 事件:** Blink 引擎使用了 tracing 机制，可以启用 tracing 并查看 `FindInPageRequest` 相关的事件，了解查找的性能和执行流程。
* **查看调用堆栈:**  当在断点处暂停时，查看调用堆栈可以了解代码是如何一步步到达当前位置的。
* **检查 IPC 消息:**  可以使用 Chromium 的内部工具（如 `chrome://tracing`）来检查浏览器进程和渲染进程之间的 IPC 消息，确认查找请求是否正确地从浏览器进程传递到了渲染进程。

希望以上分析能够帮助你理解 `find_task_controller.cc` 的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/editing/finder/find_task_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/finder/find_task_controller.h"

#include "third_party/blink/public/mojom/frame/find_in_page.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_idle_request_options.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/find_buffer.h"
#include "third_party/blink/renderer/core/editing/finder/find_options.h"
#include "third_party/blink/renderer/core/editing/finder/find_results.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/scheduler/scripted_idle_task_controller.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"

namespace blink {

namespace {
constexpr base::TimeDelta kFindTaskTimeAllotment = base::Milliseconds(10);

// Check if we need to yield after this many matches have been found. We start
// with Start matches and double them every time we yield until we are
// processing Limit matches per yield check.
constexpr int kMatchYieldCheckIntervalStart = 100;
constexpr int kMatchYieldCheckIntervalLimit = 6400;

}  // namespace

class FindTaskController::FindTask final : public GarbageCollected<FindTask> {
 public:
  FindTask(FindTaskController* controller,
           Document* document,
           int identifier,
           const String& search_text,
           const mojom::blink::FindOptions& options)
      : document_(document),
        controller_(controller),
        identifier_(identifier),
        search_text_(search_text),
        options_(options.Clone()) {
    DCHECK(document_);
    if (options.run_synchronously_for_testing) {
      Invoke();
    } else {
      controller_->GetLocalFrame()
          ->GetTaskRunner(blink::TaskType::kInternalFindInPage)
          ->PostTask(FROM_HERE, WTF::BindOnce(&FindTask::Invoke,
                                              WrapWeakPersistent(this)));
    }
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(controller_);
    visitor->Trace(document_);
  }

  void Invoke() {
    const base::TimeTicks task_start_time = base::TimeTicks::Now();
    if (!controller_)
      return;
    if (!controller_->ShouldFindMatches(identifier_, search_text_, *options_)) {
      controller_->DidFinishTask(identifier_, search_text_, *options_,
                                 true /* finished_whole_request */,
                                 PositionInFlatTree(), 0 /* match_count */,
                                 true /* aborted */, task_start_time);
      return;
    }
    SCOPED_UMA_HISTOGRAM_TIMER("WebCore.FindInPage.TaskDuration");

    Document* document = controller_->GetLocalFrame()->GetDocument();
    if (!document || document_ != document)
      return;
    auto forced_activatable_display_locks =
        document->GetDisplayLockDocumentState()
            .GetScopedForceActivatableLocks();
    PositionInFlatTree search_start =
        PositionInFlatTree::FirstPositionInNode(*document);
    PositionInFlatTree search_end;
    if (document->documentElement() &&
        document->documentElement()->lastChild()) {
      search_end = PositionInFlatTree::AfterNode(
          *document->documentElement()->lastChild());
    } else {
      search_end = PositionInFlatTree::LastPositionInNode(*document);
    }
    DCHECK_EQ(search_start.GetDocument(), search_end.GetDocument());

    if (Range* resume_from_range = controller_->ResumeFindingFromRange()) {
      // This is a continuation of a finding operation that timed out and didn't
      // complete last time around, so we should start from where we left off.
      DCHECK(resume_from_range->collapsed());
      search_start = FromPositionInDOMTree<EditingInFlatTreeStrategy>(
          resume_from_range->EndPosition());
      if (search_start.GetDocument() != search_end.GetDocument())
        return;
    }

    // This is required if we forced any of the display-locks.
    document->UpdateStyleAndLayout(DocumentUpdateReason::kFindInPage);

    int match_count = 0;
    bool full_range_searched = true;
    PositionInFlatTree next_task_start_position;

    auto find_options = FindOptions()
                            .SetBackwards(!options_->forward)
                            .SetCaseInsensitive(!options_->match_case)
                            .SetStartingInSelection(options_->new_session);
    const auto start_time = base::TimeTicks::Now();

    auto time_allotment_expired = [start_time]() {
      auto time_elapsed = base::TimeTicks::Now() - start_time;
      return time_elapsed > kFindTaskTimeAllotment;
    };

    int match_yield_check_interval = controller_->GetMatchYieldCheckInterval();

    while (search_start < search_end) {
      // Find in the whole block.
      FindBuffer buffer(EphemeralRangeInFlatTree(search_start, search_end),
                        RubySupport::kEnabledIfNecessary);
      FindResults match_results =
          buffer.FindMatches(search_text_, find_options);
      bool yielded_while_iterating_results = false;
      for (MatchResultICU match : match_results) {
        const EphemeralRangeInFlatTree ephemeral_match_range =
            buffer.RangeFromBufferIndex(match.start,
                                        match.start + match.length);
        auto* const match_range = MakeGarbageCollected<Range>(
            ephemeral_match_range.GetDocument(),
            ToPositionInDOMTree(ephemeral_match_range.StartPosition()),
            ToPositionInDOMTree(ephemeral_match_range.EndPosition()));
        if (match_range->collapsed()) {
          // resultRange will be collapsed if the matched text spans over
          // multiple TreeScopes.  TODO(rakina): Show such matches to users.
          next_task_start_position = ephemeral_match_range.EndPosition();
          continue;
        }
        ++match_count;
        controller_->DidFindMatch(identifier_, match_range);

        // Check if we should yield. Since we accumulate text on block
        // boundaries, if a lot of the text is in a single block, then we may
        // get stuck in there processing all of the matches. It's not so bad per
        // se, but when coupled with updating painting of said matches and the
        // scrollbar ticks, then we can block the main thread for quite some
        // time.
        if ((match_count % match_yield_check_interval) == 0 &&
            time_allotment_expired()) {
          // Next time we should start at the end of the current match.
          next_task_start_position = ephemeral_match_range.EndPosition();
          yielded_while_iterating_results = true;
          break;
        }
      }

      // If we have yielded from the inner loop, then just break out of the
      // loop, since we already updated the next_task_start_position.
      if (yielded_while_iterating_results) {
        full_range_searched = false;
        break;
      }

      // At this point, all text in the block collected above has been
      // processed. Now we move to the next block if there's any,
      // otherwise we should stop.
      search_start = buffer.PositionAfterBlock();
      if (search_start.IsNull() || search_start >= search_end) {
        full_range_searched = true;
        break;
      }

      // We should also check if we should yield after every block search, since
      // it's a nice natural boundary. Note that if we yielded out of the inner
      // loop, then we should exit before updating the search_start position to
      // the PositionAfterBlock. Otherwise, we may miss the matches that happen
      // in the same block. This block updates next_task_start_position to be
      // the updated search_start.
      if (time_allotment_expired()) {
        next_task_start_position = search_start;
        full_range_searched = false;
        break;
      }
    }
    controller_->DidFinishTask(identifier_, search_text_, *options_,
                               full_range_searched, next_task_start_position,
                               match_count, false /* aborted */,
                               task_start_time);
  }

  Member<Document> document_;
  Member<FindTaskController> controller_;
  const int identifier_;
  const String search_text_;
  mojom::blink::FindOptionsPtr options_;
};

FindTaskController::FindTaskController(WebLocalFrameImpl& owner_frame,
                                       TextFinder& text_finder)
    : owner_frame_(owner_frame),
      text_finder_(text_finder),
      resume_finding_from_range_(nullptr),
      match_yield_check_interval_(kMatchYieldCheckIntervalStart) {}

int FindTaskController::GetMatchYieldCheckInterval() const {
  return match_yield_check_interval_;
}

void FindTaskController::StartRequest(
    int identifier,
    const String& search_text,
    const mojom::blink::FindOptions& options) {
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(
      "blink", "FindInPageRequest",
      TRACE_ID_WITH_SCOPE("FindInPageRequest", identifier));
  DCHECK(!finding_in_progress_);
  DCHECK_EQ(current_find_identifier_, kInvalidFindIdentifier);
  // This is a brand new search, so we need to reset everything.
  finding_in_progress_ = true;
  current_match_count_ = 0;
  current_find_identifier_ = identifier;
  match_yield_check_interval_ = kMatchYieldCheckIntervalStart;
  RequestFindTask(identifier, search_text, options);
}

void FindTaskController::CancelPendingRequest() {
  if (find_task_)
    find_task_.Clear();
  if (finding_in_progress_) {
    last_find_request_completed_with_no_matches_ = false;
  }
  finding_in_progress_ = false;
  resume_finding_from_range_ = nullptr;
  current_find_identifier_ = kInvalidFindIdentifier;
}

void FindTaskController::RequestFindTask(
    int identifier,
    const String& search_text,
    const mojom::blink::FindOptions& options) {
  DCHECK_EQ(find_task_, nullptr);
  DCHECK_EQ(identifier, current_find_identifier_);
  find_task_ = MakeGarbageCollected<FindTask>(
      this, GetLocalFrame()->GetDocument(), identifier, search_text, options);
}

void FindTaskController::DidFinishTask(
    int identifier,
    const String& search_text,
    const mojom::blink::FindOptions& options,
    bool finished_whole_request,
    PositionInFlatTree next_starting_position,
    int match_count,
    bool aborted,
    base::TimeTicks task_start_time) {
  if (current_find_identifier_ != identifier)
    return;
  if (find_task_)
    find_task_.Clear();
  // Remember what we search for last time, so we can skip searching if more
  // letters are added to the search string (and last outcome was 0).
  last_search_string_ = search_text;

  if (next_starting_position.IsNotNull()) {
    resume_finding_from_range_ = MakeGarbageCollected<Range>(
        *next_starting_position.GetDocument(),
        ToPositionInDOMTree(next_starting_position),
        ToPositionInDOMTree(next_starting_position));
  }

  if (match_count > 0) {
    text_finder_->UpdateMatches(identifier, match_count,
                                finished_whole_request);
  }

  if (!finished_whole_request) {
    match_yield_check_interval_ = std::min(kMatchYieldCheckIntervalLimit,
                                           2 * match_yield_check_interval_);
    // Task ran out of time, request for another one.
    RequestFindTask(identifier, search_text, options);
    return;  // Done for now, resume work later.
  }

  text_finder_->FinishCurrentScopingEffort(identifier);

  last_find_request_completed_with_no_matches_ =
      !aborted && !current_match_count_;
  finding_in_progress_ = false;
  current_find_identifier_ = kInvalidFindIdentifier;
}

LocalFrame* FindTaskController::GetLocalFrame() const {
  return OwnerFrame().GetFrame();
}

bool FindTaskController::ShouldFindMatches(
    int identifier,
    const String& search_text,
    const mojom::blink::FindOptions& options) {
  if (identifier != current_find_identifier_)
    return false;
  // Don't scope if we can't find a frame, a document, or a view.
  // The user may have closed the tab/application, so abort.
  LocalFrame* frame = GetLocalFrame();
  if (!frame || !frame->View() || !frame->GetPage() || !frame->GetDocument())
    return false;

  DCHECK(frame->GetDocument());
  DCHECK(frame->View());

  if (options.force)
    return true;

  if (!OwnerFrame().HasVisibleContent())
    return false;

  // If the frame completed the scoping operation and found 0 matches the last
  // time it was searched, then we don't have to search it again if the user is
  // just adding to the search string or sending the same search string again.
  if (last_find_request_completed_with_no_matches_ &&
      !last_search_string_.empty()) {
    // Check to see if the search string prefixes match.
    String previous_search_prefix =
        search_text.Substring(0, last_search_string_.length());

    if (previous_search_prefix == last_search_string_)
      return false;  // Don't search this frame, it will be fruitless.
  }

  return true;
}

void FindTaskController::DidFindMatch(int identifier, Range* result_range) {
  current_match_count_++;
  text_finder_->DidFindMatch(identifier, current_match_count_, result_range);
}

void FindTaskController::Trace(Visitor* visitor) const {
  visitor->Trace(owner_frame_);
  visitor->Trace(text_finder_);
  visitor->Trace(find_task_);
  visitor->Trace(resume_finding_from_range_);
}

void FindTaskController::ResetLastFindRequestCompletedWithNoMatches() {
  last_find_request_completed_with_no_matches_ = false;
}

}  // namespace blink

"""

```