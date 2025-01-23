Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Understanding - The Big Picture:**

The first step is to read the file and its comments. The header comment `// Copyright 2019 The Chromium Authors` and the `#include` statements immediately tell us this is part of the Chromium project, specifically within the Blink rendering engine. The file name `content_capture_task.cc` strongly suggests this code is responsible for capturing content, likely for some form of analysis or transmission.

**2. Identifying Key Classes and Data Structures:**

As I read through the code, I identify the core classes and data structures:

*   `ContentCaptureTask`:  The main class. It manages the entire content capture process.
*   `TaskDelay`:  Handles the delay between content capture attempts.
*   `TaskSession`: Likely manages the overall capture session, potentially across multiple documents.
*   `TaskSession::DocumentSession`:  Seems to manage capture for a single document.
*   `cc::NodeInfo`:  A structure to hold information about content nodes, probably from the Compositor thread.
*   `WebContentHolder`:  A container for captured web content.
*   `WebContentCaptureClient`: An interface to interact with the embedder (browser).
*   `ContentCaptureTaskHistogramReporter`:  Used for performance monitoring.

**3. Dissecting Functionality - Method by Method:**

Now, I go through each method and try to understand its purpose. I look for keywords and patterns:

*   **Constructors and Destructors:**  Understand initialization and cleanup. Note the dependency injection of `LocalFrame` and `TaskSession`.
*   **`Run` and Scheduling Methods (`Schedule`, `ScheduleInternal`):** This is the core logic execution. I look for how tasks are triggered and managed. The `TaskDelay` class is clearly linked here. The `ScheduleReason` enum is important for understanding different triggers.
*   **`CaptureContent`:** This is where the actual content extraction happens. Notice the interaction with `cc::LayerTreeHost`.
*   **`SendContent`:**  Focuses on transmitting captured data using the `WebContentCaptureClient` interface. The batching logic (`kBatchSize`) is noteworthy.
*   **`ProcessSession` and `ProcessDocumentSession`:**  Manage the overall workflow of capturing and sending data for multiple documents.
*   **Helper Methods:**  `GetWebContentCaptureClient`, `ShouldPause`.

**4. Connecting to Web Concepts (JavaScript, HTML, CSS):**

This is where I relate the low-level C++ to high-level web technologies:

*   **HTML:** The captured `cc::NodeInfo` likely represents elements in the HTML DOM tree. The concept of a "document" and "nodes" is central to HTML.
*   **CSS:**  While not explicitly mentioned in the function names, the fact that the code interacts with the rendering engine (via `cc::LayerTreeHost`) means CSS properties that influence layout and painting are indirectly relevant. Changes in CSS can trigger content capture.
*   **JavaScript:** JavaScript interactions can cause dynamic changes to the DOM, which would trigger the content capture mechanism. User interactions like clicks, scrolls, and data entry via JavaScript are all potential triggers.

**5. Logic Inference (Assumptions and Outputs):**

I try to deduce what the code *does* based on its structure. I imagine scenarios:

*   **Scenario: Initial page load:**  The task likely starts capturing content after the page is rendered.
*   **Scenario: User scrolls:**  This probably triggers a content capture with a specific `ScheduleReason`.
*   **Scenario: JavaScript modifies the DOM:**  This leads to a "content change" and a scheduled capture.

I consider what the inputs and outputs of the key methods might be (though without seeing the definition of `cc::NodeInfo`, I remain somewhat abstract). `CaptureContent` takes no explicit input but relies on the internal state of the rendering tree and outputs a vector of `cc::NodeInfo`. `SendContent` takes a `DocumentSession` and sends `WebContentHolder` objects to the embedder.

**6. Identifying Potential User/Programming Errors:**

I look for areas where things could go wrong:

*   **Race Conditions:**  Since this code deals with asynchronous tasks and potentially interacts with the UI thread, race conditions are a possibility (although the code uses locking and task scheduling to mitigate this).
*   **Null Pointers:**  The frequent checks for null pointers (e.g., `local_frame_root_->View()`) highlight the importance of handling cases where parts of the rendering tree aren't yet initialized or have been destroyed.
*   **Incorrect Configuration:** The `WebContentCaptureClient` is provided by the embedder. If this client is not correctly implemented or configured, content capture might fail.

**7. Tracing User Actions:**

I consider how a user's actions lead to this code being executed:

*   **Basic Page Load:**  The browser requests a webpage, the HTML is parsed, CSS is applied, JavaScript is executed, and the rendering tree is built. `ContentCaptureTask` is likely initialized at some point during this process.
*   **Scrolling:** The user scrolls, triggering a scroll event. This event is handled by the browser, which might then call a method on `WebContentCaptureClient` indicating a scroll, leading to the scheduling of a `ContentCaptureTask`.
*   **JavaScript Interaction:** A user interacts with a button, causing JavaScript to modify the DOM. This DOM change is detected by the rendering engine and triggers a `Schedule` call on the `ContentCaptureTask`.

**8. Iteration and Refinement:**

My initial understanding might be incomplete or slightly off. As I delve deeper or encounter new information, I revisit my analysis and refine it. For example, understanding the role of the `histogram_reporter_` adds a dimension to the analysis – performance monitoring.

By following these steps, systematically examining the code, and relating it to web concepts, I can arrive at a comprehensive understanding of the functionality of `content_capture_task.cc`.
这个文件 `blink/renderer/core/content_capture/content_capture_task.cc` 是 Chromium Blink 引擎中负责**内容捕获**的核心组件。它的主要功能是：

**核心功能：**

1. **从渲染树捕获内容信息：** 该任务负责遍历当前页面的渲染树（Render Tree），提取出需要捕获的内容信息。这些信息以 `cc::NodeInfo` 的形式存在，包含了节点的位置、大小、层叠上下文等渲染相关的属性。
2. **管理捕获任务的调度和执行：**  它决定何时进行内容捕获，以及如何处理捕获到的数据。这涉及到延迟策略、重试机制以及与主线程的协作。
3. **批量发送捕获到的内容：** 为了效率，捕获到的内容不会立即逐个发送，而是会组织成批次 (`kBatchSize`)，然后通过 `WebContentCaptureClient` 接口发送给浏览器进程或其他组件。
4. **管理内容捕获会话：**  它跟踪哪些内容已经被捕获和发送，哪些内容发生了变化需要重新捕获。这通过 `TaskSession` 和 `TaskSession::DocumentSession` 来管理。
5. **处理内容变更：** 当页面内容发生变化时（例如，DOM 结构改变，样式改变，用户交互等），该任务会被触发以捕获新的内容信息。
6. **提供性能指标：**  通过 `ContentCaptureTaskHistogramReporter` 收集内容捕获任务的性能指标，例如捕获和发送内容所花费的时间，发送的节点数量等。

**与 JavaScript, HTML, CSS 的关系：**

该文件直接处理的是渲染后的页面状态，因此与 JavaScript, HTML, CSS 有着密切的关系：

*   **HTML:** `ContentCaptureTask` 捕获的节点信息直接来源于 HTML 结构生成的 DOM 树和渲染树。捕获的 `cc::NodeInfo`  会包含 DOM 节点的 ID (`DOMNodeIds`) 以及其他与 HTML 元素相关的渲染属性。
    *   **例子：**  假设 HTML 中有一个 `<div>Hello</div>`，`ContentCaptureTask` 可能会捕获到这个 `div` 元素的边界框坐标、层叠顺序、是否可见等信息。
*   **CSS:** CSS 样式会影响元素的渲染结果，而 `ContentCaptureTask` 捕获的是渲染后的状态。因此，CSS 的变化会直接影响捕获到的内容信息。
    *   **例子：**  如果 CSS 将上述 `div` 的颜色设置为红色，并将 `font-size` 增大，`ContentCaptureTask` 捕获到的信息中可能不会包含颜色或字体大小本身，但 `div` 的边界框大小可能会因为字体增大而变化。
*   **JavaScript:** JavaScript 可以动态地修改 DOM 结构和 CSS 样式，这些修改会导致页面内容的变更，从而触发 `ContentCaptureTask` 进行新的内容捕获。
    *   **例子：**  一个 JavaScript 脚本通过 `document.getElementById('myDiv').textContent = 'World';` 修改了 `div` 的文本内容，或者通过 `document.getElementById('myDiv').style.display = 'none';` 隐藏了该元素，这些操作都会被 `ContentCaptureTask` 感知到，并触发新的捕获任务。

**逻辑推理 (假设输入与输出):**

假设输入是用户刚刚加载完一个包含以下 HTML 的页面：

```html
<!DOCTYPE html>
<html>
<head>
  <title>Content Capture Test</title>
  <style>
    #target { width: 100px; height: 50px; background-color: blue; }
  </style>
</head>
<body>
  <div id="target"></div>
  <p>Some text</p>
</body>
</html>
```

**假设输入：** 页面加载完成，渲染树构建完毕。

**可能的输出 (简化描述):**

`ContentCaptureTask` 的 `CaptureContent()` 方法会遍历渲染树，并可能输出类似以下信息的 `cc::NodeInfo` 列表：

*   **针对 `div#target`:**
    *   节点类型: `div`
    *   ID: (某种内部表示的 ID)
    *   边界框:  (x, y, width: 100, height: 50)
    *   层叠上下文: ...
    *   是否可见: true
*   **针对 `p` 元素:**
    *   节点类型: `p`
    *   ID: (某种内部表示的 ID)
    *   边界框:  (x, y, width: ..., height: ...)
    *   层叠上下文: ...
    *   是否可见: true
    *   文本内容: "Some text" (如果捕获文本内容)

**假设输入：**  用户点击了一个按钮，JavaScript 脚本将 `div#target` 的背景色修改为红色。

**可能的输出：**

`ContentCaptureTask` 被触发，`CaptureContent()` 再次执行，输出的 `cc::NodeInfo` 列表中，针对 `div#target` 的条目，尽管其他属性可能不变，但由于渲染结果的变化，可能会标记这个节点需要更新。具体更新方式取决于 Content Capture 的实现细节。

**用户或编程常见的使用错误：**

1. **`WebContentCaptureClient` 未正确实现或连接：**  `ContentCaptureTask` 依赖于浏览器提供的 `WebContentCaptureClient` 接口来发送捕获到的数据。如果浏览器没有正确地实现或连接这个接口，内容捕获到的数据将无法发送。
    *   **例子：**  浏览器开发者可能忘记在相应的 Frame 或 Document 对象上设置 `WebContentCaptureClient` 的实现。
2. **频繁且不必要的 DOM 操作导致过多的内容捕获：**  如果 JavaScript 代码频繁地进行细微的 DOM 修改，可能会导致 `ContentCaptureTask` 被频繁触发，消耗不必要的资源。
    *   **例子：**  一个动画效果通过 JavaScript 每帧都修改一个元素的样式，如果没有合理的节流措施，可能会导致过多的内容捕获任务。
3. **假设捕获的是实时的、完全精确的像素级信息：**  `ContentCaptureTask` 通常捕获的是抽象的渲染信息，而不是实时的像素数据。开发者不应该假设捕获到的数据是像素级的完美快照。
4. **在不需要内容捕获的场景下仍然启用：**  如果某个功能或产品不需要使用内容捕获，应该禁用它以减少性能开销。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户发起页面加载：** 用户在地址栏输入网址或点击链接，浏览器开始加载网页。
2. **HTML 解析和 DOM 树构建：** 渲染引擎解析 HTML 代码，构建 DOM 树。
3. **CSS 解析和样式计算：** 渲染引擎解析 CSS 样式，计算每个元素的最终样式。
4. **渲染树构建：**  结合 DOM 树和样式信息，构建渲染树，确定元素的布局和绘制顺序。
5. **`ContentCaptureTask` 初始化：** 在渲染树构建完成后，或者在特定的时机，`ContentCaptureTask` 被创建并与特定的 `LocalFrame` 关联。
6. **初始内容捕获 (可能)：**  在页面初始渲染完成后，`ContentCaptureTask` 可能会被调度执行第一次内容捕获，将初始的渲染信息发送给浏览器。
7. **用户交互或 JavaScript 触发内容变更：**
    *   **滚动页面：**  用户滚动页面可能会触发内容捕获，以便更新可视区域的内容信息。`ScheduleReason::kScrolling`。
    *   **点击按钮触发 JavaScript 修改 DOM：** JavaScript 代码修改了 DOM 结构或样式，例如改变了元素的文本内容、位置、大小、可见性等。这会触发 `has_content_change_ = true;` 和 `Schedule()` 函数，其中 `reason` 可能为 `ScheduleReason::kUserActivatedContentChange` 或 `ScheduleReason::kNonUserActivatedContentChange`。
    *   **页面动画或动态效果：**  JavaScript 或 CSS 动画导致元素属性发生变化，同样会触发内容捕获。
8. **`ContentCaptureTask::Run()` 执行：**  根据调度策略 (`TaskDelay`)，`ContentCaptureTask` 的 `Run()` 方法被执行。
9. **`ContentCaptureTask::CaptureContent()` 执行：**  `Run()` 方法内部调用 `CaptureContent()` 方法，遍历渲染树，提取 `cc::NodeInfo`。
10. **`TaskSession` 管理捕获到的内容：** 捕获到的 `cc::NodeInfo` 被存储在 `TaskSession` 中。
11. **`ContentCaptureTask::SendContent()` 执行：**  将捕获到的内容分批次通过 `WebContentCaptureClient` 发送给浏览器进程。

**调试线索：**

*   **断点设置：** 在 `ContentCaptureTask::Run()`, `CaptureContent()`, `SendContent()` 等关键方法设置断点，观察其执行时机和参数。
*   **日志输出：**  在关键路径添加日志输出，例如打印 `ScheduleReason`，捕获到的节点数量，发送的内容批次大小等。
*   **Trace 事件：**  Chromium 提供了 Trace 事件机制，可以查看 `content_capture` 相关的 Trace 事件，了解任务的调度和执行情况。
*   **检查 `WebContentCaptureClient` 的实现：** 确认浏览器进程是否正确实现了 `WebContentCaptureClient` 接口，并且能够接收到发送的数据。
*   **分析页面性能：**  观察页面在进行用户交互或动画时的性能表现，如果发现异常的 CPU 或内存占用，可能与频繁的内容捕获有关。

总而言之，`content_capture_task.cc` 是 Blink 引擎中一个关键的组件，负责捕获页面的渲染状态并将这些信息传递给浏览器或其他需要这些信息的模块。理解其工作原理有助于调试与页面内容捕获相关的各种问题。

### 提示词
```
这是目录为blink/renderer/core/content_capture/content_capture_task.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/content_capture/content_capture_task.h"

#include <cmath>

#include "base/auto_reset.h"
#include "base/feature_list.h"
#include "cc/trees/layer_tree_host.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_content_capture_client.h"
#include "third_party/blink/public/web/web_content_holder.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

ContentCaptureTask::TaskDelay::TaskDelay(
    const base::TimeDelta& task_initial_delay)
    : task_initial_delay_(task_initial_delay) {}

base::TimeDelta ContentCaptureTask::TaskDelay::ResetAndGetInitialDelay() {
  delay_exponent_ = 0;
  return task_initial_delay_;
}

base::TimeDelta ContentCaptureTask::TaskDelay::GetNextTaskDelay() const {
  return base::Milliseconds(task_initial_delay_.InMilliseconds() *
                            (1 << delay_exponent_));
}

void ContentCaptureTask::TaskDelay::IncreaseDelayExponent() {
  // Increases the delay up to 128s.
  if (delay_exponent_ < 8)
    ++delay_exponent_;
}

ContentCaptureTask::ContentCaptureTask(LocalFrame& local_frame_root,
                                       TaskSession& task_session)
    : local_frame_root_(&local_frame_root),
      task_session_(&task_session),
      delay_task_(
          local_frame_root_->GetTaskRunner(TaskType::kInternalContentCapture),
          this,
          &ContentCaptureTask::Run) {
  DCHECK(local_frame_root.Client()->GetWebContentCaptureClient());
  task_delay_ = std::make_unique<TaskDelay>(local_frame_root.Client()
                                                ->GetWebContentCaptureClient()
                                                ->GetTaskInitialDelay());

  // The histogram is all about time, just disable it if high resolution isn't
  // supported.
  if (base::TimeTicks::IsHighResolution()) {
    histogram_reporter_ =
        base::MakeRefCounted<ContentCaptureTaskHistogramReporter>();
    task_session_->SetSentNodeCountCallback(
        WTF::BindRepeating(&ContentCaptureTaskHistogramReporter::
                               RecordsSentContentCountPerDocument,
                           histogram_reporter_));
  }
}

ContentCaptureTask::~ContentCaptureTask() = default;

void ContentCaptureTask::Shutdown() {
  DCHECK(local_frame_root_);
  local_frame_root_ = nullptr;
  CancelTask();
}

bool ContentCaptureTask::CaptureContent(Vector<cc::NodeInfo>& data) {
  if (captured_content_for_testing_) {
    data = captured_content_for_testing_.value();
    return true;
  }
  // Because this is called from a different task, the frame may be in any
  // lifecycle step so we need to early-out in many cases.
  if (const auto* root_frame_view = local_frame_root_->View()) {
    if (const auto* cc_layer = root_frame_view->RootCcLayer()) {
      if (auto* layer_tree_host = cc_layer->layer_tree_host()) {
        std::vector<cc::NodeInfo> content;
        if (layer_tree_host->CaptureContent(&content)) {
          for (auto c : content)
            data.push_back(std::move(c));
          return true;
        }
        return false;
      }
    }
  }
  return false;
}

bool ContentCaptureTask::CaptureContent() {
  DCHECK(task_session_);
  Vector<cc::NodeInfo> buffer;
  if (histogram_reporter_) {
    histogram_reporter_->OnCaptureContentStarted();
  }
  bool result = CaptureContent(buffer);
  if (!buffer.empty())
    task_session_->SetCapturedContent(buffer);
  if (histogram_reporter_) {
    histogram_reporter_->OnCaptureContentEnded(buffer.size());
  }
  return result;
}

void ContentCaptureTask::SendContent(
    TaskSession::DocumentSession& doc_session) {
  auto* document = doc_session.GetDocument();
  DCHECK(document);
  auto* client = GetWebContentCaptureClient(*document);
  DCHECK(client);

  if (histogram_reporter_) {
    histogram_reporter_->OnSendContentStarted();
  }
  WebVector<WebContentHolder> content_batch;
  content_batch.reserve(kBatchSize);
  // Only send changed content after the new content was sent.
  bool sending_changed_content = !doc_session.HasUnsentCapturedContent();
  while (content_batch.size() < kBatchSize) {
    ContentHolder* holder;
    if (sending_changed_content)
      holder = doc_session.GetNextChangedNode();
    else
      holder = doc_session.GetNextUnsentNode();
    if (!holder)
      break;
    content_batch.emplace_back(WebContentHolder(*holder));
  }
  if (!content_batch.empty()) {
    if (sending_changed_content) {
      client->DidUpdateContent(content_batch);
    } else {
      client->DidCaptureContent(content_batch, !doc_session.FirstDataHasSent());
      doc_session.SetFirstDataHasSent();
    }
  }
  if (histogram_reporter_) {
    histogram_reporter_->OnSendContentEnded(content_batch.size());
  }
}

WebContentCaptureClient* ContentCaptureTask::GetWebContentCaptureClient(
    const Document& document) {
  if (auto* frame = document.GetFrame())
    return frame->Client()->GetWebContentCaptureClient();
  return nullptr;
}

bool ContentCaptureTask::ProcessSession() {
  DCHECK(task_session_);
  while (auto* document_session =
             task_session_->GetNextUnsentDocumentSession()) {
    if (!ProcessDocumentSession(*document_session))
      return false;
    if (ShouldPause())
      return !task_session_->HasUnsentData();
  }
  return true;
}

bool ContentCaptureTask::ProcessDocumentSession(
    TaskSession::DocumentSession& doc_session) {
  // If no client, we don't need to send it at all.
  auto* content_capture_client =
      GetWebContentCaptureClient(*doc_session.GetDocument());
  if (!content_capture_client) {
    doc_session.Reset();
    return true;
  }

  while (doc_session.HasUnsentCapturedContent() ||
         doc_session.HasUnsentChangedContent()) {
    SendContent(doc_session);
    if (ShouldPause()) {
      return !doc_session.HasUnsentData();
    }
  }
  // Sent the detached nodes.
  if (doc_session.HasUnsentDetachedNodes())
    content_capture_client->DidRemoveContent(doc_session.MoveDetachedNodes());
  DCHECK(!doc_session.HasUnsentData());
  return true;
}

bool ContentCaptureTask::RunInternal() {
  base::AutoReset<TaskState> state(&task_state_, TaskState::kProcessRetryTask);
  // Already shutdown.
  if (!local_frame_root_)
    return true;

  do {
    switch (task_state_) {
      case TaskState::kProcessRetryTask:
        if (task_session_->HasUnsentData()) {
          if (!ProcessSession())
            return false;
        }
        task_state_ = TaskState::kCaptureContent;
        break;
      case TaskState::kCaptureContent:
        if (!has_content_change_)
          return true;
        if (!CaptureContent()) {
          // Don't schedule task again in this case.
          return true;
        }
        has_content_change_ = false;
        if (!task_session_->HasUnsentData())
          return true;

        task_state_ = TaskState::kProcessCurrentSession;
        break;
      case TaskState::kProcessCurrentSession:
        return ProcessSession();
      default:
        return true;
    }
  } while (!ShouldPause());
  return false;
}

void ContentCaptureTask::Run(TimerBase*) {
  TRACE_EVENT0("content_capture", "RunTask");
  task_delay_->IncreaseDelayExponent();
  if (histogram_reporter_) {
    histogram_reporter_->OnTaskRun();
  }
  bool completed = RunInternal();
  if (!completed) {
    ScheduleInternal(ScheduleReason::kRetryTask);
  }
  if (histogram_reporter_ &&
      (completed || task_state_ == TaskState::kCaptureContent)) {
    // The current capture session ends if the task indicates it completed or
    // is about to capture the new changes.
    histogram_reporter_->OnAllCapturedContentSent();
  }
}

base::TimeDelta ContentCaptureTask::GetAndAdjustDelay(ScheduleReason reason) {
  switch (reason) {
    case ScheduleReason::kFirstContentChange:
    case ScheduleReason::kScrolling:
    case ScheduleReason::kRetryTask:
    case ScheduleReason::kUserActivatedContentChange:
      return task_delay_->ResetAndGetInitialDelay();
    case ScheduleReason::kNonUserActivatedContentChange:
      return task_delay_->GetNextTaskDelay();
  }
}

void ContentCaptureTask::ScheduleInternal(ScheduleReason reason) {
  DCHECK(local_frame_root_);
  base::TimeDelta delay = GetAndAdjustDelay(reason);

  // Return if the current task is about to run soon.
  if (delay_task_.IsActive() && delay_task_.NextFireInterval() < delay) {
    return;
  }

  if (delay_task_.IsActive())
    delay_task_.Stop();

  delay_task_.StartOneShot(delay, FROM_HERE);
  TRACE_EVENT_INSTANT1("content_capture", "ScheduleTask",
                       TRACE_EVENT_SCOPE_THREAD, "reason", reason);
  if (histogram_reporter_) {
    histogram_reporter_->OnTaskScheduled(/* record_task_delay = */ reason !=
                                         ScheduleReason::kRetryTask);
  }
}

void ContentCaptureTask::Schedule(ScheduleReason reason) {
  DCHECK(local_frame_root_);
  has_content_change_ = true;
  if (histogram_reporter_) {
    histogram_reporter_->OnContentChanged();
  }
  ScheduleInternal(reason);
}

bool ContentCaptureTask::ShouldPause() {
  if (task_stop_for_testing_) {
    return task_state_ == task_stop_for_testing_.value();
  }
  return ThreadScheduler::Current()->ShouldYieldForHighPriorityWork();
}

void ContentCaptureTask::CancelTask() {
  if (delay_task_.IsActive())
    delay_task_.Stop();
}
void ContentCaptureTask::ClearDocumentSessionsForTesting() {
  task_session_->ClearDocumentSessionsForTesting();
}

base::TimeDelta ContentCaptureTask::GetTaskNextFireIntervalForTesting() const {
  return delay_task_.IsActive() ? delay_task_.NextFireInterval()
                                : base::TimeDelta();
}

void ContentCaptureTask::CancelTaskForTesting() {
  CancelTask();
}

void ContentCaptureTask::Trace(Visitor* visitor) const {
  visitor->Trace(local_frame_root_);
  visitor->Trace(task_session_);
  visitor->Trace(delay_task_);
}

}  // namespace blink
```