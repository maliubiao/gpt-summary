Response:
Let's break down the thought process for analyzing the `ServiceWorkerEventQueue.cc` file.

**1. Understanding the Goal:**

The primary goal is to understand the *functionality* of this code. This means figuring out what it does, how it works, and its role in the larger Chromium/Blink system. The secondary goal is to connect this functionality to web technologies (JavaScript, HTML, CSS) and identify potential user/developer errors.

**2. Initial Skim and Keyword Identification:**

The first step is a quick read-through of the code, looking for keywords and familiar concepts. Keywords that jump out include:

* `ServiceWorkerEventQueue`: This is the central class, so its methods and data members are key.
* `Event`, `Enqueue`, `Start`, `End`:  These suggest the core functionality is managing a queue of events.
* `Normal`, `Pending`, `Offline`: These seem to be different types of events.
* `StartCallback`, `AbortCallback`: Callbacks associated with events.
* `Timeout`, `Idle`:  Related to event lifecycle and inactivity.
* `StayAwakeToken`:  Something that prevents idling.
* `base::TimeDelta`, `base::TimeTicks`:  Indicates time management.
* `base::FeatureList`:  Suggests feature flags and potentially conditional behavior.
* `mojom::ServiceWorkerEventStatus`:  Related to event outcomes.

**3. Deconstructing the Class Structure:**

Next, examine the class `ServiceWorkerEventQueue` and its nested classes (`StayAwakeToken`, `Event`, `EventInfo`). Understanding the purpose of each class is crucial.

* **`ServiceWorkerEventQueue`:** The main manager of the event queue. It handles enqueuing, processing, and timing out events.
* **`StayAwakeToken`:**  A mechanism to keep the service worker alive while an operation is in progress. This is important to prevent premature shutdown.
* **`Event`:** Represents a single event in the queue, holding its type, callbacks, and timeout.
* **`EventInfo`:**  Contains metadata about an event, specifically its expiration time and abort callback.

**4. Analyzing Key Methods:**

Focus on the most important methods and their roles in the overall process:

* **`EnqueueNormal`, `EnqueuePending`, `EnqueueOffline`:** These methods add events to the queue. Note the different event types.
* **`ProcessEvents`:** This is the core logic for deciding which event to run next. It considers event type and whether an event is already running.
* **`StartEvent`:**  Actually initiates the processing of an event.
* **`EndEvent`:**  Marks the completion of an event.
* **`UpdateStatus`:** Handles event timeouts.
* **`OnNoInflightEvent`:**  Called when there are no active events, potentially triggering the idle callback.
* **`SetIdleDelay`:** Configures the delay before the service worker goes idle.
* **`CreateStayAwakeToken`:** Creates a token to prevent idling.

**5. Tracing the Event Lifecycle:**

Imagine the journey of an event through the system:

1. **Enqueue:** An event is added to the queue using one of the `Enqueue...` methods.
2. **Process:** When the queue is ready and no other incompatible events are running, `ProcessEvents` selects an event.
3. **Start:** `StartEvent` executes the event's start callback.
4. **Running:** The service worker processes the event (this happens *outside* this class, in the service worker's JavaScript).
5. **End:**  The service worker signals completion by calling `EndEvent`.
6. **Timeout/Abort:** If an event takes too long, `UpdateStatus` can trigger the abort callback.

**6. Connecting to Web Technologies:**

Think about how service workers interact with web pages and how these events relate:

* **JavaScript:** Service worker event listeners (e.g., `install`, `activate`, `fetch`, `push`, `message`) trigger these events. The callbacks in `ServiceWorkerEventQueue` will eventually lead to the execution of the corresponding JavaScript event handler.
* **HTML:**  While not directly related to HTML structure, the *actions* in the HTML (e.g., loading resources, network requests) can indirectly trigger service worker events.
* **CSS:** Similarly, CSS loading or changes don't directly trigger these events, but the *network requests* made to fetch CSS files do.

**7. Identifying Potential Issues and Debugging:**

Consider what could go wrong:

* **Timeouts:** Events taking too long can lead to aborts, potentially causing unexpected behavior on the web page.
* **Deadlocks/Blocking:**  If an event prevents other events from running, it could lead to a stuck service worker.
* **Idle Issues:**  Incorrectly managing idle timeouts can cause the service worker to shut down prematurely or stay alive unnecessarily.
* **Concurrency:**  Managing the order and execution of different event types is crucial to avoid race conditions.

**8. Constructing Examples and Scenarios:**

Create concrete examples to illustrate the concepts:

* **Timeout:** A fetch event takes longer than expected due to a slow network.
* **Idle:**  A service worker becomes idle after a period of inactivity.
* **Stay Awake:** A background sync event uses a `StayAwakeToken` to prevent interruption.
* **User Error:**  A developer might write code that causes a service worker event handler to take an excessively long time.

**9. Thinking about Debugging:**

Consider how a developer would track down issues related to the event queue:

* **Service Worker Inspection Tools:** Chromium's developer tools provide insights into service worker status, events, and network activity.
* **Logs:**  The `DCHECK` statements in the code are hints that logging (or assertions in debug builds) could be used to track the flow of events.
* **Breakpoints:** Setting breakpoints in the `ServiceWorkerEventQueue` code itself would allow for detailed step-by-step analysis.

**10. Refining and Organizing:**

Finally, organize the information into clear sections with headings and bullet points to make it easy to understand. Use precise language and avoid jargon where possible. Ensure that the explanation addresses all parts of the original request.
这个 `service_worker_event_queue.cc` 文件是 Chromium Blink 渲染引擎中，专门用于管理 Service Worker 事件队列的组件。 它的主要功能是：

**核心功能：管理 Service Worker 事件**

1. **事件排队 (Enqueueing Events):**  接收并存储需要 Service Worker 处理的各种事件。这些事件可能来自浏览器内核的各个部分，例如网络请求拦截 (fetch event)、消息推送 (push event)、后台同步 (background sync event) 等。
   -  提供了 `EnqueueNormal`, `EnqueuePending`, `EnqueueOffline` 等方法来添加不同类型的事件。
   -  每个事件都包含了启动回调 (`start_callback`) 和中止回调 (`abort_callback`)，以及可选的自定义超时时间。

2. **事件调度和处理 (Scheduling and Processing Events):**  根据事件的类型和当前 Service Worker 的状态，决定何时启动处理哪个事件。
   -  维护了两个主要的事件队列：`queued_online_events_` (在线事件) 和 `queued_offline_events_` (离线事件)。
   -  使用 `ProcessEvents()` 方法来从队列中取出可以处理的事件并启动。
   -  `CanStartEvent()` 方法决定一个事件是否可以在当前状态下启动。例如，离线事件可能只有在没有其他在线事件正在运行时才能启动。

3. **事件生命周期管理 (Event Lifecycle Management):** 跟踪事件的开始和结束，以及超时处理。
   -  `StartEvent()` 方法负责执行事件的启动回调。
   -  `EndEvent()` 方法在事件处理完成后被调用，从内部记录中移除该事件。
   -  `UpdateStatus()` 方法定期检查事件是否超时，如果超时则执行中止回调。

4. **保持 Service Worker 活跃 (Keeping Service Worker Alive):**  在有事件需要处理时，防止 Service Worker 进入休眠状态。
   -  使用了 `StayAwakeToken` 类来管理保持 Service Worker 活跃的状态。当有事件需要处理时，会创建一个 `StayAwakeToken`，当所有相关操作完成后，该 Token 会被销毁，允许 Service Worker 进入休眠。
   -  `ResetIdleTimeout()` 方法重置空闲超时计时器。
   -  `SetIdleDelay()` 方法设置 Service Worker 空闲超时的时间。

5. **空闲状态管理 (Idle State Management):**  当没有事件需要处理时，管理 Service Worker 的空闲状态和休眠。
   -  `idle_callback_` 是一个在 Service Worker 空闲一段时间后执行的回调，通常用于释放资源或进入休眠状态。
   -  `OnNoInflightEvent()` 方法在没有正在处理的事件时被调用，并安排空闲回调的执行。

6. **事件 ID 管理 (Event ID Management):**  为每个事件分配唯一的 ID。

**与 JavaScript, HTML, CSS 的关系：**

`ServiceWorkerEventQueue` 位于浏览器内核，是 Service Worker 功能的核心部分。它并不直接操作 JavaScript、HTML 或 CSS，而是作为 Service Worker 与这些技术交互的桥梁。

* **JavaScript:**
    - **触发事件：**  当网页中的 JavaScript 代码发起网络请求 (如使用 `fetch`)，或者收到推送消息 (`push` event listener)，或者执行后台同步 (`sync` event listener) 时，浏览器内核会创建相应的事件并将其添加到 `ServiceWorkerEventQueue` 中。
    - **事件处理：**  `ServiceWorkerEventQueue` 调度的事件最终会触发 Service Worker 中对应的 JavaScript 事件处理函数 (例如 `onfetch`, `onpush`, `onsync`) 的执行。
    - **假设输入与输出：**
        - **假设输入：**  JavaScript 代码执行 `fetch('/api/data')`。
        - **逻辑推理：** 浏览器会创建一个 `fetch` 事件，并将其添加到 `ServiceWorkerEventQueue` 中。
        - **假设输出：**  `ServiceWorkerEventQueue` 最终会调用注册在 Service Worker 中的 `fetch` 事件处理函数，并将网络请求的信息传递给它。Service Worker 的 JavaScript 代码可以决定如何处理这个请求（例如，从缓存中返回数据，或者发起真正的网络请求）。

* **HTML:**
    - **间接影响：** HTML 中资源的加载，例如 `<img src="...">` 或 `<link rel="stylesheet" href="...">`，会触发网络请求，这些请求可能被 Service Worker 拦截处理。`ServiceWorkerEventQueue` 会管理这些 `fetch` 事件。
    - **用户操作举例：** 用户点击一个包含 `<img>` 标签的链接，导致浏览器尝试加载图片。这个加载图片的请求会触发一个 `fetch` 事件，并被添加到 `ServiceWorkerEventQueue` 中，等待 Service Worker 处理。

* **CSS:**
    - **间接影响：** 类似于 HTML，CSS 文件的加载也会触发网络请求，进而产生 `fetch` 事件，由 `ServiceWorkerEventQueue` 管理。
    - **用户操作举例：** 用户访问一个网页，浏览器开始解析 HTML 并发现一个 `<link>` 标签指向一个 CSS 文件。加载这个 CSS 文件的请求会产生一个 `fetch` 事件，进入 `ServiceWorkerEventQueue`。

**逻辑推理示例：**

假设 Service Worker 注册了一个 `fetch` 事件监听器，并且网页发起了一个网络请求。

1. **输入：** 网页 JavaScript 执行 `fetch('/some/resource')`。
2. **逻辑推理：**
   - 浏览器内核创建一个类型为 "normal" 的 `fetch` 事件，包含请求的 URL 等信息。
   - `ServiceWorkerEventQueue::EnqueueNormal` 被调用，将该事件添加到 `queued_online_events_` 队列中。
   - 如果当前没有其他在线事件正在运行，并且 Service Worker 已经准备好处理事件 (`is_ready_for_processing_events_` 为 true)，则 `ProcessEvents()` 会被调用。
   - `ProcessEvents()` 检查 `queued_online_events_` 队列，发现待处理的 `fetch` 事件。
   - `CanStartEvent()` 返回 true，因为没有其他冲突的事件正在运行。
   - `StartEvent()` 被调用，执行与该 `fetch` 事件关联的启动回调。
   - 这个启动回调最终会调用 Service Worker 中注册的 `onfetch` 事件处理函数。
3. **输出：** Service Worker 的 `onfetch` 事件处理函数被执行，接收到请求对象，可以决定如何响应这个请求 (例如，返回缓存的响应或发起网络请求)。

**用户或编程常见的使用错误：**

1. **Service Worker 事件处理函数执行时间过长：**
   - **错误：**  在 Service Worker 的事件处理函数中执行了大量耗时的同步操作，或者发起了长时间运行的网络请求但没有妥善处理超时。
   - **后果：**  可能导致事件超时，`ServiceWorkerEventQueue` 会调用中止回调，并且可能影响用户体验。
   - **用户操作如何到达：** 用户点击一个链接，触发一个 `fetch` 事件，Service Worker 的 `onfetch` 处理函数执行了一个非常慢的数据库查询。 `ServiceWorkerEventQueue` 中的 `UpdateStatus()` 检测到事件超时。

2. **错误地管理 `StayAwakeToken`：**
   - **错误：** 创建了 `StayAwakeToken` 但忘记在操作完成后销毁它。
   - **后果：**  可能导致 Service Worker 持续保持活跃状态，消耗不必要的资源。
   - **用户操作如何到达：**  开发者在 Service Worker 的 `onbackgroundsync` 处理函数中创建了一个 `StayAwakeToken`，但在同步操作完成后忘记释放它。即使同步完成，Service Worker 也不会进入空闲状态。

3. **Service Worker 初始化未完成就尝试处理事件：**
   - **错误：**  在 Service Worker 的全局脚本执行完成之前，就尝试分发事件。
   - **后果：**  可能会导致某些事件处理失败或行为异常。
   - **用户操作如何到达：** 用户首次访问一个安装了 Service Worker 的网站，浏览器开始下载并执行 Service Worker 的脚本。 如果在脚本执行完成前，有网络请求需要被 Service Worker 处理，可能会遇到问题。  `kServiceWorkerEventQueueWaitForScriptEvaluation` 这个 Feature Flag 就是为了解决这个问题而引入的。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在一个安装了 Service Worker 的网站上点击了一个链接，导致浏览器发起了一个新的页面请求。

1. **用户操作：** 用户点击链接。
2. **浏览器行为：** 浏览器开始导航到新的 URL。
3. **网络请求：** 浏览器发起对新页面 HTML 的网络请求。
4. **Service Worker 拦截：** 如果 Service Worker 已经注册并且作用域包含当前页面，该网络请求会被 Service Worker 拦截。
5. **`fetch` 事件创建：** 浏览器内核创建一个 `fetch` 事件，包含该网络请求的信息。
6. **事件入队：** 这个 `fetch` 事件被添加到 `ServiceWorkerEventQueue` 的 `queued_online_events_` 队列中，通过调用 `EnqueueNormal`。
7. **事件调度：** `ServiceWorkerEventQueue` 检查当前状态，如果可以处理 `fetch` 事件，`ProcessEvents()` 会被调用。
8. **事件启动：** `StartEvent()` 被调用，执行与该 `fetch` 事件关联的启动回调。
9. **Service Worker `onfetch` 调用：** 启动回调最终会调用 Service Worker 中注册的 `onfetch` 事件处理函数，并将请求对象传递给它。

**调试线索：**

* **查看 Service Worker 的状态：**  在 Chrome 的开发者工具中，可以查看 Service Worker 的状态（例如，是否激活，是否正在运行）。
* **检查 Service Worker 的事件日志：**  开发者工具通常会显示 Service Worker 接收和处理的事件。
* **在 `ServiceWorkerEventQueue.cc` 中设置断点：**  如果需要深入了解事件队列的行为，可以在关键方法（如 `EnqueueNormal`, `ProcessEvents`, `StartEvent`, `EndEvent`, `UpdateStatus`) 中设置断点，跟踪事件的流动和状态变化。
* **查看 `DCHECK` 宏：** 代码中使用了 `DCHECK` 宏，这些宏在 Debug 构建中会进行断言检查。如果触发了断言，可以提供关于程序状态错误的信息。
* **检查 Feature Flag 的状态：**  `kServiceWorkerEventQueueWaitForScriptEvaluation` 的状态会影响事件处理的时机，在调试时需要注意其是否启用。

总而言之，`service_worker_event_queue.cc` 是 Service Worker 功能中至关重要的组件，它负责有序地管理和调度各种 Service Worker 事件，确保 Service Worker 能够正确地响应来自浏览器和网页的请求。 理解它的工作原理对于调试 Service Worker 相关的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/service_worker/service_worker_event_queue.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/service_worker/service_worker_event_queue.h"

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_event_status.mojom-blink.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

// This feature flag enables a new behavior that waits
// processing events until the top-level script is evaluated.
// See: https://crbug.com/1462568
BASE_FEATURE(kServiceWorkerEventQueueWaitForScriptEvaluation,
             "ServiceWorkerEventQueueWaitForScriptEvaluation",
             base::FEATURE_ENABLED_BY_DEFAULT);

// static
constexpr base::TimeDelta ServiceWorkerEventQueue::kEventTimeout;
constexpr base::TimeDelta ServiceWorkerEventQueue::kUpdateInterval;

ServiceWorkerEventQueue::StayAwakeToken::StayAwakeToken(
    base::WeakPtr<ServiceWorkerEventQueue> event_queue)
    : event_queue_(std::move(event_queue)) {
  DCHECK(event_queue_);
  event_queue_->ResetIdleTimeout();
  event_queue_->num_of_stay_awake_tokens_++;
}

ServiceWorkerEventQueue::StayAwakeToken::~StayAwakeToken() {
  // If |event_queue_| has already been destroyed, it means the worker thread
  // has already been killed.
  if (!event_queue_)
    return;
  DCHECK_GT(event_queue_->num_of_stay_awake_tokens_, 0);
  event_queue_->num_of_stay_awake_tokens_--;

  if (!event_queue_->HasInflightEvent())
    event_queue_->OnNoInflightEvent();
}

ServiceWorkerEventQueue::ServiceWorkerEventQueue(
    BeforeStartEventCallback before_start_event_callback,
    base::RepeatingClosure idle_callback,
    scoped_refptr<base::SequencedTaskRunner> task_runner)
    : ServiceWorkerEventQueue(std::move(before_start_event_callback),
                              std::move(idle_callback),
                              std::move(task_runner),
                              base::DefaultTickClock::GetInstance()) {}

ServiceWorkerEventQueue::ServiceWorkerEventQueue(
    BeforeStartEventCallback before_start_event_callback,
    base::RepeatingClosure idle_callback,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    const base::TickClock* tick_clock)
    : task_runner_(std::move(task_runner)),
      before_start_event_callback_(std::move(before_start_event_callback)),
      idle_callback_(std::move(idle_callback)),
      tick_clock_(tick_clock) {
  if (!base::FeatureList::IsEnabled(
          kServiceWorkerEventQueueWaitForScriptEvaluation)) {
    is_ready_for_processing_events_ = true;
  }
}

ServiceWorkerEventQueue::~ServiceWorkerEventQueue() {
  // Abort all callbacks.
  for (auto& event : all_events_) {
    std::move(event.value->abort_callback)
        .Run(blink::mojom::ServiceWorkerEventStatus::ABORTED);
  }
}

void ServiceWorkerEventQueue::Start() {
  DCHECK(!timer_.IsRunning());
  timer_.Start(FROM_HERE, kUpdateInterval,
               WTF::BindRepeating(&ServiceWorkerEventQueue::UpdateStatus,
                                  WTF::Unretained(this)));
  if (base::FeatureList::IsEnabled(
          kServiceWorkerEventQueueWaitForScriptEvaluation)) {
    is_ready_for_processing_events_ = true;
    ResetIdleTimeout();
    ProcessEvents();
  } else if (!HasInflightEvent() && !HasScheduledIdleCallback()) {
    // If no event happens until Start(), the idle callback should be scheduled.
    OnNoInflightEvent();
  }
}

void ServiceWorkerEventQueue::EnqueueNormal(
    int event_id,
    StartCallback start_callback,
    AbortCallback abort_callback,
    std::optional<base::TimeDelta> custom_timeout) {
  EnqueueEvent(std::make_unique<Event>(
      event_id, Event::Type::Normal, std::move(start_callback),
      std::move(abort_callback), std::move(custom_timeout)));
}

void ServiceWorkerEventQueue::EnqueuePending(
    int event_id,
    StartCallback start_callback,
    AbortCallback abort_callback,
    std::optional<base::TimeDelta> custom_timeout) {
  EnqueueEvent(std::make_unique<Event>(
      event_id, Event::Type::Pending, std::move(start_callback),
      std::move(abort_callback), std::move(custom_timeout)));
}

void ServiceWorkerEventQueue::EnqueueOffline(
    int event_id,
    StartCallback start_callback,
    AbortCallback abort_callback,
    std::optional<base::TimeDelta> custom_timeout) {
  EnqueueEvent(std::make_unique<ServiceWorkerEventQueue::Event>(
      event_id, ServiceWorkerEventQueue::Event::Type::Offline,
      std::move(start_callback), std::move(abort_callback),
      std::move(custom_timeout)));
}

bool ServiceWorkerEventQueue::CanStartEvent(const Event& event) const {
  if (running_event_type_ == RunningEventType::kNone) {
    DCHECK(!HasInflightEvent());
    return true;
  }
  if (event.type == Event::Type::Offline)
    return running_event_type_ == RunningEventType::kOffline;
  return running_event_type_ == RunningEventType::kOnline;
}

std::map<int, std::unique_ptr<ServiceWorkerEventQueue::Event>>&
ServiceWorkerEventQueue::GetActiveEventQueue() {
  if (running_event_type_ == RunningEventType::kNone) {
    // Either online events or offline events can be started when inflight
    // events don't exist. If online events exist in the queue, prioritize
    // online events.
    return queued_online_events_.empty() ? queued_offline_events_
                                         : queued_online_events_;
  }
  if (running_event_type_ == RunningEventType::kOffline)
    return queued_offline_events_;
  return queued_online_events_;
}

void ServiceWorkerEventQueue::EnqueueEvent(std::unique_ptr<Event> event) {
  DCHECK(event->type != Event::Type::Pending || did_idle_timeout());
  DCHECK(!HasEvent(event->event_id));
  DCHECK(!HasEventInQueue(event->event_id));

  bool can_start_processing_events = is_ready_for_processing_events_ &&
                                     !processing_events_ &&
                                     event->type != Event::Type::Pending;

  // Start counting the timer when an event is enqueued.
  all_events_.insert(
      event->event_id,
      std::make_unique<EventInfo>(
          tick_clock_->NowTicks() +
              event->custom_timeout.value_or(kEventTimeout),
          WTF::BindOnce(std::move(event->abort_callback), event->event_id)));

  auto& queue = event->type == Event::Type::Offline ? queued_offline_events_
                                                    : queued_online_events_;
  queue.emplace(event->event_id, std::move(event));

  if (!can_start_processing_events)
    return;

  ResetIdleTimeout();
  ProcessEvents();
}

void ServiceWorkerEventQueue::ProcessEvents() {
  // TODO(crbug.com/1462568): Switch to CHECK once we resolve the bug.
  DCHECK(is_ready_for_processing_events_);
  DCHECK(!processing_events_);
  processing_events_ = true;
  auto& queue = GetActiveEventQueue();
  while (!queue.empty() && CanStartEvent(*queue.begin()->second)) {
    int event_id = queue.begin()->first;
    std::unique_ptr<Event> event = std::move(queue.begin()->second);
    queue.erase(queue.begin());
    StartEvent(event_id, std::move(event));
  }
  processing_events_ = false;

  // We have to check HasInflightEvent() and may trigger
  // OnNoInflightEvent() here because StartEvent() can call EndEvent()
  // synchronously, and EndEvent() never triggers OnNoInflightEvent()
  // while ProcessEvents() is running.
  if (!HasInflightEvent())
    OnNoInflightEvent();
}

void ServiceWorkerEventQueue::StartEvent(int event_id,
                                         std::unique_ptr<Event> event) {
  DCHECK(HasEvent(event_id));
  running_event_type_ = event->type == Event::Type::Offline
                            ? RunningEventType::kOffline
                            : RunningEventType::kOnline;
  if (before_start_event_callback_)
    before_start_event_callback_.Run(event->type == Event::Type::Offline);
  std::move(event->start_callback).Run(event_id);
}

void ServiceWorkerEventQueue::EndEvent(int event_id) {
  DCHECK(HasEvent(event_id));
  all_events_.erase(event_id);
  // Check |processing_events_| here because EndEvent() can be called
  // synchronously in StartEvent(). We don't want to trigger
  // OnNoInflightEvent() while ProcessEvents() is running.
  if (!processing_events_ && !HasInflightEvent())
    OnNoInflightEvent();
}

bool ServiceWorkerEventQueue::HasEvent(int event_id) const {
  return base::Contains(all_events_, event_id);
}

bool ServiceWorkerEventQueue::HasEventInQueue(int event_id) const {
  return (base::Contains(queued_online_events_, event_id) ||
          base::Contains(queued_offline_events_, event_id));
}

std::unique_ptr<ServiceWorkerEventQueue::StayAwakeToken>
ServiceWorkerEventQueue::CreateStayAwakeToken() {
  return std::make_unique<ServiceWorkerEventQueue::StayAwakeToken>(
      weak_factory_.GetWeakPtr());
}

void ServiceWorkerEventQueue::SetIdleDelay(base::TimeDelta idle_delay) {
  idle_delay_ = idle_delay;

  if (HasInflightEvent())
    return;

  if (did_idle_timeout()) {
    // The idle callback has already been called. It should not be called again
    // until this worker becomes active.
    return;
  }

  // There should be a scheduled idle callback because this is now in the idle
  // delay. The idle callback will be rescheduled based on the new idle delay.
  DCHECK(HasScheduledIdleCallback());
  idle_callback_handle_.Cancel();

  // Calculate the updated time of when the |idle_callback_| should be invoked.
  DCHECK(!last_no_inflight_event_time_.is_null());
  auto new_idle_callback_time = last_no_inflight_event_time_ + idle_delay;
  base::TimeDelta delta_until_idle =
      new_idle_callback_time - tick_clock_->NowTicks();

  if (delta_until_idle <= base::Seconds(0)) {
    // The new idle delay is shorter than the previous idle delay, and the idle
    // time has been already passed. Let's run the idle callback immediately.
    TriggerIdleCallback();
    return;
  }

  // Let's schedule the idle callback in |delta_until_idle|.
  ScheduleIdleCallback(delta_until_idle);
}

void ServiceWorkerEventQueue::CheckEventQueue() {
  if (!HasInflightEvent()) {
    OnNoInflightEvent();
  }
}

void ServiceWorkerEventQueue::UpdateStatus() {
  base::TimeTicks now = tick_clock_->NowTicks();

  // Construct a new map because WTF::HashMap doesn't support deleting elements
  // while iterating.
  HashMap<int /* event_id */, std::unique_ptr<EventInfo>> new_all_events;

  bool should_idle_delay_to_be_zero = false;

  // Time out all events exceeding `kEventTimeout`.
  for (auto& it : all_events_) {
    // Check if the event has timed out.
    int event_id = it.key;
    std::unique_ptr<EventInfo>& event_info = it.value;
    if (event_info->expiration_time > now) {
      new_all_events.insert(event_id, std::move(event_info));
      continue;
    }

    // The event may still be in one of the queues when it timed out. Try to
    // remove the event from both.
    queued_online_events_.erase(event_id);
    queued_offline_events_.erase(event_id);

    // Run the abort callback.
    std::move(event_info->abort_callback)
        .Run(blink::mojom::ServiceWorkerEventStatus::TIMEOUT);

    should_idle_delay_to_be_zero = true;
  }
  all_events_.swap(new_all_events);

  // Set idle delay to zero if needed.
  if (should_idle_delay_to_be_zero) {
    // Inflight events might be timed out and there might be no inflight event
    // at this point.
    if (!HasInflightEvent()) {
      OnNoInflightEvent();
    }
    // Shut down the worker as soon as possible since the worker may have gone
    // into bad state.
    SetIdleDelay(base::Seconds(0));
  }
}

void ServiceWorkerEventQueue::ScheduleIdleCallback(base::TimeDelta delay) {
  DCHECK(!HasInflightEvent());
  DCHECK(!HasScheduledIdleCallback());

  // WTF::Unretained() is safe because the task runner will be destroyed
  // before |this| is destroyed at ServiceWorkerGlobalScope::Dispose().
  idle_callback_handle_ = PostDelayedCancellableTask(
      *task_runner_, FROM_HERE,
      WTF::BindOnce(&ServiceWorkerEventQueue::TriggerIdleCallback,
                    WTF::Unretained(this)),
      delay);
}

void ServiceWorkerEventQueue::TriggerIdleCallback() {
  DCHECK(!HasInflightEvent());
  DCHECK(!HasScheduledIdleCallback());
  DCHECK(!did_idle_timeout_);

  did_idle_timeout_ = true;
  idle_callback_.Run();
}

void ServiceWorkerEventQueue::OnNoInflightEvent() {
  DCHECK(!HasInflightEvent());
  running_event_type_ = RunningEventType::kNone;
  // There might be events in the queue because offline (or non-offline) events
  // can be enqueued during running non-offline (or offline) events.
  auto& queue = GetActiveEventQueue();
  if (!queue.empty()) {
    ProcessEvents();
    return;
  }
  last_no_inflight_event_time_ = tick_clock_->NowTicks();
  ScheduleIdleCallback(idle_delay_);
}

bool ServiceWorkerEventQueue::HasInflightEvent() const {
  size_t num_queued_events =
      queued_online_events_.size() + queued_offline_events_.size();
  DCHECK_LE(num_queued_events, all_events_.size());
  return all_events_.size() - num_queued_events > 0 ||
         num_of_stay_awake_tokens_ > 0;
}

void ServiceWorkerEventQueue::ResetIdleTimeout() {
  last_no_inflight_event_time_ = base::TimeTicks();
  idle_callback_handle_.Cancel();
  did_idle_timeout_ = false;
}

bool ServiceWorkerEventQueue::HasScheduledIdleCallback() const {
  return idle_callback_handle_.IsActive();
}

int ServiceWorkerEventQueue::NextEventId() {
  CHECK_LT(next_event_id_, std::numeric_limits<int>::max());
  return next_event_id_++;
}

ServiceWorkerEventQueue::Event::Event(
    int event_id,
    ServiceWorkerEventQueue::Event::Type type,
    StartCallback start_callback,
    AbortCallback abort_callback,
    std::optional<base::TimeDelta> custom_timeout)
    : event_id(event_id),
      type(type),
      start_callback(std::move(start_callback)),
      abort_callback(std::move(abort_callback)),
      custom_timeout(custom_timeout) {}

ServiceWorkerEventQueue::Event::~Event() = default;

ServiceWorkerEventQueue::EventInfo::EventInfo(
    base::TimeTicks expiration_time,
    base::OnceCallback<void(blink::mojom::ServiceWorkerEventStatus)>
        abort_callback)
    : expiration_time(expiration_time),
      abort_callback(std::move(abort_callback)) {}

ServiceWorkerEventQueue::EventInfo::~EventInfo() = default;

}  // namespace blink

"""

```