Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of the `performance.cc` file in the Chromium Blink engine. I need to go through each method and understand its purpose, paying attention to how it interacts with web technologies like JavaScript, HTML, and CSS. I also need to identify potential user or programming errors and how a user's actions might lead to this code being executed.

Here's a breakdown of the methods and their functionalities:

- **`AddSoftNavigationPerformanceTimeline`**: Adds soft navigation performance entries.
- **`AddRenderCoarsenedEntry`**:  Schedules a callback to add a performance entry, potentially with a delay for time coarsening.
- **`SchedulePendingRenderCoarsenedEntries`**:  Posts a delayed task to flush pending entries.
- **`FlushPendingRenderCoarsenedEntries`**: Executes pending callbacks to add performance entries, handling potential delays for coarsening.
- **`AddFirstPaintTiming`, `AddFirstContentfulPaintTiming`, `AddPaintTiming`**: Record paint timing metrics.
- **`CanAddResourceTimingEntry`**: Checks if more resource timing entries can be added.
- **`AddLongTaskTiming`**: Records long task timing information.
- **`AddBackForwardCacheRestoration`**: Records back/forward cache restoration timing.
- **`GetUserTiming`**: Returns the `UserTiming` object.
- **`mark`**: Creates a performance mark.
- **`ProcessUserFeatureMark`**: Processes user-defined feature marks.
- **`clearMarks`**: Clears performance marks.
- **`measure` (multiple overloads)**: Creates performance measures.
- **`MeasureInternal`**: Internal function to handle different `measure` overloads.
- **`MeasureWithDetail`**: Creates a performance measure with detailed information.
- **`clearMeasures`**: Clears performance measures.
- **`RegisterPerformanceObserver`, `UnregisterPerformanceObserver`, `UpdatePerformanceObserverFilterOptions`**: Manage performance observers.
- **`NotifyObserversOfEntry`**: Notifies registered observers of a new performance entry.
- **`HasObserverFor`**: Checks if there's an observer for a specific entry type.
- **`ActivateObserver`, `SuspendObserver`**: Control the active state of performance observers.
- **`DeliverObservationsTimerFired`**:  Handles the timer for delivering observations to active observers.
- **`GetDroppedEntriesForTypes`**: Returns the count of dropped entries for specific types.
- **`ClampTimeResolution`**:  Limits the precision of time measurements.
- **`MonotonicTimeToDOMHighResTimeStamp` (static and member)**: Converts monotonic time to DOMHighResTimeStamp.
- **`RenderTimeToDOMHighResTimeStamp`**: Converts render time to DOMHighResTimeStamp.
- **`now`**: Returns the current DOMHighResTimeStamp.
- **`CanExposeNode`**: Checks if a given DOM node can be exposed in performance entries.
- **`toJSONForBinding`, `BuildJSONValue`**:  Methods for converting the `Performance` object to JSON.
- **`InsertEntryIntoSortedBuffer`**: Inserts a performance entry into a sorted buffer.
- **`Trace`**:  Method for tracing object dependencies for garbage collection.
- **`UserEntryPoint` (nested class)**:  Helper class for implementing `bind`.
- **`bind`**:  Allows binding `this` and arguments to a function.
- **`SetClocksForTesting`, `ResetTimeOriginForTesting`**: Methods for setting up test environments.
- **`softNavPaintMetricsSupported`**:  Indicates support for soft navigation paint metrics.

Based on this analysis, I can formulate the summary.
这是`blink/renderer/core/timing/performance.cc`文件的第二部分，它主要负责以下功能，延续了第一部分对于性能监控和测量的实现：

**核心功能归纳:**

1. **软导航性能条目的管理:**
   - `AddSoftNavigationPerformanceTimeline`:  接收并存储软导航（Soft Navigation）事件的性能条目。如果缓冲区未满，则插入并排序，否则增加丢弃计数。
   - **与 JavaScript/HTML/CSS 的关系:** 当用户进行软导航时（例如，单页应用内部的路由切换，不触发完整的页面重载），会生成 `SoftNavigationEntry`，这个方法负责记录这些性能数据，以便开发者通过 Performance API 获取。

2. **渲染时间精度控制和管理:**
   - `AddRenderCoarsenedEntry`:  添加一个渲染相关的性能条目，并考虑了时间精度调整（coarsening）。它会延迟执行回调，以实现粗粒度的渲染时间报告，这通常用于跨域隔离的场景，以减少信息泄露。
   - `SchedulePendingRenderCoarsenedEntries`:  安排一个定时任务来刷新待处理的、需要进行时间精度调整的性能条目。
   - `FlushPendingRenderCoarsenedEntries`:  实际执行待处理的性能条目添加操作，并根据目标时间进行排序和处理。如果目标时间晚于当前时间，则会重新安排到下一个时机执行。
   - **与 JavaScript/HTML/CSS 的关系:** 渲染时间与页面的绘制过程紧密相关。例如，当浏览器渲染 HTML 和 CSS 样式后进行首次绘制（First Paint, FP）或首次内容绘制（First Contentful Paint, FCP）时，会调用这些方法来记录时间。跨域隔离的网页可能会使用时间精度调整来限制可观察的渲染时间精度。
   - **假设输入与输出:** 假设 `earliest_timestamp_for_timeline` 为 `100ms`，`time_origin_` 为 `t0`，`target_time` 将是 `t0 + 100ms`。如果当前时间早于 `target_time`，回调将被延迟执行。

3. **Paint Timing 记录:**
   - `AddFirstPaintTiming`, `AddFirstContentfulPaintTiming`, `AddPaintTiming`:  记录首次渲染时间和首次内容渲染时间等关键的绘制时刻。这些方法会创建 `PerformancePaintTiming` 类型的性能条目，并添加到相应的缓冲区。
   - **与 JavaScript/HTML/CSS 的关系:** 这些方法对应了网页加载和渲染过程中重要的时间节点，可以通过 Performance API 中的 `paint` 条目获取。浏览器会在完成首次绘制或首次内容绘制后调用这些方法。
   - **假设输入与输出:** 假设 `start_time` 是某个 `base::TimeTicks` 值，例如表示页面开始加载后 50ms 的时刻。这些方法会将其转换为 `DOMHighResTimeStamp` 并创建一个 `PerformancePaintTiming` 对象。

4. **长任务 (Long Task) 记录:**
   - `AddLongTaskTiming`: 记录执行时间超过一定阈值的 JavaScript 任务。它会创建 `PerformanceLongTaskTiming` 类型的性能条目。
   - **与 JavaScript 的关系:** 当一段 JavaScript 代码执行时间过长，阻塞了主线程时，会触发此方法记录。开发者可以通过 Performance API 中的 `longtask` 条目来监控。
   - **假设输入与输出:** 假设 `start_time` 是长任务开始的 `base::TimeTicks`，`end_time` 是结束的 `base::TimeTicks`，`name` 是任务的描述。该方法会创建一个包含这些信息的 `PerformanceLongTaskTiming` 对象。

5. **后退/前进缓存 (Back/Forward Cache) 恢复记录:**
   - `AddBackForwardCacheRestoration`: 记录从后退/前进缓存恢复页面时的相关时间。
   - **与 JavaScript/HTML/CSS 的关系:** 当用户通过浏览器的后退或前进按钮导航时，如果页面可以从缓存中恢复，则会调用此方法记录恢复过程的时间。这有助于评估缓存的性能。

6. **用户自定义 Timing (User Timing) 的管理:**
   - `GetUserTiming`: 获取用于管理用户自定义性能标记和测量的 `UserTiming` 对象。
   - `mark`：创建用户自定义的性能标记（mark）。开发者可以使用 `performance.mark()` 在代码中插入标记点。
   - `ProcessUserFeatureMark`: 处理特定的用户自定义标记，例如用于统计功能使用情况。
   - `clearMarks`: 清除用户自定义的性能标记。
   - `measure` (多个重载): 创建用户自定义的性能测量（measure），计算两个标记点之间的时间差。开发者可以使用 `performance.measure()` 来测量代码段的执行时间。
   - `MeasureInternal`, `MeasureWithDetail`: 内部方法，用于处理 `measure` 方法的不同参数形式。
   - `clearMeasures`: 清除用户自定义的性能测量。
   - **与 JavaScript 的关系:** 这些方法直接对应了 Web Performance API 中的 `performance.mark()` 和 `performance.measure()` 方法，允许开发者在 JavaScript 代码中自定义性能监控点。
   - **用户常见使用错误:**  调用 `performance.measure()` 时，提供的起始标记或结束标记不存在会导致错误。例如，`performance.measure('myMeasure', 'startMark', 'endMark')`，如果 'startMark' 或 'endMark' 没有被 `performance.mark()` 创建，就会出错。

7. **性能观察者 (Performance Observer) 的管理:**
   - `RegisterPerformanceObserver`, `UnregisterPerformanceObserver`, `UpdatePerformanceObserverFilterOptions`: 管理注册的性能观察者对象。性能观察者可以监听特定类型的性能条目被添加到性能时间线。
   - `NotifyObserversOfEntry`: 当新的性能条目被添加时，通知所有相关的性能观察者。
   - `HasObserverFor`: 检查是否存在监听特定性能条目类型的观察者。
   - `ActivateObserver`, `SuspendObserver`: 控制性能观察者的激活状态。
   - `DeliverObservationsTimerFired`:  触发定时器，向激活的性能观察者交付其监听到的性能条目。
   - `GetDroppedEntriesForTypes`: 获取特定类型性能条目的丢弃数量。
   - **与 JavaScript 的关系:** 这些方法实现了 Web Performance API 中的 `PerformanceObserver` 接口，允许 JavaScript 代码注册回调函数来异步接收性能事件。

8. **时间精度控制和转换:**
   - `ClampTimeResolution`: 限制时间测量的精度，用于安全和隐私考虑。
   - `MonotonicTimeToDOMHighResTimeStamp` (静态和成员方法): 将单调时钟时间转换为 `DOMHighResTimeStamp`，这是 Performance API 中使用的时间戳格式。
   - `RenderTimeToDOMHighResTimeStamp`: 将渲染相关的时间转换为 `DOMHighResTimeStamp`，并可能应用精度调整。
   - `now`: 返回当前的 `DOMHighResTimeStamp`。
   - **与 JavaScript 的关系:**  `performance.now()` 返回的就是 `DOMHighResTimeStamp`，这些方法负责将底层的计时器转换为这种格式。

9. **其他辅助功能:**
   - `CanAddResourceTimingEntry`: 检查是否可以添加新的资源加载性能条目。
   - `CanExposeNode`: 检查一个 DOM 节点是否可以暴露在性能条目中（例如，Largest Contentful Paint）。
   - `toJSONForBinding`, `BuildJSONValue`:  将 `Performance` 对象转换为 JSON 格式，用于 JavaScript 绑定。
   - `InsertEntryIntoSortedBuffer`: 将性能条目插入到已排序的缓冲区中，保持时间顺序。
   - `Trace`: 用于垃圾回收的追踪方法。
   - `bind`:  用于将函数绑定到特定的 `this` 值和参数，可能用于事件处理等场景。
   - `SetClocksForTesting`, `ResetTimeOriginForTesting`:  用于测试目的，可以设置自定义的时钟和时间原点。
   - `softNavPaintMetricsSupported`:  指示是否支持软导航的 paint 指标。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **页面加载和渲染:** 用户在浏览器中输入网址或点击链接，浏览器开始加载 HTML、CSS 和 JavaScript 资源。
2. **解析 HTML 和 CSS:** 浏览器解析 HTML 结构和 CSS 样式。
3. **JavaScript 执行:** 浏览器执行 JavaScript 代码。
4. **触发性能事件:**
   - **首次绘制/首次内容绘制:** 当浏览器完成初步渲染时，会调用 `AddFirstPaintTiming` 和 `AddFirstContentfulPaintTiming`。
   - **资源加载:** 加载图片、脚本、样式表等资源时，相关的 Resource Timing 条目可能被添加到缓冲区，`CanAddResourceTimingEntry` 会被检查。
   - **长任务执行:**  执行耗时的 JavaScript 代码段时，会调用 `AddLongTaskTiming`。
   - **用户自定义标记和测量:** JavaScript 代码调用 `performance.mark()` 和 `performance.measure()` 时，会触发 `mark` 和 `measure` 相关的方法。
   - **软导航:** 在支持软导航的单页应用中，用户进行内部导航时，会调用 `AddSoftNavigationPerformanceTimeline`。
   - **后退/前进:** 用户点击浏览器的后退或前进按钮时，可能会调用 `AddBackForwardCacheRestoration`。
   - **注册性能观察者:** JavaScript 代码调用 `performance.observe()` 注册性能观察者后，当相应的性能事件发生时，`NotifyObserversOfEntry` 会被调用。
5. **性能 API 查询:** 开发者可能在控制台或代码中使用 `performance.getEntriesByType()` 等方法来获取这些性能数据。

**用户或编程常见的使用错误举例:**

1. **`performance.measure()` 使用错误:**
   ```javascript
   performance.mark('start');
   // ... 一些代码 ...
   // 错误：忘记创建 end 标记
   performance.measure('myMeasure', 'start', 'end'); // 'end' 标记不存在
   ```
   **输出/结果:**  `performance.measure` 会抛出一个错误，指示无法找到名为 'end' 的标记。

2. **缓冲区溢出导致性能条目丢失:** 如果性能事件发生过于频繁，超过了缓冲区的容量限制 (如 `kDefaultSoftNavigationBufferSize`, `kDefaultPaintEntriesBufferSize`, `kDefaultLongTaskBufferSize`)，新的条目可能无法被记录，并且 `dropped_entries_count_map_` 中的计数器会被增加。开发者可以通过 Performance Observer 的 `droppedEntries` 选项来获取丢失的条目数量。

3. **在跨域隔离环境中使用未调整精度的 API:**  在启用了跨域隔离的页面中，如果尝试获取高精度的时间戳，可能会因为精度调整而被限制，返回粗粒度的值。

**总结该部分的功能:**

这是 `blink/renderer/core/timing/performance.cc` 文件的后半部分，它主要负责以下方面的性能监控和管理：

- **软导航性能条目的记录和管理。**
- **渲染时间的精度控制和延迟添加机制。**
- **关键渲染时刻 (Paint Timing) 的记录。**
- **长时间运行 JavaScript 任务 (Long Task) 的记录。**
- **后退/前进缓存恢复过程的性能记录。**
- **用户自定义性能标记和测量的创建、管理和清除。**
- **性能观察者的注册、激活、暂停和通知机制。**
- **将单调时钟时间转换为 Performance API 使用的 `DOMHighResTimeStamp`，并进行精度调整。**
- **提供辅助方法用于检查资源条目添加、节点可暴露性以及对象到 JSON 的转换。**

这部分代码与 Web Performance API 紧密相关，为浏览器提供了底层机制来收集和报告各种性能指标，帮助开发者分析和优化网页的性能。

Prompt: 
```
这是目录为blink/renderer/core/timing/performance.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
formanceTimeline(
    SoftNavigationEntry* entry) {
  probe::PerformanceEntryAdded(GetExecutionContext(), entry);
  if (soft_navigation_buffer_.size() < kDefaultSoftNavigationBufferSize) {
    InsertEntryIntoSortedBuffer(soft_navigation_buffer_, *entry, kRecordSwaps);
  } else {
    ++(dropped_entries_count_map_.find(PerformanceEntry::kSoftNavigation)
           ->value);
  }
}

void Performance::AddRenderCoarsenedEntry(
    base::OnceCallback<void(Performance&)> callback,
    DOMHighResTimeStamp earliest_timestamp_for_timeline) {
  if (!RuntimeEnabledFeatures::ExposeCoarsenedRenderTimeEnabled() ||
      time_origin_.is_null() || cross_origin_isolated_capability_) {
    std::move(callback).Run(*this);
    return;
  }

  base::TimeTicks target_time =
      time_origin_ + base::Milliseconds(earliest_timestamp_for_timeline);
  if (pending_entry_operations_with_render_coarsening_.empty()) {
    SchedulePendingRenderCoarsenedEntries(target_time);
  }

  pending_entry_operations_with_render_coarsening_.push_back(
      std::make_pair(std::move(callback), target_time));
}

void Performance::SchedulePendingRenderCoarsenedEntries(
    base::TimeTicks target_time) {
  task_runner_->PostDelayedTask(
      FROM_HERE,
      WTF::BindOnce(
          [](WeakPersistent<Performance> self) {
            if (self) {
              self->FlushPendingRenderCoarsenedEntries();
            }
          },
          WrapWeakPersistent(this)),
      target_time - base::TimeTicks::Now());
}

void Performance::FlushPendingRenderCoarsenedEntries() {
  base::TimeTicks now = base::TimeTicks::Now();

  Vector<std::pair<base::OnceCallback<void(Performance&)>, base::TimeTicks>>
      pending_entries;
  std::swap(pending_entry_operations_with_render_coarsening_, pending_entries);
  base::TimeTicks next_tick;
  for (auto& [callback, target_time] : pending_entries) {
    // We could have had a few entries batched and this one is coarsened to the
    // future. Fire it in the next batch.
    if (target_time > now) {
      pending_entry_operations_with_render_coarsening_.push_back(
          std::make_pair(std::move(callback), target_time));
      next_tick =
          next_tick.is_null() ? target_time : std::min(next_tick, target_time);
    } else {
      std::move(callback).Run(*this);
    }
  }

  if (!next_tick.is_null()) {
    SchedulePendingRenderCoarsenedEntries(next_tick);
  }
}

void Performance::AddFirstPaintTiming(base::TimeTicks start_time,
                                      bool is_triggered_by_soft_navigation) {
  AddPaintTiming(PerformancePaintTiming::PaintType::kFirstPaint, start_time,
                 is_triggered_by_soft_navigation);
}

void Performance::AddFirstContentfulPaintTiming(
    base::TimeTicks start_time,
    bool is_triggered_by_soft_navigation) {
  AddPaintTiming(PerformancePaintTiming::PaintType::kFirstContentfulPaint,
                 start_time, is_triggered_by_soft_navigation);
}

void Performance::AddPaintTiming(PerformancePaintTiming::PaintType type,
                                 base::TimeTicks start_time,
                                 bool is_triggered_by_soft_navigation) {
  PerformanceEntry* entry = MakeGarbageCollected<PerformancePaintTiming>(
      type, RenderTimeToDOMHighResTimeStamp(start_time),
      DynamicTo<LocalDOMWindow>(GetExecutionContext()),
      is_triggered_by_soft_navigation);
  DCHECK((type == PerformancePaintTiming::PaintType::kFirstPaint) ||
         (type == PerformancePaintTiming::PaintType::kFirstContentfulPaint));

  AddRenderCoarsenedEntry(
      WTF::BindOnce(
          [](Persistent<PerformanceEntry> entry, Performance& performance) {
            if (performance.paint_entries_timing_.size() <
                kDefaultPaintEntriesBufferSize) {
              performance.InsertEntryIntoSortedBuffer(
                  performance.paint_entries_timing_, *entry, kRecordSwaps);
            } else {
              ++(performance.dropped_entries_count_map_
                     .find(PerformanceEntry::kPaint)
                     ->value);
            }
            performance.NotifyObserversOfEntry(*entry);
          },
          WrapPersistent(entry)),
      entry->startTime());
}
bool Performance::CanAddResourceTimingEntry() {
  // https://w3c.github.io/resource-timing/#dfn-can-add-resource-timing-entry
  return resource_timing_buffer_.size() < resource_timing_buffer_size_limit_;
}

void Performance::AddLongTaskTiming(base::TimeTicks start_time,
                                    base::TimeTicks end_time,
                                    const AtomicString& name,
                                    const AtomicString& container_type,
                                    const AtomicString& container_src,
                                    const AtomicString& container_id,
                                    const AtomicString& container_name) {
  double dom_high_res_start_time =
      MonotonicTimeToDOMHighResTimeStamp(start_time);

  ExecutionContext* execution_context = GetExecutionContext();
  auto* entry = MakeGarbageCollected<PerformanceLongTaskTiming>(
      dom_high_res_start_time,
      // Convert the delta between start and end times to an int to reduce the
      // granularity of the duration to 1 ms.
      static_cast<int>(MonotonicTimeToDOMHighResTimeStamp(end_time) -
                       dom_high_res_start_time),
      name, container_type, container_src, container_id, container_name,
      DynamicTo<LocalDOMWindow>(execution_context));
  if (longtask_buffer_.size() < kDefaultLongTaskBufferSize) {
    InsertEntryIntoSortedBuffer(longtask_buffer_, *entry, kRecordSwaps);
  } else {
    ++(dropped_entries_count_map_.find(PerformanceEntry::kLongTask)->value);
    UseCounter::Count(execution_context, WebFeature::kLongTaskBufferFull);
  }
  if ((++long_task_counter_ % kLongTaskUkmSampleInterval) == 0) {
    RecordLongTaskUkm(execution_context,
                      base::Milliseconds(dom_high_res_start_time),
                      end_time - start_time);
  }
  NotifyObserversOfEntry(*entry);
}

void Performance::AddBackForwardCacheRestoration(
    base::TimeTicks start_time,
    base::TimeTicks pageshow_start_time,
    base::TimeTicks pageshow_end_time) {
  auto* entry = MakeGarbageCollected<BackForwardCacheRestoration>(
      MonotonicTimeToDOMHighResTimeStamp(start_time),
      MonotonicTimeToDOMHighResTimeStamp(pageshow_start_time),
      MonotonicTimeToDOMHighResTimeStamp(pageshow_end_time),
      DynamicTo<LocalDOMWindow>(GetExecutionContext()));
  if (back_forward_cache_restoration_buffer_.size() <
      back_forward_cache_restoration_buffer_size_limit_) {
    InsertEntryIntoSortedBuffer(back_forward_cache_restoration_buffer_, *entry,
                                kRecordSwaps);
  } else {
    ++(dropped_entries_count_map_
           .find(PerformanceEntry::kBackForwardCacheRestoration)
           ->value);
  }
  NotifyObserversOfEntry(*entry);
}

UserTiming& Performance::GetUserTiming() {
  if (!user_timing_)
    user_timing_ = MakeGarbageCollected<UserTiming>(*this);
  return *user_timing_;
}

PerformanceMark* Performance::mark(ScriptState* script_state,
                                   const AtomicString& mark_name,
                                   PerformanceMarkOptions* mark_options,
                                   ExceptionState& exception_state) {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(const AtomicString, mark_fully_loaded,
                                  ("mark_fully_loaded"));
  DEFINE_THREAD_SAFE_STATIC_LOCAL(const AtomicString, mark_fully_visible,
                                  ("mark_fully_visible"));
  DEFINE_THREAD_SAFE_STATIC_LOCAL(const AtomicString, mark_interactive,
                                  ("mark_interactive"));
  DEFINE_THREAD_SAFE_STATIC_LOCAL(const AtomicString, mark_feature_usage,
                                  ("mark_feature_usage"));
  bool has_start_time = mark_options && mark_options->hasStartTime();
  if (has_start_time || (mark_options && mark_options->hasDetail())) {
    UseCounter::Count(GetExecutionContext(), WebFeature::kUserTimingL3);
  }
  PerformanceMark* performance_mark = PerformanceMark::Create(
      script_state, mark_name, mark_options, exception_state);
  if (performance_mark) {
    background_tracing_helper_->MaybeEmitBackgroundTracingPerformanceMarkEvent(
        *performance_mark);
    GetUserTiming().AddMarkToPerformanceTimeline(*performance_mark,
                                                 mark_options);
    if (mark_name == mark_fully_loaded) {
      if (LocalDOMWindow* window = LocalDOMWindow::From(script_state)) {
        window->GetFrame()
            ->Loader()
            .GetDocumentLoader()
            ->GetTiming()
            .SetUserTimingMarkFullyLoaded(
                base::Milliseconds(performance_mark->startTime()));
      }
    } else if (mark_name == mark_fully_visible) {
      if (LocalDOMWindow* window = LocalDOMWindow::From(script_state)) {
        window->GetFrame()
            ->Loader()
            .GetDocumentLoader()
            ->GetTiming()
            .SetUserTimingMarkFullyVisible(
                base::Milliseconds(performance_mark->startTime()));
      }
    } else if (mark_name == mark_interactive) {
      if (LocalDOMWindow* window = LocalDOMWindow::From(script_state)) {
        window->GetFrame()
            ->Loader()
            .GetDocumentLoader()
            ->GetTiming()
            .SetUserTimingMarkInteractive(
                base::Milliseconds(performance_mark->startTime()));
      }
    } else if (mark_name == mark_feature_usage && mark_options->hasDetail()) {
      if (RuntimeEnabledFeatures::PerformanceMarkFeatureUsageEnabled()) {
        ProcessUserFeatureMark(mark_options);
      }
    } else {
      if (LocalDOMWindow* window = LocalDOMWindow::From(script_state)) {
        if (window->GetFrame() && window->GetFrame()->IsOutermostMainFrame()) {
          window->GetFrame()
              ->Loader()
              .GetDocumentLoader()
              ->GetTiming()
              .NotifyCustomUserTimingMarkAdded(
                  mark_name, base::Milliseconds(performance_mark->startTime()));
        }
      }
    }
    NotifyObserversOfEntry(*performance_mark);
  }
  return performance_mark;
}

void Performance::ProcessUserFeatureMark(
    const PerformanceMarkOptions* mark_options) {
  const ExecutionContext* exec_context = GetExecutionContext();
  if (!exec_context) {
    return;
  }

  const ScriptValue& detail = mark_options->detail();
  if (!detail.IsObject()) {
    return;
  }

  v8::Isolate* isolate = GetExecutionContext()->GetIsolate();
  v8::Local<v8::Context> current_context = isolate->GetCurrentContext();
  v8::Local<v8::Object> object;
  if (!detail.V8Value()->ToObject(current_context).ToLocal(&object)) {
    return;
  }

  v8::Local<v8::Value> user_feature_name_val;
  if (!object->Get(current_context, V8AtomicString(isolate, "feature"))
           .ToLocal(&user_feature_name_val) ||
      user_feature_name_val->IsUndefined()) {
    return;
  }

  v8::Local<v8::String> user_feature_name;
  if (!user_feature_name_val->ToString(current_context)
           .ToLocal(&user_feature_name)) {
    return;
  }

  String blink_user_feature_name =
      ToBlinkString<String>(isolate, user_feature_name, kDoNotExternalize);

  // Check if the user feature name is mapped to an allowed WebFeature.
  auto maybe_web_feature =
      PerformanceMark::GetWebFeatureForUserFeatureName(blink_user_feature_name);
  if (!maybe_web_feature.has_value()) {
    // We have no matching WebFeature translation yet, skip.
    return;
  }

  // Tick the corresponding use counter.
  UseCounter::Count(GetExecutionContext(), maybe_web_feature.value());
}

void Performance::clearMarks(const AtomicString& mark_name) {
  GetUserTiming().ClearMarks(mark_name);
}

PerformanceMeasure* Performance::measure(ScriptState* script_state,
                                         const AtomicString& measure_name,
                                         ExceptionState& exception_state) {
  // When |startOrOptions| is not provided, it's assumed to be an empty
  // dictionary.
  return MeasureInternal(script_state, measure_name, nullptr, std::nullopt,
                         exception_state);
}

PerformanceMeasure* Performance::measure(
    ScriptState* script_state,
    const AtomicString& measure_name,
    const V8UnionPerformanceMeasureOptionsOrString* start_or_options,
    ExceptionState& exception_state) {
  return MeasureInternal(script_state, measure_name, start_or_options,
                         std::nullopt, exception_state);
}

PerformanceMeasure* Performance::measure(
    ScriptState* script_state,
    const AtomicString& measure_name,
    const V8UnionPerformanceMeasureOptionsOrString* start_or_options,
    const String& end,
    ExceptionState& exception_state) {
  return MeasureInternal(script_state, measure_name, start_or_options,
                         std::optional<String>(end), exception_state);
}

// |MeasureInternal| exists to unify the arguments from different
// `performance.measure()` overloads into a consistent form, then delegate to
// |MeasureWithDetail|.
//
// |start_or_options| is either a String or a dictionary of options. When it's
// a String, it represents a starting performance mark. When it's a dictionary,
// the allowed fields are 'start', 'duration', 'end' and 'detail'. However,
// there are some combinations of fields and parameters which must raise
// errors. Specifically, the spec (https://https://w3c.github.io/user-timing/)
// requires errors to thrown in the following cases:
//  - If |start_or_options| is a dictionary and 'end_mark' is passed.
//  - If an options dictionary contains neither a 'start' nor an 'end' field.
//  - If an options dictionary contains all of 'start', 'duration' and 'end'.
//
// |end_mark| will be std::nullopt unless the `performance.measure()` overload
// specified an end mark.
PerformanceMeasure* Performance::MeasureInternal(
    ScriptState* script_state,
    const AtomicString& measure_name,
    const V8UnionPerformanceMeasureOptionsOrString* start_or_options,
    std::optional<String> end_mark,
    ExceptionState& exception_state) {
  // An empty option is treated with no difference as null, undefined.
  if (start_or_options && start_or_options->IsPerformanceMeasureOptions() &&
      !IsMeasureOptionsEmpty(
          *start_or_options->GetAsPerformanceMeasureOptions())) {
    UseCounter::Count(GetExecutionContext(), WebFeature::kUserTimingL3);
    // measure("name", { start, end }, *)
    if (end_mark) {
      exception_state.ThrowTypeError(
          "If a non-empty PerformanceMeasureOptions object was passed, "
          "|end_mark| must not be passed.");
      return nullptr;
    }
    const PerformanceMeasureOptions* options =
        start_or_options->GetAsPerformanceMeasureOptions();
    if (!options->hasStart() && !options->hasEnd()) {
      exception_state.ThrowTypeError(
          "If a non-empty PerformanceMeasureOptions object was passed, at "
          "least one of its 'start' or 'end' properties must be present.");
      return nullptr;
    }

    if (options->hasStart() && options->hasDuration() && options->hasEnd()) {
      exception_state.ThrowTypeError(
          "If a non-empty PerformanceMeasureOptions object was passed, it "
          "must not have all of its 'start', 'duration', and 'end' "
          "properties defined");
      return nullptr;
    }

    V8UnionDoubleOrString* start = options->getStartOr(nullptr);
    std::optional<double> duration;
    if (options->hasDuration()) {
      duration = options->duration();
    }
    V8UnionDoubleOrString* end = options->getEndOr(nullptr);

    return MeasureWithDetail(
        script_state, measure_name, start, duration, end,
        options->hasDetail() ? options->detail() : ScriptValue(),
        exception_state);
  }

  // measure("name", "mark1", *)
  V8UnionDoubleOrString* start = nullptr;
  if (start_or_options && start_or_options->IsString()) {
    start = MakeGarbageCollected<V8UnionDoubleOrString>(
        start_or_options->GetAsString());
  }
  // We let |end_mark| behave the same whether it's empty, undefined or null
  // in JS, as long as |end_mark| is null in C++.
  V8UnionDoubleOrString* end = nullptr;
  if (end_mark) {
    end = MakeGarbageCollected<V8UnionDoubleOrString>(*end_mark);
  }
  return MeasureWithDetail(script_state, measure_name, start,
                           /* duration = */ std::nullopt, end, ScriptValue(),
                           exception_state);
}

PerformanceMeasure* Performance::MeasureWithDetail(
    ScriptState* script_state,
    const AtomicString& measure_name,
    const V8UnionDoubleOrString* start,
    const std::optional<double>& duration,
    const V8UnionDoubleOrString* end,
    const ScriptValue& detail,
    ExceptionState& exception_state) {
  PerformanceMeasure* performance_measure = GetUserTiming().Measure(
      script_state, measure_name, start, duration, end, detail, exception_state,
      LocalDOMWindow::From(script_state));
  if (performance_measure)
    NotifyObserversOfEntry(*performance_measure);
  return performance_measure;
}

void Performance::clearMeasures(const AtomicString& measure_name) {
  GetUserTiming().ClearMeasures(measure_name);
}

void Performance::RegisterPerformanceObserver(PerformanceObserver& observer) {
  observer_filter_options_ |= observer.FilterOptions();
  observers_.insert(&observer);
}

void Performance::UnregisterPerformanceObserver(
    PerformanceObserver& old_observer) {
  observers_.erase(&old_observer);
  UpdatePerformanceObserverFilterOptions();
}

void Performance::UpdatePerformanceObserverFilterOptions() {
  observer_filter_options_ = PerformanceEntry::kInvalid;
  for (const auto& observer : observers_) {
    observer_filter_options_ |= observer->FilterOptions();
  }
}

void Performance::NotifyObserversOfEntry(PerformanceEntry& entry) const {
  bool observer_found = false;
  for (auto& observer : observers_) {
    if (observer->FilterOptions() & entry.EntryTypeEnum() &&
        (!entry.IsTriggeredBySoftNavigation() ||
         observer->IncludeSoftNavigationObservations()) &&
        observer->CanObserve(entry)) {
      observer->EnqueuePerformanceEntry(entry);
      observer_found = true;
    }
  }
  if (observer_found && entry.EntryTypeEnum() == PerformanceEntry::kPaint)
    UseCounter::Count(GetExecutionContext(), WebFeature::kPaintTimingObserved);
}

bool Performance::HasObserverFor(
    PerformanceEntry::EntryType filter_type) const {
  return observer_filter_options_ & filter_type;
}

void Performance::ActivateObserver(PerformanceObserver& observer) {
  if (active_observers_.empty())
    deliver_observations_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);

  if (suspended_observers_.Contains(&observer))
    suspended_observers_.erase(&observer);
  active_observers_.insert(&observer);
}

void Performance::SuspendObserver(PerformanceObserver& observer) {
  DCHECK(!suspended_observers_.Contains(&observer));
  if (!active_observers_.Contains(&observer))
    return;
  active_observers_.erase(&observer);
  suspended_observers_.insert(&observer);
}

void Performance::DeliverObservationsTimerFired(TimerBase*) {
  decltype(active_observers_) observers;
  active_observers_.Swap(observers);
  for (const auto& observer : observers) {
    observer->Deliver(observer->RequiresDroppedEntries()
                          ? std::optional<int>(GetDroppedEntriesForTypes(
                                observer->FilterOptions()))
                          : std::nullopt);
  }
}

int Performance::GetDroppedEntriesForTypes(PerformanceEntryTypeMask types) {
  int dropped_count = 0;
  for (const auto type : kDroppableEntryTypes) {
    if (types & type)
      dropped_count += dropped_entries_count_map_.at(type);
  }
  return dropped_count;
}

// static
DOMHighResTimeStamp Performance::ClampTimeResolution(
    base::TimeDelta time,
    bool cross_origin_isolated_capability) {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(TimeClamper, clamper, ());
  return clamper.ClampTimeResolution(time, cross_origin_isolated_capability)
      .InMillisecondsF();
}

// static
DOMHighResTimeStamp Performance::MonotonicTimeToDOMHighResTimeStamp(
    base::TimeTicks time_origin,
    base::TimeTicks monotonic_time,
    bool allow_negative_value,
    bool cross_origin_isolated_capability) {
  // Avoid exposing raw platform timestamps.
  if (monotonic_time.is_null() || time_origin.is_null())
    return 0.0;

  DOMHighResTimeStamp clamped_time =
      ClampTimeResolution(monotonic_time.since_origin(),
                          cross_origin_isolated_capability) -
      ClampTimeResolution(time_origin.since_origin(),
                          cross_origin_isolated_capability);
  if (clamped_time < 0 && !allow_negative_value)
    return 0.0;
  return clamped_time;
}

DOMHighResTimeStamp Performance::MonotonicTimeToDOMHighResTimeStamp(
    base::TimeTicks monotonic_time) const {
  return MonotonicTimeToDOMHighResTimeStamp(time_origin_, monotonic_time,
                                            false /* allow_negative_value */,
                                            cross_origin_isolated_capability_);
}

DOMHighResTimeStamp Performance::RenderTimeToDOMHighResTimeStamp(
    base::TimeTicks monotonic_time) const {
  if (monotonic_time.is_null() || time_origin_.is_null()) {
    return 0;
  }

  if (RuntimeEnabledFeatures::ExposeCoarsenedRenderTimeEnabled() &&
      !cross_origin_isolated_capability_) {
    return (monotonic_time - time_origin_)
        .CeilToMultiple(kExtraCoarseResolution)
        .InMillisecondsF();
  } else {
    return MonotonicTimeToDOMHighResTimeStamp(monotonic_time);
  }
}

DOMHighResTimeStamp Performance::now() const {
  return MonotonicTimeToDOMHighResTimeStamp(tick_clock_->NowTicks());
}

// static
bool Performance::CanExposeNode(Node* node) {
  if (!node || !node->isConnected() || node->IsInShadowTree())
    return false;

  // Do not expose |node| when the document is not 'fully active'.
  const Document& document = node->GetDocument();
  if (!document.IsActive() || !document.GetFrame())
    return false;

  return true;
}

ScriptValue Performance::toJSONForBinding(ScriptState* script_state) const {
  V8ObjectBuilder result(script_state);
  BuildJSONValue(result);
  return result.GetScriptValue();
}

void Performance::BuildJSONValue(V8ObjectBuilder& builder) const {
  builder.AddNumber("timeOrigin", timeOrigin());
  // |memory| is not part of the spec, omitted.
}

// Insert entry in PerformanceEntryVector while maintaining sorted order (via
// Bubble Sort). We assume that the order of insertion roughly corresponds to
// the order of the StartTime, hence the sort beginning from the tail-end.
void Performance::InsertEntryIntoSortedBuffer(PerformanceEntryVector& entries,
                                              PerformanceEntry& entry,
                                              Metrics record) {
  entries.push_back(&entry);

  int number_of_swaps = 0;

  if (entries.size() > 1) {
    // Bubble Sort from tail.
    int left = entries.size() - 2;
    while (left >= 0 &&
           entries[left]->startTime() > entries[left + 1]->startTime()) {
      if (record == kRecordSwaps) {
        UseCounter::Count(GetExecutionContext(),
                          WebFeature::kPerformanceEntryBufferSwaps);
      }
      number_of_swaps++;
      SwapEntries(entries, left, left + 1);
      left--;
    }
  }

  UMA_HISTOGRAM_COUNTS_1000(kSwapsPerInsertionHistogram, number_of_swaps);

  return;
}

void Performance::Trace(Visitor* visitor) const {
  visitor->Trace(resource_timing_buffer_);
  visitor->Trace(resource_timing_secondary_buffer_);
  visitor->Trace(element_timing_buffer_);
  visitor->Trace(event_timing_buffer_);
  visitor->Trace(layout_shift_buffer_);
  visitor->Trace(largest_contentful_paint_buffer_);
  visitor->Trace(longtask_buffer_);
  visitor->Trace(visibility_state_buffer_);
  visitor->Trace(back_forward_cache_restoration_buffer_);
  visitor->Trace(soft_navigation_buffer_);
  visitor->Trace(long_animation_frame_buffer_);
  visitor->Trace(navigation_timing_);
  visitor->Trace(user_timing_);
  visitor->Trace(paint_entries_timing_);
  visitor->Trace(first_input_timing_);
  visitor->Trace(observers_);
  visitor->Trace(active_observers_);
  visitor->Trace(suspended_observers_);
  visitor->Trace(deliver_observations_timer_);
  visitor->Trace(resource_timing_buffer_full_timer_);
  visitor->Trace(background_tracing_helper_);
  EventTarget::Trace(visitor);
}

namespace {
class UserEntryPoint : public ScriptFunction {
 public:
  UserEntryPoint(V8Function* callback,
                 ScriptValue this_arg,
                 const HeapVector<ScriptValue>& args)
      : callback_(callback), this_arg_(this_arg), bound_args_(args) {}
  void CallRaw(
      ScriptState* script_state,
      const v8::FunctionCallbackInfo<v8::Value>& callback_info) override {
    static size_t call_index = 0;
    v8::Isolate* isolate = script_state->GetIsolate();
    probe::UserEntryPoint probe_scope(ExecutionContext::From(script_state),
                                      callback_->CallbackObject(),
                                      ++call_index);

    int length = callback_info.Length();
    HeapVector<ScriptValue> args(bound_args_);
    args.reserve(length + bound_args_.size());
    for (int i = 0; i < length; ++i) {
      args.push_back(ScriptValue(isolate, callback_info[i]));
    }

    callback_info.GetReturnValue().Set(
        callback_
            ->Invoke(
                bindings::V8ValueOrScriptWrappableAdapter(this_arg_.V8Value()),
                args)
            .FromMaybe(ScriptValue())
            .V8Value());
  }

  void Trace(Visitor* visitor) const override {
    ScriptFunction::Trace(visitor);
    visitor->Trace(callback_);
    visitor->Trace(this_arg_);
    visitor->Trace(bound_args_);
  }

 private:
  Member<V8Function> callback_;
  ScriptValue this_arg_;
  HeapVector<ScriptValue> bound_args_;
};

}  // namespace

V8Function* Performance::bind(V8Function* inner_function,
                              const ScriptValue this_arg,
                              const HeapVector<ScriptValue>& bound_args) {
  return V8Function::Create(
      MakeGarbageCollected<UserEntryPoint>(inner_function, this_arg, bound_args)
          ->ToV8Function(inner_function->CallbackRelevantScriptState()));
}

void Performance::SetClocksForTesting(const base::Clock* clock,
                                      const base::TickClock* tick_clock) {
  tick_clock_ = tick_clock;
  // Recompute |unix_at_zero_monotonic_|.
  unix_at_zero_monotonic_ = GetUnixAtZeroMonotonic(clock, tick_clock_);
}

void Performance::ResetTimeOriginForTesting(base::TimeTicks time_origin) {
  time_origin_ = time_origin;
}

// TODO(https://crbug.com/1457049): remove this once visited links are
// partitioned.
bool Performance::softNavPaintMetricsSupported() const {
  CHECK(
      RuntimeEnabledFeatures::SoftNavigationHeuristicsExposeFPAndFCPEnabled());
  return true;
}

}  // namespace blink

"""


```