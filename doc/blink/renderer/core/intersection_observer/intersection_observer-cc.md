Response:
The user wants to understand the functionality of the `intersection_observer.cc` file in the Chromium Blink rendering engine. I need to:

1. **Identify the core purpose of the file:**  Based on the file name and included headers, it's clearly related to the `IntersectionObserver` API.
2. **List the key functionalities:**  This involves parsing the code for the main actions and responsibilities of the classes and methods.
3. **Explain the relationship with web technologies (JavaScript, HTML, CSS):**  Crucially, the `IntersectionObserver` is a JavaScript API, so its connection to JS is direct. Its behavior is influenced by HTML elements and their styling (CSS).
4. **Provide examples illustrating these relationships:** Concrete examples will make the explanations clearer.
5. **Offer logical reasoning with input/output:** This means considering how the `IntersectionObserver` reacts to different configurations and changes in the DOM.
6. **Highlight common user/programming errors:**  Point out potential pitfalls when using the `IntersectionObserver` API.
好的，这个文件 `blink/renderer/core/intersection_observer/intersection_observer.cc` 是 Chromium Blink 引擎中实现 **Intersection Observer API** 的核心代码。它的主要功能是：

**核心功能：**

1. **监听目标元素与视口或指定祖先元素的交叉状态：**  `IntersectionObserver` 的主要职责是观察一个目标 HTML 元素是否进入或离开了另一个元素（通常是视口或者指定的祖先元素，称为 `root`）的边界。

2. **管理观察目标：**  它维护着一个被观察的 `Element` 列表（存储在 `observations_` 成员中）。

3. **处理交叉状态变化：** 当被观察元素的交叉状态发生变化时（例如，元素进入视口一部分，完全进入视口，或离开视口），`IntersectionObserver` 会收集这些变化信息。

4. **触发回调函数：**  当交叉状态发生变化时，`IntersectionObserver` 会调用用户提供的回调函数 (`IntersectionObserverCallback`)，并将一个包含交叉信息的 `IntersectionObserverEntry` 对象数组作为参数传递给该回调函数。

5. **配置交叉检测行为：**  `IntersectionObserver` 允许用户通过 `IntersectionObserverInit` 对象配置交叉检测的行为，包括：
    * **`root`**: 指定作为交叉边界的祖先元素。如果未指定，则默认为视口。
    * **`rootMargin`**:  在 `root` 元素的边界上添加或收缩边距，以调整交叉的触发范围。
    * **`threshold`**:  指定一个或多个阈值，表示目标元素与 `root` 交叉的可见比例。当交叉比例跨越这些阈值时，会触发回调。
    * **`delay`**: 设置一个延迟时间，用于节流回调函数的触发频率，尤其是在启用 `trackVisibility` 时。
    * **`trackVisibility`**:  启用更精细的可见性追踪，会考虑元素是否被遮挡等情况。
    * **`scrollMargin`**: （在支持的情况下）类似于 `rootMargin`，但应用于滚动容器。

6. **提供 `takeRecords()` 方法：**  允许用户手动获取所有待处理的交叉记录，而无需等待回调函数被触发。

7. **管理观察者的生命周期：**  提供 `observe()`、`unobserve()` 和 `disconnect()` 方法来添加、移除和断开对元素的观察。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `IntersectionObserver` 是一个 **JavaScript API**。开发者通过 JavaScript 代码创建和使用 `IntersectionObserver` 对象，并定义回调函数来处理交叉事件。
    ```javascript
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          console.log('目标元素进入视口', entry.target);
          // 执行相应的操作，例如加载图片、播放动画等
        } else {
          console.log('目标元素离开视口', entry.target);
        }
      });
    }, {
      root: document.querySelector('#scrollContainer'), // HTML 中 ID 为 scrollContainer 的元素
      rootMargin: '0px 0px -200px 0px', // CSS 样式影响边距的计算
      threshold: [0, 0.5, 1] // CSS 样式影响元素的大小和位置
    });

    const targetElement = document.querySelector('.my-element'); // HTML 中的元素
    observer.observe(targetElement);
    ```

* **HTML:**  `IntersectionObserver` 观察的目标是 **HTML 元素**。通过 JavaScript 获取 HTML 元素的引用，并将其传递给 `observer.observe()` 方法进行观察。`root` 选项也可以指向 HTML 中的特定元素。

* **CSS:**  **CSS 样式会影响 `IntersectionObserver` 的行为。**
    * **元素的大小和位置：**  CSS 样式决定了被观察元素和 `root` 元素的大小和位置，这是计算交叉状态的基础。
    * **`rootMargin` 和 `scrollMargin` 的解析：**  代码中的 `ParseMargin` 函数解析了 `IntersectionObserverInit` 中提供的 `rootMargin` 和 `scrollMargin` 字符串，其语法与 CSS 的 `margin` 属性类似。例如，`"10px 20px"` 会被解析为上/下边距 10px，左/右边距 20px。支持像素 (`px`) 和百分比 (`%`) 单位。
    * **隐藏和显示元素：** 如果一个被观察元素被 CSS 隐藏 (`display: none` 或 `visibility: hidden`)，通常不会触发交叉事件。

**逻辑推理与假设输入/输出：**

**假设输入：**

* **HTML:**
  ```html
  <div id="container" style="width: 200px; height: 200px; overflow: scroll;">
    <div id="target" style="width: 100px; height: 100px; background-color: red; margin-top: 300px;"></div>
  </div>
  ```
* **JavaScript:**
  ```javascript
  const container = document.getElementById('container');
  const target = document.getElementById('target');
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      console.log('Intersection Ratio:', entry.intersectionRatio);
      if (entry.isIntersecting) {
        console.log('Target is intersecting!');
      }
    });
  }, {
    root: container,
    threshold: [0.5]
  });
  observer.observe(target);

  // 初始状态：target 完全不在 container 的视口内
  ```

**输出：**

* **初始状态：**  `intersectionRatio` 将为 0，`isIntersecting` 将为 `false`。回调函数不会立即执行。

* **用户向下滚动 `container`，使得 `target` 元素有 50% 的面积进入 `container` 的可视区域：**  回调函数将被触发，输出的 `intersectionRatio` 将接近 0.5，`isIntersecting` 将为 `true`。

* **用户继续滚动，使得 `target` 完全进入 `container`：**  回调函数可能不会再次触发，因为我们只设置了一个阈值 0.5。如果我们设置了多个阈值（例如 `[0.5, 1]`），那么当 `target` 完全进入时，会再次触发回调，`intersectionRatio` 将接近 1。

* **用户向上滚动，使得 `target` 离开 `container` 的可视区域：**  回调函数将被触发，输出的 `intersectionRatio` 将变为 0，`isIntersecting` 将为 `false`。

**用户或编程常见的使用错误：**

1. **忘记调用 `observe()` 方法：** 创建了 `IntersectionObserver` 对象，但是没有调用 `observe()` 方法来指定要观察的目标元素，导致回调函数永远不会被触发。

   ```javascript
   const observer = new IntersectionObserver(/* ... */);
   const targetElement = document.querySelector('.my-element');
   // 缺少 observer.observe(targetElement);
   ```

2. **`root` 元素未正确指定或不存在：**  如果 `root` 选项指向的元素不存在或者不是目标元素的祖先元素，可能导致意外的行为或回调函数不被触发。

   ```javascript
   const observer = new IntersectionObserver(/* ... */, { root: document.querySelector('#nonExistentRoot') });
   observer.observe(document.querySelector('.my-element'));
   ```

3. **`rootMargin` 格式错误：**  `rootMargin` 字符串的格式不正确，例如使用了不支持的单位或数量不对，会导致解析错误。代码中的 `ParseMargin` 函数会抛出 `DOMExceptionCode::kSyntaxError`。

   ```javascript
   const observer = new IntersectionObserver(/* ... */, { rootMargin: '10px 20px 30px 40px 50px' }); // 错误：数量过多
   ```

4. **`threshold` 值超出范围：**  `threshold` 的值必须在 0 到 1 之间。提供超出此范围的值会导致 `exception_state.ThrowRangeError`。

   ```javascript
   const observer = new IntersectionObserver(/* ... */, { threshold: [0.5, 1.2] }); // 错误：1.2 超出范围
   ```

5. **在回调函数中进行复杂的同步操作：**  `IntersectionObserver` 的回调函数会在主线程上执行。在回调函数中执行耗时的同步操作可能会导致页面卡顿。建议在回调函数中只进行必要的轻量级操作，或者使用 `requestAnimationFrame` 或 `setTimeout` 将任务推迟到下一个帧。

6. **未正确处理 `disconnect()` 或 `unobserve()`：**  如果不再需要观察某个元素或整个观察者，应该调用 `unobserve()` 或 `disconnect()` 来释放资源，避免潜在的内存泄漏。

7. **误解 `trackVisibility` 的影响：**  启用 `trackVisibility` 会增加计算成本，如果不需要精确的可见性追踪，不应随意启用。并且启用 `trackVisibility` 时，`delay` 选项的值必须至少为 100 毫秒。

这个文件中的代码负责处理 `IntersectionObserver` 的底层逻辑，包括参数解析、交叉状态的计算、回调函数的调度等。理解这个文件的功能有助于深入了解浏览器的 Intersection Observer API 的实现机制。

### 提示词
```
这是目录为blink/renderer/core/intersection_observer/intersection_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"

#include <algorithm>
#include <limits>

#include "base/numerics/clamped_math.h"
#include "base/time/time.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intersection_observer_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intersection_observer_delegate.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intersection_observer_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_document_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_double_doublesequence.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/intersection_observer/element_intersection_observer_data.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_controller.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_delegate.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/timer.h"

namespace blink {

namespace {

// Internal implementation of IntersectionObserverDelegate when using
// IntersectionObserver with an EventCallback.
class IntersectionObserverDelegateImpl final
    : public IntersectionObserverDelegate {
 public:
  IntersectionObserverDelegateImpl(
      ExecutionContext* context,
      IntersectionObserver::EventCallback callback,
      IntersectionObserver::DeliveryBehavior delivery_behavior,
      bool needs_initial_observation_with_detached_target)
      : context_(context),
        callback_(std::move(callback)),
        delivery_behavior_(delivery_behavior),
        needs_initial_observation_with_detached_target_(
            needs_initial_observation_with_detached_target) {}
  IntersectionObserverDelegateImpl(const IntersectionObserverDelegateImpl&) =
      delete;
  IntersectionObserverDelegateImpl& operator=(
      const IntersectionObserverDelegateImpl&) = delete;

  IntersectionObserver::DeliveryBehavior GetDeliveryBehavior() const override {
    return delivery_behavior_;
  }

  bool NeedsInitialObservationWithDetachedTarget() const override {
    return needs_initial_observation_with_detached_target_;
  }

  void Deliver(const HeapVector<Member<IntersectionObserverEntry>>& entries,
               IntersectionObserver& observer) override {
    callback_.Run(entries);
  }

  ExecutionContext* GetExecutionContext() const override {
    return context_.Get();
  }

  void Trace(Visitor* visitor) const override {
    IntersectionObserverDelegate::Trace(visitor);
    visitor->Trace(context_);
  }

 private:
  WeakMember<ExecutionContext> context_;
  IntersectionObserver::EventCallback callback_;
  IntersectionObserver::DeliveryBehavior delivery_behavior_;
  bool needs_initial_observation_with_detached_target_;
};

void ParseMargin(const String& margin_parameter,
                 Vector<Length>& margin,
                 ExceptionState& exception_state,
                 const String& marginName) {
  // TODO(szager): Make sure this exact syntax and behavior is spec-ed
  // somewhere.

  // The root margin argument accepts syntax similar to that for CSS margin:
  //
  // "1px" = top/right/bottom/left
  // "1px 2px" = top/bottom left/right
  // "1px 2px 3px" = top left/right bottom
  // "1px 2px 3px 4px" = top left right bottom

  CSSParserTokenStream stream(margin_parameter);
  stream.ConsumeWhitespace();
  while (stream.Peek().GetType() != kEOFToken &&
         !exception_state.HadException()) {
    if (margin.size() == 4) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kSyntaxError,
          "Extra text found at the end of " + marginName + "Margin.");
      break;
    }
    const CSSParserToken token = stream.Peek();
    switch (token.GetType()) {
      case kPercentageToken:
        margin.push_back(Length::Percent(token.NumericValue()));
        stream.ConsumeIncludingWhitespace();
        break;
      case kDimensionToken:
        switch (token.GetUnitType()) {
          case CSSPrimitiveValue::UnitType::kPixels:
            margin.push_back(
                Length::Fixed(static_cast<int>(floor(token.NumericValue()))));
            break;
          case CSSPrimitiveValue::UnitType::kPercentage:
            margin.push_back(Length::Percent(token.NumericValue()));
            break;
          default:
            exception_state.ThrowDOMException(
                DOMExceptionCode::kSyntaxError,
                marginName + "Margin must be specified in pixels or percent.");
        }
        stream.ConsumeIncludingWhitespace();
        break;
      default:
        exception_state.ThrowDOMException(
            DOMExceptionCode::kSyntaxError,
            marginName + "Margin must be specified in pixels or percent.");
    }
  }
}

void ParseThresholds(const V8UnionDoubleOrDoubleSequence* threshold_parameter,
                     Vector<float>& thresholds,
                     ExceptionState& exception_state) {
  switch (threshold_parameter->GetContentType()) {
    case V8UnionDoubleOrDoubleSequence::ContentType::kDouble:
      thresholds.push_back(
          base::MakeClampedNum<float>(threshold_parameter->GetAsDouble()));
      break;
    case V8UnionDoubleOrDoubleSequence::ContentType::kDoubleSequence:
      for (auto threshold_value : threshold_parameter->GetAsDoubleSequence())
        thresholds.push_back(base::MakeClampedNum<float>(threshold_value));
      break;
  }

  if (thresholds.empty())
    thresholds.push_back(0.f);

  for (auto threshold_value : thresholds) {
    if (std::isnan(threshold_value) || threshold_value < 0.0 ||
        threshold_value > 1.0) {
      exception_state.ThrowRangeError(
          "Threshold values must be numbers between 0 and 1");
      break;
    }
  }

  std::sort(thresholds.begin(), thresholds.end());
}

// Returns a Vector of 4 margins (top, right, bottom, left) following
// https://drafts.csswg.org/css-box-4/#margin-shorthand
Vector<Length> NormalizeMargins(const Vector<Length>& margins) {
  Vector<Length> normalized_margins(4, Length::Fixed(0));

  switch (margins.size()) {
    case 0:
      break;
    case 1:
      normalized_margins[0] = normalized_margins[1] = normalized_margins[2] =
          normalized_margins[3] = margins[0];
      break;
    case 2:
      normalized_margins[0] = normalized_margins[2] = margins[0];
      normalized_margins[1] = normalized_margins[3] = margins[1];
      break;
    case 3:
      normalized_margins[0] = margins[0];
      normalized_margins[1] = normalized_margins[3] = margins[1];
      normalized_margins[2] = margins[2];
      break;
    case 4:
      normalized_margins[0] = margins[0];
      normalized_margins[1] = margins[1];
      normalized_margins[2] = margins[2];
      normalized_margins[3] = margins[3];
      break;
    default:
      NOTREACHED();
  }

  return normalized_margins;
}

Vector<Length> NormalizeScrollMargins(const Vector<Length>& margins) {
  Vector<Length> normalized_margins = NormalizeMargins(margins);
  if (std::all_of(normalized_margins.begin(), normalized_margins.end(),
                  [](const auto& m) { return m.IsZero(); })) {
    return Vector<Length>();
  }
  return normalized_margins;
}

String StringifyMargin(const Vector<Length>& margin) {
  StringBuilder string_builder;

  const auto append_length = [&](const Length& length) {
    string_builder.AppendNumber(length.IntValue());
    if (length.IsPercent()) {
      string_builder.Append('%');
    } else {
      string_builder.Append(base::byte_span_from_cstring("px"));
    }
  };

  if (margin.empty()) {
    string_builder.Append("0px 0px 0px 0px");
  } else {
    DCHECK_EQ(margin.size(), 4u);
    append_length(margin[0]);
    string_builder.Append(' ');
    append_length(margin[1]);
    string_builder.Append(' ');
    append_length(margin[2]);
    string_builder.Append(' ');
    append_length(margin[3]);
  }

  return string_builder.ToString();
}

}  // anonymous namespace

static bool throttle_delay_enabled = true;

void IntersectionObserver::SetThrottleDelayEnabledForTesting(bool enabled) {
  throttle_delay_enabled = enabled;
}

IntersectionObserver* IntersectionObserver::Create(
    const IntersectionObserverInit* observer_init,
    IntersectionObserverDelegate& delegate,
    std::optional<LocalFrameUkmAggregator::MetricId> ukm_metric_id,
    ExceptionState& exception_state) {
  Node* root = nullptr;
  if (observer_init->root()) {
    switch (observer_init->root()->GetContentType()) {
      case V8UnionDocumentOrElement::ContentType::kDocument:
        root = observer_init->root()->GetAsDocument();
        break;
      case V8UnionDocumentOrElement::ContentType::kElement:
        root = observer_init->root()->GetAsElement();
        break;
    }
  }

  Params params = {
      .root = root,
      .delay = base::Milliseconds(observer_init->delay()),
      .track_visibility = observer_init->trackVisibility(),
  };
  if (params.track_visibility && params.delay < base::Milliseconds(100)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "To enable the 'trackVisibility' option, you must also use a "
        "'delay' option with a value of at least 100. Visibility is more "
        "expensive to compute than the basic intersection; enabling this "
        "option may negatively affect your page's performance. Please make "
        "sure you *really* need visibility tracking before enabling the "
        "'trackVisibility' option.");
    return nullptr;
  }

  ParseMargin(observer_init->rootMargin(), params.margin, exception_state,
              "root");
  if (exception_state.HadException()) {
    return nullptr;
  }

  if (RuntimeEnabledFeatures::IntersectionObserverScrollMarginEnabled()) {
    ParseMargin(observer_init->scrollMargin(), params.scroll_margin,
                exception_state, "scroll");
    if (exception_state.HadException()) {
      return nullptr;
    }
  }

  ParseThresholds(observer_init->threshold(), params.thresholds,
                  exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  return MakeGarbageCollected<IntersectionObserver>(delegate, ukm_metric_id,
                                                    std::move(params));
}

IntersectionObserver* IntersectionObserver::Create(
    ScriptState* script_state,
    V8IntersectionObserverCallback* callback,
    const IntersectionObserverInit* observer_init,
    ExceptionState& exception_state) {
  V8IntersectionObserverDelegate* delegate =
      MakeGarbageCollected<V8IntersectionObserverDelegate>(callback,
                                                           script_state);
  if (observer_init && observer_init->trackVisibility()) {
    UseCounter::Count(delegate->GetExecutionContext(),
                      WebFeature::kIntersectionObserverV2);
  }
  return Create(observer_init, *delegate,
                LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
                exception_state);
}

IntersectionObserver* IntersectionObserver::Create(
    const Document& document,
    EventCallback callback,
    std::optional<LocalFrameUkmAggregator::MetricId> ukm_metric_id,
    Params&& params) {
  IntersectionObserverDelegateImpl* intersection_observer_delegate =
      MakeGarbageCollected<IntersectionObserverDelegateImpl>(
          document.GetExecutionContext(), std::move(callback), params.behavior,
          params.needs_initial_observation_with_detached_target);
  return MakeGarbageCollected<IntersectionObserver>(
      *intersection_observer_delegate, ukm_metric_id, std::move(params));
}

IntersectionObserver::IntersectionObserver(
    IntersectionObserverDelegate& delegate,
    std::optional<LocalFrameUkmAggregator::MetricId> ukm_metric_id,
    Params&& params)
    : ActiveScriptWrappable<IntersectionObserver>({}),
      ExecutionContextClient(delegate.GetExecutionContext()),
      delegate_(&delegate),
      ukm_metric_id_(ukm_metric_id),
      root_(params.root),
      thresholds_(std::move(params.thresholds)),
      delay_(params.delay),
      margin_(NormalizeMargins(params.margin)),
      scroll_margin_(NormalizeScrollMargins(params.scroll_margin)),
      margin_target_(params.margin_target),
      root_is_implicit_(params.root ? 0 : 1),
      track_visibility_(params.track_visibility),
      track_fraction_of_root_(params.semantics == kFractionOfRoot),
      always_report_root_bounds_(params.always_report_root_bounds),
      use_overflow_clip_edge_(params.use_overflow_clip_edge),
      expose_occluder_id_(params.expose_occluder_id) {
  if (params.root) {
    if (params.root->IsDocumentNode()) {
      To<Document>(params.root)
          ->EnsureDocumentExplicitRootIntersectionObserverData()
          .AddObserver(*this);
    } else {
      DCHECK(params.root->IsElementNode());
      To<Element>(params.root)
          ->EnsureIntersectionObserverData()
          .AddObserver(*this);
    }
  }
}

void IntersectionObserver::ProcessCustomWeakness(const LivenessBroker& info) {
  // For explicit-root observers, if the root element disappears for any reason,
  // any remaining obsevations must be dismantled.
  if (root() && !info.IsHeapObjectAlive(root()))
    root_ = nullptr;
  if (!RootIsImplicit() && !root())
    disconnect();
}

bool IntersectionObserver::RootIsValid() const {
  return RootIsImplicit() || root();
}

void IntersectionObserver::observe(Element* target,
                                   ExceptionState& exception_state) {
  if (!RootIsValid() || !target)
    return;

  if (target->EnsureIntersectionObserverData().GetObservationFor(*this))
    return;

  IntersectionObservation* observation =
      MakeGarbageCollected<IntersectionObservation>(*this, *target);
  target->EnsureIntersectionObserverData().AddObservation(*observation);
  observations_.insert(observation);
  if (root() && root()->isConnected()) {
    root()
        ->GetDocument()
        .EnsureIntersectionObserverController()
        .AddTrackedObserver(*this);
  }
  if (target->isConnected()) {
    target->GetDocument()
        .EnsureIntersectionObserverController()
        .AddTrackedObservation(*observation);
    if (LocalFrameView* frame_view = target->GetDocument().View()) {
      // The IntersectionObserver spec requires that at least one observation
      // be recorded after observe() is called, even if the frame is throttled.
      frame_view->SetIntersectionObservationState(LocalFrameView::kRequired);
      frame_view->ScheduleAnimation();
    }
  } else if (delegate_->NeedsInitialObservationWithDetachedTarget()) {
    ComputeIntersectionsContext context;
    observation->ComputeIntersectionImmediately(context);
  }
}

void IntersectionObserver::unobserve(Element* target,
                                     ExceptionState& exception_state) {
  if (!target || !target->IntersectionObserverData())
    return;

  IntersectionObservation* observation =
      target->IntersectionObserverData()->GetObservationFor(*this);
  if (!observation)
    return;

  observation->Disconnect();
  observations_.erase(observation);
  active_observations_.erase(observation);
  if (root() && root()->isConnected() && observations_.empty()) {
    root()
        ->GetDocument()
        .EnsureIntersectionObserverController()
        .RemoveTrackedObserver(*this);
  }
}

void IntersectionObserver::disconnect(ExceptionState& exception_state) {
  for (auto& observation : observations_)
    observation->Disconnect();
  observations_.clear();
  active_observations_.clear();
  if (root() && root()->isConnected()) {
    root()
        ->GetDocument()
        .EnsureIntersectionObserverController()
        .RemoveTrackedObserver(*this);
  }
}

HeapVector<Member<IntersectionObserverEntry>> IntersectionObserver::takeRecords(
    ExceptionState& exception_state) {
  HeapVector<Member<IntersectionObserverEntry>> entries;
  for (auto& observation : observations_)
    observation->TakeRecords(entries);
  active_observations_.clear();
  return entries;
}

String IntersectionObserver::rootMargin() const {
  return StringifyMargin(RootMargin());
}

String IntersectionObserver::scrollMargin() const {
  return StringifyMargin(ScrollMargin());
}

base::TimeDelta IntersectionObserver::GetEffectiveDelay() const {
  return throttle_delay_enabled ? delay_ : base::TimeDelta();
}

bool IntersectionObserver::IsInternal() const {
  return !GetUkmMetricId() ||
         GetUkmMetricId() !=
             LocalFrameUkmAggregator::kJavascriptIntersectionObserver;
}

void IntersectionObserver::ReportUpdates(IntersectionObservation& observation) {
  DCHECK_EQ(observation.Observer(), this);
  bool needs_scheduling = active_observations_.empty();
  active_observations_.insert(&observation);

  if (needs_scheduling) {
    To<LocalDOMWindow>(GetExecutionContext())
        ->document()
        ->EnsureIntersectionObserverController()
        .ScheduleIntersectionObserverForDelivery(*this);
  }
}

IntersectionObserver::DeliveryBehavior
IntersectionObserver::GetDeliveryBehavior() const {
  return delegate_->GetDeliveryBehavior();
}

void IntersectionObserver::Deliver() {
  if (!NeedsDelivery())
    return;
  HeapVector<Member<IntersectionObserverEntry>> entries;
  for (auto& observation : observations_)
    observation->TakeRecords(entries);
  active_observations_.clear();
  if (entries.size())
    delegate_->Deliver(entries, *this);
}

bool IntersectionObserver::HasPendingActivity() const {
  return NeedsDelivery();
}

void IntersectionObserver::Trace(Visitor* visitor) const {
  visitor->template RegisterWeakCallbackMethod<
      IntersectionObserver, &IntersectionObserver::ProcessCustomWeakness>(this);
  visitor->Trace(delegate_);
  visitor->Trace(observations_);
  visitor->Trace(active_observations_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

}  // namespace blink
```